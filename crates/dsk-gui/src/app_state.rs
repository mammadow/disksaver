//! Headless application state machine, confirmation modals, and explore cache manager.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dsk_core::clean::RuleTier;
use dsk_core::insights::{
    DupeProgress, DupeRemediationAction, DupeReport, DuplicateGroup, FullInsightsReport,
};
use dsk_core::optimize::{OptimizerIntent, WofAlgorithm, WofSamplePreview};
use dsk_core::{
    CleanPlan, CleanProgress, CleanReport, DenyContext, GrowthReport, GrowthWindow,
    JournalEntryRecord, JournalRunRecord, NodeFlags, NodeId, Phase, ROOT, ScanReport,
    SystemPreconditions, VolumeInfo, apply_preconditions, ext_breakdown_subtree, is_denied_path,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::tree_model::{DeletionLedger, ExploreFilter, TreeModel, TreeSort};
use crate::treemap::{
    SortedChildrenCache, TreemapLayout, build_cushion_mesh, build_treemap_layout,
};
use crate::worker::{JobLane, WorkerEvent, WorkerHandle, WorkerJob, WorkerProgress};

/// A mutating optimizer operation waiting for user confirmation. Holds only plain data (no
/// `Arc<ScanReport>`), so [`ConfirmAction`] stays `Eq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptimizerAction {
    CompactVhdx {
        path: PathBuf,
        distro: Option<String>,
        dry_run: bool,
    },
    CompressFolder {
        folder: PathBuf,
        algo: WofAlgorithm,
        dry_run: bool,
    },
    /// Hiberfile / CompactOS / VSS / Reserved Storage (helper-delegable intent).
    SystemIntent {
        intent: OptimizerIntent,
        dry_run: bool,
    },
    DehydrateCloudFiles {
        paths: Vec<PathBuf>,
        dry_run: bool,
    },
}

impl OptimizerAction {
    pub fn dry_run(&self) -> bool {
        match self {
            Self::CompactVhdx { dry_run, .. }
            | Self::CompressFolder { dry_run, .. }
            | Self::SystemIntent { dry_run, .. }
            | Self::DehydrateCloudFiles { dry_run, .. } => *dry_run,
        }
    }

    /// Converts the confirmed action into its worker job. `use_helper` routes system intents
    /// through the elevated helper when the GUI itself is not elevated.
    pub fn into_job(self, use_helper: bool) -> WorkerJob {
        match self {
            Self::CompactVhdx {
                path,
                distro,
                dry_run,
            } => WorkerJob::CompactVhdx {
                path,
                distro,
                dry_run,
            },
            Self::CompressFolder {
                folder,
                algo,
                dry_run,
            } => WorkerJob::CompressFolder {
                folder,
                algo,
                dry_run,
            },
            Self::SystemIntent { intent, dry_run } => WorkerJob::RunOptimizerIntent {
                intent,
                dry_run,
                use_helper,
            },
            Self::DehydrateCloudFiles { paths, dry_run } => {
                WorkerJob::DehydrateCloudFiles { paths, dry_run }
            }
        }
    }
}

/// Primary navigation tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ActiveTab {
    #[default]
    Overview,
    Cleanup,
    Explore,
    History,
    Optimize,
    Insights,
    /// Video compressor (P9.11).
    Videos,
}

/// Confirmation actions requiring user acknowledgement before destructive operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmAction {
    CleanRules {
        rule_count: usize,
        item_count: u64,
        total_est_bytes: u64,
        dry_run: bool,
        selected_rule_ids: Vec<String>,
    },
    RecycleTarget {
        node_id: NodeId,
        path: PathBuf,
        bytes: u64,
        is_dir: bool,
        blocked_reason: Option<String>,
    },
    ApplyOptimizer {
        title: String,
        target_path: String,
        detail: String,
        action: OptimizerAction,
    },
    RelocateFolder {
        source: PathBuf,
        target_parent: PathBuf,
        /// From the current scan when the source folder is part of it.
        total_bytes: Option<u64>,
        file_count: Option<u64>,
    },
    UndoRelocation {
        id: String,
        source: String,
        target: String,
    },
    RecycleInsightPath {
        label: String,
        path: PathBuf,
        bytes: u64,
        volume_root: String,
    },
    RemediateDuplicateGroup {
        group: DuplicateGroup,
        keep_index: usize,
        action: DupeRemediationAction,
    },
}

/// Severity kind for top-level status notification banner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BannerKind {
    Info,
    Warning,
    Error,
    Success,
}

/// Status banner message displayed in the UI header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusBanner {
    pub kind: BannerKind,
    pub message: String,
}

/// Headless application state machine managing UI state, caches, and background events.
pub struct AppState {
    pub active_tab: ActiveTab,

    // Drives and Scan
    pub volumes: Vec<VolumeInfo>,
    pub selected_volume: Option<VolumeInfo>,
    pub scan_report: Option<Arc<ScanReport>>,
    pub scan_generation: u64,
    pub is_refreshing_drives: bool,
    pub is_scanning: bool,
    pub scan_progress: Option<(Phase, u64, u64)>,
    pub helper_connected: bool,
    pub helper_plan_id: Option<String>,
    pub locked_holders: FxHashMap<String, Vec<String>>,

    // Cleanup Plan & Execution
    pub raw_plan: Option<CleanPlan>,
    pub preconditions: Option<SystemPreconditions>,
    pub force_battery: bool,
    pub selected_rules: BTreeSet<String>,
    pub is_cleaning: bool,
    pub clean_progress: Option<CleanProgress>,
    pub last_clean_report: Option<CleanReport>,

    // Explore / Treemap / Tree
    pub zoom_root: NodeId,
    pub history_stack: Vec<NodeId>,
    pub selected_node: Option<NodeId>,
    pub hovered_node: Option<NodeId>,
    pub explore_filter: ExploreFilter,
    pub tree_model: TreeModel,
    pub treemap_layout: TreemapLayout,
    pub treemap_mesh: eframe::egui::Mesh,
    pub ext_breakdown: Vec<(String, u64, u32)>,
    pub ledger: DeletionLedger,
    pub children_cache: SortedChildrenCache,

    // Audit History
    pub history_runs: Vec<JournalRunRecord>,
    pub history_entries: Vec<JournalEntryRecord>,
    pub selected_history_run_id: Option<String>,
    pub is_loading_history: bool,

    // Modals and Guardrails
    pub confirm_modal: Option<ConfirmAction>,
    pub status_banner: Option<StatusBanner>,
    pub deny_ctx: DenyContext,

    // Optimize Tab State
    pub vhdx_candidates: Vec<dsk_core::optimize::VhdxCandidate>,
    pub cloud_candidates: Vec<dsk_core::optimize::CloudDehydrateCandidate>,
    pub tunables_status: Option<dsk_core::optimize::SystemTunablesStatus>,
    pub compact_os_state: Option<bool>,
    pub active_relocations: Vec<dsk_core::clean::RelocationRecord>,
    pub is_optimizing: bool,
    pub last_optimize_message: Option<String>,

    // Insights Tab State
    pub insights_report: Option<FullInsightsReport>,
    pub dupes_report: Option<DupeReport>,
    pub dupes_progress: Option<DupeProgress>,
    pub is_insights_running: bool,
    pub is_dupes_running: bool,

    // Reclaim ledger + disk hunt (P9.1, P9.10)
    pub reclaim: Option<Arc<crate::worker::ReclaimResult>>,
    pub is_reclaim_running: bool,
    /// Explore: color the treemap by removability instead of file type.
    pub explore_color_removable: bool,

    // Video compressor (P9.11)
    pub videos: crate::views::videos::VideosState,

    // Shell / layout polish state (UI-only, zero side effects)
    pub sidebar_collapsed: bool,
    pub explore_split_ratio: f32,
    pub show_shortcuts_modal: bool,

    // Cache & Growth Tracking State
    pub scan_use_cache: bool,
    pub growth_window: GrowthWindow,
    pub growth_report: Option<GrowthReport>,
    pub is_loading_growth: bool,

    // Background job bookkeeping
    /// BuildPlan is running on the Heavy lane.
    pub is_planning: bool,
    /// A recycle / duplicate-remediation job is running on the Heavy lane.
    pub is_recycling: bool,
    /// The read-only optimizer probe is running (Optimizers lane).
    pub is_probing_optimizers: bool,
    /// The probe was spawned for the current scan/state. Reset by `ScanFinished` and
    /// `OptimizerFinished` (and the Refresh button), never by merely rendering a frame, so the
    /// Optimize tab probes exactly once even when the probe fails.
    pub optimizers_probe_attempted: bool,
    pub optimizers_probe_error: Option<String>,
    /// Waiting for the UAC prompt / helper handshake (Helper lane).
    pub is_connecting_helper: bool,
    /// Latest WOF 2% sample (computed on the worker, never on the UI thread).
    pub wof_sample: Option<(PathBuf, Result<WofSamplePreview, String>)>,
    /// Hash of the duplicate group being remediated live (removed from the report on success).
    pub pending_dupe_group: Option<String>,

    // Storage locations (`None` = defaults under %LOCALAPPDATA%\DiskSaver). Injected by
    // `--test-journal` / `--growth-db` and by headless tests so they never touch real databases.
    pub journal_path: Option<PathBuf>,
    pub growth_db_path: Option<PathBuf>,
    pub hash_cache_path: Option<PathBuf>,

    // Per-frame caches
    plan_generation: u64,
    effective_plan_cache: Option<(EffectivePlanKey, Arc<CleanPlan>)>,
    top_dirs_cache: Option<(u64, Vec<NodeId>)>,

    // Cache tracking keys
    cached_layout_keys: Option<(u64, u64, NodeId, [i32; 4], u16, bool)>,
    cached_mesh_keys: Option<(Option<NodeId>, Option<NodeId>)>,
    cached_tree_keys: Option<(u64, u64, NodeId, ExploreFilter, TreeSort, FxHashSet<NodeId>)>,
    cached_ext_keys: Option<(u64, u64, NodeId)>,
}

type EffectivePlanKey = (u64, bool, usize, u64);

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Creates a clean headless `AppState` initialized with defaults.
    pub fn new() -> Self {
        Self {
            active_tab: ActiveTab::Overview,
            volumes: Vec::new(),
            selected_volume: None,
            scan_report: None,
            scan_generation: 0,
            is_refreshing_drives: false,
            is_scanning: false,
            scan_progress: None,
            helper_connected: false,
            helper_plan_id: None,
            locked_holders: FxHashMap::default(),

            raw_plan: None,
            preconditions: None,
            force_battery: false,
            selected_rules: BTreeSet::new(),
            is_cleaning: false,
            clean_progress: None,
            last_clean_report: None,

            zoom_root: ROOT,
            history_stack: Vec::new(),
            selected_node: None,
            hovered_node: None,
            explore_filter: ExploreFilter::default(),
            tree_model: TreeModel::new(),
            treemap_layout: TreemapLayout {
                zoom_root: ROOT,
                items: Vec::new(),
                leaf_rects: 0,
                collapsed_groups: 0,
            },
            treemap_mesh: eframe::egui::Mesh::default(),
            ext_breakdown: Vec::new(),
            ledger: DeletionLedger::new(),
            children_cache: SortedChildrenCache::new(),

            history_runs: Vec::new(),
            history_entries: Vec::new(),
            selected_history_run_id: None,
            is_loading_history: false,

            confirm_modal: None,
            status_banner: None,
            deny_ctx: DenyContext::default(),

            vhdx_candidates: Vec::new(),
            cloud_candidates: Vec::new(),
            tunables_status: None,
            compact_os_state: None,
            active_relocations: Vec::new(),
            is_optimizing: false,
            last_optimize_message: None,

            insights_report: None,
            dupes_report: None,
            dupes_progress: None,
            is_insights_running: false,
            is_dupes_running: false,

            reclaim: None,
            is_reclaim_running: false,
            videos: Default::default(),
            explore_color_removable: false,

            sidebar_collapsed: false,
            explore_split_ratio: 0.45,
            show_shortcuts_modal: false,

            scan_use_cache: true,
            growth_window: GrowthWindow::H24,
            growth_report: None,
            is_loading_growth: false,

            is_planning: false,
            is_recycling: false,
            is_probing_optimizers: false,
            optimizers_probe_attempted: false,
            optimizers_probe_error: None,
            is_connecting_helper: false,
            wof_sample: None,
            pending_dupe_group: None,

            journal_path: None,
            growth_db_path: None,
            hash_cache_path: None,

            plan_generation: 0,
            effective_plan_cache: None,
            top_dirs_cache: None,

            cached_layout_keys: None,
            cached_mesh_keys: None,
            cached_tree_keys: None,
            cached_ext_keys: None,
        }
    }

    /// True while any job occupies the single-slot Heavy lane. Every Heavy-lane trigger must be
    /// disabled while this is true: spawning would silently cancel the running job.
    pub fn heavy_busy(&self) -> bool {
        self.is_scanning
            || self.is_planning
            || self.is_cleaning
            || self.is_optimizing
            || self.is_insights_running
            || self.is_dupes_running
            || self.is_recycling
            || self.is_reclaim_running
    }

    /// True while any background job is running on any lane (drives repaint scheduling).
    pub fn any_job_active(&self) -> bool {
        self.heavy_busy()
            || self.is_refreshing_drives
            || self.is_loading_history
            || self.is_loading_growth
            || self.is_probing_optimizers
            || self.is_connecting_helper
            || self.videos.busy()
    }

    /// Short label for the running Heavy-lane job, if any.
    pub fn heavy_activity_label(&self) -> Option<&'static str> {
        if self.is_scanning {
            Some("Scanning...")
        } else if self.is_cleaning {
            Some("Cleaning...")
        } else if self.is_planning {
            Some("Building cleanup plan...")
        } else if self.is_optimizing {
            Some("Optimizing...")
        } else if self.is_insights_running {
            Some("Analyzing insights...")
        } else if self.is_dupes_running {
            Some("Finding duplicates...")
        } else if self.is_recycling {
            Some("Moving to Recycle Bin...")
        } else if self.is_reclaim_running {
            Some("Finding space...")
        } else {
            None
        }
    }

    fn clear_heavy_flags(&mut self) {
        self.is_scanning = false;
        self.is_planning = false;
        self.is_cleaning = false;
        self.is_optimizing = false;
        self.is_insights_running = false;
        self.is_dupes_running = false;
        self.is_recycling = false;
        self.is_reclaim_running = false;
        self.dupes_progress = None;
    }

    /// Spawns `job` and sets exactly the busy flag its completion event clears.
    ///
    /// All UI triggers go through here. A Heavy-lane spawn supersedes the running Heavy job,
    /// whose terminal event is then discarded by the worker; clearing every Heavy flag first
    /// guarantees no spinner is left stuck for a job that will never report back.
    pub fn spawn_job(&mut self, worker: &mut WorkerHandle, job: WorkerJob) -> u64 {
        if job.lane() == JobLane::Heavy {
            self.clear_heavy_flags();
        }
        match &job {
            WorkerJob::ScanTarget { .. } => {
                self.is_scanning = true;
                self.scan_progress = None;
            }
            WorkerJob::BuildPlan { .. } => self.is_planning = true,
            WorkerJob::ExecuteClean { .. } => {
                self.is_cleaning = true;
                self.clean_progress = None;
            }
            WorkerJob::RecycleNode { .. } | WorkerJob::RecycleInsightPath { .. } => {
                self.is_recycling = true;
            }
            WorkerJob::RemediateDuplicates { group, dry_run, .. } => {
                self.is_recycling = true;
                self.pending_dupe_group = (!dry_run).then(|| group.blake3_hex.clone());
            }
            WorkerJob::CompactVhdx { .. }
            | WorkerJob::CompressFolder { .. }
            | WorkerJob::RunOptimizerIntent { .. }
            | WorkerJob::DehydrateCloudFiles { .. }
            | WorkerJob::SampleWof { .. }
            | WorkerJob::RelocateFolder { .. }
            | WorkerJob::UndoRelocation { .. } => self.is_optimizing = true,
            WorkerJob::RunInsights { .. } => self.is_insights_running = true,
            WorkerJob::BuildReclaim { .. } => self.is_reclaim_running = true,
            WorkerJob::FindDuplicates { .. } => {
                self.is_dupes_running = true;
                self.dupes_progress = None;
            }
            WorkerJob::RefreshDrives => self.is_refreshing_drives = true,
            WorkerJob::LoadHistory { .. } => self.is_loading_history = true,
            WorkerJob::LoadGrowth { .. } => self.is_loading_growth = true,
            WorkerJob::ProbeOptimizers { .. } => {
                self.is_probing_optimizers = true;
                self.optimizers_probe_attempted = true;
                self.optimizers_probe_error = None;
            }
            WorkerJob::ConnectHelper => self.is_connecting_helper = true,
            WorkerJob::ProbeVideoEngine => {
                self.videos.probing = true;
                self.videos.engine_probe_attempted = true;
            }
            WorkerJob::FindVideos { .. } => {
                self.videos.finding = true;
                self.videos.progress = None;
            }
            WorkerJob::SampleVideo { path, .. } => self.videos.sampling = Some(path.clone()),
            WorkerJob::CompressVideos { .. } => {
                self.videos.compressing = true;
                self.videos.progress = None;
                self.videos.last_batch = None;
            }
            WorkerJob::LoadHeldVideos { .. } => self.videos.loading_held = true,
            WorkerJob::PurgeHeldVideos { .. } => self.videos.purging = true,
        }
        worker.spawn_job(job)
    }

    /// Spawns the Optimize-tab probe at most once per scan/optimizer change: no-op while a probe
    /// runs or after one was attempted (even if it failed). Returns `true` if a probe started.
    pub fn ensure_optimizer_probe(&mut self, worker: &mut WorkerHandle) -> bool {
        if self.optimizers_probe_attempted || self.is_probing_optimizers {
            return false;
        }
        let job = WorkerJob::ProbeOptimizers {
            scan_report: self.scan_report.clone(),
            journal_path: self.journal_path.clone(),
        };
        self.spawn_job(worker, job);
        true
    }

    /// Marks optimizer probe results stale so the next Optimize frame re-probes once.
    pub fn invalidate_optimizer_probe(&mut self) {
        self.optimizers_probe_attempted = false;
    }

    /// Cached [`AppState::effective_plan`] (cloning a plan with hundreds of thousands of items
    /// every frame was the dominant per-frame cost of the Overview and Cleanup tabs).
    pub fn effective_plan_shared(&mut self) -> Option<Arc<CleanPlan>> {
        let raw = self.raw_plan.as_ref()?;
        let key: EffectivePlanKey = (
            self.plan_generation,
            self.force_battery,
            raw.rules.len(),
            raw.total_est_bytes,
        );
        if let Some((k, plan)) = &self.effective_plan_cache
            && *k == key
        {
            return Some(Arc::clone(plan));
        }
        let plan = Arc::new(self.effective_plan()?);
        self.effective_plan_cache = Some((key, Arc::clone(&plan)));
        Some(plan)
    }

    /// Top-10 largest folders of the current scan, computed once per scan generation.
    pub fn top_dirs_cached(&mut self) -> Vec<NodeId> {
        let Some(report) = self.scan_report.as_ref() else {
            return Vec::new();
        };
        if let Some((generation, ids)) = &self.top_dirs_cache
            && *generation == self.scan_generation
        {
            return ids.clone();
        }
        let ids = dsk_core::top_dirs(&report.index, 10, 3);
        self.top_dirs_cache = Some((self.scan_generation, ids.clone()));
        ids
    }

    /// Removes insight rows at or under a path that was just moved to the Recycle Bin so the
    /// tab never offers an action on something that no longer exists.
    pub fn prune_recycled_insight(&mut self, path: &Path) {
        let gone = |p: &Path| p == path || p.starts_with(path);
        if let Some(r) = &mut self.insights_report {
            r.projects.artifacts.retain(|a| !gone(&a.artifact_path));
            r.ai_models.models.retain(|m| !gone(&m.path));
            r.orphans.candidates.retain(|c| !gone(&c.path));
            r.cold.cold_files.retain(|f| !gone(&f.path));
            for g in &mut r.gaming.games {
                if g.shadercache_path.as_deref().is_some_and(gone) {
                    g.shadercache_path = None;
                }
            }
        }
    }

    /// Selects an active volume.
    pub fn select_volume(&mut self, vol: VolumeInfo) {
        self.selected_volume = Some(vol);
    }

    /// Returns true if either the GUI process itself is elevated or the elevated helper
    /// daemon is connected.
    pub fn effective_elevated(&self, is_elevated: bool) -> bool {
        is_elevated || self.helper_connected
    }

    /// Toggles the checkbox inclusion of a rule ID in the cleanup selection.
    pub fn toggle_rule(&mut self, rule_id: &str) {
        if self.selected_rules.contains(rule_id) {
            self.selected_rules.remove(rule_id);
        } else {
            self.selected_rules.insert(rule_id.to_string());
        }
    }

    /// Computes the effective cleanup plan in memory by evaluating preconditions
    /// against `raw_plan` without modifying `raw_plan`.
    pub fn effective_plan(&self) -> Option<CleanPlan> {
        let mut plan = self.raw_plan.clone()?;
        if let Some(ref pre) = self.preconditions {
            apply_preconditions(&mut plan, pre, self.force_battery);
        }
        Some(plan)
    }

    /// Prepares a cleanup confirmation modal action using the currently selected rules.
    pub fn prepare_clean_confirm(&self, dry_run: bool) -> Option<ConfirmAction> {
        let effective = self.effective_plan()?;
        let selected_ids: Vec<String> = self.selected_rules.iter().cloned().collect();
        let filtered = effective.filtered_rules(&selected_ids);
        let rule_count = filtered.rules.len();
        let item_count: u64 = filtered.rules.iter().map(|r| r.item_count).sum();
        let total_est_bytes = filtered.total_est_bytes;

        Some(ConfirmAction::CleanRules {
            rule_count,
            item_count,
            total_est_bytes,
            dry_run,
            selected_rule_ids: selected_ids,
        })
    }

    /// Prepares a recycle confirmation modal action for a target node, checking safety gates.
    pub fn prepare_recycle_confirm(&self, id: NodeId) -> Option<ConfirmAction> {
        let report = self.scan_report.as_ref()?;
        if (id as usize) >= report.index.len() {
            return None;
        }

        let path_str = report.index.path(id);
        let path = PathBuf::from(&path_str);
        let is_dir = report.index.flags(id).contains(NodeFlags::DIR);
        let bytes = self.ledger.effective_bytes(&report.index, id);
        let flags = report.index.flags(id);

        let mut blocked_reason = None;
        if id == ROOT {
            blocked_reason = Some("Cannot recycle drive root".to_string());
        } else if let Some(reason) = is_denied_path(&path, &self.deny_ctx) {
            blocked_reason = Some(format!("Protected path: {reason}"));
        } else if flags.intersects(
            NodeFlags::CLOUD
                | NodeFlags::OFFLINE
                | NodeFlags::METAFILE
                | NodeFlags::REPARSE
                | NodeFlags::ORPHANS,
        ) {
            blocked_reason = Some(format!("Cannot recycle node with flags: {flags:?}"));
        }

        Some(ConfirmAction::RecycleTarget {
            node_id: id,
            path,
            bytes,
            is_dir,
            blocked_reason,
        })
    }

    /// Zooms into a directory node, updating `zoom_root` and navigation history stack.
    pub fn zoom_into(&mut self, id: NodeId) {
        if let Some(ref report) = self.scan_report
            && (id as usize) < report.index.len()
            && id != self.zoom_root
        {
            self.history_stack.push(self.zoom_root);
            self.zoom_root = id;
            self.selected_node = Some(id);
            self.invalidate_explore_caches();
        }
    }

    /// Navigates up to the parent of `zoom_root`, returning true if navigation occurred.
    pub fn navigate_up(&mut self) -> bool {
        if let Some(ref report) = self.scan_report
            && self.zoom_root != ROOT
        {
            let parent = report.index.parent(self.zoom_root);
            if parent != dsk_core::NONE {
                self.history_stack.push(self.zoom_root);
                self.zoom_root = parent;
                self.selected_node = Some(parent);
                self.invalidate_explore_caches();
                return true;
            }
        }
        false
    }

    /// Navigates back along the navigation history stack, returning true if navigation occurred.
    pub fn navigate_back(&mut self) -> bool {
        while let Some(prev) = self.history_stack.pop() {
            if let Some(ref report) = self.scan_report
                && (prev as usize) < report.index.len()
                && !self.ledger.is_removed_or_ancestor(&report.index, prev)
            {
                self.zoom_root = prev;
                self.selected_node = Some(prev);
                self.invalidate_explore_caches();
                return true;
            }
        }
        false
    }

    /// Recovers navigation state (zoom_root, history_stack, selected_node, hovered_node)
    /// when the current node or its ancestors have been removed in the ledger.
    pub fn recover_removed_navigation(&mut self) {
        let Some(ref sr) = self.scan_report else {
            return;
        };

        if self
            .ledger
            .is_removed_or_ancestor(&sr.index, self.zoom_root)
        {
            let mut curr = self.zoom_root;
            while curr != dsk_core::NONE && self.ledger.is_removed_or_ancestor(&sr.index, curr) {
                curr = sr.index.parent(curr);
            }
            self.zoom_root = if curr != dsk_core::NONE { curr } else { ROOT };
        }

        self.history_stack
            .retain(|&nid| !self.ledger.is_removed_or_ancestor(&sr.index, nid));
        self.history_stack.dedup();
        while self.history_stack.last() == Some(&self.zoom_root) {
            self.history_stack.pop();
        }

        if let Some(sel) = self.selected_node
            && self.ledger.is_removed_or_ancestor(&sr.index, sel)
        {
            self.selected_node = None;
        }

        if let Some(hov) = self.hovered_node
            && self.ledger.is_removed_or_ancestor(&sr.index, hov)
        {
            self.hovered_node = None;
        }
    }

    /// Invalidates all explore caches so subsequent frame queries recompute.
    pub fn invalidate_explore_caches(&mut self) {
        self.cached_layout_keys = None;
        self.cached_mesh_keys = None;
        self.cached_tree_keys = None;
        self.cached_ext_keys = None;
    }

    /// Ensures explore views (treemap layout, cushion mesh, tree table, extension breakdown)
    /// are up to date, recomputing only the specific projections whose inputs have changed.
    pub fn ensure_explore_caches(&mut self, viewport: [f32; 4], max_depth: u16) {
        let Some(ref report) = self.scan_report else {
            return;
        };

        let scan_gen = self.scan_generation;
        let ledger_gen = self.ledger.generation;
        let zoom_root = self.zoom_root;
        let vp_quantized = [
            viewport[0] as i32,
            viewport[1] as i32,
            viewport[2] as i32,
            viewport[3] as i32,
        ];

        // 1. Layout recompute check
        // The removable color mode only applies when hunt verdicts exist for this index.
        let removable = self.explore_color_removable
            && self
                .reclaim
                .as_ref()
                .is_some_and(|r| r.verdicts.len() == report.index.len());
        let layout_keys = (
            scan_gen,
            ledger_gen,
            zoom_root,
            vp_quantized,
            max_depth,
            removable,
        );
        let layout_changed = self.cached_layout_keys != Some(layout_keys);
        if layout_changed {
            self.treemap_layout = build_treemap_layout(
                &report.index,
                &mut self.children_cache,
                &self.ledger.subtracted,
                &self.ledger.removed,
                zoom_root,
                viewport,
                max_depth,
            );
            if removable && let Some(r) = self.reclaim.as_ref() {
                for item in &mut self.treemap_layout.items {
                    if let Some(id) = item.node_id
                        && let Some(&v) = r.verdicts.get(id as usize)
                    {
                        item.color =
                            crate::theme::verdict_color(dsk_core::hunt::Verdict::from_u8(v));
                    }
                }
            }
            self.cached_layout_keys = Some(layout_keys);
            // Invalidate mesh keys to force mesh rebuild on new layout
            self.cached_mesh_keys = None;
        }

        // 2. Mesh recompute check (rebuilds only when layout or hovered/selected node changes)
        let mesh_keys = (self.hovered_node, self.selected_node);
        if self.cached_mesh_keys != Some(mesh_keys) {
            self.treemap_mesh = build_cushion_mesh(
                &self.treemap_layout.items,
                self.hovered_node,
                self.selected_node,
            );
            self.cached_mesh_keys = Some(mesh_keys);
        }

        // 3. Tree model recompute check (zero-alloc reference check on cache hits)
        let tree_cache_hit = self.cached_tree_keys.as_ref().is_some_and(|k| {
            k.0 == scan_gen
                && k.1 == ledger_gen
                && k.2 == zoom_root
                && k.3 == self.explore_filter
                && k.4 == self.tree_model.sort
                && k.5 == self.tree_model.expanded
        });

        if !tree_cache_hit {
            self.tree_model.rebuild(
                &report.index,
                &mut self.children_cache,
                &self.ledger,
                zoom_root,
                &self.explore_filter,
            );
            self.cached_tree_keys = Some((
                scan_gen,
                ledger_gen,
                zoom_root,
                self.explore_filter.clone(),
                self.tree_model.sort,
                self.tree_model.expanded.clone(),
            ));
        }

        // 4. Extension breakdown check
        let ext_keys = (scan_gen, ledger_gen, zoom_root);
        if self.cached_ext_keys != Some(ext_keys) {
            self.ext_breakdown = ext_breakdown_subtree(&report.index, zoom_root, 10);
            self.cached_ext_keys = Some(ext_keys);
        }
    }

    /// Applies a worker event to the state machine.
    pub fn apply_worker_event(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::DrivesLoaded(vols) => {
                self.volumes = vols;
                self.is_refreshing_drives = false;
            }

            WorkerEvent::ScanFinished(report) => {
                self.scan_report = Some(report);
                self.scan_generation = self.scan_generation.wrapping_add(1);
                self.is_scanning = false;
                // VHDX / cloud candidates come from the scan: re-probe on next Optimize frame.
                self.invalidate_optimizer_probe();
                self.wof_sample = None;
                self.scan_progress = None;
                self.helper_plan_id = None;
                self.locked_holders.clear();
                self.zoom_root = ROOT;
                self.history_stack.clear();
                self.selected_node = None;
                self.hovered_node = None;
                self.ledger.clear();
                self.children_cache.clear();
                self.invalidate_explore_caches();
            }

            WorkerEvent::PlanFinished {
                plan,
                preconditions,
                helper_plan_id,
                locked_holders,
            } => {
                self.is_planning = false;
                self.plan_generation = self.plan_generation.wrapping_add(1);
                self.raw_plan = Some(plan);
                self.preconditions = Some(preconditions);
                self.helper_plan_id = helper_plan_id;
                self.locked_holders = locked_holders;
                self.selected_rules.clear();
                if let Some(effective) = self.effective_plan() {
                    for rule in effective.rules {
                        // 🟡 Review / 🔴 Advanced rules are listed but never pre-checked.
                        if rule.rule_id != "os.vc.recycle_bin" && rule.tier == RuleTier::Safe {
                            self.selected_rules.insert(rule.rule_id);
                        }
                    }
                }
            }

            WorkerEvent::CleanFinished {
                report,
                ledger_deltas,
            } => {
                self.is_cleaning = false;
                self.clean_progress = None;
                self.last_clean_report = Some(report.clone());
                self.confirm_modal = None;

                if !report.dry_run {
                    let prev_gen = self.ledger.generation;
                    if let Some(ref sr) = self.scan_report {
                        for (nid, bytes) in ledger_deltas {
                            self.ledger.record_deleted_node(&sr.index, nid, bytes);
                        }
                    }
                    if self.ledger.generation != prev_gen {
                        self.children_cache.clear();
                        self.recover_removed_navigation();
                        self.invalidate_explore_caches();
                    }
                }
            }

            WorkerEvent::RecycleFinished {
                node_id,
                outcome,
                run_id: _,
                journal_warning,
            } => {
                self.is_recycling = false;
                self.confirm_modal = None;
                if let Some(ref sr) = self.scan_report {
                    let freed = if outcome.bytes_hint > 0 {
                        outcome.bytes_hint
                    } else {
                        self.ledger.effective_bytes(&sr.index, node_id)
                    };
                    self.ledger.record_deleted_node(&sr.index, node_id, freed);
                    self.children_cache.clear();
                    self.recover_removed_navigation();
                    self.invalidate_explore_caches();
                }
                if let Some(warning) = journal_warning {
                    self.status_banner = Some(StatusBanner {
                        kind: BannerKind::Warning,
                        message: warning,
                    });
                }
            }

            WorkerEvent::HistoryLoaded(runs) => {
                self.history_runs = runs;
                self.is_loading_history = false;
            }

            WorkerEvent::GrowthLoaded(rep) => {
                self.growth_report = Some(rep);
                self.is_loading_growth = false;
            }

            WorkerEvent::HelperConnected => {
                self.is_connecting_helper = false;
                self.helper_connected = true;
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Success,
                    message: "Elevated helper connected with Administrator privileges.".to_string(),
                });
            }

            WorkerEvent::RunEntriesLoaded { run_id, entries } => {
                self.selected_history_run_id = Some(run_id);
                self.history_entries = entries;
            }

            WorkerEvent::OptimizersProbed {
                vhdx_candidates,
                cloud_candidates,
                tunables_status,
                compact_os_state,
                active_relocations,
            } => {
                self.vhdx_candidates = vhdx_candidates;
                self.cloud_candidates = cloud_candidates;
                self.tunables_status = Some(tunables_status);
                self.compact_os_state = compact_os_state;
                self.active_relocations = active_relocations;
                self.is_probing_optimizers = false;
                self.optimizers_probe_error = None;
            }

            WorkerEvent::OptimizerFinished { message, warning } => {
                self.is_optimizing = false;
                self.last_optimize_message = Some(message.clone());
                self.status_banner = Some(StatusBanner {
                    kind: if warning {
                        BannerKind::Warning
                    } else {
                        BannerKind::Success
                    },
                    message,
                });
                self.confirm_modal = None;
                // System state changed (hiberfile, CompactOS, relocations, ...): re-probe once.
                self.invalidate_optimizer_probe();
            }

            WorkerEvent::WofSampled { folder, result } => {
                self.is_optimizing = false;
                self.wof_sample = Some((folder, result));
            }

            WorkerEvent::VideoEngineProbed(engine) => {
                self.videos.probing = false;
                self.videos.engine = engine;
            }

            WorkerEvent::VideosProgress(p) => {
                self.videos.progress = Some(p);
            }

            WorkerEvent::VideosFound(d) => {
                self.videos.finding = false;
                self.videos.progress = None;
                // Keep the selection and results for videos that are still listed.
                self.videos
                    .selected
                    .retain(|p| d.candidates.iter().any(|c| &c.path == p));
                self.videos.results.clear();
                let msg = format!(
                    "Found {} videos that can shrink by about {}.",
                    d.candidates.len(),
                    crate::theme::fmt_bytes(d.est_saving_bytes)
                );
                self.videos.discovery = Some(d);
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Success,
                    message: msg,
                });
            }

            WorkerEvent::VideoSampled { path, result } => {
                self.videos.sampling = None;
                self.videos.samples.insert(path, result);
            }

            WorkerEvent::VideoFileDone(o) => {
                self.videos.selected.remove(&o.path);
                self.videos.results.insert(o.path.clone(), o);
            }

            WorkerEvent::VideosCompressed(report) => {
                self.videos.compressing = false;
                self.videos.progress = None;
                self.status_banner = Some(crate::views::videos::batch_banner(&report));
                if report.held_bytes > 0 {
                    self.videos.held_loaded = false;
                }
                self.videos.last_batch = Some(report);
            }

            WorkerEvent::HeldVideosLoaded(result) => {
                self.videos.loading_held = false;
                self.videos.held_loaded = true;
                match result {
                    Ok(h) => self.videos.held = h,
                    Err(e) => {
                        self.status_banner = Some(StatusBanner {
                            kind: BannerKind::Error,
                            message: format!("Could not read held originals: {e}"),
                        })
                    }
                }
            }

            WorkerEvent::HeldVideosPurged(result) => {
                self.videos.purging = false;
                self.videos.held_loaded = false;
                self.status_banner = Some(match result {
                    Ok(r) => StatusBanner {
                        kind: if r.errors.is_empty() {
                            BannerKind::Success
                        } else {
                            BannerKind::Warning
                        },
                        message: format!(
                            "Deleted {} held originals, freeing {}.{}",
                            r.purged,
                            crate::theme::fmt_bytes(r.purged_bytes),
                            if r.errors.is_empty() {
                                String::new()
                            } else {
                                format!(" {} kept: {}", r.errors.len(), r.errors.join("; "))
                            }
                        ),
                    },
                    Err(e) => StatusBanner {
                        kind: BannerKind::Error,
                        message: format!("Could not delete held originals: {e}"),
                    },
                });
            }

            WorkerEvent::ReclaimFinished(result) => {
                self.is_reclaim_running = false;
                let msg = format!(
                    "Found ~{} you can free without losing anything ({} opportunities, {} hunt findings).",
                    crate::theme::fmt_bytes(result.assembled.ledger.headline_bytes),
                    result.assembled.ledger.opportunities.len(),
                    result.hunt.findings.len()
                );
                self.reclaim = Some(result);
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Success,
                    message: msg,
                });
            }

            WorkerEvent::InsightsFinished(report) => {
                self.is_insights_running = false;
                self.insights_report = Some(report);
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Success,
                    message: "Storage insights analysis finished.".to_string(),
                });
            }

            WorkerEvent::DupesProgress(dp) => {
                self.dupes_progress = Some(dp);
            }

            WorkerEvent::DupesFinished(rep) => {
                self.is_dupes_running = false;
                self.dupes_progress = None;
                let msg = format!(
                    "Duplicate scan finished: {} group(s) found.",
                    rep.groups.len()
                );
                self.dupes_report = Some(rep);
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Success,
                    message: msg,
                });
            }

            WorkerEvent::DupeRemediationFinished(out) => {
                self.is_recycling = false;
                let mut msg = format!(
                    "Duplicate remediation ({}): processed {}, skipped {}.",
                    if out.dry_run { "dry-run" } else { "live" },
                    out.processed,
                    out.skipped
                );
                if let Some(first) = out.notes.first() {
                    msg.push_str(&format!(" Note: {first}"));
                }
                let pending = self.pending_dupe_group.take();
                if !out.dry_run
                    && out.processed > 0
                    && out.skipped == 0
                    && let (Some(hex), Some(rep)) = (pending, self.dupes_report.as_mut())
                {
                    rep.groups.retain(|g| g.blake3_hex != hex);
                }
                self.status_banner = Some(StatusBanner {
                    kind: if out.skipped > 0 {
                        BannerKind::Warning
                    } else {
                        BannerKind::Success
                    },
                    message: msg,
                });
                self.confirm_modal = None;
            }

            WorkerEvent::InsightRecycleFinished {
                path,
                freed_bytes: _,
                dry_run,
            } => {
                self.is_recycling = false;
                if !dry_run {
                    self.prune_recycled_insight(&path);
                }
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Success,
                    message: format!(
                        "{}: {}",
                        if dry_run {
                            "Dry-run checked Recycle Bin target"
                        } else {
                            "Moved to Recycle Bin"
                        },
                        path.display()
                    ),
                });
                self.confirm_modal = None;
            }

            WorkerEvent::JobProgress(prog) => match prog {
                WorkerProgress::Scan(phase, done, total) => {
                    self.scan_progress = Some((phase, done, total));
                }
                WorkerProgress::Clean(cp) => {
                    self.clean_progress = Some(cp);
                }
            },

            WorkerEvent::JobError { lane, message } => {
                match lane {
                    JobLane::Heavy => {
                        if self.is_optimizing {
                            // A failed optimizer may still have changed system state.
                            self.invalidate_optimizer_probe();
                        }
                        self.pending_dupe_group = None;
                        self.clear_heavy_flags();
                    }
                    JobLane::History => {
                        self.is_loading_history = false;
                    }
                    JobLane::Growth => {
                        self.is_loading_growth = false;
                    }
                    JobLane::Drives => {
                        self.is_refreshing_drives = false;
                    }
                    JobLane::Optimizers => {
                        // Stays "attempted": a failing probe is reported once, not retried
                        // every frame.
                        self.is_probing_optimizers = false;
                        self.optimizers_probe_error = Some(message.clone());
                    }
                    JobLane::Helper => {
                        self.is_connecting_helper = false;
                    }
                    JobLane::Videos => self.videos.clear_busy(),
                }
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Error,
                    message,
                });
            }

            WorkerEvent::JobCancelled(lane) => {
                let mut message = "Job cancelled".to_string();
                match lane {
                    JobLane::Heavy => {
                        if self.is_optimizing {
                            self.invalidate_optimizer_probe();
                        }
                        self.pending_dupe_group = None;
                        self.clear_heavy_flags();
                    }
                    JobLane::History => {
                        self.is_loading_history = false;
                    }
                    JobLane::Growth => {
                        self.is_loading_growth = false;
                    }
                    JobLane::Drives => {
                        self.is_refreshing_drives = false;
                    }
                    JobLane::Optimizers => {
                        self.is_probing_optimizers = false;
                    }
                    JobLane::Helper => {
                        self.is_connecting_helper = false;
                        message = "Administrator unlock cancelled (the UAC prompt was declined)."
                            .to_string();
                    }
                    JobLane::Videos => self.videos.clear_busy(),
                }
                self.status_banner = Some(StatusBanner {
                    kind: BannerKind::Info,
                    message,
                });
            }
        }
    }

    /// Polls all pending events from `worker` and applies them to `self`.
    pub fn poll_worker(&mut self, worker: &mut WorkerHandle) {
        while let Some(event) = worker.poll() {
            self.apply_worker_event(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsk_core::clean::{
        CleanPlan, PlannedItem, PlannedRoot, PlannedRule, PreconditionRule, RuleTier,
    };
    use dsk_core::index::builder::{EntryBatch, IndexBuilder, RawEntry};
    use dsk_core::index::names::NameArena;
    use dsk_core::{NodeFlags, ScanMethod};
    use rustc_hash::FxHashSet;

    fn make_test_entry(
        names: &mut NameArena,
        key: u64,
        parent_key: u64,
        name: &str,
        flags: NodeFlags,
        alloc: u64,
    ) -> RawEntry {
        let name_ref = names.push_str(name);
        RawEntry {
            key,
            parent_key,
            name: name_ref,
            flags,
            logical: alloc,
            allocated: alloc,
            mtime: 0,
            atime: 0,
            file_id: key,
            reparse_tag: 0,
        }
    }

    #[test]
    fn checkbox_selection_updates_filtered_plan_and_confirm_bytes() {
        let mut state = AppState::new();

        // 1. Create a raw CleanPlan with 2 rules: rule_a (100MB) and rule_b (50MB)
        let rule_a = PlannedRule {
            rule_id: "rule_a".to_string(),
            name: "Rule A".to_string(),
            category: "dev".to_string(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            method: dsk_core::clean::RuleMethod::DeleteContents,
            preconditions: PreconditionRule::default(),
            explain: "Explain A".to_string(),
            est_bytes: 100 * 1024 * 1024,
            item_count: 2,
            roots: vec![PlannedRoot {
                root_path: r"C:\cache_a".to_string(),
                root_file_id: 1,
                file_id_kind: dsk_core::FileIdKind::NtfsFrn64,
                min_age_days: None,
                exclude_names: Vec::new(),
                allow_unlisted_children: false,
                items: vec![
                    PlannedItem {
                        rel_path: "f1.tmp".to_string(),
                        expected_file_id: 10,
                        bytes: 50 * 1024 * 1024,
                        is_dir: false,
                        mtime_min: 0,
                    },
                    PlannedItem {
                        rel_path: "f2.tmp".to_string(),
                        expected_file_id: 11,
                        bytes: 50 * 1024 * 1024,
                        is_dir: false,
                        mtime_min: 0,
                    },
                ],
            }],
            os_handler_bytes: None,
            estimate: Default::default(),
        };

        let rule_b = PlannedRule {
            rule_id: "rule_b".to_string(),
            name: "Rule B".to_string(),
            category: "apps".to_string(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            method: dsk_core::clean::RuleMethod::DeleteContents,
            preconditions: PreconditionRule::default(),
            explain: "Explain B".to_string(),
            est_bytes: 50 * 1024 * 1024,
            item_count: 1,
            roots: vec![PlannedRoot {
                root_path: r"C:\cache_b".to_string(),
                root_file_id: 2,
                file_id_kind: dsk_core::FileIdKind::NtfsFrn64,
                min_age_days: None,
                exclude_names: Vec::new(),
                allow_unlisted_children: false,
                items: vec![PlannedItem {
                    rel_path: "b.tmp".to_string(),
                    expected_file_id: 20,
                    bytes: 50 * 1024 * 1024,
                    is_dir: false,
                    mtime_min: 0,
                }],
            }],
            os_handler_bytes: None,
            estimate: Default::default(),
        };

        let raw_plan = CleanPlan {
            version: 1,
            scanned_path: r"C:\".to_string(),
            volume_root: r"C:\".to_string(),
            scan_method: ScanMethod::Auto,
            total_est_bytes: 150 * 1024 * 1024,
            rules: vec![rule_a, rule_b],
            skipped: Vec::new(),
        };

        let preconditions = SystemPreconditions {
            elevated: true,
            running_processes: FxHashSet::default(),
            servicing_reason: None,
            battery_pct: Some(80),
            on_ac_power: true,
        };

        assert!(!state.effective_elevated(false));
        assert!(state.effective_elevated(true));
        state.apply_worker_event(WorkerEvent::HelperConnected);
        assert!(state.effective_elevated(false));

        let mut holders = FxHashMap::default();
        holders.insert("rule_a".to_string(), vec!["locker.exe".to_string()]);

        // Emit PlanFinished event
        state.apply_worker_event(WorkerEvent::PlanFinished {
            plan: raw_plan,
            preconditions,
            helper_plan_id: Some("plan-123".to_string()),
            locked_holders: holders,
        });

        assert_eq!(state.helper_plan_id.as_deref(), Some("plan-123"));
        assert_eq!(
            state.locked_holders.get("rule_a").map(Vec::as_slice),
            Some(&["locker.exe".to_string()][..])
        );

        // Initially both rules should be selected by default
        assert_eq!(state.selected_rules.len(), 2);
        assert!(state.selected_rules.contains("rule_a"));
        assert!(state.selected_rules.contains("rule_b"));

        // Confirm action with both selected
        let confirm = state.prepare_clean_confirm(false).expect("confirm action");
        match confirm {
            ConfirmAction::CleanRules {
                rule_count,
                item_count,
                total_est_bytes,
                dry_run,
                selected_rule_ids,
            } => {
                assert_eq!(rule_count, 2);
                assert_eq!(item_count, 3);
                assert_eq!(total_est_bytes, 150 * 1024 * 1024);
                assert!(!dry_run);
                assert_eq!(selected_rule_ids.len(), 2);
            }
            _ => panic!("unexpected confirm variant"),
        }

        // Uncheck rule_b
        state.toggle_rule("rule_b");
        assert_eq!(state.selected_rules.len(), 1);
        assert!(!state.selected_rules.contains("rule_b"));

        // Confirm action now reflects only rule_a
        let confirm_uncheck = state.prepare_clean_confirm(true).expect("confirm action");
        match confirm_uncheck {
            ConfirmAction::CleanRules {
                rule_count,
                item_count,
                total_est_bytes,
                dry_run,
                selected_rule_ids,
            } => {
                assert_eq!(rule_count, 1);
                assert_eq!(item_count, 2);
                assert_eq!(total_est_bytes, 100 * 1024 * 1024);
                assert!(dry_run);
                assert_eq!(selected_rule_ids, vec!["rule_a".to_string()]);
            }
            _ => panic!("unexpected confirm variant"),
        }
    }

    #[test]
    fn recycle_confirm_blocks_denied_cloud_offline_and_drive_root_paths() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(
                &mut names,
                10,
                5,
                "normal.txt",
                NodeFlags::empty(),
                1024 * 1024,
            ),
            make_test_entry(
                &mut names,
                20,
                5,
                "cloud.dat",
                NodeFlags::CLOUD,
                5 * 1024 * 1024,
            ),
            make_test_entry(
                &mut names,
                30,
                5,
                "offline.dat",
                NodeFlags::OFFLINE,
                2 * 1024 * 1024,
            ),
            make_test_entry(
                &mut names,
                40,
                5,
                "reparse_dir",
                NodeFlags::DIR | NodeFlags::REPARSE,
                0,
            ),
            make_test_entry(&mut names, 50, 5, "Windows", NodeFlags::DIR, 0),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let report = Arc::new(ScanReport {
            index,
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(10),
            skipped: 0,
            check: None,
            fallback_reason: None,
        });

        let mut state = AppState::new();
        state.apply_worker_event(WorkerEvent::ScanFinished(report));

        let normal_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\normal.txt"))
            .unwrap();
        let cloud_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\cloud.dat"))
            .unwrap();
        let offline_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\offline.dat"))
            .unwrap();
        let reparse_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\reparse_dir"))
            .unwrap();
        let windows_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\Windows"))
            .unwrap();

        // 1. Root node must be blocked
        let root_confirm = state.prepare_recycle_confirm(ROOT).unwrap();
        if let ConfirmAction::RecycleTarget { blocked_reason, .. } = root_confirm {
            assert!(blocked_reason.is_some());
            assert!(blocked_reason.unwrap().contains("root"));
        }

        // 2. Normal file must be allowed
        let normal_confirm = state.prepare_recycle_confirm(normal_id).unwrap();
        if let ConfirmAction::RecycleTarget { blocked_reason, .. } = normal_confirm {
            assert_eq!(blocked_reason, None);
        }

        // 3. Cloud placeholder must be blocked
        let cloud_confirm = state.prepare_recycle_confirm(cloud_id).unwrap();
        if let ConfirmAction::RecycleTarget { blocked_reason, .. } = cloud_confirm {
            assert!(blocked_reason.is_some());
        }

        // 4. Offline node must be blocked
        let offline_confirm = state.prepare_recycle_confirm(offline_id).unwrap();
        if let ConfirmAction::RecycleTarget { blocked_reason, .. } = offline_confirm {
            assert!(blocked_reason.is_some());
        }

        // 5. Reparse point must be blocked
        let reparse_confirm = state.prepare_recycle_confirm(reparse_id).unwrap();
        if let ConfirmAction::RecycleTarget { blocked_reason, .. } = reparse_confirm {
            assert!(blocked_reason.is_some());
        }

        // 6. Denied path (C:\Windows) must be blocked
        let win_confirm = state.prepare_recycle_confirm(windows_id).unwrap();
        if let ConfirmAction::RecycleTarget { blocked_reason, .. } = win_confirm {
            assert!(blocked_reason.is_some());
            assert!(blocked_reason.unwrap().contains("Protected"));
        }
    }

    #[test]
    fn scan_and_clean_events_update_ledger_and_invalidate_treemap() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "dir", NodeFlags::DIR, 0),
            make_test_entry(
                &mut names,
                11,
                10,
                "file1.dat",
                NodeFlags::empty(),
                100 * 1024 * 1024,
            ),
            make_test_entry(
                &mut names,
                12,
                10,
                "file2.dat",
                NodeFlags::empty(),
                50 * 1024 * 1024,
            ),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let report = Arc::new(ScanReport {
            index,
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(10),
            skipped: 0,
            check: None,
            fallback_reason: None,
        });

        let mut state = AppState::new();
        state.apply_worker_event(WorkerEvent::ScanFinished(report));

        let vp = [0.0, 0.0, 800.0, 600.0];
        state.ensure_explore_caches(vp, 5);
        assert_eq!(state.treemap_layout.leaf_rects, 2);
        let initial_mesh_vlen = state.treemap_mesh.vertices.len();
        assert!(initial_mesh_vlen > 0);

        // Hovering a node should ONLY update cushion mesh without changing layout
        let file1_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir\file1.dat"))
            .unwrap();
        state.hovered_node = Some(file1_id);
        state.ensure_explore_caches(vp, 5);
        // Treemap layout items count unchanged
        assert_eq!(state.treemap_layout.leaf_rects, 2);

        // Now simulate live CleanFinished deleting file1.dat
        let clean_report = CleanReport {
            run_id: "test-run-1".to_string(),
            volume: r"C:\".to_string(),
            dry_run: false,
            est_bytes: 100 * 1024 * 1024,
            est_deleted_bytes: 100 * 1024 * 1024,
            before_free_bytes: 1_000_000,
            after_free_bytes: 1_000_000 + 100 * 1024 * 1024,
            freed_measured: 100 * 1024 * 1024,
            items_ok: 1,
            items_skipped: 0,
            items_failed: 0,
            rule_summaries: Vec::new(),
            skipped_rules: Vec::new(),
            restore_point: None,
        };

        let initial_gen = state.ledger.generation;
        let file2_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir\file2.dat"))
            .unwrap();

        state.apply_worker_event(WorkerEvent::CleanFinished {
            report: clean_report,
            ledger_deltas: vec![(file1_id, 100 * 1024 * 1024)],
        });

        assert_eq!(state.ledger.generation, initial_gen + 1);
        assert!(state.children_cache.is_empty());

        // Ensure caches recomputed with updated ledger
        state.ensure_explore_caches(vp, 5);
        // Now only file2.dat remains in layout
        assert_eq!(state.treemap_layout.leaf_rects, 1);
        assert_eq!(state.treemap_layout.items[0].node_id, Some(file2_id));
    }

    #[test]
    fn explore_zoom_and_history_back_stack_roundtrip() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "dir_a", NodeFlags::DIR, 0),
            make_test_entry(&mut names, 20, 10, "subdir_b", NodeFlags::DIR, 0),
            make_test_entry(
                &mut names,
                21,
                20,
                "file_c.txt",
                NodeFlags::empty(),
                1024 * 1024,
            ),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let report = Arc::new(ScanReport {
            index,
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(10),
            skipped: 0,
            check: None,
            fallback_reason: None,
        });

        let mut state = AppState::new();
        state.apply_worker_event(WorkerEvent::ScanFinished(report));

        assert_eq!(state.zoom_root, ROOT);
        assert!(state.history_stack.is_empty());

        let dir_a = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_a"))
            .unwrap();
        let subdir_b = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_a\subdir_b"))
            .unwrap();

        // Zoom into dir_a
        state.zoom_into(dir_a);
        assert_eq!(state.zoom_root, dir_a);
        assert_eq!(state.history_stack, vec![ROOT]);

        // Zoom into subdir_b
        state.zoom_into(subdir_b);
        assert_eq!(state.zoom_root, subdir_b);
        assert_eq!(state.history_stack, vec![ROOT, dir_a]);

        // Navigate back to dir_a
        assert!(state.navigate_back());
        assert_eq!(state.zoom_root, dir_a);
        assert_eq!(state.history_stack, vec![ROOT]);

        // Navigate back to ROOT
        assert!(state.navigate_back());
        assert_eq!(state.zoom_root, ROOT);
        assert!(state.history_stack.is_empty());

        // Navigate back when empty returns false
        assert!(!state.navigate_back());

        // Zoom into subdir_b again and test navigate_up
        state.zoom_into(subdir_b);
        assert_eq!(state.zoom_root, subdir_b);
        assert!(state.navigate_up());
        assert_eq!(state.zoom_root, dir_a);

        // Recycle the active zoom_root: should automatically navigate up
        let recycle_outcome = dsk_core::RecycleOutcome {
            path: r"C:\dir_a".to_string(),
            canonical_path: r"\\?\C:\dir_a".to_string(),
            bytes_hint: 1024 * 1024,
        };
        state.apply_worker_event(WorkerEvent::RecycleFinished {
            node_id: dir_a,
            outcome: recycle_outcome,
            run_id: "rec-1".to_string(),
            journal_warning: None,
        });
        // zoom_root navigated up from removed dir_a to ROOT
        assert_eq!(state.zoom_root, ROOT);
    }

    #[test]
    fn tree_cache_rebuilds_on_expand_collapse() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "folder", NodeFlags::DIR, 0),
            make_test_entry(&mut names, 11, 10, "child.txt", NodeFlags::empty(), 1024),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let report = Arc::new(ScanReport {
            index,
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(10),
            skipped: 0,
            check: None,
            fallback_reason: None,
        });

        let mut state = AppState::new();
        state.apply_worker_event(WorkerEvent::ScanFinished(report));

        let vp = [0.0, 0.0, 800.0, 600.0];
        state.ensure_explore_caches(vp, 5);

        // Initially collapsed: only 1 row (folder)
        assert_eq!(state.tree_model.rows.len(), 1);
        assert_eq!(state.tree_model.rows[0].name, "folder");

        let folder_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\folder"))
            .unwrap();

        // Expand folder
        state.tree_model.expanded.insert(folder_id);
        state.ensure_explore_caches(vp, 5);

        // Now rebuilt with 2 rows (folder + child.txt)
        assert_eq!(state.tree_model.rows.len(), 2);
        assert_eq!(state.tree_model.rows[1].name, "child.txt");

        // Collapse folder
        state.tree_model.expanded.remove(&folder_id);
        state.ensure_explore_caches(vp, 5);

        // Rebuilt back to 1 row
        assert_eq!(state.tree_model.rows.len(), 1);
    }

    #[test]
    fn clean_and_recycle_finished_recover_zoom_root_and_history_from_deleted_ancestor() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "dir_a", NodeFlags::DIR, 0),
            make_test_entry(&mut names, 20, 10, "subdir_b", NodeFlags::DIR, 0),
            make_test_entry(
                &mut names,
                21,
                20,
                "file_c.txt",
                NodeFlags::empty(),
                1024 * 1024,
            ),
            make_test_entry(&mut names, 30, 5, "dir_x", NodeFlags::DIR, 0),
            make_test_entry(&mut names, 40, 30, "subdir_y", NodeFlags::DIR, 0),
            make_test_entry(
                &mut names,
                41,
                40,
                "file_z.txt",
                NodeFlags::empty(),
                2 * 1024 * 1024,
            ),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let report = Arc::new(ScanReport {
            index,
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(10),
            skipped: 0,
            check: None,
            fallback_reason: None,
        });

        let mut state = AppState::new();
        state.apply_worker_event(WorkerEvent::ScanFinished(report));

        let dir_a = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_a"))
            .unwrap();
        let subdir_b = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_a\subdir_b"))
            .unwrap();
        let file_c = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_a\subdir_b\file_c.txt"))
            .unwrap();

        // Zoom deep into subdir_b
        state.zoom_into(dir_a);
        state.zoom_into(subdir_b);
        assert_eq!(state.zoom_root, subdir_b);
        assert_eq!(state.history_stack, vec![ROOT, dir_a]);
        state.selected_node = Some(file_c);
        state.hovered_node = Some(file_c);

        // Recycle dir_a (the ancestor of current zoom_root subdir_b and selected file_c)
        let recycle_outcome = dsk_core::RecycleOutcome {
            path: r"C:\dir_a".to_string(),
            canonical_path: r"\\?\C:\dir_a".to_string(),
            bytes_hint: 1024 * 1024,
        };
        state.apply_worker_event(WorkerEvent::RecycleFinished {
            node_id: dir_a,
            outcome: recycle_outcome,
            run_id: "rec-1".to_string(),
            journal_warning: None,
        });

        // Navigation should be recovered to ROOT, history pruned, selection cleared
        assert_eq!(state.zoom_root, ROOT);
        assert!(state.history_stack.is_empty());
        assert_eq!(state.selected_node, None);
        assert_eq!(state.hovered_node, None);

        // Now test CleanFinished recovering from deleted ancestor
        let dir_x = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_x"))
            .unwrap();
        let subdir_y = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_x\subdir_y"))
            .unwrap();
        let file_z = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir_x\subdir_y\file_z.txt"))
            .unwrap();

        state.zoom_into(dir_x);
        state.zoom_into(subdir_y);
        assert_eq!(state.zoom_root, subdir_y);
        assert_eq!(state.history_stack, vec![ROOT, dir_x]);
        state.selected_node = Some(file_z);
        state.hovered_node = Some(file_z);

        let clean_report = CleanReport {
            run_id: "clean-run-2".to_string(),
            volume: r"C:\".to_string(),
            dry_run: false,
            est_bytes: 2 * 1024 * 1024,
            est_deleted_bytes: 2 * 1024 * 1024,
            before_free_bytes: 1_000_000,
            after_free_bytes: 1_000_000 + 2 * 1024 * 1024,
            freed_measured: 2 * 1024 * 1024,
            items_ok: 1,
            items_skipped: 0,
            items_failed: 0,
            rule_summaries: Vec::new(),
            skipped_rules: Vec::new(),
            restore_point: None,
        };

        // Clean deletes dir_x
        state.apply_worker_event(WorkerEvent::CleanFinished {
            report: clean_report,
            ledger_deltas: vec![(dir_x, 2 * 1024 * 1024)],
        });

        // Navigation should be recovered to ROOT, history pruned, selection cleared
        assert_eq!(state.zoom_root, ROOT);
        assert!(state.history_stack.is_empty());
        assert_eq!(state.selected_node, None);
        assert_eq!(state.hovered_node, None);
    }

    #[test]
    fn recycle_finished_with_journal_warning_still_updates_ledger_and_warns() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "dir", NodeFlags::DIR, 0),
            make_test_entry(&mut names, 11, 10, "target.dat", NodeFlags::empty(), 5000),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let report = Arc::new(ScanReport {
            index,
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(10),
            skipped: 0,
            check: None,
            fallback_reason: None,
        });

        let mut state = AppState::new();
        state.apply_worker_event(WorkerEvent::ScanFinished(report));

        let target_id = state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\dir\target.dat"))
            .unwrap();

        // Set confirm modal
        state.confirm_modal = state.prepare_recycle_confirm(target_id);
        assert!(state.confirm_modal.is_some());

        let recycle_outcome = dsk_core::RecycleOutcome {
            path: r"C:\dir\target.dat".to_string(),
            canonical_path: r"\\?\C:\dir\target.dat".to_string(),
            bytes_hint: 5000,
        };

        // Emit RecycleFinished with journal warning
        state.apply_worker_event(WorkerEvent::RecycleFinished {
            node_id: target_id,
            outcome: recycle_outcome,
            run_id: String::new(),
            journal_warning: Some("Failed to record journal entry".to_string()),
        });

        // 1. Modal must be closed
        assert!(state.confirm_modal.is_none());

        // 2. Ledger must record deletion despite journal error
        let sr = state.scan_report.as_ref().unwrap();
        assert!(state.ledger.is_removed_or_ancestor(&sr.index, target_id));

        // 3. Children cache must be cleared
        assert!(state.children_cache.is_empty());

        // 4. Status banner must reflect warning
        assert_eq!(
            state.status_banner,
            Some(StatusBanner {
                kind: BannerKind::Warning,
                message: "Failed to record journal entry".to_string(),
            })
        );
    }

    #[test]
    fn gui_tier_filter_toggles_review_and_advanced_rules_and_updates_confirm_modal() {
        let mut state = AppState::new();

        let rule_safe = PlannedRule {
            rule_id: "rule_safe".to_string(),
            name: "Safe Rule".to_string(),
            category: "system".to_string(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            method: dsk_core::clean::RuleMethod::DeleteContents,
            preconditions: PreconditionRule::default(),
            explain: "Safe".to_string(),
            est_bytes: 10 * 1024 * 1024,
            item_count: 1,
            roots: Vec::new(),
            os_handler_bytes: None,
            estimate: Default::default(),
        };

        let rule_review = PlannedRule {
            rule_id: "rule_review".to_string(),
            name: "Review Rule".to_string(),
            category: "system".to_string(),
            tier: RuleTier::Review,
            regenerable: true,
            requires_admin: true,
            method: dsk_core::clean::RuleMethod::DeleteContents,
            preconditions: PreconditionRule::default(),
            explain: "Review".to_string(),
            est_bytes: 20 * 1024 * 1024,
            item_count: 1,
            roots: Vec::new(),
            os_handler_bytes: None,
            estimate: Default::default(),
        };

        let rule_advanced = PlannedRule {
            rule_id: "rule_advanced".to_string(),
            name: "Advanced Rule".to_string(),
            category: "system".to_string(),
            tier: RuleTier::Advanced,
            regenerable: false,
            requires_admin: true,
            method: dsk_core::clean::RuleMethod::DeleteContents,
            preconditions: PreconditionRule::default(),
            explain: "Advanced".to_string(),
            est_bytes: 30 * 1024 * 1024,
            item_count: 1,
            roots: Vec::new(),
            os_handler_bytes: None,
            estimate: Default::default(),
        };

        let plan = CleanPlan {
            version: 1,
            volume_root: r"C:\".to_string(),
            scanned_path: r"C:\".to_string(),
            scan_method: ScanMethod::Dir,
            rules: vec![rule_safe, rule_review, rule_advanced],
            skipped: Vec::new(),
            total_est_bytes: 60 * 1024 * 1024,
        };

        state.raw_plan = Some(plan);

        // 1. Initially select Safe only
        state.selected_rules.clear();
        state.selected_rules.insert("rule_safe".to_string());
        let confirm_safe = state.prepare_clean_confirm(false).unwrap();
        match confirm_safe {
            ConfirmAction::CleanRules {
                rule_count,
                total_est_bytes,
                ..
            } => {
                assert_eq!(rule_count, 1);
                assert_eq!(total_est_bytes, 10 * 1024 * 1024);
            }
            _ => panic!("expected CleanRules confirm action"),
        }

        // 2. Select Review
        state.selected_rules.insert("rule_review".to_string());
        let confirm_review = state.prepare_clean_confirm(false).unwrap();
        match confirm_review {
            ConfirmAction::CleanRules {
                rule_count,
                total_est_bytes,
                ..
            } => {
                assert_eq!(rule_count, 2);
                assert_eq!(total_est_bytes, 30 * 1024 * 1024);
            }
            _ => panic!("expected CleanRules confirm action"),
        }

        // 3. Select Advanced
        state.selected_rules.insert("rule_advanced".to_string());
        let confirm_adv = state.prepare_clean_confirm(false).unwrap();
        match confirm_adv {
            ConfirmAction::CleanRules {
                rule_count,
                total_est_bytes,
                ..
            } => {
                assert_eq!(rule_count, 3);
                assert_eq!(total_est_bytes, 60 * 1024 * 1024);
            }
            _ => panic!("expected CleanRules confirm action"),
        }
    }

    fn tiny_report() -> Arc<ScanReport> {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![make_test_entry(
            &mut names,
            10,
            5,
            "f.bin",
            NodeFlags::empty(),
            4096,
        )];
        b.push_batch(EntryBatch { names, entries });
        Arc::new(ScanReport {
            index: b.finish(),
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(1),
            skipped: 0,
            check: None,
            fallback_reason: None,
        })
    }

    /// P9.1/P9.10: "Find space" is a Heavy job with its own busy flag, cleared when superseded,
    /// and the removable color mode only applies once hunt verdicts exist.
    #[test]
    fn find_space_job_flags_and_removable_mode() {
        let mut state = AppState::new();
        let mut worker = WorkerHandle::new_inert();
        let sr = tiny_report();
        state.scan_report = Some(sr.clone());

        state.spawn_job(
            &mut worker,
            WorkerJob::BuildReclaim {
                scan_report: sr.clone(),
                journal_path: None,
            },
        );
        assert!(state.is_reclaim_running && state.heavy_busy());
        assert_eq!(state.heavy_activity_label(), Some("Finding space..."));

        state.spawn_job(
            &mut worker,
            WorkerJob::RunInsights {
                scan_report: sr,
                opts: dsk_core::insights::InsightsOptions::default(),
            },
        );
        assert!(!state.is_reclaim_running, "superseded job clears its flag");

        // Without verdicts the color mode is a no-op: the layout key ignores it.
        state.explore_color_removable = true;
        state.ensure_explore_caches([0.0, 0.0, 400.0, 300.0], 3);
        assert_eq!(state.cached_layout_keys.map(|k| k.5), Some(false));
    }

    #[test]
    fn superseding_a_heavy_job_never_leaves_a_stale_spinner() {
        let mut state = AppState::new();
        let mut worker = WorkerHandle::new_inert();
        let sr = tiny_report();

        state.spawn_job(
            &mut worker,
            WorkerJob::RunInsights {
                scan_report: sr.clone(),
                opts: dsk_core::insights::InsightsOptions::default(),
            },
        );
        assert!(state.is_insights_running && state.heavy_busy());

        // The insights job is superseded; its InsightsFinished will be discarded by the worker,
        // so its flag must be cleared now or the spinner would spin forever.
        state.spawn_job(
            &mut worker,
            WorkerJob::FindDuplicates {
                scan_report: sr,
                min_bytes: 1,
                cache_db_path: None,
            },
        );
        assert!(!state.is_insights_running);
        assert!(state.is_dupes_running);
        assert_eq!(state.heavy_activity_label(), Some("Finding duplicates..."));

        state.apply_worker_event(WorkerEvent::JobCancelled(JobLane::Heavy));
        assert!(!state.heavy_busy());
        assert!(!state.any_job_active());

        // Non-heavy lanes never clear heavy flags (a UAC prompt does not cancel a clean).
        state.spawn_job(
            &mut worker,
            WorkerJob::ExecuteClean {
                plan: CleanPlan {
                    version: 1,
                    scanned_path: r"C:\".to_string(),
                    volume_root: r"C:\".to_string(),
                    scan_method: ScanMethod::Dir,
                    total_est_bytes: 0,
                    rules: Vec::new(),
                    skipped: Vec::new(),
                },
                selected_rule_ids: Vec::new(),
                dry_run: true,
                force_battery: false,
                journal_path: None,
                scan_report: None,
                use_helper: false,
                helper_plan_id: None,
            },
        );
        state.spawn_job(&mut worker, WorkerJob::ConnectHelper);
        assert!(state.is_cleaning && state.is_connecting_helper);
        state.apply_worker_event(WorkerEvent::JobCancelled(JobLane::Helper));
        assert!(state.is_cleaning, "helper cancel leaves the clean running");
        assert!(!state.is_connecting_helper);
        assert_eq!(worker.lane_spawn_count(JobLane::Heavy), 3);
        assert_eq!(worker.lane_spawn_count(JobLane::Helper), 1);
    }

    #[test]
    fn plan_finished_clears_planning_and_refreshes_cached_effective_plan() {
        let mut state = AppState::new();
        let mut worker = WorkerHandle::new_inert();
        state.spawn_job(
            &mut worker,
            WorkerJob::BuildPlan {
                report: tiny_report(),
                include_recycle_bin: false,
                max_tier: RuleTier::Safe,
                use_helper: false,
            },
        );
        assert!(state.is_planning);
        let mk_plan = |bytes: u64| CleanPlan {
            version: 1,
            scanned_path: r"C:\".to_string(),
            volume_root: r"C:\".to_string(),
            scan_method: ScanMethod::Dir,
            total_est_bytes: bytes,
            rules: Vec::new(),
            skipped: Vec::new(),
        };
        let pre = SystemPreconditions {
            elevated: false,
            running_processes: FxHashSet::default(),
            servicing_reason: None,
            battery_pct: None,
            on_ac_power: true,
        };
        state.apply_worker_event(WorkerEvent::PlanFinished {
            plan: mk_plan(100),
            preconditions: pre.clone(),
            helper_plan_id: None,
            locked_holders: FxHashMap::default(),
        });
        assert!(!state.is_planning);
        let a = state.effective_plan_shared().unwrap();
        let b = state.effective_plan_shared().unwrap();
        assert!(Arc::ptr_eq(&a, &b), "cache hit: no per-frame clone");
        state.apply_worker_event(WorkerEvent::PlanFinished {
            plan: mk_plan(200),
            preconditions: pre,
            helper_plan_id: None,
            locked_holders: FxHashMap::default(),
        });
        let c = state.effective_plan_shared().unwrap();
        assert!(!Arc::ptr_eq(&a, &c), "a new plan invalidates the cache");
    }

    #[test]
    fn recycled_insight_rows_and_remediated_dupe_groups_disappear() {
        use dsk_core::insights::{
            DupFileEntry, DupeRemediationOutcome, DupeStats, ProjectArtifactCandidate,
            ProjectEcosystem,
        };
        let mut state = AppState::new();
        let mut worker = WorkerHandle::new_inert();
        let mut report = FullInsightsReport::default();
        for name in ["a", "b"] {
            report.projects.artifacts.push(ProjectArtifactCandidate {
                ecosystem: ProjectEcosystem::Rust,
                project_name: name.to_string(),
                project_root: PathBuf::from(format!(r"C:\dev\{name}")),
                artifact_path: PathBuf::from(format!(r"C:\dev\{name}\target")),
                marker_evidence: "Cargo.toml".to_string(),
                allocated_bytes: 1,
                reclaimable_bytes: 1,
                hardlink_shared_bytes: 0,
                file_count: 1,
                days_since_modified: 1,
            });
        }
        state.insights_report = Some(report);
        state.is_recycling = true;
        state.apply_worker_event(WorkerEvent::InsightRecycleFinished {
            path: PathBuf::from(r"C:\dev\a\target"),
            freed_bytes: 1,
            dry_run: false,
        });
        assert!(!state.is_recycling);
        let arts = &state.insights_report.as_ref().unwrap().projects.artifacts;
        assert_eq!(arts.len(), 1, "recycled artifact is no longer offered");
        assert_eq!(arts[0].project_name, "b");

        let entry = |n: u32| DupFileEntry {
            node_id: n,
            path: PathBuf::from(format!(r"C:\d\{n}.bin")),
            file_id: u64::from(n),
            logical_bytes: 1,
            allocated_bytes: 1,
            mtime_min: 1,
            atime_min: 1,
            hardlinked: false,
        };
        let group = |hex: &str| DuplicateGroup {
            blake3_hex: hex.to_string(),
            file_size: 1,
            files: vec![entry(1), entry(2)],
            reclaimable_bytes: 1,
        };
        state.dupes_report = Some(DupeReport {
            volume_root: r"C:\".to_string(),
            min_bytes: 1,
            groups: vec![group("aa"), group("bb")],
            total_wasted_bytes: 2,
            stats: DupeStats::default(),
        });
        state.spawn_job(
            &mut worker,
            WorkerJob::RemediateDuplicates {
                group: group("aa"),
                keep_index: 0,
                action: DupeRemediationAction::RecycleDuplicates,
                dry_run: false,
                journal_path: None,
                volume_root: r"C:\".to_string(),
            },
        );
        state.apply_worker_event(WorkerEvent::DupeRemediationFinished(
            DupeRemediationOutcome {
                dry_run: false,
                action: DupeRemediationAction::RecycleDuplicates,
                processed: 1,
                skipped: 0,
                reclaimed_bytes: 1,
                notes: Vec::new(),
            },
        ));
        let groups = &state.dupes_report.as_ref().unwrap().groups;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].blake3_hex, "bb");
        assert!(!state.is_recycling);
    }
}
