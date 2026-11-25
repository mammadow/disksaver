//! Background worker coordinator for asynchronous scanning, plan building, clean execution, and history loading.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, Sender, unbounded};
use dsk_core::clean::{RelocationRecord, RuleTier};
use dsk_core::insights::{
    DupeProgress, DupeRemediationAction, DupeRemediationOutcome, DupeReport, DuplicateGroup,
    FullInsightsReport, InsightsOptions, default_hash_cache_path, find_duplicates,
    recycle_orphan_folder, remediate_duplicate_group, run_all_insights,
};
use dsk_core::optimize::{
    CloudDehydrateCandidate, OptimizerIntent, SystemTunablesStatus, VhdxCandidate, WofAlgorithm,
    WofSamplePreview, compact_vhdx, compress_folder_wof, dehydrate_cloud_file,
    discover_vhdx_candidates, execute_folder_relocation, find_hydrated_cloud_candidates,
    probe_sys_tunables, query_compact_os_state, run_optimizer_intent,
    sample_folder_compressibility, undo_folder_relocation,
};
use dsk_core::video::{
    BatchReport, CompressOptions, DiscoverOptions, HeldOriginal, PurgeReport, SampleResult,
    VideoDiscovery, VideoEngine, VideoJobOutcome, VideoProgress,
};
use dsk_core::{
    ActionJournal, CleanPlan, CleanProgress, CleanReport, DenyContext, ExecuteOptions, GrowthDb,
    GrowthReport, GrowthWindow, JournalEntryRecord, JournalRunRecord, NodeId, Phase, PlanOptions,
    Progress, RecycleOutcome, ScanMethod, ScanOptions, ScanReport, SystemPreconditions,
    build_plan_from_index, builtin_rules, connect_or_launch_helper, enrich_os_handler_estimates,
    execute_plan, helper_build_plan, helper_execute_plan_rules, helper_run_optimizer,
    helper_scan_volume, list_volumes, move_to_recycle_bin, probe_locked_roots, probe_preconditions,
    scan_volume, volume_root_of,
};
use rustc_hash::FxHashMap;

/// Execution lanes for independent background jobs.
///
/// Each lane runs at most one job; spawning a job supersedes (cancels) only the job on the same
/// lane. Read-only probes and the UAC helper connection get their own lanes so that opening the
/// Optimize tab or clicking "Unlock Admin" never cancels a running scan or cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobLane {
    Heavy = 0,
    Drives = 1,
    History = 2,
    Growth = 3,
    /// Read-only optimizer probe (vssadmin/DISM/powercfg/compact queries).
    Optimizers = 4,
    /// UAC prompt + elevated helper handshake.
    Helper = 5,
    /// Video compressor (P9.11): hours-long batches must not be cancelled by a scan.
    Videos = 6,
}

impl JobLane {
    pub const COUNT: usize = 7;
    pub const ALL: [JobLane; JobLane::COUNT] = [
        JobLane::Heavy,
        JobLane::Drives,
        JobLane::History,
        JobLane::Growth,
        JobLane::Optimizers,
        JobLane::Helper,
        JobLane::Videos,
    ];
}

/// High-level jobs executable by the background worker.
#[derive(Clone, Debug)]
pub enum WorkerJob {
    RefreshDrives,
    ScanTarget {
        path: PathBuf,
        method: ScanMethod,
        use_helper: bool,
        use_cache: bool,
        /// Growth rollup database (`None` = `%LOCALAPPDATA%\DiskSaver\growth.db`).
        growth_db_path: Option<PathBuf>,
    },
    BuildPlan {
        report: Arc<ScanReport>,
        include_recycle_bin: bool,
        max_tier: RuleTier,
        use_helper: bool,
    },
    ConnectHelper,
    ExecuteClean {
        plan: CleanPlan,
        selected_rule_ids: Vec<String>,
        dry_run: bool,
        force_battery: bool,
        journal_path: Option<PathBuf>,
        scan_report: Option<Arc<ScanReport>>,
        use_helper: bool,
        helper_plan_id: Option<String>,
    },
    RecycleNode {
        node_id: NodeId,
        path: PathBuf,
        index: Arc<ScanReport>,
        journal_path: Option<PathBuf>,
    },
    LoadHistory {
        journal_path: Option<PathBuf>,
        limit: usize,
        selected_run: Option<String>,
    },
    LoadGrowth {
        volume_root: String,
        window: GrowthWindow,
        db_path: Option<PathBuf>,
    },
    ProbeOptimizers {
        scan_report: Option<Arc<ScanReport>>,
        journal_path: Option<PathBuf>,
    },
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
    /// Administrator-level system optimizer (hiberfile, CompactOS, VSS, Reserved Storage).
    /// Runs in-process when elevated, otherwise through the elevated helper as an intent-only
    /// `RunOptimizer` request (§10.1).
    RunOptimizerIntent {
        intent: OptimizerIntent,
        dry_run: bool,
        use_helper: bool,
    },
    /// Dehydrates every listed in-sync cloud placeholder in ONE job. (Spawning one job per file
    /// on the single-slot Heavy lane cancelled all but the last file.)
    DehydrateCloudFiles {
        paths: Vec<PathBuf>,
        dry_run: bool,
    },
    /// 2% WOF compressibility sample (reads file contents, so it never runs on the UI thread).
    SampleWof {
        scan_report: Arc<ScanReport>,
        folder: PathBuf,
    },
    RelocateFolder {
        source: PathBuf,
        target_parent: PathBuf,
        journal_path: Option<PathBuf>,
    },
    UndoRelocation {
        id: String,
        journal_path: Option<PathBuf>,
    },
    RunInsights {
        scan_report: Arc<ScanReport>,
        opts: InsightsOptions,
    },
    FindDuplicates {
        scan_report: Arc<ScanReport>,
        min_bytes: u64,
        cache_db_path: Option<PathBuf>,
    },
    RemediateDuplicates {
        group: DuplicateGroup,
        keep_index: usize,
        action: DupeRemediationAction,
        dry_run: bool,
        journal_path: Option<PathBuf>,
        volume_root: String,
    },
    RecycleInsightPath {
        path: PathBuf,
        volume_root: String,
        dry_run: bool,
        journal_path: Option<PathBuf>,
    },
    /// P9.1 + P9.10: build the reclaim ledger and run the disk hunt on a finished scan.
    BuildReclaim {
        scan_report: Arc<ScanReport>,
        journal_path: Option<PathBuf>,
    },
    /// P9.11: locate ffmpeg and test which encoders work (a few seconds).
    ProbeVideoEngine,
    /// P9.11: scan `roots` and list videos worth compressing.
    FindVideos {
        roots: Vec<PathBuf>,
        opts: DiscoverOptions,
        engine: Option<Arc<VideoEngine>>,
        journal_path: Option<PathBuf>,
    },
    /// P9.11: encode a 30 s preview of one video and score it.
    SampleVideo {
        engine: Arc<VideoEngine>,
        path: PathBuf,
        opts: CompressOptions,
    },
    /// P9.11: compress the selected videos one after another.
    CompressVideos {
        engine: Arc<VideoEngine>,
        paths: Vec<PathBuf>,
        opts: CompressOptions,
    },
    /// P9.11: originals parked in "DiskSaver Originals" folders.
    LoadHeldVideos {
        journal_path: Option<PathBuf>,
    },
    /// P9.11: permanently delete held originals whose replacement is intact.
    PurgeHeldVideos {
        journal_path: Option<PathBuf>,
    },
}

/// Reclaim ledger plus disk hunt for one scan (P9.1, P9.10).
#[derive(Debug)]
pub struct ReclaimResult {
    pub assembled: dsk_core::ledger::assemble::Assembled,
    pub hunt: dsk_core::hunt::HuntReport,
    /// Hunt verdict per index node (Explore "Removable" coloring).
    pub verdicts: Vec<u8>,
}

impl WorkerJob {
    /// Categorizes a job into its non-interfering execution lane.
    pub fn lane(&self) -> JobLane {
        match self {
            WorkerJob::ScanTarget { .. }
            | WorkerJob::BuildPlan { .. }
            | WorkerJob::ExecuteClean { .. }
            | WorkerJob::RecycleNode { .. }
            | WorkerJob::CompactVhdx { .. }
            | WorkerJob::CompressFolder { .. }
            | WorkerJob::RunOptimizerIntent { .. }
            | WorkerJob::DehydrateCloudFiles { .. }
            | WorkerJob::SampleWof { .. }
            | WorkerJob::RelocateFolder { .. }
            | WorkerJob::UndoRelocation { .. }
            | WorkerJob::RunInsights { .. }
            | WorkerJob::FindDuplicates { .. }
            | WorkerJob::RemediateDuplicates { .. }
            | WorkerJob::RecycleInsightPath { .. }
            | WorkerJob::BuildReclaim { .. } => JobLane::Heavy,
            WorkerJob::RefreshDrives => JobLane::Drives,
            WorkerJob::LoadHistory { .. } => JobLane::History,
            WorkerJob::LoadGrowth { .. } => JobLane::Growth,
            WorkerJob::ProbeOptimizers { .. } => JobLane::Optimizers,
            WorkerJob::ConnectHelper => JobLane::Helper,
            WorkerJob::ProbeVideoEngine
            | WorkerJob::FindVideos { .. }
            | WorkerJob::SampleVideo { .. }
            | WorkerJob::CompressVideos { .. }
            | WorkerJob::LoadHeldVideos { .. }
            | WorkerJob::PurgeHeldVideos { .. } => JobLane::Videos,
        }
    }
}

/// Installed app and game folders for the hunt (same filter as the CLI).
fn hunt_installed_roots(
    index: &dsk_core::Index,
    assembled: &dsk_core::ledger::assemble::Assembled,
) -> Vec<dsk_core::hunt::InstalledRoot> {
    let norm = dsk_core::clean::deny::normalize_win_path_str;
    let pf = norm(&dsk_core::win::volume::program_files_dir());
    let pf86 = norm(&dsk_core::win::volume::program_files_x86_dir());
    let home = std::env::var_os("USERPROFILE").map(|h| norm(std::path::Path::new(&h)));
    let mut out = Vec::new();
    for app in dsk_core::win::prefetch::enumerate_installed_apps() {
        let Some(loc) = app.install_location else {
            continue;
        };
        let n = norm(&loc);
        if loc.components().count() < 3
            || n == pf
            || n == pf86
            || home.as_deref() == Some(n.as_str())
            || index.find_by_path(&loc).is_none()
        {
            continue;
        }
        out.push(dsk_core::hunt::InstalledRoot {
            path: loc,
            name: app.name,
            store: None,
        });
    }
    for g in &assembled.insights.gaming.games {
        out.push(dsk_core::hunt::InstalledRoot {
            path: g.install_path.clone(),
            name: g.title.clone(),
            store: Some(g.store.display_name().to_string()),
        });
    }
    out
}

/// Video compressor progress (P9.11).
#[derive(Clone, Debug, PartialEq)]
pub enum VideosProgress {
    /// Scanning a root: entries seen so far.
    Scanning(PathBuf, u64),
    /// Probing found videos: done / total.
    Inspecting(usize, usize),
    Compress(VideoProgress),
}

/// Progress updates emitted during active jobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerProgress {
    Scan(Phase, u64, u64),
    Clean(CleanProgress),
}

/// Events emitted from background workers back to the UI state machine.
#[derive(Clone, Debug)]
pub enum WorkerEvent {
    DrivesLoaded(Vec<dsk_core::VolumeInfo>),
    ScanFinished(Arc<ScanReport>),
    PlanFinished {
        plan: CleanPlan,
        preconditions: SystemPreconditions,
        helper_plan_id: Option<String>,
        locked_holders: FxHashMap<String, Vec<String>>,
    },
    CleanFinished {
        report: CleanReport,
        ledger_deltas: Vec<(NodeId, u64)>,
    },
    RecycleFinished {
        node_id: NodeId,
        outcome: RecycleOutcome,
        run_id: String,
        journal_warning: Option<String>,
    },
    HistoryLoaded(Vec<JournalRunRecord>),
    GrowthLoaded(GrowthReport),
    HelperConnected,
    RunEntriesLoaded {
        run_id: String,
        entries: Vec<JournalEntryRecord>,
    },
    OptimizersProbed {
        vhdx_candidates: Vec<VhdxCandidate>,
        cloud_candidates: Vec<CloudDehydrateCandidate>,
        tunables_status: SystemTunablesStatus,
        compact_os_state: Option<bool>,
        active_relocations: Vec<RelocationRecord>,
    },
    OptimizerFinished {
        message: String,
        /// Partial success (e.g. some files in a dehydrate batch failed): shown as a warning.
        warning: bool,
    },
    WofSampled {
        folder: PathBuf,
        result: Result<WofSamplePreview, String>,
    },
    JobProgress(WorkerProgress),
    JobError {
        lane: JobLane,
        message: String,
    },
    JobCancelled(JobLane),
    InsightsFinished(FullInsightsReport),
    ReclaimFinished(Arc<ReclaimResult>),
    DupesProgress(DupeProgress),
    DupesFinished(DupeReport),
    DupeRemediationFinished(DupeRemediationOutcome),
    InsightRecycleFinished {
        path: PathBuf,
        freed_bytes: u64,
        dry_run: bool,
    },
    VideoEngineProbed(Option<Arc<VideoEngine>>),
    VideosProgress(VideosProgress),
    VideosFound(Arc<VideoDiscovery>),
    VideoSampled {
        path: PathBuf,
        result: Result<SampleResult, String>,
    },
    VideoFileDone(VideoJobOutcome),
    VideosCompressed(BatchReport),
    HeldVideosLoaded(Result<Vec<HeldOriginal>, String>),
    HeldVideosPurged(Result<PurgeReport, String>),
}

#[derive(Debug)]
struct WorkerMessage {
    job_id: u64,
    lane: JobLane,
    event: WorkerEvent,
}

struct LaneState {
    active_cancel: Arc<AtomicBool>,
    active_job_id: u64,
    active_thread: Option<JoinHandle<()>>,
}

impl Default for LaneState {
    fn default() -> Self {
        Self {
            active_cancel: Arc::new(AtomicBool::new(false)),
            active_job_id: 0,
            active_thread: None,
        }
    }
}

/// Coordinator managing background job lifecycle, cancellation, and event delivery across
/// independent lanes.
pub struct WorkerHandle {
    tx_msg: Sender<WorkerMessage>,
    rx_msg: Receiver<WorkerMessage>,
    lanes: [LaneState; JobLane::COUNT],
    next_job_id: u64,
    spawn_counts: [u64; JobLane::COUNT],
    /// `false` for [`WorkerHandle::new_inert`]: jobs are counted but never executed.
    execute: bool,
    /// Jobs recorded (not run) by an inert worker, for test assertions.
    inert_jobs: Vec<WorkerJob>,
}

impl Default for WorkerHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerHandle {
    /// Creates a new worker handle ready to coordinate jobs across all lanes.
    pub fn new() -> Self {
        let (tx_msg, rx_msg) = unbounded();
        Self {
            tx_msg,
            rx_msg,
            lanes: std::array::from_fn(|_| LaneState::default()),
            next_job_id: 0,
            spawn_counts: [0; JobLane::COUNT],
            execute: true,
            inert_jobs: Vec::new(),
        }
    }

    /// A worker that records spawns but never runs them: no threads, no disk, registry, or
    /// process I/O. Used by headless GUI frame tests (e.g. "the Optimize probe is spawned once
    /// across many frames") so they cannot touch the real journal or launch system tools.
    pub fn new_inert() -> Self {
        let mut worker = Self::new();
        worker.execute = false;
        worker
    }

    /// Total jobs ever spawned on `lane` (frame-stability diagnostics and tests).
    pub fn lane_spawn_count(&self, lane: JobLane) -> u64 {
        self.spawn_counts[lane as usize]
    }

    /// Jobs recorded by an inert worker ([`WorkerHandle::new_inert`]); empty otherwise.
    pub fn inert_jobs(&self) -> &[WorkerJob] {
        &self.inert_jobs
    }

    /// Cancels any currently executing background job on the Heavy lane.
    pub fn cancel_active(&mut self) {
        self.cancel_lane(JobLane::Heavy);
    }

    /// Cancels any currently executing background job on the specified lane.
    pub fn cancel_lane(&mut self, lane: JobLane) {
        self.lanes[lane as usize]
            .active_cancel
            .store(true, Ordering::SeqCst);
    }

    /// Cancels all background jobs across all lanes.
    pub fn cancel_all(&mut self) {
        for lane in &self.lanes {
            lane.active_cancel.store(true, Ordering::SeqCst);
        }
    }

    /// Spawns a new background job, safely superseding any previously active job in the SAME lane.
    pub fn spawn_job(&mut self, job: WorkerJob) -> u64 {
        let lane = job.lane();
        let lane_idx = lane as usize;

        // Cancel previously active job on this specific lane only
        self.lanes[lane_idx]
            .active_cancel
            .store(true, Ordering::SeqCst);

        self.next_job_id = self.next_job_id.wrapping_add(1);
        let job_id = self.next_job_id;
        self.lanes[lane_idx].active_job_id = job_id;

        let cancel = Arc::new(AtomicBool::new(false));
        self.lanes[lane_idx].active_cancel = Arc::clone(&cancel);
        self.spawn_counts[lane_idx] += 1;
        if !self.execute {
            self.inert_jobs.push(job);
            return job_id;
        }

        let tx = self.tx_msg.clone();
        let handle = std::thread::Builder::new()
            .name(format!("dsk-worker-{lane:?}-{job_id}"))
            .spawn(move || {
                run_job(job_id, lane, job, cancel, tx);
            });

        self.lanes[lane_idx].active_thread = handle.ok();
        job_id
    }

    /// Polls for the next valid event emitted by an active job on its respective lane.
    ///
    /// Silently drops events emitted by superseded or cancelled prior jobs.
    pub fn poll(&mut self) -> Option<WorkerEvent> {
        while let Ok(msg) = self.rx_msg.try_recv() {
            let lane_idx = msg.lane as usize;
            if msg.job_id == self.lanes[lane_idx].active_job_id {
                return Some(msg.event);
            }
        }
        None
    }

    /// Drains all available events for active jobs into a `Vec`.
    pub fn drain_events(&mut self) -> Vec<WorkerEvent> {
        let mut events = Vec::new();
        while let Some(ev) = self.poll() {
            events.push(ev);
        }
        events
    }

    /// Returns the active job id counter (most recently spawned job id).
    pub fn active_job_id(&self) -> u64 {
        self.next_job_id
    }

    /// Returns the active job id for a specific lane.
    pub fn lane_active_job_id(&self, lane: JobLane) -> u64 {
        self.lanes[lane as usize].active_job_id
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

fn extract_volume_root(path: &Path, default_root: &str) -> String {
    if let Some(vr) = volume_root_of(path) {
        return vr;
    }

    for comp in path.components() {
        if let std::path::Component::Prefix(prefix_comp) = comp {
            let p_str = prefix_comp.as_os_str().to_string_lossy();
            let clean = p_str.strip_prefix(r"\\?\").unwrap_or(&p_str);
            let bytes = clean.as_bytes();
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                return format!("{}:\\", (bytes[0] as char).to_ascii_uppercase());
            }
        }
    }

    if let Some(s) = path.to_str() {
        let clean = s.strip_prefix(r"\\?\").unwrap_or(s);
        let bytes = clean.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return format!("{}:\\", (bytes[0] as char).to_ascii_uppercase());
        }
    }

    default_root.to_string()
}

/// Outcome of a batched cloud dehydration.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DehydrateSummary {
    pub succeeded: usize,
    pub reclaimed_bytes: u64,
    pub failures: Vec<(PathBuf, String)>,
}

impl DehydrateSummary {
    pub fn message(&self, dry_run: bool) -> String {
        let mut msg = format!(
            "Cloud dehydration{}: {} file(s) {}, {} reclaimed",
            if dry_run { " (dry run)" } else { "" },
            self.succeeded,
            if dry_run { "checked" } else { "dehydrated" },
            crate::theme::fmt_bytes(self.reclaimed_bytes)
        );
        if let Some((path, err)) = self.failures.first() {
            msg.push_str(&format!(
                "; {} failed (first: {}: {err})",
                self.failures.len(),
                path.display()
            ));
        }
        msg
    }
}

/// Dehydrates `paths` one by one inside a single job. A per-file failure (file changed, pinned,
/// provider offline) is recorded and the batch continues; only cancellation stops it.
pub fn dehydrate_cloud_batch(
    paths: &[PathBuf],
    dry_run: bool,
    cancel: &AtomicBool,
) -> dsk_core::Result<DehydrateSummary> {
    dehydrate_batch_with(paths, cancel, |p| dehydrate_cloud_file(p, dry_run))
}

fn dehydrate_batch_with(
    paths: &[PathBuf],
    cancel: &AtomicBool,
    mut dehydrate: impl FnMut(&Path) -> dsk_core::Result<u64>,
) -> dsk_core::Result<DehydrateSummary> {
    let mut summary = DehydrateSummary::default();
    for path in paths {
        if cancel.load(Ordering::Relaxed) {
            return Err(dsk_core::DskError::Cancelled);
        }
        match dehydrate(path) {
            Ok(freed) => {
                summary.succeeded += 1;
                summary.reclaimed_bytes = summary.reclaimed_bytes.saturating_add(freed);
            }
            Err(e) => summary.failures.push((path.clone(), e.to_string())),
        }
    }
    Ok(summary)
}

fn run_job(
    job_id: u64,
    lane: JobLane,
    job: WorkerJob,
    cancel: Arc<AtomicBool>,
    tx: Sender<WorkerMessage>,
) {
    if cancel.load(Ordering::Relaxed) {
        let _ = tx.send(WorkerMessage {
            job_id,
            lane,
            event: WorkerEvent::JobCancelled(lane),
        });
        return;
    }

    match job {
        WorkerJob::RefreshDrives => match list_volumes() {
            Ok(vols) => {
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::DrivesLoaded(vols),
                });
            }
            Err(e) => {
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::JobError {
                        lane,
                        message: format!("Failed to list volumes: {e}"),
                    },
                });
            }
        },

        WorkerJob::ScanTarget {
            path,
            method,
            use_helper,
            use_cache,
            growth_db_path,
        } => {
            let opts = ScanOptions {
                method,
                threads: None,
                use_cache,
            };
            let tx_prog = tx.clone();
            let cancel_prog = Arc::clone(&cancel);
            let progress_cb = move |p: Progress| {
                if !cancel_prog.load(Ordering::Relaxed) {
                    let _ = tx_prog.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobProgress(WorkerProgress::Scan(
                            p.phase, p.done, p.total,
                        )),
                    });
                }
            };

            let scan_res = if use_helper && !dsk_core::is_elevated() {
                connect_or_launch_helper(std::time::Duration::from_secs(10)).and_then(
                    |mut client| {
                        helper_scan_volume(
                            &mut client,
                            &path.to_string_lossy(),
                            method,
                            &progress_cb,
                            &cancel,
                        )
                    },
                )
            } else {
                scan_volume(&path, &opts, &progress_cb, &cancel)
            };

            match scan_res {
                Ok(report) => {
                    if cancel.load(Ordering::Relaxed) {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::JobCancelled(lane),
                        });
                    } else {
                        // Only whole-volume scans are volume rollups (a folder scan would record a
                        // tiny "C:\" snapshot and wreck the next 24h/7d comparison).
                        if let Some(vol_root) = volume_root_of(&path)
                            && let Ok(mut db) = GrowthDb::open(
                                &growth_db_path.unwrap_or_else(GrowthDb::default_path),
                            )
                        {
                            let _ = db.record_rollup_with_basis(
                                &report.index,
                                &vol_root,
                                GrowthDb::now_unix(),
                                dsk_core::SizeBasis::from_scan_method(report.method_used),
                            );
                        }
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::ScanFinished(Arc::new(report)),
                        });
                    }
                }
                Err(dsk_core::DskError::Cancelled) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobCancelled(lane),
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Scan failed: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::BuildPlan {
            report,
            include_recycle_bin,
            max_tier,
            use_helper,
        } => {
            let root_path_str = report.index.path(dsk_core::ROOT);
            if use_helper && !dsk_core::is_elevated() {
                match connect_or_launch_helper(std::time::Duration::from_secs(10)).and_then(
                    |mut client| {
                        helper_build_plan(
                            &mut client,
                            &root_path_str.to_string_lossy(),
                            max_tier,
                            include_recycle_bin,
                        )
                    },
                ) {
                    Ok((plan_id, plan, preconditions)) => {
                        if cancel.load(Ordering::Relaxed) {
                            let _ = tx.send(WorkerMessage {
                                job_id,
                                lane,
                                event: WorkerEvent::JobCancelled(lane),
                            });
                            return;
                        }
                        let locked_holders = probe_locked_roots(&plan);
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::PlanFinished {
                                plan,
                                preconditions,
                                helper_plan_id: Some(plan_id),
                                locked_holders,
                            },
                        });
                    }
                    Err(dsk_core::DskError::Cancelled) => {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::JobCancelled(lane),
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::JobError {
                                lane,
                                message: format!("Helper plan build failed: {e}"),
                            },
                        });
                    }
                }
                return;
            }

            let rules = match builtin_rules() {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Failed to load rules: {e}"),
                        },
                    });
                    return;
                }
            };
            let deny_ctx = DenyContext::default();
            let plan_opts = PlanOptions {
                rule_filter: Vec::new(),
                include_recycle_bin,
                include_os_handlers: true,
                tier_max: max_tier,
                now_min2000: None,
            };
            let dynamic_roots = dsk_core::clean::providers::dynamic_roots(
                &report.index,
                &dsk_core::insights::scan_gaming_libraries(&report.index),
            );
            let env_lookup = dynamic_roots.env_lookup();
            let scanned_path = Path::new(&root_path_str);
            let mut plan = build_plan_from_index(
                &report.index,
                report.method_used,
                scanned_path,
                &rules,
                &deny_ctx,
                &plan_opts,
                &env_lookup,
            );

            enrich_os_handler_estimates(&mut plan, &cancel);
            dsk_core::mark_admin_gated_estimates(&mut plan, dsk_core::is_elevated());
            if cancel.load(Ordering::Relaxed) {
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::JobCancelled(lane),
                });
                return;
            }

            let preconditions = probe_preconditions();
            let locked_holders = probe_locked_roots(&plan);
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::PlanFinished {
                    plan,
                    preconditions,
                    helper_plan_id: None,
                    locked_holders,
                },
            });
        }

        WorkerJob::ExecuteClean {
            plan,
            selected_rule_ids,
            dry_run,
            force_battery,
            journal_path,
            scan_report,
            use_helper,
            helper_plan_id,
        } => {
            let deny_ctx = DenyContext::default();
            let actual_journal_path = journal_path.unwrap_or_else(ActionJournal::default_path);
            let opts = ExecuteOptions {
                dry_run,
                force_battery,
                journal_path: Some(actual_journal_path.clone()),
            };
            let tx_prog = tx.clone();
            let cancel_prog = Arc::clone(&cancel);
            let progress_cb = move |p: CleanProgress| {
                if !cancel_prog.load(Ordering::Relaxed) {
                    let _ = tx_prog.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobProgress(WorkerProgress::Clean(p)),
                    });
                }
            };

            let exec_res = if use_helper && !dsk_core::is_elevated() {
                connect_or_launch_helper(std::time::Duration::from_secs(10)).and_then(
                    |mut client| {
                        let resolved_plan_id = if let Some(pid) = helper_plan_id {
                            pid
                        } else {
                            let max_tier = plan
                                .rules
                                .iter()
                                .map(|r| r.tier)
                                .max()
                                .unwrap_or(RuleTier::Safe);
                            let include_recycle_bin =
                                plan.rules.iter().any(|r| r.rule_id == "os.vc.recycle_bin");
                            let (pid, _, _) = helper_build_plan(
                                &mut client,
                                &plan.volume_root,
                                max_tier,
                                include_recycle_bin,
                            )?;
                            pid
                        };
                        helper_execute_plan_rules(
                            &mut client,
                            &resolved_plan_id,
                            &selected_rule_ids,
                            dry_run,
                            force_battery,
                            &progress_cb,
                        )
                    },
                )
            } else {
                let filtered_plan = plan.filtered_rules(&selected_rule_ids);
                execute_plan(&filtered_plan, &opts, &deny_ctx, &progress_cb, &cancel)
            };

            match exec_res {
                Ok(report) => {
                    let mut ledger_deltas = Vec::new();
                    if !dry_run
                        && !report.rule_summaries.is_empty()
                        && let Some(ref sr) = scan_report
                        && let Ok(journal) = ActionJournal::open(&actual_journal_path)
                        && let Ok(entries) = journal.get_run_entries(&report.run_id)
                    {
                        for entry in entries {
                            if entry.status == "deleted"
                                && let Some(nid) = sr.index.find_by_path(Path::new(&entry.path))
                            {
                                ledger_deltas.push((nid, entry.size_bytes));
                            }
                        }
                    }

                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::CleanFinished {
                            report,
                            ledger_deltas,
                        },
                    });
                }
                Err(dsk_core::DskError::Cancelled) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobCancelled(lane),
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Clean failed: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::RecycleNode {
            node_id,
            path,
            index,
            journal_path,
        } => {
            let deny_ctx = DenyContext::default();
            match move_to_recycle_bin(&path, &deny_ctx) {
                Ok(outcome) => {
                    let vol_root = extract_volume_root(&path, &index.index.volume().root);
                    let actual_journal_path =
                        journal_path.unwrap_or_else(ActionJournal::default_path);

                    let (run_id, journal_warning) = match ActionJournal::open(&actual_journal_path)
                    {
                        Ok(mut journal) => {
                            match journal.record_manual_recycle(
                                &vol_root,
                                &outcome.canonical_path,
                                outcome.bytes_hint,
                                outcome.bytes_hint as i64,
                            ) {
                                Ok(rid) => (rid, None),
                                Err(e) => (
                                    String::new(),
                                    Some(format!(
                                        "Recycled successfully, but failed to record journal: {e}"
                                    )),
                                ),
                            }
                        }
                        Err(e) => (
                            String::new(),
                            Some(format!(
                                "Recycled successfully, but failed to open journal: {e}"
                            )),
                        ),
                    };

                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::RecycleFinished {
                            node_id,
                            outcome,
                            run_id,
                            journal_warning,
                        },
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Failed to recycle item: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::LoadHistory {
            journal_path,
            limit,
            selected_run,
        } => {
            let actual_journal_path = journal_path.unwrap_or_else(ActionJournal::default_path);
            if !actual_journal_path.exists() {
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::HistoryLoaded(Vec::new()),
                });
                if let Some(run_id) = selected_run {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::RunEntriesLoaded {
                            run_id,
                            entries: Vec::new(),
                        },
                    });
                }
                return;
            }
            match ActionJournal::open(&actual_journal_path) {
                Ok(journal) => match journal.list_runs(limit) {
                    Ok(runs) => {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::HistoryLoaded(runs),
                        });
                        if let Some(run_id) = selected_run
                            && let Ok(entries) = journal.get_run_entries(&run_id)
                        {
                            let _ = tx.send(WorkerMessage {
                                job_id,
                                lane,
                                event: WorkerEvent::RunEntriesLoaded { run_id, entries },
                            });
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::JobError {
                                lane,
                                message: format!("Failed to list history runs: {e}"),
                            },
                        });
                    }
                },
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Failed to open journal: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::LoadGrowth {
            volume_root,
            window,
            db_path,
        } => {
            let actual_db_path = db_path.unwrap_or_else(GrowthDb::default_path);
            let vol_key = GrowthDb::normalize_volume_key(&volume_root);
            let now = GrowthDb::now_unix();
            match GrowthDb::open_existing(&actual_db_path) {
                Ok(Some(db)) => match db.compute_growth_since(&vol_key, window, now, 15) {
                    Ok(rep) => {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::GrowthLoaded(rep),
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::JobError {
                                lane,
                                message: format!("Failed to compute growth report: {e}"),
                            },
                        });
                    }
                },
                Ok(None) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::GrowthLoaded(GrowthReport {
                            volume: vol_key,
                            window: window.label().to_string(),
                            has_baseline: false,
                            latest_at_unix: None,
                            baseline_at_unix: None,
                            volume_delta_bytes: 0,
                            runaways: Vec::new(),
                            entries: Vec::new(),
                        }),
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Failed to open growth database: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::ConnectHelper => {
            match connect_or_launch_helper(std::time::Duration::from_secs(10)) {
                Ok(_client) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::HelperConnected,
                    });
                }
                Err(dsk_core::DskError::Cancelled) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobCancelled(lane),
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Failed to connect to elevated helper: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::ProbeOptimizers {
            scan_report,
            journal_path,
        } => {
            let cancelled = || {
                if cancel.load(Ordering::Relaxed) {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobCancelled(lane),
                    });
                    true
                } else {
                    false
                }
            };
            let vhdx_candidates = if let Some(ref sr) = scan_report {
                discover_vhdx_candidates(&sr.index)
            } else {
                Vec::new()
            };

            let cloud_candidates = if let Some(ref sr) = scan_report {
                find_hydrated_cloud_candidates(&sr.index, 30, 10_000_000)
            } else {
                Vec::new()
            };
            if cancelled() {
                return;
            }

            let tunables_status = probe_sys_tunables(scan_report.as_ref().map(|sr| &sr.index));
            if cancelled() {
                return;
            }
            let compact_os_state = query_compact_os_state().ok().map(|s| s.enabled);

            // Read-only probe: never create journal.db just to list relocations.
            let jp = journal_path.unwrap_or_else(ActionJournal::default_path);
            let active_relocations = if jp.is_file() {
                ActionJournal::open(&jp)
                    .and_then(|j| j.list_active_relocations())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            if cancelled() {
                return;
            }

            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::OptimizersProbed {
                    vhdx_candidates,
                    cloud_candidates,
                    tunables_status,
                    compact_os_state,
                    active_relocations,
                },
            });
        }

        WorkerJob::CompactVhdx {
            path,
            distro,
            dry_run,
        } => match compact_vhdx(&path, distro.as_deref(), dry_run) {
            Ok(rep) => {
                let msg = format!(
                    "VHDX compact completed: freed {} bytes (dry_run: {})",
                    rep.freed_bytes, rep.dry_run
                );
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::OptimizerFinished {
                        message: msg,
                        warning: false,
                    },
                });
            }
            Err(e) => {
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::JobError {
                        lane,
                        message: format!("VHDX compaction failed: {e}"),
                    },
                });
            }
        },

        WorkerJob::CompressFolder {
            folder,
            algo,
            dry_run,
        } => match compress_folder_wof(&folder, algo, dry_run, &cancel) {
            Ok(rep) => {
                let msg = format!(
                    "WOF compression completed on {}: freed {} bytes (dry_run: {})",
                    folder.display(),
                    rep.freed_bytes,
                    rep.dry_run
                );
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::OptimizerFinished {
                        message: msg,
                        warning: false,
                    },
                });
            }
            Err(e) => {
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::JobError {
                        lane,
                        message: format!("Folder compression failed: {e}"),
                    },
                });
            }
        },

        WorkerJob::RunOptimizerIntent {
            intent,
            dry_run,
            use_helper,
        } => {
            let res = if use_helper && !dsk_core::is_elevated() {
                connect_or_launch_helper(std::time::Duration::from_secs(30))
                    .and_then(|mut client| helper_run_optimizer(&mut client, &intent, dry_run))
            } else {
                run_optimizer_intent(&intent, dry_run)
            };
            let event = match res {
                Ok(message) => WorkerEvent::OptimizerFinished {
                    message,
                    warning: false,
                },
                Err(dsk_core::DskError::Cancelled) => WorkerEvent::JobCancelled(lane),
                Err(e) => WorkerEvent::JobError {
                    lane,
                    message: format!("{} failed: {e}", intent.label()),
                },
            };
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event,
            });
        }

        WorkerJob::DehydrateCloudFiles { paths, dry_run } => {
            let event = match dehydrate_cloud_batch(&paths, dry_run, &cancel) {
                Err(dsk_core::DskError::Cancelled) => WorkerEvent::JobCancelled(lane),
                Err(e) => WorkerEvent::JobError {
                    lane,
                    message: format!("Cloud dehydration failed: {e}"),
                },
                Ok(summary) => WorkerEvent::OptimizerFinished {
                    message: summary.message(dry_run),
                    warning: !summary.failures.is_empty(),
                },
            };
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event,
            });
        }

        WorkerJob::SampleWof {
            scan_report,
            folder,
        } => {
            let result = match scan_report.index.find_by_path(&folder) {
                Some(node) => sample_folder_compressibility(&scan_report.index, node)
                    .map_err(|e| e.to_string()),
                None => Err(format!(
                    "{} is not part of the current scan; scan its drive first",
                    folder.display()
                )),
            };
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::WofSampled { folder, result },
            });
        }

        WorkerJob::RelocateFolder {
            source,
            target_parent,
            journal_path,
        } => {
            let jp = journal_path.unwrap_or_else(ActionJournal::default_path);
            let deny = DenyContext::from_env();
            let mut journal_res = ActionJournal::open(&jp);
            let res = match journal_res {
                Ok(ref mut journal) => {
                    execute_folder_relocation(&source, &target_parent, &deny, journal, &cancel)
                }
                Err(e) => Err(dsk_core::DskError::Journal(e.to_string())),
            };

            match res {
                Ok(rep) => {
                    let msg = format!(
                        "Folder relocation complete: moved {} files ({} bytes) to {}",
                        rep.file_count,
                        rep.bytes_moved,
                        rep.target_path.display()
                    );
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::OptimizerFinished {
                            message: msg,
                            warning: false,
                        },
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Relocation failed: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::UndoRelocation { id, journal_path } => {
            let jp = journal_path.unwrap_or_else(ActionJournal::default_path);
            let mut journal_res = ActionJournal::open(&jp);
            let res = match journal_res {
                Ok(ref mut journal) => undo_folder_relocation(&id, journal, &cancel),
                Err(e) => Err(dsk_core::DskError::Journal(e.to_string())),
            };

            match res {
                Ok(rep) => {
                    let msg = format!(
                        "Relocation {id} successfully restored: {} files returned to {}",
                        rep.file_count,
                        rep.source_path.display()
                    );
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::OptimizerFinished {
                            message: msg,
                            warning: false,
                        },
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Undo relocation failed: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::RunInsights { scan_report, opts } => {
            let report = run_all_insights(&scan_report.index, &opts);
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::InsightsFinished(report),
            });
        }

        WorkerJob::ProbeVideoEngine => {
            let engine = VideoEngine::locate(None).map(Arc::new);
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::VideoEngineProbed(engine),
            });
        }

        WorkerJob::FindVideos {
            roots,
            mut opts,
            engine,
            journal_path,
        } => {
            let jp = journal_path.unwrap_or_else(ActionJournal::default_path);
            let journal = ActionJournal::open_existing(&jp).ok().flatten();
            opts.calibration = journal.as_ref().and_then(|j| {
                j.calibration_ratio(
                    &dsk_core::video::calibration_category(opts.codec, opts.quality),
                    20,
                )
                .ok()
                .flatten()
            });
            let mut files = Vec::new();
            let mut excluded = 0usize;
            for root in &roots {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let tx_p = tx.clone();
                let root_p = root.clone();
                let progress_cb = move |p: Progress| {
                    if p.done.is_multiple_of(20_000) {
                        let _ = tx_p.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::VideosProgress(VideosProgress::Scanning(
                                root_p.clone(),
                                p.done,
                            )),
                        });
                    }
                };
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::VideosProgress(VideosProgress::Scanning(root.clone(), 0)),
                });
                let sopts = ScanOptions {
                    method: ScanMethod::Auto,
                    threads: None,
                    use_cache: true,
                };
                match scan_volume(root, &sopts, &progress_cb, &cancel) {
                    Ok(report) => {
                        opts.exclude_roots = dsk_core::video::app_and_game_roots(&report.index);
                        let (found, ex) =
                            dsk_core::video::collect_video_files(&report.index, &opts);
                        files.extend(found);
                        excluded += ex;
                    }
                    Err(dsk_core::DskError::Cancelled) => break,
                    Err(e) => {
                        let _ = tx.send(WorkerMessage {
                            job_id,
                            lane,
                            event: WorkerEvent::JobError {
                                lane,
                                message: format!("Could not scan {}: {e}", root.display()),
                            },
                        });
                        return;
                    }
                }
            }
            if cancel.load(Ordering::Relaxed) {
                let _ = tx.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::JobCancelled(lane),
                });
                return;
            }
            let tx_i = tx.clone();
            let inspect = move |done: usize, total: usize| {
                let _ = tx_i.send(WorkerMessage {
                    job_id,
                    lane,
                    event: WorkerEvent::VideosProgress(VideosProgress::Inspecting(done, total)),
                });
            };
            let mut d = dsk_core::video::discover_videos(
                files,
                engine.as_ref().map(|e| &e.tools),
                &opts,
                journal.as_ref(),
                &inspect,
                &cancel,
            );
            d.excluded_app_files = excluded;
            let event = if cancel.load(Ordering::Relaxed) {
                WorkerEvent::JobCancelled(lane)
            } else {
                WorkerEvent::VideosFound(Arc::new(d))
            };
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event,
            });
        }

        WorkerJob::SampleVideo { engine, path, opts } => {
            let result = dsk_core::video::sample_video(&engine, &path, &opts, None, 30.0, &cancel)
                .map_err(|e| e.to_string());
            let event = if cancel.load(Ordering::Relaxed) {
                WorkerEvent::JobCancelled(lane)
            } else {
                WorkerEvent::VideoSampled { path, result }
            };
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event,
            });
        }

        WorkerJob::CompressVideos {
            engine,
            paths,
            opts,
        } => {
            let deny = DenyContext::default();
            let tx_p = tx.clone();
            let tx_d = tx.clone();
            let mut last_sent = std::time::Instant::now() - std::time::Duration::from_secs(1);
            let report = dsk_core::video::compress_batch(
                &engine,
                &paths,
                &opts,
                &deny,
                &mut |p| {
                    // Encode progress arrives several times a second; the UI needs ~4/s.
                    if p.phase == dsk_core::video::VideoPhase::Encoding
                        && last_sent.elapsed() < std::time::Duration::from_millis(250)
                    {
                        return;
                    }
                    last_sent = std::time::Instant::now();
                    let _ = tx_p.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::VideosProgress(VideosProgress::Compress(p.clone())),
                    });
                },
                &mut |o| {
                    let _ = tx_d.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::VideoFileDone(o.clone()),
                    });
                },
                &cancel,
            );
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::VideosCompressed(report),
            });
        }

        WorkerJob::LoadHeldVideos { journal_path } => {
            let jp = journal_path.unwrap_or_else(ActionJournal::default_path);
            let result = match ActionJournal::open_existing(&jp) {
                Ok(Some(j)) => dsk_core::video::list_held_originals(&j).map_err(|e| e.to_string()),
                Ok(None) => Ok(Vec::new()),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::HeldVideosLoaded(result),
            });
        }

        WorkerJob::PurgeHeldVideos { journal_path } => {
            let jp = journal_path.unwrap_or_else(ActionJournal::default_path);
            let result = match ActionJournal::open_existing(&jp) {
                Ok(Some(mut j)) => {
                    dsk_core::video::purge_held_originals(&mut j, false).map_err(|e| e.to_string())
                }
                Ok(None) => Ok(PurgeReport::default()),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(WorkerMessage {
                job_id,
                lane,
                event: WorkerEvent::HeldVideosPurged(result),
            });
        }

        WorkerJob::BuildReclaim {
            scan_report,
            journal_path,
        } => {
            let index = &scan_report.index;
            let target = index.path(dsk_core::ROOT);
            let opts = dsk_core::ledger::assemble::AssembleOptions {
                journal_path: Some(
                    journal_path.unwrap_or_else(dsk_core::clean::ActionJournal::default_path),
                ),
                ..Default::default()
            };
            match dsk_core::ledger::assemble::assemble(
                index,
                scan_report.method_used,
                &target,
                &opts,
                &cancel,
            ) {
                Ok(assembled) => {
                    let mut ctx =
                        dsk_core::hunt::HuntContext::new(dsk_core::clean::DenyContext::default());
                    ctx.ledger = Some(&assembled.ledger);
                    ctx.installed = hunt_installed_roots(index, &assembled);
                    ctx.ignore =
                        dsk_core::hunt::load_ignore_list(&dsk_core::hunt::default_ignore_path());
                    ctx.skipped_dirs = scan_report.skipped;
                    ctx.elevated = dsk_core::is_elevated();
                    ctx.mft_scan = matches!(
                        scan_report.method_used,
                        ScanMethod::Mft | ScanMethod::UsnIncremental
                    );
                    let hopts = dsk_core::hunt::HuntOptions {
                        many: true,
                        ..Default::default()
                    };
                    let verdicts = dsk_core::hunt::classify(index, &ctx, &hopts).verdicts;
                    let hunt = dsk_core::hunt::run_hunt(index, &ctx, &hopts);
                    drop(ctx);
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::ReclaimFinished(Arc::new(ReclaimResult {
                            assembled,
                            hunt,
                            verdicts,
                        })),
                    });
                }
                Err(dsk_core::DskError::Cancelled) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobCancelled(lane),
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Finding space failed: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::FindDuplicates {
            scan_report,
            min_bytes,
            cache_db_path,
        } => {
            let default_db = default_hash_cache_path();
            let cache_p = cache_db_path.as_deref().unwrap_or(&default_db);
            let tx_p = tx.clone();
            let res = find_duplicates(
                &scan_report.index,
                min_bytes,
                Some(cache_p),
                None,
                &cancel,
                move |p| {
                    let _ = tx_p.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::DupesProgress(p),
                    });
                },
            );
            match res {
                Ok(rep) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::DupesFinished(rep),
                    });
                }
                Err(dsk_core::DskError::Cancelled) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobCancelled(lane),
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Duplicate scan failed: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::RemediateDuplicates {
            group,
            keep_index,
            action,
            dry_run,
            journal_path,
            volume_root,
        } => {
            let deny_ctx = dsk_core::clean::DenyContext::default();
            match remediate_duplicate_group(
                &group,
                keep_index,
                action,
                dry_run,
                journal_path.as_deref(),
                &volume_root,
                &deny_ctx,
            ) {
                Ok(out) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::DupeRemediationFinished(out),
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Duplicate remediation failed: {e}"),
                        },
                    });
                }
            }
        }

        WorkerJob::RecycleInsightPath {
            path,
            volume_root,
            dry_run,
            journal_path,
        } => {
            let deny_ctx = dsk_core::clean::DenyContext::default();
            let res = if path.is_dir() {
                recycle_orphan_folder(
                    &path,
                    dry_run,
                    journal_path.as_deref(),
                    &volume_root,
                    &deny_ctx,
                )
            } else if dry_run {
                Ok(dsk_core::RecycleOutcome {
                    path: path.to_string_lossy().into_owned(),
                    canonical_path: path.to_string_lossy().into_owned(),
                    bytes_hint: std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
                })
            } else {
                dsk_core::move_to_recycle_bin(&path, &deny_ctx).and_then(|outcome| {
                    let mut journal = ActionJournal::open(
                        journal_path
                            .as_deref()
                            .unwrap_or(&ActionJournal::default_path()),
                    )?;
                    let _ = journal.record_manual_recycle(
                        &volume_root,
                        &outcome.canonical_path,
                        outcome.bytes_hint,
                        outcome.bytes_hint.min(i64::MAX as u64) as i64,
                    )?;
                    Ok(outcome)
                })
            };
            match res {
                Ok(outcome) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::InsightRecycleFinished {
                            path,
                            freed_bytes: outcome.bytes_hint,
                            dry_run,
                        },
                    });
                }
                Err(e) => {
                    let _ = tx.send(WorkerMessage {
                        job_id,
                        lane,
                        event: WorkerEvent::JobError {
                            lane,
                            message: format!("Recycle operation failed: {e}"),
                        },
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn worker_handle_lifecycle_and_stale_event_discard() {
        let mut worker = WorkerHandle::new();
        assert_eq!(worker.active_job_id(), 0);

        // Spawn first job
        let id1 = worker.spawn_job(WorkerJob::RefreshDrives);
        assert_eq!(id1, 1);
        assert_eq!(worker.active_job_id(), 1);

        // Immediately spawn second job on same lane: should supersede first job
        let id2 = worker.spawn_job(WorkerJob::RefreshDrives);
        assert_eq!(id2, 2);
        assert_eq!(worker.active_job_id(), 2);

        // Wait briefly for job 2 to deliver DrivesLoaded
        let mut received_event = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if let Some(WorkerEvent::DrivesLoaded(_) | WorkerEvent::JobError { .. }) = worker.poll()
            {
                received_event = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(received_event, "expected event for active job 2");
    }

    #[test]
    fn worker_load_history_isolated_tempdir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_path = temp.path().join("test_journal.db");

        // Record a manual recycle run in the journal
        {
            let mut journal = ActionJournal::open(&journal_path).expect("open journal");
            let run_id = journal
                .record_manual_recycle(r"C:\", r"C:\test\sample.txt", 4096, 4096)
                .expect("record manual recycle");
            assert!(!run_id.is_empty());
        }

        let mut worker = WorkerHandle::new();
        let job = WorkerJob::LoadHistory {
            journal_path: Some(journal_path),
            limit: 10,
            selected_run: None,
        };

        worker.spawn_job(job);

        let mut history_loaded = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if let Some(WorkerEvent::HistoryLoaded(runs)) = worker.poll() {
                assert_eq!(runs.len(), 1);
                assert_eq!(runs[0].volume, r"C:\");
                assert_eq!(runs[0].est_bytes, 4096);
                history_loaded = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(history_loaded, "expected HistoryLoaded event");
    }

    #[test]
    fn worker_independent_lanes_do_not_cancel_each_other() {
        let temp = tempfile::tempdir().expect("tempdir");
        let scan_dir = temp.path().join("scandir");
        std::fs::create_dir_all(&scan_dir).expect("create scan dir");
        std::fs::write(scan_dir.join("a.txt"), b"hello").expect("write file");

        let journal_path = temp.path().join("test_journal.db");
        {
            let mut journal = ActionJournal::open(&journal_path).expect("open journal");
            journal
                .record_manual_recycle(r"C:\", r"C:\test\a.txt", 5, 5)
                .expect("record manual recycle");
        }

        let mut worker = WorkerHandle::new();

        // 1. Spawn a Heavy scan job
        let heavy_id = worker.spawn_job(WorkerJob::ScanTarget {
            path: scan_dir,
            method: ScanMethod::Dir,
            use_helper: false,
            use_cache: false,
            growth_db_path: Some(temp.path().join("growth.db")),
        });
        assert_eq!(worker.lane_active_job_id(JobLane::Heavy), heavy_id);

        // 2. Concurrently spawn Drives and History jobs: must NOT cancel Heavy job
        let drives_id = worker.spawn_job(WorkerJob::RefreshDrives);
        assert_eq!(worker.lane_active_job_id(JobLane::Drives), drives_id);

        let history_id = worker.spawn_job(WorkerJob::LoadHistory {
            journal_path: Some(journal_path),
            limit: 10,
            selected_run: None,
        });
        assert_eq!(worker.lane_active_job_id(JobLane::History), history_id);

        // 3. Poll for completion across all 3 lanes
        let mut got_scan = false;
        let mut got_drives = false;
        let mut got_history = false;

        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match worker.poll() {
                Some(WorkerEvent::ScanFinished(_)) => got_scan = true,
                Some(WorkerEvent::DrivesLoaded(_)) => got_drives = true,
                Some(WorkerEvent::HistoryLoaded(_)) => got_history = true,
                Some(WorkerEvent::JobProgress(_)) => {}
                Some(other) => panic!("unexpected event: {other:?}"),
                None => std::thread::sleep(Duration::from_millis(10)),
            }
            if got_scan && got_drives && got_history {
                break;
            }
        }

        assert!(got_scan, "Heavy scan completed without interference");
        assert!(got_drives, "Drives refresh completed concurrently");
        assert!(got_history, "History loading completed concurrently");
    }

    #[test]
    fn worker_load_history_missing_db_does_not_create_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing_dir = temp.path().join("absent_dir");
        let missing_journal = missing_dir.join("journal.db");

        let mut worker = WorkerHandle::new();
        worker.spawn_job(WorkerJob::LoadHistory {
            journal_path: Some(missing_journal.clone()),
            limit: 10,
            selected_run: Some("missing-run".to_string()),
        });

        let mut got_history = false;
        let mut got_entries = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            match worker.poll() {
                Some(WorkerEvent::HistoryLoaded(runs)) => {
                    assert!(runs.is_empty());
                    got_history = true;
                }
                Some(WorkerEvent::RunEntriesLoaded { run_id, entries }) => {
                    assert_eq!(run_id, "missing-run");
                    assert!(entries.is_empty());
                    got_entries = true;
                }
                Some(other) => panic!("unexpected event: {other:?}"),
                None => std::thread::sleep(Duration::from_millis(10)),
            }
            if got_history && got_entries {
                break;
            }
        }

        assert!(got_history, "expected empty HistoryLoaded event");
        assert!(got_entries, "expected empty RunEntriesLoaded event");
        assert!(
            !missing_journal.exists(),
            "read-only LoadHistory must not create journal.db"
        );
        assert!(
            !missing_dir.exists(),
            "read-only LoadHistory must not create missing parent directory"
        );
    }

    #[test]
    fn dehydrate_batch_processes_every_file_and_records_failures() {
        let paths: Vec<PathBuf> = (0..5)
            .map(|i| PathBuf::from(format!(r"C:\OneDrive\f{i}.bin")))
            .collect();
        let cancel = AtomicBool::new(false);
        let mut seen = Vec::new();
        let summary = dehydrate_batch_with(&paths, &cancel, |p| {
            seen.push(p.to_path_buf());
            if p.ends_with("f2.bin") {
                Err(dsk_core::DskError::Optimize("file is pinned".to_string()))
            } else {
                Ok(1000)
            }
        })
        .expect("batch");
        assert_eq!(
            seen, paths,
            "every file in the batch is attempted, in order"
        );
        assert_eq!(summary.succeeded, 4);
        assert_eq!(summary.reclaimed_bytes, 4000);
        assert_eq!(summary.failures.len(), 1);
        assert!(summary.message(false).contains("1 failed"));

        cancel.store(true, Ordering::SeqCst);
        assert!(matches!(
            dehydrate_batch_with(&paths, &cancel, |_| Ok(1)),
            Err(dsk_core::DskError::Cancelled)
        ));
    }

    #[test]
    fn batched_dehydrate_is_one_heavy_job_not_n_superseding_jobs() {
        let mut worker = WorkerHandle::new_inert();
        let paths: Vec<PathBuf> = (0..10)
            .map(|i| PathBuf::from(format!(r"C:\OneDrive\f{i}.bin")))
            .collect();
        let job = WorkerJob::DehydrateCloudFiles {
            paths: paths.clone(),
            dry_run: true,
        };
        assert_eq!(job.lane(), JobLane::Heavy);
        worker.spawn_job(job);
        assert_eq!(worker.lane_spawn_count(JobLane::Heavy), 1);
    }

    #[test]
    fn probes_and_helper_connect_never_share_the_heavy_lane() {
        assert_eq!(
            WorkerJob::ProbeOptimizers {
                scan_report: None,
                journal_path: None
            }
            .lane(),
            JobLane::Optimizers
        );
        assert_eq!(WorkerJob::ConnectHelper.lane(), JobLane::Helper);

        // Spawning a probe while a heavy job is active must not supersede it.
        let mut worker = WorkerHandle::new_inert();
        let heavy = worker.spawn_job(WorkerJob::DehydrateCloudFiles {
            paths: Vec::new(),
            dry_run: true,
        });
        worker.spawn_job(WorkerJob::ProbeOptimizers {
            scan_report: None,
            journal_path: None,
        });
        worker.spawn_job(WorkerJob::ConnectHelper);
        assert_eq!(worker.lane_active_job_id(JobLane::Heavy), heavy);
    }

    #[test]
    fn worker_probe_does_not_create_missing_journal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("absent").join("journal.db");
        let mut worker = WorkerHandle::new();
        worker.spawn_job(WorkerJob::ProbeOptimizers {
            scan_report: None,
            journal_path: Some(missing.clone()),
        });
        let start = std::time::Instant::now();
        let mut done = false;
        while start.elapsed() < Duration::from_secs(120) {
            match worker.poll() {
                Some(WorkerEvent::OptimizersProbed {
                    active_relocations, ..
                }) => {
                    assert!(active_relocations.is_empty());
                    done = true;
                    break;
                }
                Some(other) => panic!("unexpected event: {other:?}"),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        assert!(done, "probe finished");
        assert!(
            !missing.exists(),
            "read-only probe must not create journal.db"
        );
    }

    #[test]
    fn worker_load_growth_missing_db_does_not_create_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing_dir = temp.path().join("absent_growth");
        let missing_db = missing_dir.join("growth.db");

        let mut worker = WorkerHandle::new();
        worker.spawn_job(WorkerJob::LoadGrowth {
            volume_root: r"C:\".to_string(),
            window: GrowthWindow::H24,
            db_path: Some(missing_db.clone()),
        });

        let mut got_growth = None;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            match worker.poll() {
                Some(WorkerEvent::GrowthLoaded(rep)) => {
                    got_growth = Some(rep);
                    break;
                }
                Some(other) => panic!("unexpected event: {other:?}"),
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }

        let rep = got_growth.expect("expected empty GrowthLoaded event");
        assert!(!rep.has_baseline);
        assert!(rep.entries.is_empty());
        assert!(!missing_db.exists(), "LoadGrowth must not create growth.db");
        assert!(
            !missing_dir.exists(),
            "LoadGrowth must not create missing parent directory"
        );
    }
}
