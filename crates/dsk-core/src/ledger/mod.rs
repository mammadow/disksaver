#![forbid(unsafe_code)]

//! Reclaim Ledger (P9.1): one ranked, de-overlapped list of every way to free space.
//!
//! Sources (cleanup rules, insights, duplicates, sizing, virtual disks, compression, the disk hunt)
//! add [`Opportunity`] entries. Each entry may *claim* index subtrees; a byte belongs to the first
//! entry that claims it in priority order, so totals never count a file twice (for example conda
//! `pkgs` belongs to the conda rule, not also to "cold files" and "duplicates").
//!
//! The ledger never mutates anything. Every opportunity carries an [`ActionRef`] naming an
//! existing executor and a CLI hint for applying it.

use std::path::{Path, PathBuf};

pub mod assemble;

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::clean::plan::{CleanPlan, EstimateBasis};
use crate::clean::rules::{RuleMethod, RuleTier};
use crate::index::{Index, NodeFlags, NodeId};
use crate::insights::FullInsightsReport;
use crate::insights::dupes::DupeReport;
use crate::optimize::intent::OptimizerIntent;
use crate::optimize::sizing::{SizingConfidence, SizingRecommendation};
use crate::optimize::vhdx::VhdxCandidate;
use crate::optimize::wof::WofAlgorithm;

/// Projects built within this many days count as active (their build output is a decision).
pub const ACTIVE_PROJECT_DAYS: u32 = 30;

/// Calibration category for cleanup runs (rule executor).
pub const CALIBRATION_CLEAN: &str = "clean";
/// Calibration category for WOF compression.
pub const CALIBRATION_WOF: &str = "wof";
/// Calibration category for virtual-disk compaction.
pub const CALIBRATION_VHDX: &str = "vhdx";

/// How invisible an action is to the owner (display and headline grouping).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// Data and behavior unchanged (compression, trimming, hard-link dedupe of immutable files).
    Invisible,
    /// Reversible system settings (hibernation, pagefile, reserved storage).
    Sizing,
    /// Rebuilt on demand (caches, build outputs).
    Regenerable,
    /// Left behind (orphans, extra copies, installers, temp files).
    Leftover,
    /// The owner's call (apps, games, models, cold personal files).
    Decision,
}

impl Lane {
    pub fn label(self) -> &'static str {
        match self {
            Self::Invisible => "Invisible",
            Self::Sizing => "Sizing",
            Self::Regenerable => "Regenerable",
            Self::Leftover => "Leftover",
            Self::Decision => "Decision",
        }
    }

    /// Lanes counted in the "free without losing anything" headline.
    pub fn in_headline(self) -> bool {
        matches!(self, Self::Invisible | Self::Regenerable)
    }
}

/// How the byte estimate was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Summed from scanned sizes.
    Measured,
    /// Extrapolated from a sample (compression ratio, guest file system usage).
    Sampled,
    /// Rule of thumb or matching heuristic; the number is indicative.
    Heuristic,
    /// Known only after the tool runs (DISM, pnputil, compaction without a guest estimate).
    AtRunTime,
    /// Needs administrator rights to estimate.
    NeedsAdmin,
}

impl Confidence {
    /// Weight used for ranking.
    pub fn weight(self) -> f64 {
        match self {
            Self::Measured => 1.0,
            Self::Sampled => 0.8,
            Self::Heuristic => 0.5,
            Self::AtRunTime | Self::NeedsAdmin => 0.3,
        }
    }
}

/// What it takes to get the space back if the owner changes their mind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// Undo restores the original state (decompress, split hard links, setting back).
    Reversible,
    /// Deleted, but the owning app rebuilds or re-downloads it.
    Regenerable,
    /// Moved to the Recycle Bin: space returns only when the bin is emptied.
    RecycleBin,
    /// Uninstall or permanent removal.
    Permanent,
}

/// The existing executor that applies an opportunity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionRef {
    CleanRule {
        rule_id: String,
        tier: RuleTier,
    },
    Optimizer {
        intent: OptimizerIntent,
    },
    CompressFolder {
        path: PathBuf,
        algorithm: WofAlgorithm,
    },
    CompactVhdx {
        path: PathBuf,
        distro: Option<String>,
    },
    RecyclePath {
        path: PathBuf,
    },
    DupeGroup {
        blake3_hex: String,
        hardlink: bool,
    },
    UninstallApp {
        name: String,
    },
    LauncherGame {
        store: String,
        title: String,
    },
    /// Stale build generations (P9.7 sweep).
    SweepBuildOutput {
        root: PathBuf,
    },
    /// Re-encode a video to AV1/HEVC after a verified quality check (P9.11).
    CompressVideo {
        path: PathBuf,
    },
    /// Informational only (the owner acts outside DiskSaver).
    None,
}

impl ActionRef {
    /// A command line (or instruction) that applies this action with today's tools.
    pub fn cli_hint(&self) -> String {
        match self {
            Self::CleanRule { rule_id, tier } => format!(
                "disksaver clean --rule {rule_id} --tier {} --yes",
                match tier {
                    RuleTier::Safe => "safe",
                    RuleTier::Review => "review",
                    RuleTier::Advanced => "advanced",
                }
            ),
            Self::Optimizer { intent } => match intent {
                OptimizerIntent::SetHiberfile { mode } => format!(
                    "disksaver optimize tunables --hiberfile {} --use-helper",
                    format!("{mode:?}").to_ascii_lowercase()
                ),
                OptimizerIntent::SetCompactOs { enable } => format!(
                    "disksaver optimize compress --compact-os {} --use-helper",
                    if *enable { "always" } else { "never" }
                ),
                OptimizerIntent::VssResize { drive, max_percent } => format!(
                    "disksaver optimize tunables --vss-drive {drive} --vss-max {max_percent} --use-helper"
                ),
                OptimizerIntent::VssPruneOldest { drive } => {
                    format!(
                        "disksaver optimize tunables --vss-drive {drive} --vss-prune --use-helper"
                    )
                }
                OptimizerIntent::SetReservedStorage { enabled } => format!(
                    "disksaver optimize tunables --reserved-storage {} --use-helper",
                    if *enabled { "enable" } else { "disable" }
                ),
                OptimizerIntent::SetPagefile {
                    drive,
                    initial_mb,
                    max_mb,
                } => format!(
                    "disksaver optimize tunables --pagefile {initial_mb}-{max_mb} --pagefile-drive {drive} --use-helper"
                ),
                OptimizerIntent::SetPagefileSystemManaged { drive } => format!(
                    "disksaver optimize tunables --pagefile system --pagefile-drive {drive} --use-helper"
                ),
                OptimizerIntent::SetPagefileAutomatic => {
                    "disksaver optimize tunables --pagefile auto --use-helper".to_string()
                }
                OptimizerIntent::CompressProgramFilesApp {
                    x86,
                    folder,
                    algorithm,
                } => format!(
                    "disksaver optimize compress --path \"{}\" --algo {} --use-helper",
                    if *x86 {
                        crate::win::volume::program_files_x86_dir()
                    } else {
                        crate::win::volume::program_files_dir()
                    }
                    .join(folder)
                    .display(),
                    algorithm.as_compact_arg().to_ascii_lowercase()
                ),
                OptimizerIntent::DecompressProgramFilesApp { x86, folder } => format!(
                    "disksaver optimize compress --path \"{}\" --undo --use-helper",
                    if *x86 {
                        crate::win::volume::program_files_x86_dir()
                    } else {
                        crate::win::volume::program_files_dir()
                    }
                    .join(folder)
                    .display()
                ),
            },
            Self::CompressFolder { path, algorithm } => format!(
                "disksaver optimize compress --path \"{}\" --algo {}",
                path.display(),
                algorithm.as_compact_arg().to_ascii_lowercase()
            ),
            Self::CompactVhdx { path, distro } => match distro {
                Some(d) => format!(
                    "disksaver optimize vhdx --path \"{}\" --sparse {d}",
                    path.display()
                ),
                None => format!("disksaver optimize vhdx --path \"{}\"", path.display()),
            },
            Self::RecyclePath { path } => {
                format!(
                    "GUI: Insights or Explore > Move to Recycle Bin: {}",
                    path.display()
                )
            }
            Self::DupeGroup { hardlink, .. } => format!(
                "disksaver dupes --action {} --yes",
                if *hardlink { "hardlink" } else { "recycle" }
            ),
            Self::UninstallApp { name } => format!("disksaver uninstall \"{name}\""),
            Self::SweepBuildOutput { root } => format!(
                "disksaver sweep \"{}\" --yes",
                root.parent().unwrap_or(root).display()
            ),
            Self::CompressVideo { path } => {
                format!("disksaver videos \"{}\" --compress --yes", path.display())
            }
            Self::LauncherGame { store, title } => {
                format!("{store}: uninstall or move \"{title}\" from the launcher")
            }
            Self::None => "decide in File Explorer".to_string(),
        }
    }
}

/// One way to free space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Opportunity {
    /// Stable identifier, e.g. `rule:dev.uv.cache`, `wof:C:\Program Files\JetBrains`.
    pub id: String,
    pub lane: Lane,
    pub title: String,
    pub detail: String,
    pub path: Option<PathBuf>,
    /// Bytes this opportunity owns after de-overlapping and calibration.
    pub est_bytes: u64,
    /// The source's own estimate before de-overlapping.
    pub raw_est_bytes: u64,
    pub confidence: Confidence,
    pub reversibility: Reversibility,
    pub requires_admin: bool,
    pub action: ActionRef,
    /// Ranking score: bytes × confidence weight.
    pub score: f64,
    /// Measured/estimated ratio applied from past runs, if any.
    #[serde(default)]
    pub calibration: Option<f64>,
}

/// Bytes and count per lane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneTotal {
    pub lane: Lane,
    pub bytes: u64,
    pub count: usize,
}

/// The finished ledger.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Ledger {
    pub volume_root: String,
    pub opportunities: Vec<Opportunity>,
    pub lane_totals: Vec<LaneTotal>,
    /// Invisible + Regenerable bytes: "free without losing anything".
    pub headline_bytes: u64,
    pub notes: Vec<String>,
    /// Owning opportunity index per index node (`u32::MAX` = unclaimed). Not serialized; valid only
    /// against the index the ledger was built from. Used by the disk hunt.
    #[serde(skip)]
    pub owner_of: Vec<u32>,
}

impl Ledger {
    /// The opportunity that owns `node`, if any.
    pub fn owner(&self, node: NodeId) -> Option<&Opportunity> {
        self.owner_of
            .get(node as usize)
            .and_then(|&i| (i != u32::MAX).then(|| self.opportunities.get(i as usize)))
            .flatten()
    }
}

/// How an entry's bytes are derived from its claims.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Measure {
    /// `min(raw, unowned allocated bytes in the claimed subtrees)`.
    Subtree,
    /// `unowned allocated bytes × ratio` (compression).
    Ratio(f64),
    /// The source's number as is; claims only reserve nodes.
    Fixed,
}

struct Pending {
    opp: Opportunity,
    claims: Vec<NodeId>,
    measure: Measure,
    /// Lower claims first.
    priority: u8,
    calibration_category: Option<&'static str>,
}

/// Claim priorities: the action that removes data claims before the one that shrinks it.
mod prio {
    pub const SIZING: u8 = 5;
    pub const RULE: u8 = 10;
    pub const SWEEP: u8 = 15;
    pub const PROJECT: u8 = 20;
    pub const DUPE: u8 = 30;
    pub const VHDX: u8 = 35;
    pub const ORPHAN: u8 = 40;
    pub const HUNT: u8 = 50;
    pub const DECISION: u8 = 70;
    pub const COLD_FILE: u8 = 80;
    pub const COMPRESS: u8 = 90;
}

/// A folder estimated to shrink under WOF compression (from the P9.3 estimator).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressCandidate {
    pub path: PathBuf,
    pub algorithm: WofAlgorithm,
    /// Predicted fraction of bytes saved, 0.0–1.0.
    pub savings_ratio: f64,
    /// `true` when measured by trial compression rather than the in-memory estimator.
    pub measured: bool,
    pub requires_admin: bool,
}

/// Collects opportunities, then resolves ownership.
pub struct LedgerBuilder<'a> {
    index: Option<&'a Index>,
    volume_root: String,
    pending: Vec<Pending>,
    notes: Vec<String>,
    calibration: Vec<(&'static str, f64)>,
    seen_ids: FxHashSet<String>,
}

impl<'a> LedgerBuilder<'a> {
    pub fn new(index: Option<&'a Index>) -> Self {
        Self {
            index,
            volume_root: index.map(|ix| ix.volume().root.clone()).unwrap_or_default(),
            pending: Vec::new(),
            notes: Vec::new(),
            calibration: Vec::new(),
            seen_ids: FxHashSet::default(),
        }
    }

    /// Applies a measured/estimated ratio to every opportunity of `category`.
    pub fn with_calibration(mut self, category: &'static str, ratio: f64) -> Self {
        self.calibration.push((category, ratio));
        self
    }

    /// Reads calibration ratios from an existing journal (never creates one).
    pub fn with_journal_calibration(mut self, journal_path: &Path) -> Self {
        if let Ok(Some(j)) = crate::clean::journal::ActionJournal::open_existing(journal_path) {
            for cat in [CALIBRATION_CLEAN, CALIBRATION_WOF, CALIBRATION_VHDX] {
                if let Ok(Some(r)) = j.calibration_ratio(cat, 20) {
                    self.calibration.push((cat, r));
                }
            }
        }
        self
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    fn node_for(&self, path: &Path) -> Option<NodeId> {
        self.index.and_then(|ix| ix.find_by_path(path))
    }

    fn push(
        &mut self,
        opp: Opportunity,
        claims: Vec<NodeId>,
        measure: Measure,
        priority: u8,
        calibration_category: Option<&'static str>,
    ) {
        if !self.seen_ids.insert(opp.id.clone()) {
            return;
        }
        self.pending.push(Pending {
            opp,
            claims,
            measure,
            priority,
            calibration_category,
        });
    }

    /// Adds a fully formed opportunity from another module (e.g. the disk hunt).
    pub fn add_external(
        &mut self,
        opp: Opportunity,
        claim_paths: &[PathBuf],
        measured_subtree: bool,
    ) {
        let claims = claim_paths
            .iter()
            .filter_map(|p| self.node_for(p))
            .collect();
        let measure = if measured_subtree {
            Measure::Subtree
        } else {
            Measure::Fixed
        };
        self.push(opp, claims, measure, prio::HUNT, None);
    }

    /// Cleanup rules from a plan.
    pub fn add_clean_plan(&mut self, plan: &CleanPlan) {
        for rule in &plan.rules {
            let claims: Vec<NodeId> = rule
                .roots
                .iter()
                .filter_map(|r| self.node_for(Path::new(&r.root_path)))
                .collect();
            let confidence = match rule.estimate {
                EstimateBasis::Measured => Confidence::Measured,
                EstimateBasis::AtRunTime => Confidence::AtRunTime,
                EstimateBasis::NeedsAdmin => Confidence::NeedsAdmin,
            };
            let is_handler_or_tool = matches!(
                rule.method,
                RuleMethod::OsHandler { .. }
                    | RuleMethod::DismComponentCleanup { .. }
                    | RuleMethod::DriverStorePrune { .. }
            );
            let lane = if rule.regenerable {
                Lane::Regenerable
            } else {
                Lane::Leftover
            };
            let opp = Opportunity {
                id: format!("rule:{}", rule.rule_id),
                lane,
                title: rule.name.clone(),
                detail: rule.explain.clone(),
                path: rule.roots.first().map(|r| PathBuf::from(&r.root_path)),
                est_bytes: 0,
                raw_est_bytes: rule.est_bytes,
                confidence,
                reversibility: if rule.regenerable {
                    Reversibility::Regenerable
                } else {
                    Reversibility::Permanent
                },
                requires_admin: rule.requires_admin,
                action: ActionRef::CleanRule {
                    rule_id: rule.rule_id.clone(),
                    tier: rule.tier,
                },
                score: 0.0,
                calibration: None,
            };
            let measure = if is_handler_or_tool || claims.is_empty() {
                Measure::Fixed
            } else {
                Measure::Subtree
            };
            self.push(opp, claims, measure, prio::RULE, Some(CALIBRATION_CLEAN));
        }
    }

    /// Project artifacts, AI models, orphans, games, cold apps and cold files.
    pub fn add_insights(&mut self, report: &FullInsightsReport) {
        for a in &report.projects.artifacts {
            let claims = self.node_for(&a.artifact_path).into_iter().collect();
            // Build output of a project worked on this month is regenerable, but deleting it
            // costs a full rebuild: the owner's call, not "free" space. Stale generations of
            // active projects come from the sweep instead.
            let active = a.days_since_modified < ACTIVE_PROJECT_DAYS;
            self.push(
                Opportunity {
                    id: format!("project:{}", a.artifact_path.display()),
                    lane: if active {
                        Lane::Decision
                    } else {
                        Lane::Regenerable
                    },
                    title: format!(
                        "{} build output: {}",
                        a.ecosystem.display_name(),
                        a.project_name
                    ),
                    detail: if active {
                        format!(
                            "Active project (built {}d ago): deleting forces a full rebuild. {}",
                            a.days_since_modified, a.marker_evidence
                        )
                    } else {
                        format!(
                            "Project untouched for {}d; rebuilt if you work on it again. {}",
                            a.days_since_modified, a.marker_evidence
                        )
                    },
                    path: Some(a.artifact_path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: a.reclaimable_bytes,
                    confidence: Confidence::Measured,
                    reversibility: Reversibility::RecycleBin,
                    requires_admin: false,
                    action: ActionRef::RecyclePath {
                        path: a.artifact_path.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::PROJECT,
                None,
            );
        }
        for o in &report.orphans.candidates {
            let claims = self.node_for(&o.path).into_iter().collect();
            self.push(
                Opportunity {
                    id: format!("orphan:{}", o.path.display()),
                    lane: Lane::Leftover,
                    title: format!("Leftover app data: {}", o.folder_name),
                    detail: format!("{} ({}% confidence)", o.reason, o.confidence),
                    path: Some(o.path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: o.allocated_bytes,
                    confidence: Confidence::Heuristic,
                    reversibility: Reversibility::RecycleBin,
                    requires_admin: false,
                    action: ActionRef::RecyclePath {
                        path: o.path.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::ORPHAN,
                None,
            );
        }
        for m in &report.ai_models.models {
            let claims = self.node_for(&m.path).into_iter().collect();
            self.push(
                Opportunity {
                    id: format!("ai:{}", m.path.display()),
                    lane: Lane::Decision,
                    title: format!("{}: {}", m.kind.display_name(), m.model_name),
                    detail: format!("Model weights, last used ~{}d ago.", m.days_since_access),
                    path: Some(m.path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: m.allocated_bytes,
                    confidence: Confidence::Measured,
                    reversibility: Reversibility::RecycleBin,
                    requires_admin: false,
                    action: ActionRef::RecyclePath {
                        path: m.path.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::DECISION,
                None,
            );
        }
        for g in &report.gaming.games {
            if g.allocated_bytes < 1024 * 1024 * 1024 {
                continue;
            }
            let claims = self.node_for(&g.install_path).into_iter().collect();
            let age = g
                .days_since_access
                .map(|d| format!("last played ~{d}d ago"))
                .unwrap_or_else(|| "last play unknown".to_string());
            self.push(
                Opportunity {
                    id: format!("game:{}", g.install_path.display()),
                    lane: Lane::Decision,
                    title: format!("Game: {}", g.title),
                    detail: format!("{} install, {age}.", g.store.display_name()),
                    path: Some(g.install_path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: g.allocated_bytes,
                    confidence: Confidence::Measured,
                    reversibility: Reversibility::Permanent,
                    requires_admin: false,
                    action: ActionRef::LauncherGame {
                        store: g.store.display_name().to_string(),
                        title: g.title.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::DECISION,
                None,
            );
        }
        for a in &report.cold.cold_apps {
            let claims = a
                .install_location
                .as_deref()
                .and_then(|p| self.node_for(p))
                .into_iter()
                .collect();
            self.push(
                Opportunity {
                    id: format!("app:{}", a.app_name),
                    lane: Lane::Decision,
                    title: format!("Unused app: {}", a.app_name),
                    detail: a.telemetry_note.clone(),
                    path: a.install_location.clone(),
                    est_bytes: 0,
                    raw_est_bytes: a.allocated_bytes,
                    confidence: Confidence::Heuristic,
                    reversibility: Reversibility::Permanent,
                    requires_admin: false,
                    action: ActionRef::UninstallApp {
                        name: a.app_name.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::DECISION,
                None,
            );
        }
        for f in &report.cold.cold_files {
            if f.allocated_bytes < 256 * 1024 * 1024 {
                continue;
            }
            let claims = self.node_for(&f.path).into_iter().collect();
            self.push(
                Opportunity {
                    id: format!("cold:{}", f.path.display()),
                    lane: Lane::Decision,
                    title: format!(
                        "Untouched {}d: {}",
                        f.days_cold,
                        f.path
                            .file_name()
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_default()
                    ),
                    detail: f.path.display().to_string(),
                    path: Some(f.path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: f.allocated_bytes,
                    confidence: Confidence::Measured,
                    reversibility: Reversibility::RecycleBin,
                    requires_admin: false,
                    action: ActionRef::RecyclePath {
                        path: f.path.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::COLD_FILE,
                None,
            );
        }
    }

    /// Duplicate groups. `immutable` decides per group whether a hard link is safe (P9.6).
    pub fn add_dupes(
        &mut self,
        report: &DupeReport,
        immutable: &dyn Fn(&crate::insights::DuplicateGroup) -> bool,
    ) {
        for g in &report.groups {
            if g.files.len() < 2 || g.reclaimable_bytes == 0 {
                continue;
            }
            let hardlink = immutable(g);
            // The first entry is the keeper (remediation default `--keep 0`).
            let claims: Vec<NodeId> = g.files.iter().skip(1).map(|f| f.node_id).collect();
            let name = g.files[0]
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            self.push(
                Opportunity {
                    id: format!("dupe:{}", g.blake3_hex),
                    lane: if hardlink {
                        Lane::Invisible
                    } else {
                        Lane::Leftover
                    },
                    title: format!("{} identical copies of {name}", g.files.len()),
                    detail: g
                        .files
                        .iter()
                        .map(|f| f.path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" | "),
                    path: Some(g.files[0].path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: g.reclaimable_bytes,
                    confidence: Confidence::Measured,
                    reversibility: if hardlink {
                        Reversibility::Reversible
                    } else {
                        Reversibility::RecycleBin
                    },
                    requires_admin: false,
                    action: ActionRef::DupeGroup {
                        blake3_hex: g.blake3_hex.clone(),
                        hardlink,
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::DUPE,
                None,
            );
        }
    }

    /// Hibernation, pagefile, CompactOS, Reserved Storage, shadow storage.
    pub fn add_sizing(&mut self, recs: &[SizingRecommendation], system_drive: &str) {
        for r in recs {
            if r.est_savings_bytes == 0 {
                continue;
            }
            let file = match r.id.as_str() {
                "sizing:hiberfile_reduced" => Some("hiberfil.sys"),
                "sizing:pagefile" => Some("pagefile.sys"),
                _ => None,
            };
            let claims = file
                .and_then(|f| self.node_for(&PathBuf::from(format!(r"{system_drive}\{f}"))))
                .into_iter()
                .collect();
            self.push(
                Opportunity {
                    id: r.id.clone(),
                    lane: Lane::Sizing,
                    title: r.title.clone(),
                    detail: format!("{} Trade-off: {}", r.detail, r.caveat),
                    path: None,
                    est_bytes: 0,
                    raw_est_bytes: r.est_savings_bytes,
                    confidence: match r.confidence {
                        SizingConfidence::Measured => Confidence::Measured,
                        SizingConfidence::Typical => Confidence::Heuristic,
                    },
                    reversibility: Reversibility::Reversible,
                    requires_admin: r.requires_admin,
                    action: r
                        .intent
                        .clone()
                        .map(|intent| ActionRef::Optimizer { intent })
                        .unwrap_or(ActionRef::None),
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Fixed,
                prio::SIZING,
                None,
            );
        }
    }

    /// Virtual disks. `est_reclaimable_bytes` comes from the P9.4 guest estimator (0 = unknown).
    pub fn add_vhdx(&mut self, candidates: &[VhdxCandidate]) {
        for c in candidates {
            // WSL and Docker have a known trim + compact workflow; other VM disks belong to their
            // own app (Hyper-V, VirtualBox, app-bundled VMs) and are only worth listing when large.
            let known_workflow = matches!(
                c.kind,
                crate::optimize::vhdx::VhdxKind::WslDistro
                    | crate::optimize::vhdx::VhdxKind::DockerDesktop
            );
            if !known_workflow && c.est_reclaimable_bytes < (1u64 << 30) {
                continue;
            }
            let in_program_files = crate::clean::deny::is_under_root(
                &c.path,
                &crate::win::volume::program_files_dir(),
            ) || crate::clean::deny::is_under_root(
                &c.path,
                &crate::win::volume::program_files_x86_dir(),
            );
            let known_but_tiny =
                c.est_reclaimable_bytes > 0 && c.est_reclaimable_bytes < 64 * 1024 * 1024;
            if in_program_files || known_but_tiny {
                continue;
            }
            let claims = self.node_for(&c.path).into_iter().collect();
            let known = c.est_reclaimable_bytes > 0;
            let guest = c
                .guest_used_bytes
                .map(|u| format!(" Guest uses {:.1} GiB.", u as f64 / (1u64 << 30) as f64))
                .unwrap_or_default();
            self.push(
                Opportunity {
                    id: format!("vhdx:{}", c.path.display()),
                    lane: Lane::Invisible,
                    title: format!(
                        "Trim and compact {}",
                        c.distro_name
                            .as_deref()
                            .unwrap_or(&format!("{:?} disk", c.kind))
                    ),
                    detail: format!(
                        "{:.1} GiB virtual disk.{guest}{}",
                        c.host_allocated_bytes as f64 / (1u64 << 30) as f64,
                        if known {
                            ""
                        } else {
                            " Free space inside is unknown until measured."
                        }
                    ),
                    path: Some(c.path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: c.est_reclaimable_bytes,
                    confidence: if known {
                        Confidence::Sampled
                    } else {
                        Confidence::AtRunTime
                    },
                    reversibility: Reversibility::Reversible,
                    requires_admin: true,
                    action: ActionRef::CompactVhdx {
                        path: c.path.clone(),
                        distro: c.distro_name.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Fixed,
                prio::VHDX,
                Some(CALIBRATION_VHDX),
            );
        }
    }

    /// Folders that shrink under WOF compression.
    pub fn add_compression(&mut self, candidates: &[CompressCandidate]) {
        for c in candidates {
            let Some(node) = self.node_for(&c.path) else {
                continue;
            };
            let raw = self
                .index
                .map(|ix| (ix.total_allocated(node) as f64 * c.savings_ratio) as u64)
                .unwrap_or(0);
            self.push(
                Opportunity {
                    id: format!("wof:{}", c.path.display()),
                    lane: Lane::Invisible,
                    title: format!(
                        "Compress {} ({})",
                        c.path
                            .file_name()
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_default(),
                        c.algorithm.as_compact_arg()
                    ),
                    detail: format!(
                        "Transparent WOF compression; about {:.0} % smaller{}.",
                        c.savings_ratio * 100.0,
                        if c.measured {
                            " (trial-compressed)"
                        } else {
                            " (sampled)"
                        }
                    ),
                    path: Some(c.path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: raw,
                    confidence: if c.measured {
                        Confidence::Measured
                    } else {
                        Confidence::Sampled
                    },
                    reversibility: Reversibility::Reversible,
                    requires_admin: c.requires_admin,
                    action: ActionRef::CompressFolder {
                        path: c.path.clone(),
                        algorithm: c.algorithm,
                    },
                    score: 0.0,
                    calibration: None,
                },
                vec![node],
                Measure::Ratio(c.savings_ratio.clamp(0.0, 1.0)),
                prio::COMPRESS,
                Some(CALIBRATION_WOF),
            );
        }
    }

    /// Stale build generations: they belong to the sweep, the rest of the folder to its project.
    pub fn add_sweeps(&mut self, sweeps: &[crate::sweep::SweepCandidate]) {
        for c in sweeps {
            if c.stale_bytes == 0 {
                continue;
            }
            let rels: FxHashSet<String> = c
                .planned
                .items
                .iter()
                .map(|i| i.rel_path.to_ascii_lowercase())
                .collect();
            // Claim only top-level stale items (their subtrees follow).
            let claims: Vec<NodeId> = c
                .planned
                .items
                .iter()
                .filter(|i| {
                    i.rel_path
                        .rsplit_once('\\')
                        .is_none_or(|(parent, _)| !rels.contains(&parent.to_ascii_lowercase()))
                })
                .filter_map(|i| self.node_for(&c.root.join(&i.rel_path)))
                .collect();
            self.push(
                Opportunity {
                    id: format!("sweep:{}", c.root.display()),
                    lane: Lane::Regenerable,
                    title: format!(
                        "{}: stale build generations in {}",
                        c.kind.label(),
                        c.project
                            .file_name()
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_default()
                    ),
                    detail: format!(
                        "{} stale of {} units; the current build is kept (newest output {}d old).",
                        c.stale_units,
                        c.stale_units + c.kept_units,
                        c.newest_build_days.unwrap_or(0)
                    ),
                    path: Some(c.root.clone()),
                    est_bytes: 0,
                    raw_est_bytes: c.stale_bytes,
                    confidence: Confidence::Measured,
                    reversibility: Reversibility::Regenerable,
                    requires_admin: false,
                    action: ActionRef::SweepBuildOutput {
                        root: c.root.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::SWEEP,
                Some(CALIBRATION_CLEAN),
            );
        }
    }

    /// Downloads intelligence findings (installers of installed software, extracted archives,
    /// partial downloads).
    pub fn add_downloads(&mut self, report: &crate::insights::downloads::DownloadsReport) {
        for f in &report.findings {
            let claims = self.node_for(&f.path).into_iter().collect();
            self.push(
                Opportunity {
                    id: format!("download:{}", f.path.display()),
                    lane: Lane::Leftover,
                    title: f
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    detail: format!(
                        "{} ({}% confidence, {}d old)",
                        crate::insights::downloads::describe(&f.kind),
                        f.confidence,
                        f.days_old
                    ),
                    path: Some(f.path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: f.bytes,
                    confidence: if f.confidence >= 80 {
                        Confidence::Measured
                    } else {
                        Confidence::Heuristic
                    },
                    reversibility: Reversibility::RecycleBin,
                    requires_admin: false,
                    action: ActionRef::RecyclePath {
                        path: f.path.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Subtree,
                prio::ORPHAN,
                None,
            );
        }
    }

    /// Oversized recordings: the owner moves them or shrinks them with `disksaver videos`.
    pub fn add_recordings(&mut self, report: &crate::insights::media::RecordingsReport) {
        for r in &report.findings {
            let claims = self.node_for(&r.path).into_iter().collect();
            self.push(
                Opportunity {
                    id: format!("recording:{}", r.path.display()),
                    lane: Lane::Decision,
                    title: format!(
                        "Oversized recording: {}",
                        r.path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
                    ),
                    detail: format!(
                        "{:.0} Mbit/s for {:.0} min; about {:.1} GiB at {:.0} Mbit/s. Shrink it with a verified AV1/HEVC re-encode (disksaver videos), or move the library to another drive (disksaver move-library videos <D:\\Videos>).",
                        r.bitrate_mbps,
                        r.duration_secs / 60.0,
                        r.reencoded_bytes as f64 / (1u64 << 30) as f64,
                        crate::insights::media::REENCODE_TARGET_MBPS
                    ),
                    path: Some(r.path.clone()),
                    est_bytes: 0,
                    raw_est_bytes: r.bytes.saturating_sub(r.reencoded_bytes),
                    confidence: Confidence::Heuristic,
                    reversibility: Reversibility::Permanent,
                    requires_admin: false,
                    action: ActionRef::CompressVideo {
                        path: r.path.clone(),
                    },
                    score: 0.0,
                    calibration: None,
                },
                claims,
                Measure::Fixed,
                prio::DECISION,
                None,
            );
        }
    }

    /// Resolves ownership, applies calibration, ranks, and totals.
    pub fn finish(mut self) -> Ledger {
        let n = self.index.map(|ix| ix.len()).unwrap_or(0);
        let mut owner_of = vec![u32::MAX; n];
        // Owner decisions (uninstall, delete a model, move a recording) are alternatives to the
        // other lanes, not overlapping deletions: they resolve after everything else, so they
        // never take bytes from compression or cleanup. Within each pass: priority, then larger
        // raw estimates first.
        let mut order: Vec<usize> = (0..self.pending.len()).collect();
        order.sort_by(|&a, &b| {
            let (pa, pb) = (&self.pending[a], &self.pending[b]);
            (pa.opp.lane == Lane::Decision)
                .cmp(&(pb.opp.lane == Lane::Decision))
                .then(pa.priority.cmp(&pb.priority))
                .then(pb.opp.raw_est_bytes.cmp(&pa.opp.raw_est_bytes))
        });

        let mut resolved: Vec<Opportunity> = Vec::with_capacity(order.len());
        for &i in &order {
            let p = &self.pending[i];
            let slot = resolved.len() as u32;
            let decision = p.opp.lane == Lane::Decision;
            let lanes: Vec<Lane> = resolved.iter().map(|o| o.lane).collect();
            let unowned = match self.index {
                Some(ix) if !p.claims.is_empty() => claim_subtrees(
                    ix,
                    &p.claims,
                    &mut owner_of,
                    slot,
                    // A decision still counts bytes that are only compressed (uninstalling frees
                    // them too); bytes another deletion or decision owns are not counted twice.
                    &|owner: u32| decision && lanes.get(owner as usize) == Some(&Lane::Invisible),
                ),
                _ => 0,
            };
            let mut est = match p.measure {
                Measure::Fixed => p.opp.raw_est_bytes,
                Measure::Subtree if p.claims.is_empty() => p.opp.raw_est_bytes,
                Measure::Subtree => p.opp.raw_est_bytes.min(unowned),
                Measure::Ratio(r) => (unowned as f64 * r) as u64,
            };
            let mut opp = p.opp.clone();
            if let Some(cat) = p.calibration_category
                && let Some(&(_, ratio)) = self.calibration.iter().find(|(c, _)| *c == cat)
            {
                est = (est as f64 * ratio) as u64;
                opp.calibration = Some(ratio);
            }
            opp.est_bytes = est;
            opp.score = est as f64 * opp.confidence.weight();
            resolved.push(opp);
        }

        // Display order: lane, then score. Remap owners to the new positions.
        let mut display: Vec<usize> = (0..resolved.len()).collect();
        display.sort_by(|&a, &b| {
            resolved[a]
                .lane
                .cmp(&resolved[b].lane)
                .then(resolved[b].score.total_cmp(&resolved[a].score))
        });
        let mut new_pos = vec![0u32; resolved.len()];
        for (pos, &old) in display.iter().enumerate() {
            new_pos[old] = pos as u32;
        }
        for o in owner_of.iter_mut().filter(|o| **o != u32::MAX) {
            *o = new_pos[*o as usize];
        }
        let opportunities: Vec<Opportunity> =
            display.into_iter().map(|i| resolved[i].clone()).collect();

        let mut lane_totals: Vec<LaneTotal> = Vec::new();
        for lane in [
            Lane::Invisible,
            Lane::Sizing,
            Lane::Regenerable,
            Lane::Leftover,
            Lane::Decision,
        ] {
            let (bytes, count) = opportunities
                .iter()
                .filter(|o| o.lane == lane)
                .fold((0u64, 0usize), |(b, c), o| {
                    (b.saturating_add(o.est_bytes), c + 1)
                });
            lane_totals.push(LaneTotal { lane, bytes, count });
        }
        let headline_bytes = lane_totals
            .iter()
            .filter(|t| t.lane.in_headline())
            .map(|t| t.bytes)
            .fold(0u64, u64::saturating_add);

        if opportunities
            .iter()
            .any(|o| o.reversibility == Reversibility::RecycleBin)
        {
            self.notes.push(
                "Items moved to the Recycle Bin free space only when the bin is emptied."
                    .to_string(),
            );
        }

        Ledger {
            volume_root: self.volume_root,
            opportunities,
            lane_totals,
            headline_bytes,
            notes: self.notes,
            owner_of,
        }
    }
}

/// Marks every unowned node under `roots` as owned by `slot` and returns their allocated bytes.
/// Nodes owned by an earlier entry count too when `shared(owner)` says so (they keep that owner).
/// Reparse directories are not entered; secondary hard links already carry 0 allocated bytes.
fn claim_subtrees(
    ix: &Index,
    roots: &[NodeId],
    owner_of: &mut [u32],
    slot: u32,
    shared: &dyn Fn(u32) -> bool,
) -> u64 {
    let mut bytes = 0u64;
    let mut stack: Vec<NodeId> = roots.to_vec();
    let mut seen: FxHashSet<NodeId> = FxHashSet::default();
    while let Some(node) = stack.pop() {
        if !seen.insert(node) {
            continue;
        }
        let Some(owner) = owner_of.get_mut(node as usize) else {
            continue;
        };
        let flags = ix.flags(node);
        let is_file = !flags.contains(NodeFlags::DIR);
        if *owner == u32::MAX {
            *owner = slot;
            if is_file {
                bytes = bytes.saturating_add(ix.allocated(node));
            }
        } else if is_file && shared(*owner) {
            bytes = bytes.saturating_add(ix.allocated(node));
        }
        if flags.contains(NodeFlags::DIR) && !flags.contains(NodeFlags::REPARSE) {
            stack.extend(ix.children(node));
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::volume::VolumeInfo;

    /// `C:\conda\pkgs\big.tar` (4000) and `C:\conda\lib.dll` (1000).
    fn conda_index() -> Index {
        let mut names = NameArena::new();
        let mut raw = Vec::new();
        let mut add = |key: u64, parent: u64, name: &str, dir: bool, bytes: u64| {
            let n = names.push_str(name);
            raw.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags: if dir {
                    NodeFlags::DIR
                } else {
                    NodeFlags::empty()
                },
                logical: bytes,
                allocated: bytes,
                mtime: 0,
                atime: 0,
                file_id: key,
                reparse_tag: 0,
            });
        };
        add(5, 5, r"C:", true, 0);
        add(10, 5, "conda", true, 0);
        add(11, 10, "pkgs", true, 0);
        add(12, 11, "big.tar", false, 4000);
        add(13, 10, "lib.dll", false, 1000);
        let mut b = IndexBuilder::new(
            5,
            r"C:\",
            VolumeInfo {
                root: r"C:\".into(),
                ..Default::default()
            },
        );
        b.push_batch(EntryBatch {
            entries: raw,
            names,
        });
        b.finish()
    }

    fn opp(id: &str, lane: Lane, raw: u64) -> Opportunity {
        Opportunity {
            id: id.into(),
            lane,
            title: id.into(),
            detail: String::new(),
            path: None,
            est_bytes: 0,
            raw_est_bytes: raw,
            confidence: Confidence::Measured,
            reversibility: Reversibility::Regenerable,
            requires_admin: false,
            action: ActionRef::None,
            score: 0.0,
            calibration: None,
        }
    }

    #[test]
    fn bytes_are_owned_once_by_the_highest_priority_claim() {
        let ix = conda_index();
        let pkgs = ix.find_by_path(Path::new(r"C:\conda\pkgs")).unwrap();
        let conda = ix.find_by_path(Path::new(r"C:\conda")).unwrap();
        let mut b = LedgerBuilder::new(Some(&ix));
        // A compression candidate over the whole folder (50 %) and a rule over pkgs.
        b.push(
            opp("wof:conda", Lane::Invisible, 0),
            vec![conda],
            Measure::Ratio(0.5),
            prio::COMPRESS,
            Some(CALIBRATION_WOF),
        );
        b.push(
            opp("rule:conda", Lane::Regenerable, 4000),
            vec![pkgs],
            Measure::Subtree,
            prio::RULE,
            Some(CALIBRATION_CLEAN),
        );
        // A cold-file claim on the same tarball adds nothing.
        b.push(
            opp("cold:big.tar", Lane::Decision, 4000),
            vec![
                ix.find_by_path(Path::new(r"C:\conda\pkgs\big.tar"))
                    .unwrap(),
            ],
            Measure::Subtree,
            prio::COLD_FILE,
            None,
        );
        let ledger = b.with_calibration(CALIBRATION_WOF, 0.8).finish();

        let get = |id: &str| ledger.opportunities.iter().find(|o| o.id == id).unwrap();
        assert_eq!(get("rule:conda").est_bytes, 4000);
        assert_eq!(get("cold:big.tar").est_bytes, 0);
        // Only lib.dll (1000) is left to compress: 1000 × 0.5 × 0.8 calibration.
        assert_eq!(get("wof:conda").est_bytes, 400);
        assert_eq!(get("wof:conda").calibration, Some(0.8));
        assert_eq!(ledger.headline_bytes, 4400);

        // Lanes in display order; owners follow the display positions.
        assert_eq!(ledger.opportunities[0].lane, Lane::Invisible);
        let tar = ix
            .find_by_path(Path::new(r"C:\conda\pkgs\big.tar"))
            .unwrap();
        assert_eq!(ledger.owner(tar).unwrap().id, "rule:conda");
        let dll = ix.find_by_path(Path::new(r"C:\conda\lib.dll")).unwrap();
        assert_eq!(ledger.owner(dll).unwrap().id, "wof:conda");
    }

    #[test]
    fn decisions_never_take_bytes_from_other_lanes() {
        let ix = conda_index();
        let conda = ix.find_by_path(Path::new(r"C:\conda")).unwrap();
        let pkgs = ix.find_by_path(Path::new(r"C:\conda\pkgs")).unwrap();
        let mut b = LedgerBuilder::new(Some(&ix));
        // "Uninstall conda" has a higher claim priority number but is a decision.
        b.push(
            opp("app:conda", Lane::Decision, 5000),
            vec![conda],
            Measure::Subtree,
            prio::DECISION,
            None,
        );
        b.push(
            opp("rule:pkgs", Lane::Regenerable, 4000),
            vec![pkgs],
            Measure::Subtree,
            prio::RULE,
            None,
        );
        b.push(
            opp("wof:conda", Lane::Invisible, 0),
            vec![conda],
            Measure::Ratio(0.5),
            prio::COMPRESS,
            None,
        );
        let l = b.finish();
        let get = |id: &str| {
            l.opportunities
                .iter()
                .find(|o| o.id == id)
                .unwrap()
                .est_bytes
        };
        assert_eq!(get("rule:pkgs"), 4000);
        assert_eq!(
            get("wof:conda"),
            500,
            "compression is not blocked by the decision"
        );
        assert_eq!(
            get("app:conda"),
            1000,
            "the decision counts compressed bytes, not the rule's"
        );
        assert_eq!(l.headline_bytes, 4500);
    }

    #[test]
    fn fixed_estimates_and_duplicate_ids() {
        let mut b = LedgerBuilder::new(None);
        b.push(
            opp("sizing:x", Lane::Sizing, 7),
            vec![],
            Measure::Fixed,
            prio::SIZING,
            None,
        );
        b.push(
            opp("sizing:x", Lane::Sizing, 99),
            vec![],
            Measure::Fixed,
            prio::SIZING,
            None,
        );
        let ledger = b.finish();
        assert_eq!(ledger.opportunities.len(), 1);
        assert_eq!(ledger.opportunities[0].est_bytes, 7);
        assert_eq!(ledger.headline_bytes, 0, "sizing is not in the headline");
        let sizing = ledger
            .lane_totals
            .iter()
            .find(|t| t.lane == Lane::Sizing)
            .unwrap();
        assert_eq!((sizing.bytes, sizing.count), (7, 1));
    }

    #[test]
    fn cli_hints_name_existing_commands() {
        let hint = ActionRef::CleanRule {
            rule_id: "dev.uv.cache".into(),
            tier: RuleTier::Safe,
        }
        .cli_hint();
        assert_eq!(
            hint,
            "disksaver clean --rule dev.uv.cache --tier safe --yes"
        );
        let hint = ActionRef::Optimizer {
            intent: OptimizerIntent::SetHiberfile {
                mode: crate::optimize::sys_tunables::HiberfileMode::Reduced,
            },
        }
        .cli_hint();
        assert!(hint.contains("--hiberfile reduced"));
    }
}
