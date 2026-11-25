#![forbid(unsafe_code)]

//! Actionable storage insights engines: project artifacts, AI models, duplicate finder,
//! gaming stores, orphaned app data, and cold file/program scoring.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::index::Index;
use crate::time::filetime_to_min2000;

pub mod ai_models;
pub mod cold;
pub mod downloads;
pub mod dupes;
pub mod gaming;
pub mod media;
pub mod orphans;
pub mod projects;

pub use ai_models::{AiModelCandidate, AiModelStoreKind, AiModelsReport, scan_ai_models};
pub use cold::{
    ColdAppCandidate, ColdDataReport, ColdFileCandidate, scan_cold_data, scan_cold_data_live,
};
pub use dupes::{
    DupFileEntry, DupeClass, DupeProgress, DupeRemediationAction, DupeRemediationOutcome,
    DupeReport, DupeStage, DupeStats, DuplicateGroup, HashCacheDb, classify_dupe_group,
    classify_dupe_path, default_hash_cache_path, find_duplicates, is_hardlink_safe_group,
    remediate_duplicate_group,
};
pub use gaming::{
    DiscoveredGame, GameStoreKind, GamingLibraryReport, MAX_VDF_DEPTH, VdfValue, parse_vdf,
    scan_gaming_libraries,
};
pub use orphans::{
    OrphanAppCandidate, OrphanScanReport, OrphanScope, recycle_orphan_folder,
    scan_orphaned_app_data, scan_orphaned_app_data_with_apps,
};
pub use projects::{
    ProjectArtifactCandidate, ProjectEcosystem, ProjectScanReport, scan_project_artifacts,
};

pub(crate) fn current_min2000() -> u32 {
    let now_ft = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| 116_444_736_000_000_000u64.saturating_add(d.as_secs().saturating_mul(10_000_000)))
        .unwrap_or(0);
    filetime_to_min2000(now_ft)
}

/// Configuration thresholds for the unified non-hashing insights pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsightsOptions {
    pub project_min_bytes: u64,
    pub ai_min_bytes: u64,
    pub orphan_min_bytes: u64,
    pub cold_min_file_bytes: u64,
    pub cold_days_threshold: u32,
}

impl Default for InsightsOptions {
    fn default() -> Self {
        Self {
            project_min_bytes: 1_048_576,
            ai_min_bytes: 10 * 1024 * 1024,
            orphan_min_bytes: 1_048_576,
            cold_min_file_bytes: 50 * 1024 * 1024,
            cold_days_threshold: 90,
        }
    }
}

/// Combined report aggregating all fast metadata-driven Insights analyzers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullInsightsReport {
    pub volume_root: String,
    pub projects: ProjectScanReport,
    pub ai_models: AiModelsReport,
    pub gaming: GamingLibraryReport,
    pub orphans: OrphanScanReport,
    pub cold: ColdDataReport,
    pub total_reclaimable_estimate: u64,
}

/// Executes all fast metadata-driven Insights analyzers on `index` (project artifacts,
/// AI model weights, gaming libraries, orphaned app data, and cold files/apps).
pub fn run_all_insights(index: &Index, opts: &InsightsOptions) -> FullInsightsReport {
    let projects = scan_project_artifacts(index, opts.project_min_bytes);
    let ai_models = scan_ai_models(index, opts.ai_min_bytes);
    let gaming = scan_gaming_libraries(index);
    let orphans = scan_orphaned_app_data(index, Some(&gaming), opts.orphan_min_bytes);
    let cold = scan_cold_data_live(index, opts.cold_min_file_bytes, opts.cold_days_threshold);

    let total_reclaimable_estimate = projects
        .total_reclaimable_bytes
        .saturating_add(ai_models.total_allocated_bytes)
        .saturating_add(orphans.total_allocated_bytes);

    FullInsightsReport {
        volume_root: index.volume().root.clone(),
        projects,
        ai_models,
        gaming,
        orphans,
        cold,
        total_reclaimable_estimate,
    }
}
