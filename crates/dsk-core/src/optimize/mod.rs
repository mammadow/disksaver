#![forbid(unsafe_code)]

//! Non-destructive space reclamation engines for VHDX compaction, WOF transparent compression,
//! system storage tunables, Cloud Files dehydration, and verified folder relocation.

pub mod cloud;
pub mod intent;
pub mod relocate;
pub mod sizing;
pub mod sys_tunables;
pub mod vhdx;
pub mod vhdx_inspect;
pub mod wof;
pub mod wof_discover;

pub use cloud::{CloudDehydrateCandidate, dehydrate_cloud_file, find_hydrated_cloud_candidates};
pub use intent::{OptimizerIntent, run_optimizer_intent};
pub use relocate::{
    RelocationPlan, RelocationReport, execute_folder_relocation, undo_folder_relocation,
};
pub use sys_tunables::{
    HiberfileMode, SystemTunablesStatus, configure_hiberfile, probe_sys_tunables,
    resize_or_prune_vss, set_reserved_storage,
};
pub use vhdx::{
    VhdxCandidate, VhdxCompactReport, VhdxKind, build_diskpart_compact_script, compact_vhdx,
    discover_vhdx_candidates,
};
pub use wof::{
    CompactOsReport, CompactOsState, WofAlgorithm, WofCompressionReport, WofSamplePreview,
    compress_folder_wof, query_compact_os_state, sample_folder_compressibility,
    set_compact_os_enabled,
};

use serde::{Deserialize, Serialize};

/// High-level categories of non-destructive optimizations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimizerKind {
    VhdxCompact,
    WofCompress,
    CompactOs,
    SysTunables,
    CloudDehydrate,
    FolderRelocate,
}

/// Generic candidate surfaced by optimizer discovery for user review.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizeCandidate {
    pub kind: OptimizerKind,
    pub title: String,
    pub description: String,
    pub target_path: String,
    pub current_bytes: u64,
    pub estimated_reclaimable_bytes: u64,
    pub requires_admin: bool,
    pub safe_recommended: bool,
}

/// Summary report returned upon applying an optimization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizeReport {
    pub kind: OptimizerKind,
    pub target: String,
    pub before_free_bytes: u64,
    pub after_free_bytes: u64,
    pub freed_bytes: u64,
    pub detail: String,
}
