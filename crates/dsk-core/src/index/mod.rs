#![forbid(unsafe_code)]

pub mod builder;
pub mod codec;
pub mod growth;
pub mod names;
pub mod query;
pub mod snapshot;
pub mod usn_delta;

pub use builder::{EntryBatch, Index, IndexBuilder, NONE, NodeFlags, NodeId, ROOT, RawEntry};
pub use codec::{CODEC_MAGIC, CODEC_VERSION, decode_scan_report, encode_scan_report};
pub use growth::{
    GrowthDb, GrowthDelta, GrowthReport, GrowthWindow, MAX_ROLLUP_DEPTH, MAX_ROWS_PER_SNAPSHOT,
    MIN_ROLLUP_BYTES, RETENTION_DAYS, RUNAWAY_BYTES_PER_DAY, SizeBasis,
};
pub use names::{NameArena, NameRef, wtf8_to_os_string, wtf8_to_string_lossy};
pub use query::{ext_breakdown, ext_breakdown_subtree, top_dirs, top_files};
pub use snapshot::{
    SNAPSHOT_MAGIC, SNAPSHOT_VERSION, SnapshotMeta, default_snapshot_dir, load_snapshot_verified,
    save_snapshot_atomic, snapshot_path_for_volume,
};
