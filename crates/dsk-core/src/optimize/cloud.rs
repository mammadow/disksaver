#![forbid(unsafe_code)]

//! Cloud Files API placeholder dehydration engine (§8.4).
//!
//! Identifies hydrated cloud placeholders (OneDrive, Dropbox, iCloud, Google Drive, Box)
//! consuming local disk space and safely dehydrates them without losing un-uploaded local edits.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::win::cfapi::{dehydrate_placeholder_file, is_placeholder_in_sync};

/// Candidate file managed by Cloud Files API that is currently hydrated locally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudDehydrateCandidate {
    pub node_id: NodeId,
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub days_since_access: u32,
}

/// Identifies regular files managed by Cloud Files providers that are hydrated locally
/// and exceed the specified age and size thresholds.
pub fn find_hydrated_cloud_candidates(
    index: &Index,
    min_age_days: u32,
    min_bytes: u64,
) -> Vec<CloudDehydrateCandidate> {
    let now_ft = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| 116_444_736_000_000_000u64.saturating_add(d.as_secs().saturating_mul(10_000_000)))
        .unwrap_or(0);
    let now_mins = crate::time::filetime_to_min2000(now_ft);
    let min_age_mins = min_age_days.saturating_mul(1440);

    let mut candidates = Vec::new();
    let mut stack: Vec<NodeId> = index.children(ROOT).collect();

    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if flags.contains(NodeFlags::DIR) {
            stack.extend(index.children(node));
            continue;
        }

        // Must be flagged as Cloud Files reparse point, NOT already offline/dehydrated
        let is_cloud = flags.contains(NodeFlags::CLOUD);
        let is_offline = flags.contains(NodeFlags::OFFLINE);
        let allocated = index.allocated(node);

        if is_cloud && !is_offline && allocated >= min_bytes {
            let mtime_mins = index.mtime_min(node);
            let age_mins = now_mins.saturating_sub(mtime_mins);
            if age_mins >= min_age_mins {
                let days_since_access = age_mins / 1440;
                candidates.push(CloudDehydrateCandidate {
                    node_id: node,
                    path: index.path(node),
                    allocated_bytes: allocated,
                    days_since_access,
                });
            }
        }
    }

    // Sort largest candidates first
    candidates.sort_by_key(|a| std::cmp::Reverse(a.allocated_bytes));
    candidates
}

/// Safely dehydrates a local cloud file placeholder, verifying in-sync state first.
///
/// Returns the number of local bytes reclaimed.
pub fn dehydrate_cloud_file(path: &Path, dry_run: bool) -> Result<u64> {
    if !path.exists() {
        return Err(DskError::Optimize(format!(
            "path does not exist: {}",
            path.display()
        )));
    }

    if dry_run {
        let in_sync = is_placeholder_in_sync(path)?;
        if !in_sync {
            return Err(DskError::PreconditionFailed(
                "cloud file is not in sync with remote provider".to_string(),
            ));
        }
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        return Ok(size);
    }

    dehydrate_placeholder_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::volume::VolumeInfo;
    use tempfile::tempdir;

    #[test]
    fn find_hydrated_cloud_candidates_filters_by_cloud_flag_allocated_size_and_age() {
        let now_ft = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_mul(10_000_000)
            + 116_444_736_000_000_000;
        let old_time = now_ft.saturating_sub(100 * 86400 * 10_000_000);
        let recent_time = now_ft.saturating_sub(5 * 86400 * 10_000_000);

        let mut builder = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();

        let r1 = names.push_str("synced_large_old.pdf");
        let r2 = names.push_str("small.txt");
        let r3 = names.push_str("offline.zip");
        let r4 = names.push_str("recent.iso");
        let r5 = names.push_str("local.bin");

        builder.push_batch(EntryBatch {
            names,
            entries: vec![
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    name: r1,
                    flags: NodeFlags::CLOUD,
                    logical: 10_000_000,
                    allocated: 10_000_000,
                    mtime: old_time,
                    atime: old_time,
                    file_id: 10,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 5,
                    name: r2,
                    flags: NodeFlags::CLOUD,
                    logical: 100,
                    allocated: 100,
                    mtime: old_time,
                    atime: old_time,
                    file_id: 11,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 12,
                    parent_key: 5,
                    name: r3,
                    flags: NodeFlags::CLOUD | NodeFlags::OFFLINE,
                    logical: 10_000_000,
                    allocated: 0,
                    mtime: old_time,
                    atime: old_time,
                    file_id: 12,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 13,
                    parent_key: 5,
                    name: r4,
                    flags: NodeFlags::CLOUD,
                    logical: 10_000_000,
                    allocated: 10_000_000,
                    mtime: recent_time,
                    atime: recent_time,
                    file_id: 13,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 14,
                    parent_key: 5,
                    name: r5,
                    flags: NodeFlags::empty(),
                    logical: 10_000_000,
                    allocated: 10_000_000,
                    mtime: old_time,
                    atime: old_time,
                    file_id: 14,
                    reparse_tag: 0,
                },
            ],
        });

        let index = builder.finish();

        let results = find_hydrated_cloud_candidates(&index, 30, 1_000_000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].allocated_bytes, 10_000_000);
        assert!(results[0].days_since_access >= 99);
    }

    #[test]
    fn dehydrate_cloud_file_rejects_regular_non_cloud_temp_file_safely() {
        let temp = tempdir().unwrap();
        let regular_file = temp.path().join("local_file.txt");
        fs::write(&regular_file, b"sample text not connected to cloud").unwrap();

        // Dry-run should fail because it's not a cloud placeholder
        let res = dehydrate_cloud_file(&regular_file, true);
        assert!(res.is_err());
    }
}
