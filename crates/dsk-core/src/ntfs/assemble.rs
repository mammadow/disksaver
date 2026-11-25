#![forbid(unsafe_code)]

use rustc_hash::FxHashMap;

use crate::index::builder::{EntryBatch, Index, IndexBuilder, NodeFlags, RawEntry};
use crate::index::names::{NameArena, NameRef};
use crate::ntfs::summary::FileSummary;
use crate::ntfs::{
    AF_COMPRESSED, AF_SPARSE, FA_HIDDEN, FA_OFFLINE, FA_RECALL_ON_DATA_ACCESS, FA_RECALL_ON_OPEN,
    FA_SYSTEM, TAG_WOF, is_cloud_tag,
};
use crate::volume::VolumeInfo;

/// A batch of summarized NTFS file records with their associated WTF-8 names.
#[derive(Debug, Default)]
pub struct SummaryBatch {
    pub names: NameArena,
    pub items: Vec<FileSummary>,
}

/// Consolidated output of an MFT scan across multiple batches.
#[derive(Debug, Default)]
pub struct MftScanOutput {
    pub batches: Vec<SummaryBatch>,
    pub skipped: u64,
    pub total_records: u64,
}

/// Assembles MFT record summaries into a populated [`Index`].
pub fn assemble(out: MftScanOutput, volume: VolumeInfo) -> Index {
    let mut combined_names = NameArena::new();
    let mut base_records: FxHashMap<u64, FileSummary> = FxHashMap::default();
    let mut extension_records: Vec<FileSummary> = Vec::new();

    // 1. Cross-batch NameArena rebasing and partitioning into base and extension records
    for mut batch in out.batches {
        let base_off = combined_names.append(&batch.names);
        if base_off != 0 {
            for item in &mut batch.items {
                for link in &mut item.names {
                    link.name.off += base_off;
                }
            }
        }
        for item in batch.items {
            if item.base_record == 0 {
                base_records.insert(item.record, item);
            } else {
                extension_records.push(item);
            }
        }
    }

    // 2. Merge extension records into base records
    for ext in extension_records {
        if let Some(base) = base_records.get_mut(&ext.base_record) {
            base.allocated = base.allocated.saturating_add(ext.allocated);
            base.has_ads |= ext.has_ads;
            base.has_wof_stream |= ext.has_wof_stream;
            base.unnamed_flags |= ext.unnamed_flags;
            base.names.extend(ext.names);
            if base.logical == 0 {
                base.logical = ext.logical;
            }
            if base.si.is_none() {
                base.si = ext.si;
            }
            if base.reparse_tag == 0 {
                base.reparse_tag = ext.reparse_tag;
            }
        }
    }

    // 3. Build RawEntry list
    let mut raw_entries = Vec::new();

    let mut records: Vec<u64> = base_records.keys().copied().collect();
    records.sort_unstable();

    for record_no in records {
        let summary = match base_records.get(&record_no) {
            Some(s) => s,
            None => continue,
        };

        let mut flags = NodeFlags::empty();
        if summary.is_dir {
            flags |= NodeFlags::DIR;
        }
        if let Some(si) = summary.si {
            if (si.attributes & FA_HIDDEN) != 0 {
                flags |= NodeFlags::HIDDEN;
            }
            if (si.attributes & FA_SYSTEM) != 0 {
                flags |= NodeFlags::SYSTEM;
            }
            if (si.attributes & FA_OFFLINE) != 0 {
                flags |= NodeFlags::OFFLINE;
            }
            if (si.attributes & (FA_RECALL_ON_OPEN | FA_RECALL_ON_DATA_ACCESS)) != 0 {
                flags |= NodeFlags::CLOUD;
            }
        }
        if is_cloud_tag(summary.reparse_tag) {
            flags |= NodeFlags::CLOUD;
        }
        if summary.reparse_tag != 0 {
            flags |= NodeFlags::REPARSE;
        }
        if summary.reparse_tag == TAG_WOF || summary.has_wof_stream {
            flags |= NodeFlags::WOF;
        }
        if (summary.unnamed_flags & AF_COMPRESSED) != 0 {
            flags |= NodeFlags::COMPRESSED;
        }
        if (summary.unnamed_flags & AF_SPARSE) != 0 {
            flags |= NodeFlags::SPARSE;
        }
        if summary.has_ads {
            flags |= NodeFlags::ADS;
        }
        if summary.record < 24 && summary.record != 5 {
            flags |= NodeFlags::METAFILE;
        }

        let (mtime, atime) = match summary.si {
            Some(si) => (si.mtime, si.atime),
            None => (0, 0),
        };
        let file_id = ((summary.seq as u64) << 48) | summary.record;

        // Root record (record 5) handling
        if summary.record == 5 {
            raw_entries.push(RawEntry {
                key: 5,
                parent_key: 5,
                name: NameRef::default(),
                flags,
                logical: summary.logical,
                allocated: summary.allocated,
                mtime,
                atime,
                file_id,
                reparse_tag: summary.reparse_tag,
            });
            continue;
        }

        // Records with no non-DOS names (other than root) are dropped
        if summary.names.is_empty() {
            continue;
        }

        // Emit RawEntry for each link
        for link in &summary.names {
            let parent_valid = match base_records.get(&link.parent_record) {
                Some(parent_summary) => parent_summary.seq == link.parent_seq,
                None => false,
            };
            let parent_key = if parent_valid {
                link.parent_record
            } else {
                u64::MAX
            };

            raw_entries.push(RawEntry {
                key: summary.record,
                parent_key,
                name: link.name,
                flags,
                logical: summary.logical,
                allocated: summary.allocated,
                mtime,
                atime,
                file_id,
                reparse_tag: summary.reparse_tag,
            });
        }
    }

    // 4. Initialize IndexBuilder and assemble Index
    let root_path = volume.root.clone();
    let mut builder = IndexBuilder::new(5, &root_path, volume);
    builder.push_batch(EntryBatch {
        names: combined_names,
        entries: raw_entries,
    });
    builder.finish()
}

#[cfg(test)]
mod tests {
    use smallvec::smallvec;
    use std::path::PathBuf;

    use super::*;
    use crate::index::{NodeFlags, ROOT};
    use crate::ntfs::attr::StandardInfo;
    use crate::ntfs::summary::LinkName;
    use crate::ntfs::{
        AF_COMPRESSED, AF_SPARSE, FA_HIDDEN, FA_OFFLINE, FA_RECALL_ON_DATA_ACCESS,
        FA_RECALL_ON_OPEN, FA_SYSTEM, TAG_WOF,
    };

    fn test_volume() -> VolumeInfo {
        VolumeInfo {
            root: r"C:\".to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0x1234_5678,
            cluster_size: 4096,
            total_bytes: 1_000_000_000,
            free_bytes: 500_000_000,
            seek_penalty: Some(false),
        }
    }

    fn make_summary(record: u64, seq: u16, is_dir: bool) -> FileSummary {
        FileSummary {
            record,
            seq,
            base_record: 0,
            is_dir,
            si: None,
            names: smallvec![],
            logical: 0,
            allocated: 0,
            has_ads: false,
            has_wof_stream: false,
            unnamed_flags: 0,
            reparse_tag: 0,
        }
    }

    #[test]
    fn root_and_children() {
        let mut names = NameArena::new();
        let name_file = names.push_str("file.txt");

        let root = make_summary(5, 5, true);
        let mut file = make_summary(30, 1, false);
        file.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_file,
        });

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, file],
            }],
            skipped: 0,
            total_records: 2,
        };

        let ix = assemble(out, test_volume());
        let f = 1; // node id 1 is file.txt
        assert_eq!(ix.path(f), PathBuf::from(r"C:\file.txt"));
    }

    #[test]
    fn extension_merged_into_base() {
        let mut names = NameArena::new();
        let name_file = names.push_str("file.txt");

        let root = make_summary(5, 5, true);
        let mut base = make_summary(30, 1, false);
        base.allocated = 4096;
        base.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_file,
        });

        let mut ext = make_summary(31, 1, false);
        ext.base_record = 30;
        ext.allocated = 2 * 4096;

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, base, ext],
            }],
            skipped: 0,
            total_records: 3,
        };

        let ix = assemble(out, test_volume());
        let n = 1;
        assert_eq!(ix.allocated(n), 3 * 4096);
        assert_eq!(ix.len(), 2);
    }

    #[test]
    fn stale_parent_seq_orphans() {
        let mut names = NameArena::new();
        let name_dir = names.push_str("dir");
        let name_stale = names.push_str("stale.txt");

        let root = make_summary(5, 5, true);
        let mut dir = make_summary(30, 2, true);
        dir.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_dir,
        });

        let mut stale_file = make_summary(40, 1, false);
        // Stale sequence: directory has seq 2, file references parent_seq 1
        stale_file.names.push(LinkName {
            parent_record: 30,
            parent_seq: 1,
            name: name_stale,
        });

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, dir, stale_file],
            }],
            skipped: 0,
            total_records: 3,
        };

        let ix = assemble(out, test_volume());
        // Find stale.txt node id
        let n = (1..ix.len() as u32)
            .find(|&id| ix.name(id) == "stale.txt")
            .expect("stale.txt node should exist");
        assert!(ix.flags(ix.parent(n)).contains(NodeFlags::ORPHANS));
    }

    #[test]
    fn flags_mapped() {
        let mut names = NameArena::new();
        let name_file = names.push_str("cloud.txt");

        let root = make_summary(5, 5, true);
        let mut file = make_summary(30, 1, false);
        file.si = Some(StandardInfo {
            mtime: 100,
            atime: 200,
            attributes: FA_HIDDEN | FA_SYSTEM | FA_RECALL_ON_OPEN,
        });
        file.reparse_tag = 0x9000_001A; // is_cloud_tag is true
        file.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_file,
        });

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, file],
            }],
            skipped: 0,
            total_records: 2,
        };

        let ix = assemble(out, test_volume());
        let n = 1;
        assert!(ix.flags(n).contains(
            NodeFlags::HIDDEN | NodeFlags::SYSTEM | NodeFlags::CLOUD | NodeFlags::REPARSE
        ));
    }

    #[test]
    fn metafiles_flagged() {
        let mut names = NameArena::new();
        let name_extend = names.push_str("$Extend");
        let name_usn = names.push_str("$UsnJrnl");

        let root = make_summary(5, 5, true);
        let mut extend = make_summary(11, 1, true); // rec 11 is < 24
        extend.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_extend,
        });

        let mut usn = make_summary(40, 1, false); // rec 40 is >= 24 under 11
        usn.names.push(LinkName {
            parent_record: 11,
            parent_seq: 1,
            name: name_usn,
        });

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, extend, usn],
            }],
            skipped: 0,
            total_records: 3,
        };

        let ix = assemble(out, test_volume());
        let usn_node = (1..ix.len() as u32)
            .find(|&id| ix.name(id) == "$UsnJrnl")
            .expect("$UsnJrnl node exists");
        assert!(ix.flags(usn_node).contains(NodeFlags::METAFILE));
    }

    #[test]
    fn root_is_not_metafile() {
        let mut names = NameArena::new();
        let name_user = names.push_str("user.txt");

        let root = make_summary(5, 5, true);
        let mut user_file = make_summary(30, 1, false);
        user_file.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_user,
        });

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, user_file],
            }],
            skipped: 0,
            total_records: 2,
        };

        let ix = assemble(out, test_volume());
        let user_node = 1;
        assert!(!ix.flags(ROOT).contains(NodeFlags::METAFILE));
        assert!(!ix.flags(user_node).contains(NodeFlags::METAFILE));
    }

    #[test]
    fn file_id_encodes_seq() {
        let mut names = NameArena::new();
        let name_file = names.push_str("file.txt");

        let root = make_summary(5, 5, true);
        let mut file = make_summary(30, 3, false);
        file.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_file,
        });

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, file],
            }],
            skipped: 0,
            total_records: 2,
        };

        let ix = assemble(out, test_volume());
        let n = 1;
        assert_eq!(ix.file_id(n), (3u64 << 48) | 30);
    }

    #[test]
    fn cross_batch_rebasing_and_extension_merge() {
        let mut names0 = NameArena::new();
        let name_primary = names0.push_str("primary.txt");

        let mut names1 = NameArena::new();
        let name_alias = names1.push_str("alias.txt");

        let root = make_summary(5, 5, true);
        let mut base = make_summary(30, 1, false);
        base.allocated = 4096;
        base.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_primary,
        });

        let mut ext = make_summary(31, 1, false);
        ext.base_record = 30;
        ext.allocated = 4096;
        ext.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_alias,
        });

        let out = MftScanOutput {
            batches: vec![
                SummaryBatch {
                    names: names0,
                    items: vec![root, base],
                },
                SummaryBatch {
                    names: names1,
                    items: vec![ext],
                },
            ],
            skipped: 0,
            total_records: 3,
        };

        let ix = assemble(out, test_volume());
        assert_eq!(ix.allocated(1), 8192);
        assert_eq!(ix.name(1), "primary.txt");
        assert_eq!(ix.name(2), "alias.txt");
        assert!(ix.flags(1).contains(NodeFlags::HARDLINK));
        assert!(
            ix.flags(2)
                .contains(NodeFlags::HARDLINK | NodeFlags::DUP_LINK)
        );
    }

    #[test]
    fn flags_wof_sparse_compressed_ads_offline() {
        let mut names = NameArena::new();
        let name_file = names.push_str("special.dat");

        let root = make_summary(5, 5, true);
        let mut file = make_summary(30, 1, false);
        file.si = Some(StandardInfo {
            mtime: 10,
            atime: 20,
            attributes: FA_OFFLINE | FA_RECALL_ON_DATA_ACCESS,
        });
        file.unnamed_flags = AF_COMPRESSED | AF_SPARSE;
        file.reparse_tag = TAG_WOF;
        file.has_ads = true;
        file.names.push(LinkName {
            parent_record: 5,
            parent_seq: 5,
            name: name_file,
        });

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names,
                items: vec![root, file],
            }],
            skipped: 0,
            total_records: 2,
        };

        let ix = assemble(out, test_volume());
        let n = 1;
        let expected = NodeFlags::OFFLINE
            | NodeFlags::CLOUD
            | NodeFlags::COMPRESSED
            | NodeFlags::SPARSE
            | NodeFlags::WOF
            | NodeFlags::ADS
            | NodeFlags::REPARSE;
        assert!(ix.flags(n).contains(expected));
    }

    #[test]
    fn unnamed_records_dropped() {
        let root = make_summary(5, 5, true);
        // Record with no names
        let nameless = make_summary(50, 1, false);

        let out = MftScanOutput {
            batches: vec![SummaryBatch {
                names: NameArena::new(),
                items: vec![root, nameless],
            }],
            skipped: 0,
            total_records: 2,
        };

        let ix = assemble(out, test_volume());
        // Only ROOT should exist
        assert_eq!(ix.len(), 1);
    }
}
