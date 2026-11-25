//! Incremental USN delta applicator for [`Index`].

#![forbid(unsafe_code)]

use std::collections::HashSet;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::error::Result;
use crate::index::builder::{EntryBatch, Index, IndexBuilder, NONE, NodeFlags, ROOT, RawEntry};
use crate::index::names::{NameArena, NameRef};
use crate::ntfs::usn::UsnDelta;
use crate::volume::VolumeInfo;

/// Windows FILETIME ticks for `2000-01-01T00:00:00Z`.
const FILETIME_2000_01_01: u64 = 125_911_584_000_000_000;
const TICKS_PER_MINUTE: u64 = 600_000_000;

#[inline]
fn min2000_to_filetime(min: u32) -> u64 {
    if min == 0 {
        0
    } else {
        FILETIME_2000_01_01.saturating_add((min as u64).saturating_mul(TICKS_PER_MINUTE))
    }
}

#[derive(Clone, Copy)]
enum NameSource {
    Old(NameRef),
    Delta(NameRef),
}

struct WorkingNode {
    alive: bool,
    own_key: u64,
    parent_key: u64,
    target_parent_frn: Option<u64>,
    file_id: u64,
    name: NameSource,
    logical: u64,
    allocated: u64,
    mtime: u32,
    atime: u32,
    flags: NodeFlags,
    reparse_tag: u32,
}

#[inline]
fn is_ntfs_root_frn(frn: u64, root_fid: u64, is_ntfs: bool) -> bool {
    frn == root_fid || (is_ntfs && (frn & 0x0000_FFFF_FFFF_FFFF) == 5)
}

#[inline]
fn names_match_ignore_case(a: &[u8], b: &str) -> bool {
    let a_lossy = String::from_utf8_lossy(a);
    if a_lossy.eq_ignore_ascii_case(b) {
        return true;
    }
    a_lossy.to_lowercase() == b.to_lowercase()
}

fn node_name_bytes<'a>(
    wn: &WorkingNode,
    old_names: &'a NameArena,
    delta_names: &'a NameArena,
) -> &'a [u8] {
    match wn.name {
        NameSource::Old(nr) => old_names.bytes(nr),
        NameSource::Delta(nr) => delta_names.bytes(nr),
    }
}

fn parent_frn_matches(
    wn: &WorkingNode,
    expected_parent_frn: u64,
    working: &[WorkingNode],
    root_fid: u64,
    is_ntfs: bool,
) -> bool {
    if let Some(pfrn) = wn.target_parent_frn {
        return pfrn == expected_parent_frn
            || (is_ntfs_root_frn(pfrn, root_fid, is_ntfs)
                && is_ntfs_root_frn(expected_parent_frn, root_fid, is_ntfs));
    }
    if wn.parent_key == 0 {
        return false;
    }
    let pidx = (wn.parent_key - 1) as usize;
    if pidx >= working.len() || !working[pidx].alive {
        return false;
    }
    working[pidx].file_id == expected_parent_frn
        || (pidx == 0 && is_ntfs_root_frn(expected_parent_frn, root_fid, is_ntfs))
}

impl Index {
    /// Applies a batch of NTFS USN deltas and recomputes hard-link deduplication
    /// and bottom-up directory `agg_alloc` / `agg_count` totals.
    pub fn apply_usn_deltas(&mut self, deltas: &[UsnDelta]) -> Result<()> {
        self.apply_usn_deltas_with_volume(deltas, None)
    }

    /// Applies USN deltas and optionally updates the stored [`VolumeInfo`] (for example,
    /// live `free_bytes` / `total_bytes` on a cached snapshot).
    pub fn apply_usn_deltas_with_volume(
        &mut self,
        deltas: &[UsnDelta],
        updated_volume: Option<VolumeInfo>,
    ) -> Result<()> {
        if (deltas.is_empty() && updated_volume.is_none()) || self.is_empty() {
            return Ok(());
        }

        let old_len = self.len();
        let vol = updated_volume.unwrap_or_else(|| self.volume().clone());
        let is_ntfs = vol.fs_name.eq_ignore_ascii_case("NTFS");

        let mut referenced_frns: HashSet<u64> = HashSet::with_capacity(deltas.len() * 2);
        for d in deltas {
            match d {
                UsnDelta::Upsert {
                    file_id,
                    parent_file_id,
                    old_parent_file_id,
                    ..
                } => {
                    if *file_id != 0 {
                        referenced_frns.insert(*file_id);
                    }
                    if *parent_file_id != 0 {
                        referenced_frns.insert(*parent_file_id);
                    }
                    if let Some(op) = old_parent_file_id
                        && *op != 0
                    {
                        referenced_frns.insert(*op);
                    }
                }
                UsnDelta::Delete {
                    file_id,
                    parent_file_id,
                    ..
                } => {
                    if *file_id != 0 {
                        referenced_frns.insert(*file_id);
                    }
                    if let Some(pf) = parent_file_id
                        && *pf != 0
                    {
                        referenced_frns.insert(*pf);
                    }
                }
            }
        }

        let parent_sl = self.parent_slice();
        let file_id_sl = self.file_id_slice();
        let logical_sl = self.logical_slice();
        let allocated_sl = self.allocated_slice();
        let mtime_sl = self.mtime_slice();
        let atime_sl = self.atime_slice();
        let flags_sl = self.flags_slice();
        let name_off_sl = self.name_off_slice();
        let name_len_sl = self.name_len_slice();
        let old_names = self.names();

        let mut working: Vec<WorkingNode> = Vec::with_capacity(old_len + deltas.len());
        let mut frn_to_work: FxHashMap<u64, SmallVec<[usize; 1]>> = FxHashMap::default();

        for i in 0..old_len {
            let p = parent_sl[i];
            let parent_key = if p == NONE { 0 } else { (p as u64) + 1 };
            let fid = file_id_sl[i];
            let reparse_tag = self.reparse_tag(i as u32).unwrap_or(0);
            working.push(WorkingNode {
                alive: true,
                own_key: (i as u64) + 1,
                parent_key,
                target_parent_frn: None,
                file_id: fid,
                name: NameSource::Old(NameRef {
                    off: name_off_sl[i],
                    len: name_len_sl[i],
                }),
                logical: logical_sl[i],
                allocated: allocated_sl[i],
                mtime: mtime_sl[i],
                atime: atime_sl[i],
                flags: flags_sl[i] & !(NodeFlags::HARDLINK | NodeFlags::DUP_LINK),
                reparse_tag,
            });
            if fid != 0 && referenced_frns.contains(&fid) {
                frn_to_work.entry(fid).or_default().push(i);
            }
        }

        let root_fid = working[0].file_id;
        let mut delta_names = NameArena::new();

        for delta in deltas {
            match delta {
                UsnDelta::Delete {
                    file_id,
                    parent_file_id,
                    name,
                } => {
                    if *file_id == 0 || is_ntfs_root_frn(*file_id, root_fid, is_ntfs) {
                        continue;
                    }
                    let Some(indices) = frn_to_work.get(file_id) else {
                        continue;
                    };
                    match (parent_file_id, name) {
                        (Some(pfid), Some(n)) => {
                            let mut deleted_exact = false;
                            for &wi in indices {
                                if wi != 0
                                    && working[wi].alive
                                    && parent_frn_matches(
                                        &working[wi],
                                        *pfid,
                                        &working,
                                        root_fid,
                                        is_ntfs,
                                    )
                                    && names_match_ignore_case(
                                        node_name_bytes(&working[wi], old_names, &delta_names),
                                        n,
                                    )
                                {
                                    working[wi].alive = false;
                                    deleted_exact = true;
                                }
                            }
                            if !deleted_exact {
                                // Single-link fallback if parent FRN sequence drifted.
                                let alive: SmallVec<[usize; 2]> = indices
                                    .iter()
                                    .copied()
                                    .filter(|&wi| wi != 0 && working[wi].alive)
                                    .collect();
                                if alive.len() == 1
                                    && names_match_ignore_case(
                                        node_name_bytes(
                                            &working[alive[0]],
                                            old_names,
                                            &delta_names,
                                        ),
                                        n,
                                    )
                                {
                                    working[alive[0]].alive = false;
                                }
                            }
                        }
                        _ => {
                            for &wi in indices {
                                if wi != 0 {
                                    working[wi].alive = false;
                                }
                            }
                        }
                    }
                }
                UsnDelta::Upsert {
                    file_id,
                    parent_file_id,
                    old_parent_file_id,
                    old_name,
                    name,
                    logical,
                    allocated,
                    mtime,
                    atime,
                    flags,
                    reparse_tag,
                    preserve_existing_sizes_if_unreadable,
                } => {
                    if *file_id == 0 || is_ntfs_root_frn(*file_id, root_fid, is_ntfs) {
                        continue;
                    }
                    let clean_flags = *flags & !(NodeFlags::HARDLINK | NodeFlags::DUP_LINK);
                    let matched_wi = frn_to_work.get(file_id).and_then(|indices| {
                        // 1. Prefer matching the old `(parent, name)` if this is a rename/move.
                        if let (Some(op), Some(on)) = (old_parent_file_id, old_name)
                            && let Some(&wi) = indices.iter().find(|&&wi| {
                                wi != 0
                                    && working[wi].alive
                                    && parent_frn_matches(
                                        &working[wi],
                                        *op,
                                        &working,
                                        root_fid,
                                        is_ntfs,
                                    )
                                    && names_match_ignore_case(
                                        node_name_bytes(&working[wi], old_names, &delta_names),
                                        on,
                                    )
                            })
                        {
                            return Some(wi);
                        }
                        // 2. Otherwise match exact `(parent_file_id, name)`.
                        if let Some(wi) = indices.iter().copied().find(|&wi| {
                            wi != 0
                                && working[wi].alive
                                && parent_frn_matches(
                                    &working[wi],
                                    *parent_file_id,
                                    &working,
                                    root_fid,
                                    is_ntfs,
                                )
                                && names_match_ignore_case(
                                    node_name_bytes(&working[wi], old_names, &delta_names),
                                    name,
                                )
                        }) {
                            return Some(wi);
                        }
                        // 3. Directories cannot have hard links, so an unmatched upsert for a
                        //    directory FRN that is alive under another `(parent, name)` is a
                        //    rename/move whose RENAME_OLD_NAME was never seen (e.g. it preceded
                        //    the snapshot cursor). Move the node, keeping its subtree, instead of
                        //    adding an empty twin and leaving the old path as a ghost.
                        if clean_flags.contains(NodeFlags::DIR) {
                            let mut alive_dirs = indices.iter().copied().filter(|&wi| {
                                wi != 0
                                    && working[wi].alive
                                    && working[wi].flags.contains(NodeFlags::DIR)
                            });
                            if let (Some(only), None) = (alive_dirs.next(), alive_dirs.next()) {
                                return Some(only);
                            }
                        }
                        None
                    });

                    if let Some(wi) = matched_wi {
                        working[wi].target_parent_frn = Some(*parent_file_id);
                        working[wi].name = NameSource::Delta(delta_names.push_str(name));
                        if !*preserve_existing_sizes_if_unreadable {
                            working[wi].logical = *logical;
                            working[wi].allocated = *allocated;
                            working[wi].mtime = *mtime;
                            working[wi].atime = *atime;
                            working[wi].flags = clean_flags;
                            working[wi].reparse_tag = *reparse_tag;
                        }
                    } else {
                        let new_wi = working.len();
                        let new_key = (new_wi as u64) + 1;
                        let nref = delta_names.push_str(name);
                        working.push(WorkingNode {
                            alive: true,
                            own_key: new_key,
                            parent_key: 0,
                            target_parent_frn: Some(*parent_file_id),
                            file_id: *file_id,
                            name: NameSource::Delta(nref),
                            logical: *logical,
                            allocated: *allocated,
                            mtime: *mtime,
                            atime: *atime,
                            flags: clean_flags,
                            reparse_tag: *reparse_tag,
                        });
                        frn_to_work.entry(*file_id).or_default().push(new_wi);
                    }

                    // Keep shared size/timestamp attributes consistent across all live hard links for `file_id`.
                    if !*preserve_existing_sizes_if_unreadable
                        && let Some(indices) = frn_to_work.get(file_id)
                        && indices.len() > 1
                    {
                        for &wi in indices {
                            if wi != 0 && working[wi].alive {
                                working[wi].logical = *logical;
                                working[wi].allocated = *allocated;
                                working[wi].mtime = *mtime;
                                working[wi].atime = *atime;
                                working[wi].reparse_tag = *reparse_tag;
                            }
                        }
                    }
                }
            }
        }

        // Resolve deferred `target_parent_frn` links so newly created parent dirs resolve even out-of-order.
        for wi in 1..working.len() {
            if !working[wi].alive {
                continue;
            }
            if let Some(pfrn) = working[wi].target_parent_frn {
                if is_ntfs_root_frn(pfrn, root_fid, is_ntfs) {
                    working[wi].parent_key = 1;
                } else if let Some(p_indices) = frn_to_work.get(&pfrn) {
                    let parent_wi = p_indices
                        .iter()
                        .copied()
                        .find(|&p| working[p].alive && working[p].flags.contains(NodeFlags::DIR))
                        .or_else(|| p_indices.iter().copied().find(|&p| working[p].alive));
                    if let Some(p) = parent_wi {
                        working[wi].parent_key = working[p].own_key;
                    } else {
                        working[wi].alive = false;
                    }
                } else {
                    working[wi].alive = false;
                }
            }
        }

        // Rebuild validated SoA tree using IndexBuilder (preserves hard-link dedup,
        // orphan rejection, sibling chains, and bottom-up agg_alloc/agg_count).
        let root_ref = NameRef {
            off: name_off_sl[ROOT as usize],
            len: name_len_sl[ROOT as usize],
        };
        let root_name = String::from_utf8_lossy(old_names.bytes(root_ref)).into_owned();
        let mut builder = IndexBuilder::new(1, &root_name, vol);

        const BATCH_SIZE: usize = 16_384;
        let mut batch_names = NameArena::new();
        let mut batch_entries = Vec::with_capacity(BATCH_SIZE);

        for wn in working.iter().skip(1) {
            if !wn.alive || wn.parent_key == 0 {
                continue;
            }
            let raw_bytes = node_name_bytes(wn, old_names, &delta_names);
            let name_ref = batch_names.push_wtf8(raw_bytes);
            batch_entries.push(RawEntry {
                key: wn.own_key,
                parent_key: wn.parent_key,
                file_id: wn.file_id,
                name: name_ref,
                logical: wn.logical,
                allocated: wn.allocated,
                mtime: min2000_to_filetime(wn.mtime),
                atime: min2000_to_filetime(wn.atime),
                flags: wn.flags,
                reparse_tag: wn.reparse_tag,
            });
            if batch_entries.len() >= BATCH_SIZE {
                builder.push_batch(EntryBatch {
                    names: std::mem::take(&mut batch_names),
                    entries: std::mem::take(&mut batch_entries),
                });
            }
        }

        if !batch_entries.is_empty() {
            builder.push_batch(EntryBatch {
                names: batch_names,
                entries: batch_entries,
            });
        }

        *self = builder.finish();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::VolumeInfo;

    fn test_vol() -> VolumeInfo {
        VolumeInfo {
            root: "C:\\".to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0x1122_3344,
            cluster_size: 4096,
            total_bytes: 1_000_000_000,
            free_bytes: 500_000_000,
            seek_penalty: Some(false),
        }
    }

    fn base_index() -> Index {
        let mut names = NameArena::new();
        let d_logs = names.push_str("Logs");
        let f_app = names.push_str("app.log");
        let f_hl1 = names.push_str("shared_a.bin");
        let f_hl2 = names.push_str("shared_b.bin");

        let mut b = IndexBuilder::new(5, "C:\\", test_vol());
        b.push_batch(EntryBatch {
            names,
            entries: vec![
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    file_id: 10,
                    name: d_logs,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 10,
                    file_id: 11,
                    name: f_app,
                    logical: 5_000,
                    allocated: 8_192,
                    mtime: 20,
                    atime: 20,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
                // Two hard links sharing FRN 20
                RawEntry {
                    key: 12,
                    parent_key: 5,
                    file_id: 20,
                    name: f_hl1,
                    logical: 16_000,
                    allocated: 16_384,
                    mtime: 30,
                    atime: 30,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 13,
                    parent_key: 10,
                    file_id: 20,
                    name: f_hl2,
                    logical: 16_000,
                    allocated: 16_384,
                    mtime: 30,
                    atime: 30,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
            ],
        });
        b.finish()
    }

    #[test]
    fn unpaired_directory_rename_moves_subtree_instead_of_leaving_ghost() {
        let mut ix = base_index();
        let before_total = ix.agg_alloc_slice()[0];
        // NEW_NAME-only upsert (its OLD_NAME was outside the read window).
        let deltas = vec![UsnDelta::Upsert {
            file_id: 10,
            parent_file_id: 5,
            old_parent_file_id: None,
            old_name: None,
            name: "Logs2".to_string(),
            logical: 0,
            allocated: 0,
            mtime: 50,
            atime: 50,
            flags: NodeFlags::DIR,
            reparse_tag: 0,
            preserve_existing_sizes_if_unreadable: false,
        }];
        ix.apply_usn_deltas(&deltas).unwrap();

        assert!(
            ix.find_by_path(std::path::Path::new("C:\\Logs")).is_none(),
            "old directory name must not survive as a ghost"
        );
        assert!(
            ix.find_by_path(std::path::Path::new("C:\\Logs2\\app.log"))
                .is_some(),
            "children move with the renamed directory"
        );
        assert_eq!(ix.agg_alloc_slice()[0], before_total);
    }

    #[test]
    fn usn_deltas_create_grow_rename_and_delete_preserves_totals() {
        let mut ix = base_index();
        assert_eq!(ix.agg_alloc_slice()[0], 24_576);

        let deltas = vec![
            UsnDelta::Upsert {
                file_id: 11,
                parent_file_id: 10,
                old_parent_file_id: None,
                old_name: None,
                name: "app.log".to_string(),
                logical: 24_000,
                allocated: 24_576,
                mtime: 40,
                atime: 40,
                flags: NodeFlags::empty(),
                reparse_tag: 0,
                preserve_existing_sizes_if_unreadable: false,
            },
            UsnDelta::Upsert {
                file_id: 30,
                parent_file_id: 10,
                old_parent_file_id: None,
                old_name: None,
                name: "Archive".to_string(),
                logical: 0,
                allocated: 0,
                mtime: 41,
                atime: 41,
                flags: NodeFlags::DIR,
                reparse_tag: 0,
                preserve_existing_sizes_if_unreadable: false,
            },
            UsnDelta::Upsert {
                file_id: 31,
                parent_file_id: 30,
                old_parent_file_id: None,
                old_name: None,
                name: "old.log".to_string(),
                logical: 4_000,
                allocated: 4_096,
                mtime: 42,
                atime: 42,
                flags: NodeFlags::empty(),
                reparse_tag: 0,
                preserve_existing_sizes_if_unreadable: false,
            },
            UsnDelta::Delete {
                file_id: 20,
                parent_file_id: Some(5),
                name: Some("shared_a.bin".to_string()),
            },
        ];

        ix.apply_usn_deltas(&deltas).unwrap();

        assert_eq!(ix.agg_alloc_slice()[0], 45_056);

        let logs = ix.find_by_path(std::path::Path::new("C:\\Logs")).unwrap();
        assert_eq!(ix.agg_alloc_slice()[logs as usize], 45_056);

        let shared_b = ix
            .find_by_path(std::path::Path::new("C:\\Logs\\shared_b.bin"))
            .unwrap();
        assert!(!ix.flags(shared_b).contains(NodeFlags::DUP_LINK));
        assert!(!ix.flags(shared_b).contains(NodeFlags::HARDLINK));
        assert!(
            ix.find_by_path(std::path::Path::new("C:\\shared_a.bin"))
                .is_none()
        );

        ix.apply_usn_deltas(&[UsnDelta::Upsert {
            file_id: 30,
            parent_file_id: 5,
            old_parent_file_id: Some(10),
            old_name: Some("Archive".to_string()),
            name: "ArchiveMoving".to_string(),
            logical: 0,
            allocated: 0,
            mtime: 50,
            atime: 50,
            flags: NodeFlags::DIR,
            reparse_tag: 0,
            preserve_existing_sizes_if_unreadable: false,
        }])
        .unwrap();

        assert!(
            ix.find_by_path(std::path::Path::new("C:\\ArchiveMoving\\old.log"))
                .is_some()
        );
        assert!(
            ix.find_by_path(std::path::Path::new("C:\\Logs\\Archive\\old.log"))
                .is_none()
        );
        let logs2 = ix.find_by_path(std::path::Path::new("C:\\Logs")).unwrap();
        assert_eq!(ix.agg_alloc_slice()[logs2 as usize], 24_576 + 16_384);
        assert_eq!(ix.agg_alloc_slice()[0], 45_056);
    }

    #[test]
    fn adding_hardlink_does_not_double_count_root() {
        let mut ix = base_index();
        ix.apply_usn_deltas(&[UsnDelta::Upsert {
            file_id: 20,
            parent_file_id: 5,
            old_parent_file_id: None,
            old_name: None,
            name: "shared_c.bin".to_string(),
            logical: 16_000,
            allocated: 16_384,
            mtime: 60,
            atime: 60,
            flags: NodeFlags::empty(),
            reparse_tag: 0,
            preserve_existing_sizes_if_unreadable: false,
        }])
        .unwrap();

        assert_eq!(ix.agg_alloc_slice()[0], 24_576);
        assert!(
            ix.find_by_path(std::path::Path::new("C:\\shared_c.bin"))
                .is_some()
        );
    }

    #[test]
    fn min2000_filetime_roundtrips_cleanly() {
        for m in [0u32, 1, 40, 123_456, 15_000_000] {
            let ft = min2000_to_filetime(m);
            assert_eq!(crate::time::filetime_to_min2000(ft), m);
        }
    }
}
