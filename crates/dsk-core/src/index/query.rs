#![forbid(unsafe_code)]

use std::path::Path;

use rustc_hash::FxHashMap;

use crate::index::{Index, NodeFlags, NodeId, ROOT};

pub fn top_dirs(ix: &Index, n: usize, max_depth: u16) -> Vec<NodeId> {
    if n == 0 || max_depth == 0 || ix.len() <= 1 {
        return Vec::new();
    }
    let mut dirs = Vec::new();
    let mut stack = Vec::new();
    for c in ix.children(ROOT) {
        if ix.flags(c).contains(NodeFlags::DIR) {
            stack.push((c, 1u16));
        }
    }
    while let Some((u, d)) = stack.pop() {
        dirs.push(u);
        if d < max_depth {
            for c in ix.children(u) {
                if ix.flags(c).contains(NodeFlags::DIR) {
                    stack.push((c, d + 1));
                }
            }
        }
    }
    dirs.sort_unstable_by(|&a, &b| {
        ix.total_allocated(b)
            .cmp(&ix.total_allocated(a))
            .then_with(|| a.cmp(&b))
    });
    if dirs.len() > n {
        dirs.truncate(n);
    }
    dirs
}

pub fn top_files(ix: &Index, n: usize) -> Vec<NodeId> {
    if n == 0 || ix.is_empty() {
        return Vec::new();
    }
    let mut files = Vec::new();
    let skip_mask = NodeFlags::DIR | NodeFlags::DUP_LINK | NodeFlags::METAFILE;
    for id in 0..ix.len() as NodeId {
        let f = ix.flags(id);
        if !f.intersects(skip_mask) {
            files.push(id);
        }
    }
    files.sort_unstable_by(|&a, &b| {
        ix.allocated(b)
            .cmp(&ix.allocated(a))
            .then_with(|| a.cmp(&b))
    });
    if files.len() > n {
        files.truncate(n);
    }
    files
}

pub fn ext_breakdown_subtree(ix: &Index, root: NodeId, n: usize) -> Vec<(String, u64, u32)> {
    if n == 0 || ix.is_empty() || (root as usize) >= ix.len() {
        return Vec::new();
    }

    let mut map: FxHashMap<String, (u64, u32)> = FxHashMap::default();
    let mut stack = vec![root];

    while let Some(curr) = stack.pop() {
        let f = ix.flags(curr);
        if f.contains(NodeFlags::DIR) {
            for c in ix.children(curr) {
                stack.push(c);
            }
        } else {
            let name = ix.name(curr);
            let ext = Path::new(name.as_ref())
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .unwrap_or_default();

            let alloc = ix.total_allocated(curr);
            let entry = map.entry(ext).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(alloc);
            entry.1 = entry.1.saturating_add(1);
        }
    }

    let mut list: Vec<(String, u64, u32)> = map
        .into_iter()
        .map(|(ext, (bytes, count))| (ext, bytes, count))
        .collect();

    list.sort_unstable_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });

    if list.len() > n {
        list.truncate(n);
    }
    list
}

pub fn ext_breakdown(ix: &Index, n: usize) -> Vec<(String, u64, u32)> {
    ext_breakdown_subtree(ix, ROOT, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::builder::{EntryBatch, IndexBuilder, RawEntry};
    use crate::index::names::NameArena;
    use crate::volume::VolumeInfo;

    fn batch(entries: &[(u64, u64, &str, bool, u64, u64)]) -> EntryBatch {
        let mut names = NameArena::new();
        let mut raw_entries = Vec::new();
        for &(key, parent, name, dir, alloc, file_id) in entries {
            let name_ref = names.push_str(name);
            let flags = if dir {
                NodeFlags::DIR
            } else {
                NodeFlags::empty()
            };
            raw_entries.push(RawEntry {
                key,
                parent_key: parent,
                name: name_ref,
                flags,
                logical: alloc,
                allocated: alloc,
                mtime: 0,
                atime: 0,
                file_id,
                reparse_tag: 0,
            });
        }
        EntryBatch {
            names,
            entries: raw_entries,
        }
    }

    #[test]
    fn top_dirs_sorted_excluding_root() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[
            (10, 5, "small", true, 0, 0),
            (11, 10, "s_file", false, 1000, 0),
            (20, 5, "big", true, 0, 0),
            (21, 20, "b_file", false, 5000, 0),
        ]);
        b.push_batch(batch_data);
        let ix = b.finish();

        let small = ix.children(ROOT).find(|&c| ix.name(c) == "small").unwrap();
        let big = ix.children(ROOT).find(|&c| ix.name(c) == "big").unwrap();

        assert_eq!(top_dirs(&ix, 2, 8), vec![big, small]);
    }

    #[test]
    fn top_files_skip_dup_links_and_metafiles() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let n1 = names.push_str("f_normal");
        let n2 = names.push_str("f_dup");
        let n3 = names.push_str("f_meta");
        let batch_data = EntryBatch {
            names,
            entries: vec![
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    name: n1,
                    flags: NodeFlags::empty(),
                    logical: 4096,
                    allocated: 4096,
                    mtime: 0,
                    atime: 0,
                    file_id: 1,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 5,
                    name: n2,
                    flags: NodeFlags::empty(),
                    logical: 4096,
                    allocated: 4096,
                    mtime: 0,
                    atime: 0,
                    file_id: 1,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 12,
                    parent_key: 5,
                    name: n3,
                    flags: NodeFlags::METAFILE,
                    logical: 10000,
                    allocated: 10000,
                    mtime: 0,
                    atime: 0,
                    file_id: 0,
                    reparse_tag: 0,
                },
            ],
        };
        b.push_batch(batch_data);
        let ix = b.finish();

        assert!(!top_files(&ix, 10).iter().any(|&n| {
            ix.flags(n)
                .intersects(NodeFlags::DUP_LINK | NodeFlags::METAFILE)
        }));
    }

    #[test]
    fn ext_breakdown_case_insensitive() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[
            (10, 5, "a.MP4", false, 4096, 0),
            (11, 5, "b.mp4", false, 4096, 0),
            (12, 5, "c.Mp4", false, 4096, 0),
            (13, 5, "README", false, 1024, 0),
        ]);
        b.push_batch(batch_data);
        let ix = b.finish();

        assert_eq!(ext_breakdown(&ix, 5)[0], ("mp4".into(), 3 * 4096, 3)); /* "a.MP4","b.mp4","c.Mp4"; "README" counts under "" */
    }

    #[test]
    fn ext_breakdown_subtree_scopes_strictly_to_zoomed_directory() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[
            (10, 5, "dir_a", true, 0, 0),
            (11, 10, "vid1.mp4", false, 4000, 0),
            (12, 10, "sub_a", true, 0, 0),
            (13, 12, "vid2.MP4", false, 6000, 0),
            (14, 12, "doc.pdf", false, 2000, 0),
            (20, 5, "dir_b", true, 0, 0),
            (21, 20, "other.mp4", false, 10000, 0),
            (22, 20, "image.png", false, 5000, 0),
            (30, 5, "root_file.txt", false, 1000, 0),
        ]);
        b.push_batch(batch_data);
        let ix = b.finish();

        let dir_a = ix.children(ROOT).find(|&c| ix.name(c) == "dir_a").unwrap();
        let dir_b = ix.children(ROOT).find(|&c| ix.name(c) == "dir_b").unwrap();
        let sub_a = ix.children(dir_a).find(|&c| ix.name(c) == "sub_a").unwrap();

        // Subtree breakdown of dir_a includes vid1.mp4, vid2.MP4, doc.pdf (not dir_b, not root_file.txt)
        let res_a = ext_breakdown_subtree(&ix, dir_a, 10);
        assert_eq!(res_a.len(), 2);
        assert_eq!(res_a[0], ("mp4".to_string(), 10000, 2));
        assert_eq!(res_a[1], ("pdf".to_string(), 2000, 1));

        // Subtree breakdown of sub_a strictly includes vid2.MP4 and doc.pdf
        let res_sub_a = ext_breakdown_subtree(&ix, sub_a, 10);
        assert_eq!(res_sub_a.len(), 2);
        assert_eq!(res_sub_a[0], ("mp4".to_string(), 6000, 1));
        assert_eq!(res_sub_a[1], ("pdf".to_string(), 2000, 1));

        // Subtree breakdown of dir_b strictly includes other.mp4 and image.png
        let res_b = ext_breakdown_subtree(&ix, dir_b, 10);
        assert_eq!(res_b.len(), 2);
        assert_eq!(res_b[0], ("mp4".to_string(), 10000, 1));
        assert_eq!(res_b[1], ("png".to_string(), 5000, 1));

        // Edge cases: n == 0 or out-of-bounds root
        assert!(ext_breakdown_subtree(&ix, dir_a, 0).is_empty());
        assert!(ext_breakdown_subtree(&ix, 9999, 10).is_empty());
    }
}
