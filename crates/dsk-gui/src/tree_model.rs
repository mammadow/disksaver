//! Virtualized tree projection, explore filters, and deletion ledger.

#![forbid(unsafe_code)]

use dsk_core::{Index, NONE, NodeFlags, NodeId, ROOT};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::treemap::{SortedChildrenCache, node_effective_bytes};

pub const MAX_FILTERED_ROWS: usize = 10_000;

/// Tracks deleted nodes and subtracts freed byte counts up to ROOT.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct DeletionLedger {
    pub removed: FxHashSet<NodeId>,
    pub subtracted: FxHashMap<NodeId, u64>,
    pub generation: u64,
}

impl DeletionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.removed.is_empty()
    }

    /// Walks up the ancestor chain and returns true if `id` or any ancestor is in `removed`.
    pub fn is_removed_or_ancestor(&self, index: &Index, id: NodeId) -> bool {
        if self.removed.is_empty() || (id as usize) >= index.len() {
            return false;
        }
        let mut curr = id;
        while curr != NONE {
            if self.removed.contains(&curr) {
                return true;
            }
            curr = index.parent(curr);
        }
        false
    }

    /// Returns the effective byte size of a node, or 0 if deleted / ancestor deleted.
    pub fn effective_bytes(&self, index: &Index, id: NodeId) -> u64 {
        if (id as usize) >= index.len() || self.is_removed_or_ancestor(index, id) {
            return 0;
        }
        node_effective_bytes(id, index, &self.subtracted)
    }

    /// Records a deleted node and propagates size delta up to ROOT without double counting.
    pub fn record_deleted_node(&mut self, index: &Index, id: NodeId, freed_bytes: u64) {
        if id == ROOT || (id as usize) >= index.len() || self.is_removed_or_ancestor(index, id) {
            return;
        }
        let delta = freed_bytes.min(self.effective_bytes(index, id));
        self.removed.insert(id);
        self.generation = self.generation.wrapping_add(1);

        let mut curr = index.parent(id);
        while curr != NONE {
            let entry = self.subtracted.entry(curr).or_insert(0);
            *entry = entry.saturating_add(delta);
            curr = index.parent(curr);
        }
    }

    /// Resolves paths against the index and records deletions, skipping non-existent nodes.
    pub fn record_paths(&mut self, index: &Index, items: &[(String, u64)]) {
        for (path_str, freed_bytes) in items {
            if let Some(node_id) = index.find_by_path(std::path::Path::new(path_str)) {
                self.record_deleted_node(index, node_id, *freed_bytes);
            }
        }
    }

    pub fn clear(&mut self) {
        self.removed.clear();
        self.subtracted.clear();
        self.generation = self.generation.wrapping_add(1);
    }
}

/// Filter criteria for exploring index nodes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExploreFilter {
    pub query: String,
    pub ext_filter: Option<String>,
    pub required_flags: NodeFlags,
}

impl ExploreFilter {
    pub fn is_empty(&self) -> bool {
        self.query.trim().is_empty()
            && self.ext_filter.as_ref().is_none_or(|s| s.trim().is_empty())
            && self.required_flags.is_empty()
    }

    /// Evaluates whether a node matches the filter query, extension, and required flags.
    pub fn matches(&self, index: &Index, id: NodeId) -> bool {
        if (id as usize) >= index.len() {
            return false;
        }
        if !self.required_flags.is_empty() && !index.flags(id).contains(self.required_flags) {
            return false;
        }
        if let Some(ref ext) = self.ext_filter {
            let ext_clean = ext.trim().strip_prefix('.').unwrap_or(ext.trim());
            if !ext_clean.is_empty() {
                let name = index.name(id);
                let node_ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
                if !node_ext.eq_ignore_ascii_case(ext_clean) {
                    return false;
                }
            }
        }
        let q = self.query.trim();
        if !q.is_empty() {
            let name = index.name(id);
            if !name.to_lowercase().contains(&q.to_lowercase()) {
                return false;
            }
        }
        true
    }
}

/// Sorting mode for tree view rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TreeSort {
    #[default]
    SizeDesc,
    NameAsc,
    FilesDesc,
    MtimeDesc,
}

/// Projected flattened tree row for virtualized UI rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeRow {
    pub node_id: NodeId,
    pub depth: u16,
    pub is_dir: bool,
    pub has_children: bool,
    pub is_expanded: bool,
    pub name: String,
    pub eff_bytes: u64,
    pub file_count: u32,
    pub mtime_min: u32,
    pub flags: NodeFlags,
}

/// Projector managing expanded nodes, sorting, and flattened visible rows.
#[derive(Clone, Debug, Default)]
pub struct TreeModel {
    pub expanded: FxHashSet<NodeId>,
    pub sort: TreeSort,
    pub rows: Vec<TreeRow>,
    pub truncated: bool,
}

impl TreeModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_expanded(&self, id: NodeId) -> bool {
        self.expanded.contains(&id)
    }

    pub fn set_expanded(&mut self, id: NodeId, expanded: bool) {
        if expanded {
            self.expanded.insert(id);
        } else {
            self.expanded.remove(&id);
        }
    }

    pub fn toggle_expanded(&mut self, id: NodeId) -> bool {
        if self.expanded.contains(&id) {
            self.expanded.remove(&id);
            false
        } else {
            self.expanded.insert(id);
            true
        }
    }

    /// Expands all ancestors up to ROOT so that `id` becomes visible in tree projections.
    pub fn expand_ancestors(&mut self, index: &Index, id: NodeId) {
        if (id as usize) >= index.len() {
            return;
        }
        let mut curr = index.parent(id);
        while curr != NONE {
            self.expanded.insert(curr);
            curr = index.parent(curr);
        }
    }

    /// Rebuilds flattened rows based on current expansion state, sort mode, and active filter.
    pub fn rebuild(
        &mut self,
        index: &Index,
        cache: &mut SortedChildrenCache,
        ledger: &DeletionLedger,
        zoom_root: NodeId,
        filter: &ExploreFilter,
    ) {
        self.rows.clear();
        self.truncated = false;

        if index.is_empty()
            || (zoom_root as usize) >= index.len()
            || ledger.is_removed_or_ancestor(index, zoom_root)
        {
            return;
        }

        if filter.is_empty() {
            self.rebuild_hierarchy(index, cache, ledger, zoom_root);
        } else {
            self.rebuild_filtered(index, ledger, zoom_root, filter);
        }
    }

    fn rebuild_hierarchy(
        &mut self,
        index: &Index,
        cache: &mut SortedChildrenCache,
        ledger: &DeletionLedger,
        zoom_root: NodeId,
    ) {
        let top_children = get_sorted_children(zoom_root, self.sort, index, cache, ledger);
        let mut stack: Vec<(NodeId, u16)> = Vec::with_capacity(top_children.len() * 2);

        // Push in reverse order so the first child is popped first
        for &c in top_children.iter().rev() {
            stack.push((c, 0));
        }

        while let Some((id, depth)) = stack.pop() {
            let is_dir = index.flags(id).contains(NodeFlags::DIR);
            let has_children = if is_dir {
                check_has_children(id, index, ledger)
            } else {
                false
            };
            let is_expanded = has_children && self.expanded.contains(&id);

            self.rows.push(TreeRow {
                node_id: id,
                depth,
                is_dir,
                has_children,
                is_expanded,
                name: index.name(id).to_string(),
                eff_bytes: ledger.effective_bytes(index, id),
                file_count: index.file_count(id),
                mtime_min: index.mtime_min(id),
                flags: index.flags(id),
            });

            if is_expanded {
                let children = get_sorted_children(id, self.sort, index, cache, ledger);
                for &c in children.iter().rev() {
                    stack.push((c, depth.saturating_add(1)));
                }
            }
        }
    }

    fn rebuild_filtered(
        &mut self,
        index: &Index,
        ledger: &DeletionLedger,
        zoom_root: NodeId,
        filter: &ExploreFilter,
    ) {
        let mut matched: Vec<NodeId> = Vec::new();
        let mut stack: Vec<NodeId> = Vec::new();

        for c in index.children(zoom_root) {
            if !ledger.removed.contains(&c) {
                stack.push(c);
            }
        }

        while let Some(id) = stack.pop() {
            if index.flags(id).contains(NodeFlags::DIR) {
                for c in index.children(id) {
                    if !ledger.removed.contains(&c) {
                        stack.push(c);
                    }
                }
            }

            if filter.matches(index, id) {
                matched.push(id);
                if matched.len() >= MAX_FILTERED_ROWS {
                    self.truncated = true;
                    break;
                }
            }
        }

        match self.sort {
            TreeSort::SizeDesc => {
                matched.sort_by(|&a, &b| {
                    let size_a = ledger.effective_bytes(index, a);
                    let size_b = ledger.effective_bytes(index, b);
                    size_b.cmp(&size_a).then_with(|| a.cmp(&b))
                });
            }
            TreeSort::NameAsc => {
                matched.sort_by(|&a, &b| {
                    index
                        .name(a)
                        .to_lowercase()
                        .cmp(&index.name(b).to_lowercase())
                        .then_with(|| a.cmp(&b))
                });
            }
            TreeSort::FilesDesc => {
                matched.sort_by(|&a, &b| {
                    index
                        .file_count(b)
                        .cmp(&index.file_count(a))
                        .then_with(|| a.cmp(&b))
                });
            }
            TreeSort::MtimeDesc => {
                matched.sort_by(|&a, &b| {
                    index
                        .mtime_min(b)
                        .cmp(&index.mtime_min(a))
                        .then_with(|| a.cmp(&b))
                });
            }
        }

        self.rows.reserve(matched.len());
        for id in matched {
            let is_dir = index.flags(id).contains(NodeFlags::DIR);
            let has_children = if is_dir {
                check_has_children(id, index, ledger)
            } else {
                false
            };

            self.rows.push(TreeRow {
                node_id: id,
                depth: 0,
                is_dir,
                has_children,
                is_expanded: false,
                name: index.name(id).to_string(),
                eff_bytes: ledger.effective_bytes(index, id),
                file_count: index.file_count(id),
                mtime_min: index.mtime_min(id),
                flags: index.flags(id),
            });
        }
    }
}

#[inline]
fn check_has_children(id: NodeId, index: &Index, ledger: &DeletionLedger) -> bool {
    if !index.flags(id).contains(NodeFlags::DIR) {
        return false;
    }
    index.children(id).any(|c| !ledger.removed.contains(&c))
}

fn get_sorted_children(
    parent: NodeId,
    sort: TreeSort,
    index: &Index,
    cache: &mut SortedChildrenCache,
    ledger: &DeletionLedger,
) -> Vec<NodeId> {
    match sort {
        TreeSort::SizeDesc => {
            let cached = cache.get_or_insert_sorted(parent, index, &ledger.subtracted);
            cached
                .iter()
                .copied()
                .filter(|&c| !ledger.removed.contains(&c))
                .collect()
        }
        TreeSort::NameAsc => {
            let mut children: Vec<NodeId> = index
                .children(parent)
                .filter(|&c| !ledger.removed.contains(&c))
                .collect();
            children.sort_by(|&a, &b| {
                index
                    .name(a)
                    .to_lowercase()
                    .cmp(&index.name(b).to_lowercase())
                    .then_with(|| a.cmp(&b))
            });
            children
        }
        TreeSort::FilesDesc => {
            let mut children: Vec<NodeId> = index
                .children(parent)
                .filter(|&c| !ledger.removed.contains(&c))
                .collect();
            children.sort_by(|&a, &b| {
                index
                    .file_count(b)
                    .cmp(&index.file_count(a))
                    .then_with(|| a.cmp(&b))
            });
            children
        }
        TreeSort::MtimeDesc => {
            let mut children: Vec<NodeId> = index
                .children(parent)
                .filter(|&c| !ledger.removed.contains(&c))
                .collect();
            children.sort_by(|&a, &b| {
                index
                    .mtime_min(b)
                    .cmp(&index.mtime_min(a))
                    .then_with(|| a.cmp(&b))
            });
            children
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsk_core::ROOT;
    use dsk_core::index::builder::{EntryBatch, IndexBuilder, RawEntry};
    use dsk_core::index::names::NameArena;
    use dsk_core::volume::VolumeInfo;

    fn make_test_entry(
        names: &mut NameArena,
        key: u64,
        parent_key: u64,
        name: &str,
        dir: bool,
        alloc: u64,
        mtime: u64,
    ) -> RawEntry {
        let name_ref = names.push_str(name);
        let flags = if dir {
            NodeFlags::DIR
        } else {
            NodeFlags::empty()
        };
        RawEntry {
            key,
            parent_key,
            name: name_ref,
            flags,
            logical: alloc,
            allocated: alloc,
            mtime,
            atime: 0,
            file_id: 0,
            reparse_tag: 0,
        }
    }

    #[test]
    fn deletion_ledger_subtracts_bytes_up_to_root_without_double_counting() {
        // Hierarchy:
        // root (key 5)
        //   - dirA (key 10, 0B): fileA1 (key 11, 100B), fileA2 (key 12, 50B)
        //   - dirB (key 20, 0B): fileB1 (key 21, 200B)
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "dirA", true, 0, 100),
            make_test_entry(&mut names, 11, 10, "fileA1", false, 100, 101),
            make_test_entry(&mut names, 12, 10, "fileA2", false, 50, 102),
            make_test_entry(&mut names, 20, 5, "dirB", true, 0, 200),
            make_test_entry(&mut names, 21, 20, "fileB1", false, 200, 201),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let dir_a = index
            .find_by_path(std::path::Path::new(r"C:\dirA"))
            .unwrap();
        let file_a1 = index
            .find_by_path(std::path::Path::new(r"C:\dirA\fileA1"))
            .unwrap();
        let file_a2 = index
            .find_by_path(std::path::Path::new(r"C:\dirA\fileA2"))
            .unwrap();
        let dir_b = index
            .find_by_path(std::path::Path::new(r"C:\dirB"))
            .unwrap();
        let file_b1 = index
            .find_by_path(std::path::Path::new(r"C:\dirB\fileB1"))
            .unwrap();

        let mut ledger = DeletionLedger::new();
        assert_eq!(ledger.effective_bytes(&index, ROOT), 350);
        assert_eq!(ledger.effective_bytes(&index, dir_a), 150);
        assert_eq!(ledger.effective_bytes(&index, file_a1), 100);

        // Delete fileA1 (100B)
        ledger.record_deleted_node(&index, file_a1, 100);
        assert_eq!(ledger.effective_bytes(&index, file_a1), 0);
        assert_eq!(ledger.effective_bytes(&index, dir_a), 50);
        assert_eq!(ledger.effective_bytes(&index, ROOT), 250);
        assert!(ledger.is_removed_or_ancestor(&index, file_a1));

        // Call again on fileA1 -> must NOT double count!
        ledger.record_deleted_node(&index, file_a1, 100);
        assert_eq!(ledger.effective_bytes(&index, dir_a), 50);
        assert_eq!(ledger.effective_bytes(&index, ROOT), 250);

        // Record by path for fileB1 (200B)
        ledger.record_paths(&index, &[(r"C:\dirB\fileB1".to_string(), 200)]);
        assert_eq!(ledger.effective_bytes(&index, file_b1), 0);
        assert_eq!(ledger.effective_bytes(&index, dir_b), 0);
        assert_eq!(ledger.effective_bytes(&index, ROOT), 50);

        // Delete parent dirA (50B remaining)
        ledger.record_deleted_node(&index, dir_a, 50);
        assert_eq!(ledger.effective_bytes(&index, ROOT), 0);
        assert!(ledger.is_removed_or_ancestor(&index, file_a2));
        assert_eq!(ledger.effective_bytes(&index, file_a2), 0);
    }

    #[test]
    fn tree_model_expand_collapse_and_sort_order() {
        // Hierarchy:
        // root (key 5)
        //   - folder_z (key 10, 200B): child_b (key 11, 50B), child_a (key 12, 150B)
        //   - folder_a (key 20, 100B): sub_child (key 21, 100B)
        //   - file_top (key 30, 500B)
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "folder_z", true, 0, 100),
            make_test_entry(&mut names, 11, 10, "child_b.dat", false, 50, 101),
            make_test_entry(&mut names, 12, 10, "child_a.dat", false, 150, 102),
            make_test_entry(&mut names, 20, 5, "folder_a", true, 0, 200),
            make_test_entry(&mut names, 21, 20, "sub_child.txt", false, 100, 201),
            make_test_entry(&mut names, 30, 5, "file_top.bin", false, 500, 300),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let folder_z = index
            .find_by_path(std::path::Path::new(r"C:\folder_z"))
            .unwrap();
        let folder_a = index
            .find_by_path(std::path::Path::new(r"C:\folder_a"))
            .unwrap();
        let sub_child = index
            .find_by_path(std::path::Path::new(r"C:\folder_a\sub_child.txt"))
            .unwrap();

        let mut model = TreeModel::new();
        let mut cache = SortedChildrenCache::new();
        let ledger = DeletionLedger::new();
        let filter = ExploreFilter::default();

        // Initial rebuild with SizeDesc: 3 top-level items
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter);
        assert_eq!(model.rows.len(), 3);
        assert_eq!(model.rows[0].name, "file_top.bin");
        assert_eq!(model.rows[0].depth, 0);
        assert_eq!(model.rows[0].eff_bytes, 500);
        assert!(!model.rows[0].has_children);

        assert_eq!(model.rows[1].name, "folder_z");
        assert_eq!(model.rows[1].depth, 0);
        assert_eq!(model.rows[1].eff_bytes, 200);
        assert!(model.rows[1].has_children);
        assert!(!model.rows[1].is_expanded);

        assert_eq!(model.rows[2].name, "folder_a");
        assert_eq!(model.rows[2].depth, 0);
        assert_eq!(model.rows[2].eff_bytes, 100);

        // Expand folder_z
        assert!(model.toggle_expanded(folder_z));
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter);
        assert_eq!(model.rows.len(), 5);
        assert_eq!(model.rows[1].name, "folder_z");
        assert!(model.rows[1].is_expanded);
        assert_eq!(model.rows[2].name, "child_a.dat");
        assert_eq!(model.rows[2].depth, 1);
        assert_eq!(model.rows[2].eff_bytes, 150);
        assert_eq!(model.rows[3].name, "child_b.dat");
        assert_eq!(model.rows[3].depth, 1);
        assert_eq!(model.rows[3].eff_bytes, 50);
        assert_eq!(model.rows[4].name, "folder_a");
        assert_eq!(model.rows[4].depth, 0);

        // Test expand_ancestors
        let mut model2 = TreeModel::new();
        model2.expand_ancestors(&index, sub_child);
        assert!(model2.is_expanded(folder_a));

        // Test NameAsc sort
        model.sort = TreeSort::NameAsc;
        model.expanded.clear();
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter);
        assert_eq!(model.rows.len(), 3);
        assert_eq!(model.rows[0].name, "file_top.bin");
        assert_eq!(model.rows[1].name, "folder_a");
        assert_eq!(model.rows[2].name, "folder_z");
    }

    #[test]
    fn tree_model_filters_by_query_extension_and_node_flags() {
        // Hierarchy:
        // root (key 5)
        //   - app.log (key 10, 10B)
        //   - backup.LOG (key 20, 20B)
        //   - config.json (key 30, 1B)
        //   - docs (key 40, dir)
        //     - readme.md (key 41, 2B)
        //     - changelog.txt (key 42, 3B)
        //     - sub_dir (key 43, dir)
        //       - nested.log (key 44, 5B)
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "app.log", false, 10, 10),
            make_test_entry(&mut names, 20, 5, "backup.LOG", false, 20, 20),
            make_test_entry(&mut names, 30, 5, "config.json", false, 1, 30),
            make_test_entry(&mut names, 40, 5, "docs", true, 0, 40),
            make_test_entry(&mut names, 41, 40, "readme.md", false, 2, 41),
            make_test_entry(&mut names, 42, 40, "changelog.txt", false, 3, 42),
            make_test_entry(&mut names, 43, 40, "sub_dir", true, 0, 43),
            make_test_entry(&mut names, 44, 43, "nested.log", false, 5, 44),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let mut model = TreeModel::new();
        let mut cache = SortedChildrenCache::new();
        let ledger = DeletionLedger::new();

        // Query filter: "log" (case-insensitive substring)
        let filter = ExploreFilter {
            query: "log".to_string(),
            ext_filter: None,
            required_flags: NodeFlags::empty(),
        };
        assert!(!filter.is_empty());
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter);
        assert_eq!(model.rows.len(), 4);
        // By default SizeDesc: backup.LOG(20), app.log(10), nested.log(5), changelog.txt(3)
        assert_eq!(model.rows[0].name, "backup.LOG");
        assert_eq!(model.rows[1].name, "app.log");
        assert_eq!(model.rows[2].name, "nested.log");
        assert_eq!(model.rows[3].name, "changelog.txt");

        // Extension filter: ".log" (case-insensitive, normalizing leading dot)
        let filter_ext = ExploreFilter {
            query: String::new(),
            ext_filter: Some(".log".to_string()),
            required_flags: NodeFlags::empty(),
        };
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter_ext);
        assert_eq!(model.rows.len(), 3);
        assert_eq!(model.rows[0].name, "backup.LOG");
        assert_eq!(model.rows[1].name, "app.log");
        assert_eq!(model.rows[2].name, "nested.log");

        // Flag filter: NodeFlags::DIR
        let filter_dir = ExploreFilter {
            query: String::new(),
            ext_filter: None,
            required_flags: NodeFlags::DIR,
        };
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter_dir);
        assert_eq!(model.rows.len(), 2);
        let names: Vec<String> = model.rows.iter().map(|r| r.name.clone()).collect();
        assert!(names.contains(&"docs".to_string()));
        assert!(names.contains(&"sub_dir".to_string()));
    }

    #[test]
    fn tree_model_filters_caps_at_max_filtered_rows() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let total_files = 11_000;
        let mut entries = Vec::with_capacity(total_files + 1);
        entries.push(make_test_entry(&mut names, 10, 5, "big_dir", true, 0, 0));
        for i in 1..=total_files {
            entries.push(make_test_entry(
                &mut names,
                100 + i as u64,
                10,
                &format!("item_{i}.txt"),
                false,
                10,
                10,
            ));
        }
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let mut model = TreeModel::new();
        let mut cache = SortedChildrenCache::new();
        let ledger = DeletionLedger::new();
        let filter = ExploreFilter {
            query: "item_".to_string(),
            ext_filter: None,
            required_flags: NodeFlags::empty(),
        };

        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter);
        assert!(model.truncated);
        assert_eq!(model.rows.len(), MAX_FILTERED_ROWS);
    }

    #[test]
    fn tree_model_sort_modes_files_and_mtime() {
        let ft1 = dsk_core::time::FILETIME_EPOCH_2000 + 600_000_000 * 10; // 10 mins
        let ft2 = dsk_core::time::FILETIME_EPOCH_2000 + 600_000_000 * 50; // 50 mins

        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "dir_many", true, 0, ft1),
            make_test_entry(&mut names, 11, 10, "f1.bin", false, 10, ft1),
            make_test_entry(&mut names, 12, 10, "f2.bin", false, 10, ft1),
            make_test_entry(&mut names, 13, 10, "f3.bin", false, 10, ft1),
            make_test_entry(&mut names, 20, 5, "dir_few", true, 0, ft2),
            make_test_entry(&mut names, 21, 20, "f4.bin", false, 10, ft2),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let mut model = TreeModel::new();
        let mut cache = SortedChildrenCache::new();
        let ledger = DeletionLedger::new();
        let filter = ExploreFilter::default();

        // Sort by FilesDesc
        model.sort = TreeSort::FilesDesc;
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter);
        assert_eq!(model.rows.len(), 2);
        assert_eq!(model.rows[0].name, "dir_many");
        assert_eq!(model.rows[1].name, "dir_few");

        // Sort by MtimeDesc
        model.sort = TreeSort::MtimeDesc;
        model.rebuild(&index, &mut cache, &ledger, ROOT, &filter);
        assert_eq!(model.rows.len(), 2);
        assert_eq!(model.rows[0].name, "dir_few");
        assert_eq!(model.rows[1].name, "dir_many");
    }

    #[test]
    fn deletion_ledger_bounds_and_empty() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![make_test_entry(
            &mut names, 10, 5, "file.bin", false, 50, 100,
        )];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let mut ledger = DeletionLedger::new();
        assert!(ledger.is_empty());

        // ROOT node cannot be recorded deleted
        ledger.record_deleted_node(&index, ROOT, 50);
        assert!(ledger.is_empty());
        assert_eq!(ledger.effective_bytes(&index, ROOT), 50);

        // Out of bounds node
        assert_eq!(ledger.effective_bytes(&index, 9999), 0);
        assert!(!ledger.is_removed_or_ancestor(&index, 9999));
        ledger.record_deleted_node(&index, 9999, 100);
        assert!(ledger.is_empty());

        // Clear ledger
        let file_id = index
            .find_by_path(std::path::Path::new(r"C:\file.bin"))
            .unwrap();
        ledger.record_deleted_node(&index, file_id, 50);
        assert!(!ledger.is_empty());
        assert_eq!(ledger.effective_bytes(&index, file_id), 0);
        ledger.clear();
        assert!(ledger.is_empty());
        assert_eq!(ledger.effective_bytes(&index, file_id), 50);
    }
}
