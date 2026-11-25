#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use bitflags::bitflags;
use rustc_hash::FxHashMap;

use crate::index::names::{NameArena, NameRef, wtf8_to_os_string, wtf8_to_string_lossy};
use crate::time::filetime_to_min2000;
use crate::volume::VolumeInfo;

pub type NodeId = u32;
pub const ROOT: NodeId = 0;
pub const NONE: NodeId = u32::MAX;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub struct NodeFlags: u16 {
        const DIR = 1 << 0;
        const HARDLINK = 1 << 1;
        const REPARSE = 1 << 2;
        const CLOUD = 1 << 3;
        const COMPRESSED = 1 << 4;
        const SPARSE = 1 << 5;
        const ADS = 1 << 6;
        const SYSTEM = 1 << 7;
        const HIDDEN = 1 << 8;
        const WOF = 1 << 9;
        const OFFLINE = 1 << 10;
        const ORPHANS = 1 << 11;
        const METAFILE = 1 << 12;
        const DUP_LINK = 1 << 13;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawEntry {
    pub key: u64,
    pub parent_key: u64,
    pub name: NameRef,
    pub flags: NodeFlags,
    pub logical: u64,
    pub allocated: u64,
    pub mtime: u64,
    pub atime: u64,
    pub file_id: u64,
    pub reparse_tag: u32,
}

#[derive(Default, Debug)]
pub struct EntryBatch {
    pub names: NameArena,
    pub entries: Vec<RawEntry>,
}

pub struct ChildIter<'a> {
    index: &'a Index,
    curr: NodeId,
}

impl<'a> Iterator for ChildIter<'a> {
    type Item = NodeId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr == NONE || (self.curr as usize) >= self.index.len() {
            None
        } else {
            let item = self.curr;
            self.curr = self.index.next_sibling[item as usize];
            Some(item)
        }
    }
}

fn split_path_segments(p: &Path) -> Vec<String> {
    let raw = p.to_string_lossy();
    if raw.is_empty() {
        return Vec::new();
    }
    let s = raw.replace('/', "\\");
    let trimmed = if s.len() >= 8
        && (s[..8].eq_ignore_ascii_case(r"\\?\UNC\") || s[..8].eq_ignore_ascii_case(r"\??\UNC\"))
    {
        &s[8..]
    } else if s.len() >= 4
        && (s[..4].eq_ignore_ascii_case(r"\\?\") || s[..4].eq_ignore_ascii_case(r"\??\"))
    {
        &s[4..]
    } else {
        &s[..]
    };
    trimmed
        .split('\\')
        .filter(|seg| !seg.is_empty())
        .map(|seg| seg.to_string())
        .collect()
}

#[derive(Debug)]
pub struct Index {
    volume: VolumeInfo,
    names: NameArena,
    parent: Vec<NodeId>,
    first_child: Vec<NodeId>,
    next_sibling: Vec<NodeId>,
    name_off: Vec<u32>,
    name_len: Vec<u16>,
    flags: Vec<NodeFlags>,
    logical: Vec<u64>,
    allocated: Vec<u64>,
    mtime: Vec<u32>,
    atime: Vec<u32>,
    file_id: Vec<u64>,
    agg_alloc: Vec<u64>,
    agg_count: Vec<u32>,
    reparse_tags: FxHashMap<NodeId, u32>,
}

impl Index {
    #[inline]
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.parent.is_empty()
    }

    #[inline]
    pub fn volume(&self) -> &VolumeInfo {
        &self.volume
    }

    #[inline]
    pub fn parent(&self, id: NodeId) -> NodeId {
        if (id as usize) < self.len() {
            self.parent[id as usize]
        } else {
            NONE
        }
    }

    pub fn children(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        let curr = if (id as usize) < self.len() {
            self.first_child[id as usize]
        } else {
            NONE
        };
        ChildIter { index: self, curr }
    }

    #[inline]
    pub fn name_bytes(&self, id: NodeId) -> &[u8] {
        if (id as usize) < self.len() {
            self.names.bytes(NameRef {
                off: self.name_off[id as usize],
                len: self.name_len[id as usize],
            })
        } else {
            &[]
        }
    }

    #[inline]
    pub fn name(&self, id: NodeId) -> Cow<'_, str> {
        wtf8_to_string_lossy(self.name_bytes(id))
    }

    #[inline]
    pub fn name_os(&self, id: NodeId) -> OsString {
        wtf8_to_os_string(self.name_bytes(id))
    }

    pub fn path(&self, id: NodeId) -> PathBuf {
        if (id as usize) >= self.len() {
            return PathBuf::new();
        }
        let mut chain = Vec::new();
        let mut curr = id;
        while curr != NONE {
            chain.push(curr);
            if curr == ROOT {
                break;
            }
            curr = self.parent[curr as usize];
        }
        chain.reverse();
        let mut p = PathBuf::new();
        for node in chain {
            p.push(self.name_os(node));
        }
        p
    }

    /// Looks up a node by its Windows filesystem path.
    ///
    /// Normalizes path separators, strips verbatim device prefixes (`\\?\`, `\??\`, `\\?\UNC\`),
    /// matches root segments case-insensitively, and traverses descendants top-down, prioritizing
    /// exact name matches with case-insensitive fallback. Returns `None` if the path falls outside
    /// the indexed root or cannot be found.
    pub fn find_by_path(&self, target: &Path) -> Option<NodeId> {
        if self.is_empty() {
            return None;
        }

        let root_path = self.path(ROOT);
        let root_segs = split_path_segments(&root_path);
        let target_segs = split_path_segments(target);

        if target_segs.len() < root_segs.len() {
            return None;
        }

        for i in 0..root_segs.len() {
            if !target_segs[i].eq_ignore_ascii_case(&root_segs[i]) {
                return None;
            }
        }

        if target_segs.len() == root_segs.len() {
            return Some(ROOT);
        }

        let remaining_segs = &target_segs[root_segs.len()..];
        let mut curr = ROOT;

        for seg in remaining_segs {
            let mut found = None;
            let mut fallback = None;
            let seg_lower = seg.to_lowercase();

            for c in self.children(curr) {
                let name = self.name(c);
                if name.as_ref() == seg {
                    found = Some(c);
                    break;
                }
                if fallback.is_none() && name.to_lowercase() == seg_lower {
                    fallback = Some(c);
                }
            }

            curr = found.or(fallback)?;
        }

        Some(curr)
    }

    pub fn depth(&self, id: NodeId) -> u16 {
        if id == ROOT || (id as usize) >= self.len() {
            return 0;
        }
        let mut d = 0u16;
        let mut curr = id;
        while curr != ROOT && curr != NONE {
            d = d.saturating_add(1);
            curr = self.parent[curr as usize];
        }
        d
    }

    #[inline]
    pub fn flags(&self, id: NodeId) -> NodeFlags {
        if (id as usize) < self.len() {
            self.flags[id as usize]
        } else {
            NodeFlags::empty()
        }
    }

    #[inline]
    pub fn logical(&self, id: NodeId) -> u64 {
        if (id as usize) < self.len() {
            self.logical[id as usize]
        } else {
            0
        }
    }

    #[inline]
    pub fn allocated(&self, id: NodeId) -> u64 {
        if (id as usize) < self.len() {
            self.allocated[id as usize]
        } else {
            0
        }
    }

    #[inline]
    pub fn total_allocated(&self, id: NodeId) -> u64 {
        if (id as usize) < self.len() {
            self.agg_alloc[id as usize]
        } else {
            0
        }
    }

    #[inline]
    pub fn file_count(&self, id: NodeId) -> u32 {
        if (id as usize) < self.len() {
            self.agg_count[id as usize]
        } else {
            0
        }
    }

    #[inline]
    pub fn mtime_min(&self, id: NodeId) -> u32 {
        if (id as usize) < self.len() {
            self.mtime[id as usize]
        } else {
            0
        }
    }

    #[inline]
    pub fn atime_min(&self, id: NodeId) -> u32 {
        if (id as usize) < self.len() {
            self.atime[id as usize]
        } else {
            0
        }
    }

    #[inline]
    pub fn file_id(&self, id: NodeId) -> u64 {
        if (id as usize) < self.len() {
            self.file_id[id as usize]
        } else {
            0
        }
    }

    #[inline]
    pub fn reparse_tag(&self, id: NodeId) -> Option<u32> {
        self.reparse_tags.get(&id).copied()
    }

    pub fn names(&self) -> &NameArena {
        &self.names
    }

    pub fn parent_slice(&self) -> &[NodeId] {
        &self.parent
    }

    pub fn first_child_slice(&self) -> &[NodeId] {
        &self.first_child
    }

    pub fn next_sibling_slice(&self) -> &[NodeId] {
        &self.next_sibling
    }

    pub fn name_off_slice(&self) -> &[u32] {
        &self.name_off
    }

    pub fn name_len_slice(&self) -> &[u16] {
        &self.name_len
    }

    pub fn flags_slice(&self) -> &[NodeFlags] {
        &self.flags
    }

    pub fn logical_slice(&self) -> &[u64] {
        &self.logical
    }

    pub fn allocated_slice(&self) -> &[u64] {
        &self.allocated
    }

    pub fn mtime_slice(&self) -> &[u32] {
        &self.mtime
    }

    pub fn atime_slice(&self) -> &[u32] {
        &self.atime
    }

    pub fn file_id_slice(&self) -> &[u64] {
        &self.file_id
    }

    pub fn agg_alloc_slice(&self) -> &[u64] {
        &self.agg_alloc
    }

    pub fn agg_count_slice(&self) -> &[u32] {
        &self.agg_count
    }

    pub fn reparse_tags_map(&self) -> &FxHashMap<NodeId, u32> {
        &self.reparse_tags
    }

    /// Constructs an [`Index`] from pre-validated raw Structure-of-Arrays parts.
    ///
    /// Validates node count, slice length equality, parent/child/sibling index bounds,
    /// and name arena offsets before returning an initialized `Index`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_checked(
        volume: VolumeInfo,
        names: NameArena,
        parent: Vec<NodeId>,
        first_child: Vec<NodeId>,
        next_sibling: Vec<NodeId>,
        name_off: Vec<u32>,
        name_len: Vec<u16>,
        flags: Vec<NodeFlags>,
        logical: Vec<u64>,
        allocated: Vec<u64>,
        mtime: Vec<u32>,
        atime: Vec<u32>,
        file_id: Vec<u64>,
        agg_alloc: Vec<u64>,
        agg_count: Vec<u32>,
        reparse_tags: FxHashMap<NodeId, u32>,
    ) -> crate::error::Result<Self> {
        let n = parent.len();
        if n == 0 {
            return Err(crate::error::DskError::Ipc(
                "index must contain at least ROOT node".to_string(),
            ));
        }
        if n > 50_000_000 {
            return Err(crate::error::DskError::Ipc(format!(
                "node count {n} exceeds 50,000,000 limit"
            )));
        }
        if first_child.len() != n
            || next_sibling.len() != n
            || name_off.len() != n
            || name_len.len() != n
            || flags.len() != n
            || logical.len() != n
            || allocated.len() != n
            || mtime.len() != n
            || atime.len() != n
            || file_id.len() != n
            || agg_alloc.len() != n
            || agg_count.len() != n
        {
            return Err(crate::error::DskError::Ipc(
                "index SoA column lengths mismatch".to_string(),
            ));
        }

        if parent[ROOT as usize] != NONE {
            return Err(crate::error::DskError::Ipc(format!(
                "parent[ROOT] must be NONE, got {}",
                parent[ROOT as usize]
            )));
        }

        let arena_len = names.as_bytes().len();
        if arena_len > 2_000_000_000 {
            return Err(crate::error::DskError::Ipc(format!(
                "name arena length {arena_len} exceeds 2,000,000,000 limit"
            )));
        }

        let n_u32 = n as u32;
        for i in 0..n {
            let p = parent[i];
            if i > 0 && p == NONE {
                return Err(crate::error::DskError::Ipc(format!(
                    "non-root node {i} has parent NONE"
                )));
            }
            if p != NONE && p >= n_u32 {
                return Err(crate::error::DskError::Ipc(format!(
                    "parent[{i}] = {p} out of bounds ({n})"
                )));
            }
            let fc = first_child[i];
            if fc != NONE && (fc >= n_u32 || fc == ROOT) {
                return Err(crate::error::DskError::Ipc(format!(
                    "first_child[{i}] = {fc} invalid ({n})"
                )));
            }
            let ns = next_sibling[i];
            if ns != NONE && (ns >= n_u32 || ns == ROOT) {
                return Err(crate::error::DskError::Ipc(format!(
                    "next_sibling[{i}] = {ns} invalid ({n})"
                )));
            }
            let off = name_off[i] as usize;
            let len = name_len[i] as usize;
            if off.saturating_add(len) > arena_len {
                return Err(crate::error::DskError::Ipc(format!(
                    "name slice for node {i} ({off}..{}) exceeds arena length {arena_len}",
                    off + len
                )));
            }
        }

        // Validate parent-chain reachability to ROOT (no cycles) in O(N)
        let mut parent_state = vec![0u8; n];
        parent_state[ROOT as usize] = 2;
        let mut chain = Vec::new();
        for start in 1..n {
            if parent_state[start] == 2 {
                continue;
            }
            chain.clear();
            let mut curr = start;
            loop {
                let st = parent_state[curr];
                if st == 2 {
                    for &visited in &chain {
                        parent_state[visited] = 2;
                    }
                    break;
                }
                if st == 1 {
                    return Err(crate::error::DskError::Ipc(format!(
                        "cycle detected in parent links starting from node {start}"
                    )));
                }
                parent_state[curr] = 1;
                chain.push(curr);
                curr = parent[curr] as usize;
            }
        }

        // Validate first_child / next_sibling acyclicity and parent consistency in O(N)
        let mut child_seen = vec![false; n];
        for (p_idx, &fc) in first_child.iter().enumerate().take(n) {
            let mut c = fc;
            while c != NONE {
                let c_idx = c as usize;
                if child_seen[c_idx] {
                    return Err(crate::error::DskError::Ipc(format!(
                        "cycle or duplicate child link detected at node {c_idx}"
                    )));
                }
                if parent[c_idx] != p_idx as u32 {
                    return Err(crate::error::DskError::Ipc(format!(
                        "child {c_idx} under parent {p_idx} has mismatched parent[{}] = {}",
                        c_idx, parent[c_idx]
                    )));
                }
                child_seen[c_idx] = true;
                c = next_sibling[c_idx];
            }
        }

        for &tag_node in reparse_tags.keys() {
            if tag_node >= n_u32 {
                return Err(crate::error::DskError::Ipc(format!(
                    "reparse tag node {tag_node} out of bounds ({n})"
                )));
            }
        }

        Ok(Self {
            volume,
            names,
            parent,
            first_child,
            next_sibling,
            name_off,
            name_len,
            flags,
            logical,
            allocated,
            mtime,
            atime,
            file_id,
            agg_alloc,
            agg_count,
            reparse_tags,
        })
    }

    pub fn heap_bytes(&self) -> usize {
        self.parent.capacity() * std::mem::size_of::<NodeId>()
            + self.first_child.capacity() * std::mem::size_of::<NodeId>()
            + self.next_sibling.capacity() * std::mem::size_of::<NodeId>()
            + self.name_off.capacity() * std::mem::size_of::<u32>()
            + self.name_len.capacity() * std::mem::size_of::<u16>()
            + self.flags.capacity() * std::mem::size_of::<NodeFlags>()
            + self.logical.capacity() * std::mem::size_of::<u64>()
            + self.allocated.capacity() * std::mem::size_of::<u64>()
            + self.mtime.capacity() * std::mem::size_of::<u32>()
            + self.atime.capacity() * std::mem::size_of::<u32>()
            + self.file_id.capacity() * std::mem::size_of::<u64>()
            + self.agg_alloc.capacity() * std::mem::size_of::<u64>()
            + self.agg_count.capacity() * std::mem::size_of::<u32>()
            + self.names.heap_bytes()
            + self.reparse_tags.capacity() * (std::mem::size_of::<(NodeId, u32)>() + 1)
    }
}

pub struct IndexBuilder {
    root_key: u64,
    root_name_ref: NameRef,
    volume: VolumeInfo,
    names: NameArena,
    entries: Vec<RawEntry>,
}

impl IndexBuilder {
    pub fn new(root_key: u64, root_name: &str, volume: VolumeInfo) -> Self {
        let mut names = NameArena::new();
        let root_name_ref = names.push_str(root_name);
        Self {
            root_key,
            root_name_ref,
            volume,
            names,
            entries: Vec::new(),
        }
    }

    pub fn push_batch(&mut self, mut b: EntryBatch) {
        let base = self.names.append(&b.names);
        for entry in &mut b.entries {
            entry.name.off += base;
        }
        self.entries.extend(b.entries);
    }

    pub fn finish(mut self) -> Index {
        let estimated_nodes = self.entries.len() + 2;
        let mut parent = Vec::with_capacity(estimated_nodes);
        let mut first_child = Vec::with_capacity(estimated_nodes);
        let mut next_sibling = Vec::with_capacity(estimated_nodes);
        let mut name_off = Vec::with_capacity(estimated_nodes);
        let mut name_len = Vec::with_capacity(estimated_nodes);
        let mut flags = Vec::with_capacity(estimated_nodes);
        let mut logical = Vec::with_capacity(estimated_nodes);
        let mut allocated = Vec::with_capacity(estimated_nodes);
        let mut mtime = Vec::with_capacity(estimated_nodes);
        let mut atime = Vec::with_capacity(estimated_nodes);
        let mut file_id = Vec::with_capacity(estimated_nodes);
        let mut agg_alloc = Vec::with_capacity(estimated_nodes);
        let mut agg_count = Vec::with_capacity(estimated_nodes);
        let mut reparse_tags = FxHashMap::default();

        // 1. ROOT node (NodeId 0)
        parent.push(NONE);
        first_child.push(NONE);
        next_sibling.push(NONE);
        name_off.push(self.root_name_ref.off);
        name_len.push(self.root_name_ref.len);
        flags.push(NodeFlags::DIR);
        logical.push(0);
        allocated.push(0);
        mtime.push(0);
        atime.push(0);
        file_id.push(0);
        agg_alloc.push(0);
        agg_count.push(0);

        let mut dir_map = FxHashMap::default();
        dir_map.insert(self.root_key, ROOT);
        let mut parent_keys = vec![0u64];

        for entry in self.entries {
            if entry.key == self.root_key {
                flags[ROOT as usize] |= entry.flags | NodeFlags::DIR;
                logical[ROOT as usize] = entry.logical;
                allocated[ROOT as usize] = entry.allocated;
                mtime[ROOT as usize] = filetime_to_min2000(entry.mtime);
                atime[ROOT as usize] = filetime_to_min2000(entry.atime);
                file_id[ROOT as usize] = entry.file_id;
                if entry.reparse_tag != 0 {
                    reparse_tags.insert(ROOT, entry.reparse_tag);
                }
            } else {
                let id = parent.len() as NodeId;
                parent.push(NONE);
                first_child.push(NONE);
                next_sibling.push(NONE);
                name_off.push(entry.name.off);
                name_len.push(entry.name.len);
                flags.push(entry.flags);
                logical.push(entry.logical);
                allocated.push(entry.allocated);
                mtime.push(filetime_to_min2000(entry.mtime));
                atime.push(filetime_to_min2000(entry.atime));
                file_id.push(entry.file_id);
                agg_alloc.push(0);
                agg_count.push(0);
                if entry.reparse_tag != 0 {
                    reparse_tags.insert(id, entry.reparse_tag);
                }
                parent_keys.push(entry.parent_key);
                if entry.flags.contains(NodeFlags::DIR) {
                    dir_map.insert(entry.key, id);
                }
            }
        }

        // 2. Directory key -> NodeId map. Attach each entry to parent directory node.
        for (id, &pkey) in parent_keys.iter().enumerate().skip(1) {
            parent[id] = dir_map.get(&pkey).copied().unwrap_or(NONE);
        }

        // 3. Reachability / cycles / orphans resolution
        let initial_count = parent.len();
        let mut state = vec![0u8; initial_count];
        state[ROOT as usize] = 2; // REACHABLE

        let mut orphan_id: Option<NodeId> = None;

        for i in 1..initial_count {
            let node_i = i as NodeId;
            if state[node_i as usize] != 0 {
                continue;
            }
            let mut curr = node_i;
            let mut path = Vec::new();
            loop {
                let curr_idx = curr as usize;
                if curr_idx < state.len() && state[curr_idx] == 2 {
                    for &p_node in &path {
                        state[p_node as usize] = 2;
                    }
                    break;
                }
                if curr_idx < state.len() && state[curr_idx] == 1 {
                    // Cycle detected!
                    let cycle_pos = path.iter().position(|&x| x == curr).unwrap();
                    let cycle = &path[cycle_pos..];
                    let break_node = *cycle.iter().min().unwrap();

                    let oid = if let Some(oid) = orphan_id {
                        oid
                    } else {
                        let oid = parent.len() as NodeId;
                        let name_ref = self.names.push_str("<orphaned>");
                        parent.push(ROOT);
                        first_child.push(NONE);
                        next_sibling.push(NONE);
                        name_off.push(name_ref.off);
                        name_len.push(name_ref.len);
                        flags.push(NodeFlags::DIR | NodeFlags::ORPHANS);
                        logical.push(0);
                        allocated.push(0);
                        mtime.push(0);
                        atime.push(0);
                        file_id.push(0);
                        agg_alloc.push(0);
                        agg_count.push(0);
                        orphan_id = Some(oid);
                        oid
                    };

                    parent[break_node as usize] = oid;
                    for &p_node in &path {
                        state[p_node as usize] = 2;
                    }
                    break;
                }
                if curr_idx < state.len() && state[curr_idx] == 0 {
                    state[curr_idx] = 1;
                    path.push(curr);
                    let p = parent[curr_idx];
                    if p == NONE {
                        // Missing parent: curr is topmost unreachable ancestor
                        let oid = if let Some(oid) = orphan_id {
                            oid
                        } else {
                            let oid = parent.len() as NodeId;
                            let name_ref = self.names.push_str("<orphaned>");
                            parent.push(ROOT);
                            first_child.push(NONE);
                            next_sibling.push(NONE);
                            name_off.push(name_ref.off);
                            name_len.push(name_ref.len);
                            flags.push(NodeFlags::DIR | NodeFlags::ORPHANS);
                            logical.push(0);
                            allocated.push(0);
                            mtime.push(0);
                            atime.push(0);
                            file_id.push(0);
                            agg_alloc.push(0);
                            agg_count.push(0);
                            orphan_id = Some(oid);
                            oid
                        };

                        parent[curr_idx] = oid;
                        for &p_node in &path {
                            state[p_node as usize] = 2;
                        }
                        break;
                    } else {
                        curr = p;
                    }
                } else {
                    // curr is orphan_id (>= initial_count), which reaches ROOT
                    for &p_node in &path {
                        state[p_node as usize] = 2;
                    }
                    break;
                }
            }
        }

        // Link first_child and next_sibling
        let total_nodes = parent.len();
        let mut last_child = vec![NONE; total_nodes];
        for (id, &p) in parent.iter().enumerate().skip(1) {
            if p != NONE {
                let p_idx = p as usize;
                let last = last_child[p_idx];
                if last == NONE {
                    first_child[p_idx] = id as NodeId;
                } else {
                    next_sibling[last as usize] = id as NodeId;
                }
                last_child[p_idx] = id as NodeId;
            }
        }

        // 4. METAFILE is inherited by all descendants (BFS iterative)
        let mut queue = Vec::with_capacity(total_nodes);
        queue.push(ROOT);
        let mut head = 0;
        while head < queue.len() {
            let u = queue[head];
            head += 1;
            let u_is_meta = flags[u as usize].contains(NodeFlags::METAFILE);
            let mut c = first_child[u as usize];
            while c != NONE {
                if u_is_meta {
                    flags[c as usize] |= NodeFlags::METAFILE;
                }
                queue.push(c);
                c = next_sibling[c as usize];
            }
        }

        // 5. Hard links deduplication
        let mut links: Vec<(u64, NodeId)> = Vec::new();
        for id in 1..total_nodes as NodeId {
            let idx = id as usize;
            if !flags[idx].contains(NodeFlags::DIR) && file_id[idx] != 0 {
                links.push((file_id[idx], id));
            }
        }
        links.sort_unstable();

        let mut i = 0;
        while i < links.len() {
            let mut j = i + 1;
            while j < links.len() && links[j].0 == links[i].0 {
                j += 1;
            }
            if j - i > 1 {
                flags[links[i].1 as usize] |= NodeFlags::HARDLINK;
                for k in (i + 1)..j {
                    flags[links[k].1 as usize] |= NodeFlags::HARDLINK | NodeFlags::DUP_LINK;
                }
            }
            i = j;
        }

        // 6. Iterative post-order aggregate (no recursion)
        for &u in queue.iter().rev() {
            let u_idx = u as usize;
            if flags[u_idx].contains(NodeFlags::DIR) {
                let mut tot = allocated[u_idx];
                let mut cnt = 0u32;
                let mut c = first_child[u_idx];
                while c != NONE {
                    let c_idx = c as usize;
                    tot = tot.saturating_add(agg_alloc[c_idx]);
                    cnt = cnt.saturating_add(agg_count[c_idx]);
                    c = next_sibling[c_idx];
                }
                agg_alloc[u_idx] = tot;
                agg_count[u_idx] = cnt;
            } else {
                agg_count[u_idx] = 1;
                if flags[u_idx].contains(NodeFlags::DUP_LINK) {
                    agg_alloc[u_idx] = 0;
                } else {
                    agg_alloc[u_idx] = allocated[u_idx];
                }
            }
        }

        // 7. shrink_to_fit on all vectors and names
        parent.shrink_to_fit();
        first_child.shrink_to_fit();
        next_sibling.shrink_to_fit();
        name_off.shrink_to_fit();
        name_len.shrink_to_fit();
        flags.shrink_to_fit();
        logical.shrink_to_fit();
        allocated.shrink_to_fit();
        mtime.shrink_to_fit();
        atime.shrink_to_fit();
        file_id.shrink_to_fit();
        agg_alloc.shrink_to_fit();
        agg_count.shrink_to_fit();
        self.names.shrink_to_fit();
        reparse_tags.shrink_to_fit();

        Index {
            volume: self.volume,
            names: self.names,
            parent,
            first_child,
            next_sibling,
            name_off,
            name_len,
            flags,
            logical,
            allocated,
            mtime,
            atime,
            file_id,
            agg_alloc,
            agg_count,
            reparse_tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
    fn links_children_and_aggregates() {
        // root(5) -> A(10) -> f1 4096, f2 8192 ; root -> f3 100
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[
            (10, 5, "A", true, 0, 0),
            (11, 10, "f1", false, 4096, 0),
            (12, 10, "f2", false, 8192, 0),
            (13, 5, "f3", false, 100, 0),
        ]);
        b.push_batch(batch_data);
        let ix = b.finish();

        let a = ix.children(ROOT).find(|&c| ix.name(c) == "A").unwrap();
        let f1 = ix.children(a).find(|&c| ix.name(c) == "f1").unwrap();

        assert_eq!(ix.total_allocated(ROOT), 4096 + 8192 + 100);
        assert_eq!(ix.total_allocated(a), 12_288);
        assert_eq!(ix.file_count(ROOT), 3);
        assert_eq!(ix.path(f1), PathBuf::from(r"C:\A\f1"));
        assert_eq!(ix.depth(f1), 2);
    }

    #[test]
    fn hard_links_counted_once() {
        // file_id 77, 4096 bytes, linked from root and from A
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[
            (10, 5, "A", true, 0, 0),
            (11, 5, "link1", false, 4096, 77),
            (12, 10, "link2", false, 4096, 77),
        ]);
        b.push_batch(batch_data);
        let ix = b.finish();

        let a = ix.children(ROOT).find(|&c| ix.name(c) == "A").unwrap();
        let both = [
            ix.children(ROOT).find(|&c| ix.name(c) == "link1").unwrap(),
            ix.children(a).find(|&c| ix.name(c) == "link2").unwrap(),
        ];

        assert_eq!(ix.total_allocated(ROOT), 4096);
        assert!(
            both.iter()
                .all(|&n| ix.flags(n).contains(NodeFlags::HARDLINK))
        );
        assert_eq!(
            both.iter()
                .filter(|&&n| ix.flags(n).contains(NodeFlags::DUP_LINK))
                .count(),
            1
        );
    }

    #[test]
    fn missing_parent_goes_to_orphans() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[(11, 999, "orphan_file", false, 4096, 0)]);
        b.push_batch(batch_data);
        let ix = b.finish();

        let o = ix
            .children(ROOT)
            .find(|&c| ix.flags(c).contains(NodeFlags::ORPHANS))
            .unwrap();
        assert_eq!(ix.name(o), "<orphaned>");
        assert_eq!(ix.total_allocated(ROOT), 4096); // still counted
    }

    #[test]
    fn parent_cycle_goes_to_orphans() {
        /* dirs 20<->21, file under 21 */
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[
            (20, 21, "d20", true, 0, 0),
            (21, 20, "d21", true, 0, 0),
            (22, 21, "f", false, 4096, 0),
        ]);
        b.push_batch(batch_data);
        let ix = b.finish();

        assert_eq!(ix.total_allocated(ROOT), 4096);
    }

    #[test]
    fn deep_chain_does_not_overflow() {
        /* 200_000 nested dirs + leaf 4096 */
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let n = 200_000u64;
        let mut names = NameArena::new();
        let mut entries = Vec::with_capacity(n as usize + 1);

        let name_d = names.push_str("d");
        entries.push(RawEntry {
            key: 10,
            parent_key: 5,
            name: name_d,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: 0,
            reparse_tag: 0,
        });
        for i in 11..10 + n {
            entries.push(RawEntry {
                key: i,
                parent_key: i - 1,
                name: name_d,
                flags: NodeFlags::DIR,
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: 0,
                reparse_tag: 0,
            });
        }
        let name_f = names.push_str("f");
        entries.push(RawEntry {
            key: 10 + n,
            parent_key: 10 + n - 1,
            name: name_f,
            flags: NodeFlags::empty(),
            logical: 4096,
            allocated: 4096,
            mtime: 0,
            atime: 0,
            file_id: 0,
            reparse_tag: 0,
        });
        b.push_batch(EntryBatch { names, entries });
        let ix = b.finish();

        assert_eq!(ix.total_allocated(ROOT), 4096);
    }

    #[test]
    fn metafile_flag_inherits() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let n1 = names.push_str("$Extend");
        let n2 = names.push_str("child");
        let entries = vec![
            RawEntry {
                key: 10,
                parent_key: 5,
                name: n1,
                flags: NodeFlags::DIR | NodeFlags::METAFILE,
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: 0,
                reparse_tag: 0,
            },
            RawEntry {
                key: 11,
                parent_key: 10,
                name: n2,
                flags: NodeFlags::empty(),
                logical: 100,
                allocated: 100,
                mtime: 0,
                atime: 0,
                file_id: 0,
                reparse_tag: 0,
            },
        ];
        b.push_batch(EntryBatch { names, entries });
        let ix = b.finish();

        let extend = ix
            .children(ROOT)
            .find(|&c| ix.name(c) == "$Extend")
            .unwrap();
        let child_of_extend = ix
            .children(extend)
            .find(|&c| ix.name(c) == "child")
            .unwrap();

        assert!(ix.flags(child_of_extend).contains(NodeFlags::METAFILE));
    }

    #[test]
    fn root_key_entry_updates_root() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let n = names.push_str(".");
        let entries = vec![RawEntry {
            key: 5,
            parent_key: 5,
            name: n,
            flags: NodeFlags::DIR,
            logical: 8192,
            allocated: 8192,
            mtime: 0,
            atime: 0,
            file_id: 0,
            reparse_tag: 0,
        }];
        b.push_batch(EntryBatch { names, entries });
        let ix = b.finish();

        assert_eq!(ix.allocated(ROOT), 8192);
        assert_eq!(ix.len(), 1);
    }

    #[test]
    fn batches_rebase_names() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut n1_arena = NameArena::new();
        let r1 = n1_arena.push_str("alpha");
        b.push_batch(EntryBatch {
            names: n1_arena,
            entries: vec![RawEntry {
                key: 10,
                parent_key: 5,
                name: r1,
                flags: NodeFlags::empty(),
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: 0,
                reparse_tag: 0,
            }],
        });
        let mut n2_arena = NameArena::new();
        let r2 = n2_arena.push_str("beta");
        b.push_batch(EntryBatch {
            names: n2_arena,
            entries: vec![RawEntry {
                key: 11,
                parent_key: 5,
                name: r2,
                flags: NodeFlags::empty(),
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: 0,
                reparse_tag: 0,
            }],
        });
        let ix = b.finish();

        let n1 = ix.children(ROOT).find(|&c| ix.name(c) == "alpha").unwrap();
        let n2 = ix.children(ROOT).find(|&c| ix.name(c) == "beta").unwrap();

        assert_eq!(ix.name(n1), "alpha");
        assert_eq!(ix.name(n2), "beta");
    }

    #[test]
    fn memory_budget() {
        /* 100_000 files, 20-byte names */
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let count = 100_000usize;
        let mut names = NameArena::new();
        let mut entries = Vec::with_capacity(count);
        let name_ref = names.push_str("01234567890123456789");
        for i in 0..count {
            entries.push(RawEntry {
                key: (i + 10) as u64,
                parent_key: 5,
                name: name_ref,
                flags: NodeFlags::empty(),
                logical: 1000,
                allocated: 4096,
                mtime: 0,
                atime: 0,
                file_id: 0,
                reparse_tag: 0,
            });
        }
        b.push_batch(EntryBatch { names, entries });
        let ix = b.finish();

        assert!(ix.heap_bytes() / ix.len() <= 100);
    }

    #[test]
    fn find_by_path_resolves_volume_and_subfolder_roots_case_insensitively() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let batch_data = batch(&[
            (10, 5, "Projects", true, 0, 0),
            (11, 10, "DiskSaver", true, 0, 0),
            (12, 11, "src", true, 0, 0),
            (13, 12, "main.rs", false, 2048, 0),
            (14, 5, "Windows", true, 0, 0),
        ]);
        b.push_batch(batch_data);
        let ix = b.finish();

        let projects = ix
            .children(ROOT)
            .find(|&c| ix.name(c) == "Projects")
            .unwrap();
        let disksaver = ix
            .children(projects)
            .find(|&c| ix.name(c) == "DiskSaver")
            .unwrap();
        let src = ix
            .children(disksaver)
            .find(|&c| ix.name(c) == "src")
            .unwrap();
        let main_rs = ix.children(src).find(|&c| ix.name(c) == "main.rs").unwrap();
        let windows = ix
            .children(ROOT)
            .find(|&c| ix.name(c) == "Windows")
            .unwrap();

        // 1. Root match variants
        assert_eq!(ix.find_by_path(Path::new(r"C:\")), Some(ROOT));
        assert_eq!(ix.find_by_path(Path::new("C:")), Some(ROOT));
        assert_eq!(ix.find_by_path(Path::new("c:/")), Some(ROOT));
        assert_eq!(ix.find_by_path(Path::new(r"\\?\C:\")), Some(ROOT));
        assert_eq!(ix.find_by_path(Path::new(r"\??\c:\")), Some(ROOT));

        // 2. Child and nested resolution with case-insensitivity and slash normalization
        assert_eq!(ix.find_by_path(Path::new(r"C:\projects")), Some(projects));
        assert_eq!(
            ix.find_by_path(Path::new("c:/PROJECTS/disksaver")),
            Some(disksaver)
        );
        assert_eq!(
            ix.find_by_path(Path::new(r"\\?\C:\Projects\DiskSaver\src\main.rs")),
            Some(main_rs)
        );
        assert_eq!(ix.find_by_path(Path::new(r"c:\windows")), Some(windows));

        // 3. Mismatched drive or non-existent path
        assert_eq!(ix.find_by_path(Path::new(r"D:\Projects")), None);
        assert_eq!(ix.find_by_path(Path::new(r"C:\NonExistent")), None);
        assert_eq!(ix.find_by_path(Path::new(r"C:\Projects\Other")), None);

        // 4. Subfolder root index
        let mut sub_b = IndexBuilder::new(10, r"C:\Projects", VolumeInfo::default());
        let sub_batch = batch(&[
            (11, 10, "DiskSaver", true, 0, 0),
            (12, 11, "file.txt", false, 512, 0),
        ]);
        sub_b.push_batch(sub_batch);
        let sub_ix = sub_b.finish();

        let sub_ds = sub_ix
            .children(ROOT)
            .find(|&c| sub_ix.name(c) == "DiskSaver")
            .unwrap();
        let sub_file = sub_ix
            .children(sub_ds)
            .find(|&c| sub_ix.name(c) == "file.txt")
            .unwrap();

        assert_eq!(sub_ix.find_by_path(Path::new(r"c:\projects")), Some(ROOT));
        assert_eq!(
            sub_ix.find_by_path(Path::new(r"\\?\C:\PROJECTS\disksaver")),
            Some(sub_ds)
        );
        assert_eq!(
            sub_ix.find_by_path(Path::new(r"C:\Projects\DiskSaver\file.txt")),
            Some(sub_file)
        );
        assert_eq!(sub_ix.find_by_path(Path::new(r"C:\")), None); // parent of subfolder root is not in index
    }
}
