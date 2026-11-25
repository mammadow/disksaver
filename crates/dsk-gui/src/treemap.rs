//! High-performance squarified cushion treemap engine.

#![forbid(unsafe_code)]

use dsk_core::{Index, NodeFlags, NodeId};
use eframe::egui::epaint::{Vertex, WHITE_UV};
use eframe::egui::{Color32, Mesh, Pos2};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::theme::{self, node_color};

pub const MAX_TREEMAP_RECTS: usize = 4_000;
pub const MIN_SUBDIVISION_PT: f32 = 6.0;
pub const MIN_TAIL_PT: f32 = 2.0;

/// Lazily sorts and caches children descending by effective size once per visited parent NodeId.
#[derive(Clone, Debug, Default)]
pub struct SortedChildrenCache {
    pub cache: FxHashMap<NodeId, Vec<NodeId>>,
}

impl SortedChildrenCache {
    pub fn new() -> Self {
        Self {
            cache: FxHashMap::default(),
        }
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn get_or_insert_sorted(
        &mut self,
        parent: NodeId,
        index: &Index,
        size_delta: &FxHashMap<NodeId, u64>,
    ) -> &[NodeId] {
        self.cache.entry(parent).or_insert_with(|| {
            let mut children: Vec<NodeId> = index.children(parent).collect();
            children.sort_by(|&a, &b| {
                let size_a = index
                    .total_allocated(a)
                    .saturating_sub(size_delta.get(&a).copied().unwrap_or(0));
                let size_b = index
                    .total_allocated(b)
                    .saturating_sub(size_delta.get(&b).copied().unwrap_or(0));
                size_b.cmp(&size_a).then_with(|| a.cmp(&b))
            });
            children
        })
    }
}

/// A rendered leaf tile or synthetic collapsed tail rectangle in the treemap layout.
#[derive(Clone, Debug, PartialEq)]
pub struct TreemapItem {
    pub node_id: Option<NodeId>,
    pub rect: [f32; 4], // [min_x, min_y, max_x, max_y]
    pub color: Color32,
    pub depth: u16,
    pub bytes: u64,
    pub label: String,
    pub small_tail_count: u32,
}

/// Output of the squarified layout algorithm.
#[derive(Clone, Debug)]
pub struct TreemapLayout {
    pub zoom_root: NodeId,
    pub items: Vec<TreemapItem>,
    pub leaf_rects: usize,
    pub collapsed_groups: u32,
}

/// Helper to compute effective byte size taking deletion deltas into account.
#[inline]
pub fn node_effective_bytes(id: NodeId, index: &Index, size_delta: &FxHashMap<NodeId, u64>) -> u64 {
    let raw = index.total_allocated(id);
    let delta = size_delta.get(&id).copied().unwrap_or(0);
    raw.saturating_sub(delta)
}

enum PartitionedItem {
    Normal {
        node_id: NodeId,
        rect: [f32; 4],
        bytes: u64,
    },
    SmallTail {
        rect: [f32; 4],
        bytes: u64,
        count: u32,
    },
}

#[inline]
fn worst_aspect_ratio(areas: &[f64], row: &[usize], row_sum: f64, side: f64) -> f64 {
    if row_sum <= 0.0 || side <= 0.0 {
        return f64::INFINITY;
    }
    let s2 = row_sum * row_sum;
    let side2 = side * side;
    let mut worst = 0.0f64;
    for &idx in row {
        let a = areas[idx];
        if a <= 0.0 {
            continue;
        }
        let r1 = (side2 * a) / s2;
        let r2 = s2 / (side2 * a);
        let asp = r1.max(r2);
        if asp > worst {
            worst = asp;
        }
    }
    worst
}

#[inline]
fn worst_aspect_ratio_cand(
    areas: &[f64],
    row: &[usize],
    cand_area: f64,
    row_sum: f64,
    side: f64,
) -> f64 {
    if row_sum <= 0.0 || side <= 0.0 {
        return f64::INFINITY;
    }
    let s2 = row_sum * row_sum;
    let side2 = side * side;
    let mut worst = 0.0f64;
    for &idx in row {
        let a = areas[idx];
        if a <= 0.0 {
            continue;
        }
        let r1 = (side2 * a) / s2;
        let r2 = s2 / (side2 * a);
        let asp = r1.max(r2);
        if asp > worst {
            worst = asp;
        }
    }
    if cand_area > 0.0 {
        let r1 = (side2 * cand_area) / s2;
        let r2 = s2 / (side2 * cand_area);
        let asp = r1.max(r2);
        if asp > worst {
            worst = asp;
        }
    }
    worst
}

fn squarify_partition(
    rect: [f32; 4],
    items: &[(NodeId, u64)],
    max_slots: usize,
) -> Vec<PartitionedItem> {
    let mut result = Vec::new();
    let rw = (rect[2] - rect[0]).max(0.0);
    let rh = (rect[3] - rect[1]).max(0.0);
    if rw <= 0.0 || rh <= 0.0 || items.is_empty() || max_slots == 0 {
        return result;
    }

    if max_slots == 1 {
        let total_bytes: u64 = items.iter().map(|(_, b)| *b).sum();
        if items.len() == 1 {
            result.push(PartitionedItem::Normal {
                node_id: items[0].0,
                rect,
                bytes: items[0].1,
            });
        } else {
            result.push(PartitionedItem::SmallTail {
                rect,
                bytes: total_bytes,
                count: items.len() as u32,
            });
        }
        return result;
    }

    let total_bytes: u64 = items.iter().map(|(_, b)| *b).sum();
    if total_bytes == 0 {
        return result;
    }

    let total_area = (rw as f64) * (rh as f64);
    let areas: Vec<f64> = items
        .iter()
        .map(|(_, b)| (*b as f64 / total_bytes as f64) * total_area)
        .collect();

    let mut rem_rect = rect;
    let mut rem_idx = 0;

    while rem_idx < items.len() {
        let cur_w = (rem_rect[2] - rem_rect[0]).max(0.0);
        let cur_h = (rem_rect[3] - rem_rect[1]).max(0.0);
        let minor = cur_w.min(cur_h);
        let remaining_count = items.len() - rem_idx;
        let available_slots = max_slots.saturating_sub(result.len());

        // Stop iterating trailing small siblings once remaining strip minor axis < 2.0 pt
        // OR if available slots cannot fit more than 1 item and there are multiple remaining
        if minor < MIN_TAIL_PT || (available_slots <= 1 && remaining_count > 1) {
            let tail_bytes: u64 = items[rem_idx..].iter().map(|(_, b)| *b).sum();
            result.push(PartitionedItem::SmallTail {
                rect: rem_rect,
                bytes: tail_bytes,
                count: remaining_count as u32,
            });
            break;
        }

        let side = minor as f64;
        let mut row: Vec<usize> = Vec::with_capacity(8);
        row.push(rem_idx);
        let mut row_sum = areas[rem_idx];
        let mut curr_worst = worst_aspect_ratio(&areas, &row, row_sum, side);

        let mut next_idx = rem_idx + 1;
        while next_idx < items.len() {
            let items_after = items.len() - (next_idx + 1);
            let needed = result.len() + row.len() + 1 + if items_after > 0 { 1 } else { 0 };
            if needed > max_slots {
                break;
            }

            let cand_sum = row_sum + areas[next_idx];
            let cand_worst = worst_aspect_ratio_cand(&areas, &row, areas[next_idx], cand_sum, side);
            if cand_worst <= curr_worst {
                row.push(next_idx);
                row_sum = cand_sum;
                curr_worst = cand_worst;
                next_idx += 1;
            } else {
                break;
            }
        }

        let is_last_row = next_idx >= items.len();
        if cur_w >= cur_h {
            let strip_thickness = if is_last_row {
                cur_w
            } else {
                ((row_sum / side) as f32).min(cur_w)
            };
            let x0 = rem_rect[0];
            let x1 = if is_last_row {
                rem_rect[2]
            } else {
                (x0 + strip_thickness).min(rem_rect[2])
            };

            let mut cur_y = rem_rect[1];
            for (i, &idx) in row.iter().enumerate() {
                let y0 = cur_y;
                let y1 = if i == row.len() - 1 {
                    rem_rect[3]
                } else {
                    let h_item = ((areas[idx] / row_sum) as f32 * cur_h).min(rem_rect[3] - cur_y);
                    (cur_y + h_item).min(rem_rect[3])
                };
                result.push(PartitionedItem::Normal {
                    node_id: items[idx].0,
                    rect: [x0, y0, x1, y1],
                    bytes: items[idx].1,
                });
                cur_y = y1;
            }
            rem_rect[0] = x1;
        } else {
            let strip_thickness = if is_last_row {
                cur_h
            } else {
                ((row_sum / side) as f32).min(cur_h)
            };
            let y0 = rem_rect[1];
            let y1 = if is_last_row {
                rem_rect[3]
            } else {
                (y0 + strip_thickness).min(rem_rect[3])
            };

            let mut cur_x = rem_rect[0];
            for (i, &idx) in row.iter().enumerate() {
                let x0 = cur_x;
                let x1 = if i == row.len() - 1 {
                    rem_rect[2]
                } else {
                    let w_item = ((areas[idx] / row_sum) as f32 * cur_w).min(rem_rect[2] - cur_x);
                    (cur_x + w_item).min(rem_rect[2])
                };
                result.push(PartitionedItem::Normal {
                    node_id: items[idx].0,
                    rect: [x0, y0, x1, y1],
                    bytes: items[idx].1,
                });
                cur_x = x1;
            }
            rem_rect[1] = y1;
        }

        rem_idx = next_idx;
    }

    result
}

struct LayoutContext<'a> {
    max_depth: u16,
    index: &'a Index,
    cache: &'a mut SortedChildrenCache,
    size_delta: &'a FxHashMap<NodeId, u64>,
    hidden: &'a FxHashSet<NodeId>,
    projected_rects: &'a mut usize,
}

fn layout_recursive(
    partitions: Vec<PartitionedItem>,
    current_depth: u16,
    ctx: &mut LayoutContext<'_>,
    layout: &mut TreemapLayout,
) {
    for part in partitions {
        match part {
            PartitionedItem::SmallTail { rect, bytes, count } => {
                layout.items.push(TreemapItem {
                    node_id: None,
                    rect,
                    color: theme::small_tail_color(),
                    depth: current_depth,
                    bytes,
                    label: format!("<{count} small items>"),
                    small_tail_count: count,
                });
                layout.collapsed_groups += 1;
            }
            PartitionedItem::Normal {
                node_id,
                rect,
                bytes,
            } => {
                let is_dir = ctx.index.flags(node_id).contains(NodeFlags::DIR);
                let cur_w = rect[2] - rect[0];
                let cur_h = rect[3] - rect[1];
                let expansion_room = MAX_TREEMAP_RECTS.saturating_sub(*ctx.projected_rects);

                let can_descend = is_dir
                    && current_depth < ctx.max_depth
                    && cur_w >= MIN_SUBDIVISION_PT
                    && cur_h >= MIN_SUBDIVISION_PT
                    && expansion_room > 0;

                if can_descend {
                    let children_ids =
                        ctx.cache
                            .get_or_insert_sorted(node_id, ctx.index, ctx.size_delta);
                    let mut active_children: Vec<(NodeId, u64)> =
                        Vec::with_capacity(children_ids.len());
                    for &cid in children_ids {
                        if !ctx.hidden.contains(&cid) {
                            let eff = node_effective_bytes(cid, ctx.index, ctx.size_delta);
                            if eff > 0 {
                                active_children.push((cid, eff));
                            }
                        }
                    }

                    if !active_children.is_empty() {
                        let child_max_slots = 1 + expansion_room;
                        let child_parts =
                            squarify_partition(rect, &active_children, child_max_slots);
                        if !child_parts.is_empty() {
                            *ctx.projected_rects += child_parts.len() - 1;
                            layout_recursive(child_parts, current_depth + 1, ctx, layout);
                            continue;
                        }
                    }
                }

                layout.items.push(TreemapItem {
                    node_id: Some(node_id),
                    rect,
                    color: node_color(
                        ctx.index.flags(node_id),
                        &ctx.index.name(node_id),
                        current_depth,
                    ),
                    depth: current_depth,
                    bytes,
                    label: ctx.index.name(node_id).to_string(),
                    small_tail_count: 0,
                });
            }
        }
    }
}

/// Pure squarified treemap layout generator.
pub fn build_treemap_layout(
    index: &Index,
    cache: &mut SortedChildrenCache,
    size_delta: &FxHashMap<NodeId, u64>,
    hidden: &FxHashSet<NodeId>,
    zoom_root: NodeId,
    viewport: [f32; 4],
    max_depth: u16,
) -> TreemapLayout {
    let w = (viewport[2] - viewport[0]).max(0.0);
    let h = (viewport[3] - viewport[1]).max(0.0);
    if w <= 0.0 || h <= 0.0 || index.is_empty() || (zoom_root as usize) >= index.len() {
        return TreemapLayout {
            zoom_root,
            items: Vec::new(),
            leaf_rects: 0,
            collapsed_groups: 0,
        };
    }

    let root_bytes = node_effective_bytes(zoom_root, index, size_delta);
    if root_bytes == 0 || hidden.contains(&zoom_root) {
        return TreemapLayout {
            zoom_root,
            items: Vec::new(),
            leaf_rects: 0,
            collapsed_groups: 0,
        };
    }

    let mut layout = TreemapLayout {
        zoom_root,
        items: Vec::with_capacity(1024),
        leaf_rects: 0,
        collapsed_groups: 0,
    };

    let is_dir = index.flags(zoom_root).contains(NodeFlags::DIR);
    let can_subdivide =
        is_dir && max_depth > 0 && w >= MIN_SUBDIVISION_PT && h >= MIN_SUBDIVISION_PT;

    if can_subdivide {
        let children_ids = cache.get_or_insert_sorted(zoom_root, index, size_delta);
        let mut active_children: Vec<(NodeId, u64)> = Vec::with_capacity(children_ids.len());
        for &cid in children_ids {
            if !hidden.contains(&cid) {
                let eff = node_effective_bytes(cid, index, size_delta);
                if eff > 0 {
                    active_children.push((cid, eff));
                }
            }
        }

        if !active_children.is_empty() {
            let partitions = squarify_partition(viewport, &active_children, MAX_TREEMAP_RECTS);
            let mut projected_rects = partitions.len();
            let mut ctx = LayoutContext {
                max_depth,
                index,
                cache,
                size_delta,
                hidden,
                projected_rects: &mut projected_rects,
            };
            layout_recursive(partitions, 1, &mut ctx, &mut layout);
        } else {
            layout.items.push(TreemapItem {
                node_id: Some(zoom_root),
                rect: viewport,
                color: node_color(index.flags(zoom_root), &index.name(zoom_root), 0),
                depth: 0,
                bytes: root_bytes,
                label: index.name(zoom_root).to_string(),
                small_tail_count: 0,
            });
        }
    } else {
        layout.items.push(TreemapItem {
            node_id: Some(zoom_root),
            rect: viewport,
            color: node_color(index.flags(zoom_root), &index.name(zoom_root), 0),
            depth: 0,
            bytes: root_bytes,
            label: index.name(zoom_root).to_string(),
            small_tail_count: 0,
        });
    }

    layout.leaf_rects = layout.items.iter().filter(|i| i.node_id.is_some()).count();
    layout.collapsed_groups = layout
        .items
        .iter()
        .filter(|i| i.small_tail_count > 0)
        .count() as u32;

    layout
}

/// Generates 1 batched egui::Mesh with Gouraud-shaded cushion contours and highlights.
pub fn build_cushion_mesh(
    items: &[TreemapItem],
    hovered: Option<NodeId>,
    selected: Option<NodeId>,
) -> Mesh {
    let mut mesh = Mesh::default();
    mesh.vertices.reserve(items.len() * 5);
    mesh.indices.reserve(items.len() * 12);

    for item in items {
        let [x0, y0, x1, y1] = item.rect;
        let cx = (x0 + x1) * 0.5;
        let cy = (y0 + y1) * 0.5;
        let is_selected = item.node_id.is_some() && item.node_id == selected;
        let is_hovered = item.node_id.is_some() && item.node_id == hovered;

        let center_col = if is_selected {
            let r = ((item.color.r() as f32) * 1.45).min(255.0) as u8;
            let g = ((item.color.g() as f32) * 1.45).min(255.0) as u8;
            let b = ((item.color.b() as f32) * 1.45).min(255.0) as u8;
            Color32::from_rgba_premultiplied(r, g, b, item.color.a())
        } else if is_hovered {
            let r = ((item.color.r() as f32) * 1.30).min(255.0) as u8;
            let g = ((item.color.g() as f32) * 1.30).min(255.0) as u8;
            let b = ((item.color.b() as f32) * 1.30).min(255.0) as u8;
            Color32::from_rgba_premultiplied(r, g, b, item.color.a())
        } else {
            let r = ((item.color.r() as f32) * 1.18).min(255.0) as u8;
            let g = ((item.color.g() as f32) * 1.18).min(255.0) as u8;
            let b = ((item.color.b() as f32) * 1.18).min(255.0) as u8;
            Color32::from_rgba_premultiplied(r, g, b, item.color.a())
        };

        let perim_col = if is_selected {
            Color32::from_rgb(255, 255, 255)
        } else if is_hovered {
            Color32::from_rgb(224, 231, 255)
        } else {
            let pr = ((item.color.r() as f32) * 0.72) as u8;
            let pg = ((item.color.g() as f32) * 0.72) as u8;
            let pb = ((item.color.b() as f32) * 0.72) as u8;
            Color32::from_rgba_premultiplied(pr, pg, pb, item.color.a())
        };

        let v0 = mesh.vertices.len() as u32;
        mesh.vertices.push(Vertex {
            pos: Pos2::new(x0, y0),
            uv: WHITE_UV,
            color: perim_col,
        });
        mesh.vertices.push(Vertex {
            pos: Pos2::new(x1, y0),
            uv: WHITE_UV,
            color: perim_col,
        });
        mesh.vertices.push(Vertex {
            pos: Pos2::new(x1, y1),
            uv: WHITE_UV,
            color: perim_col,
        });
        mesh.vertices.push(Vertex {
            pos: Pos2::new(x0, y1),
            uv: WHITE_UV,
            color: perim_col,
        });
        mesh.vertices.push(Vertex {
            pos: Pos2::new(cx, cy),
            uv: WHITE_UV,
            color: center_col,
        });

        mesh.indices.extend_from_slice(&[
            v0 + 4,
            v0,
            v0 + 1, // Top
            v0 + 4,
            v0 + 1,
            v0 + 2, // Right
            v0 + 4,
            v0 + 2,
            v0 + 3, // Bottom
            v0 + 4,
            v0 + 3,
            v0, // Left
        ]);
    }

    mesh
}

/// Hit-tests a point in logical points against all emitted layout items.
pub fn hit_test(layout: &TreemapLayout, pos: [f32; 2]) -> Option<&TreemapItem> {
    let [x, y] = pos;
    layout.items.iter().rev().find(|item| {
        x >= item.rect[0] && x <= item.rect[2] && y >= item.rect[1] && y <= item.rect[3]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsk_core::ROOT;
    use dsk_core::index::builder::{EntryBatch, IndexBuilder, RawEntry};
    use dsk_core::index::names::NameArena;
    use dsk_core::volume::VolumeInfo;
    use std::time::{Duration, Instant};

    fn make_test_entry(
        names: &mut NameArena,
        key: u64,
        parent_key: u64,
        name: &str,
        dir: bool,
        alloc: u64,
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
            mtime: 0,
            atime: 0,
            file_id: 0,
            reparse_tag: 0,
        }
    }

    #[test]
    fn treemap_conserves_viewport_area_and_handles_zero_byte_children() {
        // Hierarchy:
        // root(5)
        //   - dirA(10): fileA1(100MB), fileA2(50MB), empty_dir(0B), zero_file(0B)
        //   - dirB(20): fileB1(150MB)
        //   - hidden_dir(30): fileH1(200MB)
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "dirA", true, 0),
            make_test_entry(&mut names, 11, 10, "fileA1", false, 100 * 1024 * 1024),
            make_test_entry(&mut names, 12, 10, "fileA2", false, 50 * 1024 * 1024),
            make_test_entry(&mut names, 13, 10, "empty_dir", true, 0),
            make_test_entry(&mut names, 14, 10, "zero_file", false, 0),
            make_test_entry(&mut names, 20, 5, "dirB", true, 0),
            make_test_entry(&mut names, 21, 20, "fileB1", false, 150 * 1024 * 1024),
            make_test_entry(&mut names, 30, 5, "hidden_dir", true, 0),
            make_test_entry(&mut names, 31, 30, "fileH1", false, 200 * 1024 * 1024),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let mut cache = SortedChildrenCache::new();
        let size_delta = FxHashMap::default();
        let mut hidden = FxHashSet::default();

        let hidden_node = index
            .children(ROOT)
            .find(|&c| index.name(c) == "hidden_dir")
            .unwrap();
        hidden.insert(hidden_node);

        let viewport = [0.0f32, 0.0f32, 800.0f32, 600.0f32];
        let expected_area = (viewport[2] - viewport[0]) * (viewport[3] - viewport[1]);

        let layout =
            build_treemap_layout(&index, &mut cache, &size_delta, &hidden, ROOT, viewport, 10);

        assert!(!layout.items.is_empty(), "layout must not be empty");

        // Verify zero-byte nodes and hidden nodes are never emitted
        for item in &layout.items {
            if let Some(nid) = item.node_id {
                assert_ne!(nid, hidden_node);
                assert!(item.bytes > 0, "emitted leaf item has 0 bytes");
            }
        }

        // Verify area conservation: sum of leaf rectangle areas must equal viewport area
        let sum_area: f32 = layout
            .items
            .iter()
            .map(|it| (it.rect[2] - it.rect[0]) * (it.rect[3] - it.rect[1]))
            .sum();

        let diff = (sum_area - expected_area).abs();
        assert!(
            diff < 1.0,
            "Treemap area conservation failed: sum={sum_area}, expected={expected_area}, diff={diff}"
        );
    }

    #[test]
    fn treemap_collapses_sub_2pt_tails_and_caps_4000_rects() {
        // Build a directory with 6,000 tiny files
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let mut entries = Vec::with_capacity(6_001);
        entries.push(make_test_entry(&mut names, 10, 5, "big_dir", true, 0));
        for i in 1..=6_000 {
            entries.push(make_test_entry(
                &mut names,
                100 + i as u64,
                10,
                &format!("file_{i}.txt"),
                false,
                1024,
            ));
        }
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let mut cache = SortedChildrenCache::new();
        let size_delta = FxHashMap::default();
        let hidden = FxHashSet::default();

        let viewport = [0.0f32, 0.0f32, 400.0f32, 300.0f32];
        let layout =
            build_treemap_layout(&index, &mut cache, &size_delta, &hidden, ROOT, viewport, 10);

        assert!(
            layout.items.len() <= MAX_TREEMAP_RECTS,
            "items.len() {} exceeded MAX_TREEMAP_RECTS {MAX_TREEMAP_RECTS}",
            layout.items.len()
        );
        assert!(
            layout.collapsed_groups >= 1,
            "expected at least 1 collapsed small item group"
        );

        // Verify total area is still conserved
        let expected_area = 400.0 * 300.0;
        let sum_area: f32 = layout
            .items
            .iter()
            .map(|it| (it.rect[2] - it.rect[0]) * (it.rect[3] - it.rect[1]))
            .sum();
        assert!(
            (sum_area - expected_area).abs() < 1.0,
            "Area conservation failed with collapsed tails: sum={sum_area}, expected={expected_area}"
        );
    }

    #[test]
    fn treemap_1m_nodes_layout_and_mesh_under_100ms() {
        // Construct 1,000,000 nodes: 1,000 directories with 1,000 files each
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();

        const NUM_DIRS: usize = 1_000;
        const FILES_PER_DIR: usize = 1_000;

        let mut entries = Vec::with_capacity(NUM_DIRS * (FILES_PER_DIR + 1));
        for d in 0..NUM_DIRS {
            let dir_key = 10_000 + d as u64;
            entries.push(make_test_entry(&mut names, dir_key, 5, "dir", true, 0));
            for f in 0..FILES_PER_DIR {
                let file_key = 100_000_000 + (d * FILES_PER_DIR + f) as u64;
                let size = ((f + 1) * 1024) as u64;
                entries.push(make_test_entry(
                    &mut names, file_key, dir_key, "f.dat", false, size,
                ));
            }
        }
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        assert!(index.len() >= 1_000_000);

        let mut cache = SortedChildrenCache::new();
        let size_delta = FxHashMap::default();
        let hidden = FxHashSet::default();
        let viewport = [0.0f32, 0.0f32, 1920.0f32, 1080.0f32];

        // Benchmark starts AFTER index construction
        let start = Instant::now();
        let layout =
            build_treemap_layout(&index, &mut cache, &size_delta, &hidden, ROOT, viewport, 8);
        let mesh = build_cushion_mesh(&layout.items, None, None);
        let elapsed = start.elapsed();

        println!(
            "1M nodes treemap layout & cushion mesh time: {:?} (items: {}, vertices: {}, indices: {})",
            elapsed,
            layout.items.len(),
            mesh.vertices.len(),
            mesh.indices.len()
        );

        assert!(
            elapsed < Duration::from_millis(100),
            "Expected 1M nodes layout+mesh < 100ms, took {elapsed:?}"
        );
        assert!(layout.items.len() <= MAX_TREEMAP_RECTS);
        assert_eq!(mesh.indices.len(), layout.items.len() * 12);
        assert_eq!(mesh.vertices.len(), layout.items.len() * 5);
    }

    #[test]
    fn hit_test_matches_deepest_leaf_rect() {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let entries = vec![
            make_test_entry(&mut names, 10, 5, "A.txt", false, 1000),
            make_test_entry(&mut names, 20, 5, "B.txt", false, 1000),
        ];
        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        let mut cache = SortedChildrenCache::new();
        let size_delta = FxHashMap::default();
        let hidden = FxHashSet::default();

        let viewport = [0.0f32, 0.0f32, 100.0f32, 100.0f32];
        let layout =
            build_treemap_layout(&index, &mut cache, &size_delta, &hidden, ROOT, viewport, 5);

        assert_eq!(layout.items.len(), 2);
        let first = &layout.items[0];
        let mid_x = (first.rect[0] + first.rect[2]) * 0.5;
        let mid_y = (first.rect[1] + first.rect[3]) * 0.5;

        let hit = hit_test(&layout, [mid_x, mid_y]);
        assert_eq!(hit, Some(first));

        let miss = hit_test(&layout, [999.0, 999.0]);
        assert_eq!(miss, None);
    }
}
