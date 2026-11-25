//! Explore view: breadcrumbs, filters, draggable GPU cushion treemap, virtualized tree table,
//! quick-inspector card, extension breakdown, and context actions.

#![forbid(unsafe_code)]

use dsk_core::{NodeFlags, NodeId, ROOT, open_item, reveal_in_explorer};
use eframe::egui::epaint::{CornerRadius, FontId, Stroke};
use eframe::egui::{
    self, Align, Align2, Color32, CursorIcon, Margin, Pos2, Rect, RichText, ScrollArea, Sense,
    StrokeKind, Vec2,
};

use crate::app_state::{ActiveTab, AppState, ConfirmAction};
use crate::theme::{self, ThemeTokens, fmt_bytes, fmt_count, node_color, verdict_color};
use crate::tree_model::TreeSort;
use crate::treemap::hit_test;
use crate::ui_kit::{self, Icon};
use crate::worker::WorkerHandle;

fn tree_sort_label(sort: TreeSort) -> &'static str {
    match sort {
        TreeSort::SizeDesc => "Size (Largest)",
        TreeSort::NameAsc => "Name (A-Z)",
        TreeSort::FilesDesc => "Files (Most)",
        TreeSort::MtimeDesc => "Modified (Newest)",
    }
}

/// Opens a file/folder off the UI thread so Shell COM never blocks rendering.
fn open_async(path: &std::path::Path) {
    let p = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = open_item(&p);
    });
}

/// Reveals a path in File Explorer off the UI thread.
fn reveal_async(path: &std::path::Path) {
    let p = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = reveal_in_explorer(&p);
    });
}

/// Renders the shared right-click context menu for any node (treemap tile or tree row).
pub fn render_shared_context_menu(ui: &mut egui::Ui, state: &mut AppState, node_id: NodeId) {
    let Some(report) = state.scan_report.clone() else {
        return;
    };
    if (node_id as usize) >= report.index.len() {
        return;
    }

    let is_dir = report.index.flags(node_id).contains(NodeFlags::DIR);
    let path = report.index.path(node_id);
    let path_str = path.display().to_string();
    let tokens = ThemeTokens::for_ui(ui);

    if is_dir && ui.button("Zoom Here").clicked() {
        state.zoom_into(node_id);
        ui.close();
    }

    if ui.button("Open").clicked() {
        open_async(&path);
        ui.close();
    }

    if ui.button("Reveal in Explorer").clicked() {
        reveal_async(&path);
        ui.close();
    }

    if ui.button("Copy Path").clicked() {
        ui.ctx().copy_text(path_str);
        ui.close();
    }

    ui.separator();

    if state.heavy_busy() {
        let btn = ui.add_enabled(false, egui::Button::new("Move to Recycle Bin..."));
        btn.on_disabled_hover_text("Wait for the running job to finish");
        return;
    }
    let recycle_action = state.prepare_recycle_confirm(node_id);
    match recycle_action {
        Some(ConfirmAction::RecycleTarget {
            blocked_reason: Some(reason),
            ..
        }) => {
            let btn = ui.add_enabled(false, egui::Button::new("Move to Recycle Bin..."));
            btn.on_disabled_hover_text(reason);
        }
        Some(
            confirm @ ConfirmAction::RecycleTarget {
                blocked_reason: None,
                ..
            },
        ) => {
            if ui
                .button(RichText::new("Move to Recycle Bin...").color(tokens.danger))
                .clicked()
            {
                state.confirm_modal = Some(confirm);
                ui.close();
            }
        }
        _ => {
            let btn = ui.add_enabled(false, egui::Button::new("Move to Recycle Bin..."));
            btn.on_disabled_hover_text("Cannot recycle this item");
        }
    }
}

/// Renders the Explore tab contents.
pub fn render(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    tokens: &ThemeTokens,
) {
    let _ = worker;

    let Some(report) = state.scan_report.clone() else {
        if ui_kit::empty_state(
            ui,
            Icon::Explore,
            "No Volume Scanned",
            "Select and scan a drive in Overview to explore its interactive cushion treemap and virtualized directory tree.",
            Some("Go to Overview"),
            tokens,
        ) {
            state.active_tab = ActiveTab::Overview;
        }
        return;
    };

    // Section 1: Breadcrumb Bar
    let mut zoom_to = None;
    let zoom_root_eff = state.ledger.effective_bytes(&report.index, state.zoom_root);
    let zoom_root_files = report.index.file_count(state.zoom_root) as u64;

    ui_kit::inset_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            if ui_kit::icon_button(
                ui,
                Icon::Copy,
                14.0,
                tokens.text_secondary,
                "Copy selected or zoomed path",
                tokens,
            )
            .clicked()
            {
                let target = state.selected_node.unwrap_or(state.zoom_root);
                let p = report.index.path(target).display().to_string();
                ui.ctx().copy_text(p);
            }
            ui_kit::pill_badge(
                ui,
                &format!(
                    "{} · {} files",
                    fmt_bytes(zoom_root_eff),
                    fmt_count(zoom_root_files)
                ),
                tokens.info,
                tokens,
            );

            ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                let can_back = !state.history_stack.is_empty();
                if ui_kit::icon_button(
                    ui,
                    Icon::Back,
                    14.0,
                    if can_back {
                        tokens.text_primary
                    } else {
                        tokens.text_muted
                    },
                    "Back (Alt+Left or Backspace)",
                    tokens,
                )
                .clicked()
                    && can_back
                {
                    state.navigate_back();
                }

                let can_up = state.zoom_root != ROOT;
                if ui_kit::icon_button(
                    ui,
                    Icon::Up,
                    14.0,
                    if can_up {
                        tokens.text_primary
                    } else {
                        tokens.text_muted
                    },
                    "Up to parent folder (Alt+Up)",
                    tokens,
                )
                .clicked()
                    && can_up
                {
                    state.navigate_up();
                }

                ui_kit::inline_divider(ui, tokens);

                // Breadcrumb path segments (collapse deep middle segments past 5 crumbs)
                let mut crumbs = Vec::new();
                let mut curr = state.zoom_root;
                while curr != dsk_core::NONE {
                    crumbs.push(curr);
                    curr = report.index.parent(curr);
                }
                crumbs.reverse();

                let root_display = report
                    .index
                    .path(ROOT)
                    .display()
                    .to_string()
                    .trim_start_matches(r"\\?\")
                    .to_string();
                let displayed: Vec<Option<NodeId>> = if crumbs.len() <= 5 {
                    crumbs.iter().map(|&n| Some(n)).collect()
                } else {
                    let mut v = Vec::with_capacity(5);
                    v.push(Some(crumbs[0]));
                    v.push(None);
                    for &n in &crumbs[crumbs.len() - 3..] {
                        v.push(Some(n));
                    }
                    v
                };

                for (idx, maybe_nid) in displayed.into_iter().enumerate() {
                    if idx > 0 {
                        ui_kit::icon_widget(ui, Icon::ChevronRight, 11.0, tokens.text_muted);
                    }
                    let Some(nid) = maybe_nid else {
                        let full = report.index.path(state.zoom_root).display().to_string();
                        ui.label(RichText::new("…").color(tokens.text_muted))
                            .on_hover_text(full);
                        continue;
                    };
                    let name = if nid == ROOT {
                        root_display.clone()
                    } else {
                        report.index.name(nid).to_string()
                    };
                    let is_current = nid == state.zoom_root;
                    let text = if is_current {
                        RichText::new(name).strong().color(tokens.accent)
                    } else {
                        RichText::new(name).color(tokens.text_secondary)
                    };
                    if ui.small_button(text).clicked() {
                        zoom_to = Some(nid);
                    }
                }
            });
        });
    });

    if let Some(nid) = zoom_to {
        state.zoom_into(nid);
    }

    ui.add_space(6.0);

    // Section 2: Filter & Mode Strip
    let mut filter_changed = false;
    let mut sort_changed = false;
    let mut color_mode_changed = false;

    ui.horizontal_wrapped(|ui| {
        ui_kit::icon_widget(ui, Icon::Search, 14.0, tokens.text_secondary);
        let query_resp = ui.add(
            egui::TextEdit::singleline(&mut state.explore_filter.query)
                .desired_width(150.0)
                .hint_text("Search name..."),
        );
        if query_resp.changed() {
            filter_changed = true;
        }
        if !state.explore_filter.query.is_empty()
            && ui_kit::icon_button(
                ui,
                Icon::Close,
                11.0,
                tokens.text_secondary,
                "Clear search",
                tokens,
            )
            .clicked()
        {
            state.explore_filter.query.clear();
            filter_changed = true;
        }

        let mut ext_buf = state.explore_filter.ext_filter.clone().unwrap_or_default();
        let ext_resp = ui.add(
            egui::TextEdit::singleline(&mut ext_buf)
                .desired_width(72.0)
                .hint_text("Ext (log)"),
        );
        if ext_resp.changed() {
            state.explore_filter.ext_filter = if ext_buf.trim().is_empty() {
                None
            } else {
                Some(ext_buf.trim().to_string())
            };
            filter_changed = true;
        }

        ui_kit::inline_divider(ui, tokens);
        let flag_chips = [
            (NodeFlags::CLOUD, "CLOUD"),
            (NodeFlags::COMPRESSED, "COMPR"),
            (NodeFlags::WOF, "WOF"),
            (NodeFlags::SPARSE, "SPARSE"),
            (NodeFlags::HARDLINK, "HARDLINK"),
            (NodeFlags::REPARSE, "REPARSE"),
        ];

        for (flag, label) in flag_chips {
            let active = state.explore_filter.required_flags.contains(flag);
            if ui_kit::chip_toggle(ui, active, label, None, tokens).clicked() {
                state.explore_filter.required_flags.toggle(flag);
                filter_changed = true;
            }
        }

        if !state.explore_filter.is_empty()
            && ui_kit::secondary_button(ui, "Clear", true, tokens).clicked()
        {
            state.explore_filter = Default::default();
            filter_changed = true;
        }

        ui_kit::inline_divider(ui, tokens);
        ui.label(
            RichText::new("Sort:")
                .size(11.5)
                .color(tokens.text_secondary),
        );
        let prev_sort = state.tree_model.sort;
        egui::ComboBox::from_id_salt("explore_tree_sort")
            .selected_text(tree_sort_label(state.tree_model.sort))
            .show_ui(ui, |ui| {
                for sort in [
                    TreeSort::SizeDesc,
                    TreeSort::NameAsc,
                    TreeSort::FilesDesc,
                    TreeSort::MtimeDesc,
                ] {
                    ui.selectable_value(&mut state.tree_model.sort, sort, tree_sort_label(sort));
                }
            });
        if crate::views::reclaim::render_explore_controls(ui, state, tokens) {
            color_mode_changed = true;
        }
        if state.tree_model.sort != prev_sort {
            sort_changed = true;
        }
    });

    if filter_changed || sort_changed || color_mode_changed {
        state.invalidate_explore_caches();
    }

    ui.add_space(6.0);

    // Section 3: Draggable Split View (Treemap Top / Virtualized Tree + Inspector Bottom)
    let available_h = ui.available_height().max(320.0);
    let max_treemap_h = (available_h - 170.0).max(150.0);
    let treemap_h = (available_h * state.explore_split_ratio).clamp(150.0, max_treemap_h);
    let treemap_size = Vec2::new(ui.available_width(), treemap_h);

    // 3A: Interactive Cushion Treemap
    let (treemap_rect, treemap_response) =
        ui.allocate_exact_size(treemap_size, Sense::click_and_drag());

    let inner_rect = treemap_rect.shrink(1.0);
    let vp = [
        inner_rect.min.x,
        inner_rect.min.y,
        inner_rect.max.x,
        inner_rect.max.y,
    ];
    state.ensure_explore_caches(vp, 4);

    let painter = ui.painter_at(treemap_rect);
    painter.rect_filled(treemap_rect, CornerRadius::ZERO, tokens.inset_bg);

    if !state.treemap_mesh.is_empty() {
        painter.add(egui::Shape::mesh(state.treemap_mesh.clone()));
    }

    // Crisp clipped multi-line labels with 1px shadow + hover/selection focus ring overlay
    let mut selected_tile_rect: Option<Rect> = None;
    let mut hovered_tile_rect: Option<Rect> = None;
    let shadow_col = Color32::from_black_alpha(150);

    for item in &state.treemap_layout.items {
        let [x0, y0, x1, y1] = item.rect;
        let tile_rect = Rect::from_min_max(Pos2::new(x0, y0), Pos2::new(x1, y1));
        let w = tile_rect.width();
        let h = tile_rect.height();

        if item.node_id.is_some() && item.node_id == state.selected_node {
            selected_tile_rect = Some(tile_rect);
        } else if item.node_id.is_some() && item.node_id == state.hovered_node {
            hovered_tile_rect = Some(tile_rect);
        }

        if w >= 48.0 && h >= 18.0 {
            let clipped = painter.with_clip_rect(tile_rect.shrink(3.0));
            if w >= 86.0 && h >= 34.0 {
                let name_pos = Pos2::new(tile_rect.center().x, tile_rect.center().y - 7.0);
                let size_pos = Pos2::new(tile_rect.center().x, tile_rect.center().y + 7.5);
                clipped.text(
                    name_pos + Vec2::new(0.0, 1.0),
                    Align2::CENTER_CENTER,
                    &item.label,
                    FontId::proportional(11.5),
                    shadow_col,
                );
                clipped.text(
                    name_pos,
                    Align2::CENTER_CENTER,
                    &item.label,
                    FontId::proportional(11.5),
                    Color32::WHITE,
                );
                clipped.text(
                    size_pos + Vec2::new(0.0, 1.0),
                    Align2::CENTER_CENTER,
                    fmt_bytes(item.bytes),
                    FontId::proportional(10.0),
                    shadow_col,
                );
                clipped.text(
                    size_pos,
                    Align2::CENTER_CENTER,
                    fmt_bytes(item.bytes),
                    FontId::proportional(10.0),
                    theme::with_alpha(Color32::WHITE, 230),
                );
            } else {
                let c = tile_rect.center();
                clipped.text(
                    c + Vec2::new(0.0, 1.0),
                    Align2::CENTER_CENTER,
                    &item.label,
                    FontId::proportional(10.5),
                    shadow_col,
                );
                clipped.text(
                    c,
                    Align2::CENTER_CENTER,
                    &item.label,
                    FontId::proportional(10.5),
                    Color32::WHITE,
                );
            }
        }
    }

    if let Some(r) = hovered_tile_rect {
        painter.rect_stroke(
            r,
            CornerRadius::ZERO,
            Stroke::new(1.5, theme::with_alpha(Color32::WHITE, 210)),
            StrokeKind::Inside,
        );
    }
    if let Some(r) = selected_tile_rect {
        painter.rect_stroke(
            r,
            CornerRadius::ZERO,
            Stroke::new(2.0, tokens.accent_hover),
            StrokeKind::Inside,
        );
    }

    painter.rect_stroke(
        treemap_rect,
        CornerRadius::ZERO,
        Stroke::new(1.0, tokens.border),
        StrokeKind::Inside,
    );

    // Treemap mouse interaction
    if let Some(pos) = treemap_response.hover_pos() {
        if let Some(item) = hit_test(&state.treemap_layout, [pos.x, pos.y]) {
            state.hovered_node = item.node_id;
        }
    } else {
        state.hovered_node = None;
    }

    // Treemap rich hover tooltip
    if let Some(nid) = state.hovered_node {
        let name = report.index.name(nid);
        let path = report.index.path(nid).display().to_string();
        let eff = state.ledger.effective_bytes(&report.index, nid);
        let flags = report.index.flags(nid);
        let pct = if zoom_root_eff > 0 {
            (eff as f64 / zoom_root_eff as f64) * 100.0
        } else {
            0.0
        };
        let verdict_opt = if state.explore_color_removable {
            state
                .reclaim
                .as_ref()
                .and_then(|r| r.verdicts.get(nid as usize).copied())
                .map(dsk_core::hunt::Verdict::from_u8)
        } else {
            None
        };

        treemap_response.clone().on_hover_ui_at_pointer(|ui| {
            ui.horizontal(|ui| {
                ui_kit::icon_widget(
                    ui,
                    if flags.contains(NodeFlags::DIR) {
                        Icon::Folder
                    } else {
                        Icon::File
                    },
                    14.0,
                    tokens.accent,
                );
                ui.strong(&*name);
            });
            ui.label(RichText::new(&path).size(11.0).color(tokens.text_secondary));
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(fmt_bytes(eff))
                        .monospace()
                        .strong()
                        .color(tokens.text_primary),
                );
                ui.label(
                    RichText::new(format!("({pct:.1}% of view)"))
                        .size(11.5)
                        .color(tokens.text_secondary),
                );
                if flags.contains(NodeFlags::DIR) {
                    ui.label(
                        RichText::new(format!(
                            "· {} files",
                            fmt_count(report.index.file_count(nid) as u64)
                        ))
                        .size(11.5)
                        .color(tokens.text_muted),
                    );
                }
            });
            if let Some(v) = verdict_opt {
                ui.add_space(2.0);
                ui_kit::pill_badge(ui, v.label(), verdict_color(v), tokens);
            }
            if !flags.is_empty() && flags != NodeFlags::DIR {
                ui.label(
                    RichText::new(format!("Flags: {flags:?}"))
                        .size(10.5)
                        .color(tokens.text_muted),
                );
            }
            if flags.contains(NodeFlags::DIR) {
                ui.label(
                    RichText::new("Double-click to zoom in · Right-click for actions")
                        .size(10.5)
                        .color(tokens.accent),
                );
            }
        });
    }

    if treemap_response.clicked()
        && let Some(pos) = treemap_response.interact_pointer_pos()
        && let Some(item) = hit_test(&state.treemap_layout, [pos.x, pos.y])
        && let Some(nid) = item.node_id
    {
        state.selected_node = Some(nid);
        state.tree_model.expand_ancestors(&report.index, nid);
    }

    if treemap_response.double_clicked()
        && let Some(pos) = treemap_response.interact_pointer_pos()
        && let Some(item) = hit_test(&state.treemap_layout, [pos.x, pos.y])
        && let Some(nid) = item.node_id
        && report.index.flags(nid).contains(NodeFlags::DIR)
    {
        state.zoom_into(nid);
    }

    if treemap_response.secondary_clicked()
        && let Some(pos) = treemap_response.interact_pointer_pos()
        && let Some(item) = hit_test(&state.treemap_layout, [pos.x, pos.y])
        && let Some(nid) = item.node_id
    {
        state.selected_node = Some(nid);
    }

    let selected_ctx_node = state.selected_node;
    treemap_response.context_menu(|ui| {
        if let Some(nid) = selected_ctx_node {
            render_shared_context_menu(ui, state, nid);
        }
    });

    // Draggable horizontal splitter bar
    let (split_rect, split_resp) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 10.0),
        Sense::click_and_drag(),
    );
    if ui.is_rect_visible(split_rect) {
        let grip_col = if split_resp.hovered() || split_resp.dragged() {
            tokens.accent
        } else {
            tokens.border
        };
        let grip = Rect::from_center_size(split_rect.center(), Vec2::new(48.0, 3.0));
        ui.painter()
            .rect_filled(grip, CornerRadius::same(2), grip_col);
    }
    if split_resp.hovered() || split_resp.dragged() {
        ui.ctx().set_cursor_icon(CursorIcon::ResizeVertical);
    }
    if split_resp.dragged() {
        let delta_y = split_resp.drag_delta().y;
        let next_h = treemap_h + delta_y;
        state.explore_split_ratio = (next_h / available_h).clamp(0.22, 0.75);
    }
    if split_resp.double_clicked() {
        state.explore_split_ratio = 0.45;
    }

    // 3B: Bottom Split (~62% Virtualized Tree | ~38% Inspector + Findings + Extensions)
    let ext_breakdown = state.ext_breakdown.clone();
    let current_selected = state.selected_node;
    let zoom_root_id = state.zoom_root;
    let row_count = state.tree_model.rows.len();

    let mut action_toggle = None;
    let mut action_select = None;
    let mut action_zoom = None;
    let mut action_ext_click = None;
    let mut hunt_navigate: Option<NodeId> = None;

    let bottom_h = ui.available_height().max(130.0);
    let total_w = ui.available_width().max(520.0);
    let gap = 10.0;
    let left_w = ((total_w - gap) * 0.62).clamp(280.0, (total_w - 220.0).max(280.0));
    let right_w = (total_w - gap - left_w).max(200.0);

    ui.horizontal_top(|ui| {
        // Left Pane: Virtualized Tree Table
        ui.vertical(|ui| {
            ui.set_width(left_w);
            ui.set_min_height(bottom_h);
            ui_kit::card_frame(tokens)
                .inner_margin(Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.strong(
                            RichText::new(format!(
                                "Directory Tree ({})",
                                fmt_count(row_count as u64)
                            ))
                            .color(tokens.text_primary),
                        );
                        if state.tree_model.truncated {
                            ui_kit::pill_badge(ui, "capped at 10k rows", tokens.warning, tokens);
                        }
                    });
                    ui.add_space(4.0);

                    let row_height = 24.0;
                    let tree_scroll_h = (bottom_h - 46.0).max(80.0);

                    ScrollArea::vertical()
                        .id_salt("explore_tree_scroll")
                        .max_height(tree_scroll_h)
                        .auto_shrink([false, false])
                        .show_rows(ui, row_height, row_count, |ui, row_range| {
                            let visible_rows: Vec<_> = state.tree_model.rows[row_range].to_vec();
                            for (local_idx, row) in visible_rows.into_iter().enumerate() {
                                let node_id = row.node_id;
                                let is_selected = current_selected == Some(node_id);
                                let depth_indent = (row.depth as f32 * 14.0).min(180.0);

                                let (row_rect, row_resp) = ui.allocate_exact_size(
                                    Vec2::new(ui.available_width(), row_height),
                                    Sense::click(),
                                );

                                let bg_color = if is_selected {
                                    tokens.row_selected
                                } else if row_resp.hovered() {
                                    tokens.row_hover
                                } else if local_idx % 2 == 1 {
                                    tokens.row_alt
                                } else {
                                    Color32::TRANSPARENT
                                };
                                ui.painter_at(row_rect).rect_filled(
                                    row_rect,
                                    CornerRadius::same(4),
                                    bg_color,
                                );

                                // Non-overlapping left (name) and right (stats) sub-rects
                                let stats_w = (row_rect.width() * 0.36).clamp(150.0, 210.0);
                                let split_x =
                                    (row_rect.max.x - stats_w - 6.0).max(row_rect.min.x + 80.0);
                                let left_rect = Rect::from_min_max(
                                    row_rect.min,
                                    Pos2::new(split_x, row_rect.max.y),
                                );
                                let right_rect = Rect::from_min_max(
                                    Pos2::new(split_x + 6.0, row_rect.min.y),
                                    row_rect.max,
                                );

                                let mut left_ui = ui.new_child(
                                    egui::UiBuilder::new()
                                        .max_rect(left_rect)
                                        .layout(egui::Layout::left_to_right(Align::Center)),
                                );
                                left_ui.set_clip_rect(left_rect.intersect(ui.clip_rect()));

                                left_ui.add_space(depth_indent + 6.0);

                                // Expand toggle for dirs
                                if row.has_children {
                                    let chev = if row.is_expanded {
                                        Icon::ChevronDown
                                    } else {
                                        Icon::ChevronRight
                                    };
                                    if ui_kit::icon_button(
                                        &mut left_ui,
                                        chev,
                                        11.0,
                                        tokens.text_secondary,
                                        if row.is_expanded {
                                            "Collapse"
                                        } else {
                                            "Expand"
                                        },
                                        tokens,
                                    )
                                    .clicked()
                                    {
                                        action_toggle = Some(node_id);
                                    }
                                } else {
                                    left_ui.add_space(24.0);
                                }

                                let item_icon = if row.is_dir { Icon::Folder } else { Icon::File };
                                let icon_col = if row.is_dir {
                                    tokens.warning
                                } else {
                                    node_color(row.flags, &row.name, row.depth)
                                };
                                ui_kit::icon_widget(&mut left_ui, item_icon, 13.0, icon_col);

                                let name_text = if is_selected {
                                    RichText::new(&row.name)
                                        .strong()
                                        .color(tokens.row_selected_text)
                                } else {
                                    RichText::new(&row.name).color(tokens.text_primary)
                                };
                                left_ui.add(egui::Label::new(name_text).truncate());

                                // Right-aligned stats in dedicated rect
                                let mut right_ui = ui.new_child(
                                    egui::UiBuilder::new()
                                        .max_rect(right_rect)
                                        .layout(egui::Layout::right_to_left(Align::Center)),
                                );
                                right_ui.set_clip_rect(right_rect.intersect(ui.clip_rect()));
                                right_ui.add_space(6.0);
                                right_ui.label(
                                    RichText::new(fmt_bytes(row.eff_bytes))
                                        .monospace()
                                        .strong()
                                        .size(12.0)
                                        .color(tokens.text_primary),
                                );

                                let share = if zoom_root_eff > 0 {
                                    row.eff_bytes as f32 / zoom_root_eff as f32
                                } else {
                                    0.0
                                };
                                let (bar_r, _) = right_ui
                                    .allocate_exact_size(Vec2::new(46.0, 6.0), Sense::hover());
                                ui_kit::inline_ratio_bar(
                                    right_ui.painter(),
                                    bar_r,
                                    share,
                                    if row.is_dir { tokens.accent } else { icon_col },
                                    tokens,
                                );

                                if row.is_dir && row.file_count > 0 {
                                    right_ui.label(
                                        RichText::new(format!("{}f", row.file_count))
                                            .size(10.5)
                                            .color(tokens.text_muted),
                                    );
                                }
                                if row.flags.contains(NodeFlags::CLOUD) {
                                    ui_kit::icon_widget(
                                        &mut right_ui,
                                        Icon::Cloud,
                                        12.0,
                                        tokens.info,
                                    );
                                }
                                if row.flags.contains(NodeFlags::REPARSE) {
                                    ui_kit::icon_widget(
                                        &mut right_ui,
                                        Icon::Link,
                                        12.0,
                                        tokens.purple,
                                    );
                                }
                                if row.flags.intersects(NodeFlags::COMPRESSED | NodeFlags::WOF) {
                                    ui_kit::icon_widget(
                                        &mut right_ui,
                                        Icon::Compressed,
                                        12.0,
                                        tokens.purple,
                                    );
                                }

                                if row_resp.clicked() {
                                    action_select = Some(node_id);
                                }
                                if row_resp.double_clicked() && row.is_dir {
                                    action_zoom = Some(node_id);
                                }

                                row_resp.context_menu(|ui| {
                                    render_shared_context_menu(ui, state, node_id);
                                });
                            }
                        });
                });
        });

        ui.add_space(gap);

        // Right Pane: Quick Inspector + Removable Findings + Extensions Breakdown
        ui.vertical(|ui| {
            ui.set_width(right_w);
            ScrollArea::vertical()
                .id_salt("explore_right_pane")
                .max_height(bottom_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // 1. Selected Item Quick-Inspector Card
                    if let Some(sel_id) = current_selected
                        && (sel_id as usize) < report.index.len()
                    {
                        let flags = report.index.flags(sel_id);
                        let is_dir = flags.contains(NodeFlags::DIR);
                        let name = report.index.name(sel_id).to_string();
                        let path = report.index.path(sel_id);
                        let path_str = path.display().to_string();
                        let eff = state.ledger.effective_bytes(&report.index, sel_id);
                        let pct = if zoom_root_eff > 0 {
                            (eff as f64 / zoom_root_eff as f64) * 100.0
                        } else {
                            0.0
                        };

                        ui_kit::card_frame(tokens)
                            .inner_margin(Margin::same(10))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                    ui_kit::pill_badge(
                                        ui,
                                        &format!("{} ({pct:.1}%)", fmt_bytes(eff)),
                                        tokens.accent,
                                        tokens,
                                    );
                                    ui.with_layout(
                                        egui::Layout::left_to_right(Align::Center),
                                        |ui| {
                                            ui_kit::icon_widget(
                                                ui,
                                                if is_dir { Icon::Folder } else { Icon::File },
                                                15.0,
                                                if is_dir {
                                                    tokens.warning
                                                } else {
                                                    tokens.accent
                                                },
                                            );
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&name)
                                                        .strong()
                                                        .color(tokens.text_primary),
                                                )
                                                .truncate(),
                                            );
                                        },
                                    );
                                });
                                ui.label(
                                    RichText::new(&path_str)
                                        .monospace()
                                        .size(11.0)
                                        .color(tokens.text_secondary),
                                );
                                ui.add_space(6.0);
                                ui.horizontal_wrapped(|ui| {
                                    if is_dir
                                        && sel_id != zoom_root_id
                                        && ui_kit::secondary_button(ui, "Zoom", true, tokens)
                                            .clicked()
                                    {
                                        action_zoom = Some(sel_id);
                                    }
                                    if ui_kit::secondary_button(ui, "Reveal", true, tokens)
                                        .clicked()
                                    {
                                        reveal_async(&path);
                                    }
                                    if ui_kit::secondary_button(ui, "Open", true, tokens).clicked()
                                    {
                                        open_async(&path);
                                    }
                                    if ui_kit::secondary_button(ui, "Copy", true, tokens).clicked()
                                    {
                                        ui.ctx().copy_text(path_str);
                                    }

                                    let recycle_action = (!state.heavy_busy())
                                        .then(|| state.prepare_recycle_confirm(sel_id))
                                        .flatten();
                                    match recycle_action {
                                        Some(
                                            confirm @ ConfirmAction::RecycleTarget {
                                                blocked_reason: None,
                                                ..
                                            },
                                        ) => {
                                            if ui_kit::danger_button(ui, "Recycle...", true, tokens)
                                                .clicked()
                                            {
                                                state.confirm_modal = Some(confirm);
                                            }
                                        }
                                        Some(ConfirmAction::RecycleTarget {
                                            blocked_reason: Some(reason),
                                            ..
                                        }) => {
                                            ui_kit::danger_button(ui, "Recycle...", false, tokens)
                                                .on_disabled_hover_text(reason);
                                        }
                                        _ => {
                                            ui_kit::danger_button(ui, "Recycle...", false, tokens)
                                                .on_disabled_hover_text(if state.heavy_busy() {
                                                    "Wait for the running job to finish"
                                                } else {
                                                    "Cannot recycle this item"
                                                });
                                        }
                                    }
                                });
                            });
                        ui.add_space(8.0);
                    }

                    // 2. Biggest removable findings
                    if let Some(nid) =
                        crate::views::reclaim::render_explore_findings(ui, state, tokens)
                    {
                        hunt_navigate = Some(nid);
                    }
                    if state.reclaim.is_some() {
                        ui.add_space(8.0);
                    }

                    // 3. Extensions Breakdown Panel
                    ui_kit::card_frame(tokens)
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui_kit::section_header(
                                ui,
                                "Extensions Breakdown",
                                Some("Click an extension to filter the tree."),
                                tokens,
                            );
                            ui.add_space(6.0);

                            if ext_breakdown.is_empty() {
                                ui.label(
                                    RichText::new("No files in current subtree.")
                                        .color(tokens.text_muted),
                                );
                            } else {
                                let segments: Vec<(f32, Color32, String)> = ext_breakdown
                                    .iter()
                                    .take(7)
                                    .map(|(ext, bytes, _)| {
                                        let sample = if ext.is_empty() {
                                            "file".to_string()
                                        } else {
                                            format!("x.{ext}")
                                        };
                                        let label = if ext.is_empty() {
                                            "<none>".to_string()
                                        } else {
                                            format!(".{ext}")
                                        };
                                        (
                                            *bytes as f32,
                                            node_color(NodeFlags::empty(), &sample, 1),
                                            label,
                                        )
                                    })
                                    .collect();
                                let seg_refs: Vec<(f32, Color32, &str)> = segments
                                    .iter()
                                    .map(|(v, c, l)| (*v, *c, l.as_str()))
                                    .collect();
                                ui_kit::segmented_bar(ui, &seg_refs, 8.0, tokens);
                                ui.add_space(8.0);

                                let zoom_eff =
                                    state.ledger.effective_bytes(&report.index, zoom_root_id);

                                egui::Grid::new("ext_breakdown_grid")
                                    .striped(true)
                                    .min_col_width(48.0)
                                    .spacing([10.0, 5.0])
                                    .show(ui, |ui| {
                                        ui.strong(
                                            RichText::new("Ext")
                                                .size(11.5)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Size")
                                                .size(11.5)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Files")
                                                .size(11.5)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Share")
                                                .size(11.5)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.end_row();

                                        for (ext, bytes, count) in &ext_breakdown {
                                            let ext_label = if ext.is_empty() {
                                                "<no ext>".to_string()
                                            } else {
                                                format!(".{ext}")
                                            };
                                            let sample = if ext.is_empty() {
                                                "file".to_string()
                                            } else {
                                                format!("x.{ext}")
                                            };
                                            let dot_col =
                                                node_color(NodeFlags::empty(), &sample, 1);

                                            let is_active_filter =
                                                state.explore_filter.ext_filter.as_deref()
                                                    == Some(ext.as_str());

                                            ui.horizontal(|ui| {
                                                let (dot, _) = ui.allocate_exact_size(
                                                    Vec2::splat(8.0),
                                                    Sense::hover(),
                                                );
                                                ui.painter().circle_filled(
                                                    dot.center(),
                                                    3.5,
                                                    dot_col,
                                                );
                                                let label_widget = if is_active_filter {
                                                    RichText::new(&ext_label)
                                                        .strong()
                                                        .color(tokens.accent)
                                                } else {
                                                    RichText::new(&ext_label)
                                                        .color(tokens.text_primary)
                                                };
                                                if ui
                                                    .selectable_label(
                                                        is_active_filter,
                                                        label_widget,
                                                    )
                                                    .clicked()
                                                {
                                                    action_ext_click = Some(ext.clone());
                                                }
                                            });

                                            ui.label(
                                                RichText::new(fmt_bytes(*bytes))
                                                    .monospace()
                                                    .strong()
                                                    .size(12.0),
                                            );
                                            ui.label(
                                                RichText::new(fmt_count(*count as u64))
                                                    .size(11.5)
                                                    .color(tokens.text_secondary),
                                            );

                                            let pct = if zoom_eff > 0 {
                                                (*bytes as f32 / zoom_eff as f32).clamp(0.0, 1.0)
                                            } else {
                                                0.0
                                            };
                                            ui.horizontal(|ui| {
                                                let (bar_r, _) = ui.allocate_exact_size(
                                                    Vec2::new(42.0, 6.0),
                                                    Sense::hover(),
                                                );
                                                ui_kit::inline_ratio_bar(
                                                    ui.painter(),
                                                    bar_r,
                                                    pct,
                                                    dot_col,
                                                    tokens,
                                                );
                                                ui.label(
                                                    RichText::new(format!("{:.1}%", pct * 100.0))
                                                        .size(11.0)
                                                        .color(tokens.text_secondary),
                                                );
                                            });

                                            ui.end_row();
                                        }
                                    });
                            }
                        });
                });
        });
    });

    if let Some(node_id) = action_toggle {
        state.tree_model.toggle_expanded(node_id);
        state.invalidate_explore_caches();
    }
    if let Some(node_id) = action_select {
        state.selected_node = Some(node_id);
    }
    if let Some(node_id) = action_zoom {
        state.zoom_into(node_id);
    }
    if let Some(node_id) = hunt_navigate {
        let target = state
            .scan_report
            .as_ref()
            .map(|r| {
                if r.index.flags(node_id).contains(NodeFlags::DIR) {
                    node_id
                } else {
                    r.index.parent(node_id)
                }
            })
            .unwrap_or(node_id);
        state.zoom_into(target);
        state.selected_node = Some(node_id);
    }
    if let Some(ext) = action_ext_click {
        if state.explore_filter.ext_filter.as_deref() == Some(&ext) {
            state.explore_filter.ext_filter = None;
        } else {
            state.explore_filter.ext_filter = Some(ext);
        }
        state.invalidate_explore_caches();
    }
}
