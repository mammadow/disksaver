//! History view: SQLite audit KPIs, runs history, and virtualized per-item deletion records.

#![forbid(unsafe_code)]

use eframe::egui::{self, Align, CornerRadius, Pos2, Rect, RichText, ScrollArea, Sense, Vec2};

use crate::app_state::AppState;
use crate::theme::{ThemeTokens, fmt_bytes, fmt_count, fmt_unix_timestamp};
use crate::ui_kit::{self, Icon};
use crate::worker::{WorkerHandle, WorkerJob};

/// State retained across frames for the history view search filter.
#[derive(Default)]
pub struct HistoryViewState {
    pub search_query: String,
    /// `(query, run id, entry count, matching entry indices)`: the lower-cased filter over a
    /// run's entries (which can be hundreds of thousands) is recomputed only when one changes.
    filter_cache: Option<(String, String, usize, Vec<usize>)>,
}

impl HistoryViewState {
    fn filtered_indices(
        &mut self,
        run_id: &str,
        entries: &[dsk_core::JournalEntryRecord],
    ) -> &[usize] {
        let q = self.search_query.trim().to_lowercase();
        let fresh = self
            .filter_cache
            .as_ref()
            .is_none_or(|(cq, cr, n, _)| *cq != q || cr != run_id || *n != entries.len());
        if fresh {
            let idx = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    q.is_empty()
                        || e.path.to_lowercase().contains(&q)
                        || e.rule_id.to_lowercase().contains(&q)
                        || e.status.to_lowercase().contains(&q)
                })
                .map(|(i, _)| i)
                .collect();
            self.filter_cache = Some((q, run_id.to_string(), entries.len(), idx));
        }
        self.filter_cache
            .as_ref()
            .map(|(_, _, _, v)| v.as_slice())
            .unwrap_or_default()
    }
}

/// First 8 characters of a run id (char-boundary safe).
fn short_id(id: &str) -> &str {
    id.char_indices().nth(8).map_or(id, |(i, _)| &id[..i])
}

/// Renders the History tab contents.
pub fn render(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &mut HistoryViewState,
    tokens: &ThemeTokens,
) {
    ui.add_space(4.0);

    // Header and Refresh Control
    ui.horizontal(|ui| {
        ui_kit::section_header(
            ui,
            "Audit History",
            Some("Persistent SQLite audit log of cleanups, simulations, and manual recycling."),
            tokens,
        );
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            let can_refresh = !state.is_loading_history;
            if ui_kit::secondary_button(ui, "Refresh History", can_refresh, tokens).clicked() {
                let job = WorkerJob::LoadHistory {
                    journal_path: state.journal_path.clone(),
                    limit: 100,
                    selected_run: state.selected_history_run_id.clone(),
                };
                state.spawn_job(worker, job);
            }
            if state.is_loading_history {
                ui.spinner();
                ui.label(RichText::new("Loading history...").color(tokens.info));
            }
        });
    });

    ui.add_space(10.0);

    if state.history_runs.is_empty() {
        if !state.is_loading_history {
            ui_kit::empty_state(
                ui,
                Icon::History,
                "No Audit Runs Recorded Yet",
                "Run a dry-run simulation, safe cleanup, or manual recycle to record an audit trail.",
                None,
                tokens,
            );
        }
        return;
    }

    // Top 4-Card KPI Summary Strip
    let total_runs = state.history_runs.len() as u64;
    let live_runs = state.history_runs.iter().filter(|r| !r.dry_run).count() as u64;
    let total_measured_freed: u64 = state
        .history_runs
        .iter()
        .filter(|r| !r.dry_run)
        .map(|r| r.freed_measured.max(0) as u64)
        .sum();
    let total_items: u64 = state.history_runs.iter().map(|r| r.items_ok).sum();

    ui.columns(4, |cols| {
        cols[0].vertical(|ui| {
            ui_kit::kpi_tile(
                ui,
                "Total Runs",
                &fmt_count(total_runs),
                None,
                tokens.info,
                tokens,
            );
        });
        cols[1].vertical(|ui| {
            ui_kit::kpi_tile(
                ui,
                "Live Cleanups",
                &fmt_count(live_runs),
                None,
                tokens.success,
                tokens,
            );
        });
        cols[2].vertical(|ui| {
            ui_kit::kpi_tile(
                ui,
                "Measured Freed",
                &fmt_bytes(total_measured_freed),
                None,
                tokens.accent,
                tokens,
            );
        });
        cols[3].vertical(|ui| {
            ui_kit::kpi_tile(
                ui,
                "Items Audited",
                &fmt_count(total_items),
                None,
                tokens.purple,
                tokens,
            );
        });
    });

    ui.add_space(10.0);

    let mut select_run: Option<String> = None;
    let body_h = ui.available_height().max(200.0);
    let total_w = ui.available_width().max(520.0);
    let gap = 10.0;
    let left_w = ((total_w - gap) * 0.46).clamp(240.0, (total_w - 240.0).max(240.0));
    let right_w = (total_w - gap - left_w).max(220.0);

    ui.horizontal_top(|ui| {
        // Left Pane: Runs Table
        ui.vertical(|ui| {
            ui.set_width(left_w);
            ui.set_min_height(body_h);
            ui_kit::card_frame(tokens)
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.strong(format!("Recent Runs ({})", state.history_runs.len()));
                    ui.add_space(6.0);

                    ScrollArea::both()
                        .id_salt("history_runs_scroll")
                        .max_height((body_h - 46.0).max(80.0))
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            egui::Grid::new("history_runs_grid")
                                .striped(true)
                                .min_col_width(48.0)
                                .spacing([10.0, 6.0])
                                .show(ui, |ui| {
                                    ui.strong(
                                        RichText::new("Run")
                                            .size(11.5)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Mode")
                                            .size(11.5)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Started (UTC)")
                                            .size(11.5)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Vol")
                                            .size(11.5)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Meas / Est")
                                            .size(11.5)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Items")
                                            .size(11.5)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.end_row();

                                    for run in &state.history_runs {
                                        let is_selected = state.selected_history_run_id.as_deref()
                                            == Some(&run.run_id);

                                        let sid = short_id(&run.run_id);
                                        let id_label = if is_selected {
                                            RichText::new(sid)
                                                .monospace()
                                                .strong()
                                                .color(tokens.accent)
                                        } else {
                                            RichText::new(sid)
                                                .monospace()
                                                .color(tokens.text_primary)
                                        };

                                        if ui.selectable_label(is_selected, id_label).clicked()
                                            && !is_selected
                                        {
                                            select_run = Some(run.run_id.clone());
                                        }

                                        if run.dry_run {
                                            ui_kit::pill_badge(ui, "dry-run", tokens.info, tokens);
                                        } else {
                                            ui_kit::pill_badge(ui, "live", tokens.success, tokens);
                                        }

                                        ui.label(
                                            RichText::new(fmt_unix_timestamp(run.started_at_unix))
                                                .monospace()
                                                .size(11.0)
                                                .color(tokens.text_secondary),
                                        );

                                        ui_kit::pill_badge(
                                            ui,
                                            &run.volume,
                                            tokens.text_secondary,
                                            tokens,
                                        );

                                        let meas = fmt_bytes(run.freed_measured.max(0) as u64);
                                        let est = fmt_bytes(run.est_bytes);
                                        ui.label(
                                            RichText::new(format!("{meas} / {est}"))
                                                .monospace()
                                                .size(11.5)
                                                .strong(),
                                        );

                                        ui.label(
                                            RichText::new(fmt_count(run.items_ok))
                                                .monospace()
                                                .size(11.5),
                                        );

                                        ui.end_row();
                                    }
                                });
                        });
                });
        });

        ui.add_space(gap);

        // Right Pane: Selected Run Items Audit Table
        ui.vertical(|ui| {
            ui.set_width(right_w);
            ui.set_min_height(body_h);
            ui_kit::card_frame(tokens)
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.strong("Run Item Details");
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut view_state.search_query)
                                    .desired_width(150.0)
                                    .hint_text("Filter items..."),
                            );
                            ui_kit::icon_widget(ui, Icon::Search, 13.0, tokens.text_secondary);
                        });
                    });
                    ui.add_space(4.0);

                    if let Some(ref run_id) = state.selected_history_run_id {
                        let filtered = view_state.filtered_indices(run_id, &state.history_entries);

                        ui.label(
                            RichText::new(format!(
                                "Showing {} items for run {}",
                                fmt_count(filtered.len() as u64),
                                short_id(run_id)
                            ))
                            .size(11.5)
                            .color(tokens.text_secondary),
                        );
                        ui.add_space(4.0);

                        let row_h = 26.0;
                        ScrollArea::vertical()
                            .id_salt("history_entries_scroll")
                            .max_height((body_h - 68.0).max(80.0))
                            .auto_shrink([false, false])
                            .show_rows(ui, row_h, filtered.len(), |ui, range| {
                                for (local_idx, &i) in filtered[range].iter().enumerate() {
                                    let entry = &state.history_entries[i];
                                    let (row_rect, row_resp) = ui.allocate_exact_size(
                                        Vec2::new(ui.available_width(), row_h),
                                        Sense::hover(),
                                    );
                                    if local_idx % 2 == 1 {
                                        ui.painter().rect_filled(
                                            row_rect,
                                            CornerRadius::same(4),
                                            tokens.row_alt,
                                        );
                                    }

                                    let right_w = (row_rect.width() * 0.45).clamp(170.0, 270.0);
                                    let split_x =
                                        (row_rect.max.x - right_w - 6.0).max(row_rect.min.x + 80.0);
                                    let left_rect = Rect::from_min_max(
                                        Pos2::new(row_rect.min.x + 6.0, row_rect.min.y),
                                        Pos2::new(split_x, row_rect.max.y),
                                    );
                                    let right_rect = Rect::from_min_max(
                                        Pos2::new(split_x + 6.0, row_rect.min.y),
                                        Pos2::new(row_rect.max.x - 6.0, row_rect.max.y),
                                    );

                                    let mut left_ui = ui.new_child(
                                        egui::UiBuilder::new()
                                            .max_rect(left_rect)
                                            .layout(egui::Layout::left_to_right(Align::Center)),
                                    );
                                    left_ui.set_clip_rect(left_rect.intersect(ui.clip_rect()));
                                    left_ui.add(
                                        egui::Label::new(
                                            RichText::new(&entry.path)
                                                .size(11.5)
                                                .color(tokens.text_primary),
                                        )
                                        .truncate(),
                                    );

                                    let mut right_ui = ui.new_child(
                                        egui::UiBuilder::new()
                                            .max_rect(right_rect)
                                            .layout(egui::Layout::right_to_left(Align::Center)),
                                    );
                                    right_ui.set_clip_rect(right_rect.intersect(ui.clip_rect()));
                                    let status_col = match entry.status.as_str() {
                                        "deleted" | "recycled" | "simulated" => tokens.success,
                                        "failed" | "error" => tokens.danger,
                                        _ => tokens.text_secondary,
                                    };
                                    ui_kit::pill_badge(
                                        &mut right_ui,
                                        &entry.status,
                                        status_col,
                                        tokens,
                                    );
                                    right_ui.label(
                                        RichText::new(fmt_bytes(entry.size_bytes))
                                            .monospace()
                                            .strong()
                                            .size(11.5),
                                    );
                                    ui_kit::pill_badge(
                                        &mut right_ui,
                                        &entry.rule_id,
                                        tokens.text_secondary,
                                        tokens,
                                    );

                                    row_resp.on_hover_text(&entry.path);
                                }
                            });
                    } else {
                        ui.add_space(16.0);
                        ui.label(
                            RichText::new(
                                "Select a run from the left to inspect item audit entries.",
                            )
                            .color(tokens.text_muted),
                        );
                    }
                });
        });
    });

    if let Some(run_id) = select_run {
        // Drop the previous run's rows immediately instead of showing them under the new id.
        state.selected_history_run_id = Some(run_id.clone());
        state.history_entries.clear();
        let job = WorkerJob::LoadHistory {
            journal_path: state.journal_path.clone(),
            limit: 100,
            selected_run: Some(run_id),
        };
        state.spawn_job(worker, job);
    }
}
