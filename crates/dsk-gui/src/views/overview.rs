//! Overview view: mounted drive rings, Find Space ledger, scan telemetry, safe cleanup CTA,
//! top largest folders, and 24h/7d folder growth tracking.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use dsk_core::ledger::Lane;
use dsk_core::{GrowthWindow, ROOT, ScanMethod, volume_root_of};
use eframe::egui::{self, Align, RichText, ScrollArea, Sense, Stroke, Vec2};

use crate::app_state::{ActiveTab, AppState};
use crate::theme::{ThemeTokens, fmt_bytes, fmt_count, fmt_signed_bytes, tint_on};
use crate::ui_kit::{self, Icon};
use crate::views::reclaim::ReclaimJump;
use crate::worker::{WorkerHandle, WorkerJob};

/// Renders the Overview tab contents. Returns an optional [`ReclaimJump`] when a user clicks an
/// action or folder jump.
pub fn render(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    is_elevated: bool,
    tokens: &ThemeTokens,
    selected_lane: &mut Option<Lane>,
) -> Option<ReclaimJump> {
    let _ = is_elevated;
    let mut jump_to: Option<ReclaimJump> = None;

    ScrollArea::vertical().show(ui, |ui| {
        ui.add_space(4.0);

        // Section 1: Mounted Drives
        ui.horizontal(|ui| {
            ui_kit::icon_widget(ui, Icon::Drive, 17.0, tokens.accent);
            ui_kit::section_header(ui, "Mounted Drives", None, tokens);
            ui.add_space(12.0);
            ui.checkbox(
                &mut state.scan_use_cache,
                "Use USN Cache (fast incremental rescan)",
            )
            .on_hover_text(
                "Uses zstd-compressed .dsi snapshots and NTFS USN journal deltas when available; uncheck for a full rescan.",
            );
        });
        ui.add_space(8.0);

        let use_cache = state.scan_use_cache;
        let can_scan = !state.heavy_busy();
        let mut scan_request = None;

        if state.volumes.is_empty() {
            let msg = if state.is_refreshing_drives {
                "Detecting mounted volumes..."
            } else {
                "No mounted volumes detected."
            };
            ui_kit::card_frame(tokens).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    if state.is_refreshing_drives {
                        ui.spinner();
                    }
                    ui.label(RichText::new(msg).color(tokens.text_secondary));
                });
            });
        } else {
            ui.with_layout(
                egui::Layout::left_to_right(Align::TOP).with_main_wrap(true),
                |ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(12.0, 12.0);
                    for vol in &state.volumes {
                        let is_selected = state
                            .selected_volume
                            .as_ref()
                            .is_some_and(|v| v.root == vol.root);
                        let (clicked, _, _) = render_drive_card(
                            ui,
                            vol,
                            is_selected,
                            state.scan_report.is_some(),
                            can_scan,
                            tokens,
                        );
                        if clicked {
                            scan_request = Some(vol.clone());
                        }
                    }
                },
            );
        }

        if let Some(vol) = scan_request {
            let job = WorkerJob::ScanTarget {
                path: PathBuf::from(&vol.root),
                method: ScanMethod::Auto,
                use_helper: state.helper_connected,
                use_cache,
                growth_db_path: state.growth_db_path.clone(),
            };
            state.selected_volume = Some(vol);
            state.spawn_job(worker, job);
        }

        ui.add_space(14.0);

        // Section 2: Find Space (reclaim ledger + disk hunt)
        if let Some(jump) =
            crate::views::reclaim::render_overview_panel(ui, state, worker, tokens, selected_lane)
        {
            jump_to = Some(jump);
        }

        ui.add_space(14.0);

        // Section 3: Scan Telemetry & Safe Cleanup Summary (2 equal columns)
        let active_report = state.scan_report.clone();
        let effective_plan = state.effective_plan_shared();

        ui.columns(2, |cols| {
            // Left Card: Scan Telemetry
            cols[0].vertical(|ui| {
                ui_kit::card_frame(tokens).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.set_min_height(225.0);
                    ui.horizontal(|ui| {
                        ui_kit::section_header(ui, "Current Scan Telemetry", None, tokens);
                        if let Some(ref report) = active_report {
                            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                match report.method_used {
                                    ScanMethod::UsnIncremental => {
                                        ui_kit::pill_badge(
                                            ui,
                                            "Instant USN Rescan",
                                            tokens.success,
                                            tokens,
                                        );
                                        ui_kit::icon_widget(ui, Icon::Bolt, 14.0, tokens.success);
                                    }
                                    other => {
                                        ui_kit::pill_badge(
                                            ui,
                                            &format!("{other:?}"),
                                            tokens.info,
                                            tokens,
                                        );
                                    }
                                }
                            });
                        }
                    });
                    ui.add_space(8.0);

                    if let Some(ref report) = active_report {
                        let total_alloc = report.index.total_allocated(ROOT);
                        let root_path_str = report
                            .index
                            .path(ROOT)
                            .display()
                            .to_string()
                            .trim_start_matches(r"\\?\")
                            .to_string();

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Target:")
                                    .size(12.0)
                                    .color(tokens.text_secondary),
                            );
                            ui.label(
                                RichText::new(&root_path_str)
                                    .monospace()
                                    .strong()
                                    .color(tokens.text_primary),
                            );
                        });
                        if let Some(ref reason) = report.fallback_reason {
                            ui.label(
                                RichText::new(reason)
                                    .size(11.5)
                                    .color(tokens.warning),
                            );
                        }
                        ui.add_space(8.0);

                        ui.columns(2, |kpis| {
                            kpis[0].vertical(|ui| {
                                ui_kit::kpi_tile(
                                    ui,
                                    "Total Allocated",
                                    &fmt_bytes(total_alloc),
                                    None,
                                    tokens.accent,
                                    tokens,
                                );
                                ui.add_space(6.0);
                                ui_kit::kpi_tile(
                                    ui,
                                    "Total Nodes",
                                    &fmt_count(report.index.len() as u64),
                                    None,
                                    tokens.purple,
                                    tokens,
                                );
                            });
                            kpis[1].vertical(|ui| {
                                ui_kit::kpi_tile(
                                    ui,
                                    "Indexed Files",
                                    &fmt_count(report.index.file_count(ROOT) as u64),
                                    None,
                                    tokens.info,
                                    tokens,
                                );
                                ui.add_space(6.0);
                                ui_kit::kpi_tile(
                                    ui,
                                    "Elapsed Time",
                                    &format!("{:.2} s", report.elapsed.as_secs_f64()),
                                    None,
                                    tokens.success,
                                    tokens,
                                );
                            });
                        });
                    } else if state.is_scanning {
                        ui.label(
                            RichText::new("Scan in progress...")
                                .strong()
                                .color(tokens.info),
                        );
                        ui.add_space(6.0);
                        if let Some((phase, done, total)) = state.scan_progress {
                            let ratio = if total > 0 {
                                (done as f32 / total as f32).clamp(0.0, 1.0)
                            } else {
                                0.0
                            };
                            ui_kit::progress_bar(
                                ui,
                                ratio,
                                10.0,
                                tokens.info,
                                Some(&format!("{phase:?}: {done} / {total}")),
                                tokens,
                            );
                        }
                    } else {
                        ui.add_space(12.0);
                        ui.label(
                            RichText::new("Select a drive above to inspect disk usage and file telemetry.")
                                .color(tokens.text_secondary),
                        );
                    }
                });
            });

            // Right Card: Safe Cleanup Summary CTA
            cols[1].vertical(|ui| {
                ui_kit::card_frame(tokens).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.set_min_height(225.0);
                    ui.horizontal(|ui| {
                        ui_kit::icon_widget(ui, Icon::Cleanup, 17.0, tokens.success);
                        ui_kit::section_header(ui, "Safe Reclaimable Summary", None, tokens);
                    });
                    ui.add_space(10.0);

                    if let Some(effective) = effective_plan.as_deref() {
                        let total_bytes = effective.total_est_bytes;
                        let rules_count = effective.rules.len();

                        ui.label(
                            RichText::new(fmt_bytes(total_bytes))
                                .size(26.0)
                                .strong()
                                .color(tokens.success),
                        );
                        ui.label(
                            RichText::new("Safe temporary and cache files ready to clean")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.add_space(10.0);

                        ui.horizontal_wrapped(|ui| {
                            ui_kit::pill_badge(
                                ui,
                                &format!("{rules_count} active rules"),
                                tokens.info,
                                tokens,
                            );
                            if !effective.skipped.is_empty() {
                                ui_kit::pill_badge(
                                    ui,
                                    &format!("{} skipped / locked", effective.skipped.len()),
                                    tokens.warning,
                                    tokens,
                                );
                            }
                        });

                        ui.add_space(14.0);
                        if ui_kit::primary_button(ui, "Review Safe Cleanup →", true, tokens)
                            .clicked()
                        {
                            state.active_tab = ActiveTab::Cleanup;
                        }
                    } else if state.is_scanning {
                        ui.label(
                            RichText::new("Cleanup plan will be built automatically once the scan finishes.")
                                .color(tokens.text_secondary),
                        );
                    } else if state.is_planning {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(
                                RichText::new("Building safe cleanup plan...")
                                    .color(tokens.info),
                            );
                        });
                    } else {
                        ui.add_space(12.0);
                        ui.label(
                            RichText::new(
                                "Scan a drive to evaluate curated developer, browser, and OS cache rules.",
                            )
                            .color(tokens.text_secondary),
                        );
                    }
                });
            });
        });

        ui.add_space(14.0);

        // Section 4: Top 10 Largest Folders Quick-Jump into Explore
        ui_kit::card_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui_kit::section_header(
                ui,
                "Top Largest Folders",
                Some("Largest subdirectories under the scanned root. Click Explore to zoom in."),
                tokens,
            );
            ui.add_space(8.0);

            if let Some(ref report) = active_report {
                let top_folder_ids = state.top_dirs_cached();
                if top_folder_ids.is_empty() {
                    ui.label(
                        RichText::new("No large subdirectories discovered.")
                            .color(tokens.text_muted),
                    );
                } else {
                    let max_eff = top_folder_ids
                        .iter()
                        .map(|&nid| state.ledger.effective_bytes(&report.index, nid))
                        .max()
                        .unwrap_or(1)
                        .max(1);

                    let mut navigate_to = None;
                    ScrollArea::horizontal()
                        .id_salt("top_folders_hscroll")
                        .show(ui, |ui| {
                            egui::Grid::new("top_folders_grid")
                                .striped(true)
                                .min_col_width(72.0)
                                .spacing([14.0, 6.0])
                                .show(ui, |ui| {
                                    ui.strong(
                                        RichText::new("Folder")
                                            .size(12.0)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Path")
                                            .size(12.0)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Share")
                                            .size(12.0)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong(
                                        RichText::new("Size")
                                            .size(12.0)
                                            .color(tokens.text_secondary),
                                    );
                                    ui.strong("");
                                    ui.end_row();

                                    for nid in top_folder_ids {
                                        let name = report.index.name(nid);
                                        let path_str = report.index.path(nid).display().to_string();
                                        let short_path = truncate_middle(&path_str, 52);
                                        let eff = state.ledger.effective_bytes(&report.index, nid);
                                        let share = eff as f32 / max_eff as f32;

                                        ui.horizontal(|ui| {
                                            ui_kit::icon_widget(
                                                ui,
                                                Icon::Folder,
                                                14.0,
                                                tokens.warning,
                                            );
                                            ui.label(RichText::new(&*name).strong());
                                        });
                                        ui.label(
                                            RichText::new(short_path)
                                                .color(tokens.text_secondary)
                                                .size(12.0),
                                        )
                                        .on_hover_text(&path_str);
                                        let (bar_rect, _) = ui.allocate_exact_size(
                                            Vec2::new(110.0, 8.0),
                                            Sense::hover(),
                                        );
                                        ui_kit::inline_ratio_bar(
                                            ui.painter(),
                                            bar_rect,
                                            share,
                                            tokens.accent,
                                            tokens,
                                        );
                                        ui.label(
                                            RichText::new(fmt_bytes(eff))
                                                .monospace()
                                                .strong()
                                                .color(tokens.text_primary),
                                        );
                                        if ui_kit::secondary_button(ui, "Explore →", true, tokens)
                                            .clicked()
                                        {
                                            navigate_to = Some(nid);
                                        }
                                        ui.end_row();
                                    }
                                });
                        });
                    if let Some(nid) = navigate_to {
                        jump_to = Some(ReclaimJump::Explore(nid));
                    }
                }
            } else {
                ui.label(
                    RichText::new("Scan a drive to display top largest folders.")
                        .color(tokens.text_muted),
                );
            }
        });

        ui.add_space(14.0);

        // Section 5: What Grew (24h / 7d Rollup Deltas & Runaway Alerts)
        let active_vol_root = active_report
            .as_ref()
            .and_then(|r| volume_root_of(&r.index.path(ROOT)))
            .or_else(|| state.selected_volume.as_ref().map(|v| v.root.clone()))
            .or_else(|| state.volumes.first().map(|v| v.root.clone()));

        ui_kit::card_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui_kit::section_header(
                    ui,
                    "What Grew",
                    Some("Compares cached folder rollups across scans (>= 5 GiB/day triggers a runaway alert)."),
                    tokens,
                );
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    let refresh_clicked = ui_kit::secondary_button(
                        ui,
                        if state.is_loading_growth {
                            "Loading..."
                        } else {
                            "Refresh"
                        },
                        active_vol_root.is_some() && !state.is_loading_growth,
                        tokens,
                    )
                    .clicked();

                    let prev_window = state.growth_window;
                    if ui_kit::chip_toggle(
                        ui,
                        state.growth_window == GrowthWindow::D7,
                        "7d",
                        None,
                        tokens,
                    )
                    .clicked()
                    {
                        state.growth_window = GrowthWindow::D7;
                    }
                    if ui_kit::chip_toggle(
                        ui,
                        state.growth_window == GrowthWindow::H24,
                        "24h",
                        None,
                        tokens,
                    )
                    .clicked()
                    {
                        state.growth_window = GrowthWindow::H24;
                    }

                    if (state.growth_window != prev_window || refresh_clicked)
                        && let Some(ref vol_root) = active_vol_root
                    {
                        let job = WorkerJob::LoadGrowth {
                            volume_root: vol_root.clone(),
                            window: state.growth_window,
                            db_path: state.growth_db_path.clone(),
                        };
                        state.spawn_job(worker, job);
                    }
                });
            });
            ui.add_space(8.0);

            let mut growth_nav_path: Option<String> = None;
            if let Some(ref rep) = state.growth_report {
                if !rep.has_baseline {
                    ui.label(
                        RichText::new(
                            "No prior baseline snapshot found for this window yet. Scan the drive again later to inspect folder growth.",
                        )
                        .color(tokens.text_muted),
                    );
                } else {
                    if !rep.runaways.is_empty() {
                        ui_kit::callout_banner(
                            ui,
                            tokens,
                            tokens.danger,
                            Icon::Warning,
                            &format!(
                                "Runaway Growth Alert: {} folder(s) exceeded 5 GiB/day in the {} window.",
                                rep.runaways.len(),
                                rep.window
                            ),
                            None,
                            false,
                        );
                        ui.add_space(8.0);
                    }

                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Volume Net Change:")
                                .color(tokens.text_secondary),
                        );
                        let delta_col = if rep.volume_delta_bytes > 0 {
                            tokens.danger
                        } else {
                            tokens.success
                        };
                        ui_kit::pill_badge(
                            ui,
                            &fmt_signed_bytes(rep.volume_delta_bytes),
                            delta_col,
                            tokens,
                        );
                    });
                    ui.add_space(6.0);

                    if rep.entries.is_empty() {
                        ui.label(
                            RichText::new("No folder deltas >= 10 MiB recorded in this window.")
                                .color(tokens.text_muted),
                        );
                    } else {
                        ScrollArea::horizontal()
                            .id_salt("what_grew_hscroll")
                            .show(ui, |ui| {
                                egui::Grid::new("what_grew_grid")
                                    .striped(true)
                                    .min_col_width(72.0)
                                    .spacing([12.0, 6.0])
                                    .show(ui, |ui| {
                                        ui.strong(
                                            RichText::new("Path")
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Delta")
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Rate / Day")
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Current")
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Previous")
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong(
                                            RichText::new("Status")
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                        );
                                        ui.strong("");
                                        ui.end_row();

                                        for entry in &rep.entries {
                                            let short_path = truncate_middle(&entry.path, 48);
                                            ui.label(
                                                RichText::new(short_path)
                                                    .size(12.0)
                                                    .color(tokens.text_primary),
                                            )
                                            .on_hover_text(&entry.path);
                                            ui.label(
                                                RichText::new(fmt_signed_bytes(entry.delta_bytes))
                                                    .monospace()
                                                    .strong()
                                                    .color(if entry.delta_bytes > 0 {
                                                        tokens.danger
                                                    } else {
                                                        tokens.success
                                                    }),
                                            );
                                            ui.label(
                                                RichText::new(format!(
                                                    "{}/d",
                                                    fmt_signed_bytes(entry.rate_bytes_per_day)
                                                ))
                                                .monospace()
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                            );
                                            ui.label(
                                                RichText::new(fmt_bytes(entry.current_bytes))
                                                    .monospace()
                                                    .size(12.0),
                                            );
                                            ui.label(
                                                RichText::new(fmt_bytes(entry.previous_bytes))
                                                    .monospace()
                                                    .size(12.0)
                                                    .color(tokens.text_secondary),
                                            );
                                            if entry.runaway {
                                                ui_kit::pill_badge(
                                                    ui,
                                                    "RUNAWAY",
                                                    tokens.danger,
                                                    tokens,
                                                );
                                            } else {
                                                ui_kit::dot_badge(
                                                    ui,
                                                    "Normal",
                                                    tokens.text_muted,
                                                    tokens,
                                                );
                                            }

                                            let can_explore = active_report
                                                .as_ref()
                                                .and_then(|r| {
                                                    r.index.find_by_path(Path::new(&entry.path))
                                                })
                                                .is_some();
                                            if ui_kit::secondary_button(
                                                ui,
                                                "Explore →",
                                                can_explore,
                                                tokens,
                                            )
                                            .clicked()
                                            {
                                                growth_nav_path = Some(entry.path.clone());
                                            }
                                            ui.end_row();
                                        }
                                    });
                            });
                    }
                }
            } else {
                ui.label(
                    RichText::new("Scan a drive to inspect 24h / 7d folder growth deltas.")
                        .color(tokens.text_muted),
                );
            }

            if let Some(target_path) = growth_nav_path
                && let Some(ref rep) = active_report
                && let Some(nid) = rep.index.find_by_path(Path::new(&target_path))
            {
                jump_to = Some(ReclaimJump::Explore(nid));
            }
        });

        ui.add_space(8.0);
    });

    jump_to
}

fn truncate_middle(s: &str, max_chars: usize) -> String {
    let total = s.chars().count();
    if total <= max_chars || max_chars < 8 {
        return s.to_string();
    }
    let head_len = (max_chars - 1) / 3;
    let tail_len = max_chars - 1 - head_len;
    let head: String = s.chars().take(head_len).collect();
    let tail: String = s.chars().skip(total - tail_len).collect();
    format!("{head}…{tail}")
}

fn render_drive_card(
    ui: &mut egui::Ui,
    vol: &dsk_core::VolumeInfo,
    is_selected: bool,
    has_report: bool,
    can_scan: bool,
    tokens: &ThemeTokens,
) -> (bool, egui::Rect, egui::Rect) {
    let total = vol.total_bytes;
    let free = vol.free_bytes;
    let used = total.saturating_sub(free);
    let ratio = if total > 0 {
        (used as f32 / total as f32).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let frame = if is_selected {
        ui_kit::card_frame(tokens)
            .fill(tint_on(
                tokens.card_bg,
                tokens.accent,
                if tokens.is_dark { 0.08 } else { 0.05 },
            ))
            .stroke(Stroke::new(1.5, tokens.accent))
    } else {
        ui_kit::card_frame(tokens)
    };

    let mut clicked = false;
    let mut btn_rect = egui::Rect::NOTHING;
    let card_resp = frame.show(ui, |ui| {
        // Explicit vertical container resets outer horizontal_wrapped layout inheritance.
        ui.vertical(|ui| {
            ui.set_width(268.0);
            let display_root = vol.root.trim_start_matches(r"\\?\");
            let health_col = tokens.health_color(ratio);

            ui.horizontal(|ui| {
                ui_kit::storage_ring(
                    ui,
                    ratio,
                    &format!("{:.0}%", ratio * 100.0),
                    "used",
                    64.0,
                    health_col,
                    tokens,
                );
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(display_root)
                                .size(17.0)
                                .strong()
                                .color(tokens.text_primary),
                        );
                        ui_kit::pill_badge(ui, &vol.fs_name, tokens.text_secondary, tokens);
                        if vol.seek_penalty == Some(false) {
                            ui_kit::pill_badge(ui, "SSD", tokens.success, tokens);
                        } else if vol.seek_penalty == Some(true) {
                            ui_kit::pill_badge(ui, "HDD", tokens.warning, tokens);
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("{} free", fmt_bytes(free)))
                            .size(13.0)
                            .strong()
                            .color(tokens.text_primary),
                    );
                    ui.label(
                        RichText::new(format!("{} used of {}", fmt_bytes(used), fmt_bytes(total)))
                            .size(11.5)
                            .color(tokens.text_secondary),
                    );
                });
            });

            ui.add_space(10.0);
            let btn_label = if is_selected && has_report {
                "Rescan Drive"
            } else {
                "Scan Drive"
            };
            ui.with_layout(egui::Layout::top_down_justified(Align::Center), |ui| {
                let resp = ui_kit::primary_button(ui, btn_label, can_scan, tokens)
                    .on_disabled_hover_text("Wait for the running job to finish");
                btn_rect = resp.rect;
                if resp.clicked() {
                    clicked = true;
                }
            });
        });
    });

    (clicked, card_resp.response.rect, btn_rect)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol(root: &str) -> dsk_core::VolumeInfo {
        dsk_core::VolumeInfo {
            root: root.to_string(),
            fs_name: "NTFS".to_string(),
            total_bytes: 1_000_000_000_000,
            free_bytes: 120_000_000_000,
            seek_penalty: Some(false),
            ..Default::default()
        }
    }

    #[test]
    fn mounted_drive_cards_align_at_top_and_scan_button_is_single_line() {
        let ctx = egui::Context::default();
        let tokens = ThemeTokens::dark();
        let vols = [vol(r"C:\"), vol(r"D:\")];
        let mut c1 = egui::Rect::NOTHING;
        let mut c2 = egui::Rect::NOTHING;
        let mut b1 = egui::Rect::NOTHING;
        let mut b2 = egui::Rect::NOTHING;

        let out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(1000.0, 700.0),
                )),
                ..Default::default()
            },
            |ui| {
                ui.with_layout(
                    egui::Layout::left_to_right(Align::TOP).with_main_wrap(true),
                    |ui| {
                        ui.spacing_mut().item_spacing = Vec2::new(12.0, 12.0);
                        let r1 = render_drive_card(ui, &vols[0], true, false, true, &tokens);
                        c1 = r1.1;
                        b1 = r1.2;
                        let r2 = render_drive_card(ui, &vols[1], false, false, true, &tokens);
                        c2 = r2.1;
                        b2 = r2.2;
                    },
                );
            },
        );
        out.drop_without_applying_deltas();

        assert!(
            (c1.min.y - c2.min.y).abs() <= 1.0,
            "cards should share top baseline: c1={c1:?}, c2={c2:?}"
        );
        assert!(
            b1.width() >= 220.0 && b1.height() <= 36.0,
            "Scan Drive button should span full card width on one line: b1={b1:?}"
        );
        assert!(
            b2.width() >= 220.0 && b2.height() <= 36.0,
            "Scan Drive button should span full card width on one line: b2={b2:?}"
        );
    }
}
