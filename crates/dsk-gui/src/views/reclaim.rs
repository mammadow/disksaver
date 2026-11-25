//! "Find space" panels (P9.1 ledger, P9.10 hunt): the Overview headline and opportunity list,
//! and the Explore "Removable" color mode with its biggest-findings list.
//!
//! Read-only: every row shows a direct jump into the corresponding GUI workflow (or CLI hint copy),
//! and paths open in Explore. Mutating actions stay in their dedicated tabs with confirmations.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use dsk_core::NodeId;
use dsk_core::clean::RuleTier;
use dsk_core::hunt::FindingKind;
use dsk_core::ledger::{ActionRef, Lane, Opportunity};
use dsk_core::optimize::WofAlgorithm;
use eframe::egui::{self, Align, Color32, RichText, Sense, Vec2};

use crate::app_state::{ActiveTab, AppState};
use crate::theme::{ThemeTokens, fmt_bytes, verdict_color, verdict_legend};
use crate::ui_kit::{self, Icon};
use crate::worker::{WorkerHandle, WorkerJob};

/// Structured in-app navigation target derived from an [`Opportunity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReclaimJump {
    Explore(NodeId),
    CleanupRule { rule_id: String, tier: RuleTier },
    Optimize,
    OptimizeWof { folder: PathBuf, algo: WofAlgorithm },
    InsightsDuplicates,
    InsightsGames { filter: String },
    InsightsColdApps { filter: String },
    InsightsProjects,
    Videos,
}

fn lane_color(l: Lane, tokens: &ThemeTokens) -> Color32 {
    match l {
        Lane::Invisible => tokens.success,
        Lane::Sizing => tokens.info,
        Lane::Regenerable => {
            if tokens.is_dark {
                Color32::from_rgb(163, 230, 53)
            } else {
                Color32::from_rgb(77, 124, 15)
            }
        }
        Lane::Leftover => tokens.warning,
        Lane::Decision => tokens.purple,
    }
}

fn node_for(state: &AppState, path: &Path) -> Option<NodeId> {
    state.scan_report.as_ref()?.index.find_by_path(path)
}

/// Maps a ledger [`Opportunity`] to a direct in-app GUI destination when available.
pub fn jump_for_opportunity(state: &AppState, opp: &Opportunity) -> Option<ReclaimJump> {
    match &opp.action {
        ActionRef::CleanRule { rule_id, tier } => Some(ReclaimJump::CleanupRule {
            rule_id: rule_id.clone(),
            tier: *tier,
        }),
        ActionRef::Optimizer { .. } | ActionRef::CompactVhdx { .. } => Some(ReclaimJump::Optimize),
        ActionRef::CompressFolder { path, algorithm } => Some(ReclaimJump::OptimizeWof {
            folder: path.clone(),
            algo: *algorithm,
        }),
        ActionRef::DupeGroup { .. } => Some(ReclaimJump::InsightsDuplicates),
        ActionRef::LauncherGame { title, .. } => Some(ReclaimJump::InsightsGames {
            filter: title.clone(),
        }),
        ActionRef::UninstallApp { name } => Some(ReclaimJump::InsightsColdApps {
            filter: name.clone(),
        }),
        ActionRef::CompressVideo { .. } => Some(ReclaimJump::Videos),
        ActionRef::RecyclePath { path } => node_for(state, path)
            .or_else(|| path.parent().and_then(|p| node_for(state, p)))
            .map(ReclaimJump::Explore),
        ActionRef::SweepBuildOutput { root } => node_for(state, root)
            .or_else(|| root.parent().and_then(|p| node_for(state, p)))
            .map(ReclaimJump::Explore)
            .or(Some(ReclaimJump::InsightsProjects)),
        ActionRef::None => opp
            .path
            .as_deref()
            .and_then(|p| {
                node_for(state, p).or_else(|| p.parent().and_then(|par| node_for(state, par)))
            })
            .map(ReclaimJump::Explore),
    }
}

fn action_jump_label(jump: &ReclaimJump) -> &'static str {
    match jump {
        ReclaimJump::Explore(_) => "Explore →",
        ReclaimJump::CleanupRule { .. } => "Open in Cleanup",
        ReclaimJump::Optimize => "Open Optimize",
        ReclaimJump::OptimizeWof { .. } => "Compress →",
        ReclaimJump::InsightsDuplicates => "View Dupes",
        ReclaimJump::InsightsGames { .. } => "View Games",
        ReclaimJump::InsightsColdApps { .. } => "View Apps",
        ReclaimJump::InsightsProjects => "View Projects",
        ReclaimJump::Videos => "Open Videos",
    }
}

/// Overview section. Returns a [`ReclaimJump`] when the user triggers an opportunity jump.
pub fn render_overview_panel(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    tokens: &ThemeTokens,
    selected_lane: &mut Option<Lane>,
) -> Option<ReclaimJump> {
    let mut navigate: Option<ReclaimJump> = None;

    ui_kit::accent_card(ui, tokens, tokens.success, |ui| {
        ui.horizontal(|ui| {
            ui_kit::icon_widget(ui, Icon::Sparkles, 18.0, tokens.success);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Find Space")
                        .size(16.0)
                        .strong()
                        .color(tokens.text_primary),
                );
                ui.label(
                    RichText::new(
                        "Ranks de-overlapped cleanup, compression, virtual disk, duplicate, and hunt opportunities.",
                    )
                    .size(12.0)
                    .color(tokens.text_secondary),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let can_run = state.scan_report.is_some() && !state.heavy_busy();
                if ui_kit::primary_button(
                    ui,
                    if state.reclaim.is_some() {
                        "Re-run Find Space"
                    } else {
                        "Find Space"
                    },
                    can_run,
                    tokens,
                )
                .on_hover_text(
                    "Builds the reclaim ledger and hunts the whole volume for big and swarm removable items (read-only).",
                )
                .clicked()
                    && let Some(sr) = state.scan_report.clone()
                {
                    let job = WorkerJob::BuildReclaim {
                        scan_report: sr,
                        journal_path: state.journal_path.clone(),
                    };
                    state.spawn_job(worker, job);
                }

                if state.is_reclaim_running {
                    ui.spinner();
                    ui.label(
                        RichText::new("Sampling & hunting...")
                            .size(12.0)
                            .color(tokens.info),
                    );
                }
            });
        });

        let Some(result) = state.reclaim.clone() else {
            ui.add_space(6.0);
            if state.scan_report.is_none() {
                ui.label(
                    RichText::new(
                        "Scan a drive above to calculate safe & optional reclaimable space.",
                    )
                    .size(12.0)
                    .color(tokens.text_muted),
                );
            } else if !state.is_reclaim_running {
                ui.label(
                    RichText::new("Press Find Space to assemble all space-saving opportunities for this scan.")
                        .size(12.0)
                        .color(tokens.text_secondary),
                );
            }
            return;
        };

        let ledger = &result.assembled.ledger;
        ui.add_space(10.0);

        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "Free ~{} without losing anything",
                    fmt_bytes(ledger.headline_bytes)
                ))
                .size(20.0)
                .strong()
                .color(tokens.success),
            );
            ui.add_space(8.0);
            ui_kit::pill_badge(
                ui,
                &format!("{} opportunities", ledger.opportunities.len()),
                tokens.info,
                tokens,
            );
            if !result.hunt.findings.is_empty() {
                ui_kit::pill_badge(
                    ui,
                    &format!("{} hunt findings", result.hunt.findings.len()),
                    tokens.purple,
                    tokens,
                );
            }
        });

        ui.add_space(6.0);
        let segments: Vec<(f32, Color32, &str)> = ledger
            .lane_totals
            .iter()
            .map(|t| (t.bytes as f32, lane_color(t.lane, tokens), t.lane.label()))
            .collect();
        ui_kit::segmented_bar(ui, &segments, 10.0, tokens);

        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if ui_kit::chip_toggle(ui, selected_lane.is_none(), "All Lanes", None, tokens).clicked()
            {
                *selected_lane = None;
            }
            for t in &ledger.lane_totals {
                let col = lane_color(t.lane, tokens);
                let label = format!("{} · {} ({})", t.lane.label(), fmt_bytes(t.bytes), t.count);
                let active = *selected_lane == Some(t.lane);
                if ui_kit::chip_toggle(ui, active, &label, Some(col), tokens).clicked() {
                    *selected_lane = if active { None } else { Some(t.lane) };
                }
            }
        });

        ui.add_space(8.0);
        let visible_opps: Vec<&Opportunity> = ledger
            .opportunities
            .iter()
            .filter(|o| o.est_bytes >= 64 * 1024 * 1024)
            .filter(|o| selected_lane.is_none_or(|lane| o.lane == lane))
            .take(18)
            .collect();

        if visible_opps.is_empty() {
            ui.label(
                RichText::new("No opportunities >= 64 MiB match this lane filter.")
                    .size(12.0)
                    .color(tokens.text_muted),
            );
        } else {
            ui_kit::inset_frame(tokens).show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::horizontal()
                    .id_salt("reclaim_opps_hscroll")
                    .show(ui, |ui| {
                        egui::Grid::new("reclaim_opportunities")
                            .striped(true)
                            .min_col_width(56.0)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                ui.strong(
                                    RichText::new("Frees")
                                        .size(12.0)
                                        .color(tokens.text_secondary),
                                );
                                ui.strong(
                                    RichText::new("Lane")
                                        .size(12.0)
                                        .color(tokens.text_secondary),
                                );
                                ui.strong(
                                    RichText::new("Opportunity")
                                        .size(12.0)
                                        .color(tokens.text_secondary),
                                );
                                ui.strong(
                                    RichText::new("Action")
                                        .size(12.0)
                                        .color(tokens.text_secondary),
                                );
                                ui.end_row();

                                for o in visible_opps {
                                    ui.label(
                                        RichText::new(fmt_bytes(o.est_bytes))
                                            .monospace()
                                            .strong()
                                            .color(tokens.text_primary),
                                    );
                                    ui_kit::dot_badge(
                                        ui,
                                        o.lane.label(),
                                        lane_color(o.lane, tokens),
                                        tokens,
                                    );
                                    ui.label(RichText::new(&o.title).color(tokens.text_primary))
                                        .on_hover_text(&o.detail);
                                    ui.horizontal(|ui| {
                                        if let Some(jump) = jump_for_opportunity(state, o) {
                                            let lbl = action_jump_label(&jump);
                                            if ui_kit::secondary_button(ui, lbl, true, tokens)
                                                .clicked()
                                            {
                                                navigate = Some(jump);
                                            }
                                        }
                                        if o.action != ActionRef::None
                                            && ui_kit::icon_button(
                                                ui,
                                                Icon::Copy,
                                                12.0,
                                                tokens.text_secondary,
                                                &format!(
                                                    "Copy CLI command:\n{}",
                                                    o.action.cli_hint()
                                                ),
                                                tokens,
                                            )
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(o.action.cli_hint());
                                        }
                                    });
                                    ui.end_row();
                                }
                            });
                    });
            });
        }

        if !ledger.notes.is_empty() {
            ui.add_space(6.0);
            for n in &ledger.notes {
                ui.label(RichText::new(n).size(11.5).color(tokens.text_secondary));
            }
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Tip: Turn on \"Removable\" colors in Explore to inspect every reclaimable area on the treemap.",
            )
            .size(11.5)
            .color(tokens.text_muted),
        );
    });

    navigate
}

/// Explore toolbar controls: color mode segmented toggle and verdict legend.
pub fn render_explore_controls(
    ui: &mut egui::Ui,
    state: &mut AppState,
    tokens: &ThemeTokens,
) -> bool {
    let available = state.reclaim.is_some();
    let mut changed = false;
    ui_kit::inline_divider(ui, tokens);
    ui.label(
        RichText::new("Color:")
            .size(11.5)
            .color(tokens.text_secondary),
    );

    if ui_kit::chip_toggle(
        ui,
        !state.explore_color_removable,
        "File Type",
        None,
        tokens,
    )
    .clicked()
        && state.explore_color_removable
    {
        state.explore_color_removable = false;
        changed = true;
    }

    let rem_resp = ui.add_enabled_ui(available, |ui| {
        ui_kit::chip_toggle(
            ui,
            state.explore_color_removable && available,
            "Removable",
            Some(tokens.success),
            tokens,
        )
    });
    if rem_resp
        .inner
        .on_hover_text(if available {
            "Color the treemap by removability: reclaimable, leftover, cold data, apps, protected, in use."
        } else {
            "Run Overview > Find Space first."
        })
        .clicked()
        && available
        && !state.explore_color_removable
    {
        state.explore_color_removable = true;
        changed = true;
    }

    if state.explore_color_removable && available {
        ui.add_space(4.0);
        for (v, label) in verdict_legend() {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                let (dot_r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                ui.painter()
                    .circle_filled(dot_r.center(), 3.5, verdict_color(v));
                ui.label(RichText::new(label).size(11.0).color(tokens.text_secondary));
            });
        }
    }

    changed
}

/// Explore side list of the biggest findings. Returns a node to zoom into.
pub fn render_explore_findings(
    ui: &mut egui::Ui,
    state: &mut AppState,
    tokens: &ThemeTokens,
) -> Option<NodeId> {
    let result = state.reclaim.clone()?;
    let mut navigate = None;

    ui_kit::card_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::CollapsingHeader::new(
            RichText::new(format!(
                "Biggest Removable ({})",
                result.hunt.findings.len()
            ))
            .strong()
            .color(tokens.text_primary),
        )
        .default_open(true)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("hunt_findings")
                .max_height(220.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for f in result.hunt.findings.iter().take(40) {
                        ui.horizontal(|ui| {
                            let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                            ui.painter()
                                .circle_filled(dot.center(), 3.5, verdict_color(f.verdict));

                            ui.label(
                                RichText::new(fmt_bytes(f.bytes))
                                    .monospace()
                                    .strong()
                                    .size(12.0)
                                    .color(verdict_color(f.verdict)),
                            );
                            let name = f
                                .path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| f.path.display().to_string());
                            let resp = ui
                                .link(RichText::new(name).size(12.0))
                                .on_hover_text(format!("{}\n{}", f.path.display(), f.reason));
                            if resp.clicked() {
                                navigate = node_for(state, &f.path)
                                    .or_else(|| f.path.parent().and_then(|p| node_for(state, p)));
                            }
                            if f.action != ActionRef::None
                                && ui_kit::icon_button(
                                    ui,
                                    Icon::Copy,
                                    11.0,
                                    tokens.text_secondary,
                                    &format!("Copy: {}", f.action.cli_hint()),
                                    tokens,
                                )
                                .clicked()
                            {
                                ui.ctx().copy_text(f.action.cli_hint());
                            }
                        });
                    }
                });

            let swarms: Vec<_> = result
                .hunt
                .swarms
                .iter()
                .filter(|s| s.kind == FindingKind::Swarm)
                .collect();
            if !swarms.is_empty() {
                ui.add_space(6.0);
                ui.strong(
                    RichText::new("Many Small Things")
                        .size(12.0)
                        .color(tokens.text_secondary),
                );
                for s in swarms.iter().take(8) {
                    ui.label(
                        RichText::new(format!("{}  {}", fmt_bytes(s.bytes), s.title))
                            .size(11.5)
                            .color(verdict_color(s.verdict)),
                    )
                    .on_hover_text(&s.reason);
                }
            }
            if let Some(u) = &result.hunt.unaccounted {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!(
                        "Not visible to this scan: {}",
                        fmt_bytes(u.gap_bytes)
                    ))
                    .size(11.0)
                    .color(tokens.text_muted),
                )
                .on_hover_text(u.causes.join("\n"));
            }
        });
    });

    navigate
}

/// Applies a navigation request into Explore.
pub fn open_in_explore(state: &mut AppState, node: NodeId) {
    state.active_tab = ActiveTab::Explore;
    state.zoom_into(node);
}
