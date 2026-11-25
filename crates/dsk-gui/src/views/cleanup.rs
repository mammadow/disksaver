//! Cleanup view: rule checklist, precondition warnings, Why Safe inspector, sticky action footer,
//! simulation/execution triggers, and post-clean report.

#![forbid(unsafe_code)]

use dsk_core::clean::RuleTier;
use eframe::egui::{self, Align, Color32, Margin, RichText, ScrollArea, Sense, Vec2};

use crate::app_state::{ActiveTab, AppState};
use crate::theme::{ThemeTokens, fmt_bytes, fmt_count};
use crate::ui_kit::{self, Icon};
use crate::worker::{WorkerHandle, WorkerJob};

fn spawn_plan_rebuild(
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &CleanupViewState,
) {
    if let Some(report) = state.scan_report.clone() {
        let job = WorkerJob::BuildPlan {
            report,
            include_recycle_bin: view_state.include_recycle_bin,
            max_tier: view_state.plan_max_tier(),
            use_helper: state.helper_connected,
        };
        state.spawn_job(worker, job);
    }
}

/// State retained across frames for the cleanup view filters and selection.
pub struct CleanupViewState {
    pub search_query: String,
    pub selected_category: Option<String>,
    pub inspected_rule_id: Option<String>,
    pub include_recycle_bin: bool,
    /// Starts at Safe: the automatic post-scan plan stays fast (no Review/Advanced OS-handler
    /// estimates) and the highlighted chip matches the rules actually planned.
    pub selected_tier_filter: Option<RuleTier>,
}

impl Default for CleanupViewState {
    fn default() -> Self {
        Self {
            search_query: String::new(),
            selected_category: None,
            inspected_rule_id: None,
            include_recycle_bin: false,
            selected_tier_filter: Some(RuleTier::Safe),
        }
    }
}

impl CleanupViewState {
    /// Highest tier the plan is built for. One definition for every trigger (scan finished,
    /// helper connected, tier chips, recycle-bin toggle), so the highlighted chip always matches
    /// the plan: "All" means up to Advanced. Review/Advanced rules are listed but never
    /// pre-checked.
    pub fn plan_max_tier(&self) -> RuleTier {
        self.selected_tier_filter.unwrap_or(RuleTier::Advanced)
    }
}

fn tier_color(tier: RuleTier, tokens: &ThemeTokens) -> Color32 {
    match tier {
        RuleTier::Safe => tokens.success,
        RuleTier::Review => tokens.warning,
        RuleTier::Advanced => tokens.danger,
    }
}

/// Renders the Cleanup tab contents with a sticky bottom execution footer.
pub fn render(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &mut CleanupViewState,
    is_elevated: bool,
    tokens: &ThemeTokens,
) {
    let heavy_busy = state.heavy_busy();

    // Top Banners (Preconditions, Progress, Post-Clean Report)
    if let Some(ref pre) = state.preconditions {
        let mut alerts = Vec::new();
        if let Some(ref reason) = pre.servicing_reason {
            alerts.push(format!("Servicing lock active: {reason}"));
        }
        if !pre.on_ac_power
            && let Some(pct) = pre.battery_pct
            && pct < 30
        {
            alerts.push(format!(
                "Battery is low ({pct}%). Automated cleanup paused on battery < 30%."
            ));
        }

        if !alerts.is_empty() {
            let body = alerts.join("\n");
            ui_kit::callout_banner(
                ui,
                tokens,
                tokens.danger,
                Icon::Warning,
                "Precondition Alerts",
                Some(&body),
                false,
            );
            ui.add_space(4.0);
            ui.checkbox(&mut state.force_battery, "Force run on battery");
            ui.add_space(6.0);
        }
    }

    if state.is_cleaning {
        ui_kit::accent_card(ui, tokens, tokens.info, |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.strong("Cleanup in Progress...");
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if ui_kit::danger_button(ui, "Cancel", true, tokens).clicked() {
                        worker.cancel_active();
                    }
                });
            });
            if let Some(ref prog) = state.clean_progress {
                let ratio = if prog.total > 0 {
                    (prog.done as f32 / prog.total as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                ui.add_space(6.0);
                ui_kit::progress_bar(
                    ui,
                    ratio,
                    9.0,
                    tokens.info,
                    Some(&format!(
                        "{:?} · {} / {} items",
                        prog.phase, prog.done, prog.total
                    )),
                    tokens,
                );
                if !prog.rule_id.is_empty() {
                    ui.label(
                        RichText::new(format!("Current rule: {}", prog.rule_id))
                            .size(11.5)
                            .color(tokens.text_secondary),
                    );
                }
            }
        });
        ui.add_space(8.0);
    } else if state.last_clean_report.is_some() {
        let mut dismiss_report = false;
        if let Some(ref report) = state.last_clean_report {
            let accent = if report.dry_run {
                tokens.info
            } else {
                tokens.success
            };
            let title = if report.dry_run {
                "Simulation Completed (Dry Run)"
            } else {
                "Cleanup Completed Successfully"
            };
            ui_kit::accent_card(ui, tokens, accent, |ui| {
                ui.horizontal(|ui| {
                    ui_kit::icon_widget(
                        ui,
                        if report.dry_run {
                            Icon::Info
                        } else {
                            Icon::Check
                        },
                        16.0,
                        accent,
                    );
                    ui.label(RichText::new(title).size(15.0).strong().color(accent));
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if ui_kit::icon_button(
                            ui,
                            Icon::Close,
                            12.0,
                            tokens.text_secondary,
                            "Dismiss report",
                            tokens,
                        )
                        .clicked()
                        {
                            dismiss_report = true;
                        }
                    });
                });

                if let Some(ref rp) = report.restore_point {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(rp.summary())
                            .size(12.0)
                            .color(if rp.is_warning() {
                                tokens.warning
                            } else {
                                tokens.text_secondary
                            }),
                    );
                }

                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui_kit::pill_badge(
                        ui,
                        &format!("Estimated: {}", fmt_bytes(report.est_bytes)),
                        tokens.info,
                        tokens,
                    );
                    ui_kit::pill_badge(
                        ui,
                        &format!(
                            "Measured Freed: {}",
                            fmt_bytes(report.freed_measured.max(0) as u64)
                        ),
                        tokens.success,
                        tokens,
                    );
                    ui_kit::pill_badge(
                        ui,
                        &format!("Processed: {}", fmt_count(report.items_ok)),
                        tokens.text_secondary,
                        tokens,
                    );
                    if report.items_skipped > 0 {
                        ui_kit::pill_badge(
                            ui,
                            &format!("Skipped: {}", report.items_skipped),
                            tokens.warning,
                            tokens,
                        );
                    }
                    if report.items_failed > 0 {
                        ui_kit::pill_badge(
                            ui,
                            &format!("Errors: {}", report.items_failed),
                            tokens.danger,
                            tokens,
                        );
                    }
                });

                for s in report
                    .rule_summaries
                    .iter()
                    .filter(|s| s.note.is_some())
                    .take(4)
                {
                    ui.label(
                        RichText::new(format!(
                            "• {}: {}",
                            s.name,
                            s.note.as_deref().unwrap_or_default()
                        ))
                        .size(11.5)
                        .color(tokens.text_secondary),
                    );
                }
            });
        }
        if dismiss_report {
            state.last_clean_report = None;
        }
        ui.add_space(8.0);
    }

    // Filter Bar & Bulk Selection
    ui_kit::inset_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            if ui_kit::secondary_button(ui, "Select None", true, tokens).clicked() {
                state.selected_rules.clear();
            }
            if ui_kit::secondary_button(ui, "Select All Safe", true, tokens).clicked()
                && let Some(effective) = state.effective_plan_shared()
            {
                for rule in &effective.rules {
                    if rule.rule_id != "os.vc.recycle_bin" && rule.tier == RuleTier::Safe {
                        state.selected_rules.insert(rule.rule_id.clone());
                    }
                }
            }

            ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                ui_kit::icon_widget(ui, Icon::Search, 14.0, tokens.text_secondary);
                ui.add(
                    egui::TextEdit::singleline(&mut view_state.search_query)
                        .desired_width(160.0)
                        .hint_text("Filter rules..."),
                );

                ui.add_space(4.0);
                ui.label(
                    RichText::new("Category:")
                        .size(12.0)
                        .color(tokens.text_secondary),
                );
                let categories = ["All", "system", "dev", "browsers", "apps", "gaming"];
                let current_cat = view_state.selected_category.as_deref().unwrap_or("All");

                egui::ComboBox::from_id_salt("cleanup_cat_combo")
                    .selected_text(current_cat)
                    .show_ui(ui, |ui| {
                        for &cat in &categories {
                            let is_sel = if cat == "All" {
                                view_state.selected_category.is_none()
                            } else {
                                view_state.selected_category.as_deref() == Some(cat)
                            };
                            if ui.selectable_label(is_sel, cat).clicked() {
                                view_state.selected_category = if cat == "All" {
                                    None
                                } else {
                                    Some(cat.to_string())
                                };
                            }
                        }
                    });
            });
        });

        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Tier:")
                    .size(12.0)
                    .color(tokens.text_secondary),
            );
            let tier_chips = [
                (None, "All", None),
                (Some(RuleTier::Safe), "Safe", Some(tokens.success)),
                (Some(RuleTier::Review), "Review", Some(tokens.warning)),
                (Some(RuleTier::Advanced), "Advanced", Some(tokens.danger)),
            ];
            for (t_val, t_name, accent) in tier_chips {
                let is_sel = view_state.selected_tier_filter == t_val;
                let resp = ui.add_enabled_ui(!heavy_busy, |ui| {
                    ui_kit::chip_toggle(ui, is_sel, t_name, accent, tokens)
                });
                if resp.inner.clicked() && !is_sel {
                    view_state.selected_tier_filter = t_val;
                    spawn_plan_rebuild(state, worker, view_state);
                }
            }

            ui_kit::inline_divider(ui, tokens);
            if ui
                .add_enabled(
                    !heavy_busy,
                    egui::Checkbox::new(&mut view_state.include_recycle_bin, "Include Recycle Bin"),
                )
                .changed()
            {
                spawn_plan_rebuild(state, worker, view_state);
            }
        });
    });

    ui.add_space(8.0);

    // Body + Sticky Footer
    let effective_plan = state.effective_plan_shared();
    if let Some(ref plan) = effective_plan {
        let q = view_state.search_query.trim().to_lowercase();
        let cat_filter = view_state.selected_category.as_deref();

        let filtered_rules: Vec<_> = plan
            .rules
            .iter()
            .filter(|r| {
                if let Some(t) = view_state.selected_tier_filter
                    && r.tier != t
                {
                    return false;
                }
                if let Some(cat) = cat_filter
                    && !r.category.eq_ignore_ascii_case(cat)
                {
                    return false;
                }
                q.is_empty()
                    || r.name.to_lowercase().contains(&q)
                    || r.rule_id.to_lowercase().contains(&q)
                    || r.explain.to_lowercase().contains(&q)
            })
            .collect();

        if view_state.inspected_rule_id.is_none()
            && let Some(first) = filtered_rules.first()
        {
            view_state.inspected_rule_id = Some(first.rule_id.clone());
        }

        let footer_h = 62.0;
        let body_h = (ui.available_height() - footer_h - 8.0).max(120.0);
        let total_w = ui.available_width().max(520.0);
        let gap = 10.0;
        let left_w = ((total_w - gap) * 0.56).clamp(280.0, (total_w - 220.0).max(280.0));
        let right_w = (total_w - gap - left_w).max(200.0);

        ui.horizontal_top(|ui| {
            // Left Pane: Rules Checklist
            ui.vertical(|ui| {
                ui.set_width(left_w);
                ui.set_min_height(body_h);
                ui_kit::card_frame(tokens)
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.strong(format!("Cleanup Rules ({})", filtered_rules.len()));
                            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                ui.label(
                                    RichText::new("Click a rule to inspect rationale")
                                        .size(11.0)
                                        .color(tokens.text_muted),
                                );
                            });
                        });
                        ui.add_space(6.0);

                        ScrollArea::vertical()
                            .id_salt("cleanup_rules_scroll")
                            .max_height((body_h - 60.0).max(60.0))
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for (idx, rule) in filtered_rules.iter().enumerate() {
                                    let mut is_checked =
                                        state.selected_rules.contains(&rule.rule_id);
                                    let can_check = !rule.requires_admin || is_elevated;
                                    let is_inspected = view_state.inspected_rule_id.as_deref()
                                        == Some(&rule.rule_id);

                                    let row_bg = if is_inspected {
                                        tokens.row_selected
                                    } else if idx % 2 == 1 {
                                        tokens.row_alt
                                    } else {
                                        Color32::TRANSPARENT
                                    };

                                    egui::Frame::new()
                                        .fill(row_bg)
                                        .corner_radius(eframe::egui::CornerRadius::same(6))
                                        .inner_margin(Margin::symmetric(8, 5))
                                        .show(ui, |ui| {
                                            ui.set_width(ui.available_width());
                                            ui.with_layout(
                                                egui::Layout::right_to_left(Align::Center),
                                                |ui| {
                                                    if rule.requires_admin && !is_elevated {
                                                        ui_kit::icon_widget(
                                                            ui,
                                                            Icon::Lock,
                                                            12.0,
                                                            tokens.danger,
                                                        );
                                                        ui.label(
                                                            RichText::new("Admin")
                                                                .size(11.0)
                                                                .color(tokens.danger),
                                                        );
                                                    } else {
                                                        ui.label(
                                                            RichText::new(format!(
                                                                "{} items",
                                                                rule.item_count
                                                            ))
                                                            .size(11.0)
                                                            .color(tokens.text_muted),
                                                        );
                                                    }

                                                    let est_str = match rule.estimate.note() {
                                                        None => fmt_bytes(rule.est_bytes),
                                                        Some(_) if rule.est_bytes > 0 => {
                                                            format!(
                                                                "≥ {}",
                                                                fmt_bytes(rule.est_bytes)
                                                            )
                                                        }
                                                        Some(note) => note.to_string(),
                                                    };
                                                    ui.label(
                                                        RichText::new(est_str)
                                                            .monospace()
                                                            .strong()
                                                            .size(12.0)
                                                            .color(tokens.text_primary),
                                                    );

                                                    ui.with_layout(
                                                        egui::Layout::left_to_right(Align::Center),
                                                        |ui| {
                                                            if ui
                                                                .add_enabled(
                                                                    can_check,
                                                                    egui::Checkbox::without_text(
                                                                        &mut is_checked,
                                                                    ),
                                                                )
                                                                .changed()
                                                            {
                                                                state.toggle_rule(&rule.rule_id);
                                                            }

                                                            let (dot, _) = ui.allocate_exact_size(
                                                                Vec2::splat(8.0),
                                                                Sense::hover(),
                                                            );
                                                            ui.painter().circle_filled(
                                                                dot.center(),
                                                                3.5,
                                                                tier_color(rule.tier, tokens),
                                                            );

                                                            ui_kit::pill_badge(
                                                                ui,
                                                                &rule.category,
                                                                tokens.text_secondary,
                                                                tokens,
                                                            );

                                                            let label_text = if is_inspected {
                                                                RichText::new(&rule.name)
                                                                    .strong()
                                                                    .color(tokens.row_selected_text)
                                                            } else {
                                                                RichText::new(&rule.name)
                                                                    .color(tokens.text_primary)
                                                            };
                                                            if ui
                                                                .add(
                                                                    egui::Button::selectable(
                                                                        is_inspected,
                                                                        label_text,
                                                                    )
                                                                    .truncate(),
                                                                )
                                                                .clicked()
                                                            {
                                                                view_state.inspected_rule_id =
                                                                    Some(rule.rule_id.clone());
                                                            }
                                                        },
                                                    );
                                                },
                                            );
                                        });
                                }
                            });
                    });
            });

            ui.add_space(gap);

            // Right Pane: "Why Safe?" Spec Sheet Inspector
            ui.vertical(|ui| {
                ui.set_width(right_w);
                ui.set_min_height(body_h);
                ui_kit::card_frame(tokens)
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui_kit::icon_widget(ui, Icon::Info, 15.0, tokens.accent);
                            ui.strong("Why Safe? Rule Inspector");
                        });
                        ui.add_space(6.0);

                        let inspected_rule = view_state
                            .inspected_rule_id
                            .as_ref()
                            .and_then(|id| plan.rules.iter().find(|r| &r.rule_id == id));

                        ScrollArea::vertical()
                            .id_salt("cleanup_inspector_scroll")
                            .max_height((body_h - 60.0).max(60.0))
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if let Some(rule) = inspected_rule {
                                    ui.label(
                                        RichText::new(&rule.name)
                                            .size(16.0)
                                            .strong()
                                            .color(tokens.text_primary),
                                    );
                                    ui.label(
                                        RichText::new(&rule.rule_id)
                                            .monospace()
                                            .size(11.0)
                                            .color(tokens.text_muted),
                                    );
                                    ui.add_space(8.0);

                                    let t_col = tier_color(rule.tier, tokens);
                                    ui_kit::callout_banner(
                                        ui,
                                        tokens,
                                        t_col,
                                        Icon::ShieldCheck,
                                        &rule.explain,
                                        None,
                                        false,
                                    );

                                    if rule.rule_id == "sys.windows.old"
                                        && let Some(idx) = rule.explain.find("(Rollback window:")
                                    {
                                        let window_text = rule.explain[idx..]
                                            .trim_start_matches('(')
                                            .trim_end_matches(')');
                                        ui.add_space(6.0);
                                        ui_kit::pill_badge(
                                            ui,
                                            window_text,
                                            tokens.warning,
                                            tokens,
                                        );
                                    }

                                    ui.add_space(8.0);
                                    ui.columns(2, |meta| {
                                        meta[0].vertical(|ui| {
                                            ui_kit::inset_frame(tokens).show(ui, |ui| {
                                                ui.set_width(ui.available_width());
                                                ui.set_min_height(42.0);
                                                ui.label(
                                                    RichText::new("Safety Tier")
                                                        .size(11.0)
                                                        .color(tokens.text_muted),
                                                );
                                                ui_kit::dot_badge(
                                                    ui,
                                                    &format!("{:?}", rule.tier),
                                                    t_col,
                                                    tokens,
                                                );
                                            });
                                            ui.add_space(4.0);
                                            ui_kit::inset_frame(tokens).show(ui, |ui| {
                                                ui.set_width(ui.available_width());
                                                ui.set_min_height(42.0);
                                                ui.label(
                                                    RichText::new("Method")
                                                        .size(11.0)
                                                        .color(tokens.text_muted),
                                                );
                                                ui.strong(format!("{:?}", rule.method));
                                            });
                                        });
                                        meta[1].vertical(|ui| {
                                            ui_kit::inset_frame(tokens).show(ui, |ui| {
                                                ui.set_width(ui.available_width());
                                                ui.set_min_height(42.0);
                                                ui.label(
                                                    RichText::new("Regenerable")
                                                        .size(11.0)
                                                        .color(tokens.text_muted),
                                                );
                                                ui.strong(if rule.regenerable {
                                                    "Yes (auto-rebuilt)"
                                                } else {
                                                    "No"
                                                });
                                            });
                                            ui.add_space(4.0);
                                            ui_kit::inset_frame(tokens).show(ui, |ui| {
                                                ui.set_width(ui.available_width());
                                                ui.set_min_height(42.0);
                                                ui.label(
                                                    RichText::new("Elevation")
                                                        .size(11.0)
                                                        .color(tokens.text_muted),
                                                );
                                                ui.strong(if rule.requires_admin {
                                                    "Administrator"
                                                } else {
                                                    "Standard User"
                                                });
                                            });
                                        });
                                    });

                                    let mut shown_lockers: Vec<String> = Vec::new();
                                    if !rule.preconditions.process_not_running.is_empty() {
                                        ui.add_space(6.0);
                                        ui.label(
                                            RichText::new(format!(
                                                "Must Close: {}",
                                                rule.preconditions.process_not_running.join(", ")
                                            ))
                                            .size(12.0)
                                            .color(tokens.text_secondary),
                                        );
                                        if let Some(ref pre) = state.preconditions {
                                            for p in &rule.preconditions.process_not_running {
                                                if pre
                                                    .running_processes
                                                    .iter()
                                                    .any(|rp| rp.eq_ignore_ascii_case(p))
                                                {
                                                    shown_lockers.push(p.clone());
                                                }
                                            }
                                        }
                                    }
                                    if let Some(holders) = state.locked_holders.get(&rule.rule_id) {
                                        for h in holders {
                                            if !shown_lockers
                                                .iter()
                                                .any(|existing| existing.eq_ignore_ascii_case(h))
                                            {
                                                shown_lockers.push(h.clone());
                                            }
                                        }
                                    }
                                    if !shown_lockers.is_empty() {
                                        ui.add_space(4.0);
                                        ui.horizontal_wrapped(|ui| {
                                            for p in &shown_lockers {
                                                ui_kit::pill_badge(
                                                    ui,
                                                    &format!("Locked by {p}"),
                                                    tokens.danger,
                                                    tokens,
                                                );
                                            }
                                        });
                                    }

                                    ui.add_space(8.0);
                                    ui.strong(
                                        RichText::new("Matched Target Roots")
                                            .size(12.5)
                                            .color(tokens.text_primary),
                                    );
                                    ui.add_space(2.0);
                                    for root in &rule.roots {
                                        ui.label(
                                            RichText::new(format!("• {}", root.root_path))
                                                .monospace()
                                                .size(11.0)
                                                .color(tokens.text_secondary),
                                        );
                                        if !root.items.is_empty() {
                                            let sample_count = root.items.len().min(5);
                                            for item in &root.items[..sample_count] {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "    {} ({})",
                                                        item.rel_path,
                                                        fmt_bytes(item.bytes)
                                                    ))
                                                    .size(10.5)
                                                    .color(tokens.text_muted),
                                                );
                                            }
                                            if root.items.len() > 5 {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "    ... and {} more items",
                                                        root.items.len() - 5
                                                    ))
                                                    .size(10.5)
                                                    .color(tokens.text_muted),
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    ui.label(
                                        RichText::new(
                                            "Select a rule from the list to inspect its safety rationale and matched paths.",
                                        )
                                        .color(tokens.text_muted),
                                    );
                                }
                            });
                    });
            });
        });

        ui.add_space(8.0);

        // Sticky Bottom Execution Footer Bar
        let selected_count = state.selected_rules.len();
        let selected_bytes: u64 = plan
            .rules
            .iter()
            .filter(|r| state.selected_rules.contains(&r.rule_id))
            .map(|r| r.est_bytes)
            .sum();

        ui_kit::card_frame(tokens)
            .inner_margin(Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui_kit::icon_widget(ui, Icon::Cleanup, 16.0, tokens.success);
                    ui.label(
                        RichText::new(format!("{selected_count} rules selected"))
                            .strong()
                            .color(tokens.text_primary),
                    );
                    ui_kit::pill_badge(
                        ui,
                        &format!("~{} reclaimable", fmt_bytes(selected_bytes)),
                        if selected_bytes > 0 {
                            tokens.success
                        } else {
                            tokens.text_secondary
                        },
                        tokens,
                    );

                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let can_execute = selected_count > 0 && !heavy_busy;

                        if ui_kit::danger_button(ui, "Clean Selected...", can_execute, tokens)
                            .clicked()
                            && let Some(confirm) = state.prepare_clean_confirm(false)
                        {
                            state.confirm_modal = Some(confirm);
                        }

                        if ui_kit::secondary_button(ui, "Dry Run (Simulate)", can_execute, tokens)
                            .clicked()
                            && let Some(confirm) = state.prepare_clean_confirm(true)
                        {
                            state.confirm_modal = Some(confirm);
                        }
                    });
                });
            });
    } else if state.is_scanning {
        ui_kit::empty_state(
            ui,
            Icon::Rescan,
            "Scan in Progress",
            "Your cleanup plan will be built automatically as soon as the scan completes.",
            None,
            tokens,
        );
    } else if state.is_planning {
        ui_kit::card_frame(tokens).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Building safe cleanup plan...").color(tokens.info));
            });
        });
    } else {
        if ui_kit::empty_state(
            ui,
            Icon::Cleanup,
            "No Active Cleanup Plan",
            "Scan a drive in Overview to evaluate safe developer, browser, and system cleanup rules.",
            Some("Go to Overview"),
            tokens,
        ) {
            state.active_tab = ActiveTab::Overview;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tier_chip_matches_the_automatic_plan() {
        let v = CleanupViewState::default();
        assert_eq!(v.selected_tier_filter, Some(RuleTier::Safe));
        assert_eq!(v.plan_max_tier(), RuleTier::Safe);
        let all = CleanupViewState {
            selected_tier_filter: None,
            ..CleanupViewState::default()
        };
        assert_eq!(all.plan_max_tier(), RuleTier::Advanced);
    }
}
