//! Insights view tab: Project Build Artifacts, AI Models, Duplicates, Gaming & Orphans,
//! and Cold Files / Dormant Programs (§9.1–§9.6).

#![forbid(unsafe_code)]

use dsk_core::insights::{DupeRemediationAction, DupeStage, InsightsOptions};
use eframe::egui::{self, Align, RichText, ScrollArea};
use rustc_hash::FxHashMap;

use crate::app_state::{ActiveTab, AppState, ConfirmAction};
use crate::theme::{ThemeTokens, fmt_bytes};
use crate::ui_kit::{self, Icon};
use crate::worker::{WorkerHandle, WorkerJob};

/// Active sub-view inside the Insights tab.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum InsightsSubtab {
    #[default]
    Projects,
    AiModels,
    Duplicates,
    GamingOrphans,
    ColdData,
}

/// Retained UI control state for the Insights tab.
#[derive(Debug, Clone)]
pub struct InsightsViewState {
    pub subtab: InsightsSubtab,
    pub min_bytes_mib: u64,
    pub cold_days: u32,
    pub filter_text: String,
    pub dupe_keep_choice: FxHashMap<String, usize>,
}

impl Default for InsightsViewState {
    fn default() -> Self {
        Self {
            subtab: InsightsSubtab::Projects,
            min_bytes_mib: 1,
            cold_days: 90,
            filter_text: String::new(),
            dupe_keep_choice: FxHashMap::default(),
        }
    }
}

/// Renders the primary Insights tab with its 5 specialized subtabs and safe remediation triggers.
pub fn render(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &mut InsightsViewState,
    tokens: &ThemeTokens,
) {
    let has_scan = state.scan_report.is_some();
    let can_run = has_scan && !state.heavy_busy();

    // Header Actions + Progress
    ui.horizontal(|ui| {
        ui_kit::section_header(
            ui,
            "Storage Insights",
            Some("Discover build caches, AI weights, BLAKE3 duplicates, games, orphan folders, and cold data."),
            tokens,
        );

        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            if ui_kit::secondary_button(ui, "Find Duplicates", can_run, tokens).clicked()
                && let Some(sr) = state.scan_report.clone()
            {
                let min_b = view_state.min_bytes_mib.max(1).saturating_mul(1024 * 1024);
                let job = WorkerJob::FindDuplicates {
                    scan_report: sr,
                    min_bytes: min_b,
                    cache_db_path: state.hash_cache_path.clone(),
                };
                state.spawn_job(worker, job);
            }

            if ui_kit::primary_button(ui, "Analyze Insights", can_run, tokens).clicked()
                && let Some(sr) = state.scan_report.clone()
            {
                let min_b = view_state.min_bytes_mib.saturating_mul(1024 * 1024);
                let job = WorkerJob::RunInsights {
                    scan_report: sr,
                    opts: InsightsOptions {
                        project_min_bytes: min_b,
                        ai_min_bytes: min_b.max(10 * 1024 * 1024),
                        orphan_min_bytes: min_b,
                        cold_min_file_bytes: min_b.max(50 * 1024 * 1024),
                        cold_days_threshold: view_state.cold_days.max(1),
                    },
                };
                state.spawn_job(worker, job);
            }
        });
    });

    if state.is_insights_running || state.is_dupes_running || state.is_recycling {
        ui.add_space(6.0);
        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                if let Some(ref dp) = state.dupes_progress {
                    let ratio = if dp.total > 0 {
                        (dp.done as f32 / dp.total as f32).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    let label = match dp.stage {
                        DupeStage::Collecting => "Collecting inodes".to_string(),
                        DupeStage::PartialHash => format!("Partial {} / {}", dp.done, dp.total),
                        DupeStage::FullHash => format!("BLAKE3 {} / {}", dp.done, dp.total),
                        DupeStage::Done => "Complete".to_string(),
                    };
                    ui_kit::progress_bar(ui, ratio, 8.0, tokens.info, Some(&label), tokens);
                } else {
                    ui.label(
                        RichText::new(
                            state
                                .heavy_activity_label()
                                .unwrap_or("Analyzing insights..."),
                        )
                        .color(tokens.info),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if ui_kit::danger_button(ui, "Cancel", true, tokens).clicked() {
                        worker.cancel_active();
                    }
                });
            });
        });
    }

    ui.add_space(8.0);

    // Filter Controls Bar
    ui_kit::inset_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Min size:")
                    .size(12.0)
                    .color(tokens.text_secondary),
            );
            for (mib, label) in [
                (1, "1 MiB"),
                (10, "10 MiB"),
                (50, "50 MiB"),
                (250, "250 MiB"),
            ] {
                if ui_kit::chip_toggle(ui, view_state.min_bytes_mib == mib, label, None, tokens)
                    .clicked()
                {
                    view_state.min_bytes_mib = mib;
                }
            }

            ui_kit::inline_divider(ui, tokens);
            ui.label(
                RichText::new("Cold days:")
                    .size(12.0)
                    .color(tokens.text_secondary),
            );
            ui.add(egui::DragValue::new(&mut view_state.cold_days).range(7..=730));

            ui_kit::inline_divider(ui, tokens);
            ui_kit::icon_widget(ui, Icon::Search, 14.0, tokens.text_secondary);
            ui.add(
                egui::TextEdit::singleline(&mut view_state.filter_text)
                    .desired_width(180.0)
                    .hint_text("Filter name or path..."),
            );
            if !view_state.filter_text.is_empty()
                && ui_kit::icon_button(
                    ui,
                    Icon::Close,
                    11.0,
                    tokens.text_secondary,
                    "Clear filter",
                    tokens,
                )
                .clicked()
            {
                view_state.filter_text.clear();
            }
        });
    });

    ui.add_space(8.0);

    // Subtab switcher (5 subtabs)
    ui.horizontal_wrapped(|ui| {
        let proj_cnt = state
            .insights_report
            .as_ref()
            .map(|r| r.projects.artifacts.len())
            .unwrap_or(0);
        let ai_cnt = state
            .insights_report
            .as_ref()
            .map(|r| r.ai_models.models.len())
            .unwrap_or(0);
        let dup_cnt = state
            .dupes_report
            .as_ref()
            .map(|r| r.groups.len())
            .unwrap_or(0);
        let go_cnt = state
            .insights_report
            .as_ref()
            .map(|r| r.gaming.games.len() + r.orphans.candidates.len())
            .unwrap_or(0);
        let cold_cnt = state
            .insights_report
            .as_ref()
            .map(|r| r.cold.cold_files.len() + r.cold.cold_apps.len())
            .unwrap_or(0);

        for (sub, lbl) in [
            (InsightsSubtab::Projects, format!("Projects ({proj_cnt})")),
            (InsightsSubtab::AiModels, format!("AI Models ({ai_cnt})")),
            (
                InsightsSubtab::Duplicates,
                format!("Duplicates ({dup_cnt})"),
            ),
            (
                InsightsSubtab::GamingOrphans,
                format!("Gaming & Orphans ({go_cnt})"),
            ),
            (InsightsSubtab::ColdData, format!("Cold Data ({cold_cnt})")),
        ] {
            if ui_kit::chip_toggle(ui, view_state.subtab == sub, &lbl, None, tokens).clicked() {
                view_state.subtab = sub;
            }
        }
    });

    ui.add_space(8.0);

    if state.scan_report.is_none() {
        if ui_kit::empty_state(
            ui,
            Icon::Insights,
            "No Volume Scanned",
            "Run a volume or folder scan from Overview first to discover project caches, AI weights, duplicates, and cold files.",
            Some("Go to Overview"),
            tokens,
        ) {
            state.active_tab = ActiveTab::Overview;
        }
        return;
    }

    let volume_root = state
        .scan_report
        .as_ref()
        .map(|s| s.index.volume().root.clone())
        .unwrap_or_else(|| r"C:\".to_string());
    let filter_lower = view_state.filter_text.trim().to_ascii_lowercase();
    let actions_enabled = !state.heavy_busy();

    ScrollArea::vertical().show(ui, |ui| match view_state.subtab {
        InsightsSubtab::Projects => {
            render_projects_subtab(
                ui,
                state,
                worker,
                view_state,
                &filter_lower,
                &volume_root,
                actions_enabled,
                tokens,
            );
        }
        InsightsSubtab::AiModels => {
            render_ai_models_subtab(
                ui,
                state,
                worker,
                view_state,
                &filter_lower,
                &volume_root,
                actions_enabled,
                tokens,
            );
        }
        InsightsSubtab::Duplicates => {
            render_duplicates_subtab(
                ui,
                state,
                worker,
                view_state,
                &filter_lower,
                actions_enabled,
                tokens,
            );
        }
        InsightsSubtab::GamingOrphans => {
            render_gaming_and_orphans_subtab(
                ui,
                state,
                worker,
                view_state,
                &filter_lower,
                &volume_root,
                actions_enabled,
                tokens,
            );
        }
        InsightsSubtab::ColdData => {
            render_cold_data_subtab(
                ui,
                state,
                worker,
                view_state,
                &filter_lower,
                &volume_root,
                actions_enabled,
                tokens,
            );
        }
    });
}

fn trigger_analyze_insights(
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &InsightsViewState,
) {
    if !state.heavy_busy()
        && let Some(sr) = state.scan_report.clone()
    {
        let min_b = view_state.min_bytes_mib.saturating_mul(1024 * 1024);
        let job = WorkerJob::RunInsights {
            scan_report: sr,
            opts: InsightsOptions {
                project_min_bytes: min_b,
                ai_min_bytes: min_b.max(10 * 1024 * 1024),
                orphan_min_bytes: min_b,
                cold_min_file_bytes: min_b.max(50 * 1024 * 1024),
                cold_days_threshold: view_state.cold_days.max(1),
            },
        };
        state.spawn_job(worker, job);
    }
}

fn matches_filter(text: &str, path: &std::path::Path, filter_lower: &str) -> bool {
    if filter_lower.is_empty() {
        return true;
    }
    text.to_ascii_lowercase().contains(filter_lower)
        || path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(filter_lower)
}

/// Opens Explorer on a background thread so Shell COM never stalls the UI thread.
fn reveal_async(path: &std::path::Path) {
    let p = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = dsk_core::reveal_in_explorer(&p);
    });
}

fn recycle_button(ui: &mut egui::Ui, enabled: bool, tokens: &ThemeTokens) -> bool {
    ui_kit::danger_button(ui, "Move to Recycle Bin", enabled, tokens)
        .on_disabled_hover_text("Wait for the running job to finish")
        .clicked()
}

#[allow(clippy::too_many_arguments)]
fn render_projects_subtab(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &InsightsViewState,
    filter_lower: &str,
    volume_root: &str,
    actions_enabled: bool,
    tokens: &ThemeTokens,
) {
    let Some(report) = state.insights_report.as_ref().map(|r| r.projects.clone()) else {
        if ui_kit::empty_state(
            ui,
            Icon::Insights,
            "Project Build Artifacts Not Analyzed Yet",
            "Discover Rust target/, node_modules/, .venv/, and CMake build caches with hard-link-aware sizing.",
            actions_enabled.then_some("Analyze Insights"),
            tokens,
        ) {
            trigger_analyze_insights(state, worker, view_state);
        }
        return;
    };

    ui_kit::callout_banner(
        ui,
        tokens,
        tokens.info,
        Icon::Sparkles,
        &format!(
            "Reclaimable (hard-link-aware): {} across {} artifact folders",
            fmt_bytes(report.total_reclaimable_bytes),
            report.artifacts.len()
        ),
        Some(&format!(
            "Total allocated footprint: {}",
            fmt_bytes(report.total_allocated_bytes)
        )),
        false,
    );
    ui.add_space(8.0);

    let mut pending_recycle: Option<ConfirmAction> = None;
    for art in &report.artifacts {
        if !matches_filter(&art.project_name, &art.artifact_path, filter_lower) {
            continue;
        }
        ui_kit::card_frame(tokens)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if recycle_button(ui, actions_enabled, tokens) {
                        pending_recycle = Some(ConfirmAction::RecycleInsightPath {
                            label: format!(
                                "{} ({})",
                                art.project_name,
                                art.ecosystem.display_name()
                            ),
                            path: art.artifact_path.clone(),
                            bytes: art.reclaimable_bytes,
                            volume_root: volume_root.to_string(),
                        });
                    }
                    if ui_kit::secondary_button(ui, "Reveal", true, tokens).clicked() {
                        reveal_async(&art.artifact_path);
                    }
                    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                        ui_kit::pill_badge(
                            ui,
                            art.ecosystem.display_name(),
                            tokens.success,
                            tokens,
                        );
                        ui.add(
                            egui::Label::new(RichText::new(&art.project_name).strong()).truncate(),
                        );
                        ui.label(
                            RichText::new(format!(
                                "{} · marker: {} · untouched {}d",
                                fmt_bytes(art.reclaimable_bytes),
                                art.marker_evidence,
                                art.days_since_modified
                            ))
                            .size(12.0)
                            .color(tokens.text_secondary),
                        );
                    });
                });
                ui.label(
                    RichText::new(art.artifact_path.display().to_string())
                        .monospace()
                        .color(tokens.text_muted)
                        .size(11.0),
                );
            });
        ui.add_space(4.0);
    }

    if let Some(modal) = pending_recycle {
        state.confirm_modal = Some(modal);
    }
}

#[allow(clippy::too_many_arguments)]
fn render_ai_models_subtab(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &InsightsViewState,
    filter_lower: &str,
    volume_root: &str,
    actions_enabled: bool,
    tokens: &ThemeTokens,
) {
    let Some(report) = state.insights_report.as_ref().map(|r| r.ai_models.clone()) else {
        if ui_kit::empty_state(
            ui,
            Icon::Insights,
            "AI Models Not Analyzed Yet",
            "Locate HuggingFace, Ollama, LM Studio, and standalone GGUF / Safetensors weights.",
            actions_enabled.then_some("Analyze Insights"),
            tokens,
        ) {
            trigger_analyze_insights(state, worker, view_state);
        }
        return;
    };

    ui_kit::callout_banner(
        ui,
        tokens,
        tokens.purple,
        Icon::Sparkles,
        &format!(
            "Total AI Model Footprint: {} across {} store(s)/weight(s)",
            fmt_bytes(report.total_allocated_bytes),
            report.models.len()
        ),
        None,
        false,
    );
    ui.add_space(8.0);

    let mut pending_recycle: Option<ConfirmAction> = None;
    for m in &report.models {
        if !matches_filter(&m.model_name, &m.path, filter_lower) {
            continue;
        }
        ui_kit::card_frame(tokens)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if recycle_button(ui, actions_enabled, tokens) {
                        pending_recycle = Some(ConfirmAction::RecycleInsightPath {
                            label: format!("AI Model {}", m.model_name),
                            path: m.path.clone(),
                            bytes: m.allocated_bytes,
                            volume_root: volume_root.to_string(),
                        });
                    }
                    if ui_kit::secondary_button(ui, "Reveal", true, tokens).clicked() {
                        reveal_async(&m.path);
                    }
                    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                        ui_kit::pill_badge(ui, m.kind.display_name(), tokens.purple, tokens);
                        ui.add(egui::Label::new(RichText::new(&m.model_name).strong()).truncate());
                        ui.label(
                            RichText::new(format!(
                                "{} · {} file(s) · untouched {}d",
                                fmt_bytes(m.allocated_bytes),
                                m.file_count,
                                m.days_since_access
                            ))
                            .size(12.0)
                            .color(tokens.text_secondary),
                        );
                    });
                });
                ui.label(
                    RichText::new(m.path.display().to_string())
                        .monospace()
                        .color(tokens.text_muted)
                        .size(11.0),
                );
            });
        ui.add_space(4.0);
    }

    if let Some(modal) = pending_recycle {
        state.confirm_modal = Some(modal);
    }
}

fn render_duplicates_subtab(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &mut InsightsViewState,
    filter_lower: &str,
    actions_enabled: bool,
    tokens: &ThemeTokens,
) {
    let Some(report) = state.dupes_report.clone() else {
        if ui_kit::empty_state(
            ui,
            Icon::Copy,
            "Duplicate Scan Not Run Yet",
            "Run zero-hydration, seek-adaptive BLAKE3 duplicate detection to find identical copies.",
            actions_enabled.then_some("Find Duplicates"),
            tokens,
        ) && let Some(sr) = state.scan_report.clone()
        {
            let min_b = view_state.min_bytes_mib.max(1).saturating_mul(1024 * 1024);
            let job = WorkerJob::FindDuplicates {
                scan_report: sr,
                min_bytes: min_b,
                cache_db_path: state.hash_cache_path.clone(),
            };
            state.spawn_job(worker, job);
        }
        return;
    };

    let io_mode = match report.stats.seek_penalty {
        Some(false) => format!("SSD Parallel ({} threads)", report.stats.worker_threads),
        Some(true) => "HDD Sequential (1 thread, file_id ordered)".to_string(),
        None => "Unknown Media Sequential (1 thread)".to_string(),
    };
    ui_kit::callout_banner(
        ui,
        tokens,
        tokens.info,
        Icon::Copy,
        &format!(
            "{} duplicate group(s) · {} wasted",
            report.groups.len(),
            fmt_bytes(report.total_wasted_bytes)
        ),
        Some(&format!(
            "{} hard links collapsed · {} cache hits · {io_mode}",
            report.stats.collapsed_hardlinks, report.stats.cache_hits
        )),
        false,
    );
    ui.add_space(8.0);

    let mut pending_confirm: Option<ConfirmAction> = None;
    let mut pending_dry_run: Option<WorkerJob> = None;
    for group in report.groups.iter().take(200) {
        if !filter_lower.is_empty()
            && !group
                .files
                .iter()
                .any(|f| matches_filter("", &f.path, filter_lower))
        {
            continue;
        }
        let keep_idx = view_state
            .dupe_keep_choice
            .get(&group.blake3_hex)
            .copied()
            .unwrap_or(0)
            .min(group.files.len().saturating_sub(1));

        ui_kit::card_frame(tokens)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.strong(format!(
                        "{} × {} copies",
                        fmt_bytes(group.file_size),
                        group.files.len()
                    ));
                    ui_kit::pill_badge(
                        ui,
                        &format!("{} reclaimable", fmt_bytes(group.reclaimable_bytes)),
                        tokens.success,
                        tokens,
                    );
                    ui.label(
                        RichText::new(group.blake3_hex.get(..12).unwrap_or(&group.blake3_hex))
                            .color(tokens.text_muted)
                            .monospace()
                            .size(11.0),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    if ui_kit::danger_button(ui, "Recycle Copies", actions_enabled, tokens)
                        .clicked()
                    {
                        pending_confirm = Some(ConfirmAction::RemediateDuplicateGroup {
                            group: group.clone(),
                            keep_index: keep_idx,
                            action: DupeRemediationAction::RecycleDuplicates,
                        });
                    }
                    if ui_kit::secondary_button(ui, "Hardlink (Read-Only)", actions_enabled, tokens)
                        .clicked()
                    {
                        pending_confirm = Some(ConfirmAction::RemediateDuplicateGroup {
                            group: group.clone(),
                            keep_index: keep_idx,
                            action: DupeRemediationAction::ReplaceWithHardlinks,
                        });
                    }
                    if ui_kit::secondary_button(ui, "ReFS Reflink", actions_enabled, tokens)
                        .clicked()
                    {
                        pending_confirm = Some(ConfirmAction::RemediateDuplicateGroup {
                            group: group.clone(),
                            keep_index: keep_idx,
                            action: DupeRemediationAction::CloneExtentsRefs,
                        });
                    }
                    if ui_kit::secondary_button(ui, "Dry-Run Preview", actions_enabled, tokens)
                        .clicked()
                    {
                        pending_dry_run = Some(WorkerJob::RemediateDuplicates {
                            group: group.clone(),
                            keep_index: keep_idx,
                            action: DupeRemediationAction::RecycleDuplicates,
                            dry_run: true,
                            journal_path: state.journal_path.clone(),
                            volume_root: report.volume_root.clone(),
                        });
                    }
                });

                ui.add_space(4.0);
                ui_kit::inset_frame(tokens).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    for (idx, file) in group.files.iter().enumerate() {
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if ui_kit::secondary_button(ui, "Reveal", true, tokens).clicked() {
                                reveal_async(&file.path);
                            }
                            ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                                let is_keep = idx == keep_idx;
                                if ui
                                    .radio(is_keep, if is_keep { "KEEP" } else { "Copy" })
                                    .clicked()
                                {
                                    view_state
                                        .dupe_keep_choice
                                        .insert(group.blake3_hex.clone(), idx);
                                }
                                if is_keep {
                                    ui_kit::pill_badge(ui, "CANONICAL", tokens.success, tokens);
                                }
                                let fp = file.path.display().to_string();
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&fp).size(12.0).color(tokens.text_primary),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(&fp);
                            });
                        });
                    }
                });
            });
        ui.add_space(4.0);
    }

    if let Some(modal) = pending_confirm {
        state.confirm_modal = Some(modal);
    }
    if let Some(job) = pending_dry_run {
        state.spawn_job(worker, job);
    }
}

#[allow(clippy::too_many_arguments)]
fn render_gaming_and_orphans_subtab(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &InsightsViewState,
    filter_lower: &str,
    volume_root: &str,
    actions_enabled: bool,
    tokens: &ThemeTokens,
) {
    let Some(insights) = state.insights_report.clone() else {
        if ui_kit::empty_state(
            ui,
            Icon::Insights,
            "Gaming & Orphans Not Analyzed Yet",
            "Detect Steam/Epic/Xbox/GOG/Riot games, shader caches, and orphaned AppData folders.",
            actions_enabled.then_some("Analyze Insights"),
            tokens,
        ) {
            trigger_analyze_insights(state, worker, view_state);
        }
        return;
    };

    let mut pending_recycle: Option<ConfirmAction> = None;

    ui_kit::section_header(
        ui,
        &format!(
            "Gaming Libraries ({} games · {})",
            insights.gaming.games.len(),
            fmt_bytes(insights.gaming.total_allocated_bytes)
        ),
        None,
        tokens,
    );
    ui.add_space(6.0);

    if insights.gaming.games.is_empty() {
        ui.label(RichText::new("No game installations detected.").color(tokens.text_muted));
    } else {
        for g in &insights.gaming.games {
            if !matches_filter(&g.title, &g.install_path, filter_lower) {
                continue;
            }
            ui_kit::card_frame(tokens)
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if let Some(ref sc) = g.shadercache_path
                            && ui_kit::danger_button(
                                ui,
                                "Recycle Shader Cache",
                                actions_enabled,
                                tokens,
                            )
                            .clicked()
                        {
                            pending_recycle = Some(ConfirmAction::RecycleInsightPath {
                                label: format!("{} Shader Cache", g.title),
                                path: sc.clone(),
                                bytes: 0,
                                volume_root: volume_root.to_string(),
                            });
                        }
                        if ui_kit::secondary_button(ui, "Reveal Folder", true, tokens).clicked() {
                            reveal_async(&g.install_path);
                        }
                        ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                            ui_kit::pill_badge(ui, g.store.display_name(), tokens.info, tokens);
                            ui.add(egui::Label::new(RichText::new(&g.title).strong()).truncate());
                            ui.label(
                                RichText::new(fmt_bytes(g.allocated_bytes))
                                    .monospace()
                                    .color(tokens.text_secondary),
                            );
                        });
                    });
                    ui.label(
                        RichText::new(g.install_path.display().to_string())
                            .monospace()
                            .color(tokens.text_muted)
                            .size(11.0),
                    );
                });
            ui.add_space(4.0);
        }
    }

    ui.add_space(12.0);
    ui_kit::section_header(
        ui,
        &format!(
            "Suspected Orphaned App Data ({} · {})",
            insights.orphans.candidates.len(),
            fmt_bytes(insights.orphans.total_allocated_bytes)
        ),
        Some(
            "Orphan remediation strictly uses the Windows Recycle Bin (never permanent deletion).",
        ),
        tokens,
    );
    ui.add_space(6.0);

    for c in &insights.orphans.candidates {
        if !matches_filter(&c.folder_name, &c.path, filter_lower) {
            continue;
        }
        ui_kit::card_frame(tokens)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if recycle_button(ui, actions_enabled, tokens) {
                        pending_recycle = Some(ConfirmAction::RecycleInsightPath {
                            label: format!("Orphan folder {}", c.folder_name),
                            path: c.path.clone(),
                            bytes: c.allocated_bytes,
                            volume_root: volume_root.to_string(),
                        });
                    }
                    if ui_kit::secondary_button(ui, "Reveal", true, tokens).clicked() {
                        reveal_async(&c.path);
                    }
                    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                        ui_kit::pill_badge(
                            ui,
                            &format!("{} {}%", c.scope.display_name(), c.confidence),
                            tokens.warning,
                            tokens,
                        );
                        ui.add(egui::Label::new(RichText::new(&c.folder_name).strong()).truncate());
                        ui.label(
                            RichText::new(fmt_bytes(c.allocated_bytes))
                                .monospace()
                                .color(tokens.text_secondary),
                        );
                    });
                });
                ui.label(
                    RichText::new(&c.reason)
                        .color(tokens.text_secondary)
                        .size(11.5),
                );
                ui.label(
                    RichText::new(c.path.display().to_string())
                        .monospace()
                        .color(tokens.text_muted)
                        .size(11.0),
                );
            });
        ui.add_space(4.0);
    }

    if let Some(modal) = pending_recycle {
        state.confirm_modal = Some(modal);
    }
}

#[allow(clippy::too_many_arguments)]
fn render_cold_data_subtab(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &InsightsViewState,
    filter_lower: &str,
    volume_root: &str,
    actions_enabled: bool,
    tokens: &ThemeTokens,
) {
    let Some(cold) = state.insights_report.as_ref().map(|r| r.cold.clone()) else {
        if ui_kit::empty_state(
            ui,
            Icon::Insights,
            "Cold Data Not Scored Yet",
            "Score cold large files and rarely executed programs (UserAssist / BAM / Prefetch).",
            actions_enabled.then_some("Analyze Insights"),
            tokens,
        ) {
            trigger_analyze_insights(state, worker, view_state);
        }
        return;
    };

    if let Some(ref note) = cold.advisory_note {
        ui_kit::callout_banner(ui, tokens, tokens.warning, Icon::Info, note, None, false);
        ui.add_space(8.0);
    }

    let mut pending_recycle: Option<ConfirmAction> = None;

    ui_kit::section_header(
        ui,
        &format!(
            "Cold Large Files ({} · {})",
            cold.cold_files.len(),
            fmt_bytes(cold.total_cold_file_bytes)
        ),
        None,
        tokens,
    );
    ui.add_space(6.0);

    for f in cold.cold_files.iter().take(100) {
        if !matches_filter("", &f.path, filter_lower) {
            continue;
        }
        ui_kit::card_frame(tokens)
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if recycle_button(ui, actions_enabled, tokens) {
                        pending_recycle = Some(ConfirmAction::RecycleInsightPath {
                            label: f
                                .path
                                .file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "Cold file".to_string()),
                            path: f.path.clone(),
                            bytes: f.allocated_bytes,
                            volume_root: volume_root.to_string(),
                        });
                    }
                    if ui_kit::secondary_button(ui, "Reveal", true, tokens).clicked() {
                        reveal_async(&f.path);
                    }
                    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                        ui_kit::pill_badge(
                            ui,
                            &format!("Score {} · {}d", f.cold_score, f.days_cold),
                            tokens.info,
                            tokens,
                        );
                        ui.label(
                            RichText::new(fmt_bytes(f.allocated_bytes))
                                .monospace()
                                .strong(),
                        );
                        let fp = f.path.display().to_string();
                        ui.add(
                            egui::Label::new(
                                RichText::new(&fp).size(12.0).color(tokens.text_secondary),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&fp);
                    });
                });
            });
        ui.add_space(3.0);
    }

    ui.add_space(12.0);
    ui_kit::section_header(
        ui,
        &format!(
            "Dormant Installed Programs ({} · {})",
            cold.cold_apps.len(),
            fmt_bytes(cold.total_cold_app_bytes)
        ),
        None,
        tokens,
    );
    ui.add_space(6.0);

    for a in cold.cold_apps.iter().take(100) {
        let dummy_path = std::path::Path::new("");
        let loc_path = a.install_location.as_deref().unwrap_or(dummy_path);
        if !matches_filter(&a.app_name, loc_path, filter_lower) {
            continue;
        }
        ui_kit::card_frame(tokens)
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if let Some(ref loc) = a.install_location
                        && ui_kit::secondary_button(ui, "Reveal Install Dir", true, tokens)
                            .clicked()
                    {
                        reveal_async(loc);
                    }
                    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                        ui_kit::pill_badge(
                            ui,
                            &format!("Score {}", a.cold_score),
                            tokens.purple,
                            tokens,
                        );
                        ui.add(egui::Label::new(RichText::new(&a.app_name).strong()).truncate());
                        if a.allocated_bytes > 0 {
                            ui.label(
                                RichText::new(fmt_bytes(a.allocated_bytes))
                                    .monospace()
                                    .color(tokens.text_secondary),
                            );
                        }
                        ui.add(
                            egui::Label::new(
                                RichText::new(&a.telemetry_note)
                                    .color(tokens.text_muted)
                                    .size(11.5),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&a.telemetry_note);
                    });
                });
            });
        ui.add_space(3.0);
    }

    if let Some(modal) = pending_recycle {
        state.confirm_modal = Some(modal);
    }
}
