//! eframe application shell, collapsible sidebar, contextual header, status footer,
//! keyboard shortcuts, modal dispatch, and worker lifecycle management.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use dsk_core::ledger::Lane;
use dsk_core::{NodeFlags, ROOT, ScanMethod, is_elevated, volume_root_of};
use eframe::egui::epaint::{CornerRadius, Stroke};
use eframe::egui::{self, Align, Color32, Margin, Panel, Pos2, Rect, RichText, Sense, Vec2};

use crate::app_state::{ActiveTab, AppState, BannerKind, ConfirmAction};
use crate::theme::{self, ThemeTokens, fmt_bytes, fmt_count};
use crate::ui_kit::{self, Icon};
use crate::views::cleanup::CleanupViewState;
use crate::views::history::HistoryViewState;
use crate::views::insights::{self, InsightsViewState};
use crate::views::optimize::OptimizeViewState;
use crate::views::reclaim::ReclaimJump;
use crate::views::{cleanup, explore, history, optimize, overview, videos};
use crate::worker::{JobLane, WorkerEvent, WorkerHandle, WorkerJob};

/// Repaint cadence while any background job is running (progress, spinners, results).
const BUSY_REPAINT: Duration = Duration::from_millis(100);

/// Startup options (command line or tests).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppOptions {
    /// Folder or volume to scan immediately.
    pub startup_path: Option<PathBuf>,
    /// Action journal override (`--test-journal`); `None` = `%LOCALAPPDATA%\DiskSaver\journal.db`.
    pub journal_path: Option<PathBuf>,
    /// Growth database override (`--growth-db`); `None` = `%LOCALAPPDATA%\DiskSaver\growth.db`.
    pub growth_db_path: Option<PathBuf>,
    /// Duplicate hash cache override; `None` = the default user cache.
    pub hash_cache_path: Option<PathBuf>,
    /// Tab to open at startup (`--tab overview|cleanup|explore|history|optimize|insights|videos`).
    pub initial_tab: Option<ActiveTab>,
}

/// Maps a `--tab` value (case-insensitive) to a tab.
pub fn parse_tab(name: &str) -> Option<ActiveTab> {
    match name.trim().to_ascii_lowercase().as_str() {
        "overview" => Some(ActiveTab::Overview),
        "cleanup" => Some(ActiveTab::Cleanup),
        "explore" => Some(ActiveTab::Explore),
        "history" => Some(ActiveTab::History),
        "optimize" => Some(ActiveTab::Optimize),
        "insights" => Some(ActiveTab::Insights),
        "videos" => Some(ActiveTab::Videos),
        _ => None,
    }
}

impl AppOptions {
    /// Parses `disksaver-gui [PATH] [--tab <NAME>] [--test-journal <DB>] [--growth-db <DB>]
    /// [--hash-cache <DB>]`.
    /// `argv[0]` is skipped; the first non-flag argument is the startup path; unknown flags are
    /// ignored (forward compatibility with shortcuts created by newer builds).
    pub fn parse<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut opts = Self::default();
        let mut iter = args.into_iter().map(Into::into).skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--test-journal" | "--journal" => {
                    opts.journal_path = iter.next().map(PathBuf::from)
                }
                "--growth-db" => opts.growth_db_path = iter.next().map(PathBuf::from),
                "--hash-cache" => opts.hash_cache_path = iter.next().map(PathBuf::from),
                "--tab" => opts.initial_tab = iter.next().as_deref().and_then(parse_tab),
                flag if flag.starts_with("--") => {}
                _ if opts.startup_path.is_none() => opts.startup_path = Some(PathBuf::from(arg)),
                _ => {}
            }
        }
        opts
    }
}

/// The primary DiskSaver desktop GUI application shell.
pub struct DiskSaverApp {
    pub state: AppState,
    pub worker: WorkerHandle,
    pub theme: ThemeTokens,
    pub startup_path: Option<PathBuf>,
    pub is_elevated: bool,

    // Per-view retained state
    pub cleanup_state: CleanupViewState,
    pub history_state: HistoryViewState,
    pub optimize_state: OptimizeViewState,
    pub insights_state: InsightsViewState,
    pub overview_lane_filter: Option<Lane>,

    applied_theme_is_dark: Option<bool>,
}

impl DiskSaverApp {
    /// Creates a new `DiskSaverApp` and dispatches initial background discovery jobs.
    pub fn new(cc: Option<&eframe::CreationContext<'_>>, startup_path: Option<PathBuf>) -> Self {
        Self::with_options(
            cc,
            AppOptions {
                startup_path,
                ..AppOptions::default()
            },
        )
    }

    /// Creates the app with explicit storage locations.
    pub fn with_options(cc: Option<&eframe::CreationContext<'_>>, opts: AppOptions) -> Self {
        Self::with_worker(cc, opts, WorkerHandle::new())
    }

    /// Creates the app around a caller-supplied worker (headless tests pass
    /// [`WorkerHandle::new_inert`] so no job ever touches real disks, databases, or tools).
    pub fn with_worker(
        cc: Option<&eframe::CreationContext<'_>>,
        opts: AppOptions,
        worker: WorkerHandle,
    ) -> Self {
        let elevated = is_elevated();
        let theme = ThemeTokens::dark();

        let applied_theme_is_dark = if let Some(cc) = cc {
            theme::install_system_fonts(&cc.egui_ctx);
            theme::apply_theme(&cc.egui_ctx, &theme);
            Some(theme.is_dark)
        } else {
            None
        };

        let mut state = AppState::new();
        state.journal_path = opts.journal_path;
        state.growth_db_path = opts.growth_db_path;
        state.hash_cache_path = opts.hash_cache_path;
        if let Some(tab) = opts.initial_tab {
            state.active_tab = tab;
        }

        let mut app = Self {
            state,
            worker,
            theme,
            startup_path: opts.startup_path.clone(),
            is_elevated: elevated,
            cleanup_state: CleanupViewState::default(),
            history_state: HistoryViewState::default(),
            optimize_state: OptimizeViewState::default(),
            insights_state: InsightsViewState::default(),
            overview_lane_filter: None,
            applied_theme_is_dark,
        };

        // Initial background discovery jobs
        app.spawn_refresh_drives_and_history();

        // If startup path is supplied, initiate scan immediately
        if let Some(path) = opts.startup_path {
            app.spawn_scan(path);
        }

        app
    }

    /// Switches between Obsidian Dark and Crisp Light themes.
    pub fn toggle_theme(&mut self, ctx: &egui::Context) {
        self.theme = if self.theme.is_dark {
            ThemeTokens::light()
        } else {
            ThemeTokens::dark()
        };
        theme::apply_theme(ctx, &self.theme);
        self.applied_theme_is_dark = Some(self.theme.is_dark);
    }

    /// Spawns a scan of `path` with the current helper/cache settings.
    pub fn spawn_scan(&mut self, path: PathBuf) {
        let job = WorkerJob::ScanTarget {
            path,
            method: ScanMethod::Auto,
            use_helper: self.state.helper_connected,
            use_cache: self.state.scan_use_cache,
            growth_db_path: self.state.growth_db_path.clone(),
        };
        self.state.spawn_job(&mut self.worker, job);
    }

    /// Spawns background refreshes for both mounted volumes and SQLite audit history.
    pub fn spawn_refresh_drives_and_history(&mut self) {
        self.state
            .spawn_job(&mut self.worker, WorkerJob::RefreshDrives);
        let job = WorkerJob::LoadHistory {
            journal_path: self.state.journal_path.clone(),
            limit: 100,
            selected_run: None,
        };
        self.state.spawn_job(&mut self.worker, job);
    }

    fn spawn_build_plan(&mut self, use_helper: bool) {
        if let Some(sr) = self.state.scan_report.clone() {
            let job = WorkerJob::BuildPlan {
                report: sr,
                include_recycle_bin: self.cleanup_state.include_recycle_bin,
                max_tier: self.cleanup_state.plan_max_tier(),
                use_helper,
            };
            self.state.spawn_job(&mut self.worker, job);
        }
    }

    /// Routes a Find Space opportunity action directly to the matching tab and pre-populates context.
    pub fn apply_reclaim_jump(&mut self, jump: ReclaimJump) {
        match jump {
            ReclaimJump::Explore(nid) => {
                self.state.active_tab = ActiveTab::Explore;
                let target = self
                    .state
                    .scan_report
                    .as_ref()
                    .map(|r| {
                        if r.index.flags(nid).contains(NodeFlags::DIR) {
                            nid
                        } else {
                            r.index.parent(nid)
                        }
                    })
                    .unwrap_or(nid);
                self.state.zoom_into(target);
                self.state.selected_node = Some(nid);
            }
            ReclaimJump::CleanupRule { rule_id, tier } => {
                self.state.active_tab = ActiveTab::Cleanup;
                self.cleanup_state.inspected_rule_id = Some(rule_id);
                if tier > self.cleanup_state.plan_max_tier() {
                    self.cleanup_state.selected_tier_filter = None;
                    if !self.state.heavy_busy() {
                        self.spawn_build_plan(self.state.helper_connected);
                    }
                }
            }
            ReclaimJump::Optimize => {
                self.state.active_tab = ActiveTab::Optimize;
            }
            ReclaimJump::OptimizeWof { folder, algo } => {
                self.state.active_tab = ActiveTab::Optimize;
                self.optimize_state.wof_target_folder = folder.display().to_string();
                self.optimize_state.wof_algo = algo;
            }
            ReclaimJump::InsightsDuplicates => {
                self.state.active_tab = ActiveTab::Insights;
                self.insights_state.subtab = insights::InsightsSubtab::Duplicates;
            }
            ReclaimJump::InsightsGames { filter } => {
                self.state.active_tab = ActiveTab::Insights;
                self.insights_state.subtab = insights::InsightsSubtab::GamingOrphans;
                self.insights_state.filter_text = filter;
            }
            ReclaimJump::InsightsColdApps { filter } => {
                self.state.active_tab = ActiveTab::Insights;
                self.insights_state.subtab = insights::InsightsSubtab::ColdData;
                self.insights_state.filter_text = filter;
            }
            ReclaimJump::InsightsProjects => {
                self.state.active_tab = ActiveTab::Insights;
                self.insights_state.subtab = insights::InsightsSubtab::Projects;
            }
            ReclaimJump::Videos => {
                self.state.active_tab = ActiveTab::Videos;
            }
        }
    }

    /// Returns true if any background job is active (drives repaint scheduling).
    pub fn is_busy(&self) -> bool {
        self.state.any_job_active()
    }

    /// Polls worker events and handles automated post-event triggers.
    pub fn poll_worker_events(&mut self) {
        while let Some(event) = self.worker.poll() {
            match event {
                WorkerEvent::ScanFinished(report) => {
                    self.state
                        .apply_worker_event(WorkerEvent::ScanFinished(report.clone()));
                    if let Some(vol_root) = volume_root_of(&report.index.path(dsk_core::ROOT)) {
                        let job = WorkerJob::LoadGrowth {
                            volume_root: vol_root,
                            window: self.state.growth_window,
                            db_path: self.state.growth_db_path.clone(),
                        };
                        self.state.spawn_job(&mut self.worker, job);
                    }
                    // Automatically spawn plan builder so Overview & Cleanup populate
                    self.spawn_build_plan(self.state.helper_connected);
                }

                WorkerEvent::CleanFinished {
                    ref report,
                    ref ledger_deltas,
                } => {
                    let is_live = !report.dry_run;
                    self.state.apply_worker_event(WorkerEvent::CleanFinished {
                        report: report.clone(),
                        ledger_deltas: ledger_deltas.clone(),
                    });

                    if is_live {
                        self.spawn_refresh_drives_and_history();
                        // Re-run plan so remaining items stay up-to-date
                        self.spawn_build_plan(self.state.helper_connected);
                    }
                }

                WorkerEvent::HelperConnected => {
                    self.state.apply_worker_event(WorkerEvent::HelperConnected);
                    // Rebuild the plan through the helper, but never by cancelling a running
                    // scan/clean: a later ScanFinished or ExecuteClean uses the helper anyway.
                    if !self.state.heavy_busy() {
                        self.spawn_build_plan(true);
                    }
                }

                WorkerEvent::RecycleFinished {
                    node_id,
                    outcome,
                    run_id,
                    journal_warning,
                } => {
                    self.state.apply_worker_event(WorkerEvent::RecycleFinished {
                        node_id,
                        outcome,
                        run_id,
                        journal_warning,
                    });
                    self.spawn_refresh_drives_and_history();
                }

                other => {
                    self.state.apply_worker_event(other);
                }
            }
        }
    }

    /// Handles global and Explore keyboard shortcuts without hijacking focused text inputs.
    pub fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            if self.state.confirm_modal.is_some() {
                self.state.confirm_modal = None;
            } else if self.state.videos.confirm.is_some() {
                self.state.videos.confirm = None;
            } else if self.state.show_shortcuts_modal {
                self.state.show_shortcuts_modal = false;
            }
        }

        if ctx.text_edit_focused() {
            return;
        }

        let cmd = egui::Modifiers::COMMAND;
        let tab_keys = [
            (egui::Key::Num1, ActiveTab::Overview),
            (egui::Key::Num2, ActiveTab::Explore),
            (egui::Key::Num3, ActiveTab::Cleanup),
            (egui::Key::Num4, ActiveTab::Optimize),
            (egui::Key::Num5, ActiveTab::Insights),
            (egui::Key::Num6, ActiveTab::Videos),
            (egui::Key::Num7, ActiveTab::History),
        ];
        for (key, tab) in tab_keys {
            if ctx.input_mut(|i| i.consume_key(cmd, key)) {
                self.state.active_tab = tab;
                break;
            }
        }

        if ctx.input_mut(|i| i.consume_key(cmd, egui::Key::B)) {
            self.state.sidebar_collapsed = !self.state.sidebar_collapsed;
        }

        let cmd_shift = egui::Modifiers {
            command: true,
            ctrl: true,
            shift: true,
            ..egui::Modifiers::NONE
        };
        let cmd_shift_alt = egui::Modifiers {
            command: true,
            shift: true,
            ..egui::Modifiers::NONE
        };
        if ctx.input_mut(|i| {
            i.consume_key(cmd_shift, egui::Key::T) || i.consume_key(cmd_shift_alt, egui::Key::T)
        }) {
            self.toggle_theme(ctx);
        }

        let no_modal = self.state.confirm_modal.is_none() && self.state.videos.confirm.is_none();
        if no_modal
            && ctx.input_mut(|i| {
                i.consume_key(egui::Modifiers::SHIFT, egui::Key::Questionmark)
                    || i.consume_key(egui::Modifiers::NONE, egui::Key::Questionmark)
            })
        {
            self.state.show_shortcuts_modal = !self.state.show_shortcuts_modal;
        }

        if no_modal
            && !self.state.show_shortcuts_modal
            && self.state.active_tab == ActiveTab::Explore
            && self.state.scan_report.is_some()
        {
            if ctx.input_mut(|i| {
                i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowLeft)
                    || i.consume_key(egui::Modifiers::NONE, egui::Key::Backspace)
            }) {
                self.state.navigate_back();
            } else if ctx.input_mut(|i| i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowUp)) {
                self.state.navigate_up();
            }
        }
    }

    fn nav_badge(&self, tab: ActiveTab) -> Option<(String, Color32)> {
        match tab {
            ActiveTab::Overview => None,
            ActiveTab::Explore => self.state.scan_report.as_ref().map(|r| {
                let raw = r
                    .index
                    .path(ROOT)
                    .display()
                    .to_string()
                    .trim_start_matches(r"\\?\")
                    .to_string();
                let compact = if raw.chars().count() <= 4 {
                    raw
                } else {
                    let leaf = std::path::Path::new(&raw)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or(raw);
                    truncate_chars(&leaf, 9)
                };
                (compact, self.theme.info)
            }),
            ActiveTab::Cleanup => self
                .state
                .raw_plan
                .as_ref()
                .filter(|p| p.total_est_bytes > 0)
                .map(|p| (fmt_bytes(p.total_est_bytes), self.theme.success)),
            ActiveTab::Optimize => {
                let count = self.state.vhdx_candidates.len()
                    + self.state.cloud_candidates.len()
                    + self.state.active_relocations.len();
                (count > 0).then(|| (count.to_string(), self.theme.purple))
            }
            ActiveTab::Insights => {
                let ins = self
                    .state
                    .insights_report
                    .as_ref()
                    .map(|r| {
                        r.projects.artifacts.len()
                            + r.ai_models.models.len()
                            + r.orphans.candidates.len()
                            + r.cold.cold_files.len()
                    })
                    .unwrap_or(0);
                let dup = self
                    .state
                    .dupes_report
                    .as_ref()
                    .map(|r| r.groups.len())
                    .unwrap_or(0);
                let total = ins + dup;
                (total > 0).then(|| (total.to_string(), self.theme.warning))
            }
            ActiveTab::Videos => {
                if self.state.videos.busy() {
                    Some(("Busy".to_string(), self.theme.info))
                } else {
                    self.state
                        .videos
                        .discovery
                        .as_ref()
                        .filter(|d| d.est_saving_bytes > 0)
                        .map(|d| (fmt_bytes(d.est_saving_bytes), self.theme.success))
                }
            }
            ActiveTab::History => (!self.state.history_runs.is_empty()).then(|| {
                (
                    self.state.history_runs.len().to_string(),
                    self.theme.text_secondary,
                )
            }),
        }
    }

    /// Renders the collapsible left navigation sidebar.
    pub fn render_sidebar(&mut self, ui: &mut egui::Ui) {
        let collapsed = self.state.sidebar_collapsed;
        let width = if collapsed { 60.0 } else { 212.0 };
        let tokens = self.theme;

        Panel::left("nav_sidebar")
            .resizable(false)
            .exact_size(width)
            .frame(
                egui::Frame::new()
                    .fill(tokens.sidebar_bg)
                    .stroke(Stroke::NONE)
                    .inner_margin(Margin::symmetric(8, 12)),
            )
            .show(ui, |ui| {
                // Brand + collapse toggle
                ui.horizontal(|ui| {
                    let emblem_size = 28.0;
                    let (emblem_rect, _) =
                        ui.allocate_exact_size(Vec2::splat(emblem_size), Sense::hover());
                    if ui.is_rect_visible(emblem_rect) {
                        ui.painter().rect_filled(
                            emblem_rect,
                            CornerRadius::same(7),
                            tokens.accent_soft,
                        );
                        ui.painter().rect_stroke(
                            emblem_rect,
                            CornerRadius::same(7),
                            Stroke::new(1.0, theme::tint_on(tokens.border, tokens.accent, 0.5)),
                            egui::StrokeKind::Inside,
                        );
                        ui_kit::paint_icon(
                            ui.painter(),
                            emblem_rect.shrink(5.0),
                            Icon::Drive,
                            tokens.accent,
                        );
                    }
                    if !collapsed {
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new("DiskSaver")
                                .size(15.5)
                                .strong()
                                .color(tokens.text_primary),
                        );
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if ui_kit::icon_button(
                                ui,
                                Icon::SidebarToggle,
                                14.0,
                                tokens.text_secondary,
                                "Collapse sidebar (Ctrl+B)",
                                &tokens,
                            )
                            .clicked()
                            {
                                self.state.sidebar_collapsed = true;
                            }
                        });
                    }
                });

                if collapsed {
                    ui.add_space(4.0);
                    ui.vertical_centered(|ui| {
                        if ui_kit::icon_button(
                            ui,
                            Icon::SidebarToggle,
                            14.0,
                            tokens.text_secondary,
                            "Expand sidebar (Ctrl+B)",
                            &tokens,
                        )
                        .clicked()
                        {
                            self.state.sidebar_collapsed = false;
                        }
                    });
                }

                ui.add_space(12.0);

                // Primary navigation items
                let items = [
                    (ActiveTab::Overview, Icon::Overview, "Overview", "Ctrl+1"),
                    (ActiveTab::Explore, Icon::Explore, "Explore", "Ctrl+2"),
                    (ActiveTab::Cleanup, Icon::Cleanup, "Cleanup", "Ctrl+3"),
                    (ActiveTab::Optimize, Icon::Optimize, "Optimize", "Ctrl+4"),
                    (ActiveTab::Insights, Icon::Insights, "Insights", "Ctrl+5"),
                    (ActiveTab::Videos, Icon::Videos, "Videos", "Ctrl+6"),
                    (ActiveTab::History, Icon::History, "History", "Ctrl+7"),
                ];

                for (tab, icon, label, shortcut) in items {
                    let selected = self.state.active_tab == tab;
                    let badge = self.nav_badge(tab);
                    let row_h = 34.0;
                    let row_w = ui.available_width();
                    let (rect, resp) =
                        ui.allocate_exact_size(Vec2::new(row_w, row_h), Sense::click());

                    if ui.is_rect_visible(rect) {
                        let bg = if selected {
                            tokens.accent_soft
                        } else if resp.hovered() {
                            tokens.surface_hover
                        } else {
                            Color32::TRANSPARENT
                        };
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(8), bg);

                        if selected {
                            let pill = Rect::from_min_max(
                                Pos2::new(rect.min.x + 2.0, rect.min.y + 7.0),
                                Pos2::new(rect.min.x + 5.0, rect.max.y - 7.0),
                            );
                            ui.painter()
                                .rect_filled(pill, CornerRadius::same(2), tokens.accent);
                        }

                        let fg = if selected {
                            tokens.accent
                        } else if resp.hovered() {
                            tokens.text_primary
                        } else {
                            tokens.text_secondary
                        };

                        if collapsed {
                            let icon_rect =
                                Rect::from_center_size(rect.center(), Vec2::splat(17.0));
                            ui_kit::paint_icon(ui.painter(), icon_rect, icon, fg);
                            if let Some((_, bcol)) = &badge {
                                ui.painter().circle_filled(
                                    Pos2::new(rect.max.x - 9.0, rect.min.y + 9.0),
                                    3.2,
                                    *bcol,
                                );
                            }
                        } else {
                            let icon_center = Pos2::new(rect.min.x + 21.0, rect.center().y);
                            let icon_rect =
                                Rect::from_center_size(icon_center, Vec2::splat(16.0));
                            ui_kit::paint_icon(ui.painter(), icon_rect, icon, fg);

                            let text_pos = Pos2::new(rect.min.x + 38.0, rect.center().y);
                            let label_col = if selected {
                                tokens.text_primary
                            } else {
                                fg
                            };
                            ui.painter().text(
                                text_pos,
                                egui::Align2::LEFT_CENTER,
                                label,
                                egui::FontId::proportional(13.5),
                                label_col,
                            );

                            if let Some((btext, bcol)) = &badge {
                                let badge_bg = theme::tint_on(
                                    tokens.card_bg,
                                    *bcol,
                                    if tokens.is_dark { 0.20 } else { 0.12 },
                                );
                                let galley = ui.painter().layout_no_wrap(
                                    btext.clone(),
                                    egui::FontId::proportional(10.5),
                                    *bcol,
                                );
                                let max_bw = (rect.width() - 116.0).max(24.0);
                                let bw = (galley.size().x + 10.0).min(max_bw);
                                let bh = 18.0;
                                let bx = rect.max.x - 6.0 - bw;
                                let brect = Rect::from_min_size(
                                    Pos2::new(bx, rect.center().y - bh * 0.5),
                                    Vec2::new(bw, bh),
                                );
                                ui.painter()
                                    .rect_filled(brect, CornerRadius::same(9), badge_bg);
                                let text_clip = brect.shrink2(Vec2::new(4.0, 0.0));
                                ui.painter().with_clip_rect(text_clip).galley(
                                    Pos2::new(
                                        brect.min.x + 5.0,
                                        brect.center().y - galley.size().y * 0.5,
                                    ),
                                    galley,
                                    *bcol,
                                );
                            }
                        }
                    }

                    let tip = if let Some((btext, _)) = badge {
                        format!("{label} ({shortcut}) — {btext}")
                    } else {
                        format!("{label} ({shortcut})")
                    };
                    if resp.on_hover_text(tip).clicked() {
                        self.state.active_tab = tab;
                    }
                    ui.add_space(2.0);
                }

                // Bottom footer: Theme toggle, Shortcuts, and Elevation status
                ui.with_layout(egui::Layout::bottom_up(Align::Min), |ui| {
                    ui.add_space(2.0);
                    // Utility row: Theme + Shortcuts
                    if collapsed {
                        ui.vertical_centered(|ui| {
                            let (t_icon, t_tip) = if tokens.is_dark {
                                (Icon::Sun, "Switch to Light Mode (Ctrl+Shift+T)")
                            } else {
                                (Icon::Moon, "Switch to Dark Mode (Ctrl+Shift+T)")
                            };
                            if ui_kit::icon_button(ui, t_icon, 15.0, tokens.text_secondary, t_tip, &tokens)
                                .clicked()
                            {
                                self.toggle_theme(ui.ctx());
                            }
                            if ui_kit::icon_button(
                                ui,
                                Icon::Keyboard,
                                15.0,
                                tokens.text_secondary,
                                "Keyboard Shortcuts (?)",
                                &tokens,
                            )
                            .clicked()
                            {
                                self.state.show_shortcuts_modal = true;
                            }
                        });
                    } else {
                        ui.horizontal(|ui| {
                            let (t_icon, t_label) = if tokens.is_dark {
                                (Icon::Sun, "Light")
                            } else {
                                (Icon::Moon, "Dark")
                            };
                            if ui_kit::icon_text_button(ui, t_icon, t_label, true, &tokens)
                                .on_hover_text("Toggle theme (Ctrl+Shift+T)")
                                .clicked()
                            {
                                self.toggle_theme(ui.ctx());
                            }

                            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                if ui_kit::icon_button(
                                    ui,
                                    Icon::Keyboard,
                                    14.0,
                                    tokens.text_secondary,
                                    "Keyboard Shortcuts (?)",
                                    &tokens,
                                )
                                .clicked()
                                {
                                    self.state.show_shortcuts_modal = true;
                                }
                            });
                        });
                    }

                    ui.add_space(6.0);

                    // Elevation status card
                    if collapsed {
                        ui.vertical_centered(|ui| {
                            if self.is_elevated || self.state.helper_connected {
                                ui_kit::icon_widget(ui, Icon::ShieldCheck, 16.0, tokens.success)
                                    .on_hover_text(if self.is_elevated {
                                        "Running as Administrator"
                                    } else {
                                        "Admin Helper Connected"
                                    });
                            } else if self.state.is_connecting_helper {
                                ui.spinner();
                            } else if ui_kit::icon_button(
                                ui,
                                Icon::Shield,
                                16.0,
                                tokens.warning,
                                "Unlock Admin (UAC)",
                                &tokens,
                            )
                            .clicked()
                            {
                                self.state
                                    .spawn_job(&mut self.worker, WorkerJob::ConnectHelper);
                            }
                        });
                    } else {
                        ui_kit::inset_frame(&tokens).show(ui, |ui| {
                            // Explicitly reset to top-down inside bottom_up footer layout so
                            // status label stays above the UAC action button.
                            ui.vertical(|ui| {
                                ui.set_width(ui.available_width());
                                if self.is_elevated || self.state.helper_connected {
                                    ui.horizontal(|ui| {
                                        ui_kit::icon_widget(
                                            ui,
                                            Icon::ShieldCheck,
                                            15.0,
                                            tokens.success,
                                        );
                                        let lbl = if self.is_elevated {
                                            "Administrator"
                                        } else {
                                            "Admin Helper"
                                        };
                                        ui.label(
                                            RichText::new(lbl)
                                                .size(12.0)
                                                .strong()
                                                .color(tokens.success),
                                        );
                                    });
                                } else {
                                    ui.horizontal(|ui| {
                                        ui_kit::icon_widget(
                                            ui,
                                            Icon::Shield,
                                            14.0,
                                            tokens.text_secondary,
                                        );
                                        ui.label(
                                            RichText::new("Standard User")
                                                .size(12.0)
                                                .color(tokens.text_secondary),
                                        );
                                    });
                                    ui.add_space(4.0);
                                    if self.state.is_connecting_helper {
                                        ui.horizontal(|ui| {
                                            ui.spinner();
                                            ui.label(
                                                RichText::new("Waiting for UAC...")
                                                    .size(11.5)
                                                    .color(tokens.warning),
                                            );
                                        });
                                    } else if ui_kit::secondary_button(
                                        ui,
                                        "Unlock Admin (UAC)",
                                        true,
                                        &tokens,
                                    )
                                    .on_hover_text(
                                        "Start the elevated helper: unlocks System rules, $MFT scans, and admin optimizers",
                                    )
                                    .clicked()
                                    {
                                        self.state
                                            .spawn_job(&mut self.worker, WorkerJob::ConnectHelper);
                                    }
                                }
                            });
                        });
                    }
                });
            });
    }

    /// Renders slim contextual top bar with active view title, scanned volume pill,
    /// cross-lane job monitor, and global Refresh / Rescan controls.
    pub fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        let tokens = self.theme;
        let tab_title = match self.state.active_tab {
            ActiveTab::Overview => "Overview",
            ActiveTab::Explore => "Explore Filesystem",
            ActiveTab::Cleanup => "Safe Cleanup",
            ActiveTab::Optimize => "Storage Optimization",
            ActiveTab::Insights => "Storage Insights",
            ActiveTab::Videos => "Video Compressor",
            ActiveTab::History => "Audit History",
        };

        let compact_pill = egui::Frame::new()
            .fill(tokens.inset_bg)
            .stroke(Stroke::new(1.0, tokens.border_subtle))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(8, 2));

        Panel::top("top_app_panel")
            .frame(
                egui::Frame::new()
                    .fill(tokens.header_bg)
                    .stroke(Stroke::NONE)
                    .inner_margin(Margin::symmetric(16, 8)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(tab_title)
                            .size(17.0)
                            .strong()
                            .color(tokens.text_primary),
                    );

                    ui.add_space(8.0);
                    if let Some(ref rep) = self.state.scan_report {
                        let full_root = rep
                            .index
                            .path(ROOT)
                            .display()
                            .to_string()
                            .trim_start_matches(r"\\?\")
                            .to_string();
                        let shown_root = truncate_root_tail(&full_root, 24);
                        let files = fmt_count(rep.index.file_count(ROOT) as u64);
                        ui.scope(|ui| {
                            ui_kit::pill_badge(
                                ui,
                                &format!("{shown_root} · {files} files"),
                                tokens.info,
                                &tokens,
                            );
                        })
                        .response
                        .on_hover_text(full_root);
                    } else {
                        ui_kit::dot_badge(ui, "No volume scanned", tokens.text_muted, &tokens);
                    }

                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        // Rescan current target
                        let can_rescan = !self.state.heavy_busy()
                            && (self.state.selected_volume.is_some()
                                || self.startup_path.is_some());
                        if ui_kit::secondary_button(ui, "Rescan", can_rescan, &tokens)
                            .on_hover_text("Rescan current target")
                            .clicked()
                        {
                            let target_path = self
                                .state
                                .selected_volume
                                .as_ref()
                                .map(|v| PathBuf::from(&v.root))
                                .or_else(|| self.startup_path.clone());

                            if let Some(path) = target_path {
                                self.spawn_scan(path);
                            }
                        }

                        // Refresh drives & history
                        let can_refresh =
                            !self.state.is_refreshing_drives && !self.state.is_loading_history;
                        if ui_kit::secondary_button(ui, "Refresh", can_refresh, &tokens)
                            .on_hover_text("Refresh drives and audit history")
                            .clicked()
                        {
                            self.spawn_refresh_drives_and_history();
                        }

                        // Videos lane activity indicator (visible from any tab!)
                        if let Some(v_label) = self.state.videos.activity_label() {
                            compact_pill.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    ui.spinner();
                                    ui.label(
                                        RichText::new(v_label).size(12.0).color(tokens.purple),
                                    );
                                    if ui_kit::icon_button(
                                        ui,
                                        Icon::Close,
                                        11.0,
                                        tokens.text_secondary,
                                        "Cancel video job",
                                        &tokens,
                                    )
                                    .clicked()
                                    {
                                        self.worker.cancel_lane(JobLane::Videos);
                                    }
                                });
                            });
                        }

                        // Active Heavy-lane activity indicator
                        if let Some(label) = self.state.heavy_activity_label() {
                            let color = if self.state.is_cleaning || self.state.is_recycling {
                                tokens.danger
                            } else {
                                tokens.info
                            };
                            compact_pill.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    ui.spinner();
                                    ui.label(RichText::new(label).size(12.0).strong().color(color));
                                    if self.state.is_scanning
                                        && let Some((phase, done, total)) = self.state.scan_progress
                                    {
                                        let ratio = if total > 0 {
                                            (done as f32 / total as f32).clamp(0.0, 1.0)
                                        } else {
                                            0.0
                                        };
                                        let (bar_r, _) = ui.allocate_exact_size(
                                            Vec2::new(88.0, 8.0),
                                            Sense::hover(),
                                        );
                                        ui_kit::inline_ratio_bar(
                                            ui.painter(),
                                            bar_r,
                                            ratio,
                                            color,
                                            &tokens,
                                        );
                                        ui.label(
                                            RichText::new(format!("{phase:?}"))
                                                .size(11.0)
                                                .color(tokens.text_secondary),
                                        );
                                    }
                                    if ui_kit::icon_button(
                                        ui,
                                        Icon::Close,
                                        11.0,
                                        tokens.text_secondary,
                                        "Cancel active task",
                                        &tokens,
                                    )
                                    .clicked()
                                    {
                                        self.worker.cancel_active();
                                    }
                                });
                            });
                        }
                    });
                });
            });
    }

    /// Renders compact bottom status bar showing scan telemetry and shortcut hints.
    pub fn render_status_footer(&self, ui: &mut egui::Ui) {
        let tokens = self.theme;
        Panel::bottom("status_footer")
            .exact_size(26.0)
            .frame(
                egui::Frame::new()
                    .fill(tokens.sidebar_bg)
                    .stroke(Stroke::NONE)
                    .inner_margin(Margin::symmetric(14, 4)),
            )
            .show(ui, |ui| {
                let mut left_parts = Vec::new();
                if let Some(ref rep) = self.state.scan_report {
                    let engine = match rep.method_used {
                        ScanMethod::UsnIncremental => "Instant USN",
                        ScanMethod::Mft => "$MFT",
                        ScanMethod::Dir => "Parallel Dir",
                        other => {
                            let _ = other;
                            "Auto"
                        }
                    };
                    left_parts.push(format!(
                        "Engine: {engine} · {} nodes · {} · {:.2}s",
                        fmt_count(rep.index.len() as u64),
                        fmt_bytes(rep.index.total_allocated(ROOT)),
                        rep.elapsed.as_secs_f64()
                    ));
                } else {
                    left_parts.push("Ready — select a mounted drive to inspect disk space".into());
                }
                if let Some(ref vol) = self.state.selected_volume {
                    let root = vol.root.trim_start_matches(r"\\?\");
                    left_parts.push(format!("{root} {} free", fmt_bytes(vol.free_bytes)));
                }
                let telemetry = left_parts.join("  ·  ");
                let telemetry_col = if self.state.scan_report.is_some() {
                    tokens.text_secondary
                } else {
                    tokens.text_muted
                };

                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("Ctrl+1–7 Tabs · Ctrl+B Sidebar · ? Shortcuts")
                            .size(11.0)
                            .color(tokens.text_muted),
                    );
                    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&telemetry).size(11.0).color(telemetry_col),
                            )
                            .truncate(),
                        );
                    });
                });
            });
    }

    /// Renders any active top-level status or warning banner.
    pub fn render_status_banner(&mut self, ui: &mut egui::Ui) {
        let Some(banner) = self.state.status_banner.clone() else {
            return;
        };
        let tokens = self.theme;
        let (accent, icon) = match banner.kind {
            BannerKind::Info => (tokens.info, Icon::Info),
            BannerKind::Warning => (tokens.warning, Icon::Warning),
            BannerKind::Error => (tokens.danger, Icon::Warning),
            BannerKind::Success => (tokens.success, Icon::Check),
        };

        egui::Frame::new()
            .inner_margin(Margin {
                left: 0,
                right: 0,
                top: 0,
                bottom: 8,
            })
            .show(ui, |ui| {
                if ui_kit::callout_banner(ui, &tokens, accent, icon, &banner.message, None, true) {
                    self.state.status_banner = None;
                }
            });
    }

    /// Renders confirmation modals for clean execution and recycling.
    ///
    /// Confirm buttons are disabled while a Heavy-lane job runs (for example the plan rebuild
    /// that follows a scan): confirming would silently cancel that job.
    pub fn render_confirm_modal(&mut self, ctx: &egui::Context) {
        let Some(confirm) = self.state.confirm_modal.clone() else {
            return;
        };
        let tokens = self.theme;
        let busy_label = self.state.heavy_activity_label();

        egui::Modal::new(egui::Id::unique("confirm_action_modal"))
            .frame(ui_kit::modal_frame(&tokens))
            .backdrop_color(tokens.modal_backdrop)
            .show(ctx, |ui| {
                ui.set_width(460.0);
                match confirm {
                    ConfirmAction::CleanRules {
                        rule_count,
                        item_count,
                        total_est_bytes,
                        dry_run,
                        selected_rule_ids,
                    } => {
                        let (title, icon, accent) = if dry_run {
                            ("Confirm Simulation (Dry Run)", Icon::Info, tokens.info)
                        } else {
                            ("Confirm Cleanup", Icon::Cleanup, tokens.danger)
                        };
                        modal_header(ui, icon, title, accent, &tokens);

                        ui_kit::inset_frame(&tokens).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(format!("Rules to execute: {rule_count}"));
                            ui.label(format!("Planned items: {}", fmt_count(item_count)));
                            ui.label(
                                RichText::new(format!(
                                    "Estimated space to reclaim: {}",
                                    fmt_bytes(total_est_bytes)
                                ))
                                .strong(),
                            );
                        });

                        ui.add_space(8.0);
                        if dry_run {
                            ui_kit::callout_banner(
                                ui,
                                &tokens,
                                tokens.info,
                                Icon::Info,
                                "Safe simulation — no files will be modified or deleted.",
                                None,
                                false,
                            );
                        } else {
                            ui_kit::callout_banner(
                                ui,
                                &tokens,
                                tokens.warning,
                                Icon::Warning,
                                "Matching temporary and cache files will be cleaned.",
                                None,
                                false,
                            );
                            if let Some(plan) = self.state.effective_plan_shared()
                                && dsk_core::clean::executor::plan_requires_restore_point(
                                    &plan.filtered_rules(&selected_rule_ids),
                                )
                            {
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(
                                        "A System Restore point will be requested first (Advanced / driver-store / ResetBase rules).",
                                    )
                                    .size(11.5)
                                    .color(tokens.warning),
                                );
                            }
                        }

                        ui.add_space(12.0);
                        let action_label = if dry_run {
                            "Start Simulation"
                        } else {
                            "Execute Cleanup"
                        };
                        match confirm_row(ui, busy_label, action_label, !dry_run, &tokens) {
                            ModalChoice::Confirm => {
                                if let Some(effective) = self.state.effective_plan() {
                                    let job = WorkerJob::ExecuteClean {
                                        plan: effective,
                                        selected_rule_ids,
                                        dry_run,
                                        force_battery: self.state.force_battery,
                                        journal_path: self.state.journal_path.clone(),
                                        scan_report: self.state.scan_report.clone(),
                                        use_helper: self.state.helper_connected,
                                        helper_plan_id: self.state.helper_plan_id.clone(),
                                    };
                                    self.state.spawn_job(&mut self.worker, job);
                                }
                                self.state.confirm_modal = None;
                            }
                            ModalChoice::Cancel => self.state.confirm_modal = None,
                            ModalChoice::Pending => {}
                        }
                    }

                    ConfirmAction::RecycleTarget {
                        node_id,
                        path,
                        bytes,
                        is_dir,
                        blocked_reason,
                    } => {
                        modal_header(
                            ui,
                            Icon::Trash,
                            "Move to Recycle Bin",
                            tokens.danger,
                            &tokens,
                        );

                        if let Some(reason) = blocked_reason {
                            ui_kit::callout_banner(
                                ui,
                                &tokens,
                                tokens.danger,
                                Icon::Lock,
                                "Action Blocked",
                                Some(&reason),
                                false,
                            );
                            ui.add_space(12.0);
                            if ui_kit::secondary_button(ui, "Close", true, &tokens).clicked() {
                                self.state.confirm_modal = None;
                            }
                        } else {
                            let kind_str = if is_dir { "Directory" } else { "File" };
                            ui_kit::inset_frame(&tokens).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.label(
                                    RichText::new(path.display().to_string())
                                        .monospace()
                                        .size(12.0),
                                );
                                ui.label(format!("{kind_str} · {}", fmt_bytes(bytes)));
                            });

                            ui.add_space(8.0);
                            ui.label(
                                RichText::new(
                                    "The item will be moved to the Windows Recycle Bin and can be restored later.",
                                )
                                .size(12.0)
                                .color(tokens.text_secondary),
                            );

                            ui.add_space(12.0);
                            match confirm_row(
                                ui,
                                busy_label,
                                "Move to Recycle Bin",
                                true,
                                &tokens,
                            ) {
                                ModalChoice::Confirm => {
                                    if let Some(sr) = self.state.scan_report.clone() {
                                        let job = WorkerJob::RecycleNode {
                                            node_id,
                                            path,
                                            index: sr,
                                            journal_path: self.state.journal_path.clone(),
                                        };
                                        self.state.spawn_job(&mut self.worker, job);
                                    }
                                    self.state.confirm_modal = None;
                                }
                                ModalChoice::Cancel => self.state.confirm_modal = None,
                                ModalChoice::Pending => {}
                            }
                        }
                    }

                    ConfirmAction::ApplyOptimizer {
                        title,
                        target_path,
                        detail,
                        action,
                    } => {
                        let is_sim = action.dry_run();
                        modal_header(
                            ui,
                            Icon::Optimize,
                            &format!("Confirm {title}"),
                            if is_sim { tokens.info } else { tokens.accent },
                            &tokens,
                        );
                        ui_kit::inset_frame(&tokens).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(&detail);
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!("Target: {target_path}"))
                                    .monospace()
                                    .size(12.0)
                                    .color(tokens.accent),
                            );
                        });
                        if is_sim {
                            ui.add_space(8.0);
                            ui_kit::callout_banner(
                                ui,
                                &tokens,
                                tokens.info,
                                Icon::Info,
                                "Simulation only — nothing will be changed.",
                                None,
                                false,
                            );
                        }
                        ui.add_space(12.0);

                        let action_label = if is_sim {
                            "Start Simulation"
                        } else {
                            "Execute Optimization"
                        };
                        match confirm_row(ui, busy_label, action_label, false, &tokens) {
                            ModalChoice::Confirm => {
                                let use_helper = self.state.helper_connected && !self.is_elevated;
                                let job = action.into_job(use_helper);
                                self.state.spawn_job(&mut self.worker, job);
                                self.state.confirm_modal = None;
                            }
                            ModalChoice::Cancel => self.state.confirm_modal = None,
                            ModalChoice::Pending => {}
                        }
                    }

                    ConfirmAction::RelocateFolder {
                        source,
                        target_parent,
                        total_bytes,
                        file_count,
                    } => {
                        modal_header(
                            ui,
                            Icon::ExternalLink,
                            "Confirm Folder Relocation",
                            tokens.warning,
                            &tokens,
                        );
                        ui_kit::inset_frame(&tokens).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            match (file_count, total_bytes) {
                                (Some(files), Some(bytes)) => {
                                    ui.label(format!(
                                        "Moving {} files ({})",
                                        fmt_count(files),
                                        fmt_bytes(bytes)
                                    ));
                                }
                                _ => {
                                    ui.label("Moving folder (size unknown: outside active scan)");
                                }
                            }
                            ui.label(
                                RichText::new(format!("From: {}", source.display()))
                                    .monospace()
                                    .size(12.0)
                                    .color(tokens.warning),
                            );
                            ui.label(
                                RichText::new(format!("To:   {}", target_parent.display()))
                                    .monospace()
                                    .size(12.0)
                                    .color(tokens.info),
                            );
                        });
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(
                                "A directory junction will be created at the source so applications continue working seamlessly.",
                            )
                            .size(12.0)
                            .color(tokens.text_secondary),
                        );
                        ui.add_space(12.0);

                        match confirm_row(ui, busy_label, "Execute Relocation", false, &tokens) {
                            ModalChoice::Confirm => {
                                let job = WorkerJob::RelocateFolder {
                                    source,
                                    target_parent,
                                    journal_path: self.state.journal_path.clone(),
                                };
                                self.state.spawn_job(&mut self.worker, job);
                                self.state.confirm_modal = None;
                            }
                            ModalChoice::Cancel => self.state.confirm_modal = None,
                            ModalChoice::Pending => {}
                        }
                    }

                    ConfirmAction::UndoRelocation { id, source, target } => {
                        modal_header(
                            ui,
                            Icon::Back,
                            "Confirm Undo Relocation",
                            tokens.danger,
                            &tokens,
                        );
                        ui_kit::inset_frame(&tokens).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                RichText::new(format!(
                                    "Restore {target} back to {source} and remove the directory junction."
                                ))
                                .size(12.5),
                            );
                        });
                        ui.add_space(12.0);

                        match confirm_row(
                            ui,
                            busy_label,
                            "Restore Original Folder",
                            true,
                            &tokens,
                        ) {
                            ModalChoice::Confirm => {
                                let job = WorkerJob::UndoRelocation {
                                    id,
                                    journal_path: self.state.journal_path.clone(),
                                };
                                self.state.spawn_job(&mut self.worker, job);
                                self.state.confirm_modal = None;
                            }
                            ModalChoice::Cancel => self.state.confirm_modal = None,
                            ModalChoice::Pending => {}
                        }
                    }

                    ConfirmAction::RecycleInsightPath {
                        label,
                        path,
                        bytes,
                        volume_root,
                    } => {
                        modal_header(
                            ui,
                            Icon::Trash,
                            "Move Item to Recycle Bin",
                            tokens.danger,
                            &tokens,
                        );
                        ui_kit::inset_frame(&tokens).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(&label).strong());
                            ui.label(
                                RichText::new(path.display().to_string())
                                    .monospace()
                                    .size(12.0)
                                    .color(tokens.text_secondary),
                            );
                            if bytes > 0 {
                                ui.label(format!("Estimated size: {}", fmt_bytes(bytes)));
                            }
                        });
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("The item will be moved safely to the Windows Recycle Bin.")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.add_space(12.0);
                        match confirm_row(ui, busy_label, "Move to Recycle Bin", true, &tokens) {
                            ModalChoice::Confirm => {
                                let job = WorkerJob::RecycleInsightPath {
                                    path,
                                    volume_root,
                                    dry_run: false,
                                    journal_path: self.state.journal_path.clone(),
                                };
                                self.state.spawn_job(&mut self.worker, job);
                                self.state.confirm_modal = None;
                            }
                            ModalChoice::Cancel => self.state.confirm_modal = None,
                            ModalChoice::Pending => {}
                        }
                    }

                    ConfirmAction::RemediateDuplicateGroup {
                        group,
                        keep_index,
                        action,
                    } => {
                        modal_header(
                            ui,
                            Icon::Copy,
                            "Confirm Duplicate Group Action",
                            tokens.warning,
                            &tokens,
                        );
                        let keep_path = group
                            .files
                            .get(keep_index)
                            .map(|f| f.path.display().to_string())
                            .unwrap_or_default();
                        ui_kit::inset_frame(&tokens).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(format!("Action: {action:?}"));
                            ui.label(
                                RichText::new(format!("Keep canonical: {keep_path}"))
                                    .monospace()
                                    .size(12.0),
                            );
                            ui.label(format!(
                                "Copies affected: {} · Reclaimable: {}",
                                group.files.len().saturating_sub(1),
                                fmt_bytes(group.reclaimable_bytes)
                            ));
                        });
                        ui.add_space(12.0);
                        match confirm_row(ui, busy_label, "Apply Action", false, &tokens) {
                            ModalChoice::Confirm => {
                                let vol = self
                                    .state
                                    .scan_report
                                    .as_ref()
                                    .map(|s| s.index.volume().root.clone())
                                    .unwrap_or_else(|| r"C:\".to_string());
                                let job = WorkerJob::RemediateDuplicates {
                                    group,
                                    keep_index,
                                    action,
                                    dry_run: false,
                                    journal_path: self.state.journal_path.clone(),
                                    volume_root: vol,
                                };
                                self.state.spawn_job(&mut self.worker, job);
                                self.state.confirm_modal = None;
                            }
                            ModalChoice::Cancel => self.state.confirm_modal = None,
                            ModalChoice::Pending => {}
                        }
                    }
                }
            });
    }

    fn render_shortcuts_modal(&mut self, ctx: &egui::Context) {
        if !self.state.show_shortcuts_modal {
            return;
        }
        let tokens = self.theme;
        let mut close = false;
        egui::Modal::new(egui::Id::unique("shortcuts_help_modal"))
            .frame(ui_kit::modal_frame(&tokens))
            .backdrop_color(tokens.modal_backdrop)
            .show(ctx, |ui| {
                ui.set_width(380.0);
                modal_header(
                    ui,
                    Icon::Keyboard,
                    "Keyboard Shortcuts",
                    tokens.accent,
                    &tokens,
                );
                ui_kit::inset_frame(&tokens).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("shortcuts_grid")
                        .spacing([18.0, 6.0])
                        .show(ui, |ui| {
                            for (key, desc) in [
                                ("Ctrl + 1 .. 7", "Switch workspace tab"),
                                ("Ctrl + B", "Collapse / expand sidebar"),
                                ("Ctrl + Shift + T", "Toggle dark / light theme"),
                                ("Alt + Left / Backspace", "Explore: navigate back"),
                                ("Alt + Up", "Explore: parent directory"),
                                ("?", "Show / hide shortcuts"),
                                ("Esc", "Close active modal"),
                            ] {
                                ui_kit::pill_badge(ui, key, tokens.accent, &tokens);
                                ui.label(RichText::new(desc).color(tokens.text_primary));
                                ui.end_row();
                            }
                        });
                });
                ui.add_space(12.0);
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if ui_kit::primary_button(ui, "Done", true, &tokens).clicked() {
                        close = true;
                    }
                });
            });
        if close {
            self.state.show_shortcuts_modal = false;
        }
    }

    /// Renders the complete UI frame inside `ui`.
    pub fn render(&mut self, ui: &mut egui::Ui) {
        if self.applied_theme_is_dark != Some(self.theme.is_dark) {
            theme::apply_theme(ui.ctx(), &self.theme);
            self.applied_theme_is_dark = Some(self.theme.is_dark);
        }

        // Poll background events
        self.poll_worker_events();

        // Keep progress, spinners, and job results flowing without input events while any lane
        // is busy; an idle app repaints only on input (0% idle CPU).
        if self.is_busy() {
            ui.ctx().request_repaint_after(BUSY_REPAINT);
        }

        // Keyboard shortcuts
        self.handle_shortcuts(ui.ctx());

        // Left navigation rail, top header, bottom status footer
        self.render_sidebar(ui);
        self.render_top_bar(ui);
        self.render_status_footer(ui);

        // Central Panel dispatching to the selected tab view
        let effective_elev = self.state.effective_elevated(self.is_elevated);
        let process_elevated = self.is_elevated;
        let tokens = self.theme;
        let mut jump_to: Option<ReclaimJump> = None;

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(tokens.background)
                    .inner_margin(Margin::symmetric(16, 12)),
            )
            .show(ui, |ui| {
                self.render_status_banner(ui);
                match self.state.active_tab {
                    ActiveTab::Overview => {
                        jump_to = overview::render(
                            ui,
                            &mut self.state,
                            &mut self.worker,
                            effective_elev,
                            &tokens,
                            &mut self.overview_lane_filter,
                        );
                    }
                    ActiveTab::Cleanup => {
                        cleanup::render(
                            ui,
                            &mut self.state,
                            &mut self.worker,
                            &mut self.cleanup_state,
                            effective_elev,
                            &tokens,
                        );
                    }
                    ActiveTab::Explore => {
                        explore::render(ui, &mut self.state, &mut self.worker, &tokens);
                    }
                    ActiveTab::History => {
                        history::render(
                            ui,
                            &mut self.state,
                            &mut self.worker,
                            &mut self.history_state,
                            &tokens,
                        );
                    }
                    ActiveTab::Optimize => {
                        optimize::render(
                            ui,
                            &mut self.state,
                            &mut self.worker,
                            &mut self.optimize_state,
                            process_elevated,
                            &tokens,
                        );
                    }
                    ActiveTab::Insights => {
                        insights::render(
                            ui,
                            &mut self.state,
                            &mut self.worker,
                            &mut self.insights_state,
                            &tokens,
                        );
                    }
                    ActiveTab::Videos => {
                        videos::render(ui, &mut self.state, &mut self.worker, &tokens);
                    }
                }
            });

        if let Some(jump) = jump_to {
            self.apply_reclaim_jump(jump);
        }

        // Overlay modals
        self.render_confirm_modal(ui.ctx());
        self.render_shortcuts_modal(ui.ctx());
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

fn truncate_root_tail(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    let tail: String = s.chars().skip(count - keep).collect();
    format!("…{tail}")
}

fn modal_header(ui: &mut egui::Ui, icon: Icon, title: &str, accent: Color32, tokens: &ThemeTokens) {
    ui.horizontal(|ui| {
        ui_kit::icon_widget(ui, icon, 18.0, accent);
        ui.label(
            RichText::new(title)
                .size(16.5)
                .strong()
                .color(tokens.text_primary),
        );
    });
    ui.add_space(6.0);
    ui.separator();
    ui.add_space(6.0);
}

/// What the user chose in a confirmation modal this frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModalChoice {
    Pending,
    Cancel,
    Confirm,
}

/// Cancel on the left, the confirm button on the right. The confirm button is disabled (with a
/// note) while a Heavy-lane job runs, because confirming would cancel that job.
fn confirm_row(
    ui: &mut egui::Ui,
    busy_label: Option<&'static str>,
    confirm_label: &str,
    destructive: bool,
    tokens: &ThemeTokens,
) -> ModalChoice {
    if let Some(label) = busy_label {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(
                RichText::new(format!("Waiting for the current job to finish ({label})"))
                    .size(11.5)
                    .color(tokens.warning),
            );
        });
        ui.add_space(6.0);
    }
    let mut choice = ModalChoice::Pending;
    ui.horizontal(|ui| {
        if ui_kit::secondary_button(ui, "Cancel", true, tokens).clicked() {
            choice = ModalChoice::Cancel;
        }
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            let can_confirm = busy_label.is_none();
            let resp = if destructive {
                ui_kit::danger_button(ui, confirm_label, can_confirm, tokens)
            } else {
                ui_kit::primary_button(ui, confirm_label, can_confirm, tokens)
            };
            if resp.clicked() {
                choice = ModalChoice::Confirm;
            }
        });
    });
    choice
}

impl eframe::App for DiskSaverApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::OptimizerAction;
    use crate::worker::JobLane;
    use dsk_core::clean::{
        CleanPlan, PlannedItem, PlannedRoot, PlannedRule, PreconditionRule, RuleMethod, RuleTier,
    };
    use dsk_core::index::builder::{EntryBatch, IndexBuilder, RawEntry};
    use dsk_core::index::names::NameArena;
    use dsk_core::{
        JournalEntryRecord, JournalRunRecord, NodeFlags, ScanMethod, ScanReport, VolumeInfo,
    };
    use std::sync::Arc;

    /// Headless app that never touches the real journal/growth DB and never runs jobs.
    fn test_app() -> DiskSaverApp {
        let tmp = std::env::temp_dir().join(format!(
            "dsk_gui_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        DiskSaverApp::with_worker(
            None,
            AppOptions {
                startup_path: None,
                journal_path: Some(tmp.join("journal.db")),
                growth_db_path: Some(tmp.join("growth.db")),
                hash_cache_path: Some(tmp.join("hash_cache.sqlite")),
                initial_tab: None,
            },
            WorkerHandle::new_inert(),
        )
    }

    fn run_frames(ctx: &egui::Context, app: &mut DiskSaverApp, n: usize) {
        for _ in 0..n {
            let output = ctx.run_ui(egui::RawInput::default(), |ui| {
                app.render(ui);
            });
            output.drop_without_applying_deltas();
        }
    }

    fn make_test_report() -> Arc<ScanReport> {
        let mut b = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let mut names = NameArena::new();
        let n1 = names.push_str("Windows");
        let n2 = names.push_str("Temp");
        let n3 = names.push_str("file.log");

        let entries = vec![
            RawEntry {
                key: 10,
                parent_key: 5,
                name: n1,
                flags: NodeFlags::DIR,
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: 10,
                reparse_tag: 0,
            },
            RawEntry {
                key: 20,
                parent_key: 10,
                name: n2,
                flags: NodeFlags::DIR,
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: 20,
                reparse_tag: 0,
            },
            RawEntry {
                key: 30,
                parent_key: 20,
                name: n3,
                flags: NodeFlags::empty(),
                logical: 1024 * 1024,
                allocated: 1024 * 1024,
                mtime: 0,
                atime: 0,
                file_id: 30,
                reparse_tag: 0,
            },
        ];

        b.push_batch(EntryBatch { names, entries });
        let index = b.finish();

        Arc::new(ScanReport {
            index,
            method_used: ScanMethod::Dir,
            elapsed: Duration::from_millis(50),
            skipped: 0,
            check: None,
            fallback_reason: None,
        })
    }

    fn make_test_plan() -> CleanPlan {
        CleanPlan {
            version: 1,
            scanned_path: r"C:\".to_string(),
            volume_root: r"C:\".to_string(),
            scan_method: ScanMethod::Dir,
            total_est_bytes: 1024 * 1024,
            rules: vec![PlannedRule {
                rule_id: "os.temp".to_string(),
                name: "Windows Temp".to_string(),
                category: "system".to_string(),
                tier: RuleTier::Safe,
                regenerable: true,
                requires_admin: false,
                method: RuleMethod::DeleteContents,
                preconditions: PreconditionRule::default(),
                explain: "Temporary operating system files".to_string(),
                est_bytes: 1024 * 1024,
                item_count: 1,
                roots: vec![PlannedRoot {
                    root_path: r"C:\Windows\Temp".to_string(),
                    root_file_id: 20,
                    file_id_kind: dsk_core::FileIdKind::NtfsFrn64,
                    min_age_days: Some(7),
                    exclude_names: Vec::new(),
                    allow_unlisted_children: false,
                    items: vec![PlannedItem {
                        rel_path: "file.log".to_string(),
                        expected_file_id: 30,
                        bytes: 1024 * 1024,
                        is_dir: false,
                        mtime_min: 0,
                    }],
                }],
                os_handler_bytes: None,
                estimate: Default::default(),
            }],
            skipped: Vec::new(),
        }
    }

    #[test]
    fn headless_egui_renders_all_four_tabs_without_panic() {
        let ctx = egui::Context::default();
        let mut app = test_app();

        // Populate test data
        app.state.volumes = vec![
            VolumeInfo {
                root: r"C:\".to_string(),
                fs_name: "NTFS".to_string(),
                serial: 1234,
                cluster_size: 4096,
                total_bytes: 500 * 1024 * 1024 * 1024,
                free_bytes: 200 * 1024 * 1024 * 1024,
                seek_penalty: Some(false),
            },
            VolumeInfo {
                root: r"D:\".to_string(),
                fs_name: "NTFS".to_string(),
                serial: 5678,
                cluster_size: 4096,
                total_bytes: 1000 * 1024 * 1024 * 1024,
                free_bytes: 600 * 1024 * 1024 * 1024,
                seek_penalty: Some(true),
            },
        ];

        let report = make_test_report();
        app.state.scan_report = Some(report);
        app.state.raw_plan = Some(make_test_plan());
        app.state.selected_rules.insert("os.temp".to_string());

        app.state.history_runs = vec![JournalRunRecord {
            run_id: "test-run-123".to_string(),
            started_at_unix: 1700000000,
            finished_at_unix: 1700000060,
            dry_run: false,
            volume: r"C:\".to_string(),
            est_bytes: 1024 * 1024,
            freed_measured: 1024 * 1024,
            items_ok: 1,
            items_skipped: 0,
            items_failed: 0,
        }];

        app.state.history_entries = vec![JournalEntryRecord {
            id: 1,
            run_id: "test-run-123".to_string(),
            path: r"C:\Windows\Temp\file.log".to_string(),
            rule_id: "os.temp".to_string(),
            disposition: "deleted".to_string(),
            size_bytes: 1024 * 1024,
            file_id: 30,
            status: "deleted".to_string(),
            error_msg: None,
        }];

        let tabs = [
            ActiveTab::Overview,
            ActiveTab::Cleanup,
            ActiveTab::Explore,
            ActiveTab::History,
            ActiveTab::Optimize,
            ActiveTab::Insights,
            ActiveTab::Videos,
        ];

        for tab in tabs {
            app.state.active_tab = tab;
            let output = ctx.run_ui(egui::RawInput::default(), |ui| {
                app.render(ui);
            });
            output.drop_without_applying_deltas();
        }

        // Exercise all 5 Insights subtabs with populated reports and confirm modals.
        use crate::views::insights::InsightsSubtab;
        use dsk_core::insights::{
            AiModelCandidate, AiModelStoreKind, AiModelsReport, ColdAppCandidate, ColdDataReport,
            ColdFileCandidate, DiscoveredGame, DupFileEntry, DupeRemediationAction, DupeReport,
            DupeStats, DuplicateGroup, FullInsightsReport, GameStoreKind, GamingLibraryReport,
            OrphanAppCandidate, OrphanScanReport, OrphanScope, ProjectArtifactCandidate,
            ProjectEcosystem, ProjectScanReport,
        };
        app.state.insights_report = Some(FullInsightsReport {
            volume_root: r"C:\".to_string(),
            projects: ProjectScanReport {
                artifacts: vec![ProjectArtifactCandidate {
                    ecosystem: ProjectEcosystem::Rust,
                    project_name: "demo".to_string(),
                    project_root: PathBuf::from(r"C:\dev\demo"),
                    artifact_path: PathBuf::from(r"C:\dev\demo\target"),
                    marker_evidence: "Cargo.toml".to_string(),
                    allocated_bytes: 1_000_000,
                    reclaimable_bytes: 1_000_000,
                    hardlink_shared_bytes: 0,
                    file_count: 10,
                    days_since_modified: 14,
                }],
                total_allocated_bytes: 1_000_000,
                total_reclaimable_bytes: 1_000_000,
                total_hardlink_shared_bytes: 0,
            },
            ai_models: AiModelsReport {
                models: vec![AiModelCandidate {
                    kind: AiModelStoreKind::HuggingFace,
                    model_name: "meta-llama/test".to_string(),
                    path: PathBuf::from(r"C:\Users\Alice\.cache\huggingface\hub\models--test"),
                    allocated_bytes: 4_000_000_000,
                    file_count: 3,
                    days_since_access: 30,
                }],
                total_allocated_bytes: 4_000_000_000,
            },
            gaming: GamingLibraryReport {
                library_roots: vec![PathBuf::from(r"D:\SteamLibrary")],
                games: vec![DiscoveredGame {
                    store: GameStoreKind::Steam,
                    app_id: Some("730".to_string()),
                    title: "Counter-Strike 2".to_string(),
                    install_path: PathBuf::from(r"D:\SteamLibrary\steamapps\common\cs2"),
                    workshop_path: None,
                    shadercache_path: Some(PathBuf::from(
                        r"D:\SteamLibrary\steamapps\shadercache\730",
                    )),
                    allocated_bytes: 30_000_000_000,
                    days_since_access: Some(12),
                }],
                total_allocated_bytes: 30_000_000_000,
            },
            orphans: OrphanScanReport {
                candidates: vec![OrphanAppCandidate {
                    scope: OrphanScope::AppDataLocal,
                    folder_name: "LegacyTool".to_string(),
                    path: PathBuf::from(r"C:\Users\Alice\AppData\Local\LegacyTool"),
                    allocated_bytes: 250_000_000,
                    file_count: 42,
                    days_since_touch: 200,
                    confidence: 85,
                    reason: "No matching installed program".to_string(),
                }],
                total_allocated_bytes: 250_000_000,
            },
            cold: ColdDataReport {
                last_access_disabled: Some(true),
                advisory_note: Some("LastAccess disabled".to_string()),
                cold_files: vec![ColdFileCandidate {
                    path: PathBuf::from(r"C:\Users\Alice\Downloads\old.iso"),
                    allocated_bytes: 4_000_000_000,
                    days_cold: 180,
                    cold_score: 90,
                    extension: Some("iso".to_string()),
                }],
                cold_apps: vec![ColdAppCandidate {
                    app_name: "DormantApp".to_string(),
                    publisher: None,
                    install_location: Some(PathBuf::from(r"C:\Program Files\DormantApp")),
                    allocated_bytes: 500_000_000,
                    days_since_last_run: Some(210),
                    observed_runs: 1,
                    cold_score: 85,
                    telemetry_note: "Prefetch".to_string(),
                }],
                total_cold_file_bytes: 4_000_000_000,
                total_cold_app_bytes: 500_000_000,
                unscored_apps: 0,
            },
            total_reclaimable_estimate: 4_251_000_000,
        });
        let dup_group = DuplicateGroup {
            blake3_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            file_size: 4096,
            files: vec![
                DupFileEntry {
                    node_id: 10,
                    path: PathBuf::from(r"C:\a.bin"),
                    file_id: 10,
                    logical_bytes: 4096,
                    allocated_bytes: 4096,
                    mtime_min: 1,
                    atime_min: 1,
                    hardlinked: false,
                },
                DupFileEntry {
                    node_id: 11,
                    path: PathBuf::from(r"C:\b.bin"),
                    file_id: 11,
                    logical_bytes: 4096,
                    allocated_bytes: 4096,
                    mtime_min: 2,
                    atime_min: 2,
                    hardlinked: false,
                },
            ],
            reclaimable_bytes: 4096,
        };
        app.state.dupes_report = Some(DupeReport {
            volume_root: r"C:\".to_string(),
            min_bytes: 1024,
            groups: vec![dup_group.clone()],
            total_wasted_bytes: 4096,
            stats: DupeStats::default(),
        });
        app.state.active_tab = ActiveTab::Insights;
        for sub in [
            InsightsSubtab::Projects,
            InsightsSubtab::AiModels,
            InsightsSubtab::Duplicates,
            InsightsSubtab::GamingOrphans,
            InsightsSubtab::ColdData,
        ] {
            app.insights_state.subtab = sub;
            let output = ctx.run_ui(egui::RawInput::default(), |ui| {
                app.render(ui);
            });
            output.drop_without_applying_deltas();
        }
        app.state.confirm_modal = Some(ConfirmAction::RecycleInsightPath {
            label: "LegacyTool".to_string(),
            path: PathBuf::from(r"C:\Users\Alice\AppData\Local\LegacyTool"),
            bytes: 250_000_000,
            volume_root: r"C:\".to_string(),
        });
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();
        app.state.confirm_modal = Some(ConfirmAction::RemediateDuplicateGroup {
            group: dup_group,
            keep_index: 0,
            action: DupeRemediationAction::RecycleDuplicates,
        });
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();

        // Test modal dialogs render cleanly
        app.state.confirm_modal = app.state.prepare_clean_confirm(true);
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();

        app.state.confirm_modal = app.state.prepare_clean_confirm(false);
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();

        app.state.confirm_modal = app.state.prepare_recycle_confirm(30);
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();

        app.state.confirm_modal = Some(ConfirmAction::ApplyOptimizer {
            title: "Compact VHDX".to_string(),
            target_path: r"C:\docker.vhdx".to_string(),
            detail: "Compacting simulated VHDX".to_string(),
            action: OptimizerAction::CompactVhdx {
                path: PathBuf::from(r"C:\docker.vhdx"),
                distro: None,
                dry_run: true,
            },
        });
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();

        app.state.confirm_modal = Some(ConfirmAction::RelocateFolder {
            source: PathBuf::from(r"C:\Models"),
            target_parent: PathBuf::from(r"D:\Data"),
            total_bytes: Some(1_000_000_000),
            file_count: Some(5),
        });
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();

        app.state.confirm_modal = Some(ConfirmAction::UndoRelocation {
            id: "reloc-123".to_string(),
            source: r"C:\Models".to_string(),
            target: r"D:\Data\Models".to_string(),
        });
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();

        app.state.confirm_modal = None;
    }

    #[test]
    fn is_busy_tracks_refresh_drives_and_resets_on_completion_error_and_cancel() {
        let mut app = test_app();
        // Clear initial startup flags first to isolate RefreshDrives tracking
        app.state.is_refreshing_drives = false;
        app.state.is_loading_history = false;
        assert!(!app.is_busy());

        app.state.is_refreshing_drives = true;
        assert!(app.is_busy());
        app.state
            .apply_worker_event(WorkerEvent::DrivesLoaded(Vec::new()));
        assert!(!app.is_busy());

        app.state.is_refreshing_drives = true;
        assert!(app.is_busy());
        app.state.apply_worker_event(WorkerEvent::JobError {
            lane: crate::worker::JobLane::Drives,
            message: "test drive error".to_string(),
        });
        assert!(!app.is_busy());

        app.state.is_refreshing_drives = true;
        assert!(app.is_busy());
        app.state
            .apply_worker_event(WorkerEvent::JobCancelled(crate::worker::JobLane::Drives));
        assert!(!app.is_busy());
    }

    #[test]
    fn explore_tab_renders_cleanly_across_all_tree_sort_modes() {
        use crate::tree_model::TreeSort;

        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.scan_report = Some(make_test_report());
        app.state.active_tab = ActiveTab::Explore;

        for sort in [
            TreeSort::SizeDesc,
            TreeSort::NameAsc,
            TreeSort::FilesDesc,
            TreeSort::MtimeDesc,
        ] {
            app.state.tree_model.sort = sort;
            app.state.invalidate_explore_caches();
            let output = ctx.run_ui(egui::RawInput::default(), |ui| {
                app.render(ui);
            });
            output.drop_without_applying_deltas();
            assert!(!app.state.tree_model.rows.is_empty());
        }
    }

    #[test]
    fn overview_renders_usn_badge_and_what_grew_runaway_cleanly() {
        use dsk_core::{GrowthDelta, GrowthReport};

        let ctx = egui::Context::default();
        let mut app = test_app();

        let mut usn_report = make_test_report();
        Arc::get_mut(&mut usn_report)
            .expect("unique test report Arc")
            .method_used = ScanMethod::UsnIncremental;
        app.state
            .apply_worker_event(WorkerEvent::ScanFinished(usn_report));

        let runaway_entry = GrowthDelta {
            path: r"C:\Windows\Temp".to_string(),
            current_bytes: 12 * 1024 * 1024 * 1024,
            previous_bytes: 1024 * 1024 * 1024,
            delta_bytes: 11 * 1024 * 1024 * 1024,
            rate_bytes_per_day: 11 * 1024 * 1024 * 1024,
            runaway: true,
        };
        app.state
            .apply_worker_event(WorkerEvent::GrowthLoaded(GrowthReport {
                volume: r"C:\".to_string(),
                window: "24h".to_string(),
                has_baseline: true,
                latest_at_unix: Some(1_700_086_400),
                baseline_at_unix: Some(1_700_000_000),
                volume_delta_bytes: 11 * 1024 * 1024 * 1024,
                runaways: vec![runaway_entry.clone()],
                entries: vec![runaway_entry],
            }));

        app.state.active_tab = ActiveTab::Overview;
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render(ui);
        });
        output.drop_without_applying_deltas();
        assert!(
            app.state
                .growth_report
                .as_ref()
                .is_some_and(|r| !r.runaways.is_empty())
        );
    }

    #[test]
    fn optimize_tab_probes_once_across_frames_and_reprobes_only_after_scan_or_optimizer() {
        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.active_tab = ActiveTab::Optimize;

        run_frames(&ctx, &mut app, 15);
        assert_eq!(
            app.worker.lane_spawn_count(JobLane::Optimizers),
            1,
            "opening Optimize must spawn ProbeOptimizers once, not once per frame"
        );
        assert!(app.state.is_probing_optimizers);

        // A failing probe is reported once and never retried per frame.
        app.state.apply_worker_event(WorkerEvent::JobError {
            lane: JobLane::Optimizers,
            message: "vssadmin failed".to_string(),
        });
        run_frames(&ctx, &mut app, 15);
        assert_eq!(app.worker.lane_spawn_count(JobLane::Optimizers), 1);
        assert_eq!(
            app.state.optimizers_probe_error.as_deref(),
            Some("vssadmin failed")
        );

        // A new scan invalidates the probe: exactly one re-probe.
        app.state
            .apply_worker_event(WorkerEvent::ScanFinished(make_test_report()));
        run_frames(&ctx, &mut app, 15);
        assert_eq!(app.worker.lane_spawn_count(JobLane::Optimizers), 2);

        // Successful completion: still no per-frame respawn.
        app.state.apply_worker_event(WorkerEvent::OptimizersProbed {
            vhdx_candidates: Vec::new(),
            cloud_candidates: Vec::new(),
            tunables_status: dsk_core::optimize::SystemTunablesStatus {
                system_drive: "C:".to_string(),
                hiberfil_bytes: None,
                is_laptop_battery_present: false,
                vss_used_bytes: None,
                vss_max_bytes: None,
                reserved_storage_enabled: None,
                servicing_busy: false,
            },
            compact_os_state: None,
            active_relocations: Vec::new(),
        });
        assert!(!app.state.is_probing_optimizers);
        run_frames(&ctx, &mut app, 15);
        assert_eq!(app.worker.lane_spawn_count(JobLane::Optimizers), 2);

        // An optimizer changed system state: exactly one more probe.
        app.state
            .apply_worker_event(WorkerEvent::OptimizerFinished {
                message: "done".to_string(),
                warning: false,
            });
        run_frames(&ctx, &mut app, 15);
        assert_eq!(app.worker.lane_spawn_count(JobLane::Optimizers), 3);

        // The probe never occupies (or cancels) the Heavy lane.
        assert_eq!(app.worker.lane_spawn_count(JobLane::Heavy), 0);
    }

    #[test]
    fn all_tabs_are_frame_stable_and_never_spawn_from_the_render_loop() {
        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.scan_report = Some(make_test_report());
        app.state.raw_plan = Some(make_test_plan());
        let baseline: Vec<u64> = JobLane::ALL
            .iter()
            .map(|l| app.worker.lane_spawn_count(*l))
            .collect();
        for tab in [
            ActiveTab::Overview,
            ActiveTab::Cleanup,
            ActiveTab::Explore,
            ActiveTab::History,
            ActiveTab::Insights,
        ] {
            app.state.active_tab = tab;
            run_frames(&ctx, &mut app, 10);
        }
        let after: Vec<u64> = JobLane::ALL
            .iter()
            .map(|l| app.worker.lane_spawn_count(*l))
            .collect();
        assert_eq!(
            baseline, after,
            "rendering without input must not spawn jobs"
        );
    }

    #[test]
    fn startup_jobs_use_injected_journal_and_growth_paths() {
        let app = test_app();
        let journal = app.state.journal_path.clone().expect("injected journal");
        assert_ne!(journal, dsk_core::ActionJournal::default_path());
        assert!(
            !journal.starts_with(
                dsk_core::ActionJournal::default_path()
                    .parent()
                    .expect("journal dir")
            ),
            "tests must never point at %LOCALAPPDATA%\\DiskSaver"
        );
        let history_jobs: Vec<_> = app
            .worker
            .inert_jobs()
            .iter()
            .filter_map(|j| match j {
                WorkerJob::LoadHistory { journal_path, .. } => Some(journal_path.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(history_jobs, vec![Some(journal)]);
        assert!(!app.state.journal_path.as_ref().unwrap().exists());
    }

    #[test]
    fn heavy_triggers_are_locked_while_a_heavy_job_runs() {
        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.scan_report = Some(make_test_report());
        app.state.raw_plan = Some(make_test_plan());
        // A scan is running; open the clean confirmation and render it.
        let scan = WorkerJob::ScanTarget {
            path: PathBuf::from(r"C:\"),
            method: ScanMethod::Dir,
            use_helper: false,
            use_cache: false,
            growth_db_path: None,
        };
        app.state.spawn_job(&mut app.worker, scan);
        assert!(app.state.heavy_busy());
        assert_eq!(app.state.heavy_activity_label(), Some("Scanning..."));
        app.state.confirm_modal = app.state.prepare_clean_confirm(false);
        let heavy_before = app.worker.lane_spawn_count(JobLane::Heavy);
        run_frames(&ctx, &mut app, 5);
        assert_eq!(
            app.worker.lane_spawn_count(JobLane::Heavy),
            heavy_before,
            "no Heavy job may be spawned (and the scan cancelled) while it runs"
        );
        assert!(
            app.state.confirm_modal.is_some(),
            "modal stays open, confirm disabled"
        );
    }

    #[test]
    fn app_options_parse_test_journal_and_startup_path() {
        let o = AppOptions::parse([
            "disksaver-gui",
            "--test-journal",
            r"C:\tmp\j.db",
            r"D:\Data",
            "--growth-db",
            r"C:\tmp\g.db",
            "--unknown-flag",
            "--tab",
            "Optimize",
        ]);
        assert_eq!(o.initial_tab, Some(ActiveTab::Optimize));
        assert_eq!(parse_tab("bogus"), None);
        assert_eq!(o.startup_path, Some(PathBuf::from(r"D:\Data")));
        assert_eq!(o.journal_path, Some(PathBuf::from(r"C:\tmp\j.db")));
        assert_eq!(o.growth_db_path, Some(PathBuf::from(r"C:\tmp\g.db")));
        assert_eq!(AppOptions::parse(["disksaver-gui"]), AppOptions::default());
    }

    #[test]
    fn videos_tab_renders_every_state_and_applies_its_events() {
        use crate::views::videos::VideoConfirm;
        use crate::worker::{JobLane, VideosProgress, WorkerEvent};
        use dsk_core::video::ffmpeg::{EncoderCaps, FfmpegTools, VideoStreamInfo};
        use dsk_core::video::{
            BatchReport, EncoderKind, HeldOriginal, OriginalDisposition, ProbeInfo, Quality,
            QualityMetric, SampleResult, SkipReason, VideoCandidate, VideoDiscovery, VideoEngine,
            VideoJobOutcome, VideoJobStatus, VideoPhase, VideoProgress,
        };

        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.active_tab = ActiveTab::Videos;
        app.state.volumes = vec![VolumeInfo {
            root: r"\\?\C:\".into(),
            ..Default::default()
        }];
        // No ffmpeg yet: the first visit asks for a probe, then the install hint renders.
        run_frames(&ctx, &mut app, 2);
        assert!(app.state.videos.engine_probe_attempted && app.state.videos.probing);
        assert!(app.state.videos.roots.contains(r"C:\"));
        app.state
            .apply_worker_event(WorkerEvent::VideoEngineProbed(None));
        run_frames(&ctx, &mut app, 1);

        app.state
            .apply_worker_event(WorkerEvent::VideoEngineProbed(Some(Arc::new(
                VideoEngine {
                    tools: FfmpegTools {
                        ffmpeg: "ffmpeg.exe".into(),
                        ffprobe: "ffprobe.exe".into(),
                    },
                    encoders: vec![EncoderCaps {
                        kind: EncoderKind::Av1Nvenc,
                        ten_bit: true,
                    }],
                    metric: QualityMetric::Vmaf,
                    version: Some("ffmpeg version 8.1".into()),
                },
            ))));
        assert!(!app.state.videos.busy());
        let cand = |p: &str, gib: u64| VideoCandidate {
            path: PathBuf::from(p),
            bytes: gib << 30,
            info: Some(ProbeInfo {
                duration_secs: 600.0,
                video: Some(VideoStreamInfo {
                    codec: "h264".into(),
                    width: 1920,
                    height: 1080,
                    fps: 30.0,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            est_output_bytes: (gib << 30) / 4,
            skip: None,
        };
        let (a, b, c) = (
            cand(r"C:\Users\A\Videos\a.mp4", 5),
            cand(r"D:\Archive\b.MOV", 2),
            cand(r"D:\Archive\c.mkv", 1),
        );
        let mut skipped = cand(r"D:\Archive\x.mp4", 1);
        skipped.skip = Some(SkipReason::AlreadyEfficient);
        app.state
            .apply_worker_event(WorkerEvent::VideosFound(Arc::new(VideoDiscovery {
                candidates: vec![a.clone(), b.clone(), c.clone()],
                skipped: vec![skipped],
                total_video_bytes: 9 << 30,
                est_saving_bytes: 6 << 30,
                excluded_app_files: 2,
            })));
        app.state.videos.selected.insert(a.path.clone());
        app.state.videos.selected.insert(b.path.clone());
        app.state.apply_worker_event(WorkerEvent::VideoSampled {
            path: b.path.clone(),
            result: Ok(SampleResult {
                source: b.path.clone(),
                sample_path: PathBuf::from(r"C:\tmp\b.sample.mkv"),
                start_secs: 285.0,
                seconds: 30.0,
                source_slice_bytes: 100 << 20,
                sample_bytes: 25 << 20,
                ratio: 0.25,
                projected_output_bytes: 512 << 20,
                score: Some(96.7),
                metric: QualityMetric::Vmaf,
                encoder: EncoderKind::Av1Nvenc,
                speed: 7.7,
            }),
        });
        app.state.apply_worker_event(WorkerEvent::VideoSampled {
            path: c.path.clone(),
            result: Err("no video stream".into()),
        });
        app.state.videos.held = vec![HeldOriginal {
            id: 1,
            held_path: PathBuf::from(r"C:\Users\A\DiskSaver Originals\2026-11-18\a.mp4"),
            original_path: a.path.clone(),
            output_path: a.path.clone(),
            bytes: 5 << 30,
            held_exists: true,
            replacement_ok: true,
        }];
        app.state.videos.held_loaded = true;
        run_frames(&ctx, &mut app, 3);

        // A running batch, then a finished file.
        app.state.videos.compressing = true;
        app.state
            .apply_worker_event(WorkerEvent::VideosProgress(VideosProgress::Compress(
                VideoProgress {
                    file_index: 0,
                    file_count: 2,
                    path: a.path.clone(),
                    phase: VideoPhase::Encoding,
                    fraction: 0.4,
                    speed: 3.1,
                    saved_so_far: 0,
                },
            )));
        run_frames(&ctx, &mut app, 2);
        let done = VideoJobOutcome {
            path: a.path.clone(),
            output_path: Some(a.path.clone()),
            status: VideoJobStatus::Replaced,
            original_bytes: 5 << 30,
            new_bytes: 1 << 30,
            score: Some(96.9),
            min_segment_score: Some(95.0),
            metric: Some(QualityMetric::Vmaf),
            encoder: Some(EncoderKind::Av1Nvenc),
            quality: Quality::Balanced,
            elapsed_secs: 600.0,
            disposition: OriginalDisposition::Held(PathBuf::from(r"C:\held\a.mp4")),
            message: None,
        };
        app.state
            .apply_worker_event(WorkerEvent::VideoFileDone(done.clone()));
        assert!(app.state.videos.results.contains_key(&a.path));
        assert!(!app.state.videos.selected.contains(&a.path));
        app.state
            .apply_worker_event(WorkerEvent::VideosCompressed(BatchReport {
                outcomes: vec![done],
                replaced: 1,
                saved_bytes: 4 << 30,
                recycle_bin_bytes: 0,
                held_bytes: 5 << 30,
                stopped: Some("cancelled".into()),
            }));
        assert!(!app.state.videos.compressing && !app.state.videos.held_loaded);
        app.state.videos.held_loaded = true;
        run_frames(&ctx, &mut app, 2);

        // Both confirmation dialogs.
        app.state.videos.confirm = Some(VideoConfirm::Compress {
            paths: vec![b.path.clone()],
            bytes: 2 << 30,
            saving: 1 << 30,
            hours: 0.2,
        });
        run_frames(&ctx, &mut app, 2);
        app.state.videos.confirm = Some(VideoConfirm::PurgeHeld {
            count: 1,
            bytes: 5 << 30,
        });
        run_frames(&ctx, &mut app, 2);
        app.state.videos.confirm = None;

        // Inspecting progress, then a cancelled Videos lane clears every flag.
        app.state.videos.finding = true;
        app.state
            .apply_worker_event(WorkerEvent::VideosProgress(VideosProgress::Inspecting(
                3, 10,
            )));
        run_frames(&ctx, &mut app, 1);
        app.state
            .apply_worker_event(WorkerEvent::JobCancelled(JobLane::Videos));
        assert!(!app.state.videos.busy());
        assert!(!app.state.heavy_busy());
        assert_eq!(parse_tab("videos"), Some(ActiveTab::Videos));
    }

    #[test]
    fn light_mode_and_collapsed_sidebar_render_all_tabs_without_panic() {
        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.scan_report = Some(make_test_report());
        app.state.raw_plan = Some(make_test_plan());
        app.state.sidebar_collapsed = true;
        app.toggle_theme(&ctx);
        assert!(!app.theme.is_dark);
        assert_eq!(ctx.theme(), egui::Theme::Light);

        for tab in [
            ActiveTab::Overview,
            ActiveTab::Explore,
            ActiveTab::Cleanup,
            ActiveTab::Optimize,
            ActiveTab::Insights,
            ActiveTab::Videos,
            ActiveTab::History,
        ] {
            app.state.active_tab = tab;
            run_frames(&ctx, &mut app, 2);
        }

        app.state.show_shortcuts_modal = true;
        run_frames(&ctx, &mut app, 1);
    }

    #[test]
    fn reclaim_jump_routes_every_action_ref_to_expected_tab_and_state() {
        use crate::views::insights::InsightsSubtab;
        use crate::views::reclaim::jump_for_opportunity;
        use dsk_core::ledger::{ActionRef, Confidence, Lane, Opportunity, Reversibility};
        use dsk_core::optimize::{OptimizerIntent, WofAlgorithm};

        let mut app = test_app();
        app.state.scan_report = Some(make_test_report());

        let opp = |action: ActionRef, path: Option<&str>| Opportunity {
            id: "test".to_string(),
            lane: Lane::Regenerable,
            title: "Test".to_string(),
            detail: "Detail".to_string(),
            path: path.map(PathBuf::from),
            est_bytes: 128 * 1024 * 1024,
            raw_est_bytes: 128 * 1024 * 1024,
            confidence: Confidence::Measured,
            reversibility: Reversibility::Regenerable,
            requires_admin: false,
            action,
            score: 1.0,
            calibration: None,
        };

        // CleanRule (Review tier widens filter & inspects rule)
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::CleanRule {
                    rule_id: "os.temp".into(),
                    tier: RuleTier::Review,
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Cleanup);
        assert_eq!(
            app.cleanup_state.inspected_rule_id.as_deref(),
            Some("os.temp")
        );
        assert_eq!(app.cleanup_state.selected_tier_filter, None);

        // CompressFolder -> Optimize with prefilled path & algorithm
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::CompressFolder {
                    path: PathBuf::from(r"D:\Games"),
                    algorithm: WofAlgorithm::Lzx,
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Optimize);
        assert_eq!(app.optimize_state.wof_target_folder, r"D:\Games");
        assert_eq!(app.optimize_state.wof_algo, WofAlgorithm::Lzx);

        // Optimizer / CompactVhdx -> Optimize
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::Optimizer {
                    intent: OptimizerIntent::SetCompactOs { enable: true },
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Optimize);

        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::CompactVhdx {
                    path: PathBuf::from(r"C:\wsl\ext4.vhdx"),
                    distro: Some("Ubuntu".into()),
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Optimize);

        // DupeGroup -> Insights > Duplicates
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::DupeGroup {
                    blake3_hex: "abc".into(),
                    hardlink: false,
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Insights);
        assert_eq!(app.insights_state.subtab, InsightsSubtab::Duplicates);

        // LauncherGame -> Insights > GamingOrphans + title filter
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::LauncherGame {
                    store: "Steam".into(),
                    title: "Counter-Strike".into(),
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Insights);
        assert_eq!(app.insights_state.subtab, InsightsSubtab::GamingOrphans);
        assert_eq!(app.insights_state.filter_text, "Counter-Strike");

        // UninstallApp -> Insights > ColdData + name filter
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::UninstallApp {
                    name: "OldTool".into(),
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Insights);
        assert_eq!(app.insights_state.subtab, InsightsSubtab::ColdData);
        assert_eq!(app.insights_state.filter_text, "OldTool");

        // SweepBuildOutput fallback -> Insights > Projects
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::SweepBuildOutput {
                    root: PathBuf::from(r"Z:\NonExistent\target"),
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Insights);
        assert_eq!(app.insights_state.subtab, InsightsSubtab::Projects);

        // CompressVideo -> Videos
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::CompressVideo {
                    path: PathBuf::from(r"C:\clip.mp4"),
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Videos);

        // RecyclePath inside index -> Explore zoomed to parent dir with file selected
        let j = jump_for_opportunity(
            &app.state,
            &opp(
                ActionRef::RecyclePath {
                    path: PathBuf::from(r"C:\Windows\Temp\file.log"),
                },
                None,
            ),
        )
        .unwrap();
        app.apply_reclaim_jump(j);
        assert_eq!(app.state.active_tab, ActiveTab::Explore);
        assert_ne!(app.state.zoom_root, ROOT);
        assert!(app.state.selected_node.is_some());
    }

    #[test]
    fn keyboard_shortcuts_switch_tabs_and_toggle_sidebar_without_hijacking_text_input() {
        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.scan_report = Some(make_test_report());

        let send_key = |ctx: &egui::Context,
                        app: &mut DiskSaverApp,
                        key: egui::Key,
                        modifiers: egui::Modifiers| {
            let raw = egui::RawInput {
                events: vec![egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers,
                }],
                ..Default::default()
            };
            let output = ctx.run_ui(raw, |ui| {
                app.render(ui);
            });
            output.drop_without_applying_deltas();
        };

        // Prime initial frame
        run_frames(&ctx, &mut app, 1);

        // Ctrl+2 switches to Explore
        send_key(&ctx, &mut app, egui::Key::Num2, egui::Modifiers::COMMAND);
        assert_eq!(app.state.active_tab, ActiveTab::Explore);

        // Ctrl+B toggles sidebar
        assert!(!app.state.sidebar_collapsed);
        send_key(&ctx, &mut app, egui::Key::B, egui::Modifiers::COMMAND);
        assert!(app.state.sidebar_collapsed);

        // Ctrl+Shift+T toggles Light theme
        send_key(
            &ctx,
            &mut app,
            egui::Key::T,
            egui::Modifiers {
                command: true,
                ctrl: true,
                shift: true,
                ..egui::Modifiers::NONE
            },
        );
        assert!(!app.theme.is_dark);

        // Escape closes shortcuts modal
        app.state.show_shortcuts_modal = true;
        send_key(&ctx, &mut app, egui::Key::Escape, egui::Modifiers::NONE);
        assert!(!app.state.show_shortcuts_modal);

        // Focused text input prevents Backspace / Ctrl+B from triggering app navigation
        let zoom_parent = app
            .state
            .scan_report
            .as_ref()
            .unwrap()
            .index
            .find_by_path(std::path::Path::new(r"C:\Windows\Temp"));
        if let Some(nid) = zoom_parent {
            app.state.zoom_into(nid);
        }
        let prev_zoom = app.state.zoom_root;
        let prev_collapsed = app.state.sidebar_collapsed;

        let text_id = egui::Id::unique("test_focused_text_input");
        let mut buf = "hello".to_string();
        let prime = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.add(egui::TextEdit::singleline(&mut buf).id(text_id));
            ui.ctx().memory_mut(|m| m.request_focus(text_id));
            app.render(ui);
        });
        prime.drop_without_applying_deltas();

        let out = ctx.run_ui(
            egui::RawInput {
                events: vec![
                    egui::Event::Key {
                        key: egui::Key::Backspace,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    },
                    egui::Event::Key {
                        key: egui::Key::B,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers: egui::Modifiers::COMMAND,
                    },
                ],
                ..Default::default()
            },
            |ui| {
                ui.add(egui::TextEdit::singleline(&mut buf).id(text_id));
                assert!(ui.ctx().text_edit_focused());
                app.render(ui);
            },
        );
        out.drop_without_applying_deltas();
        assert_eq!(app.state.zoom_root, prev_zoom);
        assert_eq!(app.state.sidebar_collapsed, prev_collapsed);
    }

    #[test]
    fn all_tabs_render_cleanly_at_minimum_viewport_in_both_themes() {
        let ctx = egui::Context::default();
        let mut app = test_app();
        app.state.scan_report = Some(make_test_report());
        app.state.status_banner = Some(crate::app_state::StatusBanner {
            kind: BannerKind::Info,
            message: "Verification status banner".into(),
        });

        let tabs = [
            ActiveTab::Overview,
            ActiveTab::Explore,
            ActiveTab::Cleanup,
            ActiveTab::Optimize,
            ActiveTab::Insights,
            ActiveTab::Videos,
            ActiveTab::History,
        ];

        for &dark in &[true, false] {
            app.theme = if dark {
                ThemeTokens::dark()
            } else {
                ThemeTokens::light()
            };
            app.applied_theme_is_dark = None;

            for &collapsed in &[false, true] {
                app.state.sidebar_collapsed = collapsed;
                for tab in tabs {
                    app.state.active_tab = tab;
                    let raw = egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(900.0, 600.0))),
                        ..Default::default()
                    };
                    let out = ctx.run_ui(raw, |ui| {
                        app.render(ui);
                    });
                    assert!(
                        !out.shapes.is_empty(),
                        "expected painted shapes for {tab:?} (dark={dark}, collapsed={collapsed})"
                    );
                    out.drop_without_applying_deltas();
                }
            }
        }
    }
}
