//! Videos tab (P9.11): find big, inefficiently encoded videos on every drive, preview the result,
//! and shrink the selected ones with a verified AV1/HEVC re-encode.
//!
//! Nothing is replaced until the new file passed the quality check; originals go to the Recycle
//! Bin (or a "DiskSaver Originals" folder when too big for it). The batch runs on its own worker
//! lane, so scanning or cleaning elsewhere never cancels it.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dsk_core::video::{
    BatchReport, CompressOptions, DiscoverOptions, EncoderPref, HeldOriginal, OriginalDisposition,
    OriginalPolicy, Quality, SampleResult, TargetCodec, VideoCandidate, VideoDiscovery,
    VideoEngine, VideoJobOutcome, VideoJobStatus, VideoPhase, VideoProgress,
};
use eframe::egui::{self, Align, RichText};

use crate::app_state::{AppState, BannerKind, StatusBanner};
use crate::theme::{ThemeTokens, fmt_bytes};
use crate::ui_kit::{self, Icon};
use crate::worker::{VideosProgress, WorkerHandle, WorkerJob};

/// Confirmation the Videos tab is waiting for.
#[derive(Clone, Debug, PartialEq)]
pub enum VideoConfirm {
    Compress {
        paths: Vec<PathBuf>,
        bytes: u64,
        saving: u64,
        hours: f64,
    },
    PurgeHeld {
        count: usize,
        bytes: u64,
    },
}

/// Sort order of the candidate table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VideoSort {
    #[default]
    Saving,
    Size,
    Bitrate,
    Path,
}

/// Everything the Videos tab keeps between frames.
#[derive(Debug)]
pub struct VideosState {
    pub engine: Option<Arc<VideoEngine>>,
    pub engine_probe_attempted: bool,
    pub probing: bool,
    /// Drive roots (`C:\`) to search; filled from the drive list on first render.
    pub roots: BTreeSet<String>,
    pub roots_initialized: bool,
    /// Extra folder to search (e.g. an archive on a network drive).
    pub extra_folder: String,
    pub min_size_mib: u64,
    pub codec: TargetCodec,
    pub quality: Quality,
    pub originals: OriginalPolicy,
    pub sort: VideoSort,
    pub finding: bool,
    pub progress: Option<VideosProgress>,
    pub discovery: Option<Arc<VideoDiscovery>>,
    pub selected: BTreeSet<PathBuf>,
    pub samples: HashMap<PathBuf, Result<SampleResult, String>>,
    pub sampling: Option<PathBuf>,
    pub compressing: bool,
    pub results: HashMap<PathBuf, VideoJobOutcome>,
    pub last_batch: Option<BatchReport>,
    pub held: Vec<HeldOriginal>,
    pub held_loaded: bool,
    pub loading_held: bool,
    pub purging: bool,
    pub confirm: Option<VideoConfirm>,
    pub show_skipped: bool,
}

impl Default for VideosState {
    fn default() -> Self {
        Self {
            engine: None,
            engine_probe_attempted: false,
            probing: false,
            roots: BTreeSet::new(),
            roots_initialized: false,
            extra_folder: String::new(),
            min_size_mib: 200,
            codec: TargetCodec::Av1,
            quality: Quality::Balanced,
            originals: OriginalPolicy::Recycle,
            sort: VideoSort::Saving,
            finding: false,
            progress: None,
            discovery: None,
            selected: BTreeSet::new(),
            samples: HashMap::new(),
            sampling: None,
            compressing: false,
            results: HashMap::new(),
            last_batch: None,
            held: Vec::new(),
            held_loaded: false,
            loading_held: false,
            purging: false,
            confirm: None,
            show_skipped: false,
        }
    }
}

impl VideosState {
    /// A job runs on the Videos lane (starting another would cancel it).
    pub fn busy(&self) -> bool {
        self.probing
            || self.finding
            || self.sampling.is_some()
            || self.compressing
            || self.loading_held
            || self.purging
    }

    /// Clears every busy flag (job error or cancel on the Videos lane).
    pub fn clear_busy(&mut self) {
        self.probing = false;
        self.finding = false;
        self.sampling = None;
        self.compressing = false;
        self.loading_held = false;
        self.purging = false;
        self.progress = None;
    }

    /// Short label for the running job.
    pub fn activity_label(&self) -> Option<&'static str> {
        if self.compressing {
            Some("Compressing videos...")
        } else if self.finding {
            Some("Finding videos...")
        } else if self.sampling.is_some() {
            Some("Encoding a preview...")
        } else if self.probing {
            Some("Detecting video encoders...")
        } else if self.purging {
            Some("Deleting held originals...")
        } else if self.loading_held {
            Some("Loading held originals...")
        } else {
            None
        }
    }

    fn compress_options(&self, journal: Option<PathBuf>) -> CompressOptions {
        CompressOptions {
            codec: self.codec,
            quality: self.quality,
            encoder: EncoderPref::Auto,
            originals: self.originals,
            journal_path: Some(journal.unwrap_or_else(dsk_core::ActionJournal::default_path)),
            ..Default::default()
        }
    }

    /// Selected candidates that have not been compressed yet.
    fn pending_selection(&self) -> Vec<&VideoCandidate> {
        let Some(d) = &self.discovery else {
            return Vec::new();
        };
        d.candidates
            .iter()
            .filter(|c| self.selected.contains(&c.path) && !self.results.contains_key(&c.path))
            .collect()
    }
}

fn fmt_duration(secs: f64) -> String {
    let s = secs.max(0.0).round() as u64;
    match (s / 3600, (s % 3600) / 60, s % 60) {
        (0, 0, sec) => format!("{sec}s"),
        (0, m, sec) => format!("{m}m{sec:02}s"),
        (h, m, _) => format!("{h}h{m:02}m"),
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn reveal_async(p: &Path) {
    let path = p.to_path_buf();
    std::thread::spawn(move || {
        let _ = dsk_core::reveal_in_explorer(&path);
    });
}

fn open_async(p: &Path) {
    let path = p.to_path_buf();
    std::thread::spawn(move || {
        let _ = dsk_core::open_item(&path);
    });
}

fn engine_status(
    ui: &mut egui::Ui,
    st: &VideosState,
    state_spawn: &mut Option<WorkerJob>,
    tokens: &ThemeTokens,
) {
    if st.probing {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(
                RichText::new("Detecting ffmpeg and video encoders...")
                    .size(12.0)
                    .color(tokens.info),
            );
        });
        return;
    }

    match &st.engine {
        Some(e) => {
            let enc = e
                .encoder_for(st.codec, EncoderPref::Auto)
                .map(|c| {
                    format!(
                        "{} ({}-bit)",
                        c.kind.label(),
                        if c.ten_bit { 10 } else { 8 }
                    )
                })
                .unwrap_or_else(|| format!("no working {} encoder", st.codec.label()));
            ui.horizontal_wrapped(|ui| {
                ui_kit::pill_badge(
                    ui,
                    e.version.as_deref().unwrap_or("ffmpeg"),
                    tokens.info,
                    tokens,
                );
                ui_kit::pill_badge(ui, &enc, tokens.success, tokens);
                ui_kit::pill_badge(
                    ui,
                    &format!("Quality gate: {}", e.metric.label()),
                    tokens.purple,
                    tokens,
                );
            });
        }
        None => {
            ui_kit::callout_banner(
                ui,
                tokens,
                tokens.warning,
                Icon::Warning,
                "ffmpeg was not found — DiskSaver uses your own copy to encode.",
                None,
                false,
            );
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.code(dsk_core::video::INSTALL_HINT);
                if ui_kit::secondary_button(ui, "Copy", true, tokens).clicked() {
                    ui.ctx()
                        .copy_text(dsk_core::video::INSTALL_HINT.to_string());
                }
                if ui_kit::primary_button(ui, "Retry", !st.busy(), tokens)
                    .on_hover_text("Look for ffmpeg again after installing it")
                    .clicked()
                {
                    *state_spawn = Some(WorkerJob::ProbeVideoEngine);
                }
            });
        }
    }
}

/// Renders the Videos tab.
pub fn render(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    tokens: &ThemeTokens,
) {
    // First visit: detect the encoder once.
    if !state.videos.engine_probe_attempted && !state.videos.busy() {
        state.spawn_job(worker, WorkerJob::ProbeVideoEngine);
    }
    if !state.videos.roots_initialized && !state.volumes.is_empty() {
        state.videos.roots_initialized = true;
        for v in &state.volumes {
            let r = v.root.trim_start_matches(r"\\?\");
            if r.len() >= 2 {
                state.videos.roots.insert(format!("{}\\", &r[..2]));
            }
        }
    }

    let mut spawn: Option<WorkerJob> = None;
    egui::ScrollArea::vertical()
        .id_salt("videos_tab_scroll")
        .show(ui, |ui| {
            ui.add_space(4.0);
            ui_kit::section_header(
                ui,
                "Shrink Videos",
                Some(
                    "Re-encodes large videos to AV1 or HEVC on your GPU. Originals are replaced only after a VMAF quality check passes.",
                ),
                tokens,
            );
            ui.add_space(6.0);
            engine_status(ui, &state.videos, &mut spawn, tokens);
            ui.add_space(8.0);
            render_controls(ui, state, &mut spawn, tokens);
            ui.add_space(8.0);
            render_progress(ui, state, worker, tokens);
            ui.add_space(6.0);
            render_table(ui, state, &mut spawn, tokens);
            ui.add_space(10.0);
            render_held(ui, state, &mut spawn, tokens);
            ui.add_space(12.0);
        });
    if let Some(job) = spawn
        && !state.videos.busy()
    {
        state.spawn_job(worker, job);
    }
    render_confirm(ui.ctx(), state, worker, tokens);
}

fn render_controls(
    ui: &mut egui::Ui,
    state: &mut AppState,
    spawn: &mut Option<WorkerJob>,
    tokens: &ThemeTokens,
) {
    let st = &mut state.videos;
    let busy = st.busy();

    ui_kit::card_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let extra = st.extra_folder.trim();
        let mut roots: Vec<PathBuf> = if extra.is_empty() {
            st.roots.iter().map(PathBuf::from).collect()
        } else {
            vec![PathBuf::from(extra)]
        };
        roots.retain(|r| r.exists());

        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            if ui_kit::primary_button(ui, "Find Videos", !busy && !roots.is_empty(), tokens)
                .on_hover_text("Scans the chosen drives (read-only) and inspects every big video")
                .clicked()
            {
                *spawn = Some(WorkerJob::FindVideos {
                    roots,
                    opts: DiscoverOptions {
                        min_bytes: st.min_size_mib << 20,
                        codec: st.codec,
                        quality: st.quality,
                        ..Default::default()
                    },
                    engine: st.engine.clone(),
                    journal_path: state.journal_path.clone(),
                });
            }

            ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Search:").size(12.0).color(tokens.text_secondary));
                    let drives: Vec<String> = state
                        .volumes
                        .iter()
                        .filter_map(|v| {
                            let r = v.root.trim_start_matches(r"\\?\");
                            (r.len() >= 2).then(|| format!("{}\\", &r[..2]))
                        })
                        .collect();
                    for d in drives {
                        let mut on = st.roots.contains(&d);
                        if ui
                            .add_enabled(!busy, egui::Checkbox::new(&mut on, &d))
                            .changed()
                        {
                            if on {
                                st.roots.insert(d);
                            } else {
                                st.roots.remove(&d);
                            }
                        }
                    }
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut st.extra_folder)
                            .hint_text("or a folder: D:\\Archive")
                            .desired_width(170.0),
                    );
                    ui.label(RichText::new("Min:").size(12.0).color(tokens.text_secondary));
                    egui::ComboBox::from_id_salt("videos_min_size")
                        .selected_text(if st.min_size_mib >= 1024 {
                            format!("{} GB", st.min_size_mib / 1024)
                        } else {
                            format!("{} MB", st.min_size_mib)
                        })
                        .show_ui(ui, |ui| {
                            for (v, l) in [
                                (100, "100 MB"),
                                (200, "200 MB"),
                                (500, "500 MB"),
                                (1024, "1 GB"),
                            ] {
                                ui.selectable_value(&mut st.min_size_mib, v, l);
                            }
                        });
                });
            });
        });

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Codec:").size(12.0).color(tokens.text_secondary));
            ui.add_enabled_ui(!busy, |ui| {
                if ui_kit::chip_toggle(ui, st.codec == TargetCodec::Av1, "AV1", None, tokens)
                    .on_hover_text("Smallest files. Plays in Windows, browsers, VLC, recent phones and TVs.")
                    .clicked()
                {
                    st.codec = TargetCodec::Av1;
                }
                if ui_kit::chip_toggle(ui, st.codec == TargetCodec::Hevc, "HEVC", None, tokens)
                    .on_hover_text("About 30% bigger than AV1; plays on more older TVs and phones.")
                    .clicked()
                {
                    st.codec = TargetCodec::Hevc;
                }
            });

            ui_kit::inline_divider(ui, tokens);
            ui.label(RichText::new("Quality:").size(12.0).color(tokens.text_secondary));
            ui.add_enabled_ui(!busy, |ui| {
                for (q, lbl, tip) in [
                    (Quality::High, "High", "For irreplaceable footage: VMAF ~98."),
                    (Quality::Balanced, "Balanced", "Looks the same for almost all footage: VMAF ~95-97."),
                    (Quality::Small, "Small", "Smallest; slight visible loss on grainy footage."),
                ] {
                    if ui_kit::chip_toggle(ui, st.quality == q, lbl, None, tokens)
                        .on_hover_text(tip)
                        .clicked()
                    {
                        st.quality = q;
                    }
                }
            });

            ui_kit::inline_divider(ui, tokens);
            ui.label(RichText::new("Originals:").size(12.0).color(tokens.text_secondary));
            ui.add_enabled_ui(!busy, |ui| {
                for (pol, lbl, tip) in [
                    (OriginalPolicy::Recycle, "Recycle Bin", "Space returns when you empty the bin. Huge originals move to \"DiskSaver Originals\"."),
                    (OriginalPolicy::Hold, "Holding folder", "Moved to \"DiskSaver Originals\" on the same drive."),
                    (OriginalPolicy::KeepBoth, "Keep both", "New file is written beside the original."),
                ] {
                    if ui_kit::chip_toggle(ui, st.originals == pol, lbl, None, tokens)
                        .on_hover_text(tip)
                        .clicked()
                    {
                        st.originals = pol;
                    }
                }
            });
        });
    });
}

fn render_progress(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    tokens: &ThemeTokens,
) {
    let st = &state.videos;
    if !st.busy() {
        if let Some(b) = &st.last_batch {
            render_batch_summary(ui, b, tokens);
        }
        return;
    }
    ui_kit::accent_card(ui, tokens, tokens.info, |ui| {
        ui.horizontal(|ui| {
            ui.spinner();
            match &st.progress {
                Some(VideosProgress::Scanning(root, n)) => {
                    ui.label(format!("Scanning {} ({n} entries)...", root.display()));
                }
                Some(VideosProgress::Inspecting(done, total)) => {
                    let f = if *total > 0 {
                        *done as f32 / *total as f32
                    } else {
                        0.0
                    };
                    ui_kit::progress_bar(
                        ui,
                        f,
                        9.0,
                        tokens.info,
                        Some(&format!("Inspecting videos {done}/{total}")),
                        tokens,
                    );
                }
                Some(VideosProgress::Compress(p)) => render_compress_progress(ui, p, tokens),
                None => {
                    ui.label(st.activity_label().unwrap_or("Working..."));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if ui_kit::danger_button(ui, "Cancel", true, tokens).clicked() {
                    worker.cancel_lane(crate::worker::JobLane::Videos);
                }
            });
        });
    });
}

fn render_compress_progress(ui: &mut egui::Ui, p: &VideoProgress, tokens: &ThemeTokens) {
    let overall = (p.file_index as f64 + p.fraction) / p.file_count.max(1) as f64;
    let what = match &p.phase {
        VideoPhase::Waiting(w) => w.clone(),
        VideoPhase::Encoding => {
            format!("encoding {:.0}% at {:.1}x", p.fraction * 100.0, p.speed)
        }
        VideoPhase::Verifying => "checking quality".into(),
        VideoPhase::Replacing => "replacing".into(),
    };
    ui_kit::progress_bar(
        ui,
        overall as f32,
        9.0,
        tokens.accent,
        Some(&format!(
            "{}/{} · {} — {what}",
            p.file_index + 1,
            p.file_count,
            file_name(&p.path)
        )),
        tokens,
    );
    if p.saved_so_far > 0 {
        ui_kit::pill_badge(
            ui,
            &format!("Saved {}", fmt_bytes(p.saved_so_far)),
            tokens.success,
            tokens,
        );
    }
}

fn render_batch_summary(ui: &mut egui::Ui, b: &BatchReport, tokens: &ThemeTokens) {
    let kept = b
        .outcomes
        .iter()
        .filter(|o| o.status == VideoJobStatus::KeptBoth)
        .count();
    let msg = format!(
        "Last run: {} of {} videos replaced, saving {}.{}",
        b.replaced,
        b.outcomes.len(),
        fmt_bytes(b.saved_bytes),
        if kept > 0 {
            format!(" {kept} compressed copies written next to their originals.")
        } else {
            String::new()
        }
    );
    let mut details = Vec::new();
    if b.recycle_bin_bytes > 0 {
        details.push(format!(
            "{} of originals are in the Recycle Bin (space returns when emptied).",
            fmt_bytes(b.recycle_bin_bytes)
        ));
    }
    if b.held_bytes > 0 {
        details.push(format!(
            "{} of originals wait in \"DiskSaver Originals\" below.",
            fmt_bytes(b.held_bytes)
        ));
    }
    if let Some(s) = &b.stopped {
        details.push(format!("Stopped early: {s}."));
    }
    let body = (!details.is_empty()).then(|| details.join(" "));
    let accent = if b.stopped.is_some() {
        tokens.warning
    } else {
        tokens.success
    };
    ui_kit::callout_banner(
        ui,
        tokens,
        accent,
        Icon::Check,
        &msg,
        body.as_deref(),
        false,
    );
}

fn sorted_candidates(d: &VideoDiscovery, sort: VideoSort) -> Vec<&VideoCandidate> {
    let mut v: Vec<&VideoCandidate> = d.candidates.iter().collect();
    match sort {
        VideoSort::Saving => v.sort_by_key(|c| std::cmp::Reverse(c.est_saving_bytes())),
        VideoSort::Size => v.sort_by_key(|c| std::cmp::Reverse(c.bytes)),
        VideoSort::Bitrate => v.sort_by(|a, b| b.bitrate_mbps().total_cmp(&a.bitrate_mbps())),
        VideoSort::Path => v.sort_by(|a, b| a.path.cmp(&b.path)),
    }
    v
}

fn render_table(
    ui: &mut egui::Ui,
    state: &mut AppState,
    spawn: &mut Option<WorkerJob>,
    tokens: &ThemeTokens,
) {
    let journal = state.journal_path.clone();
    let st = &mut state.videos;
    let Some(d) = st.discovery.clone() else {
        if !st.busy() {
            ui_kit::empty_state(
                ui,
                Icon::Videos,
                "No Video Scan Yet",
                "Choose drives above and click Find Videos to locate large inefficiently encoded videos.",
                None,
                tokens,
            );
        }
        return;
    };
    let busy = st.busy();
    let total: u64 = d.candidates.iter().map(|c| c.bytes).sum();
    let after = total.saturating_sub(d.est_saving_bytes);

    ui_kit::accent_card(ui, tokens, tokens.success, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} videos can shrink: {} → ~{}",
                    d.candidates.len(),
                    fmt_bytes(total),
                    fmt_bytes(after)
                ))
                .size(16.0)
                .strong()
                .color(tokens.text_primary),
            );
            ui_kit::pill_badge(
                ui,
                &format!("Saves ~{}", fmt_bytes(d.est_saving_bytes)),
                tokens.success,
                tokens,
            );
        });
        if total > 0 {
            ui.add_space(6.0);
            ui_kit::segmented_bar(
                ui,
                &[
                    (after as f32, tokens.info, "Compressed Size"),
                    (
                        d.est_saving_bytes as f32,
                        tokens.success,
                        "Estimated Savings",
                    ),
                ],
                8.0,
                tokens,
            );
        }

        if d.excluded_app_files > 0 {
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!(
                    "{} videos inside app, game, and system folders were left out.",
                    d.excluded_app_files
                ))
                .size(11.5)
                .color(tokens.text_secondary),
            );
        }
        let dups = d
            .skipped
            .iter()
            .filter(|c| {
                matches!(
                    c.skip,
                    Some(dsk_core::video::SkipReason::LikelyDuplicate(_))
                )
            })
            .count();
        if dups > 0 {
            ui.add_space(4.0);
            ui_kit::callout_banner(
                ui,
                tokens,
                tokens.warning,
                Icon::Warning,
                &format!(
                    "{dups} videos have an identical copy and are held back (remove duplicates first in Insights > Duplicates)."
                ),
                None,
                false,
            );
        }
    });

    ui.add_space(8.0);

    let (sel_bytes, sel_saving, sel_hours, sel_paths) = {
        let pending = st.pending_selection();
        (
            pending.iter().map(|c| c.bytes).sum::<u64>(),
            pending.iter().map(|c| c.est_saving_bytes()).sum::<u64>(),
            pending.iter().map(|c| c.duration_secs()).sum::<f64>() / 3600.0,
            pending
                .iter()
                .map(|c| c.path.clone())
                .collect::<Vec<PathBuf>>(),
        )
    };

    ui_kit::card_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            let can = !busy && !sel_paths.is_empty() && st.engine.is_some();
            if ui_kit::primary_button(
                ui,
                &format!(
                    "Compress {} selected (~{})",
                    sel_paths.len(),
                    fmt_bytes(sel_saving)
                ),
                can,
                tokens,
            )
            .clicked()
            {
                st.confirm = Some(VideoConfirm::Compress {
                    paths: sel_paths.clone(),
                    bytes: sel_bytes,
                    saving: sel_saving,
                    hours: sel_hours,
                });
            }

            ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                if ui_kit::secondary_button(ui, "Select >= 1 GB", true, tokens).clicked() {
                    st.selected = d
                        .candidates
                        .iter()
                        .filter(|c| c.bytes >= 1 << 30)
                        .map(|c| c.path.clone())
                        .collect();
                }
                if ui_kit::secondary_button(ui, "Select all", true, tokens).clicked() {
                    st.selected = d.candidates.iter().map(|c| c.path.clone()).collect();
                }
                if ui_kit::secondary_button(ui, "Clear", true, tokens).clicked() {
                    st.selected.clear();
                }
            });
        });

        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Sort:")
                    .size(12.0)
                    .color(tokens.text_secondary),
            );
            for (s, lbl) in [
                (VideoSort::Saving, "Saving"),
                (VideoSort::Size, "Size"),
                (VideoSort::Bitrate, "Bitrate"),
                (VideoSort::Path, "Path"),
            ] {
                if ui_kit::chip_toggle(ui, st.sort == s, lbl, None, tokens).clicked() {
                    st.sort = s;
                }
            }
        });

        ui.add_space(8.0);
        let rows = sorted_candidates(&d, st.sort);
        egui::ScrollArea::both()
            .id_salt("videos_table")
            .max_height(380.0)
            .show(ui, |ui| {
                egui::Grid::new("videos_grid")
                    .striped(true)
                    .min_col_width(36.0)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("");
                        ui.strong(
                            RichText::new("Size")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.strong(
                            RichText::new("After ~")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.strong(
                            RichText::new("Saves ~")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.strong(
                            RichText::new("Length")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.strong(
                            RichText::new("Video")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.strong(
                            RichText::new("Mb/s")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.strong(
                            RichText::new("File")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.strong(
                            RichText::new("Status")
                                .size(12.0)
                                .color(tokens.text_secondary),
                        );
                        ui.end_row();
                        for c in rows {
                            let mut on = st.selected.contains(&c.path);
                            let done = st.results.get(&c.path).cloned();
                            if ui
                                .add_enabled(done.is_none(), egui::Checkbox::without_text(&mut on))
                                .changed()
                            {
                                if on {
                                    st.selected.insert(c.path.clone());
                                } else {
                                    st.selected.remove(&c.path);
                                }
                            }
                            ui.label(RichText::new(fmt_bytes(c.bytes)).monospace().size(12.0));
                            ui.label(
                                RichText::new(fmt_bytes(c.est_output_bytes))
                                    .monospace()
                                    .size(12.0)
                                    .color(tokens.text_secondary),
                            );
                            ui.label(
                                RichText::new(fmt_bytes(c.est_saving_bytes()))
                                    .monospace()
                                    .strong()
                                    .size(12.0)
                                    .color(tokens.success),
                            );
                            ui.label(fmt_duration(c.duration_secs()));
                            ui.label(c.video_summary());
                            ui.label(
                                RichText::new(format!("{:.1}", c.bitrate_mbps()))
                                    .monospace()
                                    .size(12.0),
                            );
                            if ui
                                .link(file_name(&c.path))
                                .on_hover_text(c.path.display().to_string())
                                .clicked()
                            {
                                reveal_async(&c.path);
                            }
                            ui.horizontal(|ui| {
                                render_row_status(
                                    ui,
                                    st,
                                    c,
                                    done.clone(),
                                    busy,
                                    spawn,
                                    &journal,
                                    tokens,
                                );
                            });
                            ui.end_row();
                        }
                    });
            });
    });

    if !d.skipped.is_empty() {
        ui.add_space(8.0);
        ui_kit::card_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::CollapsingHeader::new(format!("Skipped ({})", d.skipped.len()))
                .id_salt("videos_skipped")
                .show(ui, |ui| {
                    egui::Grid::new("videos_skipped_grid")
                        .striped(true)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            for c in d.skipped.iter().take(300) {
                                ui.label(RichText::new(fmt_bytes(c.bytes)).monospace().size(12.0));
                                ui.label(file_name(&c.path))
                                    .on_hover_text(c.path.display().to_string());
                                ui.label(
                                    RichText::new(
                                        c.skip.as_ref().map(|s| s.label()).unwrap_or_default(),
                                    )
                                    .color(tokens.text_muted),
                                );
                                ui.end_row();
                            }
                        });
                });
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn render_row_status(
    ui: &mut egui::Ui,
    st: &VideosState,
    c: &VideoCandidate,
    done: Option<VideoJobOutcome>,
    busy: bool,
    spawn: &mut Option<WorkerJob>,
    journal: &Option<PathBuf>,
    tokens: &ThemeTokens,
) {
    if let Some(o) = done {
        let (color, text) = match o.status {
            VideoJobStatus::Replaced | VideoJobStatus::KeptBoth => (
                tokens.success,
                format!(
                    "{} ({}{})",
                    fmt_bytes(o.new_bytes),
                    o.metric.map(|m| m.label()).unwrap_or(""),
                    o.score.map(|s| format!(" {s:.1}")).unwrap_or_default()
                ),
            ),
            VideoJobStatus::Failed => (tokens.danger, o.status.label().to_string()),
            _ => (tokens.warning, o.status.label().to_string()),
        };
        let mut hover = o.message.clone().unwrap_or_default();
        if let OriginalDisposition::Held(p) = &o.disposition {
            hover = format!("Original held at {}", p.display());
        }
        let r = ui.label(RichText::new(text).color(color).strong());
        if !hover.is_empty() {
            r.on_hover_text(hover);
        }
        if let Some(out) = &o.output_path
            && ui_kit::icon_button(
                ui,
                Icon::Play,
                12.0,
                tokens.accent,
                "Play the new file",
                tokens,
            )
            .clicked()
        {
            open_async(out);
        }
        return;
    }
    if st.sampling.as_deref() == Some(c.path.as_path()) {
        ui.spinner();
        ui.label(RichText::new("previewing...").size(11.5).color(tokens.info));
        return;
    }
    match st.samples.get(&c.path) {
        Some(Ok(s)) => {
            let pass = s.score.is_some_and(|v| v >= s.metric.gate(93.0));
            ui.label(
                RichText::new(format!(
                    "preview {:.0}% · {} {}",
                    s.ratio * 100.0,
                    s.metric.label(),
                    s.score
                        .map(|v| format!("{v:.1}"))
                        .unwrap_or_else(|| "?".into())
                ))
                .color(if pass { tokens.success } else { tokens.warning }),
            )
            .on_hover_text(format!(
                "30 s preview with {}: whole file about {} ({:.1}x real time)",
                s.encoder.label(),
                fmt_bytes(s.projected_output_bytes),
                s.speed
            ));
            if ui_kit::icon_button(ui, Icon::Play, 12.0, tokens.accent, "Watch preview", tokens)
                .clicked()
            {
                open_async(&s.sample_path);
            }
        }
        Some(Err(e)) => {
            ui.label(RichText::new("preview failed").color(tokens.danger))
                .on_hover_text(e);
        }
        None => {
            if let Some(engine) = &st.engine
                && ui_kit::secondary_button(ui, "Preview", !busy, tokens)
                    .on_hover_text("Encode 30 s from the middle and measure size and quality")
                    .clicked()
            {
                *spawn = Some(WorkerJob::SampleVideo {
                    engine: engine.clone(),
                    path: c.path.clone(),
                    opts: st.compress_options(journal.clone()),
                });
            }
        }
    }
}

fn render_held(
    ui: &mut egui::Ui,
    state: &mut AppState,
    spawn: &mut Option<WorkerJob>,
    tokens: &ThemeTokens,
) {
    let journal = state.journal_path.clone();
    let st = &mut state.videos;
    ui_kit::card_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::CollapsingHeader::new("Held Originals")
            .id_salt("videos_held")
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Originals too big for the Recycle Bin wait in \"DiskSaver Originals\" folders until you check the new files.")
                        .size(11.5)
                        .color(tokens.text_secondary),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui_kit::secondary_button(ui, "Refresh", !st.busy(), tokens).clicked()
                        || (!st.held_loaded && !st.busy())
                    {
                        *spawn = Some(WorkerJob::LoadHeldVideos {
                            journal_path: journal.clone(),
                        });
                    }
                    let ready: Vec<&HeldOriginal> = st
                        .held
                        .iter()
                        .filter(|h| h.held_exists && h.replacement_ok)
                        .collect();
                    let bytes: u64 = ready.iter().map(|h| h.bytes).sum();
                    if ui_kit::danger_button(
                        ui,
                        &format!("Delete {} held originals ({})", ready.len(), fmt_bytes(bytes)),
                        !st.busy() && !ready.is_empty(),
                        tokens,
                    )
                    .clicked()
                    {
                        st.confirm = Some(VideoConfirm::PurgeHeld {
                            count: ready.len(),
                            bytes,
                        });
                    }
                });
                if st.held.is_empty() && st.held_loaded {
                    ui.label(RichText::new("None.").color(tokens.text_muted));
                }
                egui::Grid::new("videos_held_grid")
                    .striped(true)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        for h in &st.held {
                            ui.label(RichText::new(fmt_bytes(h.bytes)).monospace().size(12.0));
                            if ui
                                .link(file_name(&h.held_path))
                                .on_hover_text(h.held_path.display().to_string())
                                .clicked()
                            {
                                reveal_async(&h.held_path);
                            }
                            ui.label(format!("→ {}", file_name(&h.output_path)))
                                .on_hover_text(h.output_path.display().to_string());
                            if !h.held_exists {
                                ui_kit::pill_badge(
                                    ui,
                                    "already deleted",
                                    tokens.text_muted,
                                    tokens,
                                );
                            } else if !h.replacement_ok {
                                ui_kit::pill_badge(
                                    ui,
                                    "replacement missing: kept",
                                    tokens.warning,
                                    tokens,
                                );
                            } else {
                                ui_kit::pill_badge(ui, "ready to delete", tokens.success, tokens);
                            }
                            ui.end_row();
                        }
                    });
            });
    });
}

fn render_confirm(
    ctx: &egui::Context,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    tokens: &ThemeTokens,
) {
    let Some(confirm) = state.videos.confirm.clone() else {
        return;
    };
    let mut close = false;
    let mut start: Option<WorkerJob> = None;
    egui::Modal::new(egui::Id::unique("videos_confirm_modal"))
        .frame(ui_kit::modal_frame(tokens))
        .backdrop_color(tokens.modal_backdrop)
        .show(ctx, |ui| {
            ui.set_width(460.0);
            match &confirm {
                VideoConfirm::Compress {
                    paths,
                    bytes,
                    saving,
                    hours,
                } => {
                    let st = &state.videos;
                    ui.horizontal(|ui| {
                        ui_kit::icon_widget(ui, Icon::Videos, 18.0, tokens.accent);
                        ui.heading("Compress Videos");
                    });
                    ui.separator();
                    ui_kit::inset_frame(tokens).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(format!(
                            "{} videos · {} ({hours:.1} h of footage) → {} {}",
                            paths.len(),
                            fmt_bytes(*bytes),
                            st.codec.label(),
                            st.quality.label()
                        ));
                        ui.label(
                            RichText::new(format!("Estimated saving: ~{}", fmt_bytes(*saving)))
                                .strong()
                                .color(tokens.success),
                        );
                    });
                    ui.add_space(6.0);
                    ui.label("Each file is encoded next to the original, then verified: same length and streams, clearly smaller, and VMAF >= 93. Files that miss are kept.");
                    ui.label(match st.originals {
                        OriginalPolicy::Recycle => "Originals go to the Recycle Bin (or \"DiskSaver Originals\" if oversized).",
                        OriginalPolicy::Hold => "Originals move to \"DiskSaver Originals\" on the same drive.",
                        OriginalPolicy::KeepBoth => "Originals stay beside each new file.",
                    });
                    ui.add_space(4.0);
                    ui_kit::callout_banner(
                        ui,
                        tokens,
                        tokens.info,
                        Icon::Info,
                        "Runs at low priority, pauses during full-screen games, and stops on battery.",
                        None,
                        false,
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui_kit::secondary_button(ui, "Cancel", true, tokens).clicked() {
                            close = true;
                        }
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            let can = !state.videos.busy() && state.videos.engine.is_some();
                            if ui_kit::primary_button(ui, "Start Encoding", can, tokens).clicked()
                                && let Some(engine) = state.videos.engine.clone()
                            {
                                start = Some(WorkerJob::CompressVideos {
                                    engine,
                                    paths: paths.clone(),
                                    opts: state.videos.compress_options(state.journal_path.clone()),
                                });
                                close = true;
                            }
                        });
                    });
                }
                VideoConfirm::PurgeHeld { count, bytes } => {
                    ui.horizontal(|ui| {
                        ui_kit::icon_widget(ui, Icon::Trash, 18.0, tokens.danger);
                        ui.heading("Delete Held Originals");
                    });
                    ui.separator();
                    ui_kit::callout_banner(
                        ui,
                        tokens,
                        tokens.danger,
                        Icon::Warning,
                        &format!(
                            "Permanently delete {count} originals ({}) whose compressed replacement is verified?",
                            fmt_bytes(*bytes)
                        ),
                        Some("This cannot be undone. Missing or changed replacements are kept."),
                        false,
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui_kit::secondary_button(ui, "Cancel", true, tokens).clicked() {
                            close = true;
                        }
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if ui_kit::danger_button(
                                ui,
                                "Delete Permanently",
                                !state.videos.busy(),
                                tokens,
                            )
                            .clicked()
                            {
                                start = Some(WorkerJob::PurgeHeldVideos {
                                    journal_path: state.journal_path.clone(),
                                });
                                close = true;
                            }
                        });
                    });
                }
            }
        });
    if close {
        state.videos.confirm = None;
    }
    if let Some(job) = start {
        state.spawn_job(worker, job);
    }
}

/// Applies a finished batch summary banner.
pub fn batch_banner(b: &BatchReport) -> StatusBanner {
    let failed = b
        .outcomes
        .iter()
        .filter(|o| o.status == VideoJobStatus::Failed)
        .count();
    StatusBanner {
        kind: if failed > 0 || b.stopped.is_some() {
            BannerKind::Warning
        } else {
            BannerKind::Success
        },
        message: format!(
            "Videos: {} of {} replaced, saving {}{}{}",
            b.replaced,
            b.outcomes.len(),
            fmt_bytes(b.saved_bytes),
            if failed > 0 {
                format!("; {failed} failed (originals kept)")
            } else {
                String::new()
            },
            b.stopped
                .as_ref()
                .map(|s| format!("; stopped: {s}"))
                .unwrap_or_default()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_flags_cover_every_job_and_clear_together() {
        let mut s = VideosState::default();
        assert!(!s.busy());
        s.compressing = true;
        s.sampling = Some(PathBuf::from("a.mp4"));
        assert!(s.busy());
        assert_eq!(s.activity_label(), Some("Compressing videos..."));
        s.clear_busy();
        assert!(!s.busy());
        assert_eq!(s.activity_label(), None);
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(fmt_duration(42.0), "42s");
        assert_eq!(fmt_duration(10_028.0), "2h47m");
    }
}
