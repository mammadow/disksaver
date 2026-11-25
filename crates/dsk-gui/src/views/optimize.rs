//! Optimize view: non-destructive disk space reclamation dashboard (§8.1–8.6).
//!
//! Provides 5 primary optimization panels:
//! 1. Virtual Disks & WSL VHDX Compaction (`diskpart` default on Windows 11 Home + `wsl --set-sparse`)
//! 2. WOF Transparent Compression (2% sample preview + XPRESS/LZX) & CompactOS
//! 3. System Storage Tunables (`hiberfil.sys`, VSS shadow storage cap/pruning, Reserved Storage)
//! 4. Cloud Files API Placeholder Dehydration (OneDrive, Dropbox, etc. in-sync items)
//! 5. Cross-Drive Folder Relocation & 1-Click Directory Junction Undo

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use dsk_core::optimize::{HiberfileMode, OptimizerIntent, WofAlgorithm};
use dsk_core::{NodeFlags, ROOT};
use eframe::egui::{self, Align, RichText, ScrollArea};

use crate::app_state::{AppState, ConfirmAction, OptimizerAction};
use crate::theme::{ThemeTokens, fmt_bytes, fmt_count};
use crate::ui_kit::{self, Icon};
use crate::worker::{WorkerHandle, WorkerJob};

/// Cached "is this an existing local directory?" check keyed by the exact input text, so typing
/// re-checks once per edit instead of stat-ing the disk on every frame.
#[derive(Default)]
pub struct DirCheckCache {
    last: Option<(String, bool)>,
}

impl DirCheckCache {
    /// `true` when `input` is an absolute drive-letter path (`X:\...`) to an existing directory.
    /// UNC/relative input is rejected lexically without touching the disk (a network stat can
    /// block for seconds and these tools only support local fixed drives).
    pub fn is_local_dir(&mut self, input: &str) -> bool {
        if let Some((text, ok)) = &self.last
            && text == input
        {
            return *ok;
        }
        let ok = is_local_drive_path(input) && Path::new(input.trim()).is_dir();
        self.last = Some((input.to_string(), ok));
        ok
    }

    /// Whether the answer for `input` is already cached (no disk access needed).
    pub fn is_cached(&self, input: &str) -> bool {
        self.last.as_ref().is_some_and(|(t, _)| t == input)
    }
}

/// Lexical check: `X:\something` (not UNC, not relative, not a device path).
pub fn is_local_drive_path(input: &str) -> bool {
    let b = input.trim().as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// State retained across frames for optimize inputs and previews.
pub struct OptimizeViewState {
    pub wof_target_folder: String,
    pub wof_algo: WofAlgorithm,
    pub relocate_source: String,
    pub relocate_target_parent: String,
    pub vss_max_input: String,
    pub wof_dir_check: DirCheckCache,
    pub relocate_src_check: DirCheckCache,
    pub relocate_dst_check: DirCheckCache,
}

impl Default for OptimizeViewState {
    fn default() -> Self {
        Self {
            wof_target_folder: String::new(),
            wof_algo: WofAlgorithm::Xpress8k,
            relocate_source: String::new(),
            relocate_target_parent: String::new(),
            vss_max_input: "5".to_string(),
            wof_dir_check: DirCheckCache::default(),
            relocate_src_check: DirCheckCache::default(),
            relocate_dst_check: DirCheckCache::default(),
        }
    }
}

/// Elevation context for the Optimize tab.
#[derive(Clone, Copy, Debug)]
struct AdminCaps {
    /// DiskSaver itself runs elevated: path-based admin tools (diskpart) are available.
    process_elevated: bool,
    /// System tunables can run: elevated, or delegated to the connected helper as intents.
    system_tunables: bool,
    /// The helper handshake (UAC prompt) is in progress.
    connecting: bool,
}

/// Renders the Optimize tab contents.
///
/// `process_elevated` is whether *this process* is elevated (not "helper connected"): path-based
/// admin tools such as diskpart are never delegated to the helper (§10.1 intents only).
pub fn render(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &mut OptimizeViewState,
    process_elevated: bool,
    tokens: &ThemeTokens,
) {
    // Probe once per scan / optimizer change (never once per frame).
    state.ensure_optimizer_probe(worker);

    let caps = AdminCaps {
        process_elevated,
        system_tunables: process_elevated || state.helper_connected,
        connecting: state.is_connecting_helper,
    };
    let busy = state.heavy_busy();

    ScrollArea::vertical().show(ui, |ui| {
        ui.add_space(4.0);

        // Header controls
        ui.horizontal(|ui| {
            ui_kit::section_header(
                ui,
                "Non-Destructive Space Reclamation",
                Some("Reclaim gigabytes of disk space without deleting personal files or applications."),
                tokens,
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if ui_kit::secondary_button(
                    ui,
                    "Refresh Optimizers",
                    !state.is_probing_optimizers,
                    tokens,
                )
                .on_hover_text("Probe virtual disks, system tunables, and active relocations")
                .clicked()
                {
                    state.invalidate_optimizer_probe();
                    state.ensure_optimizer_probe(worker);
                }
                if state.is_probing_optimizers {
                    ui.spinner();
                    ui.label(RichText::new("Probing...").color(tokens.info));
                }
            });
        });

        if let Some(ref err) = state.optimizers_probe_error {
            ui.add_space(6.0);
            ui_kit::callout_banner(
                ui,
                tokens,
                tokens.warning,
                Icon::Warning,
                &format!("Probe failed: {err}"),
                Some("Use Refresh Optimizers to retry."),
                false,
            );
        }
        if let Some(label) = state.heavy_activity_label() {
            ui.add_space(6.0);
            ui_kit::callout_banner(
                ui,
                tokens,
                tokens.warning,
                Icon::Info,
                &format!("Actions are paused while a job runs: {label}"),
                None,
                false,
            );
        }
        ui.add_space(10.0);

        // Section 1: WSL & Virtual Disks (.vhdx)
        render_vhdx_card(ui, state, caps, busy, tokens);
        ui.add_space(10.0);

        // Section 2: WOF Transparent Compression & CompactOS
        render_wof_card(ui, state, worker, view_state, caps, busy, tokens);
        ui.add_space(10.0);

        // Section 3: System Storage Tunables
        render_tunables_card(ui, state, worker, caps, busy, tokens);
        ui.add_space(10.0);

        // Section 4: Cloud Placeholder Dehydration
        render_cloud_card(ui, state, busy, tokens);
        ui.add_space(10.0);

        // Section 5: Cross-Drive Folder Relocation & Directory Junction Undo
        render_relocation_card(ui, state, view_state, busy, tokens);
        ui.add_space(12.0);
    });
}

/// Explains why an admin control is disabled and offers the unlock path.
fn admin_hint(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    caps: AdminCaps,
    tokens: &ThemeTokens,
) {
    if caps.system_tunables {
        return;
    }
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui_kit::icon_widget(ui, Icon::Lock, 13.0, tokens.warning);
        ui.label(
            RichText::new("Administrator rights required.")
                .color(tokens.warning)
                .size(11.5),
        );
        if caps.connecting {
            ui.spinner();
            ui.label(RichText::new("Waiting for UAC...").size(11.5));
        } else if ui_kit::secondary_button(ui, "Unlock Admin (UAC)", true, tokens)
            .on_hover_text("Start the elevated helper; these settings then run through it")
            .clicked()
        {
            state.spawn_job(worker, WorkerJob::ConnectHelper);
        }
    });
}

fn confirm_system_intent(
    state: &mut AppState,
    title: &str,
    detail: String,
    intent: OptimizerIntent,
) {
    state.confirm_modal = Some(ConfirmAction::ApplyOptimizer {
        title: title.to_string(),
        target_path: intent.label(),
        detail,
        action: OptimizerAction::SystemIntent {
            intent,
            dry_run: false,
        },
    });
}

fn render_vhdx_card(
    ui: &mut egui::Ui,
    state: &mut AppState,
    caps: AdminCaps,
    busy: bool,
    tokens: &ThemeTokens,
) {
    ui_kit::accent_card(ui, tokens, tokens.info, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui_kit::icon_widget(ui, Icon::Drive, 16.0, tokens.info);
            ui.label(
                RichText::new("WSL & Virtual Disks (.vhdx)")
                    .strong()
                    .size(15.0)
                    .color(tokens.text_primary),
            );
            if !caps.process_elevated {
                ui_kit::pill_badge(
                    ui,
                    "Live compact needs DiskSaver run as Admin (Simulation works unelevated)",
                    tokens.warning,
                    tokens,
                );
            }
        });
        ui.label(
            RichText::new(
                "Reclaim unallocated host space inside WSL2 distributions and Docker Desktop virtual disks.",
            )
            .color(tokens.text_secondary)
            .size(12.0),
        );
        ui.add_space(8.0);

        if state.vhdx_candidates.is_empty() {
            let msg = if state.scan_report.is_none() {
                "Scan a drive to discover virtual disks."
            } else {
                "No virtual disks detected in active scan."
            };
            ui.label(RichText::new(msg).color(tokens.text_muted));
            return;
        }

        let mut pending: Option<ConfirmAction> = None;
        for candidate in &state.vhdx_candidates {
            ui_kit::inset_frame(tokens).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let file_name = candidate
                        .path
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_else(|| "virtual_disk.vhdx".to_string());

                    ui.strong(RichText::new(&file_name).color(tokens.text_primary));
                    ui_kit::pill_badge(ui, &format!("{:?}", candidate.kind), tokens.info, tokens);

                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let target = candidate.path.to_string_lossy().to_string();
                        if ui_kit::primary_button(
                            ui,
                            "Compact (diskpart)",
                            caps.process_elevated && !busy,
                            tokens,
                        )
                        .clicked()
                        {
                            pending = Some(ConfirmAction::ApplyOptimizer {
                                title: "Compact Virtual Disk".to_string(),
                                target_path: target.clone(),
                                detail: format!(
                                    "Will shut down WSL, verify no process locks, and run diskpart compact on {}.",
                                    candidate.path.display()
                                ),
                                action: OptimizerAction::CompactVhdx {
                                    path: candidate.path.clone(),
                                    distro: None,
                                    dry_run: false,
                                },
                            });
                        }

                        if let Some(ref distro) = candidate.distro_name
                            && ui_kit::secondary_button(
                                ui,
                                &format!("Set Sparse ({distro})"),
                                caps.process_elevated && !busy,
                                tokens,
                            )
                            .clicked()
                        {
                            pending = Some(ConfirmAction::ApplyOptimizer {
                                title: "Enable Sparse VHDX + Compact".to_string(),
                                target_path: target.clone(),
                                detail: format!(
                                    "Will shut down WSL, enable lasting sparse mode for '{distro}' (wsl --manage --set-sparse), then compact the disk."
                                ),
                                action: OptimizerAction::CompactVhdx {
                                    path: candidate.path.clone(),
                                    distro: Some(distro.clone()),
                                    dry_run: false,
                                },
                            });
                        }

                        if ui_kit::secondary_button(ui, "Simulation", !busy, tokens).clicked() {
                            pending = Some(ConfirmAction::ApplyOptimizer {
                                title: "Simulate Virtual Disk Compaction".to_string(),
                                target_path: target,
                                detail: "Reports what would be done without shutting down WSL or touching the disk.".to_string(),
                                action: OptimizerAction::CompactVhdx {
                                    path: candidate.path.clone(),
                                    distro: candidate.distro_name.clone(),
                                    dry_run: true,
                                },
                            });
                        }
                    });
                });

                ui.add_space(2.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "Allocated: {}",
                            fmt_bytes(candidate.host_allocated_bytes)
                        ))
                        .monospace()
                        .size(11.5)
                        .color(tokens.text_secondary),
                    );
                    if let Some(guest) = candidate.guest_used_bytes {
                        ui.label(
                            RichText::new(format!("· Guest Used: {}", fmt_bytes(guest)))
                                .monospace()
                                .size(11.5)
                                .color(tokens.text_secondary),
                        );
                    }
                    if candidate.est_reclaimable_bytes > 0 {
                        ui.label(
                            RichText::new(format!(
                                "· Est. Reclaimable: ~{}",
                                fmt_bytes(candidate.est_reclaimable_bytes)
                            ))
                            .monospace()
                            .strong()
                            .color(tokens.success)
                            .size(11.5),
                        );
                    }
                });

                if !candidate.locked_by.is_empty() {
                    ui.label(
                        RichText::new(format!(
                            "Locked by processes: {}",
                            candidate.locked_by.join(", ")
                        ))
                        .color(tokens.danger)
                        .size(11.5),
                    );
                }
            });
            ui.add_space(4.0);
        }
        if let Some(p) = pending {
            state.confirm_modal = Some(p);
        }
    });
}

fn render_wof_card(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    view_state: &mut OptimizeViewState,
    caps: AdminCaps,
    busy: bool,
    tokens: &ThemeTokens,
) {
    ui_kit::accent_card(ui, tokens, tokens.purple, |ui| {
        ui.horizontal(|ui| {
            ui_kit::icon_widget(ui, Icon::Compressed, 16.0, tokens.purple);
            ui.label(
                RichText::new("WOF Transparent Compression & CompactOS")
                    .strong()
                    .size(15.0)
                    .color(tokens.text_primary),
            );
        });
        ui.label(
            RichText::new(
                "Transparent filesystem compression for applications, games, and Windows operating system files.",
            )
            .color(tokens.text_secondary)
            .size(12.0),
        );
        ui.add_space(8.0);

        // CompactOS subcard
        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.strong("CompactOS (Operating System Compression)");
                let (label, col) = match state.compact_os_state {
                    Some(true) => ("ENABLED", tokens.success),
                    Some(false) => ("DISABLED", tokens.warning),
                    None if state.is_probing_optimizers => ("PROBING...", tokens.text_muted),
                    None => ("UNKNOWN", tokens.text_secondary),
                };
                ui_kit::pill_badge(ui, label, col, tokens);

                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    let enabled = caps.system_tunables && !busy;
                    let offer_disable = state.compact_os_state != Some(false);
                    let offer_enable = state.compact_os_state != Some(true);
                    if offer_disable
                        && ui_kit::secondary_button(ui, "Disable CompactOS", enabled, tokens)
                            .clicked()
                    {
                        confirm_system_intent(
                            state,
                            "Disable CompactOS",
                            "Decompresses Windows system files (takes several minutes; uses ~2-4 GB more space).".to_string(),
                            OptimizerIntent::SetCompactOs { enable: false },
                        );
                    }
                    if offer_enable
                        && ui_kit::primary_button(
                            ui,
                            "Enable CompactOS (~2-4 GB free)",
                            enabled,
                            tokens,
                        )
                        .clicked()
                    {
                        confirm_system_intent(
                            state,
                            "Enable CompactOS",
                            "Compresses Windows system files with XPRESS (takes several minutes; reversible).".to_string(),
                            OptimizerIntent::SetCompactOs { enable: true },
                        );
                    }
                });
            });
            admin_hint(ui, state, worker, caps, tokens);
        });

        ui.add_space(6.0);

        // Folder WOF Compression
        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.strong("Per-Folder WOF Compression");
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("Target Folder:")
                        .size(12.0)
                        .color(tokens.text_secondary),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut view_state.wof_target_folder)
                        .desired_width(240.0)
                        .hint_text(r"D:\Games\Old"),
                );

                ui.label(
                    RichText::new("Algorithm:")
                        .size(12.0)
                        .color(tokens.text_secondary),
                );
                ui.radio_value(
                    &mut view_state.wof_algo,
                    WofAlgorithm::Xpress8k,
                    "Xpress8k (Fast)",
                );
                ui.radio_value(&mut view_state.wof_algo, WofAlgorithm::Xpress16k, "Xpress16k");
                ui.radio_value(
                    &mut view_state.wof_algo,
                    WofAlgorithm::Lzx,
                    "LZX (Cold Data)",
                );
            });

            let folder_text = view_state.wof_target_folder.trim().to_string();
            let folder_ok = view_state.wof_dir_check.is_local_dir(&folder_text);
            let folder_p = PathBuf::from(&folder_text);
            let in_scan = state
                .scan_report
                .as_ref()
                .is_some_and(|sr| sr.index.find_by_path(&folder_p).is_some());

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui_kit::secondary_button(
                    ui,
                    "2% Sample Preview",
                    folder_ok && in_scan && !busy,
                    tokens,
                )
                .on_disabled_hover_text("Enter a folder that is part of the current scan")
                .clicked()
                    && let Some(sr) = state.scan_report.clone()
                {
                    let job = WorkerJob::SampleWof {
                        scan_report: sr,
                        folder: folder_p.clone(),
                    };
                    state.spawn_job(worker, job);
                }

                if ui_kit::primary_button(ui, "Compress Folder", folder_ok && !busy, tokens)
                    .clicked()
                {
                    state.confirm_modal = Some(ConfirmAction::ApplyOptimizer {
                        title: "WOF Folder Compression".to_string(),
                        target_path: folder_text.clone(),
                        detail: format!(
                            "Compresses files in this folder with {:?} at background priority (transparent; files stay readable).",
                            view_state.wof_algo
                        ),
                        action: OptimizerAction::CompressFolder {
                            folder: folder_p.clone(),
                            algo: view_state.wof_algo,
                            dry_run: false,
                        },
                    });
                }

                if ui_kit::secondary_button(ui, "Simulate", folder_ok && !busy, tokens).clicked() {
                    state.confirm_modal = Some(ConfirmAction::ApplyOptimizer {
                        title: "Simulate WOF Folder Compression".to_string(),
                        target_path: folder_text.clone(),
                        detail: "Reports estimated savings without compressing anything.".to_string(),
                        action: OptimizerAction::CompressFolder {
                            folder: folder_p.clone(),
                            algo: view_state.wof_algo,
                            dry_run: true,
                        },
                    });
                }
            });
            if !folder_text.is_empty() && !folder_ok {
                ui.add_space(2.0);
                ui.label(
                    RichText::new("Enter an existing local folder such as D:\\Games\\Old.")
                        .size(11.5)
                        .color(tokens.text_muted),
                );
            }

            match &state.wof_sample {
                Some((folder, Ok(prev))) => {
                    ui.add_space(6.0);
                    let badge_color = if prev.recommended {
                        tokens.success
                    } else {
                        tokens.warning
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui_kit::pill_badge(
                            ui,
                            &format!(
                                "{}: ~{:.1}% savings ({})",
                                folder.display(),
                                prev.estimated_savings_pct,
                                fmt_bytes(prev.estimated_savings_bytes())
                            ),
                            badge_color,
                            tokens,
                        );
                        if let Some(ref reason) = prev.skip_reason {
                            ui.label(
                                RichText::new(format!("({reason})"))
                                    .size(11.5)
                                    .color(tokens.text_secondary),
                            );
                        }
                    });
                }
                Some((folder, Err(err))) => {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("Sample failed for {}: {err}", folder.display()))
                            .color(tokens.danger)
                            .size(11.5),
                    );
                }
                None => {}
            }
        });
    });
}

fn render_tunables_card(
    ui: &mut egui::Ui,
    state: &mut AppState,
    worker: &mut WorkerHandle,
    caps: AdminCaps,
    busy: bool,
    tokens: &ThemeTokens,
) {
    ui_kit::accent_card(ui, tokens, tokens.success, |ui| {
        ui.horizontal(|ui| {
            ui_kit::icon_widget(ui, Icon::Optimize, 16.0, tokens.success);
            ui.label(
                RichText::new("System Storage Tunables")
                    .strong()
                    .size(15.0)
                    .color(tokens.text_primary),
            );
        });
        ui.label(
            RichText::new(
                "Configure Windows hibernation file size, VSS shadow storage cap, and Reserved Storage.",
            )
            .color(tokens.text_secondary)
            .size(12.0),
        );
        admin_hint(ui, state, worker, caps, tokens);
        ui.add_space(8.0);

        let Some(tunables) = state.tunables_status.clone() else {
            let msg = if state.is_probing_optimizers {
                "Probing system tunables..."
            } else {
                "System tunables have not been probed yet."
            };
            ui.label(RichText::new(msg).color(tokens.text_muted));
            return;
        };
        let enabled = caps.system_tunables && !busy;
        let drive = if tunables.system_drive.is_empty() {
            "C:".to_string()
        } else {
            tunables.system_drive.clone()
        };

        // Hiberfile
        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.strong("Hibernation (hiberfil.sys)");
                if let Some(bytes) = tunables.hiberfil_bytes {
                    ui_kit::pill_badge(ui, &fmt_bytes(bytes), tokens.info, tokens);
                } else {
                    ui_kit::pill_badge(ui, "Disabled (0 B)", tokens.text_muted, tokens);
                }

                if tunables.is_laptop_battery_present {
                    ui_kit::pill_badge(ui, "Battery detected", tokens.warning, tokens);
                }

                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    let battery_note = if tunables.is_laptop_battery_present {
                        " This device has a battery: without hibernation, a fully drained battery loses unsaved work."
                    } else {
                        ""
                    };
                    if ui_kit::secondary_button(ui, "Off", enabled, tokens).clicked() {
                        confirm_system_intent(
                            state,
                            "Turn Off Hibernation",
                            format!("Deletes hiberfil.sys and disables hibernation and Fast Startup (powercfg /h off).{battery_note}"),
                            OptimizerIntent::SetHiberfile { mode: HiberfileMode::Off },
                        );
                    }
                    if ui_kit::secondary_button(ui, "Reduced (~20% RAM)", enabled, tokens).clicked()
                    {
                        confirm_system_intent(
                            state,
                            "Reduce Hibernation File",
                            "Keeps Fast Startup but removes full hibernation (powercfg /h /type reduced).".to_string(),
                            OptimizerIntent::SetHiberfile { mode: HiberfileMode::Reduced },
                        );
                    }
                    if ui_kit::secondary_button(ui, "Full", enabled, tokens).clicked() {
                        confirm_system_intent(
                            state,
                            "Full Hibernation",
                            "Restores full hibernation (powercfg /h /type full); uses more disk space.".to_string(),
                            OptimizerIntent::SetHiberfile { mode: HiberfileMode::Full },
                        );
                    }
                });
            });
        });

        ui.add_space(6.0);

        // VSS Shadow Storage
        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.strong(format!("VSS Shadow Storage ({drive})"));
                match (tunables.vss_used_bytes, tunables.vss_max_bytes) {
                    (None, None) => {
                        ui_kit::pill_badge(ui, "Usage unknown", tokens.text_muted, tokens);
                    }
                    (used, max) => {
                        if let Some(used) = used {
                            ui_kit::pill_badge(
                                ui,
                                &format!("Used: {}", fmt_bytes(used)),
                                tokens.info,
                                tokens,
                            );
                        }
                        if let Some(max) = max {
                            ui_kit::pill_badge(
                                ui,
                                &format!("Max: {}", fmt_bytes(max)),
                                tokens.text_secondary,
                                tokens,
                            );
                        }
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if ui_kit::danger_button(ui, "Prune Oldest", enabled, tokens).clicked() {
                        confirm_system_intent(
                            state,
                            "Delete Oldest Shadow Copy",
                            format!("Permanently deletes the oldest System Restore / shadow copy on {drive}. It cannot be recovered."),
                            OptimizerIntent::VssPruneOldest { drive: drive.clone() },
                        );
                    }

                    if ui_kit::secondary_button(ui, "Set Cap (5%)", enabled, tokens).clicked() {
                        confirm_system_intent(
                            state,
                            "Cap Shadow Storage",
                            format!("Limits shadow storage on {drive} to 5% of the volume. Windows deletes the oldest restore points that do not fit."),
                            OptimizerIntent::VssResize { drive: drive.clone(), max_percent: 5 },
                        );
                    }
                });
            });
        });

        ui.add_space(6.0);

        // Reserved Storage
        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.strong("Windows Reserved Storage (~7 GB)");
                let (badge_txt, badge_col) = match tunables.reserved_storage_enabled {
                    Some(true) => ("ENABLED", tokens.success),
                    Some(false) => ("DISABLED", tokens.text_secondary),
                    None => ("UNKNOWN", tokens.text_muted),
                };
                ui_kit::pill_badge(ui, badge_txt, badge_col, tokens);

                if tunables.servicing_busy {
                    ui_kit::pill_badge(ui, "Windows servicing busy", tokens.danger, tokens);
                }

                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    let can_change = enabled && !tunables.servicing_busy;
                    let current = tunables.reserved_storage_enabled;
                    if current != Some(false)
                        && ui_kit::secondary_button(
                            ui,
                            "Disable (~7 GB free)",
                            can_change,
                            tokens,
                        )
                        .clicked()
                    {
                        confirm_system_intent(
                            state,
                            "Disable Reserved Storage",
                            "Frees the ~7 GB Windows keeps for updates (DISM /Set-ReservedStorageState). Updates may then need free space you provide.".to_string(),
                            OptimizerIntent::SetReservedStorage { enabled: false },
                        );
                    }
                    if current != Some(true)
                        && ui_kit::secondary_button(ui, "Enable", can_change, tokens).clicked()
                    {
                        confirm_system_intent(
                            state,
                            "Enable Reserved Storage",
                            "Lets Windows reserve ~7 GB for updates again.".to_string(),
                            OptimizerIntent::SetReservedStorage { enabled: true },
                        );
                    }
                });
            });
        });
    });
}

fn render_cloud_card(ui: &mut egui::Ui, state: &mut AppState, busy: bool, tokens: &ThemeTokens) {
    ui_kit::accent_card(ui, tokens, tokens.accent, |ui| {
        ui.horizontal(|ui| {
            ui_kit::icon_widget(ui, Icon::Cloud, 16.0, tokens.accent);
            ui.label(
                RichText::new("Cloud Files API Placeholder Dehydration")
                    .strong()
                    .size(15.0)
                    .color(tokens.text_primary),
            );
        });
        ui.label(
            RichText::new(
                "Free local space by dehydrating in-sync cloud files (OneDrive, Dropbox, iCloud, Box) untouched for > 30 days.",
            )
            .color(tokens.text_secondary)
            .size(12.0),
        );
        ui.add_space(8.0);

        if state.cloud_candidates.is_empty() {
            ui.label(
                RichText::new("No locally hydrated cloud placeholders over 30 days old detected.")
                    .color(tokens.text_muted),
            );
            return;
        }

        let mut pending: Option<ConfirmAction> = None;
        let total_cloud_bytes: u64 = state
            .cloud_candidates
            .iter()
            .map(|c| c.allocated_bytes)
            .sum();
        ui.horizontal(|ui| {
            ui_kit::pill_badge(
                ui,
                &format!(
                    "{} candidates · {} reclaimable",
                    state.cloud_candidates.len(),
                    fmt_bytes(total_cloud_bytes)
                ),
                tokens.accent,
                tokens,
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if ui_kit::primary_button(ui, "Dehydrate All In-Sync", !busy, tokens).clicked() {
                    let paths: Vec<PathBuf> =
                        state.cloud_candidates.iter().map(|c| c.path.clone()).collect();
                    pending = Some(ConfirmAction::ApplyOptimizer {
                        title: "Dehydrate Cloud Files".to_string(),
                        target_path: format!("{} file(s)", paths.len()),
                        detail: format!(
                            "Releases the local copy of {} in-sync cloud file(s) ({}). They stay available online and download again on open. Pinned or changed files are skipped.",
                            paths.len(),
                            fmt_bytes(total_cloud_bytes)
                        ),
                        action: OptimizerAction::DehydrateCloudFiles {
                            paths,
                            dry_run: false,
                        },
                    });
                }
            });
        });

        ui.add_space(6.0);
        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            for c in state.cloud_candidates.iter().take(5) {
                ui.horizontal(|ui| {
                    ui.strong(c.path.file_name().unwrap_or_default().to_string_lossy());
                    ui.label(
                        RichText::new(format!(
                            "{} · {}d old",
                            fmt_bytes(c.allocated_bytes),
                            c.days_since_access
                        ))
                        .monospace()
                        .size(12.0)
                        .color(tokens.text_secondary),
                    );
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if ui_kit::secondary_button(ui, "Dehydrate", !busy, tokens).clicked() {
                            pending = Some(ConfirmAction::ApplyOptimizer {
                                title: "Dehydrate Cloud File".to_string(),
                                target_path: c.path.display().to_string(),
                                detail: "Releases the local copy; the file stays available online."
                                    .to_string(),
                                action: OptimizerAction::DehydrateCloudFiles {
                                    paths: vec![c.path.clone()],
                                    dry_run: false,
                                },
                            });
                        }
                    });
                });
            }
        });
        if let Some(p) = pending {
            state.confirm_modal = Some(p);
        }
    });
}

fn render_relocation_card(
    ui: &mut egui::Ui,
    state: &mut AppState,
    view_state: &mut OptimizeViewState,
    busy: bool,
    tokens: &ThemeTokens,
) {
    ui_kit::accent_card(ui, tokens, tokens.warning, |ui| {
        ui.horizontal(|ui| {
            ui_kit::icon_widget(ui, Icon::ExternalLink, 16.0, tokens.warning);
            ui.label(
                RichText::new("Cross-Drive Folder Relocation & Reversible Directory Junctions")
                    .strong()
                    .size(15.0)
                    .color(tokens.text_primary),
            );
        });
        ui.label(
            RichText::new(
                "Relocate large directories (AI models, game folders, SDKs) to another drive with XXH3 verification and 1-click restore.",
            )
            .color(tokens.text_secondary)
            .size(12.0),
        );
        ui.add_space(8.0);

        ui_kit::inset_frame(tokens).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Grid::new("relocate_form_grid")
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Source Folder:")
                            .size(12.0)
                            .color(tokens.text_secondary),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut view_state.relocate_source)
                            .desired_width(340.0)
                            .hint_text(r"C:\Models"),
                    );
                    ui.end_row();

                    ui.label(
                        RichText::new("Target Parent Dir:")
                            .size(12.0)
                            .color(tokens.text_secondary),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut view_state.relocate_target_parent)
                            .desired_width(340.0)
                            .hint_text(r"D:\Storage"),
                    );
                    ui.end_row();
                });

            let src_text = view_state.relocate_source.trim().to_string();
            let dst_text = view_state.relocate_target_parent.trim().to_string();
            let src_ok = view_state.relocate_src_check.is_local_dir(&src_text);
            let dst_ok = view_state.relocate_dst_check.is_local_dir(&dst_text);
            let can_relocate = src_ok && dst_ok && !busy;

            ui.add_space(6.0);
            if ui_kit::primary_button(ui, "Execute Verified Relocation...", can_relocate, tokens)
                .on_disabled_hover_text(
                    "Enter an existing local source folder and target parent folder",
                )
                .clicked()
            {
                let src = PathBuf::from(&src_text);
                let (total_bytes, file_count) = state
                    .scan_report
                    .as_ref()
                    .and_then(|sr| {
                        let id = sr.index.find_by_path(&src)?;
                        (id != ROOT && sr.index.flags(id).contains(NodeFlags::DIR))
                            .then(|| (sr.index.total_allocated(id), sr.index.file_count(id) as u64))
                    })
                    .map_or((None, None), |(b, f)| (Some(b), Some(f)));
                state.confirm_modal = Some(ConfirmAction::RelocateFolder {
                    source: src,
                    target_parent: PathBuf::from(&dst_text),
                    total_bytes,
                    file_count,
                });
            }
        });

        ui.add_space(8.0);
        ui.strong(
            RichText::new("Active Relocations (Audited in SQLite)")
                .size(12.5)
                .color(tokens.text_primary),
        );
        ui.add_space(4.0);

        if state.active_relocations.is_empty() {
            ui.label(
                RichText::new("No active folder relocations recorded in action journal.")
                    .color(tokens.text_muted),
            );
        } else {
            let mut pending: Option<ConfirmAction> = None;
            for rec in &state.active_relocations {
                ui_kit::inset_frame(tokens).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(&rec.source_path)
                                .monospace()
                                .strong()
                                .size(12.0),
                        );
                        ui.label(RichText::new("→").color(tokens.text_muted));
                        ui.label(
                            RichText::new(&rec.target_path)
                                .monospace()
                                .size(12.0)
                                .color(tokens.accent),
                        );
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui_kit::pill_badge(
                            ui,
                            &format!(
                                "{} files · {}",
                                fmt_count(rec.file_count),
                                fmt_bytes(rec.bytes_moved)
                            ),
                            tokens.text_secondary,
                            tokens,
                        );

                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if ui_kit::danger_button(ui, "Undo Relocation...", !busy, tokens)
                                .clicked()
                            {
                                pending = Some(ConfirmAction::UndoRelocation {
                                    id: rec.id.clone(),
                                    source: rec.source_path.clone(),
                                    target: rec.target_path.clone(),
                                });
                            }
                        });
                    });
                });
                ui.add_space(4.0);
            }
            if let Some(p) = pending {
                state.confirm_modal = Some(p);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_check_is_cached_per_input_and_rejects_unc_without_io() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_string_lossy().to_string();
        let mut cache = DirCheckCache::default();
        assert!(cache.is_local_dir(&dir));
        assert!(cache.is_cached(&dir));
        // Removing the folder does not change the cached answer for the same text (no re-stat
        // per frame); editing the text re-checks once.
        drop(tmp);
        assert!(
            cache.is_local_dir(&dir),
            "same input: cached, no disk access"
        );
        let edited = format!("{dir}\\");
        assert!(!cache.is_local_dir(&edited));

        assert!(!is_local_drive_path(r"\\server\share\models"));
        assert!(!is_local_drive_path(r"relative\path"));
        assert!(!is_local_drive_path(r"\\?\C:\x"));
        assert!(is_local_drive_path(r"D:\Games"));
        assert!(!cache.is_local_dir(r"\\server\share"));
    }
}
