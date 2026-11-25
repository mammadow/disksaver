//! Intent-only system optimizer requests (spec §10.1 `RunOptimizer(kind, params)`).
//!
//! The elevated helper must never act on caller-supplied paths or command lines. An
//! [`OptimizerIntent`] names one fixed operation plus validated scalar parameters; the helper maps
//! it onto a pinned `System32` binary with a fixed argument template (§10.7). Path-taking
//! optimizers (VHDX compaction, WOF folder compression, relocation, cloud dehydration) are
//! deliberately not representable here: they run unelevated with the user's own rights, or in an
//! elevated DiskSaver process the user started themselves.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};
use crate::optimize::sizing::{check_pagefile_commit_safety, paging_files_value};
use crate::optimize::sys_tunables::{
    HiberfileMode, configure_hiberfile, resize_or_prune_vss, set_reserved_storage,
};
use crate::optimize::wof::set_compact_os_enabled;
use crate::win::sysinfo::{read_paging_files, write_paging_files};

/// A parameter-only, administrator-level optimizer operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OptimizerIntent {
    /// `powercfg /h …`
    SetHiberfile { mode: HiberfileMode },
    /// `compact /CompactOS:always|never`
    SetCompactOs { enable: bool },
    /// `vssadmin resize shadowstorage /for=X: /on=X: /maxsize=N%`
    VssResize { drive: String, max_percent: u8 },
    /// `vssadmin delete shadows /for=X: /oldest /quiet`
    VssPruneOldest { drive: String },
    /// `Dism /Online /Set-ReservedStorageState /State:Enabled|Disabled`
    SetReservedStorage { enabled: bool },
    /// Fixed-size pagefile on one drive (`PagingFiles = "X:\pagefile.sys <initial> <max>"`).
    /// Takes effect after a reboot.
    SetPagefile {
        drive: String,
        initial_mb: u32,
        max_mb: u32,
    },
    /// System-managed pagefile on one drive (`"X:\pagefile.sys 0 0"`).
    SetPagefileSystemManaged { drive: String },
    /// Windows manages pagefiles on all drives (`"?:\pagefile.sys"`), the default.
    SetPagefileAutomatic,
    /// WOF-compress one app folder directly under Program Files (P9.3). Only a folder *name* is
    /// passed; the helper resolves it under `FOLDERID_ProgramFiles[X86]` and re-checks that the
    /// kernel-resolved parent is exactly that folder.
    CompressProgramFilesApp {
        x86: bool,
        folder: String,
        algorithm: crate::win::wof::WofAlgorithm,
    },
    /// Undo [`OptimizerIntent::CompressProgramFilesApp`].
    DecompressProgramFilesApp { x86: bool, folder: String },
}

/// A single folder name: no separators, wildcards, `..`, drive or stream syntax.
pub fn is_safe_folder_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.trim() == name
        && !name.ends_with('.')
        && name != "."
        && name != ".."
        && !name.chars().any(|c| {
            matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control()
        })
}

/// Resolves `Program Files[ (x86)]\<folder>` from the Known Folder and checks that the
/// kernel-resolved path is a direct child of it (no junction or `..` escape).
pub fn program_files_app_path(x86: bool, folder: &str) -> Result<std::path::PathBuf> {
    if !is_safe_folder_name(folder) {
        return Err(DskError::Optimize(format!(
            "not a plain folder name: '{folder}'"
        )));
    }
    let base = if x86 {
        crate::win::volume::program_files_x86_dir()
    } else {
        crate::win::volume::program_files_dir()
    };
    let path = base.join(folder);
    let canon_base = std::fs::canonicalize(&base)?;
    let canon = std::fs::canonicalize(&path)?;
    if canon.parent() != Some(canon_base.as_path()) {
        return Err(DskError::Denied(format!(
            "'{}' does not resolve to a folder directly under {}",
            path.display(),
            base.display()
        )));
    }
    Ok(path)
}

/// Bounds for [`OptimizerIntent::SetPagefile`] sizes, in MiB.
pub const PAGEFILE_MIN_MB: u32 = 1024;
pub const PAGEFILE_MAX_MB: u32 = 1024 * 1024;

impl OptimizerIntent {
    /// Short human-readable label for confirmations and logs.
    pub fn label(&self) -> String {
        match self {
            Self::SetHiberfile { mode } => format!("Set hibernation mode to {mode:?}"),
            Self::SetCompactOs { enable: true } => "Enable CompactOS".to_string(),
            Self::SetCompactOs { enable: false } => "Disable CompactOS".to_string(),
            Self::VssResize { drive, max_percent } => {
                format!("Cap VSS shadow storage on {drive} at {max_percent}%")
            }
            Self::VssPruneOldest { drive } => format!("Delete the oldest shadow copy on {drive}"),
            Self::SetReservedStorage { enabled: true } => "Enable Reserved Storage".to_string(),
            Self::SetReservedStorage { enabled: false } => "Disable Reserved Storage".to_string(),
            Self::SetPagefile {
                drive,
                initial_mb,
                max_mb,
            } => format!("Set the pagefile on {drive} to {initial_mb}–{max_mb} MiB (after reboot)"),
            Self::SetPagefileSystemManaged { drive } => {
                format!("Let Windows size the pagefile on {drive} (after reboot)")
            }
            Self::SetPagefileAutomatic => {
                "Let Windows manage pagefiles on all drives (after reboot)".to_string()
            }
            Self::CompressProgramFilesApp {
                x86,
                folder,
                algorithm,
            } => format!(
                r"Compress Program Files{}\{folder} with {}",
                if *x86 { " (x86)" } else { "" },
                algorithm.as_compact_arg()
            ),
            Self::DecompressProgramFilesApp { x86, folder } => format!(
                r"Undo compression of Program Files{}\{folder}",
                if *x86 { " (x86)" } else { "" }
            ),
        }
    }

    /// Validates scalar parameters before anything runs (the helper re-validates every request).
    pub fn validate(&self) -> Result<()> {
        let check_drive = |drive: &str| -> Result<()> {
            let b = drive.trim().trim_end_matches(['\\', '/']).as_bytes();
            if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                Ok(())
            } else {
                Err(DskError::Optimize(format!(
                    "optimizer intent requires a bare drive letter like C: (got '{drive}')"
                )))
            }
        };
        match self {
            Self::VssResize { drive, max_percent } => {
                check_drive(drive)?;
                if !(1..=100).contains(max_percent) {
                    return Err(DskError::Optimize(format!(
                        "VSS max_percent must be between 1 and 100 (got {max_percent})"
                    )));
                }
                Ok(())
            }
            Self::VssPruneOldest { drive } => check_drive(drive),
            Self::SetPagefile {
                drive,
                initial_mb,
                max_mb,
            } => {
                check_drive(drive)?;
                if !(PAGEFILE_MIN_MB..=PAGEFILE_MAX_MB).contains(initial_mb)
                    || !(PAGEFILE_MIN_MB..=PAGEFILE_MAX_MB).contains(max_mb)
                    || max_mb < initial_mb
                {
                    return Err(DskError::Optimize(format!(
                        "pagefile sizes must satisfy {PAGEFILE_MIN_MB} <= initial <= max <= {PAGEFILE_MAX_MB} MiB (got {initial_mb}/{max_mb})"
                    )));
                }
                Ok(())
            }
            Self::SetPagefileSystemManaged { drive } => check_drive(drive),
            Self::CompressProgramFilesApp { folder, .. }
            | Self::DecompressProgramFilesApp { folder, .. } => {
                if is_safe_folder_name(folder) {
                    Ok(())
                } else {
                    Err(DskError::Optimize(format!(
                        "not a plain folder name: '{folder}'"
                    )))
                }
            }
            Self::SetHiberfile { .. }
            | Self::SetCompactOs { .. }
            | Self::SetReservedStorage { .. }
            | Self::SetPagefileAutomatic => Ok(()),
        }
    }
}

/// Validates and runs `intent` in the current process (which must already be elevated for live
/// runs). Returns a user-facing status message.
pub fn run_optimizer_intent(intent: &OptimizerIntent, dry_run: bool) -> Result<String> {
    intent.validate()?;
    match intent {
        OptimizerIntent::SetHiberfile { mode } => configure_hiberfile(*mode, dry_run),
        OptimizerIntent::SetCompactOs { enable } => {
            if dry_run {
                return Ok(format!(
                    "Dry run: would {} CompactOS via System32\\compact.exe",
                    if *enable { "enable" } else { "disable" }
                ));
            }
            set_compact_os_enabled(*enable).map(|r| r.message)
        }
        OptimizerIntent::VssResize { drive, max_percent } => {
            resize_or_prune_vss(drive, Some(*max_percent), false, dry_run)
        }
        OptimizerIntent::VssPruneOldest { drive } => {
            resize_or_prune_vss(drive, None, true, dry_run)
        }
        OptimizerIntent::SetReservedStorage { enabled } => set_reserved_storage(*enabled, dry_run),
        OptimizerIntent::SetPagefile { .. }
        | OptimizerIntent::SetPagefileSystemManaged { .. }
        | OptimizerIntent::SetPagefileAutomatic => run_pagefile_intent(intent, dry_run),
        OptimizerIntent::CompressProgramFilesApp {
            x86,
            folder,
            algorithm,
        } => {
            let path = program_files_app_path(*x86, folder)?;
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let rep = crate::optimize::wof::compress_folder_wof_with(
                &path,
                *algorithm,
                dry_run,
                &cancel,
                &crate::optimize::wof::WofApplyOptions {
                    min_age_days: 14,
                    ..Default::default()
                },
            )?;
            Ok(if dry_run {
                format!("Dry run: would compress {}", path.display())
            } else {
                format!(
                    "Compressed {} files in {} with {}: freed {:.1} MiB ({} skipped, {} failed)",
                    rep.files_compressed,
                    path.display(),
                    algorithm.as_compact_arg(),
                    rep.freed_bytes as f64 / 1_048_576.0,
                    rep.files_skipped,
                    rep.files_failed
                )
            })
        }
        OptimizerIntent::DecompressProgramFilesApp { x86, folder } => {
            let path = program_files_app_path(*x86, folder)?;
            if dry_run {
                return Ok(format!("Dry run: would decompress {}", path.display()));
            }
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let rep = crate::optimize::wof::decompress_folder_wof(&path, &cancel)?;
            Ok(format!(
                "Decompressed {} files in {} ({} failed)",
                rep.files_compressed,
                path.display(),
                rep.files_failed
            ))
        }
    }
}

fn run_pagefile_intent(intent: &OptimizerIntent, dry_run: bool) -> Result<String> {
    let value = paging_files_value(intent)?;
    if let OptimizerIntent::SetPagefile { max_mb, .. } = intent {
        check_pagefile_commit_safety(*max_mb)?;
    }
    let previous = read_paging_files()
        .map(|v| v.join(" | "))
        .unwrap_or_else(|| "<unreadable>".to_string());
    if dry_run {
        return Ok(format!(
            "Dry run: would set PagingFiles to [{}] (currently [{previous}]); takes effect after a reboot",
            value.join(" | ")
        ));
    }
    write_paging_files(&value)?;
    Ok(format!(
        "PagingFiles set to [{}] (was [{previous}]). Reboot to apply.",
        value.join(" | ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intents_roundtrip_and_reject_paths_or_bad_ranges() {
        let intents = [
            OptimizerIntent::SetHiberfile {
                mode: HiberfileMode::Reduced,
            },
            OptimizerIntent::SetCompactOs { enable: true },
            OptimizerIntent::VssResize {
                drive: "C:".to_string(),
                max_percent: 5,
            },
            OptimizerIntent::VssPruneOldest {
                drive: "d:\\".to_string(),
            },
            OptimizerIntent::SetReservedStorage { enabled: false },
            OptimizerIntent::SetPagefile {
                drive: "C:".to_string(),
                initial_mb: 4096,
                max_mb: 8192,
            },
            OptimizerIntent::SetPagefileSystemManaged {
                drive: "c:".to_string(),
            },
            OptimizerIntent::SetPagefileAutomatic,
        ];
        for i in &intents {
            assert!(i.validate().is_ok(), "{i:?}");
            assert!(!i.label().is_empty());
            let json = serde_json::to_string(i).unwrap();
            let back: OptimizerIntent = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, i);
        }

        for bad_drive in [r"C:\Windows", r"\\server\share", "C", "", "CC:", "C:; del"] {
            assert!(
                OptimizerIntent::VssPruneOldest {
                    drive: bad_drive.to_string()
                }
                .validate()
                .is_err(),
                "{bad_drive:?} must be rejected"
            );
        }
        for (initial_mb, max_mb) in [(0u32, 8192u32), (4096, 2048), (4096, u32::MAX), (100, 100)] {
            assert!(
                OptimizerIntent::SetPagefile {
                    drive: "C:".to_string(),
                    initial_mb,
                    max_mb
                }
                .validate()
                .is_err(),
                "{initial_mb}/{max_mb} must be rejected"
            );
        }
        for bad in [
            "", "..", r"a\b", "a/b", "C:", "x*", "trail.", " lead", "a:stream",
        ] {
            assert!(
                OptimizerIntent::CompressProgramFilesApp {
                    x86: false,
                    folder: bad.to_string(),
                    algorithm: crate::win::wof::WofAlgorithm::Lzx,
                }
                .validate()
                .is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(is_safe_folder_name("JetBrains") && is_safe_folder_name("Microsoft Office"));
        // A real Program Files child resolves; a missing one fails before anything runs.
        assert!(program_files_app_path(false, "Common Files").is_ok());
        assert!(program_files_app_path(false, "definitely-not-installed-xyz").is_err());
        assert!(
            OptimizerIntent::SetPagefileSystemManaged {
                drive: r"C:\pagefile.sys".to_string()
            }
            .validate()
            .is_err()
        );
        for pct in [0u8, 101, 255] {
            assert!(
                OptimizerIntent::VssResize {
                    drive: "C:".to_string(),
                    max_percent: pct
                }
                .validate()
                .is_err()
            );
        }
        // Unknown kinds (e.g. a path-taking optimizer) are not deserializable at all.
        assert!(
            serde_json::from_str::<OptimizerIntent>(
                r#"{"kind":"compact_vhdx","path":"C:\\x.vhdx"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn dry_run_intents_never_execute_tools() {
        let msg = run_optimizer_intent(&OptimizerIntent::SetCompactOs { enable: true }, true)
            .expect("dry run");
        assert!(msg.starts_with("Dry run"));
        let msg = run_optimizer_intent(
            &OptimizerIntent::VssResize {
                drive: "C:".to_string(),
                max_percent: 7,
            },
            true,
        )
        .expect("dry run");
        assert!(msg.contains("Dry run") && msg.contains("/maxsize=7%"));
        let msg =
            run_optimizer_intent(&OptimizerIntent::SetPagefileAutomatic, true).expect("dry run");
        assert!(
            msg.starts_with("Dry run") && msg.contains(r"?:\pagefile.sys"),
            "{msg}"
        );
    }
}
