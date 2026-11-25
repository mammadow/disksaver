#![forbid(unsafe_code)]

//! Orphaned application leftover detector & Recycle-Bin-only remediation (§9.5).
//!
//! Cross-references `AppData/{Local,LocalLow,Roaming}` subfolders against
//! Win32/AppX installed application manifests, discovered game titles, and Windows/driver
//! safe-vendor allowlists. Defaults strictly to Recycle Bin deletion (never hard-delete).

use std::path::{Path, PathBuf};

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path, is_under_root};
use crate::clean::journal::ActionJournal;
use crate::error::{DskError, Result};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::insights::current_min2000;
use crate::insights::gaming::GamingLibraryReport;
use crate::win::prefetch::{InstalledAppRecord, enumerate_installed_apps};
use crate::win::recycle::{RecycleOutcome, move_to_recycle_bin};
use crate::win::wsl::registered_wsl_distros;

/// Parent root container where an orphaned leftover folder was located.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OrphanScope {
    AppDataLocal,
    AppDataLocalLow,
    AppDataRoaming,
    ProgramData,
}

impl OrphanScope {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::AppDataLocal => "AppData\\Local",
            Self::AppDataLocalLow => "AppData\\LocalLow",
            Self::AppDataRoaming => "AppData\\Roaming",
            Self::ProgramData => "ProgramData",
        }
    }
}

/// Candidate leftover application data folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanAppCandidate {
    pub scope: OrphanScope,
    pub folder_name: String,
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub file_count: u64,
    pub days_since_touch: u32,
    pub confidence: u8,
    pub reason: String,
}

/// Summary of suspected orphaned AppData / ProgramData folders.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanScanReport {
    pub candidates: Vec<OrphanAppCandidate>,
    pub total_allocated_bytes: u64,
}

/// Conservative system/OS/runtime/GPU allowlist that must NEVER be flagged as orphaned bloat.
const SAFE_SYSTEM_AND_RUNTIME_VENDORS: &[&str] = &[
    "microsoft",
    "windows",
    "packages",
    "temp",
    "d3dscache",
    "squirreltemp",
    "crashdumps",
    "elevateddiagnostics",
    "comms",
    "connecteddevicesplatform",
    "dbg",
    "fontconfig",
    "nvidia",
    "nv_cache",
    "amd",
    "ati",
    "intel",
    "realtek",
    "vulkan",
    "khronos",
    "opengl",
    "directx",
    "disksaver",
    "isolatedstorage",
    "virtualstore",
    "deployment",
    "publishers",
    "identities",
    "assembly",
    "programs",
    "cef",
    "webview2",
    "peerdistrepub",
    "package cache",
    "usoshared",
    "regid.1991-06.com.microsoft",
    "serviceprofiles",
    "windowspowershell",
    "powershell",
    "ssh",
    "gnupg",
    "rustup",
    "cargo",
    "dotnet",
    "nuget",
    "pip",
    "uv",
    "npm",
    "npm-cache",
    "yarn",
    "pnpm",
    "huggingface",
    "ollama",
    "torch",
    "steam",
    "valve",
    "epic",
    "epicgameslauncher",
    "riot games",
    "battle.net",
    "ubisoft",
    "ea",
    "gog.com",
    "xbox",
    "application data",
    "desktop",
    "history",
    "temporary internet files",
    "low",
    // Curated vendor aliases (P6 Task 3) whose AppData folders often outlive or never match an
    // Uninstall entry (per-user installs, portable builds, browser/mail profiles).
    "google",
    "chromium",
    "mozilla",
    "thunderbird",
    "adobe",
    "jetbrains",
    "anthropic",
    "claude",
    "openai",
    "discord",
    "spotify",
    "slack",
    "zoom",
    "code",
    "github",
    "githubdesktop",
    "docker",
    "bravesoftware",
    "opera software",
    "vivaldi",
    "teams",
    "onedrive",
    // Secrets and wallets: data loss here is unrecoverable even from the Recycle Bin once emptied.
    "1password",
    "bitwarden",
    "keepass",
    "keepassxc",
    "electrum",
    "exodus",
    "bitcoin",
    "ethereum",
    "monero",
    "ledger live",
    "atomic",
    "wasabiwallet",
    "gnupg",
    "putty",
    "winscp",
    // Live virtual machines and tool-managed caches: "no matching program" is not evidence of an
    // orphan here (P9.0). `wsl` holds the distros' ext4.vhdx disks.
    "wsl",
    "lxss",
    "ms-playwright",
    "pnpm-cache",
    "pnpm-state",
    "node-gyp",
    "electron",
    "electron-builder",
    "go-build",
    "pypoetry",
    "deno",
    "volta",
    "nvm",
];

/// Virtual disk images. A folder holding one belongs to a VM, WSL distro, emulator, or container
/// runtime; recycling it destroys that machine, so it is never an orphan candidate.
const VIRTUAL_DISK_EXTENSIONS: &[&str] = &["vhd", "vhdx", "avhd", "avhdx", "vmdk", "vdi", "qcow2"];

fn is_virtual_disk_name(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, ext)| {
        VIRTUAL_DISK_EXTENSIONS
            .iter()
            .any(|v| ext.eq_ignore_ascii_case(v))
    })
}

fn normalize_alnum(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn split_alnum_tokens(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            cur.push(ch.to_ascii_lowercase());
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn classify_orphan_scope(path_lower: &str) -> Option<OrphanScope> {
    let trimmed = path_lower.trim_end_matches(['\\', '/']);
    if trimmed.ends_with(r"\appdata\local") {
        return Some(OrphanScope::AppDataLocal);
    }
    if trimmed.ends_with(r"\appdata\locallow") {
        return Some(OrphanScope::AppDataLocalLow);
    }
    if trimmed.ends_with(r"\appdata\roaming") {
        return Some(OrphanScope::AppDataRoaming);
    }
    // `ProgramData` is deliberately NOT scanned (P6 Task 3 scopes orphans to per-user AppData):
    // package managers and services keep live state there without Uninstall entries
    // (`chocolatey`, `scoop`, Docker engine data, `USOPrivate`), so "no matching program" is not
    // evidence of an orphan.
    None
}

/// With fewer installed Win32/AppX entries than this, the registry enumeration is treated as
/// failed/partial and no folder is flagged (every vendor folder would otherwise look orphaned).
pub const MIN_INSTALLED_APPS_FOR_ORPHAN_SCAN: usize = 10;

struct OrphanSubtree {
    allocated_bytes: u64,
    file_count: u64,
    days_since_touch: u32,
    has_virtual_disk: bool,
}

fn measure_orphan_subtree(index: &Index, root: NodeId, now_mins: u32) -> OrphanSubtree {
    let mut stack = vec![root];
    let mut seen_fids: FxHashSet<u64> = FxHashSet::default();
    let mut alloc = 0u64;
    let mut files = 0u64;
    let mut newest_touch = 0u32;
    let mut has_virtual_disk = false;

    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if flags.contains(NodeFlags::DIR) {
            if node != root && flags.contains(NodeFlags::REPARSE) {
                continue;
            }
            for child in index.children(node) {
                stack.push(child);
            }
            continue;
        }
        files += 1;
        has_virtual_disk |= is_virtual_disk_name(&index.name(node));
        let fid = index.file_id(node);
        if fid == 0 || seen_fids.insert(fid) {
            alloc = alloc.saturating_add(index.allocated(node));
        }
        let touch = index.atime_min(node).max(index.mtime_min(node));
        newest_touch = newest_touch.max(touch);
    }

    let days = if newest_touch == 0 || now_mins <= newest_touch {
        0
    } else {
        (now_mins - newest_touch) / 1440
    };
    OrphanSubtree {
        allocated_bytes: alloc,
        file_count: files,
        days_since_touch: days,
        has_virtual_disk,
    }
}

fn folder_matches_known_software(
    folder_name: &str,
    known_norms: &FxHashSet<String>,
    known_tokens: &FxHashSet<String>,
) -> bool {
    let folder_norm = normalize_alnum(folder_name);
    if folder_norm.len() < 3 {
        return true; // Avoid flagging ambiguous 1-2 character short folders cleanly.
    }
    if known_norms.iter().any(|k| {
        k == &folder_norm
            || (folder_norm.len() >= 4 && k.contains(&folder_norm))
            || (k.len() >= 4 && folder_norm.contains(k))
    }) {
        return true;
    }
    let folder_toks = split_alnum_tokens(folder_name);
    folder_toks
        .iter()
        .any(|tok| tok.len() >= 4 && known_tokens.contains(tok))
}

/// Scans `AppData/{Local,LocalLow,Roaming}` in `index` using live Windows
/// uninstall/AppX manifests plus optional discovered games (`§9.5`). Registered WSL distro
/// folders are always protected.
pub fn scan_orphaned_app_data(
    index: &Index,
    gaming: Option<&GamingLibraryReport>,
    min_bytes: u64,
) -> OrphanScanReport {
    let installed = enumerate_installed_apps();
    if installed.len() < MIN_INSTALLED_APPS_FOR_ORPHAN_SCAN {
        // Registry enumeration failed or was truncated: refuse to guess.
        return OrphanScanReport::default();
    }
    let protected_roots: Vec<PathBuf> = registered_wsl_distros()
        .into_iter()
        .map(|d| d.base_path)
        .collect();
    scan_orphaned_app_data_with_apps(index, &installed, gaming, &protected_roots, min_bytes)
}

/// Pure, deterministic orphan detector using supplied `installed_apps` & `gaming` catalogs.
///
/// A top-level AppData folder that equals or contains any of `protected_roots` (registered WSL
/// distro `BasePath`s) is never a candidate, and neither is one holding a virtual disk image.
pub fn scan_orphaned_app_data_with_apps(
    index: &Index,
    installed_apps: &[InstalledAppRecord],
    gaming: Option<&GamingLibraryReport>,
    protected_roots: &[PathBuf],
    min_bytes: u64,
) -> OrphanScanReport {
    let deny_ctx = DenyContext::default();
    let now_mins = current_min2000();

    let mut known_norms: FxHashSet<String> = FxHashSet::default();
    let mut known_tokens: FxHashSet<String> = FxHashSet::default();

    for app in installed_apps {
        let norm_name = normalize_alnum(&app.name);
        if norm_name.len() >= 3 {
            known_norms.insert(norm_name);
        }
        for tok in split_alnum_tokens(&app.name) {
            if tok.len() >= 4 {
                known_tokens.insert(tok);
            }
        }
        if let Some(ref pub_name) = app.publisher {
            let np = normalize_alnum(pub_name);
            if np.len() >= 3 {
                known_norms.insert(np);
            }
            for tok in split_alnum_tokens(pub_name) {
                if tok.len() >= 4 {
                    known_tokens.insert(tok);
                }
            }
        }
        if let Some(ref loc) = app.install_location
            && let Some(leaf) = loc.file_name().and_then(|s| s.to_str())
        {
            let nl = normalize_alnum(leaf);
            if nl.len() >= 3 {
                known_norms.insert(nl);
            }
        }
    }

    if let Some(g_report) = gaming {
        for g in &g_report.games {
            let nt = normalize_alnum(&g.title);
            if nt.len() >= 3 {
                known_norms.insert(nt);
            }
            if let Some(leaf) = g.install_path.file_name().and_then(|s| s.to_str()) {
                let nl = normalize_alnum(leaf);
                if nl.len() >= 3 {
                    known_norms.insert(nl);
                }
            }
        }
    }

    let safe_vendors: FxHashSet<String> = SAFE_SYSTEM_AND_RUNTIME_VENDORS
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();

    let mut candidates = Vec::new();
    let mut stack = vec![ROOT];
    while let Some(dir_id) = stack.pop() {
        let flags = index.flags(dir_id);
        if !flags.contains(NodeFlags::DIR)
            || (dir_id != ROOT
                && flags.intersects(NodeFlags::REPARSE | NodeFlags::SYSTEM | NodeFlags::ORPHANS))
        {
            continue;
        }
        let dir_path = index.path(dir_id);
        let dir_lower = dir_path.to_string_lossy().to_ascii_lowercase();

        if let Some(scope) = classify_orphan_scope(&dir_lower) {
            for child in index.children(dir_id) {
                let cflags = index.flags(child);
                if !cflags.contains(NodeFlags::DIR)
                    || cflags
                        .intersects(NodeFlags::REPARSE | NodeFlags::SYSTEM | NodeFlags::ORPHANS)
                {
                    continue;
                }
                let folder_name = index.name(child).into_owned();
                let folder_lower = folder_name.to_ascii_lowercase();
                if folder_lower.starts_with('.') || safe_vendors.contains(&folder_lower) {
                    continue;
                }
                let child_path = index.path(child);
                if is_denied_path(&child_path, &deny_ctx).is_some() {
                    continue;
                }
                if folder_matches_known_software(&folder_name, &known_norms, &known_tokens) {
                    continue;
                }
                if protected_roots
                    .iter()
                    .any(|p| is_under_root(p, &child_path))
                {
                    continue;
                }

                let OrphanSubtree {
                    allocated_bytes,
                    file_count,
                    days_since_touch,
                    has_virtual_disk,
                } = measure_orphan_subtree(index, child, now_mins);
                if has_virtual_disk || allocated_bytes < min_bytes || file_count == 0 {
                    continue;
                }

                let mut confidence: u8 = 60;
                if days_since_touch >= 30 {
                    confidence = confidence.saturating_add(15);
                }
                if days_since_touch >= 180 {
                    confidence = confidence.saturating_add(10);
                }
                if allocated_bytes >= 100 * 1024 * 1024 {
                    confidence = confidence.saturating_add(10);
                }

                candidates.push(OrphanAppCandidate {
                    scope,
                    folder_name,
                    path: child_path,
                    allocated_bytes,
                    file_count,
                    days_since_touch,
                    confidence: confidence.min(95),
                    reason: format!(
                        "No matching installed Win32/AppX program or game found in {} (untouched ~{}d)",
                        scope.display_name(),
                        days_since_touch
                    ),
                });
            }
            continue;
        }

        let start = stack.len();
        for child in index.children(dir_id) {
            stack.push(child);
        }
        stack[start..].reverse();
    }

    candidates.sort_by(|a, b| {
        b.allocated_bytes
            .cmp(&a.allocated_bytes)
            .then_with(|| b.confidence.cmp(&a.confidence))
            .then_with(|| a.path.cmp(&b.path))
    });
    let total_allocated_bytes = candidates
        .iter()
        .fold(0u64, |acc, c| acc.saturating_add(c.allocated_bytes));

    OrphanScanReport {
        candidates,
        total_allocated_bytes,
    }
}

/// Safely recycles a suspected orphaned app folder into the Windows Recycle Bin (`Recycle-only`
/// safety invariant — never permanently deletes) and appends a journal entry when `!dry_run`.
pub fn recycle_orphan_folder(
    path: &Path,
    dry_run: bool,
    journal_path: Option<&Path>,
    volume_root: &str,
    deny_ctx: &DenyContext,
) -> Result<RecycleOutcome> {
    if let Some(reason) = is_denied_path(path, deny_ctx) {
        return Err(DskError::DeniedPath(format!(
            "{reason}: {}",
            path.display()
        )));
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(DskError::PreconditionFailed(format!(
            "orphan remediation requires a real non-reparse directory: {}",
            path.display()
        )));
    }

    if dry_run {
        return Ok(RecycleOutcome {
            path: path.to_string_lossy().into_owned(),
            canonical_path: path.to_string_lossy().into_owned(),
            bytes_hint: 0,
        });
    }

    let outcome = move_to_recycle_bin(path, deny_ctx)?;
    let mut journal = ActionJournal::open(journal_path.unwrap_or(&ActionJournal::default_path()))?;
    let _ = journal.record_manual_recycle(
        volume_root,
        &outcome.canonical_path,
        outcome.bytes_hint,
        outcome.bytes_hint.min(i64::MAX as u64) as i64,
    )?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::volume::VolumeInfo;
    use crate::win::prefetch::InstalledAppSource;
    use tempfile::tempdir;

    #[test]
    fn identifies_unmatched_appdata_and_preserves_installed_apps_and_system_vendors() {
        let mut names = NameArena::new();
        let n_root = names.push_str(r"C:\");
        let mut raw = vec![RawEntry {
            key: 5,
            parent_key: 5,
            name: n_root,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: 5,
            reparse_tag: 0,
        }];
        let mut k = 10u64;
        let mut add = |parent: u64, name: &str, bytes: Option<u64>| {
            let key = k;
            k += 1;
            let n = names.push_str(name);
            let is_dir = bytes.is_none();
            let sz = bytes.unwrap_or(0);
            raw.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags: if is_dir {
                    NodeFlags::DIR
                } else {
                    NodeFlags::empty()
                },
                logical: sz,
                allocated: sz,
                mtime: 0,
                atime: 0,
                file_id: key,
                reparse_tag: 0,
            });
            key
        };

        let users = add(5, "Users", None);
        let alice = add(users, "Alice", None);
        let appdata = add(alice, "AppData", None);
        let local = add(appdata, "Local", None);

        // 1. Safe system vendor -> must NOT be flagged
        let ms = add(local, "Microsoft", None);
        add(ms, "settings.dat", Some(50_000_000));
        // 2. Installed app match -> must NOT be flagged
        let brave = add(local, "BraveSoftware", None);
        add(brave, "cache.bin", Some(120_000_000));
        // 3. Genuine uninstalled remnant -> MUST be flagged
        let leftover = add(local, "OldLegacyTool", None);
        add(leftover, "dump.bin", Some(250_000_000));
        // 4. Curated vendors (mail/browser profiles, wallets) -> must NOT be flagged
        let mozilla = add(local, "Mozilla", None);
        add(mozilla, "profile.db", Some(80_000_000));
        let roaming = add(appdata, "Roaming", None);
        let wallet = add(roaming, "Electrum", None);
        add(wallet, "wallet.dat", Some(5_000_000));
        // 5. ProgramData is out of scope (package managers/services keep live state there)
        let program_data = add(5, "ProgramData", None);
        let choco = add(program_data, "chocolatey", None);
        add(choco, "lib.bin", Some(400_000_000));

        let mut b = IndexBuilder::new(
            5,
            r"C:\",
            VolumeInfo {
                root: r"C:\".to_string(),
                ..Default::default()
            },
        );
        b.push_batch(EntryBatch {
            entries: raw,
            names,
        });
        let index = b.finish();

        let installed = vec![InstalledAppRecord {
            name: "Brave Browser".to_string(),
            publisher: Some("Brave Software Inc".to_string()),
            install_location: None,
            source: InstalledAppSource::Win32Uninstall,
            system_component: false,
        }];

        let report = scan_orphaned_app_data_with_apps(&index, &installed, None, &[], 1_048_576);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].folder_name, "OldLegacyTool");
        assert_eq!(report.candidates[0].scope, OrphanScope::AppDataLocal);
        assert_eq!(report.candidates[0].allocated_bytes, 250_000_000);
    }

    /// Regression (P9.0): `%LOCALAPPDATA%\wsl` (a live Ubuntu distro's 53.6 GiB ext4.vhdx) was
    /// reported as an orphan with 70 % confidence.
    #[test]
    fn never_flags_wsl_distros_or_folders_holding_virtual_disks() {
        let mut names = NameArena::new();
        let n_root = names.push_str(r"C:\");
        let mut raw = vec![RawEntry {
            key: 5,
            parent_key: 5,
            name: n_root,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: 5,
            reparse_tag: 0,
        }];
        let mut k = 10u64;
        let mut add = |parent: u64, name: &str, bytes: Option<u64>| {
            let key = k;
            k += 1;
            let n = names.push_str(name);
            raw.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags: if bytes.is_none() {
                    NodeFlags::DIR
                } else {
                    NodeFlags::empty()
                },
                logical: bytes.unwrap_or(0),
                allocated: bytes.unwrap_or(0),
                mtime: 0,
                atime: 0,
                file_id: key,
                reparse_tag: 0,
            });
            key
        };

        let users = add(5, "Users", None);
        let alice = add(users, "Alice", None);
        let appdata = add(alice, "AppData", None);
        let local = add(appdata, "Local", None);
        let roaming = add(appdata, "Roaming", None);

        // Default WSL store: safe-listed name and contains a VHDX.
        let wsl = add(local, "wsl", None);
        let distro = add(wsl, "{11111111-2222-3333-4444-555555555555}", None);
        add(distro, "ext4.vhdx", Some(57_588_842_496));
        // Unknown vendor folder whose only distinguishing trait is a nested virtual disk.
        let vms = add(local, "RetroLabVMs", None);
        let vm_dir = add(vms, "win98", None);
        add(vm_dir, "Win98.VDI", Some(2_000_000_000));
        // A distro imported to a custom location that holds no VHDX at the top (protected root).
        let imported = add(roaming, "ImportedDistro", None);
        let rootfs = add(imported, "rootfs", None);
        add(rootfs, "layer.tar", Some(900_000_000));
        // A genuine leftover must still be found.
        let leftover = add(local, "OldLegacyTool", None);
        add(leftover, "dump.bin", Some(250_000_000));

        let mut b = IndexBuilder::new(
            5,
            r"C:\",
            VolumeInfo {
                root: r"C:\".to_string(),
                ..Default::default()
            },
        );
        b.push_batch(EntryBatch {
            entries: raw,
            names,
        });
        let index = b.finish();

        let protected = [PathBuf::from(
            r"c:\users\alice\appdata\roaming\ImportedDistro\rootfs",
        )];
        let report = scan_orphaned_app_data_with_apps(&index, &[], None, &protected, 1_048_576);
        let flagged: Vec<&str> = report
            .candidates
            .iter()
            .map(|c| c.folder_name.as_str())
            .collect();
        assert_eq!(flagged, ["OldLegacyTool"], "got {flagged:?}");
        assert_eq!(report.total_allocated_bytes, 250_000_000);

        // Without the protected root, the imported distro folder would be flagged.
        let unprotected = scan_orphaned_app_data_with_apps(&index, &[], None, &[], 1_048_576);
        assert!(
            unprotected
                .candidates
                .iter()
                .any(|c| c.folder_name == "ImportedDistro")
        );
        assert!(is_virtual_disk_name("ext4.VHDX") && !is_virtual_disk_name("vhdx.txt"));
    }

    #[test]
    fn recycle_orphan_folder_supports_dry_run_and_rejects_denied_or_non_dir() {
        let dir = tempdir().expect("tempdir");
        let folder = dir.path().join("LeftoverApp");
        std::fs::create_dir_all(&folder).expect("mkdir");
        let deny_ctx = DenyContext::default();

        let dry = recycle_orphan_folder(
            &folder,
            true,
            Some(&dir.path().join("j.sqlite")),
            r"C:\",
            &deny_ctx,
        )
        .expect("dry run succeeds");
        assert!(folder.exists());
        assert_eq!(dry.bytes_hint, 0);

        let file = dir.path().join("regular.txt");
        std::fs::write(&file, b"hello").expect("write");
        assert!(
            recycle_orphan_folder(&file, false, None, r"C:\", &deny_ctx).is_err(),
            "files should be rejected by folder helper"
        );
        assert!(
            recycle_orphan_folder(
                Path::new(r"C:\Windows\System32"),
                true,
                None,
                r"C:\",
                &deny_ctx
            )
            .is_err(),
            "denied system paths must be rejected"
        );
    }
}
