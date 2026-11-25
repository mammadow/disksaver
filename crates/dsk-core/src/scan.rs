#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};
use crate::index::{Index, ROOT};
use crate::ntfs::{Progress, assemble, read_mft_layout, scan_mft};
use crate::volume::VolumeInfo;
use crate::win::{
    DirScanOptions, enable_privilege, is_elevated, open_volume, scan_dirs, volume_info,
    volume_root_of,
};

/// Method used or requested for volume scanning.
use crate::index::snapshot::{
    SnapshotMeta, default_snapshot_dir, load_snapshot_verified, save_snapshot_atomic,
    snapshot_path_for_volume,
};
use crate::ntfs::usn::{UsnDelta, validate_usn_continuity};
use crate::win::usn::{DEFAULT_MAX_USN_EVENTS, query_usn_journal, read_usn_deltas_since};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanMethod {
    #[default]
    Auto,
    Mft,
    Dir,
    UsnIncremental,
}

/// Options controlling volume scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanOptions {
    pub method: ScanMethod,
    pub threads: Option<usize>,
    pub use_cache: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            method: ScanMethod::Auto,
            threads: None,
            use_cache: true,
        }
    }
}

/// Self-check verifying MFT scanned allocation against filesystem volume used space.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct UsageCheck {
    pub scanned_alloc: u64,
    pub volume_used: u64,
    pub diff_pct: f64,
}

/// Consolidated scan report containing the generated index, metrics, and diagnostics.
#[derive(Debug)]
pub struct ScanReport {
    pub index: Index,
    pub method_used: ScanMethod,
    pub elapsed: Duration,
    pub skipped: u64,
    pub check: Option<UsageCheck>,
    pub fallback_reason: Option<String>,
}

/// Determines the scan method to employ based on caller request and environment capabilities.
pub fn choose_method(
    requested: ScanMethod,
    volume_root: Option<&str>,
    fs_name: &str,
    elevated: bool,
) -> Result<ScanMethod> {
    match requested {
        ScanMethod::Dir => Ok(ScanMethod::Dir),
        ScanMethod::Mft => {
            if volume_root.is_none() {
                return Err(DskError::NotVolumeRoot(String::new()));
            }
            if !fs_name.eq_ignore_ascii_case("NTFS") {
                return Err(DskError::Unsupported(fs_name.to_string()));
            }
            if !elevated {
                return Err(DskError::NotElevated);
            }
            Ok(ScanMethod::Mft)
        }
        ScanMethod::UsnIncremental => {
            if volume_root.is_none() {
                return Err(DskError::NotVolumeRoot(String::new()));
            }
            if !fs_name.eq_ignore_ascii_case("NTFS") {
                return Err(DskError::Unsupported(fs_name.to_string()));
            }
            if !elevated {
                return Err(DskError::NotElevated);
            }
            Ok(ScanMethod::UsnIncremental)
        }
        ScanMethod::Auto => {
            if volume_root.is_some() && fs_name.eq_ignore_ascii_case("NTFS") && elevated {
                Ok(ScanMethod::Mft)
            } else {
                Ok(ScanMethod::Dir)
            }
        }
    }
}

fn calculate_diff_pct(scanned_alloc: u64, volume_used: u64) -> f64 {
    if volume_used == 0 {
        if scanned_alloc == 0 { 0.0 } else { 100.0 }
    } else {
        (scanned_alloc as f64 - volume_used as f64).abs() / (volume_used as f64) * 100.0
    }
}

fn execute_mft(
    root: &str,
    vol: &VolumeInfo,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<(Index, u64, UsageCheck)> {
    let _ = enable_privilege("SeBackupPrivilege");
    let handle = open_volume(root)?;
    let boot = handle.boot_sector()?;
    let layout = read_mft_layout(&handle, &boot)?;
    let out = scan_mft(&handle, &layout, progress, cancel)?;
    let skipped = out.skipped;
    let index = assemble(out, vol.clone());

    let scanned_alloc = index.total_allocated(ROOT);
    let volume_used = vol.total_bytes.saturating_sub(vol.free_bytes);
    let diff_pct = calculate_diff_pct(scanned_alloc, volume_used);

    Ok((
        index,
        skipped,
        UsageCheck {
            scanned_alloc,
            volume_used,
            diff_pct,
        },
    ))
}

fn execute_dir(
    path: &Path,
    vol_root: Option<&str>,
    vol: VolumeInfo,
    opts: &ScanOptions,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<(Index, u64)> {
    if vol_root.is_some() && is_elevated() {
        let _ = enable_privilege("SeBackupPrivilege");
    }
    let mut dir_opts = DirScanOptions::for_volume(&vol);
    if let Some(t) = opts.threads {
        dir_opts.threads = t.max(1);
    }
    let target_path = vol_root.map(Path::new).unwrap_or(path);
    let dir_out = scan_dirs(target_path, vol, &dir_opts, progress, cancel)?;
    Ok((dir_out.index, dir_out.skipped))
}

/// Scans a directory or volume into an [`Index`].
pub fn scan_volume(
    path: &Path,
    opts: &ScanOptions,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<ScanReport> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let start = Instant::now();
    let vol_root = volume_root_of(path);

    if opts.method == ScanMethod::Mft && vol_root.is_none() {
        return Err(DskError::NotVolumeRoot(path.display().to_string()));
    }

    let vol = if let Some(ref r) = vol_root {
        volume_info(r)?
    } else {
        std::fs::metadata(path)?;
        let enclosing_vol = std::path::absolute(path).ok().and_then(|abs| {
            abs.components().next().and_then(|comp| {
                if let std::path::Component::Prefix(prefix) = comp {
                    match prefix.kind() {
                        std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => {
                            let drive_root = format!("{}:\\", d as char);
                            volume_info(&drive_root).ok()
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            })
        });
        enclosing_vol.unwrap_or_else(|| VolumeInfo {
            cluster_size: 4096,
            ..Default::default()
        })
    };

    let chosen = choose_method(
        opts.method,
        vol_root.as_deref(),
        &vol.fs_name,
        is_elevated(),
    )?;

    scan_volume_chosen(
        path, opts, vol_root, vol, chosen, None, start, progress, cancel,
    )
}

/// Scans a path or volume using an explicit snapshot cache directory (useful for isolated tests).
pub fn scan_volume_with_cache_dir(
    path: &Path,
    opts: &ScanOptions,
    cache_dir: Option<&Path>,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<ScanReport> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let start = Instant::now();
    let vol_root = volume_root_of(path);

    if (opts.method == ScanMethod::Mft || opts.method == ScanMethod::UsnIncremental)
        && vol_root.is_none()
    {
        return Err(DskError::NotVolumeRoot(path.display().to_string()));
    }

    let vol = if let Some(ref r) = vol_root {
        volume_info(r)?
    } else {
        std::fs::metadata(path)?;
        let enclosing_vol = std::path::absolute(path).ok().and_then(|abs| {
            abs.components().next().and_then(|comp| {
                if let std::path::Component::Prefix(prefix) = comp {
                    match prefix.kind() {
                        std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => {
                            let drive_root = format!("{}:\\", d as char);
                            volume_info(&drive_root).ok()
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            })
        });
        enclosing_vol.unwrap_or_else(|| VolumeInfo {
            cluster_size: 4096,
            ..Default::default()
        })
    };

    let chosen = choose_method(
        opts.method,
        vol_root.as_deref(),
        &vol.fs_name,
        is_elevated(),
    )?;

    scan_volume_chosen(
        path, opts, vol_root, vol, chosen, cache_dir, start, progress, cancel,
    )
}

fn apply_cached_snapshot_with_provider<F>(
    vol: &VolumeInfo,
    snap_path: &Path,
    start: Instant,
    fetch_deltas: F,
) -> Result<ScanReport>
where
    F: FnOnce(&SnapshotMeta) -> Result<(u64, i64, Vec<UsnDelta>)>,
{
    let (meta, mut cached) = load_snapshot_verified(snap_path)?;
    if meta.volume_serial != vol.serial || !meta.volume_root.eq_ignore_ascii_case(&vol.root) {
        return Err(DskError::Unsupported(
            "cached snapshot volume metadata mismatch".to_string(),
        ));
    }
    if cached.method_used != ScanMethod::Mft && cached.method_used != ScanMethod::UsnIncremental {
        return Err(DskError::Unsupported(
            "cached snapshot was not created from an MFT scan".to_string(),
        ));
    }

    let (journal_id, new_next_usn, deltas) = fetch_deltas(&meta)?;
    if !deltas.is_empty() || cached.index.volume().free_bytes != vol.free_bytes {
        cached
            .index
            .apply_usn_deltas_with_volume(&deltas, Some(vol.clone()))?;
    }

    let report = ScanReport {
        index: cached.index,
        method_used: ScanMethod::UsnIncremental,
        elapsed: start.elapsed(),
        skipped: 0,
        check: None,
        fallback_reason: None,
    };

    if new_next_usn != meta.next_usn || journal_id != meta.usn_journal_id {
        let updated_meta = SnapshotMeta {
            volume_root: vol.root.clone(),
            volume_serial: vol.serial,
            usn_journal_id: journal_id,
            next_usn: new_next_usn,
            created_at_unix: SnapshotMeta::now_unix(),
        };
        let _ = save_snapshot_atomic(snap_path, &updated_meta, &report);
    }

    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn scan_volume_chosen(
    path: &Path,
    opts: &ScanOptions,
    vol_root: Option<String>,
    vol: VolumeInfo,
    chosen: ScanMethod,
    cache_dir: Option<&Path>,
    start: Instant,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<ScanReport> {
    let mut fallback_reason = None;

    if chosen == ScanMethod::Mft || chosen == ScanMethod::UsnIncremental {
        let root = vol_root
            .as_deref()
            .expect("volume_root guaranteed present when chosen is Mft/UsnIncremental");

        let effective_cache_dir = cache_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(default_snapshot_dir);
        let snap_path = snapshot_path_for_volume(&effective_cache_dir, root, vol.serial);

        if opts.use_cache
            && (opts.method == ScanMethod::Auto || opts.method == ScanMethod::UsnIncremental)
            && snap_path.exists()
        {
            progress(Progress {
                phase: crate::ntfs::Phase::Aggregating,
                done: 0,
                total: 0,
            });
            match apply_cached_snapshot_with_provider(&vol, &snap_path, start, |meta| {
                let live_usn = query_usn_journal(root)?;
                validate_usn_continuity(meta.usn_journal_id, meta.next_usn, &live_usn)?;
                let (new_next_usn, deltas) = read_usn_deltas_since(
                    root,
                    live_usn.usn_journal_id,
                    meta.next_usn,
                    live_usn.next_usn,
                    vol.cluster_size,
                    DEFAULT_MAX_USN_EVENTS,
                )?;
                Ok((live_usn.usn_journal_id, new_next_usn, deltas))
            }) {
                Ok(report) => return Ok(report),
                Err(e) => {
                    fallback_reason =
                        Some(format!("USN incremental cache fallback to full scan: {e}"));
                }
            }
        }

        // Capture the USN cursor BEFORE the MFT read: changes made while the scan runs then lie
        // after the saved `next_usn` and are replayed by the next incremental scan (replaying an
        // already-reflected change is harmless because upserts re-read live state). Capturing it
        // afterwards would silently drop those changes forever.
        let pre_scan_usn = if opts.use_cache {
            query_usn_journal(root).ok()
        } else {
            None
        };

        if opts.method == ScanMethod::Mft {
            let (index, skipped, check) = execute_mft(root, &vol, progress, cancel)?;
            let report = ScanReport {
                index,
                method_used: ScanMethod::Mft,
                elapsed: start.elapsed(),
                skipped,
                check: Some(check),
                fallback_reason: None,
            };
            if let Some(live_usn) = pre_scan_usn {
                let meta = SnapshotMeta {
                    volume_root: root.to_string(),
                    volume_serial: vol.serial,
                    usn_journal_id: live_usn.usn_journal_id,
                    next_usn: live_usn.next_usn,
                    created_at_unix: SnapshotMeta::now_unix(),
                };
                let _ = save_snapshot_atomic(&snap_path, &meta, &report);
            }
            return Ok(report);
        }

        // Under ScanMethod::Auto or UsnIncremental fallback
        match execute_mft(root, &vol, progress, cancel) {
            Ok((index, skipped, check)) if check.diff_pct <= 2.0 => {
                let report = ScanReport {
                    index,
                    method_used: ScanMethod::Mft,
                    elapsed: start.elapsed(),
                    skipped,
                    check: Some(check),
                    fallback_reason,
                };
                if let Some(live_usn) = pre_scan_usn {
                    let meta = SnapshotMeta {
                        volume_root: root.to_string(),
                        volume_serial: vol.serial,
                        usn_journal_id: live_usn.usn_journal_id,
                        next_usn: live_usn.next_usn,
                        created_at_unix: SnapshotMeta::now_unix(),
                    };
                    let _ = save_snapshot_atomic(&snap_path, &meta, &report);
                }
                return Ok(report);
            }
            Ok((_, _, check)) => {
                fallback_reason = Some(format!(
                    "usage check failed: diff {:.2}% > 2.0%",
                    check.diff_pct
                ));
            }
            Err(DskError::Cancelled) => return Err(DskError::Cancelled),
            Err(e) => {
                fallback_reason = Some(format!("MFT scan failed: {e}"));
            }
        }
    }

    let (index, skipped) = execute_dir(path, vol_root.as_deref(), vol, opts, progress, cancel)?;

    Ok(ScanReport {
        index,
        method_used: ScanMethod::Dir,
        elapsed: start.elapsed(),
        skipped,
        check: None,
        fallback_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_derive() {
        assert_eq!(ScanMethod::default(), ScanMethod::Auto);
        let opts = ScanOptions::default();
        assert_eq!(opts.method, ScanMethod::Auto);
        assert!(opts.use_cache);

        let dir = tempfile::tempdir().unwrap();
        let snap_path = snapshot_path_for_volume(dir.path(), "C:\\", 0xCAFE_BABE);
        let vol = VolumeInfo {
            root: "C:\\".to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0xCAFE_BABE,
            cluster_size: 4096,
            total_bytes: 1_000_000,
            free_bytes: 500_000,
            seek_penalty: Some(false),
        };
        let mut names = crate::index::names::NameArena::new();
        let fname = names.push_str("cached.dat");
        let mut builder = crate::index::builder::IndexBuilder::new(5, "C:\\", vol.clone());
        builder.push_batch(crate::index::builder::EntryBatch {
            names,
            entries: vec![crate::index::builder::RawEntry {
                key: 10,
                parent_key: 5,
                file_id: 10,
                name: fname,
                logical: 4_000,
                allocated: 4_096,
                mtime: 10,
                atime: 10,
                flags: crate::index::builder::NodeFlags::empty(),
                reparse_tag: 0,
            }],
        });
        let cached_report = ScanReport {
            index: builder.finish(),
            method_used: ScanMethod::Mft,
            elapsed: Duration::from_millis(5),
            skipped: 0,
            check: None,
            fallback_reason: None,
        };
        let meta = SnapshotMeta {
            volume_root: "C:\\".to_string(),
            volume_serial: 0xCAFE_BABE,
            usn_journal_id: 9001,
            next_usn: 1000,
            created_at_unix: 1_700_000_000,
        };
        save_snapshot_atomic(&snap_path, &meta, &cached_report).unwrap();

        // Continuous USN deltas apply cleanly and update snapshot next_usn.
        let res = apply_cached_snapshot_with_provider(&vol, &snap_path, Instant::now(), |m| {
            let live = crate::ntfs::usn::UsnJournalState {
                usn_journal_id: 9001,
                first_usn: 500,
                next_usn: 2000,
                lowest_valid_usn: 500,
            };
            validate_usn_continuity(m.usn_journal_id, m.next_usn, &live)?;
            Ok((
                live.usn_journal_id,
                live.next_usn,
                vec![UsnDelta::Upsert {
                    file_id: 20,
                    parent_file_id: 5,
                    old_parent_file_id: None,
                    old_name: None,
                    name: "added.dat".to_string(),
                    logical: 8_000,
                    allocated: 8_192,
                    mtime: 50,
                    atime: 50,
                    flags: crate::index::builder::NodeFlags::empty(),
                    reparse_tag: 0,
                    preserve_existing_sizes_if_unreadable: false,
                }],
            ))
        })
        .unwrap();
        assert_eq!(res.method_used, ScanMethod::UsnIncremental);
        assert_eq!(res.index.agg_alloc_slice()[0], 4_096 + 8_192);
        let (reloaded_meta, reloaded_rep) = load_snapshot_verified(&snap_path).unwrap();
        assert_eq!(reloaded_meta.next_usn, 2000);
        assert_eq!(reloaded_rep.method_used, ScanMethod::UsnIncremental);

        // Journal wrap triggers clean Err for fallback to full scan.
        let wrap_err = apply_cached_snapshot_with_provider(&vol, &snap_path, Instant::now(), |m| {
            let live = crate::ntfs::usn::UsnJournalState {
                usn_journal_id: 9001,
                first_usn: 5000,
                next_usn: 9000,
                lowest_valid_usn: 5000,
            };
            validate_usn_continuity(m.usn_journal_id, m.next_usn, &live)?;
            unreachable!()
        })
        .unwrap_err();
        assert!(wrap_err.to_string().contains("wrapped"));

        // Corrupt snapshot returns Err for clean fallback to full scan.
        std::fs::write(&snap_path, b"corrupted garbage").unwrap();
        assert!(
            apply_cached_snapshot_with_provider(&vol, &snap_path, Instant::now(), |_| Ok((
                0,
                0,
                vec![]
            )))
            .is_err()
        );
        assert_eq!(opts.threads, None);

        let check = UsageCheck {
            scanned_alloc: 1000,
            volume_used: 1010,
            diff_pct: 0.99,
        };
        let cloned_check = check;
        assert_eq!(check, cloned_check);
    }

    #[test]
    fn diff_pct_formula() {
        assert_eq!(calculate_diff_pct(0, 0), 0.0);
        assert_eq!(calculate_diff_pct(100, 0), 100.0);
        assert!((calculate_diff_pct(101, 100) - 1.0).abs() < 1e-9);
        assert!((calculate_diff_pct(99, 100) - 1.0).abs() < 1e-9);
        assert!((calculate_diff_pct(102, 100) - 2.0).abs() < 1e-9);
        assert!((calculate_diff_pct(103, 100) - 3.0).abs() < 1e-9);
    }

    #[test]
    fn choose_method_case_insensitivity() {
        assert_eq!(
            choose_method(ScanMethod::Auto, Some("C:\\"), "ntfs", true).unwrap(),
            ScanMethod::Mft
        );
        assert_eq!(
            choose_method(ScanMethod::Mft, Some("C:\\"), "NtFs", true).unwrap(),
            ScanMethod::Mft
        );
        assert_eq!(
            choose_method(ScanMethod::Auto, Some("D:\\"), "refs", true).unwrap(),
            ScanMethod::Dir
        );
        assert!(matches!(
            choose_method(ScanMethod::Mft, Some("D:\\"), "ReFS", true),
            Err(DskError::Unsupported(fs)) if fs == "ReFS"
        ));
    }
}
