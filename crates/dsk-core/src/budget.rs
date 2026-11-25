#![forbid(unsafe_code)]

//! "Keep it free" (P9.9): an opt-in free-space budget for the tray agent and alerts for known
//! fast-growing folders.
//!
//! Budget mode runs only the safe part of the reclaim ledger (🟢 regenerable rules, stale build
//! sweeps) and re-applies WOF compression to recorded folders, at most once a day, on AC power,
//! and only after the owner set a budget (`disksaver-tray --budget <GiB>`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const GIB: u64 = 1 << 30;

/// Persisted tray settings (`%APPDATA%\DiskSaver\tray.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayConfig {
    /// Keep at least this many GiB free on the system drive. `None` = budget mode off.
    #[serde(default)]
    pub budget_gib: Option<u64>,
    #[serde(default)]
    pub last_budget_run_unix: Option<i64>,
    /// Last measured size and time per watched folder.
    #[serde(default)]
    pub offender_samples: BTreeMap<String, (u64, i64)>,
    #[serde(default)]
    pub last_offender_check_unix: Option<i64>,
}

pub fn default_config_path() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("DiskSaver")
        .join("tray.json")
}

/// Loads the config; a missing or unreadable file is the default (budget off).
pub fn load_config(path: &Path) -> TrayConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_config(path: &Path, cfg: &TrayConfig) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(cfg).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&tmp, path)
}

/// Seconds between budget runs.
pub const BUDGET_MIN_INTERVAL_SECS: i64 = 24 * 3600;

/// Whether the budget run is due: budget set, free space below it, on AC power, and not run in
/// the last 24 hours.
pub fn budget_run_due(cfg: &TrayConfig, free_bytes: u64, on_ac: bool, now_unix: i64) -> bool {
    let Some(budget) = cfg.budget_gib else {
        return false;
    };
    on_ac
        && free_bytes < budget.saturating_mul(GIB)
        && cfg
            .last_budget_run_unix
            .is_none_or(|t| now_unix - t >= BUDGET_MIN_INTERVAL_SECS)
}

/// Folders that are known to grow fast when something goes wrong or is left unchecked.
pub fn offender_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        out.push(local.join("NVIDIA").join("DXCache"));
        out.push(local.join("Temp"));
        out.push(local.join("CrashDumps"));
        out.push(local.join("D3DSCache"));
    }
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        out.push(home.join("Videos").join("Captures"));
        out.push(home.join("Videos").join("NVIDIA"));
    }
    for d in crate::win::wsl::registered_wsl_distros() {
        out.push(d.vhdx_path);
    }
    out.retain(|p| p.exists());
    out
}

/// Size of a file, or of a folder walked up to `max_entries` entries (`None` if the cap was hit,
/// so a huge folder never makes the tray busy).
pub fn measure_capped(path: &Path, max_entries: usize) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.is_file() {
        return Some(meta.len());
    }
    let mut total = 0u64;
    let mut seen = 0usize;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > max_entries {
                return None;
            }
            let Ok(m) = e.metadata() else { continue };
            if m.file_type().is_symlink() {
                continue;
            }
            if m.is_dir() {
                stack.push(e.path());
            } else {
                total = total.saturating_add(m.len());
            }
        }
    }
    Some(total)
}

/// A folder growing fast.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OffenderAlert {
    pub path: PathBuf,
    pub bytes: u64,
    pub growth_per_day: u64,
}

/// Alert threshold.
pub const OFFENDER_BYTES_PER_DAY: u64 = 2 * GIB;

/// Compares new samples with the stored ones and updates them. Needs at least 6 hours between
/// samples so short bursts (an installer unpacking to %TEMP%) do not alert.
pub fn offender_alerts(
    cfg: &mut TrayConfig,
    samples: &[(PathBuf, u64)],
    now_unix: i64,
) -> Vec<OffenderAlert> {
    let mut alerts = Vec::new();
    for (path, bytes) in samples {
        let key = path.display().to_string();
        if let Some(&(prev, at)) = cfg.offender_samples.get(&key) {
            let hours = (now_unix - at) as f64 / 3600.0;
            if hours >= 6.0 {
                let per_day = (bytes.saturating_sub(prev) as f64 * 24.0 / hours) as u64;
                if per_day >= OFFENDER_BYTES_PER_DAY {
                    alerts.push(OffenderAlert {
                        path: path.clone(),
                        bytes: *bytes,
                        growth_per_day: per_day,
                    });
                }
                cfg.offender_samples.insert(key, (*bytes, now_unix));
            }
        } else {
            cfg.offender_samples.insert(key, (*bytes, now_unix));
        }
    }
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_runs_only_when_due() {
        let mut cfg = TrayConfig::default();
        assert!(!budget_run_due(&cfg, 0, true, 1000), "off by default");
        cfg.budget_gib = Some(20);
        assert!(budget_run_due(&cfg, 10 * GIB, true, 1000));
        assert!(!budget_run_due(&cfg, 10 * GIB, false, 1000), "on battery");
        assert!(!budget_run_due(&cfg, 30 * GIB, true, 1000), "above budget");
        cfg.last_budget_run_unix = Some(1000);
        assert!(
            !budget_run_due(&cfg, 10 * GIB, true, 1000 + 3600),
            "ran an hour ago"
        );
        assert!(budget_run_due(&cfg, 10 * GIB, true, 1000 + 25 * 3600));
    }

    #[test]
    fn offender_growth_needs_time_and_volume() {
        let mut cfg = TrayConfig::default();
        let p = PathBuf::from(r"C:\x\DXCache");
        assert!(
            offender_alerts(&mut cfg, &[(p.clone(), GIB)], 0).is_empty(),
            "first sample"
        );
        assert!(
            offender_alerts(&mut cfg, &[(p.clone(), 5 * GIB)], 3600).is_empty(),
            "too soon"
        );
        // +3 GiB in 12 h = 6 GiB/day.
        let a = offender_alerts(&mut cfg, &[(p.clone(), 4 * GIB)], 12 * 3600);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].growth_per_day, 6 * GIB);
        // Slow growth does not alert.
        assert!(offender_alerts(&mut cfg, &[(p, 4 * GIB + 1)], 36 * 3600).is_empty());
    }

    #[test]
    fn config_roundtrip_and_capped_measure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("tray.json");
        assert_eq!(load_config(&path), TrayConfig::default());
        let cfg = TrayConfig {
            budget_gib: Some(25),
            ..Default::default()
        };
        save_config(&path, &cfg).unwrap();
        assert_eq!(load_config(&path), cfg);

        let d = dir.path().join("m");
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::write(d.join("a").join("f"), vec![0u8; 1000]).unwrap();
        std::fs::write(d.join("g"), vec![0u8; 24]).unwrap();
        assert_eq!(measure_capped(&d, 100), Some(1024));
        assert_eq!(measure_capped(&d, 1), None, "cap reached");
    }
}
