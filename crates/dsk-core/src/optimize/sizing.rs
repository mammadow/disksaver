#![forbid(unsafe_code)]

//! System sizing advisor (P9.5): hibernation, pagefile, CompactOS, Reserved Storage, and shadow
//! storage recommendations computed from measured facts. Pure functions plus one live gatherer.
//!
//! Every recommendation that changes a setting maps to an [`OptimizerIntent`] (scalar parameters
//! only), so it can run through the elevated helper without passing paths or command lines.

use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};
use crate::index::{Index, ROOT};
use crate::optimize::intent::OptimizerIntent;
use crate::optimize::sys_tunables::{HiberfileMode, SystemTunablesStatus};
use crate::win::sysinfo::{crash_dump_mode, hibernation_facts, memory_facts, read_paging_files};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// One configured pagefile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagefileEntry {
    /// Drive letter with colon, e.g. `C:`.
    pub drive: String,
    /// Initial size in MiB; `0` together with `max_mb == 0` means system managed.
    pub initial_mb: u32,
    pub max_mb: u32,
}

/// How pagefiles are configured (`Memory Management\PagingFiles`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PagefileConfig {
    /// `?:\pagefile.sys`: Windows manages size and location on all drives.
    Automatic,
    /// Explicit per-drive entries.
    Entries { entries: Vec<PagefileEntry> },
    /// No pagefile at all.
    Disabled,
    #[default]
    Unknown,
}

/// Parses `PagingFiles` registry strings.
pub fn parse_paging_files(raw: &[String]) -> PagefileConfig {
    if raw.is_empty() {
        return PagefileConfig::Disabled;
    }
    let mut entries = Vec::new();
    for line in raw {
        let mut parts = line.split_whitespace();
        let Some(path) = parts.next() else { continue };
        if path.starts_with("?:") {
            return PagefileConfig::Automatic;
        }
        let b = path.as_bytes();
        if b.len() < 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
            return PagefileConfig::Unknown;
        }
        let initial_mb = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let max_mb = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        entries.push(PagefileEntry {
            drive: format!("{}:", (b[0] as char).to_ascii_uppercase()),
            initial_mb,
            max_mb,
        });
    }
    if entries.is_empty() {
        PagefileConfig::Unknown
    } else {
        PagefileConfig::Entries { entries }
    }
}

/// Builds the `PagingFiles` value for a pagefile intent from validated scalars only.
pub fn paging_files_value(intent: &OptimizerIntent) -> Result<Vec<String>> {
    intent.validate()?;
    match intent {
        OptimizerIntent::SetPagefile {
            drive,
            initial_mb,
            max_mb,
        } => Ok(vec![format!(
            r"{}\pagefile.sys {initial_mb} {max_mb}",
            normalize_drive(drive)?
        )]),
        OptimizerIntent::SetPagefileSystemManaged { drive } => Ok(vec![format!(
            r"{}\pagefile.sys 0 0",
            normalize_drive(drive)?
        )]),
        OptimizerIntent::SetPagefileAutomatic => Ok(vec![r"?:\pagefile.sys".to_string()]),
        other => Err(DskError::Optimize(format!(
            "{} is not a pagefile intent",
            other.label()
        ))),
    }
}

fn normalize_drive(drive: &str) -> Result<String> {
    let b = drive.trim().trim_end_matches(['\\', '/']).as_bytes();
    if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        Ok(format!("{}:", (b[0] as char).to_ascii_uppercase()))
    } else {
        Err(DskError::Optimize(format!(
            "expected a bare drive letter like C: (got '{drive}')"
        )))
    }
}

/// Measured inputs for [`advise_sizing`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizingFacts {
    pub system_drive: String,
    pub volume_total_bytes: u64,
    pub ram_bytes: Option<u64>,
    pub commit_peak_bytes: Option<u64>,
    pub commit_limit_bytes: Option<u64>,
    pub pagefile: PagefileConfig,
    /// Current size of `<system drive>\pagefile.sys`.
    pub pagefile_bytes: Option<u64>,
    /// `CrashDumpEnabled`: 0 none, 1 complete, 2 kernel, 3 small, 7 automatic.
    pub crash_dump_mode: Option<u32>,
    /// `HiberFileType`: 1 reduced, 2 full.
    pub hiber_file_type: Option<u32>,
    pub hibernate_enabled: Option<bool>,
    pub hiberfil_bytes: Option<u64>,
    pub battery_present: bool,
    pub compact_os_enabled: Option<bool>,
    pub reserved_storage_enabled: Option<bool>,
    pub vss_used_bytes: Option<u64>,
    pub vss_max_bytes: Option<u64>,
}

/// Collects [`SizingFacts`] from a tunables probe plus live memory and registry reads.
pub fn gather_sizing_facts(
    status: &SystemTunablesStatus,
    index: Option<&Index>,
    compact_os_enabled: Option<bool>,
) -> SizingFacts {
    let mem = memory_facts();
    let (hiber_file_type, hibernate_enabled) = hibernation_facts();
    let drive = if status.system_drive.is_empty() {
        "C:".to_string()
    } else {
        status.system_drive.clone()
    };
    let pagefile_bytes = index
        .and_then(|ix| {
            ix.children(ROOT)
                .find(|&c| ix.name(c).eq_ignore_ascii_case("pagefile.sys"))
                .map(|c| ix.allocated(c))
        })
        .or_else(|| {
            std::fs::metadata(format!(r"{drive}\pagefile.sys"))
                .ok()
                .map(|m| m.len())
        });
    SizingFacts {
        system_drive: drive,
        volume_total_bytes: index.map(|ix| ix.volume().total_bytes).unwrap_or(0),
        ram_bytes: mem.map(|m| m.physical_bytes),
        commit_peak_bytes: mem.map(|m| m.commit_peak_bytes),
        commit_limit_bytes: mem.map(|m| m.commit_limit_bytes),
        pagefile: read_paging_files()
            .map(|r| parse_paging_files(&r))
            .unwrap_or_default(),
        pagefile_bytes,
        crash_dump_mode: crash_dump_mode(),
        hiber_file_type,
        hibernate_enabled,
        hiberfil_bytes: status.hiberfil_bytes,
        battery_present: status.is_laptop_battery_present,
        compact_os_enabled,
        reserved_storage_enabled: status.reserved_storage_enabled,
        vss_used_bytes: status.vss_used_bytes,
        vss_max_bytes: status.vss_max_bytes,
    }
}

/// How sure an estimate is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizingConfidence {
    /// Computed from measured sizes.
    Measured,
    /// A typical figure; the real amount is known only after applying.
    Typical,
}

/// One sizing recommendation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SizingRecommendation {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub current_bytes: u64,
    pub est_savings_bytes: u64,
    pub confidence: SizingConfidence,
    pub intent: Option<OptimizerIntent>,
    pub requires_admin: bool,
    pub requires_reboot: bool,
    /// What the owner gives up.
    pub caveat: String,
}

/// Smallest pagefile the advisor will propose, in MiB.
pub const MIN_RECOMMENDED_PAGEFILE_MB: u32 = 4096;

/// Recommended fixed pagefile `(initial_mb, max_mb)`: large enough that RAM + pagefile is at least
/// 1.5 × the observed commit peak, never below [`MIN_RECOMMENDED_PAGEFILE_MB`]. `None` when the
/// crash-dump mode needs a RAM-sized pagefile (complete, kernel, or automatic dumps), or when
/// memory facts are missing.
pub fn recommended_pagefile_mb(f: &SizingFacts) -> Option<(u32, u32)> {
    let ram = f.ram_bytes?;
    let peak = f.commit_peak_bytes?;
    if !matches!(f.crash_dump_mode, Some(0) | Some(3)) {
        return None;
    }
    let needed = (peak.saturating_mul(3) / 2).saturating_sub(ram);
    let needed_mb = needed.div_ceil(MIB).div_ceil(1024) * 1024;
    let initial = (needed_mb as u32).max(MIN_RECOMMENDED_PAGEFILE_MB);
    let max = initial.saturating_mul(2).max(8192);
    Some((initial, max))
}

/// Checks that a fixed pagefile keeps the commit limit at ≥ 1.5 × the observed peak. Fails closed
/// when memory facts are unavailable.
pub fn check_pagefile_commit_safety(max_mb: u32) -> Result<()> {
    let mem = memory_facts().ok_or_else(|| {
        DskError::PreconditionFailed(
            "cannot read memory commit figures; refusing to resize the pagefile".to_string(),
        )
    })?;
    let limit = mem.physical_bytes.saturating_add(u64::from(max_mb) * MIB);
    let need = mem.commit_peak_bytes.saturating_mul(3) / 2;
    if limit < need {
        return Err(DskError::PreconditionFailed(format!(
            "RAM + {max_mb} MiB pagefile = {:.1} GiB, below 1.5 × the observed commit peak ({:.1} GiB)",
            limit as f64 / GIB as f64,
            need as f64 / GIB as f64
        )));
    }
    Ok(())
}

/// Computes sizing recommendations, largest savings first.
pub fn advise_sizing(f: &SizingFacts) -> Vec<SizingRecommendation> {
    let mut out = Vec::new();

    // Hibernation: Full keeps a RAM image; Reduced keeps Fast Startup only (~20 % of RAM).
    if let (Some(hiber), Some(ram)) = (f.hiberfil_bytes, f.ram_bytes)
        && f.hibernate_enabled != Some(false)
        && hiber >= GIB
    {
        let reduced_target = ram / 5;
        let is_full = f.hiber_file_type == Some(2) || hiber > ram * 3 / 10;
        if is_full && hiber > reduced_target + GIB {
            out.push(SizingRecommendation {
                id: "sizing:hiberfile_reduced".into(),
                title: "Hibernation file: Full → Reduced".into(),
                detail: format!(
                    "hiberfil.sys is {:.1} GiB; Reduced keeps Fast Startup at about 20 % of RAM.",
                    hiber as f64 / GIB as f64
                ),
                current_bytes: hiber,
                est_savings_bytes: hiber - reduced_target,
                confidence: SizingConfidence::Measured,
                intent: Some(OptimizerIntent::SetHiberfile {
                    mode: HiberfileMode::Reduced,
                }),
                requires_admin: true,
                requires_reboot: false,
                caveat: if f.battery_present {
                    "Hibernate disappears, including the automatic hibernate at critical battery on this laptop.".into()
                } else {
                    "Hibernate disappears; Fast Startup keeps working.".into()
                },
            });
        }
    }

    // Pagefile sized from the observed commit peak.
    let system_managed = match &f.pagefile {
        PagefileConfig::Automatic => true,
        PagefileConfig::Entries { entries } => entries.iter().any(|e| {
            e.drive.eq_ignore_ascii_case(&f.system_drive) && e.initial_mb == 0 && e.max_mb == 0
        }),
        _ => false,
    };
    if let (Some(current), true) = (f.pagefile_bytes, system_managed) {
        match recommended_pagefile_mb(f) {
            Some((initial, max)) => {
                let target = u64::from(initial) * MIB;
                if current > target + GIB {
                    out.push(SizingRecommendation {
                        id: "sizing:pagefile".into(),
                        title: format!("Pagefile: system managed → {initial}–{max} MiB"),
                        detail: format!(
                            "pagefile.sys is {:.1} GiB; commit peak since boot is {:.1} GiB with {:.1} GiB RAM.",
                            current as f64 / GIB as f64,
                            f.commit_peak_bytes.unwrap_or(0) as f64 / GIB as f64,
                            f.ram_bytes.unwrap_or(0) as f64 / GIB as f64
                        ),
                        current_bytes: current,
                        est_savings_bytes: current - target,
                        confidence: SizingConfidence::Measured,
                        intent: Some(OptimizerIntent::SetPagefile {
                            drive: f.system_drive.clone(),
                            initial_mb: initial,
                            max_mb: max,
                        }),
                        requires_admin: true,
                        requires_reboot: true,
                        caveat: "Based on the commit peak since the last boot; very large workloads may need more. Undo with --pagefile system.".into(),
                    });
                }
            }
            None if current >= 4 * GIB && f.crash_dump_mode.is_some() => {
                out.push(SizingRecommendation {
                    id: "sizing:pagefile_dump_mode".into(),
                    title: "Pagefile kept large by the crash-dump setting".into(),
                    detail: "Complete, kernel, and automatic memory dumps need a large pagefile. Switching to small memory dumps (System Properties > Startup and Recovery) lets it shrink.".into(),
                    current_bytes: current,
                    est_savings_bytes: 0,
                    confidence: SizingConfidence::Typical,
                    intent: None,
                    requires_admin: true,
                    requires_reboot: true,
                    caveat: "Small dumps carry less detail for diagnosing crashes.".into(),
                });
            }
            None => {}
        }
    }

    if f.compact_os_enabled == Some(false) {
        out.push(SizingRecommendation {
            id: "sizing:compact_os".into(),
            title: "CompactOS: compress Windows binaries".into(),
            detail: "Windows judged it not beneficial on this machine, but it typically frees 2–4 GiB on any SSD system.".into(),
            current_bytes: 0,
            est_savings_bytes: 2 * GIB,
            confidence: SizingConfidence::Typical,
            intent: Some(OptimizerIntent::SetCompactOs { enable: true }),
            requires_admin: true,
            requires_reboot: false,
            caveat: "A small CPU cost when Windows files are read; reversible.".into(),
        });
    }

    if f.reserved_storage_enabled == Some(true) {
        out.push(SizingRecommendation {
            id: "sizing:reserved_storage".into(),
            title: "Reserved Storage off".into(),
            detail: "Windows keeps about 7 GiB reserved for updates.".into(),
            current_bytes: 7 * GIB,
            est_savings_bytes: 7 * GIB,
            confidence: SizingConfidence::Typical,
            intent: Some(OptimizerIntent::SetReservedStorage { enabled: false }),
            requires_admin: true,
            requires_reboot: false,
            caveat: "Feature updates then need that much free space themselves.".into(),
        });
    }

    if let Some(used) = f.vss_used_bytes
        && f.volume_total_bytes > 0
    {
        let cap = f.volume_total_bytes / 20; // 5 %
        if used > cap + GIB {
            out.push(SizingRecommendation {
                id: "sizing:vss_cap".into(),
                title: "Cap System Restore storage at 5 %".into(),
                detail: format!(
                    "Shadow copies use {:.1} GiB of {:.1} GiB allowed.",
                    used as f64 / GIB as f64,
                    f.vss_max_bytes.unwrap_or(0) as f64 / GIB as f64
                ),
                current_bytes: used,
                est_savings_bytes: used - cap,
                confidence: SizingConfidence::Measured,
                intent: Some(OptimizerIntent::VssResize {
                    drive: f.system_drive.clone(),
                    max_percent: 5,
                }),
                requires_admin: true,
                requires_reboot: false,
                caveat: "The oldest restore points are deleted to fit the cap.".into(),
            });
        }
    }

    out.sort_by_key(|a| std::cmp::Reverse(a.est_savings_bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laptop_facts() -> SizingFacts {
        SizingFacts {
            system_drive: "C:".into(),
            volume_total_bytes: 952 * GIB,
            ram_bytes: Some(32 * GIB),
            commit_peak_bytes: Some(20 * GIB),
            commit_limit_bytes: Some(42 * GIB),
            pagefile: PagefileConfig::Automatic,
            pagefile_bytes: Some(10 * GIB),
            crash_dump_mode: Some(3),
            hiber_file_type: Some(2),
            hibernate_enabled: Some(true),
            hiberfil_bytes: Some(12_690 * MIB),
            battery_present: true,
            compact_os_enabled: Some(false),
            reserved_storage_enabled: None,
            vss_used_bytes: None,
            vss_max_bytes: None,
        }
    }

    #[test]
    fn parses_paging_files_forms() {
        assert_eq!(
            parse_paging_files(&[r"?:\pagefile.sys".into()]),
            PagefileConfig::Automatic
        );
        assert_eq!(parse_paging_files(&[]), PagefileConfig::Disabled);
        assert_eq!(
            parse_paging_files(&[
                r"c:\pagefile.sys 4096 8192".into(),
                r"D:\pagefile.sys".into()
            ]),
            PagefileConfig::Entries {
                entries: vec![
                    PagefileEntry {
                        drive: "C:".into(),
                        initial_mb: 4096,
                        max_mb: 8192
                    },
                    PagefileEntry {
                        drive: "D:".into(),
                        initial_mb: 0,
                        max_mb: 0
                    },
                ]
            }
        );
        assert_eq!(
            parse_paging_files(&["garbage".into()]),
            PagefileConfig::Unknown
        );
    }

    #[test]
    fn laptop_profile_gets_reduced_hiberfile_and_smaller_pagefile() {
        let recs = advise_sizing(&laptop_facts());
        let ids: Vec<&str> = recs.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"sizing:hiberfile_reduced"), "{ids:?}");
        assert!(ids.contains(&"sizing:pagefile"), "{ids:?}");
        assert!(ids.contains(&"sizing:compact_os"), "{ids:?}");

        let hib = recs
            .iter()
            .find(|r| r.id == "sizing:hiberfile_reduced")
            .unwrap();
        // 12.4 GiB file vs 6.4 GiB reduced target.
        assert!((5 * GIB..7 * GIB).contains(&hib.est_savings_bytes));
        assert!(hib.caveat.contains("laptop"));

        let pf = recs.iter().find(|r| r.id == "sizing:pagefile").unwrap();
        assert_eq!(
            pf.intent,
            Some(OptimizerIntent::SetPagefile {
                drive: "C:".into(),
                initial_mb: 4096,
                max_mb: 8192
            })
        );
        assert_eq!(pf.est_savings_bytes, 6 * GIB);
        assert!(pf.requires_reboot);
    }

    #[test]
    fn pagefile_sizing_follows_commit_peak_and_dump_mode() {
        let mut f = laptop_facts();
        // Peak 40 GiB with 32 GiB RAM: 1.5 × 40 − 32 = 28 GiB → 28672 MiB.
        f.commit_peak_bytes = Some(40 * GIB);
        assert_eq!(recommended_pagefile_mb(&f), Some((28_672, 57_344)));
        // Kernel/automatic/complete dumps need a big pagefile: advise switching instead.
        f.crash_dump_mode = Some(7);
        assert_eq!(recommended_pagefile_mb(&f), None);
        let recs = advise_sizing(&f);
        assert!(
            recs.iter()
                .any(|r| r.id == "sizing:pagefile_dump_mode" && r.intent.is_none())
        );
        // Unknown memory facts: no recommendation.
        f.crash_dump_mode = Some(3);
        f.ram_bytes = None;
        assert_eq!(recommended_pagefile_mb(&f), None);
    }

    #[test]
    fn already_reduced_hiberfile_is_left_alone() {
        let mut f = laptop_facts();
        f.hiber_file_type = Some(1);
        f.hiberfil_bytes = Some(6 * GIB);
        assert!(
            !advise_sizing(&f)
                .iter()
                .any(|r| r.id == "sizing:hiberfile_reduced")
        );
    }

    #[test]
    fn paging_files_value_is_built_from_validated_scalars() {
        assert_eq!(
            paging_files_value(&OptimizerIntent::SetPagefile {
                drive: "c:".into(),
                initial_mb: 4096,
                max_mb: 8192
            })
            .unwrap(),
            vec![r"C:\pagefile.sys 4096 8192".to_string()]
        );
        assert_eq!(
            paging_files_value(&OptimizerIntent::SetPagefileAutomatic).unwrap(),
            vec![r"?:\pagefile.sys".to_string()]
        );
        assert!(
            paging_files_value(&OptimizerIntent::SetPagefile {
                drive: r"C:\x".into(),
                initial_mb: 4096,
                max_mb: 8192
            })
            .is_err()
        );
        assert!(
            paging_files_value(&OptimizerIntent::SetPagefile {
                drive: "C:".into(),
                initial_mb: 512,
                max_mb: 8192
            })
            .is_err()
        );
        assert!(paging_files_value(&OptimizerIntent::SetCompactOs { enable: true }).is_err());
    }
}
