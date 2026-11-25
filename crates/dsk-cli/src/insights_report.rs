#![forbid(unsafe_code)]

//! Human-readable formatters for `disksaver dupes` and `disksaver insights`.

use dsk_core::insights::{
    AiModelsReport, ColdDataReport, DupeRemediationOutcome, DupeReport, DuplicateGroup,
    FullInsightsReport, GamingLibraryReport, OrphanScanReport, ProjectScanReport,
};
use serde::Serialize;

/// A duplicate group whose remediation failed as a whole (for example the keeper changed after
/// the scan). Recorded instead of aborting the run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DupeGroupFailure {
    pub blake3_hex: String,
    pub error: String,
}

/// Result of remediating every group of a duplicate report.
#[derive(Debug, Default)]
pub struct DupeBatchOutcome {
    pub remediations: Vec<DupeRemediationOutcome>,
    pub failures: Vec<DupeGroupFailure>,
    pub cancelled: bool,
}

impl DupeBatchOutcome {
    /// Process exit code: 130 when cancelled, 1 when any group failed, otherwise 0.
    pub fn exit_code(&self) -> i32 {
        if self.cancelled {
            130
        } else if !self.failures.is_empty() {
            1
        } else {
            0
        }
    }
}

/// Remediates each group independently: a group-level error (keeper changed since the scan,
/// deny-listed path, journal failure, …) becomes a [`DupeGroupFailure`] and the remaining groups
/// still run. Only cancellation stops the batch. Callers print the summary first and exit
/// non-zero afterwards (see [`DupeBatchOutcome::exit_code`]).
pub fn remediate_groups_continue_on_error<'a, I, F>(groups: I, mut remediate: F) -> DupeBatchOutcome
where
    I: IntoIterator<Item = &'a DuplicateGroup>,
    F: FnMut(&DuplicateGroup) -> dsk_core::Result<DupeRemediationOutcome>,
{
    let mut out = DupeBatchOutcome::default();
    for group in groups {
        match remediate(group) {
            Ok(r) => out.remediations.push(r),
            Err(dsk_core::DskError::Cancelled) => {
                out.cancelled = true;
                break;
            }
            Err(e) => out.failures.push(DupeGroupFailure {
                blake3_hex: group.blake3_hex.clone(),
                error: e.to_string(),
            }),
        }
    }
    out
}

fn fmt_bytes(b: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;
    let bf = b as f64;
    if bf >= TIB {
        format!("{:.2} TiB", bf / TIB)
    } else if bf >= GIB {
        format!("{:.2} GiB", bf / GIB)
    } else if bf >= MIB {
        format!("{:.1} MiB", bf / MIB)
    } else if bf >= KIB {
        format!("{:.1} KiB", bf / KIB)
    } else {
        format!("{b} B")
    }
}

pub fn print_dupes_human(
    report: &DupeReport,
    remediations: &[DupeRemediationOutcome],
    failures: &[DupeGroupFailure],
    keep: usize,
) {
    println!("=== Duplicate File Report ({}) ===", report.volume_root);
    println!(
        "Scanned {} unique inodes ({} hard links collapsed), {} size buckets, {} partial hashes, {} full BLAKE3 ({} cache hits, {} threads)",
        report.stats.total_candidates,
        report.stats.collapsed_hardlinks,
        report.stats.size_buckets,
        report.stats.partial_hashed,
        report.stats.full_hashed,
        report.stats.cache_hits,
        report.stats.worker_threads
    );
    println!(
        "Found {} duplicate group(s), {} reclaimable\n",
        report.groups.len(),
        fmt_bytes(report.total_wasted_bytes)
    );

    for (idx, g) in report.groups.iter().take(25).enumerate() {
        println!(
            "  [{:>2}] {} x {} copies -> {} reclaimable ({})",
            idx + 1,
            fmt_bytes(g.file_size),
            g.files.len(),
            fmt_bytes(g.reclaimable_bytes),
            g.blake3_hex.get(..12).unwrap_or(&g.blake3_hex)
        );
        let keep_idx = keep.min(g.files.len().saturating_sub(1));
        for (fidx, f) in g.files.iter().enumerate() {
            let tag = if fidx == keep_idx { "KEEP" } else { "DUP " };
            println!("       [{tag}] {}", f.path.display());
        }
    }

    if !remediations.is_empty() {
        let total_proc: usize = remediations.iter().map(|r| r.processed).sum();
        let total_skip: usize = remediations.iter().map(|r| r.skipped).sum();
        let total_saved: u64 = remediations.iter().map(|r| r.reclaimed_bytes).sum();
        let dry = remediations.first().is_some_and(|r| r.dry_run);
        println!(
            "\nRemediation ({}): processed {}, skipped {}, reclaimed {}",
            if dry { "DRY RUN" } else { "LIVE" },
            total_proc,
            total_skip,
            fmt_bytes(total_saved)
        );
        for r in remediations {
            for n in &r.notes {
                println!("    note: {n}");
            }
        }
    }

    if !failures.is_empty() {
        eprintln!(
            "\n{} duplicate group(s) failed and were left unchanged:",
            failures.len()
        );
        for f in failures {
            eprintln!(
                "  - {}: {}",
                f.blake3_hex.get(..12).unwrap_or(&f.blake3_hex),
                f.error
            );
        }
    }
}

pub fn print_projects_human(report: &ProjectScanReport) {
    println!(
        "--- Project Build Artifacts ({}) ---",
        report.artifacts.len()
    );
    println!(
        "  Total allocated: {}, hard-link-aware reclaimable: {}",
        fmt_bytes(report.total_allocated_bytes),
        fmt_bytes(report.total_reclaimable_bytes)
    );
    for a in report.artifacts.iter().take(25) {
        println!(
            "  [{:<16}] {:>10}  {} (marker: {})",
            a.ecosystem.display_name(),
            fmt_bytes(a.reclaimable_bytes),
            a.artifact_path.display(),
            a.marker_evidence
        );
    }
}

pub fn print_ai_models_human(report: &AiModelsReport) {
    println!(
        "--- AI Model Weights & Caches ({}) ---",
        report.models.len()
    );
    println!(
        "  Total allocated: {}",
        fmt_bytes(report.total_allocated_bytes)
    );
    for m in report.models.iter().take(25) {
        println!(
            "  [{:<24}] {:>10}  {} ({})",
            m.kind.display_name(),
            fmt_bytes(m.allocated_bytes),
            m.model_name,
            m.path.display()
        );
    }
}

pub fn print_gaming_human(report: &GamingLibraryReport) {
    println!("--- Gaming Libraries ({} games) ---", report.games.len());
    println!(
        "  Total allocated: {}",
        fmt_bytes(report.total_allocated_bytes)
    );
    for g in report.games.iter().take(25) {
        println!(
            "  [{:<18}] {:>10}  {} ({})",
            g.store.display_name(),
            fmt_bytes(g.allocated_bytes),
            g.title,
            g.install_path.display()
        );
    }
}

pub fn print_orphans_human(report: &OrphanScanReport) {
    println!(
        "--- Suspected Orphaned App Data ({}) ---",
        report.candidates.len()
    );
    println!(
        "  Total reclaimable (Recycle-only): {}",
        fmt_bytes(report.total_allocated_bytes)
    );
    for c in report.candidates.iter().take(25) {
        println!(
            "  [{:<15} {:>2}%] {:>10}  {} ({})",
            c.scope.display_name(),
            c.confidence,
            fmt_bytes(c.allocated_bytes),
            c.path.display(),
            c.days_since_touch
        );
    }
}

pub fn print_cold_human(report: &ColdDataReport) {
    println!(
        "--- Cold Files ({}) & Dormant Apps ({}) ---",
        report.cold_files.len(),
        report.cold_apps.len()
    );
    if let Some(ref note) = report.advisory_note {
        println!("  Note: {note}");
    }
    println!(
        "  Cold files total: {}, dormant apps total: {}",
        fmt_bytes(report.total_cold_file_bytes),
        fmt_bytes(report.total_cold_app_bytes)
    );
    for f in report.cold_files.iter().take(15) {
        println!(
            "  [File score {:>3} | {:>3}d] {:>10}  {}",
            f.cold_score,
            f.days_cold,
            fmt_bytes(f.allocated_bytes),
            f.path.display()
        );
    }
    for a in report.cold_apps.iter().take(15) {
        println!(
            "  [App  score {:>3}] {:>10}  {} ({})",
            a.cold_score,
            fmt_bytes(a.allocated_bytes),
            a.app_name,
            a.telemetry_note
        );
    }
}

pub fn print_all_insights_human(report: &FullInsightsReport) {
    println!("=== Storage Insights ({}) ===", report.volume_root);
    println!(
        "Estimated reclaimable across projects/models/orphans: {}\n",
        fmt_bytes(report.total_reclaimable_estimate)
    );
    print_projects_human(&report.projects);
    println!();
    print_ai_models_human(&report.ai_models);
    println!();
    print_gaming_human(&report.gaming);
    println!();
    print_orphans_human(&report.orphans);
    println!();
    print_cold_human(&report.cold);
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsk_core::insights::{DupFileEntry, DupeRemediationAction};
    use std::path::PathBuf;

    fn group(hex: &str) -> DuplicateGroup {
        let entry = |n: u32| DupFileEntry {
            node_id: n,
            path: PathBuf::from(format!(r"C:\dup\{hex}_{n}.bin")),
            file_id: u64::from(n),
            logical_bytes: 4096,
            allocated_bytes: 4096,
            mtime_min: 1,
            atime_min: 1,
            hardlinked: false,
        };
        DuplicateGroup {
            blake3_hex: hex.repeat(16),
            file_size: 4096,
            files: vec![entry(1), entry(2)],
            reclaimable_bytes: 4096,
        }
    }

    fn ok_outcome() -> DupeRemediationOutcome {
        DupeRemediationOutcome {
            dry_run: false,
            action: DupeRemediationAction::RecycleDuplicates,
            processed: 1,
            skipped: 0,
            reclaimed_bytes: 4096,
            notes: Vec::new(),
        }
    }

    #[test]
    fn group_level_failure_is_recorded_and_remaining_groups_still_run() {
        let groups = vec![group("aaaa"), group("bbbb"), group("cccc")];
        let mut seen = Vec::new();
        let out = remediate_groups_continue_on_error(&groups, |g| {
            seen.push(g.blake3_hex.clone());
            if g.blake3_hex.starts_with("bbbb") {
                Err(dsk_core::DskError::Optimize(
                    "keeper changed since scan".to_string(),
                ))
            } else {
                Ok(ok_outcome())
            }
        });
        assert_eq!(seen.len(), 3, "a failing group must not abort the batch");
        assert_eq!(out.remediations.len(), 2);
        assert_eq!(out.failures.len(), 1);
        assert!(out.failures[0].error.contains("keeper changed"));
        assert!(!out.cancelled);
        assert_eq!(out.exit_code(), 1);
    }

    #[test]
    fn cancellation_stops_the_batch_with_exit_130() {
        let groups = vec![group("aaaa"), group("bbbb"), group("cccc")];
        let mut calls = 0;
        let out = remediate_groups_continue_on_error(&groups, |_| {
            calls += 1;
            if calls == 2 {
                Err(dsk_core::DskError::Cancelled)
            } else {
                Ok(ok_outcome())
            }
        });
        assert_eq!(calls, 2);
        assert!(out.cancelled);
        assert_eq!(out.exit_code(), 130);
        let clean = remediate_groups_continue_on_error(&groups[..1], |_| Ok(ok_outcome()));
        assert_eq!(clean.exit_code(), 0);
    }
}
