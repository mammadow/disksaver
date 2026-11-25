#![forbid(unsafe_code)]

use dsk_core::clean::{CleanPlan, CleanReport, JournalEntryRecord, JournalRunRecord};

use crate::report::fmt_bytes;

/// Formats a `CleanPlan` as a structured human-readable summary.
pub fn format_human_plan(plan: &CleanPlan) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Cleanup Plan for {} (Volume: {}, Method: {:?})\n",
        plan.scanned_path, plan.volume_root, plan.scan_method
    ));

    let total_items: u64 = plan.rules.iter().map(|r| r.item_count).sum();
    out.push_str(&format!(
        "Total Estimated Reclaimable: {} across {} rules ({} items)\n",
        fmt_bytes(plan.total_est_bytes),
        plan.rules.len(),
        total_items
    ));

    if !plan.rules.is_empty() {
        out.push_str("\nPlanned Rules:\n");
        for r in &plan.rules {
            let note = r
                .estimate
                .note()
                .map(|n| format!("  [{n}]"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  {:>10}  {:>6} items  [{}] {} ({}){}\n",
                fmt_bytes(r.est_bytes),
                r.item_count,
                r.category,
                r.name,
                r.rule_id,
                note
            ));
        }
    }

    if !plan.skipped.is_empty() {
        out.push_str(&format!("\nSkipped Rules ({}):\n", plan.skipped.len()));
        for s in &plan.skipped {
            out.push_str(&format!("  - {} ({}): {}\n", s.name, s.rule_id, s.reason));
        }
    }

    out
}

/// Prints a `CleanPlan` to stdout.
pub fn print_human_plan(plan: &CleanPlan) {
    print!("{}", format_human_plan(plan));
}

/// Formats a `CleanReport` as a structured human-readable summary.
pub fn format_human_clean(report: &CleanReport) -> String {
    let mut out = String::new();
    let mode = if report.dry_run {
        "DRY RUN (simulation)"
    } else {
        "LIVE"
    };
    out.push_str(&format!(
        "Cleanup Report [{}] (Run: {}, Volume: {})\n",
        mode, report.run_id, report.volume
    ));

    let freed_str = if report.freed_measured >= 0 {
        fmt_bytes(report.freed_measured as u64)
    } else {
        format!("-{}", fmt_bytes(report.freed_measured.unsigned_abs()))
    };

    out.push_str(&format!(
        "Estimated reclaimable: {}, Measured freed: {}\n",
        fmt_bytes(report.est_bytes),
        freed_str
    ));
    out.push_str(&format!(
        "Items: {} ok, {} skipped, {} failed\n",
        report.items_ok, report.items_skipped, report.items_failed
    ));
    if let Some(ref rp) = report.restore_point {
        let marker = if rp.is_warning() { "WARNING: " } else { "" };
        out.push_str(&format!("{marker}{}\n", rp.summary()));
    }

    if !report.rule_summaries.is_empty() {
        out.push_str("\nRule Summaries:\n");
        for s in &report.rule_summaries {
            let note = s
                .note
                .as_deref()
                .map(|n| format!(" - {n}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  {:>10} deleted (est {:>10})  {:>5} ok, {:>3} skip, {:>3} fail  {} ({}){}\n",
                fmt_bytes(s.deleted_bytes),
                fmt_bytes(s.est_bytes),
                s.items_ok,
                s.items_skipped,
                s.items_failed,
                s.name,
                s.rule_id,
                note
            ));
        }
    }

    if !report.skipped_rules.is_empty() {
        out.push_str(&format!(
            "\nSkipped Rules ({}):\n",
            report.skipped_rules.len()
        ));
        for s in &report.skipped_rules {
            out.push_str(&format!("  - {} ({}): {}\n", s.name, s.rule_id, s.reason));
        }
    }

    out
}

/// Prints a `CleanReport` to stdout.
pub fn print_human_clean(report: &CleanReport) {
    print!("{}", format_human_clean(report));
}

/// Formats a list of `JournalRunRecord`s as a table.
pub fn format_human_history_runs(runs: &[JournalRunRecord]) -> String {
    if runs.is_empty() {
        return "No cleanup history found.\n".to_string();
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{:<24}  {:<8}  {:<6}  {:>10}  {:>10}  {:>8}  {:>8}  {:>8}\n",
        "RUN ID", "MODE", "VOL", "ESTIMATED", "FREED", "OK", "SKIP", "FAIL"
    ));

    for r in runs {
        let mode = if r.dry_run { "dry-run" } else { "live" };
        let freed_str = if r.freed_measured >= 0 {
            fmt_bytes(r.freed_measured as u64)
        } else {
            format!("-{}", fmt_bytes(r.freed_measured.unsigned_abs()))
        };
        out.push_str(&format!(
            "{:<24}  {:<8}  {:<6}  {:>10}  {:>10}  {:>8}  {:>8}  {:>8}\n",
            r.run_id,
            mode,
            r.volume,
            fmt_bytes(r.est_bytes),
            freed_str,
            r.items_ok,
            r.items_skipped,
            r.items_failed
        ));
    }

    out
}

/// Prints a list of `JournalRunRecord`s to stdout.
pub fn print_human_history_runs(runs: &[JournalRunRecord]) {
    print!("{}", format_human_history_runs(runs));
}

/// Formats details of a specific `JournalRunRecord` and its entry list.
pub fn format_human_history_run_details(
    run: &JournalRunRecord,
    entries: &[JournalEntryRecord],
) -> String {
    let mut out = String::new();
    let mode = if run.dry_run { "dry-run" } else { "live" };
    out.push_str(&format!(
        "Run ID: {} ({}, Volume: {})\n",
        run.run_id, mode, run.volume
    ));

    let freed_str = if run.freed_measured >= 0 {
        fmt_bytes(run.freed_measured as u64)
    } else {
        format!("-{}", fmt_bytes(run.freed_measured.unsigned_abs()))
    };

    out.push_str(&format!(
        "Estimated: {}, Freed: {}, Items: {} ok, {} skipped, {} failed\n",
        fmt_bytes(run.est_bytes),
        freed_str,
        run.items_ok,
        run.items_skipped,
        run.items_failed
    ));

    if entries.is_empty() {
        out.push_str("\nNo entries recorded for this run.\n");
    } else {
        out.push_str(&format!(
            "\n{:<10}  {:<12}  {:<24}  {:>10}  {}\n",
            "STATUS", "DISP", "RULE", "SIZE", "PATH"
        ));
        for e in entries {
            let err = e
                .error_msg
                .as_deref()
                .map(|m| format!(" [error: {m}]"))
                .unwrap_or_default();
            out.push_str(&format!(
                "{:<10}  {:<12}  {:<24}  {:>10}  {}{}\n",
                e.status,
                e.disposition,
                e.rule_id,
                fmt_bytes(e.size_bytes),
                e.path,
                err
            ));
        }
    }

    out
}

/// Prints details of a specific `JournalRunRecord` to stdout.
pub fn print_human_history_run_details(run: &JournalRunRecord, entries: &[JournalEntryRecord]) {
    print!("{}", format_human_history_run_details(run, entries));
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsk_core::ScanMethod;
    use dsk_core::clean::rules::{PreconditionRule, RuleMethod};
    use dsk_core::clean::{PlannedRule, RuleExecutionSummary, RuleTier, SkippedRule};

    #[test]
    fn format_empty_plan() {
        let plan = CleanPlan {
            version: 1,
            scanned_path: r"C:\test".into(),
            volume_root: r"C:\".into(),
            scan_method: ScanMethod::Dir,
            total_est_bytes: 0,
            rules: Vec::new(),
            skipped: Vec::new(),
        };

        let formatted = format_human_plan(&plan);
        assert!(formatted.contains(r"Cleanup Plan for C:\test"));
        assert!(formatted.contains("Total Estimated Reclaimable: 0 B across 0 rules"));
    }

    #[test]
    fn format_populated_plan() {
        let plan = CleanPlan {
            version: 1,
            scanned_path: r"C:\Users\Alice".into(),
            volume_root: r"C:\".into(),
            scan_method: ScanMethod::Auto,
            total_est_bytes: 52_428_800,
            rules: vec![PlannedRule {
                rule_id: "dev.cargo.cache".into(),
                name: "Cargo Cache".into(),
                category: "dev".into(),
                tier: RuleTier::Safe,
                regenerable: true,
                requires_admin: false,
                method: RuleMethod::DeleteContents,
                preconditions: PreconditionRule::default(),
                explain: "Cargo registry cache".into(),
                est_bytes: 52_428_800,
                item_count: 42,
                roots: Vec::new(),
                os_handler_bytes: None,
                estimate: Default::default(),
            }],
            skipped: vec![SkippedRule {
                rule_id: "os.vc.update_cleanup".into(),
                name: "Update Cleanup".into(),
                reason: "requires elevation".into(),
            }],
        };

        let formatted = format_human_plan(&plan);
        assert!(formatted.contains("50.0 MiB"));
        assert!(formatted.contains("Cargo Cache (dev.cargo.cache)"));
        assert!(formatted.contains("Update Cleanup (os.vc.update_cleanup): requires elevation"));
    }

    #[test]
    fn format_clean_report_dry_run_and_live() {
        let dry_report = CleanReport {
            run_id: "run-20261111-001".into(),
            volume: r"C:\".into(),
            dry_run: true,
            est_bytes: 104_857_600,
            est_deleted_bytes: 104_857_600,
            before_free_bytes: 1_000_000_000,
            after_free_bytes: 1_000_000_000,
            freed_measured: 0,
            items_ok: 10,
            items_skipped: 1,
            items_failed: 0,
            rule_summaries: vec![RuleExecutionSummary {
                rule_id: "sys.temp.user".into(),
                name: "User Temp".into(),
                est_bytes: 104_857_600,
                deleted_bytes: 104_857_600,
                items_ok: 10,
                items_skipped: 1,
                items_failed: 0,
                note: Some("dry-run".into()),
            }],
            skipped_rules: Vec::new(),
            restore_point: None,
        };

        let dry_str = format_human_clean(&dry_report);
        assert!(dry_str.contains("DRY RUN (simulation)"));
        assert!(dry_str.contains("100.0 MiB"));
        assert!(dry_str.contains("dry-run"));

        let live_report = CleanReport {
            run_id: "run-20261111-002".into(),
            volume: r"C:\".into(),
            dry_run: false,
            est_bytes: 104_857_600,
            est_deleted_bytes: 104_857_600,
            before_free_bytes: 1_000_000_000,
            after_free_bytes: 1_104_857_600,
            freed_measured: 104_857_600,
            items_ok: 10,
            items_skipped: 0,
            items_failed: 0,
            rule_summaries: Vec::new(),
            skipped_rules: Vec::new(),
            restore_point: None,
        };

        let live_str = format_human_clean(&live_report);
        assert!(live_str.contains("LIVE"));
        assert!(live_str.contains("Measured freed: 100.0 MiB"));
        assert!(!live_str.contains("Restore"));

        let mut warned = live_report.clone();
        warned.restore_point = Some(dsk_core::RestorePointOutcome::DisabledOrUnavailable(
            "System Restore service is disabled".into(),
        ));
        let warned_str = format_human_clean(&warned);
        assert!(warned_str.contains("WARNING: No System Restore point"));
        assert!(warned_str.contains("service is disabled"));
    }

    #[test]
    fn format_history_runs_and_details() {
        let runs = vec![JournalRunRecord {
            run_id: "run-001".into(),
            started_at_unix: 1700000000,
            finished_at_unix: 1700000010,
            volume: r"C:\".into(),
            dry_run: false,
            est_bytes: 2048,
            freed_measured: 2048,
            items_ok: 2,
            items_skipped: 0,
            items_failed: 0,
        }];

        let runs_str = format_human_history_runs(&runs);
        assert!(runs_str.contains("RUN ID"));
        assert!(runs_str.contains("run-001"));
        assert!(runs_str.contains("2.0 KiB"));

        let empty_runs_str = format_human_history_runs(&[]);
        assert_eq!(empty_runs_str, "No cleanup history found.\n");

        let entries = vec![JournalEntryRecord {
            id: 1,
            run_id: "run-001".into(),
            rule_id: "sys.temp.user".into(),
            path: r"C:\temp\file.tmp".into(),
            file_id: 1234,
            size_bytes: 2048,
            disposition: "delete".into(),
            status: "deleted".into(),
            error_msg: None,
        }];

        let details_str = format_human_history_run_details(&runs[0], &entries);
        assert!(details_str.contains("Run ID: run-001"));
        assert!(details_str.contains("deleted"));
        assert!(details_str.contains(r"C:\temp\file.tmp"));
    }
}
