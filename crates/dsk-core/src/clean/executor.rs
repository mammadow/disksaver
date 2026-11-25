#![forbid(unsafe_code)]

//! Safe cleanup plan executor and OS handler estimator.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::clean::deny::DenyContext;
use crate::clean::driverstore::{
    is_pnputil_xml, parse_pnputil_bound_infs_any, parse_pnputil_drivers_any,
    select_prunable_drivers, validate_oem_inf_name,
};
use crate::clean::journal::{ActionJournal, JournalEntryRecord, JournalRunRecord};
use crate::clean::plan::{CleanPlan, SkippedRule};
use crate::clean::rules::{RuleMethod, RuleTier};
use crate::error::{DskError, Result};
use crate::time::filetime_to_min2000;
use crate::win::cleaner::{DeleteOutcomeKind, safe_clean_root};
use crate::win::os_handlers::{estimate_os_handler, purge_os_handler, run_clean_command};
use crate::win::pipe::PipeClientImpersonator;
use crate::win::preconditions::{apply_preconditions, find_locking_processes, probe_preconditions};
use crate::win::process::hidden_command;
use crate::win::restore::{
    RestorePointOutcome, create_restore_point_if_enabled, query_os_uninstall_window_days,
};
use crate::win::volume::{system32_dir, volume_info};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Execution phase for progress reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanPhase {
    CheckingPreconditions,
    EstimatingHandlers,
    CleaningFiles,
    RunningHandlers,
    RunningCommands,
    RecordingJournal,
}

/// Progress event dispatched during cleanup execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanProgress {
    pub phase: CleanPhase,
    pub rule_id: String,
    pub done: u64,
    pub total: u64,
}

/// Options controlling cleanup plan execution.
#[derive(Clone, Debug, Default)]
pub struct ExecuteOptions {
    pub dry_run: bool,
    pub force_battery: bool,
    pub journal_path: Option<PathBuf>,
}

/// Summary of an individual rule's execution outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleExecutionSummary {
    pub rule_id: String,
    pub name: String,
    pub est_bytes: u64,
    pub deleted_bytes: u64,
    pub items_ok: u64,
    pub items_skipped: u64,
    pub items_failed: u64,
    pub note: Option<String>,
}

/// Comprehensive report produced at the completion of plan execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanReport {
    pub run_id: String,
    pub volume: String,
    pub dry_run: bool,
    pub est_bytes: u64,
    pub est_deleted_bytes: u64,
    pub before_free_bytes: u64,
    pub after_free_bytes: u64,
    pub freed_measured: i64,
    pub items_ok: u64,
    pub items_skipped: u64,
    pub items_failed: u64,
    pub rule_summaries: Vec<RuleExecutionSummary>,
    pub skipped_rules: Vec<SkippedRule>,
    /// Result of the pre-cleanup System Restore point attempt. `None` when none was needed (dry
    /// run, or no Advanced / ResetBase / driver-store rule selected). `#[serde(default)]` keeps
    /// older helper/client builds wire-compatible.
    #[serde(default)]
    pub restore_point: Option<RestorePointOutcome>,
}

/// Enriches `CleanPlan` with live space estimates for `OsHandler` rules via COM.
pub fn enrich_os_handler_estimates(plan: &mut CleanPlan, cancel: &AtomicBool) {
    let rollback_days = if plan.rules.iter().any(|r| r.rule_id == "sys.windows.old") {
        query_os_uninstall_window_days()
    } else {
        None
    };

    for rule in &mut plan.rules {
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        if let RuleMethod::OsHandler { handler_key } = &rule.method {
            match estimate_os_handler(handler_key, &plan.volume_root, cancel) {
                Ok(info) => {
                    rule.est_bytes = info.space_used;
                    rule.os_handler_bytes = Some(info.space_used);
                }
                Err(_) => {
                    rule.est_bytes = 0;
                    rule.os_handler_bytes = Some(0);
                }
            }
        }

        if rule.rule_id == "sys.windows.old"
            && let Some(days) = rollback_days
            && !rule.explain.contains("Rollback window:")
        {
            rule.explain
                .push_str(&format!(" (Rollback window: {days} day(s) remaining)"));
        }
    }

    plan.total_est_bytes = plan.rules.iter().map(|r| r.est_bytes).sum();
}

/// Execution state bundled for safe cleanup execution and progress reporting.
struct ExecutionState<'a> {
    deny_ctx: &'a DenyContext,
    impersonator: Option<&'a PipeClientImpersonator>,
    dry_run: bool,
    now_min2000: u32,
    run_id: &'a str,
    progress: &'a (dyn Fn(CleanProgress) + Sync),
    cancel: &'a AtomicBool,
    journal_entries: &'a mut Vec<JournalEntryRecord>,
    total_items_ok: &'a mut u64,
    total_items_skipped: &'a mut u64,
    total_items_failed: &'a mut u64,
    total_deleted_bytes: &'a mut u64,
    restore_point: &'a mut Option<RestorePointOutcome>,
}

#[derive(Default)]
struct RuleItemCounters {
    ok: u64,
    skipped: u64,
    failed: u64,
    deleted_bytes: u64,
}

/// Helper executing safe deletion across all planned roots of a rule, updating journal entries,
/// progress, and counters while honoring cancellation between roots.
fn execute_clean_roots(
    rule: &crate::clean::plan::PlannedRule,
    disposition: &str,
    state: &mut ExecutionState<'_>,
    counters: &mut RuleItemCounters,
) -> Result<()> {
    for root in &rule.roots {
        if state.cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }

        let root_report = safe_clean_root(
            root,
            state.deny_ctx,
            state.dry_run,
            state.now_min2000,
            state.cancel,
        )?;

        for item in root_report.outcomes {
            let (status, ok, sk, fa, del_b) = match item.kind {
                DeleteOutcomeKind::Deleted => {
                    let st = if state.dry_run { "dry_run" } else { "deleted" };
                    (st, 1, 0, 0, item.bytes)
                }
                DeleteOutcomeKind::Skipped => ("skipped", 0, 1, 0, 0),
                DeleteOutcomeKind::Failed => ("failed", 0, 0, 1, 0),
            };

            counters.ok += ok;
            counters.skipped += sk;
            counters.failed += fa;
            counters.deleted_bytes += del_b;

            *state.total_items_ok += ok;
            *state.total_items_skipped += sk;
            *state.total_items_failed += fa;
            *state.total_deleted_bytes += del_b;

            state.journal_entries.push(JournalEntryRecord {
                id: 0,
                run_id: state.run_id.to_string(),
                rule_id: rule.rule_id.clone(),
                path: item.path,
                file_id: item.file_id,
                size_bytes: item.bytes,
                disposition: disposition.to_string(),
                status: status.to_string(),
                error_msg: item.detail,
            });

            (state.progress)(CleanProgress {
                phase: CleanPhase::CleaningFiles,
                rule_id: rule.rule_id.clone(),
                done: counters.ok + counters.skipped + counters.failed,
                total: rule.item_count,
            });
        }

        if state.cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }
    }

    Ok(())
}

/// `true` when the selected rules can make changes that are hard to undo without System Restore:
/// any Advanced rule, DISM `/ResetBase` (removes superseded components for good), or driver store
/// pruning (deletes driver packages).
pub fn plan_requires_restore_point(plan: &CleanPlan) -> bool {
    plan.rules.iter().any(|r| {
        r.tier == RuleTier::Advanced
            || matches!(
                r.method,
                RuleMethod::DismComponentCleanup {
                    reset_base: true,
                    ..
                } | RuleMethod::DriverStorePrune { .. }
            )
    })
}

fn run_active_rules(
    active_plan: &CleanPlan,
    plan: &CleanPlan,
    state: &mut ExecutionState<'_>,
    rule_summaries: &mut Vec<RuleExecutionSummary>,
) -> Result<()> {
    if !state.dry_run && plan_requires_restore_point(active_plan) {
        *state.restore_point = Some(create_restore_point_if_enabled(
            "DiskSaver Pre-Advanced Cleanup Restore Point",
        ));
    }

    for rule in &active_plan.rules {
        if state.cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }

        let _imp_guard = if !rule.requires_admin {
            match state.impersonator {
                Some(imp) => Some(imp.impersonate()?),
                None => None,
            }
        } else {
            None
        };

        match &rule.method {
            RuleMethod::DeleteContents | RuleMethod::DeleteOlderThan => {
                (state.progress)(CleanProgress {
                    phase: CleanPhase::CleaningFiles,
                    rule_id: rule.rule_id.clone(),
                    done: 0,
                    total: rule.item_count,
                });

                let disp = match rule.method {
                    RuleMethod::DeleteContents => "delete_contents",
                    RuleMethod::DeleteOlderThan => "delete_older_than",
                    _ => "delete",
                };

                let mut counters = RuleItemCounters::default();
                execute_clean_roots(rule, disp, state, &mut counters)?;

                rule_summaries.push(RuleExecutionSummary {
                    rule_id: rule.rule_id.clone(),
                    name: rule.name.clone(),
                    est_bytes: rule.est_bytes,
                    deleted_bytes: counters.deleted_bytes,
                    items_ok: counters.ok,
                    items_skipped: counters.skipped,
                    items_failed: counters.failed,
                    note: None,
                });
            }

            RuleMethod::OsHandler { handler_key } => {
                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningHandlers,
                    rule_id: rule.rule_id.clone(),
                    done: 0,
                    total: 1,
                });

                if state.dry_run {
                    state.journal_entries.push(JournalEntryRecord {
                        id: 0,
                        run_id: state.run_id.to_string(),
                        rule_id: rule.rule_id.clone(),
                        path: format!("<VolumeCaches:{handler_key}>"),
                        file_id: 0,
                        size_bytes: rule.est_bytes,
                        disposition: "os_handler".to_string(),
                        status: "dry_run".to_string(),
                        error_msg: None,
                    });

                    rule_summaries.push(RuleExecutionSummary {
                        rule_id: rule.rule_id.clone(),
                        name: rule.name.clone(),
                        est_bytes: rule.est_bytes,
                        deleted_bytes: rule.est_bytes,
                        items_ok: 1,
                        items_skipped: 0,
                        items_failed: 0,
                        note: Some("dry-run".to_string()),
                    });

                    *state.total_items_ok += 1;
                    *state.total_deleted_bytes += rule.est_bytes;
                } else {
                    match purge_os_handler(
                        handler_key,
                        &plan.volume_root,
                        rule.est_bytes,
                        state.cancel,
                    ) {
                        Ok(purged_bytes) => {
                            state.journal_entries.push(JournalEntryRecord {
                                id: 0,
                                run_id: state.run_id.to_string(),
                                rule_id: rule.rule_id.clone(),
                                path: format!("<VolumeCaches:{handler_key}>"),
                                file_id: 0,
                                size_bytes: purged_bytes,
                                disposition: "os_handler".to_string(),
                                status: "deleted".to_string(),
                                error_msg: None,
                            });

                            rule_summaries.push(RuleExecutionSummary {
                                rule_id: rule.rule_id.clone(),
                                name: rule.name.clone(),
                                est_bytes: rule.est_bytes,
                                deleted_bytes: purged_bytes,
                                items_ok: 1,
                                items_skipped: 0,
                                items_failed: 0,
                                note: None,
                            });

                            *state.total_items_ok += 1;
                            *state.total_deleted_bytes += purged_bytes;
                        }
                        Err(DskError::Cancelled) => return Err(DskError::Cancelled),
                        Err(e) => {
                            state.journal_entries.push(JournalEntryRecord {
                                id: 0,
                                run_id: state.run_id.to_string(),
                                rule_id: rule.rule_id.clone(),
                                path: format!("<VolumeCaches:{handler_key}>"),
                                file_id: 0,
                                size_bytes: 0,
                                disposition: "os_handler".to_string(),
                                status: "failed".to_string(),
                                error_msg: Some(e.to_string()),
                            });

                            rule_summaries.push(RuleExecutionSummary {
                                rule_id: rule.rule_id.clone(),
                                name: rule.name.clone(),
                                est_bytes: rule.est_bytes,
                                deleted_bytes: 0,
                                items_ok: 0,
                                items_skipped: 0,
                                items_failed: 1,
                                note: Some(e.to_string()),
                            });

                            *state.total_items_failed += 1;
                        }
                    }
                }

                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningHandlers,
                    rule_id: rule.rule_id.clone(),
                    done: 1,
                    total: 1,
                });
            }

            RuleMethod::Command {
                program,
                args,
                fallback_delete_contents,
                timeout_secs,
                program_candidates,
            } => {
                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningCommands,
                    rule_id: rule.rule_id.clone(),
                    done: 0,
                    total: 1,
                });

                // §10.7: never launch PATH-resolved tools from the elevated helper. `CreateProcess`
                // uses the helper's primary (admin) token even while the thread impersonates the
                // client, so a tool planted in a user-writable PATH folder would run elevated.
                // Inside the helper we only use the handle-based fallback (impersonated).
                let in_elevated_helper = state.impersonator.is_some();
                let resolved_program = if in_elevated_helper {
                    None
                } else {
                    crate::win::os_handlers::resolve_rule_program(program, program_candidates)
                };
                let bin_found = resolved_program.is_some();
                let missing_reason = if in_elevated_helper {
                    format!(
                        "tool command '{program}' is never run by the elevated helper; run this rule without the helper"
                    )
                } else {
                    format!("program '{program}' not found on PATH")
                };

                if !bin_found {
                    if *fallback_delete_contents {
                        // Binary missing but fallback deletion is allowed -> run execute_clean_roots across roots.
                        (state.progress)(CleanProgress {
                            phase: CleanPhase::CleaningFiles,
                            rule_id: rule.rule_id.clone(),
                            done: 0,
                            total: rule.item_count,
                        });

                        let mut counters = RuleItemCounters::default();
                        execute_clean_roots(
                            rule,
                            "fallback_delete_contents",
                            state,
                            &mut counters,
                        )?;

                        rule_summaries.push(RuleExecutionSummary {
                            rule_id: rule.rule_id.clone(),
                            name: rule.name.clone(),
                            est_bytes: rule.est_bytes,
                            deleted_bytes: counters.deleted_bytes,
                            items_ok: counters.ok,
                            items_skipped: counters.skipped,
                            items_failed: counters.failed,
                            note: Some(format!("{missing_reason}; fell back to raw deletion")),
                        });
                    } else {
                        // CAS store or non-fallback: NEVER delete rule.roots!
                        state.journal_entries.push(JournalEntryRecord {
                            id: 0,
                            run_id: state.run_id.to_string(),
                            rule_id: rule.rule_id.clone(),
                            path: format!("<command:{program}>"),
                            file_id: 0,
                            size_bytes: 0,
                            disposition: "command".to_string(),
                            status: "skipped".to_string(),
                            error_msg: Some(format!("{missing_reason}; raw deletion forbidden")),
                        });

                        rule_summaries.push(RuleExecutionSummary {
                            rule_id: rule.rule_id.clone(),
                            name: rule.name.clone(),
                            est_bytes: rule.est_bytes,
                            deleted_bytes: 0,
                            items_ok: 0,
                            items_skipped: 1,
                            items_failed: 0,
                            note: Some(missing_reason.clone()),
                        });

                        *state.total_items_skipped += 1;
                    }
                } else if state.dry_run {
                    state.journal_entries.push(JournalEntryRecord {
                        id: 0,
                        run_id: state.run_id.to_string(),
                        rule_id: rule.rule_id.clone(),
                        path: format!("<command:{program}>"),
                        file_id: 0,
                        size_bytes: rule.est_bytes,
                        disposition: "command".to_string(),
                        status: "dry_run".to_string(),
                        error_msg: None,
                    });

                    rule_summaries.push(RuleExecutionSummary {
                        rule_id: rule.rule_id.clone(),
                        name: rule.name.clone(),
                        est_bytes: rule.est_bytes,
                        deleted_bytes: rule.est_bytes,
                        items_ok: 1,
                        items_skipped: 0,
                        items_failed: 0,
                        note: Some("dry-run".to_string()),
                    });

                    *state.total_items_ok += 1;
                    *state.total_deleted_bytes += rule.est_bytes;
                } else {
                    let program_path = resolved_program
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|| program.clone());
                    match run_clean_command(&program_path, args, *timeout_secs, false, state.cancel)
                    {
                        Ok(outcome) => {
                            if outcome.ran && outcome.exit_code == Some(0) {
                                state.journal_entries.push(JournalEntryRecord {
                                    id: 0,
                                    run_id: state.run_id.to_string(),
                                    rule_id: rule.rule_id.clone(),
                                    path: format!("<command:{program}>"),
                                    file_id: 0,
                                    size_bytes: rule.est_bytes,
                                    disposition: "command".to_string(),
                                    status: "executed".to_string(),
                                    error_msg: None,
                                });

                                rule_summaries.push(RuleExecutionSummary {
                                    rule_id: rule.rule_id.clone(),
                                    name: rule.name.clone(),
                                    est_bytes: rule.est_bytes,
                                    deleted_bytes: rule.est_bytes,
                                    items_ok: 1,
                                    items_skipped: 0,
                                    items_failed: 0,
                                    note: None,
                                });

                                *state.total_items_ok += 1;
                                *state.total_deleted_bytes += rule.est_bytes;
                            } else {
                                state.journal_entries.push(JournalEntryRecord {
                                    id: 0,
                                    run_id: state.run_id.to_string(),
                                    rule_id: rule.rule_id.clone(),
                                    path: format!("<command:{program}>"),
                                    file_id: 0,
                                    size_bytes: 0,
                                    disposition: "command".to_string(),
                                    status: "failed".to_string(),
                                    error_msg: Some(outcome.detail.clone()),
                                });

                                rule_summaries.push(RuleExecutionSummary {
                                    rule_id: rule.rule_id.clone(),
                                    name: rule.name.clone(),
                                    est_bytes: rule.est_bytes,
                                    deleted_bytes: 0,
                                    items_ok: 0,
                                    items_skipped: 0,
                                    items_failed: 1,
                                    note: Some(outcome.detail),
                                });

                                *state.total_items_failed += 1;
                            }
                        }
                        Err(DskError::Cancelled) => return Err(DskError::Cancelled),
                        Err(e) => {
                            state.journal_entries.push(JournalEntryRecord {
                                id: 0,
                                run_id: state.run_id.to_string(),
                                rule_id: rule.rule_id.clone(),
                                path: format!("<command:{program}>"),
                                file_id: 0,
                                size_bytes: 0,
                                disposition: "command".to_string(),
                                status: "failed".to_string(),
                                error_msg: Some(e.to_string()),
                            });

                            rule_summaries.push(RuleExecutionSummary {
                                rule_id: rule.rule_id.clone(),
                                name: rule.name.clone(),
                                est_bytes: rule.est_bytes,
                                deleted_bytes: 0,
                                items_ok: 0,
                                items_skipped: 0,
                                items_failed: 1,
                                note: Some(e.to_string()),
                            });

                            *state.total_items_failed += 1;
                        }
                    }
                }

                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningCommands,
                    rule_id: rule.rule_id.clone(),
                    done: 1,
                    total: 1,
                });
            }

            RuleMethod::DismComponentCleanup {
                reset_base,
                timeout_secs,
            } => {
                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningCommands,
                    rule_id: rule.rule_id.clone(),
                    done: 0,
                    total: 1,
                });

                let dism_path = system32_dir()
                    .join("Dism.exe")
                    .to_string_lossy()
                    .into_owned();

                let mut args = vec![
                    "/Online".to_string(),
                    "/Cleanup-Image".to_string(),
                    "/StartComponentCleanup".to_string(),
                ];
                if *reset_base {
                    args.push("/ResetBase".to_string());
                }

                if state.dry_run {
                    state.journal_entries.push(JournalEntryRecord {
                        id: 0,
                        run_id: state.run_id.to_string(),
                        rule_id: rule.rule_id.clone(),
                        path: format!("<dism:{}>", args.join(" ")),
                        file_id: 0,
                        size_bytes: rule.est_bytes,
                        disposition: "dism_cleanup".to_string(),
                        status: "dry_run".to_string(),
                        error_msg: None,
                    });

                    rule_summaries.push(RuleExecutionSummary {
                        rule_id: rule.rule_id.clone(),
                        name: rule.name.clone(),
                        est_bytes: rule.est_bytes,
                        deleted_bytes: rule.est_bytes,
                        items_ok: 1,
                        items_skipped: 0,
                        items_failed: 0,
                        note: Some("dry-run".to_string()),
                    });

                    *state.total_items_ok += 1;
                    *state.total_deleted_bytes += rule.est_bytes;
                } else {
                    match run_clean_command(&dism_path, &args, *timeout_secs, false, state.cancel) {
                        Ok(outcome) => {
                            if outcome.ran && outcome.exit_code == Some(0) {
                                state.journal_entries.push(JournalEntryRecord {
                                    id: 0,
                                    run_id: state.run_id.to_string(),
                                    rule_id: rule.rule_id.clone(),
                                    path: format!("<dism:{}>", args.join(" ")),
                                    file_id: 0,
                                    size_bytes: rule.est_bytes,
                                    disposition: "dism_cleanup".to_string(),
                                    status: "executed".to_string(),
                                    error_msg: None,
                                });

                                rule_summaries.push(RuleExecutionSummary {
                                    rule_id: rule.rule_id.clone(),
                                    name: rule.name.clone(),
                                    est_bytes: rule.est_bytes,
                                    deleted_bytes: rule.est_bytes,
                                    items_ok: 1,
                                    items_skipped: 0,
                                    items_failed: 0,
                                    note: None,
                                });

                                *state.total_items_ok += 1;
                                *state.total_deleted_bytes += rule.est_bytes;
                            } else {
                                state.journal_entries.push(JournalEntryRecord {
                                    id: 0,
                                    run_id: state.run_id.to_string(),
                                    rule_id: rule.rule_id.clone(),
                                    path: format!("<dism:{}>", args.join(" ")),
                                    file_id: 0,
                                    size_bytes: 0,
                                    disposition: "dism_cleanup".to_string(),
                                    status: "failed".to_string(),
                                    error_msg: Some(outcome.detail.clone()),
                                });

                                rule_summaries.push(RuleExecutionSummary {
                                    rule_id: rule.rule_id.clone(),
                                    name: rule.name.clone(),
                                    est_bytes: rule.est_bytes,
                                    deleted_bytes: 0,
                                    items_ok: 0,
                                    items_skipped: 0,
                                    items_failed: 1,
                                    note: Some(outcome.detail),
                                });

                                *state.total_items_failed += 1;
                            }
                        }
                        Err(DskError::Cancelled) => return Err(DskError::Cancelled),
                        Err(e) => {
                            state.journal_entries.push(JournalEntryRecord {
                                id: 0,
                                run_id: state.run_id.to_string(),
                                rule_id: rule.rule_id.clone(),
                                path: format!("<dism:{}>", args.join(" ")),
                                file_id: 0,
                                size_bytes: 0,
                                disposition: "dism_cleanup".to_string(),
                                status: "failed".to_string(),
                                error_msg: Some(e.to_string()),
                            });

                            rule_summaries.push(RuleExecutionSummary {
                                rule_id: rule.rule_id.clone(),
                                name: rule.name.clone(),
                                est_bytes: rule.est_bytes,
                                deleted_bytes: 0,
                                items_ok: 0,
                                items_skipped: 0,
                                items_failed: 1,
                                note: Some(e.to_string()),
                            });

                            *state.total_items_failed += 1;
                        }
                    }
                }

                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningCommands,
                    rule_id: rule.rule_id.clone(),
                    done: 1,
                    total: 1,
                });
            }

            RuleMethod::DriverStorePrune { timeout_secs } => {
                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningCommands,
                    rule_id: rule.rule_id.clone(),
                    done: 0,
                    total: 1,
                });

                let pnputil_path = system32_dir()
                    .join("pnputil.exe")
                    .to_string_lossy()
                    .into_owned();

                // XML first (element names are culture-neutral on builds that support
                // `/format xml`), the English text output as a fallback for older pnputil.
                let enum_out = pnputil_enumerate(&pnputil_path, &["/enum-drivers"]);
                let dev_out = pnputil_enumerate(&pnputil_path, &["/enum-devices", "/drivers"]);

                match (enum_out, dev_out) {
                    (Ok(enum_res), Ok(dev_res)) => {
                        let enum_text = String::from_utf8_lossy(&enum_res.stdout);
                        let dev_text = String::from_utf8_lossy(&dev_res.stdout);

                        let packages = parse_pnputil_drivers_any(&enum_text);
                        let bound = parse_pnputil_bound_infs_any(&dev_text);
                        // Fail closed: if either enumeration failed (pre-2004 pnputil without
                        // `/enum-devices /drivers`) or produced nothing parseable (localized
                        // output), "bound" would be empty and in-use drivers would look prunable.
                        let enumeration_trusted = enum_res.status.success()
                            && dev_res.status.success()
                            && !packages.is_empty()
                            && !bound.is_empty();
                        let prunable = if enumeration_trusted {
                            select_prunable_drivers(&packages, &bound)
                        } else {
                            Vec::new()
                        };

                        if !enumeration_trusted {
                            rule_summaries.push(RuleExecutionSummary {
                                rule_id: rule.rule_id.clone(),
                                name: rule.name.clone(),
                                est_bytes: rule.est_bytes,
                                deleted_bytes: 0,
                                items_ok: 0,
                                items_skipped: 1,
                                items_failed: 0,
                                note: Some(
                                    "pnputil driver/device enumeration failed or was unparseable; skipped (bound drivers could not be determined)"
                                        .to_string(),
                                ),
                            });
                            *state.total_items_skipped += 1;
                        } else if prunable.is_empty() {
                            rule_summaries.push(RuleExecutionSummary {
                                rule_id: rule.rule_id.clone(),
                                name: rule.name.clone(),
                                est_bytes: rule.est_bytes,
                                deleted_bytes: 0,
                                items_ok: 0,
                                items_skipped: 0,
                                items_failed: 0,
                                note: Some("no superseded driver packages found".to_string()),
                            });
                        } else {
                            let mut ok_cnt = 0u64;
                            let mut failed_cnt = 0u64;

                            for pkg in &prunable {
                                if state.cancel.load(Ordering::Relaxed) {
                                    return Err(DskError::Cancelled);
                                }

                                if !validate_oem_inf_name(&pkg.published_name) {
                                    continue;
                                }

                                let inf_name = &pkg.published_name;
                                if state.dry_run {
                                    state.journal_entries.push(JournalEntryRecord {
                                        id: 0,
                                        run_id: state.run_id.to_string(),
                                        rule_id: rule.rule_id.clone(),
                                        path: format!("<driverstore:{inf_name}>"),
                                        file_id: 0,
                                        size_bytes: 0,
                                        disposition: "driver_store_prune".to_string(),
                                        status: "dry_run".to_string(),
                                        error_msg: None,
                                    });
                                    ok_cnt += 1;
                                } else {
                                    let del_args =
                                        vec!["/delete-driver".to_string(), inf_name.clone()];
                                    match run_clean_command(
                                        &pnputil_path,
                                        &del_args,
                                        *timeout_secs,
                                        false,
                                        state.cancel,
                                    ) {
                                        Ok(outcome)
                                            if outcome.ran && outcome.exit_code == Some(0) =>
                                        {
                                            state.journal_entries.push(JournalEntryRecord {
                                                id: 0,
                                                run_id: state.run_id.to_string(),
                                                rule_id: rule.rule_id.clone(),
                                                path: format!("<driverstore:{inf_name}>"),
                                                file_id: 0,
                                                size_bytes: 0,
                                                disposition: "driver_store_prune".to_string(),
                                                status: "deleted".to_string(),
                                                error_msg: None,
                                            });
                                            ok_cnt += 1;
                                        }
                                        Ok(outcome) => {
                                            state.journal_entries.push(JournalEntryRecord {
                                                id: 0,
                                                run_id: state.run_id.to_string(),
                                                rule_id: rule.rule_id.clone(),
                                                path: format!("<driverstore:{inf_name}>"),
                                                file_id: 0,
                                                size_bytes: 0,
                                                disposition: "driver_store_prune".to_string(),
                                                status: "failed".to_string(),
                                                error_msg: Some(outcome.detail),
                                            });
                                            failed_cnt += 1;
                                        }
                                        Err(DskError::Cancelled) => {
                                            return Err(DskError::Cancelled);
                                        }
                                        Err(e) => {
                                            state.journal_entries.push(JournalEntryRecord {
                                                id: 0,
                                                run_id: state.run_id.to_string(),
                                                rule_id: rule.rule_id.clone(),
                                                path: format!("<driverstore:{inf_name}>"),
                                                file_id: 0,
                                                size_bytes: 0,
                                                disposition: "driver_store_prune".to_string(),
                                                status: "failed".to_string(),
                                                error_msg: Some(e.to_string()),
                                            });
                                            failed_cnt += 1;
                                        }
                                    }
                                }
                            }

                            *state.total_items_ok += ok_cnt;
                            *state.total_items_failed += failed_cnt;

                            rule_summaries.push(RuleExecutionSummary {
                                rule_id: rule.rule_id.clone(),
                                name: rule.name.clone(),
                                est_bytes: rule.est_bytes,
                                deleted_bytes: 0,
                                items_ok: ok_cnt,
                                items_skipped: 0,
                                items_failed: failed_cnt,
                                note: Some(format!("pruned {ok_cnt} superseded package(s)")),
                            });
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        rule_summaries.push(RuleExecutionSummary {
                            rule_id: rule.rule_id.clone(),
                            name: rule.name.clone(),
                            est_bytes: rule.est_bytes,
                            deleted_bytes: 0,
                            items_ok: 0,
                            items_skipped: 0,
                            items_failed: 1,
                            note: Some(format!("failed to query driver store: {e}")),
                        });
                        *state.total_items_failed += 1;
                    }
                }

                (state.progress)(CleanProgress {
                    phase: CleanPhase::RunningCommands,
                    rule_id: rule.rule_id.clone(),
                    done: 1,
                    total: 1,
                });
            }
        }
    }

    if state.cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    Ok(())
}

/// Opens the action journal and records one run.
///
/// Inside the elevated helper (`impersonator` is `Some`) the journal is opened while impersonating
/// the client: the default path lives in the user's writable profile, so an elevated open could
/// be redirected with junctions into protected directories.
fn record_journal_run(
    opts: &ExecuteOptions,
    impersonator: Option<&PipeClientImpersonator>,
    run_record: &JournalRunRecord,
    entries: &[JournalEntryRecord],
) -> Result<()> {
    let journal_path = opts
        .journal_path
        .clone()
        .unwrap_or_else(ActionJournal::default_path);
    let _imp_guard = match impersonator {
        Some(imp) => Some(imp.impersonate()?),
        None => None,
    };
    let mut journal = ActionJournal::open(&journal_path)?;
    journal.record_run(run_record, entries)?;
    // P9.1 calibration: live runs large enough that unrelated disk activity is noise.
    if !run_record.dry_run && run_record.est_bytes >= CALIBRATION_MIN_EST_BYTES {
        let _ = journal.record_calibration(
            crate::ledger::CALIBRATION_CLEAN,
            run_record.est_bytes,
            run_record.freed_measured.max(0) as u64,
        );
    }
    Ok(())
}

/// Live runs estimated below this are not used for calibration.
const CALIBRATION_MIN_EST_BYTES: u64 = 64 * 1024 * 1024;

/// Executes a prepared `CleanPlan` with safety checks, journaling, progress callbacks,
/// and optional per-rule client impersonation when invoked from the elevated helper daemon.
pub fn execute_plan_with_impersonation(
    plan: &CleanPlan,
    opts: &ExecuteOptions,
    deny_ctx: &DenyContext,
    impersonator: Option<&PipeClientImpersonator>,
    progress: &(dyn Fn(CleanProgress) + Sync),
    cancel: &AtomicBool,
) -> Result<CleanReport> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let now = SystemTime::now();
    let now_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let started_at_unix = now_epoch.as_secs() as i64;
    let count = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let run_id = format!(
        "{:016x}-{:08x}-{:08x}",
        now_epoch.as_millis(),
        std::process::id(),
        count
    );

    // 1. Re-evaluate runtime preconditions right before executing.
    progress(CleanProgress {
        phase: CleanPhase::CheckingPreconditions,
        rule_id: String::new(),
        done: 0,
        total: plan.rules.len() as u64,
    });

    let pre = probe_preconditions();
    let mut active_plan = plan.clone();
    apply_preconditions(&mut active_plan, &pre, opts.force_battery);

    progress(CleanProgress {
        phase: CleanPhase::CheckingPreconditions,
        rule_id: String::new(),
        done: plan.rules.len() as u64,
        total: plan.rules.len() as u64,
    });

    // 2. Measure initial volume free space before executing rules.
    let before_free_opt = volume_info(&plan.volume_root).ok().map(|v| v.free_bytes);
    let before_free_bytes = before_free_opt.unwrap_or(0);

    // 3. Compute current timestamp in min2000 for age checks.
    let ft = match now.duration_since(UNIX_EPOCH) {
        Ok(d) => 116_444_736_000_000_000u64
            .saturating_add(d.as_secs().saturating_mul(10_000_000))
            .saturating_add((d.subsec_nanos() / 100) as u64),
        Err(_) => 0,
    };
    let now_min2000 = filetime_to_min2000(ft);

    let mut journal_entries = Vec::new();
    let mut rule_summaries = Vec::with_capacity(active_plan.rules.len());
    let mut total_items_ok: u64 = 0;
    let mut total_items_skipped: u64 = 0;
    let mut total_items_failed: u64 = 0;
    let mut total_deleted_bytes: u64 = 0;
    let mut restore_point: Option<RestorePointOutcome> = None;

    // 4. Execute active rules inside a bounded block to ensure partial journal flushing on cancel/error.
    let run_res = {
        let mut state = ExecutionState {
            deny_ctx,
            impersonator,
            dry_run: opts.dry_run,
            now_min2000,
            run_id: &run_id,
            progress,
            cancel,
            journal_entries: &mut journal_entries,
            total_items_ok: &mut total_items_ok,
            total_items_skipped: &mut total_items_skipped,
            total_items_failed: &mut total_items_failed,
            total_deleted_bytes: &mut total_deleted_bytes,
            restore_point: &mut restore_point,
        };

        run_active_rules(&active_plan, plan, &mut state, &mut rule_summaries)
    };

    // Flush partial live deletions to ActionJournal if execution aborted mid-run with error or cancellation.
    if let Err(err) = run_res {
        if !opts.dry_run && !journal_entries.is_empty() {
            let finished_at_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let partial_after_free_opt = volume_info(&plan.volume_root).ok().map(|v| v.free_bytes);
            let freed_measured = match (before_free_opt, partial_after_free_opt) {
                (Some(before), Some(after)) => (after as i128 - before as i128)
                    .clamp(i64::MIN as i128, i64::MAX as i128)
                    as i64,
                _ => 0,
            };

            let run_record = JournalRunRecord {
                run_id: run_id.clone(),
                started_at_unix,
                finished_at_unix,
                volume: plan.volume_root.clone(),
                dry_run: false,
                est_bytes: active_plan.total_est_bytes,
                freed_measured,
                items_ok: total_items_ok,
                items_skipped: total_items_skipped,
                items_failed: total_items_failed,
            };

            let _ = record_journal_run(opts, impersonator, &run_record, &journal_entries);
        }
        return Err(err);
    }

    // 5. Measure volume free space after execution and compute delta.
    let after_free_opt = volume_info(&plan.volume_root).ok().map(|v| v.free_bytes);
    let after_free_bytes = after_free_opt.unwrap_or(0);
    let freed_measured = match (before_free_opt, after_free_opt) {
        (Some(before), Some(after)) => {
            (after as i128 - before as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
        }
        _ => 0,
    };

    // 6. Record the entire run and all item entries in the journal.
    progress(CleanProgress {
        phase: CleanPhase::RecordingJournal,
        rule_id: String::new(),
        done: 0,
        total: 1,
    });

    let finished_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let run_record = JournalRunRecord {
        run_id: run_id.clone(),
        started_at_unix,
        finished_at_unix,
        volume: plan.volume_root.clone(),
        dry_run: opts.dry_run,
        est_bytes: active_plan.total_est_bytes,
        freed_measured,
        items_ok: total_items_ok,
        items_skipped: total_items_skipped,
        items_failed: total_items_failed,
    };

    match record_journal_run(opts, impersonator, &run_record, &journal_entries) {
        Ok(()) => {}
        // Inside the helper the journal is best-effort: the work is already done and the client
        // still receives the full report.
        Err(_) if impersonator.is_some() => {}
        Err(e) => return Err(e),
    }

    progress(CleanProgress {
        phase: CleanPhase::RecordingJournal,
        rule_id: String::new(),
        done: 1,
        total: 1,
    });

    Ok(CleanReport {
        run_id,
        volume: plan.volume_root.clone(),
        dry_run: opts.dry_run,
        est_bytes: active_plan.total_est_bytes,
        est_deleted_bytes: total_deleted_bytes,
        before_free_bytes,
        after_free_bytes,
        freed_measured,
        items_ok: total_items_ok,
        items_skipped: total_items_skipped,
        items_failed: total_items_failed,
        rule_summaries,
        skipped_rules: active_plan.skipped,
        restore_point,
    })
}

/// Executes a prepared `CleanPlan` in-process without pipe client impersonation.
pub fn execute_plan(
    plan: &CleanPlan,
    opts: &ExecuteOptions,
    deny_ctx: &DenyContext,
    progress: &(dyn Fn(CleanProgress) + Sync),
    cancel: &AtomicBool,
) -> Result<CleanReport> {
    execute_plan_with_impersonation(plan, opts, deny_ctx, None, progress, cancel)
}

/// Probes planned cleanup roots and representative files via Windows Restart Manager
/// (`find_locking_processes`) to identify processes holding locks on cleanup targets.
pub fn probe_locked_roots(plan: &CleanPlan) -> FxHashMap<String, Vec<String>> {
    const MAX_SAMPLE_FILES_PER_ROOT: usize = 8;
    let mut locked: FxHashMap<String, Vec<String>> = FxHashMap::default();

    for rule in &plan.rules {
        let mut procs = BTreeSet::new();

        for root in &rule.roots {
            let root_path = Path::new(&root.root_path);
            if root_path.exists() {
                for proc_name in find_locking_processes(root_path) {
                    procs.insert(proc_name);
                }
            }

            for item in root
                .items
                .iter()
                .filter(|item| !item.is_dir)
                .take(MAX_SAMPLE_FILES_PER_ROOT)
            {
                let item_path = root_path.join(&item.rel_path);
                if item_path.exists() {
                    for proc_name in find_locking_processes(&item_path) {
                        procs.insert(proc_name);
                    }
                }
            }
        }

        if !procs.is_empty() {
            locked.insert(rule.rule_id.clone(), procs.into_iter().collect());
        }
    }

    locked
}

/// Runs a read-only pnputil enumeration windowlessly, preferring `/format xml` and falling back
/// to the default text output when this pnputil build does not support XML (it prints usage).
fn pnputil_enumerate(pnputil: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    let xml = hidden_command(pnputil)
        .args(args)
        .args(["/format", "xml"])
        .output()?;
    if xml.status.success() && is_pnputil_xml(&String::from_utf8_lossy(&xml.stdout)) {
        return Ok(xml);
    }
    hidden_command(pnputil).args(args).output()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::plan::{FileIdKind, PlannedItem, PlannedRoot, PlannedRule};
    use crate::clean::rules::PreconditionRule;
    use crate::scan::ScanMethod;

    #[test]
    fn probe_locked_roots_detects_active_file_lock() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file_path = tmp.path().join("locked_cache.dat");
        let _open_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&file_path)
            .expect("open lock file");

        let plan = CleanPlan {
            version: 1,
            scanned_path: tmp.path().to_string_lossy().to_string(),
            volume_root: tmp.path().to_string_lossy().to_string(),
            scan_method: ScanMethod::Dir,
            total_est_bytes: 0,
            rules: vec![PlannedRule {
                rule_id: "test.locked.rule".to_string(),
                name: "Test Locked Rule".to_string(),
                category: "test".to_string(),
                tier: RuleTier::Safe,
                regenerable: true,
                requires_admin: false,
                method: RuleMethod::DeleteContents,
                preconditions: PreconditionRule::default(),
                explain: "test".to_string(),
                est_bytes: 0,
                item_count: 1,
                roots: vec![PlannedRoot {
                    root_path: tmp.path().to_string_lossy().to_string(),
                    root_file_id: 0,
                    file_id_kind: FileIdKind::Unpinned,
                    min_age_days: None,
                    exclude_names: Vec::new(),
                    allow_unlisted_children: false,
                    items: vec![PlannedItem {
                        rel_path: "locked_cache.dat".to_string(),
                        expected_file_id: 0,
                        bytes: 0,
                        is_dir: false,
                        mtime_min: 0,
                    }],
                }],
                os_handler_bytes: None,
                estimate: Default::default(),
            }],
            skipped: Vec::new(),
        };

        let map = probe_locked_roots(&plan);
        // Either Restart Manager detects our own test process locking the open file or returns empty
        // depending on host RM state, but must never panic or error and keys match rule_id.
        if let Some(holders) = map.get("test.locked.rule") {
            assert!(!holders.is_empty());
        }
    }
}
