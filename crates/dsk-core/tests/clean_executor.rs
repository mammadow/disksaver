use std::sync::atomic::{AtomicBool, Ordering};

use dsk_core::clean::{
    ActionJournal, CleanPhase, CleanPlan, CleanProgress, DenyContext, ExecuteOptions, FileIdKind,
    PlannedItem, PlannedRoot, PlannedRule, PreconditionRule, RuleMethod, RuleTier,
};
use dsk_core::error::DskError;
use dsk_core::execute_plan;

#[test]
fn execute_plan_dry_run_then_live_clean_records_journal_and_preserves_roots() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();

    let cache_dir = base.join("cache_root");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let file1 = cache_dir.join("temp_1.dat");
    let file2 = cache_dir.join("temp_2.dat");
    std::fs::write(&file1, "1234567890").expect("write file1");
    std::fs::write(&file2, "abcdefghij").expect("write file2");

    let journal_file = base.join("journal.db");

    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![
            PlannedItem {
                rel_path: "temp_1.dat".to_string(),
                expected_file_id: 0,
                bytes: 10,
                is_dir: false,
                mtime_min: 0,
            },
            PlannedItem {
                rel_path: "temp_2.dat".to_string(),
                expected_file_id: 0,
                bytes: 10,
                is_dir: false,
                mtime_min: 0,
            },
        ],
    };

    let planned_rule = PlannedRule {
        rule_id: "test.cache.clean".to_string(),
        name: "Test Cache Clean".to_string(),
        category: "temp".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::DeleteContents,
        preconditions: PreconditionRule::default(),
        explain: "Testing safe clean".to_string(),
        est_bytes: 20,
        item_count: 2,
        roots: vec![planned_root],
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let plan = CleanPlan {
        version: 1,
        scanned_path: base.to_string_lossy().into_owned(),
        volume_root: base.to_string_lossy().into_owned(),
        scan_method: dsk_core::ScanMethod::Dir,
        total_est_bytes: 20,
        rules: vec![planned_rule],
        skipped: Vec::new(),
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);
    let noop_progress = |_| {};

    // 1. Dry run
    let dry_opts = ExecuteOptions {
        dry_run: true,
        force_battery: true,
        journal_path: Some(journal_file.clone()),
    };

    let dry_report = execute_plan(&plan, &dry_opts, &deny_ctx, &noop_progress, &cancel)
        .expect("dry run execution");

    assert!(dry_report.dry_run);
    assert_eq!(dry_report.items_ok, 2);
    assert_eq!(dry_report.items_failed, 0);
    assert_eq!(dry_report.items_skipped, 0);

    // Files MUST still exist after dry-run!
    assert!(file1.exists(), "file1 must survive dry-run");
    assert!(file2.exists(), "file2 must survive dry-run");
    assert!(cache_dir.exists(), "cache root must survive dry-run");

    // Journal must record dry_run = true
    let journal = ActionJournal::open(&journal_file).expect("open journal");
    let runs = journal.list_runs(10).expect("list runs");
    assert_eq!(runs.len(), 1);
    assert!(runs[0].dry_run);
    assert_eq!(runs[0].items_ok, 2);

    let dry_entries = journal
        .get_run_entries(&dry_report.run_id)
        .expect("get dry entries");
    assert_eq!(dry_entries.len(), 2);
    assert_eq!(dry_entries[0].status, "dry_run");
    assert_eq!(dry_entries[1].status, "dry_run");

    // 2. Live clean
    let live_opts = ExecuteOptions {
        dry_run: false,
        force_battery: true,
        journal_path: Some(journal_file.clone()),
    };

    let live_report = execute_plan(&plan, &live_opts, &deny_ctx, &noop_progress, &cancel)
        .expect("live execution");

    assert!(!live_report.dry_run);
    assert_eq!(live_report.items_ok, 2);
    assert_eq!(live_report.items_failed, 0);
    assert_eq!(live_report.items_skipped, 0);

    // Files MUST be deleted!
    assert!(!file1.exists(), "file1 must be deleted by live clean");
    assert!(!file2.exists(), "file2 must be deleted by live clean");

    // Cache root directory MUST be preserved!
    assert!(
        cache_dir.exists(),
        "cache root directory must be preserved after delete_contents"
    );

    // Verify journal has both runs and live entries marked as deleted
    let journal_after = ActionJournal::open(&journal_file).expect("open journal after live");
    let runs_after = journal_after.list_runs(10).expect("list runs after");
    assert_eq!(runs_after.len(), 2);
    assert_eq!(runs_after[0].run_id, live_report.run_id);
    assert!(!runs_after[0].dry_run);
    assert_eq!(runs_after[0].items_ok, 2);

    let live_entries = journal_after
        .get_run_entries(&live_report.run_id)
        .expect("get live entries");
    assert_eq!(live_entries.len(), 2);
    assert_eq!(live_entries[0].status, "deleted");
    assert_eq!(live_entries[1].status, "deleted");
}

#[test]
fn cas_command_rule_without_binary_never_falls_back_to_raw_delete() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();

    let cas_store_dir = base.join("pnpm_store");
    std::fs::create_dir_all(&cas_store_dir).expect("create cas dir");
    let important_pkg = cas_store_dir.join("react@18.0.0.tar");
    std::fs::write(&important_pkg, "IMPORTANT_PACKAGE_DATA").expect("write package");

    let journal_file = base.join("journal_cas.db");

    let planned_root = PlannedRoot {
        root_path: cas_store_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "react@18.0.0.tar".to_string(),
            expected_file_id: 0,
            bytes: 1000,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let cas_rule = PlannedRule {
        rule_id: "dev.pnpm.store".to_string(),
        name: "pnpm store".to_string(),
        category: "dev".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::Command {
            program: "nonexistent_pnpm_binary_12345_xyz".to_string(),
            args: vec!["store".to_string(), "prune".to_string()],
            fallback_delete_contents: false,
            timeout_secs: 10,
            program_candidates: vec![],
        },
        preconditions: PreconditionRule::default(),
        explain: "pnpm CAS store pruning".to_string(),
        est_bytes: 1000,
        item_count: 1,
        roots: vec![planned_root],
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let plan = CleanPlan {
        version: 1,
        scanned_path: base.to_string_lossy().into_owned(),
        volume_root: base.to_string_lossy().into_owned(),
        scan_method: dsk_core::ScanMethod::Dir,
        total_est_bytes: 1000,
        rules: vec![cas_rule],
        skipped: Vec::new(),
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);
    let noop_progress = |_| {};

    let opts = ExecuteOptions {
        dry_run: false,
        force_battery: true,
        journal_path: Some(journal_file.clone()),
    };

    let report = execute_plan(&plan, &opts, &deny_ctx, &noop_progress, &cancel)
        .expect("execution of cas rule");

    // The package file MUST survive because fallback_delete_contents is FALSE!
    assert!(
        important_pkg.exists(),
        "CAS store contents must NEVER be deleted when tool binary is missing!"
    );
    assert_eq!(report.items_skipped, 1);
    assert_eq!(report.items_ok, 0);
    assert_eq!(report.items_failed, 0);

    let journal = ActionJournal::open(&journal_file).expect("open journal");
    let entries = journal
        .get_run_entries(&report.run_id)
        .expect("get entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].status, "skipped");
}

#[test]
fn command_rule_with_fallback_deletes_contents_when_binary_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();

    let cache_dir = base.join("tool_cache");
    std::fs::create_dir_all(&cache_dir).expect("create dir");
    let trash_file = cache_dir.join("trash.tmp");
    std::fs::write(&trash_file, "TRASH").expect("write trash");

    let journal_file = base.join("journal_fallback.db");

    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "trash.tmp".to_string(),
            expected_file_id: 0,
            bytes: 5,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let rule = PlannedRule {
        rule_id: "tool.fallback.test".to_string(),
        name: "Tool Fallback Test".to_string(),
        category: "dev".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::Command {
            program: "nonexistent_tool_binary_98765_abc".to_string(),
            args: vec!["clean".to_string()],
            fallback_delete_contents: true,
            timeout_secs: 10,
            program_candidates: vec![],
        },
        preconditions: PreconditionRule::default(),
        explain: "Fallback delete test".to_string(),
        est_bytes: 5,
        item_count: 1,
        roots: vec![planned_root],
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let plan = CleanPlan {
        version: 1,
        scanned_path: base.to_string_lossy().into_owned(),
        volume_root: base.to_string_lossy().into_owned(),
        scan_method: dsk_core::ScanMethod::Dir,
        total_est_bytes: 5,
        rules: vec![rule],
        skipped: Vec::new(),
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);
    let noop_progress = |_| {};

    let opts = ExecuteOptions {
        dry_run: false,
        force_battery: true,
        journal_path: Some(journal_file),
    };

    let report = execute_plan(&plan, &opts, &deny_ctx, &noop_progress, &cancel)
        .expect("execution with fallback");

    assert_eq!(report.items_ok, 1);
    assert!(
        !trash_file.exists(),
        "trash file must be deleted via fallback"
    );
    assert!(cache_dir.exists(), "cache root must survive");
}

#[test]
fn execute_plan_aborts_on_cancel() {
    let plan = CleanPlan {
        version: 1,
        scanned_path: r"C:\fake".to_string(),
        volume_root: r"C:\fake".to_string(),
        scan_method: dsk_core::ScanMethod::Dir,
        total_est_bytes: 0,
        rules: Vec::new(),
        skipped: Vec::new(),
    };
    let cancel = AtomicBool::new(true);
    let deny_ctx = DenyContext::default_for_test();
    let opts = ExecuteOptions::default();

    let err = execute_plan(&plan, &opts, &deny_ctx, &|_| {}, &cancel).unwrap_err();
    assert!(matches!(err, DskError::Cancelled));
}

#[test]
fn execute_plan_skips_rule_when_active_process_running_at_execute_time() {
    let current_exe = std::env::current_exe().expect("current exe");
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("exe name")
        .to_string();

    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();

    let cache_dir = base.join("cache_root");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let protected_file = cache_dir.join("must_survive.dat");
    std::fs::write(&protected_file, "1234567890").expect("write file");

    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "must_survive.dat".to_string(),
            expected_file_id: 0,
            bytes: 10,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let planned_rule = PlannedRule {
        rule_id: "test.blocked.process".to_string(),
        name: "Test Blocked Process".to_string(),
        category: "temp".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::DeleteContents,
        preconditions: PreconditionRule {
            process_not_running: vec![exe_name.clone()],
            check_servicing: false,
            exclude_names: Vec::new(),
        },
        explain: "Skipped because test process is running".to_string(),
        est_bytes: 10,
        item_count: 1,
        roots: vec![planned_root],
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let plan = CleanPlan {
        version: 1,
        scanned_path: base.to_string_lossy().into_owned(),
        volume_root: base.to_string_lossy().into_owned(),
        scan_method: dsk_core::ScanMethod::Dir,
        total_est_bytes: 10,
        rules: vec![planned_rule],
        skipped: Vec::new(),
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);
    // Never touch the real %LOCALAPPDATA%\DiskSaver\journal.db from tests.
    let journal_dir = tempfile::tempdir().expect("journal tempdir");
    let opts = ExecuteOptions {
        dry_run: false,
        force_battery: true,
        journal_path: Some(journal_dir.path().join("journal.db")),
    };

    let report =
        execute_plan(&plan, &opts, &deny_ctx, &|_| {}, &cancel).expect("execution must succeed");

    // The rule must be in skipped_rules
    assert_eq!(report.skipped_rules.len(), 1);
    assert_eq!(report.skipped_rules[0].rule_id, "test.blocked.process");
    assert!(report.skipped_rules[0].reason.contains(&exe_name));

    // report.est_bytes must be 0 (excluding the skipped rule's bytes)
    assert_eq!(report.est_bytes, 0);
    assert_eq!(report.items_ok, 0);

    // Target file must be preserved
    assert!(
        protected_file.exists(),
        "file must survive when rule is skipped by precondition"
    );
}

#[test]
fn execute_plan_command_records_exit_code_zero_and_nonzero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();
    let journal_file = base.join("cmd_journal.db");

    let rule_ok = PlannedRule {
        rule_id: "test.cmd.ok".to_string(),
        name: "Command OK".to_string(),
        category: "dev".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::Command {
            program: "cmd.exe".to_string(),
            args: vec!["/C".to_string(), "exit 0".to_string()],
            fallback_delete_contents: false,
            timeout_secs: 5,
            program_candidates: vec![],
        },
        preconditions: PreconditionRule::default(),
        explain: "Exit 0 test".to_string(),
        est_bytes: 50,
        item_count: 1,
        roots: Vec::new(),
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let rule_fail = PlannedRule {
        rule_id: "test.cmd.fail".to_string(),
        name: "Command Fail".to_string(),
        category: "dev".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::Command {
            program: "cmd.exe".to_string(),
            args: vec!["/C".to_string(), "exit 7".to_string()],
            fallback_delete_contents: false,
            timeout_secs: 5,
            program_candidates: vec![],
        },
        preconditions: PreconditionRule::default(),
        explain: "Exit 7 test".to_string(),
        est_bytes: 50,
        item_count: 1,
        roots: Vec::new(),
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let plan = CleanPlan {
        version: 1,
        scanned_path: base.to_string_lossy().into_owned(),
        volume_root: base.to_string_lossy().into_owned(),
        scan_method: dsk_core::ScanMethod::Dir,
        total_est_bytes: 100,
        rules: vec![rule_ok, rule_fail],
        skipped: Vec::new(),
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);
    let opts = ExecuteOptions {
        dry_run: false,
        force_battery: true,
        journal_path: Some(journal_file.clone()),
    };

    let report =
        execute_plan(&plan, &opts, &deny_ctx, &|_| {}, &cancel).expect("execution must complete");

    assert_eq!(report.items_ok, 1);
    assert_eq!(report.items_failed, 1);

    let journal = ActionJournal::open(&journal_file).expect("open journal");
    let entries = journal.get_run_entries(&report.run_id).expect("entries");
    assert_eq!(entries.len(), 2);

    let ok_entry = entries
        .iter()
        .find(|e| e.rule_id == "test.cmd.ok")
        .expect("ok entry");
    assert_eq!(ok_entry.status, "executed");
    assert!(ok_entry.error_msg.is_none());

    let fail_entry = entries
        .iter()
        .find(|e| e.rule_id == "test.cmd.fail")
        .expect("fail entry");
    assert_eq!(fail_entry.status, "failed");
    assert!(fail_entry.error_msg.as_deref().unwrap_or("").contains("7"));
}

#[test]
fn execute_plan_mid_run_cancellation_flushes_partial_journal_and_preserves_remaining_rules() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();
    let journal_file = base.join("cancel_partial_journal.db");

    let dir1 = base.join("dir1");
    let dir2 = base.join("dir2");
    std::fs::create_dir_all(&dir1).expect("create dir1");
    std::fs::create_dir_all(&dir2).expect("create dir2");

    let file1 = dir1.join("item1.dat");
    let file2 = dir2.join("item2.dat");
    std::fs::write(&file1, "file1 contents").expect("write file1");
    std::fs::write(&file2, "file2 contents").expect("write file2");

    let root1 = PlannedRoot {
        root_path: dir1.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "item1.dat".to_string(),
            expected_file_id: 0,
            bytes: 14,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let root2 = PlannedRoot {
        root_path: dir2.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "item2.dat".to_string(),
            expected_file_id: 0,
            bytes: 14,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let rule1 = PlannedRule {
        rule_id: "test.rule1".to_string(),
        name: "Rule 1".to_string(),
        category: "temp".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::DeleteContents,
        preconditions: PreconditionRule::default(),
        explain: "Rule 1".to_string(),
        est_bytes: 14,
        item_count: 1,
        roots: vec![root1],
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let rule2 = PlannedRule {
        rule_id: "test.rule2".to_string(),
        name: "Rule 2".to_string(),
        category: "temp".to_string(),
        tier: RuleTier::Safe,
        regenerable: true,
        requires_admin: false,
        method: RuleMethod::DeleteContents,
        preconditions: PreconditionRule::default(),
        explain: "Rule 2".to_string(),
        est_bytes: 14,
        item_count: 1,
        roots: vec![root2],
        os_handler_bytes: None,
        estimate: Default::default(),
    };

    let plan = CleanPlan {
        version: 1,
        scanned_path: base.to_string_lossy().into_owned(),
        volume_root: base.to_string_lossy().into_owned(),
        scan_method: dsk_core::ScanMethod::Dir,
        total_est_bytes: 28,
        rules: vec![rule1, rule2],
        skipped: Vec::new(),
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);
    let opts = ExecuteOptions {
        dry_run: false,
        force_battery: true,
        journal_path: Some(journal_file.clone()),
    };

    // When rule 1 completes progress, trigger cancel so rule 2 is aborted before starting
    let on_progress = |p: CleanProgress| {
        if p.phase == CleanPhase::CleaningFiles && p.rule_id == "test.rule1" && p.done >= 1 {
            cancel.store(true, Ordering::Relaxed);
        }
    };

    let err = execute_plan(&plan, &opts, &deny_ctx, &on_progress, &cancel).unwrap_err();
    assert!(matches!(err, DskError::Cancelled));

    // Rule 1 file was deleted before cancel was observed
    assert!(!file1.exists(), "file1 must be deleted by rule 1");

    // Rule 2 file must survive because execution was cancelled!
    assert!(
        file2.exists(),
        "file2 must survive because rule 2 was not executed"
    );

    // Journal must have recorded the partial run with rule 1's deleted item!
    let journal = ActionJournal::open(&journal_file).expect("open journal");
    let runs = journal.list_runs(10).expect("list runs");
    assert_eq!(runs.len(), 1, "partial run must be flushed to journal");
    assert_eq!(runs[0].items_ok, 1);

    let entries = journal.get_run_entries(&runs[0].run_id).expect("entries");
    assert_eq!(entries.len(), 1, "only rule 1 entries should be recorded");
    assert_eq!(entries[0].rule_id, "test.rule1");
    assert_eq!(entries[0].status, "deleted");
}
