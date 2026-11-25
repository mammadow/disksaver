mod common;

use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use common::make_junction;
use dsk_core::clean::{DenyContext, FileIdKind, PlannedItem, PlannedRoot};
use dsk_core::error::DskError;
use dsk_core::filetime_to_min2000;
use dsk_core::win::{DeleteOutcomeKind, query_file_id, safe_clean_root};

#[test]
fn junction_escape_blocked_outside_sentinel_survives() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let outside_dir = base.join("outside_protected");
    std::fs::create_dir_all(&outside_dir).expect("create outside dir");
    let secret_file = outside_dir.join("secret.txt");
    std::fs::write(&secret_file, "TOP_SECRET_RECOVERABLE_DATA").expect("write secret");

    let cache_dir = base.join("cache");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let junction_link = cache_dir.join("sub");
    make_junction(&junction_link, &outside_dir);

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    // Plan rule root targeting cache_dir
    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "sub".to_string(),
            expected_file_id: 0,
            bytes: 100,
            is_dir: true,
            mtime_min: 0,
        }],
    };

    let report = safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel)
        .expect("safe_clean_root execution");

    // The outside sentinel file MUST survive completely untouched!
    assert!(
        secret_file.exists(),
        "outside protected secret file must survive untouched"
    );
    assert_eq!(
        std::fs::read_to_string(&secret_file).expect("read secret"),
        "TOP_SECRET_RECOVERABLE_DATA"
    );

    // The cache root itself MUST still exist!
    assert!(cache_dir.exists(), "rule root cache dir must still exist");

    // Either sub was deleted as a link or blocked from escaping
    if junction_link.exists() {
        let item_outcome = report.outcomes.iter().find(|o| o.path.contains("sub"));
        if let Some(outcome) = item_outcome {
            assert!(
                outcome.kind == DeleteOutcomeKind::Failed
                    || outcome.kind == DeleteOutcomeKind::Skipped
            );
        }
    }
}

#[test]
fn intermediate_junction_escape_blocked_and_fails() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let outside_dir = base.join("outside_target");
    std::fs::create_dir_all(&outside_dir).expect("create outside dir");
    let secret_child = outside_dir.join("victim.txt");
    std::fs::write(&secret_child, "MUST_NOT_BE_DELETED").expect("write victim");

    let cache_dir = base.join("cache2");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let intermediate_junction = cache_dir.join("link_dir");
    make_junction(&intermediate_junction, &outside_dir);

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    // Plan item through the intermediate junction: cache2\link_dir\victim.txt
    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: r"link_dir\victim.txt".to_string(),
            expected_file_id: 0,
            bytes: 50,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let report = safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel)
        .expect("safe_clean_root should not panic");

    // Outside file MUST survive!
    assert!(
        secret_child.exists(),
        "victim file outside root must not be deleted through intermediate junction"
    );
    assert_eq!(
        std::fs::read_to_string(&secret_child).expect("read victim"),
        "MUST_NOT_BE_DELETED"
    );

    // The outcome must be Failed because path escaped rule root
    assert_eq!(report.failed_count, 1);
    assert_eq!(report.deleted_count, 0);
    let outcome = &report.outcomes[0];
    assert_eq!(outcome.kind, DeleteOutcomeKind::Failed);
    assert!(
        outcome
            .detail
            .as_ref()
            .map(|d| d.contains("escaped rule root"))
            .unwrap_or(false),
        "detail should indicate escape: {:?}",
        outcome.detail
    );
}

#[test]
fn file_id_swap_aborts_deletion() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let cache_dir = base.join("cache_toctou");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let target_file = cache_dir.join("a.tmp");
    std::fs::write(&target_file, "original planned content").expect("write a.tmp");

    let original_id = query_file_id(&target_file, FileIdKind::FxHash128).expect("query file id");
    assert_ne!(original_id, 0);

    // Delete a.tmp and consume the slot with dummy files
    std::fs::remove_file(&target_file).expect("remove original a.tmp");
    let dummy = cache_dir.join("dummy.tmp");
    std::fs::write(&dummy, "dummy to consume slot").expect("write dummy");

    // Recreate a.tmp with new contents
    std::fs::write(&target_file, "new replacement content - DO NOT DELETE")
        .expect("recreate a.tmp");

    let new_id = query_file_id(&target_file, FileIdKind::FxHash128).expect("query new file id");

    // If NTFS assigned the exact same ID, synthesize an expected_id that differs deterministically
    let expected_id = if new_id == original_id {
        original_id.wrapping_add(100)
    } else {
        original_id
    };

    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::FxHash128,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "a.tmp".to_string(),
            expected_file_id: expected_id,
            bytes: 100,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    let report = safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel)
        .expect("safe_clean_root execute");

    // The replaced file must NOT be deleted!
    assert!(target_file.exists(), "swapped file must NOT be deleted");
    assert_eq!(
        std::fs::read_to_string(&target_file).expect("read"),
        "new replacement content - DO NOT DELETE"
    );

    assert_eq!(report.failed_count, 1);
    assert_eq!(report.deleted_count, 0);
    assert_eq!(report.outcomes[0].kind, DeleteOutcomeKind::Failed);
    assert!(
        report.outcomes[0]
            .detail
            .as_ref()
            .map(|d| d.contains("file ID mismatch"))
            .unwrap_or(false)
    );
}

#[test]
fn denied_paths_refused_in_cleaner() {
    let ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    // Synthetic rule targeting C:\Windows\System32
    let root_sys32 = PlannedRoot {
        root_path: r"C:\Windows\System32".to_string(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "cmd.exe".to_string(),
            expected_file_id: 0,
            bytes: 100,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let res = safe_clean_root(&root_sys32, &ctx, false, 0, &cancel);
    assert!(
        matches!(res, Err(DskError::DeniedPath(_))),
        "C:\\Windows\\System32 must be rejected with DeniedPath error"
    );

    // Synthetic rule targeting user personal library Documents
    let root_docs = PlannedRoot {
        root_path: r"C:\Users\Alice\Documents".to_string(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "taxes.pdf".to_string(),
            expected_file_id: 0,
            bytes: 1000,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let res2 = safe_clean_root(&root_docs, &ctx, false, 0, &cancel);
    assert!(
        matches!(res2, Err(DskError::DeniedPath(_))),
        "User Documents library must be rejected with DeniedPath error"
    );
}

#[test]
fn dry_run_and_readonly_and_age_and_root_preservation() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let cache_dir = base.join("cache_multi");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");

    let old_file = cache_dir.join("old.tmp");
    std::fs::write(&old_file, "old file data").expect("write old");

    let readonly_file = cache_dir.join("readonly.tmp");
    std::fs::write(&readonly_file, "read-only file data").expect("write readonly");

    let new_file = cache_dir.join("new.tmp");
    std::fs::write(&new_file, "new file data").expect("write new");

    let keep_file = cache_dir.join("keep.me");
    std::fs::write(&keep_file, "keep me data").expect("write keep.me");

    // Real now_min2000 from SystemTime::now() -> Win32 FILETIME -> filetime_to_min2000
    let now = SystemTime::now();
    let dur = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time after unix epoch");
    let now_ft =
        dur.as_secs() * 10_000_000 + (dur.subsec_nanos() as u64 / 100) + 116_444_736_000_000_000;
    let now_min2000 = filetime_to_min2000(now_ft);

    // Set old.tmp and readonly.tmp mtimes to 10 days ago
    let ten_days_ago = now - Duration::from_secs(10 * 86400);
    let f_old = std::fs::File::options()
        .write(true)
        .open(&old_file)
        .expect("open old");
    f_old.set_modified(ten_days_ago).expect("set modified old");
    drop(f_old);

    let f_ro = std::fs::File::options()
        .write(true)
        .open(&readonly_file)
        .expect("open readonly");
    f_ro.set_modified(ten_days_ago)
        .expect("set modified readonly");
    drop(f_ro);

    let mut perms = std::fs::metadata(&readonly_file)
        .expect("metadata")
        .permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&readonly_file, perms).expect("set readonly");

    let min_age_days = Some(5u32);

    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days,
        exclude_names: vec!["keep.me".to_string()],
        allow_unlisted_children: false,
        items: vec![
            PlannedItem {
                rel_path: "old.tmp".to_string(),
                expected_file_id: 0,
                bytes: 12,
                is_dir: false,
                mtime_min: 100,
            },
            PlannedItem {
                rel_path: "readonly.tmp".to_string(),
                expected_file_id: 0,
                bytes: 18,
                is_dir: false,
                mtime_min: 100,
            },
            PlannedItem {
                rel_path: "new.tmp".to_string(),
                expected_file_id: 0,
                bytes: 13,
                is_dir: false,
                mtime_min: 2000,
            },
            PlannedItem {
                rel_path: "keep.me".to_string(),
                expected_file_id: 0,
                bytes: 12,
                is_dir: false,
                mtime_min: 100,
            },
        ],
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    // 1. Dry run: nothing must be deleted!
    let dry_report = safe_clean_root(&planned_root, &deny_ctx, true, now_min2000, &cancel)
        .expect("dry run safe_clean_root");

    assert!(old_file.exists(), "old.tmp must still exist after dry run");
    assert!(
        readonly_file.exists(),
        "readonly.tmp must still exist after dry run"
    );
    assert!(new_file.exists(), "new.tmp must still exist after dry run");
    assert!(keep_file.exists(), "keep.me must still exist after dry run");
    assert!(
        cache_dir.exists(),
        "cache root dir must still exist after dry run"
    );

    // In dry run, keep.me is skipped due to exclude_names, new.tmp skipped due to min_age_days
    let keep_outcome = dry_report
        .outcomes
        .iter()
        .find(|o| o.path.contains("keep.me"))
        .expect("keep.me outcome");
    assert_eq!(keep_outcome.kind, DeleteOutcomeKind::Skipped);

    let new_outcome = dry_report
        .outcomes
        .iter()
        .find(|o| o.path.contains("new.tmp"))
        .expect("new.tmp outcome");
    assert_eq!(new_outcome.kind, DeleteOutcomeKind::Skipped);
    assert!(
        new_outcome
            .detail
            .as_ref()
            .map(|d| d.contains("modified recently"))
            .unwrap_or(false)
    );

    // 2. Live run KEEPING min_age_days: Some(5): clean old & readonly, skip new.tmp and excluded keep.me
    let live_report = safe_clean_root(&planned_root, &deny_ctx, false, now_min2000, &cancel)
        .expect("live safe_clean_root");

    // old.tmp deleted (age 10 days >= 5 days)
    assert!(!old_file.exists(), "old.tmp should be deleted");
    // readonly.tmp deleted (age 10 days >= 5 days; disposition flag handles readonly)
    assert!(
        !readonly_file.exists(),
        "readonly.tmp should be deleted despite read-only attribute"
    );
    // new.tmp survives (age 0 days < 5 days)
    assert!(
        new_file.exists(),
        "new.tmp must survive due to min_age_days: Some(5)"
    );
    // keep.me survives (excluded)
    assert!(
        keep_file.exists(),
        "keep.me must survive due to exclude_names"
    );
    // Cache directory itself MUST STILL EXIST!
    assert!(
        cache_dir.exists(),
        "cache root directory itself must NEVER be deleted"
    );

    assert_eq!(live_report.deleted_count, 2);
    assert_eq!(live_report.skipped_count, 2);
    assert_eq!(live_report.failed_count, 0);
}

#[test]
fn unlisted_post_plan_file_untouched() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let cache_dir = base.join("cache_unlisted");
    let sub_dir = cache_dir.join("sub");
    std::fs::create_dir_all(&sub_dir).expect("create sub dir");

    let planned_file = sub_dir.join("planned.tmp");
    std::fs::write(&planned_file, "planned to be deleted").expect("write planned");

    // Plan contains planned.tmp and then sub (post-order deepest first)
    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![
            PlannedItem {
                rel_path: r"sub\planned.tmp".to_string(),
                expected_file_id: 0,
                bytes: 20,
                is_dir: false,
                mtime_min: 0,
            },
            PlannedItem {
                rel_path: "sub".to_string(),
                expected_file_id: 0,
                bytes: 0,
                is_dir: true,
                mtime_min: 0,
            },
        ],
    };

    // Before cleanup, an unlisted file is created inside sub!
    let unlisted_file = sub_dir.join("surprise_unlisted.tmp");
    std::fs::write(&unlisted_file, "UNLISTED_FILE_DATA").expect("write unlisted");

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    let report =
        safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel).expect("safe_clean_root");

    // planned.tmp should be deleted
    assert!(!planned_file.exists(), "planned.tmp should be deleted");

    // unlisted_file MUST STILL EXIST!
    assert!(
        unlisted_file.exists(),
        "unlisted file created after plan must NOT be deleted"
    );
    assert_eq!(
        std::fs::read_to_string(&unlisted_file).expect("read unlisted"),
        "UNLISTED_FILE_DATA"
    );

    // sub directory MUST STILL EXIST because it was not empty!
    assert!(
        sub_dir.exists(),
        "sub directory must NOT be removed when containing unlisted file"
    );

    // The outcome for sub should be Skipped (directory not empty)
    let sub_outcome = report
        .outcomes
        .iter()
        .find(|o| o.path.ends_with("sub"))
        .expect("sub outcome");
    assert_eq!(sub_outcome.kind, DeleteOutcomeKind::Skipped);
    assert!(
        sub_outcome
            .detail
            .as_ref()
            .map(|d| d.contains("not empty"))
            .unwrap_or(false)
    );
}

#[test]
fn ntfs_frn64_pinning_and_swap_abort() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let cache_dir = base.join("cache_frn");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let target_file = cache_dir.join("pinned.tmp");
    std::fs::write(&target_file, "original content to delete").expect("write pinned.tmp");

    let root_frn = query_file_id(&cache_dir, FileIdKind::NtfsFrn64).expect("query root FRN");
    let file_frn = query_file_id(&target_file, FileIdKind::NtfsFrn64).expect("query file FRN");
    assert_ne!(root_frn, 0, "NTFS root FRN should be non-zero");
    assert_ne!(file_frn, 0, "NTFS file FRN should be non-zero");

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    // 1. Successful deletion when NtfsFrn64 matches
    let planned_root = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: root_frn,
        file_id_kind: FileIdKind::NtfsFrn64,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "pinned.tmp".to_string(),
            expected_file_id: file_frn,
            bytes: 26,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let report = safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel)
        .expect("safe_clean_root with NtfsFrn64");
    assert_eq!(report.deleted_count, 1);
    assert_eq!(report.failed_count, 0);
    assert!(
        !target_file.exists(),
        "target_file should have been deleted"
    );

    // 2. FRN mismatch abort after swap or wrong FRN
    let swapped_file = cache_dir.join("swapped.tmp");
    std::fs::write(&swapped_file, "do not delete - swapped content").expect("write swapped.tmp");
    let swapped_frn =
        query_file_id(&swapped_file, FileIdKind::NtfsFrn64).expect("query swapped FRN");

    let planned_mismatch = PlannedRoot {
        root_path: cache_dir.to_string_lossy().into_owned(),
        root_file_id: root_frn,
        file_id_kind: FileIdKind::NtfsFrn64,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "swapped.tmp".to_string(),
            // Intentionally wrong FRN
            expected_file_id: swapped_frn.wrapping_add(42),
            bytes: 31,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let report_mismatch = safe_clean_root(&planned_mismatch, &deny_ctx, false, 0, &cancel)
        .expect("safe_clean_root execution");
    assert_eq!(report_mismatch.failed_count, 1);
    assert_eq!(report_mismatch.deleted_count, 0);
    assert!(
        swapped_file.exists(),
        "swapped_file must not be deleted on FRN mismatch"
    );
    assert!(
        report_mismatch.outcomes[0]
            .detail
            .as_ref()
            .map(|d| d.contains("file ID mismatch"))
            .unwrap_or(false)
    );
}

#[test]
fn reparse_root_refused_and_preserves_target() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let outside_target = base.join("outside_folder");
    std::fs::create_dir_all(&outside_target).expect("create outside folder");
    let outside_file = outside_target.join("important.txt");
    std::fs::write(&outside_file, "CRITICAL_PAYLOAD").expect("write important");

    let junction_root = base.join("junction_root");
    make_junction(&junction_root, &outside_target);

    let planned_root = PlannedRoot {
        root_path: junction_root.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "important.txt".to_string(),
            expected_file_id: 0,
            bytes: 16,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    let report = safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel)
        .expect("safe_clean_root returns CleanRootReport on root error");

    // Must refuse the reparse root
    assert_eq!(report.failed_count, 1);
    assert_eq!(report.deleted_count, 0);
    assert!(
        report.outcomes[0]
            .detail
            .as_ref()
            .map(|d| d.contains("reparse point"))
            .unwrap_or(false)
    );

    // Outside files must be completely preserved!
    assert!(outside_file.exists(), "outside file must survive");
    assert_eq!(
        std::fs::read_to_string(&outside_file).expect("read"),
        "CRITICAL_PAYLOAD"
    );
}

#[test]
fn canonical_deny_above_root_and_unsafe_rel_path_blocked() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    // 1. Test canonical deny above root:
    // Create a protected directory inside tmp and configure it in DenyContext
    let protected_dir = base.join("protected_dir");
    let protected_sub = protected_dir.join("System32");
    std::fs::create_dir_all(&protected_sub).expect("create protected System32");
    let victim = protected_sub.join("victim.txt");
    std::fs::write(&victim, "CANONICAL_PROTECTED").expect("write victim");

    // Create an intermediate directory containing a junction to protected_dir
    let wrapper_dir = base.join("wrapper");
    std::fs::create_dir_all(&wrapper_dir).expect("create wrapper");
    let junction_in_wrapper = wrapper_dir.join("link");
    make_junction(&junction_in_wrapper, &protected_dir);

    // Now root_path is wrapper\link\System32.
    // Lexically, wrapper\link\System32 does not contain "protected_dir" in its path string!
    let stealth_root = junction_in_wrapper.join("System32");

    let mut deny_ctx = DenyContext::default_for_test();
    // Deny the canonical target via DenyContext::windows_dir
    deny_ctx.windows_dir = protected_dir.to_string_lossy().into_owned();

    let planned_root = PlannedRoot {
        root_path: stealth_root.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "victim.txt".to_string(),
            expected_file_id: 0,
            bytes: 19,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let cancel = AtomicBool::new(false);
    let res = safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel);
    // Root canonical path check must reject with DeniedPath error!
    assert!(
        matches!(res, Err(DskError::DeniedPath(_))),
        "stealth root pointing into denied directory must be rejected by canonical deny check: {:?}",
        res
    );
    assert!(victim.exists(), "victim file must survive");

    // 2. Test unsafe item.rel_path components (.. traversal, drive prefix, empty)
    let normal_root = base.join("normal_cache");
    std::fs::create_dir_all(&normal_root).expect("create normal cache");
    let outside_secret = base.join("outside_secret.txt");
    std::fs::write(&outside_secret, "OUTSIDE_DATA").expect("write outside secret");

    let unsafe_root = PlannedRoot {
        root_path: normal_root.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![
            PlannedItem {
                rel_path: r"..\outside_secret.txt".to_string(),
                expected_file_id: 0,
                bytes: 12,
                is_dir: false,
                mtime_min: 0,
            },
            PlannedItem {
                rel_path: r"C:\Windows\System32\calc.exe".to_string(),
                expected_file_id: 0,
                bytes: 12,
                is_dir: false,
                mtime_min: 0,
            },
            PlannedItem {
                rel_path: "".to_string(),
                expected_file_id: 0,
                bytes: 0,
                is_dir: false,
                mtime_min: 0,
            },
            PlannedItem {
                rel_path: "/".to_string(),
                expected_file_id: 0,
                bytes: 0,
                is_dir: false,
                mtime_min: 0,
            },
            PlannedItem {
                rel_path: r"\\".to_string(),
                expected_file_id: 0,
                bytes: 0,
                is_dir: false,
                mtime_min: 0,
            },
        ],
    };

    let default_deny = DenyContext::default_for_test();
    let report_unsafe = safe_clean_root(&unsafe_root, &default_deny, false, 0, &cancel)
        .expect("safe_clean_root should complete and fail items");
    assert_eq!(report_unsafe.failed_count, 5);
    assert_eq!(report_unsafe.deleted_count, 0);
    for outcome in &report_unsafe.outcomes {
        assert_eq!(outcome.kind, DeleteOutcomeKind::Failed);
        assert!(
            outcome
                .detail
                .as_ref()
                .map(|d| d.contains("unsafe relative path"))
                .unwrap_or(false),
            "expected 'unsafe relative path', got {:?}",
            outcome.detail
        );
    }
    assert!(
        outside_secret.exists(),
        "outside secret must never be touched"
    );
}

#[test]
fn dangling_junction_root_rejected_as_reparse_point() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let base = tmp.path();

    let ephemeral_target = base.join("ephemeral_target");
    std::fs::create_dir_all(&ephemeral_target).expect("create target");

    let dangling_junction = base.join("dangling_root_link");
    make_junction(&dangling_junction, &ephemeral_target);

    // Remove the target directory so `dangling_junction.exists()` is false,
    // while the junction reparse point itself remains on disk.
    std::fs::remove_dir(&ephemeral_target).expect("remove target to make junction dangling");
    assert!(
        !dangling_junction.exists(),
        "dangling junction should report exists() == false when traversed"
    );

    let planned_root = PlannedRoot {
        root_path: dangling_junction.to_string_lossy().into_owned(),
        root_file_id: 0,
        file_id_kind: FileIdKind::Unpinned,
        min_age_days: None,
        exclude_names: Vec::new(),
        allow_unlisted_children: false,
        items: vec![PlannedItem {
            rel_path: "some_file.tmp".to_string(),
            expected_file_id: 0,
            bytes: 64,
            is_dir: false,
            mtime_min: 0,
        }],
    };

    let deny_ctx = DenyContext::default_for_test();
    let cancel = AtomicBool::new(false);

    let report = safe_clean_root(&planned_root, &deny_ctx, false, 0, &cancel)
        .expect("safe_clean_root should open dangling junction with FILE_FLAG_OPEN_REPARSE_POINT");

    assert_eq!(report.failed_count, 1);
    assert_eq!(report.deleted_count, 0);
    assert!(
        report.outcomes[0]
            .detail
            .as_ref()
            .is_some_and(|d| d.contains("reparse point")),
        "expected reparse point rejection detail, got {:?}",
        report.outcomes[0].detail
    );
}
