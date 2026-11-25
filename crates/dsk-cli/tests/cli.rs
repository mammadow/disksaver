use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use predicates::str::contains;

#[test]
fn scan_folder_json() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
    std::fs::write(tmp.path().join("b.txt"), b"world").unwrap();
    let dir = tmp.path().to_str().unwrap();

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args(["scan", dir, "--method", "dir", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["method"], "dir");
    assert_eq!(v["files"], 2);
    assert!(v["top_files"][0]["bytes"].as_u64().unwrap() > 0);
    assert!(v["stats"].is_null());
}

#[test]
fn scan_human_output() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
    let dir = tmp.path().to_str().unwrap();

    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["scan", dir])
        .assert()
        .success()
        .stdout(contains("Scanned").and(contains("Largest folders")));
}

#[test]
fn mft_on_folder_fails_nicely() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_str().unwrap();

    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["scan", dir, "--method", "mft"])
        .assert()
        .code(2)
        .stderr(contains("needs a volume root"));
}

#[test]
fn mft_unelevated_fails_nicely() {
    if !dsk_core::win::is_elevated() {
        Command::cargo_bin("disksaver")
            .unwrap()
            .args(["scan", "C:\\", "--method", "mft"])
            .assert()
            .code(2)
            .stderr(contains("elevated"));
    }
}

#[test]
fn scan_folder_stats_json() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("test.bin"), vec![0u8; 1024]).unwrap();
    let dir = tmp.path().to_str().unwrap();

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args(["scan", dir, "--method", "dir", "--json", "--stats"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v["stats"].is_object());
    assert!(v["stats"]["peak_working_set"].as_u64().unwrap() > 0);
    assert!(v["stats"]["index_heap_bytes"].as_u64().is_some());
}

#[test]
fn scan_folder_stats_human() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("sample.txt"), b"some sample content").unwrap();
    let dir = tmp.path().to_str().unwrap();

    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["scan", dir, "--stats"])
        .assert()
        .success()
        .stdout(
            contains("Stats:")
                .and(contains("Peak working set"))
                .and(contains("Index heap bytes")),
        );
}

#[test]
fn scan_all_json_fields_present() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub").join("data.csv"), b"1,2,3").unwrap();
    let dir = tmp.path().to_str().unwrap();

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "scan",
            dir,
            "--method",
            "dir",
            "--json",
            "--stats",
            "--top-dirs",
            "5",
            "--depth",
            "2",
            "--top-files",
            "5",
            "--top-ext",
            "5",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let obj = v.as_object().unwrap();

    // Verify all keys from the schema specification
    let required_keys = [
        "path",
        "method",
        "elapsed_ms",
        "files",
        "dirs",
        "skipped",
        "scanned_alloc",
        "check",
        "fallback_reason",
        "top_dirs",
        "top_files",
        "extensions",
        "stats",
    ];

    for key in &required_keys {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }

    assert_eq!(v["files"], 1);
    assert_eq!(v["dirs"], 1);
    assert!(v["top_dirs"].is_array());
    assert!(v["top_files"].is_array());
    assert!(v["extensions"].is_array());
}

#[test]
fn nonexistent_path_fails() {
    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["scan", "Z:\\nonexistent_dir_123456789\\abc"])
        .assert()
        .code(1)
        .stderr(contains("error:"));
}

#[test]
fn clean_without_yes_refuses_with_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("sentinel.tmp");
    std::fs::write(&file_path, b"do not delete me").unwrap();
    let dir = tmp.path().to_str().unwrap();

    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["clean", dir])
        .assert()
        .code(2)
        .stderr(contains(
            "refusing to delete without --yes (pass --dry-run to simulate, or --yes to execute)",
        ));

    assert!(file_path.exists(), "file must not be deleted");
}

#[test]
fn history_nonexistent_journal_behavior() {
    let tmp = tempfile::tempdir().unwrap();
    let non_existent = tmp.path().join("missing_journal.db");
    let db_str = non_existent.to_str().unwrap();

    // 1. Human history without database should exit 0 and report no history without creating DB
    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["history", "--journal", db_str])
        .assert()
        .success()
        .stdout(contains("No cleanup history found."));
    assert!(
        !non_existent.exists(),
        "db file should not be created on read-only check"
    );

    // 2. JSON history without database should exit 0 and emit []
    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args(["history", "--journal", db_str, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(out).unwrap();
    assert_eq!(s.trim(), "[]");
    assert!(!non_existent.exists());

    // 3. History with specific run ID when database is missing should exit 1
    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["history", "--journal", db_str, "--run", "missing-run-id"])
        .assert()
        .code(1)
        .stderr(contains("not found"));
}

#[test]
fn plan_dry_run_clean_and_history_e2e_on_synthetic_temp() {
    use std::time::{Duration, SystemTime};

    let tmp = tempfile::tempdir().unwrap();
    let iso_dir = tmp.path().to_path_buf();
    let iso_dir_str = iso_dir.to_str().unwrap();

    // Create an old file (> 5 days old, e.g. 10 days)
    let old_file_path = iso_dir.join("old.tmp");
    let old_file = std::fs::File::create(&old_file_path).unwrap();
    old_file.set_len(2048).unwrap();
    let ten_days_ago = SystemTime::now() - Duration::from_secs(10 * 86400);
    old_file.set_modified(ten_days_ago).unwrap();
    drop(old_file);

    // Create a fresh file (< 2 days old)
    let recent_file_path = iso_dir.join("recent.tmp");
    std::fs::write(&recent_file_path, b"recent temporary file").unwrap();

    let plan_path = tmp.path().join("plan.json");
    let plan_path_str = plan_path.to_str().unwrap();
    let journal_path = tmp.path().join("journal.db");
    let journal_path_str = journal_path.to_str().unwrap();

    // 1. Run plan --out plan.json with isolated TEMP and TMP
    Command::cargo_bin("disksaver")
        .unwrap()
        .env("TEMP", iso_dir_str)
        .env("TMP", iso_dir_str)
        .args([
            "plan",
            iso_dir_str,
            "--rule",
            "sys.temp.user",
            "--no-os-handlers",
            "--out",
            plan_path_str,
        ])
        .assert()
        .success();

    assert!(plan_path.exists(), "plan file should be written");
    let plan_content = std::fs::read_to_string(&plan_path).unwrap();
    let plan_val: serde_json::Value = serde_json::from_str(&plan_content).unwrap();

    let rules = plan_val["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 1, "should match sys.temp.user");
    assert_eq!(rules[0]["rule_id"], "sys.temp.user");
    let items = rules[0]["roots"][0]["items"]
        .as_array()
        .expect("items array");
    assert_eq!(items.len(), 1, "only old file should be matched");
    assert_eq!(items[0]["rel_path"], "old.tmp");

    // 2. Clean with --dry-run (using plan file)
    Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "clean",
            "--plan",
            plan_path_str,
            "--dry-run",
            "--journal",
            journal_path_str,
        ])
        .assert()
        .success();

    assert!(old_file_path.exists(), "dry-run must keep old file");
    assert!(recent_file_path.exists(), "dry-run must keep recent file");

    // 3. Clean with --yes (using plan file)
    Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "clean",
            "--plan",
            plan_path_str,
            "--yes",
            "--journal",
            journal_path_str,
        ])
        .assert()
        .success();

    assert!(!old_file_path.exists(), "live clean must delete old file");
    assert!(
        recent_file_path.exists(),
        "live clean must preserve recent file"
    );
    assert!(iso_dir.exists(), "folder root must remain intact");

    // 4. History check
    let hist_out = Command::cargo_bin("disksaver")
        .unwrap()
        .args(["history", "--journal", journal_path_str, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let runs: Vec<serde_json::Value> = serde_json::from_slice(&hist_out).unwrap();
    assert_eq!(runs.len(), 2, "must have recorded dry-run and live run");
    // Newest run first: live run is index 0
    let live_run = &runs[0];
    let live_run_id = live_run["run_id"].as_str().unwrap();
    assert_eq!(live_run["dry_run"], false);

    // 5. Query specific run details
    let run_details_out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "history",
            "--journal",
            journal_path_str,
            "--run",
            live_run_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&run_details_out).unwrap();
    assert!(
        !entries.is_empty(),
        "must have recorded entries for deleted file"
    );
    let deleted_entry = entries
        .iter()
        .find(|e| e["path"].as_str().unwrap().contains("old.tmp"))
        .expect("entry for old.tmp");
    assert_eq!(deleted_entry["status"], "deleted");
}

#[test]
fn cli_plan_tier_review_includes_tier2_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_str().unwrap();
    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args(["plan", dir, "--tier", "review", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("rules").is_some());

    // Also test that --tier advanced is accepted by clap
    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["plan", dir, "--tier", "advanced", "--json"])
        .assert()
        .success();
}

#[test]
fn cli_optimize_tunables_probe_json() {
    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args(["optimize", "tunables", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("servicing_busy").is_some());
    assert!(v.get("is_laptop_battery_present").is_some());
}

#[test]
fn cli_optimize_compress_dry_run_json() {
    let tmp = tempfile::tempdir().unwrap();
    let sample_dir = tmp.path().join("compress_me");
    std::fs::create_dir_all(&sample_dir).unwrap();
    for i in 0..10 {
        std::fs::write(
            sample_dir.join(format!("file_{i}.txt")),
            b"repetitive text content for compression testing\n".repeat(50),
        )
        .unwrap();
    }

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "optimize",
            "compress",
            "--path",
            sample_dir.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("estimated_savings_pct").is_some());
    assert!(v.get("recommended").is_some());
}

#[test]
fn cli_optimize_relocate_and_undo_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let source_dir = tmp.path().join("src_models");
    let target_parent = tmp.path().join("dst_storage");
    let journal_path = tmp.path().join("cli_reloc_journal.db");

    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::create_dir_all(&target_parent).unwrap();
    std::fs::write(
        source_dir.join("weights.bin"),
        b"neural network weights payload",
    )
    .unwrap();

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "optimize",
            "relocate",
            "--source",
            source_dir.to_str().unwrap(),
            "--target-parent",
            target_parent.to_str().unwrap(),
            "--journal",
            journal_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let reloc_id = v["relocation_id"].as_str().expect("relocation_id");

    // Source must now exist as junction
    assert!(source_dir.exists());

    // Undo relocation
    Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "optimize",
            "undo-relocate",
            "--id",
            reloc_id,
            "--journal",
            journal_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    assert!(source_dir.exists());
    assert!(!target_parent.join("src_models").exists());
}

#[test]
fn cli_dupes_finds_duplicates_and_gates_live_remediation_without_yes() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_root = tmp.path().join("scan_dupes");
    let cache_db = tmp.path().join("hash_cache.sqlite");
    std::fs::create_dir_all(&scan_root).unwrap();

    let payload = vec![0x7Cu8; 4096];
    std::fs::write(scan_root.join("copy_a.bin"), &payload).unwrap();
    std::fs::write(scan_root.join("copy_b.bin"), &payload).unwrap();

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "dupes",
            scan_root.to_str().unwrap(),
            "--min-bytes",
            "1024",
            "--cache-db",
            cache_db.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["groups"].as_array().unwrap().len(), 1);
    assert_eq!(v["total_wasted_bytes"].as_u64(), Some(4096));

    // Must fail with exit code 2 when --action is supplied without --yes or --dry-run.
    Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "dupes",
            scan_root.to_str().unwrap(),
            "--min-bytes",
            "1024",
            "--cache-db",
            cache_db.to_str().unwrap(),
            "--action",
            "hardlink",
        ])
        .assert()
        .code(2);
}

#[test]
fn cli_insights_detects_projects_and_models_json() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("workspace_root");
    let cargo_proj = root.join("my_crate");
    let cargo_tgt = cargo_proj.join("target");
    std::fs::create_dir_all(&cargo_tgt).unwrap();
    std::fs::write(cargo_proj.join("Cargo.toml"), "[package]\nname=\"demo\"\n").unwrap();
    std::fs::write(cargo_tgt.join("artifact.rlib"), vec![0u8; 4096]).unwrap();

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "insights",
            root.to_str().unwrap(),
            "--section",
            "projects",
            "--min-bytes",
            "1024",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let artifacts = v["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0]["ecosystem"], "Rust");
}

#[test]
fn cli_scan_no_cache_and_growth_respects_missing_db_and_reports_runaway() {
    use dsk_core::index::builder::{EntryBatch, IndexBuilder, NodeFlags, RawEntry};
    use dsk_core::index::names::NameArena;
    use dsk_core::{GrowthDb, VolumeInfo};

    let tmp = tempfile::tempdir().unwrap();
    let scan_dir = tmp.path().join("sample_scan");
    std::fs::create_dir_all(&scan_dir).unwrap();
    std::fs::write(scan_dir.join("hello.bin"), vec![1u8; 4096]).unwrap();

    // 1. `--no-cache` works cleanly on `scan`
    Command::cargo_bin("disksaver")
        .unwrap()
        .args(["scan", scan_dir.to_str().unwrap(), "--no-cache", "--json"])
        .assert()
        .success();

    // 2. `disksaver growth` with nonexistent DB does NOT create it on disk
    let missing_db = tmp.path().join("never_created").join("growth.db");
    let out_empty = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "growth",
            "C:\\",
            "--db",
            missing_db.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let empty_json: serde_json::Value = serde_json::from_slice(&out_empty).unwrap();
    assert_eq!(empty_json["has_baseline"], false);
    assert!(!missing_db.exists());
    assert!(!tmp.path().join("never_created").exists());

    // 3. Populate isolated growth.db and verify `disksaver growth --json` reports runaway
    let db_path = tmp.path().join("populated.db");
    let mut db = GrowthDb::open(&db_path).unwrap();
    let now = GrowthDb::now_unix();
    let vol = VolumeInfo {
        root: "C:\\".to_string(),
        fs_name: "NTFS".to_string(),
        serial: 1,
        cluster_size: 4096,
        total_bytes: 1_000_000_000_000,
        free_bytes: 500_000_000_000,
        seek_penalty: Some(false),
    };
    let make_ix = |bytes: u64| {
        let mut names = NameArena::new();
        let dn = names.push_str("RunawayLogs");
        let fn_ = names.push_str("trace.log");
        let mut b = IndexBuilder::new(5, "C:\\", vol.clone());
        b.push_batch(EntryBatch {
            names,
            entries: vec![
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    file_id: 10,
                    name: dn,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 10,
                    file_id: 11,
                    name: fn_,
                    logical: bytes,
                    allocated: bytes,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
            ],
        });
        b.finish()
    };

    let ix0 = make_ix(500_000_000);
    db.record_rollup_from_index(&ix0, "C:\\", now - 86_400)
        .unwrap();
    let ix1 = make_ix(500_000_000 + 6 * 1024 * 1024 * 1024);
    db.record_rollup_from_index(&ix1, "C:\\", now).unwrap();
    drop(db);

    let out_pop = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "growth",
            "C:\\",
            "--window",
            "24h",
            "--db",
            db_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let pop_json: serde_json::Value = serde_json::from_slice(&out_pop).unwrap();
    assert_eq!(pop_json["has_baseline"], true);
    let runaways = pop_json["runaways"].as_array().unwrap();
    assert_eq!(runaways.len(), 1);
    assert_eq!(runaways[0]["path"], "C:\\RunawayLogs");
    assert_eq!(runaways[0]["runaway"], true);
}

#[test]
fn cli_install_dir_dry_run_reports_protected_dacl_and_binaries() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("release_bins");
    std::fs::create_dir_all(&src).unwrap();
    for bin in [
        "disksaver.exe",
        "disksaver-gui.exe",
        "dsk-helper.exe",
        "disksaver-tray.exe",
    ] {
        std::fs::write(src.join(bin), format!("mock-{bin}")).unwrap();
    }
    let dst = tmp.path().join("ProtectedInstall");

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "install-dir",
            dst.to_str().unwrap(),
            "--source-dir",
            src.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["dry_run"], true);
    assert_eq!(
        json["sddl_applied"],
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
    );
    // Dry runs never measure writability.
    assert!(json["user_writable_after"].is_null());
    assert_eq!(json["copied_binaries"].as_array().unwrap().len(), 4);
    assert!(
        json["skipped_missing_binaries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // A temp dir under the user profile is renamable by the user: a live install would refuse.
    assert!(
        !json["blocking_issues"].as_array().unwrap().is_empty(),
        "expected blocking issues for a user-profile target: {json}"
    );
    assert!(
        !dst.exists(),
        "dry-run must not create destination directory"
    );

    // `--target` is accepted as an alternative to the positional TARGET, but not both at once.
    Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "install-dir",
            "--target",
            dst.to_str().unwrap(),
            "--source-dir",
            src.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .assert()
        .success();
    Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "install-dir",
            dst.to_str().unwrap(),
            "--target",
            dst.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .code(2);
}

#[test]
fn cli_install_dir_defaults_to_program_files_and_passes_preflight() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("bins");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("disksaver.exe"), b"mock").unwrap();

    let out = Command::cargo_bin("disksaver")
        .unwrap()
        .args([
            "install-dir",
            "--source-dir",
            src.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let target = json["target_dir"].as_str().unwrap().to_ascii_lowercase();
    assert!(
        target.ends_with(r"\disksaver"),
        "unexpected default target {target}"
    );
    assert!(
        json["blocking_issues"].as_array().unwrap().is_empty(),
        "Program Files target should pass pre-flight: {json}"
    );
}
