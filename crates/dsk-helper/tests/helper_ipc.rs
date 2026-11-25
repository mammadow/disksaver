use std::process::Command;
use std::time::Duration;

use dsk_core::index::codec::decode_scan_report;
use dsk_core::ipc::protocol::{
    HelperRequest, HelperResponse, MAX_CONTROL_FRAME_BYTES, MAX_STREAM_FRAME_BYTES, read_frame,
    write_frame,
};
use dsk_core::scan::ScanMethod;
use dsk_core::win::pipe::NamedPipeClient;

#[test]
fn helper_ipc_integration_ping_scan_plan_and_shutdown() {
    let helper_exe = env!("CARGO_BIN_EXE_dsk-helper");
    let current_exe = std::env::current_exe().expect("current test exe");
    let test_dir = current_exe
        .parent()
        .expect("test parent dir")
        .to_str()
        .unwrap();

    let pipe_name = format!(
        r"\\.\pipe\DiskSaverHelper_Test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let tmp = tempfile::tempdir().expect("temp dir");
    std::fs::write(tmp.path().join("test_file.tmp"), b"test content").unwrap();
    // Keep the helper's journal out of the real %LOCALAPPDATA%\DiskSaver.
    let journal_dir = tempfile::tempdir().expect("journal dir");
    let journal_path = journal_dir.path().join("journal.db");

    if dsk_core::win::is_elevated() {
        // Security boundary: an elevated helper must refuse test-only overrides with exit code 2.
        let out = Command::new(helper_exe)
            .args([
                "--pipe",
                &pipe_name,
                "--idle-timeout-secs",
                "15",
                "--allow-unelevated-test",
                "--expected-client-dir",
                test_dir,
                "--test-journal",
                journal_path.to_str().unwrap(),
            ])
            .output()
            .expect("spawn elevated dsk-helper refusal check");
        assert_eq!(out.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("disallowed when running elevated"),
            "unexpected stderr: {stderr}"
        );
        return;
    }

    let mut child = Command::new(helper_exe)
        .args([
            "--pipe",
            &pipe_name,
            "--idle-timeout-secs",
            "15",
            "--allow-unelevated-test",
            "--expected-client-dir",
            test_dir,
            "--test-journal",
            journal_path.to_str().unwrap(),
        ])
        .spawn()
        .expect("failed to spawn dsk-helper");

    // Connect client
    let mut client =
        NamedPipeClient::connect(&pipe_name, Duration::from_secs(5)).expect("connect to helper");

    // 1. Ping
    write_frame(&mut client, &HelperRequest::Ping, MAX_CONTROL_FRAME_BYTES).unwrap();
    let resp: HelperResponse = read_frame(&mut client, MAX_CONTROL_FRAME_BYTES).unwrap();
    assert!(
        matches!(resp, HelperResponse::Pong { helper_pid, .. } if helper_pid == child.id()),
        "unexpected pong: {resp:?}"
    );

    // 2. ScanVolume
    let scan_req = HelperRequest::ScanVolume {
        volume_root: tmp.path().to_str().unwrap().to_string(),
        method: ScanMethod::Dir,
    };
    write_frame(&mut client, &scan_req, MAX_CONTROL_FRAME_BYTES).unwrap();

    // Read progress / complete
    let report_bytes = loop {
        let resp: HelperResponse = read_frame(&mut client, MAX_STREAM_FRAME_BYTES).unwrap();
        match resp {
            HelperResponse::ScanProgress { .. } => continue,
            HelperResponse::ScanComplete {
                report_bytes: bytes,
            } => break bytes,
            other => panic!("unexpected response during scan: {other:?}"),
        }
    };
    let decoded_report = decode_scan_report(&mut &report_bytes[..]).expect("decode report");
    assert!(!decoded_report.index.is_empty());

    // 3. BuildPlan (should reuse cached scan and impersonate client before OS estimation)
    let build_req = HelperRequest::BuildPlan {
        volume_root: tmp.path().to_str().unwrap().to_string(),
        max_tier: dsk_core::clean::rules::RuleTier::Safe,
        include_recycle_bin: false,
    };
    write_frame(&mut client, &build_req, MAX_CONTROL_FRAME_BYTES).unwrap();
    let resp: HelperResponse = read_frame(&mut client, MAX_STREAM_FRAME_BYTES).unwrap();
    let (plan_id, plan) = match resp {
        HelperResponse::PlanBuilt {
            plan_id,
            plan,
            preconditions: _,
        } => (plan_id, plan),
        other => panic!("unexpected response during BuildPlan: {other:?}"),
    };
    assert!(!plan_id.is_empty());

    // 4. ExecutePlanRules (dry-run on returned plan rules)
    let rule_ids: Vec<String> = plan.rules.iter().map(|r| r.rule_id.clone()).collect();
    let exec_req = HelperRequest::ExecutePlanRules {
        plan_id,
        rule_ids,
        dry_run: true,
        force_battery: true,
    };
    write_frame(&mut client, &exec_req, MAX_CONTROL_FRAME_BYTES).unwrap();
    let clean_report = loop {
        let resp: HelperResponse = read_frame(&mut client, MAX_STREAM_FRAME_BYTES).unwrap();
        match resp {
            HelperResponse::CleanProgress(_) => continue,
            HelperResponse::CleanComplete(report) => break report,
            other => panic!("unexpected response during ExecutePlanRules: {other:?}"),
        }
    };
    assert!(clean_report.dry_run);

    // 5. Red-team test: ExecutePlanRules with unknown plan_id should return HelperResponse::Error
    let red_team_req = HelperRequest::ExecutePlanRules {
        plan_id: "plan-unapproved-fake".to_string(),
        rule_ids: vec!["some.rule".to_string()],
        dry_run: true,
        force_battery: true,
    };
    write_frame(&mut client, &red_team_req, MAX_CONTROL_FRAME_BYTES).unwrap();
    let resp: HelperResponse = read_frame(&mut client, MAX_CONTROL_FRAME_BYTES).unwrap();
    assert!(
        matches!(resp, HelperResponse::Error { ref kind, .. } if kind == "execution_error"),
        "expected error response for fake plan_id, got: {resp:?}"
    );

    // 6. RunOptimizer (intent-only, dry run): fixed template reported, nothing executed.
    let opt_req = HelperRequest::RunOptimizer {
        intent: dsk_core::optimize::OptimizerIntent::VssResize {
            drive: "C:".to_string(),
            max_percent: 6,
        },
        dry_run: true,
    };
    write_frame(&mut client, &opt_req, MAX_CONTROL_FRAME_BYTES).unwrap();
    let resp: HelperResponse = read_frame(&mut client, MAX_CONTROL_FRAME_BYTES).unwrap();
    match resp {
        HelperResponse::OptimizerComplete { message } => {
            assert!(message.contains("Dry run"), "{message}");
            assert!(message.contains("/maxsize=6%"), "{message}");
        }
        other => panic!("unexpected RunOptimizer response: {other:?}"),
    }

    // 7. Red-team: a path smuggled in as a "drive" is rejected by the helper's re-validation.
    let bad_req = HelperRequest::RunOptimizer {
        intent: dsk_core::optimize::OptimizerIntent::VssPruneOldest {
            drive: r"C:\Windows\System32".to_string(),
        },
        dry_run: true,
    };
    write_frame(&mut client, &bad_req, MAX_CONTROL_FRAME_BYTES).unwrap();
    let resp: HelperResponse = read_frame(&mut client, MAX_CONTROL_FRAME_BYTES).unwrap();
    assert!(
        matches!(resp, HelperResponse::Error { .. }),
        "expected rejection of non-drive VSS target, got: {resp:?}"
    );

    // 8. Shutdown
    write_frame(
        &mut client,
        &HelperRequest::Shutdown,
        MAX_CONTROL_FRAME_BYTES,
    )
    .unwrap();
    let resp: HelperResponse = read_frame(&mut client, MAX_CONTROL_FRAME_BYTES).unwrap();
    assert_eq!(resp, HelperResponse::ShuttingDown);

    drop(client);

    // Wait for helper to exit
    let exit_status = child.wait().expect("child exit");
    assert!(exit_status.success(), "helper exit status: {exit_status:?}");
    assert!(
        journal_path.exists(),
        "helper must journal into the --test-journal override, not %LOCALAPPDATA%"
    );
}
