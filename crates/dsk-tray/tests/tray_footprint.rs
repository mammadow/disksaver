//! Verifies that `disksaver-tray.exe --check-once --json` runs cleanly with peak
//! working set well below 20 MiB and carries zero heavy GUI dependencies.

#![forbid(unsafe_code)]

use std::process::Command;

use dsk_core::{TRAY_FOOTPRINT_BUDGET_BYTES, TrayCheckReport};

#[test]
fn tray_check_once_json_stays_under_20_mib_working_set() {
    let tray_exe = env!("CARGO_BIN_EXE_disksaver-tray");
    let out = Command::new(tray_exe)
        .args(["--check-once", "--json"])
        .output()
        .expect("spawn disksaver-tray --check-once --json");

    assert!(
        out.status.success(),
        "disksaver-tray failed (exit {:?}): stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let report: TrayCheckReport = serde_json::from_slice(&out.stdout).expect("parse tray JSON");
    assert!(report.checked_volumes >= 1, "expected at least one volume");
    assert!(
        report.peak_working_set_bytes > 0,
        "peak_working_set_bytes should be populated"
    );
    assert!(
        report.peak_working_set_bytes < TRAY_FOOTPRINT_BUDGET_BYTES,
        "disksaver-tray peak working set {} bytes exceeded budget {} bytes",
        report.peak_working_set_bytes,
        TRAY_FOOTPRINT_BUDGET_BYTES
    );
}
