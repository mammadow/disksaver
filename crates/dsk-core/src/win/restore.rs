//! Windows System Restore point creation and OS uninstall window query.

#![allow(unsafe_code)]

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{
    ERROR_SERVICE_DISABLED, GetLastError, RPC_E_CHANGED_MODE, S_FALSE, S_OK,
};
use windows::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoInitializeSecurity, CoUninitialize, EOAC_NONE,
    RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Restore::{
    APPLICATION_INSTALL, BEGIN_SYSTEM_CHANGE, END_SYSTEM_CHANGE, RESTOREPOINTINFOW,
    SRSetRestorePointW, STATEMGRSTATUS,
};

use crate::win::process::hidden_command;
use crate::win::volume::system32_dir;

/// Outcome of attempting to create a Windows System Restore point.
///
/// Serialized into `CleanReport::restore_point` (and across the helper pipe) so the CLI and GUI
/// can tell the user when an Advanced cleanup ran *without* a fresh restore point (System Restore
/// off, throttled, or not elevated), as spec §15 requires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum RestorePointOutcome {
    Created { sequence_number: u64 },
    DisabledOrUnavailable(String),
}

impl RestorePointOutcome {
    /// One-line, user-facing summary for reports.
    pub fn summary(&self) -> String {
        match self {
            Self::Created { sequence_number } => format!(
                "System Restore point #{sequence_number} requested before Advanced cleanup \
                 (Windows may reuse a point created in the last 24 hours)"
            ),
            Self::DisabledOrUnavailable(reason) => {
                format!("No System Restore point was created before Advanced cleanup: {reason}")
            }
        }
    }

    /// `true` when cleanup proceeded without a restore point (callers should warn).
    pub fn is_warning(&self) -> bool {
        matches!(self, Self::DisabledOrUnavailable(_))
    }
}

/// Per-call COM apartment for `SRSetRestorePointW` (Microsoft's sample initializes COM and COM
/// security first so the System Restore service can call back into the process).
struct ComMtaGuard {
    need_uninit: bool,
}

impl ComMtaGuard {
    fn enter() -> Self {
        // SAFETY: Standard MTA initialization of the calling thread.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr == S_OK || hr == S_FALSE {
            Self { need_uninit: true }
        } else {
            // RPC_E_CHANGED_MODE: the thread is already an STA owned by someone else. COM is
            // usable as-is and we must NOT call CoUninitialize for an init we did not perform.
            debug_assert!(hr == RPC_E_CHANGED_MODE || hr.is_err());
            Self { need_uninit: false }
        }
    }
}

impl Drop for ComMtaGuard {
    fn drop(&mut self) {
        if self.need_uninit {
            // SAFETY: Balances the successful S_OK/S_FALSE CoInitializeEx above on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// Best-effort process-wide COM security with impersonation. `RPC_E_TOO_LATE` (the process
/// already initialized COM security) is expected and ignored.
fn ensure_com_security_for_restore() {
    // SAFETY: Documented default-ACL call; failure only means security was already initialized.
    let _ = unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
    };
}

/// Creates a Windows System Restore point if System Restore is enabled on the system (§10.7).
///
/// Executes both `BEGIN_SYSTEM_CHANGE` and `END_SYSTEM_CHANGE` so the restore point is committed.
/// Returns [`RestorePointOutcome::Created`] on success, or [`RestorePointOutcome::DisabledOrUnavailable`]
/// if System Restore is disabled, throttled, or unavailable on this SKU.
pub fn create_restore_point_if_enabled(description: &str) -> RestorePointOutcome {
    // System Restore requires administrator rights; do not touch process-wide COM security in an
    // unelevated GUI/CLI just to receive ERROR_ACCESS_DENIED.
    if !crate::win::volume::is_elevated() {
        return RestorePointOutcome::DisabledOrUnavailable(
            "not running elevated (System Restore requires administrator rights)".to_string(),
        );
    }
    let _com = ComMtaGuard::enter();
    ensure_com_security_for_restore();

    let mut desc_utf16 = [0u16; 256];
    let encoded: Vec<u16> = description.encode_utf16().take(255).collect();
    desc_utf16[..encoded.len()].copy_from_slice(&encoded);

    let rp_begin = RESTOREPOINTINFOW {
        dwEventType: BEGIN_SYSTEM_CHANGE,
        dwRestorePtType: APPLICATION_INSTALL,
        llSequenceNumber: 0,
        szDescription: desc_utf16,
    };

    let mut sm_status = STATEMGRSTATUS::default();

    // SAFETY: Invoking SRSetRestorePointW(BEGIN_SYSTEM_CHANGE) with stack-allocated structs.
    let ok = unsafe { SRSetRestorePointW(&rp_begin, &mut sm_status) };

    if ok.as_bool() {
        let seq = sm_status.llSequenceNumber;
        let rp_end = RESTOREPOINTINFOW {
            dwEventType: END_SYSTEM_CHANGE,
            dwRestorePtType: APPLICATION_INSTALL,
            llSequenceNumber: seq,
            szDescription: desc_utf16,
        };
        let mut end_status = STATEMGRSTATUS::default();
        // SAFETY: Completing restore point transaction with END_SYSTEM_CHANGE and returned sequence number.
        let _ = unsafe { SRSetRestorePointW(&rp_end, &mut end_status) };

        RestorePointOutcome::Created {
            sequence_number: seq as u64,
        }
    } else {
        let err = unsafe { GetLastError() };
        let n_status = sm_status.nStatus;
        let msg = if err == ERROR_SERVICE_DISABLED || n_status == ERROR_SERVICE_DISABLED {
            "System Restore service is disabled".to_string()
        } else if n_status.0 != 0 {
            format!("System Restore status: Win32 {}", n_status.0)
        } else {
            format!("System Restore error: Win32 {}", err.0)
        };
        RestorePointOutcome::DisabledOrUnavailable(msg)
    }
}

/// Parses the output of `Dism.exe /Online /Get-OSUninstallWindow` to extract remaining rollback days.
///
/// Ignores unrelated header lines such as `Version: 10.0.26100.1`.
pub fn parse_dism_uninstall_window_days(stdout: &str) -> Option<u32> {
    for line in stdout.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let key_lower = key.trim().to_ascii_lowercase();
            if key_lower.contains("uninstall window") {
                let val_trimmed = val.trim();
                if let Ok(days) = val_trimmed.parse::<u32>()
                    && days <= 365
                {
                    return Some(days);
                }
            }
        }
    }
    None
}

/// Queries the remaining days for reverting previous Windows installations via DISM.
pub fn query_os_uninstall_window_days() -> Option<u32> {
    let dism_path = system32_dir().join("Dism.exe");

    // `/English` keeps the "Uninstall Window" key culture-neutral on localized Windows.
    let out = hidden_command(dism_path)
        .args(["/English", "/Online", "/Get-OSUninstallWindow"])
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&out.stdout);
    parse_dism_uninstall_window_days(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_point_outcome_serializes_and_summarizes() {
        let created = RestorePointOutcome::Created {
            sequence_number: 42,
        };
        let skipped = RestorePointOutcome::DisabledOrUnavailable("disabled".to_string());
        assert!(!created.is_warning());
        assert!(skipped.is_warning());
        assert!(created.summary().contains("#42"));
        assert!(skipped.summary().contains("No System Restore point"));
        for o in [created, skipped] {
            let json = serde_json::to_string(&o).expect("serialize");
            let back: RestorePointOutcome = serde_json::from_str(&json).expect("roundtrip");
            assert_eq!(back, o);
        }
    }

    #[test]
    fn restore_point_attempt_never_panics() {
        let outcome = create_restore_point_if_enabled("DiskSaver Test");
        // May succeed or be disabled/throttled on test VM, but must not panic!
        assert!(matches!(
            outcome,
            RestorePointOutcome::Created { .. } | RestorePointOutcome::DisabledOrUnavailable(_)
        ));
    }

    #[test]
    fn parse_dism_uninstall_window_days_ignores_version_header() {
        let error_output = "\
Deployment Image Servicing and Management tool
Version: 10.0.26100.1

Image Version: 10.0.26100.2033

Error: 1168
";
        assert_eq!(parse_dism_uninstall_window_days(error_output), None);

        let valid_output = "\
Deployment Image Servicing and Management tool
Version: 10.0.26100.1

Image Version: 10.0.26100.2033

Uninstall Window : 10
The operation completed successfully.
";
        assert_eq!(parse_dism_uninstall_window_days(valid_output), Some(10));
    }
}
