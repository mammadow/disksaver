//! Win32 runtime preconditions engine: processes, servicing, battery, and file locks.

use std::path::Path;

use rustc_hash::FxHashSet;
use windows::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_MULTI_SZ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
    RegQueryValueExW,
};
use windows::Win32::System::RestartManager::{
    CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
    RmStartSession,
};
use windows::core::{PCWSTR, PWSTR};

use crate::clean::{CleanPlan, RuleMethod, SkippedRule};
use crate::error::{DskError, Result};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

fn win32_err(ctx: &'static str, code: u32) -> DskError {
    let clean_code = if (code & 0xFFFF_0000) == 0x8007_0000 {
        code & 0xFFFF
    } else {
        code
    };
    DskError::Win32 {
        ctx,
        code: clean_code,
    }
}

/// RAII guard for Win32 `HANDLE` values.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// RAII guard for Win32 `HKEY` registry handles.
struct RegKeyGuard(HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if self.0 != HKEY::default() {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

/// RAII guard for Restart Manager sessions.
struct RmSessionGuard(u32);

impl Drop for RmSessionGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = RmEndSession(self.0);
            }
        }
    }
}

/// Snapshot of system preconditions probed before executing a cleanup plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemPreconditions {
    pub elevated: bool,
    pub running_processes: FxHashSet<String>,
    pub servicing_reason: Option<String>,
    pub battery_pct: Option<u8>,
    pub on_ac_power: bool,
}

/// Enumerates all currently running processes into a set of lowercased executable names.
pub fn running_processes() -> Result<FxHashSet<String>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| win32_err("CreateToolhelp32Snapshot", e.code().0 as u32))?;
    let _guard = HandleGuard(snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut procs = FxHashSet::default();

    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            if len > 0 {
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();
                procs.insert(name);
            }

            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    Ok(procs)
}

/// Parses raw bytes of a `REG_MULTI_SZ` value, returning true if non-zero UTF-16 characters exist.
pub fn has_pending_file_renames(bytes: &[u8]) -> bool {
    if bytes.len() <= 2 {
        return false;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .any(|&[b0, b1]| u16::from_ne_bytes([b0, b1]) != 0)
}

/// Checks whether Windows servicing, installers, or reboot-pending operations are busy.
pub fn servicing_busy(running: &FxHashSet<String>) -> Option<String> {
    // 1. Process check
    if running.contains("tiworker.exe") {
        return Some("tiworker.exe is running".to_string());
    }
    if running.contains("trustedinstaller.exe") {
        return Some("trustedinstaller.exe is running".to_string());
    }

    // 2. HKLM Component Based Servicing RebootPending
    let cbs_key_w = to_wide(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    );
    let mut hkey = HKEY::default();
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(cbs_key_w.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if res == ERROR_SUCCESS {
        let _guard = RegKeyGuard(hkey);
        return Some("CBS RebootPending".to_string());
    }

    // 3. HKLM WindowsUpdate Auto Update RebootRequired
    let wu_key_w = to_wide(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    );
    let mut hkey = HKEY::default();
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wu_key_w.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if res == ERROR_SUCCESS {
        let _guard = RegKeyGuard(hkey);
        return Some("Windows Update RebootRequired".to_string());
    }

    // 4. HKLM Session Manager PendingFileRenameOperations
    let sm_key_w = to_wide(r"SYSTEM\CurrentControlSet\Control\Session Manager");
    let mut hkey = HKEY::default();
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sm_key_w.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if res == ERROR_SUCCESS {
        let _guard = RegKeyGuard(hkey);
        let val_name_w = to_wide("PendingFileRenameOperations");
        let mut val_type = REG_VALUE_TYPE(0);
        let mut size = 0u32;
        let q_res = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(val_name_w.as_ptr()),
                None,
                Some(&mut val_type),
                None,
                Some(&mut size),
            )
        };
        if q_res == ERROR_SUCCESS && size > 2 && val_type == REG_MULTI_SZ {
            let mut buf = vec![0u8; size as usize];
            let q2_res = unsafe {
                RegQueryValueExW(
                    hkey,
                    PCWSTR(val_name_w.as_ptr()),
                    None,
                    Some(&mut val_type),
                    Some(buf.as_mut_ptr()),
                    Some(&mut size),
                )
            };
            if q2_res == ERROR_SUCCESS && has_pending_file_renames(&buf[..size as usize]) {
                return Some("PendingFileRenameOperations".to_string());
            }
        }
    }

    None
}

/// Queries current power status returning `(on_ac_power, battery_pct_if_present)`.
///
/// Desktop systems without batteries cleanly map to `(true, None)`.
pub fn power_status() -> (bool, Option<u8>) {
    let mut sps = SYSTEM_POWER_STATUS::default();
    let ok = unsafe { GetSystemPowerStatus(&mut sps) };
    if ok.is_err() {
        return (true, None);
    }

    // BatteryFlag: bit 7 (128) = no system battery, 255 = unknown status
    // BatteryLifePercent: 255 = status unknown
    let no_battery = (sps.BatteryFlag & 128 != 0) || sps.BatteryLifePercent == 255;
    let on_ac = sps.ACLineStatus == 1 || sps.ACLineStatus == 255 || no_battery;
    let battery_pct = if no_battery {
        None
    } else {
        Some(sps.BatteryLifePercent)
    };

    (on_ac, battery_pct)
}

/// Identifies processes holding locks on the specified file or directory path.
pub fn find_locking_processes(path: &Path) -> Vec<String> {
    let mut session_handle = 0u32;
    let mut session_key = [0u16; CCH_RM_SESSION_KEY as usize + 1];

    let start_res =
        unsafe { RmStartSession(&mut session_handle, None, PWSTR(session_key.as_mut_ptr())) };
    if start_res != ERROR_SUCCESS {
        return Vec::new();
    }
    let _session_guard = RmSessionGuard(session_handle);

    let path_str = path.to_string_lossy();
    let path_w = to_wide(&path_str);
    let files = [PCWSTR(path_w.as_ptr())];

    let reg_res = unsafe { RmRegisterResources(session_handle, Some(&files), None, None) };
    if reg_res != ERROR_SUCCESS {
        return Vec::new();
    }

    let mut n_needed = 0u32;
    let mut n_proc_info = 0u32;
    let mut reboot_reasons = 0u32;
    let mut proc_info: Vec<RM_PROCESS_INFO> = Vec::new();

    // Call RmGetList in a loop to handle ERROR_MORE_DATA
    for _ in 0..4 {
        let (ptr, slice_opt) = if proc_info.is_empty() {
            (None, None)
        } else {
            (Some(proc_info.as_mut_ptr()), Some(proc_info.as_mut_slice()))
        };
        let _ = slice_opt;

        let res = unsafe {
            RmGetList(
                session_handle,
                &mut n_needed,
                &mut n_proc_info,
                ptr,
                &mut reboot_reasons,
            )
        };

        if res == ERROR_SUCCESS {
            break;
        } else if res == ERROR_MORE_DATA {
            proc_info.resize_with(n_needed as usize, RM_PROCESS_INFO::default);
            n_proc_info = n_needed;
        } else {
            return Vec::new();
        }
    }

    let mut lock_names = Vec::new();
    let mut seen = FxHashSet::default();

    for proc in proc_info.iter().take(n_proc_info as usize) {
        let len = proc
            .strAppName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(proc.strAppName.len());
        if len > 0 {
            let app_name = String::from_utf16_lossy(&proc.strAppName[..len]);
            let pid = proc.Process.dwProcessId;
            let formatted = if pid != 0 {
                format!("{app_name} (PID {pid})")
            } else {
                app_name
            };
            if seen.insert(formatted.clone()) {
                lock_names.push(formatted);
            }
        }
    }

    lock_names
}

/// Probes the full system preconditions.
pub fn probe_preconditions() -> SystemPreconditions {
    let elevated = crate::win::is_elevated();
    let running_proc_set = running_processes().unwrap_or_default();
    let servicing = servicing_busy(&running_proc_set);
    let (on_ac, bat_pct) = power_status();

    SystemPreconditions {
        elevated,
        running_processes: running_proc_set,
        servicing_reason: servicing,
        battery_pct: bat_pct,
        on_ac_power: on_ac,
    }
}

/// Applies runtime preconditions against a cleanup plan, moving ineligible rules to `plan.skipped`.
pub fn apply_preconditions(plan: &mut CleanPlan, pre: &SystemPreconditions, force_battery: bool) {
    let old_rules = std::mem::take(&mut plan.rules);
    let mut kept_rules = Vec::with_capacity(old_rules.len());

    for rule in old_rules {
        // 1. Elevation check
        if rule.requires_admin && !pre.elevated {
            plan.skipped.push(SkippedRule {
                rule_id: rule.rule_id,
                name: rule.name,
                reason: "requires elevation".to_string(),
            });
            continue;
        }

        // 2. Process check
        let mut blocked_proc = None;
        for p in &rule.preconditions.process_not_running {
            let p_lower = p.to_lowercase();
            if pre.running_processes.contains(&p_lower) {
                blocked_proc = Some(p.clone());
                break;
            }
        }
        if let Some(p) = blocked_proc {
            plan.skipped.push(SkippedRule {
                rule_id: rule.rule_id,
                name: rule.name,
                reason: format!("process running: {p}"),
            });
            continue;
        }

        // 3. Servicing check
        if let (true, Some(reason)) = (rule.preconditions.check_servicing, &pre.servicing_reason) {
            plan.skipped.push(SkippedRule {
                rule_id: rule.rule_id,
                name: rule.name,
                reason: format!("Windows servicing / reboot pending: {reason}"),
            });
            continue;
        }

        // 4. Battery check
        let low_battery =
            !force_battery && !pre.on_ac_power && matches!(pre.battery_pct, Some(pct) if pct < 30);

        let is_heavy = matches!(
            rule.method,
            RuleMethod::OsHandler { .. } | RuleMethod::Command { .. }
        ) || rule.est_bytes > 100 * 1024 * 1024;

        if low_battery && is_heavy {
            plan.skipped.push(SkippedRule {
                rule_id: rule.rule_id,
                name: rule.name,
                reason: "on low battery (<30%)".to_string(),
            });
            continue;
        }

        kept_rules.push(rule);
    }

    plan.total_est_bytes = kept_rules
        .iter()
        .map(|r| r.os_handler_bytes.unwrap_or(r.est_bytes))
        .sum();
    plan.rules = kept_rules;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::PlannedRule;
    use crate::clean::rules::{PreconditionRule, RuleTier};
    use crate::scan::ScanMethod;

    #[test]
    fn enumerates_current_process() {
        let procs = running_processes().expect("must enumerate processes");
        assert!(!procs.is_empty(), "process list should not be empty");

        let current_exe = std::env::current_exe().expect("must get current exe path");
        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .expect("must get exe file name")
            .to_lowercase();

        assert!(
            procs.contains(&exe_name),
            "running_processes must include current test binary '{exe_name}', got: {procs:?}"
        );
    }

    #[test]
    fn power_status_does_not_fail() {
        let (on_ac, battery_pct) = power_status();
        // Smoke check: on AC or battery present, no panic or invalid state
        if let Some(pct) = battery_pct {
            assert!(pct <= 100, "battery percent must be <= 100, got {pct}");
        }
        let _ = on_ac;
    }

    #[test]
    fn pending_file_rename_operations_parser() {
        // Empty bytes
        assert!(!has_pending_file_renames(&[]));
        // Only 2 null bytes (\0)
        assert!(!has_pending_file_renames(&[0, 0]));
        // Double null (\0\0) in UTF-16
        assert!(!has_pending_file_renames(&[0, 0, 0, 0]));

        // Valid non-empty REG_MULTI_SZ: "C:\\foo\0\0"
        let sample: Vec<u16> = "C:\\foo"
            .encode_utf16()
            .chain(core::iter::once(0))
            .chain(core::iter::once(0))
            .collect();
        let bytes: Vec<u8> = sample.iter().flat_map(|&u| u.to_ne_bytes()).collect();
        assert!(has_pending_file_renames(&bytes));
    }

    #[test]
    fn find_locking_processes_smoke() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let closed_file = temp_dir.path().join("unlocked.txt");
        std::fs::write(&closed_file, b"unlocked").expect("write file");

        // Closed file should have 0 locking processes
        let lockers = find_locking_processes(&closed_file);
        assert!(
            lockers.is_empty(),
            "expected 0 lockers on closed file, got {lockers:?}"
        );

        // NamedTempFile keeps an open handle, so Restart Manager should detect current test runner locking it
        let open_temp = tempfile::NamedTempFile::new().expect("temp file");
        let open_lockers = find_locking_processes(open_temp.path());
        assert!(
            open_lockers
                .iter()
                .any(|l| l.to_lowercase().contains("dsk_core")),
            "expected current test process to lock open temp file, got {open_lockers:?}"
        );
    }

    #[test]
    fn apply_preconditions_filters_elevation_process_servicing_and_battery() {
        let mut running = FxHashSet::default();
        running.insert("chrome.exe".to_string());

        let pre = SystemPreconditions {
            elevated: false,
            running_processes: running,
            servicing_reason: Some("CBS RebootPending".to_string()),
            battery_pct: Some(20),
            on_ac_power: false,
        };

        let mut plan = CleanPlan {
            version: 1,
            scanned_path: r"C:\".to_string(),
            volume_root: r"C:\".to_string(),
            scan_method: ScanMethod::Mft,
            total_est_bytes: 500 * 1024 * 1024,
            rules: vec![
                // Rule 1: Requires admin (should fail elevation)
                PlannedRule {
                    rule_id: "rule.admin".into(),
                    name: "Admin Rule".into(),
                    category: "sys".into(),
                    tier: RuleTier::Safe,
                    regenerable: true,
                    requires_admin: true,
                    method: RuleMethod::DeleteContents,
                    preconditions: PreconditionRule::default(),
                    explain: "test".into(),
                    est_bytes: 10 * 1024 * 1024,
                    item_count: 1,
                    roots: vec![],
                    os_handler_bytes: None,
                    estimate: Default::default(),
                },
                // Rule 2: Requires chrome not running (should fail process)
                PlannedRule {
                    rule_id: "rule.chrome".into(),
                    name: "Chrome Rule".into(),
                    category: "browsers".into(),
                    tier: RuleTier::Safe,
                    regenerable: true,
                    requires_admin: false,
                    method: RuleMethod::DeleteContents,
                    preconditions: PreconditionRule {
                        process_not_running: vec!["chrome.exe".into()],
                        check_servicing: false,
                        exclude_names: vec![],
                    },
                    explain: "test".into(),
                    est_bytes: 20 * 1024 * 1024,
                    item_count: 1,
                    roots: vec![],
                    os_handler_bytes: None,
                    estimate: Default::default(),
                },
                // Rule 3: Checks servicing (should fail servicing)
                PlannedRule {
                    rule_id: "rule.servicing".into(),
                    name: "Servicing Rule".into(),
                    category: "sys".into(),
                    tier: RuleTier::Safe,
                    regenerable: true,
                    requires_admin: false,
                    method: RuleMethod::DeleteContents,
                    preconditions: PreconditionRule {
                        process_not_running: vec![],
                        check_servicing: true,
                        exclude_names: vec![],
                    },
                    explain: "test".into(),
                    est_bytes: 30 * 1024 * 1024,
                    item_count: 1,
                    roots: vec![],
                    os_handler_bytes: None,
                    estimate: Default::default(),
                },
                // Rule 4: Heavy rule on battery (OsHandler or est_bytes > 100MB, should fail battery)
                PlannedRule {
                    rule_id: "rule.battery".into(),
                    name: "Battery Heavy Rule".into(),
                    category: "sys".into(),
                    tier: RuleTier::Safe,
                    regenerable: true,
                    requires_admin: false,
                    method: RuleMethod::OsHandler {
                        handler_key: "test_handler".into(),
                    },
                    preconditions: PreconditionRule::default(),
                    explain: "test".into(),
                    est_bytes: 0,
                    item_count: 0,
                    roots: vec![],
                    os_handler_bytes: Some(150 * 1024 * 1024),
                    estimate: Default::default(),
                },
                // Rule 5: Safe light rule that should pass!
                PlannedRule {
                    rule_id: "rule.pass".into(),
                    name: "Passing Rule".into(),
                    category: "apps".into(),
                    tier: RuleTier::Safe,
                    regenerable: true,
                    requires_admin: false,
                    method: RuleMethod::DeleteContents,
                    preconditions: PreconditionRule::default(),
                    explain: "test".into(),
                    est_bytes: 5 * 1024 * 1024,
                    item_count: 1,
                    roots: vec![],
                    os_handler_bytes: None,
                    estimate: Default::default(),
                },
            ],
            skipped: vec![],
        };

        apply_preconditions(&mut plan, &pre, false);

        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].rule_id, "rule.pass");
        assert_eq!(plan.total_est_bytes, 5 * 1024 * 1024);

        assert_eq!(plan.skipped.len(), 4);
        let skip_admin = plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "rule.admin")
            .unwrap();
        assert_eq!(skip_admin.reason, "requires elevation");

        let skip_proc = plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "rule.chrome")
            .unwrap();
        assert_eq!(skip_proc.reason, "process running: chrome.exe");

        let skip_serv = plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "rule.servicing")
            .unwrap();
        assert_eq!(
            skip_serv.reason,
            "Windows servicing / reboot pending: CBS RebootPending"
        );

        let skip_bat = plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "rule.battery")
            .unwrap();
        assert_eq!(skip_bat.reason, "on low battery (<30%)");

        // Test force_battery = true
        let mut plan2 = CleanPlan {
            version: 1,
            scanned_path: r"C:\".to_string(),
            volume_root: r"C:\".to_string(),
            scan_method: ScanMethod::Mft,
            total_est_bytes: 150 * 1024 * 1024,
            rules: vec![PlannedRule {
                rule_id: "rule.battery".into(),
                name: "Battery Heavy Rule".into(),
                category: "sys".into(),
                tier: RuleTier::Safe,
                regenerable: true,
                requires_admin: false,
                method: RuleMethod::OsHandler {
                    handler_key: "test_handler".into(),
                },
                preconditions: PreconditionRule::default(),
                explain: "test".into(),
                est_bytes: 0,
                item_count: 0,
                roots: vec![],
                os_handler_bytes: Some(150 * 1024 * 1024),
                estimate: Default::default(),
            }],
            skipped: vec![],
        };
        apply_preconditions(&mut plan2, &pre, true);
        assert_eq!(plan2.rules.len(), 1);
        assert_eq!(plan2.rules[0].rule_id, "rule.battery");
        assert_eq!(plan2.total_est_bytes, 150 * 1024 * 1024);
        assert!(plan2.skipped.is_empty());
    }

    #[test]
    fn probe_preconditions_smoke() {
        let pre = probe_preconditions();
        // Running processes should contain current exe
        assert!(!pre.running_processes.is_empty());
    }
}
