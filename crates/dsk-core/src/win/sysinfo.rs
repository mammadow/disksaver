//! Memory, pagefile, crash-dump, and hibernation facts for the sizing advisor (P9.5).
//!
//! Reads are unelevated. The only write is [`write_paging_files`], which needs administrator
//! rights and is reached solely through the validated `OptimizerIntent::SetPagefile*` intents.

#![allow(unsafe_code)]

use serde::{Deserialize, Serialize};
use windows::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_MULTI_SZ, REG_VALUE_TYPE,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::core::PCWSTR;

use crate::error::{DskError, Result};
use crate::win::prefetch::{RegKeyGuard, open_reg_key_read, read_reg_dword, to_wide};

const MEMORY_MANAGEMENT_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
const CRASH_CONTROL_KEY: &str = r"SYSTEM\CurrentControlSet\Control\CrashControl";
const POWER_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Power";

/// System-wide memory commit figures from `GetPerformanceInfo`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryFacts {
    pub physical_bytes: u64,
    /// Current commit limit (RAM + all pagefiles).
    pub commit_limit_bytes: u64,
    /// Highest commit charge since boot.
    pub commit_peak_bytes: u64,
    pub commit_total_bytes: u64,
}

/// Reads commit and physical memory totals. `None` if the call fails.
pub fn memory_facts() -> Option<MemoryFacts> {
    let mut info = PERFORMANCE_INFORMATION {
        cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a properly sized, writable PERFORMANCE_INFORMATION with `cb` set.
    unsafe { GetPerformanceInfo(&mut info, info.cb) }.ok()?;
    let page = info.PageSize as u64;
    Some(MemoryFacts {
        physical_bytes: (info.PhysicalTotal as u64).saturating_mul(page),
        commit_limit_bytes: (info.CommitLimit as u64).saturating_mul(page),
        commit_peak_bytes: (info.CommitPeak as u64).saturating_mul(page),
        commit_total_bytes: (info.CommitTotal as u64).saturating_mul(page),
    })
}

fn read_reg_multi_sz(hkey: HKEY, name: &str) -> Option<Vec<String>> {
    let name_w = to_wide(name);
    let mut val_type = REG_VALUE_TYPE(0);
    let mut byte_len = 0u32;
    // SAFETY: Size query of a named value under an open key.
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut val_type),
            None,
            Some(&mut byte_len),
        )
    };
    if res.0 != 0 || val_type != REG_MULTI_SZ || byte_len > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; byte_len as usize];
    // SAFETY: `buf` holds exactly `byte_len` bytes from the size query above.
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut val_type),
            Some(buf.as_mut_ptr()),
            Some(&mut byte_len),
        )
    };
    if res.0 != 0 {
        return None;
    }
    let words: Vec<u16> = buf[..(byte_len as usize).min(buf.len())]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .collect();
    Some(parse_multi_sz(&words))
}

/// Splits a REG_MULTI_SZ UTF-16 buffer into its non-empty strings.
pub fn parse_multi_sz(words: &[u16]) -> Vec<String> {
    words
        .split(|&w| w == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf16_lossy(s).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Raw `PagingFiles` entries (e.g. `?:\pagefile.sys`, `C:\pagefile.sys 4096 8192`).
pub fn read_paging_files() -> Option<Vec<String>> {
    let key = open_reg_key_read(HKEY_LOCAL_MACHINE, MEMORY_MANAGEMENT_KEY)?;
    read_reg_multi_sz(key.0, "PagingFiles")
}

/// `CrashControl\CrashDumpEnabled` (0 none, 1 complete, 2 kernel, 3 small, 7 automatic).
pub fn crash_dump_mode() -> Option<u32> {
    let key = open_reg_key_read(HKEY_LOCAL_MACHINE, CRASH_CONTROL_KEY)?;
    read_reg_dword(key.0, "CrashDumpEnabled")
}

/// `Power\HiberFileType` (1 reduced, 2 full) and `Power\HibernateEnabled`.
pub fn hibernation_facts() -> (Option<u32>, Option<bool>) {
    let Some(key) = open_reg_key_read(HKEY_LOCAL_MACHINE, POWER_KEY) else {
        return (None, None);
    };
    (
        read_reg_dword(key.0, "HiberFileType"),
        read_reg_dword(key.0, "HibernateEnabled").map(|v| v != 0),
    )
}

/// Encodes strings as a REG_MULTI_SZ byte buffer (each string NUL-terminated, plus a final NUL).
pub fn encode_multi_sz(entries: &[String]) -> Vec<u8> {
    let mut words: Vec<u16> = Vec::new();
    for e in entries {
        words.extend(e.encode_utf16());
        words.push(0);
    }
    words.push(0);
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Replaces `PagingFiles`. Administrator rights required; takes effect after a reboot.
///
/// Callers must pass entries built by `optimize::sizing::paging_files_value` from validated
/// scalars, never caller-supplied strings.
pub fn write_paging_files(entries: &[String]) -> Result<()> {
    let path_w = to_wide(MEMORY_MANAGEMENT_KEY);
    let mut key = HKEY::default();
    // SAFETY: Opening a fixed HKLM key for value writes; `path_w` is NUL-terminated.
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_w.as_ptr()),
            None,
            KEY_SET_VALUE | KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if res.0 != 0 {
        return Err(DskError::Win32 {
            ctx: "RegOpenKeyExW(Memory Management)",
            code: res.0,
        });
    }
    let guard = RegKeyGuard(key);
    let data = encode_multi_sz(entries);
    let name_w = to_wide("PagingFiles");
    // SAFETY: Writing a REG_MULTI_SZ value from an owned, correctly terminated buffer.
    let res = unsafe {
        RegSetValueExW(
            guard.0,
            PCWSTR(name_w.as_ptr()),
            None,
            REG_MULTI_SZ,
            Some(&data),
        )
    };
    if res.0 != 0 {
        return Err(DskError::Win32 {
            ctx: "RegSetValueExW(PagingFiles)",
            code: res.0,
        });
    }
    Ok(())
}

/// `true` when the machine runs on battery, `false` on AC power, `None` when unknown (desktops
/// without a battery report AC). Long background work (video re-encoding) pauses on battery.
pub fn on_battery() -> Option<bool> {
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    let mut status = SYSTEM_POWER_STATUS::default();
    // SAFETY: `status` is a valid, writable SYSTEM_POWER_STATUS for the duration of the call.
    unsafe { GetSystemPowerStatus(&mut status) }.ok()?;
    match status.ACLineStatus {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

/// `true` while a full-screen Direct3D app (a game) or presentation mode is in the foreground,
/// so GPU-heavy background work can wait instead of stealing frames.
pub fn fullscreen_app_running() -> bool {
    use windows::Win32::UI::Shell::{
        QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN,
        SHQueryUserNotificationState,
    };
    // SAFETY: SHQueryUserNotificationState only writes the returned enum value.
    match unsafe { SHQueryUserNotificationState() } {
        Ok(state) => {
            state == QUNS_RUNNING_D3D_FULL_SCREEN
                || state == QUNS_BUSY
                || state == QUNS_PRESENTATION_MODE
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_sz_roundtrip() {
        let entries = vec![
            r"C:\pagefile.sys 4096 8192".to_string(),
            r"D:\pagefile.sys 0 0".into(),
        ];
        let bytes = encode_multi_sz(&entries);
        let words: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        assert_eq!(parse_multi_sz(&words), entries);
        assert!(parse_multi_sz(&[0, 0]).is_empty());
    }

    #[test]
    fn live_reads_never_panic_and_are_plausible() {
        if let Some(m) = memory_facts() {
            assert!(m.physical_bytes > 0);
            assert!(m.commit_limit_bytes >= m.commit_total_bytes);
        }
        let _ = read_paging_files();
        let _ = crash_dump_mode();
        let _ = hibernation_facts();
        let _ = on_battery();
        let _ = fullscreen_app_running();
    }
}
