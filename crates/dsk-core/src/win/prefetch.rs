//! Win32 installed program manifests, UserAssist ROT13 registry usage, BAM execution
//! history, and `MAM\x04` compressed Prefetch (`.pf`) reader via `ntdll!RtlDecompressBufferEx`.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_BINARY, REG_DWORD, REG_EXPAND_SZ,
    REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    RegQueryValueExW,
};
use windows::core::{PCSTR, PCWSTR, PWSTR};

use crate::error::{DskError, Result};
use crate::win::volume::system32_dir;

pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

pub(crate) struct RegKeyGuard(pub(crate) HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: RegKeyGuard owns an open HKEY acquired via RegOpenKeyExW.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

struct LibraryGuard(HMODULE);

impl Drop for LibraryGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: LibraryGuard owns an HMODULE acquired via LoadLibraryW.
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}

/// Origin registry source for an installed Windows application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstalledAppSource {
    Win32Uninstall,
    AppXPackage,
}

/// Metadata for an installed Win32 or AppX application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledAppRecord {
    pub name: String,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    pub source: InstalledAppSource,
    /// `SystemComponent = 1`: a component hidden from Settings > Apps (e.g. each of the ~45 MSI
    /// parts of the CUDA toolkit). Still evidence that the software is installed.
    #[serde(default)]
    pub system_component: bool,
}

/// Decoded UserAssist entry (Explorer GUI launch tracker, §9.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAssistEntry {
    pub decoded_name: String,
    pub run_count: u32,
    pub last_exec_filetime: u64,
}

/// Background Activity Moderator (BAM) execution timestamp record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BamEntry {
    pub exe_path: String,
    pub last_exec_filetime: u64,
}

/// Parsed summary of a Windows `.pf` Prefetch trace file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefetchRecord {
    pub exe_name: String,
    pub format_version: u32,
    pub run_count: u32,
    pub last_run_filetime: u64,
    pub pf_path: Option<PathBuf>,
}

/// Decodes an ASCII ROT13 string (used by Windows Explorer UserAssist value names).
pub fn rot13_decode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect()
}

pub(crate) fn read_reg_string(hkey: HKEY, name: &str) -> Option<String> {
    let name_w = to_wide(name);
    let mut val_type = REG_VALUE_TYPE(0);
    let mut byte_len = 0u32;
    // SAFETY: Querying byte size of named registry value under open HKEY.
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
    if res.0 != 0 || byte_len == 0 || (val_type != REG_SZ && val_type != REG_EXPAND_SZ) {
        return None;
    }

    let mut buf = vec![0u8; byte_len as usize];
    // SAFETY: Buffer has capacity matching byte_len from previous query.
    let res2 = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut val_type),
            Some(buf.as_mut_ptr()),
            Some(&mut byte_len),
        )
    };
    if res2.0 != 0 {
        return None;
    }

    let u16_words: Vec<u16> = buf[..(byte_len as usize).min(buf.len())]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&w| w != 0)
        .collect();
    let s = String::from_utf16_lossy(&u16_words).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

pub(crate) fn read_reg_dword(hkey: HKEY, name: &str) -> Option<u32> {
    let name_w = to_wide(name);
    let mut val_type = REG_VALUE_TYPE(0);
    let mut data = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: Stack DWORD buffer with explicit size; `name_w` is null-terminated.
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut val_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        )
    };
    (res.0 == 0 && val_type == REG_DWORD && size == size_of::<u32>() as u32).then_some(data)
}

/// Opens `hive\subkey_path` read-only.
pub(crate) fn open_reg_key_read(hive: HKEY, subkey_path: &str) -> Option<RegKeyGuard> {
    let path_w = to_wide(subkey_path);
    let mut key = HKEY::default();
    // SAFETY: Read-only open of a registry key; `path_w` is null-terminated.
    let res = unsafe { RegOpenKeyExW(hive, PCWSTR(path_w.as_ptr()), None, KEY_READ, &mut key) };
    (res.0 == 0).then_some(RegKeyGuard(key))
}

pub(crate) fn enum_subkey_names(hkey: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    let mut idx = 0u32;
    loop {
        let mut buf = [0u16; 512];
        let mut len = buf.len() as u32;
        // SAFETY: buf is valid writable UTF-16 buffer for RegEnumKeyExW.
        let res = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if res.0 != 0 {
            break;
        }
        names.push(String::from_utf16_lossy(&buf[..len as usize]));
        idx += 1;
    }
    names
}

fn collect_uninstall_apps_from_hive(
    hive: HKEY,
    subkey_path: &str,
    out: &mut Vec<InstalledAppRecord>,
) {
    let path_w = to_wide(subkey_path);
    let mut root_key = HKEY::default();
    // SAFETY: Opening standard Uninstall registry container read-only.
    let res =
        unsafe { RegOpenKeyExW(hive, PCWSTR(path_w.as_ptr()), None, KEY_READ, &mut root_key) };
    if res.0 != 0 {
        return;
    }
    let _guard = RegKeyGuard(root_key);

    for child_name in enum_subkey_names(root_key) {
        let child_w = to_wide(&child_name);
        let mut child_key = HKEY::default();
        // SAFETY: Opening enumerated uninstall child subkey read-only.
        let c_res = unsafe {
            RegOpenKeyExW(
                root_key,
                PCWSTR(child_w.as_ptr()),
                None,
                KEY_READ,
                &mut child_key,
            )
        };
        if c_res.0 != 0 {
            continue;
        }
        let _c_guard = RegKeyGuard(child_key);

        let Some(display_name) = read_reg_string(child_key, "DisplayName") else {
            continue;
        };
        let publisher = read_reg_string(child_key, "Publisher");
        let install_location = read_reg_string(child_key, "InstallLocation")
            .map(|p| PathBuf::from(p.trim_matches('"')))
            .or_else(|| {
                read_reg_string(child_key, "DisplayIcon").and_then(|icon| {
                    let clean = icon
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_matches('"');
                    Path::new(clean).parent().map(Path::to_path_buf)
                })
            });

        out.push(InstalledAppRecord {
            name: display_name,
            publisher,
            install_location,
            source: InstalledAppSource::Win32Uninstall,
            system_component: read_reg_dword(child_key, "SystemComponent") == Some(1),
        });
    }
}

fn collect_appx_packages(out: &mut Vec<InstalledAppRecord>) {
    let path_w = to_wide(
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
    );
    let mut root_key = HKEY::default();
    // SAFETY: Opening HKCU AppModel Repository Packages registry key read-only.
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path_w.as_ptr()),
            None,
            KEY_READ,
            &mut root_key,
        )
    };
    if res.0 != 0 {
        return;
    }
    let _guard = RegKeyGuard(root_key);

    for pkg_name in enum_subkey_names(root_key) {
        let pkg_w = to_wide(&pkg_name);
        let mut pkg_key = HKEY::default();
        // SAFETY: Opening AppX package entry read-only.
        let p_res = unsafe {
            RegOpenKeyExW(
                root_key,
                PCWSTR(pkg_w.as_ptr()),
                None,
                KEY_READ,
                &mut pkg_key,
            )
        };
        if p_res.0 != 0 {
            continue;
        }
        let _p_guard = RegKeyGuard(pkg_key);

        let display = read_reg_string(pkg_key, "DisplayName")
            .unwrap_or_else(|| pkg_name.split('_').next().unwrap_or(&pkg_name).to_string());
        let root_folder = read_reg_string(pkg_key, "PackageRootFolder").map(PathBuf::from);
        out.push(InstalledAppRecord {
            name: display,
            publisher: None,
            install_location: root_folder,
            source: InstalledAppSource::AppXPackage,
            system_component: false,
        });
    }
}

/// Enumerates installed Win32 programs (HKLM/HKCU Uninstall + Wow6432Node) and AppX packages.
pub fn enumerate_installed_apps() -> Vec<InstalledAppRecord> {
    let mut apps = Vec::new();
    collect_uninstall_apps_from_hive(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        &mut apps,
    );
    collect_uninstall_apps_from_hive(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        &mut apps,
    );
    collect_uninstall_apps_from_hive(
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        &mut apps,
    );
    collect_appx_packages(&mut apps);
    apps
}

/// Parses a single `UserAssist` registry binary count record (`len >= 68`).
pub fn parse_user_assist_record(encoded_name: &str, blob: &[u8]) -> Option<UserAssistEntry> {
    if blob.len() < 68 {
        return None;
    }
    let run_count = u32::from_le_bytes(blob[4..8].try_into().ok()?);
    let last_exec_filetime = u64::from_le_bytes(blob[60..68].try_into().ok()?);
    Some(UserAssistEntry {
        decoded_name: rot13_decode(encoded_name),
        run_count,
        last_exec_filetime,
    })
}

/// Reads decoded Explorer `UserAssist` program launch counts and timestamps from `HKCU`.
pub fn read_user_assist_entries() -> Vec<UserAssistEntry> {
    let mut out = Vec::new();
    let root_w = to_wide(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
    let mut root_key = HKEY::default();
    // SAFETY: Opening HKCU UserAssist root read-only.
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(root_w.as_ptr()),
            None,
            KEY_READ,
            &mut root_key,
        )
    };
    if res.0 != 0 {
        return out;
    }
    let _guard = RegKeyGuard(root_key);

    for guid in enum_subkey_names(root_key) {
        let count_sub = to_wide(&format!(r"{guid}\Count"));
        let mut count_key = HKEY::default();
        // SAFETY: Opening Count subkey under UserAssist GUID read-only.
        let c_res = unsafe {
            RegOpenKeyExW(
                root_key,
                PCWSTR(count_sub.as_ptr()),
                None,
                KEY_READ,
                &mut count_key,
            )
        };
        if c_res.0 != 0 {
            continue;
        }
        let _c_guard = RegKeyGuard(count_key);

        let mut idx = 0u32;
        loop {
            let mut name_buf = [0u16; 1024];
            let mut name_len = name_buf.len() as u32;
            let mut val_type = 0u32;
            let mut data_buf = [0u8; 128];
            let mut data_len = data_buf.len() as u32;
            // SAFETY: Enumerating binary values under UserAssist Count key into stack buffers.
            let e_res = unsafe {
                RegEnumValueW(
                    count_key,
                    idx,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut val_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            // ERROR_MORE_DATA (234): an oversized value such as `UEME_CTLSESSION` (~1.6 KB). Skip it
            // instead of ending the enumeration and losing every later entry.
            if e_res.0 == 234 {
                idx += 1;
                continue;
            }
            if e_res.0 != 0 {
                break;
            }
            if val_type == REG_BINARY.0 {
                let encoded = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                if let Some(entry) =
                    parse_user_assist_record(&encoded, &data_buf[..(data_len as usize).min(128)])
                {
                    out.push(entry);
                }
            }
            idx += 1;
        }
    }

    out
}

/// Reads Background Activity Moderator (`BAM`) timestamps from `HKLM` if accessible.
pub fn read_bam_entries() -> Vec<BamEntry> {
    let mut out = Vec::new();
    let root_w = to_wide(r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings");
    let mut root_key = HKEY::default();
    // SAFETY: Opening HKLM BAM state key read-only; safely returns empty when restricted.
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(root_w.as_ptr()),
            None,
            KEY_READ,
            &mut root_key,
        )
    };
    if res.0 != 0 {
        return out;
    }
    let _guard = RegKeyGuard(root_key);

    for sid in enum_subkey_names(root_key) {
        let sid_w = to_wide(&sid);
        let mut sid_key = HKEY::default();
        // SAFETY: Opening per-SID BAM subkey read-only.
        let s_res = unsafe {
            RegOpenKeyExW(
                root_key,
                PCWSTR(sid_w.as_ptr()),
                None,
                KEY_READ,
                &mut sid_key,
            )
        };
        if s_res.0 != 0 {
            continue;
        }
        let _s_guard = RegKeyGuard(sid_key);

        let mut idx = 0u32;
        loop {
            let mut name_buf = [0u16; 1024];
            let mut name_len = name_buf.len() as u32;
            let mut val_type = 0u32;
            let mut data_buf = [0u8; 64];
            let mut data_len = data_buf.len() as u32;
            // SAFETY: Enumerating BAM binary values containing 64-bit FILETIME.
            let e_res = unsafe {
                RegEnumValueW(
                    sid_key,
                    idx,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut val_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            if e_res.0 == 234 {
                // ERROR_MORE_DATA: unexpected oversized value; skip it and keep enumerating.
                idx += 1;
                continue;
            }
            if e_res.0 != 0 {
                break;
            }
            if val_type == REG_BINARY.0 && data_len >= 8 {
                let exe_path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                if let Ok(arr) = data_buf[0..8].try_into() {
                    out.push(BamEntry {
                        exe_path,
                        last_exec_filetime: u64::from_le_bytes(arr),
                    });
                }
            }
            idx += 1;
        }
    }

    out
}

/// Decompresses a Windows 10/11 `MAM\x04` compressed Prefetch blob via `ntdll!RtlDecompressBufferEx`
/// (`COMPRESSION_FORMAT_XPRESS_HUFF = 4`), or returns raw bytes when already uncompressed (`SCCA`).
pub fn decompress_prefetch_mam(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() >= 8 && &raw[4..8] == b"SCCA" {
        return Ok(raw.to_vec());
    }

    if raw.len() < 12 || &raw[0..3] != b"MAM" {
        return Err(DskError::Optimize(
            "invalid prefetch header (expected MAM or SCCA)".to_string(),
        ));
    }

    let compression_format = (raw[3] & 0x0F) as u16;
    if compression_format == 0 {
        return Err(DskError::Optimize(
            "unsupported MAM compression format 0".to_string(),
        ));
    }

    let uncompressed_size = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    const MAX_PREFETCH_BYTES: u32 = 32 * 1024 * 1024;
    if uncompressed_size == 0 || uncompressed_size > MAX_PREFETCH_BYTES {
        return Err(DskError::Optimize(format!(
            "implausible MAM uncompressed prefetch size: {uncompressed_size}"
        )));
    }

    let ntdll_path = system32_dir().join("ntdll.dll");
    let ntdll_w = to_wide(&ntdll_path.to_string_lossy());
    // SAFETY: Loading pinned System32\ntdll.dll via LoadLibraryW; freed via LibraryGuard on Drop.
    let hmod = unsafe { LoadLibraryW(PCWSTR(ntdll_w.as_ptr())) }.map_err(|e| DskError::Win32 {
        ctx: "LoadLibraryW(ntdll.dll)",
        code: (e.code().0 as u32) & 0xFFFF,
    })?;
    let _lib_guard = LibraryGuard(hmod);

    type FnRtlGetCompressionWorkSpaceSize =
        unsafe extern "system" fn(u16, *mut u32, *mut u32) -> i32;
    type FnRtlDecompressBufferEx =
        unsafe extern "system" fn(u16, *mut u8, u32, *const u8, u32, *mut u32, *mut c_void) -> i32;

    // SAFETY: Querying standard exported RtlGetCompressionWorkSpaceSize & RtlDecompressBufferEx symbols.
    let get_ws_addr = unsafe {
        GetProcAddress(
            hmod,
            PCSTR(c"RtlGetCompressionWorkSpaceSize".as_ptr() as *const u8),
        )
    };
    let decomp_addr =
        unsafe { GetProcAddress(hmod, PCSTR(c"RtlDecompressBufferEx".as_ptr() as *const u8)) };

    let (Some(get_ws_fn), Some(decomp_fn)) = (get_ws_addr, decomp_addr) else {
        return Err(DskError::Unsupported(
            "ntdll decompression APIs unavailable".to_string(),
        ));
    };

    // SAFETY: Transmuting ntdll function pointers retrieved from GetProcAddress to exact Win32 ABI types.
    let rtl_get_ws: FnRtlGetCompressionWorkSpaceSize = unsafe { std::mem::transmute(get_ws_fn) };
    let rtl_decomp_ex: FnRtlDecompressBufferEx = unsafe { std::mem::transmute(decomp_fn) };

    let mut comp_ws = 0u32;
    let mut frag_ws = 0u32;
    // SAFETY: Querying required workspace size for compression_format.
    let ws_status = unsafe { rtl_get_ws(compression_format, &mut comp_ws, &mut frag_ws) };
    if ws_status < 0 {
        return Err(DskError::Optimize(format!(
            "RtlGetCompressionWorkSpaceSize failed: NTSTATUS={ws_status:#X}"
        )));
    }

    let mut workspace = vec![0u8; frag_ws.max(1) as usize];
    let mut output = vec![0u8; uncompressed_size as usize];
    let mut final_size = 0u32;
    let payload = &raw[8..];

    // SAFETY: output and workspace buffers match queried sizes; payload is valid compressed slice.
    let dec_status = unsafe {
        rtl_decomp_ex(
            compression_format,
            output.as_mut_ptr(),
            uncompressed_size,
            payload.as_ptr(),
            payload.len() as u32,
            &mut final_size,
            workspace.as_mut_ptr() as *mut c_void,
        )
    };
    if dec_status < 0 {
        return Err(DskError::Optimize(format!(
            "RtlDecompressBufferEx failed: NTSTATUS={dec_status:#X}"
        )));
    }

    output.truncate((final_size as usize).min(output.len()));
    Ok(output)
}

/// Parses either compressed (`MAM\x04`) or uncompressed (`SCCA`) Windows Prefetch file bytes
/// cleanly with strict bounds checks.
pub fn parse_prefetch_bytes(raw: &[u8]) -> Result<PrefetchRecord> {
    let data = decompress_prefetch_mam(raw)?;
    if data.len() < 84 || &data[4..8] != b"SCCA" {
        return Err(DskError::Optimize(
            "invalid decompressed prefetch payload (missing SCCA header)".to_string(),
        ));
    }

    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let name_words: Vec<u16> = data[16..76]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&w| w != 0)
        .collect();
    let exe_name = String::from_utf16_lossy(&name_words);

    let (last_run_offset, run_count_offset) = match version {
        17 => (120usize, 144usize),
        23 => (128usize, 152usize),
        26 => (128usize, 200usize),
        30 | 31 => (128usize, 208usize),
        _ => (128usize, 208usize),
    };

    let last_run_filetime = data
        .get(last_run_offset..last_run_offset + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);

    let run_count = data
        .get(run_count_offset..run_count_offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);

    Ok(PrefetchRecord {
        exe_name,
        format_version: version,
        run_count,
        last_run_filetime,
        pf_path: None,
    })
}

/// Best-effort scan of `C:\Windows\Prefetch\*.pf` (returns readable `.pf` records; empty if
/// restricted or disabled).
pub fn scan_windows_prefetch() -> Vec<PrefetchRecord> {
    let Some(win_dir) = system32_dir().parent().map(Path::to_path_buf) else {
        return Vec::new();
    };
    let pf_dir = win_dir.join("Prefetch");
    let Ok(entries) = std::fs::read_dir(pf_dir) else {
        return Vec::new();
    };

    let mut records = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        let is_pf = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("pf"))
            .unwrap_or(false);
        if !is_pf {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&p)
            && let Ok(mut rec) = parse_prefetch_bytes(&bytes)
        {
            rec.pf_path = Some(p);
            records.push(rec);
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_and_user_assist_and_prefetch_scca_parsing_work_safely() {
        assert_eq!(
            rot13_decode("P:\\Cebtenz Svyrf\\Ncc.rkr"),
            "C:\\Program Files\\App.exe"
        );

        let mut ua_blob = vec![0u8; 72];
        ua_blob[4..8].copy_from_slice(&42u32.to_le_bytes());
        ua_blob[60..68].copy_from_slice(&133_500_000_000_000_000u64.to_le_bytes());
        let parsed = parse_user_assist_record("Grfg.rkr", &ua_blob).unwrap();
        assert_eq!(parsed.decoded_name, "Test.exe");
        assert_eq!(parsed.run_count, 42);
        assert_eq!(parsed.last_exec_filetime, 133_500_000_000_000_000);
        assert!(parse_user_assist_record("short", &[0u8; 16]).is_none());

        // Synthetic uncompressed v30 SCCA buffer
        let mut scca = vec![0u8; 256];
        scca[0..4].copy_from_slice(&30u32.to_le_bytes());
        scca[4..8].copy_from_slice(b"SCCA");
        let name_u16: Vec<u16> = "CARGO.EXE\0".encode_utf16().collect();
        for (i, w) in name_u16.iter().enumerate() {
            scca[16 + i * 2..18 + i * 2].copy_from_slice(&w.to_le_bytes());
        }
        scca[128..136].copy_from_slice(&133_600_000_000_000_000u64.to_le_bytes());
        scca[208..212].copy_from_slice(&17u32.to_le_bytes());
        let pf = parse_prefetch_bytes(&scca).unwrap();
        assert_eq!(pf.exe_name, "CARGO.EXE");
        assert_eq!(pf.format_version, 30);
        assert_eq!(pf.run_count, 17);
        assert_eq!(pf.last_run_filetime, 133_600_000_000_000_000);

        // Compress with ntdll!RtlCompressBuffer (LZNT1=2) or XPRESS and test decompress_prefetch_mam!
        let ntdll_path = system32_dir().join("ntdll.dll");
        let ntdll_w = to_wide(&ntdll_path.to_string_lossy());
        let hmod = unsafe { LoadLibraryW(PCWSTR(ntdll_w.as_ptr())) }.unwrap();
        let _lib = LibraryGuard(hmod);
        type FnRtlGetWs = unsafe extern "system" fn(u16, *mut u32, *mut u32) -> i32;
        type FnRtlCompressBuffer = unsafe extern "system" fn(
            u16,
            *const u8,
            u32,
            *mut u8,
            u32,
            u32,
            *mut u32,
            *mut c_void,
        ) -> i32;
        if let (Some(gws), Some(cmp)) = unsafe {
            (
                GetProcAddress(
                    hmod,
                    PCSTR(c"RtlGetCompressionWorkSpaceSize".as_ptr() as *const u8),
                ),
                GetProcAddress(hmod, PCSTR(c"RtlCompressBuffer".as_ptr() as *const u8)),
            )
        } {
            let rtl_ws: FnRtlGetWs = unsafe { std::mem::transmute(gws) };
            let rtl_cmp: FnRtlCompressBuffer = unsafe { std::mem::transmute(cmp) };
            let mut ws_cmp = 0u32;
            let mut ws_frag = 0u32;
            let fmt = 4u16; // COMPRESSION_FORMAT_XPRESS_HUFF
            if unsafe { rtl_ws(fmt, &mut ws_cmp, &mut ws_frag) } >= 0 {
                let mut ws = vec![0u8; ws_cmp.max(1) as usize];
                let mut compressed = vec![0u8; 1024];
                let mut final_cmp = 0u32;
                let st = unsafe {
                    rtl_cmp(
                        fmt,
                        scca.as_ptr(),
                        scca.len() as u32,
                        compressed.as_mut_ptr(),
                        compressed.len() as u32,
                        4096,
                        &mut final_cmp,
                        ws.as_mut_ptr() as *mut c_void,
                    )
                };
                if st >= 0 {
                    let mut mam = Vec::with_capacity(8 + final_cmp as usize);
                    mam.extend_from_slice(b"MAM\x04");
                    mam.extend_from_slice(&(scca.len() as u32).to_le_bytes());
                    mam.extend_from_slice(&compressed[..final_cmp as usize]);
                    let roundtrip = parse_prefetch_bytes(&mam).unwrap();
                    assert_eq!(roundtrip.exe_name, "CARGO.EXE");
                    assert_eq!(roundtrip.run_count, 17);
                }
            }
        }
    }

    #[test]
    fn mam_decompression_rejects_oversized_and_corrupted_headers() {
        assert!(parse_prefetch_bytes(b"").is_err());
        assert!(parse_prefetch_bytes(b"BAD!1234").is_err());
        let mut bomb = Vec::new();
        bomb.extend_from_slice(b"MAM\x04");
        bomb.extend_from_slice(&u32::MAX.to_le_bytes());
        bomb.extend_from_slice(&[0u8; 16]);
        assert!(decompress_prefetch_mam(&bomb).is_err());
    }
}
