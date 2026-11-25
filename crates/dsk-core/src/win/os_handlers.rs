//! Windows COM `IEmptyVolumeCache` handlers and bounded external command runner.

#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    E_ABORT, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, RPC_E_CHANGED_MODE, S_FALSE, S_OK,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CLSIDFromString, COINIT, COINIT_APARTMENTTHREADED,
    COINIT_DISABLE_OLE1DDE, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE, RegCloseKey,
    RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::UI::LegacyWindowsEnvironmentFeatures::{
    EMPTY_VOLUME_CACHE_FLAGS, EVCF_REMOVEFROMLIST, IEmptyVolumeCache, IEmptyVolumeCache2,
    IEmptyVolumeCacheCallBack, IEmptyVolumeCacheCallBack_Impl,
};
use windows::core::{Interface, PCWSTR, PWSTR};

use crate::error::{DskError, Result};

/// Public information about an enumerated or estimated VolumeCaches handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsHandlerInfo {
    pub key_name: String,
    pub clsid: String,
    pub display_name: Option<String>,
    pub space_used: u64,
}

/// Outcome of executing an external tool cleanup command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutcome {
    pub ran: bool,
    pub exit_code: Option<i32>,
    pub detail: String,
}

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

/// RAII guard for HKEY registry handles.
struct RegKeyGuard(HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if self.0 != HKEY::default() {
            // SAFETY: self.0 is a valid open HKEY and is closed exactly once.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

/// RAII guard for CoInitializeEx / CoUninitialize.
pub(crate) struct ComApartmentGuard {
    need_uninit: bool,
}

impl ComApartmentGuard {
    pub(crate) fn new() -> Result<Self> {
        // SAFETY: CoInitializeEx is called with standard STA flags for VolumeCache COM handlers.
        let hr = unsafe {
            CoInitializeEx(
                None,
                COINIT(COINIT_APARTMENTTHREADED.0 | COINIT_DISABLE_OLE1DDE.0),
            )
        };
        if hr == S_OK || hr == S_FALSE {
            Ok(Self { need_uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            // Thread already belongs to an MTA apartment. Must NOT call CoUninitialize() on drop.
            Ok(Self { need_uninit: false })
        } else {
            Err(win32_err("CoInitializeEx", hr.0 as u32))
        }
    }
}

impl Drop for ComApartmentGuard {
    fn drop(&mut self) {
        if self.need_uninit {
            // SAFETY: CoUninitialize balances the successful S_OK/S_FALSE CoInitializeEx call.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

/// RAII guard for PWSTR allocated by COM handlers via `CoTaskMemAlloc`.
struct CoTaskMemPwstr(PWSTR);

impl Drop for CoTaskMemPwstr {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: The pointer was allocated by the COM server using CoTaskMemAlloc.
            unsafe {
                CoTaskMemFree(Some(self.0.0 as *const c_void));
            }
            self.0 = PWSTR::null();
        }
    }
}

impl CoTaskMemPwstr {
    fn to_string_lossy(&self) -> Option<String> {
        if self.0.0.is_null() {
            None
        } else {
            // SAFETY: self.0 points to a valid null-terminated UTF-16 COM string.
            unsafe {
                let mut len = 0;
                while *self.0.0.add(len) != 0 {
                    len += 1;
                }
                let slice = core::slice::from_raw_parts(self.0.0, len);
                let s = String::from_utf16_lossy(slice).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            }
        }
    }
}

/// RAII guard to invoke `IEmptyVolumeCache::Deactivate` on scope exit.
struct VcDeactivateGuard<'a>(&'a IEmptyVolumeCache);

impl<'a> Drop for VcDeactivateGuard<'a> {
    fn drop(&mut self) {
        // SAFETY: Deactivate is invoked once on an initialized IEmptyVolumeCache before release.
        unsafe {
            let _ = self.0.Deactivate();
        }
    }
}

/// Scoped RAII guard that binds a borrowed `&AtomicBool` to a shared callback slot
/// for the exact lifetime of a synchronous COM call and clears it to `None` on drop.
struct CancelSlotGuard {
    slot: Arc<Mutex<Option<usize>>>,
}

impl CancelSlotGuard {
    fn new(cancel: &AtomicBool) -> (Self, Arc<Mutex<Option<usize>>>) {
        let slot = Arc::new(Mutex::new(Some(cancel as *const AtomicBool as usize)));
        (
            Self {
                slot: Arc::clone(&slot),
            },
            slot,
        )
    }
}

impl Drop for CancelSlotGuard {
    fn drop(&mut self) {
        let mut guard = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }
}

/// COM callback implementing `IEmptyVolumeCacheCallBack` for progress and cancellation.
#[windows::core::implement(IEmptyVolumeCacheCallBack)]
struct EmptyVolumeCacheCallBack {
    cancel_slot: Arc<Mutex<Option<usize>>>,
    progress: Arc<AtomicU64>,
}

impl EmptyVolumeCacheCallBack {
    fn is_cancelled(&self) -> bool {
        let guard = self.cancel_slot.lock().unwrap_or_else(|e| e.into_inner());
        match *guard {
            Some(ptr) => {
                // SAFETY: While the mutex is held and `*guard` is `Some(ptr)`, `CancelSlotGuard`
                // on the caller's stack frame has not been dropped yet, so `ptr` is guaranteed
                // to reference a live `AtomicBool`.
                let cancel = unsafe { &*(ptr as *const AtomicBool) };
                cancel.load(Ordering::Relaxed)
            }
            None => true,
        }
    }
}

impl IEmptyVolumeCacheCallBack_Impl for EmptyVolumeCacheCallBack_Impl {
    fn ScanProgress(
        &self,
        dwlspaceused: u64,
        _dwflags: u32,
        _pcwszstatus: &PCWSTR,
    ) -> windows::core::Result<()> {
        if self.is_cancelled() {
            return Err(E_ABORT.into());
        }
        self.progress.store(dwlspaceused, Ordering::Relaxed);
        Ok(())
    }

    fn PurgeProgress(
        &self,
        dwlspacefreed: u64,
        _dwlspacetofree: u64,
        _dwflags: u32,
        _pcwszstatus: &PCWSTR,
    ) -> windows::core::Result<()> {
        if self.is_cancelled() {
            return Err(E_ABORT.into());
        }
        self.progress.store(dwlspacefreed, Ordering::Relaxed);
        Ok(())
    }
}

/// Looks up the CLSID registered for a given `VolumeCaches` handler in HKLM.
///
/// Returns `Ok(Some("{GUID}"))` if found, `Ok(None)` if the key or default value does not exist.
pub fn lookup_handler_clsid(handler_key: &str) -> Result<Option<String>> {
    let subkey =
        format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\{handler_key}");
    let subkey_w = to_wide(&subkey);
    let mut hkey = HKEY::default();

    // SAFETY: Opening HKLM subkey with KEY_READ.
    let open_res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if open_res == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if open_res != ERROR_SUCCESS {
        return Err(win32_err("RegOpenKeyExW", open_res.0));
    }
    let _key_guard = RegKeyGuard(hkey);

    // Read default value (PCWSTR::null())
    let mut val_type = REG_VALUE_TYPE(0);
    let mut size_bytes = 0u32;
    // SAFETY: Querying default value size.
    let q_res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::null(),
            None,
            Some(&mut val_type),
            None,
            Some(&mut size_bytes),
        )
    };
    if q_res == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if q_res != ERROR_SUCCESS {
        return Err(win32_err("RegQueryValueExW", q_res.0));
    }

    if (val_type != REG_SZ && val_type != REG_EXPAND_SZ) || size_bytes < 2 {
        return Ok(None);
    }

    let mut buf = vec![0u16; (size_bytes as usize).div_ceil(2) + 1];
    let mut bytes_read = (buf.len() * 2) as u32;
    // SAFETY: Buffer is allocated with 2-byte aligned u16, large enough for bytes_read.
    let q2_res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::null(),
            None,
            Some(&mut val_type),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut bytes_read),
        )
    };
    if q2_res != ERROR_SUCCESS {
        return Err(win32_err("RegQueryValueExW", q2_res.0));
    }

    let u16_len = (bytes_read as usize / 2).min(buf.len());
    let u16_slice = &buf[..u16_len];
    let trimmed_slice = match u16_slice.iter().position(|&c| c == 0) {
        Some(pos) => &u16_slice[..pos],
        None => u16_slice,
    };

    let clsid_str = String::from_utf16_lossy(trimmed_slice).trim().to_string();
    if clsid_str.is_empty() {
        Ok(None)
    } else {
        Ok(Some(clsid_str))
    }
}

/// Estimates space used by a curated Windows `VolumeCaches` COM handler.
pub fn estimate_os_handler(
    handler_key: &str,
    volume_root: &str,
    cancel: &AtomicBool,
) -> Result<OsHandlerInfo> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let clsid = match lookup_handler_clsid(handler_key)? {
        Some(c) => c,
        None => {
            return Err(win32_err(
                "VolumeCaches key not found",
                ERROR_FILE_NOT_FOUND.0,
            ));
        }
    };

    let _com_guard = ComApartmentGuard::new()?;

    let clsid_w = to_wide(&clsid);
    // SAFETY: Converting CLSID string to GUID.
    let guid = unsafe { CLSIDFromString(PCWSTR(clsid_w.as_ptr())) }
        .map_err(|e| win32_err("CLSIDFromString", e.code().0 as u32))?;

    // SAFETY: Instantiating in-process COM server.
    let unk: windows::core::IUnknown =
        unsafe { CoCreateInstance(&guid, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| win32_err("CoCreateInstance", e.code().0 as u32))?;

    let subkey =
        format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\{handler_key}");
    let subkey_w = to_wide(&subkey);
    let mut hkey = HKEY::default();
    // SAFETY: Opening HKLM subkey handle for handler Initialize.
    let open_res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if open_res != ERROR_SUCCESS {
        return Err(win32_err("RegOpenKeyExW", open_res.0));
    }
    let _key_guard = RegKeyGuard(hkey);

    let vol_w = to_wide(volume_root);
    let key_w = to_wide(handler_key);

    let mut display_name_pwstr = PWSTR::null();
    let mut description_pwstr = PWSTR::null();
    let mut btn_text_pwstr = PWSTR::null();
    let mut flags = EMPTY_VOLUME_CACHE_FLAGS(0);

    // Try IEmptyVolumeCache2 first, fallback to IEmptyVolumeCache.
    let cache: IEmptyVolumeCache = if let Ok(vc2) = unk.cast::<IEmptyVolumeCache2>() {
        // SAFETY: InitializeEx called with open registry key and volume root.
        let init_res = unsafe {
            vc2.InitializeEx(
                hkey,
                PCWSTR(vol_w.as_ptr()),
                PCWSTR(key_w.as_ptr()),
                &mut display_name_pwstr,
                &mut description_pwstr,
                &mut btn_text_pwstr,
                &mut flags,
            )
        };
        if let Err(e) = init_res {
            return Err(win32_err(
                "IEmptyVolumeCache2::InitializeEx",
                e.code().0 as u32,
            ));
        }
        (*vc2).clone()
    } else {
        let vc1: IEmptyVolumeCache = unk
            .cast::<IEmptyVolumeCache>()
            .map_err(|e| win32_err("IEmptyVolumeCache cast", e.code().0 as u32))?;
        // SAFETY: Initialize called with open registry key and volume root.
        let init_res = unsafe {
            vc1.Initialize(
                hkey,
                PCWSTR(vol_w.as_ptr()),
                &mut display_name_pwstr,
                &mut description_pwstr,
                &mut flags,
            )
        };
        if let Err(e) = init_res {
            return Err(win32_err(
                "IEmptyVolumeCache::Initialize",
                e.code().0 as u32,
            ));
        }
        vc1
    };

    // RAII guards for COM allocated strings and Deactivate teardown.
    let display_guard = CoTaskMemPwstr(display_name_pwstr);
    let _desc_guard = CoTaskMemPwstr(description_pwstr);
    let _btn_guard = CoTaskMemPwstr(btn_text_pwstr);
    let _deact_guard = VcDeactivateGuard(&cache);

    if (flags.0 & EVCF_REMOVEFROMLIST.0) != 0 {
        return Ok(OsHandlerInfo {
            key_name: handler_key.to_string(),
            clsid,
            display_name: display_guard.to_string_lossy(),
            space_used: 0,
        });
    }

    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let progress_bytes = Arc::new(AtomicU64::new(0));
    let (_cancel_guard, cancel_slot) = CancelSlotGuard::new(cancel);
    let cb_obj = EmptyVolumeCacheCallBack {
        cancel_slot,
        progress: Arc::clone(&progress_bytes),
    };
    let cb: IEmptyVolumeCacheCallBack = cb_obj.into();

    let mut space_used: u64 = 0;
    // SAFETY: GetSpaceUsed is called with valid callback and out-pointer.
    let space_res = unsafe { cache.GetSpaceUsed(&mut space_used, &cb) };
    if let Err(e) = space_res {
        if e.code() == E_ABORT {
            return Err(DskError::Cancelled);
        }
        return Err(win32_err(
            "IEmptyVolumeCache::GetSpaceUsed",
            e.code().0 as u32,
        ));
    }

    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let final_space = space_used.max(progress_bytes.load(Ordering::Relaxed));

    Ok(OsHandlerInfo {
        key_name: handler_key.to_string(),
        clsid,
        display_name: display_guard.to_string_lossy(),
        space_used: final_space,
    })
}

/// Executes `Purge` on a curated Windows `VolumeCaches` COM handler.
///
/// Returns the number of bytes purged.
pub fn purge_os_handler(
    handler_key: &str,
    volume_root: &str,
    est_bytes: u64,
    cancel: &AtomicBool,
) -> Result<u64> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }
    if est_bytes == 0 {
        return Ok(0);
    }

    let clsid = match lookup_handler_clsid(handler_key)? {
        Some(c) => c,
        None => {
            return Err(win32_err(
                "VolumeCaches key not found",
                ERROR_FILE_NOT_FOUND.0,
            ));
        }
    };

    let _com_guard = ComApartmentGuard::new()?;

    let clsid_w = to_wide(&clsid);
    // SAFETY: Converting CLSID string to GUID.
    let guid = unsafe { CLSIDFromString(PCWSTR(clsid_w.as_ptr())) }
        .map_err(|e| win32_err("CLSIDFromString", e.code().0 as u32))?;

    // SAFETY: Instantiating in-process COM server.
    let unk: windows::core::IUnknown =
        unsafe { CoCreateInstance(&guid, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| win32_err("CoCreateInstance", e.code().0 as u32))?;

    let subkey =
        format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\{handler_key}");
    let subkey_w = to_wide(&subkey);
    let mut hkey = HKEY::default();
    // SAFETY: Opening HKLM subkey handle for handler Initialize.
    let open_res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if open_res != ERROR_SUCCESS {
        return Err(win32_err("RegOpenKeyExW", open_res.0));
    }
    let _key_guard = RegKeyGuard(hkey);

    let vol_w = to_wide(volume_root);
    let key_w = to_wide(handler_key);

    let mut display_name_pwstr = PWSTR::null();
    let mut description_pwstr = PWSTR::null();
    let mut btn_text_pwstr = PWSTR::null();
    let mut flags = EMPTY_VOLUME_CACHE_FLAGS(0);

    let cache: IEmptyVolumeCache = if let Ok(vc2) = unk.cast::<IEmptyVolumeCache2>() {
        // SAFETY: InitializeEx called with open registry key and volume root.
        let init_res = unsafe {
            vc2.InitializeEx(
                hkey,
                PCWSTR(vol_w.as_ptr()),
                PCWSTR(key_w.as_ptr()),
                &mut display_name_pwstr,
                &mut description_pwstr,
                &mut btn_text_pwstr,
                &mut flags,
            )
        };
        if let Err(e) = init_res {
            return Err(win32_err(
                "IEmptyVolumeCache2::InitializeEx",
                e.code().0 as u32,
            ));
        }
        (*vc2).clone()
    } else {
        let vc1: IEmptyVolumeCache = unk
            .cast::<IEmptyVolumeCache>()
            .map_err(|e| win32_err("IEmptyVolumeCache cast", e.code().0 as u32))?;
        // SAFETY: Initialize called with open registry key and volume root.
        let init_res = unsafe {
            vc1.Initialize(
                hkey,
                PCWSTR(vol_w.as_ptr()),
                &mut display_name_pwstr,
                &mut description_pwstr,
                &mut flags,
            )
        };
        if let Err(e) = init_res {
            return Err(win32_err(
                "IEmptyVolumeCache::Initialize",
                e.code().0 as u32,
            ));
        }
        vc1
    };

    let _display_guard = CoTaskMemPwstr(display_name_pwstr);
    let _desc_guard = CoTaskMemPwstr(description_pwstr);
    let _btn_guard = CoTaskMemPwstr(btn_text_pwstr);
    let _deact_guard = VcDeactivateGuard(&cache);

    if (flags.0 & EVCF_REMOVEFROMLIST.0) != 0 {
        return Ok(0);
    }

    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let progress_bytes = Arc::new(AtomicU64::new(0));
    let (_cancel_guard, cancel_slot) = CancelSlotGuard::new(cancel);
    let cb_obj = EmptyVolumeCacheCallBack {
        cancel_slot,
        progress: Arc::clone(&progress_bytes),
    };
    let cb: IEmptyVolumeCacheCallBack = cb_obj.into();

    let mut current_space: u64 = 0;
    // SAFETY: Query space before purging to verify availability.
    let space_res = unsafe { cache.GetSpaceUsed(&mut current_space, &cb) };
    if let Err(e) = space_res {
        if e.code() == E_ABORT {
            return Err(DskError::Cancelled);
        }
        return Err(win32_err(
            "IEmptyVolumeCache::GetSpaceUsed",
            e.code().0 as u32,
        ));
    }

    let bytes_to_purge = if current_space > 0 {
        current_space
    } else {
        est_bytes
    };
    if bytes_to_purge == 0 {
        return Ok(0);
    }

    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    // SAFETY: Purge is called with verified bytes to purge and callback.
    let purge_res = unsafe { cache.Purge(bytes_to_purge, &cb) };
    if let Err(e) = purge_res {
        if e.code() == E_ABORT {
            return Err(DskError::Cancelled);
        }
        return Err(win32_err("IEmptyVolumeCache::Purge", e.code().0 as u32));
    }

    let freed = progress_bytes.load(Ordering::Relaxed);
    if freed > 0 {
        Ok(freed)
    } else {
        Ok(bytes_to_purge)
    }
}

/// Resolves an executable name across explicit `path_var` and `pathext_var` values.
///
/// When `pathext_var` is `None`, defaults to `".COM;.EXE;.BAT;.CMD"`.
/// If `program` already has a known `PATHEXT` extension, it is checked directly.
/// Otherwise (extensionless or non-`PATHEXT` dot in name), candidates with `PATHEXT`
/// extensions are prioritized over extensionless companion scripts.
pub fn find_program_in_path(
    program: &str,
    path_var: Option<&OsStr>,
    pathext_var: Option<&OsStr>,
) -> Option<PathBuf> {
    let prog_path = Path::new(program);
    let default_pathext = OsStr::new(".COM;.EXE;.BAT;.CMD");
    let pathext_raw = pathext_var.unwrap_or(default_pathext);

    let mut extensions: Vec<String> = std::env::split_paths(pathext_raw)
        .filter_map(|p| {
            let s = p.to_string_lossy();
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.starts_with('.') {
                Some(trimmed.to_string())
            } else {
                Some(format!(".{trimmed}"))
            }
        })
        .collect();

    if extensions.is_empty() && pathext_var.is_none() {
        extensions = vec![".COM".into(), ".EXE".into(), ".BAT".into(), ".CMD".into()];
    }

    let has_pathext = prog_path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            extensions.iter().any(|p_ext| {
                let clean = p_ext.strip_prefix('.').unwrap_or(p_ext);
                clean.eq_ignore_ascii_case(ext)
            })
        });

    let is_qualified = prog_path.is_absolute() || program.contains('\\') || program.contains('/');

    if is_qualified {
        if has_pathext {
            if prog_path.is_file() {
                return Some(prog_path.to_path_buf());
            }
            return None;
        }

        // Extensionless or non-PATHEXT dot in name: try PATHEXT extensions first.
        for ext in &extensions {
            let mut candidate_os = prog_path.as_os_str().to_os_string();
            candidate_os.push(ext);
            let candidate = PathBuf::from(candidate_os);
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        if prog_path.is_file() {
            return Some(prog_path.to_path_buf());
        }
        return None;
    }

    let path_val = path_var?;
    for dir in std::env::split_paths(path_val) {
        if has_pathext {
            let direct = dir.join(prog_path);
            if direct.is_file() {
                return Some(direct);
            }
        } else {
            // First try appending each ext in PATHEXT
            for ext in &extensions {
                let mut name = prog_path.as_os_str().to_os_string();
                name.push(ext);
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
            // Only if none of those exist, fall back to direct
            let direct = dir.join(prog_path);
            if direct.is_file() {
                return Some(direct);
            }
        }
    }

    None
}

/// Resolves an executable name across `PATH` and `PATHEXT`.
pub fn find_program_on_path(program: &str) -> Option<PathBuf> {
    find_program_in_path(
        program,
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("PATHEXT").as_deref(),
    )
}

/// Executes an external cleanup command with timeout and cancellation safety.
/// Resolves a rule's tool: the first `candidates` template (`%VAR%` expanded) that names an
/// existing regular file, else `program` on `PATH`.
pub fn resolve_rule_program(program: &str, candidates: &[String]) -> Option<PathBuf> {
    for tmpl in candidates {
        let Some(segments) =
            crate::clean::rules::expand_path_template(tmpl, &|k| std::env::var(k).ok())
        else {
            continue;
        };
        if segments.iter().any(|s| s.contains('*')) {
            continue;
        }
        // Segment 0 is the drive (`C:`), so joining gives `C:\Users\...`.
        let path = PathBuf::from(segments.join("\\"));
        if !path.is_absolute() {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&path)
            && meta.is_file()
        {
            return Some(path);
        }
    }
    find_program_on_path(program)
}

pub fn run_clean_command(
    program: &str,
    args: &[String],
    timeout_secs: u64,
    dry_run: bool,
    cancel: &AtomicBool,
) -> Result<CommandOutcome> {
    let resolved_path = match find_program_on_path(program) {
        Some(p) => p,
        None => {
            return Ok(CommandOutcome {
                ran: false,
                exit_code: None,
                detail: format!("program '{program}' not found on PATH"),
            });
        }
    };

    if dry_run {
        return Ok(CommandOutcome {
            ran: false,
            exit_code: None,
            detail: format!(
                "dry-run: would execute '{}' with args [{}]",
                resolved_path.display(),
                args.join(", ")
            ),
        });
    }

    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let mut cmd = crate::win::process::hidden_command(&resolved_path);
    cmd.args(args);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    let mut child = cmd.spawn()?;
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let start = Instant::now();

    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DskError::Cancelled);
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(CommandOutcome {
                ran: true,
                exit_code: None,
                detail: format!("command '{program}' timed out after {}s", timeout.as_secs()),
            });
        }

        match child.try_wait()? {
            Some(status) => {
                let code = status.code();
                return Ok(CommandOutcome {
                    ran: true,
                    exit_code: code,
                    detail: format!("process exited with code {:?}", code),
                });
            }
            None => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_volume_cache_handler_on_windows() {
        let clsid = lookup_handler_clsid("Thumbnail Cache")
            .expect("lookup should not fail on standard Windows installation");
        assert!(clsid.is_some(), "Thumbnail Cache handler key must exist");
        let clsid_str = clsid.unwrap();
        assert!(
            clsid_str.starts_with('{') && clsid_str.ends_with('}'),
            "CLSID must be in GUID format: {}",
            clsid_str
        );
    }

    #[test]
    fn missing_handler_returns_none() {
        let res = lookup_handler_clsid("DiskSaverNonExistentHandler999")
            .expect("missing key must return Ok(None)");
        assert_eq!(res, None);
    }

    #[test]
    fn estimate_thumbnail_cache_non_destructive_smoke() {
        let cancel = AtomicBool::new(false);
        let res = estimate_os_handler("Thumbnail Cache", "C:\\", &cancel);
        match res {
            Ok(info) => {
                assert_eq!(info.key_name, "Thumbnail Cache");
                assert!(info.clsid.starts_with('{'));
            }
            Err(DskError::Win32 { ctx, code }) => {
                // Graceful error if running in restricted CI environment
                println!("Graceful Win32 error in test: {ctx} ({code:#x})");
            }
            Err(other) => panic!("Unexpected error estimating Thumbnail Cache: {:?}", other),
        }
    }

    #[test]
    fn run_command_dry_run_and_timeout_and_missing_binary() {
        let cancel = AtomicBool::new(false);

        // 1. Missing binary
        let out_missing =
            run_clean_command("disksaver_nonexistent_binary_xyz", &[], 5, false, &cancel)
                .expect("missing binary should return outcome with ran: false");
        assert!(!out_missing.ran);
        assert!(out_missing.detail.contains("not found on PATH"));

        // 2. Dry-run never runs process
        let out_dry =
            run_clean_command("cmd.exe", &["/C".into(), "exit 0".into()], 5, true, &cancel)
                .expect("dry run should succeed");
        assert!(!out_dry.ran);
        assert!(out_dry.detail.contains("dry-run"));

        // 3. Quick command execution
        let out_live = run_clean_command(
            "cmd.exe",
            &["/C".into(), "exit 0".into()],
            5,
            false,
            &cancel,
        )
        .expect("live command should succeed");
        assert!(out_live.ran);
        assert_eq!(out_live.exit_code, Some(0));

        // 3b. Non-zero exit code execution
        let out_nonzero = run_clean_command(
            "cmd.exe",
            &["/C".into(), "exit 42".into()],
            5,
            false,
            &cancel,
        )
        .expect("command with non-zero exit code should succeed");
        assert!(out_nonzero.ran);
        assert_eq!(out_nonzero.exit_code, Some(42));

        // 4. Timeout execution
        let out_timeout = run_clean_command(
            "cmd.exe",
            &[
                "/C".into(),
                "powershell -Command Start-Sleep -Seconds 10".into(),
            ],
            1,
            false,
            &cancel,
        )
        .expect("timed out command should return outcome");
        assert!(out_timeout.ran);
        assert_eq!(out_timeout.exit_code, None);
        assert!(out_timeout.detail.contains("timed out"));
    }

    #[test]
    fn cancellation_and_zero_bytes_coverage() {
        let cancel = AtomicBool::new(true);

        // Pre-cancelled estimate
        let err_est = estimate_os_handler("Thumbnail Cache", "C:\\", &cancel);
        assert!(matches!(err_est, Err(DskError::Cancelled)));

        // Pre-cancelled purge
        let err_purge = purge_os_handler("Thumbnail Cache", "C:\\", 1024, &cancel);
        assert!(matches!(err_purge, Err(DskError::Cancelled)));

        // Pre-cancelled command
        let err_cmd = run_clean_command("cmd.exe", &[], 5, false, &cancel);
        assert!(matches!(err_cmd, Err(DskError::Cancelled)));

        // Purge with est_bytes == 0 should return Ok(0) immediately
        let not_cancelled = AtomicBool::new(false);
        let zero_purge = purge_os_handler("Thumbnail Cache", "C:\\", 0, &not_cancelled)
            .expect("purge with 0 est_bytes should succeed with 0");
        assert_eq!(zero_purge, 0);
    }

    #[test]
    fn find_program_on_path_resolves_common_tools() {
        let cmd = find_program_on_path("cmd");
        assert!(cmd.is_some(), "cmd should be found on PATH");
        let cmd_path = cmd.unwrap();
        assert!(cmd_path.is_file());

        let cmd_exe = find_program_on_path("cmd.exe");
        assert!(cmd_exe.is_some(), "cmd.exe should be found on PATH");

        let missing = find_program_on_path("non_existent_tool_xyz_999.exe");
        assert!(missing.is_none());
    }

    #[test]
    fn find_program_in_path_prioritizes_pathext_over_companion() {
        let temp_dir = tempfile::tempdir().expect("tempdir should be created");
        let dir_path = temp_dir.path();

        let extless = dir_path.join("mytool");
        std::fs::write(&extless, "#!/bin/sh\necho Unix script\n")
            .expect("writing extensionless script");

        let cmd_script = dir_path.join("mytool.cmd");
        std::fs::write(&cmd_script, "@echo off\r\nexit 0\r\n").expect("writing cmd script");

        let pathext = OsStr::new(".COM;.EXE;.BAT;.CMD");

        // 1. Unqualified PATH lookup prioritizes .cmd over extensionless
        let resolved_unqual =
            find_program_in_path("mytool", Some(dir_path.as_os_str()), Some(pathext))
                .expect("PATH lookup must resolve");
        assert!(resolved_unqual.is_file());
        assert_eq!(resolved_unqual.file_stem().unwrap(), "mytool");
        assert!(
            resolved_unqual
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("cmd")),
            "must resolve to .cmd wrapper instead of extensionless file"
        );

        // 2. Qualified path lookup without extension prioritizes .cmd over extensionless
        let qual_extless_str = extless.to_str().expect("valid utf-8 path");
        let resolved_qual = find_program_in_path(qual_extless_str, None, Some(pathext))
            .expect("qualified lookup must resolve");
        assert!(resolved_qual.is_file());
        assert_eq!(resolved_qual.file_stem().unwrap(), "mytool");
        assert!(
            resolved_qual
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("cmd")),
            "must resolve to .cmd wrapper instead of extensionless file"
        );

        // 3. Qualified path lookup with explicit .cmd extension resolves directly
        let qual_cmd_str = cmd_script.to_str().expect("valid utf-8 path");
        let resolved_explicit = find_program_in_path(qual_cmd_str, None, Some(pathext));
        assert_eq!(
            resolved_explicit,
            Some(cmd_script.clone()),
            "Qualified path with explicit .cmd must resolve directly"
        );

        // 4. Clean execution of resolved .cmd script via run_clean_command
        let cancel = AtomicBool::new(false);
        let out_script = run_clean_command(resolved_qual.to_str().unwrap(), &[], 5, false, &cancel)
            .expect("running .cmd script should succeed");
        assert!(out_script.ran);
        assert_eq!(out_script.exit_code, Some(0));
    }

    #[test]
    fn callback_outliving_scope_aborts_safely_without_dangling_deref() {
        let progress = Arc::new(AtomicU64::new(0));
        let cb: IEmptyVolumeCacheCallBack = {
            let scoped_cancel = AtomicBool::new(false);
            let (_guard, slot) = CancelSlotGuard::new(&scoped_cancel);
            let cb_obj = EmptyVolumeCacheCallBack {
                cancel_slot: slot,
                progress: Arc::clone(&progress),
            };
            let cb_iface: IEmptyVolumeCacheCallBack = cb_obj.into();

            // While guard is alive and scoped_cancel is false, callbacks succeed and record progress.
            unsafe {
                cb_iface
                    .ScanProgress(4096, 0, PWSTR::null())
                    .expect("active ScanProgress should succeed");
            }
            assert_eq!(progress.load(Ordering::Relaxed), 4096);
            cb_iface
        };

        // Now `_guard` and `scoped_cancel` have both been dropped!
        // Any late COM callback on the retained `IEmptyVolumeCacheCallBack` must safely return E_ABORT.
        let scan_err = unsafe { cb.ScanProgress(8192, 0, PWSTR::null()) }
            .expect_err("ScanProgress after scope exit must abort");
        assert_eq!(scan_err.code(), E_ABORT);

        let purge_err = unsafe { cb.PurgeProgress(1024, 4096, 0, PWSTR::null()) }
            .expect_err("PurgeProgress after scope exit must abort");
        assert_eq!(purge_err.code(), E_ABORT);
        assert_eq!(progress.load(Ordering::Relaxed), 4096);
    }
}
