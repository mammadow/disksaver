//! Win32 Cloud Files API (`cfapi`) primitives.
//!
//! Provides safe wrappers around Windows Cloud Files API for querying placeholder status,
//! validating in-sync states, and dehydrating synced local files to release disk space (§8.4).

#![allow(unsafe_code)]

use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::CloudFilters::{
    CF_DEHYDRATE_FLAG_NONE, CF_IN_SYNC_STATE_IN_SYNC, CF_PIN_STATE_PINNED, CF_PIN_STATE_UNPINNED,
    CF_PLACEHOLDER_INFO_STANDARD, CF_PLACEHOLDER_STANDARD_INFO, CfDehydratePlaceholder,
    CfGetPlaceholderInfo, CfSetPinState,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING, WRITE_DAC,
};
use windows::core::PCWSTR;

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

/// RAII handle guard ensuring handles are closed.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Checks whether a cloud placeholder file is fully in-sync with the remote provider.
///
/// Returns `true` if and only if `InSyncState == CF_IN_SYNC_STATE_IN_SYNC`.
pub fn is_placeholder_in_sync(path: &Path) -> Result<bool> {
    let wide = to_wide(&path.to_string_lossy());
    // SAFETY: Querying file attributes for null-terminated path before opening placeholder handle.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Ok(false);
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0 {
        return Ok(false);
    }

    // SAFETY: Opening file with FILE_READ_ATTRIBUTES and FILE_FLAG_BACKUP_SEMANTICS
    // to query Cloud Filter placeholder info without reading file content.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0),
            None,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) => return Ok(false),
        Err(e) => {
            let code = e.code().0 as u32;
            return Err(win32_err("CreateFileW for CfGetPlaceholderInfo", code));
        }
    };
    let _guard = HandleGuard(handle);

    Ok(query_standard_placeholder_info(handle)
        .is_some_and(|info| info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC))
}

/// `CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH` (4 KiB).
const CF_MAX_FILE_IDENTITY_LENGTH: usize = 4096;
/// `HRESULT_FROM_WIN32(ERROR_MORE_DATA)`.
const HRESULT_MORE_DATA: i32 = 0x8007_00EA_u32 as i32;

/// Reads the fixed part of `CF_PLACEHOLDER_STANDARD_INFO`. Returns `None` if the handle is not a
/// cloud placeholder.
///
/// `CF_PLACEHOLDER_STANDARD_INFO` ends in a variable-length `FileIdentity`; providers such as
/// OneDrive store far more than the 1 byte declared in the struct, so a struct-sized buffer makes
/// the call fail with `ERROR_MORE_DATA` for every real placeholder. Use a 8-byte aligned buffer with
/// room for the maximum identity and also accept `ERROR_MORE_DATA` (fixed fields are filled).
fn query_standard_placeholder_info(handle: HANDLE) -> Option<CF_PLACEHOLDER_STANDARD_INFO> {
    let byte_len = size_of::<CF_PLACEHOLDER_STANDARD_INFO>() + CF_MAX_FILE_IDENTITY_LENGTH;
    let mut buf = vec![0u64; byte_len.div_ceil(8)];
    let mut returned_len = 0u32;

    // SAFETY: handle is valid; `buf` is 8-byte aligned and `byte_len` bytes long.
    let hr = unsafe {
        CfGetPlaceholderInfo(
            handle,
            CF_PLACEHOLDER_INFO_STANDARD,
            buf.as_mut_ptr() as *mut _,
            (buf.len() * 8) as u32,
            Some(&mut returned_len),
        )
    };
    match hr {
        Ok(()) => {}
        Err(e) if e.code().0 == HRESULT_MORE_DATA => {}
        Err(_) => return None,
    }
    // SAFETY: The buffer is aligned for and at least as large as the struct, and the fixed fields
    // were written by CfGetPlaceholderInfo.
    Some(unsafe { std::ptr::read(buf.as_ptr() as *const CF_PLACEHOLDER_STANDARD_INFO) })
}

/// Unpins and dehydrates a cloud file placeholder if it is confirmed in-sync.
///
/// Returns `Ok(freed_bytes)` or an error if the file is not in sync or cannot be dehydrated.
pub fn dehydrate_placeholder_file(path: &Path) -> Result<u64> {
    let wide = to_wide(&path.to_string_lossy());

    // SAFETY: Inspecting file attributes to reject missing targets or directories up front.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(DskError::Optimize(format!(
            "cloud placeholder path does not exist: {}",
            path.display()
        )));
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0 {
        return Err(DskError::PreconditionFailed(format!(
            "cannot dehydrate directory '{}'",
            path.display()
        )));
    }

    // SAFETY: Opening the placeholder without reading data. CfSetPinState needs
    // FILE_WRITE_ATTRIBUTES (or WRITE_DAC) and CfDehydratePlaceholder needs WRITE_DATA or WRITE_DAC;
    // WRITE_DAC is used so no data-write intent is expressed. Writers are not shared so the file
    // cannot change between the in-sync check and dehydration.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | FILE_WRITE_ATTRIBUTES.0 | WRITE_DAC.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0),
            None,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) => {
            return Err(DskError::Optimize(
                "invalid handle for placeholder".to_string(),
            ));
        }
        Err(e) => {
            let code = e.code().0 as u32;
            return Err(win32_err("CreateFileW for CfDehydratePlaceholder", code));
        }
    };
    let _guard = HandleGuard(handle);

    // Verify in-sync state
    let Some(info) = query_standard_placeholder_info(handle) else {
        return Err(DskError::PreconditionFailed(
            "file is not a recognized cloud placeholder".to_string(),
        ));
    };

    if info.InSyncState != CF_IN_SYNC_STATE_IN_SYNC {
        return Err(DskError::PreconditionFailed(
            "cloud file has unsynced local changes; dehydration rejected".to_string(),
        ));
    }

    // Respect the user's explicit "Always keep on this device" choice.
    if info.PinState == CF_PIN_STATE_PINNED {
        return Err(DskError::PreconditionFailed(
            "cloud file is pinned (\"Always keep on this device\"); dehydration rejected"
                .to_string(),
        ));
    }
    let original_pin = info.PinState;

    let prior_size = if info.OnDiskDataSize > 0 {
        info.OnDiskDataSize as u64
    } else {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    };

    // Unpin first to prevent automatic rehydration by cloud provider
    // SAFETY: handle is valid and verified cloud placeholder.
    let unpin_res = unsafe {
        CfSetPinState(
            handle,
            CF_PIN_STATE_UNPINNED,
            windows::Win32::Storage::CloudFilters::CF_SET_PIN_FLAGS(0),
            None,
        )
    };
    if let Err(e) = unpin_res {
        let code = e.code().0 as u32;
        return Err(win32_err("CfSetPinState", code));
    }

    // SAFETY: Dehydrate placeholder starting from byte 0 through end-of-file (-1).
    let dehy_res = unsafe { CfDehydratePlaceholder(handle, 0, -1, CF_DEHYDRATE_FLAG_NONE, None) };

    if let Err(e) = dehy_res {
        // Restore the pin state the user had before we unpinned.
        if original_pin != CF_PIN_STATE_UNPINNED {
            // SAFETY: handle is valid; restoring the previously observed pin state.
            unsafe {
                let _ = CfSetPinState(
                    handle,
                    original_pin,
                    windows::Win32::Storage::CloudFilters::CF_SET_PIN_FLAGS(0),
                    None,
                );
            }
        }
        let code = e.code().0 as u32;
        return Err(win32_err("CfDehydratePlaceholder", code));
    }

    Ok(prior_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn cfapi_rejects_regular_files_directories_and_missing_paths() {
        let dir = tempdir().unwrap();
        let regular = dir.path().join("plain.txt");
        std::fs::write(&regular, b"local non-cloud file").unwrap();

        assert!(!is_placeholder_in_sync(&regular).unwrap());
        assert!(!is_placeholder_in_sync(dir.path()).unwrap());
        assert!(!is_placeholder_in_sync(&dir.path().join("missing.bin")).unwrap());

        assert!(matches!(
            dehydrate_placeholder_file(&regular),
            Err(DskError::PreconditionFailed(_))
        ));
        assert!(matches!(
            dehydrate_placeholder_file(dir.path()),
            Err(DskError::PreconditionFailed(_))
        ));
        assert!(matches!(
            dehydrate_placeholder_file(&dir.path().join("missing.bin")),
            Err(DskError::Optimize(_))
        ));
    }
}
