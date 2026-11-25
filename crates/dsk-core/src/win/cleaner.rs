//! Handle-based safe deletion primitive for cleanup operations.
//!
//! Enforces non-overridable deny checks, canonical path containment, and NTFS/directory
//! file ID pinning across all deletion steps. All Win32 handle operations and unsafe blocks
//! are strictly encapsulated within this module with comprehensive safety invariant comments.

use std::ffi::c_void;
use std::hash::Hasher;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_DIR_NOT_EMPTY, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION,
    GetLastError, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileBasicInfo,
    FileDispositionInfo, FileDispositionInfoEx, FileIdInfo, GETFINALPATHNAMEBYHANDLE_FLAGS,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, OPEN_EXISTING, SYNCHRONIZE,
    SetFileInformationByHandle, VOLUME_NAME_DOS,
};
use windows::core::PCWSTR;

use crate::clean::deny::{assert_not_denied, normalize_win_path_str};
use crate::clean::{DenyContext, FileIdKind, PlannedRoot};
use crate::error::{DskError, Result};
use crate::time::filetime_to_min2000;

/// The disposition outcome of an individual item cleanup attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteOutcomeKind {
    Deleted,
    Skipped,
    Failed,
}

/// The recorded result of attempting to delete a single file or directory item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemOutcome {
    pub path: String,
    pub file_id: u64,
    pub bytes: u64,
    pub kind: DeleteOutcomeKind,
    pub detail: Option<String>,
}

/// Summary report returned after processing all items scheduled for a planned root.
#[derive(Clone, Debug, Default)]
pub struct CleanRootReport {
    pub outcomes: Vec<ItemOutcome>,
    pub deleted_bytes: u64,
    pub deleted_count: u64,
    pub skipped_count: u64,
    pub failed_count: u64,
}

/// RAII guard ensuring a Win32 HANDLE is closed when leaving scope.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: self.0 is an active, open Win32 HANDLE uniquely owned by this guard.
            // It has not been closed previously, and is valid until this CloseHandle call.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Normalizes a filesystem path into an absolute, backslash-delimited, null-terminated
/// UTF-16 wide string prefixed with `\\?\` (or `\\?\UNC\` for network shares).
pub(crate) fn path_to_wide_null(p: &Path) -> Vec<u16> {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut wide: Vec<u16> = abs.as_os_str().encode_wide().collect();

    // Normalize forward slashes to backslashes
    for c in &mut wide {
        if *c == 0x002F {
            *c = 0x005C;
        }
    }

    let prefix_long = [0x005Cu16, 0x005C, 0x003F, 0x005C]; // \\?\
    let prefix_unc = [
        0x005Cu16, 0x005C, 0x003F, 0x005C, 0x0055, 0x004E, 0x0043, 0x005C,
    ]; // \\?\UNC\

    let mut out = if wide.starts_with(&prefix_unc) || wide.starts_with(&prefix_long) {
        wide
    } else if wide.starts_with(&[0x005Cu16, 0x005C]) {
        let mut v = prefix_unc.to_vec();
        v.extend_from_slice(&wide[2..]);
        v
    } else {
        let mut v = prefix_long.to_vec();
        v.extend_from_slice(&wide);
        v
    };

    // Keep trailing backslash only if root is a drive root like \\?\C:\
    let is_drive_root = out.len() == 7
        && out.starts_with(&prefix_long)
        && (out[4] as u8).is_ascii_alphabetic()
        && out[5] == b':' as u16
        && out[6] == 0x005C;
    if !is_drive_root {
        while out.len() > 1 && out.last() == Some(&0x005C) {
            out.pop();
        }
    }

    if out.last() != Some(&0) {
        out.push(0);
    }
    out
}

/// Retrieves the canonical DOS path for an open file or directory handle using Win32
/// `GetFinalPathNameByHandleW` with `FILE_NAME_NORMALIZED | VOLUME_NAME_DOS`.
pub fn final_path_by_handle(handle: HANDLE) -> Result<PathBuf> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: handle is an open Win32 handle. buf provides a contiguous mutable buffer
        // of u16 code units whose length matches the slice length passed to GetFinalPathNameByHandleW.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                &mut buf,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        };
        if len == 0 {
            // SAFETY: GetLastError is called immediately after a 0 return from GetFinalPathNameByHandleW.
            let err = unsafe { GetLastError() };
            return Err(DskError::Win32 {
                ctx: "GetFinalPathNameByHandleW",
                code: err.0,
            });
        }
        if (len as usize) < buf.len() {
            let s = String::from_utf16_lossy(&buf[..len as usize]);
            return Ok(PathBuf::from(s));
        }
        buf.resize(len as usize + 1, 0);
    }
}

/// Queries Win32 `FILE_ID_INFO` via `GetFileInformationByHandleEx`.
fn get_file_id_info(handle: HANDLE) -> Result<FILE_ID_INFO> {
    let mut id_info = FILE_ID_INFO::default();
    // SAFETY: handle is an open handle. id_info is a valid stack-allocated FILE_ID_INFO struct,
    // and the buffer size exactly matches std::mem::size_of::<FILE_ID_INFO>().
    let res = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &mut id_info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if res.is_err() {
        // SAFETY: GetLastError is called immediately after GetFileInformationByHandleEx fails.
        let err = unsafe { GetLastError() };
        return Err(DskError::Win32 {
            ctx: "GetFileInformationByHandleEx(FileIdInfo)",
            code: err.0,
        });
    }
    Ok(id_info)
}

/// Extracts a 64-bit identifier from `FILE_ID_INFO` matching P1's exact scan engine representation.
fn extract_file_id(kind: FileIdKind, info: &FILE_ID_INFO) -> u64 {
    match kind {
        FileIdKind::NtfsFrn64 => {
            // Lower 8 bytes contain the 64-bit NTFS FRN ((seq << 48) | record_no)
            u64::from_le_bytes(info.FileId.Identifier[0..8].try_into().unwrap())
        }
        FileIdKind::FxHash128 => {
            // Matches FxHasher over the full 16-byte Identifier used by ScanMethod::Dir
            let mut hasher = FxHasher::default();
            hasher.write(&info.FileId.Identifier);
            hasher.finish()
        }
        FileIdKind::Unpinned => 0,
    }
}

/// Queries Win32 `FILE_BASIC_INFO` via `GetFileInformationByHandleEx`.
pub(crate) fn get_basic_info(handle: HANDLE) -> Result<FILE_BASIC_INFO> {
    let mut basic_info = FILE_BASIC_INFO::default();
    // SAFETY: handle is an open handle. basic_info is a valid stack-allocated FILE_BASIC_INFO struct,
    // and the buffer size matches std::mem::size_of::<FILE_BASIC_INFO>().
    let res = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            &mut basic_info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if res.is_err() {
        // SAFETY: GetLastError is called immediately after GetFileInformationByHandleEx fails.
        let err = unsafe { GetLastError() };
        return Err(DskError::Win32 {
            ctx: "GetFileInformationByHandleEx(FileBasicInfo)",
            code: err.0,
        });
    }
    Ok(basic_info)
}

/// Verifies that `cand_path` is strictly nested underneath `root_path`.
///
/// Returns `false` if `cand_path` is outside `root_path` or if `cand_path` equals `root_path`
/// (ensuring the rule root itself is never treated as a child item).
fn is_strictly_nested(cand_path: &Path, root_path: &Path) -> bool {
    let cand_norm = normalize_win_path_str(cand_path);
    let root_norm = normalize_win_path_str(root_path);
    if cand_norm.is_empty() || root_norm.is_empty() {
        return false;
    }
    // Must NOT equal the root itself!
    if cand_norm == root_norm {
        return false;
    }
    if root_norm.ends_with('\\') {
        cand_norm.starts_with(&root_norm)
    } else {
        cand_norm.starts_with(&root_norm)
            && cand_norm.as_bytes().get(root_norm.len()) == Some(&b'\\')
    }
}

/// Classified errors that can occur during handle-based file unlinking.
enum DeleteError {
    DirNotEmpty,
    SharingViolation,
    AccessDenied,
    Other(u32),
}

/// Unlinks an item through its open handle, attempting POSIX disposition with ignore-readonly,
/// then falling back on the same handle to non-POSIX disposition and legacy disposition.
fn delete_handle(handle: HANDLE, basic_attrs: u32) -> std::result::Result<(), DeleteError> {
    // Attempt 1: POSIX semantics with ignore readonly attribute (Windows 10 RS1+)
    let disp_ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };
    // SAFETY: handle was opened with DELETE rights. disp_ex is valid and dwbuffersize
    // matches the size of FILE_DISPOSITION_INFO_EX.
    let res1 = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            &disp_ex as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if res1.is_ok() {
        return Ok(());
    }

    // SAFETY: GetLastError is queried immediately after failure.
    let err1 = unsafe { GetLastError() };
    if err1 == ERROR_DIR_NOT_EMPTY {
        return Err(DeleteError::DirNotEmpty);
    }
    if err1 == ERROR_SHARING_VIOLATION {
        return Err(DeleteError::SharingViolation);
    }
    if err1 == ERROR_ACCESS_DENIED {
        return Err(DeleteError::AccessDenied);
    }

    // If unsupported or invalid parameter on this filesystem driver, fallback on SAME handle:
    if err1 == ERROR_INVALID_PARAMETER || err1 == ERROR_NOT_SUPPORTED {
        // Attempt 2: Non-POSIX disposition with ignore readonly
        let disp_ex_fallback = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
                FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
            ),
        };
        // SAFETY: handle was opened with DELETE rights; disp_ex_fallback is a valid struct.
        let res2 = unsafe {
            SetFileInformationByHandle(
                handle,
                FileDispositionInfoEx,
                &disp_ex_fallback as *const _ as *const c_void,
                std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        };
        if res2.is_ok() {
            return Ok(());
        }

        // SAFETY: GetLastError is queried immediately after failure.
        let err2 = unsafe { GetLastError() };
        if err2 == ERROR_DIR_NOT_EMPTY {
            return Err(DeleteError::DirNotEmpty);
        }
        if err2 == ERROR_SHARING_VIOLATION {
            return Err(DeleteError::SharingViolation);
        }
        if err2 == ERROR_ACCESS_DENIED {
            return Err(DeleteError::AccessDenied);
        }

        if err2 == ERROR_INVALID_PARAMETER || err2 == ERROR_NOT_SUPPORTED {
            // Attempt 3: Legacy FileDispositionInfo
            if basic_attrs & FILE_ATTRIBUTE_READONLY.0 != 0 {
                let stripped = basic_attrs & !FILE_ATTRIBUTE_READONLY.0;
                let clear_basic = FILE_BASIC_INFO {
                    FileAttributes: if stripped == 0 {
                        FILE_ATTRIBUTE_NORMAL.0
                    } else {
                        stripped
                    },
                    ..Default::default()
                };
                // SAFETY: Attempt to clear readonly attribute if legacy driver requires it.
                let _ = unsafe {
                    SetFileInformationByHandle(
                        handle,
                        FileBasicInfo,
                        &clear_basic as *const _ as *const c_void,
                        std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                    )
                };
            }

            let disp_legacy = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: handle was opened with DELETE rights; disp_legacy is a valid struct.
            let res3 = unsafe {
                SetFileInformationByHandle(
                    handle,
                    FileDispositionInfo,
                    &disp_legacy as *const _ as *const c_void,
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            };
            if res3.is_ok() {
                return Ok(());
            }

            // SAFETY: GetLastError is queried immediately after failure.
            let err3 = unsafe { GetLastError() };
            if err3 == ERROR_DIR_NOT_EMPTY {
                return Err(DeleteError::DirNotEmpty);
            }
            if err3 == ERROR_SHARING_VIOLATION {
                return Err(DeleteError::SharingViolation);
            }
            if err3 == ERROR_ACCESS_DENIED {
                return Err(DeleteError::AccessDenied);
            }
            return Err(DeleteError::Other(err3.0));
        }
        return Err(DeleteError::Other(err2.0));
    }

    Err(DeleteError::Other(err1.0))
}

/// Queries the 64-bit file ID for a path on disk using the specified [`FileIdKind`].
pub fn query_file_id(path: &Path, kind: FileIdKind) -> Result<u64> {
    let wide = path_to_wide_null(path);
    // SAFETY: wide is a valid null-terminated UTF-16 wide string.
    let h_res = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    };
    let handle = match h_res {
        Ok(h) => h,
        Err(_) => {
            // SAFETY: GetLastError is queried immediately after CreateFileW fails.
            let err = unsafe { GetLastError() };
            return Err(DskError::Win32 {
                ctx: "CreateFileW(query_file_id)",
                code: err.0,
            });
        }
    };
    let _guard = HandleGuard(handle);
    let id_info = get_file_id_info(handle)?;
    Ok(extract_file_id(kind, &id_info))
}

/// Executes safe, handle-based deletion of items planned under a single [`PlannedRoot`].
///
/// Enforces §9.3 guarantees:
/// 1. Verifies non-overridable global deny rules on root and every target item.
/// 2. Verifies root handle is not a reparse point and matches `root_file_id`.
/// 3. Normalizes root path and verifies all target items resolve strictly beneath root.
/// 4. Verifies target item handles match planned `expected_file_id` (preventing TOCTOU swap).
/// 5. Skips offline/cloud files and items younger than `min_age_days`.
/// 6. Deletes via verified handle fallback without re-opening by path.
pub fn safe_clean_root(
    rule_root: &PlannedRoot,
    deny_ctx: &DenyContext,
    dry_run: bool,
    now_min2000: u32,
    cancel: &AtomicBool,
) -> Result<CleanRootReport> {
    // 1. Verify global deny list on rule root before ANY Win32 open.
    assert_not_denied(Path::new(&rule_root.root_path), deny_ctx)?;

    // 2. Open root handle h_root with FILE_READ_ATTRIBUTES | SYNCHRONIZE and backup/reparse flags.
    let root_wide = path_to_wide_null(Path::new(&rule_root.root_path));
    // SAFETY: root_wide is a valid null-terminated UTF-16 wide string.
    let h_root_res = unsafe {
        CreateFileW(
            PCWSTR(root_wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    };
    let h_root = match h_root_res {
        Ok(h) => h,
        Err(_) => {
            // SAFETY: GetLastError is queried immediately after CreateFileW failure.
            let err = unsafe { GetLastError() };
            if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                return Ok(CleanRootReport::default());
            }
            return Err(DskError::Win32 {
                ctx: "CreateFileW(root)",
                code: err.0,
            });
        }
    };
    let _root_guard = HandleGuard(h_root);

    // Verify h_root is NOT itself a reparse point.
    let root_basic = get_basic_info(h_root)?;
    if root_basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Ok(CleanRootReport {
            outcomes: vec![ItemOutcome {
                path: rule_root.root_path.clone(),
                file_id: rule_root.root_file_id,
                bytes: 0,
                kind: DeleteOutcomeKind::Failed,
                detail: Some("rule root is a reparse point".to_string()),
            }],
            deleted_bytes: 0,
            deleted_count: 0,
            skipped_count: 0,
            failed_count: 1,
        });
    }

    // Check FileIdInfo on h_root against root_file_id when pinned.
    if rule_root.file_id_kind != FileIdKind::Unpinned && rule_root.root_file_id != 0 {
        match get_file_id_info(h_root) {
            Ok(root_id_info) => {
                let actual_root_id = extract_file_id(rule_root.file_id_kind, &root_id_info);
                if actual_root_id != rule_root.root_file_id {
                    return Ok(CleanRootReport {
                        outcomes: vec![ItemOutcome {
                            path: rule_root.root_path.clone(),
                            file_id: rule_root.root_file_id,
                            bytes: 0,
                            kind: DeleteOutcomeKind::Failed,
                            detail: Some(format!(
                                "root file ID mismatch: expected {}, got {}",
                                rule_root.root_file_id, actual_root_id
                            )),
                        }],
                        deleted_bytes: 0,
                        deleted_count: 0,
                        skipped_count: 0,
                        failed_count: 1,
                    });
                }
            }
            Err(e) => {
                return Ok(CleanRootReport {
                    outcomes: vec![ItemOutcome {
                        path: rule_root.root_path.clone(),
                        file_id: rule_root.root_file_id,
                        bytes: 0,
                        kind: DeleteOutcomeKind::Failed,
                        detail: Some(format!("failed to query root file id: {e}")),
                    }],
                    deleted_bytes: 0,
                    deleted_count: 0,
                    skipped_count: 0,
                    failed_count: 1,
                });
            }
        }
    }

    // Capture canonical normalized DOS root path.
    let root_final_path = final_path_by_handle(h_root)?;
    assert_not_denied(&root_final_path, deny_ctx)?;

    let mut report = CleanRootReport::default();

    // 3. Walk items (ordered deepest-first post-order).
    for item in &rule_root.items {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        // Validate rel_path components to prevent escaping rule_root.root_path before CreateFileW
        let rel_clean = item.rel_path.trim_start_matches(['/', '\\']);
        let rel_path_obj = Path::new(rel_clean);
        let mut comp_count = 0usize;
        let mut is_safe = true;
        for comp in rel_path_obj.components() {
            comp_count += 1;
            if !matches!(comp, std::path::Component::Normal(_)) {
                is_safe = false;
                break;
            }
        }
        if comp_count == 0 || !is_safe {
            report.failed_count += 1;
            report.outcomes.push(ItemOutcome {
                path: format!(r"{}\{}", rule_root.root_path, item.rel_path),
                file_id: item.expected_file_id,
                bytes: item.bytes,
                kind: DeleteOutcomeKind::Failed,
                detail: Some("unsafe relative path".to_string()),
            });
            continue;
        }

        let full_path = Path::new(&rule_root.root_path).join(rel_clean);

        // Before acting on target: verify not denied.
        assert_not_denied(&full_path, deny_ctx)?;

        // Verify excluded filenames aren't touched.
        if let Some(file_name) = Path::new(&item.rel_path).file_name() {
            let name_lossy = file_name.to_string_lossy();
            if rule_root
                .exclude_names
                .iter()
                .any(|ex| ex.eq_ignore_ascii_case(&name_lossy))
            {
                report.outcomes.push(ItemOutcome {
                    path: full_path.to_string_lossy().into_owned(),
                    file_id: item.expected_file_id,
                    bytes: item.bytes,
                    kind: DeleteOutcomeKind::Skipped,
                    detail: Some("excluded filename".to_string()),
                });
                report.skipped_count += 1;
                continue;
            }
        }

        // Open target handle h_item with DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE.
        let item_wide = path_to_wide_null(&full_path);
        // SAFETY: item_wide is a valid null-terminated UTF-16 wide string.
        let h_item_res = unsafe {
            CreateFileW(
                PCWSTR(item_wide.as_ptr()),
                DELETE.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        };

        let h_item = match h_item_res {
            Ok(h) => h,
            Err(_) => {
                // SAFETY: GetLastError is queried immediately after CreateFileW failure.
                let err = unsafe { GetLastError() };
                let (kind, detail) = if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                    (DeleteOutcomeKind::Skipped, Some("already gone".to_string()))
                } else if err == ERROR_SHARING_VIOLATION {
                    (
                        DeleteOutcomeKind::Skipped,
                        Some("sharing violation".to_string()),
                    )
                } else if err == ERROR_ACCESS_DENIED {
                    (
                        DeleteOutcomeKind::Skipped,
                        Some("access denied".to_string()),
                    )
                } else {
                    (
                        DeleteOutcomeKind::Failed,
                        Some(format!("open failed: Win32 {}", err.0)),
                    )
                };
                if kind == DeleteOutcomeKind::Skipped {
                    report.skipped_count += 1;
                } else {
                    report.failed_count += 1;
                }
                report.outcomes.push(ItemOutcome {
                    path: full_path.to_string_lossy().into_owned(),
                    file_id: item.expected_file_id,
                    bytes: item.bytes,
                    kind,
                    detail,
                });
                continue;
            }
        };
        let _item_guard = HandleGuard(h_item);

        // Verify GetFileInformationByHandleEx(FileIdInfo) matches expected_file_id.
        if rule_root.file_id_kind != FileIdKind::Unpinned && item.expected_file_id != 0 {
            match get_file_id_info(h_item) {
                Ok(id_info) => {
                    let actual_id = extract_file_id(rule_root.file_id_kind, &id_info);
                    if actual_id != item.expected_file_id {
                        report.failed_count += 1;
                        report.outcomes.push(ItemOutcome {
                            path: full_path.to_string_lossy().into_owned(),
                            file_id: item.expected_file_id,
                            bytes: item.bytes,
                            kind: DeleteOutcomeKind::Failed,
                            detail: Some(format!(
                                "file ID mismatch: expected {}, got {}",
                                item.expected_file_id, actual_id
                            )),
                        });
                        continue;
                    }
                }
                Err(e) => {
                    report.failed_count += 1;
                    report.outcomes.push(ItemOutcome {
                        path: full_path.to_string_lossy().into_owned(),
                        file_id: item.expected_file_id,
                        bytes: item.bytes,
                        kind: DeleteOutcomeKind::Failed,
                        detail: Some(format!("failed to query file id: {e}")),
                    });
                    continue;
                }
            }
        }

        // Verify GetFinalPathNameByHandleW(h_item) is strictly nested under root_final_path.
        let item_final = match final_path_by_handle(h_item) {
            Ok(p) => p,
            Err(e) => {
                report.failed_count += 1;
                report.outcomes.push(ItemOutcome {
                    path: full_path.to_string_lossy().into_owned(),
                    file_id: item.expected_file_id,
                    bytes: item.bytes,
                    kind: DeleteOutcomeKind::Failed,
                    detail: Some(format!("failed to query final path: {e}")),
                });
                continue;
            }
        };

        if let Err(e) = assert_not_denied(&item_final, deny_ctx) {
            report.failed_count += 1;
            report.outcomes.push(ItemOutcome {
                path: full_path.to_string_lossy().into_owned(),
                file_id: item.expected_file_id,
                bytes: item.bytes,
                kind: DeleteOutcomeKind::Failed,
                detail: Some(format!("canonical item path denied: {e}")),
            });
            continue;
        }

        if !is_strictly_nested(&item_final, &root_final_path) {
            report.failed_count += 1;
            report.outcomes.push(ItemOutcome {
                path: full_path.to_string_lossy().into_owned(),
                file_id: item.expected_file_id,
                bytes: item.bytes,
                kind: DeleteOutcomeKind::Failed,
                detail: Some("path escaped rule root".to_string()),
            });
            continue;
        }

        // Query FileBasicInfo attributes.
        let basic = match get_basic_info(h_item) {
            Ok(b) => b,
            Err(e) => {
                report.failed_count += 1;
                report.outcomes.push(ItemOutcome {
                    path: full_path.to_string_lossy().into_owned(),
                    file_id: item.expected_file_id,
                    bytes: item.bytes,
                    kind: DeleteOutcomeKind::Failed,
                    detail: Some(format!("failed to query basic info: {e}")),
                });
                continue;
            }
        };

        let attrs = basic.FileAttributes;
        if attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN.0 != 0
            || attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0 != 0
            || attrs & FILE_ATTRIBUTE_OFFLINE.0 != 0
        {
            report.skipped_count += 1;
            report.outcomes.push(ItemOutcome {
                path: full_path.to_string_lossy().into_owned(),
                file_id: item.expected_file_id,
                bytes: item.bytes,
                kind: DeleteOutcomeKind::Skipped,
                detail: Some("cloud or offline file".to_string()),
            });
            continue;
        }

        // Check live modification time against min_age_days for files.
        if !item.is_dir
            && let Some(min_age) = rule_root.min_age_days
        {
            let mtime_ft = basic.LastWriteTime.max(0) as u64;
            let mtime_mins = filetime_to_min2000(mtime_ft);
            let threshold_mins = min_age.saturating_mul(1440);
            let age_mins = now_min2000.saturating_sub(mtime_mins);
            if age_mins < threshold_mins {
                report.skipped_count += 1;
                report.outcomes.push(ItemOutcome {
                    path: full_path.to_string_lossy().into_owned(),
                    file_id: item.expected_file_id,
                    bytes: item.bytes,
                    kind: DeleteOutcomeKind::Skipped,
                    detail: Some("modified recently".to_string()),
                });
                continue;
            }
        }

        // Perform deletion or dry-run record.
        if dry_run {
            report.deleted_count += 1;
            report.deleted_bytes += item.bytes;
            report.outcomes.push(ItemOutcome {
                path: full_path.to_string_lossy().into_owned(),
                file_id: item.expected_file_id,
                bytes: item.bytes,
                kind: DeleteOutcomeKind::Deleted,
                detail: None,
            });
        } else {
            match delete_handle(h_item, basic.FileAttributes) {
                Ok(()) => {
                    report.deleted_count += 1;
                    report.deleted_bytes += item.bytes;
                    report.outcomes.push(ItemOutcome {
                        path: full_path.to_string_lossy().into_owned(),
                        file_id: item.expected_file_id,
                        bytes: item.bytes,
                        kind: DeleteOutcomeKind::Deleted,
                        detail: None,
                    });
                }
                Err(DeleteError::DirNotEmpty) => {
                    report.skipped_count += 1;
                    report.outcomes.push(ItemOutcome {
                        path: full_path.to_string_lossy().into_owned(),
                        file_id: item.expected_file_id,
                        bytes: item.bytes,
                        kind: DeleteOutcomeKind::Skipped,
                        detail: Some("directory not empty".to_string()),
                    });
                }
                Err(DeleteError::SharingViolation) => {
                    report.skipped_count += 1;
                    report.outcomes.push(ItemOutcome {
                        path: full_path.to_string_lossy().into_owned(),
                        file_id: item.expected_file_id,
                        bytes: item.bytes,
                        kind: DeleteOutcomeKind::Skipped,
                        detail: Some("sharing violation".to_string()),
                    });
                }
                Err(DeleteError::AccessDenied) => {
                    report.skipped_count += 1;
                    report.outcomes.push(ItemOutcome {
                        path: full_path.to_string_lossy().into_owned(),
                        file_id: item.expected_file_id,
                        bytes: item.bytes,
                        kind: DeleteOutcomeKind::Skipped,
                        detail: Some("access denied".to_string()),
                    });
                }
                Err(DeleteError::Other(code)) => {
                    report.failed_count += 1;
                    report.outcomes.push(ItemOutcome {
                        path: full_path.to_string_lossy().into_owned(),
                        file_id: item.expected_file_id,
                        bytes: item.bytes,
                        kind: DeleteOutcomeKind::Failed,
                        detail: Some(format!("delete failed: Win32 {code}")),
                    });
                }
            }
        }
    }

    Ok(report)
}
