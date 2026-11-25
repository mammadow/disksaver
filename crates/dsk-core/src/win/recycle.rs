//! Guarded Windows Shell recycle, open, and reveal primitives.
//!
//! Provides safe item recycling via modern COM `IFileOperation` configured with
//! `FOFX_RECYCLEONDELETE`, guaranteed pre-flight deny-list checks, canonical path
//! resolution, reparse point rejection, and RAII-managed COM STA apartment state.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{
    CloseHandle, E_ABORT, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError, HANDLE,
    RPC_E_CHANGED_MODE, S_FALSE, S_OK,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileBasicInfo, FileStandardInfo,
    GetFileInformationByHandleEx, OPEN_EXISTING, SYNCHRONIZE,
};
use windows::Win32::System::Com::{
    CLSCTX_ALL, COINIT, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};
use windows::Win32::UI::Shell::Common::ITEMIDLIST;
use windows::Win32::UI::Shell::{
    FILEOPERATION_FLAGS, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_NORECURSEREPARSE,
    FOF_SILENT, FOFX_RECYCLEONDELETE, FileOperation, IFileOperation, IFileOperationProgressSink,
    IFileOperationProgressSink_Impl, ILCreateFromPathW, ILFree, IShellItem,
    SHCreateItemFromParsingName, SHOpenFolderAndSelectItems, ShellExecuteW,
    TSF_DELETE_RECYCLE_IF_POSSIBLE,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};
use windows_core::{AsImpl, implement};

use crate::clean::DenyContext;
use crate::clean::deny::{assert_not_denied, is_denied_for_owner_replacement};
use crate::error::{DskError, Result};
use crate::win::cleaner::final_path_by_handle;

/// Outcome report returned after successfully moving an item to the Recycle Bin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecycleOutcome {
    pub path: String,
    pub canonical_path: String,
    pub bytes_hint: u64,
}

/// RAII guard ensuring a Win32 HANDLE is closed when leaving scope.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: self.0 is an active, open Win32 HANDLE uniquely owned by this guard.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Returns `true` when the Shell is about to send the item to the Recycle Bin. Without
/// `TSF_DELETE_RECYCLE_IF_POSSIBLE` the delete would be permanent (item larger than the bin quota,
/// or a volume/share without a Recycle Bin).
fn shell_delete_will_recycle(dwflags: u32) -> bool {
    dwflags & (TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32) != 0
}

/// Progress sink that vetoes any delete the Shell cannot route to the Recycle Bin.
///
/// `FOF_NOCONFIRMATION` would otherwise silently auto-answer the Shell's "This item is too big to
/// recycle. Delete permanently?" prompt with *yes*.
#[implement(IFileOperationProgressSink)]
struct RecycleOnlySink {
    refused_permanent_delete: AtomicBool,
}

impl IFileOperationProgressSink_Impl for RecycleOnlySink_Impl {
    fn StartOperations(&self) -> windows::core::Result<()> {
        Ok(())
    }
    fn FinishOperations(&self, _hr: windows::core::HRESULT) -> windows::core::Result<()> {
        Ok(())
    }
    fn PreRenameItem(
        &self,
        _f: u32,
        _i: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PostRenameItem(
        &self,
        _f: u32,
        _i: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
        _hr: windows::core::HRESULT,
        _c: windows_core::Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PreMoveItem(
        &self,
        _f: u32,
        _i: windows_core::Ref<IShellItem>,
        _d: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PostMoveItem(
        &self,
        _f: u32,
        _i: windows_core::Ref<IShellItem>,
        _d: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
        _hr: windows::core::HRESULT,
        _c: windows_core::Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PreCopyItem(
        &self,
        _f: u32,
        _i: windows_core::Ref<IShellItem>,
        _d: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PostCopyItem(
        &self,
        _f: u32,
        _i: windows_core::Ref<IShellItem>,
        _d: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
        _hr: windows::core::HRESULT,
        _c: windows_core::Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PreDeleteItem(
        &self,
        dwflags: u32,
        _item: windows_core::Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        if shell_delete_will_recycle(dwflags) {
            Ok(())
        } else {
            self.refused_permanent_delete.store(true, Ordering::SeqCst);
            Err(E_ABORT.into())
        }
    }
    fn PostDeleteItem(
        &self,
        _f: u32,
        _i: windows_core::Ref<IShellItem>,
        _hr: windows::core::HRESULT,
        _c: windows_core::Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PreNewItem(
        &self,
        _f: u32,
        _d: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn PostNewItem(
        &self,
        _f: u32,
        _d: windows_core::Ref<IShellItem>,
        _n: &PCWSTR,
        _t: &PCWSTR,
        _a: u32,
        _hr: windows::core::HRESULT,
        _i: windows_core::Ref<IShellItem>,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn UpdateProgress(&self, _total: u32, _so_far: u32) -> windows::core::Result<()> {
        Ok(())
    }
    fn ResetTimer(&self) -> windows::core::Result<()> {
        Ok(())
    }
    fn PauseTimer(&self) -> windows::core::Result<()> {
        Ok(())
    }
    fn ResumeTimer(&self) -> windows::core::Result<()> {
        Ok(())
    }
}

/// RAII guard managing a COM single-threaded apartment (STA).
struct ComApartmentGuard {
    need_uninit: bool,
}

impl ComApartmentGuard {
    fn new() -> Result<Self> {
        // SAFETY: CoInitializeEx is called with standard STA flags for Shell COM operations.
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
            Err(DskError::Win32 {
                ctx: "CoInitializeEx",
                code: hr.0 as u32,
            })
        }
    }
}

impl Drop for ComApartmentGuard {
    fn drop(&mut self) {
        if self.need_uninit {
            // SAFETY: CoUninitialize balances successful S_OK/S_FALSE CoInitializeEx.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

/// RAII guard ensuring an `ITEMIDLIST` allocated by `ILCreateFromPathW` is freed.
struct PidlGuard(*mut ITEMIDLIST);

impl Drop for PidlGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is an ITEMIDLIST pointer allocated by ILCreateFromPathW.
            unsafe {
                ILFree(Some(self.0.cast_const()));
            }
        }
    }
}

/// Normalizes a filesystem path into an absolute, backslash-delimited, null-terminated
/// UTF-16 wide string prefixed with `\\?\` (or `\\?\UNC\` for network shares).
fn path_to_wide_null(p: &Path) -> Vec<u16> {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut wide: Vec<u16> = abs.as_os_str().encode_wide().collect();

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

/// Converts a canonical path into a Shell-compatible wide string, stripping `\\?\`
/// for paths under 260 characters and mapping `\\?\UNC\` to `\\`.
fn canonical_to_shell_wide(canonical: &Path) -> Vec<u16> {
    let s = canonical.to_string_lossy();
    let clean = if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        if stripped.len() < 260 {
            stripped.to_string()
        } else {
            s.to_string()
        }
    } else {
        s.to_string()
    };
    clean.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Moves an item (file or directory) to the Windows Recycle Bin using COM `IFileOperation`.
///
/// # Safety Guarantees & Constraints
/// 1. Lexical `assert_not_denied(path, deny_ctx)?` is checked before opening any handle.
/// 2. Pre-flight handle is opened with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`.
/// 3. Direct reparse points and junctions are rejected with `DskError::Unsupported`.
/// 4. Cloud and offline placeholders are rejected with `DskError::DeniedPath`.
/// 5. Canonical DOS path is resolved via `final_path_by_handle` and re-verified against `DenyContext`.
/// 6. Inspection handle is explicitly closed and dropped before instantiating COM `IFileOperation`.
/// 7. COM `IFileOperation` is executed with `FOFX_RECYCLEONDELETE` and abort status is verified.
pub fn move_to_recycle_bin(path: &Path, deny_ctx: &DenyContext) -> Result<RecycleOutcome> {
    recycle_impl(path, deny_ctx, false)
}

/// Recycles the original of a file DiskSaver has just replaced with a verified smaller copy
/// (video compression), at the owner's explicit request.
///
/// Identical to [`move_to_recycle_bin`] except that the personal-library rule is lifted (the
/// owner picked this file, often in `Videos`) and only a single regular file is accepted: every
/// other deny rule, the reparse/cloud checks, and the canonical-path re-check still apply, and a
/// directory is refused.
pub fn recycle_replaced_original(path: &Path, deny_ctx: &DenyContext) -> Result<RecycleOutcome> {
    recycle_impl(path, deny_ctx, true)
}

fn recycle_impl(
    path: &Path,
    deny_ctx: &DenyContext,
    owner_replacement: bool,
) -> Result<RecycleOutcome> {
    let check = |p: &Path| -> Result<()> {
        if owner_replacement {
            match is_denied_for_owner_replacement(p, deny_ctx) {
                Some(reason) => Err(DskError::DeniedPath(format!("{} ({reason})", p.display()))),
                None => Ok(()),
            }
        } else {
            assert_not_denied(p, deny_ctx)
        }
    };
    // 1. Lexical check before opening any filesystem handle
    check(path)?;

    // 2. Pre-flight inspection handle scope: must close before COM invocation
    let (canonical_path, bytes_hint) = {
        let wide = path_to_wide_null(path);
        // SAFETY: wide is a valid null-terminated UTF-16 wide string.
        let handle = unsafe {
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
        let handle = match handle {
            Ok(h) => h,
            Err(_) => {
                // SAFETY: GetLastError is called immediately after CreateFileW failure.
                let err = unsafe { GetLastError() };
                if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                    return Err(DskError::Io(std::io::Error::from_raw_os_error(
                        err.0 as i32,
                    )));
                }
                return Err(DskError::Win32 {
                    ctx: "CreateFileW(recycle_inspect)",
                    code: err.0,
                });
            }
        };
        let _handle_guard = HandleGuard(handle);

        let mut basic_info = FILE_BASIC_INFO::default();
        // SAFETY: handle is an active Win32 handle. basic_info is a valid stack struct.
        let res = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                &mut basic_info as *mut _ as *mut c_void,
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if res.is_err() {
            let err = unsafe { GetLastError() };
            return Err(DskError::Win32 {
                ctx: "GetFileInformationByHandleEx(FileBasicInfo)",
                code: err.0,
            });
        }

        // Reject direct reparse points or junctions
        if (basic_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
            return Err(DskError::Unsupported(
                "cannot recycle reparse point or junction directly".into(),
            ));
        }

        // Reject cloud or offline placeholders
        let cloud_flags = FILE_ATTRIBUTE_RECALL_ON_OPEN.0
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0
            | FILE_ATTRIBUTE_OFFLINE.0;
        if (basic_info.FileAttributes & cloud_flags) != 0 {
            return Err(DskError::DeniedPath(
                "cloud or offline placeholder cannot be recycled".into(),
            ));
        }

        // Canonical path via GetFinalPathNameByHandleW
        let canonical = final_path_by_handle(handle)?;
        check(&canonical)?;

        // bytes_hint: FileStandardInfo (EndOfFile) for files, 0 for directories
        let is_dir = (basic_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
        if owner_replacement && is_dir {
            return Err(DskError::Unsupported(
                "only a single replaced file can be recycled this way, not a folder".into(),
            ));
        }
        let bytes_hint = if !is_dir {
            let mut std_info = FILE_STANDARD_INFO::default();
            // SAFETY: handle is an active Win32 handle. std_info is a valid stack struct.
            let res = unsafe {
                GetFileInformationByHandleEx(
                    handle,
                    FileStandardInfo,
                    &mut std_info as *mut _ as *mut c_void,
                    std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
                )
            };
            if res.is_err() {
                let err = unsafe { GetLastError() };
                return Err(DskError::Win32 {
                    ctx: "GetFileInformationByHandleEx(FileStandardInfo)",
                    code: err.0,
                });
            }
            std_info.EndOfFile as u64
        } else {
            0
        };

        (canonical, bytes_hint)
    }; // _handle_guard dropped here, handle closed before instantiating COM IFileOperation!

    // 3. Shell COM invocation
    let _com_guard = ComApartmentGuard::new()?;

    // SAFETY: COM is initialized; CoCreateInstance creates a standard FileOperation object.
    let file_op: IFileOperation = unsafe { CoCreateInstance(&FileOperation, None, CLSCTX_ALL) }
        .map_err(|e| DskError::Win32 {
            ctx: "CoCreateInstance(FileOperation)",
            code: e.code().0 as u32,
        })?;

    let flags = FOF_ALLOWUNDO.0
        | FOFX_RECYCLEONDELETE.0
        | FOF_NORECURSEREPARSE.0
        | FOF_NOERRORUI.0
        | FOF_SILENT.0
        | FOF_NOCONFIRMATION.0;

    // SAFETY: file_op is an active IFileOperation interface.
    unsafe { file_op.SetOperationFlags(FILEOPERATION_FLAGS(flags)) }.map_err(|e| {
        DskError::Win32 {
            ctx: "IFileOperation::SetOperationFlags",
            code: e.code().0 as u32,
        }
    })?;

    let shell_wide = canonical_to_shell_wide(&canonical_path);
    // SAFETY: shell_wide is a valid null-terminated wide string.
    let item: IShellItem = unsafe {
        SHCreateItemFromParsingName(PCWSTR(shell_wide.as_ptr()), None)
    }
    .map_err(|e| DskError::Win32 {
        ctx: "SHCreateItemFromParsingName",
        code: e.code().0 as u32,
    })?;

    // Veto anything the Shell would delete permanently instead of recycling.
    let sink_obj = RecycleOnlySink {
        refused_permanent_delete: AtomicBool::new(false),
    };
    let sink: IFileOperationProgressSink = sink_obj.into();
    // SAFETY: `sink` is a live COM object implementing IFileOperationProgressSink.
    let cookie = unsafe { file_op.Advise(&sink) }.map_err(|e| DskError::Win32 {
        ctx: "IFileOperation::Advise",
        code: e.code().0 as u32,
    })?;

    // SAFETY: item is a valid IShellItem.
    let staged = unsafe { file_op.DeleteItem(&item, None) }.map_err(|e| DskError::Win32 {
        ctx: "IFileOperation::DeleteItem",
        code: e.code().0 as u32,
    });

    // SAFETY: PerformOperations executes the staged delete operation.
    let performed = staged.and_then(|()| {
        unsafe { file_op.PerformOperations() }.map_err(|e| DskError::Win32 {
            ctx: "IFileOperation::PerformOperations",
            code: e.code().0 as u32,
        })
    });

    // SAFETY: `cookie` was returned by Advise on this same IFileOperation.
    unsafe {
        let _ = file_op.Unadvise(cookie);
    }

    // SAFETY: `sink` wraps a `RecycleOnlySink`; `as_impl` borrows it for the flag read.
    let refused = unsafe { sink.as_impl() }
        .refused_permanent_delete
        .load(Ordering::SeqCst);
    if refused {
        return Err(DskError::DeniedPath(format!(
            "'{}' cannot be moved to the Recycle Bin (too large for the bin, or the volume has no Recycle Bin); permanent deletion refused",
            canonical_path.display()
        )));
    }
    performed?;

    // SAFETY: file_op is an active IFileOperation interface.
    let aborted = unsafe { file_op.GetAnyOperationsAborted() }.map_err(|e| DskError::Win32 {
        ctx: "IFileOperation::GetAnyOperationsAborted",
        code: e.code().0 as u32,
    })?;

    if aborted.as_bool() {
        return Err(DskError::Cancelled);
    }

    Ok(RecycleOutcome {
        path: path.to_string_lossy().into_owned(),
        canonical_path: canonical_path.to_string_lossy().into_owned(),
        bytes_hint,
    })
}

/// Opens the specified file or folder using the default registered Windows Shell handler.
pub fn open_item(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is empty",
        )));
    }
    if !path.exists() {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("path does not exist: {}", path.display()),
        )));
    }

    let wide = canonical_to_shell_wide(path);
    // SAFETY: ShellExecuteW is invoked with valid null-terminated strings and SW_SHOWNORMAL.
    let hinst = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(wide.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };

    let code = hinst.0 as isize;
    if code <= 32 {
        return Err(DskError::Win32 {
            ctx: "ShellExecuteW(open)",
            code: code as u32,
        });
    }

    Ok(())
}

/// Reveals the specified file or folder in Windows File Explorer, selecting the item.
pub fn reveal_in_explorer(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is empty",
        )));
    }
    if !path.exists() {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("path does not exist: {}", path.display()),
        )));
    }

    let _com_guard = ComApartmentGuard::new()?;

    let wide = canonical_to_shell_wide(path);
    // SAFETY: ILCreateFromPathW parses a valid null-terminated wide path.
    let pidl = unsafe { ILCreateFromPathW(PCWSTR(wide.as_ptr())) };
    if pidl.is_null() {
        let err = unsafe { GetLastError() };
        return Err(DskError::Win32 {
            ctx: "ILCreateFromPathW",
            code: err.0,
        });
    }
    let pidl_guard = PidlGuard(pidl);

    // SAFETY: pidl_guard.0 is a valid ITEMIDLIST. Passing apidl = None selects the target inside its parent.
    unsafe { SHOpenFolderAndSelectItems(pidl_guard.0, None, 0) }.map_err(|e| DskError::Win32 {
        ctx: "SHOpenFolderAndSelectItems",
        code: e.code().0 as u32,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn recycle_only_sink_vetoes_permanent_deletes() {
        assert!(shell_delete_will_recycle(
            TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32
        ));
        assert!(!shell_delete_will_recycle(0));

        let sink: IFileOperationProgressSink = RecycleOnlySink {
            refused_permanent_delete: AtomicBool::new(false),
        }
        .into();
        // SAFETY: Calling the sink through its own COM interface with a null item.
        let recyclable = unsafe {
            sink.PreDeleteItem(TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32, None::<&IShellItem>)
        };
        assert!(recyclable.is_ok());
        assert!(
            !unsafe { sink.as_impl() }
                .refused_permanent_delete
                .load(Ordering::SeqCst)
        );

        // SAFETY: As above; flags without TSF_DELETE_RECYCLE_IF_POSSIBLE = permanent delete.
        let permanent = unsafe { sink.PreDeleteItem(0, None::<&IShellItem>) };
        assert_eq!(permanent.unwrap_err().code(), E_ABORT);
        assert!(
            unsafe { sink.as_impl() }
                .refused_permanent_delete
                .load(Ordering::SeqCst)
        );
    }

    #[test]
    fn recycle_rejects_denied_paths_and_drive_roots() {
        let deny = DenyContext::default_for_test();

        let sys32 = Path::new(r"C:\Windows\System32");
        let res = move_to_recycle_bin(sys32, &deny);
        assert!(
            matches!(res, Err(DskError::DeniedPath(_))),
            "expected DeniedPath, got {:?}",
            res
        );

        let docs = Path::new(r"C:\Users\Alice\Documents");
        let res = move_to_recycle_bin(docs, &deny);
        assert!(
            matches!(res, Err(DskError::DeniedPath(_))),
            "expected DeniedPath, got {:?}",
            res
        );

        let root = Path::new(r"C:\");
        let res = move_to_recycle_bin(root, &deny);
        assert!(
            matches!(res, Err(DskError::DeniedPath(_))),
            "expected DeniedPath, got {:?}",
            res
        );
    }

    #[test]
    fn recycle_rejects_junction_and_ancestor_junction_into_denied_path() {
        let dir = tempdir().expect("tempdir");
        let target_dir = dir.path().join("real_target");
        fs::create_dir(&target_dir).expect("create real_target");
        let link_dir = dir.path().join("junction_link");

        // Create directory junction pointing link_dir -> target_dir
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link_dir)
            .arg(&target_dir)
            .status()
            .expect("mklink /J execution");
        assert!(status.success(), "mklink /J succeeded");

        let deny = DenyContext::default_for_test();

        // 1. Leaf junction refusal
        let res_leaf = move_to_recycle_bin(&link_dir, &deny);
        assert!(
            matches!(&res_leaf, Err(DskError::Unsupported(msg)) if msg.contains("reparse point")),
            "expected Unsupported reparse point error, got {:?}",
            res_leaf
        );

        // Target directory must remain intact on disk
        assert!(target_dir.exists(), "target_dir must still exist");

        // 2. Ancestor junction into denied directory
        let sys_link = dir.path().join("sys_junc");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&sys_link)
            .arg(r"C:\Windows\System32")
            .status()
            .expect("mklink /J execution to System32");
        assert!(status.success(), "mklink /J to System32 succeeded");

        // An item under sys_link (e.g. cmd.exe) resolves to C:\Windows\System32
        let file_under_junc = sys_link.join("cmd.exe");
        if file_under_junc.exists() {
            let res_ancestor = move_to_recycle_bin(&file_under_junc, &deny);
            assert!(
                matches!(res_ancestor, Err(DskError::DeniedPath(_))),
                "expected DeniedPath for ancestor junction to System32, got {:?}",
                res_ancestor
            );
        }
    }

    #[test]
    fn recycle_missing_file_returns_clean_error() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("does_not_exist_at_all.txt");
        let deny = DenyContext::default_for_test();

        let res = move_to_recycle_bin(&missing, &deny);
        assert!(
            matches!(res, Err(DskError::Io(_))),
            "expected Io error, got {:?}",
            res
        );
    }

    #[test]
    fn open_and_reveal_reject_empty_and_missing_paths() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("not_there.txt");
        let empty = Path::new("");

        assert!(matches!(open_item(empty), Err(DskError::Io(_))));
        assert!(matches!(open_item(&missing), Err(DskError::Io(_))));

        assert!(matches!(reveal_in_explorer(empty), Err(DskError::Io(_))));
        assert!(matches!(reveal_in_explorer(&missing), Err(DskError::Io(_))));
    }

    #[test]
    #[ignore = "mutates Windows Recycle Bin"]
    fn recycle_real_temp_file_smoke() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("disksaver_test_recycle.tmp");
        fs::write(&file, b"hello recycle bin").expect("write temp file");
        assert!(file.exists());

        let deny = DenyContext::from_env();
        let outcome = move_to_recycle_bin(&file, &deny).expect("recycle smoke");
        assert_eq!(outcome.bytes_hint, 17);
        assert!(!file.exists(), "file should be moved to recycle bin");
    }
}
