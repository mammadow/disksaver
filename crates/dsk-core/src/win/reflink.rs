//! Win32 cloud-safe file opening, NTFS read-only hardlinks, ReFS extent cloning,
//! and NTFS Last-Access-Timestamp registry inspection for P6 Insights.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use windows::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, CreateHardLinkW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileBasicInfo, FileIdInfo, GetFileInformationByHandleEx,
    GetFileSizeEx, MOVEFILE_REPLACE_EXISTING, MoveFileExW, OPEN_EXISTING, SetFileAttributesW,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{DUPLICATE_EXTENTS_DATA, FSCTL_DUPLICATE_EXTENTS_TO_FILE};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
    RegQueryValueExW,
};
use windows::core::PCWSTR;

use crate::error::{DskError, Result};
use crate::win::volume::{path_volume_mount_root, volume_info};
use crate::win::wof::allocated_file_size;

const ATTR_RECALL_ON_OPEN: u32 = 0x0004_0000;
const ATTR_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

static TEMP_CLONE_SEQ: AtomicU64 = AtomicU64::new(1);

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: HandleGuard uniquely owns an open Win32 HANDLE until released.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct RegKeyGuard(HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: RegKeyGuard owns an open HKEY from RegOpenKeyExW.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

fn has_blocked_read_attrs(attrs: u32) -> bool {
    let blocked = FILE_ATTRIBUTE_DIRECTORY.0
        | FILE_ATTRIBUTE_REPARSE_POINT.0
        | FILE_ATTRIBUTE_OFFLINE.0
        | ATTR_RECALL_ON_OPEN
        | ATTR_RECALL_ON_DATA_ACCESS;
    (attrs & blocked) != 0
}

fn query_handle_basic_info(handle: HANDLE) -> Result<FILE_BASIC_INFO> {
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: handle is open; basic is stack-allocated with exact FILE_BASIC_INFO byte length.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            &mut basic as *mut _ as *mut c_void,
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }
    .map_err(|e| DskError::Win32 {
        ctx: "GetFileInformationByHandleEx(FileBasicInfo)",
        code: (e.code().0 as u32) & 0xFFFF,
    })?;
    Ok(basic)
}

fn query_handle_file_id_128(handle: HANDLE) -> Result<u128> {
    let mut id_info = FILE_ID_INFO::default();
    // SAFETY: handle is open; id_info receives FILE_ID_INFO for the open file.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &mut id_info as *mut _ as *mut c_void,
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|e| DskError::Win32 {
        ctx: "GetFileInformationByHandleEx(FileIdInfo)",
        code: (e.code().0 as u32) & 0xFFFF,
    })?;
    Ok(u128::from_le_bytes(id_info.FileId.Identifier))
}

/// Opens a regular local file read-only while guaranteeing zero cloud placeholder hydration
/// (`CLOUD`, `OFFLINE`, `REPARSE_POINT`, `RECALL_ON_OPEN`, `RECALL_ON_DATA_ACCESS`) and rejecting
/// directory/reparse swap TOCTOU before returning the `std::fs::File`.
pub fn open_cloud_safe_read(path: &Path) -> Result<File> {
    let wide = to_wide(&path.to_string_lossy());

    // 1. Probe attributes WITHOUT requesting read access (cannot trigger cloud recall on open).
    // SAFETY: wide is null-terminated; FILE_FLAG_OPEN_REPARSE_POINT inspects links directly.
    let attr_handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(
                FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0,
            ),
            None,
        )
    }
    .map_err(|e| DskError::Win32 {
        ctx: "CreateFileW(attr_probe)",
        code: (e.code().0 as u32) & 0xFFFF,
    })?;
    let _attr_guard = HandleGuard(attr_handle);

    let pre_basic = query_handle_basic_info(attr_handle)?;
    if has_blocked_read_attrs(pre_basic.FileAttributes) {
        return Err(DskError::PreconditionFailed(format!(
            "skipping cloud/offline/reparse/non-regular file without hydrating: {}",
            path.display()
        )));
    }
    drop(_attr_guard);

    // 2. Open sequential read handle WITH FILE_FLAG_OPEN_REPARSE_POINT and re-verify handle attributes.
    // SAFETY: wide is null-terminated; re-checking FileBasicInfo on the handle closes TOCTOU swaps.
    let read_handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_SEQUENTIAL_SCAN.0),
            None,
        )
    }
    .map_err(|e| DskError::Win32 {
        ctx: "CreateFileW(open_cloud_safe_read)",
        code: (e.code().0 as u32) & 0xFFFF,
    })?;
    let read_guard = HandleGuard(read_handle);

    let post_basic = query_handle_basic_info(read_handle)?;
    if has_blocked_read_attrs(post_basic.FileAttributes) {
        return Err(DskError::PreconditionFailed(format!(
            "file attributes changed to cloud/offline/reparse before reading: {}",
            path.display()
        )));
    }

    let raw = read_handle.0 as RawHandle;
    std::mem::forget(read_guard);
    // SAFETY: raw is a valid, uniquely owned open Win32 file handle verified regular and non-reparse.
    Ok(unsafe { File::from_raw_handle(raw) })
}

/// Queries whether NTFS Last-Access-Timestamp updates are disabled via
/// `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate`.
///
/// Returns `Some(true)` when bit 0 is set (last-access updates disabled by policy/system),
/// `Some(false)` when updates are enabled, or `None` if unavailable.
pub fn query_last_access_disabled() -> Option<bool> {
    let subkey = to_wide(r"SYSTEM\CurrentControlSet\Control\FileSystem");
    let mut hkey = HKEY::default();
    // SAFETY: Querying standard HKLM FileSystem configuration key read-only.
    let open_res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if open_res.0 != 0 {
        return None;
    }
    let _guard = RegKeyGuard(hkey);

    let value_name = to_wide("NtfsDisableLastAccessUpdate");
    let mut val_type = REG_VALUE_TYPE(0);
    let mut data = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: Stack DWORD buffer with explicit size for NtfsDisableLastAccessUpdate.
    let q_res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut val_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        )
    };
    if q_res.0 == 0 && val_type == REG_DWORD && size == size_of::<u32>() as u32 {
        Some((data & 1) != 0)
    } else {
        None
    }
}

fn validate_same_regular_non_reparse_pair(first: &Path, second: &Path) -> Result<(u64, bool)> {
    let f1 = open_cloud_safe_read(first)?;
    let f2 = open_cloud_safe_read(second)?;
    let len1 = f1.metadata()?.len();
    let len2 = f2.metadata()?.len();
    if len1 != len2 {
        return Err(DskError::PreconditionFailed(format!(
            "size mismatch between '{}' ({len1} B) and '{}' ({len2} B)",
            first.display(),
            second.display()
        )));
    }

    let r1 = path_volume_mount_root(first);
    let r2 = path_volume_mount_root(second);
    if r1.is_none() || r1 != r2 {
        return Err(DskError::Unsupported(format!(
            "cross-volume hardlink/reflink is not supported ('{}' -> '{}')",
            first.display(),
            second.display()
        )));
    }

    use std::os::windows::io::AsRawHandle;
    let id1 = query_handle_file_id_128(HANDLE(f1.as_raw_handle()))?;
    let id2 = query_handle_file_id_128(HANDLE(f2.as_raw_handle()))?;
    Ok((len1, id1 == id2))
}

fn unique_sibling_temp_path(target: &Path, tag: &str) -> Result<PathBuf> {
    let parent = target.parent().ok_or_else(|| {
        DskError::Optimize(format!(
            "missing parent directory for '{}'",
            target.display()
        ))
    })?;
    let seq = TEMP_CLONE_SEQ.fetch_add(1, Ordering::Relaxed);
    let stem = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    Ok(parent.join(format!(".{stem}.{tag}.{}.{seq}.tmp", std::process::id())))
}

struct TempPathCleanup(Option<PathBuf>);

impl Drop for TempPathCleanup {
    fn drop(&mut self) {
        if let Some(ref p) = self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Size + last-write stamp captured before content verification, re-checked right before an
/// atomic replacement so a write that lands after hashing is never silently discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
    pub len: u64,
    pub last_write: u64,
}

/// Reads a [`FileStamp`] from metadata only (no data access, never hydrates cloud files).
pub fn file_stamp(path: &Path) -> Result<FileStamp> {
    use std::os::windows::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path)?;
    Ok(FileStamp {
        len: m.len(),
        last_write: m.last_write_time(),
    })
}

fn ensure_unchanged(path: &Path, expected: Option<FileStamp>) -> Result<()> {
    if let Some(exp) = expected
        && file_stamp(path)? != exp
    {
        return Err(DskError::PreconditionFailed(format!(
            "'{}' changed after it was verified; not replaced",
            path.display()
        )));
    }
    Ok(())
}

/// Replaces `duplicate` atomically with an NTFS hard link to `canonical` and sets
/// `FILE_ATTRIBUTE_READONLY` to protect shared hardlink extents from accidental in-place mutation.
///
/// Note that attributes belong to the file record, so after linking the keeper becomes read-only
/// too. `expected` = `(duplicate, canonical)` stamps taken before hashing; they are re-checked
/// immediately before the swap.
///
/// Returns the reclaimed allocated bytes (`0` if both paths already share the same FileId).
pub fn replace_with_readonly_hardlink(
    duplicate: &Path,
    canonical: &Path,
    expected: Option<(FileStamp, FileStamp)>,
) -> Result<u64> {
    let (_size, already_linked) = validate_same_regular_non_reparse_pair(duplicate, canonical)?;
    if already_linked {
        return Ok(0);
    }

    let before_alloc = allocated_file_size(duplicate).unwrap_or(0);
    let temp_link = unique_sibling_temp_path(duplicate, "dskhl")?;
    let mut temp_guard = TempPathCleanup(Some(temp_link.clone()));

    let tmp_w = to_wide(&temp_link.to_string_lossy());
    let canon_w = to_wide(&canonical.to_string_lossy());
    // SAFETY: Creating sibling hard link referencing canonical before atomic MoveFileExW swap.
    unsafe { CreateHardLinkW(PCWSTR(tmp_w.as_ptr()), PCWSTR(canon_w.as_ptr()), None) }.map_err(
        |e| DskError::Win32 {
            ctx: "CreateHardLinkW",
            code: (e.code().0 as u32) & 0xFFFF,
        },
    )?;

    let dup_w = to_wide(&duplicate.to_string_lossy());

    // Last-moment check: a write after hashing must not be thrown away by the swap.
    ensure_unchanged(duplicate, expected.map(|e| e.0))?;
    ensure_unchanged(canonical, expected.map(|e| e.1))?;

    // Ensure existing destination doesn't block MoveFileExW(MOVEFILE_REPLACE_EXISTING) if marked readonly.
    let mut restore_attrs = None;
    if let Ok(meta) = std::fs::symlink_metadata(duplicate) {
        use std::os::windows::fs::MetadataExt;
        let attrs = meta.file_attributes();
        if (attrs & FILE_ATTRIBUTE_READONLY.0) != 0 {
            // SAFETY: Clearing readonly only on confirmed duplicate prior to immediate atomic replacement.
            let cleared = unsafe {
                SetFileAttributesW(
                    PCWSTR(dup_w.as_ptr()),
                    FILE_FLAGS_AND_ATTRIBUTES(attrs & !FILE_ATTRIBUTE_READONLY.0),
                )
            };
            if cleared.is_ok() {
                restore_attrs = Some(attrs);
            }
        }
    }

    // SAFETY: Both tmp_w and dup_w reside on the same volume; MOVEFILE_REPLACE_EXISTING atomically swaps.
    let moved = unsafe {
        MoveFileExW(
            PCWSTR(tmp_w.as_ptr()),
            PCWSTR(dup_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING,
        )
    };
    if let Err(e) = moved {
        if let Some(attrs) = restore_attrs {
            // SAFETY: Restoring the duplicate's original attributes after a failed swap.
            let _ = unsafe {
                SetFileAttributesW(PCWSTR(dup_w.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(attrs))
            };
        }
        return Err(DskError::Win32 {
            ctx: "MoveFileExW(replace_hardlink)",
            code: (e.code().0 as u32) & 0xFFFF,
        });
    }
    temp_guard.0 = None;

    // Mark resulting hardlink read-only so shared extents are protected against accidental writes.
    if let Ok(meta) = std::fs::symlink_metadata(duplicate) {
        use std::os::windows::fs::MetadataExt;
        let attrs = meta.file_attributes() | FILE_ATTRIBUTE_READONLY.0;
        // SAFETY: Setting FILE_ATTRIBUTE_READONLY on replaced hardlink path.
        let _ =
            unsafe { SetFileAttributesW(PCWSTR(dup_w.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(attrs)) };
    }

    Ok(before_alloc)
}

/// Attempts block-extent cloning (`FSCTL_DUPLICATE_EXTENTS_TO_FILE`) on ReFS volumes so
/// `target` shares physical blocks with `source` independently (copy-on-write).
///
/// Returns `DskError::Unsupported` cleanly on NTFS/FAT32 or non-block-cloning volumes.
/// `expected` = `(target, source)` stamps taken before hashing; re-checked right before the swap.
pub fn clone_file_extents_refs(
    source: &Path,
    target: &Path,
    expected: Option<(FileStamp, FileStamp)>,
) -> Result<u64> {
    let (file_len, already_linked) = validate_same_regular_non_reparse_pair(source, target)?;
    if already_linked || file_len == 0 {
        return Ok(0);
    }

    let mount_root = path_volume_mount_root(target).ok_or_else(|| {
        DskError::Unsupported(format!(
            "unable to resolve volume for '{}'",
            target.display()
        ))
    })?;
    let vol = volume_info(&mount_root)?;
    if !vol.fs_name.eq_ignore_ascii_case("ReFS") {
        return Err(DskError::Unsupported(format!(
            "block cloning requires ReFS volume (found '{}')",
            vol.fs_name
        )));
    }

    let cluster = (vol.cluster_size as u64).max(4096);
    let aligned_len = file_len.div_ceil(cluster).saturating_mul(cluster);
    if aligned_len > i64::MAX as u64 {
        return Err(DskError::Optimize(
            "file exceeds ReFS duplicate extents maximum length".to_string(),
        ));
    }

    let src_file = open_cloud_safe_read(source)?;
    let before_alloc = allocated_file_size(target).unwrap_or(file_len);
    let temp_clone = unique_sibling_temp_path(target, "dskref")?;
    let mut temp_guard = TempPathCleanup(Some(temp_clone.clone()));
    let temp_w = to_wide(&temp_clone.to_string_lossy());

    // SAFETY: Creating unique sibling staging file on same ReFS volume for atomic block-clone swap.
    let dst_handle = unsafe {
        CreateFileW(
            PCWSTR(temp_w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_DELETE,
            None,
            CREATE_NEW,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| DskError::Win32 {
        ctx: "CreateFileW(clone_temp)",
        code: (e.code().0 as u32) & 0xFFFF,
    })?;
    let _dst_guard = HandleGuard(dst_handle);

    // The source must still be exactly the verified length before its extents are cloned.
    {
        use std::os::windows::io::AsRawHandle;
        let mut src_len_i64 = 0i64;
        // SAFETY: `src_file` is a valid open handle.
        unsafe { GetFileSizeEx(HANDLE(src_file.as_raw_handle()), &mut src_len_i64) }.map_err(
            |e| DskError::Win32 {
                ctx: "GetFileSizeEx",
                code: (e.code().0 as u32) & 0xFFFF,
            },
        )?;
        if src_len_i64 as u64 != file_len {
            return Err(DskError::PreconditionFailed(format!(
                "'{}' changed size during block cloning",
                source.display()
            )));
        }
    }

    {
        use std::os::windows::io::AsRawHandle;
        let dup_data = DUPLICATE_EXTENTS_DATA {
            FileHandle: HANDLE(src_file.as_raw_handle()),
            SourceFileOffset: 0,
            TargetFileOffset: 0,
            ByteCount: aligned_len as i64,
        };
        let mut bytes_returned = 0u32;
        // Size the staging file to the logical length first (FSCTL_DUPLICATE_EXTENTS_TO_FILE
        // requires the target range to exist).
        let eof_info = windows::Win32::Storage::FileSystem::FILE_END_OF_FILE_INFO {
            EndOfFile: file_len as i64,
        };
        // SAFETY: Setting EOF length on open staging file handle before FSCTL_DUPLICATE_EXTENTS_TO_FILE.
        unsafe {
            windows::Win32::Storage::FileSystem::SetFileInformationByHandle(
                dst_handle,
                windows::Win32::Storage::FileSystem::FileEndOfFileInfo,
                &eof_info as *const _ as *const c_void,
                size_of::<windows::Win32::Storage::FileSystem::FILE_END_OF_FILE_INFO>() as u32,
            )
        }
        .map_err(|e| DskError::Win32 {
            ctx: "SetFileInformationByHandle(FileEndOfFileInfo)",
            code: (e.code().0 as u32) & 0xFFFF,
        })?;

        // SAFETY: Both handles live on the same ReFS volume and buffer sizes are exact struct size.
        unsafe {
            DeviceIoControl(
                dst_handle,
                FSCTL_DUPLICATE_EXTENTS_TO_FILE,
                Some(&dup_data as *const _ as *const c_void),
                size_of::<DUPLICATE_EXTENTS_DATA>() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        }
        .map_err(|e| {
            DskError::Unsupported(format!("FSCTL_DUPLICATE_EXTENTS_TO_FILE failed: {e}"))
        })?;
    }
    drop(_dst_guard);

    // Last-moment check: never discard a write that landed after verification.
    ensure_unchanged(target, expected.map(|e| e.0))?;
    ensure_unchanged(source, expected.map(|e| e.1))?;

    let target_w = to_wide(&target.to_string_lossy());
    // SAFETY: Swapping cloned ReFS staging file over original target atomically.
    unsafe {
        MoveFileExW(
            PCWSTR(temp_w.as_ptr()),
            PCWSTR(target_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING,
        )
    }
    .map_err(|e| DskError::Win32 {
        ctx: "MoveFileExW(replace_reflink)",
        code: (e.code().0 as u32) & 0xFFFF,
    })?;
    temp_guard.0 = None;

    Ok(before_alloc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win::junction::{create_mount_point_junction, remove_junction_link_only};
    use tempfile::tempdir;

    #[test]
    fn open_cloud_safe_read_accepts_regular_file_and_rejects_directory_junction_and_offline() {
        let dir = tempdir().unwrap();
        let regular = dir.path().join("plain.bin");
        std::fs::write(&regular, b"hello cloud-safe world").unwrap();

        let mut f = open_cloud_safe_read(&regular).unwrap();
        let mut s = String::new();
        std::io::Read::read_to_string(&mut f, &mut s).unwrap();
        assert_eq!(s, "hello cloud-safe world");

        // Directory is rejected
        assert!(matches!(
            open_cloud_safe_read(dir.path()),
            Err(DskError::PreconditionFailed(_))
        ));

        // Directory junction is rejected
        let real_target = dir.path().join("real");
        let junc = dir.path().join("junc");
        std::fs::create_dir_all(&real_target).unwrap();
        create_mount_point_junction(&junc, &real_target).unwrap();
        assert!(matches!(
            open_cloud_safe_read(&junc),
            Err(DskError::PreconditionFailed(_))
        ));
        let _ = remove_junction_link_only(&junc);

        // Regular file flagged FILE_ATTRIBUTE_OFFLINE is rejected without reading content
        let offline = dir.path().join("offline.bin");
        std::fs::write(&offline, b"must never hydrate").unwrap();
        let wide = to_wide(&offline.to_string_lossy());
        unsafe {
            SetFileAttributesW(
                PCWSTR(wide.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_OFFLINE.0),
            )
            .unwrap();
        }
        assert!(matches!(
            open_cloud_safe_read(&offline),
            Err(DskError::PreconditionFailed(_))
        ));
        unsafe {
            let _ = SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(0x20));
        }
    }

    #[test]
    fn hardlink_replacement_links_file_sets_readonly_and_reflink_reports_unsupported_on_ntfs() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("canon.dat");
        let b = dir.path().join("copy.dat");
        let payload = vec![0x5Au8; 16 * 1024];
        std::fs::write(&a, &payload).unwrap();
        std::fs::write(&b, &payload).unwrap();

        let _reclaimed = replace_with_readonly_hardlink(&b, &a, None).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), payload);
        assert!(std::fs::metadata(&b).unwrap().permissions().readonly());

        // Second call detects matching FileId and returns 0 cleanly
        assert_eq!(replace_with_readonly_hardlink(&b, &a, None).unwrap(), 0);

        // Clear readonly before tempdir drop
        let wide = to_wide(&b.to_string_lossy());
        unsafe {
            let _ = SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(0x20));
        }

        // NTFS rejects ReFS extent cloning cleanly unless tempdir happens to be ReFS
        let c = dir.path().join("copy2.dat");
        std::fs::write(&c, &payload).unwrap();
        let mount = path_volume_mount_root(&a).unwrap();
        if !volume_info(&mount)
            .map(|v| v.fs_name.eq_ignore_ascii_case("ReFS"))
            .unwrap_or(false)
        {
            assert!(matches!(
                clone_file_extents_refs(&a, &c, None),
                Err(DskError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn query_last_access_disabled_returns_valid_option() {
        let _ = query_last_access_disabled();
    }

    #[test]
    fn hardlink_swap_refuses_when_duplicate_changed_after_verification() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("keep.dat");
        let b = dir.path().join("dup.dat");
        let payload = vec![0x11u8; 8192];
        std::fs::write(&a, &payload).unwrap();
        std::fs::write(&b, &payload).unwrap();

        let stamps = (file_stamp(&b).unwrap(), file_stamp(&a).unwrap());
        // A same-size write lands after hashing; pin a distinct mtime so the test does not depend
        // on clock-tick granularity.
        std::fs::write(&b, vec![0x22u8; 8192]).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&b)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000))
            .unwrap();

        let res = replace_with_readonly_hardlink(&b, &a, Some(stamps));
        assert!(
            matches!(res, Err(DskError::PreconditionFailed(ref m)) if m.contains("changed after")),
            "swap must be refused, got {res:?}"
        );
        assert_eq!(
            std::fs::read(&b).unwrap(),
            vec![0x22u8; 8192],
            "new data kept"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp link must be cleaned up");
    }
}
