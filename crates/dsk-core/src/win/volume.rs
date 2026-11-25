use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_ALL_ASSIGNED, GENERIC_READ, GetLastError,
    HANDLE, LUID, SetLastError, WIN32_ERROR,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDiskFreeSpaceExW,
    GetDiskFreeSpaceW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW, GetVolumePathNameW,
    OPEN_EXISTING, ReadFile,
};
use windows::Win32::System::IO::{DeviceIoControl, OVERLAPPED};
use windows::Win32::System::Ioctl::{
    DEVICE_SEEK_PENALTY_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
    STORAGE_PROPERTY_QUERY, StorageDeviceSeekPenaltyProperty,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOTE, DRIVE_REMOVABLE};
use windows::core::PCWSTR;

use crate::error::{DskError, Result};
use crate::ntfs::boot::{BootSector, parse_boot_sector};
use crate::ntfs::mft::SectorReader;
use crate::volume::VolumeInfo;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

fn win32_err(ctx: &'static str, err: windows::core::Error) -> DskError {
    let raw = err.code().0 as u32;
    let code = if (raw & 0xFFFF_0000) == 0x8007_0000 {
        raw & 0xFFFF
    } else {
        raw
    };
    DskError::Win32 { ctx, code }
}

/// Normalizes valid drive-letter volume roots (`C:`, `C:\`, `\\?\C:\`, case-insensitive)
/// to `Some(format!("{UPPER}:\\"))`. Returns `None` for subfolders, relative drive paths,
/// or non-root paths.
pub fn volume_root_of(path: &Path) -> Option<String> {
    let s = path.to_str()?;
    let rest = s.strip_prefix(r"\\?\").unwrap_or(s);
    let bytes = rest.as_bytes();

    let is_two_char_root = bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let is_three_char_root = bytes.len() == 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');

    if is_two_char_root || is_three_char_root {
        Some(format!("{}:\\", bytes[0].to_ascii_uppercase() as char))
    } else {
        None
    }
}

/// Queries volume metadata for the specified drive root.
pub fn volume_info(root: &str) -> Result<VolumeInfo> {
    let norm_root =
        volume_root_of(Path::new(root)).ok_or_else(|| DskError::NotVolumeRoot(root.to_string()))?;
    let drive_letter = norm_root
        .chars()
        .next()
        .ok_or_else(|| DskError::NotVolumeRoot(root.to_string()))?;

    let long_root = format!(r"\\?\{}:\", drive_letter);
    let root_w = to_wide(&long_root);

    let mut serial = 0u32;
    let mut fs_buf = [0u16; 260];
    unsafe {
        GetVolumeInformationW(
            PCWSTR(root_w.as_ptr()),
            None,
            Some(&mut serial),
            None,
            None,
            Some(&mut fs_buf[..]),
        )
    }
    .map_err(|e| win32_err("GetVolumeInformationW", e))?;

    let fs_len = fs_buf.iter().position(|&c| c == 0).unwrap_or(fs_buf.len());
    let fs_name = String::from_utf16_lossy(&fs_buf[..fs_len]);

    let mut free_bytes_avail = 0u64;
    let mut total_bytes = 0u64;
    let mut free_bytes = 0u64;
    unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(root_w.as_ptr()),
            Some(&mut free_bytes_avail),
            Some(&mut total_bytes),
            Some(&mut free_bytes),
        )
    }
    .map_err(|e| win32_err("GetDiskFreeSpaceExW", e))?;

    let mut sectors_per_cluster = 0u32;
    let mut bytes_per_sector = 0u32;
    let mut free_clusters = 0u32;
    let mut total_clusters = 0u32;
    unsafe {
        GetDiskFreeSpaceW(
            PCWSTR(root_w.as_ptr()),
            Some(&mut sectors_per_cluster),
            Some(&mut bytes_per_sector),
            Some(&mut free_clusters),
            Some(&mut total_clusters),
        )
    }
    .map_err(|e| win32_err("GetDiskFreeSpaceW", e))?;
    let cluster_size = sectors_per_cluster.saturating_mul(bytes_per_sector);

    let dev_path = format!(r"\\.\{}:", drive_letter);
    let dev_w = to_wide(&dev_path);
    let seek_penalty = unsafe {
        let handle_res = CreateFileW(
            PCWSTR(dev_w.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        );

        match handle_res {
            Ok(h) => {
                let query = STORAGE_PROPERTY_QUERY {
                    PropertyId: StorageDeviceSeekPenaltyProperty,
                    QueryType: PropertyStandardQuery,
                    AdditionalParameters: [0],
                };
                let mut desc = DEVICE_SEEK_PENALTY_DESCRIPTOR::default();
                let mut bytes_returned = 0u32;
                let ioctl_res = DeviceIoControl(
                    h,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    Some(&query as *const _ as *const c_void),
                    core::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                    Some(&mut desc as *mut _ as *mut c_void),
                    core::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
                    Some(&mut bytes_returned),
                    None,
                );
                let _ = CloseHandle(h);

                if ioctl_res.is_ok()
                    && bytes_returned as usize
                        >= core::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>()
                {
                    Some(desc.IncursSeekPenalty)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    };

    Ok(VolumeInfo {
        root: long_root,
        fs_name,
        serial,
        cluster_size,
        total_bytes,
        free_bytes,
        seek_penalty,
    })
}

/// Enumerates mounted fixed and removable volumes.
///
/// Returns volumes sorted alphabetically by drive root. Transient unready or
/// inaccessible drives (such as empty card reader slots) are skipped cleanly.
pub fn list_volumes() -> Result<Vec<VolumeInfo>> {
    // SAFETY: GetLogicalDrives takes no parameters and has no memory preconditions.
    let drives_mask = unsafe { GetLogicalDrives() };
    if drives_mask == 0 {
        // SAFETY: GetLastError retrieves the calling thread's last-error code value.
        let err = unsafe { GetLastError() };
        if err.0 != 0 {
            return Err(DskError::Win32 {
                ctx: "GetLogicalDrives",
                code: err.0,
            });
        }
        return Ok(Vec::new());
    }

    let mut volumes = Vec::new();
    for i in 0u8..26 {
        if (drives_mask & (1 << i)) == 0 {
            continue;
        }

        let letter = (b'A' + i) as char;
        let root = format!("{}:\\", letter);
        let root_w = to_wide(&root);

        // SAFETY: GetDriveTypeW receives a valid null-terminated UTF-16 drive root path (e.g. "C:\").
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(root_w.as_ptr())) };
        if drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE {
            continue;
        }

        // Skip transient unready or inaccessible volumes cleanly (e.g. empty card reader slots).
        if let Ok(info) = volume_info(&root) {
            volumes.push(info);
        }
    }

    Ok(volumes)
}

/// Checks whether the current process token is elevated.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok.is_err() {
        return false;
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut ret_len = 0u32;
    let res = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            core::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    unsafe {
        let _ = CloseHandle(token);
    }

    res.is_ok() && elevation.TokenIsElevated != 0
}

/// Attempts to enable a security privilege for the current process token.
pub fn enable_privilege(name: &str) -> Result<bool> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| win32_err("OpenProcessToken", e))?;

    let name_w = to_wide(name);
    let mut luid = LUID::default();
    let luid_res = unsafe { LookupPrivilegeValueW(None, PCWSTR(name_w.as_ptr()), &mut luid) };
    if let Err(e) = luid_res {
        unsafe {
            let _ = CloseHandle(token);
        }
        return Err(win32_err("LookupPrivilegeValueW", e));
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        SetLastError(WIN32_ERROR(0));
    }
    let adj_res = unsafe {
        AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            core::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
    };
    let last_err = unsafe { GetLastError() };
    unsafe {
        let _ = CloseHandle(token);
    }

    if let Err(e) = adj_res {
        return Err(win32_err("AdjustTokenPrivileges", e));
    }
    if last_err == ERROR_NOT_ALL_ASSIGNED {
        Ok(false)
    } else if last_err == WIN32_ERROR(0) {
        Ok(true)
    } else {
        Err(DskError::Win32 {
            ctx: "AdjustTokenPrivileges",
            code: last_err.0,
        })
    }
}

/// Raw volume handle wrapper for sector-level access.
#[derive(Debug)]
pub struct VolumeHandle {
    handle: HANDLE,
}

unsafe impl Send for VolumeHandle {}
unsafe impl Sync for VolumeHandle {}

impl Drop for VolumeHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl VolumeHandle {
    fn read_direct(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut bytes_read_total = 0;
        while bytes_read_total < buf.len() {
            let curr_offset = offset + bytes_read_total as u64;
            let mut overlapped = OVERLAPPED::default();
            overlapped.Anonymous.Anonymous.Offset = curr_offset as u32;
            overlapped.Anonymous.Anonymous.OffsetHigh = (curr_offset >> 32) as u32;

            let remaining = buf.len() - bytes_read_total;
            let chunk_len = remaining.min(u32::MAX as usize) as u32;
            let target = &mut buf[bytes_read_total..bytes_read_total + chunk_len as usize];
            let mut bytes_read = 0u32;
            let res = unsafe {
                ReadFile(
                    self.handle,
                    Some(target),
                    Some(&mut bytes_read),
                    Some(&mut overlapped),
                )
            };
            if let Err(e) = res {
                return Err(win32_err("ReadFile", e));
            }
            if bytes_read == 0 {
                return Err(DskError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF reading volume",
                )));
            }
            bytes_read_total += bytes_read as usize;
        }
        Ok(())
    }

    /// Reads and parses the NTFS boot sector.
    pub fn boot_sector(&self) -> Result<BootSector> {
        let mut buf = [0u8; 4096];
        self.read_at(0, &mut buf)?;
        parse_boot_sector(&buf).map_err(Into::into)
    }
}

impl SectorReader for VolumeHandle {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        match self.read_direct(offset, buf) {
            Ok(()) => Ok(()),
            Err(DskError::Win32 {
                ctx: "ReadFile",
                code,
            }) if code == ERROR_INVALID_PARAMETER.0
                && (!offset.is_multiple_of(4096) || !buf.len().is_multiple_of(4096)) =>
            {
                let aligned_start = (offset / 4096) * 4096;
                let start_offset = (offset - aligned_start) as usize;
                let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
                    DskError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "offset overflow",
                    ))
                })?;
                let aligned_end = end.div_ceil(4096) * 4096;
                let aligned_len = (aligned_end - aligned_start) as usize;
                let mut bounce = vec![0u8; aligned_len];
                self.read_direct(aligned_start, &mut bounce)?;
                buf.copy_from_slice(&bounce[start_offset..start_offset + buf.len()]);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// Opens a volume for raw sector reads.
pub fn open_volume(root: &str) -> Result<VolumeHandle> {
    let norm_root =
        volume_root_of(Path::new(root)).ok_or_else(|| DskError::NotVolumeRoot(root.to_string()))?;
    let drive_letter = norm_root
        .chars()
        .next()
        .ok_or_else(|| DskError::NotVolumeRoot(root.to_string()))?;

    let dev_path = format!(r"\\.\{}:", drive_letter);
    let dev_w = to_wide(&dev_path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(dev_w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| win32_err("CreateFileW", e))?;

    Ok(VolumeHandle { handle })
}

/// Returns the peak working set size of the current process in bytes.
pub fn peak_working_set() -> u64 {
    let mut pmc = PROCESS_MEMORY_COUNTERS {
        cb: core::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    let res = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) };
    if res.is_ok() {
        pmc.PeakWorkingSetSize as u64
    } else {
        0
    }
}

/// Resolves the canonical Windows `System32` directory via Shell KnownFolder (`FOLDERID_System`),
/// falling back to `C:\Windows\System32` without trusting mutable process environment variables (§10.7).
pub fn system32_dir() -> std::path::PathBuf {
    // SAFETY: Querying FOLDERID_System known folder path; returned PWSTR is freed via CoTaskMemFree.
    unsafe {
        if let Ok(pwstr) = windows::Win32::UI::Shell::SHGetKnownFolderPath(
            &windows::Win32::UI::Shell::FOLDERID_System,
            windows::Win32::UI::Shell::KF_FLAG_DEFAULT,
            None,
        ) {
            let path_opt = pwstr.to_string().ok();
            windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.0 as *const c_void));
            if let Some(path_str) = path_opt
                && !path_str.is_empty()
            {
                return std::path::PathBuf::from(path_str);
            }
        }
    }
    std::path::PathBuf::from(r"C:\Windows\System32")
}

/// Resolves the native `Program Files` directory via Shell KnownFolder (`FOLDERID_ProgramFiles`),
/// falling back to `C:\Program Files` without trusting mutable environment variables.
pub fn program_files_dir() -> std::path::PathBuf {
    // SAFETY: Querying FOLDERID_ProgramFiles known folder path; returned PWSTR is freed via CoTaskMemFree.
    unsafe {
        if let Ok(pwstr) = windows::Win32::UI::Shell::SHGetKnownFolderPath(
            &windows::Win32::UI::Shell::FOLDERID_ProgramFiles,
            windows::Win32::UI::Shell::KF_FLAG_DEFAULT,
            None,
        ) {
            let path_opt = pwstr.to_string().ok();
            windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.0 as *const c_void));
            if let Some(path_str) = path_opt
                && !path_str.is_empty()
            {
                return std::path::PathBuf::from(path_str);
            }
        }
    }
    std::path::PathBuf::from(r"C:\Program Files")
}

/// Resolves `Program Files (x86)` via Shell KnownFolder (`FOLDERID_ProgramFilesX86`), falling back
/// to `C:\Program Files (x86)` without trusting environment variables.
pub fn program_files_x86_dir() -> std::path::PathBuf {
    // SAFETY: Querying a known folder path; the returned PWSTR is freed via CoTaskMemFree.
    unsafe {
        if let Ok(pwstr) = windows::Win32::UI::Shell::SHGetKnownFolderPath(
            &windows::Win32::UI::Shell::FOLDERID_ProgramFilesX86,
            windows::Win32::UI::Shell::KF_FLAG_DEFAULT,
            None,
        ) {
            let path_opt = pwstr.to_string().ok();
            windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.0 as *const c_void));
            if let Some(path_str) = path_opt
                && !path_str.is_empty()
            {
                return std::path::PathBuf::from(path_str);
            }
        }
    }
    std::path::PathBuf::from(r"C:\Program Files (x86)")
}

/// Normalizes a path lexically to resolve its mount root directory (e.g. `"C:\\"` or a mounted
/// folder root) via `GetVolumePathNameW`. Returns `None` for UNC network paths or relative paths
/// that cannot be resolved to a local mount root.
pub fn path_volume_mount_root(path: &Path) -> Option<String> {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Reject UNC network paths explicitly (`\\server\share` or `\\?\UNC\server\share`).
    if trimmed.starts_with(r"\\?\UNC\")
        || trimmed.starts_with(r"\\?\unc\")
        || (trimmed.starts_with(r"\\") && !trimmed.starts_with(r"\\?\"))
    {
        return None;
    }

    // Walk up to the deepest existing ancestor so GetVolumePathNameW works even when targeting a
    // subfolder whose leaf directory has not yet been created.
    let abs = std::path::absolute(path).ok()?;
    for anc in abs.ancestors() {
        if anc.exists() {
            let anc_w = to_wide(&anc.to_string_lossy());
            let mut vol_buf = [0u16; 1024];
            // SAFETY: anc_w is null-terminated and vol_buf is an allocated writable UTF-16 slice.
            if unsafe { GetVolumePathNameW(PCWSTR(anc_w.as_ptr()), &mut vol_buf) }.is_ok() {
                let len = vol_buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(vol_buf.len());
                if len > 0 {
                    let mut mount = String::from_utf16_lossy(&vol_buf[..len]);
                    if !mount.ends_with('\\') {
                        mount.push('\\');
                    }
                    return Some(mount);
                }
            }
            break;
        }
    }

    let abs_s = abs.to_string_lossy();
    let rest = abs_s.strip_prefix(r"\\?\").unwrap_or(&abs_s);
    let bytes = rest.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some(format!("{}:\\", bytes[0].to_ascii_uppercase() as char));
    }

    None
}

/// Queries the Windows `GetDriveTypeW` value (`DRIVE_FIXED`, `DRIVE_REMOVABLE`, `DRIVE_REMOTE`,
/// etc.) for the volume hosting `path`. Returns `Some(DRIVE_REMOTE)` for UNC paths and `None`
/// if no drive root can be determined.
pub fn query_path_drive_type(path: &Path) -> Option<u32> {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.starts_with(r"\\?\UNC\")
        || trimmed.starts_with(r"\\?\unc\")
        || (trimmed.starts_with(r"\\") && !trimmed.starts_with(r"\\?\"))
    {
        return Some(DRIVE_REMOTE);
    }

    let mount_root = path_volume_mount_root(path)?;
    let root_w = to_wide(&mount_root);
    // SAFETY: root_w is a null-terminated volume mount path.
    let dt = unsafe { GetDriveTypeW(PCWSTR(root_w.as_ptr())) };
    Some(dt)
}

/// Validates that a queried `GetDriveTypeW` result represents `DRIVE_FIXED` (3), failing closed on
/// `None`, removable media (`DRIVE_REMOVABLE`), network shares (`DRIVE_REMOTE`), CD-ROMs, RAM
/// disks, or unknown/missing roots.
pub fn validate_drive_type_is_fixed(drive_type: Option<u32>, path: &Path) -> Result<()> {
    match drive_type {
        Some(dt) if dt == DRIVE_FIXED => Ok(()),
        Some(dt) if dt == DRIVE_REMOVABLE => Err(DskError::Optimize(format!(
            "removable drive is not supported for this operation: '{}' (drive_type={dt})",
            path.display()
        ))),
        Some(dt) if dt == DRIVE_REMOTE => Err(DskError::Optimize(format!(
            "network/UNC drive is not supported for this operation: '{}' (drive_type={dt})",
            path.display()
        ))),
        Some(dt) => Err(DskError::Optimize(format!(
            "non-fixed volume is not supported for this operation: '{}' (drive_type={dt})",
            path.display()
        ))),
        None => Err(DskError::Optimize(format!(
            "unable to determine volume drive type for '{}' (refusing fail-open)",
            path.display()
        ))),
    }
}

/// Verifies `path` resides on a local `DRIVE_FIXED` volume and returns `(mount_root, free_bytes)`.
pub fn require_fixed_drive_and_free_bytes(path: &Path) -> Result<(String, u64)> {
    let dt = query_path_drive_type(path);
    validate_drive_type_is_fixed(dt, path)?;

    let mount_root = path_volume_mount_root(path).ok_or_else(|| {
        DskError::Optimize(format!(
            "unable to resolve hosting volume root for '{}'",
            path.display()
        ))
    })?;
    let root_w = to_wide(&mount_root);
    let mut free_avail = 0u64;
    let mut total = 0u64;
    let mut free = 0u64;
    // SAFETY: root_w is a null-terminated mount root and pointers reference valid stack integers.
    unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(root_w.as_ptr()),
            Some(&mut free_avail),
            Some(&mut total),
            Some(&mut free),
        )
    }
    .map_err(|e| win32_err("GetDiskFreeSpaceExW", e))?;

    Ok((mount_root, free_avail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_drive_info() {
        let v = volume_info("C:\\").unwrap();
        assert_eq!(v.fs_name, "NTFS");
        assert!(v.cluster_size >= 512 && v.total_bytes > v.free_bytes);
        assert_eq!(v.root, "\\\\?\\C:\\");
    }

    #[test]
    fn list_volumes_includes_system_drive_and_valid_metadata() {
        let vols = list_volumes().expect("list_volumes should succeed");
        assert!(!vols.is_empty(), "expected at least one mounted volume");
        let c = vols
            .iter()
            .find(|v| v.root.ends_with(r"C:\") || v.root == r"\\?\C:\")
            .expect("system drive C:\\ should be in mounted volume list");
        assert!(
            c.total_bytes > 0,
            "system drive should have positive total bytes"
        );
        assert!(
            !c.fs_name.is_empty(),
            "system drive should have non-empty fs_name"
        );
        // Verify sorted order
        for w in vols.windows(2) {
            assert!(
                w[0].root < w[1].root,
                "volumes should be sorted alphabetically by root: {:?} vs {:?}",
                w[0].root,
                w[1].root
            );
        }
    }

    #[test]
    fn root_detection() {
        assert_eq!(volume_root_of(Path::new("C:")).as_deref(), Some("C:\\"));
        assert_eq!(volume_root_of(Path::new("c:")).as_deref(), Some("C:\\"));
        assert_eq!(volume_root_of(Path::new("C:\\")).as_deref(), Some("C:\\"));
        assert_eq!(volume_root_of(Path::new("c:/")).as_deref(), Some("C:\\"));
        assert_eq!(
            volume_root_of(Path::new(r"\\?\C:\")).as_deref(),
            Some("C:\\")
        );
        assert_eq!(
            volume_root_of(Path::new(r"\\?\c:\")).as_deref(),
            Some("C:\\")
        );
        assert_eq!(
            volume_root_of(Path::new(r"\\?\C:")).as_deref(),
            Some("C:\\")
        );
        assert_eq!(volume_root_of(Path::new(r"C:\Users")), None);
        assert_eq!(volume_root_of(Path::new(r"C:foo")), None);
        assert_eq!(volume_root_of(Path::new(r"foo")), None);
        assert_eq!(volume_root_of(Path::new(r"")), None);
        assert_eq!(volume_root_of(Path::new(r"\\.\C:")), None);
        assert_eq!(volume_root_of(Path::new(r"1:\")), None);
    }

    #[test]
    fn volume_info_invalid_path() {
        let err = volume_info(r"C:\Users").unwrap_err();
        match err {
            DskError::NotVolumeRoot(path) => assert_eq!(path, r"C:\Users"),
            other => panic!("expected NotVolumeRoot, got {:?}", other),
        }
    }

    #[test]
    fn open_volume_invalid_path() {
        let err = open_volume(r"C:\Users").unwrap_err();
        match err {
            DskError::NotVolumeRoot(path) => assert_eq!(path, r"C:\Users"),
            other => panic!("expected NotVolumeRoot, got {:?}", other),
        }
    }

    #[test]
    fn elevation_and_working_set_smoke() {
        let _ = is_elevated();
        let ws = peak_working_set();
        assert!(ws > 0);

        let _ = enable_privilege("SeBackupPrivilege");
    }

    #[test]
    fn fixed_drive_validation_and_query_rejects_unc_removable_and_none() {
        assert_eq!(
            query_path_drive_type(Path::new(r"C:\Windows")),
            Some(DRIVE_FIXED)
        );
        assert_eq!(
            query_path_drive_type(Path::new(r"\\server\share\folder")),
            Some(DRIVE_REMOTE)
        );
        assert!(validate_drive_type_is_fixed(Some(DRIVE_FIXED), Path::new(r"C:\Temp")).is_ok());
        assert!(validate_drive_type_is_fixed(Some(DRIVE_REMOVABLE), Path::new(r"E:\USB")).is_err());
        assert!(validate_drive_type_is_fixed(Some(DRIVE_REMOTE), Path::new(r"\\srv\s")).is_err());
        assert!(validate_drive_type_is_fixed(None, Path::new("relative_or_bad")).is_err());

        let (mount_root, free_bytes) =
            require_fixed_drive_and_free_bytes(&std::env::temp_dir()).unwrap();
        assert!(!mount_root.is_empty());
        assert!(free_bytes > 0);
        assert!(require_fixed_drive_and_free_bytes(Path::new(r"\\server\share\dir")).is_err());
    }

    #[test]
    #[ignore = "needs admin"]
    fn reads_boot_sector() {
        let h = open_volume("C:\\").unwrap();
        assert_eq!(
            h.boot_sector().unwrap().cluster_size() as u32,
            volume_info("C:\\").unwrap().cluster_size
        );
    }
}
