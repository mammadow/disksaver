//! Win32 directory junction (NTFS Mount Point) primitives.
//!
//! Provides safe abstractions for creating, inspecting, and removing directory junctions
//! using `FSCTL_SET_REPARSE_POINT` and `IO_REPARSE_TAG_MOUNT_POINT` (§8.6).

#![allow(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT,
};
use windows::core::PCWSTR;

use crate::error::{DskError, Result};

const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;
const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;

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

/// Canonicalizes a path into NT namespace format `\??\C:\...` required for NTFS Mount Points.
fn to_nt_namespace_path(path: &Path) -> Result<(String, String)> {
    let abs = std::path::absolute(path).map_err(DskError::Io)?;
    let mut abs_str = abs.to_string_lossy().to_string();

    // Strip \\?\ prefix if present
    if abs_str.starts_with(r"\\?\") {
        abs_str = abs_str[4..].to_string();
    }

    let print_name = abs_str.clone();
    let substitute_name = format!(r"\??\{abs_str}");
    Ok((substitute_name, print_name))
}

/// Creates an NTFS Mount Point directory junction at `link_path` targeting `target_dir`.
///
/// Preconditions:
/// - `link_path` will be created if it does not exist (or must be an empty directory).
/// - `target_dir` must exist.
pub fn create_mount_point_junction(link_path: &Path, target_dir: &Path) -> Result<()> {
    if !target_dir.exists() {
        return Err(DskError::Optimize(format!(
            "junction target does not exist: {}",
            target_dir.display()
        )));
    }

    if !link_path.exists() {
        fs::create_dir_all(link_path)?;
    }

    let (substitute_name, print_name) = to_nt_namespace_path(target_dir)?;

    let sub_w: Vec<u16> = substitute_name.encode_utf16().collect();
    let print_w: Vec<u16> = print_name.encode_utf16().collect();

    // Compute in usize and enforce MAXIMUM_REPARSE_DATA_BUFFER_SIZE (16 KiB) before narrowing: the
    // u16 length fields would otherwise silently wrap for very long targets.
    let sub_bytes = sub_w.len() * 2;
    let print_bytes = print_w.len() * 2;
    let reparse_data_usize = 8 + sub_bytes + 2 + print_bytes + 2;
    if 8 + reparse_data_usize > MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
        return Err(DskError::Optimize(format!(
            "junction target path is too long for a reparse point: {}",
            target_dir.display()
        )));
    }

    let sub_len_bytes = sub_bytes as u16;
    let print_len_bytes = print_bytes as u16;

    let sub_offset = 0u16;
    let print_offset = sub_len_bytes + 2; // + null terminator in buffer

    // ReparseDataLength: 8 bytes for offsets/lengths + path buffer bytes (including nulls)
    let reparse_data_len = reparse_data_usize as u16;

    let total_buffer_size = 8 + reparse_data_len as usize; // 8 bytes header (ReparseTag + ReparseDataLength + Reserved)
    let mut buffer = vec![0u8; total_buffer_size];

    // Header
    buffer[0..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer[4..6].copy_from_slice(&reparse_data_len.to_le_bytes());
    buffer[6..8].copy_from_slice(&0u16.to_le_bytes()); // Reserved

    // MountPointReparseBuffer fields (offset 8)
    buffer[8..10].copy_from_slice(&sub_offset.to_le_bytes());
    buffer[10..12].copy_from_slice(&sub_len_bytes.to_le_bytes());
    buffer[12..14].copy_from_slice(&print_offset.to_le_bytes());
    buffer[14..16].copy_from_slice(&print_len_bytes.to_le_bytes());

    // PathBuffer starts at offset 16
    let sub_dest_start = 16 + sub_offset as usize;
    for (i, &w) in sub_w.iter().enumerate() {
        let b = w.to_le_bytes();
        buffer[sub_dest_start + i * 2] = b[0];
        buffer[sub_dest_start + i * 2 + 1] = b[1];
    }

    let print_dest_start = 16 + print_offset as usize;
    for (i, &w) in print_w.iter().enumerate() {
        let b = w.to_le_bytes();
        buffer[print_dest_start + i * 2] = b[0];
        buffer[print_dest_start + i * 2 + 1] = b[1];
    }

    let link_w = to_wide(&link_path.to_string_lossy());
    // SAFETY: Opening link directory with FILE_FLAG_OPEN_REPARSE_POINT and FILE_FLAG_BACKUP_SEMANTICS
    // for issuing FSCTL_SET_REPARSE_POINT.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(link_w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(
                FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0,
            ),
            None,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) => return Err(DskError::Optimize("invalid junction handle".to_string())),
        Err(e) => {
            let code = e.code().0 as u32;
            return Err(win32_err("CreateFileW for FSCTL_SET_REPARSE_POINT", code));
        }
    };
    let _guard = HandleGuard(handle);

    let mut bytes_returned = 0u32;
    // SAFETY: DeviceIoControl with FSCTL_SET_REPARSE_POINT on open reparse point handle.
    let success = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            Some(buffer.as_ptr() as *const _),
            buffer.len() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    if let Err(e) = success {
        let code = e.code().0 as u32;
        return Err(win32_err("DeviceIoControl FSCTL_SET_REPARSE_POINT", code));
    }

    Ok(())
}

/// Reads the target directory path from a directory junction.
pub fn read_mount_point_target(link_path: &Path) -> Result<PathBuf> {
    let link_w = to_wide(&link_path.to_string_lossy());
    // SAFETY: Opening directory handle to query reparse point data.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(link_w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(
                FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0,
            ),
            None,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) => return Err(DskError::Optimize("invalid junction handle".to_string())),
        Err(e) => {
            let code = e.code().0 as u32;
            return Err(win32_err("CreateFileW for FSCTL_GET_REPARSE_POINT", code));
        }
    };
    let _guard = HandleGuard(handle);

    let mut buffer = vec![0u8; 16384];
    let mut bytes_returned = 0u32;

    // SAFETY: DeviceIoControl FSCTL_GET_REPARSE_POINT populates buffer.
    let success = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_GET_REPARSE_POINT,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    if let Err(e) = success {
        let code = e.code().0 as u32;
        return Err(win32_err("DeviceIoControl FSCTL_GET_REPARSE_POINT", code));
    }

    if bytes_returned < 16 {
        return Err(DskError::Optimize("truncated reparse data".to_string()));
    }

    let tag = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    if tag != IO_REPARSE_TAG_MOUNT_POINT {
        return Err(DskError::Optimize(format!(
            "not a mount point reparse point (tag: {tag:#X})"
        )));
    }

    let sub_offset = u16::from_le_bytes(buffer[8..10].try_into().unwrap()) as usize;
    let sub_len = u16::from_le_bytes(buffer[10..12].try_into().unwrap()) as usize;
    let print_offset = u16::from_le_bytes(buffer[12..14].try_into().unwrap()) as usize;
    let print_len = u16::from_le_bytes(buffer[14..16].try_into().unwrap()) as usize;

    // Prefer PrintName, fallback to SubstituteName
    let (target_offset, target_len) = if print_len > 0 {
        (16 + print_offset, print_len)
    } else {
        (16 + sub_offset, sub_len)
    };

    if target_offset + target_len > bytes_returned as usize {
        return Err(DskError::Optimize(
            "invalid reparse path bounds".to_string(),
        ));
    }

    let raw_bytes = &buffer[target_offset..target_offset + target_len];
    let u16_slice: Vec<u16> = raw_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
        .collect();

    let mut target_str = String::from_utf16_lossy(&u16_slice);
    if target_str.starts_with(r"\??\") {
        target_str = target_str[4..].to_string();
    }

    Ok(PathBuf::from(target_str))
}

/// Removes a directory junction link only, leaving the underlying target directory
/// and all its contents completely intact.
pub fn remove_junction_link_only(link_path: &Path) -> Result<()> {
    // In Windows, removing a directory junction via RemoveDirectoryW removes the junction
    // point itself without recursing or touching the target contents.
    // We also attempt FSCTL_DELETE_REPARSE_POINT as an additional safeguard.
    let link_w = to_wide(&link_path.to_string_lossy());
    let handle = unsafe {
        CreateFileW(
            PCWSTR(link_w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(
                FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0,
            ),
            None,
        )
    };

    if let Ok(h) = handle
        && !h.is_invalid()
    {
        let _guard = HandleGuard(h);
        let mut del_buf = [0u8; 8];
        del_buf[0..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        let mut bytes_returned = 0u32;
        let _ = unsafe {
            DeviceIoControl(
                h,
                FSCTL_DELETE_REPARSE_POINT,
                Some(del_buf.as_ptr() as *const _),
                del_buf.len() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };
    }

    if link_path.exists() {
        fs::remove_dir(link_path)?;
    }

    Ok(())
}

/// Resolves the canonical final filesystem path of an existing directory (following junctions/reparse
/// points) via `GetFinalPathNameByHandleW` (§8.6).
pub fn resolve_final_path_by_handle(dir_path: &Path) -> Result<PathBuf> {
    let dir_w = to_wide(&dir_path.to_string_lossy());
    // SAFETY: Opening directory without FILE_FLAG_OPEN_REPARSE_POINT so Windows resolves
    // junctions/mount points to their target handle before querying GetFinalPathNameByHandleW.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(dir_w.as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0),
            None,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) => {
            return Err(DskError::Optimize(format!(
                "invalid handle resolving final path for '{}'",
                dir_path.display()
            )));
        }
        Err(e) => {
            return Err(win32_err("CreateFileW for final path", e.code().0 as u32));
        }
    };
    let _guard = HandleGuard(handle);

    crate::win::cleaner::final_path_by_handle(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junction_rejects_targets_longer_than_the_reparse_buffer() {
        let tmp = tempfile::tempdir().unwrap();
        let canon = std::fs::canonicalize(tmp.path()).unwrap(); // `\?\` long-path form
        let mut deep = canon.clone();
        // ~4.6k UTF-16 chars: substitute + print names exceed the 16 KiB reparse buffer.
        for i in 0..23 {
            deep.push(format!("{i:02}{}", "d".repeat(198)));
        }
        fs::create_dir_all(&deep).unwrap();

        let link = tmp.path().join("long_link");
        let res = create_mount_point_junction(&link, &deep);
        assert!(
            matches!(res, Err(DskError::Optimize(ref m)) if m.contains("too long")),
            "expected a clean length error, got {res:?}"
        );
    }
}
