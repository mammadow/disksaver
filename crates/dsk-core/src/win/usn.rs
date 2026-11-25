//! Win32 USN Journal querying, continuous delta reading, and `OpenFileById` stat helpers.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
    ERROR_JOURNAL_DELETE_IN_PROGRESS, ERROR_JOURNAL_ENTRY_DELETED, ERROR_JOURNAL_NOT_ACTIVE,
    ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
    WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_DESCRIPTOR,
    FILE_ID_DESCRIPTOR_0, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo, FileBasicInfo, FileIdType,
    FileStandardInfo, GetFileInformationByHandleEx, OPEN_EXISTING, OpenFileById,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V1, USN_JOURNAL_DATA_V1,
};
use windows_core::PCWSTR;

use crate::error::{DskError, Result};
use crate::index::builder::NodeFlags;
use crate::ntfs::usn::{
    CoalescedUsnOp, UsnDelta, UsnJournalState, UsnRecord, coalesce_usn_records,
    parse_usn_read_buffer, rewind_unpaired_rename_tail,
};
use crate::ntfs::{
    FA_COMPRESSED, FA_HIDDEN, FA_OFFLINE, FA_RECALL_ON_DATA_ACCESS, FA_RECALL_ON_OPEN, FA_SPARSE,
    FA_SYSTEM, TAG_WOF, is_cloud_tag,
};
use crate::time::filetime_to_min2000;

/// Hard upper bound on raw USN events before falling back to a sequential full MFT scan.
pub const DEFAULT_MAX_USN_EVENTS: usize = 200_000;

struct FileHandleGuard(HANDLE);

impl Drop for FileHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` was successfully returned by `CreateFileW` or `OpenFileById` and is closed once here.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn open_volume_raw_handle(volume_root: &str) -> Result<FileHandleGuard> {
    let trimmed = volume_root.trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return Err(DskError::NotVolumeRoot(volume_root.to_string()));
    }
    let dev_path = format!("\\\\.\\{trimmed}");
    let wide: Vec<u16> = dev_path.encode_utf16().chain(std::iter::once(0)).collect();
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // SAFETY: `wide` is NUL-terminated UTF-16 and lives across the `CreateFileW` call.
    let res = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            share,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    match res {
        Ok(h) if h != INVALID_HANDLE_VALUE && !h.is_invalid() => Ok(FileHandleGuard(h)),
        Ok(_) => Err(DskError::Io(io::Error::other(
            "CreateFileW returned invalid volume handle",
        ))),
        Err(e) => {
            let code = (e.code().0 as u32) & 0xFFFF;
            if code == ERROR_ACCESS_DENIED.0 {
                Err(DskError::NotElevated)
            } else {
                Err(DskError::Win32 {
                    ctx: "CreateFileW open volume for USN",
                    code,
                })
            }
        }
    }
}

#[derive(Clone, Copy)]
enum FrnStat {
    Ok {
        logical: u64,
        allocated: u64,
        mtime: u32,
        atime: u32,
        flags: NodeFlags,
        reparse_tag: u32,
    },
    Deleted,
    Unreadable,
}

fn attributes_to_node_flags(attrs: u32, is_dir: bool, reparse_tag: u32) -> NodeFlags {
    let mut flags = NodeFlags::empty();
    if is_dir || (attrs & 0x10 != 0) {
        flags |= NodeFlags::DIR;
    }
    if attrs & FA_HIDDEN != 0 {
        flags |= NodeFlags::HIDDEN;
    }
    if attrs & FA_SYSTEM != 0 {
        flags |= NodeFlags::SYSTEM;
    }
    if attrs & FA_SPARSE != 0 {
        flags |= NodeFlags::SPARSE;
    }
    if attrs & FA_COMPRESSED != 0 {
        flags |= NodeFlags::COMPRESSED;
    }
    if attrs & FA_OFFLINE != 0 {
        flags |= NodeFlags::OFFLINE;
    }
    if attrs & (FA_RECALL_ON_OPEN | FA_RECALL_ON_DATA_ACCESS) != 0 {
        flags |= NodeFlags::CLOUD;
    }
    if attrs & 0x400 != 0 {
        flags |= NodeFlags::REPARSE;
    }
    if reparse_tag != 0 {
        flags |= NodeFlags::REPARSE;
        if reparse_tag == TAG_WOF {
            flags |= NodeFlags::WOF;
        }
        if is_cloud_tag(reparse_tag) {
            flags |= NodeFlags::CLOUD;
        }
    }
    flags
}

fn classify_win32_usn_err(err: windows_core::Error, op: &'static str) -> DskError {
    let raw_code = (err.code().0 as u32) & 0xFFFF;
    let code = WIN32_ERROR(raw_code);
    if code == ERROR_ACCESS_DENIED {
        return DskError::NotElevated;
    }
    if code == ERROR_JOURNAL_ENTRY_DELETED {
        return DskError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{op}: USN journal entry deleted (Win32 1181)"),
        ));
    }
    if code == ERROR_JOURNAL_NOT_ACTIVE || code == ERROR_JOURNAL_DELETE_IN_PROGRESS {
        return DskError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{op}: USN journal not active (Win32 {})", code.0),
        ));
    }
    DskError::Win32 {
        ctx: op,
        code: raw_code,
    }
}

/// Queries live USN journal state (`UsnJournalID`, `FirstUsn`, `NextUsn`, `LowestValidUsn`) for `volume_root`.
pub fn query_usn_journal(volume_root: &str) -> Result<UsnJournalState> {
    let vol = open_volume_raw_handle(volume_root)?;
    let mut data = USN_JOURNAL_DATA_V1::default();
    let mut bytes_ret = 0u32;

    // SAFETY: `vol.0` is an open volume handle and `data` points to properly aligned out storage.
    let res = unsafe {
        DeviceIoControl(
            vol.0,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(&mut data as *mut USN_JOURNAL_DATA_V1 as *mut c_void),
            size_of::<USN_JOURNAL_DATA_V1>() as u32,
            Some(&mut bytes_ret),
            None,
        )
    };
    if let Err(e) = res {
        return Err(classify_win32_usn_err(e, "FSCTL_QUERY_USN_JOURNAL"));
    }

    Ok(UsnJournalState {
        usn_journal_id: data.UsnJournalID,
        first_usn: data.FirstUsn,
        next_usn: data.NextUsn,
        lowest_valid_usn: data.LowestValidUsn,
    })
}

fn stat_file_by_frn(vol_handle: HANDLE, frn: u64, cluster_size: u32) -> FrnStat {
    let desc = FILE_ID_DESCRIPTOR {
        dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: FileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 { FileId: frn as i64 },
    };

    let flags_and_attrs = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // SAFETY: `vol_handle` is a valid open handle on the NTFS volume and `desc` lives across the call.
    let opened = unsafe {
        OpenFileById(
            vol_handle,
            &desc,
            FILE_READ_ATTRIBUTES.0,
            share,
            None,
            flags_and_attrs,
        )
    };

    let fh = match opened {
        Ok(h) if h != INVALID_HANDLE_VALUE && !h.is_invalid() => FileHandleGuard(h),
        Ok(_) => return FrnStat::Deleted,
        Err(e) => {
            let code = WIN32_ERROR((e.code().0 as u32) & 0xFFFF);
            if code == ERROR_FILE_NOT_FOUND
                || code == ERROR_PATH_NOT_FOUND
                || code == ERROR_INVALID_PARAMETER
            {
                return FrnStat::Deleted;
            }
            if code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION {
                return FrnStat::Unreadable;
            }
            return FrnStat::Unreadable;
        }
    };

    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: `fh.0` is an open file handle and `basic` is sized to `FILE_BASIC_INFO`.
    let basic_ok = unsafe {
        GetFileInformationByHandleEx(
            fh.0,
            FileBasicInfo,
            &mut basic as *mut FILE_BASIC_INFO as *mut c_void,
            size_of::<FILE_BASIC_INFO>() as u32,
        )
        .is_ok()
    };

    let mut std_info = FILE_STANDARD_INFO::default();
    // SAFETY: `fh.0` is an open file handle and `std_info` is sized to `FILE_STANDARD_INFO`.
    let std_ok = unsafe {
        GetFileInformationByHandleEx(
            fh.0,
            FileStandardInfo,
            &mut std_info as *mut FILE_STANDARD_INFO as *mut c_void,
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
        .is_ok()
    };

    if !basic_ok || !std_ok {
        return FrnStat::Unreadable;
    }

    let is_dir = std_info.Directory;
    let logical = if is_dir {
        0
    } else {
        std_info.EndOfFile.max(0) as u64
    };
    let mut allocated = if is_dir {
        0
    } else {
        std_info.AllocationSize.max(0) as u64
    };

    let mut reparse_tag = 0u32;
    if basic.FileAttributes & 0x400 != 0 {
        let mut tag_info = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: `fh.0` is an open reparse point handle and `tag_info` is sized appropriately.
        let tag_ok = unsafe {
            GetFileInformationByHandleEx(
                fh.0,
                FileAttributeTagInfo,
                &mut tag_info as *mut FILE_ATTRIBUTE_TAG_INFO as *mut c_void,
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
            .is_ok()
        };
        if tag_ok {
            reparse_tag = tag_info.ReparseTag;
        }
    }

    let flags = attributes_to_node_flags(basic.FileAttributes, is_dir, reparse_tag);
    if !is_dir
        && allocated == 0
        && logical > 0
        && !flags.intersects(NodeFlags::SPARSE | NodeFlags::COMPRESSED)
        && cluster_size > 0
    {
        let c = cluster_size as u64;
        allocated = logical.div_ceil(c) * c;
    }

    FrnStat::Ok {
        logical,
        allocated,
        mtime: filetime_to_min2000(basic.LastWriteTime.max(0) as u64),
        atime: filetime_to_min2000(basic.LastAccessTime.max(0) as u64),
        flags,
        reparse_tag,
    }
}

/// Reads and coalesces all USN deltas in `[start_usn, target_next_usn)`, returning `(new_next_usn, deltas)`.
pub fn read_usn_deltas_since(
    volume_root: &str,
    journal_id: u64,
    start_usn: i64,
    target_next_usn: i64,
    cluster_size: u32,
    max_events: usize,
) -> Result<(i64, Vec<UsnDelta>)> {
    if start_usn >= target_next_usn {
        return Ok((target_next_usn, Vec::new()));
    }

    let vol = open_volume_raw_handle(volume_root)?;
    let mut cursor = start_usn;
    let mut buf = vec![0u8; 64 * 1024];
    let mut all_records: Vec<UsnRecord> = Vec::new();

    while cursor < target_next_usn {
        let mut query = READ_USN_JOURNAL_DATA_V1 {
            StartUsn: cursor,
            ReasonMask: 0xFFFF_FFFF,
            ReturnOnlyOnClose: 0,
            Timeout: 0,
            BytesToWaitFor: 0,
            UsnJournalID: journal_id,
            MinMajorVersion: 2,
            MaxMajorVersion: 3,
        };
        let mut bytes_ret = 0u32;

        // SAFETY: `vol.0` is valid, `query` is initialized, and `buf` provides writable out capacity.
        let res = unsafe {
            DeviceIoControl(
                vol.0,
                FSCTL_READ_USN_JOURNAL,
                Some(&mut query as *mut READ_USN_JOURNAL_DATA_V1 as *const c_void),
                size_of::<READ_USN_JOURNAL_DATA_V1>() as u32,
                Some(buf.as_mut_ptr() as *mut c_void),
                buf.len() as u32,
                Some(&mut bytes_ret),
                None,
            )
        };
        if let Err(e) = res {
            return Err(classify_win32_usn_err(e, "FSCTL_READ_USN_JOURNAL"));
        }

        let got = bytes_ret as usize;
        if got < 8 {
            break;
        }
        let (next_usn, recs) = parse_usn_read_buffer(&buf[..got])?;
        all_records.extend(recs);
        if all_records.len() > max_events {
            return Err(DskError::Unsupported(format!(
                "USN delta backlog exceeded {max_events} events; falling back to full scan"
            )));
        }
        // A batch can legitimately contain no V2/V3 records (e.g. only filtered V4 range records)
        // while NextUsn still advances: keep reading as long as the cursor moves forward.
        if next_usn <= cursor {
            break;
        }
        cursor = next_usn;
    }

    // Never claim progress over records that were not read: a short read means the delta is
    // incomplete, so force the caller's full-scan fallback.
    if cursor < target_next_usn {
        return Err(DskError::Unsupported(format!(
            "USN journal read stopped at {cursor} before target {target_next_usn}; falling back to full scan"
        )));
    }

    // Keep OLD_NAME/NEW_NAME pairs together: if the window ends inside a rename, stop just before
    // it and let the next run read the pair as a unit (otherwise the old name becomes a ghost).
    let cursor = rewind_unpaired_rename_tail(&mut all_records, start_usn, cursor)?;

    let ops = coalesce_usn_records(&all_records);
    let mut stat_cache: HashMap<u64, FrnStat> = HashMap::new();
    let mut deltas = Vec::with_capacity(ops.len());

    for op in ops {
        match op {
            CoalescedUsnOp::DeleteLink {
                file_id,
                parent_file_id,
                name,
            } => {
                deltas.push(UsnDelta::Delete {
                    file_id,
                    parent_file_id: Some(parent_file_id),
                    name: Some(name),
                });
            }
            CoalescedUsnOp::StatAndUpsert {
                file_id,
                parent_file_id,
                old_parent_file_id,
                old_name,
                name,
                usn_file_attributes,
            } => {
                let st = *stat_cache
                    .entry(file_id)
                    .or_insert_with(|| stat_file_by_frn(vol.0, file_id, cluster_size));
                match st {
                    FrnStat::Ok {
                        logical,
                        allocated,
                        mtime,
                        atime,
                        flags,
                        reparse_tag,
                    } => {
                        deltas.push(UsnDelta::Upsert {
                            file_id,
                            parent_file_id,
                            old_parent_file_id,
                            old_name,
                            name,
                            logical,
                            allocated,
                            mtime,
                            atime,
                            flags,
                            reparse_tag,
                            preserve_existing_sizes_if_unreadable: false,
                        });
                    }
                    FrnStat::Deleted => {
                        if let (Some(op_frn), Some(oname)) = (old_parent_file_id, old_name) {
                            deltas.push(UsnDelta::Delete {
                                file_id,
                                parent_file_id: Some(op_frn),
                                name: Some(oname),
                            });
                        } else {
                            deltas.push(UsnDelta::Delete {
                                file_id,
                                parent_file_id: Some(parent_file_id),
                                name: Some(name),
                            });
                        }
                    }
                    FrnStat::Unreadable => {
                        let fallback_flags =
                            attributes_to_node_flags(usn_file_attributes, false, 0);
                        deltas.push(UsnDelta::Upsert {
                            file_id,
                            parent_file_id,
                            old_parent_file_id,
                            old_name,
                            name,
                            logical: 0,
                            allocated: 0,
                            mtime: 0,
                            atime: 0,
                            flags: fallback_flags,
                            reparse_tag: 0,
                            preserve_existing_sizes_if_unreadable: true,
                        });
                    }
                }
            }
        }
    }

    Ok((cursor, deltas))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ntfs_attributes_and_wof_cloud_tags() {
        let flags = attributes_to_node_flags(
            0x10 | FA_HIDDEN | FA_OFFLINE | FA_RECALL_ON_DATA_ACCESS | 0x400,
            true,
            TAG_WOF,
        );
        assert!(flags.contains(NodeFlags::DIR));
        assert!(flags.contains(NodeFlags::HIDDEN));
        assert!(flags.contains(NodeFlags::OFFLINE));
        assert!(flags.contains(NodeFlags::CLOUD));
        assert!(flags.contains(NodeFlags::REPARSE));
        assert!(flags.contains(NodeFlags::WOF));
    }

    #[test]
    fn classifies_win32_1181_and_1179() {
        let e1181 = windows_core::Error::from(ERROR_JOURNAL_ENTRY_DELETED);
        let mapped1181 = classify_win32_usn_err(e1181, "FSCTL_READ_USN_JOURNAL");
        assert!(mapped1181.to_string().contains("1181"));

        let e1179 = windows_core::Error::from(ERROR_JOURNAL_NOT_ACTIVE);
        let mapped1179 = classify_win32_usn_err(e1179, "FSCTL_QUERY_USN_JOURNAL");
        assert!(mapped1179.to_string().contains("1179"));
    }
}
