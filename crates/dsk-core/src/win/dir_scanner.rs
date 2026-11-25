use std::ffi::c_void;
use std::hash::Hasher;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use rustc_hash::FxHasher;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, SetLastError, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE,
    FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_EXTD_DIR_INFO, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo,
    GetCompressedFileSizeW, GetFileInformationByHandleEx, OPEN_EXISTING, SYNCHRONIZE,
};
use windows::core::PCWSTR;

use crate::error::{DskError, Result};
use crate::index::{EntryBatch, Index, IndexBuilder, NodeFlags, RawEntry};
use crate::ntfs::{Phase, Progress, TAG_WOF, is_cloud_tag};
use crate::volume::VolumeInfo;

/// Options controlling directory scanning behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirScanOptions {
    pub threads: usize,
    pub refine_sizes: bool,
}

impl Default for DirScanOptions {
    fn default() -> Self {
        Self {
            threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            refine_sizes: true,
        }
    }
}

impl DirScanOptions {
    pub fn for_volume(vol: &VolumeInfo) -> Self {
        let threads = if vol.seek_penalty == Some(true) {
            2
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        };
        Self {
            threads,
            refine_sizes: true,
        }
    }
}

/// Output produced by a completed directory scan.
#[derive(Debug)]
pub struct DirScanOutput {
    pub index: Index,
    pub skipped: u64,
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[inline]
fn round_up(val: u64, cluster: u32) -> u64 {
    let c = cluster as u64;
    if c <= 1 {
        val
    } else {
        match val.checked_add(c - 1) {
            Some(sum) => (sum / c) * c,
            None => val,
        }
    }
}

fn send_batch(
    tx: &crossbeam_channel::Sender<EntryBatch>,
    mut batch: EntryBatch,
    cancel: &AtomicBool,
) -> bool {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        match tx.send_timeout(batch, Duration::from_millis(50)) {
            Ok(()) => return true,
            Err(crossbeam_channel::SendTimeoutError::Timeout(b)) => {
                batch = b;
            }
            Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => return false,
        }
    }
}

fn is_drive_root(wide: &[u16]) -> bool {
    // "C:\" (len 3)
    if wide.len() == 3
        && (wide[0] as u8).is_ascii_alphabetic()
        && wide[1] == b':' as u16
        && wide[2] == 0x005C
    {
        return true;
    }
    // "\\?\C:\" (len 7)
    let prefix_long = [0x005Cu16, 0x005C, 0x003F, 0x005C];
    if wide.len() == 7
        && wide.starts_with(&prefix_long)
        && (wide[4] as u8).is_ascii_alphabetic()
        && wide[5] == b':' as u16
        && wide[6] == 0x005C
    {
        return true;
    }
    false
}

fn is_unc_root(wide: &[u16]) -> bool {
    let prefix_unc = [
        0x005Cu16, 0x005C, 0x003F, 0x005C, 0x0055, 0x004E, 0x0043, 0x005C,
    ];
    let rest = if wide.starts_with(&prefix_unc) {
        &wide[8..]
    } else if wide.starts_with(&[0x005Cu16, 0x005C]) {
        &wide[2..]
    } else {
        return false;
    };
    // In server\share or server\share\, there are at most 2 slashes
    let slashes = rest.iter().filter(|&&c| c == 0x005C).count();
    slashes <= 2
}

fn normalize_root_path(root: &Path) -> Result<(Vec<u16>, String)> {
    let abs_path = std::path::absolute(root).unwrap_or_else(|_| {
        if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(root))
                .unwrap_or_else(|_| root.to_path_buf())
        }
    });

    let mut os_wide: Vec<u16> = abs_path.as_os_str().encode_wide().collect();
    // Normalize forward slashes to backslashes for Win32 \\?\ handling
    for c in &mut os_wide {
        if *c == 0x002F {
            *c = 0x005C;
        }
    }

    let prefix_long = [0x005Cu16, 0x005C, 0x003F, 0x005C]; // \\?\
    let prefix_unc = [
        0x005Cu16, 0x005C, 0x003F, 0x005C, 0x0055, 0x004E, 0x0043, 0x005C,
    ]; // \\?\UNC\

    let (mut long_wide, mut name_wide) = if os_wide.starts_with(&prefix_unc) {
        let mut name = vec![0x005Cu16, 0x005C];
        name.extend_from_slice(&os_wide[8..]);
        (os_wide, name)
    } else if os_wide.starts_with(&prefix_long) {
        let name = os_wide[4..].to_vec();
        (os_wide, name)
    } else if os_wide.starts_with(&[0x005Cu16, 0x005C]) {
        let mut long = prefix_unc.to_vec();
        long.extend_from_slice(&os_wide[2..]);
        (long, os_wide)
    } else {
        let mut long = prefix_long.to_vec();
        long.extend_from_slice(&os_wide);
        (long, os_wide)
    };

    // Strip trailing backslashes unless the path is a volume drive root or UNC root
    if !is_drive_root(&long_wide) && !is_unc_root(&long_wide) {
        while long_wide.len() > 1 && long_wide.last() == Some(&0x005C) {
            long_wide.pop();
        }
        while name_wide.len() > 1 && name_wide.last() == Some(&0x005C) {
            name_wide.pop();
        }
    }

    if long_wide.last() != Some(&0) {
        long_wide.push(0);
    }

    let root_name = String::from_utf16_lossy(&name_wide);
    Ok((long_wide, root_name))
}

struct ScanContext<'a> {
    volume: &'a VolumeInfo,
    opts: &'a DirScanOptions,
    cancel: &'a AtomicBool,
    skipped: &'a AtomicU64,
    next_dir_key: &'a AtomicU64,
}

fn scan_dir_task<'scope>(
    s: &rayon::Scope<'scope>,
    dir_path_w: Vec<u16>,
    curr_key: u64,
    tx: crossbeam_channel::Sender<EntryBatch>,
    ctx: &'scope ScanContext<'scope>,
) {
    if ctx.cancel.load(Ordering::Relaxed) {
        return;
    }

    let handle_res = unsafe {
        CreateFileW(
            PCWSTR(dir_path_w.as_ptr()),
            FILE_LIST_DIRECTORY.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    };

    let handle = match handle_res {
        Ok(h) => h,
        Err(_) => {
            ctx.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let _guard = HandleGuard(handle);

    let mut aligned_buf = vec![0u64; 65536 / 8];
    let buf_ptr = aligned_buf.as_mut_ptr() as *mut c_void;
    let buf_size = 65536u32;
    let mut is_restart = true;

    let mut batch = EntryBatch::default();
    let mut subdirs = Vec::new();

    loop {
        if ctx.cancel.load(Ordering::Relaxed) {
            return;
        }

        let class = if is_restart {
            FileIdExtdDirectoryRestartInfo
        } else {
            FileIdExtdDirectoryInfo
        };
        is_restart = false;

        let res = unsafe { GetFileInformationByHandleEx(handle, class, buf_ptr, buf_size) };
        if res.is_err() {
            break;
        }

        let mut offset = 0usize;
        loop {
            if offset + std::mem::size_of::<FILE_ID_EXTD_DIR_INFO>() > 65536 {
                break;
            }
            let entry_ptr = unsafe {
                (aligned_buf.as_ptr() as *const u8).add(offset) as *const FILE_ID_EXTD_DIR_INFO
            };
            let info = unsafe { &*entry_ptr };

            let name_len_bytes = info.FileNameLength as usize;
            if !name_len_bytes.is_multiple_of(2) {
                break;
            }
            let name_ptr = info.FileName.as_ptr();
            let name_offset = (name_ptr as usize).saturating_sub(aligned_buf.as_ptr() as usize);
            let Some(name_end) = name_offset.checked_add(name_len_bytes) else {
                break;
            };
            if name_end > 65536 {
                break;
            }

            let name_len_chars = name_len_bytes / 2;
            let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, name_len_chars) };

            let is_dot = name_slice == [0x002E];
            let is_dotdot = name_slice == [0x002E, 0x002E];

            if !is_dot && !is_dotdot && !name_slice.is_empty() {
                let attrs = info.FileAttributes;
                let mut flags = NodeFlags::empty();
                if attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                    flags |= NodeFlags::DIR;
                }
                if attrs & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                    flags |= NodeFlags::REPARSE;
                }
                if attrs & FILE_ATTRIBUTE_SPARSE_FILE.0 != 0 {
                    flags |= NodeFlags::SPARSE;
                }
                if attrs & FILE_ATTRIBUTE_COMPRESSED.0 != 0 {
                    flags |= NodeFlags::COMPRESSED;
                }
                if attrs & FILE_ATTRIBUTE_SYSTEM.0 != 0 {
                    flags |= NodeFlags::SYSTEM;
                }
                if attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0 {
                    flags |= NodeFlags::HIDDEN;
                }
                if attrs & FILE_ATTRIBUTE_OFFLINE.0 != 0 {
                    flags |= NodeFlags::OFFLINE;
                }

                let mut reparse_tag = 0u32;
                if flags.contains(NodeFlags::REPARSE) {
                    reparse_tag = if info.ReparsePointTag != 0 {
                        info.ReparsePointTag
                    } else {
                        info.EaSize
                    };
                    if is_cloud_tag(reparse_tag) {
                        flags |= NodeFlags::CLOUD;
                    }
                    if reparse_tag == TAG_WOF {
                        flags |= NodeFlags::WOF;
                    }
                }

                let is_dir = flags.contains(NodeFlags::DIR);
                let is_reparse = flags.contains(NodeFlags::REPARSE);

                let mut hasher = FxHasher::default();
                hasher.write(&info.FileId.Identifier);
                let file_id = hasher.finish();

                let mtime = info.LastWriteTime.max(0) as u64;
                let atime = info.LastAccessTime.max(0) as u64;

                let name_ref = batch.names.push_utf16(name_slice);

                if is_dir && !is_reparse {
                    let sub_key = ctx.next_dir_key.fetch_add(1, Ordering::Relaxed);
                    batch.entries.push(RawEntry {
                        key: sub_key,
                        parent_key: curr_key,
                        name: name_ref,
                        flags,
                        logical: 0,
                        allocated: 0,
                        mtime,
                        atime,
                        file_id,
                        reparse_tag,
                    });

                    let mut child_w =
                        Vec::with_capacity(dir_path_w.len() + 1 + name_slice.len() + 1);
                    child_w.extend_from_slice(&dir_path_w[..dir_path_w.len() - 1]);
                    if child_w.last() != Some(&0x005C) {
                        child_w.push(0x005C);
                    }
                    child_w.extend_from_slice(name_slice);
                    child_w.push(0);

                    subdirs.push((child_w, sub_key));
                } else {
                    let (logical, allocated) = if is_dir {
                        (0, 0)
                    } else {
                        let logical = info.EndOfFile.max(0) as u64;
                        let mut allocated = info.AllocationSize.max(0) as u64;
                        if ctx.opts.refine_sizes
                            && flags.intersects(
                                NodeFlags::COMPRESSED | NodeFlags::SPARSE | NodeFlags::REPARSE,
                            )
                        {
                            let mut file_w =
                                Vec::with_capacity(dir_path_w.len() + 1 + name_slice.len() + 1);
                            file_w.extend_from_slice(&dir_path_w[..dir_path_w.len() - 1]);
                            if file_w.last() != Some(&0x005C) {
                                file_w.push(0x005C);
                            }
                            file_w.extend_from_slice(name_slice);
                            file_w.push(0);

                            let mut high = 0u32;
                            unsafe { SetLastError(WIN32_ERROR(0)) };
                            let low = unsafe {
                                GetCompressedFileSizeW(PCWSTR(file_w.as_ptr()), Some(&mut high))
                            };
                            if low != u32::MAX || unsafe { GetLastError() } == WIN32_ERROR(0) {
                                let raw = ((high as u64) << 32) | (low as u64);
                                allocated = round_up(raw, ctx.volume.cluster_size);
                            }
                        }
                        (logical, allocated)
                    };

                    batch.entries.push(RawEntry {
                        key: u64::MAX,
                        parent_key: curr_key,
                        name: name_ref,
                        flags,
                        logical,
                        allocated,
                        mtime,
                        atime,
                        file_id,
                        reparse_tag,
                    });
                }

                if batch.entries.len() >= 4096
                    && !send_batch(&tx, std::mem::take(&mut batch), ctx.cancel)
                {
                    return;
                }
            }

            if info.NextEntryOffset == 0 {
                break;
            }
            let Some(next_offset) = offset.checked_add(info.NextEntryOffset as usize) else {
                break;
            };
            offset = next_offset;
            if offset >= 65536 {
                break;
            }
        }
    }

    if !batch.entries.is_empty() && !send_batch(&tx, batch, ctx.cancel) {
        return;
    }

    for (sub_w, sub_key) in subdirs {
        let tx_clone = tx.clone();
        s.spawn(move |s| {
            scan_dir_task(s, sub_w, sub_key, tx_clone, ctx);
        });
    }
}

/// Recursively scans a directory tree in parallel into an [`Index`].
pub fn scan_dirs(
    root: &Path,
    volume: VolumeInfo,
    opts: &DirScanOptions,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<DirScanOutput> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let (root_wide, root_name) = normalize_root_path(root)?;

    let next_dir_key = AtomicU64::new(1);
    let skipped = AtomicU64::new(0);

    let ctx = ScanContext {
        volume: &volume,
        opts,
        cancel,
        skipped: &skipped,
        next_dir_key: &next_dir_key,
    };

    let (tx, rx) = crossbeam_channel::bounded::<EntryBatch>(64);

    let builder_vol = volume.clone();
    let builder_name = root_name;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.threads.max(1))
        .thread_name(|i| format!("dsk-scan-{i}"))
        .build()
        .map_err(|e| DskError::Unsupported(format!("failed to build rayon pool: {e}")))?;

    let index = std::thread::scope(|thread_scope| {
        let builder_thread = thread_scope.spawn(|| {
            let mut builder = IndexBuilder::new(0, &builder_name, builder_vol);
            let mut total_entries = 0u64;
            while let Ok(batch) = rx.recv() {
                total_entries += batch.entries.len() as u64;
                builder.push_batch(batch);
                progress(Progress {
                    phase: Phase::Enumerating,
                    done: total_entries,
                    total: 0,
                });
            }
            progress(Progress {
                phase: Phase::Aggregating,
                done: total_entries,
                total: total_entries,
            });
            builder.finish()
        });

        pool.scope(|s| {
            let tx_root = tx.clone();
            s.spawn(|s| {
                scan_dir_task(s, root_wide, 0, tx_root, &ctx);
            });
        });

        drop(tx);

        builder_thread
            .join()
            .map_err(|_| DskError::Unsupported("builder thread panicked".into()))
    })?;

    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    Ok(DirScanOutput {
        index,
        skipped: skipped.load(Ordering::Relaxed),
    })
}
