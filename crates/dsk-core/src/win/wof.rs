//! Win32 Windows Overlay Filter (WOF) and CompactOS primitives.

#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use windows::Win32::Storage::FileSystem::GetCompressedFileSizeW;
use windows::Win32::System::Threading::{
    BELOW_NORMAL_PRIORITY_CLASS, GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
    THREAD_MODE_BACKGROUND_END,
};
use windows::core::PCWSTR;

use crate::error::{DskError, Result};
use crate::win::process::{hidden_command, hidden_command_with_flags};
use crate::win::volume::system32_dir;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// RAII guard placing the current thread in Windows low-priority background I/O & CPU mode
/// (`THREAD_MODE_BACKGROUND_BEGIN`) for WOF compression and restoring it on drop (§8.1).
///
/// `!Send`: background mode is per-thread, so the guard must be dropped on the thread that
/// entered it.
pub struct BackgroundThreadGuard {
    active: bool,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl BackgroundThreadGuard {
    /// Attempts to enter `THREAD_MODE_BACKGROUND_BEGIN`. Restored automatically on `Drop`.
    pub fn enter() -> Self {
        // SAFETY: Setting priority on the calling pseudo-handle (GetCurrentThread) is valid for
        // the current thread and is paired with THREAD_MODE_BACKGROUND_END on Drop.
        let ok = unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) };
        Self {
            active: ok.is_ok(),
            _not_send: core::marker::PhantomData,
        }
    }
}

impl Drop for BackgroundThreadGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: Ends background mode previously begun on this exact thread.
            unsafe {
                let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
            }
        }
    }
}

/// Queries the actual physical disk allocation size of a file via `GetCompressedFileSizeW`.
pub fn allocated_file_size(path: &Path) -> std::io::Result<u64> {
    let wide = to_wide(&path.to_string_lossy());
    let mut high = 0u32;
    // SAFETY: wide is null-terminated; high receives the upper 32 bits of the compressed size.
    let low = unsafe { GetCompressedFileSizeW(PCWSTR(wide.as_ptr()), Some(&mut high)) };
    if low == windows::Win32::Storage::FileSystem::INVALID_FILE_SIZE {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error().unwrap_or(0) != 0 {
            return Err(err);
        }
    }
    Ok(((high as u64) << 32) | (low as u64))
}

/// WOF compression algorithm options supported by Windows (§8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WofAlgorithm {
    Xpress4k,
    Xpress8k,
    Xpress16k,
    Lzx,
}

impl WofAlgorithm {
    pub fn as_compact_arg(&self) -> &'static str {
        match self {
            Self::Xpress4k => "XPRESS4K",
            Self::Xpress8k => "XPRESS8K",
            Self::Xpress16k => "XPRESS16K",
            Self::Lzx => "LZX",
        }
    }
}

fn compact_exe_path() -> PathBuf {
    system32_dir().join("compact.exe")
}

/// Applies WOF compression to an explicit, pre-filtered list of regular files in bounded command batches
/// under `THREAD_MODE_BACKGROUND_BEGIN` + `BELOW_NORMAL_PRIORITY_CLASS` without descending into
/// reparse directories (§8.1).
pub fn apply_compact_exe_compression_batch(files: &[PathBuf], algo: WofAlgorithm) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }

    let _bg_guard = BackgroundThreadGuard::enter();
    let compact_bin = compact_exe_path();
    let algo_arg = format!("/exe:{}", algo.as_compact_arg());

    // Keep each CreateProcess command line safely below Windows' 32,767 char limit.
    const MAX_CMDLINE_CHARS: usize = 20_000;
    let mut idx = 0usize;
    while idx < files.len() {
        let mut cmd = hidden_command_with_flags(&compact_bin, BELOW_NORMAL_PRIORITY_CLASS.0);
        cmd.arg("/c").arg(&algo_arg).arg("/i");

        let mut chars_used = 256usize;
        let start = idx;
        while idx < files.len() {
            let p_str = files[idx].to_string_lossy();
            let needed = p_str.len() + 3;
            if idx > start && chars_used + needed > MAX_CMDLINE_CHARS {
                break;
            }
            cmd.arg(&files[idx]);
            chars_used += needed;
            idx += 1;
        }

        let out = cmd.output()?;
        if !out.status.success() && out.status.code() != Some(1) {
            let err_text = String::from_utf8_lossy(&out.stdout).to_string();
            return Err(DskError::Optimize(format!(
                "compact.exe failed: {err_text}"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// P9.3: handle-based WOF compression, undo, and a codec-accurate estimator.
// ---------------------------------------------------------------------------------------------

/// `WOF_FILE_COMPRESSION_INFO_V1` (wofapi.h): the `ExternalFileInfo` buffer that
/// `WofSetFileDataLocation` and `WofIsExternalFile` use for `WOF_PROVIDER_FILE`. (Not
/// `FILE_PROVIDER_EXTERNAL_INFO_V1`, which carries a leading `Version` and belongs to
/// `FSCTL_SET_EXTERNAL_BACKING`: passing that layout here makes `Version = 1` the algorithm, so
/// every file silently became LZX. Verified on Windows 11 build 26300.)
#[repr(C)]
struct FileProviderExternalInfoV1 {
    algorithm: u32,
    flags: u32,
}

impl WofAlgorithm {
    fn provider_algorithm(self) -> u32 {
        use windows::Win32::Storage::FileSystem::{
            FILE_PROVIDER_COMPRESSION_LZX, FILE_PROVIDER_COMPRESSION_XPRESS4K,
            FILE_PROVIDER_COMPRESSION_XPRESS8K, FILE_PROVIDER_COMPRESSION_XPRESS16K,
        };
        match self {
            Self::Xpress4k => FILE_PROVIDER_COMPRESSION_XPRESS4K,
            Self::Xpress8k => FILE_PROVIDER_COMPRESSION_XPRESS8K,
            Self::Xpress16k => FILE_PROVIDER_COMPRESSION_XPRESS16K,
            Self::Lzx => FILE_PROVIDER_COMPRESSION_LZX,
        }
    }

    /// WOF compresses independent chunks of this size.
    pub fn chunk_bytes(self) -> usize {
        match self {
            Self::Xpress4k => 4 * 1024,
            Self::Xpress8k => 8 * 1024,
            Self::Xpress16k => 16 * 1024,
            Self::Lzx => 32 * 1024,
        }
    }

    pub fn from_provider(v: u32) -> Option<Self> {
        [Self::Xpress4k, Self::Lzx, Self::Xpress8k, Self::Xpress16k]
            .into_iter()
            .find(|a| a.provider_algorithm() == v)
    }
}

/// Outcome of compressing one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WofFileOutcome {
    Compressed {
        before: u64,
        after: u64,
    },
    /// WOF declined: the data does not shrink.
    NotBeneficial,
    /// Left alone on purpose (reason).
    Skipped(&'static str),
    Failed(String),
}

const ATTR_SKIP_FOR_WOF: u32 = 0x0000_0004 // SYSTEM
    | 0x0000_0400 // REPARSE_POINT (includes files already WOF-compressed)
    | 0x0000_0800 // COMPRESSED (LZNT1)
    | 0x0000_1000 // OFFLINE
    | 0x0000_4000 // ENCRYPTED
    | 0x0000_0200 // SPARSE_FILE
    | 0x0004_0000 // RECALL_ON_OPEN
    | 0x0040_0000; // RECALL_ON_DATA_ACCESS

struct OwnedHandle(windows::Win32::Foundation::HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle was returned by CreateFileW and is closed exactly once.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

fn open_for_wof(
    path: &Path,
    access: u32,
    share: u32,
    no_follow: bool,
) -> std::result::Result<OwnedHandle, u32> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
        OPEN_EXISTING,
    };
    let wide = crate::win::cleaner::path_to_wide_null(path);
    // SAFETY: `wide` is NUL-terminated; the handle is owned by `OwnedHandle`.
    let h = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_MODE(share),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(if no_follow {
                FILE_FLAG_OPEN_REPARSE_POINT.0
            } else {
                0
            }),
            None,
        )
    };
    match h {
        Ok(h) => Ok(OwnedHandle(h)),
        Err(e) => Err((e.code().0 as u32) & 0xFFFF),
    }
}

/// Compresses one regular file in place with WOF, through a handle that does not follow reparse
/// points and that denies concurrent writers (a file being written is skipped as "in use").
/// The kernel-resolved path must stay under `root`.
pub fn wof_compress_file(path: &Path, root: &Path, algo: WofAlgorithm) -> WofFileOutcome {
    use windows::Win32::Foundation::{ERROR_COMPRESSION_NOT_BENEFICIAL, ERROR_SHARING_VIOLATION};
    use windows::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
        WOF_PROVIDER_FILE, WofSetFileDataLocation,
    };

    let before = allocated_file_size(path).unwrap_or(0);
    let access =
        FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0 | FILE_WRITE_ATTRIBUTES.0 | SYNCHRONIZE.0;
    let handle = match open_for_wof(path, access, FILE_SHARE_READ.0, true) {
        Ok(h) => h,
        Err(code) if code == ERROR_SHARING_VIOLATION.0 => return WofFileOutcome::Skipped("in use"),
        Err(code) => return WofFileOutcome::Failed(format!("open failed (Win32 error {code})")),
    };
    let basic = match crate::win::cleaner::get_basic_info(handle.0) {
        Ok(b) => b,
        Err(e) => return WofFileOutcome::Failed(format!("attributes: {e}")),
    };
    if basic.FileAttributes & 0x10 != 0 {
        return WofFileOutcome::Skipped("directory");
    }
    if basic.FileAttributes & ATTR_SKIP_FOR_WOF != 0 {
        return WofFileOutcome::Skipped(
            "reparse, cloud, compressed, sparse, encrypted, or system file",
        );
    }
    // The WOF filter does not surface its reparse attribute through this handle, so ask it.
    if wof_file_algorithm(path).is_some() {
        return WofFileOutcome::Skipped("already WOF-compressed");
    }
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    match crate::win::cleaner::final_path_by_handle(handle.0) {
        Ok(final_path) if crate::clean::deny::is_under_root(&final_path, &canonical_root) => {}
        Ok(final_path) => {
            return WofFileOutcome::Failed(format!(
                "resolves outside the folder: {}",
                final_path.display()
            ));
        }
        Err(e) => return WofFileOutcome::Failed(format!("final path: {e}")),
    }

    let info = FileProviderExternalInfoV1 {
        algorithm: algo.provider_algorithm(),
        flags: 0,
    };
    // SAFETY: `info` is a valid FILE_PROVIDER_EXTERNAL_INFO_V1 for the call's duration and the
    // handle is open.
    let res = unsafe {
        WofSetFileDataLocation(
            handle.0,
            WOF_PROVIDER_FILE,
            &info as *const _ as *const core::ffi::c_void,
            size_of::<FileProviderExternalInfoV1>() as u32,
        )
    };
    drop(handle);
    match res {
        Ok(()) => WofFileOutcome::Compressed {
            before,
            after: allocated_file_size(path).unwrap_or(before),
        },
        Err(e) if (e.code().0 as u32) & 0xFFFF == ERROR_COMPRESSION_NOT_BENEFICIAL.0 => {
            WofFileOutcome::NotBeneficial
        }
        Err(e) => WofFileOutcome::Failed(format!("WofSetFileDataLocation: {e}")),
    }
}

/// WOF algorithm of a file compressed by the file provider, or `None`.
pub fn wof_file_algorithm(path: &Path) -> Option<WofAlgorithm> {
    use windows::Win32::Storage::FileSystem::{WOF_PROVIDER_FILE, WofIsExternalFile};
    let wide = to_wide(&path.to_string_lossy());
    let mut is_external = windows_core::BOOL(0);
    let mut provider = 0u32;
    let mut info = FileProviderExternalInfoV1 {
        algorithm: u32::MAX,
        flags: 0,
    };
    let mut len = size_of::<FileProviderExternalInfoV1>() as u32;
    // SAFETY: All out-pointers reference live stack values; `len` is the buffer size.
    let ok = unsafe {
        WofIsExternalFile(
            PCWSTR(wide.as_ptr()),
            Some(&mut is_external),
            Some(&mut provider),
            Some(&mut info as *mut _ as *mut core::ffi::c_void),
            Some(&mut len),
        )
    };
    if ok.is_err() || !is_external.as_bool() || provider != WOF_PROVIDER_FILE {
        return None;
    }
    WofAlgorithm::from_provider(info.algorithm)
}

/// Removes WOF compression from one file (undo).
pub fn wof_decompress_file(path: &Path) -> Result<()> {
    use windows::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::FSCTL_DELETE_EXTERNAL_BACKING;

    let access =
        FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0 | FILE_WRITE_ATTRIBUTES.0 | SYNCHRONIZE.0;
    // The FSCTL must pass through the WOF filter, which a no-follow (reparse) open bypasses. So
    // refuse links up front and verify afterwards that the handle is the same file.
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || meta.is_dir() {
        return Err(DskError::Denied(format!(
            "not a regular file: {}",
            path.display()
        )));
    }
    let handle =
        open_for_wof(path, access, FILE_SHARE_READ.0, false).map_err(|code| DskError::Win32 {
            ctx: "CreateFileW(wof decompress)",
            code,
        })?;
    let final_path = crate::win::cleaner::final_path_by_handle(handle.0)?;
    let canonical = std::fs::canonicalize(path)?;
    if crate::clean::deny::normalize_win_path_str(&final_path)
        != crate::clean::deny::normalize_win_path_str(&canonical)
    {
        return Err(DskError::Denied(format!(
            "{} resolved to {}",
            path.display(),
            final_path.display()
        )));
    }
    // SAFETY: Valid handle; the control code takes no buffers.
    let res = unsafe {
        DeviceIoControl(
            handle.0,
            FSCTL_DELETE_EXTERNAL_BACKING,
            None,
            0,
            None,
            0,
            None,
            None,
        )
    };
    drop(handle);
    match res {
        Ok(()) => Ok(()),
        // ERROR_OBJECT_NOT_EXTERNALLY_BACKED: fine if nothing is compressed any more.
        Err(e) if (e.code().0 as u32) & 0xFFFF == 342 && wof_file_algorithm(path).is_none() => {
            Ok(())
        }
        Err(e) => Err(DskError::Optimize(format!(
            "FSCTL_DELETE_EXTERNAL_BACKING: {e}"
        ))),
    }
}

/// Windows' own verdict on compressing binaries on `volume` (`C:\`), with its preferred algorithm.
pub fn should_compress_binaries(volume: &str) -> Option<(bool, Option<WofAlgorithm>)> {
    use windows::Win32::Storage::FileSystem::WofShouldCompressBinaries;
    let wide = to_wide(volume);
    let mut algorithm = u32::MAX;
    // SAFETY: `wide` is NUL-terminated; `algorithm` is a live out-pointer.
    let yes = unsafe { WofShouldCompressBinaries(PCWSTR(wide.as_ptr()), &mut algorithm) };
    Some((yes.as_bool(), WofAlgorithm::from_provider(algorithm)))
}

/// Raw XPRESS-Huffman compressor (the codec WOF's XPRESS4K/8K/16K uses), for estimates.
pub struct XpressHuffEstimator {
    handle: windows::Win32::Storage::Compression::COMPRESSOR_HANDLE,
    out: Vec<u8>,
}

// The handle is used from one thread at a time only.
unsafe impl Send for XpressHuffEstimator {}

impl XpressHuffEstimator {
    pub fn new() -> Option<Self> {
        use windows::Win32::Storage::Compression::{
            COMPRESS_ALGORITHM, COMPRESS_ALGORITHM_XPRESS_HUFF, COMPRESS_RAW, COMPRESSOR_HANDLE,
            CreateCompressor,
        };
        let mut handle = COMPRESSOR_HANDLE::default();
        // SAFETY: `handle` is a live out-pointer; default allocation routines.
        unsafe {
            CreateCompressor(
                COMPRESS_ALGORITHM(COMPRESS_ALGORITHM_XPRESS_HUFF.0 | COMPRESS_RAW),
                None,
                &mut handle,
            )
        }
        .ok()?;
        Some(Self {
            handle,
            out: Vec::new(),
        })
    }

    /// Bytes `data` occupies when stored as WOF chunks of `chunk` bytes: each chunk is kept
    /// compressed only if that is smaller.
    pub fn chunked_size(&mut self, data: &[u8], chunk: usize) -> usize {
        use windows::Win32::Storage::Compression::Compress;
        let mut total = 0usize;
        for piece in data.chunks(chunk.max(512)) {
            if self.out.len() < piece.len() + 1024 {
                self.out.resize(piece.len() + 1024, 0);
            }
            let mut written = 0usize;
            // SAFETY: Input and output buffers are valid for their stated lengths.
            let ok = unsafe {
                Compress(
                    self.handle,
                    Some(piece.as_ptr() as *const core::ffi::c_void),
                    piece.len(),
                    Some(self.out.as_mut_ptr() as *mut core::ffi::c_void),
                    self.out.len(),
                    &mut written,
                )
            };
            total += if ok.is_ok() {
                written.min(piece.len())
            } else {
                piece.len()
            };
        }
        total
    }
}

impl Drop for XpressHuffEstimator {
    fn drop(&mut self) {
        // SAFETY: The handle came from CreateCompressor and is closed once.
        unsafe {
            let _ = windows::Win32::Storage::Compression::CloseCompressor(self.handle);
        }
    }
}

/// Queries CompactOS state from pinned `System32\compact.exe /CompactOS:query`.
pub fn query_compact_os_via_compact_exe() -> Result<bool> {
    let compact_bin = compact_exe_path();

    let out = hidden_command(&compact_bin)
        .arg("/CompactOS:query")
        .output()?;

    let text = String::from_utf8_lossy(&out.stdout);
    parse_compact_os_query(&text).ok_or_else(|| {
        DskError::Optimize(
            "CompactOS state is unknown (unrecognized or localized compact.exe output)".to_string(),
        )
    })
}

/// Parses `compact.exe /CompactOS:query` output.
///
/// `compact.exe` has no culture-neutral switch, so only the English sentences are trusted:
/// "The system is in the Compact state" / "The system is not in the Compact state". Anything else
/// (localized Windows, errors) is `None` so callers report "unknown" instead of guessing
/// "disabled" and offering the wrong toggle.
pub fn parse_compact_os_query(stdout: &str) -> Option<bool> {
    // Normalize the line wrap compact.exe inserts at ~80 columns.
    let flat = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.contains("is not in the Compact state") {
        Some(false)
    } else if flat.contains("is in the Compact state") {
        Some(true)
    } else {
        None
    }
}

/// Enables or disables CompactOS via pinned `System32\compact.exe /CompactOS:always|never`.
pub fn set_compact_os_via_compact_exe(enable: bool) -> Result<String> {
    let compact_bin = compact_exe_path();

    let arg = if enable {
        "/CompactOS:always"
    } else {
        "/CompactOS:never"
    };

    let out = hidden_command(&compact_bin).arg(arg).output()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(DskError::Optimize(format!(
            "failed to set CompactOS: {text}"
        )));
    }

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn compact_os_query_parser_is_fail_unknown_on_localized_output() {
        assert_eq!(
            parse_compact_os_query("The system is in the Compact state.\r\nIt will remain..."),
            Some(true)
        );
        // Real Windows 11 output wraps mid-sentence.
        assert_eq!(
            parse_compact_os_query(
                "The system is not in the Compact state because Windows has determined that, it\r\nis not beneficial for this system.\r\n"
            ),
            Some(false)
        );
        assert_eq!(
            parse_compact_os_query("Das System befindet sich nicht im komprimierten Zustand."),
            None
        );
        assert_eq!(parse_compact_os_query(""), None);
    }

    #[test]
    fn background_thread_guard_and_compact_bin_pinning_and_allocated_size() {
        let bin = compact_exe_path();
        assert!(
            bin.to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(r"system32\compact.exe")
        );

        {
            let _guard = BackgroundThreadGuard::enter();
        }

        let dir = tempdir().unwrap();
        let file = dir.path().join("sample.bin");
        let payload = vec![0x42u8; 8192];
        std::fs::write(&file, &payload).unwrap();
        let alloc = allocated_file_size(&file).unwrap();
        assert!(alloc >= 4096);
    }

    /// P9.3: compress by handle, verify content and allocation, then undo. Needs NTFS (the temp
    /// directory on the system drive).
    #[test]
    fn handle_based_wof_compress_and_undo_roundtrip() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("log.txt");
        let payload: Vec<u8> = "2026-11-17 INFO request handled in 12 ms\n"
            .repeat(20_000)
            .into_bytes();
        std::fs::write(&file, &payload).unwrap();
        let before = allocated_file_size(&file).unwrap();

        match wof_compress_file(&file, dir.path(), WofAlgorithm::Xpress8k) {
            WofFileOutcome::Compressed { after, .. } => {
                assert!(after < before / 4, "{after} vs {before}");
            }
            other => panic!("expected compression, got {other:?}"),
        }
        assert_eq!(std::fs::read(&file).unwrap(), payload, "content unchanged");
        assert_eq!(wof_file_algorithm(&file), Some(WofAlgorithm::Xpress8k));
        // Already compressed: skipped, not recompressed.
        assert!(matches!(
            wof_compress_file(&file, dir.path(), WofAlgorithm::Lzx),
            WofFileOutcome::Skipped(_)
        ));

        wof_decompress_file(&file).unwrap();
        assert_eq!(wof_file_algorithm(&file), None);
        assert_eq!(std::fs::read(&file).unwrap(), payload);
        assert!(allocated_file_size(&file).unwrap() >= before);

        // A file outside `root` (here: the root is a sibling folder) is refused.
        let other_root = dir.path().join("elsewhere");
        std::fs::create_dir(&other_root).unwrap();
        assert!(matches!(
            wof_compress_file(&file, &other_root, WofAlgorithm::Xpress8k),
            WofFileOutcome::Failed(_)
        ));

        // A file open for writing is skipped.
        let busy = dir.path().join("busy.log");
        std::fs::write(&busy, &payload).unwrap();
        let _writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&busy)
            .unwrap();
        assert_eq!(
            wof_compress_file(&busy, dir.path(), WofAlgorithm::Xpress8k),
            WofFileOutcome::Skipped("in use")
        );
    }

    #[test]
    fn xpress_huff_estimator_tracks_compressibility() {
        let mut est = XpressHuffEstimator::new().expect("cabinet.dll compressor");
        let text = "the quick brown fox jumps over the lazy dog. "
            .repeat(4096)
            .into_bytes();
        let packed = est.chunked_size(&text, 8192);
        assert!(packed * 5 < text.len(), "{packed}");
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let noise: Vec<u8> = (0..65_536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let raw = est.chunked_size(&noise, 8192);
        assert_eq!(raw, noise.len(), "incompressible chunks are stored as is");
        assert!(should_compress_binaries(r"C:\").is_some());
    }
}
