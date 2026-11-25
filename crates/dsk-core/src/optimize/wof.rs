#![forbid(unsafe_code)]

//! WOF (Windows Overlay Filter) 2% sample compressibility estimator, folder compressor, and CompactOS.

use std::fs::File;
use std::io::Read;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path, is_under_root};
use crate::error::{DskError, Result};
use crate::index::{Index, NodeFlags, NodeId};
use crate::win::volume::system32_dir;
pub use crate::win::wof::WofAlgorithm;
use crate::win::wof::{
    allocated_file_size, apply_compact_exe_compression_batch, query_compact_os_via_compact_exe,
    set_compact_os_via_compact_exe,
};

const FILE_ATTRIBUTE_SYSTEM_MASK: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_REPARSE_MASK: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_COMPRESSED_MASK: u32 = 0x0000_0800;
const FILE_ATTRIBUTE_OFFLINE_MASK: u32 = 0x0000_1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN_MASK: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_MASK: u32 = 0x0040_0000;

const MAX_TOTAL_SAMPLE_BYTES: u64 = 64 * 1024 * 1024;
/// Folders whose sample predicts less than this saving are not compressed (§8.1).
pub const MIN_WOF_SAVINGS_PCT: f32 = 15.0;

const INCOMPRESSIBLE_EXTENSIONS: &[&str] = &[
    "zip",
    "7z",
    "rar",
    "tar",
    "gz",
    "xz",
    "bz2",
    "zst",
    "tgz",
    "mp4",
    "mkv",
    "avi",
    "mov",
    "wmv",
    "mp3",
    "flac",
    "aac",
    "ogg",
    "jpg",
    "jpeg",
    "png",
    "webp",
    "gif",
    "ico",
    "pak",
    "gguf",
    "safetensors",
    "bin",
    "iso",
    "img",
    "vhdx",
    "vhd",
    "vdi",
    "vmdk",
    "db",
    "sqlite",
    "sqlite3",
    "wal",
    "ost",
    "pst",
];

/// Sample-based preview of potential space reclamation via transparent WOF compression (§8.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WofSamplePreview {
    pub folder: PathBuf,
    pub total_logical_bytes: u64,
    pub sampled_bytes: u64,
    pub estimated_compressed_bytes: u64,
    pub estimated_savings_pct: f32,
    pub recommended: bool,
    pub skip_reason: Option<String>,
    /// Bytes saved across the folder after per-file cluster rounding (P9.3). `0` when unknown.
    #[serde(default)]
    pub projected_savings_bytes: u64,
}

impl WofSamplePreview {
    /// Projected bytes saved for the whole folder: `total_logical_bytes × estimated_savings_pct`.
    ///
    /// `estimated_compressed_bytes` describes only the sampled bytes, so it must not be
    /// subtracted from the folder total (P9.0: that overstated savings by roughly the folder
    /// size).
    pub fn estimated_savings_bytes(&self) -> u64 {
        if self.sampled_bytes == 0 || !self.estimated_savings_pct.is_finite() {
            return 0;
        }
        if self.projected_savings_bytes > 0 {
            return self.projected_savings_bytes;
        }
        let pct = f64::from(self.estimated_savings_pct.clamp(0.0, 100.0));
        (self.total_logical_bytes as f64 * pct / 100.0) as u64
    }
}

/// Outcome report returned after applying WOF compression to a folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WofCompressionReport {
    pub folder: PathBuf,
    pub algorithm: WofAlgorithm,
    pub before_allocated_bytes: u64,
    pub after_allocated_bytes: u64,
    pub freed_bytes: u64,
    pub elapsed_ms: u64,
    pub dry_run: bool,
    #[serde(default)]
    pub files_compressed: u64,
    #[serde(default)]
    pub files_skipped: u64,
    #[serde(default)]
    pub files_failed: u64,
    /// Up to 20 failure messages.
    #[serde(default)]
    pub failures: Vec<String>,
}

/// CompactOS state queried from the operating system.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactOsState {
    pub enabled: bool,
    pub supported: bool,
}

/// Outcome report returned after modifying CompactOS state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactOsReport {
    pub enabled: bool,
    pub message: String,
}

/// Fast in-memory match-finder estimating LZ compressibility on a file sample buffer.
pub fn estimate_lz_compressed_size(data: &[u8]) -> usize {
    if data.len() < 16 {
        return data.len();
    }
    let mut hash_table = [0usize; 2048];
    let mut ip = 0;
    let mut compressed_size = 0;
    let mut last_match = 0;

    while ip + 4 < data.len() {
        let val = ((data[ip] as u32) << 16) | ((data[ip + 1] as u32) << 8) | (data[ip + 2] as u32);
        let h = ((val.wrapping_mul(2654435761) >> 21) as usize) & (hash_table.len() - 1);
        let ref_pos = hash_table[h];
        hash_table[h] = ip;

        let offset = ip.saturating_sub(ref_pos);
        if ref_pos > 0
            && offset > 0
            && offset < 65536
            && data[ip..ip + 4] == data[ref_pos..ref_pos + 4]
        {
            let mut len = 4;
            while ip + len < data.len() && data[ip + len] == data[ref_pos + (len % offset)] {
                len += 1;
            }
            let literals = ip - last_match;
            compressed_size += literals + 3;
            ip += len;
            last_match = ip;
        } else {
            ip += 1;
        }
    }
    compressed_size += data.len().saturating_sub(last_match);
    compressed_size.min(data.len())
}

fn is_windows_system_subtree(path: &Path, deny_ctx: &DenyContext) -> bool {
    if is_under_root(path, Path::new(&deny_ctx.windows_dir)) {
        return true;
    }
    if let Some(sys_win) = system32_dir().parent()
        && is_under_root(path, sys_win)
    {
        return true;
    }
    let sys_drive_win = format!(r"{}\Windows", deny_ctx.system_drive.trim_end_matches('\\'));
    is_under_root(path, Path::new(&sys_drive_win)) || is_under_root(path, Path::new(r"C:\Windows"))
}

fn is_unsafe_live_attrs(attrs: u32, skip_compressed: bool) -> bool {
    let blocked_mask = FILE_ATTRIBUTE_SYSTEM_MASK
        | FILE_ATTRIBUTE_REPARSE_MASK
        | FILE_ATTRIBUTE_OFFLINE_MASK
        | FILE_ATTRIBUTE_RECALL_ON_OPEN_MASK
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_MASK;
    if (attrs & blocked_mask) != 0 {
        return true;
    }
    skip_compressed && (attrs & FILE_ATTRIBUTE_COMPRESSED_MASK) != 0
}

fn is_incompressible_file_name(name_lower: &str) -> bool {
    if matches!(
        name_lower,
        "pagefile.sys" | "hiberfil.sys" | "swapfile.sys" | "dumpstack.log.tmp"
    ) {
        return true;
    }

    if let Some(pos) = name_lower.rfind('.') {
        let ext = &name_lower[pos + 1..];
        INCOMPRESSIBLE_EXTENSIONS.contains(&ext)
    } else {
        false
    }
}

/// Sampling window: 64 KiB read at offsets spread evenly across the folder's bytes.
const SAMPLE_WINDOW: usize = 64 * 1024;

/// Plans sampling windows `(file index, offset, length)` over files of the given sizes so the
/// sample is weighted by bytes, not by file count (a folder of a few huge `.pak` files gets as
/// many windows as one of many small DLLs). Reads everything when the folder fits in the budget.
pub fn plan_sample_windows(sizes: &[u64], budget: u64) -> Vec<(usize, u64, usize)> {
    let total: u64 = sizes.iter().sum();
    let mut out = Vec::new();
    if total == 0 || budget == 0 {
        return out;
    }
    let window = budget.min(SAMPLE_WINDOW as u64);
    if total <= budget {
        for (i, &sz) in sizes.iter().enumerate() {
            let mut off = 0u64;
            while off < sz {
                let len = (sz - off).min(window) as usize;
                out.push((i, off, len));
                off += len as u64;
            }
        }
        return out;
    }
    let windows = (budget / window).max(1);
    let stride = total / windows;
    let mut prefix = Vec::with_capacity(sizes.len());
    let mut acc = 0u64;
    for &sz in sizes {
        prefix.push(acc);
        acc += sz;
    }
    let mut last: Option<(usize, u64)> = None;
    for k in 0..windows {
        let g = k * stride + stride / 2;
        let i = prefix
            .partition_point(|&start| start <= g)
            .saturating_sub(1);
        let sz = sizes[i];
        if sz == 0 {
            continue;
        }
        let within = (g - prefix[i]).min(sz.saturating_sub(1));
        let off = (within / 4096) * 4096;
        if last == Some((i, off)) {
            continue;
        }
        last = Some((i, off));
        let len = (sz - off).min(window) as usize;
        out.push((i, off, len));
    }
    out
}

/// Estimated on-disk size of `data` under `algo`: the real XPRESS-Huffman codec at WOF's chunk
/// size, with LZX approximated as 88 % of XPRESS16K (it has no public encoder). Falls back to the
/// built-in LZ estimate when the Compression API is unavailable.
fn estimate_wof_size(
    est: &mut Option<crate::win::wof::XpressHuffEstimator>,
    data: &[u8],
    algo: WofAlgorithm,
) -> usize {
    match est {
        Some(e) => {
            let chunk = if algo == WofAlgorithm::Lzx {
                16 * 1024
            } else {
                algo.chunk_bytes()
            };
            let size = e.chunked_size(data, chunk);
            if algo == WofAlgorithm::Lzx {
                size * 88 / 100
            } else {
                size
            }
        }
        None => estimate_lz_compressed_size(data),
    }
}

/// Reads the planned windows and returns `(sampled, estimated_compressed)` bytes.
fn sample_windows(
    paths: &[PathBuf],
    windows: &[(usize, u64, usize)],
    algo: WofAlgorithm,
) -> (u64, u64) {
    use std::io::{Seek, SeekFrom};
    let mut est = crate::win::wof::XpressHuffEstimator::new();
    let mut buf = vec![0u8; SAMPLE_WINDOW];
    let mut sampled = 0u64;
    let mut compressed = 0u64;
    let mut open: Option<(usize, File)> = None;
    let mut rejected: Option<usize> = None;
    for &(i, off, len) in windows {
        if rejected == Some(i) {
            continue;
        }
        if open.as_ref().is_none_or(|(j, _)| *j != i) {
            // Re-check live attributes: never read (and hydrate) cloud or offline files.
            let ok = std::fs::symlink_metadata(&paths[i])
                .map(|m| {
                    !m.file_type().is_symlink() && !is_unsafe_live_attrs(m.file_attributes(), true)
                })
                .unwrap_or(false);
            if !ok {
                rejected = Some(i);
                continue;
            }
            match File::open(&paths[i]) {
                Ok(f) => open = Some((i, f)),
                Err(_) => {
                    rejected = Some(i);
                    continue;
                }
            }
        }
        let Some((_, f)) = open.as_mut() else {
            continue;
        };
        if f.seek(SeekFrom::Start(off)).is_err() {
            continue;
        }
        let n = f.read(&mut buf[..len]).unwrap_or(0);
        if n == 0 {
            continue;
        }
        sampled += n as u64;
        compressed += estimate_wof_size(&mut est, &buf[..n], algo) as u64;
    }
    (sampled, compressed)
}

/// Bytes a file of `logical` size and `allocated` clusters saves at `ratio` (compressed/original),
/// rounded to whole clusters.
fn projected_file_savings(logical: u64, allocated: u64, ratio: f64, cluster: u64) -> u64 {
    let compressed = (logical as f64 * ratio).ceil() as u64;
    let rounded = compressed.div_ceil(cluster) * cluster;
    allocated.saturating_sub(rounded)
}

/// Estimates XPRESS8K WOF savings for a folder of the index (§8.1), sampling up to 64 MiB.
pub fn sample_folder_compressibility(
    index: &Index,
    folder_node: NodeId,
) -> Result<WofSamplePreview> {
    sample_folder_compressibility_algo(
        index,
        folder_node,
        WofAlgorithm::Xpress8k,
        MAX_TOTAL_SAMPLE_BYTES,
    )
}

#[cfg(test)]
fn sample_folder_compressibility_with_cap(
    index: &Index,
    folder_node: NodeId,
    max_total_sample_bytes: u64,
) -> Result<WofSamplePreview> {
    sample_folder_compressibility_algo(
        index,
        folder_node,
        WofAlgorithm::Xpress8k,
        max_total_sample_bytes,
    )
}

/// Estimates WOF savings for `algo`, reading at most `max_total_sample_bytes` (P9.3).
pub fn sample_folder_compressibility_algo(
    index: &Index,
    folder_node: NodeId,
    algo: WofAlgorithm,
    max_total_sample_bytes: u64,
) -> Result<WofSamplePreview> {
    let folder_path = index.path(folder_node);
    let deny_ctx = DenyContext::default();
    let blocked = |reason: String| WofSamplePreview {
        folder: folder_path.clone(),
        total_logical_bytes: index.total_allocated(folder_node),
        sampled_bytes: 0,
        estimated_compressed_bytes: 0,
        estimated_savings_pct: 0.0,
        recommended: false,
        skip_reason: Some(reason),
        projected_savings_bytes: 0,
    };

    if is_windows_system_subtree(&folder_path, &deny_ctx) {
        return Ok(blocked(
            "Windows system folder is blocked outside CompactOS".to_string(),
        ));
    }
    if let Some(reason) = is_denied_path(&folder_path, &deny_ctx) {
        return Ok(blocked(format!("protected system folder: {reason}")));
    }

    let cluster = u64::from(index.volume().cluster_size.max(512)).max(4096);
    let mut files: Vec<(NodeId, u64, u64)> = Vec::new();
    let mut subtree_logical = 0u64;
    let mut stack = vec![folder_node];
    while let Some(curr) = stack.pop() {
        let flags = index.flags(curr);
        if flags.contains(NodeFlags::REPARSE)
            || flags.contains(NodeFlags::OFFLINE)
            || flags.contains(NodeFlags::SYSTEM)
        {
            continue;
        }
        if flags.contains(NodeFlags::DIR) {
            stack.extend(index.children(curr));
            continue;
        }
        let logical = index.logical(curr);
        subtree_logical = subtree_logical.saturating_add(logical);
        if flags.intersects(NodeFlags::COMPRESSED | NodeFlags::WOF | NodeFlags::CLOUD) {
            continue;
        }
        let name = index.name(curr).to_ascii_lowercase();
        // A file of one cluster or less cannot shrink.
        if !is_incompressible_file_name(&name) && logical > cluster {
            files.push((curr, logical, index.allocated(curr)));
        }
    }
    let total_logical = subtree_logical.max(index.logical(folder_node));
    if files.is_empty() {
        let mut p = blocked("no compressible regular files found".to_string());
        p.total_logical_bytes = total_logical;
        return Ok(p);
    }

    let sizes: Vec<u64> = files.iter().map(|f| f.1).collect();
    let windows = plan_sample_windows(&sizes, max_total_sample_bytes);
    let mut paths: Vec<PathBuf> = vec![PathBuf::new(); files.len()];
    for &(i, _, _) in &windows {
        if paths[i].as_os_str().is_empty() {
            paths[i] = index.path(files[i].0);
        }
    }
    let (total_sampled, total_estimated_compressed) = sample_windows(&paths, &windows, algo);
    if total_sampled == 0 {
        let mut p = blocked("unable to read file sample data".to_string());
        p.total_logical_bytes = total_logical;
        return Ok(p);
    }

    let ratio = (total_estimated_compressed as f64 / total_sampled as f64).min(1.0);
    let pct = ((1.0 - ratio) * 100.0) as f32;
    let projected: u64 = files
        .iter()
        .map(|&(_, logical, allocated)| projected_file_savings(logical, allocated, ratio, cluster))
        .fold(0u64, u64::saturating_add);
    let recommended = pct >= MIN_WOF_SAVINGS_PCT;
    Ok(WofSamplePreview {
        folder: folder_path,
        total_logical_bytes: total_logical,
        sampled_bytes: total_sampled,
        estimated_compressed_bytes: total_estimated_compressed,
        estimated_savings_pct: pct,
        recommended,
        skip_reason: (!recommended)
            .then(|| format!("estimated savings ({pct:.1}%) below 15% threshold")),
        projected_savings_bytes: if recommended { projected } else { 0 },
    })
}

/// Kernel-resolved (`GetFinalPathNameByHandleW`) DOS path without the `\\?\` prefix.
fn canonical_dos_path(path: &Path) -> Result<PathBuf> {
    let canon = std::fs::canonicalize(path)?;
    let s = canon.to_string_lossy();
    Ok(match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => canon.clone(),
    })
}

/// Estimates XPRESS8K WOF savings (percent) from a byte-weighted sample of already-filtered live
/// files. Returns `None` when nothing could be read.
fn sample_live_files_savings_pct(files: &[PathBuf]) -> Option<f32> {
    let sizes: Vec<u64> = files
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .collect();
    let windows = plan_sample_windows(&sizes, MAX_TOTAL_SAMPLE_BYTES);
    let (sampled, estimated) = sample_windows(files, &windows, WofAlgorithm::Xpress8k);
    if sampled == 0 {
        return None;
    }
    Some(sampled.saturating_sub(estimated) as f32 / sampled as f32 * 100.0)
}

fn collect_wof_targets(
    root: &Path,
    deny_ctx: &DenyContext,
    cancel: &AtomicBool,
) -> Result<(Vec<PathBuf>, u64, u64)> {
    let mut stack = vec![root.to_path_buf()];
    let mut eligible_files = Vec::new();
    let mut skipped_alloc = 0u64;
    let mut before_alloc = 0u64;

    while let Some(curr) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }

        let Ok(meta) = std::fs::symlink_metadata(&curr) else {
            continue;
        };
        if meta.file_type().is_symlink() || is_unsafe_live_attrs(meta.file_attributes(), false) {
            continue;
        }
        if is_windows_system_subtree(&curr, deny_ctx) || is_denied_path(&curr, deny_ctx).is_some() {
            continue;
        }

        if meta.is_dir() {
            let lower = curr.to_string_lossy().to_ascii_lowercase();
            // Driver-written shader caches are rewritten constantly: compressing them is wasted.
            if DRIVER_CACHE_MARKERS.iter().any(|m| lower.ends_with(m)) {
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&curr) else {
                continue;
            };
            for entry in rd.flatten() {
                stack.push(entry.path());
            }
        } else if meta.is_file() {
            let alloc = allocated_file_size(&curr).unwrap_or(meta.len());
            before_alloc = before_alloc.saturating_add(alloc);

            let name_lower = curr
                .file_name()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if is_unsafe_live_attrs(meta.file_attributes(), true)
                || is_incompressible_file_name(&name_lower)
                || meta.len() <= 512
            {
                skipped_alloc = skipped_alloc.saturating_add(alloc);
            } else {
                eligible_files.push(curr);
            }
        }
    }

    Ok((eligible_files, skipped_alloc, before_alloc))
}

const DRIVER_CACHE_MARKERS: &[&str] = &[
    r"\dxcache",
    r"\glcache",
    r"\d3dscache",
    r"\shadercache",
    r"\vkcache",
    r"\dxccache",
];

/// Options for [`compress_folder_wof_with`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WofApplyOptions {
    /// Refuse folders whose sample predicts less than [`MIN_WOF_SAVINGS_PCT`].
    pub enforce_gate: bool,
    /// Leave files written within this many days alone (they are likely to be rewritten).
    pub min_age_days: u32,
    /// Worker threads (`0` = half the logical CPUs, at most 4).
    pub threads: usize,
}

impl Default for WofApplyOptions {
    fn default() -> Self {
        Self {
            enforce_gate: true,
            min_age_days: 0,
            threads: 0,
        }
    }
}

/// Compresses a folder with WOF (§8.1), strictly blocking `C:\Windows` outside CompactOS and
/// skipping reparse, offline, and system files.
pub fn compress_folder_wof(
    folder: &Path,
    algo: WofAlgorithm,
    dry_run: bool,
    cancel: &AtomicBool,
) -> Result<WofCompressionReport> {
    compress_folder_wof_with(folder, algo, dry_run, cancel, &WofApplyOptions::default())
}

/// Resolves and validates a folder for WOF work: not a Windows system subtree or a deny-listed
/// path, lexically or after the kernel resolves junctions, `subst` drives, and volume GUIDs.
fn checked_wof_root(folder: &Path, deny_ctx: &DenyContext) -> Result<PathBuf> {
    if is_windows_system_subtree(folder, deny_ctx) {
        return Err(DskError::Denied(format!(
            "Windows system directory '{}' cannot be WOF-compressed outside CompactOS",
            folder.display()
        )));
    }
    if let Some(reason) = is_denied_path(folder, deny_ctx) {
        return Err(DskError::Denied(format!(
            "path '{}' is denied: {reason}",
            folder.display()
        )));
    }

    let root_meta = std::fs::symlink_metadata(folder)?;
    if root_meta.file_type().is_symlink()
        || is_unsafe_live_attrs(root_meta.file_attributes(), false)
    {
        return Err(DskError::Denied(format!(
            "refusing WOF compression on reparse, offline, or system path '{}'",
            folder.display()
        )));
    }

    let canonical = canonical_dos_path(folder)?;
    if is_windows_system_subtree(&canonical, deny_ctx) {
        return Err(DskError::Denied(format!(
            "'{}' resolves to Windows system directory '{}' and cannot be WOF-compressed outside CompactOS",
            folder.display(),
            canonical.display()
        )));
    }
    if let Some(reason) = is_denied_path(&canonical, deny_ctx) {
        return Err(DskError::Denied(format!(
            "'{}' resolves to denied path '{}': {reason}",
            folder.display(),
            canonical.display()
        )));
    }
    Ok(canonical)
}

/// [`compress_folder_wof`] with options. Files are compressed one by one through
/// [`crate::win::wof::wof_compress_file`] (no-follow handle, writers denied, containment checked)
/// on a small background-priority pool. Falls back to `compact.exe` on file systems without WOF.
pub fn compress_folder_wof_with(
    folder: &Path,
    algo: WofAlgorithm,
    dry_run: bool,
    cancel: &AtomicBool,
    opts: &WofApplyOptions,
) -> Result<WofCompressionReport> {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;

    let start = Instant::now();
    let deny_ctx = DenyContext::default();
    let canonical = checked_wof_root(folder, &deny_ctx)?;

    let (mut eligible_files, mut skipped_alloc, before_alloc) =
        collect_wof_targets(&canonical, &deny_ctx, cancel)?;

    if opts.min_age_days > 0 {
        let cutoff = std::time::SystemTime::now()
            - std::time::Duration::from_secs(u64::from(opts.min_age_days) * 86_400);
        let mut kept = Vec::with_capacity(eligible_files.len());
        for p in eligible_files {
            let recent = std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .map(|t| t > cutoff)
                .unwrap_or(true);
            if recent {
                skipped_alloc = skipped_alloc.saturating_add(allocated_file_size(&p).unwrap_or(0));
            } else {
                kept.push(p);
            }
        }
        eligible_files = kept;
    }

    // §8.1: test-compress a sample first and skip folders that would gain less than 15%.
    if !dry_run
        && opts.enforce_gate
        && let Some(pct) = sample_live_files_savings_pct(&eligible_files)
        && pct < MIN_WOF_SAVINGS_PCT
    {
        return Err(DskError::PreconditionFailed(format!(
            "estimated WOF savings for '{}' are {pct:.1}% (< {MIN_WOF_SAVINGS_PCT}%); not worth compressing",
            folder.display()
        )));
    }

    if dry_run {
        return Ok(WofCompressionReport {
            folder: folder.to_path_buf(),
            algorithm: algo,
            before_allocated_bytes: before_alloc,
            after_allocated_bytes: before_alloc,
            freed_bytes: 0,
            elapsed_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            files_compressed: 0,
            files_skipped: 0,
            files_failed: 0,
            failures: Vec::new(),
        });
    }

    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let compressed = AtomicU64::new(0);
    let skipped = AtomicU64::new(0);
    let failed = AtomicU64::new(0);
    let unsupported = AtomicU64::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let threads = if opts.threads > 0 {
        opts.threads
    } else {
        std::thread::available_parallelism()
            .map(|n| (n.get() / 2).clamp(1, 4))
            .unwrap_or(2)
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("dsk-wof-{i}"))
        .build()
        .map_err(|e| DskError::Optimize(format!("thread pool: {e}")))?;
    pool.install(|| {
        use rayon::prelude::*;
        eligible_files.par_iter().for_each(|path| {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let _bg = crate::win::wof::BackgroundThreadGuard::enter();
            match crate::win::wof::wof_compress_file(path, &canonical, algo) {
                crate::win::wof::WofFileOutcome::Compressed { .. } => {
                    compressed.fetch_add(1, Ordering::Relaxed);
                }
                crate::win::wof::WofFileOutcome::NotBeneficial
                | crate::win::wof::WofFileOutcome::Skipped(_) => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                }
                crate::win::wof::WofFileOutcome::Failed(msg) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    // 0x80070001 / 0x80070032: the file system has no WOF support.
                    if msg.contains("0x80070001") || msg.contains("0x80070032") {
                        unsupported.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Ok(mut f) = failures.lock()
                        && f.len() < 20
                    {
                        f.push(format!("{}: {msg}", path.display()));
                    }
                }
            }
        });
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    let mut failures = failures.into_inner().unwrap_or_default();
    let (mut files_compressed, mut files_failed) = (
        compressed.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );
    if files_compressed == 0
        && files_failed > 0
        && unsupported.load(Ordering::Relaxed) == files_failed
    {
        for chunk in eligible_files.chunks(64) {
            if cancel.load(Ordering::Relaxed) {
                return Err(DskError::Cancelled);
            }
            apply_compact_exe_compression_batch(chunk, algo)?;
        }
        files_compressed = eligible_files.len() as u64;
        files_failed = 0;
        failures.clear();
    }

    let compressed_after: u64 = eligible_files
        .iter()
        .map(|p| {
            allocated_file_size(p)
                .unwrap_or_else(|_| std::fs::symlink_metadata(p).map(|m| m.len()).unwrap_or(0))
        })
        .fold(0u64, u64::saturating_add);
    let after_alloc = skipped_alloc.saturating_add(compressed_after);
    let freed = before_alloc.saturating_sub(after_alloc);

    Ok(WofCompressionReport {
        folder: folder.to_path_buf(),
        algorithm: algo,
        before_allocated_bytes: before_alloc,
        after_allocated_bytes: after_alloc,
        freed_bytes: freed,
        elapsed_ms: start.elapsed().as_millis() as u64,
        dry_run: false,
        files_compressed,
        files_skipped: skipped.load(Ordering::Relaxed),
        files_failed,
        failures,
    })
}

/// Undoes WOF compression for every file under `folder` (does not follow links).
pub fn decompress_folder_wof(folder: &Path, cancel: &AtomicBool) -> Result<WofCompressionReport> {
    let start = Instant::now();
    let deny_ctx = DenyContext::default();
    let canonical = checked_wof_root(folder, &deny_ctx)?;
    let mut stack = vec![canonical.clone()];
    let mut files = Vec::new();
    let mut before = 0u64;
    while let Some(curr) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }
        let Ok(meta) = std::fs::symlink_metadata(&curr) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&curr) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        } else if meta.is_file() {
            before = before.saturating_add(allocated_file_size(&curr).unwrap_or(meta.len()));
            if crate::win::wof::wof_file_algorithm(&curr).is_some() {
                files.push(curr);
            }
        }
    }
    let mut done = 0u64;
    let mut failures = Vec::new();
    for f in &files {
        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }
        match crate::win::wof::wof_decompress_file(f) {
            Ok(()) => done += 1,
            Err(e) if failures.len() < 20 => failures.push(format!("{}: {e}", f.display())),
            Err(_) => {}
        }
    }
    let after = {
        let mut total = 0u64;
        let mut stack = vec![canonical];
        while let Some(curr) = stack.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&curr) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&curr) {
                    stack.extend(rd.flatten().map(|e| e.path()));
                }
            } else {
                total = total.saturating_add(allocated_file_size(&curr).unwrap_or(meta.len()));
            }
        }
        total
    };
    Ok(WofCompressionReport {
        folder: folder.to_path_buf(),
        algorithm: WofAlgorithm::Xpress8k,
        before_allocated_bytes: before,
        after_allocated_bytes: after,
        freed_bytes: 0,
        elapsed_ms: start.elapsed().as_millis() as u64,
        dry_run: false,
        files_compressed: done,
        files_skipped: 0,
        files_failed: (files.len() as u64).saturating_sub(done),
        failures,
    })
}

/// Queries CompactOS state from Windows.
pub fn query_compact_os_state() -> Result<CompactOsState> {
    let enabled = query_compact_os_via_compact_exe()?;
    Ok(CompactOsState {
        enabled,
        supported: true,
    })
}

/// Enables or disables CompactOS.
pub fn set_compact_os_enabled(enable: bool) -> Result<CompactOsReport> {
    let msg = set_compact_os_via_compact_exe(enable)?;
    Ok(CompactOsReport {
        enabled: enable,
        message: msg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (P9.0): previews printed `total − sample_compressed`, so a 7.3 GiB folder with
    /// a 29 MiB sample "saved" ~7.29 GiB regardless of the measured ratio.
    #[test]
    fn preview_savings_scale_the_sampled_ratio_to_the_folder() {
        let mut p = WofSamplePreview {
            folder: PathBuf::from(r"C:\Apps"),
            total_logical_bytes: 7_300_000_000,
            sampled_bytes: 29_000_000,
            estimated_compressed_bytes: 14_819_000,
            estimated_savings_pct: 48.9,
            recommended: true,
            skip_reason: None,
            projected_savings_bytes: 0,
        };
        let saved = p.estimated_savings_bytes();
        assert!(
            (3_560_000_000..=3_580_000_000).contains(&saved),
            "saved {saved}"
        );
        assert_ne!(
            saved,
            p.total_logical_bytes - p.estimated_compressed_bytes,
            "must not mix sample and folder units"
        );

        p.sampled_bytes = 0;
        assert_eq!(p.estimated_savings_bytes(), 0);
        p.sampled_bytes = 1;
        p.estimated_savings_pct = f32::NAN;
        assert_eq!(p.estimated_savings_bytes(), 0);
        p.estimated_savings_pct = 250.0;
        assert_eq!(p.estimated_savings_bytes(), p.total_logical_bytes);
    }

    #[test]
    fn estimate_lz_compressed_size_reduces_repetitive_data_and_preserves_random() {
        let repetitive = vec![b'A'; 4096];
        let comp_rep = estimate_lz_compressed_size(&repetitive);
        assert!(comp_rep < 100, "repetitive data must compress dramatically");

        // High entropy sequence (LCG with period 2^32)
        let mut seed = 0x12345678u32;
        let random: Vec<u8> = (0..4096)
            .map(|_| {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                (seed >> 24) as u8
            })
            .collect();
        let comp_rnd = estimate_lz_compressed_size(&random);
        assert!(
            comp_rnd >= 3000,
            "pseudo-random sequence should have high compressed size"
        );
    }

    #[test]
    fn wof_blocks_windows_subtrees_and_skips_reparse_offline_system_and_caps_samples() {
        use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
        use crate::volume::VolumeInfo;
        use crate::win::junction::{create_mount_point_junction, remove_junction_link_only};
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let cancel = AtomicBool::new(false);

        // 1. Strictly block C:\Windows subtrees (even C:\Windows\Temp) outside CompactOS
        let blocked = compress_folder_wof(
            Path::new(r"C:\Windows\Temp"),
            WofAlgorithm::Xpress8k,
            true,
            &cancel,
        );
        assert!(matches!(blocked, Err(DskError::Denied(_))));

        // 2. Folder containing compressible text, incompressible files (pagefile.sys, .vhdx), and a junction
        let target = dir.path().join("wof_target");
        let outside = dir.path().join("outside");
        let nested_junc = target.join("junc_out");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let text_a = target.join("compressible_a.log");
        let text_b = target.join("compressible_b.log");
        let pagefile = target.join("pagefile.sys");
        let disk = target.join("vm.vhdx");
        std::fs::write(&text_a, "ABCD".repeat(4096)).unwrap();
        std::fs::write(&text_b, "EFGH".repeat(4096)).unwrap();
        std::fs::write(&pagefile, "Z".repeat(4096)).unwrap();
        std::fs::write(&disk, "Q".repeat(4096)).unwrap();
        std::fs::write(outside.join("outside.log"), "W".repeat(4096)).unwrap();
        create_mount_point_junction(&nested_junc, &outside).unwrap();

        // Dry run measures real file allocations (not directory 0 bytes)
        let dry_report =
            compress_folder_wof(&target, WofAlgorithm::Xpress8k, true, &cancel).unwrap();
        assert!(dry_report.before_allocated_bytes > 0);
        assert_eq!(dry_report.freed_bytes, 0);

        // Verify collection skips junction & incompressible files
        let (eligible, skipped_alloc, total_before) =
            collect_wof_targets(&target, &DenyContext::default(), &cancel).unwrap();
        assert_eq!(eligible.len(), 2);
        assert!(skipped_alloc > 0);
        assert!(total_before > skipped_alloc);

        // Build Index containing REPARSE, OFFLINE, SYSTEM, and C:\Windows nodes and test sampling + byte cap
        let root_str = format!(
            "{}\\",
            dir.path()
                .to_string_lossy()
                .chars()
                .take(2)
                .collect::<String>()
        );
        let root_trim = root_str.trim_end_matches('\\').to_string();
        let mut names = NameArena::new();
        let mut b = IndexBuilder::new(
            5,
            &root_str,
            VolumeInfo {
                root: root_str.clone(),
                ..Default::default()
            },
        );

        let mut entries = Vec::new();
        let n_root = names.push_str(&root_trim);
        entries.push(RawEntry {
            key: 5,
            parent_key: 5,
            name: n_root,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: 5,
            reparse_tag: 0,
        });

        let n_win = names.push_str("Windows");
        let n_win_temp = names.push_str("Temp");
        entries.push(RawEntry {
            key: 10,
            parent_key: 5,
            name: n_win,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: 10,
            reparse_tag: 0,
        });
        entries.push(RawEntry {
            key: 11,
            parent_key: 10,
            name: n_win_temp,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: 11,
            reparse_tag: 0,
        });

        let mut next_key = 20u64;
        let mut parent_key = 5u64;
        for comp in target.components() {
            if let std::path::Component::Normal(seg) = comp {
                let s = seg.to_string_lossy();
                let n = names.push_str(&s);
                entries.push(RawEntry {
                    key: next_key,
                    parent_key,
                    name: n,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: next_key,
                    reparse_tag: 0,
                });
                parent_key = next_key;
                next_key += 1;
            }
        }
        let folder_key = parent_key;

        let n_a = names.push_str("compressible_a.log");
        let n_b = names.push_str("compressible_b.log");
        let n_off = names.push_str("offline.log");
        let n_sys = names.push_str("system.log");
        let n_junc = names.push_str("junc_out");
        let n_junc_child = names.push_str("outside.log");
        let n_page = names.push_str("pagefile.sys");
        let junc_key = next_key + 3;
        entries.extend([
            RawEntry {
                key: next_key,
                parent_key: folder_key,
                name: n_a,
                flags: NodeFlags::empty(),
                logical: 16384,
                allocated: 16384,
                mtime: 0,
                atime: 0,
                file_id: next_key,
                reparse_tag: 0,
            },
            RawEntry {
                key: next_key + 1,
                parent_key: folder_key,
                name: n_off,
                flags: NodeFlags::OFFLINE,
                logical: 16384,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: next_key + 1,
                reparse_tag: 0,
            },
            RawEntry {
                key: next_key + 2,
                parent_key: folder_key,
                name: n_sys,
                flags: NodeFlags::SYSTEM,
                logical: 16384,
                allocated: 16384,
                mtime: 0,
                atime: 0,
                file_id: next_key + 2,
                reparse_tag: 0,
            },
            RawEntry {
                key: junc_key,
                parent_key: folder_key,
                name: n_junc,
                flags: NodeFlags::DIR | NodeFlags::REPARSE,
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: junc_key,
                reparse_tag: 0,
            },
            RawEntry {
                key: next_key + 4,
                parent_key: junc_key,
                name: n_junc_child,
                flags: NodeFlags::empty(),
                logical: 16384,
                allocated: 16384,
                mtime: 0,
                atime: 0,
                file_id: next_key + 4,
                reparse_tag: 0,
            },
            RawEntry {
                key: next_key + 5,
                parent_key: folder_key,
                name: n_page,
                flags: NodeFlags::empty(),
                logical: 4096,
                allocated: 4096,
                mtime: 0,
                atime: 0,
                file_id: next_key + 5,
                reparse_tag: 0,
            },
            RawEntry {
                key: next_key + 6,
                parent_key: folder_key,
                name: n_b,
                flags: NodeFlags::empty(),
                logical: 16384,
                allocated: 16384,
                mtime: 0,
                atime: 0,
                file_id: next_key + 6,
                reparse_tag: 0,
            },
        ]);

        b.push_batch(EntryBatch { entries, names });
        let index = b.finish();

        let win_temp_id = index
            .find_by_path(Path::new(&format!("{root_str}Windows\\Temp")))
            .expect("Windows\\Temp node");
        let win_prev = sample_folder_compressibility(&index, win_temp_id).unwrap();
        assert!(!win_prev.recommended);
        assert!(
            win_prev
                .skip_reason
                .as_deref()
                .unwrap_or("")
                .contains("blocked")
        );

        let folder_id = index.find_by_path(&target).expect("target folder node");
        let capped = sample_folder_compressibility_with_cap(&index, folder_id, 1024).unwrap();
        assert!(capped.sampled_bytes <= 1024);
        assert!(capped.recommended);

        let _ = remove_junction_link_only(&nested_junc);
    }

    fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn wof_rejects_windows_reached_through_an_ancestor_junction() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("win_link");
        let windir = system32_dir().parent().unwrap().to_path_buf();
        crate::win::junction::create_mount_point_junction(&link, &windir).unwrap();

        // Lexically under %TEMP%, but the kernel resolves it to C:\Windows\Help.
        let smuggled = link.join("Help");
        let cancel = AtomicBool::new(false);
        let res = compress_folder_wof(&smuggled, WofAlgorithm::Xpress8k, true, &cancel);
        let _ = crate::win::junction::remove_junction_link_only(&link);
        assert!(matches!(res, Err(DskError::Denied(_))), "got {res:?}");
    }

    #[test]
    fn sample_windows_are_weighted_by_bytes() {
        // One 1 GiB file and a thousand 4 KiB files: the big file gets almost all windows.
        let mut sizes = vec![4096u64; 1000];
        sizes.push(1 << 30);
        let windows = plan_sample_windows(&sizes, 8 * 1024 * 1024);
        let big = windows.iter().filter(|w| w.0 == 1000).count();
        assert!(big * 10 >= windows.len() * 9, "{big} of {}", windows.len());
        assert!(windows.iter().map(|w| w.2 as u64).sum::<u64>() <= 8 * 1024 * 1024);
        // Offsets are spread over the file, not just its start.
        let max_off = windows
            .iter()
            .filter(|w| w.0 == 1000)
            .map(|w| w.1)
            .max()
            .unwrap();
        assert!(max_off > (1 << 29));
        // Small folders are read in full.
        let all = plan_sample_windows(&[100_000, 3], 1 << 20);
        assert_eq!(all.iter().map(|w| w.2 as u64).sum::<u64>(), 100_003);
        assert!(plan_sample_windows(&[], 1 << 20).is_empty());
        // Cluster rounding: a 6 KiB file at ratio 0.5 still needs one 4 KiB cluster.
        assert_eq!(projected_file_savings(6144, 8192, 0.5, 4096), 4096);
        assert_eq!(projected_file_savings(4096, 4096, 0.1, 4096), 0);
    }

    /// P9.3: folder compression through the handle-based engine, then undo.
    #[test]
    fn folder_compress_and_undo_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("app");
        std::fs::create_dir_all(root.join("lib")).unwrap();
        let payload = "fn main() { println!(\"hello\"); } // padding padding\n"
            .repeat(4000)
            .into_bytes();
        for i in 0..6 {
            std::fs::write(root.join("lib").join(format!("m{i}.rs")), &payload).unwrap();
        }
        std::fs::write(root.join("movie.mp4"), vec![7u8; 50_000]).unwrap();
        let cancel = AtomicBool::new(false);

        let rep = compress_folder_wof_with(
            &root,
            WofAlgorithm::Xpress16k,
            false,
            &cancel,
            &WofApplyOptions {
                threads: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!((rep.files_compressed, rep.files_failed), (6, 0), "{rep:?}");
        assert!(rep.freed_bytes > 500_000, "{rep:?}");
        assert_eq!(
            crate::win::wof::wof_file_algorithm(&root.join("lib").join("m0.rs")),
            Some(WofAlgorithm::Xpress16k)
        );
        assert_eq!(
            crate::win::wof::wof_file_algorithm(&root.join("movie.mp4")),
            None,
            "incompressible types are skipped"
        );
        assert_eq!(
            std::fs::read(root.join("lib").join("m3.rs")).unwrap(),
            payload
        );

        let undo = decompress_folder_wof(&root, &cancel).unwrap();
        assert_eq!(
            (undo.files_compressed, undo.files_failed),
            (6, 0),
            "{undo:?}"
        );
        assert!(undo.after_allocated_bytes > undo.before_allocated_bytes);
        assert_eq!(
            crate::win::wof::wof_file_algorithm(&root.join("lib").join("m0.rs")),
            None
        );

        // Files written within `min_age_days` are left alone.
        let fresh = compress_folder_wof_with(
            &root,
            WofAlgorithm::Xpress8k,
            false,
            &cancel,
            &WofApplyOptions {
                min_age_days: 14,
                enforce_gate: false,
                threads: 1,
            },
        )
        .unwrap();
        assert_eq!(fresh.files_compressed, 0);
    }

    #[test]
    fn wof_live_compression_refuses_folders_below_savings_threshold() {
        let temp = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for i in 0..3u64 {
            let p = temp.path().join(format!("blob{i}.dat"));
            std::fs::write(&p, pseudo_random_bytes(8192, 0x9E37_79B9 + i)).unwrap();
            files.push(p);
        }
        let pct = sample_live_files_savings_pct(&files).unwrap();
        assert!(pct < MIN_WOF_SAVINGS_PCT, "random data pct {pct}");

        // Rejected by the sample gate before compact.exe is ever invoked.
        let cancel = AtomicBool::new(false);
        let res = compress_folder_wof(temp.path(), WofAlgorithm::Xpress8k, false, &cancel);
        assert!(
            matches!(res, Err(DskError::PreconditionFailed(ref m)) if m.contains("15")),
            "got {res:?}"
        );

        let text = temp.path().join("notes.txt");
        std::fs::write(&text, "repetitive log line\n".repeat(2000)).unwrap();
        assert!(sample_live_files_savings_pct(&[text]).unwrap() >= MIN_WOF_SAVINGS_PCT);
    }
}
