#![forbid(unsafe_code)]

//! Duplicate file detection and safe remediation engine (§9.3).
//!
//! Guarantees zero cloud placeholder hydration via [`open_cloud_safe_read`], collapses NTFS
//! `(volume_serial, file_id)` hard links *before* hashing, adapts `rayon` worker concurrency
//! to `VolumeInfo::seek_penalty`, and caches validated BLAKE3 digests in SQLite.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rayon::prelude::*;
use rusqlite::{Connection, OptionalExtension, params};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::clean::deny::{DenyContext, is_denied_path};
use crate::clean::journal::{ActionJournal, JournalEntryRecord, JournalRunRecord};
use crate::error::{DskError, Result};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::win::recycle::move_to_recycle_bin;
use crate::win::reflink::{
    clone_file_extents_refs, file_stamp, open_cloud_safe_read, replace_with_readonly_hardlink,
};

const PARTIAL_WINDOW_BYTES: usize = 4096;
const FULL_HASH_CHUNK_BYTES: usize = 128 * 1024;
const HDD_MIN_POOL_THREADS: usize = 1;
const SSD_MAX_POOL_THREADS: usize = 8;

/// Progress stage reported during duplicate scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DupeStage {
    Collecting,
    PartialHash,
    FullHash,
    Done,
}

/// Progress update emitted by [`find_duplicates`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DupeProgress {
    pub stage: DupeStage,
    pub done: usize,
    pub total: usize,
}

/// One concrete file belonging to a verified duplicate group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DupFileEntry {
    pub node_id: NodeId,
    pub path: PathBuf,
    pub file_id: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub mtime_min: u32,
    pub atime_min: u32,
    /// The inode has other hard links: removing or relinking this path frees nothing.
    #[serde(default)]
    pub hardlinked: bool,
}

impl DupFileEntry {
    /// Bytes actually freed by removing this path (0 when other hard links keep the data alive).
    pub fn reclaimable_bytes(&self) -> u64 {
        if self.hardlinked {
            0
        } else if self.allocated_bytes > 0 {
            self.allocated_bytes
        } else {
            self.logical_bytes
        }
    }
}

/// Verified identical files sharing size, partial xxHash3, and full BLAKE3 digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub blake3_hex: String,
    pub file_size: u64,
    pub files: Vec<DupFileEntry>,
    pub reclaimable_bytes: u64,
}

/// Execution telemetry for a duplicate scan run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DupeStats {
    pub total_candidates: usize,
    pub collapsed_hardlinks: usize,
    pub size_buckets: usize,
    pub partial_hashed: usize,
    pub full_hashed: usize,
    pub cache_hits: usize,
    pub seek_penalty: Option<bool>,
    pub worker_threads: usize,
}

/// Complete duplicate detection report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DupeReport {
    pub volume_root: String,
    pub min_bytes: u64,
    pub groups: Vec<DuplicateGroup>,
    pub total_wasted_bytes: u64,
    pub stats: DupeStats,
}

/// Safe duplicate remediation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DupeRemediationAction {
    RecycleDuplicates,
    ReplaceWithHardlinks,
    CloneExtentsRefs,
}

/// Result summary from remediating a [`DuplicateGroup`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DupeRemediationOutcome {
    pub dry_run: bool,
    pub action: DupeRemediationAction,
    pub processed: usize,
    pub skipped: usize,
    pub reclaimed_bytes: u64,
    pub notes: Vec<String>,
}

/// Returns the default user-scoped SQLite path for cached duplicate file hashes.
pub fn default_hash_cache_path() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("DiskSaver").join("hash_cache.sqlite")
}

/// Persistent SQLite cache mapping `(volume_serial, file_id)` to `(size, mtime, blake3)`.
pub struct HashCacheDb {
    conn: Connection,
}

impl HashCacheDb {
    /// Opens (creating parent directory and schema if missing) the hash cache database.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).map_err(|e| DskError::Journal(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 3000;
             CREATE TABLE IF NOT EXISTS file_hashes (
                 volume_serial INTEGER NOT NULL,
                 file_id       INTEGER NOT NULL,
                 size_bytes    INTEGER NOT NULL,
                 mtime_min     INTEGER NOT NULL,
                 blake3        BLOB NOT NULL,
                 updated_at    INTEGER NOT NULL,
                 PRIMARY KEY (volume_serial, file_id)
             );",
        )
        .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Looks up a cached BLAKE3 digest, returning `None` on size or mtime mismatch.
    pub fn lookup(
        &self,
        volume_serial: u32,
        file_id: u64,
        size_bytes: u64,
        mtime_min: u32,
    ) -> Result<Option<[u8; 32]>> {
        if file_id == 0 || size_bytes > i64::MAX as u64 {
            return Ok(None);
        }
        let row = self
            .conn
            .query_row(
                "SELECT size_bytes, mtime_min, blake3
                 FROM file_hashes
                 WHERE volume_serial = ?1 AND file_id = ?2",
                params![i64::from(volume_serial), file_id as i64],
                |r| {
                    let cached_size: i64 = r.get(0)?;
                    let cached_mtime: i64 = r.get(1)?;
                    let digest: Vec<u8> = r.get(2)?;
                    Ok((cached_size, cached_mtime, digest))
                },
            )
            .optional()
            .map_err(|e| DskError::Journal(e.to_string()))?;

        let Some((cached_size, cached_mtime, digest)) = row else {
            return Ok(None);
        };
        if cached_size < 0
            || cached_size as u64 != size_bytes
            || cached_mtime < 0
            || cached_mtime as u64 != u64::from(mtime_min)
            || digest.len() != 32
        {
            return Ok(None);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(Some(out))
    }

    /// Stores a batch of verified BLAKE3 digests inside one transaction.
    pub fn store_batch(&mut self, rows: &[(u32, u64, u64, u32, [u8; 32])]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
            .unwrap_or(0);
        let tx = self
            .conn
            .transaction()
            .map_err(|e| DskError::Journal(e.to_string()))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO file_hashes
                         (volume_serial, file_id, size_bytes, mtime_min, blake3, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(volume_serial, file_id) DO UPDATE SET
                         size_bytes = excluded.size_bytes,
                         mtime_min  = excluded.mtime_min,
                         blake3     = excluded.blake3,
                         updated_at = excluded.updated_at",
                )
                .map_err(|e| DskError::Journal(e.to_string()))?;
            for &(vol_serial, file_id, size_bytes, mtime_min, ref digest) in rows {
                if file_id == 0 || size_bytes > i64::MAX as u64 {
                    continue;
                }
                stmt.execute(params![
                    i64::from(vol_serial),
                    file_id as i64,
                    size_bytes as i64,
                    i64::from(mtime_min),
                    digest.as_slice(),
                    now_secs,
                ])
                .map_err(|e| DskError::Journal(e.to_string()))?;
            }
        }
        tx.commit().map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }
}

fn partial_hash_file(path: &Path, expected_len: u64) -> Result<u64> {
    let mut file = open_cloud_safe_read(path)?;
    let actual_len = file.metadata()?.len();
    if actual_len != expected_len {
        return Err(DskError::PreconditionFailed(format!(
            "file size changed before partial hash: {}",
            path.display()
        )));
    }

    if expected_len <= (PARTIAL_WINDOW_BYTES * 2) as u64 {
        let mut buf = Vec::with_capacity(expected_len as usize);
        file.read_to_end(&mut buf)?;
        return Ok(xxh3_64(&buf));
    }

    let mut head = [0u8; PARTIAL_WINDOW_BYTES];
    file.read_exact(&mut head)?;

    file.seek(SeekFrom::End(-(PARTIAL_WINDOW_BYTES as i64)))?;
    let mut tail = [0u8; PARTIAL_WINDOW_BYTES];
    file.read_exact(&mut tail)?;

    let mut combined = Vec::with_capacity(PARTIAL_WINDOW_BYTES * 2 + 8);
    combined.extend_from_slice(&expected_len.to_le_bytes());
    combined.extend_from_slice(&head);
    combined.extend_from_slice(&tail);
    Ok(xxh3_64(&combined))
}

fn full_hash_file(path: &Path, expected_len: u64, cancel: &AtomicBool) -> Result<[u8; 32]> {
    let mut file: File = open_cloud_safe_read(path)?;
    let actual_len = file.metadata()?.len();
    if actual_len != expected_len {
        return Err(DskError::PreconditionFailed(format!(
            "file size changed before full hash: {}",
            path.display()
        )));
    }

    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; FULL_HASH_CHUNK_BYTES];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn format_hex_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn choose_worker_threads(seek_penalty: Option<bool>, requested: Option<usize>) -> usize {
    if let Some(n) = requested {
        return n.max(HDD_MIN_POOL_THREADS);
    }
    match seek_penalty {
        Some(false) => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(2, SSD_MAX_POOL_THREADS),
        // Unknown or rotational media stays single-threaded sequential by file_id.
        _ => HDD_MIN_POOL_THREADS,
    }
}

fn collect_unique_inode_candidates(
    index: &Index,
    min_bytes: u64,
    deny_ctx: &DenyContext,
    cancel: &AtomicBool,
) -> Result<(Vec<DupFileEntry>, usize)> {
    let min_logical = min_bytes.max(1);
    let vol_serial = index.volume().serial;
    let mut stack = vec![ROOT];
    let mut seen_inodes: FxHashSet<(u32, u64)> = FxHashSet::default();
    let mut collapsed_hardlinks = 0usize;
    let mut out = Vec::new();

    while let Some(node) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }
        let flags = index.flags(node);
        if node != ROOT
            && flags.intersects(
                NodeFlags::REPARSE
                    | NodeFlags::SYSTEM
                    | NodeFlags::ORPHANS
                    | NodeFlags::CLOUD
                    | NodeFlags::OFFLINE
                    | NodeFlags::METAFILE,
            )
        {
            continue;
        }
        if flags.contains(NodeFlags::DIR) {
            let dir_lower = index.path(node).to_string_lossy().to_ascii_lowercase();
            let dir_sep = if dir_lower.ends_with('\\') {
                dir_lower
            } else {
                format!("{dir_lower}\\")
            };
            if node != ROOT
                && (dir_sep.contains(r"\windows\")
                    || dir_sep.contains(r"\$recycle.bin\")
                    || dir_sep.contains(r"\system volume information\"))
            {
                continue;
            }
            let start = stack.len();
            for child in index.children(node) {
                stack.push(child);
            }
            stack[start..].reverse();
            continue;
        }

        let logical = index.logical(node);
        if logical < min_logical {
            continue;
        }
        let path = index.path(node);
        if is_denied_path(&path, deny_ctx).is_some() {
            continue;
        }

        let file_id = index.file_id(node);
        if file_id != 0 && !seen_inodes.insert((vol_serial, file_id)) {
            collapsed_hardlinks = collapsed_hardlinks.saturating_add(1);
            continue;
        }

        out.push(DupFileEntry {
            node_id: node,
            path,
            file_id,
            logical_bytes: logical,
            allocated_bytes: index.allocated(node),
            mtime_min: index.mtime_min(node),
            atime_min: index.atime_min(node),
            hardlinked: flags.contains(NodeFlags::HARDLINK),
        });
    }

    Ok((out, collapsed_hardlinks))
}

/// Finds content-identical duplicate files across `index` without hydrating cloud files,
/// collapsing hard links first and sizing worker concurrency via `seek_penalty`.
pub fn find_duplicates<F>(
    index: &Index,
    min_bytes: u64,
    cache_db_path: Option<&Path>,
    threads: Option<usize>,
    cancel: &AtomicBool,
    mut progress: F,
) -> Result<DupeReport>
where
    F: FnMut(DupeProgress),
{
    let vol_info = index.volume();
    let vol_serial = vol_info.serial;
    let seek_penalty = vol_info.seek_penalty;
    let worker_threads = choose_worker_threads(seek_penalty, threads);
    let deny_ctx = DenyContext::default();

    progress(DupeProgress {
        stage: DupeStage::Collecting,
        done: 0,
        total: 0,
    });

    let (candidates, collapsed_hardlinks) =
        collect_unique_inode_candidates(index, min_bytes, &deny_ctx, cancel)?;
    let total_candidates = candidates.len();

    let mut by_size: FxHashMap<u64, Vec<DupFileEntry>> = FxHashMap::default();
    for entry in candidates {
        by_size.entry(entry.logical_bytes).or_default().push(entry);
    }

    let mut partial_candidates: Vec<DupFileEntry> = Vec::new();
    let mut size_buckets = 0usize;
    for (_sz, mut bucket) in by_size {
        if bucket.len() >= 2 {
            size_buckets += 1;
            partial_candidates.append(&mut bucket);
        }
    }

    if worker_threads == 1 {
        partial_candidates
            .sort_by(|a, b| a.file_id.cmp(&b.file_id).then_with(|| a.path.cmp(&b.path)));
    }

    let partial_total = partial_candidates.len();
    progress(DupeProgress {
        stage: DupeStage::PartialHash,
        done: 0,
        total: partial_total,
    });

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_threads)
        .build()
        .map_err(|e| DskError::Optimize(format!("failed to create duplicate worker pool: {e}")))?;

    let partial_done = AtomicUsize::new(0);
    let partial_results: Vec<(DupFileEntry, Option<u64>)> = pool.install(|| {
        partial_candidates
            .into_par_iter()
            .map(|entry| {
                if cancel.load(Ordering::Relaxed) {
                    return (entry, None);
                }
                let h = partial_hash_file(&entry.path, entry.logical_bytes).ok();
                partial_done.fetch_add(1, Ordering::Relaxed);
                (entry, h)
            })
            .collect()
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }
    progress(DupeProgress {
        stage: DupeStage::PartialHash,
        done: partial_total,
        total: partial_total,
    });

    let mut by_partial: FxHashMap<(u64, u64), Vec<DupFileEntry>> = FxHashMap::default();
    for (entry, partial) in partial_results {
        if let Some(h) = partial {
            by_partial
                .entry((entry.logical_bytes, h))
                .or_default()
                .push(entry);
        }
    }

    let mut full_candidates: Vec<DupFileEntry> = Vec::new();
    for (_key, mut bucket) in by_partial {
        if bucket.len() >= 2 {
            full_candidates.append(&mut bucket);
        }
    }

    if worker_threads == 1 {
        full_candidates.sort_by(|a, b| a.file_id.cmp(&b.file_id).then_with(|| a.path.cmp(&b.path)));
    }

    let full_total = full_candidates.len();
    progress(DupeProgress {
        stage: DupeStage::FullHash,
        done: 0,
        total: full_total,
    });

    let mut db = match cache_db_path {
        Some(p) => Some(HashCacheDb::open(p)?),
        None => None,
    };

    let mut cache_hits = 0usize;
    let mut cached_pairs: Vec<(DupFileEntry, [u8; 32])> = Vec::new();
    let mut cache_misses: Vec<DupFileEntry> = Vec::with_capacity(full_candidates.len());

    for entry in full_candidates {
        if let Some(ref cache) = db
            && let Some(digest) = cache.lookup(
                vol_serial,
                entry.file_id,
                entry.logical_bytes,
                entry.mtime_min,
            )?
        {
            cache_hits += 1;
            cached_pairs.push((entry, digest));
            continue;
        }
        cache_misses.push(entry);
    }

    let full_done = AtomicUsize::new(cache_hits);
    let computed_pairs: Vec<(DupFileEntry, Option<[u8; 32]>)> = pool.install(|| {
        cache_misses
            .into_par_iter()
            .map(|entry| {
                if cancel.load(Ordering::Relaxed) {
                    return (entry, None);
                }
                let digest = full_hash_file(&entry.path, entry.logical_bytes, cancel).ok();
                full_done.fetch_add(1, Ordering::Relaxed);
                (entry, digest)
            })
            .collect()
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }
    progress(DupeProgress {
        stage: DupeStage::FullHash,
        done: full_total,
        total: full_total,
    });

    let mut new_cache_rows: Vec<(u32, u64, u64, u32, [u8; 32])> = Vec::new();
    let mut by_blake3: FxHashMap<(u64, [u8; 32]), Vec<DupFileEntry>> = FxHashMap::default();

    for (entry, digest) in cached_pairs {
        by_blake3
            .entry((entry.logical_bytes, digest))
            .or_default()
            .push(entry);
    }
    for (entry, maybe_digest) in computed_pairs {
        if let Some(digest) = maybe_digest {
            if entry.file_id != 0 {
                new_cache_rows.push((
                    vol_serial,
                    entry.file_id,
                    entry.logical_bytes,
                    entry.mtime_min,
                    digest,
                ));
            }
            by_blake3
                .entry((entry.logical_bytes, digest))
                .or_default()
                .push(entry);
        }
    }

    if let Some(ref mut cache) = db {
        cache.store_batch(&new_cache_rows)?;
    }

    let mut groups = Vec::new();
    let mut total_wasted_bytes = 0u64;
    for ((file_size, digest), mut files) in by_blake3 {
        if files.len() < 2 {
            continue;
        }
        // Default keeper (index 0): prefer a hard-linked member (removing it would free nothing),
        // then the oldest copy.
        files.sort_by(|a, b| {
            b.hardlinked
                .cmp(&a.hardlinked)
                .then_with(|| a.mtime_min.cmp(&b.mtime_min))
                .then_with(|| a.path.cmp(&b.path))
        });
        let reclaimable_bytes: u64 = files
            .iter()
            .skip(1)
            .map(DupFileEntry::reclaimable_bytes)
            .fold(0u64, u64::saturating_add);
        total_wasted_bytes = total_wasted_bytes.saturating_add(reclaimable_bytes);
        groups.push(DuplicateGroup {
            blake3_hex: format_hex_32(&digest),
            file_size,
            files,
            reclaimable_bytes,
        });
    }

    groups.sort_by(|a, b| {
        b.reclaimable_bytes
            .cmp(&a.reclaimable_bytes)
            .then_with(|| b.file_size.cmp(&a.file_size))
            .then_with(|| a.blake3_hex.cmp(&b.blake3_hex))
    });

    progress(DupeProgress {
        stage: DupeStage::Done,
        done: full_total,
        total: full_total,
    });

    Ok(DupeReport {
        volume_root: vol_info.root.clone(),
        min_bytes,
        groups,
        total_wasted_bytes,
        stats: DupeStats {
            total_candidates,
            collapsed_hardlinks,
            size_buckets,
            partial_hashed: partial_total,
            full_hashed: full_total,
            cache_hits,
            seek_penalty,
            worker_threads,
        },
    })
}

/// Content class of a duplicate group (P9.6), deciding the default remediation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DupeClass {
    /// Content-addressed caches and model weights: nothing ever rewrites them in place, so a
    /// read-only hard link is invisible.
    ImmutableStore,
    /// Archives, installers, disk images, and media: rarely edited; hard link or recycle a copy.
    ReadMostly,
    /// Inside an application install folder: updaters may rewrite files in place, so never link.
    AppInstall,
    /// Anything else (documents, source, data): recycle the extra copy or leave it.
    Other,
}

const IMMUTABLE_STORE_MARKERS: &[&str] = &[
    r"\huggingface\hub\",
    r"\.ollama\models\blobs\",
    r"\ollama\models\blobs\",
    r"\.lmstudio\models\",
    r"\lm-studio\models\",
    r"\.cache\torch\hub\",
    r"\pip\cache\",
    r"\uv\cache\",
    r"\.cargo\registry\cache\",
    r"\npm-cache\_cacache\",
];

const MODEL_EXTS: &[&str] = &["gguf", "safetensors", "ckpt", "pt", "pth", "onnx", "bin"];

const READ_MOSTLY_EXTS: &[&str] = &[
    "zip", "7z", "rar", "tar", "gz", "tgz", "xz", "zst", "iso", "img", "msi", "msix", "exe", "cab",
    "mp4", "mkv", "mov", "avi", "webm", "mp3", "flac", "wav", "jpg", "jpeg", "png", "heic", "raw",
    "cr2", "nef", "pdf",
];

const APP_INSTALL_MARKERS: &[&str] = &[
    r"\program files\",
    r"\program files (x86)\",
    r"\appdata\local\programs\",
    r"\windows\",
    r"\windowsapps\",
    r"\steamapps\common\",
    r"\epic games\",
    r"\.vscode\extensions\",
    r"\node_modules\",
    r"\site-packages\",
    r"\miniconda3\",
    r"\anaconda3\",
];

/// Classifies one path.
pub fn classify_dupe_path(path: &Path) -> DupeClass {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if APP_INSTALL_MARKERS.iter().any(|m| lower.contains(m)) {
        return DupeClass::AppInstall;
    }
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if IMMUTABLE_STORE_MARKERS.iter().any(|m| lower.contains(m))
        || (MODEL_EXTS.contains(&ext.as_str()) && lower.contains(r"\models"))
    {
        return DupeClass::ImmutableStore;
    }
    if READ_MOSTLY_EXTS.contains(&ext.as_str()) {
        return DupeClass::ReadMostly;
    }
    DupeClass::Other
}

/// Classifies a group: the most restrictive member class wins (an app-install copy makes the
/// whole group `AppInstall`).
pub fn classify_dupe_group(group: &DuplicateGroup) -> DupeClass {
    let rank = |c: DupeClass| match c {
        DupeClass::AppInstall => 0,
        DupeClass::Other => 1,
        DupeClass::ReadMostly => 2,
        DupeClass::ImmutableStore => 3,
    };
    group
        .files
        .iter()
        .map(|f| classify_dupe_path(&f.path))
        .min_by_key(|&c| rank(c))
        .unwrap_or(DupeClass::Other)
}

/// Whether replacing the extra copies with read-only hard links is invisible to the owner:
/// immutable-store groups only, and only when no member already has other hard links.
pub fn is_hardlink_safe_group(group: &DuplicateGroup) -> bool {
    classify_dupe_group(group) == DupeClass::ImmutableStore
        && !group.files.iter().any(|f| f.hardlinked)
}

/// Safely remediates all copies in `group` except `keep_index` using Recycle Bin, NTFS
/// read-only hard links, or ReFS extent cloning, while verifying live file integrity first.
pub fn remediate_duplicate_group(
    group: &DuplicateGroup,
    keep_index: usize,
    action: DupeRemediationAction,
    dry_run: bool,
    journal_path: Option<&Path>,
    volume_root: &str,
    deny_ctx: &DenyContext,
) -> Result<DupeRemediationOutcome> {
    if group.files.len() < 2 || keep_index >= group.files.len() {
        return Err(DskError::PreconditionFailed(
            "invalid duplicate group or keep_index".to_string(),
        ));
    }

    let canonical = &group.files[keep_index];
    if let Some(reason) = is_denied_path(&canonical.path, deny_ctx) {
        return Err(DskError::DeniedPath(format!(
            "{reason}: {}",
            canonical.path.display()
        )));
    }

    let cancel = AtomicBool::new(false);
    // Stamp first, then hash: any write that lands after this point changes the stamp and is
    // detected right before the replacement swap.
    let canonical_stamp = file_stamp(&canonical.path)?;
    // Verify canonical file still exists cleanly and matches expected digest before acting on duplicates.
    let canonical_digest = full_hash_file(&canonical.path, group.file_size, &cancel)?;
    if format_hex_32(&canonical_digest) != group.blake3_hex {
        return Err(DskError::PreconditionFailed(format!(
            "canonical file modified since duplicate scan: {}",
            canonical.path.display()
        )));
    }

    let mut journal = if !dry_run {
        Some(ActionJournal::open(
            journal_path.unwrap_or(&ActionJournal::default_path()),
        )?)
    } else {
        None
    };
    let started_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let run_id = format!(
        "dupes-{}-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        std::process::id(),
        group.blake3_hex.get(..12).unwrap_or("group")
    );
    let mut replace_entries: Vec<JournalEntryRecord> = Vec::new();

    let mut processed = 0usize;
    let mut skipped = 0usize;
    let mut reclaimed_bytes = 0u64;
    let mut notes = Vec::new();

    for (idx, candidate) in group.files.iter().enumerate() {
        if idx == keep_index {
            continue;
        }
        if let Some(reason) = is_denied_path(&candidate.path, deny_ctx) {
            skipped += 1;
            notes.push(format!(
                "skipped denied path ({reason}): {}",
                candidate.path.display()
            ));
            continue;
        }

        let cand_stamp = match file_stamp(&candidate.path) {
            Ok(s) => s,
            Err(e) => {
                skipped += 1;
                notes.push(format!("skipped '{}' ({e})", candidate.path.display()));
                continue;
            }
        };
        let cand_digest = match full_hash_file(&candidate.path, group.file_size, &cancel) {
            Ok(d) => d,
            Err(e) => {
                skipped += 1;
                notes.push(format!("skipped '{}' ({e})", candidate.path.display()));
                continue;
            }
        };
        if format_hex_32(&cand_digest) != group.blake3_hex {
            skipped += 1;
            notes.push(format!(
                "skipped modified duplicate: {}",
                candidate.path.display()
            ));
            continue;
        }

        let est = candidate.reclaimable_bytes();

        if dry_run {
            processed += 1;
            reclaimed_bytes = reclaimed_bytes.saturating_add(est);
            continue;
        }

        // A failure on one copy (too big for the Recycle Bin, changed since verification, ...) is
        // reported per file instead of aborting the rest of the group.
        let result = match action {
            DupeRemediationAction::RecycleDuplicates => {
                move_to_recycle_bin(&candidate.path, deny_ctx).and_then(|outcome| {
                    let saved = if candidate.hardlinked {
                        0
                    } else {
                        outcome.bytes_hint.max(est)
                    };
                    if let Some(ref mut j) = journal {
                        j.record_manual_recycle(
                            volume_root,
                            &outcome.canonical_path,
                            outcome.bytes_hint,
                            saved.min(i64::MAX as u64) as i64,
                        )?;
                    }
                    Ok(saved)
                })
            }
            DupeRemediationAction::ReplaceWithHardlinks => replace_with_readonly_hardlink(
                &candidate.path,
                &canonical.path,
                Some((cand_stamp, canonical_stamp)),
            ),
            DupeRemediationAction::CloneExtentsRefs => clone_file_extents_refs(
                &canonical.path,
                &candidate.path,
                Some((cand_stamp, canonical_stamp)),
            ),
        };

        match result {
            Ok(saved) => {
                let saved = if candidate.hardlinked { 0 } else { saved };
                reclaimed_bytes = reclaimed_bytes.saturating_add(saved);
                processed += 1;
                let disposition = match action {
                    DupeRemediationAction::RecycleDuplicates => None,
                    DupeRemediationAction::ReplaceWithHardlinks => Some("hardlink_replace"),
                    DupeRemediationAction::CloneExtentsRefs => Some("reflink_clone"),
                };
                if let Some(disposition) = disposition {
                    replace_entries.push(JournalEntryRecord {
                        id: 0,
                        run_id: run_id.clone(),
                        rule_id: "insights.dupes".to_string(),
                        path: candidate.path.to_string_lossy().into_owned(),
                        file_id: candidate.file_id,
                        size_bytes: saved,
                        disposition: disposition.to_string(),
                        status: "replaced".to_string(),
                        error_msg: Some(format!("linked to {}", canonical.path.display())),
                    });
                }
            }
            Err(e) => {
                skipped += 1;
                notes.push(format!("failed '{}' ({e})", candidate.path.display()));
            }
        }
    }

    if let Some(ref mut j) = journal
        && !replace_entries.is_empty()
    {
        let finished_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(started_at_unix);
        let run = JournalRunRecord {
            run_id: run_id.clone(),
            started_at_unix,
            finished_at_unix,
            volume: volume_root.to_string(),
            dry_run: false,
            est_bytes: group.reclaimable_bytes,
            freed_measured: reclaimed_bytes.min(i64::MAX as u64) as i64,
            items_ok: replace_entries.len() as u64,
            items_skipped: 0,
            items_failed: skipped as u64,
        };
        j.record_run(&run, &replace_entries)?;
    }

    Ok(DupeRemediationOutcome {
        dry_run,
        action,
        processed,
        skipped,
        reclaimed_bytes,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::volume::VolumeInfo;
    use std::fs;
    use tempfile::tempdir;

    fn build_disk_backed_index(
        root: &Path,
        entries_spec: Vec<(String, u64, NodeFlags, u64, u32)>,
        seek_penalty: Option<bool>,
    ) -> Index {
        let mut names = NameArena::new();
        let root_name = names.push_str(&root.to_string_lossy());
        let mut raw = vec![RawEntry {
            key: 5,
            parent_key: 5,
            name: root_name,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: 5,
            reparse_tag: 0,
        }];
        for (offset, (rel, bytes, flags, fid, mtime_min)) in entries_spec.into_iter().enumerate() {
            let key = 10u64 + offset as u64;
            let n = names.push_str(&rel);
            raw.push(RawEntry {
                key,
                parent_key: 5,
                name: n,
                flags,
                logical: bytes,
                allocated: bytes,
                mtime: crate::time::FILETIME_EPOCH_2000
                    + u64::from(mtime_min) * crate::time::INTERVALS_PER_MINUTE,
                atime: 0,
                file_id: fid,
                reparse_tag: 0,
            });
        }
        let root_str = root.to_string_lossy().into_owned();
        let mut b = IndexBuilder::new(
            5,
            &root_str,
            VolumeInfo {
                root: root_str.clone(),
                serial: 0xABCD_1234,
                seek_penalty,
                ..Default::default()
            },
        );
        b.push_batch(EntryBatch {
            entries: raw,
            names,
        });
        b.finish()
    }

    #[test]
    fn finds_exact_duplicates_collapses_hardlinks_and_skips_cloud_offline() {
        let dir = tempdir().expect("tempdir");
        let a = dir.path().join("alpha.bin");
        let b = dir.path().join("beta.bin");
        let uniq = dir.path().join("unique.bin");
        let offline_clone = dir.path().join("cloud.bin");
        let hl_alias = dir.path().join("alpha_hardlink.bin");

        let payload_dup = vec![0x5Au8; 16 * 1024];
        let mut payload_uniq = vec![0x5Au8; 16 * 1024];
        payload_uniq[9000] = 0x11; // differs only in the middle (tests full blake3 after partial match)

        fs::write(&a, &payload_dup).expect("write a");
        fs::write(&b, &payload_dup).expect("write b");
        fs::write(&uniq, &payload_uniq).expect("write uniq");
        fs::write(&offline_clone, &payload_dup).expect("write cloud");
        fs::hard_link(&a, &hl_alias).expect("hard link");

        let index = build_disk_backed_index(
            dir.path(),
            vec![
                (
                    "alpha.bin".to_string(),
                    payload_dup.len() as u64,
                    NodeFlags::empty(),
                    101,
                    10,
                ),
                (
                    "alpha_hardlink.bin".to_string(),
                    payload_dup.len() as u64,
                    NodeFlags::HARDLINK,
                    101,
                    10,
                ),
                (
                    "beta.bin".to_string(),
                    payload_dup.len() as u64,
                    NodeFlags::empty(),
                    102,
                    20,
                ),
                (
                    "unique.bin".to_string(),
                    payload_uniq.len() as u64,
                    NodeFlags::empty(),
                    103,
                    15,
                ),
                (
                    "cloud.bin".to_string(),
                    payload_dup.len() as u64,
                    NodeFlags::CLOUD | NodeFlags::OFFLINE,
                    104,
                    25,
                ),
            ],
            Some(true), // HDD sequential fallback check
        );

        let cancel = AtomicBool::new(false);
        let db_path = dir.path().join("cache.sqlite");
        let report = find_duplicates(&index, 4096, Some(&db_path), None, &cancel, |_| {})
            .expect("find duplicates");

        assert_eq!(report.stats.collapsed_hardlinks, 1);
        assert_eq!(report.stats.worker_threads, 1);
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].files.len(), 2);
        let names: Vec<String> = report.groups[0]
            .files
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["alpha.bin", "beta.bin"]);
        assert_eq!(report.total_wasted_bytes, payload_dup.len() as u64);

        // Second run must hit SQLite HashCacheDb cleanly.
        let report2 = find_duplicates(&index, 4096, Some(&db_path), Some(2), &cancel, |_| {})
            .expect("second find");
        assert_eq!(report2.stats.worker_threads, 2);
        assert!(report2.stats.cache_hits >= 2);
    }

    #[test]
    fn hardlinked_members_reclaim_nothing() {
        let mk = |hardlinked: bool, allocated: u64| DupFileEntry {
            node_id: 1,
            path: PathBuf::from(r"C:\x.bin"),
            file_id: 1,
            logical_bytes: 4096,
            allocated_bytes: allocated,
            mtime_min: 0,
            atime_min: 0,
            hardlinked,
        };
        assert_eq!(mk(false, 8192).reclaimable_bytes(), 8192);
        assert_eq!(mk(false, 0).reclaimable_bytes(), 4096);
        // Another link (e.g. a pnpm store entry) keeps the data alive.
        assert_eq!(mk(true, 8192).reclaimable_bytes(), 0);
    }

    #[test]
    fn hash_cache_db_invalidates_on_size_or_mtime_change() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("cache.sqlite");
        let mut db = HashCacheDb::open(&db_path).expect("open cache");

        let digest = [0xAAu8; 32];
        db.store_batch(&[(0x1234, 999, 8192, 500, digest)])
            .expect("store");
        assert_eq!(
            db.lookup(0x1234, 999, 8192, 500).expect("hit"),
            Some(digest)
        );
        assert_eq!(db.lookup(0x1234, 999, 8193, 500).expect("size miss"), None);
        assert_eq!(db.lookup(0x1234, 999, 8192, 501).expect("mtime miss"), None);
    }

    #[test]
    fn remediate_duplicate_group_supports_dry_run_and_hardlink_replacement() {
        let dir = tempdir().expect("tempdir");
        let keep = dir.path().join("keep.dat");
        let dup = dir.path().join("copy.dat");
        let content = vec![0x42u8; 8192];
        fs::write(&keep, &content).expect("write keep");
        fs::write(&dup, &content).expect("write dup");

        let index = build_disk_backed_index(
            dir.path(),
            vec![
                (
                    "keep.dat".to_string(),
                    content.len() as u64,
                    NodeFlags::empty(),
                    201,
                    5,
                ),
                (
                    "copy.dat".to_string(),
                    content.len() as u64,
                    NodeFlags::empty(),
                    202,
                    10,
                ),
            ],
            Some(false),
        );
        let cancel = AtomicBool::new(false);
        let report = find_duplicates(&index, 1024, None, None, &cancel, |_| {}).expect("scan");
        assert_eq!(
            report.stats.worker_threads.clamp(2, 8),
            report.stats.worker_threads
        );
        assert_eq!(report.groups.len(), 1);

        let deny_ctx = DenyContext::default();
        let dry = remediate_duplicate_group(
            &report.groups[0],
            0,
            DupeRemediationAction::ReplaceWithHardlinks,
            true,
            None,
            &dir.path().to_string_lossy(),
            &deny_ctx,
        )
        .expect("dry run");
        assert!(dry.dry_run);
        assert_eq!(dry.processed, 1);

        // Never write the real %LOCALAPPDATA%\DiskSaver\journal.db from tests.
        let journal_dir = tempdir().expect("journal dir");
        let journal_path = journal_dir.path().join("journal.db");
        let live = remediate_duplicate_group(
            &report.groups[0],
            0,
            DupeRemediationAction::ReplaceWithHardlinks,
            false,
            Some(&journal_path),
            &dir.path().to_string_lossy(),
            &deny_ctx,
        )
        .expect("live hardlink");
        assert_eq!(live.processed, 1);
        assert!(fs::metadata(&dup).expect("meta").permissions().readonly());

        // Hard-link replacements are journaled.
        let journal = ActionJournal::open(&journal_path).expect("journal");
        let runs = journal.list_runs(10).expect("runs");
        assert_eq!(runs.len(), 1);
        let entries = journal.get_run_entries(&runs[0].run_id).expect("entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].disposition, "hardlink_replace");
        // Clear read-only before TempDir cleanup on Windows.
        #[allow(clippy::permissions_set_readonly_false)]
        {
            let mut perms = fs::metadata(&dup).expect("meta").permissions();
            perms.set_readonly(false);
            let _ = fs::set_permissions(&dup, perms);
        }
    }

    /// P9.6: hard links only for content-addressed stores; app installs never.
    #[test]
    fn dupe_classes_pick_safe_remediation() {
        let entry = |p: &str, hardlinked: bool| DupFileEntry {
            node_id: 0,
            path: PathBuf::from(p),
            file_id: 0,
            logical_bytes: 1,
            allocated_bytes: 1,
            mtime_min: 0,
            atime_min: 0,
            hardlinked,
        };
        let group = |files: Vec<DupFileEntry>| DuplicateGroup {
            blake3_hex: "x".into(),
            file_size: 1,
            files,
            reclaimable_bytes: 1,
        };
        let hf = group(vec![
            entry(
                r"C:\Users\A\.cache\huggingface\hub\models--x\blobs\077e",
                false,
            ),
            entry(
                r"C:\Users\A\.cache\huggingface\hub\models--x\snapshots\3a9\model.safetensors",
                false,
            ),
        ]);
        assert_eq!(classify_dupe_group(&hf), DupeClass::ImmutableStore);
        assert!(is_hardlink_safe_group(&hf));

        let zips = group(vec![
            entry(r"C:\Games\pack.zip", false),
            entry(r"C:\Users\A\Downloads\pack.zip", false),
        ]);
        assert_eq!(classify_dupe_group(&zips), DupeClass::ReadMostly);
        assert!(!is_hardlink_safe_group(&zips));

        let conda = group(vec![
            entry(
                r"C:\Users\A\miniconda3\Library\bin\cublasLt64_11.dll",
                false,
            ),
            entry(
                r"C:\Users\A\miniconda3\pkgs\cudatoolkit\Library\bin\cublasLt64_11.dll",
                false,
            ),
        ]);
        assert_eq!(classify_dupe_group(&conda), DupeClass::AppInstall);

        let mixed = group(vec![
            entry(r"C:\Program Files\Topaz\nvinfer_10.dll", false),
            entry(r"C:\Users\A\.ollama\models\blobs\sha256-1", false),
        ]);
        assert_eq!(
            classify_dupe_group(&mixed),
            DupeClass::AppInstall,
            "most restrictive wins"
        );

        let linked = group(vec![
            entry(r"C:\Users\A\.ollama\models\blobs\sha256-1", true),
            entry(r"C:\Users\A\.lmstudio\models\m.gguf", false),
        ]);
        assert!(
            !is_hardlink_safe_group(&linked),
            "existing hard links are left alone"
        );
    }
}
