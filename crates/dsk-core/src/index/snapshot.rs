//! Atomic zstd-compressed `.dsi` snapshot persistence with streaming BLAKE3 verification.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};
use crate::index::codec::{decode_scan_report, encode_scan_report};
use crate::scan::ScanReport;

/// Magic header identifying DiskSaver zstd-compressed index snapshots.
pub const SNAPSHOT_MAGIC: [u8; 8] = *b"DSKSNP01";

/// Current snapshot container format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Default zstd compression level (good balance of speed and compression ratio).
pub const SNAPSHOT_ZSTD_LEVEL: i32 = 3;

/// Maximum permitted serialized metadata header size (1 MiB) to defend against bogus length prefixes.
const MAX_META_BYTES: usize = 1024 * 1024;
/// Upper bound on the decompressed `ScanReport` payload of a `.dsi` snapshot (the codec additionally
/// caps node count at 50M and the name arena at 2 GB).
const MAX_SNAPSHOT_DECOMPRESSED_BYTES: u64 = 6 * 1024 * 1024 * 1024;

/// Metadata stored in the header of a `.dsi` snapshot file for USN continuity validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub volume_root: String,
    pub volume_serial: u32,
    pub usn_journal_id: u64,
    pub next_usn: i64,
    pub created_at_unix: u64,
}

impl SnapshotMeta {
    /// Returns the current UNIX epoch timestamp in seconds.
    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Returns the default directory (`%LOCALAPPDATA%\DiskSaver\index`) for `.dsi` snapshots.
pub fn default_snapshot_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA")
        && !local.trim().is_empty()
    {
        return PathBuf::from(local).join("DiskSaver").join("index");
    }
    if let Ok(profile) = std::env::var("USERPROFILE")
        && !profile.trim().is_empty()
    {
        return PathBuf::from(profile)
            .join("AppData")
            .join("Local")
            .join("DiskSaver")
            .join("index");
    }
    PathBuf::from("index")
}

/// Computes the deterministic `.dsi` snapshot filename inside `dir` for a volume root + serial.
pub fn snapshot_path_for_volume(dir: &Path, volume_root: &str, volume_serial: u32) -> PathBuf {
    let mut san = String::with_capacity(8);
    for ch in volume_root.chars() {
        if ch.is_ascii_alphanumeric() {
            san.push(ch.to_ascii_lowercase());
        }
    }
    if san.is_empty() {
        san.push_str("vol");
    }
    dir.join(format!("{san}_{volume_serial:08x}.dsi"))
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct HashingReader<'a, R: Read> {
    inner: &'a mut R,
    hasher: &'a mut blake3::Hasher,
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

struct TempFileGuard {
    path: PathBuf,
    committed: bool,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn temp_path_for(path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        DskError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing filename",
        ))
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    Ok(path.with_file_name(tmp_name))
}

/// Atomically writes a zstd-compressed, BLAKE3-protected `.dsi` snapshot (`<path>.tmp.<pid>` + rename).
pub fn save_snapshot_atomic(path: &Path, meta: &SnapshotMeta, report: &ScanReport) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let meta_bytes = serde_json::to_vec(meta)
        .map_err(|e| DskError::Ipc(format!("failed to encode snapshot metadata: {e}")))?;
    if meta_bytes.len() > MAX_META_BYTES {
        return Err(DskError::Ipc(format!(
            "snapshot metadata exceeds {} byte limit",
            MAX_META_BYTES
        )));
    }

    let tmp_path = temp_path_for(path)?;
    let mut guard = TempFileGuard {
        path: tmp_path.clone(),
        committed: false,
    };

    {
        let file = File::create(&tmp_path)?;
        let mut hw = HashingWriter::new(BufWriter::with_capacity(64 * 1024, file));

        hw.write_all(&SNAPSHOT_MAGIC)?;
        hw.write_all(&SNAPSHOT_VERSION.to_le_bytes())?;
        hw.write_all(&(meta_bytes.len() as u32).to_le_bytes())?;
        hw.write_all(&meta_bytes)?;

        {
            let mut zenc = zstd::stream::write::Encoder::new(&mut hw, SNAPSHOT_ZSTD_LEVEL)?;
            encode_scan_report(report, &mut zenc)?;
            zenc.finish()?;
        }

        hw.flush()?;
        let digest = hw.hasher.finalize();
        let mut bw = hw.inner;
        bw.write_all(digest.as_bytes())?;
        bw.flush()?;
        let file = bw.into_inner().map_err(|e| DskError::Io(e.into_error()))?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    guard.committed = true;
    Ok(())
}

/// Reads and verifies a `.dsi` snapshot, checking magic, version, metadata, and BLAKE3 trailer.
pub fn load_snapshot_verified(path: &Path) -> Result<(SnapshotMeta, ScanReport)> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    // Minimum size: 8B magic + 4B version + 4B meta_len + 32B blake3 digest.
    const MIN_CONTAINER_BYTES: u64 = 48;
    if file_len < MIN_CONTAINER_BYTES {
        return Err(DskError::Ipc(format!(
            "snapshot truncated: {} bytes",
            file_len
        )));
    }

    let body_len = file_len - 32;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = blake3::Hasher::new();

    let (meta, report, extra_uncompressed, remaining_container) = {
        let mut bounded = reader.by_ref().take(body_len);
        let mut hr = HashingReader {
            inner: &mut bounded,
            hasher: &mut hasher,
        };

        let mut magic = [0u8; 8];
        hr.read_exact(&mut magic)?;
        if magic != SNAPSHOT_MAGIC {
            return Err(DskError::Ipc("invalid snapshot magic".into()));
        }

        let mut ver_buf = [0u8; 4];
        hr.read_exact(&mut ver_buf)?;
        let version = u32::from_le_bytes(ver_buf);
        if version != SNAPSHOT_VERSION {
            return Err(DskError::Ipc(format!(
                "unsupported snapshot version {version}"
            )));
        }

        let mut meta_len_buf = [0u8; 4];
        hr.read_exact(&mut meta_len_buf)?;
        let meta_len = u32::from_le_bytes(meta_len_buf) as usize;
        if meta_len > MAX_META_BYTES {
            return Err(DskError::Ipc(format!(
                "invalid snapshot metadata length {meta_len}"
            )));
        }

        let mut meta_buf = vec![0u8; meta_len];
        hr.read_exact(&mut meta_buf)?;
        let meta: SnapshotMeta = serde_json::from_slice(&meta_buf)
            .map_err(|e| DskError::Ipc(format!("corrupt snapshot metadata: {e}")))?;

        let mut zdec = zstd::stream::read::Decoder::new(&mut hr)?;
        // Bound the decompressed stream (zstd-bomb defense) on top of the codec's own caps.
        let report = decode_scan_report(&mut (&mut zdec).take(MAX_SNAPSHOT_DECOMPRESSED_BYTES))?;
        // Probe for trailing payload with a single byte instead of draining an unbounded stream;
        // reaching EOF also consumes the zstd frame epilogue.
        let mut probe = [0u8; 1];
        let extra_uncompressed = zdec.read(&mut probe)? as u64;
        drop(zdec);
        let remaining_container = bounded.limit();
        (meta, report, extra_uncompressed, remaining_container)
    };

    if extra_uncompressed > 0 || remaining_container > 0 {
        return Err(DskError::Ipc(
            "snapshot contains unexpected trailing bytes".into(),
        ));
    }

    let mut expected_trailer = [0u8; 32];
    reader.read_exact(&mut expected_trailer)?;
    let mut eof_probe = [0u8; 1];
    if reader.read(&mut eof_probe)? != 0 {
        return Err(DskError::Ipc(
            "snapshot grew or contains unhashed trailing data".into(),
        ));
    }

    let actual_digest = hasher.finalize();
    if actual_digest != blake3::Hash::from(expected_trailer) {
        return Err(DskError::Ipc("snapshot BLAKE3 digest mismatch".into()));
    }

    Ok((meta, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::builder::{EntryBatch, IndexBuilder, NodeFlags, RawEntry};
    use crate::index::names::NameArena;
    use crate::scan::ScanMethod;
    use crate::volume::VolumeInfo;
    use std::time::Duration;

    fn sample_report() -> (SnapshotMeta, ScanReport) {
        let vol = VolumeInfo {
            root: "C:\\".to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0xDEAD_BEEF,
            cluster_size: 4096,
            total_bytes: 500_000_000_000,
            free_bytes: 120_000_000_000,
            seek_penalty: Some(false),
        };
        let mut names = NameArena::new();
        let dir_name = names.push_str("Projects");
        let file_name = names.push_str("snapshot_test.bin");
        let mut b = IndexBuilder::new(5, "C:\\", vol);
        b.push_batch(EntryBatch {
            names,
            entries: vec![
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    file_id: (1u64 << 48) | 10,
                    name: dir_name,
                    logical: 0,
                    allocated: 0,
                    mtime: 100,
                    atime: 100,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 10,
                    file_id: (1u64 << 48) | 11,
                    name: file_name,
                    logical: 123_456,
                    allocated: 126_976,
                    mtime: 200,
                    atime: 200,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
            ],
        });
        let index = b.finish();
        let meta = SnapshotMeta {
            volume_root: "C:\\".to_string(),
            volume_serial: 0xDEAD_BEEF,
            usn_journal_id: 0x01DB_0000_0000_0042,
            next_usn: 8_388_608,
            created_at_unix: 1_700_000_000,
        };
        let report = ScanReport {
            index,
            method_used: ScanMethod::Mft,
            elapsed: Duration::from_millis(42),
            skipped: 0,
            check: None,
            fallback_reason: None,
        };
        (meta, report)
    }

    #[test]
    fn roundtrip_snapshot_and_leave_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let snap_path = snapshot_path_for_volume(dir.path(), "C:\\", 0xDEAD_BEEF);
        let (meta, report) = sample_report();

        save_snapshot_atomic(&snap_path, &meta, &report).unwrap();
        assert!(snap_path.exists());

        let tmp_name = format!(
            "{}.tmp.{}",
            snap_path.file_name().unwrap().to_string_lossy(),
            std::process::id()
        );
        assert!(!dir.path().join(tmp_name).exists());

        let (loaded_meta, loaded_report) = load_snapshot_verified(&snap_path).unwrap();
        assert_eq!(loaded_meta, meta);
        assert_eq!(loaded_report.method_used, ScanMethod::Mft);
        assert_eq!(loaded_report.index.len(), report.index.len());
        assert_eq!(
            loaded_report.index.agg_alloc_slice()[0],
            report.index.agg_alloc_slice()[0]
        );
    }

    #[test]
    fn corrupt_byte_fails_blake3_verification() {
        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("corrupt.dsi");
        let (meta, report) = sample_report();
        save_snapshot_atomic(&snap_path, &meta, &report).unwrap();

        let mut bytes = fs::read(&snap_path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        fs::write(&snap_path, &bytes).unwrap();

        assert!(load_snapshot_verified(&snap_path).is_err());
    }

    #[test]
    fn truncated_snapshot_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("trunc.dsi");
        let (meta, report) = sample_report();
        save_snapshot_atomic(&snap_path, &meta, &report).unwrap();

        let bytes = fs::read(&snap_path).unwrap();
        fs::write(&snap_path, &bytes[..bytes.len() - 10]).unwrap();

        assert!(load_snapshot_verified(&snap_path).is_err());
    }

    #[test]
    fn version_mismatch_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("badver.dsi");
        let (meta, report) = sample_report();
        save_snapshot_atomic(&snap_path, &meta, &report).unwrap();

        let mut bytes = fs::read(&snap_path).unwrap();
        // Overwrite version bytes [8..12] AND recompute trailing 32-byte digest so version check specifically rejects it.
        bytes[8..12].copy_from_slice(&99u32.to_le_bytes());
        let data_end = bytes.len() - 32;
        let new_hash = blake3::hash(&bytes[..data_end]);
        bytes[data_end..].copy_from_slice(new_hash.as_bytes());
        fs::write(&snap_path, &bytes).unwrap();

        let err = load_snapshot_verified(&snap_path).unwrap_err();
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn bad_magic_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("badmagic.dsi");
        fs::write(
            &snap_path,
            b"NOT_DSK_0000000000000000000000000000000000000000",
        )
        .unwrap();
        assert!(load_snapshot_verified(&snap_path).is_err());
    }
}
