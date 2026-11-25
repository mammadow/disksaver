//! Bounds-checked binary Structure-of-Arrays wire codec for [`ScanReport`] and [`Index`].

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::time::Duration;

use rustc_hash::FxHashMap;

use crate::error::{DskError, Result};
use crate::index::builder::{Index, NodeFlags};
use crate::index::names::NameArena;
use crate::scan::{ScanMethod, ScanReport, UsageCheck};
use crate::volume::VolumeInfo;

pub const CODEC_MAGIC: [u8; 8] = *b"DSKCOD01";
pub const CODEC_VERSION: u32 = 1;

pub const MAX_NODE_COUNT: usize = 50_000_000;
pub const MAX_NAMES_ARENA_BYTES: usize = 2_000_000_000;

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

    fn finalize_hash(&self) -> blake3::Hash {
        self.hasher.finalize()
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct HashingReader<R: Read> {
    inner: R,
    hasher: blake3::Hasher,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn finalize_hash(&self) -> blake3::Hash {
        self.hasher.finalize()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Encodes a [`ScanReport`] into a compact, bounds-checked binary format with BLAKE3 integrity.
pub fn encode_scan_report(report: &ScanReport, out: &mut impl Write) -> Result<()> {
    let mut hw = HashingWriter::new(out);

    // 1. Magic and version
    hw.write_all(&CODEC_MAGIC)?;
    hw.write_all(&CODEC_VERSION.to_le_bytes())?;

    // 2. Scan metadata
    let method_byte: u8 = match report.method_used {
        ScanMethod::Auto => 0,
        ScanMethod::Mft => 1,
        ScanMethod::Dir => 2,
        ScanMethod::UsnIncremental => 3,
    };
    hw.write_all(&[method_byte])?;
    let elapsed_micros = report.elapsed.as_micros().min(u64::MAX as u128) as u64;
    hw.write_all(&elapsed_micros.to_le_bytes())?;
    hw.write_all(&report.skipped.to_le_bytes())?;

    if let Some(ref chk) = report.check {
        hw.write_all(&[1u8])?;
        hw.write_all(&chk.scanned_alloc.to_le_bytes())?;
        hw.write_all(&chk.volume_used.to_le_bytes())?;
        hw.write_all(&chk.diff_pct.to_bits().to_le_bytes())?;
    } else {
        hw.write_all(&[0u8])?;
    }

    if let Some(ref reason) = report.fallback_reason {
        let b = reason.as_bytes();
        hw.write_all(&(b.len() as u32).to_le_bytes())?;
        hw.write_all(b)?;
    } else {
        hw.write_all(&0u32.to_le_bytes())?;
    }

    // 3. VolumeInfo JSON
    let vol_json = serde_json::to_vec(report.index.volume())
        .map_err(|e| DskError::Ipc(format!("failed to serialize volume info: {e}")))?;
    hw.write_all(&(vol_json.len() as u32).to_le_bytes())?;
    hw.write_all(&vol_json)?;

    // 4. Index SoA columns
    let node_count = report.index.len();
    if node_count > MAX_NODE_COUNT {
        return Err(DskError::Ipc(format!(
            "node count {node_count} exceeds limit {MAX_NODE_COUNT}"
        )));
    }
    hw.write_all(&(node_count as u32).to_le_bytes())?;

    let name_bytes = report.index.names().as_bytes();
    if name_bytes.len() > MAX_NAMES_ARENA_BYTES {
        return Err(DskError::Ipc(format!(
            "name arena length {} exceeds limit {MAX_NAMES_ARENA_BYTES}",
            name_bytes.len()
        )));
    }
    hw.write_all(&(name_bytes.len() as u32).to_le_bytes())?;
    hw.write_all(name_bytes)?;

    for &v in report.index.parent_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.first_child_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.next_sibling_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.name_off_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.name_len_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.flags_slice() {
        hw.write_all(&v.bits().to_le_bytes())?;
    }
    for &v in report.index.logical_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.allocated_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.mtime_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.atime_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.file_id_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.agg_alloc_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }
    for &v in report.index.agg_count_slice() {
        hw.write_all(&v.to_le_bytes())?;
    }

    // 5. Reparse tags
    let tags = report.index.reparse_tags_map();
    hw.write_all(&(tags.len() as u32).to_le_bytes())?;
    for (&node_id, &tag) in tags {
        hw.write_all(&node_id.to_le_bytes())?;
        hw.write_all(&tag.to_le_bytes())?;
    }

    hw.flush()?;

    // 6. Trailing BLAKE3 checksum
    let digest = hw.finalize_hash();
    hw.inner.write_all(digest.as_bytes())?;
    hw.inner.flush()?;

    Ok(())
}

/// Decodes a [`ScanReport`] from a stream, validating all bounds and BLAKE3 integrity.
pub fn decode_scan_report(inp: &mut impl Read) -> Result<ScanReport> {
    let mut hr = HashingReader::new(inp);

    // 1. Magic and version
    let mut magic = [0u8; 8];
    hr.read_exact(&mut magic)?;
    if magic != CODEC_MAGIC {
        return Err(DskError::Ipc("invalid codec magic header".to_string()));
    }

    let mut ver_buf = [0u8; 4];
    hr.read_exact(&mut ver_buf)?;
    let version = u32::from_le_bytes(ver_buf);
    if version != CODEC_VERSION {
        return Err(DskError::Ipc(format!(
            "unsupported codec version {version}"
        )));
    }

    // 2. Scan metadata
    let mut method_buf = [0u8; 1];
    hr.read_exact(&mut method_buf)?;
    let method_used = match method_buf[0] {
        0 => ScanMethod::Auto,
        1 => ScanMethod::Mft,
        2 => ScanMethod::Dir,
        3 => ScanMethod::UsnIncremental,
        m => return Err(DskError::Ipc(format!("invalid scan method {m}"))),
    };

    let mut u64_buf = [0u8; 8];
    hr.read_exact(&mut u64_buf)?;
    let elapsed = Duration::from_micros(u64::from_le_bytes(u64_buf));

    hr.read_exact(&mut u64_buf)?;
    let skipped = u64::from_le_bytes(u64_buf);

    let mut has_check_buf = [0u8; 1];
    hr.read_exact(&mut has_check_buf)?;
    let check = if has_check_buf[0] != 0 {
        hr.read_exact(&mut u64_buf)?;
        let scanned_alloc = u64::from_le_bytes(u64_buf);
        hr.read_exact(&mut u64_buf)?;
        let volume_used = u64::from_le_bytes(u64_buf);
        hr.read_exact(&mut u64_buf)?;
        let diff_pct = f64::from_bits(u64::from_le_bytes(u64_buf));
        Some(UsageCheck {
            scanned_alloc,
            volume_used,
            diff_pct,
        })
    } else {
        None
    };

    let mut u32_buf = [0u8; 4];
    hr.read_exact(&mut u32_buf)?;
    let reason_len = u32::from_le_bytes(u32_buf) as usize;
    let fallback_reason = if reason_len > 0 {
        if reason_len > 65536 {
            return Err(DskError::Ipc("oversized fallback reason".to_string()));
        }
        let mut b = vec![0u8; reason_len];
        hr.read_exact(&mut b)?;
        Some(String::from_utf8_lossy(&b).into_owned())
    } else {
        None
    };

    // 3. VolumeInfo JSON
    hr.read_exact(&mut u32_buf)?;
    let vol_len = u32::from_le_bytes(u32_buf) as usize;
    if vol_len > 65536 {
        return Err(DskError::Ipc("oversized volume json metadata".to_string()));
    }
    let mut vol_buf = vec![0u8; vol_len];
    hr.read_exact(&mut vol_buf)?;
    let volume: VolumeInfo = serde_json::from_slice(&vol_buf)
        .map_err(|e| DskError::Ipc(format!("corrupted volume info JSON: {e}")))?;

    // 4. Index SoA columns
    hr.read_exact(&mut u32_buf)?;
    let node_count = u32::from_le_bytes(u32_buf) as usize;
    if node_count > MAX_NODE_COUNT {
        return Err(DskError::Ipc(format!(
            "node count {node_count} exceeds limit {MAX_NODE_COUNT}"
        )));
    }

    hr.read_exact(&mut u32_buf)?;
    let names_len = u32::from_le_bytes(u32_buf) as usize;
    if names_len > MAX_NAMES_ARENA_BYTES {
        return Err(DskError::Ipc(format!(
            "name arena length {names_len} exceeds limit {MAX_NAMES_ARENA_BYTES}"
        )));
    }

    let init_name_cap = names_len.min(65_536);
    let mut name_bytes = Vec::with_capacity(init_name_cap);
    let mut remaining_names = names_len;
    let mut chunk_buf = vec![0u8; remaining_names.min(65_536)];
    while remaining_names > 0 {
        let to_read = remaining_names.min(chunk_buf.len());
        hr.read_exact(&mut chunk_buf[..to_read])?;
        name_bytes.extend_from_slice(&chunk_buf[..to_read]);
        remaining_names -= to_read;
    }
    let names = NameArena::from_vec(name_bytes);

    let init_node_cap = node_count.min(65_536);
    let mut parent = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u32_buf)?;
        parent.push(u32::from_le_bytes(u32_buf));
    }

    let mut first_child = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u32_buf)?;
        first_child.push(u32::from_le_bytes(u32_buf));
    }

    let mut next_sibling = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u32_buf)?;
        next_sibling.push(u32::from_le_bytes(u32_buf));
    }

    let mut name_off = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u32_buf)?;
        name_off.push(u32::from_le_bytes(u32_buf));
    }

    let mut u16_buf = [0u8; 2];
    let mut name_len = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u16_buf)?;
        name_len.push(u16::from_le_bytes(u16_buf));
    }

    let mut flags = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u16_buf)?;
        flags.push(NodeFlags::from_bits_truncate(u16::from_le_bytes(u16_buf)));
    }

    let mut logical = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u64_buf)?;
        logical.push(u64::from_le_bytes(u64_buf));
    }

    let mut allocated = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u64_buf)?;
        allocated.push(u64::from_le_bytes(u64_buf));
    }

    let mut mtime = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u32_buf)?;
        mtime.push(u32::from_le_bytes(u32_buf));
    }

    let mut atime = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u32_buf)?;
        atime.push(u32::from_le_bytes(u32_buf));
    }

    let mut file_id = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u64_buf)?;
        file_id.push(u64::from_le_bytes(u64_buf));
    }

    let mut agg_alloc = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u64_buf)?;
        agg_alloc.push(u64::from_le_bytes(u64_buf));
    }

    let mut agg_count = Vec::with_capacity(init_node_cap);
    for _ in 0..node_count {
        hr.read_exact(&mut u32_buf)?;
        agg_count.push(u32::from_le_bytes(u32_buf));
    }

    // 5. Reparse tags
    hr.read_exact(&mut u32_buf)?;
    let tags_count = u32::from_le_bytes(u32_buf) as usize;
    if tags_count > node_count {
        return Err(DskError::Ipc(format!(
            "reparse tags count {tags_count} exceeds node count {node_count}"
        )));
    }
    let mut reparse_tags = FxHashMap::default();
    for _ in 0..tags_count {
        hr.read_exact(&mut u32_buf)?;
        let nid = u32::from_le_bytes(u32_buf);
        hr.read_exact(&mut u32_buf)?;
        let tag = u32::from_le_bytes(u32_buf);
        reparse_tags.insert(nid, tag);
    }

    // 6. Verify BLAKE3 digest
    let expected_hash = hr.finalize_hash();
    let mut actual_digest = [0u8; 32];
    hr.inner.read_exact(&mut actual_digest)?;

    if expected_hash.as_bytes() != &actual_digest {
        return Err(DskError::Ipc(
            "BLAKE3 checksum verification failed".to_string(),
        ));
    }

    let index = Index::from_parts_checked(
        volume,
        names,
        parent,
        first_child,
        next_sibling,
        name_off,
        name_len,
        flags,
        logical,
        allocated,
        mtime,
        atime,
        file_id,
        agg_alloc,
        agg_count,
        reparse_tags,
    )?;

    Ok(ScanReport {
        index,
        method_used,
        elapsed,
        skipped,
        check,
        fallback_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::builder::{IndexBuilder, NodeId};
    use proptest::prelude::*;
    use std::io::Cursor;

    fn build_test_report() -> ScanReport {
        let vol = VolumeInfo {
            root: r"C:\".to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0xDEADBEEF,
            cluster_size: 4096,
            total_bytes: 1_000_000_000,
            free_bytes: 400_000_000,
            seek_penalty: Some(false),
        };
        let mut builder = IndexBuilder::new(0, "C:", vol);
        let mut batch = crate::index::builder::EntryBatch::default();
        let sub_ref = batch.names.push_str("Users");
        batch.entries.push(crate::index::builder::RawEntry {
            key: 1,
            parent_key: 0,
            name: sub_ref,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 1000,
            atime: 1000,
            file_id: 100,
            reparse_tag: 0,
        });
        let file_ref = batch.names.push_str("doc.txt");
        batch.entries.push(crate::index::builder::RawEntry {
            key: 2,
            parent_key: 1,
            name: file_ref,
            flags: NodeFlags::empty(),
            logical: 1234,
            allocated: 4096,
            mtime: 2000,
            atime: 2000,
            file_id: 200,
            reparse_tag: 0,
        });
        builder.push_batch(batch);
        let index = builder.finish();

        ScanReport {
            index,
            method_used: ScanMethod::Mft,
            elapsed: Duration::from_millis(42),
            skipped: 5,
            check: Some(UsageCheck {
                scanned_alloc: 4096,
                volume_used: 600_000_000,
                diff_pct: 0.12,
            }),
            fallback_reason: Some("test fallback".to_string()),
        }
    }

    #[test]
    fn scan_report_roundtrip_preserves_all_nodes_flags_reparse_tags_and_aggregates() {
        let report = build_test_report();
        let mut buf = Vec::new();
        encode_scan_report(&report, &mut buf).expect("encode should succeed");

        assert!(buf.starts_with(&CODEC_MAGIC));

        let mut cursor = Cursor::new(&buf);
        let decoded = decode_scan_report(&mut cursor).expect("decode should succeed");

        assert_eq!(decoded.method_used, report.method_used);
        assert_eq!(decoded.elapsed, report.elapsed);
        assert_eq!(decoded.skipped, report.skipped);
        assert_eq!(decoded.check, report.check);
        assert_eq!(decoded.fallback_reason, report.fallback_reason);

        let orig_idx = &report.index;
        let dec_idx = &decoded.index;

        assert_eq!(dec_idx.len(), orig_idx.len());
        assert_eq!(dec_idx.volume(), orig_idx.volume());

        for i in 0..orig_idx.len() as NodeId {
            assert_eq!(dec_idx.name_bytes(i), orig_idx.name_bytes(i));
            assert_eq!(dec_idx.flags(i), orig_idx.flags(i));
            assert_eq!(dec_idx.parent(i), orig_idx.parent(i));
            assert_eq!(dec_idx.logical(i), orig_idx.logical(i));
            assert_eq!(dec_idx.allocated(i), orig_idx.allocated(i));
            assert_eq!(dec_idx.total_allocated(i), orig_idx.total_allocated(i));
            assert_eq!(dec_idx.file_count(i), orig_idx.file_count(i));
            assert_eq!(dec_idx.file_id(i), orig_idx.file_id(i));
            assert_eq!(dec_idx.mtime_min(i), orig_idx.mtime_min(i));
            assert_eq!(dec_idx.atime_min(i), orig_idx.atime_min(i));
            assert_eq!(dec_idx.reparse_tag(i), orig_idx.reparse_tag(i));
        }
    }

    #[test]
    fn codec_rejects_corrupted_checksum_and_out_of_bounds_node_links() {
        let report = build_test_report();
        let mut buf = Vec::new();
        encode_scan_report(&report, &mut buf).expect("encode should succeed");

        // 1. Flip a payload bit: checksum verification must fail!
        let mut corrupted_payload = buf.clone();
        let payload_idx = 20;
        corrupted_payload[payload_idx] ^= 0xFF;
        let mut cur1 = Cursor::new(&corrupted_payload);
        let res1 = decode_scan_report(&mut cur1);
        assert!(res1.is_err());

        // 2. Flip a digest bit: checksum verification must fail!
        let mut corrupted_digest = buf.clone();
        let last_idx = corrupted_digest.len() - 1;
        corrupted_digest[last_idx] ^= 0xFF;
        let mut cur2 = Cursor::new(&corrupted_digest);
        let res2 = decode_scan_report(&mut cur2);
        assert!(res2.is_err());

        // 3. Truncated stream
        let truncated = &buf[..buf.len() - 10];
        let mut cur3 = Cursor::new(truncated);
        let res3 = decode_scan_report(&mut cur3);
        assert!(res3.is_err());

        // 4. Cyclic parent link in Index::from_parts_checked must be rejected
        let idx = &report.index;
        let mut bad_parent = idx.parent_slice().to_vec();
        bad_parent[1] = 1; // Self-loop cycle
        let cyc_res = Index::from_parts_checked(
            idx.volume().clone(),
            NameArena::from_vec(idx.names().as_bytes().to_vec()),
            bad_parent,
            idx.first_child_slice().to_vec(),
            idx.next_sibling_slice().to_vec(),
            idx.name_off_slice().to_vec(),
            idx.name_len_slice().to_vec(),
            idx.flags_slice().to_vec(),
            idx.logical_slice().to_vec(),
            idx.allocated_slice().to_vec(),
            idx.mtime_slice().to_vec(),
            idx.atime_slice().to_vec(),
            idx.file_id_slice().to_vec(),
            idx.agg_alloc_slice().to_vec(),
            idx.agg_count_slice().to_vec(),
            idx.reparse_tags_map().clone(),
        );
        assert!(cyc_res.is_err());
    }

    proptest! {
        #[test]
        fn proptest_arbitrary_bytes_never_panic_in_decode_scan_report(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let mut cursor = Cursor::new(data);
            let _ = decode_scan_report(&mut cursor);
        }
    }
}
