#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};

use crate::error::{DskError, NtfsError, Result};
use crate::ntfs::attr::{AttrBody, attributes, parse_attribute_list};
use crate::ntfs::boot::BootSector;
use crate::ntfs::record::{apply_fixups, parse_header};
use crate::ntfs::runs::{Run, decode_runs};
use crate::ntfs::summary::summarize_record;
use crate::ntfs::{ATTR_ATTRIBUTE_LIST, ATTR_DATA, MftScanOutput, SummaryBatch};

/// Block or disk sector reader trait.
pub trait SectorReader: Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

/// Description of the layout of an MFT stream on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MftLayout {
    pub record_size: u32,
    pub cluster_size: u64,
    pub runs: Vec<Run>,
    pub total_records: u64,
}

/// MFT scanning pipeline phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    ReadingMft,
    Enumerating,
    Linking,
    Aggregating,
}

/// Progress report for volume scanning operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub phase: Phase,
    pub done: u64,
    pub total: u64,
}

fn mft_offset_to_disk_offset(runs: &[Run], cluster_size: u64, mft_offset: u64) -> Result<u64> {
    let mut curr_mft_offset: u64 = 0;
    for run in runs {
        let run_bytes = run
            .len
            .checked_mul(cluster_size)
            .ok_or(NtfsError::Truncated("run byte length overflow"))?;
        let run_end = curr_mft_offset
            .checked_add(run_bytes)
            .ok_or(NtfsError::Truncated("run offset overflow"))?;
        if mft_offset >= curr_mft_offset && mft_offset < run_end {
            let lcn = run.lcn.ok_or(NtfsError::BadRunList)?;
            let offset_in_run = mft_offset - curr_mft_offset;
            let disk_offset = lcn
                .checked_mul(cluster_size)
                .ok_or(NtfsError::Truncated("lcn offset overflow"))?
                .checked_add(offset_in_run)
                .ok_or(NtfsError::Truncated("disk offset overflow"))?;
            return Ok(disk_offset);
        }
        curr_mft_offset = run_end;
    }
    Err(NtfsError::Truncated("record offset beyond known runs").into())
}

/// Reads the MFT layout by inspecting record 0 and any referenced extension records.
pub fn read_mft_layout(r: &dyn SectorReader, boot: &BootSector) -> Result<MftLayout> {
    let cluster_size = boot.cluster_size();
    if cluster_size == 0 || boot.mft_record_size == 0 {
        return Err(NtfsError::BadBootSector.into());
    }
    let record_size = boot.mft_record_size;

    // 1. Read record 0
    let mft0_offset = boot
        .mft_lcn
        .checked_mul(cluster_size)
        .ok_or(NtfsError::Truncated("mft offset overflow"))?;
    let mut rec0_buf = vec![0u8; record_size as usize];
    r.read_at(mft0_offset, &mut rec0_buf)?;
    apply_fixups(&mut rec0_buf)?;
    let h0 = parse_header(&rec0_buf)?;

    // 2. Scan attributes of record 0
    let mut attr_list_entries = None;
    let mut extents: Vec<(u64, Vec<Run>, u64)> = Vec::new();

    for attr_res in attributes(&rec0_buf, &h0) {
        let attr = attr_res?;
        match (attr.type_code, attr.name_utf16le.is_empty(), attr.body) {
            (ATTR_ATTRIBUTE_LIST, _, AttrBody::Resident { value }) => {
                let parsed = parse_attribute_list(value)?;
                attr_list_entries = Some(parsed);
            }
            (ATTR_ATTRIBUTE_LIST, _, AttrBody::NonResident { .. }) => {
                return Err(NtfsError::Truncated("non-resident $MFT attribute list").into());
            }
            (
                ATTR_DATA,
                true,
                AttrBody::NonResident {
                    start_vcn,
                    data_size,
                    runs,
                },
            ) => {
                let decoded = decode_runs(runs)?;
                extents.push((start_vcn, decoded, data_size));
            }
            _ => {}
        }
    }

    // 3. If resident attribute list exists, load extension records through known runs
    if let Some(entries) = attr_list_entries {
        let mut known_runs: Vec<Run> = Vec::new();
        for (_, runs, _) in &extents {
            known_runs.extend_from_slice(runs);
        }

        let mut data_entries: Vec<_> = entries
            .into_iter()
            .filter(|e| e.type_code == ATTR_DATA)
            .collect();
        data_entries.sort_unstable_by_key(|e| e.start_vcn);

        let mut visited_records = HashSet::new();
        visited_records.insert(0); // record 0 is already loaded

        for entry in data_entries {
            if !visited_records.insert(entry.record) {
                continue;
            }

            let rec_mft_offset = entry
                .record
                .checked_mul(record_size as u64)
                .ok_or(NtfsError::Truncated("mft offset overflow"))?;
            let disk_offset = mft_offset_to_disk_offset(&known_runs, cluster_size, rec_mft_offset)?;

            let mut ext_buf = vec![0u8; record_size as usize];
            r.read_at(disk_offset, &mut ext_buf)?;
            apply_fixups(&mut ext_buf)?;
            let ext_h = parse_header(&ext_buf)?;

            for attr_res in attributes(&ext_buf, &ext_h) {
                let attr = attr_res?;
                if let (
                    ATTR_DATA,
                    true,
                    AttrBody::NonResident {
                        start_vcn,
                        data_size,
                        runs,
                    },
                ) = (attr.type_code, attr.name_utf16le.is_empty(), attr.body)
                {
                    let decoded = decode_runs(runs)?;
                    known_runs.extend_from_slice(&decoded);
                    extents.push((start_vcn, decoded, data_size));
                }
            }
        }
    }

    if extents.is_empty() {
        return Err(NtfsError::Truncated("no $MFT data stream").into());
    }

    // 4. Concatenate all $DATA extents ordered by start_vcn
    extents.sort_unstable_by_key(|(vcn, _, _)| *vcn);

    let mut all_runs = Vec::new();
    for (_, runs, _) in &extents {
        all_runs.extend_from_slice(runs);
    }

    let data_size = extents
        .iter()
        .find(|(vcn, _, _)| *vcn == 0)
        .map(|(_, _, ds)| *ds)
        .unwrap_or(0);

    let total_records = if data_size > 0 {
        data_size / (record_size as u64)
    } else {
        let total_clusters: u64 = all_runs.iter().map(|r| r.len).sum();
        let total_bytes = total_clusters
            .checked_mul(cluster_size)
            .ok_or(NtfsError::Truncated("total clusters overflow"))?;
        total_bytes / (record_size as u64)
    };

    Ok(MftLayout {
        record_size,
        cluster_size,
        runs: all_runs,
        total_records,
    })
}

/// Scans the entire MFT in parallel, emitting summarized file records.
pub fn scan_mft(
    r: &dyn SectorReader,
    layout: &MftLayout,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<MftScanOutput> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    if layout.record_size == 0 || layout.cluster_size == 0 {
        return Err(NtfsError::BadBootSector.into());
    }
    let record_size = layout.record_size as usize;

    const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
    let max_records_per_chunk = (MAX_CHUNK_BYTES / record_size).max(1);

    let done_counter = AtomicU64::new(0);

    std::thread::scope(|s| {
        let (tx, rx) = crossbeam_channel::bounded::<(u64, Vec<u8>)>(8);

        let reader_handle = s.spawn(move || -> Result<()> {
            let mut current_record_no = 0u64;
            let total_records = layout.total_records;

            for run in &layout.runs {
                if current_record_no >= total_records {
                    break;
                }

                let run_records = match run.len.checked_mul(layout.cluster_size) {
                    Some(bytes) => bytes / (layout.record_size as u64),
                    None => return Err(NtfsError::Truncated("run length overflow").into()),
                };

                let records_to_read =
                    run_records.min(total_records.saturating_sub(current_record_no));
                let mut run_rec_offset = 0u64;

                while run_rec_offset < records_to_read {
                    if cancel.load(Ordering::Relaxed) {
                        return Ok(());
                    }

                    let chunk_records = (records_to_read - run_rec_offset)
                        .min(max_records_per_chunk as u64)
                        as usize;
                    let chunk_bytes = chunk_records * record_size;

                    let mut buf = vec![0u8; chunk_bytes];
                    if let Some(lcn) = run.lcn {
                        let disk_offset = lcn
                            .checked_mul(layout.cluster_size)
                            .ok_or(NtfsError::Truncated("lcn overflow"))?
                            .checked_add(run_rec_offset * (layout.record_size as u64))
                            .ok_or(NtfsError::Truncated("chunk offset overflow"))?;
                        r.read_at(disk_offset, &mut buf)?;
                    }

                    let first_record_no = current_record_no;
                    current_record_no += chunk_records as u64;
                    run_rec_offset += chunk_records as u64;

                    let mut item = (first_record_no, buf);
                    loop {
                        if cancel.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        match tx.send_timeout(item, Duration::from_millis(50)) {
                            Ok(()) => break,
                            Err(crossbeam_channel::SendTimeoutError::Timeout(it)) => {
                                item = it;
                            }
                            Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                                return Ok(());
                            }
                        }
                    }
                }
            }

            Ok(())
        });

        let parse_chunk = |(first_record_no, mut buf): (u64, Vec<u8>)| -> (SummaryBatch, u64, u64) {
            let mut batch = SummaryBatch::default();
            let mut skipped = 0u64;
            let mut count = 0u64;

            for (i, slot) in buf.chunks_exact_mut(record_size).enumerate() {
                let record_no = first_record_no + i as u64;
                count += 1;

                // Completely zeroed record slot is an unallocated MFT slot, not an error
                if slot.get(0..4) == Some(&[0, 0, 0, 0]) {
                    continue;
                }

                match summarize_record(slot, record_no, layout.cluster_size, &mut batch.names) {
                    Ok(Some(summary)) => {
                        batch.items.push(summary);
                    }
                    Ok(None) => {}
                    Err(_) => {
                        skipped += 1;
                    }
                }
            }

            let new_done = done_counter.fetch_add(count, Ordering::Relaxed) + count;
            progress(Progress {
                phase: Phase::ReadingMft,
                done: new_done.min(layout.total_records),
                total: layout.total_records,
            });

            (batch, skipped, count)
        };

        let chunk_results: Vec<(SummaryBatch, u64, u64)> =
            rx.into_iter().par_bridge().map(parse_chunk).collect();

        let reader_res = reader_handle
            .join()
            .map_err(|_| DskError::Unsupported("reader thread panicked".into()))?;
        reader_res?;

        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }

        let mut batches = Vec::with_capacity(chunk_results.len());
        let mut total_skipped = 0u64;

        for (batch, skipped, _) in chunk_results {
            batches.push(batch);
            total_skipped = total_skipped.saturating_add(skipped);
        }

        Ok(MftScanOutput {
            batches,
            skipped: total_skipped,
            total_records: layout.total_records,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::builder::{Index, NodeFlags, NodeId, ROOT};
    use crate::index::names::NameArena;
    use crate::ntfs::assemble::assemble;
    use crate::ntfs::boot::parse_boot_sector;
    use crate::ntfs::runs::decode_runs;
    use crate::ntfs::summary::summarize_record;
    use crate::ntfs::testutil::{ImageBuilder, MemReader, RecordBuilder, rich_record};
    use crate::volume::VolumeInfo;
    use proptest::prelude::*;

    fn vol() -> VolumeInfo {
        VolumeInfo {
            root: r"C:\".to_string(),
            cluster_size: 4096,
            ..Default::default()
        }
    }

    fn find(ix: &Index, path: &str) -> Option<NodeId> {
        (0..ix.len() as NodeId).find(|&id| ix.path(id).to_string_lossy() == path)
    }

    #[test]
    fn scans_synthetic_volume() {
        // records: 0 $MFT, 5 root, 30 dir "Users", 31 "a.txt" in Users (2 clusters), 32 "shared.bin" linked from root and Users (1 cluster)
        let mft_extents = [(100, 16)];
        let mft_bytes = 16 * 4096;
        let u_rec = RecordBuilder::new(30, 1)
            .dir()
            .file_name(5, 1, 1, "Users")
            .build(1024);
        let a_rec = RecordBuilder::new(31, 1)
            .file_name(30, 1, 1, "a.txt")
            .data_nonresident(
                None,
                0,
                2 * 4096,
                0,
                &[Run {
                    lcn: Some(200),
                    len: 2,
                }],
            )
            .build(1024);
        let shared_rec = RecordBuilder::new(32, 1)
            .file_name(5, 1, 1, "shared.bin")
            .file_name(30, 1, 1, "shared.bin")
            .data_nonresident(
                None,
                0,
                4096,
                0,
                &[Run {
                    lcn: Some(250),
                    len: 1,
                }],
            )
            .build(1024);

        let (image, boot) = ImageBuilder::new(4096, 1024)
            .mft_extents(&mft_extents)
            .record(u_rec)
            .record(a_rec)
            .record(shared_rec)
            .build();

        let reader = MemReader(image);
        let layout = read_mft_layout(&reader, &boot).unwrap();
        let out = scan_mft(&reader, &layout, &|_| {}, &AtomicBool::new(false)).unwrap();
        let ix = assemble(out, vol());

        assert!(find(&ix, r"C:\Users\a.txt").is_some());
        assert_eq!(ix.total_allocated(ROOT), mft_bytes + 3 * 4096);
        assert!(
            ix.flags(find(&ix, r"C:\shared.bin").unwrap())
                .contains(NodeFlags::HARDLINK)
        );
    }

    #[test]
    fn fragmented_mft_with_attribute_list() {
        // 2 MFT extents at distant LCNs; file record lives in extent 2
        let mft_extents = [(100, 16), (10_000, 16)];
        let far_rec = RecordBuilder::new(70, 1)
            .file_name(5, 1, 1, "far.txt")
            .data_resident(None, 10)
            .build(1024);

        let (image, boot) = ImageBuilder::new(4096, 1024)
            .mft_extents(&mft_extents)
            .fragmented_via_attr_list()
            .record(far_rec)
            .build();

        let reader = MemReader(image);
        let layout = read_mft_layout(&reader, &boot).unwrap();
        let out = scan_mft(&reader, &layout, &|_| {}, &AtomicBool::new(false)).unwrap();
        let ix = assemble(out, vol());
        assert!(find(&ix, r"C:\far.txt").is_some());
    }

    #[test]
    fn multi_chunk_scan() {
        // ImageBuilder auto-creates only records 0 ($MFT) and 5 (root); add 10_000 file records (> 4 MiB of MFT)
        let count = 10_000;
        let mut builder = ImageBuilder::new(4096, 1024);
        for i in 0..count {
            let rec_no = 6 + i;
            let r = RecordBuilder::new(rec_no, 1)
                .file_name(5, 1, 1, &format!("f{i}.txt"))
                .data_resident(None, 0)
                .build(1024);
            builder = builder.record_at(rec_no, r);
        }
        let (image, boot) = builder.build();

        let reader = MemReader(image);
        let layout = read_mft_layout(&reader, &boot).unwrap();
        let out = scan_mft(&reader, &layout, &|_| {}, &AtomicBool::new(false)).unwrap();
        let ix = assemble(out, vol());
        assert_eq!(ix.file_count(ROOT), 10_001);
    }

    #[test]
    fn corrupted_record_is_skipped() {
        // one record with broken fixup
        let ok_rec = RecordBuilder::new(30, 1)
            .file_name(5, 1, 1, "ok.txt")
            .data_resident(None, 0)
            .build(1024);
        let mut bad_rec = RecordBuilder::new(31, 1)
            .file_name(5, 1, 1, "bad.txt")
            .data_resident(None, 0)
            .build(1024);
        bad_rec[510] ^= 0xFF;

        let (image, boot) = ImageBuilder::new(4096, 1024)
            .record(ok_rec)
            .record(bad_rec)
            .build();

        let reader = MemReader(image);
        let layout = read_mft_layout(&reader, &boot).unwrap();
        let out = scan_mft(&reader, &layout, &|_| {}, &AtomicBool::new(false)).unwrap();
        assert_eq!(out.skipped, 1);
        let ix = assemble(out, vol());
        assert!(find(&ix, r"C:\ok.txt").is_some());
    }

    #[test]
    fn cancel_returns_cancelled() {
        let (image, _boot) = ImageBuilder::new(4096, 1024).build();
        let reader = MemReader(image);
        let layout = MftLayout {
            record_size: 1024,
            cluster_size: 4096,
            runs: vec![Run {
                lcn: Some(4),
                len: 16,
            }],
            total_records: 64,
        };
        assert!(matches!(
            scan_mft(&reader, &layout, &|_| {}, &AtomicBool::new(true)),
            Err(DskError::Cancelled)
        ));
    }

    #[test]
    fn non_resident_attribute_list_returns_truncated_error() {
        let rec0 = RecordBuilder::new(0, 1)
            .std_info(0, 0, 0x06)
            .file_name(5, 1, 1, "$MFT")
            .data_nonresident(
                None,
                0,
                8192,
                0,
                &[Run {
                    lcn: Some(10),
                    len: 2,
                }],
            )
            .attribute_list_nonresident(&[Run {
                lcn: Some(20),
                len: 1,
            }])
            .build(1024);
        let (image, boot) = ImageBuilder::new(4096, 1024)
            .mft_extents(&[(10, 2)])
            .record(rec0)
            .build();
        let reader = MemReader(image);
        let err = read_mft_layout(&reader, &boot).unwrap_err();
        match err {
            DskError::Ntfs(NtfsError::Truncated(msg)) => {
                assert_eq!(msg, "non-resident $MFT attribute list");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn progress_reports_reading_mft_and_reaches_total() {
        let ok_rec = RecordBuilder::new(30, 1)
            .file_name(5, 1, 1, "test.txt")
            .data_resident(None, 0)
            .build(1024);
        let (image, boot) = ImageBuilder::new(4096, 1024)
            .mft_extents(&[(10, 8)])
            .record(ok_rec)
            .build();
        let reader = MemReader(image);
        let layout = read_mft_layout(&reader, &boot).unwrap();

        let progress_calls = AtomicU64::new(0);
        let last_done = AtomicU64::new(0);

        let out = scan_mft(
            &reader,
            &layout,
            &|p| {
                assert_eq!(p.phase, Phase::ReadingMft);
                assert_eq!(p.total, layout.total_records);
                progress_calls.fetch_add(1, Ordering::Relaxed);
                last_done.store(p.done, Ordering::Relaxed);
            },
            &AtomicBool::new(false),
        )
        .unwrap();

        assert_eq!(out.total_records, layout.total_records);
        assert!(progress_calls.load(Ordering::Relaxed) > 0);
        assert_eq!(last_done.load(Ordering::Relaxed), layout.total_records);
    }

    proptest! {
        #[test]
        fn summarize_never_panics(mut b in prop::collection::vec(any::<u8>(), 1024)) {
            let _ = summarize_record(&mut b, 7, 4096, &mut NameArena::default());
        }

        #[test]
        fn mutated_valid_record_never_panics(idx in 0usize..1024, val in any::<u8>()) {
            let mut r = rich_record();
            r[idx] = val;
            let _ = summarize_record(&mut r, 7, 4096, &mut NameArena::default());
        }

        #[test]
        fn decode_runs_never_panics(b in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode_runs(&b);
        }

        #[test]
        fn boot_never_panics(b in prop::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_boot_sector(&b);
        }
    }
}
