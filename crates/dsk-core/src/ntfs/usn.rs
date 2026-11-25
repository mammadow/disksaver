//! Bounds-checked pure-Rust parser for NTFS USN Journal records (`USN_RECORD_V2` / `V3`)
//! and continuity/delta definitions.

#![forbid(unsafe_code)]

use std::io;

use rustc_hash::FxHashMap;

use crate::error::{DskError, Result};
use crate::index::builder::NodeFlags;

pub const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
pub const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
pub const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
pub const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
pub const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
pub const USN_REASON_CLOSE: u32 = 0x8000_0000;

/// Minimum byte size of `USN_RECORD_V2` fixed header.
pub const USN_V2_HEADER_LEN: usize = 60;
/// Minimum byte size of `USN_RECORD_V3` fixed header.
pub const USN_V3_HEADER_LEN: usize = 76;

/// Parsed fields from `USN_RECORD_V2` or `USN_RECORD_V3`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsnRecord {
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference_number: u64,
    pub file_id_high: u64,
    pub parent_file_reference_number: u64,
    pub parent_file_id_high: u64,
    pub usn: i64,
    pub timestamp: i64,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
}

/// Live USN journal cursor state retrieved from `FSCTL_QUERY_USN_JOURNAL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsnJournalState {
    pub usn_journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub lowest_valid_usn: i64,
}

/// Coalesced per-link USN operation ready to stat (if upsert) or apply directly (if delete).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoalescedUsnOp {
    StatAndUpsert {
        file_id: u64,
        parent_file_id: u64,
        old_parent_file_id: Option<u64>,
        old_name: Option<String>,
        name: String,
        usn_file_attributes: u32,
    },
    DeleteLink {
        file_id: u64,
        parent_file_id: u64,
        name: String,
    },
}

/// High-level tree delta applied to an [`crate::index::Index`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsnDelta {
    Upsert {
        file_id: u64,
        parent_file_id: u64,
        old_parent_file_id: Option<u64>,
        old_name: Option<String>,
        name: String,
        logical: u64,
        allocated: u64,
        mtime: u32,
        atime: u32,
        flags: NodeFlags,
        reparse_tag: u32,
        preserve_existing_sizes_if_unreadable: bool,
    },
    Delete {
        file_id: u64,
        parent_file_id: Option<u64>,
        name: Option<String>,
    },
}

fn invalid_usn(msg: impl Into<String>) -> DskError {
    DskError::Io(io::Error::new(io::ErrorKind::InvalidData, msg.into()))
}

#[inline]
fn read_u16_le(slice: &[u8], off: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice
        .get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid_usn("USN record truncated reading u16"))?;
    Ok(u16::from_le_bytes(bytes))
}

#[inline]
fn read_u32_le(slice: &[u8], off: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice
        .get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid_usn("USN record truncated reading u32"))?;
    Ok(u32::from_le_bytes(bytes))
}

#[inline]
fn read_u64_le(slice: &[u8], off: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice
        .get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid_usn("USN record truncated reading u64"))?;
    Ok(u64::from_le_bytes(bytes))
}

#[inline]
fn read_i64_le(slice: &[u8], off: usize) -> Result<i64> {
    let bytes: [u8; 8] = slice
        .get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid_usn("USN record truncated reading i64"))?;
    Ok(i64::from_le_bytes(bytes))
}

/// Parses an entire `FSCTL_READ_USN_JOURNAL` response buffer (`8B next_usn` + records).
pub fn parse_usn_read_buffer(buf: &[u8]) -> Result<(i64, Vec<UsnRecord>)> {
    if buf.len() < 8 {
        return Err(invalid_usn(format!(
            "USN read buffer too short: {} bytes",
            buf.len()
        )));
    }
    let next_usn = read_i64_le(buf, 0)?;
    let records = parse_usn_records(&buf[8..])?;
    Ok((next_usn, records))
}

/// Parses a contiguous sequence of `USN_RECORD_V2` / `USN_RECORD_V3` entries from raw bytes.
pub fn parse_usn_records(buf: &[u8]) -> Result<Vec<UsnRecord>> {
    let mut out = Vec::new();
    let mut offset = 0usize;

    while offset < buf.len() {
        let rem = &buf[offset..];
        if rem.len() < 8 {
            return Err(invalid_usn(format!(
                "trailing {} bytes in USN buffer smaller than common header",
                rem.len()
            )));
        }

        let rec_len_u32 = read_u32_le(rem, 0)?;
        let rec_len = rec_len_u32 as usize;
        if rec_len < USN_V2_HEADER_LEN || !rec_len.is_multiple_of(8) || rec_len > rem.len() {
            return Err(invalid_usn(format!(
                "invalid USN RecordLength {} (remaining {} bytes)",
                rec_len,
                rem.len()
            )));
        }

        let rec = &rem[..rec_len];
        let major_version = read_u16_le(rec, 4)?;
        let minor_version = read_u16_le(rec, 6)?;

        let (
            min_header_len,
            file_reference_number,
            file_id_high,
            parent_file_reference_number,
            parent_file_id_high,
            usn,
            timestamp,
            reason,
            source_info,
            security_id,
            file_attributes,
            name_len,
            name_off,
        ) = match major_version {
            2 => (
                USN_V2_HEADER_LEN,
                read_u64_le(rec, 8)?,
                0u64,
                read_u64_le(rec, 16)?,
                0u64,
                read_i64_le(rec, 24)?,
                read_i64_le(rec, 32)?,
                read_u32_le(rec, 40)?,
                read_u32_le(rec, 44)?,
                read_u32_le(rec, 48)?,
                read_u32_le(rec, 52)?,
                read_u16_le(rec, 56)? as usize,
                read_u16_le(rec, 58)? as usize,
            ),
            3 => {
                if rec_len < USN_V3_HEADER_LEN {
                    return Err(invalid_usn(format!(
                        "USN_RECORD_V3 RecordLength {} < {}",
                        rec_len, USN_V3_HEADER_LEN
                    )));
                }
                (
                    USN_V3_HEADER_LEN,
                    read_u64_le(rec, 8)?,
                    read_u64_le(rec, 16)?,
                    read_u64_le(rec, 24)?,
                    read_u64_le(rec, 32)?,
                    read_i64_le(rec, 40)?,
                    read_i64_le(rec, 48)?,
                    read_u32_le(rec, 56)?,
                    read_u32_le(rec, 60)?,
                    read_u32_le(rec, 64)?,
                    read_u32_le(rec, 68)?,
                    read_u16_le(rec, 72)? as usize,
                    read_u16_le(rec, 74)? as usize,
                )
            }
            other => {
                return Err(DskError::Unsupported(format!(
                    "unsupported USN record major version {other}"
                )));
            }
        };

        if name_off < min_header_len || !name_len.is_multiple_of(2) {
            return Err(invalid_usn(format!(
                "invalid USN FileNameOffset ({name_off}) or odd FileNameLength ({name_len})"
            )));
        }

        let name_end = name_off
            .checked_add(name_len)
            .ok_or_else(|| invalid_usn("USN FileNameOffset + FileNameLength overflow"))?;
        if name_end > rec_len {
            return Err(invalid_usn(format!(
                "USN FileName extends past RecordLength ({name_end} > {rec_len})"
            )));
        }

        let name_slice = &rec[name_off..name_end];
        let mut utf16 = Vec::with_capacity(name_len / 2);
        let (pairs, _) = name_slice.as_chunks::<2>();
        for pair in pairs {
            utf16.push(u16::from_le_bytes(*pair));
        }
        let file_name = String::from_utf16_lossy(&utf16);

        out.push(UsnRecord {
            major_version,
            minor_version,
            file_reference_number,
            file_id_high,
            parent_file_reference_number,
            parent_file_id_high,
            usn,
            timestamp,
            reason,
            source_info,
            security_id,
            file_attributes,
            file_name,
        });

        offset += rec_len;
    }

    Ok(out)
}

/// Strictly validates that a saved USN journal cursor is continuous with `live`.
pub fn validate_usn_continuity(
    saved_journal_id: u64,
    saved_next_usn: i64,
    live: &UsnJournalState,
) -> Result<()> {
    if saved_journal_id == 0 || saved_journal_id != live.usn_journal_id {
        return Err(invalid_usn(format!(
            "USN journal ID mismatch (cached {saved_journal_id:#x}, live {:#x})",
            live.usn_journal_id
        )));
    }
    if saved_next_usn < live.first_usn || saved_next_usn < live.lowest_valid_usn {
        return Err(invalid_usn(format!(
            "USN cursor wrapped past journal start (cached {saved_next_usn}, first {}, lowest_valid {})",
            live.first_usn, live.lowest_valid_usn
        )));
    }
    if saved_next_usn > live.next_usn {
        return Err(invalid_usn(format!(
            "USN cursor ahead of live journal (cached {saved_next_usn} > live {})",
            live.next_usn
        )));
    }
    Ok(())
}

struct PendingRenameOld {
    immediate_old: (u64, String),
    orig_old_link: Option<(u64, String)>,
    created_in_batch: bool,
}

enum PendingKind {
    Upsert {
        old_link: Option<(u64, String)>,
        created_in_batch: bool,
        usn_file_attributes: u32,
    },
    Delete,
}

struct PendingEntry {
    seq: u64,
    file_id: u64,
    parent_file_id: u64,
    name: String,
    kind: PendingKind,
}

/// Coalesces chronological raw USN journal records into minimal per-link operations,
/// collapsing repeated writes, pairing `RENAME_OLD_NAME`/`RENAME_NEW_NAME`,
/// cancelling ephemeral create+delete pairs, and filtering internal `$Extend` metadata noise.
/// Index of the earliest `RENAME_OLD_NAME` record whose `RENAME_NEW_NAME` partner is not in
/// `records` (same metafile filter as [`coalesce_usn_records`]).
pub fn first_unmatched_rename_old(records: &[UsnRecord]) -> Option<usize> {
    let mut open: FxHashMap<u64, usize> = FxHashMap::default();
    for (i, rec) in records.iter().enumerate() {
        let frn = rec.file_reference_number & 0x0000_FFFF_FFFF_FFFF;
        let parent = rec.parent_file_reference_number & 0x0000_FFFF_FFFF_FFFF;
        if frn < 24 || parent == 11 {
            continue;
        }
        if rec.reason & USN_REASON_RENAME_OLD_NAME != 0 {
            open.entry(rec.file_reference_number).or_insert(i);
        } else if rec.reason & USN_REASON_RENAME_NEW_NAME != 0 {
            open.remove(&rec.file_reference_number);
        }
    }
    open.into_values().min()
}

/// Keeps a rename's `OLD_NAME`/`NEW_NAME` pair inside one read window.
///
/// When the window `[start_usn, cursor)` ends between the two records, applying only the first
/// half drops the old link while the next run sees a bare `NEW_NAME`: the old name survives as a
/// "ghost" next to the new one until a full rescan. This truncates `records` before the earliest
/// unmatched `OLD_NAME` and returns the rewound cursor (that record's USN) so the next incremental
/// run re-reads the pair together. Nothing after the rewind point has been applied, so nothing is
/// applied twice. An unmatched `OLD_NAME` *at* `start_usn` cannot be rewound (it would livelock),
/// so it forces the full-scan fallback instead.
pub fn rewind_unpaired_rename_tail(
    records: &mut Vec<UsnRecord>,
    start_usn: i64,
    cursor: i64,
) -> Result<i64> {
    let Some(i) = first_unmatched_rename_old(records) else {
        return Ok(cursor);
    };
    let rewind_to = records[i].usn;
    if rewind_to <= start_usn {
        return Err(DskError::Unsupported(
            "USN rename pair is incomplete at the journal cursor; falling back to full scan"
                .to_string(),
        ));
    }
    records.truncate(i);
    Ok(rewind_to.min(cursor))
}

pub fn coalesce_usn_records(records: &[UsnRecord]) -> Vec<CoalescedUsnOp> {
    let mut seq = 0u64;
    let mut entries: FxHashMap<(u64, u64, String), PendingEntry> = FxHashMap::default();
    let mut pending_rename: FxHashMap<u64, PendingRenameOld> = FxHashMap::default();

    for rec in records {
        let frn_rec = rec.file_reference_number & 0x0000_FFFF_FFFF_FFFF;
        let parent_rec = rec.parent_file_reference_number & 0x0000_FFFF_FFFF_FFFF;
        // Skip internal NTFS metafiles ($MFT..$UpCase, $Extend = 11) and $Extend\* ($UsnJrnl).
        if frn_rec < 24 || parent_rec == 11 {
            continue;
        }

        let key = (
            rec.file_reference_number,
            rec.parent_file_reference_number,
            rec.file_name.to_lowercase(),
        );
        seq += 1;

        if rec.reason & USN_REASON_FILE_DELETE != 0 {
            if let Some(prev) = entries.remove(&key) {
                match prev.kind {
                    PendingKind::Upsert {
                        old_link,
                        created_in_batch,
                        ..
                    } => {
                        if !created_in_batch {
                            entries.insert(
                                key,
                                PendingEntry {
                                    seq,
                                    file_id: rec.file_reference_number,
                                    parent_file_id: rec.parent_file_reference_number,
                                    name: rec.file_name.clone(),
                                    kind: PendingKind::Delete,
                                },
                            );
                        } else if let Some((orig_p, orig_n)) = old_link {
                            let orig_key =
                                (rec.file_reference_number, orig_p, orig_n.to_lowercase());
                            entries.insert(
                                orig_key,
                                PendingEntry {
                                    seq,
                                    file_id: rec.file_reference_number,
                                    parent_file_id: orig_p,
                                    name: orig_n,
                                    kind: PendingKind::Delete,
                                },
                            );
                        }
                    }
                    PendingKind::Delete => {
                        entries.insert(key, prev);
                    }
                }
            } else {
                entries.insert(
                    key,
                    PendingEntry {
                        seq,
                        file_id: rec.file_reference_number,
                        parent_file_id: rec.parent_file_reference_number,
                        name: rec.file_name.clone(),
                        kind: PendingKind::Delete,
                    },
                );
            }
            continue;
        }

        if rec.reason & USN_REASON_RENAME_OLD_NAME != 0 {
            let (orig_old_link, created_in_batch) = match entries.remove(&key) {
                Some(PendingEntry {
                    kind:
                        PendingKind::Upsert {
                            old_link,
                            created_in_batch,
                            ..
                        },
                    ..
                }) => (old_link, created_in_batch),
                Some(other) => {
                    entries.insert(key, other);
                    (None, false)
                }
                None => (None, false),
            };
            pending_rename.insert(
                rec.file_reference_number,
                PendingRenameOld {
                    immediate_old: (rec.parent_file_reference_number, rec.file_name.clone()),
                    orig_old_link,
                    created_in_batch,
                },
            );
            continue;
        }

        let is_create = rec.reason & USN_REASON_FILE_CREATE != 0;
        let rename_old = if rec.reason & USN_REASON_RENAME_NEW_NAME != 0 {
            pending_rename.remove(&rec.file_reference_number)
        } else {
            None
        };

        if let Some(existing) = entries.get_mut(&key) {
            existing.seq = seq;
            existing.name = rec.file_name.clone();
            match &mut existing.kind {
                PendingKind::Upsert {
                    old_link,
                    created_in_batch,
                    usn_file_attributes,
                } => {
                    *usn_file_attributes = rec.file_attributes;
                    if is_create {
                        *created_in_batch = true;
                    }
                    if let Some(ro) = rename_old
                        && old_link.is_none()
                        && !ro.created_in_batch
                    {
                        *old_link = Some(ro.orig_old_link.unwrap_or(ro.immediate_old));
                    }
                }
                PendingKind::Delete => {
                    let old_link = rename_old.and_then(|ro| {
                        if ro.created_in_batch {
                            None
                        } else {
                            Some(ro.orig_old_link.unwrap_or(ro.immediate_old))
                        }
                    });
                    existing.kind = PendingKind::Upsert {
                        old_link,
                        created_in_batch: is_create,
                        usn_file_attributes: rec.file_attributes,
                    };
                }
            }
        } else {
            let (old_link, created_in_batch) = if let Some(ro) = rename_old {
                let ol = if ro.created_in_batch {
                    None
                } else {
                    Some(ro.orig_old_link.unwrap_or(ro.immediate_old))
                };
                (ol, ro.created_in_batch || is_create)
            } else {
                (None, is_create)
            };
            entries.insert(
                key,
                PendingEntry {
                    seq,
                    file_id: rec.file_reference_number,
                    parent_file_id: rec.parent_file_reference_number,
                    name: rec.file_name.clone(),
                    kind: PendingKind::Upsert {
                        old_link,
                        created_in_batch,
                        usn_file_attributes: rec.file_attributes,
                    },
                },
            );
        }
    }

    let mut ordered: Vec<PendingEntry> = entries.into_values().collect();
    ordered.sort_by_key(|e| e.seq);

    ordered
        .into_iter()
        .map(|e| match e.kind {
            PendingKind::Delete => CoalescedUsnOp::DeleteLink {
                file_id: e.file_id,
                parent_file_id: e.parent_file_id,
                name: e.name,
            },
            PendingKind::Upsert {
                old_link,
                usn_file_attributes,
                ..
            } => {
                let (old_parent_file_id, old_name) = match old_link {
                    Some((op, on)) => (Some(op), Some(on)),
                    None => (None, None),
                };
                CoalescedUsnOp::StatAndUpsert {
                    file_id: e.file_id,
                    parent_file_id: e.parent_file_id,
                    old_parent_file_id,
                    old_name,
                    name: e.name,
                    usn_file_attributes,
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn build_v2_record(frn: u64, parent_frn: u64, usn: i64, reason: u32, name: &str) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = utf16.len() * 2;
        let raw_len = USN_V2_HEADER_LEN + name_bytes_len;
        let rec_len = (raw_len + 7) & !7;
        let mut out = vec![0u8; rec_len];
        out[0..4].copy_from_slice(&(rec_len as u32).to_le_bytes());
        out[4..6].copy_from_slice(&2u16.to_le_bytes());
        out[6..8].copy_from_slice(&0u16.to_le_bytes());
        out[8..16].copy_from_slice(&frn.to_le_bytes());
        out[16..24].copy_from_slice(&parent_frn.to_le_bytes());
        out[24..32].copy_from_slice(&usn.to_le_bytes());
        out[32..40].copy_from_slice(&133_000_000_000_000_000i64.to_le_bytes());
        out[40..44].copy_from_slice(&reason.to_le_bytes());
        out[52..56].copy_from_slice(&0x20u32.to_le_bytes());
        out[56..58].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        out[58..60].copy_from_slice(&(USN_V2_HEADER_LEN as u16).to_le_bytes());
        for (i, ch) in utf16.iter().enumerate() {
            let off = USN_V2_HEADER_LEN + i * 2;
            out[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        out
    }

    fn build_v3_record(frn: u64, parent_frn: u64, usn: i64, reason: u32, name: &str) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = utf16.len() * 2;
        let raw_len = USN_V3_HEADER_LEN + name_bytes_len;
        let rec_len = (raw_len + 7) & !7;
        let mut out = vec![0u8; rec_len];
        out[0..4].copy_from_slice(&(rec_len as u32).to_le_bytes());
        out[4..6].copy_from_slice(&3u16.to_le_bytes());
        out[6..8].copy_from_slice(&0u16.to_le_bytes());
        out[8..16].copy_from_slice(&frn.to_le_bytes());
        out[24..32].copy_from_slice(&parent_frn.to_le_bytes());
        out[40..48].copy_from_slice(&usn.to_le_bytes());
        out[48..56].copy_from_slice(&133_000_000_000_000_000i64.to_le_bytes());
        out[56..60].copy_from_slice(&reason.to_le_bytes());
        out[68..72].copy_from_slice(&0x10u32.to_le_bytes());
        out[72..74].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        out[74..76].copy_from_slice(&(USN_V3_HEADER_LEN as u16).to_le_bytes());
        for (i, ch) in utf16.iter().enumerate() {
            let off = USN_V3_HEADER_LEN + i * 2;
            out[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        out
    }

    #[test]
    fn parses_v2_and_v3_records_from_read_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&4096i64.to_le_bytes());
        buf.extend_from_slice(&build_v2_record(
            (2u64 << 48) | 100,
            (5u64 << 48) | 5,
            1024,
            USN_REASON_FILE_CREATE | USN_REASON_CLOSE,
            "hello.log",
        ));
        buf.extend_from_slice(&build_v3_record(
            (3u64 << 48) | 200,
            (2u64 << 48) | 100,
            2048,
            USN_REASON_DATA_EXTEND,
            "nested_dir",
        ));

        let (next_usn, recs) = parse_usn_read_buffer(&buf).unwrap();
        assert_eq!(next_usn, 4096);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].major_version, 2);
        assert_eq!(recs[0].file_reference_number, (2u64 << 48) | 100);
        assert_eq!(recs[0].file_name, "hello.log");
        assert_eq!(recs[1].major_version, 3);
        assert_eq!(recs[1].parent_file_reference_number, (2u64 << 48) | 100);
        assert_eq!(recs[1].file_name, "nested_dir");
    }

    #[test]
    fn rejects_invalid_record_lengths_and_bounds() {
        // RecordLength < 60
        let mut short = build_v2_record(10, 5, 100, 1, "a.txt");
        short[0..4].copy_from_slice(&56u32.to_le_bytes());
        assert!(parse_usn_records(&short).is_err());

        // RecordLength % 8 != 0
        let mut unaligned = build_v2_record(10, 5, 100, 1, "a.txt");
        let len = unaligned.len() as u32;
        unaligned[0..4].copy_from_slice(&(len - 2).to_le_bytes());
        assert!(parse_usn_records(&unaligned).is_err());

        // FileNameOffset + FileNameLength > RecordLength (and overflow test)
        let mut oob = build_v2_record(10, 5, 100, 1, "a.txt");
        oob[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(parse_usn_records(&oob).is_err());

        // RecordLength > slice remaining
        let mut overrun = build_v2_record(10, 5, 100, 1, "a.txt");
        overrun[0..4].copy_from_slice(&4096u32.to_le_bytes());
        assert!(parse_usn_records(&overrun).is_err());
    }

    #[test]
    fn continuity_checks_journal_id_and_range() {
        let live = UsnJournalState {
            usn_journal_id: 777,
            first_usn: 1_000,
            next_usn: 5_000,
            lowest_valid_usn: 1_200,
        };
        assert!(validate_usn_continuity(777, 1_200, &live).is_ok());
        assert!(validate_usn_continuity(777, 5_000, &live).is_ok());
        // Journal ID mismatch
        assert!(validate_usn_continuity(888, 2_000, &live).is_err());
        // Wrapped past first_usn / lowest_valid_usn
        assert!(validate_usn_continuity(777, 900, &live).is_err());
        assert!(validate_usn_continuity(777, 1_100, &live).is_err());
        // Future USN beyond live next_usn
        assert!(validate_usn_continuity(777, 5_001, &live).is_err());
    }

    proptest! {
        #[test]
        fn usn_parser_never_panics_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_usn_records(&data);
            let _ = parse_usn_read_buffer(&data);
        }

        #[test]
        fn usn_parser_handles_fuzzed_v2_v3_headers(
            major in prop_oneof![Just(2u16), Just(3u16), Just(4u16)],
            rec_len in 0u32..300u32,
            name_off in 0u16..200u16,
            name_len in 0u16..200u16,
            payload in proptest::collection::vec(any::<u8>(), 80..256),
        ) {
            let mut buf = payload;
            buf[0..4].copy_from_slice(&rec_len.to_le_bytes());
            buf[4..6].copy_from_slice(&major.to_le_bytes());
            if major == 2 {
                buf[56..58].copy_from_slice(&name_len.to_le_bytes());
                buf[58..60].copy_from_slice(&name_off.to_le_bytes());
            } else {
                buf[72..74].copy_from_slice(&name_len.to_le_bytes());
                buf[74..76].copy_from_slice(&name_off.to_le_bytes());
            }
            let _ = parse_usn_records(&buf);
        }
    }

    fn make_rec(frn: u64, parent_frn: u64, reason: u32, name: &str) -> UsnRecord {
        UsnRecord {
            major_version: 2,
            minor_version: 0,
            file_reference_number: frn,
            file_id_high: 0,
            parent_file_reference_number: parent_frn,
            parent_file_id_high: 0,
            usn: 100,
            timestamp: 0,
            reason,
            source_info: 0,
            security_id: 0,
            file_attributes: 0x20,
            file_name: name.to_string(),
        }
    }

    #[test]
    fn rename_pair_split_at_window_end_rewinds_cursor() {
        let with_usn = |usn: i64, r: UsnRecord| UsnRecord { usn, ..r };
        // Unrelated create, then a rename whose NEW_NAME falls outside this read window.
        let mut recs = vec![
            with_usn(100, make_rec(200, 5, USN_REASON_FILE_CREATE, "a.txt")),
            with_usn(160, make_rec(300, 5, USN_REASON_RENAME_OLD_NAME, "old.txt")),
            with_usn(220, make_rec(400, 5, USN_REASON_DATA_EXTEND, "b.txt")),
        ];
        assert_eq!(first_unmatched_rename_old(&recs), Some(1));
        let cursor = rewind_unpaired_rename_tail(&mut recs, 50, 300).expect("rewind");
        assert_eq!(cursor, 160, "next run starts at the unmatched OLD_NAME");
        assert_eq!(
            recs.len(),
            1,
            "records from the OLD_NAME on are re-read next run"
        );

        // A complete pair is left alone.
        let mut paired = vec![
            with_usn(100, make_rec(300, 5, USN_REASON_RENAME_OLD_NAME, "old.txt")),
            with_usn(110, make_rec(300, 5, USN_REASON_RENAME_NEW_NAME, "new.txt")),
        ];
        assert_eq!(first_unmatched_rename_old(&paired), None);
        assert_eq!(
            rewind_unpaired_rename_tail(&mut paired, 50, 300).unwrap(),
            300
        );
        assert_eq!(paired.len(), 2);

        // Unmatched OLD_NAME at the very start cannot make progress: full-scan fallback.
        let mut stuck = vec![with_usn(
            50,
            make_rec(300, 5, USN_REASON_RENAME_OLD_NAME, "old.txt"),
        )];
        assert!(rewind_unpaired_rename_tail(&mut stuck, 50, 300).is_err());

        // Metafile noise never triggers a rewind.
        let mut noise = vec![with_usn(
            120,
            make_rec(500, 11, USN_REASON_RENAME_OLD_NAME, "$UsnJrnl"),
        )];
        assert_eq!(
            rewind_unpaired_rename_tail(&mut noise, 50, 300).unwrap(),
            300
        );
    }

    #[test]
    fn coalesces_chained_renames_creates_and_ignores_extend() {
        let records = vec![
            // Noise on $Extend\$UsnJrnl
            make_rec(500, 11, USN_REASON_DATA_EXTEND, "$UsnJrnl:$J"),
            // Temporary file created, extended 3 times, then deleted in same window -> vanishes cleanly
            make_rec(100, 5, USN_REASON_FILE_CREATE, "temp.tmp"),
            make_rec(100, 5, USN_REASON_DATA_EXTEND, "temp.tmp"),
            make_rec(
                100,
                5,
                USN_REASON_FILE_DELETE | USN_REASON_CLOSE,
                "temp.tmp",
            ),
            // Existing file renamed a.txt -> b.txt -> c.txt
            make_rec(200, 5, USN_REASON_RENAME_OLD_NAME, "a.txt"),
            make_rec(
                200,
                5,
                USN_REASON_RENAME_NEW_NAME | USN_REASON_CLOSE,
                "b.txt",
            ),
            make_rec(200, 5, USN_REASON_RENAME_OLD_NAME, "b.txt"),
            make_rec(
                200,
                10,
                USN_REASON_RENAME_NEW_NAME | USN_REASON_CLOSE,
                "c.txt",
            ),
        ];

        let ops = coalesce_usn_records(&records);
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            CoalescedUsnOp::StatAndUpsert {
                file_id: 200,
                parent_file_id: 10,
                old_parent_file_id: Some(5),
                old_name: Some("a.txt".to_string()),
                name: "c.txt".to_string(),
                usn_file_attributes: 0x20,
            }
        );
    }
}
