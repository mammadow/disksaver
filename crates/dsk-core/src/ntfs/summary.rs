#![forbid(unsafe_code)]

use smallvec::SmallVec;

use crate::error::NtfsError;
use crate::index::names::{NameArena, NameRef};
use crate::ntfs::attr::{
    StandardInfo, attributes, parse_file_name, parse_reparse_tag, parse_standard_info,
};
use crate::ntfs::record::{REC_DIRECTORY, REC_IN_USE, apply_fixups, parse_header};
use crate::ntfs::runs::allocated_clusters;
use crate::ntfs::{
    ATTR_DATA, ATTR_FILE_NAME, ATTR_INDEX_ALLOCATION, ATTR_REPARSE_POINT, ATTR_STANDARD_INFO,
};

/// A hard link name and its parent directory record number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkName {
    pub parent_record: u64,
    pub parent_seq: u16,
    pub name: NameRef,
}

/// Consolidated summary of an NTFS file or directory record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSummary {
    pub record: u64,
    pub seq: u16,
    pub base_record: u64,
    pub is_dir: bool,
    pub si: Option<StandardInfo>,
    pub names: SmallVec<[LinkName; 1]>,
    pub logical: u64,
    pub allocated: u64,
    pub has_ads: bool,
    pub has_wof_stream: bool,
    pub unnamed_flags: u16,
    pub reparse_tag: u32,
}

fn is_wof_compressed_data(name_utf16le: &[u8]) -> bool {
    const WOF_NAME: &str = "WofCompressedData";
    if name_utf16le.len() != WOF_NAME.len() * 2 {
        return false;
    }
    let (chunks, _) = name_utf16le.as_chunks::<2>();
    chunks
        .iter()
        .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
        .eq(WOF_NAME.encode_utf16())
}

/// Summarizes an NTFS file record into a [`FileSummary`].
///
/// Returns `Ok(None)` if the record is not in use.
pub fn summarize_record(
    rec: &mut [u8],
    record_no: u64,
    cluster_size: u64,
    names: &mut NameArena,
) -> Result<Option<FileSummary>, NtfsError> {
    if rec.len() < 48 {
        return Err(NtfsError::Truncated("record header"));
    }

    if rec.get(0..4) != Some(b"FILE") {
        return Err(NtfsError::BadSignature);
    }

    let flags = u16::from_le_bytes(
        rec.get(22..24)
            .ok_or(NtfsError::Truncated("flags"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("flags"))?,
    );
    if (flags & REC_IN_USE) == 0 {
        return Ok(None);
    }

    apply_fixups(rec)?;
    let h = parse_header(rec)?;

    let is_dir = (h.flags & REC_DIRECTORY) != 0;
    let mut si: Option<StandardInfo> = None;
    let mut summary_names: SmallVec<[LinkName; 1]> = SmallVec::new();
    let mut logical: u64 = 0;
    let mut allocated: u64 = 0;
    let mut has_ads = false;
    let mut has_wof_stream = false;
    let mut unnamed_flags: u16 = 0;
    let mut reparse_tag: u32 = 0;

    for attr_res in attributes(rec, &h) {
        let attr = attr_res?;
        match attr.type_code {
            ATTR_STANDARD_INFO => {
                if let crate::ntfs::attr::AttrBody::Resident { value } = attr.body {
                    si = Some(parse_standard_info(value)?);
                }
            }
            ATTR_FILE_NAME => {
                if let crate::ntfs::attr::AttrBody::Resident { value } = attr.body {
                    let fn_attr = parse_file_name(value)?;
                    if fn_attr.namespace != 2 {
                        let (chunks, _) = fn_attr.name_utf16le.as_chunks::<2>();
                        let u16_chars: Vec<u16> = chunks
                            .iter()
                            .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
                            .collect();
                        let name_ref = names.push_utf16(&u16_chars);
                        summary_names.push(LinkName {
                            parent_record: fn_attr.parent_record,
                            parent_seq: fn_attr.parent_seq,
                            name: name_ref,
                        });
                    }
                }
            }
            ATTR_DATA => {
                if attr.name_utf16le.is_empty() {
                    unnamed_flags = attr.flags;
                    match attr.body {
                        crate::ntfs::attr::AttrBody::Resident { value } => {
                            logical = value.len() as u64;
                        }
                        crate::ntfs::attr::AttrBody::NonResident {
                            start_vcn,
                            data_size,
                            runs,
                        } => {
                            if start_vcn == 0 {
                                logical = data_size;
                            }
                            let clusters = allocated_clusters(runs)?;
                            let bytes = clusters
                                .checked_mul(cluster_size)
                                .ok_or(NtfsError::BadRunList)?;
                            allocated =
                                allocated.checked_add(bytes).ok_or(NtfsError::BadRunList)?;
                        }
                    }
                } else {
                    if is_wof_compressed_data(attr.name_utf16le) {
                        has_wof_stream = true;
                    } else {
                        has_ads = true;
                    }
                    if let crate::ntfs::attr::AttrBody::NonResident { runs, .. } = attr.body {
                        let clusters = allocated_clusters(runs)?;
                        let bytes = clusters
                            .checked_mul(cluster_size)
                            .ok_or(NtfsError::BadRunList)?;
                        allocated = allocated.checked_add(bytes).ok_or(NtfsError::BadRunList)?;
                    }
                }
            }
            ATTR_INDEX_ALLOCATION => {
                if let crate::ntfs::attr::AttrBody::NonResident { runs, .. } = attr.body {
                    let clusters = allocated_clusters(runs)?;
                    let bytes = clusters
                        .checked_mul(cluster_size)
                        .ok_or(NtfsError::BadRunList)?;
                    allocated = allocated.checked_add(bytes).ok_or(NtfsError::BadRunList)?;
                }
            }
            ATTR_REPARSE_POINT => {
                if let crate::ntfs::attr::AttrBody::Resident { value } = attr.body {
                    reparse_tag = parse_reparse_tag(value)?;
                }
            }
            _ => {}
        }
    }

    Ok(Some(FileSummary {
        record: record_no,
        seq: h.seq,
        base_record: h.base_record,
        is_dir,
        si,
        names: summary_names,
        logical,
        allocated,
        has_ads,
        has_wof_stream,
        unnamed_flags,
        reparse_tag,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::names::NameArena;
    use crate::ntfs::attr::parse_attribute_list;
    use crate::ntfs::record::parse_header;
    use crate::ntfs::runs::Run;
    use crate::ntfs::testutil::RecordBuilder;
    use crate::ntfs::{AF_SPARSE, TAG_WOF};

    #[test]
    fn regular_file_sizes() {
        let runs = [Run {
            lcn: Some(100),
            len: 3,
        }];
        let mut r = RecordBuilder::new(1, 1)
            .data_nonresident(None, 0, 10_000, 0, &runs)
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 1, 4096, &mut a).unwrap().unwrap();
        assert_eq!((s.logical, s.allocated), (10_000, 3 * 4096));
    }

    #[test]
    fn dos_name_skipped() {
        let mut r = RecordBuilder::new(2, 1)
            .file_name(5, 1, 2, "REPORT~1.PDF")
            .file_name(5, 1, 1, "report.pdf")
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 2, 4096, &mut a).unwrap().unwrap();
        assert_eq!(s.names.len(), 1);
    }

    #[test]
    fn win32_and_dos_name_kept() {
        let mut r = RecordBuilder::new(3, 1)
            .file_name(5, 1, 3, "report.pdf")
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 3, 4096, &mut a).unwrap().unwrap();
        assert_eq!(s.names.len(), 1);
    }

    #[test]
    fn hard_link_two_names() {
        let mut r = RecordBuilder::new(4, 1)
            .file_name(5, 1, 1, "link1.txt")
            .file_name(6, 1, 1, "link2.txt")
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 4, 4096, &mut a).unwrap().unwrap();
        assert_eq!(s.names.len(), 2);
    }

    #[test]
    fn resident_file_zero_alloc() {
        let mut r = RecordBuilder::new(5, 1)
            .data_resident(None, 300)
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 5, 4096, &mut a).unwrap().unwrap();
        assert_eq!((s.logical, s.allocated), (300, 0));
    }

    #[test]
    fn wof_file() {
        let runs_unnamed = [Run {
            lcn: None,
            len: 245,
        }];
        let runs_wof = [Run {
            lcn: Some(500),
            len: 60,
        }];
        let mut r = RecordBuilder::new(6, 1)
            .data_nonresident(None, 0, 1_000_000, 0, &runs_unnamed)
            .data_nonresident(Some("WofCompressedData"), 0, 60 * 4096, 0, &runs_wof)
            .reparse(TAG_WOF)
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 6, 4096, &mut a).unwrap().unwrap();
        assert_eq!(
            (
                s.logical,
                s.allocated,
                s.reparse_tag,
                s.has_ads,
                s.has_wof_stream
            ),
            (1_000_000, 60 * 4096, TAG_WOF, false, true)
        );
    }

    #[test]
    fn ads_counted() {
        let runs_ads = [Run {
            lcn: Some(200),
            len: 3,
        }];
        let mut r = RecordBuilder::new(7, 1)
            .data_nonresident(Some("stream"), 0, 12000, 0, &runs_ads)
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 7, 4096, &mut a).unwrap().unwrap();
        assert_eq!((s.allocated, s.has_ads), (3 * 4096, true));
    }

    #[test]
    fn sparse_file() {
        let runs_sparse = [
            Run {
                lcn: None,
                len: 1000,
            },
            Run {
                lcn: Some(9),
                len: 1,
            },
        ];
        let mut r = RecordBuilder::new(8, 1)
            .data_nonresident(None, 0, 1001 * 4096, AF_SPARSE, &runs_sparse)
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 8, 4096, &mut a).unwrap().unwrap();
        assert_eq!(s.allocated, 4096);
        assert_ne!(s.unnamed_flags & AF_SPARSE, 0);
    }

    #[test]
    fn directory_index_allocation() {
        let runs_dir = [Run {
            lcn: Some(300),
            len: 4,
        }];
        let mut r = RecordBuilder::new(9, 1)
            .dir()
            .index_allocation(&runs_dir)
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 9, 4096, &mut a).unwrap().unwrap();
        assert!(s.is_dir);
        assert_eq!(s.allocated, 4 * 4096);
    }

    #[test]
    fn extension_record_base() {
        let mut r = RecordBuilder::new(10, 1).base(42).build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 10, 4096, &mut a).unwrap().unwrap();
        assert_eq!(s.base_record, 42);
    }

    #[test]
    fn not_in_use_returns_none() {
        let mut r = RecordBuilder::new(9, 1).not_in_use().build(1024);
        let mut a = NameArena::new();
        assert!(summarize_record(&mut r, 9, 4096, &mut a).unwrap().is_none());
    }

    #[test]
    fn non_vcn0_extent_does_not_set_logical() {
        let runs_ext = [Run {
            lcn: Some(7),
            len: 2,
        }];
        let mut r = RecordBuilder::new(12, 1)
            .data_nonresident(None, 100, 999, 0, &runs_ext)
            .build(1024);
        let mut a = NameArena::new();
        let s = summarize_record(&mut r, 12, 4096, &mut a).unwrap().unwrap();
        assert_eq!((s.logical, s.allocated), (0, 2 * 4096));
    }

    #[test]
    fn zero_length_attribute_is_error() {
        let mut r = RecordBuilder::new(9, 1).data_resident(None, 64).build(1024);
        let h = parse_header(&r).unwrap();
        let off = h.attrs_offset as usize;
        r[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
        let mut a = NameArena::new();
        assert!(matches!(
            summarize_record(&mut r, 9, 4096, &mut a),
            Err(NtfsError::BadAttribute)
        ));
    }

    #[test]
    fn attribute_list_parses() {
        let entries = [(0x10u32, 0u64, 10u64), (0x80u32, 0u64, 77u64)];
        let mut v = vec![0u8; 64];
        for (i, &(tc, vcn, rec)) in entries.iter().enumerate() {
            let off = i * 32;
            v[off..off + 4].copy_from_slice(&tc.to_le_bytes());
            v[off + 4..off + 6].copy_from_slice(&32u16.to_le_bytes());
            v[off + 8..off + 16].copy_from_slice(&vcn.to_le_bytes());
            v[off + 16..off + 24].copy_from_slice(&rec.to_le_bytes());
        }
        assert_eq!(parse_attribute_list(&v).unwrap()[1].record, 77);
    }
}
