#![forbid(unsafe_code)]

use crate::error::NtfsError;
use crate::ntfs::ATTR_END;
use crate::ntfs::record::RecordHeader;

#[inline]
fn get_u16(slice: &[u8], range: std::ops::Range<usize>) -> Option<u16> {
    let bytes = slice.get(range)?;
    let arr: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

#[inline]
fn get_u32(slice: &[u8], range: std::ops::Range<usize>) -> Option<u32> {
    let bytes = slice.get(range)?;
    let arr: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

#[inline]
fn get_u64(slice: &[u8], range: std::ops::Range<usize>) -> Option<u64> {
    let bytes = slice.get(range)?;
    let arr: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

/// A reference to an attribute in an NTFS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrRef<'a> {
    pub type_code: u32,
    pub name_utf16le: &'a [u8],
    pub flags: u16,
    pub body: AttrBody<'a>,
}

/// The body of an attribute: resident (in-record value) or non-resident (run list extents).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrBody<'a> {
    Resident {
        value: &'a [u8],
    },
    NonResident {
        start_vcn: u64,
        data_size: u64,
        runs: &'a [u8],
    },
}

/// Iterator over attributes in an NTFS file record.
pub struct AttributeIter<'a> {
    rec: &'a [u8],
    offset: usize,
    limit: usize,
    finished: bool,
    initial_err: Option<NtfsError>,
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = Result<AttrRef<'a>, NtfsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(err) = self.initial_err.take() {
            self.finished = true;
            return Some(Err(err));
        }

        if self.finished || self.offset >= self.limit {
            return None;
        }

        // Must have at least 4 bytes for type_code
        if self
            .offset
            .checked_add(4)
            .is_none_or(|end| end > self.limit || end > self.rec.len())
        {
            self.finished = true;
            return Some(Err(NtfsError::BadAttribute));
        }

        let type_code = match get_u32(self.rec, self.offset..self.offset + 4) {
            Some(b) => b,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };

        if type_code == ATTR_END {
            self.finished = true;
            return None;
        }

        // Must have at least 8 bytes for total_len
        if self
            .offset
            .checked_add(8)
            .is_none_or(|end| end > self.limit || end > self.rec.len())
        {
            self.finished = true;
            return Some(Err(NtfsError::BadAttribute));
        }

        let total_len = match get_u32(self.rec, self.offset + 4..self.offset + 8) {
            Some(b) => b as usize,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };

        if total_len == 0 {
            self.finished = true;
            return Some(Err(NtfsError::BadAttribute));
        }

        let next_offset = match self.offset.checked_add(total_len) {
            Some(n) => n,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };

        if next_offset > self.limit || next_offset > self.rec.len() {
            self.finished = true;
            return Some(Err(NtfsError::BadAttribute));
        }

        let attr_slice = match self.rec.get(self.offset..next_offset) {
            Some(s) => s,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };

        if attr_slice.len() < 16 {
            self.finished = true;
            return Some(Err(NtfsError::BadAttribute));
        }

        let non_resident = *match attr_slice.get(8) {
            Some(b) => b,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };
        let name_len = *match attr_slice.get(9) {
            Some(b) => b,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        } as usize;
        let name_offset = match get_u16(attr_slice, 10..12) {
            Some(b) => b as usize,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };
        let flags = match get_u16(attr_slice, 12..14) {
            Some(b) => b,
            None => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };

        let name_utf16le = if name_len == 0 {
            &[][..]
        } else {
            let name_bytes_len = match name_len.checked_mul(2) {
                Some(l) => l,
                None => {
                    self.finished = true;
                    return Some(Err(NtfsError::BadAttribute));
                }
            };
            let name_end = match name_offset.checked_add(name_bytes_len) {
                Some(e) => e,
                None => {
                    self.finished = true;
                    return Some(Err(NtfsError::BadAttribute));
                }
            };
            match attr_slice.get(name_offset..name_end) {
                Some(s) => s,
                None => {
                    self.finished = true;
                    return Some(Err(NtfsError::BadAttribute));
                }
            }
        };

        let body = match non_resident {
            0 => {
                if attr_slice.len() < 22 {
                    self.finished = true;
                    return Some(Err(NtfsError::BadAttribute));
                }
                let value_len = match get_u32(attr_slice, 16..20) {
                    Some(b) => b as usize,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };
                let value_offset = match get_u16(attr_slice, 20..22) {
                    Some(b) => b as usize,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };

                let val_end = match value_offset.checked_add(value_len) {
                    Some(e) => e,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };

                let value = match attr_slice.get(value_offset..val_end) {
                    Some(s) => s,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };
                AttrBody::Resident { value }
            }
            1 => {
                if attr_slice.len() < 64 {
                    self.finished = true;
                    return Some(Err(NtfsError::BadAttribute));
                }
                let start_vcn = match get_u64(attr_slice, 16..24) {
                    Some(b) => b,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };
                let runs_offset = match get_u16(attr_slice, 32..34) {
                    Some(b) => b as usize,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };
                let data_size = match get_u64(attr_slice, 48..56) {
                    Some(b) => b,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };

                if runs_offset > attr_slice.len() {
                    self.finished = true;
                    return Some(Err(NtfsError::BadAttribute));
                }
                let runs = match attr_slice.get(runs_offset..) {
                    Some(s) => s,
                    None => {
                        self.finished = true;
                        return Some(Err(NtfsError::BadAttribute));
                    }
                };
                AttrBody::NonResident {
                    start_vcn,
                    data_size,
                    runs,
                }
            }
            _ => {
                self.finished = true;
                return Some(Err(NtfsError::BadAttribute));
            }
        };

        self.offset = next_offset;
        Some(Ok(AttrRef {
            type_code,
            name_utf16le,
            flags,
            body,
        }))
    }
}

/// Returns an iterator over all attributes in a file record buffer.
pub fn attributes<'a>(
    rec: &'a [u8],
    h: &RecordHeader,
) -> impl Iterator<Item = Result<AttrRef<'a>, NtfsError>> {
    let offset = h.attrs_offset as usize;
    let limit = (h.bytes_in_use as usize).min(rec.len());
    let initial_err = if offset > limit || offset > rec.len() {
        Some(NtfsError::BadAttribute)
    } else {
        None
    };
    AttributeIter {
        rec,
        offset,
        limit,
        finished: false,
        initial_err,
    }
}

/// Standard file information parsed from `$STANDARD_INFORMATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardInfo {
    pub mtime: u64,
    pub atime: u64,
    pub attributes: u32,
}

/// Parses the `$STANDARD_INFORMATION` resident attribute value.
pub fn parse_standard_info(v: &[u8]) -> Result<StandardInfo, NtfsError> {
    let mtime = get_u64(v, 8..16).ok_or(NtfsError::Truncated("standard info mtime"))?;
    let atime = get_u64(v, 24..32).ok_or(NtfsError::Truncated("standard info atime"))?;
    let attributes = get_u32(v, 32..36).ok_or(NtfsError::Truncated("standard info attributes"))?;
    Ok(StandardInfo {
        mtime,
        atime,
        attributes,
    })
}

/// File name attribute parsed from `$FILE_NAME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileNameAttr<'a> {
    pub parent_record: u64,
    pub parent_seq: u16,
    pub namespace: u8,
    pub name_utf16le: &'a [u8],
}

/// Parses the `$FILE_NAME` resident attribute value.
pub fn parse_file_name(v: &[u8]) -> Result<FileNameAttr<'_>, NtfsError> {
    let parent_ref = get_u64(v, 0..8).ok_or(NtfsError::Truncated("parent ref"))?;
    let parent_record = parent_ref & 0x0000_FFFF_FFFF_FFFF;
    let parent_seq = (parent_ref >> 48) as u16;

    let name_len = *v.get(64).ok_or(NtfsError::Truncated("name len"))? as usize;
    let namespace = *v.get(65).ok_or(NtfsError::Truncated("namespace"))?;

    let name_bytes_len = name_len
        .checked_mul(2)
        .ok_or(NtfsError::Truncated("name len overflow"))?;
    let name_end = 66usize
        .checked_add(name_bytes_len)
        .ok_or(NtfsError::Truncated("name offset overflow"))?;

    let name_utf16le = v
        .get(66..name_end)
        .ok_or(NtfsError::Truncated("file name"))?;

    Ok(FileNameAttr {
        parent_record,
        parent_seq,
        namespace,
        name_utf16le,
    })
}

/// Parses a reparse tag from a `$REPARSE_POINT` resident attribute value.
pub fn parse_reparse_tag(v: &[u8]) -> Result<u32, NtfsError> {
    get_u32(v, 0..4).ok_or(NtfsError::Truncated("reparse tag"))
}

/// An entry in an `$ATTRIBUTE_LIST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrListEntry {
    pub type_code: u32,
    pub start_vcn: u64,
    pub record: u64,
}

/// Parses an `$ATTRIBUTE_LIST` attribute value.
pub fn parse_attribute_list(v: &[u8]) -> Result<Vec<AttrListEntry>, NtfsError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < v.len() {
        if v.len() - offset < 4 {
            if v.get(offset..).is_some_and(|s| s.iter().all(|&b| b == 0)) {
                break;
            }
            return Err(NtfsError::Truncated("attribute list entry"));
        }

        let type_code =
            get_u32(v, offset..offset + 4).ok_or(NtfsError::Truncated("attr list type"))?;

        if type_code == 0 || type_code == ATTR_END {
            break;
        }

        let rec_len = get_u16(v, offset + 4..offset + 6)
            .ok_or(NtfsError::Truncated("attr list rec_len"))? as usize;

        if rec_len < 24 {
            return Err(NtfsError::BadAttribute);
        }

        let end = offset.checked_add(rec_len).ok_or(NtfsError::BadAttribute)?;
        if end > v.len() {
            return Err(NtfsError::Truncated("attr list rec_len overflow"));
        }

        let start_vcn = get_u64(v, offset + 8..offset + 16)
            .ok_or(NtfsError::Truncated("attr list start_vcn"))?;

        let base_ref = get_u64(v, offset + 16..offset + 24)
            .ok_or(NtfsError::Truncated("attr list base_ref"))?;
        let record = base_ref & 0x0000_FFFF_FFFF_FFFF;

        entries.push(AttrListEntry {
            type_code,
            start_vcn,
            record,
        });

        offset = end;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_std_info_valid_and_truncated() {
        let mut v = vec![0u8; 48];
        v[8..16].copy_from_slice(&123_456_789u64.to_le_bytes());
        v[24..32].copy_from_slice(&987_654_321u64.to_le_bytes());
        v[32..36].copy_from_slice(&0x20u32.to_le_bytes());

        let si = parse_standard_info(&v).unwrap();
        assert_eq!(si.mtime, 123_456_789);
        assert_eq!(si.atime, 987_654_321);
        assert_eq!(si.attributes, 0x20);

        assert!(matches!(
            parse_standard_info(&v[..35]),
            Err(NtfsError::Truncated(_))
        ));
    }

    #[test]
    fn parse_file_name_valid_and_truncated() {
        let name = "hello.txt";
        let name_u16: Vec<u16> = name.encode_utf16().collect();
        let mut v = vec![0u8; 66 + name_u16.len() * 2];
        let parent_ref: u64 = (2u64 << 48) | 42u64;
        v[0..8].copy_from_slice(&parent_ref.to_le_bytes());
        v[64] = name_u16.len() as u8;
        v[65] = 1; // Win32
        for (i, code) in name_u16.iter().enumerate() {
            v[66 + i * 2..66 + i * 2 + 2].copy_from_slice(&code.to_le_bytes());
        }

        let fn_attr = parse_file_name(&v).unwrap();
        assert_eq!(fn_attr.parent_record, 42);
        assert_eq!(fn_attr.parent_seq, 2);
        assert_eq!(fn_attr.namespace, 1);
        assert_eq!(fn_attr.name_utf16le.len(), name_u16.len() * 2);

        // Truncated buffer
        assert!(matches!(
            parse_file_name(&v[..65]),
            Err(NtfsError::Truncated(_))
        ));
        assert!(matches!(
            parse_file_name(&v[..70]),
            Err(NtfsError::Truncated(_))
        ));
    }

    #[test]
    fn parse_reparse_tag_valid_and_truncated() {
        let mut v = vec![0u8; 16];
        v[0..4].copy_from_slice(&0x8000_0017u32.to_le_bytes());
        assert_eq!(parse_reparse_tag(&v).unwrap(), 0x8000_0017);

        assert!(matches!(
            parse_reparse_tag(&v[..3]),
            Err(NtfsError::Truncated(_))
        ));
    }

    #[test]
    fn parse_attribute_list_truncated() {
        let mut v = vec![0u8; 16];
        v[0..4].copy_from_slice(&0x10u32.to_le_bytes());
        v[4..6].copy_from_slice(&32u16.to_le_bytes());
        assert!(matches!(
            parse_attribute_list(&v),
            Err(NtfsError::Truncated(_))
        ));
    }
}
