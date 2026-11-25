#![forbid(unsafe_code)]

use crate::error::NtfsError;

/// A contiguous run of clusters on disk.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Run {
    /// Logical Cluster Number (LCN). `None` represents a sparse run.
    pub lcn: Option<u64>,
    /// Number of clusters in this run.
    pub len: u64,
}

/// Decodes an NTFS data run list into a vector of [`Run`]s.
///
/// Parsing terminates when a `0x00` header byte is encountered or at buffer end.
/// Returns [`NtfsError::BadRunList`] if any run is malformed, truncated, or causes LCN overflow.
pub fn decode_runs(b: &[u8]) -> Result<Vec<Run>, NtfsError> {
    let mut runs = Vec::new();
    let mut offset = 0;
    let mut current_lcn: i64 = 0;

    while offset < b.len() {
        let header = *b.get(offset).ok_or(NtfsError::BadRunList)?;
        offset += 1;
        if header == 0 {
            break;
        }

        let len_size = (header & 0x0F) as usize;
        let off_size = ((header >> 4) & 0x0F) as usize;

        if len_size == 0 || len_size > 8 || off_size > 8 {
            return Err(NtfsError::BadRunList);
        }

        let len_bytes = b
            .get(offset..offset + len_size)
            .ok_or(NtfsError::BadRunList)?;
        offset += len_size;
        let mut len_buf = [0u8; 8];
        len_buf[..len_size].copy_from_slice(len_bytes);
        let len = u64::from_le_bytes(len_buf);
        if len == 0 {
            return Err(NtfsError::BadRunList);
        }

        let lcn = if off_size == 0 {
            None
        } else {
            let off_bytes = b
                .get(offset..offset + off_size)
                .ok_or(NtfsError::BadRunList)?;
            offset += off_size;
            let is_neg = (off_bytes[off_size - 1] & 0x80) != 0;
            let mut off_buf = if is_neg { [0xFFu8; 8] } else { [0u8; 8] };
            off_buf[..off_size].copy_from_slice(off_bytes);
            let delta = i64::from_le_bytes(off_buf);
            current_lcn = current_lcn
                .checked_add(delta)
                .ok_or(NtfsError::BadRunList)?;
            if current_lcn < 0 {
                return Err(NtfsError::BadRunList);
            }
            Some(current_lcn as u64)
        };

        runs.push(Run { lcn, len });
    }

    Ok(runs)
}

/// Computes the total number of allocated (non-sparse) clusters in a run list without allocating memory.
///
/// Returns [`NtfsError::BadRunList`] if any run is malformed or truncated.
pub fn allocated_clusters(b: &[u8]) -> Result<u64, NtfsError> {
    let mut total: u64 = 0;
    let mut offset = 0;

    while offset < b.len() {
        let header = *b.get(offset).ok_or(NtfsError::BadRunList)?;
        offset += 1;
        if header == 0 {
            break;
        }

        let len_size = (header & 0x0F) as usize;
        let off_size = ((header >> 4) & 0x0F) as usize;

        if len_size == 0 || len_size > 8 || off_size > 8 {
            return Err(NtfsError::BadRunList);
        }

        let len_bytes = b
            .get(offset..offset + len_size)
            .ok_or(NtfsError::BadRunList)?;
        offset += len_size;
        let mut len_buf = [0u8; 8];
        len_buf[..len_size].copy_from_slice(len_bytes);
        let len = u64::from_le_bytes(len_buf);
        if len == 0 {
            return Err(NtfsError::BadRunList);
        }

        if off_size > 0 {
            if offset + off_size > b.len() {
                return Err(NtfsError::BadRunList);
            }
            offset += off_size;
            total = total.checked_add(len).ok_or(NtfsError::BadRunList)?;
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs::testutil::encode_runs;

    #[test]
    fn runs_single() {
        assert_eq!(
            decode_runs(&[0x21, 0x18, 0x34, 0x56, 0x00]).unwrap(),
            vec![Run {
                lcn: Some(0x5634),
                len: 0x18
            }]
        );
    }

    #[test]
    fn runs_negative_delta() {
        assert_eq!(
            decode_runs(&[0x11, 0x30, 0x60, 0x11, 0x10, 0xF0, 0x00]).unwrap()[1],
            Run {
                lcn: Some(0x50),
                len: 0x10
            }
        );
    }

    #[test]
    fn runs_sparse() {
        assert_eq!(
            decode_runs(&[0x01, 0x08, 0x00]).unwrap(),
            vec![Run { lcn: None, len: 8 }]
        );
    }

    #[test]
    fn runs_truncated() {
        assert!(matches!(
            decode_runs(&[0x21, 0x18]),
            Err(NtfsError::BadRunList)
        ));
    }

    #[test]
    fn allocated_ignores_sparse() {
        assert_eq!(
            allocated_clusters(&encode_runs(&[
                Run {
                    lcn: None,
                    len: 1000
                },
                Run {
                    lcn: Some(9),
                    len: 1
                }
            ]))
            .unwrap(),
            1
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let rs = vec![
            Run {
                lcn: Some(100),
                len: 3,
            },
            Run { lcn: None, len: 7 },
            Run {
                lcn: Some(40),
                len: 2,
            },
        ];
        assert_eq!(decode_runs(&encode_runs(&rs)).unwrap(), rs);
    }

    #[test]
    fn runs_empty() {
        assert_eq!(decode_runs(&[]).unwrap(), vec![]);
        assert_eq!(decode_runs(&[0x00]).unwrap(), vec![]);
        assert_eq!(allocated_clusters(&[]).unwrap(), 0);
        assert_eq!(allocated_clusters(&[0x00]).unwrap(), 0);
    }

    #[test]
    fn runs_zero_len_rejected() {
        assert!(matches!(
            decode_runs(&[0x11, 0x00, 0x10]),
            Err(NtfsError::BadRunList)
        ));
        assert!(matches!(
            allocated_clusters(&[0x11, 0x00, 0x10]),
            Err(NtfsError::BadRunList)
        ));
    }

    #[test]
    fn allocated_multi_runs() {
        let runs = [
            Run {
                lcn: Some(10),
                len: 5,
            },
            Run { lcn: None, len: 20 },
            Run {
                lcn: Some(50),
                len: 15,
            },
        ];
        let encoded = encode_runs(&runs);
        assert_eq!(allocated_clusters(&encoded).unwrap(), 20);
    }
}
