#![forbid(unsafe_code)]

use crate::error::NtfsError;

/// File record is in use.
pub const REC_IN_USE: u16 = 0x0001;
/// File record represents a directory.
pub const REC_DIRECTORY: u16 = 0x0002;

/// Fixed header of an NTFS file record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub seq: u16,
    pub link_count: u16,
    pub attrs_offset: u16,
    pub flags: u16,
    pub bytes_in_use: u32,
    pub base_record: u64,
}

/// Applies the Update Sequence Array (USA) fixups to a record buffer in-place.
///
/// The sector stride is calculated as `rec.len() / (usa_count - 1)`.
/// Returns [`NtfsError::BadSignature`] if the record does not start with `"FILE"`,
/// or [`NtfsError::FixupMismatch`] if any sector tail does not match the USN.
pub fn apply_fixups(rec: &mut [u8]) -> Result<(), NtfsError> {
    if rec.len() < 48 {
        return Err(NtfsError::Truncated("record header"));
    }

    if rec.get(0..4) != Some(b"FILE") {
        return Err(NtfsError::BadSignature);
    }

    let usa_offset = u16::from_le_bytes(
        rec.get(4..6)
            .ok_or(NtfsError::Truncated("usa_offset"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("usa_offset"))?,
    ) as usize;

    let usa_count = u16::from_le_bytes(
        rec.get(6..8)
            .ok_or(NtfsError::Truncated("usa_count"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("usa_count"))?,
    ) as usize;

    if usa_count <= 1 {
        return Err(NtfsError::Truncated("usa_count"));
    }

    let num_sectors = usa_count - 1;
    let total_usa_bytes = usa_count
        .checked_mul(2)
        .ok_or(NtfsError::Truncated("usa"))?;
    let usa_end = usa_offset
        .checked_add(total_usa_bytes)
        .ok_or(NtfsError::Truncated("usa"))?;
    if usa_end > rec.len() {
        return Err(NtfsError::Truncated("usa"));
    }

    let stride = rec.len() / num_sectors;
    if stride < 2 || !rec.len().is_multiple_of(num_sectors) {
        return Err(NtfsError::Truncated("stride"));
    }

    let usn_0 = *rec.get(usa_offset).ok_or(NtfsError::Truncated("usn"))?;
    let usn_1 = *rec.get(usa_offset + 1).ok_or(NtfsError::Truncated("usn"))?;

    // Step 1: verify all sector tails match USN
    for sector in 0..num_sectors {
        let tail_off = (sector + 1)
            .checked_mul(stride)
            .and_then(|v| v.checked_sub(2))
            .ok_or(NtfsError::Truncated("sector tail"))?;
        if tail_off + 2 > rec.len() {
            return Err(NtfsError::Truncated("sector tail"));
        }
        let b0 = rec[tail_off];
        let b1 = rec[tail_off + 1];
        if b0 != usn_0 || b1 != usn_1 {
            return Err(NtfsError::FixupMismatch { sector });
        }
    }

    // Step 2: restore original bytes from USA
    for sector in 0..num_sectors {
        let tail_off = (sector + 1) * stride - 2;
        let usa_entry_off = usa_offset + 2 * (sector + 1);
        rec[tail_off] = rec[usa_entry_off];
        rec[tail_off + 1] = rec[usa_entry_off + 1];
    }

    Ok(())
}

/// Parses the fixed header of an NTFS file record.
///
/// Returns [`NtfsError::BadSignature`] if the record does not start with `"FILE"`.
pub fn parse_header(rec: &[u8]) -> Result<RecordHeader, NtfsError> {
    if rec.len() < 42 {
        return Err(NtfsError::Truncated("record header"));
    }

    if rec.get(0..4) != Some(b"FILE") {
        return Err(NtfsError::BadSignature);
    }

    let seq = u16::from_le_bytes(
        rec.get(16..18)
            .ok_or(NtfsError::Truncated("seq"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("seq"))?,
    );

    let link_count = u16::from_le_bytes(
        rec.get(18..20)
            .ok_or(NtfsError::Truncated("link_count"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("link_count"))?,
    );

    let attrs_offset = u16::from_le_bytes(
        rec.get(20..22)
            .ok_or(NtfsError::Truncated("attrs_offset"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("attrs_offset"))?,
    );

    let flags = u16::from_le_bytes(
        rec.get(22..24)
            .ok_or(NtfsError::Truncated("flags"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("flags"))?,
    );

    let bytes_in_use = u32::from_le_bytes(
        rec.get(24..28)
            .ok_or(NtfsError::Truncated("bytes_in_use"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("bytes_in_use"))?,
    );

    let base_ref = u64::from_le_bytes(
        rec.get(32..40)
            .ok_or(NtfsError::Truncated("base_record"))?
            .try_into()
            .map_err(|_| NtfsError::Truncated("base_record"))?,
    );
    let base_record = base_ref & 0x0000_FFFF_FFFF_FFFF;

    Ok(RecordHeader {
        seq,
        link_count,
        attrs_offset,
        flags,
        bytes_in_use,
        base_record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs::testutil::RecordBuilder;

    #[test]
    fn fixups_restore_sector_tails() {
        let mut r = RecordBuilder::new(30, 1).build(1024);
        apply_fixups(&mut r).unwrap();
        assert_eq!(parse_header(&r).unwrap().seq, 1);
    }

    #[test]
    fn fixup_mismatch_detected() {
        let mut r = RecordBuilder::new(30, 1).build(1024);
        r[1022] ^= 0xFF;
        assert!(matches!(
            apply_fixups(&mut r),
            Err(NtfsError::FixupMismatch { sector: 1 })
        ));
    }

    #[test]
    fn baad_signature_rejected() {
        let mut r = vec![0u8; 1024];
        r[..4].copy_from_slice(b"BAAD");
        assert!(matches!(parse_header(&r), Err(NtfsError::BadSignature)));
    }

    #[test]
    fn record_short_buffer() {
        assert!(matches!(
            parse_header(&[0u8; 40]),
            Err(NtfsError::Truncated(_))
        ));
        let mut short = vec![0u8; 40];
        assert!(matches!(
            apply_fixups(&mut short),
            Err(NtfsError::Truncated(_))
        ));
    }

    #[test]
    fn record_header_fields() {
        let mut r = RecordBuilder::new(42, 7).dir().base(100).build(1024);
        apply_fixups(&mut r).unwrap();
        let h = parse_header(&r).unwrap();
        assert_eq!(h.seq, 7);
        assert_eq!(h.base_record, 100);
        assert_eq!(h.flags & REC_DIRECTORY, REC_DIRECTORY);
        assert_eq!(h.flags & REC_IN_USE, REC_IN_USE);
    }
}
