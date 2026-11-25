#![forbid(unsafe_code)]

use crate::error::NtfsError;

/// Parsed NTFS boot sector information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u32,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mft_record_size: u32,
    pub serial: u64,
}

impl BootSector {
    /// Returns the cluster size in bytes (`bytes_per_sector * sectors_per_cluster`).
    pub fn cluster_size(&self) -> u64 {
        (self.bytes_per_sector as u64) * (self.sectors_per_cluster as u64)
    }
}

/// Parses an NTFS boot sector (at least 512 bytes).
///
/// Returns [`NtfsError::BadBootSector`] if the buffer is malformed or not an NTFS boot sector.
pub fn parse_boot_sector(b: &[u8]) -> Result<BootSector, NtfsError> {
    if b.len() < 512 {
        return Err(NtfsError::BadBootSector);
    }

    if b.get(510..512) != Some(&[0x55, 0xAA]) {
        return Err(NtfsError::BadBootSector);
    }

    if b.get(3..11) != Some(b"NTFS    ") {
        return Err(NtfsError::BadBootSector);
    }

    let bps_bytes = b.get(0x0B..0x0D).ok_or(NtfsError::BadBootSector)?;
    let bytes_per_sector =
        u16::from_le_bytes(bps_bytes.try_into().map_err(|_| NtfsError::BadBootSector)?);
    if bytes_per_sector < 512 || !bytes_per_sector.is_power_of_two() {
        return Err(NtfsError::BadBootSector);
    }

    let spc_raw = *b.get(0x0D).ok_or(NtfsError::BadBootSector)?;
    let sectors_per_cluster = if spc_raw > 0x80 {
        let shift = 256 - spc_raw as u32;
        if shift >= 31 {
            return Err(NtfsError::BadBootSector);
        }
        1u32 << shift
    } else if spc_raw > 0 {
        let spc = spc_raw as u32;
        if !spc.is_power_of_two() {
            return Err(NtfsError::BadBootSector);
        }
        spc
    } else {
        return Err(NtfsError::BadBootSector);
    };

    let ts_bytes = b.get(0x28..0x30).ok_or(NtfsError::BadBootSector)?;
    let total_sectors =
        u64::from_le_bytes(ts_bytes.try_into().map_err(|_| NtfsError::BadBootSector)?);

    let lcn_bytes = b.get(0x30..0x38).ok_or(NtfsError::BadBootSector)?;
    let mft_lcn = u64::from_le_bytes(lcn_bytes.try_into().map_err(|_| NtfsError::BadBootSector)?);

    let cpr_raw = *b.get(0x40).ok_or(NtfsError::BadBootSector)? as i8;
    let mft_record_size = if cpr_raw < 0 {
        let shift = cpr_raw.unsigned_abs() as u32;
        if shift >= 31 {
            return Err(NtfsError::BadBootSector);
        }
        1u32 << shift
    } else if cpr_raw > 0 {
        let cluster_size = (bytes_per_sector as u64)
            .checked_mul(sectors_per_cluster as u64)
            .ok_or(NtfsError::BadBootSector)?;
        let rec_size = (cpr_raw as u64)
            .checked_mul(cluster_size)
            .ok_or(NtfsError::BadBootSector)?;
        u32::try_from(rec_size).map_err(|_| NtfsError::BadBootSector)?
    } else {
        return Err(NtfsError::BadBootSector);
    };

    if mft_record_size < 512 || !mft_record_size.is_power_of_two() {
        return Err(NtfsError::BadBootSector);
    }

    let serial_bytes = b.get(0x48..0x50).ok_or(NtfsError::BadBootSector)?;
    let serial = u64::from_le_bytes(
        serial_bytes
            .try_into()
            .map_err(|_| NtfsError::BadBootSector)?,
    );

    Ok(BootSector {
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors,
        mft_lcn,
        mft_record_size,
        serial,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(bytes_per_sector: u16, sectors_per_cluster: u8, clusters_per_record: i8) -> Vec<u8> {
        sample_spc(bytes_per_sector, sectors_per_cluster, clusters_per_record)
    }

    fn sample_spc(bytes_per_sector: u16, spc: u8, clusters_per_record: i8) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&bytes_per_sector.to_le_bytes());
        b[0x0D] = spc;
        b[0x28..0x30].copy_from_slice(&100_000u64.to_le_bytes());
        b[0x30..0x38].copy_from_slice(&4u64.to_le_bytes());
        b[0x40] = clusters_per_record as u8;
        b[0x48..0x50].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    fn fat_sector() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[3..11].copy_from_slice(b"MSDOS5.0");
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    #[test]
    fn boot_parses_common_volume() {
        let b = parse_boot_sector(&sample(512, 8, -10)).unwrap();
        assert_eq!(b.cluster_size(), 4096);
        assert_eq!(b.mft_record_size, 1024);
        assert_eq!(b.total_sectors, 100_000);
        assert_eq!(b.mft_lcn, 4);
        assert_eq!(b.serial, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn boot_negative_sectors_per_cluster() {
        assert_eq!(
            parse_boot_sector(&sample_spc(512, 0xF4, -10))
                .unwrap()
                .cluster_size(),
            2 * 1024 * 1024
        );
    }

    #[test]
    fn boot_rejects_non_ntfs() {
        assert!(matches!(
            parse_boot_sector(&fat_sector()),
            Err(NtfsError::BadBootSector)
        ));
    }

    #[test]
    fn boot_rejects_short_buffer() {
        assert!(matches!(
            parse_boot_sector(&[0u8; 511]),
            Err(NtfsError::BadBootSector)
        ));
    }

    #[test]
    fn boot_positive_clusters_per_record() {
        let mut b = sample(512, 8, 1);
        b[0x40] = 2; // 2 clusters per record = 2 * 4096 = 8192
        let bs = parse_boot_sector(&b).unwrap();
        assert_eq!(bs.mft_record_size, 8192);
    }

    #[test]
    fn boot_cpr_min_i8_does_not_panic() {
        let mut b = sample(512, 8, -10);
        b[0x40] = 0x80; // 0x80 = -128i8, unsigned_abs() = 128 >= 31 -> BadBootSector
        assert!(matches!(
            parse_boot_sector(&b),
            Err(NtfsError::BadBootSector)
        ));
    }
}
