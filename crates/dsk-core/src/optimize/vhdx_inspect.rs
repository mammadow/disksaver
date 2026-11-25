#![forbid(unsafe_code)]

//! Read-only VHDX + ext4 inspector (P9.4): how much of a WSL or Docker virtual disk is actually
//! used inside, without booting the distro.
//!
//! Parses the VHDX region table, metadata (block size, virtual size, sector size), and Block
//! Allocation Table (MS-VHDX), then reads the ext4 superblock at guest offset 1024 (WSL and Docker
//! format the whole disk without a partition table). Every read is bounds-checked; malformed input
//! returns an error, never a panic (proptest below).

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

const BAT_GUID: [u8; 16] = guid(
    0x2DC2_7766,
    0xF623,
    0x4200,
    [0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08],
);
const METADATA_GUID: [u8; 16] = guid(
    0x8B7C_A206,
    0x4790,
    0x4B9A,
    [0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E],
);
const FILE_PARAMETERS_GUID: [u8; 16] = guid(
    0xCAA1_6737,
    0xFA36,
    0x4D43,
    [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B],
);
const VIRTUAL_DISK_SIZE_GUID: [u8; 16] = guid(
    0x2FA5_4224,
    0xCD1B,
    0x4876,
    [0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8],
);
const LOGICAL_SECTOR_SIZE_GUID: [u8; 16] = guid(
    0x8141_BF1D,
    0xA96F,
    0x4709,
    [0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F],
);

/// On-disk GUID layout: Data1/2/3 little-endian, Data4 as is.
const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

const PAYLOAD_FULLY_PRESENT: u64 = 6;
const PAYLOAD_PARTIALLY_PRESENT: u64 = 7;

/// File system found inside the virtual disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestFs {
    pub kind: String,
    pub total_bytes: u64,
    /// Blocks the file system counts as used (`blocks − free`), metadata included.
    pub used_bytes: u64,
    /// `used_bytes` minus the inode tables mkfs reserves up front. With lazy inode-table init
    /// (the WSL/Docker default) those tables are never written, so they occupy no VHDX blocks:
    /// a 1 TiB WSL disk reserves ~16 GiB of them.
    #[serde(default)]
    pub data_bytes: u64,
    /// The file system was unmounted cleanly, so its free count is current.
    pub clean: bool,
}

/// Result of inspecting a VHDX.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdxInspection {
    pub block_size: u64,
    pub virtual_size: u64,
    /// Payload blocks the host file actually stores.
    pub allocated_payload_bytes: u64,
    /// The VHDX log has unapplied entries (the disk was not detached cleanly).
    pub log_pending: bool,
    pub guest: Option<GuestFs>,
}

impl VhdxInspection {
    /// Upper bound of what trimming + compaction can return to the host: allocated payload minus
    /// what the guest uses. `None` when the guest file system is unknown.
    pub fn reclaimable_upper_bound(&self) -> Option<u64> {
        let g = self.guest.as_ref()?;
        Some(self.allocated_payload_bytes.saturating_sub(g.data_bytes))
    }
}

fn read_at<R: Read + Seek>(r: &mut R, off: u64, buf: &mut [u8]) -> Result<()> {
    r.seek(SeekFrom::Start(off))?;
    r.read_exact(buf)?;
    Ok(())
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn bad(msg: &str) -> DskError {
    DskError::Optimize(format!("not a valid VHDX: {msg}"))
}

/// Parsed geometry needed to map guest offsets.
struct Geometry {
    block_size: u64,
    virtual_size: u64,
    chunk_ratio: u64,
    bat_offset: u64,
    bat_len: u64,
}

fn parse_geometry<R: Read + Seek>(r: &mut R, file_len: u64) -> Result<(Geometry, bool)> {
    let mut sig = [0u8; 8];
    read_at(r, 0, &mut sig)?;
    if &sig != b"vhdxfile" {
        return Err(bad("missing file type identifier"));
    }

    // Two headers at 64 KiB and 128 KiB; the valid one with the higher sequence number wins.
    let mut log_pending = false;
    let mut best_seq = None;
    for off in [64 * KIB, 128 * KIB] {
        let mut h = [0u8; 64];
        if read_at(r, off, &mut h).is_err() || &h[0..4] != b"head" {
            continue;
        }
        let seq = u64_at(&h, 8).unwrap_or(0);
        if best_seq.is_none_or(|s| seq > s) {
            best_seq = Some(seq);
            log_pending = h[48..64].iter().any(|&b| b != 0);
        }
    }

    let mut rt = vec![0u8; 64 * KIB as usize];
    read_at(r, 192 * KIB, &mut rt)?;
    if &rt[0..4] != b"regi" {
        return Err(bad("missing region table"));
    }
    let count = u32_at(&rt, 8).unwrap_or(0) as usize;
    if count == 0 || count > 2047 {
        return Err(bad("region count out of range"));
    }
    let (mut bat, mut meta) = (None, None);
    for i in 0..count {
        let e = 16 + i * 32;
        let id = rt
            .get(e..e + 16)
            .ok_or_else(|| bad("region entry out of range"))?;
        let off = u64_at(&rt, e + 16).ok_or_else(|| bad("region entry"))?;
        let len = u64::from(u32_at(&rt, e + 24).ok_or_else(|| bad("region entry"))?);
        if off.checked_add(len).is_none_or(|end| end > file_len) || len == 0 {
            return Err(bad("region outside the file"));
        }
        if id == BAT_GUID {
            bat = Some((off, len));
        } else if id == METADATA_GUID {
            meta = Some((off, len));
        }
    }
    let (bat_offset, bat_len) = bat.ok_or_else(|| bad("no BAT region"))?;
    let (meta_off, meta_len) = meta.ok_or_else(|| bad("no metadata region"))?;
    if meta_len > 16 * MIB {
        return Err(bad("metadata region too large"));
    }
    let mut m = vec![0u8; meta_len as usize];
    read_at(r, meta_off, &mut m)?;
    if &m[0..8.min(m.len())] != b"metadata" {
        return Err(bad("bad metadata signature"));
    }
    let entries = u16_at(&m, 10).unwrap_or(0) as usize;
    if entries > 2047 {
        return Err(bad("metadata count out of range"));
    }
    let (mut block_size, mut virtual_size, mut sector) = (None, None, None);
    for i in 0..entries {
        let e = 32 + i * 32;
        let Some(id) = m.get(e..e + 16) else { break };
        let item_off = u32_at(&m, e + 16).unwrap_or(0) as usize;
        let item_len = u32_at(&m, e + 20).unwrap_or(0) as usize;
        let Some(item) = item_off
            .checked_add(item_len)
            .and_then(|end| m.get(item_off..end))
        else {
            continue;
        };
        if id == FILE_PARAMETERS_GUID {
            block_size = u32_at(item, 0).map(u64::from);
        } else if id == VIRTUAL_DISK_SIZE_GUID {
            virtual_size = u64_at(item, 0);
        } else if id == LOGICAL_SECTOR_SIZE_GUID {
            sector = u32_at(item, 0).map(u64::from);
        }
    }
    let block_size = block_size.ok_or_else(|| bad("no block size"))?;
    let virtual_size = virtual_size.ok_or_else(|| bad("no virtual size"))?;
    let sector = sector.ok_or_else(|| bad("no logical sector size"))?;
    if !(MIB..=256 * MIB).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(bad("block size out of range"));
    }
    if sector != 512 && sector != 4096 {
        return Err(bad("logical sector size must be 512 or 4096"));
    }
    if virtual_size == 0 || virtual_size > 64 * 1024 * 1024 * MIB {
        return Err(bad("virtual size out of range"));
    }
    let chunk_ratio = ((1u64 << 23) * sector) / block_size;
    if chunk_ratio == 0 {
        return Err(bad("chunk ratio is zero"));
    }
    Ok((
        Geometry {
            block_size,
            virtual_size,
            chunk_ratio,
            bat_offset,
            bat_len,
        },
        log_pending,
    ))
}

fn read_bat<R: Read + Seek>(r: &mut R, g: &Geometry) -> Result<Vec<u64>> {
    if g.bat_len > 512 * MIB {
        return Err(bad("BAT too large"));
    }
    let mut raw = vec![0u8; g.bat_len as usize];
    read_at(r, g.bat_offset, &mut raw)?;
    Ok(raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect())
}

/// Reads `buf.len()` guest bytes at `guest_off` (unallocated blocks read as zeros).
fn read_guest<R: Read + Seek>(
    r: &mut R,
    g: &Geometry,
    bat: &[u64],
    file_len: u64,
    guest_off: u64,
    buf: &mut [u8],
) -> Result<()> {
    let block = guest_off / g.block_size;
    let within = guest_off % g.block_size;
    if within + buf.len() as u64 > g.block_size {
        return Err(bad("guest read crosses a block"));
    }
    let idx = block + block / g.chunk_ratio;
    let entry = *bat
        .get(idx as usize)
        .ok_or_else(|| bad("guest offset beyond BAT"))?;
    let state = entry & 7;
    if state != PAYLOAD_FULLY_PRESENT && state != PAYLOAD_PARTIALLY_PRESENT {
        buf.fill(0);
        return Ok(());
    }
    let file_off = (entry >> 20)
        .checked_mul(MIB)
        .and_then(|o| o.checked_add(within))
        .ok_or_else(|| bad("payload offset overflow"))?;
    if file_off + buf.len() as u64 > file_len {
        return Err(bad("payload block outside the file"));
    }
    read_at(r, file_off, buf)
}

/// Parses an ext4 superblock (1024 bytes read at guest offset 1024).
pub fn parse_ext4_superblock(sb: &[u8]) -> Option<GuestFs> {
    if u16_at(sb, 0x38)? != 0xEF53 {
        return None;
    }
    let log = u32_at(sb, 0x18)?;
    if log > 6 {
        return None;
    }
    let block = 1024u64 << log;
    let incompat = u32_at(sb, 0x60)?;
    let is64 = incompat & 0x80 != 0;
    let hi = |o: usize| {
        if is64 {
            u64::from(u32_at(sb, o).unwrap_or(0)) << 32
        } else {
            0
        }
    };
    let blocks = u64::from(u32_at(sb, 0x04)?) | hi(0x150);
    let free = u64::from(u32_at(sb, 0x0C)?) | hi(0x158);
    if free > blocks {
        return None;
    }
    let inodes = u64::from(u32_at(sb, 0x00)?);
    let rev = u32_at(sb, 0x4C)?;
    let inode_size = if rev >= 1 {
        u64::from(u16_at(sb, 0x58)?)
    } else {
        128
    };
    let used = (blocks - free).saturating_mul(block);
    let inode_tables = inodes.saturating_mul(inode_size.clamp(128, 4096));
    Some(GuestFs {
        kind: "ext4".into(),
        total_bytes: blocks.saturating_mul(block),
        used_bytes: used,
        data_bytes: used.saturating_sub(inode_tables),
        clean: u16_at(sb, 0x3A)? & 1 == 1,
    })
}

/// Inspects a VHDX from any reader.
pub fn inspect_reader<R: Read + Seek>(r: &mut R, file_len: u64) -> Result<VhdxInspection> {
    let (g, log_pending) = parse_geometry(r, file_len)?;
    let bat = read_bat(r, &g)?;
    let blocks = g.virtual_size.div_ceil(g.block_size);
    let mut allocated = 0u64;
    for b in 0..blocks {
        let idx = (b + b / g.chunk_ratio) as usize;
        let Some(&e) = bat.get(idx) else { break };
        let s = e & 7;
        if s == PAYLOAD_FULLY_PRESENT || s == PAYLOAD_PARTIALLY_PRESENT {
            allocated += g.block_size;
        }
    }
    let mut sb = [0u8; 1024];
    let guest = read_guest(r, &g, &bat, file_len, 1024, &mut sb)
        .ok()
        .and_then(|()| parse_ext4_superblock(&sb));
    Ok(VhdxInspection {
        block_size: g.block_size,
        virtual_size: g.virtual_size,
        allocated_payload_bytes: allocated,
        log_pending,
        guest,
    })
}

/// Inspects a VHDX file on disk. Opens it read-only and shares only reads, so an attached
/// (running) disk fails with "in use" instead of yielding a half-written superblock.
pub fn inspect_vhdx(path: &Path) -> Result<VhdxInspection> {
    const FILE_SHARE_READ: u32 = 1;
    let mut f = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)?;
    let len = f.metadata()?.len();
    let mut r = std::io::BufReader::new(&mut f);
    inspect_reader(&mut r, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Builds a minimal VHDX: 1 MiB blocks, 512-byte sectors, 64 MiB virtual size, block 0 and
    /// block 5 present, an ext4 superblock (4 KiB blocks) at guest offset 1024.
    pub(super) fn synthetic_vhdx(
        blocks_total: u32,
        blocks_free: u32,
        log_pending: bool,
    ) -> Vec<u8> {
        let mut img = vec![0u8; 8 * MIB as usize];
        img[0..8].copy_from_slice(b"vhdxfile");
        for (off, seq) in [(64 * KIB, 1u64), (128 * KIB, 2u64)] {
            let o = off as usize;
            img[o..o + 4].copy_from_slice(b"head");
            img[o + 8..o + 16].copy_from_slice(&seq.to_le_bytes());
            if log_pending && seq == 2 {
                img[o + 48] = 0xAB;
            }
        }
        // Region table: BAT at 1 MiB (len 64 KiB), metadata at 2 MiB (len 64 KiB).
        let rt = (192 * KIB) as usize;
        img[rt..rt + 4].copy_from_slice(b"regi");
        img[rt + 8..rt + 12].copy_from_slice(&2u32.to_le_bytes());
        for (i, (id, off)) in [(BAT_GUID, MIB), (METADATA_GUID, 2 * MIB)]
            .iter()
            .enumerate()
        {
            let e = rt + 16 + i * 32;
            img[e..e + 16].copy_from_slice(id);
            img[e + 16..e + 24].copy_from_slice(&off.to_le_bytes());
            img[e + 24..e + 28].copy_from_slice(&(64 * KIB as u32).to_le_bytes());
        }
        // Metadata.
        let m = (2 * MIB) as usize;
        img[m..m + 8].copy_from_slice(b"metadata");
        img[m + 10..m + 12].copy_from_slice(&3u16.to_le_bytes());
        let items: [([u8; 16], Vec<u8>); 3] = [
            (
                FILE_PARAMETERS_GUID,
                [(MIB as u32).to_le_bytes(), 0u32.to_le_bytes()].concat(),
            ),
            (VIRTUAL_DISK_SIZE_GUID, (64 * MIB).to_le_bytes().to_vec()),
            (LOGICAL_SECTOR_SIZE_GUID, 512u32.to_le_bytes().to_vec()),
        ];
        let mut data_off = 4096usize;
        for (i, (id, data)) in items.iter().enumerate() {
            let e = m + 32 + i * 32;
            img[e..e + 16].copy_from_slice(id);
            img[e + 16..e + 20].copy_from_slice(&(data_off as u32).to_le_bytes());
            img[e + 20..e + 24].copy_from_slice(&(data.len() as u32).to_le_bytes());
            img[m + data_off..m + data_off + data.len()].copy_from_slice(data);
            data_off += 64;
        }
        // BAT: block 0 → file offset 4 MiB, block 5 → 5 MiB (FULLY_PRESENT).
        let bat = MIB as usize;
        for (block, mb) in [(0u64, 4u64), (5, 5)] {
            let entry = (mb << 20) | PAYLOAD_FULLY_PRESENT;
            let o = bat + block as usize * 8;
            img[o..o + 8].copy_from_slice(&entry.to_le_bytes());
        }
        // ext4 superblock at guest offset 1024 = file offset 4 MiB + 1024.
        let sb = (4 * MIB + 1024) as usize;
        img[sb + 0x04..sb + 0x08].copy_from_slice(&blocks_total.to_le_bytes());
        img[sb + 0x0C..sb + 0x10].copy_from_slice(&blocks_free.to_le_bytes());
        img[sb + 0x18..sb + 0x1C].copy_from_slice(&2u32.to_le_bytes()); // 4 KiB blocks
        img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        img[sb + 0x3A..sb + 0x3C].copy_from_slice(&1u16.to_le_bytes());
        img
    }

    #[test]
    fn reads_geometry_bat_and_ext4_usage() {
        // 16384 blocks of 4 KiB = 64 MiB, 16128 free → 1 MiB used.
        let img = synthetic_vhdx(16_384, 16_128, false);
        let len = img.len() as u64;
        let ins = inspect_reader(&mut Cursor::new(img), len).unwrap();
        assert_eq!(ins.block_size, MIB);
        assert_eq!(ins.virtual_size, 64 * MIB);
        assert_eq!(ins.allocated_payload_bytes, 2 * MIB);
        assert!(!ins.log_pending);
        let g = ins.guest.clone().unwrap();
        assert_eq!(
            (g.kind.as_str(), g.used_bytes, g.clean),
            ("ext4", MIB, true)
        );
        assert_eq!(g.data_bytes, MIB, "no inode tables declared");
        assert_eq!(ins.reclaimable_upper_bound(), Some(MIB));
    }

    #[test]
    fn flags_pending_log_and_rejects_garbage() {
        let img = synthetic_vhdx(100, 50, true);
        let len = img.len() as u64;
        assert!(
            inspect_reader(&mut Cursor::new(img), len)
                .unwrap()
                .log_pending
        );
        let mut junk = vec![0u8; 512 * 1024];
        junk[0..8].copy_from_slice(b"vhdxfile");
        assert!(inspect_reader(&mut Cursor::new(junk.clone()), junk.len() as u64).is_err());
        assert!(inspect_reader(&mut Cursor::new(vec![1u8; 10]), 10).is_err());
        // Free > total is not a valid superblock.
        let mut sb = [0u8; 1024];
        sb[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&5u32.to_le_bytes());
        sb[0x0C..0x10].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(parse_ext4_superblock(&sb), None);
    }

    #[test]
    fn subtracts_preallocated_inode_tables() {
        // 1 TiB file system (4 KiB blocks), 64 Mi inodes of 256 B = 16 GiB of tables,
        // 20 GiB counted as used → ~4 GiB of real data.
        let mut sb = [0u8; 1024];
        let blocks: u64 = (1u64 << 40) / 4096;
        let used: u64 = (20u64 << 30) / 4096;
        sb[0x00..0x04].copy_from_slice(&(64u32 << 20).to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&(blocks as u32).to_le_bytes());
        sb[0x0C..0x10].copy_from_slice(&((blocks - used) as u32).to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
        sb[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        sb[0x4C..0x50].copy_from_slice(&1u32.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());
        let g = parse_ext4_superblock(&sb).unwrap();
        assert_eq!(g.used_bytes, 20u64 << 30);
        assert_eq!(g.data_bytes, 4u64 << 30);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
        /// Never panics on arbitrary images, including corrupted valid ones.
        #[test]
        fn never_panics_on_corrupted_images(flips in proptest::collection::vec((0usize..(8 << 20), proptest::prelude::any::<u8>()), 0..64)) {
            let mut img = synthetic_vhdx(16_384, 100, false);
            for (pos, val) in flips {
                img[pos] = val;
            }
            let len = img.len() as u64;
            let _ = inspect_reader(&mut Cursor::new(img), len);
        }

        #[test]
        fn never_panics_on_random_superblocks(sb in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1100)) {
            let _ = parse_ext4_superblock(&sb);
        }
    }
}
