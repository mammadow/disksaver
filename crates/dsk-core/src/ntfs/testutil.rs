#![forbid(unsafe_code)]

use crate::error::{NtfsError, Result};
use crate::ntfs::boot::BootSector;
use crate::ntfs::mft::SectorReader;
use crate::ntfs::runs::Run;
use crate::ntfs::{
    ATTR_ATTRIBUTE_LIST, ATTR_DATA, ATTR_END, ATTR_FILE_NAME, ATTR_INDEX_ALLOCATION,
    ATTR_REPARSE_POINT, ATTR_STANDARD_INFO, REC_IN_USE,
};

/// Encodes a slice of [`Run`]s into standard NTFS data run list format.
pub(crate) fn encode_runs(runs: &[Run]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut last_lcn: u64 = 0;

    for run in runs {
        let len_bytes = run.len.to_le_bytes();
        let mut len_size = 8;
        for k in (1..8).rev() {
            if len_bytes[k..].iter().all(|&b| b == 0) {
                len_size = k;
            } else {
                break;
            }
        }

        let (off_size, delta_bytes) = match run.lcn {
            None => (0, [0u8; 8]),
            Some(cur_lcn) => {
                let delta = (cur_lcn as i64) - (last_lcn as i64);
                last_lcn = cur_lcn;
                let d_bytes = delta.to_le_bytes();
                let mut sz = 8;
                for k in 1..8 {
                    let is_neg = (d_bytes[k - 1] & 0x80) != 0;
                    let pad = if is_neg { 0xFF } else { 0x00 };
                    if d_bytes[k..].iter().all(|&b| b == pad) {
                        sz = k;
                        break;
                    }
                }
                (sz, d_bytes)
            }
        };

        let header = ((off_size as u8) << 4) | (len_size as u8);
        out.push(header);
        out.extend_from_slice(&len_bytes[..len_size]);
        if off_size > 0 {
            out.extend_from_slice(&delta_bytes[..off_size]);
        }
    }

    out.push(0x00);
    out
}

#[allow(dead_code)]
enum AttrSpec {
    StandardInfo {
        mtime: u64,
        atime: u64,
        attrs: u32,
    },
    FileName {
        parent_rec: u64,
        parent_seq: u16,
        namespace: u8,
        name: String,
    },
    DataResident {
        name: Option<String>,
        len: usize,
    },
    DataNonResident {
        name: Option<String>,
        start_vcn: u64,
        data_size: u64,
        flags: u16,
        runs: Vec<Run>,
    },
    IndexAllocation {
        runs: Vec<Run>,
    },
    AttributeList {
        entries: Vec<(u32, u64, u64)>,
    },
    AttributeListNonResident {
        runs: Vec<Run>,
    },
    Reparse {
        tag: u32,
    },
}

/// Helper for constructing NTFS file records with authentic headers, attributes,
/// and Update Sequence Array (USA) fixups for unit and integration testing.
#[allow(dead_code)]
pub(crate) struct RecordBuilder {
    record_no: u64,
    seq: u16,
    flags: u16,
    base_record: u64,
    link_count: u16,
    attrs: Vec<AttrSpec>,
}

#[allow(dead_code)]
impl RecordBuilder {
    pub(crate) fn new(record_no: u64, seq: u16) -> Self {
        Self {
            record_no,
            seq,
            flags: REC_IN_USE,
            base_record: 0,
            link_count: 0,
            attrs: Vec::new(),
        }
    }

    pub(crate) fn dir(mut self) -> Self {
        self.flags |= crate::ntfs::REC_DIRECTORY;
        self
    }

    pub(crate) fn base(mut self, rec: u64) -> Self {
        self.base_record = rec;
        self
    }

    pub(crate) fn not_in_use(mut self) -> Self {
        self.flags &= !REC_IN_USE;
        self
    }

    pub(crate) fn std_info(mut self, mtime: u64, atime: u64, attrs: u32) -> Self {
        self.attrs.push(AttrSpec::StandardInfo {
            mtime,
            atime,
            attrs,
        });
        self
    }

    pub(crate) fn file_name(
        mut self,
        parent_rec: u64,
        parent_seq: u16,
        namespace: u8,
        name: &str,
    ) -> Self {
        self.link_count += 1;
        self.attrs.push(AttrSpec::FileName {
            parent_rec,
            parent_seq,
            namespace,
            name: name.to_string(),
        });
        self
    }

    pub(crate) fn data_resident(mut self, name: Option<&str>, len: usize) -> Self {
        self.attrs.push(AttrSpec::DataResident {
            name: name.map(ToString::to_string),
            len,
        });
        self
    }

    pub(crate) fn data_nonresident(
        mut self,
        name: Option<&str>,
        start_vcn: u64,
        data_size: u64,
        flags: u16,
        runs: &[Run],
    ) -> Self {
        self.attrs.push(AttrSpec::DataNonResident {
            name: name.map(ToString::to_string),
            start_vcn,
            data_size,
            flags,
            runs: runs.to_vec(),
        });
        self
    }

    pub(crate) fn index_allocation(mut self, runs: &[Run]) -> Self {
        self.attrs.push(AttrSpec::IndexAllocation {
            runs: runs.to_vec(),
        });
        self
    }

    pub(crate) fn attribute_list(mut self, entries: &[(u32, u64, u64)]) -> Self {
        self.attrs.push(AttrSpec::AttributeList {
            entries: entries.to_vec(),
        });
        self
    }

    pub(crate) fn attribute_list_nonresident(mut self, runs: &[Run]) -> Self {
        self.attrs.push(AttrSpec::AttributeListNonResident {
            runs: runs.to_vec(),
        });
        self
    }

    pub(crate) fn reparse(mut self, tag: u32) -> Self {
        self.attrs.push(AttrSpec::Reparse { tag });
        self
    }

    pub(crate) fn build(self, record_size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; record_size];
        buf[0..4].copy_from_slice(b"FILE");

        let usa_offset = 48u16;
        buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());

        let num_sectors = record_size / 512;
        let usa_count = (num_sectors + 1) as u16;
        buf[6..8].copy_from_slice(&usa_count.to_le_bytes());

        buf[16..18].copy_from_slice(&self.seq.to_le_bytes());
        let link_count = if self.link_count == 0 {
            1
        } else {
            self.link_count
        };
        buf[18..20].copy_from_slice(&link_count.to_le_bytes());

        let usa_end = (usa_offset as usize) + (usa_count as usize) * 2;
        let attrs_offset = ((usa_end + 7) & !7) as u16;
        buf[20..22].copy_from_slice(&attrs_offset.to_le_bytes());
        buf[22..24].copy_from_slice(&self.flags.to_le_bytes());
        buf[28..32].copy_from_slice(&(record_size as u32).to_le_bytes());
        buf[32..40].copy_from_slice(&(self.base_record & 0x0000_FFFF_FFFF_FFFF).to_le_bytes());
        buf[40..42].copy_from_slice(&(self.attrs.len() as u16).to_le_bytes());
        buf[44..48].copy_from_slice(&(self.record_no as u32).to_le_bytes());

        let mut cur_offset = attrs_offset as usize;
        for (instance, attr) in self.attrs.iter().enumerate() {
            let encoded = encode_attribute(attr, instance as u16);
            assert!(
                cur_offset + encoded.len() + 8 <= record_size,
                "record buffer overflow in RecordBuilder"
            );
            buf[cur_offset..cur_offset + encoded.len()].copy_from_slice(&encoded);
            cur_offset += encoded.len();
        }

        // Write ATTR_END marker (0xFFFF_FFFF) aligned to 8 bytes
        buf[cur_offset..cur_offset + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        cur_offset += 8;

        let bytes_in_use = cur_offset as u32;
        buf[24..28].copy_from_slice(&bytes_in_use.to_le_bytes());

        // Apply USA fixups
        let usn: u16 = 0x0001;
        let usa_start = usa_offset as usize;
        buf[usa_start..usa_start + 2].copy_from_slice(&usn.to_le_bytes());

        for sector in 0..num_sectors {
            let tail_off = (sector + 1) * 512 - 2;
            let usa_entry_off = usa_start + 2 * (sector + 1);
            buf[usa_entry_off] = buf[tail_off];
            buf[usa_entry_off + 1] = buf[tail_off + 1];
            buf[tail_off] = (usn & 0xFF) as u8;
            buf[tail_off + 1] = (usn >> 8) as u8;
        }

        buf
    }

    pub(crate) fn record_no(&self) -> u64 {
        self.record_no
    }
}

fn encode_resident(
    type_code: u32,
    instance: u16,
    flags: u16,
    name: Option<&str>,
    value: &[u8],
) -> Vec<u8> {
    let name_utf16: Option<Vec<u16>> = name.map(|s| s.encode_utf16().collect());
    let name_len = name_utf16.as_ref().map_or(0, |v| v.len()) as u8;
    let name_offset = if name_len > 0 { 24u16 } else { 0u16 };

    let value_offset = if name_len > 0 {
        ((24 + (name_len as usize) * 2 + 7) & !7) as u16
    } else {
        24u16
    };

    let total_len = ((value_offset as usize + value.len() + 7) & !7) as u32;
    let mut out = vec![0u8; total_len as usize];

    out[0..4].copy_from_slice(&type_code.to_le_bytes());
    out[4..8].copy_from_slice(&total_len.to_le_bytes());
    out[8] = 0; // non_resident = 0
    out[9] = name_len;
    out[10..12].copy_from_slice(&name_offset.to_le_bytes());
    out[12..14].copy_from_slice(&flags.to_le_bytes());
    out[14..16].copy_from_slice(&instance.to_le_bytes());
    out[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    out[20..22].copy_from_slice(&value_offset.to_le_bytes());

    if let Some(n_u16) = name_utf16 {
        let n_start = name_offset as usize;
        for (i, code) in n_u16.iter().enumerate() {
            out[n_start + i * 2..n_start + i * 2 + 2].copy_from_slice(&code.to_le_bytes());
        }
    }

    let val_start = value_offset as usize;
    out[val_start..val_start + value.len()].copy_from_slice(value);

    out
}

#[allow(clippy::too_many_arguments)]
fn encode_nonresident(
    type_code: u32,
    instance: u16,
    flags: u16,
    name: Option<&str>,
    start_vcn: u64,
    last_vcn: u64,
    allocated_size: u64,
    data_size: u64,
    initialized_size: u64,
    runs_bytes: &[u8],
) -> Vec<u8> {
    let name_utf16: Option<Vec<u16>> = name.map(|s| s.encode_utf16().collect());
    let name_len = name_utf16.as_ref().map_or(0, |v| v.len()) as u8;
    let name_offset = if name_len > 0 { 64u16 } else { 0u16 };

    let runs_offset = if name_len > 0 {
        ((64 + (name_len as usize) * 2 + 7) & !7) as u16
    } else {
        64u16
    };

    let total_len = ((runs_offset as usize + runs_bytes.len() + 7) & !7) as u32;
    let mut out = vec![0u8; total_len as usize];

    out[0..4].copy_from_slice(&type_code.to_le_bytes());
    out[4..8].copy_from_slice(&total_len.to_le_bytes());
    out[8] = 1; // non_resident = 1
    out[9] = name_len;
    out[10..12].copy_from_slice(&name_offset.to_le_bytes());
    out[12..14].copy_from_slice(&flags.to_le_bytes());
    out[14..16].copy_from_slice(&instance.to_le_bytes());
    out[16..24].copy_from_slice(&start_vcn.to_le_bytes());
    out[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    out[32..34].copy_from_slice(&runs_offset.to_le_bytes());
    // 34..36 compression_unit = 0
    // 36..40 padding = 0
    out[40..48].copy_from_slice(&allocated_size.to_le_bytes());
    out[48..56].copy_from_slice(&data_size.to_le_bytes());
    out[56..64].copy_from_slice(&initialized_size.to_le_bytes());

    if let Some(n_u16) = name_utf16 {
        let n_start = name_offset as usize;
        for (i, code) in n_u16.iter().enumerate() {
            out[n_start + i * 2..n_start + i * 2 + 2].copy_from_slice(&code.to_le_bytes());
        }
    }

    let runs_start = runs_offset as usize;
    out[runs_start..runs_start + runs_bytes.len()].copy_from_slice(runs_bytes);

    out
}

fn encode_attribute(attr: &AttrSpec, instance: u16) -> Vec<u8> {
    match attr {
        AttrSpec::StandardInfo {
            mtime,
            atime,
            attrs,
        } => {
            let mut val = vec![0u8; 48];
            val[8..16].copy_from_slice(&mtime.to_le_bytes());
            val[16..24].copy_from_slice(&mtime.to_le_bytes()); // mft_mtime
            val[24..32].copy_from_slice(&atime.to_le_bytes());
            val[32..36].copy_from_slice(&attrs.to_le_bytes());
            encode_resident(ATTR_STANDARD_INFO, instance, 0, None, &val)
        }
        AttrSpec::FileName {
            parent_rec,
            parent_seq,
            namespace,
            name,
        } => {
            let name_u16: Vec<u16> = name.encode_utf16().collect();
            let val_len = 66 + name_u16.len() * 2;
            let mut val = vec![0u8; val_len];
            let parent_ref = ((*parent_seq as u64) << 48) | (*parent_rec & 0x0000_FFFF_FFFF_FFFF);
            val[0..8].copy_from_slice(&parent_ref.to_le_bytes());
            val[64] = name_u16.len() as u8;
            val[65] = *namespace;
            for (i, code) in name_u16.iter().enumerate() {
                val[66 + i * 2..66 + i * 2 + 2].copy_from_slice(&code.to_le_bytes());
            }
            encode_resident(ATTR_FILE_NAME, instance, 0, None, &val)
        }
        AttrSpec::DataResident { name, len } => {
            let val = vec![0u8; *len];
            encode_resident(ATTR_DATA, instance, 0, name.as_deref(), &val)
        }
        AttrSpec::DataNonResident {
            name,
            start_vcn,
            data_size,
            flags,
            runs,
        } => {
            let runs_bytes = encode_runs(runs);
            let total_clusters: u64 = runs.iter().map(|r| r.len).sum();
            let last_vcn = if total_clusters == 0 {
                *start_vcn
            } else {
                start_vcn + total_clusters - 1
            };
            let allocated_clusters: u64 =
                runs.iter().filter(|r| r.lcn.is_some()).map(|r| r.len).sum();
            let allocated_size = allocated_clusters * 4096;
            encode_nonresident(
                ATTR_DATA,
                instance,
                *flags,
                name.as_deref(),
                *start_vcn,
                last_vcn,
                allocated_size,
                *data_size,
                *data_size,
                &runs_bytes,
            )
        }
        AttrSpec::IndexAllocation { runs } => {
            let runs_bytes = encode_runs(runs);
            let total_clusters: u64 = runs.iter().map(|r| r.len).sum();
            let last_vcn = if total_clusters == 0 {
                0
            } else {
                total_clusters - 1
            };
            let allocated_clusters: u64 =
                runs.iter().filter(|r| r.lcn.is_some()).map(|r| r.len).sum();
            let allocated_size = allocated_clusters * 4096;
            let data_size = total_clusters * 4096;
            encode_nonresident(
                ATTR_INDEX_ALLOCATION,
                instance,
                0,
                Some("$I30"),
                0,
                last_vcn,
                allocated_size,
                data_size,
                data_size,
                &runs_bytes,
            )
        }
        AttrSpec::AttributeList { entries } => {
            let mut val = vec![0u8; entries.len() * 32];
            for (i, &(type_code, start_vcn, record)) in entries.iter().enumerate() {
                let off = i * 32;
                val[off..off + 4].copy_from_slice(&type_code.to_le_bytes());
                val[off + 4..off + 6].copy_from_slice(&32u16.to_le_bytes());
                val[off + 6] = 0; // name_len = 0
                val[off + 7] = 26; // name_offset = 26
                val[off + 8..off + 16].copy_from_slice(&start_vcn.to_le_bytes());
                let base_ref = record & 0x0000_FFFF_FFFF_FFFF;
                val[off + 16..off + 24].copy_from_slice(&base_ref.to_le_bytes());
            }
            encode_resident(ATTR_ATTRIBUTE_LIST, instance, 0, None, &val)
        }
        AttrSpec::AttributeListNonResident { runs } => {
            let runs_bytes = encode_runs(runs);
            let total_clusters: u64 = runs.iter().map(|r| r.len).sum();
            let last_vcn = if total_clusters == 0 {
                0
            } else {
                total_clusters - 1
            };
            let allocated_clusters: u64 =
                runs.iter().filter(|r| r.lcn.is_some()).map(|r| r.len).sum();
            let allocated_size = allocated_clusters * 4096;
            let data_size = total_clusters * 4096;
            encode_nonresident(
                ATTR_ATTRIBUTE_LIST,
                instance,
                0,
                None,
                0,
                last_vcn,
                allocated_size,
                data_size,
                data_size,
                &runs_bytes,
            )
        }
        AttrSpec::Reparse { tag } => {
            let mut val = vec![0u8; 16];
            val[0..4].copy_from_slice(&tag.to_le_bytes());
            encode_resident(ATTR_REPARSE_POINT, instance, 0, None, &val)
        }
    }
}

pub(crate) fn rich_record() -> Vec<u8> {
    let runs = [Run {
        lcn: Some(50),
        len: 4,
    }];
    RecordBuilder::new(100, 2)
        .dir()
        .base(5)
        .std_info(123_456_789, 987_654_321, 0x20)
        .file_name(5, 1, 1, "test.txt")
        .data_resident(Some("resident_stream"), 64)
        .data_nonresident(Some("nonresident_stream"), 0, 16384, 0, &runs)
        .index_allocation(&runs)
        .attribute_list(&[(0x80, 0, 100)])
        .reparse(0x8000_0017)
        .build(1024)
}

#[allow(dead_code)]
pub(crate) struct MemReader(pub Vec<u8>);

impl SectorReader for MemReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let off = offset as usize;
        let end = off
            .checked_add(buf.len())
            .ok_or(NtfsError::Truncated("read_at overflow"))?;
        if end > self.0.len() {
            return Err(NtfsError::Truncated("read_at beyond EOF").into());
        }
        buf.copy_from_slice(&self.0[off..end]);
        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) struct ImageBuilder {
    cluster_size: u64,
    record_size: u32,
    mft_extents: Vec<(u64, u64)>,
    fragmented_via_attr_list: bool,
    records: std::collections::BTreeMap<u64, Vec<u8>>,
}

#[allow(dead_code)]
impl ImageBuilder {
    pub(crate) fn new(cluster_size: u64, record_size: u32) -> Self {
        Self {
            cluster_size,
            record_size,
            mft_extents: Vec::new(),
            fragmented_via_attr_list: false,
            records: std::collections::BTreeMap::new(),
        }
    }

    pub(crate) fn mft_extents(mut self, extents: &[(u64, u64)]) -> Self {
        self.mft_extents = extents.to_vec();
        self
    }

    pub(crate) fn fragmented_via_attr_list(mut self) -> Self {
        self.fragmented_via_attr_list = true;
        self
    }

    pub(crate) fn record(mut self, rec: Vec<u8>) -> Self {
        if rec.len() >= 48 {
            let rec_no = u32::from_le_bytes([rec[44], rec[45], rec[46], rec[47]]) as u64;
            self.records.insert(rec_no, rec);
        }
        self
    }

    pub(crate) fn record_at(mut self, rec_no: u64, rec: Vec<u8>) -> Self {
        self.records.insert(rec_no, rec);
        self
    }

    pub(crate) fn build(mut self) -> (Vec<u8>, BootSector) {
        let max_rec = self.records.keys().copied().max().unwrap_or(5).max(5);
        if self.mft_extents.is_empty() {
            let records_needed = max_rec + 1;
            let bytes_needed = records_needed * (self.record_size as u64);
            let clusters_needed = bytes_needed.div_ceil(self.cluster_size);
            self.mft_extents = vec![(4, clusters_needed.max(16))];
        }

        if !self.records.contains_key(&0) {
            let total_clusters: u64 = self.mft_extents.iter().map(|(_, c)| *c).sum();
            let total_data_size = total_clusters * self.cluster_size;

            if self.fragmented_via_attr_list && self.mft_extents.len() > 1 {
                let ext_rec_no = (1..16)
                    .find(|n| !self.records.contains_key(n) && *n != 5)
                    .unwrap_or(15);
                let (lcn_0, clusters_0) = self.mft_extents[0];
                let mut attr_list_entries: Vec<(u32, u64, u64)> = Vec::new();
                attr_list_entries.push((ATTR_DATA, 0, 0));

                let mut ext_builder = RecordBuilder::new(ext_rec_no, 1).base(0);
                let mut curr_vcn = clusters_0;
                for &(lcn_i, clusters_i) in &self.mft_extents[1..] {
                    attr_list_entries.push((ATTR_DATA, curr_vcn, ext_rec_no));
                    ext_builder = ext_builder.data_nonresident(
                        None,
                        curr_vcn,
                        0,
                        0,
                        &[Run {
                            lcn: Some(lcn_i),
                            len: clusters_i,
                        }],
                    );
                    curr_vcn += clusters_i;
                }

                let ext_rec = ext_builder.build(self.record_size as usize);
                self.records.insert(ext_rec_no, ext_rec);

                let rec0 = RecordBuilder::new(0, 1)
                    .std_info(0, 0, 0x06)
                    .file_name(5, 1, 1, "$MFT")
                    .data_nonresident(
                        None,
                        0,
                        total_data_size,
                        0,
                        &[Run {
                            lcn: Some(lcn_0),
                            len: clusters_0,
                        }],
                    )
                    .attribute_list(&attr_list_entries)
                    .build(self.record_size as usize);
                self.records.insert(0, rec0);
            } else {
                let all_runs: Vec<Run> = self
                    .mft_extents
                    .iter()
                    .map(|&(lcn, len)| Run {
                        lcn: Some(lcn),
                        len,
                    })
                    .collect();
                let rec0 = RecordBuilder::new(0, 1)
                    .std_info(0, 0, 0x06)
                    .file_name(5, 1, 1, "$MFT")
                    .data_nonresident(None, 0, total_data_size, 0, &all_runs)
                    .build(self.record_size as usize);
                self.records.insert(0, rec0);
            }
        }

        if !self.records.contains_key(&5) {
            let rec5 = RecordBuilder::new(5, 1)
                .dir()
                .file_name(5, 1, 1, ".")
                .build(self.record_size as usize);
            self.records.insert(5, rec5);
        }

        let max_extent_end = self
            .mft_extents
            .iter()
            .map(|(lcn, len)| (lcn + len) * self.cluster_size)
            .max()
            .unwrap_or(0);
        let image_size = max_extent_end.max(8192) as usize;
        let mut image = vec![0u8; image_size];

        let sectors_per_cluster = (self.cluster_size / 512) as u32;
        let total_sectors = (image.len() / 512) as u64;
        let boot = BootSector {
            bytes_per_sector: 512,
            sectors_per_cluster,
            total_sectors,
            mft_lcn: self.mft_extents[0].0,
            mft_record_size: self.record_size,
            serial: 0x1234_5678_9ABC_DEF0,
        };

        image[510..512].copy_from_slice(&[0x55, 0xAA]);
        image[3..11].copy_from_slice(b"NTFS    ");
        image[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        let spc_byte = if sectors_per_cluster <= 0x80 {
            sectors_per_cluster as u8
        } else {
            (256 - sectors_per_cluster.trailing_zeros()) as u8
        };
        image[0x0D] = spc_byte;
        image[0x28..0x30].copy_from_slice(&total_sectors.to_le_bytes());
        image[0x30..0x38].copy_from_slice(&boot.mft_lcn.to_le_bytes());
        let cpr_byte: u8 = if self.record_size < self.cluster_size as u32 {
            let shift = self.record_size.trailing_zeros();
            (256 - shift) as u8
        } else {
            (self.record_size / self.cluster_size as u32) as u8
        };
        image[0x40] = cpr_byte;
        image[0x48..0x50].copy_from_slice(&boot.serial.to_le_bytes());

        for (&rec_no, rec_bytes) in &self.records {
            let mft_offset = rec_no * (self.record_size as u64);
            let mut curr_mft_off: u64 = 0;
            let mut placed = false;
            for &(lcn, clusters) in &self.mft_extents {
                let ext_bytes = clusters * self.cluster_size;
                if mft_offset >= curr_mft_off
                    && mft_offset + (self.record_size as u64) <= curr_mft_off + ext_bytes
                {
                    let disk_offset = (lcn * self.cluster_size) + (mft_offset - curr_mft_off);
                    let start = disk_offset as usize;
                    let end = start + rec_bytes.len();
                    assert!(end <= image.len(), "record placed out of image bounds");
                    image[start..end].copy_from_slice(rec_bytes);
                    placed = true;
                    break;
                }
                curr_mft_off += ext_bytes;
            }
            assert!(
                placed,
                "record {rec_no} at offset {mft_offset} did not fit in mft_extents"
            );
        }

        (image, boot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs::record::{REC_DIRECTORY, REC_IN_USE, apply_fixups, parse_header};

    #[test]
    fn builder_exercises_all_attributes() {
        let runs = [Run {
            lcn: Some(50),
            len: 4,
        }];
        let mut rec = RecordBuilder::new(100, 2)
            .dir()
            .base(5)
            .std_info(123_456_789, 987_654_321, 0x20)
            .file_name(5, 1, 1, "test.txt")
            .data_resident(Some("resident_stream"), 64)
            .data_nonresident(Some("nonresident_stream"), 0, 16384, 0, &runs)
            .index_allocation(&runs)
            .attribute_list(&[(0x80, 0, 100)])
            .reparse(0x8000_0017)
            .build(1024);

        apply_fixups(&mut rec).unwrap();
        let hdr = parse_header(&rec).unwrap();
        assert_eq!(hdr.seq, 2);
        assert_eq!(hdr.base_record, 5);
        assert_eq!(hdr.flags & REC_DIRECTORY, REC_DIRECTORY);
        assert_eq!(hdr.flags & REC_IN_USE, REC_IN_USE);
    }

    #[test]
    fn builder_not_in_use() {
        let mut rec = RecordBuilder::new(100, 1).not_in_use().build(1024);
        apply_fixups(&mut rec).unwrap();
        let hdr = parse_header(&rec).unwrap();
        assert_eq!(hdr.flags & REC_IN_USE, 0);
    }
}
