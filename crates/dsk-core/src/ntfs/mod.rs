#![forbid(unsafe_code)]

pub mod assemble;
pub mod attr;
pub mod boot;
pub mod mft;
pub mod record;
pub mod runs;
pub mod summary;
pub mod usn;

#[cfg(test)]
pub(crate) mod testutil;

pub use assemble::{MftScanOutput, SummaryBatch, assemble};
pub use mft::{MftLayout, Phase, Progress, SectorReader, read_mft_layout, scan_mft};
pub use usn::{
    CoalescedUsnOp, USN_REASON_CLOSE, USN_REASON_DATA_EXTEND, USN_REASON_DATA_OVERWRITE,
    USN_REASON_DATA_TRUNCATION, USN_REASON_FILE_CREATE, USN_REASON_FILE_DELETE,
    USN_REASON_HARD_LINK_CHANGE, USN_REASON_RENAME_NEW_NAME, USN_REASON_RENAME_OLD_NAME,
    USN_REASON_REPARSE_POINT_CHANGE, UsnDelta, UsnJournalState, UsnRecord, coalesce_usn_records,
    parse_usn_read_buffer, parse_usn_records, validate_usn_continuity,
};

pub use attr::{
    AttrBody, AttrListEntry, AttrRef, FileNameAttr, StandardInfo, attributes, parse_attribute_list,
    parse_file_name, parse_reparse_tag, parse_standard_info,
};
pub use boot::{BootSector, parse_boot_sector};
pub use record::{REC_DIRECTORY, REC_IN_USE, RecordHeader, apply_fixups, parse_header};
pub use runs::{Run, allocated_clusters, decode_runs};
pub use summary::{FileSummary, LinkName, summarize_record};

pub const ATTR_STANDARD_INFO: u32 = 0x10;
pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_INDEX_ROOT: u32 = 0x90;
pub const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
pub const ATTR_BITMAP: u32 = 0xB0;
pub const ATTR_REPARSE_POINT: u32 = 0xC0;
pub const ATTR_END: u32 = 0xFFFF_FFFF;

pub const TAG_WOF: u32 = 0x8000_0017;
pub const TAG_SYMLINK: u32 = 0xA000_000C;
pub const TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const TAG_APPEXECLINK: u32 = 0x8000_001B;
pub const TAG_DEDUP: u32 = 0x8000_0013;

pub fn is_cloud_tag(t: u32) -> bool {
    t & 0xFFFF_0FFF == 0x9000_001A
}

// SI attribute bits
pub const FA_HIDDEN: u32 = 0x2;
pub const FA_SYSTEM: u32 = 0x4;
pub const FA_SPARSE: u32 = 0x200;
pub const FA_COMPRESSED: u32 = 0x800;
pub const FA_OFFLINE: u32 = 0x1000;
pub const FA_RECALL_ON_OPEN: u32 = 0x4_0000;
pub const FA_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

// attr flags
pub const AF_COMPRESSED: u16 = 0x0001;
pub const AF_SPARSE: u16 = 0x8000;
