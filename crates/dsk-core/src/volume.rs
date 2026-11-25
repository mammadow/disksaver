#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// High-level volume metadata queried from Win32 APIs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// Volume root path, formatted as a long path (e.g. `\\?\C:\`).
    pub root: String,
    /// Filesystem name (e.g. `NTFS`, `ReFS`).
    pub fs_name: String,
    /// Volume serial number.
    pub serial: u32,
    /// Cluster size in bytes (e.g. 4096).
    pub cluster_size: u32,
    /// Total capacity of the volume in bytes.
    pub total_bytes: u64,
    /// Free space on the volume in bytes.
    pub free_bytes: u64,
    /// Whether the volume has a seek penalty (`Some(true)` for HDD, `Some(false)` for SSD/NVMe, `None` if undetermined).
    pub seek_penalty: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_info_default() {
        let v = VolumeInfo::default();
        assert_eq!(v.root, "");
        assert_eq!(v.fs_name, "");
        assert_eq!(v.serial, 0);
        assert_eq!(v.cluster_size, 0);
        assert_eq!(v.total_bytes, 0);
        assert_eq!(v.free_bytes, 0);
        assert_eq!(v.seek_penalty, None);
    }

    #[test]
    fn volume_info_clone_and_eq() {
        let v1 = VolumeInfo {
            root: "\\\\?\\C:\\".into(),
            fs_name: "NTFS".into(),
            serial: 0x12345678,
            cluster_size: 4096,
            total_bytes: 1_000_000_000_000,
            free_bytes: 500_000_000_000,
            seek_penalty: Some(false),
        };
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }
}
