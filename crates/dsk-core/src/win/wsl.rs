//! Registered WSL distributions (`HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss`).
//!
//! Each distro's `BasePath` holds its virtual disk (`VhdFileName`, normally `ext4.vhdx`). Insights
//! use it so a live distro is never mistaken for orphaned app data, and the VHDX optimizer uses it
//! to pass the real distro name to `wsl --manage <name> --set-sparse`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::HKEY_CURRENT_USER;

use crate::win::prefetch::{enum_subkey_names, open_reg_key_read, read_reg_string};

const LXSS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Lxss";

/// One registered WSL distribution of the current user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslDistro {
    /// `DistributionName`, as accepted by `wsl -d` / `wsl --manage`.
    pub name: String,
    /// `BasePath` without any `\\?\` prefix.
    pub base_path: PathBuf,
    /// `BasePath\VhdFileName` (defaults to `ext4.vhdx`).
    pub vhdx_path: PathBuf,
}

/// Strips the `\\?\` / `\??\` prefix WSL writes for some distros (e.g. `docker-desktop`).
pub fn normalize_lxss_base_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim().trim_matches('"');
    let plain = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix(r"\??\"))
        .unwrap_or(trimmed);
    if plain.starts_with("UNC\\") || plain.is_empty() {
        return None;
    }
    Some(PathBuf::from(plain.trim_end_matches(['\\', '/'])))
}

/// Lists the current user's registered WSL distributions. Returns an empty list when WSL is not
/// installed or the key cannot be read.
pub fn registered_wsl_distros() -> Vec<WslDistro> {
    let Some(root) = open_reg_key_read(HKEY_CURRENT_USER, LXSS_KEY) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for guid in enum_subkey_names(root.0) {
        let Some(key) = open_reg_key_read(root.0, &guid) else {
            continue;
        };
        let (Some(name), Some(base_raw)) = (
            read_reg_string(key.0, "DistributionName"),
            read_reg_string(key.0, "BasePath"),
        ) else {
            continue;
        };
        let Some(base_path) = normalize_lxss_base_path(&base_raw) else {
            continue;
        };
        let vhd_name =
            read_reg_string(key.0, "VhdFileName").unwrap_or_else(|| "ext4.vhdx".to_string());
        let vhdx_path = base_path.join(Path::new(&vhd_name).file_name().unwrap_or_default());
        out.push(WslDistro {
            name,
            base_path,
            vhdx_path,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_path_prefixes_are_stripped_and_unc_rejected() {
        assert_eq!(
            normalize_lxss_base_path(r"\\?\C:\Users\A\AppData\Local\Docker\wsl\main"),
            Some(PathBuf::from(r"C:\Users\A\AppData\Local\Docker\wsl\main"))
        );
        assert_eq!(
            normalize_lxss_base_path(r"C:\Users\A\AppData\Local\wsl\{8dc3}\"),
            Some(PathBuf::from(r"C:\Users\A\AppData\Local\wsl\{8dc3}"))
        );
        assert_eq!(normalize_lxss_base_path(r"\\?\UNC\srv\share\wsl"), None);
        assert_eq!(normalize_lxss_base_path("  "), None);
    }

    #[test]
    fn live_enumeration_never_panics_and_yields_absolute_paths() {
        for d in registered_wsl_distros() {
            assert!(!d.name.is_empty());
            assert!(d.base_path.is_absolute(), "{:?}", d.base_path);
            assert!(d.vhdx_path.starts_with(&d.base_path));
        }
    }
}
