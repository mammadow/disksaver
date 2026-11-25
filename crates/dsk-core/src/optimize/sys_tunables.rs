#![forbid(unsafe_code)]

//! System Storage Tunables: Hiberfile, VSS shadow storage, and Reserved Storage (§8.2, §8.3).

use std::fs;

use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};
use crate::index::{Index, ROOT};
use crate::win::preconditions::{power_status, running_processes, servicing_busy};
use crate::win::process::hidden_command;
use crate::win::volume::{path_volume_mount_root, system32_dir};

/// Hibernation operating modes supported by Windows 10/11 (§8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HiberfileMode {
    /// Full hibernation: RAM image + Fast Startup (typically 40%–80% of RAM).
    Full,
    /// Reduced hibernation: Fast Startup only (typically 20% of RAM).
    Reduced,
    /// Hibernation off: disables both hibernation and Fast Startup.
    Off,
}

/// Comprehensive probe status of Windows system storage tunables.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemTunablesStatus {
    /// System drive (`C:`) that the hiberfile, VSS, and Reserved Storage values refer to.
    #[serde(default)]
    pub system_drive: String,
    /// Allocated size of `C:\hiberfil.sys` in bytes, if present.
    pub hiberfil_bytes: Option<u64>,
    /// Whether a laptop/device battery is detected (warn before disabling hibernation).
    pub is_laptop_battery_present: bool,
    /// Currently used VSS shadow copy storage bytes on system drive.
    pub vss_used_bytes: Option<u64>,
    /// Maximum allocated cap for VSS shadow storage on system drive.
    pub vss_max_bytes: Option<u64>,
    /// Whether Windows 10/11 Reserved Storage (~7 GB) is currently enabled.
    pub reserved_storage_enabled: Option<bool>,
    /// Whether Windows Update or CBS servicing is currently active.
    pub servicing_busy: bool,
}

/// Probes the current state of system storage tunables.
pub fn probe_sys_tunables(index: Option<&Index>) -> SystemTunablesStatus {
    let sys32 = system32_dir();
    let system_drive = path_volume_mount_root(&sys32)
        .and_then(|root| root.get(..2).map(str::to_string))
        .unwrap_or_else(|| "C:".to_string());
    let hiber_path = format!(r"{system_drive}\hiberfil.sys");

    // 1. Probe hiberfil.sys size
    let hiberfil_bytes = if let Some(idx) = index {
        let mut found = None;
        for child in idx.children(ROOT) {
            if idx.name(child).eq_ignore_ascii_case("hiberfil.sys") {
                found = Some(idx.allocated(child));
                break;
            }
        }
        found.or_else(|| fs::metadata(&hiber_path).ok().map(|m| m.len()))
    } else {
        fs::metadata(&hiber_path).ok().map(|m| m.len())
    };

    // 2. Battery presence
    let (_, battery) = power_status();
    let is_laptop_battery_present = battery.is_some();

    // 3. Servicing busy
    let running = running_processes().unwrap_or_default();
    let servicing_is_busy = servicing_busy(&running).is_some();

    // 4. VSS shadow storage query
    let (vss_used_bytes, vss_max_bytes) = query_vss_shadow_storage(&system_drive);

    // 5. Reserved Storage query
    let reserved_storage_enabled = query_reserved_storage_state();

    SystemTunablesStatus {
        system_drive,
        hiberfil_bytes,
        is_laptop_battery_present,
        vss_used_bytes,
        vss_max_bytes,
        reserved_storage_enabled,
        servicing_busy: servicing_is_busy,
    }
}

/// Parses output of `vssadmin list shadowstorage` to extract used and maximum bytes.
pub fn parse_vssadmin_shadowstorage_output(stdout: &str) -> (Option<u64>, Option<u64>) {
    let mut used_bytes = None;
    let mut max_bytes = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Used Shadow Copy Storage space:") {
            used_bytes = extract_bytes_from_vssadmin_line(trimmed);
        } else if trimmed.starts_with("Maximum Shadow Copy Storage space:") {
            max_bytes = extract_bytes_from_vssadmin_line(trimmed);
        }
    }

    (used_bytes, max_bytes)
}

fn extract_bytes_from_vssadmin_line(line: &str) -> Option<u64> {
    // Example: "Used Shadow Copy Storage space: 4.51 GB (4843479040)"
    let start = line.rfind('(')?;
    let end = line.rfind(')')?;
    if end > start + 1 {
        let inner = &line[start + 1..end];
        let num_str: String = inner.chars().filter(|c| c.is_ascii_digit()).collect();
        return num_str.parse::<u64>().ok();
    }
    None
}

fn vss_drive_arg(volume_drive: &str) -> Result<String> {
    let clean = volume_drive.trim().trim_end_matches(['\\', '/']);
    let bytes = clean.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Ok(format!("{}:", (bytes[0] as char).to_ascii_uppercase()))
    } else {
        Err(DskError::Optimize(format!(
            "invalid drive letter specification for VSS operation: '{volume_drive}'"
        )))
    }
}

/// Queries VSS shadow storage via pinned `System32\vssadmin.exe list shadowstorage`.
///
/// `/for=<drive>` restricts the listing to the requested volume's association; without it the
/// parser would report whichever association vssadmin printed last.
fn query_vss_shadow_storage(drive: &str) -> (Option<u64>, Option<u64>) {
    let Ok(clean_drive) = vss_drive_arg(drive) else {
        return (None, None);
    };
    let vssadmin_bin = system32_dir().join("vssadmin.exe");
    let for_arg = format!("/for={clean_drive}");

    let out = hidden_command(&vssadmin_bin)
        .args(["list", "shadowstorage", &for_arg])
        .output();

    if let Ok(output) = out {
        let text = String::from_utf8_lossy(&output.stdout);
        return parse_vssadmin_shadowstorage_output(&text);
    }

    (None, None)
}

/// Parses output of `dism.exe /Online /Get-ReservedStorageState`.
pub fn parse_dism_reserved_storage_output(stdout: &str) -> Option<bool> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Reserved storage is") || trimmed.starts_with("State :") {
            if trimmed.contains("Enabled") || trimmed.contains("enabled") {
                return Some(true);
            }
            if trimmed.contains("Disabled") || trimmed.contains("disabled") {
                return Some(false);
            }
        }
    }
    None
}

/// Queries Reserved Storage state via pinned `System32\Dism.exe`.
fn query_reserved_storage_state() -> Option<bool> {
    let dism_bin = system32_dir().join("Dism.exe");

    let out = hidden_command(&dism_bin)
        // `/English` keeps "Reserved storage is Enabled/Disabled" culture-neutral.
        .args(["/English", "/Online", "/Get-ReservedStorageState"])
        .output();

    if let Ok(output) = out {
        let text = String::from_utf8_lossy(&output.stdout);
        return parse_dism_reserved_storage_output(&text);
    }

    None
}

/// Configures the Windows hibernation mode via pinned `System32\powercfg.exe`.
pub fn configure_hiberfile(mode: HiberfileMode, dry_run: bool) -> Result<String> {
    let powercfg_bin = system32_dir().join("powercfg.exe");

    let args: Vec<&str> = match mode {
        HiberfileMode::Full => vec!["/h", "/type", "full"],
        HiberfileMode::Reduced => vec!["/h", "/type", "reduced"],
        HiberfileMode::Off => vec!["/h", "off"],
    };

    if dry_run {
        return Ok(format!(
            "Dry run: Would execute {} with args {:?}",
            powercfg_bin.display(),
            args
        ));
    }

    let out = hidden_command(&powercfg_bin)
        .args(args)
        .output()
        .map_err(DskError::Io)?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(DskError::Optimize(format!(
            "powercfg failed with code {:?}: {err}",
            out.status.code()
        )));
    }

    Ok(format!(
        "Successfully configured hibernation mode to {:?}",
        mode
    ))
}

/// Resizes shadow storage maximum cap or prunes oldest shadow copies via pinned `System32\vssadmin.exe`.
pub fn resize_or_prune_vss(
    volume_drive: &str,
    max_percent: Option<u8>,
    delete_oldest_only: bool,
    dry_run: bool,
) -> Result<String> {
    let clean_drive = vss_drive_arg(volume_drive)?;
    let vssadmin_bin = system32_dir().join("vssadmin.exe");

    if delete_oldest_only {
        let for_arg = format!("/for={clean_drive}");
        let args = ["delete", "shadows", &for_arg, "/oldest", "/quiet"];
        if dry_run {
            return Ok(format!(
                "Dry run: Would execute {} with args {:?}",
                vssadmin_bin.display(),
                args
            ));
        }

        let out = hidden_command(&vssadmin_bin)
            .args(args)
            .output()
            .map_err(DskError::Io)?;

        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(DskError::Optimize(format!("vssadmin failed: {err}")));
        }

        return Ok(format!(
            "Successfully pruned oldest shadow copies on {clean_drive}"
        ));
    }

    if let Some(pct) = max_percent {
        if !(1..=100).contains(&pct) {
            return Err(DskError::Optimize(format!(
                "VSS max_percent must be between 1 and 100 (got {pct})"
            )));
        }

        let max_arg = format!("/maxsize={pct}%");
        let for_arg = format!("/for={clean_drive}");
        let on_arg = format!("/on={clean_drive}");
        let args = ["resize", "shadowstorage", &for_arg, &on_arg, &max_arg];

        if dry_run {
            return Ok(format!(
                "Dry run: Would execute {} with args {:?}",
                vssadmin_bin.display(),
                args
            ));
        }

        let out = hidden_command(&vssadmin_bin)
            .args(args)
            .output()
            .map_err(DskError::Io)?;

        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(DskError::Optimize(format!("vssadmin failed: {err}")));
        }

        return Ok(format!(
            "Successfully resized VSS shadow storage cap on {clean_drive} to {pct}%"
        ));
    }

    Err(DskError::Optimize(
        "no VSS operation specified (expected max_percent or delete_oldest_only)".to_string(),
    ))
}

/// Enables or disables Windows Reserved Storage via pinned `System32\Dism.exe`.
pub fn set_reserved_storage(enabled: bool, dry_run: bool) -> Result<String> {
    let running = running_processes().unwrap_or_default();
    if let Some(reason) = servicing_busy(&running) {
        return Err(DskError::PreconditionFailed(format!(
            "Cannot modify Reserved Storage while servicing is active: {reason}"
        )));
    }

    let dism_bin = system32_dir().join("Dism.exe");

    let state_arg = if enabled {
        "/State:Enabled"
    } else {
        "/State:Disabled"
    };

    let args = [
        "/English",
        "/Online",
        "/Set-ReservedStorageState",
        state_arg,
        "/Quiet",
        "/NoRestart",
    ];

    if dry_run {
        return Ok(format!(
            "Dry run: Would execute {} with args {:?}",
            dism_bin.display(),
            args
        ));
    }

    let out = hidden_command(&dism_bin)
        .args(args)
        .output()
        .map_err(DskError::Io)?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(DskError::Optimize(format!("dism.exe failed: {err}")));
    }

    Ok(format!(
        "Successfully set Reserved Storage state to {}",
        if enabled { "Enabled" } else { "Disabled" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vssadmin_shadowstorage_and_dism_reserved_storage_outputs() {
        let sample_vss = r#"
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Shadow Copy Storage association
   For volume: (C:)\\?\Volume{12345678-1234-1234-1234-123456789abc}\
   Shadow Copy Storage volume: (C:)\\?\Volume{12345678-1234-1234-1234-123456789abc}\
   Used Shadow Copy Storage space: 4.51 GB (4843479040)
   Allocated Shadow Copy Storage space: 5.20 GB (5583454208)
   Maximum Shadow Copy Storage space: 23.8 GB (25595904000)
"#;
        let (used, max) = parse_vssadmin_shadowstorage_output(sample_vss);
        assert_eq!(used, Some(4843479040));
        assert_eq!(max, Some(25595904000));

        let sample_dism_enabled = r#"
Deployment Image Servicing and Management tool
Version: 10.0.22621.1

Image Version: 10.0.22621.2861

Reserved storage is Enabled.
The operation completed successfully.
"#;
        assert_eq!(
            parse_dism_reserved_storage_output(sample_dism_enabled),
            Some(true)
        );

        let sample_dism_disabled = r#"
Reserved storage is Disabled.
The operation completed successfully.
"#;
        assert_eq!(
            parse_dism_reserved_storage_output(sample_dism_disabled),
            Some(false)
        );
    }

    #[test]
    fn sys_tunables_dry_run_validates_arguments_and_emits_script() {
        let hib_dry = configure_hiberfile(HiberfileMode::Reduced, true).unwrap();
        assert!(hib_dry.contains("Dry run:"));
        assert!(hib_dry.contains("reduced"));

        let vss_dry = resize_or_prune_vss("C:", Some(10), false, true).unwrap();
        assert!(vss_dry.contains("Dry run:"));
        assert!(vss_dry.contains("/maxsize=10%"));

        let vss_prune_dry = resize_or_prune_vss("C:", None, true, true).unwrap();
        assert!(vss_prune_dry.contains("Dry run:"));
        assert!(vss_prune_dry.contains("/oldest"));
        assert!(
            vss_prune_dry
                .to_ascii_lowercase()
                .contains(r"system32\vssadmin.exe")
        );

        assert!(resize_or_prune_vss("C: & calc.exe", Some(10), false, true).is_err());
        assert!(resize_or_prune_vss("", None, true, true).is_err());
        assert!(resize_or_prune_vss(r"C:\Windows", Some(10), false, true).is_err());
        assert!(resize_or_prune_vss("C:", Some(0), false, true).is_err());
        assert!(resize_or_prune_vss("C:", Some(101), false, true).is_err());
        assert!(resize_or_prune_vss("d\\", Some(15), false, true).is_err());
        assert!(
            resize_or_prune_vss("d:\\", Some(15), false, true)
                .unwrap()
                .contains("/for=D:")
        );
    }
}
