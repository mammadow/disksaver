//! Owner-decision primitives (P9.8): launch an app's registered uninstaller, move a user library
//! with the supported Known Folder redirect, and read video durations for bitrate checks.
//!
//! Nothing here runs without an explicit owner action, and nothing here is reachable from the
//! elevated helper.

#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use windows::core::{GUID, PCWSTR};

use crate::error::{DskError, Result};
use crate::win::prefetch::{enum_subkey_names, open_reg_key_read, read_reg_string, to_wide};

// ---------------------------------------------------------------------------------------------
// Uninstallers
// ---------------------------------------------------------------------------------------------

/// A registered uninstaller, split into program and arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallCommand {
    pub app_name: String,
    pub program: PathBuf,
    pub args: String,
    /// The raw registry value, for display.
    pub raw: String,
}

/// Splits an `UninstallString` into program and arguments. `MsiExec.exe /I{GUID}` and `/X{GUID}`
/// become the pinned `System32\msiexec.exe /x {GUID}`.
pub fn parse_uninstall_string(raw: &str) -> Option<(PathBuf, String)> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("msiexec") || lower.contains("\\msiexec.exe") {
        let open = s.find('{')?;
        let close = s[open..].find('}')? + open;
        let guid = &s[open..=close];
        if guid.len() != 38
            || !guid[1..37]
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-')
        {
            return None;
        }
        return Some((
            crate::win::volume::system32_dir().join("msiexec.exe"),
            format!("/x {guid}"),
        ));
    }
    let (program, args) = if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        (rest[..end].to_string(), rest[end + 1..].trim().to_string())
    } else {
        // Unquoted: the program ends at the first `.exe` followed by a space or the end.
        let pos = lower.find(".exe")? + 4;
        if pos < s.len() && !s[pos..].starts_with(' ') {
            return None;
        }
        (s[..pos].to_string(), s[pos..].trim().to_string())
    };
    let program = PathBuf::from(program);
    program.is_absolute().then_some((program, args))
}

fn find_in_hive(hive: HKEY, path: &str, app_name: &str) -> Option<String> {
    let root = open_reg_key_read(hive, path)?;
    for child in enum_subkey_names(root.0) {
        let Some(key) = open_reg_key_read(root.0, &child) else {
            continue;
        };
        if read_reg_string(key.0, "DisplayName").is_some_and(|n| n.eq_ignore_ascii_case(app_name)) {
            return read_reg_string(key.0, "UninstallString");
        }
    }
    None
}

/// Finds the registered uninstaller for the app whose `DisplayName` equals `app_name`.
pub fn find_uninstall_command(app_name: &str) -> Option<UninstallCommand> {
    let raw = [
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ]
    .into_iter()
    .find_map(|(hive, path)| find_in_hive(hive, path, app_name))?;
    let (program, args) = parse_uninstall_string(&raw)?;
    Some(UninstallCommand {
        app_name: app_name.to_string(),
        program,
        args,
        raw,
    })
}

/// Starts the uninstaller (it shows its own UI and UAC prompt) and returns without waiting.
pub fn launch_uninstaller(cmd: &UninstallCommand) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let meta = std::fs::metadata(&cmd.program)?;
    if !meta.is_file() {
        return Err(DskError::PreconditionFailed(format!(
            "uninstaller not found: {}",
            cmd.program.display()
        )));
    }
    // CREATE_NO_WINDOW only suppresses a console; GUI uninstallers still show their windows.
    crate::win::process::hidden_command(&cmd.program)
        .raw_arg(&cmd.args)
        .spawn()
        .map(|_| ())
        .map_err(DskError::Io)
}

// ---------------------------------------------------------------------------------------------
// Known folder (library) moves
// ---------------------------------------------------------------------------------------------

/// User libraries DiskSaver may move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserLibrary {
    Videos,
    Downloads,
    Music,
    Pictures,
    Documents,
}

impl UserLibrary {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "videos" => Some(Self::Videos),
            "downloads" => Some(Self::Downloads),
            "music" => Some(Self::Music),
            "pictures" => Some(Self::Pictures),
            "documents" => Some(Self::Documents),
            _ => None,
        }
    }

    fn folder_id(self) -> GUID {
        use windows::Win32::UI::Shell::{
            FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Pictures,
            FOLDERID_Videos,
        };
        match self {
            Self::Videos => FOLDERID_Videos,
            Self::Downloads => FOLDERID_Downloads,
            Self::Music => FOLDERID_Music,
            Self::Pictures => FOLDERID_Pictures,
            Self::Documents => FOLDERID_Documents,
        }
    }

    /// Current location.
    pub fn current_path(self) -> Option<PathBuf> {
        use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
        // SAFETY: The returned PWSTR is freed with CoTaskMemFree after copying.
        unsafe {
            let p = SHGetKnownFolderPath(&self.folder_id(), KF_FLAG_DEFAULT, None).ok()?;
            let s = p.to_string().ok();
            windows::Win32::System::Com::CoTaskMemFree(Some(p.0 as *const core::ffi::c_void));
            s.map(PathBuf::from)
        }
    }
}

/// Checks a library move before Windows sees it (its own check-only mode accepts, for example, a
/// target inside the library): fixed local drive, not inside the library or a system location,
/// new or empty, and room for `library_bytes` plus 1 GiB.
pub fn validate_library_target(lib: UserLibrary, target: &Path, library_bytes: u64) -> Result<()> {
    use crate::clean::deny::{DenyContext, is_under_root};
    let current = lib
        .current_path()
        .ok_or_else(|| DskError::Optimize(format!("{lib:?} has no current location")))?;
    if !target.is_absolute() || target.to_string_lossy().starts_with(r"\\") {
        return Err(DskError::Denied(
            "the target must be a local absolute path".into(),
        ));
    }
    if is_under_root(target, &current) || is_under_root(&current, target) {
        return Err(DskError::Denied(format!(
            "{} overlaps the current {lib:?} folder {}",
            target.display(),
            current.display()
        )));
    }
    let deny = DenyContext::default();
    let probe = target.join("__dsk_probe__");
    if let Some(reason) = crate::clean::deny::is_denied_path(target, &deny)
        .or_else(|| crate::clean::deny::is_denied_path(&probe, &deny))
        .filter(|r| !r.contains("personal library"))
    {
        return Err(DskError::Denied(format!("{}: {reason}", target.display())));
    }
    let pf = crate::win::volume::program_files_dir();
    let win = crate::win::volume::system32_dir();
    if is_under_root(target, &pf) || win.parent().is_some_and(|w| is_under_root(target, w)) {
        return Err(DskError::Denied(
            "the target cannot be inside Windows or Program Files".into(),
        ));
    }
    crate::win::volume::validate_drive_type_is_fixed(
        crate::win::volume::query_path_drive_type(target),
        target,
    )?;
    if target.exists() {
        let empty = std::fs::read_dir(target)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        if !empty {
            return Err(DskError::Denied(format!(
                "{} already exists and is not empty",
                target.display()
            )));
        }
    }
    let root = crate::win::volume::path_volume_mount_root(target)
        .ok_or_else(|| DskError::Optimize("cannot resolve the target drive".into()))?;
    let free = crate::win::volume::volume_info(&root)?.free_bytes;
    let need = library_bytes.saturating_add(1 << 30);
    if free < need {
        return Err(DskError::PreconditionFailed(format!(
            "{root} has {:.1} GiB free; moving needs {:.1} GiB",
            free as f64 / (1u64 << 30) as f64,
            need as f64 / (1u64 << 30) as f64
        )));
    }
    Ok(())
}

/// Moves a library to `target` with `IKnownFolderManager::Redirect` (copy contents, delete the
/// source copies), exactly like Explorer's Properties > Location > Move. `check_only` validates
/// without moving anything. Call [`validate_library_target`] first.
pub fn move_user_library(lib: UserLibrary, target: &Path, check_only: bool) -> Result<()> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree};
    use windows::Win32::UI::Shell::{
        IKnownFolderManager, KF_REDIRECT_CHECK_ONLY, KF_REDIRECT_COPY_CONTENTS,
        KF_REDIRECT_DEL_SOURCE_CONTENTS, KnownFolderManager,
    };
    let _com = crate::win::os_handlers::ComApartmentGuard::new()?;
    // SAFETY: Standard in-proc COM activation of the Known Folder Manager.
    let mgr: IKnownFolderManager =
        unsafe { CoCreateInstance(&KnownFolderManager, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| DskError::Optimize(format!("KnownFolderManager: {e}")))?;
    let flags = if check_only {
        KF_REDIRECT_CHECK_ONLY.0
    } else {
        KF_REDIRECT_COPY_CONTENTS.0 | KF_REDIRECT_DEL_SOURCE_CONTENTS.0
    } as u32;
    let wide = to_wide(&target.to_string_lossy());
    let id = lib.folder_id();
    let mut err = windows::core::PWSTR::null();
    // SAFETY: `id` and `wide` outlive the call; `err` receives a CoTaskMem string or stays null.
    let res = unsafe {
        mgr.Redirect(
            &id,
            None,
            flags,
            PCWSTR(wide.as_ptr()),
            None,
            Some(&mut err),
        )
    };
    let detail = if err.is_null() {
        String::new()
    } else {
        // SAFETY: `err` was allocated by the manager with CoTaskMemAlloc.
        let s = unsafe { err.to_string().unwrap_or_default() };
        unsafe { CoTaskMemFree(Some(err.0 as *const core::ffi::c_void)) };
        s
    };
    res.map_err(|e| DskError::Optimize(format!("moving {lib:?} failed: {e} {detail}")))
}

// ---------------------------------------------------------------------------------------------
// Media durations
// ---------------------------------------------------------------------------------------------

/// Playback duration from the Shell property system (`System.Media.Duration`). Uses only fast,
/// cached properties so no slow parsing of the whole file happens.
pub fn media_duration_secs(path: &Path) -> Option<f64> {
    use windows::Win32::Storage::EnhancedStorage::PKEY_Media_Duration;
    use windows::Win32::System::Com::StructuredStorage::PropVariantToUInt64;
    use windows::Win32::UI::Shell::PropertiesSystem::{
        GPS_DEFAULT, IPropertyStore, SHGetPropertyStoreFromParsingName,
    };
    let _com = crate::win::os_handlers::ComApartmentGuard::new().ok()?;
    let wide = to_wide(&path.to_string_lossy());
    // SAFETY: `wide` is NUL-terminated; the store is released on drop.
    let store: IPropertyStore =
        unsafe { SHGetPropertyStoreFromParsingName(PCWSTR(wide.as_ptr()), None, GPS_DEFAULT) }
            .ok()?;
    // SAFETY: Reads one property; the PROPVARIANT is cleared on drop.
    let value = unsafe { store.GetValue(&PKEY_Media_Duration) }.ok()?;
    // SAFETY: `value` is a valid PROPVARIANT.
    let hundred_ns = unsafe { PropVariantToUInt64(&value) }.ok()?;
    (hundred_ns > 0).then(|| hundred_ns as f64 / 10_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uninstall_strings() {
        let (p, a) =
            parse_uninstall_string(r#""C:\Program Files\App\unins000.exe" /SILENT"#).unwrap();
        assert_eq!(
            (p, a.as_str()),
            (
                PathBuf::from(r"C:\Program Files\App\unins000.exe"),
                "/SILENT"
            )
        );
        let (p, a) = parse_uninstall_string(r"C:\Tools\Uninstall.exe --remove").unwrap();
        assert_eq!(
            (p, a.as_str()),
            (PathBuf::from(r"C:\Tools\Uninstall.exe"), "--remove")
        );
        let (p, a) =
            parse_uninstall_string("MsiExec.exe /I{8A69D345-D564-463C-AFF1-A69D9E530F96}").unwrap();
        assert!(
            p.to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(r"system32\msiexec.exe")
        );
        assert_eq!(a, "/x {8A69D345-D564-463C-AFF1-A69D9E530F96}");
        assert_eq!(parse_uninstall_string("MsiExec.exe /I{not-a-guid}"), None);
        assert_eq!(
            parse_uninstall_string("uninstall.exe"),
            None,
            "relative program"
        );
        assert_eq!(parse_uninstall_string(r"C:\a.exefoo"), None);
    }

    #[test]
    fn library_paths_resolve_and_check_only_moves_nothing() {
        let videos = UserLibrary::Videos
            .current_path()
            .expect("Videos known folder");
        assert!(videos.is_absolute());
        assert_eq!(
            UserLibrary::parse("DOWNLOADS"),
            Some(UserLibrary::Downloads)
        );
        assert_eq!(UserLibrary::parse("windows"), None);
        // Windows' own check-only mode accepts a target inside the library; ours does not.
        assert!(validate_library_target(UserLibrary::Videos, &videos.join("nested"), 0).is_err());
        assert!(validate_library_target(UserLibrary::Videos, Path::new(r"relative\x"), 0).is_err());
        assert!(
            validate_library_target(UserLibrary::Videos, Path::new(r"C:\Windows\Videos"), 0)
                .is_err()
        );
        assert!(
            validate_library_target(UserLibrary::Videos, Path::new(r"\\server\share\v"), 0)
                .is_err()
        );
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("busy.txt"), "x").unwrap();
        assert!(
            validate_library_target(UserLibrary::Videos, tmp.path(), 0).is_err(),
            "non-empty target"
        );
        let fresh = tmp.path().join("NewVideos");
        assert!(validate_library_target(UserLibrary::Videos, &fresh, 0).is_ok());
        assert!(
            validate_library_target(UserLibrary::Videos, &fresh, u64::MAX / 2).is_err(),
            "not enough free space"
        );
        assert_eq!(UserLibrary::Videos.current_path(), Some(videos));
    }

    #[test]
    fn media_duration_of_a_non_media_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "x").unwrap();
        assert_eq!(media_duration_secs(&f), None);
    }
}
