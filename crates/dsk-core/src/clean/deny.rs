#![forbid(unsafe_code)]

//! Non-overridable safety deny-list for cleanup operations.
//!
//! Enforces compile-time forbid of unsafe code and strict component-boundary path
//! validation to prevent accidental or malicious deletion of critical operating system
//! directories, user profiles, personal libraries, and volume metadata.

use std::path::Path;

use crate::error::{DskError, Result};

/// Environment and profile context used to evaluate non-overridable cleanup deny rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyContext {
    pub system_drive: String,
    pub windows_dir: String,
    pub program_data: String,
    pub program_files: String,
    pub user_profiles: Vec<String>,
    pub local_app_data: Option<String>,
}

impl DenyContext {
    /// Constructs a [`DenyContext`] with explicit path strings.
    pub fn new(
        system_drive: impl Into<String>,
        windows_dir: impl Into<String>,
        program_data: impl Into<String>,
        program_files: impl Into<String>,
        user_profiles: Vec<String>,
        local_app_data: Option<String>,
    ) -> Self {
        Self {
            system_drive: system_drive.into(),
            windows_dir: windows_dir.into(),
            program_data: program_data.into(),
            program_files: program_files.into(),
            user_profiles,
            local_app_data,
        }
    }

    /// Discovers system and user profile paths from the current process environment.
    pub fn from_env() -> Self {
        fn canonicalize_if_exists(raw: String) -> String {
            std::fs::canonicalize(&raw)
                .ok()
                .map(|p| {
                    let s = p.to_string_lossy();
                    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
                })
                .unwrap_or(raw)
        }

        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let windows_dir = canonicalize_if_exists(
            std::env::var("SystemRoot")
                .or_else(|_| std::env::var("windir"))
                .unwrap_or_else(|_| r"C:\Windows".into()),
        );
        let program_data = canonicalize_if_exists(
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()),
        );
        let program_files = canonicalize_if_exists(
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into()),
        );
        let mut user_profiles = Vec::new();
        if let Ok(prof) = std::env::var("USERPROFILE") {
            user_profiles.push(canonicalize_if_exists(prof));
        }
        let local_app_data = std::env::var("LOCALAPPDATA")
            .ok()
            .map(canonicalize_if_exists);

        Self {
            system_drive,
            windows_dir,
            program_data,
            program_files,
            user_profiles,
            local_app_data,
        }
    }

    /// Provides a deterministic context for unit tests.
    pub fn default_for_test() -> Self {
        Self {
            system_drive: "C:".into(),
            windows_dir: r"C:\Windows".into(),
            program_data: r"C:\ProgramData".into(),
            program_files: r"C:\Program Files".into(),
            user_profiles: vec![r"C:\Users\Alice".into()],
            local_app_data: Some(r"C:\Users\Alice\AppData\Local".into()),
        }
    }
}

impl Default for DenyContext {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Normalizes a Windows path lexically without performing filesystem I/O.
///
/// Strips verbatim prefixes (`\\?\` and `\\?\UNC\`), converts `/` to `\`, collapses
/// redundant slashes, resolves lexical `.` and `..` segments, uppercases ASCII characters,
/// and strips non-root trailing backslashes (retaining drive roots like `C:\`).
pub fn normalize_win_path_str(p: &Path) -> String {
    let raw = p.to_string_lossy();
    if raw.is_empty() {
        return String::new();
    }

    // Convert all forward slashes to backslashes
    let mut s = raw.replace('/', "\\");

    // Handle verbatim prefixes: \\?\UNC\ or \??\UNC\
    let raw_bytes = s.as_bytes();
    if let Some(prefix) = raw_bytes.get(..8)
        && (prefix.eq_ignore_ascii_case(br"\\?\UNC\") || prefix.eq_ignore_ascii_case(br"\??\UNC\"))
    {
        s = format!(r"\\{}", &s[8..]);
    } else if let Some(prefix) = raw_bytes.get(..4)
        && (prefix.eq_ignore_ascii_case(br"\\?\") || prefix.eq_ignore_ascii_case(br"\??\"))
    {
        s = s[4..].to_string();
    }

    if s.is_empty() {
        return String::new();
    }

    // Check if UNC path (starts with \\)
    if s.starts_with(r"\\") {
        let after_unc = s.trim_start_matches('\\');
        let parts: Vec<&str> = after_unc
            .split('\\')
            .filter(|seg| !seg.is_empty())
            .collect();

        if parts.is_empty() {
            return r"\\".to_string();
        }
        if parts.len() == 1 {
            return format!(r"\\{}", parts[0].to_uppercase());
        }

        let server = parts[0].to_uppercase();
        let share = parts[1].to_uppercase();

        let mut stack: Vec<&str> = Vec::new();
        for &seg in &parts[2..] {
            if seg == "." {
                continue;
            } else if seg == ".." {
                stack.pop();
            } else {
                stack.push(seg);
            }
        }

        let mut out = format!(r"\\{server}\{share}");
        for seg in stack {
            out.push('\\');
            out.push_str(&seg.to_uppercase());
        }
        return out;
    }

    // Check if drive path (e.g. C:\... or C:...)
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_uppercase();
        let after_colon = &s[2..];

        let parts: Vec<&str> = after_colon
            .split('\\')
            .filter(|seg| !seg.is_empty())
            .collect();

        let mut stack: Vec<&str> = Vec::new();
        for seg in parts {
            if seg == "." {
                continue;
            } else if seg == ".." {
                stack.pop();
            } else {
                stack.push(seg);
            }
        }

        if stack.is_empty() {
            return format!("{drive}:\\");
        }

        let mut out = format!("{drive}:");
        for seg in stack {
            out.push('\\');
            out.push_str(&seg.to_uppercase());
        }
        return out;
    }

    // Generic / relative path
    let is_absolute_root = s.starts_with('\\');
    let parts: Vec<&str> = s.split('\\').filter(|seg| !seg.is_empty()).collect();
    let mut stack: Vec<&str> = Vec::new();
    for seg in parts {
        if seg == "." {
            continue;
        } else if seg == ".." {
            stack.pop();
        } else {
            stack.push(seg);
        }
    }

    if stack.is_empty() {
        if is_absolute_root {
            return "\\".to_string();
        }
        return String::new();
    }

    let mut out = if is_absolute_root {
        "\\".to_string()
    } else {
        String::new()
    };
    for (i, seg) in stack.iter().enumerate() {
        if i > 0 || is_absolute_root {
            out.push('\\');
        }
        out.push_str(&seg.to_uppercase());
    }
    out
}

/// Strict path-component prefix match.
///
/// Returns `true` if `candidate` equals `root` or is a component-delimited descendant of `root`.
/// Case-insensitive on Windows ASCII.
pub fn is_under_root(candidate: &Path, root: &Path) -> bool {
    let cand_norm = normalize_win_path_str(candidate);
    let root_norm = normalize_win_path_str(root);
    is_under_root_normalized(&cand_norm, &root_norm)
}

fn is_under_root_normalized(cand_norm: &str, root_norm: &str) -> bool {
    if cand_norm.is_empty() || root_norm.is_empty() {
        return false;
    }

    if cand_norm == root_norm {
        return true;
    }

    if root_norm.ends_with('\\') {
        cand_norm.starts_with(root_norm)
    } else {
        cand_norm.starts_with(root_norm)
            && cand_norm.as_bytes().get(root_norm.len()) == Some(&b'\\')
    }
}

fn normalize_drive_prefix(drive: &str) -> String {
    let trimmed = drive.trim();
    if let Some(ch) = trimmed.chars().next()
        && ch.is_ascii_alphabetic()
    {
        return format!("{}:", ch.to_ascii_uppercase());
    }
    "C:".to_string()
}

/// Deny reason for anything inside a personal library (Documents, Pictures, Desktop, Videos,
/// Music). Cleanup never touches these folders.
pub const PERSONAL_LIBRARY_REASON: &str = "user personal library is protected";

/// Deny check for the one owner-driven operation allowed inside personal libraries: recycling a
/// single regular file the owner selected after DiskSaver replaced it with a verified smaller copy
/// (video compression). Every other rule (system folders, profile roots, `$Recycle.Bin`, DiskSaver
/// data, ...) still applies; the caller must additionally reject directories.
pub fn is_denied_for_owner_replacement(path: &Path, ctx: &DenyContext) -> Option<&'static str> {
    match is_denied_path(path, ctx) {
        Some(PERSONAL_LIBRARY_REASON) => None,
        other => other,
    }
}

/// Evaluates whether a given path is prohibited by the non-overridable deny list.
///
/// Returns `Some(&'static str)` describing the reason if denied, or `None` if permitted.
pub fn is_denied_path(path: &Path, ctx: &DenyContext) -> Option<&'static str> {
    let p_norm = normalize_win_path_str(path);

    // 1. Empty path
    if p_norm.is_empty() {
        return Some("empty path is denied");
    }

    // 2. Drive root: e.g. "C:\" or any "X:\"
    if matches!(p_norm.as_bytes(), [d, b':', b'\\'] if d.is_ascii_alphabetic()) {
        return Some("drive root is denied");
    }

    // 3. UNC share root: e.g. "\\SERVER\SHARE" or "\\SERVER"
    if let Some(rest) = p_norm.strip_prefix(r"\\") {
        let parts: Vec<&str> = rest.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.len() <= 2 {
            return Some("UNC share root is denied");
        }
    }

    // 4. Drive-level volume protected directories on ANY drive or UNC root:
    // e.g. <any_drive>:\System Volume Information, <any_drive>:\$Extend, <any_drive>:\$Recycle.Bin
    let p_bytes = p_norm.as_bytes();
    if p_bytes.len() >= 3
        && p_bytes[0].is_ascii_alphabetic()
        && p_bytes[1] == b':'
        && p_bytes[2] == b'\\'
    {
        let after_drive = &p_norm[3..];
        let first_seg = after_drive.split('\\').next().unwrap_or("");
        if first_seg == "SYSTEM VOLUME INFORMATION" {
            return Some("System Volume Information is protected");
        }
        if first_seg == "$EXTEND" {
            return Some("$Extend NTFS metadata is protected");
        }
        if first_seg == "$RECYCLE.BIN" {
            return Some("$Recycle.Bin is protected");
        }
    } else if let Some(rest) = p_norm.strip_prefix(r"\\") {
        let parts: Vec<&str> = rest.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.len() >= 3 {
            let first_seg = parts[2];
            if first_seg == "SYSTEM VOLUME INFORMATION" {
                return Some("System Volume Information is protected");
            }
            if first_seg == "$EXTEND" {
                return Some("$Extend NTFS metadata is protected");
            }
            if first_seg == "$RECYCLE.BIN" {
                return Some("$Recycle.Bin is protected");
            }
        }
    }

    // 5. Windows directory:
    // - Exact match on <win> root: DENIED
    // - Recursive subtree on protected subdirs: DENIED
    let win_norm = normalize_win_path_str(Path::new(&ctx.windows_dir));
    if !win_norm.is_empty() {
        if p_norm == win_norm {
            return Some("windows directory root is denied");
        }

        const PROTECTED_WIN_SUBDIRS: &[&str] = &[
            "SYSTEM32",
            "SYSWOW64",
            "WINSXS",
            "INSTALLER",
            "SERVICING",
            r"SOFTWAREDISTRIBUTION\DATASTORE",
        ];

        for sub in PROTECTED_WIN_SUBDIRS {
            let target = format!(r"{win_norm}\{sub}");
            if is_under_root_normalized(&p_norm, &target) {
                return Some("windows system directory is protected");
            }
        }
    }

    // 6. ProgramData:
    // Recursive: <program_data>\Package Cache
    let pdata_norm = normalize_win_path_str(Path::new(&ctx.program_data));
    if !pdata_norm.is_empty() {
        let pkg_cache = format!(r"{pdata_norm}\PACKAGE CACHE");
        if is_under_root_normalized(&p_norm, &pkg_cache) {
            return Some("ProgramData Package Cache is protected");
        }
    }

    // 7. ProgramFiles:
    // Recursive: <program_files>\WindowsApps
    let pfiles_norm = normalize_win_path_str(Path::new(&ctx.program_files));
    if !pfiles_norm.is_empty() {
        let win_apps = format!(r"{pfiles_norm}\WINDOWSAPPS");
        if is_under_root_normalized(&p_norm, &win_apps) {
            return Some("WindowsApps directory is protected");
        }
    }

    // 8. DiskSaver internal storage:
    // Recursive: <local_app_data>\DiskSaver
    if let Some(ref lad) = ctx.local_app_data {
        let lad_norm = normalize_win_path_str(Path::new(lad));
        if !lad_norm.is_empty() {
            let ds = format!(r"{lad_norm}\DISKSAVER");
            if is_under_root_normalized(&p_norm, &ds) {
                return Some("DiskSaver local data is protected");
            }
        }
    }

    // 9. Users root and dynamic user profiles under <system_drive>\Users:
    let sys_drive = normalize_drive_prefix(&ctx.system_drive);
    let users_dir = format!(r"{sys_drive}\USERS");
    if p_norm == users_dir {
        return Some("users directory root is denied");
    }

    let users_prefix = format!(r"{users_dir}\");
    if p_norm.starts_with(&users_prefix) {
        let remainder = &p_norm[users_prefix.len()..];
        let parts: Vec<&str> = remainder.split('\\').filter(|s| !s.is_empty()).collect();
        // Exact profile root: C:\Users\<name>
        if parts.len() == 1 {
            return Some("user profile root is denied");
        }
        if parts.len() >= 2 {
            let top_sub = parts[1];
            if matches!(
                top_sub,
                "DOCUMENTS" | "PICTURES" | "DESKTOP" | "VIDEOS" | "MUSIC"
            ) {
                return Some(PERSONAL_LIBRARY_REASON);
            }
            if parts.len() >= 4
                && parts[1] == "APPDATA"
                && parts[2] == "LOCAL"
                && parts[3] == "DISKSAVER"
            {
                return Some("DiskSaver local data is protected");
            }
        }
    }

    // 10. Configured user profiles in ctx.user_profiles:
    // Exact profile root: DENIED
    // Personal libraries: Documents, Pictures, Desktop, Videos, Music: DENIED
    // AppData\Local\DiskSaver: DENIED
    for prof in &ctx.user_profiles {
        let prof_norm = normalize_win_path_str(Path::new(prof));
        if prof_norm.is_empty() {
            continue;
        }
        if p_norm == prof_norm {
            return Some("user profile root is denied");
        }
        for lib in &["DOCUMENTS", "PICTURES", "DESKTOP", "VIDEOS", "MUSIC"] {
            let lib_path = format!(r"{prof_norm}\{lib}");
            if is_under_root_normalized(&p_norm, &lib_path) {
                return Some(PERSONAL_LIBRARY_REASON);
            }
        }
        let ds_path = format!(r"{prof_norm}\APPDATA\LOCAL\DISKSAVER");
        if is_under_root_normalized(&p_norm, &ds_path) {
            return Some("DiskSaver local data is protected");
        }
    }

    None
}

/// Asserts that a target path is not blocked by the non-overridable deny list.
///
/// Returns `Ok(())` if permitted, or `Err(DskError::DeniedPath(...))` if blocked.
pub fn assert_not_denied(path: &Path, ctx: &DenyContext) -> Result<()> {
    if let Some(reason) = is_denied_path(path, ctx) {
        Err(DskError::DeniedPath(format!(
            "{} ({reason})",
            path.display()
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_replacement_relaxes_only_personal_libraries() {
        let ctx = DenyContext::default_for_test();
        let video = Path::new(r"C:\Users\Alice\Videos\rec.mp4");
        assert_eq!(is_denied_path(video, &ctx), Some(PERSONAL_LIBRARY_REASON));
        assert_eq!(is_denied_for_owner_replacement(video, &ctx), None);
        for p in [
            r"C:\Windows\System32\x.mp4",
            r"C:\Users\Alice",
            r"C:\Users",
            r"D:\$Recycle.Bin\x.mp4",
            r"C:\Users\Alice\AppData\Local\DiskSaver\x.mp4",
            r"C:\",
        ] {
            assert!(
                is_denied_for_owner_replacement(Path::new(p), &ctx).is_some(),
                "{p} must stay denied"
            );
        }
    }

    #[test]
    fn blocks_system_roots_and_protected_dirs() {
        let ctx = DenyContext::default_for_test();

        let blocked = [
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:/Windows/WinSxS/foo",
            r"\\?\C:\ProgramData\Package Cache\bar",
            r"C:\Windows\SoftwareDistribution\DataStore\x",
            r"C:\System Volume Information",
            r"C:\$Recycle.Bin",
            r"C:\",
            "",
            r"\\server\share",
        ];

        for path in blocked {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_some(),
                "expected path '{path}' to be blocked"
            );
            assert!(
                assert_not_denied(Path::new(path), &ctx).is_err(),
                "expected assert_not_denied to return Err for '{path}'"
            );
        }
    }

    #[test]
    fn does_not_confuse_sibling_prefixes() {
        let ctx = DenyContext::default_for_test();

        let allowed = [
            r"C:\Windows\System32Cache",
            r"C:\Windows\Temp",
            r"C:\Windows\SystemTemp",
            r"C:\Windows\Logs\CBS",
            r"C:\Windows\Minidump",
            r"C:\Windows\LiveKernelReports",
            r"C:\Windows\Panther",
            r"C:\Windows\SoftwareDistribution\Download",
        ];

        for path in allowed {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_none(),
                "expected path '{path}' to be allowed"
            );
            assert!(
                assert_not_denied(Path::new(path), &ctx).is_ok(),
                "expected assert_not_denied to return Ok for '{path}'"
            );
        }
    }

    #[test]
    fn blocks_user_profile_and_personal_folders() {
        let ctx = DenyContext::default_for_test();

        let blocked = [
            r"C:\Users",
            r"C:\Users\Alice",
            r"C:\Users\Alice\Documents",
            r"C:\Users\Alice\Documents\tax.pdf",
            r"C:\Users\Alice\Desktop",
            r"C:\Users\Alice\Pictures\vacation.jpg",
            r"C:\Users\Alice\Videos\clip.mp4",
            r"C:\Users\Alice\Music\song.mp3",
            // Dynamic user on system drive not in ctx.user_profiles
            r"C:\Users\Bob",
            r"C:\Users\Bob\Documents\secret.docx",
        ];

        for path in blocked {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_some(),
                "expected path '{path}' to be blocked"
            );
            assert!(
                assert_not_denied(Path::new(path), &ctx).is_err(),
                "expected assert_not_denied to return Err for '{path}'"
            );
        }
    }

    #[test]
    fn allows_dev_and_temp_caches_under_appdata() {
        let ctx = DenyContext::default_for_test();

        let allowed = [
            r"C:\Users\Alice\AppData\Local\Temp\x",
            r"C:\Users\Alice\AppData\Local\Temp",
            r"C:\Users\Alice\AppData\Local\npm-cache",
        ];
        for path in allowed {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_none(),
                "expected path '{path}' to be allowed"
            );
            assert!(
                assert_not_denied(Path::new(path), &ctx).is_ok(),
                "expected assert_not_denied to return Ok for '{path}'"
            );
        }

        let blocked = [
            r"C:\Users\Alice\AppData\Local\DiskSaver\journal.db",
            r"C:\Users\Alice\AppData\Local\DiskSaver",
            r"C:\Users\Alice\AppData\Local\DiskSaver\cache\x",
        ];
        for path in blocked {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_some(),
                "expected path '{path}' to be blocked"
            );
            assert!(
                assert_not_denied(Path::new(path), &ctx).is_err(),
                "expected assert_not_denied to return Err for '{path}'"
            );
        }
    }

    #[test]
    fn blocks_lexical_dot_dot_traversal() {
        let ctx = DenyContext::default_for_test();

        let blocked = [
            r"C:\Windows\Temp\..\System32",
            r"C:\Windows\Temp\..\System32\cmd.exe",
            r"C:\Users\Alice\AppData\Local\Temp\..\..\..\Documents\secret.pdf",
            r"C:\Windows\..\Windows",
        ];

        for path in blocked {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_some(),
                "expected traversal path '{path}' to be blocked"
            );
        }
    }

    #[test]
    fn blocks_secondary_drive_recycle_bin_and_roots() {
        let ctx = DenyContext::default_for_test();

        let blocked = [
            r"D:\$Recycle.Bin",
            r"D:\$Recycle.Bin\S-1-5-21-123456789-1001",
            r"D:\System Volume Information",
            r"D:\$Extend",
            r"D:\$Extend\$UsnJrnl",
            r"D:\",
            r"E:\",
        ];

        for path in blocked {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_some(),
                "expected secondary drive path '{path}' to be blocked"
            );
        }

        let allowed = [r"D:\clean_target", r"D:\clean_target\temp.log"];
        for path in allowed {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_none(),
                "expected secondary drive clean target '{path}' to be allowed"
            );
        }
    }

    #[test]
    fn normalize_win_path_str_contract() {
        assert_eq!(normalize_win_path_str(Path::new("")), "");
        assert_eq!(normalize_win_path_str(Path::new(r"C:\")), r"C:\");
        assert_eq!(normalize_win_path_str(Path::new(r"C:")), r"C:\");
        assert_eq!(
            normalize_win_path_str(Path::new(r"C:\Windows\System32\")),
            r"C:\WINDOWS\SYSTEM32"
        );
        assert_eq!(
            normalize_win_path_str(Path::new(r"c:/windows/system32")),
            r"C:\WINDOWS\SYSTEM32"
        );
        assert_eq!(
            normalize_win_path_str(Path::new(r"\\?\C:\Windows\System32")),
            r"C:\WINDOWS\SYSTEM32"
        );
        assert_eq!(
            normalize_win_path_str(Path::new(r"\\?\UNC\server\share\sub\file.txt")),
            r"\\SERVER\SHARE\SUB\FILE.TXT"
        );
        assert_eq!(
            normalize_win_path_str(Path::new(r"\\server\share\")),
            r"\\SERVER\SHARE"
        );
        assert_eq!(
            normalize_win_path_str(Path::new(r"C:\a\b\..\c\.\d")),
            r"C:\A\C\D"
        );
    }

    #[test]
    fn handles_multibyte_utf8_paths_without_panic() {
        let ctx = DenyContext::default_for_test();

        let allowed = [
            r"C:\ü\foo",
            r"D:\日本語\temp",
            r"C:\Users\Ələkbər\AppData\Local\Temp",
        ];
        for path in allowed {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_none(),
                "expected path '{path}' to be allowed"
            );
        }

        let blocked = [
            r"C:\Users\Ələkbər\Documents\secret.pdf",
            r"C:\Users\Ələkbər",
        ];
        for path in blocked {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_some(),
                "expected path '{path}' to be blocked"
            );
        }
    }

    #[test]
    fn handles_multibyte_utf8_case_insensitive_profiles() {
        let mut ctx = DenyContext::default_for_test();
        ctx.user_profiles.push(r"D:\Profiles\Ələkbər".to_string());
        ctx.user_profiles.push(r"D:\Profiles\Müller".to_string());

        let blocked = [
            r"D:\Profiles\ƏLƏKBƏR",
            r"D:\Profiles\ələkbər\Documents\secret.pdf",
            r"D:\Profiles\ƏLƏKBƏR\Documents\secret.pdf",
            r"D:\Profiles\MÜLLER",
            r"D:\Profiles\MÜLLER\Desktop\notes.txt",
            r"D:\Profiles\müller\AppData\Local\DiskSaver\journal.db",
        ];
        for path in blocked {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_some(),
                "expected non-ASCII case-variant path '{path}' to be blocked"
            );
        }

        let allowed = [
            r"D:\Profiles\ƏLƏKBƏR\AppData\Local\Temp\cache.tmp",
            r"D:\Profiles\MÜLLER\AppData\Local\Temp\cache.tmp",
        ];
        for path in allowed {
            assert!(
                is_denied_path(Path::new(path), &ctx).is_none(),
                "expected non-ASCII temp path '{path}' to be allowed"
            );
        }
    }

    #[test]
    fn is_under_root_component_contract() {
        assert!(is_under_root(
            Path::new(r"C:\Windows\System32"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(is_under_root(
            Path::new(r"C:\Windows\System32\drivers"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!is_under_root(
            Path::new(r"C:\Windows\System32Cache"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!is_under_root(
            Path::new(r"C:\Windows\Temp"),
            Path::new(r"C:\Windows\System32")
        ));
    }
}
