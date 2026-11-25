//! Hardened installation directory (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`)
//! and atomic deployment of sibling DiskSaver release binaries (§10.3, P8 Task 1).
//!
//! Threat model: an unprivileged process that can write into (or swap) the directory holding
//! `dsk-helper.exe` can impersonate `disksaver-gui.exe` and pass the helper's same-directory peer
//! check, or plant a DLL the elevated helper loads. The installer therefore:
//! 1. refuses targets whose ancestors standard users can rename/re-ACL (they could swap the tree),
//!    and targets reached through junctions/symlinks;
//! 2. creates the directory atomically with an Administrators-owned protected DACL (or re-ACLs an
//!    existing directory through a no-follow handle, rejecting reparse points);
//! 3. verifies the result is not user-writable and that no pre-existing entry is user-controlled
//!    (e.g. a planted `version.dll`);
//! 4. copies binaries via same-directory `.tmp.<pid>` staging + rename.

#![allow(unsafe_code)]

use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING,
};
use windows::core::{BOOL, PCWSTR};

use crate::clean::deny::normalize_win_path_str;
use crate::error::{DskError, Result};
use crate::win::pipe::{
    is_directory_user_renamable, is_directory_user_writable, sddl_grants_non_admin_write,
};
use crate::win::volume::program_files_dir;

/// Protected DACL applied to the DiskSaver install directory (`SYSTEM` & `Administrators`: Full;
/// `Users`: Read & Execute only; inheritance blocked via `D:P`).
pub const PROTECTED_INSTALL_SDDL: &str =
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

const PROTECTED_INSTALL_OWNER_AND_DACL_SDDL: &str =
    "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// Binaries copied into the hardened install directory when present.
pub const INSTALL_BINARY_NAMES: &[&str] = &[
    "disksaver.exe",
    "disksaver-gui.exe",
    "dsk-helper.exe",
    "disksaver-tray.exe",
];

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

/// Summary of an `install-dir` execution (live or `--dry-run`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    pub target_dir: PathBuf,
    pub sddl_applied: String,
    /// `None` for `--dry-run` (nothing was applied or measured); `Some(false)` after a successful
    /// live install (a live install refuses instead of reporting `Some(true)`).
    pub user_writable_after: Option<bool>,
    pub dry_run: bool,
    /// Destination paths copied (live) or that would be copied (`--dry-run`).
    pub copied_binaries: Vec<PathBuf>,
    pub skipped_missing_binaries: Vec<String>,
    /// Pre-flight problems that make a live install refuse (always empty after a live install).
    pub blocking_issues: Vec<String>,
}

/// Default install location: `<FOLDERID_ProgramFiles>\DiskSaver` (normally
/// `C:\Program Files\DiskSaver`).
pub fn default_install_dir() -> PathBuf {
    program_files_dir().join("DiskSaver")
}

fn to_wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_win32_error(ctx: &'static str) -> DskError {
    DskError::Win32 {
        ctx,
        // SAFETY: Reading the calling thread's last-error value.
        code: unsafe { GetLastError() }.0,
    }
}

struct SecurityDescGuard(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescGuard {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: Allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
            self.0 = PSECURITY_DESCRIPTOR::default();
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: Closing a handle opened by `CreateFileW` in this module.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct TempFileGuard(PathBuf, bool);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.1 {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// Self-relative protected security descriptor plus pointers to its owner SID and DACL. The
/// pointers stay valid for the lifetime of the guard.
struct ProtectedSd {
    guard: SecurityDescGuard,
    owner: PSID,
    dacl: *mut ACL,
}

fn build_protected_sd() -> Result<ProtectedSd> {
    let sddl_w = to_wide(PROTECTED_INSTALL_OWNER_AND_DACL_SDDL);
    let mut p_sd = PSECURITY_DESCRIPTOR::default();

    // SAFETY: Converts a constant SDDL string into a security descriptor owned by the guard.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut p_sd,
            None,
        )
    }
    .map_err(|_| {
        last_win32_error("ConvertStringSecurityDescriptorToSecurityDescriptorW(install)")
    })?;
    let guard = SecurityDescGuard(p_sd);

    let mut owner = PSID::default();
    let mut owner_defaulted = BOOL::default();
    let mut dacl_present = BOOL::default();
    let mut dacl: *mut ACL = core::ptr::null_mut();
    let mut dacl_defaulted = BOOL::default();

    // SAFETY: Extracts owner SID and DACL pointers valid for the lifetime of `guard`.
    unsafe {
        GetSecurityDescriptorOwner(p_sd, &mut owner, &mut owner_defaulted)
            .map_err(|_| last_win32_error("GetSecurityDescriptorOwner(install)"))?;
        GetSecurityDescriptorDacl(p_sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
            .map_err(|_| last_win32_error("GetSecurityDescriptorDacl(install)"))?;
    }

    if !dacl_present.as_bool() || dacl.is_null() || owner.0.is_null() {
        return Err(DskError::Io(std::io::Error::other(
            "converted SDDL security descriptor lacked an Owner SID or DACL",
        )));
    }
    Ok(ProtectedSd { guard, owner, dacl })
}

/// Opens an existing directory for `READ_CONTROL | WRITE_DAC | WRITE_OWNER` without following
/// reparse points, and rejects anything that is not a plain directory.
fn open_plain_directory_for_acl(dir: &Path) -> Result<OwnedHandle> {
    let dir_w = to_wide_path(dir);
    // SAFETY: Opening a directory handle with BACKUP_SEMANTICS (required for directories) and
    // OPEN_REPARSE_POINT so a junction/symlink is opened itself rather than followed.
    let h = unsafe {
        CreateFileW(
            PCWSTR(dir_w.as_ptr()),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| last_win32_error("CreateFileW(install_dir)"))?;
    let handle = OwnedHandle(h);

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is a valid open handle and `info` is a properly sized out-structure.
    unsafe { GetFileInformationByHandle(handle.0, &mut info) }
        .map_err(|_| last_win32_error("GetFileInformationByHandle(install_dir)"))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DskError::Denied(format!(
            "refusing to install into '{}': it is a junction/symlink (reparse point)",
            dir.display()
        )));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(DskError::Denied(format!(
            "refusing to install into '{}': not a directory",
            dir.display()
        )));
    }
    Ok(handle)
}

/// Applies `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)` to an existing
/// `target_dir` through a no-follow handle so `BUILTIN\Administrators` owns the folder, inheritance
/// is blocked (`D:P`), and standard users hold strictly Read & Execute access. Inheritable ACEs are
/// propagated to existing children by the system.
pub fn apply_protected_install_dacl(target_dir: &Path) -> Result<()> {
    let handle = open_plain_directory_for_acl(target_dir)?;
    let sd = build_protected_sd()?;
    let sec_info = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;

    // SAFETY: Applies Owner (`BA`) and the protected DACL (both owned by `sd.guard`) to the handle.
    let rc: WIN32_ERROR = unsafe {
        SetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            sec_info,
            Some(sd.owner),
            None,
            Some(sd.dacl as *const ACL),
            None,
        )
    };
    drop(sd.guard);
    if rc != WIN32_ERROR(0) {
        return Err(DskError::Win32 {
            ctx: "SetSecurityInfo(install_dir)",
            code: rc.0,
        });
    }
    Ok(())
}

/// Creates `target_dir` with the protected owner/DACL in one atomic `CreateDirectoryW` call, so
/// there is no window in which inherited (user-writable) ACEs apply. Fails if it already exists.
fn create_protected_install_dir(target_dir: &Path) -> Result<()> {
    let sd = build_protected_sd()?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.guard.0.0,
        bInheritHandle: false.into(),
    };
    let dir_w = to_wide_path(target_dir);
    // SAFETY: `dir_w` is NUL-terminated and `sa` points at a descriptor owned by `sd.guard`.
    unsafe { CreateDirectoryW(PCWSTR(dir_w.as_ptr()), Some(&sa)) }
        .map_err(|_| last_win32_error("CreateDirectoryW(install_dir)"))?;
    Ok(())
}

fn path_is_reparse_point(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
}

/// Returns the reasons a live install into `target_dir` would be refused (empty = OK).
pub fn install_preflight_issues(target_dir: &Path) -> Vec<String> {
    let mut issues = Vec::new();
    let Some(parent) = target_dir.parent() else {
        issues.push("install target has no parent directory".to_string());
        return issues;
    };
    if !parent.is_dir() {
        issues.push(format!(
            "parent directory '{}' does not exist (create it as an administrator first)",
            parent.display()
        ));
        return issues;
    }

    match std::fs::canonicalize(parent) {
        Ok(canon) if normalize_win_path_str(&canon) == normalize_win_path_str(parent) => {}
        Ok(canon) => issues.push(format!(
            "parent directory '{}' is not canonical (resolves to '{}'; junction, symlink, or short name)",
            parent.display(),
            canon.display()
        )),
        Err(e) => issues.push(format!(
            "cannot resolve parent directory '{}': {e}",
            parent.display()
        )),
    }

    for ancestor in parent.ancestors() {
        if is_directory_user_renamable(ancestor) {
            issues.push(format!(
                "ancestor '{}' lets non-admin users rename, delete, or re-ACL its contents (the install directory could be swapped)",
                ancestor.display()
            ));
        }
    }

    if target_dir.exists() || path_is_reparse_point(target_dir) {
        if path_is_reparse_point(target_dir) {
            issues.push(format!(
                "target '{}' is a junction/symlink (reparse point)",
                target_dir.display()
            ));
        } else if !target_dir.is_dir() {
            issues.push(format!(
                "target '{}' exists and is not a directory",
                target_dir.display()
            ));
        }
    }
    issues
}

/// Lists direct entries of `dir` (except the binaries about to be atomically replaced) whose
/// owner/DACL lets standard users modify them, e.g. a DLL planted before the directory was hardened.
pub fn untrusted_install_dir_entries(dir: &Path, replacing: &[&str]) -> Result<Vec<PathBuf>> {
    let mut untrusted = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if replacing.iter().any(|r| r.eq_ignore_ascii_case(&name_str)) {
            continue;
        }
        let path = entry.path();
        if path_is_reparse_point(&path) || is_directory_user_writable(&path) {
            untrusted.push(path);
        }
    }
    Ok(untrusted)
}

/// Atomically copies `src` into `dst` via a sibling `.tmp.<pid>` staging file and `sync_all` + rename.
pub fn atomic_copy_binary(src: &Path, dst: &Path) -> Result<()> {
    let parent = dst.parent().ok_or_else(|| {
        DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination binary path has no parent directory",
        ))
    })?;
    let file_name = dst.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination binary path has invalid filename",
        ))
    })?;

    let tmp_path = parent.join(format!("{file_name}.tmp.{}", std::process::id()));
    let mut guard = TempFileGuard(tmp_path.clone(), false);

    {
        let mut reader = File::open(src)?;
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        std::io::copy(&mut reader, &mut writer)?;
        writer.sync_all()?;
    }
    std::fs::rename(&tmp_path, dst)?;
    guard.1 = true;
    Ok(())
}

/// Hardens `target_dir` with `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`, verifies
/// `!is_directory_user_writable(target_dir)`, and atomically copies available DiskSaver binaries
/// from `source_dir` (defaulting to the current executable's directory).
///
/// `--dry-run` touches nothing and reports `blocking_issues` that a live install would refuse on.
pub fn install_binaries_to_dir(
    target_dir: &Path,
    source_dir: Option<&Path>,
    dry_run: bool,
) -> Result<InstallReport> {
    let has_parent_dir_component = target_dir
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));
    if target_dir.as_os_str().is_empty()
        || !target_dir.is_absolute()
        || target_dir.parent().is_none()
        || has_parent_dir_component
    {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "install target must be an explicit absolute non-root directory without '..' (got '{}')",
                target_dir.display()
            ),
        )));
    }
    if sddl_grants_non_admin_write(PROTECTED_INSTALL_SDDL) {
        return Err(DskError::Denied(
            "internal SDDL constant failed non-admin write verification".to_string(),
        ));
    }

    let resolved_src = match source_dir {
        Some(dir) => dir.to_path_buf(),
        None => std::env::current_exe()?
            .parent()
            .ok_or_else(|| {
                DskError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "current executable has no parent directory",
                ))
            })?
            .to_path_buf(),
    };

    let mut present_pairs = Vec::new();
    let mut present_names = Vec::new();
    let mut skipped_missing = Vec::new();
    for &bin_name in INSTALL_BINARY_NAMES {
        let src = resolved_src.join(bin_name);
        if src.is_file() {
            present_pairs.push((src, target_dir.join(bin_name)));
            present_names.push(bin_name);
        } else {
            skipped_missing.push(bin_name.to_string());
        }
    }

    if present_pairs.is_empty() {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no DiskSaver binaries found in source directory '{}'",
                resolved_src.display()
            ),
        )));
    }

    let issues = install_preflight_issues(target_dir);

    if dry_run {
        return Ok(InstallReport {
            target_dir: target_dir.to_path_buf(),
            sddl_applied: PROTECTED_INSTALL_SDDL.to_string(),
            user_writable_after: None,
            dry_run: true,
            copied_binaries: present_pairs.into_iter().map(|(_, dst)| dst).collect(),
            skipped_missing_binaries: skipped_missing,
            blocking_issues: issues,
        });
    }

    if !issues.is_empty() {
        return Err(DskError::Denied(format!(
            "refusing installation into '{}': {}",
            target_dir.display(),
            issues.join("; ")
        )));
    }

    if target_dir.is_dir() {
        apply_protected_install_dacl(target_dir)?;
    } else {
        create_protected_install_dir(target_dir)?;
    }

    if is_directory_user_writable(target_dir) {
        return Err(DskError::Denied(format!(
            "refusing installation into '{}': directory remained writable by non-admin users after ACL hardening",
            target_dir.display()
        )));
    }

    let untrusted = untrusted_install_dir_entries(target_dir, &present_names)?;
    if !untrusted.is_empty() {
        let list: Vec<String> = untrusted.iter().map(|p| p.display().to_string()).collect();
        return Err(DskError::Denied(format!(
            "refusing installation into '{}': existing entries are controlled by non-admin users (remove them first): {}",
            target_dir.display(),
            list.join(", ")
        )));
    }

    let mut copied = Vec::with_capacity(present_pairs.len());
    for (src, dst) in present_pairs {
        atomic_copy_binary(&src, &dst)?;
        copied.push(dst);
    }

    Ok(InstallReport {
        target_dir: target_dir.to_path_buf(),
        sddl_applied: PROTECTED_INSTALL_SDDL.to_string(),
        user_writable_after: Some(false),
        dry_run: false,
        copied_binaries: copied,
        skipped_missing_binaries: skipped_missing,
        blocking_issues: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win::volume::is_elevated;

    #[test]
    fn protected_install_sddl_blocks_non_admin_writes() {
        assert!(!sddl_grants_non_admin_write(PROTECTED_INSTALL_SDDL));
        assert!(!sddl_grants_non_admin_write(
            PROTECTED_INSTALL_OWNER_AND_DACL_SDDL
        ));
    }

    #[test]
    fn default_install_dir_is_under_program_files() {
        let dir = default_install_dir();
        assert!(dir.is_absolute());
        assert!(dir.ends_with("DiskSaver"));
        assert_eq!(dir.parent().unwrap(), program_files_dir());
    }

    #[test]
    fn install_binaries_dry_run_plans_present_binaries_without_touching_disk() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src_dir = tmp.path().join("release");
        std::fs::create_dir_all(&src_dir).expect("create src_dir");
        std::fs::write(src_dir.join("disksaver.exe"), b"cli").expect("cli");
        std::fs::write(src_dir.join("disksaver-tray.exe"), b"tray").expect("tray");

        let target_dir = tmp.path().join("never_created_install");
        let report =
            install_binaries_to_dir(&target_dir, Some(&src_dir), true).expect("dry-run report");

        assert!(report.dry_run);
        assert_eq!(report.sddl_applied, PROTECTED_INSTALL_SDDL);
        assert_eq!(report.user_writable_after, None);
        assert_eq!(
            report.copied_binaries,
            vec![
                target_dir.join("disksaver.exe"),
                target_dir.join("disksaver-tray.exe"),
            ]
        );
        assert_eq!(
            report.skipped_missing_binaries,
            vec!["disksaver-gui.exe", "dsk-helper.exe"]
        );
        // A temp dir lives under the user's own (renamable) profile: a live install must refuse.
        assert!(
            !report.blocking_issues.is_empty(),
            "user-profile ancestors must be reported as blocking"
        );
        assert!(
            !target_dir.exists(),
            "dry-run must not create target install directory"
        );
    }

    #[test]
    fn install_preflight_accepts_program_files_and_rejects_user_profile_targets() {
        let pf_issues = install_preflight_issues(&program_files_dir().join("DiskSaverProbe"));
        assert!(pf_issues.is_empty(), "unexpected issues: {pf_issues:?}");

        let (_tmp, dir) = crate::win::pipe::tests::make_user_writable_tempdir();
        let issues = install_preflight_issues(&dir.join("DiskSaver"));
        assert!(issues.iter().any(|i| i.contains("ancestor")), "{issues:?}");

        let missing_parent = dir.join("missing").join("DiskSaver");
        let issues = install_preflight_issues(&missing_parent);
        assert!(
            issues.iter().any(|i| i.contains("does not exist")),
            "{issues:?}"
        );
    }

    #[test]
    fn untrusted_entries_flag_user_owned_files_but_skip_replaced_binaries() {
        let (_tmp, dir) = crate::win::pipe::tests::make_user_writable_tempdir();
        std::fs::write(dir.join("version.dll"), b"planted").expect("dll");
        std::fs::write(dir.join("dsk-helper.exe"), b"old").expect("exe");

        let untrusted =
            untrusted_install_dir_entries(&dir, &["DSK-HELPER.EXE"]).expect("enumerate");
        assert_eq!(untrusted, vec![dir.join("version.dll")]);
    }

    #[test]
    fn install_binaries_rejects_relative_root_or_dotdot_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("disksaver.exe"), b"cli").expect("cli");
        assert!(
            install_binaries_to_dir(Path::new("relative_dir"), Some(tmp.path()), true).is_err()
        );
        assert!(install_binaries_to_dir(Path::new(r"C:\"), Some(tmp.path()), true).is_err());
        assert!(
            install_binaries_to_dir(
                Path::new(r"C:\Program Files\..\Users\Public\DiskSaver"),
                Some(tmp.path()),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn atomic_copy_binary_replaces_existing_and_leaves_no_tmp_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("disksaver-new.exe");
        let dst = tmp.path().join("disksaver.exe");
        std::fs::write(&dst, b"old-bytes").expect("write old");
        std::fs::write(&src, b"new-release-bytes").expect("write new");

        atomic_copy_binary(&src, &dst).expect("atomic copy");
        assert_eq!(std::fs::read(&dst).expect("read dst"), b"new-release-bytes");

        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "expected zero leftover temp files");
    }

    #[test]
    fn live_install_refuses_unsafe_targets_without_copying_binaries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src_dir = tmp.path().join("src");
        let dst_dir = tmp.path().join("dst");
        std::fs::create_dir_all(&src_dir).expect("create src");
        std::fs::write(src_dir.join("disksaver.exe"), b"cli").expect("write cli");

        // Refused by the ancestor check (elevated) or the owner/ACL change (unelevated).
        let res = install_binaries_to_dir(&dst_dir, Some(&src_dir), false);
        assert!(res.is_err(), "install under a user profile must be refused");
        assert!(
            !dst_dir.join("disksaver.exe").exists(),
            "must not copy binaries into an unhardened directory"
        );
    }

    #[test]
    #[ignore = "requires administrator privileges; creates and removes C:\\ProgramData\\DiskSaverInstallTest_<pid>"]
    fn elevated_live_install_hardens_dacl_and_copies_atomically() {
        assert!(is_elevated(), "run with Administrator token");
        let tmp = tempfile::tempdir().expect("tempdir");
        let src_dir = tmp.path().join("src");
        std::fs::create_dir_all(&src_dir).expect("create src");
        for bin in INSTALL_BINARY_NAMES {
            std::fs::write(src_dir.join(bin), format!("payload-{bin}")).expect("write mock bin");
        }

        // ProgramData's ancestors are not renamable by standard users.
        let dst_dir = PathBuf::from(r"C:\ProgramData")
            .join(format!("DiskSaverInstallTest_{}", std::process::id()));
        let report = install_binaries_to_dir(&dst_dir, Some(&src_dir), false);
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&dst_dir);
        };
        let report = match report {
            Ok(r) => r,
            Err(e) => {
                cleanup();
                panic!("elevated install failed: {e}");
            }
        };
        let writable = is_directory_user_writable(&dst_dir);
        let all_copied = INSTALL_BINARY_NAMES
            .iter()
            .all(|bin| dst_dir.join(bin).is_file());
        cleanup();

        assert!(!report.dry_run);
        assert_eq!(report.user_writable_after, Some(false));
        assert!(!writable);
        assert_eq!(report.copied_binaries.len(), INSTALL_BINARY_NAMES.len());
        assert!(all_copied);
    }
}
