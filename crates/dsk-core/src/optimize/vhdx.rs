#![forbid(unsafe_code)]

//! Virtual disk discovery (`.vhdx`, `.vhd`), WSL sparse mode toggle, and `diskpart` compactor.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::HANDLE;

use crate::clean::deny::{DenyContext, is_denied_path, normalize_win_path_str};
use crate::error::{DskError, Result};
use crate::index::Index;
use crate::win::cleaner::final_path_by_handle;
use crate::win::preconditions::find_locking_processes;
use crate::win::process::hidden_command;
use crate::win::volume::system32_dir;
use crate::win::wsl::{WslDistro, registered_wsl_distros};

/// Type/provenance of a discovered virtual disk container.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VhdxKind {
    WslDistro,
    DockerDesktop,
    WsaLeftover,
    HyperVOrVirtualBox,
}

/// Metadata and compaction potential for a discovered virtual hard disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdxCandidate {
    pub path: PathBuf,
    pub kind: VhdxKind,
    pub distro_name: Option<String>,
    pub host_allocated_bytes: u64,
    pub guest_used_bytes: Option<u64>,
    pub est_reclaimable_bytes: u64,
    pub locked_by: Vec<String>,
}

/// Outcome report returned after virtual disk compaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdxCompactReport {
    pub vhdx_path: PathBuf,
    pub before_allocated_bytes: u64,
    pub after_allocated_bytes: u64,
    pub freed_bytes: u64,
    pub sparse_enabled: bool,
    pub elapsed_ms: u64,
    pub dry_run: bool,
    /// `Some(true)` when an in-guest `fstrim` ran first, `Some(false)` when it failed.
    #[serde(default)]
    pub trimmed: Option<bool>,
}

/// Parses output from `wsl.exe -d <distro> -- df -B1 /` to compute guest usage.
pub fn parse_wsl_df_output(df_stdout: &str) -> Option<u64> {
    for line in df_stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            return parts[2].parse::<u64>().ok();
        }
    }
    None
}

/// Scans the index for `.vhdx`, `.vhd`, `.vdi`, and `.vmdk` files, naming WSL disks after the
/// current user's registered distros.
pub fn discover_vhdx_candidates(index: &Index) -> Vec<VhdxCandidate> {
    discover_vhdx_candidates_with_distros(index, &registered_wsl_distros())
}

/// Returns the registered distro whose virtual disk is `vhdx_path`.
fn distro_for_vhdx<'a>(vhdx_path: &Path, distros: &'a [WslDistro]) -> Option<&'a WslDistro> {
    let target = normalize_win_path_str(vhdx_path);
    distros
        .iter()
        .find(|d| normalize_win_path_str(&d.vhdx_path).eq_ignore_ascii_case(&target))
}

/// [`discover_vhdx_candidates`] with an explicit distro list.
///
/// `distro_name` is set only from the registry: it is passed to `wsl --manage <name>
/// --set-sparse`, so a name guessed from the path (e.g. "WSL" for `wsl\{GUID}\ext4.vhdx`) would
/// target a distro that does not exist.
pub fn discover_vhdx_candidates_with_distros(
    index: &Index,
    distros: &[WslDistro],
) -> Vec<VhdxCandidate> {
    let mut candidates = Vec::new();

    for node in 0..index.len() as u32 {
        if index.flags(node).contains(crate::index::NodeFlags::DIR) {
            continue;
        }

        let name = index.name(node);
        let name_lower = name.to_ascii_lowercase();

        if !name_lower.ends_with(".vhdx")
            && !name_lower.ends_with(".vhd")
            && !name_lower.ends_with(".vdi")
            && !name_lower.ends_with(".vmdk")
        {
            continue;
        }

        let full_path = index.path(node);
        let full_path_lower = full_path.to_string_lossy().to_ascii_lowercase();

        let registered = distro_for_vhdx(&full_path, distros);
        let (kind, distro_name) = if full_path_lower.contains("docker")
            || registered.is_some_and(|d| d.name.eq_ignore_ascii_case("docker-desktop"))
        {
            // Docker Desktop manages its own disks; no sparse toggle from here.
            (VhdxKind::DockerDesktop, None)
        } else if let Some(d) = registered {
            (VhdxKind::WslDistro, Some(d.name.clone()))
        } else if full_path_lower.contains("wsa") || full_path_lower.contains("subsystemforandroid")
        {
            (VhdxKind::WsaLeftover, None)
        } else if full_path_lower.contains("canonical")
            || full_path_lower.contains("ubuntu")
            || full_path_lower.contains("debian")
            || full_path_lower.contains("wsl")
            || name_lower == "ext4.vhdx"
        {
            // Looks like WSL but is not registered for this user: unknown distro name.
            (VhdxKind::WslDistro, None)
        } else {
            (VhdxKind::HyperVOrVirtualBox, None)
        };

        let host_alloc = index.allocated(node);
        let locked_by = find_locking_processes(&full_path);
        // P9.4: read-only look inside (fails harmlessly while the disk is attached).
        let inspection = if locked_by.is_empty() && name_lower.ends_with(".vhdx") {
            crate::optimize::vhdx_inspect::inspect_vhdx(&full_path).ok()
        } else {
            None
        };
        let guest_used_bytes = inspection
            .as_ref()
            .and_then(|i| i.guest.as_ref())
            .map(|g| g.data_bytes);
        let est_reclaimable_bytes = inspection
            .as_ref()
            .and_then(|i| i.reclaimable_upper_bound())
            .map(|b| b.min(host_alloc))
            .unwrap_or(0);

        candidates.push(VhdxCandidate {
            path: full_path,
            kind,
            distro_name,
            host_allocated_bytes: host_alloc,
            guest_used_bytes,
            est_reclaimable_bytes,
            locked_by,
        });
    }

    candidates
}

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Builds a verified `diskpart` script to compact a VHDX safely (§8.5).
pub fn build_diskpart_compact_script(vhdx_path: &Path) -> Result<String> {
    let path_str = vhdx_path.to_string_lossy();
    if path_str.is_empty()
        || path_str.contains('\0')
        || path_str.contains('"')
        || path_str.contains('\n')
        || path_str.contains('\r')
    {
        return Err(DskError::Optimize(format!(
            "invalid characters in VHDX path: '{path_str}'"
        )));
    }

    let lower = path_str.to_ascii_lowercase();
    if !lower.ends_with(".vhdx") && !lower.ends_with(".vhd") {
        return Err(DskError::Optimize(format!(
            "diskpart compaction supports only .vhdx or .vhd files (got '{path_str}')"
        )));
    }

    let deny_ctx = DenyContext::default();
    if let Some(reason) = is_denied_path(vhdx_path, &deny_ctx) {
        return Err(DskError::Denied(format!(
            "path '{path_str}' is denied: {reason}"
        )));
    }

    let norm = path_str.replace('/', "\\");
    Ok(format!(
        "select vdisk file=\"{norm}\"\nattach vdisk readonly\ncompact vdisk\ndetach vdisk\nexit\n"
    ))
}

/// Builds a best-effort `detach vdisk` script used after a failed compaction.
pub fn build_diskpart_detach_script(vhdx_path: &Path) -> Result<String> {
    let full = build_diskpart_compact_script(vhdx_path)?;
    let select = full.lines().next().unwrap_or_default();
    Ok(format!("{select}\ndetach vdisk\nexit\n"))
}

/// WSL distros and Docker Desktop keep their `.vhdx` attached inside the WSL2 VM.
fn vhdx_needs_wsl_shutdown(vhdx_path: &Path) -> bool {
    let lower = vhdx_path.to_string_lossy().to_ascii_lowercase();
    let name = vhdx_path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name == "ext4.vhdx"
        || ["wsl", "docker", "canonical", "ubuntu", "debian"]
            .iter()
            .any(|k| lower.contains(k))
}

const FILE_SHARE_READ: u32 = 0x1;

/// Writes `script` to a unique temp file and runs `diskpart /s <file>` while holding the file open
/// with read-only sharing.
///
/// The script lives in the (user-writable) `%TEMP%` and diskpart re-opens it by path, so a
/// medium-integrity process could otherwise swap it for `select disk 0` / `clean` before the
/// elevated diskpart reads it. Holding a `FILE_SHARE_READ`-only handle blocks writes, deletes and
/// renames of the file *and of every parent directory*; the content and final path are re-verified
/// through that handle before diskpart starts.
fn run_diskpart_script(diskpart_bin: &Path, script: &str) -> Result<std::process::Output> {
    // Long-name, non-verbatim temp dir so the final-path comparison below is exact even when
    // %TEMP% is an 8.3 short path.
    let canon_tmp = std::fs::canonicalize(std::env::temp_dir())?;
    let canon_str = canon_tmp.to_string_lossy();
    let temp_base = match canon_str.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => canon_tmp.clone(),
    };
    let pinned = write_and_pin_script(&temp_base, script)?;

    let out = hidden_command(diskpart_bin)
        .arg("/s")
        .arg(&pinned.path)
        .output()?;
    drop(pinned);
    Ok(out)
}

/// A script file pinned open with read-only sharing; deleted on drop.
struct PinnedScript {
    path: PathBuf,
    _handle: std::fs::File,
    _guard: TempFileGuard,
}

/// Creates a uniquely named script in `dir`, re-opens it with `FILE_SHARE_READ` only, and verifies
/// content and final path through that handle.
fn write_and_pin_script(dir: &Path, script: &str) -> Result<PinnedScript> {
    let script_path = dir.join(format!(
        "disksaver_compact_{}_{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let script_guard = TempFileGuard(script_path.clone());
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&script_path)?;
        f.write_all(script.as_bytes())?;
        f.sync_all()?;
    }

    // Re-open read-only with read-only sharing and pin it for the lifetime of the diskpart run.
    let mut pinned = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&script_path)?;
    let mut on_disk = String::new();
    pinned.read_to_string(&mut on_disk)?;
    if on_disk != script {
        return Err(DskError::Optimize(
            "diskpart script was modified before it could be pinned; aborting".to_string(),
        ));
    }
    let final_path = final_path_by_handle(HANDLE(pinned.as_raw_handle()))?;
    if normalize_win_path_str(&final_path) != normalize_win_path_str(&script_path) {
        return Err(DskError::Optimize(format!(
            "diskpart script path was redirected to '{}'; aborting",
            final_path.display()
        )));
    }

    Ok(PinnedScript {
        path: script_path,
        _handle: pinned,
        _guard: script_guard,
    })
}

/// Compacts a target VHDX using pinned `System32\diskpart.exe` (and `System32\wsl.exe` when enabled),
/// ensuring all locking processes are stopped first and temporary script files are always removed.
pub fn compact_vhdx(
    vhdx_path: &Path,
    enable_wsl_sparse: Option<&str>,
    dry_run: bool,
) -> Result<VhdxCompactReport> {
    compact_vhdx_with(
        vhdx_path,
        &VhdxCompactOptions {
            sparse_distro: enable_wsl_sparse.map(str::to_string),
            trim_distro: None,
        },
        dry_run,
    )
}

/// Options for [`compact_vhdx_with`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VhdxCompactOptions {
    /// Turn on lasting sparse mode for this registered distro.
    pub sparse_distro: Option<String>,
    /// Run `fstrim -av` as root inside this registered distro first, so blocks the guest freed
    /// are released to the host. Without a trim, compaction can only drop blocks the guest never
    /// wrote.
    pub trim_distro: Option<String>,
}

/// Distro names go on a `wsl.exe` command line: allow only what WSL itself accepts.
pub fn is_valid_distro_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// [`compact_vhdx`] with an optional in-guest trim (P9.4).
pub fn compact_vhdx_with(
    vhdx_path: &Path,
    opts: &VhdxCompactOptions,
    dry_run: bool,
) -> Result<VhdxCompactReport> {
    let enable_wsl_sparse = opts.sparse_distro.as_deref();
    for d in opts.sparse_distro.iter().chain(opts.trim_distro.iter()) {
        if !is_valid_distro_name(d) {
            return Err(DskError::Optimize(format!(
                "invalid WSL distro name: '{d}'"
            )));
        }
    }
    let start = Instant::now();
    let before_alloc = std::fs::metadata(vhdx_path).map(|m| m.len()).unwrap_or(0);

    let script = build_diskpart_compact_script(vhdx_path)?;

    if dry_run {
        return Ok(VhdxCompactReport {
            vhdx_path: vhdx_path.to_path_buf(),
            before_allocated_bytes: before_alloc,
            after_allocated_bytes: before_alloc,
            freed_bytes: 0,
            sparse_enabled: enable_wsl_sparse.is_some(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            trimmed: None,
        });
    }

    let sys32 = system32_dir();
    let wsl_bin = sys32.join("wsl.exe");
    let diskpart_bin = sys32.join("diskpart.exe");

    // 0. Trim inside the guest so freed ext4 blocks are unmapped in the VHDX (P9.4). A failed
    //    trim is not fatal: compaction still drops never-written blocks.
    let trimmed = opts.trim_distro.as_deref().map(|distro| {
        hidden_command(&wsl_bin)
            .args(["-d", distro, "-u", "root", "--", "fstrim", "-av"])
            .output()
            .is_ok_and(|o| o.status.success())
    });

    // 1. WSL / Docker Desktop disks are held open by the WSL2 VM: shut it down first via the pinned
    //    System32 binary, then give the VM a moment to release the file.
    if enable_wsl_sparse.is_some()
        || opts.trim_distro.is_some()
        || vhdx_needs_wsl_shutdown(vhdx_path)
    {
        let shutdown = hidden_command(&wsl_bin).arg("--shutdown").output();
        if let Ok(out) = &shutdown
            && !out.status.success()
        {
            return Err(DskError::Optimize(format!(
                "wsl --shutdown failed (exit {:?}); refusing to compact a possibly attached disk",
                out.status.code()
            )));
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // 2. Verify nothing holds the disk. Restart Manager reports holders by name (but returns an
    //    empty list on its own errors), so an exclusive open is the authoritative lock test.
    let locking = find_locking_processes(vhdx_path);
    if !locking.is_empty() {
        return Err(DskError::Optimize(format!(
            "VHDX is locked by running processes: {}",
            locking.join(", ")
        )));
    }
    if let Err(e) = OpenOptions::new().read(true).share_mode(0).open(vhdx_path) {
        return Err(DskError::Optimize(format!(
            "VHDX '{}' is in use or unreadable ({e}); close the VM/WSL distro and retry",
            vhdx_path.display()
        )));
    }

    // 3. Optional sparse mode toggle via pinned System32 wsl.exe
    let mut sparse_ok = false;
    if let Some(distro) = enable_wsl_sparse {
        let out = hidden_command(&wsl_bin)
            .args(["--manage", distro, "--set-sparse", "true"])
            .output();
        if let Ok(res) = out {
            sparse_ok = res.status.success();
        }
    }

    // 4. Run the script through a pinned, swap-proof script file.
    let out = run_diskpart_script(&diskpart_bin, &script)?;

    if !out.status.success() {
        // diskpart `/s` stops at the first failing command, which can leave the disk attached
        // read-only (WSL then refuses to start): always attempt a detach.
        if let Ok(detach) = build_diskpart_detach_script(vhdx_path) {
            let _ = run_diskpart_script(&diskpart_bin, &detach);
        }
        let err_text = String::from_utf8_lossy(&out.stdout).to_string();
        return Err(DskError::Optimize(format!("diskpart failed: {err_text}")));
    }

    let after_alloc = std::fs::metadata(vhdx_path).map(|m| m.len()).unwrap_or(0);
    let freed = before_alloc.saturating_sub(after_alloc);

    Ok(VhdxCompactReport {
        vhdx_path: vhdx_path.to_path_buf(),
        before_allocated_bytes: before_alloc,
        after_allocated_bytes: after_alloc,
        freed_bytes: freed,
        sparse_enabled: sparse_ok,
        elapsed_ms: start.elapsed().as_millis() as u64,
        dry_run: false,
        trimmed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeFlags;
    use crate::index::builder::{EntryBatch, IndexBuilder, RawEntry};
    use crate::index::names::NameArena;
    use crate::volume_info;

    #[test]
    fn parse_wsl_df_output_computes_reclaimable_headroom() {
        let df_stdout = "Filesystem     1B-blocks        Used   Available Use% Mounted on\n\
                         /dev/sdc     1081101172736 12345678900 1013725806592   2% /";
        let used = parse_wsl_df_output(df_stdout);
        assert_eq!(used, Some(12345678900));

        // Bad output
        assert_eq!(parse_wsl_df_output("invalid output"), None);
    }

    #[test]
    fn build_diskpart_script_escapes_and_rejects_invalid_paths() {
        let valid_path = Path::new(r"C:\WSL\ext4.vhdx");
        let script = build_diskpart_compact_script(valid_path).expect("valid script");
        assert!(script.contains(r#"select vdisk file="C:\WSL\ext4.vhdx""#));
        assert!(script.contains("attach vdisk readonly"));
        assert!(script.contains("compact vdisk"));
        assert!(script.contains("detach vdisk"));

        // Path with quote
        let evil_path = Path::new("C:\\WSL\\ext4.vhdx\"\nexit");
        assert!(build_diskpart_compact_script(evil_path).is_err());
    }

    #[test]
    fn discover_vhdx_identifies_docker_and_wsl_ext4_vhdx_in_index() {
        let mut names = NameArena::new();
        let mut b = IndexBuilder::new(5, r"C:\", volume_info(r"C:\").unwrap_or_default());

        let n_root = names.push_str("C:");
        let n_wsl = names.push_str("CanonicalGroup");
        let n_ext4 = names.push_str("ext4.vhdx");
        let n_docker = names.push_str("DockerDesktop.vhdx");

        let batch = EntryBatch {
            entries: vec![
                RawEntry {
                    key: 5,
                    parent_key: 5,
                    name: n_root,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 5,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    name: n_wsl,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 10,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 10,
                    name: n_ext4,
                    flags: NodeFlags::empty(),
                    logical: 50_000_000_000,
                    allocated: 50_000_000_000,
                    mtime: 0,
                    atime: 0,
                    file_id: 11,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 12,
                    parent_key: 5,
                    name: n_docker,
                    flags: NodeFlags::empty(),
                    logical: 20_000_000_000,
                    allocated: 20_000_000_000,
                    mtime: 0,
                    atime: 0,
                    file_id: 12,
                    reparse_tag: 0,
                },
            ],
            names,
        };

        b.push_batch(batch);
        let index = b.finish();

        let candidates = discover_vhdx_candidates_with_distros(&index, &[]);
        assert_eq!(candidates.len(), 2);

        let wsl_cand = candidates
            .iter()
            .find(|c| c.kind == VhdxKind::WslDistro)
            .expect("wsl cand");
        assert_eq!(wsl_cand.host_allocated_bytes, 50_000_000_000);
        // Unregistered: no guessed name, so no `--set-sparse` against a non-existent distro.
        assert_eq!(wsl_cand.distro_name, None);

        // Registered under a different display name than the path suggests.
        let distros = [WslDistro {
            name: "Ubuntu-24.04".to_string(),
            base_path: PathBuf::from(r"c:\CanonicalGroup"),
            vhdx_path: PathBuf::from(r"C:\CanonicalGroup\ext4.vhdx"),
        }];
        let named = discover_vhdx_candidates_with_distros(&index, &distros);
        let wsl_named = named
            .iter()
            .find(|c| c.kind == VhdxKind::WslDistro)
            .expect("wsl cand");
        assert_eq!(wsl_named.distro_name.as_deref(), Some("Ubuntu-24.04"));

        let docker_cand = candidates
            .iter()
            .find(|c| c.kind == VhdxKind::DockerDesktop)
            .expect("docker cand");
        assert_eq!(docker_cand.host_allocated_bytes, 20_000_000_000);
    }

    #[test]
    fn temp_file_guard_and_script_validation_enforce_hygiene() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("diskpart_temp_guard.txt");
        {
            let _guard = TempFileGuard(sentinel.clone());
            std::fs::write(&sentinel, b"temp script").unwrap();
            assert!(sentinel.exists());
        }
        assert!(
            !sentinel.exists(),
            "TempFileGuard must delete temporary diskpart script on drop"
        );

        assert!(build_diskpart_compact_script(Path::new("")).is_err());
        assert!(build_diskpart_compact_script(Path::new("C:\\WSL\\bad\0.vhdx")).is_err());
        assert!(build_diskpart_compact_script(Path::new(r"C:\WSL\not_vhdx.txt")).is_err());
        assert!(build_diskpart_compact_script(Path::new(r"C:\WSL\disk.vhd")).is_ok());
    }

    #[test]
    fn detach_script_and_wsl_shutdown_detection() {
        let detach = build_diskpart_detach_script(Path::new(r"C:\WSL\ext4.vhdx")).unwrap();
        assert_eq!(
            detach,
            "select vdisk file=\"C:\\WSL\\ext4.vhdx\"\ndetach vdisk\nexit\n"
        );
        assert!(build_diskpart_detach_script(Path::new("C:\\a\"\nclean.vhdx")).is_err());

        assert!(vhdx_needs_wsl_shutdown(Path::new(r"D:\distros\ext4.vhdx")));
        assert!(vhdx_needs_wsl_shutdown(Path::new(
            r"C:\Users\u\AppData\Local\Docker\wsl\disk\docker_data.vhdx"
        )));
        assert!(!vhdx_needs_wsl_shutdown(Path::new(r"D:\VMs\win11.vhdx")));
    }

    #[test]
    fn pinned_diskpart_script_cannot_be_swapped_or_moved() {
        let tmp = tempfile::tempdir().unwrap();
        let canon = std::fs::canonicalize(tmp.path()).unwrap();
        let base = PathBuf::from(canon.to_string_lossy().trim_start_matches(r"\\?\"));
        let subdir = base.join("scripts");
        std::fs::create_dir(&subdir).unwrap();

        let script = "select vdisk file=\"C:\\x.vhdx\"\nexit\n";
        let pinned = write_and_pin_script(&subdir, script).expect("pin script");
        assert_eq!(std::fs::read_to_string(&pinned.path).unwrap(), script);

        // While pinned: no writes, no rename/delete of the file, no rename of its directory.
        assert!(std::fs::write(&pinned.path, "select disk 0\nclean\n").is_err());
        assert!(std::fs::rename(&pinned.path, subdir.join("moved.txt")).is_err());
        assert!(std::fs::rename(&subdir, base.join("scripts_moved")).is_err());
        assert_eq!(std::fs::read_to_string(&pinned.path).unwrap(), script);

        let path = pinned.path.clone();
        drop(pinned);
        assert!(!path.exists(), "pinned script must be deleted on drop");
    }
}
