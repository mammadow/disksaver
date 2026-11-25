//! Windowless child-process construction for every background tool DiskSaver launches.
//!
//! The GUI, tray agent, and elevated helper are `windows`-subsystem binaries in release builds.
//! A console-subsystem child (`vssadmin`, `Dism`, `powercfg`, `compact`, `pnputil`, `wsl`,
//! `diskpart`, `schtasks`, rule tools, …) started from such a process gets a brand-new console
//! window unless `CREATE_NO_WINDOW` is passed, which shows up as a flashing black window on every
//! probe. All background spawns go through [`hidden_command`] / [`hidden_command_with_flags`]; a
//! source-level regression test below fails if a new bare `Command::new` slips into production
//! code in `dsk-core`, `dsk-helper`, or `dsk-tray`.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::process::CommandExt;
use std::process::Command;

/// `CREATE_NO_WINDOW`: a console child runs without a console window (ignored by GUI children).
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `BELOW_NORMAL_PRIORITY_CLASS`: background work that must not compete with the foreground.
pub const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;

/// Builds a [`Command`] whose console (if any) is never shown.
pub fn hidden_command(program: impl AsRef<OsStr>) -> Command {
    hidden_command_with_flags(program, 0)
}

/// Builds a windowless [`Command`] with additional process creation flags (for example
/// [`BELOW_NORMAL_PRIORITY_CLASS`]). `CommandExt::creation_flags` *replaces* earlier flags, so
/// callers must pass every flag they need here instead of calling `creation_flags` again.
pub fn hidden_command_with_flags(program: impl AsRef<OsStr>, extra_flags: u32) -> Command {
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW | extra_flags);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn flag_constants_match_win32_headers() {
        assert_eq!(
            CREATE_NO_WINDOW,
            windows::Win32::System::Threading::CREATE_NO_WINDOW.0
        );
        assert_eq!(
            BELOW_NORMAL_PRIORITY_CLASS,
            windows::Win32::System::Threading::BELOW_NORMAL_PRIORITY_CLASS.0
        );
    }

    #[test]
    fn hidden_command_runs_console_tools_and_captures_output() {
        let cmd_exe = crate::win::volume::system32_dir().join("cmd.exe");
        let out = hidden_command_with_flags(&cmd_exe, BELOW_NORMAL_PRIORITY_CLASS)
            .args(["/d", "/c", "echo dsk-windowless"])
            .output()
            .expect("run cmd.exe windowless");
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("dsk-windowless"));
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_rs_files(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }

    /// Regression guard: production code in the background crates must not construct a bare
    /// `Command::new` (which flashes a console window from a windows-subsystem parent). Test
    /// modules (everything after the first `#[cfg(test)]`) and this file are exempt.
    #[test]
    fn production_sources_never_spawn_bare_commands() {
        let core_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let roots = [
            core_dir.join("src"),
            core_dir.join("..").join("dsk-helper").join("src"),
            core_dir.join("..").join("dsk-tray").join("src"),
        ];
        let mut files = Vec::new();
        for r in &roots {
            collect_rs_files(r, &mut files);
        }
        assert!(files.len() > 20, "expected to scan the crate sources");

        let mut offenders = Vec::new();
        for f in files {
            if f.file_name().is_some_and(|n| n == "process.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            let prod = text.split("#[cfg(test)]").next().unwrap_or("");
            for (i, line) in prod.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("Command::new(") {
                    offenders.push(format!("{}:{}", f.display(), i + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "use win::process::hidden_command instead of Command::new: {offenders:?}"
        );
    }
}
