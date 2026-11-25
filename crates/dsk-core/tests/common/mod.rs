#![allow(dead_code)]

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{FSCTL_SET_COMPRESSION, FSCTL_SET_SPARSE};

pub const COMPRESSION_FORMAT_DEFAULT: u16 = 1;

/// Sets the sparse flag on an open file handle using `FSCTL_SET_SPARSE`.
pub fn set_sparse(file: &File) {
    let handle = HANDLE(file.as_raw_handle());
    let mut bytes_returned = 0u32;
    let res = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_SPARSE,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };
    res.expect("FSCTL_SET_SPARSE failed");
}

/// Sets compression on an open file handle using `FSCTL_SET_COMPRESSION`.
pub fn set_compressed(file: &File) {
    let handle = HANDLE(file.as_raw_handle());
    let mut format = COMPRESSION_FORMAT_DEFAULT;
    let mut bytes_returned = 0u32;
    let res = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_COMPRESSION,
            Some(&mut format as *mut u16 as *const c_void),
            std::mem::size_of::<u16>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };
    res.expect("FSCTL_SET_COMPRESSION failed");
}

/// Creates a directory junction (`mklink /J`) pointing `link` to `target`.
pub fn make_junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .expect("failed to execute mklink /J");
    assert!(
        status.success(),
        "mklink /J failed: exit code {:?}",
        status.code()
    );
}

/// RAII guard that restores access to a directory upon drop.
pub struct DenyGuard {
    path: PathBuf,
    username: String,
}

impl Drop for DenyGuard {
    fn drop(&mut self) {
        let _ = Command::new("icacls")
            .arg(&self.path)
            .args(["/remove:d", &self.username])
            .status();
    }
}

/// Denies read/execution access on a directory using `icacls <dir> /deny %USERNAME%:(RX)`.
pub fn deny_read(dir: &Path) -> DenyGuard {
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "Everyone".into());
    let status = Command::new("icacls")
        .arg(dir)
        .args(["/deny", &format!("{}:(RX)", username)])
        .status()
        .expect("failed to execute icacls /deny");
    assert!(
        status.success(),
        "icacls /deny failed: exit code {:?}",
        status.code()
    );

    DenyGuard {
        path: dir.to_path_buf(),
        username,
    }
}
