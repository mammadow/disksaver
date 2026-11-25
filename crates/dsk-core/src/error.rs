#![forbid(unsafe_code)]

use thiserror::Error;

/// NTFS filesystem parsing errors.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum NtfsError {
    #[error("bad boot sector")]
    BadBootSector,
    #[error("bad signature")]
    BadSignature,
    #[error("fixup mismatch in sector {sector}")]
    FixupMismatch { sector: usize },
    #[error("truncated: {0}")]
    Truncated(&'static str),
    #[error("bad attribute")]
    BadAttribute,
    #[error("bad run list")]
    BadRunList,
}

/// Disk Saver core error type.
#[derive(Debug, Error)]
pub enum DskError {
    #[error("Win32 error during {ctx}: {code}")]
    Win32 { ctx: &'static str, code: u32 },
    #[error(transparent)]
    Ntfs(#[from] NtfsError),
    #[error("operation requires administrative privileges")]
    NotElevated,
    #[error("not a volume root: {0}")]
    NotVolumeRoot(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("operation cancelled")]
    Cancelled,
    #[error("blocked by global deny-list: {0}")]
    DeniedPath(String),
    #[error("blocked by global deny-list: {0}")]
    Denied(String),
    #[error("optimization error: {0}")]
    Optimize(String),
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("file identity changed since planning: {0}")]
    FileIdMismatch(String),
    #[error("rule parse error: {0}")]
    RuleParse(String),
    #[error("journal error: {0}")]
    Journal(String),
    #[error("IPC error: {0}")]
    Ipc(String),
    #[error("helper authentication error: {0}")]
    HelperAuth(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience Result alias using [`DskError`].
pub type Result<T> = std::result::Result<T, DskError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntfs_error_display() {
        let err: DskError = NtfsError::BadBootSector.into();
        assert!(err.to_string().contains("bad boot sector"));
    }

    #[test]
    fn dsk_error_conversions() {
        let io_err: DskError =
            std::io::Error::new(std::io::ErrorKind::NotFound, "file not found").into();
        assert!(io_err.to_string().contains("file not found"));

        let fixup: DskError = NtfsError::FixupMismatch { sector: 2 }.into();
        assert!(fixup.to_string().contains("sector 2"));

        let win32 = DskError::Win32 {
            ctx: "DeviceIoControl",
            code: 5,
        };
        assert!(win32.to_string().contains("DeviceIoControl"));
        assert!(win32.to_string().contains("5"));

        let unsupp = DskError::Unsupported("ReFS".into());
        assert!(unsupp.to_string().contains("ReFS"));

        let not_root = DskError::NotVolumeRoot("C:\\foo".into());
        assert!(not_root.to_string().contains("C:\\foo"));

        let not_elev = DskError::NotElevated;
        assert!(not_elev.to_string().contains("administrative privileges"));

        let cancelled = DskError::Cancelled;
        assert!(cancelled.to_string().contains("cancelled"));

        let denied = DskError::DeniedPath("C:\\Windows".into());
        assert_eq!(
            denied.to_string(),
            "blocked by global deny-list: C:\\Windows"
        );

        let precond = DskError::PreconditionFailed("process running".into());
        assert_eq!(precond.to_string(), "precondition failed: process running");

        let mismatch = DskError::FileIdMismatch("C:\\foo.tmp".into());
        assert_eq!(
            mismatch.to_string(),
            "file identity changed since planning: C:\\foo.tmp"
        );

        let rule = DskError::RuleParse("missing field".into());
        assert_eq!(rule.to_string(), "rule parse error: missing field");

        let journal = DskError::Journal("db locked".into());
        assert_eq!(journal.to_string(), "journal error: db locked");

        let ipc = DskError::Ipc("pipe broken".into());
        assert_eq!(ipc.to_string(), "IPC error: pipe broken");

        let helper_auth = DskError::HelperAuth("pid mismatch".into());
        assert_eq!(
            helper_auth.to_string(),
            "helper authentication error: pid mismatch"
        );
    }
}
