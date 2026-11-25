use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use dsk_core::error::DskError;
use dsk_core::ntfs::Phase;
use dsk_core::scan::{ScanMethod, ScanOptions, choose_method, scan_volume};

fn opts(method: ScanMethod) -> ScanOptions {
    ScanOptions {
        method,
        threads: None,
        use_cache: false,
    }
}

fn no() -> AtomicBool {
    AtomicBool::new(false)
}

#[test]
fn choose_method_table() {
    use ScanMethod::*;
    assert_eq!(
        choose_method(Auto, Some("C:\\"), "NTFS", true).unwrap(),
        Mft
    );
    assert_eq!(
        choose_method(Auto, Some("C:\\"), "NTFS", false).unwrap(),
        Dir
    );
    assert_eq!(
        choose_method(Auto, Some("E:\\"), "exFAT", true).unwrap(),
        Dir
    );
    assert_eq!(choose_method(Auto, None, "NTFS", true).unwrap(), Dir);
    assert!(matches!(
        choose_method(Mft, None, "NTFS", true),
        Err(DskError::NotVolumeRoot(_))
    ));
    assert!(matches!(
        choose_method(Mft, Some("E:\\"), "exFAT", true),
        Err(DskError::Unsupported(s)) if s == "exFAT"
    ));
    assert!(matches!(
        choose_method(Mft, Some("C:\\"), "NTFS", false),
        Err(DskError::NotElevated)
    ));
    assert_eq!(choose_method(Dir, Some("C:\\"), "NTFS", true).unwrap(), Dir);
}

#[test]
fn folder_auto_uses_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let sub = tmp.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("test.txt"), b"hello").unwrap();

    let r = scan_volume(tmp.path(), &opts(ScanMethod::Auto), &|_| {}, &no()).unwrap();
    assert_eq!(r.method_used, ScanMethod::Dir);
    assert!(r.check.is_none());
    assert!(r.fallback_reason.is_none());
    assert!(r.index.len() >= 2);
}

#[test]
fn folder_dir_uses_dir() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("file.txt"), b"123").unwrap();

    let r = scan_volume(tmp.path(), &opts(ScanMethod::Dir), &|_| {}, &no()).unwrap();
    assert_eq!(r.method_used, ScanMethod::Dir);
    assert!(r.check.is_none());
    assert!(r.fallback_reason.is_none());
}

#[test]
fn mft_on_folder_fails_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let err = scan_volume(tmp.path(), &opts(ScanMethod::Mft), &|_| {}, &no()).unwrap_err();
    match err {
        DskError::NotVolumeRoot(p) => assert_eq!(p, tmp.path().display().to_string()),
        other => panic!("expected NotVolumeRoot, got {other:?}"),
    }
}

#[test]
fn nonexistent_path_fails_io() {
    let bad_path = Path::new("C:\\nonexistent_test_dir_123456789");
    let err = scan_volume(bad_path, &opts(ScanMethod::Auto), &|_| {}, &no()).unwrap_err();
    assert!(matches!(err, DskError::Io(_)));
}

#[test]
fn cancellation_at_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let cancel = AtomicBool::new(true);
    let err = scan_volume(tmp.path(), &opts(ScanMethod::Auto), &|_| {}, &cancel).unwrap_err();
    assert!(matches!(err, DskError::Cancelled));
}

#[test]
fn thread_override_honored() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("f1.txt"), b"data").unwrap();
    let options = ScanOptions {
        method: ScanMethod::Dir,
        threads: Some(1),
        use_cache: false,
    };
    let r = scan_volume(tmp.path(), &options, &|_| {}, &no()).unwrap();
    assert_eq!(r.method_used, ScanMethod::Dir);
    assert!(r.index.len() >= 2);
}

#[test]
fn progress_callback_invoked() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("sample.txt"), b"sample").unwrap();
    let progress_calls = AtomicU64::new(0);
    let r = scan_volume(
        tmp.path(),
        &opts(ScanMethod::Auto),
        &|p| {
            assert!(matches!(p.phase, Phase::Enumerating | Phase::Aggregating));
            progress_calls.fetch_add(1, Ordering::Relaxed);
        },
        &no(),
    )
    .unwrap();
    assert_eq!(r.method_used, ScanMethod::Dir);
    assert!(progress_calls.load(Ordering::Relaxed) > 0);
}

#[test]
fn empty_directory_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let r = scan_volume(tmp.path(), &opts(ScanMethod::Auto), &|_| {}, &no()).unwrap();
    assert_eq!(r.method_used, ScanMethod::Dir);
    assert_eq!(r.index.len(), 1);
}

#[test]
#[ignore = "needs admin"]
fn mft_scan_of_system_drive_passes_check() {
    let r = scan_volume(Path::new("C:\\"), &opts(ScanMethod::Mft), &|_| {}, &no()).unwrap();
    assert_eq!(r.method_used, ScanMethod::Mft);
    let check = r.check.expect("MFT scan should produce UsageCheck");
    assert!(
        check.diff_pct <= 2.0,
        "diff_pct too high: {}% (scanned: {}, volume used: {})",
        check.diff_pct,
        check.scanned_alloc,
        check.volume_used
    );
}
