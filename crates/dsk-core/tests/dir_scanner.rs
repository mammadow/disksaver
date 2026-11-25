mod common;

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use std::sync::atomic::AtomicBool;

use dsk_core::error::DskError;
use dsk_core::index::{Index, NodeFlags, NodeId, ROOT};
use dsk_core::volume::VolumeInfo;
use dsk_core::win::{DirScanOptions, scan_dirs, volume_info};
use tempfile::TempDir;

use common::{deny_read, make_junction, set_compressed, set_sparse};

fn round_up(val: u64, cluster: u32) -> u64 {
    let c = cluster as u64;
    if c <= 1 { val } else { val.div_ceil(c) * c }
}

fn child(ix: &Index, parent: NodeId, name: &str) -> NodeId {
    ix.children(parent)
        .find(|&c| ix.name(c) == name)
        .unwrap_or_else(|| panic!("child with name '{}' not found", name))
}

fn get_c_volume() -> VolumeInfo {
    volume_info(r"C:\").unwrap_or_else(|_| VolumeInfo {
        root: r"\\?\C:\".into(),
        fs_name: "NTFS".into(),
        cluster_size: 4096,
        ..Default::default()
    })
}

fn new_temp_dir() -> TempDir {
    // Ensure the temp directory is on C: for NTFS support
    let local_temp =
        std::env::var_os("LOCALAPPDATA").map(|p| std::path::PathBuf::from(p).join("Temp"));
    local_temp
        .as_deref()
        .and_then(|p| TempDir::new_in(p).ok())
        .or_else(|| TempDir::new_in(std::env::temp_dir()).ok())
        .unwrap_or_else(|| TempDir::new().unwrap())
}

#[test]
fn counts_files_and_sizes() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();
    let cluster = vol.cluster_size.max(4096);

    std::fs::write(root.join("f1.bin"), vec![0x41; 10_000]).unwrap();
    std::fs::write(root.join("f2.bin"), vec![0x42; 10_000]).unwrap();
    std::fs::write(root.join("f3.bin"), vec![0x43; 10_000]).unwrap();

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(root, vol, &opts, &|_| {}, &cancel).unwrap();
    let ix = out.index;

    assert_eq!(ix.file_count(ROOT), 3);
    assert_eq!(ix.total_allocated(ROOT), 3 * round_up(10_000, cluster));
}

#[test]
fn hard_link_counted_once() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();
    let cluster = vol.cluster_size.max(4096);

    let f1 = root.join("original.bin");
    let f2 = root.join("link.bin");
    std::fs::write(&f1, vec![0xAA; 100_000]).unwrap();
    std::fs::hard_link(&f1, &f2).unwrap();

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(root, vol, &opts, &|_| {}, &cancel).unwrap();
    let ix = out.index;

    assert_eq!(ix.total_allocated(ROOT), round_up(100_000, cluster));
}

#[test]
fn junction_not_traversed() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();

    let target = root.join("target_dir");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("nested.txt"), b"inside target").unwrap();

    let j_path = root.join("j");
    make_junction(&j_path, &target);

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(root, vol, &opts, &|_| {}, &cancel).unwrap();
    let ix = out.index;

    let j = child(&ix, ROOT, "j");
    assert!(ix.flags(j).contains(NodeFlags::REPARSE));
    assert_eq!(ix.children(j).count(), 0);
}

#[test]
fn sparse_file_small_allocation() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();

    let f_path = root.join("sparse.bin");
    let file = File::create(&f_path).unwrap();
    set_sparse(&file);
    file.set_len(1 << 30).unwrap(); // 1 GiB logical
    drop(file);

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(root, vol, &opts, &|_| {}, &cancel).unwrap();
    let ix = out.index;

    let f = child(&ix, ROOT, "sparse.bin");
    assert_eq!(ix.logical(f), 1 << 30);
    assert!(ix.allocated(f) < 1 << 20);
    assert!(ix.flags(f).contains(NodeFlags::SPARSE));
}

#[test]
fn compressed_file_refined() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();

    let f_path = root.join("compressed.bin");
    let mut file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&f_path)
        .unwrap();
    set_compressed(&file);
    let zeroes = vec![0u8; 2 * 1024 * 1024]; // 2 MiB zeroes
    file.write_all(&zeroes).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(root, vol, &opts, &|_| {}, &cancel).unwrap();
    let ix = out.index;

    let f = child(&ix, ROOT, "compressed.bin");
    assert!(ix.allocated(f) < 1 << 20);
    assert!(ix.flags(f).contains(NodeFlags::COMPRESSED));
}

#[test]
fn unpaired_surrogate_name_roundtrips() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();

    let wide_name = [0x61u16, 0xD800u16, 0x62u16];
    let os_name = OsString::from_wide(&wide_name);
    let f_path = root.join(&os_name);
    std::fs::write(&f_path, b"surrogate").unwrap();

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(root, vol, &opts, &|_| {}, &cancel).unwrap();
    let ix = out.index;

    let f = ix
        .children(ROOT)
        .find(|&c| ix.name_os(c) == os_name)
        .expect("child with surrogate name not found");
    assert_eq!(ix.name_os(f), OsString::from_wide(&wide_name));
}

#[test]
fn long_path_scanned() {
    let tmp = new_temp_dir();
    let canon_root = tmp.path().canonicalize().unwrap();
    let vol = get_c_volume();

    let mut curr = canon_root.clone();
    for i in 0..10 {
        curr = curr.join(format!(
            "long_directory_component_{}_abcdefghijklmnopqrstuvwxyz",
            i
        ));
        std::fs::create_dir(&curr).unwrap();
    }
    let file_path = curr.join("deep_file.txt");
    std::fs::write(&file_path, b"content").unwrap();

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(&canon_root, vol, &opts, &|_| {}, &cancel).unwrap();
    let ix = out.index;

    let mut deepest = ROOT;
    let mut deepest_depth = 0;
    for node in 0..ix.len() as NodeId {
        let d = ix.depth(node);
        if d > deepest_depth {
            deepest_depth = d;
            deepest = node;
        }
    }

    assert!(ix.path(deepest).as_os_str().len() > 400);
}

#[test]
fn access_denied_dir_skipped() {
    let tmp = new_temp_dir();
    let root = tmp.path().to_path_buf();
    let locked = root.join("locked_folder");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("secret.txt"), b"secret").unwrap();

    let guard = deny_read(&locked);
    let vol = get_c_volume();
    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(&root, vol, &opts, &|_| {}, &cancel).unwrap();

    assert!(out.skipped >= 1);
    drop(guard);
}

#[test]
fn dir_scan_cancel() {
    let tmp = new_temp_dir();
    let root = tmp.path().to_path_buf();
    let vol = get_c_volume();
    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(true);

    let res = scan_dirs(&root, vol, &opts, &|_| {}, &cancel);
    assert!(matches!(res, Err(DskError::Cancelled)));
}

#[test]
fn root_path_with_forward_slashes_scanned() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();

    std::fs::write(root.join("f1.txt"), b"file1").unwrap();
    std::fs::write(root.join("f2.txt"), b"file2").unwrap();

    let root_str = root.to_str().unwrap().replace('\\', "/");
    let forward_slash_path = std::path::Path::new(&root_str);

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(forward_slash_path, vol, &opts, &|_| {}, &cancel).unwrap();

    assert_eq!(out.skipped, 0);
    assert_eq!(out.index.file_count(ROOT), 2);
}

#[test]
fn root_path_with_trailing_slash_scanned() {
    let tmp = new_temp_dir();
    let root = tmp.path();
    let vol = get_c_volume();

    std::fs::write(root.join("f1.txt"), b"file1").unwrap();
    std::fs::write(root.join("f2.txt"), b"file2").unwrap();

    let trailing_str = format!("{}\\", root.to_str().unwrap().trim_end_matches('\\'));
    let trailing_slash_path = std::path::Path::new(&trailing_str);

    let opts = DirScanOptions::for_volume(&vol);
    let cancel = AtomicBool::new(false);
    let out = scan_dirs(trailing_slash_path, vol, &opts, &|_| {}, &cancel).unwrap();

    assert_eq!(out.skipped, 0);
    assert_eq!(out.index.file_count(ROOT), 2);
}
