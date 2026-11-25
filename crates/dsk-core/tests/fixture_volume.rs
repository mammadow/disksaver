use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use dsk_core::index::{Index, NodeFlags, NodeId, ROOT};
use dsk_core::scan::{ScanMethod, ScanOptions, scan_volume};

fn opts(method: ScanMethod) -> ScanOptions {
    ScanOptions {
        method,
        threads: None,
        use_cache: false,
    }
}

fn no_cancel() -> AtomicBool {
    AtomicBool::new(false)
}

fn fixture_path() -> PathBuf {
    let p = std::env::var("DSK_FIXTURE").expect("DSK_FIXTURE must be set (e.g. R:\\)");
    PathBuf::from(p)
}

fn relative_path(ix: &Index, mut id: NodeId) -> PathBuf {
    let mut parts = Vec::new();
    while id != ROOT && id != dsk_core::index::NONE {
        parts.push(ix.name_os(id));
        id = ix.parent(id);
    }
    parts.reverse();
    let mut rel = PathBuf::new();
    for part in parts {
        rel.push(part);
    }
    rel
}

fn find_node_by_rel_path<P: AsRef<Path>>(ix: &Index, rel: P) -> Option<NodeId> {
    let mut curr = ROOT;
    for comp in rel.as_ref().components() {
        let name = comp.as_os_str();
        let mut found = None;
        for child in ix.children(curr) {
            if ix.name_os(child) == name {
                found = Some(child);
                break;
            }
        }
        curr = found?;
    }
    Some(curr)
}

fn should_ignore_path(rel: &Path, flags: NodeFlags) -> bool {
    if flags.contains(NodeFlags::METAFILE) {
        return true;
    }
    for comp in rel.components() {
        let lossy = comp.as_os_str().to_string_lossy();
        if lossy.eq_ignore_ascii_case("System Volume Information")
            || lossy.eq_ignore_ascii_case("$Recycle.Bin")
            || lossy == "<orphaned>"
        {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryStats {
    flags: NodeFlags,
    logical: u64,
    allocated: u64,
}

#[test]
#[ignore = "needs admin and DSK_FIXTURE VHDX"]
fn mft_matches_dir_scan() {
    let fix = fixture_path();
    let mft_rep = scan_volume(&fix, &opts(ScanMethod::Mft), &|_| {}, &no_cancel())
        .expect("MFT scan of fixture volume failed");
    let dir_rep = scan_volume(&fix, &opts(ScanMethod::Dir), &|_| {}, &no_cancel())
        .expect("Dir scan of fixture volume failed");

    let mft_ix = &mft_rep.index;
    let dir_ix = &dir_rep.index;
    let cluster_size = mft_ix.volume().cluster_size as i64;

    let mut mft_map: HashMap<PathBuf, EntryStats> = HashMap::new();
    for id in 1..mft_ix.len() as NodeId {
        let flags = mft_ix.flags(id);
        let rel = relative_path(mft_ix, id);
        if should_ignore_path(&rel, flags) {
            continue;
        }
        mft_map.insert(
            rel,
            EntryStats {
                flags,
                logical: mft_ix.logical(id),
                allocated: mft_ix.allocated(id),
            },
        );
    }

    let mut dir_map: HashMap<PathBuf, EntryStats> = HashMap::new();
    for id in 1..dir_ix.len() as NodeId {
        let flags = dir_ix.flags(id);
        let rel = relative_path(dir_ix, id);
        if should_ignore_path(&rel, flags) {
            continue;
        }
        dir_map.insert(
            rel,
            EntryStats {
                flags,
                logical: dir_ix.logical(id),
                allocated: dir_ix.allocated(id),
            },
        );
    }

    // Verify same set of paths
    for path in mft_map.keys() {
        assert!(
            dir_map.contains_key(path),
            "Path present in MFT but missing from Dir: {:?}",
            path
        );
    }
    for path in dir_map.keys() {
        assert!(
            mft_map.contains_key(path),
            "Path present in Dir but missing from MFT: {:?}",
            path
        );
    }

    // Verify allocation consistency per file
    for (path, mft_stats) in &mft_map {
        let dir_stats = &dir_map[path];
        if mft_stats.flags.contains(NodeFlags::DIR) {
            continue;
        }

        if mft_stats.flags.contains(NodeFlags::ADS) {
            assert!(
                mft_stats.allocated >= dir_stats.allocated,
                "ADS file {:?} should have mft.allocated ({}) >= dir.allocated ({})",
                path,
                mft_stats.allocated,
                dir_stats.allocated
            );
        } else {
            let diff = (mft_stats.allocated as i64 - dir_stats.allocated as i64).abs();
            assert!(
                diff <= cluster_size,
                "File {:?} allocation diff {} exceeds cluster size {}: mft={}, dir={}",
                path,
                diff,
                cluster_size,
                mft_stats.allocated,
                dir_stats.allocated
            );
        }
    }
}

#[test]
#[ignore = "needs admin and DSK_FIXTURE VHDX"]
fn mft_total_matches_volume_used() {
    let fix = fixture_path();
    let r =
        scan_volume(&fix, &opts(ScanMethod::Mft), &|_| {}, &no_cancel()).expect("MFT scan failed");
    let check = r.check.expect("MFT scan should produce UsageCheck");
    assert!(
        check.diff_pct <= 2.0,
        "diff_pct too high: {}% (scanned: {}, volume used: {})",
        check.diff_pct,
        check.scanned_alloc,
        check.volume_used
    );
}

#[test]
#[ignore = "needs admin and DSK_FIXTURE VHDX"]
fn many_links_file_counted_once() {
    let fix = fixture_path();
    let r =
        scan_volume(&fix, &opts(ScanMethod::Mft), &|_| {}, &no_cancel()).expect("MFT scan failed");
    let ix = &r.index;

    let links_dir = find_node_by_rel_path(ix, "links").expect("links dir must exist");
    assert_eq!(
        ix.total_allocated(links_dir),
        1 << 20,
        "links dir total_allocated expected 1 MiB (1048576), got {}",
        ix.total_allocated(links_dir)
    );

    let non_dup_links = ix
        .children(links_dir)
        .filter(|&c| !ix.flags(c).contains(NodeFlags::DIR))
        .filter(|&c| !ix.flags(c).contains(NodeFlags::DUP_LINK))
        .count();
    assert_eq!(non_dup_links, 1, "expected exactly 1 non-duplicate link");
}

#[test]
#[ignore = "needs admin and DSK_FIXTURE VHDX"]
fn wof_file_allocated_less_than_logical() {
    let fix = fixture_path();
    let r =
        scan_volume(&fix, &opts(ScanMethod::Mft), &|_| {}, &no_cancel()).expect("MFT scan failed");
    let ix = &r.index;

    let f = find_node_by_rel_path(ix, r"wof\data.txt").expect("wof\\data.txt must exist");
    assert!(
        ix.allocated(f) * 2 < ix.logical(f),
        "wof file allocated ({}) * 2 should be < logical ({})",
        ix.allocated(f),
        ix.logical(f)
    );
    assert!(
        ix.flags(f).contains(NodeFlags::WOF),
        "wof file should contain NodeFlags::WOF, got flags {:?}",
        ix.flags(f)
    );
}

#[test]
#[ignore = "needs admin and DSK_FIXTURE VHDX"]
fn ads_counted_by_mft() {
    let fix = fixture_path();
    let r =
        scan_volume(&fix, &opts(ScanMethod::Mft), &|_| {}, &no_cancel()).expect("MFT scan failed");
    let ix = &r.index;

    let host = find_node_by_rel_path(ix, r"ads\host.txt").expect("ads\\host.txt must exist");
    assert!(
        ix.allocated(host) >= 2 << 20,
        "ads host file allocated expected >= 2 MiB, got {}",
        ix.allocated(host)
    );
    assert!(
        ix.flags(host).contains(NodeFlags::ADS),
        "ads host file should contain NodeFlags::ADS, got flags {:?}",
        ix.flags(host)
    );
}
