use super::*;
use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
use crate::time::{FILETIME_EPOCH_2000, INTERVALS_PER_MINUTE};
use crate::volume::VolumeInfo;

const NOW: u32 = 14_000_000;

fn ft(days_ago: u32) -> u64 {
    FILETIME_EPOCH_2000 + u64::from(NOW - days_ago * MINUTES_PER_DAY) * INTERVALS_PER_MINUTE
}

fn build(files: &[(&str, u64, u32)]) -> Index {
    let mut names = NameArena::new();
    let n_root = names.push_str("C:");
    let mut raw = vec![RawEntry {
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
    }];
    let mut dirs: FxHashMap<String, u64> = FxHashMap::default();
    let mut next = 10u64;
    for (path, bytes, days) in files {
        let parts: Vec<&str> = path.split('\\').skip(1).collect();
        let mut parent = 5u64;
        let mut prefix = String::new();
        for (i, part) in parts.iter().enumerate() {
            prefix.push('\\');
            prefix.push_str(part);
            let is_file = i + 1 == parts.len();
            if !is_file && let Some(&k) = dirs.get(&prefix) {
                parent = k;
                continue;
            }
            let key = next;
            next += 1;
            let n = names.push_str(part);
            raw.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags: if is_file {
                    NodeFlags::empty()
                } else {
                    NodeFlags::DIR
                },
                logical: if is_file { *bytes } else { 0 },
                allocated: if is_file { *bytes } else { 0 },
                // Directories look as old as their first file; units use file times.
                mtime: ft(*days),
                atime: ft(*days),
                file_id: key,
                reparse_tag: 0,
            });
            if !is_file {
                dirs.insert(prefix.clone(), key);
            }
            parent = key;
        }
    }
    let mut b = IndexBuilder::new(
        5,
        r"C:\",
        VolumeInfo {
            root: r"C:\".into(),
            ..Default::default()
        },
    );
    b.push_batch(EntryBatch {
        entries: raw,
        names,
    });
    b.finish()
}

const OLD_APP: &str = "aaaaaaaaaaaaaaaa";
const NEW_APP: &str = "bbbbbbbbbbbbbbbb";
const SERDE: &str = "cccccccccccccccc";

fn workspace() -> Index {
    let t = r"C:\ws\target";
    build(&[
        (r"C:\ws\Cargo.toml", 100, 1),
        (&format!(r"{t}\CACHEDIR.TAG"), 100, 90),
        (&format!(r"{t}\debug\deps\app-{OLD_APP}.pdb"), 240_000, 60),
        (&format!(r"{t}\debug\deps\app-{OLD_APP}.exe"), 10_000, 60),
        (
            &format!(r"{t}\debug\.fingerprint\app-{OLD_APP}\bin-app"),
            10,
            60,
        ),
        (&format!(r"{t}\debug\deps\app-{NEW_APP}.pdb"), 250_000, 1),
        (
            &format!(r"{t}\debug\.fingerprint\app-{NEW_APP}\bin-app"),
            10,
            1,
        ),
        // An old dependency that was never rebuilt is still the newest serde: kept.
        (
            &format!(r"{t}\debug\deps\libserde-{SERDE}.rlib"),
            50_000,
            60,
        ),
        (
            &format!(r"{t}\debug\incremental\app-1111111111111111\s-old\dep-graph.bin"),
            70_000,
            60,
        ),
        (
            &format!(r"{t}\debug\incremental\app-2222222222222222\s-new\dep-graph.bin"),
            80_000,
            1,
        ),
        (&format!(r"{t}\debug\app.exe"), 10_000, 1),
        (r"C:\web\package.json", 100, 1),
        (r"C:\web\.next\cache\webpack\old.pack", 5_000, 40),
        (r"C:\web\.next\cache\webpack\new.pack", 6_000, 1),
        (r"C:\web\.next\cache\images\stale\a.webp", 700, 40),
    ])
}

fn opts() -> SweepOptions {
    SweepOptions {
        keep_days: 14,
        now_min2000: Some(NOW),
    }
}

#[test]
fn cargo_sweep_removes_only_stale_generations() {
    let ix = workspace();
    let cands = find_sweep_candidates(
        &ix,
        &opts(),
        FileIdKind::Unpinned,
        &DenyContext::default_for_test(),
    );
    let cargo = cands
        .iter()
        .find(|c| c.kind == SweepKind::CargoTarget)
        .expect("cargo target");
    let rels: Vec<&str> = cargo
        .planned
        .items
        .iter()
        .map(|i| i.rel_path.as_str())
        .collect();

    assert!(
        rels.contains(&format!(r"debug\deps\app-{OLD_APP}.pdb").as_str()),
        "{rels:?}"
    );
    assert!(rels.contains(&format!(r"debug\deps\app-{OLD_APP}.exe").as_str()));
    assert!(rels.contains(&format!(r"debug\.fingerprint\app-{OLD_APP}").as_str()));
    assert!(rels.contains(&r"debug\incremental\app-1111111111111111"));
    for kept in [
        NEW_APP,
        SERDE,
        "2222222222222222",
        "app.exe",
        "CACHEDIR.TAG",
    ] {
        assert!(
            rels.iter().all(|r| !r.contains(kept)),
            "{kept} must be kept: {rels:?}"
        );
    }
    assert_eq!(cargo.stale_bytes, 240_000 + 10_000 + 10 + 70_000);
    assert_eq!(cargo.newest_build_days, Some(1));

    // Children come before their directories (the executor deletes in this order).
    let fp = rels
        .iter()
        .position(|r| *r == format!(r"debug\.fingerprint\app-{OLD_APP}"))
        .unwrap();
    let fp_child = rels
        .iter()
        .position(|r| *r == format!(r"debug\.fingerprint\app-{OLD_APP}\bin-app"))
        .unwrap();
    assert!(fp_child < fp);
}

#[test]
fn next_cache_sweep_keeps_recent_files_and_their_folders() {
    let ix = workspace();
    let cands = find_sweep_candidates(
        &ix,
        &opts(),
        FileIdKind::Unpinned,
        &DenyContext::default_for_test(),
    );
    let next = cands
        .iter()
        .find(|c| c.kind == SweepKind::NextCache)
        .expect("next cache");
    let rels: Vec<&str> = next
        .planned
        .items
        .iter()
        .map(|i| i.rel_path.as_str())
        .collect();
    assert!(rels.contains(&r"webpack\old.pack"));
    assert!(rels.contains(&r"images\stale\a.webp"));
    assert!(
        rels.contains(&r"images\stale"),
        "fully stale folders go too"
    );
    assert!(
        !rels.contains(&r"webpack"),
        "a folder with a recent file stays"
    );
    assert!(!rels.iter().any(|r| r.contains("new.pack")));
    assert_eq!(next.stale_bytes, 5_700);
}

#[test]
fn hash_names_parse() {
    assert_eq!(
        split_cargo_hash("app-0123456789abcdef.pdb"),
        Some(("app", "0123456789abcdef"))
    );
    assert_eq!(
        split_cargo_hash("libserde_json-0123456789abcdef.rlib"),
        Some(("libserde_json", "0123456789abcdef"))
    );
    assert_eq!(split_cargo_hash("app-0123.pdb"), None);
    assert_eq!(split_cargo_hash("app.exe"), None);
}

/// End to end on real files: scan a temp workspace, plan, and delete through `safe_clean_root`.
#[test]
fn live_sweep_deletes_planned_items_on_disk() {
    use std::time::{Duration, SystemTime};

    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws");
    let deps = ws.join("target").join("debug").join("deps");
    std::fs::create_dir_all(&deps).unwrap();
    std::fs::write(ws.join("Cargo.toml"), "[package]").unwrap();
    std::fs::write(
        ws.join("target").join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55",
    )
    .unwrap();
    let old = deps.join(format!("app-{OLD_APP}.pdb"));
    let new = deps.join(format!("app-{NEW_APP}.pdb"));
    std::fs::write(&old, vec![1u8; 8192]).unwrap();
    std::fs::write(&new, vec![2u8; 8192]).unwrap();
    let sixty_days = SystemTime::now() - Duration::from_secs(60 * 86_400);
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(sixty_days)
        .unwrap();

    let cancel = AtomicBool::new(false);
    let report = crate::scan::scan_volume(
        &ws,
        &crate::scan::ScanOptions {
            method: crate::scan::ScanMethod::Dir,
            threads: Some(2),
            use_cache: false,
        },
        &|_| {},
        &cancel,
    )
    .unwrap();
    let deny = DenyContext::default();
    let cands = find_sweep_candidates(
        &report.index,
        &SweepOptions::default(),
        FileIdKind::FxHash128,
        &deny,
    );
    assert_eq!(cands.len(), 1, "{cands:?}");
    let dry = run_planned(&cands[0], &deny, true, &cancel).unwrap();
    assert!(old.exists() && dry.deleted == 1);

    let live = run_planned(&cands[0], &deny, false, &cancel).unwrap();
    assert_eq!((live.deleted, live.failed), (1, 0), "{live:?}");
    assert!(!old.exists(), "stale generation deleted");
    assert!(new.exists(), "current generation kept");
    assert!(ws.join("target").join("CACHEDIR.TAG").exists());
}
