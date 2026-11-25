use super::*;
use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
use crate::ledger::{Confidence, LedgerBuilder, Opportunity, Reversibility};
use crate::time::{FILETIME_EPOCH_2000, INTERVALS_PER_MINUTE};
use crate::volume::VolumeInfo;

const NOW: u32 = 14_000_000; // minutes since 2000 (~2026)

fn ft_days_ago(days: u32) -> u64 {
    FILETIME_EPOCH_2000 + u64::from(NOW - days * MINUTES_PER_DAY) * INTERVALS_PER_MINUTE
}

/// Builds `C:\` from `(path, bytes, days_ago)`; a trailing `\` makes an empty directory.
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
        let parts: Vec<&str> = path.split('\\').skip(1).filter(|p| !p.is_empty()).collect();
        let is_dir_only = path.ends_with('\\');
        let mut parent = 5u64;
        let mut prefix = String::new();
        for (i, part) in parts.iter().enumerate() {
            prefix.push('\\');
            prefix.push_str(&part.to_ascii_lowercase());
            let is_file = i + 1 == parts.len() && !is_dir_only;
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
                mtime: ft_days_ago(*days),
                atime: ft_days_ago(*days),
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
            total_bytes: 100 * GIB,
            free_bytes: 50 * GIB,
            ..Default::default()
        },
    );
    b.push_batch(EntryBatch {
        entries: raw,
        names,
    });
    b.finish()
}

fn opts() -> HuntOptions {
    HuntOptions {
        now_min2000: Some(NOW),
        many: true,
        ..Default::default()
    }
}

fn find<'a>(r: &'a HuntReport, path: &str) -> &'a HuntFinding {
    r.findings
        .iter()
        .find(|f| f.path == Path::new(path))
        .unwrap_or_else(|| {
            panic!(
                "no finding for {path}; got {:?}",
                r.findings
                    .iter()
                    .map(|f| f.path.display().to_string())
                    .collect::<Vec<_>>()
            )
        })
}

fn sample_volume() -> Index {
    build(&[
        (r"C:\hiberfil.sys", GIB, 1),
        (r"C:\rtr8CC2.tmp", 300 * MIB, 278),
        (r"C:\Windows\System32\big.dll", 600 * MIB, 400),
        (r"C:\Users\A\Videos\rec.mp4", 2 * GIB, 18),
        (r"C:\Users\A\Videos\old-trip.mkv", GIB, 500),
        (r"C:\Users\A\Downloads\setup.exe", 300 * MIB, 100),
        (r"C:\Users\A\Downloads\dataset.zip", 300 * MIB, 200),
        (r"C:\projects\app\target\debug\app.pdb", 400 * MIB, 2),
        (r"C:\projects\app\src\main.rs", 10_000, 2),
        (r"C:\Tools\gradle-8.5\lib\core.jar", 400 * MIB, 100),
        (r"C:\Tools\gradle-8.10\lib\core.jar", 400 * MIB, 5),
        (r"C:\Program Files\Game\data.pak", GIB, 40),
        (r"C:\Program Files\Launcher\launcher.exe", 300 * MIB, 5),
        (
            r"C:\Program Files\Launcher\games\Racer\racer.pak",
            2 * GIB,
            30,
        ),
        (r"C:\Program Files\Game\node_modules\x.js", 100 * MIB, 50),
        (r"C:\VMs\disk.vhdx", 2 * GIB, 400),
        (r"C:\Ignored\big.bin", GIB, 900),
        (r"C:\web\a\node_modules\x.js", 100 * MIB, 50),
        (
            r"C:\web\a\node_modules\dep\node_modules\y.js",
            100 * MIB,
            50,
        ),
        (r"C:\web\b\node_modules\x.js", 100 * MIB, 50),
        (r"C:\web\c\node_modules\x.js", 100 * MIB, 50),
        (r"C:\Users\A\Desktop\photo (1).jpg", 60 * MIB, 10),
        (r"C:\Users\A\Desktop\photo (2).jpg", 60 * MIB, 10),
    ])
}

fn context<'a>(ledger: Option<&'a Ledger>) -> HuntContext<'a> {
    let mut ctx = HuntContext::new(DenyContext::default_for_test());
    ctx.ledger = ledger;
    ctx.installed = vec![
        InstalledRoot {
            path: PathBuf::from(r"C:\Program Files\Game"),
            name: "Game".into(),
            store: Some("Steam".into()),
        },
        InstalledRoot {
            path: PathBuf::from(r"C:\Program Files\Launcher"),
            name: "Launcher".into(),
            store: None,
        },
        InstalledRoot {
            path: PathBuf::from(r"C:\Program Files\Launcher\games\Racer"),
            name: "Racer".into(),
            store: Some("Epic Games".into()),
        },
    ];
    ctx.ignore = vec![PathBuf::from(r"C:\Ignored")];
    ctx
}

fn target_ledger(ix: &Index) -> Ledger {
    let mut b = LedgerBuilder::new(Some(ix));
    b.add_external(
        Opportunity {
            id: "project:target".into(),
            lane: Lane::Regenerable,
            title: "Rust build output: app".into(),
            detail: "Rebuilt by cargo".into(),
            path: Some(PathBuf::from(r"C:\projects\app\target")),
            est_bytes: 0,
            raw_est_bytes: 400 * MIB,
            confidence: Confidence::Measured,
            reversibility: Reversibility::RecycleBin,
            requires_admin: false,
            action: ActionRef::RecyclePath {
                path: PathBuf::from(r"C:\projects\app\target"),
            },
            score: 0.0,
            calibration: None,
        },
        &[PathBuf::from(r"C:\projects\app\target")],
        true,
    );
    b.finish()
}

#[test]
fn verdicts_units_and_big_files() {
    let ix = sample_volume();
    let ledger = target_ledger(&ix);
    let ctx = context(Some(&ledger));
    let r = run_hunt(&ix, &ctx, &opts());

    // Claimed build output collapses into one unit carrying the ledger's action.
    let target = find(&r, r"C:\projects\app\target");
    assert_eq!(
        (target.kind, target.verdict),
        (FindingKind::Unit, Verdict::Claimed)
    );
    assert_eq!(target.opportunity_id.as_deref(), Some("project:target"));

    // Protected: system subtree and root system files, never actionable.
    let sys = find(&r, r"C:\Windows\System32");
    assert_eq!(sys.verdict, Verdict::Protected);
    assert_eq!(sys.action, ActionRef::None);
    let hib = find(&r, r"C:\hiberfil.sys");
    assert_eq!(hib.verdict, Verdict::Protected);
    assert_eq!(hib.action, ActionRef::None);

    // Personal library: listed, never actioned, even when cold.
    let rec = find(&r, r"C:\Users\A\Videos\rec.mp4");
    assert_eq!(
        (rec.verdict, &rec.action),
        (Verdict::Active, &ActionRef::None)
    );
    assert!(rec.reason.contains("personal library"));
    let trip = find(&r, r"C:\Users\A\Videos\old-trip.mkv");
    assert_eq!(
        (trip.verdict, &trip.action),
        (Verdict::ColdUserData, &ActionRef::None)
    );

    // Leftovers with evidence.
    let setup = find(&r, r"C:\Users\A\Downloads\setup.exe");
    assert_eq!(setup.verdict, Verdict::Leftover);
    assert!(setup.reason.contains("installer"));
    assert!(matches!(setup.action, ActionRef::RecyclePath { .. }));
    let tmp = find(&r, r"C:\rtr8CC2.tmp");
    assert_eq!(tmp.verdict, Verdict::Leftover);
    let old = find(&r, r"C:\Tools\gradle-8.5");
    assert_eq!(
        (old.kind, old.verdict),
        (FindingKind::Unit, Verdict::Leftover)
    );
    assert!(old.reason.contains("gradle-8.10"), "{}", old.reason);
    assert!(r.findings.iter().all(|f| f.path != Path::new(r"C:\Tools\gradle-8.10")
        || f.verdict != Verdict::Leftover));

    // Cold data outside personal libraries is actionable.
    let zip = find(&r, r"C:\Users\A\Downloads\dataset.zip");
    assert_eq!(zip.verdict, Verdict::ColdUserData);

    // Installed game root becomes one unit with a launcher action.
    let game = find(&r, r"C:\Program Files\Game");
    assert_eq!(game.verdict, Verdict::InstalledApp);
    assert!(matches!(game.action, ActionRef::LauncherGame { .. }));

    // A launcher folder holding a game is not one "uninstall the launcher" unit.
    assert!(
        r.findings
            .iter()
            .all(|f| f.path != Path::new(r"C:\Program Files\Launcher"))
    );
    let racer = find(&r, r"C:\Program Files\Launcher\games\Racer");
    assert!(matches!(racer.action, ActionRef::LauncherGame { .. }));

    // A virtual disk is never leftover or cold, however old.
    let vhd = find(&r, r"C:\VMs\disk.vhdx");
    assert_eq!(
        (vhd.verdict, &vhd.action),
        (Verdict::Active, &ActionRef::None)
    );

    // The ignore list hides findings.
    assert!(
        r.findings
            .iter()
            .all(|f| !f.path.starts_with(r"C:\Ignored"))
    );
    assert_eq!(r.ignored, 1);

    // Units never nest and totals never exceed what was scanned.
    for a in r.findings.iter().filter(|f| f.kind == FindingKind::Unit) {
        for b in &r.findings {
            if a.path != b.path {
                assert!(
                    !b.path.starts_with(&a.path),
                    "{:?} inside {:?}",
                    b.path,
                    a.path
                );
            }
        }
    }
    let listed: u64 = r.findings.iter().map(|f| f.bytes).sum();
    assert!(listed <= ix.total_allocated(ROOT));

    // Unaccounted space on a volume-root index.
    let un = r.unaccounted.as_ref().expect("unaccounted");
    assert_eq!(un.volume_used_bytes, 50 * GIB);
    assert!(un.causes.iter().any(|c| c.contains("without admin")));
}

#[test]
fn swarms_count_outermost_folders_and_copy_names() {
    let ix = sample_volume();
    let r = run_hunt(&ix, &context(None), &opts());
    let nm = r
        .swarms
        .iter()
        .find(|s| s.swarm == Some(SwarmKind::RecurringFolder) && s.title.contains("node_modules"))
        .expect("node_modules swarm");
    // Three outermost folders; the nested one is counted inside its parent.
    assert_eq!(nm.member_count, 3);
    assert_eq!(nm.bytes, 400 * MIB);

    let copies = r
        .swarms
        .iter()
        .find(|s| s.swarm == Some(SwarmKind::NamePattern))
        .expect("copy-name swarm");
    assert_eq!(copies.member_count, 2);
    assert!(r.notes.iter().any(|n| n.contains("ledger")));
}

#[test]
fn filters_by_verdict_and_age() {
    let ix = sample_volume();
    let mut o = opts();
    o.verdict_filter = vec![Verdict::Leftover];
    o.older_than_days = Some(200);
    let r = run_hunt(&ix, &context(None), &o);
    let paths: Vec<String> = r
        .findings
        .iter()
        .map(|f| f.path.display().to_string())
        .collect();
    assert_eq!(paths, [r"C:\rtr8CC2.tmp"], "{paths:?}");
}

#[test]
fn helpers_parse_versions_and_patterns() {
    assert_eq!(
        split_version("gradle-8.10"),
        Some(("gradle-".into(), vec![8, 10]))
    );
    assert_eq!(
        split_version("IntelliJIdea2025.1"),
        Some(("intellijidea".into(), vec![2025, 1]))
    );
    assert_eq!(
        split_version("node-v20.1.0"),
        Some(("node-".into(), vec![20, 1, 0]))
    );
    assert_eq!(split_version("v20"), None, "a bare version has no prefix");
    assert_eq!(split_version("x64"), None);
    assert_eq!(split_version("python3.11-venv"), None);
    assert!(split_version("gradle-8.10").unwrap().1 > split_version("gradle-8.5").unwrap().1);

    assert!(copy_pattern("report (3).docx").is_some());
    assert!(copy_pattern("Copy of notes.txt").is_some());
    assert!(copy_pattern("notes - Copy.txt").is_some());
    assert!(copy_pattern("Windows (x86).txt").is_none());
    assert!(copy_pattern("plain.txt").is_none());

    assert_eq!(
        leftover_file_reason("a.TMP", 10, 30, false),
        Some("temporary file or unfinished download")
    );
    assert_eq!(leftover_file_reason("a.tmp", 2, 30, false), None);
    assert_eq!(
        leftover_file_reason("setup.exe", 40, 30, false),
        None,
        "only in Downloads"
    );
    assert!(leftover_file_reason("setup.exe", 40, 30, true).is_some());
    assert_eq!(Verdict::parse("COLD"), Some(Verdict::ColdUserData));
}

#[test]
fn ignore_list_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("sub").join("hunt-ignore.txt");
    assert!(load_ignore_list(&file).is_empty());
    add_to_ignore_list(&file, Path::new(r"C:\Keep\This")).unwrap();
    add_to_ignore_list(&file, Path::new(r"c:\keep\this\")).unwrap();
    assert_eq!(
        load_ignore_list(&file),
        vec![PathBuf::from(r"C:\Keep\This")]
    );
}
