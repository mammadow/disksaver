#![forbid(unsafe_code)]

//! Cold file & infrequently used program scorer (§9.6).
//!
//! Combines `Index` file access/modify timestamps (honoring NTFS `NtfsDisableLastAccessUpdate`
//! policy), Explorer ROT13 `UserAssist`, Background Activity Moderator (`BAM`), and Windows
//! Prefetch (`.pf`) telemetry to surface stale files and dormant applications.

use std::path::{Path, PathBuf};

use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path, normalize_win_path_str};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::insights::current_min2000;
use crate::time::filetime_to_min2000;
use crate::win::prefetch::{
    BamEntry, InstalledAppRecord, PrefetchRecord, UserAssistEntry, enumerate_installed_apps,
    read_bam_entries, read_user_assist_entries, scan_windows_prefetch,
};
use crate::win::reflink::query_last_access_disabled;

/// Large file identified as untouched for longer than `cold_days_threshold`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdFileCandidate {
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub days_cold: u32,
    pub cold_score: u8,
    pub extension: Option<String>,
}

/// Installed application scored by Windows execution telemetry (`UserAssist`/`BAM`/`Prefetch`)
/// and install footprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdAppCandidate {
    pub app_name: String,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    pub allocated_bytes: u64,
    pub days_since_last_run: Option<u32>,
    pub observed_runs: u32,
    pub cold_score: u8,
    pub telemetry_note: String,
}

/// Combined cold data analysis report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdDataReport {
    pub last_access_disabled: Option<bool>,
    pub advisory_note: Option<String>,
    pub cold_files: Vec<ColdFileCandidate>,
    pub cold_apps: Vec<ColdAppCandidate>,
    pub total_cold_file_bytes: u64,
    pub total_cold_app_bytes: u64,
    /// Installed apps (grouped by install folder) left unscored because no execution history was
    /// available for them: without administrator rights Prefetch and BAM cannot be read, and an
    /// untouched install folder alone does not show that an app is unused.
    #[serde(default)]
    pub unscored_apps: u32,
}

const SKIP_SYSTEM_FOLDERS_LOWER: &[&str] = &[
    r"\windows\",
    r"\program files\",
    r"\program files (x86)\",
    r"\programdata\",
    r"\$recycle.bin\",
    r"\system volume information\",
];

/// Uninstall entries sometimes carry an unexpanded installer template as their name
/// (e.g. `${{arpDisplayName}}` in one CUDA component).
fn is_unresolved_display_name(name: &str) -> bool {
    name.contains("${") || name.contains("{{") || name.contains("$(")
}

/// Picks the entry that names an install-folder group: a visible (non-`SystemComponent`) entry
/// with a resolved name, else any resolved name, else the first entry.
fn representative_app<'a>(members: &[&'a InstalledAppRecord]) -> &'a InstalledAppRecord {
    members
        .iter()
        .find(|a| !a.system_component && !is_unresolved_display_name(&a.name))
        .or_else(|| {
            members
                .iter()
                .find(|a| !is_unresolved_display_name(&a.name))
        })
        .copied()
        .unwrap_or(members[0])
}

fn normalize_stem(s: &str) -> String {
    let fname = Path::new(s)
        .file_stem()
        .and_then(|x| x.to_str())
        .unwrap_or(s);
    fname
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn collect_dir_footprint_and_touch(index: &Index, root: NodeId) -> (u64, u32) {
    let mut stack = vec![root];
    let mut seen_fids: FxHashSet<u64> = FxHashSet::default();
    let mut alloc = 0u64;
    let mut newest_touch = 0u32;

    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if flags.contains(NodeFlags::DIR) {
            if node != root && flags.contains(NodeFlags::REPARSE) {
                continue;
            }
            for child in index.children(node) {
                stack.push(child);
            }
            continue;
        }
        let fid = index.file_id(node);
        if fid == 0 || seen_fids.insert(fid) {
            alloc = alloc.saturating_add(index.allocated(node));
        }
        newest_touch = newest_touch.max(index.mtime_min(node).max(index.atime_min(node)));
    }
    (alloc, newest_touch)
}

/// Evaluates cold files and cold installed applications using live Windows registry & Prefetch
/// telemetry (`§9.6`).
pub fn scan_cold_data_live(
    index: &Index,
    min_file_bytes: u64,
    cold_days_threshold: u32,
) -> ColdDataReport {
    let apps = enumerate_installed_apps();
    let ua = read_user_assist_entries();
    let bam = read_bam_entries();
    let pf = scan_windows_prefetch();
    let last_access_disabled = query_last_access_disabled();
    scan_cold_data(
        index,
        &apps,
        &ua,
        &bam,
        &pf,
        last_access_disabled,
        min_file_bytes,
        cold_days_threshold,
    )
}

/// Deterministic, side-effect-free cold file and unused program scorer.
#[allow(clippy::too_many_arguments)]
pub fn scan_cold_data(
    index: &Index,
    installed_apps: &[InstalledAppRecord],
    user_assist: &[UserAssistEntry],
    bam: &[BamEntry],
    prefetch: &[PrefetchRecord],
    last_access_disabled: Option<bool>,
    min_file_bytes: u64,
    cold_days_threshold: u32,
) -> ColdDataReport {
    let deny_ctx = DenyContext::default();
    let now_mins = current_min2000();

    let mut notes: Vec<String> = Vec::new();
    if last_access_disabled == Some(true) {
        notes.push(
            "NTFS LastAccess timestamp updates are disabled on this system; scoring coldness using mtime, UserAssist, BAM, and Prefetch."
                .to_string(),
        );
    }

    // 1. Cold large files in user/data trees.
    let mut cold_files = Vec::new();
    let mut stack = vec![ROOT];
    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if node != ROOT
            && flags.intersects(
                NodeFlags::REPARSE
                    | NodeFlags::SYSTEM
                    | NodeFlags::ORPHANS
                    | NodeFlags::CLOUD
                    | NodeFlags::OFFLINE
                    | NodeFlags::METAFILE,
            )
        {
            continue;
        }
        if flags.contains(NodeFlags::DIR) {
            let path_lower = index.path(node).to_string_lossy().to_ascii_lowercase();
            let path_with_sep = if path_lower.ends_with('\\') {
                path_lower
            } else {
                format!("{path_lower}\\")
            };
            if node != ROOT
                && SKIP_SYSTEM_FOLDERS_LOWER
                    .iter()
                    .any(|p| path_with_sep.contains(p))
            {
                continue;
            }
            let start = stack.len();
            for child in index.children(node) {
                stack.push(child);
            }
            stack[start..].reverse();
            continue;
        }

        let alloc = index.allocated(node);
        if alloc < min_file_bytes {
            continue;
        }
        let path = index.path(node);
        if is_denied_path(&path, &deny_ctx).is_some() {
            continue;
        }

        let mtime = index.mtime_min(node);
        let atime = index.atime_min(node);
        let effective_touch = if last_access_disabled == Some(true) || atime == 0 {
            mtime
        } else {
            atime.max(mtime)
        };
        if effective_touch == 0 || now_mins <= effective_touch {
            continue;
        }
        let days_cold = (now_mins - effective_touch) / 1440;
        if days_cold < cold_days_threshold {
            continue;
        }

        let age_pts = ((days_cold.saturating_sub(cold_days_threshold) / 5) + 40).min(75);
        let size_pts = if alloc >= 1_073_741_824 {
            25
        } else if alloc >= 268_435_456 {
            15
        } else {
            5
        };
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());

        cold_files.push(ColdFileCandidate {
            path,
            allocated_bytes: alloc,
            days_cold,
            cold_score: (age_pts + size_pts).min(100) as u8,
            extension,
        });
    }

    cold_files.sort_by(|a, b| {
        b.cold_score
            .cmp(&a.cold_score)
            .then_with(|| b.allocated_bytes.cmp(&a.allocated_bytes))
            .then_with(|| a.path.cmp(&b.path))
    });

    // 2. Index execution telemetry by normalized executable/app stems & full path hints.
    #[derive(Default)]
    struct ExecObs {
        latest_ft: u64,
        runs: u32,
        sources: Vec<&'static str>,
    }

    let mut telemetry_by_stem: FxHashMap<String, ExecObs> = FxHashMap::default();
    let mut bam_paths: Vec<(String, u64)> = Vec::new();
    let mut ua_names: Vec<(String, u32, u64)> = Vec::new();

    for entry in user_assist {
        let stem = normalize_stem(&entry.decoded_name);
        if !stem.is_empty() {
            let e = telemetry_by_stem.entry(stem).or_default();
            e.latest_ft = e.latest_ft.max(entry.last_exec_filetime);
            e.runs = e.runs.saturating_add(entry.run_count);
            if !e.sources.contains(&"UserAssist") {
                e.sources.push("UserAssist");
            }
        }
        ua_names.push((
            entry.decoded_name.to_ascii_lowercase(),
            entry.run_count,
            entry.last_exec_filetime,
        ));
    }

    for entry in bam {
        let stem = normalize_stem(&entry.exe_path);
        if !stem.is_empty() {
            let e = telemetry_by_stem.entry(stem).or_default();
            e.latest_ft = e.latest_ft.max(entry.last_exec_filetime);
            e.runs = e.runs.max(1);
            if !e.sources.contains(&"BAM") {
                e.sources.push("BAM");
            }
        }
        bam_paths.push((
            entry.exe_path.to_ascii_lowercase(),
            entry.last_exec_filetime,
        ));
    }

    for pf in prefetch {
        let stem = normalize_stem(&pf.exe_name);
        if !stem.is_empty() {
            let e = telemetry_by_stem.entry(stem).or_default();
            e.latest_ft = e.latest_ft.max(pf.last_run_filetime);
            e.runs = e.runs.saturating_add(pf.run_count);
            if !e.sources.contains(&"Prefetch") {
                e.sources.push("Prefetch");
            }
        }
    }

    // Prefetch and BAM record every executable launch but need administrator rights. Without
    // them only UserAssist (Explorer/Start launches) is available, so "no trace" proves nothing.
    let exec_history_available = !prefetch.is_empty() || !bam.is_empty();

    // Group entries that share an install folder: the CUDA toolkit alone registers ~45 MSI
    // components for one directory, which used to count the same 4 GiB ~45 times.
    let mut groups: Vec<Vec<&InstalledAppRecord>> = Vec::new();
    let mut group_by_key: FxHashMap<String, usize> = FxHashMap::default();
    let mut seen_names: FxHashSet<String> = FxHashSet::default();
    for app in installed_apps {
        if !seen_names.insert(app.name.to_ascii_lowercase()) {
            continue;
        }
        let loc_norm = app
            .install_location
            .as_deref()
            .map(|loc| normalize_win_path_str(loc).to_ascii_lowercase())
            .unwrap_or_default();
        let key = if loc_norm.is_empty() {
            format!("name:{}", app.name.to_ascii_lowercase())
        } else {
            format!("loc:{loc_norm}")
        };
        match group_by_key.get(&key) {
            Some(&i) => groups[i].push(app),
            None => {
                group_by_key.insert(key, groups.len());
                groups.push(vec![app]);
            }
        }
    }

    let mut cold_apps = Vec::new();
    let mut unscored_apps = 0u32;

    for members in &groups {
        let app = representative_app(members);
        let mut member_stems: Vec<String> = members
            .iter()
            .map(|m| normalize_stem(&m.name))
            .filter(|n| n.len() >= 3)
            .collect();
        if member_stems.is_empty() {
            continue;
        }
        member_stems.sort();
        member_stems.dedup();

        let (allocated_bytes, dir_touch_mins) = app
            .install_location
            .as_ref()
            .and_then(|loc| index.find_by_path(loc))
            .map(|nid| collect_dir_footprint_and_touch(index, nid))
            .unwrap_or((0, 0));

        let mut latest_ft = 0u64;
        let mut observed_runs = 0u32;
        let mut sources: Vec<&'static str> = Vec::new();

        for stem in &member_stems {
            if let Some(obs) = telemetry_by_stem.get(stem) {
                latest_ft = latest_ft.max(obs.latest_ft);
                observed_runs = observed_runs.max(obs.runs);
                for s in &obs.sources {
                    if !sources.contains(s) {
                        sources.push(s);
                    }
                }
            }
        }

        if let Some(ref loc) = app.install_location {
            let loc_lower = loc.to_string_lossy().to_ascii_lowercase();
            let leaf_norm = loc
                .file_name()
                .and_then(|s| s.to_str())
                .map(normalize_stem)
                .unwrap_or_default();
            if leaf_norm.len() >= 3
                && let Some(obs) = telemetry_by_stem.get(&leaf_norm)
            {
                latest_ft = latest_ft.max(obs.latest_ft);
                observed_runs = observed_runs.saturating_add(obs.runs);
                for s in &obs.sources {
                    if !sources.contains(s) {
                        sources.push(s);
                    }
                }
            }
            for (bp, bft) in &bam_paths {
                if bp.contains(&loc_lower) {
                    latest_ft = latest_ft.max(*bft);
                    observed_runs = observed_runs.max(1);
                    if !sources.contains(&"BAM") {
                        sources.push("BAM");
                    }
                }
            }
            for (ua_n, u_runs, uft) in &ua_names {
                if ua_n.contains(&loc_lower) {
                    latest_ft = latest_ft.max(*uft);
                    observed_runs = observed_runs.saturating_add(*u_runs);
                    if !sources.contains(&"UserAssist") {
                        sources.push("UserAssist");
                    }
                }
            }
        }

        let telemetry_mins = if latest_ft > 0 {
            filetime_to_min2000(latest_ft)
        } else {
            0
        };
        let effective_mins = telemetry_mins.max(dir_touch_mins);
        let days_since_last_run = if effective_mins > 0 && now_mins > effective_mins {
            Some((now_mins - effective_mins) / 1440)
        } else if latest_ft == 0 && dir_touch_mins == 0 {
            None
        } else {
            Some(0)
        };

        let is_cold = match days_since_last_run {
            Some(d) => d >= cold_days_threshold,
            // No run observed anywhere across UserAssist/BAM/Prefetch and measurable install dir.
            None => observed_runs == 0 && allocated_bytes >= 10 * 1024 * 1024,
        };
        if !is_cold {
            continue;
        }
        if sources.is_empty() && !exec_history_available {
            // Only install-file timestamps are left, and they record installs and updates, not
            // use. Report the gap instead of guessing "cold".
            unscored_apps = unscored_apps.saturating_add(1);
            continue;
        }

        let display_name = if is_unresolved_display_name(&app.name) {
            app.install_location
                .as_deref()
                .and_then(Path::file_name)
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| app.name.clone())
        } else {
            app.name.clone()
        };

        let cold_score = match days_since_last_run {
            Some(d) => {
                let age_pts = ((d.saturating_sub(cold_days_threshold) / 4) + 50).min(85);
                let run_bonus = if observed_runs == 0 { 15 } else { 0 };
                (age_pts + run_bonus).min(100) as u8
            }
            None => 75,
        };

        let telemetry_note = if sources.is_empty() {
            match days_since_last_run {
                Some(d) => {
                    format!("No UserAssist/BAM/Prefetch trace; install files untouched {d}d")
                }
                None => "No UserAssist, BAM, or Prefetch execution recorded".to_string(),
            }
        } else {
            format!(
                "Tracked via {} ({} run(s); ~{}d ago)",
                sources.join("+"),
                observed_runs,
                days_since_last_run.unwrap_or(cold_days_threshold)
            )
        };

        cold_apps.push(ColdAppCandidate {
            app_name: display_name,
            publisher: app.publisher.clone(),
            install_location: app.install_location.clone(),
            allocated_bytes,
            days_since_last_run,
            observed_runs,
            cold_score,
            telemetry_note,
        });
    }

    cold_apps.sort_by(|a, b| {
        b.cold_score
            .cmp(&a.cold_score)
            .then_with(|| b.allocated_bytes.cmp(&a.allocated_bytes))
            .then_with(|| a.app_name.cmp(&b.app_name))
    });

    let total_cold_file_bytes = cold_files
        .iter()
        .fold(0u64, |acc, f| acc.saturating_add(f.allocated_bytes));
    let total_cold_app_bytes = cold_apps
        .iter()
        .fold(0u64, |acc, a| acc.saturating_add(a.allocated_bytes));

    if unscored_apps > 0 {
        notes.push(format!(
            "{unscored_apps} installed app(s) were not scored: execution history (Prefetch, BAM) needs administrator rights, and an untouched install folder alone does not show an app is unused. Run elevated for a complete list."
        ));
    }
    let advisory_note = (!notes.is_empty()).then(|| notes.join(" "));

    ColdDataReport {
        last_access_disabled,
        advisory_note,
        cold_files,
        cold_apps,
        total_cold_file_bytes,
        total_cold_app_bytes,
        unscored_apps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::time::{FILETIME_EPOCH_2000, INTERVALS_PER_MINUTE};
    use crate::volume::VolumeInfo;
    use crate::win::prefetch::InstalledAppSource;

    #[test]
    fn scores_cold_files_and_programs_across_telemetry_and_honors_last_access_flag() {
        let now_mins = current_min2000();
        let old_mins = now_mins.saturating_sub(200 * 1440);
        let recent_mins = now_mins.saturating_sub(5 * 1440);

        let mut names = NameArena::new();
        let n_root = names.push_str(r"C:\");
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
        let mut k = 10u64;
        let to_ft = |m: u32| FILETIME_EPOCH_2000 + u64::from(m) * INTERVALS_PER_MINUTE;

        let n_users = names.push_str("Users");
        raw.push(RawEntry {
            key: k,
            parent_key: 5,
            name: n_users,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: k,
            reparse_tag: 0,
        });
        let users_k = k;
        k += 1;
        let n_alice = names.push_str("Alice");
        raw.push(RawEntry {
            key: k,
            parent_key: users_k,
            name: n_alice,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: k,
            reparse_tag: 0,
        });
        let alice_k = k;
        k += 1;
        let n_dl = names.push_str("Downloads");
        raw.push(RawEntry {
            key: k,
            parent_key: alice_k,
            name: n_dl,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: k,
            reparse_tag: 0,
        });
        let dl_k = k;
        k += 1;

        let n_iso = names.push_str("ubuntu-old.iso");
        raw.push(RawEntry {
            key: k,
            parent_key: dl_k,
            name: n_iso,
            flags: NodeFlags::empty(),
            logical: 4_000_000_000,
            allocated: 4_000_000_000,
            mtime: to_ft(old_mins),
            atime: to_ft(recent_mins), // recent atime would look warm EXCEPT when LastAccessDisabled == true!
            file_id: k,
            reparse_tag: 0,
        });
        k += 1;

        let n_fresh = names.push_str("notes-new.zip");
        raw.push(RawEntry {
            key: k,
            parent_key: dl_k,
            name: n_fresh,
            flags: NodeFlags::empty(),
            logical: 200_000_000,
            allocated: 200_000_000,
            mtime: to_ft(recent_mins),
            atime: to_ft(recent_mins),
            file_id: k,
            reparse_tag: 0,
        });
        k += 1;

        let n_pf = names.push_str("Program Files");
        raw.push(RawEntry {
            key: k,
            parent_key: 5,
            name: n_pf,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: 0,
            atime: 0,
            file_id: k,
            reparse_tag: 0,
        });
        let pf_k = k;
        k += 1;

        let n_old_app = names.push_str("DormantCAD");
        raw.push(RawEntry {
            key: k,
            parent_key: pf_k,
            name: n_old_app,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: to_ft(old_mins),
            atime: to_ft(old_mins),
            file_id: k,
            reparse_tag: 0,
        });
        let old_app_k = k;
        k += 1;
        let n_old_exe = names.push_str("DormantCAD.exe");
        raw.push(RawEntry {
            key: k,
            parent_key: old_app_k,
            name: n_old_exe,
            flags: NodeFlags::empty(),
            logical: 500_000_000,
            allocated: 500_000_000,
            mtime: to_ft(old_mins),
            atime: to_ft(old_mins),
            file_id: k,
            reparse_tag: 0,
        });
        k += 1;

        let n_hot_app = names.push_str("DailyEditor");
        raw.push(RawEntry {
            key: k,
            parent_key: pf_k,
            name: n_hot_app,
            flags: NodeFlags::DIR,
            logical: 0,
            allocated: 0,
            mtime: to_ft(old_mins),
            atime: to_ft(old_mins),
            file_id: k,
            reparse_tag: 0,
        });
        let hot_app_k = k;
        k += 1;
        let n_hot_exe = names.push_str("DailyEditor.exe");
        raw.push(RawEntry {
            key: k,
            parent_key: hot_app_k,
            name: n_hot_exe,
            flags: NodeFlags::empty(),
            logical: 300_000_000,
            allocated: 300_000_000,
            mtime: to_ft(old_mins),
            atime: to_ft(old_mins),
            file_id: k,
            reparse_tag: 0,
        });

        let mut b = IndexBuilder::new(
            5,
            r"C:\",
            VolumeInfo {
                root: r"C:\".to_string(),
                ..Default::default()
            },
        );
        b.push_batch(EntryBatch {
            entries: raw,
            names,
        });
        let index = b.finish();

        let apps = vec![
            InstalledAppRecord {
                name: "DormantCAD".to_string(),
                publisher: Some("OldSoft".to_string()),
                install_location: Some(PathBuf::from(r"C:\Program Files\DormantCAD")),
                source: InstalledAppSource::Win32Uninstall,
                system_component: false,
            },
            InstalledAppRecord {
                name: "DailyEditor".to_string(),
                publisher: Some("DevCorp".to_string()),
                install_location: Some(PathBuf::from(r"C:\Program Files\DailyEditor")),
                source: InstalledAppSource::Win32Uninstall,
                system_component: false,
            },
        ];
        let bam = vec![BamEntry {
            exe_path: r"\Device\HarddiskVolume3\Program Files\DailyEditor\DailyEditor.exe"
                .to_string(),
            last_exec_filetime: to_ft(recent_mins),
        }];
        let pf = vec![PrefetchRecord {
            exe_name: "DORMANTCAD.EXE".to_string(),
            format_version: 30,
            run_count: 1,
            last_run_filetime: to_ft(old_mins),
            pf_path: None,
        }];

        let report = scan_cold_data(&index, &apps, &[], &bam, &pf, Some(true), 100_000_000, 90);

        assert!(report.advisory_note.is_some());
        assert_eq!(report.cold_files.len(), 1);
        assert!(report.cold_files[0].path.ends_with("ubuntu-old.iso"));
        assert_eq!(report.cold_apps.len(), 1);
        assert_eq!(report.cold_apps[0].app_name, "DormantCAD");
        assert!(report.cold_apps[0].telemetry_note.contains("Prefetch"));
        assert_eq!(report.unscored_apps, 0);
    }

    /// Builds a `C:\` index from `(path, bytes, mtime_filetime)` file entries, creating parent
    /// directories on the way.
    fn index_with_files(files: &[(&str, u64, u64)]) -> Index {
        let mut names = NameArena::new();
        let n_root = names.push_str(r"C:\");
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
        for (path, bytes, mtime) in files {
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
                    mtime: *mtime,
                    atime: *mtime,
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
                root: r"C:\".to_string(),
                ..Default::default()
            },
        );
        b.push_batch(EntryBatch {
            entries: raw,
            names,
        });
        b.finish()
    }

    fn app(name: &str, loc: &str, system_component: bool) -> InstalledAppRecord {
        InstalledAppRecord {
            name: name.to_string(),
            publisher: Some("NVIDIA Corporation".to_string()),
            install_location: Some(PathBuf::from(loc)),
            source: InstalledAppSource::Win32Uninstall,
            system_component,
        }
    }

    /// Regression (P9.0): ~45 CUDA MSI components sharing one install folder were each reported
    /// as a separate 4.1 GiB cold app, one of them named `${{arpDisplayName}}`.
    #[test]
    fn cold_apps_sharing_an_install_folder_are_counted_once_under_a_visible_name() {
        let old_ft = FILETIME_EPOCH_2000
            + u64::from(current_min2000().saturating_sub(200 * 1440)) * INTERVALS_PER_MINUTE;
        let cuda = r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.2";
        let index = index_with_files(&[(
            r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.2\bin\cublas64_13.dll",
            4_000_000_000,
            old_ft,
        )]);
        let apps = vec![
            app("${{arpDisplayName}}", cuda, true),
            app("CUBLAS Runtime", cuda, true),
            app("NVIDIA CUDA Toolkit 13.2", &format!(r"{cuda}\"), false),
            app("CUDA Documentation", cuda, true),
        ];
        // Execution history is available (elevated run): an unrelated Prefetch record.
        let pf = vec![PrefetchRecord {
            exe_name: "NOTEPAD.EXE".to_string(),
            format_version: 30,
            run_count: 3,
            last_run_filetime: old_ft,
            pf_path: None,
        }];

        let report = scan_cold_data(&index, &apps, &[], &[], &pf, Some(true), u64::MAX, 90);
        assert_eq!(report.cold_apps.len(), 1, "{:?}", report.cold_apps);
        assert_eq!(report.cold_apps[0].app_name, "NVIDIA CUDA Toolkit 13.2");
        assert_eq!(report.cold_apps[0].allocated_bytes, 4_000_000_000);
        assert_eq!(report.total_cold_app_bytes, 4_000_000_000);

        // All members hidden or unresolved: the folder name stands in for a template name.
        let only_template = vec![app("${{arpDisplayName}}", cuda, true)];
        let report = scan_cold_data(&index, &only_template, &[], &[], &pf, None, u64::MAX, 90);
        assert_eq!(report.cold_apps.len(), 1);
        assert_eq!(report.cold_apps[0].app_name, "v13.2");
    }

    /// Regression (P9.0): unelevated runs (no Prefetch/BAM) called every app "cold" from install
    /// folder timestamps alone.
    #[test]
    fn apps_without_execution_evidence_are_unscored_not_cold() {
        let old_ft = FILETIME_EPOCH_2000
            + u64::from(current_min2000().saturating_sub(200 * 1440)) * INTERVALS_PER_MINUTE;
        let index = index_with_files(&[
            (r"C:\Games\Tankers\tankers.exe", 900_000_000, old_ft),
            (r"C:\Tools\OldCad\oldcad.exe", 300_000_000, old_ft),
        ]);
        let apps = vec![
            app("Tankers Launcher", r"C:\Games\Tankers", false),
            app("OldCad", r"C:\Tools\OldCad", false),
        ];
        // UserAssist (no admin needed) saw OldCad launched 200 days ago: that is evidence.
        let ua = vec![UserAssistEntry {
            decoded_name: r"C:\Tools\OldCad\OldCad.exe".to_string(),
            run_count: 2,
            last_exec_filetime: old_ft,
        }];

        let report = scan_cold_data(&index, &apps, &ua, &[], &[], Some(true), u64::MAX, 90);
        let names: Vec<&str> = report
            .cold_apps
            .iter()
            .map(|a| a.app_name.as_str())
            .collect();
        assert_eq!(names, ["OldCad"]);
        assert_eq!(report.unscored_apps, 1);
        let note = report.advisory_note.expect("note");
        assert!(note.contains("LastAccess") && note.contains("1 installed app(s) were not scored"));
    }
}
