#![forbid(unsafe_code)]

//! Stale build-output sweep (P9.7).
//!
//! Active projects keep their build folders, but those folders accumulate generations nobody
//! will reuse: Cargo keeps every `<crate>-<hash>` ever built (each feature/profile change makes a
//! new one, each with its own PDBs and incremental caches), and Next.js keeps an ever-growing
//! `.next\cache`. The sweep removes only *stale generations*, measured against the project's own
//! newest build, never the build output that the next `cargo build` / `next build` will reuse.
//!
//! Deletion goes through [`safe_clean_root`] (deny list, no-follow root, file-ID pinning, final
//! path containment), exactly like cleanup rules.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path};
use crate::clean::plan::{FileIdKind, PlannedItem, PlannedRoot};
use crate::error::{DskError, Result};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::win::cleaner::safe_clean_root;
use crate::win::preconditions::running_processes;

const MINUTES_PER_DAY: u32 = 1440;

/// Which kind of build folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepKind {
    CargoTarget,
    NextCache,
}

impl SweepKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::CargoTarget => "Cargo target",
            Self::NextCache => "Next.js cache",
        }
    }

    /// Processes that may be writing into the folder.
    pub fn blocking_processes(self) -> &'static [&'static str] {
        match self {
            Self::CargoTarget => &[
                "cargo.exe",
                "rustc.exe",
                "rust-analyzer.exe",
                "clippy-driver.exe",
            ],
            Self::NextCache => &["node.exe"],
        }
    }
}

/// Options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepOptions {
    /// Generations older than the project's newest build by more than this are stale.
    pub keep_days: u32,
    /// Minutes since 2000-01-01 (`None` = now). Used only for the Next.js cache.
    pub now_min2000: Option<u32>,
}

impl Default for SweepOptions {
    fn default() -> Self {
        Self {
            keep_days: 14,
            now_min2000: None,
        }
    }
}

/// One build folder with its stale generations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepCandidate {
    pub kind: SweepKind,
    /// The swept folder (`...\target` or `...\.next\cache`).
    pub root: PathBuf,
    pub project: PathBuf,
    pub total_bytes: u64,
    pub stale_bytes: u64,
    pub stale_units: usize,
    pub kept_units: usize,
    /// Days between now and the newest build output.
    pub newest_build_days: Option<u32>,
    pub notes: Vec<String>,
    /// Items for [`safe_clean_root`], children before parents.
    pub planned: PlannedRoot,
}

/// Result of [`execute_sweep`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepOutcome {
    pub root: PathBuf,
    pub dry_run: bool,
    pub deleted_bytes: u64,
    pub deleted: u64,
    pub skipped: u64,
    pub failed: u64,
    pub failures: Vec<String>,
}

fn child_named(index: &Index, dir: NodeId, name: &str) -> Option<NodeId> {
    index
        .children(dir)
        .find(|&c| index.name(c).eq_ignore_ascii_case(name))
}

fn is_dir(index: &Index, n: NodeId) -> bool {
    let f = index.flags(n);
    f.contains(NodeFlags::DIR) && !f.contains(NodeFlags::REPARSE)
}

/// Newest write time (minutes since 2000) in a subtree.
fn newest_in(index: &Index, node: NodeId) -> u32 {
    let mut newest = index.mtime_min(node);
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        newest = newest.max(index.mtime_min(n));
        if is_dir(index, n) {
            stack.extend(index.children(n));
        }
    }
    newest
}

/// Appends post-order items for the whole subtree at `node` (`rel` is its path under the root).
/// Cloud/offline/metafile nodes are left alone, so their parents are kept too.
fn push_subtree_items(index: &Index, node: NodeId, rel: &str, out: &mut Vec<PlannedItem>) -> u64 {
    let flags = index.flags(node);
    if flags.intersects(NodeFlags::CLOUD | NodeFlags::OFFLINE | NodeFlags::METAFILE) {
        return 0;
    }
    let mut bytes = 0u64;
    if is_dir(index, node) {
        let before = out.len();
        let mut complete = true;
        for c in index.children(node) {
            let cf = index.flags(c);
            if cf.intersects(NodeFlags::CLOUD | NodeFlags::OFFLINE | NodeFlags::METAFILE) {
                complete = false;
                continue;
            }
            let child_rel = format!("{rel}\\{}", index.name(c));
            bytes = bytes.saturating_add(push_subtree_items(index, c, &child_rel, out));
        }
        let _ = before;
        if complete {
            out.push(PlannedItem {
                rel_path: rel.to_string(),
                expected_file_id: index.file_id(node),
                bytes: 0,
                is_dir: true,
                mtime_min: index.mtime_min(node),
            });
        }
    } else {
        let b = if flags.contains(NodeFlags::DUP_LINK) {
            0
        } else {
            index.allocated(node)
        };
        bytes = b;
        out.push(PlannedItem {
            rel_path: rel.to_string(),
            expected_file_id: index.file_id(node),
            bytes: b,
            is_dir: false,
            mtime_min: index.mtime_min(node),
        });
    }
    bytes
}

/// Splits `name-<16 hex>[.ext...]` into `(name, hash)`.
pub fn split_cargo_hash(file_or_dir: &str) -> Option<(&str, &str)> {
    let stem = file_or_dir.split('.').next().unwrap_or(file_or_dir);
    let (name, hash) = stem.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && !name.is_empty())
        .then_some((name, hash))
}

#[derive(Default)]
struct Unit {
    crate_name: String,
    newest: u32,
    nodes: Vec<(NodeId, String)>,
}

/// Plans the sweep of one Cargo `target` directory.
pub fn plan_cargo_target(
    index: &Index,
    target: NodeId,
    opts: &SweepOptions,
    file_id_kind: FileIdKind,
) -> Option<SweepCandidate> {
    if !is_dir(index, target) || child_named(index, target, "CACHEDIR.TAG").is_none() {
        return None;
    }
    let project = index.path(index.parent(target));
    let keep_mins = opts.keep_days.saturating_mul(MINUTES_PER_DAY);

    // Profiles: `target\<p>` or `target\<triple>\<p>` holding `deps` or `.fingerprint`.
    let mut profiles: Vec<(NodeId, String)> = Vec::new();
    for c in index.children(target).filter(|&c| is_dir(index, c)) {
        let cname = index.name(c).into_owned();
        if child_named(index, c, "deps").is_some()
            || child_named(index, c, ".fingerprint").is_some()
        {
            profiles.push((c, cname));
        } else {
            for g in index.children(c).filter(|&g| is_dir(index, g)) {
                if child_named(index, g, "deps").is_some() {
                    profiles.push((g, format!("{cname}\\{}", index.name(g))));
                }
            }
        }
    }

    let mut items = Vec::new();
    let mut stale_bytes = 0u64;
    let mut stale_units = 0usize;
    let mut kept_units = 0usize;
    let mut newest_overall = 0u32;
    let mut notes = Vec::new();

    for (profile, prel) in &profiles {
        let mut units: FxHashMap<String, Unit> = FxHashMap::default();
        let mut add = |hash: &str, name: &str, node: NodeId, rel: String, newest: u32| {
            let u = units.entry(hash.to_string()).or_default();
            if u.crate_name.is_empty() || !name.starts_with("lib") {
                u.crate_name = name.to_string();
            }
            u.newest = u.newest.max(newest);
            u.nodes.push((node, rel));
        };
        for sub in [".fingerprint", "build"] {
            if let Some(dir) = child_named(index, *profile, sub) {
                for c in index.children(dir) {
                    let name = index.name(c);
                    if let Some((crate_name, hash)) = split_cargo_hash(&name) {
                        add(
                            hash,
                            crate_name,
                            c,
                            format!("{prel}\\{sub}\\{name}"),
                            newest_in(index, c),
                        );
                    }
                }
            }
        }
        if let Some(deps) = child_named(index, *profile, "deps") {
            for c in index.children(deps) {
                let name = index.name(c);
                if let Some((crate_name, hash)) = split_cargo_hash(&name) {
                    add(
                        hash,
                        crate_name,
                        c,
                        format!("{prel}\\deps\\{name}"),
                        newest_in(index, c),
                    );
                }
            }
        }
        // Incremental caches: `incremental\<crate>-<hash>` with their own hashes.
        let mut incr: Vec<(NodeId, String, String, u32)> = Vec::new();
        if let Some(dir) = child_named(index, *profile, "incremental") {
            for c in index.children(dir).filter(|&c| is_dir(index, c)) {
                let name = index.name(c).into_owned();
                if let Some((crate_name, _)) = split_cargo_hash(&name) {
                    incr.push((
                        c,
                        crate_name.to_string(),
                        format!("{prel}\\incremental\\{name}"),
                        newest_in(index, c),
                    ));
                }
            }
        }

        let profile_newest = units
            .values()
            .map(|u| u.newest)
            .chain(incr.iter().map(|i| i.3))
            .max()
            .unwrap_or(0);
        if profile_newest == 0 {
            continue;
        }
        newest_overall = newest_overall.max(profile_newest);
        let cutoff = profile_newest.saturating_sub(keep_mins);

        // Always keep the newest generation of every crate name.
        let mut newest_by_crate: FxHashMap<String, u32> = FxHashMap::default();
        for u in units.values() {
            let e = newest_by_crate.entry(u.crate_name.clone()).or_default();
            *e = (*e).max(u.newest);
        }
        for u in units.values() {
            let keep = u.newest >= cutoff || newest_by_crate.get(&u.crate_name) == Some(&u.newest);
            if keep {
                kept_units += 1;
                continue;
            }
            stale_units += 1;
            for (node, rel) in &u.nodes {
                stale_bytes =
                    stale_bytes.saturating_add(push_subtree_items(index, *node, rel, &mut items));
            }
        }
        let mut newest_incr: FxHashMap<String, u32> = FxHashMap::default();
        for (_, name, _, newest) in &incr {
            let e = newest_incr.entry(name.clone()).or_default();
            *e = (*e).max(*newest);
        }
        for (node, name, rel, newest) in &incr {
            if *newest >= cutoff || newest_incr.get(name) == Some(newest) {
                kept_units += 1;
                continue;
            }
            stale_units += 1;
            stale_bytes =
                stale_bytes.saturating_add(push_subtree_items(index, *node, rel, &mut items));
        }
    }

    if profiles.is_empty() {
        notes.push("no Cargo profile folders (deps/.fingerprint) found".into());
    }
    let now = opts
        .now_min2000
        .unwrap_or_else(crate::insights::current_min2000);
    Some(SweepCandidate {
        kind: SweepKind::CargoTarget,
        root: index.path(target),
        project,
        total_bytes: index.total_allocated(target),
        stale_bytes,
        stale_units,
        kept_units,
        newest_build_days: (newest_overall > 0 && now > newest_overall)
            .then(|| (now - newest_overall) / MINUTES_PER_DAY),
        notes,
        planned: PlannedRoot {
            root_path: index.path(target).to_string_lossy().into_owned(),
            root_file_id: index.file_id(target),
            file_id_kind,
            min_age_days: None,
            exclude_names: Vec::new(),
            allow_unlisted_children: false,
            items: dedupe_items(items),
        },
    })
}

/// Plans the sweep of a Next.js `.next\cache`: files untouched for `keep_days`.
pub fn plan_next_cache(
    index: &Index,
    cache: NodeId,
    opts: &SweepOptions,
    file_id_kind: FileIdKind,
) -> Option<SweepCandidate> {
    if !is_dir(index, cache) {
        return None;
    }
    let now = opts
        .now_min2000
        .unwrap_or_else(crate::insights::current_min2000);
    let cutoff = now.saturating_sub(opts.keep_days.saturating_mul(MINUTES_PER_DAY));
    let mut items = Vec::new();
    let mut stale_bytes = 0u64;
    let mut stale_units = 0usize;
    let mut kept_units = 0usize;
    // Post-order: a directory is removed only when everything under it is.
    fn walk(
        index: &Index,
        node: NodeId,
        rel: &str,
        cutoff: u32,
        items: &mut Vec<PlannedItem>,
        stale: &mut (u64, usize, usize),
    ) -> bool {
        let mut all = true;
        for c in index.children(node) {
            let f = index.flags(c);
            let crel = if rel.is_empty() {
                index.name(c).into_owned()
            } else {
                format!("{rel}\\{}", index.name(c))
            };
            if f.intersects(
                NodeFlags::CLOUD | NodeFlags::OFFLINE | NodeFlags::METAFILE | NodeFlags::REPARSE,
            ) {
                all = false;
                continue;
            }
            if f.contains(NodeFlags::DIR) {
                if walk(index, c, &crel, cutoff, items, stale) {
                    items.push(PlannedItem {
                        rel_path: crel,
                        expected_file_id: index.file_id(c),
                        bytes: 0,
                        is_dir: true,
                        mtime_min: index.mtime_min(c),
                    });
                } else {
                    all = false;
                }
            } else if index.mtime_min(c) < cutoff {
                let b = index.allocated(c);
                stale.0 = stale.0.saturating_add(b);
                stale.1 += 1;
                items.push(PlannedItem {
                    rel_path: crel,
                    expected_file_id: index.file_id(c),
                    bytes: b,
                    is_dir: false,
                    mtime_min: index.mtime_min(c),
                });
            } else {
                stale.2 += 1;
                all = false;
            }
        }
        all
    }
    let mut acc = (0u64, 0usize, 0usize);
    walk(index, cache, "", cutoff, &mut items, &mut acc);
    stale_bytes += acc.0;
    stale_units += acc.1;
    kept_units += acc.2;
    let newest = newest_in(index, cache);
    let next_dir = index.parent(cache);
    Some(SweepCandidate {
        kind: SweepKind::NextCache,
        root: index.path(cache),
        project: index.path(index.parent(next_dir)),
        total_bytes: index.total_allocated(cache),
        stale_bytes,
        stale_units,
        kept_units,
        newest_build_days: (newest > 0 && now > newest).then(|| (now - newest) / MINUTES_PER_DAY),
        notes: Vec::new(),
        planned: PlannedRoot {
            root_path: index.path(cache).to_string_lossy().into_owned(),
            root_file_id: index.file_id(cache),
            file_id_kind,
            min_age_days: None,
            exclude_names: Vec::new(),
            allow_unlisted_children: false,
            items,
        },
    })
}

fn dedupe_items(items: Vec<PlannedItem>) -> Vec<PlannedItem> {
    let mut seen: FxHashSet<String> = FxHashSet::default();
    items
        .into_iter()
        .filter(|i| seen.insert(i.rel_path.to_ascii_lowercase()))
        .collect()
}

/// Finds every Cargo target (`target` with `CACHEDIR.TAG` beside a `Cargo.toml`) and Next.js
/// cache (`.next\cache` beside a `package.json`) in the index, largest stale share first.
pub fn find_sweep_candidates(
    index: &Index,
    opts: &SweepOptions,
    file_id_kind: FileIdKind,
    deny: &DenyContext,
) -> Vec<SweepCandidate> {
    let mut out = Vec::new();
    let mut stack = vec![ROOT];
    while let Some(dir) = stack.pop() {
        for c in index.children(dir) {
            if !is_dir(index, c) {
                continue;
            }
            let name = index.name(c);
            if name.eq_ignore_ascii_case("target")
                && child_named(index, dir, "Cargo.toml").is_some()
                && child_named(index, c, "CACHEDIR.TAG").is_some()
            {
                if is_denied_path(&index.path(c), deny).is_none()
                    && let Some(cand) = plan_cargo_target(index, c, opts, file_id_kind)
                {
                    out.push(cand);
                }
                continue;
            }
            if name.eq_ignore_ascii_case(".next")
                && child_named(index, dir, "package.json").is_some()
            {
                if let Some(cache) = child_named(index, c, "cache")
                    && is_denied_path(&index.path(cache), deny).is_none()
                    && let Some(cand) = plan_next_cache(index, cache, opts, file_id_kind)
                {
                    out.push(cand);
                }
                continue;
            }
            stack.push(c);
        }
    }
    out.retain(|c| c.stale_bytes > 0 || !c.notes.is_empty());
    out.sort_by_key(|a| std::cmp::Reverse(a.stale_bytes));
    out
}

/// Deletes a candidate's stale generations. Refuses while a build tool runs, or when the target
/// no longer carries Cargo's `CACHEDIR.TAG`.
pub fn execute_sweep(
    candidate: &SweepCandidate,
    deny: &DenyContext,
    dry_run: bool,
    cancel: &AtomicBool,
) -> Result<SweepOutcome> {
    if !dry_run {
        let running = running_processes().unwrap_or_default();
        let blockers: Vec<&str> = candidate
            .kind
            .blocking_processes()
            .iter()
            .copied()
            .filter(|p| running.iter().any(|r| r.eq_ignore_ascii_case(p)))
            .collect();
        if !blockers.is_empty() {
            return Err(DskError::PreconditionFailed(format!(
                "close {} first; it may be writing into {}",
                blockers.join(", "),
                candidate.root.display()
            )));
        }
        if candidate.kind == SweepKind::CargoTarget
            && !candidate.root.join("CACHEDIR.TAG").is_file()
        {
            return Err(DskError::PreconditionFailed(format!(
                "{} no longer looks like a Cargo target (CACHEDIR.TAG missing)",
                candidate.root.display()
            )));
        }
    }
    run_planned(candidate, deny, dry_run, cancel)
}

/// Deletes the planned items without the running-process precondition (tests run under
/// `cargo.exe`).
pub(crate) fn run_planned(
    candidate: &SweepCandidate,
    deny: &DenyContext,
    dry_run: bool,
    cancel: &AtomicBool,
) -> Result<SweepOutcome> {
    let now = crate::insights::current_min2000();
    let report = safe_clean_root(&candidate.planned, deny, dry_run, now, cancel)?;
    Ok(SweepOutcome {
        root: candidate.root.clone(),
        dry_run,
        deleted_bytes: report.deleted_bytes,
        deleted: report.deleted_count,
        skipped: report.skipped_count,
        failed: report.failed_count,
        failures: report
            .outcomes
            .iter()
            .filter(|o| o.kind == crate::win::cleaner::DeleteOutcomeKind::Failed)
            .take(20)
            .map(|o| format!("{}: {}", o.path, o.detail.clone().unwrap_or_default()))
            .collect(),
    })
}

/// Path of a candidate's root (for display).
pub fn candidate_root(c: &SweepCandidate) -> &Path {
    &c.root
}

#[cfg(test)]
mod tests;
