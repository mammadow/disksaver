#![forbid(unsafe_code)]

//! Disk hunt (P9.10): explores the whole index for the biggest removable things and for swarms
//! of small things that add up.
//!
//! Every file gets a removability [`Verdict`] in linear passes over the [`Index`] (no disk I/O).
//! Folders collapse into *units* (one finding instead of thousands of files), big files outside a
//! unit are listed on their own, and swarm detectors group recurring folder names, file families,
//! file-count hot spots, and copy-like names. The hunt only proposes; deny-listed nodes never carry
//! an action.

use std::path::{Path, PathBuf};

use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::ledger::{ActionRef, Lane, Ledger};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const MINUTES_PER_DAY: u32 = 1440;

/// Removability of a node, highest precedence first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Verdict {
    /// Deny-listed system location or system file. Never actionable.
    Protected = 0,
    /// Owned by a ledger opportunity (rule, build output, duplicate, model, ...).
    Claimed = 1,
    /// Left behind: installers, partial downloads, dumps, backups, old logs, older versions.
    Leftover = 2,
    /// Large personal data untouched for a long time.
    ColdUserData = 3,
    /// Inside an installed app or game.
    InstalledApp = 4,
    /// In use, recent, or unknown.
    Active = 5,
}

impl Verdict {
    pub const ALL: [Verdict; 6] = [
        Verdict::Protected,
        Verdict::Claimed,
        Verdict::Leftover,
        Verdict::ColdUserData,
        Verdict::InstalledApp,
        Verdict::Active,
    ];

    pub fn from_u8(v: u8) -> Verdict {
        Self::ALL
            .get(v as usize)
            .copied()
            .unwrap_or(Verdict::Active)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::Claimed => "claimed",
            Self::Leftover => "leftover",
            Self::ColdUserData => "cold",
            Self::InstalledApp => "installed",
            Self::Active => "active",
        }
    }

    /// Parses a CLI label (`protected`, `claimed`, `leftover`, `cold`, `installed`, `active`).
    pub fn parse(s: &str) -> Option<Verdict> {
        Self::ALL
            .into_iter()
            .find(|v| v.label().eq_ignore_ascii_case(s.trim()))
    }

    /// Ranking weight: how readily the bytes can be freed.
    fn weight(self) -> f64 {
        match self {
            Self::Claimed => 1.0,
            Self::Leftover => 0.9,
            Self::ColdUserData => 0.6,
            Self::InstalledApp => 0.4,
            Self::Active => 0.25,
            Self::Protected => 0.05,
        }
    }
}

/// What a finding represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A folder whose bytes share one verdict.
    Unit,
    /// A single big file outside any unit.
    BigFile,
    /// Many small things grouped together.
    Swarm,
}

/// Swarm detector that produced a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmKind {
    RecurringFolder,
    FileFamily,
    CountHotspot,
    NamePattern,
}

/// One hunt result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HuntFinding {
    pub kind: FindingKind,
    pub verdict: Verdict,
    pub title: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub file_count: u64,
    pub days_since_touch: Option<u32>,
    /// 0–100.
    pub confidence: u8,
    /// Why the hunt thinks so.
    pub reason: String,
    pub action: ActionRef,
    /// Ledger opportunity that owns these bytes, if any.
    pub opportunity_id: Option<String>,
    pub swarm: Option<SwarmKind>,
    /// Up to 50 member paths for swarms, largest first.
    pub members: Vec<PathBuf>,
    pub member_count: u64,
    pub score: f64,
}

/// Bytes and files per verdict across the hunted tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictTotal {
    pub verdict: Verdict,
    pub bytes: u64,
    pub files: u64,
}

/// Space the scan could not see.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unaccounted {
    pub volume_used_bytes: u64,
    pub scanned_bytes: u64,
    pub gap_bytes: u64,
    pub causes: Vec<String>,
}

/// Full hunt output.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HuntReport {
    pub scanned_path: String,
    /// Units and big files, best first.
    pub findings: Vec<HuntFinding>,
    /// Swarms (only with `HuntOptions::many`).
    pub swarms: Vec<HuntFinding>,
    pub verdict_totals: Vec<VerdictTotal>,
    pub unaccounted: Option<Unaccounted>,
    /// Findings suppressed by the ignore list.
    pub ignored: u64,
    pub notes: Vec<String>,
}

/// Tunables.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HuntOptions {
    pub top: usize,
    pub min_unit_bytes: u64,
    pub min_file_bytes: u64,
    pub cold_days: u32,
    pub leftover_days: u32,
    pub many: bool,
    /// Keep only these verdicts in `findings`/`swarms` (empty = all).
    pub verdict_filter: Vec<Verdict>,
    /// Keep only findings untouched for at least this many days.
    pub older_than_days: Option<u32>,
    /// Minutes since 2000-01-01 (`None` = now).
    pub now_min2000: Option<u32>,
}

impl Default for HuntOptions {
    fn default() -> Self {
        Self {
            top: 50,
            min_unit_bytes: 256 * MIB,
            min_file_bytes: 256 * MIB,
            cold_days: 90,
            leftover_days: 30,
            many: false,
            verdict_filter: Vec::new(),
            older_than_days: None,
            now_min2000: None,
        }
    }
}

/// An installed app or game folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledRoot {
    pub path: PathBuf,
    pub name: String,
    /// Launcher name for games (`Steam`, `Epic Games`, ...); `None` for apps.
    pub store: Option<String>,
}

/// Inputs beyond the index.
pub struct HuntContext<'a> {
    pub ledger: Option<&'a Ledger>,
    pub deny: DenyContext,
    pub installed: Vec<InstalledRoot>,
    /// Paths (and their subtrees) the owner asked never to suggest.
    pub ignore: Vec<PathBuf>,
    /// Directories the scanner could not open.
    pub skipped_dirs: u64,
    pub elevated: bool,
    /// Raw `$MFT` scans also see metadata and alternate data streams.
    pub mft_scan: bool,
}

impl HuntContext<'_> {
    pub fn new(deny: DenyContext) -> Self {
        Self {
            ledger: None,
            deny,
            installed: Vec::new(),
            ignore: Vec::new(),
            skipped_dirs: 0,
            elevated: false,
            mft_scan: false,
        }
    }
}

/// Per-node verdicts plus the aggregates the report is built from.
pub struct HuntClassification {
    /// Verdict per node (files: own verdict; directories: dominant verdict by bytes).
    pub verdicts: Vec<u8>,
    order: Vec<NodeId>,
    dir_slot: Vec<u32>,
    dirs: Vec<DirAgg>,
    file_reason: FxHashMap<NodeId, &'static str>,
    ignored_nodes: u64,
}

impl HuntClassification {
    /// Verdict of `node`.
    pub fn verdict(&self, node: NodeId) -> Verdict {
        Verdict::from_u8(self.verdicts.get(node as usize).copied().unwrap_or(5))
    }
}

#[derive(Clone, Default)]
struct DirAgg {
    bytes: [u64; 6],
    files: u64,
    logical: u64,
    newest_touch: u32,
    /// 0 none, 1 system-protected subtree, 2 personal library.
    protection: u8,
    installed: u32,
    ignored: bool,
    under_downloads: bool,
    leftover_reason: Option<String>,
    swarm_mask: u32,
    /// Another install root (a game in a launcher folder) sits somewhere below.
    nested_install: bool,
}

/// Folder names that recur across a disk and are usually caches or build output.
const RECURRING_NAMES: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    ".next",
    ".nuxt",
    ".turbo",
    ".parcel-cache",
    ".gradle",
    "obj",
    "cache",
    "code cache",
    "gpucache",
    "shadercache",
    "grshadercache",
    ".cache",
    "logs",
    "crashdumps",
    "crashpad",
    "deriveddatacache",
    "intermediate",
];

const MEDIA_ARCHIVE_DATA_EXTS: &[&str] = &[
    "mp4", "mkv", "mov", "avi", "wmv", "webm", "m4v", "ts", "mts", "flv", "wav", "flac", "mp3",
    "aac", "m4a", "raw", "cr2", "nef", "arw", "dng", "psd", "tif", "tiff", "zip", "7z", "rar",
    "tar", "gz", "tgz", "xz", "zst", "bz2", "iso", "img", "dmg", "csv", "parquet", "npz", "npy",
    "h5", "hdf5", "pkl", "tfrecord", "arrow", "feather",
];

const VIRTUAL_DISK_EXTS: &[&str] = &["vhd", "vhdx", "avhd", "avhdx", "vmdk", "vdi", "qcow2"];

fn ext_of(name: &str) -> Option<String> {
    name.rsplit_once('.')
        .filter(|(stem, ext)| !stem.is_empty() && !ext.is_empty() && ext.len() <= 16)
        .map(|(_, e)| e.to_ascii_lowercase())
}

/// Evidence that a *file* was left behind. `days` is the age since last write.
pub fn leftover_file_reason(
    name: &str,
    days: u32,
    leftover_days: u32,
    under_downloads: bool,
) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let ext = ext_of(&lower);
    let ext = ext.as_deref().unwrap_or("");
    let week = days >= 7;
    let old = days >= leftover_days;
    match ext {
        "tmp" | "temp" | "crdownload" | "part" | "partial" | "download" | "!qb" | "!ut" if week => {
            Some("temporary file or unfinished download")
        }
        "dmp" | "mdmp" | "hdmp" | "hprof" if week => Some("crash or heap dump"),
        "bak" | "old" | "orig" if old => Some("backup copy"),
        "log" | "etl" | "trace" if old => Some("old log or trace"),
        "exe" | "msi" | "msix" | "msixbundle" | "appx" | "appxbundle" if under_downloads && old => {
            Some("installer kept in Downloads")
        }
        _ => None,
    }
}

/// Splits `name` into `(prefix, numeric version)` at the first digit when the rest is only digits
/// and dots, e.g. `gradle-8.5` → (`gradle-`, [8, 5]), `IntelliJIdea2025.1` → (`IntelliJIdea`,
/// [2025, 1]). A leading `v` after a separator belongs to the version.
pub fn split_version(name: &str) -> Option<(String, Vec<u64>)> {
    let pos = name.find(|c: char| c.is_ascii_digit())?;
    let (mut prefix, rest) = name.split_at(pos);
    if prefix.ends_with(['v', 'V']) {
        let trimmed = &prefix[..prefix.len() - 1];
        if trimmed.is_empty() || trimmed.ends_with(['-', '_', ' ', '.']) {
            prefix = trimmed;
        }
    }
    if prefix.trim_end_matches(['-', '_', ' ', '.']).len() < 2 {
        return None;
    }
    if !rest.chars().all(|c| c.is_ascii_digit() || c == '.') || rest.ends_with('.') {
        return None;
    }
    let parts: Option<Vec<u64>> = rest.split('.').map(|p| p.parse().ok()).collect();
    Some((prefix.to_ascii_lowercase(), parts?))
}

/// Copy-like names: `name (2).ext`, `Copy of name`, `name - Copy.ext`.
pub fn copy_pattern(name: &str) -> Option<&'static str> {
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    let lower = stem.to_ascii_lowercase();
    if lower.starts_with("copy of ") || lower.ends_with(" - copy") || lower.contains(" - copy (") {
        return Some("“Copy of” / “- Copy” names");
    }
    if let Some(open) = stem.rfind(" (")
        && stem.ends_with(')')
        && stem[open + 2..stem.len() - 1]
            .chars()
            .all(|c| c.is_ascii_digit())
        && stem.len() > open + 3
    {
        return Some("“name (N)” duplicates");
    }
    None
}

fn now_min2000() -> u32 {
    crate::insights::current_min2000()
}

fn days_since(now: u32, touch: u32) -> Option<u32> {
    (touch > 0).then(|| now.saturating_sub(touch) / MINUTES_PER_DAY)
}

/// Classifies every node.
pub fn classify(index: &Index, ctx: &HuntContext<'_>, opts: &HuntOptions) -> HuntClassification {
    let n = index.len();
    let now = opts.now_min2000.unwrap_or_else(now_min2000);

    // Breadth-first order: parents before children.
    let mut order: Vec<NodeId> = Vec::with_capacity(n);
    if n > 0 {
        order.push(ROOT);
    }
    let mut i = 0;
    while i < order.len() {
        let node = order[i];
        i += 1;
        let f = index.flags(node);
        if f.contains(NodeFlags::DIR) && (node == ROOT || !f.contains(NodeFlags::REPARSE)) {
            order.extend(index.children(node));
        }
    }

    let mut dir_slot = vec![u32::MAX; n];
    let mut dirs: Vec<DirAgg> = Vec::new();
    let mut depth = vec![0u16; 0];
    for &node in &order {
        if index.flags(node).contains(NodeFlags::DIR) {
            dir_slot[node as usize] = dirs.len() as u32;
            dirs.push(DirAgg {
                installed: u32::MAX,
                ..Default::default()
            });
            depth.push(0);
        }
    }

    let installed_nodes: FxHashMap<NodeId, u32> = ctx
        .installed
        .iter()
        .enumerate()
        .filter_map(|(i, r)| index.find_by_path(&r.path).map(|n| (n, i as u32)))
        .collect();
    let ignored_nodes: FxHashSet<NodeId> = ctx
        .ignore
        .iter()
        .filter_map(|p| index.find_by_path(p))
        .collect();

    // Top-down directory attributes.
    for &node in &order {
        let Some(&slot) = dir_slot.get(node as usize) else {
            continue;
        };
        if slot == u32::MAX {
            continue;
        }
        let parent = index.parent(node);
        let (mut agg, d) = if node == ROOT || parent as usize >= n {
            (
                DirAgg {
                    installed: u32::MAX,
                    ..Default::default()
                },
                0u16,
            )
        } else {
            let ps = dir_slot[parent as usize] as usize;
            let p = &dirs[ps];
            (
                DirAgg {
                    protection: p.protection,
                    installed: p.installed,
                    ignored: p.ignored,
                    under_downloads: p.under_downloads,
                    leftover_reason: p.leftover_reason.clone(),
                    swarm_mask: p.swarm_mask,
                    ..Default::default()
                },
                depth[ps].saturating_add(1),
            )
        };
        depth[slot as usize] = d;
        let name = index.name(node);
        if agg.protection == 0 && d <= 6 {
            // Probe two levels down: a denial that holds there covers the whole subtree, which
            // separates protected subtrees (System32, personal libraries) from exact-path denials
            // (a profile root, the Users folder).
            let probe = index.path(node).join("__dsk_probe__").join("__dsk_probe__");
            if let Some(reason) = is_denied_path(&probe, &ctx.deny) {
                agg.protection = if reason.contains("personal library") {
                    2
                } else {
                    1
                };
            }
        }
        if let Some(&i) = installed_nodes.get(&node) {
            agg.installed = i;
        }
        if ignored_nodes.contains(&node) {
            agg.ignored = true;
        }
        if d >= 2 && name.eq_ignore_ascii_case("downloads") {
            agg.under_downloads = true;
        }
        dirs[slot as usize] = agg;
    }

    // Older sibling versions (directory-level leftovers).
    for &node in &order {
        let slot = dir_slot[node as usize];
        if slot == u32::MAX {
            continue;
        }
        let parent_agg = &dirs[slot as usize];
        if parent_agg.protection != 0 || parent_agg.installed != u32::MAX {
            continue;
        }
        let parent_path_lower = index.path(node).to_string_lossy().to_ascii_lowercase();
        if parent_path_lower.contains(r"\program files")
            || parent_path_lower.contains(r"\windows\")
            || parent_path_lower.ends_with(r"\windows")
            || parent_path_lower.contains(r"\dotnet")
        {
            continue;
        }
        let mut groups: FxHashMap<String, Vec<(NodeId, Vec<u64>)>> = FxHashMap::default();
        for c in index.children(node) {
            if !index.flags(c).contains(NodeFlags::DIR) || installed_nodes.contains_key(&c) {
                continue;
            }
            if let Some((prefix, ver)) = split_version(&index.name(c)) {
                groups.entry(prefix).or_default().push((c, ver));
            }
        }
        for (_, mut members) in groups {
            if members.len() < 2 {
                continue;
            }
            members.sort_by(|a, b| b.1.cmp(&a.1));
            let newest_name = index.name(members[0].0).into_owned();
            for (old, _) in members.into_iter().skip(1) {
                let s = dir_slot[old as usize];
                if s != u32::MAX {
                    dirs[s as usize].leftover_reason =
                        Some(format!("older version beside {newest_name}"));
                }
            }
        }
    }
    // Re-inherit leftover reasons set on siblings after the first pass.
    for &node in &order {
        let slot = dir_slot[node as usize];
        if slot == u32::MAX || node == ROOT {
            continue;
        }
        let ps = dir_slot[index.parent(node) as usize];
        if ps != u32::MAX
            && dirs[slot as usize].leftover_reason.is_none()
            && let Some(r) = dirs[ps as usize].leftover_reason.clone()
        {
            dirs[slot as usize].leftover_reason = Some(r);
        }
    }

    // Per-file verdicts.
    let mut verdicts = vec![Verdict::Active as u8; n];
    let mut file_reason: FxHashMap<NodeId, &'static str> = FxHashMap::default();
    let mut ignored_count = 0u64;
    let owner =
        |node: NodeId| -> Option<Lane> { ctx.ledger.and_then(|l| l.owner(node)).map(|o| o.lane) };
    for &node in &order {
        let f = index.flags(node);
        if f.contains(NodeFlags::DIR) {
            continue;
        }
        let parent = index.parent(node);
        let ps = dir_slot.get(parent as usize).copied().unwrap_or(u32::MAX);
        let Some(p) = (ps != u32::MAX).then(|| &dirs[ps as usize]) else {
            continue;
        };
        let name = index.name(node);
        let lower = name.to_ascii_lowercase();
        let days = days_since(now, index.mtime_min(node)).unwrap_or(0);
        let alloc = index.allocated(node);
        let ext = ext_of(&lower);
        let is_vdisk = ext
            .as_deref()
            .is_some_and(|e| VIRTUAL_DISK_EXTS.contains(&e));
        let at_root = parent == ROOT;
        let system_file = at_root
            && matches!(
                lower.as_str(),
                "hiberfil.sys"
                    | "pagefile.sys"
                    | "swapfile.sys"
                    | "dumpstack.log.tmp"
                    | "dumpstack.log"
            );

        let verdict = if p.ignored {
            ignored_count += 1;
            Verdict::Active
        } else if system_file || p.protection == 1 || f.contains(NodeFlags::METAFILE) {
            Verdict::Protected
        } else if owner(node).is_some() {
            Verdict::Claimed
        } else if p.protection == 2 {
            // Personal libraries: listed, never actioned.
            if alloc >= 64 * MIB && days >= opts.cold_days {
                Verdict::ColdUserData
            } else {
                Verdict::Active
            }
        } else if p.installed != u32::MAX {
            Verdict::InstalledApp
        } else if is_vdisk {
            Verdict::Active
        } else if let Some(reason) =
            leftover_file_reason(&name, days, opts.leftover_days, p.under_downloads)
        {
            file_reason.insert(node, reason);
            Verdict::Leftover
        } else if p.leftover_reason.is_some() && days >= opts.leftover_days {
            Verdict::Leftover
        } else if (alloc >= 64 * MIB
            && days >= opts.cold_days
            && ext
                .as_deref()
                .is_some_and(|e| MEDIA_ARCHIVE_DATA_EXTS.contains(&e)))
            || (alloc >= GIB && days >= 365)
        {
            Verdict::ColdUserData
        } else {
            Verdict::Active
        };
        verdicts[node as usize] = verdict as u8;

        let agg = &mut dirs[ps as usize];
        agg.bytes[verdict as usize] = agg.bytes[verdict as usize].saturating_add(alloc);
        agg.files += 1;
        agg.logical = agg.logical.saturating_add(index.logical(node));
        agg.newest_touch = agg.newest_touch.max(index.mtime_min(node));
    }

    // Bottom-up aggregation and directory verdicts.
    for &node in order.iter().rev() {
        let slot = dir_slot[node as usize];
        if slot == u32::MAX {
            continue;
        }
        let (bytes, files, logical, newest, installed, nested) = {
            let a = &dirs[slot as usize];
            (
                a.bytes,
                a.files,
                a.logical,
                a.newest_touch,
                a.installed,
                a.nested_install,
            )
        };
        let dom = (0..6).max_by_key(|&v| bytes[v]).unwrap_or(5);
        verdicts[node as usize] = if bytes.iter().all(|&b| b == 0) {
            Verdict::Active as u8
        } else {
            dom as u8
        };
        if node == ROOT {
            continue;
        }
        let ps = dir_slot[index.parent(node) as usize];
        if ps == u32::MAX || ps == slot {
            continue;
        }
        let p = &mut dirs[ps as usize];
        if nested || (installed != u32::MAX && installed != p.installed) {
            p.nested_install = true;
        }
        for (acc, add) in p.bytes.iter_mut().zip(bytes) {
            *acc = acc.saturating_add(add);
        }
        p.files += files;
        p.logical = p.logical.saturating_add(logical);
        p.newest_touch = p.newest_touch.max(newest);
    }

    HuntClassification {
        verdicts,
        order,
        dir_slot,
        dirs,
        file_reason,
        ignored_nodes: ignored_count,
    }
}

fn action_for(
    index: &Index,
    ctx: &HuntContext<'_>,
    node: NodeId,
    verdict: Verdict,
    personal: bool,
) -> (ActionRef, Option<String>) {
    if let Some(o) = ctx.ledger.and_then(|l| l.owner(node)) {
        // Protected system files still link to their sizing action (hibernation, pagefile).
        if verdict != Verdict::Protected || o.lane == Lane::Sizing {
            return (o.action.clone(), Some(o.id.clone()));
        }
    }
    match verdict {
        Verdict::Leftover | Verdict::ColdUserData if !personal => (
            ActionRef::RecyclePath {
                path: index.path(node),
            },
            None,
        ),
        _ => (ActionRef::None, None),
    }
}

/// Runs the hunt.
pub fn run_hunt(index: &Index, ctx: &HuntContext<'_>, opts: &HuntOptions) -> HuntReport {
    let cls = classify(index, ctx, opts);
    let now = opts.now_min2000.unwrap_or_else(now_min2000);
    let mut findings: Vec<HuntFinding> = Vec::new();

    // Units and big files: walk down until a folder qualifies as one unit.
    let mut stack: Vec<NodeId> = vec![ROOT];
    while let Some(dir) = stack.pop() {
        let slot = cls.dir_slot[dir as usize];
        if slot == u32::MAX {
            continue;
        }
        let agg = &cls.dirs[slot as usize];
        if agg.ignored {
            continue;
        }
        let total: u64 = agg.bytes.iter().sum();
        if dir != ROOT
            && total >= opts.min_unit_bytes
            && let Some(f) = unit_finding(index, ctx, &cls, dir, total, now)
        {
            findings.push(f);
            continue;
        }
        for c in index.children(dir) {
            let f = index.flags(c);
            if f.contains(NodeFlags::DIR) {
                if !f.contains(NodeFlags::REPARSE) {
                    stack.push(c);
                }
                continue;
            }
            let alloc = index.allocated(c);
            if alloc < opts.min_file_bytes {
                continue;
            }
            let verdict = cls.verdict(c);
            let personal = agg.protection == 2;
            let (action, opp) = action_for(index, ctx, c, verdict, personal);
            let days = days_since(now, index.mtime_min(c));
            let reason = file_reason_text(&cls, c, verdict, agg, days, opp.is_some());
            findings.push(HuntFinding {
                kind: FindingKind::BigFile,
                verdict,
                title: index.name(c).into_owned(),
                path: index.path(c),
                bytes: alloc,
                file_count: 1,
                days_since_touch: days,
                confidence: confidence_for(verdict),
                reason,
                action,
                opportunity_id: opp,
                swarm: None,
                members: Vec::new(),
                member_count: 1,
                score: 0.0,
            });
        }
    }

    let swarms = if opts.many {
        find_swarms(index, ctx, &cls, opts, now)
    } else {
        Vec::new()
    };

    let mut verdict_totals: Vec<VerdictTotal> = Verdict::ALL
        .iter()
        .map(|&v| VerdictTotal {
            verdict: v,
            bytes: 0,
            files: 0,
        })
        .collect();
    let root_slot = cls.dir_slot.first().copied().unwrap_or(u32::MAX);
    if root_slot != u32::MAX {
        let root = &cls.dirs[root_slot as usize];
        for (total, &b) in verdict_totals.iter_mut().zip(&root.bytes) {
            total.bytes = b;
        }
    }
    for (node, &v) in cls.verdicts.iter().enumerate() {
        if !index.flags(node as NodeId).contains(NodeFlags::DIR) {
            verdict_totals[v as usize].files += 1;
        }
    }

    let filter = |f: &HuntFinding| {
        (opts.verdict_filter.is_empty() || opts.verdict_filter.contains(&f.verdict))
            && opts
                .older_than_days
                .is_none_or(|d| f.days_since_touch.is_some_and(|t| t >= d))
    };
    let mut findings: Vec<HuntFinding> = findings.into_iter().filter(filter).collect();
    for f in &mut findings {
        f.score = score(f);
    }
    findings.sort_by(|a, b| b.score.total_cmp(&a.score));
    findings.truncate(opts.top);
    let swarms: Vec<HuntFinding> = swarms.into_iter().filter(filter).collect();

    let mut notes = Vec::new();
    if ctx.ledger.is_none() {
        notes.push(
            "No reclaim ledger was supplied, so rule and insight claims are not shown.".to_string(),
        );
    }

    HuntReport {
        scanned_path: index.path(ROOT).display().to_string(),
        findings,
        swarms,
        verdict_totals,
        unaccounted: unaccounted(index, ctx),
        ignored: cls.ignored_nodes,
        notes,
    }
}

fn confidence_for(v: Verdict) -> u8 {
    match v {
        Verdict::Protected => 100,
        Verdict::Claimed => 90,
        Verdict::Leftover => 70,
        Verdict::ColdUserData => 60,
        Verdict::InstalledApp => 80,
        Verdict::Active => 50,
    }
}

fn score(f: &HuntFinding) -> f64 {
    let age = f64::from(f.days_since_touch.unwrap_or(0).min(365)) / 365.0;
    f.bytes as f64 * f.verdict.weight() * (f64::from(f.confidence) / 100.0) * (1.0 + age)
}

fn file_reason_text(
    cls: &HuntClassification,
    node: NodeId,
    verdict: Verdict,
    parent: &DirAgg,
    days: Option<u32>,
    claimed: bool,
) -> String {
    let age = days
        .map(|d| format!("last written {d}d ago"))
        .unwrap_or_else(|| "age unknown".to_string());
    match verdict {
        Verdict::Protected => format!("system file or protected location; {age}"),
        Verdict::Claimed => format!("covered by a reclaim opportunity; {age}"),
        Verdict::Leftover => {
            let why = cls
                .file_reason
                .get(&node)
                .map(|s| s.to_string())
                .or_else(|| parent.leftover_reason.clone())
                .unwrap_or_else(|| "left behind".to_string());
            format!("{why}; {age}")
        }
        Verdict::ColdUserData if parent.protection == 2 => format!(
            "in a personal library (DiskSaver never deletes there; move or delete it in Explorer); {age}"
        ),
        Verdict::ColdUserData => format!("large and untouched; {age}"),
        Verdict::InstalledApp => format!("part of an installed app or game; {age}"),
        Verdict::Active if parent.protection == 2 => {
            format!("in a personal library, recently written ({age}); your call in Explorer")
        }
        Verdict::Active if claimed => format!("in use; {age}"),
        Verdict::Active => format!("in use or unknown; {age}"),
    }
}

/// Returns a unit finding when `dir` qualifies as one removable unit.
fn unit_finding(
    index: &Index,
    ctx: &HuntContext<'_>,
    cls: &HuntClassification,
    dir: NodeId,
    total: u64,
    now: u32,
) -> Option<HuntFinding> {
    let slot = cls.dir_slot[dir as usize] as usize;
    let agg = &cls.dirs[slot];
    let parent = index.parent(dir);
    let parent_agg = (dir != ROOT)
        .then(|| cls.dir_slot.get(parent as usize))
        .flatten()
        .filter(|&&s| s != u32::MAX)
        .map(|&s| &cls.dirs[s as usize]);
    let days = days_since(now, agg.newest_touch);
    let path = index.path(dir);
    let name = index.name(dir).into_owned();

    // 1. Root of a ledger opportunity.
    if let Some(ledger) = ctx.ledger
        && let Some(owner) = ledger.owner(dir)
        && ledger.owner(parent).is_none_or(|p| p.id != owner.id)
        && agg.protection != 1
    {
        return Some(HuntFinding {
            kind: FindingKind::Unit,
            verdict: Verdict::Claimed,
            title: owner.title.clone(),
            path,
            bytes: total,
            file_count: agg.files,
            days_since_touch: days,
            confidence: confidence_for(Verdict::Claimed),
            reason: format!(
                "{} ({} lane; frees ~{:.1} GiB)",
                owner.detail,
                owner.lane.label(),
                owner.est_bytes as f64 / GIB as f64
            ),
            action: owner.action.clone(),
            opportunity_id: Some(owner.id.clone()),
            swarm: None,
            members: Vec::new(),
            member_count: agg.files,
            score: 0.0,
        });
    }
    // 2. Installed app or game root, unless it holds other installs (a launcher folder with its
    //    games): then each game becomes its own unit further down.
    if agg.installed != u32::MAX
        && !agg.nested_install
        && parent_agg.is_none_or(|p| p.installed != agg.installed)
    {
        let root = &ctx.installed[agg.installed as usize];
        let action = match &root.store {
            Some(store) => ActionRef::LauncherGame {
                store: store.clone(),
                title: root.name.clone(),
            },
            None => ActionRef::UninstallApp {
                name: root.name.clone(),
            },
        };
        return Some(HuntFinding {
            kind: FindingKind::Unit,
            verdict: Verdict::InstalledApp,
            title: root.name.clone(),
            path,
            bytes: total,
            file_count: agg.files,
            days_since_touch: days,
            confidence: confidence_for(Verdict::InstalledApp),
            reason: format!(
                "installed {}; newest file written {}",
                if root.store.is_some() { "game" } else { "app" },
                days.map(|d| format!("{d}d ago"))
                    .unwrap_or_else(|| "unknown".into())
            ),
            action,
            opportunity_id: None,
            swarm: None,
            members: Vec::new(),
            member_count: agg.files,
            score: 0.0,
        });
    }
    // 3. Root of a protected subtree.
    if agg.protection == 1 && parent_agg.is_none_or(|p| p.protection != 1) {
        return Some(HuntFinding {
            kind: FindingKind::Unit,
            verdict: Verdict::Protected,
            title: name,
            path,
            bytes: total,
            file_count: agg.files,
            days_since_touch: days,
            confidence: 100,
            reason: "protected system location; only Windows' own tools may shrink it".into(),
            action: ActionRef::None,
            opportunity_id: None,
            swarm: None,
            members: Vec::new(),
            member_count: agg.files,
            score: 0.0,
        });
    }
    // 4. A folder that is ≥ 90 % leftover or cold data.
    for v in [Verdict::Leftover, Verdict::ColdUserData] {
        if agg.bytes[v as usize] as f64 >= 0.9 * total as f64 && total > 0 {
            let personal = agg.protection == 2;
            let (action, _) = action_for(index, ctx, dir, v, personal);
            let reason = match v {
                Verdict::Leftover => agg
                    .leftover_reason
                    .clone()
                    .unwrap_or_else(|| "mostly installers, temp files, dumps, and old logs".into()),
                _ if personal => {
                    "large personal files untouched for months (your call in Explorer)".into()
                }
                _ => "large files untouched for months".into(),
            };
            return Some(HuntFinding {
                kind: FindingKind::Unit,
                verdict: v,
                title: name,
                path,
                bytes: total,
                file_count: agg.files,
                days_since_touch: days,
                confidence: confidence_for(v),
                reason,
                action,
                opportunity_id: None,
                swarm: None,
                members: Vec::new(),
                member_count: agg.files,
                score: 0.0,
            });
        }
    }
    None
}

fn subtree_bytes(cls: &HuntClassification, dir: NodeId) -> (u64, u64, u32) {
    let s = cls.dir_slot[dir as usize];
    if s == u32::MAX {
        return (0, 0, 0);
    }
    let a = &cls.dirs[s as usize];
    (a.bytes.iter().sum(), a.files, a.newest_touch)
}

fn dominant(bytes_by_verdict: &[u64; 6]) -> Verdict {
    Verdict::from_u8((0..6).max_by_key(|&v| bytes_by_verdict[v]).unwrap_or(5) as u8)
}

fn find_swarms(
    index: &Index,
    ctx: &HuntContext<'_>,
    cls: &HuntClassification,
    opts: &HuntOptions,
    now: u32,
) -> Vec<HuntFinding> {
    let mut out = Vec::new();
    let min_bytes = opts.min_unit_bytes;

    // 1. Recurring folder names (outermost occurrence only).
    let mut name_bit: FxHashMap<&str, u32> = FxHashMap::default();
    for (i, n) in RECURRING_NAMES.iter().enumerate() {
        name_bit.insert(n, 1u32 << i);
    }
    struct Rec {
        count: u64,
        bytes: u64,
        files: u64,
        newest: u32,
        by_verdict: [u64; 6],
        members: Vec<(u64, NodeId)>,
    }
    let mut recurring: FxHashMap<&str, Rec> = FxHashMap::default();
    let mut mask = vec![0u32; cls.dirs.len()];
    for &node in &cls.order {
        let slot = cls.dir_slot[node as usize];
        if slot == u32::MAX {
            continue;
        }
        let parent_mask = if node == ROOT {
            0
        } else {
            let ps = cls.dir_slot[index.parent(node) as usize];
            if ps == u32::MAX { 0 } else { mask[ps as usize] }
        };
        let mut m = parent_mask;
        let lower = index.name(node).to_ascii_lowercase();
        let dom = dominant(&cls.dirs[slot as usize].bytes);
        if let Some((&key, &bit)) = name_bit.get_key_value(lower.as_str())
            && parent_mask & bit == 0
            && !cls.dirs[slot as usize].ignored
            // Folders inside installed apps or protected areas are part of the app, not clutter.
            && !matches!(dom, Verdict::InstalledApp | Verdict::Protected)
        {
            m |= bit;
            let (bytes, files, newest) = subtree_bytes(cls, node);
            let e = recurring.entry(key).or_insert(Rec {
                count: 0,
                bytes: 0,
                files: 0,
                newest: 0,
                by_verdict: [0; 6],
                members: Vec::new(),
            });
            e.count += 1;
            e.bytes = e.bytes.saturating_add(bytes);
            e.files += files;
            e.newest = e.newest.max(newest);
            for v in 0..6 {
                e.by_verdict[v] += cls.dirs[slot as usize].bytes[v];
            }
            e.members.push((bytes, node));
        }
        mask[slot as usize] = m;
    }
    for (name, mut r) in recurring {
        if r.count < 3 || r.bytes < min_bytes {
            continue;
        }
        r.members.sort_by_key(|a| std::cmp::Reverse(a.0));
        out.push(HuntFinding {
            kind: FindingKind::Swarm,
            verdict: dominant(&r.by_verdict),
            title: format!("{} × “{name}” folders", r.count),
            path: PathBuf::from(name),
            bytes: r.bytes,
            file_count: r.files,
            days_since_touch: days_since(now, r.newest),
            confidence: 70,
            reason: "the same folder name recurs across the disk; usually caches or build output"
                .into(),
            action: ActionRef::None,
            opportunity_id: None,
            swarm: Some(SwarmKind::RecurringFolder),
            members: r
                .members
                .iter()
                .take(50)
                .map(|(_, n)| index.path(*n))
                .collect(),
            member_count: r.count,
            score: r.bytes as f64,
        });
    }

    // 2. File families inside removable verdicts, 3. name patterns.
    struct Fam {
        count: u64,
        bytes: u64,
        newest: u32,
        members: Vec<(u64, NodeId)>,
    }
    let mut families: FxHashMap<String, Fam> = FxHashMap::default();
    let mut patterns: FxHashMap<&'static str, Fam> = FxHashMap::default();
    for &node in &cls.order {
        if index.flags(node).contains(NodeFlags::DIR) {
            continue;
        }
        let v = cls.verdict(node);
        let name = index.name(node);
        let alloc = index.allocated(node);
        let touch = index.mtime_min(node);
        if matches!(
            v,
            Verdict::Claimed | Verdict::Leftover | Verdict::ColdUserData
        ) && let Some(ext) = ext_of(&name)
        {
            let e = families.entry(ext).or_insert(Fam {
                count: 0,
                bytes: 0,
                newest: 0,
                members: Vec::new(),
            });
            e.count += 1;
            e.bytes = e.bytes.saturating_add(alloc);
            e.newest = e.newest.max(touch);
            push_capped(&mut e.members, alloc, node);
        }
        if v != Verdict::Protected
            && let Some(kind) = copy_pattern(&name)
        {
            let e = patterns.entry(kind).or_insert(Fam {
                count: 0,
                bytes: 0,
                newest: 0,
                members: Vec::new(),
            });
            e.count += 1;
            e.bytes = e.bytes.saturating_add(alloc);
            e.newest = e.newest.max(touch);
            push_capped(&mut e.members, alloc, node);
        }
    }
    let mut fams: Vec<(String, Fam)> = families
        .into_iter()
        .filter(|(_, f)| f.count >= 20 && f.bytes >= min_bytes)
        .collect();
    fams.sort_by_key(|a| std::cmp::Reverse(a.1.bytes));
    for (ext, mut f) in fams.into_iter().take(10) {
        f.members.sort_by_key(|a| std::cmp::Reverse(a.0));
        out.push(HuntFinding {
            kind: FindingKind::Swarm,
            verdict: Verdict::Claimed,
            title: format!("{} × *.{ext}", f.count),
            path: PathBuf::from(format!("*.{ext}")),
            bytes: f.bytes,
            file_count: f.count,
            days_since_touch: days_since(now, f.newest),
            confidence: 70,
            reason: "files of one type inside removable areas (caches, build output, leftovers)"
                .into(),
            action: ActionRef::None,
            opportunity_id: None,
            swarm: Some(SwarmKind::FileFamily),
            members: f.members.iter().map(|(_, n)| index.path(*n)).collect(),
            member_count: f.count,
            score: f.bytes as f64,
        });
    }
    for (kind, mut f) in patterns {
        if f.count < 10 && f.bytes < 100 * MIB {
            continue;
        }
        f.members.sort_by_key(|a| std::cmp::Reverse(a.0));
        out.push(HuntFinding {
            kind: FindingKind::Swarm,
            verdict: Verdict::Leftover,
            title: format!("{} × {kind}", f.count),
            path: PathBuf::from(kind),
            bytes: f.bytes,
            file_count: f.count,
            days_since_touch: days_since(now, f.newest),
            confidence: 50,
            reason: "copy-like names; check them with `disksaver dupes` before removing".into(),
            action: ActionRef::None,
            opportunity_id: None,
            swarm: Some(SwarmKind::NamePattern),
            members: f.members.iter().map(|(_, n)| index.path(*n)).collect(),
            member_count: f.count,
            score: f.bytes as f64,
        });
    }

    // 4. File-count hot spots: descend while one child holds ≥ 80 % of the files.
    let mut hot: Vec<HuntFinding> = Vec::new();
    let mut stack = vec![ROOT];
    while let Some(dir) = stack.pop() {
        let (_, files, newest) = subtree_bytes(cls, dir);
        if files < 10_000 {
            continue;
        }
        let child_dirs: Vec<NodeId> = index
            .children(dir)
            .filter(|&c| index.flags(c).contains(NodeFlags::DIR))
            .collect();
        let dominant_child = child_dirs
            .iter()
            .copied()
            .find(|&c| subtree_bytes(cls, c).1 * 5 >= files * 4);
        if let Some(c) = dominant_child {
            stack.push(c);
            continue;
        }
        let slot = cls.dir_slot[dir as usize] as usize;
        let agg = &cls.dirs[slot];
        let bytes: u64 = agg.bytes.iter().sum();
        let avg = bytes / files.max(1);
        if dir != ROOT && (files >= 50_000 || avg < 16 * 1024) {
            let slack = bytes.saturating_sub(agg.logical);
            hot.push(HuntFinding {
                kind: FindingKind::Swarm,
                verdict: dominant(&agg.bytes),
                title: format!("{files} files in {}", index.name(dir)),
                path: index.path(dir),
                bytes,
                file_count: files,
                days_since_touch: days_since(now, newest),
                confidence: 60,
                reason: format!(
                    "average file {} KiB; {:.1} MiB lost to cluster slack. Huge file counts also grow $MFT and slow every scan",
                    avg / 1024,
                    slack as f64 / MIB as f64
                ),
                action: ActionRef::None,
                opportunity_id: None,
                swarm: Some(SwarmKind::CountHotspot),
                members: Vec::new(),
                member_count: files,
                score: files as f64,
            });
        } else {
            stack.extend(child_dirs);
        }
    }
    hot.sort_by_key(|a| std::cmp::Reverse(a.file_count));
    hot.truncate(10);
    out.extend(hot);

    let _ = ctx;
    out
}

fn push_capped(members: &mut Vec<(u64, NodeId)>, bytes: u64, node: NodeId) {
    const CAP: usize = 50;
    if members.len() < CAP {
        members.push((bytes, node));
        return;
    }
    if let Some((i, _)) = members
        .iter()
        .enumerate()
        .min_by_key(|(_, (b, _))| *b)
        .filter(|(_, (b, _))| *b < bytes)
    {
        members[i] = (bytes, node);
    }
}

fn unaccounted(index: &Index, ctx: &HuntContext<'_>) -> Option<Unaccounted> {
    let vol = index.volume();
    let root = index.path(ROOT);
    let root_s = root.to_string_lossy();
    let is_volume_root =
        root_s.trim_end_matches('\\').len() == 2 && root_s.as_bytes().get(1) == Some(&b':');
    if !is_volume_root || vol.total_bytes == 0 {
        return None;
    }
    let used = vol.total_bytes.saturating_sub(vol.free_bytes);
    let scanned = index.total_allocated(ROOT);
    let gap = used.saturating_sub(scanned);
    let mut causes = Vec::new();
    if gap * 50 <= used {
        causes.push("within 2 % of used space: nothing significant is hidden".into());
    } else {
        if ctx.skipped_dirs > 0 {
            causes.push(format!(
                "{} folders could not be opened (access denied)",
                ctx.skipped_dirs
            ));
        }
        if !ctx.elevated {
            causes.push(
                "without admin: other users' profiles, System Volume Information (restore points), and protected folders are not visible; rerun with --use-helper".into(),
            );
        }
        if !ctx.mft_scan {
            causes.push(
                "directory scans do not see NTFS metadata ($MFT, $LogFile, USN journal) or alternate data streams".into(),
            );
        }
    }
    Some(Unaccounted {
        volume_used_bytes: used,
        scanned_bytes: scanned,
        gap_bytes: gap,
        causes,
    })
}

/// `%APPDATA%\DiskSaver\hunt-ignore.txt`: one path per line.
pub fn default_ignore_path() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("DiskSaver")
        .join("hunt-ignore.txt")
}

/// Loads the ignore list (missing file = empty).
pub fn load_ignore_list(path: &Path) -> Vec<PathBuf> {
    std::fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Appends `entry` to the ignore list unless already present.
pub fn add_to_ignore_list(path: &Path, entry: &Path) -> std::io::Result<()> {
    let mut list = load_ignore_list(path);
    let norm = crate::clean::deny::normalize_win_path_str(entry);
    if list
        .iter()
        .any(|p| crate::clean::deny::normalize_win_path_str(p) == norm)
    {
        return Ok(());
    }
    list.push(entry.to_path_buf());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body: String = list.iter().map(|p| format!("{}\n", p.display())).collect();
    std::fs::write(path, body)
}

#[cfg(test)]
mod tests;
