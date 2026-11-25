#![forbid(unsafe_code)]

//! `disksaver reclaim`, `hunt`, and `sweep` (P9.1, P9.10, P9.7), plus sizing output (P9.5).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use clap::Args;
use dsk_core::clean::{CleanPlan, DenyContext, ExecuteOptions, RuleTier, execute_plan};
use dsk_core::hunt::{
    HuntContext, HuntFinding, HuntOptions, HuntReport, InstalledRoot, Verdict, add_to_ignore_list,
    default_ignore_path, load_ignore_list,
};
use dsk_core::index::Index;
use dsk_core::ledger::assemble::{AssembleOptions, Assembled, assemble};
use dsk_core::ledger::{ActionRef, Lane, Ledger};
use dsk_core::optimize::OptimizerIntent;
use dsk_core::optimize::sizing::{SizingFacts, SizingRecommendation};
use dsk_core::sweep::{SweepOptions, execute_sweep, find_sweep_candidates};
use dsk_core::{ScanMethod, ScanReport};

use crate::report::fmt_bytes;
use crate::{
    MethodArg, TierArg, default_system_drive_path, fail_with_error, scan_for_insights,
    setup_cancel_flag,
};

/// Parses sizes like `256MiB`, `1GiB`, `500MB`, `4096`.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let split = t
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num.parse().map_err(|_| format!("invalid size '{s}'"))?;
    let mul: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024f64.powi(4),
        other => return Err(format!("unknown size unit '{other}'")),
    };
    Ok((n * mul) as u64)
}

/// Parses `90`, `90d`, `12w` into days.
pub fn parse_days(s: &str) -> Result<u32, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mul) = if let Some(n) = t.strip_suffix('d') {
        (n, 1)
    } else if let Some(n) = t.strip_suffix('w') {
        (n, 7)
    } else {
        (t.as_str(), 1)
    };
    num.parse::<u32>()
        .map(|n| n * mul)
        .map_err(|_| format!("invalid age '{s}' (expected e.g. 90d)"))
}

/// `--pagefile` values: `auto`, `system`, `<MiB>`, or `<initial>-<max>` (MiB).
pub fn parse_pagefile_spec(spec: &str, drive: &str) -> Result<OptimizerIntent, String> {
    let s = spec.trim().to_ascii_lowercase();
    let intent = match s.as_str() {
        "auto" | "automatic" => OptimizerIntent::SetPagefileAutomatic,
        "system" | "system-managed" => OptimizerIntent::SetPagefileSystemManaged {
            drive: drive.to_string(),
        },
        _ => {
            let (a, b) = s.split_once('-').unwrap_or((s.as_str(), s.as_str()));
            let initial_mb: u32 = a.trim().parse().map_err(|_| {
                format!("invalid --pagefile '{spec}' (auto, system, <MiB> or <initial>-<max>)")
            })?;
            let max_mb: u32 = b
                .trim()
                .parse()
                .map_err(|_| format!("invalid --pagefile '{spec}'"))?;
            OptimizerIntent::SetPagefile {
                drive: drive.to_string(),
                initial_mb,
                max_mb,
            }
        }
    };
    intent.validate().map_err(|e| e.to_string())?;
    Ok(intent)
}

pub fn print_sizing_human(facts: &SizingFacts, recs: &[SizingRecommendation]) {
    println!("[Sizing advisor] system drive {}", facts.system_drive);
    if let (Some(ram), Some(peak)) = (facts.ram_bytes, facts.commit_peak_bytes) {
        println!(
            "  RAM {}  commit peak since boot {}  pagefile {}",
            fmt_bytes(ram),
            fmt_bytes(peak),
            facts
                .pagefile_bytes
                .map(fmt_bytes)
                .unwrap_or_else(|| "none".into())
        );
    }
    if recs.is_empty() {
        println!("  Nothing to change: sizes already fit this machine.");
    }
    for r in recs {
        println!(
            "  {:>10}  {}{}",
            fmt_bytes(r.est_savings_bytes),
            r.title,
            if r.requires_reboot {
                " (after reboot)"
            } else {
                ""
            }
        );
        println!("              {}", r.detail);
        println!("              Trade-off: {}", r.caveat);
        if let Some(i) = &r.intent {
            println!(
                "              Apply: {}",
                ActionRef::Optimizer { intent: i.clone() }.cli_hint()
            );
        }
    }
}

fn parse_lanes(raw: &[String]) -> Result<Vec<Lane>, String> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .filter(|s| !s.trim().is_empty())
        .map(|s| match s.trim().to_ascii_lowercase().as_str() {
            "invisible" => Ok(Lane::Invisible),
            "sizing" => Ok(Lane::Sizing),
            "regenerable" => Ok(Lane::Regenerable),
            "leftover" => Ok(Lane::Leftover),
            "decision" => Ok(Lane::Decision),
            other => Err(format!(
                "unknown lane '{other}' (invisible, sizing, regenerable, leftover, decision)"
            )),
        })
        .collect()
}

#[derive(Args, Debug)]
pub struct ReclaimArgs {
    /// Volume root or folder (defaults to the system drive)
    pub path: Option<PathBuf>,
    /// Highest cleanup-rule tier to include
    #[arg(long, default_value = "review", value_enum)]
    pub tier: TierArg,
    /// Only show these lanes (comma separated: invisible,sizing,regenerable,leftover,decision)
    #[arg(long, value_delimiter = ',')]
    pub lanes: Vec<String>,
    /// Also hash duplicate files (reads file contents)
    #[arg(long)]
    pub with_dupes: bool,
    /// Minimum duplicate size
    #[arg(long, default_value = "16MiB", value_parser = parse_size)]
    pub dupes_min: u64,
    /// Skip sampling install folders for compression savings
    #[arg(long)]
    pub no_compression: bool,
    /// Rows to print
    #[arg(long, default_value_t = 40)]
    pub top: usize,
    #[arg(long, default_value = "auto", value_enum)]
    pub method: MethodArg,
    /// Scan through the elevated helper (sees system folders without an elevated shell)
    #[arg(long)]
    pub use_helper: bool,
    /// Apply the safe part: 🟢 regenerable cleanup rules and stale build sweeps. Everything else
    /// is listed with the command that applies it.
    #[arg(long)]
    pub yes: bool,
    /// Simulate what --yes would do
    #[arg(long)]
    pub dry_run: bool,
    /// Journal for the applied cleanup
    #[arg(long)]
    pub journal: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

fn scan(
    path: &std::path::Path,
    method: MethodArg,
    use_helper: bool,
    json: bool,
    cancel: &std::sync::Arc<AtomicBool>,
) -> ScanReport {
    scan_for_insights(path, method, use_helper, json, cancel)
}

fn assemble_or_exit(
    report: &ScanReport,
    target: &std::path::Path,
    opts: &AssembleOptions,
    cancel: &AtomicBool,
) -> Assembled {
    match assemble(&report.index, report.method_used, target, opts, cancel) {
        Ok(a) => a,
        Err(e) => fail_with_error("Error building the reclaim ledger", &e),
    }
}

fn print_ledger(ledger: &Ledger, lanes: &[Lane], top: usize) {
    println!(
        "Free ~{} without losing anything (invisible + regenerable)",
        fmt_bytes(ledger.headline_bytes)
    );
    for t in &ledger.lane_totals {
        println!(
            "  {:<12} {:>10}  ({} items)",
            t.lane.label(),
            fmt_bytes(t.bytes),
            t.count
        );
    }
    println!();
    let mut shown = 0usize;
    for o in &ledger.opportunities {
        if (!lanes.is_empty() && !lanes.contains(&o.lane))
            || o.est_bytes == 0 && o.raw_est_bytes == 0
        {
            continue;
        }
        if shown >= top {
            break;
        }
        shown += 1;
        let conf = format!("{:?}", o.confidence).to_ascii_lowercase();
        println!(
            "{:>10}  [{:<11}] {:<10} {}",
            fmt_bytes(o.est_bytes),
            o.lane.label(),
            conf,
            o.title
        );
        if !o.detail.is_empty() {
            let detail: String = o.detail.chars().take(160).collect();
            println!("            {detail}");
        }
        println!("            → {}", o.action.cli_hint());
    }
    for n in &ledger.notes {
        println!("Note: {n}");
    }
}

pub fn run_reclaim(args: ReclaimArgs) {
    let lanes = match parse_lanes(&args.lanes) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let cancel = setup_cancel_flag();
    let target = args.path.clone().unwrap_or_else(default_system_drive_path);
    let report = scan(&target, args.method, args.use_helper, args.json, &cancel);
    let opts = AssembleOptions {
        tier_max: args.tier.into(),
        dupes_min_bytes: args.with_dupes.then_some(args.dupes_min),
        hash_cache: Some(dsk_core::insights::default_hash_cache_path()),
        compression: !args.no_compression,
        ..Default::default()
    };
    if !args.json {
        eprintln!("Building the reclaim ledger...");
    }
    let assembled = assemble_or_exit(&report, &target, &opts, &cancel);

    if !args.yes && !args.dry_run {
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&assembled.ledger).unwrap()
            );
        } else {
            print_ledger(&assembled.ledger, &lanes, args.top);
            println!(
                "\nApply the safe part (🟢 regenerable rules + stale build sweeps) with: disksaver reclaim --yes"
            );
        }
        return;
    }

    // --yes / --dry-run: only 🟢 regenerable rules and sweeps; the rest needs its own command.
    let safe_rules: Vec<String> = assembled
        .ledger
        .opportunities
        .iter()
        .filter_map(|o| match &o.action {
            ActionRef::CleanRule {
                rule_id,
                tier: RuleTier::Safe,
            } if o.lane == Lane::Regenerable && o.est_bytes > 0 => Some(rule_id.clone()),
            _ => None,
        })
        .collect();
    let plan: CleanPlan = assembled.plan.filtered_rules(&safe_rules);
    let deny = DenyContext::default();
    let exec_opts = ExecuteOptions {
        dry_run: args.dry_run,
        force_battery: false,
        journal_path: args.journal.clone(),
    };
    let clean = execute_plan(&plan, &exec_opts, &deny, &|_| {}, &cancel);
    let mut sweep_results = Vec::new();
    for c in &assembled.sweeps {
        sweep_results.push((
            c.root.clone(),
            execute_sweep(c, &deny, args.dry_run, &cancel),
        ));
    }
    if args.json {
        let sweeps: Vec<serde_json::Value> = sweep_results
            .iter()
            .map(|(root, r)| match r {
                Ok(o) => serde_json::to_value(o).unwrap(),
                Err(e) => serde_json::json!({ "root": root, "error": e.to_string() }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "clean": clean.as_ref().ok(),
                "clean_error": clean.as_ref().err().map(|e| e.to_string()),
                "sweeps": sweeps,
            }))
            .unwrap()
        );
    } else {
        match &clean {
            Ok(r) => crate::clean_report::print_human_clean(r),
            Err(e) => eprintln!("Cleanup failed: {e}"),
        }
        for (root, r) in &sweep_results {
            match r {
                Ok(o) => println!(
                    "Sweep {}: {} {} items, {} ({} skipped, {} failed)",
                    root.display(),
                    if o.dry_run { "would delete" } else { "deleted" },
                    o.deleted,
                    fmt_bytes(o.deleted_bytes),
                    o.skipped,
                    o.failed
                ),
                Err(e) => println!("Sweep {}: skipped ({e})", root.display()),
            }
        }
        println!(
            "\nOther lanes (compression, sizing, leftovers, decisions) each list their own command above; run `disksaver reclaim` to see them."
        );
    }
    if clean.is_err() {
        std::process::exit(1);
    }
}

#[derive(Args, Debug)]
pub struct HuntArgs {
    /// Volume root or folder (defaults to the system drive)
    pub path: Option<PathBuf>,
    /// Findings to print
    #[arg(long, default_value_t = 50)]
    pub top: usize,
    /// Smallest unit or file to list
    #[arg(long, default_value = "256MiB", value_parser = parse_size)]
    pub min_size: u64,
    /// Also look for swarms of small things (recurring folders, file families, hot spots, copies)
    #[arg(long)]
    pub many: bool,
    /// Only these verdicts (protected, claimed, leftover, cold, installed, active)
    #[arg(long, value_delimiter = ',')]
    pub verdict: Vec<String>,
    /// Only findings untouched at least this long (e.g. 90d)
    #[arg(long, value_parser = parse_days)]
    pub older_than: Option<u32>,
    /// Skip the reclaim ledger (faster; no rule or insight claims)
    #[arg(long)]
    pub no_ledger: bool,
    /// Never suggest this path again (adds it to the ignore list and exits)
    #[arg(long)]
    pub ignore: Option<PathBuf>,
    #[arg(long, default_value = "auto", value_enum)]
    pub method: MethodArg,
    #[arg(long)]
    pub use_helper: bool,
    #[arg(long)]
    pub json: bool,
}

/// Installed app and game folders for the hunt: skips drive roots, Program Files itself, and
/// profile roots that some uninstall entries point at.
pub fn installed_roots(index: &Index, assembled: Option<&Assembled>) -> Vec<InstalledRoot> {
    let mut out = Vec::new();
    let pf = dsk_core::win::volume::program_files_dir();
    let pf86 = dsk_core::win::volume::program_files_x86_dir();
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
    for app in dsk_core::win::prefetch::enumerate_installed_apps() {
        let Some(loc) = app.install_location else {
            continue;
        };
        let depth = loc.components().count();
        if depth < 3
            || dsk_core::clean::deny::normalize_win_path_str(&loc)
                == dsk_core::clean::deny::normalize_win_path_str(&pf)
            || dsk_core::clean::deny::normalize_win_path_str(&loc)
                == dsk_core::clean::deny::normalize_win_path_str(&pf86)
            || home.as_ref().is_some_and(|h| {
                dsk_core::clean::deny::normalize_win_path_str(h)
                    == dsk_core::clean::deny::normalize_win_path_str(&loc)
            })
            || index.find_by_path(&loc).is_none()
        {
            continue;
        }
        out.push(InstalledRoot {
            path: loc,
            name: app.name,
            store: None,
        });
    }
    if let Some(a) = assembled {
        for g in &a.insights.gaming.games {
            out.push(InstalledRoot {
                path: g.install_path.clone(),
                name: g.title.clone(),
                store: Some(g.store.display_name().to_string()),
            });
        }
    }
    out
}

fn print_finding(f: &HuntFinding) {
    let age = f
        .days_since_touch
        .map(|d| format!("{d}d"))
        .unwrap_or_else(|| "?".into());
    println!(
        "{:>10}  {:<9} {:>5}  {}",
        fmt_bytes(f.bytes),
        f.verdict.label(),
        age,
        if f.kind == dsk_core::hunt::FindingKind::Swarm {
            f.title.clone()
        } else {
            f.path.display().to_string()
        }
    );
    println!("            {}", f.reason);
    if f.action != ActionRef::None {
        println!("            → {}", f.action.cli_hint());
    }
}

fn print_hunt(r: &HuntReport) {
    println!("Biggest things on {}:", r.scanned_path);
    for f in &r.findings {
        print_finding(f);
    }
    if !r.swarms.is_empty() {
        println!("\nSwarms (many small things that add up):");
        for s in &r.swarms {
            print_finding(s);
            for m in s.members.iter().take(3) {
                println!("              e.g. {}", m.display());
            }
        }
    }
    println!("\nBy verdict:");
    for t in &r.verdict_totals {
        if t.bytes > 0 {
            println!(
                "  {:<10} {:>10}  {} files",
                t.verdict.label(),
                fmt_bytes(t.bytes),
                t.files
            );
        }
    }
    if let Some(u) = &r.unaccounted {
        println!(
            "\nUsed {} • scanned {} • not visible {}",
            fmt_bytes(u.volume_used_bytes),
            fmt_bytes(u.scanned_bytes),
            fmt_bytes(u.gap_bytes)
        );
        for c in &u.causes {
            println!("  - {c}");
        }
    }
    if r.ignored > 0 {
        println!("({} files hidden by the ignore list)", r.ignored);
    }
    for n in &r.notes {
        println!("Note: {n}");
    }
}

pub fn run_hunt(args: HuntArgs) {
    if let Some(p) = &args.ignore {
        let list = default_ignore_path();
        match add_to_ignore_list(&list, p) {
            Ok(()) => println!(
                "{} will no longer be suggested ({}).",
                p.display(),
                list.display()
            ),
            Err(e) => {
                eprintln!("Could not update {}: {e}", list.display());
                std::process::exit(1);
            }
        }
        return;
    }
    let mut verdicts = Vec::new();
    for v in &args.verdict {
        match Verdict::parse(v) {
            Some(x) => verdicts.push(x),
            None => {
                eprintln!(
                    "unknown verdict '{v}' (protected, claimed, leftover, cold, installed, active)"
                );
                std::process::exit(2);
            }
        }
    }
    let cancel = setup_cancel_flag();
    let target = args.path.clone().unwrap_or_else(default_system_drive_path);
    let report = scan(&target, args.method, args.use_helper, args.json, &cancel);
    let assembled = (!args.no_ledger).then(|| {
        if !args.json {
            eprintln!("Building the reclaim ledger...");
        }
        assemble_or_exit(
            &report,
            &target,
            &AssembleOptions {
                compression: false,
                ..Default::default()
            },
            &cancel,
        )
    });
    let mut ctx = HuntContext::new(DenyContext::default());
    ctx.ledger = assembled.as_ref().map(|a| &a.ledger);
    ctx.installed = installed_roots(&report.index, assembled.as_ref());
    ctx.ignore = load_ignore_list(&default_ignore_path());
    ctx.skipped_dirs = report.skipped;
    ctx.elevated = dsk_core::is_elevated();
    ctx.mft_scan = matches!(
        report.method_used,
        ScanMethod::Mft | ScanMethod::UsnIncremental
    );
    let opts = HuntOptions {
        top: args.top,
        min_unit_bytes: args.min_size,
        min_file_bytes: args.min_size,
        many: args.many,
        verdict_filter: verdicts,
        older_than_days: args.older_than,
        ..Default::default()
    };
    let hunt = dsk_core::hunt::run_hunt(&report.index, &ctx, &opts);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&hunt).unwrap());
    } else {
        print_hunt(&hunt);
    }
}

#[derive(Args, Debug)]
pub struct SweepArgs {
    /// Folder holding projects (defaults to the current directory)
    pub path: Option<PathBuf>,
    /// Keep generations built within this many days of the newest build
    #[arg(long, default_value_t = 14)]
    pub keep_days: u32,
    /// Delete the stale generations
    #[arg(long)]
    pub yes: bool,
    /// Simulate the deletion
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, default_value = "dir", value_enum)]
    pub method: MethodArg,
    #[arg(long)]
    pub json: bool,
}

pub fn run_sweep(args: SweepArgs) {
    let cancel = setup_cancel_flag();
    let target = args
        .path
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| default_system_drive_path()));
    let report = scan(&target, args.method, false, args.json, &cancel);
    let kind = match report.method_used {
        ScanMethod::Mft | ScanMethod::UsnIncremental => dsk_core::clean::FileIdKind::NtfsFrn64,
        _ => dsk_core::clean::FileIdKind::FxHash128,
    };
    let deny = DenyContext::default();
    let opts = SweepOptions {
        keep_days: args.keep_days,
        now_min2000: None,
    };
    let candidates = find_sweep_candidates(&report.index, &opts, kind, &deny);
    if !args.yes && !args.dry_run {
        if args.json {
            let summary: Vec<serde_json::Value> = candidates
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "kind": c.kind, "root": c.root, "project": c.project,
                        "total_bytes": c.total_bytes, "stale_bytes": c.stale_bytes,
                        "stale_units": c.stale_units, "kept_units": c.kept_units,
                        "newest_build_days": c.newest_build_days, "items": c.planned.items.len(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&summary).unwrap());
        } else {
            if candidates.is_empty() {
                println!("No stale build generations under {}.", target.display());
            }
            for c in &candidates {
                println!(
                    "{:>10} stale of {:>10}  {}  ({}: {} stale / {} kept units, newest build {}d ago)",
                    fmt_bytes(c.stale_bytes),
                    fmt_bytes(c.total_bytes),
                    c.root.display(),
                    c.kind.label(),
                    c.stale_units,
                    c.kept_units,
                    c.newest_build_days.unwrap_or(0)
                );
            }
            if !candidates.is_empty() {
                println!(
                    "\nDelete them with: disksaver sweep \"{}\" --yes",
                    target.display()
                );
            }
        }
        return;
    }
    let mut failed = false;
    let mut results = Vec::new();
    for c in &candidates {
        let r = execute_sweep(c, &deny, args.dry_run, &cancel);
        if r.is_err() {
            failed = true;
        }
        results.push((c.root.clone(), r));
    }
    if args.json {
        let out: Vec<serde_json::Value> = results
            .iter()
            .map(|(root, r)| match r {
                Ok(o) => serde_json::to_value(o).unwrap(),
                Err(e) => serde_json::json!({ "root": root, "error": e.to_string() }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        for (root, r) in &results {
            match r {
                Ok(o) => println!(
                    "{} {}: {} items, {} ({} skipped, {} failed)",
                    if o.dry_run {
                        "Would delete in"
                    } else {
                        "Deleted in"
                    },
                    root.display(),
                    o.deleted,
                    fmt_bytes(o.deleted_bytes),
                    o.skipped,
                    o.failed
                ),
                Err(e) => println!("{}: {e}", root.display()),
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// The app's name exactly as Settings > Apps shows it
    pub name: String,
    /// Start the uninstaller (it shows its own window); otherwise only print what would run
    #[arg(long)]
    pub yes: bool,
}

pub fn run_uninstall(args: UninstallArgs) {
    let Some(cmd) = dsk_core::win::decisions::find_uninstall_command(&args.name) else {
        eprintln!(
            "No registered uninstaller for \"{}\". Use the exact name from Settings > Apps.",
            args.name
        );
        std::process::exit(1);
    };
    println!("{} → {} {}", cmd.app_name, cmd.program.display(), cmd.args);
    if !args.yes {
        println!("Start it with: disksaver uninstall \"{}\" --yes", args.name);
        return;
    }
    if let Err(e) = dsk_core::win::decisions::launch_uninstaller(&cmd) {
        eprintln!("Could not start the uninstaller: {e}");
        std::process::exit(1);
    }
    println!("Uninstaller started; follow its window.");
}

#[derive(Args, Debug)]
pub struct MoveLibraryArgs {
    /// videos, downloads, music, pictures, or documents
    pub library: String,
    /// New location on another fixed drive (new or empty folder)
    pub target: PathBuf,
    /// Move now (Windows copies the files, then deletes the originals)
    #[arg(long)]
    pub yes: bool,
}

fn folder_bytes(p: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() && !m.file_type().is_symlink() {
                stack.push(e.path());
            } else {
                total = total.saturating_add(m.len());
            }
        }
    }
    total
}

pub fn run_move_library(args: MoveLibraryArgs) {
    use dsk_core::win::decisions::{UserLibrary, move_user_library, validate_library_target};
    let Some(lib) = UserLibrary::parse(&args.library) else {
        eprintln!(
            "unknown library '{}' (videos, downloads, music, pictures, documents)",
            args.library
        );
        std::process::exit(2);
    };
    let Some(current) = lib.current_path() else {
        eprintln!("{lib:?} has no current location");
        std::process::exit(1);
    };
    let bytes = folder_bytes(&current);
    println!(
        "{lib:?}: {} ({}) → {}",
        current.display(),
        fmt_bytes(bytes),
        args.target.display()
    );
    if let Err(e) = validate_library_target(lib, &args.target, bytes)
        .and_then(|()| move_user_library(lib, &args.target, true))
    {
        eprintln!("Cannot move: {e}");
        std::process::exit(1);
    }
    if !args.yes {
        println!(
            "Checks passed. Move it with: disksaver move-library {} \"{}\" --yes",
            args.library,
            args.target.display()
        );
        return;
    }
    match move_user_library(lib, &args.target, false) {
        Ok(()) => println!("Moved. {lib:?} now lives at {}", args.target.display()),
        Err(e) => {
            eprintln!("Move failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes_days_and_pagefile_specs() {
        assert_eq!(parse_size("256MiB").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_size("1g").unwrap(), 1 << 30);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("12 parsecs").is_err());
        assert_eq!(parse_days("90d").unwrap(), 90);
        assert_eq!(parse_days("2w").unwrap(), 14);
        assert!(parse_days("soon").is_err());
        assert_eq!(
            parse_pagefile_spec("auto", "C:").unwrap(),
            OptimizerIntent::SetPagefileAutomatic
        );
        assert_eq!(
            parse_pagefile_spec("4096-8192", "C:").unwrap(),
            OptimizerIntent::SetPagefile {
                drive: "C:".into(),
                initial_mb: 4096,
                max_mb: 8192
            }
        );
        assert_eq!(
            parse_pagefile_spec("6144", "d:").unwrap(),
            OptimizerIntent::SetPagefile {
                drive: "d:".into(),
                initial_mb: 6144,
                max_mb: 6144
            }
        );
        assert!(parse_pagefile_spec("8192-4096", "C:").is_err());
        assert!(parse_pagefile_spec("4096", r"C:\x").is_err());
        assert_eq!(
            parse_lanes(&["invisible,regenerable".into()]).unwrap(),
            vec![Lane::Invisible, Lane::Regenerable]
        );
        assert!(parse_lanes(&["magic".into()]).is_err());
    }
}
