#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use clap::{Args, Parser, Subcommand, ValueEnum};
use dsk_core::clean::rules::builtin_rules;
use dsk_core::clean::{
    ActionJournal, CleanPhase, CleanPlan, CleanProgress, DenyContext, ExecuteOptions, PlanOptions,
    RuleMethod, RuleTier, build_plan_from_index, enrich_os_handler_estimates, execute_plan,
};
use dsk_core::insights::{
    DupeRemediationAction, InsightsOptions, default_hash_cache_path, find_duplicates,
    remediate_duplicate_group, run_all_insights, scan_ai_models, scan_cold_data_live,
    scan_gaming_libraries, scan_orphaned_app_data, scan_project_artifacts,
};
use dsk_core::optimize::{
    HiberfileMode, WofAlgorithm, configure_hiberfile, dehydrate_cloud_file,
    discover_vhdx_candidates, execute_folder_relocation, probe_sys_tunables,
    query_compact_os_state, resize_or_prune_vss, set_compact_os_enabled, set_reserved_storage,
    undo_folder_relocation,
};
use dsk_core::{Phase, Progress, ScanMethod, ScanOptions, scan_volume};

mod clean_report;
mod insights_report;
mod reclaim_cmd;
mod report;
mod videos_cmd;
use report::{build_json_report, exit_code_for_error, print_human_report};

#[derive(Parser, Debug)]
#[command(
    name = "disksaver",
    version,
    about = "High-precision Windows NTFS disk analyzer, safe cleaner, and storage reclaimer"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a directory or volume
    Scan(ScanArgs),
    /// Create a safe cleanup plan
    Plan(PlanArgs),
    /// Execute a safe cleanup plan or scan and clean
    Clean(CleanArgs),
    /// Query cleanup history and journal records
    History(HistoryArgs),
    /// Non-destructive disk space reclamation
    Optimize(OptimizeArgs),
    /// Find duplicate files and optionally deduplicate/recycle copies
    Dupes(DupesArgs),
    /// Discover project artifacts, AI models, gaming libraries, orphaned app data, and cold files
    Insights(InsightsArgs),
    /// Analyze historical folder growth deltas (24h / 7d) and runaway directories
    Growth(GrowthArgs),
    /// Harden a target install directory DACL and copy sibling DiskSaver binaries atomically
    InstallDir(InstallDirArgs),
    /// Ranked, de-overlapped list of every way to free space (read-only unless --yes)
    Reclaim(reclaim_cmd::ReclaimArgs),
    /// Explore the whole volume for the biggest removable things and swarms of small ones
    Hunt(reclaim_cmd::HuntArgs),
    /// Sweep stale generations out of build-output folders (Cargo target, Next.js cache)
    Sweep(reclaim_cmd::SweepArgs),
    /// Start an installed app's own uninstaller
    Uninstall(reclaim_cmd::UninstallArgs),
    /// Move a user library (Videos, Downloads, ...) to another drive the way Explorer does
    MoveLibrary(reclaim_cmd::MoveLibraryArgs),
    /// Find big videos on every drive and shrink the ones you pick (verified AV1/HEVC re-encode)
    Videos(videos_cmd::VideosArgs),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum MethodArg {
    Auto,
    Mft,
    Dir,
}

impl From<MethodArg> for ScanMethod {
    fn from(m: MethodArg) -> Self {
        match m {
            MethodArg::Auto => ScanMethod::Auto,
            MethodArg::Mft => ScanMethod::Mft,
            MethodArg::Dir => ScanMethod::Dir,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum TierArg {
    Safe,
    Review,
    Advanced,
}

impl From<TierArg> for RuleTier {
    fn from(t: TierArg) -> Self {
        match t {
            TierArg::Safe => RuleTier::Safe,
            TierArg::Review => RuleTier::Review,
            TierArg::Advanced => RuleTier::Advanced,
        }
    }
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to directory or volume root to scan
    pub path: PathBuf,

    /// Scan method to use
    #[arg(long, default_value = "auto", value_enum)]
    pub method: MethodArg,

    /// Number of top directories to display
    #[arg(long, default_value_t = 20)]
    pub top_dirs: usize,

    /// Maximum directory depth for top directory search
    #[arg(long, default_value_t = 3)]
    pub depth: u16,

    /// Number of top files to display
    #[arg(long, default_value_t = 20)]
    pub top_files: usize,

    /// Number of top extensions to display
    #[arg(long, default_value_t = 10)]
    pub top_ext: usize,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,

    /// Include memory and index statistics
    #[arg(long)]
    pub stats: bool,

    /// Transparently launch/connect elevated helper when unelevated
    #[arg(long)]
    pub use_helper: bool,

    /// Bypass cached .dsi snapshots and USN incremental updates
    #[arg(long)]
    pub no_cache: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum GrowthWindowArg {
    #[value(name = "24h")]
    H24,
    #[value(name = "7d")]
    D7,
}

impl From<GrowthWindowArg> for dsk_core::GrowthWindow {
    fn from(w: GrowthWindowArg) -> Self {
        match w {
            GrowthWindowArg::H24 => dsk_core::GrowthWindow::H24,
            GrowthWindowArg::D7 => dsk_core::GrowthWindow::D7,
        }
    }
}

#[derive(Args, Debug)]
pub struct GrowthArgs {
    /// Path or volume root to inspect growth for (defaults to %SystemDrive%\)
    pub path: Option<PathBuf>,

    /// Comparison window (24h or 7d)
    #[arg(long, default_value = "24h", value_enum)]
    pub window: GrowthWindowArg,

    /// Maximum number of growing directories to list
    #[arg(long, default_value_t = 20)]
    pub top: usize,

    /// Optional SQLite database path (defaults to %LOCALAPPDATA%\DiskSaver\growth.db)
    #[arg(long)]
    pub db: Option<PathBuf>,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct InstallDirArgs {
    /// Target installation directory (defaults to "%ProgramFiles%\DiskSaver")
    #[arg(value_name = "TARGET", conflicts_with = "target")]
    pub target_pos: Option<PathBuf>,

    /// Target installation directory (alternative to the positional TARGET)
    #[arg(long = "target", value_name = "DIR")]
    pub target: Option<PathBuf>,

    /// Optional source directory containing built .exe binaries (defaults to current exe directory)
    #[arg(long)]
    pub source_dir: Option<PathBuf>,

    /// Show planned DACL hardening and file copies without touching disk
    #[arg(long)]
    pub dry_run: bool,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    /// Path to directory or volume root to scan (defaults to %SystemDrive%\)
    pub path: Option<PathBuf>,

    /// Specific rule IDs to include (can be specified multiple times)
    #[arg(long = "rule")]
    pub rules: Vec<String>,

    /// Maximum rule tier to include (safe, review, advanced)
    #[arg(long, default_value = "safe", value_enum)]
    pub tier: TierArg,

    /// Include Recycle Bin in cleanup plan
    #[arg(long)]
    pub include_recycle_bin: bool,

    /// Disable OS VolumeCaches COM handlers
    #[arg(long)]
    pub no_os_handlers: bool,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,

    /// Path to write serialized CleanPlan JSON
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Transparently launch/connect elevated helper when unelevated
    #[arg(long)]
    pub use_helper: bool,
}

#[derive(Args, Debug)]
pub struct CleanArgs {
    /// Load serialized CleanPlan from file
    #[arg(long, conflicts_with = "path")]
    pub plan: Option<PathBuf>,

    /// Path to directory or volume root to scan and clean (defaults to %SystemDrive%\ if --plan omitted)
    pub path: Option<PathBuf>,

    /// Specific rule IDs to include (can be specified multiple times)
    #[arg(long = "rule")]
    pub rules: Vec<String>,

    /// Maximum rule tier to include (safe, review, advanced)
    #[arg(long, default_value = "safe", value_enum)]
    pub tier: TierArg,

    /// Include Recycle Bin in cleanup plan
    #[arg(long)]
    pub include_recycle_bin: bool,

    /// Disable OS VolumeCaches COM handlers
    #[arg(long)]
    pub no_os_handlers: bool,

    /// Execute deletions live (safety gate: required unless --dry-run is passed)
    #[arg(long)]
    pub yes: bool,

    /// Simulate execution without deleting files or running purge handlers
    #[arg(long)]
    pub dry_run: bool,

    /// Force execution on low battery (< 30%)
    #[arg(long)]
    pub force: bool,

    /// Path to SQLite action journal database (defaults to %LOCALAPPDATA%\DiskSaver\journal.db)
    #[arg(long)]
    pub journal: Option<PathBuf>,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,

    /// Transparently launch/connect elevated helper when unelevated
    #[arg(long)]
    pub use_helper: bool,
}

#[derive(Args, Debug)]
pub struct HistoryArgs {
    /// Maximum number of runs to display
    #[arg(long, default_value_t = 20)]
    pub limit: usize,

    /// Show detailed item entries for a specific run ID
    #[arg(long)]
    pub run: Option<String>,

    /// Path to SQLite action journal database (defaults to %LOCALAPPDATA%\DiskSaver\journal.db)
    #[arg(long)]
    pub journal: Option<PathBuf>,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct OptimizeArgs {
    #[command(subcommand)]
    pub command: OptimizeCommands,
}

#[derive(Subcommand, Debug)]
pub enum OptimizeCommands {
    /// Discover or compact virtual disks (.vhdx, .vhd, Docker, WSL)
    Vhdx {
        /// Target virtual disk path to compact (if omitted, discovers all virtual disks)
        #[arg(long)]
        path: Option<PathBuf>,
        /// Optional WSL distro name to enable lasting sparse auto-trim
        #[arg(long)]
        sparse: Option<String>,
        /// Do not run `fstrim` inside the registered distro before compacting
        #[arg(long)]
        no_trim: bool,
        /// Perform simulation without modifying disk
        #[arg(long)]
        dry_run: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// WOF transparent folder compression and CompactOS
    Compress {
        /// Target folder to compress
        #[arg(long)]
        path: Option<PathBuf>,
        /// WOF algorithm (xpress4k, xpress8k, xpress16k, lzx)
        #[arg(long, default_value = "xpress8k")]
        algo: String,
        /// CompactOS mode (query, always, never)
        #[arg(long)]
        compact_os: Option<String>,
        /// Estimate savings only (byte-weighted sample through the real codec)
        #[arg(long)]
        dry_run: bool,
        /// Remove WOF compression from --path instead (undo)
        #[arg(long)]
        undo: bool,
        /// Re-compress every folder compressed before (updates rewrite files uncompressed)
        #[arg(long)]
        reapply: bool,
        /// Leave files written within this many days alone
        #[arg(long, default_value_t = 14)]
        min_age_days: u32,
        /// Route CompactOS changes, and folders directly under Program Files, through the
        /// elevated helper (UAC prompt) when not elevated
        #[arg(long)]
        use_helper: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Windows system storage tunables (hiberfile, VSS, Reserved Storage)
    Tunables {
        /// Configure hiberfile mode (full, reduced, off)
        #[arg(long)]
        hiberfile: Option<String>,
        /// Resize VSS shadow storage maximum cap percentage (e.g. 5)
        #[arg(long)]
        vss_max: Option<u8>,
        /// Prune oldest VSS shadow copies
        #[arg(long)]
        vss_prune: bool,
        /// Volume drive for VSS (defaults to C:)
        #[arg(long, default_value = "C:")]
        vss_drive: String,
        /// Configure Reserved Storage (enable, disable)
        #[arg(long)]
        reserved_storage: Option<String>,
        /// Pagefile: `auto` (Windows manages all drives), `system` (system-managed on
        /// --pagefile-drive), or a fixed size `<initial>-<max>` in MiB. Takes effect after a reboot.
        #[arg(long)]
        pagefile: Option<String>,
        /// Drive for --pagefile (defaults to C:)
        #[arg(long, default_value = "C:")]
        pagefile_drive: String,
        /// Print sizing recommendations (hibernation, pagefile, CompactOS, ...) and exit
        #[arg(long)]
        advise: bool,
        /// Perform simulation
        #[arg(long)]
        dry_run: bool,
        /// Route changes through the elevated helper (UAC prompt) when not elevated
        #[arg(long)]
        use_helper: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Dehydrate in-sync cloud placeholder files
    Dehydrate {
        /// Target cloud file to dehydrate
        #[arg(long)]
        path: PathBuf,
        /// Perform check without releasing storage
        #[arg(long)]
        dry_run: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Relocate a folder across drives and create a directory junction
    Relocate {
        /// Source directory to relocate
        #[arg(long)]
        source: PathBuf,
        /// Target parent directory on fixed drive
        #[arg(long)]
        target_parent: PathBuf,
        /// Path to SQLite action journal database
        #[arg(long)]
        journal: Option<PathBuf>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Restore an active folder relocation from journal
    UndoRelocate {
        /// Relocation ID to undo
        #[arg(long)]
        id: String,
        /// Path to SQLite action journal database
        #[arg(long)]
        journal: Option<PathBuf>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Runs an administrator optimizer intent through the elevated helper when `use_helper` is set
/// and this process is not elevated (§10.1 intent-only delegation). Returns `None` when the
/// caller should run the operation in-process instead.
fn delegate_optimizer_intent(
    use_helper: bool,
    intent: dsk_core::optimize::OptimizerIntent,
    dry_run: bool,
) -> Option<dsk_core::Result<String>> {
    if !use_helper || dsk_core::is_elevated() {
        return None;
    }
    Some(
        dsk_core::connect_or_launch_helper(std::time::Duration::from_secs(30))
            .and_then(|mut client| dsk_core::helper_run_optimizer(&mut client, &intent, dry_run)),
    )
}

/// `Some((x86, folder_name))` when `path` is a folder directly under Program Files (x86).
fn program_files_child(path: &std::path::Path) -> Option<(bool, String)> {
    let parent = path.parent()?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    let norm = dsk_core::clean::deny::normalize_win_path_str;
    if norm(parent) == norm(&dsk_core::win::volume::program_files_dir()) {
        Some((false, name))
    } else if norm(parent) == norm(&dsk_core::win::volume::program_files_x86_dir()) {
        Some((true, name))
    } else {
        None
    }
}

fn parse_wof_algo(s: &str) -> Option<WofAlgorithm> {
    match s.to_ascii_lowercase().as_str() {
        "xpress4k" => Some(WofAlgorithm::Xpress4k),
        "xpress8k" => Some(WofAlgorithm::Xpress8k),
        "xpress16k" => Some(WofAlgorithm::Xpress16k),
        "lzx" => Some(WofAlgorithm::Lzx),
        _ => None,
    }
}

/// `optimize compress --reapply`: re-compresses recorded folders (files written in the last day
/// are left for next time). Program Files folders need an elevated shell or `--use-helper`.
fn reapply_compressed_roots(use_helper: bool, dry_run: bool, json: bool, cancel: &AtomicBool) {
    let roots = ActionJournal::open_existing(&ActionJournal::default_path())
        .ok()
        .flatten()
        .and_then(|j| j.list_wof_roots().ok())
        .unwrap_or_default();
    let mut results = Vec::new();
    for (path, algo_s, _, _) in roots {
        let Some(algo) = parse_wof_algo(&algo_s) else {
            continue;
        };
        if !path.is_dir() {
            results.push(serde_json::json!({ "path": path, "skipped": "folder no longer exists" }));
            continue;
        }
        if !dsk_core::is_elevated()
            && let Some((x86, folder)) = program_files_child(&path)
        {
            if !use_helper {
                results.push(serde_json::json!({ "path": path, "skipped": "needs an elevated shell or --use-helper" }));
                continue;
            }
            let intent = dsk_core::optimize::OptimizerIntent::CompressProgramFilesApp {
                x86,
                folder,
                algorithm: algo,
            };
            let r = delegate_optimizer_intent(true, intent, dry_run);
            results.push(match r {
                Some(Ok(msg)) => serde_json::json!({ "path": path, "message": msg }),
                Some(Err(e)) => serde_json::json!({ "path": path, "error": e.to_string() }),
                None => serde_json::json!({ "path": path, "skipped": "helper unavailable" }),
            });
            continue;
        }
        let r = dsk_core::optimize::wof::compress_folder_wof_with(
            &path,
            algo,
            dry_run,
            cancel,
            &dsk_core::optimize::wof::WofApplyOptions {
                enforce_gate: false,
                min_age_days: 1,
                threads: 0,
            },
        );
        results.push(match r {
            Ok(rep) => {
                if !dry_run {
                    record_wof_root_result(&path, algo, false, rep.freed_bytes);
                }
                serde_json::json!({ "path": path, "files_compressed": rep.files_compressed, "freed_bytes": rep.freed_bytes })
            }
            Err(e) => serde_json::json!({ "path": path, "error": e.to_string() }),
        });
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
    } else if results.is_empty() {
        println!("No compressed folders recorded yet.");
    } else {
        for r in &results {
            println!("{r}");
        }
    }
}

/// Remembers (or forgets, after undo) a compressed folder for re-compression after updates.
fn record_wof_root_result(path: &std::path::Path, algo: WofAlgorithm, undo: bool, saved: u64) {
    if let Ok(mut j) = ActionJournal::open(&ActionJournal::default_path()) {
        let _ = if undo {
            j.remove_wof_root(path)
        } else {
            j.record_wof_root(path, algo.as_compact_arg(), saved)
        };
    }
}

pub(crate) fn setup_cancel_flag() -> Arc<AtomicBool> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_handler = Arc::clone(&cancel);
    let _ = ctrlc::set_handler(move || {
        cancel_handler.store(true, Ordering::SeqCst);
    });
    cancel
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum DupeActionArg {
    Recycle,
    Hardlink,
    Reflink,
}

impl From<DupeActionArg> for DupeRemediationAction {
    fn from(v: DupeActionArg) -> Self {
        match v {
            DupeActionArg::Recycle => DupeRemediationAction::RecycleDuplicates,
            DupeActionArg::Hardlink => DupeRemediationAction::ReplaceWithHardlinks,
            DupeActionArg::Reflink => DupeRemediationAction::CloneExtentsRefs,
        }
    }
}

#[derive(Args, Debug)]
pub struct DupesArgs {
    /// Path to directory or volume root (defaults to system drive)
    pub path: Option<PathBuf>,

    /// Minimum duplicate file size in bytes
    #[arg(long, default_value_t = 1_048_576)]
    pub min_bytes: u64,

    /// Override worker threads (defaults to seek-penalty adaptive concurrency)
    #[arg(long)]
    pub threads: Option<usize>,

    /// Scan method to use
    #[arg(long, default_value = "auto", value_enum)]
    pub method: MethodArg,

    /// Optional custom SQLite hash cache path
    #[arg(long)]
    pub cache_db: Option<PathBuf>,

    /// Delegate raw volume scan through elevated helper IPC when unelevated
    #[arg(long)]
    pub use_helper: bool,

    /// Optional remediation action to apply to duplicate copies
    #[arg(long, value_enum)]
    pub action: Option<DupeActionArg>,

    /// Index inside each duplicate group to preserve (default 0)
    #[arg(long, default_value_t = 0)]
    pub keep: usize,

    /// Preview remediation without mutating files
    #[arg(long)]
    pub dry_run: bool,

    /// Confirm live duplicate remediation without interactive prompt
    #[arg(long)]
    pub yes: bool,

    /// Optional SQLite action journal path
    #[arg(long)]
    pub journal: Option<PathBuf>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum InsightsSectionArg {
    All,
    Projects,
    Ai,
    Gaming,
    Orphans,
    Cold,
}

#[derive(Args, Debug)]
pub struct InsightsArgs {
    /// Path to directory or volume root (defaults to system drive)
    pub path: Option<PathBuf>,

    /// Insights section to inspect
    #[arg(long, default_value = "all", value_enum)]
    pub section: InsightsSectionArg,

    /// Minimum size threshold in bytes for artifacts/models/cold files
    #[arg(long, default_value_t = 1_048_576)]
    pub min_bytes: u64,

    /// Cold inactivity window threshold in days
    #[arg(long, default_value_t = 90)]
    pub cold_days: u32,

    /// Scan method to use
    #[arg(long, default_value = "auto", value_enum)]
    pub method: MethodArg,

    /// Delegate raw volume scan through elevated helper IPC when unelevated
    #[arg(long)]
    pub use_helper: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub(crate) fn default_system_drive_path() -> PathBuf {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let drive = drive.trim_end_matches(['\\', '/']);
    PathBuf::from(format!("{drive}\\"))
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Plan(args) => run_plan(args),
        Commands::Clean(args) => run_clean(args),
        Commands::History(args) => run_history(args),
        Commands::Optimize(args) => run_optimize(args),
        Commands::Dupes(args) => run_dupes(args),
        Commands::Insights(args) => run_insights(args),
        Commands::Growth(args) => run_growth(args),
        Commands::InstallDir(args) => run_install_dir(args),
        Commands::Reclaim(args) => reclaim_cmd::run_reclaim(args),
        Commands::Hunt(args) => reclaim_cmd::run_hunt(args),
        Commands::Sweep(args) => reclaim_cmd::run_sweep(args),
        Commands::Uninstall(args) => reclaim_cmd::run_uninstall(args),
        Commands::MoveLibrary(args) => reclaim_cmd::run_move_library(args),
        Commands::Videos(args) => videos_cmd::run_videos(args),
    }
}

fn run_scan(args: ScanArgs) {
    let cancel = setup_cancel_flag();

    let last_update = Mutex::new(Instant::now());
    let progress_fn = |p: Progress| {
        let mut last = match last_update.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if last.elapsed().as_millis() >= 50 {
            *last = Instant::now();
            let phase_name = match p.phase {
                Phase::ReadingMft => "Reading MFT",
                Phase::Enumerating => "Enumerating",
                Phase::Linking => "Linking",
                Phase::Aggregating => "Aggregating",
            };
            if p.total > 0 {
                eprint!("\r[{}] {} / {}", phase_name, p.done, p.total);
            } else {
                eprint!("\r[{}] {}", phase_name, p.done);
            }
            let _ = std::io::stderr().flush();
        }
    };
    let dummy_progress = |_| {};

    let progress: &(dyn Fn(Progress) + Sync) = if args.json {
        &dummy_progress
    } else {
        &progress_fn
    };

    let opts = ScanOptions {
        method: args.method.into(),
        threads: None,
        use_cache: !args.no_cache,
    };

    let result = if args.use_helper && !dsk_core::is_elevated() {
        match dsk_core::connect_or_launch_helper(std::time::Duration::from_secs(15)) {
            Ok(mut client) => dsk_core::helper_scan_volume(
                &mut client,
                &args.path.to_string_lossy(),
                opts.method,
                progress,
                &cancel,
            ),
            Err(e) => Err(e),
        }
    } else {
        scan_volume(&args.path, &opts, progress, &cancel)
    };

    if !args.json {
        eprint!("\r{:80}\r", "");
        let _ = std::io::stderr().flush();
    }

    match result {
        Ok(report) => {
            if let Some(vol_root) = dsk_core::volume_root_of(&args.path)
                && let Ok(mut db) = dsk_core::GrowthDb::open(&dsk_core::GrowthDb::default_path())
            {
                let _ = db.record_rollup_with_basis(
                    &report.index,
                    &vol_root,
                    dsk_core::GrowthDb::now_unix(),
                    dsk_core::SizeBasis::from_scan_method(report.method_used),
                );
            }
            let json_rep = build_json_report(
                &args.path,
                &report,
                args.top_dirs,
                args.depth,
                args.top_files,
                args.top_ext,
                args.stats,
            );
            if args.json {
                match serde_json::to_string_pretty(&json_rep) {
                    Ok(json_str) => println!("{json_str}"),
                    Err(e) => {
                        eprintln!("error serializing JSON: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                print_human_report(&json_rep, report.elapsed);
            }
        }
        Err(err) => {
            let (code, msg) = exit_code_for_error(&err);
            if let Some(msg) = msg {
                eprintln!("{msg}");
            }
            std::process::exit(code);
        }
    }
}

fn run_plan(args: PlanArgs) {
    let cancel = setup_cancel_flag();
    let scanned_path = args.path.unwrap_or_else(default_system_drive_path);

    let last_update = Mutex::new(Instant::now());
    let progress_fn = |p: Progress| {
        let mut last = match last_update.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if last.elapsed().as_millis() >= 50 {
            *last = Instant::now();
            let phase_name = match p.phase {
                Phase::ReadingMft => "Reading MFT",
                Phase::Enumerating => "Enumerating",
                Phase::Linking => "Linking",
                Phase::Aggregating => "Aggregating",
            };
            if p.total > 0 {
                eprint!("\r[{}] {} / {}", phase_name, p.done, p.total);
            } else {
                eprint!("\r[{}] {}", phase_name, p.done);
            }
            let _ = std::io::stderr().flush();
        }
    };
    let dummy_progress = |_| {};
    let progress: &(dyn Fn(Progress) + Sync) = if args.json {
        &dummy_progress
    } else {
        &progress_fn
    };

    let plan = if args.use_helper && !dsk_core::is_elevated() {
        let mut client =
            match dsk_core::connect_or_launch_helper(std::time::Duration::from_secs(15)) {
                Ok(c) => c,
                Err(err) => {
                    let (code, msg) = exit_code_for_error(&err);
                    if let Some(msg) = msg {
                        eprintln!("{msg}");
                    }
                    std::process::exit(code);
                }
            };
        let (_plan_id, mut helper_plan, _pre) = match dsk_core::helper_build_plan(
            &mut client,
            &scanned_path.to_string_lossy(),
            args.tier.into(),
            args.include_recycle_bin,
        ) {
            Ok(res) => res,
            Err(err) => {
                let (code, msg) = exit_code_for_error(&err);
                if let Some(msg) = msg {
                    eprintln!("{msg}");
                }
                std::process::exit(code);
            }
        };
        if !args.rules.is_empty() {
            helper_plan.rules.retain(|r| {
                args.rules
                    .iter()
                    .any(|rf| rf.eq_ignore_ascii_case(&r.rule_id))
            });
        }
        if args.no_os_handlers {
            helper_plan
                .rules
                .retain(|r| !matches!(r.method, RuleMethod::OsHandler { .. }));
        }
        helper_plan.total_est_bytes = helper_plan.rules.iter().map(|r| r.est_bytes).sum();
        helper_plan
    } else {
        let opts = ScanOptions {
            method: ScanMethod::Auto,
            threads: None,
            use_cache: true,
        };

        let result = scan_volume(&scanned_path, &opts, progress, &cancel);

        if !args.json {
            eprint!("\r{:80}\r", "");
            let _ = std::io::stderr().flush();
        }

        let report = match result {
            Ok(r) => r,
            Err(err) => {
                let (code, msg) = exit_code_for_error(&err);
                if let Some(msg) = msg {
                    eprintln!("{msg}");
                }
                std::process::exit(code);
            }
        };

        let rules = match builtin_rules() {
            Ok(r) => r,
            Err(err) => {
                let (code, msg) = exit_code_for_error(&err);
                if let Some(msg) = msg {
                    eprintln!("{msg}");
                }
                std::process::exit(code);
            }
        };
        let deny_ctx = DenyContext::from_env();
        let plan_opts = PlanOptions {
            rule_filter: args.rules,
            include_recycle_bin: args.include_recycle_bin,
            include_os_handlers: !args.no_os_handlers,
            tier_max: args.tier.into(),
            now_min2000: None,
        };
        let dynamic_roots = dsk_core::clean::providers::dynamic_roots(
            &report.index,
            &dsk_core::insights::scan_gaming_libraries(&report.index),
        );
        let env_lookup = dynamic_roots.env_lookup();

        let mut plan = build_plan_from_index(
            &report.index,
            report.method_used,
            &scanned_path,
            &rules,
            &deny_ctx,
            &plan_opts,
            &env_lookup,
        );

        if !args.no_os_handlers {
            enrich_os_handler_estimates(&mut plan, &cancel);
        }
        dsk_core::mark_admin_gated_estimates(&mut plan, dsk_core::is_elevated());
        plan
    };

    if let Some(out_path) = &args.out {
        if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty())
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("error creating directory for plan output: {e}");
            std::process::exit(1);
        }
        match serde_json::to_string_pretty(&plan) {
            Ok(json_str) => {
                if let Err(e) = std::fs::write(out_path, json_str) {
                    eprintln!("error writing plan file: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("error serializing plan JSON: {e}");
                std::process::exit(1);
            }
        }
    }

    if args.json {
        match serde_json::to_string_pretty(&plan) {
            Ok(json_str) => println!("{json_str}"),
            Err(e) => {
                eprintln!("error serializing plan JSON: {e}");
                std::process::exit(1);
            }
        }
    } else {
        clean_report::print_human_plan(&plan);
    }
}

fn run_clean(args: CleanArgs) {
    // Immediate pre-scan safety gate
    if !args.yes && !args.dry_run {
        eprintln!(
            "refusing to delete without --yes (pass --dry-run to simulate, or --yes to execute)"
        );
        std::process::exit(2);
    }

    if args.use_helper && args.plan.is_some() && !dsk_core::is_elevated() {
        eprintln!(
            "refusing --use-helper with external --plan file; pass a target path so the helper builds and pins its own plan"
        );
        std::process::exit(2);
    }

    let cancel = setup_cancel_flag();
    let deny_ctx = DenyContext::from_env();
    let dry_run = !args.yes || args.dry_run;

    let last_update = Mutex::new(Instant::now());
    let clean_progress_fn = |p: CleanProgress| {
        let mut last = match last_update.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if last.elapsed().as_millis() >= 50 {
            *last = Instant::now();
            let phase_name = match p.phase {
                CleanPhase::CheckingPreconditions => "Checking preconditions",
                CleanPhase::EstimatingHandlers => "Estimating handlers",
                CleanPhase::CleaningFiles => "Cleaning files",
                CleanPhase::RunningHandlers => "Running handlers",
                CleanPhase::RunningCommands => "Running commands",
                CleanPhase::RecordingJournal => "Recording journal",
            };
            if p.total > 0 {
                eprint!("\r[{phase_name}] {}: {} / {}", p.rule_id, p.done, p.total);
            } else {
                eprint!("\r[{phase_name}] {}", p.rule_id);
            }
            let _ = std::io::stderr().flush();
        }
    };
    let dummy_clean_progress = |_| {};
    let clean_progress: &(dyn Fn(CleanProgress) + Sync) = if args.json {
        &dummy_clean_progress
    } else {
        &clean_progress_fn
    };

    let clean_result = if args.use_helper && !dsk_core::is_elevated() {
        let scanned_path = args.path.unwrap_or_else(default_system_drive_path);
        match dsk_core::connect_or_launch_helper(std::time::Duration::from_secs(15)) {
            Ok(mut client) => match dsk_core::helper_build_plan(
                &mut client,
                &scanned_path.to_string_lossy(),
                args.tier.into(),
                args.include_recycle_bin,
            ) {
                Ok((plan_id, mut built_plan, _pre)) => {
                    if !args.rules.is_empty() {
                        built_plan.rules.retain(|r| {
                            args.rules
                                .iter()
                                .any(|rf| rf.eq_ignore_ascii_case(&r.rule_id))
                        });
                    }
                    if args.no_os_handlers {
                        built_plan
                            .rules
                            .retain(|r| !matches!(r.method, RuleMethod::OsHandler { .. }));
                    }
                    let rule_ids: Vec<String> =
                        built_plan.rules.iter().map(|r| r.rule_id.clone()).collect();
                    dsk_core::helper_execute_plan_rules(
                        &mut client,
                        &plan_id,
                        &rule_ids,
                        dry_run,
                        args.force,
                        clean_progress,
                    )
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    } else {
        let plan = if let Some(plan_path) = &args.plan {
            let content = match std::fs::read_to_string(plan_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error reading plan file: {e}");
                    std::process::exit(1);
                }
            };
            let mut loaded_plan: CleanPlan = match serde_json::from_str(&content) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error parsing plan JSON: {e}");
                    std::process::exit(1);
                }
            };

            if !args.rules.is_empty() {
                loaded_plan.rules.retain(|r| {
                    args.rules
                        .iter()
                        .any(|rf| rf.eq_ignore_ascii_case(&r.rule_id))
                });
            }
            if args.no_os_handlers {
                loaded_plan
                    .rules
                    .retain(|r| !matches!(r.method, RuleMethod::OsHandler { .. }));
            }
            loaded_plan.total_est_bytes = loaded_plan.rules.iter().map(|r| r.est_bytes).sum();
            loaded_plan
        } else {
            let scanned_path = args.path.unwrap_or_else(default_system_drive_path);

            let scan_last_update = Mutex::new(Instant::now());
            let progress_fn = |p: Progress| {
                let mut last = match scan_last_update.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if last.elapsed().as_millis() >= 50 {
                    *last = Instant::now();
                    let phase_name = match p.phase {
                        Phase::ReadingMft => "Reading MFT",
                        Phase::Enumerating => "Enumerating",
                        Phase::Linking => "Linking",
                        Phase::Aggregating => "Aggregating",
                    };
                    if p.total > 0 {
                        eprint!("\r[{}] {} / {}", phase_name, p.done, p.total);
                    } else {
                        eprint!("\r[{}] {}", phase_name, p.done);
                    }
                    let _ = std::io::stderr().flush();
                }
            };
            let dummy_progress = |_| {};
            let progress: &(dyn Fn(Progress) + Sync) = if args.json {
                &dummy_progress
            } else {
                &progress_fn
            };

            let opts = ScanOptions {
                method: ScanMethod::Auto,
                threads: None,
                use_cache: true,
            };

            let result = scan_volume(&scanned_path, &opts, progress, &cancel);

            if !args.json {
                eprint!("\r{:80}\r", "");
                let _ = std::io::stderr().flush();
            }

            let report = match result {
                Ok(r) => r,
                Err(err) => {
                    let (code, msg) = exit_code_for_error(&err);
                    if let Some(msg) = msg {
                        eprintln!("{msg}");
                    }
                    std::process::exit(code);
                }
            };

            let rules = match builtin_rules() {
                Ok(r) => r,
                Err(err) => {
                    let (code, msg) = exit_code_for_error(&err);
                    if let Some(msg) = msg {
                        eprintln!("{msg}");
                    }
                    std::process::exit(code);
                }
            };
            let plan_opts = PlanOptions {
                rule_filter: args.rules,
                include_recycle_bin: args.include_recycle_bin,
                include_os_handlers: !args.no_os_handlers,
                tier_max: args.tier.into(),
                now_min2000: None,
            };
            let dynamic_roots = dsk_core::clean::providers::dynamic_roots(
                &report.index,
                &dsk_core::insights::scan_gaming_libraries(&report.index),
            );
            let env_lookup = dynamic_roots.env_lookup();

            let mut built_plan = build_plan_from_index(
                &report.index,
                report.method_used,
                &scanned_path,
                &rules,
                &deny_ctx,
                &plan_opts,
                &env_lookup,
            );

            if !args.no_os_handlers {
                enrich_os_handler_estimates(&mut built_plan, &cancel);
            }
            dsk_core::mark_admin_gated_estimates(&mut built_plan, dsk_core::is_elevated());
            built_plan
        };

        let exec_opts = ExecuteOptions {
            dry_run,
            force_battery: args.force,
            journal_path: args.journal,
        };

        execute_plan(&plan, &exec_opts, &deny_ctx, clean_progress, &cancel)
    };

    if !args.json {
        eprint!("\r{:80}\r", "");
        let _ = std::io::stderr().flush();
    }

    match clean_result {
        Ok(clean_report) => {
            if args.json {
                match serde_json::to_string_pretty(&clean_report) {
                    Ok(json_str) => println!("{json_str}"),
                    Err(e) => {
                        eprintln!("error serializing clean report JSON: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                clean_report::print_human_clean(&clean_report);
            }
        }
        Err(err) => {
            let (code, msg) = exit_code_for_error(&err);
            if let Some(msg) = msg {
                eprintln!("{msg}");
            }
            std::process::exit(code);
        }
    }
}

fn run_history(args: HistoryArgs) {
    let db_path = args.journal.unwrap_or_else(ActionJournal::default_path);

    if !db_path.exists() {
        if let Some(run_id) = &args.run {
            eprintln!("run not found: {run_id}");
            std::process::exit(1);
        } else {
            if args.json {
                println!("[]");
            } else {
                println!("No cleanup history found.");
            }
            return;
        }
    }

    let journal = match ActionJournal::open(&db_path) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error opening journal database: {e}");
            std::process::exit(1);
        }
    };

    if let Some(run_id) = &args.run {
        let runs = match journal.list_runs(usize::MAX) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error querying journal runs: {e}");
                std::process::exit(1);
            }
        };
        let maybe_run = runs.into_iter().find(|r| r.run_id == *run_id);
        let run = match maybe_run {
            Some(r) => r,
            None => {
                eprintln!("run not found: {run_id}");
                std::process::exit(1);
            }
        };

        let entries = match journal.get_run_entries(run_id) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error querying journal entries: {e}");
                std::process::exit(1);
            }
        };

        if args.json {
            match serde_json::to_string_pretty(&entries) {
                Ok(json_str) => println!("{json_str}"),
                Err(e) => {
                    eprintln!("error serializing journal entries JSON: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            clean_report::print_human_history_run_details(&run, &entries);
        }
    } else {
        let runs = match journal.list_runs(args.limit) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error querying journal runs: {e}");
                std::process::exit(1);
            }
        };

        if runs.is_empty() {
            if args.json {
                println!("[]");
            } else {
                println!("No cleanup history found.");
            }
            return;
        }

        if args.json {
            match serde_json::to_string_pretty(&runs) {
                Ok(json_str) => println!("{json_str}"),
                Err(e) => {
                    eprintln!("error serializing journal runs JSON: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            clean_report::print_human_history_runs(&runs);
        }
    }
}

fn run_optimize(args: OptimizeArgs) {
    let cancel = setup_cancel_flag();

    match args.command {
        OptimizeCommands::Vhdx {
            path,
            sparse,
            no_trim,
            dry_run,
            json,
        } => {
            if let Some(target_path) = path {
                // Trim inside the registered distro that owns this disk (P9.4); Docker manages
                // its own disks and is never trimmed from here.
                let norm = dsk_core::clean::deny::normalize_win_path_str;
                let trim_distro = (!no_trim)
                    .then(|| {
                        dsk_core::win::wsl::registered_wsl_distros()
                            .into_iter()
                            .find(|d| norm(&d.vhdx_path) == norm(&target_path))
                            .map(|d| d.name)
                            .filter(|n| !n.eq_ignore_ascii_case("docker-desktop"))
                    })
                    .flatten();
                let opts = dsk_core::optimize::vhdx::VhdxCompactOptions {
                    sparse_distro: sparse.clone(),
                    trim_distro,
                };
                match dsk_core::optimize::vhdx::compact_vhdx_with(&target_path, &opts, dry_run) {
                    Ok(rep) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                        } else {
                            println!(
                                "[Optimize] VHDX compact finished on {}: freed {} (dry_run: {}, trimmed: {})",
                                target_path.display(),
                                report::fmt_bytes(rep.freed_bytes),
                                rep.dry_run,
                                match rep.trimmed {
                                    Some(true) => "yes",
                                    Some(false) => "failed",
                                    None => "no",
                                }
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Error compacting VHDX: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                let sys_drive = default_system_drive_path();
                let opts = ScanOptions {
                    method: ScanMethod::Auto,
                    threads: None,
                    use_cache: true,
                };
                let progress_fn = |_| {};
                match scan_volume(&sys_drive, &opts, &progress_fn, &cancel) {
                    Ok(report) => {
                        let candidates = discover_vhdx_candidates(&report.index);
                        if json {
                            println!("{}", serde_json::to_string_pretty(&candidates).unwrap());
                        } else if candidates.is_empty() {
                            println!("No virtual disks detected on {}", sys_drive.display());
                        } else {
                            println!("Found {} virtual disk candidate(s):", candidates.len());
                            for c in candidates {
                                println!(
                                    "  - {} [{:?}{}] file {}, guest uses {}, up to ~{} reclaimable after trim + compact{}",
                                    c.path.display(),
                                    c.kind,
                                    c.distro_name
                                        .as_deref()
                                        .map(|d| format!(": {d}"))
                                        .unwrap_or_default(),
                                    report::fmt_bytes(c.host_allocated_bytes),
                                    c.guest_used_bytes
                                        .map(report::fmt_bytes)
                                        .unwrap_or_else(|| "?".into()),
                                    report::fmt_bytes(c.est_reclaimable_bytes),
                                    if c.locked_by.is_empty() {
                                        String::new()
                                    } else {
                                        format!(" (in use by {})", c.locked_by.join(", "))
                                    }
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error scanning for virtual disks: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }

        OptimizeCommands::Compress {
            path,
            algo,
            compact_os,
            dry_run,
            undo,
            reapply,
            min_age_days,
            use_helper,
            json,
        } => {
            if reapply {
                reapply_compressed_roots(use_helper, dry_run, json, &cancel);
                return;
            }
            if let Some(ref mode) = compact_os {
                match mode.to_ascii_lowercase().as_str() {
                    "query" => match query_compact_os_state() {
                        Ok(st) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&st).unwrap());
                            } else {
                                println!(
                                    "[CompactOS] State: {}",
                                    if st.enabled { "Enabled" } else { "Disabled" }
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("Error querying CompactOS: {e}");
                            std::process::exit(1);
                        }
                    },
                    mode @ ("always" | "enable" | "never" | "disable")
                        if let Some(res) = delegate_optimizer_intent(
                            use_helper,
                            dsk_core::optimize::OptimizerIntent::SetCompactOs {
                                enable: matches!(mode, "always" | "enable"),
                            },
                            false,
                        ) =>
                    {
                        match res {
                            Ok(msg) => {
                                if json {
                                    println!("{}", serde_json::json!({ "message": msg }));
                                } else {
                                    println!("[CompactOS via helper] {msg}");
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "Error changing CompactOS through the elevated helper: {e}"
                                );
                                std::process::exit(1);
                            }
                        }
                    }
                    "always" | "enable" => match set_compact_os_enabled(true) {
                        Ok(rep) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                            } else {
                                println!("[CompactOS] {}", rep.message);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error enabling CompactOS: {e}");
                            std::process::exit(1);
                        }
                    },
                    "never" | "disable" => match set_compact_os_enabled(false) {
                        Ok(rep) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                            } else {
                                println!("[CompactOS] {}", rep.message);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error disabling CompactOS: {e}");
                            std::process::exit(1);
                        }
                    },
                    other => {
                        eprintln!(
                            "Unknown CompactOS mode: {other} (expected query, always, never)"
                        );
                        std::process::exit(1);
                    }
                }
                return;
            }

            let Some(target_path) = path else {
                eprintln!("Error: expected --path <FOLDER> or --compact-os <query|always|never>");
                std::process::exit(1);
            };

            let algorithm = match algo.to_ascii_lowercase().as_str() {
                "xpress4k" => WofAlgorithm::Xpress4k,
                "xpress8k" => WofAlgorithm::Xpress8k,
                "xpress16k" => WofAlgorithm::Xpress16k,
                "lzx" => WofAlgorithm::Lzx,
                other => {
                    eprintln!(
                        "Unknown WOF algorithm: {other} (expected xpress4k, xpress8k, xpress16k, lzx)"
                    );
                    std::process::exit(1);
                }
            };

            if dry_run {
                let opts = ScanOptions {
                    method: ScanMethod::Auto,
                    threads: None,
                    use_cache: true,
                };
                let progress_fn = |_| {};
                match scan_volume(&target_path, &opts, &progress_fn, &cancel) {
                    Ok(rep) => {
                        let preview = dsk_core::optimize::wof::sample_folder_compressibility_algo(
                            &rep.index,
                            dsk_core::ROOT,
                            algorithm,
                            64 * 1024 * 1024,
                        );
                        match preview {
                            Ok(p) => {
                                if json {
                                    println!("{}", serde_json::to_string_pretty(&p).unwrap());
                                } else {
                                    println!(
                                        "[WOF Preview] Estimated savings: {:.1}% (~{} bytes), Recommended: {}",
                                        p.estimated_savings_pct,
                                        p.estimated_savings_bytes(),
                                        p.recommended
                                    );
                                    if let Some(r) = p.skip_reason {
                                        println!("  Note: {r}");
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error estimating compressibility: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error scanning folder {}: {e}", target_path.display());
                        std::process::exit(1);
                    }
                }
            } else {
                // Folders directly under Program Files go through the helper as a name-only
                // intent when this shell is not elevated.
                if use_helper
                    && !dsk_core::is_elevated()
                    && let Some((x86, folder)) = program_files_child(&target_path)
                {
                    let intent = if undo {
                        dsk_core::optimize::OptimizerIntent::DecompressProgramFilesApp {
                            x86,
                            folder,
                        }
                    } else {
                        dsk_core::optimize::OptimizerIntent::CompressProgramFilesApp {
                            x86,
                            folder,
                            algorithm,
                        }
                    };
                    match delegate_optimizer_intent(true, intent, false) {
                        Some(Ok(msg)) => {
                            record_wof_root_result(&target_path, algorithm, undo, 0);
                            if json {
                                println!("{}", serde_json::json!({ "message": msg }));
                            } else {
                                println!("[WOF via helper] {msg}");
                            }
                        }
                        Some(Err(e)) => {
                            eprintln!("Error compressing through the elevated helper: {e}");
                            std::process::exit(1);
                        }
                        None => unreachable!("use_helper is set and the shell is not elevated"),
                    }
                    return;
                }
                let res = if undo {
                    dsk_core::optimize::wof::decompress_folder_wof(&target_path, &cancel)
                } else {
                    dsk_core::optimize::wof::compress_folder_wof_with(
                        &target_path,
                        algorithm,
                        false,
                        &cancel,
                        &dsk_core::optimize::wof::WofApplyOptions {
                            min_age_days,
                            ..Default::default()
                        },
                    )
                };
                match res {
                    Ok(rep) => {
                        record_wof_root_result(&target_path, algorithm, undo, rep.freed_bytes);
                        if json {
                            println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                        } else if undo {
                            println!(
                                "[WOF] Decompressed {} files in {} ({} failed); now {}",
                                rep.files_compressed,
                                target_path.display(),
                                rep.files_failed,
                                report::fmt_bytes(rep.after_allocated_bytes)
                            );
                        } else {
                            println!(
                                "[WOF] Compressed {} files in {} with {:?}: freed {} in {:.1}s ({} skipped, {} failed)",
                                rep.files_compressed,
                                target_path.display(),
                                rep.algorithm,
                                report::fmt_bytes(rep.freed_bytes),
                                rep.elapsed_ms as f64 / 1000.0,
                                rep.files_skipped,
                                rep.files_failed
                            );
                            for f in rep.failures.iter().take(5) {
                                println!("  failed: {f}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error applying WOF compression: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }

        OptimizeCommands::Tunables {
            hiberfile,
            vss_max,
            vss_prune,
            vss_drive,
            reserved_storage,
            pagefile,
            pagefile_drive,
            advise,
            dry_run,
            use_helper,
            json,
        } => {
            if advise {
                let status = probe_sys_tunables(None);
                let compact_os = query_compact_os_state().ok().map(|s| s.enabled);
                let facts =
                    dsk_core::optimize::sizing::gather_sizing_facts(&status, None, compact_os);
                let recs = dsk_core::optimize::sizing::advise_sizing(&facts);
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "facts": facts,
                            "recommendations": recs,
                        }))
                        .unwrap()
                    );
                } else {
                    reclaim_cmd::print_sizing_human(&facts, &recs);
                }
                return;
            }

            if let Some(ref spec) = pagefile {
                let intent = match reclaim_cmd::parse_pagefile_spec(spec, &pagefile_drive) {
                    Ok(i) => i,
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(2);
                    }
                };
                let res = delegate_optimizer_intent(use_helper, intent.clone(), dry_run)
                    .unwrap_or_else(|| dsk_core::optimize::run_optimizer_intent(&intent, dry_run));
                match res {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => {
                        eprintln!("Error configuring the pagefile: {e}");
                        std::process::exit(1);
                    }
                }
                if hiberfile.is_none()
                    && vss_max.is_none()
                    && !vss_prune
                    && reserved_storage.is_none()
                {
                    return;
                }
            }

            if hiberfile.is_none() && vss_max.is_none() && !vss_prune && reserved_storage.is_none()
            {
                let status = probe_sys_tunables(None);
                if json {
                    println!("{}", serde_json::to_string_pretty(&status).unwrap());
                } else {
                    println!("[System Storage Tunables]");
                    if let Some(b) = status.hiberfil_bytes {
                        println!(
                            "  Hiberfile: {} bytes (Battery present: {})",
                            b, status.is_laptop_battery_present
                        );
                    } else {
                        println!("  Hiberfile: Disabled");
                    }
                    if let Some(used) = status.vss_used_bytes {
                        println!(
                            "  VSS Shadows: Used {} bytes, Max cap {} bytes",
                            used,
                            status.vss_max_bytes.unwrap_or(0)
                        );
                    }
                    if let Some(res) = status.reserved_storage_enabled {
                        println!(
                            "  Reserved Storage: {}",
                            if res { "Enabled" } else { "Disabled" }
                        );
                    }
                    if status.servicing_busy {
                        println!("  Note: Windows servicing lock is active");
                    }
                }
                return;
            }

            if let Some(ref mode) = hiberfile {
                let h_mode = match mode.to_ascii_lowercase().as_str() {
                    "full" => HiberfileMode::Full,
                    "reduced" => HiberfileMode::Reduced,
                    "off" => HiberfileMode::Off,
                    other => {
                        eprintln!("Unknown hiberfile mode: {other} (expected full, reduced, off)");
                        std::process::exit(1);
                    }
                };
                let res = delegate_optimizer_intent(
                    use_helper,
                    dsk_core::optimize::OptimizerIntent::SetHiberfile { mode: h_mode },
                    dry_run,
                )
                .unwrap_or_else(|| configure_hiberfile(h_mode, dry_run));
                match res {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => {
                        eprintln!("Error configuring hiberfile: {e}");
                        std::process::exit(1);
                    }
                }
            }

            if vss_prune || vss_max.is_some() {
                let intent = if vss_prune {
                    dsk_core::optimize::OptimizerIntent::VssPruneOldest {
                        drive: vss_drive.clone(),
                    }
                } else {
                    dsk_core::optimize::OptimizerIntent::VssResize {
                        drive: vss_drive.clone(),
                        max_percent: vss_max.unwrap_or(0),
                    }
                };
                let res =
                    delegate_optimizer_intent(use_helper, intent, dry_run).unwrap_or_else(|| {
                        resize_or_prune_vss(&vss_drive, vss_max, vss_prune, dry_run)
                    });
                match res {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => {
                        eprintln!("Error configuring VSS shadow storage: {e}");
                        std::process::exit(1);
                    }
                }
            }

            if let Some(ref res) = reserved_storage {
                let enable = match res.to_ascii_lowercase().as_str() {
                    "enable" | "true" | "1" => true,
                    "disable" | "false" | "0" => false,
                    other => {
                        eprintln!(
                            "Unknown reserved storage state: {other} (expected enable, disable)"
                        );
                        std::process::exit(1);
                    }
                };
                let res = delegate_optimizer_intent(
                    use_helper,
                    dsk_core::optimize::OptimizerIntent::SetReservedStorage { enabled: enable },
                    dry_run,
                )
                .unwrap_or_else(|| set_reserved_storage(enable, dry_run));
                match res {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => {
                        eprintln!("Error setting Reserved Storage: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }

        OptimizeCommands::Dehydrate {
            path,
            dry_run,
            json,
        } => match dehydrate_cloud_file(&path, dry_run) {
            Ok(freed) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "path": path,
                            "reclaimed_bytes": freed,
                            "dry_run": dry_run
                        })
                    );
                } else {
                    println!(
                        "[Cloud Dehydration] Succeeded for {}: reclaimed {} bytes (dry_run: {})",
                        path.display(),
                        freed,
                        dry_run
                    );
                }
            }
            Err(e) => {
                eprintln!("Error dehydrating cloud file: {e}");
                std::process::exit(1);
            }
        },

        OptimizeCommands::Relocate {
            source,
            target_parent,
            journal,
            json,
        } => {
            let jp = journal.unwrap_or_else(ActionJournal::default_path);
            let deny = DenyContext::from_env();
            let mut j = match ActionJournal::open(&jp) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Error opening action journal: {e}");
                    std::process::exit(1);
                }
            };

            match execute_folder_relocation(&source, &target_parent, &deny, &mut j, &cancel) {
                Ok(rep) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                    } else {
                        println!(
                            "[Relocate] Successfully relocated {} files ({} bytes) to {}",
                            rep.file_count,
                            rep.bytes_moved,
                            rep.target_path.display()
                        );
                        println!("  Relocation ID: {}", rep.relocation_id);
                        println!(
                            "  Directory junction created at: {}",
                            rep.source_path.display()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error executing folder relocation: {e}");
                    std::process::exit(1);
                }
            }
        }

        OptimizeCommands::UndoRelocate { id, journal, json } => {
            let jp = journal.unwrap_or_else(ActionJournal::default_path);
            let mut j = match ActionJournal::open(&jp) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Error opening action journal: {e}");
                    std::process::exit(1);
                }
            };

            match undo_folder_relocation(&id, &mut j, &cancel) {
                Ok(rep) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                    } else {
                        println!(
                            "[Undo Relocate] Successfully restored {} files ({} bytes) back to {}",
                            rep.file_count,
                            rep.bytes_moved,
                            rep.source_path.display()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error undoing folder relocation: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

pub(crate) fn scan_for_insights(
    path: &std::path::Path,
    method: MethodArg,
    use_helper: bool,
    json: bool,
    cancel: &Arc<AtomicBool>,
) -> dsk_core::ScanReport {
    let dummy_progress = |_: Progress| {};
    let stderr_progress = |p: Progress| {
        if !json && p.done.is_multiple_of(25_000) && p.done > 0 {
            eprint!("\rScanning... {}", p.done);
            let _ = std::io::stderr().flush();
        }
    };
    let progress: &(dyn Fn(Progress) + Sync) = if json {
        &dummy_progress
    } else {
        &stderr_progress
    };
    let opts = ScanOptions {
        method: method.into(),
        threads: None,
        use_cache: true,
    };

    let res = if use_helper && !dsk_core::is_elevated() {
        match dsk_core::connect_or_launch_helper(std::time::Duration::from_secs(15)) {
            Ok(mut client) => dsk_core::helper_scan_volume(
                &mut client,
                &path.to_string_lossy(),
                opts.method,
                progress,
                cancel,
            ),
            Err(e) => Err(e),
        }
    } else {
        scan_volume(path, &opts, progress, cancel)
    };

    if !json {
        eprint!("\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }

    match res {
        Ok(r) => r,
        Err(e) => fail_with_error("Error scanning path", &e),
    }
}

pub(crate) fn fail_with_error(prefix: &str, err: &dsk_core::DskError) -> ! {
    let (code, hint) = exit_code_for_error(err);
    eprintln!("{prefix}: {err}");
    if let Some(h) = hint {
        eprintln!("Hint: {h}");
    }
    std::process::exit(code);
}

fn run_dupes(args: DupesArgs) {
    if args.action.is_some() && !args.dry_run && !args.yes {
        eprintln!(
            "Refusing live duplicate remediation without --yes (pass --dry-run to preview safely)"
        );
        std::process::exit(2);
    }

    let cancel = setup_cancel_flag();
    let target = args.path.unwrap_or_else(default_system_drive_path);
    let scan_report = scan_for_insights(&target, args.method, args.use_helper, args.json, &cancel);

    let default_db = default_hash_cache_path();
    let cache_path = args.cache_db.as_deref().unwrap_or(&default_db);

    let report = match find_duplicates(
        &scan_report.index,
        args.min_bytes,
        Some(cache_path),
        args.threads,
        &cancel,
        |p| {
            if !args.json && p.total > 0 {
                eprint!("\r[{:?}] {} / {}", p.stage, p.done, p.total);
                let _ = std::io::stderr().flush();
            }
        },
    ) {
        Ok(r) => r,
        Err(e) => fail_with_error("Error finding duplicates", &e),
    };
    if !args.json {
        eprint!("\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }

    let batch = match args.action {
        Some(action_arg) => {
            let action: DupeRemediationAction = action_arg.into();
            let deny_ctx = DenyContext::default();
            let vol_root = &scan_report.index.volume().root;
            insights_report::remediate_groups_continue_on_error(&report.groups, |group| {
                if cancel.load(Ordering::Relaxed) {
                    return Err(dsk_core::DskError::Cancelled);
                }
                let keep = args.keep.min(group.files.len().saturating_sub(1));
                remediate_duplicate_group(
                    group,
                    keep,
                    action,
                    args.dry_run,
                    args.journal.as_deref(),
                    vol_root,
                    &deny_ctx,
                )
            })
        }
        None => insights_report::DupeBatchOutcome::default(),
    };

    if args.json {
        if batch.remediations.is_empty() && batch.failures.is_empty() && !batch.cancelled {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            let payload = serde_json::json!({
                "report": report,
                "remediations": batch.remediations,
                "group_failures": batch.failures,
                "cancelled": batch.cancelled,
            });
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
    } else {
        insights_report::print_dupes_human(
            &report,
            &batch.remediations,
            &batch.failures,
            args.keep,
        );
        if batch.cancelled {
            eprintln!("Duplicate remediation cancelled; remaining groups were not processed.");
        }
    }

    // Summary first, then a non-zero exit when any group failed or the run was cancelled.
    let code = batch.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
}

fn run_insights(args: InsightsArgs) {
    let cancel = setup_cancel_flag();
    let target = args.path.unwrap_or_else(default_system_drive_path);
    let scan_report = scan_for_insights(&target, args.method, args.use_helper, args.json, &cancel);

    match args.section {
        InsightsSectionArg::All => {
            let opts = InsightsOptions {
                project_min_bytes: args.min_bytes,
                ai_min_bytes: args.min_bytes,
                orphan_min_bytes: args.min_bytes,
                cold_min_file_bytes: args.min_bytes,
                cold_days_threshold: args.cold_days,
            };
            let report = run_all_insights(&scan_report.index, &opts);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                insights_report::print_all_insights_human(&report);
            }
        }
        InsightsSectionArg::Projects => {
            let report = scan_project_artifacts(&scan_report.index, args.min_bytes);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                insights_report::print_projects_human(&report);
            }
        }
        InsightsSectionArg::Ai => {
            let report = scan_ai_models(&scan_report.index, args.min_bytes);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                insights_report::print_ai_models_human(&report);
            }
        }
        InsightsSectionArg::Gaming => {
            let report = scan_gaming_libraries(&scan_report.index);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                insights_report::print_gaming_human(&report);
            }
        }
        InsightsSectionArg::Orphans => {
            let gaming = scan_gaming_libraries(&scan_report.index);
            let report = scan_orphaned_app_data(&scan_report.index, Some(&gaming), args.min_bytes);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                insights_report::print_orphans_human(&report);
            }
        }
        InsightsSectionArg::Cold => {
            let report = scan_cold_data_live(&scan_report.index, args.min_bytes, args.cold_days);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                insights_report::print_cold_human(&report);
            }
        }
    }
}

fn run_growth(args: GrowthArgs) {
    let target = args.path.unwrap_or_else(default_system_drive_path);
    let vol_key = dsk_core::volume_root_of(&target)
        .unwrap_or_else(|| dsk_core::GrowthDb::normalize_volume_key(&target.to_string_lossy()));
    let window: dsk_core::GrowthWindow = args.window.into();
    let db_path = args.db.unwrap_or_else(dsk_core::GrowthDb::default_path);
    let now = dsk_core::GrowthDb::now_unix();

    let report = match dsk_core::GrowthDb::open_existing(&db_path) {
        Ok(Some(db)) => match db.compute_growth_since(&vol_key, window, now, args.top) {
            Ok(rep) => rep,
            Err(e) => {
                eprintln!("error computing growth report: {e}");
                std::process::exit(1);
            }
        },
        Ok(None) => dsk_core::GrowthReport {
            volume: dsk_core::GrowthDb::normalize_volume_key(&vol_key),
            window: window.label().to_string(),
            has_baseline: false,
            latest_at_unix: None,
            baseline_at_unix: None,
            volume_delta_bytes: 0,
            runaways: Vec::new(),
            entries: Vec::new(),
        },
        Err(e) => {
            eprintln!("error opening growth database: {e}");
            std::process::exit(1);
        }
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    if !report.has_baseline {
        println!(
            "No growth baseline recorded yet for {} (window {}). Run `disksaver scan {}` across time to record snapshots.",
            report.volume, report.window, report.volume
        );
        return;
    }

    println!(
        "Growth report for {} (window: {}, volume delta: {:+} B):",
        report.volume, report.window, report.volume_delta_bytes
    );
    if !report.runaways.is_empty() {
        println!("\nRunaway growth alerts (>= 5 GiB/day):");
        for r in &report.runaways {
            println!(
                "  [RUNAWAY] {}  +{}/day (+{} B, now {} B)",
                r.path,
                report::fmt_bytes(r.rate_bytes_per_day.max(0) as u64),
                r.delta_bytes,
                report::fmt_bytes(r.current_bytes)
            );
        }
    }
    if report.entries.is_empty() {
        println!("No growing directories detected in this window.");
    } else {
        println!("\nTop growing directories:");
        for (i, e) in report.entries.iter().enumerate() {
            let tag = if e.runaway { " [RUNAWAY]" } else { "" };
            println!(
                "  {:>2}. {:<50} +{} ({}/day, now {}){}",
                i + 1,
                e.path,
                report::fmt_bytes(e.delta_bytes.max(0) as u64),
                report::fmt_bytes(e.rate_bytes_per_day.max(0) as u64),
                report::fmt_bytes(e.current_bytes),
                tag
            );
        }
    }
}

fn run_install_dir(args: InstallDirArgs) {
    let target = args
        .target
        .or(args.target_pos)
        .unwrap_or_else(dsk_core::default_install_dir);
    match dsk_core::install_binaries_to_dir(&target, args.source_dir.as_deref(), args.dry_run) {
        Ok(report) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return;
            }
            println!(
                "{} {}",
                if report.dry_run {
                    "Dry-run install plan for"
                } else {
                    "Installed DiskSaver into"
                },
                report.target_dir.display()
            );
            println!("  Protected SDDL : {}", report.sddl_applied);
            match report.user_writable_after {
                Some(writable) => println!("  User writable  : {writable}"),
                None => println!("  User writable  : (not evaluated in --dry-run)"),
            }
            println!("  Binaries ({}):", report.copied_binaries.len());
            for bin in &report.copied_binaries {
                println!("    {}", bin.display());
            }
            if !report.skipped_missing_binaries.is_empty() {
                println!(
                    "  Skipped missing: {}",
                    report.skipped_missing_binaries.join(", ")
                );
            }
            if report.blocking_issues.is_empty() {
                if report.dry_run {
                    println!("  Pre-flight     : OK (run elevated without --dry-run to install)");
                }
            } else {
                println!("  Blocking issues (a live install would refuse):");
                for issue in &report.blocking_issues {
                    println!("    - {issue}");
                }
            }
        }
        Err(err) => fail_with_error("install-dir failed", &err),
    }
}
