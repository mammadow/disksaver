//! Core library for Disk Saver (`disksaver`).
//!
//! `unsafe` is denied crate-wide; only the Win32 FFI quarantine in [`win`] may opt in (P4–P8
//! invariant: `#![forbid(unsafe_code)]` everywhere outside `win/`).
#![deny(unsafe_code)]

pub mod budget;
pub mod clean;
pub mod error;
pub mod hunt;
pub mod index;
pub mod insights;
pub mod ipc;
pub mod ledger;
pub mod ntfs;
pub mod optimize;
pub mod scan;
pub mod sweep;
pub mod time;
pub mod video;
pub mod volume;
#[allow(unsafe_code)]
pub mod win;

pub use clean::{
    ActionJournal, CleanPhase, CleanPlan, CleanProgress, CleanReport, DenyContext, EstimateBasis,
    ExecuteOptions, FileIdKind, JournalEntryRecord, JournalRunRecord, PlanOptions, PlannedItem,
    PlannedRoot, PlannedRule, RelocationRecord, RuleExecutionSummary, SkippedRule,
    assert_not_denied, build_plan_from_index, builtin_rules, enrich_os_handler_estimates,
    execute_plan, execute_plan_with_impersonation, is_denied_path, mark_admin_gated_estimates,
    probe_locked_roots,
};
pub use error::{DskError, NtfsError, Result};
pub use index::{
    CODEC_MAGIC, CODEC_VERSION, GrowthDb, GrowthDelta, GrowthReport, GrowthWindow, Index, NONE,
    NodeFlags, NodeId, ROOT, RUNAWAY_BYTES_PER_DAY, SNAPSHOT_MAGIC, SNAPSHOT_VERSION, SizeBasis,
    SnapshotMeta, decode_scan_report, default_snapshot_dir, encode_scan_report, ext_breakdown,
    ext_breakdown_subtree, load_snapshot_verified, save_snapshot_atomic, snapshot_path_for_volume,
    top_dirs, top_files, wtf8_to_string_lossy,
};
pub use ipc::{
    HelperRequest, HelperResponse, HelperSessionStore, MAX_CONTROL_FRAME_BYTES,
    MAX_STREAM_FRAME_BYTES, SystemPreconditionsDto, connect_or_launch_helper, helper_build_plan,
    helper_execute_plan_rules, helper_run_optimizer, helper_scan_volume, read_frame, write_frame,
};
pub use ntfs::{Phase, Progress, UsnDelta, UsnJournalState, UsnRecord, validate_usn_continuity};
pub use scan::{
    ScanMethod, ScanOptions, ScanReport, UsageCheck, choose_method, scan_volume,
    scan_volume_with_cache_dir,
};
pub use time::filetime_to_min2000;
pub use volume::VolumeInfo;
pub use win::{
    BackgroundPriorityGuard, BalloonAlert, CleanRootReport, CommandOutcome, DeleteOutcomeKind,
    INSTALL_BINARY_NAMES, InstallReport, ItemOutcome, LOW_SPACE_BYTES_THRESHOLD,
    LOW_SPACE_PCT_THRESHOLD, NamedPipeClient, NamedPipeServer, OsHandlerInfo,
    PROTECTED_INSTALL_SDDL, PipeImpersonationGuard, RecycleOutcome, RestorePointOutcome,
    SCHEDULED_TASK_NAME, SystemPreconditions, TRAY_FOOTPRINT_BUDGET_BYTES, TRAY_POLL_INTERVAL,
    TrayCheckReport, apply_preconditions, apply_protected_install_dacl, atomic_copy_binary,
    attach_parent_console_for_cli_output, build_schtasks_args, check_low_space_alerts,
    configure_scheduled_safe_clean, default_install_dir, default_pipe_name, estimate_os_handler,
    find_program_in_path, find_program_on_path, hidden_command, hidden_command_with_flags,
    install_binaries_to_dir, is_directory_user_writable, is_elevated, launch_elevated_helper,
    list_volumes, lookup_handler_clsid, move_to_recycle_bin, open_item, probe_preconditions,
    purge_os_handler, reveal_in_explorer, run_clean_command, run_tray_check_once, run_tray_loop,
    safe_clean_root, volume_info, volume_root_of,
};
