//! Windows-specific APIs, volume operations, directory scanning, and clean primitives.

pub mod cfapi;
pub mod cleaner;
pub mod decisions;
pub mod dir_scanner;
pub mod fileinfo;
pub mod install;
pub mod junction;
pub mod os_handlers;
pub mod pipe;
pub mod preconditions;
pub mod prefetch;
pub mod process;
pub mod recycle;
pub mod reflink;
pub mod restore;
pub mod sysinfo;
pub mod tray;
pub mod usn;
pub mod volume;
pub mod wof;
pub mod wsl;

pub use cleaner::{
    CleanRootReport, DeleteOutcomeKind, ItemOutcome, final_path_by_handle, query_file_id,
    safe_clean_root,
};
pub use dir_scanner::{DirScanOptions, DirScanOutput, scan_dirs};
pub use install::{
    INSTALL_BINARY_NAMES, InstallReport, PROTECTED_INSTALL_SDDL, apply_protected_install_dacl,
    atomic_copy_binary, default_install_dir, install_binaries_to_dir, install_preflight_issues,
    untrusted_install_dir_entries,
};
pub use os_handlers::{
    CommandOutcome, OsHandlerInfo, estimate_os_handler, find_program_in_path, find_program_on_path,
    lookup_handler_clsid, purge_os_handler, run_clean_command,
};
pub use pipe::{
    NamedPipeClient, NamedPipeServer, PipeClientImpersonator, PipeImpersonationGuard,
    default_pipe_name, is_directory_user_renamable, is_directory_user_writable,
    launch_elevated_helper, query_path_owner_dacl_sddl, sddl_allows_non_admin_rename,
    sddl_grants_non_admin_write, validate_local_pipe_name,
};
pub use preconditions::{
    SystemPreconditions, apply_preconditions, find_locking_processes, power_status,
    probe_preconditions, running_processes, servicing_busy,
};
pub use process::{
    BELOW_NORMAL_PRIORITY_CLASS, CREATE_NO_WINDOW, hidden_command, hidden_command_with_flags,
};
pub use recycle::{
    RecycleOutcome, move_to_recycle_bin, open_item, recycle_replaced_original, reveal_in_explorer,
};
pub use restore::{
    RestorePointOutcome, create_restore_point_if_enabled, parse_dism_uninstall_window_days,
    query_os_uninstall_window_days,
};
pub use tray::{
    BackgroundPriorityGuard, BalloonAlert, LOW_SPACE_BYTES_THRESHOLD, LOW_SPACE_PCT_THRESHOLD,
    SCHEDULED_TASK_NAME, TRAY_FOOTPRINT_BUDGET_BYTES, TRAY_POLL_INTERVAL, TRAY_REALERT_PERIOD,
    TrayCheckReport, attach_parent_console_for_cli_output, build_schtasks_args,
    check_low_space_alerts, configure_scheduled_safe_clean, run_tray_check_once, run_tray_loop,
    safe_clean_confirmation_text, should_notify_low_space,
};
pub use volume::{
    VolumeHandle, enable_privilege, is_elevated, list_volumes, open_volume, peak_working_set,
    program_files_dir, system32_dir, volume_info, volume_root_of,
};
