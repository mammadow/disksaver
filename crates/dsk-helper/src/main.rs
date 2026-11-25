#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Disk Saver on-demand UAC elevated helper daemon (`dsk-helper.exe`).

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dsk_core::Progress;
use dsk_core::clean::deny::DenyContext;
use dsk_core::clean::executor::{
    CleanProgress, ExecuteOptions, enrich_os_handler_estimates, execute_plan_with_impersonation,
};
use dsk_core::clean::plan::{PlanOptions, build_plan_from_index};
use dsk_core::clean::rules::builtin_rules;
use dsk_core::error::{DskError, Result};
use dsk_core::index::codec::encode_scan_report;
use dsk_core::ipc::protocol::{
    HelperRequest, HelperResponse, HelperSessionStore, MAX_CONTROL_FRAME_BYTES,
    MAX_STREAM_FRAME_BYTES, read_frame, write_frame,
};
use dsk_core::optimize::run_optimizer_intent;
use dsk_core::scan::{ScanMethod, ScanOptions, scan_volume};
use dsk_core::win::pipe::{NamedPipeServer, is_directory_user_writable};
use dsk_core::win::preconditions::probe_preconditions;
use dsk_core::win::volume::is_elevated;

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperArgs {
    pub pipe_name: String,
    pub idle_timeout_secs: u64,
    pub allow_unelevated_test: bool,
    pub expected_client_dir: Option<PathBuf>,
    /// Test-only journal override (refused when elevated) so integration tests never write the
    /// real `%LOCALAPPDATA%DiskSaverjournal.db`.
    pub test_journal: Option<PathBuf>,
}

impl HelperArgs {
    pub fn parse<I, T>(args: I) -> std::result::Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let mut pipe_name = None;
        let mut idle_timeout_secs = 300; // 5 minutes default
        let mut allow_unelevated_test = false;
        let mut expected_client_dir = None;
        let mut test_journal = None;

        let mut iter = args.into_iter().map(Into::into).skip(1); // skip argv[0]
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--pipe" => {
                    let val = iter
                        .next()
                        .ok_or_else(|| "missing value for --pipe".to_string())?;
                    pipe_name = Some(val);
                }
                "--idle-timeout-secs" => {
                    let val = iter
                        .next()
                        .ok_or_else(|| "missing value for --idle-timeout-secs".to_string())?;
                    idle_timeout_secs = val
                        .parse::<u64>()
                        .map_err(|e| format!("invalid --idle-timeout-secs: {e}"))?;
                }
                "--allow-unelevated-test" => {
                    allow_unelevated_test = true;
                }
                "--expected-client-dir" => {
                    let val = iter
                        .next()
                        .ok_or_else(|| "missing value for --expected-client-dir".to_string())?;
                    expected_client_dir = Some(PathBuf::from(val));
                }
                "--test-journal" => {
                    let val = iter
                        .next()
                        .ok_or_else(|| "missing value for --test-journal".to_string())?;
                    test_journal = Some(PathBuf::from(val));
                }
                unknown => {
                    return Err(format!("unknown option: {unknown}"));
                }
            }
        }

        let pipe_name = pipe_name.ok_or_else(|| "missing required argument: --pipe".to_string())?;

        Ok(Self {
            pipe_name,
            idle_timeout_secs,
            allow_unelevated_test,
            expected_client_dir,
            test_journal,
        })
    }
}

/// Maximum idle lifetime of the elevated helper (P4: 5-minute idle watchdog).
pub const MAX_ELEVATED_IDLE_TIMEOUT_SECS: u64 = 300;

/// When elevated, the watchdog can never be disabled (`0`) or extended beyond 5 minutes; the
/// unelevated test mode keeps the requested value.
pub fn effective_idle_timeout_secs(requested: u64, elevated: bool) -> u64 {
    if elevated {
        requested.clamp(1, MAX_ELEVATED_IDLE_TIMEOUT_SECS)
    } else {
        requested
    }
}

pub fn run_server(args: &HelperArgs) -> Result<()> {
    let elevated = is_elevated();
    if elevated
        && (args.allow_unelevated_test
            || args.expected_client_dir.is_some()
            || args.test_journal.is_some())
    {
        eprintln!(
            "dsk-helper refused to start: --allow-unelevated-test, --expected-client-dir and --test-journal are disallowed when running elevated"
        );
        std::process::exit(2);
    }

    if !args.allow_unelevated_test && !elevated {
        eprintln!("dsk-helper requires elevated administrator privileges");
        std::process::exit(2);
    }
    let idle_timeout_secs = effective_idle_timeout_secs(args.idle_timeout_secs, elevated);

    let default_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let expected_dir = args.expected_client_dir.as_ref().unwrap_or(&default_dir);

    if is_directory_user_writable(expected_dir) {
        eprintln!(
            "warning: expected client directory '{}' allows write access to non-admin users",
            expected_dir.display()
        );
    }

    let last_activity = Arc::new(AtomicU64::new(current_epoch_ms()));
    let timeout_ms = idle_timeout_secs.saturating_mul(1000);
    let running = Arc::new(AtomicBool::new(true));
    // Set while a request is executing: long DISM / VolumeCaches / driver-store operations emit no
    // progress for many minutes and must never be killed mid-operation by the idle watchdog.
    let request_in_flight = Arc::new(AtomicBool::new(false));

    if idle_timeout_secs > 0 {
        let last_act_watchdog = Arc::clone(&last_activity);
        let running_watchdog = Arc::clone(&running);
        let in_flight_watchdog = Arc::clone(&request_in_flight);
        std::thread::spawn(move || {
            while running_watchdog.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                if in_flight_watchdog.load(Ordering::Acquire) {
                    continue;
                }
                let elapsed =
                    current_epoch_ms().saturating_sub(last_act_watchdog.load(Ordering::Relaxed));
                if elapsed >= timeout_ms {
                    std::process::exit(0);
                }
            }
        });
    }

    let mut server = NamedPipeServer::create_first_instance(&args.pipe_name)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let mut session_store = HelperSessionStore::new();

    while running.load(Ordering::Relaxed) {
        // Only verified clients refresh the idle timer; rejected or failed connections must not
        // keep the elevated helper alive.
        let _client_pid = match server.wait_for_verified_client(expected_dir) {
            Ok(pid) => pid,
            Err(DskError::HelperAuth(e)) => {
                eprintln!("rejected unverified helper client: {e}");
                continue;
            }
            Err(e) => {
                // e.g. a client that connected and vanished (ERROR_NO_DATA): reset the instance and
                // keep serving until the idle watchdog fires.
                eprintln!("wait_for_verified_client error: {e}");
                let _ = server.disconnect();
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        last_activity.store(current_epoch_ms(), Ordering::Relaxed);

        // Inner request-response loop
        loop {
            let req: HelperRequest = match read_frame(&mut server, MAX_CONTROL_FRAME_BYTES) {
                Ok(r) => r,
                Err(DskError::Io(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof
                        || e.raw_os_error() == Some(109) =>
                {
                    // Client disconnected (109 = ERROR_BROKEN_PIPE)
                    break;
                }
                Err(e) => {
                    eprintln!("read_frame error: {e}");
                    break;
                }
            };

            last_activity.store(current_epoch_ms(), Ordering::Relaxed);

            request_in_flight.store(true, Ordering::Release);
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_request(
                    &req,
                    &mut server,
                    &mut session_store,
                    &cancel,
                    &last_activity,
                    args.test_journal.as_deref(),
                )
            }));
            last_activity.store(current_epoch_ms(), Ordering::Relaxed);
            request_in_flight.store(false, Ordering::Release);

            match res {
                Ok(Ok(should_stop)) => {
                    if should_stop {
                        running.store(false, Ordering::Relaxed);
                        return Ok(());
                    }
                }
                Ok(Err(err)) => {
                    let kind = match &err {
                        DskError::Cancelled => "cancelled",
                        _ => "execution_error",
                    };
                    let resp = HelperResponse::Error {
                        kind: kind.to_string(),
                        message: err.to_string(),
                    };
                    let _ = write_frame(&mut server, &resp, MAX_CONTROL_FRAME_BYTES);
                }
                Err(panic_payload) => {
                    let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    let resp = HelperResponse::Error {
                        kind: "panic".to_string(),
                        message: panic_msg,
                    };
                    let _ = write_frame(&mut server, &resp, MAX_CONTROL_FRAME_BYTES);
                }
            }
        }

        let _ = server.disconnect();
    }

    Ok(())
}

fn handle_request(
    req: &HelperRequest,
    server: &mut NamedPipeServer,
    session_store: &mut HelperSessionStore,
    cancel: &AtomicBool,
    last_activity: &AtomicU64,
    journal_override: Option<&Path>,
) -> Result<bool> {
    match req {
        HelperRequest::Ping => {
            let resp = HelperResponse::Pong {
                helper_pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            };
            write_frame(server, &resp, MAX_CONTROL_FRAME_BYTES)?;
            Ok(false)
        }

        HelperRequest::ScanVolume {
            volume_root,
            method,
        } => {
            let report = {
                let server_mutex = std::sync::Mutex::new(server);
                let scan_progress = |p: Progress| {
                    last_activity.store(current_epoch_ms(), Ordering::Relaxed);
                    let resp = HelperResponse::ScanProgress {
                        phase: p.phase,
                        done: p.done,
                        total: p.total,
                    };
                    if let Ok(mut s) = server_mutex.lock() {
                        let _ = write_frame(&mut *s, &resp, MAX_CONTROL_FRAME_BYTES);
                    }
                };

                let opts = ScanOptions {
                    method: *method,
                    threads: None,
                    // §10.1: the helper acts only on its own fresh scan. `.dsi` snapshots live in
                    // the user-writable %LOCALAPPDATA% (forgeable, junction-redirectable writes).
                    use_cache: false,
                };
                let report = Arc::new(scan_volume(
                    Path::new(volume_root),
                    &opts,
                    &scan_progress,
                    cancel,
                )?);

                let mut report_bytes = Vec::new();
                encode_scan_report(&report, &mut report_bytes)?;

                let resp = HelperResponse::ScanComplete { report_bytes };
                if let Ok(mut s) = server_mutex.lock() {
                    write_frame(&mut *s, &resp, MAX_STREAM_FRAME_BYTES)?;
                }
                report
            };
            session_store.set_last_scan(volume_root.clone(), report);
            Ok(false)
        }

        HelperRequest::BuildPlan {
            volume_root,
            max_tier,
            include_recycle_bin,
        } => {
            let report = if let Some(cached) = session_store.get_last_scan(volume_root) {
                cached
            } else {
                let opts = ScanOptions {
                    method: ScanMethod::Auto,
                    threads: None,
                    // §10.1: the helper acts only on its own fresh scan. `.dsi` snapshots live in
                    // the user-writable %LOCALAPPDATA% (forgeable, junction-redirectable writes).
                    use_cache: false,
                };
                let scanned =
                    Arc::new(scan_volume(Path::new(volume_root), &opts, &|_| {}, cancel)?);
                session_store.set_last_scan(volume_root.clone(), Arc::clone(&scanned));
                scanned
            };

            let plan_opts = PlanOptions {
                tier_max: *max_tier,
                include_recycle_bin: *include_recycle_bin,
                include_os_handlers: true,
                rule_filter: Vec::new(),
                now_min2000: None,
            };

            let mut plan = {
                let _imp_guard = server.impersonate_client()?;
                let rules = builtin_rules()?;
                let deny_ctx = DenyContext::default();
                let env_lookup = |var: &str| env::var(var).ok();

                build_plan_from_index(
                    &report.index,
                    report.method_used,
                    Path::new(volume_root),
                    &rules,
                    &deny_ctx,
                    &plan_opts,
                    &env_lookup,
                )
            };

            // Client impersonation guard dropped above before COM OS handler estimation.
            enrich_os_handler_estimates(&mut plan, cancel);

            let preconditions = probe_preconditions();
            let plan_id = session_store.insert_plan(plan.clone());

            let resp = HelperResponse::PlanBuilt {
                plan_id,
                plan,
                preconditions: (&preconditions).into(),
            };
            write_frame(server, &resp, MAX_STREAM_FRAME_BYTES)?;
            Ok(false)
        }

        HelperRequest::ExecutePlanRules {
            plan_id,
            rule_ids,
            dry_run,
            force_battery,
        } => {
            let active_plan = session_store.validate_execution_rules(plan_id, rule_ids)?;
            let deny_ctx = DenyContext::default();

            let impersonator = server.impersonator();
            let server_mutex = std::sync::Mutex::new(server);
            let clean_progress = |p: CleanProgress| {
                last_activity.store(current_epoch_ms(), Ordering::Relaxed);
                if let Ok(mut s) = server_mutex.lock() {
                    let _ = write_frame(
                        &mut *s,
                        &HelperResponse::CleanProgress(p),
                        MAX_CONTROL_FRAME_BYTES,
                    );
                }
            };

            let exec_opts = ExecuteOptions {
                dry_run: *dry_run,
                force_battery: *force_battery,
                journal_path: journal_override.map(Path::to_path_buf),
            };

            let clean_report = execute_plan_with_impersonation(
                &active_plan,
                &exec_opts,
                &deny_ctx,
                Some(&impersonator),
                &clean_progress,
                cancel,
            )?;

            let resp = HelperResponse::CleanComplete(clean_report);
            if let Ok(mut s) = server_mutex.lock() {
                write_frame(&mut *s, &resp, MAX_STREAM_FRAME_BYTES)?;
            }
            Ok(false)
        }

        HelperRequest::RunOptimizer { intent, dry_run } => {
            // §10.1: intent only. The client names a fixed operation with scalar parameters;
            // `run_optimizer_intent` re-validates them and runs pinned System32 tools with fixed
            // argument templates under the helper's own (admin) token. No client path or string
            // reaches a command line, so nothing here needs client impersonation.
            let message = run_optimizer_intent(intent, *dry_run)?;
            write_frame(
                server,
                &HelperResponse::OptimizerComplete { message },
                MAX_CONTROL_FRAME_BYTES,
            )?;
            Ok(false)
        }

        HelperRequest::Shutdown => {
            let resp = HelperResponse::ShuttingDown;
            let _ = write_frame(server, &resp, MAX_CONTROL_FRAME_BYTES);
            Ok(true)
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let parsed = match HelperArgs::parse(args) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("dsk-helper error: {err}");
            std::process::exit(2);
        }
    };

    if let Err(e) = run_server(&parsed) {
        eprintln!("dsk-helper server error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_helper_args_pipe_name_and_idle_timeout() {
        let args = vec![
            "dsk-helper.exe".to_string(),
            "--pipe".to_string(),
            r"\\.\pipe\DiskSaverHelper_Test".to_string(),
            "--idle-timeout-secs".to_string(),
            "60".to_string(),
            "--allow-unelevated-test".to_string(),
            "--expected-client-dir".to_string(),
            r"C:\bin".to_string(),
        ];
        let parsed = HelperArgs::parse(args).expect("valid args");
        assert_eq!(parsed.pipe_name, r"\\.\pipe\DiskSaverHelper_Test");
        assert_eq!(parsed.idle_timeout_secs, 60);
        assert!(parsed.allow_unelevated_test);
        assert_eq!(parsed.expected_client_dir, Some(PathBuf::from(r"C:\bin")));

        // Missing --pipe
        let bad_args = vec!["dsk-helper.exe".to_string()];
        assert!(HelperArgs::parse(bad_args).is_err());

        // Invalid timeout
        let bad_timeout = vec![
            "dsk-helper.exe".to_string(),
            "--pipe".to_string(),
            "pipe1".to_string(),
            "--idle-timeout-secs".to_string(),
            "not_a_num".to_string(),
        ];
        assert!(HelperArgs::parse(bad_timeout).is_err());
    }

    #[test]
    fn elevated_idle_timeout_is_clamped_and_never_disabled() {
        assert_eq!(effective_idle_timeout_secs(0, true), 1);
        assert_eq!(effective_idle_timeout_secs(60, true), 60);
        assert_eq!(
            effective_idle_timeout_secs(86_400, true),
            MAX_ELEVATED_IDLE_TIMEOUT_SECS
        );
        // Unelevated test mode keeps the requested value (0 disables the watchdog in tests).
        assert_eq!(effective_idle_timeout_secs(0, false), 0);
        assert_eq!(effective_idle_timeout_secs(900, false), 900);
    }
}
