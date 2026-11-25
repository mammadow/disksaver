//! Safe `#![forbid(unsafe_code)]` client helpers for communicating with `dsk-helper.exe`.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::clean::executor::{CleanProgress, CleanReport};
use crate::clean::plan::CleanPlan;
use crate::clean::rules::RuleTier;
use crate::error::{DskError, Result};
use crate::index::decode_scan_report;
use crate::ipc::protocol::{
    HelperRequest, HelperResponse, MAX_CONTROL_FRAME_BYTES, MAX_STREAM_FRAME_BYTES, read_frame,
    write_frame,
};
use crate::ntfs::Progress;
use crate::optimize::intent::OptimizerIntent;
use crate::scan::{ScanMethod, ScanReport};
use crate::win::pipe::{NamedPipeClient, default_pipe_name, launch_elevated_helper};
use crate::win::preconditions::SystemPreconditions;

fn map_helper_error(kind: String, message: String) -> DskError {
    if kind.eq_ignore_ascii_case("cancelled") {
        DskError::Cancelled
    } else if kind.eq_ignore_ascii_case("not_elevated") {
        DskError::NotElevated
    } else if kind.eq_ignore_ascii_case("helper_auth") {
        DskError::HelperAuth(message)
    } else {
        DskError::Ipc(format!("{kind}: {message}"))
    }
}

/// The helper only ever accepts clients whose image lives in its own directory (§10.3), so only a
/// sibling `dsk-helper.exe` is ever launched (never one from a parent directory).
fn locate_helper_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| DskError::Ipc("current executable has no parent directory".to_string()))?;
    Ok(exe_dir.join("dsk-helper.exe"))
}

/// Rejects a helper built from a different release (protocol drift).
fn check_helper_version(version: &str) -> Result<()> {
    if version == env!("CARGO_PKG_VERSION") {
        Ok(())
    } else {
        Err(DskError::Ipc(format!(
            "helper version '{version}' does not match client version '{}'",
            env!("CARGO_PKG_VERSION")
        )))
    }
}

/// Connects to an already-running elevated `dsk-helper.exe` pipe instance or launches it
/// via UAC (`ShellExecuteExW(runas)`), then verifies the connection with `Ping` -> `Pong`.
pub fn connect_or_launch_helper(timeout: Duration) -> Result<NamedPipeClient> {
    let pipe_name = default_pipe_name()?;
    let mut client = match NamedPipeClient::connect(&pipe_name, Duration::from_millis(300)) {
        Ok(c) => c,
        Err(_) => {
            let helper_exe = locate_helper_exe()?;
            if !helper_exe.is_file() {
                return Err(DskError::Ipc(format!(
                    "elevated helper executable not found: {}",
                    helper_exe.display()
                )));
            }
            launch_elevated_helper(&helper_exe, &pipe_name)?;
            NamedPipeClient::connect(&pipe_name, timeout)?
        }
    };

    write_frame(&mut client, &HelperRequest::Ping, MAX_CONTROL_FRAME_BYTES)?;
    match read_frame::<_, HelperResponse>(&mut client, MAX_CONTROL_FRAME_BYTES)? {
        HelperResponse::Pong { version, .. } => {
            check_helper_version(&version)?;
            Ok(client)
        }
        HelperResponse::Error { kind, message } => Err(map_helper_error(kind, message)),
        other => Err(DskError::Ipc(format!(
            "unexpected helper handshake response (expected Pong): {other:?}"
        ))),
    }
}

/// Delegates a volume scan to the connected elevated helper, streaming progress callbacks and
/// decoding the compressed `ScanReport`.
pub fn helper_scan_volume(
    client: &mut NamedPipeClient,
    volume_root: &str,
    method: ScanMethod,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: &AtomicBool,
) -> Result<ScanReport> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    write_frame(
        client,
        &HelperRequest::ScanVolume {
            volume_root: volume_root.to_string(),
            method,
        },
        MAX_CONTROL_FRAME_BYTES,
    )?;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }

        match read_frame::<_, HelperResponse>(client, MAX_STREAM_FRAME_BYTES)? {
            HelperResponse::ScanProgress { phase, done, total } => {
                progress(Progress { phase, done, total });
            }
            HelperResponse::ScanComplete { report_bytes } => {
                return decode_scan_report(&mut report_bytes.as_slice());
            }
            HelperResponse::Error { kind, message } => return Err(map_helper_error(kind, message)),
            other => {
                return Err(DskError::Ipc(format!(
                    "unexpected response during helper scan: {other:?}"
                )));
            }
        }
    }
}

/// Requests that the connected elevated helper build (and session-pin) a `CleanPlan`.
pub fn helper_build_plan(
    client: &mut NamedPipeClient,
    volume_root: &str,
    max_tier: RuleTier,
    include_recycle_bin: bool,
) -> Result<(String, CleanPlan, SystemPreconditions)> {
    write_frame(
        client,
        &HelperRequest::BuildPlan {
            volume_root: volume_root.to_string(),
            max_tier,
            include_recycle_bin,
        },
        MAX_CONTROL_FRAME_BYTES,
    )?;

    match read_frame::<_, HelperResponse>(client, MAX_STREAM_FRAME_BYTES)? {
        HelperResponse::PlanBuilt {
            plan_id,
            plan,
            preconditions,
        } => Ok((plan_id, plan, SystemPreconditions::from(preconditions))),
        HelperResponse::Error { kind, message } => Err(map_helper_error(kind, message)),
        other => Err(DskError::Ipc(format!(
            "unexpected response during helper plan build: {other:?}"
        ))),
    }
}

/// Executes specific rules from a session-pinned `plan_id` inside the connected elevated helper.
pub fn helper_execute_plan_rules(
    client: &mut NamedPipeClient,
    plan_id: &str,
    rule_ids: &[String],
    dry_run: bool,
    force_battery: bool,
    progress: &(dyn Fn(CleanProgress) + Sync),
) -> Result<CleanReport> {
    write_frame(
        client,
        &HelperRequest::ExecutePlanRules {
            plan_id: plan_id.to_string(),
            rule_ids: rule_ids.to_vec(),
            dry_run,
            force_battery,
        },
        MAX_CONTROL_FRAME_BYTES,
    )?;

    loop {
        match read_frame::<_, HelperResponse>(client, MAX_STREAM_FRAME_BYTES)? {
            HelperResponse::CleanProgress(p) => progress(p),
            HelperResponse::CleanComplete(report) => return Ok(report),
            HelperResponse::Error { kind, message } => return Err(map_helper_error(kind, message)),
            other => {
                return Err(DskError::Ipc(format!(
                    "unexpected response during helper execution: {other:?}"
                )));
            }
        }
    }
}

/// Runs an intent-only administrator optimizer (§10.1) through the elevated helper and returns
/// its status message. The helper re-validates the intent and only ever runs pinned `System32`
/// tools with fixed argument templates.
pub fn helper_run_optimizer(
    client: &mut NamedPipeClient,
    intent: &OptimizerIntent,
    dry_run: bool,
) -> Result<String> {
    intent.validate()?;
    write_frame(
        client,
        &HelperRequest::RunOptimizer {
            intent: intent.clone(),
            dry_run,
        },
        MAX_CONTROL_FRAME_BYTES,
    )?;
    match read_frame::<_, HelperResponse>(client, MAX_CONTROL_FRAME_BYTES)? {
        HelperResponse::OptimizerComplete { message } => Ok(message),
        HelperResponse::Error { kind, message } => Err(map_helper_error(kind, message)),
        other => Err(DskError::Ipc(format!(
            "unexpected response to RunOptimizer: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_is_only_located_as_a_sibling_executable() {
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(locate_helper_exe().unwrap(), exe_dir.join("dsk-helper.exe"));
    }

    #[test]
    fn helper_version_mismatch_is_rejected() {
        assert!(check_helper_version(env!("CARGO_PKG_VERSION")).is_ok());
        assert!(check_helper_version("0.0.0-other").is_err());
    }
}
