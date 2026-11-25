//! Inter-process communication protocol and framing helpers for elevated helper daemon.

#![forbid(unsafe_code)]

pub mod client;
pub mod protocol;

pub use client::{
    connect_or_launch_helper, helper_build_plan, helper_execute_plan_rules, helper_run_optimizer,
    helper_scan_volume,
};
pub use protocol::{
    HelperRequest, HelperResponse, HelperSessionStore, MAX_CONTROL_FRAME_BYTES,
    MAX_STREAM_FRAME_BYTES, SystemPreconditionsDto, read_frame, write_frame,
};
