#![forbid(unsafe_code)]

//! Oversized recordings (P9.8): screen and game captures recorded at very high bitrates. Shown
//! as owner decisions: move them, or shrink them with the verified re-encode in
//! [`crate::video`] (P9.11), which only runs when the owner selects the files.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::index::{Index, NodeFlags, ROOT};

const VIDEO_EXTS: &[&str] = &[
    "mp4", "mkv", "mov", "avi", "wmv", "webm", "m4v", "ts", "mts", "flv",
];

/// Target bitrate the size estimate assumes after a re-encode (good-quality 1080p HEVC/AV1).
pub const REENCODE_TARGET_MBPS: f64 = 10.0;

/// One oversized recording.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecordingFinding {
    pub path: PathBuf,
    pub bytes: u64,
    pub duration_secs: f64,
    pub bitrate_mbps: f64,
    /// Approximate size after re-encoding at [`REENCODE_TARGET_MBPS`].
    pub reencoded_bytes: u64,
}

/// Report.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RecordingsReport {
    pub findings: Vec<RecordingFinding>,
    /// Bytes a re-encode would save across all findings.
    pub potential_savings: u64,
}

/// Bitrate in Mbit/s.
pub fn bitrate_mbps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    bytes as f64 * 8.0 / secs / 1_000_000.0
}

/// Classifies one recording: oversized when the bitrate is at least `min_mbps`.
pub fn classify_recording(
    path: PathBuf,
    bytes: u64,
    secs: f64,
    min_mbps: f64,
) -> Option<RecordingFinding> {
    let mbps = bitrate_mbps(bytes, secs);
    if mbps < min_mbps {
        return None;
    }
    let reencoded = (secs * REENCODE_TARGET_MBPS * 1_000_000.0 / 8.0) as u64;
    Some(RecordingFinding {
        path,
        bytes,
        duration_secs: secs,
        bitrate_mbps: mbps,
        reencoded_bytes: reencoded.min(bytes),
    })
}

/// Finds video files of at least `min_bytes` whose bitrate is at least `min_mbps`. Durations come
/// from `duration` (the Shell property system in production); cloud placeholders are skipped so
/// nothing is downloaded.
pub fn scan_recordings(
    index: &Index,
    min_bytes: u64,
    min_mbps: f64,
    duration: &dyn Fn(&std::path::Path) -> Option<f64>,
) -> RecordingsReport {
    let mut findings = Vec::new();
    let mut stack = vec![ROOT];
    while let Some(dir) = stack.pop() {
        for c in index.children(dir) {
            let f = index.flags(c);
            if f.intersects(
                NodeFlags::REPARSE | NodeFlags::CLOUD | NodeFlags::OFFLINE | NodeFlags::SYSTEM,
            ) {
                continue;
            }
            if f.contains(NodeFlags::DIR) {
                stack.push(c);
                continue;
            }
            let bytes = index.allocated(c);
            if bytes < min_bytes {
                continue;
            }
            let name = index.name(c).to_ascii_lowercase();
            let is_video = name
                .rsplit_once('.')
                .is_some_and(|(_, e)| VIDEO_EXTS.contains(&e));
            if !is_video {
                continue;
            }
            let path = index.path(c);
            if let Some(secs) = duration(&path)
                && let Some(fnd) = classify_recording(path, bytes, secs, min_mbps)
            {
                findings.push(fnd);
            }
        }
    }
    findings.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    let potential_savings = findings
        .iter()
        .map(|f| f.bytes.saturating_sub(f.reencoded_bytes))
        .fold(0u64, u64::saturating_add);
    RecordingsReport {
        findings,
        potential_savings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitrate_and_reencode_estimate() {
        // 58.6 GiB in 2 h = ~70 Mbit/s → ~9 GB at 10 Mbit/s.
        let bytes = (58.6 * (1u64 << 30) as f64) as u64;
        let f = classify_recording(PathBuf::from("rec.mp4"), bytes, 7200.0, 40.0).unwrap();
        assert!((69.0..71.0).contains(&f.bitrate_mbps), "{}", f.bitrate_mbps);
        assert_eq!(f.reencoded_bytes, 9_000_000_000);
        // A normal 1080p movie at 8 Mbit/s is not flagged.
        assert!(classify_recording(PathBuf::from("m.mkv"), 7_200_000_000, 7200.0, 40.0).is_none());
        assert_eq!(bitrate_mbps(1, 0.0), 0.0);
    }
}
