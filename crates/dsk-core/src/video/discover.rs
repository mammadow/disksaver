#![forbid(unsafe_code)]

//! Finding videos worth compressing (P9.11) and estimating the compressed size.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use super::ffmpeg::{AudioStreamInfo, FfmpegTools, ProbeInfo, probe};
use super::{HOLDING_FOLDER, Quality, TargetCodec, is_video_name};
use crate::clean::ActionJournal;
use crate::clean::deny::{is_under_root, normalize_win_path_str};
use crate::index::{Index, NodeFlags, ROOT};

/// Marker in the name of DiskSaver's in-progress output files.
pub const TEMP_MARKER: &str = ".dsk-tmp.";

/// A video file found on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoFile {
    pub path: PathBuf,
    /// Bytes on disk.
    pub bytes: u64,
    /// Last write, minutes since 2000 (0 = unknown).
    pub mtime_min2000: u32,
}

/// Discovery settings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoverOptions {
    /// Ignore files smaller than this.
    pub min_bytes: u64,
    /// Only list files that would shrink by at least this fraction...
    pub min_saving_ratio: f64,
    /// ...and at least this many bytes.
    pub min_saving_bytes: u64,
    /// Files written more recently than this may still be recording or editing.
    pub min_age_hours: u32,
    pub codec: TargetCodec,
    pub quality: Quality,
    /// Installed app and game folders: their videos belong to the app, not the owner.
    pub exclude_roots: Vec<PathBuf>,
    /// Parallel ffprobe processes.
    pub threads: usize,
    /// Fixed "now" for tests.
    pub now_min2000: Option<u32>,
    /// Measured/estimated size ratio from earlier compressions (journal calibration).
    pub calibration: Option<f64>,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            min_bytes: 200 << 20,
            min_saving_ratio: 0.25,
            min_saving_bytes: 32 << 20,
            min_age_hours: 24,
            codec: TargetCodec::Av1,
            quality: Quality::Balanced,
            exclude_roots: Vec::new(),
            threads: 4,
            now_min2000: None,
            calibration: None,
        }
    }
}

/// Why a video is listed but not offered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum SkipReason {
    /// Re-encoding would not save enough.
    AlreadyEfficient,
    /// DiskSaver already compressed it.
    AlreadyCompressed,
    /// Dolby Vision dynamic metadata would be lost.
    DolbyVision,
    NoVideo,
    /// Written within the last day (may still be recording or being edited).
    RecentlyModified,
    ProbeFailed(String),
    /// ffmpeg is not installed, so the file could not be inspected.
    NoTools,
    /// Another file has the same size and length. Compressing either copy would make them
    /// differ, so the duplicate finder could no longer pair them: remove the copies first.
    LikelyDuplicate(PathBuf),
}

impl SkipReason {
    pub fn label(&self) -> String {
        match self {
            Self::AlreadyEfficient => "already efficiently encoded".into(),
            Self::AlreadyCompressed => "already compressed by DiskSaver".into(),
            Self::DolbyVision => "Dolby Vision (its dynamic metadata would be lost)".into(),
            Self::NoVideo => "no video stream".into(),
            Self::RecentlyModified => "changed in the last day (may still be in use)".into(),
            Self::ProbeFailed(e) => format!("could not be read: {e}"),
            Self::NoTools => "ffmpeg is not installed".into(),
            Self::LikelyDuplicate(p) => format!(
                "identical copy of {}: remove duplicates first (disksaver dupes)",
                p.display()
            ),
        }
    }
}

/// One video with its probe result and estimate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VideoCandidate {
    pub path: PathBuf,
    pub bytes: u64,
    pub info: Option<ProbeInfo>,
    /// Estimated size after compression (`bytes` when unknown).
    pub est_output_bytes: u64,
    pub skip: Option<SkipReason>,
}

impl VideoCandidate {
    pub fn est_saving_bytes(&self) -> u64 {
        self.bytes.saturating_sub(self.est_output_bytes)
    }

    pub fn duration_secs(&self) -> f64 {
        self.info.as_ref().map(|i| i.duration_secs).unwrap_or(0.0)
    }

    /// Overall bitrate in Mbit/s.
    pub fn bitrate_mbps(&self) -> f64 {
        let d = self.duration_secs();
        if d > 0.0 {
            self.bytes as f64 * 8.0 / d / 1e6
        } else {
            0.0
        }
    }

    /// `h264 1920x1080@30` style description.
    pub fn video_summary(&self) -> String {
        match self.info.as_ref().and_then(|i| i.video.as_ref()) {
            Some(v) => format!("{} {}x{}@{:.0}", v.codec, v.width, v.height, v.fps),
            None => "-".into(),
        }
    }
}

/// Discovery result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VideoDiscovery {
    /// Worth compressing, biggest saving first.
    pub candidates: Vec<VideoCandidate>,
    /// Listed with the reason they are not offered.
    pub skipped: Vec<VideoCandidate>,
    pub total_video_bytes: u64,
    pub est_saving_bytes: u64,
    /// Videos inside app, game, and system folders that were left out.
    pub excluded_app_files: usize,
}

/// Folders whose videos belong to Windows or an app (checked on the upper-cased path).
fn excluded_location(norm: &str) -> bool {
    let after_drive = norm.get(2..).unwrap_or("");
    const ROOT_PREFIXES: &[&str] = &[r"\WINDOWS\", r"\PROGRAM FILES", r"\PROGRAMDATA\"];
    const ANYWHERE: &[&str] = &[
        r"\APPDATA\",
        r"\STEAMAPPS\",
        r"\$RECYCLE.BIN\",
        r"\NODE_MODULES\",
        r"\.GIT\",
        r"\SYSTEM VOLUME INFORMATION\",
    ];
    ROOT_PREFIXES.iter().any(|p| after_drive.starts_with(p))
        || ANYWHERE.iter().any(|p| norm.contains(p))
        || norm.contains(&format!(r"\{}\", HOLDING_FOLDER.to_ascii_uppercase()))
}

/// `true` when `path` should never be offered (system, app, game, or holding folders).
pub fn is_excluded_path(path: &Path, exclude_roots: &[PathBuf]) -> bool {
    excluded_location(&normalize_win_path_str(path))
        || exclude_roots.iter().any(|r| is_under_root(path, r))
}

/// Install folders of registered apps and detected games on `index`'s volume: their videos
/// (intros, cutscenes, tutorials) belong to the app, so discovery leaves them out.
pub fn app_and_game_roots(index: &Index) -> Vec<PathBuf> {
    let pf = normalize_win_path_str(&crate::win::volume::program_files_dir());
    let pf86 = normalize_win_path_str(&crate::win::volume::program_files_x86_dir());
    let home = std::env::var_os("USERPROFILE").map(|h| normalize_win_path_str(Path::new(&h)));
    let mut out: Vec<PathBuf> = crate::win::prefetch::enumerate_installed_apps()
        .into_iter()
        .filter_map(|a| a.install_location)
        .filter(|loc| {
            let n = normalize_win_path_str(loc);
            loc.components().count() >= 3
                && n != pf
                && n != pf86
                && home.as_deref() != Some(n.as_str())
                && index.find_by_path(loc).is_some()
        })
        .collect();
    out.extend(
        crate::insights::gaming::scan_gaming_libraries(index)
            .games
            .into_iter()
            .map(|g| g.install_path),
    );
    out
}

/// Video files of at least `opts.min_bytes` in `index`, outside system/app/game folders. Returns
/// the files and how many were left out because of their location.
pub fn collect_video_files(index: &Index, opts: &DiscoverOptions) -> (Vec<VideoFile>, usize) {
    let mut out = Vec::new();
    let mut excluded = 0usize;
    let mut stack = vec![ROOT];
    while let Some(dir) = stack.pop() {
        for c in index.children(dir) {
            let f = index.flags(c);
            if f.intersects(NodeFlags::REPARSE | NodeFlags::SYSTEM) {
                continue;
            }
            if f.contains(NodeFlags::DIR) {
                stack.push(c);
                continue;
            }
            if f.intersects(NodeFlags::CLOUD | NodeFlags::OFFLINE) {
                continue;
            }
            let bytes = index.allocated(c);
            if bytes < opts.min_bytes {
                continue;
            }
            let name = index.name(c);
            if !is_video_name(&name) || name.contains(TEMP_MARKER) {
                continue;
            }
            let path = index.path(c);
            if is_excluded_path(&path, &opts.exclude_roots) {
                excluded += 1;
                continue;
            }
            out.push(VideoFile {
                path,
                bytes,
                mtime_min2000: index.mtime_min(c),
            });
        }
    }
    (out, excluded)
}

/// Audio bitrate kept in the output: copied streams keep theirs; streams that must be re-encoded
/// (PCM, WMA, ...) become 192 kbit/s AAC.
pub(crate) fn kept_audio_bitrate(a: &AudioStreamInfo) -> u64 {
    if super::compress::audio_needs_reencode(&a.codec, "mp4") {
        192_000
    } else if a.bit_rate > 0 {
        a.bit_rate
    } else {
        192_000
    }
}

/// Estimated output size for `info` at `codec` / `quality`. Deliberately conservative: measured
/// results are usually smaller (screen recordings much smaller), and the journal calibrates it.
pub fn estimate_output_bytes(info: &ProbeInfo, codec: TargetCodec, quality: Quality) -> u64 {
    let size = if info.size_bytes > 0 {
        info.size_bytes
    } else {
        u64::MAX
    };
    let (Some(v), true) = (&info.video, info.duration_secs > 0.0) else {
        return info.size_bytes;
    };
    let src_v = info.video_bitrate() as f64;
    if src_v <= 0.0 {
        return info.size_bytes;
    }
    let factor = match v.codec.as_str() {
        "h264" => 0.33,
        "hevc" => 0.62,
        "vp9" => 0.7,
        "av1" => 0.95,
        "vp8" => 0.45,
        "mpeg2video" | "mpeg4" | "msmpeg4v2" | "msmpeg4v3" | "wmv1" | "wmv2" | "wmv3" | "vc1"
        | "mjpeg" | "h263" | "flv1" | "prores" | "dnxhd" | "rawvideo" | "huffyuv" | "ffv1"
        | "utvideo" | "cfhd" => 0.2,
        _ => 0.4,
    };
    let pixels = (u64::from(v.width) * u64::from(v.height)).max(1) as f64;
    let fps = if v.fps > 0.0 {
        v.fps.clamp(1.0, 240.0)
    } else {
        30.0
    };
    // Balanced AV1 needs about 6 Mbit/s for demanding 1080p30 content.
    let cap = 6.0e6 * (pixels / 2_073_600.0).powf(0.85) * (fps / 30.0).powf(0.6);
    let mut out_v = (src_v * factor).min(cap) * quality.size_factor();
    if codec == TargetCodec::Hevc {
        out_v *= 1.3;
    }
    let out_v = out_v.min(src_v).max(150_000.0);
    let audio: u64 = info.audio.iter().map(kept_audio_bitrate).sum();
    let bytes = (out_v + audio as f64) / 8.0 * info.duration_secs * 1.005;
    (bytes as u64).min(size)
}

fn classify(
    f: VideoFile,
    tools: Option<&FfmpegTools>,
    opts: &DiscoverOptions,
    now: u32,
) -> VideoCandidate {
    let mut c = VideoCandidate {
        path: f.path,
        bytes: f.bytes,
        info: None,
        est_output_bytes: f.bytes,
        skip: None,
    };
    if f.mtime_min2000 > 0
        && now.saturating_sub(f.mtime_min2000) < opts.min_age_hours.saturating_mul(60)
    {
        c.skip = Some(SkipReason::RecentlyModified);
        return c;
    }
    let Some(tools) = tools else {
        c.skip = Some(SkipReason::NoTools);
        return c;
    };
    let info = match probe(tools, &c.path) {
        Ok(i) => i,
        Err(e) => {
            c.skip = Some(SkipReason::ProbeFailed(e.to_string()));
            return c;
        }
    };
    if info.is_disksaver_output() {
        c.skip = Some(SkipReason::AlreadyCompressed);
    } else if info.video.is_none() {
        c.skip = Some(SkipReason::NoVideo);
    } else if info.video.as_ref().is_some_and(|v| v.dolby_vision) {
        c.skip = Some(SkipReason::DolbyVision);
    } else {
        let mut info_sized = info.clone();
        if info_sized.size_bytes == 0 {
            info_sized.size_bytes = c.bytes;
        }
        let est = estimate_output_bytes(&info_sized, opts.codec, opts.quality) as f64
            * opts.calibration.unwrap_or(1.0);
        c.est_output_bytes = (est as u64).min(c.bytes);
        let saving = c.est_saving_bytes();
        if saving < opts.min_saving_bytes
            || (saving as f64) < c.bytes as f64 * opts.min_saving_ratio
        {
            c.skip = Some(SkipReason::AlreadyEfficient);
        }
    }
    c.info = Some(info);
    c
}

/// Holds back candidates that have a twin with the same size and length (to the millisecond):
/// for multi-gigabyte videos that is almost always a copy. Each is pointed at its twin.
pub fn mark_likely_duplicates(cands: &mut [VideoCandidate]) {
    let mut groups: std::collections::HashMap<(u64, i64), Vec<usize>> = Default::default();
    for (i, c) in cands.iter().enumerate() {
        if c.skip.is_none() && c.info.is_some() {
            let key = (c.bytes, (c.duration_secs() * 1000.0).round() as i64);
            groups.entry(key).or_default().push(i);
        }
    }
    for idxs in groups.values().filter(|v| v.len() > 1) {
        let paths: Vec<PathBuf> = idxs.iter().map(|&i| cands[i].path.clone()).collect();
        for (k, &i) in idxs.iter().enumerate() {
            let twin = paths[(k + 1) % paths.len()].clone();
            cands[i].skip = Some(SkipReason::LikelyDuplicate(twin));
        }
    }
}

/// Probes `files` (in parallel) and sorts them into candidates and skipped files. Files the
/// journal records as DiskSaver output are skipped without probing. `progress(done, total)`.
pub fn discover_videos(
    files: Vec<VideoFile>,
    tools: Option<&FfmpegTools>,
    opts: &DiscoverOptions,
    journal: Option<&ActionJournal>,
    progress: &(dyn Fn(usize, usize) + Sync),
    cancel: &AtomicBool,
) -> VideoDiscovery {
    let now = opts
        .now_min2000
        .unwrap_or_else(crate::insights::current_min2000);
    let mut out = VideoDiscovery {
        total_video_bytes: files.iter().map(|f| f.bytes).sum(),
        ..Default::default()
    };
    let (known, files): (Vec<VideoFile>, Vec<VideoFile>) = files.into_iter().partition(|f| {
        journal.is_some_and(|j| j.video_job_for_output(&f.path).ok().flatten().is_some())
    });
    for f in known {
        out.skipped.push(VideoCandidate {
            est_output_bytes: f.bytes,
            path: f.path,
            bytes: f.bytes,
            info: None,
            skip: Some(SkipReason::AlreadyCompressed),
        });
    }
    let total = files.len();
    let done = AtomicUsize::new(0);
    let work = || {
        files
            .into_par_iter()
            .filter_map(|f| {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let c = classify(f, tools, opts, now);
                progress(done.fetch_add(1, Ordering::Relaxed) + 1, total);
                Some(c)
            })
            .collect::<Vec<_>>()
    };
    let results = match rayon::ThreadPoolBuilder::new()
        .num_threads(opts.threads.clamp(1, 16))
        .build()
    {
        Ok(pool) => pool.install(work),
        Err(_) => work(),
    };
    let mut results = results;
    mark_likely_duplicates(&mut results);
    for c in results {
        if c.skip.is_some() {
            out.skipped.push(c);
        } else {
            out.candidates.push(c);
        }
    }
    out.candidates
        .sort_by_key(|c| std::cmp::Reverse(c.est_saving_bytes()));
    out.skipped.sort_by_key(|c| std::cmp::Reverse(c.bytes));
    out.est_saving_bytes = out
        .candidates
        .iter()
        .map(VideoCandidate::est_saving_bytes)
        .sum();
    out
}
