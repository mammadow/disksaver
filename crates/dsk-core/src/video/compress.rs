#![forbid(unsafe_code)]

//! Compressing videos (P9.11): encode next to the original, verify, then swap.
//!
//! Order of operations for one file:
//! 1. Refuse links, cloud placeholders, protected locations, files open for writing, files
//!    DiskSaver already produced, and Dolby Vision.
//! 2. Encode to `<name>.dsk-tmp.<ext>` in the same folder (same volume, so the swap is a rename).
//! 3. Verify the new file: video present, same number of audio streams, duration within 1 % (at
//!    least 1 s), meaningfully smaller, and quality over several segments at or above the gate.
//!    A miss retries once at the next higher quality, then gives up and keeps the original.
//! 4. Re-check that the original did not change while encoding, copy its timestamps onto the new
//!    file, then swap: when the name stays the same the original moves out first (Recycle Bin, or
//!    the holding folder when it is too big for the bin) and the new file takes its name; when the
//!    extension changes (`.MOV` -> `.mp4`) the new file is renamed into place first.
//! 5. Journal the job and calibrate future estimates.

use std::ffi::OsString;
use std::fs;
use std::os::windows::fs::{FileTimesExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::discover::{TEMP_MARKER, estimate_output_bytes};
use super::ffmpeg::{
    EncoderCaps, FfmpegTools, ProbeInfo, QualityMetric, Segment, choose_encoder, detect_encoders,
    has_filter, measure_quality, plan_segments, probe, run_ffmpeg, tool_version,
};
use super::{EncoderKind, EncoderPref, HOLDING_FOLDER, MARKER_TAG, Quality, TargetCodec};
use crate::clean::deny::{DenyContext, is_denied_for_owner_replacement, normalize_win_path_str};
use crate::clean::{ActionJournal, VideoJobRecord};
use crate::error::{DskError, Result};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const CLOUD_ATTRIBUTES: u32 = 0x1000 | 0x0004_0000 | 0x0040_0000;
const FILE_SHARE_READ: u32 = 0x1;
const ERROR_SHARING_VIOLATION: i32 = 32;

/// A located ffmpeg with the encoders that work on this machine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VideoEngine {
    pub tools: FfmpegTools,
    pub encoders: Vec<EncoderCaps>,
    pub metric: QualityMetric,
    pub version: Option<String>,
}

impl VideoEngine {
    /// Detects working encoders (a short test encode each) and the quality metric.
    pub fn new(tools: FfmpegTools) -> Self {
        let encoders = detect_encoders(&tools);
        let metric = if has_filter(&tools, "libvmaf") {
            QualityMetric::Vmaf
        } else {
            QualityMetric::Ssim
        };
        let version = tool_version(&tools);
        Self {
            tools,
            encoders,
            metric,
            version,
        }
    }

    /// Finds ffmpeg (see [`super::locate_tools`]) and builds the engine.
    pub fn locate(explicit: Option<&Path>) -> Option<Self> {
        super::locate_tools(explicit).map(Self::new)
    }

    pub fn encoder_for(&self, codec: TargetCodec, pref: EncoderPref) -> Option<EncoderCaps> {
        choose_encoder(&self.encoders, codec, pref)
    }
}

/// What happens to the original after a verified replacement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginalPolicy {
    /// Recycle Bin (space returns when the bin is emptied); originals too big for the bin go to
    /// the holding folder instead.
    #[default]
    Recycle,
    /// Always the `DiskSaver Originals` holding folder on the same volume.
    Hold,
    /// Keep both side by side (`name.av1.mp4` next to the original); frees nothing until the
    /// owner deletes one.
    KeepBoth,
}

/// Compression settings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressOptions {
    pub codec: TargetCodec,
    pub quality: Quality,
    pub encoder: EncoderPref,
    /// Minimum VMAF (mapped for SSIM) the new file must reach.
    pub min_vmaf: f64,
    /// The new file must be at least this much smaller.
    pub min_saving_ratio: f64,
    pub originals: OriginalPolicy,
    /// Keep encoding on battery power.
    pub allow_battery: bool,
    /// Wait while a full-screen game runs.
    pub wait_for_fullscreen: bool,
    /// Retry once at the next higher quality when the gate is missed.
    pub retry_higher_quality: bool,
    /// Journal database (`None`: do not journal).
    pub journal_path: Option<PathBuf>,
    /// Holding folder override (must be on the same volume as the videos; `None`: the default
    /// from [`holding_root_for`]).
    pub holding_root: Option<PathBuf>,
}

impl Default for CompressOptions {
    fn default() -> Self {
        Self {
            codec: TargetCodec::Av1,
            quality: Quality::Balanced,
            encoder: EncoderPref::Auto,
            min_vmaf: 93.0,
            min_saving_ratio: 0.15,
            originals: OriginalPolicy::Recycle,
            allow_battery: false,
            wait_for_fullscreen: true,
            retry_higher_quality: true,
            journal_path: None,
            holding_root: None,
        }
    }
}

/// Result of one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoJobStatus {
    /// The compressed file replaced the original.
    Replaced,
    /// Both files kept (by choice, or because the original could not be moved).
    KeptBoth,
    /// Re-encoding did not save enough; the original is untouched.
    NotSmaller,
    /// The new file missed the quality gate; the original is untouched.
    QualityTooLow,
    /// Another program has the file open for writing.
    InUse,
    /// Stopped because the machine switched to battery.
    OnBattery,
    AlreadyCompressed,
    Failed,
    Cancelled,
}

impl VideoJobStatus {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Replaced => "replaced",
            Self::KeptBoth => "kept_both",
            Self::NotSmaller => "not_smaller",
            Self::QualityTooLow => "quality_too_low",
            Self::InUse => "in_use",
            Self::OnBattery => "on_battery",
            Self::AlreadyCompressed => "already_compressed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Replaced => "replaced",
            Self::KeptBoth => "both kept",
            Self::NotSmaller => "not smaller, kept original",
            Self::QualityTooLow => "quality gate missed, kept original",
            Self::InUse => "in use, skipped",
            Self::OnBattery => "stopped on battery",
            Self::AlreadyCompressed => "already compressed",
            Self::Failed => "failed, kept original",
            Self::Cancelled => "cancelled, kept original",
        }
    }
}

/// Where the original went.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "path", rename_all = "snake_case")]
pub enum OriginalDisposition {
    #[default]
    Untouched,
    Recycled,
    Held(PathBuf),
    Kept,
}

impl OriginalDisposition {
    fn tag(&self) -> &'static str {
        match self {
            Self::Untouched => "none",
            Self::Recycled => "recycled",
            Self::Held(_) => "held",
            Self::Kept => "kept",
        }
    }
}

/// Outcome of one file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VideoJobOutcome {
    pub path: PathBuf,
    pub output_path: Option<PathBuf>,
    pub status: VideoJobStatus,
    pub original_bytes: u64,
    pub new_bytes: u64,
    /// Mean quality score over the checked segments.
    pub score: Option<f64>,
    pub min_segment_score: Option<f64>,
    pub metric: Option<QualityMetric>,
    pub encoder: Option<EncoderKind>,
    pub quality: Quality,
    pub elapsed_secs: f64,
    pub disposition: OriginalDisposition,
    pub message: Option<String>,
}

impl VideoJobOutcome {
    fn new(path: &Path, quality: Quality) -> Self {
        Self {
            path: path.to_path_buf(),
            output_path: None,
            status: VideoJobStatus::Failed,
            original_bytes: 0,
            new_bytes: 0,
            score: None,
            min_segment_score: None,
            metric: None,
            encoder: None,
            quality,
            elapsed_secs: 0.0,
            disposition: OriginalDisposition::Untouched,
            message: None,
        }
    }

    fn finish(mut self, status: VideoJobStatus, msg: Option<String>, start: Instant) -> Self {
        self.status = status;
        self.message = msg;
        self.elapsed_secs = start.elapsed().as_secs_f64();
        self
    }

    /// Bytes this job will free once the original is gone (0 unless replaced).
    pub fn saved_bytes(&self) -> u64 {
        if self.status == VideoJobStatus::Replaced {
            self.original_bytes.saturating_sub(self.new_bytes)
        } else {
            0
        }
    }
}

/// Stage of the current file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VideoPhase {
    /// Paused (full-screen game).
    Waiting(String),
    Encoding,
    Verifying,
    Replacing,
}

/// Batch progress.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VideoProgress {
    pub file_index: usize,
    pub file_count: usize,
    pub path: PathBuf,
    pub phase: VideoPhase,
    /// 0..1 of the current file's encode.
    pub fraction: f64,
    /// Encode speed as a multiple of real time.
    pub speed: f64,
    /// Bytes saved by the files finished so far.
    pub saved_so_far: u64,
}

/// Batch result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BatchReport {
    pub outcomes: Vec<VideoJobOutcome>,
    pub replaced: usize,
    /// Original minus new size over replaced files.
    pub saved_bytes: u64,
    /// Originals now in the Recycle Bin (space returns when it is emptied).
    pub recycle_bin_bytes: u64,
    /// Originals parked in holding folders.
    pub held_bytes: u64,
    /// Why the batch stopped early.
    pub stopped: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Containers and arguments
// ---------------------------------------------------------------------------------------------

const BITMAP_SUBTITLES: &[&str] = &["dvd_subtitle", "hdmv_pgs_subtitle", "dvb_subtitle", "xsub"];
const TEXT_SUBTITLES: &[&str] = &["subrip", "ass", "ssa", "mov_text", "webvtt", "text"];

/// Output container for a source extension: MKV stays MKV, WebM stays WebM when AV1 can keep its
/// audio and subtitles, everything else becomes MP4 unless it carries fonts or picture subtitles
/// (MKV keeps those).
pub fn output_container(src_ext: &str, codec: TargetCodec, info: &ProbeInfo) -> &'static str {
    let bitmap_subs = info
        .subtitles
        .iter()
        .any(|s| BITMAP_SUBTITLES.contains(&s.codec.as_str()));
    match src_ext.to_ascii_lowercase().as_str() {
        "mkv" => "mkv",
        "webm"
            if codec == TargetCodec::Av1
                && info
                    .audio
                    .iter()
                    .all(|a| matches!(a.codec.as_str(), "opus" | "vorbis"))
                && info.subtitles.iter().all(|s| s.codec == "webvtt") =>
        {
            "webm"
        }
        "webm" => "mkv",
        _ if info.attachments > 0 || bitmap_subs => "mkv",
        _ => "mp4",
    }
}

/// `true` when an audio codec cannot be copied into `container`.
pub fn audio_needs_reencode(codec: &str, container: &str) -> bool {
    match container {
        "mp4" => !matches!(
            codec,
            "aac" | "mp3" | "mp2" | "ac3" | "eac3" | "opus" | "flac" | "alac"
        ),
        "webm" => !matches!(codec, "opus" | "vorbis"),
        // MKV takes anything; PCM still becomes FLAC (lossless, about half the size).
        _ => codec.starts_with("pcm_"),
    }
}

/// Full ffmpeg argument list for one encode. `input_opts` go before `-i` (sample seeking).
pub fn build_encode_args(
    info: &ProbeInfo,
    src: &Path,
    dst: &Path,
    enc: EncoderCaps,
    quality: Quality,
    container: &str,
    input_opts: &[String],
) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();
    let mut push = |s: &str| a.push(OsString::from(s));
    push("-hwaccel");
    push("auto");
    for o in input_opts {
        push(o);
    }
    push("-i");
    a.push(src.as_os_str().to_owned());
    let mut push = |s: &str| a.push(OsString::from(s));
    if let Some(v) = &info.video {
        push("-map");
        push(&format!("0:{}", v.index));
    }
    for au in &info.audio {
        push("-map");
        push(&format!("0:{}", au.index));
    }
    let kept_subs: Vec<_> = info
        .subtitles
        .iter()
        .filter(|s| match container {
            "mp4" => TEXT_SUBTITLES.contains(&s.codec.as_str()),
            "webm" => s.codec == "webvtt",
            _ => true,
        })
        .collect();
    for s in &kept_subs {
        push("-map");
        push(&format!("0:{}", s.index));
    }
    if container == "mkv" && info.attachments > 0 {
        push("-map");
        push("0:t?");
    }
    for o in [
        "-map_metadata",
        "0",
        "-map_chapters",
        "0",
        "-c:v",
        enc.kind.ffmpeg_name(),
    ] {
        push(o);
    }
    for o in enc.kind.encode_args(quality, enc.ten_bit) {
        push(&o);
    }
    if let Some(v) = &info.video {
        for (flag, val) in [
            ("-color_primaries", &v.color_primaries),
            ("-color_trc", &v.color_transfer),
            ("-colorspace", &v.color_space),
            ("-color_range", &v.color_range),
        ] {
            if let Some(val) = val {
                push(flag);
                push(val);
            }
        }
    }
    push("-fps_mode");
    push("passthrough");
    for (i, au) in info.audio.iter().enumerate() {
        if audio_needs_reencode(&au.codec, container) {
            if container == "mkv" {
                push(&format!("-c:a:{i}"));
                push("flac");
            } else if container == "webm" {
                push(&format!("-c:a:{i}"));
                push("libopus");
                push(&format!("-b:a:{i}"));
                push(if au.channels > 2 { "320k" } else { "160k" });
            } else {
                push(&format!("-c:a:{i}"));
                push("aac");
                push(&format!("-b:a:{i}"));
                push(if au.channels > 2 { "384k" } else { "192k" });
            }
        } else {
            push(&format!("-c:a:{i}"));
            push("copy");
        }
    }
    if !kept_subs.is_empty() {
        push("-c:s");
        push(if container == "mp4" {
            "mov_text"
        } else {
            "copy"
        });
    }
    if container == "mkv" && info.attachments > 0 {
        push("-c:t");
        push("copy");
    }
    if container == "mp4" && enc.kind.codec() == TargetCodec::Hevc {
        push("-tag:v");
        push("hvc1");
    }
    push("-metadata");
    push(&format!(
        "{MARKER_TAG}={}-{}",
        enc.kind.codec().tag(),
        quality.tag()
    ));
    if container == "mp4" {
        for o in [
            "-metadata",
            "major_brand=",
            "-metadata",
            "minor_version=",
            "-metadata",
            "compatible_brands=",
            "-movflags",
            "+use_metadata_tags+faststart",
        ] {
            push(o);
        }
    }
    push("-max_muxing_queue_size");
    push("4096");
    push("-y");
    a.push(dst.as_os_str().to_owned());
    a
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// `X:\` for a drive-letter path.
fn drive_root(path: &Path) -> Option<String> {
    let s = path.to_str()?;
    let s = s.strip_prefix(r"\\?\").unwrap_or(s);
    let b = s.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        .then(|| format!("{}:\\", (b[0] as char).to_ascii_uppercase()))
}

/// Holding folder for originals on `path`'s volume: `%USERPROFILE%\DiskSaver Originals` on the
/// profile's volume, `X:\DiskSaver Originals` elsewhere.
pub fn holding_root_for(path: &Path) -> Option<PathBuf> {
    let drive = drive_root(path)?;
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from)
        && drive_root(&home).as_deref() == Some(drive.as_str())
    {
        return Some(home.join(HOLDING_FOLDER));
    }
    Some(PathBuf::from(drive).join(HOLDING_FOLDER))
}

/// `YYYY-MM-DD` (UTC) for a holding sub-folder.
fn today_utc() -> String {
    let days = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `p`, or `p` with ` (2)`, ` (3)`, ... before the extension when taken.
fn unique_path(p: PathBuf) -> PathBuf {
    if !p.exists() {
        return p;
    }
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
    (2..10_000)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|c| !c.exists())
        .unwrap_or(p)
}

fn same_path(a: &Path, b: &Path) -> bool {
    normalize_win_path_str(a) == normalize_win_path_str(b)
}

/// `true` when another program has the file open for writing (or exclusively).
fn file_in_use(path: &Path) -> bool {
    matches!(
        fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path),
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
    )
}

/// Moves `src` into the holding folder, keeping its path below the drive root.
fn hold_original(src: &Path, root: Option<&Path>) -> Result<PathBuf> {
    let root = match root {
        Some(r) => r.to_path_buf(),
        None => holding_root_for(src)
            .ok_or_else(|| DskError::Unsupported("not a drive-letter path".into()))?,
    };
    let s = src.to_string_lossy();
    let rel = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let rel = rel.get(3..).unwrap_or("");
    let dest = unique_path(root.join(today_utc()).join(rel));
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(src, &dest)?;
    Ok(dest)
}

fn dispose_original(
    src: &Path,
    policy: OriginalPolicy,
    deny: &DenyContext,
    holding_root: Option<&Path>,
) -> Result<OriginalDisposition> {
    match policy {
        OriginalPolicy::KeepBoth => Ok(OriginalDisposition::Kept),
        OriginalPolicy::Hold => hold_original(src, holding_root).map(OriginalDisposition::Held),
        OriginalPolicy::Recycle => {
            match crate::win::recycle::recycle_replaced_original(src, deny) {
                Ok(_) => Ok(OriginalDisposition::Recycled),
                // Too big for the bin (the Shell refuses rather than deleting), bin disabled, ...
                Err(_) if src.exists() => {
                    hold_original(src, holding_root).map(OriginalDisposition::Held)
                }
                Err(e) => Err(e),
            }
        }
    }
}

fn remove_quietly(p: &Path) {
    let _ = fs::remove_file(p);
}

fn journal_job(opts: &CompressOptions, o: &VideoJobOutcome, est: u64) {
    let Some(jp) = &opts.journal_path else {
        return;
    };
    let Ok(mut j) = ActionJournal::open(jp) else {
        return;
    };
    let rec = VideoJobRecord {
        id: 0,
        finished_at_unix: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        source_path: o.path.to_string_lossy().into_owned(),
        output_path: o
            .output_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        original_bytes: o.original_bytes,
        new_bytes: o.new_bytes,
        encoder: o.encoder.map(|e| e.label().to_string()).unwrap_or_default(),
        quality: o.quality.tag().to_string(),
        vmaf: o.score,
        status: o.status.tag().to_string(),
        original_disposition: o.disposition.tag().to_string(),
        held_path: match &o.disposition {
            OriginalDisposition::Held(p) => Some(p.to_string_lossy().into_owned()),
            _ => None,
        },
        purged: false,
    };
    let _ = j.record_video_job(&rec);
    if matches!(
        o.status,
        VideoJobStatus::Replaced | VideoJobStatus::KeptBoth
    ) && o.quality == opts.quality
    {
        let _ = j.record_calibration(
            &format!("video.{}.{}", opts.codec.tag(), opts.quality.tag()),
            est,
            o.new_bytes,
        );
    }
}

/// Calibration category for `opts` (see [`ActionJournal::calibration_ratio`]).
pub fn calibration_category(codec: TargetCodec, quality: Quality) -> String {
    format!("video.{}.{}", codec.tag(), quality.tag())
}

// ---------------------------------------------------------------------------------------------
// One file
// ---------------------------------------------------------------------------------------------

/// Compresses one file. `on_progress(phase, fraction, speed)`; `stop` is polled during long
/// steps and returns the status to stop with ([`VideoJobStatus::Cancelled`] or
/// [`VideoJobStatus::OnBattery`]). Never leaves a temp file behind on failure, and never touches
/// the original unless the new file passed every check.
pub fn compress_one(
    engine: &VideoEngine,
    path: &Path,
    opts: &CompressOptions,
    deny: &DenyContext,
    on_progress: &mut dyn FnMut(VideoPhase, f64, f64),
    stop: &dyn Fn() -> Option<VideoJobStatus>,
) -> VideoJobOutcome {
    let start = Instant::now();
    let mut out = VideoJobOutcome::new(path, opts.quality);
    let fail = |o: VideoJobOutcome, m: String| o.finish(VideoJobStatus::Failed, Some(m), start);

    // 1. The file itself.
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => return fail(out, format!("cannot read the file: {e}")),
    };
    if !meta.is_file() {
        return fail(out, "not a regular file".into());
    }
    let attrs = meta.file_attributes();
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return fail(out, "links are not compressed".into());
    }
    if attrs & CLOUD_ATTRIBUTES != 0 {
        return fail(
            out,
            "cloud placeholder: make it available offline first".into(),
        );
    }
    out.original_bytes = meta.len();
    if let Some(reason) = is_denied_for_owner_replacement(path, deny) {
        return fail(out, format!("protected location ({reason})"));
    }
    if path
        .file_name()
        .is_some_and(|n| n.to_string_lossy().contains(TEMP_MARKER))
    {
        return fail(out, "DiskSaver work file".into());
    }

    // 2. What is in it.
    let mut info = match probe(&engine.tools, path) {
        Ok(i) => i,
        Err(e) => return fail(out, e.to_string()),
    };
    if info.size_bytes == 0 {
        info.size_bytes = out.original_bytes;
    }
    if info.is_disksaver_output() {
        return out.finish(VideoJobStatus::AlreadyCompressed, None, start);
    }
    let Some(src_video) = info.video.clone() else {
        return fail(out, "no video stream".into());
    };
    if src_video.dolby_vision {
        return fail(
            out,
            "Dolby Vision: its dynamic metadata would be lost".into(),
        );
    }
    if file_in_use(path) {
        return out.finish(
            VideoJobStatus::InUse,
            Some("another program has it open (still recording?)".into()),
            start,
        );
    }
    let Some(first_enc) = engine.encoder_for(opts.codec, opts.encoder) else {
        return fail(
            out,
            format!(
                "no working {} encoder for {:?} in this ffmpeg build",
                opts.codec.label(),
                opts.encoder
            ),
        );
    };

    // 3. Where the new file goes.
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    let container = output_container(&ext, opts.codec, &info);
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!("{stem}{TEMP_MARKER}{container}"));
    remove_quietly(&tmp);

    let est = estimate_output_bytes(&info, opts.codec, opts.quality);
    if let Some(root) = drive_root(path)
        && let Ok(vi) = crate::win::volume::volume_info(&root)
    {
        let need = est.saturating_mul(3) / 2 + (256 << 20);
        if vi.free_bytes < need {
            return fail(
                out,
                format!(
                    "not enough free space on {root} for the new file (needs about {} MiB)",
                    need >> 20
                ),
            );
        }
    }

    // 4. Encode and verify (retrying at a higher quality or on the CPU encoder).
    let mut encoders = vec![first_enc];
    if first_enc.kind.is_hardware()
        && let Some(cpu) = engine
            .encoders
            .iter()
            .find(|c| c.kind == first_enc.kind.cpu_fallback())
    {
        encoders.push(*cpu);
    }
    let mut enc_idx = 0;
    let mut quality = opts.quality;
    let gate = engine.metric.gate(opts.min_vmaf);
    let stop_flag = std::cell::Cell::new(None::<VideoJobStatus>);
    let should_stop = || {
        if stop_flag.get().is_none() {
            stop_flag.set(stop());
        }
        stop_flag.get().is_some()
    };
    let duration = info.duration_secs;
    loop {
        let enc = encoders[enc_idx];
        out.encoder = Some(enc.kind);
        out.quality = quality;
        out.metric = Some(engine.metric);
        let args = build_encode_args(&info, path, &tmp, enc, quality, container, &[]);
        on_progress(VideoPhase::Encoding, 0.0, 0.0);
        let run = run_ffmpeg(
            &engine.tools,
            &args,
            duration,
            &mut |f, s| on_progress(VideoPhase::Encoding, f, s),
            &should_stop,
        );
        match run {
            Ok(()) => {}
            Err(DskError::Cancelled) => {
                remove_quietly(&tmp);
                let st = stop_flag.get().unwrap_or(VideoJobStatus::Cancelled);
                return out.finish(st, None, start);
            }
            Err(e) => {
                remove_quietly(&tmp);
                if enc_idx + 1 < encoders.len() {
                    enc_idx += 1;
                    continue;
                }
                return fail(out, e.to_string());
            }
        }

        on_progress(VideoPhase::Verifying, 1.0, 0.0);
        let new_info = match probe(&engine.tools, &tmp) {
            Ok(i) => i,
            Err(e) => {
                remove_quietly(&tmp);
                return fail(out, format!("the new file is unreadable: {e}"));
            }
        };
        let Some(new_video) = new_info.video.clone() else {
            remove_quietly(&tmp);
            return fail(out, "the new file has no video stream".into());
        };
        if new_info.audio.len() != info.audio.len() {
            remove_quietly(&tmp);
            return fail(
                out,
                format!(
                    "audio streams differ ({} vs {})",
                    new_info.audio.len(),
                    info.audio.len()
                ),
            );
        }
        if duration > 0.0 {
            let tol = (duration * 0.01).max(1.0);
            if (new_info.duration_secs - duration).abs() > tol {
                remove_quietly(&tmp);
                return fail(
                    out,
                    format!(
                        "duration differs ({:.1}s vs {:.1}s)",
                        new_info.duration_secs, duration
                    ),
                );
            }
        }
        let new_bytes = fs::metadata(&tmp).map(|m| m.len()).unwrap_or(u64::MAX);
        out.new_bytes = new_bytes;
        if new_bytes as f64 > out.original_bytes as f64 * (1.0 - opts.min_saving_ratio) {
            remove_quietly(&tmp);
            let msg = format!(
                "the new file would be {:.0} % of the original",
                new_bytes as f64 * 100.0 / out.original_bytes.max(1) as f64
            );
            return out.finish(VideoJobStatus::NotSmaller, Some(msg), start);
        }
        // The decoder rotates phone video upright; compare at the new file's size.
        let rotated = matches!(src_video.rotation.rem_euclid(360), 90 | 270);
        let (rw, rh) = if rotated {
            (src_video.height, src_video.width)
        } else {
            (src_video.width, src_video.height)
        };
        let ref_scale = ((rw, rh) != (new_video.width, new_video.height))
            .then_some((new_video.width, new_video.height));
        let segments = plan_segments(duration);
        let scores = match measure_quality(
            &engine.tools,
            engine.metric,
            &tmp,
            path,
            &segments,
            ref_scale,
            gate,
            &should_stop,
        ) {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                remove_quietly(&tmp);
                return fail(out, "quality check produced no score".into());
            }
            Err(DskError::Cancelled) => {
                remove_quietly(&tmp);
                let st = stop_flag.get().unwrap_or(VideoJobStatus::Cancelled);
                return out.finish(st, None, start);
            }
            Err(e) => {
                remove_quietly(&tmp);
                return fail(out, e.to_string());
            }
        };
        let mean = scores.iter().sum::<f64>() / scores.len() as f64;
        let min = scores.iter().copied().fold(f64::INFINITY, f64::min);
        out.score = Some(mean);
        out.min_segment_score = Some(min);
        if mean < gate || min < gate - engine.metric.segment_slack() {
            remove_quietly(&tmp);
            if opts.retry_higher_quality
                && let Some(h) = quality.higher()
            {
                quality = h;
                continue;
            }
            return out.finish(
                VideoJobStatus::QualityTooLow,
                Some(format!(
                    "{} {mean:.2} (lowest segment {min:.2}) is under the gate {gate:.2}",
                    engine.metric.label()
                )),
                start,
            );
        }
        break;
    }

    // 5. Swap.
    on_progress(VideoPhase::Replacing, 1.0, 0.0);
    match fs::symlink_metadata(path) {
        Ok(now) if now.len() == meta.len() && now.modified().ok() == meta.modified().ok() => {}
        _ => {
            remove_quietly(&tmp);
            return fail(
                out,
                "the original changed while it was being compressed".into(),
            );
        }
    }
    let mut times = fs::FileTimes::new();
    if let Ok(m) = meta.modified() {
        times = times.set_modified(m);
    }
    if let Ok(c) = meta.created() {
        times = times.set_created(c);
    }
    if let Ok(f) = fs::OpenOptions::new().write(true).open(&tmp) {
        let _ = f.set_times(times);
    }

    let result = match opts.originals {
        OriginalPolicy::KeepBoth => {
            let final_path =
                unique_path(dir.join(format!("{stem}.{}.{container}", opts.codec.tag())));
            match fs::rename(&tmp, &final_path) {
                Ok(()) => {
                    out.output_path = Some(final_path);
                    out.disposition = OriginalDisposition::Kept;
                    out.finish(VideoJobStatus::KeptBoth, None, start)
                }
                Err(e) => {
                    remove_quietly(&tmp);
                    fail(out, format!("could not name the new file: {e}"))
                }
            }
        }
        policy => {
            let natural = dir.join(format!("{stem}.{container}"));
            if same_path(&natural, path) {
                // Same name: the original must move out first.
                match dispose_original(path, policy, deny, opts.holding_root.as_deref()) {
                    Ok(d) => {
                        out.disposition = d;
                        match fs::rename(&tmp, path) {
                            Ok(()) => {
                                out.output_path = Some(path.to_path_buf());
                                out.finish(VideoJobStatus::Replaced, None, start)
                            }
                            Err(e) => {
                                out.output_path = Some(tmp.clone());
                                fail(
                                    out,
                                    format!(
                                        "the original was moved but the new file could not take its name ({e}); it is at {}",
                                        tmp.display()
                                    ),
                                )
                            }
                        }
                    }
                    Err(e) => {
                        remove_quietly(&tmp);
                        fail(out, format!("could not move the original: {e}"))
                    }
                }
            } else {
                // New extension (.MOV -> .mp4): put the new file in place first.
                let final_path = if natural.exists() {
                    unique_path(dir.join(format!("{stem} ({}).{container}", opts.codec.tag())))
                } else {
                    natural
                };
                match fs::rename(&tmp, &final_path) {
                    Ok(()) => {
                        out.output_path = Some(final_path);
                        match dispose_original(path, policy, deny, opts.holding_root.as_deref()) {
                            Ok(d) => {
                                out.disposition = d;
                                out.finish(VideoJobStatus::Replaced, None, start)
                            }
                            Err(e) => out.finish(
                                VideoJobStatus::KeptBoth,
                                Some(format!("the original could not be moved, both kept: {e}")),
                                start,
                            ),
                        }
                    }
                    Err(e) => {
                        remove_quietly(&tmp);
                        fail(out, format!("could not name the new file: {e}"))
                    }
                }
            }
        }
    };
    journal_job(opts, &result, est);
    result
}

// ---------------------------------------------------------------------------------------------
// Batches
// ---------------------------------------------------------------------------------------------

/// Compresses `paths` one after another, calling `on_done` as each file finishes. Stops on cancel
/// and (unless allowed) on battery; waits while a full-screen game runs.
pub fn compress_batch(
    engine: &VideoEngine,
    paths: &[PathBuf],
    opts: &CompressOptions,
    deny: &DenyContext,
    progress: &mut dyn FnMut(&VideoProgress),
    on_done: &mut dyn FnMut(&VideoJobOutcome),
    cancel: &AtomicBool,
) -> BatchReport {
    let mut report = BatchReport::default();
    let n = paths.len();
    let last_power_check = std::cell::Cell::new(Instant::now() - Duration::from_secs(60));
    let on_battery_now = || -> bool {
        if opts.allow_battery || last_power_check.get().elapsed() < Duration::from_secs(10) {
            return false;
        }
        last_power_check.set(Instant::now());
        crate::win::sysinfo::on_battery() == Some(true)
    };
    for (i, p) in paths.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.stopped = Some("cancelled".into());
            break;
        }
        if !opts.allow_battery && crate::win::sysinfo::on_battery() == Some(true) {
            report.stopped = Some("on battery power: plug in to continue".into());
            break;
        }
        if opts.wait_for_fullscreen {
            while crate::win::sysinfo::fullscreen_app_running() {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                progress(&VideoProgress {
                    file_index: i,
                    file_count: n,
                    path: p.clone(),
                    phase: VideoPhase::Waiting("paused while a full-screen app runs".into()),
                    fraction: 0.0,
                    speed: 0.0,
                    saved_so_far: report.saved_bytes,
                });
                for _ in 0..20 {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
            if cancel.load(Ordering::Relaxed) {
                report.stopped = Some("cancelled".into());
                break;
            }
        }
        let saved = report.saved_bytes;
        let o = compress_one(
            engine,
            p,
            opts,
            deny,
            &mut |phase, fraction, speed| {
                progress(&VideoProgress {
                    file_index: i,
                    file_count: n,
                    path: p.clone(),
                    phase,
                    fraction,
                    speed,
                    saved_so_far: saved,
                })
            },
            &|| {
                if cancel.load(Ordering::Relaxed) {
                    Some(VideoJobStatus::Cancelled)
                } else if on_battery_now() {
                    Some(VideoJobStatus::OnBattery)
                } else {
                    None
                }
            },
        );
        if o.status == VideoJobStatus::Replaced {
            report.replaced += 1;
            report.saved_bytes += o.saved_bytes();
            match &o.disposition {
                OriginalDisposition::Recycled => report.recycle_bin_bytes += o.original_bytes,
                OriginalDisposition::Held(_) => report.held_bytes += o.original_bytes,
                _ => {}
            }
        }
        let status = o.status;
        on_done(&o);
        report.outcomes.push(o);
        match status {
            VideoJobStatus::Cancelled => {
                report.stopped = Some("cancelled".into());
                break;
            }
            VideoJobStatus::OnBattery => {
                report.stopped = Some("on battery power: plug in to continue".into());
                break;
            }
            _ => {}
        }
    }
    report
}

// ---------------------------------------------------------------------------------------------
// Samples
// ---------------------------------------------------------------------------------------------

/// A short test encode: real size and quality before committing to a whole file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SampleResult {
    pub source: PathBuf,
    /// The encoded sample (kept so the owner can watch it).
    pub sample_path: PathBuf,
    pub start_secs: f64,
    pub seconds: f64,
    /// Source bytes for the same stretch (pro rata).
    pub source_slice_bytes: u64,
    pub sample_bytes: u64,
    /// `sample_bytes / source_slice_bytes`.
    pub ratio: f64,
    /// Whole-file size projected from the ratio.
    pub projected_output_bytes: u64,
    pub score: Option<f64>,
    pub metric: QualityMetric,
    pub encoder: EncoderKind,
    /// Encode speed as a multiple of real time.
    pub speed: f64,
}

/// Folder for sample encodes (`%TEMP%\DiskSaver\video-samples`).
pub fn sample_dir() -> PathBuf {
    std::env::temp_dir().join("DiskSaver").join("video-samples")
}

/// Encodes `seconds` of `path` starting at `at` (default: the middle) and scores it.
pub fn sample_video(
    engine: &VideoEngine,
    path: &Path,
    opts: &CompressOptions,
    at: Option<f64>,
    seconds: f64,
    cancel: &AtomicBool,
) -> Result<SampleResult> {
    let mut info = probe(&engine.tools, path)?;
    let bytes = fs::metadata(path)?.len();
    if info.size_bytes == 0 {
        info.size_bytes = bytes;
    }
    if info.video.is_none() {
        return Err(DskError::Unsupported("no video stream".into()));
    }
    let enc = engine
        .encoder_for(opts.codec, opts.encoder)
        .ok_or_else(|| {
            DskError::Unsupported(format!("no working {} encoder", opts.codec.label()))
        })?;
    let d = info.duration_secs;
    let secs = if d > 0.0 { seconds.min(d) } else { seconds };
    let start = at
        .unwrap_or(((d - secs) / 2.0).max(0.0))
        .clamp(0.0, (d - secs).max(0.0));
    let dir = sample_dir();
    fs::create_dir_all(&dir)?;
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "video".into());
    let out = dir.join(format!(
        "{stem}.sample-{}-{}.mkv",
        enc.kind.codec().tag(),
        opts.quality.tag()
    ));
    let input_opts = vec![
        "-ss".to_string(),
        format!("{start:.3}"),
        "-t".to_string(),
        format!("{secs:.3}"),
    ];
    let args = build_encode_args(&info, path, &out, enc, opts.quality, "mkv", &input_opts);
    let t0 = Instant::now();
    run_ffmpeg(&engine.tools, &args, secs, &mut |_, _| {}, &|| {
        cancel.load(Ordering::Relaxed)
    })?;
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let sample_bytes = fs::metadata(&out)?.len();
    let source_slice_bytes = if d > 0.0 {
        (bytes as f64 * secs / d) as u64
    } else {
        bytes
    };
    let ratio = sample_bytes as f64 / source_slice_bytes.max(1) as f64;
    let score = measure_quality(
        &engine.tools,
        engine.metric,
        &out,
        path,
        &[Segment {
            enc_start: 0.0,
            ref_start: start,
            len: secs.min(30.0),
        }],
        None,
        engine.metric.gate(opts.min_vmaf),
        &|| cancel.load(Ordering::Relaxed),
    )
    .ok()
    .and_then(|v| v.first().copied());
    Ok(SampleResult {
        source: path.to_path_buf(),
        sample_path: out,
        start_secs: start,
        seconds: secs,
        source_slice_bytes,
        sample_bytes,
        ratio,
        projected_output_bytes: (bytes as f64 * ratio.min(1.0)) as u64,
        score,
        metric: engine.metric,
        encoder: enc.kind,
        speed: secs / elapsed,
    })
}

// ---------------------------------------------------------------------------------------------
// Held originals
// ---------------------------------------------------------------------------------------------

/// An original parked in a holding folder.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HeldOriginal {
    pub id: i64,
    pub held_path: PathBuf,
    pub original_path: PathBuf,
    pub output_path: PathBuf,
    pub bytes: u64,
    /// The held file still exists.
    pub held_exists: bool,
    /// The compressed replacement still exists with the size recorded at replacement time.
    pub replacement_ok: bool,
}

/// Purge result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PurgeReport {
    pub items: Vec<HeldOriginal>,
    pub purged: usize,
    pub purged_bytes: u64,
    pub dry_run: bool,
    pub errors: Vec<String>,
}

/// Originals in holding folders, with whether their replacement is intact.
pub fn list_held_originals(journal: &ActionJournal) -> Result<Vec<HeldOriginal>> {
    Ok(journal
        .held_video_originals()?
        .into_iter()
        .filter_map(|r| {
            let held = PathBuf::from(r.held_path?);
            let output = PathBuf::from(&r.output_path);
            let held_meta = fs::metadata(&held).ok();
            Some(HeldOriginal {
                id: r.id,
                bytes: held_meta
                    .as_ref()
                    .map(|m| m.len())
                    .unwrap_or(r.original_bytes),
                held_exists: held_meta.is_some(),
                replacement_ok: fs::metadata(&output).is_ok_and(|m| m.len() == r.new_bytes),
                held_path: held,
                original_path: PathBuf::from(r.source_path),
                output_path: output,
            })
        })
        .collect())
}

/// Permanently deletes held originals whose compressed replacement is still intact. Originals
/// whose replacement is missing or changed are kept and reported.
pub fn purge_held_originals(journal: &mut ActionJournal, dry_run: bool) -> Result<PurgeReport> {
    let deny = DenyContext::default();
    let items = list_held_originals(journal)?;
    let mut rep = PurgeReport {
        dry_run,
        ..Default::default()
    };
    let marker = format!(r"\{}\", HOLDING_FOLDER.to_ascii_uppercase());
    for it in &items {
        if !it.held_exists {
            if !dry_run {
                journal.mark_video_original_purged(it.id)?;
            }
            continue;
        }
        if !it.replacement_ok {
            rep.errors.push(format!(
                "kept {}: its replacement {} is missing or changed",
                it.held_path.display(),
                it.output_path.display()
            ));
            continue;
        }
        if !normalize_win_path_str(&it.held_path).contains(&marker)
            || is_denied_for_owner_replacement(&it.held_path, &deny).is_some()
        {
            rep.errors.push(format!(
                "kept {}: not inside a {HOLDING_FOLDER} folder",
                it.held_path.display()
            ));
            continue;
        }
        if dry_run {
            rep.purged += 1;
            rep.purged_bytes += it.bytes;
            continue;
        }
        match fs::remove_file(&it.held_path) {
            Ok(()) => {
                rep.purged += 1;
                rep.purged_bytes += it.bytes;
                journal.mark_video_original_purged(it.id)?;
                // Remove now-empty folders up to the holding root.
                let mut dir = it.held_path.parent().map(Path::to_path_buf);
                while let Some(d) = dir {
                    if d.file_name()
                        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(HOLDING_FOLDER))
                        || fs::remove_dir(&d).is_err()
                    {
                        break;
                    }
                    dir = d.parent().map(Path::to_path_buf);
                }
            }
            Err(e) => rep.errors.push(format!("{}: {e}", it.held_path.display())),
        }
    }
    rep.items = items;
    Ok(rep)
}
