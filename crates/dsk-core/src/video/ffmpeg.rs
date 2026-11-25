#![forbid(unsafe_code)]

//! ffmpeg / ffprobe integration: locating the owner's tools, probing files, detecting working
//! encoders, running an encode with progress and cancellation, and scoring quality.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{EncoderKind, EncoderPref, MARKER_TAG, Quality, TargetCodec};
use crate::error::{DskError, Result};
use crate::win::process::{BELOW_NORMAL_PRIORITY_CLASS, hidden_command, hidden_command_with_flags};

/// The owner's ffmpeg and ffprobe executables (always from the same folder).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfmpegTools {
    pub ffmpeg: PathBuf,
    pub ffprobe: PathBuf,
}

/// Command that installs ffmpeg for the current user (shown when it is missing).
pub const INSTALL_HINT: &str = "winget install --id Gyan.FFmpeg -e";

fn tools_at(p: &Path) -> Option<FfmpegTools> {
    let (dir, ffmpeg) = if p.is_dir() {
        (p.to_path_buf(), p.join("ffmpeg.exe"))
    } else {
        (p.parent()?.to_path_buf(), p.to_path_buf())
    };
    let ffprobe = dir.join("ffprobe.exe");
    (ffmpeg.is_file() && ffprobe.is_file()).then_some(FfmpegTools { ffmpeg, ffprobe })
}

/// WinGet package folders (`...\WinGet\Packages\*FFmpeg*\<build>\bin`), newest build first.
fn winget_package_bins(packages: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(packages) else {
        return out;
    };
    for pkg in rd.flatten() {
        let name = pkg.file_name().to_string_lossy().to_ascii_lowercase();
        if !name.contains("ffmpeg") {
            continue;
        }
        let pkg = pkg.path();
        out.push(pkg.join("bin"));
        let mut builds: Vec<PathBuf> = std::fs::read_dir(&pkg)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path().join("bin"))
            .collect();
        builds.sort();
        builds.reverse();
        out.extend(builds);
    }
    out
}

fn well_known_dirs() -> Vec<PathBuf> {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let mut out = Vec::new();
    if let Some(la) = env("LOCALAPPDATA") {
        out.push(la.join(r"Microsoft\WinGet\Links"));
        out.extend(winget_package_bins(&la.join(r"Microsoft\WinGet\Packages")));
    }
    if let Some(pf) = env("ProgramFiles") {
        out.extend(winget_package_bins(&pf.join(r"WinGet\Packages")));
        out.push(pf.join(r"ffmpeg\bin"));
    }
    if let Some(home) = env("USERPROFILE") {
        out.push(home.join(r"scoop\apps\ffmpeg\current\bin"));
        out.push(home.join(r"scoop\shims"));
    }
    if let Some(pd) = env("ProgramData") {
        out.push(pd.join(r"chocolatey\bin"));
    }
    out.push(PathBuf::from(r"C:\ffmpeg\bin"));
    out
}

/// Finds ffmpeg + ffprobe: `explicit` (a folder or `ffmpeg.exe`), `%DSK_FFMPEG%`, `PATH`, then
/// WinGet / Scoop / Chocolatey / common folders. An elevated process ignores copies in folders a
/// standard user can write to (a planted binary must never run with admin rights).
pub fn locate_tools(explicit: Option<&Path>) -> Option<FfmpegTools> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Some(p) = explicit {
        cands.push(p.to_path_buf());
    }
    if let Some(v) = std::env::var_os("DSK_FFMPEG") {
        cands.push(PathBuf::from(v));
    }
    if let Some(p) = crate::win::find_program_on_path("ffmpeg.exe") {
        cands.push(p);
    }
    cands.extend(well_known_dirs());
    let elevated = crate::win::volume::is_elevated();
    cands.iter().filter_map(|c| tools_at(c)).find(|t| {
        !elevated
            || t.ffmpeg
                .parent()
                .is_some_and(|d| !crate::win::pipe::is_directory_user_writable(d))
    })
}

/// Runs a short tool invocation and captures its output, killing it after `timeout`.
pub(crate) fn output_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = se.as_mut() {
            let _ = s.take(4 << 20).read_to_end(&mut b);
        }
        b
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DskError::Optimize(format!(
                "{} timed out",
                cmd.get_program().to_string_lossy()
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    Ok(Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    })
}

/// `ffmpeg version 8.1-full_build-www.gyan.dev` (the first line of `-version`, minus copyright).
pub fn tool_version(tools: &FfmpegTools) -> Option<String> {
    let mut cmd = hidden_command(&tools.ffmpeg);
    cmd.arg("-version");
    let out = output_with_timeout(cmd, Duration::from_secs(15)).ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| l.split(" Copyright").next().unwrap_or(l).trim().to_string())
}

/// `true` when the ffmpeg build has the named filter (e.g. `libvmaf`).
pub fn has_filter(tools: &FfmpegTools, name: &str) -> bool {
    let mut cmd = hidden_command(&tools.ffmpeg);
    cmd.args(["-hide_banner", "-filters"]);
    output_with_timeout(cmd, Duration::from_secs(15))
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.split_whitespace().nth(1) == Some(name))
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------------------------

/// The main video stream.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VideoStreamInfo {
    pub index: u32,
    pub codec: String,
    pub width: u32,
    pub height: u32,
    pub fps: f64,
    pub pix_fmt: String,
    /// Stream bitrate when the container reports it, else 0.
    pub bit_rate: u64,
    pub color_transfer: Option<String>,
    pub color_primaries: Option<String>,
    pub color_space: Option<String>,
    pub color_range: Option<String>,
    /// Display rotation in degrees (phones record portrait video as rotated landscape).
    pub rotation: i32,
    pub dolby_vision: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AudioStreamInfo {
    pub index: u32,
    pub codec: String,
    pub channels: u32,
    pub bit_rate: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SubtitleStreamInfo {
    pub index: u32,
    pub codec: String,
}

/// What ffprobe reports about a file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProbeInfo {
    pub format_name: String,
    pub duration_secs: f64,
    pub bit_rate: u64,
    pub size_bytes: u64,
    pub video: Option<VideoStreamInfo>,
    pub audio: Vec<AudioStreamInfo>,
    pub subtitles: Vec<SubtitleStreamInfo>,
    pub attachments: u32,
    /// Container tags with lower-cased keys.
    pub tags: BTreeMap<String, String>,
}

impl ProbeInfo {
    /// `true` for files DiskSaver produced (never offered again).
    pub fn is_disksaver_output(&self) -> bool {
        self.tags.contains_key(MARKER_TAG)
    }

    /// HDR10 / HLG transfer characteristics.
    pub fn is_hdr(&self) -> bool {
        self.video
            .as_ref()
            .and_then(|v| v.color_transfer.as_deref())
            .is_some_and(|t| matches!(t, "smpte2084" | "arib-std-b67"))
    }

    pub fn audio_bitrate(&self) -> u64 {
        self.audio.iter().map(|a| a.bit_rate).sum()
    }

    /// Video bitrate: the stream's own figure, else the container's minus audio, else size/time.
    pub fn video_bitrate(&self) -> u64 {
        if let Some(v) = &self.video
            && v.bit_rate > 0
        {
            return v.bit_rate;
        }
        let total = if self.bit_rate > 0 {
            self.bit_rate
        } else if self.duration_secs > 0.0 {
            (self.size_bytes as f64 * 8.0 / self.duration_secs) as u64
        } else {
            0
        };
        total.saturating_sub(self.audio_bitrate())
    }
}

fn as_u64(v: &Value) -> u64 {
    match v {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(s) => s.trim().parse::<f64>().map(|f| f as u64).unwrap_or(0),
        _ => 0,
    }
}

fn as_f64(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn as_str(v: &Value) -> Option<String> {
    v.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "unknown")
        .map(str::to_string)
}

/// Parses `"30000/1001"` frame rates.
pub fn parse_rate(s: &str) -> f64 {
    match s.split_once('/') {
        Some((n, d)) => {
            let (n, d) = (
                n.parse::<f64>().unwrap_or(0.0),
                d.parse::<f64>().unwrap_or(0.0),
            );
            if d > 0.0 { n / d } else { 0.0 }
        }
        None => s.parse().unwrap_or(0.0),
    }
}

/// Parses `ffprobe -print_format json -show_format -show_streams` output.
pub fn parse_probe_json(json: &str) -> Result<ProbeInfo> {
    let root: Value = serde_json::from_str(json)
        .map_err(|e| DskError::Optimize(format!("unreadable ffprobe output: {e}")))?;
    let fmt = &root["format"];
    let mut info = ProbeInfo {
        format_name: as_str(&fmt["format_name"]).unwrap_or_default(),
        duration_secs: as_f64(&fmt["duration"]),
        bit_rate: as_u64(&fmt["bit_rate"]),
        size_bytes: as_u64(&fmt["size"]),
        ..Default::default()
    };
    if let Some(tags) = fmt["tags"].as_object() {
        for (k, v) in tags {
            if let Some(s) = v.as_str() {
                info.tags.insert(k.to_ascii_lowercase(), s.to_string());
            }
        }
    }
    let streams = root["streams"].as_array().cloned().unwrap_or_default();
    for s in &streams {
        let index = as_u64(&s["index"]) as u32;
        let codec = as_str(&s["codec_name"]).unwrap_or_default();
        match s["codec_type"].as_str() {
            Some("video") => {
                let attached = as_u64(&s["disposition"]["attached_pic"]) == 1;
                if attached || info.video.is_some() {
                    continue;
                }
                let mut fps = parse_rate(s["avg_frame_rate"].as_str().unwrap_or("0/0"));
                if fps <= 0.0 {
                    fps = parse_rate(s["r_frame_rate"].as_str().unwrap_or("0/0"));
                }
                let mut rotation = 0;
                let mut dolby_vision = false;
                for sd in s["side_data_list"].as_array().into_iter().flatten() {
                    if let Some(r) = sd.get("rotation") {
                        rotation = as_f64(r) as i32;
                    }
                    if sd["side_data_type"]
                        .as_str()
                        .is_some_and(|t| t.to_ascii_lowercase().contains("dovi"))
                    {
                        dolby_vision = true;
                    }
                }
                if rotation == 0
                    && let Some(r) = s["tags"]["rotate"].as_str()
                {
                    rotation = r.trim().parse().unwrap_or(0);
                }
                info.video = Some(VideoStreamInfo {
                    index,
                    codec,
                    width: as_u64(&s["width"]) as u32,
                    height: as_u64(&s["height"]) as u32,
                    fps,
                    pix_fmt: as_str(&s["pix_fmt"]).unwrap_or_default(),
                    bit_rate: as_u64(&s["bit_rate"]),
                    color_transfer: as_str(&s["color_transfer"]),
                    color_primaries: as_str(&s["color_primaries"]),
                    color_space: as_str(&s["color_space"]),
                    color_range: as_str(&s["color_range"]),
                    rotation,
                    dolby_vision,
                });
                if info.duration_secs <= 0.0 {
                    info.duration_secs = as_f64(&s["duration"]);
                }
            }
            Some("audio") => info.audio.push(AudioStreamInfo {
                index,
                codec,
                channels: as_u64(&s["channels"]) as u32,
                bit_rate: as_u64(&s["bit_rate"]),
            }),
            Some("subtitle") => info.subtitles.push(SubtitleStreamInfo { index, codec }),
            Some("attachment") => info.attachments += 1,
            _ => {}
        }
    }
    Ok(info)
}

/// Probes `path` with ffprobe (reads headers only; never modifies the file).
pub fn probe(tools: &FfmpegTools, path: &Path) -> Result<ProbeInfo> {
    let mut cmd = hidden_command(&tools.ffprobe);
    cmd.args([
        "-v",
        "error",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
        "-i",
    ])
    .arg(path);
    let out = output_with_timeout(cmd, Duration::from_secs(60))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(DskError::Optimize(format!(
            "ffprobe could not read {}: {}",
            path.display(),
            err.lines().last().unwrap_or("unknown error").trim()
        )));
    }
    parse_probe_json(&String::from_utf8_lossy(&out.stdout))
}

// ---------------------------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------------------------

/// An encoder that produced output on this machine, with its best bit depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderCaps {
    pub kind: EncoderKind,
    pub ten_bit: bool,
}

/// Encoders this ffmpeg build lists (not yet proven to work on this hardware).
pub fn listed_encoders(tools: &FfmpegTools) -> Vec<EncoderKind> {
    let mut cmd = hidden_command(&tools.ffmpeg);
    cmd.args(["-hide_banner", "-encoders"]);
    let Ok(out) = output_with_timeout(cmd, Duration::from_secs(15)) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    EncoderKind::ALL
        .into_iter()
        .filter(|k| {
            text.lines()
                .any(|l| l.split_whitespace().nth(1) == Some(k.ffmpeg_name()))
        })
        .collect()
}

fn test_encode(tools: &FfmpegTools, kind: EncoderKind, ten_bit: bool) -> bool {
    let mut cmd = hidden_command(&tools.ffmpeg);
    cmd.args([
        "-hide_banner",
        "-nostdin",
        "-v",
        "error",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=640x360:rate=30:duration=1",
        "-frames:v",
        "15",
        "-c:v",
        kind.ffmpeg_name(),
    ])
    .args(kind.encode_args(Quality::Balanced, ten_bit))
    .args(["-f", "null", "-"]);
    output_with_timeout(cmd, Duration::from_secs(60)).is_ok_and(|o| o.status.success())
}

/// Encoders that actually work here (a 15-frame test encode each, run in parallel), preferring
/// 10-bit output. Listed in [`EncoderKind::ALL`] order.
pub fn detect_encoders(tools: &FfmpegTools) -> Vec<EncoderCaps> {
    let listed = listed_encoders(tools);
    let results: Vec<Option<EncoderCaps>> = std::thread::scope(|s| {
        let handles: Vec<_> = listed
            .iter()
            .map(|&kind| {
                s.spawn(move || {
                    if test_encode(tools, kind, true) {
                        Some(EncoderCaps {
                            kind,
                            ten_bit: true,
                        })
                    } else if test_encode(tools, kind, false) {
                        Some(EncoderCaps {
                            kind,
                            ten_bit: false,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().ok().flatten())
            .collect()
    });
    results.into_iter().flatten().collect()
}

/// Picks the first working encoder for `codec` matching `pref` (hardware before CPU for Auto).
pub fn choose_encoder(
    caps: &[EncoderCaps],
    codec: TargetCodec,
    pref: EncoderPref,
) -> Option<EncoderCaps> {
    EncoderKind::ALL
        .into_iter()
        .filter(|k| k.codec() == codec && (pref == EncoderPref::Auto || k.vendor() == pref))
        .find_map(|k| caps.iter().find(|c| c.kind == k).copied())
}

// ---------------------------------------------------------------------------------------------
// Running an encode
// ---------------------------------------------------------------------------------------------

/// Last lines of ffmpeg's error output, for messages.
fn tail(s: &str, lines: usize) -> String {
    let v: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    v[v.len().saturating_sub(lines)..].join(" | ")
}

/// Runs ffmpeg with `args` at below-normal priority. `on_progress(fraction, speed)` is called as
/// ffmpeg reports its position; `should_stop` is polled about four times a second and kills the
/// process (returning [`DskError::Cancelled`]) when it returns `true`.
pub fn run_ffmpeg(
    tools: &FfmpegTools,
    args: &[OsString],
    total_secs: f64,
    on_progress: &mut dyn FnMut(f64, f64),
    should_stop: &dyn Fn() -> bool,
) -> Result<()> {
    let mut cmd = hidden_command_with_flags(&tools.ffmpeg, BELOW_NORMAL_PRIORITY_CLASS);
    cmd.args([
        "-hide_banner",
        "-nostdin",
        "-nostats",
        "-v",
        "error",
        "-progress",
        "pipe:1",
    ])
    .args(args)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, rx) = channel::<String>();
    let t_out = std::thread::spawn(move || {
        if let Some(so) = stdout {
            for line in BufReader::new(so).lines().map_while(std::io::Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        }
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(mut se) = stderr {
            let _ = (&mut se).take(1 << 20).read_to_end(&mut b);
            // Drain the rest so ffmpeg never blocks on a full pipe.
            let _ = std::io::copy(&mut se, &mut std::io::sink());
        }
        String::from_utf8_lossy(&b).into_owned()
    });
    let mut speed = 0.0;
    let mut stopped = false;
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(line) => {
                if let Some(v) = line.strip_prefix("out_time_us=") {
                    if let Ok(us) = v.trim().parse::<i64>()
                        && total_secs > 0.0
                    {
                        on_progress((us as f64 / 1e6 / total_secs).clamp(0.0, 1.0), speed);
                    }
                } else if let Some(v) = line.strip_prefix("speed=") {
                    speed = v.trim().trim_end_matches('x').parse().unwrap_or(speed);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if !stopped && should_stop() {
            let _ = child.kill();
            stopped = true;
        }
    }
    let status = child.wait()?;
    let _ = t_out.join();
    let err = t_err.join().unwrap_or_default();
    if stopped {
        return Err(DskError::Cancelled);
    }
    if !status.success() {
        return Err(DskError::Optimize(format!(
            "ffmpeg failed ({}): {}",
            status.code().unwrap_or(-1),
            tail(&err, 3)
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Quality scoring
// ---------------------------------------------------------------------------------------------

/// How quality is scored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualityMetric {
    /// Netflix VMAF (0–100); 93+ is visually identical for most viewers.
    Vmaf,
    /// Structural similarity (0–1), used when ffmpeg lacks libvmaf.
    Ssim,
}

impl QualityMetric {
    pub fn label(self) -> &'static str {
        match self {
            Self::Vmaf => "VMAF",
            Self::Ssim => "SSIM",
        }
    }

    /// The gate for this metric given the owner's VMAF gate (SSIM uses a mapped value).
    pub fn gate(self, vmaf_gate: f64) -> f64 {
        match self {
            Self::Vmaf => vmaf_gate,
            Self::Ssim => (0.97 + (vmaf_gate - 93.0) * 0.003).clamp(0.90, 0.995),
        }
    }

    /// How far one segment may fall below the gate when the average clears it.
    pub fn segment_slack(self) -> f64 {
        match self {
            Self::Vmaf => 6.0,
            Self::Ssim => 0.02,
        }
    }
}

/// A stretch of the encoded file compared with the same stretch of the reference.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Segment {
    pub enc_start: f64,
    pub ref_start: f64,
    pub len: f64,
}

/// Segments covering the start, middle, and end of a `duration`-second video (the whole video
/// when it is short).
pub fn plan_segments(duration: f64) -> Vec<Segment> {
    if duration <= 0.0 {
        return vec![Segment {
            enc_start: 0.0,
            ref_start: 0.0,
            len: 8.0,
        }];
    }
    if duration <= 40.0 {
        return vec![Segment {
            enc_start: 0.0,
            ref_start: 0.0,
            len: duration,
        }];
    }
    let len = 8.0;
    let last = (duration - len - 0.5).max(0.0);
    [0.02, 0.25, 0.5, 0.75]
        .iter()
        .map(|f| duration * f)
        .chain(std::iter::once(last))
        .map(|start| Segment {
            enc_start: start,
            ref_start: start,
            len,
        })
        .collect()
}

/// Parses `VMAF score: 95.8` or `SSIM ... All:0.9823 (17.5)` from ffmpeg's log.
pub fn parse_score(metric: QualityMetric, log: &str) -> Option<f64> {
    match metric {
        QualityMetric::Vmaf => log
            .lines()
            .rev()
            .find_map(|l| l.split("VMAF score:").nth(1))
            .and_then(|v| v.split_whitespace().next()?.parse().ok()),
        QualityMetric::Ssim => log
            .lines()
            .rev()
            .find_map(|l| l.split("All:").nth(1))
            .and_then(|v| v.split_whitespace().next()?.parse().ok()),
    }
}

fn threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 16)
}

/// Scores one segment. Frames are paired by index on a shared `1/30` timebase (`settb`, then
/// `setpts=N`): variable-frame-rate phone video otherwise pairs the wrong frames, and so does
/// `setpts=N/(30*TB)` alone when one file has MKV's coarse millisecond timebase (every third frame
/// lands on its neighbour). Both mistakes score a perfect copy around 50 VMAF. `enc_trim` / `ref_trim` drop leading
/// frames to absorb a one-frame seek offset.
#[allow(clippy::too_many_arguments)]
pub fn score_segment(
    tools: &FfmpegTools,
    metric: QualityMetric,
    encoded: &Path,
    reference: &Path,
    seg: Segment,
    ref_scale: Option<(u32, u32)>,
    enc_trim: u32,
    ref_trim: u32,
) -> Result<f64> {
    let trim = |n: u32| {
        if n > 0 {
            format!("trim=start_frame={n},")
        } else {
            String::new()
        }
    };
    let scale = ref_scale
        .map(|(w, h)| format!("scale={w}:{h}:flags=bicubic,"))
        .unwrap_or_default();
    let cmp = match metric {
        QualityMetric::Vmaf => format!("libvmaf=n_threads={}:n_subsample=2", threads()),
        QualityMetric::Ssim => "ssim".to_string(),
    };
    let graph = format!(
        "[0:v]{}settb=1/30,setpts=N,format=yuv420p[d];[1:v]{}{}settb=1/30,setpts=N,format=yuv420p[r];[d][r]{cmp}",
        trim(enc_trim),
        trim(ref_trim),
        scale
    );
    let mut cmd = hidden_command_with_flags(&tools.ffmpeg, BELOW_NORMAL_PRIORITY_CLASS);
    cmd.args(["-hide_banner", "-nostdin", "-nostats", "-v", "info"])
        .args(["-ss", &format!("{:.3}", seg.enc_start)])
        .args(["-t", &format!("{:.3}", seg.len)])
        .arg("-i")
        .arg(encoded)
        .args(["-ss", &format!("{:.3}", seg.ref_start)])
        .args(["-t", &format!("{:.3}", seg.len)])
        .arg("-i")
        .arg(reference)
        .args(["-lavfi", &graph, "-f", "null", "-"]);
    let out = output_with_timeout(cmd, Duration::from_secs(1800))?;
    let log = String::from_utf8_lossy(&out.stderr);
    parse_score(metric, &log).ok_or_else(|| {
        DskError::Optimize(format!(
            "quality check produced no {} score: {}",
            metric.label(),
            tail(&log, 2)
        ))
    })
}

#[allow(clippy::too_many_arguments)]
/// Scores every segment; a segment under `gate` is re-scored with a one-frame offset either way
/// and keeps the best result (seek points can land one frame apart).
pub fn measure_quality(
    tools: &FfmpegTools,
    metric: QualityMetric,
    encoded: &Path,
    reference: &Path,
    segments: &[Segment],
    ref_scale: Option<(u32, u32)>,
    gate: f64,
    should_stop: &dyn Fn() -> bool,
) -> Result<Vec<f64>> {
    let mut scores = Vec::with_capacity(segments.len());
    for seg in segments {
        if should_stop() {
            return Err(DskError::Cancelled);
        }
        let mut best = score_segment(tools, metric, encoded, reference, *seg, ref_scale, 0, 0)?;
        if best < gate {
            for (e, r) in [(1, 0), (0, 1)] {
                if let Ok(s) =
                    score_segment(tools, metric, encoded, reference, *seg, ref_scale, e, r)
                {
                    best = best.max(s);
                }
            }
        }
        scores.push(best);
    }
    Ok(scores)
}
