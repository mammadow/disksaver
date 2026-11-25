#![forbid(unsafe_code)]

//! Video compressor: finds big, inefficiently encoded videos on every drive and re-encodes
//! selected files to AV1 or HEVC on the GPU, keeping the picture visually identical.
//!
//! Representative hardware-encoder benchmarks (AV1 NVENC, Balanced preset): high-bitrate screen
//! recordings shrink up to ~97% (VMAF ~96.9), mobile clips ~77% (VMAF ~97.4), and game captures
//! ~83% (VMAF ~95.5), encoding at 3–11× real time.
//!
//! Safety model:
//! - The encoder is the owner's own ffmpeg (WinGet, Scoop, Chocolatey, PATH); DiskSaver does not
//!   bundle or download it.
//! - Nothing is replaced until the new file is verified: the streams are present, the duration
//!   matches, the file is meaningfully smaller, and a quality score (VMAF, or SSIM without libvmaf)
//!   over several segments clears the gate. Frames are paired by index, not timestamp, because
//!   phone footage has variable frame rates that otherwise produce false failures.
//! - The original goes to the Recycle Bin (the only exception to the personal-library deny rule,
//!   see [`crate::clean::deny::is_denied_for_owner_replacement`]); originals too big for the bin
//!   are parked in a `DiskSaver Originals` folder on the same volume. Every job is journaled.
//! - Work runs at below-normal priority, waits while a full-screen game runs, and stops on battery.

pub mod compress;
pub mod discover;
pub mod ffmpeg;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

pub use compress::{
    BatchReport, CompressOptions, HeldOriginal, OriginalDisposition, OriginalPolicy, PurgeReport,
    SampleResult, VideoEngine, VideoJobOutcome, VideoJobStatus, VideoPhase, VideoProgress,
    audio_needs_reencode, build_encode_args, calibration_category, compress_batch, compress_one,
    holding_root_for, list_held_originals, output_container, purge_held_originals, sample_dir,
    sample_video,
};
pub use discover::{
    DiscoverOptions, SkipReason, VideoCandidate, VideoDiscovery, VideoFile, app_and_game_roots,
    collect_video_files, discover_videos, estimate_output_bytes, is_excluded_path,
    mark_likely_duplicates,
};
pub use ffmpeg::{
    EncoderCaps, FfmpegTools, INSTALL_HINT, ProbeInfo, QualityMetric, locate_tools, probe,
};

/// File extensions treated as video.
pub const VIDEO_EXTS: &[&str] = &[
    "mp4", "mkv", "mov", "avi", "wmv", "webm", "m4v", "ts", "mts", "m2ts", "flv", "mpg", "mpeg",
    "3gp",
];

/// Name of the folder that holds originals too big for the Recycle Bin.
pub const HOLDING_FOLDER: &str = "DiskSaver Originals";

/// Metadata key written into every compressed file so it is never offered again.
pub const MARKER_TAG: &str = "disksaver_video";

/// `true` when `name` has a video extension.
pub fn is_video_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, e)| VIDEO_EXTS.iter().any(|v| v.eq_ignore_ascii_case(e)))
}

/// Output codec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetCodec {
    /// Smallest files; plays in Windows (free AV1 extension), browsers, VLC, recent phones/TVs.
    #[default]
    Av1,
    /// Wider device support (older TVs and phones); about 30 % larger than AV1.
    Hevc,
}

impl TargetCodec {
    pub fn label(self) -> &'static str {
        match self {
            Self::Av1 => "AV1",
            Self::Hevc => "HEVC",
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Self::Av1 => "av1",
            Self::Hevc => "hevc",
        }
    }
}

/// Quality preset (constant-quality encoding; file size follows the content).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Quality {
    /// For irreplaceable footage: VMAF ~98.
    High,
    /// Visually identical for almost all footage: VMAF ~95–97.
    #[default]
    Balanced,
    /// Noticeably smaller, small visible loss on grainy footage.
    Small,
}

impl Quality {
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Balanced => "Balanced",
            Self::Small => "Small",
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Balanced => "balanced",
            Self::Small => "small",
        }
    }

    /// The next higher-quality preset (used when a file misses the quality gate).
    pub fn higher(self) -> Option<Self> {
        match self {
            Self::Small => Some(Self::Balanced),
            Self::Balanced => Some(Self::High),
            Self::High => None,
        }
    }

    /// Size multiplier relative to Balanced, for estimates.
    pub fn size_factor(self) -> f64 {
        match self {
            Self::High => 1.45,
            Self::Balanced => 1.0,
            Self::Small => 0.7,
        }
    }
}

/// Which encoder family to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncoderPref {
    /// Best working hardware encoder, then the CPU.
    #[default]
    Auto,
    Nvidia,
    Intel,
    Amd,
    Cpu,
}

/// A concrete ffmpeg encoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncoderKind {
    Av1Nvenc,
    HevcNvenc,
    Av1Qsv,
    HevcQsv,
    Av1Amf,
    HevcAmf,
    SvtAv1,
    X265,
}

impl EncoderKind {
    /// Every encoder in preference order (hardware first).
    pub const ALL: [EncoderKind; 8] = [
        Self::Av1Nvenc,
        Self::Av1Qsv,
        Self::Av1Amf,
        Self::SvtAv1,
        Self::HevcNvenc,
        Self::HevcQsv,
        Self::HevcAmf,
        Self::X265,
    ];

    pub fn ffmpeg_name(self) -> &'static str {
        match self {
            Self::Av1Nvenc => "av1_nvenc",
            Self::HevcNvenc => "hevc_nvenc",
            Self::Av1Qsv => "av1_qsv",
            Self::HevcQsv => "hevc_qsv",
            Self::Av1Amf => "av1_amf",
            Self::HevcAmf => "hevc_amf",
            Self::SvtAv1 => "libsvtav1",
            Self::X265 => "libx265",
        }
    }

    pub fn codec(self) -> TargetCodec {
        match self {
            Self::Av1Nvenc | Self::Av1Qsv | Self::Av1Amf | Self::SvtAv1 => TargetCodec::Av1,
            _ => TargetCodec::Hevc,
        }
    }

    pub fn vendor(self) -> EncoderPref {
        match self {
            Self::Av1Nvenc | Self::HevcNvenc => EncoderPref::Nvidia,
            Self::Av1Qsv | Self::HevcQsv => EncoderPref::Intel,
            Self::Av1Amf | Self::HevcAmf => EncoderPref::Amd,
            Self::SvtAv1 | Self::X265 => EncoderPref::Cpu,
        }
    }

    pub fn is_hardware(self) -> bool {
        self.vendor() != EncoderPref::Cpu
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Av1Nvenc => "NVIDIA NVENC AV1",
            Self::HevcNvenc => "NVIDIA NVENC HEVC",
            Self::Av1Qsv => "Intel Quick Sync AV1",
            Self::HevcQsv => "Intel Quick Sync HEVC",
            Self::Av1Amf => "AMD AMF AV1",
            Self::HevcAmf => "AMD AMF HEVC",
            Self::SvtAv1 => "CPU SVT-AV1",
            Self::X265 => "CPU x265 HEVC",
        }
    }

    /// The CPU encoder producing the same codec (fallback when hardware fails on a file).
    pub fn cpu_fallback(self) -> EncoderKind {
        match self.codec() {
            TargetCodec::Av1 => Self::SvtAv1,
            TargetCodec::Hevc => Self::X265,
        }
    }

    /// The constant-quality value for `q` (lower is better for every encoder used here).
    pub fn quality_value(self, q: Quality) -> u32 {
        let (high, balanced, small) = match self {
            Self::Av1Nvenc => (28, 32, 36),
            Self::HevcNvenc => (23, 26, 29),
            Self::Av1Qsv => (26, 30, 34),
            Self::HevcQsv => (22, 25, 28),
            // AV1 AMF quantizers use the 0–255 AV1 qindex scale.
            Self::Av1Amf => (100, 120, 140),
            Self::HevcAmf => (22, 25, 28),
            Self::SvtAv1 => (28, 34, 40),
            Self::X265 => (21, 24, 27),
        };
        match q {
            Quality::High => high,
            Quality::Balanced => balanced,
            Quality::Small => small,
        }
    }

    /// Pixel format for 10-bit (preferred: less banding, better compression) or 8-bit output.
    pub fn pix_fmt(self, ten_bit: bool) -> &'static str {
        match (self.is_hardware(), ten_bit) {
            (true, true) => "p010le",
            (true, false) => "nv12",
            (false, true) => "yuv420p10le",
            (false, false) => "yuv420p",
        }
    }

    /// Encoder arguments after `-c:v <name>` (rate control, preset, pixel format).
    pub fn encode_args(self, q: Quality, ten_bit: bool) -> Vec<String> {
        let v = self.quality_value(q).to_string();
        let mut a: Vec<String> = match self {
            Self::Av1Nvenc | Self::HevcNvenc => [
                "-preset",
                "p5",
                "-tune",
                "hq",
                "-rc",
                "vbr",
                "-cq",
                &v,
                "-b:v",
                "0",
                "-spatial-aq",
                "1",
                "-temporal-aq",
                "1",
                "-rc-lookahead",
                "32",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            Self::Av1Qsv | Self::HevcQsv => ["-preset", "slow", "-global_quality", &v]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            Self::Av1Amf => [
                "-quality", "quality", "-rc", "cqp", "-qp_i", &v, "-qp_p", &v, "-qp_b", &v,
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            Self::HevcAmf => [
                "-quality", "quality", "-rc", "cqp", "-qp_i", &v, "-qp_p", &v,
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            Self::SvtAv1 => ["-preset", "8", "-crf", &v]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            Self::X265 => [
                "-preset",
                "medium",
                "-crf",
                &v,
                "-x265-params",
                "log-level=error",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        };
        if matches!(self, Self::HevcNvenc | Self::HevcQsv | Self::HevcAmf) {
            a.extend([
                "-profile:v".into(),
                if ten_bit { "main10" } else { "main" }.into(),
            ]);
        }
        a.extend(["-pix_fmt".into(), self.pix_fmt(ten_bit).into()]);
        a
    }
}
