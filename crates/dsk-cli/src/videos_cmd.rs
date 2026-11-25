#![forbid(unsafe_code)]

//! `disksaver videos` (P9.11): find big, inefficiently encoded videos on every drive, preview the
//! result, and compress the ones you pick with a verified AV1/HEVC re-encode.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use clap::{Args, ValueEnum};
use dsk_core::clean::{ActionJournal, DenyContext};
use dsk_core::video::{
    BatchReport, CompressOptions, DiscoverOptions, EncoderPref, OriginalDisposition,
    OriginalPolicy, Quality, SkipReason, TargetCodec, VideoCandidate, VideoDiscovery, VideoEngine,
    VideoFile, VideoJobOutcome, VideoJobStatus, VideoPhase, app_and_game_roots,
    calibration_category, collect_video_files, discover_videos, is_video_name, list_held_originals,
    purge_held_originals, sample_video,
};

use crate::reclaim_cmd::parse_size;
use crate::report::fmt_bytes;
use crate::{MethodArg, scan_for_insights, setup_cancel_flag};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum CodecArg {
    Av1,
    Hevc,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum QualityArg {
    High,
    Balanced,
    Small,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum EncoderArg {
    Auto,
    Nvidia,
    Intel,
    Amd,
    Cpu,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OriginalsArg {
    /// Recycle Bin; originals too big for it go to the holding folder
    Recycle,
    /// Always the "DiskSaver Originals" holding folder on the same drive
    Hold,
    /// Keep both files side by side (frees nothing until you delete one)
    Keep,
}

#[derive(Args, Debug)]
pub struct VideosArgs {
    /// Drives, folders, or video files (default: every drive)
    pub paths: Vec<PathBuf>,
    /// Only videos at least this big
    #[arg(long, default_value = "200MiB", value_parser = parse_size)]
    pub min_size: u64,
    /// Output codec (AV1 is smallest; HEVC plays on more old TVs and phones)
    #[arg(long, value_enum, default_value = "av1")]
    pub codec: CodecArg,
    /// Quality preset (high for irreplaceable footage)
    #[arg(long, value_enum, default_value = "balanced")]
    pub quality: QualityArg,
    /// Encoder family
    #[arg(long, value_enum, default_value = "auto")]
    pub encoder: EncoderArg,
    /// Minimum VMAF the new file must reach (mapped to SSIM when ffmpeg lacks libvmaf)
    #[arg(long, default_value_t = 93.0)]
    pub min_vmaf: f64,
    /// What happens to originals after a verified replacement
    #[arg(long, value_enum, default_value = "recycle")]
    pub originals: OriginalsArg,
    /// Encode a short preview of the given video and report its real size and quality
    #[arg(long)]
    pub sample: bool,
    /// Preview length in seconds
    #[arg(long, default_value_t = 30.0)]
    pub sample_secs: f64,
    /// Preview start in seconds (default: the middle)
    #[arg(long)]
    pub at: Option<f64>,
    /// Compress the listed videos (or the given files); a dry run unless --yes
    #[arg(long)]
    pub compress: bool,
    /// With --compress: only the N biggest savings
    #[arg(long)]
    pub top: Option<usize>,
    /// Replace files for real
    #[arg(long)]
    pub yes: bool,
    /// Keep encoding on battery power
    #[arg(long)]
    pub allow_battery: bool,
    /// Show originals parked in "DiskSaver Originals" folders
    #[arg(long)]
    pub held: bool,
    /// With --held: permanently delete held originals whose replacement is intact (needs --yes)
    #[arg(long)]
    pub purge: bool,
    /// Also list videos that were skipped, with the reason
    #[arg(long)]
    pub show_skipped: bool,
    /// Rows to print
    #[arg(long, default_value_t = 40)]
    pub rows: usize,
    /// ffmpeg folder or ffmpeg.exe (default: PATH, WinGet, Scoop, Chocolatey)
    #[arg(long)]
    pub ffmpeg: Option<PathBuf>,
    #[arg(long, default_value = "auto", value_enum)]
    pub method: MethodArg,
    /// Journal database
    #[arg(long)]
    pub journal: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

fn codec(a: CodecArg) -> TargetCodec {
    match a {
        CodecArg::Av1 => TargetCodec::Av1,
        CodecArg::Hevc => TargetCodec::Hevc,
    }
}

fn quality(a: QualityArg) -> Quality {
    match a {
        QualityArg::High => Quality::High,
        QualityArg::Balanced => Quality::Balanced,
        QualityArg::Small => Quality::Small,
    }
}

fn encoder(a: EncoderArg) -> EncoderPref {
    match a {
        EncoderArg::Auto => EncoderPref::Auto,
        EncoderArg::Nvidia => EncoderPref::Nvidia,
        EncoderArg::Intel => EncoderPref::Intel,
        EncoderArg::Amd => EncoderPref::Amd,
        EncoderArg::Cpu => EncoderPref::Cpu,
    }
}

/// `2h47m`, `17m58s`, `42s`.
pub fn fmt_duration(secs: f64) -> String {
    let s = secs.max(0.0).round() as u64;
    match (s / 3600, (s % 3600) / 60, s % 60) {
        (0, 0, sec) => format!("{sec}s"),
        (0, m, sec) => format!("{m}m{sec:02}s"),
        (h, m, _) => format!("{h}h{m:02}m"),
    }
}

/// Every mounted drive as `X:\`.
fn all_drives() -> Vec<PathBuf> {
    dsk_core::list_volumes()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let r = v.root.trim_start_matches(r"\\?\").to_string();
            (r.len() >= 2).then(|| PathBuf::from(format!("{}\\", &r[..2])))
        })
        .collect()
}

fn journal_path(args: &VideosArgs) -> PathBuf {
    args.journal
        .clone()
        .unwrap_or_else(ActionJournal::default_path)
}

fn engine_line(e: &VideoEngine, c: TargetCodec, p: EncoderPref, min_vmaf: f64) -> String {
    let enc = e
        .encoder_for(c, p)
        .map(|x| {
            format!(
                "{} ({}-bit)",
                x.kind.label(),
                if x.ten_bit { 10 } else { 8 }
            )
        })
        .unwrap_or_else(|| format!("no working {} encoder", c.label()));
    format!(
        "{} · {} · quality check: {} (gate {})",
        e.version.as_deref().unwrap_or("ffmpeg"),
        enc,
        e.metric.label(),
        match e.metric {
            dsk_core::video::QualityMetric::Vmaf => format!("{min_vmaf:.0}"),
            m => format!("{:.3}", m.gate(min_vmaf)),
        }
    )
}

fn print_candidates(d: &VideoDiscovery, rows: usize, show_skipped: bool) {
    if d.candidates.is_empty() {
        println!("No videos worth compressing were found.");
    } else {
        println!(
            "{:>10} {:>10} {:>10} {:>7}  {:<22} {:>6}  Path",
            "Size", "After ~", "Saves ~", "Length", "Video", "Mb/s"
        );
        for c in d.candidates.iter().take(rows) {
            println!(
                "{:>10} {:>10} {:>10} {:>7}  {:<22} {:>6.1}  {}",
                fmt_bytes(c.bytes),
                fmt_bytes(c.est_output_bytes),
                fmt_bytes(c.est_saving_bytes()),
                fmt_duration(c.duration_secs()),
                truncate(&c.video_summary(), 22),
                c.bitrate_mbps(),
                c.path.display()
            );
        }
        if d.candidates.len() > rows {
            println!("... and {} more (--rows N)", d.candidates.len() - rows);
        }
        let total: u64 = d.candidates.iter().map(|c| c.bytes).sum();
        let hours: f64 = d
            .candidates
            .iter()
            .map(VideoCandidate::duration_secs)
            .sum::<f64>()
            / 3600.0;
        println!(
            "\n{} videos can shrink: {} -> about {} (saves ~{}), {:.1} h of footage.",
            d.candidates.len(),
            fmt_bytes(total),
            fmt_bytes(total.saturating_sub(d.est_saving_bytes)),
            fmt_bytes(d.est_saving_bytes),
            hours
        );
    }
    if !d.skipped.is_empty() {
        if show_skipped {
            println!("\nSkipped:");
            for c in d.skipped.iter().take(rows) {
                println!(
                    "{:>10}  {}  ({})",
                    fmt_bytes(c.bytes),
                    c.path.display(),
                    c.skip.as_ref().map(|s| s.label()).unwrap_or_default()
                );
            }
        } else {
            println!(
                "{} videos skipped (already efficient, in use, ...): --show-skipped lists them.",
                d.skipped.len()
            );
        }
    }
    if d.excluded_app_files > 0 {
        println!(
            "{} videos inside app, game, and system folders were left out.",
            d.excluded_app_files
        );
    }
    let dups = d
        .skipped
        .iter()
        .filter(|c| matches!(c.skip, Some(SkipReason::LikelyDuplicate(_))))
        .count();
    if dups > 0 {
        println!(
            "{dups} videos have an identical copy and were held back: remove the copies first \
             (disksaver dupes <folder>), then search again."
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).chain(['…']).collect()
    }
}

fn print_outcome(o: &VideoJobOutcome) {
    let mark = match o.status {
        VideoJobStatus::Replaced | VideoJobStatus::KeptBoth => "✔",
        VideoJobStatus::Failed => "✘",
        _ => "·",
    };
    let score = o
        .score
        .zip(o.metric)
        .map(|(s, m)| format!(", {} {s:.1}", m.label()))
        .unwrap_or_default();
    let enc = o
        .encoder
        .map(|e| format!(", {}", e.label()))
        .unwrap_or_default();
    let sizes = if o.new_bytes > 0 {
        format!(
            "{} -> {}",
            fmt_bytes(o.original_bytes),
            fmt_bytes(o.new_bytes)
        )
    } else {
        fmt_bytes(o.original_bytes)
    };
    let disp = match &o.disposition {
        OriginalDisposition::Recycled => "; original in the Recycle Bin".to_string(),
        OriginalDisposition::Held(p) => format!("; original held at {}", p.display()),
        _ => String::new(),
    };
    eprint!("\r{:<100}\r", "");
    println!(
        "{mark} {:<10} {sizes} ({}{score}{enc}{disp})  {}",
        o.status.label(),
        o.quality.label(),
        o.output_path.as_ref().unwrap_or(&o.path).display()
    );
    if let Some(m) = &o.message {
        println!("    {m}");
    }
}

fn print_batch_summary(r: &BatchReport) {
    println!(
        "\nReplaced {} of {} videos, saving {}.",
        r.replaced,
        r.outcomes.len(),
        fmt_bytes(r.saved_bytes)
    );
    let kept: Vec<&VideoJobOutcome> = r
        .outcomes
        .iter()
        .filter(|o| o.status == VideoJobStatus::KeptBoth)
        .collect();
    if !kept.is_empty() {
        let potential: u64 = kept
            .iter()
            .map(|o| o.original_bytes.saturating_sub(o.new_bytes))
            .sum();
        println!(
            "{} compressed copies were written next to their originals; deleting the originals would free {}.",
            kept.len(),
            fmt_bytes(potential)
        );
    }
    if r.recycle_bin_bytes > 0 {
        println!(
            "{} of originals are in the Recycle Bin: the space comes back when you empty it.",
            fmt_bytes(r.recycle_bin_bytes)
        );
    }
    if r.held_bytes > 0 {
        println!(
            "{} of originals were too big for the Recycle Bin and are in \"DiskSaver Originals\" folders.\n\
             Check the new files, then: disksaver videos --held --purge --yes",
            fmt_bytes(r.held_bytes)
        );
    }
    if let Some(s) = &r.stopped {
        println!("Stopped early: {s}.");
    }
}

fn run_held(args: &VideosArgs) {
    let jp = journal_path(args);
    let mut j = match ActionJournal::open_existing(&jp) {
        Ok(Some(j)) => j,
        Ok(None) => {
            println!("No held originals (no journal yet).");
            return;
        }
        Err(e) => crate::fail_with_error("Cannot open the journal", &e),
    };
    if args.purge {
        if !args.yes {
            match purge_held_originals(&mut j, true) {
                Ok(r) => {
                    println!(
                        "Would permanently delete {} held originals ({}). Run again with --yes.",
                        r.purged,
                        fmt_bytes(r.purged_bytes)
                    );
                    for e in &r.errors {
                        println!("  {e}");
                    }
                }
                Err(e) => crate::fail_with_error("Purge failed", &e),
            }
            return;
        }
        match purge_held_originals(&mut j, false) {
            Ok(r) => {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&r).unwrap());
                } else {
                    println!(
                        "Deleted {} held originals, freeing {}.",
                        r.purged,
                        fmt_bytes(r.purged_bytes)
                    );
                    for e in &r.errors {
                        println!("  {e}");
                    }
                }
                if !r.errors.is_empty() {
                    std::process::exit(1);
                }
            }
            Err(e) => crate::fail_with_error("Purge failed", &e),
        }
        return;
    }
    match list_held_originals(&j) {
        Ok(items) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&items).unwrap());
                return;
            }
            if items.is_empty() {
                println!("No held originals.");
                return;
            }
            let mut total = 0;
            for it in &items {
                total += if it.held_exists { it.bytes } else { 0 };
                println!(
                    "{:>10}  {}  -> replaced by {}{}",
                    fmt_bytes(it.bytes),
                    it.held_path.display(),
                    it.output_path.display(),
                    if !it.held_exists {
                        "  (already deleted)"
                    } else if !it.replacement_ok {
                        "  (replacement missing or changed: kept)"
                    } else {
                        ""
                    }
                );
            }
            println!(
                "\n{} held. Delete the ones with an intact replacement: disksaver videos --held --purge --yes",
                fmt_bytes(total)
            );
        }
        Err(e) => crate::fail_with_error("Cannot read held originals", &e),
    }
}

pub fn run_videos(args: VideosArgs) {
    if args.held {
        run_held(&args);
        return;
    }
    let cancel = setup_cancel_flag();
    let tcodec = codec(args.codec);
    let tquality = quality(args.quality);
    let tenc = encoder(args.encoder);

    let engine = VideoEngine::locate(args.ffmpeg.as_deref());
    match &engine {
        Some(e) => eprintln!("{}", engine_line(e, tcodec, tenc, args.min_vmaf)),
        None => {
            eprintln!(
                "ffmpeg was not found. Install it with:  {}\n(or pass --ffmpeg <folder>). Listing sizes only.",
                dsk_core::video::INSTALL_HINT
            );
            if args.sample || args.compress {
                std::process::exit(2);
            }
        }
    }

    let opts = CompressOptions {
        codec: tcodec,
        quality: tquality,
        encoder: tenc,
        min_vmaf: args.min_vmaf,
        originals: match args.originals {
            OriginalsArg::Recycle => OriginalPolicy::Recycle,
            OriginalsArg::Hold => OriginalPolicy::Hold,
            OriginalsArg::Keep => OriginalPolicy::KeepBoth,
        },
        allow_battery: args.allow_battery,
        journal_path: Some(journal_path(&args)),
        ..Default::default()
    };

    let (files, roots): (Vec<PathBuf>, Vec<PathBuf>) =
        args.paths.iter().cloned().partition(|p| p.is_file());

    if args.sample {
        let Some(file) = files.first() else {
            eprintln!("--sample needs a video file: disksaver videos \"<file>\" --sample");
            std::process::exit(2);
        };
        let e = engine.as_ref().unwrap();
        eprintln!("Encoding a {:.0}s preview...", args.sample_secs);
        match sample_video(e, file, &opts, args.at, args.sample_secs, &cancel) {
            Ok(s) => {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&s).unwrap());
                    return;
                }
                println!(
                    "{:.0}s from {} with {}: {} -> {} ({:.0} % of the original, {:.1}x real time)",
                    s.seconds,
                    fmt_duration(s.start_secs),
                    s.encoder.label(),
                    fmt_bytes(s.source_slice_bytes),
                    fmt_bytes(s.sample_bytes),
                    s.ratio * 100.0,
                    s.speed
                );
                match s.score {
                    Some(v) => println!(
                        "{} {:.1} ({})",
                        s.metric.label(),
                        v,
                        if v >= s.metric.gate(args.min_vmaf) {
                            "passes the gate"
                        } else {
                            "under the gate: try --quality high"
                        }
                    ),
                    None => println!("Quality could not be scored."),
                }
                let bytes = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
                println!(
                    "Whole file: {} -> about {} (saves ~{}).\nWatch the preview: {}",
                    fmt_bytes(bytes),
                    fmt_bytes(s.projected_output_bytes),
                    fmt_bytes(bytes.saturating_sub(s.projected_output_bytes)),
                    s.sample_path.display()
                );
            }
            Err(e) => crate::fail_with_error("Preview failed", &e),
        }
        return;
    }

    // Collect files: explicit ones as given, folders and drives through a scan.
    let mut videos: Vec<VideoFile> = files
        .iter()
        .filter(|f| {
            let ok = f
                .file_name()
                .is_some_and(|n| is_video_name(&n.to_string_lossy()));
            if !ok {
                eprintln!("Not a video file: {}", f.display());
            }
            ok
        })
        .map(|f| VideoFile {
            bytes: std::fs::metadata(f).map(|m| m.len()).unwrap_or(0),
            path: f.clone(),
            mtime_min2000: 0,
        })
        .collect();
    let calibration = ActionJournal::open_existing(&journal_path(&args))
        .ok()
        .flatten()
        .and_then(|j| {
            j.calibration_ratio(&calibration_category(tcodec, tquality), 20)
                .ok()
                .flatten()
        });
    let mut dopts = DiscoverOptions {
        min_bytes: args.min_size,
        codec: tcodec,
        quality: tquality,
        calibration,
        ..Default::default()
    };
    let roots = if roots.is_empty() && files.is_empty() {
        all_drives()
    } else {
        roots
    };
    let mut excluded = 0;
    for root in &roots {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if !args.json {
            eprintln!("Scanning {}...", root.display());
        }
        let report = scan_for_insights(root, args.method, false, args.json, &cancel);
        eprint!("\r{:<60}\r", "");
        dopts.exclude_roots = app_and_game_roots(&report.index);
        let (found, ex) = collect_video_files(&report.index, &dopts);
        excluded += ex;
        videos.extend(found);
    }
    let journal = ActionJournal::open_existing(&journal_path(&args))
        .ok()
        .flatten();
    let total = videos.len();
    let progress = |done: usize, total: usize| {
        if done.is_multiple_of(10) || done == total {
            eprint!("\rInspecting videos {done}/{total}");
            let _ = std::io::stderr().flush();
        }
    };
    let mut d = discover_videos(
        videos,
        engine.as_ref().map(|e| &e.tools),
        &dopts,
        journal.as_ref(),
        &progress,
        &cancel,
    );
    drop(journal);
    d.excluded_app_files = excluded;
    if total > 0 {
        eprint!("\r{:<60}\r", "");
    }

    if !args.compress {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&d).unwrap());
            return;
        }
        print_candidates(&d, args.rows, args.show_skipped);
        if let Some(first) = d.candidates.first() {
            let where_ = if args.paths.is_empty() {
                String::new()
            } else {
                args.paths
                    .iter()
                    .map(|p| format!("\"{}\" ", p.display()))
                    .collect::<String>()
            };
            println!(
                "\nPreview one:     disksaver videos \"{}\" --sample\n\
                 Compress them:   disksaver videos {where_}--compress --yes   (--top 10 for the biggest only)\n\
                 Originals go to the Recycle Bin; nothing is replaced until the new file passes the quality check.",
                first.path.display()
            );
        }
        return;
    }

    for c in &d.skipped {
        if files.contains(&c.path) {
            eprintln!(
                "Skipping {}: {}",
                c.path.display(),
                c.skip.as_ref().map(|s| s.label()).unwrap_or_default()
            );
        }
    }
    let selected: Vec<&VideoCandidate> = d
        .candidates
        .iter()
        .take(args.top.unwrap_or(usize::MAX))
        .collect();
    if selected.is_empty() {
        println!("Nothing to compress.");
        return;
    }
    let total_bytes: u64 = selected.iter().map(|c| c.bytes).sum();
    let saving: u64 = selected.iter().map(|c| c.est_saving_bytes()).sum();
    let hours: f64 = selected.iter().map(|c| c.duration_secs()).sum::<f64>() / 3600.0;
    if !args.yes {
        for c in &selected {
            println!(
                "{:>10} -> ~{:>10}  {}",
                fmt_bytes(c.bytes),
                fmt_bytes(c.est_output_bytes),
                c.path.display()
            );
        }
        println!(
            "\nWould compress {} videos ({}, {:.1} h of footage) to {} {} and save about {}.\n\
             Originals: {}. Run again with --yes to start.",
            selected.len(),
            fmt_bytes(total_bytes),
            hours,
            tcodec.label(),
            tquality.label(),
            fmt_bytes(saving),
            match opts.originals {
                OriginalPolicy::Recycle =>
                    "Recycle Bin (too-big ones go to a \"DiskSaver Originals\" folder)",
                OriginalPolicy::Hold => "moved to a \"DiskSaver Originals\" folder",
                OriginalPolicy::KeepBoth => "kept next to the new files",
            }
        );
        return;
    }

    let e = engine.as_ref().unwrap();
    let paths: Vec<PathBuf> = selected.iter().map(|c| c.path.clone()).collect();
    let deny = DenyContext::default();
    let json = args.json;
    let report = dsk_core::video::compress_batch(
        e,
        &paths,
        &opts,
        &deny,
        &mut |p| {
            if json {
                return;
            }
            let name = p
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let what = match &p.phase {
                VideoPhase::Waiting(w) => w.clone(),
                VideoPhase::Encoding => {
                    format!("encoding {:>3.0}% {:>4.1}x", p.fraction * 100.0, p.speed)
                }
                VideoPhase::Verifying => "checking quality".into(),
                VideoPhase::Replacing => "replacing".into(),
            };
            eprint!(
                "\r[{}/{}] {:<28} {}",
                p.file_index + 1,
                p.file_count,
                what,
                truncate(&name, 50)
            );
            let _ = std::io::stderr().flush();
        },
        &mut |o| {
            if !json {
                print_outcome(o);
            }
        },
        &cancel,
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_batch_summary(&report);
    }
    if report
        .outcomes
        .iter()
        .any(|o| o.status == VideoJobStatus::Failed)
    {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(fmt_duration(42.4), "42s");
        assert_eq!(fmt_duration(1078.0), "17m58s");
        assert_eq!(fmt_duration(10_028.0), "2h47m");
    }

    #[test]
    fn long_text_is_truncated() {
        assert_eq!(truncate("h264 1920x1080@30", 22), "h264 1920x1080@30");
        assert_eq!(truncate("abcdefghij", 5).chars().count(), 5);
    }
}
