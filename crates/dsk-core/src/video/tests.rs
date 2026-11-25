use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::compress::{build_encode_args, output_container};
use super::discover::{collect_video_files, estimate_output_bytes, is_excluded_path};
use super::ffmpeg::{
    AudioStreamInfo, EncoderCaps, ProbeInfo, QualityMetric, SubtitleStreamInfo, VideoStreamInfo,
    choose_encoder, parse_probe_json, parse_rate, parse_score, plan_segments,
};
use super::*;
use crate::clean::DenyContext;
use crate::index::{EntryBatch, IndexBuilder, NameArena, NodeFlags, RawEntry};
use crate::time::{FILETIME_EPOCH_2000, INTERVALS_PER_MINUTE};
use crate::volume::VolumeInfo;

const MIB: u64 = 1 << 20;
const NOW: u32 = 14_000_000;

// ---------------------------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------------------------

#[test]
fn video_names_and_presets() {
    assert!(is_video_name("IMG_2860.MOV"));
    assert!(is_video_name("rec.mkv"));
    assert!(!is_video_name("notes.txt"));
    assert!(!is_video_name("mp4"));
    assert_eq!(Quality::Small.higher(), Some(Quality::Balanced));
    assert_eq!(Quality::Balanced.higher(), Some(Quality::High));
    assert_eq!(Quality::High.higher(), None);
}

#[test]
fn encoder_args_match_measured_settings() {
    let a = EncoderKind::Av1Nvenc.encode_args(Quality::Balanced, true);
    let s = a.join(" ");
    assert!(s.contains("-cq 32"), "{s}");
    assert!(s.contains("-b:v 0"));
    assert!(s.ends_with("-pix_fmt p010le"));
    let h = EncoderKind::HevcNvenc
        .encode_args(Quality::High, false)
        .join(" ");
    assert!(h.contains("-cq 23") && h.contains("-profile:v main") && h.contains("nv12"));
    let cpu = EncoderKind::SvtAv1
        .encode_args(Quality::Small, true)
        .join(" ");
    assert!(cpu.contains("-crf 40") && cpu.contains("yuv420p10le"));
    assert_eq!(EncoderKind::Av1Nvenc.cpu_fallback(), EncoderKind::SvtAv1);
    assert_eq!(EncoderKind::HevcQsv.cpu_fallback(), EncoderKind::X265);
    // Every encoder: lower value = higher quality.
    for k in EncoderKind::ALL {
        assert!(k.quality_value(Quality::High) < k.quality_value(Quality::Balanced));
        assert!(k.quality_value(Quality::Balanced) < k.quality_value(Quality::Small));
    }
}

#[test]
fn encoder_choice_prefers_hardware_and_honours_vendor() {
    let caps = [
        EncoderCaps {
            kind: EncoderKind::SvtAv1,
            ten_bit: true,
        },
        EncoderCaps {
            kind: EncoderKind::HevcQsv,
            ten_bit: false,
        },
        EncoderCaps {
            kind: EncoderKind::Av1Nvenc,
            ten_bit: true,
        },
    ];
    let pick = |c, p| choose_encoder(&caps, c, p).map(|e| e.kind);
    assert_eq!(
        pick(TargetCodec::Av1, EncoderPref::Auto),
        Some(EncoderKind::Av1Nvenc)
    );
    assert_eq!(
        pick(TargetCodec::Av1, EncoderPref::Cpu),
        Some(EncoderKind::SvtAv1)
    );
    assert_eq!(
        pick(TargetCodec::Hevc, EncoderPref::Auto),
        Some(EncoderKind::HevcQsv)
    );
    assert_eq!(pick(TargetCodec::Hevc, EncoderPref::Nvidia), None);
}

const IPHONE_JSON: &str = r#"{
  "streams": [
    {"index": 0, "codec_name": "h264", "codec_type": "video", "width": 1920, "height": 1080,
     "pix_fmt": "yuv420p", "color_range": "tv", "color_space": "bt709", "color_transfer": "bt709",
     "color_primaries": "bt709", "r_frame_rate": "30/1", "avg_frame_rate": "26643/889",
     "bit_rate": "20683218", "disposition": {"attached_pic": 0},
     "side_data_list": [{"side_data_type": "Display Matrix", "rotation": -90}]},
    {"index": 1, "codec_name": "aac", "codec_type": "audio", "channels": 2, "bit_rate": "96000"},
    {"index": 2, "codec_type": "data", "codec_tag_string": "mebx"},
    {"index": 3, "codec_name": "mjpeg", "codec_type": "video", "width": 320, "height": 240,
     "disposition": {"attached_pic": 1}},
    {"index": 4, "codec_name": "mov_text", "codec_type": "subtitle"}
  ],
  "format": {"format_name": "mov,mp4,m4a,3gp,3g2,mj2", "duration": "1078.263333",
             "size": "2826379264", "bit_rate": "20970000",
             "tags": {"com.apple.quicktime.model": "iPhone 6", "creation_time": "2015-08-01T10:00:00Z"}}
}"#;

#[test]
fn probe_json_is_parsed_like_ffprobe_reports_it() {
    let i = parse_probe_json(IPHONE_JSON).unwrap();
    let v = i.video.as_ref().unwrap();
    assert_eq!(
        (v.index, v.codec.as_str(), v.width, v.height),
        (0, "h264", 1920, 1080)
    );
    assert!((v.fps - 29.97).abs() < 0.01, "{}", v.fps);
    assert_eq!(v.rotation, -90);
    assert!(!v.dolby_vision);
    assert_eq!(i.audio.len(), 1);
    assert_eq!(i.subtitles.len(), 1);
    assert_eq!(i.tags["com.apple.quicktime.model"], "iPhone 6");
    assert!(!i.is_disksaver_output());
    assert!(!i.is_hdr());
    assert_eq!(i.video_bitrate(), 20_683_218);
    assert!(parse_probe_json("not json").is_err());

    let mut marked = i.clone();
    marked
        .tags
        .insert(MARKER_TAG.to_string(), "av1-balanced".into());
    assert!(marked.is_disksaver_output());
    assert_eq!(parse_rate("30000/1001").round(), 30.0);
    assert_eq!(parse_rate("0/0"), 0.0);
}

#[test]
fn dolby_vision_side_data_is_detected() {
    let j = IPHONE_JSON.replace(
        r#"{"side_data_type": "Display Matrix", "rotation": -90}"#,
        r#"{"side_data_type": "DOVI configuration record"}"#,
    );
    assert!(parse_probe_json(&j).unwrap().video.unwrap().dolby_vision);
}

#[test]
fn scores_are_parsed_from_ffmpeg_logs() {
    let vmaf = "[Parsed_libvmaf_4 @ 0000] VMAF score: 96.933967\n";
    assert_eq!(parse_score(QualityMetric::Vmaf, vmaf), Some(96.933967));
    let ssim =
        "[Parsed_ssim_4 @ 0] SSIM Y:0.981 (17.2) U:0.99 (20.1) V:0.99 (20.4) All:0.985342 (18.3)\n";
    assert_eq!(parse_score(QualityMetric::Ssim, ssim), Some(0.985342));
    assert_eq!(parse_score(QualityMetric::Vmaf, "nothing"), None);
    assert_eq!(QualityMetric::Vmaf.gate(93.0), 93.0);
    assert!((QualityMetric::Ssim.gate(93.0) - 0.97).abs() < 1e-9);
}

#[test]
fn segments_cover_start_middle_and_end() {
    let short = plan_segments(20.0);
    assert_eq!(short.len(), 1);
    assert_eq!(short[0].len, 20.0);
    let long = plan_segments(10_028.0);
    assert_eq!(long.len(), 5);
    assert!(long[0].ref_start < 300.0);
    assert!(long.last().unwrap().ref_start + long.last().unwrap().len <= 10_028.0);
    assert!(long.iter().all(|s| s.enc_start == s.ref_start));
}

fn info(codec: &str, w: u32, h: u32, fps: f64, mbps: f64, secs: f64) -> ProbeInfo {
    let bytes = (mbps * 1e6 / 8.0 * secs) as u64;
    ProbeInfo {
        format_name: "mov".into(),
        duration_secs: secs,
        bit_rate: (mbps * 1e6) as u64,
        size_bytes: bytes,
        video: Some(VideoStreamInfo {
            codec: codec.into(),
            width: w,
            height: h,
            fps,
            ..Default::default()
        }),
        audio: vec![AudioStreamInfo {
            index: 1,
            codec: "aac".into(),
            channels: 2,
            bit_rate: 128_000,
        }],
        ..Default::default()
    }
}

#[test]
fn estimates_are_conservative_against_measurements() {
    // iPhone 1080p30 H.264 at 21 Mbit/s: measured 23 % of the original at Balanced AV1.
    let i = info("h264", 1920, 1080, 30.0, 21.0, 1078.0);
    let est = estimate_output_bytes(&i, TargetCodec::Av1, Quality::Balanced);
    let ratio = est as f64 / i.size_bytes as f64;
    assert!((0.23..0.40).contains(&ratio), "ratio {ratio}");
    // OBS 2560x1600@60 at 50 Mbit/s: measured 3 %; the estimate stays well under the original.
    let obs = info("h264", 2560, 1600, 60.0, 50.2, 10_028.0);
    let r = estimate_output_bytes(&obs, TargetCodec::Av1, Quality::Balanced) as f64
        / obs.size_bytes as f64;
    assert!((0.03..0.45).contains(&r), "ratio {r}");
    // HEVC output is bigger than AV1, High bigger than Balanced.
    let hevc = estimate_output_bytes(&i, TargetCodec::Hevc, Quality::Balanced);
    let high = estimate_output_bytes(&i, TargetCodec::Av1, Quality::High);
    assert!(hevc > est && high > est);
    // An efficient HEVC phone video barely shrinks.
    let eff = info("hevc", 1920, 1080, 30.0, 8.0, 600.0);
    let e = estimate_output_bytes(&eff, TargetCodec::Av1, Quality::Balanced) as f64
        / eff.size_bytes as f64;
    assert!(e > 0.6, "efficient source ratio {e}");
    // Never larger than the source; no video means no estimate.
    let tiny = info("h264", 640, 360, 30.0, 0.2, 60.0);
    assert!(estimate_output_bytes(&tiny, TargetCodec::Hevc, Quality::High) <= tiny.size_bytes);
    let mut none = i.clone();
    none.video = None;
    assert_eq!(
        estimate_output_bytes(&none, TargetCodec::Av1, Quality::Balanced),
        none.size_bytes
    );
}

#[test]
fn containers_and_audio_follow_the_source() {
    let i = info("h264", 1920, 1080, 30.0, 21.0, 60.0);
    assert_eq!(output_container("MOV", TargetCodec::Av1, &i), "mp4");
    assert_eq!(output_container("mkv", TargetCodec::Hevc, &i), "mkv");
    assert_eq!(output_container("avi", TargetCodec::Av1, &i), "mp4");
    let mut webm = i.clone();
    webm.audio[0].codec = "opus".into();
    assert_eq!(output_container("webm", TargetCodec::Av1, &webm), "webm");
    assert_eq!(output_container("webm", TargetCodec::Hevc, &webm), "mkv");
    let mut pgs = i.clone();
    pgs.subtitles.push(SubtitleStreamInfo {
        index: 2,
        codec: "hdmv_pgs_subtitle".into(),
    });
    assert_eq!(output_container("mp4", TargetCodec::Av1, &pgs), "mkv");
    assert!(audio_needs_reencode("pcm_s16le", "mp4"));
    assert!(audio_needs_reencode("pcm_s16le", "mkv"));
    assert!(audio_needs_reencode("wmav2", "mp4"));
    assert!(!audio_needs_reencode("aac", "mp4"));
    assert!(!audio_needs_reencode("dts", "mkv"));
    assert!(audio_needs_reencode("aac", "webm"));
}

#[test]
fn encode_args_keep_streams_metadata_and_mark_the_output() {
    let mut i = parse_probe_json(IPHONE_JSON).unwrap();
    i.audio.push(AudioStreamInfo {
        index: 5,
        codec: "pcm_s16le".into(),
        channels: 2,
        bit_rate: 1_536_000,
    });
    let enc = EncoderCaps {
        kind: EncoderKind::HevcNvenc,
        ten_bit: true,
    };
    let a: Vec<String> = build_encode_args(
        &i,
        Path::new(r"D:\v\IMG.MOV"),
        Path::new(r"D:\v\IMG.dsk-tmp.mp4"),
        enc,
        Quality::Balanced,
        "mp4",
        &[],
    )
    .into_iter()
    .map(|s| s.to_string_lossy().into_owned())
    .collect();
    let s = a.join(" ");
    assert!(s.starts_with(r"-hwaccel auto -i D:\v\IMG.MOV"), "{s}");
    assert!(s.contains("-map 0:0 -map 0:1 -map 0:5 -map 0:4"), "{s}");
    assert!(
        !s.contains("0:3"),
        "attached picture must not be mapped: {s}"
    );
    assert!(s.contains("-map_metadata 0 -map_chapters 0"));
    assert!(
        s.contains("-c:a:0 copy") && s.contains("-c:a:1 aac -b:a:1 192k"),
        "{s}"
    );
    assert!(s.contains("-c:s mov_text"));
    assert!(s.contains("-tag:v hvc1"));
    assert!(s.contains("-fps_mode passthrough"));
    assert!(s.contains(&format!("{MARKER_TAG}=hevc-balanced")));
    assert!(s.contains("+use_metadata_tags+faststart"));
    assert!(s.contains("-color_primaries bt709"));
    assert_eq!(a.last().unwrap(), r"D:\v\IMG.dsk-tmp.mp4");

    let sample: Vec<String> = build_encode_args(
        &i,
        Path::new("a.mp4"),
        Path::new("b.mkv"),
        enc,
        Quality::High,
        "mkv",
        &["-ss".into(), "10.000".into()],
    )
    .into_iter()
    .map(|s| s.to_string_lossy().into_owned())
    .collect();
    let ss = sample.join(" ");
    assert!(ss.starts_with("-hwaccel auto -ss 10.000 -i a.mp4"), "{ss}");
    assert!(
        ss.contains("-c:a:1 flac") && !ss.contains("movflags"),
        "{ss}"
    );
}

fn ft_minutes_ago(min: u32) -> u64 {
    FILETIME_EPOCH_2000 + u64::from(NOW - min) * INTERVALS_PER_MINUTE
}

/// Builds `C:\` from `(path, bytes, minutes_ago)`.
fn build(files: &[(&str, u64, u32)]) -> crate::index::Index {
    let mut names = NameArena::new();
    let n_root = names.push_str("C:");
    let mut raw = vec![RawEntry {
        key: 5,
        parent_key: 5,
        name: n_root,
        flags: NodeFlags::DIR,
        logical: 0,
        allocated: 0,
        mtime: 0,
        atime: 0,
        file_id: 5,
        reparse_tag: 0,
    }];
    let mut dirs: rustc_hash::FxHashMap<String, u64> = Default::default();
    let mut next = 10u64;
    for (path, bytes, mins) in files {
        let parts: Vec<&str> = path.split('\\').skip(1).collect();
        let mut parent = 5u64;
        let mut prefix = String::new();
        for (i, part) in parts.iter().enumerate() {
            prefix.push('\\');
            prefix.push_str(&part.to_ascii_lowercase());
            let is_file = i + 1 == parts.len();
            if !is_file && let Some(&k) = dirs.get(&prefix) {
                parent = k;
                continue;
            }
            let key = next;
            next += 1;
            let n = names.push_str(part);
            raw.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags: if is_file {
                    NodeFlags::empty()
                } else {
                    NodeFlags::DIR
                },
                logical: if is_file { *bytes } else { 0 },
                allocated: if is_file { *bytes } else { 0 },
                mtime: ft_minutes_ago(*mins),
                atime: ft_minutes_ago(*mins),
                file_id: key,
                reparse_tag: 0,
            });
            if !is_file {
                dirs.insert(prefix.clone(), key);
            }
            parent = key;
        }
    }
    let mut b = IndexBuilder::new(
        5,
        r"C:\",
        VolumeInfo {
            root: r"C:\".into(),
            ..Default::default()
        },
    );
    b.push_batch(EntryBatch {
        entries: raw,
        names,
    });
    b.finish()
}

#[test]
fn collection_skips_system_app_game_and_holding_folders() {
    let ix = build(&[
        (r"C:\Users\A\Videos\rec.mp4", 900 * MIB, 5000),
        (r"C:\Users\A\Videos\small.mp4", 50 * MIB, 5000),
        (r"C:\Users\A\Videos\notes.txt", 900 * MIB, 5000),
        (
            r"C:\Users\A\AppData\Local\Packages\WhatsApp\IMG.MOV",
            900 * MIB,
            5000,
        ),
        (r"C:\Program Files\Game\intro.mp4", 900 * MIB, 5000),
        (r"C:\Windows\Web\video.mp4", 900 * MIB, 5000),
        (
            r"C:\SteamLibrary\steamapps\common\X\movie.mkv",
            900 * MIB,
            5000,
        ),
        (r"C:\Games\GTA\cutscene.mp4", 900 * MIB, 5000),
        (
            r"C:\Users\A\DiskSaver Originals\2026-11-18\x.mp4",
            900 * MIB,
            5000,
        ),
        (r"C:\Users\A\Videos\rec.dsk-tmp.mp4", 900 * MIB, 5000),
        (r"C:\Archive\Family\IMG_2860.MOV", 2600 * MIB, 5000),
        (r"C:\Archive\Family\fresh.MOV", 2600 * MIB, 10),
    ]);
    let opts = DiscoverOptions {
        exclude_roots: vec![PathBuf::from(r"C:\Games\GTA")],
        now_min2000: Some(NOW),
        ..Default::default()
    };
    let (files, excluded) = collect_video_files(&ix, &opts);
    let mut names: Vec<String> = files.iter().map(|f| f.path.display().to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            r"C:\Archive\Family\IMG_2860.MOV".to_string(),
            r"C:\Archive\Family\fresh.MOV".into(),
            r"C:\Users\A\Videos\rec.mp4".into(),
        ]
    );
    assert_eq!(excluded, 6);
    assert!(is_excluded_path(
        Path::new(r"D:\steamapps\common\a.mp4"),
        &[]
    ));
    assert!(!is_excluded_path(
        Path::new(r"D:\Disk Arxiv\Elxan\IMG.MOV"),
        &[]
    ));

    // Without ffmpeg every file is listed as skipped, and the fresh one for its age.
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let d = discover_videos(files, None, &opts, None, &|_, _| {}, &cancel);
    assert!(d.candidates.is_empty());
    assert_eq!(d.skipped.len(), 3);
    let fresh = d
        .skipped
        .iter()
        .find(|c| c.path.ends_with("fresh.MOV"))
        .unwrap();
    assert_eq!(fresh.skip, Some(SkipReason::RecentlyModified));
    assert!(
        d.skipped
            .iter()
            .filter(|c| !c.path.ends_with("fresh.MOV"))
            .all(|c| c.skip == Some(SkipReason::NoTools))
    );
    assert_eq!(d.total_video_bytes, 6100 * MIB);
}

#[test]
fn identical_copies_are_held_back_until_deduplicated() {
    let cand = |p: &str, bytes: u64, secs: f64| VideoCandidate {
        path: PathBuf::from(p),
        bytes,
        info: Some(ProbeInfo {
            duration_secs: secs,
            ..Default::default()
        }),
        est_output_bytes: bytes / 4,
        skip: None,
    };
    let mut v = vec![
        cand(r"D:\a\102APPLE\IMG_5006.MOV", 2_394_000_000, 901.2),
        cand(r"D:\b\101APPLE\IMG_5006.MOV", 2_394_000_000, 901.2),
        cand(r"D:\c\IMG_6726.MOV", 2_394_000_000, 908.0),
        cand(r"D:\c\other.mp4", 900_000_000, 901.2),
    ];
    mark_likely_duplicates(&mut v);
    assert_eq!(
        v[0].skip,
        Some(SkipReason::LikelyDuplicate(PathBuf::from(
            r"D:\b\101APPLE\IMG_5006.MOV"
        )))
    );
    assert_eq!(
        v[1].skip,
        Some(SkipReason::LikelyDuplicate(PathBuf::from(
            r"D:\a\102APPLE\IMG_5006.MOV"
        )))
    );
    assert!(v[2].skip.is_none() && v[3].skip.is_none());
    assert!(
        v[0].skip
            .as_ref()
            .unwrap()
            .label()
            .contains("disksaver dupes")
    );
}

#[test]
fn holding_folder_sits_on_the_same_volume() {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    if let Some(drive) = home.get(..2) {
        let r = holding_root_for(&Path::new(&home).join(r"Videos\a.mp4")).unwrap();
        assert_eq!(r, Path::new(&home).join(HOLDING_FOLDER));
        assert!(r.to_string_lossy().starts_with(drive));
    }
    let other = if home.starts_with('Q') { "R" } else { "Q" };
    assert_eq!(
        holding_root_for(Path::new(&format!(r"{other}:\Arxiv\a.mov"))).unwrap(),
        PathBuf::from(format!(r"{other}:\{HOLDING_FOLDER}"))
    );
    assert_eq!(holding_root_for(Path::new(r"\\server\share\a.mp4")), None);
}

// ---------------------------------------------------------------------------------------------
// Real ffmpeg (skipped when it is not installed)
// ---------------------------------------------------------------------------------------------

fn engine() -> Option<&'static VideoEngine> {
    static ENGINE: OnceLock<Option<VideoEngine>> = OnceLock::new();
    ENGINE
        .get_or_init(|| VideoEngine::locate(None).filter(|e| !e.encoders.is_empty()))
        .as_ref()
}

/// A fresh temp folder with a high-bitrate H.264 + AAC test clip named `name`.
fn make_clip(name: &str, secs: u32) -> Option<(PathBuf, PathBuf)> {
    let e = engine()?;
    let dir = std::env::temp_dir().join(format!(
        "dsk-video-test-{}-{}",
        std::process::id(),
        name.replace('.', "-")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let clip = dir.join(name);
    let out = crate::win::process::hidden_command(&e.tools.ffmpeg)
        .args(["-hide_banner", "-v", "error", "-f", "lavfi", "-i"])
        .arg(format!("testsrc2=size=1280x720:rate=30:duration={secs}"))
        .args(["-f", "lavfi", "-i"])
        .arg(format!("sine=frequency=440:duration={secs}"))
        .args([
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-qp",
            "8",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-b:a",
            "128k",
            "-shortest",
            "-y",
        ])
        .arg(&clip)
        .output()
        .ok()?;
    (out.status.success() && clip.is_file()).then_some((dir, clip))
}

#[test]
fn real_ffmpeg_keep_both_compresses_verifies_and_marks() {
    let Some((dir, clip)) = make_clip("clip.mp4", 6) else {
        eprintln!("ffmpeg or a test encoder is not available; skipping");
        return;
    };
    let e = engine().unwrap();
    let codec = if e.encoder_for(TargetCodec::Av1, EncoderPref::Auto).is_some() {
        TargetCodec::Av1
    } else {
        TargetCodec::Hevc
    };
    let opts = CompressOptions {
        codec,
        originals: OriginalPolicy::KeepBoth,
        allow_battery: true,
        wait_for_fullscreen: false,
        ..Default::default()
    };
    let deny = DenyContext::default();
    let o = compress_one(e, &clip, &opts, &deny, &mut |_, _, _| {}, &|| None);
    assert_eq!(o.status, VideoJobStatus::KeptBoth, "{o:?}");
    let out = o.output_path.clone().unwrap();
    assert!(out.is_file() && clip.is_file());
    assert!(
        out.to_string_lossy()
            .contains(&format!(".{}.", codec.tag()))
    );
    assert!(o.new_bytes < o.original_bytes / 2, "{o:?}");
    assert!(o.score.unwrap() >= e.metric.gate(opts.min_vmaf), "{o:?}");
    let pi = probe(&e.tools, &out).unwrap();
    assert!(pi.is_disksaver_output());
    assert_eq!(pi.audio.len(), 1);
    // The new file carries the original's modification time.
    let (m0, m1) = (
        std::fs::metadata(&clip).unwrap().modified().unwrap(),
        std::fs::metadata(&out).unwrap().modified().unwrap(),
    );
    assert_eq!(m0, m1);
    // Offering the output again is refused.
    let again = compress_one(e, &out, &opts, &deny, &mut |_, _, _| {}, &|| None);
    assert_eq!(again.status, VideoJobStatus::AlreadyCompressed);
    // No work files left behind.
    assert!(
        std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .all(|f| !f.file_name().to_string_lossy().contains(".dsk-tmp."))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_ffmpeg_hold_swaps_in_place_and_purge_needs_an_intact_replacement() {
    let Some((dir, clip)) = make_clip("trip.mov", 4) else {
        eprintln!("ffmpeg or a test encoder is not available; skipping");
        return;
    };
    let e = engine().unwrap();
    let codec = if e.encoder_for(TargetCodec::Av1, EncoderPref::Auto).is_some() {
        TargetCodec::Av1
    } else {
        TargetCodec::Hevc
    };
    let journal_path = dir.join("journal.db");
    let holding = dir.join(HOLDING_FOLDER);
    let opts = CompressOptions {
        codec,
        originals: OriginalPolicy::Hold,
        allow_battery: true,
        wait_for_fullscreen: false,
        journal_path: Some(journal_path.clone()),
        holding_root: Some(holding.clone()),
        ..Default::default()
    };
    let deny = DenyContext::default();
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let mut phases = Vec::new();
    let mut done = Vec::new();
    let rep = compress_batch(
        e,
        std::slice::from_ref(&clip),
        &opts,
        &deny,
        &mut |p| phases.push(p.phase.clone()),
        &mut |o| done.push(o.status),
        &cancel,
    );
    assert_eq!(rep.replaced, 1, "{rep:?}");
    assert_eq!(done, vec![VideoJobStatus::Replaced]);
    let o = &rep.outcomes[0];
    // .mov becomes .mp4 next to where the original was; the original is held.
    let out = o.output_path.clone().unwrap();
    assert_eq!(out, dir.join("trip.mp4"));
    assert!(out.is_file() && !clip.exists());
    let OriginalDisposition::Held(held) = &o.disposition else {
        panic!("{o:?}")
    };
    assert!(held.is_file() && held.starts_with(&holding));
    assert_eq!(rep.held_bytes, o.original_bytes);
    assert!(rep.saved_bytes > 0);
    assert!(phases.contains(&VideoPhase::Verifying) && phases.contains(&VideoPhase::Replacing));

    let mut j = crate::clean::ActionJournal::open(&journal_path).unwrap();
    let jobs = j.list_video_jobs(10).unwrap();
    assert_eq!(jobs[0].status, "replaced");
    assert_eq!(jobs[0].original_disposition, "held");
    assert!(j.video_job_for_output(&out).unwrap().is_some());

    // A changed replacement blocks the purge.
    let real = std::fs::read(&out).unwrap();
    std::fs::write(&out, b"changed").unwrap();
    let blocked = purge_held_originals(&mut j, false).unwrap();
    assert_eq!(blocked.purged, 0);
    assert_eq!(blocked.errors.len(), 1);
    assert!(held.is_file());
    std::fs::write(&out, &real).unwrap();

    let dry = purge_held_originals(&mut j, true).unwrap();
    assert_eq!((dry.purged, dry.purged_bytes), (1, o.original_bytes));
    assert!(held.is_file());
    let done = purge_held_originals(&mut j, false).unwrap();
    assert_eq!(done.purged, 1, "{done:?}");
    assert!(!held.exists());
    assert!(j.held_video_originals().unwrap().is_empty());
    drop(j);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_ffmpeg_sample_reports_size_and_quality() {
    let Some((dir, clip)) = make_clip("sample-src.mp4", 8) else {
        eprintln!("ffmpeg or a test encoder is not available; skipping");
        return;
    };
    let e = engine().unwrap();
    let opts = CompressOptions {
        codec: e
            .encoder_for(TargetCodec::Av1, EncoderPref::Auto)
            .map(|c| c.kind.codec())
            .unwrap_or(TargetCodec::Hevc),
        ..Default::default()
    };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let s = sample_video(e, &clip, &opts, None, 4.0, &cancel).unwrap();
    assert!((s.seconds - 4.0).abs() < 0.01);
    assert!((s.start_secs - 2.0).abs() < 0.01);
    assert!(s.sample_path.is_file());
    assert!(s.ratio > 0.0 && s.ratio < 0.5, "{s:?}");
    assert!(
        s.score
            .is_some_and(|v| v > 80.0 || e.metric == QualityMetric::Ssim),
        "{s:?}"
    );
    let _ = std::fs::remove_file(&s.sample_path);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_ffmpeg_cancel_leaves_the_original_and_no_work_file() {
    let Some((dir, clip)) = make_clip("cancel.mp4", 6) else {
        eprintln!("ffmpeg or a test encoder is not available; skipping");
        return;
    };
    let e = engine().unwrap();
    let opts = CompressOptions {
        codec: e
            .encoder_for(TargetCodec::Av1, EncoderPref::Auto)
            .map(|c| c.kind.codec())
            .unwrap_or(TargetCodec::Hevc),
        originals: OriginalPolicy::Hold,
        holding_root: Some(dir.join(HOLDING_FOLDER)),
        allow_battery: true,
        wait_for_fullscreen: false,
        ..Default::default()
    };
    let before = std::fs::read(&clip).unwrap();
    let o = compress_one(
        e,
        &clip,
        &opts,
        &DenyContext::default(),
        &mut |_, _, _| {},
        &|| Some(VideoJobStatus::Cancelled),
    );
    assert_eq!(o.status, VideoJobStatus::Cancelled, "{o:?}");
    assert_eq!(std::fs::read(&clip).unwrap(), before);
    assert!(
        std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .all(|f| f.file_name().to_string_lossy() == "cancel.mp4")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
