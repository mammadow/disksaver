#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use dsk_core::{
    DskError, Index, NodeFlags, NodeId, ROOT, ScanMethod, ScanReport, ext_breakdown, top_dirs,
    top_files,
};
use serde::{Deserialize, Serialize};

/// Formats a byte quantity using binary units (B, KiB, MiB, GiB, TiB, PiB).
/// Values 1024 and above display exactly one decimal digit.
pub fn fmt_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;
    const PIB: u64 = 1024 * 1024 * 1024 * 1024 * 1024;

    if n < KIB {
        format!("{n} B")
    } else if n < MIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else if n < GIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n < TIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n < PIB {
        format!("{:.1} TiB", n as f64 / TIB as f64)
    } else {
        format!("{:.1} PiB", n as f64 / PIB as f64)
    }
}

/// Converts active `NodeFlags` bits into their string representation names.
pub fn node_flags_to_vec(flags: NodeFlags) -> Vec<String> {
    let mut names = Vec::new();
    let bits: &[(NodeFlags, &str)] = &[
        (NodeFlags::HARDLINK, "HARDLINK"),
        (NodeFlags::COMPRESSED, "COMPRESSED"),
        (NodeFlags::SPARSE, "SPARSE"),
        (NodeFlags::REPARSE, "REPARSE"),
        (NodeFlags::CLOUD, "CLOUD"),
        (NodeFlags::ADS, "ADS"),
        (NodeFlags::SYSTEM, "SYSTEM"),
        (NodeFlags::HIDDEN, "HIDDEN"),
        (NodeFlags::WOF, "WOF"),
        (NodeFlags::OFFLINE, "OFFLINE"),
        (NodeFlags::ORPHANS, "ORPHANS"),
        (NodeFlags::METAFILE, "METAFILE"),
        (NodeFlags::DUP_LINK, "DUP_LINK"),
    ];
    for &(bit, name) in bits {
        if flags.contains(bit) {
            names.push(name.to_string());
        }
    }
    names
}

/// Counts total directories excluding orphans.
pub fn count_dirs(ix: &Index) -> u64 {
    let mut dirs = 0u64;
    for id in 1..ix.len() as NodeId {
        let f = ix.flags(id);
        if f.contains(NodeFlags::DIR) && !f.contains(NodeFlags::ORPHANS) {
            dirs += 1;
        }
    }
    dirs
}

/// Maps a scan error into an exit status code and optional stderr diagnostic message.
pub fn exit_code_for_error(err: &DskError) -> (i32, Option<String>) {
    match err {
        DskError::NotVolumeRoot(_) => (
            2,
            Some("--method mft needs a volume root like C:\\".to_string()),
        ),
        DskError::NotElevated => (
            2,
            Some("run from an elevated terminal, or use --method dir".to_string()),
        ),
        DskError::Unsupported(fs) => (
            2,
            Some(format!("raw scan supports NTFS only (this volume is {fs})")),
        ),
        DskError::Cancelled => (130, None),
        other => (1, Some(format!("error: {other}"))),
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub struct UsageCheckJson {
    pub scanned_alloc: u64,
    pub volume_used: u64,
    pub diff_pct: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TopDirEntry {
    pub path: String,
    pub bytes: u64,
    pub files: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TopFileEntry {
    pub path: String,
    pub bytes: u64,
    pub flags: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExtEntry {
    pub ext: String,
    pub bytes: u64,
    pub count: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatsEntry {
    pub peak_working_set: u64,
    pub index_heap_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonReport {
    pub path: String,
    pub method: String,
    pub elapsed_ms: u64,
    pub files: u64,
    pub dirs: u64,
    pub skipped: u64,
    pub scanned_alloc: u64,
    pub check: Option<UsageCheckJson>,
    pub fallback_reason: Option<String>,
    pub top_dirs: Vec<TopDirEntry>,
    pub top_files: Vec<TopFileEntry>,
    pub extensions: Vec<ExtEntry>,
    pub stats: Option<StatsEntry>,
}

/// Constructs a `JsonReport` from a completed `ScanReport` and query parameters.
pub fn build_json_report(
    path: &Path,
    report: &ScanReport,
    top_dirs_limit: usize,
    depth: u16,
    top_files_limit: usize,
    top_ext_limit: usize,
    include_stats: bool,
) -> JsonReport {
    let ix = &report.index;
    let files = ix.file_count(ROOT) as u64;
    let dirs = count_dirs(ix);
    let scanned_alloc = ix.total_allocated(ROOT);

    let top_dir_ids = top_dirs(ix, top_dirs_limit, depth);
    let top_dirs_data = top_dir_ids
        .into_iter()
        .map(|id| TopDirEntry {
            path: ix.path(id).display().to_string(),
            bytes: ix.total_allocated(id),
            files: ix.file_count(id),
        })
        .collect();

    let top_file_ids = top_files(ix, top_files_limit);
    let top_files_data = top_file_ids
        .into_iter()
        .map(|id| TopFileEntry {
            path: ix.path(id).display().to_string(),
            bytes: ix.allocated(id),
            flags: node_flags_to_vec(ix.flags(id)),
        })
        .collect();

    let ext_data = ext_breakdown(ix, top_ext_limit)
        .into_iter()
        .map(|(ext, bytes, count)| ExtEntry { ext, bytes, count })
        .collect();

    let stats = if include_stats {
        Some(StatsEntry {
            peak_working_set: dsk_core::win::peak_working_set(),
            index_heap_bytes: ix.heap_bytes() as u64,
        })
    } else {
        None
    };

    let method = match report.method_used {
        ScanMethod::Mft => "mft",
        ScanMethod::Dir => "dir",
        ScanMethod::Auto => "auto",
        ScanMethod::UsnIncremental => "usn",
    };

    let check = report.check.map(|c| UsageCheckJson {
        scanned_alloc: c.scanned_alloc,
        volume_used: c.volume_used,
        diff_pct: c.diff_pct,
    });

    JsonReport {
        path: path.display().to_string(),
        method: method.to_string(),
        elapsed_ms: report.elapsed.as_millis() as u64,
        files,
        dirs,
        skipped: report.skipped,
        scanned_alloc,
        check,
        fallback_reason: report.fallback_reason.clone(),
        top_dirs: top_dirs_data,
        top_files: top_files_data,
        extensions: ext_data,
        stats,
    }
}

/// Prints a human-readable scan report to stdout.
pub fn print_human_report(report: &JsonReport, elapsed: Duration) {
    println!(
        "Scanned {} ({}) in {:.2}s: {} files, {} folders, {} on disk",
        report.path,
        report.method,
        elapsed.as_secs_f64(),
        report.files,
        report.dirs,
        fmt_bytes(report.scanned_alloc)
    );

    if let Some(ref reason) = report.fallback_reason {
        println!("Fallback: {reason}");
    }

    if let Some(ref check) = report.check {
        println!(
            "Check: scanned {}, volume used {}, diff {:.2}%",
            fmt_bytes(check.scanned_alloc),
            fmt_bytes(check.volume_used),
            check.diff_pct
        );
    }

    println!("\nLargest folders:");
    for d in &report.top_dirs {
        println!(
            "  {:>10}  {:>8} files  {}",
            fmt_bytes(d.bytes),
            d.files,
            d.path
        );
    }

    println!("\nLargest files:");
    for f in &report.top_files {
        if f.flags.is_empty() {
            println!("  {:>10}  {}", fmt_bytes(f.bytes), f.path);
        } else {
            println!(
                "  {:>10}  [{}]  {}",
                fmt_bytes(f.bytes),
                f.flags.join(", "),
                f.path
            );
        }
    }

    println!("\nBy extension:");
    for e in &report.extensions {
        let ext_name = if e.ext.is_empty() { "(no ext)" } else { &e.ext };
        println!(
            "  {:>10}  {:>10}  ({} files)",
            ext_name,
            fmt_bytes(e.bytes),
            e.count
        );
    }

    if let Some(ref st) = report.stats {
        println!("\nStats:");
        println!("  Peak working set: {}", fmt_bytes(st.peak_working_set));
        println!("  Index heap bytes: {}", fmt_bytes(st.index_heap_bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_bytes_units() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(11_659_350_016), "10.9 GiB");
    }

    #[test]
    fn fmt_bytes_all_tiers() {
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024 * 1024), "1.0 TiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024 * 1024 * 1024), "1.0 PiB");
    }

    #[test]
    fn node_flags_conversion() {
        let flags = NodeFlags::HARDLINK | NodeFlags::SPARSE | NodeFlags::COMPRESSED;
        let vec = node_flags_to_vec(flags);
        assert_eq!(vec, vec!["HARDLINK", "COMPRESSED", "SPARSE"]);

        assert!(node_flags_to_vec(NodeFlags::empty()).is_empty());
    }

    #[test]
    fn error_exit_codes_and_messages() {
        assert_eq!(
            exit_code_for_error(&DskError::NotVolumeRoot("foo".into())),
            (
                2,
                Some("--method mft needs a volume root like C:\\".to_string())
            )
        );
        assert_eq!(
            exit_code_for_error(&DskError::NotElevated),
            (
                2,
                Some("run from an elevated terminal, or use --method dir".to_string())
            )
        );
        assert_eq!(
            exit_code_for_error(&DskError::Unsupported("exFAT".into())),
            (
                2,
                Some("raw scan supports NTFS only (this volume is exFAT)".to_string())
            )
        );
        assert_eq!(exit_code_for_error(&DskError::Cancelled), (130, None));
        assert_eq!(
            exit_code_for_error(&DskError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found"
            ))),
            (1, Some("error: not found".to_string()))
        );
    }
}
