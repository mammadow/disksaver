#![forbid(unsafe_code)]

//! Downloads intelligence (P9.7): installers of software that is already installed, archives that
//! were already extracted, and stale partial downloads. Recycle-only suggestions.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::index::{Index, NodeFlags, NodeId};
use crate::insights::current_min2000;
use crate::win::prefetch::InstalledAppRecord;

/// What a Downloads item is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DownloadKind {
    /// An installer whose product matches an installed app.
    InstallerOfInstalled {
        product: String,
        installed_as: String,
    },
    /// An installer with no installed match, untouched for a while.
    OldInstaller { product: Option<String> },
    /// An archive whose contents sit in a sibling folder.
    ExtractedArchive {
        folder: PathBuf,
        matched_entries: u32,
        total_entries: u32,
    },
    /// An unfinished browser or torrent download.
    PartialDownload,
}

/// One suggestion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadFinding {
    pub path: PathBuf,
    pub bytes: u64,
    pub days_old: u32,
    pub kind: DownloadKind,
    /// 0–100.
    pub confidence: u8,
}

/// Report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadsReport {
    pub findings: Vec<DownloadFinding>,
    pub total_bytes: u64,
}

const VENDOR_ONLY: &[&str] = &[
    "microsoft",
    "nvidia",
    "google",
    "intel",
    "amd",
    "adobe",
    "update",
    "driver",
    "drivers",
    "tools",
    "runtime",
    "redist",
    "redistributable",
    "jetbrains",
    "apple",
    "oracle",
];

const INSTALLER_EXTS: &[&str] = &["exe", "msi", "msix", "msixbundle", "appx", "appxbundle"];
const ARCHIVE_EXTS: &[&str] = &["zip", "7z", "rar"];
const PARTIAL_EXTS: &[&str] = &[
    "crdownload",
    "part",
    "partial",
    "download",
    "!qb",
    "!ut",
    "opdownload",
];

fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 3 && !t.chars().all(|c| c.is_ascii_digit()))
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| {
            !matches!(
                t.as_str(),
                "setup"
                    | "installer"
                    | "install"
                    | "win"
                    | "x64"
                    | "x86"
                    | "amd64"
                    | "windows"
                    | "the"
                    | "for"
                    | "and"
                    | "release"
                    | "version"
                    | "bit"
            )
        })
        .collect()
}

/// Matches an installer's product name (or file name) to an installed app: every significant
/// token of the shorter name must appear in the other, with at least one token of 4+ letters.
pub fn match_installed<'a>(
    name: &str,
    installed: &'a [InstalledAppRecord],
) -> Option<&'a InstalledAppRecord> {
    let want = tokens(name);
    if want.is_empty() || !want.iter().any(|t| t.len() >= 4) {
        return None;
    }
    // A vendor name alone ("nvidia", "microsoft") would match every app of that vendor.
    if want.len() == 1 && VENDOR_ONLY.contains(&want[0].as_str()) {
        return None;
    }
    installed.iter().find(|app| {
        let have: FxHashSet<String> = tokens(&app.name).into_iter().collect();
        if have.is_empty() {
            return false;
        }
        let (small, big): (Vec<&String>, &FxHashSet<String>) = if want.len() <= have.len() {
            (want.iter().collect(), &have)
        } else {
            let w: FxHashSet<String> = want.iter().cloned().collect();
            return have.iter().all(|t| w.contains(t)) && have.iter().any(|t| t.len() >= 4);
        };
        small.iter().all(|t| big.contains(*t))
    })
}

/// Reads up to `max` entry names from a zip's central directory. Bounds-checked; `None` for
/// anything that is not a plain (non-ZIP64) zip.
pub fn zip_entry_names<R: Read + Seek>(r: &mut R, len: u64, max: usize) -> Option<Vec<String>> {
    let tail_len = len.min(66_000);
    r.seek(SeekFrom::Start(len - tail_len)).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    r.read_exact(&mut tail).ok()?;
    let eocd = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| tail[i..i + 4] == [0x50, 0x4B, 0x05, 0x06])?;
    let e = &tail[eocd..];
    let entries = u16::from_le_bytes([e[10], e[11]]) as usize;
    let cd_size = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
    let cd_off = u32::from_le_bytes([e[16], e[17], e[18], e[19]]) as u64;
    if cd_off == 0xFFFF_FFFF || cd_size > 32 * 1024 * 1024 || cd_off + cd_size > len {
        return None;
    }
    r.seek(SeekFrom::Start(cd_off)).ok()?;
    let mut cd = vec![0u8; cd_size as usize];
    r.read_exact(&mut cd).ok()?;
    let mut names = Vec::new();
    let mut p = 0usize;
    for _ in 0..entries.min(max) {
        let h = cd.get(p..p + 46)?;
        if h[0..4] != [0x50, 0x4B, 0x01, 0x02] {
            return None;
        }
        let n = u16::from_le_bytes([h[28], h[29]]) as usize;
        let x = u16::from_le_bytes([h[30], h[31]]) as usize;
        let c = u16::from_le_bytes([h[32], h[33]]) as usize;
        let name = cd.get(p + 46..p + 46 + n)?;
        names.push(String::from_utf8_lossy(name).replace('/', "\\"));
        p = p.checked_add(46 + n + x + c)?;
    }
    Some(names)
}

fn find_child_ci(index: &Index, dir: NodeId, name: &str) -> Option<NodeId> {
    index
        .children(dir)
        .find(|&c| index.name(c).eq_ignore_ascii_case(name))
}

/// Share of an archive's file entries present under `folder` (or under its single top folder).
fn extracted_share(index: &Index, folder: NodeId, names: &[String]) -> (u32, u32) {
    let files: Vec<&String> = names.iter().filter(|n| !n.ends_with('\\')).collect();
    let mut matched = 0u32;
    for n in &files {
        let mut node = Some(folder);
        for part in n.split('\\').filter(|p| !p.is_empty()) {
            node = node.and_then(|d| find_child_ci(index, d, part));
        }
        if node.is_some() {
            matched += 1;
        }
    }
    (matched, files.len() as u32)
}

/// Downloads folders of the current user (the Known Folder may have been moved).
pub fn downloads_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE") {
        roots.push(PathBuf::from(home).join("Downloads"));
    }
    roots
}

/// Analyzes the Downloads folders in `index`.
pub fn scan_downloads(
    index: &Index,
    roots: &[PathBuf],
    installed: &[InstalledAppRecord],
    installer_min_days: u32,
) -> DownloadsReport {
    let now = current_min2000();
    let mut findings = Vec::new();
    for root in roots {
        let Some(root_node) = index.find_by_path(root) else {
            continue;
        };
        let mut stack = vec![root_node];
        while let Some(dir) = stack.pop() {
            for c in index.children(dir) {
                let f = index.flags(c);
                if f.intersects(NodeFlags::REPARSE | NodeFlags::CLOUD | NodeFlags::OFFLINE) {
                    continue;
                }
                if f.contains(NodeFlags::DIR) {
                    stack.push(c);
                    continue;
                }
                let name = index.name(c).into_owned();
                let lower = name.to_ascii_lowercase();
                let Some((stem, ext)) = lower.rsplit_once('.') else {
                    continue;
                };
                let bytes = index.allocated(c);
                let mt = index.mtime_min(c);
                let days = if mt > 0 && now > mt {
                    (now - mt) / 1440
                } else {
                    0
                };
                let path = index.path(c);

                if PARTIAL_EXTS.contains(&ext) && days >= 7 {
                    findings.push(DownloadFinding {
                        path,
                        bytes,
                        days_old: days,
                        kind: DownloadKind::PartialDownload,
                        confidence: 95,
                    });
                    continue;
                }
                if INSTALLER_EXTS.contains(&ext) && bytes >= 1024 * 1024 {
                    let info = if ext == "exe" {
                        crate::win::fileinfo::product_info(&path)
                    } else {
                        None
                    };
                    let product = info.as_ref().and_then(|i| {
                        i.product_name
                            .clone()
                            .or_else(|| i.file_description.clone())
                    });
                    let probe = product.clone().unwrap_or_else(|| stem.to_string());
                    if let Some(app) = match_installed(&probe, installed)
                        .or_else(|| match_installed(stem, installed))
                    {
                        findings.push(DownloadFinding {
                            path,
                            bytes,
                            days_old: days,
                            kind: DownloadKind::InstallerOfInstalled {
                                product: probe,
                                installed_as: app.name.clone(),
                            },
                            confidence: if product.is_some() { 85 } else { 70 },
                        });
                    } else if days >= installer_min_days {
                        findings.push(DownloadFinding {
                            path,
                            bytes,
                            days_old: days,
                            kind: DownloadKind::OldInstaller { product },
                            confidence: 50,
                        });
                    }
                    continue;
                }
                if ARCHIVE_EXTS.contains(&ext) && bytes >= 1024 * 1024 {
                    let Some(sibling) = index.children(dir).find(|&s| {
                        s != c
                            && index.flags(s).contains(NodeFlags::DIR)
                            && index.name(s).eq_ignore_ascii_case(stem)
                    }) else {
                        continue;
                    };
                    let names = if ext == "zip" {
                        std::fs::File::open(&path).ok().and_then(|mut fh| {
                            let len = fh.metadata().ok()?.len();
                            zip_entry_names(&mut fh, len, 5000)
                        })
                    } else {
                        None
                    };
                    let (matched, total, confidence) = match names {
                        Some(n) if !n.is_empty() => {
                            let (m, t) = extracted_share(index, sibling, &n);
                            // Archives often wrap everything in one top folder named like the stem.
                            let (m2, t2) = index
                                .children(sibling)
                                .filter(|&s| index.flags(s).contains(NodeFlags::DIR))
                                .map(|s| extracted_share(index, s, &n))
                                .max_by_key(|x| x.0)
                                .unwrap_or((0, t));
                            let (m, t) = if m2 > m { (m2, t2) } else { (m, t) };
                            let conf = if t > 0 && m * 10 >= t * 9 {
                                90
                            } else if m * 2 >= t {
                                60
                            } else {
                                0
                            };
                            (m, t, conf)
                        }
                        _ => (0, 0, 55),
                    };
                    if confidence > 0 {
                        findings.push(DownloadFinding {
                            path,
                            bytes,
                            days_old: days,
                            kind: DownloadKind::ExtractedArchive {
                                folder: index.path(sibling),
                                matched_entries: matched,
                                total_entries: total,
                            },
                            confidence,
                        });
                    }
                }
            }
        }
    }
    findings.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    let total_bytes = findings
        .iter()
        .map(|f| f.bytes)
        .fold(0u64, u64::saturating_add);
    DownloadsReport {
        findings,
        total_bytes,
    }
}

/// Short reason text for a finding.
pub fn describe(kind: &DownloadKind) -> String {
    match kind {
        DownloadKind::InstallerOfInstalled {
            product,
            installed_as,
        } => {
            format!("installer for {product}, already installed as \"{installed_as}\"")
        }
        DownloadKind::OldInstaller { product } => format!(
            "installer{} not matched to an installed app",
            product
                .as_ref()
                .map(|p| format!(" for {p}"))
                .unwrap_or_default()
        ),
        DownloadKind::ExtractedArchive {
            folder,
            matched_entries,
            total_entries,
        } if *total_entries > 0 => format!(
            "already extracted to {} ({matched_entries}/{total_entries} files present)",
            folder.display()
        ),
        DownloadKind::ExtractedArchive { folder, .. } => {
            format!("a folder with the same name exists: {}", folder.display())
        }
        DownloadKind::PartialDownload => "unfinished download".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win::prefetch::InstalledAppSource;
    use std::io::{Cursor, Write};

    fn app(name: &str) -> InstalledAppRecord {
        InstalledAppRecord {
            name: name.into(),
            publisher: None,
            install_location: None,
            source: InstalledAppSource::Win32Uninstall,
            system_component: false,
        }
    }

    #[test]
    fn installer_names_match_installed_apps() {
        let installed = vec![
            app("IntelliJ IDEA 2026.2"),
            app("Docker Desktop"),
            app("NVIDIA CUDA Toolkit 13.2"),
        ];
        // JetBrains names the IntelliJ installer idea-<version>.exe.
        assert_eq!(
            match_installed("idea-2026.2", &installed).map(|a| a.name.as_str()),
            Some("IntelliJ IDEA 2026.2")
        );
        assert_eq!(
            match_installed("IntelliJ IDEA", &installed).map(|a| a.name.as_str()),
            Some("IntelliJ IDEA 2026.2")
        );
        assert_eq!(
            match_installed("Docker Desktop Installer", &installed).map(|a| a.name.as_str()),
            Some("Docker Desktop")
        );
        assert_eq!(
            match_installed("cuda_13.2.1_windows", &installed).map(|a| a.name.as_str()),
            Some("NVIDIA CUDA Toolkit 13.2")
        );
        assert_eq!(
            match_installed("nvidia-setup", &installed),
            None,
            "vendor name alone"
        );
        assert_eq!(
            match_installed("nvidia driver", &installed),
            None,
            "every token must match"
        );
        assert_eq!(
            match_installed("CUDA Toolkit", &installed).map(|a| a.name.as_str()),
            Some("NVIDIA CUDA Toolkit 13.2")
        );
        assert_eq!(match_installed("setup", &installed), None);
    }

    fn make_zip(names: &[&str]) -> Vec<u8> {
        // Stored entries with empty contents: local headers, central directory, EOCD.
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for n in names {
            let off = out.len() as u32;
            out.extend([0x50, 0x4B, 0x03, 0x04]);
            out.extend([0u8; 22]);
            out.extend((n.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(n.as_bytes());
            let mut h = vec![0x50, 0x4B, 0x01, 0x02];
            h.extend([0u8; 24]);
            h.extend((n.len() as u16).to_le_bytes());
            h.extend([0u8; 12]);
            h.extend(off.to_le_bytes());
            h.extend(n.as_bytes());
            cd.extend(h);
        }
        let cd_off = out.len() as u32;
        out.extend(&cd);
        out.extend([0x50, 0x4B, 0x05, 0x06, 0, 0, 0, 0]);
        out.extend((names.len() as u16).to_le_bytes());
        out.extend((names.len() as u16).to_le_bytes());
        out.extend((cd.len() as u32).to_le_bytes());
        out.extend(cd_off.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_zip_central_directory() {
        let z = make_zip(&["pack/", "pack/a.txt", "pack/sub/b.bin"]);
        let len = z.len() as u64;
        let names = zip_entry_names(&mut Cursor::new(z), len, 100).unwrap();
        assert_eq!(names, [r"pack\", r"pack\a.txt", r"pack\sub\b.bin"]);
        assert_eq!(
            zip_entry_names(&mut Cursor::new(vec![0u8; 100]), 100, 10),
            None
        );
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&make_zip(&["x.txt"])).unwrap();
    }

    proptest::proptest! {
        #[test]
        fn zip_parser_never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
            let len = data.len() as u64;
            let _ = zip_entry_names(&mut Cursor::new(data), len, 50);
        }
    }
}
