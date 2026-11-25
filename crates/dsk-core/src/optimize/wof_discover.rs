#![forbid(unsafe_code)]

//! WOF compression candidate discovery (P9.3): which installed app, toolchain, and game folders
//! shrink the most under transparent compression, measured with the codec-accurate sampler.

use std::path::{Path, PathBuf};

use crate::clean::deny::{DenyContext, is_denied_path};
use crate::index::{Index, NodeFlags, NodeId};
use crate::insights::GamingLibraryReport;
use crate::ledger::CompressCandidate;
use crate::optimize::wof::{WofAlgorithm, sample_folder_compressibility_algo};

/// Options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoverOptions {
    /// Folders smaller than this are not worth a candidate.
    pub min_folder_bytes: u64,
    /// Bytes read per folder by the sampler.
    pub sample_budget: u64,
    pub max_candidates: usize,
    /// Folders untouched this long get LZX (best ratio, slower to decompress).
    pub lzx_after_days: u32,
    /// Minutes since 2000-01-01 (`None` = now).
    pub now_min2000: Option<u32>,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            min_folder_bytes: 512 * 1024 * 1024,
            sample_budget: 8 * 1024 * 1024,
            max_candidates: 25,
            lzx_after_days: 90,
            now_min2000: None,
        }
    }
}

/// Launcher container folders under Program Files: their games are candidates one by one.
const LAUNCHER_CONTAINERS: &[&str] = &[
    "steam",
    "epic games",
    "ea games",
    "ubisoft",
    "gog galaxy",
    "riot games",
    "battle.net",
    "windowsapps",
    "windows defender",
    "windows nt",
    "windows mail",
    "windows media player",
    "windows photo viewer",
    "windows sidebar",
    "windowspowershell",
    "modifiablewindowsapps",
];

fn newest_mtime(index: &Index, node: NodeId) -> u32 {
    let mut newest = 0u32;
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        newest = newest.max(index.mtime_min(n));
        let f = index.flags(n);
        if f.contains(NodeFlags::DIR) && !f.contains(NodeFlags::REPARSE) {
            stack.extend(index.children(n));
        }
    }
    newest
}

/// Candidate folders to sample: Program Files children, the user's installed programs and
/// toolchains, and every launcher game.
pub fn candidate_roots(
    index: &Index,
    gaming: Option<&GamingLibraryReport>,
) -> Vec<(PathBuf, bool)> {
    let mut roots: Vec<(PathBuf, bool)> = Vec::new();
    let push_children = |dir: &Path, admin: bool, roots: &mut Vec<(PathBuf, bool)>| {
        if let Some(node) = index.find_by_path(dir) {
            for c in index.children(node) {
                let f = index.flags(c);
                if !f.contains(NodeFlags::DIR) || f.contains(NodeFlags::REPARSE) {
                    continue;
                }
                let name = index.name(c).to_ascii_lowercase();
                if LAUNCHER_CONTAINERS.contains(&name.as_str()) {
                    continue;
                }
                roots.push((dir.join(&*index.name(c)), admin));
            }
        }
    };
    push_children(&crate::win::volume::program_files_dir(), true, &mut roots);
    push_children(
        &crate::win::volume::program_files_x86_dir(),
        true,
        &mut roots,
    );
    if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        push_children(&local.join("Programs"), false, &mut roots);
    }
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        for t in [
            "miniconda3",
            "anaconda3",
            r".vscode\extensions",
            r".rustup\toolchains",
        ] {
            roots.push((home.join(t), false));
        }
    }
    if let Some(g) = gaming {
        let pf = crate::win::volume::program_files_dir();
        let pf86 = crate::win::volume::program_files_x86_dir();
        for game in &g.games {
            let admin = crate::clean::deny::is_under_root(&game.install_path, &pf)
                || crate::clean::deny::is_under_root(&game.install_path, &pf86);
            roots.push((game.install_path.clone(), admin));
        }
    }
    roots
}

/// Samples candidate folders and returns the ones that pass the 15 % gate, largest savings first.
pub fn discover_compress_candidates(
    index: &Index,
    gaming: Option<&GamingLibraryReport>,
    opts: &DiscoverOptions,
) -> Vec<CompressCandidate> {
    let deny = DenyContext::default();
    let now = opts
        .now_min2000
        .unwrap_or_else(crate::insights::current_min2000);
    let mut out: Vec<(u64, CompressCandidate)> = Vec::new();
    for (path, admin) in candidate_roots(index, gaming) {
        let Some(node) = index.find_by_path(&path) else {
            continue;
        };
        let total = index.total_allocated(node);
        if total < opts.min_folder_bytes || is_denied_path(&path, &deny).is_some() {
            continue;
        }
        let newest = newest_mtime(index, node);
        let cold = newest > 0 && now.saturating_sub(newest) / 1440 >= opts.lzx_after_days;
        let algorithm = if cold {
            WofAlgorithm::Lzx
        } else {
            WofAlgorithm::Xpress8k
        };
        let Ok(preview) =
            sample_folder_compressibility_algo(index, node, algorithm, opts.sample_budget)
        else {
            continue;
        };
        if !preview.recommended {
            continue;
        }
        let saved = preview.estimated_savings_bytes();
        if saved == 0 {
            continue;
        }
        out.push((
            saved,
            CompressCandidate {
                path,
                algorithm,
                savings_ratio: (saved as f64 / total.max(1) as f64).clamp(0.0, 1.0),
                measured: false,
                requires_admin: admin,
            },
        ));
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.0));
    out.into_iter()
        .take(opts.max_candidates)
        .map(|(_, c)| c)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_skip_launcher_containers() {
        assert!(LAUNCHER_CONTAINERS.contains(&"steam"));
        assert!(!LAUNCHER_CONTAINERS.contains(&"jetbrains"));
    }
}
