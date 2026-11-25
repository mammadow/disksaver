#![forbid(unsafe_code)]

//! Gaming library discovery & bounded Valve VDF/ACF parser (§9.4).
//!
//! Discovers installed games, Steam Workshop content, and Shader Caches across Steam,
//! Epic Games, Xbox/MS Store, GOG Galaxy, Battle.net, Riot Games, EA App, and Ubisoft Connect
//! using a strictly iterative VDF parser capped at `MAX_VDF_DEPTH = 16`.

use std::path::{Path, PathBuf};

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path};
use crate::error::{DskError, Result};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::insights::current_min2000;

/// Maximum nesting depth permitted by the Valve VDF/ACF parser (security/DoS guard).
pub const MAX_VDF_DEPTH: usize = 16;

const MAX_MANIFEST_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Parsed node inside a Valve KeyValues (`.vdf` / `.acf`) document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VdfValue {
    Str(String),
    Map(Vec<(String, VdfValue)>),
}

impl VdfValue {
    /// Returns child map entries if this node is a `Map`.
    pub fn as_map(&self) -> Option<&[(String, VdfValue)]> {
        match self {
            Self::Map(entries) => Some(entries.as_slice()),
            Self::Str(_) => None,
        }
    }

    /// Returns inner string if this node is a `Str`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            Self::Map(_) => None,
        }
    }

    /// Performs a case-insensitive child lookup when `self` is a `Map`.
    pub fn get_ci(&self, key: &str) -> Option<&VdfValue> {
        let map = self.as_map()?;
        map.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    }

    /// Performs a case-insensitive string lookup when `self` is a `Map`.
    pub fn get_str_ci(&self, key: &str) -> Option<&str> {
        self.get_ci(key).and_then(|v| v.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum VdfToken {
    Str(String),
    LBrace,
    RBrace,
}

fn tokenize_vdf(input: &str) -> Result<Vec<VdfToken>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // Skip C++/Valve `//` single-line comments.
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '{' {
            tokens.push(VdfToken::LBrace);
            i += 1;
            continue;
        }
        if c == '}' {
            tokens.push(VdfToken::RBrace);
            i += 1;
            continue;
        }
        if c == '"' {
            i += 1;
            let mut s = String::new();
            let mut terminated = false;
            while i < chars.len() {
                let ch = chars[i];
                if ch == '"' {
                    terminated = true;
                    i += 1;
                    break;
                }
                if ch == '\\' {
                    i += 1;
                    if i >= chars.len() {
                        return Err(DskError::RuleParse(
                            "unterminated escape sequence inside VDF string".to_string(),
                        ));
                    }
                    let esc = match chars[i] {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '\\' => '\\',
                        '"' => '"',
                        other => other,
                    };
                    s.push(esc);
                    i += 1;
                } else {
                    s.push(ch);
                    i += 1;
                }
            }
            if !terminated {
                return Err(DskError::RuleParse(
                    "unterminated quoted string in VDF document".to_string(),
                ));
            }
            tokens.push(VdfToken::Str(s));
            continue;
        }

        // Unquoted bare token (terminated by whitespace, braces, or quotes).
        let mut bare = String::new();
        while i < chars.len() {
            let ch = chars[i];
            if ch.is_whitespace() || ch == '{' || ch == '}' || ch == '"' {
                break;
            }
            if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
                break;
            }
            bare.push(ch);
            i += 1;
        }
        if !bare.is_empty() {
            tokens.push(VdfToken::Str(bare));
        }
    }

    Ok(tokens)
}

/// Strictly iterative, depth-bounded parser for Valve VDF/ACF documents (`MAX_VDF_DEPTH = 16`).
pub fn parse_vdf(input: &str) -> Result<VdfValue> {
    let tokens = tokenize_vdf(input)?;

    struct Frame {
        key: Option<String>,
        entries: Vec<(String, VdfValue)>,
    }

    let mut stack: Vec<Frame> = vec![Frame {
        key: None,
        entries: Vec::new(),
    }];
    let mut pending_key: Option<String> = None;

    for tok in tokens {
        match tok {
            VdfToken::Str(s) => {
                if let Some(key) = pending_key.take() {
                    if let Some(top) = stack.last_mut() {
                        top.entries.push((key, VdfValue::Str(s)));
                    }
                } else {
                    pending_key = Some(s);
                }
            }
            VdfToken::LBrace => {
                let key = pending_key.take().ok_or_else(|| {
                    DskError::RuleParse("unexpected '{' without preceding VDF key".to_string())
                })?;
                if stack.len() >= MAX_VDF_DEPTH {
                    return Err(DskError::RuleParse(format!(
                        "VDF nesting depth exceeds limit {MAX_VDF_DEPTH}"
                    )));
                }
                stack.push(Frame {
                    key: Some(key),
                    entries: Vec::new(),
                });
            }
            VdfToken::RBrace => {
                if pending_key.is_some() {
                    return Err(DskError::RuleParse(
                        "unexpected '}' before VDF value for key".to_string(),
                    ));
                }
                if stack.len() <= 1 {
                    return Err(DskError::RuleParse(
                        "unexpected unmatched '}' at VDF root".to_string(),
                    ));
                }
                let finished = stack.pop().ok_or_else(|| {
                    DskError::RuleParse("internal VDF parser frame underflow".to_string())
                })?;
                let key = finished.key.ok_or_else(|| {
                    DskError::RuleParse("missing key for closed VDF block".to_string())
                })?;
                if let Some(parent) = stack.last_mut() {
                    parent.entries.push((key, VdfValue::Map(finished.entries)));
                }
            }
        }
    }

    if pending_key.is_some() {
        return Err(DskError::RuleParse(
            "unexpected EOF waiting for VDF value".to_string(),
        ));
    }
    if stack.len() != 1 {
        return Err(DskError::RuleParse(
            "unclosed '{' block in VDF document".to_string(),
        ));
    }

    let root = stack.pop().expect("root frame verified");
    Ok(VdfValue::Map(root.entries))
}

/// Supported PC game launcher/store ecosystems.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GameStoreKind {
    Steam,
    SteamWorkshop,
    SteamShaderCache,
    EpicGames,
    Xbox,
    GogGalaxy,
    BattleNet,
    RiotGames,
    EaApp,
    UbisoftConnect,
}

impl GameStoreKind {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Steam => "Steam",
            Self::SteamWorkshop => "Steam Workshop",
            Self::SteamShaderCache => "Steam Shader Cache",
            Self::EpicGames => "Epic Games",
            Self::Xbox => "Xbox / MS Store",
            Self::GogGalaxy => "GOG Galaxy",
            Self::BattleNet => "Battle.net",
            Self::RiotGames => "Riot Games",
            Self::EaApp => "EA App",
            Self::UbisoftConnect => "Ubisoft Connect",
        }
    }
}

/// Discovered game installation or associated Steam cache directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredGame {
    pub store: GameStoreKind,
    pub app_id: Option<String>,
    pub title: String,
    pub install_path: PathBuf,
    pub workshop_path: Option<PathBuf>,
    pub shadercache_path: Option<PathBuf>,
    pub allocated_bytes: u64,
    pub days_since_access: Option<u32>,
}

/// Summary of discovered PC gaming stores and games on the scanned volume.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GamingLibraryReport {
    pub library_roots: Vec<PathBuf>,
    pub games: Vec<DiscoveredGame>,
    pub total_allocated_bytes: u64,
}

fn read_bounded_utf8(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_MANIFEST_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn measure_subtree_alloc_and_days(index: &Index, root: NodeId, now_mins: u32) -> (u64, u32) {
    let mut stack = vec![root];
    let mut seen_fids: FxHashSet<u64> = FxHashSet::default();
    let mut alloc = 0u64;
    let mut newest_touch = 0u32;

    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if flags.contains(NodeFlags::DIR) {
            if node != root && flags.contains(NodeFlags::REPARSE) {
                continue;
            }
            for child in index.children(node) {
                stack.push(child);
            }
            continue;
        }
        let fid = index.file_id(node);
        if fid == 0 || seen_fids.insert(fid) {
            alloc = alloc.saturating_add(index.allocated(node));
        }
        let touch = index.atime_min(node).max(index.mtime_min(node));
        newest_touch = newest_touch.max(touch);
    }

    let days = if newest_touch == 0 || now_mins <= newest_touch {
        0
    } else {
        (now_mins - newest_touch) / 1440
    };
    (alloc, days)
}

fn measure_path_or_default(index: &Index, path: &Path, now_mins: u32) -> (u64, Option<u32>) {
    if let Some(node) = index.find_by_path(path) {
        let (bytes, days) = measure_subtree_alloc_and_days(index, node, now_mins);
        (bytes, Some(days))
    } else {
        (0, None)
    }
}

#[derive(Clone, Debug, Default)]
struct AcfMeta {
    appid: Option<String>,
    name: Option<String>,
    installdir: Option<String>,
    size_on_disk: u64,
}

/// Steam app IDs are plain decimal numbers.
fn is_valid_steam_appid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit())
}

/// `installdir` must be a single folder name under `steamapps\common`. The `.acf` files are
/// user-writable, and `Path::join` with an absolute or `..` value would escape the library and
/// point remediation (recycle) actions at arbitrary folders.
fn is_safe_steam_installdir(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() <= 255
        && t != "."
        && t != ".."
        && !t.chars().any(|c| {
            matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control()
        })
}

fn parse_acf_metadata(raw: &str) -> Option<AcfMeta> {
    let parsed = parse_vdf(raw).ok()?;
    let state = parsed
        .get_ci("AppState")
        .or_else(|| parsed.as_map().and_then(|m| m.first().map(|(_, v)| v)))?;
    let appid = state
        .get_str_ci("appid")
        .filter(|s| is_valid_steam_appid(s))
        .map(str::to_string);
    let name = state.get_str_ci("name").map(str::to_string);
    let installdir = state
        .get_str_ci("installdir")
        .filter(|s| is_safe_steam_installdir(s))
        .map(str::to_string);
    let size_on_disk = state
        .get_str_ci("SizeOnDisk")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    Some(AcfMeta {
        appid,
        name,
        installdir,
        size_on_disk,
    })
}

#[derive(Deserialize)]
struct EpicItemManifest {
    #[serde(rename = "DisplayName")]
    display_name: Option<String>,
    #[serde(rename = "InstallLocation")]
    install_location: Option<String>,
    #[serde(rename = "CatalogItemId")]
    catalog_item_id: Option<String>,
    #[serde(rename = "InstallSize")]
    install_size: Option<u64>,
}

fn path_key(p: &Path) -> String {
    p.to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase()
}

/// Scans an [`Index`] (augmented cleanly with bounded on-disk Steam `.vdf`/`.acf` and Epic
/// `.item` manifests when present) to catalog installed PC game libraries (§9.4).
pub fn scan_gaming_libraries(index: &Index) -> GamingLibraryReport {
    let deny_ctx = DenyContext::default();
    let now_mins = current_min2000();

    let mut seen_game_paths: FxHashSet<String> = FxHashSet::default();
    let mut seen_library_roots: FxHashSet<String> = FxHashSet::default();
    let mut library_roots: Vec<PathBuf> = Vec::new();
    let mut games: Vec<DiscoveredGame> = Vec::new();

    let mut steamapps_nodes: Vec<NodeId> = Vec::new();

    // First walk the Index to discover steamapps, Epic manifests, and known publisher game roots.
    let mut stack = vec![ROOT];
    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if node != ROOT
            && flags.intersects(
                NodeFlags::REPARSE | NodeFlags::SYSTEM | NodeFlags::ORPHANS | NodeFlags::OFFLINE,
            )
        {
            continue;
        }
        if !flags.contains(NodeFlags::DIR) {
            let name_lower = index.name(node).to_ascii_lowercase();
            let path = index.path(node);
            if name_lower.ends_with(".item")
                && path
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains(r"\epicgameslauncher\data\manifests\")
                && let Some(raw) = read_bounded_utf8(&path)
                && let Ok(manifest) = serde_json::from_str::<EpicItemManifest>(&raw)
                && let Some(loc) = manifest.install_location
            {
                let install_path = PathBuf::from(&loc);
                let key = path_key(&install_path);
                if !key.is_empty()
                    && is_denied_path(&install_path, &deny_ctx).is_none()
                    && seen_game_paths.insert(key)
                {
                    let (idx_bytes, days) = measure_path_or_default(index, &install_path, now_mins);
                    let allocated = if idx_bytes > 0 {
                        idx_bytes
                    } else {
                        manifest.install_size.unwrap_or(0)
                    };
                    let title = manifest.display_name.unwrap_or_else(|| {
                        install_path
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "Epic Game".to_string())
                    });
                    games.push(DiscoveredGame {
                        store: GameStoreKind::EpicGames,
                        app_id: manifest.catalog_item_id,
                        title,
                        install_path,
                        workshop_path: None,
                        shadercache_path: None,
                        allocated_bytes: allocated,
                        days_since_access: days,
                    });
                }
            }
            continue;
        }

        let dir_path = index.path(node);
        let name_lower = index.name(node).to_ascii_lowercase();
        let path_lower = dir_path.to_string_lossy().to_ascii_lowercase();

        if name_lower == "steamapps" {
            steamapps_nodes.push(node);
            if let Some(parent) = dir_path.parent() {
                let k = path_key(parent);
                if seen_library_roots.insert(k) {
                    library_roots.push(parent.to_path_buf());
                }
            }
        } else if let Some(store) = classify_launcher_games_parent(&path_lower, &name_lower) {
            let k = path_key(&dir_path);
            if seen_library_roots.insert(k) {
                library_roots.push(dir_path.clone());
            }
            for child in index.children(node) {
                if !index.flags(child).contains(NodeFlags::DIR) {
                    continue;
                }
                let child_name = index.name(child).into_owned();
                let child_lower = child_name.to_ascii_lowercase();
                if matches!(
                    child_lower.as_str(),
                    "riot client" | "commonredist" | "directx" | "launcher"
                ) {
                    continue;
                }
                let install_path = index.path(child);
                if is_denied_path(&install_path, &deny_ctx).is_some() {
                    continue;
                }
                let gk = path_key(&install_path);
                if !seen_game_paths.insert(gk) {
                    continue;
                }
                let (allocated_bytes, days) =
                    measure_subtree_alloc_and_days(index, child, now_mins);
                games.push(DiscoveredGame {
                    store,
                    app_id: None,
                    title: child_name,
                    install_path,
                    workshop_path: None,
                    shadercache_path: None,
                    allocated_bytes,
                    days_since_access: Some(days),
                });
            }
            continue;
        }

        let start = stack.len();
        for child in index.children(node) {
            stack.push(child);
        }
        stack[start..].reverse();
    }

    // Parse Steam `libraryfolders.vdf` & `appmanifest_*.acf` inside discovered `steamapps` folders.
    let mut extra_steamapps: Vec<PathBuf> = Vec::new();
    for sa_id in &steamapps_nodes {
        let sa_path = index.path(*sa_id);
        let vdf_path = sa_path.join("libraryfolders.vdf");
        if let Some(raw_vdf) = read_bounded_utf8(&vdf_path)
            && let Ok(parsed) = parse_vdf(&raw_vdf)
            && let Some(root_map) = parsed
                .get_ci("libraryfolders")
                .and_then(|v| v.as_map())
                .or_else(|| parsed.as_map())
        {
            for (_entry_key, val) in root_map {
                if let Some(lib_path_str) = val.get_str_ci("path") {
                    let lib_root = PathBuf::from(lib_path_str);
                    let lk = path_key(&lib_root);
                    if seen_library_roots.insert(lk) {
                        library_roots.push(lib_root.clone());
                    }
                    let cand_sa = lib_root.join("steamapps");
                    if cand_sa != sa_path && index.find_by_path(&cand_sa).is_some() {
                        extra_steamapps.push(cand_sa);
                    }
                }
            }
        }
    }

    for extra_sa in extra_steamapps {
        if let Some(node) = index.find_by_path(&extra_sa)
            && !steamapps_nodes.contains(&node)
        {
            steamapps_nodes.push(node);
        }
    }

    for sa_id in steamapps_nodes {
        let sa_path = index.path(sa_id);
        let common_path = sa_path.join("common");
        let workshop_content_root = sa_path.join("workshop").join("content");
        let shadercache_root = sa_path.join("shadercache");

        let mut linked_workshop_ids: FxHashSet<String> = FxHashSet::default();
        let mut linked_shader_ids: FxHashSet<String> = FxHashSet::default();

        for child in index.children(sa_id) {
            if index.flags(child).contains(NodeFlags::DIR) {
                continue;
            }
            let fname_lower = index.name(child).to_ascii_lowercase();
            if !(fname_lower.starts_with("appmanifest_") && fname_lower.ends_with(".acf")) {
                continue;
            }
            let acf_path = index.path(child);
            let acf = read_bounded_utf8(&acf_path).and_then(|raw| parse_acf_metadata(&raw));
            let Some(meta) = acf else {
                continue;
            };
            let Some(installdir) = meta.installdir else {
                continue;
            };
            let install_path = common_path.join(&installdir);
            if is_denied_path(&install_path, &deny_ctx).is_some() {
                continue;
            }
            let gk = path_key(&install_path);
            if !seen_game_paths.insert(gk) {
                continue;
            }

            let (idx_alloc, days) = measure_path_or_default(index, &install_path, now_mins);
            let mut allocated = if idx_alloc > 0 {
                idx_alloc
            } else {
                meta.size_on_disk
            };

            let mut workshop_path = None;
            let mut shadercache_path = None;
            if let Some(ref aid) = meta.appid {
                let ws = workshop_content_root.join(aid);
                if let Some(ws_node) = index.find_by_path(&ws) {
                    let (ws_bytes, _) = measure_subtree_alloc_and_days(index, ws_node, now_mins);
                    allocated = allocated.saturating_add(ws_bytes);
                    workshop_path = Some(ws);
                    linked_workshop_ids.insert(aid.clone());
                }
                let sc = shadercache_root.join(aid);
                if let Some(sc_node) = index.find_by_path(&sc) {
                    let (sc_bytes, _) = measure_subtree_alloc_and_days(index, sc_node, now_mins);
                    allocated = allocated.saturating_add(sc_bytes);
                    shadercache_path = Some(sc);
                    linked_shader_ids.insert(aid.clone());
                }
            }

            games.push(DiscoveredGame {
                store: GameStoreKind::Steam,
                app_id: meta.appid,
                title: meta.name.unwrap_or(installdir),
                install_path,
                workshop_path,
                shadercache_path,
                allocated_bytes: allocated,
                days_since_access: days,
            });
        }

        // Also surface unattached folders inside `steamapps/common` when `.acf` was absent.
        if let Some(common_node) = index.find_by_path(&common_path) {
            for child in index.children(common_node) {
                if !index.flags(child).contains(NodeFlags::DIR) {
                    continue;
                }
                let child_path = index.path(child);
                if is_denied_path(&child_path, &deny_ctx).is_some() {
                    continue;
                }
                let gk = path_key(&child_path);
                if !seen_game_paths.insert(gk) {
                    continue;
                }
                let (allocated_bytes, days) =
                    measure_subtree_alloc_and_days(index, child, now_mins);
                games.push(DiscoveredGame {
                    store: GameStoreKind::Steam,
                    app_id: None,
                    title: index.name(child).into_owned(),
                    install_path: child_path,
                    workshop_path: None,
                    shadercache_path: None,
                    allocated_bytes,
                    days_since_access: Some(days),
                });
            }
        }

        // Surface orphaned/unattached Steam Workshop & Shader Cache directories (>= 1 MiB).
        for (root_path, linked, kind, label) in [
            (
                workshop_content_root,
                linked_workshop_ids,
                GameStoreKind::SteamWorkshop,
                "Workshop App",
            ),
            (
                shadercache_root,
                linked_shader_ids,
                GameStoreKind::SteamShaderCache,
                "Shader Cache App",
            ),
        ] {
            if let Some(cache_root_node) = index.find_by_path(&root_path) {
                for child in index.children(cache_root_node) {
                    if !index.flags(child).contains(NodeFlags::DIR) {
                        continue;
                    }
                    let id_name = index.name(child).into_owned();
                    if linked.contains(&id_name) {
                        continue;
                    }
                    let cpath = index.path(child);
                    let ck = path_key(&cpath);
                    if !seen_game_paths.insert(ck) {
                        continue;
                    }
                    let (allocated_bytes, days) =
                        measure_subtree_alloc_and_days(index, child, now_mins);
                    if allocated_bytes >= 1_048_576 {
                        games.push(DiscoveredGame {
                            store: kind,
                            app_id: Some(id_name.clone()),
                            title: format!("{label} {id_name}"),
                            install_path: cpath,
                            workshop_path: None,
                            shadercache_path: None,
                            allocated_bytes,
                            days_since_access: Some(days),
                        });
                    }
                }
            }
        }
    }

    games.sort_by(|a, b| {
        b.allocated_bytes
            .cmp(&a.allocated_bytes)
            .then_with(|| a.title.cmp(&b.title))
    });
    let total_allocated_bytes = games
        .iter()
        .fold(0u64, |acc, g| acc.saturating_add(g.allocated_bytes));

    GamingLibraryReport {
        library_roots,
        games,
        total_allocated_bytes,
    }
}

fn classify_launcher_games_parent(path_lower: &str, name_lower: &str) -> Option<GameStoreKind> {
    if name_lower == "xboxgames" || path_lower.ends_with(r"\modifiablewindowsapps") {
        return Some(GameStoreKind::Xbox);
    }
    if path_lower.ends_with(r"\epic games") {
        return Some(GameStoreKind::EpicGames);
    }
    if path_lower.ends_with(r"\gog galaxy\games") {
        return Some(GameStoreKind::GogGalaxy);
    }
    if name_lower == "riot games" {
        return Some(GameStoreKind::RiotGames);
    }
    if path_lower.ends_with(r"\ea games") {
        return Some(GameStoreKind::EaApp);
    }
    if path_lower.ends_with(r"\ubisoft game launcher\games") {
        return Some(GameStoreKind::UbisoftConnect);
    }
    if name_lower == "battle.net" && path_lower.contains(r"program files") {
        return Some(GameStoreKind::BattleNet);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::volume::VolumeInfo;
    use proptest::prelude::*;

    #[test]
    fn acf_metadata_rejects_path_escaping_installdir_and_non_numeric_appid() {
        let ok = parse_acf_metadata(
            "\"AppState\" { \"appid\" \"730\" \"installdir\" \"Counter-Strike Global Offensive\" }",
        )
        .unwrap();
        assert_eq!(ok.appid.as_deref(), Some("730"));
        assert_eq!(
            ok.installdir.as_deref(),
            Some("Counter-Strike Global Offensive")
        );

        for (appid, installdir) in [
            (r"C:\\Users\\X\\Downloads", r"C:\\Users\\X\\Documents"),
            ("..", ".."),
            (r"..\\..\\Desktop", r"..\\..\\Desktop"),
            ("12a", "sub/dir"),
        ] {
            let raw =
                format!("\"AppState\" {{ \"appid\" \"{appid}\" \"installdir\" \"{installdir}\" }}");
            let meta = parse_acf_metadata(&raw).unwrap();
            assert_eq!(meta.appid, None, "appid {appid:?} must be rejected");
            assert_eq!(
                meta.installdir, None,
                "installdir {installdir:?} must be rejected"
            );
        }
    }
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn vdf_parser_enforces_max_depth_and_handles_escapes_and_comments() {
        let valid = r#"
        // Steam library registry
        "libraryfolders"
        {
            "0"
            {
                "path"      "D:\\SteamLibrary"
                "apps"
                {
                    "730"   "12345"
                }
            }
        }
        "#;
        let parsed = parse_vdf(valid).expect("parse valid vdf");
        let libs = parsed.get_ci("libraryfolders").expect("libraryfolders");
        let entry0 = libs.get_ci("0").expect("entry 0");
        assert_eq!(entry0.get_str_ci("path"), Some(r"D:\SteamLibrary"));
        assert_eq!(
            entry0.get_ci("apps").and_then(|a| a.get_str_ci("730")),
            Some("12345")
        );

        // Depth == MAX_VDF_DEPTH - 1 nested blocks (1 root + 15 explicit = 16 frames total) succeeds.
        let mut depth_16 = String::new();
        for i in 0..15 {
            depth_16.push_str(&format!("\"k{i}\" {{ "));
        }
        depth_16.push_str("\"leaf\" \"ok\" ");
        for _ in 0..15 {
            depth_16.push_str("} ");
        }
        assert!(parse_vdf(&depth_16).is_ok());

        // Depth > MAX_VDF_DEPTH rejects cleanly without stack overflow.
        let mut too_deep = String::new();
        for i in 0..17 {
            too_deep.push_str(&format!("\"k{i}\" {{ "));
        }
        for _ in 0..17 {
            too_deep.push_str("} ");
        }
        assert!(parse_vdf(&too_deep).is_err());

        // Malformed inputs return clean Err.
        assert!(parse_vdf(r#""unclosed" "abc"#).is_err());
        assert!(parse_vdf(r#"}"#).is_err());
        assert!(parse_vdf(r#""k" {"#).is_err());
        assert!(parse_vdf(r#""orphan_key""#).is_err());
    }

    proptest! {
        #[test]
        fn proptest_vdf_parser_never_panics_on_arbitrary_input(s in ".*") {
            let _ = parse_vdf(&s);
        }
    }

    #[test]
    fn scans_steam_vdf_acf_workshop_shadercache_and_xbox_riot() {
        let dir = tempdir().expect("tempdir");
        let steamapps = dir.path().join("SteamLibrary").join("steamapps");
        let common_game = steamapps.join("common").join("HalfLife3");
        let ws = steamapps.join("workshop").join("content").join("730");
        let orphaned_ws = steamapps.join("workshop").join("content").join("9999");
        let sc = steamapps.join("shadercache").join("730");
        let xbox_game = dir.path().join("XboxGames").join("Starfield");
        let riot_game = dir.path().join("Riot Games").join("VALORANT");
        let riot_client = dir.path().join("Riot Games").join("Riot Client");

        fs::create_dir_all(&common_game).expect("mkdir");
        fs::create_dir_all(&ws).expect("mkdir");
        fs::create_dir_all(&orphaned_ws).expect("mkdir");
        fs::create_dir_all(&sc).expect("mkdir");
        fs::create_dir_all(&xbox_game).expect("mkdir");
        fs::create_dir_all(&riot_game).expect("mkdir");
        fs::create_dir_all(&riot_client).expect("mkdir");

        fs::write(
            steamapps.join("libraryfolders.vdf"),
            format!(
                "\"libraryfolders\" {{ \"0\" {{ \"path\" \"{}\" }} }}",
                dir.path()
                    .join("SteamLibrary")
                    .to_string_lossy()
                    .replace('\\', "\\\\")
            ),
        )
        .expect("write vdf");
        fs::write(
            steamapps.join("appmanifest_730.acf"),
            "\"AppState\" { \"appid\" \"730\" \"name\" \"Half-Life 3\" \"installdir\" \"HalfLife3\" \"SizeOnDisk\" \"50000000\" }",
        )
        .expect("write acf");

        let mut names = NameArena::new();
        let root_str = dir.path().to_string_lossy().into_owned();
        let n_root = names.push_str(&root_str);
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
        let mut next_k = 10u64;
        let mut add = |parent: u64, name: &str, bytes: Option<u64>| {
            let key = next_k;
            next_k += 1;
            let n = names.push_str(name);
            let is_dir = bytes.is_none();
            let sz = bytes.unwrap_or(0);
            raw.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags: if is_dir {
                    NodeFlags::DIR
                } else {
                    NodeFlags::empty()
                },
                logical: sz,
                allocated: sz,
                mtime: 0,
                atime: 0,
                file_id: key,
                reparse_tag: 0,
            });
            key
        };

        let sl = add(5, "SteamLibrary", None);
        let sa = add(sl, "steamapps", None);
        add(sa, "libraryfolders.vdf", Some(128));
        add(sa, "appmanifest_730.acf", Some(128));
        let common = add(sa, "common", None);
        let hl3 = add(common, "HalfLife3", None);
        add(hl3, "game.pak", Some(4_000_000_000));
        let w = add(sa, "workshop", None);
        let wc = add(w, "content", None);
        let w730 = add(wc, "730", None);
        add(w730, "mod.vpk", Some(500_000_000));
        let w9999 = add(wc, "9999", None);
        add(w9999, "orphan.vpk", Some(2_000_000));
        let sc_dir = add(sa, "shadercache", None);
        let sc730 = add(sc_dir, "730", None);
        add(sc730, "dx12.cache", Some(200_000_000));

        let xb = add(5, "XboxGames", None);
        let sf = add(xb, "Starfield", None);
        add(sf, "starfield.exe", Some(1_000_000_000));

        let rg = add(5, "Riot Games", None);
        let val = add(rg, "VALORANT", None);
        add(val, "pakchunk.pak", Some(800_000_000));
        let rc = add(rg, "Riot Client", None);
        add(rc, "RiotClientServices.exe", Some(50_000_000));

        let mut b = IndexBuilder::new(
            5,
            &root_str,
            VolumeInfo {
                root: root_str.clone(),
                ..Default::default()
            },
        );
        b.push_batch(EntryBatch {
            entries: raw,
            names,
        });
        let index = b.finish();

        let report = scan_gaming_libraries(&index);
        assert!(report.games.iter().any(|g| g.title == "Half-Life 3"
            && g.store == GameStoreKind::Steam
            && g.allocated_bytes == 4_700_000_000
            && g.workshop_path.is_some()
            && g.shadercache_path.is_some()));
        assert!(report.games.iter().any(
            |g| g.store == GameStoreKind::SteamWorkshop && g.app_id.as_deref() == Some("9999")
        ));
        assert!(
            report
                .games
                .iter()
                .any(|g| g.store == GameStoreKind::Xbox && g.title == "Starfield")
        );
        assert!(
            report
                .games
                .iter()
                .any(|g| g.store == GameStoreKind::RiotGames && g.title == "VALORANT")
        );
        assert!(!report.games.iter().any(|g| g.title == "Riot Client"));
    }
}
