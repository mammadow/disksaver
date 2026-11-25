#![forbid(unsafe_code)]

//! Dynamic rule roots (P9.2): path templates may use multi-valued `%DSK_*%` placeholders whose
//! values come from analyzers instead of fixed locations:
//!
//! | Placeholder | Values |
//! |---|---|
//! | `%DSK_STEAM_LIBRARIES%` | every Steam library folder (from `libraryfolders.vdf`) |
//! | `%DSK_STEAM_ORPHAN_WORKSHOP%` | `steamapps\workshop\content\<appid>` of games no longer installed |
//! | `%DSK_GAME_REDIST%` | `_CommonRedist` folders inside installed Steam games |
//!
//! Values are joined with `|` (illegal in Windows paths) by the env lookup and split back here,
//! so one template expands to one root per value.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::index::{Index, NodeFlags};
use crate::insights::gaming::{GameStoreKind, GamingLibraryReport};

/// Separator for multi-valued placeholder values.
pub const DYNAMIC_SEP: char = '|';

/// Expands the first `%DSK_*%` placeholder in `tmpl` into one template per value. Templates
/// without one are returned as is; an unknown or empty placeholder yields nothing.
pub fn expand_dynamic_template(tmpl: &str, env: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let Some(start) = tmpl.find("%DSK_") else {
        return vec![tmpl.to_string()];
    };
    let Some(len) = tmpl[start + 1..].find('%') else {
        return Vec::new();
    };
    let var = &tmpl[start + 1..start + 1 + len];
    let Some(values) = env(var) else {
        return Vec::new();
    };
    values
        .split(DYNAMIC_SEP)
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.contains('%'))
        .map(|v| format!("{}{}{}", &tmpl[..start], v, &tmpl[start + len + 2..]))
        .collect()
}

/// Values for the `%DSK_*%` placeholders, computed from an index and its gaming report.
#[derive(Clone, Debug, Default)]
pub struct DynamicRoots {
    values: FxHashMap<&'static str, Vec<String>>,
}

impl DynamicRoots {
    pub fn get(&self, var: &str) -> Option<String> {
        self.values
            .get(var)
            .filter(|v| !v.is_empty())
            .map(|v| v.join(&DYNAMIC_SEP.to_string()))
    }

    pub fn values(&self, var: &str) -> &[String] {
        self.values.get(var).map(Vec::as_slice).unwrap_or(&[])
    }

    /// An env lookup that answers `%DSK_*%` from here and everything else from the process
    /// environment.
    pub fn env_lookup(&self) -> impl Fn(&str) -> Option<String> + '_ {
        move |k: &str| {
            if k.starts_with("DSK_") {
                self.get(k)
            } else {
                std::env::var(k).ok()
            }
        }
    }
}

/// Computes dynamic roots.
pub fn dynamic_roots(index: &Index, gaming: &GamingLibraryReport) -> DynamicRoots {
    let mut values: FxHashMap<&'static str, Vec<String>> = FxHashMap::default();

    // Steam libraries: library roots that contain `steamapps`.
    let mut libraries: Vec<std::path::PathBuf> = Vec::new();
    for root in &gaming.library_roots {
        if let Some(node) = index.find_by_path(&root.join("steamapps"))
            && index.flags(node).contains(NodeFlags::DIR)
            && !libraries.iter().any(|l| l == root)
        {
            libraries.push(root.clone());
        }
    }
    values.insert(
        "DSK_STEAM_LIBRARIES",
        libraries.iter().map(|p| p.display().to_string()).collect(),
    );

    // Workshop content of appids that are not installed in any library.
    let installed: FxHashSet<&str> = gaming
        .games
        .iter()
        .filter(|g| g.store == GameStoreKind::Steam)
        .filter_map(|g| g.app_id.as_deref())
        .collect();
    let mut orphan_workshop = Vec::new();
    for lib in &libraries {
        let content = lib.join("steamapps").join("workshop").join("content");
        let Some(node) = index.find_by_path(&content) else {
            continue;
        };
        for c in index.children(node) {
            let name = index.name(c);
            if index.flags(c).contains(NodeFlags::DIR)
                && !name.is_empty()
                && name.chars().all(|ch| ch.is_ascii_digit())
                && !installed.contains(name.as_ref())
            {
                orphan_workshop.push(content.join(name.as_ref()).display().to_string());
            }
        }
    }
    values.insert("DSK_STEAM_ORPHAN_WORKSHOP", orphan_workshop);

    // Redistributable installers inside installed Steam games.
    let mut redist = Vec::new();
    for g in gaming
        .games
        .iter()
        .filter(|g| g.store == GameStoreKind::Steam)
    {
        let p = g.install_path.join("_CommonRedist");
        if index.find_by_path(&p).is_some() {
            redist.push(p.display().to_string());
        }
    }
    values.insert("DSK_GAME_REDIST", redist);

    DynamicRoots { values }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_templates_expand_per_value() {
        let env = |k: &str| match k {
            "DSK_STEAM_LIBRARIES" => {
                Some(r"C:\Program Files (x86)\Steam|D:\SteamLibrary".to_string())
            }
            "DSK_EMPTY" => Some(String::new()),
            "DSK_EVIL" => Some(r"%SystemRoot%|D:\ok".to_string()),
            _ => None,
        };
        assert_eq!(
            expand_dynamic_template(r"%DSK_STEAM_LIBRARIES%\steamapps\downloading", &env),
            vec![
                r"C:\Program Files (x86)\Steam\steamapps\downloading".to_string(),
                r"D:\SteamLibrary\steamapps\downloading".to_string()
            ]
        );
        assert!(expand_dynamic_template(r"%DSK_EMPTY%\x", &env).is_empty());
        assert!(expand_dynamic_template(r"%DSK_MISSING%\x", &env).is_empty());
        assert_eq!(
            expand_dynamic_template(r"%DSK_EVIL%", &env),
            vec![r"D:\ok".to_string()],
            "values cannot smuggle new placeholders"
        );
        assert_eq!(
            expand_dynamic_template(r"%LOCALAPPDATA%\x", &env),
            vec![r"%LOCALAPPDATA%\x".to_string()]
        );
    }
}
