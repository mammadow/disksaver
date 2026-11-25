#![forbid(unsafe_code)]

//! TOML rule schema, compiled-in rule packs, and path template expander.

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};

fn default_timeout() -> u64 {
    60
}

fn default_dism_timeout() -> u64 {
    // `/StartComponentCleanup /ResetBase` routinely takes 20-60 minutes on real machines; killing
    // Dism.exe mid-servicing is worse than waiting.
    7200 // 2 hours
}

fn default_pnputil_timeout() -> u64 {
    300 // 5 minutes
}

fn default_true() -> bool {
    true
}

/// Safety risk and review tier for cleanup rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleTier {
    Safe,
    Review,
    Advanced,
}

/// Cleanup execution method.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleMethod {
    /// Recursively delete directory contents while preserving the root directory.
    DeleteContents,
    /// Recursively delete directory contents older than `min_age_days`.
    DeleteOlderThan,
    /// Invoke a curated Windows VolumeCaches COM handler.
    OsHandler { handler_key: String },
    /// Execute an external CLI tool command, optionally falling back to `delete_contents`.
    Command {
        program: String,
        args: Vec<String>,
        fallback_delete_contents: bool,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        /// Tool locations tried before `PATH` (`%VAR%` templates), for tools that do not add
        /// themselves to `PATH` (e.g. `%USERPROFILE%\miniconda3\Scripts\conda.exe`). Never used by
        /// the elevated helper, which runs no tool commands at all.
        #[serde(default)]
        program_candidates: Vec<String>,
    },
    /// Windows Component Store (WinSxS) cleanup via DISM.exe.
    DismComponentCleanup {
        #[serde(default)]
        reset_base: bool,
        #[serde(default = "default_dism_timeout")]
        timeout_secs: u64,
    },
    /// Prune superseded unbound OEM driver packages via pnputil.exe.
    DriverStorePrune {
        #[serde(default = "default_pnputil_timeout")]
        timeout_secs: u64,
    },
}

/// Preconditions required before a rule can be executed safely.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconditionRule {
    /// Process image names that must not be running (e.g. `chrome.exe`).
    #[serde(default)]
    pub process_not_running: Vec<String>,
    /// Check whether Windows servicing or reboot is pending.
    #[serde(default)]
    pub check_servicing: bool,
    /// Exact filenames to preserve inside cleaned directories (e.g. `CBS.log`).
    #[serde(default)]
    pub exclude_names: Vec<String>,
}

/// Full declaration of a cleanup rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDef {
    /// Stable unique identifier (e.g. `sys.temp.windows`, `dev.cargo.cache`).
    pub id: String,
    /// User-facing descriptive name.
    pub name: String,
    /// Category grouping (e.g. `system`, `dev`, `browsers`, `apps`, `gaming`).
    pub category: String,
    /// Safety tier.
    pub tier: RuleTier,
    /// Whether target contents are regenerable caches.
    pub regenerable: bool,
    /// Whether administrative elevation is required.
    #[serde(default)]
    pub requires_admin: bool,
    /// Whether the rule is enabled by default in `--tier safe` plans.
    #[serde(default = "default_true")]
    pub default_enabled: bool,
    /// Path templates supporting environment variables and single-segment `*` wildcards.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Minimum file age in days for age-based rules.
    pub min_age_days: Option<u32>,
    /// Safety preconditions.
    #[serde(default)]
    pub preconditions: PreconditionRule,
    /// Cleanup execution method.
    pub method: RuleMethod,
    /// User-facing explanation of what this rule cleans and why it is safe.
    pub explain: String,
}

#[derive(Deserialize)]
struct RulesDocument {
    #[serde(default, alias = "rules")]
    rule: Vec<RuleDef>,
}

/// Parses rules from a TOML string representation.
pub fn parse_rules_toml(src: &str) -> Result<Vec<RuleDef>> {
    match toml::from_str::<RulesDocument>(src) {
        Ok(doc) if !doc.rule.is_empty() => Ok(doc.rule),
        Ok(_) => match toml::from_str::<Vec<RuleDef>>(src) {
            Ok(rules) => Ok(rules),
            Err(_) => Ok(Vec::new()),
        },
        Err(e) => {
            if let Ok(rules) = toml::from_str::<Vec<RuleDef>>(src) {
                return Ok(rules);
            }
            Err(DskError::RuleParse(e.to_string()))
        }
    }
}

/// Loads and parses all compiled-in rule packs, asserting unique rule IDs.
pub fn builtin_rules() -> Result<Vec<RuleDef>> {
    let packs: [(&'static str, &'static str); 6] = [
        ("system.toml", include_str!("../../rules/system.toml")),
        ("dev.toml", include_str!("../../rules/dev.toml")),
        ("browsers.toml", include_str!("../../rules/browsers.toml")),
        ("apps.toml", include_str!("../../rules/apps.toml")),
        ("gaming.toml", include_str!("../../rules/gaming.toml")),
        ("gpu.toml", include_str!("../../rules/gpu.toml")),
    ];

    let mut all_rules = Vec::new();
    let mut seen_ids = FxHashSet::default();

    for (pack_name, src) in packs {
        let rules = parse_rules_toml(src)
            .map_err(|e| DskError::RuleParse(format!("failed to parse {pack_name}: {e}")))?;
        for rule in rules {
            if !seen_ids.insert(rule.id.clone()) {
                return Err(DskError::RuleParse(format!(
                    "duplicate rule ID '{}' found in {}",
                    rule.id, pack_name
                )));
            }
            all_rules.push(rule);
        }
    }

    Ok(all_rules)
}

/// Expands `%VAR%` placeholders in path templates, normalizes slashes, and splits path segments.
///
/// Returns `None` if any `%VAR%` is missing, empty, or contains directory traversal (`..`),
/// or if any segment contains `..`. Preserves drive root (e.g. `"C:"`) as segment 0 and
/// single-segment `*` wildcards intact.
pub fn expand_path_template(
    tmpl: &str,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<Vec<String>> {
    if tmpl.trim().is_empty() {
        return None;
    }

    // Step 1: Expand %VAR% tokens
    let mut expanded = String::with_capacity(tmpl.len() + 32);
    let mut chars = tmpl.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut var_name = String::new();
            let mut closed = false;
            for vch in chars.by_ref() {
                if vch == '%' {
                    closed = true;
                    break;
                }
                var_name.push(vch);
            }

            if !closed || var_name.is_empty() {
                return None;
            }

            let val = env_lookup(&var_name)?;
            if val.trim().is_empty() || val.contains("..") {
                return None;
            }
            expanded.push_str(&val);
        } else {
            expanded.push(ch);
        }
    }

    // Step 2: Convert forward slashes to backslashes
    let mut s = expanded.replace('/', "\\");

    // Step 3: Handle verbatim prefixes
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        s = format!(r"\\{rest}");
    } else if let Some(rest) = s.strip_prefix(r"\??\UNC\") {
        s = format!(r"\\{rest}");
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix(r"\??\") {
        s = rest.to_string();
    }

    // Step 4: Split into segments
    let mut segments = Vec::new();
    let parts = s.split('\\');
    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        if trimmed == ".." {
            return None;
        }
        segments.push(trimmed.to_string());
    }

    if segments.is_empty() {
        return None;
    }

    // Step 5: Normalize drive root as segment 0 if applicable
    if segments[0].len() == 2 && segments[0].ends_with(':') {
        let drive_char = segments[0].chars().next()?;
        if drive_char.is_ascii_alphabetic() {
            segments[0] = format!("{}:", drive_char.to_ascii_uppercase());
        }
    }

    Some(segments)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::clean::deny::{DenyContext, is_denied_path};

    #[test]
    fn builtin_rules_parse_with_unique_ids_and_zero_denied_roots() {
        let rules = builtin_rules().expect("builtin rules must parse cleanly");
        assert!(!rules.is_empty(), "expected non-empty builtin rules");

        let mut seen_ids = FxHashSet::default();
        let deny_ctx = DenyContext::default_for_test();

        let test_env = |var: &str| -> Option<String> {
            match var {
                "SystemRoot" | "windir" => Some(r"C:\Windows".to_string()),
                "SystemDrive" => Some("C:".to_string()),
                "ProgramData" => Some(r"C:\ProgramData".to_string()),
                "ProgramFiles" => Some(r"C:\Program Files".to_string()),
                "ProgramFiles(x86)" => Some(r"C:\Program Files (x86)".to_string()),
                "USERPROFILE" => Some(r"C:\Users\Alice".to_string()),
                "LOCALAPPDATA" => Some(r"C:\Users\Alice\AppData\Local".to_string()),
                "APPDATA" => Some(r"C:\Users\Alice\AppData\Roaming".to_string()),
                "TEMP" | "TMP" => Some(r"C:\Users\Alice\AppData\Local\Temp".to_string()),
                "CARGO_HOME" => Some(r"C:\Users\Alice\.cargo".to_string()),
                "npm_config_cache" => Some(r"C:\Users\Alice\AppData\Local\npm-cache".to_string()),
                "PIP_CACHE_DIR" => Some(r"C:\Users\Alice\AppData\Local\pip\Cache".to_string()),
                "GOCACHE" => Some(r"C:\Users\Alice\AppData\Local\go-build".to_string()),
                _ => None,
            }
        };

        for rule in &rules {
            assert!(
                seen_ids.insert(rule.id.clone()),
                "duplicate rule ID detected: {}",
                rule.id
            );

            // Verify opt-in recycle bin rule safety
            if rule.id == "os.vc.recycle_bin" {
                assert!(
                    !rule.default_enabled,
                    "os.vc.recycle_bin MUST have default_enabled = false"
                );
            }

            // Verify CAS store rules never fall back to raw delete_contents
            if rule.id == "dev.pnpm.store" || rule.id == "dev.uv.cache" {
                match &rule.method {
                    RuleMethod::Command {
                        fallback_delete_contents,
                        ..
                    } => {
                        assert!(
                            !fallback_delete_contents,
                            "rule {} must set fallback_delete_contents = false",
                            rule.id
                        );
                    }
                    other => panic!(
                        "rule {} must use Command method, found {:?}",
                        rule.id, other
                    ),
                }
            }

            // Verify no expanded template literal resolves to a denied path
            for path_tmpl in &rule.paths {
                if let Some(segments) = expand_path_template(path_tmpl, &test_env) {
                    assert!(!segments.is_empty());
                    // Reassemble path for deny check, replacing single-segment wildcards with a sample folder name
                    let reassembled: String = segments
                        .iter()
                        .map(|s| {
                            if s == "*" {
                                "sample_profile"
                            } else {
                                s.as_str()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\\");

                    let is_denied = is_denied_path(Path::new(&reassembled), &deny_ctx);
                    assert!(
                        is_denied.is_none(),
                        "rule '{}' path template '{}' resolved to denied path '{}' ({:?})",
                        rule.id,
                        path_tmpl,
                        reassembled,
                        is_denied
                    );
                }
            }
        }
    }

    #[test]
    fn expand_template_supports_overrides_and_missing_vars() {
        let env = |var: &str| -> Option<String> {
            match var {
                "CARGO_HOME" => Some(r"D:\custom_cargo".to_string()),
                "USERPROFILE" => Some(r"C:\Users\Alice".to_string()),
                "EMPTY_VAR" => Some(String::new()),
                "TRAVERSAL_VAR" => Some(r"C:\Users\Alice\..\Bob".to_string()),
                _ => None,
            }
        };

        // 1. Explicit CARGO_HOME set
        let expanded = expand_path_template(r"%CARGO_HOME%\registry\cache", &env);
        assert_eq!(
            expanded,
            Some(vec![
                "D:".to_string(),
                "custom_cargo".to_string(),
                "registry".to_string(),
                "cache".to_string(),
            ])
        );

        // 2. Fallback when env var is unset: returns None cleanly
        let missing = expand_path_template(r"%NONEXISTENT_VAR%\sub", &env);
        assert_eq!(missing, None);

        // 3. Empty variable returns None
        let empty = expand_path_template(r"%EMPTY_VAR%\sub", &env);
        assert_eq!(empty, None);

        // 4. Traversal variable returns None
        let traversal = expand_path_template(r"%TRAVERSAL_VAR%\sub", &env);
        assert_eq!(traversal, None);

        // 5. Template with literal .. returns None
        let traversal_literal = expand_path_template(r"C:\Windows\..\Windows\Temp", &env);
        assert_eq!(traversal_literal, None);

        // 6. Template with forward slashes and verbatim \\?\ prefix
        let normalized = expand_path_template(r"\\?\C:/Users/Alice/AppData/Local/Temp", &env);
        assert_eq!(
            normalized,
            Some(vec![
                "C:".to_string(),
                "Users".to_string(),
                "Alice".to_string(),
                "AppData".to_string(),
                "Local".to_string(),
                "Temp".to_string(),
            ])
        );

        // 7. Wildcards preserved intact
        let wildcard =
            expand_path_template(r"%USERPROFILE%\AppData\Local\Google\Chrome\*\Cache", &env);
        assert_eq!(
            wildcard,
            Some(vec![
                "C:".to_string(),
                "Users".to_string(),
                "Alice".to_string(),
                "AppData".to_string(),
                "Local".to_string(),
                "Google".to_string(),
                "Chrome".to_string(),
                "*".to_string(),
                "Cache".to_string(),
            ])
        );
    }

    #[test]
    fn parse_rules_toml_handles_errors_and_empty() {
        assert_eq!(parse_rules_toml("").unwrap(), Vec::new());
        assert!(parse_rules_toml("invalid toml = =").is_err());
    }
}
