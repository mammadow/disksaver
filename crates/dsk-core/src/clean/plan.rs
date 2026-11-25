#![forbid(unsafe_code)]

//! CleanPlan data model and zero-I/O Index matcher.

use std::path::Path;

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path, is_under_root, normalize_win_path_str};
use crate::clean::rules::{PreconditionRule, RuleDef, RuleMethod, RuleTier, expand_path_template};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::scan::ScanMethod;
use crate::time::filetime_to_min2000;
use crate::win::volume_root_of;

/// Identifier pinning kind used to validate files prior to deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileIdKind {
    NtfsFrn64,
    FxHash128,
    Unpinned,
}

/// A planned file, directory, or link item scheduled for cleanup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedItem {
    pub rel_path: String,
    pub expected_file_id: u64,
    pub bytes: u64,
    pub is_dir: bool,
    pub mtime_min: u32,
}

/// A resolved root directory under which planned items are scoped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRoot {
    pub root_path: String,
    pub root_file_id: u64,
    pub file_id_kind: FileIdKind,
    pub min_age_days: Option<u32>,
    pub exclude_names: Vec<String>,
    pub allow_unlisted_children: bool,
    pub items: Vec<PlannedItem>,
}

/// A cleanup rule with resolved roots and planned items ready for execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRule {
    pub rule_id: String,
    pub name: String,
    pub category: String,
    pub tier: RuleTier,
    pub regenerable: bool,
    pub requires_admin: bool,
    pub method: RuleMethod,
    pub preconditions: PreconditionRule,
    pub explain: String,
    pub est_bytes: u64,
    pub item_count: u64,
    pub roots: Vec<PlannedRoot>,
    pub os_handler_bytes: Option<u64>,
    /// How `est_bytes` was obtained. `#[serde(default)]` keeps older plans and helper builds
    /// wire-compatible.
    #[serde(default)]
    pub estimate: EstimateBasis,
}

/// How a planned rule's `est_bytes` was obtained (P9.0): a zero is only meaningful when the
/// estimate was actually measured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstimateBasis {
    /// Summed from scanned items, or reported by the Windows cleanup handler.
    #[default]
    Measured,
    /// The tool (DISM, pnputil) decides what it removes; the size is known only after it runs.
    AtRunTime,
    /// The plan was built without administrator rights, so system locations or the handler's
    /// own estimate were not visible: `est_bytes` is a lower bound, often 0.
    NeedsAdmin,
}

impl EstimateBasis {
    /// Short qualifier shown next to the byte estimate, or `None` for measured estimates.
    pub fn note(self) -> Option<&'static str> {
        match self {
            Self::Measured => None,
            Self::AtRunTime => Some("size known after it runs"),
            Self::NeedsAdmin => Some("needs admin to estimate"),
        }
    }
}

/// Marks admin-only rules of a plan built without elevation as [`EstimateBasis::NeedsAdmin`].
/// Call after [`build_plan_from_index`] (and handler enrichment) with the building process's
/// elevation state; a no-op when `elevated`.
pub fn mark_admin_gated_estimates(plan: &mut CleanPlan, elevated: bool) {
    if elevated {
        return;
    }
    for rule in &mut plan.rules {
        if rule.requires_admin && rule.estimate == EstimateBasis::Measured {
            rule.estimate = EstimateBasis::NeedsAdmin;
        }
    }
}

/// A rule that was evaluated but skipped during plan generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedRule {
    pub rule_id: String,
    pub name: String,
    pub reason: String,
}

/// A complete, serializable cleanup plan produced from an in-memory index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanPlan {
    pub version: u32,
    pub scanned_path: String,
    pub volume_root: String,
    pub scan_method: ScanMethod,
    pub total_est_bytes: u64,
    pub rules: Vec<PlannedRule>,
    pub skipped: Vec<SkippedRule>,
}

impl CleanPlan {
    /// Returns a new `CleanPlan` retaining only the rules whose `rule_id` matches `selected_ids`.
    ///
    /// Excluded rules are appended to `skipped` with reason `"unchecked in UI"`, and `total_est_bytes`
    /// is recomputed from the retained rules.
    pub fn filtered_rules(&self, selected_ids: &[String]) -> CleanPlan {
        let selected_set: FxHashSet<&str> = selected_ids.iter().map(|s| s.as_str()).collect();
        let mut retained_rules = Vec::new();
        let mut skipped = self.skipped.clone();

        for rule in &self.rules {
            if selected_set.contains(rule.rule_id.as_str()) {
                retained_rules.push(rule.clone());
            } else {
                skipped.push(SkippedRule {
                    rule_id: rule.rule_id.clone(),
                    name: rule.name.clone(),
                    reason: "unchecked in UI".to_string(),
                });
            }
        }

        let total_est_bytes: u64 = retained_rules.iter().map(|r| r.est_bytes).sum();

        CleanPlan {
            version: self.version,
            scanned_path: self.scanned_path.clone(),
            volume_root: self.volume_root.clone(),
            scan_method: self.scan_method,
            total_est_bytes,
            rules: retained_rules,
            skipped,
        }
    }
}

/// Options controlling plan generation.
#[derive(Clone, Debug)]
pub struct PlanOptions {
    pub rule_filter: Vec<String>,
    pub include_recycle_bin: bool,
    pub include_os_handlers: bool,
    pub tier_max: RuleTier,
    pub now_min2000: Option<u32>,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            rule_filter: Vec::new(),
            include_recycle_bin: false,
            include_os_handlers: true,
            tier_max: RuleTier::Safe,
            now_min2000: None,
        }
    }
}

/// Performs case-insensitive ASCII glob matching within a single path segment.
///
/// Supports `*` (zero or more characters) and `?` (exactly one character) anywhere in `pattern`.
pub fn match_segment_glob(pattern: &str, candidate: &str) -> bool {
    let p = pattern.as_bytes();
    let c = candidate.as_bytes();
    let mut px = 0;
    let mut cx = 0;
    let mut star_p = None;
    let mut match_c = 0;

    while cx < c.len() {
        if px < p.len() && (p[px] == b'?' || p[px].eq_ignore_ascii_case(&c[cx])) {
            px += 1;
            cx += 1;
        } else if px < p.len() && p[px] == b'*' {
            star_p = Some(px);
            px += 1;
            match_c = cx;
        } else if let Some(sp) = star_p {
            px = sp + 1;
            match_c += 1;
            cx = match_c;
        } else {
            return false;
        }
    }

    while px < p.len() && p[px] == b'*' {
        px += 1;
    }

    px == p.len()
}

struct DfsFrame {
    node: NodeId,
    rel_path: String,
    children: Vec<NodeId>,
    next_child_idx: usize,
    all_children_eligible: bool,
    has_children: bool,
}

/// Traverses items inside `root_node` in iterative deepest-first post-order.
fn collect_items(
    index: &Index,
    root_node: NodeId,
    min_age_days: Option<u32>,
    now_min: u32,
    exclude_names: &[String],
    deny_ctx: &DenyContext,
    seen_file_ids: &mut FxHashSet<u64>,
) -> Vec<PlannedItem> {
    let mut items = Vec::new();
    let mut stack = Vec::new();

    let root_children: Vec<NodeId> = index.children(root_node).collect();
    let root_has_children = !root_children.is_empty();
    stack.push(DfsFrame {
        node: root_node,
        rel_path: String::new(),
        children: root_children,
        next_child_idx: 0,
        all_children_eligible: true,
        has_children: root_has_children,
    });

    while let Some(frame) = stack.last_mut() {
        if frame.next_child_idx < frame.children.len() {
            let child = frame.children[frame.next_child_idx];
            frame.next_child_idx += 1;

            let flags = index.flags(child);
            let name = index.name(child);

            // 1. Skip cloud, metafile, orphans
            if flags.intersects(NodeFlags::CLOUD | NodeFlags::METAFILE | NodeFlags::ORPHANS) {
                frame.all_children_eligible = false;
                continue;
            }

            // 2. Exclude names check (case-insensitive filename)
            if exclude_names
                .iter()
                .any(|ex| ex.eq_ignore_ascii_case(&name))
            {
                frame.all_children_eligible = false;
                continue;
            }

            // 3. Denied path check
            let child_path = index.path(child);
            if is_denied_path(&child_path, deny_ctx).is_some() {
                frame.all_children_eligible = false;
                continue;
            }

            let child_rel_path = if frame.rel_path.is_empty() {
                name.to_string()
            } else {
                format!("{}\\{}", frame.rel_path, name)
            };

            // 4. Reparse point: leaf item, never descend!
            if flags.contains(NodeFlags::REPARSE) {
                if let Some(age) = min_age_days {
                    let threshold_mins = age.saturating_mul(1440);
                    let age_mins = now_min.saturating_sub(index.mtime_min(child));
                    if age_mins < threshold_mins {
                        frame.all_children_eligible = false;
                        continue;
                    }
                }

                let file_id = index.file_id(child);
                let bytes = if flags.contains(NodeFlags::DUP_LINK)
                    || (file_id != 0 && !seen_file_ids.insert(file_id))
                {
                    0
                } else {
                    index.allocated(child)
                };

                items.push(PlannedItem {
                    rel_path: child_rel_path,
                    expected_file_id: file_id,
                    bytes,
                    is_dir: flags.contains(NodeFlags::DIR),
                    mtime_min: index.mtime_min(child),
                });
                continue;
            }

            // 5. Regular file (non-DIR)
            if !flags.contains(NodeFlags::DIR) {
                if let Some(age) = min_age_days {
                    let threshold_mins = age.saturating_mul(1440);
                    let age_mins = now_min.saturating_sub(index.mtime_min(child));
                    if age_mins < threshold_mins {
                        frame.all_children_eligible = false;
                        continue;
                    }
                }

                let file_id = index.file_id(child);
                let bytes = if flags.contains(NodeFlags::DUP_LINK)
                    || (file_id != 0 && !seen_file_ids.insert(file_id))
                {
                    0
                } else {
                    index.allocated(child)
                };

                items.push(PlannedItem {
                    rel_path: child_rel_path,
                    expected_file_id: file_id,
                    bytes,
                    is_dir: false,
                    mtime_min: index.mtime_min(child),
                });
                continue;
            }

            // 6. Regular directory: push new frame to stack
            let sub_children: Vec<NodeId> = index.children(child).collect();
            let sub_has_children = !sub_children.is_empty();
            stack.push(DfsFrame {
                node: child,
                rel_path: child_rel_path,
                children: sub_children,
                next_child_idx: 0,
                all_children_eligible: true,
                has_children: sub_has_children,
            });
        } else {
            // All children of top frame finished -> pop frame post-order
            let finished_frame = stack.pop().unwrap();
            // Never add root_node itself to items
            if stack.is_empty() {
                break;
            }

            let parent_frame = stack.last_mut().unwrap();
            let child_node = finished_frame.node;

            let eligible_to_delete = if finished_frame.has_children {
                finished_frame.all_children_eligible
            } else if let Some(age) = min_age_days {
                let threshold_mins = age.saturating_mul(1440);
                let age_mins = now_min.saturating_sub(index.mtime_min(child_node));
                age_mins >= threshold_mins
            } else {
                true
            };

            if eligible_to_delete {
                let file_id = index.file_id(child_node);
                let bytes = if file_id != 0 && !seen_file_ids.insert(file_id) {
                    0
                } else {
                    index.allocated(child_node)
                };

                items.push(PlannedItem {
                    rel_path: finished_frame.rel_path,
                    expected_file_id: file_id,
                    bytes,
                    is_dir: true,
                    mtime_min: index.mtime_min(child_node),
                });
            } else {
                parent_frame.all_children_eligible = false;
            }
        }
    }

    items
}

/// Generates a `CleanPlan` by matching rules against an in-memory `Index` without filesystem I/O.
pub fn build_plan_from_index(
    index: &Index,
    scan_method: ScanMethod,
    scanned_path: &Path,
    rules: &[RuleDef],
    deny_ctx: &DenyContext,
    opts: &PlanOptions,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> CleanPlan {
    let scanned_path_norm = normalize_win_path_str(scanned_path);
    let root_path_norm = normalize_win_path_str(&index.path(ROOT));

    let root_segs: Vec<&str> = root_path_norm
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect();

    let root_drive = if !root_segs.is_empty() {
        root_segs[0].to_ascii_uppercase()
    } else {
        "C:".to_string()
    };

    let scanned_segs: Vec<&str> = scanned_path_norm
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect();

    let is_volume_root = volume_root_of(scanned_path).is_some()
        || volume_root_of(Path::new(&scanned_path_norm)).is_some();

    let volume_root = if !index.volume().root.is_empty() {
        normalize_win_path_str(Path::new(&index.volume().root))
    } else if let Some(vr) = volume_root_of(Path::new(&scanned_path_norm)) {
        vr
    } else if scanned_path_norm.len() >= 2 && scanned_path_norm.as_bytes()[1] == b':' {
        format!(
            "{}:\\",
            (scanned_path_norm.as_bytes()[0] as char).to_ascii_uppercase()
        )
    } else {
        "C:\\".to_string()
    };

    let file_id_kind = match scan_method {
        ScanMethod::Mft | ScanMethod::UsnIncremental => FileIdKind::NtfsFrn64,
        ScanMethod::Dir | ScanMethod::Auto => FileIdKind::FxHash128,
    };

    let now_min = opts.now_min2000.unwrap_or_else(|| {
        let ft =
            match std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH) {
                Ok(d) => 116_444_736_000_000_000u64
                    .saturating_add(d.as_secs().saturating_mul(10_000_000))
                    .saturating_add((d.subsec_nanos() / 100) as u64),
                Err(_) => 0,
            };
        filetime_to_min2000(ft)
    });

    let mut plan_rules = Vec::new();
    let mut plan_skipped = Vec::new();

    for rule in rules {
        // Step 1: Filter rule eligibility
        let matches_filter = if !opts.rule_filter.is_empty() {
            opts.rule_filter
                .iter()
                .any(|f| f.eq_ignore_ascii_case(&rule.id))
        } else {
            // Raising `tier_max` above Safe is the explicit opt-in that unlocks 🟡/🔴 rules (P4
            // Task 4); their `default_enabled = false` only means "unchecked by default in the UI".
            rule.tier <= opts.tier_max
                && (rule.default_enabled
                    || rule.tier > RuleTier::Safe
                    || (opts.include_recycle_bin && rule.id == "os.vc.recycle_bin"))
        };

        if !matches_filter {
            continue;
        }

        // Step 2: Handle OS handler, DISM, and DriverStore rules
        if matches!(
            &rule.method,
            RuleMethod::OsHandler { .. }
                | RuleMethod::DismComponentCleanup { .. }
                | RuleMethod::DriverStorePrune { .. }
        ) {
            if !is_volume_root {
                plan_skipped.push(SkippedRule {
                    rule_id: rule.id.clone(),
                    name: rule.name.clone(),
                    reason: "not a volume root".to_string(),
                });
                continue;
            }

            if matches!(&rule.method, RuleMethod::OsHandler { .. })
                && !opts.include_os_handlers
                && opts.rule_filter.is_empty()
            {
                plan_skipped.push(SkippedRule {
                    rule_id: rule.id.clone(),
                    name: rule.name.clone(),
                    reason: "OS handlers disabled".to_string(),
                });
                continue;
            }

            plan_rules.push(PlannedRule {
                rule_id: rule.id.clone(),
                name: rule.name.clone(),
                category: rule.category.clone(),
                tier: rule.tier,
                regenerable: rule.regenerable,
                requires_admin: rule.requires_admin,
                method: rule.method.clone(),
                preconditions: rule.preconditions.clone(),
                explain: rule.explain.clone(),
                est_bytes: 0,
                item_count: 0,
                roots: Vec::new(),
                os_handler_bytes: None,
                estimate: if matches!(
                    rule.method,
                    RuleMethod::DismComponentCleanup { .. } | RuleMethod::DriverStorePrune { .. }
                ) {
                    EstimateBasis::AtRunTime
                } else {
                    EstimateBasis::Measured
                },
            });
            continue;
        }

        // Step 3: Handle path-based and command rules
        let mut matched_roots = Vec::new();
        let mut valid_templates_count = 0usize;
        let mut off_volume_count = 0usize;
        let mut outside_scanned_count = 0usize;
        let mut seen_rule_root_nodes = FxHashSet::default();
        let mut seen_file_ids = FxHashSet::default();
        let mut rule_denied: Option<String> = None;

        let templates: Vec<String> = rule
            .paths
            .iter()
            .flat_map(|t| crate::clean::providers::expand_dynamic_template(t, env_lookup))
            .collect();
        for tmpl in &templates {
            let Some(tmpl_segs) = expand_path_template(tmpl, env_lookup) else {
                continue;
            };
            if tmpl_segs.is_empty() {
                continue;
            }
            valid_templates_count += 1;

            let tmpl_drive = tmpl_segs[0].to_ascii_uppercase();
            if tmpl_drive != root_drive {
                off_volume_count += 1;
                continue;
            }

            // Check if template falls under scanned_path
            if tmpl_segs.len() < scanned_segs.len() {
                outside_scanned_count += 1;
                continue;
            }

            let mut matches_scanned_prefix = true;
            for i in 0..scanned_segs.len() {
                if !match_segment_glob(&tmpl_segs[i], scanned_segs[i]) {
                    matches_scanned_prefix = false;
                    break;
                }
            }
            if !matches_scanned_prefix {
                outside_scanned_count += 1;
                continue;
            }

            // Check if template can align with index root
            if tmpl_segs.len() < root_segs.len() {
                outside_scanned_count += 1;
                continue;
            }

            let mut matches_root_prefix = true;
            for i in 0..root_segs.len() {
                if !match_segment_glob(&tmpl_segs[i], root_segs[i]) {
                    matches_root_prefix = false;
                    break;
                }
            }
            if !matches_root_prefix {
                outside_scanned_count += 1;
                continue;
            }

            let remaining_segs = &tmpl_segs[root_segs.len()..];
            let mut current_nodes = vec![ROOT];

            for seg_pat in remaining_segs {
                let mut next_nodes = Vec::new();
                for &node in &current_nodes {
                    for child in index.children(node) {
                        let flags = index.flags(child);
                        if !flags.contains(NodeFlags::DIR) {
                            continue;
                        }
                        if flags.intersects(
                            NodeFlags::REPARSE
                                | NodeFlags::CLOUD
                                | NodeFlags::ORPHANS
                                | NodeFlags::METAFILE,
                        ) {
                            continue;
                        }
                        let child_name = index.name(child);
                        if match_segment_glob(seg_pat, &child_name) {
                            next_nodes.push(child);
                        }
                    }
                }
                current_nodes = next_nodes;
                if current_nodes.is_empty() {
                    break;
                }
            }

            for root_node in current_nodes {
                if !seen_rule_root_nodes.insert(root_node) {
                    continue;
                }
                let root_path_str = index.path(root_node).to_string_lossy().to_string();

                // Ensure matched root_node is actually under scanned_path (filters wildcard expansions)
                if !is_under_root(Path::new(&root_path_str), Path::new(&scanned_path_norm)) {
                    outside_scanned_count += 1;
                    continue;
                }

                if let Some(deny_reason) = is_denied_path(Path::new(&root_path_str), deny_ctx) {
                    rule_denied = Some(format!("denied path: {root_path_str} ({deny_reason})"));
                    break;
                }

                let items = collect_items(
                    index,
                    root_node,
                    rule.min_age_days,
                    now_min,
                    &rule.preconditions.exclude_names,
                    deny_ctx,
                    &mut seen_file_ids,
                );

                let planned_root = PlannedRoot {
                    root_path: root_path_str,
                    root_file_id: index.file_id(root_node),
                    file_id_kind,
                    min_age_days: rule.min_age_days,
                    exclude_names: rule.preconditions.exclude_names.clone(),
                    allow_unlisted_children: false,
                    items,
                };
                matched_roots.push(planned_root);
            }

            if rule_denied.is_some() {
                break;
            }
        }

        if let Some(reason) = rule_denied {
            plan_skipped.push(SkippedRule {
                rule_id: rule.id.clone(),
                name: rule.name.clone(),
                reason,
            });
            continue;
        }

        let total_items: u64 = matched_roots.iter().map(|r| r.items.len() as u64).sum();
        if total_items > 0 {
            let total_bytes: u64 = matched_roots
                .iter()
                .flat_map(|r| &r.items)
                .map(|it| it.bytes)
                .sum();

            plan_rules.push(PlannedRule {
                rule_id: rule.id.clone(),
                name: rule.name.clone(),
                category: rule.category.clone(),
                tier: rule.tier,
                regenerable: rule.regenerable,
                requires_admin: rule.requires_admin,
                method: rule.method.clone(),
                preconditions: rule.preconditions.clone(),
                explain: rule.explain.clone(),
                est_bytes: total_bytes,
                item_count: total_items,
                roots: matched_roots,
                os_handler_bytes: None,
                estimate: Default::default(),
            });
        } else {
            let reason = if valid_templates_count > 0 && off_volume_count == valid_templates_count {
                "different volume".to_string()
            } else if valid_templates_count > 0
                && (outside_scanned_count + off_volume_count) == valid_templates_count
            {
                "outside scanned path".to_string()
            } else {
                "nothing to clean".to_string()
            };

            plan_skipped.push(SkippedRule {
                rule_id: rule.id.clone(),
                name: rule.name.clone(),
                reason,
            });
        }
    }

    let total_est_bytes: u64 = plan_rules.iter().map(|r| r.est_bytes).sum();

    CleanPlan {
        version: 1,
        scanned_path: scanned_path_norm,
        volume_root,
        scan_method,
        total_est_bytes,
        rules: plan_rules,
        skipped: plan_skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, NodeFlags, RawEntry};
    use crate::volume::VolumeInfo;

    fn helper_build_index(entries: &[(u64, u64, &str, NodeFlags, u64, u64, u32)]) -> Index {
        let mut names = NameArena::new();
        let mut raw_entries = Vec::new();
        for &(key, parent, name, flags, alloc, file_id, mtime) in entries {
            let name_ref = names.push_str(name);
            let ft = crate::time::FILETIME_EPOCH_2000
                .saturating_add((mtime as u64).saturating_mul(crate::time::INTERVALS_PER_MINUTE));
            raw_entries.push(RawEntry {
                key,
                parent_key: parent,
                name: name_ref,
                flags,
                logical: alloc,
                allocated: alloc,
                mtime: ft,
                atime: ft,
                file_id,
                reparse_tag: 0,
            });
        }
        let batch = EntryBatch {
            names,
            entries: raw_entries,
        };
        let mut b = IndexBuilder::new(
            5,
            r"C:\",
            VolumeInfo {
                root: r"\\?\C:\".into(),
                ..VolumeInfo::default()
            },
        );
        b.push_batch(batch);
        b.finish()
    }

    #[test]
    fn matches_wildcard_profile_dirs_and_respects_excludes() {
        let ix = helper_build_index(&[
            (10, 5, "Users", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "Alice", NodeFlags::DIR, 0, 11, 0),
            (12, 11, "AppData", NodeFlags::DIR, 0, 12, 0),
            (13, 12, "Local", NodeFlags::DIR, 0, 13, 0),
            (14, 13, "Google", NodeFlags::DIR, 0, 14, 0),
            (15, 14, "Chrome", NodeFlags::DIR, 0, 15, 0),
            (16, 15, "User Data", NodeFlags::DIR, 0, 16, 0),
            (17, 16, "Default", NodeFlags::DIR, 0, 17, 0),
            (18, 17, "Cache", NodeFlags::DIR, 0, 18, 0),
            (19, 18, "sub", NodeFlags::DIR, 0, 19, 0),
            (20, 19, "data_1", NodeFlags::empty(), 1024, 20, 0),
            (21, 18, "data_0", NodeFlags::empty(), 2048, 21, 0),
            (22, 17, "Cookies", NodeFlags::empty(), 4096, 22, 0),
            (23, 16, "Profile 1", NodeFlags::DIR, 0, 23, 0),
            (24, 23, "Cache", NodeFlags::DIR, 0, 24, 0),
            (25, 24, "cache_data", NodeFlags::empty(), 512, 25, 0),
            (26, 23, "History", NodeFlags::empty(), 8192, 26, 0),
        ]);

        let rule = RuleDef {
            id: "browser.chrome.cache".into(),
            name: "Chrome Cache".into(),
            category: "browsers".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Test Chrome cache".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();
        let env_lookup = |var: &str| match var {
            "LOCALAPPDATA" => Some(r"C:\Users\Alice\AppData\Local".into()),
            _ => None,
        };

        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[rule],
            &deny_ctx,
            &opts,
            &env_lookup,
        );

        assert_eq!(plan.rules.len(), 1);
        let p_rule = &plan.rules[0];
        assert_eq!(p_rule.roots.len(), 2);

        // Verify Default\Cache post-order: data_1 before sub!
        let default_cache = p_rule
            .roots
            .iter()
            .find(|r| r.root_path.contains("Default"))
            .unwrap();
        let items: Vec<&str> = default_cache
            .items
            .iter()
            .map(|it| it.rel_path.as_str())
            .collect();
        assert!(items.contains(&"data_0"));
        assert!(items.contains(&"sub\\data_1"));
        assert!(items.contains(&"sub"));
        let idx_sub_file = items.iter().position(|&x| x == "sub\\data_1").unwrap();
        let idx_sub_dir = items.iter().position(|&x| x == "sub").unwrap();
        assert!(
            idx_sub_file < idx_sub_dir,
            "deepest file must appear before parent sub directory"
        );

        // Verify Cookies untouched
        assert!(!items.iter().any(|&x| x.contains("Cookies")));

        // Profile 1 Cache verified
        let prof1_cache = p_rule
            .roots
            .iter()
            .find(|r| r.root_path.contains("Profile 1"))
            .unwrap();
        assert_eq!(prof1_cache.items.len(), 1);
        assert_eq!(prof1_cache.items[0].rel_path, "cache_data");
    }

    #[test]
    fn skips_cloud_nodes_and_does_not_traverse_reparse_points() {
        let ix = helper_build_index(&[
            (10, 5, "Cache", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "cloud_file", NodeFlags::CLOUD, 4096, 11, 0),
            (
                12,
                10,
                "junction_dir",
                NodeFlags::DIR | NodeFlags::REPARSE,
                0,
                12,
                0,
            ),
            (
                13,
                12,
                "hidden_target_file",
                NodeFlags::empty(),
                8192,
                13,
                0,
            ),
            (14, 10, "regular_file", NodeFlags::empty(), 1024, 14, 0),
        ]);

        let rule = RuleDef {
            id: "test.cache".into(),
            name: "Test Cache".into(),
            category: "test".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Cache".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Test".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();
        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        assert_eq!(plan.rules.len(), 1);
        let items = &plan.rules[0].roots[0].items;
        let item_names: Vec<&str> = items.iter().map(|it| it.rel_path.as_str()).collect();

        // regular_file is planned
        assert!(item_names.contains(&"regular_file"));
        // junction_dir is planned as a leaf is_dir: true
        assert!(item_names.contains(&"junction_dir"));
        let junc_item = items
            .iter()
            .find(|it| it.rel_path == "junction_dir")
            .unwrap();
        assert!(junc_item.is_dir);

        // cloud_file must be skipped
        assert!(!item_names.contains(&"cloud_file"));
        // hidden_target_file under reparse must never be traversed
        assert!(
            !item_names
                .iter()
                .any(|name| name.contains("hidden_target_file"))
        );
    }

    #[test]
    fn respects_min_age_days() {
        let ix = helper_build_index(&[
            (10, 5, "Temp", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "old_file", NodeFlags::empty(), 1024, 11, 100),
            (12, 10, "new_file", NodeFlags::empty(), 2048, 12, 2000),
            (13, 10, "sub_all_old", NodeFlags::DIR, 0, 13, 50),
            (14, 13, "old_f2", NodeFlags::empty(), 512, 14, 50),
            (15, 10, "sub_mixed", NodeFlags::DIR, 0, 15, 50),
            (16, 15, "old_f3", NodeFlags::empty(), 256, 16, 50),
            (17, 15, "new_f4", NodeFlags::empty(), 128, 17, 2000),
        ]);

        let rule = RuleDef {
            id: "test.temp".into(),
            name: "Test Temp".into(),
            category: "test".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Temp".into()],
            min_age_days: Some(1),
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteOlderThan,
            explain: "Test".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions {
            now_min2000: Some(2000),
            ..PlanOptions::default()
        };

        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        assert_eq!(plan.rules.len(), 1);
        let items = &plan.rules[0].roots[0].items;
        let item_names: Vec<&str> = items.iter().map(|it| it.rel_path.as_str()).collect();

        assert!(item_names.contains(&"old_file"));
        assert!(!item_names.contains(&"new_file"));

        // sub_all_old has all eligible descendants -> both old_f2 and sub_all_old included
        assert!(item_names.contains(&"sub_all_old\\old_f2"));
        assert!(item_names.contains(&"sub_all_old"));

        // sub_mixed has new_f4 preserved -> old_f3 is included, but sub_mixed is NOT included!
        assert!(item_names.contains(&"sub_mixed\\old_f3"));
        assert!(!item_names.contains(&"sub_mixed"));
        assert!(!item_names.contains(&"sub_mixed\\new_f4"));
    }

    #[test]
    fn blocks_denied_path_templates_even_if_injected_in_custom_rules() {
        let ix = helper_build_index(&[
            (10, 5, "Windows", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "System32", NodeFlags::DIR, 0, 11, 0),
            (12, 11, "malicious.dll", NodeFlags::empty(), 1024, 12, 0),
        ]);

        let rule = RuleDef {
            id: "exploit.sys32".into(),
            name: "Exploit System32".into(),
            category: "custom".into(),
            tier: RuleTier::Safe,
            regenerable: false,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Windows\System32".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Injected attack".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();

        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        assert_eq!(plan.rules.len(), 0);
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].rule_id, "exploit.sys32");
        assert!(plan.skipped[0].reason.contains("denied"));
    }

    #[test]
    fn sets_file_id_kind_from_scan_method() {
        let ix = helper_build_index(&[
            (10, 5, "Temp", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "file.tmp", NodeFlags::empty(), 100, 11, 0),
        ]);
        let rule = RuleDef {
            id: "test.temp".into(),
            name: "Test Temp".into(),
            category: "test".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Temp".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Test".into(),
        };
        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();

        let mft_plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            std::slice::from_ref(&rule),
            &deny_ctx,
            &opts,
            &|_| None,
        );
        assert_eq!(
            mft_plan.rules[0].roots[0].file_id_kind,
            FileIdKind::NtfsFrn64
        );

        let dir_plan = build_plan_from_index(
            &ix,
            ScanMethod::Dir,
            Path::new(r"C:\"),
            std::slice::from_ref(&rule),
            &deny_ctx,
            &opts,
            &|_| None,
        );
        assert_eq!(
            dir_plan.rules[0].roots[0].file_id_kind,
            FileIdKind::FxHash128
        );
    }

    #[test]
    fn command_and_os_handler_volume_root_vs_subfolder() {
        let ix = helper_build_index(&[
            (10, 5, "npm_cache", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "item.tmp", NodeFlags::empty(), 500, 11, 0),
            (12, 5, "Users", NodeFlags::DIR, 0, 12, 0),
            (13, 12, "Alice", NodeFlags::DIR, 0, 13, 0),
            (14, 13, "local_cache", NodeFlags::DIR, 0, 14, 0),
            (15, 14, "local.tmp", NodeFlags::empty(), 200, 15, 0),
        ]);

        let os_rule = RuleDef {
            id: "os.vc.update_cleanup".into(),
            name: "Update Cleanup".into(),
            category: "system".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: true,
            default_enabled: true,
            paths: vec![],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::OsHandler {
                handler_key: "Update Cleanup".into(),
            },
            explain: "OS handler test".into(),
        };

        let cmd_rule = RuleDef {
            id: "dev.npm.cache".into(),
            name: "npm cache".into(),
            category: "dev".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\npm_cache".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::Command {
                program: "npm".into(),
                args: vec!["cache".into(), "clean".into(), "--force".into()],
                fallback_delete_contents: true,
                timeout_secs: 60,
                program_candidates: vec![],
            },
            explain: "Command rule test".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();

        // 1. Scanned at volume root C:\ -> OS handler included, Command rule included
        let root_plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[os_rule.clone(), cmd_rule.clone()],
            &deny_ctx,
            &opts,
            &|_| None,
        );
        assert_eq!(root_plan.rules.len(), 2);
        let os_p = root_plan
            .rules
            .iter()
            .find(|r| r.rule_id == "os.vc.update_cleanup")
            .unwrap();
        assert_eq!(os_p.os_handler_bytes, None);
        let cmd_p = root_plan
            .rules
            .iter()
            .find(|r| r.rule_id == "dev.npm.cache")
            .unwrap();
        assert_eq!(cmd_p.roots.len(), 1);
        assert_eq!(cmd_p.item_count, 1);

        // 2. Scanned at subfolder C:\Users\Alice -> OS handler skipped ("not a volume root"), cmd_rule skipped ("outside scanned path")
        let mut b_sub = IndexBuilder::new(13, r"C:\Users\Alice", VolumeInfo::default());
        let mut names = NameArena::new();
        let ref_local = names.push_str("local_cache");
        let ref_file = names.push_str("local.tmp");
        b_sub.push_batch(EntryBatch {
            names,
            entries: vec![
                RawEntry {
                    key: 14,
                    parent_key: 13,
                    name: ref_local,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 14,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 15,
                    parent_key: 14,
                    name: ref_file,
                    flags: NodeFlags::empty(),
                    logical: 200,
                    allocated: 200,
                    mtime: 0,
                    atime: 0,
                    file_id: 15,
                    reparse_tag: 0,
                },
            ],
        });
        let ix_sub = b_sub.finish();

        let sub_plan = build_plan_from_index(
            &ix_sub,
            ScanMethod::Mft,
            Path::new(r"C:\Users\Alice"),
            &[os_rule, cmd_rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        assert_eq!(sub_plan.rules.len(), 0);
        assert_eq!(sub_plan.skipped.len(), 2);
        let os_skip = sub_plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "os.vc.update_cleanup")
            .unwrap();
        assert_eq!(os_skip.reason, "not a volume root");
        let cmd_skip = sub_plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "dev.npm.cache")
            .unwrap();
        assert_eq!(cmd_skip.reason, "outside scanned path");
    }

    #[test]
    fn glob_matching_semantics() {
        assert!(match_segment_glob("*", "anything"));
        assert!(match_segment_glob("*", ""));
        assert!(match_segment_glob(
            "Microsoft.DesktopAppInstaller_*",
            "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
        ));
        assert!(match_segment_glob(
            "microsoft.desktopappinstaller_*",
            "MICROSOFT.DESKTOPAPPINSTALLER_8WEKYB3D8BBWE"
        ));
        assert!(match_segment_glob("*.log", "CBS.log"));
        assert!(!match_segment_glob("*.log", "CBS.txt"));
        assert!(match_segment_glob("file?.txt", "file1.txt"));
        assert!(!match_segment_glob("file?.txt", "file12.txt"));
        assert!(match_segment_glob("cache", "CACHE"));
        assert!(!match_segment_glob("cache", "cache_storage"));
    }

    #[test]
    fn deduplicates_same_folder_from_multiple_templates() {
        // C:\Users\Alice\.cargo (key 13)
        //   item (key 14)
        let ix = helper_build_index(&[
            (10, 5, "Users", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "Alice", NodeFlags::DIR, 0, 11, 0),
            (12, 11, ".cargo", NodeFlags::DIR, 0, 12, 0),
            (13, 12, "bin", NodeFlags::DIR, 0, 13, 0),
            (14, 13, "cargo.exe", NodeFlags::empty(), 2048, 14, 0),
        ]);

        let rule = RuleDef {
            id: "dev.cargo.bin".into(),
            name: "Cargo Bin".into(),
            category: "dev".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![
                r"%CARGO_HOME%\bin".into(),
                r"%USERPROFILE%\.cargo\bin".into(),
            ],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Test cargo deduplication".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();
        let env_lookup = |var: &str| match var {
            "CARGO_HOME" => Some(r"C:\Users\Alice\.cargo".into()),
            "USERPROFILE" => Some(r"C:\Users\Alice".into()),
            _ => None,
        };

        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[rule],
            &deny_ctx,
            &opts,
            &env_lookup,
        );

        assert_eq!(plan.rules.len(), 1);
        // Only 1 root because both templates resolve to the same C:\Users\Alice\.cargo\bin folder
        assert_eq!(plan.rules[0].roots.len(), 1);
        assert_eq!(plan.rules[0].item_count, 1);
        assert_eq!(plan.rules[0].roots[0].items[0].rel_path, "cargo.exe");
    }

    #[test]
    fn deduplicates_hardlink_bytes_in_rule() {
        // C:\Cache (10)
        //   link1 (11, file_id = 999, alloc = 4096)
        //   link2 (12, file_id = 999, DUP_LINK, alloc = 4096)
        let ix = helper_build_index(&[
            (10, 5, "Cache", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "link1", NodeFlags::empty(), 4096, 999, 0),
            (12, 10, "link2", NodeFlags::DUP_LINK, 4096, 999, 0),
        ]);

        let rule = RuleDef {
            id: "test.links".into(),
            name: "Test Links".into(),
            category: "test".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Cache".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Test hardlink deduplication".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();
        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        assert_eq!(plan.rules.len(), 1);
        let items = &plan.rules[0].roots[0].items;
        assert_eq!(items.len(), 2);
        // Total bytes counted should be 4096, not 8192!
        assert_eq!(plan.rules[0].est_bytes, 4096);
        assert_eq!(plan.total_est_bytes, 4096);
    }

    #[test]
    fn filters_rules_by_tier_and_explicit_rule_filter() {
        let ix = helper_build_index(&[
            (10, 5, "Cache", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "item.tmp", NodeFlags::empty(), 100, 11, 0),
        ]);

        let safe_rule = RuleDef {
            id: "rule.safe".into(),
            name: "Safe Rule".into(),
            category: "test".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Cache".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Safe".into(),
        };

        let review_rule = RuleDef {
            id: "rule.review".into(),
            name: "Review Rule".into(),
            category: "test".into(),
            tier: RuleTier::Review,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Cache".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Review".into(),
        };

        let deny_ctx = DenyContext::default_for_test();

        // 1. Default tier_max = Safe -> review_rule omitted
        let opts_default = PlanOptions::default();
        let plan1 = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[safe_rule.clone(), review_rule.clone()],
            &deny_ctx,
            &opts_default,
            &|_| None,
        );
        assert_eq!(plan1.rules.len(), 1);
        assert_eq!(plan1.rules[0].rule_id, "rule.safe");

        // 2. Explicit rule_filter: specifies "rule.review" -> review_rule included even if tier_max = Safe
        let opts_filter = PlanOptions {
            rule_filter: vec!["rule.review".into()],
            ..PlanOptions::default()
        };
        let plan2 = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[safe_rule, review_rule],
            &deny_ctx,
            &opts_filter,
            &|_| None,
        );
        assert_eq!(plan2.rules.len(), 1);
        assert_eq!(plan2.rules[0].rule_id, "rule.review");
    }

    #[test]
    fn handles_off_volume_rules() {
        let ix = helper_build_index(&[]);
        let d_rule = RuleDef {
            id: "rule.drive_d".into(),
            name: "D Drive Rule".into(),
            category: "test".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"D:\Temp".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Off volume".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();
        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[d_rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        assert_eq!(plan.rules.len(), 0);
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].reason, "different volume");
    }

    #[test]
    fn preserves_directory_when_excluded_file_present() {
        // C:\Logs (10)
        //   CBS (11)
        //     CBS.log (12, excluded)
        //     other.log (13, eligible)
        let ix = helper_build_index(&[
            (10, 5, "Logs", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "CBS", NodeFlags::DIR, 0, 11, 0),
            (12, 11, "CBS.log", NodeFlags::empty(), 1024, 12, 0),
            (13, 11, "other.log", NodeFlags::empty(), 2048, 13, 0),
        ]);

        let rule = RuleDef {
            id: "sys.cbs.logs".into(),
            name: "CBS Logs".into(),
            category: "system".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: true,
            default_enabled: true,
            paths: vec![r"C:\Logs\CBS".into()],
            min_age_days: None,
            preconditions: PreconditionRule {
                exclude_names: vec!["CBS.log".into()],
                ..PreconditionRule::default()
            },
            method: RuleMethod::DeleteContents,
            explain: "Test CBS exclusion".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();
        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &[rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        assert_eq!(plan.rules.len(), 1);
        let items = &plan.rules[0].roots[0].items;
        let item_names: Vec<&str> = items.iter().map(|it| it.rel_path.as_str()).collect();

        // other.log is planned
        assert!(item_names.contains(&"other.log"));
        // CBS.log is NOT planned (excluded)
        assert!(!item_names.contains(&"CBS.log"));
        // The CBS directory itself is the rule root, so it is never in items anyway!
    }

    #[test]
    fn subfolder_scope_filters_volume_index_and_skips_os_handlers() {
        // Volume-rooted index C:\ (e.g. from an MFT scan)
        let ix = helper_build_index(&[
            (10, 5, "Windows", NodeFlags::DIR, 0, 10, 0),
            (11, 10, "Temp", NodeFlags::DIR, 0, 11, 0),
            (12, 11, "win.tmp", NodeFlags::empty(), 1024, 12, 0),
            (13, 5, "Users", NodeFlags::DIR, 0, 13, 0),
            (14, 13, "Alice", NodeFlags::DIR, 0, 14, 0),
            (15, 14, "AppData", NodeFlags::DIR, 0, 15, 0),
            (16, 15, "Local", NodeFlags::DIR, 0, 16, 0),
            (17, 16, "Temp", NodeFlags::DIR, 0, 17, 0),
            (18, 17, "alice.tmp", NodeFlags::empty(), 512, 18, 0),
            (19, 13, "Bob", NodeFlags::DIR, 0, 19, 0),
            (20, 19, "AppData", NodeFlags::DIR, 0, 20, 0),
            (21, 20, "Local", NodeFlags::DIR, 0, 21, 0),
            (22, 21, "Temp", NodeFlags::DIR, 0, 22, 0),
            (23, 22, "bob.tmp", NodeFlags::empty(), 256, 23, 0),
        ]);

        let os_rule = RuleDef {
            id: "os.vc.update_cleanup".into(),
            name: "Update Cleanup".into(),
            category: "system".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: true,
            default_enabled: true,
            paths: vec![],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::OsHandler {
                handler_key: "Update Cleanup".into(),
            },
            explain: "OS handler test".into(),
        };

        let win_temp_rule = RuleDef {
            id: "sys.temp.windows".into(),
            name: "Windows Temp".into(),
            category: "system".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: true,
            default_enabled: true,
            paths: vec![r"C:\Windows\Temp".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "Win temp".into(),
        };

        let wildcard_user_rule = RuleDef {
            id: "user.temp.all".into(),
            name: "All Users Temp".into(),
            category: "user".into(),
            tier: RuleTier::Safe,
            regenerable: true,
            requires_admin: false,
            default_enabled: true,
            paths: vec![r"C:\Users\*\AppData\Local\Temp".into()],
            min_age_days: None,
            preconditions: PreconditionRule::default(),
            method: RuleMethod::DeleteContents,
            explain: "User temp".into(),
        };

        let deny_ctx = DenyContext::default_for_test();
        let opts = PlanOptions::default();

        let plan = build_plan_from_index(
            &ix,
            ScanMethod::Mft,
            Path::new(r"C:\Users\Alice"),
            &[os_rule, win_temp_rule, wildcard_user_rule],
            &deny_ctx,
            &opts,
            &|_| None,
        );

        // 1. OS handler must be skipped because scanned_path is C:\Users\Alice (not a volume root!)
        let os_skip = plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "os.vc.update_cleanup")
            .expect("os handler must be in skipped");
        assert_eq!(os_skip.reason, "not a volume root");

        // 2. Windows Temp must be skipped because it is outside C:\Users\Alice
        let win_skip = plan
            .skipped
            .iter()
            .find(|s| s.rule_id == "sys.temp.windows")
            .expect("sys.temp.windows must be in skipped");
        assert_eq!(win_skip.reason, "outside scanned path");

        // 3. All Users Temp must ONLY match C:\Users\Alice\AppData\Local\Temp, NOT Bob!
        assert_eq!(plan.rules.len(), 1);
        let user_plan = &plan.rules[0];
        assert_eq!(user_plan.rule_id, "user.temp.all");
        assert_eq!(user_plan.roots.len(), 1);
        assert!(user_plan.roots[0].root_path.contains("Alice"));
        assert!(!user_plan.roots[0].root_path.contains("Bob"));
        assert_eq!(user_plan.roots[0].items.len(), 1);
        assert_eq!(user_plan.roots[0].items[0].rel_path, "alice.tmp");
    }

    #[test]
    fn clean_plan_filtered_rules_updates_totals_and_skipped() {
        let plan = CleanPlan {
            version: 1,
            scanned_path: r"C:\".to_string(),
            volume_root: r"C:\".to_string(),
            scan_method: ScanMethod::Mft,
            total_est_bytes: 3000,
            rules: vec![
                PlannedRule {
                    rule_id: "rule1".to_string(),
                    name: "Rule One".to_string(),
                    category: "temp".to_string(),
                    tier: RuleTier::Safe,
                    regenerable: true,
                    requires_admin: false,
                    method: RuleMethod::DeleteContents,
                    preconditions: PreconditionRule::default(),
                    explain: "test".to_string(),
                    est_bytes: 1000,
                    item_count: 5,
                    roots: Vec::new(),
                    os_handler_bytes: None,
                    estimate: Default::default(),
                },
                PlannedRule {
                    rule_id: "rule2".to_string(),
                    name: "Rule Two".to_string(),
                    category: "cache".to_string(),
                    tier: RuleTier::Safe,
                    regenerable: true,
                    requires_admin: false,
                    method: RuleMethod::DeleteContents,
                    preconditions: PreconditionRule::default(),
                    explain: "test".to_string(),
                    est_bytes: 2000,
                    item_count: 10,
                    roots: Vec::new(),
                    os_handler_bytes: None,
                    estimate: Default::default(),
                },
            ],
            skipped: vec![SkippedRule {
                rule_id: "orig_skip".to_string(),
                name: "Original Skipped".to_string(),
                reason: "nothing to clean".to_string(),
            }],
        };

        // Filter keeping only "rule2"
        let filtered = plan.filtered_rules(&["rule2".to_string()]);

        assert_eq!(filtered.rules.len(), 1);
        assert_eq!(filtered.rules[0].rule_id, "rule2");
        assert_eq!(filtered.total_est_bytes, 2000);

        // Skipped must retain "orig_skip" and add "rule1" with "unchecked in UI"
        assert_eq!(filtered.skipped.len(), 2);
        assert_eq!(filtered.skipped[0].rule_id, "orig_skip");
        assert_eq!(filtered.skipped[1].rule_id, "rule1");
        assert_eq!(filtered.skipped[1].reason, "unchecked in UI");
    }

    #[test]
    fn plan_options_max_tier_filters_review_and_advanced_rules_accurately() {
        let rules = vec![
            RuleDef {
                id: "r.safe".to_string(),
                name: "Safe Rule".to_string(),
                category: "test".to_string(),
                tier: RuleTier::Safe,
                regenerable: true,
                requires_admin: false,
                default_enabled: true,
                paths: vec![],
                min_age_days: None,
                explain: "safe".to_string(),
                method: RuleMethod::OsHandler {
                    handler_key: "SafeHandler".to_string(),
                },
                preconditions: PreconditionRule::default(),
            },
            RuleDef {
                id: "r.review".to_string(),
                name: "Review Rule".to_string(),
                category: "test".to_string(),
                tier: RuleTier::Review,
                regenerable: true,
                requires_admin: true,
                default_enabled: true,
                paths: vec![],
                min_age_days: None,
                explain: "review".to_string(),
                method: RuleMethod::DismComponentCleanup {
                    reset_base: false,
                    timeout_secs: 60,
                },
                preconditions: PreconditionRule::default(),
            },
            RuleDef {
                id: "r.advanced".to_string(),
                name: "Advanced Rule".to_string(),
                category: "test".to_string(),
                tier: RuleTier::Advanced,
                regenerable: false,
                requires_admin: true,
                default_enabled: true,
                paths: vec![],
                min_age_days: None,
                explain: "advanced".to_string(),
                method: RuleMethod::DismComponentCleanup {
                    reset_base: true,
                    timeout_secs: 60,
                },
                preconditions: PreconditionRule::default(),
            },
        ];

        let index = helper_build_index(&[]);
        let deny_ctx = DenyContext::default_for_test();
        let env_lookup = |var: &str| match var {
            "SystemDrive" => Some(r"C:".into()),
            _ => None,
        };

        // Safe only
        let opts_safe = PlanOptions {
            tier_max: RuleTier::Safe,
            ..Default::default()
        };
        let plan_safe = build_plan_from_index(
            &index,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &rules,
            &deny_ctx,
            &opts_safe,
            &env_lookup,
        );
        assert!(plan_safe.rules.iter().any(|r| r.rule_id == "r.safe"));
        assert!(!plan_safe.rules.iter().any(|r| r.rule_id == "r.review"));
        assert!(!plan_safe.rules.iter().any(|r| r.rule_id == "r.advanced"));

        // Review includes safe and review
        let opts_review = PlanOptions {
            tier_max: RuleTier::Review,
            ..Default::default()
        };
        let plan_review = build_plan_from_index(
            &index,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &rules,
            &deny_ctx,
            &opts_review,
            &env_lookup,
        );
        assert!(plan_review.rules.iter().any(|r| r.rule_id == "r.safe"));
        assert!(plan_review.rules.iter().any(|r| r.rule_id == "r.review"));
        assert!(!plan_review.rules.iter().any(|r| r.rule_id == "r.advanced"));

        // Advanced includes all three
        let opts_adv = PlanOptions {
            tier_max: RuleTier::Advanced,
            ..Default::default()
        };
        let plan_adv = build_plan_from_index(
            &index,
            ScanMethod::Mft,
            Path::new(r"C:\"),
            &rules,
            &deny_ctx,
            &opts_adv,
            &env_lookup,
        );
        assert!(plan_adv.rules.iter().any(|r| r.rule_id == "r.safe"));
        assert!(plan_adv.rules.iter().any(|r| r.rule_id == "r.review"));
        assert!(plan_adv.rules.iter().any(|r| r.rule_id == "r.advanced"));
    }

    /// Regression (P9.0): DISM, driver-store, and admin-only handler rules showed "0 B" in
    /// unelevated plans, which reads as "nothing to reclaim".
    #[test]
    fn estimate_basis_separates_measured_zero_from_unknown() {
        let rule = |id: &str, requires_admin: bool, method: RuleMethod| RuleDef {
            id: id.to_string(),
            name: id.to_string(),
            category: "system".to_string(),
            tier: RuleTier::Review,
            regenerable: true,
            requires_admin,
            default_enabled: true,
            paths: vec![],
            min_age_days: None,
            explain: String::new(),
            method,
            preconditions: PreconditionRule::default(),
        };
        let rules = vec![
            rule(
                "h.user",
                false,
                RuleMethod::OsHandler {
                    handler_key: "Thumbnail Cache".to_string(),
                },
            ),
            rule(
                "h.admin",
                true,
                RuleMethod::OsHandler {
                    handler_key: "Update Cleanup".to_string(),
                },
            ),
            rule(
                "dism",
                true,
                RuleMethod::DismComponentCleanup {
                    reset_base: false,
                    timeout_secs: 60,
                },
            ),
            rule(
                "drivers",
                true,
                RuleMethod::DriverStorePrune { timeout_secs: 60 },
            ),
        ];
        let index = helper_build_index(&[]);
        let opts = PlanOptions {
            tier_max: RuleTier::Review,
            ..Default::default()
        };
        let build = || {
            build_plan_from_index(
                &index,
                ScanMethod::Mft,
                Path::new(r"C:\"),
                &rules,
                &DenyContext::default_for_test(),
                &opts,
                &|_| None,
            )
        };
        let basis = |plan: &CleanPlan, id: &str| {
            plan.rules
                .iter()
                .find(|r| r.rule_id == id)
                .map(|r| r.estimate)
                .unwrap()
        };

        let mut unelevated = build();
        mark_admin_gated_estimates(&mut unelevated, false);
        assert_eq!(basis(&unelevated, "h.user"), EstimateBasis::Measured);
        assert_eq!(basis(&unelevated, "h.admin"), EstimateBasis::NeedsAdmin);
        assert_eq!(basis(&unelevated, "dism"), EstimateBasis::AtRunTime);
        assert_eq!(basis(&unelevated, "drivers"), EstimateBasis::AtRunTime);
        assert_eq!(
            EstimateBasis::NeedsAdmin.note(),
            Some("needs admin to estimate")
        );

        let mut elevated = build();
        mark_admin_gated_estimates(&mut elevated, true);
        assert_eq!(basis(&elevated, "h.admin"), EstimateBasis::Measured);

        // Plans saved by older builds (no `estimate` key) still load, as Measured.
        let mut json = serde_json::to_value(&unelevated.rules[0]).unwrap();
        json.as_object_mut().unwrap().remove("estimate");
        let old: PlannedRule = serde_json::from_value(json).unwrap();
        assert_eq!(old.estimate, EstimateBasis::Measured);
        assert_eq!(
            serde_json::to_value(EstimateBasis::NeedsAdmin).unwrap(),
            "needs_admin"
        );
    }
}
