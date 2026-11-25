#![forbid(unsafe_code)]

//! Safe cleanup rules, plan generation, journaling, and execution.

pub mod deny;
pub mod driverstore;
pub mod executor;
pub mod journal;
pub mod plan;
pub mod providers;
pub mod rules;

pub use deny::{
    DenyContext, assert_not_denied, is_denied_path, is_under_root, normalize_win_path_str,
};
pub use driverstore::{
    DriverPackageInfo, parse_pnputil_bound_infs, parse_pnputil_drivers, select_prunable_drivers,
    validate_oem_inf_name,
};
pub use executor::{
    CleanPhase, CleanProgress, CleanReport, ExecuteOptions, RuleExecutionSummary,
    enrich_os_handler_estimates, execute_plan, execute_plan_with_impersonation, probe_locked_roots,
};
pub use journal::{
    ActionJournal, JournalEntryRecord, JournalRunRecord, RelocationRecord, VideoJobRecord,
};
pub use plan::{
    CleanPlan, EstimateBasis, FileIdKind, PlanOptions, PlannedItem, PlannedRoot, PlannedRule,
    SkippedRule, build_plan_from_index, mark_admin_gated_estimates, match_segment_glob,
};
pub use rules::{
    PreconditionRule, RuleDef, RuleMethod, RuleTier, builtin_rules, expand_path_template,
    parse_rules_toml,
};
