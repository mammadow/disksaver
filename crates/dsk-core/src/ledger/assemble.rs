#![forbid(unsafe_code)]

//! One call that gathers every reclaim source into a [`Ledger`] (used by the CLI `reclaim` and
//! `hunt` commands and the GUI Overview). Read-only: nothing here changes the disk, and the journal
//! is only read when it already exists.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};

use crate::clean::deny::DenyContext;
use crate::clean::executor::enrich_os_handler_estimates;
use crate::clean::journal::ActionJournal;
use crate::clean::plan::{
    CleanPlan, FileIdKind, PlanOptions, build_plan_from_index, mark_admin_gated_estimates,
};
use crate::clean::rules::{RuleTier, builtin_rules};
use crate::error::Result;
use crate::index::Index;
use crate::insights::downloads::{DownloadsReport, downloads_roots, scan_downloads};
use crate::insights::dupes::{DupeReport, find_duplicates, is_hardlink_safe_group};
use crate::insights::{FullInsightsReport, InsightsOptions, run_all_insights};
use crate::ledger::{CompressCandidate, Ledger, LedgerBuilder};
use crate::optimize::sizing::{
    SizingFacts, SizingRecommendation, advise_sizing, gather_sizing_facts,
};
use crate::optimize::sys_tunables::probe_sys_tunables;
use crate::optimize::vhdx::{VhdxCandidate, discover_vhdx_candidates};
use crate::optimize::wof_discover::{DiscoverOptions, discover_compress_candidates};
use crate::scan::ScanMethod;
use crate::sweep::{SweepCandidate, SweepOptions, find_sweep_candidates};
use crate::win::prefetch::enumerate_installed_apps;

/// What to include.
#[derive(Clone, Debug)]
pub struct AssembleOptions {
    pub tier_max: RuleTier,
    pub include_os_handlers: bool,
    pub insights: InsightsOptions,
    /// Hash duplicates of at least this size (reads file contents; `None` skips).
    pub dupes_min_bytes: Option<u64>,
    pub hash_cache: Option<PathBuf>,
    /// Sample install folders for WOF savings (reads up to 8 MiB per folder).
    pub compression: bool,
    pub sizing: bool,
    pub vhdx: bool,
    pub sweeps: bool,
    pub downloads: bool,
    /// Look for oversized video recordings (reads cached media properties only).
    pub recordings: bool,
    /// Journal to read calibration ratios from (never created).
    pub journal_path: Option<PathBuf>,
}

impl Default for AssembleOptions {
    fn default() -> Self {
        Self {
            tier_max: RuleTier::Review,
            include_os_handlers: true,
            insights: InsightsOptions::default(),
            dupes_min_bytes: None,
            hash_cache: None,
            compression: true,
            sizing: true,
            vhdx: true,
            sweeps: true,
            downloads: true,
            recordings: true,
            journal_path: Some(ActionJournal::default_path()),
        }
    }
}

/// Everything gathered, plus the ledger built from it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assembled {
    pub ledger: Ledger,
    pub plan: CleanPlan,
    pub insights: FullInsightsReport,
    pub sizing_facts: Option<SizingFacts>,
    pub sizing: Vec<SizingRecommendation>,
    pub vhdx: Vec<VhdxCandidate>,
    pub compression: Vec<CompressCandidate>,
    pub dupes: Option<DupeReport>,
    pub sweeps: Vec<SweepCandidate>,
    pub downloads: DownloadsReport,
    pub recordings: crate::insights::media::RecordingsReport,
}

/// Gathers all sources for `index` and builds the ledger.
pub fn assemble(
    index: &Index,
    scan_method: ScanMethod,
    scanned_path: &Path,
    opts: &AssembleOptions,
    cancel: &AtomicBool,
) -> Result<Assembled> {
    let deny = DenyContext::default();
    let rules = builtin_rules()?;
    let plan_opts = PlanOptions {
        rule_filter: Vec::new(),
        include_recycle_bin: false,
        include_os_handlers: opts.include_os_handlers,
        tier_max: opts.tier_max,
        now_min2000: None,
    };
    let dynamic_roots = crate::clean::providers::dynamic_roots(
        index,
        &crate::insights::scan_gaming_libraries(index),
    );
    let env_lookup = dynamic_roots.env_lookup();
    let mut plan = build_plan_from_index(
        index,
        scan_method,
        scanned_path,
        &rules,
        &deny,
        &plan_opts,
        &env_lookup,
    );
    if opts.include_os_handlers {
        enrich_os_handler_estimates(&mut plan, cancel);
    }
    mark_admin_gated_estimates(&mut plan, crate::win::volume::is_elevated());

    let insights = run_all_insights(index, &opts.insights);

    let (sizing_facts, sizing) = if opts.sizing && index.volume().root.len() <= 8 {
        let status = probe_sys_tunables(Some(index));
        let compact_os = crate::optimize::wof::query_compact_os_state()
            .ok()
            .map(|s| s.enabled);
        let facts = gather_sizing_facts(&status, Some(index), compact_os);
        let recs = advise_sizing(&facts);
        (Some(facts), recs)
    } else {
        (None, Vec::new())
    };

    let vhdx = if opts.vhdx {
        discover_vhdx_candidates(index)
    } else {
        Vec::new()
    };

    let compression = if opts.compression {
        discover_compress_candidates(index, Some(&insights.gaming), &DiscoverOptions::default())
    } else {
        Vec::new()
    };

    let file_id_kind = match scan_method {
        ScanMethod::Mft | ScanMethod::UsnIncremental => FileIdKind::NtfsFrn64,
        ScanMethod::Dir | ScanMethod::Auto => FileIdKind::FxHash128,
    };
    let sweeps = if opts.sweeps {
        find_sweep_candidates(index, &SweepOptions::default(), file_id_kind, &deny)
    } else {
        Vec::new()
    };

    let downloads = if opts.downloads {
        scan_downloads(index, &downloads_roots(), &enumerate_installed_apps(), 30)
    } else {
        DownloadsReport::default()
    };

    let recordings = if opts.recordings {
        crate::insights::media::scan_recordings(
            index,
            1 << 30,
            40.0,
            &crate::win::decisions::media_duration_secs,
        )
    } else {
        Default::default()
    };

    let dupes = match opts.dupes_min_bytes {
        Some(min) => {
            find_duplicates(index, min, opts.hash_cache.as_deref(), None, cancel, |_| {}).ok()
        }
        None => None,
    };

    let mut b = LedgerBuilder::new(Some(index));
    if let Some(j) = &opts.journal_path {
        b = b.with_journal_calibration(j);
    }
    b.add_clean_plan(&plan);
    b.add_sweeps(&sweeps);
    b.add_insights(&insights);
    if let Some(d) = &dupes {
        b.add_dupes(d, &is_hardlink_safe_group);
    }
    b.add_downloads(&downloads);
    b.add_recordings(&recordings);
    if let Some(f) = &sizing_facts {
        b.add_sizing(&sizing, &f.system_drive);
    }
    b.add_vhdx(&vhdx);
    b.add_compression(&compression);
    if !crate::win::volume::is_elevated() {
        b.note("Run elevated (or use the helper) to estimate system rules, DISM, and the driver store.");
    }
    let ledger = b.finish();

    Ok(Assembled {
        ledger,
        plan,
        insights,
        sizing_facts,
        sizing,
        vhdx,
        compression,
        dupes,
        sweeps,
        downloads,
        recordings,
    })
}
