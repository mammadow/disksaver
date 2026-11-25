//! SQLite directory rollup history (`growth.db`) and 24h / 7d growth delta analyzer.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{DskError, Result};
use crate::index::builder::{Index, NONE, NodeFlags, NodeId, ROOT};

/// Threshold (`5 GiB/day`) above which a directory's growth rate is flagged as runaway.
pub const RUNAWAY_BYTES_PER_DAY: i64 = 5 * 1024 * 1024 * 1024;

/// Maximum tree depth automatically recorded even if under [`MIN_ROLLUP_BYTES`].
pub const MAX_ROLLUP_DEPTH: u16 = 4;

/// Minimum subtree allocation (`10 MiB`) recorded at any depth.
pub const MIN_ROLLUP_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum directory rollup rows stored per snapshot.
pub const MAX_ROWS_PER_SNAPSHOT: usize = 5_000;

/// Snapshots of the same volume and size basis closer together than this are collapsed into the
/// newest one.
pub const SNAPSHOT_DEDUPE_SECS: i64 = 3_600;

/// Retention period for stored growth snapshots.
pub const RETENTION_DAYS: i64 = 30;

/// How a snapshot's sizes were measured. Different scan engines count different things (the MFT
/// reader includes metafiles, alternate streams, and directory index allocations; the directory
/// walker sees only main streams and skips access-denied trees), so a snapshot is only ever
/// compared against a baseline with the same basis. Legacy rows (no basis) compare with anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SizeBasis {
    /// MFT reader (and USN-incremental updates of an MFT snapshot).
    Mft,
    /// `FindFirstFileEx` directory walker.
    Dir,
}

impl SizeBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            SizeBasis::Mft => "mft",
            SizeBasis::Dir => "dir",
        }
    }

    /// Maps a scan report's `method_used` to its size basis.
    pub fn from_scan_method(method: crate::scan::ScanMethod) -> Self {
        match method {
            crate::scan::ScanMethod::Dir => SizeBasis::Dir,
            _ => SizeBasis::Mft,
        }
    }
}

/// Parent of a stored rollup path (`C:\a\b` -> `C:\a`), or `None` at the top.
fn rollup_parent(path: &str) -> Option<&str> {
    let (parent, _) = path.trim_end_matches('\\').rsplit_once('\\')?;
    Some(parent)
}

/// Comparison time window for growth reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GrowthWindow {
    #[default]
    H24,
    D7,
}

impl GrowthWindow {
    pub fn seconds(self) -> i64 {
        match self {
            GrowthWindow::H24 => 86_400,
            GrowthWindow::D7 => 7 * 86_400,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            GrowthWindow::H24 => "24h",
            GrowthWindow::D7 => "7d",
        }
    }
}

/// Growth delta for a single directory compared against an earlier snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrowthDelta {
    pub path: String,
    pub current_bytes: u64,
    pub previous_bytes: u64,
    pub delta_bytes: i64,
    pub rate_bytes_per_day: i64,
    pub runaway: bool,
}

/// Complete growth comparison report for a volume over a time window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrowthReport {
    pub volume: String,
    pub window: String,
    pub has_baseline: bool,
    pub latest_at_unix: Option<i64>,
    pub baseline_at_unix: Option<i64>,
    pub volume_delta_bytes: i64,
    pub runaways: Vec<GrowthDelta>,
    pub entries: Vec<GrowthDelta>,
}

/// Persistent SQLite rollup database (`%LOCALAPPDATA%\DiskSaver\growth.db`).
pub struct GrowthDb {
    conn: Connection,
}

impl GrowthDb {
    /// Returns the default on-disk location (`%LOCALAPPDATA%\DiskSaver\growth.db`).
    pub fn default_path() -> PathBuf {
        if let Ok(local) = std::env::var("LOCALAPPDATA")
            && !local.trim().is_empty()
        {
            return PathBuf::from(local).join("DiskSaver").join("growth.db");
        }
        if let Ok(profile) = std::env::var("USERPROFILE")
            && !profile.trim().is_empty()
        {
            return PathBuf::from(profile)
                .join("AppData")
                .join("Local")
                .join("DiskSaver")
                .join("growth.db");
        }
        PathBuf::from("growth.db")
    }

    /// Returns the current UNIX epoch timestamp in seconds.
    pub fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Normalizes a volume/path key for consistent lookup across CLI and GUI.
    pub fn normalize_volume_key(volume: &str) -> String {
        let mut s = volume.trim().replace('/', "\\");
        let bytes = s.as_bytes();
        if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            s.push('\\');
        } else if s.len() > 3 {
            while s.ends_with('\\') {
                s.pop();
            }
        }
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            let first = s.as_bytes()[0].to_ascii_uppercase() as char;
            s = format!("{first}{}", &s[1..]);
        }
        s
    }

    fn init_pragmas_and_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                captured_at_unix INTEGER NOT NULL,
                volume TEXT NOT NULL,
                total_alloc INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dir_rollups (
                snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                agg_alloc INTEGER NOT NULL,
                agg_count INTEGER NOT NULL,
                depth INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_vol_time
                ON snapshots(volume, captured_at_unix DESC);
            CREATE INDEX IF NOT EXISTS idx_rollups_snap
                ON dir_rollups(snapshot_id);
            "#,
        )
        .map_err(|e| DskError::Journal(format!("failed to initialize growth schema: {e}")))?;
        Self::ensure_size_basis_column(conn)
    }

    /// Adds `snapshots.size_basis` to databases created before it existed (`CREATE TABLE IF NOT
    /// EXISTS` never alters an existing table). Pre-existing rows keep `NULL` = unknown basis.
    fn ensure_size_basis_column(conn: &Connection) -> Result<()> {
        let has_col: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('snapshots') WHERE name = 'size_basis')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| DskError::Journal(format!("failed to inspect growth schema: {e}")))?;
        if !has_col {
            conn.execute("ALTER TABLE snapshots ADD COLUMN size_basis TEXT", [])
                .map_err(|e| DskError::Journal(format!("failed to migrate growth schema: {e}")))?;
        }
        Ok(())
    }

    /// Opens or creates the growth database and ensures its schema exists.
    pub fn open(path: &Path) -> Result<Self> {
        if path != Path::new(":memory:")
            && let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .map_err(|e| DskError::Journal(format!("failed to open growth db: {e}")))?;
        Self::init_pragmas_and_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Opens an existing growth database without creating a file on disk if missing.
    pub fn open_existing(path: &Path) -> Result<Option<Self>> {
        if !path.is_file() {
            return Ok(None);
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| DskError::Journal(format!("failed to open existing growth db: {e}")))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| DskError::Journal(format!("failed to configure growth db: {e}")))?;
        let has_table: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='snapshots')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| DskError::Journal(format!("failed to inspect growth db schema: {e}")))?;
        if !has_table {
            return Ok(None);
        }
        Self::ensure_size_basis_column(&conn)?;
        Ok(Some(Self { conn }))
    }

    /// Records bounded directory rollups (`depth <= 4` or `>= 10 MiB`, max 5,000 rows, 30d pruning)
    /// with an unknown size basis (compared against any baseline). Production callers should use
    /// [`GrowthDb::record_rollup_with_basis`].
    pub fn record_rollup_from_index(
        &mut self,
        index: &Index,
        volume: &str,
        now_unix: i64,
    ) -> Result<usize> {
        self.record_rollup_inner(index, volume, now_unix, None)
    }

    /// Records bounded directory rollups tagged with the scan engine's [`SizeBasis`], so later
    /// reports never compare an MFT snapshot against a directory-walker baseline.
    pub fn record_rollup_with_basis(
        &mut self,
        index: &Index,
        volume: &str,
        now_unix: i64,
        basis: SizeBasis,
    ) -> Result<usize> {
        self.record_rollup_inner(index, volume, now_unix, Some(basis))
    }

    fn record_rollup_inner(
        &mut self,
        index: &Index,
        volume: &str,
        now_unix: i64,
        basis: Option<SizeBasis>,
    ) -> Result<usize> {
        if index.is_empty() {
            return Ok(0);
        }

        let norm_vol = Self::normalize_volume_key(volume);
        let first_child_sl = index.first_child_slice();
        let next_sibling_sl = index.next_sibling_slice();
        let agg_alloc_sl = index.agg_alloc_slice();
        let agg_count_sl = index.agg_count_slice();
        let root_alloc = agg_alloc_sl[ROOT as usize];

        struct RollupRow {
            path: String,
            agg_alloc: u64,
            agg_count: u32,
            depth: u16,
        }

        let mut rows: Vec<RollupRow> = Vec::new();
        let root_path = index.path(ROOT).to_string_lossy().into_owned();
        let mut stack: Vec<(NodeId, u16, String)> = vec![(ROOT, 0, root_path)];

        while let Some((nid, depth, dir_path)) = stack.pop() {
            let mut child = first_child_sl[nid as usize];
            while child != NONE {
                let flags = index.flags(child);
                if flags.contains(NodeFlags::DIR) && !flags.contains(NodeFlags::METAFILE) {
                    let c_depth = depth.saturating_add(1);
                    let c_alloc = agg_alloc_sl[child as usize];
                    let c_count = agg_count_sl[child as usize];
                    let cname = index.name(child);
                    let child_path = if dir_path.ends_with('\\') {
                        format!("{dir_path}{cname}")
                    } else {
                        format!("{dir_path}\\{cname}")
                    };

                    if c_depth <= MAX_ROLLUP_DEPTH || c_alloc >= MIN_ROLLUP_BYTES {
                        rows.push(RollupRow {
                            path: child_path.clone(),
                            agg_alloc: c_alloc,
                            agg_count: c_count,
                            depth: c_depth,
                        });
                    }

                    // Prune traversal when deeper than MAX_ROLLUP_DEPTH and entire subtree is < 10 MiB.
                    if c_depth < MAX_ROLLUP_DEPTH || c_alloc >= MIN_ROLLUP_BYTES {
                        stack.push((child, c_depth, child_path));
                    }
                }
                child = next_sibling_sl[child as usize];
            }
        }

        rows.sort_by(|a, b| b.agg_alloc.cmp(&a.agg_alloc).then(a.depth.cmp(&b.depth)));
        rows.truncate(MAX_ROWS_PER_SNAPSHOT);
        let stored_count = rows.len();

        let cutoff_unix = now_unix.saturating_sub(RETENTION_DAYS * 86_400);
        let tx = self
            .conn
            .transaction()
            .map_err(|e| DskError::Journal(format!("failed to begin growth transaction: {e}")))?;

        tx.execute(
            "DELETE FROM snapshots WHERE volume = ?1 AND captured_at_unix < ?2",
            rusqlite::params![&norm_vol, cutoff_unix],
        )
        .map_err(|e| DskError::Journal(format!("failed to prune old growth snapshots: {e}")))?;

        // Per-hour dedupe: frequent (USN-incremental) rescans would otherwise store a full
        // 5,000-row snapshot each time. Keep only the newest snapshot per volume and size basis
        // within any SNAPSHOT_DEDUPE_SECS span; 24h/7d windows never need finer resolution.
        tx.execute(
            "DELETE FROM snapshots WHERE volume = ?1 AND size_basis IS ?2 AND captured_at_unix > ?3 AND captured_at_unix <= ?4",
            rusqlite::params![
                &norm_vol,
                basis.map(SizeBasis::as_str),
                now_unix.saturating_sub(SNAPSHOT_DEDUPE_SECS),
                now_unix
            ],
        )
        .map_err(|e| DskError::Journal(format!("failed to dedupe growth snapshots: {e}")))?;

        tx.execute(
            "INSERT INTO snapshots (captured_at_unix, volume, total_alloc, size_basis) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![now_unix, &norm_vol, root_alloc as i64, basis.map(SizeBasis::as_str)],
        )
        .map_err(|e| DskError::Journal(format!("failed to insert growth snapshot: {e}")))?;
        let snap_id = tx.last_insert_rowid();

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO dir_rollups (snapshot_id, path, agg_alloc, agg_count, depth) VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .map_err(|e| DskError::Journal(format!("failed to prepare rollup insert: {e}")))?;
            for row in &rows {
                stmt.execute(rusqlite::params![
                    snap_id,
                    &row.path,
                    row.agg_alloc as i64,
                    row.agg_count as i64,
                    row.depth as i64,
                ])
                .map_err(|e| DskError::Journal(format!("failed to insert rollup row: {e}")))?;
            }
        }

        tx.commit()
            .map_err(|e| DskError::Journal(format!("failed to commit growth transaction: {e}")))?;

        Ok(stored_count)
    }

    /// `path -> (agg_alloc, depth)` for one snapshot.
    fn load_rollup_map(&self, snapshot_id: i64) -> Result<HashMap<String, (u64, u16)>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT path, agg_alloc, depth FROM dir_rollups WHERE snapshot_id = ?1")
            .map_err(|e| DskError::Journal(format!("failed to prepare rollup query: {e}")))?;
        let rows = stmt
            .query_map([snapshot_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?.max(0) as u64,
                    r.get::<_, i64>(2)?.clamp(0, i64::from(u16::MAX)) as u16,
                ))
            })
            .map_err(|e| DskError::Journal(format!("failed to query rollups: {e}")))?;

        let mut map = HashMap::new();
        for row in rows {
            let (p, b, d) = row.map_err(|e| DskError::Journal(e.to_string()))?;
            map.insert(p, (b, d));
        }
        Ok(map)
    }

    /// Computes top growing directories over `window` and flags runaway growth (`>= 5 GiB/day`).
    pub fn compute_growth_since(
        &self,
        volume: &str,
        window: GrowthWindow,
        now_unix: i64,
        limit: usize,
    ) -> Result<GrowthReport> {
        let norm_vol = Self::normalize_volume_key(volume);

        let latest: Option<(i64, i64, i64, Option<String>)> = self
            .conn
            .query_row(
                "SELECT id, captured_at_unix, total_alloc, size_basis FROM snapshots WHERE volume = ?1 ORDER BY captured_at_unix DESC, id DESC LIMIT 1",
                rusqlite::params![&norm_vol],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|e| DskError::Journal(format!("failed to query latest snapshot: {e}")))?;

        let Some((latest_id, latest_ts, latest_total, latest_basis)) = latest else {
            return Ok(GrowthReport {
                volume: norm_vol,
                window: window.label().to_string(),
                has_baseline: false,
                latest_at_unix: None,
                baseline_at_unix: None,
                volume_delta_bytes: 0,
                runaways: Vec::new(),
                entries: Vec::new(),
            });
        };

        // The window ends at the latest snapshot, not at `now`: if the last scan was three days ago,
        // "24h" must still mean the 24 hours before that scan (anchoring on `now` silently turned
        // it into a multi-day comparison).
        let _ = now_unix;
        let target_ts = latest_ts.saturating_sub(window.seconds());
        // Only compare like with like (same size basis); legacy NULL rows match anything.
        const BASIS_FILTER: &str = "(?3 IS NULL OR size_basis IS NULL OR size_basis = ?3)";
        let baseline: Option<(i64, i64, i64)> = self
            .conn
            .query_row(
                &format!(
                    "SELECT id, captured_at_unix, total_alloc FROM snapshots WHERE volume = ?1 AND id != ?2 AND {BASIS_FILTER} AND captured_at_unix <= ?4 ORDER BY captured_at_unix DESC, id DESC LIMIT 1"
                ),
                rusqlite::params![&norm_vol, latest_id, &latest_basis, target_ts],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| DskError::Journal(format!("failed to query baseline snapshot: {e}")))?;
        let baseline = match baseline {
            Some(b) => Some(b),
            None => self
                .conn
                .query_row(
                    &format!(
                        "SELECT id, captured_at_unix, total_alloc FROM snapshots WHERE volume = ?1 AND id != ?2 AND {BASIS_FILTER} ORDER BY captured_at_unix ASC, id ASC LIMIT 1"
                    ),
                    rusqlite::params![&norm_vol, latest_id, &latest_basis],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(|e| {
                    DskError::Journal(format!("failed to query fallback baseline snapshot: {e}"))
                })?,
        };

        let Some((base_id, base_ts, base_total)) = baseline else {
            return Ok(GrowthReport {
                volume: norm_vol,
                window: window.label().to_string(),
                has_baseline: false,
                latest_at_unix: Some(latest_ts),
                baseline_at_unix: None,
                volume_delta_bytes: 0,
                runaways: Vec::new(),
                entries: Vec::new(),
            });
        };

        let curr_map = self.load_rollup_map(latest_id)?;
        let prev_map = self.load_rollup_map(base_id)?;
        let elapsed_secs = (latest_ts - base_ts).max(1) as i128;
        // A per-day rate extrapolated from minutes of data is noise (one download between two
        // scans a minute apart would read as ~140 GiB/day): only flag runaways once the baseline
        // spans at least a quarter of the window.
        let runaway_window_ok = elapsed_secs >= (window.seconds() / 4).max(1) as i128;
        // Snapshots keep only the largest MAX_ROWS_PER_SNAPSHOT directories. If the baseline was
        // truncated, a path missing from it was at most the baseline's smallest stored row, not 0
        // (assuming 0 would report its entire size as growth).
        let absent_prev_floor = if prev_map.len() >= MAX_ROWS_PER_SNAPSHOT {
            prev_map.values().map(|(b, _)| *b).min().unwrap_or(0)
        } else {
            0
        };

        let mut deltas: Vec<(GrowthDelta, u16)> = Vec::new();
        for (path, (curr_bytes, depth)) in curr_map {
            let prev_bytes = match prev_map.get(&path) {
                Some((b, _)) => *b,
                // Deeper than MAX_ROLLUP_DEPTH, a directory is only recorded at >= 10 MiB: its
                // absence from the baseline means "was below 10 MiB", not "was empty" (otherwise
                // a 9 -> 11 MiB change would read as +11 MiB of growth).
                None if depth > MAX_ROLLUP_DEPTH => absent_prev_floor
                    .max(MIN_ROLLUP_BYTES.saturating_sub(1))
                    .min(curr_bytes),
                None => absent_prev_floor.min(curr_bytes),
            };
            let delta_i128 = (curr_bytes as i128) - (prev_bytes as i128);
            if delta_i128 <= 0 {
                continue;
            }
            let delta_bytes = delta_i128.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
            let rate_i128 = (delta_i128 * 86_400) / elapsed_secs;
            let rate_bytes_per_day = rate_i128.clamp(i64::MIN as i128, i64::MAX as i128) as i64;

            deltas.push((
                GrowthDelta {
                    path,
                    current_bytes: curr_bytes,
                    previous_bytes: prev_bytes,
                    delta_bytes,
                    rate_bytes_per_day,
                    runaway: false,
                },
                depth,
            ));
        }

        let deltas = attribute_growth_to_deepest_folders(deltas, runaway_window_ok);
        let runaways: Vec<GrowthDelta> = deltas.iter().filter(|d| d.runaway).cloned().collect();
        let mut deltas = deltas;
        deltas.truncate(limit);

        let vol_delta = ((latest_total as i128) - (base_total as i128))
            .clamp(i64::MIN as i128, i64::MAX as i128) as i64;

        Ok(GrowthReport {
            volume: norm_vol,
            window: window.label().to_string(),
            has_baseline: true,
            latest_at_unix: Some(latest_ts),
            baseline_at_unix: Some(base_ts),
            volume_delta_bytes: vol_delta,
            runaways,
            entries: deltas,
        })
    }
}

/// Nested-ancestor discounting for growth reports.
///
/// Every ancestor of a growing folder grows by the same bytes, so a single +7 GiB folder five
/// levels deep used to produce five +7 GiB rows (and five runaway alerts), pushing the real
/// culprit out of the top-N list. This:
/// 1. drops an ancestor row whose growth is (almost) fully explained by its listed children
///    (exclusive growth below [`MIN_ROLLUP_BYTES`]);
/// 2. flags a runaway only on the deepest folder whose own inclusive rate crosses the threshold
///    (ancestors of a flagged runaway are never flagged again), so the count matches reality.
fn attribute_growth_to_deepest_folders(
    deltas: Vec<(GrowthDelta, u16)>,
    runaway_window_ok: bool,
) -> Vec<GrowthDelta> {
    use std::collections::HashSet;

    let mut child_growth: HashMap<String, i64> = HashMap::new();
    for (d, _) in &deltas {
        if let Some(parent) = rollup_parent(&d.path) {
            *child_growth.entry(parent.to_string()).or_default() += d.delta_bytes;
        }
    }

    // Deepest first, so descendants are decided before their ancestors.
    let mut order: Vec<(GrowthDelta, u16)> = deltas;
    order.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.path.cmp(&b.0.path)));
    let mut covered_by_runaway: HashSet<String> = HashSet::new();
    let mut kept: Vec<GrowthDelta> = Vec::with_capacity(order.len());
    for (mut d, _) in order {
        let qualifies = runaway_window_ok
            && d.delta_bytes >= 64 * 1024 * 1024
            && d.rate_bytes_per_day >= RUNAWAY_BYTES_PER_DAY;
        d.runaway = qualifies && !covered_by_runaway.contains(&d.path);
        if qualifies || covered_by_runaway.contains(&d.path) {
            let mut cur = rollup_parent(&d.path);
            while let Some(p) = cur {
                if !covered_by_runaway.insert(p.to_string()) {
                    break;
                }
                cur = rollup_parent(p);
            }
        }

        let children = child_growth.get(&d.path).copied().unwrap_or(0);
        let exclusive = d.delta_bytes.saturating_sub(children.max(0));
        let explained_by_children = children > 0 && exclusive < MIN_ROLLUP_BYTES as i64;
        if d.runaway || !explained_by_children {
            kept.push(d);
        }
    }

    kept.sort_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes).then(a.path.cmp(&b.path)));
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::builder::{EntryBatch, IndexBuilder, RawEntry};
    use crate::index::names::NameArena;
    use crate::volume::VolumeInfo;

    fn make_index_with_sizes(
        logs_bytes: u64,
        deep_cache_bytes: u64,
        tiny_deep_bytes: u64,
    ) -> Index {
        let vol = VolumeInfo {
            root: "C:\\".to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0x1234_5678,
            cluster_size: 4096,
            total_bytes: 1_000_000_000_000,
            free_bytes: 500_000_000_000,
            seek_penalty: Some(false),
        };
        let mut names = NameArena::new();
        let mut b = IndexBuilder::new(5, "C:\\", vol);
        let d_logs = names.push_str("Logs");
        let f_logs = names.push_str("app.log");

        // Build a depth-6 directory under DeepRoot
        let d1 = names.push_str("d1");
        let d2 = names.push_str("d2");
        let d3 = names.push_str("d3");
        let d4 = names.push_str("d4");
        let d5 = names.push_str("d5_big");
        let d6_tiny = names.push_str("d5_tiny");
        let f_deep = names.push_str("model.bin");
        let f_tiny = names.push_str("small.txt");

        b.push_batch(EntryBatch {
            names,
            entries: vec![
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    file_id: 10,
                    name: d_logs,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 10,
                    file_id: 11,
                    name: f_logs,
                    logical: logs_bytes,
                    allocated: logs_bytes,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 20,
                    parent_key: 5,
                    file_id: 20,
                    name: d1,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 21,
                    parent_key: 20,
                    file_id: 21,
                    name: d2,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 22,
                    parent_key: 21,
                    file_id: 22,
                    name: d3,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 23,
                    parent_key: 22,
                    file_id: 23,
                    name: d4,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 24,
                    parent_key: 23,
                    file_id: 24,
                    name: d5,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 25,
                    parent_key: 24,
                    file_id: 25,
                    name: f_deep,
                    logical: deep_cache_bytes,
                    allocated: deep_cache_bytes,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 26,
                    parent_key: 23,
                    file_id: 26,
                    name: d6_tiny,
                    logical: 0,
                    allocated: 0,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::DIR,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 27,
                    parent_key: 26,
                    file_id: 27,
                    name: f_tiny,
                    logical: tiny_deep_bytes,
                    allocated: tiny_deep_bytes,
                    mtime: 10,
                    atime: 10,
                    flags: NodeFlags::empty(),
                    reparse_tag: 0,
                },
            ],
        });
        b.finish()
    }

    #[test]
    fn open_existing_does_not_create_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sub").join("growth.db");
        assert!(GrowthDb::open_existing(&db_path).unwrap().is_none());
        assert!(!db_path.exists());
        assert!(!dir.path().join("sub").exists());
    }

    #[test]
    fn short_baselines_report_growth_but_never_flag_runaways() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = GrowthDb::open(&dir.path().join("growth.db")).unwrap();
        let now = 2_000_000_000i64;

        // Two scans two hours apart with +2 GiB in C:\Logs (24 GiB/day if extrapolated), i.e.
        // longer than the hourly dedupe but far shorter than a quarter of the 24h window.
        let ix_base = make_index_with_sizes(1_000_000_000, 20_000_000, 4096);
        db.record_rollup_from_index(&ix_base, "C:\\", now - 2 * 3600)
            .unwrap();
        let ix_now =
            make_index_with_sizes(1_000_000_000 + 2 * 1024 * 1024 * 1024, 20_000_000, 4096);
        db.record_rollup_from_index(&ix_now, "C:\\", now).unwrap();

        let report = db
            .compute_growth_since("C:\\", GrowthWindow::H24, now, 20)
            .unwrap();
        assert!(report.has_baseline);
        assert!(
            report.entries.iter().any(|e| e.delta_bytes > 0),
            "growth is still listed"
        );
        assert!(
            report.runaways.is_empty(),
            "a 2-hour baseline must not produce runaway alerts: {:?}",
            report.runaways
        );
    }

    #[test]
    fn rollup_retention_and_runaway_detection() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("growth.db");
        let mut db = GrowthDb::open(&db_path).unwrap();

        let now = 2_000_000_000i64;
        let old_40d = now - 40 * 86_400;
        let baseline_25h = now - 25 * 3600;

        // Snapshot 40 days ago (should be pruned once `now` snapshot records)
        let ix_old = make_index_with_sizes(100_000_000, 20_000_000, 4096);
        db.record_rollup_from_index(&ix_old, "C:\\", old_40d)
            .unwrap();

        // Snapshot 25h ago
        let ix_base = make_index_with_sizes(1_000_000_000, 20_000_000, 4096);
        db.record_rollup_from_index(&ix_base, "C:\\", baseline_25h)
            .unwrap();

        // Current snapshot: C:\Logs grew by +7 GiB (exceeds 5 GiB/day threshold!)
        let ix_now =
            make_index_with_sizes(1_000_000_000 + 7 * 1024 * 1024 * 1024, 50_000_000, 4096);
        db.record_rollup_from_index(&ix_now, "C:\\", now).unwrap();

        let report = db
            .compute_growth_since("C:\\", GrowthWindow::H24, now, 20)
            .unwrap();
        assert!(report.has_baseline);
        assert_eq!(report.baseline_at_unix, Some(baseline_25h));
        assert!(!report.runaways.is_empty());
        assert_eq!(report.runaways[0].path, "C:\\Logs");
        assert!(report.runaways[0].runaway);

        // Depth-5 directory >= 10 MiB (`d5_big`) must appear in delta; depth-5 `d5_tiny` (4 KiB) was excluded.
        assert!(
            report
                .entries
                .iter()
                .any(|e| e.path.ends_with("d5_big") && e.delta_bytes == 30_000_000)
        );
        assert!(!report.entries.iter().any(|e| e.path.ends_with("d5_tiny")));

        // Verify 40-day-old snapshot was pruned
        let count_old: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM snapshots WHERE captured_at_unix = ?1",
                [old_40d],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count_old, 0);
    }

    #[test]
    fn nested_ancestors_are_discounted_and_runaway_counted_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = GrowthDb::open(&dir.path().join("growth.db")).unwrap();
        let now = 2_000_000_000i64;
        // +7 GiB inside C:\d1\d2\d3\d4\d5_big over 25 h.
        let gib = 1024 * 1024 * 1024u64;
        let base = make_index_with_sizes(1_000_000, 20_000_000, 4096);
        db.record_rollup_with_basis(&base, "C:\\", now - 25 * 3600, SizeBasis::Mft)
            .unwrap();
        let grown = make_index_with_sizes(1_000_000, 20_000_000 + 7 * gib, 4096);
        db.record_rollup_with_basis(&grown, "C:\\", now, SizeBasis::Mft)
            .unwrap();

        let rep = db
            .compute_growth_since("C:\\", GrowthWindow::H24, now, 15)
            .unwrap();
        assert_eq!(
            rep.runaways.len(),
            1,
            "one growing folder is one runaway, not one per ancestor: {:?}",
            rep.runaways
        );
        assert!(rep.runaways[0].path.ends_with("d5_big"));
        assert!(
            rep.entries.iter().all(|e| !e.path.ends_with("\\d1")
                && !e.path.ends_with("\\d2")
                && !e.path.ends_with("\\d3")
                && !e.path.ends_with("\\d4")),
            "ancestors fully explained by d5_big are hidden: {:?}",
            rep.entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
        assert_eq!(rep.entries[0].path, rep.runaways[0].path);
    }

    #[test]
    fn mixed_scan_methods_are_never_compared() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = GrowthDb::open(&dir.path().join("growth.db")).unwrap();
        let now = 2_000_000_000i64;
        let gib = 1024 * 1024 * 1024u64;
        // Directory-walker baseline (smaller: no metafiles) vs. an MFT scan a day later.
        let dir_scan = make_index_with_sizes(1_000_000_000, 20_000_000, 4096);
        db.record_rollup_with_basis(&dir_scan, "C:\\", now - 25 * 3600, SizeBasis::Dir)
            .unwrap();
        let mft_scan = make_index_with_sizes(1_000_000_000 + 8 * gib, 20_000_000, 4096);
        db.record_rollup_with_basis(&mft_scan, "C:\\", now, SizeBasis::Mft)
            .unwrap();
        let rep = db
            .compute_growth_since("C:\\", GrowthWindow::H24, now, 15)
            .unwrap();
        assert!(
            !rep.has_baseline,
            "an MFT snapshot must not be diffed against a directory-walker baseline"
        );

        // A same-basis baseline is found even when a newer other-basis snapshot exists.
        let mft_base = make_index_with_sizes(1_000_000_000, 20_000_000, 4096);
        db.record_rollup_with_basis(&mft_base, "C:\\", now - 26 * 3600, SizeBasis::Mft)
            .unwrap();
        let rep = db
            .compute_growth_since("C:\\", GrowthWindow::H24, now, 15)
            .unwrap();
        assert!(rep.has_baseline);
        assert_eq!(rep.baseline_at_unix, Some(now - 26 * 3600));
    }

    #[test]
    fn rescans_within_an_hour_keep_only_the_newest_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = GrowthDb::open(&dir.path().join("growth.db")).unwrap();
        let now = 2_000_000_000i64;
        let ix = make_index_with_sizes(1_000_000_000, 20_000_000, 4096);
        db.record_rollup_with_basis(&ix, "C:\\", now - 2 * 86_400, SizeBasis::Mft)
            .unwrap();
        for ts in [now - 3000, now - 1200, now] {
            db.record_rollup_with_basis(&ix, "C:\\", ts, SizeBasis::Mft)
                .unwrap();
        }
        // A different basis in the same hour is a different series and is kept.
        db.record_rollup_with_basis(&ix, "C:\\", now, SizeBasis::Dir)
            .unwrap();
        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3, "old baseline + newest MFT + newest Dir");
        let orphan_rows: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM dir_rollups WHERE snapshot_id NOT IN (SELECT id FROM snapshots)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphan_rows, 0, "rollup rows cascade with their snapshot");
    }

    #[test]
    fn window_is_anchored_on_latest_snapshot_not_now() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = GrowthDb::open(&dir.path().join("growth.db")).unwrap();
        let now = 2_000_000_000i64;
        let day = 86_400i64;
        let ix = make_index_with_sizes(1_000_000_000, 20_000_000, 4096);
        // Scans 10 days, 4 days, and 3 days ago; the report is opened today.
        for ts in [now - 10 * day, now - 4 * day, now - 3 * day] {
            db.record_rollup_with_basis(&ix, "C:\\", ts, SizeBasis::Mft)
                .unwrap();
        }
        let rep = db
            .compute_growth_since("C:\\", GrowthWindow::H24, now, 15)
            .unwrap();
        assert_eq!(rep.latest_at_unix, Some(now - 3 * day));
        assert_eq!(
            rep.baseline_at_unix,
            Some(now - 4 * day),
            "24h before the latest scan, not 24h before now"
        );
    }

    #[test]
    fn legacy_database_without_size_basis_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r"CREATE TABLE snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, captured_at_unix INTEGER NOT NULL, volume TEXT NOT NULL, total_alloc INTEGER NOT NULL);
                 CREATE TABLE dir_rollups (snapshot_id INTEGER NOT NULL, path TEXT NOT NULL, agg_alloc INTEGER NOT NULL, agg_count INTEGER NOT NULL, depth INTEGER NOT NULL);
                 INSERT INTO snapshots (captured_at_unix, volume, total_alloc) VALUES (1999900000, 'C:\', 100);
                 INSERT INTO dir_rollups VALUES (1, 'C:\Logs', 100, 1, 1);",
            )
            .unwrap();
        }
        let mut db = GrowthDb::open_existing(&path)
            .unwrap()
            .expect("existing db");
        let ix = make_index_with_sizes(500 * 1024 * 1024, 20_000_000, 4096);
        db.record_rollup_with_basis(&ix, "C:\\", 2_000_000_000, SizeBasis::Mft)
            .unwrap();
        let rep = db
            .compute_growth_since("C:\\", GrowthWindow::H24, 2_000_000_000, 15)
            .unwrap();
        assert!(rep.has_baseline, "legacy (NULL basis) rows stay comparable");
    }

    #[test]
    fn enforces_max_5000_rows_per_snapshot_and_supports_7d_window() {
        let vol = VolumeInfo {
            root: "D:\\".to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0xABCD,
            cluster_size: 4096,
            total_bytes: 1_000_000_000_000,
            free_bytes: 500_000_000_000,
            seek_penalty: Some(false),
        };
        let mut names = NameArena::new();
        let mut entries = Vec::with_capacity(5_200);
        for i in 0..5_200u64 {
            let n = names.push_str(&format!("dir_{i:04}"));
            entries.push(RawEntry {
                key: 100 + i,
                parent_key: 5,
                file_id: 100 + i,
                name: n,
                logical: 0,
                allocated: 0,
                mtime: 10,
                atime: 10,
                flags: NodeFlags::DIR,
                reparse_tag: 0,
            });
        }
        let mut b = IndexBuilder::new(5, "D:\\", vol);
        b.push_batch(EntryBatch { names, entries });
        let big_ix = b.finish();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cap.db");
        let mut db = GrowthDb::open(&db_path).unwrap();

        let now = 2_000_000_000i64;
        let stored_7d = db
            .record_rollup_from_index(&big_ix, "D:", now - 7 * 86_400)
            .unwrap();
        assert_eq!(stored_7d, MAX_ROWS_PER_SNAPSHOT);

        let ix_now = make_index_with_sizes(2_000_000_000, 10_000_000, 1024);
        db.record_rollup_from_index(&ix_now, "D:\\", now).unwrap();

        let rep_7d = db
            .compute_growth_since("d:/", GrowthWindow::D7, now, 10)
            .unwrap();
        assert!(rep_7d.has_baseline);
        assert_eq!(rep_7d.window, "7d");
        assert!(!rep_7d.entries.is_empty());
    }
}
