#![forbid(unsafe_code)]

//! SQLite action journal for tracking cleanup runs and individual item dispositions.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{DskError, Result};

static MANUAL_RECYCLE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A summary record of an entire cleanup execution run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRunRecord {
    pub run_id: String,
    pub started_at_unix: i64,
    pub finished_at_unix: i64,
    pub volume: String,
    pub dry_run: bool,
    pub est_bytes: u64,
    pub freed_measured: i64,
    pub items_ok: u64,
    pub items_skipped: u64,
    pub items_failed: u64,
}

/// A detailed disposition record for a single planned item or synthetic handler/command action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntryRecord {
    pub id: i64,
    pub run_id: String,
    pub rule_id: String,
    pub path: String,
    pub file_id: u64,
    pub size_bytes: u64,
    pub disposition: String,
    pub status: String,
    pub error_msg: Option<String>,
}

/// A persistent record of a cross-drive folder relocation operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationRecord {
    pub id: String,
    pub created_at_unix: i64,
    pub source_path: String,
    pub target_path: String,
    pub bytes_moved: u64,
    pub file_count: u64,
    pub status: String,
}

/// One finished video compression (P9.11). `original_disposition` is `recycled`, `held` (moved
/// into a `DiskSaver Originals` folder because it is too big for the Recycle Bin), `kept` (both
/// files kept side by side), or `none` when nothing was replaced (skipped / failed jobs).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VideoJobRecord {
    pub id: i64,
    pub finished_at_unix: i64,
    pub source_path: String,
    pub output_path: String,
    pub original_bytes: u64,
    pub new_bytes: u64,
    pub encoder: String,
    pub quality: String,
    pub vmaf: Option<f64>,
    pub status: String,
    pub original_disposition: String,
    pub held_path: Option<String>,
    pub purged: bool,
}

/// Action journal backed by SQLite.
pub struct ActionJournal {
    conn: rusqlite::Connection,
}

impl ActionJournal {
    /// Returns the default path for the journal database (`%LOCALAPPDATA%\DiskSaver\journal.db`).
    pub fn default_path() -> PathBuf {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            PathBuf::from(local_app_data)
                .join("DiskSaver")
                .join("journal.db")
        } else if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            PathBuf::from(user_profile)
                .join("AppData")
                .join("Local")
                .join("DiskSaver")
                .join("journal.db")
        } else {
            PathBuf::from(".disksaver").join("journal.db")
        }
    }

    /// Opens or creates an SQLite action journal at the specified path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }

        let conn =
            rusqlite::Connection::open(path).map_err(|e| DskError::Journal(e.to_string()))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| DskError::Journal(e.to_string()))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| DskError::Journal(e.to_string()))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| DskError::Journal(e.to_string()))?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                started_at_unix INTEGER NOT NULL,
                finished_at_unix INTEGER NOT NULL,
                volume TEXT NOT NULL,
                dry_run INTEGER NOT NULL,
                est_bytes INTEGER NOT NULL,
                freed_measured INTEGER NOT NULL,
                items_ok INTEGER NOT NULL,
                items_skipped INTEGER NOT NULL,
                items_failed INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                rule_id TEXT NOT NULL,
                path TEXT NOT NULL,
                file_id INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                disposition TEXT NOT NULL,
                status TEXT NOT NULL,
                error_msg TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_entries_run_id ON entries(run_id);

            CREATE TABLE IF NOT EXISTS relocations (
                id TEXT PRIMARY KEY,
                created_at_unix INTEGER NOT NULL,
                source_path TEXT NOT NULL,
                target_path TEXT NOT NULL,
                bytes_moved INTEGER NOT NULL,
                file_count INTEGER NOT NULL,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS calibration (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                estimated INTEGER NOT NULL,
                measured INTEGER NOT NULL,
                at_unix INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_calibration_category ON calibration(category, at_unix);

            CREATE TABLE IF NOT EXISTS wof_roots (
                path TEXT PRIMARY KEY COLLATE NOCASE,
                algorithm TEXT NOT NULL,
                added_at_unix INTEGER NOT NULL,
                last_applied_unix INTEGER NOT NULL,
                bytes_saved INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS video_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finished_at_unix INTEGER NOT NULL,
                source_path TEXT NOT NULL,
                output_path TEXT NOT NULL,
                original_bytes INTEGER NOT NULL,
                new_bytes INTEGER NOT NULL,
                encoder TEXT NOT NULL,
                quality TEXT NOT NULL,
                vmaf REAL,
                status TEXT NOT NULL,
                original_disposition TEXT NOT NULL,
                held_path TEXT,
                purged INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_video_jobs_output ON video_jobs(output_path COLLATE NOCASE);
            "#,
        )
        .map_err(|e| DskError::Journal(e.to_string()))?;

        Ok(Self { conn })
    }

    /// Opens an existing journal without creating one. Read-only consumers (the reclaim ledger,
    /// probes) use this so they never create `journal.db` as a side effect.
    pub fn open_existing(path: &Path) -> Result<Option<Self>> {
        if !path.is_file() {
            return Ok(None);
        }
        Self::open(path).map(Some)
    }

    /// Records one estimate-vs-measured observation (P9.1 calibration). Observations with a zero
    /// estimate carry no ratio information and are skipped.
    pub fn record_calibration(
        &mut self,
        category: &str,
        estimated: u64,
        measured: u64,
    ) -> Result<()> {
        if estimated == 0 {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn
            .execute(
                "INSERT INTO calibration (category, estimated, measured, at_unix) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    category,
                    estimated.min(i64::MAX as u64) as i64,
                    measured.min(i64::MAX as u64) as i64,
                    now
                ],
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }

    /// Remembers a WOF-compressed folder so updates that rewrite files uncompressed can be
    /// re-compressed later (P9.3 "keep it compressed"). Adds `bytes_saved` to the running total.
    pub fn record_wof_root(
        &mut self,
        path: &Path,
        algorithm: &str,
        bytes_saved: u64,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn
            .execute(
                "INSERT INTO wof_roots (path, algorithm, added_at_unix, last_applied_unix, bytes_saved) \
                 VALUES (?1, ?2, ?3, ?3, ?4) \
                 ON CONFLICT(path) DO UPDATE SET algorithm = excluded.algorithm, \
                 last_applied_unix = excluded.last_applied_unix, \
                 bytes_saved = wof_roots.bytes_saved + excluded.bytes_saved",
                rusqlite::params![
                    path.to_string_lossy(),
                    algorithm,
                    now,
                    bytes_saved.min(i64::MAX as u64) as i64
                ],
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }

    /// Records one video compression job (P9.11) and returns its row id.
    pub fn record_video_job(&mut self, rec: &VideoJobRecord) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO video_jobs (finished_at_unix, source_path, output_path, original_bytes, \
                 new_bytes, encoder, quality, vmaf, status, original_disposition, held_path, purged) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    rec.finished_at_unix,
                    rec.source_path,
                    rec.output_path,
                    rec.original_bytes.min(i64::MAX as u64) as i64,
                    rec.new_bytes.min(i64::MAX as u64) as i64,
                    rec.encoder,
                    rec.quality,
                    rec.vmaf,
                    rec.status,
                    rec.original_disposition,
                    rec.held_path,
                    rec.purged as i64,
                ],
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(self.conn.last_insert_rowid())
    }

    fn query_video_jobs(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<VideoJobRecord>> {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| DskError::Journal(e.to_string()))?;
        let rows = stmt
            .query_map(params, |r| {
                Ok(VideoJobRecord {
                    id: r.get(0)?,
                    finished_at_unix: r.get(1)?,
                    source_path: r.get(2)?,
                    output_path: r.get(3)?,
                    original_bytes: r.get::<_, i64>(4)?.max(0) as u64,
                    new_bytes: r.get::<_, i64>(5)?.max(0) as u64,
                    encoder: r.get(6)?,
                    quality: r.get(7)?,
                    vmaf: r.get(8)?,
                    status: r.get(9)?,
                    original_disposition: r.get(10)?,
                    held_path: r.get(11)?,
                    purged: r.get::<_, i64>(12)? != 0,
                })
            })
            .map_err(|e| DskError::Journal(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| DskError::Journal(e.to_string()))
    }

    const VIDEO_COLUMNS: &'static str = "id, finished_at_unix, source_path, output_path, original_bytes, \
        new_bytes, encoder, quality, vmaf, status, original_disposition, held_path, purged";

    /// Most recent video jobs first.
    pub fn list_video_jobs(&self, limit: usize) -> Result<Vec<VideoJobRecord>> {
        let sql = format!(
            "SELECT {} FROM video_jobs ORDER BY id DESC LIMIT ?1",
            Self::VIDEO_COLUMNS
        );
        self.query_video_jobs(&sql, &[&(limit.min(i64::MAX as usize) as i64)])
    }

    /// Originals parked in a `DiskSaver Originals` folder that have not been purged yet.
    pub fn held_video_originals(&self) -> Result<Vec<VideoJobRecord>> {
        let sql = format!(
            "SELECT {} FROM video_jobs WHERE original_disposition = 'held' AND purged = 0 \
             AND held_path IS NOT NULL ORDER BY id",
            Self::VIDEO_COLUMNS
        );
        self.query_video_jobs(&sql, &[])
    }

    /// The latest replacement job that produced `output_path`, if any (so a compressed file is
    /// never offered for compression again).
    pub fn video_job_for_output(&self, output_path: &Path) -> Result<Option<VideoJobRecord>> {
        let sql = format!(
            "SELECT {} FROM video_jobs WHERE output_path = ?1 COLLATE NOCASE \
             AND status = 'replaced' ORDER BY id DESC LIMIT 1",
            Self::VIDEO_COLUMNS
        );
        let p = output_path.to_string_lossy().into_owned();
        Ok(self.query_video_jobs(&sql, &[&p])?.into_iter().next())
    }

    /// Marks a held original as permanently deleted.
    pub fn mark_video_original_purged(&mut self, id: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE video_jobs SET purged = 1 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }

    /// Forgets a WOF root (after undo).
    pub fn remove_wof_root(&mut self, path: &Path) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM wof_roots WHERE path = ?1",
                rusqlite::params![path.to_string_lossy()],
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }

    /// Recorded WOF roots as `(path, algorithm, last_applied_unix, bytes_saved)`.
    pub fn list_wof_roots(&self) -> Result<Vec<(PathBuf, String, i64, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, algorithm, last_applied_unix, bytes_saved FROM wof_roots ORDER BY path")
            .map_err(|e| DskError::Journal(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    PathBuf::from(r.get::<_, String>(0)?),
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?.max(0) as u64,
                ))
            })
            .map_err(|e| DskError::Journal(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| DskError::Journal(e.to_string()))
    }

    /// Rolling measured/estimated ratio over the last `window` observations of `category`, or
    /// `None` with fewer than 3 observations. Clamped to `[0.05, 2.0]` so one outlier run cannot
    /// zero out or double every estimate.
    pub fn calibration_ratio(&self, category: &str, window: usize) -> Result<Option<f64>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT estimated, measured FROM calibration WHERE category = ?1 \
                 ORDER BY at_unix DESC, id DESC LIMIT ?2",
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![category, window as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(|e| DskError::Journal(e.to_string()))?;
        let mut est_sum = 0i128;
        let mut meas_sum = 0i128;
        let mut n = 0usize;
        for row in rows {
            let (e, m) = row.map_err(|e| DskError::Journal(e.to_string()))?;
            est_sum += i128::from(e.max(0));
            meas_sum += i128::from(m.max(0));
            n += 1;
        }
        if n < 3 || est_sum <= 0 {
            return Ok(None);
        }
        Ok(Some((meas_sum as f64 / est_sum as f64).clamp(0.05, 2.0)))
    }

    /// Records a cleanup run and all associated item entries atomically in a single SQLite transaction.
    pub fn record_run(
        &mut self,
        run: &JournalRunRecord,
        entries: &[JournalEntryRecord],
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| DskError::Journal(e.to_string()))?;

        tx.execute(
            r#"
            INSERT INTO runs (
                run_id, started_at_unix, finished_at_unix, volume, dry_run,
                est_bytes, freed_measured, items_ok, items_skipped, items_failed
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            rusqlite::params![
                &run.run_id,
                run.started_at_unix,
                run.finished_at_unix,
                &run.volume,
                run.dry_run as i32,
                run.est_bytes as i64,
                run.freed_measured,
                run.items_ok as i64,
                run.items_skipped as i64,
                run.items_failed as i64,
            ],
        )
        .map_err(|e| DskError::Journal(e.to_string()))?;

        {
            let mut stmt = tx
                .prepare(
                    r#"
                    INSERT INTO entries (
                        run_id, rule_id, path, file_id, size_bytes, disposition, status, error_msg
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    "#,
                )
                .map_err(|e| DskError::Journal(e.to_string()))?;

            for e in entries {
                stmt.execute(rusqlite::params![
                    &e.run_id,
                    &e.rule_id,
                    &e.path,
                    e.file_id as i64,
                    e.size_bytes as i64,
                    &e.disposition,
                    &e.status,
                    &e.error_msg,
                ])
                .map_err(|err| DskError::Journal(err.to_string()))?;
            }
        }

        tx.commit().map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }

    /// Lists past cleanup runs ordered newest first, up to `limit` entries.
    pub fn list_runs(&self, limit: usize) -> Result<Vec<JournalRunRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT run_id, started_at_unix, finished_at_unix, volume, dry_run,
                       est_bytes, freed_measured, items_ok, items_skipped, items_failed
                FROM runs
                ORDER BY started_at_unix DESC, rowid DESC
                LIMIT ?1
                "#,
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |row| {
                Ok(JournalRunRecord {
                    run_id: row.get(0)?,
                    started_at_unix: row.get(1)?,
                    finished_at_unix: row.get(2)?,
                    volume: row.get(3)?,
                    dry_run: row.get::<_, i32>(4)? != 0,
                    est_bytes: row.get::<_, i64>(5)? as u64,
                    freed_measured: row.get(6)?,
                    items_ok: row.get::<_, i64>(7)? as u64,
                    items_skipped: row.get::<_, i64>(8)? as u64,
                    items_failed: row.get::<_, i64>(9)? as u64,
                })
            })
            .map_err(|e| DskError::Journal(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| DskError::Journal(e.to_string()))?);
        }
        Ok(out)
    }

    /// Retrieves all item entries recorded for a given run ID, ordered by entry ID ascending.
    pub fn get_run_entries(&self, run_id: &str) -> Result<Vec<JournalEntryRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT id, run_id, rule_id, path, file_id, size_bytes, disposition, status, error_msg
                FROM entries
                WHERE run_id = ?1
                ORDER BY id ASC
                "#,
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![run_id], |row| {
                Ok(JournalEntryRecord {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    rule_id: row.get(2)?,
                    path: row.get(3)?,
                    file_id: row.get::<_, i64>(4)? as u64,
                    size_bytes: row.get::<_, i64>(5)? as u64,
                    disposition: row.get(6)?,
                    status: row.get(7)?,
                    error_msg: row.get(8)?,
                })
            })
            .map_err(|e| DskError::Journal(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| DskError::Journal(e.to_string()))?);
        }
        Ok(out)
    }

    /// Records a manual Recycle Bin disposition for an individual file/folder.
    ///
    /// Generates a collision-resistant `run_id` combining unix millisecond timestamp, process ID,
    /// and monotonic atomic counter, and atomically records a single run and entry in SQLite.
    pub fn record_manual_recycle(
        &mut self,
        volume: &str,
        canonical_path: &str,
        bytes_hint: u64,
        freed_measured: i64,
    ) -> Result<String> {
        let now = std::time::SystemTime::now();
        let ms = match now.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => 0,
        };
        let pid = std::process::id();
        let seq = MANUAL_RECYCLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let run_id = format!("recycle-{ms}-{pid}-{seq}");
        let now_secs = (ms / 1000) as i64;

        let run = JournalRunRecord {
            run_id: run_id.clone(),
            started_at_unix: now_secs,
            finished_at_unix: now_secs,
            volume: volume.to_string(),
            dry_run: false,
            est_bytes: bytes_hint,
            freed_measured,
            items_ok: 1,
            items_skipped: 0,
            items_failed: 0,
        };

        let entry = JournalEntryRecord {
            id: 0,
            run_id: run_id.clone(),
            rule_id: "explore.recycle_bin".to_string(),
            path: canonical_path.to_string(),
            file_id: 0,
            size_bytes: bytes_hint,
            disposition: "recycle_bin".to_string(),
            status: "recycled".to_string(),
            error_msg: None,
        };

        self.record_run(&run, &[entry])?;
        Ok(run_id)
    }

    /// Records a cross-drive folder relocation in the audit journal.
    pub fn record_relocation(&mut self, rec: &RelocationRecord) -> Result<()> {
        self.conn
            .execute(
                r#"
                INSERT INTO relocations (id, created_at_unix, source_path, target_path, bytes_moved, file_count, status)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(id) DO UPDATE SET status = excluded.status
                "#,
                rusqlite::params![
                    &rec.id,
                    rec.created_at_unix,
                    &rec.source_path,
                    &rec.target_path,
                    rec.bytes_moved as i64,
                    rec.file_count as i64,
                    &rec.status,
                ],
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }

    /// Lists all active (not restored) cross-drive folder relocations.
    pub fn list_active_relocations(&self) -> Result<Vec<RelocationRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT id, created_at_unix, source_path, target_path, bytes_moved, file_count, status
                FROM relocations
                WHERE status = 'active'
                ORDER BY created_at_unix DESC
                "#,
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(RelocationRecord {
                    id: row.get(0)?,
                    created_at_unix: row.get(1)?,
                    source_path: row.get(2)?,
                    target_path: row.get(3)?,
                    bytes_moved: row.get::<_, i64>(4)? as u64,
                    file_count: row.get::<_, i64>(5)? as u64,
                    status: row.get(6)?,
                })
            })
            .map_err(|e| DskError::Journal(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| DskError::Journal(e.to_string()))?);
        }
        Ok(out)
    }

    /// Marks a relocation record as restored after undo.
    pub fn mark_relocation_restored(&mut self, relocation_id: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE relocations SET status = 'restored' WHERE id = ?1",
                rusqlite::params![relocation_id],
            )
            .map_err(|e| DskError::Journal(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn journal_roundtrip_single_transaction_handles_5000_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("test_journal.db");

        let mut journal = ActionJournal::open(&db_path).expect("open journal");

        let run = JournalRunRecord {
            run_id: "run-bench-001".to_string(),
            started_at_unix: 1700000000,
            finished_at_unix: 1700000005,
            volume: r"C:\".to_string(),
            dry_run: false,
            est_bytes: 50_000_000,
            freed_measured: 48_000_000,
            items_ok: 5000,
            items_skipped: 0,
            items_failed: 0,
        };

        let mut entries = Vec::with_capacity(5000);
        for i in 0..5000 {
            entries.push(JournalEntryRecord {
                id: 0,
                run_id: run.run_id.clone(),
                rule_id: "dev.cargo.cache".to_string(),
                path: format!(r"C:\Users\Alice\.cargo\registry\cache\pkg_{i}.crate"),
                file_id: 1000 + i as u64,
                size_bytes: 10_000,
                disposition: "delete_contents".to_string(),
                status: "deleted".to_string(),
                error_msg: None,
            });
        }

        let start = Instant::now();
        journal
            .record_run(&run, &entries)
            .expect("record 5000 entries");
        let duration = start.elapsed();

        assert!(
            duration.as_millis() < 500,
            "5000 entries must be recorded in << 500ms, took {:?}",
            duration
        );

        let runs = journal.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0], run);

        let retrieved = journal.get_run_entries(&run.run_id).expect("get entries");
        assert_eq!(retrieved.len(), 5000);
        assert_eq!(retrieved[0].run_id, run.run_id);
        assert_eq!(retrieved[0].path, entries[0].path);
        assert_eq!(retrieved[4999].path, entries[4999].path);
    }

    #[test]
    fn deterministic_ordering_with_same_timestamp() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("order_journal.db");
        let mut journal = ActionJournal::open(&db_path).expect("open journal");

        let run1 = JournalRunRecord {
            run_id: "run-1".to_string(),
            started_at_unix: 1700000000,
            finished_at_unix: 1700000001,
            volume: r"C:\".to_string(),
            dry_run: false,
            est_bytes: 100,
            freed_measured: 100,
            items_ok: 1,
            items_skipped: 0,
            items_failed: 0,
        };
        let run2 = JournalRunRecord {
            run_id: "run-2".to_string(),
            started_at_unix: 1700000000,
            finished_at_unix: 1700000001,
            volume: r"C:\".to_string(),
            dry_run: false,
            est_bytes: 200,
            freed_measured: 200,
            items_ok: 1,
            items_skipped: 0,
            items_failed: 0,
        };

        journal.record_run(&run1, &[]).expect("record 1");
        journal.record_run(&run2, &[]).expect("record 2");

        let list = journal.list_runs(10).expect("list");
        assert_eq!(list.len(), 2);
        assert_eq!(
            list[0].run_id, "run-2",
            "newer rowid must come first when timestamps match"
        );
        assert_eq!(list[1].run_id, "run-1");
    }

    #[test]
    fn handles_bare_memory_path() {
        let mut journal = ActionJournal::open(Path::new(":memory:")).expect("open :memory:");
        let run = JournalRunRecord {
            run_id: "mem-run".to_string(),
            started_at_unix: 100,
            finished_at_unix: 101,
            volume: r"C:\".to_string(),
            dry_run: true,
            est_bytes: 0,
            freed_measured: 0,
            items_ok: 0,
            items_skipped: 0,
            items_failed: 0,
        };
        journal.record_run(&run, &[]).expect("record in memory");
        let runs = journal.list_runs(5).expect("list");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, "mem-run");
    }

    #[test]
    fn record_manual_recycle_persists_run_and_entry_in_temp_journal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("recycle_journal.db");
        let mut journal = ActionJournal::open(&db_path).expect("open journal");

        let run_id = journal
            .record_manual_recycle(
                r"C:\",
                r"C:\Users\Alice\large_video.mkv",
                100_000_000,
                100_000_000,
            )
            .expect("record manual recycle");

        assert!(
            run_id.starts_with("recycle-"),
            "run_id must start with recycle-, got {run_id}"
        );

        let runs = journal.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        assert_eq!(run.run_id, run_id);
        assert_eq!(run.volume, r"C:\");
        assert!(!run.dry_run);
        assert_eq!(run.est_bytes, 100_000_000);
        assert_eq!(run.freed_measured, 100_000_000);
        assert_eq!(run.items_ok, 1);
        assert_eq!(run.items_skipped, 0);
        assert_eq!(run.items_failed, 0);

        let entries = journal.get_run_entries(&run_id).expect("get entries");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.run_id, run_id);
        assert_eq!(entry.rule_id, "explore.recycle_bin");
        assert_eq!(entry.path, r"C:\Users\Alice\large_video.mkv");
        assert_eq!(entry.size_bytes, 100_000_000);
        assert_eq!(entry.disposition, "recycle_bin");
        assert_eq!(entry.status, "recycled");
        assert_eq!(entry.error_msg, None);

        // Rapid second recycle to verify unique run_id without primary key collision
        let run_id2 = journal
            .record_manual_recycle(r"C:\", r"C:\Users\Alice\other.zip", 50_000, 50_000)
            .expect("record 2nd manual recycle");
        assert_ne!(run_id, run_id2);
        let runs2 = journal.list_runs(10).expect("list runs");
        assert_eq!(runs2.len(), 2);
    }

    #[test]
    fn relocation_lifecycle_record_list_and_undo_in_temp_journal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("test_journal.db");
        let mut journal = ActionJournal::open(&db_path).expect("open journal");

        let rec = RelocationRecord {
            id: "reloc-test-001".to_string(),
            created_at_unix: 1700000100,
            source_path: r"C:\Users\Alice\Games".to_string(),
            target_path: r"D:\Relocated\Games".to_string(),
            bytes_moved: 10_000_000_000,
            file_count: 500,
            status: "active".to_string(),
        };

        journal.record_relocation(&rec).expect("record relocation");

        let active = journal.list_active_relocations().expect("list active");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "reloc-test-001");
        assert_eq!(active[0].bytes_moved, 10_000_000_000);

        journal
            .mark_relocation_restored("reloc-test-001")
            .expect("mark restored");
        let active_after = journal
            .list_active_relocations()
            .expect("list active after");
        assert_eq!(active_after.len(), 0);
    }

    #[test]
    fn calibration_and_wof_roots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.db");
        assert!(
            ActionJournal::open_existing(&path).unwrap().is_none(),
            "never created"
        );
        let mut j = ActionJournal::open(&path).unwrap();

        assert_eq!(j.calibration_ratio("clean", 20).unwrap(), None);
        j.record_calibration("clean", 0, 5).unwrap(); // ignored: no estimate
        for (e, m) in [(100u64, 80u64), (200, 160), (100, 90)] {
            j.record_calibration("clean", e, m).unwrap();
        }
        let r = j.calibration_ratio("clean", 20).unwrap().unwrap();
        assert!((r - 330.0 / 400.0).abs() < 1e-9, "{r}");
        // Clamped against outliers.
        for _ in 0..3 {
            j.record_calibration("wof", 100, 10_000).unwrap();
        }
        assert_eq!(j.calibration_ratio("wof", 20).unwrap(), Some(2.0));

        let p = Path::new(r"C:\Program Files\JetBrains");
        j.record_wof_root(p, "LZX", 1000).unwrap();
        j.record_wof_root(Path::new(r"c:\program files\jetbrains"), "LZX", 500)
            .unwrap();
        let roots = j.list_wof_roots().unwrap();
        assert_eq!(roots.len(), 1, "paths compare case-insensitively");
        assert_eq!(roots[0].3, 1500);
        j.remove_wof_root(p).unwrap();
        assert!(j.list_wof_roots().unwrap().is_empty());
    }
}
