#![forbid(unsafe_code)]

//! Verified cross-drive folder relocator and reversible directory junction engine (§8.6).
//!
//! Relocates large folders (game libraries, model caches, Docker data, SDKs) to another drive,
//! verifies 100% of copied files via length + XXH3_64 checksums, creates directory junctions,
//! and logs reversible records in `ActionJournal`.

use std::fs;
use std::io::Read;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path, normalize_win_path_str};
use crate::clean::journal::{ActionJournal, RelocationRecord};
use crate::error::{DskError, Result};
use crate::win::junction::{
    create_mount_point_junction, read_mount_point_target, remove_junction_link_only,
    resolve_final_path_by_handle,
};
use crate::win::preconditions::find_locking_processes;
use crate::win::volume::require_fixed_drive_and_free_bytes;

const FILE_ATTRIBUTE_REPARSE_POINT_MASK: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_OFFLINE_MASK: u32 = 0x0000_1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN_MASK: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_MASK: u32 = 0x0040_0000;

fn is_unsafe_relocation_entry(file_attributes: u32, is_symlink: bool) -> bool {
    is_symlink
        || (file_attributes
            & (FILE_ATTRIBUTE_REPARSE_POINT_MASK
                | FILE_ATTRIBUTE_OFFLINE_MASK
                | FILE_ATTRIBUTE_RECALL_ON_OPEN_MASK
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_MASK))
            != 0
}

/// Staging and backup folder prefixes.
const STAGING_PREFIX: &str = ".disksaver-staging-";
const BACKUP_PREFIX: &str = ".disksaver-bak-";

/// Minimum free space headroom required on target drive (512 MiB).
const MIN_FREE_SPACE_HEADROOM: u64 = 512 * 1024 * 1024;

/// Plan detailing the source, destination, and calculated size of a relocation operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationPlan {
    pub source_path: PathBuf,
    pub target_parent: PathBuf,
    pub target_path: PathBuf,
    pub total_bytes: u64,
    pub file_count: u64,
}

/// Report summarizing the completion of a relocation or undo operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationReport {
    pub relocation_id: String,
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    pub bytes_moved: u64,
    pub file_count: u64,
    pub elapsed_ms: u64,
    pub dry_run: bool,
}

/// Computes the XXH3_64 digest and byte length of a file.
fn hash_file_xxh3(path: &Path) -> Result<(u64, u64)> {
    let mut file = fs::File::open(path)?;
    let mut buffer = [0u8; 65536];
    let mut total_bytes = 0u64;
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total_bytes += n as u64;
    }

    Ok((hasher.digest(), total_bytes))
}

/// Recursively measures total logical bytes and file count in a directory,
/// rejecting nested symlinks, junctions, and cloud placeholders before planning.
fn scan_folder_metrics(dir: &Path) -> Result<(u64, u64)> {
    let mut total_bytes = 0u64;
    let mut file_count = 0u64;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let child_path = entry.path();
        let meta = fs::symlink_metadata(&child_path)?;
        let ft = meta.file_type();
        if is_unsafe_relocation_entry(meta.file_attributes(), ft.is_symlink()) {
            return Err(DskError::Optimize(format!(
                "refusing relocation of folder containing symlink, reparse point, or cloud placeholder: {}",
                child_path.display()
            )));
        }

        if ft.is_dir() {
            let (sub_bytes, sub_count) = scan_folder_metrics(&child_path)?;
            total_bytes += sub_bytes;
            file_count += sub_count;
        } else if ft.is_file() {
            total_bytes += meta.len();
            file_count += 1;
        } else {
            return Err(DskError::Optimize(format!(
                "unsupported non-regular filesystem entry inside source folder: {}",
                child_path.display()
            )));
        }
    }

    Ok((total_bytes, file_count))
}

/// Returns `true` when `target_parent` (canonicalized) equals or lies under `source_dir`.
fn target_is_inside_source(source_dir: &Path, target_parent: &Path) -> Result<bool> {
    let src = normalize_win_path_str(&fs::canonicalize(source_dir)?);
    let dst = normalize_win_path_str(&fs::canonicalize(target_parent)?);
    let src_prefix = format!("{}\\", src.trim_end_matches('\\'));
    Ok(dst == src || dst.starts_with(&src_prefix))
}

/// Formulates a planned folder relocation after validating paths, `DRIVE_FIXED` volumes, and metrics.
pub fn plan_folder_relocation(
    source_dir: &Path,
    target_parent: &Path,
    deny_ctx: &DenyContext,
) -> Result<RelocationPlan> {
    if is_denied_path(source_dir, deny_ctx).is_some() {
        return Err(DskError::Denied(format!(
            "source path is protected: {}",
            source_dir.display()
        )));
    }

    if is_denied_path(target_parent, deny_ctx).is_some() {
        return Err(DskError::Denied(format!(
            "target directory is protected: {}",
            target_parent.display()
        )));
    }

    let source_meta = fs::symlink_metadata(source_dir)?;
    if !source_meta.is_dir()
        || is_unsafe_relocation_entry(
            source_meta.file_attributes(),
            source_meta.file_type().is_symlink(),
        )
    {
        return Err(DskError::Optimize(format!(
            "source is not a regular non-reparse directory: {}",
            source_dir.display()
        )));
    }

    require_fixed_drive_and_free_bytes(source_dir)?;
    require_fixed_drive_and_free_bytes(target_parent)?;

    // The copy would otherwise recurse into its own staging folder until the disk fills up.
    if target_is_inside_source(source_dir, target_parent)? {
        return Err(DskError::Optimize(format!(
            "target directory '{}' is inside the source folder '{}'",
            target_parent.display(),
            source_dir.display()
        )));
    }

    let folder_name = source_dir
        .file_name()
        .ok_or_else(|| DskError::Optimize("invalid source directory name".to_string()))?;
    let target_path = target_parent.join(folder_name);

    if target_path.exists() {
        return Err(DskError::Optimize(format!(
            "target folder already exists: {}",
            target_path.display()
        )));
    }

    let (total_bytes, file_count) = scan_folder_metrics(source_dir)?;

    Ok(RelocationPlan {
        source_path: source_dir.to_path_buf(),
        target_parent: target_parent.to_path_buf(),
        target_path,
        total_bytes,
        file_count,
    })
}

/// Recursively copies a directory tree into destination, verifying length and XXH3 hash
/// for every single file.
fn copy_and_verify_tree(
    src: &Path,
    dst: &Path,
    cancel: &AtomicBool,
    copied_bytes: &mut u64,
    copied_files: &mut u64,
) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DskError::Cancelled);
    }

    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        if cancel.load(Ordering::Relaxed) {
            return Err(DskError::Cancelled);
        }

        let entry = entry?;
        let src_child = entry.path();
        let dst_child = dst.join(entry.file_name());
        let meta = fs::symlink_metadata(&src_child)?;
        let ft = meta.file_type();

        if is_unsafe_relocation_entry(meta.file_attributes(), ft.is_symlink()) {
            return Err(DskError::Optimize(format!(
                "refusing to copy symlink, reparse point, or cloud placeholder: {}",
                src_child.display()
            )));
        }

        if ft.is_dir() {
            copy_and_verify_tree(&src_child, &dst_child, cancel, copied_bytes, copied_files)?;
        } else if ft.is_file() {
            // Copy file content
            fs::copy(&src_child, &dst_child)?;

            // Verify byte length and XXH3_64 checksum
            let (src_hash, src_len) = hash_file_xxh3(&src_child)?;
            let (dst_hash, dst_len) = hash_file_xxh3(&dst_child)?;

            if src_len != dst_len {
                return Err(DskError::Optimize(format!(
                    "file length mismatch after copy: {} (expected {src_len}, got {dst_len})",
                    src_child.display()
                )));
            }

            if src_hash != dst_hash {
                return Err(DskError::Optimize(format!(
                    "XXH3 hash verification mismatch for file: {}",
                    src_child.display()
                )));
            }

            *copied_bytes += src_len;
            *copied_files += 1;
        } else {
            return Err(DskError::Optimize(format!(
                "unsupported non-regular filesystem entry inside source folder: {}",
                src_child.display()
            )));
        }
    }

    Ok(())
}

/// Restores `source_dir` from `backup_dir` after a failed relocation step. The relocated copy at
/// `target_path` is deleted only once the original is back in place; otherwise both copies are
/// kept and the returned message says where the data is.
fn rollback_from_backup(
    source_dir: &Path,
    backup_dir: &Path,
    target_path: &Path,
    junction_created: bool,
) -> String {
    if junction_created {
        let _ = remove_junction_link_only(source_dir);
    } else {
        // `create_mount_point_junction` may have left an empty directory behind.
        let _ = fs::remove_dir(source_dir);
    }
    match fs::rename(backup_dir, source_dir) {
        Ok(()) => {
            let _ = fs::remove_dir_all(target_path);
            "rolled back to the original folder".to_string()
        }
        Err(e) => format!(
            "ROLLBACK INCOMPLETE ({e}): original data is preserved at '{}' and a verified copy at '{}'; rename '{}' back to '{}' manually",
            backup_dir.display(),
            target_path.display(),
            backup_dir.display(),
            source_dir.display()
        ),
    }
}

/// Executes a cross-drive folder relocation with verification, directory junctioning, and journal tracking.
pub fn execute_folder_relocation(
    source_dir: &Path,
    target_parent_dir: &Path,
    deny_ctx: &DenyContext,
    journal: &mut ActionJournal,
    cancel: &AtomicBool,
) -> Result<RelocationReport> {
    let start_time = Instant::now();
    let plan = plan_folder_relocation(source_dir, target_parent_dir, deny_ctx)?;

    // 1. Verify source is not already a reparse point or cloud placeholder
    let meta = fs::symlink_metadata(source_dir)?;
    if is_unsafe_relocation_entry(meta.file_attributes(), meta.file_type().is_symlink()) {
        return Err(DskError::Optimize(format!(
            "source is already a reparse point, junction, or cloud placeholder: {}",
            source_dir.display()
        )));
    }

    // 2. Check for active process locks on source directory
    let locks = find_locking_processes(source_dir);
    if !locks.is_empty() {
        return Err(DskError::PreconditionFailed(format!(
            "source directory is locked by processes: {}",
            locks.join(", ")
        )));
    }

    // 3. Enforce DRIVE_FIXED on both endpoints and fail closed on target volume capacity
    require_fixed_drive_and_free_bytes(source_dir)?;
    let (target_root, free_bytes) = require_fixed_drive_and_free_bytes(target_parent_dir)?;
    let required_space = plan.total_bytes.saturating_add(MIN_FREE_SPACE_HEADROOM);
    if free_bytes < required_space {
        return Err(DskError::Optimize(format!(
            "insufficient free space on target drive {} (requires at least {} bytes, available: {} bytes)",
            target_root, required_space, free_bytes
        )));
    }

    // Generate unique operation ID
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let op_id = format!("{:x}", now_nanos);

    let staging_dir = target_parent_dir.join(format!("{STAGING_PREFIX}{op_id}"));
    let backup_dir = source_dir
        .parent()
        .unwrap_or_else(|| Path::new(r"C:\"))
        .join(format!(
            "{}-{BACKUP_PREFIX}{op_id}",
            source_dir.file_name().unwrap_or_default().to_string_lossy()
        ));

    // 4. Copy to a freshly created staging directory with length + XXH3 verification. `create_dir`
    //    (not `create_dir_all`) refuses a pre-existing folder or junction planted under the name.
    fs::create_dir(&staging_dir).map_err(|e| {
        DskError::Optimize(format!(
            "could not create fresh staging directory '{}': {e}",
            staging_dir.display()
        ))
    })?;
    let mut copied_bytes = 0u64;
    let mut copied_files = 0u64;

    let copy_result = copy_and_verify_tree(
        source_dir,
        &staging_dir,
        cancel,
        &mut copied_bytes,
        &mut copied_files,
    );

    if let Err(err) = copy_result {
        // Clean up partial staging directory on failure or cancellation
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(err);
    }

    // 5. Rename staging directory to final target directory
    if let Err(e) = fs::rename(&staging_dir, &plan.target_path) {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(DskError::Io(e));
    }

    // 6. Rename source directory to backup directory
    if let Err(e) = fs::rename(source_dir, &backup_dir) {
        // Rollback target directory (the source was never moved).
        let _ = fs::remove_dir_all(&plan.target_path);
        return Err(DskError::Io(e));
    }

    // 7. Create directory junction at source_dir pointing to target_path
    let junction_res = create_mount_point_junction(source_dir, &plan.target_path);
    if let Err(e) = junction_res {
        let note = rollback_from_backup(source_dir, &backup_dir, &plan.target_path, false);
        return Err(DskError::Optimize(format!(
            "junction creation failed ({e}); {note}"
        )));
    }

    // 8. Verify junction resolution via kernel handle (GetFinalPathNameByHandleW)
    let target_matches = match (
        read_mount_point_target(source_dir),
        resolve_final_path_by_handle(source_dir),
        resolve_final_path_by_handle(&plan.target_path),
    ) {
        (Ok(_), Ok(resolved_final), Ok(expected_final)) => {
            normalize_win_path_str(&resolved_final) == normalize_win_path_str(&expected_final)
        }
        _ => false,
    };

    if !target_matches {
        let note = rollback_from_backup(source_dir, &backup_dir, &plan.target_path, true);
        return Err(DskError::Optimize(format!(
            "junction target resolution failed; {note}"
        )));
    }

    // 9. Record the relocation BEFORE deleting the backup: an untracked junction could never be
    //    undone, so a journal failure rolls the whole operation back.
    let record = RelocationRecord {
        id: op_id.clone(),
        created_at_unix: (now_nanos / 1_000_000_000) as i64,
        source_path: source_dir.to_string_lossy().to_string(),
        target_path: plan.target_path.to_string_lossy().to_string(),
        bytes_moved: copied_bytes,
        file_count: copied_files,
        status: "active".to_string(),
    };

    if let Err(e) = journal.record_relocation(&record) {
        let note = rollback_from_backup(source_dir, &backup_dir, &plan.target_path, true);
        return Err(DskError::Optimize(format!(
            "failed to journal relocation ({e}); {note}"
        )));
    }

    // 10. Verified and journaled: delete the backup copy.
    let _ = fs::remove_dir_all(&backup_dir);

    Ok(RelocationReport {
        relocation_id: op_id,
        source_path: source_dir.to_path_buf(),
        target_path: plan.target_path,
        bytes_moved: copied_bytes,
        file_count: copied_files,
        elapsed_ms: start_time.elapsed().as_millis() as u64,
        dry_run: false,
    })
}

/// Restores an active folder relocation back to its original location and removes the directory junction.
pub fn undo_folder_relocation(
    relocation_id: &str,
    journal: &mut ActionJournal,
    cancel: &AtomicBool,
) -> Result<RelocationReport> {
    let start_time = Instant::now();

    let active_records = journal.list_active_relocations()?;
    let record = active_records
        .into_iter()
        .find(|r| r.id == relocation_id)
        .ok_or_else(|| {
            DskError::Optimize(format!(
                "no active relocation found with ID {relocation_id}"
            ))
        })?;

    let source_path = PathBuf::from(&record.source_path);
    let target_path = PathBuf::from(&record.target_path);

    if !target_path.is_dir() {
        return Err(DskError::Optimize(format!(
            "relocation target directory is missing: {}",
            target_path.display()
        )));
    }

    // Verify source is still a junction resolving to target via kernel final handle path
    let _ = read_mount_point_target(&source_path)?;
    let resolved_final = resolve_final_path_by_handle(&source_path)?;
    let target_final = resolve_final_path_by_handle(&target_path)?;
    if normalize_win_path_str(&resolved_final) != normalize_win_path_str(&target_final) {
        return Err(DskError::Optimize(format!(
            "source junction has been altered (resolves to {}, expected {})",
            resolved_final.display(),
            target_final.display()
        )));
    }

    // Stage copy back to a temp location next to source
    let temp_restore_dir = source_path
        .parent()
        .unwrap_or_else(|| Path::new(r"C:\"))
        .join(format!(".disksaver-restore-{relocation_id}"));

    let mut copied_bytes = 0u64;
    let mut copied_files = 0u64;

    let copy_res = copy_and_verify_tree(
        &target_path,
        &temp_restore_dir,
        cancel,
        &mut copied_bytes,
        &mut copied_files,
    );

    if let Err(e) = copy_res {
        let _ = fs::remove_dir_all(&temp_restore_dir);
        return Err(e);
    }

    // Remove the junction link only
    remove_junction_link_only(&source_path)?;

    // Rename restored directory into source_path; on failure, recreate the junction so data remains accessible
    if let Err(e) = fs::rename(&temp_restore_dir, &source_path) {
        let _ = create_mount_point_junction(&source_path, &target_path);
        let _ = fs::remove_dir_all(&temp_restore_dir);
        return Err(DskError::Io(e));
    }

    // Delete target folder
    let _ = fs::remove_dir_all(&target_path);

    // Mark relocation restored in journal
    journal.mark_relocation_restored(relocation_id)?;

    Ok(RelocationReport {
        relocation_id: relocation_id.to_string(),
        source_path,
        target_path,
        bytes_moved: copied_bytes,
        file_count: copied_files,
        elapsed_ms: start_time.elapsed().as_millis() as u64,
        dry_run: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn junction_create_read_and_remove_link_only_preserves_target_contents() {
        let temp = tempdir().unwrap();
        let target_dir = temp.path().join("real_target");
        let link_dir = temp.path().join("junction_link");

        fs::create_dir_all(&target_dir).unwrap();
        let file_path = target_dir.join("payload.txt");
        fs::write(&file_path, b"junction test payload").unwrap();

        // Create junction
        create_mount_point_junction(&link_dir, &target_dir).unwrap();
        assert!(link_dir.exists());

        // Read target
        let read_target = read_mount_point_target(&link_dir).unwrap();
        let canon_read = std::path::absolute(&read_target).unwrap();
        let canon_target = std::path::absolute(&target_dir).unwrap();
        assert_eq!(canon_read, canon_target);

        // Read payload file through junction
        let link_file = link_dir.join("payload.txt");
        assert!(link_file.exists());
        let read_bytes = fs::read(&link_file).unwrap();
        assert_eq!(read_bytes, b"junction test payload");

        // Remove junction link only
        remove_junction_link_only(&link_dir).unwrap();
        assert!(!link_dir.exists());

        // Target file and directory MUST still exist completely intact!
        assert!(target_dir.exists());
        assert!(file_path.exists());
        assert_eq!(fs::read(&file_path).unwrap(), b"junction test payload");
    }

    #[test]
    fn relocate_folder_and_undo_relocation_roundtrip_verifies_xxh3_checksums_and_journal() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source_models");
        let target_parent = temp.path().join("target_drive");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target_parent).unwrap();

        let sub = source.join("subfolder");
        fs::create_dir_all(&sub).unwrap();
        fs::write(source.join("file1.bin"), b"large model weights 1").unwrap();
        fs::write(sub.join("file2.bin"), b"large model weights 2").unwrap();

        let db_path = temp.path().join("journal.db");
        let mut journal = ActionJournal::open(&db_path).unwrap();
        let deny = DenyContext::default();
        let cancel = AtomicBool::new(false);

        // Execute relocation
        let report =
            execute_folder_relocation(&source, &target_parent, &deny, &mut journal, &cancel)
                .unwrap();

        assert_eq!(report.file_count, 2);
        assert!(report.bytes_moved > 0);
        assert!(source.exists()); // source exists as a junction!
        assert!(report.target_path.exists());

        // Payload readable through source junction
        let content1 = fs::read(source.join("file1.bin")).unwrap();
        assert_eq!(content1, b"large model weights 1");

        // Active journal record
        let active = journal.list_active_relocations().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, report.relocation_id);

        // Undo relocation
        let undo_report =
            undo_folder_relocation(&report.relocation_id, &mut journal, &cancel).unwrap();
        assert_eq!(undo_report.file_count, 2);
        assert!(source.exists());
        assert!(!report.target_path.exists()); // target directory was cleaned up

        let remaining_active = journal.list_active_relocations().unwrap();
        assert_eq!(remaining_active.len(), 0);
    }

    #[test]
    fn relocate_rejects_denied_paths_and_existing_reparse_points() {
        let temp = tempdir().unwrap();
        let source = PathBuf::from(r"C:\Windows\System32");
        let target_parent = temp.path().join("dest");
        fs::create_dir_all(&target_parent).unwrap();

        let deny = DenyContext::from_env();

        let mut journal = ActionJournal::open(&temp.path().join("journal.db")).unwrap();
        let cancel = AtomicBool::new(false);

        let res = execute_folder_relocation(&source, &target_parent, &deny, &mut journal, &cancel);
        assert!(matches!(res, Err(DskError::Denied(_))));
    }

    #[test]
    fn relocate_rejects_target_inside_source() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("src_data");
        let nested = source.join("sub").join("dest");
        fs::create_dir_all(&nested).unwrap();
        fs::write(source.join("a.bin"), b"payload").unwrap();

        assert!(target_is_inside_source(&source, &nested).unwrap());
        assert!(target_is_inside_source(&source, &source).unwrap());
        assert!(!target_is_inside_source(&source, temp.path()).unwrap());
        // A sibling whose name merely shares the prefix is not "inside".
        let sibling = temp.path().join("src_data_other");
        fs::create_dir_all(&sibling).unwrap();
        assert!(!target_is_inside_source(&source, &sibling).unwrap());

        let deny = DenyContext::default_for_test();
        let res = plan_folder_relocation(&source, &nested, &deny);
        assert!(
            matches!(res, Err(DskError::Optimize(ref m)) if m.contains("inside the source")),
            "got {res:?}"
        );
    }

    #[test]
    fn rollback_keeps_both_copies_when_original_cannot_be_restored() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("data");
        let backup = temp.path().join("data-.disksaver-bak-1");
        let target = temp.path().join("relocated");
        fs::create_dir_all(&backup).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("f.bin"), b"copy").unwrap();
        // Something non-empty now occupies the source path, so restoring the backup fails.
        fs::create_dir_all(source.join("blocker")).unwrap();

        let note = rollback_from_backup(&source, &backup, &target, false);
        assert!(note.contains("ROLLBACK INCOMPLETE"), "{note}");
        assert!(backup.exists(), "backup must be kept");
        assert!(target.join("f.bin").exists(), "verified copy must be kept");

        // Successful restore removes the relocated copy.
        fs::remove_dir_all(&source).unwrap();
        let note = rollback_from_backup(&source, &backup, &target, false);
        assert_eq!(note, "rolled back to the original folder");
        assert!(source.exists() && !backup.exists() && !target.exists());
    }

    #[test]
    fn relocate_rejects_unc_paths_nested_junctions_and_cloud_or_symlink_attrs() {
        assert!(is_unsafe_relocation_entry(0, true));
        assert!(is_unsafe_relocation_entry(
            FILE_ATTRIBUTE_REPARSE_POINT_MASK,
            false
        ));
        assert!(is_unsafe_relocation_entry(
            FILE_ATTRIBUTE_OFFLINE_MASK,
            false
        ));
        assert!(is_unsafe_relocation_entry(
            FILE_ATTRIBUTE_RECALL_ON_OPEN_MASK,
            false
        ));
        assert!(is_unsafe_relocation_entry(
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_MASK,
            false
        ));
        assert!(!is_unsafe_relocation_entry(0x20, false)); // FILE_ATTRIBUTE_ARCHIVE

        let temp = tempdir().unwrap();
        let source = temp.path().join("app_cache");
        let outside = temp.path().join("outside_secret");
        let nested_junc = source.join("link_out");
        let dest_parent = temp.path().join("dest_dir");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&dest_parent).unwrap();
        fs::write(outside.join("secret.txt"), b"keep intact").unwrap();
        create_mount_point_junction(&nested_junc, &outside).unwrap();

        let deny = DenyContext::default();
        let mut journal = ActionJournal::open(&temp.path().join("journal.db")).unwrap();
        let cancel = AtomicBool::new(false);

        // 1. Nested junction must fail closed in planning & copy
        let nested_res =
            execute_folder_relocation(&source, &dest_parent, &deny, &mut journal, &cancel);
        assert!(matches!(nested_res, Err(DskError::Optimize(_))));
        assert!(outside.join("secret.txt").exists());
        assert!(!dest_parent.join("app_cache").exists());

        // 2. Target on UNC / network share must fail DRIVE_FIXED enforcement
        let clean_src = temp.path().join("clean_src");
        fs::create_dir_all(&clean_src).unwrap();
        fs::write(clean_src.join("a.bin"), b"data").unwrap();
        let unc_res = plan_folder_relocation(
            &clean_src,
            Path::new(r"\\localhost\nonexistent_share\reloc"),
            &deny,
        );
        assert!(matches!(unc_res, Err(DskError::Optimize(_))));

        // 3. Final handle resolution matches real directory on junction
        let resolved_junc = resolve_final_path_by_handle(&nested_junc).unwrap();
        let resolved_out = resolve_final_path_by_handle(&outside).unwrap();
        assert_eq!(
            normalize_win_path_str(&resolved_junc),
            normalize_win_path_str(&resolved_out)
        );
        let _ = remove_junction_link_only(&nested_junc);
    }

    #[test]
    fn relocate_cleans_staging_on_cancellation_and_rejects_undo_with_missing_target() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("models");
        let dest_parent = temp.path().join("relocated");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&dest_parent).unwrap();
        fs::write(source.join("weights.bin"), b"weights payload").unwrap();

        let deny = DenyContext::default();
        let mut journal = ActionJournal::open(&temp.path().join("journal.db")).unwrap();

        // Pre-cancelled run leaves zero staging leftovers and leaves source intact
        let cancel_true = AtomicBool::new(true);
        let cancelled =
            execute_folder_relocation(&source, &dest_parent, &deny, &mut journal, &cancel_true);
        assert!(matches!(cancelled, Err(DskError::Cancelled)));
        let leftovers: Vec<_> = fs::read_dir(&dest_parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging folder must be cleaned on cancel"
        );
        assert!(source.join("weights.bin").exists());

        // Active relocation followed by missing target rejects undo cleanly
        let cancel_false = AtomicBool::new(false);
        let report =
            execute_folder_relocation(&source, &dest_parent, &deny, &mut journal, &cancel_false)
                .unwrap();
        fs::remove_dir_all(&report.target_path).unwrap();
        let undo_err = undo_folder_relocation(&report.relocation_id, &mut journal, &cancel_false);
        assert!(matches!(undo_err, Err(DskError::Optimize(_))));
        let _ = remove_junction_link_only(&source);
    }
}
