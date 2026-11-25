#![forbid(unsafe_code)]

//! Project build artifact & dependency cache analyzer (§9.1).
//!
//! Identifies build artifacts across 10 developer ecosystems while strictly requiring sibling
//! or child ecosystem marker files (`Cargo.toml`, `package.json`, `pom.xml`, etc.) and computing
//! hard-link-aware reclaimable bytes so globally linked stores (e.g. `.pnpm-store`) are never
//! overstated.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::time::filetime_to_min2000;

/// Developer ecosystem classifications supported by project artifact discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProjectEcosystem {
    Rust,
    NodeJs,
    Python,
    JavaMaven,
    Gradle,
    DotNet,
    Dart,
    CppCmake,
    Unity,
    Unreal,
}

impl ProjectEcosystem {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Rust => "Rust (Cargo)",
            Self::NodeJs => "Node.js",
            Self::Python => "Python",
            Self::JavaMaven => "Java (Maven)",
            Self::Gradle => "JVM (Gradle)",
            Self::DotNet => ".NET / MSBuild",
            Self::Dart => "Dart / Flutter",
            Self::CppCmake => "C / C++ (CMake)",
            Self::Unity => "Unity",
            Self::Unreal => "Unreal Engine",
        }
    }
}

/// Discovered project build cache / dependency directory with hard-link-aware savings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectArtifactCandidate {
    pub ecosystem: ProjectEcosystem,
    pub project_name: String,
    pub project_root: PathBuf,
    pub artifact_path: PathBuf,
    pub marker_evidence: String,
    pub allocated_bytes: u64,
    pub reclaimable_bytes: u64,
    pub hardlink_shared_bytes: u64,
    pub file_count: u64,
    pub days_since_modified: u32,
}

/// Aggregated report returned by [`scan_project_artifacts`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectScanReport {
    pub artifacts: Vec<ProjectArtifactCandidate>,
    pub total_allocated_bytes: u64,
    pub total_reclaimable_bytes: u64,
    pub total_hardlink_shared_bytes: u64,
}

struct ChildEntry<'a> {
    name_lower: &'a str,
    is_dir: bool,
}

fn find_child_ci<'a>(
    children: &'a [ChildEntry<'a>],
    target_lower: &str,
    require_dir: Option<bool>,
) -> bool {
    children.iter().any(|c| {
        c.name_lower == target_lower
            && match require_dir {
                Some(d) => c.is_dir == d,
                None => true,
            }
    })
}

fn find_child_ext_ci(children: &[ChildEntry<'_>], ext_lower: &str) -> bool {
    children
        .iter()
        .any(|c| !c.is_dir && c.name_lower.ends_with(ext_lower))
}

fn classify_artifact_dir(
    index: &Index,
    dir_id: NodeId,
    dir_name_lower: &str,
    siblings: &[ChildEntry<'_>],
) -> Option<(ProjectEcosystem, String)> {
    // 1. Rust Cargo `target/` requires sibling `Cargo.toml`
    if dir_name_lower == "target" && find_child_ci(siblings, "cargo.toml", Some(false)) {
        return Some((ProjectEcosystem::Rust, "Cargo.toml".to_string()));
    }

    // 2. Java Maven `target/` requires sibling `pom.xml`
    if dir_name_lower == "target" && find_child_ci(siblings, "pom.xml", Some(false)) {
        return Some((ProjectEcosystem::JavaMaven, "pom.xml".to_string()));
    }

    // 3. Node.js caches (`node_modules`, `.next`, `.nuxt`, `.turbo`, `.parcel-cache`) require
    //    sibling `package.json`
    if matches!(
        dir_name_lower,
        "node_modules" | ".next" | ".nuxt" | ".turbo" | ".parcel-cache"
    ) && find_child_ci(siblings, "package.json", Some(false))
    {
        return Some((ProjectEcosystem::NodeJs, "package.json".to_string()));
    }

    // Collect children of `dir_id` once if child marker inspection is needed
    let dir_child_names: Vec<(String, bool)> = index
        .children(dir_id)
        .map(|cid| {
            (
                index.name(cid).to_ascii_lowercase(),
                index.flags(cid).contains(NodeFlags::DIR),
            )
        })
        .collect();
    let dir_children: Vec<ChildEntry<'_>> = dir_child_names
        .iter()
        .map(|(n, d)| ChildEntry {
            name_lower: n.as_str(),
            is_dir: *d,
        })
        .collect();

    // 4. Python virtual environments require their own `pyvenv.cfg` (written by `venv`/`virtualenv`):
    //    a folder merely named `venv` next to `pyproject.toml` may hold anything.
    if matches!(dir_name_lower, ".venv" | "venv")
        && find_child_ci(&dir_children, "pyvenv.cfg", Some(false))
    {
        return Some((ProjectEcosystem::Python, "pyvenv.cfg".to_string()));
    }
    // Python bytecode / tool caches require sibling `*.py` sources (or project files).
    if matches!(
        dir_name_lower,
        "__pycache__" | ".pytest_cache" | ".mypy_cache" | ".ruff_cache"
    ) {
        if find_child_ext_ci(siblings, ".py") {
            return Some((ProjectEcosystem::Python, "*.py".to_string()));
        }
        for marker in ["pyproject.toml", "requirements.txt", "setup.py"] {
            if find_child_ci(siblings, marker, Some(false)) {
                return Some((ProjectEcosystem::Python, marker.to_string()));
            }
        }
    }

    // 4b. Dart / Flutter `.dart_tool/` or `build/` require sibling `pubspec.yaml`
    if matches!(dir_name_lower, ".dart_tool" | "build")
        && find_child_ci(siblings, "pubspec.yaml", Some(false))
    {
        return Some((ProjectEcosystem::Dart, "pubspec.yaml".to_string()));
    }

    // 5. Gradle `build/` or `.gradle/` requires sibling `build.gradle`, `build.gradle.kts`, `settings.gradle`, or `settings.gradle.kts`
    if matches!(dir_name_lower, "build" | ".gradle") {
        for marker in [
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
        ] {
            if find_child_ci(siblings, marker, Some(false)) {
                return Some((ProjectEcosystem::Gradle, marker.to_string()));
            }
        }
    }

    // 6. C/C++ CMake `build/` or `cmake-build-*` must contain CMake's own generated state
    //    (`CMakeCache.txt` / `CMakeFiles/`): a `build/` folder next to `CMakeLists.txt` alone may
    //    hold committed scripts or sources.
    if dir_name_lower == "build" || dir_name_lower.starts_with("cmake-build-") {
        let has_cmakelists = find_child_ci(siblings, "cmakelists.txt", Some(false));
        let has_cmakecache = find_child_ci(&dir_children, "cmakecache.txt", Some(false))
            || find_child_ci(&dir_children, "cmakefiles", Some(true));
        if has_cmakecache {
            let evidence = if has_cmakelists {
                "CMakeLists.txt + CMakeCache.txt"
            } else {
                "CMakeCache.txt"
            };
            return Some((ProjectEcosystem::CppCmake, evidence.to_string()));
        }
    }

    // 7. .NET `bin/` or `obj/` requires a sibling project file (`*.csproj`, `*.fsproj`, `*.vbproj`).
    //    A solution file alone is not enough: `bin/` next to a `.sln` is often a committed tools dir.
    if matches!(dir_name_lower, "bin" | "obj") {
        for ext in [".csproj", ".fsproj", ".vbproj"] {
            if find_child_ext_ci(siblings, ext) {
                return Some((ProjectEcosystem::DotNet, format!("*{ext}")));
            }
        }
    }

    // (Go `vendor/` is intentionally not flagged: it is frequently committed source.)

    // 9. Unity `Library/`, `Temp/` or `obj/` requires `ProjectSettings/ProjectVersion.txt`
    if matches!(dir_name_lower, "library" | "temp" | "obj")
        && find_child_ci(siblings, "projectsettings", Some(true))
        && unity_project_version_exists(index, dir_id)
    {
        return Some((
            ProjectEcosystem::Unity,
            "ProjectSettings/ProjectVersion.txt".to_string(),
        ));
    }

    // 10. Unreal Engine `Intermediate/`, `DerivedDataCache/`, `Binaries/`, or `Saved/` requires
    //     sibling `*.uproject`
    if matches!(
        dir_name_lower,
        "intermediate" | "deriveddatacache" | "binaries" | "saved"
    ) && find_child_ext_ci(siblings, ".uproject")
    {
        return Some((ProjectEcosystem::Unreal, "*.uproject".to_string()));
    }

    None
}

/// `true` when the parent of `dir_id` contains `ProjectSettings/ProjectVersion.txt`.
fn unity_project_version_exists(index: &Index, dir_id: NodeId) -> bool {
    let parent = index.parent(dir_id);
    if parent == dir_id {
        return false;
    }
    index.children(parent).any(|sib| {
        index.flags(sib).contains(NodeFlags::DIR)
            && index.name(sib).eq_ignore_ascii_case("projectsettings")
            && index.children(sib).any(|c| {
                !index.flags(c).contains(NodeFlags::DIR)
                    && index.name(c).eq_ignore_ascii_case("projectversion.txt")
            })
    })
}

fn measure_subtree_hardlink_aware(
    index: &Index,
    artifact_root: NodeId,
    global_hardlinks: &FxHashMap<u64, u32>,
    now_mins: u32,
) -> (u64, u64, u64, u32) {
    let mut stack = vec![artifact_root];
    let mut plain_alloc = 0u64;
    let mut file_count = 0u64;
    let mut newest_mtime = 0u32;
    let mut local_hardlinks: FxHashMap<u64, (u32, u64)> = FxHashMap::default();

    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if flags.contains(NodeFlags::DIR) {
            if node != artifact_root && flags.contains(NodeFlags::REPARSE) {
                continue;
            }
            stack.extend(index.children(node));
            continue;
        }

        if flags.contains(NodeFlags::SYSTEM) {
            continue;
        }
        file_count += 1;
        newest_mtime = newest_mtime.max(index.mtime_min(node));

        let alloc = index.allocated(node);
        let fid = index.file_id(node);
        if fid != 0 && flags.contains(NodeFlags::HARDLINK) {
            let entry = local_hardlinks.entry(fid).or_insert((0, alloc));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.max(alloc);
        } else {
            plain_alloc = plain_alloc.saturating_add(alloc);
        }
    }

    let mut unique_hardlink_alloc = 0u64;
    let mut reclaimable_hardlink_alloc = 0u64;
    for (fid, (local_cnt, alloc)) in local_hardlinks {
        unique_hardlink_alloc = unique_hardlink_alloc.saturating_add(alloc);
        let global_cnt = global_hardlinks.get(&fid).copied().unwrap_or(local_cnt);
        if local_cnt >= global_cnt {
            reclaimable_hardlink_alloc = reclaimable_hardlink_alloc.saturating_add(alloc);
        }
    }

    let total_alloc = plain_alloc.saturating_add(unique_hardlink_alloc);
    let reclaimable = plain_alloc.saturating_add(reclaimable_hardlink_alloc);
    let days_since_modified = if newest_mtime == 0 {
        0
    } else {
        now_mins.saturating_sub(newest_mtime) / 1440
    };

    (total_alloc, reclaimable, file_count, days_since_modified)
}

/// Scans an [`Index`] for developer build caches and dependency directories across all 10
/// supported ecosystems, respecting `DenyContext` and hard-link deduplication (§9.1).
pub fn scan_project_artifacts(index: &Index, min_bytes: u64) -> ProjectScanReport {
    let deny_ctx = DenyContext::default();
    let now_ft = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| 116_444_736_000_000_000u64.saturating_add(d.as_secs().saturating_mul(10_000_000)))
        .unwrap_or(0);
    let now_mins = filetime_to_min2000(now_ft);

    // Pre-pass: count global hard-link occurrences by non-zero FileId so external links
    // (such as pnpm store links shared across projects) never inflate reclaimable_bytes.
    let mut global_hardlinks: FxHashMap<u64, u32> = FxHashMap::default();
    for id in 1..index.len() as NodeId {
        let flags = index.flags(id);
        if !flags.contains(NodeFlags::DIR) && flags.contains(NodeFlags::HARDLINK) {
            let fid = index.file_id(id);
            if fid != 0 {
                *global_hardlinks.entry(fid).or_insert(0) += 1;
            }
        }
    }

    let mut candidates = Vec::new();
    let mut stack = vec![ROOT];

    while let Some(dir_id) = stack.pop() {
        let dir_flags = index.flags(dir_id);
        if !dir_flags.contains(NodeFlags::DIR)
            || (dir_id != ROOT && dir_flags.intersects(NodeFlags::REPARSE | NodeFlags::ORPHANS))
        {
            continue;
        }

        let dir_children_ids: Vec<NodeId> = index.children(dir_id).collect();
        let sibling_storage: Vec<(NodeId, String, bool)> = dir_children_ids
            .iter()
            .map(|&cid| {
                (
                    cid,
                    index.name(cid).to_ascii_lowercase(),
                    index.flags(cid).contains(NodeFlags::DIR),
                )
            })
            .collect();
        let siblings: Vec<ChildEntry<'_>> = sibling_storage
            .iter()
            .map(|(_, name, is_dir)| ChildEntry {
                name_lower: name.as_str(),
                is_dir: *is_dir,
            })
            .collect();

        let project_root = index.path(dir_id);
        let project_name = project_root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| project_root.to_string_lossy().into_owned());

        for (cid, child_lower, is_dir) in &sibling_storage {
            if !is_dir {
                continue;
            }
            let cflags = index.flags(*cid);
            if cflags.intersects(NodeFlags::REPARSE | NodeFlags::SYSTEM | NodeFlags::ORPHANS) {
                continue;
            }

            if let Some((ecosystem, marker)) =
                classify_artifact_dir(index, *cid, child_lower, &siblings)
            {
                let artifact_path = index.path(*cid);
                if is_denied_path(&artifact_path, &deny_ctx).is_some() {
                    continue;
                }

                let (alloc, reclaimable, file_count, age_days) =
                    measure_subtree_hardlink_aware(index, *cid, &global_hardlinks, now_mins);

                if alloc >= min_bytes {
                    candidates.push(ProjectArtifactCandidate {
                        ecosystem,
                        project_name: project_name.clone(),
                        project_root: project_root.clone(),
                        artifact_path,
                        marker_evidence: marker,
                        allocated_bytes: alloc,
                        reclaimable_bytes: reclaimable,
                        hardlink_shared_bytes: alloc.saturating_sub(reclaimable),
                        file_count,
                        days_since_modified: age_days,
                    });
                }
                // Do not descend inside a classified artifact folder (avoids nested node_modules noise)
            } else {
                stack.push(*cid);
            }
        }
    }

    candidates.sort_by_key(|c| std::cmp::Reverse(c.reclaimable_bytes));
    let total_allocated_bytes = candidates
        .iter()
        .map(|c| c.allocated_bytes)
        .fold(0u64, u64::saturating_add);
    let total_reclaimable_bytes = candidates
        .iter()
        .map(|c| c.reclaimable_bytes)
        .fold(0u64, u64::saturating_add);
    let total_hardlink_shared_bytes = candidates
        .iter()
        .map(|c| c.hardlink_shared_bytes)
        .fold(0u64, u64::saturating_add);

    ProjectScanReport {
        artifacts: candidates,
        total_allocated_bytes,
        total_reclaimable_bytes,
        total_hardlink_shared_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::volume::VolumeInfo;

    struct TreeBuilder {
        names: NameArena,
        entries: Vec<RawEntry>,
        next_key: u64,
    }

    impl TreeBuilder {
        fn new() -> Self {
            let mut names = NameArena::new();
            let n_root = names.push_str("C:");
            let entries = vec![RawEntry {
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
            Self {
                names,
                entries,
                next_key: 100,
            }
        }

        fn dir(&mut self, parent: u64, name: &str) -> u64 {
            let key = self.next_key;
            self.next_key += 1;
            let n = self.names.push_str(name);
            self.entries.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags: NodeFlags::DIR,
                logical: 0,
                allocated: 0,
                mtime: 0,
                atime: 0,
                file_id: key,
                reparse_tag: 0,
            });
            key
        }

        fn file(&mut self, parent: u64, name: &str, bytes: u64, flags: NodeFlags, fid: u64) -> u64 {
            let key = self.next_key;
            self.next_key += 1;
            let n = self.names.push_str(name);
            self.entries.push(RawEntry {
                key,
                parent_key: parent,
                name: n,
                flags,
                logical: bytes,
                allocated: bytes,
                mtime: 0,
                atime: 0,
                file_id: fid,
                reparse_tag: 0,
            });
            key
        }

        fn finish(self) -> Index {
            let mut b = IndexBuilder::new(
                5,
                r"C:\",
                VolumeInfo {
                    root: r"C:\".to_string(),
                    ..Default::default()
                },
            );
            b.push_batch(EntryBatch {
                entries: self.entries,
                names: self.names,
            });
            b.finish()
        }
    }

    #[test]
    fn scans_all_ten_project_ecosystems_and_requires_markers() {
        let mut t = TreeBuilder::new();
        let dev = t.dir(5, "Dev");

        // 1. Rust
        let rust_p = t.dir(dev, "rust_app");
        t.file(rust_p, "Cargo.toml", 512, NodeFlags::empty(), 1001);
        let rust_tgt = t.dir(rust_p, "target");
        t.file(rust_tgt, "app.rlib", 1_000_000, NodeFlags::empty(), 1002);

        // 2. Node.js
        let node_p = t.dir(dev, "web_app");
        t.file(node_p, "package.json", 256, NodeFlags::empty(), 1003);
        let node_m = t.dir(node_p, "node_modules");
        t.file(node_m, "bundle.js", 1_000_000, NodeFlags::empty(), 1004);

        // 3. Python
        let py_p = t.dir(dev, "py_app");
        t.file(py_p, "pyproject.toml", 256, NodeFlags::empty(), 1005);
        let py_v = t.dir(py_p, ".venv");
        t.file(py_v, "pyvenv.cfg", 128, NodeFlags::empty(), 1006);
        t.file(py_v, "torch.pyd", 1_000_000, NodeFlags::empty(), 1007);

        // 4. Java Maven
        let mvn_p = t.dir(dev, "mvn_app");
        t.file(mvn_p, "pom.xml", 512, NodeFlags::empty(), 1008);
        let mvn_t = t.dir(mvn_p, "target");
        t.file(mvn_t, "service.jar", 1_000_000, NodeFlags::empty(), 1009);

        // 5. Gradle
        let gr_p = t.dir(dev, "gradle_app");
        t.file(gr_p, "build.gradle.kts", 512, NodeFlags::empty(), 1010);
        let gr_b = t.dir(gr_p, "build");
        t.file(gr_b, "classes.jar", 1_000_000, NodeFlags::empty(), 1011);

        // 6. .NET
        let dn_p = t.dir(dev, "dotnet_app");
        t.file(dn_p, "App.csproj", 512, NodeFlags::empty(), 1012);
        let dn_o = t.dir(dn_p, "obj");
        t.file(dn_o, "App.dll", 1_000_000, NodeFlags::empty(), 1013);

        // 7. Dart / Flutter
        let dart_p = t.dir(dev, "flutter_app");
        t.file(dart_p, "pubspec.yaml", 128, NodeFlags::empty(), 1014);
        let dart_t = t.dir(dart_p, ".dart_tool");
        t.file(dart_t, "kernel.dill", 1_000_000, NodeFlags::empty(), 1015);

        // 8. C/C++ CMake
        let cm_p = t.dir(dev, "cmake_app");
        t.file(cm_p, "CMakeLists.txt", 256, NodeFlags::empty(), 1016);
        let cm_b = t.dir(cm_p, "build");
        t.file(cm_b, "CMakeCache.txt", 512, NodeFlags::empty(), 1017);
        t.file(cm_b, "engine.obj", 1_000_000, NodeFlags::empty(), 1018);

        // 9. Unity
        let un_p = t.dir(dev, "unity_game");
        t.dir(un_p, "Assets");
        let un_ps = t.dir(un_p, "ProjectSettings");
        t.file(un_ps, "ProjectVersion.txt", 64, NodeFlags::empty(), 1030);
        let un_l = t.dir(un_p, "Library");
        t.file(un_l, "shader.cache", 1_000_000, NodeFlags::empty(), 1019);

        // 10. Unreal
        let ue_p = t.dir(dev, "unreal_game");
        t.file(ue_p, "Game.uproject", 256, NodeFlags::empty(), 1020);
        let ue_i = t.dir(ue_p, "Intermediate");
        t.file(ue_i, "pak.tmp", 1_000_000, NodeFlags::empty(), 1021);

        // False-positive traps (no markers!) must NOT be flagged
        let false_p = t.dir(dev, "random_docs");
        let fp_target = t.dir(false_p, "target");
        t.file(fp_target, "report.pdf", 2_000_000, NodeFlags::empty(), 1022);
        let fp_build = t.dir(false_p, "build");
        t.file(fp_build, "notes.txt", 2_000_000, NodeFlags::empty(), 1023);
        let fp_vendor = t.dir(false_p, "vendor");
        t.file(
            fp_vendor,
            "brochure.dat",
            2_000_000,
            NodeFlags::empty(),
            1024,
        );
        let fp_lib = t.dir(false_p, "Library");
        t.file(fp_lib, "book.epub", 2_000_000, NodeFlags::empty(), 1025);

        // Weak-marker traps: names plus a nearby project file, but no generated-state proof.
        let weak = t.dir(dev, "weak_markers");
        t.file(weak, "pyproject.toml", 64, NodeFlags::empty(), 1040);
        let weak_venv = t.dir(weak, "venv"); // no pyvenv.cfg
        t.file(weak_venv, "notes.md", 2_000_000, NodeFlags::empty(), 1041);
        t.file(weak, "CMakeLists.txt", 64, NodeFlags::empty(), 1042);
        let weak_build = t.dir(weak, "build"); // no CMakeCache.txt
        t.file(
            weak_build,
            "deploy.ps1",
            2_000_000,
            NodeFlags::empty(),
            1043,
        );
        t.file(weak, "Tools.sln", 64, NodeFlags::empty(), 1044);
        let weak_bin = t.dir(weak, "bin"); // solution only, no project file
        t.file(weak_bin, "tool.exe", 2_000_000, NodeFlags::empty(), 1045);
        t.file(weak, "go.mod", 64, NodeFlags::empty(), 1046);
        let weak_vendor = t.dir(weak, "vendor"); // committed Go vendor tree
        t.file(weak_vendor, "lib.go", 2_000_000, NodeFlags::empty(), 1047);
        t.dir(weak, "ProjectSettings"); // no ProjectVersion.txt
        let weak_temp = t.dir(weak, "Temp");
        t.file(
            weak_temp,
            "scratch.bin",
            2_000_000,
            NodeFlags::empty(),
            1048,
        );

        let index = t.finish();
        let report = scan_project_artifacts(&index, 1024);

        let found: Vec<ProjectEcosystem> = report.artifacts.iter().map(|a| a.ecosystem).collect();
        assert_eq!(report.artifacts.len(), 10, "found {found:?}");
        for eco in [
            ProjectEcosystem::Rust,
            ProjectEcosystem::NodeJs,
            ProjectEcosystem::Python,
            ProjectEcosystem::JavaMaven,
            ProjectEcosystem::Gradle,
            ProjectEcosystem::DotNet,
            ProjectEcosystem::Dart,
            ProjectEcosystem::CppCmake,
            ProjectEcosystem::Unity,
            ProjectEcosystem::Unreal,
        ] {
            assert!(found.contains(&eco), "missing {eco:?} in {found:?}");
        }
        assert!(
            report
                .artifacts
                .iter()
                .all(|a| !a.project_name.contains("random_docs")
                    && !a.project_name.contains("weak_markers"))
        );
    }

    #[test]
    fn pycache_requires_sibling_python_sources() {
        let mut t = TreeBuilder::new();
        let pkg = t.dir(5, "pkg");
        t.file(pkg, "mod.py", 64, NodeFlags::empty(), 2001);
        let cache = t.dir(pkg, "__pycache__");
        t.file(
            cache,
            "mod.cpython-312.pyc",
            2_000_000,
            NodeFlags::empty(),
            2002,
        );
        let other = t.dir(5, "assets");
        let fake = t.dir(other, "__pycache__");
        t.file(fake, "photo.jpg", 2_000_000, NodeFlags::empty(), 2003);

        let report = scan_project_artifacts(&t.finish(), 1024);
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(report.artifacts[0].ecosystem, ProjectEcosystem::Python);
        assert_eq!(report.artifacts[0].marker_evidence, "*.py");
    }

    #[test]
    fn hardlink_aware_reclaimable_bytes_handles_internal_and_external_links() {
        let mut t = TreeBuilder::new();
        let store = t.dir(5, "pnpm-store");
        let external_file_fid = 9001;
        let internal_file_fid = 9002;
        // External copy inside global pnpm-store
        t.file(
            store,
            "pkg.js",
            500_000,
            NodeFlags::HARDLINK,
            external_file_fid,
        );

        let proj = t.dir(5, "Proj");
        t.file(proj, "package.json", 128, NodeFlags::empty(), 9000);
        let nm = t.dir(proj, "node_modules");
        // Hardlink shared with store -> deleting node_modules frees 0 bytes for this inode!
        t.file(
            nm,
            "shared_ext.js",
            500_000,
            NodeFlags::HARDLINK,
            external_file_fid,
        );
        // Hardlink duplicated twice ONLY inside node_modules -> deleting node_modules frees 300_000 once!
        t.file(
            nm,
            "dup_int_a.js",
            300_000,
            NodeFlags::HARDLINK,
            internal_file_fid,
        );
        t.file(
            nm,
            "dup_int_b.js",
            300_000,
            NodeFlags::HARDLINK,
            internal_file_fid,
        );

        let index = t.finish();
        let report = scan_project_artifacts(&index, 0);
        assert_eq!(report.artifacts.len(), 1);
        let cand = &report.artifacts[0];
        assert_eq!(cand.allocated_bytes, 800_000);
        assert_eq!(cand.reclaimable_bytes, 300_000);
        assert_eq!(cand.hardlink_shared_bytes, 500_000);
    }
}
