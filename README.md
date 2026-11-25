<div align="center">

# DiskSaver (`disksaver`)

**High-Precision Windows NTFS Disk Analyzer, TOCTOU-Safe Cleaner, Storage Optimizer & GPU-Accelerated Desktop GUI**

[![CI](https://github.com/mammadow/disksaver/actions/workflows/ci.yml/badge.svg)](https://github.com/mammadow/disksaver/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.95%2B%20(2024)-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-0078D6.svg)](https://www.microsoft.com/windows)
[![Offline](https://img.shields.io/badge/telemetry-zero%20%7C%20100%25%20offline-brightgreen.svg)](#security--privacy)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

*Measure true on-disk allocation at ~464,000 files/sec, uncover non-overlapping reclaim opportunities without touching personal files, and recover gigabytes safely via CLI, desktop GUI, or a `< 20 MiB` background tray monitor.*

</div>

---

## Key Features

- **Dual-Engine Precision Scanner (`--method auto | mft | dir`):**
  - **Raw NTFS `$MFT` Engine (`--method mft`):** Parses the Master File Table via direct volume sector reads when elevated, processing record attributes, non-resident runlists, extension records, and fixups with zero per-file handle overhead.
  - **Parallel Win32 Scanner (`--method dir`):** Multi-threaded traversal using `GetFileInformationByHandleEx(FileIdExtdDirectoryInfo)` with work-stealing concurrency tuned to drive seek characteristics (NVMe/SSD vs. HDD).
  - **Persistent `.dsi` Snapshots & USN Journal Incremental Rescans:** Elevated NTFS volume-root scans save `zstd`-compressed `.dsi` snapshots with `blake3` integrity footers and replay contiguous NTFS USN journal deltas for near-instant subsequent scans (automatic full-scan fallback on wrap, truncation, or `--no-cache`).
- **True "On-Disk" Space Accounting:**
  - Hard links are deduplicated and counted exactly once (`HARDLINK` / `DUP_LINK`).
  - Accurate physical cluster accounting for NTFS compression (LZNT1), Windows Overlay Filter (WOF XPRESS/LZX), sparse files, and Alternate Data Streams (ADS).
  - Junctions, symlinks, and dehydrated cloud placeholders (OneDrive / CloudFiles) are detected and skipped—never traversed into loops or silently hydrated over the network.
- **Reclaim Ledger & Disk Hunt (`reclaim`, `hunt`, `sweep`):**
  - **De-Overlapped Opportunity Ledger:** Ranks opportunities across *Invisible* (WOF compression, VHDX trim, immutable hardlinks), *Sizing* (hibernation, pagefile, CompactOS), *Regenerable* (caches, stale Cargo/Next.js build generations), *Leftover* (orphaned app data, duplicate copies, old installers), and *Decision* (apps, games, models, recordings). Every byte has exactly one owner so totals never double-count.
  - **Journal Calibration:** Recalibrates future savings estimates from measured `GetDiskFreeSpaceExW` deltas recorded in `journal.db`.
- **TOCTOU-Resistant Safe Cleanup Engine (`plan`, `clean`, `history`):**
  - **Atomic Handle Deletion:** Uses `FileDispositionInfoEx` with POSIX delete semantics over `FILE_FLAG_OPEN_REPARSE_POINT` handles.
  - **File ID Pinning & Containment:** Pins items by `NtfsFrn64` / `FxHash128` (`GetFileInformationByHandleEx`) and verifies canonical root containment (`GetFinalPathNameByHandleW`) immediately before deletion.
  - **Tiered Rules & OS COM Integration:** Built-in TOML rules (🟢 Safe, 🟡 Review, 🔴 Advanced) for Windows/GPU/dev/browser/app/gaming caches plus official `IEmptyVolumeCache` Windows cleanup handlers, battery/process/servicing precondition checks, and a transactional SQLite audit log (`journal.db`).
- **Non-Destructive Storage Optimizers (`optimize`, `dupes`, `insights`):**
  - **VHDX / WSL2 / Docker Compaction:** Inspects VHDX block allocation tables and ext4 superblocks read-only, runs guest `fstrim` when enabled, and compacts virtual disks cleanly.
  - **Transparent WOF Compression & CompactOS:** Byte-weighted sampling estimates savings before applying per-file `WofSetFileDataLocation` at background priority (reversible via `--undo`).
  - **System Tunables, Dehydration & Relocation:** Guided hibernation/pagefile/VSS/Reserved Storage sizing, CloudFiles placeholder dehydration, junction-based folder relocation (`relocate` / `undo-relocate`), BLAKE3 duplicate remediation (`recycle` / `hardlink` / `reflink`), and storage intelligence (projects, AI models, games, orphans, cold files).
- **Verified GPU Video Compressor (`videos`):**
  - Discovers oversized, inefficiently encoded videos across drives while skipping system/app/game directories and holding back duplicate pairs.
  - Encodes via the user's own `ffmpeg` (AV1 or HEVC; NVENC / QSV / AMF / CPU) at below-normal priority, pausing for full-screen games and stopping on battery.
  - Replaces originals **only** after verifying streams, duration, size reduction (`>= 15%`), and multi-segment VMAF (or SSIM fallback) quality (`>= 93`), moving originals safely to the Recycle Bin or a holding directory.
- **GPU-Accelerated Desktop GUI (`disksaver-gui.exe`):**
  - Built with `eframe 0.37` and `wgpu` (DirectX 12) featuring **Dark & Light Fluent themes**, a collapsible sidebar, custom vector icons, keyboard shortcuts, and 7 tabs: **Overview**, **Cleanup**, **Explore**, **Optimize**, **Insights**, **Videos**, and **History**.
  - Renders a squarified cushion treemap (`< 1 ms` for 1,000,000 nodes) alongside a virtualized 1M+ row filesystem tree and guarded COM `IFileOperation` (`FOFX_RECYCLEONDELETE`) recycling.
- **On-Demand Elevated Helper & `< 20 MiB` Tray Agent:**
  - `dsk-helper.exe` executes privileged intents over ACL-hardened named pipes from unelevated CLI/GUI sessions without sharing arbitrary paths or `PATH`-resolved commands.
  - `disksaver-tray.exe` (`#![forbid(unsafe_code)]`, `< 20 MiB` working set) monitors low free space, runaway directory growth, opt-in budget maintenance, and scheduled per-user safe cleanups.

---

## Installation & Quick Start

### Option 1: Portable Release Binary

Download the latest `disksaver-v<version>-windows-x86_64.zip` and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/mammadow/disksaver/releases), verify the checksum, and extract:

```powershell
Get-FileHash .\disksaver-v0.1.0-windows-x86_64.zip -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

For multi-user systems or using `--use-helper` from an unelevated shell, install into a non-user-writable directory (`%ProgramFiles%\DiskSaver`) with hardened admin/SYSTEM DACLs from an **elevated** prompt:

```powershell
.\disksaver.exe install-dir --dry-run
.\disksaver.exe install-dir
```

### Option 2: Build from Source

**Prerequisites:** Windows 10/11 (`x86_64`), [Rust 1.95+](https://rustup.rs/), and Visual Studio C++ Build Tools (`x86_64-pc-windows-msvc`).

```powershell
cargo build --release --workspace
```

Compiled binaries are emitted to `target\release\`:
- `disksaver.exe` — CLI tool
- `disksaver-gui.exe` — Desktop GUI
- `dsk-helper.exe` — On-demand elevated IPC helper
- `disksaver-tray.exe` — Lightweight system-tray monitor

To assemble a portable release archive and `SHA256SUMS.txt` under `target\dist\`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-release.ps1
```

---

## Desktop GUI (`disksaver-gui.exe`)

```powershell
# Launch to the Overview tab
.\target\release\disksaver-gui.exe

# Launch and immediately scan a drive or folder
.\target\release\disksaver-gui.exe C:\
.\target\release\disksaver-gui.exe D:\Projects

# Open directly on a specific tab (overview, cleanup, explore, optimize, insights, videos, history)
.\target\release\disksaver-gui.exe --tab optimize

# Isolate audit journal / growth DB for testing
.\target\release\disksaver-gui.exe --test-journal $env:TEMP\ds-journal.db --growth-db $env:TEMP\ds-growth.db
```

---

## CLI Reference

Run `disksaver --help` or `disksaver <command> --help` for full option details across all 15 commands:

| Command | Purpose | Example |
|---|---|---|
| `scan` | Precision disk usage scan and ranking | `disksaver scan C:\ --method auto --stats` |
| `reclaim` | Ranked, de-overlapped reclaim ledger | `disksaver reclaim C:\ --dry-run` |
| `hunt` | Find large removable units and file swarms | `disksaver hunt C:\ --many --top 30` |
| `plan` | Generate a safe cleanup plan | `disksaver plan C:\ --tier safe --out plan.json` |
| `clean` | Simulate or execute safe cleanup (`--dry-run` or `--yes`) | `disksaver clean --plan plan.json --dry-run` |
| `sweep` | Prune stale Cargo `target` / Next.js build generations | `disksaver sweep D:\Projects --keep-days 14 --dry-run` |
| `optimize` | VHDX compaction, WOF/CompactOS, tunables, dehydrate, relocate | `disksaver optimize tunables --advise` |
| `dupes` | BLAKE3 duplicate scan and recycle/hardlink/reflink remediation | `disksaver dupes D:\ --min-bytes 16777216 --dry-run` |
| `insights` | Discover project artifacts, AI models, games, orphans, cold files | `disksaver insights C:\ --section all` |
| `videos` | Find oversized videos and run verified AV1/HEVC re-encodes | `disksaver videos D:\Videos --min-size 200MiB` |
| `growth` | Report 24h / 7d folder growth and runaway growth (`>= 5 GiB/day`) | `disksaver growth --window 24h` |
| `history` | Inspect transactional cleanup and recycle audit records | `disksaver history --limit 20` |
| `uninstall` | Launch a registered application's own uninstaller | `disksaver uninstall "App Name"` |
| `move-library` | Redirect a Windows Known Folder (`videos`, `downloads`, etc.) | `disksaver move-library videos D:\Videos` |
| `install-dir` | Atomically install sibling binaries with hardened ACLs | `disksaver install-dir --dry-run` |

### System Tray Agent (`disksaver-tray.exe`)

```powershell
# Single low-space check with working-set metrics as JSON
.\target\release\disksaver-tray.exe --check-once --json

# Schedule or remove a per-user weekly Safe Clean task
.\target\release\disksaver-tray.exe --schedule-clean --volume C:\ --time 03:00
.\target\release\disksaver-tray.exe --unschedule-clean
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Scan, I/O, database, or runtime execution error |
| `2` | CLI usage error, insufficient privileges for `--method mft`, or safety refusal gate (`clean` without `--yes` / `--dry-run`) |
| `130` | Cancelled via `Ctrl+C` |

---

## Safety Model & Security Architecture

1. **Non-Overridable `DenyContext`:** Hardcoded rules block operations targeting `%SystemRoot%`, `System32`, `SysWOW64`, `WinSxS`, `WindowsApps`, `Package Cache`, drive roots, volume metadata folders, `%LOCALAPPDATA%\DiskSaver`, active user profile roots, and personal libraries (`Desktop`, `Documents`, `Pictures`, `Music`, `Videos`).
2. **Handle-Based Anti-TOCTOU Deletion:** Targets are opened with `FILE_FLAG_OPEN_REPARSE_POINT`, verified via `GetFinalPathNameByHandleW` containment and `GetFileInformationByHandleEx(FileIdInfo)` inode pinning, and deleted via `FileDispositionInfoEx`.
3. **Cloud Placeholder Protection:** Files marked with `IO_REPARSE_TAG_CLOUD`, `IO_REPARSE_TAG_ONEDRIVE`, `FILE_ATTRIBUTE_RECALL_ON_OPEN`, `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`, or `FILE_ATTRIBUTE_OFFLINE` are skipped so remote files are never hydrated unintentionally.
4. **Guarded Recycle Bin Integration:** Manual and Insights recycling uses COM `IFileOperation` with `FOFX_RECYCLEONDELETE` plus a vetoing `IFileOperationProgressSink`—if the Shell cannot route an item to the Recycle Bin, the operation aborts rather than permanently deleting it.
5. **Intent-Only Elevated Helper:** `dsk-helper.exe` validates client binary locations and pipe ACLs, executes only pinned intents (never arbitrary client paths or `PATH`-resolved tools), and logs under caller impersonation.
6. **Zero Telemetry & 100% Local State:** All snapshots (`.dsi`), cleanup journals (`journal.db`), and growth rollups (`growth.db`) live exclusively under `%LOCALAPPDATA%\DiskSaver` with zero outbound network connections.

---

## Workspace Architecture

| Crate | Binary / Output | Description |
|---|---|---|
| `dsk-core` | `lib` | NTFS `$MFT` parser, parallel Win32 scanner, SoA index, `.dsi` + USN cache, reclaim ledger, hunt, safe cleanup engine, optimizers, insights, video compressor, and Win32/COM wrappers |
| `dsk-cli` | `disksaver.exe` | 15-subcommand CLI with human and `--json` reporting |
| `dsk-gui` | `disksaver-gui.exe` | `eframe` + `wgpu` desktop GUI with 7 tabs, custom vector UI kit, cushion treemap, and virtualized filesystem tree (`#![forbid(unsafe_code)]`) |
| `dsk-helper` | `dsk-helper.exe` | On-demand elevated IPC helper over ACL-hardened Windows named pipes (`#![forbid(unsafe_code)]`) |
| `dsk-tray` | `disksaver-tray.exe` | Windowless `< 20 MiB` system-tray monitor and scheduler (`#![forbid(unsafe_code)]`) |
| `dsk-fixture` | `dsk-fixture.exe` | Synthetic NTFS fixture generator for MFT-vs-Win32 equivalence testing (`#![forbid(unsafe_code)]`) |

---

## Measured Performance

Measured on Windows 11 `x86_64` with NVMe SSD storage (release builds):

- **Full System Drive Directory Scan (`1.78M` files, `318K` folders):** `3.77 s` (~`464,000 files/sec`)
- **Index Memory Footprint:** `109.3 B / file` heap (`92.7 B / node`), `228.2 B / file` peak working set
- **1,000,000-Node Cushion Treemap Layout & GPU Mesh:** `850.7 µs` (`4,000` capped visual tiles, single batched mesh)
- **System Tray Agent Footprint:** `< 20 MiB` peak working set (`disksaver-tray.exe --check-once --json`)

---

## Contributing, Security & License

- See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, test suites, and code standards.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting and security architecture details.
- Dual-licensed under either of [MIT License](LICENSE-MIT) or [Apache License, Version 2.0](LICENSE-APACHE), at your option.
