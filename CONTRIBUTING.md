# Contributing to DiskSaver

Thank you for your interest in contributing to DiskSaver!

## Prerequisites

- **OS:** Windows 10 or Windows 11 (`x86_64`)
- **Toolchain:** [Rust](https://rustup.rs/) 1.95 or newer (`stable`, with `rustfmt` and `clippy` components)
- **Build Tools:** Visual Studio C++ Build Tools (`x86_64-pc-windows-msvc`)

## Local Verification

Before opening a pull request, ensure formatting, strict lints, and the full workspace test suite pass:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Optional: Elevated `$MFT` Equivalence Tests

Raw `$MFT` sector-reading equivalence tests use a disposable 2 GiB NTFS VHDX fixture and require an **elevated Administrator PowerShell prompt**:

```powershell
# 1. Create, format, and populate a temporary NTFS fixture at R:\
.\scripts\fixture\new-fixture-vhdx.ps1 -Letter R

# 2. Run the MFT-vs-Win32 equivalence test suite
$env:DSK_FIXTURE = 'R:\'
cargo test -p dsk-core --test fixture_volume -- --ignored

# 3. Detach and remove the temporary fixture
.\scripts\fixture\remove-fixture-vhdx.ps1
```

## Safety & Code Standards

- **Zero `unsafe` outside `dsk-core`:** `dsk-cli`, `dsk-gui`, `dsk-helper`, and `dsk-tray` enforce `#![forbid(unsafe_code)]`. Any new Win32 FFI belongs in `dsk-core::win` with explicit `// SAFETY:` comments documenting invariants.
- **No Unchecked Deletion Paths:** All destructive operations must go through `dsk-core`'s handle-based anti-TOCTOU primitives (`FILE_FLAG_OPEN_REPARSE_POINT`, canonical path containment, FRN pinning, `DenyContext`, or `FOFX_RECYCLEONDELETE` with veto sink) and log to `ActionJournal`.
- **No Network Calls or Telemetry:** DiskSaver operates 100% offline. Do not introduce outbound HTTP calls or analytics.
- **Tests Required:** Bug fixes and new rules/commands should include unit or integration tests using synthetic temp fixtures (never touching the host user's `journal.db`, `growth.db`, or personal files).
