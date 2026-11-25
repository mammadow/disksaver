# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in DiskSaver—especially around:
- Elevated helper IPC (`dsk-helper.exe`) named-pipe ACLs or client verification,
- `install-dir` DACL hardening or path-traversal / TOCTOU checks,
- Safe cleanup (`DenyContext`, File ID pinning, canonical path containment, or Recycle Bin veto handling),

please **do not** open a public issue with exploit details. Instead, report it privately through [GitHub Security Advisories](https://github.com/mammadow/disksaver/security/advisories/new).

## Security Architecture & Boundaries

- **100% Offline Execution:** DiskSaver makes zero outbound network calls and collects zero telemetry.
- **Immutable Safety Deny List (`DenyContext`):** Hardcoded, non-overridable checks block operations targeting Windows system roots, protected program directories, drive roots, volume metadata folders, and personal user libraries (`Desktop`, `Documents`, `Pictures`, `Music`, `Videos`).
- **Handle-Based Anti-TOCTOU Deletion:** Targeted cleanup files are opened with `FILE_FLAG_OPEN_REPARSE_POINT`, verified via `GetFinalPathNameByHandleW` containment and `GetFileInformationByHandleEx(FileIdInfo)` inode pinning, and deleted via `FileDispositionInfoEx`.
- **Intent-Only Elevated Helper:** `dsk-helper.exe` verifies client binary signatures/directories over hardened named pipes, accepts structured intents rather than arbitrary paths or command lines, never launches `PATH`-resolved external tools, and impersonates the caller when writing the SQLite journal.
- **Portable Release Integrity:** Pre-built release archives are unsigned portable binaries; always verify downloads against the published `SHA256SUMS.txt` before running.
