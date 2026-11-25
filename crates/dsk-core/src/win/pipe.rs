//! Hardened Win32 Named Pipe server/client, security descriptors, peer PID verification, and impersonation.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_DATA,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetFileSecurityW, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    FlushFileBuffers, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT, WaitNamedPipeW,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, OpenProcess, OpenProcessToken,
    PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::core::{PCWSTR, PWSTR};

use crate::clean::deny::normalize_win_path_str;
use crate::error::{DskError, Result};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

fn win32_err(ctx: &'static str, code: u32) -> DskError {
    let clean_code = if (code & 0xFFFF_0000) == 0x8007_0000 {
        code & 0xFFFF
    } else {
        code
    };
    DskError::Win32 {
        ctx,
        code: clean_code,
    }
}

/// RAII guard for `HANDLE` closing.
#[derive(Debug)]
pub(crate) struct HandleGuard(pub(crate) HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: Closing valid Win32 kernel handle on drop.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// RAII guard for client impersonation ensuring unconditional `RevertToSelf()`.
///
/// The guard is deliberately `!Send`/`!Sync`: impersonation is per-thread, so it must be dropped
/// on the thread that started it.
#[derive(Debug)]
pub struct PipeImpersonationGuard {
    _not_send: core::marker::PhantomData<*const ()>,
}

impl Drop for PipeImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: Reverting current thread token to self unconditionally on drop.
        if unsafe { RevertToSelf() }.is_err() {
            // Continuing would run subsequent (elevated) work under the client's identity or with
            // an undefined token; terminate instead (§10).
            std::process::abort();
        }
    }
}

/// Maps a `windows::core::Error` (HRESULT) back to the underlying Win32 error code so
/// `io::Error::kind()` works (e.g. `BrokenPipe`).
fn io_error_from_win(e: &windows::core::Error) -> std::io::Error {
    let code = e.code().0 as u32;
    let raw = if (code & 0xFFFF_0000) == 0x8007_0000 {
        (code & 0xFFFF) as i32
    } else {
        code as i32
    };
    std::io::Error::from_raw_os_error(raw)
}

/// Lightweight handle wrapper allowing scoped client impersonation for individual rules
/// while `NamedPipeServer` is borrowed by a progress mutex (§9.3, §10.6).
#[derive(Clone, Copy, Debug)]
pub struct PipeClientImpersonator {
    handle: HANDLE,
}

unsafe impl Send for PipeClientImpersonator {}
unsafe impl Sync for PipeClientImpersonator {}

impl PipeClientImpersonator {
    /// Impersonates the connected named pipe client on the calling thread and returns an RAII guard
    /// that unconditionally calls `RevertToSelf()` on drop.
    pub fn impersonate(&self) -> Result<PipeImpersonationGuard> {
        // SAFETY: Impersonating connected named pipe client on current thread.
        unsafe { ImpersonateNamedPipeClient(self.handle) }
            .map_err(|e| win32_err("ImpersonateNamedPipeClient", e.code().0 as u32))?;
        Ok(PipeImpersonationGuard {
            _not_send: core::marker::PhantomData,
        })
    }
}

/// Validates that `pipe_name` is a strictly local, safe named pipe path (`\\.\pipe\<leaf>`)
/// with no traversal, quotes, slashes, or shell metacharacters.
pub fn validate_local_pipe_name(pipe_name: &str) -> Result<()> {
    const PREFIX: &str = r"\\.\pipe\";
    if pipe_name.len() <= PREFIX.len() || pipe_name.len() > 220 {
        return Err(DskError::Ipc(format!(
            "invalid named pipe path length: '{pipe_name}'"
        )));
    }
    // `get` (not indexing) so a multi-byte UTF-8 character straddling the prefix boundary is
    // rejected instead of panicking.
    let (Some(prefix), Some(leaf)) = (pipe_name.get(..PREFIX.len()), pipe_name.get(PREFIX.len()..))
    else {
        return Err(DskError::Ipc(format!(
            "named pipe must start with '\\\\.\\pipe\\': '{pipe_name}'"
        )));
    };
    if !prefix.eq_ignore_ascii_case(PREFIX) {
        return Err(DskError::Ipc(format!(
            "named pipe must start with '\\\\.\\pipe\\': '{pipe_name}'"
        )));
    }
    if leaf.contains("..")
        || !leaf
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(DskError::Ipc(format!(
            "named pipe leaf contains unsafe characters: '{pipe_name}'"
        )));
    }
    Ok(())
}

/// Queries the current process token's User SID as a string (`S-1-5-...`) using an 8-byte aligned buffer.
pub fn current_user_sid_string() -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: Querying current process token for User SID.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| win32_err("OpenProcessToken", e.code().0 as u32))?;
    let _token_guard = HandleGuard(token);

    let mut ret_len = 0u32;
    // SAFETY: First probe to determine required buffer size for TokenUser.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut ret_len) };

    if ret_len == 0 {
        return Err(win32_err(
            "GetTokenInformation(probe)",
            unsafe { GetLastError() }.0,
        ));
    }

    // Allocate 8-byte aligned buffer to satisfy TOKEN_USER pointer alignment requirements.
    let mut aligned_buf = vec![0u64; (ret_len as usize).div_ceil(8)];
    // SAFETY: Querying TokenUser into 8-byte aligned buffer of sufficient byte length.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(aligned_buf.as_mut_ptr() as *mut c_void),
            (aligned_buf.len() * 8) as u32,
            &mut ret_len,
        )
    }
    .map_err(|e| win32_err("GetTokenInformation(User)", e.code().0 as u32))?;

    // SAFETY: aligned_buf is 8-byte aligned and initialized by GetTokenInformation(TokenUser).
    let token_user = unsafe { &*(aligned_buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;

    let mut sid_pwstr = PWSTR::null();
    // SAFETY: Converting valid binary SID pointer to string SID.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut sid_pwstr) };
    if ok.is_err() {
        return Err(win32_err(
            "ConvertSidToStringSidW",
            unsafe { GetLastError() }.0,
        ));
    }

    let sid_str = unsafe { sid_pwstr.to_string() };
    // SAFETY: Freeing local memory allocated by ConvertSidToStringSidW (on every path).
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_pwstr.0 as *mut c_void)));
    }

    sid_str.map_err(|e| DskError::HelperAuth(format!("failed to convert SID to string: {e}")))
}

/// Accepts only user-account SIDs (local/domain `S-1-5-21-…`, Entra ID `S-1-12-1-…`) for the
/// over-the-shoulder client ACE. Well-known group SIDs such as Everyone (`S-1-1-0`) or
/// Authenticated Users (`S-1-5-11`) must never be granted pipe access via a crafted `--pipe`.
fn is_valid_sid_syntax(sid: &str) -> bool {
    (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
        && sid.len() <= 128
        && sid[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
        && !sid.ends_with('-')
        && !sid.contains("--")
}

fn extract_client_sid_from_pipe_name(pipe_name: &str) -> Option<&str> {
    let rest = pipe_name.strip_prefix(r"\\.\pipe\DiskSaverHelper_")?;
    let sid_candidate = rest.split('_').next()?;
    if is_valid_sid_syntax(sid_candidate) {
        Some(sid_candidate)
    } else {
        None
    }
}

/// Computes the default pipe name scoped to the current interactive user's SID and session ID.
///
/// Format: `\\.\pipe\DiskSaverHelper_<USER_SID>_<SESSION_ID>` (§10.3).
pub fn default_pipe_name() -> Result<String> {
    let sid_str = current_user_sid_string()?;

    let pid = unsafe { GetCurrentProcessId() };
    let mut session_id = 0u32;
    // SAFETY: Querying session ID for process ID.
    let sess_ok = unsafe { ProcessIdToSessionId(pid, &mut session_id) };
    if sess_ok.is_err() {
        session_id = 0;
    }

    Ok(format!(r"\\.\pipe\DiskSaverHelper_{sid_str}_{session_id}"))
}

const SQOS_SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const SQOS_SECURITY_IMPERSONATION: u32 = 0x0002_0000;

/// Hardened Win32 Named Pipe server instance.
pub struct NamedPipeServer {
    handle: HANDLE,
    connected: bool,
}

unsafe impl Send for NamedPipeServer {}
unsafe impl Sync for NamedPipeServer {}

impl NamedPipeServer {
    /// Creates the single first instance of a secure Named Pipe server with explicit DACL.
    ///
    /// The DACL grants full control strictly to `SYSTEM` (`SY`) and `Builtin Administrators` (`BA`),
    /// and read/write access to the current interactive user's SID (`GRGW`) (§10.3).
    pub fn create_first_instance(pipe_name: &str) -> Result<Self> {
        validate_local_pipe_name(pipe_name)?;

        // Fail closed: never widen the DACL to every interactive user (`IU`) if the token query fails.
        let self_sid = current_user_sid_string()?;
        let mut sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{self_sid})");
        if let Some(client_sid) = extract_client_sid_from_pipe_name(pipe_name)
            && !client_sid.eq_ignore_ascii_case(&self_sid)
        {
            // Support Over-the-Shoulder UAC where the unelevated client's SID differs from the elevated token SID.
            sddl.push_str(&format!("(A;;GRGW;;;{client_sid})"));
        }
        let sddl_w = to_wide(&sddl);

        let mut p_sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: Converting SDDL string to binary security descriptor.
        let sd_ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1,
                &mut p_sd,
                None,
            )
        };
        if sd_ok.is_err() {
            return Err(win32_err(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                unsafe { GetLastError() }.0,
            ));
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: p_sd.0,
            bInheritHandle: false.into(),
        };

        let pipe_w = to_wide(pipe_name);
        // SAFETY: Creating named pipe server with FILE_FLAG_FIRST_PIPE_INSTANCE and PIPE_REJECT_REMOTE_CLIENTS.
        let h = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                5000,
                Some(&sa),
            )
        };

        // SAFETY: Freeing security descriptor allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(p_sd.0)));
        }

        if h.is_invalid() {
            let err = unsafe { GetLastError() };
            return Err(win32_err("CreateNamedPipeW", err.0));
        }

        Ok(Self {
            handle: h,
            connected: false,
        })
    }

    /// Waits for a client connection and verifies that the client binary is located in `expected_dir`.
    ///
    /// If peer verification fails, the connection is immediately severed (§10.4).
    pub fn wait_for_verified_client(&mut self, expected_dir: &Path) -> Result<u32> {
        // SAFETY: Waiting for client connection on named pipe.
        let conn_res = unsafe { ConnectNamedPipe(self.handle, None) };
        if let Err(e) = conn_res {
            let raw_code = e.code().0 as u32;
            let code = if (raw_code & 0xFFFF_0000) == 0x8007_0000 {
                raw_code & 0xFFFF
            } else {
                raw_code
            };
            if code != ERROR_PIPE_CONNECTED.0 {
                return Err(DskError::Win32 {
                    ctx: "ConnectNamedPipe",
                    code,
                });
            }
        }
        self.connected = true;

        let mut client_pid = 0u32;
        // SAFETY: Retrieving peer process ID of connected client.
        let pid_res = unsafe { GetNamedPipeClientProcessId(self.handle, &mut client_pid) };
        if let Err(e) = pid_res {
            let _ = self.disconnect();
            return Err(win32_err("GetNamedPipeClientProcessId", e.code().0 as u32));
        }

        // SAFETY: Opening process with query limited information to inspect executable path.
        let h_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid) };
        let h_proc = match h_proc {
            Ok(h) => h,
            Err(e) => {
                let _ = self.disconnect();
                return Err(win32_err("OpenProcess(peer)", e.code().0 as u32));
            }
        };
        let _proc_guard = HandleGuard(h_proc);

        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        // SAFETY: Querying full process image name of the client process, retrying with a larger buffer if needed.
        let mut q_res = unsafe {
            QueryFullProcessImageNameW(
                h_proc,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        if q_res.is_err() {
            buf.resize(32_768, 0);
            len = buf.len() as u32;
            q_res = unsafe {
                QueryFullProcessImageNameW(
                    h_proc,
                    PROCESS_NAME_FORMAT(0),
                    PWSTR(buf.as_mut_ptr()),
                    &mut len,
                )
            };
        }
        if let Err(e) = q_res {
            let _ = self.disconnect();
            return Err(win32_err("QueryFullProcessImageNameW", e.code().0 as u32));
        }

        let exe_path_str = String::from_utf16_lossy(&buf[..len as usize]);
        let exe_path = PathBuf::from(&exe_path_str);
        let client_dir = exe_path.parent().unwrap_or(Path::new(""));

        let canon_client_dir =
            std::fs::canonicalize(client_dir).unwrap_or_else(|_| client_dir.to_path_buf());
        let canon_expected_dir =
            std::fs::canonicalize(expected_dir).unwrap_or_else(|_| expected_dir.to_path_buf());

        let norm_client_dir = normalize_win_path_str(&canon_client_dir);
        let norm_expected_dir = normalize_win_path_str(&canon_expected_dir);

        if norm_client_dir != norm_expected_dir {
            let _ = self.disconnect();
            return Err(DskError::HelperAuth(format!(
                "client image '{}' in '{}' does not match expected dir '{}'",
                exe_path.display(),
                norm_client_dir,
                norm_expected_dir
            )));
        }

        Ok(client_pid)
    }

    /// Returns a copyable [`PipeClientImpersonator`] handle for scoped per-rule impersonation.
    pub fn impersonator(&self) -> PipeClientImpersonator {
        PipeClientImpersonator {
            handle: self.handle,
        }
    }

    /// Impersonates the connected client on the current calling thread.
    ///
    /// Returns an RAII [`PipeImpersonationGuard`] that unconditionally calls `RevertToSelf()` on drop.
    pub fn impersonate_client(&self) -> Result<PipeImpersonationGuard> {
        self.impersonator().impersonate()
    }

    /// Disconnects the current client from the pipe server.
    pub fn disconnect(&mut self) -> Result<()> {
        if self.connected {
            // SAFETY: Disconnecting named pipe instance.
            unsafe {
                let _ = DisconnectNamedPipe(self.handle);
            }
            self.connected = false;
        }
        Ok(())
    }
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        if self.connected && !self.handle.is_invalid() {
            // SAFETY: Flushes buffered data to client before closing.
            unsafe {
                let _ = FlushFileBuffers(self.handle);
            }
        }
        let _ = self.disconnect();
        if !self.handle.is_invalid() {
            // SAFETY: Closing server handle on drop.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl Read for NamedPipeServer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0u32;
        // SAFETY: Reading bytes from connected named pipe.
        let res = unsafe { ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None) };
        match res {
            Ok(()) => Ok(bytes_read as usize),
            Err(e) => {
                let last = unsafe { GetLastError() };
                if last == ERROR_PIPE_CONNECTED || last == ERROR_MORE_DATA {
                    Ok(bytes_read as usize)
                } else if last == ERROR_NO_DATA || last == WIN32_ERROR(109) {
                    // ERROR_BROKEN_PIPE
                    Ok(0)
                } else {
                    Err(io_error_from_win(&e))
                }
            }
        }
    }
}

impl Write for NamedPipeServer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes_written = 0u32;
        // SAFETY: Writing bytes to connected named pipe.
        let res = unsafe { WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None) };
        match res {
            Ok(()) => Ok(bytes_written as usize),
            Err(e) => Err(io_error_from_win(&e)),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.connected && !self.handle.is_invalid() {
            // SAFETY: FlushFileBuffers on a named pipe blocks until client reads all data.
            let res = unsafe { FlushFileBuffers(self.handle) };
            if let Err(e) = res {
                let last = unsafe { GetLastError() };
                if last == ERROR_PIPE_CONNECTED || last == WIN32_ERROR(109) {
                    return Ok(());
                }
                return Err(io_error_from_win(&e));
            }
        }
        Ok(())
    }
}

/// Hardened Win32 Named Pipe client connection.
pub struct NamedPipeClient {
    handle: HANDLE,
}

unsafe impl Send for NamedPipeClient {}
unsafe impl Sync for NamedPipeClient {}

impl NamedPipeClient {
    /// Connects to a Named Pipe server with standard impersonation levels and timeout.
    pub fn connect(pipe_name: &str, timeout: Duration) -> Result<Self> {
        validate_local_pipe_name(pipe_name)?;
        let pipe_w = to_wide(pipe_name);
        let start = Instant::now();

        loop {
            // SAFETY: Opening local named pipe with FILE_SHARE_NONE and security impersonation attributes.
            let h = unsafe {
                CreateFileW(
                    PCWSTR(pipe_w.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(
                        SQOS_SECURITY_SQOS_PRESENT | SQOS_SECURITY_IMPERSONATION,
                    ),
                    None,
                )
            };

            match h {
                Ok(handle) => return Ok(Self { handle }),
                Err(_) => {
                    let err = unsafe { GetLastError() };
                    if err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND {
                        return Err(win32_err("CreateFileW(pipe)", err.0));
                    }

                    if start.elapsed() >= timeout {
                        return Err(DskError::Ipc(format!(
                            "timed out connecting to named pipe '{pipe_name}' after {timeout:?}"
                        )));
                    }

                    let remaining_ms =
                        (timeout.saturating_sub(start.elapsed()).as_millis()).min(500) as u32;
                    if err == ERROR_FILE_NOT_FOUND {
                        // No instance exists yet: WaitNamedPipeW returns immediately in this case,
                        // so back off instead of spinning a core until the timeout.
                        std::thread::sleep(Duration::from_millis(u64::from(remaining_ms.min(25))));
                    } else {
                        // SAFETY: Waiting for a busy named pipe instance to become available.
                        let _ = unsafe { WaitNamedPipeW(PCWSTR(pipe_w.as_ptr()), remaining_ms) };
                    }
                }
            }
        }
    }
}

impl Drop for NamedPipeClient {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: Closing client handle on drop.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0u32;
        // SAFETY: Reading bytes from named pipe client handle.
        let res = unsafe { ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None) };
        match res {
            Ok(()) => Ok(bytes_read as usize),
            Err(e) => {
                let last = unsafe { GetLastError() };
                if last == ERROR_PIPE_CONNECTED || last == ERROR_MORE_DATA {
                    Ok(bytes_read as usize)
                } else if last == ERROR_NO_DATA || last == WIN32_ERROR(109) {
                    // ERROR_BROKEN_PIPE
                    Ok(0)
                } else {
                    Err(io_error_from_win(&e))
                }
            }
        }
    }
}

impl Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes_written = 0u32;
        // SAFETY: Writing bytes to named pipe client handle.
        let res = unsafe { WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None) };
        match res {
            Ok(()) => Ok(bytes_written as usize),
            Err(e) => Err(io_error_from_win(&e)),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn is_trusted_admin_or_system_trustee(trustee: &str) -> bool {
    let t = trustee.trim().to_ascii_uppercase();
    matches!(
        t.as_str(),
        "SY" | "BA" | "LA" | "LS" | "NS" | "CO" | "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544" | "S-1-3-0"
    ) || t.starts_with("S-1-5-80-") // NT SERVICE\TrustedInstaller and service SIDs
        || (t.starts_with("S-1-5-21-") && t.ends_with("-500")) // Built-in domain/local Administrator
}

/// Write-class access bits for files/directories: GENERIC_ALL | GENERIC_WRITE | WRITE_OWNER |
/// WRITE_DAC | DELETE | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | FILE_WRITE_EA |
/// FILE_APPEND_DATA/ADD_SUBDIRECTORY | FILE_WRITE_DATA/ADD_FILE.
const WRITE_CLASS_MASK: u32 = 0x500D_0156;
/// SDDL two-letter rights tokens that map onto [`WRITE_CLASS_MASK`] bits for file objects
/// (`DC`=0x2, `LC`=0x4, `RP`=0x10, `DT`=0x40, `CR`=0x100 reuse the DS token letters).
const WRITE_CLASS_TOKENS: &[&str] = &[
    "GA", "GW", "FA", "FW", "KA", "KW", "WD", "WO", "SD", "DC", "LC", "RP", "DT", "CR",
];

/// Rights that let a principal rename/delete the object itself or its children, or rewrite the
/// DACL/owner to grant themselves that: GENERIC_ALL | WRITE_OWNER | WRITE_DAC | DELETE |
/// FILE_DELETE_CHILD.
const RENAME_CLASS_MASK: u32 = 0x100D_0040;
const RENAME_CLASS_TOKENS: &[&str] = &["GA", "FA", "KA", "WD", "WO", "SD", "DT"];

/// Returns `true` when an SDDL rights field intersects `mask` / `tokens`. Unknown formats fail
/// closed (`true`).
fn ace_rights_intersect(rights: &str, mask: u32, tokens: &[&str]) -> bool {
    let r = rights.trim().to_ascii_uppercase();
    if let Some(hex) = r.strip_prefix("0X") {
        return match u32::from_str_radix(hex, 16) {
            Ok(m) => m & mask != 0,
            Err(_) => true,
        };
    }
    if r.is_empty() {
        return false;
    }
    if !r.is_ascii() || !r.len().is_multiple_of(2) {
        return true;
    }
    r.as_bytes()
        .chunks(2)
        .any(|tok| tokens.iter().any(|t| t.as_bytes() == tok))
}

/// Parsed view of the Owner and DACL portions of an SDDL string.
struct SddlView<'a> {
    owner: Option<&'a str>,
    /// `None` when the descriptor carries no `D:` section (a missing DACL grants everyone access).
    dacl: Option<&'a str>,
}

/// Length of the SID token at the start of `body`: either a string SID (`S-1-5-...`) or a
/// two-letter SDDL alias (`BA`, `SY`, ...).
fn sddl_sid_token_len(body: &str) -> usize {
    let b = body.as_bytes();
    if b.len() >= 2 && b[0] == b'S' && b[1] == b'-' {
        1 + b[1..]
            .iter()
            .take_while(|c| c.is_ascii_digit() || **c == b'-')
            .count()
    } else {
        b.len().min(2)
    }
}

/// Sequentially parses `O:`, `G:`, `D:` and `S:` sections. Anything unexpected stops parsing;
/// callers treat a missing DACL as NULL (fail closed).
fn split_sddl(sddl: &str) -> SddlView<'_> {
    let mut view = SddlView {
        owner: None,
        dacl: None,
    };
    let mut rest = sddl.trim();
    while rest.len() >= 2 && rest.as_bytes()[1] == b':' {
        let tag = rest.as_bytes()[0];
        let body = &rest[2..];
        match tag {
            b'O' | b'G' => {
                let len = sddl_sid_token_len(body);
                if tag == b'O' {
                    view.owner = Some(&body[..len]);
                }
                rest = &body[len..];
            }
            b'D' => {
                // Only an `S:` (SACL) section can follow the DACL; it never appears inside ACEs at
                // depth 0, and DACL flags (`P`, `AI`, `AR`, `NO_ACCESS_CONTROL`) never contain `S:`.
                let mut depth = 0usize;
                let mut end = body.len();
                let bytes = body.as_bytes();
                for (i, &c) in bytes.iter().enumerate() {
                    match c {
                        b'(' => depth += 1,
                        b')' => depth = depth.saturating_sub(1),
                        b'S' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                            end = i;
                            break;
                        }
                        _ => {}
                    }
                }
                view.dacl = Some(&body[..end]);
                rest = &body[end..];
            }
            _ => break,
        }
    }
    view
}

/// Iterates `(ace_type, ace_flags, rights, trustee)` tuples of a DACL section. Malformed ACEs
/// are yielded with an empty trustee so callers fail closed.
fn dacl_aces(dacl: &str) -> Vec<(&str, &str, &str, &str)> {
    let mut out = Vec::new();
    let mut rest = dacl;
    while let Some(open_idx) = rest.find('(') {
        let after_open = &rest[open_idx + 1..];
        let close_idx = after_open.find(')').unwrap_or(after_open.len());
        let ace = &after_open[..close_idx];
        rest = after_open.get(close_idx + 1..).unwrap_or("");
        let parts: Vec<&str> = ace.split(';').map(str::trim).collect();
        if parts.len() < 6 {
            out.push(("A", "", "GA", ""));
            continue;
        }
        out.push((parts[0], parts[1], parts[2], parts[5]));
    }
    out
}

fn is_allow_ace_type(ace_type: &str) -> bool {
    // ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT, ACCESS_ALLOWED_CALLBACK, ACCESS_ALLOWED_CALLBACK_OBJECT.
    matches!(
        ace_type.to_ascii_uppercase().as_str(),
        "A" | "OA" | "XA" | "ZA"
    )
}

fn ace_flags_inherit_only(flags: &str) -> bool {
    flags
        .to_ascii_uppercase()
        .as_bytes()
        .chunks(2)
        .any(|tok| tok == b"IO")
}

fn dacl_is_null(dacl: Option<&str>) -> bool {
    match dacl {
        None => true,
        Some(d) => d.to_ascii_uppercase().contains("NO_ACCESS_CONTROL"),
    }
}

/// Pure SDDL analyzer returning `true` if the security descriptor string grants write/modify/owner
/// permissions to any non-admin/non-system principal (§10.3).
///
/// Fails closed: a non-admin owner, a missing or NULL DACL (`D:NO_ACCESS_CONTROL`), malformed ACEs,
/// and unknown rights encodings are all reported as writable. Inherit-only ACEs are inspected too,
/// because they let standard users create writable children (DLL planting).
pub fn sddl_grants_non_admin_write(sddl: &str) -> bool {
    let view = split_sddl(sddl);
    if let Some(owner) = view.owner
        && !owner.is_empty()
        && !is_trusted_admin_or_system_trustee(owner)
    {
        return true;
    }
    if dacl_is_null(view.dacl) {
        return true;
    }
    dacl_aces(view.dacl.unwrap_or(""))
        .into_iter()
        .any(|(ty, _flags, rights, trustee)| {
            is_allow_ace_type(ty)
                && ace_rights_intersect(rights, WRITE_CLASS_MASK, WRITE_CLASS_TOKENS)
                && !is_trusted_admin_or_system_trustee(trustee)
        })
}

/// Pure SDDL analyzer returning `true` if a non-admin principal can rename/delete this object or
/// its children (or rewrite its DACL/owner to obtain that). Used on the ancestors of an install
/// directory: if any ancestor is renamable by standard users they can swap the whole tree.
///
/// Inherit-only ACEs are ignored because they do not apply to the object itself.
pub fn sddl_allows_non_admin_rename(sddl: &str) -> bool {
    let view = split_sddl(sddl);
    if let Some(owner) = view.owner
        && !owner.is_empty()
        && !is_trusted_admin_or_system_trustee(owner)
    {
        return true;
    }
    if dacl_is_null(view.dacl) {
        return true;
    }
    dacl_aces(view.dacl.unwrap_or(""))
        .into_iter()
        .any(|(ty, flags, rights, trustee)| {
            is_allow_ace_type(ty)
                && !ace_flags_inherit_only(flags)
                && ace_rights_intersect(rights, RENAME_CLASS_MASK, RENAME_CLASS_TOKENS)
                && !is_trusted_admin_or_system_trustee(trustee)
        })
}

/// Reads the Owner + DACL of `path` (file or directory) as an SDDL string.
pub fn query_path_owner_dacl_sddl(path: &Path) -> Result<String> {
    let path_w = to_wide(&path.to_string_lossy());
    let sec_info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
    let mut needed = 0u32;

    // SAFETY: Probing required buffer length for the security descriptor.
    let _ = unsafe { GetFileSecurityW(PCWSTR(path_w.as_ptr()), sec_info.0, None, 0, &mut needed) };
    if needed == 0 {
        return Err(win32_err(
            "GetFileSecurityW(probe)",
            unsafe { GetLastError() }.0,
        ));
    }

    let mut aligned_buf = vec![0u64; (needed as usize).div_ceil(8)];
    let p_sd = PSECURITY_DESCRIPTOR(aligned_buf.as_mut_ptr() as *mut c_void);

    // SAFETY: Reading the security descriptor into an 8-byte aligned buffer of `needed` bytes.
    let ok = unsafe {
        GetFileSecurityW(
            PCWSTR(path_w.as_ptr()),
            sec_info.0,
            Some(p_sd),
            (aligned_buf.len() * 8) as u32,
            &mut needed,
        )
    };
    if !ok.as_bool() {
        return Err(win32_err("GetFileSecurityW", unsafe { GetLastError() }.0));
    }

    let mut sddl_pwstr = PWSTR::null();
    let mut sddl_len = 0u32;
    // SAFETY: Converting the binary security descriptor (alive in `aligned_buf`) to SDDL.
    let conv = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            p_sd,
            SDDL_REVISION_1,
            sec_info,
            &mut sddl_pwstr,
            Some(&mut sddl_len),
        )
    };
    if let Err(e) = conv {
        return Err(win32_err(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            e.code().0 as u32,
        ));
    }
    if sddl_pwstr.is_null() {
        return Err(DskError::Io(std::io::Error::other(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW returned a null string",
        )));
    }

    // SAFETY: `sddl_pwstr` is a NUL-terminated LocalAlloc'd UTF-16 string.
    let sddl = unsafe { sddl_pwstr.to_string() };
    // SAFETY: Freeing SDDL string buffer allocated by ConvertSecurityDescriptorToStringSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sddl_pwstr.0 as *mut c_void)));
    }
    sddl.map_err(|e| DskError::Io(std::io::Error::other(format!("invalid SDDL UTF-16: {e}"))))
}

/// Checks if a directory (or file) is writable by standard (non-elevated) users by inspecting its
/// security descriptor (Owner and DACL) without mutating the filesystem (§10.3).
///
/// Fails closed: if the descriptor cannot be read or converted, the path is treated as writable.
pub fn is_directory_user_writable(dir: &Path) -> bool {
    match query_path_owner_dacl_sddl(dir) {
        Ok(sddl) => sddl_grants_non_admin_write(&sddl),
        Err(_) => true,
    }
}

/// Returns `true` if standard users could rename/delete `dir` or its children (or rewrite its
/// DACL/owner). Fails closed when the descriptor cannot be read.
pub fn is_directory_user_renamable(dir: &Path) -> bool {
    match query_path_owner_dacl_sddl(dir) {
        Ok(sddl) => sddl_allows_non_admin_rename(&sddl),
        Err(_) => true,
    }
}

/// Launches `dsk-helper.exe` via UAC elevation (`runas` verb) pointing to `pipe_name`.
pub fn launch_elevated_helper(helper_exe: &Path, pipe_name: &str) -> Result<u32> {
    validate_local_pipe_name(pipe_name)?;

    let verb_w = to_wide("runas");
    let exe_w = to_wide(&helper_exe.to_string_lossy());
    let params = format!("--pipe \"{pipe_name}\"");
    let params_w = to_wide(&params);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: core::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    // SAFETY: Invoking ShellExecuteExW with verb 'runas' to trigger Windows UAC elevation prompt.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok.is_err() {
        let err = unsafe { GetLastError() };
        if err == ERROR_ACCESS_DENIED || err.0 == 1223 {
            // ERROR_CANCELLED (user declined UAC)
            return Err(DskError::Cancelled);
        }
        return Err(win32_err("ShellExecuteExW(runas)", err.0));
    }

    if info.hProcess.is_invalid() {
        return Ok(0);
    }

    // SAFETY: info.hProcess is a valid process handle returned by ShellExecuteExW with SEE_MASK_NOCLOSEPROCESS.
    let pid = unsafe { GetProcessId(info.hProcess) };
    unsafe {
        let _ = CloseHandle(info.hProcess);
    }

    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{
        HelperRequest, HelperResponse, MAX_CONTROL_FRAME_BYTES, read_frame, write_frame,
    };

    #[test]
    fn default_pipe_name_produces_valid_syntax() {
        let name = default_pipe_name().expect("default pipe name query");
        assert!(name.starts_with(r"\\.\pipe\DiskSaverHelper_"));
        assert!(name.contains("S-1-5-"));
    }

    #[test]
    fn named_pipe_first_instance_blocks_duplicate_server_bind() {
        let pipe_name = format!(r"\\.\pipe\DiskSaverHelper_TestDup_{}", std::process::id());
        let server1 = NamedPipeServer::create_first_instance(&pipe_name)
            .expect("first instance must succeed");

        // Second instance on the same pipe name must fail with ACCESS_DENIED or ALREADY_EXISTS
        let server2 = NamedPipeServer::create_first_instance(&pipe_name);
        assert!(server2.is_err());

        drop(server1);
    }

    #[test]
    fn named_pipe_client_server_roundtrip_verifies_same_directory_peer_pid() {
        let pipe_name = format!(
            r"\\.\pipe\DiskSaverHelper_TestRoundtrip_{}",
            std::process::id()
        );
        let mut server = NamedPipeServer::create_first_instance(&pipe_name).expect("server create");

        let current_exe = std::env::current_exe().expect("current exe");
        let current_dir = current_exe.parent().expect("parent dir");

        let current_dir_clone = current_dir.to_path_buf();

        let server_thread = std::thread::spawn(move || {
            let client_pid = server
                .wait_for_verified_client(&current_dir_clone)
                .expect("verified client connect");
            assert_eq!(client_pid, std::process::id());

            let req: HelperRequest =
                read_frame(&mut server, MAX_CONTROL_FRAME_BYTES).expect("read ping");
            assert_eq!(req, HelperRequest::Ping);

            let resp = HelperResponse::Pong {
                helper_pid: std::process::id(),
                version: "0.1.0".to_string(),
            };
            write_frame(&mut server, &resp, MAX_CONTROL_FRAME_BYTES).expect("write pong");
        });

        let mut client =
            NamedPipeClient::connect(&pipe_name, Duration::from_secs(5)).expect("client connect");

        write_frame(&mut client, &HelperRequest::Ping, MAX_CONTROL_FRAME_BYTES)
            .expect("client write");
        let resp: HelperResponse =
            read_frame(&mut client, MAX_CONTROL_FRAME_BYTES).expect("client read");

        assert!(matches!(resp, HelperResponse::Pong { .. }));
        server_thread.join().expect("server thread finish");
    }

    #[test]
    fn named_pipe_rejects_client_when_expected_directory_mismatches() {
        let pipe_name = format!(
            r"\\.\pipe\DiskSaverHelper_TestReject_{}",
            std::process::id()
        );
        let mut server = NamedPipeServer::create_first_instance(&pipe_name).expect("server create");

        let fake_dir = Path::new(r"C:\NonExistentDiskSaverExpectedDirectory");

        let server_thread = std::thread::spawn(move || {
            let res = server.wait_for_verified_client(fake_dir);
            assert!(
                matches!(res, Err(DskError::HelperAuth(_))),
                "expected HelperAuth rejection, got: {:?}",
                res
            );
        });

        let client = NamedPipeClient::connect(&pipe_name, Duration::from_secs(5));
        server_thread.join().expect("server thread finish");
        drop(client);
    }

    #[test]
    fn impersonation_guard_reverts_cleanly_on_drop() {
        let pipe_name = format!(r"\\.\pipe\DiskSaverHelper_TestImp_{}", std::process::id());
        let mut server = NamedPipeServer::create_first_instance(&pipe_name).expect("server create");

        let current_exe = std::env::current_exe().expect("current exe");
        let current_dir = current_exe.parent().expect("parent dir").to_path_buf();

        let server_thread = std::thread::spawn(move || {
            server
                .wait_for_verified_client(&current_dir)
                .expect("verified client connect");

            {
                let guard = server.impersonate_client().expect("impersonate client");
                // Dropping guard invokes RevertToSelf()
                drop(guard);
            }
        });

        let client =
            NamedPipeClient::connect(&pipe_name, Duration::from_secs(5)).expect("client connect");
        server_thread.join().expect("server thread finish");
        drop(client);
    }

    #[test]
    fn validate_local_pipe_name_blocks_injection_and_remote_pipes() {
        assert!(validate_local_pipe_name(r"\\.\pipe\DiskSaverHelper_S-1-5-21-123_1").is_ok());
        assert!(validate_local_pipe_name(r"\\192.168.1.1\pipe\DiskSaverHelper").is_err());
        assert!(validate_local_pipe_name(r"\\.\pipe\..\evil").is_err());
        assert!(
            validate_local_pipe_name(r#"\\.\pipe\DiskSaver" --allow-unelevated-test"#).is_err()
        );
        assert!(validate_local_pipe_name(r"\\.\pipe\").is_err());
    }

    #[test]
    fn sddl_grants_non_admin_write_detects_standard_user_aces_and_owners() {
        // Admin/SYSTEM/TrustedInstaller only (like C:\Program Files)
        let admin_only = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICI;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
        assert!(!sddl_grants_non_admin_write(admin_only));

        // Authenticated Users (AU) granted modify/write
        let user_writable = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)";
        assert!(sddl_grants_non_admin_write(user_writable));

        // Non-admin user owner
        let user_owned = "O:S-1-5-21-111-222-333-1001D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        assert!(sddl_grants_non_admin_write(user_owned));
    }

    // Representative Windows 11 security descriptors (Owner + DACL only; user SID anonymized).
    const SDDL_PROGRAM_FILES: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)";
    const SDDL_DRIVE_ROOT: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)";
    const SDDL_PROGRAM_DATA: &str = "O:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)";
    const SDDL_LOCAL_APPDATA: &str = "O:S-1-5-21-1000000000-2000000000-3000000000-1001D:AI(A;OICIID;FA;;;S-1-5-21-1000000000-2000000000-3000000000-1001)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)";
    /// A folder created by an administrator directly under `C:\` inherits `Modify` for
    /// Authenticated Users from the drive root's `OICIIO;SDGXGWGR;;;AU` ACE.
    const SDDL_ADMIN_CREATED_UNDER_ROOT: &str = "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)";

    #[test]
    fn sddl_write_analyzer_matches_real_system_descriptors() {
        assert!(!sddl_grants_non_admin_write(SDDL_PROGRAM_FILES));
        assert!(!sddl_grants_non_admin_write(
            crate::win::install::PROTECTED_INSTALL_SDDL
        ));
        // Users may create folders (LC) on C:\ and files (DC) in ProgramData.
        assert!(sddl_grants_non_admin_write(SDDL_DRIVE_ROOT));
        assert!(sddl_grants_non_admin_write(SDDL_PROGRAM_DATA));
        assert!(sddl_grants_non_admin_write(SDDL_LOCAL_APPDATA));
        assert!(sddl_grants_non_admin_write(SDDL_ADMIN_CREATED_UNDER_ROOT));
    }

    #[test]
    fn sddl_write_analyzer_fails_closed_on_null_missing_or_odd_dacls() {
        // NULL DACL grants Everyone full access.
        assert!(sddl_grants_non_admin_write("O:BAD:NO_ACCESS_CONTROL"));
        // No DACL section at all is treated the same way.
        assert!(sddl_grants_non_admin_write("O:BA"));
        assert!(sddl_grants_non_admin_write(""));
        // Unparseable hex rights and malformed ACEs fail closed.
        assert!(sddl_grants_non_admin_write("O:BAD:P(A;;0xZZ;;;BU)"));
        assert!(sddl_grants_non_admin_write("O:BAD:P(A;;FA)"));
        // Rights spelled as DS-style tokens (FILE_ADD_FILE = DC, FILE_DELETE_CHILD = DT).
        assert!(sddl_grants_non_admin_write("O:BAD:P(A;;DC;;;BU)"));
        assert!(sddl_grants_non_admin_write("O:BAD:P(A;;DT;;;WD)"));
        assert!(sddl_grants_non_admin_write("O:BAD:P(A;;0x40;;;BU)"));
        // Callback / object allow ACEs count as allow ACEs.
        assert!(sddl_grants_non_admin_write("O:BAD:P(XA;;FA;;;WD;(x))"));
        // An empty (but present) DACL denies everyone.
        assert!(!sddl_grants_non_admin_write("O:BAD:P"));
        // Two-letter owner aliases directly followed by `D:` parse correctly.
        assert!(!sddl_grants_non_admin_write("O:SYD:P(A;;FA;;;SY)"));
        assert!(sddl_grants_non_admin_write("O:BUD:P(A;;FA;;;SY)"));
    }

    #[test]
    fn sddl_rename_analyzer_flags_only_renamable_ancestors() {
        assert!(!sddl_allows_non_admin_rename(SDDL_PROGRAM_FILES));
        // Users can create folders on C:\ but not delete/rename existing children.
        assert!(!sddl_allows_non_admin_rename(SDDL_DRIVE_ROOT));
        assert!(!sddl_allows_non_admin_rename(SDDL_PROGRAM_DATA));
        // User-owned profile folders and admin-created C:\<folder> (AU Modify incl. DELETE) are
        // renamable by standard users.
        assert!(sddl_allows_non_admin_rename(SDDL_LOCAL_APPDATA));
        assert!(sddl_allows_non_admin_rename(SDDL_ADMIN_CREATED_UNDER_ROOT));
        assert!(sddl_allows_non_admin_rename("O:BAD:NO_ACCESS_CONTROL"));
        assert!(sddl_allows_non_admin_rename("O:BAD:P(A;;WD;;;BU)"));
    }

    #[test]
    fn live_writability_checks_fail_closed_and_match_system_dirs() {
        let missing = Path::new(r"C:\DiskSaverDefinitelyMissingDir\nested");
        assert!(is_directory_user_writable(missing));
        assert!(is_directory_user_renamable(missing));

        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(is_directory_user_writable(tmp.path()));
        assert!(is_directory_user_renamable(tmp.path()));

        let windir = crate::win::volume::system32_dir();
        let windir = windir.parent().expect("windows dir");
        assert!(!is_directory_user_writable(windir));
        assert!(!is_directory_user_renamable(windir));
    }

    #[test]
    fn pipe_name_client_sid_only_accepts_user_account_sids() {
        assert_eq!(
            extract_client_sid_from_pipe_name(r"\\.\pipe\DiskSaverHelper_S-1-5-21-11-22-33-1001_1"),
            Some("S-1-5-21-11-22-33-1001")
        );
        assert!(
            extract_client_sid_from_pipe_name(r"\\.\pipe\DiskSaverHelper_S-1-12-1-5-6-7-8_2")
                .is_some()
        );
        // Everyone, Authenticated Users, Interactive, and malformed SIDs are rejected.
        for bad in ["S-1-1-0", "S-1-5-11", "S-1-5-4", "S-1-5-21-", "S-1-5-21--1"] {
            let name = format!(r"\\.\pipe\DiskSaverHelper_{bad}_1");
            assert_eq!(extract_client_sid_from_pipe_name(&name), None, "{bad}");
        }
    }

    #[test]
    fn validate_local_pipe_name_rejects_multibyte_prefix_without_panicking() {
        assert!(validate_local_pipe_name("\\\\.\\pipeé_suffix").is_err());
        assert!(validate_local_pipe_name("é\\\\.\\pipe\\x").is_err());
    }
}
