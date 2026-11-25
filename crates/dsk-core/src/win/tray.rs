//! Lightweight Windows system tray monitor, background priority guard, and scheduled Safe Clean helper.

use std::collections::BTreeSet;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    SetStdHandle,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END,
};
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_NOSOUND, NIIF_WARNING, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, GetMessageW, HMENU, IDI_APPLICATION, IDYES, KillTimer,
    LoadIconW, MB_DEFBUTTON2, MB_ICONQUESTION, MB_SETFOREGROUND, MB_YESNO, MF_SEPARATOR, MF_STRING,
    MSG, MessageBoxW, PostMessageW, PostQuitMessage, RegisterClassExW, SetForegroundWindow,
    SetTimer, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
    TranslateMessage, UnregisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_DESTROY,
    WM_LBUTTONDBLCLK, WM_NULL, WM_RBUTTONUP, WM_TIMER, WNDCLASSEXW,
};
use windows::core::{PCWSTR, w};

use crate::error::{DskError, Result};
use crate::volume::VolumeInfo;
use crate::win::process::{BELOW_NORMAL_PRIORITY_CLASS, hidden_command, hidden_command_with_flags};
use crate::win::volume::{list_volumes, peak_working_set, system32_dir, volume_root_of};

/// Alert threshold: fewer than 10 GiB free.
pub const LOW_SPACE_BYTES_THRESHOLD: u64 = 10 * 1024 * 1024 * 1024;
/// Alert threshold: fewer than 5% free.
pub const LOW_SPACE_PCT_THRESHOLD: u64 = 5;
/// Hard resident working-set ceiling for `disksaver-tray.exe` (20 MiB).
pub const TRAY_FOOTPRINT_BUDGET_BYTES: u64 = 20 * 1024 * 1024;
/// Windows Task Scheduler task name registered by DiskSaver.
pub const SCHEDULED_TASK_NAME: &str = "DiskSaverSafeClean";

/// Default low-space poll interval for the tray loop. Each tick is a handful of
/// `GetDiskFreeSpaceExW` calls (no disk spin-up, ~0% CPU); repeat balloons are deduplicated by
/// [`should_notify_low_space`], so a short interval does not spam the user.
pub const TRAY_POLL_INTERVAL: Duration = Duration::from_secs(300);
/// The same set of low drives is re-announced at most once per this period.
pub const TRAY_REALERT_PERIOD: Duration = Duration::from_secs(24 * 3600);

const WM_TRAYICON: u32 = WM_APP + 1;
/// Posted by the Safe Clean worker thread: `wparam` = CLI exit code (`u32::MAX` = not started).
const WM_SAFE_CLEAN_DONE: u32 = WM_APP + 2;
const TRAY_ICON_ID: u32 = 1;
const TIMER_POLL_ID: usize = 1;

const IDM_OPEN_GUI: u32 = 1001;
const IDM_CHECK_NOW: u32 = 1002;
const IDM_SAFE_CLEAN: u32 = 1003;
const IDM_SCHEDULE_ENABLE: u32 = 1004;
const IDM_SCHEDULE_DISABLE: u32 = 1005;
const IDM_EXIT: u32 = 1006;

static TRAY_CLEAN_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
/// Last announced set of low-space drives and when it was announced.
static LAST_LOW_SPACE_ALERT: Mutex<Option<(BTreeSet<String>, Instant)>> = Mutex::new(None);

fn to_wide(s: &str) -> Vec<u16> {
    let mut out: Vec<u16> = s.encode_utf16().collect();
    out.push(0);
    out
}

fn write_utf16_fixed<const N: usize>(buf: &mut [u16; N], text: &str) {
    buf.fill(0);
    if N == 0 {
        return;
    }
    let mut i = 0usize;
    for unit in text.encode_utf16() {
        if i + 1 >= N {
            break;
        }
        buf[i] = unit;
        i += 1;
    }
    buf[i] = 0;
}

/// RAII guard placing the current thread into Windows background I/O + CPU priority
/// (`THREAD_MODE_BACKGROUND_BEGIN`) and restoring normal priority on [`Drop`].
pub struct BackgroundPriorityGuard {
    entered: bool,
    // Background mode is per-thread: the guard must be dropped on the thread that entered it.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl BackgroundPriorityGuard {
    /// Enters Windows background processing mode on the calling thread, failing if Win32 rejects it.
    pub fn enter() -> Result<Self> {
        // SAFETY: `GetCurrentThread()` returns a pseudo-handle to the calling thread that needs no close.
        // Passing `THREAD_MODE_BACKGROUND_BEGIN` adjusts only the calling thread's scheduling/IO priority.
        let res = unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) };
        res.map_err(|_| DskError::Win32 {
            ctx: "SetThreadPriority(THREAD_MODE_BACKGROUND_BEGIN)",
            code: unsafe { GetLastError().0 },
        })?;
        Ok(Self {
            entered: true,
            _not_send: core::marker::PhantomData,
        })
    }

    /// Best-effort variant for background loops where restricted job objects may disallow priority changes.
    pub fn try_enter() -> Self {
        match Self::enter() {
            Ok(guard) => guard,
            Err(_) => Self {
                entered: false,
                _not_send: core::marker::PhantomData,
            },
        }
    }

    /// Returns `true` if `THREAD_MODE_BACKGROUND_BEGIN` succeeded on this thread.
    pub fn is_active(&self) -> bool {
        self.entered
    }
}

impl Drop for BackgroundPriorityGuard {
    fn drop(&mut self) {
        if self.entered {
            // SAFETY: Paired with a successful `THREAD_MODE_BACKGROUND_BEGIN` on the same thread.
            unsafe {
                let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
            }
            self.entered = false;
        }
    }
}

/// Low-disk-space alert generated for a mounted volume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalloonAlert {
    pub root: String,
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub free_pct: u8,
    pub reason: String,
}

/// Output emitted by `disksaver-tray --check-once --json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayCheckReport {
    pub alerts: Vec<BalloonAlert>,
    pub checked_volumes: usize,
    pub peak_working_set_bytes: u64,
    pub background_priority_active: bool,
}

/// Evaluates mounted volumes against `< 10 GiB` OR `< 5%` free-space thresholds.
pub fn check_low_space_alerts(volumes: &[VolumeInfo]) -> Vec<BalloonAlert> {
    let mut alerts = Vec::new();
    for vol in volumes {
        if vol.total_bytes == 0 {
            continue;
        }
        let free_pct = ((u128::from(vol.free_bytes) * 100) / u128::from(vol.total_bytes)) as u8;
        let below_bytes = vol.free_bytes < LOW_SPACE_BYTES_THRESHOLD;
        let below_pct = (u128::from(vol.free_bytes) * 100)
            < (u128::from(vol.total_bytes) * u128::from(LOW_SPACE_PCT_THRESHOLD));
        if below_bytes || below_pct {
            let reason = match (below_bytes, below_pct) {
                (true, true) => {
                    format!("Below 10 GiB and below 5% free ({free_pct}% remaining)")
                }
                (true, false) => format!("Below 10 GiB free ({free_pct}% remaining)"),
                (false, true) => format!("Below 5% free ({free_pct}% remaining)"),
                (false, false) => continue,
            };
            alerts.push(BalloonAlert {
                root: vol.root.clone(),
                free_bytes: vol.free_bytes,
                total_bytes: vol.total_bytes,
                free_pct,
                reason,
            });
        }
    }
    alerts
}

/// Runs a single background-priority volume space check and measures resident working set.
pub fn run_tray_check_once() -> Result<TrayCheckReport> {
    let bg = BackgroundPriorityGuard::try_enter();
    let background_priority_active = bg.is_active();
    let volumes = list_volumes()?;
    let alerts = check_low_space_alerts(&volumes);
    let peak_working_set_bytes = peak_working_set();
    Ok(TrayCheckReport {
        alerts,
        checked_volumes: volumes.len(),
        peak_working_set_bytes,
        background_priority_active,
    })
}

/// Decides whether a timer-driven low-space check should show a balloon.
///
/// Announces when a drive that was not in the last announcement is now low, or when the same set
/// has not been announced for [`TRAY_REALERT_PERIOD`]. A healthy check clears the state (see
/// `check_space_and_notify`), so a drive that recovers and later runs low again is announced
/// immediately.
pub fn should_notify_low_space(
    previous: Option<&(BTreeSet<String>, Instant)>,
    current: &BTreeSet<String>,
    now: Instant,
) -> bool {
    if current.is_empty() {
        return false;
    }
    match previous {
        None => true,
        Some((prev_set, at)) => {
            !current.is_subset(prev_set) || now.duration_since(*at) >= TRAY_REALERT_PERIOD
        }
    }
}

fn std_handle_present(which: windows::Win32::System::Console::STD_HANDLE) -> bool {
    // SAFETY: `GetStdHandle` only reads this process's standard-handle table.
    unsafe { GetStdHandle(which) }.is_ok_and(|h| !h.is_invalid() && !h.0.is_null())
}

/// Makes `println!`/`eprintln!` visible for one-shot CLI modes (`--check-once`, `--help`) of a
/// `windows`-subsystem binary started from an interactive console.
///
/// Such a process starts without standard handles, so Rust silently drops its output. When stdout
/// is already redirected (pipe/file, as in tests and scripts) nothing changes. Otherwise the
/// process attaches to the parent console and, if the standard handles are still unset, points
/// stdout/stderr at `CONOUT$`. Returns `true` when output now reaches a console or a redirect.
pub fn attach_parent_console_for_cli_output() -> bool {
    if std_handle_present(STD_OUTPUT_HANDLE) {
        return true;
    }
    // SAFETY: Attaching to the parent's console and (re)assigning this process's standard
    // handles; `CONOUT$` is opened with documented arguments and intentionally kept open for the
    // remaining process lifetime.
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return false;
        }
        if std_handle_present(STD_OUTPUT_HANDLE) {
            return true;
        }
        let conout = to_wide("CONOUT$");
        match CreateFileW(
            PCWSTR(conout.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) {
            Ok(h) => {
                let _ = SetStdHandle(STD_OUTPUT_HANDLE, h);
                let _ = SetStdHandle(STD_ERROR_HANDLE, h);
                true
            }
            Err(_) => false,
        }
    }
}

fn validate_hhmm(time_hhmm: &str) -> Result<&str> {
    let bytes = time_hhmm.as_bytes();
    if bytes.len() != 5 || bytes[2] != b':' {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("scheduled time must match HH:MM (got '{time_hhmm}')"),
        )));
    }
    let hh: u8 = time_hhmm[0..2].parse().map_err(|_| {
        DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid hour in HH:MM '{time_hhmm}'"),
        ))
    })?;
    let mm: u8 = time_hhmm[3..5].parse().map_err(|_| {
        DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid minute in HH:MM '{time_hhmm}'"),
        ))
    })?;
    if hh > 23 || mm > 59 {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("scheduled time out of range 00:00..23:59 (got '{time_hhmm}')"),
        )));
    }
    Ok(time_hhmm)
}

fn sibling_binary(name: &str) -> Result<PathBuf> {
    let cur = std::env::current_exe()?;
    let parent = cur.parent().ok_or_else(|| {
        DskError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "current executable has no parent directory",
        ))
    })?;
    Ok(parent.join(name))
}

/// Builds the exact `schtasks.exe` command-line arguments for enabling or removing
/// the weekly DiskSaver Safe Clean scheduled task.
pub fn build_schtasks_args(
    enabled: bool,
    cli_exe: &Path,
    volume_root: &str,
    time_hhmm: &str,
) -> Result<Vec<String>> {
    if !enabled {
        return Ok(vec![
            "/Delete".to_string(),
            "/TN".to_string(),
            SCHEDULED_TASK_NAME.to_string(),
            "/F".to_string(),
        ]);
    }

    validate_hhmm(time_hhmm)?;
    let norm_root = volume_root_of(Path::new(volume_root))
        .ok_or_else(|| DskError::NotVolumeRoot(volume_root.to_string()))?;

    let exe_str = cli_exe.to_str().ok_or_else(|| {
        DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CLI path is not valid UTF-8",
        ))
    })?;
    if exe_str.is_empty()
        || exe_str.contains('"')
        || exe_str.contains('\r')
        || exe_str.contains('\n')
    {
        return Err(DskError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid characters in CLI path for scheduled task",
        )));
    }

    let task_run = format!("\"{exe_str}\" clean --tier safe --yes {norm_root}");
    Ok(vec![
        "/Create".to_string(),
        "/TN".to_string(),
        SCHEDULED_TASK_NAME.to_string(),
        "/SC".to_string(),
        "WEEKLY".to_string(),
        "/D".to_string(),
        "SUN".to_string(),
        "/ST".to_string(),
        time_hhmm.to_string(),
        "/TR".to_string(),
        task_run,
        "/F".to_string(),
    ])
}

/// Creates or deletes the weekly Safe Clean task using pinned `System32\schtasks.exe`.
///
/// When `dry_run` is `true`, validates inputs and returns the exact arguments without
/// mutating Task Scheduler.
pub fn configure_scheduled_safe_clean(
    enabled: bool,
    cli_exe: Option<&Path>,
    volume_root: Option<&str>,
    time_hhmm: &str,
    dry_run: bool,
) -> Result<Vec<String>> {
    let default_cli = sibling_binary("disksaver.exe")?;
    let exe_path = cli_exe.unwrap_or(&default_cli);
    let default_drive = std::env::var("SystemDrive")
        .map(|d| format!("{d}\\"))
        .unwrap_or_else(|_| r"C:\".to_string());
    let vol = volume_root.unwrap_or(&default_drive);

    let args = build_schtasks_args(enabled, exe_path, vol, time_hhmm)?;
    if dry_run {
        return Ok(args);
    }

    let schtasks_path = system32_dir().join("schtasks.exe");
    let out = hidden_command(&schtasks_path).args(&args).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(DskError::Io(std::io::Error::other(format!(
            "schtasks.exe failed (exit {:?}): {} {}",
            out.status.code(),
            stderr.trim(),
            stdout.trim()
        ))));
    }
    Ok(args)
}

struct WindowClassGuard {
    class_name: Vec<u16>,
    hinstance: HINSTANCE,
    registered: bool,
}

impl Drop for WindowClassGuard {
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: Unregistering class name registered on this module once window is destroyed.
            unsafe {
                let _ = UnregisterClassW(PCWSTR(self.class_name.as_ptr()), Some(self.hinstance));
            }
            self.registered = false;
        }
    }
}

struct TrayIconGuard {
    hwnd: HWND,
    added: bool,
}

impl Drop for TrayIconGuard {
    fn drop(&mut self) {
        if self.added {
            let nid = NOTIFYICONDATAW {
                cbSize: size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: self.hwnd,
                uID: TRAY_ICON_ID,
                ..Default::default()
            };
            // SAFETY: Removing notification icon registered for `(hwnd, TRAY_ICON_ID)`.
            unsafe {
                let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
            }
            self.added = false;
        }
    }
}

struct MenuGuard(HMENU);

impl Drop for MenuGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: Menu created via `CreatePopupMenu()` in this scope.
            unsafe {
                let _ = DestroyMenu(self.0);
            }
        }
    }
}

fn show_tray_balloon(hwnd: HWND, title: &str, message: &str, warning: bool) {
    let mut nid = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_ICON_ID,
        uFlags: NIF_INFO,
        dwInfoFlags: (if warning { NIIF_WARNING } else { NIIF_INFO }) | NIIF_NOSOUND,
        ..Default::default()
    };
    write_utf16_fixed(&mut nid.szInfoTitle, title);
    write_utf16_fixed(&mut nid.szInfo, message);
    // SAFETY: `nid` is stack-allocated with valid fixed-width UTF-16 buffers and valid `hwnd`.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

fn check_space_and_notify(hwnd: HWND, notify_when_healthy: bool) {
    match run_tray_check_once() {
        Ok(report) => {
            let low: BTreeSet<String> = report.alerts.iter().map(|a| a.root.clone()).collect();
            let announce = {
                let mut last = LAST_LOW_SPACE_ALERT
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let now = Instant::now();
                let announce =
                    notify_when_healthy || should_notify_low_space(last.as_ref(), &low, now);
                if low.is_empty() {
                    *last = None;
                } else if announce {
                    *last = Some((low.clone(), now));
                }
                announce
            };
            if !announce {
                return;
            }
            if let Some(first) = report.alerts.first() {
                let title = format!("DiskSaver Low Space: {}", first.root);
                let msg = if report.alerts.len() > 1 {
                    format!(
                        "{} (+{} more drive(s) low on space)",
                        first.reason,
                        report.alerts.len() - 1
                    )
                } else {
                    first.reason.clone()
                };
                show_tray_balloon(hwnd, &title, &msg, true);
            } else if notify_when_healthy {
                let msg = format!(
                    "Checked {} mounted volume(s): all drives have healthy free space.",
                    report.checked_volumes
                );
                show_tray_balloon(hwnd, "DiskSaver Space Check", &msg, false);
            }
        }
        Err(err) => {
            // Timer-driven failures are reported too (once per distinct error); otherwise a
            // broken check would be invisible in the windowless release build.
            static LAST_ERR: Mutex<Option<String>> = Mutex::new(None);
            let text = format!("{err}");
            let mut last = LAST_ERR.lock().unwrap_or_else(|p| p.into_inner());
            if notify_when_healthy || last.as_deref() != Some(text.as_str()) {
                show_tray_balloon(hwnd, "DiskSaver Check Failed", &text, true);
                *last = Some(text);
            }
        }
    }
}

fn launch_gui_detached(hwnd: HWND) {
    let launched = sibling_binary("disksaver-gui.exe")
        .ok()
        .filter(|p| p.is_file())
        .map(|gui_exe| hidden_command(gui_exe).spawn().is_ok());
    if launched != Some(true) {
        show_tray_balloon(
            hwnd,
            "DiskSaver",
            "Could not start disksaver-gui.exe (expected next to disksaver-tray.exe).",
            true,
        );
    }
}

/// Text of the confirmation shown before the tray runs a **live** Safe Clean.
pub fn safe_clean_confirmation_text(drive: &str) -> String {
    format!(
        "Run Safe Clean on {drive} now?\n\n\
         This permanently deletes regenerable temporary and cache files matched by the built-in \
         Safe rules only (no Review/Advanced rules, no Recycle Bin). Every deletion is recorded \
         in the DiskSaver History journal.\n\n\
         Choose No to cancel. Use the DiskSaver app for a dry run or to pick individual rules."
    )
}

fn system_drive_root() -> String {
    std::env::var("SystemDrive")
        .map(|d| format!("{d}\\"))
        .unwrap_or_else(|_| r"C:\".to_string())
}

fn confirm_safe_clean(hwnd: HWND, drive: &str) -> bool {
    let text = to_wide(&safe_clean_confirmation_text(drive));
    let caption = to_wide("DiskSaver Safe Clean");
    // SAFETY: Modal message box owned by the tray window with valid NUL-terminated strings.
    let choice = unsafe {
        MessageBoxW(
            Some(hwnd),
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND,
        )
    };
    choice == IDYES
}

/// Balloon text for a finished tray Safe Clean (`u32::MAX` = the CLI could not be started).
pub fn safe_clean_result_message(exit_code: u32) -> (String, bool) {
    match exit_code {
        0 => (
            "Safe Clean finished. Open DiskSaver > History for the freed-space report.".to_string(),
            false,
        ),
        u32::MAX => (
            "Safe Clean could not start disksaver.exe.".to_string(),
            true,
        ),
        code => (
            format!(
                "Safe Clean finished with exit code {code}. Open DiskSaver > History for details."
            ),
            true,
        ),
    }
}

fn trigger_background_safe_clean(hwnd: HWND) {
    if TRAY_CLEAN_IN_FLIGHT.load(Ordering::Acquire) {
        show_tray_balloon(
            hwnd,
            "DiskSaver Safe Clean",
            "Safe Clean is already running in the background.",
            false,
        );
        return;
    }
    let drive = system_drive_root();
    // Guardrail: the tray never runs a live clean without an explicit Yes (default button: No).
    if !confirm_safe_clean(hwnd, &drive) {
        return;
    }
    let Some(cli_exe) = sibling_binary("disksaver.exe").ok().filter(|p| p.is_file()) else {
        show_tray_balloon(
            hwnd,
            "DiskSaver Safe Clean",
            "disksaver.exe was not found next to disksaver-tray.exe; nothing was cleaned.",
            true,
        );
        return;
    };
    if TRAY_CLEAN_IN_FLIGHT.swap(true, Ordering::AcqRel) {
        return;
    }
    show_tray_balloon(
        hwnd,
        "DiskSaver Safe Clean",
        &format!("Safe Clean started on {drive} (below-normal priority)."),
        false,
    );

    // HWND is not `Send`; the worker reports back by posting a message to the tray window.
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || {
        struct ResetFlag;
        impl Drop for ResetFlag {
            fn drop(&mut self) {
                TRAY_CLEAN_IN_FLIGHT.store(false, Ordering::Release);
            }
        }
        let _reset = ResetFlag;
        let _bg = BackgroundPriorityGuard::try_enter();
        let code = hidden_command_with_flags(&cli_exe, BELOW_NORMAL_PRIORITY_CLASS)
            .args(["clean", "--tier", "safe", "--yes", &drive])
            .status()
            .map(|st| st.code().map_or(u32::MAX - 1, |c| c as u32))
            .unwrap_or(u32::MAX);
        // SAFETY: Posting to the tray window owned by the message thread; if the window is
        // already destroyed the call fails harmlessly.
        unsafe {
            let _ = PostMessageW(
                Some(HWND(hwnd_raw as *mut core::ffi::c_void)),
                WM_SAFE_CLEAN_DONE,
                WPARAM(code as usize),
                LPARAM(0),
            );
        }
    });
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// P9.9: hourly offender alerts and the opt-in free-space budget.
fn keep_free_tick(hwnd: HWND) {
    use crate::budget::{
        budget_run_due, default_config_path, load_config, measure_capped, offender_alerts,
        offender_paths, save_config,
    };
    let path = default_config_path();
    let mut cfg = load_config(&path);
    let now = unix_now();
    let mut changed = false;

    if cfg.last_offender_check_unix.is_none_or(|t| now - t >= 3600) {
        let samples: Vec<(PathBuf, u64)> = offender_paths()
            .into_iter()
            .filter_map(|p| measure_capped(&p, 200_000).map(|b| (p, b)))
            .collect();
        let alerts = offender_alerts(&mut cfg, &samples, now);
        cfg.last_offender_check_unix = Some(now);
        changed = true;
        if let Some(a) = alerts.first() {
            show_tray_balloon(
                hwnd,
                "DiskSaver: a folder is growing fast",
                &format!(
                    "{} grows {:.1} GiB/day (now {:.1} GiB). Open DiskSaver > Explore to check it.",
                    a.path.display(),
                    a.growth_per_day as f64 / (1u64 << 30) as f64,
                    a.bytes as f64 / (1u64 << 30) as f64
                ),
                true,
            );
        }
    }

    let drive = system_drive_root();
    let free = crate::win::volume::volume_info(&drive)
        .map(|v| v.free_bytes)
        .unwrap_or(u64::MAX);
    let (on_ac, _) = crate::win::preconditions::power_status();
    if budget_run_due(&cfg, free, on_ac, now)
        && !TRAY_CLEAN_IN_FLIGHT.load(Ordering::Acquire)
        && let Some(cli_exe) = sibling_binary("disksaver.exe").ok().filter(|p| p.is_file())
        && !TRAY_CLEAN_IN_FLIGHT.swap(true, Ordering::AcqRel)
    {
        cfg.last_budget_run_unix = Some(now);
        changed = true;
        show_tray_balloon(
            hwnd,
            "DiskSaver budget",
            &format!(
                "{drive} is below your {} GiB budget: running the safe reclaim and re-compressing updated folders (below-normal priority).",
                cfg.budget_gib.unwrap_or(0)
            ),
            false,
        );
        let hwnd_raw = hwnd.0 as isize;
        std::thread::spawn(move || {
            struct ResetFlag;
            impl Drop for ResetFlag {
                fn drop(&mut self) {
                    TRAY_CLEAN_IN_FLIGHT.store(false, Ordering::Release);
                }
            }
            let _reset = ResetFlag;
            let _bg = BackgroundPriorityGuard::try_enter();
            let code = hidden_command_with_flags(&cli_exe, BELOW_NORMAL_PRIORITY_CLASS)
                .args(["reclaim", &drive, "--yes", "--no-compression"])
                .status()
                .map(|st| st.code().map_or(u32::MAX - 1, |c| c as u32))
                .unwrap_or(u32::MAX);
            let _ = hidden_command_with_flags(&cli_exe, BELOW_NORMAL_PRIORITY_CLASS)
                .args(["optimize", "compress", "--reapply"])
                .status();
            // SAFETY: Posting to the tray window; harmless if it is gone.
            unsafe {
                let _ = PostMessageW(
                    Some(HWND(hwnd_raw as *mut core::ffi::c_void)),
                    WM_SAFE_CLEAN_DONE,
                    WPARAM(code as usize),
                    LPARAM(0),
                );
            }
        });
    }
    if changed {
        let _ = save_config(&path, &cfg);
    }
}

fn show_context_menu(hwnd: HWND) {
    // SAFETY: Creates a temporary Win32 popup menu tied to `hwnd`, tracks user selection, and
    // destroys the menu cleanly via `MenuGuard`.
    unsafe {
        let Ok(hmenu) = CreatePopupMenu() else {
            return;
        };
        let _guard = MenuGuard(hmenu);

        let _ = AppendMenuW(
            hmenu,
            MF_STRING,
            IDM_OPEN_GUI as usize,
            w!("Open DiskSaver"),
        );
        let _ = AppendMenuW(
            hmenu,
            MF_STRING,
            IDM_CHECK_NOW as usize,
            w!("Check Free Space Now"),
        );
        let _ = AppendMenuW(
            hmenu,
            MF_STRING,
            IDM_SAFE_CLEAN as usize,
            w!("Run Safe Clean..."),
        );
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(
            hmenu,
            MF_STRING,
            IDM_SCHEDULE_ENABLE as usize,
            w!("Schedule Weekly Safe Clean"),
        );
        let _ = AppendMenuW(
            hmenu,
            MF_STRING,
            IDM_SCHEDULE_DISABLE as usize,
            w!("Remove Scheduled Safe Clean"),
        );
        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(hmenu, MF_STRING, IDM_EXIT as usize, w!("Exit"));

        let mut pt = POINT::default();
        if GetCursorPos(&mut pt).is_err() {
            return;
        }
        let _ = SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(
            hmenu,
            TPM_RETURNCMD | TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            None,
            hwnd,
            None,
        );
        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));

        match cmd.0 as u32 {
            IDM_OPEN_GUI => launch_gui_detached(hwnd),
            IDM_CHECK_NOW => check_space_and_notify(hwnd, true),
            IDM_SAFE_CLEAN => trigger_background_safe_clean(hwnd),
            IDM_SCHEDULE_ENABLE => {
                match configure_scheduled_safe_clean(true, None, None, "03:00", false) {
                    Ok(_) => show_tray_balloon(
                        hwnd,
                        "DiskSaver Scheduler",
                        "Weekly Safe Clean task registered for Sundays at 03:00.",
                        false,
                    ),
                    Err(e) => {
                        show_tray_balloon(hwnd, "DiskSaver Scheduler Error", &format!("{e}"), true)
                    }
                }
            }
            IDM_SCHEDULE_DISABLE => {
                match configure_scheduled_safe_clean(false, None, None, "03:00", false) {
                    Ok(_) => show_tray_balloon(
                        hwnd,
                        "DiskSaver Scheduler",
                        "Scheduled Safe Clean task removed.",
                        false,
                    ),
                    Err(e) => {
                        show_tray_balloon(hwnd, "DiskSaver Scheduler Error", &format!("{e}"), true)
                    }
                }
            }
            IDM_EXIT => {
                let _ = DestroyWindow(hwnd);
            }
            _ => {}
        }
    }
}

unsafe extern "system" fn tray_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            let notif_msg = (lparam.0 & 0xFFFF) as u32;
            match notif_msg {
                WM_LBUTTONDBLCLK => launch_gui_detached(hwnd),
                WM_RBUTTONUP => show_context_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_SAFE_CLEAN_DONE => {
            let (msg_text, warn) = safe_clean_result_message(wparam.0 as u32);
            show_tray_balloon(hwnd, "DiskSaver Safe Clean", &msg_text, warn);
            LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_POLL_ID {
                check_space_and_notify(hwnd, false);
                keep_free_tick(hwnd);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: Executed inside message loop shutdown on the owning window thread.
            unsafe {
                PostQuitMessage(0);
            }
            LRESULT(0)
        }
        // SAFETY: Standard fallback to Win32 default window procedure.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Runs the lightweight Win32 system tray event loop until the user chooses **Exit**.
///
/// The message thread enters [`BackgroundPriorityGuard`] (`THREAD_MODE_BACKGROUND_BEGIN`)
/// and wakes only on tray mouse events or the periodic `poll_interval` timer.
pub fn run_tray_loop(poll_interval: Duration) -> Result<()> {
    let _bg = BackgroundPriorityGuard::try_enter();
    let class_name = to_wide("DiskSaverTrayWindowClass");

    // SAFETY: Registering a dedicated hidden window class for this process, creating an invisible
    // top-level window, registering the notification icon, and pumping Win32 messages via `GetMessageW`.
    unsafe {
        let hmod = GetModuleHandleW(PCWSTR::null()).map_err(|_| DskError::Win32 {
            ctx: "GetModuleHandleW",
            code: GetLastError().0,
        })?;
        let hinst = HINSTANCE(hmod.0);
        let hicon = LoadIconW(None, IDI_APPLICATION).map_err(|_| DskError::Win32 {
            ctx: "LoadIconW",
            code: GetLastError().0,
        })?;

        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(tray_wnd_proc),
            hInstance: hinst,
            hIcon: hicon,
            hIconSm: hicon,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        if RegisterClassExW(&wc) == 0 {
            return Err(DskError::Win32 {
                ctx: "RegisterClassExW",
                code: GetLastError().0,
            });
        }
        let _class_guard = WindowClassGuard {
            class_name: class_name.clone(),
            hinstance: hinst,
            registered: true,
        };

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            w!("DiskSaver Tray"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(hinst),
            None,
        )
        .map_err(|_| DskError::Win32 {
            ctx: "CreateWindowExW",
            code: GetLastError().0,
        })?;

        let mut nid = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: TRAY_ICON_ID,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage: WM_TRAYICON,
            hIcon: hicon,
            ..Default::default()
        };
        write_utf16_fixed(&mut nid.szTip, "DiskSaver Background Monitor");
        if !Shell_NotifyIconW(NIM_ADD, &nid).as_bool() {
            let _ = DestroyWindow(hwnd);
            return Err(DskError::Win32 {
                ctx: "Shell_NotifyIconW(NIM_ADD)",
                code: GetLastError().0,
            });
        }
        let _tray_guard = TrayIconGuard { hwnd, added: true };

        let interval_ms = poll_interval.as_millis().clamp(1_000, u128::from(u32::MAX)) as u32;
        let timer_ok = SetTimer(Some(hwnd), TIMER_POLL_ID, interval_ms, None);
        if timer_ok == 0 {
            let _ = DestroyWindow(hwnd);
            return Err(DskError::Win32 {
                ctx: "SetTimer",
                code: GetLastError().0,
            });
        }

        // Perform an immediate initial low-space check.
        check_space_and_notify(hwnd, false);

        let mut msg = MSG::default();
        // GetMessageW returns -1 on error; `.as_bool()` would treat that as "keep looping" forever.
        loop {
            let rc = GetMessageW(&mut msg, None, 0, 0).0;
            if rc == 0 || rc == -1 {
                break;
            }
            let _ = TranslateMessage(&msg);
            let _ = DispatchMessageW(&msg);
        }

        let _ = KillTimer(Some(hwnd), TIMER_POLL_ID);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vol(root: &str, free_bytes: u64, total_bytes: u64) -> VolumeInfo {
        VolumeInfo {
            root: root.to_string(),
            fs_name: "NTFS".to_string(),
            serial: 0x1234,
            cluster_size: 4096,
            total_bytes,
            free_bytes,
            ..VolumeInfo::default()
        }
    }

    #[test]
    fn background_priority_guard_enters_and_restores_on_spawned_thread() {
        let handle = std::thread::spawn(|| {
            let guard = BackgroundPriorityGuard::enter().expect("enter background priority mode");
            assert!(guard.is_active());
            drop(guard);
            // Must be able to re-enter cleanly after Drop restored normal priority.
            let guard2 = BackgroundPriorityGuard::enter().expect("re-enter after drop");
            assert!(guard2.is_active());
        });
        handle.join().expect("thread join");
    }

    #[test]
    fn check_low_space_alerts_flags_under_10gb_or_under_5pct() {
        let gib = 1024 * 1024 * 1024u64;
        let vols = vec![
            // Healthy: 100 GiB / 500 GiB (20%)
            sample_vol(r"C:\", 100 * gib, 500 * gib),
            // Low absolute (< 10 GiB): 9 GiB / 100 GiB (9%)
            sample_vol(r"D:\", 9 * gib, 100 * gib),
            // Low relative (< 5%): 50 GiB / 2000 GiB (2%)
            sample_vol(r"E:\", 50 * gib, 2000 * gib),
            // Zero total should be skipped safely
            sample_vol(r"F:\", 0, 0),
        ];

        let alerts = check_low_space_alerts(&vols);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].root, r"D:\");
        assert!(alerts[0].reason.contains("10 GiB"));
        assert_eq!(alerts[1].root, r"E:\");
        assert!(alerts[1].reason.contains("5%"));
    }

    #[test]
    fn configure_scheduled_safe_clean_validates_inputs_and_builds_schtasks_args() {
        let cli = Path::new(r"C:\Program Files\DiskSaver\disksaver.exe");
        let create_args =
            configure_scheduled_safe_clean(true, Some(cli), Some("c:"), "03:30", true)
                .expect("dry_run create args");
        assert!(create_args.contains(&"/Create".to_string()));
        assert!(create_args.contains(&SCHEDULED_TASK_NAME.to_string()));
        assert!(create_args.contains(&"03:30".to_string()));
        let tr = create_args
            .iter()
            .find(|a| a.contains("disksaver.exe"))
            .expect("task run command");
        assert!(tr.contains("clean --tier safe --yes C:\\"));

        let delete_args =
            configure_scheduled_safe_clean(false, Some(cli), Some("C:"), "03:30", true)
                .expect("dry_run delete args");
        assert_eq!(
            delete_args,
            vec!["/Delete", "/TN", SCHEDULED_TASK_NAME, "/F"]
        );

        assert!(
            configure_scheduled_safe_clean(true, Some(cli), Some(r"C:\Subfolder"), "03:30", true)
                .is_err(),
            "non-root volume path must be rejected"
        );
        assert!(
            configure_scheduled_safe_clean(true, Some(cli), Some(r"C:\"), "25:99", true).is_err(),
            "out-of-range HH:MM must be rejected"
        );
    }

    #[test]
    fn low_space_balloons_are_deduplicated_until_set_grows_or_period_elapses() {
        let t0 = Instant::now();
        let c: BTreeSet<String> = [r"C:\".to_string()].into_iter().collect();
        let cd: BTreeSet<String> = [r"C:\".to_string(), r"D:\".to_string()]
            .into_iter()
            .collect();
        let empty = BTreeSet::new();

        assert!(
            !should_notify_low_space(None, &empty, t0),
            "healthy: no balloon"
        );
        assert!(
            should_notify_low_space(None, &c, t0),
            "first low drive: balloon"
        );

        let prev = (c.clone(), t0);
        let t1 = t0 + Duration::from_secs(300);
        assert!(
            !should_notify_low_space(Some(&prev), &c, t1),
            "same set: suppressed"
        );
        assert!(
            should_notify_low_space(Some(&prev), &cd, t1),
            "new low drive: balloon"
        );

        let t_day = t0 + TRAY_REALERT_PERIOD;
        assert!(
            should_notify_low_space(Some(&prev), &c, t_day),
            "daily reminder"
        );

        let prev_cd = (cd, t0);
        assert!(
            !should_notify_low_space(Some(&prev_cd), &c, t1),
            "a drive recovering (subset) is not a new alert"
        );
        assert!(TRAY_POLL_INTERVAL <= Duration::from_secs(600));
    }

    #[test]
    fn tray_safe_clean_texts_are_explicit_about_live_deletion() {
        let text = safe_clean_confirmation_text(r"C:\");
        assert!(text.contains(r"C:\"));
        assert!(text.contains("permanently deletes"));
        assert!(text.contains("Safe rules only"));
        assert!(!safe_clean_result_message(0).1);
        assert!(safe_clean_result_message(3).1);
        assert!(
            safe_clean_result_message(u32::MAX)
                .0
                .contains("could not start")
        );
    }

    #[test]
    fn console_attach_is_a_noop_when_stdout_is_present() {
        // The test harness always has (captured) standard handles.
        assert!(attach_parent_console_for_cli_output());
    }

    #[test]
    fn schtasks_executable_is_pinned_under_system32() {
        let p = system32_dir().join("schtasks.exe");
        assert!(
            p.to_string_lossy()
                .to_ascii_lowercase()
                .contains("system32"),
            "unexpected schtasks path: {}",
            p.display()
        );
    }
}
