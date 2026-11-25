//! Lightweight background system tray agent (`disksaver-tray.exe`).
//!
//! Strictly `#![forbid(unsafe_code)]`, zero GUI toolkit (`eframe`/`egui`/`wgpu`) or network
//! dependencies, keeping peak working set well below 20 MiB.

#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use dsk_core::{
    TRAY_POLL_INTERVAL, attach_parent_console_for_cli_output, configure_scheduled_safe_clean,
    run_tray_check_once, run_tray_loop,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Release builds use the `windows` subsystem (no console flash when started at logon), which
    // also means one-shot CLI modes would print into the void when run from a terminal. Attach to
    // the parent console only when arguments were given; the tray loop itself stays windowless.
    if !args.is_empty() {
        attach_parent_console_for_cli_output();
    }

    let mut check_once = false;
    let mut json = false;
    let mut schedule_clean = false;
    let mut unschedule_clean = false;
    let mut time_hhmm = "03:00".to_string();
    let mut volume_root: Option<String> = None;

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--check-once" => check_once = true,
            "--json" => json = true,
            "--schedule-clean" => schedule_clean = true,
            "--unschedule-clean" => unschedule_clean = true,
            "--time" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    eprintln!("error: --time requires HH:MM argument");
                    std::process::exit(2);
                };
                time_hhmm = val.clone();
            }
            "--volume" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    eprintln!("error: --volume requires a drive root such as C:\\");
                    std::process::exit(2);
                };
                volume_root = Some(val.clone());
            }
            "--budget" => {
                // P9.9: opt-in free-space budget (`off` disables it).
                idx += 1;
                let Some(val) = args.get(idx) else {
                    eprintln!("error: --budget requires a size in GiB or `off`");
                    std::process::exit(2);
                };
                let path = dsk_core::budget::default_config_path();
                let mut cfg = dsk_core::budget::load_config(&path);
                cfg.budget_gib = if val.eq_ignore_ascii_case("off") {
                    None
                } else {
                    match val
                        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
                        .parse::<u64>()
                    {
                        Ok(g) if (1..=10_000).contains(&g) => Some(g),
                        _ => {
                            eprintln!("error: --budget expects 1-10000 (GiB) or `off`");
                            std::process::exit(2);
                        }
                    }
                };
                if let Err(e) = dsk_core::budget::save_config(&path, &cfg) {
                    eprintln!("failed to save {}: {e}", path.display());
                    std::process::exit(1);
                }
                match cfg.budget_gib {
                    Some(g) => println!(
                        "Budget mode on: when the system drive has less than {g} GiB free (on AC power, at most daily), the tray runs the safe reclaim and re-compresses updated folders."
                    ),
                    None => println!("Budget mode off."),
                }
                return;
            }
            "--help" | "-h" => {
                println!(
                    "disksaver-tray [--check-once [--json]] [--schedule-clean [--volume C:\\] [--time 03:00]] [--unschedule-clean] [--budget <GiB>|off]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        idx += 1;
    }

    if schedule_clean || unschedule_clean {
        if let Err(err) = configure_scheduled_safe_clean(
            schedule_clean && !unschedule_clean,
            None,
            volume_root.as_deref(),
            &time_hhmm,
            false,
        ) {
            eprintln!("failed to configure scheduled Safe Clean task: {err}");
            std::process::exit(1);
        }
        return;
    }

    if check_once {
        match run_tray_check_once() {
            Ok(report) => {
                if json {
                    match serde_json::to_string_pretty(&report) {
                        Ok(out) => println!("{out}"),
                        Err(err) => {
                            eprintln!("failed to serialize tray check report: {err}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    println!(
                        "checked {} volume(s), {} low-space alert(s), peak working set {} bytes",
                        report.checked_volumes,
                        report.alerts.len(),
                        report.peak_working_set_bytes
                    );
                }
                return;
            }
            Err(err) => {
                eprintln!("tray check failed: {err}");
                std::process::exit(1);
            }
        }
    }

    if let Err(err) = run_tray_loop(TRAY_POLL_INTERVAL) {
        eprintln!("tray loop exited with error: {err}");
        std::process::exit(1);
    }
}
