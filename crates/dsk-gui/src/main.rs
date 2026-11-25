#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod app;
pub mod app_state;
pub mod theme;
pub mod tree_model;
pub mod treemap;
pub mod ui_kit;
pub mod views;
pub mod worker;

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;

/// Parses an optional initial directory or volume path from command-line arguments.
/// Skips argv[0] (the executable path) and returns the first positional (non-flag) argument.
pub fn parse_startup_path<I, S>(args: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    app::AppOptions::parse(args).startup_path
}

fn main() -> eframe::Result<()> {
    // `disksaver-gui [PATH] [--tab <NAME>] [--test-journal <DB>] [--growth-db <DB>] [--hash-cache <DB>]`
    let opts = app::AppOptions::parse(std::env::args());

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("DiskSaver")
            .with_icon(Arc::new(theme::build_app_icon())),
        system_font_fallback: true,
        ..Default::default()
    };

    eframe::run_native(
        "disksaver-gui",
        native_options,
        Box::new(|cc| Ok(Box::new(app::DiskSaverApp::with_options(Some(cc), opts)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_startup_path_empty() {
        assert_eq!(parse_startup_path(Vec::<String>::new()), None);
    }

    #[test]
    fn test_parse_startup_path_exe_only() {
        assert_eq!(parse_startup_path(vec!["disksaver-gui".to_string()]), None);
    }

    #[test]
    fn test_parse_startup_path_skips_storage_flags() {
        assert_eq!(
            parse_startup_path(vec![
                "disksaver-gui".to_string(),
                "--test-journal".to_string(),
                r"C:\tmp\journal.db".to_string(),
                r"E:\".to_string(),
            ]),
            Some(PathBuf::from(r"E:\"))
        );
    }

    #[test]
    fn test_parse_startup_path_with_arg() {
        assert_eq!(
            parse_startup_path(vec!["disksaver-gui".to_string(), r"C:\Windows".to_string()]),
            Some(PathBuf::from(r"C:\Windows"))
        );
        assert_eq!(
            parse_startup_path(vec![
                "disksaver-gui".to_string(),
                r"D:\Data".to_string(),
                "--flag".to_string(),
            ]),
            Some(PathBuf::from(r"D:\Data"))
        );
    }
}
