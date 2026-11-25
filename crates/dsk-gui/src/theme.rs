//! Theme and styling definitions for DiskSaver GUI.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use dsk_core::NodeFlags;
use eframe::egui::epaint::{CornerRadius, Shadow, Stroke};
use eframe::egui::style::{ScrollStyle, Selection, WidgetVisuals, Widgets};
use eframe::egui::{
    self, Color32, FontData, FontDefinitions, FontFamily, FontId, Margin, TextStyle, Vec2,
};

/// Formats a byte quantity using binary units (B, KiB, MiB, GiB, TiB, PiB).
/// Values 1024 and above display exactly one decimal digit.
pub fn fmt_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;
    const PIB: u64 = 1024 * 1024 * 1024 * 1024 * 1024;

    if n < KIB {
        format!("{n} B")
    } else if n < MIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else if n < GIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n < TIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n < PIB {
        format!("{:.1} TiB", n as f64 / TIB as f64)
    } else {
        format!("{:.1} PiB", n as f64 / PIB as f64)
    }
}

/// Formats a signed byte delta with explicit `+` / `-` prefix.
pub fn fmt_signed_bytes(delta: i64) -> String {
    let mag = fmt_bytes(delta.unsigned_abs());
    if delta > 0 {
        format!("+{mag}")
    } else if delta < 0 {
        format!("-{mag}")
    } else {
        "0 B".to_string()
    }
}

/// Formats an integer with comma thousands separators (e.g. `1,245,890`).
pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    if len <= 3 {
        return s;
    }
    let mut out = String::with_capacity(len + (len - 1) / 3);
    for (idx, ch) in s.chars().enumerate() {
        if idx > 0 && (len - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Formats a Unix timestamp (seconds) as UTC `YYYY-MM-DD HH:MM`.
/// Returns `"—"` for non-positive timestamps.
pub fn fmt_unix_timestamp(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return "—".to_string();
    }
    // Howard Hinnant civil-from-days algorithm (Gregorian calendar).
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02} {hour:02}:{minute:02}")
}

/// Linearly blends `fg` over `bg` using `alpha` clamped to `[0.0, 1.0]`.
pub fn blend(bg: Color32, fg: Color32, alpha: f32) -> Color32 {
    let a = if alpha.is_finite() {
        alpha.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let inv = 1.0 - a;
    let r = (bg.r() as f32 * inv + fg.r() as f32 * a)
        .round()
        .clamp(0.0, 255.0) as u8;
    let g = (bg.g() as f32 * inv + fg.g() as f32 * a)
        .round()
        .clamp(0.0, 255.0) as u8;
    let b = (bg.b() as f32 * inv + fg.b() as f32 * a)
        .round()
        .clamp(0.0, 255.0) as u8;
    Color32::from_rgb(r, g, b)
}

/// Produces a crisp tinted surface color for badges and callout banners in both dark and light modes.
pub fn tint_on(surface: Color32, accent: Color32, strength: f32) -> Color32 {
    blend(surface, accent, strength)
}

/// Returns `c` with an explicit alpha byte.
pub fn with_alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

/// Fallback color for synthetic small tail aggregated items.
pub fn small_tail_color() -> Color32 {
    Color32::from_rgb(71, 85, 105) // Slate 600
}

/// Treemap color for a hunt verdict (Explore "Removable" mode).
pub fn verdict_color(v: dsk_core::hunt::Verdict) -> Color32 {
    use dsk_core::hunt::Verdict;
    match v {
        Verdict::Claimed => Color32::from_rgb(34, 197, 94), // green: a reclaim action exists
        Verdict::Leftover => Color32::from_rgb(250, 204, 21), // yellow: left behind
        Verdict::ColdUserData => Color32::from_rgb(56, 189, 248), // blue: cold personal data
        Verdict::InstalledApp => Color32::from_rgb(168, 85, 247), // purple: uninstall or move
        Verdict::Protected => Color32::from_rgb(71, 85, 105), // slate: hands off
        Verdict::Active => Color32::from_rgb(100, 116, 139), // gray: in use
    }
}

/// Legend entries for [`verdict_color`].
pub fn verdict_legend() -> [(dsk_core::hunt::Verdict, &'static str); 6] {
    use dsk_core::hunt::Verdict;
    [
        (Verdict::Claimed, "reclaimable"),
        (Verdict::Leftover, "leftover"),
        (Verdict::ColdUserData, "cold data"),
        (Verdict::InstalledApp, "app / game"),
        (Verdict::Protected, "protected"),
        (Verdict::Active, "in use"),
    ]
}

/// Computes a visually distinctive fill color for a node based on its filesystem
/// flags, filename extension category, and directory depth.
pub fn node_color(flags: NodeFlags, name: &str, depth: u16) -> Color32 {
    // 1. Special NTFS / filesystem flags take highest precedence
    if flags.contains(NodeFlags::CLOUD) {
        return Color32::from_rgb(56, 189, 248); // Sky blue
    }
    if flags.contains(NodeFlags::COMPRESSED) || flags.contains(NodeFlags::WOF) {
        return Color32::from_rgb(168, 85, 247); // Purple
    }
    if flags.contains(NodeFlags::SPARSE) {
        return Color32::from_rgb(20, 184, 166); // Teal
    }
    if flags.contains(NodeFlags::REPARSE) {
        return Color32::from_rgb(129, 140, 248); // Indigo
    }

    // 2. Directory colors tiered slightly by depth
    if flags.contains(NodeFlags::DIR) {
        return match depth % 5 {
            0 => Color32::from_rgb(202, 138, 4), // Amber 600
            1 => Color32::from_rgb(217, 119, 6), // Amber / orange
            2 => Color32::from_rgb(234, 88, 12), // Orange 600
            3 => Color32::from_rgb(220, 38, 38), // Red 600
            _ => Color32::from_rgb(180, 83, 9),  // Warm brown / amber
        };
    }

    // 3. File extension classification
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        // Video
        "mp4" | "mkv" | "avi" | "mov" | "wmv" | "flv" | "webm" | "m4v" => {
            Color32::from_rgb(147, 51, 234) // Violet
        }
        // Audio
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" | "wma" => {
            Color32::from_rgb(236, 72, 153) // Pink
        }
        // Images
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" | "tiff" | "psd" | "raw" => {
            Color32::from_rgb(34, 197, 94) // Emerald green
        }
        // Archives & Disk Images
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "iso" | "vhd" | "vhdx" | "cab" => {
            Color32::from_rgb(249, 115, 22) // Orange
        }
        // Documents
        "pdf" | "docx" | "doc" | "xlsx" | "xls" | "pptx" | "ppt" | "txt" | "rtf" | "csv" | "md" => {
            Color32::from_rgb(59, 130, 246) // Blue
        }
        // Executables & Libraries
        "exe" | "dll" | "sys" | "msi" | "bin" | "com" | "drv" => {
            Color32::from_rgb(239, 68, 68) // Red
        }
        // Code & Data
        "rs" | "c" | "cpp" | "h" | "py" | "js" | "ts" | "html" | "css" | "json" | "xml"
        | "toml" | "yaml" | "yml" | "sql" | "sh" | "bat" | "ps1" => {
            Color32::from_rgb(20, 184, 166) // Teal
        }
        // Fallback file color
        _ => Color32::from_rgb(100, 116, 139), // Slate 500
    }
}

/// Adaptive theme styling tokens for dark ("Obsidian Studio") and light ("Crisp Daylight") modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThemeTokens {
    pub is_dark: bool,
    pub background: Color32,
    pub sidebar_bg: Color32,
    pub header_bg: Color32,
    pub card_bg: Color32,
    pub inset_bg: Color32,
    pub surface: Color32,
    pub surface_hover: Color32,
    pub border: Color32,
    pub border_subtle: Color32,
    pub text_primary: Color32,
    pub text_secondary: Color32,
    pub text_muted: Color32,
    pub selection: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_soft: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub info: Color32,
    pub purple: Color32,
    pub row_alt: Color32,
    pub row_hover: Color32,
    pub row_selected: Color32,
    pub row_selected_text: Color32,
    pub modal_backdrop: Color32,
    pub shadow_color: Color32,
}

impl ThemeTokens {
    pub fn dark() -> Self {
        Self {
            is_dark: true,
            background: Color32::from_rgb(11, 15, 23),
            sidebar_bg: Color32::from_rgb(15, 20, 31),
            header_bg: Color32::from_rgb(13, 18, 28),
            card_bg: Color32::from_rgb(20, 27, 41),
            inset_bg: Color32::from_rgb(26, 35, 52),
            surface: Color32::from_rgb(20, 27, 41),
            surface_hover: Color32::from_rgb(34, 46, 68),
            border: Color32::from_rgb(42, 56, 80),
            border_subtle: Color32::from_rgb(30, 41, 59),
            text_primary: Color32::from_rgb(241, 245, 249),
            text_secondary: Color32::from_rgb(148, 163, 184),
            text_muted: Color32::from_rgb(100, 116, 139),
            selection: Color32::from_rgb(14, 165, 233),
            accent: Color32::from_rgb(56, 189, 248),
            accent_hover: Color32::from_rgb(125, 211, 252),
            accent_soft: Color32::from_rgb(22, 46, 69),
            success: Color32::from_rgb(34, 197, 94),
            warning: Color32::from_rgb(245, 158, 11),
            danger: Color32::from_rgb(248, 113, 113),
            info: Color32::from_rgb(56, 189, 248),
            purple: Color32::from_rgb(192, 132, 252),
            row_alt: Color32::from_rgb(17, 23, 35),
            row_hover: Color32::from_rgb(29, 40, 58),
            row_selected: Color32::from_rgb(23, 47, 78),
            row_selected_text: Color32::from_rgb(125, 211, 252),
            modal_backdrop: Color32::from_black_alpha(150),
            shadow_color: Color32::from_black_alpha(110),
        }
    }

    pub fn light() -> Self {
        Self {
            is_dark: false,
            background: Color32::from_rgb(244, 246, 250),
            sidebar_bg: Color32::from_rgb(236, 240, 246),
            header_bg: Color32::from_rgb(255, 255, 255),
            card_bg: Color32::from_rgb(255, 255, 255),
            inset_bg: Color32::from_rgb(241, 245, 249),
            surface: Color32::from_rgb(255, 255, 255),
            surface_hover: Color32::from_rgb(229, 235, 244),
            border: Color32::from_rgb(207, 216, 228),
            border_subtle: Color32::from_rgb(226, 232, 240),
            text_primary: Color32::from_rgb(15, 23, 42),
            text_secondary: Color32::from_rgb(71, 85, 105),
            text_muted: Color32::from_rgb(100, 116, 139),
            selection: Color32::from_rgb(2, 132, 199),
            accent: Color32::from_rgb(2, 132, 199),
            accent_hover: Color32::from_rgb(3, 105, 161),
            accent_soft: Color32::from_rgb(224, 242, 254),
            success: Color32::from_rgb(21, 128, 61),
            warning: Color32::from_rgb(180, 83, 9),
            danger: Color32::from_rgb(220, 38, 38),
            info: Color32::from_rgb(2, 132, 199),
            purple: Color32::from_rgb(126, 34, 206),
            row_alt: Color32::from_rgb(248, 250, 252),
            row_hover: Color32::from_rgb(236, 243, 252),
            row_selected: Color32::from_rgb(219, 234, 254),
            row_selected_text: Color32::from_rgb(3, 105, 161),
            modal_backdrop: Color32::from_black_alpha(90),
            shadow_color: Color32::from_black_alpha(32),
        }
    }

    pub fn for_theme(theme: egui::Theme) -> Self {
        match theme {
            egui::Theme::Dark => Self::dark(),
            egui::Theme::Light => Self::light(),
        }
    }

    pub fn for_ui(ui: &egui::Ui) -> Self {
        if ui.visuals().dark_mode {
            Self::dark()
        } else {
            Self::light()
        }
    }

    /// Maps drive utilization ratio in `[0.0, 1.0]` to an intuitive status color.
    pub fn health_color(&self, used_ratio: f32) -> Color32 {
        if used_ratio > 0.90 {
            self.danger
        } else if used_ratio > 0.75 {
            self.warning
        } else {
            self.accent
        }
    }
}

/// Builds a complete `egui::Style` calibrated for [`ThemeTokens`].
pub fn build_style(tokens: &ThemeTokens) -> egui::Style {
    let mut style = egui::Style::default();
    let mut visuals = if tokens.is_dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    visuals.panel_fill = tokens.background;
    visuals.window_fill = tokens.card_bg;
    visuals.faint_bg_color = tokens.row_alt;
    visuals.extreme_bg_color = tokens.inset_bg;
    visuals.code_bg_color = tokens.inset_bg;
    visuals.override_text_color = Some(tokens.text_primary);
    visuals.weak_text_color = Some(tokens.text_secondary);
    visuals.hyperlink_color = tokens.accent;
    visuals.warn_fg_color = tokens.warning;
    visuals.error_fg_color = tokens.danger;
    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.window_stroke = Stroke::new(1.0, tokens.border);
    visuals.window_shadow = Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: tokens.shadow_color,
    };
    visuals.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 14,
        spread: 0,
        color: tokens.shadow_color,
    };
    visuals.selection = Selection {
        bg_fill: tokens.accent_soft,
        stroke: Stroke::new(1.0, tokens.accent),
    };
    visuals.striped = true;
    visuals.slider_trailing_fill = true;

    let r = CornerRadius::same(6);
    visuals.widgets = Widgets {
        noninteractive: WidgetVisuals {
            bg_fill: tokens.card_bg,
            weak_bg_fill: tokens.inset_bg,
            bg_stroke: Stroke::new(1.0, tokens.border_subtle),
            corner_radius: r,
            fg_stroke: Stroke::new(1.0, tokens.text_primary),
            expansion: 0.0,
        },
        inactive: WidgetVisuals {
            bg_fill: tokens.inset_bg,
            weak_bg_fill: tokens.inset_bg,
            bg_stroke: Stroke::new(1.0, tokens.border),
            corner_radius: r,
            fg_stroke: Stroke::new(1.0, tokens.text_primary),
            expansion: 0.0,
        },
        hovered: WidgetVisuals {
            bg_fill: tokens.surface_hover,
            weak_bg_fill: tokens.surface_hover,
            bg_stroke: Stroke::new(1.0, tokens.accent),
            corner_radius: r,
            fg_stroke: Stroke::new(1.5, tokens.text_primary),
            expansion: 0.0,
        },
        active: WidgetVisuals {
            bg_fill: tokens.accent_soft,
            weak_bg_fill: tokens.accent_soft,
            bg_stroke: Stroke::new(1.5, tokens.accent),
            corner_radius: r,
            fg_stroke: Stroke::new(1.5, tokens.text_primary),
            expansion: 0.0,
        },
        open: WidgetVisuals {
            bg_fill: tokens.surface_hover,
            weak_bg_fill: tokens.surface_hover,
            bg_stroke: Stroke::new(1.0, tokens.accent),
            corner_radius: r,
            fg_stroke: Stroke::new(1.0, tokens.text_primary),
            expansion: 0.0,
        },
    };

    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);
    style.spacing.window_margin = Margin::same(14);
    style.spacing.menu_margin = Margin::same(6);
    style.spacing.interact_size = Vec2::new(36.0, 26.0);

    let mut scroll = ScrollStyle::solid();
    scroll.floating = true;
    scroll.bar_width = 7.0;
    scroll.handle_min_length = 24.0;
    scroll.dormant_handle_opacity = 0.28;
    scroll.dormant_background_opacity = 0.0;
    style.spacing.scroll = scroll;

    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(18.0, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(13.5, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(13.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(11.5, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(12.5, FontFamily::Monospace),
    );

    style
}

/// Applies [`ThemeTokens`] to `ctx` for the matching Dark/Light theme slot.
pub fn apply_theme(ctx: &egui::Context, tokens: &ThemeTokens) {
    let egui_theme = if tokens.is_dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    };
    ctx.set_style_of(egui_theme, build_style(tokens));
    ctx.set_theme(egui_theme);
}

/// Installs native Windows fonts (`Segoe UI` and `Cascadia Mono` / `Consolas`) ahead of
/// egui's bundled fallback fonts. Call once during live window setup (never per frame).
pub fn install_system_fonts(ctx: &egui::Context) {
    let win_fonts = std::env::var_os("SystemRoot")
        .map(|root| PathBuf::from(root).join("Fonts"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\Fonts"));

    let mut fonts = FontDefinitions::default();
    let mut loaded_any = false;

    if let Ok(bytes) = std::fs::read(win_fonts.join("segoeui.ttf")) {
        fonts.font_data.insert(
            "segoe_ui".to_string(),
            Arc::new(FontData::from_owned(bytes)),
        );
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "segoe_ui".to_string());
        loaded_any = true;
    }

    let mono_bytes = std::fs::read(win_fonts.join("CascadiaMono.ttf"))
        .or_else(|_| std::fs::read(win_fonts.join("consola.ttf")));
    if let Ok(bytes) = mono_bytes {
        fonts.font_data.insert(
            "win_mono".to_string(),
            Arc::new(FontData::from_owned(bytes)),
        );
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "win_mono".to_string());
        loaded_any = true;
    }

    if loaded_any {
        ctx.set_fonts(fonts);
    }
}

/// Generates a 32x32 procedural RGBA application icon (squircle disk platter + cyan/emerald arc).
pub fn build_app_icon() -> egui::IconData {
    const SIZE: u32 = 32;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    let center = (SIZE as f32 - 1.0) * 0.5;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let fx = x as f32 - center;
            let fy = y as f32 - center;

            // Signed distance to a 28x28 rounded squircle (radius 6.5)
            let half = 13.5_f32;
            let corner_r = 6.0_f32;
            let qx = fx.abs() - (half - corner_r);
            let qy = fy.abs() - (half - corner_r);
            let sdf_box = qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0) - corner_r;

            let bg_alpha = (0.5 - sdf_box).clamp(0.0, 1.0);
            if bg_alpha <= 0.0 {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            // Deep slate-indigo gradient backdrop
            let t = ((fx + fy + 28.0) / 56.0).clamp(0.0, 1.0);
            let mut r = 16.0 + 10.0 * t;
            let mut g = 24.0 + 12.0 * t;
            let mut b = 46.0 + 18.0 * t;

            // Subtle inner rim
            let rim = (1.0 - (sdf_box + 1.0).abs()).clamp(0.0, 1.0) * 0.25;
            r += 56.0 * rim;
            g += 189.0 * rim;
            b += 248.0 * rim;

            let dist = fx.hypot(fy);
            let angle = fy.atan2(fx); // [-PI, PI]

            // Outer ring track (radius 7.2..10.4)
            let ring_dist = (dist - 8.8).abs();
            let ring_mask = (1.6 - ring_dist).clamp(0.0, 1.0);
            if ring_mask > 0.0 {
                // Active 260-degree sweep from top (-PI/2) clockwise; leave gap in bottom-right
                let in_emerald_slice = (-0.85..=0.45).contains(&angle);
                let in_gap = (0.65..=1.55).contains(&angle);
                if !in_gap {
                    let (ar, ag, ab) = if in_emerald_slice {
                        (34.0, 197.0, 94.0)
                    } else {
                        (56.0, 189.0, 248.0)
                    };
                    r = r * (1.0 - ring_mask) + ar * ring_mask;
                    g = g * (1.0 - ring_mask) + ag * ring_mask;
                    b = b * (1.0 - ring_mask) + ab * ring_mask;
                } else {
                    let dim = ring_mask * 0.35;
                    r = r * (1.0 - dim) + 71.0 * dim;
                    g = g * (1.0 - dim) + 85.0 * dim;
                    b = b * (1.0 - dim) + 105.0 * dim;
                }
            }

            // Center spindle dot
            let dot_mask = (2.6 - dist).clamp(0.0, 1.0);
            if dot_mask > 0.0 {
                r = r * (1.0 - dot_mask) + 241.0 * dot_mask;
                g = g * (1.0 - dot_mask) + 245.0 * dot_mask;
                b = b * (1.0 - dot_mask) + 249.0 * dot_mask;
            }

            rgba.push(r.round().clamp(0.0, 255.0) as u8);
            rgba.push(g.round().clamp(0.0, 255.0) as u8);
            rgba.push(b.round().clamp(0.0, 255.0) as u8);
            rgba.push((bg_alpha * 255.0).round().clamp(0.0, 255.0) as u8);
        }
    }

    egui::IconData {
        rgba,
        width: SIZE,
        height: SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_bytes_units() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024 * 1024), "1.0 TiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024 * 1024 * 1024), "1.0 PiB");
    }

    #[test]
    fn test_node_color_categories() {
        // Special flags
        assert_eq!(
            node_color(NodeFlags::CLOUD, "file.txt", 0),
            Color32::from_rgb(56, 189, 248)
        );
        assert_eq!(
            node_color(NodeFlags::COMPRESSED, "archive.zip", 0),
            Color32::from_rgb(168, 85, 247)
        );
        assert_eq!(
            node_color(NodeFlags::WOF, "code.rs", 0),
            Color32::from_rgb(168, 85, 247)
        );
        assert_eq!(
            node_color(NodeFlags::SPARSE, "db.bin", 0),
            Color32::from_rgb(20, 184, 166)
        );
        assert_eq!(
            node_color(NodeFlags::REPARSE, "link", 0),
            Color32::from_rgb(129, 140, 248)
        );

        // Directory
        assert_eq!(
            node_color(NodeFlags::DIR, "Folder", 0),
            Color32::from_rgb(202, 138, 4)
        );

        // Extensions
        assert_eq!(
            node_color(NodeFlags::empty(), "movie.mp4", 1),
            Color32::from_rgb(147, 51, 234)
        );
        assert_eq!(
            node_color(NodeFlags::empty(), "song.mp3", 1),
            Color32::from_rgb(236, 72, 153)
        );
        assert_eq!(
            node_color(NodeFlags::empty(), "photo.png", 1),
            Color32::from_rgb(34, 197, 94)
        );
        assert_eq!(
            node_color(NodeFlags::empty(), "backup.zip", 1),
            Color32::from_rgb(249, 115, 22)
        );
        assert_eq!(
            node_color(NodeFlags::empty(), "doc.pdf", 1),
            Color32::from_rgb(59, 130, 246)
        );
        assert_eq!(
            node_color(NodeFlags::empty(), "app.exe", 1),
            Color32::from_rgb(239, 68, 68)
        );
        assert_eq!(
            node_color(NodeFlags::empty(), "main.rs", 1),
            Color32::from_rgb(20, 184, 166)
        );
        assert_eq!(
            node_color(NodeFlags::empty(), "unknown.xyz", 1),
            Color32::from_rgb(100, 116, 139)
        );
    }

    #[test]
    fn test_theme_tokens() {
        let dark = ThemeTokens::dark();
        assert!(dark.is_dark);
        let light = ThemeTokens::light();
        assert!(!light.is_dark);
        assert_ne!(dark.background, light.background);
    }

    #[test]
    fn apply_theme_sets_dark_and_light_visuals() {
        let ctx = egui::Context::default();
        let dark = ThemeTokens::dark();
        apply_theme(&ctx, &dark);
        assert_eq!(ctx.theme(), egui::Theme::Dark);
        assert_eq!(
            ctx.style_of(egui::Theme::Dark).visuals.panel_fill,
            dark.background
        );

        let light = ThemeTokens::light();
        apply_theme(&ctx, &light);
        assert_eq!(ctx.theme(), egui::Theme::Light);
        assert_eq!(
            ctx.style_of(egui::Theme::Light).visuals.panel_fill,
            light.background
        );
        assert_eq!(
            ctx.style_of(egui::Theme::Light).visuals.window_fill,
            light.card_bg
        );
    }

    #[test]
    fn fmt_unix_timestamp_and_count_formatting() {
        assert_eq!(fmt_unix_timestamp(0), "—");
        assert_eq!(fmt_unix_timestamp(-5), "—");
        assert_eq!(fmt_unix_timestamp(1_700_000_000), "2023-11-14 22:13");
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_245_890), "1,245,890");
        assert_eq!(fmt_signed_bytes(0), "0 B");
        assert_eq!(fmt_signed_bytes(1024), "+1.0 KiB");
        assert_eq!(fmt_signed_bytes(-2048), "-2.0 KiB");
    }

    #[test]
    fn build_app_icon_has_valid_rgba_dimensions() {
        let icon = build_app_icon();
        assert_eq!(icon.width, 32);
        assert_eq!(icon.height, 32);
        assert_eq!(icon.rgba.len(), 32 * 32 * 4);
        assert!(icon.rgba.iter().skip(3).step_by(4).any(|&a| a > 200));
    }
}
