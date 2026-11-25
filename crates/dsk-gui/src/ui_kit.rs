//! Reusable vector icons, themed cards, badges, buttons, and data visualizations.

#![forbid(unsafe_code)]

use std::f32::consts::{PI, TAU};

use eframe::egui::epaint::{CornerRadius, PathShape, Shadow, Stroke};
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Margin, Pos2, Rect, RichText, Sense, StrokeKind, Vec2,
};

use crate::theme::{self, ThemeTokens};

/// Crisp geometric vector icons painted directly via `egui::Painter` (zero font/emoji gaps).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Icon {
    Overview,
    Cleanup,
    Explore,
    Optimize,
    Insights,
    Videos,
    History,
    Drive,
    Shield,
    ShieldCheck,
    Folder,
    File,
    Cloud,
    Link,
    Compressed,
    Search,
    Sun,
    Moon,
    Refresh,
    Rescan,
    Back,
    Up,
    ChevronRight,
    ChevronDown,
    Close,
    Copy,
    Warning,
    Check,
    Lock,
    Trash,
    Play,
    ExternalLink,
    Sparkles,
    Bolt,
    SidebarToggle,
    Keyboard,
    Info,
}

impl Icon {
    pub const ALL: [Icon; 37] = [
        Icon::Overview,
        Icon::Cleanup,
        Icon::Explore,
        Icon::Optimize,
        Icon::Insights,
        Icon::Videos,
        Icon::History,
        Icon::Drive,
        Icon::Shield,
        Icon::ShieldCheck,
        Icon::Folder,
        Icon::File,
        Icon::Cloud,
        Icon::Link,
        Icon::Compressed,
        Icon::Search,
        Icon::Sun,
        Icon::Moon,
        Icon::Refresh,
        Icon::Rescan,
        Icon::Back,
        Icon::Up,
        Icon::ChevronRight,
        Icon::ChevronDown,
        Icon::Close,
        Icon::Copy,
        Icon::Warning,
        Icon::Check,
        Icon::Lock,
        Icon::Trash,
        Icon::Play,
        Icon::ExternalLink,
        Icon::Sparkles,
        Icon::Bolt,
        Icon::SidebarToggle,
        Icon::Keyboard,
        Icon::Info,
    ];
}

/// Paints a geometric vector icon centered inside `rect`.
pub fn paint_icon(painter: &egui::Painter, rect: Rect, icon: Icon, color: Color32) {
    let s = rect.width().min(rect.height()).max(6.0);
    let c = rect.center();
    let p = |dx: f32, dy: f32| Pos2::new(c.x + dx * s, c.y + dy * s);
    let w = (s * 0.105).clamp(1.2, 2.4);
    let stroke = Stroke::new(w, color);
    let thin = Stroke::new((w * 0.85).max(1.0), color);

    match icon {
        Icon::Overview => {
            // 2x2 rounded bento tiles
            let g = 0.05 * s;
            let q = 0.28 * s;
            for (ox, oy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                let tile_c = Pos2::new(c.x + ox * (g + q * 0.5), c.y + oy * (g + q * 0.5));
                let r = Rect::from_center_size(tile_c, Vec2::splat(q));
                if ox > 0.0 && oy < 0.0 {
                    painter.rect_filled(r, CornerRadius::same(2), color);
                } else {
                    painter.rect_stroke(r, CornerRadius::same(2), stroke, StrokeKind::Middle);
                }
            }
        }
        Icon::Cleanup => {
            // Sweeping brush / broom motif
            painter.line_segment([p(0.28, -0.34), p(-0.04, 0.02)], stroke);
            let head = [
                p(-0.18, -0.08),
                p(0.08, 0.14),
                p(-0.14, 0.36),
                p(-0.36, 0.16),
            ];
            painter.add(PathShape::closed_line(head.to_vec(), stroke));
            painter.line_segment([p(-0.22, 0.22), p(-0.12, 0.12)], thin);
            painter.circle_filled(p(0.28, 0.26), s * 0.06, color);
        }
        Icon::Explore => {
            // Treemap / proportional split grid
            let outer = Rect::from_center_size(c, Vec2::splat(s * 0.72));
            painter.rect_stroke(outer, CornerRadius::same(2), stroke, StrokeKind::Middle);
            painter.line_segment(
                [
                    Pos2::new(c.x - s * 0.02, outer.min.y),
                    Pos2::new(c.x - s * 0.02, outer.max.y),
                ],
                thin,
            );
            painter.line_segment(
                [
                    Pos2::new(c.x - s * 0.02, c.y + s * 0.04),
                    Pos2::new(outer.max.x, c.y + s * 0.04),
                ],
                thin,
            );
        }
        Icon::Optimize => {
            // Tunable sliders (3 vertical faders)
            for (x, knob_y) in [(-0.24, -0.10), (0.0, 0.14), (0.24, -0.16)] {
                painter.line_segment([p(x, -0.32), p(x, 0.32)], thin);
                painter.circle_filled(p(x, knob_y), s * 0.095, color);
            }
        }
        Icon::Insights => {
            // Magnifying glass + pulse spark
            let lens = p(-0.07, -0.07);
            painter.circle_stroke(lens, s * 0.24, stroke);
            painter.line_segment([p(0.11, 0.11), p(0.34, 0.34)], stroke);
            painter.circle_filled(lens, s * 0.06, color);
        }
        Icon::Videos => {
            // Rounded film frame + play triangle
            let frame = Rect::from_center_size(c, Vec2::new(s * 0.76, s * 0.58));
            painter.rect_stroke(frame, CornerRadius::same(3), stroke, StrokeKind::Middle);
            let tri = vec![p(-0.10, -0.13), p(0.16, 0.0), p(-0.10, 0.13)];
            painter.add(PathShape::convex_polygon(tri, color, Stroke::NONE));
        }
        Icon::History => {
            // Counter-clockwise arc + attached arrowhead + clock hands
            let r = s * 0.32;
            let a0 = -PI * 0.72;
            paint_arc(painter, c, r, a0, PI * 1.15, stroke);
            let tip = Pos2::new(c.x + a0.cos() * r, c.y + a0.sin() * r);
            painter.add(PathShape::line(
                vec![
                    Pos2::new(tip.x - s * 0.02, tip.y - s * 0.16),
                    tip,
                    Pos2::new(tip.x + s * 0.16, tip.y + s * 0.02),
                ],
                thin,
            ));
            painter.line_segment([c, p(0.0, -0.18)], thin);
            painter.line_segment([c, p(0.14, 0.06)], thin);
        }
        Icon::Drive => {
            // Sleek NVMe/disk chassis + status LED
            let body = Rect::from_center_size(c, Vec2::new(s * 0.78, s * 0.54));
            painter.rect_stroke(body, CornerRadius::same(3), stroke, StrokeKind::Middle);
            painter.line_segment(
                [
                    Pos2::new(body.min.x + w, c.y + s * 0.06),
                    Pos2::new(body.max.x - w, c.y + s * 0.06),
                ],
                thin,
            );
            painter.circle_filled(p(0.22, 0.16), s * 0.06, color);
        }
        Icon::Shield => {
            let pts = vec![
                p(0.0, -0.36),
                p(0.30, -0.22),
                p(0.26, 0.08),
                p(0.0, 0.36),
                p(-0.26, 0.08),
                p(-0.30, -0.22),
            ];
            painter.add(PathShape::closed_line(pts, stroke));
        }
        Icon::ShieldCheck => {
            let pts = vec![
                p(0.0, -0.36),
                p(0.30, -0.22),
                p(0.26, 0.08),
                p(0.0, 0.36),
                p(-0.26, 0.08),
                p(-0.30, -0.22),
            ];
            painter.add(PathShape::closed_line(pts, stroke));
            painter.add(PathShape::line(
                vec![p(-0.13, 0.02), p(-0.02, 0.13), p(0.15, -0.09)],
                stroke,
            ));
        }
        Icon::Folder => {
            let pts = vec![
                p(-0.36, -0.24),
                p(-0.08, -0.24),
                p(0.0, -0.14),
                p(0.36, -0.14),
                p(0.36, 0.28),
                p(-0.36, 0.28),
            ];
            painter.add(PathShape::closed_line(pts, stroke));
        }
        Icon::File => {
            let pts = vec![
                p(-0.24, -0.34),
                p(0.10, -0.34),
                p(0.26, -0.18),
                p(0.26, 0.34),
                p(-0.24, 0.34),
            ];
            painter.add(PathShape::closed_line(pts, stroke));
            painter.add(PathShape::line(
                vec![p(0.10, -0.34), p(0.10, -0.18), p(0.26, -0.18)],
                thin,
            ));
        }
        Icon::Cloud => {
            // Single clean closed cloud silhouette without overlapping interior circles
            let mut pts = Vec::with_capacity(28);
            // Left bump arc (centered at (-0.18, 0.09), r=0.13) from bottom to top-left
            let lc = p(-0.18, 0.09);
            let lr = s * 0.13;
            for i in 0..=7 {
                let a = PI * 0.5 + PI * (i as f32 / 7.0);
                pts.push(Pos2::new(lc.x + a.cos() * lr, lc.y + a.sin() * lr));
            }
            // Top dome arc (centered at (-0.01, -0.06), r=0.18) from left to right
            let tc = p(-0.01, -0.06);
            let tr = s * 0.18;
            for i in 0..=8 {
                let a = -PI * 0.88 + PI * 0.86 * (i as f32 / 8.0);
                pts.push(Pos2::new(tc.x + a.cos() * tr, tc.y + a.sin() * tr));
            }
            // Right bump arc (centered at (0.19, 0.09), r=0.13) from top-right to flat bottom
            let rc = p(0.19, 0.09);
            let rr = s * 0.13;
            for i in 0..=7 {
                let a = -PI * 0.35 + PI * 0.85 * (i as f32 / 7.0);
                pts.push(Pos2::new(rc.x + a.cos() * rr, rc.y + a.sin() * rr));
            }
            painter.add(PathShape::closed_line(pts, stroke));
        }
        Icon::Link => {
            let left = Rect::from_center_size(p(-0.12, 0.0), Vec2::new(s * 0.36, s * 0.24));
            let right = Rect::from_center_size(p(0.12, 0.0), Vec2::new(s * 0.36, s * 0.24));
            painter.rect_stroke(left, CornerRadius::same(4), thin, StrokeKind::Middle);
            painter.rect_stroke(right, CornerRadius::same(4), thin, StrokeKind::Middle);
            painter.line_segment([p(-0.10, 0.0), p(0.10, 0.0)], stroke);
        }
        Icon::Compressed => {
            // Inward opposing compression arrows
            painter.line_segment([p(-0.36, 0.0), p(-0.10, 0.0)], stroke);
            painter.add(PathShape::line(
                vec![p(-0.20, -0.12), p(-0.08, 0.0), p(-0.20, 0.12)],
                stroke,
            ));
            painter.line_segment([p(0.36, 0.0), p(0.10, 0.0)], stroke);
            painter.add(PathShape::line(
                vec![p(0.20, -0.12), p(0.08, 0.0), p(0.20, 0.12)],
                stroke,
            ));
        }
        Icon::Search => {
            painter.circle_stroke(p(-0.07, -0.07), s * 0.23, stroke);
            painter.line_segment([p(0.10, 0.10), p(0.33, 0.33)], stroke);
        }
        Icon::Sun => {
            painter.circle_stroke(c, s * 0.16, stroke);
            for i in 0..8 {
                let a = (i as f32) * (TAU / 8.0);
                let p0 = Pos2::new(c.x + a.cos() * s * 0.26, c.y + a.sin() * s * 0.26);
                let p1 = Pos2::new(c.x + a.cos() * s * 0.36, c.y + a.sin() * s * 0.36);
                painter.line_segment([p0, p1], thin);
            }
        }
        Icon::Moon => {
            // Single seamless closed crescent using outer arc + quadratic Bezier inner curve
            let r = s * 0.31;
            let a0 = -PI * 0.32;
            let a1 = PI * 0.85;
            let mut pts = Vec::with_capacity(26);
            for i in 0..=14 {
                let t = i as f32 / 14.0;
                let a = a0 + (a1 - a0) * t;
                pts.push(Pos2::new(c.x + a.cos() * r, c.y + a.sin() * r));
            }
            let end_outer = *pts.last().unwrap_or(&c);
            let start_outer = pts[0];
            let ctrl = p(-0.02, 0.02);
            for i in 1..10 {
                let t = i as f32 / 10.0;
                let omt = 1.0 - t;
                let bx = omt * omt * end_outer.x + 2.0 * omt * t * ctrl.x + t * t * start_outer.x;
                let by = omt * omt * end_outer.y + 2.0 * omt * t * ctrl.y + t * t * start_outer.y;
                pts.push(Pos2::new(bx, by));
            }
            painter.add(PathShape::closed_line(pts, stroke));
        }
        Icon::Refresh => {
            let r = s * 0.29;
            let a0 = -PI * 0.80;
            let a1 = PI * 0.65;
            paint_arc(painter, c, r, a0, a1, stroke);
            let tip = Pos2::new(c.x + a1.cos() * r, c.y + a1.sin() * r);
            // Tangent at a1 is (-sin(a1), cos(a1)); backward along arc is (sin(a1), -cos(a1))
            let tx = -a1.sin();
            let ty = a1.cos();
            let nx = a1.cos();
            let ny = a1.sin();
            let arm = s * 0.16;
            painter.add(PathShape::line(
                vec![
                    Pos2::new(
                        tip.x - tx * arm + nx * arm * 0.55,
                        tip.y - ty * arm + ny * arm * 0.55,
                    ),
                    tip,
                    Pos2::new(
                        tip.x - tx * arm - nx * arm * 0.55,
                        tip.y - ty * arm - ny * arm * 0.55,
                    ),
                ],
                thin,
            ));
        }
        Icon::Rescan => {
            let r = s * 0.30;
            let a0 = -PI * 0.85;
            let a1 = PI * 0.65;
            paint_arc(painter, c, r, a0, a1, stroke);
            painter.circle_filled(c, s * 0.08, color);
            let tip = Pos2::new(c.x + a1.cos() * r, c.y + a1.sin() * r);
            let tx = -a1.sin();
            let ty = a1.cos();
            let nx = a1.cos();
            let ny = a1.sin();
            let arm = s * 0.16;
            painter.add(PathShape::line(
                vec![
                    Pos2::new(
                        tip.x - tx * arm + nx * arm * 0.55,
                        tip.y - ty * arm + ny * arm * 0.55,
                    ),
                    tip,
                    Pos2::new(
                        tip.x - tx * arm - nx * arm * 0.55,
                        tip.y - ty * arm - ny * arm * 0.55,
                    ),
                ],
                thin,
            ));
        }
        Icon::Back => {
            painter.line_segment([p(0.28, 0.0), p(-0.24, 0.0)], stroke);
            painter.add(PathShape::line(
                vec![p(-0.04, -0.22), p(-0.26, 0.0), p(-0.04, 0.22)],
                stroke,
            ));
        }
        Icon::Up => {
            painter.line_segment([p(0.0, 0.28), p(0.0, -0.24)], stroke);
            painter.add(PathShape::line(
                vec![p(-0.22, -0.04), p(0.0, -0.26), p(0.22, -0.04)],
                stroke,
            ));
        }
        Icon::ChevronRight => {
            painter.add(PathShape::line(
                vec![p(-0.12, -0.22), p(0.12, 0.0), p(-0.12, 0.22)],
                stroke,
            ));
        }
        Icon::ChevronDown => {
            painter.add(PathShape::line(
                vec![p(-0.22, -0.10), p(0.0, 0.14), p(0.22, -0.10)],
                stroke,
            ));
        }
        Icon::Close => {
            painter.line_segment([p(-0.22, -0.22), p(0.22, 0.22)], stroke);
            painter.line_segment([p(0.22, -0.22), p(-0.22, 0.22)], stroke);
        }
        Icon::Copy => {
            let back = Rect::from_center_size(p(-0.08, -0.08), Vec2::splat(s * 0.44));
            let front = Rect::from_center_size(p(0.09, 0.09), Vec2::splat(s * 0.44));
            painter.rect_stroke(back, CornerRadius::same(2), thin, StrokeKind::Middle);
            painter.rect_stroke(front, CornerRadius::same(2), stroke, StrokeKind::Middle);
        }
        Icon::Warning => {
            let tri = vec![p(0.0, -0.32), p(0.34, 0.28), p(-0.34, 0.28)];
            painter.add(PathShape::closed_line(tri, stroke));
            painter.line_segment([p(0.0, -0.11), p(0.0, 0.08)], stroke);
            painter.circle_filled(p(0.0, 0.19), s * 0.048, color);
        }
        Icon::Check => {
            painter.add(PathShape::line(
                vec![p(-0.26, 0.02), p(-0.06, 0.22), p(0.28, -0.18)],
                stroke,
            ));
        }
        Icon::Lock => {
            let body = Rect::from_center_size(p(0.0, 0.12), Vec2::new(s * 0.52, s * 0.38));
            painter.rect_stroke(body, CornerRadius::same(2), stroke, StrokeKind::Middle);
            paint_arc(painter, p(0.0, -0.07), s * 0.15, PI, TAU, stroke);
        }
        Icon::Trash => {
            painter.line_segment([p(-0.28, -0.20), p(0.28, -0.20)], stroke);
            painter.line_segment([p(-0.10, -0.30), p(0.10, -0.30)], thin);
            let bin = vec![
                p(-0.21, -0.18),
                p(0.21, -0.18),
                p(0.17, 0.30),
                p(-0.17, 0.30),
            ];
            painter.add(PathShape::closed_line(bin, stroke));
            painter.line_segment([p(-0.07, -0.06), p(-0.05, 0.18)], thin);
            painter.line_segment([p(0.07, -0.06), p(0.05, 0.18)], thin);
        }
        Icon::Play => {
            let tri = vec![p(-0.18, -0.24), p(0.26, 0.0), p(-0.18, 0.24)];
            painter.add(PathShape::convex_polygon(tri, color, Stroke::NONE));
        }
        Icon::ExternalLink => {
            let bx = Rect::from_center_size(p(-0.05, 0.05), Vec2::splat(s * 0.52));
            painter.rect_stroke(bx, CornerRadius::same(2), thin, StrokeKind::Middle);
            painter.line_segment([p(-0.02, 0.02), p(0.30, -0.30)], stroke);
            painter.add(PathShape::line(
                vec![p(0.10, -0.30), p(0.30, -0.30), p(0.30, -0.10)],
                stroke,
            ));
        }
        Icon::Sparkles => {
            painter.line_segment([p(0.0, -0.34), p(0.0, 0.34)], stroke);
            painter.line_segment([p(-0.34, 0.0), p(0.34, 0.0)], stroke);
            painter.line_segment([p(-0.18, -0.18), p(0.18, 0.18)], thin);
            painter.line_segment([p(0.18, -0.18), p(-0.18, 0.18)], thin);
        }
        Icon::Bolt => {
            let pts = vec![
                p(0.06, -0.34),
                p(-0.22, 0.04),
                p(0.02, 0.04),
                p(-0.06, 0.34),
                p(0.24, -0.04),
                p(0.0, -0.04),
            ];
            painter.add(PathShape::closed_line(pts, stroke));
        }
        Icon::SidebarToggle => {
            let frame = Rect::from_center_size(c, Vec2::new(s * 0.76, s * 0.62));
            painter.rect_stroke(frame, CornerRadius::same(2), stroke, StrokeKind::Middle);
            let split_x = frame.min.x + frame.width() * 0.34;
            painter.line_segment(
                [
                    Pos2::new(split_x, frame.min.y),
                    Pos2::new(split_x, frame.max.y),
                ],
                thin,
            );
        }
        Icon::Keyboard => {
            let frame = Rect::from_center_size(c, Vec2::new(s * 0.80, s * 0.54));
            painter.rect_stroke(frame, CornerRadius::same(2), stroke, StrokeKind::Middle);
            for dx in [-0.20, 0.0, 0.20] {
                painter.circle_filled(p(dx, -0.07), s * 0.04, color);
            }
            painter.line_segment([p(-0.18, 0.12), p(0.18, 0.12)], thin);
        }
        Icon::Info => {
            painter.circle_stroke(c, s * 0.34, stroke);
            painter.circle_filled(p(0.0, -0.14), s * 0.048, color);
            painter.line_segment([p(0.0, -0.01), p(0.0, 0.18)], stroke);
        }
    }
}

fn paint_arc(
    painter: &egui::Painter,
    center: Pos2,
    radius: f32,
    start_angle: f32,
    end_angle: f32,
    stroke: Stroke,
) {
    const STEPS: usize = 20;
    let pts: Vec<Pos2> = (0..=STEPS)
        .map(|i| {
            let t = i as f32 / STEPS as f32;
            let a = start_angle + (end_angle - start_angle) * t;
            Pos2::new(center.x + a.cos() * radius, center.y + a.sin() * radius)
        })
        .collect();
    painter.add(PathShape::line(pts, stroke));
}

/// Allocates and paints a non-interactive vector icon widget.
pub fn icon_widget(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    if ui.is_rect_visible(rect) {
        paint_icon(ui.painter(), rect, icon, color);
    }
    resp
}

/// Fixed-height vertical hairline divider safe inside `horizontal_wrapped` toolbars.
pub fn inline_divider(ui: &mut egui::Ui, tokens: &ThemeTokens) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(7.0, 18.0), Sense::hover());
    if ui.is_rect_visible(rect) {
        let x = rect.center().x;
        let top = rect.center().y - 7.0;
        let bottom = rect.center().y + 7.0;
        ui.painter().line_segment(
            [Pos2::new(x, top), Pos2::new(x, bottom)],
            Stroke::new(1.0, tokens.border),
        );
    }
}

/// Compact clickable button containing both a crisp vector icon and a text label.
pub fn icon_text_button(
    ui: &mut egui::Ui,
    icon: Icon,
    label: &str,
    enabled: bool,
    tokens: &ThemeTokens,
) -> egui::Response {
    let font_id = FontId::proportional(12.5);
    let text_col = if enabled {
        tokens.text_primary
    } else {
        tokens.text_muted
    };
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font_id, text_col);
    let icon_sz = 13.0;
    let gap = 6.0;
    let pad_x = 10.0;
    let w = pad_x * 2.0 + icon_sz + gap + galley.size().x;
    let h = 26.0;
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), sense);
    if ui.is_rect_visible(rect) {
        let fill = if !enabled {
            tokens.inset_bg
        } else if resp.is_pointer_button_down_on() {
            tokens.accent_soft
        } else if resp.hovered() {
            tokens.surface_hover
        } else {
            tokens.inset_bg
        };
        let border_col = if enabled && resp.hovered() {
            tokens.accent
        } else {
            tokens.border
        };
        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(7), fill);
        painter.rect_stroke(
            rect,
            CornerRadius::same(7),
            Stroke::new(1.0, border_col),
            StrokeKind::Inside,
        );
        let icon_rect = Rect::from_center_size(
            Pos2::new(rect.min.x + pad_x + icon_sz * 0.5, rect.center().y),
            Vec2::splat(icon_sz),
        );
        let icon_col = if enabled {
            tokens.text_secondary
        } else {
            tokens.text_muted
        };
        paint_icon(painter, icon_rect, icon, icon_col);
        let text_pos = Pos2::new(
            rect.min.x + pad_x + icon_sz + gap,
            rect.center().y - galley.size().y * 0.5,
        );
        painter.galley(text_pos, galley, text_col);
    }
    resp
}

/// Compact clickable icon button with subtle hover pill background.
pub fn icon_button(
    ui: &mut egui::Ui,
    icon: Icon,
    size: f32,
    color: Color32,
    tooltip: &str,
    tokens: &ThemeTokens,
) -> egui::Response {
    let btn_size = (size + 10.0).max(24.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(btn_size), Sense::click());
    if ui.is_rect_visible(rect) {
        if resp.hovered() {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(6), tokens.surface_hover);
        }
        let icon_rect = Rect::from_center_size(rect.center(), Vec2::splat(size));
        paint_icon(ui.painter(), icon_rect, icon, color);
    }
    resp.on_hover_text(tooltip)
}

/// Standard elevated card container.
pub fn card_frame(tokens: &ThemeTokens) -> egui::Frame {
    egui::Frame::new()
        .fill(tokens.card_bg)
        .stroke(Stroke::new(1.0, tokens.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
}

/// Subtle recessed container for nested sections or summary panels.
pub fn inset_frame(tokens: &ThemeTokens) -> egui::Frame {
    egui::Frame::new()
        .fill(tokens.inset_bg)
        .stroke(Stroke::new(1.0, tokens.border_subtle))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(10))
}

/// Elevated modal container with crisp border and shadow.
pub fn modal_frame(tokens: &ThemeTokens) -> egui::Frame {
    egui::Frame::new()
        .fill(tokens.card_bg)
        .stroke(Stroke::new(1.0, tokens.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(18))
        .shadow(Shadow {
            offset: [0, 10],
            blur: 28,
            spread: 0,
            color: tokens.shadow_color,
        })
}

/// Card container with a 3px vertical accent stripe on the left edge.
pub fn accent_card<R>(
    ui: &mut egui::Ui,
    tokens: &ThemeTokens,
    accent: Color32,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let resp = egui::Frame::new()
        .fill(tokens.card_bg)
        .stroke(Stroke::new(1.0, tokens.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin {
            left: 17,
            right: 14,
            top: 12,
            bottom: 12,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        });

    let r = resp.response.rect;
    let inset = (r.height() * 0.2).min(8.0);
    let stripe = Rect::from_min_max(
        Pos2::new(r.min.x + 1.5, r.min.y + inset),
        Pos2::new(r.min.x + 4.5, (r.max.y - inset).max(r.min.y + inset + 2.0)),
    );
    ui.painter()
        .rect_filled(stripe, CornerRadius::same(2), accent);

    resp.inner
}

/// Theme-aware callout banner. Returns `true` when the close button was clicked.
pub fn callout_banner(
    ui: &mut egui::Ui,
    tokens: &ThemeTokens,
    accent: Color32,
    icon: Icon,
    title: &str,
    body: Option<&str>,
    dismissible: bool,
) -> bool {
    let mut dismissed = false;
    let strength = if tokens.is_dark { 0.14 } else { 0.08 };
    let fill = theme::tint_on(tokens.card_bg, accent, strength);
    let border = theme::tint_on(tokens.border, accent, 0.55);

    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if dismissible {
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if icon_button(
                        ui,
                        Icon::Close,
                        12.0,
                        tokens.text_secondary,
                        "Dismiss",
                        tokens,
                    )
                    .clicked()
                    {
                        dismissed = true;
                    }
                    ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                        icon_widget(ui, icon, 16.0, accent);
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(title).color(accent).strong());
                            if let Some(detail) = body
                                && !detail.is_empty()
                            {
                                ui.label(
                                    RichText::new(detail)
                                        .size(12.0)
                                        .color(tokens.text_secondary),
                                );
                            }
                        });
                    });
                });
            } else {
                ui.horizontal(|ui| {
                    icon_widget(ui, icon, 16.0, accent);
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(title).color(accent).strong());
                        if let Some(detail) = body
                            && !detail.is_empty()
                        {
                            ui.label(
                                RichText::new(detail)
                                    .size(12.0)
                                    .color(tokens.text_secondary),
                            );
                        }
                    });
                });
            }
        });

    dismissed
}

/// Compact pill badge with soft tinted fill and strong foreground label.
pub fn pill_badge(ui: &mut egui::Ui, text: &str, color: Color32, tokens: &ThemeTokens) {
    let fill = theme::tint_on(
        tokens.card_bg,
        color,
        if tokens.is_dark { 0.20 } else { 0.12 },
    );
    let stroke = theme::tint_on(tokens.border, color, 0.45);
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).strong().color(color));
        });
}

/// Compact badge with a solid colored dot and crisp label.
pub fn dot_badge(ui: &mut egui::Ui, text: &str, dot_color: Color32, tokens: &ThemeTokens) {
    egui::Frame::new()
        .fill(tokens.inset_bg)
        .stroke(Stroke::new(1.0, tokens.border_subtle))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
                let (dot_rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                ui.painter()
                    .circle_filled(dot_rect.center(), 3.5, dot_color);
                ui.label(
                    RichText::new(text)
                        .size(11.0)
                        .strong()
                        .color(tokens.text_primary),
                );
            });
        });
}

/// High-contrast primary CTA button with scoped hover/active states.
pub fn primary_button(
    ui: &mut egui::Ui,
    label: &str,
    enabled: bool,
    tokens: &ThemeTokens,
) -> egui::Response {
    let base_fill = if tokens.is_dark {
        Color32::from_rgb(2, 119, 189)
    } else {
        Color32::from_rgb(2, 116, 180)
    };
    let hover_fill = if tokens.is_dark {
        Color32::from_rgb(14, 145, 218)
    } else {
        Color32::from_rgb(3, 102, 160)
    };
    let active_fill = tokens.selection;
    let fill = if enabled { base_fill } else { tokens.inset_bg };
    let text_col = if enabled {
        Color32::WHITE
    } else {
        tokens.text_muted
    };
    let stroke = if enabled {
        Stroke::NONE
    } else {
        Stroke::new(1.0, tokens.border_subtle)
    };
    ui.scope(|ui| {
        if enabled {
            let w = &mut ui.visuals_mut().widgets;
            w.inactive.weak_bg_fill = base_fill;
            w.inactive.bg_fill = base_fill;
            w.hovered.weak_bg_fill = hover_fill;
            w.hovered.bg_fill = hover_fill;
            w.hovered.bg_stroke = Stroke::new(1.0, tokens.accent_hover);
            w.active.weak_bg_fill = active_fill;
            w.active.bg_fill = active_fill;
        }
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(label).strong().color(text_col))
                .fill(fill)
                .stroke(stroke)
                .corner_radius(CornerRadius::same(7))
                .wrap_mode(egui::TextWrapMode::Extend),
        )
    })
    .inner
}

/// Guarded destructive action button with danger tint and scoped hover states.
pub fn danger_button(
    ui: &mut egui::Ui,
    label: &str,
    enabled: bool,
    tokens: &ThemeTokens,
) -> egui::Response {
    let base_fill = theme::tint_on(
        tokens.card_bg,
        tokens.danger,
        if tokens.is_dark { 0.20 } else { 0.10 },
    );
    let hover_fill = theme::tint_on(
        tokens.card_bg,
        tokens.danger,
        if tokens.is_dark { 0.34 } else { 0.20 },
    );
    let fill = if enabled { base_fill } else { tokens.inset_bg };
    let stroke = if enabled {
        Stroke::new(1.0, theme::tint_on(tokens.border, tokens.danger, 0.7))
    } else {
        Stroke::new(1.0, tokens.border_subtle)
    };
    let text_col = if enabled {
        tokens.danger
    } else {
        tokens.text_muted
    };
    ui.scope(|ui| {
        if enabled {
            let w = &mut ui.visuals_mut().widgets;
            w.inactive.weak_bg_fill = base_fill;
            w.hovered.weak_bg_fill = hover_fill;
            w.hovered.bg_stroke = Stroke::new(1.0, tokens.danger);
            w.active.weak_bg_fill = hover_fill;
            w.active.bg_stroke = Stroke::new(1.5, tokens.danger);
        }
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(label).strong().color(text_col))
                .fill(fill)
                .stroke(stroke)
                .corner_radius(CornerRadius::same(7))
                .wrap_mode(egui::TextWrapMode::Extend),
        )
    })
    .inner
}

/// Secondary hairline button with consistent hover feedback.
pub fn secondary_button(
    ui: &mut egui::Ui,
    label: &str,
    enabled: bool,
    tokens: &ThemeTokens,
) -> egui::Response {
    let text_col = if enabled {
        tokens.text_primary
    } else {
        tokens.text_muted
    };
    ui.scope(|ui| {
        let w = &mut ui.visuals_mut().widgets;
        w.inactive.weak_bg_fill = tokens.inset_bg;
        w.hovered.weak_bg_fill = tokens.surface_hover;
        w.hovered.bg_stroke = Stroke::new(1.0, tokens.accent);
        w.active.weak_bg_fill = tokens.accent_soft;
        w.active.bg_stroke = Stroke::new(1.0, tokens.accent);
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(label).color(text_col))
                .fill(tokens.inset_bg)
                .stroke(Stroke::new(1.0, tokens.border))
                .corner_radius(CornerRadius::same(7)),
        )
    })
    .inner
}

/// Pill filter/toggle chip with preserved selected hover styling.
pub fn chip_toggle(
    ui: &mut egui::Ui,
    selected: bool,
    label: &str,
    accent_opt: Option<Color32>,
    tokens: &ThemeTokens,
) -> egui::Response {
    let accent = accent_opt.unwrap_or(tokens.accent);
    let sel_fill = theme::tint_on(
        tokens.card_bg,
        accent,
        if tokens.is_dark { 0.24 } else { 0.14 },
    );
    let sel_hover = theme::tint_on(
        tokens.card_bg,
        accent,
        if tokens.is_dark { 0.34 } else { 0.22 },
    );
    let fill = if selected { sel_fill } else { tokens.inset_bg };
    let hover_fill = if selected {
        sel_hover
    } else {
        tokens.surface_hover
    };
    let stroke = if selected {
        Stroke::new(1.0, accent)
    } else {
        Stroke::new(1.0, tokens.border_subtle)
    };
    let text_col = if selected {
        accent
    } else {
        tokens.text_secondary
    };
    let text = if selected {
        RichText::new(label).size(11.5).strong().color(text_col)
    } else {
        RichText::new(label).size(11.5).color(text_col)
    };
    ui.scope(|ui| {
        let w = &mut ui.visuals_mut().widgets;
        w.inactive.weak_bg_fill = fill;
        w.hovered.weak_bg_fill = hover_fill;
        w.hovered.bg_stroke = Stroke::new(1.0, accent);
        w.active.weak_bg_fill = sel_hover;
        ui.add(
            egui::Button::new(text)
                .fill(fill)
                .stroke(stroke)
                .corner_radius(CornerRadius::same(12)),
        )
    })
    .inner
}

/// Radial ring gauge visualizing a `[0.0, 1.0]` utilization ratio.
pub fn storage_ring(
    ui: &mut egui::Ui,
    ratio: f32,
    center_primary: &str,
    center_sub: &str,
    diameter: f32,
    color: Color32,
    tokens: &ThemeTokens,
) -> egui::Response {
    let clamped = if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(diameter), Sense::hover());

    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let center = rect.center();
        let thickness = (diameter * 0.11).clamp(3.0, 9.0);
        let radius = (diameter * 0.5 - thickness * 0.75).max(6.0);

        // Background track
        let track_col = if tokens.is_dark {
            tokens.inset_bg
        } else {
            tokens.border_subtle
        };
        painter.circle_stroke(center, radius, Stroke::new(thickness, track_col));

        // Foreground arc starting at top (-PI/2) clockwise
        if clamped > 0.005 {
            let start = -PI * 0.5;
            let sweep = clamped * TAU;
            let segments = ((clamped * 48.0).ceil() as usize).clamp(4, 48);
            let pts: Vec<Pos2> = (0..=segments)
                .map(|i| {
                    let a = start + sweep * (i as f32 / segments as f32);
                    Pos2::new(center.x + a.cos() * radius, center.y + a.sin() * radius)
                })
                .collect();

            let cap_r = thickness * 0.5;
            if let Some(&first) = pts.first() {
                painter.circle_filled(first, cap_r, color);
            }
            if let Some(&last) = pts.last() {
                painter.circle_filled(last, cap_r, color);
            }
            painter.add(PathShape::line(pts, Stroke::new(thickness, color)));
        }

        // Centered typography
        if center_sub.is_empty() {
            painter.text(
                center,
                Align2::CENTER_CENTER,
                center_primary,
                FontId::proportional((diameter * 0.23).clamp(11.0, 18.0)),
                tokens.text_primary,
            );
        } else {
            painter.text(
                Pos2::new(center.x, center.y - diameter * 0.08),
                Align2::CENTER_CENTER,
                center_primary,
                FontId::proportional((diameter * 0.22).clamp(11.0, 17.0)),
                tokens.text_primary,
            );
            painter.text(
                Pos2::new(center.x, center.y + diameter * 0.14),
                Align2::CENTER_CENTER,
                center_sub,
                FontId::proportional((diameter * 0.14).clamp(9.0, 12.0)),
                tokens.text_secondary,
            );
        }
    }

    resp
}

/// Rounded horizontal progress bar with optional caption label on the right.
pub fn progress_bar(
    ui: &mut egui::Ui,
    ratio: f32,
    height: f32,
    fill: Color32,
    label: Option<&str>,
    tokens: &ThemeTokens,
) {
    let clamped = if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.0
    };
    ui.horizontal(|ui| {
        let bar_w = if label.is_some() {
            (ui.available_width() * 0.58).clamp(80.0, 320.0)
        } else {
            ui.available_width().max(60.0)
        };
        let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, height), Sense::hover());
        if ui.is_rect_visible(rect) {
            let radius = CornerRadius::same((height * 0.5).round().clamp(2.0, 255.0) as u8);
            ui.painter().rect_filled(rect, radius, tokens.inset_bg);
            if clamped > 0.005 {
                let fill_w = (rect.width() * clamped).max(height.min(rect.width()));
                let fill_rect = Rect::from_min_size(
                    rect.min,
                    Vec2::new(fill_w.min(rect.width()), rect.height()),
                );
                ui.painter().rect_filled(fill_rect, radius, fill);
            }
        }
        if let Some(txt) = label {
            ui.label(RichText::new(txt).size(11.5).color(tokens.text_secondary));
        }
    });
}

/// Subtle inline proportional bar painted inside a pre-allocated table/row rect.
pub fn inline_ratio_bar(
    painter: &egui::Painter,
    rect: Rect,
    ratio: f32,
    color: Color32,
    tokens: &ThemeTokens,
) {
    let clamped = if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let radius = CornerRadius::same(3);
    painter.rect_filled(rect, radius, tokens.inset_bg);
    if clamped > 0.005 {
        let w = (rect.width() * clamped).clamp(3.0_f32.min(rect.width()), rect.width());
        let fill_rect = Rect::from_min_size(rect.min, Vec2::new(w, rect.height()));
        painter.rect_filled(fill_rect, radius, color);
    }
}

/// Stacked proportional segmented bar across multiple `(value, color, label)` categories.
pub fn segmented_bar(
    ui: &mut egui::Ui,
    segments: &[(f32, Color32, &str)],
    height: f32,
    tokens: &ThemeTokens,
) -> egui::Response {
    let w = ui.available_width().max(80.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, height), Sense::hover());

    let valid: Vec<(f32, Color32, &str)> = segments
        .iter()
        .copied()
        .filter(|(v, _, _)| v.is_finite() && *v > 0.0)
        .collect();
    let total: f32 = valid.iter().map(|(v, _, _)| *v).sum();

    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let radius = CornerRadius::same((height * 0.5).round().clamp(2.0, 255.0) as u8);
        painter.rect_filled(rect, radius, tokens.inset_bg);

        if total > 0.0 && !valid.is_empty() {
            let clipped = painter.with_clip_rect(rect);
            let gap = 1.5;
            let total_gaps = gap * (valid.len().saturating_sub(1) as f32);
            let usable_w = (rect.width() - total_gaps).max(0.0);
            let mut cursor_x = rect.min.x;

            for (idx, (val, col, _)) in valid.iter().enumerate() {
                let seg_w = if idx == valid.len() - 1 {
                    (rect.max.x - cursor_x).max(0.0)
                } else {
                    ((val / total) * usable_w).max(2.0)
                };
                if seg_w > 0.5 {
                    let seg_rect = Rect::from_min_size(
                        Pos2::new(cursor_x, rect.min.y),
                        Vec2::new(seg_w.min(rect.max.x - cursor_x), rect.height()),
                    );
                    let r = if valid.len() == 1 {
                        radius
                    } else if idx == 0 {
                        CornerRadius {
                            nw: radius.nw,
                            sw: radius.sw,
                            ne: 2,
                            se: 2,
                        }
                    } else if idx == valid.len() - 1 {
                        CornerRadius {
                            nw: 2,
                            sw: 2,
                            ne: radius.ne,
                            se: radius.se,
                        }
                    } else {
                        CornerRadius::same(2)
                    };
                    clipped.rect_filled(seg_rect, r, *col);
                }
                cursor_x += seg_w + gap;
            }
            painter.rect_stroke(
                rect,
                radius,
                Stroke::new(1.0, tokens.border_subtle),
                StrokeKind::Inside,
            );
        }
    }

    if total > 0.0 && !valid.is_empty() {
        resp.on_hover_ui(|ui| {
            for (val, col, label) in &valid {
                let pct = (*val / total) * 100.0;
                ui.horizontal(|ui| {
                    let (d, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                    ui.painter().circle_filled(d.center(), 3.5, *col);
                    ui.label(RichText::new(format!("{label}: {pct:.1}%")).size(11.5));
                });
            }
        })
    } else {
        resp
    }
}

/// Compact KPI metric tile inside an inset card.
pub fn kpi_tile(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    sub: Option<&str>,
    accent: Color32,
    tokens: &ThemeTokens,
) {
    inset_frame(tokens).show(ui, |ui| {
        ui.set_width(ui.available_width().max(110.0));
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            let (dot_rect, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
            ui.painter().circle_filled(dot_rect.center(), 3.0, accent);
            ui.label(RichText::new(label).size(11.0).color(tokens.text_secondary));
        });
        ui.add_space(2.0);
        ui.label(
            RichText::new(value)
                .size(17.0)
                .strong()
                .color(tokens.text_primary),
        );
        if let Some(subtext) = sub {
            ui.label(RichText::new(subtext).size(11.0).color(tokens.text_muted));
        }
    });
}

/// Consistent section heading + optional secondary subtitle.
/// Always stacks vertically when `subtitle` is present so it works safely inside `ui.horizontal`.
pub fn section_header(
    ui: &mut egui::Ui,
    title: &str,
    subtitle: Option<&str>,
    tokens: &ThemeTokens,
) {
    if let Some(sub) = subtitle {
        ui.vertical(|ui| {
            ui.label(
                RichText::new(title)
                    .size(15.5)
                    .strong()
                    .color(tokens.text_primary),
            );
            ui.label(RichText::new(sub).size(12.0).color(tokens.text_secondary));
        });
    } else {
        ui.label(
            RichText::new(title)
                .size(15.5)
                .strong()
                .color(tokens.text_primary),
        );
    }
}

/// Centered empty-state card with circular icon halo and optional primary CTA button.
/// Returns `true` if the CTA button was clicked.
pub fn empty_state(
    ui: &mut egui::Ui,
    icon: Icon,
    title: &str,
    subtitle: &str,
    cta: Option<&str>,
    tokens: &ThemeTokens,
) -> bool {
    let mut clicked = false;
    ui.add_space(16.0);
    ui.vertical_centered(|ui| {
        card_frame(tokens)
            .inner_margin(Margin::symmetric(28, 24))
            .show(ui, |ui| {
                ui.set_max_width(440.0);
                ui.vertical_centered(|ui| {
                    let (halo_rect, _) = ui.allocate_exact_size(Vec2::splat(48.0), Sense::hover());
                    if ui.is_rect_visible(halo_rect) {
                        ui.painter().circle_filled(
                            halo_rect.center(),
                            22.0,
                            theme::tint_on(
                                tokens.card_bg,
                                tokens.accent,
                                if tokens.is_dark { 0.16 } else { 0.12 },
                            ),
                        );
                        let icon_rect =
                            Rect::from_center_size(halo_rect.center(), Vec2::splat(24.0));
                        paint_icon(ui.painter(), icon_rect, icon, tokens.accent);
                    }
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(title)
                            .size(16.0)
                            .strong()
                            .color(tokens.text_primary),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(subtitle)
                            .size(12.5)
                            .color(tokens.text_secondary),
                    );
                    if let Some(cta_label) = cta {
                        ui.add_space(12.0);
                        if primary_button(ui, cta_label, true, tokens).clicked() {
                            clicked = true;
                        }
                    }
                });
            });
    });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_vector_icons_paint_cleanly_headlessly() {
        let ctx = egui::Context::default();
        let tokens = ThemeTokens::dark();
        let out = ctx.run_ui(egui::RawInput::default(), |ui| {
            for icon in Icon::ALL {
                icon_widget(ui, icon, 18.0, tokens.accent);
            }
        });
        out.drop_without_applying_deltas();
    }

    #[test]
    fn storage_ring_and_segmented_bar_handle_boundary_values() {
        let ctx = egui::Context::default();
        for tokens in [ThemeTokens::dark(), ThemeTokens::light()] {
            let out = ctx.run_ui(egui::RawInput::default(), |ui| {
                storage_ring(ui, 0.0, "0%", "empty", 60.0, tokens.accent, &tokens);
                storage_ring(ui, 1.0, "100%", "full", 60.0, tokens.danger, &tokens);
                storage_ring(ui, f32::NAN, "—", "nan", 60.0, tokens.warning, &tokens);
                storage_ring(ui, f32::INFINITY, "—", "inf", 60.0, tokens.info, &tokens);

                segmented_bar(ui, &[], 10.0, &tokens);
                segmented_bar(
                    ui,
                    &[
                        (0.0, tokens.accent, "zero"),
                        (f32::NAN, tokens.warning, "nan"),
                        (30.0, tokens.success, "a"),
                        (70.0, tokens.info, "b"),
                    ],
                    10.0,
                    &tokens,
                );
            });
            out.drop_without_applying_deltas();
        }
    }
}
