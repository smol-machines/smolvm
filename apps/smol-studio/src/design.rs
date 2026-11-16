//! Shared native UI primitives. Vector icons and bounded rows need no assets or web renderer.
use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};

/// Semantic colors shared by both native system appearances.
#[derive(Clone, Copy)]
pub struct Palette {
    pub ink: Color32,
    pub muted: Color32,
    pub sidebar: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub line: Color32,
    pub surface: Color32,
    pub base: Color32,
    pub selected: Color32,
    pub green: Color32,
    pub red: Color32,
    pub error_background: Color32,
    pub danger_fill: Color32,
    hover: Color32,
    hover_line: Color32,
}

impl Palette {
    fn for_theme(theme: egui::Theme) -> Self {
        if theme == egui::Theme::Dark {
            Self {
                ink: Color32::from_rgb(236, 238, 242),
                muted: Color32::from_rgb(163, 167, 176),
                sidebar: Color32::from_rgb(19, 20, 23),
                accent: Color32::from_rgb(236, 238, 242),
                on_accent: Color32::from_rgb(24, 25, 28),
                line: Color32::from_rgb(61, 64, 71),
                surface: Color32::from_rgb(30, 32, 36),
                base: Color32::from_rgb(24, 25, 28),
                selected: Color32::from_rgb(49, 52, 59),
                green: Color32::from_rgb(117, 202, 140),
                red: Color32::from_rgb(255, 146, 138),
                error_background: Color32::from_rgb(55, 30, 29),
                danger_fill: Color32::from_rgb(179, 38, 30),
                hover: Color32::from_rgb(40, 42, 48),
                hover_line: Color32::from_rgb(100, 104, 114),
            }
        } else {
            Self {
                ink: Color32::from_rgb(17, 17, 17),
                muted: Color32::from_rgb(104, 106, 111),
                sidebar: Color32::from_rgb(243, 244, 246),
                accent: Color32::from_rgb(17, 17, 17),
                on_accent: Color32::WHITE,
                line: Color32::from_rgb(226, 226, 227),
                surface: Color32::from_rgb(249, 249, 250),
                base: Color32::WHITE,
                selected: Color32::from_rgb(232, 235, 239),
                green: Color32::from_rgb(44, 122, 63),
                red: Color32::from_rgb(179, 38, 30),
                error_background: Color32::from_rgb(255, 243, 242),
                danger_fill: Color32::from_rgb(179, 38, 30),
                hover: Color32::from_rgb(243, 243, 243),
                hover_line: Color32::from_rgb(188, 188, 192),
            }
        }
    }
}

pub fn palette(ui: &egui::Ui) -> Palette {
    Palette::for_theme(egui::Theme::from_dark_mode(ui.visuals().dark_mode))
}

#[derive(Clone, Copy)]
pub enum Icon {
    Machine,
    Cloud,
    Containers,
    Settings,
    Image,
    Volume,
    Project,
    File,
    Network,
}

pub fn icon(painter: &egui::Painter, rect: egui::Rect, kind: Icon, color: Color32) {
    let r = rect.shrink(2.0);
    let stroke = Stroke::new(1.5, color);
    let point = |x: f32, y: f32| r.min + egui::vec2(x * r.width(), y * r.height());
    match kind {
        Icon::File => {
            painter.add(egui::Shape::closed_line(
                vec![
                    point(0.15, 0.0),
                    point(0.62, 0.0),
                    point(0.88, 0.26),
                    point(0.88, 1.0),
                    point(0.15, 1.0),
                ],
                stroke,
            ));
            painter.line_segment([point(0.62, 0.0), point(0.62, 0.26)], stroke);
            painter.line_segment([point(0.62, 0.26), point(0.88, 0.26)], stroke);
        }
        Icon::Project => {
            painter.add(egui::Shape::closed_line(
                vec![
                    point(0.0, 0.16),
                    point(0.4, 0.16),
                    point(0.52, 0.32),
                    point(1.0, 0.32),
                    point(1.0, 0.9),
                    point(0.0, 0.9),
                ],
                stroke,
            ));
        }
        Icon::Network => {
            for (a, b) in [
                (point(0.5, 0.25), point(0.5, 0.55)),
                (point(0.15, 0.55), point(0.85, 0.55)),
                (point(0.15, 0.55), point(0.15, 0.75)),
                (point(0.85, 0.55), point(0.85, 0.75)),
            ] {
                painter.line_segment([a, b], stroke);
            }
            for (x, y) in [(0.5, 0.12), (0.15, 0.88), (0.85, 0.88)] {
                painter.rect_stroke(
                    egui::Rect::from_center_size(point(x, y), rect.size() * 0.24),
                    2,
                    stroke,
                    egui::StrokeKind::Inside,
                );
            }
        }
        Icon::Image => {
            painter.add(egui::Shape::line(
                vec![
                    point(0.5, 0.0),
                    point(1.0, 0.25),
                    point(0.5, 0.5),
                    point(0.0, 0.25),
                    point(0.5, 0.0),
                ],
                stroke,
            ));
            for y in [0.5, 0.75] {
                painter.add(egui::Shape::line(
                    vec![point(0.0, y), point(0.5, y + 0.25), point(1.0, y)],
                    stroke,
                ));
            }
        }
        Icon::Volume => {
            painter.rect_stroke(
                egui::Rect::from_min_max(point(0.0, 0.4), point(1.0, 1.0)),
                2,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.add(egui::Shape::line(
                vec![
                    point(0.0, 0.4),
                    point(0.2, 0.0),
                    point(0.8, 0.0),
                    point(1.0, 0.4),
                ],
                stroke,
            ));
            painter.circle_filled(point(0.75, 0.7), 1.5, color);
        }
        Icon::Machine => {
            painter.rect_stroke(
                egui::Rect::from_min_max(point(0.0, 0.05), point(1.0, 0.75)),
                2,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.line_segment([point(0.5, 0.75), point(0.5, 1.0)], stroke);
            painter.line_segment([point(0.25, 1.0), point(0.75, 1.0)], stroke);
        }
        Icon::Cloud => {
            painter.add(egui::Shape::line(
                vec![
                    point(0.22, 0.85),
                    point(0.1, 0.8),
                    point(0.02, 0.66),
                    point(0.04, 0.48),
                    point(0.18, 0.36),
                    point(0.3, 0.36),
                    point(0.34, 0.18),
                    point(0.5, 0.08),
                    point(0.68, 0.1),
                    point(0.8, 0.24),
                    point(0.81, 0.4),
                    point(0.95, 0.46),
                    point(1.0, 0.62),
                    point(0.95, 0.78),
                    point(0.8, 0.85),
                    point(0.22, 0.85),
                ],
                stroke,
            ));
        }
        Icon::Containers => {
            for (x, y) in [(0.0, 0.0), (0.55, 0.0), (0.0, 0.55), (0.55, 0.55)] {
                painter.rect_stroke(
                    egui::Rect::from_min_max(point(x, y), point(x + 0.4, y + 0.4)),
                    2,
                    stroke,
                    egui::StrokeKind::Inside,
                );
            }
        }
        Icon::Settings => {
            for (y, x) in [(0.18, 0.3), (0.5, 0.7), (0.82, 0.4)] {
                painter.line_segment([point(0.0, y), point(1.0, y)], stroke);
                painter.circle_filled(
                    point(x, y),
                    2.5,
                    Palette::for_theme(painter.ctx().theme()).surface,
                );
                painter.circle_stroke(point(x, y), 2.5, stroke);
            }
        }
    }
}

#[derive(Clone, Copy)]
pub enum ToolbarIcon {
    Back,
    Forward,
    Up,
    Refresh,
}

pub fn icon_button(
    ui: &mut egui::Ui,
    kind: ToolbarIcon,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let response = ui.add_enabled(enabled, egui::Button::new("").min_size(Vec2::splat(30.0)));
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, enabled && ui.is_enabled(), label)
    });
    let color = if enabled && ui.is_enabled() {
        palette(ui).muted
    } else {
        palette(ui).line
    };
    let center = response.rect.center();
    let stroke = Stroke::new(1.4, color);
    let point = |x, y| center + egui::vec2(x, y);
    match kind {
        ToolbarIcon::Refresh => {
            let points = (0..=20)
                .map(|i| {
                    let angle = 0.4 + i as f32 / 20.0 * 5.2;
                    point(angle.cos() * 5.5, angle.sin() * 5.5)
                })
                .collect();
            ui.painter().add(egui::Shape::line(points, stroke));
            ui.painter().add(egui::Shape::line(
                vec![point(1.0, -4.0), point(5.0, -3.0), point(5.0, -7.0)],
                stroke,
            ));
        }
        _ => {
            let transform = |x: f32, y: f32| match kind {
                ToolbarIcon::Forward => point(-x, y),
                ToolbarIcon::Up => point(y, x),
                _ => point(x, y),
            };
            ui.painter()
                .line_segment([transform(-5.0, 0.0), transform(5.0, 0.0)], stroke);
            ui.painter().add(egui::Shape::line(
                vec![
                    transform(-1.0, -4.0),
                    transform(-5.0, 0.0),
                    transform(-1.0, 4.0),
                ],
                stroke,
            ));
        }
    }
    response.on_hover_text(label)
}

/// Keep untagged image identities recognizable without letting a digest dominate a heading.
fn image_label(image: &str) -> String {
    if let Some(digest) = image.strip_prefix("sha256:")
        && digest.len() == 64
        && digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        format!("Image {}", &digest[..12])
    } else {
        image.to_owned()
    }
}

pub fn nav(ui: &mut egui::Ui, selected: bool, kind: Icon, label: &str) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), 34.0],
        egui::Button::selectable(selected, "")
            .fill(if selected {
                palette(ui).base
            } else {
                Color32::TRANSPARENT
            })
            .stroke(if selected {
                Stroke::new(1.0, palette(ui).line)
            } else {
                Stroke::NONE
            })
            .corner_radius(6),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Button, ui.is_enabled(), selected, label)
    });
    row_feedback(ui, &response, selected);
    let color = if selected {
        palette(ui).accent
    } else {
        palette(ui).muted
    };
    let rect = response.rect;
    icon(
        ui.painter(),
        egui::Rect::from_center_size(
            egui::pos2(rect.left() + 18.0, rect.center().y),
            Vec2::splat(18.0),
        ),
        kind,
        color,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 36.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(13.0),
        if selected {
            palette(ui).accent
        } else {
            palette(ui).ink
        },
    );
    response
}

/// Separate label and shortcut anchors keep the command switcher aligned on every OS.
pub fn switcher_button(ui: &mut egui::Ui, shortcut: &str) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), 30.0],
        egui::Button::new("")
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0, palette(ui).line)),
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), "Go to workspace")
    });
    let rect = response.rect;
    ui.painter().text(
        rect.left_center() + egui::vec2(10.0, 0.0),
        egui::Align2::LEFT_CENTER,
        "Go to…",
        FontId::proportional(12.0),
        palette(ui).muted,
    );
    ui.painter().text(
        rect.right_center() - egui::vec2(10.0, 0.0),
        egui::Align2::RIGHT_CENTER,
        shortcut,
        FontId::proportional(11.0),
        palette(ui).muted,
    );
    response
}

pub fn nav_group(ui: &mut egui::Ui, label: &str) {
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.label(heading(label, 11.0).color(palette(ui).muted));
    });
    ui.add_space(4.0);
}

pub fn primary<'a>(ui: &egui::Ui, label: &'a str) -> egui::Button<'a> {
    egui::Button::new(RichText::new(label).color(palette(ui).on_accent))
        .fill(palette(ui).accent)
        .stroke(Stroke::NONE)
        .min_size(egui::vec2(0.0, 32.0))
}

/// Navigation tabs retain button focus and accessibility while using a quiet underline.
pub fn tab(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    let response = ui.add(
        egui::Button::selectable(
            selected,
            RichText::new(label).color(if selected {
                palette(ui).ink
            } else {
                palette(ui).muted
            }),
        )
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::NONE)
        .min_size(egui::vec2(0.0, 34.0)),
    );
    if selected {
        let r = response.rect;
        ui.painter().line_segment(
            [
                egui::pos2(r.left() + 8.0, r.bottom()),
                egui::pos2(r.right() - 8.0, r.bottom()),
            ],
            Stroke::new(2.0, palette(ui).ink),
        );
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect,
            4,
            Stroke::new(1.0, palette(ui).ink),
            egui::StrokeKind::Inside,
        );
    }
    response
}

fn row_feedback(ui: &egui::Ui, response: &egui::Response, selected: bool) {
    if response.hovered() && !selected {
        ui.painter()
            .rect_filled(response.rect, 6, palette(ui).surface);
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect,
            6,
            Stroke::new(1.0, palette(ui).ink),
            egui::StrokeKind::Inside,
        );
    }
}

pub fn state_color(ui: &egui::Ui, state: &str) -> Color32 {
    match state {
        "running" | "started" | "ready" | "healthy" => palette(ui).green,
        "failed" | "unreachable" | "error" | "unhealthy" => palette(ui).red,
        "paused" | "frozen" | "pausing" | "starting" => palette(ui).accent,
        _ => palette(ui).muted,
    }
}

pub fn badge(ui: &mut egui::Ui, state: &str) {
    let color = state_color(ui, state);
    egui::Frame::new()
        .fill(color.gamma_multiply(0.09))
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(9, 4))
        .show(ui, |ui| {
            ui.spacing_mut().interact_size.y = 16.0;
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(6.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 3.0, color);
                let mut chars = state.chars();
                let label = chars
                    .next()
                    .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
                    .unwrap_or_default();
                ui.label(RichText::new(label).size(12.0).color(color));
            });
        });
}

pub fn eyebrow(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .size(11.0)
            .strong()
            .color(palette(ui).muted),
    );
}

pub fn card(ctx: &egui::Context) -> egui::Frame {
    let colors = Palette::for_theme(ctx.theme());
    egui::Frame::new()
        .fill(colors.base)
        .stroke(Stroke::new(1.0, colors.line))
        .corner_radius(8)
        .inner_margin(16)
}

pub fn metric(ui: &mut egui::Ui, label: &str, value: &str, unit: &str) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).size(12.0).color(palette(ui).muted));
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(heading(value, 26.0));
            ui.label(RichText::new(unit).size(12.0).color(palette(ui).muted));
        });
    });
}

/// Equal-width filters keep the inventory toolbar quiet and easy to scan.
pub fn segmented<T: Copy + PartialEq>(ui: &mut egui::Ui, value: &mut T, options: &[(T, &str)]) {
    egui::Frame::new()
        .fill(palette(ui).selected.gamma_multiply(0.5))
        .corner_radius(7)
        .inner_margin(3)
        .show(ui, |ui| {
            let width =
                (ui.available_width() - 4.0 * (options.len() - 1) as f32) / options.len() as f32;
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.horizontal(|ui| {
                for (candidate, label) in options {
                    let selected = *value == *candidate;
                    if ui
                        .add_sized(
                            [width, 26.0],
                            egui::Button::selectable(
                                selected,
                                RichText::new(*label).size(11.5).color(if selected {
                                    palette(ui).ink
                                } else {
                                    palette(ui).muted
                                }),
                            )
                            .fill(if selected {
                                palette(ui).base
                            } else {
                                Color32::TRANSPARENT
                            })
                            .stroke(Stroke::NONE)
                            .corner_radius(5),
                        )
                        .clicked()
                    {
                        *value = *candidate;
                    }
                }
            });
        });
}

pub fn property(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.set_min_height(28.0);
        ui.label(RichText::new(label).size(13.0).color(palette(ui).muted));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add(egui::Label::new(RichText::new(value).size(13.0)).truncate())
                .on_hover_text(value);
        });
    });
}

pub fn memory(mib: u64) -> String {
    if mib >= 1024 {
        format!("{:.1} GiB", mib as f64 / 1024.0)
    } else {
        format!("{mib} MiB")
    }
}

/// The button supplies keyboard and accessibility semantics; text is laid out
/// separately so long image names cannot overlap the state indicator.
pub fn machine_row(
    ui: &mut egui::Ui,
    selected: bool,
    name: &str,
    subtitle: &str,
    state: &str,
) -> egui::Response {
    resource_row(ui, selected, name, subtitle, state, Icon::Machine)
}

pub fn resource_row(
    ui: &mut egui::Ui,
    selected: bool,
    name: &str,
    subtitle: &str,
    state: &str,
    kind: Icon,
) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), 60.0],
        egui::Button::selectable(selected, "")
            .fill(if selected {
                palette(ui).selected
            } else {
                Color32::TRANSPARENT
            })
            .stroke(Stroke::NONE)
            .corner_radius(6),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::Role::Button,
            ui.is_enabled(),
            selected,
            format!("{name}, {state}, {subtitle}"),
        )
    });
    row_feedback(ui, &response, selected);
    if selected && response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.shrink(2.0),
            4,
            Stroke::new(1.0, palette(ui).ink),
            egui::StrokeKind::Inside,
        );
    }
    let r = response.rect;
    let icon_rect =
        egui::Rect::from_center_size(egui::pos2(r.left() + 25.0, r.center().y), Vec2::splat(30.0));
    ui.painter().rect_filled(icon_rect, 8, palette(ui).base);
    icon(
        ui.painter(),
        icon_rect.shrink(6.0),
        kind,
        if selected {
            palette(ui).ink
        } else {
            palette(ui).muted
        },
    );
    let left = r.left() + 49.0;
    let painter = ui.painter_at(egui::Rect::from_min_max(
        egui::pos2(left, r.top()),
        egui::pos2(r.right() - 22.0, r.bottom()),
    ));
    let subtitle = if state.is_empty() {
        subtitle.to_owned()
    } else {
        let mut chars = state.chars();
        let label = chars
            .next()
            .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
            .unwrap_or_default();
        if subtitle.is_empty() {
            label
        } else {
            format!("{label} · {subtitle}")
        }
    };
    for (text, y, size, color) in [
        (name, 12.0, 13.0, palette(ui).ink),
        (subtitle.as_str(), 33.0, 11.5, palette(ui).muted),
    ] {
        let mut job = egui::text::LayoutJob::simple_singleline(
            text.to_owned(),
            if text == name {
                FontId::new(size, egui::FontFamily::Name("studio-heading".into()))
            } else {
                FontId::proportional(size)
            },
            color,
        );
        job.wrap.max_width = (r.width() - 74.0).max(1.0);
        job.wrap.max_rows = 1;
        job.wrap.break_anywhere = true;
        let galley = ui.fonts_mut(|f| f.layout_job(job));
        painter.galley(egui::pos2(left, r.top() + y), galley, color);
    }
    if !state.is_empty() {
        ui.painter().circle_filled(
            egui::pos2(r.right() - 13.0, r.center().y),
            3.0,
            state_color(ui, state),
        );
    }
    response.on_hover_text(format!("{name}\n{subtitle}"))
}

/// A shared identity block keeps machine and container inspectors aligned.
pub fn workload_heading(
    ui: &mut egui::Ui,
    kind: Icon,
    name: &str,
    image: &str,
    state: &str,
    health: Option<&str>,
) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 9, palette(ui).surface);
        ui.painter().rect_stroke(
            rect,
            9,
            Stroke::new(1.0, palette(ui).line),
            egui::StrokeKind::Inside,
        );
        icon(ui.painter(), rect.shrink(10.0), kind, palette(ui).ink);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.add(egui::Label::new(heading(name, 21.0)).truncate())
                .on_hover_text(name);
            ui.horizontal(|ui| {
                badge(ui, state);
                if let Some(health) = health {
                    badge(ui, health);
                }
                ui.add(
                    egui::Label::new(
                        RichText::new(image_label(image))
                            .size(12.0)
                            .color(palette(ui).muted),
                    )
                    .truncate(),
                )
                .on_hover_text(image);
            });
        });
    });
}

pub fn resource_heading(ui: &mut egui::Ui, kind: Icon, title: &str, subtitle: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(44.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 10, palette(ui).surface);
        ui.painter().rect_stroke(
            rect,
            10,
            Stroke::new(1.0, palette(ui).line),
            egui::StrokeKind::Inside,
        );
        icon(ui.painter(), rect.shrink(12.0), kind, palette(ui).muted);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.add(egui::Label::new(heading(title, 21.0)).truncate())
                .on_hover_text(title);
            if !subtitle.is_empty() {
                ui.add(
                    egui::Label::new(RichText::new(subtitle).size(12.0).color(palette(ui).muted))
                        .truncate(),
                )
                .on_hover_text(subtitle);
            }
        });
    });
}

pub fn search(ui: &mut egui::Ui, value: &mut String, hint: &str) {
    let response = ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(egui::Margin {
                left: 30,
                right: 10,
                top: 9,
                bottom: 9,
            }),
    );
    let center = egui::pos2(response.rect.left() + 14.0, response.rect.center().y - 1.0);
    ui.painter()
        .circle_stroke(center, 4.0, Stroke::new(1.2, palette(ui).muted));
    ui.painter().line_segment(
        [center + egui::vec2(3.0, 3.0), center + egui::vec2(6.0, 6.0)],
        Stroke::new(1.2, palette(ui).muted),
    );
    if ui.is_enabled() && ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
        response.request_focus();
    }
}

pub fn empty_state(ui: &mut egui::Ui, kind: Icon, title: &str, message: &str) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(56.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 14, palette(ui).surface);
    ui.painter().rect_stroke(
        rect,
        14,
        Stroke::new(1.0, palette(ui).line),
        egui::StrokeKind::Inside,
    );
    icon(ui.painter(), rect.shrink(15.0), kind, palette(ui).muted);
    ui.add_space(16.0);
    ui.label(heading(title, 20.0));
    ui.add_space(6.0);
    ui.add(egui::Label::new(RichText::new(message).size(13.0).color(palette(ui).muted)).wrap());
}

pub fn section_title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.allocate_ui_with_layout(
        egui::vec2(230.0_f32.min(ui.available_width()), 44.0),
        egui::Layout::top_down(egui::Align::LEFT),
        |ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.label(heading(title, 19.0));
            ui.add(
                egui::Label::new(RichText::new(subtitle).size(11.5).color(palette(ui).muted))
                    .truncate(),
            )
            .on_hover_text(subtitle);
        },
    );
}

pub fn notice(ui: &mut egui::Ui, message: &str) {
    egui::Frame::new()
        .fill(palette(ui).error_background)
        .corner_radius(8)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(message).color(palette(ui).red)).wrap());
        });
}

pub fn error_notice(ui: &mut egui::Ui, title: &str, detail: &str) {
    egui::Frame::new()
        .fill(palette(ui).error_background)
        .corner_radius(8)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).color(palette(ui).red));
            ui.collapsing("Details", |ui| {
                ui.add(
                    egui::Label::new(RichText::new(detail).size(12.0).color(palette(ui).muted))
                        .wrap(),
                );
                if ui.small_button("Copy error").clicked() {
                    ui.ctx().copy_text(detail.to_owned());
                }
            });
        });
}

/// The same licensed Inter font and monochrome tokens as smolmachines.com.
fn fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let mut regular = egui::FontData::from_static(include_bytes!("../assets/InterVariable.ttf"));
    regular.tweak.coords = egui::epaint::text::VariationCoords::new([(b"wght", 400.0)]);
    let mut semibold = regular.clone();
    semibold.tweak.coords = egui::epaint::text::VariationCoords::new([(b"wght", 600.0)]);
    fonts.font_data.insert("studio-body".into(), regular.into());
    fonts
        .font_data
        .insert("studio-heading".into(), semibold.into());
    fonts
        .families
        .get_mut(&egui::FontFamily::Proportional)
        .unwrap()
        .insert(0, "studio-body".into());
    let mut headings = fonts.families[&egui::FontFamily::Proportional].clone();
    headings.insert(0, "studio-heading".into());
    fonts
        .families
        .insert(egui::FontFamily::Name("studio-heading".into()), headings);
    ctx.set_fonts(fonts);
}

pub fn brand_texture(ctx: &egui::Context) -> egui::TextureHandle {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/brand-mark.png"))
        .expect("bundled brand mark");
    ctx.load_texture(
        "smol-brand",
        egui::ColorImage::from_rgba_unmultiplied(
            [icon.width as usize, icon.height as usize],
            &icon.rgba,
        ),
        egui::TextureOptions::LINEAR,
    )
}

pub fn heading(text: &str, size: f32) -> RichText {
    RichText::new(text)
        .family(egui::FontFamily::Name("studio-heading".into()))
        .size(size)
}

pub fn theme(ctx: &egui::Context) {
    fonts(ctx);
    ctx.set_theme(egui::ThemePreference::System);
    ctx.options_mut(|options| options.fallback_theme = egui::Theme::Light);
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        let colors = Palette::for_theme(theme);
        ctx.style_mut_of(theme, |style| {
            style
                .text_styles
                .insert(egui::TextStyle::Body, FontId::proportional(14.0));
            style
                .text_styles
                .insert(egui::TextStyle::Button, FontId::proportional(13.0));
            style
                .text_styles
                .insert(egui::TextStyle::Small, FontId::proportional(11.5));
            style.text_styles.insert(
                egui::TextStyle::Heading,
                FontId::new(18.0, egui::FontFamily::Name("studio-heading".into())),
            );
            style.spacing.item_spacing = Vec2::new(8.0, 6.0);
            style.spacing.button_padding = Vec2::new(11.0, 6.0);
            style.spacing.interact_size.y = 30.0;
            style.spacing.window_margin = egui::Margin::same(16);
            style.visuals.override_text_color = Some(colors.ink);
            style.visuals.hyperlink_color = colors.ink;
            style.visuals.panel_fill = colors.base;
            style.visuals.window_fill = colors.base;
            style.visuals.widgets.open.weak_bg_fill = colors.surface;
            style.visuals.window_corner_radius = 12.into();
            style.visuals.window_stroke = Stroke::new(1.0, colors.line);
            style.visuals.selection.bg_fill = colors.selected;
            style.visuals.selection.stroke = Stroke::new(1.0, colors.accent);
            style.visuals.widgets.noninteractive.corner_radius = 6.into();
            style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, colors.line);
            style.visuals.widgets.inactive.weak_bg_fill = colors.base;
            style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, colors.line);
            style.visuals.widgets.inactive.corner_radius = 5.into();
            style.visuals.widgets.hovered.weak_bg_fill = colors.hover;
            style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, colors.hover_line);
            style.visuals.widgets.hovered.corner_radius = 5.into();
            style.visuals.widgets.active.weak_bg_fill = colors.selected;
            style.visuals.widgets.active.corner_radius = 5.into();
            style.visuals.extreme_bg_color = colors.surface;
        });
    }
}

#[cfg(test)]
mod appearance_tests {
    use super::*;

    #[test]
    fn native_theme_changes_update_existing_context_without_an_override() {
        let ctx = egui::Context::default();
        theme(&ctx);
        for system_theme in [
            None,
            Some(egui::Theme::Dark),
            Some(egui::Theme::Light),
            None,
        ] {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    system_theme,
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        let dark = system_theme == Some(egui::Theme::Dark);
                        assert_eq!(ui.visuals().dark_mode, dark);
                        assert_eq!(ui.visuals().panel_fill, palette(ui).base);
                        assert_eq!(ui.visuals().override_text_color, Some(palette(ui).ink));
                    });
                },
            );
            output.textures_delta.clear();
            assert_eq!(
                ctx.options(|o| o.theme_preference),
                egui::ThemePreference::System
            );
        }
    }

    fn luminance(color: Color32) -> f64 {
        let linear = |value: u8| {
            let s = f64::from(value) / 255.0;
            if s <= 0.04045 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
    }
    fn contrast(a: Color32, b: Color32) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }
    #[test]
    fn text_and_action_colors_remain_readable_in_both_appearances() {
        for theme in [egui::Theme::Light, egui::Theme::Dark] {
            let p = Palette::for_theme(theme);
            for text in [p.ink, p.muted, p.green, p.red] {
                for background in [p.base, p.surface, p.sidebar] {
                    assert!(
                        contrast(text, background) >= 4.5,
                        "{theme:?}: {text:?} on {background:?}"
                    );
                }
            }
            assert!(contrast(p.accent, p.on_accent) >= 4.5);
            assert!(contrast(p.red, p.error_background) >= 4.5);
            assert!(contrast(Color32::WHITE, p.danger_fill) >= 4.5);
        }
    }
}
