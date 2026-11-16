//! Shared native UI primitives. Vector icons and bounded rows need no assets or web renderer.
use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};

pub const INK: Color32 = Color32::from_rgb(17, 17, 17);
pub const MUTED: Color32 = Color32::from_rgb(104, 106, 111);
pub const SIDEBAR: Color32 = Color32::from_rgb(243, 244, 246);
pub const ACCENT: Color32 = Color32::from_rgb(17, 17, 17);
pub const LINE: Color32 = Color32::from_rgb(226, 226, 227);
pub const SURFACE: Color32 = Color32::from_rgb(249, 249, 250);
pub const SELECTED: Color32 = Color32::from_rgb(232, 235, 239);
pub const GREEN: Color32 = Color32::from_rgb(44, 122, 63);
pub const RED: Color32 = Color32::from_rgb(179, 38, 30);

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
                painter.circle_filled(point(x, y), 2.5, SURFACE);
                painter.circle_stroke(point(x, y), 2.5, stroke);
            }
        }
    }
}

pub fn nav(ui: &mut egui::Ui, selected: bool, kind: Icon, label: &str) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), 34.0],
        egui::Button::selectable(selected, "")
            .fill(if selected {
                Color32::WHITE
            } else {
                Color32::TRANSPARENT
            })
            .stroke(if selected {
                Stroke::new(1.0, LINE)
            } else {
                Stroke::NONE
            })
            .corner_radius(6),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Button, ui.is_enabled(), selected, label)
    });
    row_feedback(ui, &response, selected);
    let color = if selected { ACCENT } else { MUTED };
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
        if selected { ACCENT } else { INK },
    );
    response
}

/// Separate label and shortcut anchors keep the command switcher aligned on every OS.
pub fn switcher_button(ui: &mut egui::Ui, shortcut: &str) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), 30.0],
        egui::Button::new("")
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0, LINE)),
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
        MUTED,
    );
    ui.painter().text(
        rect.right_center() - egui::vec2(10.0, 0.0),
        egui::Align2::RIGHT_CENTER,
        shortcut,
        FontId::proportional(11.0),
        MUTED,
    );
    response
}

pub fn nav_group(ui: &mut egui::Ui, label: &str) {
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.label(heading(label, 11.0).color(MUTED));
    });
    ui.add_space(4.0);
}

pub fn primary(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(Color32::WHITE))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .min_size(egui::vec2(0.0, 32.0))
}

/// Navigation tabs retain button focus and accessibility while using a quiet underline.
pub fn tab(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    let response = ui.add(
        egui::Button::selectable(
            selected,
            RichText::new(label).color(if selected { INK } else { MUTED }),
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
            Stroke::new(2.0, INK),
        );
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect,
            4,
            Stroke::new(1.0, INK),
            egui::StrokeKind::Inside,
        );
    }
    response
}

fn row_feedback(ui: &egui::Ui, response: &egui::Response, selected: bool) {
    if response.hovered() && !selected {
        ui.painter().rect_filled(response.rect, 6, SURFACE);
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect,
            6,
            Stroke::new(1.0, INK),
            egui::StrokeKind::Inside,
        );
    }
}

pub fn state_color(state: &str) -> Color32 {
    match state {
        "running" | "started" | "ready" | "healthy" => GREEN,
        "failed" | "unreachable" | "error" | "unhealthy" => RED,
        "paused" | "frozen" | "pausing" | "starting" => ACCENT,
        _ => MUTED,
    }
}

pub fn badge(ui: &mut egui::Ui, state: &str) {
    let color = state_color(state);
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
    ui.label(RichText::new(text).size(11.0).strong().color(MUTED));
}

pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(Color32::WHITE)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(8)
        .inner_margin(16)
}

pub fn metric(ui: &mut egui::Ui, label: &str, value: &str, unit: &str) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).size(12.0).color(MUTED));
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(heading(value, 26.0));
            ui.label(RichText::new(unit).size(12.0).color(MUTED));
        });
    });
}

/// Equal-width filters keep the inventory toolbar quiet and easy to scan.
pub fn segmented<T: Copy + PartialEq>(ui: &mut egui::Ui, value: &mut T, options: &[(T, &str)]) {
    egui::Frame::new()
        .fill(SELECTED.gamma_multiply(0.5))
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
                                    INK
                                } else {
                                    MUTED
                                }),
                            )
                            .fill(if selected {
                                Color32::WHITE
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
        ui.label(RichText::new(label).size(13.0).color(MUTED));
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
                SELECTED
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
            Stroke::new(1.0, INK),
            egui::StrokeKind::Inside,
        );
    }
    let r = response.rect;
    let icon_rect =
        egui::Rect::from_center_size(egui::pos2(r.left() + 25.0, r.center().y), Vec2::splat(30.0));
    ui.painter().rect_filled(icon_rect, 8, Color32::WHITE);
    icon(
        ui.painter(),
        icon_rect.shrink(6.0),
        kind,
        if selected { INK } else { MUTED },
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
        (name, 12.0, 13.0, INK),
        (subtitle.as_str(), 33.0, 11.5, MUTED),
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
            state_color(state),
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
        ui.painter().rect_filled(rect, 9, SURFACE);
        ui.painter()
            .rect_stroke(rect, 9, Stroke::new(1.0, LINE), egui::StrokeKind::Inside);
        icon(ui.painter(), rect.shrink(10.0), kind, INK);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.add(egui::Label::new(heading(name, 21.0)).truncate())
                .on_hover_text(name);
            ui.horizontal(|ui| {
                badge(ui, state);
                if let Some(health) = health {
                    badge(ui, health);
                }
                ui.add(egui::Label::new(RichText::new(image).size(12.0).color(MUTED)).truncate())
                    .on_hover_text(image);
            });
        });
    });
}

pub fn resource_heading(ui: &mut egui::Ui, kind: Icon, title: &str, subtitle: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(44.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 10, SURFACE);
        ui.painter()
            .rect_stroke(rect, 10, Stroke::new(1.0, LINE), egui::StrokeKind::Inside);
        icon(ui.painter(), rect.shrink(12.0), kind, MUTED);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.add(egui::Label::new(heading(title, 21.0)).truncate())
                .on_hover_text(title);
            if !subtitle.is_empty() {
                ui.add(
                    egui::Label::new(RichText::new(subtitle).size(12.0).color(MUTED)).truncate(),
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
        .circle_stroke(center, 4.0, Stroke::new(1.2, MUTED));
    ui.painter().line_segment(
        [center + egui::vec2(3.0, 3.0), center + egui::vec2(6.0, 6.0)],
        Stroke::new(1.2, MUTED),
    );
    if ui.is_enabled() && ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
        response.request_focus();
    }
}

pub fn empty_state(ui: &mut egui::Ui, kind: Icon, title: &str, message: &str) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(56.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 14, SURFACE);
    ui.painter()
        .rect_stroke(rect, 14, Stroke::new(1.0, LINE), egui::StrokeKind::Inside);
    icon(ui.painter(), rect.shrink(15.0), kind, MUTED);
    ui.add_space(16.0);
    ui.label(heading(title, 20.0));
    ui.add_space(6.0);
    ui.add(egui::Label::new(RichText::new(message).size(13.0).color(MUTED)).wrap());
}

pub fn section_title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.allocate_ui_with_layout(
        egui::vec2(230.0_f32.min(ui.available_width()), 44.0),
        egui::Layout::top_down(egui::Align::LEFT),
        |ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.label(heading(title, 19.0));
            ui.add(egui::Label::new(RichText::new(subtitle).size(11.5).color(MUTED)).truncate())
                .on_hover_text(subtitle);
        },
    );
}

pub fn notice(ui: &mut egui::Ui, message: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(255, 243, 242))
        .corner_radius(8)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(message).color(RED)).wrap());
        });
}

pub fn error_notice(ui: &mut egui::Ui, title: &str, detail: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(255, 243, 242))
        .corner_radius(8)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).color(RED));
            ui.collapsing("Details", |ui| {
                ui.add(egui::Label::new(RichText::new(detail).size(12.0).color(MUTED)).wrap());
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
        .color(INK)
}

pub fn theme(ctx: &egui::Context) {
    fonts(ctx);
    ctx.set_theme(egui::ThemePreference::Light);
    ctx.style_mut_of(egui::Theme::Light, |style| {
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
        style.visuals.widgets.noninteractive.corner_radius = 6.into();
        style.spacing.window_margin = egui::Margin::same(16);
        style.visuals.override_text_color = Some(INK);
        style.visuals.hyperlink_color = INK;
        style.visuals.panel_fill = Color32::WHITE;
        style.visuals.window_fill = Color32::WHITE;
        style.visuals.widgets.open.weak_bg_fill = SURFACE;
        style.visuals.window_corner_radius = 12.into();
        style.visuals.window_stroke = Stroke::new(1.0, LINE);
        style.visuals.selection.bg_fill = SELECTED;
        style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
        style.visuals.widgets.inactive.weak_bg_fill = Color32::WHITE;
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE);
        style.visuals.widgets.inactive.corner_radius = 5.into();
        style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(243, 243, 243);
        style.visuals.widgets.hovered.bg_stroke =
            Stroke::new(1.0, Color32::from_rgb(188, 188, 192));
        style.visuals.widgets.hovered.corner_radius = 5.into();
        style.visuals.widgets.active.weak_bg_fill = SELECTED;
        style.visuals.widgets.active.corner_radius = 5.into();
        style.visuals.extreme_bg_color = SURFACE;
    });
}
