//! Shared native UI primitives. Vector icons and bounded rows need no assets or web renderer.
use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};

pub const INK: Color32 = Color32::from_rgb(17, 17, 17);
pub const MUTED: Color32 = Color32::from_rgb(85, 85, 85);
pub const ACCENT: Color32 = Color32::from_rgb(17, 17, 17);
pub const LINE: Color32 = Color32::from_rgb(226, 226, 227);
pub const SURFACE: Color32 = Color32::from_rgb(249, 249, 249);
pub const SELECTED: Color32 = Color32::from_rgb(237, 237, 237);
pub const GREEN: Color32 = Color32::from_rgb(44, 122, 63);
pub const RED: Color32 = Color32::from_rgb(179, 38, 30);

#[derive(Clone, Copy)]
pub enum Icon {
    Machine,
    Cloud,
    Containers,
    Settings,
    Terminal,
}

pub fn icon(painter: &egui::Painter, rect: egui::Rect, kind: Icon, color: Color32) {
    let r = rect.shrink(2.0);
    let stroke = Stroke::new(1.5, color);
    let point = |x: f32, y: f32| r.min + egui::vec2(x * r.width(), y * r.height());
    match kind {
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
        Icon::Terminal => {
            painter.line_segment([point(0.1, 0.2), point(0.4, 0.5)], stroke);
            painter.line_segment([point(0.4, 0.5), point(0.1, 0.8)], stroke);
            painter.line_segment([point(0.55, 0.8), point(0.95, 0.8)], stroke);
        }
    }
}

pub fn nav(ui: &mut egui::Ui, selected: bool, kind: Icon, label: &str) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), 38.0],
        egui::Button::selectable(selected, ""),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Button, ui.is_enabled(), selected, label)
    });
    let color = if selected { ACCENT } else { MUTED };
    let rect = response.rect;
    icon(
        ui.painter(),
        egui::Rect::from_center_size(
            egui::pos2(rect.left() + 22.0, rect.center().y),
            Vec2::splat(20.0),
        ),
        kind,
        color,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 42.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(14.0),
        if selected { ACCENT } else { INK },
    );
    response
}

pub fn primary(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(Color32::WHITE))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .min_size(egui::vec2(0.0, 34.0))
}

pub fn state_color(state: &str) -> Color32 {
    match state {
        "running" | "started" | "ready" => GREEN,
        "failed" | "unreachable" | "error" => RED,
        "paused" | "frozen" | "pausing" | "starting" => ACCENT,
        _ => MUTED,
    }
}

pub fn badge(ui: &mut egui::Ui, state: &str) {
    let color = state_color(state);
    egui::Frame::new()
        .fill(color.gamma_multiply(0.09))
        .corner_radius(2)
        .inner_margin(egui::Margin::symmetric(10, 5))
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
        .corner_radius(0)
        .inner_margin(18)
}

pub fn metric(ui: &mut egui::Ui, label: &str, value: &str, unit: &str) {
    card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(label).size(12.0).color(MUTED));
        ui.horizontal(|ui| {
            ui.label(RichText::new(value).size(26.0).strong());
            ui.label(RichText::new(unit).size(12.0).color(MUTED));
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
    let response = ui.add_sized(
        [ui.available_width(), 64.0],
        egui::Button::selectable(selected, ""),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::Role::Button,
            ui.is_enabled(),
            selected,
            format!("{name}, {state}, {subtitle}"),
        )
    });
    let r = response.rect;
    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(r.min + egui::vec2(0.0, 12.0), egui::vec2(3.0, 40.0)),
            2,
            ACCENT,
        );
    }
    let icon_rect =
        egui::Rect::from_center_size(egui::pos2(r.left() + 25.0, r.center().y), Vec2::splat(30.0));
    ui.painter().rect_filled(
        icon_rect,
        7,
        if selected { Color32::WHITE } else { SURFACE },
    );
    icon(
        ui.painter(),
        icon_rect.shrink(6.0),
        Icon::Machine,
        if selected { ACCENT } else { MUTED },
    );
    let left = r.left() + 49.0;
    let painter = ui.painter_at(egui::Rect::from_min_max(
        egui::pos2(left, r.top()),
        egui::pos2(r.right() - 22.0, r.bottom()),
    ));
    for (text, y, size, color) in [(name, 13.0, 14.0, INK), (subtitle, 36.0, 11.5, MUTED)] {
        let mut job = egui::text::LayoutJob::simple_singleline(
            text.to_owned(),
            FontId::proportional(size),
            color,
        );
        job.wrap.max_width = (r.width() - 74.0).max(1.0);
        job.wrap.max_rows = 1;
        job.wrap.break_anywhere = true;
        let galley = ui.fonts_mut(|f| f.layout_job(job));
        painter.galley(egui::pos2(left, r.top() + y), galley, color);
    }
    ui.painter().circle_filled(
        egui::pos2(r.right() - 13.0, r.center().y),
        3.0,
        state_color(state),
    );
    response.on_hover_text(format!("{name}\n{subtitle}\n{state}"))
}

pub fn section_title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(heading(title, 24.0));
    ui.label(RichText::new(subtitle).color(MUTED));
}

pub fn notice(ui: &mut egui::Ui, message: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(255, 243, 242))
        .corner_radius(0)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(message).color(RED)).wrap());
        });
}

pub fn error_notice(ui: &mut egui::Ui, title: &str, detail: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(255, 243, 242))
        .corner_radius(0)
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
            FontId::new(23.0, egui::FontFamily::Name("studio-heading".into())),
        );
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(12.0, 7.0);
        style.spacing.interact_size.y = 32.0;
        style.spacing.window_margin = egui::Margin::same(20);
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
        style.visuals.widgets.inactive.corner_radius = 0.into();
        style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(243, 243, 243);
        style.visuals.widgets.hovered.bg_stroke =
            Stroke::new(1.0, Color32::from_rgb(136, 136, 136));
        style.visuals.widgets.hovered.corner_radius = 0.into();
        style.visuals.widgets.active.weak_bg_fill = SELECTED;
        style.visuals.widgets.active.corner_radius = 0.into();
        style.visuals.extreme_bg_color = SURFACE;
    });
}
