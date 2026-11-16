use super::{DockerView, PickMode};
use crate::design::{self, MUTED};
use eframe::egui::{self, RichText};
use smol_studio::docker::Action;

impl DockerView {
    pub(super) fn project_form(&mut self, ui: &mut egui::Ui, frame: &eframe::Frame) {
        let ctx = ui.ctx().clone();
        let enabled = self.pending.is_none();
        let body_height = (ui.available_height() - 80.0).max(100.0);
        egui::ScrollArea::vertical().id_salt("compose-form").max_height(body_height).auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(12.0);
            ui.label(design::heading(if self.compose_name.is_some() { "Project settings" } else { "Open a Compose project" }, 20.0));
            if let Some(name) = &self.compose_name { ui.add(egui::Label::new(RichText::new(name).color(MUTED)).wrap()); }
            if self.compose_discovered { ui.add_space(8.0); hint(ui, "Detected from Compose containers. Review profiles and environment before applying: the original profile choices and shell variables are not recorded."); }
            ui.add_space(16.0);
            ui.add_enabled_ui(enabled, |ui| {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(design::heading("Compose files", 14.0));
                    hint(ui, "Applied in order. Later files override the base configuration.");
                    ui.add_space(10.0);
                    hint(ui, "Project directory");
                    ui.add(egui::TextEdit::singleline(&mut self.compose_project_dir).desired_width(f32::INFINITY).hint_text("Default: directory of the first Compose file").margin(egui::Margin::symmetric(10, 9)));
                    hint(ui, "Resolves relative paths and the default .env file.");
                    ui.add_space(12.0);
                    if paths(ui, &mut self.compose_files, false) { self.file_error = None; }
                    ui.add_space(12.0);
                    ui.horizontal_wrapped(|ui| {
                        for (label, mode) in [("Choose files…", PickMode::Replace), ("Add files…", PickMode::Append)] {
                            if ui.button(label).clicked() {
                                self.pick_mode = mode;
                                self.file_picker.open_compose(frame, self.compose_files.first().map(String::as_str).unwrap_or(""), &ctx);
                            }
                        }
                    });
                });
                ui.add_space(12.0);
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(design::heading("Environment", 14.0));
                    hint(ui, "Choose files for Compose variable substitution. Later files override earlier values; inherited shell variables take precedence.");
                    ui.add_space(12.0);
                    ui.push_id("environment-files", |ui| { if paths(ui, &mut self.compose_env_files, true) { self.file_error = None; } });
                    if self.compose_env_files.is_empty() { hint(ui, "Using the project’s default .env file, if present."); }
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(self.compose_env_files.len() < 32, egui::Button::new("Choose environment files…")).clicked() {
                            self.pick_mode = PickMode::Environment;
                            self.file_picker.open_environment(frame, self.compose_env_files.first().or(self.compose_files.first()).map(String::as_str).unwrap_or(""), &ctx);
                        }
                        if ui.add_enabled(self.compose_env_files.len() < 32, egui::Button::new("Add path")).clicked() { self.compose_env_files.push(String::new()); }
                    });
                    ui.add_space(8.0);
                    hint(ui, "Studio remembers file paths, not their contents.");
                });
                ui.add_space(12.0);
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(design::heading("Profiles", 14.0));
                    hint(ui, "Enable additional services. Separate profiles with commas, or use * for all.");
                    ui.add_space(8.0);
                    ui.add(egui::TextEdit::singleline(&mut self.compose_profiles).desired_width(f32::INFINITY).hint_text("Default services only").margin(egui::Margin::symmetric(10, 9)));
                });
            });
            if let Some(error) = &self.file_error { ui.add_space(8.0); design::notice(ui, error); }
            if self.compose_files.iter().any(|p| !p.is_empty()) && let Err(error) = self.compose_source().validate() {
                ui.add_space(8.0); ui.label(RichText::new(error).small().color(design::RED));
            }
            ui.add_space(12.0);
        });
        ui.separator();
        ui.add_space(8.0);
        let source = self.compose_source();
        ui.add_enabled_ui(enabled && source.validate().is_ok(), |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.add(design::primary("Apply project…")).clicked() {
                    self.confirm = Some(Action::Compose {
                        source: source.clone(),
                        up: true,
                    });
                }
                if self.compose_name.is_some() && ui.button("Remove containers…").clicked() {
                    self.confirm = Some(Action::Compose {
                        source: source.clone(),
                        up: false,
                    });
                }
            });
        });
        hint(ui, "Named volumes are retained when you remove containers.");
    }
}

fn hint(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).size(11.5).color(MUTED)).wrap());
}

fn paths(ui: &mut egui::Ui, files: &mut Vec<String>, allow_empty: bool) -> bool {
    let mut changed = false;
    let length = files.len();
    let mut remove = None;
    let mut move_file = None;
    for (index, file) in files.iter_mut().enumerate() {
        ui.push_id(index, |ui| {
            if index > 0 {
                ui.add_space(10.0);
            }
            let filename = std::path::Path::new(file.as_str())
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("Choose a file");
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{}. {filename}", index + 1))
                        .small()
                        .color(MUTED),
                )
                .truncate(),
            );
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(allow_empty || length > 1, egui::Button::new("×"))
                        .on_hover_text("Remove file from this configuration")
                        .clicked()
                    {
                        remove = Some(index);
                    }
                    if ui
                        .add_enabled(index + 1 < length, egui::Button::new("↓"))
                        .on_hover_text("Apply later")
                        .clicked()
                    {
                        move_file = Some((index, index + 1));
                    }
                    if ui
                        .add_enabled(index > 0, egui::Button::new("↑"))
                        .on_hover_text("Apply earlier")
                        .clicked()
                    {
                        move_file = Some((index, index - 1));
                    }
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(file)
                                .hint_text("Paste the full path")
                                .desired_width(ui.available_width())
                                .margin(egui::Margin::symmetric(10, 9)),
                        )
                        .changed();
                });
            });
        });
    }
    if let Some(index) = remove {
        files.remove(index);
        changed = true;
    }
    if let Some((from, to)) = move_file {
        files.swap(from, to);
        changed = true;
    }
    changed
}
