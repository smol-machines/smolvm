use crate::{design, file_picker::FilePicker};
use eframe::egui::{self, RichText};
use smol_studio::model::{Machine, NewMachine, Operation, PublishedPort, SharedFolder};

#[derive(Default)]
pub struct Editor {
    draft: NewMachine,
    pub error: Option<String>,
    last_error: Option<String>,
    focused: bool,
    picker: FilePicker,
    picking_folder: Option<usize>,
}

impl Editor {
    pub fn picking(&self) -> bool {
        self.picker.is_open()
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        frame: &eframe::Frame,
        machines: &[Machine],
        pending: Option<&Operation>,
        inventory_valid: bool,
    ) -> (bool, Option<Operation>) {
        if let Some(selection) = self.picker.poll(ctx)
            && let (Some(index), Some(files)) = (self.picking_folder.take(), selection)
            && let Some(file) = files.first()
            && let Some(folder) = self.draft.folders.get_mut(index)
        {
            match file.path().to_str() {
                Some(path) => folder.host = path.to_owned(),
                None => self.error = Some("The selected folder path is not valid UTF-8.".into()),
            }
        }
        let creating = matches!(pending, Some(Operation::Create(_)));
        let enabled = pending.is_none() && !self.picking();
        let mut open = true;
        let mut close = false;
        let mut action = None;
        let error_changed = self.error != self.last_error;
        self.last_error = self.error.clone();
        egui::Window::new("New machine")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .fixed_size(egui::vec2(
                510.0,
                (ctx.content_rect().height() - 80.0).clamp(400.0, 680.0),
            ))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Create a Linux environment on this computer.")
                        .size(12.0)
                        .color(design::MUTED),
                );
                ui.add_space(12.0);
                let form_height = (ui.available_height() - 82.0).max(180.0);
                ui.add_enabled_ui(enabled, |ui| {
                    let mut scroll = egui::ScrollArea::vertical()
                        .id_salt("new-machine-form")
                        .max_height(form_height);
                    if error_changed {
                        scroll = scroll.vertical_scroll_offset(0.0);
                    }
                    scroll.show(ui, |ui| {
                        if let Some(error) = &self.error {
                            design::error_notice(
                                ui,
                                "Machine could not be created. Your settings are kept below.",
                                error,
                            );
                            ui.add_space(12.0);
                        }
                        ui.label(design::heading("General", 14.0));
                        ui.add_space(6.0);
                        ui.label("Name");
                        let name = ui.add(
                            egui::TextEdit::singleline(&mut self.draft.name)
                                .desired_width(f32::INFINITY)
                                .hint_text("my-project"),
                        );
                        if !self.focused {
                            name.request_focus();
                            self.focused = true;
                        }
                        ui.add_space(8.0);
                        ui.label("Image");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.draft.image)
                                .desired_width(f32::INFINITY)
                                .hint_text("e.g. ubuntu:24.04 or alpine:3.21"),
                        );
                        ui.label(
                            RichText::new(
                                "Leave empty for bare Linux, or enter a local image path.",
                            )
                            .size(11.5)
                            .color(design::MUTED),
                        );
                        ui.add_space(16.0);
                        ui.label(design::heading("Resources", 14.0));
                        ui.add_space(6.0);
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.columns(2, |cols| {
                                cols[0].label(
                                    RichText::new("CPU limit").size(12.0).color(design::MUTED),
                                );
                                cols[0].add(
                                    egui::DragValue::new(&mut self.draft.cpus)
                                        .range(1..=64)
                                        .suffix(" cores"),
                                );
                                cols[1].label(
                                    RichText::new("Memory limit")
                                        .size(12.0)
                                        .color(design::MUTED),
                                );
                                cols[1].add(
                                    egui::DragValue::new(&mut self.draft.memory_mib)
                                        .range(256..=262_144)
                                        .speed(128)
                                        .suffix(" MiB"),
                                );
                            });
                        });
                        ui.add_space(16.0);
                        ui.label(design::heading("Connectivity", 14.0));
                        ui.checkbox(&mut self.draft.network, "Allow outbound network access");
                        ui.add_space(8.0);
                        egui::CollapsingHeader::new(format!(
                            "Shared folders · {}",
                            self.draft.folders.len()
                        ))
                        .id_salt("new-shared-folders")
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(
                                    "Make a folder on your computer available inside the machine.",
                                )
                                .small()
                                .color(design::MUTED),
                            );
                            let mut remove = None;
                            let mut pick = None;
                            for (index, folder) in self.draft.folders.iter_mut().enumerate() {
                                ui.push_id(("folder", index), |ui| {
                                    design::card().show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.label(
                                            RichText::new("On your computer")
                                                .small()
                                                .color(design::MUTED),
                                        );
                                        ui.horizontal(|ui| {
                                            ui.add(
                                                egui::TextEdit::singleline(&mut folder.host)
                                                    .desired_width(
                                                        (ui.available_width() - 90.0).max(100.0),
                                                    )
                                                    .hint_text("Choose a folder…"),
                                            );
                                            if ui.button("Choose…").clicked() {
                                                pick = Some(index);
                                            }
                                        });
                                        ui.label(
                                            RichText::new("Inside the machine")
                                                .small()
                                                .color(design::MUTED),
                                        );
                                        ui.add(
                                            egui::TextEdit::singleline(&mut folder.guest)
                                                .desired_width(f32::INFINITY)
                                                .hint_text("/workspace"),
                                        );
                                        ui.horizontal(|ui| {
                                            ui.checkbox(&mut folder.read_only, "Read only");
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if ui.small_button("Remove").clicked() {
                                                        remove = Some(index);
                                                    }
                                                },
                                            );
                                        });
                                    });
                                    ui.add_space(6.0);
                                });
                            }
                            if let Some(index) = remove {
                                self.draft.folders.remove(index);
                            }
                            if let Some(index) = pick {
                                self.picking_folder = Some(index);
                                self.picker.open_folder(
                                    frame,
                                    &self.draft.folders[index].host,
                                    ctx,
                                );
                            }
                            if ui.button("+ Add shared folder").clicked() {
                                self.draft.folders.push(SharedFolder {
                                    host: String::new(),
                                    guest: "/workspace".into(),
                                    read_only: true,
                                });
                            }
                        });
                        egui::CollapsingHeader::new(format!(
                            "Published ports · {}",
                            self.draft.ports.len()
                        ))
                        .id_salt("new-published-ports")
                        .show(ui, |ui| {
                            let mut remove = None;
                            for (index, port) in self.draft.ports.iter_mut().enumerate() {
                                ui.push_id(("port", index), |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label("Host");
                                        ui.add(
                                            egui::DragValue::new(&mut port.host).range(1..=65535),
                                        );
                                        ui.label("Guest");
                                        ui.add(
                                            egui::DragValue::new(&mut port.guest).range(1..=65535),
                                        );
                                        ui.label(RichText::new("TCP").small().color(design::MUTED));
                                        if ui.small_button("Remove").clicked() {
                                            remove = Some(index);
                                        }
                                    });
                                });
                            }
                            if let Some(index) = remove {
                                self.draft.ports.remove(index);
                            }
                            if ui.button("+ Add port").clicked() {
                                self.draft.ports.push(PublishedPort {
                                    host: 8080,
                                    guest: 8080,
                                });
                            }
                            ui.label(
                                RichText::new("Published ports also enable networking.")
                                    .small()
                                    .color(design::MUTED),
                            );
                        });
                        ui.add_space(8.0);
                        let duplicate = machines.iter().any(|m| m.name == self.draft.name);
                        if duplicate {
                            ui.label(
                                RichText::new("A machine with this name already exists.")
                                    .small()
                                    .color(design::RED),
                            );
                        } else if !self.draft.name.is_empty()
                            && let Err(e) = self.draft.validate()
                        {
                            ui.label(RichText::new(e).small().color(design::RED));
                        }
                    });
                });
                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    if creating {
                        ui.spinner();
                        ui.label(
                            RichText::new("Creating machine…")
                                .small()
                                .color(design::MUTED),
                        );
                    } else {
                        ui.label(
                            RichText::new("Starts when you’re ready.")
                                .small()
                                .color(design::MUTED),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let valid = self.draft.validate().is_ok()
                            && !machines.iter().any(|m| m.name == self.draft.name);
                        if ui
                            .add_enabled(
                                enabled && inventory_valid && valid,
                                design::primary("Create machine"),
                            )
                            .clicked()
                        {
                            self.error = None;
                            action = Some(Operation::Create(self.draft.clone()));
                        }
                        if ui
                            .add_enabled(enabled, egui::Button::new("Cancel"))
                            .clicked()
                        {
                            close = true;
                        }
                    });
                });
            });
        ((!open || close) && enabled, action)
    }
}
