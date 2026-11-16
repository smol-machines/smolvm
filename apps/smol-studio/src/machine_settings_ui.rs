use crate::{design, file_picker::FilePicker};
use eframe::egui::{self, RichText};
use smol_studio::{
    machine_settings::{Folder, FolderMode, Port, Protocol, Settings},
    model::Operation,
};

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq)]
enum Tab {
    #[default]
    Resources,
    Folders,
    Ports,
}

pub struct Editor {
    original: Settings,
    draft: Settings,
    storage: String,
    overlay: String,
    tab: Tab,
    pub error: Option<String>,
    last_error: Option<String>,
    picker: FilePicker,
    picking_folder: Option<usize>,
}

fn label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(12.0).color(design::MUTED));
}

impl Editor {
    pub fn new(settings: Settings) -> Self {
        Self {
            storage: settings
                .storage_gb
                .map(|n| n.to_string())
                .unwrap_or_default(),
            overlay: settings
                .overlay_gb
                .map(|n| n.to_string())
                .unwrap_or_default(),
            draft: settings.clone(),
            original: settings,
            tab: Tab::default(),
            error: None,
            last_error: None,
            picker: FilePicker::default(),
            picking_folder: None,
        }
    }

    pub fn picking(&self) -> bool {
        self.picker.is_open()
    }

    fn proposed(&self) -> Result<Settings, String> {
        let mut next = self.draft.clone();
        for (text, value) in [
            (&self.storage, &mut next.storage_gb),
            (&self.overlay, &mut next.overlay_gb),
        ] {
            if !text.trim().is_empty() {
                *value = Some(
                    text.trim()
                        .parse()
                        .map_err(|_| "Enter disk sizes as whole GiB.")?,
                );
            }
        }
        self.original.update_args(&next)?;
        Ok(next)
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        frame: &eframe::Frame,
        busy: bool,
    ) -> (bool, Option<Operation>) {
        if let Some(selection) = self.picker.poll(ctx)
            && let (Some(index), Some(files)) = (self.picking_folder.take(), selection)
            && let Some(file) = files.first()
            && let Some(folder) = self.draft.shared_folders.get_mut(index)
        {
            if let Some(path) = file.path().to_str() {
                folder.host = path.to_owned();
            } else {
                self.error = Some("The selected folder path is not valid UTF-8.".into());
            }
        }
        let enabled = !busy && !self.picking();
        let mut open = true;
        let mut action = None;
        let mut close = false;
        let error_changed = self.error != self.last_error;
        self.last_error = self.error.clone();
        let mut window = egui::Window::new("Machine settings")
            .id(egui::Id::unique("machine-settings"))
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .fixed_size(egui::vec2(
                510.0,
                (ctx.content_rect().height() - 80.0).clamp(400.0, 680.0),
            ));
        if enabled {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            ui.add(egui::Label::new(design::heading(&self.original.name, 16.0)).truncate())
                .on_hover_text(&self.original.name);
            label(
                ui,
                "Changes apply on the next start. The machine stays stopped.",
            );
            ui.add_space(8.0);
            ui.add_enabled_ui(enabled, |ui| {
                ui.horizontal(|ui| {
                    for (tab, name) in [
                        (Tab::Resources, "Resources".to_owned()),
                        (
                            Tab::Folders,
                            format!("Folders ({})", self.draft.shared_folders.len()),
                        ),
                        (
                            Tab::Ports,
                            format!("Ports ({})", self.draft.port_mappings.len()),
                        ),
                    ] {
                        if design::tab(ui, self.tab == tab, &name).clicked() {
                            self.tab = tab;
                        }
                    }
                });
            });
            ui.separator();
            ui.add_space(8.0);
            let form_height = (ui.available_height() - 100.0).max(160.0);
            let mut scroll = egui::ScrollArea::vertical()
                .id_salt((
                    "machine-settings-form",
                    &self.original.name,
                    self.original.created_at,
                    self.tab,
                ))
                .max_height(form_height)
                .min_scrolled_height(form_height)
                .auto_shrink([false, false]);
            if error_changed {
                scroll = scroll.vertical_scroll_offset(0.0);
            }
            scroll.show(ui, |ui| {
                if let Some(error) = &self.error {
                    let summary = if error.len() < 240 && !error.contains('\n') {
                        error.as_str()
                    } else {
                        "Settings could not be saved. Your edits are kept."
                    };
                    design::error_notice(ui, summary, error);
                    ui.add_space(12.0);
                }
                ui.add_enabled_ui(enabled, |ui| match self.tab {
                    Tab::Resources => self.resources(ui),
                    Tab::Folders => self.folders(ui, ctx, frame),
                    Tab::Ports => self.ports(ui),
                });
            });
            let next = self.proposed();
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(4.0);
            // Keep validation and actions visible even when a folder list is long.
            if let Err(error) = &next {
                ui.add(egui::Label::new(RichText::new(error).small().color(design::RED)).wrap());
            } else {
                label(
                    ui,
                    if next.as_ref().is_ok_and(|next| next != &self.original) {
                        "Changes have not been saved."
                    } else {
                        "No changes to save."
                    },
                );
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if busy {
                    ui.spinner();
                    ui.label("Working…");
                } else if ui
                    .add_enabled(enabled, egui::Button::new("Reload"))
                    .on_hover_text("Discard these edits and read the machine's current settings.")
                    .clicked()
                {
                    self.error = None;
                    action = Some(Operation::ReadSettings(self.original.name.clone()));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(
                            enabled && next.as_ref().is_ok_and(|next| next != &self.original),
                            design::primary("Save changes"),
                        )
                        .clicked()
                    {
                        self.error = None;
                        action = Some(Operation::UpdateSettings {
                            original: Box::new(self.original.clone()),
                            updated: Box::new(next.unwrap()),
                        });
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

    fn resources(&mut self, ui: &mut egui::Ui) {
        design::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.columns(2, |columns| {
                label(&mut columns[0], "CPU limit");
                columns[0].add(
                    egui::DragValue::new(&mut self.draft.cpus)
                        .range(1..=16.max(self.original.cpus))
                        .suffix(" cores"),
                );
                label(&mut columns[1], "Memory limit");
                columns[1].add(
                    egui::DragValue::new(&mut self.draft.memory_mib)
                        .range(64..=u32::MAX)
                        .speed(128)
                        .suffix(" MiB"),
                );
            });
        });
        ui.add_space(16.0);
        ui.label(design::heading("Disks", 14.0));
        ui.add_space(8.0);
        design::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.columns(2, |columns| {
                for (column, (name, value)) in columns.iter_mut().zip([
                    ("Storage disk (GiB)", &mut self.storage),
                    ("Overlay disk (GiB)", &mut self.overlay),
                ]) {
                    label(column, name);
                    column.add(
                        egui::TextEdit::singleline(value)
                            .desired_width(f32::INFINITY)
                            .hint_text("Keep current size"),
                    );
                }
            });
            ui.add_space(10.0);
            label(
                ui,
                "Disks can grow but cannot shrink. Leave a size empty to keep it unchanged.",
            );
        });
        ui.add_space(16.0);
        design::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.checkbox(&mut self.draft.network, "Enable networking");
            label(
                ui,
                "Required for published ports. Existing egress rules are preserved.",
            );
        });
    }

    fn folders(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, frame: &eframe::Frame) {
        label(
            ui,
            "Make folders on your computer available inside this machine.",
        );
        ui.add_space(8.0);
        if ui.button("+ Add shared folder").clicked() {
            self.draft.shared_folders.push(Folder {
                host: String::new(),
                guest: "/workspace".into(),
                mode: FolderMode::ReadOnly,
            });
        }
        ui.add_space(12.0);
        if self.draft.shared_folders.is_empty() {
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label("No shared folders");
                label(ui, "Files already stored inside the machine stay there.");
            });
        }
        let mut remove = None;
        let mut pick = None;
        for (index, folder) in self.draft.shared_folders.iter_mut().enumerate() {
            ui.push_id(("folder", index), |ui| {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    label(ui, "On your computer");
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Choose…").clicked() { pick = Some(index); }
                            ui.add(egui::TextEdit::singleline(&mut folder.host).desired_width(f32::INFINITY).hint_text("Choose a folder…"));
                        });
                    });
                    ui.add_space(8.0);
                    label(ui, "Inside the machine");
                    ui.add(egui::TextEdit::singleline(&mut folder.guest).desired_width(f32::INFINITY).hint_text("/workspace"));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Remove").clicked() { remove = Some(index); }
                            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                label(ui, "Access");
                                egui::ComboBox::from_id_salt("mode").selected_text(folder.mode.label()).show_ui(ui, |ui| {
                                    for mode in [FolderMode::ReadOnly, FolderMode::ReadWrite, FolderMode::Staged] {
                                        ui.selectable_value(&mut folder.mode, mode, mode.label());
                                    }
                                });
                            });
                        });
                    });
                    if folder.mode == FolderMode::Staged {
                        ui.add_space(8.0);
                        label(ui, "A guest-local copy syncs back on sync or graceful stop, including deletions.");
                    }
                });
                ui.add_space(8.0);
            });
        }
        if let Some(index) = remove {
            self.draft.shared_folders.remove(index);
        }
        if let Some(index) = pick {
            self.picking_folder = Some(index);
            self.picker
                .open_folder(frame, &self.draft.shared_folders[index].host, ctx);
        }
    }

    fn ports(&mut self, ui: &mut egui::Ui) {
        label(
            ui,
            "Connect a port on your computer to a service inside this machine.",
        );
        ui.add_space(8.0);
        if !self.draft.network {
            ui.checkbox(
                &mut self.draft.network,
                "Enable networking for published ports",
            );
            ui.add_space(8.0);
        }
        if ui.button("+ Add port").clicked() {
            self.draft.port_mappings.push(Port {
                host: 8080,
                guest: 8080,
                protocol: Protocol::Tcp,
            });
        }
        ui.add_space(12.0);
        if self.draft.port_mappings.is_empty() {
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label("No published ports");
                label(ui, "Publish a port to reach a service from your computer.");
            });
        }
        let mut remove = None;
        for (index, port) in self.draft.port_mappings.iter_mut().enumerate() {
            ui.push_id(("port", index), |ui| {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.columns(3, |columns| {
                        label(&mut columns[0], "On your computer");
                        columns[0].add(egui::DragValue::new(&mut port.host).range(1..=65535));
                        label(&mut columns[1], "Inside the machine");
                        columns[1].add(egui::DragValue::new(&mut port.guest).range(1..=65535));
                        label(&mut columns[2], "Protocol");
                        egui::ComboBox::from_id_salt("protocol")
                            .selected_text(if port.protocol == Protocol::Tcp {
                                "TCP"
                            } else {
                                "UDP"
                            })
                            .width(70.0)
                            .show_ui(&mut columns[2], |ui| {
                                ui.selectable_value(&mut port.protocol, Protocol::Tcp, "TCP");
                                ui.selectable_value(&mut port.protocol, Protocol::Udp, "UDP");
                            });
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Remove").clicked() {
                                remove = Some(index);
                            }
                        });
                    });
                });
                ui.add_space(8.0);
            });
        }
        if let Some(index) = remove {
            self.draft.port_mappings.remove(index);
        }
    }
}
