use crate::{design, file_picker::FilePicker};
use eframe::egui::{self, RichText};
use smol_studio::{
    machine_settings::{Folder, FolderMode, Port, Protocol, Settings},
    model::Operation,
};

pub struct Editor {
    original: Settings,
    draft: Settings,
    storage: String,
    overlay: String,
    pub error: Option<String>,
    last_error: Option<String>,
    picker: FilePicker,
    picking_folder: Option<usize>,
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
        let mut open = true;
        let mut action = None;
        let mut close = false;
        let error_changed = self.error != self.last_error;
        self.last_error = self.error.clone();
        egui::Window::new(format!("Settings · {}", self.original.name))
            .id(egui::Id::unique("machine-settings"))
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false).resizable(false)
            .fixed_size(egui::vec2(510.0, (ctx.content_rect().height() - 80.0).clamp(400.0, 680.0)))
            .open(&mut open).show(ctx, |ui| {
                ui.label(RichText::new("Changes apply on the next start. The machine stays stopped.").small().color(design::MUTED));
                ui.add_space(12.0);
                let enabled = !busy && !self.picking();
                let next = self.proposed();
                let form_height = (ui.available_height() - 80.0).max(180.0);
                ui.add_enabled_ui(enabled, |ui| {
                    let mut scroll = egui::ScrollArea::vertical().id_salt("machine-settings-form")
                        .max_height(form_height);
                    if error_changed { scroll = scroll.vertical_scroll_offset(0.0); }
                    scroll.show(ui, |ui| {
                            if let Some(error) = &self.error {
                                if error.len() < 240 && !error.contains('\n') { design::notice(ui, error); }
                                else { design::error_notice(ui, "Settings could not be saved.", error); }
                                ui.add_space(12.0);
                            }
                            if let Err(error) = &next { ui.label(RichText::new(error).small().color(design::RED)); ui.add_space(8.0); }
                            design::eyebrow(ui, "RESOURCES"); ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                ui.label("CPUs"); ui.add(egui::DragValue::new(&mut self.draft.cpus).range(1..=16.max(self.original.cpus)));
                                ui.label("Memory"); ui.add(egui::DragValue::new(&mut self.draft.memory_mib).range(64..=u32::MAX).speed(128).suffix(" MiB"));
                            });
                            ui.add_space(12.0);
                            ui.horizontal(|ui| {
                                ui.label("Storage disk"); ui.add(egui::TextEdit::singleline(&mut self.storage).desired_width(62.0).hint_text("Default")); ui.label("GiB");
                                ui.label("Overlay disk"); ui.add(egui::TextEdit::singleline(&mut self.overlay).desired_width(62.0).hint_text("Default")); ui.label("GiB");
                            });
                            ui.label(RichText::new("Disks can grow but cannot shrink. Existing data is retained.").small().color(design::MUTED));
                            ui.add_space(18.0); design::eyebrow(ui, "NETWORK"); ui.add_space(8.0);
                            ui.checkbox(&mut self.draft.network, "Enable networking");
                            ui.label(RichText::new("Existing egress rules are preserved.").small().color(design::MUTED));
                            ui.add_space(18.0); design::eyebrow(ui, "SHARED FOLDERS"); ui.add_space(8.0);
                            let mut remove = None;
                            let mut pick = None;
                            for (index, folder) in self.draft.shared_folders.iter_mut().enumerate() {
                                ui.push_id(("folder", index), |ui| {
                                    design::card().show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            ui.add(egui::TextEdit::singleline(&mut folder.host).desired_width(340.0).hint_text("Host folder"));
                                            if ui.button("Choose…").clicked() { pick = Some(index); }
                                        });
                                        ui.add_space(6.0);
                                        ui.horizontal(|ui| {
                                            ui.add(egui::TextEdit::singleline(&mut folder.guest).desired_width(180.0).hint_text("/workspace"));
                                            egui::ComboBox::from_id_salt("mode").selected_text(folder.mode.label()).show_ui(ui, |ui| {
                                                for mode in [FolderMode::ReadOnly, FolderMode::ReadWrite, FolderMode::Staged] { ui.selectable_value(&mut folder.mode, mode, mode.label()); }
                                            });
                                            if ui.small_button("Remove").clicked() { remove = Some(index); }
                                        });
                                        if folder.mode == FolderMode::Staged { ui.label(RichText::new("A guest-local copy is synchronized back on sync or graceful stop, including deletions.").small().color(design::MUTED)); }
                                    });
                                    ui.add_space(6.0);
                                });
                            }
                            if let Some(index) = remove { self.draft.shared_folders.remove(index); }
                            if let Some(index) = pick {
                                self.picking_folder = Some(index);
                                self.picker.open_folder(frame, &self.draft.shared_folders[index].host, ctx);
                            }
                            if ui.button("+ Add shared folder").clicked() {
                                self.draft.shared_folders.push(Folder { host: String::new(), guest: "/workspace".into(), mode: FolderMode::ReadOnly });
                            }
                            ui.add_space(18.0); design::eyebrow(ui, "PUBLISHED PORTS"); ui.add_space(8.0);
                            let mut remove = None;
                            for (index, port) in self.draft.port_mappings.iter_mut().enumerate() {
                                ui.push_id(("port", index), |ui| { ui.horizontal(|ui| {
                                    ui.label("Host"); ui.add(egui::DragValue::new(&mut port.host).range(1..=65535));
                                    ui.label("Guest"); ui.add(egui::DragValue::new(&mut port.guest).range(1..=65535));
                                    egui::ComboBox::from_id_salt("protocol").selected_text(if port.protocol == Protocol::Tcp { "TCP" } else { "UDP" }).show_ui(ui, |ui| {
                                        ui.selectable_value(&mut port.protocol, Protocol::Tcp, "TCP"); ui.selectable_value(&mut port.protocol, Protocol::Udp, "UDP");
                                    });
                                    if ui.small_button("Remove").clicked() { remove = Some(index); }
                                }); });
                            }
                            if let Some(index) = remove { self.draft.port_mappings.remove(index); }
                            if ui.button("+ Add port").clicked() { self.draft.port_mappings.push(Port { host: 8080, guest: 8080, protocol: Protocol::Tcp }); }
                        });
                    let next = self.proposed();
                    ui.add_space(10.0); ui.separator();
                    ui.horizontal(|ui| {
                        if ui.add_enabled(next.as_ref().is_ok_and(|next| next != &self.original), design::primary("Save changes")).clicked() {
                            self.error = None;
                            action = Some(Operation::UpdateSettings { original: Box::new(self.original.clone()), updated: Box::new(next.unwrap()) });
                        }
                        if ui.button("Cancel").clicked() { close = true; }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Reload").on_hover_text("Discard these edits and read the machine's current settings.").clicked() { self.error = None; action = Some(Operation::ReadSettings(self.original.name.clone())); }
                        });
                    });
                });
                if busy { ui.horizontal(|ui| { ui.spinner(); ui.label("Working…"); }); }
            });
        ((!open || close) && !busy && !self.picking(), action)
    }
}
