use crate::{design, file_picker::FilePicker};
use eframe::egui::{self, RichText};
use smol_studio::{
    files::{self, Listing},
    model::{Machine, Operation},
};
use std::path::PathBuf;

struct Transfer {
    name: String,
    guest: String,
    local: PathBuf,
    upload: bool,
}
struct Pick {
    name: String,
    guest: String,
    upload: bool,
}

pub struct FilesView {
    machine: String,
    path: String,
    requested: String,
    listing: Option<Listing>,
    attempted: bool,
    error: Option<String>,
    notice: Option<String>,
    filter: String,
    hidden: bool,
    history: files::History,
    history_target: Option<usize>,
    picker: FilePicker,
    picking: Option<Pick>,
    transfer: Option<Transfer>,
}
impl Default for FilesView {
    fn default() -> Self {
        Self {
            machine: String::new(),
            path: "/workspace".into(),
            requested: String::new(),
            listing: None,
            attempted: false,
            error: None,
            notice: None,
            filter: String::new(),
            hidden: false,
            history: files::History::default(),
            history_target: None,
            picker: FilePicker::default(),
            picking: None,
            transfer: None,
        }
    }
}
impl FilesView {
    pub fn modal_open(&self) -> bool {
        self.picker.is_open() || self.transfer.is_some()
    }
    pub fn receive(&mut self, name: &str, listing: Listing) {
        if self.machine == name && self.requested == listing.path {
            self.history
                .record(&listing.path, self.history_target.take());
            self.listing = Some(listing);
            self.error = None;
        }
    }
    pub fn failed(&mut self, name: &str, error: String) {
        if self.machine == name {
            self.history_target = None;
            self.error = Some(error);
        }
    }
    pub fn transferred(&mut self, name: &str, upload: bool, local: &std::path::Path) {
        self.transfer = None;
        if self.machine == name {
            self.notice = Some(if upload {
                "File uploaded.".into()
            } else {
                format!("Saved to {}", local.display())
            });
            self.attempted = false;
        }
    }
    fn request(&mut self) -> Option<Operation> {
        self.attempted = true;
        self.history_target = None;
        if self.path != self.requested {
            self.notice = None;
            self.filter.clear();
        }
        self.listing = None;
        if let Err(error) = files::validate_path(&self.path) {
            self.error = Some(error);
            return None;
        }
        self.requested = self.path.clone();
        self.error = None;
        Some(Operation::ListFiles {
            name: self.machine.clone(),
            path: self.path.clone(),
        })
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        frame: &eframe::Frame,
        machine: &Machine,
        enabled: bool,
    ) -> Option<Operation> {
        if self.machine != machine.name {
            *self = Self {
                machine: machine.name.clone(),
                ..Self::default()
            };
        }
        if machine.state != "running" {
            ui.add_space(24.0);
            design::empty_state(
                ui,
                design::Icon::Project,
                "Files are available when running",
                "Start this machine to browse its folders and transfer files.",
            );
            return None;
        }
        let mut action = None;
        if enabled && !self.attempted {
            action = self.request();
        }
        ui.add_enabled_ui(enabled && action.is_none(), |ui| {
            ui.horizontal(|ui| {
                let back = self.history.back().map(|(i, p)| (i, p.to_owned()));
                let forward = self.history.forward().map(|(i, p)| (i, p.to_owned()));
                for (label, hint, target) in [("←", "Back", back), ("→", "Forward", forward)] {
                    if ui
                        .add_enabled(target.is_some(), egui::Button::new(label))
                        .on_hover_text(hint)
                        .clicked()
                        && let Some((index, path)) = target
                    {
                        self.path = path;
                        self.filter.clear();
                        action = self.request();
                        self.history_target = Some(index);
                    }
                }
                if ui
                    .add_enabled(self.path != "/", egui::Button::new("↑"))
                    .on_hover_text("Parent folder")
                    .clicked()
                {
                    self.path = files::parent(&self.path);
                    self.filter.clear();
                    action = self.request();
                }
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .desired_width((ui.available_width() - 140.0).max(60.0))
                        .hint_text("/workspace"),
                );
                if ui.button("Go").clicked()
                    || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                {
                    action = self.request();
                }
                if ui.button("Refresh").clicked() {
                    action = self.request();
                }
            });
            ui.add_space(8.0);
            design::search(ui, &mut self.filter, "Filter files…");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.hidden, "Hidden files");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(
                            self.listing.is_some() && self.error.is_none(),
                            design::primary("Upload file…"),
                        )
                        .clicked()
                    {
                        self.picking = Some(Pick {
                            name: machine.name.clone(),
                            guest: self.requested.clone(),
                            upload: true,
                        });
                        self.picker.open_file(frame, None, ui.ctx());
                    }
                });
            });
        });
        ui.add_space(10.0);
        if let Some(error) = &self.error {
            design::error_notice(ui, "Files could not be loaded or transferred.", error);
        }
        if let Some(notice) = &self.notice {
            ui.label(RichText::new(notice).small().color(design::MUTED));
        }
        if let Some(listing) = &self.listing {
            let query = self.filter.to_lowercase();
            let entries: Vec<_> = listing
                .entries
                .iter()
                .filter(|e| {
                    (self.hidden || !e.name.starts_with('.'))
                        && e.name.to_lowercase().contains(&query)
                })
                .collect();
            ui.horizontal(|ui| {
                design::eyebrow(ui, "NAME");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} of {} {}",
                            entries.len(),
                            listing.entries.len(),
                            if listing.entries.len() == 1 {
                                "item"
                            } else {
                                "items"
                            }
                        ))
                        .small()
                        .color(design::MUTED),
                    );
                });
            });
            ui.separator();
            if entries.is_empty() {
                ui.add_space(12.0);
                ui.label(design::heading(
                    if listing.entries.is_empty() {
                        "This folder is empty"
                    } else {
                        "No matching files"
                    },
                    14.0,
                ));
                ui.label(
                    RichText::new(if listing.entries.is_empty() {
                        "Upload a file to put it in this folder."
                    } else {
                        "Try another name or show hidden files."
                    })
                    .size(12.0)
                    .color(design::MUTED),
                );
                if !listing.entries.is_empty() && ui.button("Clear filters").clicked() {
                    self.filter.clear();
                    self.hidden = true;
                }
                return action;
            }
            let mut navigate = None;
            egui::ScrollArea::vertical()
                .id_salt(("guest-file-list", &self.machine, &listing.path))
                .max_height(
                    (ui.clip_rect().bottom() - ui.cursor().top() - 12.0).clamp(100.0, 380.0),
                )
                .show_rows(ui, 38.0, entries.len(), |ui, rows| {
                    for row in rows {
                        let entry = entries[row];
                        ui.push_id(&entry.name, |ui| {
                            ui.add_enabled_ui(enabled && action.is_none(), |ui| {
                                ui.horizontal(|ui| {
                                    let display = entry
                                        .name
                                        .chars()
                                        .flat_map(|c| {
                                            if c.is_control() {
                                                c.escape_default().collect::<Vec<_>>()
                                            } else {
                                                vec![c]
                                            }
                                        })
                                        .collect::<String>();
                                    let (icon, _) = ui.allocate_exact_size(
                                        egui::vec2(20.0, 20.0),
                                        egui::Sense::hover(),
                                    );
                                    design::icon(
                                        ui.painter(),
                                        icon,
                                        if entry.kind == "dir" {
                                            design::Icon::Project
                                        } else {
                                            design::Icon::File
                                        },
                                        design::MUTED,
                                    );
                                    let response = ui.add_sized(
                                        [(ui.available_width() - 155.0).max(100.0), 32.0],
                                        egui::Button::new("")
                                            .left_text(display)
                                            .frame(false)
                                            .truncate(),
                                    );
                                    if response.on_hover_text(&entry.name).clicked()
                                        && entry.kind == "dir"
                                    {
                                        navigate = Some(files::join(&listing.path, &entry.name));
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if entry.kind == "file" {
                                                if ui.small_button("Save…").clicked() {
                                                    self.picking = Some(Pick {
                                                        name: machine.name.clone(),
                                                        guest: files::join(
                                                            &listing.path,
                                                            &entry.name,
                                                        ),
                                                        upload: false,
                                                    });
                                                    self.picker.open_file(
                                                        frame,
                                                        Some(&entry.name),
                                                        ui.ctx(),
                                                    );
                                                }
                                                ui.label(
                                                    RichText::new(byte_size(entry.size))
                                                        .small()
                                                        .color(design::MUTED),
                                                );
                                            } else {
                                                ui.label(
                                                    RichText::new(match entry.kind.as_str() {
                                                        "dir" => "Folder",
                                                        "symlink" => "Symbolic link",
                                                        _ => "Special file",
                                                    })
                                                    .small()
                                                    .color(design::MUTED),
                                                );
                                            }
                                        },
                                    );
                                });
                            });
                        });
                    }
                });
            if let Some(path) = navigate {
                self.path = path;
                self.filter.clear();
                action = self.request();
            }
        } else if self.error.is_none() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Reading folder…");
            });
        }
        action
    }
    pub fn dialog(&mut self, ctx: &egui::Context, busy: bool) -> Option<Operation> {
        if let Some(selection) = self.picker.poll(ctx)
            && let (Some(pick), Some(files)) = (self.picking.take(), selection)
            && let Some(file) = files.first()
        {
            let local = file.path().to_path_buf();
            let guest = if pick.upload {
                let Some(name) = local.file_name().and_then(|n| n.to_str()) else {
                    self.error = Some("Choose a filename that can be represented in UTF-8.".into());
                    return None;
                };
                files::join(&pick.guest, name)
            } else {
                pick.guest
            };
            self.transfer = Some(Transfer {
                name: pick.name,
                guest,
                local,
                upload: pick.upload,
            });
            self.error = None;
        }
        let transfer = self.transfer.as_mut()?;
        let mut open = true;
        let mut cancel = false;
        let mut action = None;
        egui::Window::new(if transfer.upload { "Upload file" } else { "Save file" })
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .fixed_size(egui::vec2(
                500.0,
                (ctx.content_rect().height() - 120.0).clamp(360.0, 460.0),
            ))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(RichText::new(if transfer.upload {
                    "Copy a file from your computer into this machine."
                } else {
                    "Save a copy of a machine file to your computer."
                }).size(12.0).color(design::MUTED));
                ui.add_space(12.0);
                let body_height = (ui.available_height() - 60.0).max(180.0);
                egui::ScrollArea::vertical()
                    .id_salt("file-transfer-form")
                    .max_height(body_height)
                    .show(ui, |ui| {
                        if let Some(error) = &self.error {
                            design::error_notice(ui, "Transfer failed. Your paths are kept below.", error);
                            ui.add_space(12.0);
                        }
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new("On your computer").size(11.5).color(design::MUTED));
                            ui.add(egui::Label::new(transfer.local.display().to_string()).wrap().selectable(true));
                        });
                        ui.add_space(12.0);
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(format!("In {}", transfer.name)).size(11.5).color(design::MUTED));
                            ui.add_enabled_ui(!busy, |ui| {
                                ui.add(egui::TextEdit::singleline(&mut transfer.guest).desired_width(f32::INFINITY));
                            });
                            if let Err(error) = files::validate_path(&transfer.guest) {
                                ui.label(RichText::new(error).small().color(design::RED));
                            }
                        });
                        ui.add_space(12.0);
                        ui.label(RichText::new("An existing file at the destination will be replaced. Files up to 4 GiB are supported.").size(11.5).color(design::MUTED));
                    });
                ui.add_space((ui.available_height() - 48.0).max(12.0));
                ui.separator();
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if busy { ui.spinner(); ui.label("Transferring…"); }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add_enabled(!busy && files::validate_path(&transfer.guest).is_ok(), design::primary(if transfer.upload { "Upload file" } else { "Save file" })).clicked() {
                            self.error = None;
                            action = Some(Operation::TransferFile {
                                name: transfer.name.clone(), guest: transfer.guest.clone(),
                                local: transfer.local.clone(), upload: transfer.upload,
                            });
                        }
                        if ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked() { cancel = true; }
                    });
                });
            });
        if !busy && (cancel || !open || ctx.input(|i| i.key_pressed(egui::Key::Escape))) {
            self.transfer = None;
        }
        action
    }
}
fn byte_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
