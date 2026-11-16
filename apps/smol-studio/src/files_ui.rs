use crate::{design, file_picker::FilePicker};
use eframe::egui::{self, RichText};
use smol_studio::{
    files::{self, Listing, Request},
    model::{Machine, Operation},
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

struct Transfer {
    folder: bool,
    folder_name: String,
    name: String,
    guest: String,
    local: PathBuf,
    upload: bool,
}
struct Pick {
    folder: bool,
    name: String,
    guest: String,
    upload: bool,
}

pub struct FilesView {
    machine: String,
    display_name: String,
    container: bool,
    generation: String,
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
    transfer_note: Option<String>,
}
impl Default for FilesView {
    fn default() -> Self {
        Self {
            machine: String::new(),
            display_name: String::new(),
            container: false,
            generation: String::new(),
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
            transfer_note: None,
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
            self.transfer_note = None;
            self.history_target = None;
            self.error = Some(error);
        }
    }
    pub fn transferred(&mut self, name: &str, upload: bool, local: &std::path::Path) {
        self.transfer = None;
        self.transfer_note = None;
        if self.machine == name {
            self.notice = Some(if upload {
                "File uploaded.".into()
            } else {
                format!("Saved to {}", local.display())
            });
            self.attempted = false;
        }
    }
    pub fn transfer_stopped(&mut self, name: &str, upload: bool) {
        if self.machine == name {
            self.error = None;
            self.notice = None;
            self.transfer_note = Some(if upload {
                "Upload stopped. Some files may already have been written; refresh the destination before retrying."
            } else {
                "Download stopped. The partial copy was removed and your destination was left unchanged."
            }.into());
            self.attempted = false;
        }
    }
    fn request(&mut self) -> Option<Request> {
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
        Some(Request::List {
            target: self.machine.clone(),
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
        self.select_target(&machine.name, &machine.name, false, "/workspace");
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
        let request = self.show_contents(ui, frame, enabled);
        self.machine_operation(request)
    }

    fn select_target(&mut self, id: &str, name: &str, container: bool, initial: &str) {
        if self.machine != id || self.container != container {
            *self = Self {
                machine: id.into(),
                path: initial.into(),
                container,
                ..Self::default()
            };
        }
        self.display_name = name.into();
    }

    pub fn show_container(
        &mut self,
        ui: &mut egui::Ui,
        frame: &eframe::Frame,
        details: &smol_studio::container_details::ContainerDetails,
        enabled: bool,
    ) -> Option<Request> {
        self.select_target(&details.id, &details.name, true, "/");
        let generation = format!("{}:{}", details.state, details.started_at);
        if self.generation != generation {
            self.generation = generation;
            self.listing = None;
            self.attempted = false;
            self.error = None;
            self.notice = None;
        }
        if !matches!(
            details.state.as_str(),
            "created" | "running" | "paused" | "exited"
        ) {
            design::empty_state(
                ui,
                design::Icon::Project,
                "Files are unavailable",
                "Wait for the container to finish changing state, then refresh.",
            );
            return None;
        }
        self.show_contents(ui, frame, enabled)
    }

    fn show_contents(
        &mut self,
        ui: &mut egui::Ui,
        frame: &eframe::Frame,
        enabled: bool,
    ) -> Option<Request> {
        let mut action = None;
        if enabled && !self.attempted {
            action = self.request();
        }
        ui.add_enabled_ui(enabled && action.is_none(), |ui| {
            ui.horizontal(|ui| {
                let back = self.history.back().map(|(i, p)| (i, p.to_owned()));
                let forward = self.history.forward().map(|(i, p)| (i, p.to_owned()));
                for (icon, hint, target) in [
                    (design::ToolbarIcon::Back, "Back", back),
                    (design::ToolbarIcon::Forward, "Forward", forward),
                ] {
                    if design::icon_button(ui, icon, hint, target.is_some()).clicked()
                        && let Some((index, path)) = target
                    {
                        self.path = path;
                        self.filter.clear();
                        action = self.request();
                        self.history_target = Some(index);
                    }
                }
                if design::icon_button(
                    ui,
                    design::ToolbarIcon::Up,
                    "Parent folder",
                    self.path != "/",
                )
                .clicked()
                {
                    self.path = files::parent(&self.path);
                    self.filter.clear();
                    action = self.request();
                }
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .desired_width((ui.available_width() - 94.0).max(60.0))
                        .margin(egui::Margin::symmetric(10, 7))
                        .hint_text(if self.container { "/" } else { "/workspace" }),
                );
                if ui.button("Go").clicked()
                    || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                {
                    action = self.request();
                }
                if design::icon_button(ui, design::ToolbarIcon::Refresh, "Refresh folder", true)
                    .clicked()
                {
                    action = self.request();
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let search_width = (ui.available_width() - 160.0).max(100.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(search_width, 34.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        design::search(ui, &mut self.filter, "Filter files…");
                    },
                );
                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.hidden, "Show hidden files");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(
                            self.listing.is_some() && self.error.is_none(),
                            design::primary(ui, "Upload…"),
                        )
                        .clicked()
                    {
                        self.picking = Some(Pick {
                            folder: false,
                            name: self.machine.clone(),
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
            if files::guest_storage_failure(error) {
                design::error_notice(ui, "The machine reported a storage error.", error);
                ui.label(
                    RichText::new("The VM is running, but its persistent filesystem could not be accessed. Commands may fail too; changing DNS settings will not resolve this storage error.")
                        .size(12.0).color(design::palette(ui).muted),
                );
            } else {
                design::error_notice(ui, "Files could not be loaded or transferred.", error);
            }
        }
        if let Some(notice) = &self.notice {
            ui.label(
                RichText::new(notice)
                    .small()
                    .color(design::palette(ui).muted),
            );
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
                        .color(design::palette(ui).muted),
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
                    .color(design::palette(ui).muted),
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
                .max_height((ui.clip_rect().bottom() - ui.cursor().top() - 12.0).max(100.0))
                .show_rows(ui, 32.0, entries.len(), |ui, rows| {
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
                                    let response = ui.add_sized(
                                        [(ui.available_width() - 160.0).max(80.0), 32.0],
                                        egui::Button::new("").frame(false),
                                    );
                                    response.widget_info(|| {
                                        egui::WidgetInfo::labeled(
                                            egui::Role::Button,
                                            ui.is_enabled(),
                                            &display,
                                        )
                                    });
                                    let rect = response.rect;
                                    let color = if ui.is_enabled() {
                                        design::palette(ui).ink
                                    } else {
                                        design::palette(ui).muted
                                    };
                                    design::icon(
                                        ui.painter(),
                                        egui::Rect::from_center_size(
                                            egui::pos2(rect.left() + 12.0, rect.center().y),
                                            egui::Vec2::splat(18.0),
                                        ),
                                        if entry.kind == "dir" {
                                            design::Icon::Project
                                        } else {
                                            design::Icon::File
                                        },
                                        design::palette(ui).muted,
                                    );
                                    let mut job = egui::text::LayoutJob::simple_singleline(
                                        display,
                                        egui::FontId::proportional(13.0),
                                        color,
                                    );
                                    job.wrap.max_width = (rect.width() - 36.0).max(1.0);
                                    job.wrap.max_rows = 1;
                                    job.wrap.break_anywhere = true;
                                    let galley = ui.fonts_mut(|f| f.layout_job(job));
                                    let position = egui::pos2(
                                        rect.left() + 30.0,
                                        rect.center().y - galley.size().y / 2.0,
                                    );
                                    ui.painter_at(rect).galley(position, galley, color);
                                    if response.on_hover_text(&entry.name).clicked()
                                        && entry.kind == "dir"
                                    {
                                        navigate = Some(files::join(&listing.path, &entry.name));
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if entry.kind == "file"
                                                || (entry.kind == "dir" && self.container)
                                            {
                                                if ui.small_button("Save…").clicked() {
                                                    self.picking = Some(Pick {
                                                        folder: entry.kind == "dir",
                                                        name: self.machine.clone(),
                                                        guest: files::join(
                                                            &listing.path,
                                                            &entry.name,
                                                        ),
                                                        upload: false,
                                                    });
                                                    if entry.kind == "dir" {
                                                        self.picker
                                                            .folder_destination(frame, ui.ctx());
                                                    } else {
                                                        self.picker.open_file(
                                                            frame,
                                                            Some(&entry.name),
                                                            ui.ctx(),
                                                        );
                                                    }
                                                }
                                                ui.label(
                                                    RichText::new(if entry.kind == "dir" {
                                                        "Folder".into()
                                                    } else {
                                                        byte_size(entry.size)
                                                    })
                                                    .small()
                                                    .color(design::palette(ui).muted),
                                                );
                                            } else {
                                                ui.label(
                                                    RichText::new(match entry.kind.as_str() {
                                                        "dir" => "Folder",
                                                        "symlink" => "Symbolic link",
                                                        _ => "Special file",
                                                    })
                                                    .small()
                                                    .color(design::palette(ui).muted),
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
    pub fn dialog(
        &mut self,
        ctx: &egui::Context,
        busy: bool,
        interruption: Option<&AtomicBool>,
    ) -> Option<Operation> {
        let request = self.transfer_dialog(ctx, busy, interruption);
        self.machine_operation(request)
    }

    fn machine_operation(&mut self, request: Option<Request>) -> Option<Operation> {
        match request?.machine_operation() {
            Ok(operation) => Some(operation),
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    pub fn transfer_dialog(
        &mut self,
        ctx: &egui::Context,
        busy: bool,
        interruption: Option<&AtomicBool>,
    ) -> Option<Request> {
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
            let folder_name = if pick.folder {
                guest
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or("folder")
                    .to_owned()
            } else {
                String::new()
            };
            self.transfer = Some(Transfer {
                folder: pick.folder,
                folder_name,
                name: pick.name,
                guest,
                local,
                upload: pick.upload,
            });
            self.error = None;
            self.transfer_note = None;
        }
        let transfer = self.transfer.as_mut()?;
        let mut open = true;
        let mut cancel = false;
        let mut action = None;
        let stopping = interruption.is_some_and(|signal| signal.load(Ordering::Acquire));
        let title = if transfer.folder {
            "Save folder"
        } else if transfer.upload {
            "Upload file"
        } else {
            "Save file"
        };
        egui::Window::new(title)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .fixed_size(egui::vec2(
                500.0,
                (ctx.content_rect().height() - 120.0).clamp(360.0, if transfer.folder { 500.0 } else { 460.0 }),
            ))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(RichText::new(if transfer.upload {
                    if self.container { "Copy a file from your computer into this container." } else { "Copy a file from your computer into this machine." }
                } else if transfer.folder {
                    "Save this container folder and its contents to your computer."
                } else {
                    "Save a copy of this file to your computer."
                }).size(12.0).color(design::palette(ui).muted));
                ui.add_space(12.0);
                let body_height = (ui.available_height() - 60.0).max(180.0);
                egui::ScrollArea::vertical()
                    .id_salt("file-transfer-form")
                    .max_height(body_height)
                    .show(ui, |ui| {
                        if let Some(note) = &self.transfer_note {
                            design::card(ui.ctx()).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.add(egui::Label::new(note).wrap());
                            });
                            ui.add_space(12.0);
                        }
                        if let Some(error) = &self.error {
                            let summary = if error.len() < 240 && !error.contains('\n') {
                                error.as_str()
                            } else {
                                "Transfer failed. Your paths are kept below."
                            };
                            design::error_notice(ui, summary, error);
                            ui.add_space(12.0);
                        }
                        design::card(ui.ctx()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new("On your computer").size(11.5).color(design::palette(ui).muted));
                            ui.add(egui::Label::new(transfer.local.display().to_string()).wrap().selectable(true));
                            if transfer.folder {
                                ui.add_space(8.0);
                                ui.label(RichText::new("New folder name").small().color(design::palette(ui).muted));
                                ui.add_enabled(!busy, egui::TextEdit::singleline(&mut transfer.folder_name).desired_width(f32::INFINITY));
                                if let Err(error) = files::validate_folder_name(&transfer.folder_name) {
                                    ui.label(RichText::new(error).small().color(design::palette(ui).red));
                                }
                            }
                        });
                        ui.add_space(12.0);
                        design::card(ui.ctx()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(format!("In {}", self.display_name)).size(11.5).color(design::palette(ui).muted));
                            ui.add_enabled_ui(!busy, |ui| {
                                ui.add(egui::TextEdit::singleline(&mut transfer.guest).desired_width(f32::INFINITY));
                            });
                            if let Err(error) = files::validate_path(&transfer.guest) {
                                ui.label(RichText::new(error).small().color(design::palette(ui).red));
                            }
                        });
                        ui.add_space(12.0);
                        ui.label(RichText::new(if transfer.folder { "Creates a new folder after copying. Existing items stay untouched. Symbolic links remain links." } else if self.container && transfer.upload { "An existing file at the destination will be replaced. Uploads support files up to 4095 MiB." } else if self.container { "An existing file at the destination will be replaced." } else { "An existing file at the destination will be replaced. Files up to 4 GiB are supported." }).size(11.5).color(design::palette(ui).muted));
                    });
                ui.add_space((ui.available_height() - 48.0).max(12.0));
                ui.separator();
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if busy { ui.spinner(); ui.label(if stopping { "Stopping…" } else { "Transferring…" }); }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !busy && ui.add_enabled(files::validate_path(&transfer.guest).is_ok() && (!transfer.folder || files::validate_folder_name(&transfer.folder_name).is_ok()), design::primary(ui, title)).clicked() {
                            self.error = None;
                            self.transfer_note = None;
                            action = Some(if transfer.folder {
                                Request::SaveFolder {
                                    target: transfer.name.clone(), guest: transfer.guest.clone(),
                                    local: transfer.local.join(&transfer.folder_name),
                                }
                            } else {
                                Request::Transfer {
                                    target: transfer.name.clone(), guest: transfer.guest.clone(),
                                    local: transfer.local.clone(), upload: transfer.upload,
                                }
                            });
                        }
                        if busy && let Some(signal) = interruption {
                            if ui.add_enabled(!stopping, egui::Button::new("Stop transfer")).clicked() {
                                signal.store(true, Ordering::Release);
                            }
                        } else if ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked() { cancel = true; }
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
