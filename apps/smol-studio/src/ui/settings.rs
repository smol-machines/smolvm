use super::*;

impl Studio {
    pub(super) fn open_settings(&mut self) {
        if !self.settings {
            self.runtime_path = self.runtime.executable.to_string_lossy().into_owned();
            self.settings_error = None;
            self.settings_feedback = None;
            self.settings_scroll_error = false;
            self.settings = true;
        }
    }

    pub(super) fn finish_settings_check(
        &mut self,
        candidate: Runtime,
        result: Result<Payload, String>,
    ) {
        let result = (|| {
            let Payload::Machines(machines) = result? else {
                return Err("The CLI did not return a machine inventory.".into());
            };
            let changed = candidate != self.runtime;
            if changed {
                let mut preferences = smol_studio::preferences::Preferences::load()?;
                preferences.smol_cli = Some(candidate.executable.clone());
                preferences.save()?;
            }
            Ok((machines, changed))
        })();
        match result {
            Ok((machines, changed)) => {
                self.runtime = candidate;
                self.inventory.accept_snapshot();
                self.inventory_valid = true;
                self.machines = machines;
                self.schedule.completed(Instant::now());
                self.last_refresh = Some(Instant::now());
                if changed {
                    self.selected = self.machines.first().map(|m| m.name.clone());
                    self.output = None;
                    self.console_machine = None;
                    self.console_snapshot = None;
                    self.logs.reset();
                    self.tab = Tab::Overview;
                } else if !self
                    .machines
                    .iter()
                    .any(|m| Some(&m.name) == self.selected.as_ref())
                {
                    self.selected = self.machines.first().map(|m| m.name.clone());
                    self.logs.reset();
                    self.tab = Tab::Overview;
                }
                self.error = None;
                self.refresh_error = false;
                self.settings_error = None;
                self.settings_feedback = Some(
                    if changed {
                        "Saved and connected."
                    } else {
                        "Connection verified."
                    }
                    .into(),
                );
                self.activity = "Ready".into();
            }
            Err(error) => {
                self.settings_error = Some(error);
                self.settings_scroll_error = true;
                self.settings_feedback = None;
                self.activity = "CLI connection check failed".into();
            }
        }
    }

    pub(super) fn settings_dialog(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        if !self.settings {
            return;
        }
        if let Some(Some(files)) = self.settings_picker.poll(ctx)
            && let Some(file) = files.first()
        {
            self.runtime_path = file.path().to_string_lossy().into_owned();
            self.settings_error = None;
            self.settings_feedback = None;
        }
        let checking = self.settings_candidate.is_some();
        let picking = self.settings_picker.is_open();
        let changed = std::path::Path::new(self.runtime_path.trim()) != self.runtime.executable;
        let mut open = true;
        let mut close = false;
        let mut connect = false;
        let mut window = egui::Window::new("Settings")
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .default_width(510.0);
        if !checking && !picking {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            ui.set_width(510.0);
            ui.add_space(8.0);
            ui.label(design::heading("Local runtime", 18.0));
            ui.label(
                RichText::new("Studio uses the Smol CLI to manage your local machines.")
                    .size(12.0)
                    .color(MUTED),
            );
            ui.add_space(16.0);
            egui::ScrollArea::vertical()
                .id_salt(("studio-settings", &self.runtime.executable))
                .max_height((ctx.content_rect().height() - 360.0).clamp(160.0, 300.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let status = if self.inventory_valid {
                            format!(
                                "Connected · {} {}",
                                self.machines.len(),
                                if self.machines.len() == 1 {
                                    "machine"
                                } else {
                                    "machines"
                                }
                            )
                        } else {
                            "Unavailable".into()
                        };
                        design::property(ui, "Current connection", &status);
                    });
                    ui.add_space(16.0);
                    ui.label(design::heading("Smol CLI", 14.0));
                    ui.add_space(8.0);
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.add_enabled_ui(!checking && !picking, |ui| {
                            ui.label(RichText::new("Installation path").size(11.5).color(MUTED));
                            if ui
                                .add(
                                    egui::TextEdit::singleline(&mut self.runtime_path)
                                        .desired_width(f32::INFINITY)
                                        .margin(egui::Margin::symmetric(10, 8))
                                        .hint_text("Path to smol"),
                                )
                                .changed()
                            {
                                self.settings_error = None;
                                self.settings_feedback = None;
                            }
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                if ui.button("Choose file…").clicked() {
                                    self.settings_picker.open_executable(
                                        frame,
                                        &self.runtime_path,
                                        ctx,
                                    );
                                }
                                if ui.button("Use detected CLI").clicked() {
                                    self.runtime_path = Runtime::discover()
                                        .executable
                                        .to_string_lossy()
                                        .into_owned();
                                    self.settings_error = None;
                                    self.settings_feedback = None;
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("Copy path").clicked() {
                                            ctx.copy_text(self.runtime_path.clone());
                                        }
                                    },
                                );
                            });
                        });
                    });
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Studio checks the CLI before saving a new connection.")
                            .size(11.5)
                            .color(MUTED),
                    );
                    ui.add_space(12.0);
                    if let Some(error) = &self.settings_error {
                        design::error_notice(ui, "Could not use this CLI.", error);
                        if std::mem::take(&mut self.settings_scroll_error) {
                            ui.scroll_to_cursor(Some(egui::Align::BOTTOM));
                        }
                    } else if !self.inventory_valid
                        && let Some(error) = &self.error
                    {
                        design::error_notice(ui, "The current CLI is unavailable.", error);
                    }
                    ui.collapsing("Connection details", |ui| {
                        ui.label(
                            RichText::new("Your machines keep running when you close Studio.")
                                .size(12.0)
                                .color(MUTED),
                        );
                        ui.add_space(8.0);
                        ui.label(RichText::new("Current CLI").size(11.5).color(MUTED));
                        ui.add(
                            egui::Label::new(
                                RichText::new(self.runtime.executable.to_string_lossy())
                                    .monospace()
                                    .size(11.5),
                            )
                            .wrap(),
                        );
                        if ui.small_button("Copy current path").clicked() {
                            ctx.copy_text(self.runtime.executable.to_string_lossy().into_owned());
                        }
                        if let Some(path) = &self.runtime.state_dir {
                            ui.add_space(8.0);
                            ui.label(RichText::new("Machine data folder").size(11.5).color(MUTED));
                            ui.add(
                                egui::Label::new(
                                    RichText::new(path.to_string_lossy()).monospace().size(11.5),
                                )
                                .wrap(),
                            );
                        }
                    });
                });
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if checking {
                    ui.spinner();
                    ui.label(RichText::new("Checking CLI…").size(11.5).color(MUTED));
                } else if self.settings_error.is_some() {
                    ui.label(
                        RichText::new("Connection failed")
                            .size(11.5)
                            .color(design::RED),
                    );
                } else if let Some(message) = &self.settings_feedback {
                    ui.label(RichText::new(message).size(11.5).color(GREEN));
                } else if changed {
                    ui.label(RichText::new("Unsaved change").size(11.5).color(MUTED));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    connect = ui
                        .add_enabled(
                            self.pending.is_none()
                                && !picking
                                && !self.runtime_path.trim().is_empty(),
                            design::primary(if changed {
                                "Save & connect"
                            } else {
                                "Check connection"
                            }),
                        )
                        .clicked();
                    close = ui
                        .add_enabled(
                            !checking && !picking,
                            egui::Button::new(if changed { "Cancel" } else { "Done" }),
                        )
                        .clicked();
                });
            });
        });
        if connect {
            let candidate = Runtime {
                executable: self.runtime_path.trim().into(),
                state_dir: self.runtime.state_dir.clone(),
            };
            match self.worker.submit(candidate.clone(), Operation::Refresh) {
                Ok(()) => {
                    self.settings_candidate = Some(candidate);
                    self.pending = Some(Operation::Refresh);
                    self.settings_error = None;
                    self.settings_feedback = None;
                }
                Err(error) => {
                    self.settings_error = Some(error);
                    self.settings_scroll_error = true;
                }
            }
        }
        if !open || close {
            self.settings = false;
            self.settings_error = None;
            self.settings_feedback = None;
        }
    }
}
