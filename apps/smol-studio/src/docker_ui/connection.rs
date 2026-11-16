use super::*;
use smol_studio::docker_connection::{Connection, State};

impl DockerView {
    pub(super) fn connected(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|c| c.state == State::Ready)
    }
    pub(super) fn check_connection(&mut self, runtime: &Runtime, refresh: bool) {
        if self.pending.is_none() {
            self.refresh_after_check = refresh;
            self.submit(runtime, Action::Status);
        }
    }
    pub(super) fn connection_content(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        // The disconnected workspace shares the dialog's content, but keeps its
        // primary action above diagnostics even in a short window.
        ui.scope_builder(
            egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
                ui.cursor().min,
                egui::vec2(ui.available_width().min(560.0), ui.available_height()),
            )),
            |ui| {
                ui.label(design::heading("Docker connection", 22.0));
                ui.add_space(16.0);
                self.connection_summary(ui);
                ui.add_space(16.0);
                self.connection_actions(ui, runtime);
                ui.add_space(16.0);
                egui::ScrollArea::vertical()
                    .id_salt("docker-connection-page-details")
                    .show(ui, |ui| self.connection_details(ui));
            },
        );
    }
    fn connection_summary(&self, ui: &mut egui::Ui) {
        let checking = matches!(self.pending, Some(Action::Status));
        design::card(ui.ctx()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                if checking {
                    ui.spinner();
                } else {
                    let color = if self.connected() {
                        design::palette(ui).green
                    } else {
                        design::palette(ui).muted
                    };
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 3.5, color);
                }
                ui.label(design::heading(
                    if checking {
                        "Checking connection…"
                    } else {
                        self.connection
                            .as_ref()
                            .map_or("Check your Docker connection", Connection::title)
                    },
                    14.0,
                ));
            });
            if !self.connected() {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(self.connection.as_ref().map_or(
                        "Connect Smol to manage containers, images and Compose projects.",
                        Connection::description,
                    ))
                    .size(12.0)
                    .color(design::palette(ui).muted),
                );
            }
            if let Some(report) = &self.connection {
                ui.add_space(10.0);
                ui.separator();
                design::property(ui, "Context", "smol");
                if let Some(engine) = &report.engine {
                    design::property(ui, "Engine", engine);
                }
            }
        });
    }
    fn connection_actions(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        ui.horizontal_wrapped(|ui| {
            match self.connection.as_ref().map(|c| c.state) {
                Some(State::MissingCli) => {
                    if ui.add(design::primary(ui, "Get Docker CLI")).clicked() {
                        ui.ctx().open_url(egui::OpenUrl::new_tab(
                            if cfg!(target_os = "macos") { "https://docs.docker.com/engine/install/binaries/#install-client-binaries-on-macos" } else { "https://docs.docker.com/engine/install/binaries/" },
                        ));
                    }
                }
                Some(state) if state != State::Ready && ui.add_enabled(self.pending.is_none(), design::primary(ui,
                        if state == State::MissingContext { "Set up Docker…" } else { "Restore connection…" },
                    )).clicked() => {
                    self.connection_open = false;
                    self.confirm = Some(Action::Configure);
                }
                _ => {}
            }
            if ui.add_enabled(self.pending.is_none(), egui::Button::new(
                if self.connection.is_some() { "Check again" } else { "Check connection" },
            )).clicked() {
                self.check_connection(runtime, true);
            }
        });
    }
    fn connection_details(&self, ui: &mut egui::Ui) {
        if let Some(error) = &self.connection_error {
            design::error_notice(ui, "Docker setup could not complete.", error);
            ui.add_space(12.0);
        }
        let Some(report) = &self.connection else {
            return;
        };
        if report.state == State::Ready {
            ui.label(design::heading("Use Smol from your terminal", 14.0));
            ui.add_space(8.0);
            ui.label(RichText::new("These commands select Smol explicitly, regardless of your default Docker context.").size(12.0).color(design::palette(ui).muted));
            ui.add_space(10.0);
            design::card(ui.ctx()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                command_row(ui, "Containers", "docker --context smol ps");
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);
                command_row(
                    ui,
                    "Compose · run in your project folder",
                    "docker --context smol compose up -d",
                );
            });
            ui.add_space(16.0);
        }
        ui.collapsing("Connection details", |ui| {
            ui.add_space(6.0);
            if ui.small_button("Copy diagnostics").clicked() {
                ui.ctx().copy_text(report.diagnostics());
            }
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(RichText::new(report.diagnostics()).monospace().size(11.5))
                    .wrap()
                    .selectable(true),
            );
        });
    }
    pub(super) fn connection_dialog(&mut self, ctx: &egui::Context, runtime: &Runtime) {
        if !self.connection_open {
            return;
        }
        let mut open = true;
        egui::Window::new("Docker connection")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(510.0)
            .resizable(false)
            .collapsible(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .id_salt("docker-connection-dialog")
                    .max_height((ctx.content_rect().height() - 230.0).clamp(160.0, 420.0))
                    .show(ui, |ui| {
                        self.connection_summary(ui);
                        ui.add_space(16.0);
                        self.connection_details(ui);
                    });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Done").clicked() {
                            self.connection_open = false;
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            self.connection_actions(ui, runtime);
                        });
                    });
                });
            });
        self.connection_open &= open;
    }
    pub(super) fn connection_setup_dialog(&mut self, ctx: &egui::Context, runtime: &Runtime) {
        if !matches!(self.confirm, Some(Action::Configure)) {
            return;
        }
        let mut open = true;
        let mut apply = false;
        let mut cancel = false;
        egui::Window::new("Set up Docker with Smol")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(510.0)
            .resizable(false)
            .collapsible(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(RichText::new("Connect your local development tools to Smol.").size(12.0).color(design::palette(ui).muted));
                ui.add_space(16.0);
                egui::ScrollArea::vertical()
                    .id_salt("docker-connection-setup")
                    .max_height((ctx.content_rect().height() - 270.0).clamp(160.0, 360.0))
                    .show(ui, |ui| {
                        design::card(ui.ctx()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            setup_item(ui, "Docker & Compose", "Select smol as your default Docker context. Docker commands in your terminal will use Smol.");
                            ui.separator();
                            setup_item(ui, "Buildx", "Register Smol’s build service and configure its builder.");
                            ui.separator();
                            setup_item(ui, "Testcontainers", "Configure Smol’s socket when no other engine is already configured.");
                        });
                        ui.add_space(12.0);
                        ui.label(RichText::new("Smol starts its Docker adapter on demand. Your machines keep running when you close Studio.").size(12.0).color(design::palette(ui).muted));
                    });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        apply = ui.add_enabled(self.pending.is_none(), design::primary(ui, "Set up Docker")).clicked();
                        cancel = ui.button("Cancel").clicked();
                    });
                });
            });
        if apply {
            self.confirm = None;
            self.submit(runtime, Action::Configure);
        } else if cancel || !open {
            self.confirm = None;
            self.connection_open = true;
        }
    }
}

fn command_row(ui: &mut egui::Ui, label: &str, command: &str) {
    ui.label(
        RichText::new(label)
            .size(11.5)
            .color(design::palette(ui).muted),
    );
    ui.add_space(5.0);
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .small_button("Copy")
                .on_hover_text(format!("Copy {command}"))
                .clicked()
            {
                ui.ctx().copy_text(command.to_owned());
            }
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.add(
                    egui::Label::new(RichText::new(command).monospace().size(12.0))
                        .wrap()
                        .selectable(true),
                );
            });
        });
    });
}

fn setup_item(ui: &mut egui::Ui, title: &str, description: &str) {
    ui.add_space(6.0);
    ui.label(design::heading(title, 13.0));
    ui.add_space(4.0);
    ui.label(
        RichText::new(description)
            .size(12.0)
            .color(design::palette(ui).muted),
    );
    ui.add_space(8.0);
}
