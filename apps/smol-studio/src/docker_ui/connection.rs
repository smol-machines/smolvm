use super::*;
use smol_studio::docker_connection::State;

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
        ui.add_space(16.0);
        let checking = matches!(self.pending, Some(Action::Status));
        if self.connection.is_none() && checking {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Checking your Docker connection…");
            });
            return;
        }
        let Some(report) = self.connection.clone() else {
            ui.label("Check your Docker connection to continue.");
            if ui
                .add_enabled(self.pending.is_none(), design::primary("Check connection"))
                .clicked()
            {
                self.check_connection(runtime, true);
            }
            return;
        };
        design::empty_state(
            ui,
            design::Icon::Containers,
            report.title(),
            report.description(),
        );
        ui.add_space(18.0);
        if let Some(error) = &self.connection_error {
            design::error_notice(ui, "Docker setup could not complete.", error);
            ui.add_space(12.0);
        }
        ui.horizontal_wrapped(|ui| {
            if report.state == State::MissingCli {
                if ui
                    .add(egui::Button::new("Docker CLI installation"))
                    .clicked()
                {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(
                        if cfg!(target_os = "macos") { "https://docs.docker.com/engine/install/binaries/#install-client-binaries-on-macos" } else { "https://docs.docker.com/engine/install/binaries/" },
                    ));
                }
            } else if report.state != State::Ready
                && ui
                    .add_enabled(
                        self.pending.is_none(),
                        design::primary(if report.state == State::MissingContext {
                            "Set up Docker with Smol…"
                        } else {
                            "Restore Smol connection…"
                        }),
                    )
                    .clicked()
            {
                self.connection_open = false;
                self.confirm = Some(Action::Configure);
            }
            if ui
                .add_enabled(self.pending.is_none(), egui::Button::new("Check again"))
                .clicked()
            {
                self.check_connection(runtime, true);
            }
            if checking {
                ui.spinner();
            }
        });
        ui.add_space(24.0);
        design::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            design::property(ui, "Docker context", "smol");
            if let Some(engine) = &report.engine {
                ui.separator();
                design::property(ui, "Engine", engine);
            }
        });
        ui.add_space(12.0);
        ui.collapsing("Connection details", |ui| {
            if ui.button("Copy diagnostics").clicked() {
                ui.ctx().copy_text(report.diagnostics());
            }
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
            .default_width(480.0)
            .resizable(false)
            .collapsible(false)
            .open(&mut open)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height((ctx.content_rect().height() - 180.0).max(200.0))
                    .show(ui, |ui| {
                        self.connection_content(ui, runtime);
                    });
                ui.add_space(12.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Done").clicked() {
                            self.connection_open = false;
                        }
                    });
                });
            });
        self.connection_open &= open;
    }
}
