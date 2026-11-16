use super::*;
impl DockerView {
    fn diagnostic_logs_link(&mut self, ui: &mut egui::Ui) {
        if ui.link("View container logs →").clicked() {
            self.container_tab = ContainerTab::Logs;
            self.live_logs.set_visible(true);
        }
    }
    pub(super) fn container_diagnostics(
        &mut self,
        ui: &mut egui::Ui,
        runtime: &Runtime,
        details: &smol_studio::container_details::ContainerDetails,
        enabled: bool,
    ) {
        if let Some(summary) = details.exit_summary() {
            design::card(ui.ctx()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(egui::Label::new(design::heading(&summary.title, 14.0)).wrap());
                ui.add_space(6.0);
                ui.label(
                    RichText::new(summary.explanation)
                        .size(12.0)
                        .color(design::palette(ui).muted),
                );
                if details.oom_killed
                    && let Some(code) = details.exit_code
                {
                    ui.add_space(8.0);
                    design::property(ui, "Exit code", &code.to_string());
                }
                ui.add_space(10.0);
                self.diagnostic_logs_link(ui);
            });
            ui.add_space(16.0);
        }
        if !details.error.is_empty() {
            design::error_notice(ui, "The engine reported a container error.", &details.error);
            ui.add_space(16.0);
        }
        if let Some(health) = &details.health {
            design::card(ui.ctx()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.label(design::heading(if details.state == "running" { "Health check" } else { "Last reported health check" }, 14.0));
                    if details.state == "running" { design::badge(ui, health); }
                });
                if health == "unhealthy" && details.state == "running" {
                    ui.add_space(8.0);
                    ui.label(RichText::new("The configured health check is failing. Review its output and the application logs.").size(12.0).color(design::palette(ui).muted));
                } else if health == "starting" && details.state == "running" {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Waiting for the configured health check to become healthy.").size(12.0).color(design::palette(ui).muted));
                }
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    if let Some(failures) = details.health_failures.filter(|n| *n > 0) {
                        ui.label(RichText::new(format!("{failures} consecutive failed checks")).size(11.5).color(design::palette(ui).muted));
                    }
                    if let Some(code) = details.health_probe.as_ref().and_then(|p| p.exit_code) {
                        ui.label(RichText::new(format!("{}Last check: exit {code}", if details.health_failures.is_some_and(|n| n > 0) { "· " } else { "" })).size(11.5).color(design::palette(ui).muted));
                    }
                });
                if let Some(probe) = &details.health_probe {
                    if !probe.finished_at.is_empty() {
                        ui.label(RichText::new(format!("Reported {}", probe.reported_at())).size(11.0).color(design::palette(ui).muted)).on_hover_text(&probe.finished_at);
                    }
                    ui.add_space(8.0);
                    if probe.output.trim().is_empty() {
                        ui.label(RichText::new("This check produced no output.").size(12.0).color(design::palette(ui).muted));
                    } else {
                        egui::ScrollArea::vertical().id_salt(("container-health-output", &details.id)).max_height((ui.ctx().content_rect().height() - 580.0).clamp(48.0, 160.0)).show(ui, |ui| {
                            ui.add(egui::Label::new(RichText::new(&probe.output).monospace().size(12.0)).wrap());
                        });
                        if probe.truncated { ui.label(RichText::new("Showing the first 4,096 characters.").size(11.0).color(design::palette(ui).muted)); }
                    }
                } else { ui.label(RichText::new("No check result reported yet.").size(12.0).color(design::palette(ui).muted)); }
                ui.add_space(12.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(enabled, egui::Button::new("Refresh status")).clicked() {
                        self.submit(runtime, Action::Inspect(details.id.clone()));
                    }
                    if let Some(probe) = &details.health_probe && !probe.output.is_empty() && ui.button("Copy check output").clicked() { ui.ctx().copy_text(probe.output.clone()); }
                    self.diagnostic_logs_link(ui);
                });
            });
            ui.add_space(16.0);
        }
    }
}
