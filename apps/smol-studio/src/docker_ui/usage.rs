use super::*;
impl DockerView {
    pub(super) fn container_usage_ui(
        &self,
        ui: &mut egui::Ui,
        details: &smol_studio::container_details::ContainerDetails,
    ) {
        if details.state != "running" {
            design::card(ui.ctx()).inner_margin(14).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(match details.state.as_str() {
                        "paused" => "Resume this container to measure resource usage.",
                        "created" | "exited" => "Start this container to measure resource usage.",
                        _ => "Resource usage is available while this container is running.",
                    })
                    .size(12.0)
                    .color(design::palette(ui).muted),
                );
            });
            return;
        }
        let sample = self.usage.sample.as_ref();
        design::card(ui.ctx()).inner_margin(14).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(design::heading("Machine usage", 14.0))
                    .on_hover_text("CPU and memory are measured for the backing machine, which may also host other containers.");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.usage.pending() && sample.is_none() {
                        ui.spinner();
                    }
                    let status = if !self.usage.active {
                        "Updates paused".into()
                    } else if let Some((at, _)) = sample {
                        format!("{}s ago", at.elapsed().as_secs())
                    } else if self.usage.error.is_some() {
                        "Waiting for measurements".into()
                    } else {
                        "Measuring…".into()
                    };
                    ui.label(RichText::new(status).size(11.0).color(design::palette(ui).muted))
                        .on_hover_text("Updates every 5 seconds while this view is active.");
                });
            });
            ui.add_space(8.0);
            let values = [
                ("CPU", sample.map(|(_, s)| s.cpu.as_str()).unwrap_or("—")),
                ("Memory", sample.map(|(_, s)| s.memory.as_str()).unwrap_or("—")),
            ];
            let colors = design::palette(ui);
ui.columns(2, |columns| {
                for (column, (label, value)) in columns.iter_mut().zip(values) {
                    column.spacing_mut().item_spacing.y = 2.0;
                    column.label(RichText::new(label).size(11.5).color(colors.muted));
                    let (value, limit) = value.split_once('/').map_or((value, None), |(used, limit)| {
                        (used.trim(), Some(limit.trim()))
                    });
                    let unit_at = value.find(|c: char| c.is_ascii_alphabetic() || c == '%');
                    let (amount, unit) = unit_at.map_or((value, ""), |index| value.split_at(index));
                    column.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        ui.label(design::heading(amount.trim(), 23.0));
                        if !unit.is_empty() {
                            ui.label(RichText::new(unit).size(12.0).color(colors.muted));
                        }
                    });
                    if let Some(limit) = limit {
                        column.label(RichText::new(format!("of {limit} limit")).size(11.0).color(colors.muted));
                    }
                }
            });
        });
        if let Some(error) = &self.usage.error {
            ui.add_space(10.0);
            design::error_notice(
                ui,
                "Usage could not be updated. Retrying while this view is active.",
                error,
            );
        }
    }
}
