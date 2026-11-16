use super::*;
impl DockerView {
    pub(super) fn container_usage_ui(
        &self,
        ui: &mut egui::Ui,
        details: &smol_studio::container_details::ContainerDetails,
    ) {
        if details.state != "running" {
            ui.label(
                RichText::new(match details.state.as_str() {
                    "paused" => "Resume this container to measure resource usage.",
                    "created" | "exited" => "Start this container to measure resource usage.",
                    _ => "Resource usage is available while this container is running.",
                })
                .size(12.0)
                .color(MUTED),
            );
            return;
        }
        let sample = self.usage.sample.as_ref();
        ui.horizontal_wrapped(|ui| {
            if self.usage.pending() && sample.is_none() {
                ui.spinner();
            }
            let status = if !self.usage.active {
                "Updates paused while this view is inactive".into()
            } else if let Some((at, _)) = sample {
                format!("Sampled {}s ago · updates every 5s", at.elapsed().as_secs())
            } else if self.usage.error.is_some() {
                "Waiting for resource measurements".into()
            } else {
                "Measuring CPU and memory…".into()
            };
            ui.label(RichText::new(status).size(11.5).color(MUTED));
        });
        ui.add_space(10.0);
        let values = [
            (
                "Machine CPU",
                sample.map(|(_, s)| s.cpu.as_str()).unwrap_or("—"),
            ),
            (
                "Guest memory / limit",
                sample.map(|(_, s)| s.memory.as_str()).unwrap_or("—"),
            ),
        ];
        let card = |ui: &mut egui::Ui, label: &str, value: &str| {
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(label).size(11.5).color(MUTED));
                ui.add_space(6.0);
                ui.add(egui::Label::new(design::heading(value, 20.0)).wrap());
            });
        };
        if ui.available_width() >= 420.0 {
            ui.columns(2, |cols| {
                for (col, (label, value)) in cols.iter_mut().zip(values) {
                    card(col, label, value);
                }
            });
        } else {
            for (label, value) in values {
                card(ui, label, value);
                ui.add_space(8.0);
            }
        }
        if let Some(error) = &self.usage.error {
            ui.add_space(10.0);
            design::error_notice(
                ui,
                "Usage could not be updated. Retrying while this view is active.",
                error,
            );
        }
        ui.add_space(8.0);
        ui.label(RichText::new("CPU and memory describe the backing machine. Network, disk I/O and process counts are unavailable.").size(11.0).color(MUTED));
    }
}
