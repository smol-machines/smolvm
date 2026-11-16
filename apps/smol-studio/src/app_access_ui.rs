use crate::design;
use eframe::egui::{self, RichText};
use smol_studio::app_access::Endpoint;

pub fn show(ui: &mut egui::Ui, location: &str, running: bool, endpoints: &[Endpoint], empty: &str) {
    design::card(ui.ctx()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(design::heading("App access", 14.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(location)
                        .size(11.5)
                        .color(design::palette(ui).muted),
                );
            });
        });
        ui.add_space(8.0);
        if endpoints.is_empty() {
            ui.label(
                RichText::new(empty)
                    .size(12.0)
                    .color(design::palette(ui).muted),
            );
        }
        for (index, endpoint) in endpoints.iter().enumerate() {
            ui.push_id(index, |ui| {
                if index != 0 {
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(6.0);
                }
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let copy_label = if endpoint.browser_url.is_some() {
                            "Copy URL"
                        } else {
                            "Copy address"
                        };
                        if ui.button(copy_label).clicked() {
                            ui.ctx().copy_text(endpoint.address.clone());
                        }
                        if let Some(url) = &endpoint.browser_url {
                            let label = if location == "This computer" {
                                "Open HTTP"
                            } else {
                                "Open app"
                            };
                            if ui
                                .add_enabled(running, egui::Button::new(label))
                                .on_disabled_hover_text("Start the machine to open its app.")
                                .on_hover_text(if location == "This computer" {
                                    "Open using HTTP. This TCP service must speak HTTP."
                                } else {
                                    "Open the cloud-provided app URL in your browser."
                                })
                                .clicked()
                            {
                                ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                            }
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&endpoint.address).monospace().size(12.0),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&endpoint.address);
                        });
                    });
                });
                ui.label(
                    RichText::new(&endpoint.detail)
                        .size(11.5)
                        .color(design::palette(ui).muted),
                );
            });
        }
        if !running && !endpoints.is_empty() {
            ui.add_space(6.0);
            ui.label(
                RichText::new("Available when running")
                    .size(11.5)
                    .color(design::palette(ui).muted),
            );
        }
    });
}
