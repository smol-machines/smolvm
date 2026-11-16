use super::*;

impl CloudView {
    pub(super) fn create_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut draft) = self.create.take() else {
            return;
        };
        let mut open = true;
        let mut submit = false;
        let mut cancel = false;
        let busy = self.pending;
        let mut window = egui::Window::new("New cloud machine")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(480.0)
            .collapsible(false)
            .resizable(false);
        if !busy {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new(format!("Create in {}", self.account_label())).size(13.0));
            ui.label(
                RichText::new(
                    "Cloud resources are billed to this account. Your machine starts stopped.",
                )
                .size(12.0)
                .color(design::palette(ui).muted),
            );
            ui.add_space(16.0);
            egui::ScrollArea::vertical()
                .id_salt("cloud-create-form")
                .max_height((ctx.content_rect().height() - 310.0).max(170.0))
                .show(ui, |ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        design::card(ui.ctx()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                RichText::new("Name")
                                    .size(12.0)
                                    .color(design::palette(ui).muted),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.name)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("my-cloud-machine")
                                    .margin(egui::Margin::symmetric(10, 9)),
                            );
                            ui.add_space(10.0);
                            ui.label(
                                RichText::new("Container image")
                                    .size(12.0)
                                    .color(design::palette(ui).muted),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.image)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("alpine:latest")
                                    .margin(egui::Margin::symmetric(10, 9)),
                            );
                        });
                        ui.add_space(16.0);
                        ui.label(design::heading("Resources", 14.0));
                        ui.add_space(8.0);
                        design::card(ui.ctx()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            let colors = design::palette(ui);
                            ui.columns(2, |columns| {
                                columns[0].label(
                                    RichText::new("CPU cores").size(12.0).color(colors.muted),
                                );
                                columns[0].add(egui::DragValue::new(&mut draft.cpus).range(1..=64));
                                columns[1].label(
                                    RichText::new("Memory (MB)").size(12.0).color(colors.muted),
                                );
                                columns[1].add(
                                    egui::DragValue::new(&mut draft.memory_mib)
                                        .range(256..=262144)
                                        .speed(128),
                                );
                            });
                            ui.add_space(12.0);
                            ui.separator();
                            ui.add_space(8.0);
                            ui.checkbox(&mut draft.network, "Allow outbound network access");
                        });
                        ui.add_space(16.0);
                        ui.label(design::heading("App ports", 14.0));
                        ui.label(
                            RichText::new("Publish the ports your app listens on.")
                                .size(12.0)
                                .color(design::palette(ui).muted),
                        );
                        let mut remove = None;
                        for (index, port) in draft.ports.iter_mut().enumerate() {
                            ui.push_id(("cloud-port", index), |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Guest port");
                                    ui.add(egui::DragValue::new(&mut port.guest).range(1..=65535));
                                    port.host = port.guest;
                                    if ui.button("Remove").clicked() {
                                        remove = Some(index);
                                    }
                                });
                            });
                        }
                        if let Some(index) = remove {
                            draft.ports.remove(index);
                        }
                        if ui
                            .add_enabled(draft.ports.len() < 32, egui::Button::new("Add port"))
                            .clicked()
                        {
                            draft.ports.push(smol_studio::model::PublishedPort {
                                host: 8080,
                                guest: 8080,
                            });
                        }
                    });
                    if let Some(error) = &self.create_error {
                        ui.add_space(12.0);
                        design::error_notice(ui, "Machine could not be created.", error);
                        if !self.valid && !self.pending && ui.button("Refresh account").clicked() {
                            self.refresh();
                        }
                    }
                });
            let valid = validate(&draft);
            if let Err(error) = &valid
                && !draft.name.is_empty()
            {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error)
                        .size(12.0)
                        .color(design::palette(ui).red),
                );
            }
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if busy {
                    ui.spinner();
                    ui.label(if self.creating {
                        "Creating…"
                    } else {
                        "Refreshing account…"
                    });
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    submit = ui
                        .add_enabled(
                            valid.is_ok() && self.valid && !busy,
                            design::primary(ui, "Create machine"),
                        )
                        .clicked();
                    cancel = ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                });
            });
        });
        if submit {
            self.create_error = None;
            self.send(Action::Create {
                tenant: self.tenant.clone(),
                request: Box::new(CreateMachine {
                    name: Some(draft.name.trim().to_owned()),
                    source: Some(Source {
                        source_type: "image".into(),
                        reference: Some(draft.image.trim().into()),
                        arch: None,
                    }),
                    resources: Some(Resources {
                        cpus: Some(draft.cpus.into()),
                        memory_mb: Some(draft.memory_mib),
                        ..Default::default()
                    }),
                    network: Some(Network {
                        mode: Some(if draft.network { "open" } else { "blocked" }.into()),
                        cidrs: vec![],
                        hosts: vec![],
                    }),
                    ports: draft
                        .ports
                        .iter()
                        .map(|p| smol_cloud::types::Port {
                            port: p.guest,
                            host_port: None,
                        })
                        .collect(),
                    ..Default::default()
                }),
            });
        }
        if busy || submit || (open && !cancel && !ctx.input(|i| i.key_pressed(egui::Key::Escape))) {
            self.create = Some(draft);
        }
    }
}

fn validate(draft: &NewMachine) -> Result<(), String> {
    draft.validate()?;
    if draft.image.trim().is_empty() || draft.image.trim().starts_with(['/', '.']) {
        return Err("Use a registry image reference for cloud machines.".into());
    }
    smol_studio::storage::validate_reference(draft.image.trim())?;
    let mut ports = std::collections::BTreeSet::new();
    for port in &draft.ports {
        if !ports.insert(port.guest) {
            return Err(format!(
                "Guest port {} is listed more than once.",
                port.guest
            ));
        }
    }
    if ports.len() > 32 {
        return Err("Publish at most 32 app ports.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cloud_ports_reject_duplicate_guest_bindings_before_creation() {
        use smol_studio::model::PublishedPort;
        let mut draft = NewMachine {
            name: "app".into(),
            image: "alpine:3.22".into(),
            ..Default::default()
        };
        draft.ports = vec![
            PublishedPort {
                host: 8080,
                guest: 80,
            },
            PublishedPort {
                host: 8081,
                guest: 80,
            },
        ];
        assert!(
            validate(&draft)
                .unwrap_err()
                .contains("listed more than once")
        );
        draft.ports[1].guest = 443;
        assert!(validate(&draft).is_ok());
        draft.ports[1].guest = 0;
        assert!(validate(&draft).is_err());
    }
}
