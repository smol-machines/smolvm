use super::*;

#[derive(Clone, Copy, Default, PartialEq)]
pub(super) enum Tab {
    #[default]
    Overview,
    Containers,
}

fn icon(kind: Kind) -> design::Icon {
    match kind {
        Kind::Images => design::Icon::Image,
        Kind::Networks => design::Icon::Network,
        _ => design::Icon::Volume,
    }
}
fn key(kind: Kind) -> &'static str {
    if kind == Kind::Volumes { "Name" } else { "ID" }
}
fn field(details: &smol_studio::storage::Details, label: &str) -> String {
    details
        .fields
        .iter()
        .find(|(name, _)| name == label)
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}
fn metadata(ui: &mut egui::Ui, label: &str, value: &str, copy: bool) {
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(label).size(11.5).color(MUTED));
            if copy && !value.is_empty() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .small_button("Copy")
                        .on_hover_text(format!("Copy {}", label.to_lowercase()))
                        .clicked()
                    {
                        ui.ctx().copy_text(value.to_owned());
                    }
                });
            }
        });
        ui.add(
            egui::Label::new(
                RichText::new(if value.is_empty() {
                    "Not reported"
                } else {
                    value
                })
                .size(12.5),
            )
            .wrap()
            .selectable(true),
        );
    });
}
fn bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "Not reported",
    }
}

impl DockerView {
    pub(super) fn resource_list(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        egui::Panel::left("storage-list")
            .resizable(true)
            .default_size(248.0)
            .min_size(224.0)
            .max_size(380.0)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
            .show(ui, |ui| {
                design::search(
                    ui,
                    &mut self.query,
                    &format!("Search {}…", self.kind.label().to_lowercase()),
                );
                ui.add_space(12.0);
                let query = self.query.to_lowercase();
                let mut seen = std::collections::HashSet::new();
                let rows: Vec<_> = self
                    .rows
                    .iter()
                    .filter(|row| {
                        ["Name", "Repository", "Tag", "ID", "Driver"]
                            .iter()
                            .any(|key| text(row, key).to_lowercase().contains(&query))
                            || (self.kind == Kind::Images
                                && format!("{}:{}", text(row, "Repository"), text(row, "Tag"))
                                    .to_lowercase()
                                    .contains(&query))
                    })
                    .filter(|row| seen.insert(text(row, key(self.kind))))
                    .cloned()
                    .collect();
                design::eyebrow(
                    ui,
                    &format!("{}  /  {}", self.kind.label().to_uppercase(), rows.len()),
                );
                ui.add_space(8.0);
                // Filtering must not leave a hidden resource's destructive actions visible.
                if self.valid
                    && self.pending.is_none()
                    && !self
                        .storage_selected
                        .as_ref()
                        .is_some_and(|id| rows.iter().any(|r| text(r, key(self.kind)) == *id))
                {
                    self.select_resource(runtime, rows.first().map(|r| text(r, key(self.kind))));
                }
                if rows.is_empty() {
                    ui.label(
                        RichText::new(if !self.valid && self.pending.is_some() {
                            "Loading resources…"
                        } else if !self.valid {
                            "Refresh to load resources."
                        } else if self.query.is_empty() {
                            "Nothing here yet"
                        } else {
                            "No matches"
                        })
                        .small()
                        .color(MUTED),
                    );
                }
                ui.add_enabled_ui(self.pending.is_none(), |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("storage-list-scroll")
                        .show_rows(ui, 60.0, rows.len(), |ui, range| {
                            for row in &rows[range] {
                                let id = text(row, key(self.kind));
                                let title = if self.kind == Kind::Images
                                    && !matches!(text(row, "Repository").as_str(), "<none>" | "")
                                {
                                    format!("{}:{}", text(row, "Repository"), text(row, "Tag"))
                                } else if self.kind == Kind::Networks {
                                    text(row, "Name")
                                } else if self.kind == Kind::Images {
                                    "Untagged image".into()
                                } else {
                                    id.clone()
                                };
                                let subtitle = text(
                                    row,
                                    if self.kind == Kind::Images {
                                        "Size"
                                    } else {
                                        "Driver"
                                    },
                                );
                                if design::resource_row(
                                    ui,
                                    self.storage_selected.as_ref() == Some(&id),
                                    &title,
                                    &subtitle,
                                    "",
                                    icon(self.kind),
                                )
                                .clicked()
                                    && self.storage_selected.as_ref() != Some(&id)
                                {
                                    self.select_resource(runtime, Some(id));
                                }
                            }
                        });
                });
            });
    }
    fn select_resource(&mut self, runtime: &Runtime, id: Option<String>) {
        if self.storage_selected == id {
            return;
        }
        self.storage_selected = id.clone();
        self.storage = None;
        self.network = None;
        self.resource_tab = Tab::Overview;
        if let Some(id) = id {
            self.submit(
                runtime,
                if self.kind == Kind::Networks {
                    Action::NetworkInspect(id)
                } else {
                    Action::StorageInspect {
                        kind: self.kind,
                        id,
                    }
                },
            );
        }
    }
    fn open_resource_container(&mut self, runtime: &Runtime, id: &str) {
        self.kind = Kind::Containers;
        self.selected = Some(id.to_owned());
        self.details = None;
        self.rows.clear();
        self.valid = false;
        self.query.clear();
        self.stats = None;
        self.live_logs.reset();
        self.container_tab = ContainerTab::Overview;
        self.submit(runtime, Action::List(Kind::Containers));
    }
    pub(super) fn resource_details(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        if self.storage.is_none() && self.network.is_none() {
            ui.add_space(64.0);
            ui.vertical_centered(|ui| {
                if self.pending.is_some() {
                    ui.spinner();
                }
                ui.label(design::heading(
                    if self.pending.is_some() {
                        "Loading details…"
                    } else if !self.query.is_empty() {
                        "No matching resources"
                    } else {
                        "Select a resource"
                    },
                    20.0,
                ));
                ui.add_space(8.0);
                ui.label(
                    RichText::new(if !self.query.is_empty() {
                        "Try another name, tag, or ID."
                    } else {
                        "Choose an item to see its configuration and containers."
                    })
                    .color(MUTED),
                );
                if !self.query.is_empty() && ui.button("Clear search").clicked() {
                    self.query.clear();
                }
            });
            return;
        }
        let enabled = self.pending.is_none() && self.valid;
        egui::ScrollArea::vertical().id_salt(("resource-details", self.storage_selected.clone())).auto_shrink([false, false]).show(ui, |ui| {
            if self.kind == Kind::Networks {
                if let Some(details) = self.network.clone() { self.network_details(ui, runtime, &details, enabled); }
                return;
            }
            let Some(details) = self.storage.clone() else { return; };
            let title = if details.kind == Kind::Images { field(&details, "Tags").lines().next().unwrap_or("Untagged image").to_owned() } else { details.id.clone() };
            design::resource_heading(ui, icon(details.kind), &title, if details.kind == Kind::Images { "Container image" } else { "Persistent volume" });
            ui.add_space(16.0);
            ui.horizontal_wrapped(|ui| {
                if details.kind == Kind::Images && ui.add_enabled(enabled, design::primary("Tag image…")).clicked() {
                    self.tag_image = Some(super::image_tag::Form { source_id: details.id.clone(), source_label: title.clone(), reference: String::new(), plan: None, error: None, focus_reference: true });
                }
                if ui.button(if details.kind == Kind::Images { "Copy image ID" } else { "Copy volume name" }).clicked() { ui.ctx().copy_text(details.id.clone()); }
                ui.add_enabled_ui(enabled, |ui| {
                    ui.menu_button("More", |ui| {
                        if ui.add_enabled(details.users.is_empty(), egui::Button::new(RichText::new("Remove…").color(design::RED))).on_disabled_hover_text("Remove the containers that reference this resource first.").clicked() {
                            self.confirm = Some(Action::StorageRemove { kind: details.kind, id: details.id.clone(), created: details.created.clone() });
                            ui.close();
                        }
                    });
                });
            });
            self.resource_tabs(ui, details.users.len());
            match self.resource_tab {
                Tab::Containers => {
                    ui.label(RichText::new("Containers that reference this resource, including stopped containers.").size(12.0).color(MUTED));
                    ui.add_space(12.0);
                    if details.users.is_empty() { Self::empty_connections(ui); }
                    for user in &details.users {
                        ui.add_enabled_ui(enabled, |ui| {
                            if design::resource_row(ui, false, &user.name, &user.state, &user.state, design::Icon::Containers).clicked() { self.open_resource_container(runtime, &user.id); }
                        });
                    }
                }
                Tab::Overview => {
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for label in if details.kind == Kind::Images { ["Platform", "Image size", "Created"] } else { ["Driver", "Scope", "Created"] } {
                            let value = field(&details, label);
                            design::property(ui, label, if value.is_empty() { "Not reported" } else { &value });
                        }
                        ui.separator();
                        if ui.link(format!("{} →", count(details.users.len(), "container"))).clicked() { self.resource_tab = Tab::Containers; }
                    });
                    ui.add_space(20.0);
                    if details.kind == Kind::Images {
                        ui.label(design::heading("Tags", 14.0)); ui.add_space(8.0);
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            for tag in field(&details, "Tags").lines() {
                                ui.push_id(tag, |ui| { metadata(ui, "Image reference", tag, tag != "Untagged"); });
                            }
                        });
                        ui.add_space(20.0);
                        design::card().show(ui, |ui| { ui.set_width(ui.available_width()); metadata(ui, "Image ID", &details.id, true); });
                    } else {
                        ui.label(design::heading("Storage", 14.0)); ui.add_space(8.0);
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            metadata(ui, "Engine storage path", &field(&details, "Storage path"), true);
                        });
                        ui.add_space(8.0);
                        ui.label(RichText::new("Data persists when containers stop or are removed.").size(12.0).color(MUTED));
                    }
                }
            }
        });
    }
    fn resource_tabs(&mut self, ui: &mut egui::Ui, containers: usize) {
        ui.add_space(20.0);
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Overview, "Overview".to_owned()),
                (Tab::Containers, format!("Containers ({containers})")),
            ] {
                if design::tab(ui, self.resource_tab == tab, &label).clicked() {
                    self.resource_tab = tab;
                }
            }
        });
        ui.separator();
        ui.add_space(16.0);
    }
    fn empty_connections(ui: &mut egui::Ui) {
        design::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("No containers attached").size(13.0));
        });
    }
    fn network_details(
        &mut self,
        ui: &mut egui::Ui,
        runtime: &Runtime,
        details: &smol_studio::network::Details,
        enabled: bool,
    ) {
        design::resource_heading(
            ui,
            design::Icon::Network,
            &details.name,
            "Container network",
        );
        ui.add_space(16.0);
        if ui.button("Copy network name").clicked() {
            ui.ctx().copy_text(details.name.clone());
        }
        self.resource_tabs(ui, details.endpoints.len());
        match self.resource_tab {
            Tab::Overview => {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    design::property(ui, "Driver", &details.driver);
                    design::property(ui, "Scope", &details.scope);
                    design::property(ui, "Internal network", bool_label(details.internal));
                    design::property(ui, "IPv6 enabled", bool_label(details.ipv6));
                });
                ui.add_space(20.0);
                ui.label(design::heading("Subnets & gateways", 14.0));
                ui.add_space(8.0);
                if details.subnets.is_empty() {
                    ui.label(
                        RichText::new("No IP address pools reported for this network.")
                            .size(12.0)
                            .color(MUTED),
                    );
                }
                for (index, subnet) in details.subnets.iter().enumerate() {
                    ui.push_id(index, |ui| {
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            metadata(ui, "Subnet", &subnet.subnet, true);
                            ui.add_space(10.0);
                            metadata(ui, "Gateway", &subnet.gateway, true);
                            if !subnet.range.is_empty() {
                                ui.add_space(10.0);
                                metadata(ui, "Address range", &subnet.range, true);
                            }
                        });
                    });
                    ui.add_space(8.0);
                }
                ui.add_space(12.0);
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    metadata(ui, "Network ID", &details.id, true);
                });
            }
            Tab::Containers => {
                ui.label(
                    RichText::new("Attached endpoints reported by this network.")
                        .size(12.0)
                        .color(MUTED),
                );
                ui.add_space(12.0);
                if details.endpoints.is_empty() {
                    Self::empty_connections(ui);
                }
                for endpoint in &details.endpoints {
                    ui.push_id(&endpoint.id, |ui| {
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .add_enabled(
                                                enabled
                                                    && smol_studio::docker::validate_container_id(
                                                        &endpoint.id,
                                                    )
                                                    .is_ok(),
                                                egui::Button::new("View container"),
                                            )
                                            .clicked()
                                        {
                                            self.open_resource_container(runtime, &endpoint.id);
                                        }
                                        ui.with_layout(
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                ui.add(
                                                    egui::Label::new(design::heading(
                                                        &endpoint.name,
                                                        14.0,
                                                    ))
                                                    .truncate(),
                                                )
                                                .on_hover_text(&endpoint.name);
                                            },
                                        );
                                    },
                                );
                            });
                            ui.add_space(8.0);
                            metadata(ui, "IPv4 address", &endpoint.ipv4, true);
                            if !endpoint.ipv6.is_empty() {
                                ui.add_space(8.0);
                                metadata(ui, "IPv6 address", &endpoint.ipv6, true);
                            }
                        });
                    });
                    ui.add_space(8.0);
                }
            }
        }
    }
}
