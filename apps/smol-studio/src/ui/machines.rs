use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Location {
    All,
    Local,
    Cloud,
}

#[derive(Clone, Debug, PartialEq)]
enum Target {
    Local(String),
    Cloud(String),
}

struct Row {
    target: Target,
    name: String,
    source: String,
    state: String,
}

fn rows(
    local: &[Machine],
    cloud: &[smol_cloud::types::Machine],
    location: Location,
    filter: Filter,
    query: &str,
) -> Vec<Row> {
    let mut rows = Vec::new();
    if location != Location::Cloud {
        rows.extend(local.iter().map(|m| Row {
            target: Target::Local(m.name.clone()),
            name: m.name.clone(),
            source: format!("Local · {}", m.image_label()),
            state: m.state.clone(),
        }));
    }
    if location != Location::Local {
        rows.extend(cloud.iter().map(|m| Row {
            target: Target::Cloud(m.id.clone()),
            name: m.display_name().into(),
            source: format!(
                    "Cloud · {}",
                    m.source
                        .as_ref()
                        .and_then(|s| s.reference.as_deref())
                        .unwrap_or("Linux machine")
                ),
            state: if m.is_started() {
                if m.is_ready() { "running" } else { "starting" }.into()
            } else {
                m.state.clone()
            },
        }));
    }
    let query = query.trim().to_lowercase();
    rows.retain(|m| {
        (filter == Filter::All
            || (filter == Filter::Running && m.state == "running")
            || (filter == Filter::Stopped && matches!(m.state.as_str(), "created" | "stopped")))
            && (m.name.to_lowercase().contains(&query)
                || m.source.to_lowercase().contains(&query)
                || matches!(&m.target, Target::Cloud(id) if id.to_lowercase().contains(&query)))
    });
    rows.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| match (&a.target, &b.target) {
                (Target::Cloud(a), Target::Cloud(b)) => a.cmp(b),
                _ => std::cmp::Ordering::Equal,
            })
    });
    rows
}

fn reconcile_selection(
    current: Option<Target>,
    rows: &[Row],
    awaiting_creation: bool,
) -> Option<Target> {
    if awaiting_creation || rows.iter().any(|row| Some(&row.target) == current.as_ref()) {
        current
    } else {
        rows.first().map(|row| row.target.clone())
    }
}

impl Studio {
    pub(super) fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            design::section_title(
                ui,
                "Machines",
                &format!(
                    "{} local · {} cloud",
                    self.machines.len(),
                    self.cloud.inventory().len()
                ),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.menu_button("+  New machine", |ui| {
                    if ui
                        .add_enabled(self.local_ready(), egui::Button::new("On this computer"))
                        .clicked()
                    {
                        self.create = Some(crate::new_machine_ui::Editor::default());
                        ui.close();
                    }
                    if ui
                        .add_enabled(self.cloud.can_create(), egui::Button::new("In Smol Cloud"))
                        .clicked()
                    {
                        self.cloud.begin_create();
                        ui.close();
                    }
                    if !self.cloud.signed_in() && ui.button("Connect your account…").clicked() {
                        self.open_settings();
                        self.account_settings = true;
                        ui.close();
                    }
                });
                if ui
                    .add_enabled(
                        !self.inventory.busy() && self.pending.is_none(),
                        egui::Button::new("Refresh"),
                    )
                    .clicked()
                {
                    self.refresh_inventory();
                    if self.cloud.signed_in() {
                        self.cloud.refresh();
                    }
                }
            });
        });
        if let Some(error) = &self.error {
            ui.add_space(8.0);
            design::error_notice(ui, "Local machine request needs attention.", error);
        }
        if self.cloud.signed_in() {
            self.cloud.connection_notice(ui);
        }
    }

    fn choose_machine(&mut self, target: &Target) {
        match target {
            Target::Local(name) => {
                if self.selected.as_ref() != Some(name) || self.selected_cloud {
                    self.tab = Tab::Overview;
                    self.logs.reset();
                }
                self.selected = Some(name.clone());
                self.selected_cloud = false;
            }
            Target::Cloud(id) => {
                self.cloud.select(id);
                self.selected_cloud = true;
            }
        }
    }

    pub(super) fn machine_list(&mut self, ui: &mut egui::Ui) {
        if self.cloud.awaiting_created_selection() {
            self.selected_cloud = true;
        }
        if self.cloud.take_created_selection() {
            self.selected_cloud = true;
            self.location = Location::All;
            self.filter = Filter::All;
            self.query.clear();
        }
        let rows = rows(
            &self.machines,
            self.cloud.inventory(),
            self.location,
            self.filter,
            &self.query,
        );
        let current = if self.selected_cloud {
            self.cloud.selected().map(|id| Target::Cloud(id.into()))
        } else {
            self.selected.clone().map(Target::Local)
        };
        let awaiting_creation = self.cloud.awaiting_created_selection()
            || (!self.selected_cloud
                && self.inventory.busy()
                && self
                    .selected
                    .as_ref()
                    .is_some_and(|name| !self.machines.iter().any(|m| &m.name == name)));
        let next = reconcile_selection(current.clone(), &rows, awaiting_creation);
        if next != current {
            if let Some(target) = next {
                self.choose_machine(&target);
            } else {
                self.selected = None;
                self.selected_cloud = false;
            }
        }
        ui.horizontal(|ui| {
            design::eyebrow(ui, &format!("MACHINES / {}", rows.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                egui::ComboBox::from_id_salt("machine-state-filter")
                    .width(90.0)
                    .selected_text(match self.filter {
                        Filter::All => "Any state",
                        Filter::Running => "Running",
                        Filter::Stopped => "Stopped",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.filter, Filter::All, "Any state");
                        ui.selectable_value(&mut self.filter, Filter::Running, "Running");
                        ui.selectable_value(&mut self.filter, Filter::Stopped, "Stopped");
                    });
            });
        });
        ui.add_space(8.0);
        if rows.is_empty() {
            ui.add_space(20.0);
            ui.label(RichText::new("No matching machines").color(design::palette(ui).muted));
        }
        if rows.is_empty() && self.location != Location::Local && !self.cloud.signed_in() {
            ui.label(
                RichText::new("Connect your account to include cloud machines.")
                    .small()
                    .color(design::palette(ui).muted),
            );
            if ui.button("Connect account…").clicked() {
                self.open_settings();
                self.account_settings = true;
            }
            ui.add_space(8.0);
        }
        if self.location != Location::Cloud && !self.inventory_valid {
            ui.label("Local runtime unavailable");
            if ui.button("Runtime settings…").clicked() {
                self.open_settings();
                self.account_settings = false;
            }
        }
        let position = rows.iter().position(|row| match &row.target {
            Target::Local(name) => !self.selected_cloud && self.selected.as_ref() == Some(name),
            Target::Cloud(id) => self.selected_cloud && self.cloud.selected() == Some(id.as_str()),
        });
        let mut list = egui::ScrollArea::vertical().id_salt("machine_inventory");
        if position != self.selected_row_position
            && let Some(index) = position
        {
            list = list.vertical_scroll_offset(index as f32 * (60.0 + ui.spacing().item_spacing.y));
        }
        self.selected_row_position = position;
        list.show_rows(ui, 60.0, rows.len(), |ui, range| {
            for row in &rows[range] {
                let selected = match &row.target {
                    Target::Local(name) => {
                        !self.selected_cloud && self.selected.as_ref() == Some(name)
                    }
                    Target::Cloud(id) => {
                        self.selected_cloud && self.cloud.selected() == Some(id.as_str())
                    }
                };
                if design::machine_row(ui, selected, &row.name, &row.source, &row.state).clicked() {
                    self.choose_machine(&row.target);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creation_keeps_the_returned_id_while_inventory_and_search_are_stale() {
        let created = Target::Cloud("new-id".into());
        let old = Row {
            target: Target::Cloud("old-id".into()),
            name: "app".into(),
            source: "Cloud".into(),
            state: "running".into(),
        };
        assert_eq!(
            reconcile_selection(Some(created.clone()), std::slice::from_ref(&old), true),
            Some(created.clone())
        );
        let new = Row {
            target: created.clone(),
            name: "new-app".into(),
            source: "Cloud".into(),
            state: "created".into(),
        };
        assert_eq!(
            reconcile_selection(Some(created.clone()), &[old, new], false),
            Some(created)
        );
        assert_eq!(
            reconcile_selection(Some(Target::Local("gone".into())), &[], false),
            None
        );
    }
    #[test]
    fn same_names_keep_distinct_targets_and_share_search_and_filters() {
        let local: Machine =
            serde_json::from_str(r#"{"name":"api","state":"running","cpus":1,"memory_mib":512}"#)
                .unwrap();
        let cloud: smol_cloud::types::Machine = serde_json::from_str(
            r#"{"id":"remote-123","name":"api","state":"started","ready":true}"#,
        )
        .unwrap();
        let all = rows(
            std::slice::from_ref(&local),
            std::slice::from_ref(&cloud),
            Location::All,
            Filter::Running,
            "API",
        );
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.target == Target::Local("api".into())));
        assert!(
            all.iter()
                .any(|r| r.target == Target::Cloud("remote-123".into()))
        );
        assert_eq!(
            rows(
                std::slice::from_ref(&local),
                std::slice::from_ref(&cloud),
                Location::Cloud,
                Filter::All,
                "REMOTE-123"
            )
            .len(),
            1
        );
        assert_eq!(
            rows(
                std::slice::from_ref(&local),
                std::slice::from_ref(&cloud),
                Location::Local,
                Filter::All,
                ""
            )
            .len(),
            1
        );
        assert!(rows(&[local], &[cloud], Location::All, Filter::Stopped, "").is_empty());
    }
}
