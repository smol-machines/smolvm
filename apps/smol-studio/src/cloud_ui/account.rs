use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Tab {
    Overview,
    Usage,
    Limits,
}

impl CloudView {
    pub(super) fn account_dialog(&mut self, ctx: &egui::Context) {
        if !self.account_open {
            return;
        }
        let Some(identity) = self.snapshot.identity.clone() else {
            self.account_open = false;
            return;
        };
        let mut open = true;
        let mut close = false;
        egui::Window::new("Cloud account")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(480.0)
            .resizable(false)
            .collapsible(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_width(480.0);
                ui.add_space(8.0);
                ui.add(egui::Label::new(design::heading(self.account_label(), 20.0)).truncate()).on_hover_text(self.account_label());
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    for (tab, label) in [(Tab::Overview, "Account"), (Tab::Usage, "Usage"), (Tab::Limits, "Limits")] {
                        if design::tab(ui, self.account_tab == tab, label).clicked() {
                            self.account_tab = tab;
                        }
                    }
                });
                ui.separator();
                ui.add_space(12.0);
                egui::ScrollArea::vertical()
                    .id_salt(("cloud-account-details", &self.tenant, self.account_tab))
                    .max_height((ctx.content_rect().height() - 320.0).clamp(160.0, 320.0))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if !self.valid {
                            ui.label(RichText::new("Showing the last loaded details.").size(12.0).color(design::palette(ui).muted));
                            ui.add_space(8.0);
                        }
                        if let Some(error) = &self.error {
                            design::error_notice(ui, "Account could not be refreshed.", error);
                        }
                        match self.account_tab {
                            Tab::Overview => {
                                design::card(ui.ctx()).show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    design::property(ui, "Status", identity.tenant_status.as_deref().unwrap_or("Not reported"));
                                    let plan = self.snapshot.account.as_ref().and_then(|a| a["plan"]["name"].as_str()).unwrap_or("Not reported");
                                    design::property(ui, "Plan", plan);
                                    if let Some(membership) = self.snapshot.memberships.iter().find(|m| Some(&m.tenant_id) == identity.tenant_id.as_ref()) {
                                        design::property(ui, "Your role", &membership.role);
                                    }
                                    if let Some(id) = &identity.tenant_id {
                                        copy_detail(ui, "Account ID", id);
                                    }
                                    if let Some(namespace) = &identity.registry_namespace {
                                        copy_detail(ui, "Registry", &format!("registry.smolmachines.com/{namespace}"));
                                    }
                                });
                            }
                            Tab::Usage => {
                                ui.label(design::heading("Usage this period", 14.0));
                                ui.add_space(8.0);
                                if let Some(account) = &self.snapshot.account {
                                    design::card(ui.ctx()).show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        for (label, amount) in [
                                            ("Gross usage", &account["periodCost"]["totalMicros"]),
                                            ("After discounts and credits", &account["periodCost"]["amountDueMicros"]),
                                            ("Prepaid balance", &account["prepaidCreditMicros"]),
                                        ] {
                                            design::property(ui, label, &money(amount).unwrap_or_else(|| "Not reported".into()));
                                        }
                                    });
                                    ui.add_space(6.0);
                                    ui.label(RichText::new("USD · amounts reported by Smol Cloud at the last refresh.").size(11.5).color(design::palette(ui).muted));
                                } else {
                                    account_unavailable(ui, &identity);
                                }
                            }
                            Tab::Limits => {
                                if let Some(account) = &self.snapshot.account {
                                    design::card(ui.ctx()).show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        for (label, field, unit) in [
                                            ("Machines", "effectiveMaxMachines", ""),
                                            ("CPU limit", "effectiveMaxCpus", "cores"),
                                            ("Memory limit", "effectiveMaxMemoryMb", "MB"),
                                            ("Disk per machine", "effectiveMaxDiskGb", "GB"),
                                        ] {
                                            let value = account[field].as_u64().map(|v| format!("{v} {unit}").trim().to_owned()).unwrap_or_else(|| "Not reported".into());
                                            design::property(ui, label, &value);
                                        }
                                    });
                                    ui.add_space(8.0);
                                    ui.label(RichText::new("Limits apply to this cloud account. Local machines use your computer’s resources.").size(12.0).color(design::palette(ui).muted));
                                } else {
                                    account_unavailable(ui, &identity);
                                }
                            }
                        }
                        for warning in &self.snapshot.warnings {
                            ui.add_space(8.0);
                            design::notice(ui, warning);
                        }
                    });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if self.pending {
                        ui.spinner();
                        ui.label(RichText::new("Refreshing account…").size(11.5).color(design::palette(ui).muted));
                    } else {
                        let age = self.last.elapsed().as_secs();
                        ui.label(RichText::new(if self.valid { format!("Checked {age}s ago") } else { "Refresh needed".into() }).size(11.5).color(design::palette(ui).muted));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        close = ui.add(design::primary(ui, "Done")).clicked();
                        if ui.add_enabled(!self.pending, egui::Button::new("Refresh")).clicked() {
                            self.refresh();
                        }
                    });
                });
            });
        if !open || close || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.account_open = false;
        }
    }
}

fn account_unavailable(ui: &mut egui::Ui, identity: &smol_studio::cloud::Identity) {
    design::notice(
        ui,
        if identity.allows("billing:read") {
            "Account usage and limits could not be loaded. Refresh to try again."
        } else {
            "This sign-in does not have permission to view account usage and limits."
        },
    );
}

fn copy_detail(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(label)
                .size(11.5)
                .color(design::palette(ui).muted),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .small_button("Copy")
                .on_hover_text(format!("Copy {label}"))
                .clicked()
            {
                ui.ctx().copy_text(value.to_owned());
            }
        });
    });
    ui.add(egui::Label::new(RichText::new(value).monospace().size(11.5)).truncate())
        .on_hover_text(value);
}

fn money(value: &serde_json::Value) -> Option<String> {
    let micros = value.as_i64()?;
    // Round once in integer micro-dollars so large balances and negative
    // credits don't lose precision through a floating point conversion.
    let cents = (micros.unsigned_abs() + 5_000) / 10_000;
    Some(format!(
        "{}${}.{:02}",
        if micros < 0 && cents != 0 { "−" } else { "" },
        cents / 100,
        cents % 100
    ))
}

#[cfg(test)]
mod tests {
    use super::money;
    use serde_json::json;
    #[test]
    fn balances_round_micro_dollars_without_inventing_missing_values() {
        for (micros, expected) in [
            (0, "$0.00"),
            (4_999, "$0.00"),
            (5_000, "$0.01"),
            (1_995_000, "$2.00"),
            (-1_005_000, "−$1.01"),
            (i64::MIN, "−$9223372036854.78"),
        ] {
            assert_eq!(money(&json!(micros)).as_deref(), Some(expected));
        }
        assert_eq!(money(&json!(null)), None);
        assert_eq!(money(&json!("0")), None);
    }
}
