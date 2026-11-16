mod account;
mod console;
mod create;

use crate::design;
use eframe::egui::{self, Color32, RichText};
use smol_cloud::types::{CreateMachine, Network, Resources, Source};
use smol_studio::{
    cloud::{Action, CloudWorker, Event, MachineAction, OutputKind, Snapshot},
    model::NewMachine,
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
enum Tab {
    #[default]
    Overview,
    Console,
    Logs,
}

pub struct CloudView {
    worker: CloudWorker,
    snapshot: Snapshot,
    tenant: Option<String>,
    pending: bool,
    mutation: bool,
    valid: bool,
    last: Instant,
    error: Option<String>,
    device: Option<(String, String, Instant)>,
    selected: Option<String>,
    focus_selected: bool,
    console: console::Console,
    logs: Option<(String, Instant)>,
    log_filter: String,
    log_error: Option<String>,
    loading_logs: bool,
    tab: Tab,
    create_error: Option<String>,
    creating: bool,
    account_open: bool,
    account_tab: account::Tab,
    create: Option<NewMachine>,
    delete: Option<(String, String)>,
}
impl CloudView {
    pub fn new(ctx: &egui::Context) -> Self {
        let ctx = ctx.clone();
        Self {
            worker: CloudWorker::new(move || ctx.request_repaint()),
            snapshot: Snapshot::default(),
            tenant: None,
            pending: false,
            mutation: false,
            valid: false,
            last: Instant::now(),
            error: None,
            device: None,
            selected: None,
            focus_selected: false,
            console: console::Console::default(),
            logs: None,
            log_filter: String::new(),
            log_error: None,
            loading_logs: false,
            tab: Tab::Overview,
            create_error: None,
            creating: false,
            account_open: false,
            account_tab: account::Tab::Overview,
            create: None,
            delete: None,
        }
    }
    pub fn restore(&mut self) {
        self.send(Action::Restore);
    }
    fn account_label(&self) -> &str {
        match &self.tenant {
            None => "Personal account",
            Some(tenant) => self
                .snapshot
                .memberships
                .iter()
                .find(|m| &m.tenant_id == tenant)
                .map(|m| m.label())
                .unwrap_or("Team account"),
        }
    }
    pub fn modal_open(&self) -> bool {
        self.create.is_some() || self.delete.is_some() || self.account_open
    }
    pub fn mutating(&self) -> bool {
        self.mutation
    }
    fn send(&mut self, action: Action) {
        if self.pending {
            return;
        }
        let command = matches!(
            action,
            Action::Machine {
                action: MachineAction::Exec(_),
                ..
            }
        );
        let mutation = action.mutates();
        let creating = matches!(action, Action::Create { .. });
        let loading_logs = matches!(
            action,
            Action::Machine {
                action: MachineAction::Logs,
                ..
            }
        );
        match self.worker.submit(action) {
            Ok(()) => {
                if command {
                    self.console.begin();
                }
                self.pending = true;
                self.creating = creating;
                self.loading_logs = loading_logs;
                if loading_logs {
                    self.log_error = None;
                }
                self.mutation = mutation;
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }
    pub fn refresh(&mut self) {
        self.send(Action::Refresh {
            tenant: self.tenant.clone(),
        });
    }
    fn machine(&mut self, id: String, action: MachineAction) {
        self.send(Action::Machine {
            tenant: self.tenant.clone(),
            id,
            action,
        });
    }
    pub fn logic(&mut self, ctx: &egui::Context, active: bool) {
        while let Ok(event) = self.worker.events.try_recv() {
            let mutated = self.mutation;
            let creating = std::mem::take(&mut self.creating);
            self.pending = false;
            self.loading_logs = false;
            self.mutation = false;
            match event {
                Event::SignedOut => {
                    self.account_open = false;
                    self.snapshot = Snapshot::default();
                    self.tenant = None;
                    self.selected = None;
                    self.clear_machine_output();
                    self.device = None;
                    self.valid = false;
                }
                Event::Device { code, url, expires } => {
                    self.device = Some((code, url.clone(), expires));
                    ctx.open_url(egui::OpenUrl::new_tab(url));
                }
                Event::Snapshot { tenant, snapshot } => {
                    if tenant != self.tenant {
                        continue;
                    }
                    self.snapshot = *snapshot;
                    self.valid = true;
                    self.device = None;
                    self.last = Instant::now();
                    self.error = None;
                    if !self
                        .snapshot
                        .machines
                        .iter()
                        .any(|m| Some(&m.id) == self.selected.as_ref())
                    {
                        self.selected = self.snapshot.machines.first().map(|m| m.id.clone());
                        self.clear_machine_output();
                    }
                }
                Event::Created { tenant, id } => {
                    if tenant == self.tenant {
                        self.create = None;
                        self.create_error = None;
                        self.selected = Some(id);
                        self.focus_selected = true;
                        self.valid = false;
                        self.clear_machine_output();
                        self.refresh();
                    }
                }
                Event::Output {
                    kind,
                    tenant,
                    id,
                    text,
                } => {
                    if tenant == self.tenant && Some(&id) == self.selected.as_ref() {
                        match kind {
                            OutputKind::Logs => {
                                self.logs = Some((text, Instant::now()));
                                self.log_error = None;
                            }
                        }
                    }
                }
                Event::CommandFinished { tenant, id, result } => {
                    if tenant == self.tenant && Some(&id) == self.selected.as_ref() {
                        self.console.finish(result);
                    }
                }
                Event::LogError { tenant, id, error } => {
                    if tenant == self.tenant && Some(&id) == self.selected.as_ref() {
                        self.log_error = Some(error);
                    }
                }
                Event::Completed => {
                    self.device = None;
                    if mutated {
                        self.refresh();
                    }
                }
                Event::Error(e) => {
                    if creating {
                        self.create_error = Some(e.clone());
                    }
                    self.error = Some(e);
                    self.device = None;
                    self.valid = false;
                    if creating {
                        self.refresh();
                    }
                }
            }
        }
        if active
            && self.valid
            && !self.pending
            && self.device.is_none()
            && self.create.is_none()
            && self.delete.is_none()
            && !self.account_open
            && self.last.elapsed() >= Duration::from_secs(30)
        {
            self.refresh();
        }
        if active && (self.valid || self.device.is_some()) {
            ctx.request_repaint_after(Duration::from_secs(5));
        }
    }
    pub fn inventory(&self) -> &[smol_cloud::types::Machine] {
        &self.snapshot.machines
    }
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }
    pub fn select(&mut self, id: &str) {
        if self.selected.as_deref() != Some(id) {
            self.selected = Some(id.into());
            self.clear_machine_output();
            self.tab = Tab::Overview;
        }
    }
    pub fn awaiting_created_selection(&self) -> bool {
        self.focus_selected && !self.valid
    }
    pub fn take_created_selection(&mut self) -> bool {
        if self.focus_selected && self.valid {
            self.focus_selected = false;
            true
        } else {
            false
        }
    }
    pub fn signed_in(&self) -> bool {
        self.snapshot.identity.is_some()
    }
    pub fn can_create(&self) -> bool {
        self.valid
            && !self.pending
            && self
                .snapshot
                .identity
                .as_ref()
                .is_some_and(|i| i.allows("machine:create"))
    }
    pub fn begin_create(&mut self) {
        if self.can_create() {
            self.create_error = None;
            self.create = Some(NewMachine {
                image: "alpine:latest".into(),
                ..Default::default()
            });
        }
    }
    pub fn connection_notice(&self, ui: &mut egui::Ui) {
        if let Some(error) = &self.error {
            design::error_notice(ui, "Cloud connection needs attention.", error);
        }
    }
    pub fn account_ui(&mut self, ui: &mut egui::Ui) {
        self.connection_notice(ui);
        ui.label(design::heading("Smol account", 18.0));
        ui.label(
            RichText::new("Your cloud machines appear alongside local machines.")
                .size(12.0)
                .color(design::palette(ui).muted),
        );
        ui.add_space(16.0);
        if let Some((code, url, expires)) = self.device.clone() {
            ui.label("Finish signing in using this code:");
            ui.label(RichText::new(&code).monospace().size(28.0).strong());
            ui.horizontal(|ui| {
                if ui.button("Copy code").clicked() {
                    ui.ctx().copy_text(code);
                }
                ui.hyperlink_to("Open sign-in page", url);
                if ui.button("Cancel").clicked() {
                    self.send(Action::CancelLogin);
                }
            });
            ui.label(format!(
                "Expires in {} seconds",
                expires.saturating_duration_since(Instant::now()).as_secs()
            ));
            return;
        }
        if !self.signed_in() {
            if self.pending {
                ui.spinner();
                ui.label("Checking your sign-in…");
            }
            ui.add_enabled_ui(!self.pending, |ui| {
                if ui.add(design::primary(ui, "Sign in with Smol")).clicked() {
                    self.tenant = None;
                    self.send(Action::Login);
                }
                if ui.button("Use CLI sign-in").clicked() {
                    self.tenant = None;
                    self.send(Action::UseCli);
                }
                ui.collapsing("Saved sign-in", |ui| {
                    if ui.button("Restore saved session").clicked() {
                        self.tenant = None;
                        self.send(Action::Restore);
                    }
                    if ui.button("Forget saved session").clicked() {
                        self.send(Action::Logout);
                    }
                });
            });
            return;
        }
        ui.add_enabled_ui(!self.pending, |ui| {
            ui.label("Active account");
            let mut next = self.tenant.clone();
            egui::ComboBox::from_id_salt("cloud-account")
                .width(300.0)
                .selected_text(self.account_label())
                .truncate()
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut next, None, "Personal account");
                    for membership in &self.snapshot.memberships {
                        ui.selectable_value(
                            &mut next,
                            Some(membership.tenant_id.clone()),
                            membership.label(),
                        );
                    }
                });
            if next != self.tenant {
                self.tenant = next;
                self.valid = false;
                self.snapshot.machines.clear();
                self.snapshot.account = None;
                self.selected = None;
                self.clear_machine_output();
                self.create = None;
                self.delete = None;
                self.refresh();
            }
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(self.valid, egui::Button::new("Account & usage"))
                    .clicked()
                {
                    self.account_open = true;
                    self.account_tab = account::Tab::Overview;
                }
                if ui.button("Refresh account").clicked() {
                    self.refresh();
                }
                if ui.button("Sign out").clicked() {
                    self.send(Action::Logout);
                }
            });
        });
        for warning in &self.snapshot.warnings {
            design::notice(ui, warning);
        }
    }
    pub fn details(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let Some(identity) = self.snapshot.identity.clone() else {
            return;
        };
        let Some(machine) = self
            .snapshot
            .machines
            .iter()
            .find(|m| Some(&m.id) == self.selected.as_ref())
            .cloned()
        else {
            ui.add_space(100.0);
            ui.vertical_centered(|ui| {
                ui.heading("Select a machine");
                ui.label("Choose a machine from the list to see its resources and activity.");
            });
            return;
        };
        let source = machine
            .source
            .as_ref()
            .and_then(|s| s.reference.as_deref())
            .unwrap_or("Linux machine");
        design::workload_heading(
            ui,
            design::Icon::Machine,
            machine.display_name(),
            &format!("Cloud · {} · {source}", self.account_label()),
            if machine.is_started() {
                if machine.is_ready() {
                    "running"
                } else {
                    "starting"
                }
            } else {
                &machine.state
            },
            None,
        );
        ui.add_space(10.0);
        ui.add_enabled_ui(self.valid && !self.pending, |ui| {
            ui.horizontal_wrapped(|ui| {
                if machine.is_ready()
                    && ui
                        .add_enabled(
                            identity.allows("machine:exec"),
                            design::primary(ui, "Console"),
                        )
                        .clicked()
                {
                    self.tab = Tab::Console;
                }
                if matches!(machine.state.as_str(), "created" | "stopped" | "error")
                    && ui
                        .add_enabled(
                            identity.allows("machine:create"),
                            design::primary(ui, "Start machine"),
                        )
                        .clicked()
                {
                    self.machine(machine.id.clone(), MachineAction::Start);
                }
                if machine.is_started()
                    && ui
                        .add_enabled(identity.allows("machine:create"), egui::Button::new("Stop"))
                        .clicked()
                {
                    self.machine(machine.id.clone(), MachineAction::Stop);
                }
                if machine.state == "paused"
                    && ui
                        .add_enabled(
                            identity.allows("machine:create"),
                            design::primary(ui, "Resume machine"),
                        )
                        .clicked()
                {
                    self.machine(machine.id.clone(), MachineAction::Resume);
                }
                ui.menu_button("More", |ui| {
                    if ui.button("Copy machine ID").clicked() {
                        ctx.copy_text(machine.id.clone());
                        ui.close();
                    }
                    if !machine.is_started()
                        && ui
                            .add_enabled(
                                identity.allows("machine:delete"),
                                egui::Button::new(
                                    RichText::new("Delete machine…").color(design::palette(ui).red),
                                ),
                            )
                            .clicked()
                    {
                        self.delete = Some((machine.id.clone(), machine.display_name().into()));
                        ui.close();
                    }
                });
            });
        });

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Overview, "Overview"),
                (Tab::Logs, "Logs"),
                (Tab::Console, "Console"),
            ] {
                if design::tab(ui, self.tab == tab, label).clicked() {
                    self.tab = tab;
                    if tab == Tab::Logs
                        && self.logs.is_none()
                        && self.valid
                        && !self.pending
                        && identity.allows("machine:read")
                    {
                        self.machine(machine.id.clone(), MachineAction::Logs);
                    }
                }
            }
        });
        ui.separator();
        ui.add_space(16.0);
        if self.tab == Tab::Logs {
            self.logs_ui(ui, &machine.id, identity.allows("machine:read"));
            return;
        }
        if self.tab == Tab::Console {
            if let Some(command) = self.console.show(
                ui,
                self.valid && !self.pending,
                machine.is_ready(),
                identity.allows("machine:exec"),
            ) {
                self.machine(machine.id.clone(), MachineAction::Exec(command));
            }
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt(("cloud-detail", &self.tenant, &machine.id, self.tab))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.tab == Tab::Overview {
                    let endpoints: Vec<_> = machine
                        .url
                        .as_deref()
                        .and_then(smol_studio::app_access::Endpoint::cloud)
                        .into_iter()
                        .collect();
                    crate::app_access_ui::show(
                        ui,
                        "Smol Cloud",
                        machine.is_started() && machine.is_ready(),
                        &endpoints,
                        if machine.ports.is_empty() {
                            "No app ports published for this machine."
                        } else {
                            "The app URL is not available yet."
                        },
                    );
                    ui.add_space(16.0);
                    if let Some(resources) = &machine.resources {
                        ui.label(design::heading("Configuration", 14.0));
                        ui.add_space(10.0);
                        design::card(ui.ctx()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.columns(2, |columns| {
                                design::metric(
                                    &mut columns[0],
                                    "CPU limit",
                                    &resources
                                        .cpus
                                        .map(|n| n.to_string())
                                        .unwrap_or_else(|| "—".into()),
                                    "cores",
                                );
                                design::metric(
                                    &mut columns[1],
                                    "Memory limit",
                                    &resources
                                        .memory_mb
                                        .map(|n| n.to_string())
                                        .unwrap_or_else(|| "—".into()),
                                    "MB",
                                );
                            });
                            if let Some(disk) = resources.disk_gb {
                                ui.label(
                                    RichText::new(format!("Disk limit: {disk} GB"))
                                        .small()
                                        .color(design::palette(ui).muted),
                                );
                            }
                        });
                        ui.add_space(24.0);
                    }
                    design::card(ui.ctx()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        design::property(ui, "Account", self.account_label());
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            design::eyebrow(ui, "MACHINE ID");
                            if ui.small_button("Copy").clicked() {
                                ctx.copy_text(machine.id.clone());
                            }
                        });
                        ui.add(
                            egui::Label::new(RichText::new(&machine.id).monospace().size(12.0))
                                .wrap()
                                .selectable(true),
                        );
                    });
                }
            });
    }
    fn logs_ui(&mut self, ui: &mut egui::Ui, id: &str, allowed: bool) {
        let enabled = self.valid && !self.pending && allowed;
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(enabled, egui::Button::new("Reload logs"))
                    .clicked()
                {
                    self.machine(id.to_owned(), MachineAction::Logs);
                }
                if ui
                    .add_enabled(
                        self.logs.as_ref().is_some_and(|(text, _)| !text.is_empty()),
                        egui::Button::new("Copy all"),
                    )
                    .clicked()
                    && let Some((text, _)) = &self.logs
                {
                    ui.ctx().copy_text(text.clone());
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(if self.loading_logs {
                            "Fetching logs…"
                        } else {
                            "Console snapshot"
                        })
                        .small()
                        .color(design::palette(ui).muted),
                    );
                });
            });
        });
        if let Some((_, fetched)) = &self.logs {
            let seconds = fetched.elapsed().as_secs();
            let age = match seconds {
                0..5 => "just now".into(),
                5..60 => format!("{seconds}s ago"),
                60..3600 => format!("{}m ago", seconds / 60),
                _ => format!("{}h ago", seconds / 3600),
            };
            ui.label(RichText::new(format!("Fetched {age} · last 200 lines requested")).small().color(design::palette(ui).muted))
                .on_hover_text("Time this snapshot was received. Timestamps inside the output come from the cloud service.");
        } else {
            ui.label(
                RichText::new("Recent console output · last 200 lines requested")
                    .small()
                    .color(design::palette(ui).muted),
            );
        }
        if let Some(error) = &self.log_error {
            ui.add_space(8.0);
            design::error_notice(
                ui,
                if self.logs.is_some() {
                    "Could not refresh logs. Showing the previous snapshot."
                } else {
                    "Could not load logs."
                },
                error,
            );
        }
        ui.add_space(8.0);
        design::search(ui, &mut self.log_filter, "Filter log lines…");
        ui.add_space(12.0);
        let Some((text, _)) = &self.logs else {
            if self.log_error.is_none() {
                ui.label(
                    RichText::new(if self.loading_logs {
                        "Waiting for console output…"
                    } else {
                        "Reload to read this machine’s recent output."
                    })
                    .color(design::palette(ui).muted),
                );
            }
            return;
        };
        if text.is_empty() {
            ui.label(
                RichText::new("No console output was returned.").color(design::palette(ui).muted),
            );
            return;
        }
        let query = self.log_filter.to_lowercase();
        let total = text.lines().count();
        let lines: Vec<_> = text
            .lines()
            .enumerate()
            .filter(|(_, line)| query.is_empty() || line.to_lowercase().contains(&query))
            .collect();
        if lines.is_empty() {
            ui.label(
                RichText::new("No log lines match this filter.").color(design::palette(ui).muted),
            );
            return;
        }
        ui.label(
            RichText::new(if query.is_empty() {
                format!("{total} lines")
            } else {
                format!("{} of {total} lines", lines.len())
            })
            .small()
            .color(design::palette(ui).muted),
        );
        design::card(ui.ctx()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().interact_size.y = 18.0;
            egui::ScrollArea::both()
                .id_salt(("cloud-logs", &self.tenant, id))
                .auto_shrink([false, true])
                .max_height((ui.clip_rect().bottom() - ui.cursor().top() - 16.0).max(60.0))
                .show_rows(ui, 18.0, lines.len(), |ui, range| {
                    for index in range {
                        let (number, line) = lines[index];
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{:>4}", number + 1))
                                    .monospace()
                                    .size(11.0)
                                    .color(design::palette(ui).muted),
                            );
                            ui.add(
                                egui::Label::new(RichText::new(line).monospace().size(12.0))
                                    .wrap_mode(egui::TextWrapMode::Extend)
                                    .selectable(true),
                            );
                        });
                    }
                });
        });
    }
    fn clear_machine_output(&mut self) {
        self.console = console::Console::default();
        self.logs = None;
        self.log_filter.clear();
        self.log_error = None;
        self.loading_logs = false;
        self.tab = Tab::Overview;
    }
    pub fn dialogs(&mut self, ctx: &egui::Context) {
        self.account_dialog(ctx);
        self.create_dialog(ctx);
        if let Some((id, name)) = self.delete.clone() {
            let mut open = true;
            egui::Window::new("Delete cloud machine?")
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .default_width(440.0)
                .resizable(false)
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.add_space(8.0);
                    ui.label(format!("Permanently delete “{name}” and its disks?"));
                    ui.add_space(12.0);
                    design::card(ui.ctx()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        design::property(ui, "Account", self.account_label());
                        ui.add(
                            egui::Label::new(
                                RichText::new(&id)
                                    .monospace()
                                    .size(11.5)
                                    .color(design::palette(ui).muted),
                            )
                            .wrap(),
                        );
                    });
                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_enabled(
                                    self.valid && !self.pending,
                                    egui::Button::new(
                                        RichText::new("Delete machine").color(Color32::WHITE),
                                    )
                                    .fill(design::palette(ui).danger_fill),
                                )
                                .clicked()
                            {
                                self.delete = None;
                                self.machine(id, MachineAction::Delete);
                            }
                            if ui.button("Cancel").clicked() {
                                self.delete = None;
                            }
                        });
                    });
                });
            if !open {
                self.delete = None;
            }
        }
    }
}
