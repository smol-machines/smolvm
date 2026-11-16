mod account;
mod create;

use crate::design::{self, ACCENT, MUTED, SURFACE};
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
    query: String,
    output: String,
    logs: Option<(String, Instant)>,
    log_filter: String,
    log_error: Option<String>,
    loading_logs: bool,
    tab: Tab,
    create_error: Option<String>,
    creating: bool,
    account_open: bool,
    account_tab: account::Tab,
    command: String,
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
            query: String::new(),
            output: String::new(),
            logs: None,
            log_filter: String::new(),
            log_error: None,
            loading_logs: false,
            tab: Tab::Overview,
            create_error: None,
            creating: false,
            account_open: false,
            account_tab: account::Tab::Overview,
            command: String::new(),
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
    fn refresh(&mut self) {
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
                        self.query.clear();
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
                            OutputKind::Command => self.output = text,
                            OutputKind::Logs => {
                                self.logs = Some((text, Instant::now()));
                                self.log_error = None;
                            }
                        }
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
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.create.is_some() || self.delete.is_some() || self.account_open {
            ui.disable();
        }
        egui::Panel::top("cloud-heading")
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .inner_margin(egui::Margin::symmetric(22, 14)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        design::section_title(
                            ui,
                            "Cloud",
                            "Your Smol machines, wherever you work.",
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.pending {
                            ui.spinner();
                        }
                        if let Some(identity) = &self.snapshot.identity {
                            if ui
                                .add_enabled(
                                    self.valid
                                        && !self.pending
                                        && identity.allows("machine:create"),
                                    design::primary("+  New machine"),
                                )
                                .clicked()
                            {
                                self.create_error = None;
                                self.create = Some(NewMachine {
                                    image: "alpine:latest".into(),
                                    ..Default::default()
                                });
                            }
                            if ui
                                .add_enabled(!self.pending, egui::Button::new("Refresh"))
                                .clicked()
                            {
                                self.refresh();
                            }
                        }
                    });
                });
                if let Some(error) = &self.error {
                    ui.add_space(10.0);
                    design::error_notice(ui, "Your cloud connection needs attention.", error);
                }
            });
        if self.snapshot.identity.is_none() || self.device.is_some() {
            egui::CentralPanel::default().frame(egui::Frame::new().fill(SURFACE).inner_margin(32)).show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_space((ctx.content_rect().height() - 640.0).clamp(12.0, 32.0));
                    ui.vertical_centered(|ui| {
                        ui.set_max_width(480.0);
                        let (r,_) = ui.allocate_exact_size(egui::Vec2::splat(64.0),egui::Sense::hover());
                        ui.painter().rect_filled(r,18,design::SELECTED);
                        design::icon(ui.painter(),r.shrink(17.0),design::Icon::Cloud,ACCENT);
                        ui.add_space(20.0);
                        if let Some((code,url,expires)) = self.device.clone() {
                            ui.label(RichText::new("Finish signing in").size(28.0).strong());
                            ui.label(RichText::new("Enter this code in your browser to connect your account.").color(MUTED));
                            ui.add_space(24.0);
                            ui.label(RichText::new(&code).monospace().size(32.0).strong());
                            if ui.button("Copy code").clicked() { ctx.copy_text(code); }
                            ui.add_space(20.0);
                            ui.hyperlink_to("Open sign-in page",url);
                            ui.label(RichText::new(format!("Code expires in {} seconds",expires.saturating_duration_since(Instant::now()).as_secs())).small().color(MUTED));
                            if ui.button("Cancel").clicked() { self.send(Action::CancelLogin); }
                        } else {
                            ui.label(design::heading(if self.pending { "Connecting to Smol Cloud" } else { "Connect to Smol Cloud" },28.0));
                            ui.add_space(8.0);
                            ui.label(RichText::new("Connect your Smol account to manage cloud machines\nand switch between your personal and team workspaces.").color(MUTED));
                            ui.add_space(28.0);
                            if self.pending {
                                ui.spinner();
                                ui.label(RichText::new("Checking your sign-in…").color(MUTED));
                                ui.add_space(12.0);
                            }
                            ui.add_enabled_ui(!self.pending, |ui| {
                                if ui.add_sized([240.0,40.0],design::primary("Sign in with Smol")).clicked() { self.tenant=None; self.send(Action::Login); }
                                ui.add_space(8.0);
                                if ui.add_sized([240.0,36.0],egui::Button::new("Use CLI sign-in")).clicked() { self.tenant=None; self.send(Action::UseCli); }
                                ui.add_space(20.0);
                                ui.collapsing("Saved sign-in",|ui| {
                                    if ui.button("Restore saved session").clicked() { self.tenant=None; self.send(Action::Restore); }
                                    if ui.button("Forget saved session").clicked() { self.send(Action::Logout); }
                                });
                            });
                        }
                    });
                });
            });
            self.dialogs(&ctx);
            return;
        }
        let identity = self.snapshot.identity.as_ref().unwrap().clone();
        egui::Panel::top("cloud-account-bar")
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .inner_margin(egui::Margin::symmetric(24, 12)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Account").small().color(MUTED));
                    ui.add_enabled_ui(!self.pending, |ui| {
                        let mut next = self.tenant.clone();
                        egui::ComboBox::from_id_salt("cloud-account")
                            .width((ui.available_width() - 260.0).clamp(140.0, 260.0))
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
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(!self.pending, egui::Button::new("Sign out").frame(false))
                            .clicked()
                        {
                            self.send(Action::Logout);
                        }
                        if ui
                            .add_enabled(
                                !self.pending && self.valid,
                                egui::Button::new("Account & usage"),
                            )
                            .clicked()
                        {
                            self.account_open = true;
                            self.account_tab = account::Tab::Overview;
                        }
                    });
                });
                for warning in &self.snapshot.warnings {
                    design::notice(ui, warning);
                }
                if !self.valid {
                    ui.label(
                        RichText::new("Refresh this account to manage its machines.")
                            .small()
                            .color(MUTED),
                    );
                }
            });
        egui::Panel::left("cloud-list")
            .resizable(true)
            .default_size(248.0)
            .min_size(224.0)
            .max_size(380.0)
            .frame(egui::Frame::new().fill(SURFACE).inner_margin(12))
            .show(ui, |ui| {
                design::search(ui, &mut self.query, "Search cloud machines…");
                ui.add_space(14.0);
                let query = self.query.to_lowercase();
                let rows: Vec<_> = self
                    .snapshot
                    .machines
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| {
                        m.display_name().to_lowercase().contains(&query) || m.id.contains(&query)
                    })
                    .map(|(i, _)| i)
                    .collect();
                design::eyebrow(ui, &format!("MACHINES  /  {}", rows.len()));
                ui.add_space(8.0);
                if self.valid
                    && !self.pending
                    && !rows.iter().any(|&index| {
                        Some(&self.snapshot.machines[index].id) == self.selected.as_ref()
                    })
                {
                    let next = rows
                        .first()
                        .map(|&index| self.snapshot.machines[index].id.clone());
                    if next != self.selected {
                        self.selected = next;
                        self.clear_machine_output();
                    }
                }
                if rows.is_empty() && self.valid {
                    ui.label(RichText::new("No matching machines.").color(MUTED));
                }
                let mut list = egui::ScrollArea::vertical().id_salt("cloud-machines");
                if self.focus_selected
                    && let Some(index) = rows.iter().position(|&index| {
                        Some(&self.snapshot.machines[index].id) == self.selected.as_ref()
                    })
                {
                    list = list.vertical_scroll_offset(
                        index as f32 * (60.0 + ui.spacing().item_spacing.y),
                    );
                    self.focus_selected = false;
                }
                list.show_rows(ui, 60.0, rows.len(), |ui, range| {
                    for &index in &rows[range] {
                        let m = &self.snapshot.machines[index];
                        let state = if m.is_started() && !m.is_ready() {
                            "starting"
                        } else {
                            &m.state
                        };
                        let source = m
                            .source
                            .as_ref()
                            .and_then(|s| s.reference.as_deref())
                            .unwrap_or(&m.id);
                        if design::machine_row(
                            ui,
                            Some(&m.id) == self.selected.as_ref(),
                            m.display_name(),
                            source,
                            state,
                        )
                        .clicked()
                        {
                            self.selected = Some(m.id.clone());
                            self.clear_machine_output();
                        }
                    }
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(24))
            .show(ui, |ui| {
                let Some(machine) = self
                    .snapshot
                    .machines
                    .iter()
                    .find(|m| Some(&m.id) == self.selected.as_ref())
                    .cloned()
                else {
                    ui.add_space(100.0);
                    ui.vertical_centered(|ui| {
                        ui.heading(if self.query.is_empty() {
                            "Your cloud workspace"
                        } else {
                            "No matching machines"
                        });
                        ui.label(
                            RichText::new(
                                if self.query.is_empty() { "Select a machine to see its resources and activity." } else { "Try another name or clear your search." },
                            )
                            .color(MUTED),
                        );
                        if !self.query.is_empty() && ui.button("Clear search").clicked() {
                            self.query.clear();
                        }
                    });
                    return;
                };
                ui.add(
                    egui::Label::new(design::heading(machine.display_name(), 24.0))
                        .truncate(),
                )
                .on_hover_text(machine.display_name());
                ui.horizontal(|ui| {
                    design::badge(ui, if machine.is_started() && !machine.is_ready() { "starting" } else { &machine.state });
                    if let Some(source) = &machine.source {
                        let label = source.reference.as_deref().unwrap_or(&source.source_type);
                        ui.add(egui::Label::new(RichText::new(label).small().color(MUTED)).truncate()).on_hover_text(label);
                    }
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    for (tab, label) in [
                        (Tab::Overview, "Overview"),
                        (Tab::Console, "Console"),
                        (Tab::Logs, "Logs"),
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
                egui::ScrollArea::vertical().id_salt(("cloud-detail", &self.tenant, &machine.id, self.tab)).auto_shrink([false, false]).show(ui, |ui| {
                    if self.tab == Tab::Overview {
                        ui.add_enabled_ui(self.valid && !self.pending, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                if machine.is_ready() && ui
                                    .add_enabled(
                                        identity.allows("machine:exec"),
                                        design::primary("Console"),
                                    )
                                    .clicked()
                                {
                                    self.tab = Tab::Console;
                                }
                                if matches!(machine.state.as_str(), "created" | "stopped" | "error")
                                    && ui
                                        .add_enabled(
                                            identity.allows("machine:create"),
                                            design::primary("Start machine"),
                                        )
                                        .clicked()
                                {
                                    self.machine(machine.id.clone(), MachineAction::Start);
                                }
                                if machine.is_started()
                                    && ui
                                        .add_enabled(
                                            identity.allows("machine:create"),
                                            egui::Button::new("Stop"),
                                        )
                                        .clicked()
                                {
                                    self.machine(machine.id.clone(), MachineAction::Stop);
                                }
                                if machine.state == "paused"
                                    && ui
                                        .add_enabled(
                                            identity.allows("machine:create"),
                                            design::primary("Resume machine"),
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
                                                    RichText::new("Delete machine…")
                                                        .color(design::RED),
                                                ),
                                            )
                                            .clicked()
                                    {
                                        self.delete = Some((
                                            machine.id.clone(),
                                            machine.display_name().into(),
                                        ));
                                        ui.close();
                                    }
                                });
                            });
                        });

                        ui.add_space(20.0);
                        if let Some(resources) = &machine.resources {
                            ui.label(design::heading("Configuration", 14.0));
                            ui.add_space(10.0);
                            design::card().show(ui, |ui| {
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
                                            .color(MUTED),
                                    );
                                }
                            });
                            ui.add_space(24.0);
                        }
                        design::card().show(ui, |ui| {
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
                                egui::Label::new(
                                    RichText::new(&machine.id).monospace().size(12.0),
                                )
                                .wrap()
                                .selectable(true),
                            );
                        });
                    } else if self.tab == Tab::Console {
                        if !machine.is_ready() {
                            ui.label(RichText::new("Start this machine and wait for it to be ready to run commands.").size(12.0).color(MUTED));
                            ui.add_space(12.0);
                        }
                        design::eyebrow(ui, "CONSOLE");
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("Run a command · 60 second limit")
                                .small()
                                .color(MUTED),
                        );
                        ui.add(
                            egui::TextEdit::multiline(&mut self.command)
                                .desired_rows(2)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("uname -a"),
                        );
                        if ui
                            .add_enabled(
                                self.valid
                                    && !self.pending
                                    && machine.is_ready()
                                    && identity.allows("machine:exec")
                                    && !self.command.trim().is_empty(),
                                design::primary("Run command"),
                            )
                            .clicked()
                        {
                            self.output.clear();
                            self.machine(
                                machine.id.clone(),
                                MachineAction::Exec(self.command.clone()),
                            );
                        }
                        if !self.output.is_empty() {
                            ui.add_space(16.0);
                            ui.horizontal(|ui| {
                                design::eyebrow(ui, "OUTPUT");
                                if ui.small_button("Copy").clicked() {
                                    ctx.copy_text(self.output.clone());
                                }
                            });
                            egui::ScrollArea::both()
                                .id_salt("cloud-output")
                                .max_height(300.0)
                                .show(ui, |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&self.output).monospace().size(12.0),
                                        )
                                        .selectable(true),
                                    );
                                });
                        }
                    }
                });
            });
        self.dialogs(&ctx);
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
                        .color(MUTED),
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
            ui.label(RichText::new(format!("Fetched {age} · last 200 lines requested")).small().color(MUTED))
                .on_hover_text("Time this snapshot was received. Timestamps inside the output come from the cloud service.");
        } else {
            ui.label(
                RichText::new("Recent console output · last 200 lines requested")
                    .small()
                    .color(MUTED),
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
                    .color(MUTED),
                );
            }
            return;
        };
        if text.is_empty() {
            ui.label(RichText::new("No console output was returned.").color(MUTED));
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
            ui.label(RichText::new("No log lines match this filter.").color(MUTED));
            return;
        }
        ui.label(
            RichText::new(if query.is_empty() {
                format!("{total} lines")
            } else {
                format!("{} of {total} lines", lines.len())
            })
            .small()
            .color(MUTED),
        );
        design::card().show(ui, |ui| {
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
                                    .color(MUTED),
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
        self.output.clear();
        self.logs = None;
        self.log_filter.clear();
        self.log_error = None;
        self.loading_logs = false;
        self.tab = Tab::Overview;
    }
    fn dialogs(&mut self, ctx: &egui::Context) {
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
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        design::property(ui, "Account", self.account_label());
                        ui.add(
                            egui::Label::new(
                                RichText::new(&id).monospace().size(11.5).color(MUTED),
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
                                    .fill(design::RED),
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
