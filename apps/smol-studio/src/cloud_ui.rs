use crate::design::{self, ACCENT, MUTED, SURFACE};
use eframe::egui::{self, Color32, RichText};
use smol_cloud::types::{CreateMachine, Network, Resources, Source};
use smol_studio::{
    cloud::{Action, CloudWorker, Event, MachineAction, Snapshot},
    model::NewMachine,
};
use std::time::{Duration, Instant};

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
    query: String,
    output: String,
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
            query: String::new(),
            output: String::new(),
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
        self.create.is_some() || self.delete.is_some()
    }
    pub fn mutating(&self) -> bool {
        self.mutation
    }
    fn send(&mut self, action: Action) {
        if self.pending {
            return;
        }
        let mutation = action.mutates();
        match self.worker.submit(action) {
            Ok(()) => {
                self.pending = true;
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
            self.pending = false;
            self.mutation = false;
            match event {
                Event::SignedOut => {
                    self.snapshot = Snapshot::default();
                    self.tenant = None;
                    self.selected = None;
                    self.output.clear();
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
                        self.output.clear();
                    }
                }
                Event::Output { tenant, id, text } => {
                    if tenant == self.tenant && Some(&id) == self.selected.as_ref() {
                        self.output = text;
                    }
                }
                Event::Completed => {
                    self.device = None;
                    if mutated {
                        self.refresh();
                    }
                }
                Event::Error(e) => {
                    self.error = Some(e);
                    self.device = None;
                    self.valid = false;
                }
            }
        }
        if active
            && self.valid
            && !self.pending
            && self.device.is_none()
            && self.create.is_none()
            && self.delete.is_none()
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
        if self.create.is_some() || self.delete.is_some() {
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
                    ui.add_space(48.0);
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
                            ui.label(design::heading("Connect to Smol Cloud",28.0));
                            ui.add_space(8.0);
                            ui.label(RichText::new("Connect your Smol account to manage cloud machines\nand switch between your personal and team workspaces.").color(MUTED));
                            ui.add_space(28.0);
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
                            .width(220.0)
                            .selected_text(self.account_label())
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
                            self.output.clear();
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
                    });
                });
                ui.collapsing("Account & usage", |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} · {}",
                            identity.tenant_id.as_deref().unwrap_or("Not provisioned"),
                            identity
                                .tenant_status
                                .as_deref()
                                .unwrap_or("Unknown status")
                        ))
                        .small()
                        .color(MUTED),
                    );
                    if let Some(namespace) = &identity.registry_namespace {
                        ui.label(format!("Registry: registry.smolmachines.com/{namespace}"));
                    }
                    if let Some(account) = &self.snapshot.account {
                        ui.horizontal_wrapped(|ui| {
                            if let Some(plan) = account["plan"]["name"].as_str() {
                                ui.label(format!("{plan} plan"));
                            }
                            if let Some(cost) = account["periodCost"]["totalMicros"].as_u64() {
                                ui.label(format!(
                                    "Period gross usage: ${:.2}",
                                    cost as f64 / 1_000_000.0
                                ));
                            }
                            if let Some(max) = account["effectiveMaxMachines"].as_u64() {
                                ui.label(format!("{max} machine limit"));
                            }
                            if let Some(max) = account["effectiveMaxCpus"].as_u64() {
                                ui.label(format!("{max} CPU limit"));
                            }
                            if let Some(max) = account["effectiveMaxMemoryMb"].as_u64() {
                                ui.label(format!("{max} MB memory limit"));
                            }
                        });
                    }
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
            .default_size(258.0)
            .min_size(224.0)
            .max_size(380.0)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text("Search cloud machines…")
                        .desired_width(f32::INFINITY)
                        .margin(egui::Margin::symmetric(10, 9)),
                );
                ui.add_space(14.0);
                design::eyebrow(
                    ui,
                    &format!("MACHINES  /  {}", self.snapshot.machines.len()),
                );
                ui.add_space(8.0);
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
                if rows.is_empty() && self.valid {
                    ui.label(RichText::new("No matching machines.").color(MUTED));
                }
                egui::ScrollArea::vertical()
                    .id_salt("cloud-machines")
                    .show_rows(ui, 60.0, rows.len(), |ui, range| {
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
                                self.output.clear();
                            }
                        }
                    });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(24))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("cloud-detail")
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
                                ui.heading("Your cloud workspace");
                                ui.label(
                                    RichText::new(
                                        "Select a machine to see its resources and activity.",
                                    )
                                    .color(MUTED),
                                );
                            });
                            return;
                        };
                        ui.add(
                            egui::Label::new(design::heading(machine.display_name(), 24.0))
                                .truncate(),
                        )
                        .on_hover_text(machine.display_name());
                        if let Some(source) = &machine.source {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(
                                        source.reference.as_deref().unwrap_or(&source.source_type),
                                    )
                                    .small()
                                    .color(MUTED),
                                )
                                .truncate(),
                            );
                        }
                        ui.add_space(12.0);
                        design::badge(
                            ui,
                            if machine.is_started() && !machine.is_ready() {
                                "starting"
                            } else {
                                &machine.state
                            },
                        );
                        ui.add_space(18.0);
                        ui.add_enabled_ui(self.valid && !self.pending, |ui| {
                            ui.horizontal_wrapped(|ui| {
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
                                if ui
                                    .add_enabled(
                                        identity.allows("machine:read"),
                                        egui::Button::new("Load logs"),
                                    )
                                    .clicked()
                                {
                                    self.machine(machine.id.clone(), MachineAction::Logs);
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
                        ui.add_space(24.0);
                        if let Some(resources) = &machine.resources {
                            design::eyebrow(ui, "ALLOCATED RESOURCES");
                            ui.add_space(10.0);
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
                            ui.add_space(24.0);
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
                    });
            });
        self.dialogs(&ctx);
    }
    fn dialogs(&mut self, ctx: &egui::Context) {
        if let Some(mut draft) = self.create.take() {
            let mut open = true;
            let mut submit = false;
            let mut cancel = false;
            egui::Window::new("Create cloud machine").anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO).default_width(440.0).vscroll(true).max_height((ctx.content_rect().height()-100.0).max(300.0)).open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
                ui.label(format!("Account: {}", self.account_label()));
                ui.label("Cloud resources are billed to this account. The machine is created stopped; start it when ready.");
                ui.label("Name"); ui.text_edit_singleline(&mut draft.name);
                ui.label("Container image (registry reference)"); ui.text_edit_singleline(&mut draft.image);
                ui.horizontal(|ui| { ui.label("CPUs"); ui.add(egui::DragValue::new(&mut draft.cpus).range(1..=64)); ui.label("Memory MB"); ui.add(egui::DragValue::new(&mut draft.memory_mib).range(256..=262144)); });
                ui.checkbox(&mut draft.network, "Allow outbound network access");
                let valid = draft.validate().is_ok() && !draft.image.trim().is_empty() && !draft.image.starts_with(['/', '.']);
                ui.horizontal(|ui| { submit = ui.add_enabled(valid && self.valid && !self.pending, design::primary("Create in this account")).clicked(); cancel = ui.button("Cancel").clicked(); });
            });
            if submit {
                self.send(Action::Create {
                    tenant: self.tenant.clone(),
                    request: Box::new(CreateMachine {
                        name: Some(draft.name),
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
                        ..Default::default()
                    }),
                });
            } else if open && !cancel {
                self.create = Some(draft);
            }
        }
        if let Some((id, name)) = self.delete.clone() {
            let mut open = true;
            egui::Window::new("Delete cloud machine?")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(format!("Permanently delete {name} ({id}) and its disks?"));
                    ui.label(format!("Account: {}", self.account_label()));
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                self.valid && !self.pending,
                                egui::Button::new("Delete permanently"),
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
            if !open {
                self.delete = None;
            }
        }
    }
}
