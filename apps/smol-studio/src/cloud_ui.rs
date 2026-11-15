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
                        self.selected = None;
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
        egui::CentralPanel::default().frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(24)).show(ui, |ui| {
            if self.create.is_some() || self.delete.is_some() { ui.disable(); }
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(12.0);
                ui.heading("Smol Cloud");
                ui.label("Your account, organizations and machines.");
                if let Some(error) = &self.error { ui.colored_label(Color32::DARK_RED, error); }
                if self.pending { ui.horizontal(|ui| { ui.spinner(); ui.label("Connecting to Smol Cloud…"); }); }
                if let Some((code, url, expires)) = self.device.clone() {
                    ui.separator();
                    ui.heading("Finish signing in in your browser");
                    ui.horizontal(|ui| { ui.label(RichText::new(&code).monospace().size(26.0)); if ui.button("Copy code").clicked() { ctx.copy_text(code); } });
                    ui.hyperlink_to("Open sign-in page", url);
                    ui.label(format!("Expires in {} seconds", expires.saturating_duration_since(Instant::now()).as_secs()));
                    if ui.button("Cancel sign-in").clicked() { self.send(Action::CancelLogin); }
                    return;
                }
                if self.snapshot.identity.is_none() {
                    ui.add_space(30.0);
                    ui.heading("Bring your cloud into Studio");
                    ui.label("Sign in with your Smol account to create and manage machines across your organizations.");
                    ui.add_space(12.0);
                    ui.add_enabled_ui(!self.pending, |ui| {
                        if ui.button("Sign in with Smol").clicked() { self.tenant = None; self.send(Action::Login); }
                        if ui.button("Restore saved Studio sign-in").clicked() { self.tenant = None; self.send(Action::Restore); }
                        if ui.button("Use existing smol CLI sign-in").clicked() { self.tenant = None; self.send(Action::UseCli); }
                        if ui.button("Forget saved Studio sign-in").clicked() { self.send(Action::Logout); }
                    });
                    return;
                }
                let identity = self.snapshot.identity.as_ref().unwrap().clone();
                ui.add_space(12.0);
                ui.add_enabled_ui(!self.pending, |ui| {
                    ui.horizontal(|ui| {
                        let mut next = self.tenant.clone();
                        egui::ComboBox::from_id_salt("cloud-account").width(260.0).selected_text(identity.label()).show_ui(ui, |ui| {
                            ui.selectable_value(&mut next, None, "Personal account");
                            for membership in &self.snapshot.memberships {
                                ui.selectable_value(&mut next, Some(membership.tenant_id.clone()), format!("{} · {} · {}", membership.label(), membership.role, membership.status));
                            }
                        });
                        if next != self.tenant {
                            self.tenant = next; self.valid = false; self.snapshot.machines.clear(); self.snapshot.account = None;
                            self.selected = None; self.output.clear(); self.create = None; self.delete = None; self.refresh();
                        }
                        if ui.button("Refresh").clicked() { self.refresh(); }
                        if ui.button("Sign out").clicked() { self.send(Action::Logout); }
                    });
                });
                ui.label(format!("Account: {}  ·  {}", identity.tenant_id.as_deref().unwrap_or("Not provisioned"), identity.tenant_status.as_deref().unwrap_or("Unknown status")));
                if let Some(namespace) = &identity.registry_namespace { ui.label(format!("Registry: registry.smolmachines.com/{namespace}")); }
                if !self.valid { ui.label("Refresh this account before managing its machines."); }
                if let Some(account) = &self.snapshot.account {
                    ui.horizontal_wrapped(|ui| {
                        if let Some(plan) = account["plan"]["name"].as_str() { ui.label(format!("Plan: {plan}")); }
                        if let Some(cost) = account["periodCost"]["totalMicros"].as_u64() { ui.label(format!("Period gross usage: ${:.2}", cost as f64 / 1_000_000.0)); }
                        if let Some(max) = account["effectiveMaxMachines"].as_u64() { ui.label(format!("Machine limit: {max}")); }
                        if let Some(max) = account["effectiveMaxCpus"].as_u64() { ui.label(format!("CPU limit: {max}")); }
                        if let Some(max) = account["effectiveMaxMemoryMb"].as_u64() { ui.label(format!("Memory limit: {max} MB")); }
                    });
                }
                for warning in &self.snapshot.warnings { ui.label(RichText::new(warning).small().color(Color32::DARK_RED)); }
                ui.separator();
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.query).hint_text("Search cloud machines"));
                    if ui.add_enabled(self.valid && !self.pending && identity.allows("machine:create"), egui::Button::new("+ New cloud machine")).clicked() {
                        self.create = Some(NewMachine { image: "alpine:latest".into(), ..Default::default() });
                    }
                });
                let query = self.query.to_lowercase();
                let rows: Vec<_> = self.snapshot.machines.iter().enumerate().filter(|(_, m)| m.display_name().to_lowercase().contains(&query) || m.id.contains(&query)).map(|(i, _)| i).collect();
                if rows.is_empty() && self.valid { ui.label("No machines in this account match your search."); }
                egui::ScrollArea::vertical().id_salt("cloud-machines").max_height(220.0).show_rows(ui, 34.0, rows.len(), |ui, range| {
                    for &index in &rows[range] {
                        let m = &self.snapshot.machines[index];
                        let state = if m.is_started() && !m.is_ready() { "Starting (agent not ready)" } else { &m.state };
                        if ui.selectable_label(Some(&m.id) == self.selected.as_ref(), format!("{}   ·   {state}   ·   {}", m.display_name(), m.id)).clicked() { self.selected = Some(m.id.clone()); self.output.clear(); }
                    }
                });
                if let Some(machine) = self.snapshot.machines.iter().find(|m| Some(&m.id) == self.selected.as_ref()).cloned() {
                    ui.separator();
                    ui.heading(machine.display_name());
                    if let Some(source) = &machine.source { ui.label(source.reference.as_deref().unwrap_or(&source.source_type)); }
                    if let Some(resources) = &machine.resources { ui.label(format!("Limits: {} CPUs · {} MB memory · {} GB disk", resources.cpus.unwrap_or(0), resources.memory_mb.unwrap_or(0), resources.disk_gb.unwrap_or(0))); }
                    ui.add_enabled_ui(self.valid && !self.pending, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            if matches!(machine.state.as_str(), "created" | "stopped" | "error") && ui.add_enabled(identity.allows("machine:create"), egui::Button::new("Start")).clicked() { self.machine(machine.id.clone(), MachineAction::Start); }
                            if machine.is_started() && ui.add_enabled(identity.allows("machine:create"), egui::Button::new("Stop")).clicked() { self.machine(machine.id.clone(), MachineAction::Stop); }
                            if machine.state == "paused" && ui.add_enabled(identity.allows("machine:create"), egui::Button::new("Resume")).clicked() { self.machine(machine.id.clone(), MachineAction::Resume); }
                            if ui.add_enabled(identity.allows("machine:read"), egui::Button::new("Load logs")).clicked() { self.machine(machine.id.clone(), MachineAction::Logs); }
                            if !machine.is_started() && ui.add_enabled(identity.allows("machine:delete"), egui::Button::new("Delete…")).clicked() { self.delete = Some((machine.id.clone(), machine.display_name().into())); }
                        });
                        ui.add_space(8.0);
                        ui.label("Run a shell command in this machine (60 second limit)");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.command).desired_width(440.0).hint_text("uname -a"));
                            if ui.add_enabled(machine.is_ready() && identity.allows("machine:exec") && !self.command.trim().is_empty(), egui::Button::new("Run")).clicked() {
                                self.output.clear(); self.machine(machine.id.clone(), MachineAction::Exec(self.command.clone()));
                            }
                        });
                    });
                    if !self.output.is_empty() {
                        ui.horizontal(|ui| { ui.label("Output"); if ui.button("Copy output").clicked() { ctx.copy_text(self.output.clone()); } });
                        egui::ScrollArea::both().id_salt("cloud-output").max_height(280.0).show(ui, |ui| { ui.add(egui::TextEdit::multiline(&mut self.output.as_str()).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)); });
                    }
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
            egui::Window::new("Create cloud machine").open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
                ui.label(format!("Account: {}", self.snapshot.identity.as_ref().map(|i| i.label()).unwrap_or("Unknown")));
                ui.label("Cloud resources are billed to this account. The machine is created stopped; start it when ready.");
                ui.label("Name"); ui.text_edit_singleline(&mut draft.name);
                ui.label("Container image (registry reference)"); ui.text_edit_singleline(&mut draft.image);
                ui.horizontal(|ui| { ui.label("CPUs"); ui.add(egui::DragValue::new(&mut draft.cpus).range(1..=64)); ui.label("Memory MB"); ui.add(egui::DragValue::new(&mut draft.memory_mib).range(256..=262144)); });
                ui.checkbox(&mut draft.network, "Allow outbound network access");
                let valid = draft.validate().is_ok() && !draft.image.trim().is_empty() && !draft.image.starts_with(['/', '.']);
                ui.horizontal(|ui| { submit = ui.add_enabled(valid && self.valid && !self.pending, egui::Button::new("Create in this account")).clicked(); cancel = ui.button("Cancel").clicked(); });
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
                    ui.label(format!(
                        "Account: {}",
                        self.snapshot
                            .identity
                            .as_ref()
                            .map(|i| i.label())
                            .unwrap_or("Unknown")
                    ));
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
