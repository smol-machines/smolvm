use eframe::egui::{self, Color32, FontId, Margin, RichText, Stroke, Vec2};
use smol_studio::{
    model::{Machine, NewMachine, Operation, PublishedPort, SharedFolder},
    runtime::{Payload, Runtime, Worker},
    schedule::{REFRESH_INTERVAL, RefreshSchedule},
};
use std::time::Instant;

const INK: Color32 = Color32::from_rgb(35, 39, 48);
const MUTED: Color32 = Color32::from_rgb(108, 114, 126);
const ACCENT: Color32 = Color32::from_rgb(104, 79, 218);
const LINE: Color32 = Color32::from_rgb(226, 228, 235);
const SURFACE: Color32 = Color32::from_rgb(248, 249, 252);
const GREEN: Color32 = Color32::from_rgb(33, 134, 96);

#[derive(Clone, Copy, PartialEq)]
enum Filter {
    All,
    Running,
    Stopped,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    Logs,
    Console,
}

#[derive(Clone, Copy, PartialEq)]
enum Workspace {
    Local,
    Cloud,
    Containers,
}

pub struct Studio {
    cloud: crate::cloud_ui::CloudView,
    workspace: Workspace,
    terminal: Option<crate::terminal_ui::TerminalWindow>,
    docker: crate::docker_ui::DockerView,
    runtime: Runtime,
    worker: Worker,
    machines: Vec<Machine>,
    selected: Option<String>,
    filter: Filter,
    query: String,
    tab: Tab,
    logs: Option<(String, String)>,
    pending: Option<Operation>,
    schedule: RefreshSchedule,
    last_refresh: Option<Instant>,
    inventory_valid: bool,
    error: Option<String>,
    refresh_error: bool,
    activity: String,
    create: Option<NewMachine>,
    delete: Option<String>,
    settings: bool,
    runtime_path: String,
    command: String,
    output: Option<(String, String)>,
}

impl Studio {
    pub fn new(cc: &eframe::CreationContext<'_>, runtime: Runtime) -> Self {
        let ctx = cc.egui_ctx.clone();
        theme(&ctx);
        let worker = Worker::new(move || ctx.request_repaint());
        let runtime_path = runtime.executable.to_string_lossy().into_owned();
        let mut app = Self {
            cloud: crate::cloud_ui::CloudView::new(&cc.egui_ctx),
            workspace: Workspace::Local,
            terminal: None,
            docker: crate::docker_ui::DockerView::new(&cc.egui_ctx),
            runtime,
            worker,
            machines: Vec::new(),
            selected: None,
            filter: Filter::All,
            query: String::new(),
            tab: Tab::Overview,
            logs: None,
            pending: None,
            schedule: RefreshSchedule::default(),
            last_refresh: None,
            inventory_valid: false,
            error: None,
            refresh_error: false,
            activity: "Connecting to SmolVM…".into(),
            create: None,
            delete: None,
            settings: false,
            runtime_path,
            command: String::new(),
            output: None,
        };
        app.cloud.restore();
        app.submit(Operation::Refresh);
        app
    }

    fn submit(&mut self, op: Operation) {
        if self.pending.is_some() {
            return;
        }
        match self.worker.submit(self.runtime.clone(), op.clone()) {
            Ok(()) => {
                self.pending = Some(op);
            }
            Err(e) => {
                self.error = Some(e);
            }
        }
    }

    fn receive(&mut self) {
        while let Ok(done) = self.worker.responses.try_recv() {
            self.pending = None;
            let mutation = done.operation.is_mutation();
            if matches!(done.operation, Operation::Refresh) {
                self.schedule.completed(Instant::now());
            }
            match done.result {
                Ok(Payload::Machines(machines)) => {
                    if self.refresh_error {
                        self.error = None;
                        self.refresh_error = false;
                    }
                    self.machines = machines;
                    self.inventory_valid = true;
                    self.last_refresh = Some(Instant::now());
                    if !self
                        .machines
                        .iter()
                        .any(|m| Some(&m.name) == self.selected.as_ref())
                    {
                        self.selected = self.machines.first().map(|m| m.name.clone());
                        self.logs = None;
                        self.tab = Tab::Overview;
                    }
                    if self.activity == "Connecting to SmolVM…" {
                        self.activity = "Ready".into();
                    }
                }
                Ok(Payload::Logs { name, text }) => {
                    self.logs = Some((name, text));
                }
                Ok(Payload::Output { name, text }) => {
                    self.output = Some((name, text));
                }
                Ok(Payload::Completed) => {
                    self.error = None;
                    self.activity = format!(
                        "{} completed in {:.1}s",
                        done.operation.label(),
                        done.elapsed.as_secs_f64()
                    );
                    if let Operation::Create(m) = done.operation {
                        self.selected = Some(m.name);
                        self.tab = Tab::Overview;
                        self.logs = None;
                        self.query.clear();
                        self.filter = Filter::All;
                    }
                }
                Err(e) => {
                    self.refresh_error = matches!(done.operation, Operation::Refresh);
                    if matches!(done.operation, Operation::Refresh) {
                        self.inventory_valid = false;
                    }
                    self.error = Some(e);
                }
            }
            if mutation {
                self.submit(Operation::Refresh);
            }
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(210.0)
            .frame(egui::Frame::new().fill(SURFACE).inner_margin(20))
            .show(ui, |ui| {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 8, ACCENT);
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "s",
                        FontId::proportional(25.0),
                        Color32::WHITE,
                    );
                    ui.label(RichText::new("smol studio").size(21.0).strong());
                });
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Local power. Cloud reach.")
                        .color(MUTED)
                        .size(12.0),
                );
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.workspace, Workspace::Local, "Local");
                    ui.selectable_value(&mut self.workspace, Workspace::Cloud, "Cloud");
                });
                ui.selectable_value(
                    &mut self.workspace,
                    Workspace::Containers,
                    "Containers & Compose",
                );
                if self.workspace != Workspace::Local {
                    return;
                }
                ui.add_space(18.0);
                let can_create = self.inventory_valid && self.pending.is_none();
                if ui
                    .add_enabled(
                        can_create,
                        egui::Button::new(RichText::new("+  New machine").color(Color32::WHITE))
                            .fill(ACCENT)
                            .min_size([170.0, 36.0].into()),
                    )
                    .clicked()
                {
                    self.create = Some(NewMachine::default());
                }
                ui.add_space(26.0);
                eyebrow(ui, "WORKSPACE");
                ui.add_space(10.0);
                let running = self
                    .machines
                    .iter()
                    .filter(|m| m.state == "running")
                    .count();
                for (filter, label, count) in [
                    (Filter::All, "All machines", self.machines.len()),
                    (Filter::Running, "Running", running),
                    (
                        Filter::Stopped,
                        "Stopped",
                        self.machines
                            .iter()
                            .filter(|m| matches!(m.state.as_str(), "stopped" | "created"))
                            .count(),
                    ),
                ] {
                    if ui
                        .add_sized(
                            [170.0, 32.0],
                            egui::Button::selectable(
                                self.filter == filter,
                                format!("{label}    {count}"),
                            ),
                        )
                        .clicked()
                    {
                        self.filter = filter;
                    }
                    ui.add_space(4.0);
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(RichText::new("Preview  ·  0.1").small().color(MUTED));
                    ui.add_space(12.0);
                    if ui.button("Settings").clicked() {
                        self.settings = true;
                    }
                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new("Closing Studio leaves your\nmachines running.")
                            .small()
                            .color(MUTED),
                    );
                });
            });
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(RichText::new("Machines").size(27.0));
                ui.label(RichText::new("Linux environments on your computer").color(MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(self.pending.is_none(), egui::Button::new("Refresh"))
                    .clicked()
                {
                    self.submit(Operation::Refresh);
                }
            });
        });
        ui.add_space(18.0);
        ui.add(
            egui::TextEdit::singleline(&mut self.query)
                .hint_text("Search by name or image")
                .desired_width(f32::INFINITY),
        );
        ui.add_space(16.0);
        if let Some(error) = self.error.clone() {
            egui::Frame::new()
                .fill(Color32::from_rgb(255, 241, 238))
                .inner_margin(12)
                .corner_radius(6)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("SmolVM needs attention")
                                    .strong()
                                    .color(Color32::from_rgb(170, 55, 40)),
                            );
                            ui.add(egui::Label::new(error).wrap());
                        });
                        if ui.small_button("Dismiss").clicked() {
                            self.error = None;
                        }
                    });
                });
            ui.add_space(12.0);
        }
    }

    fn machine_list(&mut self, ui: &mut egui::Ui) {
        let query = self.query.to_lowercase();
        let visible: Vec<usize> = self
            .machines
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                (self.filter == Filter::All
                    || (self.filter == Filter::Running && m.state == "running")
                    || (self.filter == Filter::Stopped
                        && matches!(m.state.as_str(), "stopped" | "created")))
                    && (m.name.to_lowercase().contains(&query)
                        || m.image_label().to_lowercase().contains(&query))
            })
            .map(|(i, _)| i)
            .collect();
        if visible.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                if !self.inventory_valid {
                    ui.heading("Connect to SmolVM");
                    ui.label("Choose your installed runtime in Settings, then refresh.");
                    if ui.button("Open settings").clicked() {
                        self.settings = true;
                    }
                } else if self.machines.is_empty() {
                    ui.heading("A place for your next project");
                    ui.label("Create a Linux machine, then start it when you need it.");
                    ui.add_space(12.0);
                    if ui
                        .add_enabled(
                            self.pending.is_none(),
                            egui::Button::new("Create your first machine"),
                        )
                        .clicked()
                    {
                        self.create = Some(NewMachine::default());
                    }
                } else {
                    ui.heading("No matching machines");
                    ui.label("Try another search or choose All machines.");
                }
            });
            return;
        }
        // Only lay out visible rows, even for large machine inventories.
        egui::ScrollArea::vertical()
            .id_salt("machine_inventory")
            .show_rows(ui, 66.0, visible.len(), |ui, range| {
                for index in range {
                    let m = &self.machines[visible[index]];
                    let selected = self.selected.as_ref() == Some(&m.name);
                    let text = format!("{}\n{}", m.name, m.image_label());
                    let response = ui.add_sized(
                        [ui.available_width(), 62.0],
                        egui::Button::selectable(selected, RichText::new(text).size(14.0)).wrap(),
                    );
                    let color = state_color(&m.state);
                    let pos = response.rect.right_top() + egui::vec2(-12.0, 12.0);
                    ui.painter().circle_filled(pos, 3.5, color);
                    response.clone().on_hover_text(format!(
                        "{} · {} CPUs · {} MiB limit",
                        m.state, m.cpus, m.memory_mib
                    ));
                    if response.clicked() {
                        self.selected = Some(m.name.clone());
                        self.tab = Tab::Overview;
                        self.logs = None;
                    }
                }
            });
    }

    fn details(&mut self, ui: &mut egui::Ui) {
        let Some(m) = self
            .machines
            .iter()
            .find(|m| Some(&m.name) == self.selected.as_ref())
            .cloned()
        else {
            return;
        };
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(&m.state)
                    .color(state_color(&m.state))
                    .strong(),
            );
            if !self.inventory_valid {
                ui.label(RichText::new("Last known state").small().color(MUTED));
            }
        });
        ui.add_space(8.0);
        ui.heading(&m.name);
        ui.add(egui::Label::new(RichText::new(m.image_label()).color(MUTED)).wrap());
        ui.add_space(20.0);
        let enabled = self.pending.is_none() && self.inventory_valid;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(enabled && m.can_start(), egui::Button::new("Start"))
                .clicked()
            {
                self.submit(Operation::Start(m.name.clone()));
            }
            if ui
                .add_enabled(enabled && m.can_stop(), egui::Button::new("Stop"))
                .clicked()
            {
                self.submit(Operation::Stop(m.name.clone()));
            }
            if ui
                .add_enabled(enabled && m.can_delete(), egui::Button::new("Delete…"))
                .clicked()
            {
                self.delete = Some(m.name.clone());
            }
        });
        if m.state == "paused" {
            ui.add_space(8.0);
            if ui
                .add_enabled(enabled, egui::Button::new("Resume"))
                .clicked()
            {
                self.submit(Operation::Resume(m.name.clone()));
            }
        } else if m.state == "running" {
            if ui
                .add_enabled(enabled, egui::Button::new("Pause to disk"))
                .clicked()
            {
                self.submit(Operation::Pause(m.name.clone()));
            }
        } else if m.state == "frozen" {
            ui.label("This machine is a branch source and must remain available to its children.");
        }
        if let Some(reason) = &m.state_reason {
            ui.label(reason);
        }
        if ui
            .add_enabled(
                enabled && m.state == "running",
                egui::Button::new("Open terminal"),
            )
            .clicked()
        {
            self.terminal = Some(crate::terminal_ui::TerminalWindow::new(
                ui.ctx(),
                self.runtime.clone(),
                m.name.clone(),
            ));
        }
        ui.add_space(24.0);
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Overview, "Overview");
            ui.selectable_value(&mut self.tab, Tab::Console, "Console");
            if ui
                .selectable_value(&mut self.tab, Tab::Logs, "Logs")
                .clicked()
                && enabled
            {
                self.submit(Operation::Logs(m.name.clone()));
            }
        });
        ui.separator();
        ui.add_space(16.0);
        match self.tab {
            Tab::Console => {
                ui.label("Run a shell command (60 second limit)");
                ui.add(
                    egui::TextEdit::multiline(&mut self.command)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY)
                        .hint_text("uname -a"),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            enabled && m.state == "running" && !self.command.trim().is_empty(),
                            egui::Button::new("Run"),
                        )
                        .clicked()
                    {
                        self.output = None;
                        self.submit(Operation::Exec {
                            name: m.name.clone(),
                            command: self.command.clone(),
                        });
                    }
                    if ui
                        .add_enabled(
                            enabled && m.state == "running",
                            egui::Button::new("Usage snapshot"),
                        )
                        .clicked()
                    {
                        self.submit(Operation::Stats(m.name.clone()));
                    }
                });
                if let Some((_, text)) = self.output.as_ref().filter(|(name, _)| name == &m.name) {
                    if ui.button("Copy output").clicked() {
                        ui.ctx().copy_text(text.clone());
                    }
                    egui::ScrollArea::both()
                        .id_salt(("console", &m.name))
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(text).monospace()).selectable(true),
                            );
                        });
                }
            }
            Tab::Overview => {
                eyebrow(ui, "RESOURCE LIMITS");
                ui.add_space(12.0);
                egui::Grid::new("machine_resources")
                    .spacing([28.0, 14.0])
                    .show(ui, |ui| {
                        field(ui, "CPUs", &m.cpus.to_string());
                        field(ui, "Memory", &format!("{} MiB", m.memory_mib));
                        field(ui, "Shared folders", &m.mounts.to_string());
                        field(ui, "Published ports", &m.ports.to_string());
                        if let Some(pid) = m.pid {
                            field(ui, "Process", &pid.to_string());
                        }
                        if let Some(parent) = &m.parent_machine {
                            field(ui, "Branched from", parent);
                        }
                    });
                ui.add_space(18.0);
                ui.label(
                    RichText::new("Limits are configured capacity, not current usage.")
                        .small()
                        .color(MUTED),
                );
            }
            Tab::Logs => {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Last 200 lines").small().color(MUTED));
                    if ui
                        .add_enabled(enabled, egui::Button::new("Reload logs"))
                        .clicked()
                    {
                        self.submit(Operation::Logs(m.name.clone()));
                    }
                });
                ui.add_space(10.0);
                let log = self
                    .logs
                    .as_ref()
                    .filter(|(name, _)| name == &m.name)
                    .map(|(_, text)| text.as_str());
                match log {
                    None => {
                        ui.label("Load this machine’s workload output with Reload logs.");
                    }
                    Some("") => {
                        ui.label("No workload output yet.");
                    }
                    Some(text) => {
                        egui::ScrollArea::both()
                            .id_salt(("logs", &m.name))
                            .max_height(ui.available_height())
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(RichText::new(text).monospace().size(12.0))
                                        .selectable(true),
                                );
                            });
                    }
                }
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.create = None;
            self.delete = None;
            self.settings = false;
            return;
        }
        if let Some(mut draft) = self.create.take() {
            let mut open = true;
            let mut submit = false;
            let mut cancel = false;
            egui::Window::new("New machine")
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .collapsible(false)
                .resizable(false)
                .default_width(430.0)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("Create a Linux environment. Start it when you’re ready.");
                    ui.add_space(16.0);
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.name)
                            .hint_text("my-project")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(10.0);
                    ui.label("Container image or local image path");
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.image)
                            .hint_text("Leave empty for bare Linux")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.label("CPUs");
                        ui.add(egui::DragValue::new(&mut draft.cpus).range(1..=64));
                        ui.label("Memory");
                        ui.add(
                            egui::DragValue::new(&mut draft.memory_mib)
                                .range(256..=262_144)
                                .speed(128)
                                .suffix(" MiB"),
                        );
                    });
                    ui.add_space(12.0);
                    ui.checkbox(&mut draft.network, "Allow outbound network access");
                    ui.collapsing("Shared folders", |ui| {
                        let mut remove = None;
                        for (i, folder) in draft.folders.iter_mut().enumerate() {
                            ui.push_id(i, |ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut folder.host)
                                        .hint_text("Absolute host folder path")
                                        .desired_width(f32::INFINITY),
                                );
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut folder.guest)
                                            .hint_text("/workspace")
                                            .desired_width(180.0),
                                    );
                                    ui.checkbox(&mut folder.read_only, "Read only");
                                    if ui.small_button("Remove").clicked() {
                                        remove = Some(i);
                                    }
                                });
                            });
                        }
                        if let Some(i) = remove {
                            draft.folders.remove(i);
                        }
                        if ui.button("Add shared folder").clicked() {
                            draft.folders.push(SharedFolder {
                                host: String::new(),
                                guest: "/workspace".into(),
                                read_only: true,
                            });
                        }
                    });
                    ui.collapsing("Published ports", |ui| {
                        let mut remove = None;
                        for (i, port) in draft.ports.iter_mut().enumerate() {
                            ui.push_id(i, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Host");
                                    ui.add(egui::DragValue::new(&mut port.host).range(1..=65535));
                                    ui.label("Guest");
                                    ui.add(egui::DragValue::new(&mut port.guest).range(1..=65535));
                                    if ui.small_button("Remove").clicked() {
                                        remove = Some(i);
                                    }
                                });
                            });
                        }
                        if let Some(i) = remove {
                            draft.ports.remove(i);
                        }
                        if ui.button("Add port").clicked() {
                            draft.ports.push(PublishedPort {
                                host: 8080,
                                guest: 8080,
                            });
                        }
                        ui.label("Published ports enable networking for this machine.");
                    });
                    ui.add_space(12.0);
                    let validation = draft.validate();
                    let duplicate = self.machines.iter().any(|m| m.name == draft.name);
                    if duplicate {
                        ui.colored_label(
                            Color32::DARK_RED,
                            "A machine with this name already exists.",
                        );
                    } else if !draft.name.is_empty()
                        && let Err(e) = &validation
                    {
                        ui.colored_label(Color32::DARK_RED, e);
                    }
                    ui.horizontal(|ui| {
                        submit = ui
                            .add_enabled(
                                validation.is_ok()
                                    && !duplicate
                                    && self.pending.is_none()
                                    && self.inventory_valid,
                                egui::Button::new("Create machine"),
                            )
                            .clicked();
                        cancel = ui.button("Cancel").clicked();
                    });
                });
            if submit {
                self.submit(Operation::Create(draft));
            } else if open && !cancel {
                self.create = Some(draft);
            }
        }
        if let Some(name) = self.delete.clone() {
            let mut open = true;
            egui::Window::new("Delete machine?").anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).collapsible(false).resizable(false).default_width(420.0).open(&mut open).show(ctx, |ui| {
                ui.label(format!("Delete “{name}” and its machine disks?"));
                ui.label("Data stored inside this machine will be permanently removed. Shared host folders remain on your computer.");
                ui.add_space(16.0);
                let allowed = self.inventory_valid && self.pending.is_none() && self.machines.iter().any(|m| m.name == name && m.can_delete());
                ui.horizontal(|ui| {
                    if ui.add_enabled(allowed, egui::Button::new("Delete machine").fill(Color32::from_rgb(180, 49, 49))).clicked() {
                        self.submit(Operation::Delete(name)); self.delete = None;
                    }
                    if ui.button("Cancel").clicked() { self.delete = None; }
                });
            });
            if !open {
                self.delete = None;
            }
        }
        if self.settings {
            let mut open = true;
            egui::Window::new("Settings").anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).collapsible(false).resizable(false).default_width(500.0).open(&mut open).show(ctx, |ui| {
                ui.label("SmolVM executable");
                ui.add(egui::TextEdit::singleline(&mut self.runtime_path).desired_width(f32::INFINITY));
                ui.label(RichText::new("Studio uses your existing SmolVM installation. The selected path is saved for your next launch.").small().color(MUTED));
                if let Some(path) = &self.runtime.state_dir {
                    ui.label(format!("State directory: {}", path.display()));
                }
                ui.add_space(16.0);
                if ui.add_enabled(self.pending.is_none() && !self.runtime_path.trim().is_empty(), egui::Button::new("Connect")).clicked() {
                    let mut preferences = match smol_studio::preferences::Preferences::load() { Ok(p) => p, Err(e) => { self.error = Some(e); return; } };
                    preferences.runtime = Some(self.runtime_path.trim().into());
                    if let Err(e) = preferences.save() { self.error = Some(e); return; }
                    self.runtime.executable = self.runtime_path.trim().into();
                    self.inventory_valid = false;
                    self.machines.clear(); self.selected = None; self.logs = None; self.error = None;
                    self.activity = "Connecting to SmolVM…".into();
                    self.settings = false;
                    self.submit(Operation::Refresh);
                }
            });
            if !open {
                self.settings = false;
            }
        }
    }
}

impl eframe::App for Studio {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive();
        self.docker.logic(&self.runtime);
        if ctx.input(|i| i.viewport().close_requested())
            && (self.pending.as_ref().is_some_and(Operation::is_mutation)
                || self.cloud.mutating()
                || self.docker.mutating())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.error = Some(
                "A machine operation is still running. Close Studio after it completes.".into(),
            );
        }
        let active = ctx
            .input(|i| i.viewport().focused == Some(true) && i.viewport().minimized != Some(true));
        self.cloud
            .logic(ctx, active && (self.workspace == Workspace::Cloud));
        if self.schedule.due(
            Instant::now(),
            active && (self.workspace == Workspace::Local),
            self.pending.is_some()
                || self.settings
                || self.create.is_some()
                || self.delete.is_some(),
        ) {
            self.submit(Operation::Refresh);
        }
        if active && self.workspace == Workspace::Local {
            ctx.request_repaint_after(REFRESH_INTERVAL);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(terminal) = &mut self.terminal
            && !terminal.ui(&ctx)
        {
            self.terminal = None;
        }
        if self.create.is_some() || self.delete.is_some() || self.settings {
            ui.disable();
        }
        egui::Panel::bottom("status")
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(SURFACE)
                    .inner_margin(Margin::symmetric(16, 9)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let label = if self.workspace == Workspace::Cloud {
                        "Cloud account workspace".to_string()
                    } else {
                        self.pending
                            .as_ref()
                            .map(Operation::label)
                            .unwrap_or_else(|| self.activity.clone())
                    };
                    ui.label(RichText::new(label).size(12.0).color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let text = if self.workspace == Workspace::Cloud {
                            "Smol Cloud"
                        } else if self.inventory_valid {
                            "Local runtime connected"
                        } else {
                            "Runtime unavailable"
                        };
                        ui.label(
                            RichText::new(text)
                                .size(12.0)
                                .color(if self.inventory_valid { GREEN } else { MUTED }),
                        )
                        .on_hover_text(
                            self.last_refresh
                                .map(|t| format!("Updated {} seconds ago", t.elapsed().as_secs()))
                                .unwrap_or_else(|| "No successful refresh yet".into()),
                        );
                    });
                });
            });
        self.sidebar(ui);
        if self.workspace == Workspace::Cloud {
            self.cloud.ui(ui);
            return;
        }
        if self.workspace == Workspace::Containers {
            self.docker.ui(ui, &self.runtime);
            return;
        }
        if self.selected.is_some() {
            egui::Panel::right("details")
                .resizable(true)
                .default_size(340.0)
                .min_size(280.0)
                .max_size(480.0)
                .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(22))
                .show(ui, |ui| self.details(ui));
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(24))
            .show(ui, |ui| {
                self.header(ui);
                self.machine_list(ui);
            });
        self.dialogs(&ctx);
    }
}

fn eyebrow(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(10.0).strong().color(MUTED));
}

fn field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).color(MUTED));
    ui.label(value);
    ui.end_row();
}

fn state_color(state: &str) -> Color32 {
    match state {
        "running" => GREEN,
        "failed" | "unreachable" => Color32::from_rgb(181, 66, 46),
        "paused" | "frozen" | "pausing" => ACCENT,
        _ => MUTED,
    }
}

fn theme(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Light);
    ctx.style_mut_of(egui::Theme::Light, |style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(12.0, 7.0);
        style.visuals.override_text_color = Some(INK);
        style.visuals.panel_fill = Color32::WHITE;
        style.visuals.window_fill = Color32::WHITE;
        style.visuals.selection.bg_fill = Color32::from_rgb(237, 233, 253);
        style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
        style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE);
    });
}
