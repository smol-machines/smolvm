use eframe::egui::{self, Color32, Margin, RichText, Vec2};
use smol_studio::{
    model::{Machine, NewMachine, Operation, PublishedPort, SharedFolder},
    runtime::{Payload, Runtime, Worker},
    schedule::{REFRESH_INTERVAL, RefreshSchedule},
};
use std::time::Instant;

use crate::design::{self, ACCENT, GREEN, Icon, MUTED, SURFACE, eyebrow, theme};

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
    brand: egui::TextureHandle,
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
            brand: design::brand_texture(&cc.egui_ctx),
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
            activity: "Connecting to Smol…".into(),
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
                    if self.activity == "Connecting to Smol…" {
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
            .default_size(184.0)
            .frame(egui::Frame::new().fill(SURFACE).inner_margin(14))
            .show(ui, |ui| {
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new((self.brand.id(), Vec2::splat(36.0))));
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        ui.label(design::heading("smol machines", 14.0));
                        ui.label(RichText::new("STUDIO").size(9.0).color(MUTED));
                    });
                });
                ui.add_space(32.0);
                eyebrow(ui, "WORKSPACE");
                ui.add_space(8.0);
                for (workspace, icon, label) in [
                    (Workspace::Local, Icon::Machine, "Local machines"),
                    (Workspace::Cloud, Icon::Cloud, "Cloud"),
                    (Workspace::Containers, Icon::Containers, "Containers"),
                ] {
                    if design::nav(ui, self.workspace == workspace, icon, label).clicked() {
                        self.workspace = workspace;
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Smol Studio  /  Preview")
                            .size(10.0)
                            .color(MUTED),
                    );
                    ui.add_space(12.0);
                    if design::nav(ui, self.settings, Icon::Settings, "Settings").clicked() {
                        self.settings = true;
                    }
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(6.0), egui::Sense::hover());
                        ui.painter().circle_filled(
                            r.center(),
                            3.0,
                            if self.inventory_valid { GREEN } else { MUTED },
                        );
                        ui.label(
                            RichText::new(if self.inventory_valid {
                                "Smol connected"
                            } else {
                                "Connecting to Smol"
                            })
                            .size(12.0)
                            .color(MUTED),
                        );
                    });
                });
            });
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                design::section_title(
                    ui,
                    "Local machines",
                    "Your development environments, on this computer.",
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(
                        self.inventory_valid && self.pending.is_none(),
                        design::primary("+  New machine"),
                    )
                    .clicked()
                {
                    self.create = Some(NewMachine::default());
                }
                if ui
                    .add_enabled(self.pending.is_none(), egui::Button::new("Refresh"))
                    .clicked()
                {
                    self.submit(Operation::Refresh);
                }
            });
        });
        if let Some(error) = self.error.clone() {
            ui.add_space(12.0);
            design::error_notice(ui, "Smol couldn’t complete this request.", &error);
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
                    ui.heading("Connect to Smol");
                    ui.label("Choose your Smol CLI in Settings, then refresh.");
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
        egui::ScrollArea::vertical()
            .id_salt("machine_inventory")
            .show_rows(ui, 64.0, visible.len(), |ui, range| {
                for index in range {
                    let m = &self.machines[visible[index]];
                    let selected = self.selected.as_ref() == Some(&m.name);
                    if design::machine_row(ui, selected, &m.name, m.image_label(), &m.state)
                        .clicked()
                    {
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
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(Vec2::splat(44.0), egui::Sense::hover());
            ui.painter().rect_filled(r, 0, design::SELECTED);
            design::icon(ui.painter(), r.shrink(11.0), Icon::Machine, ACCENT);
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.add(egui::Label::new(design::heading(&m.name, 24.0)).truncate())
                    .on_hover_text(&m.name);
                ui.add(
                    egui::Label::new(RichText::new(m.image_label()).size(12.0).color(MUTED))
                        .truncate(),
                )
                .on_hover_text(m.image_label());
            });
        });
        ui.add_space(18.0);
        let enabled = self.pending.is_none() && self.inventory_valid;
        ui.horizontal_wrapped(|ui| {
            design::badge(ui, &m.state);
            if m.can_start()
                && ui
                    .add_enabled(enabled, design::primary("Start machine"))
                    .clicked()
            {
                self.submit(Operation::Start(m.name.clone()));
            }
            if m.state == "paused"
                && ui
                    .add_enabled(enabled, design::primary("Resume machine"))
                    .clicked()
            {
                self.submit(Operation::Resume(m.name.clone()));
            }
            if m.state == "running"
                && ui
                    .add_enabled(enabled, design::primary("Open terminal"))
                    .clicked()
            {
                self.terminal = Some(crate::terminal_ui::TerminalWindow::new(
                    ui.ctx(),
                    self.runtime.clone(),
                    m.name.clone(),
                ));
            }
            if m.can_stop() && ui.add_enabled(enabled, egui::Button::new("Stop")).clicked() {
                self.submit(Operation::Stop(m.name.clone()));
            }
            ui.add_enabled_ui(enabled, |ui| {
                ui.menu_button("More", |ui| {
                    if m.state == "running" && ui.button("Pause to disk").clicked() {
                        self.submit(Operation::Pause(m.name.clone()));
                        ui.close();
                    }
                    if ui.button("Copy machine name").clicked() {
                        ui.ctx().copy_text(m.name.clone());
                        ui.close();
                    }
                    if m.can_delete() {
                        ui.separator();
                        if ui
                            .button(RichText::new("Delete machine…").color(design::RED))
                            .clicked()
                        {
                            self.delete = Some(m.name.clone());
                            ui.close();
                        }
                    }
                });
            });
        });
        if m.state == "frozen" {
            ui.label("This machine is a branch source for its children.");
        }
        if let Some(reason) = &m.state_reason {
            ui.add_space(8.0);
            design::notice(ui, reason);
        }
        ui.add_space(20.0);
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
                eyebrow(ui, "ALLOCATED RESOURCES");
                ui.add_space(10.0);
                ui.columns(2, |columns| {
                    design::metric(
                        &mut columns[0],
                        "CPU limit",
                        &m.cpus.to_string(),
                        if m.cpus == 1 { "core" } else { "cores" },
                    );
                    let memory = design::memory(m.memory_mib);
                    let (value, unit) = memory.split_once(' ').unwrap_or((&memory, ""));
                    design::metric(&mut columns[1], "Memory limit", value, unit);
                });
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Configured limits · live usage is available in Console")
                        .size(11.0)
                        .color(MUTED),
                );
                ui.add_space(18.0);
                eyebrow(ui, "CONFIGURATION");
                ui.add_space(10.0);
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new("machine_resources")
                        .num_columns(2)
                        .min_row_height(18.0)
                        .spacing([28.0, 12.0])
                        .show(ui, |ui| {
                            field(ui, "Shared folders", &m.mounts.to_string());
                            field(ui, "Published ports", &m.ports.to_string());
                            if let Some(pid) = m.pid {
                                field(ui, "Process ID", &pid.to_string());
                            }
                            if let Some(parent) = &m.parent_machine {
                                field(ui, "Branched from", parent);
                            }
                        });
                });
                ui.add_space(14.0);
                ui.horizontal_wrapped(|ui| {
                    design::icon(
                        ui.painter(),
                        egui::Rect::from_min_size(ui.cursor().min, Vec2::splat(16.0)),
                        Icon::Terminal,
                        MUTED,
                    );
                    ui.add_space(22.0);
                    ui.label(
                        RichText::new("Also available in your terminal")
                            .small()
                            .color(MUTED),
                    );
                });
                let command = format!("smol machine exec --local --name {} -it -- /bin/sh", m.name);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(&command).monospace().size(11.0).color(MUTED),
                        )
                        .truncate(),
                    )
                    .on_hover_text(&command);
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(command);
                    }
                });
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
                .vscroll(true)
                .max_height((ctx.content_rect().height() - 100.0).max(300.0))
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
                                design::primary("Create machine"),
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
                    if ui.add_enabled(allowed, egui::Button::new(RichText::new("Delete machine").color(Color32::WHITE)).fill(design::RED)).clicked() {
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
                ui.label("Smol CLI executable");
                ui.add(egui::TextEdit::singleline(&mut self.runtime_path).desired_width(f32::INFINITY));
                ui.label(RichText::new("Studio uses the Smol CLI bundled with the app or installed on your computer. The selected path is saved for your next launch.").small().color(MUTED));
                if let Some(path) = &self.runtime.state_dir {
                    ui.label(format!("State directory: {}", path.display()));
                }
                ui.add_space(16.0);
                if ui.add_enabled(self.pending.is_none() && !self.runtime_path.trim().is_empty(), egui::Button::new("Connect")).clicked() {
                    let mut preferences = match smol_studio::preferences::Preferences::load() { Ok(p) => p, Err(e) => { self.error = Some(e); return; } };
                    preferences.smol_cli = Some(self.runtime_path.trim().into());
                    if let Err(e) = preferences.save() { self.error = Some(e); return; }
                    self.runtime.executable = self.runtime_path.trim().into();
                    self.inventory_valid = false;
                    self.machines.clear(); self.selected = None; self.logs = None; self.error = None;
                    self.activity = "Connecting to Smol…".into();
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
        self.docker.terminal_ui(&ctx);
        if let Some(terminal) = &mut self.terminal
            && !terminal.ui(&ctx)
        {
            self.terminal = None;
        }
        if self.create.is_some()
            || self.delete.is_some()
            || self.settings
            || self.cloud.modal_open()
            || self.docker.modal_open()
        {
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
                    let label = match self.workspace {
                        Workspace::Cloud => "Smol Cloud".to_string(),
                        Workspace::Containers => "Docker context: smol".to_string(),
                        Workspace::Local => self
                            .pending
                            .as_ref()
                            .map(Operation::label)
                            .unwrap_or_else(|| self.activity.clone()),
                    };
                    if self.workspace == Workspace::Local && self.pending.is_some() {
                        ui.spinner();
                    }
                    ui.label(RichText::new(label).size(11.0).color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new("Machines keep running when you close Studio")
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                });
            });
        self.sidebar(ui);
        match self.workspace {
            Workspace::Cloud => self.cloud.ui(ui),
            Workspace::Containers => self.docker.ui(ui, &self.runtime),
            Workspace::Local => {
                egui::Panel::top("local-heading")
                    .resizable(false)
                    .frame(
                        egui::Frame::new()
                            .fill(Color32::WHITE)
                            .inner_margin(Margin::symmetric(24, 20)),
                    )
                    .show(ui, |ui| self.header(ui));
                egui::Panel::left("local-list")
                    .resizable(true)
                    .default_size(278.0)
                    .min_size(240.0)
                    .max_size(380.0)
                    .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.query)
                                .hint_text("Search machines…")
                                .desired_width(f32::INFINITY)
                                .margin(egui::Margin::symmetric(10, 9)),
                        );
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut self.filter, Filter::All, "All");
                            ui.selectable_value(&mut self.filter, Filter::Running, "Running");
                            ui.selectable_value(&mut self.filter, Filter::Stopped, "Stopped");
                        });
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            eyebrow(ui, "MACHINES");
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(self.machines.len().to_string())
                                            .small()
                                            .color(MUTED),
                                    );
                                },
                            );
                        });
                        ui.add_space(6.0);
                        self.machine_list(ui);
                    });
                egui::CentralPanel::default().frame(egui::Frame::new().fill(SURFACE).inner_margin(28)).show(ui, |ui| {
                    if self.selected.is_some() {
                        egui::ScrollArea::vertical().id_salt("machine-detail").show(ui, |ui| self.details(ui));
                    } else {
                        ui.add_space(100.0);
                        ui.vertical_centered(|ui| {
                            ui.heading("Your next environment starts here");
                            ui.label(RichText::new("Select a machine to see its resources, logs, and terminal.").color(MUTED));
                        });
                    }
                });
            }
        }
        self.dialogs(&ctx);
    }
}

fn field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).color(MUTED));
    ui.label(value);
    ui.end_row();
}
