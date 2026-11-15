use eframe::egui::{self, Color32, Margin, RichText, Vec2};
use smol_studio::{
    model::{Machine, Operation},
    runtime::{Payload, Runtime, Worker},
    schedule::{REFRESH_INTERVAL, RefreshSchedule},
};
use std::time::Instant;

use crate::design::{self, GREEN, Icon, MUTED, SURFACE, theme};

#[derive(Clone, Copy, PartialEq)]
enum Filter {
    All,
    Running,
    Stopped,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    Files,
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
    files: crate::files_ui::FilesView,
    pending: Option<Operation>,
    schedule: RefreshSchedule,
    last_refresh: Option<Instant>,
    inventory_valid: bool,
    error: Option<String>,
    refresh_error: bool,
    activity: String,
    create: Option<crate::new_machine_ui::Editor>,
    editing: Option<crate::machine_settings_ui::Editor>,
    settings_request: Option<String>,
    delete: Option<String>,
    settings: bool,
    settings_error: Option<String>,
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
            files: crate::files_ui::FilesView::default(),
            pending: None,
            schedule: RefreshSchedule::default(),
            last_refresh: None,
            inventory_valid: false,
            error: None,
            refresh_error: false,
            activity: "Connecting to Smol…".into(),
            create: None,
            editing: None,
            settings_request: None,
            delete: None,
            settings: false,
            settings_error: None,
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
                if matches!(op, Operation::Create(_))
                    && let Some(editor) = &mut self.create
                {
                    editor.error = Some(e);
                } else {
                    self.error = Some(e);
                }
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
                Ok(Payload::Files { name, listing }) => {
                    self.files.receive(&name, listing);
                }
                Ok(Payload::Settings(settings)) => {
                    if self.settings_request.as_ref() == Some(&settings.name)
                        && self.selected.as_ref() == Some(&settings.name)
                    {
                        self.editing = Some(crate::machine_settings_ui::Editor::new(*settings));
                    }
                    self.settings_request = None;
                }
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
                    if let Operation::TransferFile {
                        name,
                        local,
                        upload,
                        ..
                    } = &done.operation
                    {
                        self.files.transferred(name, *upload, local);
                    }
                    if matches!(done.operation, Operation::UpdateSettings { .. }) {
                        self.editing = None;
                    }
                    self.error = None;
                    self.activity = format!(
                        "{} completed in {:.1}s",
                        done.operation.label(),
                        done.elapsed.as_secs_f64()
                    );
                    if let Operation::Create(m) = done.operation {
                        self.create = None;
                        self.selected = Some(m.name);
                        self.tab = Tab::Overview;
                        self.logs = None;
                        self.query.clear();
                        self.filter = Filter::All;
                    }
                }
                Err(e) => {
                    let mut shown_in_editor = false;
                    if matches!(done.operation, Operation::Create(_))
                        && let Some(editor) = &mut self.create
                    {
                        editor.error = Some(e.clone());
                        shown_in_editor = true;
                    }
                    if let Operation::ListFiles { name, .. }
                    | Operation::TransferFile { name, .. } = &done.operation
                    {
                        self.files.failed(name, e.clone());
                        shown_in_editor = true;
                    }
                    if matches!(
                        done.operation,
                        Operation::UpdateSettings { .. } | Operation::ReadSettings(_)
                    ) {
                        self.settings_request = None;
                        if let Some(editor) = &mut self.editing {
                            editor.error = Some(e.clone());
                            shown_in_editor = true;
                        }
                    }
                    self.refresh_error = matches!(done.operation, Operation::Refresh);
                    if matches!(done.operation, Operation::Refresh) {
                        self.inventory_valid = false;
                    }
                    self.error = if shown_in_editor { None } else { Some(e) };
                }
            }
            if mutation {
                self.submit(Operation::Refresh);
            }
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        use smol_studio::docker::Kind;
        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(184.0)
            .frame(egui::Frame::new().fill(design::SIDEBAR).inner_margin(12))
            .show(ui, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new((self.brand.id(), Vec2::splat(32.0))));
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(design::heading("smol studio", 15.0));
                        ui.label(RichText::new("by smol machines").size(10.0).color(MUTED));
                    });
                });
                ui.add_space(22.0);
                design::nav_group(ui, "Workspace");
                if design::nav(
                    ui,
                    self.workspace == Workspace::Local,
                    Icon::Machine,
                    "Machines",
                )
                .clicked()
                {
                    self.workspace = Workspace::Local;
                }
                ui.add_enabled_ui(!self.docker.navigating(), |ui| {
                    for (destination, icon, label) in [
                        (Some(Kind::Containers), Icon::Containers, "Containers"),
                        (None, Icon::Project, "Projects"),
                    ] {
                        let selected = self.workspace == Workspace::Containers
                            && self.docker.destination() == destination;
                        if design::nav(ui, selected, icon, label).clicked() && !selected {
                            self.workspace = Workspace::Containers;
                            self.docker.navigate(&self.runtime, destination);
                        }
                    }
                    ui.add_space(18.0);
                    design::nav_group(ui, "Resources");
                    for (kind, icon, label) in [
                        (Kind::Images, Icon::Image, "Images"),
                        (Kind::Volumes, Icon::Volume, "Volumes"),
                        (Kind::Networks, Icon::Network, "Networks"),
                    ] {
                        let selected = self.workspace == Workspace::Containers
                            && self.docker.destination() == Some(kind);
                        if design::nav(ui, selected, icon, label).clicked() && !selected {
                            self.workspace = Workspace::Containers;
                            self.docker.navigate(&self.runtime, Some(kind));
                        }
                    }
                });
                ui.add_space(18.0);
                design::nav_group(ui, "Cloud");
                if design::nav(
                    ui,
                    self.workspace == Workspace::Cloud,
                    Icon::Cloud,
                    "Smol Cloud",
                )
                .clicked()
                {
                    self.workspace = Workspace::Cloud;
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(4.0);
                    if design::nav(ui, self.settings, Icon::Settings, "Settings").clicked() {
                        self.settings = true;
                    }
                    ui.add_space(8.0);
                    ui.separator();
                });
            });
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                design::section_title(
                    ui,
                    "Machines",
                    &if !self.inventory_valid {
                        if self.pending.is_some() {
                            "Connecting to Smol…".into()
                        } else {
                            "Connection unavailable".into()
                        }
                    } else {
                        format!(
                            "{} {} · {} running",
                            self.machines.len(),
                            if self.machines.len() == 1 {
                                "machine"
                            } else {
                                "machines"
                            },
                            self.machines
                                .iter()
                                .filter(|m| m.state == "running")
                                .count()
                        )
                    },
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
                    self.create = Some(crate::new_machine_ui::Editor::default());
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
        let awaiting_created_machine = matches!(self.pending, Some(Operation::Refresh))
            && self
                .selected
                .as_ref()
                .is_some_and(|name| !self.machines.iter().any(|m| &m.name == name));
        if !awaiting_created_machine
            && !visible
                .iter()
                .any(|&i| self.selected.as_ref() == Some(&self.machines[i].name))
        {
            self.selected = visible.first().map(|&i| self.machines[i].name.clone());
            self.tab = Tab::Overview;
            self.logs = None;
        }
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
                    ui.label(RichText::new("No machines yet").color(MUTED));
                } else {
                    ui.label(RichText::new("No results").size(12.0).color(MUTED));
                }
            });
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("machine_inventory")
            .show_rows(ui, 60.0, visible.len(), |ui, range| {
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

    fn machine_actions(&mut self, ui: &mut egui::Ui, m: &Machine, enabled: bool) {
        ui.horizontal_wrapped(|ui| {
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
    }

    fn details(&mut self, ui: &mut egui::Ui, frame: &eframe::Frame) {
        let Some(m) = self
            .machines
            .iter()
            .find(|m| Some(&m.name) == self.selected.as_ref())
            .cloned()
        else {
            return;
        };
        ui.spacing_mut().item_spacing.y = 4.0;
        let enabled = self.pending.is_none() && self.inventory_valid;
        let wide = ui.available_width() >= 640.0;
        ui.horizontal(|ui| {
            let title_width = (ui.available_width() - if wide { 260.0 } else { 0.0 }).max(120.0);
            ui.allocate_ui_with_layout(
                egui::vec2(title_width, 56.0),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    ui.set_min_width(title_width);
                    ui.add(egui::Label::new(design::heading(&m.name, 23.0)).truncate())
                        .on_hover_text(&m.name);
                    ui.horizontal(|ui| {
                        design::badge(ui, &m.state);
                        ui.add(
                            egui::Label::new(
                                RichText::new(m.image_label()).size(12.0).color(MUTED),
                            )
                            .truncate(),
                        )
                        .on_hover_text(m.image_label());
                    });
                },
            );
            if wide {
                self.machine_actions(ui, &m, enabled);
            }
        });
        if !wide {
            ui.add_space(10.0);
            self.machine_actions(ui, &m, enabled);
        }
        if m.state == "frozen" {
            ui.label("This machine is a branch source for its children.");
        }
        if let Some(reason) = &m.state_reason {
            ui.add_space(8.0);
            design::notice(ui, reason);
        }
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Overview, "Overview"),
                (Tab::Files, "Files"),
                (Tab::Logs, "Logs"),
                (Tab::Console, "Console"),
            ] {
                if design::tab(ui, self.tab == tab, label).clicked() {
                    self.tab = tab;
                    if tab == Tab::Logs && enabled {
                        self.submit(Operation::Logs(m.name.clone()));
                    }
                }
            }
        });
        ui.separator();
        ui.add_space(16.0);
        match self.tab {
            Tab::Files => {
                if let Some(action) = self.files.show(ui, frame, &m, enabled) {
                    self.submit(action);
                }
            }
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
                ui.horizontal(|ui| {
                    ui.label(design::heading("Configuration", 14.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add_enabled(enabled && matches!(m.state.as_str(), "created" | "stopped"), egui::Button::new("Edit…"))
                            .on_disabled_hover_text("Stop this machine to change resources, shared folders and published ports.").clicked() {
                            self.settings_request = Some(m.name.clone());
                            self.submit(Operation::ReadSettings(m.name.clone()));
                        }
                    });
                });
                ui.add_space(10.0);
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
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
                });
                ui.add_space(20.0);
                ui.label(design::heading("Connections", 14.0));
                ui.add_space(8.0);
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    design::property(
                        ui,
                        "Shared folders",
                        &if m.mounts == 0 {
                            "None".into()
                        } else {
                            m.mounts.to_string()
                        },
                    );
                    ui.separator();
                    design::property(
                        ui,
                        "Published ports",
                        &if m.ports == 0 {
                            "None".into()
                        } else {
                            m.ports.to_string()
                        },
                    );
                    if let Some(parent) = &m.parent_machine {
                        ui.separator();
                        design::property(ui, "Branched from", parent);
                    }
                });
                ui.add_space(20.0);
                ui.collapsing("Command line & process", |ui| {
                    if let Some(pid) = m.pid {
                        design::property(ui, "Process ID", &pid.to_string());
                    }
                    let command =
                        format!("smol machine exec --local --name {} -it -- /bin/sh", m.name);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&command).monospace().size(11.0).color(MUTED),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&command);
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(command.clone());
                        }
                    });
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

    fn dialogs(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        if let Some(action) = self.files.dialog(ctx, self.pending.is_some()) {
            self.submit(action);
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape))
            && !self.files.modal_open()
            && !self.editing.as_ref().is_some_and(|e| e.picking())
            && !self.create.as_ref().is_some_and(|e| e.picking())
            && !self.pending.as_ref().is_some_and(Operation::is_mutation)
        {
            self.editing = None;
            self.settings_request = None;
            self.create = None;
            self.delete = None;
            self.settings = false;
            return;
        }
        if let Some(mut editor) = self.editing.take() {
            let (close, action) = editor.show(ctx, frame, self.pending.is_some());
            if !close {
                self.editing = Some(editor);
            }
            if let Some(action) = action {
                if let Operation::ReadSettings(name) = &action {
                    self.settings_request = Some(name.clone());
                }
                self.submit(action);
            }
        }
        if let Some(mut editor) = self.create.take() {
            let (close, action) = editor.show(
                ctx,
                frame,
                &self.machines,
                self.pending.as_ref(),
                self.inventory_valid,
            );
            if !close {
                self.create = Some(editor);
            }
            if let Some(action) = action {
                self.submit(action);
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
            let mut close = false;
            let mut connect = false;
            egui::Window::new("Settings")
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .collapsible(false)
                .resizable(false)
                .default_width(510.0)
                .max_height((ctx.content_rect().height() - 80.0).max(300.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("studio-settings")
                        .max_height((ctx.content_rect().height() - 220.0).max(200.0))
                        .show(ui, |ui| {
                            ui.label(design::heading("Local runtime", 16.0));
                            ui.label(
                                RichText::new(
                                    "Studio connects to your machines through the Smol CLI.",
                                )
                                .size(12.0)
                                .color(MUTED),
                            );
                            ui.add_space(12.0);
                            design::card().show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                design::property(
                                    ui,
                                    "Connection",
                                    if self.inventory_valid {
                                        "Connected"
                                    } else {
                                        "Unavailable"
                                    },
                                );
                                if self.inventory_valid {
                                    ui.separator();
                                    design::property(
                                        ui,
                                        "Local machines",
                                        &self.machines.len().to_string(),
                                    );
                                }
                                ui.separator();
                                design::property(ui, "When Studio closes", "Machines keep running");
                            });
                            ui.add_space(16.0);
                            ui.label(design::heading("CLI location", 14.0));
                            ui.label(
                                RichText::new(
                                    "Use the included CLI, or choose your own installation.",
                                )
                                .size(12.0)
                                .color(MUTED),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.runtime_path)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("Path to smol"),
                            );
                            ui.horizontal(|ui| {
                                if ui.button("Use detected CLI").clicked() {
                                    self.runtime_path = Runtime::discover()
                                        .executable
                                        .to_string_lossy()
                                        .into_owned();
                                    self.settings_error = None;
                                }
                                if ui.button("Copy path").clicked() {
                                    ctx.copy_text(self.runtime_path.clone());
                                }
                            });
                            if let Some(path) = &self.runtime.state_dir {
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(format!("State directory: {}", path.display()))
                                        .small()
                                        .color(MUTED),
                                );
                            }
                            if let Some(error) = &self.settings_error {
                                ui.add_space(12.0);
                                design::error_notice(ui, "Settings could not be saved.", error);
                            } else if !self.inventory_valid
                                && let Some(error) = &self.error
                            {
                                ui.add_space(12.0);
                                design::error_notice(
                                    ui,
                                    "Could not connect to the selected CLI.",
                                    error,
                                );
                            }
                        });
                    ui.add_space(12.0);
                    ui.separator();
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        connect = ui
                            .add_enabled(
                                self.pending.is_none() && !self.runtime_path.trim().is_empty(),
                                design::primary("Save & connect"),
                            )
                            .clicked();
                        close = ui.button("Done").clicked();
                    });
                });
            if connect {
                let result = (|| -> Result<(), String> {
                    let mut preferences = smol_studio::preferences::Preferences::load()?;
                    preferences.smol_cli = Some(self.runtime_path.trim().into());
                    preferences.save()
                })();
                match result {
                    Ok(()) => {
                        self.runtime.executable = self.runtime_path.trim().into();
                        self.inventory_valid = false;
                        self.machines.clear();
                        self.selected = None;
                        self.logs = None;
                        self.error = None;
                        self.activity = "Connecting to Smol…".into();
                        self.settings = false;
                        self.settings_error = None;
                        self.submit(Operation::Refresh);
                    }
                    Err(error) => self.settings_error = Some(error),
                }
            }
            if !open || close {
                self.settings = false;
                self.settings_error = None;
            }
        }
    }
}

impl eframe::App for Studio {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive();
        self.docker.logic(&self.runtime);
        let docker_visible = self.workspace == Workspace::Containers
            && ctx.input(|i| i.viewport().minimized != Some(true));
        self.docker.logs_visibility(docker_visible);
        self.docker
            .watch(ctx, &self.runtime, docker_visible, self.settings);
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
                || self.files.modal_open()
                || self.settings
                || self.create.is_some()
                || self.editing.is_some()
                || self.delete.is_some(),
        ) {
            self.submit(Operation::Refresh);
        }
        if active && self.workspace == Workspace::Local {
            ctx.request_repaint_after(REFRESH_INTERVAL);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.docker.terminal_ui(&ctx);
        if let Some(terminal) = &mut self.terminal
            && !terminal.ui(&ctx)
        {
            self.terminal = None;
        }
        if self.files.modal_open()
            || self.create.is_some()
            || self.editing.is_some()
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
                    .inner_margin(Margin::symmetric(16, 4)),
            )
            .show(ui, |ui| {
                ui.spacing_mut().interact_size.y = 18.0;
                ui.horizontal(|ui| {
                    let label = match self.workspace {
                        Workspace::Cloud => "Smol Cloud".to_string(),
                        Workspace::Containers => self.docker.status().to_owned(),
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
                            RichText::new(if self.inventory_valid {
                                "Local engine connected"
                            } else {
                                "Local engine unavailable"
                            })
                            .size(10.0)
                            .color(MUTED),
                        )
                        .on_hover_text("Machines keep running when you close Studio.");
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(5.0), egui::Sense::hover());
                        ui.painter().circle_filled(
                            r.center(),
                            2.5,
                            if self.inventory_valid { GREEN } else { MUTED },
                        );
                    });
                });
            });
        self.sidebar(ui);
        match self.workspace {
            Workspace::Cloud => self.cloud.ui(ui),
            Workspace::Containers => self.docker.ui(ui, &self.runtime, frame),
            Workspace::Local => {
                egui::Panel::top("local-heading")
                    .resizable(false)
                    .frame(
                        egui::Frame::new()
                            .fill(Color32::WHITE)
                            .inner_margin(Margin::symmetric(22, 14)),
                    )
                    .show(ui, |ui| self.header(ui));
                egui::Panel::left("local-list")
                    .resizable(true)
                    .default_size(248.0)
                    .min_size(224.0)
                    .max_size(380.0)
                    .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
                    .show(ui, |ui| {
                        design::search(ui, &mut self.query, "Search machines…");
                        ui.add_space(8.0);
                        design::segmented(
                            ui,
                            &mut self.filter,
                            &[
                                (Filter::All, "All"),
                                (Filter::Running, "Running"),
                                (Filter::Stopped, "Stopped"),
                            ],
                        );
                        ui.add_space(12.0);
                        self.machine_list(ui);
                    });
                egui::CentralPanel::default()
                    .frame(egui::Frame::new().fill(SURFACE).inner_margin(24))
                    .show(ui, |ui| {
                        if self.selected.is_some() {
                            egui::ScrollArea::vertical()
                                .id_salt("machine-detail")
                                .show(ui, |ui| self.details(ui, frame));
                        } else if !self.machines.is_empty() {
                            ui.add_space(100.0);
                            ui.vertical_centered(|ui| {
                                design::empty_state(
                                    ui,
                                    Icon::Machine,
                                    "No matching machines",
                                    "Try a different name or clear your filters.",
                                );
                                ui.add_space(16.0);
                                if ui.button("Clear filters").clicked() {
                                    self.query.clear();
                                    self.filter = Filter::All;
                                }
                            });
                        } else {
                            ui.add_space(100.0);
                            ui.vertical_centered(|ui| {
                                design::empty_state(
                                    ui,
                                    Icon::Machine,
                                    "Your workspace starts here",
                                    "Create a Linux machine, open a terminal, and get to work.",
                                );
                                ui.add_space(20.0);
                                if ui
                                    .add_enabled(
                                        self.inventory_valid && self.pending.is_none(),
                                        design::primary("+  New machine"),
                                    )
                                    .clicked()
                                {
                                    self.create = Some(crate::new_machine_ui::Editor::default());
                                }
                            });
                        }
                    });
            }
        }
        self.dialogs(&ctx, frame);
    }
}
