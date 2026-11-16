mod settings;

use eframe::egui::{self, Color32, Margin, RichText, Vec2};
use smol_studio::{
    inventory::Inventory,
    model::{Machine, Operation},
    runtime::{Payload, Runtime, Worker},
    schedule::{REFRESH_INTERVAL, RefreshSchedule},
};
use std::time::Instant;

use crate::design::{self, Icon, theme};

#[derive(Clone, Copy, PartialEq)]
enum Filter {
    All,
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash)]
enum Tab {
    Overview,
    Usage,
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
    appearance: crate::appearance::Appearance,
    desktop_menu: crate::desktop_menu::DesktopMenu,
    switcher: crate::navigation_ui::Switcher,
    cloud: crate::cloud_ui::CloudView,
    workspace: Workspace,
    terminal: Option<crate::terminal_ui::TerminalWindow>,
    docker: crate::docker_ui::DockerView,
    runtime: Runtime,
    worker: Worker,
    inventory: Inventory,
    usage: smol_studio::usage::Usage,
    machines: Vec<Machine>,
    selected: Option<String>,
    filter: Filter,
    query: String,
    tab: Tab,
    logs: crate::live_logs_ui::LiveLogs,
    files: crate::files_ui::FilesView,
    pending: Option<Operation>,
    schedule: RefreshSchedule,
    last_refresh: Option<Instant>,
    inventory_valid: bool,
    error: Option<String>,
    refresh_error: bool,
    activity: String,
    close_notice: bool,
    create: Option<crate::new_machine_ui::Editor>,
    editing: Option<crate::machine_settings_ui::Editor>,
    settings_request: Option<String>,
    delete: Option<String>,
    settings: bool,
    settings_error: Option<String>,
    settings_feedback: Option<String>,
    settings_scroll_error: bool,
    settings_candidate: Option<Runtime>,
    settings_picker: crate::file_picker::FilePicker,
    runtime_path: String,
    command: String,
    output: Option<(String, String)>,
    console_machine: Option<String>,
    console_revision: u64,
    console_snapshot: Option<smol_studio::command_progress::Snapshot>,
}

impl Studio {
    pub fn new(cc: &eframe::CreationContext<'_>, runtime: Runtime) -> Self {
        let ctx = cc.egui_ctx.clone();
        theme(&ctx);
        let worker = Worker::new(move || ctx.request_repaint());
        let ctx = cc.egui_ctx.clone();
        let inventory = Inventory::new(move || ctx.request_repaint());
        let ctx = cc.egui_ctx.clone();
        let usage = smol_studio::usage::Usage::new(move || ctx.request_repaint());
        let runtime_path = runtime.executable.to_string_lossy().into_owned();
        let mut app = Self {
            brand: design::brand_texture(&cc.egui_ctx),
            appearance: crate::appearance::Appearance::new(&cc.egui_ctx),
            desktop_menu: crate::desktop_menu::DesktopMenu::new(&cc.egui_ctx),
            switcher: crate::navigation_ui::Switcher::default(),
            cloud: crate::cloud_ui::CloudView::new(&cc.egui_ctx),
            workspace: Workspace::Local,
            terminal: None,
            docker: crate::docker_ui::DockerView::new(&cc.egui_ctx),
            runtime,
            worker,
            inventory,
            usage,
            machines: Vec::new(),
            selected: None,
            filter: Filter::All,
            query: String::new(),
            tab: Tab::Overview,
            logs: crate::live_logs_ui::LiveLogs::default(),
            files: crate::files_ui::FilesView::default(),
            pending: None,
            schedule: RefreshSchedule::default(),
            last_refresh: None,
            inventory_valid: false,
            error: None,
            refresh_error: false,
            activity: "Connecting to Smol…".into(),
            close_notice: false,
            create: None,
            editing: None,
            settings_request: None,
            delete: None,
            settings: false,
            settings_error: None,
            settings_feedback: None,
            settings_scroll_error: false,
            settings_candidate: None,
            settings_picker: crate::file_picker::FilePicker::default(),
            runtime_path,
            command: String::new(),
            output: None,
            console_machine: None,
            console_revision: 0,
            console_snapshot: None,
        };
        app.cloud.restore();
        app.refresh_inventory();
        app
    }

    fn submit(&mut self, op: Operation) {
        if self.pending.is_some() {
            return;
        }
        self.close_notice = false;
        // Capture the previous report before queuing: the worker can begin or
        // finish the next command immediately after submit succeeds.
        let previous_revision = self.worker.console.snapshot_after(0).map(|s| s.revision);
        match self.worker.submit(self.runtime.clone(), op.clone()) {
            Ok(()) => {
                if op.is_mutation() {
                    self.inventory.invalidate();
                }
                if let Operation::Exec { name, .. } = &op {
                    self.console_machine = Some(name.clone());
                    self.console_revision = previous_revision.unwrap_or(0);
                    self.console_snapshot = None;
                }
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
            if matches!(done.operation, Operation::Refresh)
                && let Some(candidate) = self.settings_candidate.take()
            {
                self.finish_settings_check(candidate, done.result);
                continue;
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
                // Inventory has its own observer; command responses never replace the list.
                Ok(Payload::Machines(_)) => {}
                // The visible Logs tab owns its reader independently of the operation worker.
                Ok(Payload::Logs { .. }) => {}
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
                        self.logs.reset();
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
                    if let Operation::Exec { name, .. } = &done.operation {
                        self.output = Some((name.clone(), format!("Command error: {e}")));
                        shown_in_editor = true;
                    }
                    self.refresh_error = false;
                    self.error = if shown_in_editor { None } else { Some(e) };
                }
            }
        }
    }

    fn local_ready(&self) -> bool {
        self.inventory_valid && self.inventory.current() && self.pending.is_none()
    }

    fn refresh_inventory(&mut self) {
        self.inventory.request();
        self.start_inventory();
    }

    fn start_inventory(&mut self) {
        // After an action, reconciliation may finish while its retry dialog is open.
        if self.pending.is_none()
            && (!self.modal_open() || !self.inventory.current())
            && let Err(error) = self.inventory.start(&self.runtime)
        {
            self.inventory_valid = false;
            self.refresh_error = true;
            self.error = Some(error);
        }
    }

    fn receive_inventory(&mut self) {
        if self.pending.is_some() || (self.modal_open() && self.inventory.current()) {
            return;
        }
        if let Some(result) = self.inventory.poll() {
            self.schedule.completed(Instant::now());
            match result {
                Ok(machines) => {
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
                        self.logs.reset();
                        self.tab = Tab::Overview;
                    }
                    if self.activity == "Connecting to Smol…" {
                        self.activity = "Ready".into();
                    }
                }
                Err(error) => {
                    self.inventory_valid = false;
                    // Keep a user-command failure visible until a successful user action.
                    if self.error.is_none() || self.refresh_error {
                        self.error = Some(error);
                        self.refresh_error = true;
                    }
                }
            }
        }
        self.start_inventory();
    }

    fn navigate(&mut self, destination: crate::navigation_ui::Destination) {
        use crate::navigation_ui::Destination;
        match destination {
            Destination::Machines => self.workspace = Workspace::Local,
            Destination::Cloud => self.workspace = Workspace::Cloud,
            Destination::Settings => self.open_settings(),
            Destination::Docker(kind) if !self.docker.navigating() => {
                if self.workspace != Workspace::Containers || self.docker.destination() != kind {
                    self.workspace = Workspace::Containers;
                    self.docker.navigate(&self.runtime, kind);
                }
            }
            Destination::Docker(_) => {}
        }
    }

    fn modal_open(&self) -> bool {
        self.files.modal_open()
            || self.create.is_some()
            || self.editing.is_some()
            || self.delete.is_some()
            || self.settings
            || self.cloud.modal_open()
            // A background Docker operation can finish with a retry dialog.
            // Its hidden form must not disable another workspace.
            || (self.workspace == Workspace::Containers && self.docker.modal_open())
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        use smol_studio::docker::Kind;
        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(184.0)
            .frame(
                egui::Frame::new()
                    .fill(design::palette(ui).sidebar)
                    .inner_margin(12),
            )
            .show(ui, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new((self.brand.id(), Vec2::splat(32.0))));
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(design::heading("smol studio", 15.0));
                        ui.label(
                            RichText::new("by smol machines")
                                .size(10.0)
                                .color(design::palette(ui).muted),
                        );
                    });
                });
                ui.add_space(12.0);
                let shortcut = ui.ctx().format_shortcut(&egui::KeyboardShortcut::new(
                    egui::Modifiers::COMMAND,
                    egui::Key::K,
                ));
                if design::switcher_button(ui, &shortcut).clicked() {
                    self.switcher.open();
                }
                ui.add_space(12.0);
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
                    ui.add_space(12.0);
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
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(6.0);
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
                        self.open_settings();
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
                        if self.inventory.busy() {
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
                    .add_enabled(self.local_ready(), design::primary(ui, "+  New machine"))
                    .clicked()
                {
                    self.create = Some(crate::new_machine_ui::Editor::default());
                }
                if ui
                    .add_enabled(
                        self.pending.is_none() && !self.inventory.busy(),
                        egui::Button::new(if self.inventory.busy() {
                            "Refreshing…"
                        } else {
                            "Refresh"
                        }),
                    )
                    .clicked()
                {
                    self.refresh_inventory();
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
        let awaiting_created_machine = self.inventory.busy()
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
            self.logs.reset();
        }
        if visible.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                if !self.inventory_valid {
                    ui.heading("Connect to Smol");
                    ui.label("Choose your Smol CLI in Settings, then refresh.");
                    if ui.button("Open settings").clicked() {
                        self.open_settings();
                    }
                } else if self.machines.is_empty() {
                    ui.label(RichText::new("No machines yet").color(design::palette(ui).muted));
                } else {
                    ui.label(
                        RichText::new("No results")
                            .size(12.0)
                            .color(design::palette(ui).muted),
                    );
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
                        self.logs.reset();
                    }
                }
            });
    }

    fn machine_actions(&mut self, ui: &mut egui::Ui, m: &Machine, enabled: bool) {
        ui.horizontal_wrapped(|ui| {
            if m.can_start()
                && ui
                    .add_enabled(enabled, design::primary(ui, "Start machine"))
                    .clicked()
            {
                self.submit(Operation::Start(m.name.clone()));
            }
            if m.state == "paused"
                && ui
                    .add_enabled(enabled, design::primary(ui, "Resume machine"))
                    .clicked()
            {
                self.submit(Operation::Resume(m.name.clone()));
            }
            if m.state == "running"
                && ui
                    .add_enabled(enabled, design::primary(ui, "Open terminal"))
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
                            .button(RichText::new("Delete machine…").color(design::palette(ui).red))
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
        let enabled = self.local_ready();
        let wide = ui.available_width() >= 640.0;
        ui.horizontal(|ui| {
            let title_width = (ui.available_width() - if wide { 260.0 } else { 0.0 }).max(120.0);
            ui.allocate_ui_with_layout(
                egui::vec2(title_width, 56.0),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    ui.set_min_width(title_width);
                    design::workload_heading(
                        ui,
                        Icon::Machine,
                        &m.name,
                        m.image_label(),
                        &m.state,
                        None,
                    );
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
        ui.horizontal_wrapped(|ui| {
            for (tab, label) in [
                (Tab::Overview, "Overview"),
                (Tab::Usage, "Usage"),
                (Tab::Files, "Files"),
                (Tab::Logs, "Logs"),
                (Tab::Console, "Console"),
            ] {
                if design::tab(ui, self.tab == tab, label).clicked() {
                    self.tab = tab;
                    self.logs.set_visible(tab == Tab::Logs);
                }
            }
        });
        ui.separator();
        ui.add_space(16.0);
        match self.tab {
            Tab::Usage => {
                egui::ScrollArea::vertical()
                    .id_salt(("machine-detail", &m.name, self.tab))
                    .auto_shrink([false, false])
                    .show(ui, |ui| crate::usage_ui::show(ui, &self.usage, &m));
            }
            Tab::Files => {
                if let Some(action) = self.files.show(ui, frame, &m, enabled) {
                    self.submit(action);
                }
            }
            Tab::Console => {
                design::card(ui.ctx()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(design::heading("Run a command", 14.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_enabled(
                                    enabled
                                        && m.state == "running"
                                        && !self.command.trim().is_empty(),
                                    design::primary(ui, "Run"),
                                )
                                .clicked()
                            {
                                self.output = None;
                                self.submit(Operation::Exec {
                                    name: m.name.clone(),
                                    command: self.command.clone(),
                                });
                            }
                        });
                    });
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .id_salt(("console-command", &m.name))
                        .max_height(96.0)
                        .min_scrolled_height(40.0)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.command)
                                    .desired_rows(2)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace)
                                    .hint_text("uname -a"),
                            );
                        });
                    ui.label(
                        RichText::new(if m.state == "running" {
                            "Shell command · 60 second limit"
                        } else {
                            "Start this machine to run commands."
                        })
                        .size(11.5)
                        .color(design::palette(ui).muted),
                    );
                });
                ui.add_space(16.0);
                let snapshot = self
                    .console_snapshot
                    .as_ref()
                    .filter(|_| self.console_machine.as_deref() == Some(&m.name));
                let finished = self.output.as_ref().filter(|(name, _)| name == &m.name);
                let text = finished
                    .map(|(_, text)| text.as_str())
                    .or_else(|| snapshot.map(|s| s.text.as_str()));
                ui.horizontal(|ui| {
                    ui.label(design::heading("Output", 14.0));
                    if let Some(snapshot) = snapshot {
                        use smol_studio::command_progress::Status;
                        let (label, color) = match snapshot.status {
                            Status::Running => ("Running", design::palette(ui).muted),
                            Status::Succeeded => ("Completed", design::palette(ui).green),
                            Status::Failed => ("Failed", design::palette(ui).red),
                        };
                        ui.label(RichText::new(label).size(11.5).color(color));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(text) = text.filter(|t| !t.is_empty())
                            && ui.small_button("Copy output").clicked()
                        {
                            ui.ctx().copy_text(text.to_owned());
                        }
                    });
                });
                if snapshot.is_some_and(|s| s.discarded) {
                    ui.label(
                        RichText::new("Recent output · older output discarded")
                            .size(11.0)
                            .color(design::palette(ui).muted),
                    );
                }
                ui.add_space(8.0);
                if let Some(text) = text.filter(|t| !t.is_empty()) {
                    let lines: Vec<_> = text.lines().collect();
                    let row_height =
                        ui.fonts_mut(|fonts| fonts.row_height(&egui::FontId::monospace(11.5)));
                    egui::ScrollArea::both()
                        .id_salt(("console", &m.name, snapshot.map(|s| s.id)))
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show_rows(ui, row_height, lines.len(), |ui, range| {
                            for index in range {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(lines[index]).monospace().size(11.5),
                                    )
                                    .wrap_mode(egui::TextWrapMode::Extend)
                                    .selectable(true),
                                );
                            }
                        });
                } else {
                    ui.label(RichText::new(if matches!(&self.pending, Some(Operation::Exec { name, .. }) if name == &m.name) { "Waiting for command output…" } else { "Command output will appear here." }).size(12.0).color(design::palette(ui).muted));
                }
            }

            Tab::Overview => {
                egui::ScrollArea::vertical()
                    .id_salt(("machine-detail", &m.name, self.tab))
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.machine_overview(ui, &m, enabled));
            }

            Tab::Logs => {
                self.logs.show_machine(ui, &self.runtime, &m.name, enabled);
            }
        }
    }

    fn machine_overview(&mut self, ui: &mut egui::Ui, m: &Machine, enabled: bool) {
        ui.horizontal(|ui| {
            ui.label(design::heading("Resources", 14.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(enabled && matches!(m.state.as_str(), "created" | "stopped"), egui::Button::new("Edit settings…"))
                    .on_disabled_hover_text("Stop this machine to change resources, shared folders and published ports.").clicked() {
                    self.settings_request = Some(m.name.clone());
                    self.submit(Operation::ReadSettings(m.name.clone()));
                }
            });
        });
        ui.add_space(8.0);
        design::card(ui.ctx()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let memory = design::memory(m.memory_mib);
            let (memory_value, memory_unit) = memory.split_once(' ').unwrap_or((&memory, ""));
            let cpu = m.cpus.to_string();
            let storage = m
                .storage_gb
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into());
            let overlay = m
                .overlay_gb
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into());
            let metrics = [
                (
                    "CPU limit",
                    cpu.as_str(),
                    if m.cpus == 1 { "core" } else { "cores" },
                ),
                ("Memory limit", memory_value, memory_unit),
                (
                    "Storage disk",
                    storage.as_str(),
                    if m.storage_gb.is_some() { "GiB" } else { "" },
                ),
                (
                    "Overlay disk",
                    overlay.as_str(),
                    if m.overlay_gb.is_some() { "GiB" } else { "" },
                ),
            ];
            let column_count = if ui.available_width() >= 420.0 { 4 } else { 2 };
            for (index, row) in metrics.chunks(column_count).enumerate() {
                if index > 0 {
                    ui.add_space(12.0);
                }
                let colors = design::palette(ui);
                ui.columns(column_count, |columns| {
                    for (column, (label, value, unit)) in columns.iter_mut().zip(row) {
                        design::metric(column, label, value, unit);
                        if *value == "—" {
                            column.label(
                                RichText::new("Not reported").size(11.0).color(colors.muted),
                            );
                        }
                    }
                });
            }
        });
        ui.add_space(16.0);
        ui.label(design::heading("Connections", 14.0));
        ui.add_space(8.0);
        design::card(ui.ctx()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            design::property(
                ui,
                "Outbound network",
                match m.network {
                    Some(true) => "Enabled",
                    Some(false) => "Disabled",
                    None => "Not reported",
                },
            );
            ui.separator();
            ui.label(
                RichText::new("Published ports")
                    .size(12.0)
                    .color(design::palette(ui).muted),
            );
            match &m.port_mappings {
                Some(ports) if !ports.is_empty() => {
                    for port in ports {
                        let address = format!("127.0.0.1:{}", port.host);
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("Copy address").clicked() {
                                        ui.ctx().copy_text(address.clone());
                                    }
                                    ui.with_layout(
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&address).monospace().size(12.0),
                                                )
                                                .truncate(),
                                            )
                                            .on_hover_text(&address);
                                        },
                                    );
                                },
                            );
                        });
                        ui.label(
                            RichText::new(format!(
                                "{} → guest port {}",
                                port.protocol.to_uppercase(),
                                port.guest
                            ))
                            .size(11.5)
                            .color(design::palette(ui).muted),
                        );
                    }
                }
                _ => {
                    ui.label(
                        RichText::new(if m.ports == 0 {
                            "No ports published".into()
                        } else {
                            format!("{} ports · details not reported", m.ports)
                        })
                        .size(12.0)
                        .color(design::palette(ui).muted),
                    );
                }
            }
            ui.add_space(8.0);
            ui.separator();
            ui.label(
                RichText::new("Shared folders")
                    .size(12.0)
                    .color(design::palette(ui).muted),
            );
            match &m.shared_folders {
                Some(folders) if !folders.is_empty() => {
                    for folder in folders {
                        ui.add_space(8.0);
                        for (label, path) in [("Guest", &folder.guest), ("Host", &folder.host)] {
                            ui.horizontal(|ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .small_button(format!("Copy {}", label.to_lowercase()))
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(path.clone());
                                        }
                                        ui.with_layout(
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    RichText::new(label)
                                                        .size(11.0)
                                                        .color(design::palette(ui).muted),
                                                );
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(path).monospace().size(12.0),
                                                    )
                                                    .truncate(),
                                                )
                                                .on_hover_text(path);
                                            },
                                        );
                                    },
                                );
                            });
                        }
                        ui.label(
                            RichText::new(match folder.mode.as_str() {
                                "ro" => "Read only",
                                "rw" => "Read and write",
                                "staged" => "Staged copy",
                                mode => mode,
                            })
                            .size(11.5)
                            .color(design::palette(ui).muted),
                        );
                    }
                }
                _ => {
                    ui.label(
                        RichText::new(if m.mounts == 0 {
                            "No shared folders".into()
                        } else {
                            format!("{} folders · details not reported", m.mounts)
                        })
                        .size(12.0)
                        .color(design::palette(ui).muted),
                    );
                }
            }
        });
        ui.add_space(16.0);
        ui.collapsing("Command line & process", |ui| {
            if let Some(parent) = &m.parent_machine {
                design::property(ui, "Branched from", parent);
            }
            if let Some(pid) = m.pid {
                design::property(ui, "Process ID", &pid.to_string());
            }
            let command = format!("smol machine exec --local --name {} -it -- /bin/sh", m.name);
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(command.clone());
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&command)
                                    .monospace()
                                    .size(11.0)
                                    .color(design::palette(ui).muted),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&command);
                    });
                });
            });
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        if let Some(action) = self.files.dialog(ctx, self.pending.is_some()) {
            self.submit(action);
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape))
            && !self.files.modal_open()
            && !self.settings_picker.is_open()
            && self.settings_candidate.is_none()
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
                self.inventory_valid && self.inventory.current(),
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
                let allowed = self.local_ready() && self.machines.iter().any(|m| m.name == name && m.can_delete());
                ui.horizontal(|ui| {
                    if ui.add_enabled(allowed, egui::Button::new(RichText::new("Delete machine").color(Color32::WHITE)).fill(design::palette(ui).danger_fill)).clicked() {
                        self.submit(Operation::Delete(name)); self.delete = None;
                    }
                    if ui.button("Cancel").clicked() { self.delete = None; }
                });
            });
            if !open {
                self.delete = None;
            }
        }
        self.settings_dialog(ctx, frame);
    }
}

impl eframe::App for Studio {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        self.appearance.input(raw);
        if self.desktop_menu.input(raw) {
            if self.pending.as_ref().is_some_and(Operation::is_mutation)
                || self.cloud.mutating()
                || self.docker.mutating()
                || self.modal_open()
            {
                self.close_notice = true;
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive();
        if let Some(snapshot) = self.worker.console.snapshot_after(self.console_revision) {
            self.console_revision = snapshot.revision;
            self.console_snapshot = Some(snapshot);
        }
        self.receive_inventory();
        self.logs.set_visible(
            self.workspace == Workspace::Local
                && self.tab == Tab::Logs
                && self.inventory_valid
                && ctx.input(|i| i.viewport().minimized != Some(true)),
        );
        self.docker.logic(&self.runtime);
        let docker_visible = self.workspace == Workspace::Containers
            && ctx.input(|i| i.viewport().minimized != Some(true));
        self.docker.logs_visibility(docker_visible);
        self.docker.sample_usage(
            ctx,
            &self.runtime,
            docker_visible,
            self.settings || self.switcher.open,
        );
        self.docker.watch(
            ctx,
            &self.runtime,
            docker_visible,
            self.settings || self.switcher.open,
        );
        if ctx.input(|i| i.viewport().close_requested())
            && (self.pending.as_ref().is_some_and(Operation::is_mutation)
                || self.cloud.mutating()
                || self.docker.mutating())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_notice = true;
        }
        let active = ctx
            .input(|i| i.viewport().focused == Some(true) && i.viewport().minimized != Some(true));
        let machine = self
            .machines
            .iter()
            .find(|m| self.selected.as_ref() == Some(&m.name));
        let usage_target = machine.map(|m| smol_studio::usage::Target {
            runtime: self.runtime.clone(),
            name: m.name.clone(),
            pid: m.pid,
        });
        let usage_active = active
            && self.workspace == Workspace::Local
            && self.tab == Tab::Usage
            && machine.is_some_and(|m| m.state == "running")
            && self.local_ready()
            && !self.modal_open();
        let now = Instant::now();
        self.usage.update(usage_target, usage_active, now);
        if let Some(after) = self.usage.repaint_after(now) {
            ctx.request_repaint_after(after);
        }

        self.cloud
            .logic(ctx, active && (self.workspace == Workspace::Cloud));
        if self.schedule.due(
            Instant::now(),
            active && (self.workspace == Workspace::Local),
            self.pending.is_some()
                || self.inventory.busy()
                || self.files.modal_open()
                || self.settings
                || self.switcher.open
                || self.create.is_some()
                || self.editing.is_some()
                || self.delete.is_some(),
        ) {
            self.refresh_inventory();
        }
        if active && self.workspace == Workspace::Local {
            ctx.request_repaint_after(REFRESH_INTERVAL);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if !self.modal_open()
            && !self.terminal.as_ref().is_some_and(|t| t.focused(&ctx))
            && !self.docker.terminal_focused(&ctx)
            && !egui::Popup::is_any_open(&ctx)
            && let Some(destination) = self.switcher.shortcuts(&ctx)
        {
            self.navigate(destination);
        }
        let switching = self.switcher.open;
        if let Some(destination) = self.switcher.show(&ctx, self.docker.navigating()) {
            self.navigate(destination);
        }
        self.docker.terminal_ui(&ctx);
        if let Some(terminal) = &mut self.terminal
            && !terminal.ui(&ctx)
        {
            self.terminal = None;
        }
        if self.modal_open() || switching {
            ui.disable();
        }
        egui::Panel::bottom("status")
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(design::palette(ui).surface)
                    .inner_margin(Margin::symmetric(16, 4)),
            )
            .show(ui, |ui| {
                ui.spacing_mut().interact_size.y = 18.0;
                ui.horizontal(|ui| {
                    let label = if self.close_notice {
                        if self.pending.as_ref().is_some_and(Operation::is_mutation)
                            || self.cloud.mutating()
                            || self.docker.mutating()
                        {
                            "Quit cancelled: an operation is still running.".to_owned()
                        } else if self.modal_open() {
                            "Quit cancelled: close the open dialog first.".to_owned()
                        } else {
                            "You can now close Studio.".to_owned()
                        }
                    } else {
                        match self.workspace {
                            Workspace::Cloud => "Smol Cloud".to_string(),
                            Workspace::Containers => self.docker.status().to_owned(),
                            Workspace::Local => self
                                .pending
                                .as_ref()
                                .map(Operation::label)
                                .unwrap_or_else(|| self.activity.clone()),
                        }
                    };
                    if self.workspace == Workspace::Local && self.pending.is_some() {
                        ui.spinner();
                    }
                    ui.label(
                        RichText::new(label)
                            .size(11.0)
                            .color(design::palette(ui).muted),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(if self.inventory_valid {
                                "Local engine connected"
                            } else {
                                "Local engine unavailable"
                            })
                            .size(10.0)
                            .color(design::palette(ui).muted),
                        )
                        .on_hover_text("Machines keep running when you close Studio.");
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(5.0), egui::Sense::hover());
                        ui.painter().circle_filled(
                            r.center(),
                            2.5,
                            if self.inventory_valid {
                                design::palette(ui).green
                            } else {
                                design::palette(ui).muted
                            },
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
                            .fill(design::palette(ui).base)
                            .inner_margin(Margin::symmetric(22, 14)),
                    )
                    .show(ui, |ui| self.header(ui));
                egui::Panel::left("local-list")
                    .resizable(true)
                    .default_size(248.0)
                    .min_size(224.0)
                    .max_size(380.0)
                    .frame(
                        egui::Frame::new()
                            .fill(design::palette(ui).surface)
                            .inner_margin(12),
                    )
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
                    .frame(
                        egui::Frame::new()
                            .fill(design::palette(ui).base)
                            .inner_margin(24),
                    )
                    .show(ui, |ui| {
                        if self.selected.is_some() {
                            self.details(ui, frame);
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
                                        self.local_ready(),
                                        design::primary(ui, "+  New machine"),
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
        self.desktop_menu.update(
            !self.modal_open()
                && !self.terminal.as_ref().is_some_and(|t| t.focused(&ctx))
                && !self.docker.terminal_focused(&ctx),
            !self.docker.navigating(),
            !self.modal_open()
                && !self.pending.as_ref().is_some_and(Operation::is_mutation)
                && !self.cloud.mutating()
                && !self.docker.mutating(),
        );
    }
}
