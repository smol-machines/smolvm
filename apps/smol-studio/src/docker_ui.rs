mod resources;

use crate::design::{self, MUTED, SURFACE};
use eframe::egui::{self, Color32, RichText};
use serde_json::Value;
use smol_studio::{
    docker::{Action, DockerWorker, Kind, Output, ProjectAction},
    runtime::Runtime,
};

#[derive(Clone, Copy)]
enum PickMode {
    New,
    Replace,
    Append,
}

#[derive(Clone, Copy, Default, PartialEq)]
enum ContainerTab {
    #[default]
    Overview,
    Logs,
    Mounts,
}

pub struct DockerView {
    worker: DockerWorker,
    events: smol_studio::event_watch::EventWatch,
    kind: Kind,
    rows: Vec<Value>,
    storage_selected: Option<String>,
    storage: Option<smol_studio::storage::Details>,
    network: Option<smol_studio::network::Details>,
    resource_tab: resources::Tab,
    new_resource: Option<Kind>,
    resource_input: String,
    resource_error: Option<String>,
    pending: Option<Action>,
    error: Option<String>,
    text: String,
    activity: String,
    compose_files: Vec<String>,
    compose_name: Option<String>,
    pick_mode: PickMode,
    file_picker: crate::file_picker::FilePicker,
    file_error: Option<String>,
    projects: Vec<smol_studio::compose::Project>,
    project_selected: Option<String>,
    project_query: String,
    projects_valid: bool,
    compose_import: bool,
    confirm: Option<Action>,
    valid: bool,
    query: String,
    compose: bool,
    opened: bool,
    selected: Option<String>,
    details: Option<smol_studio::container_details::ContainerDetails>,
    stats: Option<Value>,
    container_tab: ContainerTab,
    live_logs: crate::live_logs_ui::LiveLogs,
    terminal: Option<crate::terminal_ui::TerminalWindow>,
}
impl DockerView {
    fn select_compose_files(&mut self, paths: &[std::path::PathBuf]) {
        self.compose_import = true;
        if paths.is_empty()
            || paths.len() > 32
            || paths
                .iter()
                .any(|p| !p.is_absolute() || p.to_str().is_none())
        {
            self.file_error =
                Some("Choose up to 32 Compose files with absolute, UTF-8 paths.".into());
            return;
        }
        let files: Vec<_> = paths
            .iter()
            .map(|p| p.to_str().unwrap().to_owned())
            .collect();
        match self.pick_mode {
            PickMode::New => {
                self.compose_name = None;
                self.compose_files = files;
            }
            PickMode::Replace => self.compose_files = files,
            PickMode::Append => {
                self.compose_files.retain(|p| !p.is_empty());
                for file in files {
                    if !self.compose_files.contains(&file) {
                        self.compose_files.push(file);
                    }
                }
            }
        }
        self.file_error = None;
    }

    fn compose_source(&self) -> smol_studio::compose::Source {
        smol_studio::compose::Source {
            files: self.compose_files.iter().map(Into::into).collect(),
            name: self.compose_name.clone(),
        }
    }

    pub fn new(ctx: &egui::Context) -> Self {
        let ctx = ctx.clone();
        Self {
            worker: DockerWorker::new(move || ctx.request_repaint()),
            events: smol_studio::event_watch::EventWatch::default(),
            kind: Kind::Containers,
            rows: vec![],
            storage_selected: None,
            storage: None,
            network: None,
            resource_tab: resources::Tab::Overview,
            new_resource: None,
            resource_input: String::new(),
            resource_error: None,
            pending: None,
            error: None,
            text: String::new(),
            activity: "Docker context: smol".into(),
            compose_files: vec![String::new()],
            compose_name: None,
            pick_mode: PickMode::New,
            file_picker: crate::file_picker::FilePicker::default(),
            file_error: None,
            projects: vec![],
            project_selected: None,
            project_query: String::new(),
            projects_valid: false,
            compose_import: false,
            confirm: None,
            valid: false,
            query: String::new(),
            compose: false,
            opened: false,
            selected: None,
            details: None,
            stats: None,
            container_tab: ContainerTab::Overview,
            live_logs: crate::live_logs_ui::LiveLogs::default(),
            terminal: None,
        }
    }
    pub fn destination(&self) -> Option<Kind> {
        if self.compose { None } else { Some(self.kind) }
    }

    pub fn navigating(&self) -> bool {
        self.pending.is_some()
    }

    pub fn navigate(&mut self, runtime: &Runtime, destination: Option<Kind>) {
        if self.pending.is_some() {
            return;
        }
        self.compose = destination.is_none();
        if let Some(kind) = destination {
            self.kind = kind;
        }
        self.query.clear();
        self.storage = None;
        self.network = None;
        self.resource_tab = resources::Tab::Overview;
        self.storage_selected = None;
        self.details = None;
        self.stats = None;
        self.live_logs.reset();
        self.container_tab = ContainerTab::Overview;
        self.rows.clear();
        self.valid = false;
        self.text.clear();
        self.opened = true;
        if !cfg!(windows) {
            self.refresh(runtime);
        }
    }

    pub fn modal_open(&self) -> bool {
        self.confirm.is_some() || self.new_resource.is_some() || self.file_picker.is_open()
    }
    pub fn mutating(&self) -> bool {
        self.pending.as_ref().is_some_and(Action::mutates)
    }
    pub fn status(&self) -> &str {
        match &self.pending {
            Some(Action::Projects | Action::List(_)) => "Refreshing Docker resources…",
            Some(
                Action::Project {
                    action: ProjectAction::Start,
                    ..
                }
                | Action::Start(_),
            ) => "Starting containers…",
            Some(
                Action::Project {
                    action: ProjectAction::Stop,
                    ..
                }
                | Action::Stop(_),
            ) => "Stopping containers…",
            Some(
                Action::Project {
                    action: ProjectAction::Logs,
                    ..
                }
                | Action::Logs(_),
            ) => "Loading logs…",
            Some(Action::PullImage(_)) => "Pulling image…",
            Some(Action::CreateVolume(_)) => "Creating volume…",
            Some(Action::StorageRemove { .. }) => "Removing resource…",
            Some(_) => "Working…",
            None if self.events.disconnected() => "Automatic updates interrupted · reconnecting…",
            None => &self.activity,
        }
    }
    fn submit(&mut self, runtime: &Runtime, action: Action) {
        if self.pending.is_some() {
            return;
        }
        match self.worker.submit(runtime.clone(), action.clone()) {
            Ok(()) => {
                self.pending = Some(action);
                if self.error.take().is_some() {
                    self.activity = "Docker context: smol".into();
                }
            }
            Err(e) => self.error = Some(e),
        }
    }
    fn refresh(&mut self, runtime: &Runtime) {
        self.submit(
            runtime,
            if self.compose {
                Action::Projects
            } else {
                Action::List(self.kind)
            },
        );
    }
    pub fn logic(&mut self, runtime: &Runtime) {
        while let Ok(done) = self.worker.events.try_recv() {
            self.pending = None;
            match done.result {
                Ok(Output::Network(details)) => {
                    if self.kind == Kind::Networks
                        && self.storage_selected.as_ref() == Some(&details.id)
                    {
                        self.network = Some(details);
                    }
                }
                Ok(Output::Storage(details)) => {
                    if self.kind == details.kind
                        && self.storage_selected.as_ref() == Some(&details.id)
                    {
                        self.storage = Some(details);
                    }
                }
                Ok(Output::Projects(projects, warning)) => {
                    if let Some(warning) = warning {
                        self.error = Some(warning);
                    }
                    self.projects = projects;
                    self.projects_valid = true;
                    self.project_selected = self
                        .project_selected
                        .take()
                        .filter(|name| self.projects.iter().any(|p| &p.name == name))
                        .or_else(|| self.projects.first().map(|p| p.name.clone()));
                }
                Ok(Output::Rows(kind, rows)) => {
                    if self.kind == kind {
                        self.rows = rows;
                        self.valid = true;
                        if matches!(kind, Kind::Images | Kind::Volumes | Kind::Networks) {
                            let key = if kind == Kind::Volumes { "Name" } else { "ID" };
                            let previous = self.storage_selected.clone();
                            self.storage_selected = self
                                .storage_selected
                                .take()
                                .filter(|id| self.rows.iter().any(|r| r[key].as_str() == Some(id)))
                                .or_else(|| {
                                    self.rows
                                        .first()
                                        .and_then(|r| r[key].as_str())
                                        .map(str::to_owned)
                                });
                            if self.storage_selected != previous {
                                self.storage = None;
                                self.network = None;
                            }
                            if let Some(id) = self.storage_selected.clone() {
                                self.submit(
                                    runtime,
                                    if kind == Kind::Networks {
                                        Action::NetworkInspect(id)
                                    } else {
                                        Action::StorageInspect { kind, id }
                                    },
                                );
                            }
                        }
                        if kind == Kind::Containers {
                            let previous = self.selected.clone();
                            self.selected = self
                                .selected
                                .take()
                                .filter(|id| self.rows.iter().any(|r| r["ID"].as_str() == Some(id)))
                                .or_else(|| {
                                    self.rows
                                        .first()
                                        .and_then(|r| r["ID"].as_str())
                                        .map(str::to_owned)
                                });
                            if self.selected != previous {
                                self.live_logs.reset();
                                self.container_tab = ContainerTab::Overview;
                            }
                            if let Some(id) = self.selected.clone() {
                                self.submit(runtime, Action::Inspect(id));
                            } else {
                                self.details = None;
                                self.stats = None;
                            }
                        }
                    }
                }
                Ok(Output::Details(details)) => {
                    if self.selected.as_deref() == Some(&details.id) {
                        self.details = Some(*details);
                        self.stats = None;
                    }
                }
                Ok(Output::Stats { id, value }) => {
                    if self.selected.as_ref() == Some(&id) {
                        self.stats = Some(value);
                    }
                }
                Ok(Output::Text(text)) => self.text = text,
                Ok(Output::ComposeApplied { name, warning }) => {
                    self.project_selected = Some(name);
                    self.compose_import = false;
                    self.project_query.clear();
                    self.activity = if matches!(done.action, Action::Compose { up: true, .. }) {
                        "Project applied."
                    } else {
                        "Containers removed; project files remembered."
                    }
                    .into();
                    self.text.clear();
                    self.refresh(runtime);
                    if let Some(warning) = warning {
                        self.error = Some(warning);
                    }
                }
                Ok(Output::Completed) => {
                    if matches!(done.action, Action::PullImage(_) | Action::CreateVolume(_)) {
                        self.new_resource = None;
                        self.resource_error = None;
                    }
                    if let Action::CreateVolume(name) = &done.action {
                        self.storage_selected = Some(name.clone());
                        self.query.clear();
                    }
                    self.activity = match done.action {
                        Action::PullImage(_) => "Image pulled.",
                        Action::CreateVolume(_) => "Volume created.",
                        Action::StorageRemove {
                            kind: Kind::Images, ..
                        } => "Image removed from inventory; downloaded layers may remain cached.",
                        Action::StorageRemove { .. } => "Volume removed.",
                        Action::Compose { up: true, .. } => "Compose file applied.",
                        Action::Compose { up: false, .. } => {
                            "Compose project removed; named volumes retained."
                        }
                        Action::Project {
                            action: ProjectAction::Start,
                            ..
                        }
                        | Action::Start(_) => "Containers started.",
                        Action::Project {
                            action: ProjectAction::Stop,
                            ..
                        }
                        | Action::Stop(_) => "Containers stopped.",
                        Action::Delete(_) => "Container removed.",
                        Action::Configure => "Docker connected to Smol.",
                        Action::ForgetProject(_) => {
                            "Project forgotten; files and volumes retained."
                        }
                        _ => "Operation completed.",
                    }
                    .into();
                    self.details = None;
                    self.storage = None;
                    self.stats = None;
                    self.live_logs.reset();
                    self.text.clear();
                    self.refresh(runtime);
                }
                Err(e) => {
                    if matches!(done.action, Action::PullImage(_) | Action::CreateVolume(_)) {
                        self.resource_error = Some(e.clone());
                    }
                    self.activity = "Docker request failed; see details above.".into();
                    if matches!(done.action, Action::Projects) || done.action.mutates() {
                        self.projects_valid = false;
                    }
                    if matches!(done.action, Action::List(_)) || done.action.mutates() {
                        self.valid = false;
                    }
                    if done.action.mutates() {
                        self.refresh(runtime);
                    }
                    self.error = Some(e);
                }
            }
        }
    }
    pub fn watch(&mut self, ctx: &egui::Context, runtime: &Runtime, visible: bool, modal: bool) {
        let repaint = ctx.clone();
        let poll = self.events.poll(
            std::time::Instant::now(),
            visible && self.opened && !cfg!(windows),
            self.pending.is_some() || self.modal_open() || modal,
            move || repaint.request_repaint_after(std::time::Duration::from_millis(33)),
        );
        if poll.refresh {
            self.refresh(runtime);
        }
        if let Some(delay) = poll.wake_after {
            ctx.request_repaint_after(delay);
        }
    }
    pub fn terminal_focused(&self, ctx: &egui::Context) -> bool {
        self.terminal.as_ref().is_some_and(|t| t.focused(ctx))
    }
    pub fn terminal_ui(&mut self, ctx: &egui::Context) {
        if let Some(terminal) = &mut self.terminal
            && !terminal.ui(ctx)
        {
            self.terminal = None;
        }
    }
    fn resource_dialog(&mut self, ctx: &egui::Context, runtime: &Runtime) {
        let Some(kind) = self.new_resource else {
            return;
        };
        let busy = self.pending.is_some();
        let pulling = kind == Kind::Images;
        let title = if pulling {
            "Pull an image"
        } else {
            "Create a volume"
        };
        let mut open = true;
        let mut submit = false;
        let mut cancel = false;
        let mut window = egui::Window::new(title)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .default_width(420.0);
        if !busy {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            ui.add_space(8.0);
            ui.label(
                RichText::new(if pulling {
                    "Download an image to use with your local containers."
                } else {
                    "Keep application data across container restarts and replacements."
                })
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(16.0);
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(if pulling {
                        "Image reference"
                    } else {
                        "Volume name"
                    })
                    .size(12.0)
                    .color(MUTED),
                );
                ui.add_enabled_ui(!busy, |ui| {
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.resource_input)
                                .desired_width(f32::INFINITY)
                                .margin(egui::Margin::symmetric(10, 9))
                                .hint_text(if pulling {
                                    "postgres:17"
                                } else {
                                    "project-data"
                                }),
                        )
                        .changed()
                    {
                        self.resource_error = None;
                    }
                });
            });
            let valid = if pulling {
                smol_studio::storage::validate_reference(self.resource_input.trim())
            } else {
                smol_studio::storage::validate_volume(self.resource_input.trim())
            };
            if !self.resource_input.is_empty()
                && let Err(error) = &valid
            {
                ui.label(RichText::new(error).small().color(design::RED));
            }
            if let Some(error) = &self.resource_error {
                ui.add_space(12.0);
                egui::ScrollArea::vertical()
                    .max_height(130.0)
                    .show(ui, |ui| {
                        design::error_notice(
                            ui,
                            if pulling {
                                "Image could not be pulled."
                            } else {
                                "Volume could not be created."
                            },
                            error,
                        );
                    });
            }
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if busy {
                    ui.spinner();
                    ui.label(match self.pending {
                        Some(Action::PullImage(_)) => "Pulling image…",
                        Some(Action::CreateVolume(_)) => "Creating volume…",
                        _ => "Refreshing…",
                    });
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    submit = ui
                        .add_enabled(
                            valid.is_ok() && !busy,
                            design::primary(if pulling {
                                "Pull image"
                            } else {
                                "Create volume"
                            }),
                        )
                        .clicked();
                    cancel = ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                });
            });
        });
        if submit {
            self.resource_error = None;
            let input = self.resource_input.trim().to_owned();
            self.submit(
                runtime,
                if pulling {
                    Action::PullImage(input)
                } else {
                    Action::CreateVolume(input)
                },
            );
        } else if !busy && (!open || cancel || ctx.input(|i| i.key_pressed(egui::Key::Escape))) {
            self.new_resource = None;
        }
    }
    fn project_list(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("compose-project-list")
            .resizable(true)
            .default_size(248.0)
            .min_size(224.0)
            .max_size(380.0)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
            .show(ui, |ui| {
                design::search(ui, &mut self.project_query, "Search projects…");
                ui.add_space(12.0);
                design::eyebrow(ui, &format!("PROJECTS  /  {}", self.projects.len()));
                ui.add_space(8.0);
                let query = self.project_query.to_lowercase();
                let visible: Vec<_> = self
                    .projects
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.name.to_lowercase().contains(&query))
                    .map(|(i, _)| i)
                    .collect();
                if visible.is_empty() {
                    ui.label(
                        RichText::new(if !self.projects_valid {
                            "Refresh to discover projects."
                        } else if self.projects.is_empty() {
                            "No Compose projects yet"
                        } else {
                            "No matching projects"
                        })
                        .small()
                        .color(MUTED),
                    );
                }
                if self.pending.is_some() {
                    ui.disable();
                }
                egui::ScrollArea::vertical()
                    .id_salt("compose-projects-scroll")
                    .show_rows(ui, 60.0, visible.len(), |ui, range| {
                        for &index in &visible[range] {
                            let project = &self.projects[index];
                            let subtitle = format!(
                                "{} · {} running",
                                count(project.services().len(), "service"),
                                project.running()
                            );
                            if design::resource_row(
                                ui,
                                !self.compose_import
                                    && self.project_selected.as_ref() == Some(&project.name),
                                &project.name,
                                &subtitle,
                                project.state(),
                                design::Icon::Containers,
                            )
                            .clicked()
                            {
                                self.project_selected = Some(project.name.clone());
                                self.compose_import = false;
                                self.text.clear();
                            }
                        }
                    });
            });
    }
    fn project_details(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        let Some(project) = self
            .projects
            .iter()
            .find(|p| Some(&p.name) == self.project_selected.as_ref())
            .cloned()
        else {
            return;
        };
        let enabled = self.projects_valid && self.pending.is_none();
        egui::ScrollArea::vertical().id_salt("compose-project-detail").auto_shrink([false, false]).show(ui, |ui| {
            ui.add(egui::Label::new(design::heading(&project.name, 22.0)).truncate()).on_hover_text(&project.name);
            ui.label(RichText::new(format!("{} · {} · {} running", count(project.services().len(), "service"), count(project.containers.len(), "container"), project.running())).small().color(MUTED));
            ui.add_space(12.0);
            design::badge(ui, project.state());
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                if let Some(source) = &project.source {
                    if ui.add_enabled(enabled && (project.containers.is_empty() || project.containers.iter().any(|c| c.can_start())), design::primary("Start project…")).clicked() {
                        self.confirm = Some(Action::Compose { source: source.clone(), up: true });
                    }
                } else if ui.add_enabled(enabled && project.containers.iter().any(|c| c.can_start()), design::primary("Start containers"))
                    .on_hover_text("Starts existing stopped service containers. Link your Compose files to apply configuration and dependency ordering.").clicked() {
                    self.submit(runtime, Action::Project { name: project.name.clone(), action: ProjectAction::Start });
                }
                if ui.add_enabled(enabled && project.containers.iter().any(|c| c.can_stop()), egui::Button::new("Stop containers")).clicked() {
                    self.submit(runtime, Action::Project { name: project.name.clone(), action: ProjectAction::Stop });
                }
                if ui.add_enabled(enabled, egui::Button::new("Project logs")).clicked() {
                    self.submit(runtime, Action::Project { name: project.name.clone(), action: ProjectAction::Logs });
                }
            });
            ui.add_space(12.0);
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                design::eyebrow(ui, "COMPOSE FILES");
                if let Some(source) = &project.source {
                    for file in &source.files { ui.add(egui::Label::new(RichText::new(file.display().to_string()).small().color(MUTED)).truncate()).on_hover_text(file.display().to_string()); }
                    if ui.add_enabled(enabled, egui::Button::new("Review / apply changes…")).clicked() {
                        self.compose_files = source.files.iter().map(|p| p.to_string_lossy().into_owned()).collect();
                        self.compose_name = Some(project.name.clone());
                        self.compose_import = true;
                        self.file_error = None;
                    }
                } else {
                    ui.label(RichText::new("Link the files to update this project from Studio.").small().color(MUTED));
                    if ui.add_enabled(enabled, egui::Button::new("Link Compose files…")).clicked() {
                        self.compose_files = vec![String::new()];
                        self.compose_name = Some(project.name.clone());
                        self.compose_import = true;
                        self.file_error = None;
                    }
                }
                if project.containers.is_empty() && ui.add_enabled(enabled, egui::Button::new("Forget project…")).clicked() { self.confirm = Some(Action::ForgetProject(project.name.clone())); }
            });
            ui.add_space(12.0);
            ui.separator();
            for (service, containers) in project.services() {
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    ui.label(design::heading(service, 14.0));
                    ui.label(RichText::new(count(containers.len(), "container")).small().color(MUTED));
                });
                for container in containers {
                    let subtitle = if container.is_job() { format!("{} · one-off job", container.image) } else { container.image.clone() };
                    ui.add_enabled_ui(enabled, |ui| {
                        if design::resource_row(ui, false, &container.name, &subtitle, &container.state, design::Icon::Containers).clicked() {
                            self.compose = false;
                            self.kind = Kind::Containers;
                            self.query.clear();
                            self.selected = Some(container.id.clone());
                            self.details = None;
                            self.stats = None;
                            self.container_tab = ContainerTab::Overview;
                            self.live_logs.reset();
                            self.text.clear();
                            self.submit(runtime, Action::List(Kind::Containers));
                        }
                    });
                }
            }
            if project.containers.iter().any(|c| c.is_job()) {
                ui.add_space(16.0);
                ui.label(RichText::new("Completed one-off jobs are kept stopped when you start containers.").small().color(MUTED));
            }
        });
    }
    pub fn logs_visibility(&mut self, workspace_visible: bool) {
        self.live_logs.set_visible(
            workspace_visible
                && !self.compose
                && self.kind == Kind::Containers
                && self.container_tab == ContainerTab::Logs,
        );
    }

    fn inspector(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        let Some(details) = self.details.clone() else {
            ui.add_space(20.0);
            if self.pending.is_some() {
                ui.spinner();
            } else {
                ui.label("Refresh to load container details.");
            }
            return;
        };
        let enabled = self.valid && self.pending.is_none();
        egui::ScrollArea::vertical().id_salt("container-inspector-scroll").auto_shrink([false, false]).show(ui, |ui| {
            ui.add(egui::Label::new(design::heading(&details.name, 23.0)).truncate()).on_hover_text(&details.name);
            ui.horizontal(|ui| {
                design::badge(ui, &details.state);
                ui.add(egui::Label::new(RichText::new(&details.image).size(12.0).color(MUTED)).truncate()).on_hover_text(&details.image);
            });
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                if details.state == "running" {
                    if ui.add_enabled(enabled, design::primary("Open terminal")).clicked() {
                        match crate::terminal_ui::TerminalWindow::for_container(ui.ctx(), &details.id, &details.name) {
                            Ok(t) => self.terminal = Some(t), Err(e) => self.error = Some(e),
                        }
                    }
                    if ui.add_enabled(enabled, egui::Button::new("Stop")).clicked() { self.submit(runtime, Action::Stop(details.id.clone())); }
                } else if ui.add_enabled(enabled, design::primary("Start container")).clicked() {
                    self.submit(runtime, Action::Start(details.id.clone()));
                }
                ui.add_enabled_ui(enabled, |ui| {
                    ui.menu_button("More", |ui| {
                        if ui.button("Copy container ID").clicked() { ui.ctx().copy_text(details.id.clone()); ui.close(); }
                        if details.state != "running" {
                            ui.separator();
                            if ui.button(RichText::new("Remove container…").color(design::RED)).clicked() { self.confirm = Some(Action::Delete(details.id.clone())); ui.close(); }
                        }
                    });
                });
            });
            if details.oom_killed { ui.add_space(8.0); design::notice(ui, "Stopped after running out of memory."); }
            if !details.error.is_empty() { ui.add_space(8.0); design::notice(ui, &details.error); }
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                for (tab, label) in [(ContainerTab::Overview, "Overview"), (ContainerTab::Logs, "Logs"), (ContainerTab::Mounts, "Mounts")] {
                    if design::tab(ui, self.container_tab == tab, label).clicked() {
                        self.container_tab = tab;
                        self.live_logs.set_visible(tab == ContainerTab::Logs);
                    }
                }
            });
            ui.separator(); ui.add_space(16.0);
            match self.container_tab {
                ContainerTab::Logs => self.live_logs.show(ui, &details.id, enabled),
                ContainerTab::Mounts => {
                    ui.label(design::heading("Shared folders & volumes", 14.0)); ui.add_space(8.0);
                    if details.mounts.is_empty() { ui.label(RichText::new("No folders or volumes are mounted in this container.").size(12.0).color(MUTED)); }
                    for (index, mount) in details.mounts.iter().enumerate() {
                        ui.push_id(index, |ui| {
                            design::card().show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.add(egui::Label::new(RichText::new(&mount.target).monospace().size(13.0)).truncate()).on_hover_text(&mount.target);
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.small_button("Copy path").clicked() { ui.ctx().copy_text(mount.target.clone()); }
                                    });
                                });
                                ui.label(RichText::new(format!("{} · {}", mount.kind, if mount.writable { "Read & write" } else { "Read only" })).size(11.5).color(MUTED));
                                ui.add_space(8.0);
                                ui.add(egui::Label::new(RichText::new(&mount.source).size(12.0).color(MUTED)).wrap()).on_hover_text(&mount.source);
                            });
                            ui.add_space(8.0);
                        });
                    }
                }
                ContainerTab::Overview => {
                    if details.health.is_some() || details.state != "running" {
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if let Some(health) = &details.health { design::property(ui, "Health", health); }
                            if details.state != "running" && let Some(code) = details.exit_code { design::property(ui, "Exit code", &code.to_string()); }
                        }); ui.add_space(16.0);
                    }
                    ui.label(design::heading("Published ports", 14.0)); ui.add_space(8.0);
                    if details.ports.is_empty() { ui.label(RichText::new("No ports published to this computer.").size(12.0).color(MUTED)); }
                    else { design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for (index, port) in details.ports.iter().enumerate() {
                            ui.push_id(index, |ui| {
                                if index > 0 { ui.separator(); }
                                let binding = format!("{}:{} → {}", port.host_ip, port.host_port, port.container);
                                ui.horizontal(|ui| {
                                    ui.add(egui::Label::new(RichText::new(&binding).monospace().size(12.0)).truncate()).on_hover_text(&binding);
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if let Some(url) = port.browser_url() {
                                            if ui.small_button("Copy URL").clicked() { ui.ctx().copy_text(url.clone()); }
                                            ui.hyperlink_to("Open", url).on_hover_text("Open this TCP port using HTTP; the service must speak HTTP.");
                                        } else if ui.small_button("Copy binding").clicked() { ui.ctx().copy_text(binding.clone()); }
                                    });
                                });
                            });
                        }
                    }); }
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.label(design::heading("Resource usage", 14.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add_enabled(enabled && details.state == "running", egui::Button::new("Measure now")).clicked() { self.submit(runtime, Action::Stats(details.id.clone())); }
                        });
                    });
                    ui.add_space(8.0);
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if let Some(stats) = &self.stats {
                            for (label, key) in [("Machine CPU", "CPUPerc"), ("Guest memory / limit", "MemUsage")] {
                                if let Some(value) = stats[key].as_str() { design::property(ui, label, value); }
                            }
                            ui.label(RichText::new("Snapshot · network, disk I/O and process counts unavailable").size(11.0).color(MUTED));
                        } else { ui.label(RichText::new(if details.state == "running" { "Measure to take a CPU and memory snapshot." } else { "Start this container to measure resource usage." }).size(12.0).color(MUTED)); }
                    });
                    if let Some(project) = &details.project {
                        ui.add_space(20.0); ui.label(design::heading("Compose project", 14.0));
                        if ui.link(project).clicked() && enabled {
                            self.compose = true; self.compose_import = false; self.project_selected = Some(project.clone()); self.submit(runtime, Action::Projects);
                        }
                        if let Some(service) = &details.service { ui.label(RichText::new(format!("Service: {service}")).size(12.0).color(MUTED)); }
                    }
                    ui.add_space(20.0);
                    ui.collapsing("Command & diagnostics", |ui| {
                        design::property(ui, "Restarts", &details.restarts.to_string());
                        for arg in &details.command { ui.add(egui::Label::new(RichText::new(arg).monospace().size(11.0)).wrap()); }
                    });
                }
            }
        });
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, runtime: &Runtime, frame: &eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(Some(files)) = self.file_picker.poll(&ctx) {
            self.select_compose_files(
                &files
                    .iter()
                    .map(|f| f.path().to_owned())
                    .collect::<Vec<_>>(),
            );
        }
        if self.compose && ui.is_enabled() && self.pending.is_none() {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            if !dropped.is_empty() {
                self.pick_mode = if self.compose_import {
                    PickMode::Replace
                } else {
                    PickMode::New
                };
                self.select_compose_files(
                    &dropped
                        .iter()
                        .map(|f| f.path().to_owned())
                        .collect::<Vec<_>>(),
                );
            }
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.confirm = None;
            if self.pending.is_none() {
                self.new_resource = None;
            }
        }
        if !self.opened && !cfg!(windows) {
            self.opened = true;
            self.submit(runtime, Action::List(self.kind));
        }
        if self.confirm.is_some() {
            ui.disable();
        }
        egui::Panel::top("docker-heading")
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
                            if self.compose {
                                "Projects"
                            } else {
                                self.kind.label()
                            },
                            "Docker and Compose, powered by Smol.",
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.compose && !cfg!(windows) {
                            if ui
                                .add_enabled(
                                    self.pending.is_none(),
                                    design::primary("+  Open project"),
                                )
                                .clicked()
                            {
                                self.pick_mode = PickMode::New;
                                self.file_picker.open_compose(
                                    frame,
                                    self.compose_files.first().map(String::as_str).unwrap_or(""),
                                    &ctx,
                                );
                            }
                        } else if matches!(self.kind, Kind::Images | Kind::Volumes)
                            && !cfg!(windows)
                            && ui
                                .add_enabled(
                                    self.pending.is_none(),
                                    design::primary(if self.kind == Kind::Images {
                                        "+  Pull image"
                                    } else {
                                        "+  Create volume"
                                    }),
                                )
                                .clicked()
                        {
                            self.resource_input.clear();
                            self.resource_error = None;
                            self.new_resource = Some(self.kind);
                        }
                        if ui
                            .add_enabled(self.pending.is_none(), egui::Button::new("Refresh"))
                            .clicked()
                        {
                            self.refresh(runtime);
                        }
                        if self.pending.is_some() {
                            ui.spinner();
                        }
                        ui.add_enabled_ui(self.pending.is_none(), |ui| {
                            ui.menu_button("Connection", |ui| {
                                if ui.button("Check engine status").clicked() {
                                    self.submit(runtime, Action::Status);
                                    ui.close();
                                }
                                if ui.button("Set up Docker with Smol…").clicked() {
                                    self.confirm = Some(Action::Configure);
                                    ui.close();
                                }
                            });
                        });
                    });
                });
                if let Some(error) = &self.error {
                    ui.add_space(10.0);
                    design::error_notice(
                        ui,
                        if error.contains("context not found") {
                            "Docker isn’t connected to Smol yet."
                        } else {
                            "Docker couldn’t complete this request."
                        },
                        error,
                    );
                }
            });
        if !self.text.is_empty() {
            egui::Panel::bottom("docker-output")
                .resizable(true)
                .default_size(210.0)
                .min_size(100.0)
                .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(18))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        design::eyebrow(ui, "OUTPUT");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Close").clicked() {
                                self.text.clear();
                            }
                            if ui.small_button("Copy").clicked() {
                                ctx.copy_text(self.text.clone());
                            }
                        });
                    });
                    egui::ScrollArea::both()
                        .id_salt("docker-output-scroll")
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(&self.text).monospace().size(12.0))
                                    .selectable(true),
                            );
                        });
                });
        }
        if !self.compose
            && matches!(self.kind, Kind::Images | Kind::Volumes | Kind::Networks)
            && !cfg!(windows)
        {
            self.resource_list(ui, runtime);
        }
        if self.compose && !cfg!(windows) {
            self.project_list(ui);
        }
        if self.kind == Kind::Containers && !self.compose && !cfg!(windows) {
            egui::Panel::left("container-list")
                .resizable(true)
                .default_size(248.0)
                .min_size(224.0)
                .max_size(380.0)
                .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
                .show(ui, |ui| {
                    design::search(ui, &mut self.query, "Search containers…");
                    ui.add_space(12.0);
                    design::eyebrow(ui, &format!("CONTAINERS  /  {}", self.rows.len()));
                    ui.add_space(8.0);
                    let query = self.query.to_lowercase();
                    let visible: Vec<_> = self
                        .rows
                        .iter()
                        .enumerate()
                        .filter(|(_, r)| {
                            ["Names", "Image", "ID"]
                                .iter()
                                .any(|key| text(r, key).to_lowercase().contains(&query))
                        })
                        .map(|(index, _)| index)
                        .collect();
                    if visible.is_empty() && self.valid {
                        ui.label(
                            RichText::new(if self.rows.is_empty() {
                                "No containers yet"
                            } else {
                                "No matching containers"
                            })
                            .small()
                            .color(MUTED),
                        );
                    }
                    if self.pending.is_some() {
                        ui.disable();
                    }
                    egui::ScrollArea::vertical()
                        .id_salt("container-list-scroll")
                        .show_rows(ui, 60.0, visible.len(), |ui, range| {
                            for &index in &visible[range] {
                                let row = self.rows[index].clone();
                                let id = text(&row, "ID");
                                if design::resource_row(
                                    ui,
                                    self.selected.as_ref() == Some(&id),
                                    &text(&row, "Names"),
                                    &text(&row, "Image"),
                                    &text(&row, "State"),
                                    design::Icon::Containers,
                                )
                                .clicked()
                                {
                                    self.selected = Some(id.clone());
                                    self.details = None;
                                    self.stats = None;
                                    self.live_logs.reset();
                                    self.container_tab = ContainerTab::Overview;
                                    self.submit(runtime, Action::Inspect(id));
                                }
                            }
                        });
                });
        }
        egui::CentralPanel::default().frame(egui::Frame::new().fill(SURFACE).inner_margin(24)).show(ui,|ui| {
            if cfg!(windows){ui.label("The Docker API is available on macOS and Linux. Local and cloud machines are available on Windows.");return;}
            if self.compose && !self.compose_import && self.project_selected.is_some() {
                self.project_details(ui, runtime);
                return;
            }
            if self.compose {
                egui::ScrollArea::vertical().id_salt("compose-form").show(ui,|ui| {
                    ui.add_space(12.0);
                    ui.label(design::heading(if self.compose_name.is_some() { "Update project" } else { "Open a Compose project" }, 20.0));
                    if let Some(name) = &self.compose_name { ui.label(RichText::new(format!("Project: {name}")).color(MUTED)); }
                    ui.label(RichText::new("Files are applied in order. Later files override the base configuration.").color(MUTED));
                    ui.add_space(20.0);
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let mut move_file = None;
                        let mut remove = None;
                        let length = self.compose_files.len();
                        for (index, file) in self.compose_files.iter_mut().enumerate() {
                            if index > 0 { ui.add_space(10.0); }
                            let role = if index == 0 { "Base file".to_owned() } else { format!("Override {index}") };
                            let filename = std::path::Path::new(file.as_str()).file_name().and_then(|s| s.to_str()).unwrap_or("");
                            ui.add(egui::Label::new(RichText::new(if filename.is_empty() { role } else { format!("{role} · {filename}") }).small().color(MUTED)).truncate());
                            ui.horizontal(|ui| {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.add_enabled(length > 1, egui::Button::new("×")).on_hover_text("Remove file from this configuration").clicked() { remove = Some(index); }
                                    if ui.add_enabled(index + 1 < length, egui::Button::new("↓")).on_hover_text("Apply later").clicked() { move_file = Some((index,index+1)); }
                                    if ui.add_enabled(index > 0, egui::Button::new("↑")).on_hover_text("Apply earlier").clicked() { move_file = Some((index,index-1)); }
                                    if ui.add(egui::TextEdit::singleline(file).hint_text("Choose a file or paste its full path").desired_width(ui.available_width()).margin(egui::Margin::symmetric(10,9))).changed() { self.file_error = None; }
                                });
                            });
                        }
                        if let Some(index) = remove { self.compose_files.remove(index); }
                        if let Some((from,to)) = move_file { self.compose_files.swap(from,to); }
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            for (label, mode) in [("Choose files…", PickMode::Replace), ("Add files…", PickMode::Append)] {
                                if ui.add_enabled(self.pending.is_none(), egui::Button::new(label)).clicked() {
                                    self.pick_mode = mode;
                                    self.file_picker.open_compose(frame, self.compose_files.first().map(String::as_str).unwrap_or(""), &ctx);
                                }
                            }
                        });
                        if let Some(error) = &self.file_error { design::notice(ui, error); }
                        ui.add_space(16.0);
                        let source = self.compose_source();
                        let validation = source.validate();
                        if self.compose_files.iter().any(|p| !p.is_empty()) && let Err(error) = &validation {
                            ui.label(RichText::new(error).small().color(design::RED));
                        }
                        ui.add_enabled_ui(self.pending.is_none() && self.file_error.is_none() && validation.is_ok(), |ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui.add(design::primary("Apply project…")).clicked() { self.confirm = Some(Action::Compose { source: source.clone(), up: true }); }
                                if ui.button("Remove containers…").clicked() { self.confirm = Some(Action::Compose { source, up: false }); }
                            });
                        });
                    });
                    ui.add_space(16.0);
                    ui.label(RichText::new("Named volumes are retained when you remove a project.").small().color(MUTED));
                });
                return;
            }
            if matches!(self.kind, Kind::Images | Kind::Volumes | Kind::Networks) {
                self.resource_details(ui, runtime);
                return;
            }
            if self.kind == Kind::Containers && self.selected.is_some() {
                self.inspector(ui, runtime);
                return;
            }
            let query=self.query.to_lowercase();
            let visible: Vec<usize>=self.rows.iter().enumerate().filter(|(_,r)|["Names","Name","Repository","Image","ID"].iter().any(|key|text(r,key).to_lowercase().contains(&query))).map(|(i,_)|i).collect();
            if visible.is_empty() {
                ui.add_space(70.0);
                ui.vertical_centered(|ui| {
                    ui.heading(if !query.is_empty() && self.valid {"No matching resources"}else if self.valid && self.kind == Kind::Containers {"Run your first container"}else if self.valid {"Nothing here yet"}else{"Connect your Docker tools"});
                    ui.label(RichText::new(if !query.is_empty() && self.valid {"Try a different name or clear your search."}else if self.valid {"Use your Docker CLI, or open Compose to start a project."}else{"Set up Smol to use it with Docker, Buildx, and Compose."}).color(MUTED));
                    ui.add_space(16.0);
                    if !self.valid && ui.add_enabled(self.pending.is_none(),design::primary("Set up Docker with Smol…")).clicked(){self.confirm=Some(Action::Configure);}
                });
            }

        });
        self.resource_dialog(&ctx, runtime);
        if let Some(action) = self.confirm.clone() {
            let mut open = true;
            egui::Window::new("Confirm operation").anchor(egui::Align2::CENTER_CENTER,egui::Vec2::ZERO).default_width(440.0).open(&mut open).collapsible(false).resizable(false).show(&ctx,|ui| {
                match &action {
                    Action::Configure=>{ui.label("Register Smol’s on-demand Docker socket and select the smol context for your tools.");ui.add_space(8.0);ui.label("This changes your default Docker context and configures Buildx and Testcontainers.");}
                    Action::Delete(id)=>{ui.label(format!("Remove stopped container {id} and its writable filesystem?"));}
                    Action::StorageRemove { kind, id, .. } => {
                        ui.label(if *kind == Kind::Volumes { format!("Permanently delete volume “{id}” and all of its data?") } else { format!("Remove image {id} and its local tags from Smol?") });
                        ui.add_space(8.0);
                        ui.label(if *kind == Kind::Volumes { "This cannot be undone. Containers that reference the volume must be removed first." } else { "Downloaded layers may remain cached. This does not delete the image from its registry." });
                    }
                    Action::Compose { source, up } => {
                        ui.label(format!("{} {}?", if *up { "Apply" } else { "Remove containers for" }, source.name.as_deref().unwrap_or("this project")));
                        ui.add_space(8.0);
                        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| { for file in &source.files { ui.add(egui::Label::new(file.display().to_string()).wrap()); } });
                        ui.add_space(8.0);
                        ui.label(if *up { "This can build or pull images and start services. Studio will remember these files." } else { "Project containers and networks are removed. Named volumes and saved file locations are retained." });
                    }
                    Action::ForgetProject(name) => { ui.label(format!("Forget {name} in Studio? Its Compose files and named volumes are retained.")); }
                    _=>{}
                }
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    let (label, destructive) = match &action {
                        Action::StorageRemove { kind: Kind::Images, .. } => ("Remove image", true),
                        Action::StorageRemove { .. } => ("Delete volume", true),
                        Action::Delete(_) => ("Remove container", true),
                        Action::Compose { up: false, .. } => ("Remove containers", true),
                        Action::Compose { up: true, .. } => ("Apply project", false),
                        Action::ForgetProject(_) => ("Forget project", false),
                        _ => ("Connect Docker", false),
                    };
                    let button = design::primary(label).fill(if destructive { design::RED } else { design::ACCENT });
                    if ui.add_enabled(self.pending.is_none(),button).clicked(){self.confirm=None;self.submit(runtime,action);}
                    if ui.button("Cancel").clicked(){self.confirm=None;}
                });
            });
            if !open {
                self.confirm = None;
            }
        }
    }
}
fn text(row: &Value, key: &str) -> String {
    row[key].as_str().unwrap_or("").to_string()
}

fn count(n: usize, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}
