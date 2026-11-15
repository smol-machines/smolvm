use crate::design::{self, MUTED};
use eframe::egui::{self, Color32, RichText};
use serde_json::Value;
use smol_studio::{
    docker::{Action, DockerWorker, Kind, Output, ProjectAction},
    runtime::Runtime,
};

pub struct DockerView {
    worker: DockerWorker,
    kind: Kind,
    rows: Vec<Value>,
    storage_selected: Option<String>,
    storage: Option<smol_studio::storage::Details>,
    new_resource: Option<Kind>,
    resource_input: String,
    pending: Option<Action>,
    error: Option<String>,
    text: String,
    activity: String,
    compose_file: String,
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
    terminal: Option<crate::terminal_ui::TerminalWindow>,
}
impl DockerView {
    fn select_compose_file(&mut self, path: &std::path::Path) {
        self.compose_import = true;
        match path.to_str().filter(|_| path.is_absolute()) {
            Some(path) => {
                self.compose_file = path.to_owned();
                self.file_error = None;
            }
            None => self.file_error = Some("Choose a file with an absolute, UTF-8 path.".into()),
        }
    }

    pub fn new(ctx: &egui::Context) -> Self {
        let ctx = ctx.clone();
        Self {
            worker: DockerWorker::new(move || ctx.request_repaint()),
            kind: Kind::Containers,
            rows: vec![],
            storage_selected: None,
            storage: None,
            new_resource: None,
            resource_input: String::new(),
            pending: None,
            error: None,
            text: String::new(),
            activity: "Docker context: smol".into(),
            compose_file: String::new(),
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
        self.storage_selected = None;
        self.details = None;
        self.stats = None;
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
                Ok(Output::Storage(details)) => {
                    if self.kind == details.kind
                        && self.storage_selected.as_ref() == Some(&details.id)
                    {
                        self.storage = Some(details);
                    }
                }
                Ok(Output::Projects(projects)) => {
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
                        if matches!(kind, Kind::Images | Kind::Volumes) {
                            let key = if kind == Kind::Images { "ID" } else { "Name" };
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
                            self.storage = None;
                            if let Some(id) = self.storage_selected.clone() {
                                self.submit(runtime, Action::StorageInspect { kind, id });
                            }
                        }
                        if kind == Kind::Containers {
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
                Ok(Output::Completed) => {
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
                        _ => "Operation completed.",
                    }
                    .into();
                    self.details = None;
                    self.storage = None;
                    self.stats = None;
                    self.text.clear();
                    self.refresh(runtime);
                }
                Err(e) => {
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
    pub fn terminal_ui(&mut self, ctx: &egui::Context) {
        if let Some(terminal) = &mut self.terminal
            && !terminal.ui(ctx)
        {
            self.terminal = None;
        }
    }
    fn storage_list(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        egui::Panel::left("storage-list")
            .resizable(true)
            .default_size(280.0)
            .min_size(224.0)
            .max_size(380.0)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
            .show(ui, |ui| {
                design::search(
                    ui,
                    &mut self.query,
                    &format!("Search {}…", self.kind.label().to_lowercase()),
                );
                ui.add_space(12.0);
                design::eyebrow(ui, &self.kind.label().to_uppercase());
                ui.add_space(8.0);
                let query = self.query.to_lowercase();
                let mut seen = std::collections::HashSet::new();
                let rows: Vec<_> = self
                    .rows
                    .iter()
                    .filter(|r| {
                        ["Name", "Repository", "Tag", "ID"]
                            .iter()
                            .any(|key| text(r, key).to_lowercase().contains(&query))
                    })
                    .filter(|r| {
                        seen.insert(text(
                            r,
                            if self.kind == Kind::Images {
                                "ID"
                            } else {
                                "Name"
                            },
                        ))
                    })
                    .cloned()
                    .collect();
                if rows.is_empty() {
                    ui.label(
                        RichText::new(if !self.valid {
                            "Refresh to load resources."
                        } else if self.query.is_empty() {
                            "Nothing here yet"
                        } else {
                            "No matching resources"
                        })
                        .small()
                        .color(MUTED),
                    );
                }
                if self.pending.is_some() {
                    ui.disable();
                }
                egui::ScrollArea::vertical()
                    .id_salt("storage-list-scroll")
                    .show_rows(ui, 60.0, rows.len(), |ui, range| {
                        for row in &rows[range] {
                            let id = text(
                                row,
                                if self.kind == Kind::Images {
                                    "ID"
                                } else {
                                    "Name"
                                },
                            );
                            let title = if self.kind == Kind::Images
                                && text(row, "Repository") != "<none>"
                            {
                                format!("{}:{}", text(row, "Repository"), text(row, "Tag"))
                            } else {
                                id.clone()
                            };
                            let subtitle = text(
                                row,
                                if self.kind == Kind::Images {
                                    "Size"
                                } else {
                                    "Driver"
                                },
                            );
                            if design::resource_row(
                                ui,
                                self.storage_selected.as_ref() == Some(&id),
                                &title,
                                &subtitle,
                                "",
                                if self.kind == Kind::Images {
                                    design::Icon::Image
                                } else {
                                    design::Icon::Volume
                                },
                            )
                            .clicked()
                            {
                                self.storage_selected = Some(id.clone());
                                self.storage = None;
                                self.submit(
                                    runtime,
                                    Action::StorageInspect {
                                        kind: self.kind,
                                        id,
                                    },
                                );
                            }
                        }
                    });
            });
    }
    fn storage_details(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        let Some(details) = self.storage.clone() else {
            ui.add_space(80.0);
            ui.vertical_centered(|ui| {
                if self.pending.is_some() {
                    ui.spinner();
                }
                ui.heading(if self.kind == Kind::Images {
                    "Your local images"
                } else {
                    "Persistent storage"
                });
                ui.label(
                    RichText::new(
                        "Select a resource to inspect it and see which containers use it.",
                    )
                    .color(MUTED),
                );
            });
            return;
        };
        let enabled = self.pending.is_none() && self.valid;
        egui::ScrollArea::vertical().id_salt("storage-detail-scroll").auto_shrink([false,false]).show(ui, |ui| {
            let title = if details.kind == Kind::Images { details.fields.first().map(|(_,v)|v.lines().next().unwrap_or("Image")).unwrap_or("Image") } else { &details.id };
            design::resource_heading(ui, if details.kind == Kind::Images { design::Icon::Image } else { design::Icon::Volume }, title, if details.kind == Kind::Images { "Container image" } else { "Persistent volume" });
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(enabled && details.users.is_empty(), egui::Button::new(RichText::new("Remove…").color(design::RED))).clicked() {
                    self.confirm=Some(Action::StorageRemove {kind:details.kind,id:details.id.clone(),created:details.created.clone()});
                }
                if ui.button(if details.kind == Kind::Images { "Copy image ID" } else { "Copy volume name" }).clicked() { ui.ctx().copy_text(details.id.clone()); }
            });
            ui.add_space(12.0); ui.separator(); ui.add_space(12.0);
            design::eyebrow(ui,"USED BY CONTAINERS");
            if details.users.is_empty() { ui.label(RichText::new("No containers currently reference this resource.").small().color(MUTED)); }
            else { ui.label(RichText::new("Includes stopped containers. Remove these references before deleting the resource.").small().color(MUTED)); }
            for user in &details.users {
                ui.add_enabled_ui(enabled, |ui| {
                    if design::resource_row(ui,false,&user.name,&user.state,&user.state,design::Icon::Containers).clicked() {
                        self.kind=Kind::Containers;self.selected=Some(user.id.clone());self.details=None;self.query.clear();
                        self.submit(runtime,Action::List(Kind::Containers));
                    }
                });
            }
            ui.add_space(20.0); design::eyebrow(ui,"DETAILS");
            ui.add_space(8.0);
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                for (index, (label, value)) in details.fields.iter().enumerate() {
                    if index > 0 { ui.add_space(6.0); ui.separator(); ui.add_space(6.0); }
                    ui.horizontal_top(|ui| {
                        ui.add_sized([88.0, 18.0], egui::Label::new(RichText::new(label).size(12.0).color(MUTED)).halign(egui::Align::LEFT));
                        ui.add(egui::Label::new(RichText::new(if value.is_empty() { "Not reported" } else { value }).size(13.0)).wrap().selectable(true));
                    });
                }
            });
        });
    }
    fn resource_dialog(&mut self, ctx: &egui::Context, runtime: &Runtime) {
        let Some(kind) = self.new_resource else {
            return;
        };
        let mut open = true;
        let mut submit = false;
        let mut cancel = false;
        egui::Window::new(if kind == Kind::Images {
            "Pull image"
        } else {
            "Create volume"
        })
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .collapsible(false)
        .resizable(false)
        .default_width(420.0)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(if kind == Kind::Images {
                "Image reference"
            } else {
                "Volume name"
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.resource_input)
                    .desired_width(f32::INFINITY)
                    .hint_text(if kind == Kind::Images {
                        "alpine:3.22"
                    } else {
                        "project-data"
                    }),
            );
            let valid = if kind == Kind::Images {
                smol_studio::storage::validate_reference(self.resource_input.trim())
            } else {
                smol_studio::storage::validate_volume(self.resource_input.trim())
            };
            if !self.resource_input.is_empty()
                && let Err(error) = &valid
            {
                ui.label(RichText::new(error).small().color(design::RED));
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                submit = ui
                    .add_enabled(
                        valid.is_ok() && self.pending.is_none(),
                        design::primary(if kind == Kind::Images {
                            "Pull image"
                        } else {
                            "Create volume"
                        }),
                    )
                    .clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if submit {
            self.new_resource = None;
            let input = self.resource_input.trim().to_owned();
            self.submit(
                runtime,
                if kind == Kind::Images {
                    Action::PullImage(input)
                } else {
                    Action::CreateVolume(input)
                },
            );
        } else if !open || cancel || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.new_resource = None;
        }
    }
    fn project_list(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("compose-project-list")
            .resizable(true)
            .default_size(280.0)
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
                if ui.add_enabled(enabled && project.containers.iter().any(|c| c.can_start()), design::primary("Start containers"))
                    .on_hover_text("Starts existing stopped service containers. Apply your Compose file for dependency ordering, hooks, or configuration changes.").clicked() {
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
        egui::ScrollArea::vertical()
            .id_salt("container-inspector-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                design::resource_heading(
                    ui,
                    design::Icon::Containers,
                    &details.name,
                    &details.image,
                );
                ui.add_space(10.0);
                design::badge(ui, &details.state);
                if let Some(health) = &details.health {
                    ui.label(format!("Health: {health}"));
                }
                if details.state != "running"
                    && let Some(code) = details.exit_code
                {
                    ui.label(format!("Exit code: {code}"));
                }
                if details.oom_killed {
                    design::notice(ui, "Stopped after running out of memory.");
                }
                if !details.error.is_empty() {
                    design::notice(ui, &details.error);
                }
                let enabled = self.valid && self.pending.is_none();
                ui.add_space(12.0);
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            enabled && details.state == "running",
                            design::primary("Terminal"),
                        )
                        .clicked()
                    {
                        match crate::terminal_ui::TerminalWindow::for_container(
                            ui.ctx(),
                            &details.id,
                            &details.name,
                        ) {
                            Ok(t) => self.terminal = Some(t),
                            Err(e) => self.error = Some(e),
                        }
                    }
                    if ui.add_enabled(enabled, egui::Button::new("Logs")).clicked() {
                        self.submit(runtime, Action::Logs(details.id.clone()));
                    }
                    if details.state == "running" {
                        if ui.add_enabled(enabled, egui::Button::new("Stop")).clicked() {
                            self.submit(runtime, Action::Stop(details.id.clone()));
                        }
                    } else if ui.add_enabled(enabled, design::primary("Start")).clicked() {
                        self.submit(runtime, Action::Start(details.id.clone()));
                    }
                    ui.add_enabled_ui(enabled, |ui| {
                        ui.menu_button("More", |ui| {
                            if ui.button("Copy container ID").clicked() {
                                ui.ctx().copy_text(details.id.clone());
                                ui.close();
                            }
                            if details.state != "running" {
                                ui.separator();
                                if ui
                                    .button(RichText::new("Remove container…").color(design::RED))
                                    .clicked()
                                {
                                    self.confirm = Some(Action::Delete(details.id.clone()));
                                    ui.close();
                                }
                            }
                        });
                    });
                });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(16.0);
                design::eyebrow(ui, "PUBLISHED PORTS");
                if details.ports.is_empty() {
                    ui.label(
                        RichText::new("No ports published to this computer.")
                            .small()
                            .color(MUTED),
                    );
                }
                for port in &details.ports {
                    ui.push_id((&port.container, &port.host_ip, &port.host_port), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{}:{} → {}",
                                port.host_ip, port.host_port, port.container
                            ))
                            .monospace()
                            .size(11.0),
                        );
                        if let Some(url) = port.browser_url() {
                            ui.hyperlink_to("Open in browser", url).on_hover_text(
                                "Opens this TCP port using HTTP. The service must speak HTTP.",
                            );
                        }
                    });
                }
                ui.add_space(20.0);
                design::eyebrow(ui, "RESOURCE USAGE");
                if ui
                    .add_enabled(
                        enabled && details.state == "running",
                        egui::Button::new("Measure now"),
                    )
                    .clicked()
                {
                    self.submit(runtime, Action::Stats(details.id.clone()));
                }
                if let Some(stats) = &self.stats {
                    for (label, key) in [
                        ("Machine CPU", "CPUPerc"),
                        ("Guest memory / limit", "MemUsage"),
                    ] {
                        if let Some(value) = stats[key].as_str() {
                            ui.label(format!("{label}: {value}"));
                        }
                    }
                    ui.label(
                        RichText::new(
                            "Network, disk I/O, and process counts are not available yet.",
                        )
                        .small()
                        .color(MUTED),
                    );
                    ui.label(
                        RichText::new("Snapshot · not continuously polled")
                            .small()
                            .color(MUTED),
                    );
                }
                ui.add_space(20.0);
                design::eyebrow(ui, "MOUNTS");
                if details.mounts.is_empty() {
                    ui.label(
                        RichText::new("No shared folders or volumes.")
                            .small()
                            .color(MUTED),
                    );
                }
                for mount in &details.mounts {
                    ui.label(RichText::new(&mount.target).monospace().size(12.0));
                    ui.add(
                        egui::Label::new(RichText::new(&mount.source).small().color(MUTED)).wrap(),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} · {}",
                            mount.kind,
                            if mount.writable {
                                "Read & write"
                            } else {
                                "Read only"
                            }
                        ))
                        .small()
                        .color(MUTED),
                    );
                    ui.add_space(8.0);
                }
                if let Some(project) = &details.project {
                    ui.add_space(12.0);
                    design::eyebrow(ui, "COMPOSE");
                    if ui.link(format!("Project: {project}")).clicked() && self.pending.is_none() {
                        self.compose = true;
                        self.compose_import = false;
                        self.project_selected = Some(project.clone());
                        self.submit(runtime, Action::Projects);
                    }
                    if let Some(service) = &details.service {
                        ui.label(format!("Service: {service}"));
                    }
                }
                ui.add_space(16.0);
                ui.collapsing("Command & diagnostics", |ui| {
                    ui.label(format!("Restarts: {}", details.restarts));
                    for arg in &details.command {
                        ui.add(egui::Label::new(RichText::new(arg).monospace().size(11.0)).wrap());
                    }
                });
            });
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, runtime: &Runtime, frame: &eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(Some(file)) = self.file_picker.poll(&ctx) {
            self.select_compose_file(file.path());
        }
        if self.compose && ui.is_enabled() && self.pending.is_none() {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            if !dropped.is_empty() {
                if dropped.len() == 1 {
                    self.select_compose_file(dropped[0].path());
                } else {
                    self.file_error = Some("Drop one Compose file at a time.".into());
                    self.compose_import = true;
                }
            }
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.confirm = None;
            self.new_resource = None;
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
                                self.compose_import = true;
                                self.file_picker
                                    .open_compose(frame, &self.compose_file, &ctx);
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
        if !self.compose && matches!(self.kind, Kind::Images | Kind::Volumes) && !cfg!(windows) {
            self.storage_list(ui, runtime);
        }
        if self.compose && !cfg!(windows) {
            self.project_list(ui);
        }
        if self.kind == Kind::Containers && !self.compose && !cfg!(windows) {
            egui::Panel::left("container-list")
                .resizable(true)
                .default_size(280.0)
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
                                    self.submit(runtime, Action::Inspect(id));
                                }
                            }
                        });
                });
        }
        egui::CentralPanel::default().frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(24)).show(ui,|ui| {
            if cfg!(windows){ui.label("The Docker API is available on macOS and Linux. Local and cloud machines are available on Windows.");return;}
            if self.compose && !self.compose_import && self.project_selected.is_some() {
                self.project_details(ui, runtime);
                return;
            }
            if self.compose {
                egui::ScrollArea::vertical().id_salt("compose-form").show(ui,|ui| {
                    ui.add_space(12.0);
                    ui.heading("Open a Compose project");
                    ui.label(RichText::new("Choose or drop a Compose file to create or update its services.").color(MUTED));
                    ui.add_space(24.0);
                    design::card().show(ui,|ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Compose file").strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add_enabled(self.pending.is_none(), egui::Button::new("Choose file…")).clicked() {
                                    self.file_picker.open_compose(frame, &self.compose_file, &ctx);
                                }
                            });
                        });
                        if ui.add(egui::TextEdit::singleline(&mut self.compose_file).hint_text("Choose a file or paste its full path").desired_width(f32::INFINITY).margin(egui::Margin::symmetric(10,10))).changed() {
                            self.file_error = None;
                        }
                        if let Some(error) = &self.file_error { design::notice(ui, error); }
                        ui.label(RichText::new("Services start only when you apply the file.").small().color(MUTED));
                        ui.add_space(16.0);
                        ui.add_enabled_ui(self.pending.is_none() && self.file_error.is_none() && !self.compose_file.trim().is_empty(),|ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui.add(design::primary("Apply Compose file…")).clicked(){self.confirm=Some(Action::Compose{file:self.compose_file.clone().into(),up:true});}
                                if ui.button("Stop and remove project…").clicked(){self.confirm=Some(Action::Compose{file:self.compose_file.clone().into(),up:false});}
                            });
                        });
                    });
                    ui.add_space(16.0);
                    ui.label(RichText::new("Named volumes are retained when you remove a project.").small().color(MUTED));
                });
                return;
            }
            if matches!(self.kind, Kind::Images | Kind::Volumes) {
                self.storage_details(ui, runtime);
                return;
            }
            if self.kind == Kind::Containers && self.selected.is_some() {
                self.inspector(ui, runtime);
                return;
            }
            if self.kind == Kind::Networks {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.query).hint_text(format!("Search {}…",self.kind.label().to_lowercase())).desired_width(300.0).margin(egui::Margin::symmetric(10,9)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {ui.label(RichText::new(format!("{} {}",self.rows.len(),if self.rows.len()==1{"resource"}else{"resources"})).small().color(MUTED));});
            });
            ui.add_space(16.0);
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
            if self.kind == Kind::Networks {
                ui.horizontal(|ui| {
                    design::eyebrow(ui, "NAME");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        design::eyebrow(ui, "DRIVER");
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical().id_salt("docker-inventory").show_rows(ui, 44.0, visible.len(), |ui, range| {
                    for index in range {
                        let row = &self.rows[visible[index]];
                        let title = text(row,"Name");
                        let detail = text(row,"Driver");
                        ui.allocate_ui(egui::vec2(ui.available_width(), 38.0), |ui| {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(detail).small().color(MUTED));
                                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                    ui.add(egui::Label::new(&title).truncate()).on_hover_text(&title);
                                });
                            });
                        });
                        ui.separator();
                    }
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
                    Action::Compose{file,up}=>{ui.label(format!("{} the project defined by {}?",if *up{"Start"}else{"Stop and remove"},file.display()));ui.add_space(8.0);ui.label(if *up{"This can build or pull images and start the project’s services."}else{"Project containers and networks are removed. Named volumes are retained."});}
                    _=>{}
                }
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    let (label, destructive) = match &action {
                        Action::StorageRemove { kind: Kind::Images, .. } => ("Remove image", true),
                        Action::StorageRemove { .. } => ("Delete volume", true),
                        Action::Delete(_) => ("Remove container", true),
                        Action::Compose { up: false, .. } => ("Remove project", true),
                        Action::Compose { up: true, .. } => ("Apply Compose file", false),
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
