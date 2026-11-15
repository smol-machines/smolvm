use crate::design::{self, MUTED, SURFACE};
use eframe::egui::{self, Color32, RichText};
use serde_json::Value;
use smol_studio::{
    docker::{Action, DockerWorker, Kind, Output},
    runtime::Runtime,
};

pub struct DockerView {
    worker: DockerWorker,
    kind: Kind,
    rows: Vec<Value>,
    pending: Option<Action>,
    error: Option<String>,
    text: String,
    compose_file: String,
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
    pub fn new(ctx: &egui::Context) -> Self {
        let ctx = ctx.clone();
        Self {
            worker: DockerWorker::new(move || ctx.request_repaint()),
            kind: Kind::Containers,
            rows: vec![],
            pending: None,
            error: None,
            text: String::new(),
            compose_file: String::new(),
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
    pub fn modal_open(&self) -> bool {
        self.confirm.is_some()
    }
    pub fn mutating(&self) -> bool {
        self.pending.as_ref().is_some_and(Action::mutates)
    }
    fn submit(&mut self, runtime: &Runtime, action: Action) {
        if self.pending.is_some() {
            return;
        }
        match self.worker.submit(runtime.clone(), action.clone()) {
            Ok(()) => {
                self.pending = Some(action);
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }
    pub fn logic(&mut self, runtime: &Runtime) {
        while let Ok(done) = self.worker.events.try_recv() {
            self.pending = None;
            match done.result {
                Ok(Output::Rows(kind, rows)) => {
                    if self.kind == kind {
                        self.rows = rows;
                        self.valid = true;
                        if kind == Kind::Containers
                            && let Some(id) = self.selected.clone()
                        {
                            if self.rows.iter().any(|r| r["ID"].as_str() == Some(&id)) {
                                self.submit(runtime, Action::Inspect(id));
                            } else {
                                self.selected = None;
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
                    self.details = None;
                    self.stats = None;
                    self.text = "Operation completed.".into();
                    self.submit(runtime, Action::List(self.kind));
                }
                Err(e) => {
                    self.error = Some(e);
                    if matches!(done.action, Action::List(_)) || done.action.mutates() {
                        self.valid = false;
                    }
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
    fn inspector(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        ui.horizontal(|ui| {
            design::eyebrow(ui, "CONTAINER");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    self.selected = None;
                    self.details = None;
                    self.stats = None;
                }
            });
        });
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
            .show(ui, |ui| {
                ui.add_space(10.0);
                ui.add(egui::Label::new(design::heading(&details.name, 22.0)).truncate())
                    .on_hover_text(&details.name);
                ui.add(
                    egui::Label::new(RichText::new(&details.image).small().color(MUTED)).truncate(),
                )
                .on_hover_text(&details.image);
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
                    if ui.small_button("Copy ID").clicked() {
                        ui.ctx().copy_text(details.id.clone());
                    }
                });
                ui.add_space(20.0);
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
                    ui.label(format!("Project: {project}"));
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
    pub fn ui(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        let ctx = ui.ctx().clone();
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
                    .inner_margin(egui::Margin::symmetric(24, 20)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        design::section_title(
                            ui,
                            "Containers",
                            "Docker and Compose, powered by Smol.",
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(self.pending.is_none(), egui::Button::new("Refresh"))
                            .clicked()
                        {
                            self.submit(runtime, Action::List(self.kind));
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
                if self.pending.is_some() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Working…").small().color(MUTED));
                    });
                }
                ui.add_space(18.0);
                ui.add_enabled_ui(self.pending.is_none(), |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for kind in [
                            Kind::Containers,
                            Kind::Images,
                            Kind::Volumes,
                            Kind::Networks,
                        ] {
                            if ui
                                .selectable_label(!self.compose && self.kind == kind, kind.label())
                                .clicked()
                            {
                                self.compose = false;
                                self.kind = kind;
                                self.rows.clear();
                                self.valid = false;
                                self.submit(runtime, Action::List(kind));
                            }
                        }
                        if ui.selectable_label(self.compose, "Compose").clicked() {
                            self.compose = true;
                        }
                    });
                });
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
        if self.selected.is_some() && self.kind == Kind::Containers && !self.compose {
            egui::Panel::right("container-inspector")
                .resizable(true)
                .default_size(330.0)
                .min_size(290.0)
                .max_size(440.0)
                .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(20))
                .show(ui, |ui| self.inspector(ui, runtime));
        }
        egui::CentralPanel::default().frame(egui::Frame::new().fill(SURFACE).inner_margin(24)).show(ui,|ui| {
            if cfg!(windows){ui.label("The Docker API is available on macOS and Linux. Local and cloud machines are available on Windows.");return;}
            if self.compose {
                egui::ScrollArea::vertical().id_salt("compose-form").show(ui,|ui| {
                    ui.add_space(12.0);
                    ui.heading("Run a Compose project");
                    ui.label(RichText::new("Start your services from an existing Compose file.").color(MUTED));
                    ui.add_space(24.0);
                    design::card().show(ui,|ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new("Compose file").strong());
                        ui.add(egui::TextEdit::singleline(&mut self.compose_file).hint_text("/path/to/project/compose.yaml").desired_width(f32::INFINITY).margin(egui::Margin::symmetric(10,10)));
                        ui.label(RichText::new("Use the full path to your compose.yaml or docker-compose.yml file.").small().color(MUTED));
                        ui.add_space(16.0);
                        ui.add_enabled_ui(self.pending.is_none()&&!self.compose_file.trim().is_empty(),|ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui.add(design::primary("Start project…")).clicked(){self.confirm=Some(Action::Compose{file:self.compose_file.trim().into(),up:true});}
                                if ui.button("Stop and remove project…").clicked(){self.confirm=Some(Action::Compose{file:self.compose_file.trim().into(),up:false});}
                            });
                        });
                    });
                    ui.add_space(16.0);
                    ui.label(RichText::new("Named volumes are retained when you remove a project.").small().color(MUTED));
                });
                return;
            }
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.query).hint_text(format!("Search {}…",self.kind.label().to_lowercase())).desired_width(300.0).margin(egui::Margin::symmetric(10,9)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {ui.label(RichText::new(format!("{} {}",self.rows.len(),if self.rows.len()==1{"resource"}else{"resources"})).small().color(MUTED));});
            });
            ui.add_space(16.0);
            let query=self.query.to_lowercase();
            let visible: Vec<usize>=self.rows.iter().enumerate().filter(|(_,r)|["Names","Name","Repository","Image","ID"].iter().any(|key|text(r,key).to_lowercase().contains(&query))).map(|(i,_)|i).collect();
            if visible.is_empty() {
                ui.add_space(70.0);
                ui.vertical_centered(|ui| {
                    ui.heading(if self.valid {"Nothing here yet"}else{"Connect your Docker tools"});
                    ui.label(RichText::new(if self.valid {"Create resources with Docker, or start a Compose project."}else{"Set up Smol to use it with Docker, Buildx, and Compose."}).color(MUTED));
                    ui.add_space(16.0);
                    if !self.valid && ui.add_enabled(self.pending.is_none(),design::primary("Set up Docker with Smol…")).clicked(){self.confirm=Some(Action::Configure);}
                });
            }
            egui::ScrollArea::vertical().id_salt("docker-inventory").show_rows(ui,72.0,visible.len(),|ui,range| {
                for index in range {
                    let row=self.rows[visible[index]].clone();
                    let id=text(&row,"ID");
                    let title=match self.kind {Kind::Containers=>text(&row,"Names"),Kind::Images=>format!("{}:{}",text(&row,"Repository"),text(&row,"Tag")),_=>text(&row,"Name")};
                    let detail=match self.kind {Kind::Containers=>format!("{}  ·  {}",text(&row,"Image"),text(&row,"Status")),Kind::Images=>text(&row,"Size"),_=>text(&row,"Driver")};
                    egui::Frame::new().fill(Color32::WHITE).stroke(egui::Stroke::new(1.0,design::LINE)).corner_radius(0).inner_margin(14).show(ui,|ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let text_width=(ui.available_width()-if self.kind==Kind::Containers{240.0}else{0.0}).max(100.0);
                            ui.allocate_ui_with_layout(egui::vec2(text_width,44.0),egui::Layout::top_down(egui::Align::LEFT),|ui| {
                                ui.add(egui::Label::new(RichText::new(&title).strong()).truncate()).on_hover_text(&title);
                                ui.add(egui::Label::new(RichText::new(&detail).small().color(MUTED)).truncate()).on_hover_text(&detail);
                            });
                            if self.kind==Kind::Containers {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                                    ui.add_enabled_ui(self.valid&&self.pending.is_none(),|ui| {
                                        if ui.button("Inspect").clicked(){self.selected=Some(id.clone());self.details=None;self.stats=None;self.submit(runtime,Action::Inspect(id.clone()));}
                                        if text(&row,"State")=="running" {
                                            if ui.button("Stop").clicked(){self.submit(runtime,Action::Stop(id.clone()));}
                                        } else {
                                            ui.menu_button("More",|ui|{if ui.button(RichText::new("Remove…").color(design::RED)).clicked(){self.confirm=Some(Action::Delete(id.clone()));ui.close();}});
                                            if ui.add(design::primary("Start")).clicked(){self.submit(runtime,Action::Start(id.clone()));}
                                        }
                                    });
                                });
                            }
                        });
                    });
                }
            });
        });
        if let Some(action) = self.confirm.clone() {
            let mut open = true;
            egui::Window::new("Confirm container operation").anchor(egui::Align2::CENTER_CENTER,egui::Vec2::ZERO).default_width(440.0).open(&mut open).collapsible(false).resizable(false).show(&ctx,|ui| {
                match &action {
                    Action::Configure=>{ui.label("Register Smol’s on-demand Docker socket and select the smol context for your tools.");ui.add_space(8.0);ui.label("This changes your default Docker context and configures Buildx and Testcontainers.");}
                    Action::Delete(id)=>{ui.label(format!("Remove stopped container {id} and its writable filesystem?"));}
                    Action::Compose{file,up}=>{ui.label(format!("{} the project defined by {}?",if *up{"Start"}else{"Stop and remove"},file.display()));ui.add_space(8.0);ui.label(if *up{"This can build or pull images and start the project’s services."}else{"Project containers and networks are removed. Named volumes are retained."});}
                    _=>{}
                }
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.pending.is_none(),design::primary("Continue")).clicked(){self.confirm=None;self.submit(runtime,action);}
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
