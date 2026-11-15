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
        }
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
                    }
                }
                Ok(Output::Text(text)) => self.text = text,
                Ok(Output::Completed) => {
                    self.text = "Operation completed.".into();
                    self.submit(runtime, Action::List(self.kind));
                }
                Err(e) => {
                    self.error = Some(e);
                    self.valid = false;
                }
            }
        }
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, runtime: &Runtime) {
        let ctx = ui.ctx().clone();
        egui::CentralPanel::default().frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(24)).show(ui, |ui| {
            if self.confirm.is_some() { ui.disable(); }
            ui.heading("Containers & Compose");
            ui.label("Docker tools connected to Smol. Each container runs in a machine.");
            if cfg!(windows) {
                ui.label("Smol's Docker API is currently available on macOS and Linux. Use the Local or Cloud workspace for machine management on Windows.");
                return;
            }
            if let Some(error) = &self.error { ui.colored_label(Color32::DARK_RED, error); }
            if self.pending.is_some() { ui.horizontal(|ui| { ui.spinner(); ui.label("Working…"); }); }
            ui.add_enabled_ui(self.pending.is_none(), |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Check engine status").clicked() { self.submit(runtime, Action::Status); }
                    if ui.button("Set up Docker with Smol…").clicked() { self.confirm = Some(Action::Configure); }
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    for kind in [Kind::Containers, Kind::Images, Kind::Volumes, Kind::Networks] {
                        if ui.selectable_label(self.kind == kind, kind.label()).clicked() { self.kind = kind; self.rows.clear(); self.valid = false; self.submit(runtime, Action::List(kind)); }
                    }
                    if ui.button("Refresh").clicked() { self.submit(runtime, Action::List(self.kind)); }
                });
            });
            ui.separator();
            let row_count = self.rows.len();
            egui::ScrollArea::vertical().id_salt("docker-inventory").max_height(260.0).show_rows(ui, 64.0, row_count, |ui, range| {
                for index in range { let row = self.rows[index].clone(); let row = &row;
                    let id = text(row, "ID");
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            let title = match self.kind { Kind::Containers => text(row, "Names"), Kind::Images => format!("{}:{}", text(row, "Repository"), text(row, "Tag")), _ => text(row, "Name") };
                            ui.label(RichText::new(title).strong());
                            let detail = match self.kind { Kind::Containers => format!("{} · {} · {}", text(row, "Image"), text(row, "Status"), text(row, "Ports")), Kind::Images => text(row, "Size"), _ => text(row, "Driver") };
                            ui.label(RichText::new(detail).small());
                        });
                        if self.kind == Kind::Containers {
                            ui.add_enabled_ui(self.valid && self.pending.is_none(), |ui| {
                                if text(row, "State") == "running" {
                                    if ui.button("Stop").clicked() { self.submit(runtime, Action::Stop(id.clone())); }
                                } else {
                                    if ui.button("Start").clicked() { self.submit(runtime, Action::Start(id.clone())); }
                                    if ui.button("Remove…").clicked() { self.confirm = Some(Action::Delete(id.clone())); }
                                }
                                if ui.button("Logs").clicked() { self.submit(runtime, Action::Logs(id)); }
                            });
                        }
                    });
                    ui.separator();
                }
            });
            if self.rows.is_empty() { ui.label(if self.valid { "No resources in this view." } else { "Refresh to load this view from Smol." }); }
            ui.add_space(16.0);
            ui.heading("Compose project");
            ui.label("Absolute path to compose.yaml");
            ui.text_edit_singleline(&mut self.compose_file);
            ui.add_enabled_ui(self.pending.is_none() && !self.compose_file.trim().is_empty(), |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Start project…").clicked() { self.confirm = Some(Action::Compose { file: self.compose_file.trim().into(), up: true }); }
                    if ui.button("Stop and remove project…").clicked() { self.confirm = Some(Action::Compose { file: self.compose_file.trim().into(), up: false }); }
                });
            });
            if !self.text.is_empty() {
                ui.separator();
                if ui.button("Copy output").clicked() { ctx.copy_text(self.text.clone()); }
                egui::ScrollArea::both().id_salt("docker-output").max_height(220.0).show(ui, |ui| { ui.add(egui::Label::new(RichText::new(&self.text).monospace()).selectable(true)); });
            }
        });
        if let Some(action) = self.confirm.clone() {
            let mut open = true;
            egui::Window::new("Confirm container operation").open(&mut open).collapsible(false).show(&ctx, |ui| {
                match &action {
                    Action::Configure => { ui.label("Register Smol's on-demand Docker socket and select the smol Docker context for your tools. This changes your default Docker context and configures Buildx and Testcontainers."); }
                    Action::Delete(id) => { ui.label(format!("Remove stopped container {id} and its writable filesystem?")); }
                    Action::Compose { file, up } => { ui.label(format!("{} project defined by {} on Smol?", if *up {"Start"} else {"Stop and remove"}, file.display())); ui.label(if *up {"This can build or pull images and start the project's services."} else {"Project containers and networks are removed. Named volumes are retained."}); }
                    _ => {}
                }
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.pending.is_none(), egui::Button::new("Continue")).clicked() { self.confirm = None; self.submit(runtime, action); }
                    if ui.button("Cancel").clicked() { self.confirm = None; }
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
