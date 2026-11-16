use crate::design::{self, MUTED};
use eframe::egui::{self, Color32, RichText};
use smol_studio::log_stream::{LogStream, Status};

pub struct LiveLogs {
    id: String,
    stream: Option<LogStream>,
    revision: u64,
    text: String,
    status: Status,
    discarded: bool,
    paused: bool,
    visible: bool,
    filter: String,
}
impl Default for LiveLogs {
    fn default() -> Self {
        Self {
            id: String::new(),
            stream: None,
            revision: 0,
            text: String::new(),
            status: Status::Following,
            discarded: false,
            paused: false,
            visible: false,
            filter: String::new(),
        }
    }
}
impl LiveLogs {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
        if !visible {
            self.stream = None;
        }
    }
    pub fn show(&mut self, ui: &mut egui::Ui, id: &str, enabled: bool) {
        let ctx = ui.ctx().clone();
        self.show_reader(
            ui,
            &format!("container:{id}"),
            enabled,
            "Waiting for container output…",
            "Recent output · starts with the last 200 lines",
            || {
                LogStream::container(id, move || {
                    ctx.request_repaint_after(std::time::Duration::from_millis(33))
                })
            },
        );
    }
    pub fn show_project(
        &mut self,
        ui: &mut egui::Ui,
        name: &str,
        service: Option<&str>,
        enabled: bool,
    ) {
        let ctx = ui.ctx().clone();
        self.show_reader(
            ui,
            &format!("project:{name}:{service:?}"),
            enabled,
            "Waiting for service output…",
            "Recent output · starts with the last 200 lines per container",
            || {
                LogStream::project(name, service, move || {
                    ctx.request_repaint_after(std::time::Duration::from_millis(33))
                })
            },
        );
    }
    pub fn show_machine(
        &mut self,
        ui: &mut egui::Ui,
        runtime: &smol_studio::runtime::Runtime,
        name: &str,
        enabled: bool,
    ) {
        let ctx = ui.ctx().clone();
        self.show_reader(
            ui,
            &format!("machine:{name}"),
            enabled,
            "Waiting for workload output…",
            "Recent output · starts with the last 200 lines",
            || {
                LogStream::machine(runtime, name, move || {
                    ctx.request_repaint_after(std::time::Duration::from_millis(33))
                })
            },
        );
    }
    fn show_reader(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        enabled: bool,
        empty_hint: &str,
        history_hint: &str,
        start: impl FnOnce() -> Result<LogStream, String>,
    ) {
        if self.id != id {
            let visible = self.visible;
            self.reset();
            self.visible = visible;
            self.id = id.to_owned();
        }
        if self.visible && enabled && !self.paused && self.stream.is_none() {
            match start() {
                Ok(stream) => {
                    self.stream = Some(stream);
                    self.revision = 0;
                    self.status = Status::Following;
                    self.text.clear();
                    self.discarded = false;
                }
                Err(error) => {
                    self.status = Status::Failed(error);
                    self.paused = true;
                }
            }
        }
        if let Some(stream) = &self.stream
            && let Some(snapshot) = stream.snapshot_after(self.revision)
        {
            self.revision = snapshot.revision;
            self.text = snapshot.text;
            self.status = snapshot.status;
            self.discarded = snapshot.discarded;
        }
        ui.horizontal(|ui| {
            let label = if self.paused && !matches!(self.status, Status::Failed(_)) {
                "Updates paused".into()
            } else {
                match &self.status {
                    Status::Following => "Live output".into(),
                    Status::Finished(0) => "Log stream ended".into(),
                    Status::Finished(code) => format!("Log command exited ({code})"),
                    Status::Failed(_) => "Log connection failed".into(),
                }
            };
            ui.label(RichText::new(label).size(11.5).color(MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !self.paused && self.stream.is_some() && self.status == Status::Following {
                    if ui.button("Pause updates").clicked() {
                        self.paused = true;
                        self.stream = None;
                    }
                } else if ui
                    .add_enabled(enabled, egui::Button::new("Follow logs"))
                    .clicked()
                {
                    self.paused = false;
                    self.stream = None;
                    ui.ctx().request_repaint();
                }
                if ui
                    .add_enabled(!self.text.is_empty(), egui::Button::new("Copy all"))
                    .clicked()
                {
                    ui.ctx().copy_text(self.text.clone());
                }
            });
        });
        if let Status::Failed(error) = &self.status {
            design::error_notice(ui, "Logs could not be followed.", error);
        }
        ui.label(RichText::new(history_hint).size(11.0).color(MUTED));
        ui.add_space(8.0);
        design::search(ui, &mut self.filter, "Filter log lines…");
        ui.add_space(12.0);
        if self.text.is_empty() {
            ui.label(
                RichText::new(if self.status == Status::Following && !self.paused {
                    empty_hint
                } else {
                    "No output received."
                })
                .color(MUTED),
            );
            return;
        }
        let query = self.filter.to_lowercase();
        let lines: Vec<_> = self
            .text
            .lines()
            .enumerate()
            .filter(|(_, line)| query.is_empty() || line.to_lowercase().contains(&query))
            .collect();
        if lines.is_empty() {
            ui.label(RichText::new("No log lines match this filter.").color(MUTED));
            return;
        }
        ui.label(
            RichText::new(format!(
                "{} {}{}",
                lines.len(),
                if lines.len() == 1 { "line" } else { "lines" },
                if self.discarded {
                    " · older output discarded"
                } else {
                    ""
                }
            ))
            .size(11.0)
            .color(MUTED),
        );
        egui::Frame::new()
            .fill(Color32::WHITE)
            .stroke(egui::Stroke::new(1.0, design::LINE))
            .corner_radius(8)
            .inner_margin(12)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().interact_size.y = 18.0;
                egui::ScrollArea::both()
                    .id_salt(("live-log-lines", id))
                    .auto_shrink([false, true])
                    .stick_to_bottom(true)
                    .max_height((ui.clip_rect().bottom() - ui.cursor().top() - 16.0).max(100.0))
                    .show_rows(ui, 18.0, lines.len(), |ui, range| {
                        for index in range {
                            let (number, line) = lines[index];
                            ui.push_id(number, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!("{:>4}", number + 1))
                                            .monospace()
                                            .size(11.0)
                                            .color(MUTED),
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(line).monospace().size(12.0),
                                        )
                                        .wrap_mode(egui::TextWrapMode::Extend)
                                        .selectable(true),
                                    );
                                });
                            });
                        }
                    });
            });
    }
}
