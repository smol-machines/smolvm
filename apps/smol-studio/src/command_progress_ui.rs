use crate::design::{self, MUTED};
use eframe::egui::{self, Color32, RichText};
use smol_studio::command_progress::{Progress, Snapshot, Status};

#[derive(Default)]
pub struct ProgressView {
    snapshot: Option<Snapshot>,
    revision: u64,
    dismissed: Option<u64>,
    expanded: bool,
}
impl ProgressView {
    pub fn dismiss_finished(&mut self) {
        if let Some(snapshot) = &self.snapshot
            && snapshot.status != Status::Running
        {
            self.dismissed = Some(snapshot.id);
        }
    }
    pub fn panel(&mut self, ui: &mut egui::Ui, progress: &Progress) {
        if let Some(mut snapshot) = progress.snapshot_after(self.revision) {
            if self
                .snapshot
                .as_ref()
                .is_none_or(|last| last.id != snapshot.id)
            {
                self.expanded = true;
            }
            self.revision = snapshot.revision;
            snapshot.text = snapshot.text.replace("\r\n", "\n").replace('\r', "\n");
            self.snapshot = Some(snapshot);
        }
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        if self.dismissed == Some(snapshot.id) {
            return;
        }
        let mut dismiss = false;
        egui::Panel::bottom("command-progress")
            .resizable(self.expanded)
            .default_size(if self.expanded { 176.0 } else { 50.0 })
            .min_size(if self.expanded { 100.0 } else { 50.0 })
            .max_size(if self.expanded { 280.0 } else { 50.0 })
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(12))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if snapshot.status != Status::Running
                            && ui.small_button("Dismiss").clicked()
                        {
                            dismiss = true;
                        }
                        if ui
                            .small_button(if self.expanded {
                                "Hide output"
                            } else {
                                "Show output"
                            })
                            .clicked()
                        {
                            self.expanded = !self.expanded;
                        }
                        if ui
                            .add_enabled(
                                !snapshot.text.is_empty(),
                                egui::Button::new("Copy").small(),
                            )
                            .clicked()
                        {
                            ui.ctx().copy_text(snapshot.text.clone());
                        }
                        let (label, color) = match snapshot.status {
                            Status::Running => ("Running", MUTED),
                            Status::Succeeded => ("Completed", design::GREEN),
                            Status::Failed => ("Failed", design::RED),
                        };
                        ui.label(RichText::new(label).size(11.5).color(color));
                        if snapshot.status == Status::Running {
                            ui.spinner();
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&snapshot.title).strong().size(12.0),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&snapshot.title);
                        });
                    });
                });
                if !self.expanded {
                    return;
                }
                ui.add_space(6.0);
                if snapshot.discarded {
                    ui.label(
                        RichText::new("Recent output · older lines discarded")
                            .size(10.5)
                            .color(MUTED),
                    );
                }
                if snapshot.text.is_empty() {
                    ui.label(
                        RichText::new(if snapshot.status == Status::Running {
                            "Waiting for command output…"
                        } else {
                            "No command output."
                        })
                        .size(12.0)
                        .color(MUTED),
                    );
                } else {
                    let lines: Vec<_> = snapshot.text.lines().collect();
                    egui::ScrollArea::both()
                        .id_salt(("command-output", snapshot.id))
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show_rows(ui, 18.0, lines.len(), |ui, range| {
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
                }
            });
        if dismiss {
            self.dismissed = Some(snapshot.id);
        }
    }
}
