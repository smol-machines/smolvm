use crate::design;
use eframe::egui::{self, RichText};
use smol_studio::command_progress::{Progress, Snapshot, Status};

#[derive(Default)]
pub struct ProgressView {
    snapshot: Option<Snapshot>,
    revision: u64,
    dismissed: Option<u64>,
    expanded: bool,
    filter: String,
    follow: bool,
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
                self.filter.clear();
                self.follow = true;
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
            .default_size(if self.expanded { 200.0 } else { 50.0 })
            .min_size(if self.expanded { 132.0 } else { 50.0 })
            .max_size(if self.expanded { 280.0 } else { 50.0 })
            .frame(
                egui::Frame::new()
                    .fill(design::palette(ui).base)
                    .stroke(egui::Stroke::new(1.0, design::palette(ui).line))
                    .inner_margin(12),
            )
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
                                egui::Button::new("Copy output").small(),
                            )
                            .clicked()
                        {
                            ui.ctx().copy_text(snapshot.text.clone());
                        }
                        let (label, color) = match snapshot.status {
                            Status::Running => ("Running", design::palette(ui).muted),
                            Status::Succeeded => ("Completed", design::palette(ui).green),
                            Status::Failed => ("Failed", design::palette(ui).red),
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
                ui.add_space(8.0);
                let mut jump_to_latest = false;
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .desired_width(180.0)
                            .hint_text("Filter output…"),
                    );
                    if !self.filter.is_empty() && ui.small_button("Clear").clicked() {
                        self.filter.clear();
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        jump_to_latest = ui.checkbox(&mut self.follow, "Follow output")
                            .on_hover_text("Keep the newest lines visible. Scrolling up also stops following until you return to the bottom.")
                            .changed() && self.follow;
                    });
                });
                let query = self.filter.to_lowercase();
                let lines: Vec<_> = snapshot.text.lines().enumerate()
                    .filter(|(_, line)| query.is_empty() || line.to_lowercase().contains(&query))
                    .collect();
                ui.add_space(4.0);
                let count = lines.len();
                ui.label(RichText::new(format!(
                    "{count} {}{}{}",
                    if count == 1 { "line" } else { "lines" },
                    if query.is_empty() { "" } else if count == 1 { " matches" } else { " match" },
                    if snapshot.discarded { " · older output discarded" } else { "" },
                )).size(10.5).color(design::palette(ui).muted));
                ui.add_space(4.0);
                egui::Frame::new()
                    .fill(design::palette(ui).surface)
                    .corner_radius(6)
                    .inner_margin(8)
                    .show(ui, |ui| {
                        ui.set_min_size(ui.available_size());
                        if lines.is_empty() {
                            ui.label(RichText::new(if !snapshot.text.is_empty() {
                                "No lines match this filter."
                            } else if snapshot.status == Status::Running {
                                "Waiting for command output…"
                            } else {
                                "No command output."
                            }).size(12.0).color(design::palette(ui).muted));
                            return;
                        }
                        let row_height = ui.fonts_mut(|fonts|
                            fonts.row_height(&egui::FontId::monospace(11.5)));
                        // Match virtual row height to the actual font so scrolling
                        // does not skip lines or leave gaps in long transcripts.
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.spacing_mut().interact_size.y = row_height;
                        let mut scroll = egui::ScrollArea::both()
                            .id_salt(("command-output", snapshot.id, &self.filter))
                            .auto_shrink([false, false])
                            .stick_to_bottom(self.follow);
                        if jump_to_latest {
                            // show_rows computes integer row bounds before clamping
                            // the offset; infinity would overflow those bounds.
                            let end = (row_height + ui.spacing().item_spacing.y) * lines.len() as f32;
                            scroll = scroll.vertical_scroll_offset(end);
                        }
                        scroll.show_rows(ui, row_height, lines.len(), |ui, range| {
                                for index in range {
                                    let (number, line) = lines[index];
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(format!("{:>4}", number + 1))
                                            .monospace().size(11.5).color(design::palette(ui).muted));
                                        ui.add(egui::Label::new(RichText::new(line)
                                            .monospace().size(11.5))
                                            .wrap_mode(egui::TextWrapMode::Extend)
                                            .selectable(true));
                                    });
                                }
                            });
                    });
            });
        if dismiss {
            self.dismissed = Some(snapshot.id);
        }
    }
}
