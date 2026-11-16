use super::*;
use smol_studio::image_archive::{Plan, Request};

pub(super) struct Form {
    image_id: Option<String>,
    label: String,
    pub path: String,
    pub plan: Option<Plan>,
    pub error: Option<String>,
    pub transferring: bool,
    pub reveal_review: bool,
    pub reveal_error: bool,
    picker: crate::file_picker::FilePicker,
    focus: bool,
}
impl Form {
    pub fn import() -> Self {
        Self {
            image_id: None,
            label: String::new(),
            path: String::new(),
            plan: None,
            error: None,
            transferring: false,
            reveal_review: false,
            reveal_error: false,
            picker: Default::default(),
            focus: true,
        }
    }
    pub fn export(id: String, label: String) -> Self {
        Self {
            image_id: Some(id),
            label,
            ..Self::import()
        }
    }
}

impl DockerView {
    pub(super) fn image_archive_dialog(
        &mut self,
        ctx: &egui::Context,
        runtime: &Runtime,
        frame: &eframe::Frame,
    ) {
        let Some(mut form) = self.archive_image.take() else {
            return;
        };
        if form.transferring {
            self.archive_image = Some(form);
            return;
        }
        if let Some(Some(files)) = form.picker.poll(ctx) {
            form.plan = None;
            if let Some(path) = files.first().and_then(|file| file.path().to_str()) {
                form.path = path.into();
                form.error = None;
            } else {
                form.error = Some("Choose a file with a UTF-8 path.".into());
            }
        }
        let exporting = form.image_id.is_some();
        let busy = self.pending.is_some() || form.picker.is_open();
        let mut open = true;
        let mut cancel = false;
        let mut browse = false;
        let mut review = false;
        let mut apply = false;
        let mut window = egui::Window::new(if exporting {
            "Export image"
        } else {
            "Import images"
        })
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .collapsible(false)
        .resizable(false)
        .default_width(510.0);
        if !busy {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            ui.label(
                RichText::new(if exporting {
                    "Save an image and its tags as a Docker archive."
                } else {
                    "Load images from a Docker or OCI archive."
                })
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(12.0);
            egui::ScrollArea::vertical()
                .id_salt("image-archive-form")
                .max_height((ctx.content_rect().height() - 240.0).clamp(160.0, 320.0))
                .show(ui, |ui| {
                    if let Some(id) = &form.image_id {
                        design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            design::eyebrow(ui, "SELECTED IMAGE");
                            ui.add(egui::Label::new(RichText::new(&form.label).strong()).wrap());
                            ui.add(
                                egui::Label::new(
                                    RichText::new(id).monospace().size(11.0).color(MUTED),
                                )
                                .wrap(),
                            );
                        });
                        ui.add_space(12.0);
                    }
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            RichText::new(if exporting { "Save to" } else { "Archive file" })
                                .small()
                                .color(MUTED),
                        );
                        ui.horizontal(|ui| {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    browse = ui
                                        .add_enabled(!busy, egui::Button::new("Choose…"))
                                        .clicked();
                                    let response = ui.add_enabled(
                                        !busy,
                                        egui::TextEdit::singleline(&mut form.path)
                                            .desired_width(f32::INFINITY)
                                            .hint_text("Absolute file path"),
                                    );
                                    if form.focus && !busy {
                                        response.request_focus();
                                        form.focus = false;
                                    }
                                    if response.changed() {
                                        form.plan = None;
                                        form.error = None;
                                    }
                                },
                            );
                        });
                        ui.label(
                            RichText::new(if exporting {
                                "A .tar file that Docker, Podman and Smol can load."
                            } else {
                                "Supports tar archives, including gzip and zstd compression."
                            })
                            .size(11.0)
                            .color(MUTED),
                        );
                    });
                    if let Some(plan) = &form.plan {
                        ui.add_space(12.0);
                        let review_card = design::card().show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            design::eyebrow(ui, "REVIEW");
                            ui.add(
                                egui::Label::new(
                                    RichText::new(plan.path.display().to_string())
                                        .monospace()
                                        .size(11.5),
                                )
                                .wrap(),
                            );
                            ui.add_space(6.0);
                            if plan.importing() {
                                ui.label(format!(
                                    "Archive size: {}",
                                    smol_studio::storage::bytes_label(plan.size)
                                ));
                                ui.label("Matching local tags will point to the imported images.");
                            } else {
                                ui.label(if plan.replaces_file() {
                                    "Replaces the existing file after the export completes."
                                } else {
                                    "Creates a new archive after the export completes."
                                });
                                ui.add_space(6.0);
                                if plan.tags.is_empty() {
                                    ui.label("Untagged image · preserves its image ID.");
                                } else {
                                    ui.label(
                                        RichText::new(format!(
                                            "{} {} included",
                                            plan.tags.len(),
                                            if plan.tags.len() == 1 { "tag" } else { "tags" }
                                        ))
                                        .small()
                                        .color(MUTED),
                                    );
                                    for tag in &plan.tags {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(tag).monospace().size(11.5),
                                            )
                                            .wrap(),
                                        );
                                    }
                                }
                            }
                        });
                        if form.reveal_review {
                            review_card.response.scroll_to_me(Some(egui::Align::TOP));
                            form.reveal_review = false;
                        }
                    }
                    if let Some(error) = &form.error {
                        ui.add_space(12.0);
                        let notice = ui.vertical(|ui| {
                            design::error_notice(
                                ui,
                                if error.len() < 180 && !error.contains('\n') {
                                    error
                                } else {
                                    "Image transfer could not be completed."
                                },
                                error,
                            )
                        });
                        if form.reveal_error {
                            notice.response.scroll_to_me(Some(egui::Align::BOTTOM));
                            form.reveal_error = false;
                        }
                    }
                });
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if self.pending.is_some() {
                    ui.spinner();
                    ui.label(self.status());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(plan) = &form.plan {
                        let label = if plan.importing() {
                            "Import images"
                        } else if plan.replaces_file() {
                            "Replace & export"
                        } else {
                            "Export image"
                        };
                        apply = ui
                            .add_enabled(!busy && self.valid, design::primary(label))
                            .clicked();
                    } else {
                        review = ui
                            .add_enabled(
                                !busy && self.valid && !form.path.is_empty(),
                                design::primary("Review"),
                            )
                            .clicked();
                    }
                    cancel = ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                });
            });
        });
        if !busy && (cancel || !open || ctx.input(|i| i.key_pressed(egui::Key::Escape))) {
            return;
        }
        if browse {
            form.picker.open_archive(frame, exporting, ctx);
        }
        let action = if review {
            form.error = None;
            let path = form.path.clone().into();
            Some(Action::ReviewImageArchive(match &form.image_id {
                Some(id) => Request::Export {
                    image_id: id.clone(),
                    path,
                },
                None => Request::Import(path),
            }))
        } else if apply {
            form.error = None;
            form.transferring = true;
            form.plan.clone().map(Action::TransferImageArchive)
        } else {
            None
        };
        self.archive_image = Some(form);
        if let Some(action) = action {
            self.submit(runtime, action);
            if self.pending.is_none()
                && let Some(form) = &mut self.archive_image
            {
                form.transferring = false;
                form.error = self.error.clone();
            }
        }
    }
}
