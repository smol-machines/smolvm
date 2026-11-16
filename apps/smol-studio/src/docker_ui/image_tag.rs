use super::*;

pub(super) struct Form {
    pub source_id: String,
    pub source_label: String,
    pub reference: String,
    pub plan: Option<smol_studio::image_tag::Plan>,
    pub error: Option<String>,
    pub focus_reference: bool,
}

fn image_id(ui: &mut egui::Ui, id: &str) {
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Copy ID").clicked() {
                ui.ctx().copy_text(id.to_owned());
            }
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(id)
                            .monospace()
                            .size(11.0)
                            .color(design::palette(ui).muted),
                    )
                    .truncate(),
                )
                .on_hover_text(id);
            });
        });
    });
}

impl DockerView {
    pub(super) fn image_tag_dialog(&mut self, ctx: &egui::Context, runtime: &Runtime) {
        let Some(mut form) = self.tag_image.take() else {
            return;
        };
        let busy = self.pending.is_some();
        let mut open = true;
        let mut cancel = false;
        let mut review = false;
        let mut apply = false;
        let mut window = egui::Window::new("Tag image")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .default_width(480.0);
        if !busy {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            ui.label(RichText::new("Create a local name for this image.").small().color(design::palette(ui).muted));
            ui.add_space(12.0);
            egui::ScrollArea::vertical().id_salt("image-tag-form").max_height((ctx.content_rect().height() - 190.0).clamp(160.0, 440.0)).show(ui, |ui| {
                design::card(ui.ctx()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    design::eyebrow(ui, "SOURCE IMAGE");
                    ui.add(egui::Label::new(RichText::new(&form.source_label).strong()).wrap());
                    image_id(ui, &form.source_id);
                });
                ui.add_space(12.0);
                design::card(ui.ctx()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("New image reference").small().color(design::palette(ui).muted));
                    let response = ui.add_enabled(!busy, egui::TextEdit::singleline(&mut form.reference).desired_width(f32::INFINITY).hint_text("my-app:dev"));
                    if form.focus_reference && !busy { response.request_focus(); form.focus_reference = false; }
                    if response.changed() {
                        form.plan = None;
                        form.error = None;
                    }
                    ui.label(RichText::new("Repository and tag, including a registry if needed.").small().color(design::palette(ui).muted));
                });
                if let Some(plan) = &form.plan {
                    ui.add_space(12.0);
                    design::card(ui.ctx()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        design::eyebrow(ui, "REVIEW");
                        ui.add(egui::Label::new(RichText::new(&plan.reference).monospace()).wrap());
                        ui.add_space(8.0);
                        match plan.previous_id.as_deref() {
                            None => { ui.label("Creates a new local tag."); }
                            Some(id) if id == plan.source_id => { ui.label("This tag already points to the selected image."); }
                            Some(id) => {
                                ui.label("Moves the existing tag from this image to the selected source:");
                                image_id(ui, id);
                            }
                        }
                    });
                }
                if !form.reference.is_empty() && let Err(error) = smol_studio::image_tag::reference(form.reference.trim()) {
                    ui.add_space(8.0); ui.label(RichText::new(error).small().color(design::palette(ui).red));
                }
                if let Some(error) = &form.error {
                    ui.add_space(12.0);
                    let summary = if error.len() <= 180 && !error.contains('\n') { error.as_str() } else { "Tag could not be applied." };
                    design::error_notice(ui, summary, error);
                }
            });
            ui.add_space(12.0); ui.separator(); ui.add_space(8.0);
            ui.horizontal(|ui| {
                if busy { ui.spinner(); ui.label(self.status()); }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(plan) = &form.plan {
                        if plan.previous_id.as_deref() == Some(&plan.source_id) {
                            cancel = ui.add_enabled(!busy, design::primary(ui, "Done")).clicked();
                        } else {
                            apply = ui.add_enabled(!busy && self.valid, design::primary(ui, if plan.previous_id.is_some() { "Move tag" } else { "Create tag" })).clicked();
                        }
                    } else {
                        review = ui.add_enabled(!busy && self.valid && smol_studio::image_tag::reference(form.reference.trim()).is_ok(), design::primary(ui, "Review tag")).clicked();
                    }
                    cancel |= ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                });
            });
        });
        if !busy && (cancel || !open || ctx.input(|i| i.key_pressed(egui::Key::Escape))) {
            return;
        }
        let action = if review {
            form.error = None;
            Some(Action::ReviewImageTag {
                id: form.source_id.clone(),
                reference: form.reference.trim().into(),
            })
        } else if apply {
            form.error = None;
            form.plan.clone().map(Action::TagImage)
        } else {
            None
        };
        self.tag_image = Some(form);
        if let Some(action) = action {
            self.submit(runtime, action);
        }
    }
}
