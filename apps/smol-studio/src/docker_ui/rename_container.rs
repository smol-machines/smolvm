use super::*;

pub(super) struct Form {
    pub id: String,
    pub original: String,
    name: String,
    pub error: Option<String>,
    focus: bool,
}

impl Form {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.into(),
            original: name.into(),
            name: name.into(),
            error: None,
            focus: true,
        }
    }
}

impl DockerView {
    pub(super) fn rename_container_dialog(&mut self, ctx: &egui::Context, runtime: &Runtime) {
        let Some(mut form) = self.rename_container.take() else {
            return;
        };
        let busy = self.pending.is_some();
        let mut open = true;
        let mut cancel = false;
        let mut apply = false;
        let mut window = egui::Window::new("Rename container")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(440.0)
            .resizable(false)
            .collapsible(false);
        if !busy {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("rename-container-form")
                .max_height((ctx.content_rect().height() - 220.0).clamp(160.0, 360.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Change this container’s name without restarting it.")
                            .size(12.0)
                            .color(design::palette(ui).muted),
                    );
                    ui.add_space(12.0);
                    design::property(ui, "Current name", &form.original);
                    ui.add_space(12.0);
                    ui.label("New name");
                    let field = ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut form.name).desired_width(f32::INFINITY),
                    );
                    if form.focus && !busy {
                        field.request_focus();
                        form.focus = false;
                    }
                    if field.changed() {
                        form.error = None;
                    }
                    if let Err(error) = smol_studio::docker::validate_container_name(&form.name) {
                        ui.label(RichText::new(error).size(12.0).color(design::palette(ui).red));
                    }
                    if let Some(error) = &form.error {
                        ui.add_space(12.0);
                        design::error_notice(
                            ui,
                            if error.contains("already in use by container") {
                                "That name is already in use. Choose another name."
                            } else {
                                "Could not confirm the rename. Check the current name before retrying."
                            },
                            error,
                        );
                    }
                });
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if busy {
                    ui.spinner();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    apply = ui
                        .add_enabled(
                            !busy
                                && form.name != form.original
                                && smol_studio::docker::validate_container_name(&form.name).is_ok(),
                            design::primary(ui, "Rename container"),
                        )
                        .clicked();
                    cancel = ui.add_enabled(!busy, egui::Button::new("Cancel")).clicked();
                });
            });
        });
        if !busy && (!open || cancel || ctx.input(|i| i.key_pressed(egui::Key::Escape))) {
            return;
        }
        if apply {
            form.error = None;
            self.submit(
                runtime,
                Action::Rename {
                    id: form.id.clone(),
                    name: form.name.clone(),
                },
            );
            if self.pending.is_none() {
                form.error = self.error.take();
            }
        }
        self.rename_container = Some(form);
    }
}
