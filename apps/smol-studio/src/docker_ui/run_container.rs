use super::*;
use smol_studio::container_run::{Draft, Image, Mount, Port};

pub(super) struct Form {
    pub draft: Draft,
    pub images: Vec<Image>,
    pub error: Option<String>,
    pub loaded: bool,
    pub reveal_error: bool,
    reset_scroll: bool,
    focus: bool,
    picker: crate::file_picker::FilePicker,
    picking: Option<usize>,
}
impl Form {
    fn new() -> Self {
        Self {
            draft: Draft::default(),
            images: Vec::new(),
            error: None,
            loaded: false,
            reveal_error: false,
            reset_scroll: true,
            focus: true,
            picker: Default::default(),
            picking: None,
        }
    }
}
impl DockerView {
    pub(super) fn open_run_container(&mut self, runtime: &Runtime, image: Option<Image>) {
        let mut form = Form::new();
        if let Some(image) = image {
            form.draft.image = image.id.clone();
            form.images.push(image);
            form.loaded = true;
        }
        let load = !form.loaded;
        self.run_container = Some(form);
        if load {
            self.submit(runtime, Action::RunImages);
        }
    }
    pub(super) fn run_container_dialog(
        &mut self,
        ctx: &egui::Context,
        runtime: &Runtime,
        frame: &eframe::Frame,
    ) {
        let Some(mut form) = self.run_container.take() else {
            return;
        };
        if let Some(selection) = form.picker.poll(ctx)
            && let (Some(files), Some(index)) = (selection, form.picking.take())
        {
            if let Some(path) = files.first().and_then(|file| file.path().to_str()) {
                if let Some(mount) = form.draft.mounts.get_mut(index) {
                    mount.host = path.into();
                }
            } else {
                form.error = Some("Choose a folder with a UTF-8 path.".into());
            }
        }
        let busy = self.pending.is_some() || form.picker.is_open();
        let running = matches!(self.pending, Some(Action::RunContainer(_)));
        let mut open = true;
        let mut cancel = false;
        let mut run = false;
        let mut reload = false;
        let mut browse_images = false;
        let mut window = egui::Window::new("Run container")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(530.0)
            .resizable(false)
            .collapsible(false);
        if !busy {
            window = window.open(&mut open);
        }
        window.show(ctx, |ui| {
            ui.label(RichText::new("Start a container from an image stored in Smol.").size(12.0).color(MUTED));
            ui.add_space(12.0);
            let mut scroll = egui::ScrollArea::vertical().id_salt("run-container-form").max_height((ctx.content_rect().height()-265.0).clamp(160.0,420.0));
            if std::mem::take(&mut form.reset_scroll) { scroll = scroll.vertical_scroll_offset(0.0); }
            scroll.show(ui, |ui| {
                ui.add_enabled_ui(!busy, |ui| {
                    design::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new("Image").size(11.5).color(MUTED));
                        if !form.loaded {
                            ui.horizontal(|ui| { if busy { ui.spinner(); } ui.label(if busy {"Loading local images…"} else {"Couldn’t load local images. Refresh to try again."}); });
                        } else if form.images.is_empty() {
                            ui.label("No local images yet.");
                            browse_images=ui.button("Open Images to pull one").clicked();
                        } else {
                            let selected=form.images.iter().find(|i| i.id==form.draft.image).map(|i| i.label.as_str()).unwrap_or("Choose an image");
                            egui::ComboBox::from_id_salt("run-container-image").width(ui.available_width()).truncate().selected_text(selected).show_ui(ui,|ui| {
                                ui.style_mut().wrap_mode=Some(egui::TextWrapMode::Truncate);
                                for image in &form.images { ui.selectable_value(&mut form.draft.image,image.id.clone(),&image.label); }
                            });
                            if !form.draft.image.is_empty() {
                                ui.add(egui::Label::new(RichText::new(&form.draft.image).monospace().size(10.5).color(MUTED)).truncate()).on_hover_text(&form.draft.image);
                            }
                        }
                        ui.add_space(10.0);
                        ui.label(RichText::new("Container name").size(11.5).color(MUTED));
                        let name=ui.add(egui::TextEdit::singleline(&mut form.draft.name).desired_width(f32::INFINITY).hint_text("my-app"));
                        if form.focus && !busy { name.request_focus(); form.focus=false; }
                    });
                    ui.add_space(12.0);
                    ui.collapsing("Command", |ui| {
                        ui.label(RichText::new("Leave empty to use the image’s command. Each field is one argument; the image’s entrypoint is preserved.").size(12.0).color(MUTED));
                        let mut remove=None;
                        for (index,arg) in form.draft.command.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(if index==0 {"Command".into()} else {format!("Argument {index}")});
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                                    if ui.small_button("Remove").clicked() { remove=Some(index); }
                                    ui.add(egui::TextEdit::singleline(arg).desired_width(f32::INFINITY));
                                });
                            });
                        }
                        if let Some(index)=remove { form.draft.command.remove(index); }
                        if ui.button(if form.draft.command.is_empty() {"Set command"} else {"Add argument"}).clicked() { form.draft.command.push(String::new()); }
                    });
                    ui.add_space(8.0);
                    ui.collapsing("Ports", |ui| {
                        ui.label(RichText::new("Published on this computer’s localhost (127.0.0.1).").size(12.0).color(MUTED));
                        let mut remove=None;
                        for (index,port) in form.draft.ports.iter_mut().enumerate() {
                            ui.push_id(index,|ui| { ui.horizontal(|ui| {
                                ui.label("Host"); ui.add(egui::DragValue::new(&mut port.host).range(1..=65535));
                                ui.label("Container"); ui.add(egui::DragValue::new(&mut port.container).range(1..=65535));
                                egui::ComboBox::from_id_salt("protocol").width(60.0).selected_text(if port.udp {"UDP"}else{"TCP"}).show_ui(ui,|ui| {ui.selectable_value(&mut port.udp,false,"TCP");ui.selectable_value(&mut port.udp,true,"UDP");});
                                if ui.small_button("Remove").clicked() { remove=Some(index); }
                            }); });
                        }
                        if let Some(index)=remove {form.draft.ports.remove(index);}
                        if ui.button("Add port").clicked() { form.draft.ports.push(Port {host:8080,container:80,udp:false}); }
                    });
                    ui.add_space(8.0);
                    ui.collapsing("Shared folders", |ui| {
                        let mut remove=None;
                        for (index,mount) in form.draft.mounts.iter_mut().enumerate() {
                            ui.push_id(index,|ui| {
                                design::card().show(ui,|ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                                            if ui.button("Choose…").clicked() { form.picking=Some(index); form.picker.open_folder(frame,&mount.host,ctx); }
                                            ui.add(egui::TextEdit::singleline(&mut mount.host).desired_width(f32::INFINITY).hint_text("Host folder"));
                                        });
                                    });
                                    ui.add(egui::TextEdit::singleline(&mut mount.container).desired_width(f32::INFINITY).hint_text("Container path, e.g. /data"));
                                    ui.horizontal(|ui| {ui.checkbox(&mut mount.read_only,"Read only"); if ui.small_button("Remove folder").clicked() {remove=Some(index);}});
                                }); ui.add_space(8.0);
                            });
                        }
                        if let Some(index)=remove {form.draft.mounts.remove(index);}
                        if ui.button("Add folder").clicked() {form.draft.mounts.push(Mount::default());}
                    });
                    ui.add_space(8.0);
                    ui.collapsing("Environment",|ui| {
                        ui.label(RichText::new("Values override the image’s environment and are stored in the container configuration.").size(12.0).color(MUTED));
                        let mut remove=None;
                        for (index,(key,value)) in form.draft.environment.iter_mut().enumerate() {
                            ui.push_id(index,|ui| { ui.horizontal(|ui| {
                                if ui.small_button("Remove").clicked() {remove=Some(index);}
                                ui.add(egui::TextEdit::singleline(key).desired_width(130.0).hint_text("NAME"));
                                ui.add(egui::TextEdit::singleline(value).desired_width(ui.available_width()).password(true).hint_text("Value"));
                            });});
                        }
                        if let Some(index)=remove {form.draft.environment.remove(index);}
                        if ui.button("Add variable").clicked() {form.draft.environment.push((String::new(),String::new()));}
                    });
                });
                if let Some(error)=&form.error {
                    ui.add_space(12.0);
                    design::error_notice(ui,"Could not run container.",error);
                    if std::mem::take(&mut form.reveal_error) { ui.scroll_to_cursor(Some(egui::Align::BOTTOM)); }
                }
            });
            ui.add_space(12.0); ui.separator(); ui.add_space(8.0);
            ui.horizontal(|ui| {
                if running {ui.spinner();ui.label("Creating and starting…");}
                if !running { ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                    run=ui.add_enabled(!busy && form.loaded && !form.draft.image.is_empty(),design::primary("Run container")).clicked();
                    cancel=ui.add_enabled(!busy,egui::Button::new("Cancel")).clicked();
                    reload=ui.add_enabled(!busy,egui::Button::new("Refresh images")).clicked();
                }); }
            });
        });
        if browse_images {
            self.kind = Kind::Images;
            self.compose = false;
            self.rows.clear();
            self.valid = false;
            self.query.clear();
            self.storage = None;
            self.storage_selected = None;
            self.refresh(runtime);
            return;
        }
        if (!open || cancel || ctx.input(|i| i.key_pressed(egui::Key::Escape))) && !busy {
            return;
        }
        if reload {
            self.submit(runtime, Action::RunImages);
        }
        if run {
            match form.draft.validate() {
                Ok(()) => {
                    form.error = None;
                    self.submit(runtime, Action::RunContainer(form.draft.clone()));
                    if self.pending.is_none() {
                        form.reveal_error = true;
                        form.error = self.error.take();
                    }
                }
                Err(error) => {
                    form.error = Some(error);
                    form.reveal_error = true;
                }
            }
        }
        self.run_container = Some(form);
    }
}
