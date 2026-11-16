use crate::design::{self, Icon};
use eframe::egui::{self, Key, Modifiers, RichText};
use smol_studio::docker::Kind;

#[derive(Clone, Copy, PartialEq)]
pub enum Destination {
    Machines,
    Docker(Option<Kind>),
    Account,
    Settings,
}

impl Destination {
    pub const ALL: [Self; 8] = [
        Self::Machines,
        Self::Docker(Some(Kind::Containers)),
        Self::Docker(None),
        Self::Docker(Some(Kind::Images)),
        Self::Docker(Some(Kind::Volumes)),
        Self::Docker(Some(Kind::Networks)),
        Self::Account,
        Self::Settings,
    ];

    fn details(self) -> (&'static str, Icon, Key) {
        match self {
            Self::Machines => ("Machines", Icon::Machine, Key::Num1),
            Self::Docker(Some(Kind::Containers)) => ("Containers", Icon::Containers, Key::Num2),
            Self::Docker(None) => ("Projects", Icon::Project, Key::Num3),
            Self::Docker(Some(Kind::Images)) => ("Images", Icon::Image, Key::Num4),
            Self::Docker(Some(Kind::Volumes)) => ("Volumes", Icon::Volume, Key::Num5),
            Self::Docker(Some(Kind::Networks)) => ("Networks", Icon::Network, Key::Num6),
            Self::Account => ("Account", Icon::Cloud, Key::Num7),
            Self::Settings => ("Settings", Icon::Settings, Key::Comma),
        }
    }

    pub fn hint(self, ctx: &egui::Context) -> String {
        ctx.format_shortcut(&egui::KeyboardShortcut::new(
            Modifiers::COMMAND,
            self.details().2,
        ))
    }
}

#[derive(Default)]
pub struct Switcher {
    pub open: bool,
    query: String,
    selected: usize,
    focus: bool,
}

impl Switcher {
    pub fn open(&mut self) {
        self.open = true;
        self.query.clear();
        self.selected = 0;
        self.focus = true;
    }

    /// Called before editors and terminals process input; callers gate modal/terminal focus.
    pub fn shortcuts(&mut self, ctx: &egui::Context) -> Option<Destination> {
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::K)) {
            if self.open {
                self.open = false;
            } else {
                self.open();
            }
        }
        for destination in Destination::ALL {
            if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, destination.details().2)) {
                self.open = false;
                return Some(destination);
            }
        }
        None
    }

    pub fn show(&mut self, ctx: &egui::Context, docker_busy: bool) -> Option<Destination> {
        if !self.open {
            return None;
        }
        let mut chosen = None;
        let modal =
            egui::Modal::new(egui::Id::unique("workspace-switcher"))
                .frame(design::card(ctx).inner_margin(18))
                .show(ctx, |ui| {
                    ui.set_width(440.0);
                    ui.horizontal(|ui| {
                        ui.label(design::heading("Go to", 18.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Close").clicked() {
                                self.open = false;
                            }
                        });
                    });
                    ui.add_space(12.0);
                    let search_id = egui::Id::unique("workspace-switcher-search");
                    let searching = self.focus || ui.memory(|m| m.has_focus(search_id));
                    let (down, up, enter) = ui.input_mut(|i| {
                        (
                            searching && i.consume_key(Modifiers::NONE, Key::ArrowDown),
                            searching && i.consume_key(Modifiers::NONE, Key::ArrowUp),
                            searching && i.consume_key(Modifiers::NONE, Key::Enter),
                        )
                    });
                    let search = ui.add(
                        egui::TextEdit::singleline(&mut self.query)
                            .id(search_id)
                            .hint_text("Find a workspace…")
                            .desired_width(f32::INFINITY)
                            .margin(egui::Margin::symmetric(10, 9)),
                    );
                    if self.focus {
                        search.request_focus();
                        self.focus = false;
                    }
                    // The search keeps focus while arrows move the result highlight.
                    ui.memory_mut(|m| {
                        m.set_focus_lock_filter(
                            search.id,
                            egui::EventFilter {
                                vertical_arrows: true,
                                ..Default::default()
                            },
                        );
                    });
                    let query = self.query.trim().to_lowercase();
                    let rows: Vec<_> = Destination::ALL
                        .into_iter()
                        .filter(|d| d.details().0.to_lowercase().contains(&query))
                        .collect();
                    if search.changed() {
                        self.selected = 0;
                    }
                    self.selected = self.selected.min(rows.len().saturating_sub(1));
                    let mut moved = false;
                    if !rows.is_empty() {
                        if down {
                            self.selected = (self.selected + 1) % rows.len();
                            moved = true;
                        }
                        if up {
                            self.selected = (self.selected + rows.len() - 1) % rows.len();
                            moved = true;
                        }
                        if enter {
                            let d = rows[self.selected];
                            if !docker_busy || !matches!(d, Destination::Docker(_)) {
                                chosen = Some(d);
                            }
                        }
                    }
                    ui.add_space(12.0);
                    egui::ScrollArea::vertical()
                        .max_height(330.0)
                        .show(ui, |ui| {
                            if rows.is_empty() {
                                ui.label(
                                    RichText::new("No matching workspaces.")
                                        .color(design::palette(ui).muted),
                                );
                                ui.add_space(12.0);
                            }
                            for (index, destination) in rows.iter().enumerate() {
                                let (label, icon, _) = destination.details();
                                ui.add_enabled_ui(
                                    !docker_busy || !matches!(destination, Destination::Docker(_)),
                                    |ui| {
                                        let row =
                                            design::nav(ui, self.selected == index, icon, label);
                                        ui.painter().text(
                                            row.rect.right_center() - egui::vec2(12.0, 0.0),
                                            egui::Align2::RIGHT_CENTER,
                                            destination.hint(ctx),
                                            egui::FontId::proportional(12.0),
                                            design::palette(ui).muted,
                                        );
                                        if moved && self.selected == index {
                                            row.scroll_to_me(Some(egui::Align::Center));
                                        }
                                        if row.clicked() {
                                            chosen = Some(*destination);
                                        }
                                    },
                                );
                            }
                        });
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(RichText::new(if docker_busy {
                    "Docker workspaces will be available when the current operation finishes."
                } else {
                    "↑ ↓ to navigate   ·   Enter to open   ·   Esc to close"
                }).size(11.0).color(design::palette(ui).muted));
                });
        if modal.should_close() || chosen.is_some() {
            self.open = false;
        }
        chosen
    }
}
