use crate::{design, search_ui};
use eframe::egui::{self, RichText};
use smol_cloud::types::CommandOutput;
use std::{collections::VecDeque, ops::Range};

const VISIBLE_LINES: usize = 10_000;
const LINE_BYTES: usize = 4096;

struct Line {
    number: usize,
    bytes: Range<usize>,
}
struct Output {
    text: String,
    exit: Option<i32>,
    truncated: bool,
}

#[derive(Default)]
pub(super) struct Console {
    command: String,
    running: bool,
    output: Option<Output>,
    error: Option<String>,
    filter: String,
    lines: VecDeque<Line>,
    matches: usize,
    shortened: bool,
    revision: u64,
}

impl Console {
    pub(super) fn begin(&mut self) {
        self.running = true;
        self.error = None;
    }
    pub(super) fn finish(&mut self, result: Result<CommandOutput, String>) {
        self.running = false;
        match result {
            Ok(output) => {
                self.output = Some(Output {
                    text: format!(
                        "{}{}",
                        String::from_utf8_lossy(&output.stdout_bytes()),
                        String::from_utf8_lossy(&output.stderr_bytes())
                    ),
                    exit: output.exit_code,
                    // The SDK prefers byte-exact output when it is available.
                    truncated: (output.stdout_b64.is_none()
                        && output.stdout_truncated == Some(true))
                        || (output.stderr_b64.is_none() && output.stderr_truncated == Some(true)),
                });
                self.error = None;
                self.rebuild();
            }
            Err(error) => self.error = Some(error),
        }
    }
    fn rebuild(&mut self) {
        self.lines.clear();
        self.matches = 0;
        self.shortened = false;
        self.revision = self.revision.wrapping_add(1);
        let Some(output) = &self.output else {
            return;
        };
        let query = self.filter.to_lowercase();
        let mut offset = 0;
        for (number, chunk) in output.text.split_inclusive('\n').enumerate() {
            let line = chunk
                .strip_suffix('\n')
                .map(|s| s.strip_suffix('\r').unwrap_or(s))
                .unwrap_or(chunk);
            if query.is_empty() || line.to_lowercase().contains(&query) {
                self.matches += 1;
                self.shortened |= line.len() > LINE_BYTES;
                if self.lines.len() == VISIBLE_LINES {
                    self.lines.pop_front();
                }
                self.lines.push_back(Line {
                    number: number + 1,
                    bytes: offset..offset + line.len(),
                });
            }
            offset += chunk.len();
        }
    }
    fn shown_text(&self) -> String {
        self.output
            .as_ref()
            .map(|output| {
                self.lines
                    .iter()
                    .map(|line| &output.text[line.bytes.clone()])
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }
    pub(super) fn show(
        &mut self,
        ui: &mut egui::Ui,
        enabled: bool,
        ready: bool,
        allowed: bool,
    ) -> Option<String> {
        let mut run = None;
        design::card(ui.ctx()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                let width = (ui.available_width() - 70.0).max(100.0);
                ui.vertical(|ui| {
                    ui.set_width(width);
                    egui::ScrollArea::vertical()
                        .id_salt("cloud-command-editor")
                        .max_height(64.0)
                        .min_scrolled_height(40.0)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.add_enabled(
                                !self.running,
                                egui::TextEdit::multiline(&mut self.command)
                                    .id(egui::Id::unique("cloud-command-editor"))
                                    .desired_rows(2)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace)
                                    .hint_text("Enter a shell command…"),
                            );
                        });
                });
                ui.vertical(|ui| {
                    if ui
                        .add_enabled(
                            enabled && ready && allowed && !self.command.trim().is_empty(),
                            design::primary(ui, "Run"),
                        )
                        .clicked()
                    {
                        run = Some(self.command.clone());
                    }
                    if self.running {
                        ui.spinner();
                    }
                });
            });
            ui.label(
                RichText::new(if !ready {
                    "Start this machine and wait for it to be ready."
                } else if !allowed {
                    "Your account does not have permission to run commands."
                } else {
                    "Shell command · 60 second limit · output appears when finished"
                })
                .size(11.5)
                .color(design::palette(ui).muted),
            );
        });
        ui.add_space(12.0);
        if let Some(error) = &self.error {
            design::error_notice(
                ui,
                if self.output.is_some() {
                    "Command result unavailable. Previous output is shown."
                } else {
                    "Command result unavailable."
                },
                error,
            );
            ui.add_space(8.0);
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(design::heading(
                if self.output.is_some() && (self.running || self.error.is_some()) {
                    "Previous output"
                } else {
                    "Output"
                },
                14.0,
            ));
            if let Some(output) = &self.output {
                let label = output
                    .exit
                    .map(|code| format!("Exit {code}"))
                    .unwrap_or_else(|| "Exit status unknown".into());
                ui.label(RichText::new(label).size(11.5).color(match output.exit {
                    Some(0) => design::palette(ui).green,
                    Some(_) => design::palette(ui).red,
                    None => design::palette(ui).muted,
                }));
                if ui
                    .add_enabled(
                        !output.text.is_empty(),
                        egui::Button::new("Copy all").small(),
                    )
                    .clicked()
                {
                    ui.ctx().copy_text(output.text.clone());
                }
                if !self.filter.is_empty()
                    && ui
                        .add_enabled(
                            !self.lines.is_empty(),
                            egui::Button::new("Copy shown").small(),
                        )
                        .clicked()
                {
                    ui.ctx().copy_text(self.shown_text());
                }
            } else if self.running {
                ui.label(
                    RichText::new("Running…")
                        .size(11.5)
                        .color(design::palette(ui).muted),
                );
            }
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .id(egui::Id::unique("cloud-command-filter"))
                    .desired_width(170.0)
                    .hint_text("Filter output…"),
            );
            search_ui::register(
                ui,
                &search,
                search_ui::Scope::Content,
                self.filter.chars().count(),
            );
            if search.changed() {
                self.rebuild();
            }
        });
        if self.output.is_some() {
            let count = if self.lines.len() < self.matches {
                format!(
                    "Showing the last {} of {} matching lines",
                    self.lines.len(),
                    self.matches
                )
            } else {
                format!(
                    "{} {}",
                    self.matches,
                    if self.matches == 1 { "line" } else { "lines" }
                )
            };
            ui.label(
                RichText::new(count)
                    .size(10.5)
                    .color(design::palette(ui).muted),
            );
        }
        if self.output.as_ref().is_some_and(|o| o.truncated) {
            ui.label(
                RichText::new("The cloud service omitted some output.")
                    .size(10.5)
                    .color(design::palette(ui).muted),
            );
        }
        if self.shortened || self.matches > VISIBLE_LINES {
            ui.label(
                RichText::new("Display shortened · Copy all includes the full result received.")
                    .size(10.5)
                    .color(design::palette(ui).muted),
            );
        }
        ui.add_space(8.0);
        egui::Frame::new()
            .fill(design::palette(ui).surface)
            .corner_radius(6)
            .inner_margin(8)
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                if self.lines.is_empty() {
                    ui.label(
                        RichText::new(
                            if self.output.as_ref().is_some_and(|o| !o.text.is_empty()) {
                                "No lines match this filter."
                            } else if self.running {
                                "Waiting for command output…"
                            } else if self.output.is_some() {
                                "The command produced no output."
                            } else {
                                "Run a command to see its output here."
                            },
                        )
                        .size(12.0)
                        .color(design::palette(ui).muted),
                    );
                    return;
                }
                let row_height = ui.fonts_mut(|f| f.row_height(&egui::FontId::monospace(11.5)));
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.spacing_mut().interact_size.y = row_height;
                egui::ScrollArea::both()
                    .id_salt(("cloud-command-output", self.revision))
                    .auto_shrink([false, false])
                    .show_rows(ui, row_height, self.lines.len(), |ui, range| {
                        let text = &self.output.as_ref().unwrap().text;
                        for index in range {
                            let line = &self.lines[index];
                            let value = &text[line.bytes.clone()];
                            let value = if value.len() > LINE_BYTES {
                                format!("{}…", &value[..value.floor_char_boundary(LINE_BYTES)])
                            } else {
                                value.to_owned()
                            };
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("{:>4}", line.number))
                                        .monospace()
                                        .size(11.5)
                                        .color(design::palette(ui).muted),
                                );
                                ui.add(
                                    egui::Label::new(RichText::new(value).monospace().size(11.5))
                                        .extend()
                                        .selectable(true),
                                );
                            });
                        }
                    });
            });
        run
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filter_keeps_focus_when_copy_shown_appears_and_on_command_failure() {
        let ctx = egui::Context::default();
        let mut view = Console::default();
        view.finish(Ok(CommandOutput {
            stdout: Some("row-00012\nother\n".into()),
            ..Default::default()
        }));
        let frame = |view: &mut Console, events| {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    events,
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(960.0, 640.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        view.show(ui, true, true, true);
                    });
                },
            );
            output.textures_delta.clear();
        };
        frame(&mut view, vec![]);
        let id = egui::Id::unique("cloud-command-filter");
        ctx.memory_mut(|memory| memory.request_focus(id));
        for ch in "row-00012".chars() {
            frame(&mut view, vec![egui::Event::Text(ch.to_string())]);
            assert!(ctx.memory(|memory| memory.has_focus(id)));
        }
        assert_eq!(view.filter, "row-00012");
        assert_eq!(view.shown_text(), "row-00012");
        view.finish(Err("failed".into()));
        frame(&mut view, vec![]);
        assert!(ctx.memory(|memory| memory.has_focus(id)));
    }
    #[test]
    fn output_filter_preserves_unicode_line_numbers_and_complete_copy() {
        let text = "first\r\n雪 α\r\nlast\n";
        let mut view = Console::default();
        view.finish(Ok(CommandOutput {
            stdout: Some(text.into()),
            exit_code: Some(7),
            ..Default::default()
        }));
        view.filter = "雪".into();
        view.rebuild();
        assert_eq!(view.lines.len(), 1);
        assert_eq!(view.lines[0].number, 2);
        assert_eq!(view.shown_text(), "雪 α");
        assert_eq!(view.output.as_ref().unwrap().text, text);
        assert_eq!(view.output.as_ref().unwrap().exit, Some(7));
        view.begin();
        view.finish(Err("request failed".into()));
        assert!(!view.running);
        assert_eq!(view.output.as_ref().unwrap().text, text);
        assert_eq!(view.filter, "雪");
        view.begin();
        view.finish(Ok(CommandOutput {
            exit_code: Some(0),
            ..Default::default()
        }));
        assert!(view.error.is_none());
        assert!(view.lines.is_empty());
    }
    #[test]
    fn display_bounds_do_not_discard_the_received_result() {
        let text = (0..30_000)
            .map(|i| format!("line-{i}\n"))
            .collect::<String>()
            + &"雪".repeat(2000);
        let mut view = Console::default();
        view.finish(Ok(CommandOutput {
            stdout: Some(text.clone()),
            ..Default::default()
        }));
        assert_eq!(view.lines.len(), VISIBLE_LINES);
        assert_eq!(view.matches, 30_001);
        assert_eq!(view.lines[0].number, 20_002);
        assert!(view.shortened);
        assert_eq!(view.output.as_ref().unwrap().text, text);
        view.filter = "line-1\n".into();
        view.rebuild();
        assert!(view.lines.is_empty());
        view.filter = "line-12".into();
        view.rebuild();
        assert!(view.matches > 0);
        assert!(
            view.lines[0].number < 20_002,
            "filter searches omitted older rows too"
        );
    }
}
