use crate::design;
use eframe::egui::{self, Color32, FontId};
use smol_studio::{runtime::Runtime, terminal::Terminal};

pub struct TerminalWindow {
    terminal: Terminal,
    name: String,
    size: (u16, u16),
    error: Option<String>,
    focus_id: Option<egui::Id>,
    selection: Option<Selection>,
    revision: u64,
    scroll_pixels: f32,
}
impl TerminalWindow {
    pub fn new(ctx: &egui::Context, runtime: Runtime, name: String) -> Self {
        let ctx = ctx.clone();
        Self {
            terminal: Terminal::start(runtime, name.clone(), move || {
                ctx.request_repaint_after(std::time::Duration::from_millis(16))
            }),
            name,
            size: (24, 80),
            error: None,
            focus_id: None,
            selection: None,
            revision: 0,
            scroll_pixels: 0.0,
        }
    }
    pub fn for_container(ctx: &egui::Context, id: &str, name: &str) -> Result<Self, String> {
        let ctx = ctx.clone();
        Ok(Self {
            terminal: Terminal::container(id, move || {
                ctx.request_repaint_after(std::time::Duration::from_millis(16))
            })?,
            name: format!("{name} · container"),
            size: (24, 80),
            error: None,
            focus_id: None,
            selection: None,
            revision: 0,
            scroll_pixels: 0.0,
        })
    }
    pub fn focused(&self, ctx: &egui::Context) -> bool {
        self.focus_id
            .is_some_and(|id| ctx.memory(|m| m.has_focus(id)))
    }
    pub fn ui(&mut self, ctx: &egui::Context) -> bool {
        let mut open = true;
        egui::Window::new(format!("Terminal · {}", self.name))
            .id(egui::Id::unique(("terminal", &self.name)))
            .open(&mut open)
            .default_size([860.0, 500.0])
            .default_pos(ctx.content_rect().center() - egui::vec2(430.0, 250.0))
            .collapsible(false)
            .min_size([420.0, 240.0])
            .show(ctx, |ui| {
                let mut state = self.terminal.state.lock().unwrap();
                if self.revision != state.revision {
                    self.revision = state.revision;
                    self.selection = None;
                }
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&state.status)
                            .size(11.5)
                            .color(design::MUTED),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let screen = state.parser.screen();
                        let offset = screen.scrollback();
                        if ui
                            .add_enabled(offset > 0, egui::Button::new("Latest"))
                            .clicked()
                        {
                            state.parser.screen_mut().set_scrollback(0);
                            self.selection = None;
                        }
                        if ui
                            .button(if self.selection.is_some() {
                                "Copy selection"
                            } else {
                                "Copy screen"
                            })
                            .clicked()
                        {
                            ctx.copy_text(copy_text(state.parser.screen(), self.selection));
                        }
                        if offset > 0 {
                            ui.label(
                                egui::RichText::new(format!("{offset} lines back"))
                                    .size(11.5)
                                    .color(design::MUTED),
                            );
                        }
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "Drag to select · scroll for history · Shift+Page Up / Down",
                    )
                    .size(11.0)
                    .color(design::MUTED),
                );
                ui.add_space(6.0);
                if let Some(error) = &self.error {
                    ui.colored_label(Color32::DARK_RED, error);
                }
                let font = FontId::monospace(14.0);
                let cell = egui::vec2(ui.fonts_mut(|f| f.glyph_width(&font, 'M')), 18.0);
                let cols = ((ui.available_width() / cell.x) as u16).clamp(10, 240);
                let rows = ((ui.available_height() / cell.y) as u16).clamp(2, 100);
                if self.size != (rows, cols) && self.terminal.resize(rows, cols) {
                    self.size = (rows, cols);
                    self.selection = None;
                }
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(cols as f32 * cell.x, rows as f32 * cell.y),
                    egui::Sense::click_and_drag(),
                );
                self.focus_id = Some(response.id);
                if response.clicked() {
                    response.request_focus();
                    self.selection = None;
                }
                if response.hovered() && !state.parser.screen().alternate_screen() {
                    let delta = ui.input_mut(|i| std::mem::take(&mut i.smooth_scroll_delta.y));
                    self.scroll_pixels += delta;
                    let lines = (self.scroll_pixels / cell.y).trunc() as i32;
                    if lines != 0 {
                        self.scroll_pixels -= lines as f32 * cell.y;
                        scroll(state.parser.screen_mut(), lines);
                        self.selection = None;
                    }
                }
                if response.drag_started()
                    && let Some(origin) = ctx.input(|i| i.pointer.press_origin())
                {
                    response.request_focus();
                    let anchor = cell_at(origin, rect, cell, rows, cols);
                    self.selection = Some(Selection {
                        anchor,
                        focus: anchor,
                    });
                }
                if response.dragged()
                    && let Some(pos) = response.interact_pointer_pos()
                    && let Some(selection) = &mut self.selection
                {
                    selection.focus = cell_at(pos, rect, cell, rows, cols);
                }
                ui.memory_mut(|memory| {
                    memory.set_focus_lock_filter(
                        response.id,
                        egui::EventFilter {
                            tab: true,
                            horizontal_arrows: true,
                            vertical_arrows: true,
                            escape: true,
                        },
                    )
                });
                let painter = ui.painter_at(rect);
                painter.rect_filled(rect, 3, Color32::from_rgb(24, 27, 34));
                let screen = state.parser.screen();
                let selected = self.selection.map(|s| s.bounds(screen));
                for row in 0..rows {
                    for col in 0..cols {
                        let Some(c) = screen.cell(row, col) else {
                            continue;
                        };
                        if c.is_wide_continuation() {
                            continue;
                        }
                        let pos = rect.min + egui::vec2(col as f32 * cell.x, row as f32 * cell.y);
                        let mut fg = color(c.fgcolor(), Color32::from_rgb(225, 228, 234));
                        let mut bg = color(c.bgcolor(), Color32::from_rgb(24, 27, 34));
                        if c.inverse() {
                            std::mem::swap(&mut fg, &mut bg);
                        }
                        painter.rect_filled(
                            egui::Rect::from_min_size(
                                pos,
                                egui::vec2(cell.x * if c.is_wide() { 2.0 } else { 1.0 }, cell.y),
                            ),
                            0,
                            bg,
                        );
                        if selected
                            .is_some_and(|(start, end)| (row, col) >= start && (row, col) < end)
                        {
                            painter.rect_filled(
                                egui::Rect::from_min_size(
                                    pos,
                                    egui::vec2(
                                        cell.x * if c.is_wide() { 2.0 } else { 1.0 },
                                        cell.y,
                                    ),
                                ),
                                0,
                                Color32::from_rgba_unmultiplied(125, 161, 220, 100),
                            );
                        }
                        painter.text(pos, egui::Align2::LEFT_TOP, c.contents(), font.clone(), fg);
                    }
                }
                if response.has_focus()
                    && !state.exited
                    && !screen.hide_cursor()
                    && screen.scrollback() == 0
                {
                    let (row, col) = screen.cursor_position();
                    let pos = rect.min
                        + egui::vec2(col as f32 * cell.x, row as f32 * cell.y + cell.y - 2.0);
                    painter.rect_filled(
                        egui::Rect::from_min_size(pos, egui::vec2(cell.x, 2.0)),
                        0,
                        Color32::WHITE,
                    );
                }
                let application_cursor = screen.application_cursor();
                let paste_mode = screen.bracketed_paste();
                let exited = state.exited;
                drop(state);
                if response.has_focus() {
                    for event in ctx.input(|i| i.events.clone()) {
                        if let egui::Event::Key {
                            key,
                            modifiers,
                            pressed: true,
                            ..
                        } = &event
                        {
                            if !cfg!(target_os = "macos")
                                && modifiers.ctrl
                                && modifiers.shift
                                && *key == egui::Key::C
                            {
                                ctx.copy_text(copy_text(
                                    self.terminal.state.lock().unwrap().parser.screen(),
                                    self.selection,
                                ));
                                continue;
                            }
                            if let Some(lines) = history_key(*key, *modifiers, rows) {
                                let mut state = self.terminal.state.lock().unwrap();
                                if !state.parser.screen().alternate_screen() {
                                    scroll(state.parser.screen_mut(), lines);
                                    self.selection = None;
                                    ctx.request_repaint();
                                    continue;
                                }
                            }
                        }
                        let bytes = match event {
                            // egui turns Ctrl-C/Ctrl-X into clipboard events before
                            // widgets see key presses; a focused terminal needs the bytes.
                            egui::Event::Copy
                                if cfg!(target_os = "macos")
                                    || ctx.input(|i| i.modifiers.shift) =>
                            {
                                ctx.copy_text(copy_text(
                                    self.terminal.state.lock().unwrap().parser.screen(),
                                    self.selection,
                                ));
                                None
                            }
                            _ if exited => None,
                            egui::Event::Copy => Some(vec![3]),
                            egui::Event::Cut => Some(vec![24]),
                            egui::Event::Text(text) => Some(text.into_bytes()),
                            egui::Event::Paste(text) => Some(if paste_mode {
                                format!("\x1b[200~{text}\x1b[201~").into_bytes()
                            } else {
                                text.into_bytes()
                            }),
                            egui::Event::Key {
                                key,
                                pressed: true,
                                modifiers,
                                ..
                            } => key_bytes(key, modifiers, application_cursor),
                            _ => None,
                        };
                        if let Some(bytes) = bytes {
                            self.selection = None;
                            self.terminal
                                .state
                                .lock()
                                .unwrap()
                                .parser
                                .screen_mut()
                                .set_scrollback(0);
                            ctx.request_repaint();
                            self.error = self.terminal.input(bytes).err();
                        }
                    }
                }
            });
        open
    }
}

#[derive(Clone, Copy)]
struct Selection {
    anchor: (u16, u16),
    focus: (u16, u16),
}
impl Selection {
    fn bounds(self, screen: &vt100::Screen) -> ((u16, u16), (u16, u16)) {
        let (rows, cols) = screen.size();
        let clamp = |(row, col): (u16, u16)| (row.min(rows.get() - 1), col.min(cols.get()));
        let a = clamp(self.anchor);
        let b = clamp(self.focus);
        let (mut start, mut end) = (a.min(b), a.max(b));
        // Selecting either half of a wide character copies the whole character.
        if screen
            .cell(start.0, start.1)
            .is_some_and(|c| c.is_wide_continuation())
        {
            start.1 = start.1.saturating_sub(1);
        }
        if screen
            .cell(end.0, end.1)
            .is_some_and(|c| c.is_wide_continuation())
        {
            end.1 = end.1.saturating_add(1).min(cols.get());
        }
        (start, end)
    }
}
fn cell_at(
    pos: egui::Pos2,
    rect: egui::Rect,
    cell: egui::Vec2,
    rows: u16,
    cols: u16,
) -> (u16, u16) {
    let row = ((pos.y - rect.top()) / cell.y)
        .floor()
        .clamp(0.0, f32::from(rows - 1)) as u16;
    let col = ((pos.x - rect.left()) / cell.x)
        .round()
        .clamp(0.0, f32::from(cols)) as u16;
    (row, col)
}
fn copy_text(screen: &vt100::Screen, selection: Option<Selection>) -> String {
    match selection {
        Some(selection) => {
            let ((sr, sc), (er, ec)) = selection.bounds(screen);
            screen.contents_between(sr, sc, er, ec)
        }
        None => screen.contents(),
    }
}
fn scroll(screen: &mut vt100::Screen, lines: i32) {
    let offset = screen.scrollback();
    screen.set_scrollback(if lines >= 0 {
        offset.saturating_add(lines as usize)
    } else {
        offset.saturating_sub(lines.unsigned_abs() as usize)
    });
}
fn history_key(key: egui::Key, modifiers: egui::Modifiers, rows: u16) -> Option<i32> {
    if !modifiers.shift || modifiers.ctrl || modifiers.alt || modifiers.mac_cmd {
        return None;
    }
    match key {
        egui::Key::PageUp => Some(i32::from(rows.saturating_sub(1))),
        egui::Key::PageDown => Some(-i32::from(rows.saturating_sub(1))),
        egui::Key::Home => Some(i32::MAX),
        egui::Key::End => Some(i32::MIN),
        _ => None,
    }
}
fn key_bytes(key: egui::Key, modifiers: egui::Modifiers, application: bool) -> Option<Vec<u8>> {
    use egui::Key;
    if modifiers.ctrl {
        let code = match key {
            Key::A => 1,
            Key::B => 2,
            Key::C => 3,
            Key::D => 4,
            Key::E => 5,
            Key::F => 6,
            Key::H => 8,
            Key::K => 11,
            Key::L => 12,
            Key::N => 14,
            Key::P => 16,
            Key::R => 18,
            Key::U => 21,
            Key::W => 23,
            Key::Z => 26,
            _ => return None,
        };
        return Some(vec![code]);
    }
    let arrow = match key {
        Key::ArrowUp => Some('A'),
        Key::ArrowDown => Some('B'),
        Key::ArrowRight => Some('C'),
        Key::ArrowLeft => Some('D'),
        _ => None,
    };
    if let Some(arrow) = arrow {
        return Some(format!("\x1b{}{arrow}", if application { 'O' } else { '[' }).into_bytes());
    }
    Some(match key {
        Key::Enter => b"\r".to_vec(),
        Key::Backspace => vec![127],
        Key::Tab => b"\t".to_vec(),
        Key::Escape => vec![27],
        Key::Home => b"\x1b[H".to_vec(),
        Key::End => b"\x1b[F".to_vec(),
        Key::Delete => b"\x1b[3~".to_vec(),
        Key::PageUp => b"\x1b[5~".to_vec(),
        Key::PageDown => b"\x1b[6~".to_vec(),
        _ => return None,
    })
}
fn color(c: vt100::Color, default: Color32) -> Color32 {
    match c {
        vt100::Color::Default => default,
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(i) => {
            const BASIC: [[u8; 3]; 16] = [
                [0, 0, 0],
                [205, 49, 49],
                [13, 188, 121],
                [229, 229, 16],
                [36, 114, 200],
                [188, 63, 188],
                [17, 168, 205],
                [229, 229, 229],
                [102, 102, 102],
                [241, 76, 76],
                [35, 209, 139],
                [245, 245, 67],
                [59, 142, 234],
                [214, 112, 214],
                [41, 184, 219],
                [255, 255, 255],
            ];
            let [r, g, b] = if i < 16 {
                BASIC[i as usize]
            } else if i >= 232 {
                [8 + (i - 232) * 10; 3]
            } else {
                let n = i - 16;
                let value = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
                [value(n / 36), value(n / 6 % 6), value(n % 6)]
            };
            Color32::from_rgb(r, g, b)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU16;
    fn parser(rows: u16, cols: u16) -> vt100::Parser {
        vt100::Parser::new(
            NonZeroU16::new(rows).unwrap(),
            NonZeroU16::new(cols).unwrap(),
            1000,
        )
    }

    #[test]
    fn selection_preserves_unicode_and_soft_wraps_in_both_directions() {
        let mut p = parser(4, 8);
        p.process("A世界e\u{301}Z\r\nnext".as_bytes());
        let selection = Selection {
            anchor: (0, 2),
            focus: (0, 4),
        };
        assert_eq!(copy_text(p.screen(), Some(selection)), "世界");
        assert_eq!(
            copy_text(
                p.screen(),
                Some(Selection {
                    anchor: selection.focus,
                    focus: selection.anchor
                })
            ),
            "世界"
        );
        assert_eq!(
            copy_text(
                p.screen(),
                Some(Selection {
                    anchor: (0, 5),
                    focus: (1, 4)
                })
            ),
            "e\u{301}Z\nnext"
        );
        let mut wrapped = parser(4, 4);
        wrapped.process(b"abcdefgh");
        assert_eq!(
            copy_text(
                wrapped.screen(),
                Some(Selection {
                    anchor: (0, 0),
                    focus: (1, 4)
                })
            ),
            "abcdefgh"
        );
        // A resize between selection and copy remains bounded by the current screen.
        assert_eq!(
            copy_text(
                wrapped.screen(),
                Some(Selection {
                    anchor: (200, 200),
                    focus: (200, 210)
                })
            ),
            ""
        );
    }

    #[test]
    fn history_scrolling_is_bounded_and_copy_reads_the_visible_history() {
        let mut p = parser(3, 20);
        for i in 0..30 {
            p.process(format!("row-{i}\r\n").as_bytes());
        }
        let latest = p.screen().contents();
        scroll(p.screen_mut(), i32::MAX);
        assert_eq!(p.screen().scrollback(), p.screen().scrollback_len());
        assert!(copy_text(p.screen(), None).contains("row-0"));
        scroll(p.screen_mut(), i32::MIN);
        assert_eq!(p.screen().scrollback(), 0);
        assert_eq!(p.screen().contents(), latest);
    }

    #[test]
    fn history_shortcuts_leave_shell_navigation_and_interrupts_intact() {
        assert_eq!(
            history_key(egui::Key::PageUp, egui::Modifiers::SHIFT, 24),
            Some(23)
        );
        assert_eq!(
            history_key(egui::Key::PageDown, egui::Modifiers::SHIFT, 24),
            Some(-23)
        );
        assert_eq!(
            history_key(egui::Key::PageUp, egui::Modifiers::NONE, 24),
            None
        );
        assert_eq!(
            key_bytes(egui::Key::PageUp, egui::Modifiers::NONE, false),
            Some(b"\x1b[5~".to_vec())
        );
        assert_eq!(
            key_bytes(egui::Key::C, egui::Modifiers::CTRL, false),
            Some(vec![3])
        );
        assert_eq!(
            key_bytes(egui::Key::ArrowUp, egui::Modifiers::NONE, true),
            Some(b"\x1bOA".to_vec())
        );
    }
}
