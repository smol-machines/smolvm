use eframe::egui::{self, Color32, FontId};
use smol_studio::{runtime::Runtime, terminal::Terminal};

pub struct TerminalWindow {
    terminal: Terminal,
    name: String,
    size: (u16, u16),
    error: Option<String>,
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
        })
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
                ui.horizontal(|ui| {
                    ui.label(&state.status);
                    if ui.button("Copy screen").clicked() {
                        ctx.copy_text(state.parser.screen().contents());
                    }
                    if ui.button("Scroll back").clicked() {
                        let offset = state.parser.screen().scrollback();
                        state.parser.screen_mut().set_scrollback(offset + 12);
                    }
                    if ui.button("Latest").clicked() {
                        state.parser.screen_mut().set_scrollback(0);
                    }
                });
                if let Some(error) = &self.error {
                    ui.colored_label(Color32::DARK_RED, error);
                }
                let font = FontId::monospace(14.0);
                let cell = egui::vec2(ui.fonts_mut(|f| f.glyph_width(&font, 'M')), 18.0);
                let cols = ((ui.available_width() / cell.x) as u16).clamp(10, 240);
                let rows = ((ui.available_height() / cell.y) as u16).clamp(2, 100);
                if self.size != (rows, cols) && self.terminal.resize(rows, cols) {
                    self.size = (rows, cols);
                }
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(cols as f32 * cell.x, rows as f32 * cell.y),
                    egui::Sense::click(),
                );
                if response.clicked() {
                    response.request_focus();
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
                if response.has_focus() && !exited {
                    for event in ctx.input(|i| i.events.clone()) {
                        let bytes = match event {
                            // egui turns Ctrl-C/Ctrl-X into clipboard events before
                            // widgets see key presses; a focused terminal needs the bytes.
                            egui::Event::Copy
                                if cfg!(target_os = "macos")
                                    || ctx.input(|i| i.modifiers.shift) =>
                            {
                                ctx.copy_text(
                                    self.terminal
                                        .state
                                        .lock()
                                        .unwrap()
                                        .parser
                                        .screen()
                                        .contents(),
                                );
                                None
                            }
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
                        if let Some(bytes) = bytes
                            && let Err(e) = self.terminal.input(bytes)
                        {
                            self.error = Some(e);
                        }
                    }
                }
            });
        open
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
