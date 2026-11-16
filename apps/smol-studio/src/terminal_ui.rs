use crate::design;
use eframe::egui::{self, Color32, FontId};
use smol_studio::{runtime::Runtime, terminal::Terminal};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

const MAX_SESSIONS: usize = 8;

#[derive(Clone)]
enum Source {
    Machine(Runtime, String),
    Container(String, String),
}
struct Session {
    id: u64,
    source: Source,
    view: TerminalWindow,
}

/// One workspace owns every shell, independently of the selected resource.
#[derive(Default)]
pub struct Terminals {
    sessions: Vec<Session>,
    selected: usize,
    next_id: u64,
    open: bool,
    error: Option<String>,
}
impl Terminals {
    pub fn open_machine(
        &mut self,
        ctx: &egui::Context,
        runtime: Runtime,
        name: String,
    ) -> Result<(), String> {
        self.add(ctx, Source::Machine(runtime, name))
    }
    pub fn open_container(
        &mut self,
        ctx: &egui::Context,
        id: String,
        name: String,
    ) -> Result<(), String> {
        self.add(ctx, Source::Container(id, name))
    }
    fn add(&mut self, ctx: &egui::Context, source: Source) -> Result<(), String> {
        self.open = true;
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(
                "Eight terminal sessions are open. End a session before opening another.".into(),
            );
        }
        let view = match &source {
            Source::Machine(runtime, name) => {
                TerminalWindow::new(ctx, runtime.clone(), name.clone())
            }
            Source::Container(id, name) => TerminalWindow::for_container(ctx, id, name)?,
        };
        self.next_id += 1;
        self.sessions.push(Session {
            id: self.next_id,
            source,
            view,
        });
        self.selected = self.sessions.len() - 1;
        self.error = None;
        ctx.request_repaint();
        Ok(())
    }
    fn end_selected(&mut self) {
        self.sessions.remove(self.selected);
        self.selected = self.selected.min(self.sessions.len().saturating_sub(1));
        self.error = None;
        if let Some(session) = self.sessions.get_mut(self.selected) {
            session.view.focus_next = true;
        } else {
            self.open = false;
        }
    }
    pub fn show_error(&mut self, error: String) {
        self.open = true;
        self.error = Some(error);
    }
    pub fn focused(&self, ctx: &egui::Context) -> bool {
        self.open
            && self
                .sessions
                .get(self.selected)
                .is_some_and(|session| session.view.focused(ctx))
    }
    pub fn status_button(&mut self, ui: &mut egui::Ui) {
        if !self.sessions.is_empty()
            && ui
                .small_button(format!("Terminals ({})", self.sessions.len()))
                .on_hover_text("Show open shells; hiding the window keeps sessions running.")
                .clicked()
        {
            self.open = true;
            self.sessions[self.selected].view.focus_next = true;
        }
    }
    pub fn ui(&mut self, ctx: &egui::Context, enabled: bool) {
        for (index, session) in self.sessions.iter().enumerate() {
            session.view.visible.store(
                self.open
                    && self.selected == index
                    && ctx.input(|i| i.viewport().minimized != Some(true)),
                Ordering::Relaxed,
            );
        }
        if !self.open {
            return;
        }
        let mut open = self.open;
        let mut duplicate = None;
        let mut end = false;
        let size =
            (ctx.content_rect().size() - egui::vec2(48.0, 80.0)).min(egui::vec2(900.0, 540.0));
        egui::Window::new("Terminals")
            .id(egui::Id::unique("terminal-workspace"))
            .open(&mut open)
            .default_size(size)
            .default_pos(ctx.content_rect().center() - size / 2.0)
            .min_size([420.0, 240.0])
            .collapsible(false)
            .show(ctx, |ui| {
                if !enabled { ui.disable(); }
                egui::ScrollArea::horizontal().id_salt("terminal-tabs").auto_shrink([false, true]).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        for (index, session) in self.sessions.iter_mut().enumerate() {
                            let label = format!("{} · {}", session.id, session.view.name);
                            let response = ui.add_sized([180.0, 30.0], egui::Button::new(&label).selected(self.selected == index).truncate()).on_hover_text(&label);
                            if response.clicked() {
                                self.selected = index;
                                session.view.focus_next = true;
                            }
                            if session.view.focus_next { response.scroll_to_me(Some(egui::Align::Center)); }
                        }
                    });
                });
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(self.sessions.len() < MAX_SESSIONS && !self.sessions.is_empty(), egui::Button::new("+ New shell")).on_hover_text("Open another shell on the selected machine or container.").on_disabled_hover_text("End a session before opening another; up to eight can stay open.").clicked() {
                        duplicate = self.sessions.get(self.selected).map(|s| s.source.clone());
                    }
                    if ui.add_enabled(!self.sessions.is_empty(), egui::Button::new("End session")).on_hover_text("Close this shell and its commands. The machine or container keeps running.").clicked() { end = true; }
                    ui.label(egui::RichText::new("Hiding this window keeps sessions running.").size(11.0).color(design::palette(ui).muted));
                });
                ui.add_space(8.0);
                if let Some(error) = &self.error {
                    design::error_notice(ui, "Terminal could not be opened", error);
                }
                if let Some(session) = self.sessions.get_mut(self.selected) {
                    ui.push_id(session.id, |ui| session.view.contents(ui));
                }
            });
        self.open = open;
        if end {
            self.end_selected();
        }
        if let Some(source) = duplicate
            && let Err(error) = self.add(ctx, source)
        {
            self.show_error(error);
        }
    }
}

pub struct TerminalWindow {
    terminal: Terminal,
    name: String,
    focus_next: bool,
    visible: Arc<AtomicBool>,
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
        let visible = Arc::new(AtomicBool::new(true));
        let wake_visible = visible.clone();
        Self {
            terminal: Terminal::start(runtime, name.clone(), move || {
                ctx.request_repaint_after(std::time::Duration::from_millis(
                    if wake_visible.load(Ordering::Relaxed) {
                        16
                    } else {
                        500
                    },
                ))
            }),
            name,
            focus_next: true,
            visible,
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
        let visible = Arc::new(AtomicBool::new(true));
        let wake_visible = visible.clone();
        Ok(Self {
            terminal: Terminal::container(id, move || {
                ctx.request_repaint_after(std::time::Duration::from_millis(
                    if wake_visible.load(Ordering::Relaxed) {
                        16
                    } else {
                        500
                    },
                ))
            })?,
            name: format!("{name} · container"),
            focus_next: true,
            visible,
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
    fn contents(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut state = self.terminal.state.lock().unwrap();
        if self.revision != state.revision {
            self.revision = state.revision;
            self.selection = None;
        }
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(&state.status)
                    .size(11.5)
                    .color(design::palette(ui).muted),
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
                            .color(design::palette(ui).muted),
                    );
                }
            });
        });
        ui.label(
            egui::RichText::new("Drag to select · scroll for history · Shift+Page Up / Down")
                .size(11.0)
                .color(design::palette(ui).muted),
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
        if self.focus_next && ui.is_enabled() {
            response.request_focus();
            self.focus_next = false;
        }
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
                if selected.is_some_and(|(start, end)| (row, col) >= start && (row, col) < end) {
                    painter.rect_filled(
                        egui::Rect::from_min_size(
                            pos,
                            egui::vec2(cell.x * if c.is_wide() { 2.0 } else { 1.0 }, cell.y),
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
            let pos =
                rect.min + egui::vec2(col as f32 * cell.x, row as f32 * cell.y + cell.y - 2.0);
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
        if response.has_focus() && ui.is_enabled() {
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
                        if cfg!(target_os = "macos") || ctx.input(|i| i.modifiers.shift) =>
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
    #[cfg(unix)]
    fn shell_fixture() -> (tempfile::TempDir, Runtime) {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("test-cli");
        std::fs::write(&path, "#!/bin/sh\nprintf 'ready\\n'\nwhile IFS= read -r line; do printf 'got:%s\\n' \"$line\"; done\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (
            root,
            Runtime {
                executable: path,
                state_dir: None,
            },
        )
    }
    #[cfg(unix)]
    fn wait_until(condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !condition() {
            assert!(
                std::time::Instant::now() < deadline,
                "shell did not respond"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    #[test]
    #[cfg(unix)]
    fn shells_survive_switching_and_hiding_and_close_independently() {
        let (_root, runtime) = shell_fixture();
        let ctx = egui::Context::default();
        let mut terminals = Terminals::default();
        terminals
            .open_machine(&ctx, runtime.clone(), "first".into())
            .unwrap();
        let first = terminals.sessions[0].view.terminal.state.clone();
        terminals.sessions[0]
            .view
            .terminal
            .input(b"first-only\n".to_vec())
            .unwrap();
        terminals
            .open_machine(&ctx, runtime, "second".into())
            .unwrap();
        let second_id = terminals.sessions[1].id;
        let second = terminals.sessions[1].view.terminal.state.clone();
        terminals.sessions[1]
            .view
            .terminal
            .input(b"second-only\n".to_vec())
            .unwrap();
        wait_until(|| {
            first
                .lock()
                .unwrap()
                .parser
                .screen()
                .contents()
                .contains("got:first-only")
                && second
                    .lock()
                    .unwrap()
                    .parser
                    .screen()
                    .contents()
                    .contains("got:second-only")
        });
        assert!(
            !first
                .lock()
                .unwrap()
                .parser
                .screen()
                .contents()
                .contains("second-only")
        );
        terminals.open = false;
        terminals.ui(&ctx, true);
        assert!(!first.lock().unwrap().exited);
        assert!(!second.lock().unwrap().exited);
        assert!(!terminals.focused(&ctx));
        terminals.selected = 0;
        terminals.end_selected();
        wait_until(|| first.lock().unwrap().exited);
        assert_eq!(terminals.sessions[0].id, second_id);
        terminals.sessions[0]
            .view
            .terminal
            .input(b"still-usable\n".to_vec())
            .unwrap();
        wait_until(|| {
            second
                .lock()
                .unwrap()
                .parser
                .screen()
                .contents()
                .contains("got:still-usable")
        });
        drop(terminals);
        wait_until(|| second.lock().unwrap().exited);
    }
    #[test]
    #[cfg(unix)]
    fn session_limit_preserves_open_shells_and_releases_on_close() {
        let (_root, runtime) = shell_fixture();
        let ctx = egui::Context::default();
        let mut terminals = Terminals::default();
        for _ in 0..MAX_SESSIONS {
            terminals
                .open_machine(&ctx, runtime.clone(), "same-machine".into())
                .unwrap();
        }
        let ids: Vec<_> = terminals.sessions.iter().map(|s| s.id).collect();
        assert!(
            terminals
                .open_machine(&ctx, runtime.clone(), "overflow".into())
                .is_err()
        );
        assert_eq!(
            ids,
            terminals.sessions.iter().map(|s| s.id).collect::<Vec<_>>()
        );
        let closed = terminals.sessions[terminals.selected]
            .view
            .terminal
            .state
            .clone();
        terminals.end_selected();
        wait_until(|| closed.lock().unwrap().exited);
        terminals
            .open_machine(&ctx, runtime, "replacement".into())
            .unwrap();
        assert_eq!(terminals.sessions.len(), MAX_SESSIONS);
        assert!(terminals.sessions.last().unwrap().id > *ids.last().unwrap());
        let states: Vec<_> = terminals
            .sessions
            .iter()
            .map(|s| s.view.terminal.state.clone())
            .collect();
        drop(terminals);
        wait_until(|| states.iter().all(|s| s.lock().unwrap().exited));
    }
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
