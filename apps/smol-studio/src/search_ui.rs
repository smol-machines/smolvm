//! Resolve Find after visible search fields register, independently of panel draw order.
use eframe::egui::{
    self,
    text::{CCursor, CCursorRange},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Workspace,
    Output,
    Content,
}

#[derive(Clone, Copy)]
struct Target {
    id: egui::Id,
    scope: Scope,
    chars: usize,
}

fn key() -> egui::Id {
    egui::Id::unique("studio-find-target")
}

pub fn begin(ctx: &egui::Context) {
    ctx.data_mut(|data| data.remove::<Target>(key()));
}

pub fn register(ui: &egui::Ui, response: &egui::Response, scope: Scope, chars: usize) {
    if !response.enabled() || !ui.is_rect_visible(response.rect) {
        return;
    }
    ui.ctx().data_mut(|data| {
        if data
            .get_temp::<Target>(key())
            .is_none_or(|target| scope > target.scope)
        {
            data.insert_temp(
                key(),
                Target {
                    id: response.id,
                    scope,
                    chars,
                },
            );
        }
    });
}

pub fn finish(ctx: &egui::Context, allowed: bool) {
    let target = ctx.data(|data| data.get_temp::<Target>(key()));
    if allowed
        && let Some(target) = target
        && ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::F))
    {
        ctx.memory_mut(|memory| memory.request_focus(target.id));
        if let Some(mut state) = egui::TextEdit::load_state(ctx, target.id) {
            state.cursor.set_char_range(Some(CCursorRange::two(
                CCursor::new(0),
                CCursor::new(target.chars),
            )));
            state.store(ctx, target.id);
        }
        ctx.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct View {
        workspace: String,
        content: String,
        workspace_id: Option<egui::Id>,
        content_id: Option<egui::Id>,
    }
    impl View {
        fn frame(
            &mut self,
            ctx: &egui::Context,
            events: Vec<egui::Event>,
            content: Option<bool>,
            allowed: bool,
        ) {
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
                    begin(ctx);
                    egui::CentralPanel::default().show(root, |ui| {
                        self.workspace_id = Some(
                            crate::design::workspace_search(
                                ui,
                                &mut self.workspace,
                                "Search containers…",
                            )
                            .id,
                        );
                        if let Some(enabled) = content {
                            ui.add_enabled_ui(enabled, |ui| {
                                self.content_id = Some(
                                    crate::design::search(ui, &mut self.content, "Filter files…")
                                        .id,
                                );
                            });
                        }
                    });
                    finish(ctx, allowed);
                },
            );
            output.textures_delta.clear();
        }
    }
    fn find() -> Vec<egui::Event> {
        vec![egui::Event::Key {
            key: egui::Key::F,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::COMMAND,
        }]
    }

    #[test]
    fn find_filters_detail_without_changing_workspace_and_replaces_unicode_query() {
        let ctx = egui::Context::default();
        let mut view = View {
            workspace: "api".into(),
            content: "café雪".into(),
            ..Default::default()
        };
        view.frame(&ctx, vec![], Some(true), true);
        view.frame(&ctx, find(), Some(true), true);
        assert_eq!(ctx.memory(|m| m.focused()), view.content_id);
        view.frame(
            &ctx,
            vec![egui::Event::Text("README".into())],
            Some(true),
            true,
        );
        assert_eq!(view.content, "README");
        assert_eq!(view.workspace, "api");
    }

    #[test]
    fn find_falls_back_when_detail_is_absent_or_disabled_and_never_uses_stale_target() {
        let ctx = egui::Context::default();
        let mut view = View::default();
        view.frame(&ctx, find(), Some(true), true);
        for content in [None, Some(false)] {
            view.frame(&ctx, find(), content, true);
            assert_eq!(ctx.memory(|m| m.focused()), view.workspace_id);
        }
    }

    #[test]
    fn modal_or_terminal_gate_leaves_find_and_focus_with_owner() {
        let ctx = egui::Context::default();
        let mut view = View::default();
        view.frame(&ctx, vec![], Some(true), true);
        ctx.memory_mut(|m| m.request_focus(view.workspace_id.unwrap()));
        view.frame(&ctx, find(), Some(true), false);
        assert_eq!(ctx.memory(|m| m.focused()), view.workspace_id);
        assert!(ctx.input(|input| input.key_pressed(egui::Key::F)));
    }
}
