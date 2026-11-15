//! Native dialogs are polled by the UI and wake it only when work is ready.
use eframe::egui;
use std::{
    future::Future,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

type Selection = Option<Vec<rfd::FileHandle>>;

#[derive(Default)]
pub struct FilePicker {
    pending: Option<Pin<Box<dyn Future<Output = Selection>>>>,
}

impl FilePicker {
    pub fn is_open(&self) -> bool {
        self.pending.is_some()
    }

    pub fn open_folder(&mut self, frame: &eframe::Frame, current: &str, ctx: &egui::Context) {
        if self.is_open() {
            return;
        }
        let mut dialog = rfd::AsyncFileDialog::new()
            .set_parent(frame)
            .set_title("Share a folder with this machine");
        if Path::new(current).is_absolute() {
            dialog = dialog.set_directory(current);
        }
        self.pending = Some(Box::pin(async move {
            dialog.pick_folder().await.map(|folder| vec![folder])
        }));
        ctx.request_repaint();
    }

    pub fn open_compose(&mut self, frame: &eframe::Frame, current: &str, ctx: &egui::Context) {
        if self.is_open() {
            return;
        }
        let mut dialog = rfd::AsyncFileDialog::new()
            .set_parent(frame)
            .set_title("Open a Compose project")
            .add_filter("Compose files", &["yaml", "yml"])
            .add_filter("All files", &["*"]);
        if let Some(parent) = Path::new(current).parent().filter(|p| p.is_absolute()) {
            dialog = dialog.set_directory(parent);
        }
        self.pending = Some(Box::pin(dialog.pick_files()));
        ctx.request_repaint();
    }

    /// Outer None means pending; inner None means the dialog closed without a file.
    pub fn poll(&mut self, ctx: &egui::Context) -> Option<Selection> {
        let future = self.pending.as_mut()?;
        let waker = Waker::from(Arc::new(Repaint(ctx.clone())));
        match future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => None,
            Poll::Ready(selection) => {
                self.pending = None;
                ctx.request_repaint();
                Some(selection)
            }
        }
    }
}

struct Repaint(egui::Context);
impl Wake for Repaint {
    fn wake(self: Arc<Self>) {
        self.0.request_repaint();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.request_repaint();
    }
}
