//! Platform menu integration; all app actions still enter the ordinary egui input path.
#[cfg(target_os = "macos")]
#[path = "desktop_menu/macos.rs"]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::DesktopMenu;

#[cfg(not(target_os = "macos"))]
pub struct DesktopMenu;
#[cfg(not(target_os = "macos"))]
impl DesktopMenu {
    pub fn new(_ctx: &eframe::egui::Context) -> Self {
        Self
    }
    pub fn input(&self, _raw: &mut eframe::egui::RawInput) -> bool {
        false
    }
    pub fn update(&self, _navigation: bool, _docker: bool, _close: bool) {}
}
