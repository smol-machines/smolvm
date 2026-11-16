//! Native appearance events come from winit on macOS/Windows; Linux uses the
//! read-only desktop portal because winit does not report a Linux system theme.
#[cfg(target_os = "linux")]
#[path = "appearance/linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Appearance;

#[cfg(not(target_os = "linux"))]
pub struct Appearance;
#[cfg(not(target_os = "linux"))]
impl Appearance {
    pub fn new(_ctx: &eframe::egui::Context) -> Self {
        Self
    }
    pub fn input(&self, _raw: &mut eframe::egui::RawInput) {}
}
