#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod cloud_ui;
mod design;
mod docker_ui;
mod file_picker;
mod machine_settings_ui;
mod terminal_ui;
mod ui;

use eframe::egui;
use smol_studio::runtime::Runtime;

fn main() -> eframe::Result {
    let mut runtime = Runtime::discover();
    match smol_studio::preferences::Preferences::load() {
        Ok(p) => {
            if std::env::var_os("SMOL_STUDIO_CLI").is_none()
                && let Some(path) = p.smol_cli
            {
                runtime.executable = path;
            }
        }
        Err(e) => eprintln!("{e}"),
    }
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--cli") => runtime.executable = path_argument(&mut args, "--cli"),
            Some("--help" | "-h") => {
                println!(
                    "Smol Studio\n\nUsage: smol-studio [--cli PATH]\n\nThe Smol CLI is found beside Studio, on PATH, or through SMOL_STUDIO_CLI.\nClosing Studio leaves machines running."
                );
                return Ok(());
            }
            _ => {
                eprintln!("Unknown argument: {}", arg.to_string_lossy());
                std::process::exit(2);
            }
        }
    }
    let _instance = smol_studio::preferences::instance_lock().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Smol Studio")
            .with_app_id("com.smolmachines.studio")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([960.0, 640.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/brand-mark.png"))
                    .expect("bundled Studio icon"),
            ),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut options.wgpu_options.wgpu_setup {
        setup.power_preference = eframe::wgpu::PowerPreference::LowPower;
    }
    eframe::run_native(
        "Smol Studio",
        options,
        Box::new(move |cc| Ok(Box::new(ui::Studio::new(cc, runtime)))),
    )
}

fn path_argument(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> std::path::PathBuf {
    args.next()
        .filter(|value| !value.is_empty())
        .map(Into::into)
        .unwrap_or_else(|| {
            eprintln!("{flag} needs a path. Run smol-studio --help for usage.");
            std::process::exit(2);
        })
}
