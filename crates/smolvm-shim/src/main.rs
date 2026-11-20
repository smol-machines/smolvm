//! containerd-shim-smolvm-v2 — shim v2 entrypoint.
//!
//! See docs/kubernetes-runtime.md for the architecture. Linux-only; a stub on
//! other platforms so workspace checks pass everywhere.

#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
mod bundle;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod reaper;
#[cfg(target_os = "linux")]
mod service;
#[cfg(target_os = "linux")]
mod task;

#[cfg(target_os = "linux")]
fn main() {
    // The engine boots each VM by spawning its own executable with `_boot-vm`
    // (see `agent::manager`, which resolves /proc/self/exe). This binary links
    // the engine, so it serves that subcommand itself rather than needing a
    // separate `_boot-vm`-capable helper installed alongside it and pointed to
    // by SMOLVM_BOOT_BINARY. Checked before the shim service starts, because a
    // boot subprocess must never register itself with containerd.
    let mut args = std::env::args_os().skip(1);
    let command = args.next();
    if matches!(
        command.as_deref().and_then(|a| a.to_str()),
        Some("_boot-vm" | "_boot-vm-owned")
    ) {
        let Some(config) = args.next() else {
            eprintln!("boot requires a boot-config path");
            std::process::exit(2);
        };
        let result = if command.as_deref() == Some(std::ffi::OsStr::new("_boot-vm-owned")) {
            let Some(token) = args.next().and_then(|token| token.into_string().ok()) else {
                eprintln!("owned boot requires a startup token");
                std::process::exit(2);
            };
            smolvm::internal_boot::run_owned(config.into(), token)
        } else {
            smolvm::internal_boot::run(config.into())
        };
        if let Err(e) = result {
            eprintln!("boot failed: {e}");
            std::process::exit(1);
        }
        return;
    }
    service::run_shim();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("containerd-shim-smolvm-v2 only runs on Linux Kubernetes nodes");
    std::process::exit(1);
}
