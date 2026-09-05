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
    if args.next().as_deref().and_then(|a| a.to_str()) == Some("_boot-vm") {
        let Some(config) = args.next() else {
            eprintln!("_boot-vm requires a boot-config path");
            std::process::exit(2);
        };
        if let Err(e) = smolvm::internal_boot::run(std::path::PathBuf::from(config)) {
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
