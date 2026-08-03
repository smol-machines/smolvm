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

/// Node runtime layout laid down by `scripts/install-k8s-runtime.sh`.
#[cfg(target_os = "linux")]
const RUNTIME_ROOT: &str = "/var/lib/smolvm";

/// Point the embedded engine at the node's runtime artifacts.
///
/// containerd execs the shim with a minimal environment, from the bundle dir,
/// so nothing the engine discovers relative to `current_exe` resolves: libkrun
/// is not next to `/usr/local/bin/containerd-shim-smolvm-v2`, and neither is
/// the agent rootfs. Worse, the engine boots every VM as a subprocess
/// `<boot binary> _boot-vm <config.json>` defaulting to `current_exe` — and
/// this binary does not serve `_boot-vm`, so a pod sandbox would never boot.
/// Resolve all three against the install layout, honoring operator overrides.
///
/// Called from `main` before the tokio runtime exists, so the process is still
/// single-threaded and the `set_var`s are sound.
#[cfg(target_os = "linux")]
fn init_runtime_env() {
    let root = std::env::var_os("SMOLVM_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let root = std::path::PathBuf::from(RUNTIME_ROOT);
            std::env::set_var("SMOLVM_DATA_DIR", &root);
            root
        });
    if std::env::var_os("SMOLVM_LIB_DIR").is_none() {
        std::env::set_var("SMOLVM_LIB_DIR", root.join("lib"));
    }
    // `smolvm-vmm` is the installed smolvm binary, the one that serves `_boot-vm`.
    // Setting this also arms the boot child's parent-death watchdog, which is what
    // we want here: the pod VM belongs to this shim and must not outlive it.
    if std::env::var_os("SMOLVM_BOOT_BINARY").is_none() {
        std::env::set_var("SMOLVM_BOOT_BINARY", root.join("smolvm-vmm"));
    }
    // The rootfs otherwise resolves next to `current_exe` (a shim in /usr/local/bin
    // has none) or under `$HOME/.local/share/smolvm` — neither is where
    // install-k8s-runtime.sh lays it down. The Linux tarball's wrapper script sets
    // this same variable for the CLI; the shim has no wrapper, so set it here.
    if std::env::var_os("SMOLVM_AGENT_ROOTFS").is_none() {
        std::env::set_var("SMOLVM_AGENT_ROOTFS", root.join("agent-rootfs"));
    }
    // Root every dirs::-derived path (agent rootfs, per-VM dirs, machine db) at
    // the data root, the same relocation `smolvm serve` performs on this node.
    smolvm::process::apply_system_data_root(false);
}

#[cfg(target_os = "linux")]
fn main() {
    init_runtime_env();
    service::run_shim();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("containerd-shim-smolvm-v2 only runs on Linux Kubernetes nodes");
    std::process::exit(1);
}
