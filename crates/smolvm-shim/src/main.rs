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
    service::run_shim();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("containerd-shim-smolvm-v2 only runs on Linux Kubernetes nodes");
    std::process::exit(1);
}
