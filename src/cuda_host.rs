//! Host-side CUDA-over-vsock server (smolvm-owned lifecycle).
//!
//! When a machine is launched with CUDA enabled, smolvm starts this listener on
//! a per-VM AF_UNIX socket and points the launcher's `cuda_socket` at it (the
//! vsock port is registered `listen=false`, so libkrun connects *to* this
//! socket when the guest opens the CUDA port). Each guest connection is served
//! by [`smolvm_cuda::host::serve`] against a freshly-created backend.
//!
//! Backend selection is automatic per connection: the real driver
//! ([`GpuBackend`]) when `nvcuda.dll` / `libcuda.so.1` loads, otherwise the CPU
//! emulation backend so the transport still works (and is testable) on a host
//! with no NVIDIA GPU.

use crate::platform::uds::UdsListener;
use smolvm_cuda::host::{serve, Backend, CpuBackend, GpuBackend};
use std::path::Path;
use std::sync::OnceLock;
use std::thread;

/// Provider for the guest-RAM regions, each `(gpa_start, host_va, len)`,
/// installed by the launcher (via `krun_get_guest_ram`) before the VM starts.
/// Each connection's backend queries it to enable guest-RAM zero-copy
/// `memcpy_gpa_*`. `None` outside a microVM or on a libkrun without the API.
/// Guest RAM is usually split into a low and a high region around the 4 GiB
/// PCI hole.
type GuestRamProvider = Box<dyn Fn() -> Option<Vec<(u64, u64, u64)>> + Send + Sync>;
static GUEST_RAM: OnceLock<GuestRamProvider> = OnceLock::new();

/// Install the guest-RAM provider. Called once by the launcher before
/// `krun_start_enter`; the closure resolves lazily once the VM is up.
pub fn set_guest_ram_provider(f: GuestRamProvider) {
    let _ = GUEST_RAM.set(f);
}

/// Start the CUDA host server on `socket_path` in a background thread.
///
/// The caller passes the same path to `LaunchConfig::cuda_socket`. Returns once
/// the listener is bound; serving continues until the process exits.
pub fn start(socket_path: &Path) -> std::io::Result<()> {
    // Clean up any stale socket from a previous run.
    let _ = std::fs::remove_file(socket_path);

    let listener = UdsListener::bind(socket_path)?;
    let path_display = socket_path.display().to_string();

    thread::Builder::new()
        .name("cuda-host".into())
        .spawn(move || {
            tracing::info!(path = path_display, "CUDA host server listening");
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        thread::Builder::new()
                            .name("cuda-host-conn".into())
                            .spawn(move || {
                                let mut backend = make_backend();
                                if let Err(e) = serve(stream, backend.as_mut()) {
                                    tracing::debug!(error = %e, "CUDA host connection ended");
                                }
                            })
                            .ok();
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "CUDA host accept error");
                    }
                }
            }
        })?;

    Ok(())
}

/// Pick the best available backend for one connection: the real GPU driver if it
/// loads, else CPU emulation. Logged once per connection so the mode is visible.
fn make_backend() -> Box<dyn Backend> {
    match GpuBackend::load() {
        Ok(mut gpu) => {
            tracing::info!("cuda-host: GPU driver backend ready");
            // Enable guest-RAM zero-copy if the launcher published the regions.
            if let Some(regions) = GUEST_RAM.get().and_then(|f| f()) {
                tracing::info!(
                    count = regions.len(),
                    "cuda-host: guest-RAM zero-copy enabled"
                );
                gpu.set_guest_ram(regions);
            }
            Box::new(gpu)
        }
        Err(e) => {
            tracing::info!("cuda-host: no GPU driver ({e}) — CPU emulation backend");
            Box::new(CpuBackend::default())
        }
    }
}
