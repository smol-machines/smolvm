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

/// The host's CUDA wire fingerprint (see [`smolvm_cuda::PROTO_HASH`]). Re-exported
/// so smolvm-side callers (e.g. the boot-time stale-rootfs check in
/// `internal_boot`) can compare it against the shim hash stamped into the agent
/// rootfs, without taking a direct dependency on the `smolvm-cuda` crate.
pub use smolvm_cuda::PROTO_HASH;

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

    // One-time, launch-time preflight: if this host can't load the CUDA driver,
    // every guest connection falls back to a CPU-emulation backend that only
    // services a built-in test kernel, so a real workload (PyTorch, a custom
    // kernel, cuBLAS) dies deep inside the guest with a cryptic
    // CUDA_ERROR_NOT_FOUND. Warn the user plainly here instead. Warn-and-continue
    // rather than fail: the emulation backend is intentionally useful for the
    // built-in test path and for development on GPU-less hosts (e.g. macOS).
    // Skipped when relaying to an external daemon, which may own the GPU on a
    // different host than this process.
    if std::env::var_os("SMOLVM_CUDA_DAEMON").is_none() {
        if let Err(e) = GpuBackend::load() {
            eprintln!(
                "warning: CUDA remoting is enabled but this host has no usable CUDA GPU \
                 ({e}); guest CUDA calls will run on a CPU-emulation backend that only \
                 supports a built-in test kernel — real CUDA/PyTorch workloads will fail. \
                 Run on a Linux host with an NVIDIA GPU and driver for real acceleration."
            );
            tracing::warn!(error = %e, "cuda-host: no usable host GPU at launch; CPU-emulation fallback active");
        }
    }

    thread::Builder::new()
        .name("cuda-host".into())
        .spawn(move || {
            tracing::info!(path = path_display, "CUDA host server listening");
            // Shared-daemon mode: relay every guest connection to one CUDA daemon
            // instead of serving it in-process, so all VMs share that daemon's
            // single GPU context — the prerequisite for a forked clone to reuse a
            // golden VM's device memory (which lives in the daemon, not per-VM).
            //   SMOLVM_CUDA_SHARED=1  — smolvm spawns + manages the daemon.
            //   SMOLVM_CUDA_DAEMON=X  — relay to an external daemon at address X
            //                           (a host:port or a unix-socket path); also
            //                           overrides the managed one.
            let daemon = match std::env::var("SMOLVM_CUDA_DAEMON").ok() {
                Some(addr) => Some(addr),
                // The smolvm-managed daemon is unix-only (see `cuda_daemon`); on
                // other platforms SMOLVM_CUDA_SHARED just serves in-process.
                #[cfg(unix)]
                None if std::env::var("SMOLVM_CUDA_SHARED").as_deref() == Ok("1") => {
                    match crate::cuda_daemon::ensure_running() {
                        Ok(sock) => Some(sock.to_string_lossy().into_owned()),
                        Err(e) => {
                            tracing::warn!(error = %e, "cuda-host: managed daemon unavailable, serving in-process");
                            None
                        }
                    }
                }
                None => None,
            };
            if let Some(ref addr) = daemon {
                tracing::info!(daemon = %addr, "cuda-host: shared-daemon proxy mode");
            }
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let daemon = daemon.clone();
                        thread::Builder::new()
                            .name("cuda-host-conn".into())
                            .spawn(move || {
                                if let Some(addr) = daemon {
                                    if let Err(e) = proxy_to_daemon(stream, &addr) {
                                        tracing::debug!(error = %e, "CUDA daemon proxy ended");
                                    }
                                    return;
                                }
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

/// This VM's clone identity for the daemon-connection preamble, computed once.
/// `Some` iff this VMM process was launched from a fork snapshot (the boot
/// subprocess carries `SMOLVM_SNAPSHOT_DIR` per-process; the golden's process
/// never has it). The id is stable for this VM's lifetime and distinct across
/// sibling clones (per-process randomness ⊕ pid), so the daemon can key one
/// worker per clone and tell a clone's reconnect apart from a fresh clone.
fn fork_clone_id() -> Option<u64> {
    static ID: OnceLock<Option<u64>> = OnceLock::new();
    *ID.get_or_init(|| {
        std::env::var_os("SMOLVM_SNAPSHOT_DIR")?;
        let mut b = [0u8; 8];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b))
            .is_err()
        {
            b = (std::process::id() as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .to_le_bytes();
        }
        Some(u64::from_le_bytes(b) ^ u64::from(std::process::id()))
    })
}

/// Relay one guest connection to the shared CUDA daemon at `addr` (a byte pump
/// in both directions — the RPC is end-to-end between the guest shim and the
/// daemon, so smolvm only forwards frames). This is the minimal form of the
/// shared-host-daemon architecture: every VM's traffic lands in one process, so
/// they share a single GPU context and device memory.
///
/// A FORK-CLONE VM's proxy prepends the clone preamble (magic + clone id) so
/// the daemon routes this connection to the clone's isolating worker — and, by
/// its absence, serves the GOLDEN's own reconnect in-daemon instead of handing
/// it a worker's reconstructed COPY of its memory.
fn proxy_to_daemon(guest: crate::platform::uds::UdsStream, addr: &str) -> std::io::Result<()> {
    fn preamble() -> Option<[u8; 16]> {
        let id = fork_clone_id()?;
        let mut p = [0u8; 16];
        p[..8].copy_from_slice(&smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC);
        p[8..].copy_from_slice(&id.to_le_bytes());
        Some(p)
    }
    // A path (managed daemon) → unix socket; otherwise host:port → TCP.
    if addr.starts_with('/') {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            let mut daemon = std::os::unix::net::UnixStream::connect(addr)?;
            if let Some(p) = preamble() {
                daemon.write_all(&p)?;
            }
            let sd = daemon.try_clone()?;
            return pump(guest, daemon.try_clone()?, daemon, move || {
                let _ = sd.shutdown(std::net::Shutdown::Both);
            });
        }
        #[cfg(not(unix))]
        {
            let _ = guest;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unix-socket CUDA daemon unsupported on this platform; use SMOLVM_CUDA_DAEMON=host:port",
            ));
        }
    }
    let mut daemon = std::net::TcpStream::connect(addr)?;
    let _ = daemon.set_nodelay(true);
    if let Some(p) = preamble() {
        use std::io::Write as _;
        daemon.write_all(&p)?;
    }
    let sd = daemon.try_clone()?;
    pump(guest, daemon.try_clone()?, daemon, move || {
        let _ = sd.shutdown(std::net::Shutdown::Both);
    })
}

/// Byte-pump the guest connection and a daemon connection in both directions.
fn pump<D>(
    guest: crate::platform::uds::UdsStream,
    mut daemon_wr: D,
    mut daemon_rd: D,
    daemon_shutdown: impl FnOnce() + Send + 'static,
) -> std::io::Result<()>
where
    D: std::io::Read + std::io::Write + Send + 'static,
{
    let mut guest_rd = guest.try_clone()?;
    let guest_sd = guest_rd.try_clone()?;
    let mut guest_wr = guest;
    let up = thread::spawn(move || {
        let _ = std::io::copy(&mut guest_rd, &mut daemon_wr);
        // Guest side ended: unblock the daemon→guest copy below so the proxy
        // thread exits instead of leaking, blocked on a silent daemon.
        daemon_shutdown();
    });
    let _ = std::io::copy(&mut daemon_rd, &mut guest_wr);
    // Daemon side ended — e.g. this connection's clone worker died. Shut the
    // guest socket down so the guest's blocked read fails LOUDLY (the clone
    // would otherwise hang forever mid-training) and the up-thread unblocks.
    let _ = guest_sd.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
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
