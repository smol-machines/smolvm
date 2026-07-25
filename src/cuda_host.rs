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
            // P3b: a FORK-CLONE VM warms its daemon-side worker EAGERLY. The
            // warm-flagged preamble makes the daemon spawn the worker (CUDA
            // init + memory reconstruction + module/graph pre-warm) NOW,
            // concurrent with guest resume, instead of on the guest's first
            // CUDA call. The connection is held open as the worker's idle
            // primary channel; real guest channels attach to the live worker.
            if std::env::var("SMOLVM_CUDA_WARM_DIAL").as_deref() != Ok("0") {
              if let (Some(addr), Some(p)) = (daemon.clone(), clone_preamble(true)) {
                thread::Builder::new()
                    .name("cuda-clone-warm".into())
                    .spawn(move || {
                        use std::io::{Read as _, Write as _};
                        // The warm dial is the connection that SPAWNS the
                        // worker, so it must carry the ring-dir advert — the
                        // worker inherits the dir at spawn and every later
                        // attached channel resolves RingSetupFile against it.
                        let rd = ring_dir_advert();
                        if addr.starts_with('/') {
                            #[cfg(unix)]
                            if let Ok(mut s) = std::os::unix::net::UnixStream::connect(&addr) {
                                if rd.as_ref().is_none_or(|r| s.write_all(r).is_ok())
                                    && s.write_all(&p).is_ok()
                                {
                                    tracing::info!("cuda-host: clone warm dial sent");
                                    let mut b = [0u8; 1];
                                    let _ = s.read(&mut b); // parked for the worker's lifetime
                                }
                            }
                        } else if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
                            if rd.as_ref().is_none_or(|r| s.write_all(r).is_ok())
                                && s.write_all(&p).is_ok()
                            {
                                tracing::info!("cuda-host: clone warm dial sent");
                                let mut b = [0u8; 1];
                                let _ = s.read(&mut b);
                            }
                        }
                    })
                    .ok();
              }
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
/// The 17-byte clone-connection preamble (magic + clone id + flags), `None`
/// on non-clone VMs. Flag bit 0: forked with `--share-weights`; bit 1: warm
/// dial (spawn the worker eagerly, no Init follows on this connection).
fn clone_preamble(warm: bool) -> Option<[u8; 17]> {
    let id = fork_clone_id()?;
    let mut p = [0u8; 17];
    p[..8].copy_from_slice(&smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC);
    p[8..16].copy_from_slice(&id.to_le_bytes());
    // bit 0: this fork was requested with --share-weights (the launcher put
    // SMOLVM_CUDA_CLONE_SHARE in this clone VMM's env).
    if std::env::var_os("SMOLVM_CUDA_CLONE_SHARE").is_some() {
        p[16] |= 1;
    }
    if warm {
        p[16] |= 2;
    }
    Some(p)
}

/// Ring-dir advert (`SMVRDIR1` + u16 len + host path): tells the daemon which
/// HOST directory backs this VM's dax ring mount, so a guest `RingSetupFile`
/// can be honored. Sent on every daemon connection when the launcher exported
/// `SMOLVM_CUDA_RING_HOST_DIR` (CUDA machines with the ring mount).
fn ring_dir_advert() -> Option<Vec<u8>> {
    let dir = std::env::var("SMOLVM_CUDA_RING_HOST_DIR").ok()?;
    if dir.is_empty() || dir.len() > 512 {
        return None;
    }
    let mut v = Vec::with_capacity(10 + dir.len());
    v.extend_from_slice(b"SMVRDIR1");
    v.extend_from_slice(&(dir.len() as u16).to_le_bytes());
    v.extend_from_slice(dir.as_bytes());
    Some(v)
}

/// A FORK-CLONE VM's proxy prepends the clone preamble (magic + clone id) so
/// the daemon routes this connection to the clone's isolating worker — and, by
/// its absence, serves the GOLDEN's own reconnect in-daemon instead of handing
/// it a worker's reconstructed COPY of its memory.
fn proxy_to_daemon(guest: crate::platform::uds::UdsStream, addr: &str) -> std::io::Result<()> {
    let preamble = || clone_preamble(false);
    /// Guest-RAM advertisement for a SHARED daemon: when this VM's RAM is
    /// memfd-backed (forkable machines), tell the daemon how to map the same
    /// pages via `/proc/<pid>/fd/<memfd>` — magic + pid + fd + count +
    /// (gpa, memfd offset, len)×count. With guest RAM visible, the daemon can
    /// establish the shared-memory ring transport and zero-copy GPA memcpys
    /// instead of per-call socket framing. `None` (silently) when RAM isn't
    /// memfd-backed or the layout can't be resolved — sockets still work.
    #[cfg(target_os = "linux")]
    fn guest_ram_advert() -> Option<Vec<u8>> {
        if std::env::var_os("SMOLVM_CUDA_NO_RAM_ADVERT").is_some() {
            return None;
        }
        let regions = GUEST_RAM.get().and_then(|f| f())?; // (gpa, host_va, len)
        if regions.is_empty() {
            return None;
        }
        // memfd-backed mappings of this process: match each guest region's
        // host VA into a maps entry, then express it as a file offset.
        let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
        let mut memfd_maps: Vec<(u64, u64, u64, u64)> = Vec::new(); // start,end,file_off,inode
        for l in maps.lines() {
            if !l.contains("memfd:") {
                continue;
            }
            let mut f = l.split_whitespace();
            let range = f.next()?;
            let perms = f.next()?;
            // MAP_SHARED only: a fork CLONE maps the golden's memfd
            // MAP_PRIVATE (COW) — its live pages have diverged from the file,
            // so advertising the memfd would hand the daemon STALE golden
            // bytes. Private mappings are excluded; clones stay socket-mode.
            if perms.as_bytes().get(3) != Some(&b's') {
                continue;
            }
            let off = u64::from_str_radix(f.next()?, 16).ok()?;
            let _dev = f.next()?;
            let inode: u64 = f.next()?.parse().ok()?;
            let (s, e) = range.split_once('-')?;
            memfd_maps.push((
                u64::from_str_radix(s, 16).ok()?,
                u64::from_str_radix(e, 16).ok()?,
                off,
                inode,
            ));
        }
        if memfd_maps.is_empty() {
            return None;
        }
        // libkrun backs guest RAM with ONE MEMFD PER REGION — build an
        // inode→fd table and express each region as (gpa, fd, offset, len).
        let mut inode_to_fd: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for e in std::fs::read_dir("/proc/self/fd").ok()? {
            let e = e.ok()?;
            let is_memfd = std::fs::read_link(e.path())
                .ok()
                .and_then(|l| l.to_str().map(|s| s.contains("memfd:")))
                .unwrap_or(false);
            if !is_memfd {
                continue;
            }
            if let Ok(md) = std::fs::metadata(e.path()) {
                use std::os::unix::fs::MetadataExt as _;
                if let Some(n) = e.file_name().to_str().and_then(|s| s.parse().ok()) {
                    inode_to_fd.entry(md.ino()).or_insert(n);
                }
            }
        }
        let mut quads: Vec<(u64, u32, u64, u64)> = Vec::new();
        for &(gpa, hva, len) in &regions {
            let m = memfd_maps
                .iter()
                .find(|&&(s, e, _, _)| hva >= s && hva + len <= e)?;
            let fd_no = *inode_to_fd.get(&m.3)?;
            quads.push((gpa, fd_no, m.2 + (hva - m.0), len));
        }
        let mut p = Vec::with_capacity(20 + quads.len() * 28);
        p.extend_from_slice(b"SMVGRAM2");
        p.extend_from_slice(&(std::process::id()).to_le_bytes());
        p.extend_from_slice(&(quads.len() as u32).to_le_bytes());
        p.extend_from_slice(&[0u8; 4]); // reserved
        for (gpa, fd_no, off, len) in quads {
            p.extend_from_slice(&gpa.to_le_bytes());
            p.extend_from_slice(&fd_no.to_le_bytes());
            p.extend_from_slice(&off.to_le_bytes());
            p.extend_from_slice(&len.to_le_bytes());
        }
        Some(p)
    }
    #[cfg(not(target_os = "linux"))]
    #[cfg(all(unix, not(target_os = "linux")))]
    fn guest_ram_advert() -> Option<Vec<u8>> {
        None
    }
    /// Fork-CLONE proc-mem advertisement: the clone maps the golden's guest-RAM
    /// memfd MAP_PRIVATE (COW), so it can't be memfd-advertised (its live pages
    /// have diverged). Instead advertise our (pid, gpa, host_va, len) so the clone
    /// worker reads our LIVE pages via /proc/<pid>/mem. Emitted only for clones
    /// (right after the clone preamble); the golden uses the memfd advert above.
    #[cfg(target_os = "linux")]
    fn guest_ram_procmem_advert() -> Option<Vec<u8>> {
        if std::env::var_os("SMOLVM_CUDA_NO_RAM_ADVERT").is_some() {
            return None;
        }
        let regions = GUEST_RAM.get().and_then(|f| f())?; // (gpa, host_va, len)
        if regions.is_empty() {
            return None;
        }
        let mut p = Vec::with_capacity(20 + regions.len() * 24);
        p.extend_from_slice(b"SMVGPVM1");
        p.extend_from_slice(&std::process::id().to_le_bytes());
        p.extend_from_slice(&(regions.len() as u32).to_le_bytes());
        p.extend_from_slice(&[0u8; 4]); // reserved
        for (gpa, hva, len) in regions {
            p.extend_from_slice(&gpa.to_le_bytes());
            p.extend_from_slice(&hva.to_le_bytes());
            p.extend_from_slice(&len.to_le_bytes());
        }
        Some(p)
    }
    #[cfg(not(target_os = "linux"))]
    #[cfg(all(unix, not(target_os = "linux")))]
    fn guest_ram_procmem_advert() -> Option<Vec<u8>> {
        None
    }
    // A path (managed daemon) → unix socket; otherwise host:port → TCP.
    if addr.starts_with('/') {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            let mut daemon = std::os::unix::net::UnixStream::connect(addr)?;
            if let Some(a) = guest_ram_advert() {
                daemon.write_all(&a)?;
            }
            if let Some(r) = ring_dir_advert() {
                daemon.write_all(&r)?;
            }
            // Clone: advertise our LIVE private RAM BEFORE the clone preamble
            // so the daemon consumes it as an accept-loop preamble (like the
            // SMVGRAM2 memfd advert) and passes it to the worker via env. It must
            // NOT sit between the clone preamble and the RPC Init, where
            // peek_clone_token would read it as the routing frame and misroute
            // the clone. Gated on preamble() so a golden never emits it.
            if preamble().is_some() {
                if let Some(pm) = guest_ram_procmem_advert() {
                    daemon.write_all(&pm)?;
                }
            }
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
