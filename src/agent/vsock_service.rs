//! Registry of guest↔host vsock-backed services.
//!
//! Each entry bridges a guest vsock port to a host `AF_UNIX` socket via
//! `krun_add_vsock_port2` — a deliberate opening in guest↔host isolation. A
//! service is *enabled* purely by whether its opt-in input (a socket path) is
//! present for the launch: enabling it IS the decision, so there is no separate
//! gate. Every socket path here is host-derived (the per-VM dir or host config),
//! never guest-influenced.
//!
//! This module is the single place the launcher branches on these services.
//! Adding a new vsock-backed capability is one `impl VsockService` plus one line
//! in [`registry`] — no new control flow in the launcher.

use smolvm_protocol::ports;
use std::path::Path;

/// The optional, host-derived socket paths a service resolves itself from.
///
/// One field per opt-in source; a service reads the one it owns. All paths are
/// produced by smolvm, never by the guest.
pub struct VsockServiceInputs<'a> {
    /// Host SSH agent socket to forward into the guest.
    pub ssh_agent_socket: Option<&'a Path>,
    /// Host DNS-filter proxy socket.
    pub dns_filter_socket: Option<&'a Path>,
    /// Host CUDA-over-vsock server socket (experimental).
    pub cuda_socket: Option<&'a Path>,
    /// Host-side Docker socket to expose. libkrun *listens* on this path and
    /// forwards each host connection to the guest, which proxies it to the
    /// in-guest dockerd socket. When set, the Docker bridge is enabled.
    pub docker_socket: Option<&'a Path>,
}

/// A service resolved to "on" for a launch: the concrete wiring the launcher
/// applies.
pub struct ActiveVsockService<'a> {
    /// Human-readable name for log lines.
    pub name: &'static str,
    /// Guest-visible vsock port. Must be reserved in [`ports`] and must not
    /// collide with [`ports::AGENT_CONTROL`].
    pub port: u32,
    /// `false` → guest connects *out* to the host endpoint at `socket`
    /// (SSH/DNS/CUDA); `true` → guest serves and the host connects in.
    pub listen: bool,
    /// Host `AF_UNIX` socket the port bridges to.
    pub socket: &'a Path,
    /// Env vars injected into the guest agent to activate the guest side of the
    /// service (e.g. the SSH agent bridge). Empty when the guest side needs no
    /// signal (it connects out on its own, like the DNS and CUDA clients).
    pub guest_env: &'static [(&'static str, &'static str)],
}

/// One guest↔host vsock-backed capability. Implementors are stateless unit
/// structs registered in [`registry`].
pub trait VsockService: Sync {
    /// Resolve to an active service when enabled for this launch, else `None`.
    fn resolve<'a>(&self, inputs: &VsockServiceInputs<'a>) -> Option<ActiveVsockService<'a>>;
}

/// SSH agent forwarding: the host's `SSH_AUTH_SOCK` bridged into the guest. The
/// guest agent is told to start its bridge via `SMOLVM_SSH_AGENT=1`.
struct SshAgentService;
impl VsockService for SshAgentService {
    fn resolve<'a>(&self, inputs: &VsockServiceInputs<'a>) -> Option<ActiveVsockService<'a>> {
        inputs.ssh_agent_socket.map(|socket| ActiveVsockService {
            name: "SSH agent forwarding",
            port: ports::SSH_AGENT,
            listen: false,
            socket,
            guest_env: &[("SMOLVM_SSH_AGENT", "1")],
        })
    }
}

/// DNS filtering proxy: the guest forwards DNS queries to a host listener that
/// enforces the egress allow-list.
struct DnsFilterService;
impl VsockService for DnsFilterService {
    fn resolve<'a>(&self, inputs: &VsockServiceInputs<'a>) -> Option<ActiveVsockService<'a>> {
        inputs.dns_filter_socket.map(|socket| ActiveVsockService {
            name: "DNS filtering",
            port: ports::DNS_FILTER,
            listen: false,
            socket,
            guest_env: &[],
        })
    }
}

/// CUDA-over-vsock (experimental): the guest CUDA client connects out to a host
/// server that loads `nvcuda.dll` / `libcuda.so.1` and runs the calls on the
/// host NVIDIA GPU.
struct CudaService;
impl VsockService for CudaService {
    fn resolve<'a>(&self, inputs: &VsockServiceInputs<'a>) -> Option<ActiveVsockService<'a>> {
        inputs.cuda_socket.map(|socket| ActiveVsockService {
            name: "CUDA-over-vsock",
            port: ports::CUDA,
            listen: false,
            socket,
            // Arm guest-RAM zero-copy for `cudaMallocHost` buffers. The shim
            // only uses it when it can read `/proc/self/pagemap` (guest is root)
            // and the host published the mapping; otherwise it falls back to the
            // byte-shipping path transparently.
            guest_env: &[("SMOLVM_CUDA_ZEROCOPY", "1")],
        })
    }
}

/// Docker socket bridge: the guest serves on the vsock port (proxying to its
/// own dockerd socket) and the host connects in via the exposed Unix socket, so
/// a host client can drive the guest's Docker daemon with `DOCKER_HOST=unix://…`.
/// `listen: true` — the only inbound service besides the agent control channel.
struct DockerSocketService;
impl VsockService for DockerSocketService {
    fn resolve<'a>(&self, inputs: &VsockServiceInputs<'a>) -> Option<ActiveVsockService<'a>> {
        inputs.docker_socket.map(|socket| ActiveVsockService {
            name: "Docker socket bridge",
            port: ports::DOCKER,
            listen: true,
            socket,
            guest_env: &[(smolvm_protocol::guest_env::DOCKER_SOCKET, "1")],
        })
    }
}

/// All known vsock services. Add a capability by appending one entry.
pub fn registry() -> &'static [&'static dyn VsockService] {
    &[
        &SshAgentService,
        &DnsFilterService,
        &CudaService,
        &DockerSocketService,
    ]
}
