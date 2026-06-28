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

/// All known vsock services. Add a capability by appending one entry.
pub fn registry() -> &'static [&'static dyn VsockService] {
    &[&SshAgentService, &DnsFilterService]
}
