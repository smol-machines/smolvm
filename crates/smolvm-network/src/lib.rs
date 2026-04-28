//! Host-side virtio-net runtime.
//!
//! Context
//! =======
//!
//! This module is the host-side half of the new networking path:
//!
//! ```text
//! guest app
//!   -> guest kernel TCP/IP stack
//!   -> virtio-net device
//!   -> libkrun unix-stream bridge
//!   -> smolvm FrameStreamBridge
//!   -> shared frame queues
//!   -> smoltcp gateway/runtime
//!   -> host sockets / DNS forwarding / TCP relay
//!   -> external network
//! ```
//!
//! Main runtime components:
//!
//! ```text
//! VirtioNetworkRuntime
//! ├─ FrameStreamBridge
//! │  ├─ reader thread
//! │  └─ writer thread
//! ├─ TcpPortListeners
//! │  └─ one non-blocking accept loop per `-p HOST:GUEST`
//! ├─ Arc<NetworkFrameQueues>
//! │  ├─ guest_to_host
//! │  ├─ host_to_guest
//! │  ├─ guest_wake
//! │  ├─ host_wake
//! │  └─ relay_wake
//! └─ smolvm-net-poll thread
//!    ├─ VirtioNetworkDevice
//!    ├─ smoltcp Interface
//!    ├─ SocketSet
//!    └─ TcpRelayTable
//! ```
//!
//! Component roles:
//! - `FrameStreamBridge`: translates libkrun's Unix-stream frame protocol into
//!   queue operations
//! - `TcpPortListeners`: accepts host TCP connections for published ports
//!   and hands them to the poll loop
//! - `NetworkFrameQueues`: handoff boundary between threads
//! - `VirtioNetworkDevice`: adapts those queues to smoltcp's `phy::Device`
//! - poll thread: acts as the guest-visible gateway and protocol dispatcher
//! - `TcpRelayTable`: maps guest TCP flows onto host-side relay threads
//!
//! This runtime is responsible for:
//! - exchanging raw Ethernet frames with libkrun
//! - presenting a gateway endpoint to the guest
//! - handling DNS through a gateway UDP socket and host UDP forwarding
//! - relaying guest TCP connections to host `TcpStream`s
//! - accepting published host TCP ports and forwarding them into guest TCP
//!   connections

pub mod device;
pub mod frame_stream;
pub mod guest_env;
pub mod policy;
pub mod queues;
pub mod stack;
pub mod tcp_listeners;
pub mod tcp_relay;

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::RawFd;
use std::thread::JoinHandle;
use std::time::SystemTime;

use frame_stream::{start_frame_stream_bridge, FrameStreamBridge};
pub use policy::EgressPolicy;
use queues::{NetworkFrameQueues, DEFAULT_FRAME_QUEUE_CAPACITY};
use stack::{start_network_stack, VirtioPollConfig};
use tcp_listeners::{create_tcp_channel, TcpPortListeners};

/// Default upstream DNS resolver used by the gateway runtime.
pub const DEFAULT_DNS_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// Host->guest published TCP port mapping serviced by the virtio gateway.
///
/// This stays crate-local so the launchers can translate CLI/data-layer port
/// mappings into the gateway runtime without pulling the gateway logic back
/// into the main `smolvm` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    /// Port bound on the host loopback interface.
    pub host: u16,
    /// Port exposed inside the guest.
    pub guest: u16,
}

impl PortMapping {
    /// Create a new published port mapping.
    pub const fn new(host: u16, guest: u16) -> Self {
        Self { host, guest }
    }
}

/// Static guest network configuration for the virtio-net MVP.
///
/// This struct describes the two endpoints of the single virtual Ethernet link:
/// - the guest NIC (`guest_*`)
/// - the host-side gateway implemented by smolvm (`gateway_*`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestNetworkConfig {
    /// Guest IPv4 address.
    pub guest_ip: Ipv4Addr,
    /// Gateway IPv4 address.
    pub gateway_ip: Ipv4Addr,
    /// Prefix length.
    pub prefix_len: u8,
    /// Guest MAC address.
    pub guest_mac: [u8; 6],
    /// Gateway MAC address.
    pub gateway_mac: [u8; 6],
    /// DNS server address presented to the guest.
    pub dns_server: Ipv4Addr,
}

impl GuestNetworkConfig {
    /// Default Phase 1 guest network configuration.
    pub const fn default() -> Self {
        Self {
            guest_ip: Ipv4Addr::new(100, 96, 0, 2),
            gateway_ip: Ipv4Addr::new(100, 96, 0, 1),
            prefix_len: 30,
            guest_mac: [0x02, 0x53, 0x4d, 0x00, 0x00, 0x02],
            gateway_mac: [0x02, 0x53, 0x4d, 0x00, 0x00, 0x01],
            dns_server: Ipv4Addr::new(100, 96, 0, 1),
        }
    }
}

fn format_network_log_line(timestamp: SystemTime, message: &str) -> String {
    format!(
        "[{}]: {}",
        humantime::format_rfc3339_seconds(timestamp),
        message
    )
}

pub(crate) fn emit_network_log_line(message: fmt::Arguments<'_>) {
    eprintln!(
        "{}",
        format_network_log_line(SystemTime::now(), &message.to_string())
    );
}

macro_rules! virtio_net_log {
    ($($arg:tt)*) => {
        $crate::emit_network_log_line(format_args!($($arg)*))
    };
}

pub(crate) use virtio_net_log;

/// Running host-side virtio-net runtime for one guest NIC.
///
/// Ownership model:
/// - one runtime instance corresponds to one guest virtio NIC
/// - it owns the queue set shared by the worker threads
/// - it owns the libkrun Unix-stream bridge threads
/// - it owns the published-port listener threads
/// - it owns the smoltcp poll thread
///
/// Dropping the runtime is the shutdown signal. `Drop` marks the shared queues
/// as shutting down, wakes blocked workers, and joins the poll thread.
pub struct VirtioNetworkRuntime {
    queues: std::sync::Arc<NetworkFrameQueues>,
    _frame_bridge: FrameStreamBridge,
    published_ports: Option<TcpPortListeners>,
    poll_handle: Option<JoinHandle<()>>,
}

/// Start the host-side virtio-net runtime for one guest NIC.
///
/// Inputs:
/// - `host_fd`: the host-side Unix stream fd that libkrun will use for this
///   guest NIC. The launcher eventually gets this from the libkrun
///   `krun_add_net_unixstream()` setup path.
/// - `guest_network`: the static guest/gateway addressing and MAC plan for this
///   NIC.
/// - `published_ports`: host->guest TCP port mappings that should be serviced
///   directly by the virtio runtime instead of TSI.
///
/// High-level flow:
///
/// ```text
/// start_virtio_network()
///   -> create shared frame queues + wake pipes
///   -> start frame reader/writer threads on the Unix stream
///   -> start host TcpListeners for published ports
///   -> start the smoltcp poll thread
///   -> return a handle that owns the whole runtime
/// ```
///
/// Expanded startup picture:
///
/// ```text
/// host_fd from libkrun
///   -> FrameStreamBridge(host_fd)
///      -> reader thread
///      -> writer thread
///   -> TcpPortListeners
///      -> accept host TcpStreams
///      -> send them to the poll loop over a bounded channel
///   -> NetworkFrameQueues
///   -> start_network_stack(...)
///      -> poll thread owns smoltcp Interface + sockets
///   -> VirtioNetworkRuntime returned to launcher
/// ```
///
/// Outcome:
/// - guest->host Ethernet frames start flowing into the queues
/// - host->guest Ethernet frames emitted by smoltcp are written back to libkrun
/// - published host TCP connections can be forwarded toward guest listeners
/// - the poll loop starts acting as the guest-visible gateway
pub fn start_virtio_network(
    host_fd: RawFd,
    guest_network: GuestNetworkConfig,
    published_ports: &[PortMapping],
    egress_policy: EgressPolicy,
) -> io::Result<VirtioNetworkRuntime> {
    virtio_net_log!(
        "virtio-net: starting runtime host_fd={} guest_ip={} gateway_ip={} dns_server={}",
        host_fd,
        guest_network.guest_ip,
        guest_network.gateway_ip,
        guest_network.dns_server
    );
    let queues = NetworkFrameQueues::shared(DEFAULT_FRAME_QUEUE_CAPACITY);
    let frame_bridge = start_frame_stream_bridge(host_fd, queues.clone())?;
    // tcp_sender sends the accepted TCP connections to the channel
    // tcp_receiver receives the accepted TCP connections via the channel, and let it be consumed in poll thread.
    let (tcp_sender, tcp_receiver) = create_tcp_channel();
    let tcp_listeners = if published_ports.is_empty() {
        None
    } else {
        Some(TcpPortListeners::start(
            published_ports,
            tcp_sender,
            queues.relay_wake.clone(),
        )?)
    };
    let poll_handle = start_network_stack(
        queues.clone(),
        VirtioPollConfig {
            gateway_mac: guest_network.gateway_mac,
            guest_mac: guest_network.guest_mac,
            gateway_ipv4: guest_network.gateway_ip,
            guest_ipv4: guest_network.guest_ip,
            mtu: 1500,
        },
        tcp_listeners.as_ref().map(|_| tcp_receiver),
        egress_policy,
    )?;

    Ok(VirtioNetworkRuntime {
        queues,
        _frame_bridge: frame_bridge,
        published_ports: tcp_listeners,
        poll_handle: Some(poll_handle),
    })
}

impl Drop for VirtioNetworkRuntime {
    /// Shut down the worker threads in a bounded, cooperative way.
    ///
    /// The queue shutdown flag wakes the frame bridge and smoltcp poll loop so
    /// they can exit on their own. We only explicitly join the poll thread
    /// here because the frame bridge joins its own threads in its own `Drop`.
    fn drop(&mut self) {
        self.queues.begin_shutdown();
        self.published_ports = None;
        if let Some(handle) = self.poll_handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::format_network_log_line;
    use std::time::UNIX_EPOCH;

    #[test]
    fn formats_timestamped_network_log_prefix() {
        let line = format_network_log_line(UNIX_EPOCH, "virtio-net: smoke test");
        assert_eq!(line, "[1970-01-01T00:00:00Z]: virtio-net: smoke test");
    }
}
