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
//! - `NetworkFrameQueues`: handoff boundary between threads
//! - `VirtioNetworkDevice`: adapts those queues to smoltcp's `phy::Device`
//! - poll thread: acts as the guest-visible gateway and protocol dispatcher
//! - `TcpRelayTable`: maps guest TCP flows onto host-side relay threads
//!
//! In Phase 1 this runtime is responsible for:
//! - exchanging raw Ethernet frames with libkrun
//! - presenting a gateway endpoint to the guest
//! - handling DNS through a gateway UDP socket and host UDP forwarding
//! - relaying guest TCP connections to host `TcpStream`s
//!
//! What is *not* here yet:
//! - launcher wiring and `krun_add_net_unixstream()` setup
//! - port publishing
//! - non-DNS UDP relay
//! - policy enforcement / DNS filtering
//! - TLS MITM or deeper packet rewriting
//!
//! So this module is the host data plane, but not yet the full user-visible
//! networking feature.

pub mod device;
pub mod frame_stream;
pub mod queues;
pub mod stack;
pub mod tcp_relay;

use crate::network::addressing::GuestNetworkConfig;
use crate::network::virtio::frame_stream::{start_frame_stream_bridge, FrameStreamBridge};
use crate::network::virtio::queues::{NetworkFrameQueues, DEFAULT_FRAME_QUEUE_CAPACITY};
use crate::network::virtio::stack::{start_network_stack, VirtioPollConfig};
use std::fmt;
use std::io;
use std::os::fd::RawFd;
use std::thread::JoinHandle;
use std::time::SystemTime;

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
        $crate::network::virtio::emit_network_log_line(format_args!($($arg)*))
    };
}

pub(crate) use virtio_net_log;

/// Running host-side virtio-net runtime for one guest NIC.
///
/// Ownership model:
/// - one runtime instance corresponds to one guest virtio NIC
/// - it owns the queue set shared by the worker threads
/// - it owns the libkrun Unix-stream bridge threads
/// - it owns the smoltcp poll thread
///
/// Dropping the runtime is the shutdown signal. `Drop` marks the shared queues
/// as shutting down, wakes blocked workers, and joins the poll thread.
pub struct VirtioNetworkRuntime {
    queues: std::sync::Arc<NetworkFrameQueues>,
    _frame_bridge: FrameStreamBridge,
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
///
/// Outcome:
/// - reader thread: reads raw Ethernet frames from the Unix socket and pushes
///   them into `guest_to_host`
/// - writer thread: pops raw Ethernet frames from `host_to_guest` and writes
///   them back to the Unix socket
/// - poll thread: runs the host-side smoltcp gateway/runtime, consumes guest
///   frames, emits response frames, and handles protocol-specific logic such as
///   DNS forwarding and TCP relay setup
pub fn start_virtio_network(
    host_fd: RawFd,
    guest_network: GuestNetworkConfig,
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
    let poll_handle = start_network_stack(
        queues.clone(),
        VirtioPollConfig {
            gateway_mac: guest_network.gateway_mac,
            guest_mac: guest_network.guest_mac,
            gateway_ipv4: guest_network.gateway_ip,
            guest_ipv4: guest_network.guest_ip,
            mtu: 1500,
        },
    )?;

    Ok(VirtioNetworkRuntime {
        queues,
        _frame_bridge: frame_bridge,
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
