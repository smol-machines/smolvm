//! General UDP relay for the virtio-net backend.
//!
//! Context
//! =======
//!
//! DNS (UDP :53) is intercepted and answered by the gateway itself
//! (`stack.rs::process_dns_queries`). Every other guest UDP datagram used to be
//! dropped (`FrameAction::UnsupportedUdp`), which broke QUIC/HTTP-3, NTP, and
//! any DNS on a non-standard port. This module relays those flows to real host
//! UDP sockets, giving virtio-net parity with TSI (whose syscall-level hijack
//! gets UDP for free).
//!
//! Model — a tiny userspace NAT, mirroring the TCP relay's shape:
//!
//! ```text
//! guest datagram to D:port (≠ :53)
//!   -> classify_guest_frame: FrameAction::UdpFlow
//!   -> poll loop: egress check; ensure a smoltcp UDP socket bound to D:port
//!   -> smoltcp ingress delivers the datagram into that socket
//!   -> poll loop drains it and channels (guest, D, payload) to the relay thread
//!   -> relay thread: one connected host UdpSocket per (guest, D) flow; send
//!   -> replies: host socket readable -> channel back -> relay_wake
//!   -> poll loop writes the reply into the D-bound smoltcp socket with
//!      endpoint = guest, local_address = D  (guest sees the reply come from D)
//! ```
//!
//! Flows are connectionless, so lifetime is NAT-style idle expiry: the relay
//! drops host sockets idle for [`FLOW_IDLE_TIMEOUT`]; the poll loop drops
//! destination sockets idle for [`DST_SOCKET_IDLE_TIMEOUT`]. Loss under
//! pressure (full channels / tables) is acceptable UDP semantics — logged,
//! never blocking.

use crate::egress::EgressPolicy;
use crate::queues::WakePipe;
use crate::virtio_net_log;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as HostUdpSocket};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Max in-flight datagrams per direction before drops (UDP may drop).
const CHANNEL_CAPACITY: usize = 256;
/// Max concurrent (guest, destination) flows with live host sockets.
const MAX_FLOWS: usize = 1024;
/// Max destination-keyed smoltcp sockets in the poll loop.
const MAX_DST_SOCKETS: usize = 128;
/// Packet slots per destination socket buffer.
const UDP_PACKET_SLOTS: usize = 16;
/// Payload bytes per destination socket buffer (per direction).
const UDP_BUFFER_BYTES: usize = 64 * 1024;
/// Largest datagram we relay (gateway MTU bounds guest->host anyway).
const MAX_DATAGRAM_BYTES: usize = 65_535;
/// Drop a flow's host socket after this much inactivity.
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Remove a destination's smoltcp socket after this much inactivity.
const DST_SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Relay thread poll ceiling, so shutdown and expiry are noticed promptly.
const RELAY_POLL_MAX_MS: i32 = 1000;

/// One relayed datagram, in either direction.
pub struct UdpDatagram {
    /// Guest-side endpoint (source on egress, reply target on ingress).
    pub guest: SocketAddr,
    /// External destination the guest addressed (and replies come from).
    pub destination: SocketAddr,
    /// Datagram payload.
    pub payload: Vec<u8>,
}

/// Channel pair connecting the poll loop and the relay thread.
pub struct UdpRelayChannels {
    /// Poll loop -> relay thread.
    pub to_relay: SyncSender<UdpDatagram>,
    /// Relay thread -> poll loop.
    pub from_relay: Receiver<UdpDatagram>,
    /// Wakes the relay thread after `to_relay` sends.
    pub relay_thread_wake: WakePipe,
}

/// Start the UDP relay thread. Returns the poll-loop-side channel endpoints.
///
/// `reply_wake` is the smoltcp poll loop's existing relay wake pipe — pulsed
/// whenever a reply is queued so the loop wakes to deliver it to the guest.
/// The thread exits when `shutdown` reports true (checked at least once per
/// [`RELAY_POLL_MAX_MS`]).
pub fn start_udp_relay(
    reply_wake: Arc<WakePipe>,
    shutdown: Arc<dyn Fn() -> bool + Send + Sync>,
) -> UdpRelayChannels {
    let (to_relay_tx, to_relay_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let (from_relay_tx, from_relay_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let relay_thread_wake = WakePipe::new();
    let thread_wake = relay_thread_wake.clone();

    let _ = thread::Builder::new()
        .name("smolvm-udp-relay".into())
        .spawn(move || {
            run_udp_relay(
                to_relay_rx,
                from_relay_tx,
                thread_wake,
                reply_wake,
                shutdown,
            );
        });

    UdpRelayChannels {
        to_relay: to_relay_tx,
        from_relay: from_relay_rx,
        relay_thread_wake,
    }
}

/// Relay-thread state for one (guest, destination) flow.
struct UdpFlow {
    socket: HostUdpSocket,
    guest: SocketAddr,
    destination: SocketAddr,
    last_active: Instant,
}

fn run_udp_relay(
    outbound: Receiver<UdpDatagram>,
    inbound: SyncSender<UdpDatagram>,
    wake: WakePipe,
    reply_wake: Arc<WakePipe>,
    shutdown: Arc<dyn Fn() -> bool + Send + Sync>,
) {
    let mut flows: HashMap<(SocketAddr, SocketAddr), UdpFlow> = HashMap::new();
    let mut recv_buf = vec![0u8; MAX_DATAGRAM_BYTES];

    loop {
        if shutdown() {
            return;
        }

        // Outbound: guest datagrams handed over by the poll loop.
        loop {
            match outbound.try_recv() {
                Ok(datagram) => {
                    let key = (datagram.guest, datagram.destination);
                    if !flows.contains_key(&key) {
                        if flows.len() >= MAX_FLOWS {
                            virtio_net_log!(
                                "virtio-net: dropping UDP flow {} -> {} (flow table full)",
                                datagram.guest,
                                datagram.destination
                            );
                            continue;
                        }
                        match create_flow_socket(datagram.destination) {
                            Ok(socket) => {
                                flows.insert(
                                    key,
                                    UdpFlow {
                                        socket,
                                        guest: datagram.guest,
                                        destination: datagram.destination,
                                        last_active: Instant::now(),
                                    },
                                );
                            }
                            Err(err) => {
                                virtio_net_log!(
                                    "virtio-net: failed to open host UDP socket for {} -> {}: {}",
                                    datagram.guest,
                                    datagram.destination,
                                    err
                                );
                                continue;
                            }
                        }
                    }
                    let flow = flows.get_mut(&key).expect("flow inserted above");
                    flow.last_active = Instant::now();
                    // Best-effort send; UDP loss is allowed.
                    let _ = flow.socket.send(&datagram.payload);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }

        // Inbound: poll all flow sockets for replies.
        let mut poll_fds: Vec<libc::pollfd> = Vec::with_capacity(flows.len() + 1);
        poll_fds.push(libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        let keys: Vec<(SocketAddr, SocketAddr)> = flows.keys().copied().collect();
        for key in &keys {
            poll_fds.push(libc::pollfd {
                fd: flows[key].socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }

        // SAFETY: every pollfd holds a valid descriptor owned by this thread.
        unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                RELAY_POLL_MAX_MS,
            );
        }

        if poll_fds[0].revents & libc::POLLIN != 0 {
            wake.drain();
        }

        let mut woke_reply = false;
        for (slot, key) in keys.iter().enumerate() {
            if poll_fds[slot + 1].revents & libc::POLLIN == 0 {
                continue;
            }
            let Some(flow) = flows.get_mut(key) else {
                continue;
            };
            // Drain everything ready on this socket. WouldBlock ends the drain;
            // ECONNREFUSED (ICMP unreachable surfaced by the connected socket)
            // and friends just mean the flow is dead-ish — idle expiry handles it.
            while let Ok(len) = flow.socket.recv(&mut recv_buf) {
                flow.last_active = Instant::now();
                let reply = UdpDatagram {
                    guest: flow.guest,
                    destination: flow.destination,
                    payload: recv_buf[..len].to_vec(),
                };
                match inbound.try_send(reply) {
                    Ok(()) => woke_reply = true,
                    Err(TrySendError::Full(_)) => {
                        virtio_net_log!(
                            "virtio-net: dropping UDP reply for {} (inbound queue full)",
                            flow.guest
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
        }
        if woke_reply {
            reply_wake.wake();
        }

        // NAT-style idle expiry.
        let now = Instant::now();
        flows.retain(|_, flow| now.duration_since(flow.last_active) < FLOW_IDLE_TIMEOUT);
    }
}

/// Open a non-blocking host UDP socket connected to `destination`.
///
/// `connect` pins the peer so `send`/`recv` apply and stray traffic from other
/// peers is filtered by the kernel — each flow is its own little NAT pinhole.
fn create_flow_socket(destination: SocketAddr) -> std::io::Result<HostUdpSocket> {
    let bind_addr: SocketAddr = if destination.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = HostUdpSocket::bind(bind_addr)?;
    socket.connect(destination)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Poll-loop-side table of destination-keyed smoltcp UDP sockets.
///
/// One socket per (destination address, port) — the UDP mirror of
/// `TcpRelayTable::create_tcp_socket`'s destination-keyed listen sockets. The
/// guest's own endpoint comes from receive metadata, so all guest flows to the
/// same destination share one smoltcp socket.
pub struct UdpSocketTable {
    sockets: HashMap<SocketAddr, SocketHandle>,
    last_active: HashMap<SocketAddr, Instant>,
}

impl UdpSocketTable {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
            last_active: HashMap::new(),
        }
    }

    /// Ensure a smoltcp UDP socket exists for `destination` so the staged guest
    /// datagram has somewhere to land. Returns false when the table is full or
    /// the bind fails (the caller drops the frame — UDP semantics).
    pub fn ensure_socket(&mut self, destination: SocketAddr, sockets: &mut SocketSet<'_>) -> bool {
        if self.sockets.contains_key(&destination) {
            self.last_active.insert(destination, Instant::now());
            return true;
        }
        if self.sockets.len() >= MAX_DST_SOCKETS {
            virtio_net_log!(
                "virtio-net: dropping UDP datagram to {} (destination socket table full)",
                destination
            );
            return false;
        }

        let rx = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; UDP_PACKET_SLOTS],
            vec![0u8; UDP_BUFFER_BYTES],
        );
        let tx = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; UDP_PACKET_SLOTS],
            vec![0u8; UDP_BUFFER_BYTES],
        );
        let mut socket = UdpSocket::new(rx, tx);
        if socket
            .bind(smoltcp::wire::IpListenEndpoint {
                addr: Some(destination.ip().into()),
                port: destination.port(),
            })
            .is_err()
        {
            return false;
        }

        let handle = sockets.add(socket);
        self.sockets.insert(destination, handle);
        self.last_active.insert(destination, Instant::now());
        true
    }

    /// Drain guest datagrams from every destination socket toward the relay
    /// thread. Returns true if anything was forwarded (the caller then wakes
    /// the relay thread).
    pub fn drain_to_relay(
        &mut self,
        sockets: &mut SocketSet<'_>,
        to_relay: &SyncSender<UdpDatagram>,
    ) -> bool {
        let mut forwarded = false;
        for (&destination, &handle) in &self.sockets {
            let socket = sockets.get_mut::<UdpSocket>(handle);
            while socket.can_recv() {
                let Ok((payload, metadata)) = socket.recv() else {
                    break;
                };
                self.last_active.insert(destination, Instant::now());
                let guest = endpoint_to_socket_addr(metadata.endpoint);
                let datagram = UdpDatagram {
                    guest,
                    destination,
                    payload: payload.to_vec(),
                };
                match to_relay.try_send(datagram) {
                    Ok(()) => forwarded = true,
                    Err(TrySendError::Full(_)) => {
                        virtio_net_log!(
                            "virtio-net: dropping guest UDP datagram to {} (relay queue full)",
                            destination
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => return forwarded,
                }
            }
        }
        forwarded
    }

    /// Deliver relay replies into the matching destination socket so smoltcp
    /// sends them to the guest, sourced from the original destination address.
    pub fn deliver_replies(
        &mut self,
        sockets: &mut SocketSet<'_>,
        from_relay: &Receiver<UdpDatagram>,
    ) {
        while let Ok(reply) = from_relay.try_recv() {
            let Some(&handle) = self.sockets.get(&reply.destination) else {
                // Destination socket already expired; the reply is late.
                continue;
            };
            self.last_active.insert(reply.destination, Instant::now());
            let socket = sockets.get_mut::<UdpSocket>(handle);
            let metadata = UdpMetadata {
                endpoint: smoltcp::wire::IpEndpoint {
                    addr: reply.guest.ip().into(),
                    port: reply.guest.port(),
                },
                local_address: Some(reply.destination.ip().into()),
                meta: Default::default(),
            };
            if socket.send_slice(&reply.payload, metadata).is_err() {
                virtio_net_log!(
                    "virtio-net: dropping UDP reply to {} (guest socket buffer full)",
                    reply.guest
                );
            }
        }
    }

    /// Remove destination sockets with no traffic for [`DST_SOCKET_IDLE_TIMEOUT`].
    pub fn expire_idle(&mut self, sockets: &mut SocketSet<'_>) {
        let now = Instant::now();
        let expired: Vec<SocketAddr> = self
            .last_active
            .iter()
            .filter(|(_, last)| now.duration_since(**last) >= DST_SOCKET_IDLE_TIMEOUT)
            .map(|(dst, _)| *dst)
            .collect();
        for destination in expired {
            if let Some(handle) = self.sockets.remove(&destination) {
                sockets.remove(handle);
            }
            self.last_active.remove(&destination);
        }
    }
}

impl Default for UdpSocketTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether the gateway should relay a guest UDP datagram to this destination.
/// DNS (:53) is excluded — it has its own intercept-and-filter path. Egress
/// policy applies exactly as for TCP (static CIDRs + DNS-learned IPs).
pub fn should_relay_udp(destination: SocketAddr, egress: &EgressPolicy) -> bool {
    destination.port() != 53 && egress.allows(destination.ip())
}

fn endpoint_to_socket_addr(endpoint: smoltcp::wire::IpEndpoint) -> SocketAddr {
    let ip: std::net::IpAddr = endpoint.addr.into();
    SocketAddr::new(ip, endpoint.port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn flow_socket_round_trip() {
        // Echo server on the host loopback.
        let server = HostUdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let flow = create_flow_socket(server_addr).unwrap();
        flow.send(b"ping").unwrap();

        let mut buf = [0u8; 16];
        let (len, peer) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"ping");
        server.send_to(b"pong", peer).unwrap();

        // Non-blocking: poll briefly for the reply.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match flow.recv(&mut buf) {
                Ok(len) => {
                    assert_eq!(&buf[..len], b"pong");
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("no reply: {e}"),
            }
        }
    }

    #[test]
    fn relay_thread_round_trips_a_datagram() {
        let server = HostUdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let reply_wake = Arc::new(WakePipe::new());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let channels = start_udp_relay(
            reply_wake.clone(),
            Arc::new(move || stop_flag.load(Ordering::Relaxed)),
        );

        let guest: SocketAddr = "100.96.0.2:40000".parse().unwrap();
        channels
            .to_relay
            .send(UdpDatagram {
                guest,
                destination: server_addr,
                payload: b"hello".to_vec(),
            })
            .unwrap();
        channels.relay_thread_wake.wake();

        // Server sees the datagram and answers.
        let mut buf = [0u8; 16];
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (len, peer) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        server.send_to(b"world", peer).unwrap();

        // The reply arrives on the inbound channel addressed to the guest flow.
        let reply = channels
            .from_relay
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(reply.guest, guest);
        assert_eq!(reply.destination, server_addr);
        assert_eq!(reply.payload, b"world");

        stop.store(true, Ordering::Relaxed);
        channels.relay_thread_wake.wake();
    }

    #[test]
    fn should_relay_respects_dns_carveout_and_policy() {
        let open = EgressPolicy::unrestricted();
        assert!(should_relay_udp("1.2.3.4:123".parse().unwrap(), &open));
        assert!(!should_relay_udp("1.2.3.4:53".parse().unwrap(), &open));

        // Public CIDR — a private allow-list entry would be overridden by the
        // egress hard-floor (see egress.rs tests).
        let restricted = EgressPolicy::from_allowed_cidrs(Some(&["8.8.8.0/24".into()]));
        assert!(should_relay_udp(
            "8.8.8.3:123".parse().unwrap(),
            &restricted
        ));
        assert!(!should_relay_udp(
            "1.2.3.4:123".parse().unwrap(),
            &restricted
        ));
    }
}
