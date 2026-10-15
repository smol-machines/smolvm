//! Published UDP ports for the virtio-net backend (`-p HOST:GUEST/udp`).
//!
//! Context
//! =======
//!
//! Published TCP ports accept a connection on the host and open a matching
//! connection to the guest. UDP has no connections, so a published UDP port is
//! a tiny userspace NAT keyed by the remote client instead:
//!
//! ```text
//! client datagram to HOST (host UDP socket, publisher thread)
//!   -> InboundUdpDatagram over a bounded channel, relay_wake
//!   -> poll loop: find or open the client's session, a smoltcp UDP socket
//!      bound to gateway_ip:session_port
//!   -> send to guest_ip:GUEST (the guest sees the client as gateway:session)
//! guest reply to gateway_ip:session_port
//!   -> classify: a session endpoint, so smoltcp delivers it to that socket
//!   -> poll loop drains it as OutboundUdpDatagram to the publisher thread
//!   -> send_to(client) from the published host socket, so the client hears
//!      back from the port it addressed
//! ```
//!
//! Like the outbound relay, sessions end on idle expiry, and loss under
//! pressure (full channels or tables) is acceptable UDP behaviour: logged, never
//! blocking.

use crate::queues::WakePipe;
use crate::virtio_net_log;
use crate::BoundPublishedPorts;
use polling::{Event, Events};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as HostUdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Max in-flight datagrams per direction before drops (UDP may drop).
const CHANNEL_CAPACITY: usize = 1024;
/// Max concurrent client sessions across every published UDP port.
const MAX_SESSIONS: usize = 512;
/// Packet slots per session socket buffer (per direction).
const SESSION_PACKET_SLOTS: usize = 32;
/// Payload bytes per session socket buffer (per direction).
const SESSION_BUFFER_BYTES: usize = 32 * 1024;
/// Largest datagram read from a published host socket.
const MAX_DATAGRAM_BYTES: usize = 65_535;
/// Largest payload that reaches the guest: one 1500-byte frame less the IPv4
/// and UDP headers. The gateway does not fragment, so anything larger is
/// dropped; game and voice protocols keep their datagrams under this anyway.
pub const MAX_GUEST_PAYLOAD: usize = 1500 - 20 - 8;
/// Drop a client's session after this much silence in both directions.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Publisher thread poll ceiling, so shutdown is noticed promptly.
const PUBLISHER_POLL_MAX: Duration = Duration::from_millis(1000);
/// Gateway-side source ports handed to sessions (the IANA dynamic range).
const SESSION_PORT_START: u16 = 49_152;
const SESSION_PORT_END: u16 = 65_535;

/// A client datagram received on a published host port.
pub struct InboundUdpDatagram {
    /// Host port the client addressed.
    pub host_port: u16,
    /// Guest port the mapping forwards to.
    pub guest_port: u16,
    /// The remote client.
    pub client: SocketAddr,
    /// Datagram payload.
    pub payload: Vec<u8>,
}

/// A guest reply to send back to a client from its published host port.
pub struct OutboundUdpDatagram {
    /// Host port the client originally addressed.
    pub host_port: u16,
    /// The remote client.
    pub client: SocketAddr,
    /// Datagram payload.
    pub payload: Vec<u8>,
}

/// Poll-loop-side endpoints of the publisher thread.
pub struct UdpPublishChannels {
    /// Publisher thread -> poll loop.
    pub from_host: Receiver<InboundUdpDatagram>,
    /// Poll loop -> publisher thread.
    pub to_host: SyncSender<OutboundUdpDatagram>,
    /// Wakes the publisher thread after `to_host` sends.
    pub host_wake: WakePipe,
}

/// Running publisher thread for one guest NIC; dropping it stops the thread.
pub struct UdpPortPublisher {
    shutdown: Arc<AtomicBool>,
    wake: WakePipe,
    handle: Option<JoinHandle<()>>,
}

impl Drop for UdpPortPublisher {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.wake.wake();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One published host socket and the mapping it serves.
struct PublishedSocket {
    socket: HostUdpSocket,
    host_port: u16,
    guest_port: u16,
}

/// Start the publisher thread over the UDP sockets `ports` bound. Returns
/// `None` when no UDP port is published.
///
/// `reply_wake` is the poll loop's relay wake pipe, pulsed whenever a client
/// datagram is queued for the guest.
pub fn start_udp_publisher(
    ports: &mut BoundPublishedPorts,
    reply_wake: WakePipe,
) -> std::io::Result<Option<(UdpPortPublisher, UdpPublishChannels)>> {
    if ports.udp.is_empty() {
        return Ok(None);
    }
    let mut published = Vec::new();
    for (mapping, socket, socket_v6) in ports.udp.drain(..) {
        for socket in std::iter::once(socket).chain(socket_v6) {
            socket.set_nonblocking(true)?;
            published.push(PublishedSocket {
                socket,
                host_port: mapping.host,
                guest_port: mapping.guest,
            });
        }
    }

    let (inbound_tx, inbound_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let (outbound_tx, outbound_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let wake = WakePipe::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_wake = wake.clone();
    let thread_shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("smolvm-udp-publish".into())
        .spawn(move || {
            run_publisher(
                published,
                inbound_tx,
                outbound_rx,
                thread_wake,
                reply_wake,
                thread_shutdown,
            )
        })?;

    Ok(Some((
        UdpPortPublisher {
            shutdown,
            wake: wake.clone(),
            handle: Some(handle),
        },
        UdpPublishChannels {
            from_host: inbound_rx,
            to_host: outbound_tx,
            host_wake: wake,
        },
    )))
}

fn run_publisher(
    published: Vec<PublishedSocket>,
    inbound: SyncSender<InboundUdpDatagram>,
    outbound: Receiver<OutboundUdpDatagram>,
    wake: WakePipe,
    reply_wake: WakePipe,
    shutdown: Arc<AtomicBool>,
) {
    let poller = wake.poller();
    for (slot, published) in published.iter().enumerate() {
        // SAFETY: `published` owns every socket for this whole function and each
        // is deleted from the poller below before it is dropped.
        if let Err(err) = unsafe { poller.add(&published.socket, Event::readable(slot + 1)) } {
            tracing::warn!(host_port = published.host_port, error = %err, "published UDP port readiness failed");
        }
    }
    let mut recv_buf = vec![0u8; MAX_DATAGRAM_BYTES];
    let mut events = Events::new();

    while !shutdown.load(Ordering::SeqCst) {
        // Guest replies go out of the socket the client addressed, in its family.
        loop {
            match outbound.try_recv() {
                Ok(reply) => {
                    let socket = published.iter().find(|p| {
                        p.host_port == reply.host_port
                            && p.socket
                                .local_addr()
                                .is_ok_and(|local| local.is_ipv4() == reply.client.is_ipv4())
                    });
                    if let Some(published) = socket {
                        // Best-effort send; UDP loss is allowed.
                        let _ = published.socket.send_to(&reply.payload, reply.client);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return finish(poller, &published),
            }
        }

        events.clear();
        let _ = poller.wait(&mut events, Some(PUBLISHER_POLL_MAX));
        let mut queued = false;
        for event in events.iter() {
            let Some(entry) = event
                .key
                .checked_sub(1)
                .and_then(|slot| published.get(slot))
            else {
                continue;
            };
            loop {
                match entry.socket.recv_from(&mut recv_buf) {
                    Ok((len, client)) => {
                        let datagram = InboundUdpDatagram {
                            host_port: entry.host_port,
                            guest_port: entry.guest_port,
                            client,
                            payload: recv_buf[..len].to_vec(),
                        };
                        match inbound.try_send(datagram) {
                            Ok(()) => queued = true,
                            Err(TrySendError::Full(_)) => virtio_net_log!(
                                "virtio-net: dropping published UDP datagram from {} (queue full)",
                                client
                            ),
                            Err(TrySendError::Disconnected(_)) => {
                                return finish(poller, &published);
                            }
                        }
                    }
                    // WouldBlock ends the drain; ICMP errors surfaced on the
                    // socket (a client gone away) are not fatal to the port.
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            // Oneshot readiness: rearm after draining.
            let _ = poller.modify(&entry.socket, Event::readable(event.key));
        }
        if queued {
            reply_wake.wake();
        }
    }
    finish(poller, &published);
}

/// Deregister every published socket before the caller drops them.
fn finish(poller: &polling::Poller, published: &[PublishedSocket]) {
    for published in published {
        let _ = poller.delete(&published.socket);
    }
}

/// One client's session: its gateway-side socket toward the guest.
struct Session {
    handle: SocketHandle,
    gateway_port: u16,
    last_active: Instant,
}

/// Poll-loop-side table of client sessions on published UDP ports.
pub struct PublishedUdpTable {
    gateway_ip: Ipv4Addr,
    guest_ip: Ipv4Addr,
    sessions: HashMap<(u16, SocketAddr), Session>,
    /// Gateway port -> the session it carries, for classifying guest replies.
    by_gateway_port: HashMap<u16, (u16, SocketAddr)>,
    next_port: u16,
}

impl PublishedUdpTable {
    /// `seed` spreads session ports so a restored guest does not see a reused
    /// port for a different client.
    pub fn new(gateway_ip: Ipv4Addr, guest_ip: Ipv4Addr, seed: u16) -> Self {
        Self {
            gateway_ip,
            guest_ip,
            sessions: HashMap::new(),
            by_gateway_port: HashMap::new(),
            next_port: SESSION_PORT_START + seed % (SESSION_PORT_END - SESSION_PORT_START + 1),
        }
    }

    /// Whether a guest datagram to `destination` is a reply into a session.
    pub fn is_session_endpoint(&self, destination: SocketAddr) -> bool {
        destination.ip() == std::net::IpAddr::V4(self.gateway_ip)
            && self.by_gateway_port.contains_key(&destination.port())
    }

    /// Number of live client sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// True when no client session is live.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Forward queued client datagrams into the guest, opening a session for a
    /// client seen for the first time.
    pub fn deliver_inbound(
        &mut self,
        sockets: &mut SocketSet<'_>,
        from_host: &Receiver<InboundUdpDatagram>,
    ) {
        while let Ok(datagram) = from_host.try_recv() {
            if datagram.payload.len() > MAX_GUEST_PAYLOAD {
                virtio_net_log!(
                    "virtio-net: dropping {}-byte published UDP datagram from {} (over the {MAX_GUEST_PAYLOAD}-byte unfragmented limit)",
                    datagram.payload.len(),
                    datagram.client
                );
                continue;
            }
            let key = (datagram.host_port, datagram.client);
            let Some(handle) = self.session_for(key, sockets) else {
                continue;
            };
            let socket = sockets.get_mut::<UdpSocket>(handle);
            let metadata = UdpMetadata {
                endpoint: smoltcp::wire::IpEndpoint {
                    addr: self.guest_ip.into(),
                    port: datagram.guest_port,
                },
                local_address: Some(self.gateway_ip.into()),
                meta: Default::default(),
            };
            if socket.send_slice(&datagram.payload, metadata).is_err() {
                virtio_net_log!(
                    "virtio-net: dropping published UDP datagram from {} (guest socket buffer full)",
                    datagram.client
                );
            }
        }
    }

    fn session_for(
        &mut self,
        key: (u16, SocketAddr),
        sockets: &mut SocketSet<'_>,
    ) -> Option<SocketHandle> {
        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_active = Instant::now();
            return Some(session.handle);
        }
        if self.sessions.len() >= MAX_SESSIONS {
            virtio_net_log!(
                "virtio-net: dropping published UDP datagram from {} (session table full)",
                key.1
            );
            return None;
        }
        let gateway_port = self.allocate_port()?;
        let mut socket = UdpSocket::new(
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; SESSION_PACKET_SLOTS],
                vec![0u8; SESSION_BUFFER_BYTES],
            ),
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; SESSION_PACKET_SLOTS],
                vec![0u8; SESSION_BUFFER_BYTES],
            ),
        );
        socket
            .bind(smoltcp::wire::IpListenEndpoint {
                addr: Some(self.gateway_ip.into()),
                port: gateway_port,
            })
            .ok()?;
        let handle = sockets.add(socket);
        self.sessions.insert(
            key,
            Session {
                handle,
                gateway_port,
                last_active: Instant::now(),
            },
        );
        self.by_gateway_port.insert(gateway_port, key);
        Some(handle)
    }

    fn allocate_port(&mut self) -> Option<u16> {
        let span = u32::from(SESSION_PORT_END - SESSION_PORT_START) + 1;
        for _ in 0..span {
            let candidate = self.next_port;
            self.next_port = if candidate == SESSION_PORT_END {
                SESSION_PORT_START
            } else {
                candidate + 1
            };
            if !self.by_gateway_port.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Move guest replies toward the publisher thread. Returns true when any
    /// were queued (the caller then wakes that thread). A datagram from any
    /// guest address other than its own is dropped, so a session only carries
    /// the guest's answers.
    pub fn drain_to_host(
        &mut self,
        sockets: &mut SocketSet<'_>,
        to_host: &SyncSender<OutboundUdpDatagram>,
    ) -> bool {
        let mut queued = false;
        let guest_ip: std::net::IpAddr = self.guest_ip.into();
        for (&(host_port, client), session) in self.sessions.iter_mut() {
            let socket = sockets.get_mut::<UdpSocket>(session.handle);
            while socket.can_recv() {
                let Ok((payload, metadata)) = socket.recv() else {
                    break;
                };
                let from: std::net::IpAddr = metadata.endpoint.addr.into();
                if from != guest_ip {
                    continue;
                }
                session.last_active = Instant::now();
                let reply = OutboundUdpDatagram {
                    host_port,
                    client,
                    payload: payload.to_vec(),
                };
                match to_host.try_send(reply) {
                    Ok(()) => queued = true,
                    Err(TrySendError::Full(_)) => virtio_net_log!(
                        "virtio-net: dropping guest UDP reply to {} (publish queue full)",
                        client
                    ),
                    Err(TrySendError::Disconnected(_)) => return queued,
                }
            }
        }
        queued
    }

    /// Close sessions silent for [`SESSION_IDLE_TIMEOUT`].
    pub fn expire_idle(&mut self, sockets: &mut SocketSet<'_>) {
        let now = Instant::now();
        let by_gateway_port = &mut self.by_gateway_port;
        self.sessions.retain(|_, session| {
            let live = now.duration_since(session.last_active) < SESSION_IDLE_TIMEOUT;
            if !live {
                sockets.remove(session.handle);
                by_gateway_port.remove(&session.gateway_port);
            }
            live
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PortMapping, PortProtocol};

    #[test]
    fn publisher_moves_datagrams_both_ways_on_the_published_port() {
        let probe = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let host_port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut ports = BoundPublishedPorts::bind(&[PortMapping::with_protocol(
            host_port,
            27015,
            PortProtocol::Udp,
        )])
        .unwrap();
        assert!(ports.tcp_is_empty());
        let reply_wake = WakePipe::new();
        let (publisher, channels) = start_udp_publisher(&mut ports, reply_wake)
            .unwrap()
            .unwrap();

        let client = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .send_to(b"join", (Ipv4Addr::LOCALHOST, host_port))
            .unwrap();
        let inbound = channels
            .from_host
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(inbound.host_port, host_port);
        assert_eq!(inbound.guest_port, 27015);
        assert_eq!(inbound.client, client.local_addr().unwrap());
        assert_eq!(inbound.payload, b"join");

        channels
            .to_host
            .send(OutboundUdpDatagram {
                host_port,
                client: inbound.client,
                payload: b"welcome".to_vec(),
            })
            .unwrap();
        channels.host_wake.wake();
        let mut buf = [0u8; 16];
        let (len, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"welcome");
        assert_eq!(
            from.port(),
            host_port,
            "the reply comes from the published port"
        );
        drop(publisher);
    }

    #[test]
    fn a_published_udp_port_in_use_fails_the_bind() {
        let taken = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = taken.local_addr().unwrap().port();
        let err = BoundPublishedPorts::bind(&[PortMapping::with_protocol(
            port,
            27015,
            PortProtocol::Udp,
        )])
        .err()
        .expect("an occupied UDP port is refused");
        assert!(err.to_string().contains("cannot publish host UDP"));
    }

    #[test]
    fn sessions_are_per_client_and_answer_only_the_guest() {
        let gateway = Ipv4Addr::new(100, 96, 0, 1);
        let guest = Ipv4Addr::new(100, 96, 0, 2);
        let mut table = PublishedUdpTable::new(gateway, guest, 7);
        let mut sockets = SocketSet::new(vec![]);
        let (tx, rx) = mpsc::sync_channel(8);
        let a: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        for client in [a, b, a] {
            tx.send(InboundUdpDatagram {
                host_port: 27015,
                guest_port: 27015,
                client,
                payload: b"x".to_vec(),
            })
            .unwrap();
        }
        table.deliver_inbound(&mut sockets, &rx);
        assert_eq!(table.len(), 2, "one session per client");

        let ports: Vec<u16> = table.by_gateway_port.keys().copied().collect();
        for port in &ports {
            assert!(table.is_session_endpoint(SocketAddr::new(gateway.into(), *port)));
            assert!(!table.is_session_endpoint(SocketAddr::new(guest.into(), *port)));
        }
        assert!(!table.is_session_endpoint(SocketAddr::new(gateway.into(), 1)));
    }

    #[test]
    fn session_ports_wrap_and_skip_ports_in_use() {
        let mut table = PublishedUdpTable::new(
            Ipv4Addr::new(100, 96, 0, 1),
            Ipv4Addr::new(100, 96, 0, 2),
            SESSION_PORT_END - SESSION_PORT_START,
        );
        table
            .by_gateway_port
            .insert(SESSION_PORT_START, (1, "127.0.0.1:1".parse().unwrap()));
        assert_eq!(table.allocate_port(), Some(SESSION_PORT_END));
        assert_eq!(table.allocate_port(), Some(SESSION_PORT_START + 1));
    }
}
