//! Host-side TCP listeners for published virtio-net ports.
//!
//! Context
//! =======
//!
//! This module is the host-facing half of `-p HOST:GUEST` for the virtio-net
//! backend.
//!
//! The outbound virtio path already handles guest-initiated TCP:
//!
//! ```text
//! guest TCP connect -> smoltcp socket -> host TcpStream -> remote server
//! ```
//!
//! Published ports invert the initiator:
//!
//! ```text
//! host client -> host TcpListener -> accepted TcpStream
//!           -> smoltcp creates gateway-side TCP connection to guest_ip:GUEST
//!           -> relay thread bridges the accepted host socket to the guest flow
//! ```
//!
//! High-level flow:
//!
//! ```text
//! host client connects to 127.0.0.1:HOST (or [::1]:HOST)
//!   -> TcpPortListeners accepts TcpStream (one thread for every port)
//!   -> AcceptedTcpConnection sent over a bounded channel
//!   -> relay_wake wakes the smoltcp poll loop
//!   -> poll loop creates a guest-facing TCP socket to guest_ip:GUEST
//!   -> once Established, tcp_relay uses the accepted host TcpStream directly
//! ```

use crate::acceptor::{AcceptedConnection, BoundTcpPorts, TcpAcceptorSet};
use crate::publish_bind::BoundSockets;
use crate::queues::WakePipe;
use crate::{PortMapping, PortProtocol};
use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Mutex;

/// Maximum number of accepted published sockets queued for the poll loop: a
/// burst of inbound connections waits here rather than being dropped while
/// the poll loop takes them on.
pub const DEFAULT_PUBLISH_QUEUE_CAPACITY: usize = 4096;

/// Accepted host TCP connection waiting for the smoltcp poll loop.
pub struct AcceptedTcpConnection {
    /// Connected host-side socket returned by `accept(2)`.
    pub stream: TcpStream,
    /// Host port that accepted the connection.
    pub host_port: u16,
    /// Guest port the connection should be forwarded to.
    pub guest_port: u16,
    /// Remote peer that connected to the published port.
    pub peer_addr: SocketAddr,
}

/// Running published-port listener set for one guest NIC: every listener is
/// accepted on one shared thread ([`TcpAcceptorSet`]).
pub struct TcpPortListeners {
    acceptor: TcpAcceptorSet,
}

/// Published host ports, bound before the listener threads start.
///
/// Binding is separate so a launcher that starts the runtime only after the VM
/// is booting (Windows) can still fail the launch on a port already in use.
pub struct BoundPublishedPorts {
    tcp: BoundTcpPorts,
    pub(crate) udp: Vec<(PortMapping, BoundSockets<UdpSocket>)>,
}

impl BoundPublishedPorts {
    /// Bind every published host port, releasing any already bound on failure.
    ///
    /// Ports bind loopback (see [`crate::publish_bind`]); `SMOLVM_PUBLISH_ADDR` widens
    /// that for fleet nodes whose ingress proxy connects from another host
    /// (the control plane): `0.0.0.0` (or any address) makes the cross-host hop
    /// possible — pair it with a firewall on the port range, since whatever can
    /// reach the address can reach the port.
    pub fn bind(port_mappings: &[PortMapping]) -> io::Result<Self> {
        let tcp_mappings: Vec<PortMapping> = port_mappings
            .iter()
            .filter(|m| m.protocol == PortProtocol::Tcp)
            .copied()
            .collect();
        let mut udp = Vec::new();
        for mapping in port_mappings
            .iter()
            .filter(|m| m.protocol == PortProtocol::Udp)
        {
            udp.push((*mapping, crate::udp_publish::bind_udp_port(mapping)?));
        }
        let tcp = BoundTcpPorts::bind(&tcp_mappings)?;
        Ok(Self { tcp, udp })
    }

    /// True when no host port is published.
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty()
    }

    /// True when no host TCP port is published.
    #[cfg(test)]
    pub(crate) fn tcp_is_empty(&self) -> bool {
        self.tcp.is_empty()
    }
}

impl TcpPortListeners {
    /// Start accepting on the bound published TCP ports, handing each
    /// connection to the poll loop through `tcp_sender` and `publish_wake`.
    pub fn start(
        ports: BoundPublishedPorts,
        tcp_sender: SyncSender<AcceptedTcpConnection>,
        publish_wake: WakePipe,
    ) -> io::Result<Self> {
        let tcp_sender = Mutex::new(tcp_sender);
        let acceptor = TcpAcceptorSet::start(
            ports.tcp,
            Box::new(move |connection: AcceptedConnection| {
                let accepted = AcceptedTcpConnection {
                    stream: connection.stream,
                    host_port: connection.host_port,
                    guest_port: connection.guest_port,
                    peer_addr: connection.peer_addr,
                };
                let sent = tcp_sender
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .try_send(accepted);
                match sent {
                    Ok(()) => publish_wake.wake(),
                    Err(TrySendError::Full(accepted)) => {
                        tracing::warn!(
                            host_port = accepted.host_port,
                            guest_port = accepted.guest_port,
                            peer_addr = %accepted.peer_addr,
                            "dropping published TCP connection because the accept queue is full"
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => {}
                }
            }),
        )?;
        Ok(Self { acceptor })
    }

    pub fn mappings(&self) -> Vec<PortMapping> {
        self.acceptor.mappings()
    }

    pub fn replace(&mut self, next: &[PortMapping]) -> io::Result<()> {
        if self.acceptor.is_closed() {
            return Err(io::Error::other("the network runtime is shutting down"));
        }
        self.acceptor.replace(next)
    }

    pub fn close(&mut self) {
        self.acceptor.close();
    }
}

/// Create the bounded channel used to hand accepted host sockets to the poll loop.
/// Each host port in the provided PortMapping has a listener. When the listener
/// accepts a TCP connection, it "sends" the TcpStream to the poll thread by putting
/// the AcceptedTcpConnection into this channel. The receiver consumes it in the
/// poll thread.
pub fn create_tcp_channel() -> (
    SyncSender<AcceptedTcpConnection>,
    mpsc::Receiver<AcceptedTcpConnection>,
) {
    mpsc::sync_channel(DEFAULT_PUBLISH_QUEUE_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;
    use std::time::Duration;

    fn listener_fixture(
        capacity: usize,
    ) -> (TcpPortListeners, u16, mpsc::Receiver<AcceptedTcpConnection>) {
        let port = free_port();
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let listeners = TcpPortListeners::start(
            BoundPublishedPorts::bind(&[PortMapping::new(port, 8080)]).unwrap(),
            sender,
            WakePipe::new(),
        )
        .unwrap();
        (listeners, port, receiver)
    }

    fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn accepted_guest_port(port: u16, receiver: &mpsc::Receiver<AcceptedTcpConnection>) -> u16 {
        let _client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .guest_port
    }

    fn refuses(port: u16) -> bool {
        TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_secs(1),
        )
        .is_err()
    }

    #[test]
    fn replace_publishes_remaps_and_unpublishes_while_running() {
        let (mut listeners, kept, receiver) = listener_fixture(4);
        let added = free_port();
        listeners
            .replace(&[PortMapping::new(kept, 9090), PortMapping::new(added, 3000)])
            .unwrap();
        assert_eq!(accepted_guest_port(kept, &receiver), 9090);
        assert_eq!(accepted_guest_port(added, &receiver), 3000);
        assert_eq!(
            listeners.mappings(),
            vec![PortMapping::new(kept, 9090), PortMapping::new(added, 3000)]
        );

        listeners.replace(&[PortMapping::new(added, 3000)]).unwrap();
        assert!(refuses(kept));
        assert_eq!(accepted_guest_port(added, &receiver), 3000);
        assert_eq!(listeners.mappings(), vec![PortMapping::new(added, 3000)]);
    }

    #[test]
    fn replace_with_a_taken_port_changes_nothing() {
        let (mut listeners, kept, receiver) = listener_fixture(4);
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let free = free_port();
        assert!(listeners
            .replace(&[
                PortMapping::new(free, 3000),
                PortMapping::new(taken_port, 3001)
            ])
            .is_err());
        assert_eq!(listeners.mappings(), vec![PortMapping::new(kept, 8080)]);
        assert_eq!(accepted_guest_port(kept, &receiver), 8080);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, free)).is_ok());
    }

    #[test]
    fn replace_refuses_udp_mappings() {
        let (mut listeners, kept, _receiver) = listener_fixture(4);
        let before = listeners.mappings();
        let err = listeners
            .replace(&[
                PortMapping::new(kept, 8080),
                PortMapping::with_protocol(free_port(), 27015, PortProtocol::Udp),
            ])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert_eq!(listeners.mappings(), before, "nothing changed");
    }

    #[test]
    fn replace_refuses_a_host_port_twice_and_a_closed_set() {
        let (mut listeners, kept, _receiver) = listener_fixture(4);
        assert!(listeners
            .replace(&[PortMapping::new(kept, 1), PortMapping::new(kept, 2)])
            .is_err());
        assert_eq!(listeners.mappings(), vec![PortMapping::new(kept, 8080)]);
        listeners.close();
        assert!(listeners.mappings().is_empty());
        assert!(listeners.replace(&[PortMapping::new(kept, 8080)]).is_err());
        assert!(refuses(kept));
    }

    #[test]
    fn idle_listener_accepts_repeated_connections_and_shutdown_wakes_it() {
        let (listeners, port, receiver) = listener_fixture(4);
        for _ in 0..32 {
            let client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            let accepted = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(accepted.host_port, port);
            assert_eq!(accepted.guest_port, 8080);
            assert_eq!(accepted.peer_addr, client.local_addr().unwrap());
        }
        let (done, completion) = mpsc::channel();
        thread::spawn(move || {
            drop(listeners);
            done.send(()).unwrap();
        });
        completion.recv_timeout(Duration::from_secs(2)).unwrap();
        // Accepted sockets may leave TIME_WAIT on this port (notably on
        // Windows); partial_bind_failure below checks release without traffic.
    }

    #[test]
    fn full_accept_queue_closes_excess_connections_without_blocking_shutdown() {
        let (listeners, port, receiver) = listener_fixture(0);
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        drop(listeners);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn partial_bind_failure_releases_prior_ports() {
        let available = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let first = available.local_addr().unwrap().port();
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let second = occupied.local_addr().unwrap().port();
        drop(available);
        let result = BoundPublishedPorts::bind(&[
            PortMapping::new(first, 8080),
            PortMapping::new(second, 8081),
        ]);
        assert!(result.is_err());
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, first)).is_ok());
    }
}
