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
//!   -> TcpPortListeners accepts TcpStream
//!   -> AcceptedTcpConnection sent over a bounded channel
//!   -> relay_wake wakes the smoltcp poll loop
//!   -> poll loop creates a guest-facing TCP socket to guest_ip:GUEST
//!   -> once Established, tcp_relay uses the accepted host TcpStream directly
//! ```

use crate::queues::WakePipe;
use crate::PortMapping;
use polling::{Event, Events, Poller};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(25);
/// Maximum number of accepted published sockets queued for the poll loop.
pub const DEFAULT_PUBLISH_QUEUE_CAPACITY: usize = 64;

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

/// Running published-port listener set for one guest NIC.
pub struct TcpPortListeners {
    shutdown: Arc<AtomicBool>,
    handles: Vec<ListenerThread>,
}

struct ListenerThread {
    handle: JoinHandle<()>,
    poller: Arc<Poller>,
}

// Deregister before closing the socket, including on spawn failure and unwind.
struct ReadyListener {
    listener: TcpListener,
    poller: Arc<Poller>,
}

impl ReadyListener {
    fn new(listener: TcpListener) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        let poller = Arc::new(Poller::new()?);
        // SAFETY: ReadyListener owns the socket and removes it in Drop before
        // the socket closes. No borrowed source outlives its registration.
        unsafe {
            poller.add(&listener, Event::readable(0))?;
        }
        Ok(Self { listener, poller })
    }
}

impl Drop for ReadyListener {
    fn drop(&mut self) {
        let _ = self.poller.delete(&self.listener);
    }
}

/// Published host ports, bound before the listener threads start.
///
/// Binding is separate so a launcher that starts the runtime only after the VM
/// is booting (Windows) can still fail the launch on a port already in use.
pub struct BoundPublishedPorts(Vec<(PortMapping, TcpListener, Option<TcpListener>)>);

impl BoundPublishedPorts {
    /// Bind every published host port, releasing any already bound on failure.
    pub fn bind(port_mappings: &[PortMapping]) -> io::Result<Self> {
        // Published ports bind loopback by default. `SMOLVM_PUBLISH_ADDR`
        // widens that for fleet nodes whose ingress proxy connects from
        // another host (the control plane): `0.0.0.0` (or any address) makes
        // the cross-host hop possible — pair it with a firewall on the port
        // range, since whatever can reach the address can reach the port.
        let publish_addr: Ipv4Addr = std::env::var("SMOLVM_PUBLISH_ADDR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(Ipv4Addr::LOCALHOST);
        let publish_v6 = if publish_addr == Ipv4Addr::UNSPECIFIED {
            Ipv6Addr::UNSPECIFIED
        } else {
            Ipv6Addr::LOCALHOST
        };

        let mut bound = Vec::with_capacity(port_mappings.len());
        for mapping in port_mappings {
            // The IPv4 listener is required; the IPv6 one is best-effort so
            // hosts without IPv6 still publish normally.
            let listener = TcpListener::bind((publish_addr, mapping.host)).map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "cannot publish host TCP {publish_addr}:{} to guest TCP {}: {err}",
                        mapping.host, mapping.guest,
                    ),
                )
            })?;
            let listener_v6 = match TcpListener::bind((publish_v6, mapping.host)) {
                Ok(listener) => Some(listener),
                Err(err) => {
                    tracing::debug!(
                        host_port = mapping.host,
                        error = %err,
                        "skipping IPv6 listener for published port"
                    );
                    None
                }
            };
            bound.push((*mapping, listener, listener_v6));
        }
        Ok(Self(bound))
    }

    /// True when no host port is published.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TcpPortListeners {
    /// Start one non-blocking listener thread per bound published port.
    ///
    /// The CLI caps published mappings because every mapping creates this thread
    /// and normally a second IPv6 thread. Raise that cap only after replacing
    /// this per-listener model with multiplexed listeners or a bounded worker pool.
    pub fn start(
        ports: BoundPublishedPorts,
        tcp_sender: SyncSender<AcceptedTcpConnection>,
        publish_wake: WakePipe,
    ) -> io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(ports.0.len());

        for (mapping, listener, listener_v6) in ports.0 {
            for listener in std::iter::once(listener).chain(listener_v6) {
                let listener = ReadyListener::new(listener).inspect_err(|_| {
                    shutdown_all(&shutdown, &mut handles);
                })?;
                let poller = listener.poller.clone();

                let tcp_sender = tcp_sender.clone();
                let publish_wake = publish_wake.clone();
                let shutdown_flag = shutdown.clone();
                let host_port = mapping.host;
                let guest_port = mapping.guest;

                let handle = thread::Builder::new()
                    .name(format!("smolvm-tcp-{host_port}"))
                    .spawn(move || {
                        run_tcp_port_listener(
                            listener,
                            host_port,
                            guest_port,
                            tcp_sender,
                            publish_wake,
                            shutdown_flag,
                        )
                    })
                    .map_err(|err| {
                        shutdown_all(&shutdown, &mut handles);
                        io::Error::other(format!(
                            "failed to spawn published-port listener thread for {host_port}: {err}"
                        ))
                    })?;
                handles.push(ListenerThread { handle, poller });
            }
        }

        Ok(Self { shutdown, handles })
    }
}

impl Drop for TcpPortListeners {
    fn drop(&mut self) {
        shutdown_all(&self.shutdown, &mut self.handles);
    }
}

fn shutdown_all(shutdown: &Arc<AtomicBool>, handles: &mut Vec<ListenerThread>) {
    shutdown.store(true, Ordering::SeqCst);
    for listener in handles.iter() {
        let _ = listener.poller.notify();
    }
    for listener in handles.drain(..) {
        let _ = listener.handle.join();
    }
}

fn run_tcp_port_listener(
    listener: ReadyListener,
    host_port: u16,
    guest_port: u16,
    tcp_sender: SyncSender<AcceptedTcpConnection>,
    publish_wake: WakePipe,
    shutdown: Arc<AtomicBool>,
) {
    let mut events = Events::new();
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }

        match listener.listener.accept() {
            Ok((stream, peer_addr)) => {
                let accepted = AcceptedTcpConnection {
                    stream,
                    host_port,
                    guest_port,
                    peer_addr,
                };

                match tcp_sender.try_send(accepted) {
                    Ok(()) => publish_wake.wake(),
                    Err(TrySendError::Full(accepted)) => {
                        tracing::warn!(
                            host_port = accepted.host_port,
                            guest_port = accepted.guest_port,
                            peer_addr = %accepted.peer_addr,
                            "dropping published TCP connection because the accept queue is full"
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                // Rearm after draining. Readiness arriving between accept and
                // modify is retained; shutdown also wakes this wait explicitly.
                if let Err(err) = listener
                    .poller
                    .modify(&listener.listener, Event::readable(0))
                {
                    tracing::warn!(host_port, error = %err, "published port readiness failed");
                    return;
                }
                events.clear();
                if let Err(err) = listener.poller.wait(&mut events, None) {
                    if err.kind() != io::ErrorKind::Interrupted {
                        tracing::warn!(host_port, error = %err, "published port readiness failed");
                        return;
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                tracing::warn!(
                    host_port,
                    guest_port,
                    error = %err,
                    "published port listener accept failed"
                );
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
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

    fn listener_fixture(
        capacity: usize,
    ) -> (TcpPortListeners, u16, mpsc::Receiver<AcceptedTcpConnection>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let ready = ReadyListener::new(listener).unwrap();
        let poller = ready.poller.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let handle = thread::spawn(move || {
            run_tcp_port_listener(ready, port, 8080, sender, WakePipe::new(), flag)
        });
        (
            TcpPortListeners {
                shutdown,
                handles: vec![ListenerThread { handle, poller }],
            },
            port,
            receiver,
        )
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
            PortMapping {
                host: first,
                guest: 8080,
            },
            PortMapping {
                host: second,
                guest: 8081,
            },
        ]);
        assert!(result.is_err());
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, first)).is_ok());
    }
}
