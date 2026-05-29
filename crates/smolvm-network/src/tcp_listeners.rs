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
//! host client connects to 127.0.0.1:HOST
//!   -> TcpPortListeners accepts TcpStream
//!   -> AcceptedTcpConnection sent over a bounded channel
//!   -> relay_wake wakes the smoltcp poll loop
//!   -> poll loop creates a guest-facing TCP socket to guest_ip:GUEST
//!   -> once Established, tcp_relay uses the accepted host TcpStream directly
//! ```

use crate::queues::WakePipe;
use crate::PortMapping;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
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
    handles: Vec<JoinHandle<()>>,
}

impl TcpPortListeners {
    /// Start one non-blocking listener thread per published port.
    pub fn start(
        port_mappings: &[PortMapping],
        tcp_sender: SyncSender<AcceptedTcpConnection>,
        publish_wake: WakePipe,
    ) -> io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(port_mappings.len());

        for mapping in port_mappings {
            let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, mapping.host)) {
                Ok(listener) => listener,
                Err(err) => {
                    shutdown_all(&shutdown, &mut handles);
                    return Err(err);
                }
            };
            if let Err(err) = listener.set_nonblocking(true) {
                shutdown_all(&shutdown, &mut handles);
                return Err(err);
            }

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
            handles.push(handle);
        }

        Ok(Self { shutdown, handles })
    }
}

impl Drop for TcpPortListeners {
    fn drop(&mut self) {
        shutdown_all(&self.shutdown, &mut self.handles);
    }
}

fn shutdown_all(shutdown: &Arc<AtomicBool>, handles: &mut Vec<JoinHandle<()>>) {
    shutdown.store(true, Ordering::SeqCst);
    for handle in handles.drain(..) {
        let _ = handle.join();
    }
}

fn run_tcp_port_listener(
    listener: TcpListener,
    host_port: u16,
    guest_port: u16,
    tcp_sender: SyncSender<AcceptedTcpConnection>,
    publish_wake: WakePipe,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }

        match listener.accept() {
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
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(err) => {
                tracing::warn!(
                    host_port,
                    guest_port,
                    error = %err,
                    "published port listener accept failed"
                );
                thread::sleep(ACCEPT_POLL_INTERVAL);
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
