//! TCP relay support for the virtio-net backend.
//!
//! Context
//! =======
//!
//! In the Phase 1 virtio-net design, guest TCP does not flow directly from the
//! guest to the outside network through the host kernel. Instead, the host-side
//! smoltcp runtime terminates the guest-visible TCP connection in userspace and
//! relays payloads to a normal host `TcpStream`.
//!
//! Conceptually:
//!
//! ```text
//! guest app
//!   -> guest kernel TCP
//!   -> Ethernet frame
//!   -> smoltcp TCP socket (inside smolvm)
//!   -> channel
//!   -> host TcpStream
//!   -> remote server
//! ```
//!
//! That means:
//! - the host runtime can observe every guest TCP byte stream on this NIC
//! - smoltcp owns the guest-facing TCP state machine
//! - the relay thread owns the host-facing TCP socket
//! - channels bridge payloads between them

use crate::queues::WakePipe;
use crate::virtio_net_log;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpListenEndpoint;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const TCP_RX_BUFFER_BYTES: usize = 64 * 1024;
const TCP_TX_BUFFER_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 256;
const CHANNEL_CAPACITY: usize = 32;
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
const CLOSE_RETRY_LIMIT: u16 = 64;
const PROXY_IDLE_SLEEP: Duration = Duration::from_millis(10);
const PUBLISHED_PORT_START: u16 = 49_152;
const PUBLISHED_PORT_END: u16 = 65_535;

/// Track all active guest TCP connections bridged through host sockets.
///
/// One entry corresponds to one `(guest source, destination)` tuple. The table
/// lives in the smoltcp poll thread and owns all guest-facing socket handles.
pub struct TcpRelayTable {
    connections: HashMap<SocketHandle, TrackedConnection>,
    connection_keys: HashSet<(SocketAddr, SocketAddr)>,
    used_published_ports: HashSet<u16>,
    next_published_port: u16,
    max_connections: usize,
}

/// Newly established guest connection ready for a host relay thread.
///
/// The poll loop emits these once the guest-side smoltcp socket reaches
/// `Established`. At that point we can safely create the host-side relay
/// thread and give it channel endpoints for payload exchange.
pub struct NewTcpConnection {
    /// Destination originally requested by the guest.
    pub destination: SocketAddr,
    /// How the host-side relay should be started.
    pub relay_target: RelayTarget,
    /// Guest-to-host payloads read from the smoltcp socket.
    pub from_smoltcp: Receiver<Vec<u8>>,
    /// Host-to-guest payloads written back into the smoltcp socket.
    pub to_smoltcp: SyncSender<Vec<u8>>,
    /// Shared relay exit state.
    pub exit_state: RelayExitState,
}

#[derive(Debug)]
struct TrackedConnection {
    // `source` and `destination` identify the guest-side flow.
    source: SocketAddr,
    destination: SocketAddr,
    // guest -> host relay payloads
    to_proxy: SyncSender<Vec<u8>>,
    // host -> guest relay payloads
    from_proxy: Receiver<Vec<u8>>,
    // endpoints are held here until the guest-side handshake completes
    pending_proxy_endpoints: Option<PendingProxyEndpoints>,
    // once true, a dedicated host relay thread exists
    relay_spawned: bool,
    // partial host->guest payload not yet fully accepted by smoltcp
    buffered_proxy_data: Option<(Vec<u8>, usize)>,
    // bounded retry count for closing with unsent buffered data
    close_attempts: u16,
    // relay thread termination mode observed by the poll loop
    exit_state: RelayExitState,
    // reserved local source port for published inbound connections
    reserved_published_port: Option<u16>,
}

#[derive(Debug)]
struct PendingProxyEndpoints {
    from_smoltcp: Receiver<Vec<u8>>,
    to_smoltcp: SyncSender<Vec<u8>>,
    relay_target: RelayTarget,
}

/// How a host-side TCP relay should obtain its remote socket.
#[derive(Debug)]
pub enum RelayTarget {
    /// Open a new outbound host `TcpStream` to the destination.
    Connect(SocketAddr),
    /// Use an already-accepted host `TcpStream` from a published port listener.
    Attached(TcpStream),
}

/// Host relay termination state shared between the poll loop and the relay thread.
///
/// The relay thread cannot mutate smoltcp sockets directly because those sockets
/// are owned by the poll loop thread. Instead it reports how it finished, and
/// the poll loop interprets that into guest-side socket actions:
/// - `Graceful` -> close guest socket cleanly
/// - `Abort`    -> abort/reset guest socket
#[derive(Clone, Debug)]
pub struct RelayExitState {
    inner: Arc<AtomicU8>,
}

/// How a host TCP relay thread terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayExitMode {
    /// Relay thread is still running.
    Running = 0,
    /// Remote side closed normally; send FIN toward the guest.
    Graceful = 1,
    /// Remote connect or I/O failed; abort the guest TCP socket.
    Abort = 2,
}

impl RelayExitState {
    fn new() -> Self {
        Self {
            inner: Arc::new(AtomicU8::new(RelayExitMode::Running as u8)),
        }
    }

    fn load(&self) -> RelayExitMode {
        match self.inner.load(Ordering::Relaxed) {
            1 => RelayExitMode::Graceful,
            2 => RelayExitMode::Abort,
            _ => RelayExitMode::Running,
        }
    }

    fn store(&self, mode: RelayExitMode) {
        self.inner.store(mode as u8, Ordering::Relaxed);
    }
}

impl TcpRelayTable {
    /// Create a new relay table.
    pub fn new(max_connections: Option<usize>) -> Self {
        Self {
            connections: HashMap::new(),
            connection_keys: HashSet::new(),
            used_published_ports: HashSet::new(),
            next_published_port: PUBLISHED_PORT_START,
            max_connections: max_connections.unwrap_or(MAX_CONNECTIONS),
        }
    }

    /// Whether a relay socket already exists for the same guest source and destination.
    pub fn has_socket_for(&self, source: &SocketAddr, destination: &SocketAddr) -> bool {
        self.connection_keys.contains(&(*source, *destination))
    }

    /// Create a smoltcp TCP socket for a guest SYN.
    ///
    /// Why this happens before full ingress processing:
    /// - when the first guest SYN arrives, smoltcp needs a matching socket to
    ///   receive it
    /// - the poll loop therefore pre-creates a listening socket keyed to the
    ///   destination the guest is trying to reach
    /// - only after the guest-facing connection reaches `Established` do we
    ///   spawn the host relay thread
    ///
    /// Data path after creation:
    ///
    /// ```text
    /// smoltcp socket --to_proxy channel--> host relay thread
    /// host relay thread --from_proxy channel--> smoltcp socket
    /// ```
    pub fn create_tcp_socket(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        sockets: &mut SocketSet<'_>,
    ) -> bool {
        if self.connections.len() >= self.max_connections {
            tracing::warn!("dropping TCP connection because the relay table is full");
            return false;
        }

        let rx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER_BYTES]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER_BYTES]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
        let std::net::IpAddr::V4(destination_ip) = destination.ip() else {
            return false;
        };

        let listen_endpoint = IpListenEndpoint {
            addr: Some(destination_ip.into()),
            port: destination.port(),
        };
        if socket.listen(listen_endpoint).is_err() {
            return false;
        }

        let handle = sockets.add(socket);

        let (to_proxy_tx, to_proxy_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (from_proxy_tx, from_proxy_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let exit_state = RelayExitState::new();

        self.connection_keys.insert((source, destination));
        self.connections.insert(
            handle,
            TrackedConnection {
                source,
                destination,
                to_proxy: to_proxy_tx,
                from_proxy: from_proxy_rx,
                pending_proxy_endpoints: Some(PendingProxyEndpoints {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                    relay_target: RelayTarget::Connect(destination),
                }),
                relay_spawned: false,
                buffered_proxy_data: None,
                close_attempts: 0,
                exit_state,
                reserved_published_port: None,
            },
        );

        true
    }

    /// Create a guest-facing TCP connection for a published host socket.
    ///
    /// This is the host->guest mirror of `create_tcp_socket`:
    ///
    /// ```text
    /// host client connects to published port
    ///   -> host listener accepts TcpStream
    ///   -> poll loop creates smoltcp TCP socket from gateway_ip:ephemeral
    ///      to guest_ip:guest_port
    ///   -> guest kernel sees a normal inbound TCP connection on guest_port
    /// ```
    ///
    /// The guest-visible source address is the gateway IP, not the original
    /// host peer address. That keeps the first version simple and matches the
    /// fact that this runtime is acting as a userspace gateway/proxy.
    pub fn create_published_socket(
        &mut self,
        interface: &mut Interface,
        gateway_ip: Ipv4Addr,
        destination: SocketAddr,
        host_stream: TcpStream,
        sockets: &mut SocketSet<'_>,
    ) -> bool {
        if self.connections.len() >= self.max_connections {
            tracing::warn!("dropping published TCP connection because the relay table is full");
            return false;
        }

        let Some(local_port) = self.allocate_published_port() else {
            tracing::warn!(
                "dropping published TCP connection because no gateway source port is available"
            );
            return false;
        };

        let std::net::IpAddr::V4(destination_ip) = destination.ip() else {
            self.used_published_ports.remove(&local_port);
            return false;
        };

        let rx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER_BYTES]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER_BYTES]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
        let local_endpoint = IpListenEndpoint {
            addr: Some(gateway_ip.into()),
            port: local_port,
        };
        if socket
            .connect(
                interface.context(),
                (destination_ip, destination.port()),
                local_endpoint,
            )
            .is_err()
        {
            self.used_published_ports.remove(&local_port);
            return false;
        }

        let handle = sockets.add(socket);
        let source = SocketAddr::new(std::net::IpAddr::V4(gateway_ip), local_port);

        let (to_proxy_tx, to_proxy_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (from_proxy_tx, from_proxy_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let exit_state = RelayExitState::new();

        self.connection_keys.insert((source, destination));
        self.connections.insert(
            handle,
            TrackedConnection {
                source,
                destination,
                to_proxy: to_proxy_tx,
                from_proxy: from_proxy_rx,
                pending_proxy_endpoints: Some(PendingProxyEndpoints {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                    relay_target: RelayTarget::Attached(host_stream),
                }),
                relay_spawned: false,
                buffered_proxy_data: None,
                close_attempts: 0,
                exit_state,
                reserved_published_port: Some(local_port),
            },
        );

        true
    }

    /// Relay TCP payloads between smoltcp sockets and host relay threads.
    ///
    /// This runs in the poll thread. It is responsible for:
    /// - draining bytes received from the guest-facing smoltcp socket and
    ///   pushing them toward the host relay thread
    /// - draining bytes received from the host relay thread and writing them
    ///   back into the smoltcp socket
    /// - interpreting relay exit state into guest-side `close()` or `abort()`
    pub fn relay_data(&mut self, sockets: &mut SocketSet<'_>) {
        let mut read_buffer = [0u8; RELAY_BUFFER_BYTES];

        for (&handle, connection) in &mut self.connections {
            if !connection.relay_spawned {
                continue;
            }

            let socket = sockets.get_mut::<tcp::Socket>(handle);

            match connection.exit_state.load() {
                RelayExitMode::Abort => {
                    socket.abort();
                    continue;
                }
                RelayExitMode::Graceful => {
                    flush_proxy_data(socket, connection);
                    if connection.buffered_proxy_data.is_none() {
                        socket.close();
                    } else {
                        connection.close_attempts += 1;
                        if connection.close_attempts >= CLOSE_RETRY_LIMIT {
                            socket.abort();
                        }
                    }
                    continue;
                }
                RelayExitMode::Running => {}
            }

            while socket.can_recv() {
                match socket.recv_slice(&mut read_buffer) {
                    Ok(bytes_read) if bytes_read > 0 => {
                        let payload = read_buffer[..bytes_read].to_vec();
                        if connection.to_proxy.try_send(payload).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }

            flush_proxy_data(socket, connection);
        }
    }

    /// Collect connections that reached ESTABLISHED and need a host relay thread.
    ///
    /// The separation between `create_tcp_socket` and this method is important:
    /// the guest TCP handshake is accepted first on the smoltcp side, and only
    /// once that succeeds do we commit to opening the host-side `TcpStream`.
    pub fn take_new_connections(&mut self, sockets: &mut SocketSet<'_>) -> Vec<NewTcpConnection> {
        let mut new_connections = Vec::new();

        for (&handle, connection) in &mut self.connections {
            if connection.relay_spawned {
                continue;
            }

            let socket = sockets.get::<tcp::Socket>(handle);
            if socket.state() == tcp::State::Established {
                connection.relay_spawned = true;

                if let Some(endpoints) = connection.pending_proxy_endpoints.take() {
                    new_connections.push(NewTcpConnection {
                        destination: connection.destination,
                        relay_target: endpoints.relay_target,
                        from_smoltcp: endpoints.from_smoltcp,
                        to_smoltcp: endpoints.to_smoltcp,
                        exit_state: connection.exit_state.clone(),
                    });
                }
            }
        }

        new_connections
    }

    /// Remove closed sockets and drop their relay endpoints.
    ///
    /// This is the final ownership cleanup step for a guest TCP flow.
    pub fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        let keys = &mut self.connection_keys;
        let published_ports = &mut self.used_published_ports;
        self.connections.retain(|&handle, connection| {
            let socket = sockets.get::<tcp::Socket>(handle);
            if socket.state() == tcp::State::Closed {
                keys.remove(&(connection.source, connection.destination));
                if let Some(port) = connection.reserved_published_port {
                    published_ports.remove(&port);
                }
                sockets.remove(handle);
                false
            } else {
                true
            }
        });
    }

    fn allocate_published_port(&mut self) -> Option<u16> {
        let start = self.next_published_port;

        loop {
            let candidate = self.next_published_port;
            self.next_published_port = if candidate == PUBLISHED_PORT_END {
                PUBLISHED_PORT_START
            } else {
                candidate + 1
            };

            if self.used_published_ports.insert(candidate) {
                return Some(candidate);
            }

            if self.next_published_port == start {
                return None;
            }
        }
    }
}

/// Spawn one host TCP relay thread for an established guest connection.
///
/// Thread responsibilities:
/// - connect a host `TcpStream` to the guest-requested destination
/// - copy bytes guest->host from `from_smoltcp`
/// - copy bytes host->guest into `to_smoltcp`
/// - wake the poll loop when host->guest data arrives
/// - report termination mode through `exit_state`
pub fn spawn_tcp_relay(
    destination: SocketAddr,
    relay_target: RelayTarget,
    from_smoltcp: Receiver<Vec<u8>>,
    to_smoltcp: SyncSender<Vec<u8>>,
    relay_wake: Arc<WakePipe>,
    exit_state: RelayExitState,
) {
    let thread_name = format!("smolvm-tcp-{}", destination.port());
    virtio_net_log!(
        "virtio-net: spawning host TCP relay thread destination={} thread={}",
        destination,
        thread_name
    );
    let _ = thread::Builder::new().name(thread_name).spawn(move || {
        run_tcp_relay(
            destination,
            relay_target,
            from_smoltcp,
            to_smoltcp,
            relay_wake,
            exit_state,
        )
    });
}

fn run_tcp_relay(
    destination: SocketAddr,
    relay_target: RelayTarget,
    from_smoltcp: Receiver<Vec<u8>>,
    to_smoltcp: SyncSender<Vec<u8>>,
    relay_wake: Arc<WakePipe>,
    exit_state: RelayExitState,
) {
    // The relay thread is intentionally isolated from smoltcp internals. Its
    // contract is just channels in, channels out, and an exit code back.
    virtio_net_log!(
        "virtio-net: host TCP relay thread started destination={}",
        destination
    );
    match tcp_relay_loop(
        destination,
        relay_target,
        from_smoltcp,
        to_smoltcp,
        relay_wake,
    ) {
        Ok(mode) => {
            virtio_net_log!(
                "virtio-net: host TCP relay thread exited destination={} mode={:?}",
                destination,
                mode
            );
            exit_state.store(mode)
        }
        Err(err) => {
            virtio_net_log!(
                "virtio-net: host TCP relay failed destination={} error={}",
                destination,
                err
            );
            exit_state.store(RelayExitMode::Abort);
        }
    }
}

fn tcp_relay_loop(
    destination: SocketAddr,
    relay_target: RelayTarget,
    from_smoltcp: Receiver<Vec<u8>>,
    to_smoltcp: SyncSender<Vec<u8>>,
    relay_wake: Arc<WakePipe>,
) -> io::Result<RelayExitMode> {
    // Host-side flow:
    //
    // 1. Connect a normal host TcpStream to the destination.
    // 2. Non-blockingly drain guest payloads from the channel into the socket.
    // 3. Non-blockingly read remote payloads from the socket into the channel.
    // 4. If neither side made progress, sleep briefly to avoid a hot spin loop.
    let mut stream = match relay_target {
        RelayTarget::Connect(destination) => {
            virtio_net_log!(
                "virtio-net: connecting host TCP relay socket destination={}",
                destination
            );
            let stream = TcpStream::connect(destination)?;
            virtio_net_log!(
                "virtio-net: host TCP relay socket connected destination={}",
                destination
            );
            stream
        }
        RelayTarget::Attached(stream) => {
            virtio_net_log!(
                "virtio-net: using accepted host TCP socket for published port guest_destination={} peer_addr={:?} local_addr={:?}",
                destination,
                stream.peer_addr().ok(),
                stream.local_addr().ok()
            );
            stream
        }
    };
    stream.set_nonblocking(true)?;

    let mut guest_write_closed = false;
    let mut read_buffer = [0u8; RELAY_BUFFER_BYTES];

    loop {
        let mut did_work = false;

        loop {
            match from_smoltcp.try_recv() {
                Ok(payload) => {
                    stream.write_all(&payload)?;
                    did_work = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The guest side closed its write half. Mirror that toward
                    // the remote peer once, then keep reading until the remote
                    // side closes too.
                    if !guest_write_closed {
                        let _ = stream.shutdown(Shutdown::Write);
                        guest_write_closed = true;
                    }
                    break;
                }
            }
        }

        match stream.read(&mut read_buffer) {
            Ok(0) => return Ok(RelayExitMode::Graceful),
            Ok(bytes_read) => {
                if to_smoltcp.send(read_buffer[..bytes_read].to_vec()).is_err() {
                    return Ok(RelayExitMode::Graceful);
                }
                relay_wake.wake();
                did_work = true;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }

        if !did_work {
            thread::sleep(PROXY_IDLE_SLEEP);
        }
    }
}

fn flush_proxy_data(socket: &mut tcp::Socket<'_>, connection: &mut TrackedConnection) {
    // smoltcp send windows may accept only part of an inbound host payload.
    // `buffered_proxy_data` remembers the unwritten remainder so the next poll
    // iteration can continue where it left off instead of dropping bytes.
    if let Some((data, offset)) = &mut connection.buffered_proxy_data {
        if socket.can_send() {
            match socket.send_slice(&data[*offset..]) {
                Ok(written) => {
                    *offset += written;
                    if *offset >= data.len() {
                        connection.buffered_proxy_data = None;
                    }
                }
                Err(_) => return,
            }
        } else {
            return;
        }
    }

    while connection.buffered_proxy_data.is_none() {
        match connection.from_proxy.try_recv() {
            Ok(payload) => {
                if socket.can_send() {
                    match socket.send_slice(&payload) {
                        Ok(written) if written < payload.len() => {
                            connection.buffered_proxy_data = Some((payload, written));
                        }
                        Err(_) => {
                            connection.buffered_proxy_data = Some((payload, 0));
                        }
                        _ => {}
                    }
                } else {
                    connection.buffered_proxy_data = Some((payload, 0));
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
}
