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

use crate::policy::PolicyHandle;
use crate::queues::WakePipe;
use crate::virtio_net_log;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpListenEndpoint;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
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
    /// Outbound allow-list applied before opening a host connection for a
    /// guest-initiated flow. Inbound published-port connections bypass it.
    egress: PolicyHandle,
    /// The guest-visible gateway addresses (IPv4/IPv6/link-local). A guest flow
    /// destined to one of these is dialing "the host" via its default gateway,
    /// so the host-side relay connects to loopback instead of the gateway's own
    /// (non-routable) userspace address. See `host_connect_addr`.
    gateway_ips: Vec<IpAddr>,
    /// One authenticated smolvm-owned loopback service allowed through the
    /// otherwise-denied gateway address.
    host_service: Option<crate::GatewayHostService>,
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
    to_proxy: Option<SyncSender<Vec<u8>>>,

    // host -> guest relay payloads
    from_proxy: Receiver<Vec<u8>>,
    // endpoints are held here until the guest-side handshake completes
    pending_proxy_endpoints: Option<PendingProxyEndpoints>,
    // once true, a dedicated host relay thread exists
    relay_spawned: bool,
    // partial guest->host payload already consumed from smoltcp but not yet
    // accepted by the relay thread channel
    buffered_guest_data: Option<Vec<u8>>,
    // partial host->guest payload not yet fully accepted by smoltcp
    buffered_proxy_data: Option<(Vec<u8>, usize)>,
    // bounded retry count for closing with unsent buffered data
    close_attempts: u16,
    // set once we've sent FIN to the guest after the host half-closed, so the
    // HalfClosed handling closes the guest send-half exactly once
    guest_send_closed: bool,
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
/// - `Graceful`   -> close guest socket cleanly
/// - `HalfClosed` -> host closed its send half; send FIN to the guest but keep
///   the guest socket open so guest->host output still drains
/// - `Abort`      -> abort/reset guest socket
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
    /// Host closed its send half (host-read EOF) but the guest may still be
    /// sending. Mirror the FIN toward the guest and keep pumping guest->host
    /// until the guest closes too. Without this a hijacked-attach response is
    /// dropped: the docker CLI half-closes (`shutdown(SHUT_WR)`) after
    /// `101 UPGRADED` when it has no stdin, while the daemon is still streaming.
    HalfClosed = 3,
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
            3 => RelayExitMode::HalfClosed,
            _ => RelayExitMode::Running,
        }
    }

    fn store(&self, mode: RelayExitMode) {
        self.inner.store(mode as u8, Ordering::Relaxed);
    }
}

impl TcpRelayTable {
    /// Create a new relay table.
    pub fn new(
        max_connections: Option<usize>,
        egress: PolicyHandle,
        gateway_ips: Vec<IpAddr>,
        host_service: Option<crate::GatewayHostService>,
    ) -> Self {
        Self {
            connections: HashMap::new(),
            connection_keys: HashSet::new(),
            used_published_ports: HashSet::new(),
            next_published_port: PUBLISHED_PORT_START,
            max_connections: max_connections.unwrap_or(MAX_CONNECTIONS),
            egress,
            gateway_ips,
            host_service,
        }
    }

    fn destination_allowed(&self, destination: SocketAddr) -> bool {
        self.egress.allows(destination.ip(), Some(destination.port()))
            || (self
                .host_service
                .is_some_and(|service| service.guest_port == destination.port())
                && self.gateway_ips.contains(&destination.ip()))
    }

    /// The host-side address the relay should dial for a guest flow.
    ///
    /// The guest's default gateway IP is its stand-in for "the host" (the slirp /
    /// `host.docker.internal` convention): a guest reaches host-local services by
    /// connecting to its gateway. But that gateway IP is THIS userspace stack's
    /// own address, not a routable host interface — a literal relay to it
    /// blackholes (the guest completes the smoltcp handshake, then never receives
    /// reply bytes). Map a gateway-IP destination to loopback so it actually
    /// reaches the host; every other destination is dialed as-is. Egress already
    /// gated the ORIGINAL destination in `create_tcp_socket`, so under the
    /// multi-tenant `Strict` floor the gateway/CGNAT range is refused before it
    /// reaches here — this redirect only applies where reaching the host is the
    /// intended, local-default behavior.
    fn host_connect_addr(&self, destination: SocketAddr) -> SocketAddr {
        if let Some(ip) = self.egress.rewrite(destination.ip()) {
            return SocketAddr::new(ip, destination.port());
        }
        if self.gateway_ips.contains(&destination.ip()) {
            let loopback = if destination.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            let port = self
                .host_service
                .filter(|service| service.guest_port == destination.port())
                .map_or(destination.port(), |service| service.host_port);
            return SocketAddr::new(loopback, port);
        }
        destination
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

        // Egress policy: drop the guest SYN before any socket is created when the
        // destination isn't allowed, so the guest just sees the connection fail.
        // Inbound published-port flows take a separate path and are unaffected.
        if !self.destination_allowed(destination) {
            tracing::debug!(
                %destination,
                "virtio-net: blocking outbound connection by egress policy"
            );
            // Recorded in the machine's egress audit trail (dedicated file +
            // stderr) — parsed by the host's `read_egress_denials`.
            self.egress
                .denied("connect", &format_args!("to {destination}"));
            return false;
        }

        let rx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER_BYTES]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER_BYTES]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

        let listen_endpoint = IpListenEndpoint {
            addr: Some(destination.ip().into()),
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
                to_proxy: Some(to_proxy_tx),
                from_proxy: from_proxy_rx,

                pending_proxy_endpoints: Some(PendingProxyEndpoints {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                    relay_target: RelayTarget::Connect(self.host_connect_addr(destination)),
                }),
                relay_spawned: false,
                buffered_guest_data: None,
                buffered_proxy_data: None,
                close_attempts: 0,
                guest_send_closed: false,
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

        // Inbound published connections always target the guest's IPv4 on the
        // internal link (the host listener family is independent of this).
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
                to_proxy: Some(to_proxy_tx),
                from_proxy: from_proxy_rx,

                pending_proxy_endpoints: Some(PendingProxyEndpoints {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                    relay_target: RelayTarget::Attached(host_stream),
                }),
                relay_spawned: false,
                buffered_guest_data: None,
                buffered_proxy_data: None,
                close_attempts: 0,
                guest_send_closed: false,
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
                RelayExitMode::HalfClosed => {
                    // Host closed its send half: flush any remaining host->guest
                    // bytes, then send FIN to the guest exactly once. Crucially
                    // we do NOT `continue` — fall through to the guest->host
                    // drain below so the guest's in-flight response still
                    // reaches the host. The thread flips to Graceful once the
                    // guest closes too, and the connection is torn down then.
                    flush_proxy_data(socket, connection);
                    if connection.buffered_proxy_data.is_none() && !connection.guest_send_closed {
                        socket.close();
                        connection.guest_send_closed = true;
                    }
                }
                RelayExitMode::Running => {}
            }

            flush_guest_data(connection);
            while connection.buffered_guest_data.is_none() && socket.can_recv() {
                match socket.recv_slice(&mut read_buffer) {
                    Ok(bytes_read) if bytes_read > 0 => {
                        let payload = read_buffer[..bytes_read].to_vec();
                        if !send_guest_payload(connection, payload) {
                            break;
                        }
                    }
                    _ => break,
                }
            }

            if connection.buffered_guest_data.is_none() && !socket.may_recv() {
                connection.to_proxy = None;
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
            let state = socket.state();
            if state == tcp::State::Established || state == tcp::State::CloseWait {
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
    ///
    /// An aborted socket reaches `Closed` synchronously, but its RST is only
    /// emitted on the next interface dispatch — and smoltcp clears the
    /// endpoint tuple right after sending it. Reaping on `Closed` alone
    /// therefore destroys the queued RST and the guest never learns the
    /// connection died (it hangs until its own timeout, which is how a failed
    /// host-side connect used to black-hole every unreachable destination).
    /// Wait for `remote_endpoint()` to clear so the RST is on the wire first.
    pub fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        let keys = &mut self.connection_keys;
        let published_ports = &mut self.used_published_ports;
        self.connections.retain(|&handle, connection| {
            let socket = sockets.get::<tcp::Socket>(handle);
            if socket.state() == tcp::State::Closed && socket.remote_endpoint().is_none() {
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
/// - wake the poll loop when host->guest data arrives or guest->host backpressure eases
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
        &exit_state,
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
    exit_state: &RelayExitState,
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
    let mut guest_channel_closed = false;
    let mut host_read_closed = false;
    let mut pending_guest_data: Option<(Vec<u8>, usize)> = None;
    let mut read_buffer = [0u8; RELAY_BUFFER_BYTES];

    loop {
        let mut did_work = false;

        if pending_guest_data.is_none() && !guest_channel_closed {
            match from_smoltcp.try_recv() {
                Ok(payload) => {
                    pending_guest_data = Some((payload, 0));
                    // Consuming from the bounded guest->host channel may free
                    // capacity for a payload buffered in the smoltcp poll
                    // thread. Wake it so backpressure clears promptly even for
                    // one-way guest->host streams.
                    relay_wake.wake();
                    did_work = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    guest_channel_closed = true;
                }
            }
        }

        if let Some((payload, offset)) = &mut pending_guest_data {
            while *offset < payload.len() {
                match stream.write(&payload[*offset..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "host TCP relay wrote zero bytes",
                        ));
                    }
                    Ok(bytes_written) => {
                        *offset += bytes_written;
                        did_work = true;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err),
                }
            }

            if *offset >= payload.len() {
                pending_guest_data = None;
            }
        }

        if guest_channel_closed && pending_guest_data.is_none() && !guest_write_closed {
            // The guest side closed its write half. Mirror that toward the
            // remote peer only after all buffered guest bytes were written.
            let _ = stream.shutdown(Shutdown::Write);
            guest_write_closed = true;
        }

        // Both directions are done — the host stopped sending (host_read_closed)
        // and the guest stopped sending and was fully flushed. Finish with a
        // clean close; the poll loop tears the guest socket down.
        if host_read_closed && guest_channel_closed && pending_guest_data.is_none() {
            return Ok(RelayExitMode::Graceful);
        }

        // host -> guest, only while the host's send half is still open. On host
        // read-EOF we do NOT tear the relay down: signal HalfClosed so the poll
        // loop mirrors the FIN to the guest, then keep draining guest->host. A
        // hijacked docker attach half-closes here (`shutdown(SHUT_WR)` with no
        // stdin) while the daemon is still streaming its response back.
        if !host_read_closed {
            match stream.read(&mut read_buffer) {
                Ok(0) => {
                    host_read_closed = true;
                    exit_state.store(RelayExitMode::HalfClosed);
                    relay_wake.wake();
                    did_work = true;
                }
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
        }

        if !did_work {
            thread::sleep(PROXY_IDLE_SLEEP);
        }
    }
}

fn flush_guest_data(connection: &mut TrackedConnection) {
    let Some(payload) = connection.buffered_guest_data.take() else {
        return;
    };
    send_guest_payload(connection, payload);
}

fn send_guest_payload(connection: &mut TrackedConnection, payload: Vec<u8>) -> bool {
    let Some(to_proxy) = &connection.to_proxy else {
        return false;
    };
    match to_proxy.try_send(payload) {
        Ok(()) => true,
        Err(TrySendError::Full(payload)) => {
            connection.buffered_guest_data = Some(payload);
            false
        }
        Err(TrySendError::Disconnected(_)) => {
            connection.to_proxy = None;
            false
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection(to_proxy: SyncSender<Vec<u8>>) -> TrackedConnection {
        let (_from_proxy_tx, from_proxy) = mpsc::sync_channel(CHANNEL_CAPACITY);
        TrackedConnection {
            source: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12_345),
            destination: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 80),
            to_proxy: Some(to_proxy),
            from_proxy,
            pending_proxy_endpoints: None,
            relay_spawned: true,
            buffered_guest_data: None,
            buffered_proxy_data: None,
            close_attempts: 0,
            guest_send_closed: false,
            exit_state: RelayExitState::new(),
            reserved_published_port: None,
        }
    }

    #[test]
    fn guest_payload_is_buffered_when_relay_channel_is_full() {
        let (to_proxy, from_smoltcp) = mpsc::sync_channel(1);
        to_proxy.send(vec![1]).unwrap();
        let mut connection = test_connection(to_proxy);

        assert!(!send_guest_payload(&mut connection, vec![2]));
        assert_eq!(connection.buffered_guest_data.as_deref(), Some(&[2][..]));

        assert_eq!(from_smoltcp.recv().unwrap(), vec![1]);
        flush_guest_data(&mut connection);

        assert!(connection.buffered_guest_data.is_none());
        assert_eq!(from_smoltcp.recv().unwrap(), vec![2]);
    }

    #[test]
    fn gateway_ip_destination_dials_the_host_over_loopback() {
        let gw4: IpAddr = "100.96.0.1".parse().unwrap();
        let gw6: IpAddr = "fd00::1".parse().unwrap();
        let table = TcpRelayTable::new(
            None,
            Arc::new(crate::egress::EgressPolicy::unrestricted()),
            vec![gw4, gw6],
            None,
        );

        // A guest reaching "the host" via its gateway IP must dial loopback, not
        // the gateway's own (non-routable) userspace address — the bug that made
        // the handshake succeed but blackholed the reply. Port is preserved.
        assert_eq!(
            table.host_connect_addr(SocketAddr::new(gw4, 19997)),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 19997),
        );
        assert_eq!(
            table.host_connect_addr(SocketAddr::new(gw6, 6379)),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 6379),
        );

        // A non-gateway destination (external host / the host's LAN IP) is dialed
        // unchanged.
        let lan: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(
            table.host_connect_addr(SocketAddr::new(lan, 3306)),
            SocketAddr::new(lan, 3306),
        );
    }

    /// A policy that publishes one stand-in address and keeps the real
    /// destination to itself.
    struct StandinPolicy;

    /// RFC 5737 TEST-NET-1: never a real destination.
    const STANDIN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const REAL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

    impl crate::policy::Policy for StandinPolicy {
        fn allows(&self, _ip: IpAddr, _port: Option<u16>) -> bool {
            true
        }

        fn rewrite(&self, ip: IpAddr) -> Option<IpAddr> {
            (ip == STANDIN).then_some(REAL)
        }
    }

    #[test]
    fn a_policy_rewrite_takes_precedence_over_the_gateway_ip_redirect() {
        let gw: IpAddr = "100.96.0.1".parse().unwrap();
        let table = TcpRelayTable::new(None, Arc::new(StandinPolicy), vec![gw], None);

        // The policy gets first say: its stand-in is dialed as what it stands
        // for, with the port the guest asked for.
        assert_eq!(
            table.host_connect_addr(SocketAddr::new(STANDIN, 5432)),
            SocketAddr::new(REAL, 5432),
        );
        // The gateway-IP redirect still covers everything the policy leaves
        // alone, so the two mechanisms do not shadow each other.
        assert_eq!(
            table.host_connect_addr(SocketAddr::new(gw, 8080)),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080),
        );
        // ...and an ordinary destination is dialed unchanged.
        let public: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(
            table.host_connect_addr(SocketAddr::new(public, 443)),
            SocketAddr::new(public, 443),
        );
    }

    /// The port reaches the policy, and a denial happens before any host socket
    /// exists. Per-port grants are the thing the built-in policy cannot express,
    /// so this is the plumbing an embedder actually plugs in for.
    #[test]
    fn a_custom_policy_gates_the_syn_by_port() {
        struct OnlyHttps;

        impl crate::policy::Policy for OnlyHttps {
            fn allows(&self, _ip: IpAddr, port: Option<u16>) -> bool {
                port == Some(443)
            }
        }

        let mut table = TcpRelayTable::new(None, Arc::new(OnlyHttps), vec![], None);
        let mut sockets = SocketSet::new(vec![]);
        let source: SocketAddr = "100.96.0.2:40000".parse().unwrap();
        let dst = |port| SocketAddr::new("1.1.1.1".parse().unwrap(), port);

        // A port the policy grants gets a guest-facing socket and a relay entry.
        assert!(table.create_tcp_socket(source, dst(443), &mut sockets));
        assert!(table.has_socket_for(&source, &dst(443)));

        // One it does not is dropped outright — no socket, no entry, and the
        // guest just sees the connection fail.
        assert!(!table.create_tcp_socket(source, dst(80), &mut sockets));
        assert!(!table.has_socket_for(&source, &dst(80)));
    }

    #[test]
    fn dedicated_gateway_service_does_not_weaken_other_egress() {
        let gateway: IpAddr = "100.96.0.1".parse().unwrap();
        let external: IpAddr = "8.8.8.8".parse().unwrap();
        let table = TcpRelayTable::new(
            None,
            Arc::new(crate::egress::EgressPolicy::from_allowed_cidrs(Some(&[]))),
            vec![gateway],
            Some(crate::GatewayHostService {
                guest_port: 10_081,
                host_port: 40_081,
            }),
        );

        assert!(table.destination_allowed(SocketAddr::new(gateway, 10_081)));
        assert!(!table.destination_allowed(SocketAddr::new(gateway, 22)));
        assert!(!table.destination_allowed(SocketAddr::new(external, 10_081)));
        assert_eq!(
            table.host_connect_addr(SocketAddr::new(gateway, 10_081)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_081)
        );
    }

    #[test]
    fn guest_fin_drops_to_proxy_channel() {
        let (to_proxy, from_smoltcp) = mpsc::sync_channel(1);
        let connection = test_connection(to_proxy);
        let rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        // A closed or FIN-received socket has may_recv() == false
        assert!(!socket.may_recv());

        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);

        let mut table = TcpRelayTable::new(
            None,
            std::sync::Arc::new(crate::EgressPolicy::unrestricted()),
            vec![],
            None,
        );
        table.connections.insert(handle, connection);

        table.relay_data(&mut sockets);

        // to_proxy in the connection must have been dropped (set to None)
        assert!(table.connections.get(&handle).unwrap().to_proxy.is_none());
        // The receiver on the relay thread side must see Disconnected
        assert_eq!(from_smoltcp.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn tcp_relay_loop_handles_guest_write_shutdown_cleanly() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let (from_smoltcp_tx, from_smoltcp_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (to_smoltcp_tx, _to_smoltcp_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let wake_pipe = Arc::new(WakePipe::new());
        let exit_state = RelayExitState::new();

        // Send a payload then drop from_smoltcp_tx (simulating guest FIN)
        from_smoltcp_tx.send(b"hello server".to_vec()).unwrap();
        drop(from_smoltcp_tx);

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"hello server");
            // Server should now read EOF (0 bytes) because client shut down write half
            let eof = stream.read(&mut buf).unwrap();
            assert_eq!(eof, 0);
            drop(stream);
        });

        let relay_exit = tcp_relay_loop(
            server_addr,
            RelayTarget::Connect(server_addr),
            from_smoltcp_rx,
            to_smoltcp_tx,
            wake_pipe,
            &exit_state,
        )
        .unwrap();

        assert_eq!(relay_exit, RelayExitMode::Graceful);
        server_thread.join().unwrap();
    }

    #[test]
    fn aborted_connection_sends_rst_to_the_guest_before_cleanup() {
        use smoltcp::iface::{Config, Interface};
        use smoltcp::phy::{Loopback, Medium};
        use smoltcp::time::Instant;
        use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

        let mut device = Loopback::new(Medium::Ethernet);
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress([
                0x02, 0, 0, 0, 0, 1,
            ]))),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(100, 96, 0, 1), 30))
                .unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(100, 96, 0, 1))
            .unwrap();
        // Same as the production interface: accept flows to arbitrary
        // destinations so the relay's listen sockets can intercept them.
        interface.set_any_ip(true);

        let mut sockets = SocketSet::new(vec![]);
        let mut table = TcpRelayTable::new(
            None,
            std::sync::Arc::new(crate::EgressPolicy::unrestricted()),
            vec![],
            None,
        );

        // The "guest" dials an external destination; the relay pre-creates the
        // intercepting listen socket exactly like the poll loop does on SYN.
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)), 40_000);
        assert!(table.create_tcp_socket(source, destination, &mut sockets));

        // Guest stand-in: a client socket running a real handshake against the
        // intercepting socket over the loopback device.
        let client_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 4096]),
            tcp::SocketBuffer::new(vec![0u8; 4096]),
        ));
        sockets
            .get_mut::<tcp::Socket>(client_handle)
            .connect(
                interface.context(),
                (IpAddress::v4(192, 0, 2, 10), 443),
                40_000,
            )
            .unwrap();

        let mut now_ms: i64 = 0;
        let poll = |interface: &mut Interface,
                    device: &mut Loopback,
                    sockets: &mut SocketSet<'_>,
                    now_ms: &mut i64| {
            *now_ms += 10;
            interface.poll(Instant::from_millis(*now_ms), device, sockets);
        };

        for _ in 0..10 {
            poll(&mut interface, &mut device, &mut sockets, &mut now_ms);
            if sockets.get::<tcp::Socket>(client_handle).state() == tcp::State::Established {
                break;
            }
        }
        assert_eq!(
            sockets.get::<tcp::Socket>(client_handle).state(),
            tcp::State::Established,
            "handshake must complete before the abort is simulated"
        );

        // The host-side connect failed: the relay thread reports Abort. (The
        // intercepting socket trails the client by the final ACK, so poll until
        // the table observes it as Established.)
        let mut new_connections = Vec::new();
        for _ in 0..10 {
            poll(&mut interface, &mut device, &mut sockets, &mut now_ms);
            new_connections = table.take_new_connections(&mut sockets);
            if !new_connections.is_empty() {
                break;
            }
        }
        assert_eq!(new_connections.len(), 1);
        new_connections[0].exit_state.store(RelayExitMode::Abort);

        // Poll-loop order under test: relay_data (abort) then cleanup_closed
        // BEFORE the next egress flush. The aborted socket must survive cleanup
        // with its RST still queued, or the guest never learns and hangs until
        // its own timeout.
        table.relay_data(&mut sockets);
        table.cleanup_closed(&mut sockets);
        assert!(
            table.has_socket_for(&source, &destination),
            "aborted socket was reaped before its RST was dispatched"
        );

        // The next flushes deliver the RST; the guest-side socket must observe
        // the reset instead of staying Established.
        for _ in 0..10 {
            poll(&mut interface, &mut device, &mut sockets, &mut now_ms);
            if sockets.get::<tcp::Socket>(client_handle).state() == tcp::State::Closed {
                break;
            }
        }
        assert_eq!(
            sockets.get::<tcp::Socket>(client_handle).state(),
            tcp::State::Closed,
            "guest never received the RST for the aborted connection"
        );

        // With the RST on the wire the connection is finally reaped.
        table.cleanup_closed(&mut sockets);
        assert!(!table.has_socket_for(&source, &destination));
    }
}
