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

use crate::egress::EgressPolicy;
use crate::queues::WakePipe;
use crate::tcp_reactor::{RelayReactor, RelayWaker};
use crate::virtio_net_log;
use polling::{Event, Events};
use smoltcp::iface::{Interface, PollIngressSingleResult, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::Device;
use smoltcp::socket::tcp;
use smoltcp::wire::IpListenEndpoint;
use smolvm_protocol::mediated_egress::{Decision, FlowPrelude, MAX_INITIAL_BYTES};
use smolvm_protocol::{FlowTransport, RuleAction};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const TCP_RX_BUFFER_BYTES: usize = 64 * 1024;
const TCP_TX_BUFFER_BYTES: usize = 64 * 1024;
/// Concurrent guest TCP flows one machine may hold by default: a whole
/// ephemeral port range's worth, so a guest is limited by its own kernel the
/// way a hosted CI runner is, not by the relay. `SMOLVM_TCP_RELAY_CAPACITY`
/// overrides it.
pub(crate) const MAX_CONNECTIONS: usize = 65_536;
/// Flows beyond this many open at once get smaller guest-facing buffers, so a
/// guest holding tens of thousands of mostly idle connections costs the host
/// a quarter of the memory per flow. 16 KiB still moves hundreds of MB/s on a
/// link whose round trip is microseconds.
const FULL_BUFFER_CONNECTIONS: usize = 1024;
const TCP_SMALL_BUFFER_BYTES: usize = 16 * 1024;
/// Once the guest has closed its side and the relay waits on the remote,
/// probe the guest this often: a guest that already forgot the socket answers
/// with a reset, which frees the flow even if the remote never closes.
const GUEST_CLOSED_KEEPALIVE: Duration = Duration::from_secs(60);
/// The shortest gap between two "relay table is full" warnings.
const FULL_WARNING_INTERVAL: Duration = Duration::from_secs(10);
const CHANNEL_CAPACITY: usize = 32;
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
const CLOSE_RETRY_LIMIT: u16 = 64;
/// The longest an idle relay thread waits before rechecking both directions
/// on its own. Every way a direction gains work wakes it sooner: the host
/// socket turning readable or writable, and the poll loop handing it a guest
/// payload or closing the guest side. This only bounds the cost of a missed
/// wake.
const RELAY_WAIT_BACKSTOP: Duration = Duration::from_millis(100);
/// The relay thread's key for its host socket in its own poller.
const HOST_STREAM_KEY: usize = 0;
const FIRST_PAYLOAD_HOLD: Duration = Duration::from_millis(100);
const MEDIATED_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MEDIATED_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MEDIATED_MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const PUBLISHED_PORT_START: u16 = 49_152;
const PUBLISHED_PORT_END: u16 = 65_535;

/// Track all active guest TCP connections bridged through host sockets.
///
/// One entry corresponds to one `(guest endpoint, peer endpoint)` tuple. The
/// table lives in the smoltcp poll thread and owns every guest-facing socket.
///
/// Each flow keeps its smoltcp socket in a socket set of its own. smoltcp
/// finds the socket for an incoming segment, and asks every socket whether it
/// has something to send, by walking the whole set, so one set holding every
/// flow made each guest packet cost time in proportion to the connections
/// open: with two thousand idle connections a single download fell from
/// 600 MB/s to 40. The poll loop instead routes each segment to its flow's
/// set by its addresses and services only the flows that have work: those a
/// segment reached, those whose relay reported progress, and those whose
/// smoltcp timer is due.
pub struct TcpRelayTable {
    connections: HashMap<u64, TrackedConnection>,
    /// Flow by `(guest endpoint, peer endpoint)`.
    by_tuple: HashMap<(SocketAddr, SocketAddr), u64>,
    /// Flows to service on the next pass.
    touched: Vec<u64>,
    /// Flows' next smoltcp timer, earliest first, in milliseconds of the poll
    /// loop's clock. Entries whose time no longer matches the flow's
    /// `next_poll` are stale and skipped.
    timers: BinaryHeap<Reverse<(i64, u64)>>,
    /// Flows whose relay reported progress since the last pass.
    poll_queue: Arc<PollQueue>,
    used_published_ports: HashSet<u16>,
    next_published_port: u16,
    max_connections: usize,
    /// Outbound allow-list applied before opening a host connection for a
    /// guest-initiated flow. Inbound published-port connections bypass it.
    egress: EgressPolicy,
    /// The guest-visible gateway addresses (IPv4/IPv6/link-local). A guest flow
    /// destined to one of these is dialing "the host" via its default gateway,
    /// so the host-side relay connects to loopback instead of the gateway's own
    /// (non-routable) userspace address. See `host_connect_addr`.
    gateway_ips: Vec<IpAddr>,
    /// One authenticated smolvm-owned loopback service allowed through the
    /// otherwise-denied gateway address.
    host_service: Option<crate::GatewayHostService>,
    /// Redirect selected streams after egress admits their real destination.
    /// `None` relays every flow directly.
    intercept: Option<crate::StreamInterception>,
    /// Guest ports already reported as refusing published connections, so a
    /// client retrying in a loop produces one warning rather than one per
    /// attempt.
    unaccepted_guest_ports: HashSet<u16>,
    /// Shared host-side relay that pumps every flow of this machine on one
    /// thread. `None` (tests) gives each flow its own relay thread.
    reactor: Option<RelayReactor>,
    /// Identifies a flow to the reactor.
    next_flow_id: u64,
    /// Connections refused because the table was full, and when that was
    /// last reported, so a guest hammering a full table logs one line per
    /// interval rather than one per attempt.
    refused_full: u64,
    refused_full_reported: u64,
    last_full_warning: Option<Instant>,
}

/// Open TCP flows of one machine at a point in time. Outbound flows are the
/// guest's own connections; inbound ones arrived on a published port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowSummary {
    /// Open guest-initiated flows.
    pub outbound_open: u32,
    /// Open published-port flows.
    pub inbound_open: u32,
    /// Distinct destination IPs among the outbound flows.
    pub distinct_outbound_peers: u32,
    /// Age in seconds of the longest-lived open outbound flow, 0 when none.
    pub oldest_outbound_secs: u64,
    /// Destination of the longest-lived open outbound flow.
    pub oldest_outbound_dest: Option<SocketAddr>,
}

/// Summarize `(destination, inbound, opened_at)` flow entries as of `now`.
fn summarize_flows(
    flows: impl Iterator<Item = (SocketAddr, bool, Instant)>,
    now: Instant,
) -> FlowSummary {
    let mut summary = FlowSummary::default();
    let mut peers = HashSet::new();
    let mut oldest: Option<(Instant, SocketAddr)> = None;
    for (destination, inbound, opened_at) in flows {
        if inbound {
            summary.inbound_open = summary.inbound_open.saturating_add(1);
            continue;
        }
        summary.outbound_open = summary.outbound_open.saturating_add(1);
        peers.insert(destination.ip());
        if oldest.is_none_or(|(at, _)| opened_at < at) {
            oldest = Some((opened_at, destination));
        }
    }
    summary.distinct_outbound_peers = u32::try_from(peers.len()).unwrap_or(u32::MAX);
    if let Some((at, destination)) = oldest {
        summary.oldest_outbound_secs = now.saturating_duration_since(at).as_secs();
        summary.oldest_outbound_dest = Some(destination);
    }
    summary
}

/// Destination port whose guest flows go through the credential interceptor.
pub const INTERCEPTED_PORT: u16 = 443;

/// Upper bound on the interceptor's own connect to the destination.
const INTERCEPT_VERDICT_TIMEOUT: Duration = Duration::from_secs(15);

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
    /// Wakes the relay when the poll loop hands it a guest payload or
    /// closes the guest side.
    pub proxy_wake: RelayWaker,
    /// The policy to show the guest's opening bytes to, for an outbound
    /// connection; `None` for a published port's inbound one.
    pub watch_opening: Option<EgressPolicy>,
}

#[derive(Debug)]
struct TrackedConnection {
    // the peer the guest dialed, or the guest endpoint of a published flow
    destination: SocketAddr,
    // guest -> host relay payloads
    to_proxy: Option<ToProxy>,

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
    // when the guest-side flow entered the table, for the flow summary
    opened_at: Instant,
    // wakes the host relay, e.g. after draining a host->guest channel it found full
    relay_waker: RelayWaker,
    // the flow's own smoltcp socket set and its one socket
    set: SocketSet<'static>,
    handle: SocketHandle,
    // `(guest endpoint, peer endpoint)`, the key in `by_tuple`
    key: (SocketAddr, SocketAddr),
    // when this flow's smoltcp timer is next due (ms), as queued in `timers`
    next_poll: Option<i64>,
    // keep-alive toward the guest was armed after the guest closed its side
    guest_closed_keepalive: bool,
}

impl Drop for TrackedConnection {
    fn drop(&mut self) {
        // The guest side is gone for good (closed or reset): let the relay
        // close the host socket now rather than wait on a remote that may
        // never close its side.
        self.exit_state.guest_gone.store(true, Ordering::Release);
        self.relay_waker.wake();
    }
}

#[derive(Debug)]
struct PendingProxyEndpoints {
    from_smoltcp: Receiver<Vec<u8>>,
    to_smoltcp: SyncSender<Vec<u8>>,
    relay_target: RelayTarget,
    proxy_wake: RelayWaker,
    watch_opening: Option<EgressPolicy>,
}

/// The poll loop's sending half of a guest->host channel. It wakes the relay
/// thread on every payload it hands over, and again once it is dropped, so a
/// relay waiting on its socket sees guest data and a guest close at once.
#[derive(Debug)]
struct ToProxy {
    sender: Option<SyncSender<Vec<u8>>>,
    wake: RelayWaker,
}

impl ToProxy {
    fn try_send(&self, payload: Vec<u8>) -> Result<(), TrySendError<Vec<u8>>> {
        let sender = self
            .sender
            .as_ref()
            .ok_or(TrySendError::Disconnected(Vec::new()))?;
        sender.try_send(payload)?;
        self.wake.wake();
        Ok(())
    }
}

impl Drop for ToProxy {
    fn drop(&mut self) {
        // Disconnect first, so the woken relay observes the closed channel.
        drop(self.sender.take());
        self.wake.wake();
    }
}

/// A guest->host channel whose sender wakes the relay through `wake`.
fn proxy_channel(wake: RelayWaker) -> (ToProxy, Receiver<Vec<u8>>, RelayWaker) {
    let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
    (
        ToProxy {
            sender: Some(sender),
            wake: wake.clone(),
        },
        receiver,
        wake,
    )
}

/// How a host-side TCP relay should obtain its remote socket.
#[derive(Debug)]
pub enum RelayTarget {
    /// Open a new outbound host `TcpStream` to the destination.
    Connect(SocketAddr),
    /// Static allow under mediation; still subject to mediated time limits.
    DirectMediated(SocketAddr),
    /// Use an already-accepted host `TcpStream` from a published port listener.
    Attached(TcpStream),
    /// Dial the credential interceptor and announce the guest's real
    /// destination in an authenticated preamble before relaying guest bytes.
    Intercept {
        endpoint: crate::InterceptEndpoint,
        destination: SocketAddr,
    },
    /// Ask a host decider before connecting to the origin or using its stream.
    Mediated {
        binding: crate::MediatedBinding,
        destination: SocketAddr,
        direct_address: SocketAddr,
        direct_allowed: bool,
        audit: EgressPolicy,
    },
}

impl RelayTarget {
    /// A flow under mediated egress, bounded by its idle and total lifetime.
    pub(crate) fn is_mediated(&self) -> bool {
        matches!(
            self,
            RelayTarget::Mediated { .. } | RelayTarget::DirectMediated(_)
        )
    }
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
    /// Set by the relay when the host->guest channel was full, so the poll
    /// loop wakes it once it has drained that channel.
    host_blocked: Arc<AtomicBool>,
    /// Set when the poll loop dropped the guest side of the flow (the guest
    /// closed or reset it): the host side then has no one left to talk to.
    guest_gone: Arc<AtomicBool>,
    /// Where to report this flow to the poll loop, and whether it is already
    /// queued there.
    poll: Option<(Arc<PollQueue>, u64)>,
    queued: Arc<AtomicBool>,
}

/// Flows whose host relay made progress the poll loop should act on: data
/// for the guest, room for more guest data, or an exit.
#[derive(Debug, Default)]
pub(crate) struct PollQueue {
    ids: Mutex<Vec<u64>>,
}

impl PollQueue {
    fn take(&self) -> Vec<u64> {
        self.ids
            .lock()
            .map(|mut ids| std::mem::take(&mut *ids))
            .unwrap_or_default()
    }
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
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(AtomicU8::new(RelayExitMode::Running as u8)),
            host_blocked: Arc::new(AtomicBool::new(false)),
            guest_gone: Arc::new(AtomicBool::new(false)),
            poll: None,
            queued: Arc::new(AtomicBool::new(false)),
        }
    }

    /// State for flow `id`, which reports its progress through `queue`.
    fn for_flow(queue: &Arc<PollQueue>, id: u64) -> Self {
        Self {
            poll: Some((queue.clone(), id)),
            ..Self::new()
        }
    }

    /// Tell the poll loop this flow has news for it, and wake it.
    pub(crate) fn notify(&self, relay_wake: &WakePipe) {
        if let Some((queue, id)) = &self.poll {
            if !self.queued.swap(true, Ordering::AcqRel) {
                if let Ok(mut ids) = queue.ids.lock() {
                    ids.push(*id);
                }
            }
        }
        relay_wake.wake();
    }

    pub(crate) fn load(&self) -> RelayExitMode {
        match self.inner.load(Ordering::Relaxed) {
            1 => RelayExitMode::Graceful,
            2 => RelayExitMode::Abort,
            3 => RelayExitMode::HalfClosed,
            _ => RelayExitMode::Running,
        }
    }

    /// What dropping the poll loop's entry for the flow does.
    #[cfg(test)]
    pub(crate) fn mark_guest_gone(&self) {
        self.guest_gone.store(true, Ordering::Release);
    }

    /// Set by the relay while the host->guest channel is full.
    #[cfg(test)]
    pub(crate) fn host_blocked_flag(&self) -> &AtomicBool {
        &self.host_blocked
    }

    pub(crate) fn store(&self, mode: RelayExitMode) {
        self.inner.store(mode as u8, Ordering::Relaxed);
    }
}

impl TcpRelayTable {
    /// Create a new relay table.
    pub fn new(
        max_connections: Option<usize>,
        egress: EgressPolicy,
        gateway_ips: Vec<IpAddr>,
        host_service: Option<crate::GatewayHostService>,
    ) -> Self {
        Self {
            connections: HashMap::new(),
            by_tuple: HashMap::new(),
            touched: Vec::new(),
            timers: BinaryHeap::new(),
            poll_queue: Arc::new(PollQueue::default()),
            used_published_ports: HashSet::new(),
            next_published_port: PUBLISHED_PORT_START,
            max_connections: max_connections.unwrap_or(MAX_CONNECTIONS),
            egress,
            gateway_ips,
            host_service,
            intercept: None,
            unaccepted_guest_ports: HashSet::new(),
            reactor: None,
            next_flow_id: 0,
            refused_full: 0,
            refused_full_reported: 0,
            last_full_warning: None,
        }
    }

    /// Pump every flow on `reactor` instead of a thread per flow.
    pub(crate) fn with_reactor(mut self, reactor: RelayReactor) -> Self {
        self.reactor = Some(reactor);
        self
    }

    /// Hand an established flow to its host relay: the shared reactor when
    /// there is one, otherwise a dedicated thread.
    pub(crate) fn start_relay(
        &self,
        connection: NewTcpConnection,
        relay_wake: Arc<WakePipe>,
    ) -> io::Result<()> {
        match &self.reactor {
            Some(reactor) => {
                reactor.adopt(connection);
                Ok(())
            }
            None => spawn_tcp_relay(connection, relay_wake),
        }
    }

    /// Number a new flow and make the waker for its relay.
    fn new_flow_id(&mut self) -> (u64, RelayWaker) {
        self.next_flow_id = self.next_flow_id.wrapping_add(1);
        let id = self.next_flow_id;
        let waker = match &self.reactor {
            Some(reactor) => reactor.waker(id),
            None => RelayWaker::standalone(),
        };
        (id, waker)
    }

    /// Guest-facing buffer size for the next flow: full size for the first
    /// [`FULL_BUFFER_CONNECTIONS`], smaller beyond.
    fn next_buffer_bytes(&self) -> (usize, usize) {
        if self.connections.len() < FULL_BUFFER_CONNECTIONS {
            (TCP_RX_BUFFER_BYTES, TCP_TX_BUFFER_BYTES)
        } else {
            (TCP_SMALL_BUFFER_BYTES, TCP_SMALL_BUFFER_BYTES)
        }
    }

    /// Note a connection refused because the table is full, and say so in the
    /// machine log at most once per [`FULL_WARNING_INTERVAL`], naming the
    /// limit and how to raise it.
    fn refuse_full(&mut self, direction: &str) {
        self.refused_full = self.refused_full.saturating_add(1);
        let now = Instant::now();
        if self
            .last_full_warning
            .is_some_and(|at| now.duration_since(at) < FULL_WARNING_INTERVAL)
        {
            return;
        }
        virtio_net_log!(
            "virtio-net: refusing {} TCP connection: this machine already has {} open, its limit \
             (set SMOLVM_TCP_RELAY_CAPACITY to change it); {} refused since the last report",
            direction,
            self.connections.len(),
            self.refused_full - self.refused_full_reported
        );
        self.refused_full_reported = self.refused_full;
        self.last_full_warning = Some(now);
    }

    /// Route selected guest streams through a host interceptor.
    pub fn with_intercept(mut self, intercept: Option<crate::StreamInterception>) -> Self {
        self.intercept = intercept;
        self
    }

    /// Relay target for a guest-initiated flow that egress already admitted.
    fn outbound_target(&self, destination: SocketAddr) -> RelayTarget {
        // The dedicated rollout ingress is a smolvm-owned service on the
        // gateway, not an outbound origin. Keep it available even when every
        // external TCP flow is delegated to a broker.
        if self.is_host_service_destination(destination) {
            return RelayTarget::Connect(self.host_connect_addr(destination));
        }
        match self.egress.rule_action(
            FlowTransport::Tcp,
            destination.ip(),
            Some(destination.port()),
        ) {
            // A static allow admits the flow; it does not exempt it from a
            // credential or egress interceptor, or a range reopened with
            // `--allow-private` would carry a credential's placeholder to the
            // origin verbatim. Only mediated egress gives allow the meaning
            // "dial directly, without asking the decider".
            Some(RuleAction::Allow)
                if matches!(self.intercept, Some(crate::StreamInterception::Mediated(_))) =>
            {
                return RelayTarget::DirectMediated(self.host_connect_addr(destination));
            }
            Some(RuleAction::Redirect) => {
                if let Some(crate::StreamInterception::Mediated(binding)) = self.intercept {
                    return RelayTarget::Mediated {
                        binding,
                        destination,
                        direct_address: self.host_connect_addr(destination),
                        direct_allowed: self.egress.allows_flow(
                            FlowTransport::Tcp,
                            self.host_connect_addr(destination).ip(),
                            Some(destination.port()),
                        ),
                        audit: self.egress.clone(),
                    };
                }
            }
            _ => {}
        }
        match self.intercept {
            Some(crate::StreamInterception::Https(endpoint))
                if destination.port() == INTERCEPTED_PORT
                    && !self.gateway_ips.contains(&destination.ip()) =>
            {
                RelayTarget::Intercept {
                    endpoint,
                    destination,
                }
            }
            Some(crate::StreamInterception::AllTcp(endpoint)) => RelayTarget::Intercept {
                endpoint,
                destination,
            },
            Some(crate::StreamInterception::Mediated(binding)) => RelayTarget::Mediated {
                binding,
                destination,
                direct_address: self.host_connect_addr(destination),
                direct_allowed: self.egress.allows(self.host_connect_addr(destination).ip())
                    || self.is_host_service_destination(destination),
                audit: self.egress.clone(),
            },
            _ => RelayTarget::Connect(self.host_connect_addr(destination)),
        }
    }

    /// Start fresh stacks at different points in the ephemeral range. The guest
    /// may still have connections from the stack saved in its checkpoint.
    pub(crate) fn with_published_port_seed(mut self, seed: u16) -> Self {
        self.next_published_port =
            PUBLISHED_PORT_START + seed % (PUBLISHED_PORT_END - PUBLISHED_PORT_START + 1);
        self
    }

    /// Number of guest TCP flows currently occupying relay table entries.
    pub(crate) fn active_connections(&self) -> usize {
        self.connections.len()
    }

    /// Maximum number of simultaneous guest TCP flows accepted by this table.
    pub(crate) fn capacity(&self) -> usize {
        self.max_connections
    }

    /// Summarize the open flows for the machine's flow telemetry. Walks the
    /// table once; the poll loop calls it on a slow cadence, never per packet.
    pub(crate) fn flow_summary(&self, now: Instant) -> FlowSummary {
        summarize_flows(
            self.connections.values().map(|connection| {
                (
                    connection.destination,
                    connection.reserved_published_port.is_some(),
                    connection.opened_at,
                )
            }),
            now,
        )
    }

    fn destination_allowed(&self, destination: SocketAddr) -> bool {
        if self.is_host_service_destination(destination) {
            return true;
        }
        // A gateway destination is dialed as host loopback. A deny on the
        // dialed address has to hold even though the guest named the gateway.
        let dialed = self.host_connect_addr(destination);
        if dialed.ip() != destination.ip()
            && self
                .egress
                .rule_action(FlowTransport::Tcp, dialed.ip(), Some(dialed.port()))
                == Some(RuleAction::Deny)
        {
            return false;
        }
        if self.egress.rule_action(
            FlowTransport::Tcp,
            destination.ip(),
            Some(destination.port()),
        ) == Some(RuleAction::Redirect)
            && !matches!(self.intercept, Some(crate::StreamInterception::Mediated(_)))
        {
            return false;
        }
        self.egress.allows_flow(
            FlowTransport::Tcp,
            destination.ip(),
            Some(destination.port()),
        )
    }

    fn is_host_service_destination(&self, destination: SocketAddr) -> bool {
        self.host_service
            .is_some_and(|service| service.guest_port == destination.port())
            && self.gateway_ips.contains(&destination.ip())
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
        self.by_tuple.contains_key(&(*source, *destination))
    }

    /// The flow a guest segment from `guest` to `peer` belongs to.
    pub(crate) fn flow_for(&self, guest: SocketAddr, peer: SocketAddr) -> Option<u64> {
        self.by_tuple.get(&(guest, peer)).copied()
    }

    /// Hand the device's staged guest frame to flow `id`'s socket.
    pub(crate) fn ingress<D: Device + ?Sized>(
        &mut self,
        id: u64,
        interface: &mut Interface,
        device: &mut D,
        now: smoltcp::time::Instant,
    ) -> PollIngressSingleResult {
        let Some(connection) = self.connections.get_mut(&id) else {
            return PollIngressSingleResult::None;
        };
        let result = interface.poll_ingress_single(now, device, &mut connection.set);
        self.touched.push(id);
        result
    }

    /// Service every flow on the next pass. For neighbor discovery: a flow
    /// whose output waited on the guest's link address only learns that it
    /// arrived by being polled, and otherwise waits out smoltcp's one-second
    /// retry. Address resolution happens about once a minute, so the walk is
    /// cheap.
    pub(crate) fn touch_all(&mut self) {
        self.touched.extend(self.connections.keys().copied());
    }

    /// Earliest time (ms of the poll loop's clock) a flow's smoltcp timer is due.
    pub(crate) fn next_timer(&mut self) -> Option<i64> {
        while let Some(Reverse((at, id))) = self.timers.peek().copied() {
            match self.connections.get(&id) {
                Some(connection) if connection.next_poll == Some(at) => return Some(at),
                _ => {
                    self.timers.pop();
                }
            }
        }
        None
    }

    /// Service every flow with work: move bytes between its socket and its
    /// relay, send what smoltcp has for the guest, start relays for flows the
    /// guest finished opening (returned), reap finished flows, and schedule
    /// each flow's next timer.
    pub(crate) fn service<D: Device + ?Sized>(
        &mut self,
        interface: &mut Interface,
        device: &mut D,
        now: smoltcp::time::Instant,
    ) -> Vec<NewTcpConnection> {
        let mut ids = std::mem::take(&mut self.touched);
        for id in self.poll_queue.take() {
            if let Some(connection) = self.connections.get(&id) {
                connection.exit_state.queued.store(false, Ordering::Release);
            }
            ids.push(id);
        }
        let now_ms = now.total_millis();
        while let Some(Reverse((at, id))) = self.timers.peek().copied() {
            if at > now_ms {
                break;
            }
            self.timers.pop();
            if let Some(connection) = self.connections.get_mut(&id) {
                if connection.next_poll == Some(at) {
                    connection.next_poll = None;
                    ids.push(id);
                }
            }
        }
        ids.sort_unstable();
        ids.dedup();

        let mut new_connections = Vec::new();
        let mut read_buffer = [0u8; RELAY_BUFFER_BYTES];
        for id in ids {
            let Some(connection) = self.connections.get_mut(&id) else {
                continue;
            };
            relay_flow_data(connection, &mut read_buffer);
            if let Some(new_connection) = take_if_established(connection) {
                new_connections.push(new_connection);
            }
            loop {
                if matches!(
                    interface.poll_egress(now, device, &mut connection.set),
                    PollResult::None
                ) {
                    break;
                }
            }
            if flow_finished(connection) {
                self.reap(id);
                continue;
            }
            let next = interface
                .poll_at(now, &connection.set)
                .map(|at| at.total_millis());
            if next != connection.next_poll {
                connection.next_poll = next;
                if let Some(at) = next {
                    self.timers.push(Reverse((at, id)));
                }
            }
        }
        new_connections
    }

    /// Remove a finished flow.
    fn reap(&mut self, id: u64) {
        let Some(connection) = self.connections.remove(&id) else {
            return;
        };
        self.by_tuple.remove(&connection.key);
        if let Some(port) = connection.reserved_published_port {
            self.used_published_ports.remove(&port);
            // A published connection that closed before the guest handshake
            // completed was refused (or reset) by the guest: nothing accepts
            // connections on guest_ip:guest_port.
            if !connection.relay_spawned
                && first_refusal_of_guest_port(
                    &mut self.unaccepted_guest_ports,
                    connection.destination.port(),
                )
            {
                tracing::warn!(
                    "nothing inside the machine accepted a published-port connection on {}; \
                     a server listening only on 127.0.0.1 inside the machine is not \
                     reachable through a published port, so listen on 0.0.0.0",
                    connection.destination
                );
            }
        }
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
    pub fn create_tcp_socket(&mut self, source: SocketAddr, destination: SocketAddr) -> bool {
        if self.connections.len() >= self.max_connections {
            self.refuse_full("outbound");
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
                .record_denial("connect", &format_args!("to {destination}"));
            return false;
        }
        // A `block` entry fails the connection like a denial, recorded only as
        // the watchlist match.
        if self.egress.observe_destination(destination) {
            return false;
        }
        if self.is_host_service_destination(destination)
            && self
                .egress
                .record_decision("tcp", "allow", &destination, "internal_service")
                .is_err()
        {
            self.egress
                .record_denial("connect", &format_args!("to {destination}"));
            return false;
        }
        if self.egress.rule_action(
            FlowTransport::Tcp,
            destination.ip(),
            Some(destination.port()),
        ) == Some(RuleAction::Allow)
            && self
                .egress
                .record_decision("tcp", "allow", &destination, "static_rule")
                .is_err()
        {
            self.egress.record_denial("connect", &destination);
            return false;
        }

        let (rx_bytes, tx_bytes) = self.next_buffer_bytes();
        let rx_buffer = tcp::SocketBuffer::new(vec![0u8; rx_bytes]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0u8; tx_bytes]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
        socket.set_nagle_enabled(false);

        let listen_endpoint = IpListenEndpoint {
            addr: Some(destination.ip().into()),
            port: destination.port(),
        };
        if socket.listen(listen_endpoint).is_err() {
            return false;
        }

        let mut set = SocketSet::new(Vec::with_capacity(1));
        let handle = set.add(socket);

        let (id, waker) = self.new_flow_id();
        let (to_proxy_tx, to_proxy_rx, proxy_wake) = proxy_channel(waker);
        let relay_waker = proxy_wake.clone();
        let (from_proxy_tx, from_proxy_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let exit_state = RelayExitState::for_flow(&self.poll_queue, id);

        let key = (source, destination);
        self.by_tuple.insert(key, id);
        self.touched.push(id);
        self.connections.insert(
            id,
            TrackedConnection {
                destination,
                to_proxy: Some(to_proxy_tx),
                from_proxy: from_proxy_rx,

                pending_proxy_endpoints: Some(PendingProxyEndpoints {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                    relay_target: self.outbound_target(destination),
                    proxy_wake,
                    watch_opening: Some(self.egress.clone()),
                }),
                relay_spawned: false,
                buffered_guest_data: None,
                buffered_proxy_data: None,
                close_attempts: 0,
                guest_send_closed: false,
                exit_state,
                reserved_published_port: None,
                opened_at: Instant::now(),
                relay_waker,
                guest_closed_keepalive: false,
                set,
                handle,
                key,
                next_poll: None,
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
    ) -> bool {
        if self.connections.len() >= self.max_connections {
            self.refuse_full("published-port");
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

        let (rx_bytes, tx_bytes) = self.next_buffer_bytes();
        let rx_buffer = tcp::SocketBuffer::new(vec![0u8; rx_bytes]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0u8; tx_bytes]);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
        socket.set_nagle_enabled(false);
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

        let mut set = SocketSet::new(Vec::with_capacity(1));
        let handle = set.add(socket);
        let source = SocketAddr::new(std::net::IpAddr::V4(gateway_ip), local_port);

        let (id, waker) = self.new_flow_id();
        let (to_proxy_tx, to_proxy_rx, proxy_wake) = proxy_channel(waker);
        let relay_waker = proxy_wake.clone();
        let (from_proxy_tx, from_proxy_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let exit_state = RelayExitState::for_flow(&self.poll_queue, id);

        // The guest answers from its own endpoint to the gateway's.
        let key = (destination, source);
        self.by_tuple.insert(key, id);
        self.touched.push(id);
        self.connections.insert(
            id,
            TrackedConnection {
                destination,
                to_proxy: Some(to_proxy_tx),
                from_proxy: from_proxy_rx,

                pending_proxy_endpoints: Some(PendingProxyEndpoints {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                    relay_target: RelayTarget::Attached(host_stream),
                    proxy_wake,
                    watch_opening: None,
                }),
                relay_spawned: false,
                buffered_guest_data: None,
                buffered_proxy_data: None,
                close_attempts: 0,
                guest_send_closed: false,
                exit_state,
                reserved_published_port: Some(local_port),
                opened_at: Instant::now(),
                relay_waker,
                guest_closed_keepalive: false,
                set,
                handle,
                key,
                next_poll: None,
            },
        );

        true
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

/// Move payloads between a flow's smoltcp socket and its host relay, and act
/// on how the relay ended: close or abort the guest side.
fn relay_flow_data(connection: &mut TrackedConnection, read_buffer: &mut [u8]) {
    if !connection.relay_spawned {
        return;
    }
    // The socket lives in the connection; lend it out so both can be borrowed.
    let mut set = std::mem::replace(&mut connection.set, SocketSet::new(Vec::new()));
    relay_socket_data(
        set.get_mut::<tcp::Socket>(connection.handle),
        connection,
        read_buffer,
    );
    connection.set = set;
}

fn relay_socket_data(
    socket: &mut tcp::Socket<'_>,
    connection: &mut TrackedConnection,
    read_buffer: &mut [u8],
) {
    match connection.exit_state.load() {
        RelayExitMode::Abort => {
            socket.abort();
            return;
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
            return;
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
        match socket.recv_slice(read_buffer) {
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
        if !connection.guest_closed_keepalive {
            // The guest closed its side; if it then forgets the socket
            // while the remote never closes, a probe draws the guest's
            // reset and the flow is freed rather than held forever.
            socket.set_keep_alive(Some(GUEST_CLOSED_KEEPALIVE.into()));
            connection.guest_closed_keepalive = true;
        }
    }

    flush_proxy_data(socket, connection);
}

/// A flow the guest finished opening (`Established`, or already `CloseWait`
/// for a guest that sent its FIN at once) gets its host relay now: the guest
/// handshake is accepted first, and only then is the host side opened.
fn take_if_established(connection: &mut TrackedConnection) -> Option<NewTcpConnection> {
    if connection.relay_spawned {
        return None;
    }
    let state = connection.set.get::<tcp::Socket>(connection.handle).state();
    if state != tcp::State::Established && state != tcp::State::CloseWait {
        return None;
    }
    connection.relay_spawned = true;
    let endpoints = connection.pending_proxy_endpoints.take()?;
    Some(NewTcpConnection {
        destination: connection.destination,
        relay_target: endpoints.relay_target,
        from_smoltcp: endpoints.from_smoltcp,
        to_smoltcp: endpoints.to_smoltcp,
        exit_state: connection.exit_state.clone(),
        proxy_wake: endpoints.proxy_wake,
        watch_opening: endpoints.watch_opening,
    })
}

/// Whether a flow is over and can be dropped.
///
/// An aborted socket reaches `Closed` synchronously, but its RST is only
/// emitted on the next interface dispatch — and smoltcp clears the endpoint
/// tuple right after sending it. Reaping on `Closed` alone would destroy the
/// queued RST and the guest would never learn the connection died (it hangs
/// until its own timeout, which is how a failed host-side connect used to
/// black-hole every unreachable destination). So a `Closed` flow waits for
/// `remote_endpoint()` to clear.
///
/// TIME-WAIT guards a reused 4-tuple against stray old segments on a real
/// network; on this point-to-point link the guest keeps its own TIME-WAIT, so
/// holding the flow for smoltcp's 10 s only ties up a table slot and its
/// buffers. A late retransmitted FIN finds no socket and draws a reset, which
/// the guest takes as closed.
fn flow_finished(connection: &TrackedConnection) -> bool {
    let socket = connection.set.get::<tcp::Socket>(connection.handle);
    socket.state() == tcp::State::TimeWait
        || (socket.state() == tcp::State::Closed && socket.remote_endpoint().is_none())
}

/// Record that a published connection to `guest_port` was refused by the
/// guest. Returns `true` only the first time for each port, so the caller
/// warns once per port rather than once per connection attempt.
fn first_refusal_of_guest_port(reported: &mut HashSet<u16>, guest_port: u16) -> bool {
    reported.insert(guest_port)
}

/// Spawn one host TCP relay thread for an established guest connection.
///
/// Thread responsibilities:
/// - connect a host `TcpStream` to the guest-requested destination
/// - copy bytes guest->host from `from_smoltcp`
/// - copy bytes host->guest into `to_smoltcp`
/// - wake the poll loop when host->guest data arrives or guest->host backpressure eases
/// - report termination mode through `exit_state`
pub fn spawn_tcp_relay(connection: NewTcpConnection, relay_wake: Arc<WakePipe>) -> io::Result<()> {
    let destination = connection.destination;
    let thread_name = format!("smolvm-tcp-{}", destination.port());
    tracing::debug!(
        "virtio-net: host TCP relay thread spawn attempt destination={} thread={}",
        destination,
        thread_name
    );
    let spawn_failure_exit_state = connection.exit_state.clone();
    let spawn_failure_wake = relay_wake.clone();
    let spawn_result = thread::Builder::new()
        .name(thread_name)
        .spawn(move || run_tcp_relay(connection, relay_wake));
    match handle_relay_spawn_result(
        spawn_result,
        destination,
        &spawn_failure_exit_state,
        &spawn_failure_wake,
    ) {
        Ok(_handle) => Ok(()),
        Err(err) => Err(err),
    }
}

fn handle_relay_spawn_result<T>(
    result: io::Result<T>,
    destination: SocketAddr,
    exit_state: &RelayExitState,
    relay_wake: &WakePipe,
) -> io::Result<T> {
    result.map_err(|err| {
        virtio_net_log!(
            "virtio-net: failed to spawn host TCP relay thread destination={} error={}",
            destination,
            err
        );
        // `take_if_established` has already marked this entry as having a
        // relay. Without an explicit terminal state, a failed OS thread
        // creation leaves the entry in Running forever and eventually
        // exhausts the bounded relay table.
        exit_state.store(RelayExitMode::Abort);
        exit_state.notify(relay_wake);
        err
    })
}

fn run_tcp_relay(connection: NewTcpConnection, relay_wake: Arc<WakePipe>) {
    let destination = connection.destination;
    let exit_state = connection.exit_state.clone();
    // The relay thread is intentionally isolated from smoltcp internals. Its
    // contract is just channels in, channels out, and an exit code back.
    tracing::debug!(
        "virtio-net: host TCP relay thread started destination={}",
        destination
    );
    match tcp_relay_loop(connection, relay_wake.clone(), &exit_state) {
        Ok(mode) => {
            tracing::debug!(
                "virtio-net: host TCP relay thread exited destination={} mode={:?}",
                destination,
                mode
            );
            exit_state.store(mode)
        }
        Err(err) => {
            tracing::debug!(
                "virtio-net: host TCP relay failed destination={} error={}",
                destination,
                err
            );
            exit_state.store(RelayExitMode::Abort);
        }
    }
    exit_state.notify(&relay_wake);
}

/// Guest bytes already read, with the offset written so far, that must reach
/// the host before anything else.
pub(crate) type PendingGuestData = Option<(Vec<u8>, usize)>;

/// Open the host side of a flow, blocking until it is usable: dial the
/// destination, an interceptor, or a decider and then the route it chose.
/// Returns the connected stream and any guest bytes already read that must
/// reach it first.
pub(crate) fn open_relay_target(
    relay_target: RelayTarget,
    from_smoltcp: &Receiver<Vec<u8>>,
    relay_wake: &WakePipe,
    exit_state: &RelayExitState,
) -> io::Result<(TcpStream, PendingGuestData)> {
    let mut pending_guest_data: Option<(Vec<u8>, usize)> = None;
    let stream = match relay_target {
        RelayTarget::Connect(destination) => TcpStream::connect(destination)?,
        RelayTarget::DirectMediated(destination) => {
            TcpStream::connect_timeout(&destination, INTERCEPT_VERDICT_TIMEOUT)?
        }
        RelayTarget::Attached(stream) => stream,
        RelayTarget::Intercept {
            endpoint,
            destination,
        } => {
            tracing::debug!(
                %destination,
                interceptor = %endpoint.addr,
                "virtio-net: redirecting guest flow to credential interceptor"
            );
            // The preamble is written blocking, before any guest byte: it is a
            // few dozen bytes to a loopback listener and must precede the TLS
            // ClientHello the guest sends next.
            let mut stream = TcpStream::connect(endpoint.addr)?;
            endpoint.write_preamble(&mut stream, destination)?;
            // The interceptor dials the destination before answering; a
            // failure aborts the flow as a failed direct connect would.
            stream.set_read_timeout(Some(INTERCEPT_VERDICT_TIMEOUT))?;
            smolvm_protocol::intercept::read_verdict(&mut stream)?;
            stream.set_read_timeout(None)?;
            stream
        }
        RelayTarget::Mediated {
            binding,
            destination,
            direct_address,
            direct_allowed,
            audit,
        } => {
            // The guest handshake is complete, but the origin has not been
            // dialed. Wait briefly for application bytes so a host decider can
            // inspect them before choosing a route. Server-speaks-first flows
            // continue after this bounded hold with an empty initial payload.
            let first = collect_initial_bytes(from_smoltcp, FIRST_PAYLOAD_HOLD);
            if first.is_some() {
                exit_state.notify(relay_wake);
            }
            let first_len = first
                .as_ref()
                .map_or(0, |bytes| bytes.len().min(MAX_INITIAL_BYTES));
            let broker_result = (|| -> io::Result<(TcpStream, Decision)> {
                let mut broker =
                    TcpStream::connect_timeout(&binding.endpoint.addr, MEDIATED_CONNECT_TIMEOUT)?;
                broker.set_write_timeout(Some(INTERCEPT_VERDICT_TIMEOUT))?;
                FlowPrelude {
                    machine_id: binding.machine_id,
                    parent_id: binding.parent_id,
                    destination,
                    initial_bytes: first
                        .as_ref()
                        .map_or_else(Vec::new, |bytes| bytes[..first_len].to_vec()),
                }
                .write_to(&mut broker, &binding.endpoint.token)?;
                broker.set_read_timeout(Some(INTERCEPT_VERDICT_TIMEOUT))?;
                let decision = Decision::read_from(&mut broker)?;
                broker.set_read_timeout(None)?;
                broker.set_write_timeout(None)?;
                Ok((broker, decision))
            })();
            let (broker, decision) = match broker_result {
                Ok(result) => result,
                Err(error) => {
                    let _ =
                        audit.record_decision("tcp", "deny", &destination, "broker_unavailable");
                    return Err(error);
                }
            };
            if decision == Decision::AllowDirect && !direct_allowed {
                audit.record_decision("tcp", "deny", &destination, "direct_target_policy")?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "egress policy denied direct target",
                ));
            }
            let action = match decision {
                Decision::AllowDirect => "allow",
                Decision::Deny => "deny",
                Decision::Redirect => "redirect",
            };
            audit.record_decision("tcp", action, &destination, "broker_decision")?;
            match decision {
                Decision::Deny => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "egress decider denied flow",
                    ));
                }
                Decision::Redirect => {
                    if let Some(first) = first {
                        if first_len < first.len() {
                            pending_guest_data = Some((first, first_len));
                        }
                    }
                    broker
                }
                Decision::AllowDirect => {
                    if let Some(first) = first {
                        pending_guest_data = Some((first, 0));
                    }
                    drop(broker);
                    TcpStream::connect_timeout(&direct_address, INTERCEPT_VERDICT_TIMEOUT)?
                }
            }
        }
    };
    Ok((stream, pending_guest_data))
}

fn tcp_relay_loop(
    connection: NewTcpConnection,
    relay_wake: Arc<WakePipe>,
    exit_state: &RelayExitState,
) -> io::Result<RelayExitMode> {
    let NewTcpConnection {
        destination,
        relay_target,
        from_smoltcp,
        to_smoltcp,
        proxy_wake,
        watch_opening,
        ..
    } = connection;
    let mediated = relay_target.is_mediated();
    let (stream, pending_guest_data) =
        open_relay_target(relay_target, &from_smoltcp, &relay_wake, exit_state)?;
    prepare_host_stream(&stream)?;
    let pump = RelayPump::new(
        stream,
        from_smoltcp,
        to_smoltcp,
        RelayFlow {
            mediated,
            pending_guest_data,
            opening: watch_opening.map(|egress| OpeningWatch::new(egress, destination)),
        },
    )?;
    let poller = proxy_wake
        .standalone_poller()
        .ok_or_else(|| io::Error::other("a relay thread needs its own wake poller"))?;
    relay_stream(pump, &poller, &relay_wake, exit_state)
}

/// Whether `bytes` already hold what a decider needs to route a flow: one whole
/// TLS record (the ClientHello, SNI included), the whole header block of an
/// HTTP request, or, for any other protocol, its first segment.
///
/// A ClientHello carrying a post-quantum key share is about 1.8 KB and often
/// spans two segments, with the SNI in the second; a decider shown only the
/// first segment could not route it by name.
fn initial_bytes_complete(bytes: &[u8]) -> bool {
    if bytes.first() == Some(&0x16) {
        // A TLS record: content type, two version bytes, a two-byte length.
        return bytes.len() >= 5
            && bytes.len() >= 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    }
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    if METHODS.iter().any(|method| bytes.starts_with(method)) {
        return bytes.windows(4).any(|window| window == b"\r\n\r\n");
    }
    // Any other protocol may send a line and then wait for the server, so
    // holding it for more than its first segment would only add latency.
    true
}

/// A flow's opening bytes for the decider: the guest's segments until they are
/// [complete](initial_bytes_complete), reach `MAX_INITIAL_BYTES`, or `hold` has
/// passed since the first wait. `None` when the guest sent nothing in time (a
/// server-speaks-first protocol) or closed its side.
fn collect_initial_bytes(from: &Receiver<Vec<u8>>, hold: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + hold;
    let mut collected: Option<Vec<u8>> = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(segment) = from.recv_timeout(remaining) else {
            break;
        };
        let bytes = collected.get_or_insert_with(Vec::new);
        bytes.extend_from_slice(&segment);
        if bytes.len() >= MAX_INITIAL_BYTES || initial_bytes_complete(bytes) {
            break;
        }
    }
    collected
}

/// A relay's host socket registered in the relay's poller. Owning both ties
/// the registration to the socket's lifetime: `Drop` removes it before the
/// socket closes, on every exit path, unwinding included.
struct RegisteredPump {
    pump: RelayPump,
    poller: Arc<polling::Poller>,
}

impl RegisteredPump {
    fn new(pump: RelayPump, poller: Arc<polling::Poller>) -> io::Result<Self> {
        // SAFETY: the stream is owned by the value returned here, whose Drop
        // removes it from the poller before the stream itself is dropped.
        unsafe { poller.add(&pump.stream, Event::none(HOST_STREAM_KEY))? };
        Ok(Self { pump, poller })
    }
}

impl Drop for RegisteredPump {
    fn drop(&mut self) {
        let _ = self.poller.delete(&self.pump.stream);
    }
}

/// Make a connected host stream ready for a pump: non-blocking, and without
/// Nagle's delay, which would hold back the small writes of an interactive
/// flow the guest already decided to send.
pub(crate) fn prepare_host_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    stream.set_nodelay(true)
}

/// How a flow entered the relay.
pub(crate) struct RelayFlow {
    /// Bounded by the mediated connection lifetime.
    pub(crate) mediated: bool,
    /// Guest bytes already read (with the offset written so far) that must
    /// reach the host before anything else.
    pub(crate) pending_guest_data: Option<(Vec<u8>, usize)>,
    /// Shown the guest's opening bytes until it has seen enough of them.
    pub(crate) opening: Option<OpeningWatch>,
}

/// Copies of the first bytes a guest sends on an outbound connection, held
/// until they say what the connection is (a miner's stratum login, a TLS
/// server name) and then shown to the egress policy once. Holding copies
/// never delays the guest's bytes on their way to the host.
pub(crate) struct OpeningWatch {
    egress: EgressPolicy,
    destination: SocketAddr,
    seen: Vec<u8>,
}

impl OpeningWatch {
    pub(crate) fn new(egress: EgressPolicy, destination: SocketAddr) -> Self {
        Self {
            egress,
            destination,
            seen: Vec::new(),
        }
    }

    /// Take the next guest segment. `None` while more are needed; once the
    /// opening is known, whether a `block` watchlist entry refuses the flow.
    fn feed(&mut self, segment: &[u8]) -> Option<bool> {
        let room = crate::opening::MAX_OPENING_BYTES.saturating_sub(self.seen.len());
        self.seen
            .extend_from_slice(&segment[..segment.len().min(room)]);
        let opening = crate::opening::classify(&self.seen)?;
        Some(self.egress.observe_opening(self.destination, &opening))
    }
}

/// What one [`RelayPump::pump`] call left the flow in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PumpOutcome {
    /// Neither direction can progress until the host socket turns readable
    /// (`read`) or writable (`write`), or the poll loop wakes the relay.
    Idle { read: bool, write: bool },
    /// Still has work; the caller stopped it to be fair to other flows.
    Busy,
    /// The flow is over.
    Finished(RelayExitMode),
}

/// The data path of one flow: copies bytes both ways between its host socket
/// and the poll loop's channels without ever blocking, so one thread can pump
/// any number of flows. A dedicated relay thread drives it with
/// [`relay_stream`], the shared reactor with its own poller.
pub(crate) struct RelayPump {
    pub(crate) stream: TcpStream,
    from_smoltcp: Receiver<Vec<u8>>,
    to_smoltcp: SyncSender<Vec<u8>>,
    /// Guest bytes read from the channel (with the offset written so far)
    /// waiting on a full host send buffer.
    pending_guest_data: Option<(Vec<u8>, usize)>,
    /// Host bytes read from the socket waiting on a full host->guest channel.
    pending_host_data: Option<Vec<u8>>,
    opening: Option<OpeningWatch>,
    mediated: bool,
    started: Instant,
    last_activity: Instant,
    guest_write_closed: bool,
    guest_channel_closed: bool,
    host_read_closed: bool,
}

impl RelayPump {
    pub(crate) fn new(
        stream: TcpStream,
        from_smoltcp: Receiver<Vec<u8>>,
        to_smoltcp: SyncSender<Vec<u8>>,
        flow: RelayFlow,
    ) -> io::Result<Self> {
        let now = Instant::now();
        let mut pump = Self {
            stream,
            from_smoltcp,
            to_smoltcp,
            pending_guest_data: None,
            pending_host_data: None,
            opening: flow.opening,
            mediated: flow.mediated,
            started: now,
            last_activity: now,
            guest_write_closed: false,
            guest_channel_closed: false,
            host_read_closed: false,
        };
        // The whole first payload is the guest's opening, including any prefix
        // a decider already forwarded.
        if let Some((payload, _)) = &flow.pending_guest_data {
            let payload = payload.clone();
            pump.watch(&payload)?;
        }
        pump.pending_guest_data = flow.pending_guest_data;
        Ok(pump)
    }

    /// Shows a guest segment to the opening watch until it has a verdict, and
    /// ends the flow when that verdict is a watchlist `block`.
    fn watch(&mut self, segment: &[u8]) -> io::Result<()> {
        let Some(verdict) = self.opening.as_mut().and_then(|watch| watch.feed(segment)) else {
            return Ok(());
        };
        self.opening = None;
        if verdict {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "egress watchlist blocked the server name",
            ));
        }
        Ok(())
    }

    /// A mediated flow past its idle or total lifetime.
    pub(crate) fn expired(&self) -> bool {
        self.mediated
            && (self.started.elapsed() >= MEDIATED_MAX_LIFETIME
                || self.last_activity.elapsed() >= MEDIATED_IDLE_TIMEOUT)
    }

    /// Nothing reads or writes the host socket any more (the host stopped
    /// sending and every guest byte is written), so only an error or hang-up
    /// on it is news.
    pub(crate) fn only_waiting_for_guest(&self) -> bool {
        self.host_read_closed && self.pending_guest_data.is_none()
    }

    /// Fail a flow whose host socket broke while nothing was reading it.
    /// epoll reports EPOLLERR and EPOLLHUP whatever the interest (`hung_up`
    /// says one arrived); kqueue reports nothing, so the error is read too.
    pub(crate) fn check_host_error(&self, hung_up: bool) -> io::Result<()> {
        if let Some(err) = self.stream.take_error()? {
            return Err(err);
        }
        if hung_up {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "host TCP socket hung up",
            ));
        }
        Ok(())
    }

    /// Hand a host payload to the poll loop. `false` when the poll loop is
    /// gone (the guest flow was torn down).
    fn offer_host_data(
        &mut self,
        data: Vec<u8>,
        relay_wake: &WakePipe,
        exit_state: &RelayExitState,
    ) -> bool {
        match self.to_smoltcp.try_send(data) {
            Ok(()) => {
                exit_state.notify(relay_wake);
                true
            }
            Err(TrySendError::Full(data)) => {
                // Ask the poll loop to wake us once it drains the channel, then
                // look again: a drain between the failed send and the flag
                // would otherwise never be noticed.
                exit_state.host_blocked.store(true, Ordering::Release);
                match self.to_smoltcp.try_send(data) {
                    Ok(()) => {
                        exit_state.host_blocked.store(false, Ordering::Release);
                    }
                    Err(TrySendError::Full(data)) => self.pending_host_data = Some(data),
                    Err(TrySendError::Disconnected(_)) => return false,
                }
                exit_state.notify(relay_wake);
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Move bytes both ways until neither direction can progress, the flow
    /// ends, or `budget` rounds have run.
    pub(crate) fn pump(
        &mut self,
        read_buffer: &mut [u8],
        relay_wake: &WakePipe,
        exit_state: &RelayExitState,
        budget: usize,
    ) -> io::Result<PumpOutcome> {
        for _ in 0..budget {
            if self.expired() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mediated TCP flow lifetime expired",
                ));
            }
            let mut did_work = false;

            // guest -> host
            if self.pending_guest_data.is_none() && !self.guest_channel_closed {
                match self.from_smoltcp.try_recv() {
                    Ok(payload) => {
                        self.watch(&payload)?;
                        self.pending_guest_data = Some((payload, 0));
                        // Consuming from the bounded guest->host channel may free
                        // capacity for a payload buffered in the smoltcp poll
                        // thread. Wake it so backpressure clears promptly even
                        // for one-way guest->host streams.
                        exit_state.notify(relay_wake);
                        did_work = true;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => self.guest_channel_closed = true,
                }
            }
            if let Some((payload, offset)) = &mut self.pending_guest_data {
                while *offset < payload.len() {
                    match (&self.stream).write(&payload[*offset..]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "host TCP relay wrote zero bytes",
                            ));
                        }
                        Ok(written) => {
                            *offset += written;
                            did_work = true;
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(err) => return Err(err),
                    }
                }
                if *offset >= payload.len() {
                    self.pending_guest_data = None;
                }
            }
            if self.guest_channel_closed
                && self.pending_guest_data.is_none()
                && !self.guest_write_closed
            {
                // The guest closed its write half. Mirror that toward the
                // remote peer only after all buffered guest bytes were written.
                let _ = self.stream.shutdown(Shutdown::Write);
                self.guest_write_closed = true;
            }
            // Every guest byte reached the host and the guest side is gone
            // for good (closed or reset): whatever the remote still sends has
            // no one to reach, so end the flow instead of waiting on a remote
            // that may never close its side.
            if self.guest_write_closed && exit_state.guest_gone.load(Ordering::Acquire) {
                return Ok(PumpOutcome::Finished(RelayExitMode::Graceful));
            }
            // Both directions are done: the host stopped sending and the guest
            // stopped sending and was fully flushed. The poll loop tears the
            // guest socket down.
            if self.host_read_closed
                && self.guest_channel_closed
                && self.pending_guest_data.is_none()
            {
                return Ok(PumpOutcome::Finished(RelayExitMode::Graceful));
            }

            // host -> guest, only while the host's send half is still open. On
            // host read-EOF the relay is NOT torn down: HalfClosed has the poll
            // loop mirror the FIN to the guest while guest->host keeps draining.
            // A hijacked docker attach half-closes here (`shutdown(SHUT_WR)`
            // with no stdin) while the daemon is still streaming its response.
            if let Some(data) = self.pending_host_data.take() {
                if !self.offer_host_data(data, relay_wake, exit_state) {
                    return Ok(PumpOutcome::Finished(RelayExitMode::Graceful));
                }
                if self.pending_host_data.is_none() {
                    did_work = true;
                }
            }
            if !self.host_read_closed && self.pending_host_data.is_none() {
                match (&self.stream).read(read_buffer) {
                    Ok(0) => {
                        self.host_read_closed = true;
                        exit_state.store(RelayExitMode::HalfClosed);
                        exit_state.notify(relay_wake);
                        did_work = true;
                    }
                    Ok(read) => {
                        if !self.offer_host_data(
                            read_buffer[..read].to_vec(),
                            relay_wake,
                            exit_state,
                        ) {
                            return Ok(PumpOutcome::Finished(RelayExitMode::Graceful));
                        }
                        did_work = true;
                    }
                    Err(err)
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => return Err(err),
                }
            }

            if !did_work {
                // Read interest while the host may still send and the guest has
                // room; write interest while a guest payload waits on a full
                // host send buffer.
                return Ok(PumpOutcome::Idle {
                    read: !self.host_read_closed && self.pending_host_data.is_none(),
                    write: self.pending_guest_data.is_some(),
                });
            }
            self.last_activity = Instant::now();
        }
        Ok(PumpOutcome::Busy)
    }
}

/// Drive one flow's pump on its own thread until the flow ends, waiting on
/// `poller` whenever neither direction can make progress.
fn relay_stream(
    pump: RelayPump,
    poller: &Arc<polling::Poller>,
    relay_wake: &WakePipe,
    exit_state: &RelayExitState,
) -> io::Result<RelayExitMode> {
    let mut registered = RegisteredPump::new(pump, poller.clone())?;
    let pump = &mut registered.pump;
    let mut events = Events::new();
    let mut read_buffer = vec![0u8; RELAY_BUFFER_BYTES];
    loop {
        match pump.pump(&mut read_buffer, relay_wake, exit_state, usize::MAX)? {
            PumpOutcome::Finished(mode) => return Ok(mode),
            PumpOutcome::Busy => continue,
            PumpOutcome::Idle { read, write } => {
                poller.modify(&pump.stream, Event::new(HOST_STREAM_KEY, read, write))?;
                events.clear();
                poller.wait(&mut events, Some(RELAY_WAIT_BACKSTOP))?;
                if pump.only_waiting_for_guest() {
                    pump.check_host_error(events.iter().any(|event| event.key == HOST_STREAM_KEY))?;
                }
            }
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
    flush_proxy_payloads(socket, connection);
    // A relay that found the host->guest channel full waits for this drain.
    if connection
        .exit_state
        .host_blocked
        .swap(false, Ordering::AcqRel)
    {
        connection.relay_waker.wake();
    }
}

fn flush_proxy_payloads(socket: &mut tcp::Socket<'_>, connection: &mut TrackedConnection) {
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
mod initial_bytes_tests {
    use super::*;

    fn tls_record(body_len: usize) -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(body_len as u16).to_be_bytes());
        record.extend(std::iter::repeat_n(0xAB, body_len));
        record
    }

    // A ClientHello split across two segments is collected whole, so a decider
    // routing by SNI sees it even when the SNI is in the second segment.
    #[test]
    fn a_tls_record_split_across_segments_is_collected_whole() {
        let record = tls_record(1795);
        assert!(!initial_bytes_complete(&record[..3]));
        assert!(!initial_bytes_complete(&record[..1200]));
        assert!(initial_bytes_complete(&record));

        let (sender, receiver) = mpsc::sync_channel(4);
        sender.send(record[..1200].to_vec()).unwrap();
        let rest = record[1200..].to_vec();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            sender.send(rest).unwrap();
        });
        assert_eq!(
            collect_initial_bytes(&receiver, Duration::from_secs(2)),
            Some(record)
        );
    }

    #[test]
    fn http_request_headers_are_collected_to_their_end() {
        assert!(!initial_bytes_complete(b"GET / HTTP/1.1\r\nHost: a"));
        assert!(initial_bytes_complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
    }

    // Another protocol is handed over after its first segment, not held for the
    // whole deadline: it may be waiting for the server to answer.
    #[test]
    fn other_protocols_are_not_held_past_their_first_segment() {
        let (sender, receiver) = mpsc::sync_channel(4);
        sender.send(b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()).unwrap();
        let started = Instant::now();
        assert_eq!(
            collect_initial_bytes(&receiver, Duration::from_secs(5)),
            Some(b"SSH-2.0-OpenSSH_9.6\r\n".to_vec())
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn collection_stops_at_the_cap_and_at_the_deadline() {
        let (sender, receiver) = mpsc::sync_channel(4);
        sender.send(tls_record(MAX_INITIAL_BYTES)).unwrap();
        let collected = collect_initial_bytes(&receiver, Duration::from_secs(2)).unwrap();
        assert!(collected.len() >= MAX_INITIAL_BYTES);

        let (_sender, receiver) = mpsc::sync_channel::<Vec<u8>>(4);
        let started = Instant::now();
        assert_eq!(
            collect_initial_bytes(&receiver, Duration::from_millis(50)),
            None
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_summary_splits_directions_and_finds_the_oldest_outbound_flow() {
        let now = Instant::now();
        let ago = |secs| now - Duration::from_secs(secs);
        let pool: SocketAddr = "198.51.100.7:3333".parse().unwrap();
        let web: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let web_other_port: SocketAddr = "203.0.113.9:80".parse().unwrap();
        let guest: SocketAddr = "100.96.0.2:8080".parse().unwrap();
        let summary = summarize_flows(
            [
                (web, false, ago(30)),
                (pool, false, ago(7200)),
                (web_other_port, false, ago(5)),
                // An inbound flow older than every outbound one is not "oldest".
                (guest, true, ago(9000)),
                (guest, true, ago(1)),
            ]
            .into_iter(),
            now,
        );
        assert_eq!(
            summary,
            FlowSummary {
                outbound_open: 3,
                inbound_open: 2,
                distinct_outbound_peers: 2,
                oldest_outbound_secs: 7200,
                oldest_outbound_dest: Some(pool),
            }
        );
    }

    #[test]
    fn flow_summary_of_only_inbound_flows_has_no_oldest_outbound() {
        let now = Instant::now();
        let guest: SocketAddr = "100.96.0.2:8080".parse().unwrap();
        let summary = summarize_flows([(guest, true, now)].into_iter(), now);
        assert_eq!(summary.inbound_open, 1);
        assert_eq!(summary.outbound_open, 0);
        assert_eq!(summary.oldest_outbound_secs, 0);
        assert_eq!(summary.oldest_outbound_dest, None);
        assert_eq!(
            summarize_flows(std::iter::empty(), now),
            FlowSummary::default()
        );
    }

    #[test]
    fn guest_relay_sockets_disable_nagle_for_outbound_and_published_connections() {
        use smoltcp::iface::Config;
        use smoltcp::phy::{Loopback, Medium};
        use smoltcp::time::Instant;
        use smoltcp::wire::{EthernetAddress, HardwareAddress};

        let gateway = Ipv4Addr::new(100, 96, 0, 1);
        let mut device = Loopback::new(Medium::Ethernet);
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress([
                0x02, 0, 0, 0, 0, 1,
            ]))),
            &mut device,
            Instant::ZERO,
        );
        let mut table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None);
        let source = SocketAddr::from((Ipv4Addr::new(100, 96, 0, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 443));
        assert!(table.create_tcp_socket(source, destination));

        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let guest = SocketAddr::from((Ipv4Addr::new(100, 96, 0, 2), 8080));
        assert!(table.create_published_socket(&mut interface, gateway, guest, client,));
        assert_eq!(table.connections.len(), 2);
        for connection in table.connections.values() {
            assert!(!connection
                .set
                .get::<tcp::Socket>(connection.handle)
                .nagle_enabled());
        }
    }

    #[test]
    fn registered_relay_stream_disables_nagle_for_outbound_and_accepted_sockets() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let outbound = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();

        for stream in [outbound, accepted] {
            stream.set_nodelay(false).unwrap();
            prepare_host_stream(&stream).unwrap();
            assert!(stream.nodelay().unwrap());
        }
    }

    #[test]
    fn relay_accepts_burst_beyond_old_256_limit_and_honors_configured_cap() {
        use super::*;
        let mut table = TcpRelayTable::new(Some(320), EgressPolicy::unrestricted(), vec![], None);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        for port in 40_000..40_320 {
            let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)), port);
            assert!(table.create_tcp_socket(source, destination), "flow {port}");
        }
        assert_eq!(table.active_connections(), 320);
        let overflow = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)), 40_320);
        assert!(!table.create_tcp_socket(overflow, destination));
        assert_eq!(table.active_connections(), 320);
        assert!(
            TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None).capacity() >= 320
        );
    }
    #[test]
    fn seeded_published_ports_wrap_without_reusing_live_ports() {
        let mut table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None)
            .with_published_port_seed(u16::MAX);
        assert_eq!(table.allocate_published_port(), Some(PUBLISHED_PORT_END));
        assert_eq!(table.allocate_published_port(), Some(PUBLISHED_PORT_START));
        for expected in PUBLISHED_PORT_START + 1..PUBLISHED_PORT_END {
            assert_eq!(table.allocate_published_port(), Some(expected));
        }
        assert_eq!(table.allocate_published_port(), None);
        table.used_published_ports.remove(&PUBLISHED_PORT_END);
        assert_eq!(table.allocate_published_port(), Some(PUBLISHED_PORT_END));
        assert_eq!(table.allocate_published_port(), None);
    }

    #[test]
    fn different_port_seeds_do_not_restart_at_the_same_port() {
        let mut first = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None)
            .with_published_port_seed(123);
        let mut second = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None)
            .with_published_port_seed(456);
        assert_ne!(
            first.allocate_published_port(),
            second.allocate_published_port()
        );
    }

    fn test_connection(to_proxy: SyncSender<Vec<u8>>) -> TrackedConnection {
        test_connection_with(
            to_proxy,
            tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 1024]),
                tcp::SocketBuffer::new(vec![0; 1024]),
            ),
        )
    }

    fn test_connection_with(
        to_proxy: SyncSender<Vec<u8>>,
        socket: tcp::Socket<'static>,
    ) -> TrackedConnection {
        let (_from_proxy_tx, from_proxy) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let mut set = SocketSet::new(Vec::new());
        let handle = set.add(socket);
        TrackedConnection {
            destination: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 80),
            to_proxy: Some(ToProxy {
                sender: Some(to_proxy),
                wake: RelayWaker::standalone(),
            }),
            from_proxy,
            pending_proxy_endpoints: None,
            relay_spawned: true,
            buffered_guest_data: None,
            buffered_proxy_data: None,
            close_attempts: 0,
            guest_send_closed: false,
            exit_state: RelayExitState::new(),
            reserved_published_port: None,
            opened_at: Instant::now(),
            relay_waker: RelayWaker::standalone(),
            guest_closed_keepalive: false,
            set,
            handle,
            key: (
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12_345),
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 80),
            ),
            next_poll: None,
        }
    }

    #[test]
    fn failed_relay_thread_spawn_aborts_the_guest_connection() {
        let exit_state = RelayExitState::new();
        let wake = WakePipe::new();
        let destination = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 6443);
        let spawn_error = io::Error::other("injected thread spawn failure");

        let result =
            handle_relay_spawn_result::<()>(Err(spawn_error), destination, &exit_state, &wake);

        assert!(result.is_err());
        assert_eq!(exit_state.load(), RelayExitMode::Abort);
    }

    /// A host echo server for one connection, on loopback.
    fn echo_server() -> SocketAddr {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 64];
            while let Ok(read @ 1..) = stream.read(&mut buffer) {
                if stream.write_all(&buffer[..read]).is_err() {
                    break;
                }
            }
        });
        address
    }

    /// A relay thread connected to `destination`, with the poll loop's ends of its channels.
    fn spawn_test_relay(destination: SocketAddr) -> (ToProxy, Receiver<Vec<u8>>, RelayExitState) {
        spawn_watched_relay(destination, None)
    }

    /// `spawn_test_relay`, showing the guest's opening bytes to `watch_opening`.
    fn spawn_watched_relay(
        destination: SocketAddr,
        watch_opening: Option<EgressPolicy>,
    ) -> (ToProxy, Receiver<Vec<u8>>, RelayExitState) {
        let (to_proxy, from_smoltcp, proxy_wake) = proxy_channel(RelayWaker::standalone());
        let (to_smoltcp, from_proxy) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let exit_state = RelayExitState::new();
        spawn_tcp_relay(
            NewTcpConnection {
                destination,
                relay_target: RelayTarget::Connect(destination),
                from_smoltcp,
                to_smoltcp,
                exit_state: exit_state.clone(),
                proxy_wake,
                watch_opening,
            },
            Arc::new(WakePipe::new()),
        )
        .unwrap();
        (to_proxy, from_proxy, exit_state)
    }

    /// A policy that admits everything and records signals to `dir`, watching
    /// `watchlist` when it is written.
    fn watching_policy(dir: &std::path::Path) -> EgressPolicy {
        EgressPolicy::unrestricted().with_watchlist(
            dir.join(crate::watchlist::EGRESS_WATCHLIST_FILE),
            dir.join(crate::EGRESS_SIGNALS_LOG),
        )
    }

    #[test]
    fn a_miner_logging_in_to_its_pool_is_recorded_and_still_relayed() {
        let dir = tempfile::tempdir().unwrap();
        let pool = echo_server();
        let (to_proxy, from_proxy, _exit_state) =
            spawn_watched_relay(pool, Some(watching_policy(dir.path())));
        // ccminer's login is split across two segments, as TCP may deliver it.
        let login: &[u8] =
            b"{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"ccminer/2.3.1\"]}\n";
        to_proxy.try_send(login[..20].to_vec()).unwrap();
        to_proxy.try_send(login[20..].to_vec()).unwrap();
        let mut echoed = Vec::new();
        while echoed.len() < login.len() {
            echoed.extend(from_proxy.recv_timeout(Duration::from_secs(2)).unwrap());
        }
        assert_eq!(echoed, login, "the miner's bytes reach the pool unchanged");
        let log = std::fs::read_to_string(dir.path().join(crate::EGRESS_SIGNALS_LOG)).unwrap();
        assert!(
            log.contains(&format!("egress watch {} {pool}", crate::STRATUM_SIGNAL)),
            "{log}"
        );
    }

    #[test]
    fn ordinary_traffic_records_no_signal() {
        let dir = tempfile::tempdir().unwrap();
        let server = echo_server();
        let (to_proxy, from_proxy, _exit_state) =
            spawn_watched_relay(server, Some(watching_policy(dir.path())));
        to_proxy
            .try_send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec())
            .unwrap();
        from_proxy.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!dir.path().join(crate::EGRESS_SIGNALS_LOG).exists());
    }

    #[test]
    fn a_blocked_server_name_ends_the_flow_before_its_hello_leaves() {
        use sha2::Digest;
        let dir = tempfile::tempdir().unwrap();
        let digest = sha2::Sha256::digest(b"pool.example");
        std::fs::write(
            dir.path().join(crate::watchlist::EGRESS_WATCHLIST_FILE),
            format!("p1 dns-sha256:{digest:x} block\n"),
        )
        .unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            let _ = stream.read_to_end(&mut received);
            let _ = accepted_tx.send(received);
        });
        let (to_proxy, _from_proxy, exit_state) =
            spawn_watched_relay(server, Some(watching_policy(dir.path())));
        to_proxy
            .try_send(crate::opening::client_hello("Pool.Example"))
            .unwrap();
        wait_for_exit_mode(&exit_state, RelayExitMode::Abort, Duration::from_secs(2));
        assert_eq!(
            accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            Vec::<u8>::new(),
            "the ClientHello never reached the server"
        );
        let log = std::fs::read_to_string(dir.path().join(crate::EGRESS_SIGNALS_LOG)).unwrap();
        assert!(log.contains("egress watch p1 pool.example"), "{log}");
    }

    #[test]
    fn an_idle_relay_forwards_both_ways_without_waiting_out_a_poll_interval() {
        let (to_proxy, from_proxy, _exit_state) = spawn_test_relay(echo_server());
        let mut round_trips = Vec::new();
        for byte in 0..21u8 {
            // Let the relay go idle first: the case a fixed poll interval made slow.
            // The old 10 ms poll put the median near 15-18 ms; a woken relay is
            // well under 1 ms, so 8 ms leaves room for a loaded CI runner.
            thread::sleep(Duration::from_millis(15));
            let started = std::time::Instant::now();
            to_proxy.try_send(vec![byte]).unwrap();
            assert_eq!(
                from_proxy.recv_timeout(Duration::from_secs(2)).unwrap(),
                vec![byte]
            );
            round_trips.push(started.elapsed());
        }
        round_trips.sort();
        let median = round_trips[round_trips.len() / 2];
        assert!(
            median < Duration::from_millis(8),
            "median guest->host->guest round trip through an idle relay was {median:?}"
        );
    }

    #[test]
    fn dropping_the_guest_side_wakes_an_idle_relay_to_finish() {
        let (to_proxy, _from_proxy, exit_state) = spawn_test_relay(echo_server());
        to_proxy.try_send(vec![1]).unwrap();
        thread::sleep(Duration::from_millis(30));
        let started = std::time::Instant::now();
        drop(to_proxy);
        while exit_state.load() == RelayExitMode::Running {
            assert!(
                started.elapsed() < RELAY_WAIT_BACKSTOP / 2,
                "relay still running {:?} after the guest side closed",
                started.elapsed()
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// A host server for one connection that half-closes, then hands the
    /// accepted socket to `then`.
    fn half_closing_server(then: impl FnOnce(TcpStream) + Send + 'static) -> SocketAddr {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            then(stream);
        });
        address
    }

    fn wait_for_exit_mode(exit_state: &RelayExitState, mode: RelayExitMode, within: Duration) {
        let started = Instant::now();
        while exit_state.load() != mode {
            assert!(
                started.elapsed() < within,
                "relay is {:?} after {:?}, expected {mode:?}",
                exit_state.load(),
                started.elapsed()
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_host_reset_after_its_half_close_ends_a_relay_whose_guest_is_silent() {
        let (reset_tx, reset_rx) = mpsc::channel::<()>();
        let destination = half_closing_server(move |stream| {
            reset_rx.recv().unwrap();
            socket2::SockRef::from(&stream)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
        });
        // The guest side stays open and sends nothing.
        let (_to_proxy, _from_proxy, exit_state) = spawn_test_relay(destination);
        wait_for_exit_mode(
            &exit_state,
            RelayExitMode::HalfClosed,
            Duration::from_secs(2),
        );
        reset_tx.send(()).unwrap();
        // On epoll the relay used to spin here until the guest closed.
        wait_for_exit_mode(&exit_state, RelayExitMode::Abort, RELAY_WAIT_BACKSTOP * 5);
    }

    #[test]
    fn a_host_half_close_keeps_relaying_guest_bytes() {
        let (received_tx, received_rx) = mpsc::channel();
        let destination = half_closing_server(move |mut stream| {
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).unwrap();
            received_tx.send(buffer).unwrap();
            // Keep the socket open until the relay is checked.
            thread::sleep(Duration::from_secs(1));
        });
        let (to_proxy, _from_proxy, exit_state) = spawn_test_relay(destination);
        wait_for_exit_mode(
            &exit_state,
            RelayExitMode::HalfClosed,
            Duration::from_secs(2),
        );
        // Idle for a few backstop waits before the guest sends.
        thread::sleep(RELAY_WAIT_BACKSTOP * 3);
        to_proxy.try_send(b"ping".to_vec()).unwrap();
        assert_eq!(
            received_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            *b"ping"
        );
        assert_eq!(exit_state.load(), RelayExitMode::HalfClosed);
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
        let table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![gw4, gw6], None);

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

    #[test]
    fn deny_rule_holds_against_the_address_the_relay_dials() {
        use smolvm_protocol::{EgressRule, RuleAction};
        // The guest names the gateway, the relay dials host loopback. A deny
        // on loopback has to see the dialed address, not just the gateway.
        let gateway: IpAddr = "100.96.0.1".parse().unwrap();
        let policy = EgressPolicy::unrestricted()
            .with_rules(&[EgressRule {
                transport: None,
                cidr: Some("127.0.0.0/8".into()),
                ports: None,
                action: RuleAction::Deny,
            }])
            .unwrap();
        let table = TcpRelayTable::new(None, policy, vec![gateway], None);
        assert!(!table.destination_allowed(SocketAddr::new(gateway, 5432)));
        // Without the deny the same flow is not refused by the rule path.
        let open = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![gateway], None);
        assert!(open.destination_allowed(SocketAddr::new(gateway, 5432)));
    }

    #[test]
    fn dedicated_gateway_service_does_not_weaken_other_egress() {
        let gateway: IpAddr = "100.96.0.1".parse().unwrap();
        let external: IpAddr = "8.8.8.8".parse().unwrap();
        let table = TcpRelayTable::new(
            None,
            EgressPolicy::from_allowed_cidrs(Some(&[])),
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
        let mediated = table.with_intercept(Some(crate::StreamInterception::Mediated(
            crate::MediatedBinding {
                endpoint: crate::InterceptEndpoint {
                    addr: "127.0.0.1:43123".parse().unwrap(),
                    token: [9; 32],
                },
                machine_id: [7; 16],
                parent_id: [0; 16],
            },
        )));
        assert!(matches!(
            mediated.outbound_target(SocketAddr::new(gateway, 10_081)),
            RelayTarget::Connect(address) if address == "127.0.0.1:40081".parse().unwrap()
        ));
    }

    #[test]
    fn guest_fin_drops_to_proxy_channel() {
        let (to_proxy, from_smoltcp) = mpsc::sync_channel(1);
        let rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        // A closed or FIN-received socket has may_recv() == false
        assert!(!socket.may_recv());
        let mut connection = test_connection_with(to_proxy, socket);

        relay_flow_data(&mut connection, &mut [0u8; RELAY_BUFFER_BYTES]);

        // to_proxy in the connection must have been dropped (set to None)
        assert!(connection.to_proxy.is_none());
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
            NewTcpConnection {
                destination: server_addr,
                relay_target: RelayTarget::Connect(server_addr),
                from_smoltcp: from_smoltcp_rx,
                to_smoltcp: to_smoltcp_tx,
                exit_state: exit_state.clone(),
                proxy_wake: RelayWaker::standalone(),
                watch_opening: None,
            },
            wake_pipe,
            &exit_state,
        )
        .unwrap();

        assert_eq!(relay_exit, RelayExitMode::Graceful);
        server_thread.join().unwrap();
    }

    #[test]
    fn intercept_target_announces_the_destination_before_guest_bytes() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = crate::InterceptEndpoint {
            addr: listener.local_addr().unwrap(),
            token: [0x5a; smolvm_protocol::intercept::TOKEN_LEN],
        };
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);

        let (from_smoltcp_tx, from_smoltcp_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (to_smoltcp_tx, to_smoltcp_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let wake_pipe = Arc::new(WakePipe::new());
        let exit_state = RelayExitState::new();
        from_smoltcp_tx.send(b"\x16\x03\x01hello".to_vec()).unwrap();
        drop(from_smoltcp_tx);

        let interceptor = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let announced = endpoint.read_preamble(&mut stream).unwrap();
            stream
                .write_all(&[smolvm_protocol::intercept::VERDICT_CONNECTED])
                .unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(b"ack").unwrap();
            (announced, buf[..n].to_vec())
        });

        let relay_exit = tcp_relay_loop(
            NewTcpConnection {
                destination,
                relay_target: RelayTarget::Intercept {
                    endpoint,
                    destination,
                },
                from_smoltcp: from_smoltcp_rx,
                to_smoltcp: to_smoltcp_tx,
                exit_state: exit_state.clone(),
                proxy_wake: RelayWaker::standalone(),
                watch_opening: None,
            },
            wake_pipe,
            &exit_state,
        )
        .unwrap();
        assert_eq!(relay_exit, RelayExitMode::Graceful);
        let (announced, first_bytes) = interceptor.join().unwrap();
        assert_eq!(announced, destination);
        assert_eq!(first_bytes, b"\x16\x03\x01hello");
        assert_eq!(to_smoltcp_rx.recv().unwrap(), b"ack");
    }

    #[test]
    fn only_https_flows_are_redirected_to_the_interceptor() {
        let endpoint = crate::InterceptEndpoint {
            addr: "127.0.0.1:1".parse().unwrap(),
            token: [0; smolvm_protocol::intercept::TOKEN_LEN],
        };
        let gateway = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));
        let table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![gateway], None)
            .with_intercept(Some(crate::StreamInterception::Https(endpoint)));
        let https = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        let http = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 80);
        let gateway_https = SocketAddr::new(gateway, 443);
        assert!(matches!(
            table.outbound_target(https),
            RelayTarget::Intercept { destination, .. } if destination == https
        ));
        assert!(matches!(table.outbound_target(http), RelayTarget::Connect(addr) if addr == http));
        assert!(matches!(
            table.outbound_target(gateway_https),
            RelayTarget::Connect(addr) if addr.ip().is_loopback()
        ));
        let plain = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None);
        assert!(
            matches!(plain.outbound_target(https), RelayTarget::Connect(addr) if addr == https)
        );
    }

    /// `--block-private --allow-private 100.81.17.207/32` with a `--credential`
    /// bound to that host: the reopened range is admitted by a static allow
    /// rule, and the flow must still reach the interceptor, or the guest's
    /// placeholder goes to the origin verbatim (issue #2024).
    #[test]
    fn a_range_reopened_with_allow_private_is_still_intercepted() {
        let endpoint = crate::InterceptEndpoint {
            addr: "127.0.0.1:1".parse().unwrap(),
            token: [0; smolvm_protocol::intercept::TOKEN_LEN],
        };
        let gateway = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));
        let egress = EgressPolicy::unrestricted()
            .with_private_floor(&["100.81.17.207/32".to_string()])
            .unwrap();
        let reopened_https = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 81, 17, 207)), 443);
        let reopened_http = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 81, 17, 207)), 80);
        let public_https = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)), 443);

        let credential = TcpRelayTable::new(None, egress.clone(), vec![gateway], None)
            .with_intercept(Some(crate::StreamInterception::Https(endpoint)));
        assert!(credential.destination_allowed(reopened_https));
        for https in [reopened_https, public_https] {
            assert!(matches!(
                credential.outbound_target(https),
                RelayTarget::Intercept { destination, .. } if destination == https
            ));
        }
        assert!(matches!(
            credential.outbound_target(reopened_http),
            RelayTarget::Connect(addr) if addr == reopened_http
        ));

        let all_tcp = TcpRelayTable::new(None, egress, vec![gateway], None)
            .with_intercept(Some(crate::StreamInterception::AllTcp(endpoint)));
        for destination in [reopened_https, reopened_http] {
            assert!(matches!(
                all_tcp.outbound_target(destination),
                RelayTarget::Intercept { destination: actual, .. } if actual == destination
            ));
        }
    }

    #[test]
    fn external_interceptor_receives_all_tcp_destinations() {
        let endpoint = crate::InterceptEndpoint {
            addr: "127.0.0.1:1234".parse().unwrap(),
            token: [1; smolvm_protocol::intercept::TOKEN_LEN],
        };
        let gateway = "100.96.0.1".parse().unwrap();
        let table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![gateway], None)
            .with_intercept(Some(crate::StreamInterception::AllTcp(endpoint)));
        for address in [
            "192.0.2.1:80",
            "192.0.2.1:443",
            "192.0.2.1:22",
            "[2001:db8::1]:8443",
            "100.96.0.1:8080",
        ] {
            let requested = address.parse().unwrap();
            assert!(matches!(table.outbound_target(requested),
                RelayTarget::Intercept { endpoint: actual, destination }
                    if actual == endpoint && destination == requested));
        }
    }

    #[test]
    fn mediated_decision_precedes_origin_dial_and_preserves_first_bytes() {
        use std::net::TcpListener;

        for decision in [Decision::Deny, Decision::AllowDirect, Decision::Redirect] {
            let origin = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin_addr = origin.local_addr().unwrap();
            origin.set_nonblocking(true).unwrap();
            let broker = TcpListener::bind("127.0.0.1:0").unwrap();
            let binding = crate::MediatedBinding {
                endpoint: crate::InterceptEndpoint {
                    addr: broker.local_addr().unwrap(),
                    token: [0x5a; 32],
                },
                machine_id: [7; 16],
                parent_id: [3; 16],
            };
            let destination: SocketAddr = "1.1.1.1:443".parse().unwrap();
            let broker_thread = thread::spawn(move || {
                let (mut stream, _) = broker.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let prelude = FlowPrelude::read_from(&mut stream, &binding.endpoint.token).unwrap();
                assert_eq!(prelude.machine_id, binding.machine_id);
                assert_eq!(prelude.parent_id, binding.parent_id);
                assert_eq!(prelude.destination, destination);
                assert_eq!(prelude.initial_bytes, b"hello");
                // Nothing may have reached the origin while the broker is
                // deciding, including a direct-allow candidate.
                assert!(
                    matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
                );
                decision.write_to(&mut stream).unwrap();
                if decision == Decision::Redirect {
                    stream.write_all(b"redirected").unwrap();
                }
                if decision == Decision::AllowDirect {
                    origin.set_nonblocking(false).unwrap();
                    let (mut upstream, _) = origin.accept().unwrap();
                    let mut data = [0; 5];
                    upstream.read_exact(&mut data).unwrap();
                    assert_eq!(&data, b"hello");
                    upstream.write_all(b"direct").unwrap();
                }
                if decision == Decision::Deny {
                    assert!(
                        matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
                    );
                }
            });
            let (guest_tx, guest_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
            let (reply_tx, reply_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
            guest_tx.send(b"hello".to_vec()).unwrap();
            drop(guest_tx);
            let state = RelayExitState::new();
            let result = tcp_relay_loop(
                NewTcpConnection {
                    destination,
                    relay_target: RelayTarget::Mediated {
                        binding,
                        destination,
                        direct_address: origin_addr,
                        direct_allowed: true,
                        audit: EgressPolicy::unrestricted(),
                    },
                    from_smoltcp: guest_rx,
                    to_smoltcp: reply_tx,
                    exit_state: state.clone(),
                    proxy_wake: RelayWaker::standalone(),
                    watch_opening: None,
                },
                Arc::new(WakePipe::new()),
                &state,
            );
            broker_thread.join().unwrap();
            if decision == Decision::Deny {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            } else {
                assert!(result.is_ok());
                assert_eq!(
                    reply_rx.recv().unwrap(),
                    if decision == Decision::Redirect {
                        b"redirected".to_vec()
                    } else {
                        b"direct".to_vec()
                    }
                );
            }
        }
    }

    #[test]
    fn mediated_hold_handles_server_first_and_payload_cap() {
        use std::net::TcpListener;

        for payload in [None, Some(vec![b'x'; MAX_INITIAL_BYTES + 808])] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let binding = crate::MediatedBinding {
                endpoint: crate::InterceptEndpoint {
                    addr: listener.local_addr().unwrap(),
                    token: [4; 32],
                },
                machine_id: [5; 16],
                parent_id: [0; 16],
            };
            let destination: SocketAddr = "1.1.1.1:25".parse().unwrap();
            let expected = payload.clone();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let prelude = FlowPrelude::read_from(&mut stream, &binding.endpoint.token).unwrap();
                if expected.is_some() {
                    assert_eq!(prelude.initial_bytes, vec![b'x'; MAX_INITIAL_BYTES]);
                } else {
                    assert!(prelude.initial_bytes.is_empty());
                }
                Decision::Redirect.write_to(&mut stream).unwrap();
                if expected.is_some() {
                    let mut rest = vec![0; 808];
                    stream.read_exact(&mut rest).unwrap();
                    assert_eq!(rest, vec![b'x'; 808]);
                }
                stream.write_all(b"greeting").unwrap();
            });
            let (guest_tx, guest_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
            let (reply_tx, reply_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
            if let Some(payload) = payload {
                guest_tx.send(payload).unwrap();
            }
            let state = RelayExitState::new();
            let relay = thread::spawn(move || {
                tcp_relay_loop(
                    NewTcpConnection {
                        destination,
                        relay_target: RelayTarget::Mediated {
                            binding,
                            destination,
                            direct_address: destination,
                            direct_allowed: false,
                            audit: EgressPolicy::unrestricted(),
                        },
                        from_smoltcp: guest_rx,
                        to_smoltcp: reply_tx,
                        exit_state: state.clone(),
                        proxy_wake: RelayWaker::standalone(),
                        watch_opening: None,
                    },
                    Arc::new(WakePipe::new()),
                    &state,
                )
            });
            assert_eq!(
                reply_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                b"greeting"
            );
            drop(guest_tx);
            assert!(relay.join().unwrap().is_ok());
            server.join().unwrap();
        }
    }

    #[test]
    fn interceptor_failure_never_connects_directly() {
        use std::net::TcpListener;

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let destination = upstream.local_addr().unwrap();
        for reject in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = crate::InterceptEndpoint {
                addr: listener.local_addr().unwrap(),
                token: [1; smolvm_protocol::intercept::TOKEN_LEN],
            };
            let interceptor = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                assert_eq!(endpoint.read_preamble(&mut stream).unwrap(), destination);
                if reject {
                    stream.write_all(&[111]).unwrap();
                }
            });
            let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
            sender.send(b"guest payload".to_vec()).unwrap();
            let (reply, _receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
            assert!(tcp_relay_loop(
                NewTcpConnection {
                    destination,
                    relay_target: RelayTarget::Intercept {
                        endpoint,
                        destination
                    },
                    from_smoltcp: receiver,
                    to_smoltcp: reply,
                    exit_state: RelayExitState::new(),
                    proxy_wake: RelayWaker::standalone(),
                    watch_opening: None,
                },
                Arc::new(WakePipe::new()),
                &RelayExitState::new(),
            )
            .is_err());
            interceptor.join().unwrap();
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    /// An Ethernet link both ends of a test flow share.
    struct TestLink {
        queue: std::collections::VecDeque<Vec<u8>>,
    }

    struct TestRx(Vec<u8>);
    struct TestTx<'a>(&'a mut std::collections::VecDeque<Vec<u8>>);

    impl smoltcp::phy::RxToken for TestRx {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
        }
    }

    impl smoltcp::phy::TxToken for TestTx<'_> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut frame = vec![0; len];
            let result = f(&mut frame);
            self.0.push_back(frame);
            result
        }
    }

    impl Device for TestLink {
        type RxToken<'a>
            = TestRx
        where
            Self: 'a;
        type TxToken<'a>
            = TestTx<'a>
        where
            Self: 'a;

        fn receive(
            &mut self,
            _: smoltcp::time::Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let frame = self.queue.pop_front()?;
            Some((TestRx(frame), TestTx(&mut self.queue)))
        }

        fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
            Some(TestTx(&mut self.queue))
        }

        fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
            let mut caps = smoltcp::phy::DeviceCapabilities::default();
            caps.medium = smoltcp::phy::Medium::Ethernet;
            caps.max_transmission_unit = 1514;
            caps
        }
    }

    /// An interface like the production gateway's: 100.96.0.1/30, accepting
    /// flows to any destination.
    fn test_interface(link: &mut TestLink) -> Interface {
        use smoltcp::iface::Config;
        use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress([
                0x02, 0, 0, 0, 0, 1,
            ]))),
            link,
            smoltcp::time::Instant::ZERO,
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
        interface.set_any_ip(true);
        interface
    }

    /// The `(source, destination)` of a TCP segment in an Ethernet frame.
    fn tcp_tuple(frame: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
        use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpPacket};
        let ethernet = EthernetFrame::new_checked(frame).ok()?;
        if ethernet.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }
        let ip = Ipv4Packet::new_checked(ethernet.payload()).ok()?;
        if ip.next_header() != IpProtocol::Tcp {
            return None;
        }
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        Some((
            SocketAddr::new(IpAddr::V4(ip.src_addr()), tcp.src_port()),
            SocketAddr::new(IpAddr::V4(ip.dst_addr()), tcp.dst_port()),
        ))
    }

    /// One pass of the poll loop: route every queued frame to its flow's set
    /// (or the guest stand-in's), service the flows, let the guest send.
    fn poll_round(
        table: &mut TcpRelayTable,
        interface: &mut Interface,
        link: &mut TestLink,
        guest: &mut SocketSet<'_>,
        now_ms: i64,
    ) -> Vec<NewTcpConnection> {
        let now = smoltcp::time::Instant::from_millis(now_ms);
        while let Some(frame) = link.queue.front() {
            match tcp_tuple(frame)
                .and_then(|(source, destination)| table.flow_for(source, destination))
            {
                Some(flow) => {
                    table.ingress(flow, interface, link, now);
                }
                None => {
                    let neighbor = tcp_tuple(frame).is_none();
                    interface.poll_ingress_single(now, link, guest);
                    if neighbor {
                        table.touch_all();
                    }
                }
            }
        }
        let new_connections = table.service(interface, link, now);
        while !matches!(interface.poll_egress(now, link, guest), PollResult::None) {}
        new_connections
    }

    #[test]
    fn aborted_connection_sends_rst_to_the_guest_before_cleanup() {
        use smoltcp::wire::IpAddress;
        let mut link = TestLink {
            queue: Default::default(),
        };
        let mut interface = test_interface(&mut link);
        let mut guest = SocketSet::new(vec![]);
        let mut table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None);

        // The "guest" dials an external destination; the relay pre-creates the
        // intercepting listen socket exactly like the poll loop does on SYN.
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)), 40_000);
        assert!(table.create_tcp_socket(source, destination));
        let client = guest.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 4096]),
            tcp::SocketBuffer::new(vec![0u8; 4096]),
        ));
        guest
            .get_mut::<tcp::Socket>(client)
            .connect(
                interface.context(),
                (IpAddress::v4(192, 0, 2, 10), 443),
                40_000,
            )
            .unwrap();

        let mut now_ms = 0;
        let mut new_connections = Vec::new();
        for _ in 0..20 {
            now_ms += 10;
            new_connections.extend(poll_round(
                &mut table,
                &mut interface,
                &mut link,
                &mut guest,
                now_ms,
            ));
            if !new_connections.is_empty()
                && guest.get::<tcp::Socket>(client).state() == tcp::State::Established
            {
                break;
            }
        }
        assert_eq!(
            guest.get::<tcp::Socket>(client).state(),
            tcp::State::Established,
            "handshake must complete before the abort is simulated"
        );
        assert_eq!(new_connections.len(), 1);

        // The host-side connect failed: the relay reports Abort. The aborted
        // flow must keep its socket until the RST is on the wire, or the guest
        // never learns and hangs until its own timeout.
        new_connections[0].exit_state.store(RelayExitMode::Abort);
        new_connections[0].exit_state.notify(&WakePipe::new());
        for _ in 0..20 {
            now_ms += 10;
            poll_round(&mut table, &mut interface, &mut link, &mut guest, now_ms);
            if guest.get::<tcp::Socket>(client).state() == tcp::State::Closed {
                break;
            }
        }
        assert_eq!(
            guest.get::<tcp::Socket>(client).state(),
            tcp::State::Closed,
            "guest never received the RST for the aborted connection"
        );
        assert!(!table.has_socket_for(&source, &destination));
    }

    #[test]
    fn idle_flows_are_not_serviced_on_every_pass() {
        use smoltcp::wire::IpAddress;
        let mut link = TestLink {
            queue: Default::default(),
        };
        let mut interface = test_interface(&mut link);
        let mut guest = SocketSet::new(vec![]);
        let mut table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        for port in 40_000..40_050u16 {
            let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)), port);
            assert!(table.create_tcp_socket(source, destination));
            let client = guest.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 1024]),
                tcp::SocketBuffer::new(vec![0u8; 1024]),
            ));
            guest
                .get_mut::<tcp::Socket>(client)
                .connect(
                    interface.context(),
                    (IpAddress::v4(192, 0, 2, 10), 443),
                    port,
                )
                .unwrap();
        }
        let mut established = 0;
        for now_ms in (10..400).step_by(10) {
            established +=
                poll_round(&mut table, &mut interface, &mut link, &mut guest, now_ms).len();
        }
        assert_eq!(established, 50);
        // Every flow is open and quiet: nothing is queued for the next pass.
        assert!(table.touched.is_empty());
        assert!(table.poll_queue.take().is_empty());
    }

    #[test]
    fn refused_guest_port_is_reported_once_per_port() {
        let mut reported = HashSet::new();
        assert!(first_refusal_of_guest_port(&mut reported, 8888));
        assert!(!first_refusal_of_guest_port(&mut reported, 8888));
        assert!(!first_refusal_of_guest_port(&mut reported, 8888));
        assert!(first_refusal_of_guest_port(&mut reported, 9000));
    }

    #[test]
    fn published_connection_refused_by_the_guest_is_noted_for_its_port() {
        let mut link = TestLink {
            queue: Default::default(),
        };
        let mut interface = test_interface(&mut link);
        let gateway = Ipv4Addr::new(100, 96, 0, 1);

        // Host side of the published connection: any connected stream will do.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let host_client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_host_server, _) = listener.accept().unwrap();

        // Nothing listens on the "guest" port, so the SYN is answered with RST,
        // exactly as a guest kernel answers when the server is bound to
        // 127.0.0.1 only.
        let mut guest = SocketSet::new(vec![]);
        let mut table = TcpRelayTable::new(None, EgressPolicy::unrestricted(), vec![], None);
        let guest_port = SocketAddr::new(IpAddr::V4(gateway), 8888);
        assert!(table.create_published_socket(&mut interface, gateway, guest_port, host_client));

        for now_ms in 1..=20 {
            assert!(poll_round(
                &mut table,
                &mut interface,
                &mut link,
                &mut guest,
                now_ms * 10
            )
            .is_empty());
            if table.active_connections() == 0 {
                break;
            }
        }
        assert_eq!(
            table.active_connections(),
            0,
            "refused connection was not reaped"
        );
        assert!(table.unaccepted_guest_ports.contains(&8888));
        assert!(table.used_published_ports.is_empty());
    }
}
