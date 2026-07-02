//! Off-poll-thread DNS resolver for the virtio-net backend.
//!
//! Context
//! =======
//!
//! Guest DNS (UDP/TCP :53) is intercepted by the gateway and forwarded to an
//! upstream resolver (`stack.rs::process_dns_queries` / `process_dns_tcp`). The
//! upstream exchange is a *blocking* host socket round trip with a 2-second
//! timeout. It used to run inline on the single virtio-net poll thread — the
//! thread that owns the smoltcp interface and every one of that VM's TCP/UDP/
//! ICMP sockets. A slow or dead resolver therefore stalled *all* of the guest's
//! traffic for up to 2 seconds (head-of-line block).
//!
//! This module moves that blocking resolution off the poll thread, mirroring
//! the UDP/ICMP relay offload ([`crate::udp_relay`]). The poll loop only:
//!   1. reads a guest query out of its smoltcp DNS socket,
//!   2. applies the egress allow-host policy itself (cheap, no host I/O),
//!   3. hands allowed queries to this relay over a channel, and
//!   4. later picks the answer back up via the shared relay wake + channel and
//!      writes it into the guest socket — never blocking on the resolver.
//!
//! Egress policy (allow/deny, `learn_ip_records`) stays on the poll thread so
//! [`EgressPolicy`](crate::egress::EgressPolicy) is never shared across threads;
//! only the raw upstream forward is offloaded.
//!
//! ```text
//! guest :53 query -> smoltcp gateway socket
//!   -> poll loop: classify (allow-host) -> allowed?
//!        no  -> answer NXDOMAIN/SERVFAIL immediately (no relay)
//!        yes -> assign id, remember reply context, channel (id, query) to relay
//!   -> relay thread: UDP -> non-blocking connected host socket + poller
//!                    TCP -> bounded detached worker (rare path)
//!   -> answer bytes -> channel back -> reply_wake
//!   -> poll loop: learn A/AAAA records, write answer into the guest socket
//! ```
//!
//! DNS is low-volume and its answers are quick, so the tables here are small and
//! loss under saturation just makes a guest see a normal DNS timeout.

use crate::queues::WakePipe;
use crate::virtio_net_log;
use polling::{Event, Events};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket as HostUdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// DNS service port.
const DNS_PORT: u16 = 53;
/// Upstream exchange timeout, matching the previous inline behaviour.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// Largest DNS message we accept back (EDNS0 / DNS-over-TCP bound).
const DNS_MAX_MSG: usize = 4096;
/// Max in-flight queries buffered in each channel direction.
const CHANNEL_CAPACITY: usize = 256;
/// Max concurrent in-flight UDP queries with a live host socket.
const MAX_INFLIGHT_UDP: usize = 256;
/// Max concurrent in-flight DNS-over-TCP worker threads.
const MAX_INFLIGHT_TCP: usize = 64;
/// Relay thread poll ceiling so shutdown and deadlines are noticed promptly.
const RELAY_POLL_MAX_MS: u64 = 250;

/// Which upstream transport a query must use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

/// A query handed from the poll loop to the relay thread.
pub struct DnsQuery {
    /// Correlation id chosen by the poll loop; echoed back in the response.
    pub id: u64,
    /// Transport to reach the upstream resolver on.
    pub transport: DnsTransport,
    /// Upstream resolver address.
    pub upstream: Ipv4Addr,
    /// Raw DNS query message (no TCP length prefix).
    pub query: Vec<u8>,
}

/// A resolved answer handed back to the poll loop.
pub struct DnsResponse {
    /// The id of the originating [`DnsQuery`].
    pub id: u64,
    /// Raw DNS answer message, or `None` on error/timeout (guest sees a normal
    /// DNS timeout — identical to the old inline `forward` error path).
    pub answer: Option<Vec<u8>>,
}

/// Channel pair connecting the poll loop and the DNS relay thread.
pub struct DnsRelayChannels {
    /// Poll loop -> relay thread.
    pub to_relay: SyncSender<DnsQuery>,
    /// Relay thread -> poll loop.
    pub from_relay: Receiver<DnsResponse>,
    /// Wakes the relay thread after `to_relay` sends.
    pub relay_thread_wake: WakePipe,
}

/// Start the DNS relay thread. Returns the poll-loop-side channel endpoints.
///
/// `reply_wake` is the smoltcp poll loop's existing relay wake pipe — pulsed
/// whenever an answer is queued so the loop wakes to deliver it. The thread
/// exits when `shutdown` reports true (checked at least once per
/// [`RELAY_POLL_MAX_MS`]).
pub fn start_dns_relay(
    reply_wake: Arc<WakePipe>,
    shutdown: Arc<dyn Fn() -> bool + Send + Sync>,
) -> DnsRelayChannels {
    let (to_relay_tx, to_relay_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let (from_relay_tx, from_relay_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let relay_thread_wake = WakePipe::new();
    let thread_wake = relay_thread_wake.clone();

    let _ = thread::Builder::new()
        .name("smolvm-dns-relay".into())
        .spawn(move || {
            run_dns_relay(
                to_relay_rx,
                from_relay_tx,
                thread_wake,
                reply_wake,
                shutdown,
            );
        });

    DnsRelayChannels {
        to_relay: to_relay_tx,
        from_relay: from_relay_rx,
        relay_thread_wake,
    }
}

/// One in-flight UDP query: a non-blocking connected host socket awaiting its
/// single response, and the deadline after which we give up.
struct InflightUdp {
    socket: HostUdpSocket,
    deadline: Instant,
}

/// Send one answer back to the poll loop. Returns `true` if the caller should
/// wake the poll loop, `false` if the channel is closed (relay should exit).
fn deliver_answer(inbound: &SyncSender<DnsResponse>, id: u64, answer: Option<Vec<u8>>) -> bool {
    match inbound.try_send(DnsResponse { id, answer }) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            virtio_net_log!(
                "virtio-net: dropping DNS answer id={} (inbound queue full)",
                id
            );
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn run_dns_relay(
    outbound: Receiver<DnsQuery>,
    inbound: SyncSender<DnsResponse>,
    wake: WakePipe,
    reply_wake: Arc<WakePipe>,
    shutdown: Arc<dyn Fn() -> bool + Send + Sync>,
) {
    let mut inflight: std::collections::HashMap<u64, InflightUdp> =
        std::collections::HashMap::new();
    let mut recv_buf = vec![0u8; DNS_MAX_MSG];
    let tcp_inflight = Arc::new(AtomicUsize::new(0));

    loop {
        if shutdown() {
            return;
        }

        let mut woke_reply = false;

        // Outbound: queries handed over by the poll loop.
        loop {
            match outbound.try_recv() {
                Ok(query) => match query.transport {
                    DnsTransport::Udp => {
                        if inflight.len() >= MAX_INFLIGHT_UDP {
                            virtio_net_log!(
                                "virtio-net: dropping DNS query id={} (in-flight UDP table full)",
                                query.id
                            );
                            woke_reply |= deliver_answer(&inbound, query.id, None);
                            continue;
                        }
                        let upstream = SocketAddr::new(IpAddr::V4(query.upstream), DNS_PORT);
                        match start_udp_query(upstream, &query.query) {
                            Ok(socket) => {
                                inflight.insert(
                                    query.id,
                                    InflightUdp {
                                        socket,
                                        deadline: Instant::now() + UPSTREAM_TIMEOUT,
                                    },
                                );
                            }
                            Err(err) => {
                                virtio_net_log!(
                                    "virtio-net: DNS/UDP upstream send failed id={} error={}",
                                    query.id,
                                    err
                                );
                                woke_reply |= deliver_answer(&inbound, query.id, None);
                            }
                        }
                    }
                    DnsTransport::Tcp => {
                        spawn_tcp_query(&inbound, &reply_wake, &tcp_inflight, query);
                    }
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }

        // Inbound: block on "wake OR any in-flight UDP socket readable", exactly
        // like the UDP relay. Each socket is registered at key `slot + 1`.
        let poller = wake.poller();
        let ids: Vec<u64> = inflight.keys().copied().collect();
        for (slot, id) in ids.iter().enumerate() {
            // SAFETY: the socket is owned by `inflight` and is deleted from the
            // poller below before it can be dropped.
            let _ = unsafe { poller.add(&inflight[id].socket, Event::readable(slot + 1)) };
        }

        // Wake no later than the nearest deadline so timeouts fire on time.
        let now = Instant::now();
        let mut wait = Duration::from_millis(RELAY_POLL_MAX_MS);
        for f in inflight.values() {
            let remaining = f.deadline.saturating_duration_since(now);
            if remaining < wait {
                wait = remaining;
            }
        }

        let mut events = Events::new();
        let _ = poller.wait(&mut events, Some(wait));

        let mut ready: Vec<bool> = vec![false; ids.len()];
        for event in events.iter() {
            if event.key >= 1 && event.key - 1 < ready.len() {
                ready[event.key - 1] = true;
            }
        }

        // Deregister every socket before mutating `inflight`.
        for id in &ids {
            let _ = poller.delete(&inflight[id].socket);
        }

        // Deliver ready answers; expire the rest past their deadline.
        let now = Instant::now();
        for (slot, id) in ids.iter().enumerate() {
            if ready[slot] {
                let answer = inflight
                    .get(id)
                    .and_then(|f| match f.socket.recv(&mut recv_buf) {
                        Ok(len) => Some(recv_buf[..len].to_vec()),
                        Err(_) => None,
                    });
                match answer {
                    Some(bytes) => {
                        inflight.remove(id);
                        woke_reply |= deliver_answer(&inbound, *id, Some(bytes));
                    }
                    // Spurious readiness with nothing to read: leave it in flight
                    // to be retried or expired.
                    None if inflight.get(id).is_some_and(|f| f.deadline <= now) => {
                        inflight.remove(id);
                        woke_reply |= deliver_answer(&inbound, *id, None);
                    }
                    None => {}
                }
            } else if inflight.get(id).is_some_and(|f| f.deadline <= now) {
                inflight.remove(id);
                woke_reply |= deliver_answer(&inbound, *id, None);
            }
        }

        if woke_reply {
            reply_wake.wake();
        }
    }
}

/// Open a non-blocking host UDP socket connected to the upstream resolver and
/// send the query. The single response is collected later by the poll section.
fn start_udp_query(upstream: SocketAddr, query: &[u8]) -> std::io::Result<HostUdpSocket> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = HostUdpSocket::bind(bind)?;
    socket.connect(upstream)?;
    socket.set_nonblocking(true)?;
    socket.send(query)?;
    Ok(socket)
}

/// Resolve a DNS-over-TCP query on a bounded, detached worker thread.
///
/// DNS/TCP is the rare fallback path (truncated/large answers). Rather than
/// build a non-blocking length-prefixed TCP state machine, each query gets its
/// own short-lived worker so a slow TCP resolver never blocks the UDP fast path
/// or the poll loop. The worker count is capped; over the cap the query is
/// answered as a timeout.
fn spawn_tcp_query(
    inbound: &SyncSender<DnsResponse>,
    reply_wake: &Arc<WakePipe>,
    tcp_inflight: &Arc<AtomicUsize>,
    query: DnsQuery,
) {
    if tcp_inflight.load(Ordering::Relaxed) >= MAX_INFLIGHT_TCP {
        virtio_net_log!(
            "virtio-net: dropping DNS/TCP query id={} (worker cap reached)",
            query.id
        );
        if deliver_answer(inbound, query.id, None) {
            reply_wake.wake();
        }
        return;
    }
    tcp_inflight.fetch_add(1, Ordering::Relaxed);
    let worker_inbound = inbound.clone();
    let worker_wake = reply_wake.clone();
    let worker_inflight = tcp_inflight.clone();
    let id = query.id;
    let spawned = thread::Builder::new()
        .name("smolvm-dns-tcp".into())
        .spawn(move || {
            let upstream = SocketAddr::new(IpAddr::V4(query.upstream), DNS_PORT);
            let answer = forward_dns_query_tcp(upstream, &query.query).ok();
            if deliver_answer(&worker_inbound, id, answer) {
                worker_wake.wake();
            }
            worker_inflight.fetch_sub(1, Ordering::Relaxed);
        });
    if spawned.is_err() {
        // Could not spawn: undo the reservation and answer as a timeout.
        tcp_inflight.fetch_sub(1, Ordering::Relaxed);
        if deliver_answer(inbound, id, None) {
            reply_wake.wake();
        }
    }
}

/// Forward one DNS query to the upstream resolver over TCP (length-prefixed, per
/// RFC 1035 §4.2.2) and return the raw response message. Blocking host TCP
/// exchange with a short timeout — runs only on a detached worker, never the
/// poll thread.
fn forward_dns_query_tcp(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    let len = u16::try_from(query.len())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "DNS query too large for TCP"))?;
    let mut stream = TcpStream::connect_timeout(&upstream, UPSTREAM_TIMEOUT)?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(query)?;
    stream.flush()?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > DNS_MAX_MSG {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "upstream DNS/TCP response length out of range",
        ));
    }
    let mut response = vec![0u8; resp_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// `start_udp_query` sends off a non-blocking connected socket; its single
    /// response is collected later without blocking. Exercises the real fn
    /// against a loopback echo "resolver" (arbitrary port, so no port-53 dep).
    #[test]
    fn start_udp_query_sends_and_receives_nonblocking() {
        let upstream = HostUdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let resolver = thread::spawn(move || {
            let mut buf = [0u8; 512];
            upstream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let (n, peer) = upstream.recv_from(&mut buf).unwrap();
            upstream.send_to(&buf[..n], peer).unwrap();
        });

        let sock = start_udp_query(upstream_addr, b"\x12\x34hello-dns").unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = [0u8; 512];
        loop {
            match sock.recv(&mut buf) {
                Ok(n) => {
                    assert_eq!(&buf[..n], b"\x12\x34hello-dns");
                    break;
                }
                Err(_) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("no DNS answer: {e}"),
            }
        }
        resolver.join().unwrap();
    }

    /// End-to-end through the relay thread: a live upstream on port 53 needs
    /// privileges, so this proves the *offload contract* — the poll thread only
    /// sends/receives channel messages and never blocks — using an unreachable
    /// upstream that must resolve to a timeout answer, promptly and off-thread.
    #[test]
    fn poll_thread_never_blocks_on_dead_resolver() {
        let reply_wake = Arc::new(WakePipe::new());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let channels = start_dns_relay(
            reply_wake.clone(),
            Arc::new(move || stop_flag.load(Ordering::Relaxed)),
        );

        // 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed unroutable, so the
        // upstream never answers and the relay must time it out for us.
        let started = Instant::now();
        channels
            .to_relay
            .send(DnsQuery {
                id: 7,
                transport: DnsTransport::Udp,
                upstream: Ipv4Addr::new(192, 0, 2, 1),
                query: b"\x00\x00query".to_vec(),
            })
            .unwrap();
        channels.relay_thread_wake.wake();

        // The send returned immediately (offloaded); this thread is free.
        assert!(started.elapsed() < Duration::from_millis(50));

        // The answer (a timeout -> None) arrives via the channel, driven by the
        // relay thread, within a bit over the 2s upstream timeout.
        let resp = channels
            .from_relay
            .recv_timeout(Duration::from_secs(4))
            .expect("relay must always answer, even on timeout");
        assert_eq!(resp.id, 7);
        assert!(resp.answer.is_none());

        stop.store(true, Ordering::Relaxed);
        channels.relay_thread_wake.wake();
    }

    /// The real `forward_dns_query_tcp` resolves against a length-prefixed host
    /// TCP resolver (arbitrary loopback port) and returns the raw, unprefixed
    /// answer message. This is the code the detached DNS/TCP worker runs.
    #[test]
    fn forward_dns_query_tcp_round_trips() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Minimal DNS-over-TCP resolver: read the length-prefixed query, reply
        // with a length-prefixed canned answer.
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut len_buf = [0u8; 2];
            sock.read_exact(&mut len_buf).unwrap();
            let qlen = u16::from_be_bytes(len_buf) as usize;
            let mut q = vec![0u8; qlen];
            sock.read_exact(&mut q).unwrap();
            assert_eq!(&q, b"tcp-query");
            let answer = b"answer-bytes";
            sock.write_all(&(answer.len() as u16).to_be_bytes())
                .unwrap();
            sock.write_all(answer).unwrap();
        });

        let resp = forward_dns_query_tcp(addr, b"tcp-query").unwrap();
        assert_eq!(resp, b"answer-bytes");
        server.join().unwrap();
    }
}
