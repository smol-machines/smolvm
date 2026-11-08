//! Upstream DNS exchanges for guest queries: cache, coalescing and resends.
//!
//! [`Forwarder`] is the single place a machine's DNS queries leave the host,
//! on either network backend. The virtio-net gateway's relay thread hands it
//! the queries the egress policy allowed (`dns_relay`); for TSI machines the
//! hypervisor routes every guest UDP query on port 53 to a loopback endpoint
//! served by [`serve_loopback`]. In both cases the policy decision is made
//! before a query gets here.
//!
//! For each query it:
//!   * answers from the [`DnsCache`] when a fresh answer is held,
//!   * otherwise joins an exchange already in flight for the same question, so
//!     a burst of one name costs one upstream query,
//!   * otherwise opens a non-blocking connected socket to the upstream and
//!     sends the query, resending it at [`RESEND_AFTER`] until an answer
//!     arrives or [`UPSTREAM_TIMEOUT`] passes. A datagram lost on the way would
//!     otherwise cost the guest its own retry timer, 5 s for glibc and Go.
//!
//! The forwarder owns no thread: its caller polls [`Forwarder::sockets`] and
//! calls [`Forwarder::service`].

use crate::dns_cache::{CacheKey, DnsCache, Query};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// How long an upstream exchange may take, resends included. Shorter than the
/// 5 s a guest resolver waits before its own retry.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_millis(3500);
/// When an unanswered query is sent again, counted from the first send.
pub const RESEND_AFTER: [Duration; 4] = [
    Duration::from_millis(250),
    Duration::from_millis(750),
    Duration::from_millis(1500),
    Duration::from_millis(2500),
];
/// Upstream exchanges in flight at once, at most.
pub const MAX_INFLIGHT: usize = 256;
/// Largest DNS message accepted back.
pub const DNS_MAX_MSG: usize = 4096;
/// Receive buffer for the loopback listener.
const LISTENER_RECV_BUFFER: usize = 4 << 20;

/// One upstream exchange: a connected socket and every query waiting on it.
struct Exchange<W> {
    socket: UdpSocket,
    /// The bytes sent upstream (the first waiter's query), resent on retry.
    query: Vec<u8>,
    /// The first waiter's parsed question, when the query is cacheable.
    parsed: Option<Query>,
    /// The first waiter is the one whose query was sent; the rest asked the
    /// same question while it was in flight.
    waiters: Vec<(W, Option<Query>)>,
    started: Instant,
    sends: usize,
}

impl<W> Exchange<W> {
    fn next_resend(&self) -> Option<Instant> {
        RESEND_AFTER
            .get(self.sends - 1)
            .map(|after| self.started + *after)
    }

    fn deadline(&self) -> Instant {
        self.started + UPSTREAM_TIMEOUT
    }
}

/// An answer for one waiter; `None` means the upstream never answered.
pub type Answer<W> = (W, Option<Vec<u8>>);

/// Cache plus in-flight exchanges. Not thread-safe; owned by one thread.
pub struct Forwarder<W> {
    cache: DnsCache,
    exchanges: HashMap<u64, Exchange<W>>,
    by_key: HashMap<CacheKey, u64>,
    next_slot: u64,
    recv_buf: Vec<u8>,
}

impl<W> Default for Forwarder<W> {
    fn default() -> Self {
        Self {
            cache: DnsCache::new(),
            exchanges: HashMap::new(),
            by_key: HashMap::new(),
            next_slot: 0,
            recv_buf: vec![0u8; DNS_MAX_MSG],
        }
    }
}

impl<W> Forwarder<W> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take `query` for `waiter`, bound for `upstream`. Returns the answer at
    /// once when it can (a cache hit, or a failure to send); otherwise the
    /// answer comes out of a later [`Self::service`].
    pub fn submit(
        &mut self,
        waiter: W,
        query: Vec<u8>,
        upstream: SocketAddr,
        now: Instant,
    ) -> Option<Answer<W>> {
        let parsed = Query::parse(&query, upstream.ip());
        if let Some(parsed) = &parsed {
            if let Some(answer) = self.cache.get(parsed, now) {
                return Some((waiter, Some(answer)));
            }
            if let Some(exchange) = self
                .by_key
                .get(&parsed.key)
                .and_then(|slot| self.exchanges.get_mut(slot))
            {
                exchange.waiters.push((waiter, Some(parsed.clone())));
                return None;
            }
        }
        if self.exchanges.len() >= MAX_INFLIGHT {
            return Some((waiter, None));
        }
        let socket = match start_udp_query(upstream, &query) {
            Ok(socket) => socket,
            Err(_) => return Some((waiter, None)),
        };
        let slot = self.next_slot;
        self.next_slot = self.next_slot.wrapping_add(1);
        if let Some(parsed) = &parsed {
            self.by_key.insert(parsed.key.clone(), slot);
        }
        self.exchanges.insert(
            slot,
            Exchange {
                socket,
                query,
                waiters: vec![(waiter, parsed.clone())],
                parsed,
                started: now,
                sends: 1,
            },
        );
        None
    }

    /// The upstream sockets to poll for readability, each with its slot.
    pub fn sockets(&self) -> impl Iterator<Item = (u64, &UdpSocket)> {
        self.exchanges.iter().map(|(slot, e)| (*slot, &e.socket))
    }

    /// When [`Self::service`] next has a resend or a deadline to act on.
    pub fn next_due(&self) -> Option<Instant> {
        self.exchanges
            .values()
            .map(|e| e.next_resend().unwrap_or(e.deadline()).min(e.deadline()))
            .min()
    }

    /// Collect answers from the sockets of `ready` slots, resend what is
    /// overdue and give up on what has run out of time. Returns the answers.
    pub fn service(&mut self, ready: &[u64], now: Instant) -> Vec<Answer<W>> {
        let mut out = Vec::new();
        for slot in ready {
            let Some(exchange) = self.exchanges.get_mut(slot) else {
                continue;
            };
            // A resent query can draw more than one reply; the first that
            // answers this question wins.
            let mut answer = None;
            while let Ok(len) = exchange.socket.recv(&mut self.recv_buf) {
                let bytes = &self.recv_buf[..len];
                if exchange
                    .parsed
                    .as_ref()
                    .is_none_or(|p| p.answered_by(bytes))
                {
                    answer = Some(bytes.to_vec());
                    break;
                }
            }
            if let Some(bytes) = answer {
                let exchange = self.finish(*slot);
                if let Some(parsed) = &exchange.parsed {
                    self.cache.insert(parsed, &bytes, now);
                }
                answer_all(exchange, Some(&bytes), &mut out);
            }
        }
        let slots: Vec<u64> = self.exchanges.keys().copied().collect();
        for slot in slots {
            let expired = self.exchanges[&slot].deadline() <= now;
            if expired {
                let exchange = self.finish(slot);
                tracing::debug!(
                    sends = exchange.sends,
                    waiting = exchange.waiters.len(),
                    "DNS upstream gave no answer"
                );
                answer_all(exchange, None, &mut out);
            } else {
                let exchange = self.exchanges.get_mut(&slot).expect("present");
                if exchange.next_resend().is_some_and(|due| due <= now) {
                    exchange.sends += 1;
                    let _ = exchange.socket.send(&exchange.query);
                }
            }
        }
        out
    }

    /// Lookups answered from the cache and lookups that were not.
    pub fn cache_stats(&self) -> (u64, u64) {
        self.cache.stats()
    }

    fn finish(&mut self, slot: u64) -> Exchange<W> {
        let exchange = self.exchanges.remove(&slot).expect("present");
        if let Some(parsed) = &exchange.parsed {
            self.by_key.remove(&parsed.key);
        }
        exchange
    }
}

/// Answer every waiter of a finished exchange. `answer` is the upstream's
/// reply to the first waiter; the others get it under their own id and
/// question bytes.
fn answer_all<W>(exchange: Exchange<W>, answer: Option<&[u8]>, out: &mut Vec<Answer<W>>) {
    for (index, (waiter, parsed)) in exchange.waiters.into_iter().enumerate() {
        let bytes = match (answer, parsed) {
            (Some(answer), _) if index == 0 => Some(answer.to_vec()),
            (Some(answer), Some(parsed)) => parsed.adopt(answer),
            _ => None,
        };
        out.push((waiter, bytes));
    }
}

/// Open a non-blocking host UDP socket connected to the upstream resolver and
/// send the query. The single response is collected later.
pub fn start_udp_query(upstream: SocketAddr, query: &[u8]) -> std::io::Result<UdpSocket> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(upstream)?;
    socket.set_nonblocking(true)?;
    socket.send(query)?;
    Ok(socket)
}

/// Serve DNS for a TSI machine on a loopback UDP port: the hypervisor sends
/// each guest query here and relays the answer back. Queries go to
/// `upstream`. Returns the bound address; the thread stops once `stop` says
/// so (checked at least every 250 ms).
pub fn serve_loopback(
    upstream: SocketAddr,
    stop: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
) -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_nonblocking(true)?;
    // A burst arrives faster than one wakeup drains it, and the default
    // receive buffer holds only a couple of hundred small datagrams.
    let _ = socket2::SockRef::from(&socket).set_recv_buffer_size(LISTENER_RECV_BUFFER);
    let local = socket.local_addr()?;
    std::thread::Builder::new()
        .name("smolvm-dns".into())
        .spawn(move || run_loopback(socket, upstream, stop))?;
    Ok(local)
}

fn run_loopback(
    socket: UdpSocket,
    upstream: SocketAddr,
    stop: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
) {
    use polling::{Event, Events, Poller};
    let Ok(poller) = Poller::new() else {
        return;
    };
    // Only loopback peers are served: the hypervisor's own sockets.
    let reply = |socket: &UdpSocket, (peer, answer): Answer<SocketAddr>| {
        if let Some(answer) = answer {
            let _ = socket.send_to(&answer, peer);
        }
    };
    let mut forwarder: Forwarder<SocketAddr> = Forwarder::new();
    let mut buf = vec![0u8; DNS_MAX_MSG];
    // Key 0 is the listener, `index + 1` an upstream socket. (`usize::MAX` is
    // the poller's own notification key and cannot be registered.)
    const LISTENER: usize = 0;
    loop {
        if stop() {
            return;
        }
        let now = Instant::now();
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) if peer.ip().is_loopback() => {
                    if let Some(answer) = forwarder.submit(peer, buf[..len].to_vec(), upstream, now)
                    {
                        reply(&socket, answer);
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        // SAFETY: every socket added here is deleted below before the
        // forwarder can drop it.
        let _ = unsafe { poller.add(&socket, Event::readable(LISTENER)) };
        let slots: Vec<u64> = forwarder.sockets().map(|(slot, _)| slot).collect();
        for (index, (_, sock)) in forwarder.sockets().enumerate() {
            let _ = unsafe { poller.add(sock, Event::readable(index + 1)) };
        }
        let wait = forwarder
            .next_due()
            .map(|due| due.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(250))
            .min(Duration::from_millis(250));
        let mut events = Events::new();
        let _ = poller.wait(&mut events, Some(wait));
        let ready: Vec<u64> = events
            .iter()
            .filter(|e| e.key != LISTENER)
            .filter_map(|e| slots.get(e.key - 1).copied())
            .collect();
        let _ = poller.delete(&socket);
        for (_, sock) in forwarder.sockets() {
            let _ = poller.delete(sock);
        }
        for answer in forwarder.service(&ready, Instant::now()) {
            reply(&socket, answer);
        }
    }
}

/// The resolver a TSI machine's forwarder queries: `addr` on port 53.
pub fn upstream_addr(addr: IpAddr) -> SocketAddr {
    SocketAddr::new(addr, 53)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::tests::{answer, query};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A loopback "resolver" that answers every query after `drop_first`
    /// datagrams have been ignored, counting what it received.
    fn resolver(drop_first: usize) -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen2, stop2) = (seen.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = socket.recv_from(&mut buf) {
                    let count = seen2.fetch_add(1, Ordering::Relaxed);
                    if count >= drop_first {
                        let _ = socket.send_to(&answer(&buf[..n], &[(60, [10, 0, 0, 7])]), peer);
                    }
                }
            }
        });
        (addr, seen, stop)
    }

    /// Drive a forwarder until `want` answers are out or `limit` passes.
    fn drain<W>(f: &mut Forwarder<W>, want: usize, limit: Duration) -> Vec<Answer<W>> {
        let start = Instant::now();
        let mut out = Vec::new();
        while out.len() < want && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(5));
            let ready: Vec<u64> = f.sockets().map(|(slot, _)| slot).collect();
            out.extend(f.service(&ready, Instant::now()));
        }
        out
    }

    #[test]
    fn a_burst_of_one_name_is_one_upstream_query() {
        let (upstream, seen, stop) = resolver(0);
        let mut f: Forwarder<u16> = Forwarder::new();
        let now = Instant::now();
        for id in 0..256u16 {
            assert!(f
                .submit(id, query(id, "svc.example", 1, false), upstream, now)
                .is_none());
        }
        let answers = drain(&mut f, 256, Duration::from_secs(2));
        assert_eq!(answers.len(), 256);
        for (id, bytes) in &answers {
            let bytes = bytes.as_ref().expect("answered");
            assert_eq!(
                &bytes[..2],
                &id.to_be_bytes(),
                "each waiter gets its own id"
            );
        }
        assert_eq!(seen.load(Ordering::Relaxed), 1);
        // And the next one is a cache hit.
        let hit = f.submit(
            999,
            query(999, "svc.example", 1, false),
            upstream,
            Instant::now(),
        );
        assert!(matches!(hit, Some((999, Some(_)))));
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn a_lost_query_is_resent_well_before_the_guest_would_retry() {
        let (upstream, seen, stop) = resolver(1);
        let mut f: Forwarder<u16> = Forwarder::new();
        let started = Instant::now();
        assert!(f
            .submit(1, query(1, "lossy.example", 1, false), upstream, started)
            .is_none());
        let answers = drain(&mut f, 1, Duration::from_secs(3));
        assert!(answers[0].1.is_some());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(seen.load(Ordering::Relaxed), 2);
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn a_dead_upstream_answers_every_waiter_with_a_timeout() {
        let (upstream, _seen, stop) = resolver(usize::MAX);
        let mut f: Forwarder<u16> = Forwarder::new();
        let now = Instant::now();
        f.submit(1, query(1, "dead.example", 1, false), upstream, now);
        f.submit(2, query(2, "dead.example", 1, false), upstream, now);
        let answers = drain(&mut f, 2, UPSTREAM_TIMEOUT + Duration::from_secs(1));
        assert_eq!(answers.len(), 2);
        assert!(answers.iter().all(|(_, a)| a.is_none()));
        assert!(f.sockets().next().is_none());
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn the_loopback_server_answers_a_burst() {
        let (upstream, seen, stop) = resolver(0);
        let halt = Arc::new(AtomicBool::new(false));
        let halt2 = halt.clone();
        let addr =
            serve_loopback(upstream, Arc::new(move || halt2.load(Ordering::Relaxed))).unwrap();
        let clients: Vec<_> = (0..256u16)
            .map(|id| {
                std::thread::spawn(move || {
                    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                    s.send_to(&query(id, "burst.example", 1, false), addr)
                        .unwrap();
                    let mut buf = [0u8; 512];
                    let (n, _) = s.recv_from(&mut buf).expect("answered within a second");
                    assert_eq!(&buf[..2], &id.to_be_bytes());
                    n
                })
            })
            .collect();
        for client in clients {
            assert!(client.join().unwrap() > 12);
        }
        assert!(seen.load(Ordering::Relaxed) <= 2);
        halt.store(true, Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
    }
}
