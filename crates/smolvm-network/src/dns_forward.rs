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
//!   * otherwise sends the query to the first upstream, and at each of
//!     [`RESEND_AFTER`] to the next one in turn, until an answer arrives or
//!     [`UPSTREAM_TIMEOUT`] passes. A datagram lost on the way would otherwise
//!     cost the guest its own retry timer, 5 s for glibc and Go. (Timing the
//!     resends from each upstream's measured round trip was tried and lost:
//!     a resolver slow under a burst, such as Tailscale's, answered later
//!     without the early copies, not sooner.)
//!
//! Upstreams are the host's resolvers, in the order its resolver config lists
//! them, as glibc tries `resolv.conf` entries. Unlike glibc, a resolver that
//! stays silent while another answers is moved to the back of the order for
//! [`SLOW_UPSTREAM_PENALTY`], so one dead resolver costs the first lookup
//! 250 ms and later lookups nothing. A SERVFAIL or REFUSED answer is held back
//! while an upstream that has not been asked yet can be tried.
//!
//! The forwarder owns no thread: its caller polls [`Forwarder::sockets`] and
//! calls [`Forwarder::service`].

use crate::dns_cache::{CacheKey, DnsCache, Query};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// How long an upstream exchange may take, resends included. Shorter than the
/// 5 s a guest resolver waits before its own retry.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_millis(3500);
/// When an unanswered query is sent again, to the next upstream, counted from
/// the first send.
pub const RESEND_AFTER: [Duration; 4] = [
    Duration::from_millis(250),
    Duration::from_millis(750),
    Duration::from_millis(1500),
    Duration::from_millis(2500),
];
/// How long an upstream that stayed silent while another answered goes to the
/// back of the order.
pub const SLOW_UPSTREAM_PENALTY: Duration = Duration::from_secs(30);
/// Upstream exchanges in flight at once, at most.
pub const MAX_INFLIGHT: usize = 256;
/// Largest DNS message accepted back.
pub const DNS_MAX_MSG: usize = 4096;
/// Receive buffer for the loopback listener.
const LISTENER_RECV_BUFFER: usize = 4 << 20;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_REFUSED: u8 = 5;

/// One upstream exchange: its sockets and every query waiting on it.
struct Exchange<W> {
    /// One unconnected socket per address family in use, created on demand.
    sockets: Vec<UdpSocket>,
    /// The bytes sent upstream (the first waiter's query), resent on retry.
    query: Vec<u8>,
    /// The first waiter's parsed question, when the query is cacheable.
    parsed: Option<Query>,
    /// The first waiter is the one whose query was sent; the rest asked the
    /// same question while it was in flight.
    waiters: Vec<(W, Option<Query>)>,
    /// Upstreams in the order to try them.
    order: Vec<SocketAddr>,
    /// Upstreams sent to so far, in order.
    sent_to: Vec<SocketAddr>,
    /// When the query goes to the next upstream, if it has sends left.
    resend_due: Option<Instant>,
    /// A SERVFAIL or REFUSED answer, delivered only if nothing better comes.
    fallback: Option<Vec<u8>>,
    started: Instant,
}

impl<W> Exchange<W> {
    fn next_resend(&self) -> Option<Instant> {
        self.resend_due
    }

    /// The upstream the next send goes to.
    fn next_target(&self) -> SocketAddr {
        self.order[self.sent_to.len() % self.order.len()]
    }

    fn deadline(&self) -> Instant {
        self.started + UPSTREAM_TIMEOUT
    }

    /// Send the query to the next upstream in turn.
    fn send_next(&mut self) -> std::io::Result<()> {
        let target = self.next_target();
        self.sent_to.push(target);
        self.resend_due = RESEND_AFTER
            .get(self.sent_to.len() - 1)
            .map(|after| self.started + *after);
        let socket = match self.sockets.iter().position(|s| {
            s.local_addr()
                .is_ok_and(|a| a.is_ipv4() == target.is_ipv4())
        }) {
            Some(index) => &self.sockets[index],
            None => {
                self.sockets.push(bind_for(target)?);
                self.sockets.last().expect("just pushed")
            }
        };
        socket.send_to(&self.query, target).map(|_| ())
    }

    /// Whether some upstream has not been asked yet.
    fn untried_left(&self) -> bool {
        self.order.iter().any(|u| !self.sent_to.contains(u))
    }

    /// Whether `bytes` from `from` answers this exchange's query.
    fn accepts(&self, from: SocketAddr, bytes: &[u8]) -> bool {
        self.order.contains(&from)
            && match &self.parsed {
                Some(parsed) => parsed.answered_by(bytes),
                None => bytes.len() >= 2 && bytes[..2] == self.query[..2],
            }
    }
}

/// An unconnected non-blocking socket for upstreams of `target`'s family.
fn bind_for(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind: SocketAddr = if target.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn rcode(bytes: &[u8]) -> u8 {
    bytes.get(3).map_or(0, |b| b & 0x0f)
}

/// An answer for one waiter; `None` means no upstream answered.
pub type Answer<W> = (W, Option<Vec<u8>>);

/// Cache plus in-flight exchanges. Not thread-safe; owned by one thread.
pub struct Forwarder<W> {
    cache: DnsCache,
    exchanges: HashMap<u64, Exchange<W>>,
    by_key: HashMap<CacheKey, u64>,
    next_slot: u64,
    recv_buf: Vec<u8>,
    /// Upstreams moved to the back of the order, until when.
    penalized: HashMap<SocketAddr, Instant>,
}

impl<W> Default for Forwarder<W> {
    fn default() -> Self {
        Self {
            cache: DnsCache::new(),
            exchanges: HashMap::new(),
            by_key: HashMap::new(),
            next_slot: 0,
            recv_buf: vec![0u8; DNS_MAX_MSG],
            penalized: HashMap::new(),
        }
    }
}

impl<W> Forwarder<W> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take `query` for `waiter`, to be answered by `upstreams` (in order).
    /// Returns the answer at once when it can (a cache hit, or a failure to
    /// send); otherwise the answer comes out of a later [`Self::service`].
    pub fn submit(
        &mut self,
        waiter: W,
        query: Vec<u8>,
        upstreams: &[SocketAddr],
        now: Instant,
    ) -> Option<Answer<W>> {
        if upstreams.is_empty() {
            return Some((waiter, None));
        }
        let parsed = Query::parse(&query, upstreams);
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
        if self.exchanges.len() >= MAX_INFLIGHT || query.len() < 2 {
            return Some((waiter, None));
        }
        let mut exchange = Exchange {
            sockets: Vec::new(),
            query,
            waiters: vec![(waiter, parsed.clone())],
            parsed,
            order: self.order(upstreams, now),
            sent_to: Vec::new(),
            resend_due: None,
            fallback: None,
            started: now,
        };
        // A send that fails at once (no route to this upstream) moves on to
        // the next; only when every one fails is the guest told nothing.
        while exchange.send_next().is_err() {
            if !exchange.untried_left() {
                let (waiter, _) = exchange.waiters.pop().expect("one waiter");
                return Some((waiter, None));
            }
        }
        let slot = self.next_slot;
        self.next_slot = self.next_slot.wrapping_add(1);
        if let Some(parsed) = &exchange.parsed {
            self.by_key.insert(parsed.key.clone(), slot);
        }
        self.exchanges.insert(slot, exchange);
        None
    }

    /// `upstreams` in the order to try them now: the configured order, with
    /// the ones recently found silent moved to the back.
    fn order(&mut self, upstreams: &[SocketAddr], now: Instant) -> Vec<SocketAddr> {
        self.penalized.retain(|_, until| *until > now);
        let (mut good, slow): (Vec<_>, Vec<_>) = upstreams
            .iter()
            .copied()
            .partition(|u| !self.penalized.contains_key(u));
        good.extend(slow);
        good
    }

    /// The upstream sockets to poll for readability, each with its slot.
    pub fn sockets(&self) -> impl Iterator<Item = (u64, &UdpSocket)> {
        self.exchanges
            .iter()
            .flat_map(|(slot, e)| e.sockets.iter().map(move |s| (*slot, s)))
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
            // A resent query can draw more than one reply; the first good one
            // wins. A failure answer waits while an untried upstream remains.
            let mut answer = None;
            'sockets: for index in 0..exchange.sockets.len() {
                while let Ok((len, from)) = exchange.sockets[index].recv_from(&mut self.recv_buf) {
                    let bytes = &self.recv_buf[..len];
                    if !exchange.accepts(from, bytes) {
                        continue;
                    }
                    let failed = matches!(rcode(bytes), RCODE_SERVFAIL | RCODE_REFUSED);
                    if failed && exchange.untried_left() {
                        exchange.fallback = Some(bytes.to_vec());
                        let _ = exchange.send_next();
                        continue;
                    }
                    answer = Some((from, bytes.to_vec()));
                    break 'sockets;
                }
            }
            if let Some((from, bytes)) = answer {
                let exchange = self.finish(*slot);
                self.note_answer(&exchange, from, now);
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
                    sends = exchange.sent_to.len(),
                    waiting = exchange.waiters.len(),
                    "DNS upstreams gave no answer"
                );
                let fallback = exchange.fallback.clone();
                answer_all(exchange, fallback.as_deref(), &mut out);
            } else {
                let exchange = self.exchanges.get_mut(&slot).expect("present");
                if exchange.next_resend().is_some_and(|due| due <= now) {
                    let _ = exchange.send_next();
                }
            }
        }
        out
    }

    /// `from` answered: it is healthy, and any upstream asked before it that
    /// stayed silent goes to the back of the order for a while.
    fn note_answer(&mut self, exchange: &Exchange<W>, from: SocketAddr, now: Instant) {
        self.penalized.remove(&from);
        if let Some(first) = exchange.sent_to.iter().position(|u| *u == from) {
            for silent in &exchange.sent_to[..first] {
                if *silent != from {
                    self.penalized.insert(*silent, now + SLOW_UPSTREAM_PENALTY);
                }
            }
        }
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

/// Open a non-blocking host UDP socket connected to `upstream` and send the
/// query. The single response is collected later.
pub fn start_udp_query(upstream: SocketAddr, query: &[u8]) -> std::io::Result<UdpSocket> {
    let socket = bind_for(upstream)?;
    socket.connect(upstream)?;
    socket.send(query)?;
    Ok(socket)
}

/// Serve DNS for a TSI machine on a loopback UDP port: the hypervisor sends
/// each guest query here and relays the answer back. Queries go to
/// `upstreams`, in order. Returns the bound address; the thread stops once
/// `stop` says so (checked at least every 250 ms).
pub fn serve_loopback(
    upstreams: Vec<SocketAddr>,
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
        .spawn(move || run_loopback(socket, upstreams, stop))?;
    Ok(local)
}

fn run_loopback(
    socket: UdpSocket,
    upstreams: Vec<SocketAddr>,
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
                    if let Some(answer) =
                        forwarder.submit(peer, buf[..len].to_vec(), &upstreams, now)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::tests::{answer, query};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// How a test resolver treats the queries it gets.
    #[derive(Clone, Copy)]
    enum Mode {
        /// Ignore the first `n`, answer the rest.
        DropFirst(usize),
        /// Answer every query with this RCODE and no records.
        Fail(u8),
    }

    struct Resolver {
        addr: SocketAddr,
        seen: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    }

    impl Drop for Resolver {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    /// A loopback resolver that counts what it received.
    fn resolver(mode: Mode) -> Resolver {
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
                    let reply = match mode {
                        Mode::DropFirst(skip) if count < skip => continue,
                        Mode::DropFirst(_) => answer(&buf[..n], &[(60, [10, 0, 0, 7])]),
                        Mode::Fail(rcode) => {
                            let mut a = answer(&buf[..n], &[]);
                            a[3] = (a[3] & 0xf0) | rcode;
                            a
                        }
                    };
                    let _ = socket.send_to(&reply, peer);
                }
            }
        });
        Resolver { addr, seen, stop }
    }

    /// A resolver that never answers.
    fn dead() -> Resolver {
        resolver(Mode::DropFirst(usize::MAX))
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

    /// Resolve one query through `f` and say how long it took.
    fn lookup(
        f: &mut Forwarder<u16>,
        id: u16,
        name: &str,
        up: &[SocketAddr],
    ) -> (Option<Vec<u8>>, Duration) {
        let started = Instant::now();
        if let Some((_, answer)) = f.submit(id, query(id, name, 1, false), up, started) {
            return (answer, started.elapsed());
        }
        let mut answers = drain(f, 1, UPSTREAM_TIMEOUT + Duration::from_secs(1));
        (answers.pop().and_then(|(_, a)| a), started.elapsed())
    }

    #[test]
    fn a_burst_of_one_name_is_one_upstream_query() {
        let r = resolver(Mode::DropFirst(0));
        let mut f: Forwarder<u16> = Forwarder::new();
        let now = Instant::now();
        for id in 0..256u16 {
            assert!(f
                .submit(id, query(id, "svc.example", 1, false), &[r.addr], now)
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
        assert_eq!(r.seen.load(Ordering::Relaxed), 1);
        // And the next one is a cache hit.
        let hit = f.submit(
            999,
            query(999, "svc.example", 1, false),
            &[r.addr],
            Instant::now(),
        );
        assert!(matches!(hit, Some((999, Some(_)))));
    }

    #[test]
    fn a_lost_query_is_resent_well_before_the_guest_would_retry() {
        let r = resolver(Mode::DropFirst(1));
        let mut f: Forwarder<u16> = Forwarder::new();
        let (answer, took) = lookup(&mut f, 1, "lossy.example", &[r.addr]);
        assert!(answer.is_some());
        assert!(took < Duration::from_secs(1), "{took:?}");
        assert_eq!(r.seen.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_dead_upstream_answers_every_waiter_with_a_timeout() {
        let r = dead();
        let mut f: Forwarder<u16> = Forwarder::new();
        let now = Instant::now();
        f.submit(1, query(1, "dead.example", 1, false), &[r.addr], now);
        f.submit(2, query(2, "dead.example", 1, false), &[r.addr], now);
        let answers = drain(&mut f, 2, UPSTREAM_TIMEOUT + Duration::from_secs(1));
        assert_eq!(answers.len(), 2);
        assert!(answers.iter().all(|(_, a)| a.is_none()));
        assert!(f.sockets().next().is_none());
    }

    #[test]
    fn a_dead_first_upstream_costs_one_lookup_a_quarter_second_and_the_rest_nothing() {
        let (gone, good) = (dead(), resolver(Mode::DropFirst(0)));
        let up = [gone.addr, good.addr];
        let mut f: Forwarder<u16> = Forwarder::new();
        let (answer, took) = lookup(&mut f, 1, "one.example", &up);
        assert!(answer.is_some());
        assert!(
            took >= RESEND_AFTER[0] && took < Duration::from_millis(600),
            "{took:?}"
        );
        // The silent one now goes last: a new name is answered at once.
        let (answer, took) = lookup(&mut f, 2, "two.example", &up);
        assert!(answer.is_some());
        assert!(took < Duration::from_millis(150), "{took:?}");
        assert_eq!(gone.seen.load(Ordering::Relaxed), 1);
        assert_eq!(good.seen.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn every_upstream_is_tried_before_giving_up() {
        let (a, b, c) = (dead(), dead(), resolver(Mode::DropFirst(0)));
        let mut f: Forwarder<u16> = Forwarder::new();
        let (answer, took) = lookup(&mut f, 1, "third.example", &[a.addr, b.addr, c.addr]);
        assert!(answer.is_some(), "the third resolver answers");
        assert!(took < Duration::from_secs(1), "{took:?}");
    }

    #[test]
    fn a_failure_answer_waits_for_the_next_upstream() {
        let (refusing, good) = (resolver(Mode::Fail(5)), resolver(Mode::DropFirst(0)));
        let mut f: Forwarder<u16> = Forwarder::new();
        let (answer, took) = lookup(&mut f, 1, "x.example", &[refusing.addr, good.addr]);
        let answer = answer.expect("answered");
        assert_eq!(answer[3] & 0x0f, 0, "the good upstream's NOERROR wins");
        assert!(
            took < Duration::from_millis(200),
            "no resend timer was needed: {took:?}"
        );
        assert_eq!(refusing.seen.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn when_every_upstream_fails_the_failure_is_passed_on() {
        let (a, b) = (resolver(Mode::Fail(2)), resolver(Mode::Fail(2)));
        let mut f: Forwarder<u16> = Forwarder::new();
        let (answer, took) = lookup(&mut f, 1, "x.example", &[a.addr, b.addr]);
        assert_eq!(answer.expect("answered")[3] & 0x0f, 2);
        assert!(took < Duration::from_millis(200), "{took:?}");
    }

    #[test]
    fn an_answer_from_somewhere_else_is_ignored() {
        let r = dead();
        let mut f: Forwarder<u16> = Forwarder::new();
        let q = query(7, "spoof.example", 1, false);
        f.submit(7, q.clone(), &[r.addr], Instant::now());
        // A third party that learns our socket's port sends a forged answer.
        let (_, sock) = f.sockets().next().unwrap();
        let port = sock.local_addr().unwrap().port();
        let forger = UdpSocket::bind("127.0.0.1:0").unwrap();
        forger
            .send_to(&answer(&q, &[(60, [6, 6, 6, 6])]), ("127.0.0.1", port))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let slots: Vec<u64> = f.sockets().map(|(slot, _)| slot).collect();
        assert!(f.service(&slots, Instant::now()).is_empty());
    }

    #[test]
    fn the_loopback_server_answers_a_burst() {
        let r = resolver(Mode::DropFirst(0));
        let halt = Arc::new(AtomicBool::new(false));
        let halt2 = halt.clone();
        let addr = serve_loopback(
            vec![dead().addr, r.addr],
            Arc::new(move || halt2.load(Ordering::Relaxed)),
        )
        .unwrap();
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
        assert!(r.seen.load(Ordering::Relaxed) <= 2);
        halt.store(true, Ordering::Relaxed);
    }
}
