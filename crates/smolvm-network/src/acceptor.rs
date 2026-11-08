//! A live set of published host TCP ports, all accepted on one thread.
//!
//! Every published port used to own one or two listener threads, which is why
//! a machine was capped at 64 mappings. Here every listener is registered on a
//! single [`Poller`] and one thread accepts for all of them, so a machine can
//! publish thousands of ports (Testcontainers, Docker's ephemeral range) for
//! the cost of their sockets.
//!
//! The set is changed while it runs with [`TcpAcceptorSet::replace`]: new host
//! ports are bound first, all or nothing, so a taken port fails the call and
//! changes nothing; removed ports are closed by the time it returns
//! (connections they already accepted carry on); a kept host port moved to
//! another guest port hands its next connections there.

use crate::publish_bind::{self, BoundSockets};
use crate::{PortMapping, PortProtocol};
use polling::{Event, Events, Poller};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Pause after an accept error other than "no connection pending" (EMFILE and
/// the like), so a listener that stays readable cannot spin the thread.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(25);
/// Connections taken from one listener per readiness event, so one busy port
/// cannot starve the rest.
const ACCEPT_BATCH: usize = 64;

/// One accepted host connection on a published port.
pub struct AcceptedConnection {
    /// The connected host socket, in blocking mode.
    pub stream: TcpStream,
    /// The client that connected.
    pub peer_addr: SocketAddr,
    /// Host port that accepted it.
    pub host_port: u16,
    /// Guest port it should be forwarded to.
    pub guest_port: u16,
}

/// Receives every accepted connection, on the acceptor thread: keep it short.
pub type AcceptHandler = Box<dyn Fn(AcceptedConnection) + Send + Sync>;

/// TCP listeners bound for a set of published ports, not yet accepting.
pub struct BoundTcpPorts(pub(crate) Vec<(PortMapping, BoundSockets<TcpListener>)>);

impl BoundTcpPorts {
    /// Bind every mapping's host port, releasing those already bound on failure.
    pub fn bind(mappings: &[PortMapping]) -> io::Result<Self> {
        let mut bound = Vec::with_capacity(mappings.len());
        for mapping in mappings {
            let sockets = publish_bind::bind_tcp(mapping.host).map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "cannot publish host TCP {}:{} to guest TCP {}: {err}",
                        publish_bind::publish_addr(),
                        mapping.host,
                        mapping.guest,
                    ),
                )
            })?;
            bound.push((*mapping, sockets));
        }
        Ok(Self(bound))
    }

    /// True when nothing is bound.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A running set of published TCP ports sharing one acceptor thread.
pub struct TcpAcceptorSet {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

struct Shared {
    poller: Poller,
    shutdown: AtomicBool,
    registry: Mutex<Registry>,
    /// Serialises [`TcpAcceptorSet::replace`], which binds outside `registry`.
    replacing: Mutex<()>,
}

#[derive(Default)]
struct Registry {
    next_key: usize,
    next_seq: u64,
    /// Host port -> its guest port and listeners.
    ports: HashMap<u16, Port>,
    /// Poller key -> listener.
    listeners: HashMap<usize, Listener>,
}

struct Port {
    guest: u16,
    keys: Vec<usize>,
    /// Publication order, so [`TcpAcceptorSet::mappings`] lists ports stably.
    seq: u64,
}

struct Listener {
    socket: TcpListener,
    host_port: u16,
    loopback_only: bool,
}

impl Shared {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Registry {
    /// Register `bound`'s listeners with `poller`. On failure every listener
    /// this call added is removed again and the error returned.
    fn add(&mut self, poller: &Poller, bound: BoundTcpPorts) -> io::Result<()> {
        let mut added: Vec<u16> = Vec::new();
        for (mapping, sockets) in bound.0 {
            let loopback_only = sockets.loopback_only;
            let mut keys = Vec::with_capacity(2);
            let mut failure = None;
            for socket in sockets.into_sockets() {
                if let Err(err) = socket.set_nonblocking(true) {
                    failure = Some(err);
                    break;
                }
                let key = self.next_key;
                self.next_key += 1;
                // SAFETY: the listener is owned by `self.listeners` and is always
                // deleted from the poller before it is dropped (`remove_port`).
                if let Err(err) = unsafe { poller.add(&socket, Event::readable(key)) } {
                    failure = Some(err);
                    break;
                }
                keys.push(key);
                self.listeners.insert(
                    key,
                    Listener {
                        socket,
                        host_port: mapping.host,
                        loopback_only,
                    },
                );
            }
            let seq = self.next_seq;
            self.next_seq += 1;
            self.ports.insert(
                mapping.host,
                Port {
                    guest: mapping.guest,
                    keys,
                    seq,
                },
            );
            added.push(mapping.host);
            if let Some(err) = failure {
                for host in added {
                    self.remove_port(poller, host);
                }
                return Err(err);
            }
        }
        Ok(())
    }

    fn remove_port(&mut self, poller: &Poller, host: u16) {
        if let Some(port) = self.ports.remove(&host) {
            for key in port.keys {
                if let Some(listener) = self.listeners.remove(&key) {
                    let _ = poller.delete(&listener.socket);
                }
            }
        }
    }

    fn mappings(&self) -> Vec<PortMapping> {
        let mut ports: Vec<(&u16, &Port)> = self.ports.iter().collect();
        ports.sort_by_key(|(_, port)| port.seq);
        ports
            .into_iter()
            .map(|(&host, port)| PortMapping::new(host, port.guest))
            .collect()
    }
}

impl TcpAcceptorSet {
    /// Start accepting on `bound`, handing each connection to `handler`.
    pub fn start(bound: BoundTcpPorts, handler: AcceptHandler) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            poller: Poller::new()?,
            shutdown: AtomicBool::new(false),
            registry: Mutex::new(Registry::default()),
            replacing: Mutex::new(()),
        });
        shared.registry().add(&shared.poller, bound)?;
        let thread_shared = shared.clone();
        let thread = thread::Builder::new()
            .name("smolvm-tcp-publish".into())
            .spawn(move || run(&thread_shared, &handler))?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    /// The published mappings, in the order they were first published.
    pub fn mappings(&self) -> Vec<PortMapping> {
        self.shared.registry().mappings()
    }

    /// Make `next` the published set (TCP mappings only).
    pub fn replace(&self, next: &[PortMapping]) -> io::Result<()> {
        if let Some(udp) = next.iter().find(|m| m.protocol == PortProtocol::Udp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}:{}/udp is not a TCP listener", udp.host, udp.guest),
            ));
        }
        let mut wanted: HashMap<u16, u16> = HashMap::with_capacity(next.len());
        for mapping in next {
            if wanted.insert(mapping.host, mapping.guest).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("host port {} is published twice", mapping.host),
                ));
            }
        }
        let _replacing = self
            .shared
            .replacing
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Bind outside the registry lock: accepting carries on meanwhile.
        let added: Vec<PortMapping> = {
            let registry = self.shared.registry();
            next.iter()
                .filter(|m| !registry.ports.contains_key(&m.host))
                .copied()
                .collect()
        };
        let bound = BoundTcpPorts::bind(&added)?;
        let mut registry = self.shared.registry();
        registry.add(&self.shared.poller, bound)?;
        let removed: Vec<u16> = registry
            .ports
            .keys()
            .filter(|host| !wanted.contains_key(host))
            .copied()
            .collect();
        for host in removed {
            registry.remove_port(&self.shared.poller, host);
        }
        for (host, port) in registry.ports.iter_mut() {
            if let Some(&guest) = wanted.get(host) {
                port.guest = guest;
            }
        }
        Ok(())
    }

    /// Stop accepting and close every listener.
    pub fn close(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        let _ = self.shared.poller.notify();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let mut registry = self.shared.registry();
        let hosts: Vec<u16> = registry.ports.keys().copied().collect();
        for host in hosts {
            registry.remove_port(&self.shared.poller, host);
        }
    }

    /// True once [`Self::close`] ran.
    pub fn is_closed(&self) -> bool {
        self.shared.shutdown.load(Ordering::SeqCst)
    }
}

impl Drop for TcpAcceptorSet {
    fn drop(&mut self) {
        self.close();
    }
}

fn run(shared: &Shared, handler: &AcceptHandler) {
    let mut events = Events::new();
    let mut ready: Vec<usize> = Vec::new();
    let mut accepted: Vec<AcceptedConnection> = Vec::new();
    loop {
        events.clear();
        if let Err(err) = shared.poller.wait(&mut events, None) {
            if err.kind() != io::ErrorKind::Interrupted {
                tracing::warn!(error = %err, "published port readiness failed");
                return;
            }
        }
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        ready.clear();
        ready.extend(events.iter().map(|event| event.key));
        let mut backoff = false;
        {
            let registry = shared.registry();
            for &key in &ready {
                // A port removed after the event was raised is simply gone.
                let Some(listener) = registry.listeners.get(&key) else {
                    continue;
                };
                let guest_port = registry
                    .ports
                    .get(&listener.host_port)
                    .map_or(0, |port| port.guest);
                backoff |= accept_batch(listener, guest_port, &mut accepted);
                // Oneshot readiness: rearm after draining.
                if let Err(err) = shared.poller.modify(&listener.socket, Event::readable(key)) {
                    tracing::warn!(host_port = listener.host_port, error = %err, "published port readiness failed");
                }
            }
        }
        // Outside the lock, so the handler can never stall a replace.
        for connection in accepted.drain(..) {
            handler(connection);
        }
        if backoff {
            thread::sleep(ACCEPT_ERROR_BACKOFF);
        }
    }
}

/// Accept what is pending on `listener`; true when an accept failed.
fn accept_batch(
    listener: &Listener,
    guest_port: u16,
    accepted: &mut Vec<AcceptedConnection>,
) -> bool {
    for _ in 0..ACCEPT_BATCH {
        match listener.socket.accept() {
            Ok((stream, peer_addr)) => {
                if !publish_bind::peer_allowed(listener.loopback_only, &peer_addr) {
                    tracing::debug!(host_port = listener.host_port, %peer_addr, "dropping a non-loopback connection to a loopback-only published port");
                    continue;
                }
                if let Err(err) = stream.set_nonblocking(false) {
                    tracing::debug!(error = %err, "published connection setup failed");
                    continue;
                }
                accepted.push(AcceptedConnection {
                    stream,
                    peer_addr,
                    host_port: listener.host_port,
                    guest_port,
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return false,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                tracing::warn!(host_port = listener.host_port, error = %err, "published port accept failed");
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    /// A port free right now, from below the ephemeral range (32768 and up on
    /// Linux, 49152 on macOS). A port the kernel picks with bind(0) is an
    /// ephemeral one, and the outbound connections other tests in this
    /// process open take ephemeral ports too, so one could land on it before
    /// the test binds it again.
    fn free_port() -> u16 {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let start = 20_000 + std::process::id() % 6_000;
        loop {
            let offset = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let port = (20_000 + (start - 20_000 + offset) % 12_000) as u16;
            if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
                return port;
            }
        }
    }

    fn start(mappings: &[PortMapping]) -> (TcpAcceptorSet, mpsc::Receiver<AcceptedConnection>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let set = TcpAcceptorSet::start(
            BoundTcpPorts::bind(mappings).unwrap(),
            Box::new(move |c| {
                let _ = tx.lock().unwrap().send(c);
            }),
        )
        .unwrap();
        (set, rx)
    }

    /// Raise this test process's open-file limit (macOS starts at 256), as
    /// the launcher does for a machine's VMM process.
    fn raise_fd_limit() {
        #[cfg(unix)]
        // SAFETY: getrlimit/setrlimit on a local struct.
        unsafe {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                limit.rlim_cur = limit.rlim_max.min(4096);
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }
    }

    #[test]
    fn hundreds_of_ports_share_one_thread_and_all_accept() {
        raise_fd_limit();
        let mut mappings = Vec::new();
        while mappings.len() < 300 {
            let port = free_port();
            if !mappings.iter().any(|m: &PortMapping| m.host == port) {
                mappings.push(PortMapping::new(port, 10_000 + mappings.len() as u16));
            }
        }
        let (set, rx) = start(&mappings);
        assert_eq!(set.mappings(), mappings, "listed in publication order");
        for mapping in mappings.iter().step_by(7) {
            let _client = TcpStream::connect((Ipv4Addr::LOCALHOST, mapping.host)).unwrap();
            let accepted = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(accepted.host_port, mapping.host);
            assert_eq!(accepted.guest_port, mapping.guest);
        }
    }

    #[test]
    fn replace_keeps_the_set_when_a_new_port_is_taken() {
        let kept = free_port();
        let (set, rx) = start(&[PortMapping::new(kept, 80)]);
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let free = free_port();
        assert!(set
            .replace(&[PortMapping::new(free, 1), PortMapping::new(taken_port, 2)])
            .is_err());
        assert_eq!(set.mappings(), vec![PortMapping::new(kept, 80)]);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, free)).is_ok());
        let _client = TcpStream::connect((Ipv4Addr::LOCALHOST, kept)).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap().guest_port,
            80
        );
    }

    #[test]
    fn close_releases_every_port() {
        let port = free_port();
        let (mut set, _rx) = start(&[PortMapping::new(port, 80)]);
        set.close();
        assert!(set.mappings().is_empty());
        assert!(TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_secs(1)
        )
        .is_err());
    }
}
