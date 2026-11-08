//! Guest side of the credential tunnel.
//!
//! The host intercepts HTTPS that leaves on the machine's NIC (or, with TSI,
//! through libkrun's socket proxy). HTTPS the guest kernel sends anywhere else
//! would carry the placeholder upstream unreplaced: a VPN route (Tailscale's
//! `tailscale0` for a tailnet host or an exit node, WireGuard, OpenVPN), a
//! container's traffic that its namespace forwards into such a route, or a
//! local proxy whose own network stack sends it out encrypted (Tailscale's
//! userspace-networking SOCKS5 and HTTP proxies). When the host enables the
//! tunnel ([`guest_env::CREDENTIAL_TUNNEL`]) the agent, in every network
//! namespace in the guest:
//!
//! 1. installs nftables rules ([`nft`]) that redirect TCP port 443 leaving
//!    through any interface that would not carry it in the clear to somewhere
//!    already covered, HTTPS forwarded for another namespace, and connections
//!    to a local proxy, to listeners the agent opens in that namespace;
//! 2. hands each redirected connection to the host's interceptor over vsock
//!    ([`ports::CREDENTIAL_TUNNEL`]), with its target and a route token naming
//!    the namespace it came from (or the proxy session);
//! 3. opens the upstream connection when the interceptor asks
//!    ([`ports::CREDENTIAL_DIAL`]) from that namespace, through that proxy,
//!    with [`tunnel::DIAL_MARK`] and [`tunnel::DIAL_DSCP`] so no rule catches
//!    it again: it follows exactly the route the workload's connection would
//!    have taken;
//! 4. keeps the rules in place: each table is owned by a netlink socket the
//!    agent holds, so the kernel refuses a workload's attempt to delete or
//!    flush it, and new namespaces, interfaces and proxies are picked up as
//!    they appear.
//!
//! The interceptor terminates TLS and verifies the upstream certificate on the
//! host, so the guest relays only ciphertext and never holds a credential
//! value.

mod netns;
mod nft;
mod proxy;
mod xtables;

use netns::Link;
use nft::{Family, RuleSet};
use smolvm_protocol::intercept::connect_verdict;
use smolvm_protocol::intercept::tunnel::{self, Flow, Target};
use smolvm_protocol::{guest_env, ports};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Upper bound on the agent's connect to an upstream for the interceptor.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);
/// How often namespaces, interfaces and proxies are rescanned.
const RESCAN: Duration = Duration::from_millis(500);

/// Whether the host enabled the tunnel for this boot.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::CREDENTIAL_TUNNEL).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Install the redirects and start both halves of the tunnel.
pub fn start() {
    let engine = Arc::new(Engine::default());
    // The first pass runs before any workload starts, so the agent's own
    // namespace is covered from the first connection.
    engine.reconcile();
    let dials = engine.clone();
    let _ = thread::Builder::new()
        .name("cred-tunnel-dial".into())
        .spawn(move || {
            if let Err(e) = dials.serve_dials() {
                tracing::warn!(error = %e, "credential tunnel: dial service stopped");
            }
        });
    let _ = thread::Builder::new()
        .name("cred-tunnel-watch".into())
        .spawn(move || engine.watch());
}

/// One network namespace the tunnel covers.
struct Namespace {
    id: u32,
    inode: u64,
    path: PathBuf,
    flows: Listeners,
    proxy: Listeners,
    /// The netlink socket that owns this namespace's tables.
    owner: Option<Mutex<OwnedFd>>,
    /// Wakes the watcher when an interface or address here changes.
    events: Option<OwnedFd>,
    /// What its tables were last built from, and its addresses.
    state: Mutex<NsState>,
}

#[derive(Default)]
struct NsState {
    installed: BTreeMap<Family, RuleSet>,
    addresses: BTreeSet<IpAddr>,
}

impl Namespace {
    fn run_in<T, F>(&self, f: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        netns::run_in(&self.path, self.inode, f)
    }
}

/// A listener pair (IPv4, IPv6) on one port, and a flag that stops its
/// accept threads.
struct Listeners {
    port: u16,
    sockets: Vec<Arc<TcpListener>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Listeners {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for socket in &self.sockets {
            // SAFETY: shutting down a listening socket this struct owns wakes
            // its blocked accept, which then sees `stop`.
            unsafe { libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR) };
        }
    }
}

/// What the proxy front recorded for one intercepted proxy connection.
struct ProxySession {
    namespace: u32,
    proxy: SocketAddr,
    replay: proxy::Replay,
}

#[derive(Default)]
struct Engine {
    namespaces: Mutex<BTreeMap<u64, Arc<Namespace>>>,
    next_namespace: AtomicU32,
    sessions: Mutex<HashMap<u32, Arc<ProxySession>>>,
    next_session: AtomicU32,
}

#[derive(Clone, Copy)]
enum Role {
    Flows,
    Proxy,
}

impl Engine {
    fn namespace(&self, id: u32) -> Option<Arc<Namespace>> {
        self.namespaces
            .lock()
            .unwrap()
            .values()
            .find(|ns| ns.id == id)
            .cloned()
    }

    /// Reconcile whenever an interface or address changes in a namespace the
    /// tunnel covers (a VPN coming up, a container's veth appearing), and at
    /// least every [`RESCAN`] for new namespaces and proxies.
    fn watch(self: Arc<Self>) {
        loop {
            let namespaces: Vec<Arc<Namespace>> =
                self.namespaces.lock().unwrap().values().cloned().collect();
            let mut fds: Vec<libc::pollfd> = namespaces
                .iter()
                .filter_map(|ns| ns.events.as_ref())
                .map(|fd| libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: poll on descriptors the namespaces above keep open.
            unsafe {
                libc::poll(
                    fds.as_mut_ptr(),
                    fds.len() as libc::nfds_t,
                    RESCAN.as_millis() as libc::c_int,
                )
            };
            for ns in &namespaces {
                if let Some(events) = &ns.events {
                    netns::drain(events);
                }
            }
            self.reconcile();
        }
    }

    /// Bring every namespace's rules in line with what it holds now, and put
    /// back any that went missing.
    fn reconcile(self: &Arc<Self>) {
        let found = netns::discover();
        let proxies = netns::proxy_listeners();
        let own = netns::own_inode().ok();
        // Forget namespaces nothing holds any more; their listeners would
        // otherwise keep them alive.
        self.namespaces
            .lock()
            .unwrap()
            .retain(|inode, _| found.contains_key(inode));
        for (inode, found) in found {
            // Bound first: a guard in the match scrutinee would live through
            // the arms, which lock the map again.
            let known = self.namespaces.lock().unwrap().get(&inode).cloned();
            let ns = match known {
                Some(ns) => ns,
                None => match self.open(&found, Some(inode) == own) {
                    Ok(ns) => {
                        self.namespaces.lock().unwrap().insert(inode, ns.clone());
                        ns
                    }
                    Err(e) => {
                        tracing::debug!(inode, error = %e, "credential tunnel: namespace skipped");
                        continue;
                    }
                },
            };
            let listeners: Vec<(IpAddr, u16)> = proxies
                .get(&inode)
                .map(|listeners| listeners.iter().copied().collect())
                .unwrap_or_default();
            if let Err(e) = self.refresh(&ns, listeners) {
                tracing::debug!(inode, error = %e, "credential tunnel: namespace refresh failed");
            }
        }
    }

    /// Open listeners and the owning socket in a namespace seen for the
    /// first time.
    fn open(self: &Arc<Self>, found: &netns::Found, own: bool) -> io::Result<Arc<Namespace>> {
        let (flows, proxy, owner, events) = netns::run_in(&found.path, found.inode, move || {
            let flows = bind_pair()?;
            let proxy = bind_pair()?;
            let owner = nft::owner()?;
            let events = netns::events().ok();
            Ok((flows, proxy, owner, events))
        })?;
        let id = if own {
            0
        } else {
            1 + self.next_namespace.fetch_add(1, Ordering::Relaxed)
        };
        let ns = Arc::new(Namespace {
            id,
            inode: found.inode,
            path: found.path.clone(),
            flows: self.listen(id, flows, Role::Flows),
            proxy: self.listen(id, proxy, Role::Proxy),
            owner: Some(Mutex::new(owner)),
            events,
            state: Mutex::new(NsState::default()),
        });
        tracing::info!(
            namespace = id,
            inode = found.inode,
            flows = ns.flows.port,
            proxy = ns.proxy.port,
            "credential tunnel: covering network namespace"
        );
        Ok(ns)
    }

    fn listen(
        self: &Arc<Self>,
        ns: u32,
        (port, sockets): (u16, Vec<TcpListener>),
        role: Role,
    ) -> Listeners {
        let stop = Arc::new(AtomicBool::new(false));
        let sockets: Vec<Arc<TcpListener>> = sockets.into_iter().map(Arc::new).collect();
        for socket in &sockets {
            let socket = socket.clone();
            let stop = stop.clone();
            let engine = self.clone();
            let _ = thread::Builder::new()
                .name("cred-tunnel-accept".into())
                .spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        let client = match socket.accept() {
                            Ok((client, _)) => client,
                            Err(_) if stop.load(Ordering::SeqCst) => break,
                            Err(e) => {
                                tracing::debug!(error = %e, "credential tunnel: accept failed");
                                thread::sleep(Duration::from_millis(50));
                                continue;
                            }
                        };
                        let engine = engine.clone();
                        let _ = thread::Builder::new()
                            .name("cred-tunnel-flow".into())
                            .spawn(move || {
                                let result = match role {
                                    Role::Flows => engine.hand_flow(ns, client),
                                    Role::Proxy => engine.hand_proxy_client(ns, client),
                                };
                                if let Err(e) = result {
                                    tracing::debug!(error = %e, "credential tunnel: flow ended");
                                }
                            });
                    }
                });
        }
        Listeners {
            port,
            sockets,
            stop,
        }
    }

    /// Recompute a namespace's rules and install them if they changed or
    /// went missing.
    fn refresh(&self, ns: &Arc<Namespace>, proxies: Vec<(IpAddr, u16)>) -> io::Result<()> {
        let (flows_port, proxy_port) = (ns.flows.port, ns.proxy.port);
        let (links, addresses) = ns.run_in(|| {
            // Legacy iptables gets the same reply exemption as nf_tables.
            match xtables::ensure_exemptions() {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    chains = n,
                    "credential tunnel: exempted redirect replies in legacy iptables"
                ),
                Err(e) => {
                    tracing::debug!(error = %e, "credential tunnel: legacy iptables exemption")
                }
            }
            netns::links_and_addresses()
        })?;
        let owner = ns
            .owner
            .as_ref()
            .ok_or_else(|| io::Error::other("namespace has no owning socket"))?
            .lock()
            .unwrap();
        let mut state = ns.state.lock().unwrap();
        state.addresses = addresses;
        for family in Family::ALL {
            let rules = rules_for(&links, &proxies, family, flows_port, proxy_port);
            let previous = state.installed.get(&family);
            let intact = previous == Some(&rules)
                && nft::rule_count(&owner, family)? == Some(rules.rule_count());
            if intact {
                continue;
            }
            match nft::install(&owner, family, &rules) {
                Ok(()) => {
                    if previous == Some(&rules) {
                        tracing::warn!(
                            namespace = ns.id,
                            ?family,
                            "credential tunnel: the redirect rules went missing; reinstalled them"
                        );
                    }
                    state.installed.insert(family, rules.clone());
                }
                // A namespace with IPv6 disabled has no ip6 table to fill.
                Err(e) if family == Family::V6 => {
                    tracing::debug!(error = %e, "credential tunnel: no IPv6 rules");
                }
                Err(e) => return Err(e),
            }
        }
        // Let the redirected connections' replies past other programs'
        // anti-spoofing rules (Tailscale's among them), added after ours or
        // reset since.
        for chain in nft::foreign_base_chains(&owner)? {
            let exemption = nft::exemption(&owner, &chain)?;
            if !exemption.first {
                match nft::add_exemption(&owner, &chain, &exemption) {
                    Ok(()) => tracing::info!(
                        namespace = ns.id,
                        ?chain,
                        "credential tunnel: exempted redirect replies"
                    ),
                    Err(e) => {
                        tracing::debug!(?chain, error = %e, "credential tunnel: cannot exempt redirect replies")
                    }
                }
            }
        }
        Ok(())
    }

    /// The namespace a redirected connection came from: the listener's own
    /// when the peer address is one of its own (a connection it opened), else
    /// the namespace holding the peer address (a connection it forwarded).
    fn origin(&self, listener: u32, peer: IpAddr) -> u32 {
        let peer = canonical(peer);
        let namespaces = self.namespaces.lock().unwrap();
        let holds = |ns: &Namespace| {
            peer.is_loopback() && ns.id == listener
                || ns.state.lock().unwrap().addresses.contains(&peer)
        };
        if let Some(ns) = namespaces.values().find(|ns| ns.id == listener) {
            if holds(ns) {
                return listener;
            }
        }
        namespaces
            .values()
            .find(|ns| holds(ns))
            .map_or(listener, |ns| ns.id)
    }

    /// Give one redirected connection to the host interceptor.
    fn hand_flow(&self, listener: u32, client: TcpStream) -> io::Result<()> {
        let destination = original_destination(&client)?;
        let local = client.local_addr()?;
        if destination.port() == local.port() && destination.ip() == local.ip() {
            return Err(io::Error::other("not a redirected connection"));
        }
        let origin = self.origin(listener, client.peer_addr()?.ip());
        let flow = Flow {
            target: Target::Addr(canonical_addr(destination)),
            route: format!("ns:{origin}"),
        };
        hand_to_host(client, &flow, &[])
    }

    /// Serve one client of a local proxy through the front.
    fn hand_proxy_client(&self, listener: u32, client: TcpStream) -> io::Result<()> {
        let proxy_addr = canonical_addr(original_destination(&client)?);
        let ns = self
            .namespace(listener)
            .ok_or_else(|| io::Error::other("namespace went away"))?;
        let upstream = dial_in(&ns, proxy_addr)?;
        let (client, decision) = proxy::front(client, upstream)?;
        let proxy::Decision::Intercept {
            target,
            replay,
            early,
        } = decision
        else {
            return Ok(());
        };
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        self.sessions.lock().unwrap().insert(
            id,
            Arc::new(ProxySession {
                namespace: listener,
                proxy: proxy_addr,
                replay,
            }),
        );
        let flow = Flow {
            target,
            route: format!("px:{id}"),
        };
        let result = hand_to_host(client, &flow, &early);
        self.sessions.lock().unwrap().remove(&id);
        result
    }

    fn serve_dials(self: &Arc<Self>) -> io::Result<()> {
        let listener = crate::vsock::VsockListener::bind(ports::CREDENTIAL_DIAL)?;
        loop {
            let host = match listener.accept() {
                Ok(host) => host,
                Err(e) => {
                    if e.kind() == io::ErrorKind::InvalidInput {
                        return Err(e);
                    }
                    tracing::debug!(error = %e, "credential tunnel: dial accept failed");
                    continue;
                }
            };
            let engine = self.clone();
            let _ = thread::Builder::new()
                .name("cred-tunnel-up".into())
                .spawn(move || {
                    if let Err(e) = engine.dial(host) {
                        tracing::debug!(error = %e, "credential tunnel: upstream ended");
                    }
                });
        }
    }

    /// Open the upstream connection the interceptor asked for and relay it.
    fn dial(&self, mut host: crate::vsock::VsockStream) -> io::Result<()> {
        let flow = Flow::read(&mut host)?;
        let upstream = self.upstream(&flow);
        host.write_all(&[connect_verdict(&upstream)])?;
        crate::relay::relay_half_close(host, upstream?)
    }

    fn upstream(&self, flow: &Flow) -> io::Result<TcpStream> {
        let unknown = || io::Error::new(io::ErrorKind::NotFound, "unknown credential tunnel route");
        let (kind, id) = flow.route.split_once(':').ok_or_else(unknown)?;
        let id: u32 = id.parse().map_err(|_| unknown())?;
        match (kind, &flow.target) {
            ("ns", Target::Addr(addr)) => {
                let ns = self.namespace(id).ok_or_else(unknown)?;
                dial_in(&ns, *addr)
            }
            // The interceptor's fallback when the address the workload chose
            // is unreachable: the TLS server name, resolved and raced from
            // the same namespace.
            ("ns", Target::Name(name, port)) => {
                let ns = self.namespace(id).ok_or_else(unknown)?;
                let (name, port) = (name.clone(), *port);
                ns.run_in(move || connect_name(&name, port))
            }
            ("px", _) => {
                let session = self
                    .sessions
                    .lock()
                    .unwrap()
                    .get(&id)
                    .cloned()
                    .ok_or_else(unknown)?;
                let ns = self.namespace(session.namespace).ok_or_else(unknown)?;
                let mut upstream = dial_in(&ns, session.proxy)?;
                proxy::replay(&mut upstream, &session.replay)?;
                Ok(upstream)
            }
            _ => Err(unknown()),
        }
    }
}

/// The rules one namespace needs for `family`, from its interfaces and the
/// local proxies listening in it.
fn rules_for(
    links: &[Link],
    proxies: &[(IpAddr, u16)],
    family: Family,
    flows_port: u16,
    proxy_port: u16,
) -> RuleSet {
    let mut plaintext_local: Vec<String> = links
        .iter()
        .filter(|link| link.plaintext_local())
        .map(|link| link.name.clone())
        .collect();
    if !plaintext_local.iter().any(|name| name == "lo") {
        plaintext_local.push("lo".into());
    }
    plaintext_local.sort();
    let mut not_forwarded: Vec<String> = links
        .iter()
        .filter(|link| !link.forward_in())
        .map(|link| link.name.clone())
        .collect();
    if !not_forwarded.iter().any(|name| name == "lo") {
        not_forwarded.push("lo".into());
    }
    not_forwarded.sort();
    // A wildcard IPv6 listener takes IPv4 too (dual-stack); any other
    // listener takes only its own family.
    let mut proxies: Vec<(Option<IpAddr>, u16)> = proxies
        .iter()
        .filter_map(|&(addr, port)| match (family, addr) {
            (_, IpAddr::V6(v6)) if v6.is_unspecified() => Some((None, port)),
            (Family::V4, IpAddr::V4(v4)) if v4.is_unspecified() => Some((None, port)),
            (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_)) => Some((Some(addr), port)),
            _ => None,
        })
        .collect();
    proxies.sort();
    proxies.dedup();
    RuleSet {
        plaintext_local,
        not_forwarded,
        proxies,
        flows_port,
        proxy_port,
    }
}

/// Bind an IPv4 and, where the namespace has IPv6, an IPv6 listener on one
/// port, in the calling thread's namespace.
fn bind_pair() -> io::Result<(u16, Vec<TcpListener>)> {
    let v4 = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let port = v4.local_addr()?.port();
    let mut sockets = vec![v4];
    if let Ok(v6) = bind_v6_only(port) {
        sockets.push(v6);
    }
    Ok((port, sockets))
}

fn bind_v6_only(port: u16) -> io::Result<TcpListener> {
    // SAFETY: plain socket syscalls on a descriptor owned from creation.
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let on: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let addr = sockaddr_v6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        if libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in6).cast(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ) < 0
            || libc::listen(fd, 128) < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(TcpListener::from(owned))
    }
}

/// Hand a client connection to the interceptor with its tunnel line and any
/// bytes it already sent.
fn hand_to_host(client: TcpStream, flow: &Flow, early: &[u8]) -> io::Result<()> {
    let _ = client.set_nodelay(true);
    let mut host = crate::vsock::connect(ports::CREDENTIAL_TUNNEL)?;
    flow.write(&mut host)?;
    host.write_all(early)?;
    crate::relay::relay_half_close(host, client)
}

/// The destination the workload dialed, before the redirect rewrote it.
fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    // SAFETY: getsockopt into zeroed sockaddr buffers of the right size.
    unsafe {
        if stream.local_addr()?.is_ipv4() {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                (&mut addr as *mut libc::sockaddr_in).cast(),
                &mut len,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                u16::from_be(addr.sin_port),
            )))
        } else {
            let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IPV6,
                SO_ORIGINAL_DST,
                (&mut addr as *mut libc::sockaddr_in6).cast(),
                &mut len,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                0,
                addr.sin6_scope_id,
            )))
        }
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical(addr.ip()), addr.port())
}

/// Connect to `destination` from inside `ns`, with the tunnel's mark and
/// DSCP set before the SYN so no redirect catches the connection, on its way
/// out or wherever it is forwarded: it routes like the workload's own would.
fn dial_in(ns: &Namespace, destination: SocketAddr) -> io::Result<TcpStream> {
    ns.run_in(move || connect_marked(destination))
}

/// Resolve `name` and connect to whichever of its addresses answers first.
fn connect_name(name: &str, port: u16) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addresses: Vec<SocketAddr> = (name, port).to_socket_addrs()?.take(8).collect();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "name has no addresses",
        ));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    // Threads started here inherit this thread's network namespace.
    for address in addresses.iter().copied() {
        let tx = tx.clone();
        let _ = thread::Builder::new()
            .name("cred-tunnel-race".into())
            .spawn(move || {
                let _ = tx.send(connect_marked(address));
            });
    }
    drop(tx);
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address answered");
    for result in rx {
        match result {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn connect_marked(destination: SocketAddr) -> io::Result<TcpStream> {
    let family = match destination {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: plain socket syscalls on a descriptor this function owns; the
    // option and address buffers are sized for their types.
    unsafe {
        let fd = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Owned from here on, so every early return closes it.
        let stream = TcpStream::from_raw_fd(fd);
        let set = |level, name, value: &[u8]| {
            if libc::setsockopt(
                fd,
                level,
                name,
                value.as_ptr().cast(),
                value.len() as libc::socklen_t,
            ) < 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        set(
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &tunnel::DIAL_MARK.to_ne_bytes(),
        )?;
        let tos = libc::c_int::from(tunnel::DIAL_DSCP << 2);
        match destination {
            SocketAddr::V4(_) => set(libc::IPPROTO_IP, libc::IP_TOS, &tos.to_ne_bytes())?,
            SocketAddr::V6(_) => set(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tos.to_ne_bytes())?,
        }
        // SO_SNDTIMEO bounds a blocking connect on Linux.
        let timeout = libc::timeval {
            tv_sec: DIAL_TIMEOUT.as_secs() as _,
            tv_usec: 0,
        };
        let timeout_bytes = std::slice::from_raw_parts(
            (&timeout as *const libc::timeval).cast::<u8>(),
            std::mem::size_of::<libc::timeval>(),
        );
        set(libc::SOL_SOCKET, libc::SO_SNDTIMEO, timeout_bytes)?;
        let rc = match destination {
            SocketAddr::V4(v4) => {
                let addr = sockaddr_v4(v4);
                libc::connect(
                    fd,
                    (&addr as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            SocketAddr::V6(v6) => {
                let addr = sockaddr_v6(v6);
                libc::connect(
                    fd,
                    (&addr as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            // A connect that ran out of SO_SNDTIMEO reports EINPROGRESS.
            return Err(if error.raw_os_error() == Some(libc::EINPROGRESS) {
                io::ErrorKind::TimedOut.into()
            } else {
                error
            });
        }
        let none = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let none_bytes = std::slice::from_raw_parts(
            (&none as *const libc::timeval).cast::<u8>(),
            std::mem::size_of::<libc::timeval>(),
        );
        set(libc::SOL_SOCKET, libc::SO_SNDTIMEO, none_bytes)?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

fn sockaddr_v4(addr: SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid.
    let mut out: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    out.sin_family = libc::AF_INET as libc::sa_family_t;
    out.sin_port = addr.port().to_be();
    out.sin_addr.s_addr = u32::from(*addr.ip()).to_be();
    out
}

fn sockaddr_v6(addr: SocketAddrV6) -> libc::sockaddr_in6 {
    // SAFETY: an all-zero sockaddr_in6 is valid.
    let mut out: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    out.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    out.sin6_port = addr.port().to_be();
    out.sin6_addr.s6_addr = addr.ip().octets();
    out.sin6_scope_id = addr.scope_id();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str, kind: Option<&str>, arphrd: u16) -> Link {
        Link {
            name: name.into(),
            kind: kind.map(str::to_string),
            arphrd,
        }
    }

    #[test]
    fn the_rules_exempt_plaintext_interfaces_and_catch_forwarded_traffic() {
        let links = [
            link("lo", None, 772),
            link("eth0", None, 1),
            link("docker0", Some("bridge"), 1),
            link("veth1", Some("veth"), 1),
            link("tailscale0", Some("tun"), 65534),
        ];
        let proxies = [
            ("127.0.0.1".parse().unwrap(), 1055),
            ("::".parse().unwrap(), 1056),
        ];
        let rules = rules_for(&links, &proxies, Family::V4, 4000, 4001);
        assert_eq!(rules.plaintext_local, ["docker0", "eth0", "lo", "veth1"]);
        assert_eq!(rules.not_forwarded, ["eth0", "lo", "tailscale0"]);
        assert_eq!(
            rules.proxies,
            [(None, 1056), (Some("127.0.0.1".parse().unwrap()), 1055)]
        );
        // A proxy on 127.0.0.1 only must not catch [::1]: the client's own
        // fallback to IPv4 depends on that connection being refused.
        let v6 = rules_for(&links, &proxies, Family::V6, 4000, 4001);
        assert_eq!(v6.proxies, [(None, 1056)]);
    }

    #[test]
    fn a_namespace_without_loopback_listed_still_exempts_it() {
        let rules = rules_for(
            &[link("wg0", Some("wireguard"), 65534)],
            &[],
            Family::V4,
            1,
            2,
        );
        assert_eq!(rules.plaintext_local, ["lo"]);
    }

    #[test]
    fn origins_follow_the_peer_address() {
        let engine = Engine::default();
        let mut namespaces = engine.namespaces.lock().unwrap();
        for (id, inode, address) in [(0, 10, "10.0.2.15"), (3, 30, "172.17.0.2")] {
            let ns = Namespace {
                id,
                inode,
                path: PathBuf::from("/proc/self/ns/net"),
                flows: Listeners {
                    port: 0,
                    sockets: vec![],
                    stop: Arc::new(AtomicBool::new(false)),
                },
                proxy: Listeners {
                    port: 0,
                    sockets: vec![],
                    stop: Arc::new(AtomicBool::new(false)),
                },
                owner: None,
                events: None,
                state: Mutex::new(NsState {
                    installed: BTreeMap::new(),
                    addresses: BTreeSet::from([address.parse().unwrap()]),
                }),
            };
            namespaces.insert(inode, Arc::new(ns));
        }
        drop(namespaces);
        // Opened by the listener's own namespace.
        assert_eq!(engine.origin(0, "10.0.2.15".parse().unwrap()), 0);
        assert_eq!(engine.origin(3, "127.0.0.1".parse().unwrap()), 3);
        // Forwarded for a container.
        assert_eq!(engine.origin(0, "172.17.0.2".parse().unwrap()), 3);
        assert_eq!(engine.origin(0, "::ffff:172.17.0.2".parse().unwrap()), 3);
        // From nowhere the tunnel knows: the listener's namespace.
        assert_eq!(engine.origin(0, "100.64.0.9".parse().unwrap()), 0);
    }
}
