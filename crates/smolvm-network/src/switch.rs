//! The container switch: routed IP between machines on shared networks.
//!
//! A container engine runs every container as its own machine, each with
//! this crate's network stack in its VMM. Containers on the same network
//! reach each other by address and by name; containers on different networks
//! do not reach each other at all. Machines join and leave networks while
//! they run.
//!
//! The switch is a directory the engine owns and the stacks read:
//!
//! ```text
//! <dir>/ep/<endpoint>.sock      one per running machine, bound by its stack
//! <dir>/ep/<endpoint>.json      the machine's addresses, written by the engine:
//!                               {"members":[{"network":"n1","ip":"172.18.0.2","prefix":16}]}
//!                               (a network with IPv6 adds a member with its IPv6 address)
//! <dir>/n/<network>/<ip>        symlink to the member's endpoint socket
//! <dir>/n/<network>/names       "name ip" lines: the names that resolve on the network
//! ```
//!
//! The data path is peer to peer: a guest packet for another member's address
//! leaves the guest through its own stack, which writes the raw IP packet to
//! `<dir>/n/<network>/<dst>`, a connect that the symlink takes to the
//! destination's endpoint socket. The destination stack wraps it in an
//! Ethernet frame for its guest. A guest reaches its peers' link addresses
//! through its own stack, which answers ARP and IPv6 neighbor solicitation
//! for them with its own MAC. Framing between stacks is
//! `[4-byte big-endian length][raw IP packet]`, as for [`crate::fabric`].
//!
//! Isolation is checked on both ends. A stack forwards a packet only when
//! its destination is inside the subnet of a network the machine is on and
//! its source is the machine's own address on that network, so a guest can
//! neither reach a network it is not on nor forge another member's address.
//! A receiving stack accepts a packet only for one of its own addresses, from
//! a source inside that address's subnet. Networks never share a subnet, so
//! "inside the subnet" means "on the same network".
//!
//! Membership changes are file changes: the engine rewrites the endpoint
//! file and the symlinks, and the stack picks the new addresses up within a
//! quarter second. Nothing here needs the engine to be running for packets
//! already routed to keep flowing.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use crate::queues::NetworkFrameQueues;

/// Largest packet a peer may send.
const MAX_PACKET: usize = 65536;
/// Packets queued toward peers before new ones are dropped.
const SENDER_QUEUE_DEPTH: usize = 2048;
/// How often the endpoint file is checked for new addresses.
const CONFIG_POLL: Duration = Duration::from_millis(100);
/// Read timeout on peer sockets, used only to notice shutdown.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);
/// TTL of names the switch answers.
pub const NAME_TTL_SECS: u32 = 5;

/// Where a machine sits on the switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchEndpoint {
    /// The switch directory.
    pub dir: PathBuf,
    /// The machine's endpoint name (its file stem under `ep/`).
    pub id: String,
}

impl SwitchEndpoint {
    /// The endpoint's socket.
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("ep").join(format!("{}.sock", self.id))
    }

    /// The endpoint's address file.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join("ep").join(format!("{}.json", self.id))
    }

    /// The machine's addresses as the engine last wrote them.
    pub fn read_members(&self) -> Vec<Member> {
        std::fs::read(self.config_path())
            .map(|bytes| parse_endpoint_file(&bytes))
            .unwrap_or_default()
    }
}

/// One address of a machine, on one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// The network's directory name under `n/`.
    pub network: NetworkName,
    /// The machine's address on it.
    pub ip: IpAddr,
    /// The network's prefix length.
    pub prefix: u8,
}

/// The members in an endpoint file; malformed entries are skipped.
pub fn parse_endpoint_file(bytes: &[u8]) -> Vec<Member> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    value["members"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|m| {
                    let ip: IpAddr = m["ip"].as_str()?.parse().ok()?;
                    let max = if ip.is_ipv4() { 32 } else { 128 };
                    Some(Member {
                        network: NetworkName::new(m["network"].as_str()?)?,
                        ip,
                        prefix: u8::try_from(m["prefix"].as_u64()?)
                            .ok()
                            .filter(|p| *p <= max)?,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The endpoint file for `members`, primary first.
pub fn render_endpoint_file(members: &[Member]) -> String {
    let list: Vec<serde_json::Value> = members
        .iter()
        .map(|m| {
            serde_json::json!({
                "network": m.network.as_str(),
                "ip": m.ip.to_string(),
                "prefix": m.prefix,
            })
        })
        .collect();
    serde_json::json!({ "members": list }).to_string()
}

/// A network's name, short enough to be `Copy` (the engine uses 12 hex digits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkName {
    len: u8,
    bytes: [u8; 32],
}

impl NetworkName {
    /// `name`, or `None` when it is empty, longer than 32 bytes, or not a
    /// plain file name.
    pub fn new(name: &str) -> Option<Self> {
        if name.is_empty()
            || name.len() > 32
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self {
            len: name.len() as u8,
            bytes,
        })
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

/// An address as a 128-bit number with its width, so one subnet rule
/// covers IPv4 and IPv6.
fn bits(ip: IpAddr) -> (u128, u32) {
    match ip {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    }
}

impl Member {
    fn mask(&self) -> u128 {
        let (_, width) = bits(self.ip);
        let prefix = u32::from(self.prefix).min(width);
        let all = if width == 32 {
            u128::from(u32::MAX)
        } else {
            u128::MAX
        };
        if prefix == 0 {
            0
        } else {
            all & (all << (width - prefix))
        }
    }

    /// Whether `ip` is inside this member's network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() != self.ip.is_ipv4() {
            return false;
        }
        bits(ip).0 & self.mask() == bits(self.ip).0 & self.mask()
    }

    /// The network's own address, and an IPv4 network's broadcast, which no
    /// member owns.
    fn reserved(&self, ip: IpAddr) -> bool {
        let (net, width) = bits(self.ip);
        let net = net & self.mask();
        let ip = bits(ip).0;
        let all = if width == 32 {
            u128::from(u32::MAX)
        } else {
            u128::MAX
        };
        ip == net || (width == 32 && ip == net | (all & !self.mask()))
    }
}

/// What the poll loop asks the switch about one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Another member's address: forward it.
    Peer,
    /// Not on any network this machine is on.
    Elsewhere,
}

/// The poll loop's handle on a running switch endpoint.
#[derive(Clone)]
pub struct SwitchHandle {
    endpoint: SwitchEndpoint,
    members: Arc<RwLock<Vec<Member>>>,
    sender: SyncSender<(IpAddr, Vec<u8>)>,
    names: Arc<RwLock<HashMap<NetworkName, NamesFile>>>,
    /// When the endpoint file was last read.
    seen: Arc<std::sync::Mutex<Option<SystemTime>>>,
}

/// One network's names file, cached until it changes.
#[derive(Default)]
struct NamesFile {
    modified: Option<SystemTime>,
    entries: HashMap<String, Vec<IpAddr>>,
}

impl SwitchHandle {
    /// Where `dst` goes.
    pub fn route(&self, dst: IpAddr) -> Route {
        let members = self.members.read().unwrap_or_else(|e| e.into_inner());
        if members.iter().any(|m| m.ip == dst) {
            return Route::Elsewhere;
        }
        if members
            .iter()
            .any(|m| m.contains(dst) && !m.reserved(dst) && !is_gateway(m, dst))
        {
            Route::Peer
        } else {
            Route::Elsewhere
        }
    }

    /// Whether the stack should answer an ARP request for `target` with its
    /// own MAC: any address on the machine's networks but its own, so the
    /// guest sends traffic for its peers (and their gateways) to the stack.
    pub fn answers_arp_for(&self, target: Ipv4Addr) -> bool {
        self.answers_for(IpAddr::V4(target))
    }

    /// [`answers_arp_for`](Self::answers_arp_for) for IPv6 neighbor
    /// solicitation.
    pub fn answers_ndp_for(&self, target: Ipv6Addr) -> bool {
        self.answers_for(IpAddr::V6(target))
    }

    fn answers_for(&self, target: IpAddr) -> bool {
        let members = self.members.read().unwrap_or_else(|e| e.into_inner());
        !members.iter().any(|m| m.ip == target)
            && members
                .iter()
                .any(|m| m.contains(target) && !m.reserved(target))
    }

    /// Whether `ip` is the gateway address of one of the machine's networks.
    pub fn is_gateway(&self, ip: IpAddr) -> bool {
        let members = self.members.read().unwrap_or_else(|e| e.into_inner());
        members.iter().any(|m| is_gateway(m, ip))
    }

    /// Queue one guest IP packet for its peer. Dropped (as IP may drop)
    /// when the queue is full or the source is not the machine's own address
    /// on the destination's network.
    pub fn forward(&self, src: IpAddr, dst: IpAddr, packet: Vec<u8>) {
        let allowed = {
            let members = self.members.read().unwrap_or_else(|e| e.into_inner());
            members.iter().any(|m| m.contains(dst) && m.ip == src)
        };
        if !allowed {
            return;
        }
        match self.sender.try_send((dst, packet)) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// The addresses `name` has on the machine's networks, if it has any.
    pub fn lookup(&self, name: &str) -> Option<Vec<IpAddr>> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        // A name lookup right after a network change must see the new
        // networks, not wait for the next poll.
        self.refresh_members();
        let networks: Vec<NetworkName> = {
            let members = self.members.read().unwrap_or_else(|e| e.into_inner());
            members.iter().map(|m| m.network).collect()
        };
        let mut found = Vec::new();
        for network in networks {
            let path = self
                .endpoint
                .dir
                .join("n")
                .join(network.as_str())
                .join("names");
            let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            {
                let cache = self.names.read().unwrap_or_else(|e| e.into_inner());
                if let Some(file) = cache.get(&network) {
                    if file.modified == modified && modified.is_some() {
                        if let Some(ips) = file.entries.get(&name) {
                            found.extend(ips.iter().copied());
                        }
                        continue;
                    }
                }
            }
            let entries = std::fs::read_to_string(&path)
                .map(|text| parse_names(&text))
                .unwrap_or_default();
            if let Some(ips) = entries.get(&name) {
                found.extend(ips.iter().copied());
            }
            self.names
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(network, NamesFile { modified, entries });
        }
        found.dedup();
        (!found.is_empty()).then_some(found)
    }
}

impl SwitchHandle {
    /// Reread the endpoint file if it changed since it was last read.
    fn refresh_members(&self) {
        let modified = std::fs::metadata(self.endpoint.config_path())
            .and_then(|m| m.modified())
            .ok();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if *seen != modified {
            *seen = modified;
            *self.members.write().unwrap_or_else(|e| e.into_inner()) = self.endpoint.read_members();
        }
    }
}

fn is_gateway(m: &Member, ip: IpAddr) -> bool {
    ip.is_ipv4() == m.ip.is_ipv4() && bits(ip).0 == (bits(m.ip).0 & m.mask()) + 1
}

/// Parse a names file: `name ip` per line; a name may repeat.
pub fn parse_names(text: &str) -> HashMap<String, Vec<IpAddr>> {
    let mut out: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(ip)) = (parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(ip) = ip.parse() {
            out.entry(name.to_ascii_lowercase()).or_default().push(ip);
        }
    }
    out
}

/// Bind the endpoint socket and start the switch threads. They end when
/// `queues` starts shutting down; the socket is removed then.
pub fn start_switch(
    endpoint: SwitchEndpoint,
    queues: Arc<NetworkFrameQueues>,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) -> io::Result<SwitchHandle> {
    use std::os::unix::net::UnixListener;
    let socket = endpoint.socket_path();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A machine that died left its socket behind; the endpoint is ours.
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;
    let seen = Arc::new(std::sync::Mutex::new(
        std::fs::metadata(endpoint.config_path())
            .and_then(|m| m.modified())
            .ok(),
    ));
    let members = Arc::new(RwLock::new(endpoint.read_members()));
    let (sender, receiver) = sync_channel::<(IpAddr, Vec<u8>)>(SENDER_QUEUE_DEPTH);
    let handle = SwitchHandle {
        endpoint: endpoint.clone(),
        members: members.clone(),
        sender,
        names: Arc::new(RwLock::new(HashMap::new())),
        seen: seen.clone(),
    };

    {
        let queues = queues.clone();
        let members = members.clone();
        let socket = socket.clone();
        std::thread::Builder::new()
            .name("smolvm-switch-accept".into())
            .spawn(move || {
                accept_loop(listener, socket, queues, members, gateway_mac, guest_mac)
            })?;
    }
    {
        let queues = queues.clone();
        let members = members.clone();
        let dir = endpoint.dir.clone();
        std::thread::Builder::new()
            .name("smolvm-switch-send".into())
            .spawn(move || send_loop(dir, receiver, members, queues))?;
    }
    {
        let handle = handle.clone();
        std::thread::Builder::new()
            .name("smolvm-switch-config".into())
            .spawn(move || {
                while !queues.is_shutting_down() {
                    std::thread::sleep(CONFIG_POLL);
                    handle.refresh_members();
                }
            })?;
    }
    drop(members);
    Ok(handle)
}

fn accept_loop(
    listener: std::os::unix::net::UnixListener,
    socket: PathBuf,
    queues: Arc<NetworkFrameQueues>,
    members: Arc<RwLock<Vec<Member>>>,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    loop {
        if queues.is_shutting_down() {
            let _ = std::fs::remove_file(&socket);
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let queues = queues.clone();
                let members = members.clone();
                let _ = std::thread::Builder::new()
                    .name("smolvm-switch-recv".into())
                    .spawn(move || peer_reader(stream, queues, members, gateway_mac, guest_mac));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait_readable(&listener),
            Err(_) => {
                let _ = std::fs::remove_file(&socket);
                return;
            }
        }
    }
}

/// Block until `listener` has a connection to accept, or the shutdown poll
/// interval passes.
fn wait_readable(listener: &std::os::unix::net::UnixListener) {
    use std::os::unix::io::AsRawFd;
    let mut fd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for the duration of the call.
    unsafe { libc::poll(&mut fd, 1, SHUTDOWN_POLL.as_millis() as libc::c_int) };
}

/// Whether a packet from a peer may reach this guest: for one of its
/// addresses, from inside that address's network.
fn accepts(members: &[Member], packet: &[u8]) -> bool {
    let Some((src, dst)) = ip_endpoints(packet) else {
        return false;
    };
    members
        .iter()
        .any(|m| m.ip == dst && m.contains(src) && src != dst)
}

/// Source and destination of an IPv4 packet.
pub fn ipv4_endpoints(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst))
}

/// Source and destination of an IPv6 packet.
pub fn ipv6_endpoints(packet: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let src: [u8; 16] = packet[8..24].try_into().ok()?;
    let dst: [u8; 16] = packet[24..40].try_into().ok()?;
    Some((Ipv6Addr::from(src), Ipv6Addr::from(dst)))
}

/// Source and destination of an IPv4 or IPv6 packet.
pub fn ip_endpoints(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 => ipv4_endpoints(packet).map(|(s, d)| (IpAddr::V4(s), IpAddr::V4(d))),
        6 => ipv6_endpoints(packet).map(|(s, d)| (IpAddr::V6(s), IpAddr::V6(d))),
        _ => None,
    }
}

fn peer_reader(
    mut stream: std::os::unix::net::UnixStream,
    queues: Arc<NetworkFrameQueues>,
    members: Arc<RwLock<Vec<Member>>>,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    let _ = stream.set_read_timeout(Some(SHUTDOWN_POLL));
    loop {
        let mut len = [0u8; 4];
        if !read_full(&mut stream, &mut len, &queues) {
            return;
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_PACKET {
            return;
        }
        let mut packet = vec![0u8; len];
        if !read_full(&mut stream, &mut packet, &queues) {
            return;
        }
        let ok = accepts(&members.read().unwrap_or_else(|e| e.into_inner()), &packet);
        if !ok {
            continue;
        }
        let frame = if packet[0] >> 4 == 6 {
            let mut frame = Vec::with_capacity(14 + packet.len());
            frame.extend_from_slice(&guest_mac);
            frame.extend_from_slice(&gateway_mac);
            frame.extend_from_slice(&[0x86, 0xdd]);
            frame.extend_from_slice(&packet);
            frame
        } else {
            crate::fabric::ethernet_frame_for_guest(gateway_mac, guest_mac, &packet)
        };
        if queues.host_to_guest.push(frame).is_ok() {
            queues.host_wake.wake();
        }
    }
}

/// Fill `buf`, riding out the shutdown-poll timeouts; `false` at EOF, on an
/// error, or at shutdown.
fn read_full(
    stream: &mut std::os::unix::net::UnixStream,
    buf: &mut [u8],
    queues: &NetworkFrameQueues,
) -> bool {
    let mut filled = 0;
    while filled < buf.len() {
        if queues.is_shutting_down() {
            return false;
        }
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return false,
            Ok(n) => filled += n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(_) => return false,
        }
    }
    true
}

fn send_loop(
    dir: PathBuf,
    receiver: Receiver<(IpAddr, Vec<u8>)>,
    members: Arc<RwLock<Vec<Member>>>,
    queues: Arc<NetworkFrameQueues>,
) {
    let mut connections: HashMap<IpAddr, std::os::unix::net::UnixStream> = HashMap::new();
    let mut generation: Vec<Member> = Vec::new();
    for (dst, packet) in receiver.iter() {
        if queues.is_shutting_down() {
            return;
        }
        let network = {
            let current = members.read().unwrap_or_else(|e| e.into_inner());
            if *current != generation {
                // Addresses changed: routes may point elsewhere now.
                generation = current.clone();
                connections.clear();
            }
            current.iter().find(|m| m.contains(dst)).map(|m| m.network)
        };
        let Some(network) = network else {
            continue;
        };
        if send(&dir, network, &mut connections, dst, &packet).is_err() {
            connections.remove(&dst);
            let _ = send(&dir, network, &mut connections, dst, &packet);
        }
    }
}

fn send(
    dir: &Path,
    network: NetworkName,
    connections: &mut HashMap<IpAddr, std::os::unix::net::UnixStream>,
    dst: IpAddr,
    packet: &[u8],
) -> io::Result<()> {
    use std::collections::hash_map::Entry;
    let stream = match connections.entry(dst) {
        Entry::Occupied(e) => e.into_mut(),
        Entry::Vacant(slot) => {
            let path = dir.join("n").join(network.as_str()).join(dst.to_string());
            let stream = std::os::unix::net::UnixStream::connect(path)?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            slot.insert(stream)
        }
    };
    let mut frame = Vec::with_capacity(4 + packet.len());
    frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
    frame.extend_from_slice(packet);
    stream.write_all(&frame)
}

/// An ARP reply telling `requester` that `target` is at `mac`, for a request
/// frame `request`. `None` when `request` is not an IPv4 ARP request.
pub fn arp_reply(request: &[u8], mac: [u8; 6]) -> Option<(Ipv4Addr, Vec<u8>)> {
    // Ethernet (14) + ARP for IPv4 over Ethernet (28).
    if request.len() < 42 || request[12..14] != [0x08, 0x06] {
        return None;
    }
    let arp = &request[14..42];
    if arp[0..2] != [0, 1] || arp[2..4] != [0x08, 0x00] || arp[4] != 6 || arp[5] != 4 {
        return None;
    }
    if arp[6..8] != [0, 1] {
        return None; // not a request
    }
    let sender_mac = &arp[8..14];
    let sender_ip = &arp[14..18];
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
    let mut reply = Vec::with_capacity(42);
    reply.extend_from_slice(sender_mac);
    reply.extend_from_slice(&mac);
    reply.extend_from_slice(&[0x08, 0x06]);
    reply.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
    reply.extend_from_slice(&mac);
    reply.extend_from_slice(&target_ip.octets());
    reply.extend_from_slice(sender_mac);
    reply.extend_from_slice(sender_ip);
    Some((target_ip, reply))
}

/// A neighbor advertisement telling the soliciting guest that the target of
/// its neighbor solicitation `request` (an Ethernet frame) is at `mac`.
/// `None` when `request` is not an IPv6 neighbor solicitation.
pub fn ndp_reply(request: &[u8], mac: [u8; 6]) -> Option<(Ipv6Addr, Vec<u8>)> {
    // Ethernet (14) + IPv6 (40) + ICMPv6 NS (24 at least).
    if request.len() < 14 + 40 + 24 || request[12..14] != [0x86, 0xdd] {
        return None;
    }
    let ip = &request[14..];
    if ip[0] >> 4 != 6 || ip[6] != 58 {
        return None;
    }
    let icmp = &ip[40..];
    if icmp[0] != 135 || icmp[1] != 0 {
        return None;
    }
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&icmp[8..24]).ok()?);
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?);
    // An unspecified source (duplicate address detection) gets its answer on
    // all-nodes.
    let dst = if source.is_unspecified() {
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
    } else {
        source
    };
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(&[136, 0, 0, 0]);
    let flags: u8 = if source.is_unspecified() { 0x20 } else { 0x60 };
    body.extend_from_slice(&[flags, 0, 0, 0]);
    body.extend_from_slice(&target.octets());
    body.extend_from_slice(&[2, 1]);
    body.extend_from_slice(&mac);
    let checksum = icmpv6_checksum(target, dst, &body);
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut frame = Vec::with_capacity(14 + 40 + body.len());
    frame.extend_from_slice(&request[6..12]);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0x86, 0xdd]);
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(&[58, 255]);
    frame.extend_from_slice(&target.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&body);
    Some((target, frame))
}

/// The ICMPv6 checksum of `body` from `src` to `dst` (with the pseudo-header).
fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, body: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(word);
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&(body.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 58]);
    add(body);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(net: &str, ip: &str, prefix: u8) -> Member {
        Member {
            network: NetworkName::new(net).unwrap(),
            ip: ip.parse().unwrap(),
            prefix,
        }
    }

    fn ipv4(src: &str, dst: &str) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
        p[16..20].copy_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        p
    }

    #[test]
    fn a_member_accepts_only_its_own_network() {
        let members = [member("a", "172.18.0.2", 16), member("b", "172.19.0.3", 16)];
        assert!(accepts(&members, &ipv4("172.18.0.5", "172.18.0.2")));
        assert!(accepts(&members, &ipv4("172.19.0.9", "172.19.0.3")));
        // Right address, wrong network: someone on b may not reach a's address.
        assert!(!accepts(&members, &ipv4("172.19.0.9", "172.18.0.2")));
        // Not one of ours.
        assert!(!accepts(&members, &ipv4("172.18.0.5", "172.18.0.9")));
        assert!(!accepts(&members, &[0u8; 10]));
    }

    #[test]
    fn endpoint_files_round_trip() {
        let members = vec![
            member("a1b2", "172.18.0.2", 16),
            member("c3", "10.5.0.9", 24),
        ];
        assert_eq!(
            parse_endpoint_file(render_endpoint_file(&members).as_bytes()),
            members
        );
        assert!(parse_endpoint_file(b"not json").is_empty());
        assert!(parse_endpoint_file(
            br#"{"members":[{"network":"../x","ip":"1.2.3.4","prefix":8}]}"#
        )
        .is_empty());
    }

    #[test]
    fn names_parse_and_repeat() {
        let names = parse_names("db 172.18.0.2\nDB 172.18.0.3\nweb 172.18.0.4\nbad\n");
        assert_eq!(names["db"].len(), 2);
        assert_eq!(names["web"], vec!["172.18.0.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn members_know_their_subnet() {
        let m = member("a", "172.18.0.2", 16);
        assert!(m.contains("172.18.255.1".parse().unwrap()));
        assert!(!m.contains("172.19.0.1".parse().unwrap()));
        assert!(m.reserved("172.18.0.0".parse().unwrap()));
        assert!(m.reserved("172.18.255.255".parse().unwrap()));
        assert!(is_gateway(&m, "172.18.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_members_route_and_answer_neighbor_solicitation() {
        let m = member("a", "fd00:1::2", 64);
        assert!(m.contains("fd00:1::9".parse().unwrap()));
        assert!(!m.contains("fd00:2::9".parse().unwrap()));
        assert!(!m.contains("172.18.0.2".parse().unwrap()));
        assert!(m.reserved("fd00:1::".parse().unwrap()));
        assert!(is_gateway(&m, "fd00:1::1".parse().unwrap()));
        // A neighbor solicitation from fd00:1::2 for fd00:1::5.
        let mut frame = vec![0x33, 0x33, 0xff, 0, 0, 5];
        frame.extend_from_slice(&[2, 0x53, 0x4d, 0, 0, 2, 0x86, 0xdd]);
        let target: Ipv6Addr = "fd00:1::5".parse().unwrap();
        let src: Ipv6Addr = "fd00:1::2".parse().unwrap();
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 24, 58, 255]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&"ff02::1:ff00:5".parse::<Ipv6Addr>().unwrap().octets());
        frame.extend_from_slice(&[135, 0, 0, 0, 0, 0, 0, 0]);
        frame.extend_from_slice(&target.octets());
        let (got, reply) = ndp_reply(&frame, [2, 0x53, 0x4d, 0, 0, 1]).unwrap();
        assert_eq!(got, target);
        assert_eq!(&reply[0..6], &[2, 0x53, 0x4d, 0, 0, 2]);
        assert_eq!(reply[14 + 40], 136);
        assert_eq!(&reply[14 + 24..14 + 40], &src.octets());
        // The checksum verifies: summing again over the filled field gives 0.
        let body = &reply[14 + 40..];
        assert_eq!(icmpv6_checksum(target, src, body), 0);
    }

    #[test]
    fn arp_requests_get_a_reply_for_the_target() {
        let mut req = vec![0xffu8; 6];
        req.extend_from_slice(&[2, 0x53, 0x4d, 0, 0, 2]);
        req.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1]);
        req.extend_from_slice(&[2, 0x53, 0x4d, 0, 0, 2]);
        req.extend_from_slice(&[172, 18, 0, 2]);
        req.extend_from_slice(&[0; 6]);
        req.extend_from_slice(&[172, 18, 0, 5]);
        let (target, reply) = arp_reply(&req, [2, 0x53, 0x4d, 0, 0, 1]).unwrap();
        assert_eq!(target, Ipv4Addr::new(172, 18, 0, 5));
        assert_eq!(&reply[0..6], &[2, 0x53, 0x4d, 0, 0, 2]);
        assert_eq!(&reply[20..22], &[0, 2]); // reply opcode
        assert_eq!(&reply[28..32], &[172, 18, 0, 5]);
    }

    #[test]
    fn handle_routes_peers_and_answers_arp() {
        let (sender, _rx) = sync_channel(1);
        let handle = SwitchHandle {
            endpoint: SwitchEndpoint {
                dir: PathBuf::from("/nonexistent"),
                id: "x".into(),
            },
            members: Arc::new(RwLock::new(vec![member("a", "172.18.0.2", 16)])),
            sender,
            names: Arc::default(),
            seen: Arc::default(),
        };
        assert_eq!(handle.route("172.18.0.7".parse().unwrap()), Route::Peer);
        assert_eq!(
            handle.route("172.18.0.1".parse().unwrap()),
            Route::Elsewhere
        );
        assert_eq!(
            handle.route("172.18.0.2".parse().unwrap()),
            Route::Elsewhere
        );
        assert_eq!(handle.route("8.8.8.8".parse().unwrap()), Route::Elsewhere);
        assert!(handle.answers_arp_for("172.18.0.7".parse().unwrap()));
        assert!(!handle.answers_arp_for("172.18.0.2".parse().unwrap()));
        assert!(handle.is_gateway("172.18.0.1".parse().unwrap()));
    }

    #[test]
    fn lookups_read_every_network_of_the_machine() {
        let dir = tempfile::tempdir().unwrap();
        for (net, body) in [
            ("a", "db 172.18.0.5\n"),
            ("b", "cache 172.19.0.4\ndb 172.19.0.9\n"),
        ] {
            let d = dir.path().join("n").join(net);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("names"), body).unwrap();
        }
        let (sender, _rx) = sync_channel(1);
        let handle = SwitchHandle {
            endpoint: SwitchEndpoint {
                dir: dir.path().to_path_buf(),
                id: "x".into(),
            },
            members: Arc::new(RwLock::new(vec![
                member("a", "172.18.0.2", 16),
                member("b", "172.19.0.3", 16),
            ])),
            sender,
            names: Arc::default(),
            seen: Arc::default(),
        };
        assert_eq!(handle.lookup("DB.").unwrap().len(), 2);
        assert!(handle.lookup("cache").is_some());
        assert!(handle.lookup("other").is_none());
        // A machine on `a` only does not see `b`'s names.
        *handle.members.write().unwrap() = vec![member("a", "172.18.0.2", 16)];
        assert!(handle.lookup("cache").is_none());
    }
}
