//! Network namespaces in the guest, and what the tunnel needs to know about
//! each: its interfaces, its addresses, and local proxies listening in it.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Directories that hold bind-mounted namespaces (`ip netns add`, Docker).
const NAMED: &[&str] = &["/run/netns", "/var/run/docker/netns"];

/// A namespace and one path that opens it.
#[derive(Clone, Debug)]
pub struct Found {
    pub inode: u64,
    pub path: PathBuf,
}

/// Every network namespace some process or bind mount holds, by inode.
pub fn discover() -> BTreeMap<u64, Found> {
    let mut found = BTreeMap::new();
    let mut add = |path: PathBuf| {
        if let Ok(meta) = std::fs::metadata(&path) {
            found.entry(meta.ino()).or_insert_with(|| Found {
                inode: meta.ino(),
                path,
            });
        }
    };
    add(PathBuf::from("/proc/self/ns/net"));
    // Named namespaces live in a mount namespace (a workload's container has
    // its own), so look through one process's root in each.
    let mut roots = BTreeMap::new();
    roots.insert(0, PathBuf::from("/"));
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
                add(entry.path().join("ns/net"));
                if let Ok(mnt) = std::fs::metadata(entry.path().join("ns/mnt")) {
                    roots
                        .entry(mnt.ino())
                        .or_insert_with(|| entry.path().join("root"));
                }
            }
        }
    }
    for root in roots.values() {
        for dir in NAMED {
            if let Ok(entries) = std::fs::read_dir(root.join(dir.trim_start_matches('/'))) {
                for entry in entries.flatten() {
                    add(entry.path());
                }
            }
        }
    }
    found
}

/// The inode of this process's own namespace.
pub fn own_inode() -> io::Result<u64> {
    Ok(std::fs::metadata("/proc/self/ns/net")?.ino())
}

/// Run `f` on a thread that has entered the namespace `path` opens (checked
/// to still be `inode`); sockets it creates belong to that namespace.
pub fn run_in<T, F>(path: &Path, inode: u64, f: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    let path = path.to_path_buf();
    std::thread::Builder::new()
        .name("cred-tunnel-ns".into())
        .spawn(move || {
            let file = std::fs::File::open(&path)?;
            if file.metadata()?.ino() != inode {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "network namespace went away",
                ));
            }
            // SAFETY: setns on a namespace descriptor; affects only this
            // short-lived thread.
            if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
                return Err(io::Error::last_os_error());
            }
            f()
        })?
        .join()
        .map_err(|_| io::Error::other("namespace worker panicked"))?
}

/// One interface as the tunnel classifies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub kind: Option<String>,
    pub arphrd: u16,
}

/// Link kinds that carry traffic in the clear to another place in the guest
/// (or, for a kind-less Ethernet device, the machine's NIC).
const PLAINTEXT_LOCAL_KINDS: &[&str] = &[
    "veth", "bridge", "macvlan", "ipvlan", "vlan", "dummy", "bond", "vrf", "team",
];
/// Kinds another namespace's traffic arrives on to be forwarded.
const FORWARD_IN_KINDS: &[&str] = &["veth", "bridge", "macvlan", "ipvlan"];
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;

impl Link {
    /// Whether HTTPS out of this interface stays in the clear somewhere the
    /// tunnel already covers. Everything else (a TUN for Tailscale or
    /// OpenVPN, WireGuard, GRE, PPP, …) is where plaintext would disappear.
    pub fn plaintext_local(&self) -> bool {
        match &self.kind {
            Some(kind) => PLAINTEXT_LOCAL_KINDS.contains(&kind.as_str()),
            None => self.arphrd == ARPHRD_ETHER || self.arphrd == ARPHRD_LOOPBACK,
        }
    }

    /// Whether traffic arriving here comes from another namespace in the guest.
    pub fn forward_in(&self) -> bool {
        self.kind
            .as_deref()
            .is_some_and(|kind| FORWARD_IN_KINDS.contains(&kind))
    }
}

/// A socket in the calling thread's namespace that wakes when an interface
/// or address in it changes.
pub fn events() -> io::Result<OwnedFd> {
    const GROUPS: u32 = 0x1 /* LINK */ | 0x10 /* IPV4_IFADDR */ | 0x100 /* IPV6_IFADDR */;
    let socket = rtnl_socket()?;
    // SAFETY: bind a netlink socket this function owns to its groups.
    unsafe {
        let mut local: libc::sockaddr_nl = std::mem::zeroed();
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        local.nl_groups = GROUPS;
        if libc::bind(
            socket.as_raw_fd(),
            (&local as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(socket)
}

/// Discard what an [`events`] socket has queued.
pub fn drain(socket: &OwnedFd) {
    let mut buf = [0u8; 16 * 1024];
    // SAFETY: recv into a local buffer on a caller-owned socket.
    while unsafe {
        libc::recv(
            socket.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    } > 0
    {}
}

/// The interfaces and addresses of the current thread's namespace.
pub fn links_and_addresses() -> io::Result<(Vec<Link>, BTreeSet<IpAddr>)> {
    Ok((dump_links()?, dump_addresses()?))
}

fn rtnl_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket syscalls; the descriptor is owned from creation.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        Ok(fd)
    }
}

/// Send one dump request and hand every reply message to `each`.
fn dump(kind: u16, header: &[u8], mut each: impl FnMut(u16, &[u8])) -> io::Result<()> {
    let socket = rtnl_socket()?;
    let mut msg = Vec::with_capacity(16 + header.len());
    msg.extend_from_slice(&((16 + header.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(header);
    // SAFETY: sendto/recv on a socket this function owns, with local buffers.
    unsafe {
        let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if libc::sendto(
            socket.as_raw_fd(),
            msg.as_ptr().cast(),
            msg.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = libc::recv(socket.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            for (kind, payload) in super::nft::messages(&buf[..n as usize]) {
                if kind == libc::NLMSG_DONE as u16 {
                    return Ok(());
                }
                if kind == libc::NLMSG_ERROR as u16 {
                    let errno = payload
                        .get(0..4)
                        .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                        .unwrap_or(-libc::EIO);
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                each(kind, payload);
            }
        }
    }
}

use super::nft::{attributes, c_string};

fn dump_links() -> io::Result<Vec<Link>> {
    const IFINFOMSG_LEN: usize = 16;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_LINKINFO: u16 = 18;
    const IFLA_INFO_KIND: u16 = 1;
    let mut links = Vec::new();
    dump(libc::RTM_GETLINK, &[0u8; IFINFOMSG_LEN], |kind, payload| {
        if kind != libc::RTM_NEWLINK || payload.len() < IFINFOMSG_LEN {
            return;
        }
        let arphrd = u16::from_ne_bytes([payload[2], payload[3]]);
        let mut name = None;
        let mut link_kind = None;
        for (attr, value) in attributes(&payload[IFINFOMSG_LEN..]) {
            match attr {
                IFLA_IFNAME => name = Some(c_string(value)),
                IFLA_LINKINFO => {
                    for (info, data) in attributes(value) {
                        if info == IFLA_INFO_KIND {
                            link_kind = Some(c_string(data));
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(name) = name {
            links.push(Link {
                name,
                kind: link_kind,
                arphrd,
            });
        }
    })?;
    Ok(links)
}

fn dump_addresses() -> io::Result<BTreeSet<IpAddr>> {
    const IFADDRMSG_LEN: usize = 8;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    let mut addresses = BTreeSet::new();
    dump(libc::RTM_GETADDR, &[0u8; IFADDRMSG_LEN], |kind, payload| {
        if kind != libc::RTM_NEWADDR || payload.len() < IFADDRMSG_LEN {
            return;
        }
        for (attr, value) in attributes(&payload[IFADDRMSG_LEN..]) {
            if attr != IFA_ADDRESS && attr != IFA_LOCAL {
                continue;
            }
            if let Ok(octets) = <[u8; 4]>::try_from(value) {
                addresses.insert(IpAddr::V4(Ipv4Addr::from(octets)));
            } else if let Ok(octets) = <[u8; 16]>::try_from(value) {
                addresses.insert(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }
    })?;
    Ok(addresses)
}

/// Programs whose local listeners can be proxies that carry what they are
/// asked for out encrypted: Tailscale in userspace-networking mode (its
/// SOCKS5 `--socks5-server` and HTTP `--outbound-http-proxy-listen` proxies
/// are then the only way to the tailnet or an exit node), SSH dynamic and
/// local forwarding, and the common proxy tunnels.
const PROXY_PROGRAMS: &[&str] = &[
    "tailscaled",
    "ssh",
    "sing-box",
    "xray",
    "v2ray",
    "clash",
    "mihomo",
    "wireproxy",
    "microsocks",
    "sockd",
    "danted",
    "3proxy",
    "gost",
    "sslocal",
    "ss-local",
    "cloudflared",
    "tor",
    "warp-svc",
    "hysteria",
    "trojan",
    "naive",
    "brook",
    "chisel",
];
/// Proxy settings a client program reads from its environment.
const PROXY_VARS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// Addresses and ports local proxies listen on, by the inode of their
/// namespace: every TCP listener of a [`PROXY_PROGRAMS`] process, and every
/// local address a process's proxy settings name.
pub fn proxy_listeners() -> BTreeMap<u64, BTreeSet<(IpAddr, u16)>> {
    let mut out: BTreeMap<u64, BTreeSet<(IpAddr, u16)>> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let pid = entry.path();
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        let Ok(ns) = std::fs::metadata(pid.join("ns/net")) else {
            continue;
        };
        let is_proxy = std::fs::read_to_string(pid.join("comm"))
            .is_ok_and(|comm| PROXY_PROGRAMS.contains(&comm.trim_end()));
        if is_proxy {
            let sockets = socket_inodes(&pid.join("fd"));
            let ports = out.entry(ns.ino()).or_default();
            for table in ["net/tcp", "net/tcp6"] {
                if let Ok(text) = std::fs::read_to_string(pid.join(table)) {
                    ports.extend(listening(&text, &sockets));
                }
            }
        }
        if let Ok(environ) = std::fs::read(pid.join("environ")) {
            let named: Vec<(IpAddr, u16)> = environ
                .split(|&b| b == 0)
                .filter_map(|var| std::str::from_utf8(var).ok()?.split_once('='))
                .filter(|(name, _)| PROXY_VARS.contains(name))
                .filter_map(|(_, value)| local_proxy(value))
                .collect();
            if !named.is_empty() {
                out.entry(ns.ino()).or_default().extend(named);
            }
        }
    }
    out
}

/// The loopback address and port a proxy setting names, if it names one.
pub fn local_proxy(value: &str) -> Option<(IpAddr, u16)> {
    let rest = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = rest.split('/').next()?.rsplit('@').next()?;
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = match host {
        "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        other => other.parse().ok()?,
    };
    ip.is_loopback().then_some((ip, port))
}

fn socket_inodes(fd_dir: &Path) -> BTreeSet<u64> {
    let mut inodes = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let target = target.to_string_lossy();
                if let Some(inode) = target
                    .strip_prefix("socket:[")
                    .and_then(|rest| rest.strip_suffix(']'))
                    .and_then(|inode| inode.parse().ok())
                {
                    inodes.insert(inode);
                }
            }
        }
    }
    inodes
}

/// Local addresses of the `LISTEN` sockets in a `/proc/net/tcp{,6}` table
/// that belong to `sockets`.
pub fn listening(table: &str, sockets: &BTreeSet<u64>) -> Vec<(IpAddr, u16)> {
    const TCP_LISTEN: &str = "0A";
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local = fields.get(1)?;
            let state = fields.get(3)?;
            let inode: u64 = fields.get(9)?.parse().ok()?;
            if *state != TCP_LISTEN || !sockets.contains(&inode) {
                return None;
            }
            let (address, port) = local.rsplit_once(':')?;
            Some((proc_address(address)?, u16::from_str_radix(port, 16).ok()?))
        })
        .collect()
}

/// An address as `/proc/net/tcp{,6}` prints it: 32-bit words in host order.
fn proc_address(hex: &str) -> Option<IpAddr> {
    let mut bytes = Vec::with_capacity(16);
    for word in 0..hex.len() / 8 {
        let value = u32::from_str_radix(hex.get(word * 8..word * 8 + 8)?, 16).ok()?;
        bytes.extend_from_slice(&value.to_ne_bytes());
    }
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).ok()?,
        ))),
        _ => None,
    }
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
    fn tunnels_are_not_plaintext_local_and_bridges_are() {
        assert!(link("eth0", None, ARPHRD_ETHER).plaintext_local());
        assert!(link("lo", None, ARPHRD_LOOPBACK).plaintext_local());
        assert!(link("docker0", Some("bridge"), ARPHRD_ETHER).plaintext_local());
        assert!(link("veth9", Some("veth"), ARPHRD_ETHER).plaintext_local());
        for tunnel in [
            link("tailscale0", Some("tun"), 65534),
            link("tap0", Some("tun"), ARPHRD_ETHER),
            link("wg0", Some("wireguard"), 65534),
            link("ppp0", None, 512),
            link("gre1", Some("gre"), 778),
        ] {
            assert!(!tunnel.plaintext_local(), "{tunnel:?}");
            assert!(!tunnel.forward_in(), "{tunnel:?}");
        }
        assert!(link("docker0", Some("bridge"), ARPHRD_ETHER).forward_in());
        assert!(!link("eth0", None, ARPHRD_ETHER).forward_in());
    }

    #[test]
    fn proxy_settings_naming_a_local_address_are_found() {
        assert_eq!(
            local_proxy("socks5h://localhost:1080"),
            Some(("127.0.0.1".parse().unwrap(), 1080))
        );
        assert_eq!(
            local_proxy("http://user:pw@[::1]:3128/"),
            Some(("::1".parse().unwrap(), 3128))
        );
        assert_eq!(
            local_proxy("127.0.0.1:8080"),
            Some(("127.0.0.1".parse().unwrap(), 8080))
        );
        assert_eq!(local_proxy("http://proxy.corp:3128"), None);
        assert_eq!(local_proxy("http://10.0.0.1:3128"), None);
    }

    #[test]
    fn listening_ports_come_from_the_proxys_own_listen_sockets() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:041F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0 100 0 0 10 0\n\
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0 100 0 0 10 0\n\
   2: 0100007F:041F 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 555 1 0 100 0 0 10 0\n";
        let ours = BTreeSet::from([555]);
        assert_eq!(
            listening(table, &ours),
            vec![("127.0.0.1".parse().unwrap(), 1055)]
        );
        assert_eq!(
            proc_address("00000000000000000000000000000000"),
            Some("::".parse().unwrap())
        );
        assert_eq!(
            proc_address("00000000000000000000000001000000"),
            Some("::1".parse().unwrap())
        );
    }
}
