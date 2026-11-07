//! Guest side of the credential tunnel.
//!
//! The host intercepts HTTPS on the machine's NIC, so a workload that routes a
//! credential host through a TUN device instead (Tailscale's `tailscale0` for
//! a tailnet host or an exit node, a WireGuard interface) would send the
//! placeholder upstream unreplaced. When the host enables the tunnel
//! ([`guest_env::CREDENTIAL_TUNNEL`]) the agent:
//!
//! 1. installs one nftables rule that redirects TCP port 443 leaving through
//!    any interface other than the NIC and loopback to a local listener;
//! 2. hands each redirected connection to the host's interceptor over vsock
//!    ([`ports::CREDENTIAL_TUNNEL`]), prefixed with its original destination;
//! 3. opens the upstream connection when the interceptor asks
//!    ([`ports::CREDENTIAL_DIAL`]), with [`tunnel::DIAL_MARK`] so the redirect
//!    skips it and it follows the route the workload's connection would have
//!    taken.
//!
//! The interceptor terminates TLS and verifies the upstream certificate on the
//! host, so the guest relays only ciphertext and never holds a credential
//! value. If the rule is missing (an older kernel, or a workload that flushed
//! the ruleset), the connection goes out as before: the placeholder travels
//! unreplaced and no value is exposed.

use smolvm_protocol::intercept::{connect_verdict, tunnel};
use smolvm_protocol::{guest_env, ports};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::thread;
use std::time::Duration;

/// The machine's own NIC, whose traffic the host already intercepts.
const NIC: &str = "eth0";
/// Upper bound on the agent's connect to an upstream for the interceptor.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Whether the host enabled the tunnel for this boot.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::CREDENTIAL_TUNNEL).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Install the redirect and start both halves of the tunnel.
pub fn start() {
    // Bind and install synchronously so the rule is in place before any
    // workload starts; only the accept loops run in the background.
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::warn!(error = %e, "credential tunnel: cannot bind the redirect listener");
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            tracing::warn!(error = %e, "credential tunnel: redirect listener has no address");
            return;
        }
    };
    if let Err(e) = nft::install_redirect(NIC, port) {
        tracing::warn!(
            error = %e,
            "credential tunnel: cannot install the nftables redirect; HTTPS routed through \
             another interface than {NIC} will not have credentials substituted"
        );
        return;
    }
    tracing::info!(
        port,
        "credential tunnel: redirecting HTTPS that leaves through other interfaces"
    );
    let _ = thread::Builder::new()
        .name("cred-tunnel-dial".into())
        .spawn(|| {
            if let Err(e) = serve_dials() {
                tracing::warn!(error = %e, "credential tunnel: dial service stopped");
            }
        });
    let _ = thread::Builder::new()
        .name("cred-tunnel".into())
        .spawn(move || accept_redirected(listener));
}

fn accept_redirected(listener: TcpListener) {
    for client in listener.incoming() {
        let client = match client {
            Ok(client) => client,
            Err(e) => {
                tracing::debug!(error = %e, "credential tunnel: accept failed");
                continue;
            }
        };
        let _ = thread::Builder::new()
            .name("cred-tunnel-flow".into())
            .spawn(move || {
                if let Err(e) = hand_to_host(client) {
                    tracing::debug!(error = %e, "credential tunnel: flow ended");
                }
            });
    }
}

/// Give one redirected connection to the host interceptor.
fn hand_to_host(client: TcpStream) -> io::Result<()> {
    let destination = original_destination(&client)?;
    let _ = client.set_nodelay(true);
    let mut host = crate::vsock::connect(ports::CREDENTIAL_TUNNEL)?;
    tunnel::write_destination(&mut host, destination)?;
    crate::relay::relay_half_close(host, client)
}

/// The destination the workload dialed, before the redirect rewrote it.
fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    // SAFETY: `addr` is a properly sized, zeroed sockaddr_in and `len` its size.
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
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
    }
}

fn serve_dials() -> io::Result<()> {
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
        let _ = thread::Builder::new()
            .name("cred-tunnel-up".into())
            .spawn(move || {
                if let Err(e) = dial(host) {
                    tracing::debug!(error = %e, "credential tunnel: upstream ended");
                }
            });
    }
}

/// Open the upstream connection the interceptor asked for and relay it.
fn dial(mut host: crate::vsock::VsockStream) -> io::Result<()> {
    let destination = tunnel::read_destination(&mut host)?;
    let upstream = connect_marked(destination);
    host.write_all(&[connect_verdict(&upstream)])?;
    crate::relay::relay_half_close(host, upstream?)
}

/// Connect with [`tunnel::DIAL_MARK`] set before the SYN, so the redirect does
/// not catch the connection and it routes like an ordinary one.
fn connect_marked(destination: SocketAddr) -> io::Result<TcpStream> {
    let family = match destination {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: plain socket syscalls on a descriptor this function owns; the
    // sockaddr buffers are sized for their family.
    unsafe {
        let fd = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Owned from here on, so every early return closes it.
        let stream = TcpStream::from_raw_fd(fd);
        let mark = tunnel::DIAL_MARK;
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SO_SNDTIMEO bounds a blocking connect on Linux.
        let timeout = libc::timeval {
            tv_sec: DIAL_TIMEOUT.as_secs() as _,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
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
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&none as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
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

/// The one nftables rule the tunnel needs, sent over netlink: the guest
/// rootfs ships no `nft`, and the agent programs links and routes the same way.
///
/// ```text
/// table ip smolvm_credentials {
///   chain output {
///     type nat hook output priority -100; policy accept;
///     oifname != "eth0" oifname != "lo" meta mark != 0x534d
///       meta l4proto tcp tcp dport 443 dnat to 127.0.0.1:<port>
///   }
/// }
/// ```
///
/// Only IPv4 is redirected.
mod nft {
    use std::io;

    pub const TABLE: &str = "smolvm_credentials";
    const CHAIN: &str = "output";

    const NETLINK_NETFILTER: libc::c_int = 12;
    const NFNL_SUBSYS_NFTABLES: u16 = 10;
    const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
    const NFNL_MSG_BATCH_END: u16 = 0x11;
    const NFT_MSG_NEWTABLE: u16 = 0;
    const NFT_MSG_DELTABLE: u16 = 2;
    const NFT_MSG_NEWCHAIN: u16 = 3;
    const NFT_MSG_NEWRULE: u16 = 6;
    const NFPROTO_IPV4: u8 = 2;
    const NLA_F_NESTED: u16 = 1 << 15;

    const NFTA_TABLE_NAME: u16 = 1;
    const NFTA_CHAIN_TABLE: u16 = 1;
    const NFTA_CHAIN_NAME: u16 = 3;
    const NFTA_CHAIN_HOOK: u16 = 4;
    const NFTA_CHAIN_POLICY: u16 = 5;
    const NFTA_CHAIN_TYPE: u16 = 7;
    const NFTA_HOOK_HOOKNUM: u16 = 1;
    const NFTA_HOOK_PRIORITY: u16 = 2;
    const NF_INET_LOCAL_OUT: u32 = 3;
    const NF_IP_PRI_NAT_DST: i32 = -100;
    const NF_ACCEPT: u32 = 1;

    const NFTA_RULE_TABLE: u16 = 1;
    const NFTA_RULE_CHAIN: u16 = 2;
    const NFTA_RULE_EXPRESSIONS: u16 = 4;
    const NFTA_LIST_ELEM: u16 = 1;
    const NFTA_EXPR_NAME: u16 = 1;
    const NFTA_EXPR_DATA: u16 = 2;
    const NFTA_DATA_VALUE: u16 = 1;

    const NFTA_META_DREG: u16 = 1;
    const NFTA_META_KEY: u16 = 2;
    const NFT_META_MARK: u32 = 3;
    const NFT_META_OIFNAME: u32 = 7;
    const NFT_META_L4PROTO: u32 = 16;
    const NFTA_CMP_SREG: u16 = 1;
    const NFTA_CMP_OP: u16 = 2;
    const NFTA_CMP_DATA: u16 = 3;
    const NFT_CMP_EQ: u32 = 0;
    const NFT_CMP_NEQ: u32 = 1;
    const NFTA_PAYLOAD_DREG: u16 = 1;
    const NFTA_PAYLOAD_BASE: u16 = 2;
    const NFTA_PAYLOAD_OFFSET: u16 = 3;
    const NFTA_PAYLOAD_LEN: u16 = 4;
    const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
    const NFTA_IMMEDIATE_DREG: u16 = 1;
    const NFTA_IMMEDIATE_DATA: u16 = 2;
    const NFTA_NAT_TYPE: u16 = 1;
    const NFTA_NAT_FAMILY: u16 = 2;
    const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
    const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
    const NFT_NAT_DNAT: u32 = 1;
    const NFT_REG_1: u32 = 1;
    const NFT_REG_2: u32 = 2;
    const IFNAMSIZ: usize = 16;

    /// Replace the tunnel's table with one redirecting rule to `port`.
    pub fn install_redirect(nic: &str, port: u16) -> io::Result<()> {
        let (batch, acks) = redirect_batch(nic, port, super::tunnel::DIAL_MARK)?;
        send(&batch, acks)
    }

    /// The netlink batch for [`install_redirect`] and how many acks it asks for.
    pub(super) fn redirect_batch(nic: &str, port: u16, mark: u32) -> io::Result<(Vec<u8>, u32)> {
        let mut b = Batch::default();
        b.message(
            NFNL_MSG_BATCH_BEGIN,
            0,
            libc::AF_UNSPEC as u8,
            NFNL_SUBSYS_NFTABLES,
            |_| {},
        );
        // Create, delete and recreate: idempotent whether or not the table
        // exists (a restored checkpoint keeps the previous boot's rules).
        for (kind, create) in [
            (NFT_MSG_NEWTABLE, true),
            (NFT_MSG_DELTABLE, false),
            (NFT_MSG_NEWTABLE, true),
        ] {
            b.nft(kind, create, |b| b.attr_str(NFTA_TABLE_NAME, TABLE));
        }
        b.nft(NFT_MSG_NEWCHAIN, true, |b| {
            b.attr_str(NFTA_CHAIN_TABLE, TABLE);
            b.attr_str(NFTA_CHAIN_NAME, CHAIN);
            b.nested(NFTA_CHAIN_HOOK, |b| {
                b.attr_u32(NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
                b.attr_u32(NFTA_HOOK_PRIORITY, NF_IP_PRI_NAT_DST as u32);
            });
            b.attr_u32(NFTA_CHAIN_POLICY, NF_ACCEPT);
            b.attr_str(NFTA_CHAIN_TYPE, "nat");
        });
        let nic = ifname(nic)?;
        let lo = ifname("lo")?;
        b.nft(NFT_MSG_NEWRULE, true, |b| {
            b.attr_str(NFTA_RULE_TABLE, TABLE);
            b.attr_str(NFTA_RULE_CHAIN, CHAIN);
            b.nested(NFTA_RULE_EXPRESSIONS, |b| {
                b.meta(NFT_META_OIFNAME);
                b.cmp(NFT_CMP_NEQ, &nic);
                b.cmp(NFT_CMP_NEQ, &lo);
                b.meta(NFT_META_MARK);
                b.cmp(NFT_CMP_NEQ, &mark.to_ne_bytes());
                b.meta(NFT_META_L4PROTO);
                b.cmp(NFT_CMP_EQ, &[libc::IPPROTO_TCP as u8]);
                b.expr("payload", |b| {
                    b.attr_u32(NFTA_PAYLOAD_DREG, NFT_REG_1);
                    b.attr_u32(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
                    b.attr_u32(NFTA_PAYLOAD_OFFSET, 2);
                    b.attr_u32(NFTA_PAYLOAD_LEN, 2);
                });
                b.cmp(NFT_CMP_EQ, &443u16.to_be_bytes());
                b.immediate(NFT_REG_1, &[127, 0, 0, 1]);
                b.immediate(NFT_REG_2, &port.to_be_bytes());
                b.expr("nat", |b| {
                    b.attr_u32(NFTA_NAT_TYPE, NFT_NAT_DNAT);
                    b.attr_u32(NFTA_NAT_FAMILY, u32::from(NFPROTO_IPV4));
                    b.attr_u32(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
                    b.attr_u32(NFTA_NAT_REG_PROTO_MIN, NFT_REG_2);
                });
            });
        });
        b.message(
            NFNL_MSG_BATCH_END,
            0,
            libc::AF_UNSPEC as u8,
            NFNL_SUBSYS_NFTABLES,
            |_| {},
        );
        Ok((b.buf, b.acks))
    }

    fn ifname(name: &str) -> io::Result<[u8; IFNAMSIZ]> {
        if name.is_empty() || name.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name",
            ));
        }
        let mut out = [0u8; IFNAMSIZ];
        out[..name.len()].copy_from_slice(name.as_bytes());
        Ok(out)
    }

    #[derive(Default)]
    struct Batch {
        buf: Vec<u8>,
        seq: u32,
        acks: u32,
    }

    impl Batch {
        /// Append one netlink message with an `nfgenmsg` header.
        fn message(
            &mut self,
            kind: u16,
            flags: u16,
            family: u8,
            res_id: u16,
            body: impl FnOnce(&mut Self),
        ) {
            let start = self.buf.len();
            self.seq += 1;
            self.buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len, patched below
            self.buf.extend_from_slice(&kind.to_ne_bytes());
            self.buf
                .extend_from_slice(&((libc::NLM_F_REQUEST as u16) | flags).to_ne_bytes());
            self.buf.extend_from_slice(&self.seq.to_ne_bytes());
            self.buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
            self.buf.push(family);
            self.buf.push(0); // NFNETLINK_V0
            self.buf.extend_from_slice(&res_id.to_be_bytes());
            body(self);
            let len = (self.buf.len() - start) as u32;
            self.buf[start..start + 4].copy_from_slice(&len.to_ne_bytes());
        }

        /// An nf_tables object message that asks for an ack.
        fn nft(&mut self, kind: u16, create: bool, body: impl FnOnce(&mut Self)) {
            let mut flags = libc::NLM_F_ACK as u16;
            if create {
                flags |= libc::NLM_F_CREATE as u16;
            }
            if kind == NFT_MSG_NEWRULE {
                flags |= libc::NLM_F_APPEND as u16;
            }
            self.acks += 1;
            self.message(
                (NFNL_SUBSYS_NFTABLES << 8) | kind,
                flags,
                NFPROTO_IPV4,
                0,
                body,
            );
        }

        fn attr(&mut self, kind: u16, data: &[u8]) {
            self.buf
                .extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
            self.buf.extend_from_slice(&kind.to_ne_bytes());
            self.buf.extend_from_slice(data);
            self.pad();
        }

        fn attr_str(&mut self, kind: u16, value: &str) {
            let mut data = value.as_bytes().to_vec();
            data.push(0);
            self.attr(kind, &data);
        }

        /// nf_tables carries every 32-bit attribute big-endian.
        fn attr_u32(&mut self, kind: u16, value: u32) {
            self.attr(kind, &value.to_be_bytes());
        }

        fn nested(&mut self, kind: u16, body: impl FnOnce(&mut Self)) {
            let start = self.buf.len();
            self.buf.extend_from_slice(&0u16.to_ne_bytes());
            self.buf
                .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
            body(self);
            let len = (self.buf.len() - start) as u16;
            self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        }

        fn expr(&mut self, name: &str, data: impl FnOnce(&mut Self)) {
            self.nested(NFTA_LIST_ELEM, |b| {
                b.attr_str(NFTA_EXPR_NAME, name);
                b.nested(NFTA_EXPR_DATA, data);
            });
        }

        fn meta(&mut self, key: u32) {
            self.expr("meta", |b| {
                b.attr_u32(NFTA_META_KEY, key);
                b.attr_u32(NFTA_META_DREG, NFT_REG_1);
            });
        }

        fn cmp(&mut self, op: u32, value: &[u8]) {
            self.expr("cmp", |b| {
                b.attr_u32(NFTA_CMP_SREG, NFT_REG_1);
                b.attr_u32(NFTA_CMP_OP, op);
                b.nested(NFTA_CMP_DATA, |b| b.attr(NFTA_DATA_VALUE, value));
            });
        }

        fn immediate(&mut self, register: u32, value: &[u8]) {
            self.expr("immediate", |b| {
                b.attr_u32(NFTA_IMMEDIATE_DREG, register);
                b.nested(NFTA_IMMEDIATE_DATA, |b| b.attr(NFTA_DATA_VALUE, value));
            });
        }

        fn pad(&mut self) {
            while !self.buf.len().is_multiple_of(4) {
                self.buf.push(0);
            }
        }
    }

    /// Send the batch in one datagram and wait for every ack it asked for.
    fn send(batch: &[u8], mut acks: u32) -> io::Result<()> {
        // SAFETY: plain socket syscalls on a descriptor this function owns.
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = std::os::fd::OwnedFd::from_raw_fd(fd);
            use std::os::fd::{AsRawFd, FromRawFd};
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
            let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            if libc::sendto(
                fd.as_raw_fd(),
                batch.as_ptr().cast(),
                batch.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut reply = vec![0u8; 16 * 1024];
            while acks > 0 {
                let n = libc::recv(fd.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0);
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut rest = &reply[..n as usize];
                while rest.len() >= 16 {
                    let len = u32::from_ne_bytes(rest[0..4].try_into().unwrap()) as usize;
                    let kind = u16::from_ne_bytes(rest[4..6].try_into().unwrap());
                    if len < 16 || len > rest.len() {
                        break;
                    }
                    if kind == libc::NLMSG_ERROR as u16 && len >= 20 {
                        let errno = i32::from_ne_bytes(rest[16..20].try_into().unwrap());
                        if errno < 0 {
                            return Err(io::Error::from_raw_os_error(-errno));
                        }
                        acks -= 1;
                    }
                    rest = &rest[(len + 3) & !3..];
                    if acks == 0 {
                        break;
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk netlink messages in a batch: (type, flags, payload after nlmsghdr).
    fn messages(mut batch: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
        let mut out = Vec::new();
        while !batch.is_empty() {
            let len = u32::from_ne_bytes(batch[0..4].try_into().unwrap()) as usize;
            assert!(
                len >= 20 && len.is_multiple_of(4) && len <= batch.len(),
                "message length {len}"
            );
            let kind = u16::from_ne_bytes(batch[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(batch[6..8].try_into().unwrap());
            out.push((kind, flags, batch[16..len].to_vec()));
            batch = &batch[len..];
        }
        out
    }

    #[test]
    fn the_redirect_batch_replaces_the_table_and_adds_one_rule() {
        let (batch, acks) = nft::redirect_batch("eth0", 40123, tunnel::DIAL_MARK).unwrap();
        let messages = messages(&batch);
        let kinds: Vec<u16> = messages.iter().map(|(kind, _, _)| *kind).collect();
        // begin, new/del/new table, chain, rule, end
        assert_eq!(kinds, [0x10, 0x0a00, 0x0a02, 0x0a00, 0x0a03, 0x0a06, 0x11]);
        assert_eq!(acks, 5);
        let rule = &messages[5].2;
        let contains = |needle: &[u8]| rule.windows(needle.len()).any(|w| w == needle);
        assert!(contains(b"eth0\0\0\0\0\0\0\0\0\0\0\0\0"), "oifname operand");
        assert!(contains(nft::TABLE.as_bytes()));
        assert!(contains(&40123u16.to_be_bytes()), "redirect port");
        assert!(contains(&443u16.to_be_bytes()), "HTTPS port");
        assert!(contains(&tunnel::DIAL_MARK.to_ne_bytes()), "dial mark");
        assert!(contains(b"nat\0"));
    }

    #[test]
    fn an_interface_name_too_long_for_the_kernel_is_refused() {
        assert!(nft::redirect_batch("a-very-long-ifname", 1, 0).is_err());
    }
}
