//! The credential tunnel's nftables rules, sent over netlink: the guest rootfs
//! ships no `nft`, and the agent programs links and routes the same way.
//!
//! One table per address family in every network namespace, replaced whole
//! and atomically whenever its inputs change:
//!
//! ```text
//! table ip|ip6 smolvm_credentials {
//!   chain output {                       # connections this namespace opens
//!     type nat hook output priority -100;
//!     oifname != { <plaintext-local interfaces> } tcp dport 443  MARK DSCP redirect to :FLOWS
//!     oifname "lo" tcp dport <local proxy port>                  MARK DSCP redirect to :PROXY
//!   }
//!   chain prerouting {                   # connections it forwards for others
//!     type nat hook prerouting priority -100;
//!     iifname != { <NIC, loopback, VPN interfaces> } fib daddr type != local tcp dport 443 MARK DSCP redirect to :FLOWS
//!     iifname != { <NIC, loopback, VPN interfaces> } fib daddr type local tcp dport <proxy> MARK DSCP redirect to :PROXY
//!   }
//! ```
//!
//! Both chains list the interfaces they leave alone, so one the agent has not
//! seen yet (a bridge, veth or VPN created a moment ago) is redirected.
//!
//! ```text
//!   chain input {                        # the agent's listeners take only redirects
//!     type filter hook input priority 0;
//!     tcp dport { FLOWS, PROXY } ct status & dnat == 0 drop
//!   }
//! }
//! ```
//!
//! `MARK DSCP` is `meta mark != DIAL_MARK` and the DSCP field `!= DIAL_DSCP`:
//! the agent's own upstream connections carry both, so they are never caught
//! again here or in any namespace they are forwarded through.
//!
//! Each table is owned (`NFT_TABLE_F_OWNER`) by a netlink socket the agent
//! keeps open in that namespace: the kernel refuses anyone else's change to
//! it, and `nft flush ruleset` passes over it, so a workload cannot remove the
//! redirect, even as root.

use smolvm_protocol::intercept::tunnel::{DIAL_DSCP, DIAL_MARK};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const TABLE: &str = "smolvm_credentials";

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;
const NFTA_RULE_HANDLE: u16 = 3;
const NFT_MSG_DELRULE: u16 = 8;
/// Marks the agent's rules in other programs' chains.
const EXEMPTION_TAG: &[u8] = b"smolvm-credential-tunnel";
const NLA_F_NESTED: u16 = 1 << 15;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFT_TABLE_F_OWNER: u32 = 0x2;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_LOCAL_IN: u32 = 1;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_IP_PRI_NAT_DST: i32 = -100;
const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;

const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_MARK: u32 = 3;
const NFT_META_IIFNAME: u32 = 6;
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
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFT_CT_STATUS: u32 = 2;
const NFT_CT_DIRECTION: u32 = 1;
const IP_CT_DIR_REPLY: u8 = 1;
const IPS_DST_NAT: u32 = 1 << 5;
const NFTA_FIB_DREG: u16 = 1;
const NFTA_FIB_RESULT: u16 = 2;
const NFTA_FIB_FLAGS: u16 = 3;
const NFT_FIB_RESULT_ADDRTYPE: u32 = 3;
const NFTA_FIB_F_DADDR: u32 = 1 << 1;
const RTN_LOCAL: u32 = 2;
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const IFNAMSIZ: usize = 16;
const HTTPS: u16 = 443;

/// An address family the tunnel redirects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    fn nfproto(self) -> u8 {
        match self {
            Family::V4 => 2,
            Family::V6 => 10,
        }
    }

    /// The DSCP bits of the IP header: (offset, mask, the dial's value).
    fn dscp_field(self) -> (u32, Vec<u8>, Vec<u8>) {
        match self {
            Family::V4 => (1, vec![0xfc], vec![DIAL_DSCP << 2]),
            // Version (4 bits), then the traffic class whose top six bits
            // are the DSCP.
            Family::V6 => {
                let bits = u16::from(DIAL_DSCP) << 6;
                (0, vec![0x0f, 0xc0], bits.to_be_bytes().to_vec())
            }
        }
    }
}

/// Everything one family's table in one namespace depends on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    /// Interfaces that carry HTTPS in the clear to somewhere the tunnel
    /// already covers (the NIC, loopback, a bridge or veth into another
    /// namespace); anything else (a VPN TUN, WireGuard, a tunnel device) is
    /// redirected.
    pub plaintext_local: Vec<String>,
    /// Interfaces whose arriving traffic is not another namespace's to
    /// forward (the NIC, loopback, a VPN's inbound side); forwarded HTTPS
    /// arriving on any other is redirected.
    pub not_forwarded: Vec<String>,
    /// Local proxies of this family (Tailscale's userspace SOCKS5 and HTTP
    /// proxies): the address they listen on (`None` for every address) and
    /// their port.
    pub proxies: Vec<(Option<IpAddr>, u16)>,
    /// The agent's flow listener.
    pub flows_port: u16,
    /// The agent's proxy front listener.
    pub proxy_port: u16,
}

impl RuleSet {
    /// Rules the table holds when intact.
    pub fn rule_count(&self) -> usize {
        1 + self.proxies.len() + 1 + self.forwarded_proxies().count() + 2
    }

    /// Proxies another namespace can reach: listening on every address or on
    /// one that is not loopback.
    fn forwarded_proxies(&self) -> impl Iterator<Item = &(Option<IpAddr>, u16)> {
        self.proxies
            .iter()
            .filter(|(addr, _)| addr.is_none_or(|addr| !addr.is_loopback()))
    }
}

/// Replace `family`'s table with `rules`, atomically, owned by `owner`.
pub fn install(owner: &OwnedFd, family: Family, rules: &RuleSet) -> io::Result<()> {
    let (batch, acks) = batch(family, rules)?;
    send(owner, &batch, acks)
}

/// The netlink batch for [`install`] and how many acks it asks for.
pub fn batch(family: Family, rules: &RuleSet) -> io::Result<(Vec<u8>, u32)> {
    let mut b = Batch::new(family);
    b.batch_marker(NFNL_MSG_BATCH_BEGIN);
    // Create, delete and recreate: atomic and idempotent whether or not the
    // table exists, and connections already redirected keep their NAT.
    for (kind, create) in [
        (NFT_MSG_NEWTABLE, true),
        (NFT_MSG_DELTABLE, false),
        (NFT_MSG_NEWTABLE, true),
    ] {
        b.nft(kind, create, |b| {
            b.attr_str(NFTA_TABLE_NAME, TABLE);
            if kind == NFT_MSG_NEWTABLE {
                b.attr_u32(NFTA_TABLE_FLAGS, NFT_TABLE_F_OWNER);
            }
        });
    }
    for (chain, kind, hook, priority) in [
        ("output", "nat", NF_INET_LOCAL_OUT, NF_IP_PRI_NAT_DST),
        ("prerouting", "nat", NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST),
        ("input", "filter", NF_INET_LOCAL_IN, 0),
    ] {
        b.nft(NFT_MSG_NEWCHAIN, true, |b| {
            b.attr_str(NFTA_CHAIN_TABLE, TABLE);
            b.attr_str(NFTA_CHAIN_NAME, chain);
            b.nested(NFTA_CHAIN_HOOK, |b| {
                b.attr_u32(NFTA_HOOK_HOOKNUM, hook);
                b.attr_u32(NFTA_HOOK_PRIORITY, priority as u32);
            });
            b.attr_u32(NFTA_CHAIN_POLICY, NF_ACCEPT);
            b.attr_str(NFTA_CHAIN_TYPE, kind);
        });
    }
    let plaintext_local = rules
        .plaintext_local
        .iter()
        .map(|name| ifname(name))
        .collect::<io::Result<Vec<_>>>()?;
    let not_forwarded = rules
        .not_forwarded
        .iter()
        .map(|name| ifname(name))
        .collect::<io::Result<Vec<_>>>()?;
    let lo = ifname("lo")?;

    // Connections this namespace opens through anything but a plaintext-local
    // interface.
    b.rule("output", |b| {
        b.meta(NFT_META_OIFNAME);
        for name in &plaintext_local {
            b.cmp(NFT_CMP_NEQ, name);
        }
        b.not_ours(family);
        b.tcp_dport(HTTPS);
        b.redirect(rules.flows_port);
    });
    // Connections to a local proxy, only where it listens: a connection it
    // would refuse must still be refused.
    for &(addr, port) in &rules.proxies {
        b.rule("output", |b| {
            b.meta(NFT_META_OIFNAME);
            b.cmp(NFT_CMP_EQ, &lo);
            b.daddr(family, addr);
            b.not_ours(family);
            b.tcp_dport(port);
            b.redirect(rules.proxy_port);
        });
    }
    // Connections it forwards for another namespace.
    b.rule("prerouting", |b| {
        b.meta(NFT_META_IIFNAME);
        for name in &not_forwarded {
            b.cmp(NFT_CMP_NEQ, name);
        }
        b.daddr_type(NFT_CMP_NEQ, RTN_LOCAL);
        b.not_ours(family);
        b.tcp_dport(HTTPS);
        b.redirect(rules.flows_port);
    });
    // Connections forwarded to a proxy listening on this namespace's address.
    for &(addr, port) in rules.forwarded_proxies() {
        b.rule("prerouting", |b| {
            b.meta(NFT_META_IIFNAME);
            for name in &not_forwarded {
                b.cmp(NFT_CMP_NEQ, name);
            }
            b.daddr_type(NFT_CMP_EQ, RTN_LOCAL);
            b.daddr(family, addr);
            b.not_ours(family);
            b.tcp_dport(port);
            b.redirect(rules.proxy_port);
        });
    }
    // The listeners accept only what a redirect delivered.
    for port in [rules.flows_port, rules.proxy_port] {
        b.rule("input", |b| {
            b.tcp_dport(port);
            b.expr("ct", |b| {
                b.attr_u32(NFTA_CT_KEY, NFT_CT_STATUS);
                b.attr_u32(NFTA_CT_DREG, NFT_REG_1);
            });
            b.bitwise(&IPS_DST_NAT.to_ne_bytes(), &0u32.to_ne_bytes());
            b.cmp(NFT_CMP_EQ, &0u32.to_ne_bytes());
            b.verdict(NF_DROP);
        });
    }
    b.batch_marker(NFNL_MSG_BATCH_END);
    Ok((b.buf, b.acks))
}

/// How many rules `family`'s table holds, or `None` when it is gone.
pub fn rule_count(socket: &OwnedFd, family: Family) -> io::Result<Option<usize>> {
    let mut b = Batch::new(family);
    b.message(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE,
        (libc::NLM_F_DUMP | libc::NLM_F_ACK) as u16,
        family.nfproto(),
        0,
        |b| b.attr_str(NFTA_RULE_TABLE, TABLE),
    );
    drain(socket);
    sendto(socket, &b.buf)?;
    let mut rules = 0;
    let mut reply = vec![0u8; 64 * 1024];
    loop {
        let n = recv(socket, &mut reply)?;
        for (kind, payload) in messages(&reply[..n]) {
            if kind == libc::NLMSG_DONE as u16 {
                return Ok(Some(rules));
            }
            if kind == libc::NLMSG_ERROR as u16 {
                let errno = error_code(payload);
                if errno == 0 {
                    continue;
                }
                if errno == -libc::ENOENT {
                    return Ok(None);
                }
                return Err(io::Error::from_raw_os_error(-errno));
            }
            if kind == (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE {
                rules += 1;
            }
        }
    }
}

/// A netlink socket in the calling thread's namespace, to own its tables.
pub fn owner() -> io::Result<OwnedFd> {
    open(0)
}

/// Discard replies left queued on `socket` by an earlier, abandoned request.
fn drain(socket: &OwnedFd) {
    let mut buf = [0u8; 8192];
    // SAFETY: recv into a local buffer on a socket this module owns.
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

/// A base chain another program hooked where a redirected connection's
/// replies pass on their way back to the workload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignChain {
    family: u8,
    table: String,
    chain: String,
}

/// Base chains of other tables at prerouting and input.
///
/// A redirected connection's replies come back on loopback from the
/// destination's address. A VPN's anti-spoofing rule drops exactly that
/// (Tailscale drops its range arriving on anything but `tailscale0`; wg-quick
/// drops traffic to its address from elsewhere), so every such chain gets
/// [`add_exemption`] first.
pub fn foreign_base_chains(socket: &OwnedFd) -> io::Result<Vec<ForeignChain>> {
    let mut b = Batch::new(Family::V4);
    b.message(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETCHAIN,
        libc::NLM_F_DUMP as u16,
        libc::AF_UNSPEC as u8,
        0,
        |_| {},
    );
    let mut chains = Vec::new();
    dump(socket, &b.buf, |kind, payload| {
        if kind != (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN || payload.len() < 4 {
            return;
        }
        let family = payload[0];
        if ![1u8, 2, 10].contains(&family) {
            return; // inet, ip, ip6
        }
        let (mut table, mut chain, mut hook) = (None, None, None);
        for (attr, value) in attributes(&payload[4..]) {
            match attr {
                NFTA_CHAIN_TABLE => table = Some(c_string(value)),
                NFTA_CHAIN_NAME => chain = Some(c_string(value)),
                NFTA_CHAIN_HOOK => {
                    for (hattr, hvalue) in attributes(value) {
                        if hattr == NFTA_HOOK_HOOKNUM && hvalue.len() == 4 {
                            hook = Some(u32::from_be_bytes(hvalue.try_into().unwrap()));
                        }
                    }
                }
                _ => {}
            }
        }
        if let (Some(table), Some(chain), Some(hook)) = (table, chain, hook) {
            if table != TABLE && (hook == NF_INET_PRE_ROUTING || hook == NF_INET_LOCAL_IN) {
                chains.push(ForeignChain {
                    family,
                    table,
                    chain,
                });
            }
        }
    })?;
    Ok(chains)
}

/// Where the agent's exemption stands in `chain`.
pub struct Exemption {
    /// The chain's first rule is the exemption.
    pub first: bool,
    /// Handles of every copy of it in the chain.
    handles: Vec<u64>,
}

/// Find the agent's exemption in `chain`.
pub fn exemption(socket: &OwnedFd, chain: &ForeignChain) -> io::Result<Exemption> {
    let mut b = Batch::new(Family::V4);
    b.message(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE,
        libc::NLM_F_DUMP as u16,
        chain.family,
        0,
        |b| {
            b.attr_str(NFTA_RULE_TABLE, &chain.table);
            b.attr_str(NFTA_RULE_CHAIN, &chain.chain);
        },
    );
    let mut state = Exemption {
        first: false,
        handles: Vec::new(),
    };
    let mut position = 0;
    dump(socket, &b.buf, |kind, payload| {
        if kind != (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE || payload.len() < 4 {
            return;
        }
        let attrs = attributes(&payload[4..]);
        let ours = attrs
            .iter()
            .any(|(attr, value)| *attr == NFTA_RULE_USERDATA && *value == EXEMPTION_TAG);
        if ours {
            if position == 0 {
                state.first = true;
            }
            if let Some((_, handle)) = attrs.iter().find(|(attr, _)| *attr == NFTA_RULE_HANDLE) {
                if let Ok(handle) = <[u8; 8]>::try_from(*handle) {
                    state.handles.push(u64::from_be_bytes(handle));
                }
            }
        }
        position += 1;
    })?;
    Ok(state)
}

/// Put `iifname "lo" ct direction reply ct status dnat accept` first in
/// `chain`, replacing copies another program's insertions pushed down: a
/// redirected connection's replies, generated on this host and translated
/// back to the destination's address, are not spoofed.
pub fn add_exemption(socket: &OwnedFd, chain: &ForeignChain, stale: &Exemption) -> io::Result<()> {
    let mut b = Batch::new(Family::V4);
    b.batch_marker(NFNL_MSG_BATCH_BEGIN);
    for &handle in &stale.handles {
        b.acks += 1;
        b.message(
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELRULE,
            libc::NLM_F_ACK as u16,
            chain.family,
            0,
            |b| {
                b.attr_str(NFTA_RULE_TABLE, &chain.table);
                b.attr_str(NFTA_RULE_CHAIN, &chain.chain);
                b.attr(NFTA_RULE_HANDLE, &handle.to_be_bytes());
            },
        );
    }
    b.acks += 1;
    // No NLM_F_APPEND: the rule goes first.
    b.message(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
        (libc::NLM_F_ACK | libc::NLM_F_CREATE) as u16,
        chain.family,
        0,
        |b| {
            b.attr_str(NFTA_RULE_TABLE, &chain.table);
            b.attr_str(NFTA_RULE_CHAIN, &chain.chain);
            b.nested(NFTA_RULE_EXPRESSIONS, |b| {
                b.meta(NFT_META_IIFNAME);
                b.cmp(NFT_CMP_EQ, &ifname("lo").expect("loopback name"));
                b.expr("ct", |b| {
                    b.attr_u32(NFTA_CT_KEY, NFT_CT_DIRECTION);
                    b.attr_u32(NFTA_CT_DREG, NFT_REG_1);
                });
                b.cmp(NFT_CMP_EQ, &[IP_CT_DIR_REPLY]);
                b.expr("ct", |b| {
                    b.attr_u32(NFTA_CT_KEY, NFT_CT_STATUS);
                    b.attr_u32(NFTA_CT_DREG, NFT_REG_1);
                });
                b.bitwise(&IPS_DST_NAT.to_ne_bytes(), &0u32.to_ne_bytes());
                b.cmp(NFT_CMP_NEQ, &0u32.to_ne_bytes());
                b.verdict(NF_ACCEPT);
            });
            b.attr(NFTA_RULE_USERDATA, EXEMPTION_TAG);
        },
    );
    b.batch_marker(NFNL_MSG_BATCH_END);
    send(socket, &b.buf, b.acks)
}

/// Send one dump request on `socket` and hand every reply message to `each`.
fn dump(socket: &OwnedFd, request: &[u8], mut each: impl FnMut(u16, &[u8])) -> io::Result<()> {
    drain(socket);
    sendto(socket, request)?;
    let mut reply = vec![0u8; 64 * 1024];
    loop {
        let n = recv(socket, &mut reply)?;
        for (kind, payload) in messages(&reply[..n]) {
            if kind == libc::NLMSG_DONE as u16 {
                return Ok(());
            }
            if kind == libc::NLMSG_ERROR as u16 {
                let errno = error_code(payload);
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                continue;
            }
            each(kind, payload);
        }
    }
}

/// Netlink attributes after a fixed header: (type, payload).
pub(super) fn attributes(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let kind = u16::from_ne_bytes([buf[2], buf[3]]) & 0x3fff;
        if len < 4 || len > buf.len() {
            break;
        }
        out.push((kind, &buf[4..len]));
        buf = &buf[((len + 3) & !3).min(buf.len())..];
    }
    out
}

pub(super) fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn ifname(name: &str) -> io::Result<[u8; IFNAMSIZ]> {
    if name.is_empty() || name.len() >= IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name {name:?}"),
        ));
    }
    let mut out = [0u8; IFNAMSIZ];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Ok(out)
}

struct Batch {
    buf: Vec<u8>,
    seq: u32,
    acks: u32,
    family: Family,
}

impl Batch {
    fn new(family: Family) -> Self {
        Self {
            buf: Vec::new(),
            seq: 0,
            acks: 0,
            family,
        }
    }

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

    fn batch_marker(&mut self, kind: u16) {
        self.message(kind, 0, libc::AF_UNSPEC as u8, NFNL_SUBSYS_NFTABLES, |_| {});
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
        let family = self.family.nfproto();
        self.message((NFNL_SUBSYS_NFTABLES << 8) | kind, flags, family, 0, body);
    }

    fn rule(&mut self, chain: &str, expressions: impl FnOnce(&mut Self)) {
        self.nft(NFT_MSG_NEWRULE, true, |b| {
            b.attr_str(NFTA_RULE_TABLE, TABLE);
            b.attr_str(NFTA_RULE_CHAIN, chain);
            b.nested(NFTA_RULE_EXPRESSIONS, expressions);
        });
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

    fn payload(&mut self, base: u32, offset: u32, len: u32) {
        self.expr("payload", |b| {
            b.attr_u32(NFTA_PAYLOAD_DREG, NFT_REG_1);
            b.attr_u32(NFTA_PAYLOAD_BASE, base);
            b.attr_u32(NFTA_PAYLOAD_OFFSET, offset);
            b.attr_u32(NFTA_PAYLOAD_LEN, len);
        });
    }

    fn bitwise(&mut self, mask: &[u8], xor: &[u8]) {
        self.expr("bitwise", |b| {
            b.attr_u32(NFTA_BITWISE_SREG, NFT_REG_1);
            b.attr_u32(NFTA_BITWISE_DREG, NFT_REG_1);
            b.attr_u32(NFTA_BITWISE_LEN, mask.len() as u32);
            b.nested(NFTA_BITWISE_MASK, |b| b.attr(NFTA_DATA_VALUE, mask));
            b.nested(NFTA_BITWISE_XOR, |b| b.attr(NFTA_DATA_VALUE, xor));
        });
    }

    /// Skip the agent's own upstream connections, by mark in this namespace
    /// and by DSCP wherever they are forwarded.
    fn not_ours(&mut self, family: Family) {
        self.meta(NFT_META_MARK);
        self.cmp(NFT_CMP_NEQ, &DIAL_MARK.to_ne_bytes());
        let (offset, mask, value) = family.dscp_field();
        self.payload(NFT_PAYLOAD_NETWORK_HEADER, offset, mask.len() as u32);
        self.bitwise(&mask, &vec![0; mask.len()]);
        self.cmp(NFT_CMP_NEQ, &value);
    }

    /// Match the destination address, when there is one to match.
    fn daddr(&mut self, family: Family, addr: Option<IpAddr>) {
        match (family, addr) {
            (Family::V4, Some(IpAddr::V4(v4))) => {
                self.payload(NFT_PAYLOAD_NETWORK_HEADER, 16, 4);
                self.cmp(NFT_CMP_EQ, &v4.octets());
            }
            (Family::V6, Some(IpAddr::V6(v6))) => {
                self.payload(NFT_PAYLOAD_NETWORK_HEADER, 24, 16);
                self.cmp(NFT_CMP_EQ, &v6.octets());
            }
            _ => {}
        }
    }

    fn tcp_dport(&mut self, port: u16) {
        self.meta(NFT_META_L4PROTO);
        self.cmp(NFT_CMP_EQ, &[libc::IPPROTO_TCP as u8]);
        self.payload(NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2);
        self.cmp(NFT_CMP_EQ, &port.to_be_bytes());
    }

    fn daddr_type(&mut self, op: u32, rtn: u32) {
        self.expr("fib", |b| {
            b.attr_u32(NFTA_FIB_DREG, NFT_REG_1);
            b.attr_u32(NFTA_FIB_RESULT, NFT_FIB_RESULT_ADDRTYPE);
            b.attr_u32(NFTA_FIB_FLAGS, NFTA_FIB_F_DADDR);
        });
        self.cmp(op, &rtn.to_ne_bytes());
    }

    fn redirect(&mut self, port: u16) {
        self.expr("immediate", |b| {
            b.attr_u32(NFTA_IMMEDIATE_DREG, NFT_REG_1);
            b.nested(NFTA_IMMEDIATE_DATA, |b| {
                b.attr(NFTA_DATA_VALUE, &port.to_be_bytes())
            });
        });
        self.expr("redir", |b| {
            b.attr_u32(NFTA_REDIR_REG_PROTO_MIN, NFT_REG_1);
        });
    }

    fn verdict(&mut self, code: u32) {
        self.expr("immediate", |b| {
            b.attr_u32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
            b.nested(NFTA_IMMEDIATE_DATA, |b| {
                b.nested(NFTA_DATA_VERDICT, |b| b.attr_u32(NFTA_VERDICT_CODE, code))
            });
        });
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }
}

fn open(groups: u32) -> io::Result<OwnedFd> {
    // SAFETY: plain socket syscalls; the descriptor is owned from creation.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
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
        let mut local: libc::sockaddr_nl = std::mem::zeroed();
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        local.nl_groups = groups;
        if libc::bind(
            fd.as_raw_fd(),
            (&local as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
}

fn sendto(socket: &OwnedFd, buf: &[u8]) -> io::Result<()> {
    // SAFETY: sendto from a local buffer to the kernel's netlink address.
    unsafe {
        let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if libc::sendto(
            socket.as_raw_fd(),
            buf.as_ptr().cast(),
            buf.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn recv(socket: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: recv into a caller-owned buffer.
    let n = unsafe { libc::recv(socket.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Netlink messages in a datagram: (type, payload after the header).
pub(super) fn messages(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 16 {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        if len < 16 || len > buf.len() {
            break;
        }
        out.push((kind, &buf[16..len]));
        buf = &buf[((len + 3) & !3).min(buf.len())..];
    }
    out
}

fn error_code(payload: &[u8]) -> i32 {
    payload
        .get(0..4)
        .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
        .unwrap_or(-libc::EIO)
}

/// Send a batch in one datagram and wait for every ack it asked for.
fn send(socket: &OwnedFd, batch: &[u8], mut acks: u32) -> io::Result<()> {
    drain(socket);
    sendto(socket, batch)?;
    let mut reply = vec![0u8; 16 * 1024];
    while acks > 0 {
        let n = recv(socket, &mut reply)?;
        for (kind, payload) in messages(&reply[..n]) {
            if kind == libc::NLMSG_ERROR as u16 {
                let errno = error_code(payload);
                if errno < 0 {
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                acks = acks.saturating_sub(1);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> RuleSet {
        RuleSet {
            plaintext_local: vec!["lo".into(), "eth0".into(), "docker0".into()],
            not_forwarded: vec!["lo".into(), "eth0".into(), "tailscale0".into()],
            proxies: vec![(Some("127.0.0.1".parse().unwrap()), 1055), (None, 34152)],
            flows_port: 40123,
            proxy_port: 40124,
        }
    }

    #[test]
    fn the_batch_replaces_the_table_with_every_rule_the_set_needs() {
        let (batch, acks) = batch(Family::V4, &rules()).unwrap();
        let messages = messages(&batch);
        let kinds: Vec<u16> = messages.iter().map(|(kind, _)| *kind).collect();
        // begin, new/del/new table, three chains, the rules, end
        assert_eq!(
            &kinds[..7],
            &[0x10, 0x0a00, 0x0a02, 0x0a00, 0x0a03, 0x0a03, 0x0a03]
        );
        assert_eq!(*kinds.last().unwrap(), 0x11);
        let rules_sent = kinds.iter().filter(|&&k| k == 0x0a06).count();
        assert_eq!(rules_sent, rules().rule_count());
        assert_eq!(acks as usize, 3 + 3 + rules().rule_count());
        let all: Vec<u8> = messages.iter().flat_map(|(_, p)| p.to_vec()).collect();
        let contains = |needle: &[u8]| all.windows(needle.len()).any(|w| w == needle);
        assert!(contains(b"docker0\0\0\0\0\0\0\0\0\0"), "interface operand");
        assert!(contains(&40123u16.to_be_bytes()), "flow listener");
        assert!(contains(&1055u16.to_be_bytes()), "proxy port");
        assert!(contains(&[DIAL_DSCP << 2]), "v4 DSCP");
        assert!(contains(b"redir\0") && contains(b"fib\0") && contains(b"ct\0"));
    }

    #[test]
    fn the_v6_table_matches_the_traffic_class_dscp() {
        let (batch, _) = batch(Family::V6, &rules()).unwrap();
        let bits = (u16::from(DIAL_DSCP) << 6).to_be_bytes();
        assert!(batch.windows(2).any(|w| w == bits));
        assert_eq!(messages(&batch)[1].1[0], 10, "nfgen family is ip6");
    }

    #[test]
    fn an_interface_name_too_long_for_the_kernel_is_refused() {
        let mut rules = rules();
        rules.plaintext_local.push("a-very-long-ifname".into());
        assert!(batch(Family::V4, &rules).is_err());
    }
}
