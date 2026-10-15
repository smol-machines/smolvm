use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Fallback DNS server (Cloudflare) used when the host's resolver cannot be detected.
pub const FALLBACK_DNS: &str = "1.1.1.1";

/// Fallback DNS server as `IpAddr`.
pub const FALLBACK_DNS_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// Detect the host's primary DNS server, skipping loopback (a local stub such as
/// systemd-resolved or dnsmasq is not reachable from inside the VM).
/// Falls back to Cloudflare (1.1.1.1) if detection fails.
pub fn host_dns() -> IpAddr {
    host_nameservers()
        .into_iter()
        .find(|ip| !ip.is_loopback())
        .unwrap_or(FALLBACK_DNS_ADDR)
}

/// Where [`host_nameservers`] reads the host's resolver list.
#[cfg(not(windows))]
const HOST_RESOLVERS: &str = "/etc/resolv.conf";
#[cfg(windows)]
const HOST_RESOLVERS: &str = "GetNetworkParams";

/// The host's nameservers in order, from [`HOST_RESOLVERS`].
#[cfg(not(windows))]
fn host_nameservers() -> Vec<IpAddr> {
    resolv_conf_nameservers(&std::fs::read_to_string(HOST_RESOLVERS).unwrap_or_default())
}

/// The host's nameservers in order: the system's IPv4 resolver list, which is
/// what Windows has in place of `/etc/resolv.conf`.
#[cfg(windows)]
fn host_nameservers() -> Vec<IpAddr> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetNetworkParams, FIXED_INFO_W2KSP1};

    let mut len = 0u32;
    // SAFETY: a null buffer with a zero length only asks for the size needed.
    let rc = unsafe { GetNetworkParams(std::ptr::null_mut(), &mut len) };
    if rc != ERROR_BUFFER_OVERFLOW {
        tracing::debug!(rc, "GetNetworkParams size query failed");
        return Vec::new();
    }
    // u64 words keep the buffer aligned for the pointers inside FIXED_INFO.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    let info = buf.as_mut_ptr().cast::<FIXED_INFO_W2KSP1>();
    // SAFETY: `buf` is at least `len` bytes and aligned for FIXED_INFO.
    let rc = unsafe { GetNetworkParams(info, &mut len) };
    if rc != ERROR_SUCCESS {
        tracing::debug!(rc, "GetNetworkParams failed");
        return Vec::new();
    }
    // SAFETY: the list's nodes live inside `buf`, which outlives the walk.
    let head = unsafe { &(*info).DnsServerList };
    std::iter::successors(Some(head), |entry| unsafe { entry.Next.as_ref() })
        // An empty head entry (no resolver configured) does not parse and is skipped.
        .filter_map(|entry| {
            let text = entry.IpAddress.String.map(|c| c as u8);
            std::ffi::CStr::from_bytes_until_nul(&text)
                .ok()?
                .to_str()
                .ok()?
                .parse()
                .ok()
        })
        .collect()
}

/// Default DNS as string — prefers host's resolver, falls back to 1.1.1.1.
pub fn default_dns() -> String {
    host_dns().to_string()
}

/// Default DNS as `IpAddr`.
pub fn default_dns_addr() -> IpAddr {
    host_dns()
}

/// systemd-resolved's uplink resolver list.
///
/// On such a host `/etc/resolv.conf` is a symlink to the stub file, whose only
/// nameserver is the local stub (127.0.0.53); this file carries the real
/// uplinks the stub forwards to.
const SYSTEMD_RESOLVED_UPLINK: &str = "/run/systemd/resolve/resolv.conf";

/// Where [`effective_dns`] found the resolver it returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSource {
    /// The caller passed `--dns`.
    Override,
    /// The host's `/etc/resolv.conf`.
    HostResolvConf,
    /// systemd-resolved's uplink list, because every `/etc/resolv.conf` entry
    /// was the local stub and TSI cannot reach it.
    SystemdUplink,
    /// The host has no resolver this backend can use, so the backend keeps its
    /// own default (the public resolvers).
    BackendDefault,
}

/// The resolver a launched guest should send its DNS to.
///
/// `addr` is `None` when the host offers nothing usable, which leaves the
/// backend on its own default rather than inventing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveDns {
    /// The resolver, or `None` to keep the backend default.
    pub addr: Option<Ipv4Addr>,
    /// Which rule produced it.
    pub source: DnsSource,
}

/// Resolve the guest's resolver once, at launch, for either backend.
///
/// An explicit `--dns` wins. Otherwise the guest inherits the host's own
/// resolver, so a machine on a network that blocks the public resolvers (a VPN
/// with leak protection, a campus or corporate resolver) resolves names without
/// the caller having to discover and pass `--dns` first.
pub fn effective_dns(
    dns_override: Option<Ipv4Addr>,
    backend: crate::network::EffectiveNetworkBackend,
) -> EffectiveDns {
    let host = host_nameservers();
    let uplink = resolv_conf_nameservers(
        &std::fs::read_to_string(SYSTEMD_RESOLVED_UPLINK).unwrap_or_default(),
    );
    // A TSI guest dials its resolver itself, so the egress floor applies to it:
    // on a cloud VM the host resolver is the metadata address, and under the
    // strict floor a CGNAT resolver (Tailscale's 100.100.100.100) is blocked too.
    let floor = smolvm_network::EgressPolicy::unrestricted();
    let effective = select_dns(dns_override, backend, &host, &uplink, &|addr| {
        floor.allows_v4(addr)
    });
    if effective.source == DnsSource::BackendDefault
        && backend != crate::network::EffectiveNetworkBackend::None
    {
        // A network that blocks the public resolvers then fails every lookup in
        // the guest, so say what was read and how to choose one.
        tracing::warn!(
            looked_at = HOST_RESOLVERS,
            "no IPv4 host resolver this backend can reach; guest keeps the public resolvers, pass --dns to choose one"
        );
    }
    effective
}

/// The pure half of [`effective_dns`], with both resolver lists supplied. `reachable`
/// says whether a TSI guest may connect to an address; a host resolver it may
/// not reach is skipped, and with none left the guest keeps the public
/// resolvers.
fn select_dns(
    dns_override: Option<Ipv4Addr>,
    backend: crate::network::EffectiveNetworkBackend,
    host: &[IpAddr],
    systemd_uplink: &[IpAddr],
    reachable: &dyn Fn(Ipv4Addr) -> bool,
) -> EffectiveDns {
    use crate::network::EffectiveNetworkBackend;

    if let Some(addr) = dns_override {
        return EffectiveDns {
            addr: Some(addr),
            source: DnsSource::Override,
        };
    }
    let found = match backend {
        EffectiveNetworkBackend::None => None,
        // The gateway forwards guest queries from a host UDP socket, so a host
        // loopback stub is reachable and is taken as-is.
        EffectiveNetworkBackend::VirtioNet => v4(host)
            .next()
            .map(|addr| (addr, DnsSource::HostResolvConf)),
        // TSI does not translate a guest loopback destination to the host's
        // loopback, so a stub address would leave the guest talking to itself.
        EffectiveNetworkBackend::Tsi => v4(host)
            .find(|addr| !addr.is_loopback() && reachable(*addr))
            .map(|addr| (addr, DnsSource::HostResolvConf))
            .or_else(|| {
                v4(systemd_uplink)
                    .find(|addr| !addr.is_loopback() && reachable(*addr))
                    .map(|addr| (addr, DnsSource::SystemdUplink))
            }),
    };
    match found {
        Some((addr, source)) => EffectiveDns {
            addr: Some(addr),
            source,
        },
        None => EffectiveDns {
            addr: None,
            source: DnsSource::BackendDefault,
        },
    }
}

/// Every nameserver in a resolv.conf, in file order.
fn resolv_conf_nameservers(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver")?.trim().parse().ok())
        .collect()
}

/// The IPv4 entries of a resolver list, in order.
///
/// IPv6 entries are skipped: the resolver is carried as an `Ipv4Addr` all the
/// way to `--dns` and the virtio gateway's upstream.
fn v4(addrs: &[IpAddr]) -> impl Iterator<Item = Ipv4Addr> + '_ {
    addrs.iter().filter_map(|addr| match addr {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(_) => None,
    })
}

/// Transport a published port forwards.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    /// TCP (the default).
    #[default]
    Tcp,
    /// UDP, forwarded per remote client.
    Udp,
}

impl PortProtocol {
    /// Whether this is the default, TCP. Lets serialization omit the field, so
    /// a TCP mapping keeps the shape older readers expect.
    pub fn is_tcp(&self) -> bool {
        *self == Self::Tcp
    }

    /// Lowercase label, as written after a port spec (`8080:80/udp`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Split an optional `/tcp` or `/udp` suffix off a port spec.
    fn split_suffix(spec: &str) -> Result<(&str, Self), String> {
        match spec.rsplit_once('/') {
            None => Ok((spec, Self::Tcp)),
            Some((ports, "tcp")) => Ok((ports, Self::Tcp)),
            Some((ports, "udp")) => Ok((ports, Self::Udp)),
            Some((_, other)) => Err(format!(
                "unsupported port protocol '{other}': use tcp or udp, as in 8080:80/udp"
            )),
        }
    }
}

/// Stored `(host, guest)` port pairs of one protocol.
pub type PortTuples = Vec<(u16, u16)>;

/// Port mapping from host to guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    /// Port on the host.
    pub host: u16,
    /// Port inside the guest.
    pub guest: u16,
    /// Transport forwarded; omitted for TCP.
    #[serde(default, skip_serializing_if = "PortProtocol::is_tcp")]
    pub protocol: PortProtocol,
}

/// Maximum concrete mappings permitted for one machine.
///
/// The current forwarding implementation starts listener thread(s) per mapping,
/// so raising this limit requires multiplexing listeners or bounding the worker
/// pool in `smolvm-network` first.
pub const MAX_PORT_MAPPINGS: usize = 64;

/// A CLI or Smolfile port mapping before range expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMappingSpec {
    host: PortRange,
    guest: PortRange,
    protocol: PortProtocol,
}

/// An inclusive range of ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

/// Check if any CIDR in the list covers the given IP address.
pub fn cidrs_contain_ip(cidrs: &[String], ip: &str) -> bool {
    let ip: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    cidrs.iter().any(|cidr| {
        cidr.parse::<IpNet>()
            .or_else(|_| cidr.parse::<IpAddr>().map(IpNet::from))
            .is_ok_and(|net| net.contains(&ip))
    })
}

/// Returns true if every CIDR in the list falls entirely within loopback ranges
/// (127.0.0.0/8 for IPv4, ::1/128 for IPv6).
///
/// An empty slice returns false — no CIDRs means no policy at all, which is
/// distinct from an explicitly loopback-only policy.
pub fn cidrs_all_loopback(cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return false;
    }
    cidrs.iter().all(|cidr| {
        cidr.parse::<IpNet>()
            .or_else(|_| cidr.parse::<IpAddr>().map(IpNet::from))
            .is_ok_and(|net| net.network().is_loopback())
    })
}

/// Ensure the default DNS server is reachable in a CIDR allowlist.
///
/// If none of the existing CIDRs cover the DNS IP, appends it as /32.
///
/// Skipped when all CIDRs are loopback ranges — a loopback-only policy
/// intentionally blocks all external traffic, so auto-adding the DNS server
/// would violate the user's intent (e.g. `--outbound-localhost-only`).
pub fn ensure_dns_in_cidrs(cidrs: &mut Vec<String>) {
    if cidrs_all_loopback(cidrs) {
        return;
    }
    let dns = host_dns();
    if !cidrs_contain_ip(cidrs, &dns.to_string()) {
        cidrs.push(IpNet::from(dns).to_string());
    }
}

impl From<PortMapping> for PortMappingSpec {
    fn from(mapping: PortMapping) -> Self {
        let range = PortRange {
            start: mapping.host,
            end: mapping.host,
        };
        Self {
            host: range,
            guest: PortRange {
                start: mapping.guest,
                end: mapping.guest,
            },
            protocol: mapping.protocol,
        }
    }
}

impl PortMappingSpec {
    /// Parse a port mapping specification (`HOST:GUEST`, `PORT`, or equal-length
    /// ranges), optionally ending in `/tcp` or `/udp`.
    pub fn parse(full: &str) -> Result<Self, String> {
        let (spec, protocol) = PortProtocol::split_suffix(full)?;
        let (host, guest) = match spec.split_once(':') {
            Some((host, guest)) => (
                PortRange::parse(host, "host")?,
                PortRange::parse(guest, "guest")?,
            ),
            None => {
                let range = PortRange::parse(spec, "")?;
                (range, range)
            }
        };

        if host.len() != guest.len() {
            return Err(format!(
                "host and guest port ranges must have the same number of ports: {spec}"
            ));
        }

        Ok(Self {
            host,
            guest,
            protocol,
        })
    }

    /// Expand all user-supplied specs while enforcing the per-machine mapping cap.
    pub fn expand_all(specs: &[Self]) -> Result<Vec<PortMapping>, String> {
        let count = specs.iter().map(|spec| spec.host.len() as usize).sum();
        if count > MAX_PORT_MAPPINGS {
            return Err(format!(
                "port mappings expand to {count} entries; the maximum per machine is {MAX_PORT_MAPPINGS}"
            ));
        }

        let mut ports = Vec::with_capacity(count);
        for spec in specs {
            ports.extend(
                (spec.host.start..=spec.host.end)
                    .zip(spec.guest.start..=spec.guest.end)
                    .map(|(host, guest)| PortMapping::with_protocol(host, guest, spec.protocol)),
            );
        }
        Ok(ports)
    }
}

impl PortRange {
    fn parse(spec: &str, kind: &str) -> Result<Self, String> {
        let (start, end) = match spec.split_once('-') {
            Some((start, end)) => (parse_port(start, kind)?, parse_port(end, kind)?),
            None => {
                let port = parse_port(spec, kind)?;
                (port, port)
            }
        };

        if start > end {
            return Err(format!(
                "{kind} port range start must not exceed its end: {spec}"
            ));
        }

        Ok(Self { start, end })
    }

    const fn len(self) -> u32 {
        self.end as u32 - self.start as u32 + 1
    }
}

fn parse_port(spec: &str, kind: &str) -> Result<u16, String> {
    let label = if kind.is_empty() {
        "port".to_string()
    } else {
        format!("{kind} port")
    };
    let port: u16 = spec
        .parse()
        .map_err(|_| format!("invalid {label}: {spec}"))?;
    if port == 0 {
        return Err(format!("{label} 0 is not valid for VM port forwarding"));
    }
    Ok(port)
}

impl PortMapping {
    /// Create a new TCP port mapping.
    pub fn new(host: u16, guest: u16) -> Self {
        Self::with_protocol(host, guest, PortProtocol::Tcp)
    }

    /// Create a new port mapping for `protocol`.
    pub fn with_protocol(host: u16, guest: u16, protocol: PortProtocol) -> Self {
        Self {
            host,
            guest,
            protocol,
        }
    }

    /// Create a TCP port mapping where host and guest ports are the same.
    pub fn same(port: u16) -> Self {
        Self::new(port, port)
    }

    /// `HOST:GUEST`, with `/udp` appended for a UDP mapping.
    pub fn label(&self) -> String {
        match self.protocol {
            PortProtocol::Tcp => format!("{}:{}", self.host, self.guest),
            PortProtocol::Udp => format!("{}:{}/udp", self.host, self.guest),
        }
    }

    /// Convert to `(host, guest)` tuple for storage.
    pub fn to_tuple(&self) -> (u16, u16) {
        (self.host, self.guest)
    }

    /// TCP mappings as `(host, guest)` tuples; use [`Self::split_tuples`]
    /// to keep UDP mappings too.
    pub fn to_tuples(ports: &[Self]) -> PortTuples {
        Self::split_tuples(ports).0
    }

    /// Split mappings into the stored `(TCP tuples, UDP tuples)`.
    pub fn split_tuples(ports: &[Self]) -> (PortTuples, PortTuples) {
        let of = |protocol| {
            ports
                .iter()
                .filter(|p| p.protocol == protocol)
                .map(|p| p.to_tuple())
                .collect()
        };
        (of(PortProtocol::Tcp), of(PortProtocol::Udp))
    }

    /// Check for duplicate host ports in a list of mappings. TCP and UDP have
    /// separate port spaces, so `8080` and `8080/udp` may both be published.
    pub fn check_duplicates(ports: &[Self]) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for p in ports {
            if !seen.insert((p.host, p.protocol)) {
                let suffix = match p.protocol {
                    PortProtocol::Tcp => "",
                    PortProtocol::Udp => "/udp",
                };
                return Err(format!(
                    "duplicate host port {}{suffix}: each host port can only be mapped once",
                    p.host
                ));
            }
        }
        Ok(())
    }

    /// Parse a port mapping specification (`HOST:GUEST` or `PORT`), optionally
    /// ending in `/tcp` or `/udp`.
    pub fn parse(full: &str) -> Result<Self, String> {
        let (spec, protocol) = PortProtocol::split_suffix(full)?;
        Self::parse_ports(spec).map(|mapping| Self {
            protocol,
            ..mapping
        })
    }

    fn parse_ports(spec: &str) -> Result<Self, String> {
        if let Some((host, guest)) = spec.split_once(':') {
            let host: u16 = host
                .parse()
                .map_err(|_| format!("invalid host port: {}", host))?;
            if host == 0 {
                return Err("host port 0 is not valid for VM port forwarding".to_string());
            }
            let guest: u16 = guest
                .parse()
                .map_err(|_| format!("invalid guest port: {}", guest))?;
            if guest == 0 {
                return Err("guest port 0 is not valid for VM port forwarding".to_string());
            }
            Ok(Self::new(host, guest))
        } else {
            let port: u16 = spec
                .parse()
                .map_err(|_| format!("invalid port: {}", spec))?;
            if port == 0 {
                return Err("port 0 is not valid for VM port forwarding".to_string());
            }
            Ok(Self::same(port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::EffectiveNetworkBackend;

    // The resolver a guest actually gets. Issue #1191: every pull went to
    // 1.1.1.1, so on a network that blocks the public resolvers (a VPN with
    // leak protection, a campus resolver) no image could be pulled at all.
    // The two backends differ on loopback and that difference is load-bearing:
    // measured on a systemd-resolved host with 1.1.1.1 and 8.8.8.8 dropped,
    // `--dns 127.0.0.53` pulls under virtio-net and fails under TSI with
    // "read udp 127.0.0.1:37080->127.0.0.53:53: read: connection refused",
    // because TSI leaves a loopback destination on the guest's own loopback.
    const CAMPUS: &str = "nameserver 128.112.128.12\nnameserver 128.112.128.79\n";
    const STUB: &str = "nameserver 127.0.0.53\noptions edns0 trust-ad\n";
    const UPLINK: &str = "nameserver 192.168.5.2\nsearch mynetworksettings.com\n";

    /// [`super::select_dns`] over resolv.conf text, as a Unix host supplies it.
    fn select_dns(
        dns_override: Option<Ipv4Addr>,
        backend: EffectiveNetworkBackend,
        resolv_conf: &str,
        systemd_uplink: &str,
        reachable: &dyn Fn(Ipv4Addr) -> bool,
    ) -> EffectiveDns {
        let host = resolv_conf_nameservers(resolv_conf);
        let uplink = resolv_conf_nameservers(systemd_uplink);
        super::select_dns(dns_override, backend, &host, &uplink, reachable)
    }

    #[test]
    fn a_host_resolver_list_from_the_platform_is_selected_like_resolv_conf() {
        // Windows hands over addresses, not file text: the same list must pick
        // the same resolver.
        let corp = Ipv4Addr::new(10, 20, 0, 53);
        let list = [
            "fec0:0:0:ffff::1".parse().unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(corp),
        ];
        let text = "nameserver fec0:0:0:ffff::1\nnameserver 127.0.0.1\nnameserver 10.20.0.53\n";
        for (backend, picked) in [
            (EffectiveNetworkBackend::Tsi, corp),
            (EffectiveNetworkBackend::VirtioNet, Ipv4Addr::LOCALHOST),
        ] {
            let chosen = super::select_dns(None, backend, &list, &[], &|_| true);
            assert_eq!(chosen.addr, Some(picked));
            assert_eq!(chosen, select_dns(None, backend, text, "", &|_| true));
        }
    }

    #[test]
    fn explicit_dns_wins_on_both_backends() {
        let nine = Ipv4Addr::new(9, 9, 9, 9);
        for backend in [
            EffectiveNetworkBackend::Tsi,
            EffectiveNetworkBackend::VirtioNet,
        ] {
            let chosen = select_dns(Some(nine), backend, CAMPUS, UPLINK, &|_| true);
            assert_eq!(chosen.addr, Some(nine));
            assert_eq!(chosen.source, DnsSource::Override);
        }
    }

    #[test]
    fn a_non_loopback_host_resolver_is_taken_by_both_backends() {
        let campus = Ipv4Addr::new(128, 112, 128, 12);
        for backend in [
            EffectiveNetworkBackend::Tsi,
            EffectiveNetworkBackend::VirtioNet,
        ] {
            let chosen = select_dns(None, backend, CAMPUS, "", &|_| true);
            assert_eq!(chosen.addr, Some(campus));
            assert_eq!(chosen.source, DnsSource::HostResolvConf);
        }
    }

    #[test]
    fn virtio_net_takes_a_loopback_stub_but_tsi_reaches_past_it_to_the_uplink() {
        let virtio = select_dns(
            None,
            EffectiveNetworkBackend::VirtioNet,
            STUB,
            UPLINK,
            &|_| true,
        );
        assert_eq!(virtio.addr, Some(Ipv4Addr::new(127, 0, 0, 53)));
        assert_eq!(virtio.source, DnsSource::HostResolvConf);

        let tsi = select_dns(None, EffectiveNetworkBackend::Tsi, STUB, UPLINK, &|_| true);
        assert_eq!(tsi.addr, Some(Ipv4Addr::new(192, 168, 5, 2)));
        assert_eq!(tsi.source, DnsSource::SystemdUplink);
    }

    #[test]
    fn tsi_keeps_the_backend_default_when_every_host_resolver_is_loopback() {
        let chosen = select_dns(None, EffectiveNetworkBackend::Tsi, STUB, "", &|_| true);
        assert_eq!(chosen.addr, None);
        assert_eq!(chosen.source, DnsSource::BackendDefault);
    }

    #[test]
    fn an_empty_resolv_conf_keeps_the_backend_default() {
        for backend in [
            EffectiveNetworkBackend::Tsi,
            EffectiveNetworkBackend::VirtioNet,
        ] {
            let chosen = select_dns(None, backend, "", "", &|_| true);
            assert_eq!(chosen.addr, None);
            assert_eq!(chosen.source, DnsSource::BackendDefault);
        }
    }

    #[test]
    fn an_ipv6_only_host_keeps_the_backend_default() {
        // `--dns` and the gateway's upstream are both `Ipv4Addr`, so a v6-only
        // host has nothing to hand the guest and must keep the public resolvers.
        let v6 = "nameserver 2606:4700:4700::1111\nnameserver fe80::1\n";
        for backend in [
            EffectiveNetworkBackend::Tsi,
            EffectiveNetworkBackend::VirtioNet,
        ] {
            let chosen = select_dns(None, backend, v6, "", &|_| true);
            assert_eq!(chosen.addr, None);
            assert_eq!(chosen.source, DnsSource::BackendDefault);
        }
    }

    #[test]
    fn a_machine_with_no_network_gets_no_resolver() {
        let chosen = select_dns(None, EffectiveNetworkBackend::None, CAMPUS, UPLINK, &|_| {
            true
        });
        assert_eq!(chosen.addr, None);
        assert_eq!(chosen.source, DnsSource::BackendDefault);
    }

    #[test]
    fn a_v6_nameserver_never_shadows_the_v4_one_behind_it() {
        // File order matters: the v6 entry is first, and skipping it must not
        // also skip the usable v4 resolver on the next line.
        let mixed = "nameserver 2606:4700:4700::1111\nnameserver 128.112.128.12\n";
        let chosen = select_dns(None, EffectiveNetworkBackend::Tsi, mixed, "", &|_| true);
        assert_eq!(chosen.addr, Some(Ipv4Addr::new(128, 112, 128, 12)));
    }

    /// A GCP VM's resolver is the metadata address, which the egress floor
    /// blocks in every mode: a TSI guest must not be handed it.
    const GCP: &str = "nameserver 169.254.169.254\nsearch c.project.internal\n";

    #[test]
    fn a_tsi_guest_is_not_handed_a_resolver_the_egress_floor_blocks() {
        let floor = smolvm_network::EgressPolicy::unrestricted();
        let reachable = |addr: Ipv4Addr| floor.allows_v4(addr);
        let chosen = select_dns(None, EffectiveNetworkBackend::Tsi, GCP, "", &reachable);
        assert_eq!(chosen.addr, None);
        assert_eq!(chosen.source, DnsSource::BackendDefault);

        // A later nameserver the guest can reach is used instead.
        let both = "nameserver 169.254.169.254\nnameserver 8.8.4.4\n";
        let chosen = select_dns(None, EffectiveNetworkBackend::Tsi, both, "", &reachable);
        assert_eq!(chosen.addr, Some(Ipv4Addr::new(8, 8, 4, 4)));
    }

    #[test]
    fn virtio_net_keeps_a_floored_host_resolver_because_the_gateway_dials_it() {
        let chosen = select_dns(None, EffectiveNetworkBackend::VirtioNet, GCP, "", &|_| {
            false
        });
        assert_eq!(chosen.addr, Some(Ipv4Addr::new(169, 254, 169, 254)));
    }

    #[test]
    fn test_cidrs_contain_ip() {
        assert!(cidrs_contain_ip(&["1.1.1.1".into()], "1.1.1.1"));
        assert!(cidrs_contain_ip(&["1.1.1.1/32".into()], "1.1.1.1"));
        assert!(cidrs_contain_ip(&["0.0.0.0/0".into()], "8.8.8.8"));
        assert!(cidrs_contain_ip(&["10.0.0.0/8".into()], "10.5.3.1"));
        assert!(!cidrs_contain_ip(&["10.0.0.0/8".into()], "1.1.1.1"));
        assert!(cidrs_contain_ip(
            &["192.168.1.0/24".into()],
            "192.168.1.100"
        ));
        assert!(!cidrs_contain_ip(&["192.168.1.0/24".into()], "192.168.2.1"));
        assert!(cidrs_contain_ip(
            &["10.0.0.0/8".into(), "1.1.1.1/32".into()],
            "1.1.1.1"
        ));
        assert!(!cidrs_contain_ip(&[], "1.1.1.1"));
        assert!(!cidrs_contain_ip(&["not-a-cidr".into()], "1.1.1.1"));
    }

    #[test]
    fn test_ensure_dns_adds_when_missing() {
        let dns_cidr = IpNet::from(host_dns()).to_string();
        // A documentation range no host resolver sits in: a 10/8 range would
        // already cover a resolver on a VPN or office network.
        let mut cidrs = vec!["192.0.2.0/24".to_string()];
        ensure_dns_in_cidrs(&mut cidrs);
        assert_eq!(cidrs.len(), 2);
        assert!(cidrs.contains(&dns_cidr));
    }

    #[test]
    fn test_ensure_dns_skips_when_covered_by_subnet() {
        // Build a subnet that actually covers the detected DNS server.
        let dns = host_dns();
        let covering_cidr = match dns {
            IpAddr::V4(v4) => format!("{}.0.0.0/8", v4.octets()[0]),
            IpAddr::V6(v6) => {
                // Use a /16 covering the detected IPv6 address.
                let segs = v6.segments();
                format!("{:x}::/16", segs[0])
            }
        };
        let mut cidrs = vec![covering_cidr];
        ensure_dns_in_cidrs(&mut cidrs);
        assert_eq!(cidrs.len(), 1);
    }

    #[test]
    fn test_ensure_dns_skips_when_exact_match() {
        let dns_cidr = IpNet::from(host_dns()).to_string();
        let mut cidrs = vec!["10.0.0.0/8".to_string(), dns_cidr];
        ensure_dns_in_cidrs(&mut cidrs);
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn test_ensure_dns_skips_for_loopback_only_policy() {
        let mut cidrs = vec!["127.0.0.0/8".to_string(), "::1/128".to_string()];
        ensure_dns_in_cidrs(&mut cidrs);
        assert_eq!(
            cidrs.len(),
            2,
            "DNS must not be added for loopback-only policy"
        );
    }

    #[test]
    fn test_ensure_dns_adds_when_non_loopback_cidr_present() {
        let dns_cidr = IpNet::from(host_dns()).to_string();
        let mut cidrs = vec!["127.0.0.0/8".to_string(), "192.0.2.0/24".to_string()];
        ensure_dns_in_cidrs(&mut cidrs);
        assert_eq!(cidrs.len(), 3);
        assert!(cidrs.contains(&dns_cidr));
    }

    #[test]
    fn test_port_mapping_rejects_zero() {
        assert!(PortMapping::parse("0:80").is_err());
        assert!(PortMapping::parse("80:0").is_err());
        assert!(PortMapping::parse("0").is_err());
        assert!(PortMapping::parse("1:1").is_ok());
        assert!(PortMapping::parse("8080:80").is_ok());
    }

    #[test]
    fn port_mapping_spec_expands_equal_length_ranges() {
        let spec = PortMappingSpec::parse("5173-5175:6173-6175").unwrap();
        let ports = PortMappingSpec::expand_all(&[spec]).unwrap();

        assert_eq!(
            ports,
            vec![
                PortMapping::new(5173, 6173),
                PortMapping::new(5174, 6174),
                PortMapping::new(5175, 6175),
            ]
        );
    }

    #[test]
    fn port_mapping_spec_rejects_mismatched_range_lengths() {
        assert!(PortMappingSpec::parse("5173-5175:6173-6174").is_err());
    }

    #[test]
    fn port_mapping_spec_rejects_descending_ranges() {
        assert!(PortMappingSpec::parse("5175-5173").is_err());
    }

    #[test]
    fn port_mapping_spec_rejects_zero_in_ranges() {
        assert!(PortMappingSpec::parse("0-1").is_err());
    }

    #[test]
    fn port_mapping_spec_rejects_malformed_ranges() {
        assert!(PortMappingSpec::parse("5173--5175").is_err());
    }

    #[test]
    fn a_udp_suffix_publishes_udp_and_tcp_stays_the_default() {
        let tcp = PortMappingSpec::expand_all(&[PortMappingSpec::parse("8080:80").unwrap()]);
        assert_eq!(tcp.unwrap(), vec![PortMapping::new(8080, 80)]);
        let udp = PortMappingSpec::parse("27015-27016:27015-27016/udp").unwrap();
        assert_eq!(
            PortMappingSpec::expand_all(&[udp]).unwrap(),
            vec![
                PortMapping::with_protocol(27015, 27015, PortProtocol::Udp),
                PortMapping::with_protocol(27016, 27016, PortProtocol::Udp),
            ]
        );
        assert_eq!(
            PortMapping::parse("53/udp").unwrap(),
            PortMapping::with_protocol(53, 53, PortProtocol::Udp)
        );
        assert_eq!(
            PortMapping::parse("80/tcp").unwrap(),
            PortMapping::new(80, 80)
        );
        let err = PortMappingSpec::parse("80:80/sctp").unwrap_err();
        assert!(err.contains("unsupported port protocol 'sctp'"), "{err}");
    }

    #[test]
    fn tcp_and_udp_may_share_a_host_port_but_not_repeat_it() {
        let both = [
            PortMapping::new(27015, 27015),
            PortMapping::with_protocol(27015, 27015, PortProtocol::Udp),
        ];
        PortMapping::check_duplicates(&both).unwrap();
        let twice = [
            PortMapping::with_protocol(27015, 1, PortProtocol::Udp),
            PortMapping::with_protocol(27015, 2, PortProtocol::Udp),
        ];
        let err = PortMapping::check_duplicates(&twice).unwrap_err();
        assert!(err.contains("27015/udp"), "{err}");
    }

    /// A TCP mapping keeps the JSON shape older SDKs and records use.
    #[test]
    fn a_tcp_mapping_serializes_without_a_protocol() {
        let tcp = serde_json::to_value(PortMapping::new(8080, 80)).unwrap();
        assert_eq!(tcp, serde_json::json!({"host": 8080, "guest": 80}));
        let udp = PortMapping::with_protocol(27015, 27015, PortProtocol::Udp);
        assert_eq!(
            serde_json::to_value(udp).unwrap(),
            serde_json::json!({"host": 27015, "guest": 27015, "protocol": "udp"})
        );
        let old: PortMapping = serde_json::from_str(r#"{"host": 1, "guest": 2}"#).unwrap();
        assert_eq!(old, PortMapping::new(1, 2));
        assert_eq!(
            PortMapping::split_tuples(&[udp, PortMapping::new(1, 2)]),
            (vec![(1, 2)], vec![(27015, 27015)])
        );
    }

    #[test]
    fn port_mapping_spec_limits_total_expanded_mappings() {
        let specs = [
            PortMappingSpec::parse("1-32").unwrap(),
            PortMappingSpec::parse("33-64").unwrap(),
        ];
        assert_eq!(PortMappingSpec::expand_all(&specs).unwrap().len(), 64);

        let too_many = [PortMappingSpec::parse("1-65").unwrap()];
        assert!(PortMappingSpec::expand_all(&too_many).is_err());
    }

    #[test]
    fn test_cidrs_all_loopback() {
        assert!(cidrs_all_loopback(&[
            "127.0.0.0/8".into(),
            "::1/128".into()
        ]));
        assert!(cidrs_all_loopback(&["127.0.0.1/32".into()]));
        assert!(!cidrs_all_loopback(&[]));
        assert!(!cidrs_all_loopback(&["10.0.0.0/8".into()]));
        assert!(!cidrs_all_loopback(&[
            "127.0.0.0/8".into(),
            "10.0.0.0/8".into()
        ]));
        assert!(!cidrs_all_loopback(&["0.0.0.0/0".into()]));
    }
}

/// A machine's outbound network policy, as it can be set on a stopped machine.
///
/// `hosts` entries are exact host names (`api.github.com`) or subdomain
/// wildcards (`*.github.com`, which does not match `github.com` itself); they
/// are enforced by the host-side DNS filter. `cidrs` restrict egress by address.
/// With both empty and `network` set, egress is open.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// Outbound network access at all.
    pub network: bool,
    /// Addresses the machine may reach; empty means no address restriction.
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// Host names the machine may reach; empty means no name restriction.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Loopback only: every external destination is refused. This is how
/// `--outbound-localhost-only` is stored, and it keeps the network device a
/// machine was checkpointed with, unlike turning networking off.
pub const DENY_ALL_CIDRS: [&str; 2] = ["127.0.0.0/8", "::1/128"];

impl EgressPolicy {
    /// Unrestricted outbound access.
    pub fn allow_all() -> Self {
        Self {
            network: true,
            ..Self::default()
        }
    }

    /// No external destinations, with the network device kept in place.
    pub fn deny_all() -> Self {
        Self {
            network: true,
            cidrs: DENY_ALL_CIDRS.iter().map(|c| c.to_string()).collect(),
            hosts: Vec::new(),
        }
    }

    /// Only these host names (exact, or `*.` subdomain wildcards).
    pub fn hosts<I: IntoIterator<Item = S>, S: Into<String>>(hosts: I) -> Self {
        Self {
            network: true,
            cidrs: Vec::new(),
            hosts: hosts.into_iter().map(Into::into).collect(),
        }
    }
}
