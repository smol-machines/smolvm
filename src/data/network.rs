use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};

/// Fallback DNS server (Cloudflare) used when the host's resolver cannot be detected.
pub const FALLBACK_DNS: &str = "1.1.1.1";

/// Fallback DNS server as `IpAddr`.
pub const FALLBACK_DNS_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// Detect the host's primary DNS server from /etc/resolv.conf.
/// Falls back to Cloudflare (1.1.1.1) if detection fails.
pub fn host_dns() -> IpAddr {
    host_dns_from_resolv("/etc/resolv.conf").unwrap_or(FALLBACK_DNS_ADDR)
}

/// Parse the first nameserver from a resolv.conf file.
fn host_dns_from_resolv(path: &str) -> Option<IpAddr> {
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(addr_str) = line.strip_prefix("nameserver") {
            let addr_str = addr_str.trim();
            // Skip loopback — it's typically a local resolver (systemd-resolved,
            // dnsmasq) that isn't reachable from inside the VM.
            if let Ok(ip) = addr_str.parse::<IpAddr>() {
                if !ip.is_loopback() {
                    return Some(ip);
                }
            }
        }
    }
    None
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
    let resolv_conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let uplink = std::fs::read_to_string(SYSTEMD_RESOLVED_UPLINK).unwrap_or_default();
    let effective = select_dns(dns_override, backend, &resolv_conf, &uplink);
    if effective.source == DnsSource::BackendDefault
        && backend != crate::network::EffectiveNetworkBackend::None
    {
        // Names the one case operators hit and cannot otherwise see: a host whose
        // only nameservers are IPv6, which `--dns <IP>` (an `Ipv4Addr`) cannot express.
        tracing::debug!(
            "no IPv4 host resolver this backend can reach; guest keeps the public resolvers"
        );
    }
    effective
}

/// The pure half of [`effective_dns`], with both files supplied.
fn select_dns(
    dns_override: Option<Ipv4Addr>,
    backend: crate::network::EffectiveNetworkBackend,
    resolv_conf: &str,
    systemd_uplink: &str,
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
        EffectiveNetworkBackend::VirtioNet => nameservers_v4(resolv_conf)
            .next()
            .map(|addr| (addr, DnsSource::HostResolvConf)),
        // TSI does not translate a guest loopback destination to the host's
        // loopback, so a stub address would leave the guest talking to itself.
        EffectiveNetworkBackend::Tsi => nameservers_v4(resolv_conf)
            .find(|addr| !addr.is_loopback())
            .map(|addr| (addr, DnsSource::HostResolvConf))
            .or_else(|| {
                nameservers_v4(systemd_uplink)
                    .find(|addr| !addr.is_loopback())
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

/// Every IPv4 nameserver in a resolv.conf, in file order.
///
/// IPv6 entries are skipped: the resolver is carried as an `Ipv4Addr` all the
/// way to `--dns` and the virtio gateway's upstream.
fn nameservers_v4(contents: &str) -> impl Iterator<Item = Ipv4Addr> + '_ {
    contents.lines().filter_map(|line| {
        let line = line.trim();
        let addr = line.strip_prefix("nameserver")?.trim();
        match addr.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    })
}

/// TCP port mapping from host to guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    /// Port on the host.
    pub host: u16,
    /// Port inside the guest.
    pub guest: u16,
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
}

/// An inclusive range of TCP ports.
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
        }
    }
}

impl PortMappingSpec {
    /// Parse a port mapping specification (`HOST:GUEST`, `PORT`, or equal-length ranges).
    pub fn parse(spec: &str) -> Result<Self, String> {
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

        Ok(Self { host, guest })
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
                    .map(|(host, guest)| PortMapping::new(host, guest)),
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
    /// Create a new port mapping.
    pub fn new(host: u16, guest: u16) -> Self {
        Self { host, guest }
    }

    /// Create a port mapping where host and guest ports are the same.
    pub fn same(port: u16) -> Self {
        Self {
            host: port,
            guest: port,
        }
    }

    /// Convert to `(host, guest)` tuple for storage.
    pub fn to_tuple(&self) -> (u16, u16) {
        (self.host, self.guest)
    }

    /// Batch convert port mappings to tuple format.
    pub fn to_tuples(ports: &[Self]) -> Vec<(u16, u16)> {
        ports.iter().map(|p| p.to_tuple()).collect()
    }

    /// Check for duplicate host ports in a list of mappings.
    pub fn check_duplicates(ports: &[Self]) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for p in ports {
            if !seen.insert(p.host) {
                return Err(format!(
                    "duplicate host port {}: each host port can only be mapped once",
                    p.host
                ));
            }
        }
        Ok(())
    }

    /// Parse a port mapping specification (`HOST:GUEST` or `PORT`).
    pub fn parse(spec: &str) -> Result<Self, String> {
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

    #[test]
    fn explicit_dns_wins_on_both_backends() {
        let nine = Ipv4Addr::new(9, 9, 9, 9);
        for backend in [
            EffectiveNetworkBackend::Tsi,
            EffectiveNetworkBackend::VirtioNet,
        ] {
            let chosen = select_dns(Some(nine), backend, CAMPUS, UPLINK);
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
            let chosen = select_dns(None, backend, CAMPUS, "");
            assert_eq!(chosen.addr, Some(campus));
            assert_eq!(chosen.source, DnsSource::HostResolvConf);
        }
    }

    #[test]
    fn virtio_net_takes_a_loopback_stub_but_tsi_reaches_past_it_to_the_uplink() {
        let virtio = select_dns(None, EffectiveNetworkBackend::VirtioNet, STUB, UPLINK);
        assert_eq!(virtio.addr, Some(Ipv4Addr::new(127, 0, 0, 53)));
        assert_eq!(virtio.source, DnsSource::HostResolvConf);

        let tsi = select_dns(None, EffectiveNetworkBackend::Tsi, STUB, UPLINK);
        assert_eq!(tsi.addr, Some(Ipv4Addr::new(192, 168, 5, 2)));
        assert_eq!(tsi.source, DnsSource::SystemdUplink);
    }

    #[test]
    fn tsi_keeps_the_backend_default_when_every_host_resolver_is_loopback() {
        let chosen = select_dns(None, EffectiveNetworkBackend::Tsi, STUB, "");
        assert_eq!(chosen.addr, None);
        assert_eq!(chosen.source, DnsSource::BackendDefault);
    }

    #[test]
    fn an_empty_resolv_conf_keeps_the_backend_default() {
        for backend in [
            EffectiveNetworkBackend::Tsi,
            EffectiveNetworkBackend::VirtioNet,
        ] {
            let chosen = select_dns(None, backend, "", "");
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
            let chosen = select_dns(None, backend, v6, "");
            assert_eq!(chosen.addr, None);
            assert_eq!(chosen.source, DnsSource::BackendDefault);
        }
    }

    #[test]
    fn a_machine_with_no_network_gets_no_resolver() {
        let chosen = select_dns(None, EffectiveNetworkBackend::None, CAMPUS, UPLINK);
        assert_eq!(chosen.addr, None);
        assert_eq!(chosen.source, DnsSource::BackendDefault);
    }

    #[test]
    fn a_v6_nameserver_never_shadows_the_v4_one_behind_it() {
        // File order matters: the v6 entry is first, and skipping it must not
        // also skip the usable v4 resolver on the next line.
        let mixed = "nameserver 2606:4700:4700::1111\nnameserver 128.112.128.12\n";
        let chosen = select_dns(None, EffectiveNetworkBackend::Tsi, mixed, "");
        assert_eq!(chosen.addr, Some(Ipv4Addr::new(128, 112, 128, 12)));
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
        let mut cidrs = vec!["10.0.0.0/8".to_string()];
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
        let mut cidrs = vec!["127.0.0.0/8".to_string(), "10.0.0.0/8".to_string()];
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
