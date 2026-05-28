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

/// TCP port mapping from host to guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    /// Port on the host.
    pub host: u16,
    /// Port inside the guest.
    pub guest: u16,
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
