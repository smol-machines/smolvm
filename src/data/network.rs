use std::net::{IpAddr, Ipv4Addr};

/// Default DNS server (Cloudflare) as string.
pub const DEFAULT_DNS: &str = "1.1.1.1";

/// Default DNS server as `IpAddr`.
pub const DEFAULT_DNS_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// TCP port mapping from host to guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    /// Port on the host.
    pub host: u16,
    /// Port inside the guest.
    pub guest: u16,
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

    /// Parse a port mapping specification (`HOST:GUEST` or `PORT`).
    pub fn parse(spec: &str) -> Result<Self, String> {
        if let Some((host, guest)) = spec.split_once(':') {
            let host: u16 = host
                .parse()
                .map_err(|_| format!("invalid host port: {}", host))?;
            let guest: u16 = guest
                .parse()
                .map_err(|_| format!("invalid guest port: {}", guest))?;
            Ok(Self::new(host, guest))
        } else {
            let port: u16 = spec
                .parse()
                .map_err(|_| format!("invalid port: {}", spec))?;
            Ok(Self::same(port))
        }
    }
}
