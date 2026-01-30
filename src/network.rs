//! Network configuration.
//!
//! This module provides network policy configuration for VMs.

use crate::vm::config::NetworkPolicy;
use std::net::{IpAddr, Ipv4Addr};

/// Default DNS server (Cloudflare) as string.
pub const DEFAULT_DNS: &str = "1.1.1.1";
/// Default DNS server as IpAddr (compile-time constant).
pub const DEFAULT_DNS_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// Get the DNS server for a network policy.
pub fn get_dns_server(policy: &NetworkPolicy) -> Option<IpAddr> {
    match policy {
        NetworkPolicy::None => None,
        NetworkPolicy::Egress { dns } => Some(dns.unwrap_or(DEFAULT_DNS_ADDR)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_dns_server() {
        // None policy returns no DNS
        assert!(get_dns_server(&NetworkPolicy::None).is_none());

        // Egress with default DNS
        let dns = get_dns_server(&NetworkPolicy::Egress { dns: None }).unwrap();
        assert_eq!(dns.to_string(), DEFAULT_DNS);

        // Egress with custom DNS
        let custom: IpAddr = "8.8.8.8".parse().unwrap();
        let dns = get_dns_server(&NetworkPolicy::Egress { dns: Some(custom) }).unwrap();
        assert_eq!(dns.to_string(), "8.8.8.8");
    }
}
