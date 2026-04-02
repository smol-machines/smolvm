//! Network configuration.
//!
//! This module provides network policy configuration for VMs.

use crate::data::network::DEFAULT_DNS_ADDR;
use crate::vm::config::NetworkPolicy;
use std::net::IpAddr;

/// Get the DNS server for a network policy.
pub fn get_dns_server(policy: &NetworkPolicy) -> Option<IpAddr> {
    match policy {
        NetworkPolicy::None => None,
        NetworkPolicy::Egress { dns, .. } => Some(dns.unwrap_or(DEFAULT_DNS_ADDR)),
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
        let dns = get_dns_server(&NetworkPolicy::Egress {
            dns: None,
            allowed_cidrs: None,
        })
        .unwrap();
        assert_eq!(dns.to_string(), crate::data::network::DEFAULT_DNS);

        // Egress with custom DNS
        let custom: IpAddr = "8.8.8.8".parse().unwrap();
        let dns = get_dns_server(&NetworkPolicy::Egress {
            dns: Some(custom),
            allowed_cidrs: None,
        })
        .unwrap();
        assert_eq!(dns.to_string(), "8.8.8.8");
    }
}
