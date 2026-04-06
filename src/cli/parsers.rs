//! Shared CLI argument parsers.
//!
//! This module consolidates parser functions used across multiple CLI commands
//! to eliminate code duplication and ensure consistent validation.

use smolvm::data::mount::HostMount;

/// Parse an environment variable specification (KEY=VALUE).
pub fn parse_env_spec(spec: &str) -> Option<(String, String)> {
    let (key, value) = spec.split_once('=')?;
    if key.is_empty() {
        None
    } else {
        Some((key.to_string(), value.to_string()))
    }
}

/// Parse environment variables from CLI args.
pub fn parse_env_list(env_args: &[String]) -> Vec<(String, String)> {
    env_args.iter().filter_map(|e| parse_env_spec(e)).collect()
}

/// Convert parsed HostMount list to virtiofs binding format for agent.
///
/// Returns tuples of (virtiofs_tag, container_path, read_only).
/// The tag format is "smolvm{index}" to match libkrun virtiofs device naming.
pub fn mounts_to_virtiofs_bindings(mounts: &[HostMount]) -> Vec<(String, String, bool)> {
    mounts
        .iter()
        .enumerate()
        .map(|(i, m)| {
            (
                HostMount::mount_tag(i),
                m.target.to_string_lossy().to_string(),
                m.read_only,
            )
        })
        .collect()
}

/// Resolve a hostname to IP addresses and return as /32 CIDRs.
///
/// Resolution happens on the host at VM start time. Rejects hostnames with
/// `:port` suffixes — port filtering is not supported by the TSI egress policy.
pub fn resolve_host_to_cidrs(host: &str) -> Result<Vec<String>, String> {
    use std::net::{IpAddr, ToSocketAddrs};

    // Reject host:port syntax — we don't support port filtering and accepting
    // it silently would create a false sense of security.
    if host.contains(':') {
        return Err(format!(
            "invalid hostname '{}': port suffixes are not supported. \
             Use the hostname only (all ports are allowed to resolved IPs).",
            host
        ));
    }

    // Try parsing as bare IP first (skip resolution)
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![format!("{}/32", ip)]);
    }

    // Resolve hostname — may return multiple IPs (round-robin, CDN)
    let addrs: Vec<String> = format!("{}:0", host)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve '{}': {}", host, e))?
        .map(|addr| format!("{}/32", addr.ip()))
        .collect();

    if addrs.is_empty() {
        return Err(format!("'{}' resolved to no addresses", host));
    }

    Ok(addrs)
}

/// Parse and validate a CIDR specification (e.g., "10.0.0.0/8", "1.1.1.1").
///
/// Accepts `IP/prefix` or bare `IP` (auto-appends /32 for IPv4, /128 for IPv6).
/// Returns the normalized CIDR string.
pub fn parse_cidr(s: &str) -> Result<String, String> {
    use ipnet::IpNet;
    use std::net::IpAddr;

    // Try parsing as CIDR first, then as bare IP
    let net: IpNet = match s.parse::<IpNet>() {
        Ok(net) => net,
        Err(_) => match s.parse::<IpAddr>() {
            Ok(ip) => IpNet::from(ip), // bare IP → /32 or /128
            Err(_) => {
                return Err(format!(
                    "invalid CIDR '{}': expected format like 10.0.0.0/8 or 1.1.1.1",
                    s
                ))
            }
        },
    };

    Ok(net.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_host_bare_ip() {
        let cidrs = resolve_host_to_cidrs("1.2.3.4").unwrap();
        assert_eq!(cidrs, vec!["1.2.3.4/32"]);
    }

    #[test]
    fn resolve_host_rejects_port_suffix() {
        let err = resolve_host_to_cidrs("example.com:443").unwrap_err();
        assert!(err.contains("port suffixes are not supported"), "{}", err);
    }

    #[test]
    fn resolve_host_rejects_ipv6_with_port() {
        let err = resolve_host_to_cidrs("[::1]:80").unwrap_err();
        assert!(err.contains("port suffixes are not supported"), "{}", err);
    }

    #[test]
    fn resolve_host_real_hostname() {
        // Resolve a well-known hostname — should return at least one IP
        let cidrs = resolve_host_to_cidrs("one.one.one.one").unwrap();
        assert!(!cidrs.is_empty());
        // All results should be /32 CIDRs
        for cidr in &cidrs {
            assert!(cidr.ends_with("/32"), "expected /32 CIDR, got {}", cidr);
        }
    }

    #[test]
    fn resolve_host_nonexistent_domain() {
        let err =
            resolve_host_to_cidrs("this-domain-does-not-exist-smolvm-test.invalid").unwrap_err();
        assert!(err.contains("failed to resolve"), "{}", err);
    }

    #[test]
    fn parse_cidr_valid() {
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(parse_cidr("1.1.1.1").unwrap(), "1.1.1.1/32");
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_err());
    }
}
