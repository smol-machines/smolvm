//! Shared CLI argument parsers.
//!
//! This module consolidates parser functions used across multiple CLI commands
//! to eliminate code duplication and ensure consistent validation.

use smolvm::data::storage::HostMount;
use std::time::Duration;

/// Parse a duration string (e.g., "30s", "5m", "1h").
pub fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    humantime::parse_duration(s)
}

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
