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
    use std::net::IpAddr;

    let (ip_str, prefix_len) = if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("invalid prefix length in '{}': expected a number", s))?;
        (ip_part, prefix)
    } else {
        let default_prefix = if s.contains(':') { 128u8 } else { 32u8 };
        (s, default_prefix)
    };

    let ip: IpAddr = ip_str.parse().map_err(|_| {
        format!(
            "invalid CIDR '{}': expected format like 10.0.0.0/8 or 1.1.1.1",
            s
        )
    })?;

    match ip {
        IpAddr::V4(_) if prefix_len > 32 => {
            return Err(format!("invalid CIDR '{}': IPv4 prefix must be 0-32", s));
        }
        IpAddr::V6(_) if prefix_len > 128 => {
            return Err(format!("invalid CIDR '{}': IPv6 prefix must be 0-128", s));
        }
        _ => {}
    }

    Ok(format!("{}/{}", ip, prefix_len))
}
