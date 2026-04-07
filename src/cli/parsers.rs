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

// Env parsing delegated to the library.
pub use smolvm::util::{parse_env_list, parse_env_spec};

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

// Network helpers delegated to the library.
pub use smolvm::smolfile::{parse_cidr, resolve_host_to_cidrs};

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
