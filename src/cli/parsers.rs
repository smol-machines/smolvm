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

/// Assign positional virtiofs tags to a list of (guest_target, read_only)
/// pairs and return the agent's `(tag, target, read_only)` binding form.
///
/// The tag format is `smolvm{index}` and matches the virtiofs device
/// libkrun exposed at VM start in the same order. Order in equals order
/// out — caller must preserve the original ordering of mounts between
/// VM start and any subsequent agent request that references the tags.
///
/// Generic over any iterator of `(String, bool)` so both
/// [`HostMount`]-shaped inputs and `VmRecord`-shaped tuples (host,
/// target, ro) can adapt at the boundary without a parallel helper. Two
/// thin wrappers below ([`mounts_to_virtiofs_bindings`] and
/// [`record_mounts_to_runconfig_bindings`]) preserve the caller-side
/// ergonomics.
fn assign_virtiofs_tags<I>(items: I) -> Vec<(String, String, bool)>
where
    I: IntoIterator<Item = (String, bool)>,
{
    items
        .into_iter()
        .enumerate()
        .map(|(i, (target, ro))| (HostMount::mount_tag(i), target, ro))
        .collect()
}

/// Convert parsed [`HostMount`] list to virtiofs binding format for agent.
///
/// Used by `machine run` paths that already hold the validated, parsed
/// mount type. See [`assign_virtiofs_tags`] for the tag rule.
pub fn mounts_to_virtiofs_bindings(mounts: &[HostMount]) -> Vec<(String, String, bool)> {
    assign_virtiofs_tags(
        mounts
            .iter()
            .map(|m| (m.target.to_string_lossy().into_owned(), m.read_only)),
    )
}

/// Convert a `VmRecord`-style mount list to virtiofs binding format.
///
/// `VmRecord` stores mounts as `(host_source, guest_target, read_only)`
/// already-validated triples (see `src/data/storage.rs::HostMount::to_storage_tuple`).
/// The host source is dropped — the agent only needs the guest-facing
/// target and the tag. See [`assign_virtiofs_tags`] for the tag rule.
pub fn record_mounts_to_runconfig_bindings(
    mounts: &[(String, String, bool)],
) -> Vec<(String, String, bool)> {
    assign_virtiofs_tags(
        mounts
            .iter()
            .map(|(_host, target, ro)| (target.clone(), *ro)),
    )
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

    #[test]
    fn record_mounts_to_runconfig_bindings_assigns_positional_tags() {
        // Tags are positional so they line up with the virtiofs devices
        // libkrun exposed at VM start. Two mounts → "smolvm0", "smolvm1",
        // preserving the read-only flag and the guest target verbatim.
        let mounts = vec![
            ("/host/src".to_string(), "/app".to_string(), false),
            ("/host/data".to_string(), "/data".to_string(), true),
        ];
        let bindings = record_mounts_to_runconfig_bindings(&mounts);
        assert_eq!(
            bindings,
            vec![
                ("smolvm0".to_string(), "/app".to_string(), false),
                ("smolvm1".to_string(), "/data".to_string(), true),
            ]
        );
    }

    #[test]
    fn record_mounts_to_runconfig_bindings_empty_input() {
        // No mounts → no bindings. Init code calls this unconditionally;
        // empty must round-trip cleanly without panicking on enumerate.
        assert!(record_mounts_to_runconfig_bindings(&[]).is_empty());
    }

    #[test]
    fn assign_virtiofs_tags_keeps_order_and_assigns_zero_based_index() {
        // The shared core. The two public wrappers are thin adapters
        // around this — pin the indexing rule here so neither wrapper
        // can drift away from the canonical "smolvm{i}" naming or from
        // preserving caller order.
        let out = assign_virtiofs_tags(vec![
            ("/a".to_string(), false),
            ("/b".to_string(), true),
            ("/c".to_string(), false),
        ]);
        assert_eq!(
            out,
            vec![
                ("smolvm0".to_string(), "/a".to_string(), false),
                ("smolvm1".to_string(), "/b".to_string(), true),
                ("smolvm2".to_string(), "/c".to_string(), false),
            ]
        );
    }

    #[test]
    fn mounts_to_virtiofs_bindings_matches_record_form_for_same_inputs() {
        // The two public wrappers must agree on identical inputs — they
        // route to the same core. If a future refactor adds a wrapper
        // that *doesn't* go through `assign_virtiofs_tags`, this test
        // will catch the divergence.
        use std::path::PathBuf;
        let host_mount = HostMount {
            source: PathBuf::from("/tmp"), // any existing dir; not validated by the converter
            target: PathBuf::from("/app"),
            read_only: true,
        };
        let from_parsed = mounts_to_virtiofs_bindings(&[host_mount]);
        let from_record =
            record_mounts_to_runconfig_bindings(&[("/tmp".to_string(), "/app".to_string(), true)]);
        assert_eq!(from_parsed, from_record);
    }
}
