//! Shared environment-variable contract between the host launcher and guest agent.
//!
//! These names form the protocol boundary between:
//! - the host-side launcher, which decides what features to enable
//! - the guest agent, which reads these vars on startup and acts accordingly
//!
//! They should be treated as stable protocol constants rather than ad hoc
//! launcher strings.

/// Standard "enabled" value for boolean `SMOLVM_*` sentinel env vars.
///
/// The host writes this when a feature is enabled; the guest agent
/// compares against it. A single canonical value prevents `true` / `yes` /
/// `1` mismatches between the two sides.
pub const VALUE_ON: &str = "1";

/// Env var the host sets on guest init to signal GPU acceleration was requested.
///
/// Present means "host asked for GPU"; the guest agent reads this and emits a
/// post-boot sanity log confirming whether `/dev/dri/*` nodes actually appeared.
/// Absent means no GPU was requested.
///
/// This is a boolean sentinel — the value is [`VALUE_ON`] when set.
pub const GPU: &str = "SMOLVM_GPU";

/// Filename of this VM's readiness marker, written by the agent into the virtiofs
/// rootfs when boot completes. Per VM (so concurrent boots don't race on one
/// shared file); the host pre-creates and polls the same name. Unset → the agent
/// falls back to the shared [`crate::AGENT_READY_MARKER`] constant.
pub const READY_MARKER: &str = "SMOLVM_READY_MARKER";

/// Selects whether the guest should configure a real virtio NIC.
pub const BACKEND: &str = "SMOLVM_NETWORK_BACKEND";
/// Canonical backend value meaning "configure guest virtio-net".
pub const BACKEND_VIRTIO_NET: &str = "virtio-net";
/// Guest IPv4 address.
pub const GUEST_IP: &str = "SMOLVM_NETWORK_GUEST_IP";
/// Guest-visible default gateway IPv4 address.
pub const GATEWAY: &str = "SMOLVM_NETWORK_GATEWAY";
/// Guest subnet prefix length.
pub const PREFIX_LEN: &str = "SMOLVM_NETWORK_PREFIX_LEN";
/// Guest MAC address in colon-separated string form.
pub const GUEST_MAC: &str = "SMOLVM_NETWORK_GUEST_MAC";
/// Guest IPv6 (ULA) address. Optional: absent means IPv4-only guest config.
pub const GUEST_IP6: &str = "SMOLVM_NETWORK_GUEST_IP6";
/// Guest-visible default gateway IPv6 address.
pub const GATEWAY6: &str = "SMOLVM_NETWORK_GATEWAY6";
/// Guest IPv6 prefix length.
pub const PREFIX_LEN6: &str = "SMOLVM_NETWORK_PREFIX_LEN6";
/// Guest-visible DNS server IPv4 address.
pub const DNS: &str = "SMOLVM_NETWORK_DNS";
/// Enables the guest-side DNS filtering proxy.
pub const DNS_FILTER: &str = "SMOLVM_DNS_FILTER";
