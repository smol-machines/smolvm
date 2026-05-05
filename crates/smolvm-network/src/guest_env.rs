//! Shared environment-variable contract for guest virtio networking.
//!
//! These names form the protocol boundary between:
//! - the host-side launcher, which decides the guest/gateway plan
//! - the guest agent, which configures the in-guest NIC from that plan
//!
//! They should be treated as stable protocol constants rather than ad hoc
//! launcher strings.

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
/// Guest-visible DNS server IPv4 address.
pub const DNS: &str = "SMOLVM_NETWORK_DNS";
