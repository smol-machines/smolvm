//! Guest-side virtio-net configuration from `SMOLVM_NETWORK_*`.
//!
//! Context
//! =======
//!
//! The host side of the virtio-net design decides whether a VM should use:
//! - the legacy TSI networking path, or
//! - a real virtio-net device exposed to the guest
//!
//! When virtio-net is selected, the launcher does not run guest shell
//! commands like `ip link`, `ip addr`, or `ip route`. Instead it passes a
//! small, explicit configuration contract into the guest as environment
//! variables. The agent reads those values very early in boot and programs
//! the kernel network state directly.
//!
//! That gives us a narrow host/guest boundary:
//!
//! ```text
//! host launcher
//!   -> decides backend = virtio-net
//!   -> chooses guest IP / gateway / DNS / MAC
//!   -> exports SMOLVM_NETWORK_* env
//!   -> starts guest agent
//!
//! guest agent
//!   -> parses SMOLVM_NETWORK_* env
//!   -> configures eth0 inside the guest kernel
//!   -> continues normal boot
//! ```
//!
//! In shell terms, the Linux implementation in `linux.rs` is effectively a
//! built-in replacement for this class of commands:
//!
//! ```text
//! ip link set dev eth0 address <mac>
//! ip link set dev eth0 mtu <mtu>
//! ip addr add <guest_ip>/<prefix> dev eth0
//! ip link set dev eth0 up
//! ip route add default via <gateway>
//! printf 'nameserver <dns>\n' > /etc/resolv.conf
//! ```
//!
//! We do it inside the agent rather than by spawning external tools because the
//! guest image is intentionally small and boots before we can assume userspace
//! helpers are present.
//!
//! The Linux-specific implementation lives in `linux.rs`. Non-Linux guests
//! currently return an explicit error instead of attempting a partial setup.

use smolvm_protocol::guest_env;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Configure the guest network interface from host-provided environment.
///
/// Returns `Ok(false)` when virtio-net is not enabled for this boot.
///
/// Environment contract
/// --------------------
///
/// The host launcher currently provides:
/// - `SMOLVM_NETWORK_BACKEND=virtio-net`
/// - `SMOLVM_NETWORK_GUEST_IP`
/// - `SMOLVM_NETWORK_GATEWAY`
/// - `SMOLVM_NETWORK_PREFIX_LEN`
/// - `SMOLVM_NETWORK_GUEST_MAC`
/// - `SMOLVM_NETWORK_DNS`
/// - `SMOLVM_NETWORK_GUEST_IP6` / `SMOLVM_NETWORK_GATEWAY6` /
///   `SMOLVM_NETWORK_PREFIX_LEN6` (optional trio — absent means IPv4-only)
///
/// Example:
///
/// ```text
/// SMOLVM_NETWORK_BACKEND=virtio-net
/// SMOLVM_NETWORK_GUEST_IP=10.0.2.15
/// SMOLVM_NETWORK_GATEWAY=10.0.2.2
/// SMOLVM_NETWORK_PREFIX_LEN=24
/// SMOLVM_NETWORK_GUEST_MAC=02:53:4d:00:00:02
/// SMOLVM_NETWORK_DNS=10.0.2.2
/// SMOLVM_NETWORK_GUEST_IP6=fd53:4d00::2
/// SMOLVM_NETWORK_GATEWAY6=fd53:4d00::1
/// SMOLVM_NETWORK_PREFIX_LEN6=64
/// ```
///
/// What this function does
/// -----------------------
///
/// 1. Decide whether the current boot even wants guest virtio networking.
/// 2. Parse the environment strings into typed values.
/// 3. Call the Linux backend to program `eth0`.
///
/// Outcome
/// -------
///
/// - `Ok(false)`: no virtio-net request was present, so the agent leaves the
///   guest network untouched.
/// - `Ok(true)`: `eth0` was configured successfully.
/// - `Err(...)`: virtio-net was requested but the configuration was incomplete
///   or malformed, so boot should fail instead of continuing with a
///   half-configured NIC.
pub fn configure_from_env() -> Result<bool, String> {
    let backend = match std::env::var(guest_env::BACKEND) {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(false),
    };

    if backend != guest_env::BACKEND_VIRTIO_NET {
        return Err(format!(
            "unsupported {} value: {}",
            guest_env::BACKEND,
            backend
        ));
    }

    let guest_ip = env_ipv4(guest_env::GUEST_IP)?;
    let gateway = env_ipv4(guest_env::GATEWAY)?;
    let prefix_len = env_u8(guest_env::PREFIX_LEN)?;
    let guest_mac = env_mac(guest_env::GUEST_MAC)?;
    let dns_server = env_ipv4(guest_env::DNS)?;
    let ipv6 = env_ipv6_config()?;

    linux::configure_interface(
        "eth0", guest_mac, 1500, guest_ip, prefix_len, gateway, ipv6, dns_server,
    )?;
    Ok(true)
}

/// Parse the optional IPv6 trio. All three vars must be present together; a
/// partial set is a malformed contract and fails the boot rather than leaving a
/// half-configured stack.
fn env_ipv6_config() -> Result<Option<(Ipv6Addr, u8, Ipv6Addr)>, String> {
    let vars = [
        guest_env::GUEST_IP6,
        guest_env::GATEWAY6,
        guest_env::PREFIX_LEN6,
    ];
    let present = vars
        .iter()
        .filter(|name| std::env::var(name).is_ok_and(|v| !v.is_empty()))
        .count();
    match present {
        0 => Ok(None),
        3 => Ok(Some((
            env_ipv6(guest_env::GUEST_IP6)?,
            env_u8(guest_env::PREFIX_LEN6)?,
            env_ipv6(guest_env::GATEWAY6)?,
        ))),
        _ => Err(format!(
            "incomplete IPv6 network config: {} / {} / {} must be set together",
            guest_env::GUEST_IP6,
            guest_env::GATEWAY6,
            guest_env::PREFIX_LEN6
        )),
    }
}

fn env_ipv4(name: &str) -> Result<Ipv4Addr, String> {
    let value = std::env::var(name).map_err(|_| format!("missing {}", name))?;
    value
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid IPv4 address for {}: {}", name, value))
}

fn env_ipv6(name: &str) -> Result<Ipv6Addr, String> {
    let value = std::env::var(name).map_err(|_| format!("missing {}", name))?;
    value
        .parse::<Ipv6Addr>()
        .map_err(|_| format!("invalid IPv6 address for {}: {}", name, value))
}

fn env_u8(name: &str) -> Result<u8, String> {
    let value = std::env::var(name).map_err(|_| format!("missing {}", name))?;
    value
        .parse::<u8>()
        .map_err(|_| format!("invalid integer for {}: {}", name, value))
}

fn env_mac(name: &str) -> Result<[u8; 6], String> {
    let value = std::env::var(name).map_err(|_| format!("missing {}", name))?;
    parse_mac(&value)
}

/// Parse a colon-separated MAC address into six raw octets.
///
/// The guest kernel APIs do not consume the string form directly. They expect
/// the six raw Ethernet octets, so we translate:
///
/// ```text
/// 02:53:4d:00:00:02
///   -> [0x02, 0x53, 0x4d, 0x00, 0x00, 0x02]
/// ```
///
/// This parser is intentionally strict: exactly six hex octets separated by
/// `:` and nothing else.
fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let mut mac = [0u8; 6];
    let mut count = 0usize;
    for (index, part) in value.split(':').enumerate() {
        if index >= 6 {
            return Err(format!("invalid MAC address: {}", value));
        }
        mac[index] =
            u8::from_str_radix(part, 16).map_err(|_| format!("invalid MAC octet: {}", part))?;
        count = index + 1;
    }
    if count != 6 {
        return Err(format!("invalid MAC address: {}", value));
    }
    Ok(mac)
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
mod linux {
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[allow(clippy::too_many_arguments)]
    pub fn configure_interface(
        _ifname: &str,
        _mac: [u8; 6],
        _mtu: u16,
        _address: Ipv4Addr,
        _prefix_len: u8,
        _gateway: Ipv4Addr,
        _ipv6: Option<(Ipv6Addr, u8, Ipv6Addr)>,
        _dns_server: Ipv4Addr,
    ) -> Result<(), String> {
        Err("guest virtio networking is only supported on Linux".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_accepts_six_octets() {
        assert_eq!(
            parse_mac("02:53:4d:00:00:02").unwrap(),
            [0x02, 0x53, 0x4d, 0x00, 0x00, 0x02]
        );
    }

    #[test]
    fn parse_mac_rejects_invalid_input() {
        assert!(parse_mac("02:53:4d").is_err());
        assert!(parse_mac("zz:53:4d:00:00:02").is_err());
    }
}
