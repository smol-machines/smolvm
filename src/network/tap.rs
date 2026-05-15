//! Managed TAP networking: device creation, bridge, NAT, tc shaping, lifecycle cleanup.
//!
//! This module provides deterministic, per-VM network isolation using a Linux
//! TAP device bridged to the host's default route interface. Each VM gets its
//! own /30 subnet carved from the 100.64.0.0/10 (Carrier-Grade NAT) range,
//! with the bridge acting as the gateway and the guest assigned the second
//! usable address.
//!
//! Names are derived from a SHA-256 hash of the VM name so they are stable
//! across stop/start cycles and stay within the 15-character IFNAMSIZ limit.

use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use tracing::{debug, info, warn};

use crate::Error;

// ---------------------------------------------------------------------------
// TUN/TAP ioctl constants (from linux/if_tun.h)
// ---------------------------------------------------------------------------

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNSETPERSIST: libc::c_ulong = 0x400454cb;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Full configuration for a managed TAP network attached to a single VM.
#[derive(Clone, Debug)]
pub struct TapConfig {
    /// VM name this config belongs to.
    pub vm_name: String,
    /// TAP device name (stap-XXXXXXX, 12 chars — fits IFNAMSIZ).
    pub tap_name: String,
    /// Bridge device name (sbr-XXXXXXX, 11 chars).
    pub bridge_name: String,
    /// Subnet in CIDR notation, e.g. "100.64.0.0/30".
    pub subnet_cidr: String,
    /// Gateway IP (first usable host address, assigned to the bridge).
    pub gateway_ip: String,
    /// Guest IP (second usable host address, announced via DHCP/static config).
    pub guest_ip: String,
    /// CIDR prefix length (typically 30).
    pub prefix_len: u8,
    /// Deterministic locally-administered MAC for the guest virtio-net device.
    pub mac: [u8; 6],
    /// Host interface used for outbound NAT (e.g. "eth0", "wlan0").
    pub host_iface: String,
    /// Optional bandwidth limit for tc shaping (e.g. "100mbit").
    pub bandwidth: Option<String>,
    /// DNS server advertised to the guest.
    pub dns_server: String,
    /// Allowed egress CIDRs. When non-empty, all other egress is dropped.
    pub allowed_cidrs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Set up a fully managed TAP network stack for a VM.
///
/// This is the main orchestrator: it creates the TAP device, bridge, NAT
/// rules, optional traffic shaping, and optional egress filtering. If any
/// step fails, it attempts best-effort teardown of everything created so far.
///
/// `tap_device` must be `None` — this function only handles the managed path.
/// Callers that pass a pre-existing TAP device should skip this entirely.
pub fn setup_managed_tap(
    vm_name: &str,
    tap_device: Option<&str>,
    tap_mac: Option<&str>,
    tap_subnet: Option<&str>,
    tap_guest_ip: Option<&str>,
    tap_bandwidth: Option<&str>,
    allowed_cidrs: &[String],
) -> crate::Result<TapConfig> {
    if tap_device.is_some() {
        return Err(Error::agent(
            "tap setup",
            "setup_managed_tap must not be called with a pre-existing tap_device; \
             pass tap_device=None for managed mode",
        ));
    }

    let hash = device_hash(vm_name);
    let tap_name = format!("stap-{hash}");
    let bridge_name = format!("sbr-{hash}");

    let (subnet_cidr, gateway_ip, guest_ip, prefix_len) =
        allocate_subnet(vm_name, tap_subnet, tap_guest_ip)?;

    let mac = match tap_mac {
        Some(s) => parse_mac(s)?,
        None => generate_mac(vm_name),
    };

    let host_iface = detect_default_route_iface()?;

    let config = TapConfig {
        vm_name: vm_name.to_string(),
        tap_name,
        bridge_name,
        subnet_cidr,
        gateway_ip,
        guest_ip,
        prefix_len,
        mac,
        host_iface,
        bandwidth: tap_bandwidth.map(|s| s.to_string()),
        dns_server: "1.1.1.1".to_string(),
        allowed_cidrs: allowed_cidrs.to_vec(),
    };

    // Track which steps succeeded so we can unwind on failure.
    let mut tap_created = false;
    let mut bridge_created = false;
    let mut ip_forward_set = false;
    let mut nat_set = false;
    let mut tc_set = false;
    let mut egress_set = false;

    let result = (|| -> crate::Result<()> {
        create_tap_device(&config.tap_name)?;
        tap_created = true;

        create_bridge(&config)?;
        bridge_created = true;

        enable_ip_forward()?;
        ip_forward_set = true;

        setup_nat(&config)?;
        nat_set = true;

        setup_tc(&config)?;
        tc_set = true;

        setup_egress_rules(&config)?;
        egress_set = true;

        Ok(())
    })();

    if let Err(e) = result {
        warn!(
            vm = vm_name,
            err = %e,
            "managed TAP setup failed — cleaning up partial state"
        );

        if egress_set {
            teardown_egress_rules(&config);
        }
        if tc_set {
            teardown_tc(&config);
        }
        if nat_set {
            teardown_nat(&config);
        }
        // ip_forward is global — we intentionally do NOT reset it.
        let _ = ip_forward_set;
        if bridge_created {
            run_cmd_ignore_err("ip", &["link", "set", &config.tap_name, "nomaster"]);
            run_cmd_ignore_err(
                "ip",
                &["link", "delete", &config.bridge_name, "type", "bridge"],
            );
        }
        if tap_created {
            run_cmd_ignore_err("ip", &["link", "delete", &config.tap_name]);
        }

        return Err(e);
    }

    info!(
        vm = vm_name,
        tap = %config.tap_name,
        bridge = %config.bridge_name,
        subnet = %config.subnet_cidr,
        gateway = %config.gateway_ip,
        guest = %config.guest_ip,
        mac = %format_mac(&config.mac),
        "managed TAP network ready"
    );

    Ok(config)
}

/// Tear down a managed TAP network stack. Best-effort: logs errors but does
/// not fail so callers can always proceed with VM cleanup.
pub fn teardown(config: &TapConfig) -> crate::Result<()> {
    info!(
        vm = %config.vm_name,
        tap = %config.tap_name,
        bridge = %config.bridge_name,
        "tearing down managed TAP network"
    );

    // Reverse order of setup.
    teardown_egress_rules(config);
    teardown_tc(config);
    teardown_nat(config);

    // Detach TAP from bridge, then delete both.
    run_cmd_ignore_err("ip", &["link", "set", &config.tap_name, "nomaster"]);
    run_cmd_ignore_err(
        "ip",
        &["link", "delete", &config.bridge_name, "type", "bridge"],
    );
    run_cmd_ignore_err("ip", &["link", "delete", &config.tap_name]);

    Ok(())
}

/// Generate a deterministic locally-administered unicast MAC from a VM name.
///
/// Uses bytes [8..14] of the SHA-256 digest so the MAC is independent of the
/// device-hash (which uses bytes [0..8]). Bit 1 of byte 0 is set (locally
/// administered) and bit 0 is cleared (unicast).
pub fn generate_mac(vm_name: &str) -> [u8; 6] {
    let digest = Sha256::digest(vm_name.as_bytes());
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&digest[8..14]);
    mac[0] |= 0x02; // locally administered
    mac[0] &= 0xfe; // unicast
    mac
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// First 7 hex characters of SHA-256(vm_name).
fn device_hash(vm_name: &str) -> String {
    let digest = Sha256::digest(vm_name.as_bytes());
    hex::encode(&digest[..4])[..7].to_string()
}

/// Allocate a /30 subnet for the VM.
///
/// Returns `(subnet_cidr, gateway_ip, guest_ip, prefix_len)`.
///
/// Default behaviour: hash the VM name into an offset within the 100.64.0.0/10
/// range (about 4M addresses). Pick a /30-aligned block. The gateway gets .1
/// and the guest gets .2 within that block.
///
/// User overrides: if `user_subnet` is provided it is parsed as CIDR; first
/// host is the gateway, second host is the guest (or `user_guest_ip` override).
fn allocate_subnet(
    vm_name: &str,
    user_subnet: Option<&str>,
    user_guest_ip: Option<&str>,
) -> crate::Result<(String, String, String, u8)> {
    if let Some(cidr) = user_subnet {
        return parse_user_subnet(cidr, user_guest_ip);
    }

    // Hash into the 100.64.0.0/10 range (100.64.0.0 – 100.127.255.255).
    // That is 2^22 = 4_194_304 addresses. We need /30 blocks (4 addresses
    // each), giving us 1_048_576 possible blocks.
    let digest = Sha256::digest(vm_name.as_bytes());
    let hash_u32 = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);

    // Number of /30 blocks in 100.64.0.0/10.
    let num_blocks: u32 = 1 << 20; // 2^22 / 4
    let block_index = hash_u32 % num_blocks;

    let base: u32 = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    let block_base = base + block_index * 4;

    let network = Ipv4Addr::from(block_base);
    let gateway = Ipv4Addr::from(block_base + 1);
    let guest = Ipv4Addr::from(block_base + 2);

    let subnet_cidr = format!("{network}/30");
    let prefix_len = 30u8;

    debug!(
        vm = vm_name,
        subnet = %subnet_cidr,
        gateway = %gateway,
        guest = %guest,
        "allocated default /30 subnet"
    );

    Ok((
        subnet_cidr,
        gateway.to_string(),
        guest.to_string(),
        prefix_len,
    ))
}

/// Parse a user-supplied CIDR string and derive gateway + guest IPs.
fn parse_user_subnet(
    cidr: &str,
    user_guest_ip: Option<&str>,
) -> crate::Result<(String, String, String, u8)> {
    let (addr_str, prefix_str) = cidr.split_once('/').ok_or_else(|| {
        Error::agent(
            "tap setup",
            format!("invalid subnet CIDR '{cidr}': expected address/prefix"),
        )
    })?;

    let network_addr: Ipv4Addr = addr_str.parse().map_err(|e| {
        Error::agent(
            "tap setup",
            format!("invalid subnet address '{addr_str}': {e}"),
        )
    })?;

    let prefix_len: u8 = prefix_str.parse().map_err(|e| {
        Error::agent(
            "tap setup",
            format!("invalid prefix length '{prefix_str}': {e}"),
        )
    })?;

    if prefix_len > 30 {
        return Err(Error::agent(
            "tap setup",
            format!("prefix /{prefix_len} is too small — need at least /30 for gateway + guest"),
        ));
    }

    let net_u32 = u32::from(network_addr);
    let gateway = Ipv4Addr::from(net_u32 + 1);

    let guest = if let Some(gip) = user_guest_ip {
        gip.parse::<Ipv4Addr>()
            .map_err(|e| Error::agent("tap setup", format!("invalid guest IP '{gip}': {e}")))?
    } else {
        Ipv4Addr::from(net_u32 + 2)
    };

    let subnet_cidr = format!("{network_addr}/{prefix_len}");

    Ok((
        subnet_cidr,
        gateway.to_string(),
        guest.to_string(),
        prefix_len,
    ))
}

/// Detect the host interface attached to the default route.
fn detect_default_route_iface() -> crate::Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| Error::agent("tap setup", format!("failed to run 'ip route': {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Typical line: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
    for line in stdout.lines() {
        if let Some(dev_pos) = line.find(" dev ") {
            let after_dev = &line[dev_pos + 5..];
            if let Some(iface) = after_dev.split_whitespace().next() {
                debug!(iface = iface, "detected default route interface");
                return Ok(iface.to_string());
            }
        }
    }

    Err(Error::agent(
        "tap setup",
        "could not detect default route interface from 'ip route show default'",
    ))
}

/// Create a persistent TAP device via /dev/net/tun ioctl.
fn create_tap_device(tap_name: &str) -> crate::Result<()> {
    if tap_name.len() > 15 {
        return Err(Error::agent(
            "tap setup",
            format!(
                "TAP name '{tap_name}' exceeds IFNAMSIZ (15 chars), got {}",
                tap_name.len()
            ),
        ));
    }

    let tun_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| {
            Error::agent(
                "tap setup",
                format!(
                    "failed to open /dev/net/tun: {e} (are you root or in the 'netdev' group?)"
                ),
            )
        })?;

    let fd = tun_file.as_raw_fd();

    // Prepare ifreq struct.
    // SAFETY: zeroing a POD struct is well-defined; the subsequent ioctl
    // operates on the open fd and the zeroed struct with name + flags set.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy the device name into ifr_name (null-terminated, max 15 chars + NUL).
    let name_bytes = tap_name.as_bytes();
    for (i, &b) in name_bytes.iter().enumerate().take(libc::IFNAMSIZ - 1) {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    // Set flags: IFF_TAP | IFF_NO_PI.
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;

    // SAFETY: TUNSETIFF is the standard ioctl to create/attach a TUN/TAP
    // device. `fd` is a valid open file descriptor to /dev/net/tun, and
    // `ifr` is a properly initialized ifreq with name and flags set.
    let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(Error::agent(
            "tap setup",
            format!("TUNSETIFF ioctl failed for '{tap_name}': {errno}"),
        ));
    }

    // Make the device persistent so it survives fd close.
    // SAFETY: TUNSETPERSIST with argument 1 marks the device persistent.
    // `fd` is the same valid descriptor from the TUNSETIFF call above.
    let ret = unsafe { libc::ioctl(fd, TUNSETPERSIST, 1_i32) };
    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(Error::agent(
            "tap setup",
            format!("TUNSETPERSIST ioctl failed for '{tap_name}': {errno}"),
        ));
    }

    // fd is closed when tun_file drops — the device persists due to TUNSETPERSIST.
    drop(tun_file);

    // Bring the TAP interface up.
    run_cmd("ip", &["link", "set", tap_name, "up"])?;

    debug!(tap = tap_name, "created persistent TAP device");
    Ok(())
}

/// Create a bridge, assign the gateway IP, bring it up, and enslave the TAP.
fn create_bridge(config: &TapConfig) -> crate::Result<()> {
    let bridge = &config.bridge_name;
    let tap = &config.tap_name;
    let gw_cidr = format!("{}/{}", config.gateway_ip, config.prefix_len);

    run_cmd("ip", &["link", "add", bridge, "type", "bridge"])?;
    run_cmd("ip", &["addr", "add", &gw_cidr, "dev", bridge])?;
    run_cmd("ip", &["link", "set", bridge, "up"])?;
    run_cmd("ip", &["link", "set", tap, "master", bridge])?;

    debug!(bridge = bridge, tap = tap, gateway = %gw_cidr, "bridge created");
    Ok(())
}

/// Ensure IPv4 forwarding is enabled on the host.
fn enable_ip_forward() -> crate::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| Error::agent("tap setup", format!("failed to enable ip_forward: {e}")))?;
    debug!("IPv4 forwarding enabled");
    Ok(())
}

/// Set up iptables NAT rules for outbound traffic from the VM subnet.
fn setup_nat(config: &TapConfig) -> crate::Result<()> {
    let subnet = &config.subnet_cidr;
    let host_iface = &config.host_iface;

    // MASQUERADE outbound traffic from the VM subnet.
    run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            host_iface,
            "-j",
            "MASQUERADE",
        ],
    )?;

    // Allow forwarded traffic from the bridge.
    run_cmd(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-i",
            &config.bridge_name,
            "-o",
            host_iface,
            "-j",
            "ACCEPT",
        ],
    )?;

    // Allow related/established return traffic.
    run_cmd(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-i",
            host_iface,
            "-o",
            &config.bridge_name,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    )?;

    debug!(
        subnet = subnet,
        host_iface = host_iface,
        "NAT rules installed"
    );
    Ok(())
}

/// Set up HTB traffic shaping on the TAP device if a bandwidth limit is set.
fn setup_tc(config: &TapConfig) -> crate::Result<()> {
    let bandwidth = match &config.bandwidth {
        Some(bw) => bw,
        None => return Ok(()),
    };

    let tap = &config.tap_name;

    // Add root HTB qdisc.
    run_cmd(
        "tc",
        &[
            "qdisc", "add", "dev", tap, "root", "handle", "1:", "htb", "default", "10",
        ],
    )?;

    // Add class with the bandwidth cap.
    run_cmd(
        "tc",
        &[
            "class", "add", "dev", tap, "parent", "1:", "classid", "1:10", "htb", "rate",
            bandwidth, "ceil", bandwidth,
        ],
    )?;

    debug!(tap = tap, bandwidth = bandwidth, "tc shaping applied");
    Ok(())
}

/// Set up iptables FORWARD rules to restrict VM egress to allowed CIDRs.
fn setup_egress_rules(config: &TapConfig) -> crate::Result<()> {
    if config.allowed_cidrs.is_empty() {
        return Ok(());
    }

    let bridge = &config.bridge_name;
    let host_iface = &config.host_iface;

    // Allow each permitted CIDR.
    for cidr in &config.allowed_cidrs {
        run_cmd(
            "iptables",
            &[
                "-I", "FORWARD", "-i", bridge, "-o", host_iface, "-d", cidr, "-j", "ACCEPT",
            ],
        )?;
    }

    // Drop everything else from this bridge (appended after the per-CIDR
    // ACCEPT rules so it acts as a default-deny).
    run_cmd(
        "iptables",
        &[
            "-A", "FORWARD", "-i", bridge, "-o", host_iface, "-j", "DROP",
        ],
    )?;

    debug!(
        bridge = bridge,
        cidrs = ?config.allowed_cidrs,
        "egress filtering rules installed"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Teardown helpers (best-effort, log errors)
// ---------------------------------------------------------------------------

/// Remove the three NAT-related iptables rules.
fn teardown_nat(config: &TapConfig) {
    let subnet = &config.subnet_cidr;
    let host_iface = &config.host_iface;
    let bridge = &config.bridge_name;

    run_cmd_ignore_err(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            host_iface,
            "-j",
            "MASQUERADE",
        ],
    );

    run_cmd_ignore_err(
        "iptables",
        &[
            "-D", "FORWARD", "-i", bridge, "-o", host_iface, "-j", "ACCEPT",
        ],
    );

    run_cmd_ignore_err(
        "iptables",
        &[
            "-D",
            "FORWARD",
            "-i",
            host_iface,
            "-o",
            bridge,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    );
}

/// Remove the tc qdisc (if any).
fn teardown_tc(config: &TapConfig) {
    if config.bandwidth.is_none() {
        return;
    }
    run_cmd_ignore_err("tc", &["qdisc", "del", "dev", &config.tap_name, "root"]);
}

/// Remove egress filtering rules.
fn teardown_egress_rules(config: &TapConfig) {
    if config.allowed_cidrs.is_empty() {
        return;
    }

    let bridge = &config.bridge_name;
    let host_iface = &config.host_iface;

    // Remove the default-deny rule.
    run_cmd_ignore_err(
        "iptables",
        &[
            "-D", "FORWARD", "-i", bridge, "-o", host_iface, "-j", "DROP",
        ],
    );

    // Remove per-CIDR ACCEPT rules.
    for cidr in &config.allowed_cidrs {
        run_cmd_ignore_err(
            "iptables",
            &[
                "-D", "FORWARD", "-i", bridge, "-o", host_iface, "-d", cidr, "-j", "ACCEPT",
            ],
        );
    }
}

// ---------------------------------------------------------------------------
// Command execution helpers
// ---------------------------------------------------------------------------

/// Run an external command. Returns `Ok(())` on exit status 0, otherwise
/// returns `Error::agent` with the stderr output.
fn run_cmd(cmd: &str, args: &[&str]) -> crate::Result<()> {
    debug!(cmd = cmd, args = ?args, "running command");

    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| Error::agent("tap setup", format!("failed to execute '{cmd}': {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::agent(
            "tap setup",
            format!(
                "'{cmd} {}' failed (exit {}): {}",
                args.join(" "),
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ),
        ));
    }

    debug!(cmd = cmd, args = ?args, "command succeeded");
    Ok(())
}

/// Run an external command, logging a warning on failure but never returning
/// an error. Used in teardown paths where partial cleanup is acceptable.
fn run_cmd_ignore_err(cmd: &str, args: &[&str]) {
    match Command::new(cmd).args(args).output() {
        Ok(output) if output.status.success() => {
            debug!(cmd = cmd, args = ?args, "teardown command succeeded");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                cmd = cmd,
                args = ?args,
                stderr = %stderr.trim(),
                "teardown command failed (non-fatal)"
            );
        }
        Err(e) => {
            warn!(
                cmd = cmd,
                args = ?args,
                err = %e,
                "teardown command could not be executed (non-fatal)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// MAC address helpers
// ---------------------------------------------------------------------------

/// Parse a MAC address string like "02:ab:cd:ef:01:23" into bytes.
fn parse_mac(s: &str) -> crate::Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(Error::agent(
            "tap setup",
            format!("invalid MAC '{s}': expected 6 colon-separated hex octets"),
        ));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|e| {
            Error::agent(
                "tap setup",
                format!("invalid MAC octet '{part}' in '{s}': {e}"),
            )
        })?;
    }
    Ok(mac)
}

/// Format a MAC address as colon-separated hex.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_hash_is_7_hex_chars() {
        let h = device_hash("my-vm");
        assert_eq!(h.len(), 7);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn device_hash_is_deterministic() {
        assert_eq!(device_hash("sandbox-1"), device_hash("sandbox-1"));
    }

    #[test]
    fn device_hash_differs_for_different_names() {
        assert_ne!(device_hash("a"), device_hash("b"));
    }

    #[test]
    fn tap_name_fits_ifnamsiz() {
        // stap-XXXXXXX = 5 + 7 = 12 chars, well under 15.
        let h = device_hash("anything");
        let tap = format!("stap-{h}");
        assert!(tap.len() <= 15, "tap name '{}' exceeds IFNAMSIZ", tap);
    }

    #[test]
    fn bridge_name_fits_ifnamsiz() {
        // sbr-XXXXXXX = 4 + 7 = 11 chars.
        let h = device_hash("anything");
        let bridge = format!("sbr-{h}");
        assert!(
            bridge.len() <= 15,
            "bridge name '{}' exceeds IFNAMSIZ",
            bridge
        );
    }

    #[test]
    fn generate_mac_is_deterministic() {
        assert_eq!(generate_mac("vm-1"), generate_mac("vm-1"));
    }

    #[test]
    fn generate_mac_is_locally_administered_unicast() {
        let mac = generate_mac("test-vm");
        // Bit 1 of byte 0 must be set (locally administered).
        assert_ne!(mac[0] & 0x02, 0, "locally-administered bit not set");
        // Bit 0 of byte 0 must be clear (unicast).
        assert_eq!(mac[0] & 0x01, 0, "unicast bit not clear");
    }

    #[test]
    fn generate_mac_differs_for_different_names() {
        assert_ne!(generate_mac("a"), generate_mac("b"));
    }

    #[test]
    fn allocate_subnet_default_is_in_cgnat_range() {
        let (cidr, gw, guest, prefix) = allocate_subnet("test-vm", None, None).unwrap();
        assert!(cidr.ends_with("/30"));
        assert_eq!(prefix, 30);

        let gw_ip: Ipv4Addr = gw.parse().unwrap();
        let guest_ip: Ipv4Addr = guest.parse().unwrap();

        // Must be in 100.64.0.0/10 (100.64.0.0 – 100.127.255.255).
        let gw_u32 = u32::from(gw_ip);
        let base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
        let end = u32::from(Ipv4Addr::new(100, 127, 255, 255));
        assert!(
            gw_u32 >= base && gw_u32 <= end,
            "gateway {gw} outside CGNAT range"
        );

        // Guest must be gateway + 1.
        assert_eq!(u32::from(guest_ip), u32::from(gw_ip) + 1);
    }

    #[test]
    fn allocate_subnet_default_is_deterministic() {
        let a = allocate_subnet("stable-name", None, None).unwrap();
        let b = allocate_subnet("stable-name", None, None).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn allocate_subnet_user_override() {
        let (cidr, gw, guest, prefix) = allocate_subnet("vm", Some("10.0.0.0/24"), None).unwrap();
        assert_eq!(cidr, "10.0.0.0/24");
        assert_eq!(gw, "10.0.0.1");
        assert_eq!(guest, "10.0.0.2");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn allocate_subnet_user_guest_ip_override() {
        let (_, gw, guest, _) =
            allocate_subnet("vm", Some("10.0.0.0/24"), Some("10.0.0.100")).unwrap();
        assert_eq!(gw, "10.0.0.1");
        assert_eq!(guest, "10.0.0.100");
    }

    #[test]
    fn allocate_subnet_rejects_prefix_too_small() {
        let err = allocate_subnet("vm", Some("10.0.0.0/31"), None).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn allocate_subnet_rejects_bad_cidr() {
        assert!(allocate_subnet("vm", Some("not-a-cidr"), None).is_err());
    }

    #[test]
    fn parse_mac_valid() {
        let mac = parse_mac("02:ab:cd:ef:01:23").unwrap();
        assert_eq!(mac, [0x02, 0xab, 0xcd, 0xef, 0x01, 0x23]);
    }

    #[test]
    fn parse_mac_invalid_length() {
        assert!(parse_mac("02:ab:cd").is_err());
    }

    #[test]
    fn parse_mac_invalid_hex() {
        assert!(parse_mac("zz:ab:cd:ef:01:23").is_err());
    }

    #[test]
    fn format_mac_roundtrip() {
        let mac = [0x02, 0xab, 0xcd, 0xef, 0x01, 0x23];
        assert_eq!(format_mac(&mac), "02:ab:cd:ef:01:23");
    }

    #[test]
    fn setup_managed_tap_rejects_pre_existing_device() {
        let err = setup_managed_tap("vm", Some("tap0"), None, None, None, None, &[]).unwrap_err();
        assert!(err.to_string().contains("pre-existing"));
    }
}
