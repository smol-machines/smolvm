//! Kubernetes pod networking for shim-booted sandbox VMs.
//!
//! A pod sandbox VM must carry its CNI-assigned IP and be reachable at L2 on the
//! pod network — the same contract Kata satisfies. containerd runs the CNI plugin
//! against the sandbox's netns *before* we boot, leaving a configured interface
//! (`eth0`, a veth) there with the pod IP. This module, run in the boot
//! subprocess's privileged window (before the uid drop), discovers that
//! interface's L3 config, opens a tap in the netns, and tc-redirects the tap
//! against `eth0` (see [`smolvm_network::netns_tap`]). The launcher then bridges
//! the guest virtio-net NIC to the tap and configures the guest NIC with the
//! discovered IP/MAC, so the VM *is* the pod IP.

use std::net::Ipv4Addr;

/// CNI L3 config to apply to the guest NIC, plus the tap fd bridged to it.
///
/// Cross-platform (the launcher and boot-config boundary compile everywhere);
/// only the netns discovery below is Linux-only. Placed in the `LaunchConfig` so
/// the virtio-net arm can adopt the pod IP/MAC and bridge the tap.
#[derive(Debug, Clone)]
pub struct PodNetLaunch {
    /// Raw tap fd — owned by the boot subprocess's [`PodNetAttachment`], kept
    /// alive for the VM's lifetime. The launcher dups it for the frame bridge.
    pub tap_fd: i32,
    /// Pod IPv4 address (the CNI-assigned pod IP).
    pub ip: Ipv4Addr,
    /// Prefix length of the pod subnet.
    pub prefix: u8,
    /// Default gateway (the CNI bridge), if the netns has a default route.
    pub gateway: Option<Ipv4Addr>,
    /// MAC of the CNI interface; the guest NIC adopts it so ARP for the pod IP
    /// resolves to the VM.
    pub mac: [u8; 6],
    /// Interface MTU from the CNI config.
    pub mtu: u32,
}

/// Name of the CNI-provisioned interface containerd leaves in the pod netns.
#[cfg(target_os = "linux")]
const CNI_IFACE: &str = "eth0";
/// Name of the tap we create in the netns to carry the VM's L2 traffic.
#[cfg(target_os = "linux")]
const TAP_IFACE: &str = "tap0";

/// A live pod-netns attachment held by the boot subprocess: the tap fd (bridged
/// to the guest NIC by the launcher) and the discovered CNI L3 config. Dropping
/// it closes the tap, tearing down the datapath when the VM exits.
#[cfg(target_os = "linux")]
pub struct PodNetAttachment {
    /// Owns the tap fd for the VM's lifetime (the launcher only dups it).
    _tap: std::os::fd::OwnedFd,
    launch: PodNetLaunch,
}

#[cfg(target_os = "linux")]
impl PodNetAttachment {
    /// The launch view (tap fd + L3 config) to place in the `LaunchConfig`.
    pub fn launch(&self) -> PodNetLaunch {
        self.launch.clone()
    }
}

/// Discover the CNI interface, open a tap in `netns_path`, and tc-redirect the
/// tap against the CNI interface. Privileged (needs CAP_NET_ADMIN +
/// CAP_SYS_ADMIN); call in the boot subprocess's privileged window, before the
/// uid drop and Landlock/seccomp.
#[cfg(target_os = "linux")]
pub fn attach_pod_netns(netns_path: &str) -> std::io::Result<PodNetAttachment> {
    use std::os::fd::AsRawFd;

    let mut launch = read_pod_interface(netns_path, CNI_IFACE)?;
    // Open the tap first; only then redirect (tc needs the device to exist).
    let tap = smolvm_network::netns_tap::open_tap_in_netns(netns_path, TAP_IFACE)?;
    smolvm_network::netns_tap::setup_tc_redirect(netns_path, CNI_IFACE, TAP_IFACE)?;
    launch.tap_fd = tap.as_raw_fd();
    tracing::info!(
        netns = %netns_path,
        pod_ip = %launch.ip,
        prefix = launch.prefix,
        gateway = ?launch.gateway,
        mtu = launch.mtu,
        "pod netns attached (tap0 tc-redirected against eth0)"
    );
    Ok(PodNetAttachment { _tap: tap, launch })
}

/// Read `ifname`'s IPv4/prefix/MAC/MTU and the default gateway from inside the
/// pod netns via `nsenter … ip -j`. Returns a [`PodNetLaunch`] with `tap_fd`
/// unset (`-1`) — [`attach_pod_netns`] fills it in after opening the tap.
#[cfg(target_os = "linux")]
pub fn read_pod_interface(netns_path: &str, ifname: &str) -> std::io::Result<PodNetLaunch> {
    let addr = ip_json(netns_path, &["-j", "addr", "show", ifname])?;
    let route = ip_json(netns_path, &["-j", "route", "show", "default"])?;
    parse_pod_interface(&addr, &route, ifname)
}

/// Run `nsenter --net=<netns> ip <args>` and parse the `-j` JSON output.
#[cfg(target_os = "linux")]
fn ip_json(netns_path: &str, args: &[&str]) -> std::io::Result<serde_json::Value> {
    let out = std::process::Command::new("nsenter")
        .arg(format!("--net={netns_path}"))
        .arg("ip")
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "nsenter --net={netns_path} ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| std::io::Error::other(format!("parse `ip {}` json: {e}", args.join(" "))))
}

/// Parse `ip -j addr show <ifname>` + `ip -j route show default` into the L3
/// config. Pure (no I/O) so it is unit-testable against captured JSON.
#[cfg(target_os = "linux")]
fn parse_pod_interface(
    addr: &serde_json::Value,
    route: &serde_json::Value,
    ifname: &str,
) -> std::io::Result<PodNetLaunch> {
    let err = |m: String| std::io::Error::new(std::io::ErrorKind::InvalidData, m);

    let iface = addr
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| err(format!("no interface {ifname} in pod netns")))?;

    let mac_str = iface
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(format!("{ifname}: no MAC in `ip addr`")))?;
    let mac = parse_mac(mac_str).ok_or_else(|| err(format!("{ifname}: bad MAC {mac_str}")))?;

    let mtu = iface.get("mtu").and_then(|v| v.as_u64()).unwrap_or(1500) as u32;

    let inet = iface
        .get("addr_info")
        .and_then(|v| v.as_array())
        .and_then(|infos| {
            infos
                .iter()
                .find(|i| i.get("family").and_then(|f| f.as_str()) == Some("inet"))
        })
        .ok_or_else(|| err(format!("{ifname}: no IPv4 address in pod netns")))?;

    let ip: Ipv4Addr = inet
        .get("local")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err(format!("{ifname}: unparseable IPv4 address")))?;
    let prefix = inet.get("prefixlen").and_then(|v| v.as_u64()).unwrap_or(24) as u8;

    let gateway = route
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|r| r.get("dst").and_then(|d| d.as_str()) == Some("default"))
        })
        .and_then(|r| r.get("gateway"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());

    Ok(PodNetLaunch {
        tap_fd: -1,
        ip,
        prefix,
        gateway,
        mac,
        mtu,
    })
}

/// Parse an `aa:bb:cc:dd:ee:ff` MAC into 6 bytes.
#[cfg(target_os = "linux")]
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            return None;
        }
        out[i] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_cni_interface_json() {
        // Representative `ip -j addr show eth0` from a bridge-CNI pod.
        let addr: serde_json::Value = serde_json::from_str(
            r#"[{"ifname":"eth0","mtu":1450,"address":"0a:58:0a:58:00:6c",
                "addr_info":[
                  {"family":"inet","local":"10.88.0.108","prefixlen":16},
                  {"family":"inet6","local":"fe80::1","prefixlen":64}]}]"#,
        )
        .unwrap();
        let route: serde_json::Value =
            serde_json::from_str(r#"[{"dst":"default","gateway":"10.88.0.1","dev":"eth0"}]"#)
                .unwrap();

        let p = parse_pod_interface(&addr, &route, "eth0").unwrap();
        assert_eq!(p.ip, "10.88.0.108".parse::<Ipv4Addr>().unwrap());
        assert_eq!(p.prefix, 16);
        assert_eq!(p.gateway, Some("10.88.0.1".parse().unwrap()));
        assert_eq!(p.mtu, 1450);
        assert_eq!(p.mac, [0x0a, 0x58, 0x0a, 0x58, 0x00, 0x6c]);
    }

    #[test]
    fn tolerates_missing_default_route() {
        let addr: serde_json::Value = serde_json::from_str(
            r#"[{"ifname":"eth0","mtu":1500,"address":"02:00:00:00:00:01",
                "addr_info":[{"family":"inet","local":"192.168.1.5","prefixlen":24}]}]"#,
        )
        .unwrap();
        let route: serde_json::Value = serde_json::from_str("[]").unwrap();
        let p = parse_pod_interface(&addr, &route, "eth0").unwrap();
        assert_eq!(p.gateway, None);
        assert_eq!(p.prefix, 24);
    }

    #[test]
    fn rejects_interface_without_ipv4() {
        let addr: serde_json::Value = serde_json::from_str(
            r#"[{"ifname":"eth0","mtu":1500,"address":"02:00:00:00:00:01",
                "addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64}]}]"#,
        )
        .unwrap();
        let route: serde_json::Value = serde_json::from_str("[]").unwrap();
        assert!(parse_pod_interface(&addr, &route, "eth0").is_err());
    }
}
