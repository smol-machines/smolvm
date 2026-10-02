//! Guest-side listening state of published ports, for `machine status`.
//!
//! A published port forwards host connections to the guest's own address, so
//! a server inside the machine that listens only on 127.0.0.1 accepts nothing
//! from the host: the connection is accepted on the host and then reset, which
//! looks exactly like a crashed server. Reading the guest's `/proc/net/tcp`
//! and `/proc/net/tcp6` lets `status` say which case it is.

use smolvm::agent::AgentClient;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

/// Upper bound on the guest read; `status` must stay quick and never hang.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// TCP state code for LISTEN in `/proc/net/tcp*`.
const TCP_LISTEN: &str = "0A";

/// Whether a published guest port has a server the host can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestPortState {
    /// Something listens on a non-loopback address (0.0.0.0, ::, or the
    /// guest IP), so published connections reach it.
    Listening,
    /// Listeners exist only on loopback (127.0.0.0/8 or ::1), which a
    /// published port cannot reach. Carries one such address for the message.
    LoopbackOnly(IpAddr),
    /// Nothing listens on the port.
    NotListening,
}

impl GuestPortState {
    /// Stable machine-readable name used in JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            GuestPortState::Listening => "listening",
            GuestPortState::LoopbackOnly(_) => "loopback-only",
            GuestPortState::NotListening => "not-listening",
        }
    }

    /// One human-readable status line for a `host -> guest` mapping.
    pub fn describe(&self, host: u16, guest: u16) -> String {
        let detail = match self {
            GuestPortState::Listening => "listening".to_string(),
            GuestPortState::LoopbackOnly(addr) => format!(
                "listening on {} only, so the host cannot reach it; start the server on 0.0.0.0",
                addr
            ),
            GuestPortState::NotListening => "nothing is listening on this port".to_string(),
        };
        format!("  port {} -> {}: {}\n", host, guest, detail)
    }
}

/// Parse the LISTEN sockets out of `/proc/net/tcp` and `/proc/net/tcp6`
/// content (either or both, concatenated). Header lines, malformed lines and
/// sockets in any other state are skipped.
pub fn parse_listeners(proc_net_tcp: &str) -> Vec<(IpAddr, u16)> {
    proc_net_tcp
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _slot = fields.next()?;
            let local = fields.next()?;
            let _remote = fields.next()?;
            let state = fields.next()?;
            if state != TCP_LISTEN {
                return None;
            }
            let (addr_hex, port_hex) = local.split_once(':')?;
            let port = u16::from_str_radix(port_hex, 16).ok()?;
            Some((parse_proc_addr(addr_hex)?, port))
        })
        .collect()
}

/// Decode a `/proc/net/tcp*` address. The kernel prints each 32-bit word of
/// the network-order address as a native-endian integer; smolvm guests are
/// little-endian (x86_64, aarch64).
fn parse_proc_addr(hex: &str) -> Option<IpAddr> {
    let word = |chunk: &str| u32::from_str_radix(chunk, 16).ok().map(u32::to_le_bytes);
    match hex.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word(hex)?))),
        32 => {
            let mut octets = [0u8; 16];
            for i in 0..4 {
                octets[i * 4..i * 4 + 4].copy_from_slice(&word(hex.get(i * 8..i * 8 + 8)?)?);
            }
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn is_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Classify one guest port against the parsed listeners.
pub fn classify(listeners: &[(IpAddr, u16)], guest_port: u16) -> GuestPortState {
    let mut loopback = None;
    for (addr, port) in listeners {
        if *port != guest_port {
            continue;
        }
        if !is_loopback(addr) {
            return GuestPortState::Listening;
        }
        loopback.get_or_insert(*addr);
    }
    match loopback {
        Some(addr) => GuestPortState::LoopbackOnly(addr),
        None => GuestPortState::NotListening,
    }
}

/// Read the guest's LISTEN sockets through the agent. `None` on any failure
/// (old agent, timeout, unreadable output): callers then print nothing extra.
pub fn probe_guest_listeners(vsock_socket: &Path) -> Option<Vec<(IpAddr, u16)>> {
    let mut client = AgentClient::connect_with_short_timeout(vsock_socket).ok()?;
    let (_exit, stdout, _stderr) = client
        .vm_exec(
            vec![
                "cat".to_string(),
                "/proc/net/tcp".to_string(),
                "/proc/net/tcp6".to_string(),
            ],
            Vec::new(),
            None,
            Some(PROBE_TIMEOUT),
            None,
        )
        .ok()?;
    // `cat` exits non-zero when IPv6 is absent but still prints the IPv4
    // table; require the header so unrelated output is never read as
    // "nothing is listening".
    let text = String::from_utf8_lossy(&stdout);
    if !text.contains("local_address") {
        return None;
    }
    Some(parse_listeners(&text))
}

/// Classify every `(host, guest)` mapping.
pub fn port_states(
    ports: &[(u16, u16)],
    listeners: &[(IpAddr, u16)],
) -> Vec<(u16, u16, GuestPortState)> {
    ports
        .iter()
        .map(|&(host, guest)| (host, guest, classify(listeners, guest)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 00000000:4A26 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0200A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 100 0 0 10 0
   3: 0200A8C0:1F91 0100A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 20 4 30 10 -1
   4: 0100007F:1F92 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1 0000000000000000 100 0 0 10 0
   5: 00000000:1F92 0100007F:9C40 06 00000000:00000000 00:00000000 00000000     0        0 0 3 0000000000000000
";

    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0BB9 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:0BBA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2003 1 0000000000000000 100 0 0 10 0
   3: 00000000000000000000000001000000:22B8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2004 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_ipv4_listeners_and_ignores_other_states() {
        let listeners = parse_listeners(TCP);
        assert_eq!(
            listeners,
            vec![
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 18982),
                (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)), 8080),
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 8082),
            ]
        );
    }

    #[test]
    fn parses_ipv6_listeners() {
        let listeners = parse_listeners(TCP6);
        assert_eq!(
            listeners,
            vec![
                (IpAddr::V6(Ipv6Addr::LOCALHOST), 3000),
                (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 3001),
                (IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 3002),
                (IpAddr::V6(Ipv6Addr::LOCALHOST), 8888),
            ]
        );
    }

    #[test]
    fn malformed_lines_are_skipped() {
        assert!(parse_listeners("garbage\n 0: XYZ:22B8 0 0A\n 1: 0100007F 0 0A\n").is_empty());
    }

    #[test]
    fn classifies_mixed_listeners() {
        let text = format!("{TCP}{TCP6}");
        let listeners = parse_listeners(&text);
        // IPv4 and IPv6 loopback only: unreachable from the host.
        assert_eq!(
            classify(&listeners, 8888),
            GuestPortState::LoopbackOnly(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(classify(&listeners, 18982), GuestPortState::Listening);
        assert_eq!(classify(&listeners, 8080), GuestPortState::Listening);
        assert_eq!(classify(&listeners, 3001), GuestPortState::Listening);
        assert_eq!(
            classify(&listeners, 3000),
            GuestPortState::LoopbackOnly(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(matches!(
            classify(&listeners, 3002),
            GuestPortState::LoopbackOnly(_)
        ));
        // 8082 has a loopback listener plus a TIME_WAIT socket on 0.0.0.0;
        // only LISTEN sockets count.
        assert!(matches!(
            classify(&listeners, 8082),
            GuestPortState::LoopbackOnly(_)
        ));
        // ESTABLISHED on 8081 is not a listener.
        assert_eq!(classify(&listeners, 8081), GuestPortState::NotListening);
        assert_eq!(classify(&listeners, 1), GuestPortState::NotListening);
    }

    #[test]
    fn loopback_and_wildcard_on_the_same_port_is_reachable() {
        let listeners = vec![
            (IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80),
        ];
        assert_eq!(classify(&listeners, 80), GuestPortState::Listening);
    }

    #[test]
    fn describes_each_state() {
        assert_eq!(
            GuestPortState::LoopbackOnly(IpAddr::V4(Ipv4Addr::LOCALHOST)).describe(8888, 8888),
            "  port 8888 -> 8888: listening on 127.0.0.1 only, so the host cannot reach it; \
             start the server on 0.0.0.0\n"
        );
        assert_eq!(
            GuestPortState::Listening.describe(80, 8080),
            "  port 80 -> 8080: listening\n"
        );
        assert_eq!(
            GuestPortState::NotListening.describe(1, 2),
            "  port 1 -> 2: nothing is listening on this port\n"
        );
        assert_eq!(GuestPortState::NotListening.as_str(), "not-listening");
    }
}
