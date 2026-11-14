//! Automatic port publishing: which guest TCP ports are listening.
//!
//! With auto ports on, the guest agent reads `/proc/net/tcp` and
//! `/proc/net/tcp6` about once a second and, whenever the set of listening
//! ports changes, connects out on [`crate::ports::AUTO_PORTS`] and sends the
//! whole current set as one [`ListeningReport`] line. The host publishes each
//! reported port on its own loopback through the live port forwarder, which
//! reaches the guest port at the guest's loopback, and closes it again once a
//! report no longer names it.
//!
//! Each report is the complete set, not a delta, so a reconnect (a restored
//! guest, a restarted agent) or a dropped line cannot leave the two sides
//! disagreeing for longer than the next report. A report is a JSON object on
//! one line and readers ignore fields they do not know, so either side can
//! grow it without a protocol version bump. A host that predates this never
//! registers the vsock port and never sets [`crate::guest_env::AUTO_PORTS`],
//! so a new agent never starts the watcher; a new host with an old agent just
//! never receives a report.
//!
//! The `/proc/net/tcp` parser lives here because the host reads the same
//! tables for `machine status`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The longest report line a host reads. 65 535 five-digit ports and their
/// commas fit with room to spare, so a well-formed report is never cut.
pub const MAX_REPORT_BYTES: usize = 512 * 1024;

/// TCP state code for LISTEN in `/proc/net/tcp*`.
const TCP_LISTEN: &str = "0A";

/// One report from the guest: every TCP port it currently listens on in a
/// way the port forwarder can reach (see [`forwardable_ports`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ListeningReport {
    /// Listening TCP ports, ascending and without duplicates.
    pub tcp: Vec<u16>,
}

impl ListeningReport {
    /// The report for `ports`.
    pub fn new(ports: &BTreeSet<u16>) -> Self {
        Self {
            tcp: ports.iter().copied().collect(),
        }
    }

    /// The report as one line, newline included.
    pub fn encode(&self) -> String {
        let mut line = serde_json::to_string(self).expect("a list of ports always serializes");
        line.push('\n');
        line
    }

    /// Read one report line. `None` for anything that is not a report
    /// object, so a garbled line is skipped rather than read as "nothing
    /// listens" and closing every published port.
    pub fn decode(line: &str) -> Option<Self> {
        serde_json::from_str(line.trim()).ok()
    }

    /// The reported ports as a set, port 0 dropped.
    pub fn ports(&self) -> BTreeSet<u16> {
        self.tcp.iter().copied().filter(|&port| port != 0).collect()
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

/// Whether `addr` is a loopback address, IPv4-mapped forms included.
pub fn is_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Whether `addr` is the wildcard address, IPv4-mapped form included.
fn is_wildcard(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified())
        }
    }
}

/// The listening ports the port forwarder can reach. It connects to the
/// guest's loopback, so a server bound to the wildcard address or to
/// loopback counts (dev servers often bind `127.0.0.1` only), while one
/// bound to a single other address (a container bridge, the guest's NIC
/// address) does not: a loopback connect would be refused.
pub fn forwardable_ports(listeners: &[(IpAddr, u16)]) -> BTreeSet<u16> {
    listeners
        .iter()
        .filter(|(addr, port)| *port != 0 && (is_wildcard(addr) || is_loopback(addr)))
        .map(|(_, port)| *port)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP4: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0F02000A:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
   3: 0100007F:1F90 0100007F:D2B0 01 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 20 4 30 10 -1
";

    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:2328 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1389 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:138A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7 1 0000000000000000 100 0 0 10 0
   3: 000080FE00000000FF005450B6AD1DFE:138B 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn ipv4_listen_sockets_decode_with_hex_ports_and_other_states_are_skipped() {
        let listeners = parse_listeners(TCP4);
        assert_eq!(
            listeners,
            vec![
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
                (IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 5432),
            ],
            "the ESTABLISHED row (state 01) is not a listener"
        );
    }

    #[test]
    fn ipv6_listen_sockets_decode_including_mapped_and_link_local() {
        let listeners = parse_listeners(TCP6);
        assert_eq!(listeners.len(), 4);
        assert_eq!(listeners[0], (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 9000));
        assert_eq!(listeners[1], (IpAddr::V6(Ipv6Addr::LOCALHOST), 5001));
        assert_eq!(
            listeners[2],
            (IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 5002)
        );
        assert!(matches!(listeners[3].0, IpAddr::V6(v6) if v6.segments()[0] == 0xfe80));
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let text = "garbage\n   0: ZZZZ:1F90 00000000:0000 0A\n   1: 00000000:FFFFF 0:0 0A\n";
        assert!(parse_listeners(text).is_empty());
    }

    #[test]
    fn only_wildcard_and_loopback_listeners_are_forwardable() {
        let mut both = String::from(TCP4);
        both.push_str(TCP6);
        let ports = forwardable_ports(&parse_listeners(&both));
        // 8080 any, 3000 loopback, 9000 [::], 5001 [::1], 5002 mapped loopback;
        // 5432 on the NIC address and 5003 on a link-local address are not
        // reachable over the guest's loopback.
        assert_eq!(ports, BTreeSet::from([3000, 5001, 5002, 8080, 9000]));
    }

    #[test]
    fn reports_round_trip_as_one_line() {
        let report = ListeningReport::new(&BTreeSet::from([8000, 80, 3000]));
        let line = report.encode();
        assert_eq!(line, "{\"tcp\":[80,3000,8000]}\n");
        assert_eq!(ListeningReport::decode(&line), Some(report));
    }

    #[test]
    fn a_reader_ignores_fields_it_does_not_know_and_refuses_garbage() {
        // A newer agent may add fields; an older host still reads the ports.
        let newer = ListeningReport::decode("{\"tcp\":[8080,0],\"udp\":[53],\"v\":2}").unwrap();
        assert_eq!(newer.ports(), BTreeSet::from([8080]), "port 0 is dropped");
        assert_eq!(
            ListeningReport::decode("{}"),
            Some(ListeningReport::default()),
            "an empty object is an empty set"
        );
        for bad in ["", "8080", "{\"tcp\":\"8080\"}", "{\"tcp\":[70000]}"] {
            assert_eq!(ListeningReport::decode(bad), None, "{bad:?}");
        }
    }
}
