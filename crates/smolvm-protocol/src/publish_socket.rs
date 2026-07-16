//! Shared spec for user-published host↔guest Unix-socket bridges.
//!
//! Generalizes the fixed Docker (guest→host) and SSH-agent (host→guest) bridges
//! into a dynamic, user-specified set. The host allocates a vsock port per
//! published socket and encodes the guest-relevant fields into the
//! [`crate::guest_env::PUBLISH_SOCKETS`] env var; the guest agent decodes it and
//! starts one relay per entry.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Direction a published Unix socket is bridged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SocketDirection {
    /// A guest process listens on the guest path; smolvm exposes it on the host.
    /// Host clients connect in — the Docker-bridge pattern.
    Expose,
    /// A host process listens on the host path; smolvm makes it reachable inside
    /// the guest at the guest path. Guest clients connect in — the SSH-agent
    /// pattern.
    Mount,
}

impl SocketDirection {
    /// Wire/CLI token for this direction.
    pub fn as_str(&self) -> &'static str {
        match self {
            SocketDirection::Expose => "expose",
            SocketDirection::Mount => "mount",
        }
    }

    /// The libkrun `krun_add_vsock_port2` `listen` flag for this direction.
    ///
    /// `Expose`: the guest serves on the vsock port and the host connects in, so
    /// libkrun *listens* on the host-side socket (`true`). `Mount`: the guest
    /// connects out to the vsock port and libkrun dials the host socket, so
    /// libkrun does not listen (`false`).
    pub fn host_listens(&self) -> bool {
        matches!(self, SocketDirection::Expose)
    }
}

impl FromStr for SocketDirection {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "expose" => Ok(SocketDirection::Expose),
            "mount" => Ok(SocketDirection::Mount),
            other => Err(format!(
                "invalid socket direction '{other}' (expected 'expose' or 'mount')"
            )),
        }
    }
}

/// One published socket, as the guest agent needs to know it: which vsock port
/// carries it, which guest-side path to serve or create, and the direction.
///
/// The host-side path is intentionally absent — libkrun owns the host end, so
/// the guest never needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedSocket {
    /// vsock port assigned to this bridge by the host launcher.
    pub vsock_port: u32,
    /// Guest-side socket path: the existing app socket to proxy to (`Expose`),
    /// or the path to create a listener at (`Mount`).
    pub guest_path: String,
    /// Bridge direction.
    pub direction: SocketDirection,
}

/// Encode a list of published sockets for the guest env var, as
/// `port|dir|guest_path` entries joined by `;`. Paths cannot contain `;` or `|`
/// in any realistic case; entries that would are rejected by the host before
/// encoding (see the host-side validator).
pub fn encode(sockets: &[PublishedSocket]) -> String {
    sockets
        .iter()
        .map(|s| format!("{}|{}|{}", s.vsock_port, s.direction.as_str(), s.guest_path))
        .collect::<Vec<_>>()
        .join(";")
}

/// Decode the guest env var back into published-socket specs. Malformed entries
/// are skipped rather than failing the whole parse, so one bad entry can't take
/// down every bridge.
pub fn decode(encoded: &str) -> Vec<PublishedSocket> {
    encoded
        .split(';')
        .filter(|e| !e.is_empty())
        .filter_map(|entry| {
            let mut parts = entry.splitn(3, '|');
            let vsock_port = parts.next()?.parse::<u32>().ok()?;
            let direction = parts.next()?.parse::<SocketDirection>().ok()?;
            let guest_path = parts.next()?.to_string();
            if guest_path.is_empty() {
                return None;
            }
            Some(PublishedSocket {
                vsock_port,
                guest_path,
                direction,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_roundtrips_and_maps_to_listen_flag() {
        assert_eq!(
            "expose".parse::<SocketDirection>().unwrap(),
            SocketDirection::Expose
        );
        assert_eq!(
            "MOUNT".parse::<SocketDirection>().unwrap(),
            SocketDirection::Mount
        );
        assert!("bogus".parse::<SocketDirection>().is_err());
        assert!(SocketDirection::Expose.host_listens());
        assert!(!SocketDirection::Mount.host_listens());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let socks = vec![
            PublishedSocket {
                vsock_port: 6100,
                guest_path: "/var/run/app.sock".into(),
                direction: SocketDirection::Expose,
            },
            PublishedSocket {
                vsock_port: 6101,
                guest_path: "/tmp/host.sock".into(),
                direction: SocketDirection::Mount,
            },
        ];
        let encoded = encode(&socks);
        assert_eq!(
            encoded,
            "6100|expose|/var/run/app.sock;6101|mount|/tmp/host.sock"
        );
        assert_eq!(decode(&encoded), socks);
    }

    #[test]
    fn decode_skips_malformed_entries() {
        // empty string, missing fields, bad port, bad dir, empty path — all skipped
        assert!(decode("").is_empty());
        let mixed = "6100|expose|/ok.sock;garbage;9|nope|/x.sock;abc|expose|/y.sock;6102|mount|";
        let out = decode(mixed);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].guest_path, "/ok.sock");
    }
}
