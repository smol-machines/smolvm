//! Versioned host-only protocol for deciding a guest TCP flow before dialing
//! its original destination. The guest never receives the token or metadata.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC: &[u8; 8] = b"SMOLMEG3";
const MAGIC_V2: &[u8; 8] = b"SMOLMEG2";
/// Maximum guest application bytes presented before the decider responds.
pub const MAX_INITIAL_BYTES: usize = 8 * 1024;
/// Number of bytes in a host-minted launch identity.
pub const MACHINE_ID_LEN: usize = 16;
/// Number of bytes in the host-held authentication token.
pub const TOKEN_LEN: usize = 32;
/// Longest hostname hint a prelude carries.
pub const MAX_HOSTNAME_LEN: usize = 253;

/// The identity and destination smolvm attests to its local decider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowPrelude {
    /// Opaque identity minted by the VM host for this launch.
    pub machine_id: [u8; MACHINE_ID_LEN],
    /// Zero means this launch has no known branch parent.
    pub parent_id: [u8; MACHINE_ID_LEN],
    /// Original guest-requested destination.
    pub destination: SocketAddr,
    /// Name of the allowed DNS answer that last returned the destination
    /// address to the guest. A hint for the decider, not an authority.
    pub hostname: Option<String>,
    /// Bounded first application bytes, sent once in the prelude.
    pub initial_bytes: Vec<u8>,
}

impl FlowPrelude {
    /// Write a bounded, authenticated prelude. The token is host-held and must
    /// be unique to the binding; it is never sourced from guest bytes.
    pub fn write_to<W: Write>(&self, mut writer: W, token: &[u8; TOKEN_LEN]) -> io::Result<()> {
        if self.machine_id == [0; MACHINE_ID_LEN]
            || self.initial_bytes.len() > MAX_INITIAL_BYTES
            || !self.hostname.as_deref().is_none_or(hostname_hint_valid)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid flow prelude",
            ));
        }
        writer.write_all(MAGIC)?;
        writer.write_all(token)?;
        writer.write_all(&self.machine_id)?;
        writer.write_all(&self.parent_id)?;
        match self.destination.ip() {
            IpAddr::V4(ip) => {
                writer.write_all(&[4])?;
                writer.write_all(&self.destination.port().to_be_bytes())?;
                writer.write_all(&ip.octets())?;
            }
            IpAddr::V6(ip) => {
                writer.write_all(&[6])?;
                writer.write_all(&self.destination.port().to_be_bytes())?;
                writer.write_all(&ip.octets())?;
            }
        }
        let hostname = self.hostname.as_deref().unwrap_or_default();
        writer.write_all(&[hostname.len() as u8])?;
        writer.write_all(hostname.as_bytes())?;
        writer.write_all(&(self.initial_bytes.len() as u16).to_be_bytes())?;
        writer.write_all(&self.initial_bytes)
    }

    /// Authenticate and read one flow. Invalid lengths are rejected before
    /// allocation so a hostile local peer cannot force unbounded memory use.
    pub fn read_from<R: Read>(mut reader: R, token: &[u8; TOKEN_LEN]) -> io::Result<Self> {
        let mut fixed = [0u8; 8 + TOKEN_LEN + MACHINE_ID_LEN * 2 + 1 + 2];
        reader.read_exact(&mut fixed)?;
        let current = fixed[..8] == MAGIC[..];
        let mut mismatch = (!current && fixed[..8] != MAGIC_V2[..]) as u8;
        for (actual, expected) in fixed[8..8 + TOKEN_LEN].iter().zip(token) {
            mismatch |= actual ^ expected;
        }
        if mismatch != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "flow prelude rejected",
            ));
        }
        let mut machine_id = [0; MACHINE_ID_LEN];
        let mut parent_id = [0; MACHINE_ID_LEN];
        machine_id.copy_from_slice(&fixed[40..56]);
        parent_id.copy_from_slice(&fixed[56..72]);
        if machine_id == [0; MACHINE_ID_LEN] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing machine identity",
            ));
        }
        let port = u16::from_be_bytes([fixed[73], fixed[74]]);
        let ip = match fixed[72] {
            4 => {
                let mut bytes = [0; 4];
                reader.read_exact(&mut bytes)?;
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            6 => {
                let mut bytes = [0; 16];
                reader.read_exact(&mut bytes)?;
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid IP family",
                ))
            }
        };
        let hostname = if current {
            let mut len = [0; 1];
            reader.read_exact(&mut len)?;
            let len = usize::from(len[0]);
            if len > MAX_HOSTNAME_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hostname hint too long",
                ));
            }
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes)?;
            match String::from_utf8(bytes) {
                Ok(hostname) if hostname.is_empty() => None,
                Ok(hostname) if hostname_hint_valid(&hostname) => Some(hostname),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid hostname hint",
                    ))
                }
            }
        } else {
            None
        };
        let mut len = [0; 2];
        reader.read_exact(&mut len)?;
        let len = u16::from_be_bytes(len) as usize;
        if len > MAX_INITIAL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "initial payload too large",
            ));
        }
        let mut initial_bytes = vec![0; len];
        reader.read_exact(&mut initial_bytes)?;
        Ok(Self {
            machine_id,
            parent_id,
            destination: SocketAddr::new(ip, port),
            hostname,
            initial_bytes,
        })
    }
}

/// Whether `hostname` fits in a prelude: 1 to 253 bytes of lowercase ASCII
/// letters, digits, `-`, `_` and `.`.
pub fn hostname_hint_valid(hostname: &str) -> bool {
    (1..=MAX_HOSTNAME_LEN).contains(&hostname.len())
        && hostname.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}

/// One byte from the decider. Redirect retains the accepted broker stream as
/// the data path; AllowDirect makes smolvm dial the original destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    /// The VM host dials the original destination after this decision.
    AllowDirect = 0,
    /// Abort the guest flow without dialing the origin.
    Deny = 1,
    /// Continue guest traffic over the decider's accepted stream.
    Redirect = 2,
}

impl Decision {
    /// Read one decision byte, rejecting unknown values and closed streams.
    pub fn read_from<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        match byte[0] {
            0 => Ok(Self::AllowDirect),
            1 => Ok(Self::Deny),
            2 => Ok(Self::Redirect),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid egress decision",
            )),
        }
    }

    /// Write one decision byte.
    pub fn write_to<W: Write>(self, mut writer: W) -> io::Result<()> {
        writer.write_all(&[self as u8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_both_address_families_and_payload() {
        for destination in ["1.1.1.1:443", "[2606:4700:4700::1111]:443"] {
            let flow = FlowPrelude {
                machine_id: [7; 16],
                parent_id: [9; 16],
                destination: destination.parse().unwrap(),
                hostname: None,
                initial_bytes: b"first bytes".to_vec(),
            };
            let mut encoded = Vec::new();
            flow.write_to(&mut encoded, &[3; 32]).unwrap();
            assert_eq!(
                FlowPrelude::read_from(&encoded[..], &[3; 32]).unwrap(),
                flow
            );
            assert!(FlowPrelude::read_from(&encoded[..], &[4; 32]).is_err());
        }
    }

    #[test]
    fn rejects_oversized_and_unknown_decisions() {
        let flow = FlowPrelude {
            machine_id: [1; 16],
            parent_id: [0; 16],
            destination: "1.1.1.1:443".parse().unwrap(),
            hostname: None,
            initial_bytes: vec![0; MAX_INITIAL_BYTES + 1],
        };
        assert!(flow.write_to(Vec::new(), &[1; 32]).is_err());
        assert!(Decision::read_from(&[3][..]).is_err());
        assert_eq!(Decision::read_from(&[2][..]).unwrap(), Decision::Redirect);
    }

    fn flow_to(hostname: Option<&str>) -> FlowPrelude {
        FlowPrelude {
            machine_id: [7; 16],
            parent_id: [0; 16],
            destination: "1.1.1.1:443".parse().unwrap(),
            hostname: hostname.map(str::to_string),
            initial_bytes: b"hello".to_vec(),
        }
    }

    #[test]
    fn hostname_hint_round_trips_and_sits_before_the_payload() {
        let flow = flow_to(Some("api.example.com"));
        let mut encoded = Vec::new();
        flow.write_to(&mut encoded, &[3; 32]).unwrap();
        assert_eq!(&encoded[..8], b"SMOLMEG3");
        assert_eq!(encoded[79], 15);
        assert_eq!(&encoded[80..95], b"api.example.com");
        assert_eq!(&encoded[95..97], &[0, 5]);
        assert_eq!(
            FlowPrelude::read_from(&encoded[..], &[3; 32]).unwrap(),
            flow
        );
    }

    #[test]
    fn absent_hostname_is_a_zero_length_field() {
        let mut encoded = Vec::new();
        flow_to(None).write_to(&mut encoded, &[3; 32]).unwrap();
        assert_eq!(encoded[79], 0);
        assert_eq!(
            FlowPrelude::read_from(&encoded[..], &[3; 32])
                .unwrap()
                .hostname,
            None
        );
    }

    #[test]
    fn version_2_preludes_still_decode_without_a_hostname() {
        let mut encoded = Vec::new();
        flow_to(None).write_to(&mut encoded, &[3; 32]).unwrap();
        encoded[..8].copy_from_slice(b"SMOLMEG2");
        encoded.remove(79);
        assert_eq!(
            FlowPrelude::read_from(&encoded[..], &[3; 32]).unwrap(),
            flow_to(None)
        );
    }

    #[test]
    fn rejects_invalid_hostname_hints() {
        let long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        for hostname in [
            "",
            "API.example.com",
            "bad host",
            "caf\u{e9}.example",
            long.as_str(),
        ] {
            assert!(
                flow_to(Some(hostname))
                    .write_to(Vec::new(), &[3; 32])
                    .is_err(),
                "{hostname:?}"
            );
        }
        let mut encoded = Vec::new();
        flow_to(Some("api.example.com"))
            .write_to(&mut encoded, &[3; 32])
            .unwrap();
        encoded[80] = b' ';
        assert!(FlowPrelude::read_from(&encoded[..], &[3; 32]).is_err());
        assert!(FlowPrelude::read_from(&encoded[..90], &[3; 32]).is_err());
    }
}
