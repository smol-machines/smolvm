//! Versioned host-only protocol for deciding a guest TCP flow before dialing
//! its original destination. The guest never receives the token or metadata.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC: &[u8; 8] = b"SMOLMEG2";
/// Maximum guest application bytes presented before the decider responds.
pub const MAX_INITIAL_BYTES: usize = 8 * 1024;
/// Number of bytes in a host-minted launch identity.
pub const MACHINE_ID_LEN: usize = 16;
/// Number of bytes in the host-held authentication token.
pub const TOKEN_LEN: usize = 32;

/// The identity and destination smolvm attests to its local decider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowPrelude {
    /// Opaque identity minted by the VM host for this launch.
    pub machine_id: [u8; MACHINE_ID_LEN],
    /// Zero means this launch has no known branch parent.
    pub parent_id: [u8; MACHINE_ID_LEN],
    /// Original guest-requested destination.
    pub destination: SocketAddr,
    /// Bounded first application bytes, sent once in the prelude.
    pub initial_bytes: Vec<u8>,
}

impl FlowPrelude {
    /// Write a bounded, authenticated prelude. The token is host-held and must
    /// be unique to the binding; it is never sourced from guest bytes.
    pub fn write_to<W: Write>(&self, mut writer: W, token: &[u8; TOKEN_LEN]) -> io::Result<()> {
        if self.machine_id == [0; MACHINE_ID_LEN] || self.initial_bytes.len() > MAX_INITIAL_BYTES {
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
        writer.write_all(&(self.initial_bytes.len() as u16).to_be_bytes())?;
        writer.write_all(&self.initial_bytes)
    }

    /// Authenticate and read one flow. Invalid lengths are rejected before
    /// allocation so a hostile local peer cannot force unbounded memory use.
    pub fn read_from<R: Read>(mut reader: R, token: &[u8; TOKEN_LEN]) -> io::Result<Self> {
        let mut fixed = [0u8; 8 + TOKEN_LEN + MACHINE_ID_LEN * 2 + 1 + 2];
        reader.read_exact(&mut fixed)?;
        let mut mismatch = (fixed[..8] != MAGIC[..]) as u8;
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
            initial_bytes,
        })
    }
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
            initial_bytes: vec![0; MAX_INITIAL_BYTES + 1],
        };
        assert!(flow.write_to(Vec::new(), &[1; 32]).is_err());
        assert!(Decision::read_from(&[3][..]).is_err());
        assert_eq!(Decision::read_from(&[2][..]).unwrap(), Decision::Redirect);
    }
}
