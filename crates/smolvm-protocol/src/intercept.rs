//! Host-side stream interception handshake.
//!
//! When a machine carries a credential policy, the virtio-net relay in
//! `smolvm-network` redirects guest HTTPS flows to an interceptor listening on
//! host loopback instead of dialing the destination directly. It prefixes the
//! redirected byte stream with a fixed-size preamble that names the destination
//! the guest actually asked for and proves the connection came from the
//! machine's own relay rather than from an arbitrary host process that found
//! the loopback port.
//!
//! Wire layout (all integers big-endian):
//!
//! ```text
//! magic    8 bytes  "SMOLICPT"
//! token   32 bytes  per-machine secret shared with the interceptor
//! port     2 bytes  destination port
//! address 16 bytes  destination IP (IPv4 as an IPv4-mapped IPv6 address)
//! ```
//!
//! Guest payload follows immediately; the guest never sees the preamble.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

const MAGIC: &[u8; 8] = b"SMOLICPT";
/// Bytes of shared secret carried in every preamble.
pub const TOKEN_LEN: usize = 32;
/// Total preamble length.
pub const PREAMBLE_LEN: usize = MAGIC.len() + TOKEN_LEN + 2 + 16;

/// Where a backend redirects intercepted flows, and the secret it must present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterceptEndpoint {
    /// Loopback listener owned by the interceptor.
    pub addr: SocketAddr,
    /// Secret shared between the interceptor and the machine's relay only.
    pub token: [u8; TOKEN_LEN],
}

impl InterceptEndpoint {
    /// Encode the preamble for one redirected flow.
    pub fn preamble(&self, destination: SocketAddr) -> [u8; PREAMBLE_LEN] {
        let ip = match destination.ip() {
            IpAddr::V4(ip) => ip.to_ipv6_mapped(),
            IpAddr::V6(ip) => ip,
        };
        let mut out = [0u8; PREAMBLE_LEN];
        let (magic, rest) = out.split_at_mut(MAGIC.len());
        let (token, rest) = rest.split_at_mut(TOKEN_LEN);
        let (port, address) = rest.split_at_mut(2);
        magic.copy_from_slice(MAGIC);
        token.copy_from_slice(&self.token);
        port.copy_from_slice(&destination.port().to_be_bytes());
        address.copy_from_slice(&ip.octets());
        out
    }

    /// Write the preamble for `destination` to a freshly connected stream.
    pub fn write_preamble<W: Write>(&self, mut w: W, destination: SocketAddr) -> io::Result<()> {
        w.write_all(&self.preamble(destination))
    }

    /// Authenticate a preamble and return the destination the guest dialed. A
    /// wrong magic or token is `InvalidData`; the token comparison does not
    /// short-circuit on the first differing byte.
    pub fn parse_preamble(&self, preamble: &[u8; PREAMBLE_LEN]) -> io::Result<SocketAddr> {
        let (magic, rest) = preamble.split_at(MAGIC.len());
        let (token, rest) = rest.split_at(TOKEN_LEN);
        let (port, address) = rest.split_at(2);
        let mut mismatch = (magic != MAGIC) as u8;
        for (a, b) in token.iter().zip(self.token.iter()) {
            mismatch |= a ^ b;
        }
        if mismatch != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "intercept preamble rejected",
            ));
        }
        let address: [u8; 16] = address.try_into().expect("fixed layout");
        let ip = Ipv6Addr::from(address).to_canonical();
        Ok(SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]])))
    }

    /// Read and authenticate a preamble from an accepted connection.
    pub fn read_preamble<R: Read>(&self, mut r: R) -> io::Result<SocketAddr> {
        let mut preamble = [0u8; PREAMBLE_LEN];
        r.read_exact(&mut preamble)?;
        self.parse_preamble(&preamble)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(token: u8) -> InterceptEndpoint {
        InterceptEndpoint {
            addr: "127.0.0.1:1".parse().unwrap(),
            token: [token; TOKEN_LEN],
        }
    }

    #[test]
    fn round_trips_v4_and_v6_destinations() {
        let ep = endpoint(7);
        for dst in [
            "93.184.216.34:443",
            "[2606:2800:220:1:248:1893:25c8:1946]:8443",
        ] {
            let dst: SocketAddr = dst.parse().unwrap();
            assert_eq!(ep.parse_preamble(&ep.preamble(dst)).unwrap(), dst);
        }
    }

    #[test]
    fn rejects_wrong_token_and_magic() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let bytes = endpoint(1).preamble(dst);
        let err = endpoint(2).parse_preamble(&bytes).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut bad_magic = endpoint(1).preamble(dst);
        bad_magic[0] = b'X';
        let err = endpoint(1).parse_preamble(&bad_magic).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn short_reads_surface_as_eof() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let bytes = endpoint(1).preamble(dst);
        let err = endpoint(1)
            .read_preamble(&bytes[..bytes.len() - 1])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
