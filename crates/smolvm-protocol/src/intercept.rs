//! Host-side stream interception handshake.
//!
//! When a machine carries a credential policy, its network backend redirects
//! selected guest TCP flows (HTTPS by default) to an interceptor listening on
//! host loopback instead of dialing the destination directly. The redirecting
//! side — the virtio-net relay in `smolvm-network`, or libkrun's TSI muxer —
//! prefixes the redirected byte stream with a fixed-size preamble that names
//! the destination the guest actually asked for and proves the connection came
//! from the machine's own backend rather than from an arbitrary host process
//! that found the loopback port.
//!
//! Wire layout (all integers big-endian):
//!
//! ```text
//! magic    8 bytes  "SMOLICPT"
//! version  1 byte   1
//! token   32 bytes  per-machine secret shared with the interceptor
//! family   1 byte   4 or 6
//! port     2 bytes  destination port
//! address  4 or 16  destination IP
//! ```
//!
//! The interceptor answers with one byte before any payload flows: `0` once
//! it has connected to the destination, otherwise the Linux errno of that
//! connect. libkrun's TSI muxer reports it to the guest as the result of the
//! guest's own connect, so a guest with an unreachable IPv6 route still falls
//! back to IPv4 exactly as it would without interception. Guest payload then
//! follows; the guest never sees the preamble or the verdict.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC: &[u8; 8] = b"SMOLICPT";
const VERSION: u8 = 1;
/// Bytes of shared secret carried in every preamble.
pub const TOKEN_LEN: usize = 32;
/// Bytes of preamble before the destination address.
pub const HEADER_LEN: usize = MAGIC.len() + 1 + TOKEN_LEN + 1 + 2;

/// Total preamble length implied by an already-read fixed header, or `None`
/// if the family byte is invalid. Lets an async reader size its second read.
pub fn preamble_len(header: &[u8]) -> Option<usize> {
    match header.get(HEADER_LEN - 3)? {
        4 => Some(HEADER_LEN + 4),
        6 => Some(HEADER_LEN + 16),
        _ => None,
    }
}

/// Verdict byte for a destination the interceptor reached.
pub const VERDICT_CONNECTED: u8 = 0;

/// Verdict byte for the interceptor's connect to the real destination: `0`, or
/// the Linux errno the guest should see (guests are Linux whatever the host).
pub fn connect_verdict<T>(result: &io::Result<T>) -> u8 {
    const ENETUNREACH: u8 = 101;
    const ETIMEDOUT: u8 = 110;
    const ECONNREFUSED: u8 = 111;
    const EHOSTUNREACH: u8 = 113;
    match result {
        Ok(_) => VERDICT_CONNECTED,
        Err(e) => match e.kind() {
            io::ErrorKind::NetworkUnreachable => ENETUNREACH,
            io::ErrorKind::HostUnreachable => EHOSTUNREACH,
            io::ErrorKind::TimedOut => ETIMEDOUT,
            _ => ECONNREFUSED,
        },
    }
}

/// Read the interceptor's verdict; an error carries the errno it reported.
pub fn read_verdict<R: Read>(mut r: R) -> io::Result<()> {
    let mut verdict = [0u8; 1];
    r.read_exact(&mut verdict)?;
    match verdict[0] {
        VERDICT_CONNECTED => Ok(()),
        errno => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("interceptor could not reach the destination (errno {errno})"),
        )),
    }
}

/// Where a backend redirects intercepted flows, and the secret it must present.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterceptEndpoint {
    /// Loopback listener owned by the interceptor.
    pub addr: SocketAddr,
    /// Secret shared between the interceptor and the machine's backend only.
    pub token: [u8; TOKEN_LEN],
}

impl std::fmt::Debug for InterceptEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptEndpoint")
            .field("addr", &self.addr)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod debug_tests {
    use super::InterceptEndpoint;

    #[test]
    fn interceptor_token_is_redacted() {
        let endpoint = InterceptEndpoint {
            addr: "127.0.0.1:9000".parse().unwrap(),
            token: [42; 32],
        };
        let rendered = format!("{endpoint:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("42"));
    }
}

impl InterceptEndpoint {
    /// Encode the preamble for one redirected flow.
    pub fn preamble(&self, destination: SocketAddr) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 16);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.token);
        match destination.ip() {
            IpAddr::V4(_) => out.push(4),
            IpAddr::V6(_) => out.push(6),
        }
        out.extend_from_slice(&destination.port().to_be_bytes());
        match destination.ip() {
            IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
        }
        out
    }

    /// Write the preamble for `destination` to a freshly connected stream.
    pub fn write_preamble<W: Write>(&self, mut w: W, destination: SocketAddr) -> io::Result<()> {
        w.write_all(&self.preamble(destination))
    }

    /// Read and authenticate a preamble from an accepted connection.
    ///
    /// Returns the destination the guest dialed. A wrong magic, version or
    /// token is reported as `InvalidData` after consuming the fixed header so
    /// the caller can simply drop the connection; the token comparison does not
    /// short-circuit on the first differing byte.
    pub fn read_preamble<R: Read>(&self, mut r: R) -> io::Result<SocketAddr> {
        let mut header = [0u8; HEADER_LEN];
        r.read_exact(&mut header)?;
        let (magic, rest) = header.split_at(MAGIC.len());
        let (version, rest) = rest.split_first().expect("fixed header");
        let (token, rest) = rest.split_at(TOKEN_LEN);
        let (family, port) = rest.split_first().expect("fixed header");
        let port = u16::from_be_bytes([port[0], port[1]]);

        let mut mismatch = (magic != MAGIC) as u8 | (*version != VERSION) as u8;
        for (a, b) in token.iter().zip(self.token.iter()) {
            mismatch |= a ^ b;
        }
        if mismatch != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "intercept preamble rejected",
            ));
        }
        let ip = match family {
            4 => {
                let mut octets = [0u8; 4];
                r.read_exact(&mut octets)?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let mut octets = [0u8; 16];
                r.read_exact(&mut octets)?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "intercept preamble has an unknown address family",
                ))
            }
        };
        Ok(SocketAddr::new(ip, port))
    }
}

/// The credential tunnel: how HTTPS that a workload sends anywhere other than
/// the machine's NIC still reaches the interceptor.
///
/// The machine's network backend only sees traffic on the machine's own NIC
/// (or, with TSI, the sockets libkrun proxies). A workload that routes a host
/// through a VPN (Tailscale's `tailscale0` for a tailnet host or an exit node,
/// WireGuard, OpenVPN), forwards it for a container in its own network
/// namespace, or hands it to a local proxy such as Tailscale's userspace
/// SOCKS5/HTTP proxy sends it out encrypted, so the backend cannot intercept
/// it. The guest agent therefore catches that HTTPS inside the guest and hands
/// each connection to the interceptor over vsock
/// ([`crate::ports::CREDENTIAL_TUNNEL`]); the interceptor opens the upstream
/// connection back through the guest ([`crate::ports::CREDENTIAL_DIAL`]), from
/// where the connection came from, so it takes the route the workload chose.
/// TLS to the upstream is still made and verified on the host: the guest
/// relays ciphertext and never sees a credential value.
///
/// Both directions start with one text line, `TARGET ROUTE\n`. `TARGET` is
/// `IP:PORT`, `[IPv6]:PORT` or `NAME:PORT` (a proxy request names its
/// destination); `ROUTE` is a token the guest agent chose to find its way back
/// (a network namespace, a proxy session), opaque to the host, which only
/// reads the port and sends the line back unchanged to dial. A dial is
/// answered with one verdict byte, as [`connect_verdict`] encodes it, before
/// the upstream bytes flow.
pub mod tunnel {
    use std::io::{self, Read, Write};
    use std::net::SocketAddr;

    /// `fwmark` on the guest agent's own upstream sockets, so the redirect in
    /// their network namespace skips them. It sits outside the `0xff0000`
    /// bits Tailscale uses for its own marks, so their routing is unchanged.
    pub const DIAL_MARK: u32 = 0x534d;

    /// DSCP on the guest agent's own upstream connections. A mark does not
    /// survive a hop into another network namespace; the DSCP rides in the IP
    /// header, so the redirect skips the connection wherever it is forwarded
    /// next. From the pool RFC 2474 leaves for local use.
    pub const DIAL_DSCP: u8 = 0x37;

    /// Longest line: a DNS name, a port, a route token and `\n`.
    pub const MAX_LINE: usize = 320;

    /// Where a tunnelled connection was going.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Target {
        /// An address the workload connected to.
        Addr(SocketAddr),
        /// A DNS name and port a proxy request named.
        Name(String, u16),
    }

    impl Target {
        /// The destination port.
        pub fn port(&self) -> u16 {
            match self {
                Target::Addr(addr) => addr.port(),
                Target::Name(_, port) => *port,
            }
        }
    }

    impl std::fmt::Display for Target {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Target::Addr(addr) => write!(f, "{addr}"),
                Target::Name(name, port) => write!(f, "{name}:{port}"),
            }
        }
    }

    /// One tunnelled connection: its target and the agent's route token.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Flow {
        /// Where the connection was going.
        pub target: Target,
        /// The guest agent's token for the way back.
        pub route: String,
    }

    impl Flow {
        /// Encode the line, newline included.
        pub fn line(&self) -> String {
            format!("{} {}\n", self.target, self.route)
        }

        /// Write the line to a fresh stream.
        pub fn write<W: Write>(&self, mut w: W) -> io::Result<()> {
            w.write_all(self.line().as_bytes())
        }

        /// Read a line one byte at a time, so no byte of the stream that
        /// follows is consumed.
        pub fn read<R: Read>(mut r: R) -> io::Result<Self> {
            let mut line = Vec::with_capacity(64);
            let mut byte = [0u8; 1];
            while line.len() <= MAX_LINE {
                r.read_exact(&mut byte)?;
                if byte[0] == b'\n' {
                    return Self::parse(&line);
                }
                line.push(byte[0]);
            }
            Err(invalid("credential tunnel line too long"))
        }

        /// Parse a line without its newline.
        pub fn parse(line: &[u8]) -> io::Result<Self> {
            let text = std::str::from_utf8(line).map_err(|_| invalid("credential tunnel line"))?;
            let (target, route) = text
                .split_once(' ')
                .ok_or_else(|| invalid("credential tunnel line has no route"))?;
            if route.is_empty()
                || route.len() > 64
                || !route
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b))
            {
                return Err(invalid("credential tunnel route token"));
            }
            Ok(Self {
                target: parse_target(target)?,
                route: route.to_string(),
            })
        }
    }

    fn parse_target(text: &str) -> io::Result<Target> {
        if let Ok(addr) = text.parse::<SocketAddr>() {
            if addr.port() == 0 {
                return Err(invalid("credential tunnel target port"));
            }
            return Ok(Target::Addr(addr));
        }
        let (name, port) = text
            .rsplit_once(':')
            .ok_or_else(|| invalid("credential tunnel target is not HOST:PORT"))?;
        let port: u16 = port
            .parse()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| invalid("credential tunnel target port"))?;
        let valid_name = !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid_name {
            return Err(invalid("credential tunnel target name"));
        }
        Ok(Target::Name(name.to_ascii_lowercase(), port))
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_line_round_trips_and_leaves_the_stream_after_it() {
            for (target, route) in [
                ("100.81.17.207:443", "ns:1"),
                ("[fd7a:115c:a1e0::1]:8443", "ns:4026531840"),
                ("api.github.com:443", "px:17"),
            ] {
                let flow = Flow::parse(format!("{target} {route}").as_bytes()).unwrap();
                assert_eq!(flow.target.to_string(), target);
                let mut wire = flow.line().into_bytes();
                wire.extend_from_slice(b"\x16\x03\x01");
                let mut stream = &wire[..];
                assert_eq!(Flow::read(&mut stream).unwrap(), flow);
                assert_eq!(stream, b"\x16\x03\x01");
            }
            assert_eq!(
                Flow::parse(b"Example.COM:443 px:1").unwrap().target.port(),
                443
            );
        }

        #[test]
        fn malformed_lines_are_refused() {
            let long = format!("{} ns:1\n", "a".repeat(MAX_LINE));
            for bad in [
                &b"10.0.0.1:443\n"[..],
                b"10.0.0.1:443 \n",
                b"10.0.0.1 ns:1\n",
                b"10.0.0.1:0 ns:1\n",
                b"bad name:443 ns:1\n",
                b"a..b:443 ns:1\n",
                b"10.0.0.1:443 ns:1 extra\n",
                b"10.0.0.1:443 ns/1\n",
                b"10.0.0.1:443 ns:1",
                long.as_bytes(),
            ] {
                let mut stream = bad;
                assert!(Flow::read(&mut stream).is_err(), "{bad:?}");
            }
        }
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
            let bytes = ep.preamble(dst);
            let mut cursor = std::io::Cursor::new(bytes);
            assert_eq!(ep.read_preamble(&mut cursor).unwrap(), dst);
            assert_eq!(cursor.position() as usize, cursor.get_ref().len());
        }
    }

    #[test]
    fn rejects_wrong_token_and_magic() {
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let bytes = endpoint(1).preamble(dst);
        let err = endpoint(2).read_preamble(&bytes[..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut bad_magic = endpoint(1).preamble(dst);
        bad_magic[0] = b'X';
        let err = endpoint(1).read_preamble(&bad_magic[..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn preamble_len_follows_the_family_byte() {
        let dst4: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let dst6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let p4 = endpoint(1).preamble(dst4);
        let p6 = endpoint(1).preamble(dst6);
        assert_eq!(preamble_len(&p4[..HEADER_LEN]), Some(p4.len()));
        assert_eq!(preamble_len(&p6[..HEADER_LEN]), Some(p6.len()));
        // Too short to hold the family byte, or a family we do not speak.
        assert_eq!(preamble_len(&p4[..HEADER_LEN - 4]), None);
        let mut bad_family = p4.clone();
        bad_family[HEADER_LEN - 3] = 5;
        assert_eq!(preamble_len(&bad_family[..HEADER_LEN]), None);
    }

    #[test]
    fn verdicts_carry_the_connect_outcome() {
        let unreachable: io::Result<()> = Err(io::ErrorKind::HostUnreachable.into());
        assert_eq!(connect_verdict(&Ok::<(), io::Error>(())), VERDICT_CONNECTED);
        assert_eq!(connect_verdict(&unreachable), 113);
        read_verdict(&[VERDICT_CONNECTED][..]).unwrap();
        assert!(read_verdict(&[113u8][..]).is_err());
        assert_eq!(
            read_verdict(&[][..]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
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
