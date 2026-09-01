//! Host-side transport used for guest egress connections.
//!
//! The default transport opens a normal host TCP connection.  The SOCKS5
//! transport instead dials a host-local proxy and performs a CONNECT handshake
//! there.  Nothing is injected into the guest: applications continue to use
//! ordinary sockets and cannot observe the proxy endpoint or credentials.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

const SOCKS_VERSION: u8 = 5;
const SOCKS_CONNECT: u8 = 1;
const SOCKS_UDP_ASSOCIATE: u8 = 3;
const SOCKS_NO_AUTH: u8 = 0;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How the host network stack opens guest-originated egress connections.
///
/// `Socks5` is deliberately fail-closed: an unavailable or rejecting proxy
/// returns an error to the relay and is never retried as a direct connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum HostEgressTransport {
    /// Connect directly using the host network stack.
    #[default]
    Direct,
    /// Connect through a SOCKS5 proxy reachable from the host.
    Socks5(Socks5Proxy),
}

impl HostEgressTransport {
    /// Parse the first supported public configuration form.
    ///
    /// Only an IP literal is accepted for now. Resolving the proxy hostname
    /// through host DNS would undermine the explicit no-direct-DNS contract.
    pub fn parse(value: &str) -> io::Result<Self> {
        let endpoint = value.strip_prefix("socks5://").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "egress proxy must use socks5://",
            )
        })?;
        if endpoint.contains(['/', '?', '#', '@']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "egress proxy must be an unauthenticated socks5://IP:PORT endpoint",
            ));
        }
        let proxy_addr = SocketAddr::from_str(endpoint).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "egress proxy must contain an IP literal and port",
            )
        })?;
        if proxy_addr.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "egress proxy port must be non-zero",
            ));
        }
        Ok(Self::Socks5(Socks5Proxy::new(proxy_addr)))
    }

    /// Whether this transport forbids direct non-TCP egress.
    pub const fn is_proxy_required(&self) -> bool {
        matches!(self, Self::Socks5(_))
    }

    /// Open a host TCP stream for `destination` using the selected transport.
    pub fn connect_tcp(&self, destination: SocketAddr) -> io::Result<TcpStream> {
        match self {
            Self::Direct => TcpStream::connect(destination),
            Self::Socks5(proxy) => proxy.connect(destination),
        }
    }

    /// Exchange one UDP datagram through a SOCKS5 UDP association. This is
    /// used by the DNS relay; it never falls back to a direct host UDP socket.
    pub fn exchange_udp(
        &self,
        destination: SocketAddr,
        payload: &[u8],
        max_response: usize,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        match self {
            Self::Socks5(proxy) => proxy.exchange_udp(destination, payload, max_response, timeout),
            Self::Direct => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxied UDP exchange requires a SOCKS5 egress transport",
            )),
        }
    }
}

/// An unauthenticated host-side SOCKS5 endpoint.
///
/// Authentication of a remote HTTP/SOCKS provider belongs in the host proxy
/// (for example Mihomo). smolvm only talks to its loopback listener and never
/// persists or exposes the remote provider credentials to the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks5Proxy {
    proxy_addr: SocketAddr,
    connect_timeout: Duration,
}

impl Socks5Proxy {
    /// Create a proxy using the default bounded connect/handshake timeout.
    pub const fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(proxy_addr: SocketAddr, connect_timeout: Duration) -> Self {
        Self {
            proxy_addr,
            connect_timeout,
        }
    }

    /// Host endpoint used by the connector.
    pub const fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    fn connect(&self, destination: SocketAddr) -> io::Result<TcpStream> {
        let mut stream = self.negotiate()?;
        write_request(&mut stream, SOCKS_CONNECT, destination)?;
        let _ = read_reply(&mut stream, "CONNECT")?;

        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }

    fn negotiate(&self) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect_timeout(&self.proxy_addr, self.connect_timeout)?;
        stream.set_read_timeout(Some(self.connect_timeout))?;
        stream.set_write_timeout(Some(self.connect_timeout))?;
        stream.write_all(&[SOCKS_VERSION, 1, SOCKS_NO_AUTH])?;
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting)?;
        if greeting != [SOCKS_VERSION, SOCKS_NO_AUTH] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy did not accept no-authentication mode",
            ));
        }
        Ok(stream)
    }

    fn exchange_udp(
        &self,
        destination: SocketAddr,
        payload: &[u8],
        max_response: usize,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        let mut control = self.negotiate()?;
        let wildcard = match self.proxy_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        write_request(&mut control, SOCKS_UDP_ASSOCIATE, wildcard)?;
        let mut relay = read_reply(&mut control, "UDP ASSOCIATE")?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 proxy returned a domain name for its UDP relay address",
            )
        })?;
        if relay.ip().is_unspecified() {
            relay.set_ip(self.proxy_addr.ip());
        }

        let bind = if relay.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.connect(relay)?;

        let mut datagram = Vec::with_capacity(3 + 19 + payload.len());
        datagram.extend_from_slice(&[0, 0, 0]); // RSV, RSV, FRAG (fragmentation unsupported)
        encode_address(&mut datagram, destination);
        datagram.extend_from_slice(payload);
        socket.send(&datagram)?;

        let mut response = vec![0u8; max_response.saturating_add(22)];
        let len = socket.recv(&mut response)?;
        response.truncate(len);
        let payload_offset = parse_udp_header(&response)?;
        let answer = response[payload_offset..].to_vec();
        if answer.len() > max_response {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 UDP response exceeds configured limit",
            ));
        }
        // Keep the TCP control connection alive until the UDP response has
        // been received; dropping it tears down the association by design.
        drop(control);
        Ok(answer)
    }
}

fn write_request(stream: &mut TcpStream, command: u8, destination: SocketAddr) -> io::Result<()> {
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[SOCKS_VERSION, command, 0]);
    encode_address(&mut request, destination);
    stream.write_all(&request)
}

fn encode_address(buffer: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            buffer.push(1);
            buffer.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buffer.push(4);
            buffer.extend_from_slice(&ip.octets());
        }
    }
    buffer.extend_from_slice(&address.port().to_be_bytes());
}

fn read_reply(stream: &mut TcpStream, operation: &str) -> io::Result<Option<SocketAddr>> {
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply)?;
    if reply[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 response version",
        ));
    }
    if reply[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 {operation} failed with reply code {}", reply[1]),
        ));
    }
    let ip = match reply[3] {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            IpAddr::V4(octets.into())
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets)?;
            IpAddr::V6(octets.into())
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut domain = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut domain)?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port)?;
            return Ok(None);
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 bound-address type",
            ))
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    Ok(Some(SocketAddr::new(ip, u16::from_be_bytes(port))))
}

fn parse_udp_header(datagram: &[u8]) -> io::Result<usize> {
    if datagram.len() < 4 || datagram[0..2] != [0, 0] || datagram[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or fragmented SOCKS5 UDP response",
        ));
    }
    let address_len = match datagram[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = *datagram.get(4).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "short SOCKS5 UDP response")
            })? as usize;
            1 + len
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 UDP address type",
            ))
        }
    };
    let offset = 4usize.saturating_add(address_len).saturating_add(2);
    if offset > datagram.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short SOCKS5 UDP response",
        ));
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    fn read_request(stream: &mut TcpStream) -> (u8, SocketAddr) {
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);
        stream.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).unwrap();

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], SOCKS_VERSION);
        assert_eq!(header[2], 0);
        let ip = match header[3] {
            1 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).unwrap();
                IpAddr::V4(octets.into())
            }
            4 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).unwrap();
                IpAddr::V6(octets.into())
            }
            other => panic!("unexpected address type {other}"),
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).unwrap();
        (header[1], SocketAddr::new(ip, u16::from_be_bytes(port)))
    }

    #[test]
    fn parses_loopback_proxy_url() {
        let transport = HostEgressTransport::parse("socks5://127.0.0.1:7891").unwrap();
        assert_eq!(
            transport,
            HostEgressTransport::Socks5(Socks5Proxy::new("127.0.0.1:7891".parse().unwrap()))
        );
    }

    #[test]
    fn rejects_credentials_and_hostnames() {
        assert!(HostEgressTransport::parse("socks5://user:pass@127.0.0.1:7891").is_err());
        assert!(HostEgressTransport::parse("socks5://localhost:7891").is_err());
        assert!(HostEgressTransport::parse("http://127.0.0.1:7891").is_err());
        assert!(HostEgressTransport::parse("socks5://127.0.0.1:0").is_err());
    }

    #[test]
    fn socks5_connect_encodes_destination_and_returns_aligned_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let destination: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read_request(&mut stream), (SOCKS_CONNECT, destination));
            stream
                .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .unwrap();
            stream.write_all(b"ready").unwrap();
        });

        let proxy = Socks5Proxy::with_timeout(proxy_addr, Duration::from_secs(2));
        let mut stream = proxy.connect(destination).unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ready");
        server.join().unwrap();
    }

    #[test]
    fn socks5_udp_associate_encapsulates_and_returns_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let udp_relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = udp_relay.local_addr().unwrap();
        let destination: SocketAddr = "203.0.113.53:53".parse().unwrap();

        let server = thread::spawn(move || {
            let (mut control, _) = listener.accept().unwrap();
            assert_eq!(
                read_request(&mut control),
                (
                    SOCKS_UDP_ASSOCIATE,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                )
            );
            let mut reply = vec![SOCKS_VERSION, 0, 0];
            encode_address(&mut reply, relay_addr);
            control.write_all(&reply).unwrap();

            let mut datagram = [0u8; 512];
            let (len, peer) = udp_relay.recv_from(&mut datagram).unwrap();
            let payload_offset = parse_udp_header(&datagram[..len]).unwrap();
            assert_eq!(
                &datagram[..payload_offset],
                &[0, 0, 0, 1, 203, 0, 113, 53, 0, 53]
            );
            assert_eq!(&datagram[payload_offset..len], b"dns-query");

            let mut response = vec![0, 0, 0];
            encode_address(&mut response, destination);
            response.extend_from_slice(b"dns-answer");
            udp_relay.send_to(&response, peer).unwrap();
        });

        let transport = HostEgressTransport::Socks5(Socks5Proxy::with_timeout(
            proxy_addr,
            Duration::from_secs(2),
        ));
        let answer = transport
            .exchange_udp(destination, b"dns-query", 512, Duration::from_secs(2))
            .unwrap();
        assert_eq!(answer, b"dns-answer");
        server.join().unwrap();
    }

    #[test]
    fn direct_transport_rejects_proxied_udp_exchange() {
        assert!(HostEgressTransport::Direct
            .exchange_udp(
                "203.0.113.53:53".parse().unwrap(),
                b"query",
                512,
                Duration::from_millis(10),
            )
            .is_err());
    }

    #[test]
    fn proxy_failure_never_falls_back_to_destination() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        destination_listener.set_nonblocking(true).unwrap();
        let destination = destination_listener.local_addr().unwrap();

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = proxy_listener.accept().unwrap();
            drop(stream);
        });

        let transport = HostEgressTransport::Socks5(Socks5Proxy::with_timeout(
            proxy_addr,
            Duration::from_secs(2),
        ));
        assert!(transport.connect_tcp(destination).is_err());
        assert_eq!(
            destination_listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        server.join().unwrap();
    }
}
