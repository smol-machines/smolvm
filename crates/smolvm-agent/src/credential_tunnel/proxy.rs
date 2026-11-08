//! The front the tunnel puts before a local proxy (Tailscale's userspace
//! SOCKS5 and HTTP proxies). The proxy sends what it is asked to through its
//! own network stack, out encrypted, so a `CONNECT` to port 443 is handed to
//! the interceptor instead; every other request goes to the proxy unchanged.
//!
//! The front speaks to the real proxy for the client, so authentication and
//! the proxy's own answer reach the client as they would have. For an
//! intercepted `CONNECT` it keeps what it needs to ask the proxy again
//! (greeting, credentials, request), because the interceptor may open more
//! than one upstream connection for one client connection.

use smolvm_protocol::intercept::tunnel::Target;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};

/// Longest HTTP request or response head the front reads.
const MAX_HEAD: usize = 16 * 1024;
const HTTPS: u16 = 443;

/// How to ask the proxy for a connection again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replay {
    Socks5 {
        /// The client's greeting.
        greeting: Vec<u8>,
        /// Its username/password sub-negotiation, when the proxy chose it.
        auth: Option<Vec<u8>>,
        /// Its `CONNECT` request.
        request: Vec<u8>,
    },
    /// The client's whole `CONNECT` request head.
    HttpConnect(Vec<u8>),
}

/// What the front decided for one client connection.
pub enum Decision {
    /// Hand the client to the interceptor: its target, how to ask the proxy
    /// again, and bytes the client already sent past its request.
    Intercept {
        target: Target,
        replay: Replay,
        early: Vec<u8>,
    },
    /// Done: the front relayed the client to the proxy itself.
    Relayed,
}

/// Serve one client of the local listener `upstream` is connected to.
///
/// Whoever speaks first decides: a proxy's client always does, so a listener
/// that greets first (a server-first protocol on a forwarded port, say) is
/// relayed untouched, as is any client that does not open with a SOCKS5
/// greeting or an HTTP `CONNECT`.
pub fn front(client: TcpStream, upstream: TcpStream) -> io::Result<(TcpStream, Decision)> {
    use std::os::fd::AsRawFd;
    let mut fds = [
        libc::pollfd {
            fd: client.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: upstream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: poll on two descriptors this function holds.
    if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let client_first = fds[0].revents != 0 && fds[1].revents == 0;
    if client_first {
        let mut first = [0u8; 8];
        let peeked = client.peek(&mut first)?;
        if peeked >= 1 && first[0] == 0x05 {
            return socks5(client, upstream);
        }
        if peeked >= 1 && first[0] == b'C' {
            // Wait, briefly, for enough of an HTTP method to tell CONNECT.
            client.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            let peeked = peek_exact(&client, &mut first);
            client.set_read_timeout(None)?;
            if peeked? == first.len() && &first == b"CONNECT " {
                return http_connect(client, upstream);
            }
        }
    }
    relay(client.try_clone()?, upstream)?;
    Ok((client, Decision::Relayed))
}

fn peek_exact(client: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    // SAFETY: recv into a caller-owned buffer; MSG_PEEK leaves the bytes queued.
    let n = unsafe {
        libc::recv(
            client.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_PEEK | libc::MSG_WAITALL,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn read_n(stream: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a SOCKS5 address (after its type byte) and port.
fn socks_address(stream: &mut impl Read, atyp: u8, out: &mut Vec<u8>) -> io::Result<Target> {
    let host = match atyp {
        1 => {
            let a = read_n(stream, 4)?;
            out.extend_from_slice(&a);
            Host::Ip(IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])))
        }
        4 => {
            let a = read_n(stream, 16)?;
            out.extend_from_slice(&a);
            Host::Ip(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(a).unwrap())))
        }
        3 => {
            let len = read_n(stream, 1)?;
            let name = read_n(stream, len[0] as usize)?;
            out.extend_from_slice(&len);
            out.extend_from_slice(&name);
            Host::Name(String::from_utf8_lossy(&name).into_owned())
        }
        _ => return Err(invalid("SOCKS5 address type")),
    };
    let port = read_n(stream, 2)?;
    out.extend_from_slice(&port);
    Ok(host.with_port(u16::from_be_bytes([port[0], port[1]])))
}

enum Host {
    Ip(IpAddr),
    Name(String),
}

impl Host {
    fn with_port(self, port: u16) -> Target {
        match self {
            Host::Ip(ip) => Target::Addr(SocketAddr::new(ip, port)),
            Host::Name(name) => match name.parse::<IpAddr>() {
                Ok(ip) => Target::Addr(SocketAddr::new(ip, port)),
                Err(_) => Target::Name(name.to_ascii_lowercase(), port),
            },
        }
    }
}

fn socks5(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<(TcpStream, Decision)> {
    // Greeting: VER NMETHODS METHODS…
    let mut greeting = read_n(&mut client, 2)?;
    greeting.extend(read_n(&mut client, greeting[1] as usize)?);
    upstream.write_all(&greeting)?;
    let choice = read_n(&mut upstream, 2)?;
    client.write_all(&choice)?;
    let mut auth = None;
    match choice[1] {
        0x00 => {}
        0x02 => {
            // RFC 1929: VER ULEN UNAME PLEN PASSWD
            let mut sub = read_n(&mut client, 2)?;
            sub.extend(read_n(&mut client, sub[1] as usize)?);
            let plen = read_n(&mut client, 1)?;
            sub.extend_from_slice(&plen);
            sub.extend(read_n(&mut client, plen[0] as usize)?);
            upstream.write_all(&sub)?;
            let status = read_n(&mut upstream, 2)?;
            client.write_all(&status)?;
            if status[1] != 0 {
                return Ok((client, Decision::Relayed));
            }
            auth = Some(sub);
        }
        // No acceptable method, or one the front cannot replay: relay as is.
        _ => {
            relay(client.try_clone()?, upstream)?;
            return Ok((client, Decision::Relayed));
        }
    }
    // Request: VER CMD RSV ATYP ADDR PORT
    let mut request = read_n(&mut client, 4)?;
    let atyp = request[3];
    let target = socks_address(&mut client, atyp, &mut request)?;
    const CONNECT: u8 = 1;
    if request[1] != CONNECT || target.port() != HTTPS {
        upstream.write_all(&request)?;
        relay(client.try_clone()?, upstream)?;
        return Ok((client, Decision::Relayed));
    }
    // Ask the proxy once so the client gets its real answer, then let the
    // interceptor open the upstream connections it needs.
    upstream.write_all(&request)?;
    let reply = socks_reply(&mut upstream)?;
    client.write_all(&reply)?;
    if reply[1] != 0 {
        return Ok((client, Decision::Relayed));
    }
    drop(upstream);
    Ok((
        client,
        Decision::Intercept {
            target,
            replay: Replay::Socks5 {
                greeting,
                auth,
                request,
            },
            early: Vec::new(),
        },
    ))
}

/// Read a SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT.
fn socks_reply(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut reply = read_n(stream, 4)?;
    let atyp = reply[3];
    socks_address(stream, atyp, &mut reply)?;
    Ok(reply)
}

/// Read up to and including the blank line ending an HTTP head; bytes read
/// past it are returned too.
fn read_head(stream: &mut impl Read) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(invalid("HTTP head too long"));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The target of `CONNECT authority HTTP/1.x`.
fn connect_target(head: &[u8]) -> io::Result<Target> {
    let line = head
        .split(|&b| b == b'\r')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .ok_or_else(|| invalid("CONNECT request line"))?;
    let mut parts = line.split(' ');
    let (Some("CONNECT"), Some(authority), Some(version)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("CONNECT request line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(invalid("CONNECT version"));
    }
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok(Target::Addr(addr));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| invalid("CONNECT authority"))?;
    let port = port.parse().map_err(|_| invalid("CONNECT port"))?;
    Ok(Host::Name(host.to_string()).with_port(port))
}

fn http_status_ok(head: &[u8]) -> bool {
    // "HTTP/1.1 200 …"
    head.split(|&b| b == b' ')
        .nth(1)
        .is_some_and(|code| code.len() == 3 && code[0] == b'2')
}

fn http_connect(
    mut client: TcpStream,
    mut upstream: TcpStream,
) -> io::Result<(TcpStream, Decision)> {
    let (head, early) = read_head(&mut client)?;
    let target = match connect_target(&head) {
        Ok(target) if target.port() == HTTPS => target,
        _ => {
            upstream.write_all(&head)?;
            upstream.write_all(&early)?;
            relay(client.try_clone()?, upstream)?;
            return Ok((client, Decision::Relayed));
        }
    };
    upstream.write_all(&head)?;
    let (response, _) = read_head(&mut upstream)?;
    client.write_all(&response)?;
    if !http_status_ok(&response) {
        return Ok((client, Decision::Relayed));
    }
    drop(upstream);
    Ok((
        client,
        Decision::Intercept {
            target,
            replay: Replay::HttpConnect(head),
            early,
        },
    ))
}

/// Ask the proxy for the connection again on `upstream`, a fresh connection
/// to it, and leave the stream at the target's first byte.
pub fn replay(upstream: &mut TcpStream, replay: &Replay) -> io::Result<()> {
    match replay {
        Replay::Socks5 {
            greeting,
            auth,
            request,
        } => {
            upstream.write_all(greeting)?;
            let choice = read_n(upstream, 2)?;
            match (choice[1], auth) {
                (0x00, _) => {}
                (0x02, Some(auth)) => {
                    upstream.write_all(auth)?;
                    if read_n(upstream, 2)?[1] != 0 {
                        return Err(refused("the proxy refused the credentials"));
                    }
                }
                _ => return Err(refused("the proxy chose another method")),
            }
            upstream.write_all(request)?;
            if socks_reply(upstream)?[1] != 0 {
                return Err(refused("the proxy refused the connection"));
            }
        }
        Replay::HttpConnect(head) => {
            upstream.write_all(head)?;
            let (response, rest) = read_head(upstream)?;
            if !http_status_ok(&response) || !rest.is_empty() {
                return Err(refused("the proxy refused the connection"));
            }
        }
    }
    Ok(())
}

fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    crate::relay::relay_half_close(client, upstream)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn refused(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_targets_name_addresses_and_ports() {
        let head = b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n";
        assert_eq!(
            connect_target(head).unwrap(),
            Target::Name("api.github.com".into(), 443)
        );
        assert_eq!(
            connect_target(b"CONNECT [fd7a::1]:443 HTTP/1.1\r\n\r\n").unwrap(),
            Target::Addr("[fd7a::1]:443".parse().unwrap())
        );
        assert_eq!(
            connect_target(b"CONNECT 100.64.0.7:8443 HTTP/1.0\r\n\r\n").unwrap(),
            Target::Addr("100.64.0.7:8443".parse().unwrap())
        );
        assert!(connect_target(b"GET http://x/ HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn socks_addresses_of_every_type_parse_and_are_kept_for_replay() {
        for (atyp, wire, want) in [
            (1u8, vec![10, 0, 0, 1, 1, 187], "10.0.0.1:443"),
            (
                3,
                [&[7u8][..], b"Example", &[1, 187]].concat(),
                "example:443",
            ),
        ] {
            let mut kept = Vec::new();
            let target = socks_address(&mut &wire[..], atyp, &mut kept).unwrap();
            assert_eq!(target.to_string(), want);
            assert_eq!(kept, wire);
        }
    }

    #[test]
    fn a_head_is_split_from_what_follows_it() {
        let wire = b"CONNECT a:443 HTTP/1.1\r\n\r\n\x16\x03\x01";
        let (head, rest) = read_head(&mut &wire[..]).unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(rest, b"\x16\x03\x01");
        assert!(http_status_ok(
            b"HTTP/1.1 200 Connection established\r\n\r\n"
        ));
        assert!(!http_status_ok(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
        ));
    }
}
