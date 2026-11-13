//! Which host address a published port binds, shared by every publishing path.
//!
//! Published ports are for the host's own clients, so they bind loopback:
//! `127.0.0.1` plus `[::1]` when the host has IPv6. `SMOLVM_PUBLISH_ADDR`
//! widens that for fleet nodes whose ingress proxy connects from another host.
//! A mapping that names its own address (the Docker engine's
//! `-p 0.0.0.0:8080:80`) binds that address instead: the IPv4 wildcard also
//! takes the IPv6 wildcard, any other address only itself.
//!
//! macOS lets an unprivileged process bind a port below 1024 only on the
//! wildcard address, so `-p 80:80` failed with "Permission denied" on a Mac.
//! When the loopback bind is refused that way, the port binds the wildcard
//! address instead and every connection or datagram from a non-loopback peer
//! is dropped, so the port is still reachable from this host only.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};

/// The IPv4 address published ports bind: loopback unless the node widened it.
pub fn publish_addr() -> Ipv4Addr {
    std::env::var("SMOLVM_PUBLISH_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(Ipv4Addr::LOCALHOST)
}

/// The IPv6 companion of an IPv4 publish address.
fn companion_v6(addr: Ipv4Addr) -> Ipv6Addr {
    if addr.is_unspecified() {
        Ipv6Addr::UNSPECIFIED
    } else {
        Ipv6Addr::LOCALHOST
    }
}

/// Whether a peer may use a port bound with `loopback_only`.
pub fn peer_allowed(loopback_only: bool, peer: &SocketAddr) -> bool {
    !loopback_only || is_loopback(peer.ip())
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// The host sockets of one published port: IPv4 is required, IPv6 is
/// best-effort so hosts without IPv6 still publish normally.
#[derive(Debug)]
pub struct BoundSockets<S> {
    /// The IPv4 socket (the only socket of a mapping that names an IPv6
    /// address).
    pub v4: S,
    /// The IPv6 socket, when the host has IPv6.
    pub v6: Option<S>,
    /// True when the sockets are on the wildcard address only because a
    /// loopback bind was refused: non-loopback peers must be dropped.
    pub loopback_only: bool,
}

impl<S> BoundSockets<S> {
    /// Both sockets, IPv4 first.
    pub fn into_sockets(self) -> impl Iterator<Item = S> {
        std::iter::once(self.v4).chain(self.v6)
    }
}

/// Bind the TCP listeners of published host port `port`.
pub fn bind_tcp(port: u16) -> io::Result<BoundSockets<TcpListener>> {
    bind_tcp_on(port, None)
}

/// Bind the TCP listeners of published host port `port` on `listen`, or on
/// the default publish address.
pub fn bind_tcp_on(port: u16, listen: Option<IpAddr>) -> io::Result<BoundSockets<TcpListener>> {
    bind_listen(port, listen, |addr| {
        let socket = new_socket(addr, Type::STREAM, Protocol::TCP)?;
        // The kernel caps this at somaxconn; ask for as much as it allows.
        socket.listen(i32::MAX)?;
        Ok(socket.into())
    })
}

/// Bind the UDP sockets of published host port `port`.
pub fn bind_udp(port: u16) -> io::Result<BoundSockets<UdpSocket>> {
    bind_udp_on(port, None)
}

/// Bind the UDP sockets of published host port `port` on `listen`, or on
/// the default publish address.
pub fn bind_udp_on(port: u16, listen: Option<IpAddr>) -> io::Result<BoundSockets<UdpSocket>> {
    bind_listen(port, listen, |addr| {
        Ok(new_socket(addr, Type::DGRAM, Protocol::UDP)?.into())
    })
}

/// The address a mapping's port is published on, for messages.
pub fn listen_display(listen: Option<IpAddr>) -> String {
    match listen {
        Some(IpAddr::V6(v6)) => format!("[{v6}]"),
        Some(IpAddr::V4(v4)) => v4.to_string(),
        None => publish_addr().to_string(),
    }
}

/// [`bind_with`] for a mapping: the default address keeps its rules, the
/// IPv4 wildcard also takes the IPv6 wildcard (every interface), and any
/// other address binds only itself. A refused loopback bind below 1024 on
/// macOS falls back to the wildcard with non-loopback peers dropped, as the
/// default does.
fn bind_listen<S>(
    port: u16,
    listen: Option<IpAddr>,
    bind: impl Fn(SocketAddr) -> io::Result<S>,
) -> io::Result<BoundSockets<S>> {
    let only = |socket, loopback_only| BoundSockets {
        v4: socket,
        v6: None,
        loopback_only,
    };
    match listen {
        None => bind_with(port, publish_addr(), bind),
        Some(IpAddr::V4(v4)) if v4.is_unspecified() => bind_with(port, v4, bind),
        Some(addr) => match bind(SocketAddr::new(addr, port)) {
            Ok(socket) => Ok(only(socket, false)),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied && addr.is_loopback() => {
                let wildcard = match addr {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                };
                let socket = bind(SocketAddr::new(wildcard, port)).map_err(|_| err)?;
                Ok(only(socket, true))
            }
            Err(err) => Err(err),
        },
    }
}

fn new_socket(addr: SocketAddr, ty: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), ty, Some(protocol))?;
    if addr.is_ipv6() {
        // The IPv4 socket owns IPv4; a dual-stack IPv6 wildcard would collide with it.
        socket.set_only_v6(true)?;
    }
    #[cfg(unix)]
    if ty == Type::STREAM {
        // As std's TcpListener::bind does: a restarted machine can rebind a
        // port whose old connections are still in TIME_WAIT.
        socket.set_reuse_address(true)?;
    }
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// The binding rule, with the socket constructor and publish address passed in
/// so it is testable without privileged ports.
fn bind_with<S>(
    port: u16,
    addr: Ipv4Addr,
    bind: impl Fn(SocketAddr) -> io::Result<S>,
) -> io::Result<BoundSockets<S>> {
    match bind(SocketAddr::from((addr, port))) {
        Ok(v4) => {
            let v6 = bind_v6(&bind, companion_v6(addr), port);
            Ok(BoundSockets {
                v4,
                v6,
                loopback_only: false,
            })
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied && addr.is_loopback() => {
            let v4 = bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).map_err(|_| err)?;
            let v6 = bind_v6(&bind, Ipv6Addr::UNSPECIFIED, port);
            Ok(BoundSockets {
                v4,
                v6,
                loopback_only: true,
            })
        }
        Err(err) => Err(err),
    }
}

fn bind_v6<S>(bind: &impl Fn(SocketAddr) -> io::Result<S>, addr: Ipv6Addr, port: u16) -> Option<S> {
    bind(SocketAddr::from((addr, port)))
        .inspect_err(|err| {
            tracing::debug!(port, error = %err, "skipping IPv6 socket for published port");
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_peers_reach_a_loopback_only_port() {
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let local6: SocketAddr = "[::1]:5000".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5000".parse().unwrap();
        let lan: SocketAddr = "192.168.1.20:5000".parse().unwrap();
        let lan6: SocketAddr = "[fe80::1]:5000".parse().unwrap();
        for peer in [local, local6, mapped] {
            assert!(peer_allowed(true, &peer), "{peer}");
        }
        for peer in [lan, lan6] {
            assert!(!peer_allowed(true, &peer), "{peer}");
            assert!(peer_allowed(false, &peer), "{peer}");
        }
    }

    /// A stand-in for macOS: loopback below 1024 is refused, the wildcard is not.
    fn mac_like(addr: SocketAddr) -> io::Result<SocketAddr> {
        if addr.port() < 1024 && addr.ip().is_loopback() {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        } else {
            Ok(addr)
        }
    }

    #[test]
    fn a_refused_loopback_bind_falls_back_to_the_wildcard_and_filters_peers() {
        let bound = bind_with(80, Ipv4Addr::LOCALHOST, mac_like).unwrap();
        assert_eq!(bound.v4, "0.0.0.0:80".parse().unwrap());
        assert_eq!(bound.v6, Some("[::]:80".parse().unwrap()));
        assert!(bound.loopback_only);
    }

    #[test]
    fn an_allowed_loopback_bind_stays_on_loopback() {
        let bound = bind_with(8080, Ipv4Addr::LOCALHOST, mac_like).unwrap();
        assert_eq!(bound.v4, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(bound.v6, Some("[::1]:8080".parse().unwrap()));
        assert!(!bound.loopback_only);
    }

    #[test]
    fn a_named_address_binds_only_itself() {
        let bound = bind_listen(8080, Some("192.168.1.5".parse().unwrap()), mac_like).unwrap();
        assert_eq!(bound.v4, "192.168.1.5:8080".parse().unwrap());
        assert!(bound.v6.is_none());
        let bound = bind_listen(8080, Some("127.0.0.1".parse().unwrap()), mac_like).unwrap();
        assert_eq!(bound.v4, "127.0.0.1:8080".parse().unwrap());
        assert!(bound.v6.is_none());
        let bound = bind_listen(8080, Some("::1".parse().unwrap()), mac_like).unwrap();
        assert_eq!(bound.v4, "[::1]:8080".parse().unwrap());
        let refused = bind_listen(80, Some("127.0.0.1".parse().unwrap()), mac_like).unwrap();
        assert_eq!(refused.v4, "0.0.0.0:80".parse().unwrap());
        assert!(refused.loopback_only);
    }

    #[test]
    fn the_ipv4_wildcard_listens_on_every_interface() {
        let bound = bind_listen(8080, Some("0.0.0.0".parse().unwrap()), mac_like).unwrap();
        assert_eq!(bound.v4, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(bound.v6, Some("[::]:8080".parse().unwrap()));
    }

    #[test]
    fn a_widened_publish_address_never_filters() {
        let bound = bind_with(80, Ipv4Addr::UNSPECIFIED, mac_like).unwrap();
        assert_eq!(bound.v4, "0.0.0.0:80".parse().unwrap());
        assert_eq!(bound.v6, Some("[::]:80".parse().unwrap()));
        assert!(!bound.loopback_only);
    }

    #[test]
    fn other_errors_and_a_refused_wildcard_keep_the_original_error() {
        let in_use = bind_with(8080, Ipv4Addr::LOCALHOST, |_| -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::AddrInUse))
        })
        .unwrap_err();
        assert_eq!(in_use.kind(), io::ErrorKind::AddrInUse);
        let linux_like = bind_with(80, Ipv4Addr::LOCALHOST, |_| -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(linux_like.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn missing_ipv6_is_not_an_error() {
        let bound = bind_with(8080, Ipv4Addr::LOCALHOST, |addr| {
            if addr.is_ipv6() {
                Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
            } else {
                Ok(addr)
            }
        })
        .unwrap();
        assert!(bound.v6.is_none());
    }

    #[test]
    fn real_sockets_bind_loopback_for_an_unprivileged_port() {
        let tcp = bind_tcp(0).unwrap();
        assert!(tcp.v4.local_addr().unwrap().ip().is_loopback());
        assert!(!tcp.loopback_only);
        let udp = bind_udp(0).unwrap();
        assert!(udp.v4.local_addr().unwrap().ip().is_loopback());
    }
}
