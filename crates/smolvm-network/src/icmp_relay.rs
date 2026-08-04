//! ICMP echo (ping) relay for the virtio-net backend.
//!
//! Context
//! =======
//!
//! TCP, UDP, and DNS all reach the outside world through the gateway, but a
//! guest `ping` had nowhere to go: nothing on the host answered ICMP, so echo
//! requests were silently dropped (the same gap TSI has — its syscall hijack
//! only covers stream/datagram sockets, never ICMP). This module closes it by
//! relaying guest echo requests to real host ICMP datagram sockets and feeding
//! the real replies back, so `ping` measures actual reachability.
//!
//! Model — a userspace NAT for echo, built entirely on smoltcp sockets so no
//! Ethernet/IP frames are assembled by hand:
//!
//! ```text
//! guest echo request to D
//!   -> normal smoltcp ingress; a raw::Socket(ICMP) captures the full IP packet
//!   -> poll loop parses (guest, D, ident, seq, data); egress check
//!   -> channels it to the relay thread
//!   -> relay thread: one connected host ICMP socket per (guest, D, ident); send
//!   -> reply: host socket readable -> channel back -> relay_wake
//!   -> poll loop builds an echo *reply* IP packet sourced from D and sends it
//!      out the raw::Socket; smoltcp frames it and delivers it to the guest
//! ```
//!
//! Sourcing the reply from `D` (not the gateway) is the whole point: `ping`
//! rejects replies whose source isn't the address it targeted. smoltcp's
//! `icmp::Socket` can't do that (its TX path picks the interface's own source
//! address), so the relay sends a fully-addressed packet out a `raw::Socket`
//! instead — smoltcp still owns the Ethernet header and neighbor resolution.
//!
//! Echo is connectionless, so lifetime is NAT-style idle expiry: the relay
//! drops host sockets idle for [`FLOW_IDLE_TIMEOUT`]. Loss under pressure (full
//! channels / tables) is acceptable ICMP semantics — logged, never blocking.

use crate::egress::EgressPolicy;
use crate::queues::WakePipe;
use crate::virtio_net_log;
use polling::{Event, Events};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr,
    Ipv6Packet, Ipv6Repr,
};
use socket2::{Domain, Protocol, SockAddr, Socket as HostSocket, Type};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Max in-flight echo messages per direction before drops (ICMP may drop).
const CHANNEL_CAPACITY: usize = 256;
/// Max concurrent (guest, destination, ident) flows with live host sockets.
const MAX_FLOWS: usize = 256;
/// Largest ICMP message (type byte through payload) we relay; the guest's MTU
/// bounds requests anyway and replies mirror them.
const MAX_ICMP_BYTES: usize = 1500;
/// Default IP hop limit for relayed echo replies.
const REPLY_HOP_LIMIT: u8 = 64;
/// ICMPv4 echo-request / echo-reply type bytes.
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
/// ICMPv6 echo-request / echo-reply type bytes.
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
/// Drop a flow's host socket after this much inactivity.
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Relay thread poll ceiling, so shutdown and expiry are noticed promptly.
const RELAY_POLL_MAX_MS: i32 = 1000;

/// One relayed echo message, in either direction.
///
/// On egress it is the guest's decoded echo request; on ingress it is the host
/// reply with the guest's original `ident` restored (the host kernel rewrites
/// the on-wire identifier to its own port, so the relay stamps it back).
pub struct IcmpEcho {
    /// Guest address (echo source on egress, reply target on ingress).
    pub guest: IpAddr,
    /// External destination the guest pinged (and replies come from).
    pub destination: IpAddr,
    /// ICMP echo identifier the guest chose.
    pub ident: u16,
    /// ICMP echo sequence number.
    pub seq: u16,
    /// Echo payload, mirrored unchanged between request and reply.
    pub data: Vec<u8>,
}

/// Channel pair connecting the poll loop and the relay thread.
pub struct IcmpRelayChannels {
    /// Poll loop -> relay thread.
    pub to_relay: SyncSender<IcmpEcho>,
    /// Relay thread -> poll loop.
    pub from_relay: Receiver<IcmpEcho>,
    /// Wakes the relay thread after `to_relay` sends.
    pub relay_thread_wake: WakePipe,
}

/// Start the ICMP relay thread. Returns the poll-loop-side channel endpoints.
///
/// `reply_wake` is the smoltcp poll loop's existing relay wake pipe — pulsed
/// whenever a reply is queued so the loop wakes to deliver it to the guest.
/// The thread exits when `shutdown` reports true (checked at least once per
/// [`RELAY_POLL_MAX_MS`]).
pub fn start_icmp_relay(
    reply_wake: Arc<WakePipe>,
    shutdown: Arc<dyn Fn() -> bool + Send + Sync>,
) -> IcmpRelayChannels {
    let (to_relay_tx, to_relay_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let (from_relay_tx, from_relay_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let relay_thread_wake = WakePipe::new();
    let thread_wake = relay_thread_wake.clone();

    let _ = thread::Builder::new()
        .name("smolvm-icmp-relay".into())
        .spawn(move || {
            run_icmp_relay(
                to_relay_rx,
                from_relay_tx,
                thread_wake,
                reply_wake,
                shutdown,
            );
        });

    IcmpRelayChannels {
        to_relay: to_relay_tx,
        from_relay: from_relay_rx,
        relay_thread_wake,
    }
}

/// Relay-thread state for one (guest, destination, ident) echo flow.
struct IcmpFlow {
    socket: HostSocket,
    guest: IpAddr,
    destination: IpAddr,
    ident: u16,
    last_active: Instant,
}

fn run_icmp_relay(
    outbound: Receiver<IcmpEcho>,
    inbound: SyncSender<IcmpEcho>,
    wake: WakePipe,
    reply_wake: Arc<WakePipe>,
    shutdown: Arc<dyn Fn() -> bool + Send + Sync>,
) {
    let mut flows: HashMap<(IpAddr, IpAddr, u16), IcmpFlow> = HashMap::new();
    let mut recv_buf = [MaybeUninit::<u8>::uninit(); MAX_ICMP_BYTES];
    // The host ICMP socket may be denied (Linux `ping_group_range`, no
    // privileges); log that once rather than on every dropped ping.
    let mut warned_socket_error = false;

    loop {
        if shutdown() {
            return;
        }

        // Outbound: echo requests handed over by the poll loop.
        loop {
            match outbound.try_recv() {
                Ok(echo) => {
                    let key = (echo.guest, echo.destination, echo.ident);
                    if !flows.contains_key(&key) {
                        if flows.len() >= MAX_FLOWS {
                            virtio_net_log!(
                                "virtio-net: dropping ICMP echo {} -> {} (flow table full)",
                                echo.guest,
                                echo.destination
                            );
                            continue;
                        }
                        match create_flow_socket(echo.destination) {
                            Ok(socket) => {
                                flows.insert(
                                    key,
                                    IcmpFlow {
                                        socket,
                                        guest: echo.guest,
                                        destination: echo.destination,
                                        ident: echo.ident,
                                        last_active: Instant::now(),
                                    },
                                );
                            }
                            Err(err) => {
                                if !warned_socket_error {
                                    virtio_net_log!(
                                        "virtio-net: cannot open host ICMP socket for {} (ping disabled): {}",
                                        echo.destination,
                                        err
                                    );
                                    warned_socket_error = true;
                                }
                                continue;
                            }
                        }
                    }
                    let flow = flows.get_mut(&key).expect("flow inserted above");
                    flow.last_active = Instant::now();
                    // Best-effort send; ICMP loss is allowed.
                    let request = echo_request_bytes(echo.destination, echo.seq, &echo.data);
                    let _ = flow.socket.send(&request);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }

        // Inbound: poll all flow sockets for replies. The wake's poller blocks
        // on "wake OR any flow socket readable" in a single call; the wake is a
        // notify (no key), and each flow socket is registered at key `slot + 1`.
        let poller = wake.poller();
        let keys: Vec<(IpAddr, IpAddr, u16)> = flows.keys().copied().collect();
        for (slot, key) in keys.iter().enumerate() {
            // SAFETY: the socket is owned by `flows` and is deleted from the
            // poller below before the next iteration may drop it.
            let _ = unsafe { poller.add(&flows[key].socket, Event::readable(slot + 1)) };
        }

        let mut events = Events::new();
        let _ = poller.wait(
            &mut events,
            Some(Duration::from_millis(RELAY_POLL_MAX_MS as u64)),
        );

        // A pending notify is consumed by `wait`; nothing else to drain.
        let mut ready: Vec<bool> = vec![false; keys.len()];
        for event in events.iter() {
            if event.key >= 1 && event.key - 1 < ready.len() {
                ready[event.key - 1] = true;
            }
        }

        // Deregister sockets before the next rebuild so a closed flow's socket
        // is never left registered on the poller.
        for key in &keys {
            let _ = poller.delete(&flows[key].socket);
        }

        let mut woke_reply = false;
        for (slot, key) in keys.iter().enumerate() {
            if !ready[slot] {
                continue;
            }
            let Some(flow) = flows.get_mut(key) else {
                continue;
            };
            // Drain everything ready on this socket. WouldBlock ends the drain;
            // errors (an ICMP error surfaced on the connected socket) just mean
            // this flow is quiet — idle expiry reaps it.
            while let Ok(len) = flow.socket.recv(&mut recv_buf) {
                // SAFETY: `recv` reports `len` initialized leading bytes.
                let bytes =
                    unsafe { &*(&recv_buf[..len] as *const [MaybeUninit<u8>] as *const [u8]) };
                let Some((seq, data)) = parse_echo_reply(flow.destination, bytes) else {
                    continue;
                };
                flow.last_active = Instant::now();
                let reply = IcmpEcho {
                    guest: flow.guest,
                    destination: flow.destination,
                    ident: flow.ident,
                    seq,
                    data,
                };
                match inbound.try_send(reply) {
                    Ok(()) => woke_reply = true,
                    Err(TrySendError::Full(_)) => {
                        virtio_net_log!(
                            "virtio-net: dropping ICMP reply for {} (inbound queue full)",
                            flow.guest
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
        }
        if woke_reply {
            reply_wake.wake();
        }

        // NAT-style idle expiry.
        let now = Instant::now();
        flows.retain(|_, flow| now.duration_since(flow.last_active) < FLOW_IDLE_TIMEOUT);
    }
}

/// Open a non-blocking host ICMP datagram socket connected to `destination`.
///
/// Uses unprivileged ICMP datagram sockets (`SOCK_DGRAM`/`IPPROTO_ICMP[V6]`),
/// the same mechanism `ping` uses on Linux (gated by `net.ipv4.ping_group_range`)
/// and macOS. `connect` pins the peer so the kernel filters stray ICMP from
/// other hosts — each flow is its own NAT pinhole.
fn create_flow_socket(destination: IpAddr) -> std::io::Result<HostSocket> {
    let (domain, protocol) = match destination {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
    };
    let socket = HostSocket::new(domain, Type::DGRAM, Some(protocol))?;
    // ICMP has no ports; the kernel ignores the port on connect.
    socket.connect(&SockAddr::from(SocketAddr::new(destination, 0)))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Build the raw ICMP echo-request bytes (type byte through payload) sent to a
/// host ping socket. The kernel overwrites the identifier with the socket's
/// port and fills the checksum, so both are left zero here.
fn echo_request_bytes(destination: IpAddr, seq: u16, data: &[u8]) -> Vec<u8> {
    let type_byte = if destination.is_ipv6() {
        ICMPV6_ECHO_REQUEST
    } else {
        ICMPV4_ECHO_REQUEST
    };
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.push(type_byte);
    buf.push(0); // code
    buf.extend_from_slice(&[0, 0]); // checksum (kernel fills)
    buf.extend_from_slice(&[0, 0]); // identifier (kernel overwrites)
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Decode a host ping socket's reply (an ICMP message, no IP header) into the
/// echo `(seq, data)`. The identifier is dropped — the relay restores the
/// guest's own. Returns `None` for anything that isn't an echo reply (e.g. an
/// ICMP error the kernel surfaced on the socket).
fn parse_echo_reply(destination: IpAddr, bytes: &[u8]) -> Option<(u16, Vec<u8>)> {
    if bytes.len() < 8 {
        return None;
    }
    let expected = if destination.is_ipv6() {
        ICMPV6_ECHO_REPLY
    } else {
        ICMPV4_ECHO_REPLY
    };
    if bytes[0] != expected {
        return None;
    }
    let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
    Some((seq, bytes[8..].to_vec()))
}

/// Whether the gateway should relay a guest echo (portless, so any-port policy).
pub fn should_relay_icmp(destination: IpAddr, egress: &EgressPolicy) -> bool {
    // ICMP echo carries no port, so only any-port allow rules cover it.
    egress.allows(destination, None)
}

/// Decode a guest IPv4 ICMP echo *request* captured off the raw socket (a full
/// IP packet) into a relayable [`IcmpEcho`]. Non-echo ICMP returns `None`.
pub fn parse_guest_echo_v4(ip_packet: &[u8]) -> Option<IcmpEcho> {
    let ipv4 = Ipv4Packet::new_checked(ip_packet).ok()?;
    let icmp = Icmpv4Packet::new_checked(ipv4.payload()).ok()?;
    match Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::ignored()).ok()? {
        Icmpv4Repr::EchoRequest {
            ident,
            seq_no,
            data,
        } => Some(IcmpEcho {
            guest: IpAddr::V4(ipv4.src_addr()),
            destination: IpAddr::V4(ipv4.dst_addr()),
            ident,
            seq: seq_no,
            data: data.to_vec(),
        }),
        _ => None,
    }
}

/// IPv6 counterpart of [`parse_guest_echo_v4`].
pub fn parse_guest_echo_v6(ip_packet: &[u8]) -> Option<IcmpEcho> {
    let ipv6 = Ipv6Packet::new_checked(ip_packet).ok()?;
    let src = ipv6.src_addr();
    let dst = ipv6.dst_addr();
    let icmp = Icmpv6Packet::new_checked(ipv6.payload()).ok()?;
    match Icmpv6Repr::parse(&src, &dst, &icmp, &ChecksumCapabilities::ignored()).ok()? {
        Icmpv6Repr::EchoRequest {
            ident,
            seq_no,
            data,
        } => Some(IcmpEcho {
            guest: IpAddr::V6(src),
            destination: IpAddr::V6(dst),
            ident,
            seq: seq_no,
            data: data.to_vec(),
        }),
        _ => None,
    }
}

/// Build the IPv4 echo-*reply* packet (IP header + ICMP) to hand to the raw
/// socket. Sourced from `reply.destination` so the guest's `ping` accepts it.
pub fn build_echo_reply_v4(reply: &IcmpEcho) -> Option<Vec<u8>> {
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (reply.destination, reply.guest) else {
        return None;
    };
    let icmp = Icmpv4Repr::EchoReply {
        ident: reply.ident,
        seq_no: reply.seq,
        data: &reply.data,
    };
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: REPLY_HOP_LIMIT,
    };
    let mut buf = vec![0u8; ip.buffer_len() + icmp.buffer_len()];
    let checksum = ChecksumCapabilities::default();
    ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &checksum);
    icmp.emit(
        &mut Icmpv4Packet::new_unchecked(&mut buf[ip.buffer_len()..]),
        &checksum,
    );
    Some(buf)
}

/// IPv6 counterpart of [`build_echo_reply_v4`].
pub fn build_echo_reply_v6(reply: &IcmpEcho) -> Option<Vec<u8>> {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (reply.destination, reply.guest) else {
        return None;
    };
    let icmp = Icmpv6Repr::EchoReply {
        ident: reply.ident,
        seq_no: reply.seq,
        data: &reply.data,
    };
    let ip = Ipv6Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp.buffer_len(),
        hop_limit: REPLY_HOP_LIMIT,
    };
    let mut buf = vec![0u8; ip.buffer_len() + icmp.buffer_len()];
    ip.emit(&mut Ipv6Packet::new_unchecked(&mut buf[..]));
    icmp.emit(
        &src,
        &dst,
        &mut Icmpv6Packet::new_unchecked(&mut buf[ip.buffer_len()..]),
        &ChecksumCapabilities::default(),
    );
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn relay_thread_round_trips_an_echo_via_loopback() {
        // Unprivileged ICMP sockets are gated by `net.ipv4.ping_group_range`;
        // skip rather than fail where they aren't permitted (e.g. locked-down CI).
        if create_flow_socket(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_err() {
            eprintln!("skipping: unprivileged ICMP datagram sockets not permitted here");
            return;
        }

        let reply_wake = Arc::new(WakePipe::new());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let channels = start_icmp_relay(
            reply_wake.clone(),
            Arc::new(move || stop_flag.load(Ordering::Relaxed)),
        );

        let guest = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2));
        let destination = IpAddr::V4(Ipv4Addr::LOCALHOST);
        channels
            .to_relay
            .send(IcmpEcho {
                guest,
                destination,
                ident: 0x4321,
                seq: 9,
                data: b"relaytest".to_vec(),
            })
            .unwrap();
        channels.relay_thread_wake.wake();

        // The loopback kernel answers the echo; the relay restores our ident.
        let reply = channels
            .from_relay
            .recv_timeout(Duration::from_secs(3))
            .expect("expected an echo reply from loopback");
        assert_eq!(reply.guest, guest);
        assert_eq!(reply.destination, destination);
        assert_eq!(reply.ident, 0x4321);
        assert_eq!(reply.seq, 9);
        assert_eq!(reply.data, b"relaytest");

        stop.store(true, Ordering::Relaxed);
        channels.relay_thread_wake.wake();
    }

    #[test]
    fn echo_request_carries_seq_and_payload() {
        let bytes = echo_request_bytes(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 0x0042, b"ping");
        assert_eq!(bytes[0], ICMPV4_ECHO_REQUEST);
        assert_eq!(&bytes[6..8], &[0x00, 0x42]); // sequence
        assert_eq!(&bytes[8..], b"ping");
    }

    #[test]
    fn echo_request_uses_v6_type_for_v6_destination() {
        let bytes = echo_request_bytes(IpAddr::V6(Ipv6Addr::LOCALHOST), 1, b"");
        assert_eq!(bytes[0], ICMPV6_ECHO_REQUEST);
    }

    #[test]
    fn parse_reply_extracts_seq_and_data_ignoring_ident() {
        // type=0, code=0, cksum, ident=0xdead (host port), seq=0x0042, data.
        let reply = [0u8, 0, 0, 0, 0xde, 0xad, 0x00, 0x42, b'h', b'i'];
        let (seq, data) = parse_echo_reply(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), &reply).unwrap();
        assert_eq!(seq, 0x0042);
        assert_eq!(data, b"hi");
    }

    #[test]
    fn parse_reply_rejects_non_echo_reply() {
        // type=3 (destination unreachable) is not an echo reply.
        let err = [3u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_echo_reply(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), &err).is_none());
    }

    #[test]
    fn round_trips_guest_echo_through_reply_v4() {
        // Build a guest echo request IP packet, parse it, build the reply, and
        // confirm the reply mirrors ident/seq/data and swaps src/dst.
        let request = IcmpEcho {
            guest: IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)),
            destination: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ident: 0x1234,
            seq: 7,
            data: b"abcdefgh".to_vec(),
        };
        // Emit a request packet the way a guest would, then parse it back.
        let icmp = Icmpv4Repr::EchoRequest {
            ident: request.ident,
            seq_no: request.seq,
            data: &request.data,
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Addr::new(100, 96, 0, 2),
            dst_addr: Ipv4Addr::new(1, 1, 1, 1),
            next_header: IpProtocol::Icmp,
            payload_len: icmp.buffer_len(),
            hop_limit: 64,
        };
        let mut pkt = vec![0u8; ip.buffer_len() + icmp.buffer_len()];
        let cksum = ChecksumCapabilities::default();
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut pkt[..]), &cksum);
        icmp.emit(
            &mut Icmpv4Packet::new_unchecked(&mut pkt[ip.buffer_len()..]),
            &cksum,
        );

        let parsed = parse_guest_echo_v4(&pkt).unwrap();
        assert_eq!(parsed.destination, request.destination);
        assert_eq!(parsed.ident, request.ident);
        assert_eq!(parsed.seq, request.seq);
        assert_eq!(parsed.data, request.data);

        let reply = build_echo_reply_v4(&parsed).unwrap();
        let reply_ip = Ipv4Packet::new_checked(&reply).unwrap();
        // Reply is sourced from the pinged destination, addressed to the guest.
        assert_eq!(reply_ip.src_addr(), Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(reply_ip.dst_addr(), Ipv4Addr::new(100, 96, 0, 2));
        let reply_icmp = Icmpv4Packet::new_checked(reply_ip.payload()).unwrap();
        match Icmpv4Repr::parse(&reply_icmp, &cksum).unwrap() {
            Icmpv4Repr::EchoReply {
                ident,
                seq_no,
                data,
            } => {
                assert_eq!(ident, request.ident);
                assert_eq!(seq_no, request.seq);
                assert_eq!(data, &request.data[..]);
            }
            other => panic!("expected echo reply, got {other:?}"),
        }
    }
}
