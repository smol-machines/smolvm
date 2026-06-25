//! Host-side smoltcp runtime for the virtio-net backend.
//!
//! Context
//! =======
//!
//! This file is the in-process "gateway" that sits behind the guest's virtio
//! NIC. It does not configure the guest interface; that already happened inside
//! `smolvm-agent`. Instead, this module:
//! - receives raw Ethernet frames coming out of libkrun
//! - feeds them into smoltcp as if smolvm were the guest's next-hop gateway
//! - forwards guest DNS queries to a host UDP socket
//! - relays guest TCP streams to host `TcpStream`s
//!
//! Conceptually, it plays the role of a tiny virtual router/NAT-side gateway:
//!
//! ```text
//! guest eth0
//!   -> Ethernet frame
//!   -> Frame queues
//!   -> smoltcp Interface (gateway MAC/IP)
//!   -> protocol-specific handling:
//!        - TCP  -> host relay threads
//!        - DNS  -> host UDP socket
//!        - UDP  -> per-flow host socket relay (udp_relay)
//!   -> outbound network
//! ```
//!
//! Poll-loop-centric view:
//!
//! ```text
//! guest_to_host queue
//!   -> VirtioNetworkDevice::stage_next_frame()
//!   -> classify_guest_frame()
//!   -> smoltcp ingress
//!   -> protocol-specific side effects
//!        - TCP SYN  -> create relay/socket state
//!        - DNS UDP  -> gateway UDP socket
//!        - other UDP-> destination-keyed relay socket
//!   -> smoltcp egress
//!   -> host_to_guest queue
//!   -> FrameStream writer
//! ```
//!
//! Runtime control flow:
//!
//! ```text
//! new guest frame         -> guest_wake  -> poll loop
//! host relay has data     -> relay_wake  -> poll loop
//! published host connect  -> relay_wake  -> poll loop
//! smoltcp emitted frames  -> host_wake   -> frame writer
//! ```

use crate::device::VirtioNetworkDevice;
use crate::dns;
use crate::egress::EgressPolicy;
use crate::icmp_relay;
use crate::queues::NetworkFrameQueues;
use crate::tcp_listeners::AcceptedTcpConnection;
use crate::tcp_relay::{spawn_tcp_relay, TcpRelayTable};
use crate::udp_relay;
use crate::virtio_net_log;
use smoltcp::iface::{
    Config, Interface, PollIngressSingleResult, PollResult, SocketHandle, SocketSet,
};
use smoltcp::socket::raw::{
    PacketBuffer as RawPacketBuffer, PacketMetadata as RawPacketMetadata, Socket as RawSocket,
};
use smoltcp::socket::tcp;
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
    IpListenEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as HostUdpSocket};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant as StdInstant};

const DNS_SOCKET_PORT: u16 = 53;
const DNS_PACKET_SLOTS: usize = 8;
const DNS_BUFFER_BYTES: usize = 2048;
// DNS-over-TCP to the gateway. Real resolvers (and resolv.conf clients) fall
// back to TCP for truncated answers and EDNS, so the gateway filter must serve
// TCP/53 in addition to UDP/53. A small pool of listening sockets handles
// concurrent queries; DNS/TCP is rare and short-lived (one query per
// connection), so a few suffice.
const DNS_TCP_LISTENERS: usize = 4;
const DNS_TCP_RX_BYTES: usize = 4096;
const DNS_TCP_TX_BYTES: usize = 8192;
// A length-prefixed DNS message is bounded by a 16-bit length, but the gateway
// only needs to handle ordinary queries/responses; cap to keep buffers small
// and reject a guest that sends a bogus oversized prefix.
const DNS_TCP_MAX_MSG: usize = 4096;
const DEFAULT_IDLE_TIMEOUT_MS: i32 = 100;
/// Packet slots per ICMP raw socket buffer (per direction).
const ICMP_PACKET_SLOTS: usize = 16;
/// Payload bytes per ICMP raw socket buffer (per direction).
const ICMP_BUFFER_BYTES: usize = 32 * 1024;

/// Resolved network parameters for one guest NIC.
///
/// These are the host-side parameters for the virtual link. Note that the
/// smoltcp interface is configured with the *gateway* MAC/IP, because the host
/// runtime is acting as the guest-visible gateway endpoint.
#[derive(Debug, Clone, Copy)]
pub struct VirtioPollConfig {
    /// Host-side gateway MAC visible to the guest.
    pub gateway_mac: [u8; 6],
    /// Guest MAC address.
    pub guest_mac: [u8; 6],
    /// Gateway IPv4 address.
    pub gateway_ipv4: Ipv4Addr,
    /// Guest IPv4 address.
    pub guest_ipv4: Ipv4Addr,
    /// Gateway IPv6 (ULA) address.
    pub gateway_ipv6: Ipv6Addr,
    /// Guest IPv6 (ULA) address.
    pub guest_ipv6: Ipv6Addr,
    /// IPv6 prefix length for the virtual link.
    pub prefix_len6: u8,
    /// Upstream resolver the gateway forwards guest DNS queries to.
    pub upstream_dns: Ipv4Addr,
    /// IP-level MTU.
    pub mtu: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameAction {
    TcpSyn {
        source: SocketAddr,
        destination: SocketAddr,
    },
    DnsQuery,
    /// Non-DNS guest UDP, relayed to a host socket (see `udp_relay`).
    UdpFlow {
        destination: SocketAddr,
    },
    Passthrough,
}

/// Start the dedicated smoltcp poll thread for the virtio-net backend.
///
/// This creates one long-lived poll loop thread per guest NIC. That thread owns
/// the smoltcp `Interface`, its socket set, and the TCP relay table.
///
/// Ownership boundary:
/// - this thread owns all smoltcp state
/// - relay threads never touch smoltcp sockets directly
/// - frame bridge threads never parse protocols beyond raw Ethernet framing
pub fn start_network_stack(
    queues: Arc<NetworkFrameQueues>,
    config: VirtioPollConfig,
    tcp_receiver: Option<Receiver<AcceptedTcpConnection>>,
    egress: EgressPolicy,
) -> std::io::Result<JoinHandle<()>> {
    virtio_net_log!(
        "virtio-net: spawning poll thread guest_ip={} gateway_ip={} mtu={}",
        config.guest_ipv4,
        config.gateway_ipv4,
        config.mtu
    );
    thread::Builder::new()
        .name("smolvm-net-poll".into())
        .spawn(move || run_network_stack(queues, config, tcp_receiver, egress))
}

fn run_network_stack(
    queues: Arc<NetworkFrameQueues>,
    config: VirtioPollConfig,
    mut tcp_receiver: Option<Receiver<AcceptedTcpConnection>>,
    egress: EgressPolicy,
) {
    // Poll loop overview:
    //
    // 1. Drain staged guest Ethernet frames from the guest_to_host queue.
    // 2. Pre-classify them so we can create relay/socket state before smoltcp
    //    consumes the frame.
    // 3. Poll smoltcp ingress/egress.
    // 4. Forward DNS and relay TCP payloads.
    // 5. Sleep in poll(2) on wake pipes until guest frames, relay activity, or
    //    timers require more work.
    //
    // A useful mental model is:
    //
    //   queue input -> classify -> smoltcp -> protocol handling -> queue output
    virtio_net_log!(
        "virtio-net: poll loop started guest_ip={} gateway_ip={}",
        config.guest_ipv4,
        config.gateway_ipv4
    );
    let clock = StdInstant::now();
    let mut device = VirtioNetworkDevice::new(queues.clone(), config.mtu);
    let mut interface = create_interface(&mut device, &config);
    let mut sockets = SocketSet::new(vec![]);
    let dns_socket_handle = add_dns_socket(&mut sockets);
    let dns_tcp_handles = add_dns_tcp_sockets(&mut sockets);
    let mut dns_tcp_conns: Vec<DnsTcpConn> = (0..dns_tcp_handles.len())
        .map(|_| DnsTcpConn::default())
        .collect();
    let (icmp4_handle, icmp6_handle) = add_icmp_raw_sockets(&mut sockets);
    // Gateway addresses answer their own pings locally; everything else is
    // relayed out to real host ICMP sockets.
    let gateway_addrs = [
        IpAddr::V4(config.gateway_ipv4),
        IpAddr::V6(config.gateway_ipv6),
        IpAddr::V6(link_local_from_mac(config.gateway_mac)),
    ];
    let relay_wake = Arc::new(queues.relay_wake.clone());
    let mut relays = TcpRelayTable::new(None, egress.clone());
    let mut udp_sockets = udp_relay::UdpSocketTable::new();
    let udp_channels = {
        let shutdown_queues = queues.clone();
        udp_relay::start_udp_relay(
            relay_wake.clone(),
            Arc::new(move || shutdown_queues.is_shutting_down()),
        )
    };
    let icmp_channels = {
        let shutdown_queues = queues.clone();
        icmp_relay::start_icmp_relay(
            relay_wake.clone(),
            Arc::new(move || shutdown_queues.is_shutting_down()),
        )
    };

    // The smoltcp loop is driven by fd-based wakeups rather than busy spinning.
    // guest_wake  -> new guest frame or shutdown
    // relay_wake  -> host TCP relay thread produced data or shutdown
    let mut poll_fds = [
        libc::pollfd {
            fd: queues.guest_wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: queues.relay_wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        if queues.is_shutting_down() {
            return;
        }
        let now = smoltcp_now(clock);

        while let Some(frame) = device.stage_next_frame() {
            // We inspect the frame before giving it to smoltcp because certain
            // flows need side effects first:
            // - TCP SYN: pre-create a matching smoltcp socket + relay entry
            // - DNS UDP: allow through for gateway-side forwarding
            // - other UDP: pre-create the destination-keyed relay socket
            match classify_guest_frame(frame, &gateway_addrs) {
                FrameAction::TcpSyn {
                    source,
                    destination,
                } => {
                    virtio_net_log!(
                        "virtio-net: guest TCP SYN source={} destination={}",
                        source,
                        destination
                    );
                    if !relays.has_socket_for(&source, &destination) {
                        relays.create_tcp_socket(source, destination, &mut sockets);
                    }
                    if matches!(
                        interface.poll_ingress_single(now, &mut device, &mut sockets),
                        PollIngressSingleResult::None
                    ) {
                        device.drop_staged_frame();
                    }
                }
                FrameAction::DnsQuery | FrameAction::Passthrough => {
                    if matches!(
                        interface.poll_ingress_single(now, &mut device, &mut sockets),
                        PollIngressSingleResult::None
                    ) {
                        device.drop_staged_frame();
                    }
                }
                FrameAction::UdpFlow { destination } => {
                    // Same egress policy as TCP; a denied destination's datagram
                    // is silently dropped (a guest sees a normal UDP black hole).
                    if udp_relay::should_relay_udp(destination, &egress)
                        && udp_sockets.ensure_socket(destination, &mut sockets)
                    {
                        if matches!(
                            interface.poll_ingress_single(now, &mut device, &mut sockets),
                            PollIngressSingleResult::None
                        ) {
                            device.drop_staged_frame();
                        }
                    } else {
                        device.drop_staged_frame();
                    }
                }
            }
        }

        relay_accepted_tcp_connection(
            &mut tcp_receiver,
            &mut relays,
            &mut interface,
            &mut sockets,
            config.gateway_ipv4,
            config.guest_ipv4,
        );

        // First egress pass: let smoltcp emit any packets caused by the most
        // recent ingress work before we service higher-level relays.
        flush_interface_egress(&mut interface, &mut device, &mut sockets, now);
        interface.poll_maintenance(now);
        wake_guest_if_needed(&queues, &device);

        // Move payloads between established smoltcp TCP sockets and host relay
        // threads, and service the DNS gateway socket.
        relays.relay_data(&mut sockets);
        process_dns_queries(
            dns_socket_handle,
            &mut sockets,
            &egress,
            config.upstream_dns,
        );
        process_dns_tcp(
            &dns_tcp_handles,
            &mut dns_tcp_conns,
            &mut sockets,
            &egress,
            config.upstream_dns,
        );

        // General UDP: forward staged guest datagrams to the relay thread,
        // deliver any replies it produced, and expire idle destination sockets.
        if udp_sockets.drain_to_relay(&mut sockets, &udp_channels.to_relay) {
            udp_channels.relay_thread_wake.wake();
        }
        udp_sockets.deliver_replies(&mut sockets, &udp_channels.from_relay);
        udp_sockets.expire_idle(&mut sockets);

        // ICMP echo: the raw sockets captured any guest echo requests during
        // ingress above. Forward external pings to the relay (answering gateway
        // pings locally), then send back any replies it produced.
        let mut woke_icmp = false;
        woke_icmp |= drain_icmp_echo(
            &mut sockets,
            icmp4_handle,
            false,
            &egress,
            &gateway_addrs,
            &icmp_channels.to_relay,
        );
        woke_icmp |= drain_icmp_echo(
            &mut sockets,
            icmp6_handle,
            true,
            &egress,
            &gateway_addrs,
            &icmp_channels.to_relay,
        );
        if woke_icmp {
            icmp_channels.relay_thread_wake.wake();
        }
        deliver_icmp_replies(
            &mut sockets,
            icmp4_handle,
            icmp6_handle,
            &icmp_channels.from_relay,
        );

        // Once the guest-side TCP handshake is established inside smoltcp, we
        // can spawn the corresponding host relay thread.
        for connection in relays.take_new_connections(&mut sockets) {
            spawn_tcp_relay(
                connection.destination,
                connection.relay_target,
                connection.from_smoltcp,
                connection.to_smoltcp,
                relay_wake.clone(),
                connection.exit_state,
            );
        }

        relays.cleanup_closed(&mut sockets);

        // Second egress pass: DNS responses or relay data may have queued more
        // packets for the guest.
        flush_interface_egress(&mut interface, &mut device, &mut sockets, now);
        wake_guest_if_needed(&queues, &device);

        let timeout_ms = interface
            .poll_delay(now, &sockets)
            .map(|duration| duration.total_millis().min(i32::MAX as u64) as i32)
            .unwrap_or(DEFAULT_IDLE_TIMEOUT_MS);

        // SAFETY: both pollfds contain valid wake-pipe descriptors.
        unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                timeout_ms,
            );
        }

        if poll_fds[0].revents & libc::POLLIN != 0 {
            queues.guest_wake.drain();
        }
        if poll_fds[1].revents & libc::POLLIN != 0 {
            queues.relay_wake.drain();
        }
    }
}

fn create_interface(device: &mut VirtioNetworkDevice, config: &VirtioPollConfig) -> Interface {
    // This interface models the host-side gateway endpoint, not the guest NIC.
    //
    // Equivalent conceptual state:
    //   MAC: config.gateway_mac
    //   IP : config.gateway_ipv4/30
    //        config.gateway_ipv6/64 (ULA) + fe80 link-local
    //
    // The guest IP exists as a peer on the same virtual link; it is not an
    // address owned by this interface.
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ethernet(EthernetAddress(
            config.gateway_mac,
        ))),
        device,
        Instant::ZERO,
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(config.gateway_ipv4), 30))
            .expect("failed to add gateway IPv4 address");
        addresses
            .push(IpCidr::new(
                IpAddress::Ipv6(config.gateway_ipv6),
                config.prefix_len6,
            ))
            .expect("failed to add gateway IPv6 address");
        // RFC-clean NDP wants a link-local peer on the segment; derive the
        // standard EUI-64 link-local from the gateway MAC so the guest kernel
        // can talk NDP to fe80::… as well as to the ULA.
        addresses
            .push(IpCidr::new(
                IpAddress::Ipv6(link_local_from_mac(config.gateway_mac)),
                64,
            ))
            .expect("failed to add gateway IPv6 link-local address");
    });
    // The interface acts as the gateway and may need to answer packets for
    // destinations other than its directly assigned IP, so the route table and
    // "any IP" mode are opened up accordingly.
    interface
        .routes_mut()
        .add_default_ipv4_route(config.gateway_ipv4)
        .expect("failed to add default IPv4 route");
    interface
        .routes_mut()
        .add_default_ipv6_route(config.gateway_ipv6)
        .expect("failed to add default IPv6 route");
    interface.set_any_ip(true);
    interface
}

/// Derive the EUI-64 IPv6 link-local address for a MAC (RFC 4291 appendix A):
/// flip the universal/local bit, insert `ff:fe` in the middle.
fn link_local_from_mac(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
        u16::from_be_bytes([mac[2], 0xff]),
        u16::from_be_bytes([0xfe, mac[3]]),
        u16::from_be_bytes([mac[4], mac[5]]),
    )
}

/// add_dns_socket is adding an UDP socket inside smoltcp, so that the guest DNS packet will
/// hit this socket first. It is then proxied to the resolver. Note that this will not cause
/// a host side :53 collesion, because the smoltcp Interface, SocketSet is per VM, and the
/// gateway:53 is for that set of Interface and SocketSet, it is not bind to a host-kernel UDP socket.
///
/// The bind is wildcard (port-only) on purpose: combined with `set_any_ip`, every
/// guest UDP datagram to port 53 — whatever its destination address or family
/// (the v4 gateway, the v6 gateway, or an external resolver IP) — lands on this
/// socket and is answered from that same destination address. That transparently
/// intercepts hardcoded external resolvers too, matching TSI's DNS handling.
fn add_dns_socket(sockets: &mut SocketSet<'_>) -> SocketHandle {
    let rx_meta = vec![PacketMetadata::EMPTY; DNS_PACKET_SLOTS];
    let tx_meta = vec![PacketMetadata::EMPTY; DNS_PACKET_SLOTS];
    let rx_buffer = PacketBuffer::new(rx_meta, vec![0u8; DNS_BUFFER_BYTES]);
    let tx_buffer = PacketBuffer::new(tx_meta, vec![0u8; DNS_BUFFER_BYTES]);
    let mut socket = UdpSocket::new(rx_buffer, tx_buffer);
    socket
        .bind(smoltcp::wire::IpListenEndpoint {
            addr: None,
            port: DNS_SOCKET_PORT,
        })
        .expect("failed to bind gateway DNS socket");
    sockets.add(socket)
}

/// Add the two raw IP sockets that capture guest ICMP echo traffic.
///
/// A `raw::Socket` receives a copy of every matching IP packet *before* the
/// interface's "is this addressed to me?" check, so these capture the guest's
/// echo requests even though their destination is some external host. The same
/// sockets carry the relayed echo *replies* back out, fully addressed (source =
/// the pinged host), letting smoltcp own the Ethernet framing and ARP/NDP.
fn add_icmp_raw_sockets(sockets: &mut SocketSet<'_>) -> (SocketHandle, SocketHandle) {
    fn raw_socket(version: IpVersion, protocol: IpProtocol) -> RawSocket<'static> {
        let rx = RawPacketBuffer::new(
            vec![RawPacketMetadata::EMPTY; ICMP_PACKET_SLOTS],
            vec![0u8; ICMP_BUFFER_BYTES],
        );
        let tx = RawPacketBuffer::new(
            vec![RawPacketMetadata::EMPTY; ICMP_PACKET_SLOTS],
            vec![0u8; ICMP_BUFFER_BYTES],
        );
        RawSocket::new(Some(version), Some(protocol), rx, tx)
    }

    let v4 = sockets.add(raw_socket(IpVersion::Ipv4, IpProtocol::Icmp));
    let v6 = sockets.add(raw_socket(IpVersion::Ipv6, IpProtocol::Icmpv6));
    (v4, v6)
}

/// Drain guest echo requests captured on one ICMP raw socket. Gateway-destined
/// pings are answered locally (the gateway *is* the source), external ones are
/// forwarded to the relay thread subject to egress policy, and denied
/// destinations are dropped. Returns true if anything was sent to the relay.
fn drain_icmp_echo(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    is_ipv6: bool,
    egress: &EgressPolicy,
    gateway_addrs: &[IpAddr],
    to_relay: &SyncSender<icmp_relay::IcmpEcho>,
) -> bool {
    // Phase 1: drain received requests into owned values so the socket can be
    // re-borrowed below to emit local gateway replies.
    let mut echoes = Vec::new();
    {
        let socket = sockets.get_mut::<RawSocket>(handle);
        while socket.can_recv() {
            let Ok(packet) = socket.recv() else {
                break;
            };
            let parsed = if is_ipv6 {
                icmp_relay::parse_guest_echo_v6(packet)
            } else {
                icmp_relay::parse_guest_echo_v4(packet)
            };
            if let Some(echo) = parsed {
                echoes.push(echo);
            }
        }
    }

    // Phase 2: route each echo.
    let mut woke = false;
    let mut local_replies = Vec::new();
    for echo in echoes {
        if gateway_addrs.contains(&echo.destination) {
            local_replies.push(echo);
        } else if icmp_relay::should_relay_icmp(echo.destination, egress) {
            match to_relay.try_send(echo) {
                Ok(()) => woke = true,
                Err(TrySendError::Full(_)) => {
                    virtio_net_log!("virtio-net: dropping guest ICMP echo (relay queue full)");
                }
                Err(TrySendError::Disconnected(_)) => return woke,
            }
        }
        // else: egress policy denies the destination — silent black hole.
    }

    // Phase 3: answer gateway pings straight back out the raw socket.
    if !local_replies.is_empty() {
        let socket = sockets.get_mut::<RawSocket>(handle);
        for reply in local_replies {
            let frame = if is_ipv6 {
                icmp_relay::build_echo_reply_v6(&reply)
            } else {
                icmp_relay::build_echo_reply_v4(&reply)
            };
            if let Some(frame) = frame {
                let _ = socket.send_slice(&frame);
            }
        }
    }
    woke
}

/// Deliver echo replies produced by the relay thread, sending each as a
/// fully-addressed IP packet (source = the pinged host) out the matching raw
/// socket so smoltcp frames it back to the guest.
fn deliver_icmp_replies(
    sockets: &mut SocketSet<'_>,
    icmp4_handle: SocketHandle,
    icmp6_handle: SocketHandle,
    from_relay: &Receiver<icmp_relay::IcmpEcho>,
) {
    while let Ok(reply) = from_relay.try_recv() {
        let (handle, frame) = match reply.guest {
            IpAddr::V4(_) => (icmp4_handle, icmp_relay::build_echo_reply_v4(&reply)),
            IpAddr::V6(_) => (icmp6_handle, icmp_relay::build_echo_reply_v6(&reply)),
        };
        let Some(frame) = frame else {
            continue;
        };
        let socket = sockets.get_mut::<RawSocket>(handle);
        if socket.send_slice(&frame).is_err() {
            virtio_net_log!(
                "virtio-net: dropping ICMP reply to {} (raw socket buffer full)",
                reply.guest
            );
        }
    }
}

/// Receive the accepted TCP connection from the tcp_channel, and then relay it to
/// the TcpRelayTable where the TCP network packets will be relayed to the guest.
fn relay_accepted_tcp_connection(
    tcp_receiver: &mut Option<Receiver<AcceptedTcpConnection>>,
    relays: &mut TcpRelayTable,
    interface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    gateway_ipv4: Ipv4Addr,
    guest_ipv4: Ipv4Addr,
) {
    // Published-port model:
    //
    // host client -> accepted host TcpStream
    //             -> create guest-facing smoltcp socket from gateway_ip:ephemeral
    //             -> guest sees a normal inbound TCP connection to guest_port
    //             -> once Established, the relay thread bridges payloads
    //
    // The guest does not see the original host peer address here. This path is
    // effectively a small userspace TCP proxy/NAT at the gateway boundary.
    let mut disconnected = false;

    if let Some(receiver) = tcp_receiver.as_mut() {
        loop {
            match receiver.try_recv() {
                Ok(connection) => {
                    let guest_destination =
                        SocketAddr::new(std::net::IpAddr::V4(guest_ipv4), connection.guest_port);
                    virtio_net_log!(
                        "virtio-net: accepted published TCP connection peer={} host_port={} guest_destination={}",
                        connection.peer_addr,
                        connection.host_port,
                        guest_destination
                    );
                    if !relays.create_published_socket(
                        interface,
                        gateway_ipv4,
                        guest_destination,
                        connection.stream,
                        sockets,
                    ) {
                        tracing::warn!(
                            host_port = connection.host_port,
                            guest_port = connection.guest_port,
                            peer_addr = %connection.peer_addr,
                            "dropping published TCP connection because the guest relay path could not be created"
                        );
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
    }

    if disconnected {
        *tcp_receiver = None;
    }
}

fn process_dns_queries(
    dns_socket_handle: SocketHandle,
    sockets: &mut SocketSet<'_>,
    egress: &EgressPolicy,
    upstream_dns: Ipv4Addr,
) {
    // Phase 1 DNS model:
    // guest UDP/53 -> smoltcp gateway socket -> host UDP socket -> upstream DNS
    //               <-               response bytes               <-
    let socket = sockets.get_mut::<UdpSocket>(dns_socket_handle);
    while socket.can_recv() {
        let (query, metadata) = match socket.recv() {
            Ok((q, m)) => (q.to_vec(), m),
            Err(_) => break,
        };
        virtio_net_log!(
            "virtio-net: forwarding guest DNS query guest={} local_address={:?} query_len={} upstream_dns={}",
            metadata.endpoint,
            metadata.local_address,
            query.len(),
            upstream_dns
        );
        // Apply the same allow-host filter as TCP (see `filtered_dns_response`),
        // forwarding allowed queries over the host's UDP stack.
        let response =
            match filtered_dns_response(&query, egress, |q| forward_dns_query(upstream_dns, q)) {
                Some(response) => response,
                None => continue,
            };
        virtio_net_log!(
            "virtio-net: forwarded DNS response back to guest guest={} response_len={}",
            metadata.endpoint,
            response.len()
        );

        let response_meta = UdpMetadata {
            endpoint: metadata.endpoint,
            local_address: metadata.local_address,
            meta: Default::default(),
        };
        let _ = socket.send_slice(&response, response_meta);
    }
}

fn forward_dns_query(upstream_dns: Ipv4Addr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    // This is intentionally a plain host UDP exchange rather than a smoltcp
    // socket-to-socket relay. Once the guest packet reaches the gateway, the
    // simplest MVP path is to proxy it with the host kernel's UDP stack.
    //
    // Rough shell equivalent:
    //   send raw DNS message to `<upstream_dns>:53`
    //   wait up to 2 seconds for one reply
    let socket = HostUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let local_addr = socket.local_addr()?;
    virtio_net_log!(
        "virtio-net: sending DNS query to upstream resolver local_addr={} upstream_dns={} query_len={}",
        local_addr,
        upstream_dns,
        query.len()
    );
    socket.send_to(query, (upstream_dns, DNS_SOCKET_PORT))?;

    let mut buffer = vec![0u8; DNS_BUFFER_BYTES];
    let (bytes_read, _) = socket.recv_from(&mut buffer)?;
    buffer.truncate(bytes_read);
    virtio_net_log!(
        "virtio-net: received DNS response from upstream resolver upstream_dns={} response_len={}",
        upstream_dns,
        buffer.len()
    );
    Ok(buffer)
}

/// Apply the allow-host DNS policy to a single query and produce the response
/// bytes to return to the guest, or `None` to drop (a forwarding error on an
/// allowed query — the guest sees a normal DNS timeout).
///
/// Shared by the UDP and TCP gateway paths so both enforce identical policy:
/// only allow-listed names are forwarded (`forward`); others get NXDOMAIN; an
/// unparseable query gets SERVFAIL. Answer A/AAAA records of allowed queries are
/// learned as temporary egress IPs so the follow-up connection passes the
/// filter. Mirrors libkrun's TSI DNS filter.
fn filtered_dns_response(
    query: &[u8],
    egress: &EgressPolicy,
    forward: impl FnOnce(&[u8]) -> std::io::Result<Vec<u8>>,
) -> Option<Vec<u8>> {
    if !egress.dns_filter_active() {
        return match forward(query) {
            Ok(response) => Some(response),
            Err(err) => {
                virtio_net_log!("virtio-net: host DNS forwarding failed error={}", err);
                None
            }
        };
    }
    match dns::question_name(query) {
        Some(name) if egress.hostname_allowed(&name) => match forward(query) {
            Ok(response) => {
                egress.learn_ip_records(&dns::answer_ip_records(&response));
                Some(response)
            }
            Err(err) => {
                virtio_net_log!("virtio-net: host DNS forwarding failed error={}", err);
                None
            }
        },
        Some(name) => {
            virtio_net_log!(
                "virtio-net: blocking DNS query by allow-host policy name={}",
                name
            );
            Some(dns::error_response(query, dns::DNS_RCODE_NXDOMAIN))
        }
        None => Some(dns::error_response(query, dns::DNS_RCODE_SERVFAIL)),
    }
}

/// Forward one DNS query to the upstream resolver over TCP (length-prefixed, per
/// RFC 1035 §4.2.2) and return the raw response message. Synchronous host TCP
/// exchange with a short timeout, matching the UDP path's MVP shape.
fn forward_dns_query_tcp(upstream_dns: Ipv4Addr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    let len = u16::try_from(query.len())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "DNS query too large for TCP"))?;
    let mut stream = std::net::TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(upstream_dns), DNS_SOCKET_PORT),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(query)?;
    stream.flush()?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > DNS_TCP_MAX_MSG {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "upstream DNS/TCP response length out of range",
        ));
    }
    let mut response = vec![0u8; resp_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

/// Create the pool of smoltcp TCP listening sockets bound to the gateway's
/// port 53. Each accepts one DNS-over-TCP connection at a time and is re-armed
/// by [`process_dns_tcp`] after the connection closes.
fn add_dns_tcp_sockets(sockets: &mut SocketSet<'_>) -> Vec<SocketHandle> {
    (0..DNS_TCP_LISTENERS)
        .map(|_| {
            let rx_buffer = tcp::SocketBuffer::new(vec![0u8; DNS_TCP_RX_BYTES]);
            let tx_buffer = tcp::SocketBuffer::new(vec![0u8; DNS_TCP_TX_BYTES]);
            let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
            socket
                .listen(IpListenEndpoint {
                    addr: None,
                    port: DNS_SOCKET_PORT,
                })
                .expect("failed to listen on gateway DNS TCP socket");
            sockets.add(socket)
        })
        .collect()
}

/// Per-listener state for an in-flight DNS-over-TCP connection: the
/// accumulating length-prefixed query, and the framed response we still owe the
/// guest.
#[derive(Default)]
struct DnsTcpConn {
    /// Guest -> gateway bytes received so far (2-byte length prefix + query).
    rx: Vec<u8>,
    /// Framed response (2-byte length prefix + message) to send to the guest.
    tx: Vec<u8>,
    /// Bytes of `tx` already written to the socket.
    tx_sent: usize,
    /// The query has been answered (or rejected); drain `tx` then close.
    done: bool,
}

/// Service the DNS-over-TCP listening sockets: accept a connection, read the
/// length-prefixed query, apply the allow-host filter, forward allowed queries
/// upstream over TCP, write the length-prefixed response, and close. Closed
/// sockets are re-armed to listen again.
fn process_dns_tcp(
    handles: &[SocketHandle],
    conns: &mut [DnsTcpConn],
    sockets: &mut SocketSet<'_>,
    egress: &EgressPolicy,
    upstream_dns: Ipv4Addr,
) {
    for (handle, conn) in handles.iter().zip(conns.iter_mut()) {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);

        // A closed/finished socket: reset state and re-arm to accept the next
        // connection. `listen` only succeeds from the CLOSED state; if the
        // socket is still draining (e.g. TIME-WAIT) the error is ignored and the
        // next poll retries.
        if !socket.is_open() {
            if !conn.rx.is_empty() || !conn.tx.is_empty() || conn.done {
                *conn = DnsTcpConn::default();
            }
            let _ = socket.listen(IpListenEndpoint {
                addr: None,
                port: DNS_SOCKET_PORT,
            });
            continue;
        }

        // Already answered: flush whatever response remains, then close.
        if conn.done {
            drain_dns_tcp_tx(socket, conn);
            continue;
        }

        // Accumulate the length-prefixed query.
        while socket.can_recv() {
            let appended = socket.recv(|data| (data.len(), data.to_vec()));
            match appended {
                Ok(bytes) if !bytes.is_empty() => conn.rx.extend_from_slice(&bytes),
                _ => break,
            }
        }

        // Reject a guest that floods without ever completing a message.
        if conn.rx.len() > DNS_TCP_MAX_MSG + 2 {
            conn.done = true;
            socket.close();
            continue;
        }

        if conn.rx.len() >= 2 {
            let msg_len = u16::from_be_bytes([conn.rx[0], conn.rx[1]]) as usize;
            if msg_len == 0 || msg_len > DNS_TCP_MAX_MSG {
                conn.done = true;
                socket.close();
                continue;
            }
            if conn.rx.len() >= 2 + msg_len {
                let query = conn.rx[2..2 + msg_len].to_vec();
                virtio_net_log!(
                    "virtio-net: DNS/TCP query query_len={} upstream_dns={}",
                    query.len(),
                    upstream_dns
                );
                if let Some(response) = filtered_dns_response(&query, egress, |q| {
                    forward_dns_query_tcp(upstream_dns, q)
                }) {
                    if let Ok(resp_len) = u16::try_from(response.len()) {
                        conn.tx.extend_from_slice(&resp_len.to_be_bytes());
                        conn.tx.extend_from_slice(&response);
                    }
                }
                conn.done = true;
                drain_dns_tcp_tx(socket, conn);
            }
        }
    }
}

/// Write as much of the pending framed response as the socket will accept; once
/// fully sent, close the connection (the guest reads the answer then sees EOF).
fn drain_dns_tcp_tx(socket: &mut tcp::Socket<'_>, conn: &mut DnsTcpConn) {
    while conn.tx_sent < conn.tx.len() && socket.can_send() {
        match socket.send_slice(&conn.tx[conn.tx_sent..]) {
            Ok(n) if n > 0 => conn.tx_sent += n,
            _ => break,
        }
    }
    if conn.tx_sent >= conn.tx.len() {
        socket.close();
    }
}

fn flush_interface_egress(
    interface: &mut Interface,
    device: &mut VirtioNetworkDevice,
    sockets: &mut SocketSet<'_>,
    now: Instant,
) {
    // smoltcp may have multiple pending egress packets after a single ingress
    // event or timeout. Keep polling until the interface reports there is no
    // more immediate work.
    loop {
        let result = interface.poll_egress(now, device, sockets);
        if matches!(result, PollResult::None) {
            break;
        }
    }
}

fn wake_guest_if_needed(queues: &NetworkFrameQueues, device: &VirtioNetworkDevice) {
    // The device records only that "some frame was emitted". We convert that
    // sticky bit into one wake for the writer thread and let the writer drain
    // the entire host_to_guest queue.
    if device.frames_emitted.swap(false, Ordering::Relaxed) {
        queues.host_wake.wake();
    }
}

fn smoltcp_now(clock: StdInstant) -> Instant {
    let elapsed = clock.elapsed();
    Instant::from_millis(elapsed.as_millis() as i64)
}

fn classify_guest_frame(frame: &[u8], gateway_addrs: &[IpAddr]) -> FrameAction {
    let ethernet = match EthernetFrame::new_checked(frame) {
        Ok(frame) => frame,
        Err(_) => return FrameAction::Passthrough,
    };

    // Extract (src, dst, transport protocol, transport payload) from either IP
    // family. Anything that isn't plain IPv4/IPv6 — ARP, and IPv6 packets with
    // extension headers (which guest TCP/UDP traffic doesn't use) — passes
    // through to smoltcp untouched; that also covers ICMPv6/NDP.
    let (src_ip, dst_ip, protocol, transport): (IpAddr, IpAddr, _, _) = match ethernet.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4 = match Ipv4Packet::new_checked(ethernet.payload()) {
                Ok(packet) => packet,
                Err(_) => return FrameAction::Passthrough,
            };
            (
                IpAddr::V4(ipv4.src_addr()),
                IpAddr::V4(ipv4.dst_addr()),
                ipv4.next_header(),
                ipv4.payload(),
            )
        }
        EthernetProtocol::Ipv6 => {
            let ipv6 = match Ipv6Packet::new_checked(ethernet.payload()) {
                Ok(packet) => packet,
                Err(_) => return FrameAction::Passthrough,
            };
            (
                IpAddr::V6(ipv6.src_addr()),
                IpAddr::V6(ipv6.dst_addr()),
                ipv6.next_header(),
                ipv6.payload(),
            )
        }
        _ => return FrameAction::Passthrough,
    };

    match protocol {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp = match TcpPacket::new_checked(transport) {
                Ok(packet) => packet,
                Err(_) => return FrameAction::Passthrough,
            };

            if tcp.syn() && !tcp.ack() {
                // DNS-over-TCP to the gateway itself is intercepted by the local
                // listening sockets (process_dns_tcp), not relayed. TCP/53 to an
                // external resolver (an allow-listed IP) is left to the egress
                // relay so the policy still applies.
                if tcp.dst_port() == DNS_SOCKET_PORT && gateway_addrs.contains(&dst_ip) {
                    FrameAction::Passthrough
                } else {
                    FrameAction::TcpSyn {
                        source: SocketAddr::new(src_ip, tcp.src_port()),
                        destination: SocketAddr::new(dst_ip, tcp.dst_port()),
                    }
                }
            } else {
                FrameAction::Passthrough
            }
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp = match UdpPacket::new_checked(transport) {
                Ok(packet) => packet,
                Err(_) => return FrameAction::Passthrough,
            };

            if udp.dst_port() == DNS_SOCKET_PORT {
                FrameAction::DnsQuery
            } else {
                FrameAction::UdpFlow {
                    destination: SocketAddr::new(dst_ip, udp.dst_port()),
                }
            }
        }
        _ => FrameAction::Passthrough,
    }
}

/// Fuzz-only entrypoint for `classify_guest_frame`.
///
/// A malicious guest sends arbitrary ethernet frames over virtio-net, and the
/// host parses every one here — so this MUST NOT panic on any input. Gated
/// behind the `fuzzing` feature so it never ships in a normal build.
#[cfg(feature = "fuzzing")]
pub fn fuzz_classify_guest_frame(frame: &[u8]) {
    let _ = classify_guest_frame(frame, &[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Ethernet(IPv4(TCP SYN)) frame with no payload. `new_checked`
    /// validates lengths/header fields (not checksums), so dummy checksums are
    /// fine for exercising `classify_guest_frame`.
    fn tcp_syn_frame(dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        // Ethernet: dst MAC, src MAC, ethertype IPv4.
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x08, 0x00]);
        // IPv4: v4/IHL5, DSCP, total_len=40, id, flags/frag, ttl, proto=TCP, csum, src, dst.
        f.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 0x40, 0x06, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 2]); // src ip
        f.extend_from_slice(&dst_ip);
        // TCP: src/dst port, seq, ack, data-offset(5)/flags(SYN), window, csum, urg.
        f.extend_from_slice(&54321u16.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // seq + ack
        f.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]); // offset/SYN/window/csum/urg
        f
    }

    #[test]
    fn dns_tcp_to_gateway_is_intercepted_not_relayed() {
        let gw = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));
        // TCP/53 to the gateway -> handled by the local DNS listeners (Passthrough).
        assert_eq!(
            classify_guest_frame(&tcp_syn_frame([100, 96, 0, 1], 53), &[gw]),
            FrameAction::Passthrough
        );
    }

    #[test]
    fn dns_tcp_to_external_resolver_still_relayed() {
        let gw = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));
        // TCP/53 to an external (allow-listed) resolver must go through the egress
        // relay, NOT be swallowed by the gateway DNS listeners.
        assert!(matches!(
            classify_guest_frame(&tcp_syn_frame([1, 1, 1, 1], 53), &[gw]),
            FrameAction::TcpSyn { .. }
        ));
    }

    #[test]
    fn non_dns_tcp_to_gateway_still_relayed() {
        let gw = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));
        // Only port 53 is intercepted; other gateway ports relay as usual.
        assert!(matches!(
            classify_guest_frame(&tcp_syn_frame([100, 96, 0, 1], 443), &[gw]),
            FrameAction::TcpSyn { .. }
        ));
    }
}
