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
//!        - other supported egress -> future phases
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
//!        - other UDP-> drop for now
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
use crate::queues::NetworkFrameQueues;
use crate::tcp_listeners::AcceptedTcpConnection;
use crate::tcp_relay::{spawn_tcp_relay, TcpRelayTable};
use crate::{virtio_net_log, DEFAULT_DNS_ADDR};
use smoltcp::iface::{
    Config, Interface, PollIngressSingleResult, PollResult, SocketHandle, SocketSet,
};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
    Ipv4Packet, TcpPacket, UdpPacket,
};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as HostUdpSocket};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant as StdInstant};

const DNS_SOCKET_PORT: u16 = 53;
const DNS_PACKET_SLOTS: usize = 8;
const DNS_BUFFER_BYTES: usize = 2048;
const DEFAULT_IDLE_TIMEOUT_MS: i32 = 100;

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
    UnsupportedUdp,
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
) -> std::io::Result<JoinHandle<()>> {
    virtio_net_log!(
        "virtio-net: spawning poll thread guest_ip={} gateway_ip={} mtu={}",
        config.guest_ipv4,
        config.gateway_ipv4,
        config.mtu
    );
    thread::Builder::new()
        .name("smolvm-net-poll".into())
        .spawn(move || run_network_stack(queues, config, tcp_receiver))
}

fn run_network_stack(
    queues: Arc<NetworkFrameQueues>,
    config: VirtioPollConfig,
    mut tcp_receiver: Option<Receiver<AcceptedTcpConnection>>,
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
    let dns_socket_handle = add_dns_socket(&mut sockets, config.gateway_ipv4);
    let relay_wake = Arc::new(queues.relay_wake.clone());
    let mut relays = TcpRelayTable::new(None);

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
            // - other UDP: currently unsupported in the MVP
            match classify_guest_frame(frame) {
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
                FrameAction::UnsupportedUdp => {
                    // Phase 1 only supports DNS over UDP. Other UDP traffic is
                    // intentionally dropped until a general UDP relay exists.
                    virtio_net_log!("virtio-net: dropping unsupported guest UDP datagram");
                    device.drop_staged_frame();
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
        process_dns_queries(dns_socket_handle, &mut sockets);

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
    });
    // The interface acts as the gateway and may need to answer packets for
    // destinations other than its directly assigned IP, so the route table and
    // "any IP" mode are opened up accordingly.
    interface
        .routes_mut()
        .add_default_ipv4_route(config.gateway_ipv4)
        .expect("failed to add default IPv4 route");
    interface.set_any_ip(true);
    interface
}

/// add_dns_socket is adding an UDP socket inside smoltcp, so that the guest DNS packet will
/// hit this socket first. It is then proxied to the resolver. Note that this will not cause
/// a host side :53 collesion, because the smoltcp Interface, SocketSet is per VM, and the
/// gateway:53 is for that set of Interface and SocketSet, it is not bind to a host-kernel UDP socket.
fn add_dns_socket(sockets: &mut SocketSet<'_>, gateway_ipv4: Ipv4Addr) -> SocketHandle {
    let rx_meta = vec![PacketMetadata::EMPTY; DNS_PACKET_SLOTS];
    let tx_meta = vec![PacketMetadata::EMPTY; DNS_PACKET_SLOTS];
    let rx_buffer = PacketBuffer::new(rx_meta, vec![0u8; DNS_BUFFER_BYTES]);
    let tx_buffer = PacketBuffer::new(tx_meta, vec![0u8; DNS_BUFFER_BYTES]);
    let mut socket = UdpSocket::new(rx_buffer, tx_buffer);
    socket
        .bind(smoltcp::wire::IpListenEndpoint {
            addr: Some(gateway_ipv4.into()),
            port: DNS_SOCKET_PORT,
        })
        .expect("failed to bind gateway DNS socket");
    sockets.add(socket)
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

fn process_dns_queries(dns_socket_handle: SocketHandle, sockets: &mut SocketSet<'_>) {
    // Phase 1 DNS model:
    // guest UDP/53 -> smoltcp gateway socket -> host UDP socket -> upstream DNS
    //               <-               response bytes               <-
    let upstream_dns = match DEFAULT_DNS_ADDR {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => return,
    };

    let socket = sockets.get_mut::<UdpSocket>(dns_socket_handle);
    while socket.can_recv() {
        let (query, metadata) = match socket.recv() {
            Ok(result) => result,
            Err(_) => break,
        };
        virtio_net_log!(
            "virtio-net: forwarding guest DNS query guest={} local_address={:?} query_len={} upstream_dns={}",
            metadata.endpoint,
            metadata.local_address,
            query.len(),
            upstream_dns
        );
        let response = match forward_dns_query(upstream_dns, query) {
            Ok(response) => response,
            Err(err) => {
                virtio_net_log!("virtio-net: host DNS forwarding failed error={}", err);
                continue;
            }
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

fn classify_guest_frame(frame: &[u8]) -> FrameAction {
    let ethernet = match EthernetFrame::new_checked(frame) {
        Ok(frame) => frame,
        Err(_) => return FrameAction::Passthrough,
    };

    if ethernet.ethertype() != EthernetProtocol::Ipv4 {
        return FrameAction::Passthrough;
    }

    let ipv4 = match Ipv4Packet::new_checked(ethernet.payload()) {
        Ok(packet) => packet,
        Err(_) => return FrameAction::Passthrough,
    };

    match ipv4.next_header() {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp = match TcpPacket::new_checked(ipv4.payload()) {
                Ok(packet) => packet,
                Err(_) => return FrameAction::Passthrough,
            };

            if tcp.syn() && !tcp.ack() {
                FrameAction::TcpSyn {
                    source: SocketAddr::new(std::net::IpAddr::V4(ipv4.src_addr()), tcp.src_port()),
                    destination: SocketAddr::new(
                        std::net::IpAddr::V4(ipv4.dst_addr()),
                        tcp.dst_port(),
                    ),
                }
            } else {
                FrameAction::Passthrough
            }
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp = match UdpPacket::new_checked(ipv4.payload()) {
                Ok(packet) => packet,
                Err(_) => return FrameAction::Passthrough,
            };

            if udp.dst_port() == DNS_SOCKET_PORT {
                FrameAction::DnsQuery
            } else {
                FrameAction::UnsupportedUdp
            }
        }
        _ => FrameAction::Passthrough,
    }
}
