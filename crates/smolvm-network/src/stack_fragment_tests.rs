use super::*;
use crate::udp_publish::{InboundUdpDatagram, PublishedUdpTable};
use std::collections::BTreeMap;
use std::sync::mpsc;

struct Gateway {
    config: VirtioPollConfig,
    queues: Arc<NetworkFrameQueues>,
    device: VirtioNetworkDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
}

impl Gateway {
    fn new() -> Self {
        let config = VirtioPollConfig {
            gateway_mac: [2, 0, 0, 0, 0, 1],
            guest_mac: [2, 0, 0, 0, 0, 2],
            gateway_ipv4: Ipv4Addr::new(100, 96, 0, 1),
            guest_ipv4: Ipv4Addr::new(100, 96, 0, 2),
            prefix_len4: 30,
            gateway_ipv6: "fd00::1".parse().unwrap(),
            guest_ipv6: "fd00::2".parse().unwrap(),
            prefix_len6: 64,
            upstream_dns: Ipv4Addr::new(1, 1, 1, 1),
            upstream_resolvers: [None; crate::MAX_UPSTREAM_RESOLVERS],
            host_service: None,
            intercept: None,
            request_rules: false,
            mtu: 1500,
        };
        let queues = NetworkFrameQueues::shared(256);
        let mut device = VirtioNetworkDevice::new(queues.clone(), config.mtu);
        let interface = create_interface(&mut device, &config, 7);
        let mut gateway = Self {
            config,
            queues,
            device,
            interface,
            sockets: SocketSet::new(vec![]),
        };
        let mut arp = Vec::new();
        arp.extend_from_slice(&config.gateway_mac);
        arp.extend_from_slice(&config.guest_mac);
        arp.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
        arp.extend_from_slice(&config.guest_mac);
        arp.extend_from_slice(&config.guest_ipv4.octets());
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&config.gateway_ipv4.octets());
        gateway.ingress(arp);
        while gateway.queues.host_to_guest.pop().is_some() {}
        gateway
    }

    fn ingress(&mut self, frame: Vec<u8>) {
        self.queues.guest_to_host.push(frame).unwrap();
        self.device.stage_next_frame().unwrap();
        self.interface
            .poll_ingress_single(Instant::ZERO, &mut self.device, &mut self.sockets);
    }

    fn egress(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        // Also drive the pending fragmenter after the socket has drained.
        for _ in 0..256 {
            self.interface
                .poll_egress(Instant::ZERO, &mut self.device, &mut self.sockets);
            while let Some(frame) = self.queues.host_to_guest.pop() {
                assert!(frame.len() <= 1514, "fragment exceeds link MTU");
                frames.push(frame);
            }
        }
        frames
    }
}

fn published_fragments(payloads: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut gateway = Gateway::new();
    let mut table =
        PublishedUdpTable::new(gateway.config.gateway_ipv4, gateway.config.guest_ipv4, 123);
    let (tx, rx) = mpsc::sync_channel(payloads.len());
    for (index, payload) in payloads.iter().enumerate() {
        tx.send(InboundUdpDatagram {
            host_port: 9000,
            guest_port: 9001,
            client: SocketAddr::from(([127, 0, 0, 1], 10000 + index as u16)),
            payload: payload.clone(),
        })
        .unwrap();
    }
    table.deliver_inbound(&mut gateway.sockets, &rx);
    gateway.egress()
}

fn reassemble(frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut packets: BTreeMap<u16, BTreeMap<u16, Vec<u8>>> = BTreeMap::new();
    let mut lengths = BTreeMap::new();
    for frame in frames {
        let ethernet = EthernetFrame::new_checked(&frame).unwrap();
        let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        assert!(packets
            .entry(ip.ident())
            .or_default()
            .insert(ip.frag_offset(), ip.payload().to_vec())
            .is_none());
        if !ip.more_frags() {
            lengths.insert(
                ip.ident(),
                usize::from(ip.frag_offset()) + ip.payload().len(),
            );
        }
    }
    packets
        .into_iter()
        .map(|(id, fragments)| {
            let mut packet = Vec::new();
            for (offset, bytes) in fragments {
                assert_eq!(usize::from(offset), packet.len(), "fragment gap for {id}");
                packet.extend_from_slice(&bytes);
            }
            assert_eq!(
                Some(&packet.len()),
                lengths.get(&id),
                "missing final fragment for {id}"
            );
            let udp = UdpPacket::new_checked(&packet).unwrap();
            assert!(udp.verify_checksum(
                &IpAddress::Ipv4(Ipv4Addr::new(100, 96, 0, 1)),
                &IpAddress::Ipv4(Ipv4Addr::new(100, 96, 0, 2)),
            ));
            udp.payload().to_vec()
        })
        .collect()
}

#[test]
fn published_udp_supports_the_maximum_ipv4_payload_at_a_1500_byte_mtu() {
    let payload = (0..65507).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    assert_eq!(
        reassemble(published_fragments(std::slice::from_ref(&payload))),
        vec![payload]
    );
}

#[test]
fn simultaneous_published_datagrams_keep_all_their_fragments() {
    let mut payloads = vec![vec![1; 4096], vec![2; 8192], vec![3; 65507]];
    let mut received = reassemble(published_fragments(&payloads));
    payloads.sort();
    received.sort();
    assert_eq!(received, payloads);
}

fn guest_fragments(gateway: &Gateway, payload: &[u8], id: u16) -> Vec<Vec<u8>> {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&12345u16.to_be_bytes());
    datagram.extend_from_slice(&9000u16.to_be_bytes());
    datagram.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]); // IPv4 permits an omitted UDP checksum.
    datagram.extend_from_slice(payload);
    datagram
        .chunks(1480)
        .enumerate()
        .map(|(index, chunk)| {
            let mut frame = vec![0; 14 + 20 + chunk.len()];
            let mut ethernet = EthernetFrame::new_unchecked(&mut frame[..]);
            ethernet.set_dst_addr(EthernetAddress(gateway.config.gateway_mac));
            ethernet.set_src_addr(EthernetAddress(gateway.config.guest_mac));
            ethernet.set_ethertype(EthernetProtocol::Ipv4);
            let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len((20 + chunk.len()) as u16);
            ip.set_ident(id);
            ip.set_frag_offset((index * 1480) as u16);
            ip.set_more_frags((index + 1) * 1480 < datagram.len());
            ip.set_hop_limit(64);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(gateway.config.guest_ipv4);
            ip.set_dst_addr(Ipv4Addr::new(1, 1, 1, 1));
            ip.payload_mut().copy_from_slice(chunk);
            ip.fill_checksum();
            frame
        })
        .collect()
}

#[test]
fn out_of_order_guest_fragments_deliver_one_complete_udp_datagram() {
    let mut gateway = Gateway::new();
    let payload = (0..65507).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    let mut frames = guest_fragments(&gateway, &payload, 71);
    // Receive the first fragment last: classification still creates the
    // destination socket before smoltcp completes reassembly.
    frames.reverse();
    let mut table = udp_relay::UdpSocketTable::new();
    let (tx, rx) = mpsc::sync_channel(2);
    let count = frames.len();
    for (index, frame) in frames.into_iter().enumerate() {
        match classify_guest_frame(&frame, &[], None) {
            FrameAction::UdpFlow { destination } => {
                assert!(table.ensure_socket(destination, &mut gateway.sockets));
            }
            FrameAction::Passthrough => {}
            other => panic!("unexpected fragment action: {other:?}"),
        }
        gateway.ingress(frame);
        table.drain_to_relay(&mut gateway.sockets, &tx);
        if index + 1 < count {
            assert!(rx.try_recv().is_err(), "partial UDP payload escaped");
        }
    }
    let received = rx.try_recv().unwrap();
    assert_eq!(received.payload, payload);
    assert_eq!(received.destination, "1.1.1.1:9000".parse().unwrap());
    assert_eq!(received.guest.ip(), IpAddr::V4(gateway.config.guest_ipv4));
    assert!(rx.try_recv().is_err());
}

#[test]
fn malformed_guest_fragment_bounds_are_dropped_before_reassembly() {
    let gateway = Gateway::new();
    let mut frame = guest_fragments(&gateway, &[1; 4096], 72).remove(0);
    // Maximum encoded offset plus a full fragment exceeds a legal IPv4 packet.
    Ipv4Packet::new_unchecked(&mut frame[14..]).set_frag_offset(65528);
    assert_eq!(classify_guest_frame(&frame, &[], None), FrameAction::Drop);
    let mut frame = guest_fragments(&gateway, &[1; 4096], 73).remove(0);
    Ipv4Packet::new_unchecked(&mut frame[14..]).set_dont_frag(true);
    assert_eq!(classify_guest_frame(&frame, &[], None), FrameAction::Drop);
}
