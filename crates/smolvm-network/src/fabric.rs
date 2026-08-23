//! Inter-VM packet fabric for the virtio-net backend.
//!
//! Context
//! =======
//!
//! Every VM's network stack is a private NAT gateway: guests share one
//! hardcoded address and no path exists between VMs. Joining a named network
//! (`--network <name>`) changes that in three steps, all in this module's
//! vocabulary:
//!
//! - each VM leases a distinct /30 out of `100.96.0.0/16` (guest `.2`,
//!   gateway `.1`), so guests get real, distinct addresses;
//! - each VM's stack listens on a Unix socket named after its subnet inside
//!   the network's registry directory;
//! - a guest packet destined to another VM's subnet is forwarded — as a raw
//!   IP packet, routing rather than L4 relaying — to that subnet's socket,
//!   where the owning stack wraps it in an Ethernet frame toward its guest.
//!
//! The lease IS the bound socket: binding `<dir>/<k>.sock` claims subnet
//! `100.96.k.0/30` for as long as the socket accepts connections. A crashed
//! VM leaves a stale path behind; the next allocator probes it with a
//! connect, and reclaims it when nothing answers. No lease file, no daemon,
//! nothing to garbage-collect but a dead socket path.
//!
//! Wire format between peers: `[4-byte big-endian length][raw IP packet]`,
//! the same framing discipline as the libkrun frame stream.

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use {
    crate::queues::NetworkFrameQueues,
    std::collections::HashMap,
    std::os::unix::net::{UnixListener, UnixStream},
    std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
    std::sync::Arc,
    std::time::Duration,
};

/// The fabric address pool: `100.96.0.0/16`, carved into /30s by the third
/// octet. Subnet index 0 is never leased — it is the default (non-fabric)
/// link every VM uses when no `--network` is given.
pub const FABRIC_OCTETS: [u8; 2] = [100, 96];

/// Largest frameable packet: a fabric peer refusing anything bigger bounds
/// memory per connection and rejects corrupt length prefixes early.
const MAX_PACKET: usize = 65536;

/// One VM's claim on a fabric subnet: addresses for the guest link plus the
/// bound registry socket that *is* the lease.
#[derive(Debug)]
#[cfg(unix)]
pub struct FabricLease {
    /// Subnet index `k` in `100.96.k.0/30`.
    pub index: u8,
    /// Guest address (`100.96.k.2`).
    pub guest_ip: Ipv4Addr,
    /// Gateway address (`100.96.k.1`).
    pub gateway_ip: Ipv4Addr,
    /// The network's registry directory (shared by all members).
    pub dir: PathBuf,
    /// This lease's socket path inside `dir`.
    pub socket_path: PathBuf,
    /// The bound listener peers connect to. Holding it holds the lease.
    pub listener: UnixListener,
}

/// Claim the lowest free /30 in the network rooted at `dir`.
///
/// Binding the subnet's socket is the atomic claim. A path that exists but
/// refuses connections is a dead member's leftover and is reclaimed.
#[cfg(unix)]
pub fn allocate_lease(dir: &Path) -> io::Result<FabricLease> {
    std::fs::create_dir_all(dir)?;
    for index in 1..=u8::MAX {
        let socket_path = dir.join(format!("{index}.sock"));
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                if UnixStream::connect(&socket_path).is_ok() {
                    continue; // live member
                }
                // Dead member's leftover: reclaim, but lose the race politely
                // (another allocator may grab it between unlink and bind).
                let _ = std::fs::remove_file(&socket_path);
                match UnixListener::bind(&socket_path) {
                    Ok(listener) => listener,
                    Err(_) => continue,
                }
            }
            Err(err) => return Err(err),
        };
        return Ok(FabricLease {
            index,
            guest_ip: Ipv4Addr::new(FABRIC_OCTETS[0], FABRIC_OCTETS[1], index, 2),
            gateway_ip: Ipv4Addr::new(FABRIC_OCTETS[0], FABRIC_OCTETS[1], index, 1),
            dir: dir.to_path_buf(),
            socket_path,
            listener,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "network is full: all 255 fabric subnets are leased",
    ))
}

#[cfg(unix)]
impl Drop for FabricLease {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// The fabric subnet index a destination belongs to, if it is a fabric
/// address at all.
pub fn fabric_index(ip: Ipv4Addr) -> Option<u8> {
    let [a, b, k, _] = ip.octets();
    ([a, b] == FABRIC_OCTETS).then_some(k)
}

/// The registry socket path of subnet `k` under `dir`.
pub fn peer_socket_path(dir: &Path, index: u8) -> PathBuf {
    dir.join(format!("{index}.sock"))
}

/// Write one length-prefixed packet.
pub fn write_packet(stream: &mut impl Write, packet: &[u8]) -> io::Result<()> {
    let len = u32::try_from(packet.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(packet)
}

/// Read one length-prefixed packet. `Ok(None)` on clean EOF at a frame
/// boundary; oversized lengths are corruption and error out.
pub fn read_packet(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fabric packet length {len} out of range"),
        ));
    }
    let mut packet = vec![0u8; len];
    stream.read_exact(&mut packet)?;
    Ok(Some(packet))
}

/// Wrap a forwarded IP packet in the Ethernet frame the receiving guest
/// expects from its gateway.
pub fn ethernet_frame_for_guest(
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
    ip_packet: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + ip_packet.len());
    frame.extend_from_slice(&guest_mac);
    frame.extend_from_slice(&gateway_mac);
    frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
    frame.extend_from_slice(ip_packet);
    frame
}

/// How the poll loop hands packets to the fabric: `(destination subnet
/// index, raw IP packet)`. Bounded so a peer outage back-pressures into
/// packet drops (IP semantics) instead of unbounded memory.
#[cfg(unix)]
const SENDER_QUEUE_DEPTH: usize = 2048;

/// Poll cadence for shutdown checks on the otherwise-blocking fabric
/// threads (accept loop and per-peer readers).
#[cfg(unix)]
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

/// The poll loop's view of a running fabric: its own subnet index (so
/// classification can exclude the VM's own /30) and the channel packets are
/// forwarded through.
#[cfg(unix)]
#[derive(Clone)]
pub struct FabricHandle {
    /// This VM's leased subnet index.
    pub own_index: u8,
    sender: SyncSender<(u8, Vec<u8>)>,
}

#[cfg(unix)]
impl FabricHandle {
    /// Queue one guest IP packet for delivery to the subnet `index` peer.
    /// Drops on a full queue: the fabric is best-effort at the IP layer, and
    /// transports above it retransmit.
    pub fn forward(&self, index: u8, packet: Vec<u8>) {
        match self.sender.try_send((index, packet)) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// Start the fabric threads for a leased subnet: an accept loop delivering
/// peer packets to the guest, and a sender draining the poll loop's forward
/// queue to peer sockets. Threads exit when `queues` begins shutdown; the
/// lease (and its registry socket) dies with the accept thread.
#[cfg(unix)]
pub fn start_fabric(
    lease: FabricLease,
    queues: Arc<NetworkFrameQueues>,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) -> io::Result<FabricHandle> {
    let own_index = lease.index;
    let dir = lease.dir.clone();
    let (sender, receiver) = sync_channel::<(u8, Vec<u8>)>(SENDER_QUEUE_DEPTH);

    lease.listener.set_nonblocking(true)?;
    let accept_queues = queues.clone();
    std::thread::Builder::new()
        .name("smolvm-fabric-accept".into())
        .spawn(move || run_accept_loop(lease, accept_queues, gateway_mac, guest_mac))?;

    std::thread::Builder::new()
        .name("smolvm-fabric-send".into())
        .spawn(move || run_sender(dir, receiver, queues))?;

    Ok(FabricHandle { own_index, sender })
}

#[cfg(unix)]
fn run_accept_loop(
    lease: FabricLease,
    queues: Arc<NetworkFrameQueues>,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    loop {
        if queues.is_shutting_down() {
            return; // dropping `lease` unlinks the registry socket
        }
        match lease.listener.accept() {
            Ok((stream, _)) => {
                let reader_queues = queues.clone();
                let _ = std::thread::Builder::new()
                    .name("smolvm-fabric-recv".into())
                    .spawn(move || run_peer_reader(stream, reader_queues, gateway_mac, guest_mac));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(SHUTDOWN_POLL);
            }
            Err(_) => return,
        }
    }
}

/// Deliver one peer connection's packets to the guest. A packet is wrapped
/// in the Ethernet frame the guest expects from its gateway and pushed onto
/// the same queue smoltcp egress uses; a full queue drops the packet.
///
/// The socket carries a short read timeout purely as a shutdown poll. A
/// timeout mid-frame is NOT an error: `read_full` resumes where it left off,
/// because `read_exact` would discard partially-read bytes on timeout and
/// desync the length-prefixed stream (found the hard way: small packets
/// survived, bulk transfers corrupted).
#[cfg(unix)]
fn run_peer_reader(
    stream: UnixStream,
    queues: Arc<NetworkFrameQueues>,
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
) {
    let mut stream = stream;
    let _ = stream.set_read_timeout(Some(SHUTDOWN_POLL));
    loop {
        let mut len_bytes = [0u8; 4];
        match read_full(&mut stream, &mut len_bytes, &queues) {
            Ok(true) => {}
            _ => return, // clean EOF, real error, or shutdown
        }
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_PACKET {
            return; // corrupt peer; drop the connection
        }
        let mut packet = vec![0u8; len];
        match read_full(&mut stream, &mut packet, &queues) {
            Ok(true) => {}
            _ => return,
        }
        let frame = ethernet_frame_for_guest(gateway_mac, guest_mac, &packet);
        if queues.host_to_guest.push(frame).is_ok() {
            queues.host_wake.wake();
        }
    }
}

/// Fill `buf` completely, resuming across poll-timeout wakeups and stopping
/// on shutdown. `Ok(false)` = clean EOF before the first byte; EOF mid-buffer
/// is an error (a torn frame).
#[cfg(unix)]
fn read_full(
    stream: &mut UnixStream,
    buf: &mut [u8],
    queues: &NetworkFrameQueues,
) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        if queues.is_shutting_down() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "shutting down"));
        }
        match stream.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(true)
}

/// Drain forwarded packets to peer registry sockets, connecting on demand
/// and reconnecting once per packet on a stale cached connection (the common
/// case after a peer restart).
#[cfg(unix)]
fn run_sender(dir: PathBuf, receiver: Receiver<(u8, Vec<u8>)>, queues: Arc<NetworkFrameQueues>) {
    let mut connections: HashMap<u8, UnixStream> = HashMap::new();
    for (index, packet) in receiver.iter() {
        if queues.is_shutting_down() {
            return;
        }
        if send_to_peer(&dir, &mut connections, index, &packet).is_err() {
            connections.remove(&index);
            let _ = send_to_peer(&dir, &mut connections, index, &packet);
        }
    }
}

/// A peer that stops draining stalls its connection; cap how long one frame
/// may block the (shared) sender before the connection is torn down. Long
/// enough to ride out scheduling hiccups, short enough that one wedged peer
/// cannot freeze the whole fabric for long.
#[cfg(unix)]
const WRITE_STALL_LIMIT: Duration = Duration::from_secs(5);

#[cfg(unix)]
fn send_to_peer(
    dir: &Path,
    connections: &mut HashMap<u8, UnixStream>,
    index: u8,
    packet: &[u8],
) -> io::Result<()> {
    use std::collections::hash_map::Entry;
    let stream = match connections.entry(index) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(slot) => {
            let stream = UnixStream::connect(peer_socket_path(dir, index))?;
            let _ = stream.set_write_timeout(Some(SHUTDOWN_POLL));
            slot.insert(stream)
        }
    };
    // Frame the packet in one buffer so a partial write can be resumed from
    // an offset; `write_all` under a socket timeout would corrupt the stream
    // mid-frame (the bytes already sent cannot be unsent).
    let mut frame = Vec::with_capacity(4 + packet.len());
    frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
    frame.extend_from_slice(packet);
    write_full(stream, &frame)
}

/// Write `buf` completely, resuming across timeout wakeups; give up (so the
/// caller drops the connection) once a single frame has stalled too long.
#[cfg(unix)]
fn write_full(stream: &mut UnixStream, buf: &[u8]) -> io::Result<()> {
    let start = std::time::Instant::now();
    let mut written = 0;
    while written < buf.len() {
        match stream.write(&buf[written..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => written += n,
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                if start.elapsed() > WRITE_STALL_LIMIT {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Non-Unix stub: named networks need Unix domain sockets for the peer
/// registry; the API surface exists so callers compile, and allocation
/// reports the platform gap.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct FabricLease {
    pub index: u8,
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
}

#[cfg(not(unix))]
#[derive(Clone)]
pub struct FabricHandle {
    pub own_index: u8,
}

#[cfg(not(unix))]
impl FabricHandle {
    pub fn forward(&self, _index: u8, _packet: Vec<u8>) {}
}

#[cfg(not(unix))]
pub fn allocate_lease(_dir: &Path) -> io::Result<FabricLease> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "named inter-VM networks are not supported on this platform yet",
    ))
}

#[cfg(not(unix))]
pub fn start_fabric(
    _lease: FabricLease,
    _queues: std::sync::Arc<crate::queues::NetworkFrameQueues>,
    _gateway_mac: [u8; 6],
    _guest_mac: [u8; 6],
) -> io::Result<FabricHandle> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "named inter-VM networks are not supported on this platform yet",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn leases_are_distinct_and_release_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let first = allocate_lease(tmp.path()).unwrap();
        let second = allocate_lease(tmp.path()).unwrap();
        assert_eq!(first.index, 1);
        assert_eq!(second.index, 2);
        assert_eq!(first.guest_ip, Ipv4Addr::new(100, 96, 1, 2));
        assert_eq!(second.gateway_ip, Ipv4Addr::new(100, 96, 2, 1));

        drop(first);
        let reclaimed = allocate_lease(tmp.path()).unwrap();
        assert_eq!(reclaimed.index, 1);
    }

    #[test]
    fn stale_socket_from_a_dead_member_is_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        // A dead member: closing a listener does not unlink its path, so the
        // path exists but nothing answers — exactly what a crash leaves.
        let corpse = UnixListener::bind(peer_socket_path(tmp.path(), 1)).unwrap();
        drop(corpse);
        assert!(peer_socket_path(tmp.path(), 1).exists());
        let lease = allocate_lease(tmp.path()).unwrap();
        assert_eq!(lease.index, 1);
    }

    #[test]
    fn packet_codec_round_trips() {
        let mut wire = Vec::new();
        write_packet(&mut wire, b"hello fabric").unwrap();
        let mut reader = wire.as_slice();
        assert_eq!(
            read_packet(&mut reader).unwrap().as_deref(),
            Some(&b"hello fabric"[..])
        );
        assert_eq!(read_packet(&mut reader).unwrap(), None); // clean EOF
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(MAX_PACKET as u32 + 1).to_be_bytes());
        assert!(read_packet(&mut wire.as_slice()).is_err());
    }

    #[test]
    fn fabric_index_only_matches_the_pool() {
        assert_eq!(fabric_index(Ipv4Addr::new(100, 96, 7, 2)), Some(7));
        assert_eq!(fabric_index(Ipv4Addr::new(100, 97, 7, 2)), None);
        assert_eq!(fabric_index(Ipv4Addr::new(10, 96, 7, 2)), None);
    }

    #[test]
    fn packets_flow_between_two_fabrics() {
        let tmp = tempfile::tempdir().unwrap();
        let lease_a = allocate_lease(tmp.path()).unwrap();
        let lease_b = allocate_lease(tmp.path()).unwrap();
        let b_index = lease_b.index;
        let queues_a = NetworkFrameQueues::shared(64);
        let queues_b = NetworkFrameQueues::shared(64);
        let a = start_fabric(lease_a, queues_a.clone(), [1; 6], [2; 6]).unwrap();
        let _b = start_fabric(lease_b, queues_b.clone(), [3; 6], [4; 6]).unwrap();

        let packet = vec![0x45, 0x00, 0x00, 0x14, 0xAA, 0xBB];
        a.forward(b_index, packet.clone());

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(frame) = queues_b.host_to_guest.pop() {
                assert_eq!(&frame[..6], &[4; 6]); // B's guest MAC
                assert_eq!(&frame[6..12], &[3; 6]); // B's gateway MAC
                assert_eq!(&frame[14..], packet.as_slice());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "packet never reached the peer queue"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        queues_a.begin_shutdown();
        queues_b.begin_shutdown();
    }

    #[test]
    fn guest_frame_carries_macs_and_ethertype() {
        let frame = ethernet_frame_for_guest([1; 6], [2; 6], &[0x45, 0, 0, 20]);
        assert_eq!(&frame[..6], &[2; 6]); // destination = guest
        assert_eq!(&frame[6..12], &[1; 6]); // source = gateway
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(&frame[14..], &[0x45, 0, 0, 20]);
    }
}
