//! Host side of live port forwarding for machines without virtio-net.
//!
//! TSI binds no host ports, so a machine started without published ports has
//! nothing a later `machine update -p` could extend. Instead each live-published
//! port is a host TCP listener here: every connection it accepts dials the
//! machine's port-forward socket (libkrun bridges it to the guest's
//! [`smolvm_protocol::ports::PORT_FORWARD`] vsock port), names the guest port on
//! one line, and relays both ways. Every listener is accepted on one shared
//! thread ([`TcpAcceptorSet`]), so the number of ports costs sockets, not threads.
//!
//! TCP only. A UDP server inside a TSI machine cannot answer a client that is
//! also inside it: TSI routes a datagram reply to the host unless the guest
//! has a socket bound to the destination in the sender's own network
//! namespace, which a container's reply to a forwarder never has. UDP ports are
//! published on virtio-net machines, whose host stack carries them.

use smolvm_network::acceptor::{AcceptedConnection, BoundTcpPorts, TcpAcceptorSet};
use smolvm_network::{PortMapping, PortProtocol};
use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::Arc;

/// Host file name of the socket libkrun bridges to the guest forwarder.
pub const PORT_FORWARD_SOCKET: &str = "port-forward.sock";

/// The live-published ports of one running machine.
#[derive(Clone)]
pub struct PortForwarder {
    tcp: Arc<TcpAcceptorSet>,
}

impl PortForwarder {
    /// A forwarder that relays through `socket`, publishing nothing yet.
    pub fn new(socket: &Path) -> std::io::Result<Self> {
        let socket = socket.to_path_buf();
        let tcp = TcpAcceptorSet::start(
            BoundTcpPorts::bind(&[])?,
            Box::new(move |connection: AcceptedConnection| {
                let socket = socket.clone();
                let guest = connection.guest_port;
                let _ = std::thread::Builder::new()
                    .name("port-forward-conn".into())
                    .spawn(move || {
                        if let Err(error) = relay(connection.stream, &socket, guest) {
                            tracing::debug!(guest, %error, "port forward ended");
                        }
                    });
            }),
        )?;
        Ok(Self { tcp: Arc::new(tcp) })
    }

    /// Publish exactly `ports` (TCP): new host ports start accepting, a kept
    /// host port moved to another guest port relays new connections there, and
    /// removed ones are closed by the time this returns (connections already
    /// accepted carry on). Every new port is bound before anything changes, so
    /// a taken port fails the call with the set as it was.
    pub fn replace(&self, ports: &[PortMapping]) -> Result<(), String> {
        if let Some(udp) = ports.iter().find(|m| m.protocol == PortProtocol::Udp) {
            return Err(format!(
                "{}:{}/udp: UDP ports are published only on the virtio-net backend",
                udp.host, udp.guest
            ));
        }
        self.tcp.replace(ports).map_err(|error| error.to_string())
    }

    /// Publish an OS-allocated loopback TCP listener without a bind race.
    pub fn publish_atomic(&self, guest: u16) -> Result<PortMapping, String> {
        self.tcp
            .publish_atomic(guest)
            .map_err(|error| error.to_string())
    }

    /// The forwarded mappings.
    pub fn mappings(&self) -> Vec<PortMapping> {
        self.tcp.mappings()
    }
}

fn relay(client: TcpStream, socket: &Path, guest: u16) -> std::io::Result<()> {
    client.set_nonblocking(false)?;
    let mut tunnel = crate::platform::uds::UdsStream::connect(socket)?;
    tunnel.write_all(format!("{guest}\n").as_bytes())?;
    let mut tunnel_read = tunnel.try_clone()?;
    let mut client_read = client.try_clone()?;
    let mut client_write = client;
    // Guest to client on its own thread; client to guest here. Each direction
    // mirrors its EOF as a write shutdown so half-closed streams finish.
    let back = std::thread::spawn(move || {
        let _ = std::io::copy(&mut tunnel_read, &mut client_write);
        let _ = client_write.shutdown(Shutdown::Write);
    });
    // Keep the existing 64 KiB transfer buffer; copy also retries interrupted
    // reads rather than abandoning the tunnel while its reply reader is alive.
    let result = std::io::copy(
        &mut std::io::BufReader::with_capacity(65536, &mut client_read),
        &mut tunnel,
    );
    if result.is_ok() {
        // A normal half-close still allows the guest's reply to finish.
        let _ = tunnel.shutdown(Shutdown::Write);
    } else {
        // A reset client or failed tunnel write cannot complete a reply.
        // Wake both readers before joining, including clones of these sockets.
        let _ = tunnel.shutdown(Shutdown::Both);
        let _ = client_read.shutdown(Shutdown::Both);
    }
    let _ = back.join();
    result.map(|_| ())
}

/// Serve the ports control socket in `vm_dir` with `ports`, the way the
/// virtio-net runtime serves it: each request is the full set of mappings.
pub fn serve_forwarded_ports_control(forwarder: PortForwarder, vm_dir: &Path) {
    let allocator = forwarder.clone();
    super::launch::serve_ports_requests(
        vm_dir,
        move |guest| allocator.publish_atomic(guest),
        move |next| {
            if next
                .iter()
                .any(|mapping| mapping.protocol == smolvm_network::PortProtocol::Udp)
            {
                return Err("UDP ports can only change while the machine is stopped".to_string());
            }
            forwarder.replace(next)
        },
    );
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{Ipv4Addr, TcpListener};
    use std::time::Duration;

    /// A stand-in for libkrun's bridge: accepts on the forward socket, reads
    /// the port line, and echoes the rest back prefixed with that port.
    ///
    /// Raises this test process's open-file limit first, as the launcher does
    /// for a machine's VMM: macOS starts a process at 256, and the whole suite
    /// running in parallel ran out, which failed these tests at random. A
    /// failed accept is retried rather than ending the accept thread, which
    /// left every later connection waiting out the 30 s read timeout.
    fn fake_guest(socket: &Path) {
        crate::process::raise_nofile_limit();
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                std::thread::spawn(move || {
                    // Short reads up to a deadline, not one blocking read: on
                    // macOS a read already blocked on a Unix stream socket now
                    // and then misses the peer's half-close (seen about once in
                    // 470 runs under load, the client then waiting out its 30 s
                    // timeout after the relay had sent everything). A fresh read
                    // sees the EOF at once.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                    let deadline = std::time::Instant::now() + Duration::from_secs(30);
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 65536];
                    loop {
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => request.extend_from_slice(&chunk[..n]),
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock
                                        | std::io::ErrorKind::TimedOut
                                        | std::io::ErrorKind::Interrupted
                                ) && std::time::Instant::now() < deadline => {}
                            Err(_) => return,
                        }
                    }
                    let split = request
                        .iter()
                        .position(|b| *b == b'\n')
                        .unwrap_or(request.len());
                    let header = String::from_utf8_lossy(&request[..split]).to_string();
                    let body = String::from_utf8_lossy(request.get(split + 1..).unwrap_or(&[]));
                    let reply = format!("{header}:{body}");
                    let _ = stream.write_all(reply.as_bytes());
                });
            }
        });
    }

    #[test]
    fn a_reset_client_closes_the_guest_request_half() {
        crate::process::raise_nofile_limit();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        let guest_listener = crate::platform::uds::UdsListener::bind(&socket).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = done_tx.send(relay(server, &socket, 8080));
        });
        let mut guest = guest_listener.accept().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"request").unwrap();
        socket2::SockRef::from(&client)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(client);
        let mut received = String::new();
        let result = guest.read_to_string(&mut received);
        let relayed = done_rx.recv_timeout(Duration::from_secs(2));
        // Release the reply reader even if the assertion below fails.
        let _ = guest.shutdown(Shutdown::Both);
        drop(guest);
        worker.join().unwrap();
        assert!(
            result.is_ok(),
            "the guest must see EOF after a client reset: {result:?}; received {received:?}"
        );
        assert!(received.starts_with("8080\n"));
        assert!(
            matches!(relayed, Ok(Err(_))),
            "the relay must finish and report the client error before the guest closes: {relayed:?}"
        );
    }

    #[test]
    fn a_half_closed_large_request_receives_the_entire_reply() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        fake_guest(&socket);
        let forwarder = PortForwarder::new(&socket).unwrap();
        let port = forwarder.publish_atomic(8080).unwrap().host;
        let request = "0123456789abcdef".repeat(16384);
        assert_eq!(ask(port, &request), format!("8080:{request}"));
    }

    #[test]
    fn atomic_publication_keeps_distinct_loopback_listeners_bound() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        fake_guest(&socket);
        let forwarder = PortForwarder::new(&socket).unwrap();
        let a = forwarder.publish_atomic(8000).unwrap();
        let b = forwarder.publish_atomic(8001).unwrap();
        assert_ne!(a.host, 0);
        assert_ne!(a.host, b.host);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, a.host)).is_err());
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, b.host)).is_err());
        assert_eq!(ask(a.host, "first"), "8000:first");
        assert_eq!(ask(b.host, "second"), "8001:second");
        assert_eq!(forwarder.mappings(), vec![a, b]);
        assert!(forwarder.publish_atomic(0).is_err());
        assert_eq!(forwarder.mappings(), vec![a, b]);
    }

    fn ask(port: u16, body: &str) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        // Every port here stays bound from the moment the test has its number,
        // so no other test can take it. A reply that still never comes fails
        // the test instead of hanging it (a test that released its port before
        // binding it again once hung here for four and a half hours).
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    }

    #[test]
    fn ports_are_added_and_removed_while_running_and_reach_their_guest_port() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        fake_guest(&socket);
        let forwarder = PortForwarder::new(&socket).unwrap();
        // Guest ports no other test here uses: a removed host port may be
        // bound by another test at once, and its reply must not pass for ours.

        // Ports the OS picks and the forwarder keeps bound: a port picked and
        // released first could be taken by a parallel test before the
        // forwarder bound it, and the request then reached that test instead.
        let a = forwarder.publish_atomic(7101).unwrap();
        assert_eq!(
            ask(a.host, "hello"),
            "7101:hello",
            "half-close lets the reply finish"
        );

        let b = forwarder.publish_atomic(7102).unwrap();
        assert_eq!(ask(b.host, "x"), "7102:x");
        assert_eq!(ask(a.host, "still"), "7101:still", "adding keeps the first");

        forwarder.replace(&[b]).unwrap();
        let a = a.host;
        let b = b.host;
        // Closed by the time the change returns, not an accept poll later. The
        // freed port may already belong to another test's listener, so what is
        // checked is that nothing on it reaches this machine any more.
        if let Ok(mut stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, a)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = stream.write_all(b"late");
            let _ = stream.shutdown(Shutdown::Write);
            let mut reply = String::new();
            let _ = stream.read_to_string(&mut reply);
            assert!(
                !reply.starts_with("7101:"),
                "a removed port stops: {reply:?}"
            );
        }
        assert_eq!(ask(b, "y"), "7102:y", "a kept port keeps serving");
    }

    /// Moving a published host port to another guest port keeps its listener
    /// rather than binding the port a second time, which failed while the old
    /// listener still held it.
    #[test]
    fn a_host_port_moves_to_another_guest_port_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        fake_guest(&socket);
        let forwarder = PortForwarder::new(&socket).unwrap();
        let a = forwarder.publish_atomic(8080).unwrap().host;
        assert_eq!(ask(a, "one"), "8080:one");
        forwarder.replace(&[PortMapping::new(a, 9090)]).unwrap();
        assert_eq!(ask(a, "two"), "9090:two");
    }

    #[test]
    fn udp_is_refused_with_the_backend_that_carries_it() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        fake_guest(&socket);
        let forwarder = PortForwarder::new(&socket).unwrap();
        let a = forwarder.publish_atomic(80).unwrap().host;
        let err = forwarder
            .replace(&[PortMapping::with_protocol(a, 53, PortProtocol::Udp)])
            .unwrap_err();
        assert!(err.contains("virtio-net"), "{err}");
        assert_eq!(forwarder.mappings(), vec![PortMapping::new(a, 80)]);
    }

    #[test]
    fn a_taken_host_port_fails_the_change_and_keeps_the_old_set() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        fake_guest(&socket);
        let forwarder = PortForwarder::new(&socket).unwrap();
        let a = forwarder.publish_atomic(80).unwrap().host;
        // held by this test for as long as it runs, so it stays taken
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = held.local_addr().unwrap().port();
        assert!(forwarder.replace(&[PortMapping::new(taken, 81)]).is_err());
        assert_eq!(ask(a, "z"), "80:z");
    }
}
