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
use std::io::{Read, Write};
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
    let mut buf = [0u8; 65536];
    loop {
        let n = client_read.read(&mut buf)?;
        if n == 0 {
            break;
        }
        tunnel.write_all(&buf[..n])?;
    }
    let _ = tunnel.shutdown(Shutdown::Write);
    let _ = back.join();
    Ok(())
}

/// Serve the ports control socket in `vm_dir` with `ports`, the way the
/// virtio-net runtime serves it: each request is the full set of mappings.
pub fn serve_forwarded_ports_control(forwarder: PortForwarder, vm_dir: &Path) {
    super::launch::serve_ports_requests(vm_dir, move |next| {
        if next
            .iter()
            .any(|mapping| mapping.protocol == smolvm_network::PortProtocol::Udp)
        {
            return Err("UDP ports can only change while the machine is stopped".to_string());
        }
        forwarder.replace(next)
    });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::time::Duration;

    /// A stand-in for libkrun's bridge: accepts on the forward socket, reads
    /// the port line, and echoes the rest back prefixed with that port.
    fn fake_guest(socket: &Path) {
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                std::thread::spawn(move || {
                    let mut header = Vec::new();
                    let mut byte = [0u8; 1];
                    while stream.read_exact(&mut byte).is_ok() && byte[0] != b'\n' {
                        header.push(byte[0]);
                    }
                    let header = String::from_utf8_lossy(&header).to_string();
                    let mut body = String::new();
                    let _ = stream.read_to_string(&mut body);
                    let reply = format!("{header}:{body}");
                    let _ = stream.write_all(reply.as_bytes());
                });
            }
        });
    }

    fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn ask(port: u16, body: &str) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
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
        let (a, b) = (free_port(), free_port());

        forwarder.replace(&[PortMapping::new(a, 8080)]).unwrap();
        assert_eq!(
            ask(a, "hello"),
            "8080:hello",
            "half-close lets the reply finish"
        );

        forwarder
            .replace(&[PortMapping::new(a, 8080), PortMapping::new(b, 9090)])
            .unwrap();
        assert_eq!(ask(b, "x"), "9090:x");

        forwarder.replace(&[PortMapping::new(b, 9090)]).unwrap();
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
                !reply.starts_with("8080:"),
                "a removed port stops: {reply:?}"
            );
        }
        assert_eq!(ask(b, "y"), "9090:y", "a kept port keeps serving");
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
        let a = free_port();
        forwarder.replace(&[PortMapping::new(a, 8080)]).unwrap();
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
        let a = free_port();
        forwarder.replace(&[PortMapping::new(a, 80)]).unwrap();
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
        let (a, held) = (
            free_port(),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        );
        let taken = held.local_addr().unwrap().port();
        forwarder.replace(&[PortMapping::new(a, 80)]).unwrap();
        assert!(forwarder.replace(&[PortMapping::new(taken, 81)]).is_err());
        assert_eq!(ask(a, "z"), "80:z");
    }
}
