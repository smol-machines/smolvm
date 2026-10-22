//! Host side of live port forwarding for machines without virtio-net.
//!
//! TSI binds no host ports, so a machine started without published ports has
//! nothing a later `machine update -p` could extend. Instead each live-published
//! port is a host TCP listener here: every connection it accepts dials the
//! machine's port-forward socket (libkrun bridges it to the guest's
//! [`smolvm_protocol::ports::PORT_FORWARD`] vsock port), names the guest port on
//! one line, and relays both ways.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Host file name of the socket libkrun bridges to the guest forwarder.
pub const PORT_FORWARD_SOCKET: &str = "port-forward.sock";

/// How often an idle listener checks whether it was removed.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

struct Forward {
    /// Guest port each new connection is relayed to; changes in place.
    guest: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
    /// Owns the listener; joined so a removed port is closed once `replace`
    /// returns, not up to an accept poll later.
    accepting: std::thread::JoinHandle<()>,
}

/// The live-published ports of one running machine.
#[derive(Clone)]
pub struct PortForwarder {
    socket: PathBuf,
    forwards: Arc<Mutex<HashMap<u16, Forward>>>,
}

impl PortForwarder {
    /// A forwarder that relays through `socket`, publishing nothing yet.
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
            forwards: Arc::default(),
        }
    }

    /// Publish exactly `ports` (`(host, guest)` pairs): new host ports start
    /// accepting, a kept host port moved to another guest port relays new
    /// connections there, and removed ones are closed by the time this returns
    /// (connections already accepted carry on). Every new port is bound before
    /// anything changes, so a taken port fails the call with the set as it was.
    pub fn replace(&self, ports: &[(u16, u16)]) -> Result<(), String> {
        let mut forwards = self.forwards.lock().unwrap_or_else(|p| p.into_inner());
        let mut bound = Vec::new();
        for &(host, guest) in ports {
            if forwards.contains_key(&host) {
                continue;
            }
            let listener = TcpListener::bind((publish_addr(), host))
                .map_err(|error| format!("host port {host}: {error}"))?;
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("host port {host}: {error}"))?;
            bound.push((host, guest, listener));
        }
        let wanted: HashMap<u16, u16> = ports.iter().copied().collect();
        let removed: Vec<u16> = forwards
            .keys()
            .filter(|host| !wanted.contains_key(host))
            .copied()
            .collect();
        for host in removed {
            if let Some(forward) = forwards.remove(&host) {
                forward.stop.store(true, Ordering::Relaxed);
                let _ = forward.accepting.join();
            }
        }
        for (host, forward) in forwards.iter() {
            if let Some(&guest) = wanted.get(host) {
                forward.guest.store(guest, Ordering::Relaxed);
            }
        }
        for (host, guest, listener) in bound {
            let guest = Arc::new(AtomicU16::new(guest));
            let stop = Arc::new(AtomicBool::new(false));
            let socket = self.socket.clone();
            let (thread_guest, thread_stop) = (guest.clone(), stop.clone());
            let accepting = std::thread::Builder::new()
                .name(format!("port-forward-{host}"))
                .spawn(move || accept_loop(listener, thread_guest, socket, thread_stop))
                .map_err(|error| format!("host port {host}: {error}"))?;
            forwards.insert(
                host,
                Forward {
                    guest,
                    stop,
                    accepting,
                },
            );
        }
        Ok(())
    }
}

/// Published ports bind loopback unless the node widened it, as
/// virtio-net's listeners do (`SMOLVM_PUBLISH_ADDR`).
fn publish_addr() -> Ipv4Addr {
    std::env::var("SMOLVM_PUBLISH_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(Ipv4Addr::LOCALHOST)
}

fn accept_loop(
    listener: TcpListener,
    guest: Arc<AtomicU16>,
    socket: PathBuf,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                let guest = guest.load(Ordering::Relaxed);
                let socket = socket.clone();
                let _ = std::thread::Builder::new()
                    .name("port-forward-conn".into())
                    .spawn(move || {
                        if let Err(error) = relay(client, &socket, guest) {
                            tracing::debug!(guest, %error, "port forward ended");
                        }
                    });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(error) => {
                tracing::debug!(guest = guest.load(Ordering::Relaxed), %error, "port forward accept failed");
                std::thread::sleep(ACCEPT_POLL);
            }
        }
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

/// Serve the ports control socket in `vm_dir` with `forwarder`, the way the
/// virtio-net runtime serves it: each request is the full set of mappings.
pub fn serve_forwarded_ports_control(forwarder: PortForwarder, vm_dir: &Path) {
    super::launch::serve_ports_requests(vm_dir, move |next| {
        if next
            .iter()
            .any(|mapping| mapping.protocol == smolvm_network::PortProtocol::Udp)
        {
            return Err("UDP ports can only change while the machine is stopped".to_string());
        }
        let pairs: Vec<(u16, u16)> = next.iter().map(|m| (m.host, m.guest)).collect();
        forwarder.replace(&pairs)
    });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

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
                    let mut body = String::new();
                    let _ = stream.read_to_string(&mut body);
                    let reply = format!("{}:{body}", String::from_utf8_lossy(&header));
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
        let forwarder = PortForwarder::new(&socket);
        let (a, b) = (free_port(), free_port());

        forwarder.replace(&[(a, 8080)]).unwrap();
        assert_eq!(
            ask(a, "hello"),
            "8080:hello",
            "half-close lets the reply finish"
        );

        forwarder.replace(&[(a, 8080), (b, 9090)]).unwrap();
        assert_eq!(ask(b, "x"), "9090:x");

        forwarder.replace(&[(b, 9090)]).unwrap();
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
        let forwarder = PortForwarder::new(&socket);
        let a = free_port();
        forwarder.replace(&[(a, 8080)]).unwrap();
        assert_eq!(ask(a, "one"), "8080:one");
        forwarder.replace(&[(a, 9090)]).unwrap();
        assert_eq!(ask(a, "two"), "9090:two");
    }

    #[test]
    fn a_taken_host_port_fails_the_change_and_keeps_the_old_set() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(PORT_FORWARD_SOCKET);
        fake_guest(&socket);
        let forwarder = PortForwarder::new(&socket);
        let (a, held) = (
            free_port(),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        );
        let taken = held.local_addr().unwrap().port();
        forwarder.replace(&[(a, 80)]).unwrap();
        assert!(forwarder.replace(&[(taken, 81)]).is_err());
        assert_eq!(ask(a, "z"), "80:z");
    }
}
