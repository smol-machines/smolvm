//! Guest-side generalized Unix-socket bridges (`--expose-socket` /
//! `--mount-socket` / `--publish-socket`).
//!
//! Generalizes the fixed Docker (expose) and SSH-agent (mount) bridges into a
//! user-specified set. On startup the agent reads
//! [`guest_env::PUBLISH_SOCKETS`], decodes the per-socket specs, and starts one
//! relay thread per entry over the vsock port the host assigned it:
//!
//! - **Expose** (guest→host): the agent listens on the vsock port; for each host
//!   connection it dials the in-guest app socket and relays. Same shape as the
//!   Docker bridge.
//! - **Mount** (host→guest): the agent creates a Unix listener at the guest path;
//!   for each guest-app connection it dials the vsock port (libkrun bridges it to
//!   the host socket) and relays. Same shape as the SSH-agent bridge.
//! - **Publish** (guest→host): like `Expose`, but for each host connection the
//!   agent dials a TCP port on the guest loopback instead of a Unix socket path,
//!   so a guest TCP service is reachable through a host socket file.
//!
//! The relay honors independent TCP-style half-close so hijacked/streaming
//! protocols don't lose output — the same property the Docker bridge fixed.

use smolvm_protocol::guest_env;
use smolvm_protocol::publish_socket::{decode, PublishedSocket, SocketDirection};
use std::io;
use std::thread;

/// Start every user-published socket bridge. No-op when none are configured.
pub fn start_all() {
    let encoded = match std::env::var(guest_env::PUBLISH_SOCKETS) {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };
    for sock in decode(&encoded) {
        start_one(sock);
    }
}

fn start_one(sock: PublishedSocket) {
    thread::Builder::new()
        .name(format!("publish-sock-{}", sock.vsock_port))
        .spawn(move || {
            let result = match sock.direction {
                SocketDirection::Expose => serve_expose(&sock),
                SocketDirection::Mount => serve_mount(&sock),
                SocketDirection::Publish => serve_publish(&sock),
            };
            if let Err(e) = result {
                tracing::warn!(
                    vsock_port = sock.vsock_port,
                    guest_path = %sock.guest_path,
                    direction = sock.direction.as_str(),
                    error = %e,
                    "published socket bridge stopped"
                );
            }
        })
        .ok();
}

/// Expose: listen on the vsock port; per host connection, dial the in-guest app
/// socket and relay. Mirrors the Docker bridge but with a caller-supplied path.
#[cfg(target_os = "linux")]
fn serve_expose(sock: &PublishedSocket) -> io::Result<()> {
    use std::os::unix::net::UnixStream;

    let listener = crate::vsock::VsockListener::bind(sock.vsock_port)?;
    tracing::info!(
        vsock_port = sock.vsock_port,
        guest_path = %sock.guest_path,
        "expose-socket bridge listening"
    );
    loop {
        let host_conn = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                // A bad listener fd is terminal; per-connection errors are not.
                if e.kind() == io::ErrorKind::InvalidInput {
                    return Err(e);
                }
                continue;
            }
        };
        let guest_path = sock.guest_path.clone();
        thread::Builder::new()
            .name("expose-sock-fwd".into())
            .spawn(move || match UnixStream::connect(&guest_path) {
                Ok(app) => {
                    if let Err(e) = relay(host_conn, app) {
                        tracing::debug!(error = %e, "expose-socket relay ended");
                    }
                }
                // Guest app not up yet (or ever): drop the connection. The host
                // client sees a connection reset, same as connecting to a socket
                // whose server isn't running — no start-order coupling.
                Err(e) => tracing::debug!(
                    guest_path = %guest_path,
                    error = %e,
                    "expose-socket: in-guest app socket not reachable"
                ),
            })
            .ok();
    }
}

/// How long a publish bridge waits for the guest TCP dial. A loopback connect
/// either succeeds or is refused immediately; the timeout only bounds the case
/// where the port is firewalled to silently drop, which would otherwise pin the
/// forwarder thread until the kernel gives up.
#[cfg(target_os = "linux")]
const PUBLISH_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Publish: listen on the vsock port; per host connection, dial the guest TCP
/// port on loopback and relay. `serve_expose` with a TCP target — the workload
/// must listen on the guest loopback or on all interfaces.
#[cfg(target_os = "linux")]
fn serve_publish(sock: &PublishedSocket) -> io::Result<()> {
    use std::net::{SocketAddr, TcpStream};

    // Validated by the host and by `decode`; a missing port here is a bug, and
    // a terminal one for this bridge.
    let guest_port = sock.guest_port().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid publish target '{}'", sock.guest_path),
        )
    })?;
    let guest_addr = SocketAddr::from(([127, 0, 0, 1], guest_port));
    let listener = crate::vsock::VsockListener::bind(sock.vsock_port)?;
    tracing::info!(
        vsock_port = sock.vsock_port,
        guest_port,
        "publish-socket bridge listening"
    );
    loop {
        let host_conn = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                // A bad listener fd is terminal; per-connection errors are not.
                if e.kind() == io::ErrorKind::InvalidInput {
                    return Err(e);
                }
                continue;
            }
        };
        thread::Builder::new()
            .name("publish-sock-fwd".into())
            .spawn(
                move || match TcpStream::connect_timeout(&guest_addr, PUBLISH_DIAL_TIMEOUT) {
                    Ok(app) => {
                        if let Err(e) = relay(host_conn, app) {
                            tracing::debug!(error = %e, "publish-socket relay ended");
                        }
                    }
                    // No listener on the guest port yet (or ever): drop the
                    // connection. The host client sees a connection reset, same as
                    // the expose bridge — no start-order coupling.
                    Err(e) => tracing::debug!(
                        guest_port,
                        error = %e,
                        "publish-socket: guest TCP port not reachable"
                    ),
                },
            )
            .ok();
    }
}

/// Mount: create a Unix listener at the guest path; per guest-app connection,
/// dial the vsock port (bridged by libkrun to the host socket) and relay.
/// Mirrors the SSH-agent bridge but with a caller-supplied path/port.
#[cfg(target_os = "linux")]
fn serve_mount(sock: &PublishedSocket) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let path = std::path::Path::new(&sock.guest_path);
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    // World-accessible so any uid in the guest can reach the mounted socket,
    // matching the SSH-agent bridge.
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777));
    tracing::info!(
        vsock_port = sock.vsock_port,
        guest_path = %sock.guest_path,
        "mount-socket bridge listening"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(app_conn) => {
                let port = sock.vsock_port;
                thread::Builder::new()
                    .name("mount-sock-fwd".into())
                    .spawn(move || match crate::vsock::connect(port) {
                        Ok(host) => {
                            if let Err(e) = relay(app_conn, host) {
                                tracing::debug!(error = %e, "mount-socket relay ended");
                            }
                        }
                        Err(e) => tracing::debug!(
                            vsock_port = port,
                            error = %e,
                            "mount-socket: host endpoint not reachable"
                        ),
                    })
                    .ok();
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::InvalidInput {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Generic bidirectional relay with independent half-close, modeled on the
/// Docker bridge's `relay_to_daemon`: a FIN on one read side is mirrored to the
/// peer's write half while the other direction keeps flowing until it too
/// closes. Works over any pair of `Read + Write + AsRawFd` streams (vsock or
/// Unix), so both bridge directions share one implementation.
#[cfg(target_os = "linux")]
fn relay<A, B>(mut a: A, mut b: B) -> io::Result<()>
where
    A: io::Read + io::Write + std::os::unix::io::AsRawFd,
    B: io::Read + io::Write + std::os::unix::io::AsRawFd,
{
    let a_fd = a.as_raw_fd();
    let b_fd = b.as_raw_fd();
    let mut buf = [0u8; 65536];

    let mut a_read_open = true;
    let mut b_read_open = true;

    while a_read_open || b_read_open {
        let mut poll_fds = [
            libc::pollfd {
                // A negative fd is ignored by poll(), so a closed read side stops
                // waking the loop while the other direction drains.
                fd: if a_read_open { a_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if b_read_open { b_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // a → b
        if a_read_open && poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = a.read(&mut buf)?;
            if n == 0 {
                a_read_open = false;
                // Deliver EOF to b's write half; keep pumping b → a.
                // SAFETY: b_fd is the valid, open fd owned by `b`.
                unsafe { libc::shutdown(b_fd, libc::SHUT_WR) };
            } else {
                b.write_all(&buf[..n])?;
            }
        }

        // b → a
        if b_read_open && poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = b.read(&mut buf)?;
            if n == 0 {
                b_read_open = false;
                // SAFETY: a_fd is the valid, open fd owned by `a`.
                unsafe { libc::shutdown(a_fd, libc::SHUT_WR) };
            } else {
                a.write_all(&buf[..n])?;
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn serve_expose(_sock: &PublishedSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "published socket bridges are only supported on Linux guests",
    ))
}

#[cfg(not(target_os = "linux"))]
fn serve_mount(_sock: &PublishedSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "published socket bridges are only supported on Linux guests",
    ))
}

#[cfg(not(target_os = "linux"))]
fn serve_publish(_sock: &PublishedSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "published socket bridges are only supported on Linux guests",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::relay;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::thread;

    /// The customer's exact failure mode (vmlab-smolvm, hijacked `docker
    /// run`/`exec` with no stdin): the client half-closes its write side
    /// *before* the server has finished streaming, and the server's output must
    /// still be delivered. The relay must mirror the FIN without tearing down the
    /// other direction. If it treated half-close as a full close, the streamed
    /// output would be silently dropped (exit codes stay correct, hiding it).
    #[test]
    fn relay_preserves_output_after_client_half_close() {
        // client <-> a  ==relay==  b <-> server
        let (mut client, a) = UnixStream::pair().unwrap();
        let (b, mut server) = UnixStream::pair().unwrap();

        let relay_thread = thread::spawn(move || {
            let _ = relay(a, b);
        });

        // Server: wait for the client's FIN (read to EOF), THEN stream a large
        // response back — the "daemon still streaming after 101 UPGRADED" case.
        let payload = vec![b'Z'; 256 * 1024];
        let expected = payload.clone();
        let server_thread = thread::spawn(move || {
            let mut sink = Vec::new();
            server.read_to_end(&mut sink).unwrap(); // sees the mirrored FIN
            server.write_all(&payload).unwrap();
            // Drop closes the write half → relay finishes cleanly.
        });

        // Client: send a request, then half-close its write side with no more to
        // send (docker attach with no stdin), then read the streamed response.
        client
            .write_all(b"GET /streaming HTTP/1.1\r\n\r\n")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();

        server_thread.join().unwrap();
        relay_thread.join().unwrap();

        assert_eq!(
            got,
            expected,
            "streamed output after a client half-close must not be dropped ({} of {} bytes)",
            got.len(),
            expected.len()
        );
    }

    /// Symmetric case: the server half-closes first while the client keeps
    /// sending. The other direction must keep flowing until it closes too.
    #[test]
    fn relay_preserves_input_after_server_half_close() {
        let (mut client, a) = UnixStream::pair().unwrap();
        let (b, mut server) = UnixStream::pair().unwrap();

        let relay_thread = thread::spawn(move || {
            let _ = relay(a, b);
        });

        let request = vec![b'Q'; 128 * 1024];
        let expected = request.clone();
        let server_thread = thread::spawn(move || {
            // Server writes a short reply, half-closes its write side, then keeps
            // reading the client's request to completion.
            server.write_all(b"ACK").unwrap();
            server.shutdown(Shutdown::Write).unwrap();
            let mut sink = Vec::new();
            server.read_to_end(&mut sink).unwrap();
            sink
        });

        let mut ack = [0u8; 3];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ACK");
        client.write_all(&request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let server_saw = server_thread.join().unwrap();
        relay_thread.join().unwrap();
        assert_eq!(
            server_saw, expected,
            "client input after a server half-close must not be dropped"
        );
    }

    /// The publish-socket shape: one relay leg is a real TCP stream. The client
    /// (host side, Unix) half-closes after its request; the FIN must cross the
    /// TCP leg so the guest server sees EOF, and the server's streamed response
    /// must still be delivered — then the reverse close drains cleanly.
    #[test]
    fn relay_bridges_unix_to_tcp_with_half_close() {
        use std::net::{TcpListener, TcpStream};

        // client <-> a  ==relay==  tcp_client <-> tcp_server
        let (mut client, a) = UnixStream::pair().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let tcp_client = TcpStream::connect(addr).unwrap();
        let (mut tcp_server, _) = listener.accept().unwrap();

        let relay_thread = thread::spawn(move || {
            let _ = relay(a, tcp_client);
        });

        let payload = vec![b'T'; 256 * 1024];
        let expected = payload.clone();
        let server_thread = thread::spawn(move || {
            let mut request = Vec::new();
            tcp_server.read_to_end(&mut request).unwrap(); // sees the mirrored FIN
            tcp_server.write_all(&payload).unwrap();
            request
        });

        client.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();

        let request = server_thread.join().unwrap();
        relay_thread.join().unwrap();
        assert_eq!(request, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            got.len(),
            expected.len(),
            "streamed TCP output after a client half-close must not be dropped"
        );
        assert_eq!(got, expected);
    }

    /// Ordinary bidirectional echo — a plain request/response with no early
    /// half-close, the `docker version`/`pull` / `compose up` shape.
    #[test]
    fn relay_full_duplex_request_response() {
        let (mut client, a) = UnixStream::pair().unwrap();
        let (b, mut server) = UnixStream::pair().unwrap();

        let relay_thread = thread::spawn(move || {
            let _ = relay(a, b);
        });
        let server_thread = thread::spawn(move || {
            let mut req = [0u8; 5];
            server.read_exact(&mut req).unwrap();
            server.write_all(b"pong").unwrap();
            // Close both halves to end the relay.
        });

        client.write_all(b"ping!").unwrap();
        // Close the write half so the relay's read side EOFs and it can exit
        // (a real client closes when done; without this the relay never returns).
        client.shutdown(Shutdown::Write).unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();

        server_thread.join().unwrap();
        relay_thread.join().unwrap();
        assert_eq!(&resp, b"pong");
    }
}
