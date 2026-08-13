//! Guest-side generalized Unix-socket bridges (`--expose-socket` /
//! `--mount-socket`).
//!
//! Generalizes the fixed Docker (expose) and SSH-agent (mount) bridges into a
//! user-specified set. On startup the agent reads
//! [`guest_env::PUBLISH_SOCKETS`], decodes the per-socket specs, and starts one
//! relay thread per entry over the vsock port the host assigned it:
//!
//! - **Expose** (guest→host): the agent listens on the vsock port; for each host
//!   connection it dials the in-guest app socket and relays. Same shape as the
//!   Docker bridge.
//! - **Mount** (host→guest): the agent listens on a VM-private Unix socket and, for
//!   each guest-app connection, dials the vsock port (libkrun bridges it to the host
//!   socket) and relays. Same shape as the SSH-agent bridge. The listener node is
//!   *published* at the caller's guest path — bind-mounted there in the VM's root
//!   namespace for bare-VM execs, and injected into every OCI spec for containers —
//!   rather than bound there directly, which would put it inside a `--volume` share
//!   and make co-mounting VMs fight over one node (see [`MOUNT_SOCKET_DIR`]).
//!
//! The relay honors independent TCP-style half-close so hijacked/streaming
//! protocols don't lose output — the same property the Docker bridge fixed.

use smolvm_protocol::guest_env;
use smolvm_protocol::publish_socket::{decode, PublishedSocket, SocketDirection};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::thread;

/// VM-private directory the mount-direction listeners are bound in.
///
/// Never the caller-supplied guest path: that path may sit inside a `--volume`
/// share, where the listener node lands on the *host* filesystem and every other
/// VM mounting the same directory sees — and re-binds — it. Binding privately and
/// republishing the node by bind mount keeps each VM's socket its own.
const MOUNT_SOCKET_DIR: &str = "/run/smolvm/published-sockets";

/// Mount-direction sockets whose listener is bound *and* published at its guest
/// path, written by [`start_all`] before the agent accepts host requests.
///
/// [`inject_into_container`] reads this rather than the env var so a bridge that
/// failed to come up is never bind-mounted into a container: crun rejects a
/// missing mount source, which would turn one broken socket into a VM that can't
/// start any container.
///
/// A [`RwLock`] rather than a `OnceLock`: production writes this exactly once
/// per boot, but the lock lets tests reset it — with `OnceLock`, a single
/// [`start_all`] call in one test would permanently poison the "nothing
/// published yet" invariant for every other test in the process.
static PUBLISHED_MOUNTS: RwLock<Vec<PublishedSocket>> = RwLock::new(Vec::new());

/// Start every user-published socket bridge. No-op when none are configured.
///
/// Mount listeners are prepared here, synchronously, instead of inside their
/// bridge thread: every OCI bundle written later bind-mounts the private socket
/// node, so it has to exist before the agent starts accepting execs.
pub fn start_all() {
    let encoded = match std::env::var(guest_env::PUBLISH_SOCKETS) {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };
    let mut published = Vec::new();
    for sock in decode(&encoded) {
        match sock.direction {
            SocketDirection::Expose => spawn_bridge(sock, serve_expose),
            SocketDirection::Mount => match prepare_mount_listener(&sock) {
                Ok(listener) => {
                    published.push(sock.clone());
                    spawn_bridge(sock, move |s| serve_mount(s, listener));
                }
                Err(e) => log_bridge_error(&sock, &e),
            },
        }
    }
    *PUBLISHED_MOUNTS
        .write()
        .expect("published-sockets registry lock poisoned") = published;
}

#[cfg(target_os = "linux")]
type MountListener = std::os::unix::net::UnixListener;

#[cfg(not(target_os = "linux"))]
type MountListener = ();

/// Run one bridge on its own thread, logging why it stopped.
fn spawn_bridge<F>(sock: PublishedSocket, serve: F)
where
    F: FnOnce(&PublishedSocket) -> io::Result<()> + Send + 'static,
{
    thread::Builder::new()
        .name(format!("publish-sock-{}", sock.vsock_port))
        .spawn(move || {
            if let Err(e) = serve(&sock) {
                log_bridge_error(&sock, &e);
            }
        })
        .ok();
}

fn log_bridge_error(sock: &PublishedSocket, error: &io::Error) {
    tracing::warn!(
        vsock_port = sock.vsock_port,
        guest_path = %sock.guest_path,
        direction = sock.direction.as_str(),
        error = %error,
        "published socket bridge stopped"
    );
}

/// VM-private path the bridge for `vsock_port` listens on.
fn mount_socket_path(vsock_port: u32) -> PathBuf {
    Path::new(MOUNT_SOCKET_DIR).join(format!("{vsock_port}.sock"))
}

/// Inject each host-mounted socket into an OCI container at its public guest path.
///
/// The listener itself lives in the VM-private root namespace. Adding this mount
/// after the user-volume mounts makes the socket visible even when its public path
/// is nested under a volume target.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    let published = PUBLISHED_MOUNTS
        .read()
        .expect("published-sockets registry lock poisoned");
    inject_sockets_into_container(spec, &published);
}

fn inject_sockets_into_container(spec: &mut crate::oci::OciSpec, sockets: &[PublishedSocket]) {
    for sock in sockets {
        spec.add_bind_mount(
            &mount_socket_path(sock.vsock_port).to_string_lossy(),
            &sock.guest_path,
            false,
        );
    }
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

/// Bind the mount-direction listener on its private path and publish that node at
/// the caller-supplied guest path. Returns the bound listener for [`serve_mount`].
///
/// All-or-nothing: on failure nothing is left behind at the private path, so
/// [`inject_into_container`] can't hand a container a dead socket.
#[cfg(target_os = "linux")]
fn prepare_mount_listener(sock: &PublishedSocket) -> io::Result<MountListener> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let guest_path = Path::new(&sock.guest_path);
    if !guest_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest socket path must be absolute",
        ));
    }
    let path = mount_socket_path(sock.vsock_port);
    // A persistent machine's /run survives stop/start, so a previous boot's node
    // can still be sitting here.
    let _ = std::fs::remove_file(&path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&path)?;
    // World-accessible so any uid in the guest can reach the mounted socket,
    // matching the SSH-agent bridge.
    let published = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777))
        .and_then(|()| publish_at_guest_path(&path, guest_path));
    if let Err(e) = published {
        // Leave no stale node behind: an unpublished socket nobody listens on is
        // worse than none — it answers connects with ECONNREFUSED.
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(listener)
}

/// Make the private listener node reachable at the caller-supplied guest path by
/// bind-mounting it there in the VM's root mount namespace.
///
/// Bare-VM execs run in that namespace and have no OCI spec to inject into;
/// containers get the same node through [`inject_into_container`], which layers it
/// over any `--volume` mounted at or above the guest path.
#[cfg(target_os = "linux")]
fn publish_at_guest_path(source: &Path, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A file bind mount needs an existing target. When the guest path sits inside a
    // `--volume` share this placeholder is visible on the host as an empty file;
    // each VM's own bind mount shadows it, so it stays inert.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
    {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket source contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket destination contains NUL",
        )
    })?;
    // SAFETY: source and destination are valid C paths. A file bind mount is
    // private to this VM's mount namespace and keeps bare-VM execs working.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            destination.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Mount: per guest-app connection on the published listener, dial the vsock port
/// (bridged by libkrun to the host socket) and relay. Mirrors the SSH-agent bridge
/// but with a caller-supplied path/port.
#[cfg(target_os = "linux")]
fn serve_mount(sock: &PublishedSocket, listener: MountListener) -> io::Result<()> {
    tracing::info!(
        vsock_port = sock.vsock_port,
        guest_path = %sock.guest_path,
        private_path = %mount_socket_path(sock.vsock_port).display(),
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
fn prepare_mount_listener(_sock: &PublishedSocket) -> io::Result<MountListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "published socket bridges are only supported on Linux guests",
    ))
}

#[cfg(not(target_os = "linux"))]
fn serve_mount(_sock: &PublishedSocket, _listener: MountListener) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "published socket bridges are only supported on Linux guests",
    ))
}

#[cfg(test)]
mod mount_tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    fn spec() -> OciSpec {
        OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        )
    }

    fn mount_sock(vsock_port: u32, guest_path: &str) -> PublishedSocket {
        PublishedSocket {
            vsock_port,
            guest_path: guest_path.into(),
            direction: SocketDirection::Mount,
        }
    }

    #[test]
    fn listeners_bind_outside_the_caller_supplied_path() {
        // The bug this guards: binding at the guest path puts the listener node
        // inside a `--volume` share, where every VM sharing it collides.
        let path = mount_socket_path(6100);
        assert!(path.starts_with(MOUNT_SOCKET_DIR));
        assert_ne!(path, mount_socket_path(6101));
    }

    #[test]
    fn nothing_is_injected_before_the_bridges_are_published() {
        // An injected mount whose source doesn't exist fails `crun create`, so a
        // bridge that never came up must not reach the spec at all.
        // Reset the registry explicitly: the invariant being guarded is about
        // what the registry *contains*, not about test execution order.
        PUBLISHED_MOUNTS
            .write()
            .expect("published-sockets registry lock poisoned")
            .clear();
        let mut spec = spec();
        let baseline = spec.mounts.len();
        inject_into_container(&mut spec);
        assert_eq!(spec.mounts.len(), baseline);
    }

    #[test]
    fn container_injection_overlays_mount_socket_after_user_volume() {
        let mut spec = spec();
        spec.add_bind_mount("/mnt/virtiofs/shared", "/run/control", false);
        let volume_index = spec.mounts.len() - 1;

        inject_sockets_into_container(&mut spec, &[mount_sock(6100, "/run/control/engine.sock")]);

        let socket_index = spec
            .mounts
            .iter()
            .position(|mount| mount.destination == "/run/control/engine.sock")
            .expect("mount socket injection missing");
        let socket_mount = &spec.mounts[socket_index];
        assert!(
            socket_index > volume_index,
            "socket file mount must overlay the containing user volume"
        );
        assert_eq!(
            socket_mount.source,
            mount_socket_path(6100).to_string_lossy()
        );
        assert_eq!(socket_mount.mount_type.as_deref(), Some("bind"));
    }
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
