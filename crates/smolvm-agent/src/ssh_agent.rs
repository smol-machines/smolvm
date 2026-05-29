//! Guest-side SSH agent bridge.
//!
//! Listens on a Unix socket inside the VM and relays connections to the
//! host's SSH agent via vsock. Guest applications (git, ssh) connect to
//! this socket transparently via `SSH_AUTH_SOCK`.

use smolvm_protocol::ports;
use std::io;
use std::os::unix::net::UnixListener;
use std::thread;

/// Guest-side path for the SSH agent socket.
pub const GUEST_SSH_AUTH_SOCK: &str = "/tmp/ssh-agent.sock";

/// Start the guest-side SSH agent bridge in a background thread.
///
/// Creates a Unix socket at [`GUEST_SSH_AUTH_SOCK`] and, for each incoming
/// connection, opens a vsock connection to the host-side bridge on
/// [`ports::SSH_AGENT`] and relays bytes bidirectionally.
pub fn start() {
    thread::Builder::new()
        .name("ssh-agent-guest".into())
        .spawn(|| {
            if let Err(e) = run_bridge() {
                tracing::warn!(error = %e, "guest SSH agent bridge stopped");
            }
        })
        .ok();
}

/// Check if SSH agent forwarding is enabled via environment variable.
pub fn is_enabled() -> bool {
    std::env::var("SMOLVM_SSH_AGENT").as_deref() == Ok("1")
}

/// Inject SSH agent forwarding into an OCI container spec.
///
/// When forwarding is enabled (`SMOLVM_SSH_AGENT=1`), bind-mount the
/// guest-side bridge socket into the container at the same path and set
/// `SSH_AUTH_SOCK` so tools inside the container can find it. No-op when
/// forwarding is disabled.
///
/// Rationale: the container lives in its own mount namespace (so
/// `/tmp/ssh-agent.sock` from the VM rootfs is not visible) and gets env
/// from the image + request (not from the agent's own env), so both the
/// file and the variable have to be wired in explicitly.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    inject_into_container_if(spec, is_enabled());
}

/// Testable core of [`inject_into_container`]. Bind-mounts the bridge
/// socket and sets the env var when `enabled` is true; no-op otherwise.
/// Split out so tests can exercise the injection logic without mutating
/// the process-wide `SMOLVM_SSH_AGENT` env variable.
fn inject_into_container_if(spec: &mut crate::oci::OciSpec, enabled: bool) {
    if !enabled {
        return;
    }
    // Bind-mount the socket file; rw because SSH agent protocol is bidirectional.
    spec.add_bind_mount(GUEST_SSH_AUTH_SOCK, GUEST_SSH_AUTH_SOCK, false);
    spec.add_env("SSH_AUTH_SOCK", GUEST_SSH_AUTH_SOCK);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    #[test]
    fn inject_is_noop_when_disabled() {
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
        );
        let mounts_before = spec.mounts.len();
        let envs_before = spec.process.env.len();

        inject_into_container_if(&mut spec, false);

        assert_eq!(spec.mounts.len(), mounts_before);
        assert_eq!(spec.process.env.len(), envs_before);
        assert!(!spec
            .process
            .env
            .iter()
            .any(|e| e.starts_with("SSH_AUTH_SOCK=")));
    }

    #[test]
    fn inject_adds_env_and_mount_when_enabled() {
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
        );

        inject_into_container_if(&mut spec, true);

        // Env must point at the guest-side bridge socket.
        assert!(spec
            .process
            .env
            .iter()
            .any(|e| e == &format!("SSH_AUTH_SOCK={}", GUEST_SSH_AUTH_SOCK)));

        // Mount must bind the socket at the same path inside the container.
        let mount = spec
            .mounts
            .iter()
            .find(|m| m.destination == GUEST_SSH_AUTH_SOCK)
            .expect("bind mount for SSH agent socket not found");
        assert_eq!(mount.source, GUEST_SSH_AUTH_SOCK);
        assert_eq!(mount.mount_type.as_deref(), Some("bind"));
        // rw: the SSH agent protocol is bidirectional.
        assert!(!mount.options.iter().any(|o| o == "ro"));
        assert!(mount.options.iter().any(|o| o == "bind"));
    }

    #[test]
    fn inject_replaces_existing_ssh_auth_sock() {
        // Simulates an image whose config already exports a stale
        // SSH_AUTH_SOCK: we must replace it, not duplicate it — two entries
        // for the same key leaves the effective value shell-dependent.
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
        );
        spec.process
            .env
            .push("SSH_AUTH_SOCK=/stale/path".to_string());

        inject_into_container_if(&mut spec, true);

        let matches: Vec<_> = spec
            .process
            .env
            .iter()
            .filter(|e| e.starts_with("SSH_AUTH_SOCK="))
            .collect();
        assert_eq!(matches.len(), 1, "duplicate SSH_AUTH_SOCK entries");
        assert_eq!(
            matches[0],
            &format!("SSH_AUTH_SOCK={}", GUEST_SSH_AUTH_SOCK)
        );
    }
}

fn run_bridge() -> io::Result<()> {
    let sock_path = std::path::Path::new(GUEST_SSH_AUTH_SOCK);

    // Clean up stale socket
    let _ = std::fs::remove_file(sock_path);

    // Ensure parent directory exists
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(sock_path)?;

    // Make socket accessible to all users in the VM
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o777))?;
    }

    tracing::info!(
        path = GUEST_SSH_AUTH_SOCK,
        vsock_port = ports::SSH_AGENT,
        "guest SSH agent bridge listening"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(local_conn) => {
                thread::Builder::new()
                    .name("ssh-agent-fwd".into())
                    .spawn(move || {
                        if let Err(e) = relay_to_host(local_conn) {
                            tracing::debug!(error = %e, "SSH agent relay ended");
                        }
                    })
                    .ok();
            }
            Err(e) => {
                tracing::debug!(error = %e, "guest SSH agent accept error");
                if e.kind() == io::ErrorKind::InvalidInput {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Connect to the host SSH agent via vsock and relay bytes.
/// Bidirectional relay between a local Unix socket and a vsock connection.
///
/// Uses `poll()` to multiplex reads on both sides, forwarding data in
/// whichever direction is ready. This handles fragmented messages and
/// concurrent I/O correctly — no assumptions about request/response ordering.
#[cfg(target_os = "linux")]
fn relay_to_host(local: std::os::unix::net::UnixStream) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let mut vsock_conn = vsock_connect(ports::SSH_AGENT)?;
    let mut local = local;

    let local_fd = local.as_raw_fd();
    let vsock_fd = vsock_conn.as_raw_fd();

    let mut buf = [0u8; 16384];

    loop {
        let mut poll_fds = [
            libc::pollfd {
                fd: local_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: vsock_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, 30_000) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            // Timeout — SSH agent connections are short-lived, clean up
            break;
        }

        // local → vsock
        if poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let n = io::Read::read(&mut local, &mut buf)?;
            if n == 0 {
                break;
            }
            io::Write::write_all(&mut vsock_conn, &buf[..n])?;
        }

        // vsock → local
        if poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let n = io::Read::read(&mut vsock_conn, &mut buf)?;
            if n == 0 {
                break;
            }
            io::Write::write_all(&mut local, &buf[..n])?;
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn relay_to_host(_local: std::os::unix::net::UnixStream) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SSH agent forwarding only supported on Linux guests",
    ))
}

// ============================================================================
// vsock client connect (guest → host)
// ============================================================================

/// Wrapper around a vsock file descriptor that implements Read + Write.
#[cfg(target_os = "linux")]
struct VsockStream {
    fd: std::os::unix::io::OwnedFd,
}

#[cfg(target_os = "linux")]
impl std::os::unix::io::AsRawFd for VsockStream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
impl io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        unsafe {
            let n = libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len());
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        unsafe {
            let n = libc::write(self.fd.as_raw_fd(), buf.as_ptr() as *const _, buf.len());
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Connect to a vsock port on the host (CID 2).
#[cfg(target_os = "linux")]
fn vsock_connect(port: u32) -> io::Result<VsockStream> {
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const AF_VSOCK: libc::c_int = 40;
    const HOST_CID: u32 = 2;

    #[repr(C)]
    struct sockaddr_vm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(fd);

        let addr = sockaddr_vm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: HOST_CID,
            svm_zero: [0; 4],
        };

        if libc::connect(
            fd.as_raw_fd(),
            &addr as *const sockaddr_vm as *const libc::sockaddr,
            mem::size_of::<sockaddr_vm>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(VsockStream { fd })
    }
}
