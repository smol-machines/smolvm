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
        use std::os::fd::AsRawFd;
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
