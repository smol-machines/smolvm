//! AF_UNIX listener for crun's `--console-socket` handshake.
//!
//! When the agent spawns `crun run --console-socket <path>` for a
//! container with `process.terminal = true`, crun allocates the
//! container's PTY inside the container's user namespace and sends the
//! master fd back to the caller over `path` using `SCM_RIGHTS`. This
//! module implements the caller side of that handshake.
//!
//! See the OCI runtime spec and crun(1) for protocol details.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::pty::PtyMaster;

/// AF_UNIX listener used with `crun run --console-socket <path>`.
///
/// Binds a unix socket at the given path, accepts a single connection
/// from crun, and receives the container's PTY master fd via
/// `SCM_RIGHTS`. The socket file is removed on drop.
pub struct ConsoleSocket {
    listener: UnixListener,
    path: PathBuf,
}

impl ConsoleSocket {
    /// Bind and listen on `path`. Any stale file at the path is removed first.
    pub fn new(path: &Path) -> io::Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// Accept a connection and receive a PTY master fd via `SCM_RIGHTS`.
    ///
    /// Blocks up to `timeout` waiting for crun to connect. Returns the
    /// received fd wrapped as a [`PtyMaster`]. Subsequent reads, writes
    /// and `set_window_size` on that master control the container's PTY.
    pub fn recv_pty_master(&self, timeout: Duration) -> io::Result<PtyMaster> {
        // Wait for a connection with a bounded timeout so a misbehaving crun
        // does not hang the agent indefinitely.
        let lfd = self.listener.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd: lfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "console socket: timed out waiting for crun to connect",
            ));
        }

        let (stream, _addr) = self.listener.accept()?;

        // Receive one byte of payload plus a single SCM_RIGHTS control
        // message containing the PTY master fd. crun (and runc) always send
        // exactly one fd.
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut _,
            iov_len: byte.len(),
        };
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };
        let mut cmsg_buf = vec![0u8; cmsg_space as usize];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_buf.len() as _;

        // SAFETY: msg is fully initialized; iov and cmsg_buf outlive the call.
        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "console socket: control message truncated",
            ));
        }

        // Walk cmsgs looking for SCM_RIGHTS. Close any stray fds we do not expect.
        let mut pty_fd: libc::c_int = -1;
        let mut cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg_ptr.is_null() {
            // SAFETY: cmsg_ptr is a valid pointer returned by CMSG_FIRSTHDR/NXTHDR.
            let level = unsafe { (*cmsg_ptr).cmsg_level };
            let ty = unsafe { (*cmsg_ptr).cmsg_type };
            if level == libc::SOL_SOCKET && ty == libc::SCM_RIGHTS {
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg_ptr) } as *const libc::c_int;
                let fd = unsafe { std::ptr::read_unaligned(data_ptr) };
                if pty_fd < 0 {
                    pty_fd = fd;
                } else {
                    // Already have a master; close any extras defensively.
                    // SAFETY: fd was just handed to us by the kernel via SCM_RIGHTS.
                    unsafe { libc::close(fd) };
                }
            }
            cmsg_ptr = unsafe { libc::CMSG_NXTHDR(&msg, cmsg_ptr) };
        }

        if pty_fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "console socket: no SCM_RIGHTS fd received from crun",
            ));
        }

        // SAFETY: pty_fd was just handed to us by the kernel via SCM_RIGHTS.
        let owned = unsafe { OwnedFd::from_raw_fd(pty_fd) };
        Ok(PtyMaster::from_fd(owned))
    }
}

impl Drop for ConsoleSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::open_pty;
    use std::os::unix::io::RawFd;
    use std::os::unix::net::UnixStream;

    /// Send `fd` to `stream` via SCM_RIGHTS. Mirrors what crun does with
    /// its console socket.
    fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
        let payload = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut _,
            iov_len: payload.len(),
        };
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };
        let mut cmsg_buf = vec![0u8; cmsg_space as usize];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_buf.len() as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            assert!(!cmsg.is_null());
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
            std::ptr::write_unaligned(data, fd);
        }
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[test]
    fn console_socket_recv_round_trips_pty_master() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("console.sock");

        let server = ConsoleSocket::new(&sock_path).expect("bind console socket");

        // Client thread: connect, send a real PTY master fd, drop the local copy.
        let sock_path_cloned = sock_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&sock_path_cloned).expect("connect");
            let (master, _slave) = open_pty(40, 10).expect("open_pty");
            send_fd(&stream, master.as_raw_fd()).expect("send_fd");
            // Keep `master` alive until after sendmsg completes so the kernel
            // does not close the fd before the receiver gets its own reference.
            drop(master);
        });

        let received = server
            .recv_pty_master(Duration::from_secs(5))
            .expect("recv_pty_master");
        client_thread.join().unwrap();

        // The received fd should be a usable PTY master: we can resize it and
        // read the new size back via TIOCGWINSZ.
        received.set_window_size(100, 50).expect("set_window_size");
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(received.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
        assert_eq!(rc, 0, "TIOCGWINSZ must succeed on received master");
        assert_eq!(ws.ws_col, 100);
        assert_eq!(ws.ws_row, 50);
    }

    #[test]
    fn console_socket_recv_times_out_when_no_client_connects() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("console.sock");
        let server = ConsoleSocket::new(&sock_path).expect("bind");
        match server.recv_pty_master(Duration::from_millis(50)) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            Ok(_) => panic!("recv_pty_master must time out when no client connects"),
        }
    }
}
