//! PTY (pseudo-terminal) helpers for interactive VM exec.
//!
//! Uses POSIX `openpty()` to allocate a PTY pair and provides RAII
//! management of the master fd. The slave side is attached to a child
//! process via `Command::pre_exec`.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Monotonic counter making each console-socket path unique, so concurrent
/// sessions that share a container id (e.g. multiple `crun exec` into one
/// running container) never collide on the same socket file.
static CONSOLE_SOCKET_SEQ: AtomicU64 = AtomicU64::new(0);

/// RAII wrapper around the master side of a PTY pair.
///
/// Closes the fd on drop. Provides read/write and window-size control.
pub struct PtyMaster {
    fd: OwnedFd,
}

impl PtyMaster {
    /// Read bytes from the PTY master.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Write all bytes to the PTY master.
    pub fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n =
                unsafe { libc::write(self.fd.as_raw_fd(), data.as_ptr() as *const _, data.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            data = &data[n as usize..];
        }
        Ok(())
    }

    /// Set the terminal window size via `TIOCSWINSZ`.
    pub fn set_window_size(&self, cols: u16, rows: u16) -> io::Result<()> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ with a valid winsize struct on our owned fd.
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Wrap an already-open master fd — e.g. one received from crun over a
    /// `--console-socket` — as a `PtyMaster`.
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        PtyMaster { fd }
    }
}

/// A listening AF_UNIX socket that an OCI runtime connects to (via
/// `--console-socket`) to hand back the master fd of the container's PTY.
///
/// crun/runc, when `terminal: true`, create the console PTY themselves and — in
/// foreground mode — relay byte data between that PTY and their own stdio but do
/// NOT propagate window-size changes. Taking the master directly over this
/// socket means the agent owns the container's real console, so
/// [`PtyMaster::set_window_size`] (and resize events) reach the process's tty.
pub struct ConsoleSocket {
    path: PathBuf,
    listener: UnixListener,
}

impl ConsoleSocket {
    /// Bind a uniquely-named console socket. `tag` (e.g. the container id) is a
    /// human-readable hint; a process-global sequence number guarantees
    /// uniqueness so concurrent sessions sharing a container id (multiple
    /// `crun exec` into one container) never collide. Only the tag's tail is
    /// used, to stay within the ~108-byte AF_UNIX path limit.
    pub fn bind(tag: &str) -> io::Result<Self> {
        let tail: String = {
            let s = tag.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            let start = s.len().saturating_sub(16);
            s[start..].to_string()
        };
        let seq = CONSOLE_SOCKET_SEQ.fetch_add(1, Ordering::Relaxed);
        // The guest root filesystem (and thus /tmp) is read-only, so bind the
        // socket under the writable storage disk. crun shares this mount
        // namespace, so it can connect to the same path.
        let dir = Path::new(crate::paths::STORAGE_ROOT);
        let path = dir.join(format!("smolvm-con-{}-{}.sock", tail, seq));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        Ok(Self { path, listener })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept the runtime's connection and receive the PTY master fd via
    /// `SCM_RIGHTS`. Bounded by `timeout` so a runtime that never connects (a
    /// crun failure) can't hang the interactive session.
    pub fn recv_master(&self, timeout: Duration) -> io::Result<PtyMaster> {
        let mut pfd = libc::pollfd {
            fd: self.listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
        if pr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "console socket: runtime did not connect",
            ));
        }
        if pr < 0 {
            return Err(io::Error::last_os_error());
        }
        let (conn, _) = self.listener.accept()?;
        recv_fd(conn.as_raw_fd()).map(PtyMaster::from_owned_fd)
    }
}

impl Drop for ConsoleSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Receive a single fd from a connected unix socket via `SCM_RIGHTS`.
fn recv_fd(sock_fd: RawFd) -> io::Result<OwnedFd> {
    // 8-byte-aligned control buffer (cmsghdr requires size_t alignment).
    #[repr(C, align(8))]
    struct AlignedCmsg([u8; 32]);
    let mut cmsg = AlignedCmsg([0u8; 32]);
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: zeroed msghdr is valid; pointers below reference live local buffers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg.0.len() as _;

    let n = unsafe { libc::recvmsg(sock_fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let cptr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "console socket: no SCM_RIGHTS control message",
        ));
    }
    // SAFETY: cptr is non-null and points into our cmsg buffer.
    let chdr = unsafe { &*cptr };
    if chdr.cmsg_level != libc::SOL_SOCKET || chdr.cmsg_type != libc::SCM_RIGHTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "console socket: unexpected control message",
        ));
    }
    let mut fd: RawFd = -1;
    // SAFETY: CMSG_DATA points to at least size_of::<RawFd>() bytes here.
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cptr),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
    }
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "console socket: invalid fd received",
        ));
    }
    // SAFETY: fd was just received from the kernel and is owned by us now.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Allocate a new PTY pair with the given initial window size.
///
/// Returns `(master, slave_fd)`. The caller must close `slave_fd` in the
/// parent process after the child has been spawned.
pub fn open_pty(cols: u16, rows: u16) -> io::Result<(PtyMaster, OwnedFd)> {
    let mut master_raw: RawFd = -1;
    let mut slave_raw: RawFd = -1;

    // SAFETY: openpty writes into our pointers; we check the return value.
    let ret = unsafe {
        libc::openpty(
            &mut master_raw,
            &mut slave_raw,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Wrap in OwnedFd immediately so they get closed on error paths.
    // SAFETY: openpty returned successfully, so these are valid fds.
    let master_fd = unsafe { OwnedFd::from_raw_fd(master_raw) };
    let slave_fd = unsafe { OwnedFd::from_raw_fd(slave_raw) };

    let master = PtyMaster { fd: master_fd };

    // Set initial window size.
    master.set_window_size(cols, rows)?;

    Ok((master, slave_fd))
}

/// Build a `pre_exec` closure that makes the child the session leader
/// and attaches the slave PTY as its controlling terminal + stdio.
///
/// # Safety
///
/// The returned closure is meant for `Command::pre_exec` which runs
/// between `fork()` and `exec()`. It calls only async-signal-safe
/// functions (`setsid`, `ioctl`, `dup2`, `close`).
pub fn slave_pre_exec(slave_fd: RawFd) -> impl FnMut() -> io::Result<()> {
    move || {
        // Create a new session (detach from parent's controlling terminal).
        if unsafe { libc::setsid() } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Make the slave our controlling terminal.
        // SAFETY: TIOCSCTTY with arg 0 on a valid pty slave fd after setsid().
        if unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Dup slave fd onto stdin/stdout/stderr.
        for &target in &[0, 1, 2] {
            if slave_fd != target {
                if unsafe { libc::dup2(slave_fd, target) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        // Close the original slave fd if it wasn't one of 0/1/2.
        if slave_fd > 2 {
            unsafe { libc::close(slave_fd) };
        }

        Ok(())
    }
}
