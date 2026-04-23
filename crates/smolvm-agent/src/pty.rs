//! PTY (pseudo-terminal) helpers for interactive VM exec.
//!
//! Uses POSIX `openpty()` to allocate a PTY pair and provides RAII
//! management of the master fd. The slave side is attached to a child
//! process via `Command::pre_exec`.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// RAII wrapper around the master side of a PTY pair.
///
/// Closes the fd on drop. Provides read/write and window-size control.
pub struct PtyMaster {
    fd: OwnedFd,
}

impl PtyMaster {
    /// Wrap an already-open PTY master fd.
    ///
    /// Used by modules that obtain a master from outside the agent (e.g.
    /// the crun console-socket handshake) so they can return a `PtyMaster`
    /// without reaching into the private `fd` field.
    pub(crate) fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

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
