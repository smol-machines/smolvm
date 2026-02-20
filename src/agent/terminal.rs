//! Terminal handling for interactive sessions.
//!
//! Provides raw mode control and I/O multiplexing for bidirectional
//! communication between local terminal and remote VM.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

/// Atomic flag set by the SIGWINCH signal handler.
static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Install a SIGWINCH handler that sets an atomic flag.
///
/// Call this before entering an interactive loop that needs resize detection.
/// The handler is process-global; re-installing is safe and idempotent.
pub fn install_sigwinch_handler() {
    extern "C" fn handler(_: libc::c_int) {
        SIGWINCH_RECEIVED.store(true, Ordering::Relaxed);
    }
    // SAFETY: handler only touches an atomic — async-signal-safe.
    unsafe {
        libc::signal(libc::SIGWINCH, handler as *const () as libc::sighandler_t);
    }
}

/// Check and clear the SIGWINCH flag.
///
/// Returns `true` if a terminal resize occurred since the last check.
pub fn check_sigwinch() -> bool {
    SIGWINCH_RECEIVED.swap(false, Ordering::Relaxed)
}

/// RAII guard for terminal raw mode.
///
/// Saves the original terminal settings and restores them on drop,
/// even if the program panics.
pub struct RawModeGuard {
    fd: RawFd,
    original: libc::termios,
}

impl RawModeGuard {
    /// Enable raw mode on the given file descriptor (usually stdin).
    ///
    /// Returns `None` if the fd is not a TTY.
    pub fn new(fd: RawFd) -> Option<Self> {
        // Check if it's a TTY
        if unsafe { libc::isatty(fd) } != 1 {
            return None;
        }

        // Get current terminal settings
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }

        // Create raw mode settings
        let mut raw = original;

        // Input: disable BREAK, CR-to-NL, parity, strip, flow control
        raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);

        // Output: disable post-processing
        raw.c_oflag &= !libc::OPOST;

        // Control: 8-bit chars
        raw.c_cflag |= libc::CS8;

        // Local: disable echo, canonical mode, signals, extended
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);

        // Read returns immediately with whatever is available
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;

        // Apply raw mode
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return None;
        }

        Some(Self { fd, original })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Restore original terminal settings
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
    }
}

/// Get the current terminal size.
pub fn get_terminal_size() -> Option<(u16, u16)> {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let fd = io::stdin().as_raw_fd();

    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0 {
        Some((size.ws_col, size.ws_row))
    } else {
        None
    }
}

/// Poll result indicating which sources have data available.
pub struct PollResult {
    /// True if stdin has data available to read.
    pub stdin_ready: bool,
    /// True if the socket has data available to read.
    pub socket_ready: bool,
    /// True if the socket has hung up (peer closed connection).
    pub socket_hangup: bool,
}

/// Poll stdin and a socket for readability.
///
/// Returns which file descriptors are ready for reading.
/// Timeout is in milliseconds, -1 for infinite.
pub fn poll_io(stdin_fd: RawFd, socket_fd: RawFd, timeout_ms: i32) -> io::Result<PollResult> {
    let mut fds = [
        libc::pollfd {
            fd: stdin_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: socket_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };

    if result < 0 {
        let err = io::Error::last_os_error();
        // EINTR is not an error - just means we got a signal
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(PollResult {
                stdin_ready: false,
                socket_ready: false,
                socket_hangup: false,
            });
        }
        return Err(err);
    }

    Ok(PollResult {
        stdin_ready: fds[0].revents & libc::POLLIN != 0,
        socket_ready: fds[1].revents & libc::POLLIN != 0,
        socket_hangup: fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0,
    })
}

/// Check if stdin is a TTY.
pub fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(io::stdin().as_raw_fd()) == 1 }
}

/// Write all bytes to a writer, retrying on WouldBlock.
///
/// When stdin is set to non-blocking via `O_NONBLOCK`, the flag propagates
/// to stdout/stderr on terminals (they share the same kernel file description).
/// This helper retries writes that fail with WouldBlock.
pub fn write_all_retry(writer: &mut impl io::Write, data: &[u8]) -> io::Result<()> {
    let mut pos = 0;
    while pos < data.len() {
        match writer.write(&data[pos..]) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write"));
            }
            Ok(n) => pos += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Flush a writer, retrying on WouldBlock.
pub fn flush_retry(writer: &mut impl io::Write) -> io::Result<()> {
    loop {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// RAII guard for non-blocking stdin mode.
///
/// Sets stdin to non-blocking on creation, restores on drop.
pub struct NonBlockingStdin {
    fd: RawFd,
    original_flags: libc::c_int,
}

impl NonBlockingStdin {
    /// Set stdin to non-blocking mode.
    pub fn new() -> io::Result<Self> {
        let fd = io::stdin().as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            original_flags: flags,
        })
    }
}

impl Drop for NonBlockingStdin {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.fd, libc::F_SETFL, self.original_flags);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdin_is_tty_returns_bool() {
        // Just verify it doesn't panic - actual value depends on test environment
        let _ = stdin_is_tty();
    }

    #[test]
    fn test_get_terminal_size_returns_option() {
        // Just verify it doesn't panic
        let _ = get_terminal_size();
    }
}
