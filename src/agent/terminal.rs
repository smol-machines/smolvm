//! Terminal handling for interactive sessions.
//!
//! Provides raw mode control and I/O multiplexing for bidirectional
//! communication between local terminal and remote VM.
//!
//! The interactive TTY machinery (raw mode, `poll()`-based I/O multiplexing,
//! SIGWINCH handling, non-blocking stdin) is POSIX-specific. On Windows the
//! same public API is provided as compile-only stubs: the host control plane
//! builds, but interactive exec sessions are not wired up there. See the
//! `windows_stub` module below.

/// Portable file-descriptor handle used by the interactive poll loop. A real
/// `RawFd` on Unix; an opaque placeholder on Windows where the poll loop is a
/// stub.
#[cfg(unix)]
pub type Fd = std::os::unix::io::RawFd;
/// Portable file-descriptor handle (Windows): an opaque placeholder, since the
/// `poll()`-based interactive loop is a stub there.
#[cfg(not(unix))]
pub type Fd = i64;

#[cfg(unix)]
mod unix_impl {
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
            // POLLHUP: the pipe's write end was closed (e.g., `echo | smolvm exec -i`).
            // Without this, piped stdin EOF is never detected and the host hangs
            // forever waiting for more input.
            // POLLNVAL: macOS poll() reports /dev/null this way instead of POLLIN
            // (`smolvm machine run -i -- cat < /dev/null`); the read then sees EOF.
            stdin_ready: fds[0].revents
                & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                != 0,
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
} // mod unix_impl

#[cfg(unix)]
pub use unix_impl::{
    check_sigwinch, flush_retry, get_terminal_size, install_sigwinch_handler, poll_io,
    stdin_is_tty, write_all_retry, NonBlockingStdin, PollResult, RawModeGuard,
};

/// Windows implementation of the interactive-terminal API.
///
/// Mirrors the POSIX `unix_impl` module using Win32 console + WinSock APIs so
/// `machine exec -it` / `machine shell` drive a real raw-mode session on
/// Windows. The shared poll loop in `agent::client` is platform-agnostic and
/// is reused unchanged; only these primitives differ.
#[cfg(not(unix))]
#[allow(missing_docs)]
mod windows_impl {
    use super::Fd;
    use std::io;
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED};
    use windows_sys::Win32::Networking::WinSock::{
        ioctlsocket, WSACloseEvent, WSACreateEvent, WSAEnumNetworkEvents, WSAEventSelect, FD_CLOSE,
        FD_READ, FIONBIO, SOCKET, WSAEVENT, WSANETWORKEVENTS, WSA_INVALID_EVENT,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleScreenBufferInfo, GetNumberOfConsoleInputEvents, GetStdHandle,
        PeekConsoleInputW, ReadConsoleInputW, SetConsoleMode, CONSOLE_SCREEN_BUFFER_INFO,
        DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, INPUT_RECORD, KEY_EVENT,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::Threading::WaitForMultipleObjects;

    /// Convert the portable `Fd` (an `i64` carrying a console `HANDLE`) into a
    /// Win32 `HANDLE`.
    fn fd_to_handle(fd: Fd) -> HANDLE {
        fd as usize as HANDLE
    }

    /// Convert the portable `Fd` (an `i64` carrying a WinSock `SOCKET`) into a
    /// `SOCKET`.
    fn fd_to_socket(fd: Fd) -> SOCKET {
        fd as usize as SOCKET
    }

    fn std_output_handle() -> HANDLE {
        // SAFETY: GetStdHandle has no preconditions.
        unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
    }

    /// Last terminal size observed, used to emulate SIGWINCH via polling.
    static LAST_SIZE: Mutex<Option<(u16, u16)>> = Mutex::new(None);

    /// Seed the resize cache with the current terminal size.
    ///
    /// The Windows console has no SIGWINCH; resize is detected by comparing the
    /// current size against this cache in [`check_sigwinch`].
    pub fn install_sigwinch_handler() {
        let current = get_terminal_size();
        if let Ok(mut guard) = LAST_SIZE.lock() {
            *guard = current;
        }
    }

    /// Return `true` if the terminal has been resized since the last check.
    pub fn check_sigwinch() -> bool {
        let current = get_terminal_size();
        let mut guard = match LAST_SIZE.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if *guard != current {
            *guard = current;
            true
        } else {
            false
        }
    }

    /// RAII guard for console raw mode.
    ///
    /// Saves the input handle's mode (and the output handle's VT mode), switches
    /// the console into raw VT-input mode, and restores both on drop.
    pub struct RawModeGuard {
        input: HANDLE,
        original_input_mode: u32,
        output: HANDLE,
        original_output_mode: u32,
        restore_output: bool,
    }

    impl RawModeGuard {
        /// Enable raw mode on the given console input handle.
        ///
        /// Returns `None` if the handle is not a console.
        pub fn new(fd: Fd) -> Option<Self> {
            let input = fd_to_handle(fd);

            let mut original_input_mode: u32 = 0;
            // SAFETY: `input` is the process's console input handle; GetConsoleMode
            // fails (returns 0) if it is not a console, which we treat as "no TTY".
            if unsafe { GetConsoleMode(input, &mut original_input_mode) } == 0 {
                return None;
            }

            // Clear cooked-mode input flags, enable VT input so the guest sees
            // raw key/escape sequences.
            let raw_input_mode = (original_input_mode
                & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            // SAFETY: setting a derived mode on a valid console handle.
            if unsafe { SetConsoleMode(input, raw_input_mode) } == 0 {
                return None;
            }

            // Enable VT processing on output so ANSI escapes from the guest render.
            let output = std_output_handle();
            let mut original_output_mode: u32 = 0;
            let restore_output =
                // SAFETY: querying the output handle's mode.
                if unsafe { GetConsoleMode(output, &mut original_output_mode) } != 0 {
                    let out_mode = original_output_mode
                        | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                        | DISABLE_NEWLINE_AUTO_RETURN;
                    // SAFETY: setting a derived mode on a valid console output handle.
                    unsafe {
                        SetConsoleMode(output, out_mode);
                    }
                    true
                } else {
                    false
                };

            Some(Self {
                input,
                original_input_mode,
                output,
                original_output_mode,
                restore_output,
            })
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            // SAFETY: restoring previously-saved console modes on valid handles.
            unsafe {
                SetConsoleMode(self.input, self.original_input_mode);
                if self.restore_output {
                    SetConsoleMode(self.output, self.original_output_mode);
                }
            }
        }
    }

    /// Get the current terminal size from the console window rectangle.
    pub fn get_terminal_size() -> Option<(u16, u16)> {
        let output = std_output_handle();
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: `output` is the console output handle; the call fails (0) if it
        // is not a console.
        if unsafe { GetConsoleScreenBufferInfo(output, &mut info) } == 0 {
            return None;
        }
        let w = info.srWindow;
        let cols = (w.Right - w.Left + 1).max(0) as u16;
        let rows = (w.Bottom - w.Top + 1).max(0) as u16;
        Some((cols, rows))
    }

    /// Poll result indicating which sources have data available.
    pub struct PollResult {
        pub stdin_ready: bool,
        pub socket_ready: bool,
        pub socket_hangup: bool,
    }

    /// Poll the console input handle and the agent socket for readability.
    ///
    /// `timeout_ms` is in milliseconds; -1 means infinite. A `stdin_fd` of -1
    /// (the loop's EOF sentinel) suppresses waiting on console input.
    pub fn poll_io(stdin_fd: Fd, socket_fd: Fd, timeout_ms: i32) -> io::Result<PollResult> {
        let socket = fd_to_socket(socket_fd);

        // Register the socket with a WSA event for FD_READ | FD_CLOSE. This also
        // puts the socket into non-blocking mode; we restore blocking before
        // returning so the client's blocking receive() behaves like Unix.
        // SAFETY: WSACreateEvent has no preconditions.
        let event: WSAEVENT = unsafe { WSACreateEvent() };
        if event == WSA_INVALID_EVENT {
            return Err(io::Error::last_os_error());
        }

        // Restore the socket to blocking and free the event on every exit path.
        struct SocketCleanup {
            socket: SOCKET,
            event: WSAEVENT,
        }
        impl Drop for SocketCleanup {
            fn drop(&mut self) {
                // SAFETY: deregister the event selection, then put the socket back
                // into blocking mode and close the event.
                unsafe {
                    WSAEventSelect(self.socket, 0 as WSAEVENT, 0);
                    let mut nonblocking: u32 = 0;
                    ioctlsocket(self.socket, FIONBIO, &mut nonblocking);
                    WSACloseEvent(self.event);
                }
            }
        }
        let _cleanup = SocketCleanup { socket, event };

        // SAFETY: registering FD_READ|FD_CLOSE notifications on the socket.
        if unsafe { WSAEventSelect(socket, event, (FD_READ | FD_CLOSE) as i32) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let wait_console = stdin_fd != -1;
        let console = fd_to_handle(stdin_fd);

        // Build the wait handle set: optionally the console input handle, then
        // the WSA event (which is HANDLE-compatible).
        let mut handles: [HANDLE; 2] = [0 as HANDLE; 2];
        let mut count: u32 = 0;
        if wait_console {
            handles[count as usize] = console;
            count += 1;
        }
        handles[count as usize] = event as usize as HANDLE;
        count += 1;

        let dw_timeout: u32 = if timeout_ms < 0 {
            u32::MAX // INFINITE
        } else {
            timeout_ms as u32
        };

        // SAFETY: `handles[..count]` are valid waitable handles.
        let wait = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, dw_timeout) };

        if wait == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }

        let mut stdin_ready = false;
        let mut socket_ready = false;
        let mut socket_hangup = false;

        // The console input handle signals for non-key events too (focus, mouse,
        // resize). Peek and only report stdin readiness for actual key/char input;
        // drain non-key records so we don't busy-loop.
        if wait_console {
            stdin_ready = console_input_has_key(console);
        }

        // Read which socket events fired regardless of which handle woke the wait —
        // WSAEnumNetworkEvents reflects all pending notifications and resets them.
        let mut net_events: WSANETWORKEVENTS = unsafe { std::mem::zeroed() };
        // SAFETY: `socket` and `event` are valid; net_events is writable.
        if unsafe { WSAEnumNetworkEvents(socket, event, &mut net_events) } == 0 {
            if net_events.lNetworkEvents & FD_READ as i32 != 0 {
                socket_ready = true;
            }
            if net_events.lNetworkEvents & FD_CLOSE as i32 != 0 {
                socket_hangup = true;
            }
        }

        Ok(PollResult {
            stdin_ready,
            socket_ready,
            socket_hangup,
        })
    }

    /// Inspect pending console input records: return `true` if a key/char event
    /// is queued. Non-key events (focus/mouse/buffer-resize) are drained so the
    /// wait doesn't busy-loop, but key events are left in the queue so the
    /// client's subsequent `Stdin::read` (ReadFile/ReadConsole) consumes them.
    fn console_input_has_key(console: HANDLE) -> bool {
        loop {
            let mut available: u32 = 0;
            // SAFETY: querying the count of pending input records.
            if unsafe { GetNumberOfConsoleInputEvents(console, &mut available) } == 0
                || available == 0
            {
                return false;
            }

            // Peek (non-destructive) at the next record.
            let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
            let mut read: u32 = 0;
            // SAFETY: peeks one record into `record` without removing it.
            if unsafe { PeekConsoleInputW(console, &mut record, 1, &mut read) } == 0 || read == 0 {
                return false;
            }

            if record.EventType as u32 == KEY_EVENT {
                // Real input — leave it queued for the loop's stdin read.
                return true;
            }

            // Non-key event: remove just this record so the wait doesn't keep
            // re-signaling on it, then look again for a real key event.
            // SAFETY: removes exactly one (the peeked non-key) record.
            if unsafe { ReadConsoleInputW(console, &mut record, 1, &mut read) } == 0 || read == 0 {
                return false;
            }
        }
    }

    /// Check if stdin is a console (TTY).
    pub fn stdin_is_tty() -> bool {
        // SAFETY: GetStdHandle + GetConsoleMode; the latter fails for non-consoles.
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode: u32 = 0;
            GetConsoleMode(h, &mut mode) != 0
        }
    }

    /// Write all bytes to a writer.
    pub fn write_all_retry(writer: &mut impl io::Write, data: &[u8]) -> io::Result<()> {
        writer.write_all(data)
    }

    /// Flush a writer.
    pub fn flush_retry(writer: &mut impl io::Write) -> io::Result<()> {
        writer.flush()
    }

    /// RAII guard placeholder for non-blocking stdin.
    ///
    /// On Windows the interactive loop only reads stdin after `poll_io` reports
    /// readiness, and reads through `std::io::Stdin::read` (which yields UTF-8
    /// from the VT-input console), so no fd-level non-blocking flag is needed.
    pub struct NonBlockingStdin;

    impl NonBlockingStdin {
        pub fn new() -> io::Result<Self> {
            Ok(Self)
        }
    }
}

#[cfg(not(unix))]
pub use windows_impl::{
    check_sigwinch, flush_retry, get_terminal_size, install_sigwinch_handler, poll_io,
    stdin_is_tty, write_all_retry, NonBlockingStdin, PollResult, RawModeGuard,
};

#[cfg(all(test, unix))]
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

    #[test]
    fn test_poll_io_reports_dev_null_stdin_ready() {
        // macOS poll() reports /dev/null as POLLNVAL only. Stdin must still be
        // ready so the next read returns EOF instead of the loop spinning (#1803).
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        let stdin = std::fs::File::open("/dev/null").unwrap();
        let (socket, _peer) = UnixStream::pair().unwrap();
        let result = poll_io(stdin.as_raw_fd(), socket.as_raw_fd(), 0).unwrap();
        assert!(result.stdin_ready);
        assert!(!result.socket_ready);
    }
}
