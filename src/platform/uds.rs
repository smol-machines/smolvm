//! Cross-platform AF_UNIX (Unix-domain socket) support.
//!
//! The agent control channel, the vsock-port bridges, and the fork control
//! socket all talk over `AF_UNIX` stream sockets. `std` exposes
//! `std::os::unix::net::{UnixStream, UnixListener}` only on Unix, but AF_UNIX
//! is available on Windows 10 1809+ as well. `socket2` provides a portable
//! `Domain::UNIX` socket on every supported platform, so this module wraps it
//! into a small stream/listener API the rest of the host code shares.
//!
//! [`UdsStream`] implements [`std::io::Read`]/[`Write`] (via `socket2::Socket`)
//! and the timeout/clone/shutdown helpers the agent client relies on. On Unix
//! the raw fd is exposed for the interactive-terminal `poll()` loop; that loop
//! is itself Unix-only.

use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::path::Path;
use std::time::Duration;

/// A connected AF_UNIX stream socket.
#[derive(Debug)]
pub struct UdsStream {
    inner: Socket,
}

impl UdsStream {
    /// Connect to the AF_UNIX socket at `path`.
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let address = krun_socket::SocketPath::new(path)?;
        let addr = SockAddr::unix(address.path())?;
        let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        sock.connect(&addr)?;
        Ok(Self { inner: sock })
    }

    /// Connect with a deadline, including a full listener backlog.
    pub fn connect_timeout(path: impl AsRef<Path>, timeout: Duration) -> io::Result<Self> {
        let address = krun_socket::SocketPath::new(path)?;
        let addr = SockAddr::unix(address.path())?;
        let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        sock.connect_timeout(&addr, timeout)?;
        Ok(Self { inner: sock })
    }

    /// Wrap an already-connected `socket2::Socket` (e.g. one returned by
    /// [`UdsListener::accept`]).
    pub fn from_socket(inner: Socket) -> Self {
        Self { inner }
    }

    /// Create an unnamed, connected pair of AF_UNIX stream sockets.
    ///
    /// Backed by `socketpair(2)`; Unix-only (Windows has no socketpair for
    /// AF_UNIX). Used by the agent-client unit tests.
    #[cfg(unix)]
    pub fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = Socket::pair(Domain::UNIX, Type::STREAM, None)?;
        Ok((Self { inner: a }, Self { inner: b }))
    }

    /// Create a connected pair of stream sockets (Windows test helper).
    ///
    /// Windows has no AF_UNIX `socketpair`, so this returns a loopback TCP pair.
    /// The agent-client unit tests only push bytes through a connected bidi
    /// stream, so the transport is interchangeable here.
    #[cfg(windows)]
    pub fn pair() -> io::Result<(Self, Self)> {
        use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let a = TcpStream::connect(addr)?;
        let (b, _) = listener.accept()?;
        Ok((
            Self {
                inner: Socket::from(a),
            },
            Self {
                inner: Socket::from(b),
            },
        ))
    }

    /// Set the read timeout. `None` disables the timeout (blocking).
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    /// Get the current read timeout, if any.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_timeout()
    }

    /// Set the write timeout. `None` disables the timeout (blocking).
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)
    }

    /// Clone the underlying socket handle (a new fd/handle referring to the
    /// same connection), mirroring `UnixStream::try_clone`.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
        })
    }

    /// Shut down the read, write, or both halves of the connection.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    /// Borrow the underlying `socket2::Socket`.
    pub fn as_socket(&self) -> &Socket {
        &self.inner
    }

    /// Raw Windows `SOCKET` handle for the interactive-terminal poll loop.
    ///
    /// Returned as a `u64` (the width of a `SOCKET`) so callers can hand it to
    /// the WinSock APIs the poll loop uses.
    #[cfg(windows)]
    pub fn raw_socket(&self) -> u64 {
        use std::os::windows::io::AsRawSocket;
        self.inner.as_raw_socket()
    }
}

#[cfg(unix)]
impl UdsStream {
    /// The path the process at the other end bound its listening socket to
    /// (which its accepted connections carry), or `None` for an unnamed one.
    /// Read from the connected socket itself, so it names what was actually
    /// reached, whatever links the connect followed.
    pub fn peer_path(&self) -> io::Result<Option<std::path::PathBuf>> {
        Ok(self
            .inner
            .peer_addr()?
            .as_pathname()
            .map(std::path::Path::to_path_buf))
    }

    /// The user id of the process at the other end: the one that was
    /// listening when this stream connected.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn peer_uid(&self) -> io::Result<u32> {
        use std::os::unix::io::AsRawFd;
        // SAFETY: plain data the call fills in.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: a live socket, and a buffer of the length passed.
        let rc = unsafe {
            libc::getsockopt(
                self.inner.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    /// The user id of the process at the other end: the one that was
    /// listening when this stream connected.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn peer_uid(&self) -> io::Result<u32> {
        use std::os::unix::io::AsRawFd;
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: a live socket and two out pointers.
        if unsafe { libc::getpeereid(self.inner.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for UdsStream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.inner.as_raw_fd()
    }
}

impl Read for UdsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.inner).read(buf)
    }
}

impl Read for &UdsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.inner).read(buf)
    }
}

impl Write for UdsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.inner).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.inner).flush()
    }
}

impl Write for &UdsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.inner).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.inner).flush()
    }
}

/// A listening AF_UNIX socket.
#[derive(Debug)]
pub struct UdsListener {
    inner: Socket,
}

impl UdsListener {
    /// Bind a listening AF_UNIX socket at `path`.
    ///
    /// The caller is responsible for removing any stale socket file first
    /// (matching `UnixListener::bind` semantics, which also fail on EADDRINUSE).
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let address = krun_socket::SocketPath::new(path)?;
        let addr = SockAddr::unix(address.path())?;
        let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        sock.bind(&addr)?;
        sock.listen(128)?;
        Ok(Self { inner: sock })
    }

    /// Accept a single incoming connection.
    pub fn accept(&self) -> io::Result<UdsStream> {
        let (sock, _addr) = self.inner.accept()?;
        Ok(UdsStream::from_socket(sock))
    }

    /// Iterate over incoming connections, mirroring `UnixListener::incoming`.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }
}

/// Iterator over incoming connections to a [`UdsListener`].
pub struct Incoming<'a> {
    listener: &'a UdsListener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<UdsStream>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_paths_support_agent_requests_and_control_timeouts() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("workspace".repeat(16));
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("control.sock");
        let listener = UdsListener::bind(&path).unwrap();
        // The listener's temporary alias is already gone. A later command
        // still finds the actual socket at its original filesystem path.
        let mut client = UdsStream::connect_timeout(&path, Duration::from_secs(1)).unwrap();
        let mut server = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(b"STATUS\n").unwrap();
        let mut request = [0; 7];
        server.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"STATUS\n");
        server.write_all(b"OK\n").unwrap();
        let mut reply = [0; 3];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"OK\n");
        assert!(path.exists());
        assert_eq!(
            UdsListener::bind(&path).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
    }
}
