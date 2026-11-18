//! Bidirectional relay between a host connection arriving over vsock and an
//! in-guest peer socket, shared by the Docker socket bridge and the port
//! forwarder.

use std::io;

/// Relay bytes both ways between `host` and `peer` with independent
/// half-close: when one side closes its write half, its FIN is mirrored to the
/// other while the opposite direction keeps flowing until it closes too.
///
/// Connections are often long-lived and idle (`docker logs -f`, a dev server's
/// keep-alive, a hijacked attach stream), so this blocks on `poll`
/// indefinitely and only returns once both directions have closed. Honoring
/// half-close is required for hijacked Docker attach streams, which close
/// their write half before the daemon has finished streaming output.
#[cfg(target_os = "linux")]
pub(crate) fn relay_half_close<H, P>(mut host: H, mut daemon: P) -> io::Result<()>
where
    H: io::Read + io::Write + std::os::unix::io::AsRawFd,
    P: io::Read + io::Write + std::os::unix::io::AsRawFd,
{
    let host_fd = host.as_raw_fd();
    let peer_fd = daemon.as_raw_fd();
    let _host_flags = Nonblocking::new(host_fd)?;
    let _peer_flags = Nonblocking::new(peer_fd)?;
    let mut upload = Direction::new();
    let mut download = Direction::new();
    loop {
        upload.finish(peer_fd);
        download.finish(host_fd);
        if upload.finished() && download.finished() {
            return Ok(());
        }
        let mut ready = [
            poll_fd(host_fd, &upload, &download),
            poll_fd(peer_fd, &download, &upload),
        ];
        // Both directions are independently backpressured. No timers or
        // additional relay threads wake an idle connection.
        if unsafe { libc::poll(ready.as_mut_ptr(), 2, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready.iter().any(|r| r.revents & libc::POLLNVAL != 0) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        upload.read(&mut host, ready[0].revents)?;
        download.read(&mut daemon, ready[1].revents)?;
        upload.write(&mut daemon, ready[1].revents)?;
        download.write(&mut host, ready[0].revents)?;
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Nonblocking {
    fd: libc::c_int,
    flags: libc::c_int,
}
#[cfg(target_os = "linux")]
impl Nonblocking {
    pub(crate) fn new(fd: libc::c_int) -> io::Result<Self> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, flags })
    }
}
#[cfg(target_os = "linux")]
impl Drop for Nonblocking {
    fn drop(&mut self) {
        unsafe {
            libc::fcntl(self.fd, libc::F_SETFL, self.flags);
        }
    }
}

#[cfg(target_os = "linux")]
struct Direction {
    bytes: Box<[u8; 65536]>,
    start: usize,
    end: usize,
    reading: bool,
    shut: bool,
}
#[cfg(target_os = "linux")]
impl Direction {
    fn new() -> Self {
        Self {
            bytes: Box::new([0; 65536]),
            start: 0,
            end: 0,
            reading: true,
            shut: false,
        }
    }
    fn pending(&self) -> bool {
        self.start < self.end
    }
    fn readable(&self) -> bool {
        self.reading && !self.pending()
    }
    fn finished(&self) -> bool {
        self.shut
    }
    fn finish(&mut self, target: libc::c_int) {
        if !self.reading && !self.pending() && !self.shut {
            // Send FIN only after this direction's queued data has drained.
            unsafe {
                libc::shutdown(target, libc::SHUT_WR);
            }
            self.shut = true;
        }
    }
    fn read(&mut self, stream: &mut impl io::Read, events: libc::c_short) -> io::Result<()> {
        if !self.readable() || events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            return Ok(());
        }
        match stream.read(&mut self.bytes[..]) {
            Ok(0) => self.reading = false,
            Ok(n) => {
                self.start = 0;
                self.end = n;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
    fn write(&mut self, stream: &mut impl io::Write, events: libc::c_short) -> io::Result<()> {
        if !self.pending() || events & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) == 0 {
            return Ok(());
        }
        match stream.write(&self.bytes[self.start..self.end]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => self.start += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn poll_fd(fd: libc::c_int, read: &Direction, write: &Direction) -> libc::pollfd {
    let events = (if read.readable() { libc::POLLIN } else { 0 })
        | (if write.pending() { libc::POLLOUT } else { 0 });
    libc::pollfd {
        fd: if events == 0 { -1 } else { fd },
        events,
        revents: 0,
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn relay_half_close<H, P>(_host: H, _peer: P) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "guest relays are only supported on Linux guests",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::{fd::AsRawFd, unix::net::UnixStream},
        sync::mpsc,
        thread,
        time::Duration,
    };

    #[test]
    fn request_half_close_preserves_large_response_and_restores_borrowed_flags() {
        let (mut host, bridge_host) = UnixStream::pair().unwrap();
        let (mut peer, bridge_peer) = UnixStream::pair().unwrap();
        let host_flags = bridge_host.try_clone().unwrap();
        let peer_flags = bridge_peer.try_clone().unwrap();
        for stream in [&host, &peer] {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        let abort_host = host.try_clone().unwrap();
        let abort_peer = peer.try_clone().unwrap();
        let relay = thread::spawn(move || relay_half_close(bridge_host, bridge_peer));
        let responder = thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut request = Vec::new();
            peer.read_to_end(&mut request)?;
            peer.write_all(&vec![0x37; 1024 * 1024])?;
            peer.shutdown(std::net::Shutdown::Write)?;
            Ok(request)
        });
        host.write_all(b"request").unwrap();
        host.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = Vec::new();
        let read = host.read_to_end(&mut response);
        let request = responder.join().unwrap();
        let _ = abort_host.shutdown(std::net::Shutdown::Both);
        let _ = abort_peer.shutdown(std::net::Shutdown::Both);
        relay.join().unwrap().unwrap();
        read.unwrap();
        assert_eq!(request.unwrap(), b"request");
        assert_eq!(response, vec![0x37; 1024 * 1024]);
        for stream in [&host_flags, &peer_flags] {
            assert_eq!(
                unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
                0
            );
        }
    }

    #[test]
    fn a_blocked_upload_does_not_block_the_reverse_stream_or_half_close() {
        let (host, bridge_host) = UnixStream::pair().unwrap();
        let (mut peer, bridge_peer) = UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    bridge_peer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as _,
                )
            },
            0
        );
        let abort_host = host.try_clone().unwrap();
        let abort_peer = peer.try_clone().unwrap();
        let mut host_read = host.try_clone().unwrap();
        host_read
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut host_write = host;
        let relay = thread::spawn(move || relay_half_close(bridge_host, bridge_peer));
        let writer = thread::spawn(move || {
            host_write.write_all(&vec![0x62; 1024 * 1024])?;
            host_write.shutdown(std::net::Shutdown::Write)
        });
        let (ready, received) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut bytes = [0; 6];
            let result = host_read.read_exact(&mut bytes);
            let _ = ready.send(result.as_ref().is_ok_and(|_| bytes == *b"ready!"));
            result
        });
        let mut poll = libc::pollfd {
            fd: peer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
        peer.write_all(b"ready!").unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let reverse_progress = received
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or(false);
        let mut body = Vec::new();
        if reverse_progress {
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            peer.read_to_end(&mut body).unwrap();
        }
        let _ = abort_host.shutdown(std::net::Shutdown::Both);
        let _ = abort_peer.shutdown(std::net::Shutdown::Both);
        let wrote = writer.join().unwrap();
        let read = reader.join().unwrap();
        let relayed = relay.join().unwrap();
        assert!(
            reverse_progress,
            "the reverse stream stalled behind an upload the peer had not read"
        );
        wrote.unwrap();
        read.unwrap();
        relayed.unwrap();
        assert_eq!(body, vec![0x62; 1024 * 1024]);
    }
}
