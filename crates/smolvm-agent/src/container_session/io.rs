//! Bounded, nonblocking framing and event-driven wakeups for session owners.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub(super) struct Wake(OwnedFd);
impl Wake {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
    pub fn signal(&self) {
        let one = 1u64;
        // Coalescing is intentional; EAGAIN means a wake is already pending.
        loop {
            let n = unsafe { libc::write(self.fd(), (&one as *const u64).cast(), 8) };
            if n >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
    pub fn drain(&self) {
        let mut count = 0u64;
        loop {
            let n = unsafe { libc::read(self.fd(), (&mut count as *mut u64).cast(), 8) };
            if n >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
    pub fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub(super) fn poll(fds: &mut [libc::pollfd]) -> io::Result<()> {
    loop {
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
pub(super) fn watch(fd: RawFd, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}
pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Default)]
pub(super) struct Frame {
    header: [u8; 4],
    header_len: usize,
    body: Vec<u8>,
    body_len: usize,
}
impl Frame {
    pub fn read(&mut self, fd: RawFd) -> io::Result<Option<Vec<u8>>> {
        loop {
            if self.header_len == 4 && self.body.is_empty() {
                let len = u32::from_be_bytes(self.header) as usize;
                // Bounded session I/O only; Start specifications are parsed by
                // the ordinary request handler before entering this loop.
                if len == 0 || len > 2 * smolvm_protocol::container_session::MAX_INPUT_BYTES {
                    return Err(invalid("invalid container session frame size"));
                }
                self.body.resize(len, 0);
            }
            if !self.body.is_empty() && self.body_len == self.body.len() {
                let body = std::mem::take(&mut self.body);
                *self = Self::default();
                return Ok(Some(body));
            }
            let (bytes, count) = if self.header_len < 4 {
                (&mut self.header[..], &mut self.header_len)
            } else {
                (&mut self.body[..], &mut self.body_len)
            };
            let n = unsafe {
                libc::recv(
                    fd,
                    bytes[*count..].as_mut_ptr().cast(),
                    bytes.len() - *count,
                    libc::MSG_DONTWAIT,
                )
            };
            if n > 0 {
                *count += n as usize;
            } else if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            } else {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return Ok(None),
                    _ => return Err(error),
                }
            }
        }
    }
}

pub(super) struct WriteFrame {
    bytes: Vec<u8>,
    written: usize,
}
impl WriteFrame {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, written: 0 }
    }
    pub fn write(&mut self, fd: RawFd) -> io::Result<bool> {
        while self.written < self.bytes.len() {
            let data = &self.bytes[self.written..];
            let n = unsafe {
                libc::send(
                    fd,
                    data.as_ptr().cast(),
                    data.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if n > 0 {
                self.written += n as usize;
            } else if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            } else {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return Ok(false),
                    _ => return Err(error),
                }
            }
        }
        Ok(true)
    }
}
