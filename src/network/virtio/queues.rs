//! Shared queues and wake notifications for the virtio-net backend.
//!
//! Context
//! =======
//!
//! The host-side virtio runtime has several independently blocked workers:
//! - the Unix-stream reader thread
//! - the Unix-stream writer thread
//! - the smoltcp poll loop
//! - TCP relay threads
//!
//! They need two kinds of coordination:
//! 1. lock-free frame handoff between threads
//! 2. a way to wake a thread that is blocked in `poll(2)` or waiting for work
//!
//! This module provides both:
//! - `ArrayQueue<Vec<u8>>` for frame ownership transfer
//! - `WakePipe` as a tiny readiness primitive built from `pipe(2)` + `poll(2)`
//!
//! Data flow:
//!
//! ```text
//! guest_to_host queue : reader thread  -> smoltcp poll loop
//! host_to_guest queue : smoltcp runtime -> writer thread
//!
//! guest_wake: reader thread / shutdown -> smoltcp poll loop
//! host_wake : smoltcp runtime / shutdown -> Unix-stream writer
//! relay_wake: TCP relay threads / shutdown -> smoltcp poll loop
//! ```
//!
//! Thread interaction view:
//!
//! ```text
//! FrameStream reader thread
//!   -> guest_to_host.push(frame)
//!   -> guest_wake.wake()
//!
//! smolvm-net-poll thread
//!   -> guest_to_host.pop()
//!   -> host_to_guest.push(frame)
//!   -> host_wake.wake()
//!   -> relay_wake.wait()/drain()
//!
//! FrameStream writer thread
//!   -> host_wake.wait()
//!   -> host_to_guest.pop()
//!
//! TCP relay thread
//!   -> to_smoltcp.send(payload)
//!   -> relay_wake.wake()
//! ```

use crossbeam_queue::ArrayQueue;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Default queue capacity for guest/host ethernet frames.
pub const DEFAULT_FRAME_QUEUE_CAPACITY: usize = 1024;

/// Shared queues and wake handles for the host-side virtio-net runtime.
///
/// One `NetworkFrameQueues` is shared across all helper threads for a single
/// guest NIC.
///
/// A useful mental model is:
///
/// ```text
/// queues  = ownership transfer for frame bytes
/// wakes   = "go look at the queue now"
/// shutdown= sticky flag + wake all blocked waiters
/// ```
pub struct NetworkFrameQueues {
    /// Raw ethernet frames emitted by the guest and waiting for smoltcp.
    pub guest_to_host: ArrayQueue<Vec<u8>>,
    /// Raw ethernet frames emitted by smoltcp and waiting for libkrun.
    pub host_to_guest: ArrayQueue<Vec<u8>>,
    /// Wake the smoltcp poll loop when a guest frame arrives.
    pub guest_wake: WakePipe,
    /// Wake the libkrun writer thread when a host frame is ready.
    pub host_wake: WakePipe,
    /// Wake the smoltcp poll loop when a TCP relay thread has new data.
    pub relay_wake: WakePipe,
    /// Signals that the helper process should shut down.
    shutting_down: AtomicBool,
}

impl NetworkFrameQueues {
    /// Create a new shared queue set wrapped in `Arc`.
    pub fn shared(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            guest_to_host: ArrayQueue::new(capacity),
            host_to_guest: ArrayQueue::new(capacity),
            guest_wake: WakePipe::new(),
            host_wake: WakePipe::new(),
            relay_wake: WakePipe::new(),
            shutting_down: AtomicBool::new(false),
        })
    }

    /// Mark the runtime as shutting down and wake all waiters.
    ///
    /// The wakes are part of shutdown correctness. Without them, a thread
    /// blocked in `poll(2)` could sleep indefinitely even though the shutdown
    /// flag was already set.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.guest_wake.wake();
        self.host_wake.wake();
        self.relay_wake.wake();
    }

    /// Whether shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }
}

/// Wake notification built on `pipe(2)`.
///
/// The pattern is:
/// - one thread blocks on the read end with `poll(2)`
/// - another thread writes one byte to the write end to signal "work exists"
/// - the waiter drains pending bytes before going back to sleep
///
/// Why use a pipe here:
/// - it gives us a real file descriptor that integrates with `poll(2)`
/// - it works on the Unix platforms smolvm targets
/// - it is simpler than building a custom condvar + timeout scheme around the
///   smoltcp loop and Unix-stream writer
#[derive(Debug)]
pub struct WakePipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

impl WakePipe {
    /// Create a non-blocking wake pipe.
    ///
    /// Low-level steps:
    ///
    /// ```text
    /// pipe()               -> create read/write fds
    /// fcntl(F_SETFL)       -> add O_NONBLOCK
    /// fcntl(F_SETFD)       -> add FD_CLOEXEC
    /// wrap in OwnedFd      -> move fd lifetime into Rust ownership
    /// ```
    pub fn new() -> Self {
        let mut fds = [0i32; 2];

        // SAFETY: `pipe` initializes both file descriptors on success.
        let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(
            result,
            0,
            "pipe() failed: {}",
            std::io::Error::last_os_error()
        );

        // SAFETY: both descriptors are valid after a successful `pipe`.
        unsafe {
            set_nonblock_cloexec(fds[0]);
            set_nonblock_cloexec(fds[1]);
        }

        Self {
            // SAFETY: ownership of the raw file descriptors transfers here.
            read_fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write_fd: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        }
    }

    /// Signal the waiting side.
    ///
    /// Writing one byte is enough. The byte value itself does not matter; only
    /// readability of the pipe matters. Multiple writes coalesce naturally into
    /// "there is pending wake state".
    pub fn wake(&self) {
        let byte = [1u8; 1];
        // SAFETY: the write end is valid and non-blocking.
        unsafe {
            libc::write(self.write_fd.as_raw_fd(), byte.as_ptr().cast(), byte.len());
        }
    }

    /// Drain all pending wake bytes.
    ///
    /// This resets the readiness state after a wake. Because the pipe is
    /// non-blocking, `read <= 0` means "nothing more to drain right now".
    pub fn drain(&self) {
        let mut buf = [0u8; 256];
        loop {
            // SAFETY: the read end is valid and non-blocking.
            let read =
                unsafe { libc::read(self.read_fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if read <= 0 {
                break;
            }
        }
    }

    /// Wait until the pipe is readable or the timeout elapses.
    ///
    /// This is the low-level equivalent of "sleep until another thread signals
    /// me or the timeout expires", but implemented in file-descriptor space so
    /// it composes with other polling logic.
    pub fn wait(&self, timeout: Option<Duration>) -> std::io::Result<bool> {
        let timeout_ms = timeout
            .map(|duration| duration.as_millis().min(i32::MAX as u128) as i32)
            .unwrap_or(-1);
        let mut pollfd = libc::pollfd {
            fd: self.read_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: `pollfd` points to a valid descriptor and struct.
        let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(result > 0 && pollfd.revents & libc::POLLIN != 0)
    }

    /// File descriptor for `poll(2)`.
    ///
    /// Callers should treat this as a borrowed readiness handle, not as an fd
    /// they own or may close.
    pub fn as_raw_fd(&self) -> RawFd {
        self.read_fd.as_raw_fd()
    }
}

impl Clone for WakePipe {
    /// Clone by duplicating both file descriptors.
    ///
    /// Each clone refers to the same underlying pipe objects, so waking or
    /// draining from any clone affects the shared readiness state.
    fn clone(&self) -> Self {
        let read_fd = self
            .read_fd
            .try_clone()
            .expect("wake pipe read fd should be clonable");
        let write_fd = self
            .write_fd
            .try_clone()
            .expect("wake pipe write fd should be clonable");
        Self { read_fd, write_fd }
    }
}

impl Default for WakePipe {
    fn default() -> Self {
        Self::new()
    }
}

/// Set `O_NONBLOCK` and `FD_CLOEXEC` on a file descriptor.
///
/// # Safety
///
/// `fd` must be a valid open file descriptor.
///
/// Why these flags matter:
/// - `O_NONBLOCK`: wake helpers should never hang the runtime on a read/write
///   path that is supposed to be just a signal
/// - `FD_CLOEXEC`: if smolvm later `exec`s another process, these internal
///   coordination fds should not leak into that child
unsafe fn set_nonblock_cloexec(fd: RawFd) {
    // SAFETY: caller guarantees `fd` is valid.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(
        flags >= 0,
        "fcntl(F_GETFL) failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: caller guarantees `fd` is valid.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert!(
        result >= 0,
        "fcntl(F_SETFL) failed: {}",
        std::io::Error::last_os_error()
    );

    // SAFETY: caller guarantees `fd` is valid.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(
        flags >= 0,
        "fcntl(F_GETFD) failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: caller guarantees `fd` is valid.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    assert!(
        result >= 0,
        "fcntl(F_SETFD) failed: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_pipe_round_trip() {
        let pipe = WakePipe::new();
        pipe.wake();
        assert!(pipe.wait(Some(Duration::from_millis(10))).unwrap());
        pipe.drain();
        assert!(!pipe.wait(Some(Duration::from_millis(1))).unwrap());
    }

    #[test]
    fn queues_are_fifo() {
        let queues = NetworkFrameQueues::shared(4);
        queues.guest_to_host.push(vec![1, 2, 3]).unwrap();
        queues.guest_to_host.push(vec![4, 5, 6]).unwrap();

        assert_eq!(queues.guest_to_host.pop(), Some(vec![1, 2, 3]));
        assert_eq!(queues.guest_to_host.pop(), Some(vec![4, 5, 6]));
        assert_eq!(queues.guest_to_host.pop(), None);
    }
}
