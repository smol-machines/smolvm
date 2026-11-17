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
//! 2. a way to wake a thread that is blocked waiting on socket readiness
//!
//! This module provides both:
//! - `ArrayQueue<Vec<u8>>` for frame ownership transfer
//! - `WakePipe` as a tiny readiness primitive built on a cross-platform poller
//!   (`polling`, which maps to epoll/kqueue/IOCP). Its `notify()` is the
//!   cross-thread wakeup, replacing the old self-pipe.
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

use crate::tcp_relay::FlowSummary;
use crossbeam_queue::ArrayQueue;
use polling::{Events, Poller};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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
    ///
    /// `guest_wake` and `relay_wake` deliberately share one underlying poller:
    /// the smoltcp loop blocks on that single poller and either wake unblocks
    /// it. The loop re-runs its whole pipeline on every wakeup, so it does not
    /// need to know which side fired.
    pub guest_wake: WakePipe,
    /// Wake the libkrun writer thread when a host frame is ready.
    pub host_wake: WakePipe,
    /// Wake the smoltcp poll loop when a TCP relay thread has new data.
    pub relay_wake: WakePipe,
    /// Signals that the helper process should shut down.
    shutting_down: AtomicBool,
    /// Cumulative guest-outbound (egress) bytes for this NIC since boot, at the
    /// ethernet-frame level — every guest frame accepted into the stack is
    /// counted. Used for per-machine egress billing/telemetry. Held behind an
    /// `Arc` so the runtime owner can hand a cheap read handle to a flush thread
    /// without exposing the rest of the queue set.
    egress_bytes: Arc<AtomicU64>,
    /// The poll loop's latest open-flow summary and when it was taken, for a
    /// flush thread owned by the launcher. Written on a slow cadence only.
    flow_summary: FlowSummarySlot,
}

/// Shared slot holding the latest [`FlowSummary`] and the wall-clock time it
/// was taken; `None` until the poll loop has published one.
pub type FlowSummarySlot = Arc<Mutex<Option<(SystemTime, FlowSummary)>>>;

impl NetworkFrameQueues {
    /// Create a new shared queue set wrapped in `Arc`.
    pub fn shared(capacity: usize) -> Arc<Self> {
        // The smoltcp poll loop waits on a single poller; both the guest-frame
        // wake and the relay wake notify it, so they share one poller instance.
        let poll_loop = WakePipe::new();
        let relay_wake = poll_loop.share();
        Arc::new(Self {
            guest_to_host: ArrayQueue::new(capacity),
            host_to_guest: ArrayQueue::new(capacity),
            guest_wake: poll_loop,
            host_wake: WakePipe::new(),
            relay_wake,
            shutting_down: AtomicBool::new(false),
            egress_bytes: Arc::new(AtomicU64::new(0)),
            flow_summary: Arc::new(Mutex::new(None)),
        })
    }

    /// Add `n` guest-outbound bytes to the egress counter. Relaxed ordering is
    /// fine: the counter is a monotonic statistic, not a synchronization point.
    pub fn add_egress_bytes(&self, n: u64) {
        self.egress_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Cumulative guest-outbound bytes for this NIC since boot.
    pub fn egress_bytes(&self) -> u64 {
        self.egress_bytes.load(Ordering::Relaxed)
    }

    /// A cheap, cloneable read handle to the egress counter, for a flush thread
    /// owned by the launcher (the runtime itself is not `Clone`).
    pub fn egress_counter(&self) -> Arc<AtomicU64> {
        self.egress_bytes.clone()
    }

    /// Replace the published open-flow summary.
    pub(crate) fn publish_flow_summary(&self, summary: FlowSummary) {
        let mut slot = self
            .flow_summary
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some((SystemTime::now(), summary));
    }

    /// A cheap, cloneable read handle to the open-flow summary slot, for a
    /// flush thread owned by the launcher.
    pub fn flow_summary_slot(&self) -> FlowSummarySlot {
        self.flow_summary.clone()
    }

    /// Mark the runtime as shutting down and wake all waiters.
    ///
    /// The wakes are part of shutdown correctness. Without them, a thread
    /// blocked waiting on socket readiness could sleep indefinitely even though
    /// the shutdown flag was already set.
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

/// Cross-thread wake notification built on a cross-platform poller.
///
/// The pattern is:
/// - one thread blocks waiting on the poller (optionally alongside registered
///   socket sources)
/// - another thread calls [`WakePipe::wake`] to unblock it
/// - the waiter resumes; the wake is auto-cleared by the next `wait`
///
/// Why a poller rather than a self-pipe: `polling::Poller::notify()` is a
/// portable cross-thread wakeup that works on Windows (where a `pipe(2)` is not
/// pollable by the IOCP/wepoll backend) as well as Unix. The same poller can
/// have socket sources registered on it, which lets the ICMP/UDP relay loops
/// wait on "wake OR any flow socket readable" in a single blocking call.
#[derive(Clone, Debug)]
pub struct WakePipe {
    poller: Arc<Poller>,
}

impl WakePipe {
    /// Create a wake notification with its own poller.
    pub fn new() -> Self {
        Self {
            poller: Arc::new(Poller::new().expect("create poller for wake notification")),
        }
    }

    /// Create another handle that shares this wake's underlying poller.
    ///
    /// Two `WakePipe`s built this way notify the same waiter: useful when one
    /// loop must wake on either of two logical events (the smoltcp loop wakes on
    /// guest frames or relay data).
    pub fn share(&self) -> Self {
        Self {
            poller: self.poller.clone(),
        }
    }

    /// The underlying poller, so a caller can register socket sources on it and
    /// block on "this wake OR a socket" in a single `wait`.
    pub fn poller(&self) -> &Arc<Poller> {
        &self.poller
    }

    /// Signal the waiting side.
    ///
    /// Multiple wakes coalesce: until the waiter next blocks, repeated notifies
    /// collapse into a single "there is pending wake state".
    pub fn wake(&self) {
        // A failed notify only means the waiter will rely on its poll timeout;
        // it is never fatal.
        let _ = self.poller.notify();
    }

    /// Drain pending wake state.
    ///
    /// With a poller-backed waker the notification is consumed by `wait`
    /// itself, so this is a no-op kept for API symmetry with the old self-pipe.
    pub fn drain(&self) {}

    /// Wait until woken or the timeout elapses.
    ///
    /// Returns `Ok(true)` if the wait ended because of a wake (a `notify` or a
    /// registered source becoming ready), `Ok(false)` if the timeout elapsed.
    ///
    /// A `notify`-driven wakeup reports no events (the poller consumes the
    /// notification internally), so a pure wake is detected as either a
    /// non-empty event set or an early return: the wait unblocked before the
    /// requested deadline.
    pub fn wait(&self, timeout: Option<Duration>) -> std::io::Result<bool> {
        let mut events = Events::new();
        let start = std::time::Instant::now();
        let count = self.poller.wait(&mut events, timeout)?;
        if count > 0 {
            return Ok(true);
        }
        match timeout {
            // Without a deadline, the only way `wait` returns is a wake.
            None => Ok(true),
            // With a deadline, an early return means a `notify` woke us; a
            // return at/after the deadline is a genuine timeout.
            Some(timeout) => Ok(start.elapsed() < timeout),
        }
    }
}

impl Default for WakePipe {
    fn default() -> Self {
        Self::new()
    }
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
    fn shared_wake_notifies_same_waiter() {
        let a = WakePipe::new();
        let b = a.share();
        // Waking the shared handle unblocks a waiter on the original.
        b.wake();
        assert!(a.wait(Some(Duration::from_millis(10))).unwrap());
        a.drain();
        assert!(!a.wait(Some(Duration::from_millis(1))).unwrap());
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
