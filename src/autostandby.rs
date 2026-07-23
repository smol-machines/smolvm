//! Auto-standby: stop an idle machine's VMM to free its host RAM, and bring it
//! back on demand.
//!
//! Clean-room design, built on smolvm's own primitives. The behavior mirrors
//! what a browser/agent hosting platform needs — a machine that serves in
//! bursts and sits idle in between should consume ~no host resources while idle
//! and come back on the next request — without depending on any external
//! implementation.
//!
//! # What this module provides
//!
//! - [`ActivityTracker`]: per-machine live-activity accounting. Control-plane
//!   operations (exec/run/file-copy) hold a [`LeaseGuard`]; inbound connections
//!   hold an [`InboundGuard`]. A sticky `last_active_tick` records the most
//!   recent activity. Cheap to poll (atomics), safe to share.
//! - [`IdleController`]: a deterministic state machine that turns "no activity
//!   for `idle_timeout` seconds" into an [`IdleDecision::Hibernate`] without
//!   ever blocking the caller's loop — the same non-blocking-scheduler idiom the
//!   supervisor uses for restart backoff.
//!
//! The supervisor drives these each tick: it reads a machine's activity
//! snapshot, asks the controller, and on [`IdleDecision::Hibernate`] stops the
//! VMM process and marks the record [`crate::config::RecordState::Standby`]
//! (freeing its guest RAM). A later `start`/`exec` boots it again through the
//! normal launch path.
//!
//! # Scope of "standby"
//!
//! Stopping the VMM frees RAM and CPU — real scale-to-zero. It does not yet
//! preserve in-guest RAM *state* across the stop: waking cold-boots the machine
//! rather than resuming its exact memory image. Preserving RAM state would let
//! `machine fork`'s snapshot machinery serialize guest RAM to disk and restore
//! from it; that is a later enhancement layered on the same control plane, not a
//! precondition for the stop-on-idle behavior implemented here.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

/// Per-machine live-activity accounting.
///
/// A machine is "active" while it is doing work a user would not want
/// interrupted. We count two independent, additive signals:
///
/// - **Inbound connections**: how many host→guest forwarded connections are
///   currently open. smolvm's host-side port listeners
///   (`smolvm-network::TcpPortListeners`) accept each inbound connection in the
///   VMM process; incrementing on accept and decrementing on close gives an
///   exact live count without any conntrack/netlink dependency. Replies to the
///   guest's *own* outbound requests are not counted — only connections where
///   the guest is the responder — which matches the intent: a machine polling
///   an API outbound should still be allowed to go idle.
/// - **Control-plane leases**: an exec/run/file-copy in flight holds a lease
///   via [`ActivityTracker::lease`]. A short-lived RPC keeps the machine awake
///   for its duration and briefly after, so a burst of `exec`s doesn't race the
///   reaper.
///
/// The tracker is cheap to poll (atomics) and safe to share across the
/// supervisor task and the per-VM network threads.
#[derive(Debug, Default)]
pub struct ActivityTracker {
    inner: Mutex<HashMap<String, Arc<MachineActivity>>>,
}

#[derive(Debug, Default)]
struct MachineActivity {
    /// Currently-open inbound connections.
    inbound: AtomicU64,
    /// Currently-held control-plane leases (exec/run/cp).
    leases: AtomicU64,
    /// Monotonic tick (see [`ActivityTracker::mark`]) of the last observed
    /// activity: a new inbound connection, a lease acquisition, or an explicit
    /// mark. Compared against the caller's clock to compute idle duration.
    last_active_tick: AtomicU64,
}

impl ActivityTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    fn entry(&self, name: &str) -> Arc<MachineActivity> {
        let mut map = self.inner.lock();
        Arc::clone(
            map.entry(name.to_string())
                .or_insert_with(|| Arc::new(MachineActivity::default())),
        )
    }

    /// Record an inbound connection opening. Returns an [`InboundGuard`] that
    /// decrements the live count when dropped, so the caller cannot leak a
    /// count by forgetting to close.
    pub fn inbound_opened(&self, name: &str, now_tick: u64) -> InboundGuard {
        let a = self.entry(name);
        a.inbound.fetch_add(1, Ordering::AcqRel);
        a.last_active_tick.store(now_tick, Ordering::Release);
        InboundGuard { activity: a }
    }

    /// Acquire a control-plane lease (held for the duration of an exec/run/cp).
    /// Returns a [`LeaseGuard`] that releases on drop.
    pub fn lease(&self, name: &str, now_tick: u64) -> LeaseGuard {
        let a = self.entry(name);
        a.leases.fetch_add(1, Ordering::AcqRel);
        a.last_active_tick.store(now_tick, Ordering::Release);
        LeaseGuard { activity: a }
    }

    /// Explicitly stamp activity without holding a guard — for one-shot events
    /// (a completed request, a signal from the guest) that should reset the
    /// idle clock but have no natural lifetime.
    pub fn mark(&self, name: &str, now_tick: u64) {
        let a = self.entry(name);
        a.last_active_tick.store(now_tick, Ordering::Release);
    }

    /// Snapshot a machine's activity: `(open_inbound, held_leases,
    /// last_active_tick)`. A machine with no entry yet reads as never-active
    /// with zero live work.
    pub fn snapshot(&self, name: &str) -> ActivitySnapshot {
        let map = self.inner.lock();
        match map.get(name) {
            Some(a) => ActivitySnapshot {
                inbound: a.inbound.load(Ordering::Acquire),
                leases: a.leases.load(Ordering::Acquire),
                last_active_tick: a.last_active_tick.load(Ordering::Acquire),
            },
            None => ActivitySnapshot::default(),
        }
    }

    /// Drop all accounting for a machine (on delete). Live guards still
    /// decrement their own captured `Arc`, so this cannot underflow.
    pub fn forget(&self, name: &str) {
        self.inner.lock().remove(name);
    }

    /// True when the machine has no open inbound connections and no held
    /// leases — a precondition for even considering hibernation.
    pub fn is_quiescent(&self, name: &str) -> bool {
        let s = self.snapshot(name);
        s.inbound == 0 && s.leases == 0
    }
}

/// A point-in-time read of a machine's activity counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActivitySnapshot {
    /// Open inbound connections right now.
    pub inbound: u64,
    /// Control-plane leases held right now.
    pub leases: u64,
    /// Tick of the most recent activity.
    pub last_active_tick: u64,
}

/// Decrements a machine's inbound count when dropped.
#[must_use = "dropping the guard immediately closes the tracked connection"]
#[derive(Debug)]
pub struct InboundGuard {
    activity: Arc<MachineActivity>,
}

impl Drop for InboundGuard {
    fn drop(&mut self) {
        self.activity.inbound.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Releases a control-plane lease when dropped.
#[must_use = "dropping the guard immediately releases the lease"]
#[derive(Debug)]
pub struct LeaseGuard {
    activity: Arc<MachineActivity>,
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.activity.leases.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The decision the [`IdleController`] reaches for one machine on one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleDecision {
    /// Machine is doing live work (or has no idle timeout) — nothing to do.
    Active,
    /// Machine just went quiet this tick; the idle countdown is now armed.
    Armed,
    /// Machine is quiet and the countdown has not yet elapsed — keep waiting.
    Waiting,
    /// Machine has been quiet for the full idle timeout — hibernate it now.
    Hibernate,
}

/// Turns per-machine activity into hibernate decisions without blocking.
///
/// This is the direct analogue of the supervisor's restart scheduler: the
/// single supervisor task owns one controller, so the armed-timer map needs no
/// synchronization, and no code path ever sleeps inside the shared loop. A
/// machine that stays idle for its whole timeout is hibernated on the first
/// tick at or after the deadline; any activity in between disarms it.
///
/// The controller is generic over a monotonic clock expressed in the same
/// `tick` unit the [`ActivityTracker`] is stamped with (seconds since some
/// fixed epoch works well). Keeping the clock a parameter is what makes the
/// whole state machine deterministic under test.
#[derive(Debug, Default)]
pub struct IdleController {
    /// Machine → tick at which its hibernate becomes due. Absent = not armed.
    armed_at: HashMap<String, u64>,
}

impl IdleController {
    /// Create a controller with no machines armed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate one machine.
    ///
    /// - `idle_timeout`: the machine's configured timeout; `None`/zero disables
    ///   auto-standby and always yields [`IdleDecision::Active`].
    /// - `activity`: the current activity snapshot from [`ActivityTracker`].
    /// - `now_tick`: the current monotonic tick.
    ///
    /// The rule: a machine is a hibernate candidate only while it is fully
    /// quiescent (no inbound, no leases). The countdown runs from the later of
    /// "when it went quiet" (`last_active_tick`) and "when we first noticed it
    /// quiet" (the armed tick), so a machine that was busy right up to this
    /// tick gets the full timeout, not a partial one.
    pub fn evaluate(
        &mut self,
        name: &str,
        idle_timeout: Option<Duration>,
        activity: ActivitySnapshot,
        now_tick: u64,
    ) -> IdleDecision {
        let timeout_secs = match idle_timeout {
            Some(d) if d.as_secs() > 0 => d.as_secs(),
            _ => {
                // Auto-standby disabled: make sure any stale arming is cleared
                // so re-enabling later starts fresh.
                self.armed_at.remove(name);
                return IdleDecision::Active;
            }
        };

        // Live work → not a candidate. Disarm.
        if activity.inbound > 0 || activity.leases > 0 {
            self.armed_at.remove(name);
            return IdleDecision::Active;
        }

        match self.armed_at.get(name).copied() {
            None => {
                // First quiet tick. Arm from the later of now and the last
                // activity we saw, so recent activity extends the countdown.
                let base = now_tick.max(activity.last_active_tick);
                self.armed_at.insert(name.to_string(), base);
                IdleDecision::Armed
            }
            Some(armed_tick) => {
                // If activity happened after we armed (e.g. a connection opened
                // and closed within one interval, bumping last_active_tick),
                // push the deadline out rather than firing early.
                let base = armed_tick.max(activity.last_active_tick);
                if base > armed_tick {
                    self.armed_at.insert(name.to_string(), base);
                }
                let due = base.saturating_add(timeout_secs);
                if now_tick >= due {
                    self.armed_at.remove(name);
                    IdleDecision::Hibernate
                } else {
                    IdleDecision::Waiting
                }
            }
        }
    }

    /// Forget a machine's arming (on hibernate completion, wake, or delete) so
    /// its next idle period re-arms from scratch.
    pub fn clear(&mut self, name: &str) {
        self.armed_at.remove(name);
    }

    /// Drop arming for machines not in `live` so the map can't grow across
    /// deletes. Mirrors the supervisor's `next_restart_at` retain.
    pub fn retain_only(&mut self, live: &[String]) {
        self.armed_at.retain(|n, _| live.iter().any(|l| l == n));
    }

    /// Whether a machine currently has an armed countdown (test/telemetry).
    pub fn is_armed(&self, name: &str) -> bool {
        self.armed_at.contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Option<Duration> = Some(Duration::from_secs(30));

    #[test]
    fn no_timeout_is_always_active() {
        let mut c = IdleController::new();
        let quiet = ActivitySnapshot::default();
        assert_eq!(c.evaluate("m", None, quiet, 100), IdleDecision::Active);
        assert_eq!(
            c.evaluate("m", Some(Duration::ZERO), quiet, 100),
            IdleDecision::Active
        );
        assert!(!c.is_armed("m"));
    }

    #[test]
    fn live_inbound_keeps_active_and_disarms() {
        let mut c = IdleController::new();
        // Arm while quiet.
        assert_eq!(
            c.evaluate("m", T, ActivitySnapshot::default(), 0),
            IdleDecision::Armed
        );
        assert!(c.is_armed("m"));
        // A connection opens → active again, arming cleared.
        let busy = ActivitySnapshot {
            inbound: 1,
            leases: 0,
            last_active_tick: 5,
        };
        assert_eq!(c.evaluate("m", T, busy, 5), IdleDecision::Active);
        assert!(!c.is_armed("m"));
    }

    #[test]
    fn held_lease_keeps_active() {
        let mut c = IdleController::new();
        let leased = ActivitySnapshot {
            inbound: 0,
            leases: 2,
            last_active_tick: 3,
        };
        assert_eq!(c.evaluate("m", T, leased, 3), IdleDecision::Active);
        assert!(!c.is_armed("m"));
    }

    #[test]
    fn arms_then_waits_then_hibernates() {
        let mut c = IdleController::new();
        let quiet = ActivitySnapshot::default();
        // t=0: first quiet tick arms.
        assert_eq!(c.evaluate("m", T, quiet, 0), IdleDecision::Armed);
        // t=15: still before the 30s deadline.
        assert_eq!(c.evaluate("m", T, quiet, 15), IdleDecision::Waiting);
        // t=29: still waiting.
        assert_eq!(c.evaluate("m", T, quiet, 29), IdleDecision::Waiting);
        // t=30: deadline reached → hibernate, arming cleared.
        assert_eq!(c.evaluate("m", T, quiet, 30), IdleDecision::Hibernate);
        assert!(!c.is_armed("m"));
    }

    #[test]
    fn recent_activity_extends_the_deadline() {
        let mut c = IdleController::new();
        // Arm at t=0.
        assert_eq!(
            c.evaluate("m", T, ActivitySnapshot::default(), 0),
            IdleDecision::Armed
        );
        // At t=20 the machine is quiescent NOW but a connection was last active
        // at t=20 (opened+closed within the interval). Deadline must move to
        // t=20+30=50, not fire at 30.
        let recently = ActivitySnapshot {
            inbound: 0,
            leases: 0,
            last_active_tick: 20,
        };
        assert_eq!(c.evaluate("m", T, recently, 20), IdleDecision::Waiting);
        // t=45: still before the extended deadline.
        assert_eq!(
            c.evaluate("m", T, ActivitySnapshot::default(), 45),
            IdleDecision::Waiting
        );
        // t=50: now it fires.
        assert_eq!(
            c.evaluate("m", T, ActivitySnapshot::default(), 50),
            IdleDecision::Hibernate
        );
    }

    #[test]
    fn full_timeout_after_busy_period() {
        // A machine busy right up to t=100 must get the whole 30s, i.e. not
        // hibernate before t=130 even though we only notice it quiet at t=100.
        let mut c = IdleController::new();
        let just_quiet = ActivitySnapshot {
            inbound: 0,
            leases: 0,
            last_active_tick: 100,
        };
        assert_eq!(c.evaluate("m", T, just_quiet, 100), IdleDecision::Armed);
        assert_eq!(
            c.evaluate("m", T, ActivitySnapshot::default(), 129),
            IdleDecision::Waiting
        );
        assert_eq!(
            c.evaluate("m", T, ActivitySnapshot::default(), 130),
            IdleDecision::Hibernate
        );
    }

    #[test]
    fn retain_only_prunes_deleted_machines() {
        let mut c = IdleController::new();
        c.evaluate("a", T, ActivitySnapshot::default(), 0);
        c.evaluate("b", T, ActivitySnapshot::default(), 0);
        assert!(c.is_armed("a") && c.is_armed("b"));
        c.retain_only(&["a".to_string()]);
        assert!(c.is_armed("a"));
        assert!(!c.is_armed("b"));
    }

    #[test]
    fn tracker_counts_inbound_and_leases_with_guards() {
        let t = ActivityTracker::new();
        assert!(t.is_quiescent("m"));

        let g1 = t.inbound_opened("m", 1);
        let g2 = t.inbound_opened("m", 2);
        let l1 = t.lease("m", 3);
        let s = t.snapshot("m");
        assert_eq!(s.inbound, 2);
        assert_eq!(s.leases, 1);
        assert_eq!(s.last_active_tick, 3);
        assert!(!t.is_quiescent("m"));

        drop(g1);
        assert_eq!(t.snapshot("m").inbound, 1);
        drop(g2);
        drop(l1);
        assert!(t.is_quiescent("m"));
        // last_active_tick is sticky — it records the last activity, not the
        // current count.
        assert_eq!(t.snapshot("m").last_active_tick, 3);
    }

    #[test]
    fn forget_resets_a_machine() {
        let t = ActivityTracker::new();
        let _g = t.inbound_opened("m", 1);
        t.forget("m");
        // A fresh entry reads clean; the old guard's later drop can't underflow
        // because it holds its own Arc.
        assert_eq!(t.snapshot("m"), ActivitySnapshot::default());
    }

    #[test]
    fn end_to_end_tracker_plus_controller() {
        // Wire the two together the way the supervisor will: read a snapshot,
        // feed it to the controller.
        let t = ActivityTracker::new();
        let mut c = IdleController::new();
        let name = "web";

        // Serving a request at t=0..t=5.
        let conn = t.inbound_opened(name, 0);
        assert_eq!(
            c.evaluate(name, T, t.snapshot(name), 0),
            IdleDecision::Active
        );
        drop(conn); // request done at ~t=5
        t.mark(name, 5);

        // Goes quiet: arm at t=5, wait, fire at t=35.
        assert_eq!(
            c.evaluate(name, T, t.snapshot(name), 5),
            IdleDecision::Armed
        );
        assert_eq!(
            c.evaluate(name, T, t.snapshot(name), 20),
            IdleDecision::Waiting
        );
        assert_eq!(
            c.evaluate(name, T, t.snapshot(name), 35),
            IdleDecision::Hibernate
        );
    }
}
