//! Host memory pressure guard: what happens when branch children, having
//! diverged from their source, fill the host's RAM.
//!
//! Branch admission (`agent::fork::admit_branch_memory`) keeps a reserve free
//! at fork time, but children keep writing afterwards and the per-VM cgroup
//! ceilings add up to far more than the host (copy-on-write density is the
//! point). Without this guard the kernel's global OOM killer picks the victim
//! by size, which is the source — and every child dies with it. The guard
//! watches `/proc/pressure/memory` and `MemAvailable` and, when the host is
//! genuinely short, pauses the newest running branch child: its RAM goes to
//! disk, the host breathes, and the machine stays resumable with a recorded
//! reason (`pause_reason`, `state_reason` in the API). When memory has
//! recovered with margin it resumes those machines one at a time.
//!
//! Sources, held pool slots and machines the user paused are never touched.
//! `SMOLVM_MEMORY_PRESSURE_GUARD=0` turns the guard off; the thresholds are
//! `SMOLVM_MEMORY_PRESSURE_RESERVE_MIB` (default: the branch admission
//! reserve), `SMOLVM_MEMORY_PRESSURE_SOME_PCT` (20) and
//! `SMOLVM_MEMORY_PRESSURE_FULL_PCT` (5).
//!
//! **The VM slice.** Under `serve` with scopes, every VM runs in
//! `smolvm.slice`, capped at `MemoryMax` = host minus the host reserve (see
//! `systemd_scope::configure_vm_slice_memory`); there is no `MemoryHigh`. The
//! guard reads the slice's own `memory.current`, `memory.max` and
//! `memory.events` (not `process::host_memory_stats`, so slice headroom is
//! never counted twice) and acts before the kernel has to:
//!
//! - At [`crate::systemd_scope::VM_SLICE_RECLAIM_TARGET_PERCENT`] (85%) of the
//!   cap it asks the kernel to reclaim the slice, writing a bounded amount
//!   (`SMOLVM_SLICE_RECLAIM_STEP_MIB`, 2048 per write, enough to get back to
//!   80% at most) to `memory.reclaim` from a dedicated thread. That reclaim
//!   runs in the guard's own context, holding no filesystem locks, instead of
//!   inside some VMM's allocation in the middle of an XFS call, where a
//!   throttled reclaim on 2026-11-12 held the AGI buffer lock and stalled
//!   every other VMM and serve itself. One write in flight at a time, at most
//!   one per tick. A write the kernel could not satisfy (`EAGAIN`: what is left
//!   is guest RAM, which has no swap to go to) escalates to the next step.
//! - At `SMOLVM_MEMORY_PRESSURE_SLICE_PCT` (95%) of the cap, when the slice
//!   has hit `memory.max` since the last tick, or when reclaim fell short, it
//!   pauses the newest running branch child, as for host pressure. If nothing
//!   can be paused, or a pause has not finished within
//!   [`ESCALATE_AFTER`] while the slice is still at the line, it kills the
//!   largest running VM that is not a branch source or a held pool slot (one
//!   per [`KILL_COOLDOWN`]), so the kernel's OOM killer does not pick a source
//!   and take its children with it.
//!
//! **What the loop does not do.** The tick reads only procfs and cgroupfs
//! (into buffers allocated once, for the slice files), sends the reclaim
//! amount to the reclaim thread without blocking, and signals a process for a
//! kill. It reads machine records only when it is about to act, on a blocking
//! thread with a timeout (and never two at once), and it never waits on a
//! machine's lifecycle lock: a busy machine is skipped. Pauses and resumes,
//! which write RAM and records to disk, run as one background task at a time;
//! the loop keeps sampling, reclaiming and escalating while one runs.
use crate::api::state::ApiState;
use crate::config::{RecordState, VmRecord};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

const TICK: Duration = Duration::from_secs(2);
/// One resume per this long: a resumed child needs time to show its real footprint.
const RESUME_COOLDOWN: Duration = Duration::from_secs(30);
/// A pause still running after this long, with the slice still at the relief
/// line, is not relieving it fast enough: kill a VM instead.
pub const ESCALATE_AFTER: Duration = Duration::from_secs(20);
/// At most one kill per this long, so the memory it frees shows up before the
/// guard judges whether another is needed.
pub const KILL_COOLDOWN: Duration = Duration::from_secs(15);
/// How long the guard waits for machine records before skipping the tick.
const LIST_TIMEOUT: Duration = Duration::from_secs(5);
/// Reclaim brings the slice back this many points below the reclaim line.
const RECLAIM_HYSTERESIS_PCT: u64 = 5;

/// One reading of the host.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// Effective host (or cgroup) memory, MiB.
    pub total_mib: u64,
    /// `MemAvailable` (or cgroup headroom), MiB.
    pub available_mib: u64,
    /// `/proc/pressure/memory` `some avg10`: % of the last 10 s some task waited for memory.
    pub some_avg10: f64,
    /// `full avg10`: % of the last 10 s every task was stalled on memory.
    pub full_avg10: f64,
}

/// When the guard acts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// Host memory that should stay free (MiB); the guard acts below it.
    pub reserve_mib: u64,
    /// `some avg10` at or above which a host below the reserve counts as under pressure.
    pub some_avg10_pct: f64,
    /// `full avg10` at or above which a host below the reserve counts as under pressure.
    pub full_avg10_pct: f64,
}

/// What the guard knows about one machine.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// Machine name.
    pub name: String,
    /// Creation time (seconds since the epoch): newest children are paused first.
    pub created_at: u64,
    /// Configured guest RAM, MiB: what a resume must fit into the margin.
    pub mem_mib: u64,
    /// A running branch child that is not itself a branch source.
    pub running_clone: bool,
    /// Paused by this guard (a recorded `pause_reason`), so eligible to resume.
    pub paused_by_guard: bool,
    /// A held pool slot: parked on purpose, never a victim.
    pub held: bool,
    /// A branch source (started forkable): never killed, its children share
    /// its RAM and would die with it.
    pub source: bool,
    /// Running with a live process.
    pub running: bool,
    /// VMM process id and start time, to kill exactly this process.
    pub pid: Option<i32>,
    /// Start time recorded with `pid`.
    pub pid_start_time: Option<u64>,
}

/// The guard's action for one tick.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Pause this branch child to relieve the host.
    Pause(String),
    /// Resume this child the guard paused earlier.
    Resume(String),
    /// Nothing this tick.
    Hold,
}

/// `some avg10` and `full avg10` from `/proc/pressure/memory`.
pub fn parse_pressure(text: &str) -> Option<(f64, f64)> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let kind = parts.next()?;
        let avg10 = parts
            .find_map(|p| p.strip_prefix("avg10="))
            .and_then(|v| v.parse::<f64>().ok())?;
        match kind {
            "some" => some = Some(avg10),
            "full" => full = Some(avg10),
            _ => {}
        }
    }
    Some((some?, full.unwrap_or(0.0)))
}

/// Whether the host is short of memory right now: below half the reserve
/// whatever the kernel says, or below the reserve while tasks are already
/// stalling on memory.
pub fn under_pressure(sample: &Sample, t: &Thresholds) -> bool {
    sample.available_mib < t.reserve_mib / 2
        || (sample.available_mib < t.reserve_mib
            && (sample.some_avg10 >= t.some_avg10_pct || sample.full_avg10 >= t.full_avg10_pct))
}

/// The one action for this tick. Under pressure: pause the newest running
/// branch child. With margin (twice the reserve free plus the child's RAM):
/// resume the guard's oldest victim. Otherwise nothing.
pub fn decide(sample: &Sample, t: &Thresholds, candidates: &[Candidate]) -> Decision {
    if under_pressure(sample, t) {
        return pause_victim(candidates)
            .map(Decision::Pause)
            .unwrap_or(Decision::Hold);
    }
    let margin = sample
        .available_mib
        .saturating_sub(t.reserve_mib.saturating_mul(2));
    if margin == 0 {
        return Decision::Hold;
    }
    candidates
        .iter()
        .filter(|c| c.paused_by_guard && c.mem_mib <= margin)
        .min_by_key(|c| (c.created_at, c.name.clone()))
        .map(|c| Decision::Resume(c.name.clone()))
        .unwrap_or(Decision::Hold)
}

/// The newest running branch child that is not a held slot: what the guard
/// pauses first.
pub fn pause_victim(candidates: &[Candidate]) -> Option<String> {
    candidates
        .iter()
        .filter(|c| c.running_clone && !c.held)
        .max_by_key(|c| (c.created_at, c.name.clone()))
        .map(|c| c.name.clone())
}

/// The largest running VM that is neither a branch source nor a held slot
/// (newest on a tie): what the guard kills when pausing cannot relieve the
/// slice. The kernel's OOM killer would pick by size too, but could pick a
/// source.
pub fn kill_victim(candidates: &[Candidate]) -> Option<&Candidate> {
    candidates
        .iter()
        .filter(|c| c.running && !c.source && !c.held && c.pid.is_some())
        .max_by_key(|c| (c.mem_mib, c.created_at, c.name.clone()))
}

/// What the guard may do with one machine, from its record.
pub fn candidate(record: &VmRecord) -> Candidate {
    let running = record.state == RecordState::Running && record.is_process_alive();
    let running_clone = record.golden.is_some() && !record.forkable && running;
    Candidate {
        name: record.name.clone(),
        created_at: record.created_at,
        mem_mib: u64::from(record.mem),
        running_clone,
        paused_by_guard: record.pause_reason.is_some() && record.state == RecordState::Paused,
        held: record.forkpoint_held,
        source: record.forkable,
        running,
        pid: record.pid,
        pid_start_time: record.pid_start_time,
    }
}

/// The VM slice's memory, read straight from its cgroup files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceSample {
    /// `memory.current`: all the kernel charges the slice, page cache included.
    pub current_bytes: u64,
    /// `memory.max` (`MemoryMax`), finite.
    pub max_bytes: u64,
    /// `memory.events` `max`: how often the slice has hit `memory.max`.
    pub max_events: u64,
}

/// When the guard acts on the slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceThresholds {
    /// Percent of `memory.max` from which the guard reclaims the slice:
    /// always [`crate::systemd_scope::VM_SLICE_RECLAIM_TARGET_PERCENT`].
    pub reclaim_pct: u64,
    /// Percent of `memory.max` from which it pauses (or kills).
    pub relieve_pct: u64,
    /// Most bytes asked of `memory.reclaim` in one write.
    pub reclaim_step_bytes: u64,
}

/// What the guard does about the slice this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlicePlan {
    /// Ask the kernel to reclaim this many bytes from the slice.
    pub reclaim_bytes: Option<u64>,
    /// Pause a branch child.
    pub relieve: bool,
    /// At the relief line or at `memory.max`: a kill is allowed when pausing
    /// cannot help.
    pub critical: bool,
}

fn percent_of(bytes: u64, pct: u64) -> u64 {
    u64::try_from(u128::from(bytes) * u128::from(pct) / 100).unwrap_or(u64::MAX)
}

/// The slice thresholds from the relief percent and reclaim step settings
/// (`SMOLVM_MEMORY_PRESSURE_SLICE_PCT`, `SMOLVM_SLICE_RECLAIM_STEP_MIB`). The
/// relief line stays above the reclaim line and at most 100%.
pub fn slice_thresholds(relieve_pct: Option<&str>, step_mib: Option<&str>) -> SliceThresholds {
    let reclaim_pct = crate::systemd_scope::VM_SLICE_RECLAIM_TARGET_PERCENT;
    let relieve_pct = relieve_pct
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(95)
        .clamp(reclaim_pct + 1, 100);
    let step_mib = step_mib
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(2048);
    SliceThresholds {
        reclaim_pct,
        relieve_pct,
        reclaim_step_bytes: step_mib.saturating_mul(1024 * 1024),
    }
}

/// The slice plan for one tick. `hit_max` says the slice hit `memory.max`
/// since the last tick (the kernel reclaimed in some VMM's allocation, the
/// stall this guard exists to prevent); `reclaim_fell_short` says the last
/// `memory.reclaim` write returned `EAGAIN`.
pub fn slice_plan(
    sample: &SliceSample,
    t: &SliceThresholds,
    hit_max: bool,
    reclaim_fell_short: bool,
) -> SlicePlan {
    let reclaim_line = percent_of(sample.max_bytes, t.reclaim_pct);
    if sample.current_bytes < reclaim_line && !hit_max {
        return SlicePlan::default();
    }
    let target = percent_of(
        sample.max_bytes,
        t.reclaim_pct.saturating_sub(RECLAIM_HYSTERESIS_PCT),
    );
    let reclaim = sample
        .current_bytes
        .saturating_sub(target)
        .min(t.reclaim_step_bytes);
    let critical = hit_max || sample.current_bytes >= percent_of(sample.max_bytes, t.relieve_pct);
    SlicePlan {
        reclaim_bytes: (reclaim > 0).then_some(reclaim),
        relieve: critical || reclaim_fell_short,
        critical,
    }
}

/// Whether resuming a child of `mem_mib` keeps the slice under the line it
/// is reclaimed back to. No slice sample (no cap, or not under serve): yes.
pub fn slice_allows_resume(
    sample: Option<&SliceSample>,
    t: &SliceThresholds,
    mem_mib: u64,
) -> bool {
    sample.is_none_or(|s| {
        let line = percent_of(
            s.max_bytes,
            t.reclaim_pct.saturating_sub(RECLAIM_HYSTERESIS_PCT),
        );
        s.current_bytes
            .saturating_add(mem_mib.saturating_mul(1024 * 1024))
            <= line
    })
}

/// A cgroup `memory.max`: `None` for `max` (no limit) or junk.
pub fn parse_memory_max(text: &str) -> Option<u64> {
    text.trim().parse::<u64>().ok()
}

/// The `max` counter from a cgroup `memory.events`.
pub fn parse_events_max(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        (key == "max").then(|| value.trim().parse().ok())?
    })
}

/// Reads the slice's cgroup files through descriptors opened once and one
/// buffer allocated once, so a tick under memory pressure allocates nothing
/// and touches no disk filesystem.
// Unix rather than Linux so it compiles (and finds no slice) on macOS too.
#[cfg(unix)]
struct SliceReader {
    files: Option<[std::fs::File; 3]>,
    buf: Vec<u8>,
}

// Unix rather than Linux so it compiles (and finds no slice) on macOS too.
#[cfg(unix)]
impl SliceReader {
    fn dir() -> std::path::PathBuf {
        std::path::Path::new("/sys/fs/cgroup").join(crate::systemd_scope::VM_SLICE)
    }

    fn new() -> Self {
        Self {
            files: None,
            buf: vec![0; 4096],
        }
    }

    fn read_one(file: &std::fs::File, buf: &mut [u8]) -> Option<usize> {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, 0).ok()
    }

    /// The slice now, or `None` when it has no finite cap (or does not exist
    /// yet: systemd creates it with the first VM).
    fn read(&mut self) -> Option<SliceSample> {
        if self.files.is_none() {
            let dir = Self::dir();
            let open = |name: &str| std::fs::File::open(dir.join(name)).ok();
            self.files = Some([
                open("memory.current")?,
                open("memory.max")?,
                open("memory.events")?,
            ]);
        }
        let files = self.files.as_ref()?;
        let mut values = [0u64; 3];
        let mut gone = false;
        for (i, file) in files.iter().enumerate() {
            let Some(n) = Self::read_one(file, &mut self.buf) else {
                gone = true;
                break;
            };
            let text = std::str::from_utf8(&self.buf[..n]).ok()?;
            values[i] = match i {
                1 => parse_memory_max(text)?,
                2 => parse_events_max(text).unwrap_or(0),
                _ => text.trim().parse().ok()?,
            };
        }
        if gone {
            // The slice went away (systemd collects an empty one): reopen next
            // tick.
            self.files = None;
            return None;
        }
        Some(SliceSample {
            current_bytes: values[0],
            max_bytes: values[1],
            max_events: values[2],
        })
    }
}

/// The thread that writes `memory.reclaim`. The kernel reclaims in the
/// writer's context, so this thread, holding no filesystem locks, does the
/// work a VMM would otherwise do in its own allocation.
// Unix rather than Linux so it compiles (and finds no slice) on macOS too.
#[cfg(unix)]
struct Reclaimer {
    requests: std::sync::mpsc::SyncSender<u64>,
    busy: Arc<AtomicBool>,
    fell_short: Arc<AtomicBool>,
}

// Unix rather than Linux so it compiles (and finds no slice) on macOS too.
#[cfg(unix)]
impl Reclaimer {
    /// Start the thread, or `None` when the kernel has no `memory.reclaim`
    /// (before 5.19) or the slice does not exist yet.
    fn spawn() -> Option<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(SliceReader::dir().join("memory.reclaim"))
            .ok()?;
        let (requests, rx) = std::sync::mpsc::sync_channel::<u64>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let fell_short = Arc::new(AtomicBool::new(false));
        let (thread_busy, thread_short) = (busy.clone(), fell_short.clone());
        std::thread::Builder::new()
            .name("smolvm-reclaim".into())
            .spawn(move || {
                use std::io::Write as _;
                use std::os::unix::fs::FileExt;
                let mut buf: Vec<u8> = Vec::with_capacity(32);
                while let Ok(bytes) = rx.recv() {
                    buf.clear();
                    let _ = write!(buf, "{bytes}");
                    let started = Instant::now();
                    match file.write_at(&buf, 0) {
                        Ok(_) => {
                            thread_short.store(false, Ordering::Relaxed);
                            metrics::counter!("smolvm_slice_reclaim_bytes_total").increment(bytes);
                        }
                        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                            thread_short.store(true, Ordering::Relaxed);
                            metrics::counter!("smolvm_slice_reclaim_short_total").increment(1);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, bytes, "VM slice reclaim write failed");
                        }
                    }
                    tracing::debug!(
                        bytes,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "VM slice reclaim"
                    );
                    thread_busy.store(false, Ordering::Relaxed);
                }
            })
            .ok()?;
        Some(Self {
            requests,
            busy,
            fell_short,
        })
    }

    /// Ask for `bytes` unless a write is still running. Never blocks.
    fn request(&self, bytes: u64) {
        if self.busy.swap(true, Ordering::Relaxed) {
            return;
        }
        if self.requests.try_send(bytes).is_err() {
            self.busy.store(false, Ordering::Relaxed);
        }
    }

    fn fell_short(&self) -> bool {
        self.fell_short.load(Ordering::Relaxed)
    }
}

/// The host right now: memory and pressure.
#[cfg(target_os = "linux")]
pub fn read_sample() -> Option<Sample> {
    const MIB: u64 = 1024 * 1024;
    let memory = crate::process::host_memory_stats()?;
    let (some_avg10, full_avg10) = std::fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|t| parse_pressure(&t))
        .unwrap_or((0.0, 0.0));
    Some(Sample {
        total_mib: memory.total_bytes / MIB,
        available_mib: memory.available_bytes / MIB,
        some_avg10,
        full_avg10,
    })
}

/// The host right now; no pressure file off Linux, so no guard.
#[cfg(not(target_os = "linux"))]
pub fn read_sample() -> Option<Sample> {
    None
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The thresholds for a host with `total_mib` of memory, or None when the
/// guard is off (explicitly, or because branch admission is off).
pub fn thresholds(total_mib: u64) -> Option<Thresholds> {
    if std::env::var("SMOLVM_MEMORY_PRESSURE_GUARD").as_deref() == Ok("0") {
        return None;
    }
    let reserve_mib = match std::env::var("SMOLVM_MEMORY_PRESSURE_RESERVE_MIB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(v) => v,
        None => {
            crate::agent::fork::branch_admission_params(total_mib)
                .ok()
                .flatten()?
                .reserve_mib
        }
    };
    Some(Thresholds {
        reserve_mib,
        some_avg10_pct: env_f64("SMOLVM_MEMORY_PRESSURE_SOME_PCT", 20.0),
        full_avg10_pct: env_f64("SMOLVM_MEMORY_PRESSURE_FULL_PCT", 5.0),
    })
}

/// The slice thresholds from the environment.
fn slice_thresholds_from_env() -> SliceThresholds {
    slice_thresholds(
        std::env::var("SMOLVM_MEMORY_PRESSURE_SLICE_PCT")
            .ok()
            .as_deref(),
        std::env::var("SMOLVM_SLICE_RECLAIM_STEP_MIB")
            .ok()
            .as_deref(),
    )
}

/// The slice now; never one off Linux.
#[cfg(not(unix))]
struct SliceReader;

#[cfg(not(unix))]
impl SliceReader {
    fn new() -> Self {
        Self
    }
    fn read(&mut self) -> Option<SliceSample> {
        None
    }
}

#[cfg(not(unix))]
struct Reclaimer;

#[cfg(not(unix))]
impl Reclaimer {
    fn spawn() -> Option<Self> {
        None
    }
    fn request(&self, _bytes: u64) {}
    fn fell_short(&self) -> bool {
        false
    }
}

/// A pause or resume running in the background.
struct InFlight {
    handle: tokio::task::JoinHandle<bool>,
    started: Instant,
    resume: bool,
}

/// Machine records for the guard's decision, read on a blocking thread. `None`
/// when a previous read is still running or this one outlasts
/// [`LIST_TIMEOUT`] (a stalled disk): the tick is skipped, the loop is not.
async fn list_candidates(state: &Arc<ApiState>, busy: &Arc<AtomicBool>) -> Option<Vec<Candidate>> {
    if busy.swap(true, Ordering::Relaxed) {
        return None;
    }
    let names = state.list_machine_names();
    let db = state.db().clone();
    let done = busy.clone();
    let handle = tokio::task::spawn_blocking(move || {
        let candidates = names
            .into_iter()
            .filter_map(|n| db.get_vm(&n).ok().flatten())
            .map(|r| candidate(&r))
            .collect::<Vec<_>>();
        done.store(false, Ordering::Relaxed);
        candidates
    });
    match tokio::time::timeout(LIST_TIMEOUT, handle).await {
        Ok(Ok(candidates)) => Some(candidates),
        _ => None,
    }
}

/// Kill the slice's [`kill_victim`], at most one per [`KILL_COOLDOWN`].
fn kill_for_slice(candidates: &[Candidate], slice: &SliceSample, last_kill: &mut Option<Instant>) {
    if last_kill.is_some_and(|at| at.elapsed() < KILL_COOLDOWN) {
        return;
    }
    let Some(victim) = kill_victim(candidates) else {
        return;
    };
    let Some(pid) = victim.pid else { return };
    tracing::error!(
        machine = %victim.name,
        pid,
        mem_mib = victim.mem_mib,
        slice_current_bytes = slice.current_bytes,
        slice_max_bytes = slice.max_bytes,
        "VM slice at its memory cap and pausing cannot relieve it; killing the largest non-source VM"
    );
    if crate::process::kill_verified(pid, victim.pid_start_time) {
        metrics::counter!("smolvm_memory_pressure_kills_total").increment(1);
        *last_kill = Some(Instant::now());
    }
}

/// The guard loop; returns on shutdown.
pub async fn run(state: Arc<ApiState>, mut shutdown_rx: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_resume: Option<Instant> = None;
    let mut last_kill: Option<Instant> = None;
    let mut announced = false;
    let slice_t = slice_thresholds_from_env();
    let mut slice_reader = SliceReader::new();
    let mut reclaimer: Option<Reclaimer> = None;
    let mut reclaim_tried = false;
    let mut last_max_events: Option<u64> = None;
    let mut in_flight: Option<InFlight> = None;
    // Unknown after a restart: look once for children an earlier serve paused.
    let mut may_have_guard_paused = true;
    let listing = Arc::new(AtomicBool::new(false));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let Some(sample) = read_sample() else { continue };
                let Some(t) = thresholds(sample.total_mib) else { continue };
                let slice = slice_reader.read();
                if slice.is_some() && !reclaim_tried {
                    // Once: a kernel without memory.reclaim (before 5.19)
                    // keeps only the pause/kill step.
                    reclaim_tried = true;
                    reclaimer = Reclaimer::spawn();
                    if reclaimer.is_none() {
                        tracing::warn!("VM slice has no usable memory.reclaim; the guard can only pause or kill");
                    }
                }
                if !announced {
                    tracing::info!(
                        reserve_mib = t.reserve_mib,
                        some_pct = t.some_avg10_pct,
                        full_pct = t.full_avg10_pct,
                        slice_reclaim_pct = slice_t.reclaim_pct,
                        slice_relieve_pct = slice_t.relieve_pct,
                        slice_reclaim_step_bytes = slice_t.reclaim_step_bytes,
                        "memory pressure guard active"
                    );
                    announced = true;
                }
                let hit_max = match (slice, last_max_events) {
                    (Some(now), Some(before)) => now.max_events > before,
                    _ => false,
                };
                last_max_events = slice.map(|s| s.max_events);
                let fell_short = reclaimer.as_ref().is_some_and(Reclaimer::fell_short);
                let plan = slice
                    .map(|s| slice_plan(&s, &slice_t, hit_max, fell_short))
                    .unwrap_or_default();
                if let (Some(bytes), Some(r)) = (plan.reclaim_bytes, reclaimer.as_ref()) {
                    r.request(bytes);
                }

                if in_flight.as_ref().is_some_and(|f| f.handle.is_finished()) {
                    let done = in_flight.take().expect("checked above");
                    let ok = done.handle.await.unwrap_or(false);
                    if ok && done.resume {
                        last_resume = Some(Instant::now());
                    } else if ok {
                        may_have_guard_paused = true;
                    }
                }

                let host_pressure = under_pressure(&sample, &t);
                let relieve = plan.relieve || host_pressure;
                let resume_possible = !relieve
                    && may_have_guard_paused
                    && sample.available_mib > t.reserve_mib.saturating_mul(2);
                if !relieve && !resume_possible {
                    continue;
                }
                let Some(candidates) = list_candidates(&state, &listing).await else { continue };

                if relieve {
                    if let Some(running) = in_flight.as_ref() {
                        if plan.critical && !running.resume && running.started.elapsed() >= ESCALATE_AFTER {
                            if let Some(s) = slice.as_ref() {
                                kill_for_slice(&candidates, s, &mut last_kill);
                            }
                        }
                        continue;
                    }
                    match pause_victim(&candidates) {
                        Some(name) => {
                            let reason = match (slice, plan.relieve) {
                                (Some(s), true) => format!(
                                    "VM memory slice pressure: {} MiB of its {} MiB cap in use",
                                    s.current_bytes / (1024 * 1024),
                                    s.max_bytes / (1024 * 1024)
                                ),
                                _ => format!(
                                    "host memory pressure: {} MiB available of {} (reserve {} MiB), some {:.0}% full {:.0}%",
                                    sample.available_mib, sample.total_mib, t.reserve_mib, sample.some_avg10, sample.full_avg10
                                ),
                            };
                            let state = state.clone();
                            in_flight = Some(InFlight {
                                handle: tokio::spawn(async move { pause(&state, &name, reason).await }),
                                started: Instant::now(),
                                resume: false,
                            });
                        }
                        None if plan.critical => {
                            if let Some(s) = slice.as_ref() {
                                kill_for_slice(&candidates, s, &mut last_kill);
                            }
                        }
                        None => {}
                    }
                    continue;
                }

                may_have_guard_paused = candidates.iter().any(|c| c.paused_by_guard);
                if in_flight.is_some() || last_resume.is_some_and(|at| at.elapsed() < RESUME_COOLDOWN) {
                    continue;
                }
                if let Decision::Resume(name) = decide(&sample, &t, &candidates) {
                    let mem_mib = candidates
                        .iter()
                        .find(|c| c.name == name)
                        .map_or(0, |c| c.mem_mib);
                    if slice_allows_resume(slice.as_ref(), &slice_t, mem_mib) {
                        let state = state.clone();
                        in_flight = Some(InFlight {
                            handle: tokio::spawn(async move { resume(&state, &name).await }),
                            started: Instant::now(),
                            resume: true,
                        });
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn pause(state: &Arc<ApiState>, name: &str, reason: String) -> bool {
    // Never wait on the lifecycle lock: whoever holds it may be stuck on the
    // same memory. A busy machine is left for a later tick.
    let Ok(_guard) = state.lifecycle_lock(name).try_lock_owned() else {
        tracing::debug!(machine = %name, "memory pressure pause skipped: machine busy");
        return false;
    };
    tracing::warn!(machine = %name, %reason, "pausing the newest branch child to relieve memory");
    let db = state.db().clone();
    let (name2, reason2) = (name.to_string(), reason);
    let outcome = tokio::task::spawn_blocking(move || {
        let runtime = crate::embedded::EmbeddedRuntime::with_db(db.clone());
        let operation = format!(
            "host-memory-pressure-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        runtime.pause_machine_with_operation(&name2, &operation)?;
        db.update_vm(&name2, |record| record.pause_reason = Some(reason2))?;
        Ok::<(), crate::Error>(())
    })
    .await;
    match outcome {
        Ok(Ok(())) => {
            metrics::counter!("smolvm_memory_pressure_pauses_total").increment(1);
            tracing::warn!(machine = %name, "paused for memory pressure; resumes when memory recovers");
            true
        }
        Ok(Err(e)) => {
            tracing::warn!(machine = %name, error = %e, "memory pressure pause failed");
            false
        }
        Err(e) => {
            tracing::warn!(machine = %name, error = %e, "memory pressure pause task failed");
            false
        }
    }
}

async fn resume(state: &Arc<ApiState>, name: &str) -> bool {
    tracing::info!(machine = %name, "host memory recovered; resuming a child the guard paused");
    let Ok(_guard) = state.lifecycle_lock(name).try_lock_owned() else {
        return false;
    };
    let db = state.db().clone();
    let name2 = name.to_string();
    let outcome = tokio::task::spawn_blocking(move || {
        let runtime = crate::embedded::EmbeddedRuntime::with_db(db.clone());
        // detached: the restored VMM must outlive this runtime handle
        runtime.resume_machine_detached(&name2)?;
        db.update_vm(&name2, |record| record.pause_reason = None)?;
        Ok::<(), crate::Error>(())
    })
    .await;
    match outcome {
        Ok(Ok(())) => {
            metrics::counter!("smolvm_memory_pressure_resumes_total").increment(1);
            true
        }
        Ok(Err(e)) => {
            tracing::warn!(machine = %name, error = %e, "memory pressure resume failed");
            false
        }
        Err(e) => {
            tracing::warn!(machine = %name, error = %e, "memory pressure resume task failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Thresholds {
        Thresholds {
            reserve_mib: 2048,
            some_avg10_pct: 20.0,
            full_avg10_pct: 5.0,
        }
    }
    fn s(available_mib: u64, some: f64, full: f64) -> Sample {
        Sample {
            total_mib: 65536,
            available_mib,
            some_avg10: some,
            full_avg10: full,
        }
    }
    fn c(name: &str, created_at: u64, mem: u64) -> Candidate {
        Candidate {
            name: name.into(),
            created_at,
            mem_mib: mem,
            running_clone: true,
            paused_by_guard: false,
            held: false,
            source: false,
            running: true,
            pid: Some(1000 + created_at as i32),
            pid_start_time: None,
        }
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    fn slice(current_gib: u64, max_gib: u64) -> SliceSample {
        SliceSample {
            current_bytes: current_gib * GIB,
            max_bytes: max_gib * GIB,
            max_events: 0,
        }
    }

    fn st() -> SliceThresholds {
        slice_thresholds(None, None)
    }

    #[test]
    fn slice_thresholds_default_to_the_shared_reclaim_line_and_95() {
        let t = st();
        assert_eq!(
            t.reclaim_pct,
            crate::systemd_scope::VM_SLICE_RECLAIM_TARGET_PERCENT
        );
        assert_eq!(t.reclaim_pct, 85);
        assert_eq!(t.relieve_pct, 95);
        assert_eq!(t.reclaim_step_bytes, 2 * GIB);
        assert_eq!(slice_thresholds(Some("90"), Some("512")).relieve_pct, 90);
        assert_eq!(
            slice_thresholds(Some("90"), Some("512")).reclaim_step_bytes,
            512 * 1024 * 1024
        );
        // The relief line stays above the reclaim line and at most 100%.
        assert_eq!(slice_thresholds(Some("50"), None).relieve_pct, 86);
        assert_eq!(slice_thresholds(Some("120"), None).relieve_pct, 100);
        assert_eq!(slice_thresholds(Some("lots"), Some("0")), st());
    }

    #[test]
    fn below_the_reclaim_line_the_guard_leaves_the_slice_alone() {
        // xfs-0 on 2026-11-12: 305 GiB of a 710 GiB cap.
        assert_eq!(
            slice_plan(&slice(305, 710), &st(), false, false),
            SlicePlan::default()
        );
        assert_eq!(
            slice_plan(&slice(603, 710), &st(), false, true),
            SlicePlan::default(),
            "84.9%: a stale short reclaim alone does nothing"
        );
    }

    #[test]
    fn from_85_percent_the_guard_reclaims_a_bounded_step_back_toward_80() {
        // 610 of 710 GiB = 85.9%: 80% is 568 GiB, so 42 GiB over, capped at 2 GiB.
        let plan = slice_plan(&slice(610, 710), &st(), false, false);
        assert_eq!(plan.reclaim_bytes, Some(2 * GIB));
        assert!(!plan.relieve && !plan.critical);
        // A small slice just over the line asks for exactly what returns it to 80%.
        let small = slice_plan(
            &slice(86, 100),
            &slice_thresholds(None, Some("16384")),
            false,
            false,
        );
        assert_eq!(small.reclaim_bytes, Some(6 * GIB));
    }

    #[test]
    fn a_short_reclaim_escalates_to_a_pause_but_not_a_kill() {
        let plan = slice_plan(&slice(620, 710), &st(), false, true);
        assert!(plan.relieve);
        assert!(!plan.critical);
        assert!(
            plan.reclaim_bytes.is_some(),
            "keep reclaiming so a later success clears it"
        );
    }

    #[test]
    fn from_95_percent_or_at_the_cap_the_guard_relieves_and_may_kill() {
        let plan = slice_plan(&slice(675, 710), &st(), false, false);
        assert!(plan.relieve && plan.critical);
        let hit = slice_plan(&slice(500, 710), &st(), true, false);
        assert!(
            hit.relieve && hit.critical,
            "the kernel hit memory.max since the last tick"
        );
        assert!(
            hit.reclaim_bytes.is_none(),
            "already under 80%: nothing to reclaim"
        );
    }

    #[test]
    fn resume_must_leave_the_slice_under_80_percent() {
        let t = st();
        assert!(slice_allows_resume(None, &t, 32 * 1024));
        assert!(slice_allows_resume(Some(&slice(500, 710)), &t, 32 * 1024));
        assert!(!slice_allows_resume(Some(&slice(560, 710)), &t, 32 * 1024));
    }

    #[test]
    fn the_kill_victim_is_the_largest_running_non_source() {
        let mut source = c("golden", 1, 65536);
        source.source = true;
        source.running_clone = false;
        let mut held = c("slot", 2, 49152);
        held.held = true;
        let mut stopped = c("off", 3, 40000);
        stopped.running = false;
        let cands = vec![
            source,
            held,
            stopped,
            c("w-0", 4, 16384),
            c("w-1", 5, 32768),
            c("w-2", 6, 16384),
        ];
        assert_eq!(kill_victim(&cands).map(|v| v.name.as_str()), Some("w-1"));
        assert_eq!(kill_victim(&cands[..3]), None, "nothing we may kill");
    }

    #[test]
    fn cgroup_memory_files_parse() {
        assert_eq!(parse_memory_max("762365952000\n"), Some(762_365_952_000));
        assert_eq!(parse_memory_max("max\n"), None);
        let events = "low 0\nhigh 6100000\nmax 80279\noom 12\noom_kill 10\noom_group_kill 0\n";
        assert_eq!(parse_events_max(events), Some(80279));
        assert_eq!(parse_events_max("low 0\n"), None);
    }

    #[test]
    fn parses_the_kernel_pressure_file() {
        let text = "some avg10=12.50 avg60=3.10 avg300=0.80 total=3836020838\nfull avg10=4.00 avg60=1.00 avg300=0.20 total=3391985927\n";
        assert_eq!(parse_pressure(text), Some((12.5, 4.0)));
        assert_eq!(
            parse_pressure("some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n"),
            Some((0.0, 0.0))
        );
        assert_eq!(parse_pressure("garbage"), None);
    }

    #[test]
    fn pressure_needs_low_memory_and_stalls_or_very_low_memory() {
        assert!(
            !under_pressure(&s(10_000, 50.0, 10.0), &t()),
            "plenty of memory: stalls alone are not our problem"
        );
        assert!(
            !under_pressure(&s(1_500, 2.0, 0.0), &t()),
            "below the reserve but nobody is stalling yet"
        );
        assert!(
            under_pressure(&s(1_500, 25.0, 0.0), &t()),
            "below the reserve and tasks wait for memory"
        );
        assert!(under_pressure(&s(1_500, 0.0, 6.0), &t()));
        assert!(
            under_pressure(&s(900, 0.0, 0.0), &t()),
            "below half the reserve: act before the kernel does"
        );
    }

    #[test]
    fn the_newest_running_child_is_paused_first_and_sources_and_held_slots_never() {
        let mut source = c("golden", 1, 8192);
        source.running_clone = false;
        let mut held = c("slot-3", 300, 1024);
        held.held = true;
        let cands = vec![source, c("w-0", 100, 1024), c("w-1", 200, 1024), held];
        assert_eq!(
            decide(&s(900, 0.0, 0.0), &t(), &cands),
            Decision::Pause("w-1".into())
        );
        let only_source = vec![cands[0].clone()];
        assert_eq!(
            decide(&s(900, 0.0, 0.0), &t(), &only_source),
            Decision::Hold,
            "nothing we may pause"
        );
    }

    #[test]
    fn resume_needs_margin_and_takes_the_oldest_victim_that_fits() {
        let mut p0 = c("w-0", 100, 1024);
        p0.running_clone = false;
        p0.paused_by_guard = true;
        let mut p1 = c("w-1", 200, 4096);
        p1.running_clone = false;
        p1.paused_by_guard = true;
        let mut user_paused = c("w-9", 50, 512);
        user_paused.running_clone = false;
        let cands = vec![p1.clone(), p0.clone(), user_paused];
        assert_eq!(
            decide(&s(3_000, 0.0, 0.0), &t(), &cands),
            Decision::Hold,
            "free but no margin over twice the reserve"
        );
        assert_eq!(
            decide(&s(5_200, 0.0, 0.0), &t(), &cands),
            Decision::Resume("w-0".into()),
            "oldest victim that fits the margin"
        );
        assert_eq!(
            decide(&s(9_000, 0.0, 0.0), &t(), &cands),
            Decision::Resume("w-0".into())
        );
        assert_eq!(
            decide(&s(9_000, 0.0, 0.0), &t(), &[p1]),
            Decision::Resume("w-1".into())
        );
    }

    #[test]
    fn nothing_to_do_in_the_middle() {
        assert_eq!(
            decide(&s(3_000, 0.0, 0.0), &t(), &[c("w-0", 1, 512)]),
            Decision::Hold
        );
    }
}
