//! Hand idle page cache back so a machine's host memory follows what it uses.
//!
//! Free page reporting (virtio-balloon) returns free guest memory to the host
//! within seconds, but only in whole 2 MiB blocks, and it cannot return page
//! cache at all: after an image pull, a build or a walk over a repository the
//! guest keeps gigabytes of file pages it may never read again, and the host
//! keeps every one of them resident. The guest kernel only drops cache under
//! memory pressure, which an idle machine never has, so without help the host
//! footprint stays at the high-water mark of the last heavy job.
//!
//! Once the machine has been quiet for [`DEFAULT_QUIET`] (little CPU, no
//! memory stalls) this thread reclaims the cache in steps through the root
//! cgroup's `memory.reclaim`, a quarter of it per [`TICK`], down to a small
//! floor. Reclaim stops at once if the guest becomes busy or stalls on memory,
//! so a workload that is still reading its files keeps them.
//!
//! Freed cache lies scattered between the pages still in use, so little of it
//! forms the 2 MiB blocks free page reporting waits for. While a trim runs,
//! and for a few ticks after, reporting is lowered to [`FINE_REPORTING_ORDER`]
//! so the host gets those pieces back too; it returns to its usual order as
//! soon as the machine is busy again, where reporting every small free would
//! cost refaults.
//!
//! A live-fork golden (`SMOLVM_FORKABLE`) is left alone: its warm cache is
//! what its clones start from. `SMOLVM_MEMORY_TRIM=off`/`0` disables the
//! thread; `SMOLVM_MEMORY_TRIM=<seconds>` sets the quiet period.

use std::time::Duration;

/// How often the guest is sampled. Each sample reads three small proc files.
const TICK: Duration = Duration::from_secs(5);

/// Quiet time before the first reclaim step.
const DEFAULT_QUIET: Duration = Duration::from_secs(60);

/// CPU the guest may use, in cores, and still count as quiet. An idle Docker
/// daemon with idle containers stays well below it.
const QUIET_CORES: f64 = 0.25;

/// Share of a tick the guest may spend stalled on memory and still count as
/// quiet. Refaulting cache it needs shows up here first.
const STALL_LIMIT: f64 = 0.001;

/// Smallest and largest single reclaim request.
const MIN_STEP: u64 = 32 << 20;
const MAX_STEP: u64 = 2 << 30;

/// Cache growth since the last trim that makes another trim worthwhile.
const REARM_GROWTH: u64 = 64 << 20;

/// Ticks fine-grained reporting stays on after a trim settles, so the reports
/// it started can finish.
const FINE_REPORTING_HOLD: u32 = 3;

/// Reporting order while trimming: 16 KiB blocks, the largest host page size
/// (Apple silicon). A smaller block could not be released on such a host.
const FINE_REPORTING_ORDER: &str = "2";

const RECLAIM_PATH: &str = "/sys/fs/cgroup/memory.reclaim";
const REPORTING_ORDER_PATH: &str = "/sys/module/page_reporting/parameters/page_reporting_order";

/// Page cache left in place: binaries and libraries that are running.
fn floor(total: u64) -> u64 {
    (total / 32).clamp(64 << 20, 256 << 20)
}

/// The quiet period, or `None` when trimming is disabled.
fn quiet_period(value: Option<&str>) -> Option<Duration> {
    let Some(value) = value.map(str::trim) else {
        return Some(DEFAULT_QUIET);
    };
    if value.eq_ignore_ascii_case("off") || value == "0" {
        return None;
    }
    Some(
        value
            .parse::<u64>()
            .map(|secs| Duration::from_secs(secs.max(TICK.as_secs())))
            .unwrap_or(DEFAULT_QUIET),
    )
}

/// One look at the guest, over the last tick.
#[derive(Clone, Copy, Debug, Default)]
struct Sample {
    /// CPU used by everything except this thread, in cores.
    busy_cores: f64,
    /// Share of the tick some task was stalled on memory, outside this
    /// thread's own reclaim.
    stall: f64,
    /// Page cache (`Active(file)` + `Inactive(file)`).
    file: u64,
    /// `MemTotal`.
    total: u64,
}

/// The reclaim policy, free of I/O so it can be tested.
#[derive(Debug)]
struct Trimmer {
    quiet_ticks_needed: u32,
    quiet_ticks: u32,
    /// Whether there is cache worth trimming since the last trim settled.
    armed: bool,
    /// Lowest cache level since the last trim settled.
    low_water: u64,
    /// Whether free page reporting should report small blocks.
    fine: bool,
    /// Ticks since the trim settled while `fine` is still on.
    settled_ticks: u32,
}

impl Trimmer {
    fn new(quiet: Duration) -> Self {
        Self {
            quiet_ticks_needed: quiet.as_secs().div_ceil(TICK.as_secs()).max(1) as u32,
            quiet_ticks: 0,
            armed: true,
            low_water: u64::MAX,
            fine: false,
            settled_ticks: 0,
        }
    }

    /// How much page cache to reclaim now, if any.
    fn next(&mut self, s: &Sample) -> Option<u64> {
        self.low_water = self.low_water.min(s.file);
        if !self.armed && s.file >= self.low_water.saturating_add(REARM_GROWTH) {
            self.armed = true;
        }
        if s.busy_cores > QUIET_CORES || s.stall > STALL_LIMIT {
            self.quiet_ticks = 0;
            self.fine = false;
            return None;
        }
        self.quiet_ticks = self.quiet_ticks.saturating_add(1);
        if !self.armed {
            if self.fine {
                self.settled_ticks += 1;
                self.fine = self.settled_ticks < FINE_REPORTING_HOLD;
            }
            return None;
        }
        if self.quiet_ticks < self.quiet_ticks_needed {
            return None;
        }
        let floor = floor(s.total);
        if s.file >= floor.saturating_add(MIN_STEP) {
            self.fine = true;
            self.settled_ticks = 0;
            return Some((s.file / 4).clamp(MIN_STEP, MAX_STEP).min(s.file - floor));
        }
        self.settle(s.file);
        None
    }

    /// Record a reclaim request. `complete` is false when the kernel could not
    /// free all of it: what is left is in use, so stop for now.
    fn reclaimed(&mut self, complete: bool, file_after: u64) {
        if !complete {
            self.settle(file_after);
        }
    }

    fn settle(&mut self, file: u64) {
        self.armed = false;
        self.low_water = file;
        self.settled_ticks = 0;
    }
}

/// Start the trim thread unless it is disabled or the machine is a fork golden.
pub fn spawn() {
    let forkable = std::env::var(smolvm_protocol::guest_env::FORKABLE).as_deref()
        == Ok(smolvm_protocol::guest_env::VALUE_ON);
    let setting = std::env::var(smolvm_protocol::guest_env::MEMORY_TRIM).ok();
    let Some(quiet) = quiet_period(setting.as_deref()) else {
        return;
    };
    if forkable {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("memory-trim".into())
        .spawn(move || run(quiet));
}

fn run(quiet: Duration) {
    let mut trimmer = Trimmer::new(quiet);
    let mut probe = probe::Probe::new();
    let mut episode = 0u64;
    loop {
        std::thread::sleep(TICK);
        let Some(sample) = probe.sample() else {
            continue;
        };
        let step = trimmer.next(&sample);
        // Report small free pieces while trimming, before the reclaim frees
        // them, and back to whole blocks once the machine is busy or settled.
        probe.fine_reporting(trimmer.fine);
        if let Some(bytes) = step {
            let complete = probe.reclaim(bytes);
            let after = probe.file_bytes().unwrap_or(sample.file);
            let freed = sample.file.saturating_sub(after);
            episode = episode.saturating_add(freed);
            tracing::debug!(
                requested_mib = bytes >> 20,
                freed_mib = freed >> 20,
                "memory trim: reclaimed page cache"
            );
            trimmer.reclaimed(complete, after);
        }
        if episode > 0 && !trimmer.armed {
            tracing::info!(
                reclaimed_mib = episode >> 20,
                "memory trim: idle page cache returned"
            );
            episode = 0;
        }
    }
}

mod probe {
    use super::{Sample, FINE_REPORTING_ORDER, RECLAIM_PATH, REPORTING_ORDER_PATH, TICK};
    use std::io::Write;
    use std::time::Instant;

    /// Reads the guest's counters and turns their deltas into a [`Sample`].
    pub(super) struct Probe {
        clk_tck: f64,
        last: Option<(Instant, u64, u64, f64)>,
        /// Stall accrued during this thread's own reclaim since the last sample.
        own_stall_us: u64,
        /// The kernel's reporting order, saved while small blocks are reported.
        saved_order: Option<String>,
    }

    impl Probe {
        pub(super) fn new() -> Self {
            // SAFETY: sysconf has no preconditions.
            let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            Self {
                clk_tck: if tck > 0 { tck as f64 } else { 100.0 },
                last: None,
                own_stall_us: 0,
                saved_order: None,
            }
        }

        pub(super) fn sample(&mut self) -> Option<Sample> {
            let now = Instant::now();
            let busy = super::parse_busy_jiffies(&std::fs::read_to_string("/proc/stat").ok()?)?;
            let stall = memory_stall_us().unwrap_or(0);
            let own = thread_cpu_secs();
            let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
            let (file, total) = super::parse_file_and_total(&meminfo)?;
            let previous = self.last.replace((now, busy, stall, own));
            let own_stall = std::mem::take(&mut self.own_stall_us);
            let (then, busy0, stall0, own0) = previous?;
            let secs = now
                .duration_since(then)
                .as_secs_f64()
                .max(TICK.as_secs_f64() / 10.0);
            let cpu = busy.saturating_sub(busy0) as f64 / self.clk_tck - (own - own0).max(0.0);
            let stalled = stall.saturating_sub(stall0).saturating_sub(own_stall);
            Some(Sample {
                busy_cores: cpu.max(0.0) / secs,
                stall: stalled as f64 / (secs * 1e6),
                file,
                total,
            })
        }

        pub(super) fn file_bytes(&self) -> Option<u64> {
            let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
            super::parse_file_and_total(&meminfo).map(|(file, _)| file)
        }

        /// Ask the kernel to reclaim `bytes`. Returns whether it freed all of
        /// them. Falls back to dropping the page cache where the root cgroup
        /// has no `memory.reclaim`.
        pub(super) fn reclaim(&mut self, bytes: u64) -> bool {
            let before = memory_stall_us().unwrap_or(0);
            let result = std::fs::OpenOptions::new()
                .write(true)
                .open(RECLAIM_PATH)
                .and_then(|mut f| f.write_all(bytes.to_string().as_bytes()));
            let complete = match result {
                Ok(()) => true,
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => false,
                Err(e) => {
                    tracing::debug!(error = %e, "memory trim: memory.reclaim unavailable, dropping caches");
                    let _ = std::fs::write("/proc/sys/vm/drop_caches", "1");
                    false
                }
            };
            let after = memory_stall_us().unwrap_or(before);
            self.own_stall_us = self
                .own_stall_us
                .saturating_add(after.saturating_sub(before));
            complete
        }

        /// Report free pages down to small blocks (`on`), or restore the
        /// kernel's own reporting order. Best-effort: a kernel without the
        /// parameter keeps reporting whole blocks.
        pub(super) fn fine_reporting(&mut self, on: bool) {
            if on == self.saved_order.is_some() {
                return;
            }
            if on {
                let Ok(order) = std::fs::read_to_string(REPORTING_ORDER_PATH) else {
                    return;
                };
                if std::fs::write(REPORTING_ORDER_PATH, FINE_REPORTING_ORDER).is_ok() {
                    self.saved_order = Some(order.trim().to_string());
                }
            } else if let Some(order) = self.saved_order.take() {
                if let Err(e) = std::fs::write(REPORTING_ORDER_PATH, &order) {
                    tracing::warn!(error = %e, %order, "memory trim: could not restore the page reporting order");
                }
            }
        }
    }

    fn memory_stall_us() -> Option<u64> {
        super::parse_some_total(&std::fs::read_to_string("/proc/pressure/memory").ok()?)
    }

    /// CPU time of the calling thread, in seconds.
    fn thread_cpu_secs() -> f64 {
        // SAFETY: getrusage writes only into the zeroed struct on success.
        unsafe {
            let mut ru: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_THREAD, &mut ru) != 0 {
                return 0.0;
            }
            let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
            secs(ru.ru_utime) + secs(ru.ru_stime)
        }
    }
}

/// Busy jiffies across all CPUs from `/proc/stat`'s `cpu` line: user, nice,
/// system, irq and softirq (guest time is already inside user).
fn parse_busy_jiffies(stat: &str) -> Option<u64> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let f: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(|v| v.parse().ok())
        .collect::<Option<_>>()?;
    let get = |i: usize| f.get(i).copied().unwrap_or(0);
    Some(get(0) + get(1) + get(2) + get(5) + get(6))
}

/// Page cache and total RAM, in bytes, from `/proc/meminfo`.
fn parse_file_and_total(meminfo: &str) -> Option<(u64, u64)> {
    let (mut active, mut inactive, mut total) = (None, None, None);
    for line in meminfo.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(kib) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "Active(file):" => active = Some(kib * 1024),
            "Inactive(file):" => inactive = Some(kib * 1024),
            "MemTotal:" => total = Some(kib * 1024),
            _ => {}
        }
    }
    Some((active? + inactive?, total?))
}

/// The cumulative `some` stall time, in microseconds, of a PSI file.
fn parse_some_total(pressure: &str) -> Option<u64> {
    pressure
        .lines()
        .find(|l| l.starts_with("some "))?
        .split_whitespace()
        .find_map(|f| f.strip_prefix("total="))?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn quiet(file: u64) -> Sample {
        Sample {
            busy_cores: 0.01,
            stall: 0.0,
            file,
            total: 8 * GIB,
        }
    }

    fn busy(file: u64) -> Sample {
        Sample {
            busy_cores: 2.0,
            ..quiet(file)
        }
    }

    /// Run the trimmer against a quiet guest that frees exactly what it is
    /// asked. Returns the reclaim requests.
    fn drive(t: &mut Trimmer, file: &mut u64, ticks: usize) -> Vec<u64> {
        let mut steps = Vec::new();
        for _ in 0..ticks {
            if let Some(bytes) = t.next(&quiet(*file)) {
                *file -= bytes;
                steps.push(bytes);
                t.reclaimed(true, *file);
            }
        }
        steps
    }

    #[test]
    fn the_setting_disables_or_sets_the_quiet_period() {
        assert_eq!(quiet_period(None), Some(DEFAULT_QUIET));
        assert_eq!(quiet_period(Some("off")), None);
        assert_eq!(quiet_period(Some("OFF")), None);
        assert_eq!(quiet_period(Some("0")), None);
        assert_eq!(quiet_period(Some("120")), Some(Duration::from_secs(120)));
        assert_eq!(quiet_period(Some("1")), Some(TICK));
        assert_eq!(quiet_period(Some("soon")), Some(DEFAULT_QUIET));
    }

    #[test]
    fn nothing_is_reclaimed_before_the_quiet_period() {
        let mut t = Trimmer::new(Duration::from_secs(60));
        for _ in 0..11 {
            assert_eq!(t.next(&quiet(6 * GIB)), None);
            assert!(!t.fine);
        }
        assert!(t.next(&quiet(6 * GIB)).is_some());
        assert!(t.fine);
    }

    #[test]
    fn activity_restarts_the_quiet_period() {
        let mut t = Trimmer::new(Duration::from_secs(60));
        for _ in 0..11 {
            t.next(&quiet(6 * GIB));
        }
        assert_eq!(t.next(&busy(6 * GIB)), None);
        for _ in 0..11 {
            assert_eq!(t.next(&quiet(6 * GIB)), None);
        }
        assert!(t.next(&quiet(6 * GIB)).is_some());
    }

    #[test]
    fn memory_stalls_stop_reclaim_and_fine_reporting_at_once() {
        let mut t = Trimmer::new(TICK);
        assert!(t.next(&quiet(6 * GIB)).is_some());
        let stalled = Sample {
            stall: 0.01,
            ..quiet(5 * GIB)
        };
        assert_eq!(t.next(&stalled), None);
        assert!(!t.fine);
    }

    #[test]
    fn busy_work_turns_fine_reporting_off() {
        let mut t = Trimmer::new(TICK);
        assert!(t.next(&quiet(6 * GIB)).is_some());
        assert!(t.fine);
        assert_eq!(t.next(&busy(6 * GIB)), None);
        assert!(!t.fine);
    }

    #[test]
    fn six_gib_of_cache_is_down_to_the_floor_within_a_minute_and_a_half() {
        let mut t = Trimmer::new(TICK);
        let mut file = 6 * GIB;
        drive(&mut t, &mut file, 18);
        assert!(file <= floor(8 * GIB) + MIN_STEP, "{} MiB left", file / MIB);
        assert!(file >= floor(8 * GIB), "trimmed below the floor");
        // Settled: no further work while the cache stays put, and fine
        // reporting ends a few ticks later.
        assert!(drive(&mut t, &mut file, 20).is_empty());
        assert!(!t.fine);
    }

    #[test]
    fn fine_reporting_outlasts_the_trim_by_the_hold() {
        let mut t = Trimmer::new(TICK);
        let mut file = 512 * MIB;
        let mut fine = Vec::new();
        for _ in 0..12 {
            if let Some(bytes) = t.next(&quiet(file)) {
                file -= bytes;
                t.reclaimed(true, file);
            }
            fine.push(t.fine);
        }
        let last_step = fine
            .iter()
            .rposition(|f| *f)
            .expect("fine reporting was on");
        let first = fine.iter().position(|f| *f).unwrap();
        assert!(fine[first..=last_step].iter().all(|f| *f), "{fine:?}");
        assert!(fine[last_step + 1..].iter().all(|f| !*f), "{fine:?}");
    }

    #[test]
    fn steps_are_bounded() {
        let mut t = Trimmer::new(TICK);
        assert_eq!(t.next(&quiet(64 * GIB)), Some(MAX_STEP));
        let mut t = Trimmer::new(TICK);
        let small = floor(8 * GIB) + MIN_STEP + MIB;
        assert_eq!(t.next(&quiet(small)), Some(MIN_STEP + MIB));
    }

    #[test]
    fn a_small_cache_is_left_alone() {
        let mut t = Trimmer::new(TICK);
        let mut file = floor(8 * GIB) + MIN_STEP / 2;
        assert!(drive(&mut t, &mut file, 10).is_empty());
        assert!(!t.fine);
    }

    #[test]
    fn new_cache_rearms_after_a_trim_settles() {
        let mut t = Trimmer::new(TICK);
        let mut file = 2 * GIB;
        drive(&mut t, &mut file, 20);
        assert!(!t.armed);
        // A little growth is not worth another pass.
        file += REARM_GROWTH / 2;
        assert!(drive(&mut t, &mut file, 5).is_empty());
        // A new job's worth of cache is.
        file += 2 * GIB;
        t.next(&busy(file));
        assert!(t.armed);
        assert!(!drive(&mut t, &mut file, 5).is_empty());
    }

    #[test]
    fn an_incomplete_reclaim_settles_without_retrying() {
        let mut t = Trimmer::new(TICK);
        let bytes = t.next(&quiet(4 * GIB)).expect("a reclaim");
        // The kernel freed a little and gave up: the rest is in use.
        t.reclaimed(false, 4 * GIB - bytes / 8);
        assert!(!t.armed);
        assert_eq!(t.next(&quiet(4 * GIB - bytes / 8)), None);
    }

    #[test]
    fn proc_files_parse() {
        let stat = "cpu  100 5 50 9000 20 3 2 7 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n";
        assert_eq!(parse_busy_jiffies(stat), Some(160));
        let meminfo = "MemTotal:        8000000 kB\nMemFree:  10 kB\nActive(file):     1000 kB\nInactive(file):    24 kB\n";
        assert_eq!(
            parse_file_and_total(meminfo),
            Some((1024 * 1024, 8_000_000 * 1024))
        );
        assert_eq!(parse_file_and_total("MemTotal: 1 kB\n"), None);
        let psi = "some avg10=0.00 avg60=0.00 avg300=0.00 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=99\n";
        assert_eq!(parse_some_total(psi), Some(12345));
        assert_eq!(parse_some_total("garbage"), None);
    }
}
