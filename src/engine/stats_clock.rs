//! Elapsed CPU capacity for Docker's CPU delta / system delta calculation.

/// Use the host's monotonic clock, not nanoseconds since the Unix epoch.
/// Epoch nanoseconds multiplied by 16 CPUs already exceed u64 in 2026;
/// wall-clock corrections would also turn into bogus utilization spikes.
pub(super) fn system_cpu_usage(cpus: u64) -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: now is a valid writable timespec, and CLOCK_MONOTONIC needs no
    // privileges or resources to close. A failed sample supplies no delta.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return 0;
    }
    capacity(now.tv_sec, now.tv_nsec, cpus)
}

fn capacity(seconds: i64, nanoseconds: i64, cpus: u64) -> u64 {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return 0;
    }
    let elapsed = (seconds as u128) * 1_000_000_000 + nanoseconds as u128;
    elapsed.saturating_mul(cpus as u128).min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_clock_is_monotonic_even_with_many_cpus() {
        let before = system_cpu_usage(64);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let after = system_cpu_usage(64);
        assert!(before > 0 && before < u64::MAX);
        assert!(after > before && after < u64::MAX);
    }

    #[test]
    fn one_busy_cpu_remains_one_hundred_percent_on_large_hosts() {
        for cpus in [1, 16, 64, 512, 4096] {
            let before = capacity(86_400, 123, cpus);
            let after = capacity(86_401, 123, cpus);
            let cpu_delta = 1_000_000_000f64;
            let docker_percent = cpu_delta / (after - before) as f64 * cpus as f64 * 100.0;
            assert_eq!(docker_percent, 100.0);
        }
    }

    #[test]
    fn invalid_or_extreme_samples_never_wrap_or_panic() {
        assert_eq!(capacity(-1, 0, 16), 0);
        assert_eq!(capacity(1, -1, 16), 0);
        assert_eq!(capacity(1, 1_000_000_000, 16), 0);
        assert_eq!(capacity(1, 0, 0), 0);
        assert_eq!(capacity(i64::MAX, 999_999_999, u64::MAX), u64::MAX);
        assert_eq!(capacity(0, 1, u64::MAX), u64::MAX);
    }
}
