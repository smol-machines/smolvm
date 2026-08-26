//! Lease-aware admission for CUDA fork pools.
//!
//! The controller deliberately gates durable lease claims, not CUDA daemon
//! connections.  A claimed worker must always be allowed to finish activation;
//! moving the gate below that boundary can deadlock the daemon accept loop and
//! leaves the lease state ambiguous after a restart.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::pool::{ForkPoolAdmissionLimit, ForkPoolRecord};

const OBSERVATION_WINDOW: Duration = Duration::from_secs(8);
const MIN_STABLE_SAMPLES: u32 = 5;
const PRESSURE_TTL: Duration = Duration::from_secs(30);
const REPROBE_INTERVAL: Duration = Duration::from_secs(15 * 60);
const TARGET_VRAM_RESERVE_MIB: u64 = 8 * 1024;
const VRAM_RESERVE_PERCENT: u64 = 10;
const SMALL_DEVICE_RESERVE_CAP_PERCENT: u64 = 25;
const CPU_SATURATION_PERCENT: f64 = 90.0;
const MARGINAL_GAIN_PERCENT: f64 = 2.0;
const MIN_GPU_ACTIVITY_PERCENT: f64 = 10.0;

/// Telemetry for one host CUDA device.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GpuSample {
    /// Host CUDA device ordinal used by the guest-to-host mapping.
    pub device_ordinal: u32,
    /// Streaming-multiprocessor utilization.
    pub utilization_percent: f64,
    /// Used device memory in MiB.
    pub used_memory_mib: u64,
    /// Device-memory capacity in MiB.
    pub total_memory_mib: u64,
    /// Free memory remaining on this device.
    free_memory_mib: u64,
    /// Capacity-derived headroom reserved on this device.
    reserve_mib: u64,
}

/// Identity plus live telemetry for one CUDA-visible device. This is sampled
/// once by the pool controller and shared with both admission and `/capacity`,
/// so fleet polling never initializes NVML on the HTTP request path.
#[derive(Debug, Clone, PartialEq)]
pub struct GpuDeviceSample {
    /// CUDA-visible ordinal used by `SMOLVM_CUDA_DEVICE`.
    pub device_ordinal: u32,
    /// Stable physical-GPU or MIG UUID.
    pub uuid: String,
    /// Device model reported by NVML.
    pub name: String,
    /// Streaming-multiprocessor utilization.
    pub utilization_percent: f64,
    /// Used device memory in MiB.
    pub used_memory_mib: u64,
    /// Free device memory in MiB.
    pub free_memory_mib: u64,
    /// Total device memory in MiB.
    pub total_memory_mib: u64,
}

impl GpuDeviceSample {
    pub(crate) fn admission_sample(&self) -> GpuSample {
        GpuSample::new(
            self.device_ordinal,
            self.utilization_percent,
            self.used_memory_mib,
            self.free_memory_mib,
            self.total_memory_mib,
        )
    }
}

impl GpuSample {
    fn new(
        device_ordinal: u32,
        utilization_percent: f64,
        used_memory_mib: u64,
        free_memory_mib: u64,
        total_memory_mib: u64,
    ) -> Self {
        Self {
            device_ordinal,
            utilization_percent,
            used_memory_mib,
            total_memory_mib,
            free_memory_mib,
            reserve_mib: device_reserve_mib(total_memory_mib),
        }
    }

    fn memory_safe(self) -> bool {
        self.free_memory_mib >= self.reserve_mib
    }
}

fn device_reserve_mib(total_memory_mib: u64) -> u64 {
    let percentage_reserve = total_memory_mib.saturating_mul(VRAM_RESERVE_PERCENT) / 100;
    // An absolute 8 GiB reserve would consume all capacity on an 8 GiB GPU and
    // prevent automatic admission from ever testing a larger safe residency.
    // Retain at least 10%, while capping the absolute target at one quarter of
    // smaller devices so calibration still has useful capacity to explore.
    let absolute_reserve = TARGET_VRAM_RESERVE_MIB
        .min(total_memory_mib.saturating_mul(SMALL_DEVICE_RESERVE_CAP_PERCENT) / 100);
    percentage_reserve.max(absolute_reserve)
}

/// Public, read-only controller state returned with pool status.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionSnapshot {
    /// Maximum active or activating leases currently admitted.
    pub effective_limit: u32,
    /// Aggregate active-lease limit on the pool's CUDA device.
    pub device_limit: u32,
    /// Host CUDA device whose telemetry controls the limit.
    pub device_ordinal: u32,
    /// Explanation of the most recent controller decision.
    pub reason: String,
    /// Whether the controller is comparing a candidate resident level.
    pub calibrating: bool,
    /// Latest aggregate GPU utilization, when NVML is healthy.
    pub gpu_utilization_percent: Option<f64>,
    /// Latest aggregate used GPU memory in MiB.
    pub gpu_memory_used_mib: Option<u64>,
    /// Latest aggregate GPU memory capacity in MiB.
    pub gpu_memory_total_mib: Option<u64>,
    /// Latest host CPU busy percentage.
    pub host_cpu_percent: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct Score {
    gpu_utilization_percent: f64,
    completion_rate: Option<f64>,
}

impl Score {
    fn improvement_over(self, baseline: Self) -> f64 {
        let (current, previous) = match (self.completion_rate, baseline.completion_rate) {
            (Some(current), Some(previous)) if previous > 0.0 => (current, previous),
            _ if baseline.gpu_utilization_percent > 0.0 => (
                self.gpu_utilization_percent,
                baseline.gpu_utilization_percent,
            ),
            _ => return f64::INFINITY,
        };
        ((current - previous) / previous) * 100.0
    }
}

#[derive(Debug)]
struct PoolAdmissionState {
    ceiling: u32,
    effective_limit: u32,
    best_limit: u32,
    best_score: Option<Score>,
    testing_from: Option<(u32, Score)>,
    last_lower: Option<(u32, Score)>,
    settled: bool,
    last_probe: Instant,
    last_blocked: Option<Instant>,
    observed_active: u32,
    window_started: Instant,
    window_samples: u32,
    gpu_utilization_sum: f64,
    host_cpu_sum: f64,
    window_peak_gpu_memory_mib: u64,
    idle_gpu_memory_mib: Option<u64>,
    waiting_for_maturity: bool,
    completed_at_start: u64,
    latest_gpu: Option<GpuSample>,
    latest_host_cpu_percent: Option<f64>,
    telemetry_failed_open: bool,
    reason: String,
}

impl PoolAdmissionState {
    fn initial_limit(ceiling: u32) -> u32 {
        // Calibrate in at most three multiplicative steps without embedding a
        // GPU- or workload-specific resident count. Small pools stay unmodified.
        if ceiling <= 2 {
            ceiling
        } else {
            ceiling.div_ceil(3).max(1)
        }
    }

    fn new(ceiling: u32, now: Instant, completed_total: u64) -> Self {
        let effective_limit = Self::initial_limit(ceiling);
        Self {
            ceiling,
            effective_limit,
            best_limit: effective_limit,
            best_score: None,
            testing_from: None,
            last_lower: None,
            settled: effective_limit == ceiling,
            last_probe: now,
            last_blocked: None,
            observed_active: 0,
            window_started: now,
            window_samples: 0,
            gpu_utilization_sum: 0.0,
            host_cpu_sum: 0.0,
            window_peak_gpu_memory_mib: 0,
            idle_gpu_memory_mib: None,
            waiting_for_maturity: false,
            completed_at_start: completed_total,
            latest_gpu: None,
            latest_host_cpu_percent: None,
            telemetry_failed_open: false,
            reason: "waiting for GPU telemetry".into(),
        }
    }

    fn reset_window(&mut self, now: Instant, active: u32, completed_total: u64) {
        self.observed_active = active;
        self.window_started = now;
        self.window_samples = 0;
        self.gpu_utilization_sum = 0.0;
        self.host_cpu_sum = 0.0;
        self.window_peak_gpu_memory_mib = 0;
        self.waiting_for_maturity = false;
        self.completed_at_start = completed_total;
    }

    fn has_pressure(&self, now: Instant) -> bool {
        self.last_blocked
            .is_some_and(|blocked| now.saturating_duration_since(blocked) <= PRESSURE_TTL)
    }

    fn update_ceiling(&mut self, ceiling: u32, now: Instant, completed_total: u64) {
        if self.ceiling == ceiling {
            return;
        }
        self.ceiling = ceiling;
        self.effective_limit = self.effective_limit.min(ceiling).max(1);
        self.best_limit = self.best_limit.min(ceiling).max(1);
        self.testing_from = None;
        self.last_lower = None;
        self.settled = self.effective_limit == ceiling;
        self.best_score = None;
        self.idle_gpu_memory_mib = None;
        self.last_probe = now;
        self.reset_window(now, 0, completed_total);
        self.reason = "pool ceiling changed; restarting calibration".into();
    }

    fn observe(
        &mut self,
        now: Instant,
        active: u32,
        completed_total: u64,
        gpu: Option<GpuSample>,
        host_cpu_percent: Option<f64>,
    ) {
        let telemetry_recovered = self.telemetry_failed_open && gpu.is_some();
        self.latest_gpu = gpu;
        self.latest_host_cpu_percent = host_cpu_percent;

        let Some(gpu) = gpu else {
            // Fail open: telemetry loss must never strand work behind a stale
            // learned cap. A fixed maxActive still applies as the ceiling.
            self.effective_limit = self.ceiling;
            self.best_limit = self.ceiling;
            self.best_score = None;
            self.testing_from = None;
            self.last_lower = None;
            self.settled = true;
            self.telemetry_failed_open = true;
            self.idle_gpu_memory_mib = None;
            self.reason = "GPU telemetry unavailable; using full residency".into();
            self.reset_window(now, active, completed_total);
            return;
        };

        if telemetry_recovered {
            self.effective_limit = Self::initial_limit(self.ceiling);
            self.best_limit = self.effective_limit;
            self.best_score = None;
            self.testing_from = None;
            self.last_lower = None;
            self.settled = self.effective_limit == self.ceiling;
            self.last_probe = now;
            self.telemetry_failed_open = false;
            self.idle_gpu_memory_mib = None;
            self.reason = "GPU telemetry recovered; restarting calibration".into();
            self.reset_window(now, active, completed_total);
            return;
        }

        if active != self.observed_active {
            self.reset_window(now, active, completed_total);
        }
        if active == 0 {
            self.idle_gpu_memory_mib = Some(
                self.idle_gpu_memory_mib
                    .map_or(gpu.used_memory_mib, |idle| idle.min(gpu.used_memory_mib)),
            );
        }
        self.window_samples = self.window_samples.saturating_add(1);
        self.gpu_utilization_sum += gpu.utilization_percent;
        self.host_cpu_sum += host_cpu_percent.unwrap_or(0.0);
        self.window_peak_gpu_memory_mib = self.window_peak_gpu_memory_mib.max(gpu.used_memory_mib);

        let elapsed = now.saturating_duration_since(self.window_started);
        if active > self.effective_limit {
            self.reason = format!(
                "waiting for active leases to drain from {active} to {}",
                self.effective_limit
            );
            return;
        }
        let at_requested_residency = active == self.effective_limit;
        if !at_requested_residency
            || self.window_samples < MIN_STABLE_SAMPLES
            || elapsed < OBSERVATION_WINDOW
        {
            self.reason = format!(
                "observing stable residency at {active}/{}",
                self.effective_limit
            );
            return;
        }

        let mean_gpu = self.gpu_utilization_sum / f64::from(self.window_samples);
        let mean_cpu = self.host_cpu_sum / f64::from(self.window_samples);
        let completed = completed_total.saturating_sub(self.completed_at_start);
        // A partial cohort is phase-sensitive: two completions from a
        // three-resident probe can look identical to the prior two-resident
        // rate even when the third job is about to finish. Judge finite jobs
        // only after every resident slot has completed once in this window.
        let completion_rate =
            (active > 0 && completed >= u64::from(active) && elapsed.as_secs_f64() > 0.0)
                .then(|| completed as f64 / elapsed.as_secs_f64());
        let score = Score {
            gpu_utilization_percent: mean_gpu,
            completion_rate,
        };
        let observed_free_mib = gpu
            .total_memory_mib
            .saturating_sub(self.window_peak_gpu_memory_mib);
        let memory_safe = gpu.memory_safe() && observed_free_mib >= gpu.reserve_mib;
        let cpu_safe = mean_cpu < CPU_SATURATION_PERCENT;

        if memory_safe
            && cpu_safe
            && self.waiting_for_maturity
            && completion_rate.is_none()
            && gpu.utilization_percent >= MIN_GPU_ACTIVITY_PERCENT
        {
            self.reset_window(now, active, completed_total);
            self.reason = format!(
                "CUDA activity observed; starting a mature window at resident limit {}",
                self.effective_limit
            );
            return;
        }
        if memory_safe
            && cpu_safe
            && completion_rate.is_none()
            && mean_gpu < MIN_GPU_ACTIVITY_PERCENT
        {
            self.waiting_for_maturity = true;
            self.reason = format!(
                "waiting for CUDA activity or {active} completions before evaluating resident limit {}",
                self.effective_limit
            );
            return;
        }
        self.waiting_for_maturity = false;

        if let Some((prior_limit, prior_score)) = self.testing_from.take() {
            let improvement = score.improvement_over(prior_score);
            if improvement < MARGINAL_GAIN_PERCENT || !memory_safe || !cpu_safe {
                self.effective_limit = prior_limit;
                self.best_limit = prior_limit;
                self.best_score = Some(prior_score);
                self.settled = true;
                self.last_probe = now;
                self.reason = if !memory_safe {
                    format!(
                        "returned to {prior_limit}: limiting GPU has {} MiB free; preserving {} MiB reserve",
                        observed_free_mib,
                        gpu.reserve_mib
                    )
                } else if !cpu_safe {
                    format!("returned to {prior_limit}: host CPU saturated at {mean_cpu:.1}%")
                } else {
                    format!(
                        "returned to {prior_limit}: marginal gain {improvement:.1}% is below {MARGINAL_GAIN_PERCENT:.1}%"
                    )
                };
                self.reset_window(now, active, completed_total);
                return;
            }
            self.last_lower = Some((prior_limit, prior_score));
        }

        self.best_limit = self.effective_limit;
        self.best_score = Some(score);

        if self.settled
            && now.saturating_duration_since(self.last_probe) >= REPROBE_INTERVAL
            && self.has_pressure(now)
            && self.effective_limit < self.ceiling
        {
            self.settled = false;
        }

        if self.settled && (!memory_safe || !cpu_safe) {
            if let Some((lower_limit, lower_score)) = self.last_lower.take() {
                self.effective_limit = lower_limit;
                self.best_limit = lower_limit;
                self.best_score = Some(lower_score);
                self.last_probe = now;
                self.reason = if !memory_safe {
                    format!(
                        "returned to {lower_limit}: limiting GPU has {} MiB free; preserving {} MiB reserve",
                        observed_free_mib,
                        gpu.reserve_mib
                    )
                } else {
                    format!("returned to {lower_limit}: host CPU saturated at {mean_cpu:.1}%")
                };
                self.reset_window(now, active, completed_total);
                return;
            }
        }

        if !self.settled && self.has_pressure(now) && memory_safe && cpu_safe {
            let desired_next = self.effective_limit.saturating_mul(2).min(self.ceiling);
            if desired_next > self.effective_limit {
                let Some((next, projected_free_mib)) =
                    self.largest_memory_safe_candidate(gpu, active, desired_next)
                else {
                    let projected_free_mib = self
                        .projected_free_memory_mib(gpu, active, desired_next)
                        .unwrap_or(observed_free_mib);
                    self.settled = true;
                    self.last_probe = now;
                    self.reason = format!(
                        "holding at {}: projected limit {desired_next} leaves {projected_free_mib} MiB free; preserving {} MiB reserve",
                        self.effective_limit, gpu.reserve_mib
                    );
                    self.reset_window(now, active, completed_total);
                    return;
                };
                self.testing_from = Some((self.effective_limit, score));
                self.effective_limit = next;
                self.reason = if next == desired_next {
                    format!("probing resident limit {next}")
                } else {
                    format!(
                        "probing memory-safe resident limit {next}; projected free memory {projected_free_mib} MiB"
                    )
                };
                self.reset_window(now, active, completed_total);
                return;
            }
        }

        self.settled = true;
        self.last_probe = now;
        self.reason = if !memory_safe {
            format!(
                "holding at {}: limiting GPU has {} MiB free; preserving {} MiB reserve",
                self.effective_limit, observed_free_mib, gpu.reserve_mib
            )
        } else if !cpu_safe {
            format!(
                "holding at {} because host CPU is {:.1}% busy",
                self.effective_limit, mean_cpu
            )
        } else {
            format!("settled at resident limit {}", self.effective_limit)
        };
        self.reset_window(now, active, completed_total);
    }

    fn projected_free_memory_mib(
        &self,
        gpu: GpuSample,
        active: u32,
        candidate: u32,
    ) -> Option<u64> {
        if active == 0 || candidate <= active {
            return None;
        }
        let peak = self.window_peak_gpu_memory_mib.max(gpu.used_memory_mib);
        // If no usable idle sample survived a restart, treating all current
        // memory as active-job memory is deliberately conservative until the
        // device next reaches zero active leases. An idle sample at or above
        // the active peak is stale (for example, an unrelated process exited)
        // and must not collapse the projected worker footprint to zero.
        let active_memory = self
            .idle_gpu_memory_mib
            .filter(|idle| *idle < peak)
            .map_or(peak, |idle| peak - idle);
        let additional_workers = u64::from(candidate - active);
        let projected_additional = active_memory
            .saturating_mul(additional_workers)
            .div_ceil(u64::from(active));
        Some(
            gpu.total_memory_mib
                .saturating_sub(peak.saturating_add(projected_additional)),
        )
    }

    fn largest_memory_safe_candidate(
        &self,
        gpu: GpuSample,
        active: u32,
        upper: u32,
    ) -> Option<(u32, u64)> {
        if active == 0 || upper <= active {
            return None;
        }
        let mut low = active.saturating_add(1);
        let mut high = upper;
        let mut best = None;
        while low <= high {
            let candidate = low + (high - low) / 2;
            let projected_free = self.projected_free_memory_mib(gpu, active, candidate)?;
            if projected_free >= gpu.reserve_mib {
                best = Some((candidate, projected_free));
                low = candidate.saturating_add(1);
            } else {
                high = candidate.saturating_sub(1);
            }
        }
        best
    }

    fn snapshot(&self) -> AdmissionSnapshot {
        AdmissionSnapshot {
            effective_limit: self.effective_limit,
            device_limit: self.effective_limit,
            device_ordinal: 0,
            reason: self.reason.clone(),
            calibrating: !self.settled,
            gpu_utilization_percent: self.latest_gpu.map(|sample| sample.utilization_percent),
            gpu_memory_used_mib: self.latest_gpu.map(|sample| sample.used_memory_mib),
            gpu_memory_total_mib: self.latest_gpu.map(|sample| sample.total_memory_mib),
            host_cpu_percent: self.latest_host_cpu_percent,
        }
    }
}

/// Thread-safe bridge between the HTTP admission path and the background
/// telemetry loop.
#[derive(Default)]
pub struct AdmissionRegistry {
    inner: Mutex<AdmissionRegistryState>,
}

#[derive(Default)]
struct AdmissionRegistryState {
    devices: HashMap<u32, DeviceAdmissionState>,
    pool_devices: HashMap<String, u32>,
}

struct DeviceAdmissionState {
    admission: PoolAdmissionState,
    pools: HashMap<String, DevicePoolState>,
}

#[derive(Debug, Clone, Copy)]
struct DevicePoolState {
    ceiling: u32,
    active: u32,
    last_demand: Option<Instant>,
}

impl AdmissionRegistry {
    fn ceiling(pool: &ForkPoolRecord) -> u32 {
        pool.max_active
            .unwrap_or(pool.desired_ready)
            .min(pool.desired_ready)
            .max(1)
    }

    /// Record that a caller had work but could not claim another resident slot.
    pub fn note_blocked(&self, pool_name: &str) {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let Some(device) = inner.pool_devices.get(pool_name).copied() else {
            return;
        };
        if let Some(state) = inner.devices.get_mut(&device) {
            state.admission.last_blocked = Some(now);
            if let Some(pool) = state.pools.get_mut(pool_name) {
                pool.last_demand = Some(now);
            }
        }
    }

    /// Current dynamic pool and device claim limits. `None` means the pool uses
    /// its existing static `maxActive`/ready-slot behavior.
    pub fn limit(&self, pool: &ForkPoolRecord) -> Option<ForkPoolAdmissionLimit> {
        if !pool.auto_admission {
            return None;
        }
        let fallback = Self::ceiling(pool);
        let Some(device) = pool.admission_device_ordinal() else {
            return Some(ForkPoolAdmissionLimit {
                pool: fallback,
                device: fallback,
            });
        };
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let Some(state) = inner.devices.get_mut(&device) else {
            return Some(ForkPoolAdmissionLimit {
                pool: fallback,
                device: fallback,
            });
        };
        state
            .pools
            .entry(pool.name.clone())
            .or_insert(DevicePoolState {
                ceiling: fallback,
                active: 0,
                last_demand: None,
            });
        let device_limit = state.admission.effective_limit;
        Some(ForkPoolAdmissionLimit {
            pool: fair_pool_limit(state, &pool.name, device_limit, now, true),
            device: device_limit,
        })
    }

    /// Return the latest published telemetry and decision for an automatic pool.
    pub fn snapshot(&self, pool: &ForkPoolRecord) -> Option<AdmissionSnapshot> {
        if !pool.auto_admission {
            return None;
        }
        let device = pool.admission_device_ordinal()?;
        let inner = self.inner.lock();
        let state = inner.devices.get(&device)?;
        let mut snapshot = state.admission.snapshot();
        snapshot.device_limit = snapshot.effective_limit;
        snapshot.device_ordinal = device;
        let pool_limit = fair_pool_limit(
            state,
            &pool.name,
            snapshot.effective_limit,
            Instant::now(),
            true,
        );
        if state.pools.len() > 1 {
            snapshot.reason = format!(
                "CUDA device {device} limit {}; pool fair share {pool_limit}: {}",
                snapshot.effective_limit, snapshot.reason
            );
        }
        snapshot.effective_limit = pool_limit;
        Some(snapshot)
    }

    /// Feed one controller-tick observation into a pool's calibration state.
    pub fn observe(
        &self,
        pool: &ForkPoolRecord,
        active: u32,
        completed_total: u64,
        gpu: Option<GpuSample>,
        host_cpu_percent: Option<f64>,
    ) {
        self.observe_at(
            pool,
            active,
            completed_total,
            gpu,
            host_cpu_percent,
            Instant::now(),
        );
    }

    fn observe_at(
        &self,
        pool: &ForkPoolRecord,
        active: u32,
        completed_total: u64,
        gpu: Option<GpuSample>,
        host_cpu_percent: Option<f64>,
        now: Instant,
    ) {
        let samples = gpu.map(|sample| HashMap::from([(sample.device_ordinal, sample)]));
        self.observe_pools_at(
            &[(pool.clone(), active, completed_total)],
            samples.as_ref(),
            host_cpu_percent,
            now,
        );
    }

    /// Feed a full controller tick into device-scoped calibration states.
    pub fn observe_pools(
        &self,
        observations: &[(ForkPoolRecord, u32, u64)],
        gpu: Option<&HashMap<u32, GpuSample>>,
        host_cpu_percent: Option<f64>,
    ) {
        self.observe_pools_at(observations, gpu, host_cpu_percent, Instant::now());
    }

    /// Synchronize pool topology, activity, and ceilings without adding a
    /// telemetry sample. Event-driven reconciliation uses this so mutations
    /// become immediately claimable without shortening calibration windows.
    pub fn ensure_pools(&self, observations: &[(ForkPoolRecord, u32, u64)]) {
        self.update_pools_at(observations, None, None, Instant::now(), false);
    }

    fn observe_pools_at(
        &self,
        observations: &[(ForkPoolRecord, u32, u64)],
        gpu: Option<&HashMap<u32, GpuSample>>,
        host_cpu_percent: Option<f64>,
        now: Instant,
    ) {
        self.update_pools_at(observations, gpu, host_cpu_percent, now, true);
    }

    fn update_pools_at(
        &self,
        observations: &[(ForkPoolRecord, u32, u64)],
        gpu: Option<&HashMap<u32, GpuSample>>,
        host_cpu_percent: Option<f64>,
        now: Instant,
        sample: bool,
    ) {
        let mut grouped: HashMap<u32, Vec<&(ForkPoolRecord, u32, u64)>> = HashMap::new();
        for observation in observations {
            if observation.0.deleting {
                continue;
            }
            if let Some(device) = observation.0.admission_device_ordinal() {
                grouped.entry(device).or_default().push(observation);
            }
        }

        let mut inner = self.inner.lock();
        let live_pool_names = observations
            .iter()
            .filter(|(pool, _, _)| {
                !pool.deleting && pool.auto_admission && pool.admission_device_ordinal().is_some()
            })
            .map(|(pool, _, _)| pool.name.as_str())
            .collect::<std::collections::HashSet<_>>();
        inner
            .pool_devices
            .retain(|name, _| live_pool_names.contains(name.as_str()));

        let live_devices = grouped
            .iter()
            .filter_map(|(&device, pools)| {
                pools
                    .iter()
                    .any(|(pool, _, _)| pool.auto_admission)
                    .then_some(device)
            })
            .collect::<std::collections::HashSet<_>>();
        inner
            .devices
            .retain(|device, _| live_devices.contains(device));

        for (device, pools) in grouped {
            let auto_pools = pools
                .iter()
                .filter(|(pool, _, _)| pool.auto_admission)
                .copied()
                .collect::<Vec<_>>();
            if auto_pools.is_empty() {
                continue;
            }
            let ceiling = auto_pools.iter().fold(0_u32, |total, (pool, _, _)| {
                total.saturating_add(Self::ceiling(pool))
            });
            let active = pools
                .iter()
                .fold(0_u32, |total, (_, active, _)| total.saturating_add(*active));
            let completed = pools.iter().fold(0_u64, |total, (_, _, completed)| {
                total.saturating_add(*completed)
            });

            for (pool, _, _) in &auto_pools {
                inner.pool_devices.insert(pool.name.clone(), device);
            }
            let state = inner
                .devices
                .entry(device)
                .or_insert_with(|| DeviceAdmissionState {
                    admission: PoolAdmissionState::new(ceiling.max(1), now, completed),
                    pools: HashMap::new(),
                });
            let names = auto_pools
                .iter()
                .map(|(pool, _, _)| pool.name.as_str())
                .collect::<std::collections::HashSet<_>>();
            state.pools.retain(|name, _| names.contains(name.as_str()));
            for (pool, pool_active, _) in auto_pools {
                state
                    .pools
                    .entry(pool.name.clone())
                    .and_modify(|runtime| {
                        runtime.ceiling = Self::ceiling(pool);
                        runtime.active = *pool_active;
                    })
                    .or_insert(DevicePoolState {
                        ceiling: Self::ceiling(pool),
                        active: *pool_active,
                        last_demand: None,
                    });
            }
            state
                .admission
                .update_ceiling(ceiling.max(1), now, completed);
            if sample {
                state.admission.observe(
                    now,
                    active,
                    completed,
                    gpu.and_then(|samples| samples.get(&device).copied()),
                    host_cpu_percent,
                );
            }
        }
    }
}

fn fair_pool_limit(
    device: &DeviceAdmissionState,
    target: &str,
    device_limit: u32,
    now: Instant,
    include_target: bool,
) -> u32 {
    let mut demanded = device
        .pools
        .iter()
        .filter_map(|(name, pool)| {
            let recent = pool
                .last_demand
                .is_some_and(|demand| now.saturating_duration_since(demand) <= PRESSURE_TTL);
            (recent || (include_target && name == target)).then_some((name.as_str(), *pool))
        })
        .collect::<Vec<_>>();
    demanded.sort_unstable_by_key(|(name, _)| *name);
    if demanded.is_empty() {
        return device
            .pools
            .get(target)
            .map_or(device_limit, |pool| pool.ceiling.min(device_limit));
    }

    let demanded_names = demanded
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::HashSet<_>>();
    let occupied = device
        .pools
        .iter()
        .filter(|(name, _)| !demanded_names.contains(name.as_str()))
        .fold(0_u32, |total, (_, pool)| total.saturating_add(pool.active));
    let mut remaining = device_limit.saturating_sub(occupied);
    let mut shares = demanded
        .iter()
        .map(|(name, _)| (*name, 0_u32))
        .collect::<HashMap<_, _>>();
    while remaining > 0 {
        let mut advanced = false;
        for (name, pool) in &demanded {
            if remaining == 0 {
                break;
            }
            let share = shares.get_mut(name).expect("demanded pool has a share");
            if *share < pool.ceiling {
                *share += 1;
                remaining -= 1;
                advanced = true;
            }
        }
        if !advanced {
            break;
        }
    }
    shares.get(target).copied().unwrap_or(0)
}

/// Samples aggregate host CPU busy time from `/proc/stat`.
#[derive(Default)]
pub struct HostCpuSampler {
    #[cfg(target_os = "linux")]
    previous: Option<(u64, u64)>,
}

impl HostCpuSampler {
    /// Sample host CPU busy percentage since the previous call.
    pub fn sample(&mut self) -> Option<f64> {
        #[cfg(target_os = "linux")]
        {
            let data = std::fs::read_to_string("/proc/stat").ok()?;
            let line = data.lines().next()?;
            let mut fields = line.split_whitespace();
            if fields.next()? != "cpu" {
                return None;
            }
            let values: Vec<u64> = fields.filter_map(|field| field.parse().ok()).collect();
            if values.len() < 4 {
                return None;
            }
            let total = values.iter().copied().sum::<u64>();
            let idle = values[3].saturating_add(values.get(4).copied().unwrap_or(0));
            let result = self.previous.and_then(|(old_total, old_idle)| {
                let delta_total = total.saturating_sub(old_total);
                let delta_idle = idle.saturating_sub(old_idle);
                (delta_total > 0).then(|| {
                    100.0 * (delta_total.saturating_sub(delta_idle)) as f64 / delta_total as f64
                })
            });
            self.previous = Some((total, idle));
            result
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

/// Small dynamically-loaded NVML surface. The host NVIDIA driver already ships
/// this library; keeping it optional preserves CPU-only and non-Linux builds.
#[cfg(target_os = "linux")]
pub struct NvmlSampler {
    _library: libloading::Library,
    shutdown: unsafe extern "C" fn() -> i32,
    device_by_uuid:
        unsafe extern "C" fn(*const std::ffi::c_char, *mut *mut std::ffi::c_void) -> i32,
    memory_info: unsafe extern "C" fn(*mut std::ffi::c_void, *mut NvmlMemory) -> i32,
    utilization: unsafe extern "C" fn(*mut std::ffi::c_void, *mut NvmlUtilization) -> i32,
    cuda_devices: Vec<NvmlDeviceIdentity>,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct NvmlMemory {
    total: u64,
    free: u64,
    used: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct NvmlUtilization {
    gpu: u32,
    memory: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct NvmlPciInfo {
    bus_id_legacy: [std::ffi::c_char; 16],
    domain: u32,
    bus: u32,
    device: u32,
    pci_device_id: u32,
    pci_subsystem_id: u32,
    bus_id: [std::ffi::c_char; 32],
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct NvmlDeviceIdentity {
    uuid: std::ffi::CString,
    name: String,
    domain: u32,
    bus: u32,
    device: u32,
    mig_enabled: bool,
}

#[cfg(target_os = "linux")]
fn select_visible_devices(
    mut devices: Vec<NvmlDeviceIdentity>,
    visible: Option<&str>,
) -> Result<Vec<NvmlDeviceIdentity>, String> {
    devices.sort_unstable_by_key(|device| (device.domain, device.bus, device.device));
    let Some(visible) = visible else {
        return Ok(devices);
    };
    if visible.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut selected = Vec::new();
    for token in visible.split(',').map(str::trim) {
        if token == "-1" {
            break;
        }
        if let Ok(index) = token.parse::<usize>() {
            let Some(device) = devices.get(index) else {
                return Err(format!(
                    "CUDA_VISIBLE_DEVICES index {index} is outside {} PCI-ordered devices",
                    devices.len()
                ));
            };
            selected.push(device.clone());
            continue;
        }
        let matches = devices
            .iter()
            .filter(|device| device.uuid.to_bytes().starts_with(token.as_bytes()))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "CUDA_VISIBLE_DEVICES token '{token}' did not uniquely identify an NVML device"
            ));
        }
        selected.push(matches[0].clone());
    }
    Ok(selected)
}

#[cfg(target_os = "linux")]
impl NvmlSampler {
    /// Load and initialize the host driver's NVML library.
    pub fn new() -> Result<Self, String> {
        type Init = unsafe extern "C" fn() -> i32;
        type Shutdown = unsafe extern "C" fn() -> i32;
        type DeviceCount = unsafe extern "C" fn(*mut u32) -> i32;
        type DeviceHandle = unsafe extern "C" fn(u32, *mut *mut std::ffi::c_void) -> i32;
        type DeviceByUuid =
            unsafe extern "C" fn(*const std::ffi::c_char, *mut *mut std::ffi::c_void) -> i32;
        type DeviceUuid =
            unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_char, u32) -> i32;
        type DeviceName =
            unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_char, u32) -> i32;
        type PciInfo = unsafe extern "C" fn(*mut std::ffi::c_void, *mut NvmlPciInfo) -> i32;
        type MigMode = unsafe extern "C" fn(*mut std::ffi::c_void, *mut u32, *mut u32) -> i32;
        type MemoryInfo = unsafe extern "C" fn(*mut std::ffi::c_void, *mut NvmlMemory) -> i32;
        type Utilization = unsafe extern "C" fn(*mut std::ffi::c_void, *mut NvmlUtilization) -> i32;

        // SAFETY: the copied function pointers remain valid because the Library
        // is retained in the returned sampler until after `shutdown` runs.
        unsafe {
            let library = libloading::Library::new("libnvidia-ml.so.1")
                .map_err(|error| format!("load libnvidia-ml.so.1: {error}"))?;
            let init = *library
                .get::<Init>(b"nvmlInit_v2\0")
                .map_err(|error| format!("resolve nvmlInit_v2: {error}"))?;
            let shutdown = *library
                .get::<Shutdown>(b"nvmlShutdown\0")
                .map_err(|error| format!("resolve nvmlShutdown: {error}"))?;
            let device_count = *library
                .get::<DeviceCount>(b"nvmlDeviceGetCount_v2\0")
                .map_err(|error| format!("resolve nvmlDeviceGetCount_v2: {error}"))?;
            let device_handle = *library
                .get::<DeviceHandle>(b"nvmlDeviceGetHandleByIndex_v2\0")
                .map_err(|error| format!("resolve nvmlDeviceGetHandleByIndex_v2: {error}"))?;
            let device_by_uuid = *library
                .get::<DeviceByUuid>(b"nvmlDeviceGetHandleByUUID\0")
                .map_err(|error| format!("resolve nvmlDeviceGetHandleByUUID: {error}"))?;
            let device_uuid = *library
                .get::<DeviceUuid>(b"nvmlDeviceGetUUID\0")
                .map_err(|error| format!("resolve nvmlDeviceGetUUID: {error}"))?;
            let device_name = *library
                .get::<DeviceName>(b"nvmlDeviceGetName\0")
                .map_err(|error| format!("resolve nvmlDeviceGetName: {error}"))?;
            let pci_info = match library.get::<PciInfo>(b"nvmlDeviceGetPciInfo_v3\0") {
                Ok(symbol) => *symbol,
                Err(_) => *library
                    .get::<PciInfo>(b"nvmlDeviceGetPciInfo_v2\0")
                    .map_err(|error| format!("resolve nvmlDeviceGetPciInfo: {error}"))?,
            };
            let mig_mode = library
                .get::<MigMode>(b"nvmlDeviceGetMigMode\0")
                .ok()
                .map(|symbol| *symbol);
            let memory_info = *library
                .get::<MemoryInfo>(b"nvmlDeviceGetMemoryInfo\0")
                .map_err(|error| format!("resolve nvmlDeviceGetMemoryInfo: {error}"))?;
            let utilization = *library
                .get::<Utilization>(b"nvmlDeviceGetUtilizationRates\0")
                .map_err(|error| format!("resolve nvmlDeviceGetUtilizationRates: {error}"))?;
            let status = init();
            if status != 0 {
                return Err(format!("nvmlInit_v2 returned {status}"));
            }

            let cuda_devices = (|| -> Result<Vec<NvmlDeviceIdentity>, String> {
                let mut count = 0_u32;
                let status = device_count(&mut count);
                if status != 0 || count == 0 {
                    return Err(format!(
                        "nvmlDeviceGetCount_v2 returned {status} with count {count}"
                    ));
                }
                let mut identities = Vec::with_capacity(count as usize);
                for index in 0..count {
                    let mut device = std::ptr::null_mut();
                    let status = device_handle(index, &mut device);
                    if status != 0 || device.is_null() {
                        return Err(format!(
                            "nvmlDeviceGetHandleByIndex_v2({index}) returned {status}"
                        ));
                    }
                    let mut uuid = [0 as std::ffi::c_char; 96];
                    let status = device_uuid(device, uuid.as_mut_ptr(), uuid.len() as u32);
                    if status != 0 {
                        return Err(format!("nvmlDeviceGetUUID({index}) returned {status}"));
                    }
                    let uuid = std::ffi::CStr::from_ptr(uuid.as_ptr()).to_owned();
                    let mut name = [0 as std::ffi::c_char; 96];
                    let status = device_name(device, name.as_mut_ptr(), name.len() as u32);
                    if status != 0 {
                        return Err(format!("nvmlDeviceGetName({index}) returned {status}"));
                    }
                    let name = std::ffi::CStr::from_ptr(name.as_ptr())
                        .to_string_lossy()
                        .into_owned();
                    let mut pci = NvmlPciInfo::default();
                    let status = pci_info(device, &mut pci);
                    if status != 0 {
                        return Err(format!("nvmlDeviceGetPciInfo({index}) returned {status}"));
                    }
                    let mig_enabled = if let Some(mig_mode) = mig_mode {
                        let mut current = 0_u32;
                        let mut pending = 0_u32;
                        mig_mode(device, &mut current, &mut pending) == 0 && current != 0
                    } else {
                        false
                    };
                    identities.push(NvmlDeviceIdentity {
                        uuid,
                        name,
                        domain: pci.domain,
                        bus: pci.bus,
                        device: pci.device,
                        mig_enabled,
                    });
                }
                let visible = std::env::var("CUDA_VISIBLE_DEVICES").ok();
                let selected = if identities.iter().any(|device| device.mig_enabled) {
                    let visible = visible.as_deref().ok_or_else(|| {
                        "MIG mode requires CUDA_VISIBLE_DEVICES with explicit MIG UUIDs for admission"
                            .to_string()
                    })?;
                    let mut selected = Vec::new();
                    for token in visible.split(',').map(str::trim) {
                        if token == "-1" {
                            break;
                        }
                        if !token.starts_with("MIG-") {
                            return Err(
                                "MIG mode requires full MIG UUIDs in CUDA_VISIBLE_DEVICES".into()
                            );
                        }
                        let uuid = std::ffi::CString::new(token)
                            .map_err(|_| "CUDA_VISIBLE_DEVICES contains a NUL byte".to_string())?;
                        let mut handle = std::ptr::null_mut();
                        if device_by_uuid(uuid.as_ptr(), &mut handle) != 0 || handle.is_null() {
                            return Err(format!("NVML could not resolve MIG UUID '{token}'"));
                        }
                        let mut name = [0 as std::ffi::c_char; 96];
                        let status = device_name(handle, name.as_mut_ptr(), name.len() as u32);
                        if status != 0 {
                            return Err(format!(
                                "nvmlDeviceGetName for MIG UUID '{token}' returned {status}"
                            ));
                        }
                        selected.push(NvmlDeviceIdentity {
                            uuid,
                            name: std::ffi::CStr::from_ptr(name.as_ptr())
                                .to_string_lossy()
                                .into_owned(),
                            domain: 0,
                            bus: 0,
                            device: 0,
                            mig_enabled: true,
                        });
                    }
                    selected
                } else {
                    select_visible_devices(identities, visible.as_deref())?
                };
                if selected.is_empty() {
                    return Err("no CUDA-visible devices are available for admission".into());
                }
                Ok(selected)
            })();
            let cuda_devices = match cuda_devices {
                Ok(devices) => devices,
                Err(error) => {
                    shutdown();
                    return Err(error);
                }
            };
            Ok(Self {
                _library: library,
                shutdown,
                device_by_uuid,
                memory_info,
                utilization,
                cuda_devices,
            })
        }
    }

    /// Sample identity, utilization, and memory independently for every
    /// CUDA-visible device.
    pub fn sample_devices(&mut self) -> Option<Vec<GpuDeviceSample>> {
        // SAFETY: NVML owns device handles; all output pointers target valid,
        // initialized storage with the ABI layouts documented by NVML.
        unsafe {
            let mut samples = Vec::with_capacity(self.cuda_devices.len());
            for (index, identity) in self.cuda_devices.iter().enumerate() {
                let mut device = std::ptr::null_mut();
                if (self.device_by_uuid)(identity.uuid.as_ptr(), &mut device) != 0
                    || device.is_null()
                {
                    return None;
                }
                let mut memory = NvmlMemory::default();
                let mut utilization = NvmlUtilization::default();
                if (self.memory_info)(device, &mut memory) != 0
                    || (self.utilization)(device, &mut utilization) != 0
                {
                    return None;
                }
                let index = u32::try_from(index).ok()?;
                samples.push(GpuDeviceSample {
                    device_ordinal: index,
                    uuid: identity.uuid.to_string_lossy().into_owned(),
                    name: identity.name.clone(),
                    utilization_percent: f64::from(utilization.gpu),
                    used_memory_mib: memory.used / (1024 * 1024),
                    free_memory_mib: memory.free / (1024 * 1024),
                    total_memory_mib: memory.total / (1024 * 1024),
                });
            }
            Some(samples)
        }
    }

    /// Sample the compact telemetry used by fork-pool admission.
    pub fn sample(&mut self) -> Option<HashMap<u32, GpuSample>> {
        Some(
            self.sample_devices()?
                .into_iter()
                .map(|sample| (sample.device_ordinal, sample.admission_sample()))
                .collect(),
        )
    }
}

#[cfg(target_os = "linux")]
impl Drop for NvmlSampler {
    fn drop(&mut self) {
        // SAFETY: paired with the successful nvmlInit_v2 call in `new`.
        unsafe {
            (self.shutdown)();
        }
    }
}

#[cfg(not(target_os = "linux"))]
/// Reports unavailable NVML telemetry on unsupported hosts.
pub struct NvmlSampler;

#[cfg(not(target_os = "linux"))]
impl NvmlSampler {
    /// Report that NVML telemetry is unsupported on this host.
    pub fn new() -> Result<Self, String> {
        Err("NVML admission telemetry is only available on Linux".into())
    }

    /// Return no GPU sample on unsupported hosts.
    pub fn sample(&mut self) -> Option<HashMap<u32, GpuSample>> {
        None
    }

    /// Return no detailed device telemetry on unsupported hosts.
    pub fn sample_devices(&mut self) -> Option<Vec<GpuDeviceSample>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(size: u32) -> ForkPoolRecord {
        ForkPoolRecord {
            name: "rollouts".into(),
            golden: "golden".into(),
            desired_ready: size,
            max_active: None,
            auto_admission: true,
            cuda_device_ordinal: Some(0),
            share_weights: true,
            ready_timeout_secs: 240,
            lease_ttl_secs: 300,
            created_at: 1,
            deleting: false,
        }
    }

    fn gpu(utilization: f64, used: u64) -> Option<GpuSample> {
        Some(GpuSample::new(
            0,
            utilization,
            used,
            80 * 1024 - used,
            80 * 1024,
        ))
    }

    fn stable_window(
        registry: &AdmissionRegistry,
        pool: &ForkPoolRecord,
        start: Instant,
        observation: (u32, u64, f64, u64, f64),
    ) {
        let (active, completed, utilization, used, cpu) = observation;
        for second in 0..=8 {
            registry.observe_at(
                pool,
                active,
                completed,
                gpu(utilization, used),
                Some(cpu),
                start + Duration::from_secs(second),
            );
        }
    }

    fn pool_limit(registry: &AdmissionRegistry, pool: &ForkPoolRecord) -> Option<u32> {
        registry.limit(pool).map(|limit| limit.pool)
    }

    fn gpu_samples(samples: impl IntoIterator<Item = GpuSample>) -> HashMap<u32, GpuSample> {
        samples
            .into_iter()
            .map(|sample| (sample.device_ordinal, sample))
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn visible_devices_follow_pci_order_and_cuda_mask_order() {
        let devices = || {
            vec![
                NvmlDeviceIdentity {
                    uuid: std::ffi::CString::new("GPU-second").unwrap(),
                    name: "second".into(),
                    domain: 0,
                    bus: 2,
                    device: 0,
                    mig_enabled: false,
                },
                NvmlDeviceIdentity {
                    uuid: std::ffi::CString::new("GPU-first").unwrap(),
                    name: "first".into(),
                    domain: 0,
                    bus: 1,
                    device: 0,
                    mig_enabled: false,
                },
            ]
        };
        assert_eq!(
            select_visible_devices(devices(), None)
                .unwrap()
                .into_iter()
                .map(|device| device.uuid.into_string().unwrap())
                .collect::<Vec<_>>(),
            ["GPU-first", "GPU-second"]
        );
        assert_eq!(
            select_visible_devices(devices(), Some("1,0"))
                .unwrap()
                .into_iter()
                .map(|device| device.uuid.into_string().unwrap())
                .collect::<Vec<_>>(),
            ["GPU-second", "GPU-first"]
        );
    }

    #[test]
    fn device_sample_uses_only_its_own_headroom() {
        let sample = GpuSample::new(0, 95.0, 75 * 1024, 5 * 1024, 80 * 1024);
        assert_eq!(sample.used_memory_mib, 75 * 1024);
        assert_eq!(sample.total_memory_mib, 80 * 1024);
        assert_eq!(sample.free_memory_mib, 5 * 1024);
        assert_eq!(sample.reserve_mib, 8 * 1024);
        assert!(!sample.memory_safe());
    }

    #[test]
    fn heterogeneous_devices_each_use_their_own_reserve() {
        let small = GpuSample::new(0, 70.0, 15 * 1024, 9 * 1024, 24 * 1024);
        let large = GpuSample::new(1, 80.0, 135 * 1024, 25 * 1024, 160 * 1024);
        assert_eq!(small.reserve_mib, 6 * 1024);
        assert_eq!(large.reserve_mib, 16 * 1024);
        assert!(small.memory_safe());
        assert!(large.memory_safe());
    }

    #[test]
    fn small_devices_keep_proportional_headroom() {
        assert_eq!(device_reserve_mib(8 * 1024), 2 * 1024);
        assert_eq!(device_reserve_mib(16 * 1024), 4 * 1024);
        assert_eq!(device_reserve_mib(32 * 1024), 8 * 1024);
        assert_eq!(device_reserve_mib(80 * 1024), 8 * 1024);
    }

    #[test]
    fn same_device_pools_share_one_limit_fairly() {
        let registry = AdmissionRegistry::default();
        let mut first = pool(6);
        first.name = "first".into();
        let mut second = pool(6);
        second.name = "second".into();
        let start = Instant::now();
        let samples = gpu_samples([GpuSample::new(0, 10.0, 10_000, 70_000, 80_000)]);
        registry.observe_pools_at(
            &[(first.clone(), 0, 0), (second.clone(), 0, 0)],
            Some(&samples),
            Some(10.0),
            start,
        );

        let first_only = registry.limit(&first).unwrap();
        assert_eq!(first_only.device, 4);
        assert_eq!(first_only.pool, 4);

        registry.note_blocked("first");
        registry.note_blocked("second");
        let second_share = registry.limit(&second).unwrap();
        let first_share = registry.limit(&first).unwrap();
        assert_eq!(first_share.device, 4);
        assert_eq!(second_share.device, 4);
        assert_eq!(first_share.pool, 2);
        assert_eq!(second_share.pool, 2);
    }

    #[test]
    fn different_device_pools_calibrate_independently() {
        let registry = AdmissionRegistry::default();
        let mut first = pool(6);
        first.name = "first".into();
        let mut second = pool(12);
        second.name = "second".into();
        second.cuda_device_ordinal = Some(1);
        let samples = gpu_samples([
            GpuSample::new(0, 10.0, 10_000, 70_000, 80_000),
            GpuSample::new(1, 20.0, 20_000, 60_000, 80_000),
        ]);
        registry.observe_pools_at(
            &[(first.clone(), 0, 0), (second.clone(), 0, 0)],
            Some(&samples),
            Some(10.0),
            Instant::now(),
        );

        assert_eq!(registry.limit(&first).unwrap().device, 2);
        assert_eq!(registry.limit(&second).unwrap().device, 4);
    }

    #[test]
    fn per_device_pressure_rejects_a_larger_candidate() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 10_000), Some(10.0), start);
        registry.note_blocked("rollouts");
        stable_window(&registry, &pool, start, (4, 0, 50.0, 30_000, 50.0));
        assert_eq!(pool_limit(&registry, &pool), Some(8));

        let pressured = GpuSample::new(0, 95.0, 75 * 1024, 5 * 1024, 80 * 1024);
        for second in 0..=8 {
            registry.observe_at(
                &pool,
                8,
                0,
                Some(pressured),
                Some(50.0),
                start + Duration::from_secs(9 + second),
            );
        }

        assert_eq!(pool_limit(&registry, &pool), Some(4));
        let reason = registry.snapshot(&pool).unwrap().reason;
        assert!(
            reason.contains("limiting GPU has 5120 MiB free"),
            "{reason}"
        );
    }

    #[test]
    fn event_sync_initializes_and_resizes_without_failing_open() {
        let registry = AdmissionRegistry::default();
        let mut configured = pool(12);

        registry.ensure_pools(&[(configured.clone(), 0, 7)]);
        let initial = registry.snapshot(&configured).unwrap();
        assert_eq!(initial.effective_limit, 4);
        assert!(initial.calibrating);
        assert!(initial.reason.contains("waiting for GPU telemetry"));

        configured.desired_ready = 3;
        registry.ensure_pools(&[(configured.clone(), 0, 7)]);
        assert_eq!(registry.limit(&configured).unwrap().pool, 3);

        configured.auto_admission = false;
        registry.ensure_pools(&[(configured.clone(), 0, 7)]);
        assert_eq!(registry.limit(&configured), None);
        assert!(registry.snapshot(&configured).is_none());
    }

    #[test]
    fn event_sync_preserves_the_periodic_calibration_sample() {
        let registry = AdmissionRegistry::default();
        let configured = pool(12);
        let start = Instant::now();
        registry.observe_at(&configured, 4, 3, gpu(50.0, 30_000), Some(40.0), start);
        let before = registry.snapshot(&configured).unwrap();

        registry.ensure_pools(&[(configured.clone(), 4, 3)]);

        let after = registry.snapshot(&configured).unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn calibrates_to_the_measured_pareto_point_without_card_specific_limit() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 10_000), Some(10.0), start);
        registry.note_blocked("rollouts");

        stable_window(&registry, &pool, start, (4, 0, 56.6, 30_828, 62.0));
        assert_eq!(pool_limit(&registry, &pool), Some(8));

        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(9),
            (8, 0, 90.2, 51_138, 62.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(12));

        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(18),
            (12, 0, 88.0, 71_445, 62.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(8));
        assert!(!registry.snapshot(&pool).unwrap().calibrating);
    }

    #[test]
    fn cold_cuda_startup_matures_before_projecting_the_next_limit() {
        let registry = AdmissionRegistry::default();
        let pool = pool(24);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 39_719), Some(10.0), start);
        registry.note_blocked("rollouts");

        // CUDA workloads can spend their first window creating framework and
        // optimizer state on the CPU. The partial allocation visible in that
        // window is not a safe basis for doubling residency.
        stable_window(&registry, &pool, start, (8, 0, 0.0, 50_438, 53.0));
        assert_eq!(pool_limit(&registry, &pool), Some(8));
        let waiting = registry.snapshot(&pool).unwrap();
        assert!(waiting.calibrating);
        assert!(waiting.reason.contains("waiting for CUDA activity"));

        // Once CUDA is active, the mature eight-worker footprint rejects the
        // unsafe 16-worker doubling step but identifies 14 as the largest
        // candidate that preserves the device reserve.
        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(8),
            (8, 0, 90.0, 58_119, 65.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(14));
        let probing = registry.snapshot(&pool).unwrap();
        assert!(probing.calibrating);

        // The memory-safe candidate still has to produce a measurable gain.
        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(17),
            (14, 0, 90.0, 71_919, 65.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(8));
        let settled = registry.snapshot(&pool).unwrap();
        assert!(!settled.calibrating);
        assert!(settled.reason.contains("marginal gain"));
    }

    #[test]
    fn small_device_probes_between_current_and_unsafe_doubling_step() {
        let registry = AdmissionRegistry::default();
        let pool = pool(6);
        let start = Instant::now();
        let small_gpu = |utilization, used| {
            Some(GpuSample::new(
                0,
                utilization,
                used,
                8 * 1024 - used,
                8 * 1024,
            ))
        };
        registry.observe_at(&pool, 0, 0, small_gpu(0.0, 800), Some(10.0), start);
        registry.note_blocked("rollouts");
        for second in 0..=8 {
            registry.observe_at(
                &pool,
                2,
                u64::from(second == 8),
                small_gpu(90.0, 4_200),
                Some(40.0),
                start + Duration::from_secs(second),
            );
        }

        let snapshot = registry.snapshot(&pool).unwrap();
        assert_eq!(snapshot.effective_limit, 3);
        assert!(snapshot.calibrating);
        assert!(snapshot.reason.contains("memory-safe resident limit 3"));
    }

    #[test]
    fn partial_candidate_cohort_does_not_trigger_a_phase_biased_rollback() {
        let registry = AdmissionRegistry::default();
        let pool = pool(6);
        let start = Instant::now();
        let small_gpu = |used| Some(GpuSample::new(0, 0.0, used, 8 * 1024 - used, 8 * 1024));
        registry.observe_at(&pool, 0, 0, small_gpu(800), Some(10.0), start);
        registry.note_blocked("rollouts");

        for second in 0..=8 {
            registry.observe_at(
                &pool,
                2,
                if second == 8 { 2 } else { 0 },
                small_gpu(4_200),
                Some(40.0),
                start + Duration::from_secs(second),
            );
        }
        assert_eq!(pool_limit(&registry, &pool), Some(3));

        // Only two of the three candidate residents have completed. The old
        // eight-second comparison treated this as zero marginal gain and
        // rolled back immediately, just before the third completion arrived.
        for second in 0..=8 {
            registry.observe_at(
                &pool,
                3,
                if second == 8 { 4 } else { 2 },
                small_gpu(4_700),
                Some(40.0),
                start + Duration::from_secs(9 + second),
            );
        }
        let snapshot = registry.snapshot(&pool).unwrap();
        assert_eq!(snapshot.effective_limit, 3);
        assert!(snapshot.calibrating);
        assert!(snapshot.reason.contains("3 completions"));
    }

    #[test]
    fn complete_candidate_cohort_settles_at_intermediate_limit() {
        let registry = AdmissionRegistry::default();
        let pool = pool(6);
        let start = Instant::now();
        let small_gpu = |used| Some(GpuSample::new(0, 0.0, used, 8 * 1024 - used, 8 * 1024));
        registry.observe_at(&pool, 0, 0, small_gpu(800), Some(10.0), start);
        registry.note_blocked("rollouts");

        for second in 0..=8 {
            registry.observe_at(
                &pool,
                2,
                if second == 8 { 2 } else { 0 },
                small_gpu(4_200),
                Some(40.0),
                start + Duration::from_secs(second),
            );
        }
        assert_eq!(pool_limit(&registry, &pool), Some(3));

        for second in 0..=8 {
            registry.observe_at(
                &pool,
                3,
                if second == 8 { 5 } else { 2 },
                small_gpu(5_000),
                Some(40.0),
                start + Duration::from_secs(9 + second),
            );
        }

        let snapshot = registry.snapshot(&pool).unwrap();
        assert_eq!(snapshot.effective_limit, 3);
        assert!(!snapshot.calibrating);
        assert!(
            snapshot.reason.contains("holding at 3"),
            "{}",
            snapshot.reason
        );
    }

    #[test]
    fn partial_candidate_memory_pressure_rolls_back_without_waiting_for_cohort() {
        let registry = AdmissionRegistry::default();
        let pool = pool(6);
        let start = Instant::now();
        let small_gpu = |used| Some(GpuSample::new(0, 0.0, used, 8 * 1024 - used, 8 * 1024));
        registry.observe_at(&pool, 0, 0, small_gpu(800), Some(10.0), start);
        registry.note_blocked("rollouts");

        for second in 0..=8 {
            registry.observe_at(
                &pool,
                2,
                if second == 8 { 2 } else { 0 },
                small_gpu(4_200),
                Some(40.0),
                start + Duration::from_secs(second),
            );
        }
        assert_eq!(pool_limit(&registry, &pool), Some(3));

        // Incomplete jobs and low GPU activity can extend a candidate's
        // maturity window, but must never defer rollback after memory headroom
        // drops below the device reserve.
        for second in 0..=8 {
            registry.observe_at(
                &pool,
                3,
                2,
                small_gpu(7_000),
                Some(40.0),
                start + Duration::from_secs(9 + second),
            );
        }

        let snapshot = registry.snapshot(&pool).unwrap();
        assert_eq!(snapshot.effective_limit, 2);
        assert!(!snapshot.calibrating);
        assert!(
            snapshot.reason.contains("limiting GPU has 1192 MiB free"),
            "{}",
            snapshot.reason
        );
    }

    #[test]
    fn calibration_without_an_idle_sample_projects_conservatively() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.ensure_pools(&[(pool.clone(), 4, 0)]);
        registry.note_blocked("rollouts");

        stable_window(&registry, &pool, start, (4, 0, 60.0, 45_000, 50.0));
        assert_eq!(pool_limit(&registry, &pool), Some(6));
        let snapshot = registry.snapshot(&pool).unwrap();
        assert!(snapshot.calibrating);
        assert!(snapshot.reason.contains("memory-safe resident limit 6"));
    }

    #[test]
    fn stale_idle_baseline_projects_conservatively() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 50_000), Some(10.0), start);
        registry.note_blocked("rollouts");

        // GPU usage can fall below the recorded idle baseline when an
        // unrelated process exits. Do not interpret that stale baseline as a
        // zero-byte worker footprint and release another residency wave.
        stable_window(&registry, &pool, start, (4, 0, 60.0, 45_000, 50.0));
        assert_eq!(pool_limit(&registry, &pool), Some(6));
        let snapshot = registry.snapshot(&pool).unwrap();
        assert!(snapshot.calibrating);
        assert!(snapshot.reason.contains("memory-safe resident limit 6"));
    }

    #[test]
    fn a_completed_cpu_heavy_cohort_is_a_mature_calibration_signal() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 10_000), Some(10.0), start);
        registry.note_blocked("rollouts");

        for second in 0..=8 {
            registry.observe_at(
                &pool,
                4,
                if second == 8 { 4 } else { 0 },
                gpu(0.0, 20_000),
                Some(50.0),
                start + Duration::from_secs(second),
            );
        }
        assert_eq!(pool_limit(&registry, &pool), Some(8));
    }

    #[test]
    fn memory_safety_uses_the_observation_window_peak() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 10_000), Some(10.0), start);
        registry.note_blocked("rollouts");

        for second in 0..=8 {
            let used = if second == 4 { 75 * 1024 } else { 30_000 };
            registry.observe_at(
                &pool,
                4,
                0,
                gpu(50.0, used),
                Some(50.0),
                start + Duration::from_secs(second),
            );
        }

        assert_eq!(pool_limit(&registry, &pool), Some(4));
        let reason = registry.snapshot(&pool).unwrap().reason;
        assert!(
            reason.contains("limiting GPU has 5120 MiB free"),
            "{reason}"
        );
    }

    #[test]
    fn telemetry_failure_falls_back_to_full_residency() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        registry.observe_at(&pool, 0, 0, None, None, Instant::now());
        let snapshot = registry.snapshot(&pool).unwrap();
        assert_eq!(snapshot.effective_limit, 12);
        assert!(snapshot.reason.contains("telemetry unavailable"));
    }

    #[test]
    fn telemetry_recovery_restarts_calibration_after_existing_leases_drain() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 12, 0, None, None, start);
        assert_eq!(pool_limit(&registry, &pool), Some(12));

        registry.observe_at(
            &pool,
            12,
            0,
            gpu(90.0, 70_000),
            Some(50.0),
            start + Duration::from_secs(1),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(4));
        assert!(registry
            .snapshot(&pool)
            .unwrap()
            .reason
            .contains("restarting calibration"));

        registry.observe_at(
            &pool,
            12,
            0,
            gpu(90.0, 70_000),
            Some(50.0),
            start + Duration::from_secs(2),
        );
        assert!(registry.snapshot(&pool).unwrap().reason.contains("drain"));
        assert_eq!(pool_limit(&registry, &pool), Some(4));
    }

    #[test]
    fn cpu_saturation_rejects_a_larger_candidate() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 10_000), Some(10.0), start);
        registry.note_blocked("rollouts");
        stable_window(&registry, &pool, start, (4, 0, 50.0, 30_000, 50.0));
        assert_eq!(pool_limit(&registry, &pool), Some(8));
        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(9),
            (8, 0, 90.0, 50_000, 96.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(4));
    }

    #[test]
    fn late_cpu_saturation_rolls_back_the_last_accepted_candidate() {
        let registry = AdmissionRegistry::default();
        let pool = pool(12);
        let start = Instant::now();
        registry.observe_at(&pool, 0, 0, gpu(0.0, 10_000), Some(10.0), start);
        registry.note_blocked("rollouts");
        stable_window(&registry, &pool, start, (4, 0, 50.0, 30_000, 50.0));
        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(9),
            (8, 0, 75.0, 50_000, 70.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(12));
        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(18),
            (12, 0, 95.0, 70_000, 80.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(12));
        stable_window(
            &registry,
            &pool,
            start + Duration::from_secs(27),
            (12, 0, 95.0, 71_000, 95.0),
        );
        assert_eq!(pool_limit(&registry, &pool), Some(8));
        let snapshot = registry.snapshot(&pool).unwrap();
        assert!(snapshot.reason.contains("drain"), "{}", snapshot.reason);
    }

    #[test]
    fn a_static_pool_never_receives_a_dynamic_limit() {
        let registry = AdmissionRegistry::default();
        let mut pool = pool(12);
        pool.auto_admission = false;
        registry.observe(&pool, 0, 0, gpu(0.0, 0), Some(0.0));
        assert_eq!(registry.limit(&pool), None);
        assert_eq!(registry.snapshot(&pool), None);
    }
}
