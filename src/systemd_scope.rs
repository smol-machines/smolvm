//! Place a VM process in its own **systemd transient scope** so it survives a
//! `serve` restart.
//!
//! Today a VM is a child process inside `smolvm-node.service`'s delegated cgroup.
//! On `systemctl restart`, a surviving VM left in that cgroup makes systemd fail
//! to recreate the unit (`status=219/CGROUP`) → serve crash-loops. Adopting the
//! VM into its own `smolvm-vm-<id>.scope` (a sibling unit owned by PID1) moves it
//! out of the service cgroup, so serve can restart and reconnect to the still-
//! running VM.
//!
//! Implemented by shelling out to `busctl` (ships with systemd — no D-Bus crate
//! dependency, and absent exactly where scopes wouldn't work anyway). The caller
//! forks the VM normally (retaining stdio/fd/process-group control), then calls
//! [`adopt_into_scope`] on the resulting PID. systemd's `StartTransientUnit`
//! with a `PIDs=` property moves the process into the scope's cgroup and applies
//! the resource caps as unit properties. Scopes auto-remove when their last
//! process exits, so machine stop/delete needs no extra teardown.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Hard wall-clock bound on any single `busctl` call.
///
/// `busctl` is on both VM hot paths — `start` → [`adopt_into_scope`] and
/// `stop`/delete → [`kill_scope`] — and these run on the request-serving blocking
/// pool. systemd's `StartTransientUnit`/`KillUnit` can block for MINUTES when a VM
/// is wedged in an uninterruptible (D) kernel state (its cgroup won't die), and the
/// call had no timeout — so one stuck VM could pin blocking-pool threads until they
/// were exhausted, starving `start`/`exec` across the whole node while `/health`
/// (pure-async, no busctl) stayed green so auto-cordon never fired. This bounds the
/// call so the thread is freed in seconds; the teardown is retried out-of-band
/// instead of hanging the node. See the 2026-07-05 worker-1 wedge.
const BUSCTL_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll cadence while waiting for a `busctl` call to finish. Small relative to the
/// timeout; adds at most one interval of latency to a normal (fast) call.
const BUSCTL_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Run a `busctl` command with a hard wall-clock bound ([`BUSCTL_TIMEOUT`]).
///
/// On timeout the child is killed (busctl is a normal userspace process, so it dies
/// at once, freeing the thread) and a timeout error is returned for the caller to
/// handle out-of-band — never leaving a request-serving thread pinned on a wedged
/// systemd. std-only (no libc) so it compiles on every platform the callers do;
/// busctl's replies are tiny, so leaving stdout/stderr buffered until the poll loop
/// exits can't fill the pipe.
fn busctl_bounded(mut cmd: Command, timeout: Duration) -> Result<Output> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::agent("vm scope", format!("busctl spawn failed: {e}")))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::agent(
                        "vm scope",
                        format!(
                            "busctl timed out after {}s (systemd/cgroup wedged)",
                            timeout.as_secs()
                        ),
                    ));
                }
                std::thread::sleep(BUSCTL_POLL_INTERVAL);
            }
            Err(e) => return Err(Error::agent("vm scope", format!("busctl wait failed: {e}"))),
        }
    }
    child
        .wait_with_output()
        .map_err(|e| Error::agent("vm scope", format!("busctl output failed: {e}")))
}

/// The slice every VM scope runs in, a top-level sibling of `system.slice`.
///
/// Without it each VM scope sat directly in `system.slice` beside
/// `smolvm-node.service`, every one at the default CPU weight, so a node with
/// 87 busy VMs gave its own API about 1/88 of the contended CPU and stopped
/// answering (the 2026-11-04 x86-xfs-worker-0 saturation). In a slice of their
/// own, all VMs together weigh the same as all host services together, so the
/// node keeps at least half the CPU however many VMs it runs. systemd creates
/// the slice on demand the first time a scope names it.
pub const VM_SLICE: &str = "smolvm.slice";

/// Share of the [`VM_SLICE`] memory limit that page cache is kept below by
/// proactive reclaim. Cache above this line counts as free headroom for
/// branch admission; cache below it does not, because the kernel enforces the
/// limit on all of `memory.current` and reaching it makes VM threads reclaim
/// synchronously while they hold filesystem locks.
pub const VM_SLICE_RECLAIM_TARGET_PERCENT: u64 = 85;

/// Online CPUs on hosts at least this large keep a few CPUs free of VMs by
/// default (see [`host_reserved_cpus`]). Smaller hosts (laptops, CI runners)
/// cannot spare a whole core.
const RESERVE_CPUS_MIN_HOST: usize = 32;

/// How many host CPUs to keep free of VMs, so the node's own services always
/// have a core no guest can run on. `SMOLVM_HOST_RESERVED_CPUS` wins when it is
/// a number (`0` turns the reservation off); otherwise hosts with at least
/// [`RESERVE_CPUS_MIN_HOST`] CPUs reserve one per 64, and smaller hosts none.
/// Always leaves VMs at least one CPU.
pub fn host_reserved_cpus(online: usize, configured: Option<&str>) -> usize {
    let wanted = match configured.and_then(|v| v.trim().parse::<usize>().ok()) {
        Some(n) => n,
        None if online >= RESERVE_CPUS_MIN_HOST => (online / 64).max(1),
        None => 0,
    };
    wanted.min(online.saturating_sub(1))
}

/// Parse a kernel CPU list such as `0-191` or `0-3,8,10-11` into CPU ids.
fn parse_cpu_list(list: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in list.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (usize, usize) = (a.parse().ok()?, b.parse().ok()?);
                if a > b {
                    return None;
                }
                cpus.extend(a..=b);
            }
            None => cpus.push(part.parse().ok()?),
        }
    }
    Some(cpus)
}

/// The `AllowedCPUs` mask for [`VM_SLICE`]: every online CPU except the
/// `reserved` lowest-numbered ones (CPU 0 also takes most interrupts, so the
/// host is better off keeping it). Bit `i % 8` of byte `i / 8` is CPU `i`, as
/// systemd encodes a CPU set on the bus. Empty means no restriction.
fn vm_slice_cpu_mask(online: &[usize], reserved: usize) -> Vec<u8> {
    if reserved == 0 {
        return Vec::new();
    }
    let mut sorted = online.to_vec();
    sorted.sort_unstable();
    let mut mask = Vec::new();
    for &cpu in sorted.iter().skip(reserved) {
        if mask.len() <= cpu / 8 {
            mask.resize(cpu / 8 + 1, 0);
        }
        mask[cpu / 8] |= 1 << (cpu % 8);
    }
    mask
}

fn slice_cpus_args(mask: &[u8]) -> Vec<String> {
    // SetUnitProperties(name: s, runtime: b, properties: a(sv)). Runtime only:
    // serve sets it again on every start, so a changed reservation takes effect
    // on the next restart and nothing stale outlives a reboot.
    let mut args: Vec<String> = [
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "SetUnitProperties",
        "sba(sv)",
        VM_SLICE,
        "true",
        "1",
        "AllowedCPUs",
        "ay",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    args.push(mask.len().to_string());
    args.extend(mask.iter().map(u8::to_string));
    args
}

/// Keep [`host_reserved_cpus`] CPUs free of VMs by limiting [`VM_SLICE`] to the
/// rest. Called once by `serve` when it runs VMs in scopes; VMs already running
/// in the slice move off the reserved CPUs at once. Returns how many CPUs are
/// reserved.
pub fn configure_vm_slice() -> Result<usize> {
    let online = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|list| parse_cpu_list(&list))
        .ok_or_else(|| Error::agent("vm slice", "cannot read the online CPU list"))?;
    let configured = std::env::var("SMOLVM_HOST_RESERVED_CPUS").ok();
    let reserved = host_reserved_cpus(online.len(), configured.as_deref());
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm slice", "busctl not found; cannot set up the VM slice"))?;
    let mut cmd = Command::new(&busctl);
    cmd.args(slice_cpus_args(&vm_slice_cpu_mask(&online, reserved)));
    let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    if !out.status.success() {
        return Err(Error::agent(
            "vm slice",
            format!(
                "SetUnitProperties {VM_SLICE} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(reserved)
}

/// The least memory a host keeps out of reach of VMs by default (MiB): room for
/// the kernel, `smolvm-node serve`, the node agent, sshd and journald.
const HOST_RESERVED_MEMORY_FLOOR_MIB: u64 = 8 * 1024;

/// Share of host memory (percent) kept out of reach of VMs by default. A fixed
/// few GiB is noise on a 755–1511 GiB worker: on 2026-11-09 three of them ran
/// out of memory globally with branch children, the kernel wedged, and sshd and
/// the node agent stopped answering until the hosts were reset.
const HOST_RESERVED_MEMORY_PERCENT: u64 = 6;

/// VMs keep at least this much memory (MiB) whatever reserve is configured.
const VM_MEMORY_FLOOR_MIB: u64 = 1024;

/// How much host memory (MiB) to keep out of reach of VMs on a host with
/// `total_mib` of memory. `SMOLVM_HOST_RESERVED_MEMORY_MB` wins when it is a
/// number (`0` turns the reservation off); otherwise the larger of
/// [`HOST_RESERVED_MEMORY_FLOOR_MIB`] and [`HOST_RESERVED_MEMORY_PERCENT`] of
/// the host, but never more than a quarter of it so a small dev host still
/// runs VMs. Always leaves VMs at least [`VM_MEMORY_FLOOR_MIB`].
pub fn host_reserved_memory_mib(total_mib: u64, configured: Option<&str>) -> u64 {
    let wanted = match configured.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(n) => n,
        None => (total_mib.saturating_mul(HOST_RESERVED_MEMORY_PERCENT) / 100)
            .max(HOST_RESERVED_MEMORY_FLOOR_MIB)
            .min(total_mib / 4),
    };
    wanted.min(total_mib.saturating_sub(VM_MEMORY_FLOOR_MIB))
}

/// [`host_reserved_memory_mib`] with the operator's
/// `SMOLVM_HOST_RESERVED_MEMORY_MB`, if any.
pub fn configured_host_reserved_memory_mib(total_mib: u64) -> u64 {
    let configured = std::env::var("SMOLVM_HOST_RESERVED_MEMORY_MB").ok();
    host_reserved_memory_mib(total_mib, configured.as_deref())
}

/// systemd's encoding of "no limit" for a memory property.
const MEMORY_LIMIT_INFINITY: u64 = u64::MAX;

/// The memory limits applied to [`VM_SLICE`], in bytes
/// ([`MEMORY_LIMIT_INFINITY`] = no limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmSliceMemoryLimits {
    /// `MemoryHigh`: always [`MEMORY_LIMIT_INFINITY`]. A finite one (v1.34.1)
    /// made the kernel throttle a VMM over it with sleeps inside the
    /// allocation, which on 2026-11-12 happened inside an XFS inode create
    /// holding the AGI buffer lock; every other VMM and serve itself then
    /// queued on that lock and the node stopped answering. The memory
    /// pressure guard reclaims the slice from its own thread instead.
    pub high_bytes: u64,
    /// `MemoryMax`: the hard cap. An OOM at it kills a VM inside the slice
    /// instead of starving the host's own services.
    pub max_bytes: u64,
    /// The slice already held more than the cap when it was applied, so the
    /// limits were raised to what it holds rather than OOM-killing VMs that
    /// are running now. The next serve start with the slice below the cap
    /// applies the real one.
    pub raised_to_current: bool,
}

/// The [`VM_SLICE`] memory limits for a host with `total_bytes` of memory that
/// keeps `reserved_bytes` for itself, given what the slice holds now
/// (`current_bytes`, when known). `MemoryHigh` is always infinity, set
/// explicitly so a finite one left by v1.34.1 is cleared on upgrade.
fn vm_slice_memory_limits(
    total_bytes: u64,
    reserved_bytes: u64,
    current_bytes: Option<u64>,
) -> VmSliceMemoryLimits {
    if reserved_bytes == 0 || reserved_bytes >= total_bytes {
        return VmSliceMemoryLimits {
            high_bytes: MEMORY_LIMIT_INFINITY,
            max_bytes: MEMORY_LIMIT_INFINITY,
            raised_to_current: false,
        };
    }
    let max_bytes = total_bytes - reserved_bytes;
    // Headroom kept above what the slice already holds when the cap would
    // otherwise land at or below it.
    let gap = (max_bytes / 50).min(8 * 1024 * 1024 * 1024);
    match current_bytes {
        // Lowering the cap to what the slice holds makes the kernel reclaim at
        // once, and guest RAM (shared memory, no swap) cannot be reclaimed: it
        // would OOM-kill running VMs the moment serve restarts.
        Some(current) if current.saturating_add(gap) > max_bytes => VmSliceMemoryLimits {
            high_bytes: MEMORY_LIMIT_INFINITY,
            max_bytes: current.saturating_add(gap),
            raised_to_current: true,
        },
        _ => VmSliceMemoryLimits {
            high_bytes: MEMORY_LIMIT_INFINITY,
            max_bytes,
            raised_to_current: false,
        },
    }
}

fn slice_memory_args(limits: &VmSliceMemoryLimits) -> Vec<String> {
    // Runtime only, like AllowedCPUs: serve sets it again on every start.
    [
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "SetUnitProperties",
        "sba(sv)",
        VM_SLICE,
        "true",
        "2",
        "MemoryHigh",
        "t",
        &limits.high_bytes.to_string(),
        "MemoryMax",
        "t",
        &limits.max_bytes.to_string(),
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// What [`configure_vm_slice_memory`] applied, for the serve log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmSliceMemoryCap {
    /// Host `MemTotal` (MiB).
    pub host_total_mib: u64,
    /// Memory kept out of reach of VMs (MiB); 0 = no cap.
    pub reserved_mib: u64,
    /// The limits applied to the slice.
    pub limits: VmSliceMemoryLimits,
}

/// Cap [`VM_SLICE`] at host memory minus [`configured_host_reserved_memory_mib`],
/// so the host's own services always keep memory: guest RAM is shared memory a
/// per-VM `memory.high` cannot reclaim, and thousands of branch children can
/// otherwise push the whole host into a global OOM that wedges the kernel.
/// Called once by `serve` when it runs VMs in scopes; idempotent (a reserve of
/// 0 clears an earlier cap).
pub fn configure_vm_slice_memory() -> Result<VmSliceMemoryCap> {
    const MIB: u64 = 1024 * 1024;
    let host_total_mib = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| parse_mem_total_bytes(&meminfo))
        .ok_or_else(|| Error::agent("vm slice", "cannot read MemTotal from /proc/meminfo"))?
        / MIB;
    let reserved_mib = configured_host_reserved_memory_mib(host_total_mib);
    let current_bytes = std::fs::read_to_string(
        Path::new("/sys/fs/cgroup")
            .join(VM_SLICE)
            .join("memory.current"),
    )
    .ok()
    .and_then(|v| v.trim().parse::<u64>().ok());
    let limits = vm_slice_memory_limits(
        host_total_mib.saturating_mul(MIB),
        reserved_mib.saturating_mul(MIB),
        current_bytes,
    );
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm slice", "busctl not found; cannot set up the VM slice"))?;
    let mut cmd = Command::new(&busctl);
    cmd.args(slice_memory_args(&limits));
    let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    if !out.status.success() {
        return Err(Error::agent(
            "vm slice",
            format!(
                "SetUnitProperties {VM_SLICE} memory failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(VmSliceMemoryCap {
        host_total_mib,
        reserved_mib,
        limits,
    })
}

fn parse_mem_total_bytes(meminfo: &str) -> Option<u64> {
    let rest = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?;
    rest.split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

/// Resource caps applied to the VM's scope (as systemd unit properties).
///
/// Mirrors the per-VM cgroup limits set by [`crate::process::place_in_cgroup`]:
/// `MemoryMax` ↔ `memory.max`, `CPUQuotaPerSecUSec` ↔ `cpu.max`, `TasksMax` ↔
/// `pids.max`.
#[derive(Debug, Default, Clone)]
pub struct ScopeCaps {
    /// Hard memory ceiling in bytes (`MemoryMax`). `None` = uncapped.
    pub memory_max_bytes: Option<u64>,
    /// Reclaim threshold in bytes (`MemoryHigh`), set below `MemoryMax` so the
    /// kernel starts throttling and reclaim before the hard limit is reached.
    /// `None` disables this early threshold; `MemoryMax` still attempts reclaim.
    pub memory_high_bytes: Option<u64>,
    /// CPU quota in microseconds-of-CPU-time per real second
    /// (`CPUQuotaPerSecUSec`). For N vCPUs uncapped-overcommit, pass
    /// `N * 1_000_000`. `None` = uncapped.
    pub cpu_quota_usec_per_sec: Option<u64>,
    /// Max number of tasks/PIDs (`TasksMax`). `None` = systemd default.
    pub tasks_max: Option<u64>,
}

/// True iff we can actually create system-bus transient scopes here: a systemd
/// host (`/run/systemd/system`, à la `sd_booted()`), `busctl` present, AND we run
/// as root.
///
/// The root check matters: `StartTransientUnit` on the **system** bus needs root
/// (or polkit), and serve runs as root on the cloud worker. Without it, an
/// unprivileged local `serve` would pass the systemd check, enter scope-mode,
/// then have every adopt rejected — leaving VMs uncapped (scope-mode skips the
/// cgroup fallback). Returning false instead routes the caller to direct cgroup
/// placement, which keeps resource caps (it just isn't lossless — fine for dev).
///
/// Non-systemd hosts (macOS dev, OpenRC, bare containers) also return false.
/// Future: support the per-user systemd bus (`busctl --user`) so an unprivileged
/// local serve can still get scopes.
pub fn is_available() -> bool {
    // systemd scopes are a Linux-only concept; never available elsewhere.
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid() is always-safe (no args, no global state mutation).
        let is_root = unsafe { libc::geteuid() } == 0;
        is_root && Path::new("/run/systemd/system").is_dir() && busctl_path().is_some()
    }
}

/// Locate `busctl` (PATH, then the usual absolute locations — serve may run with
/// a minimal `PATH`).
fn busctl_path() -> Option<PathBuf> {
    for cand in ["/usr/bin/busctl", "/bin/busctl", "/usr/local/bin/busctl"] {
        let p = Path::new(cand);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    // Fall back to PATH resolution via the shell-less which-equivalent.
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("busctl"))
            .find(|p| p.exists())
    })
}

/// systemd unit names allow `[A-Za-z0-9:_.\-]`; sanitize the machine id and clamp
/// length so the scope name is always valid. Collisions are avoided by the caller
/// using unique machine ids; a dead scope self-removes when its VM exits.
pub fn scope_name(machine_id: &str) -> String {
    let safe: String = machine_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .take(200)
        .collect();
    format!("smolvm-vm-{safe}.scope")
}

/// Adopt an already-forked VM `pid` into its own transient scope with `caps`.
///
/// Returns `Err` if systemd rejects the request (e.g. the PID already exited, or
/// the bus call failed); the caller should fall back to plain cgroup placement
/// rather than failing the launch.
pub fn adopt_into_scope(machine_id: &str, pid: i32, caps: &ScopeCaps) -> Result<()> {
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm scope", "busctl not found; cannot create scope"))?;
    let name = scope_name(machine_id);
    let args = scope_start_args(machine_id, pid, caps);
    let mut cmd = Command::new(&busctl);
    cmd.args(&args);
    let mut out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    if !out.status.success() && scope_start_collided(&out.stderr) {
        // A previous VM of this name left its scope loaded in the `failed` state
        // (it was SIGKILLed by `kill_scope`, or ran out of resources). systemd
        // never garbage-collects failed units on its own, so every later start
        // of this machine would collide forever. ResetFailedUnit only unloads a
        // unit that is failed, so it cannot disturb a live VM's scope.
        reset_failed_scope(&busctl, &name)?;
        let mut cmd = Command::new(&busctl);
        cmd.args(&args);
        out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    }
    if !out.status.success() {
        return Err(Error::agent(
            "vm scope",
            format!(
                "StartTransientUnit {name} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    tracing::info!(scope = %name, pid, "adopted VM into systemd transient scope");
    Ok(())
}

/// Whether a StartTransientUnit failure was a name collision with a loaded unit.
fn scope_start_collided(stderr: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr);
    stderr.contains("already loaded") || stderr.contains("UnitExists")
}

fn reset_failed_scope(busctl: &std::path::Path, name: &str) -> Result<()> {
    let mut cmd = Command::new(busctl);
    cmd.args([
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "ResetFailedUnit",
        "s",
        name,
    ]);
    let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    if out.status.success() {
        tracing::info!(scope = %name, "reset failed VM scope left by a previous run");
    } else {
        // Not failed (e.g. still active): the retried start reports the real error.
        tracing::debug!(scope = %name, stderr = %String::from_utf8_lossy(&out.stderr).trim(), "ResetFailedUnit declined");
    }
    Ok(())
}

fn scope_start_args(machine_id: &str, pid: i32, caps: &ScopeCaps) -> Vec<String> {
    let name = scope_name(machine_id);

    // Build the a(sv) property list in busctl's positional encoding:
    //   <prop-name> <variant-type> <variant-value...>
    // PIDs is an array of u32 (`au`): "au <count> <elem...>".
    let mut props: Vec<String> = Vec::new();
    let mut nprops: u32 = 0;

    props.extend(["PIDs".into(), "au".into(), "1".into(), pid.to_string()]);
    nprops += 1;
    props.extend([
        "Description".into(),
        "s".into(),
        format!("smolvm VM {machine_id}"),
    ]);
    nprops += 1;
    props.extend(["Slice".into(), "s".into(), VM_SLICE.into()]);
    nprops += 1;
    if let Some(m) = caps.memory_high_bytes {
        props.extend(["MemoryHigh".into(), "t".into(), m.to_string()]);
        nprops += 1;
    }
    if let Some(m) = caps.memory_max_bytes {
        props.extend(["MemoryMax".into(), "t".into(), m.to_string()]);
        nprops += 1;
    }
    if let Some(q) = caps.cpu_quota_usec_per_sec {
        props.extend(["CPUQuotaPerSecUSec".into(), "t".into(), q.to_string()]);
        nprops += 1;
    }
    if let Some(t) = caps.tasks_max {
        props.extend(["TasksMax".into(), "t".into(), t.to_string()]);
        nprops += 1;
    }

    // StartTransientUnit(name: s, mode: s, properties: a(sv), aux: a(sa(sv))).
    // mode "fail": error if the unit already exists. A scope whose VM exited
    // cleanly is GC'd by systemd; a *failed* one is not, and adopt_into_scope
    // resets it and retries.
    let mut args: Vec<String> = vec![
        "call".into(),
        "org.freedesktop.systemd1".into(),
        "/org/freedesktop/systemd1".into(),
        "org.freedesktop.systemd1.Manager".into(),
        "StartTransientUnit".into(),
        "ssa(sv)a(sa(sv))".into(),
        name.clone(),
        "fail".into(),
        nprops.to_string(),
    ];
    args.extend(props);
    args.push("0".into()); // empty aux array

    args
}

/// Change the reclaim threshold and hard memory ceiling of an existing VM scope.
///
/// A live branch source retains immutable RAM generations in the same memory
/// cgroup that originally faulted those pages.  Linux does not migrate those
/// page charges when a raw-forked guardian moves between cgroups, so the scope
/// ceiling must grow with the number of retained generations and shrink again
/// when they are collected.
pub fn set_scope_memory_max(
    machine_id: &str,
    memory_max_bytes: u64,
    memory_high_bytes: u64,
) -> Result<()> {
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm scope", "busctl not found; cannot update scope"))?;
    let name = scope_name(machine_id);

    // SetUnitProperties(name: s, runtime: b, properties: a(sv)).  Runtime=true
    // keeps the transient scope transient while making the new limit effective
    // immediately in memory.max.
    let args = [
        "call".to_string(),
        "org.freedesktop.systemd1".to_string(),
        "/org/freedesktop/systemd1".to_string(),
        "org.freedesktop.systemd1.Manager".to_string(),
        "SetUnitProperties".to_string(),
        "sba(sv)".to_string(),
        name.clone(),
        "true".to_string(),
        "2".to_string(),
        "MemoryHigh".to_string(),
        "t".to_string(),
        memory_high_bytes.to_string(),
        "MemoryMax".to_string(),
        "t".to_string(),
        memory_max_bytes.to_string(),
    ];
    let mut cmd = Command::new(&busctl);
    cmd.args(args);
    let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::agent(
            "vm scope",
            format!("SetUnitProperties {name} failed: {}", stderr.trim()),
        ));
    }
    tracing::debug!(scope = %name, memory_max_bytes, "updated VM scope memory ceiling");
    Ok(())
}

/// Update the CPU quota of an existing transient VM scope without restarting it.
pub fn set_scope_cpu_count(machine_id: &str, cpus: u8) -> Result<()> {
    if cpus == 0 {
        return Err(Error::config("CPU resize", "CPU count must be nonzero"));
    }
    set_scope_cpu_quota(machine_id, u64::from(cpus) * 1_000_000)
}

/// Set an existing transient VM scope's CPU quota to `usec_per_sec` of CPU
/// time per wall-clock second across all its threads (1_000_000 = one CPU),
/// at runtime only, without restarting it.
pub fn set_scope_cpu_quota(machine_id: &str, usec_per_sec: u64) -> Result<()> {
    if usec_per_sec == 0 {
        return Err(Error::config("CPU quota", "CPU quota must be nonzero"));
    }
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm scope", "busctl not found; cannot update CPU quota"))?;
    let mut cmd = Command::new(busctl);
    cmd.args([
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "SetUnitProperties",
        "sba(sv)",
        &scope_name(machine_id),
        "true",
        "1",
        "CPUQuotaPerSecUSec",
        "t",
        &usec_per_sec.to_string(),
    ]);
    let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    if !out.status.success() {
        return Err(Error::agent(
            "CPU resize",
            format!(
                "scope quota update failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(())
}

/// Stop the scope a failed launch created once its VM process is gone.
///
/// A VM process that exits before systemd moves it into the new scope never
/// populates the scope's cgroup, so systemd never sees that cgroup become
/// empty and the scope stays active with no processes in it. Only the launch
/// that created the scope may call this, after confirming its process is dead.
/// A scope that is already gone counts as stopped.
pub fn stop_scope(machine_id: &str) -> Result<()> {
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm scope", "busctl not found; cannot stop scope"))?;
    let name = scope_name(machine_id);
    let mut cmd = Command::new(&busctl);
    cmd.args(scope_stop_args(&name));
    let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
    if out.status.success() || scope_already_gone(&out.stderr) {
        tracing::info!(scope = %name, "stopped VM scope left by a failed launch");
        return Ok(());
    }
    Err(Error::agent(
        "vm scope",
        format!(
            "StopUnit {name} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    ))
}

fn scope_stop_args(name: &str) -> Vec<String> {
    // StopUnit(name: s, mode: s).
    [
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StopUnit",
        "ss",
        name,
        "replace",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Whether a unit call failed only because the unit no longer exists.
fn scope_already_gone(stderr: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr);
    stderr.contains("not loaded") || stderr.contains("NoSuchUnit") || stderr.contains("not found")
}

/// How many processes are still in a VM's transient scope, or `None` when the
/// scope is not loaded or this host has no systemd scopes.
pub fn scope_process_count(machine_id: &str) -> Option<usize> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = machine_id;
        None
    }
    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("systemctl");
        cmd.args(["show", "-P", "ControlGroup", &scope_name(machine_id)]);
        let out = busctl_bounded(cmd, BUSCTL_TIMEOUT).ok()?;
        let cgroup = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || cgroup.is_empty() {
            return None;
        }
        let procs = std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.procs")).ok()?;
        // An exited process its parent has not reaped yet is still listed;
        // it holds nothing and needs no kill.
        let live = |pid: &str| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    let state = stat
                        .rsplit_once(')')?
                        .1
                        .split_whitespace()
                        .next()?
                        .to_string();
                    Some(state != "Z" && state != "X")
                })
                .unwrap_or(false)
        };
        Some(
            procs
                .lines()
                .map(str::trim)
                .filter(|pid| !pid.is_empty() && live(pid))
                .count(),
        )
    }
}

/// Force-kill a VM's transient scope: SIGKILL every process in its cgroup.
///
/// This is the AUTHORITATIVE teardown when the pid-based delete can't confirm
/// death — no recorded pid, or a process that outlived SIGKILL-by-pid. The scope
/// owns every process the VM spawned regardless of the pid we happened to record,
/// so killing the cgroup is what stops a stuck/crash-looping VM that would
/// otherwise become an un-deletable orphan (control marks it deleted, the node
/// keeps running it). Returns `Ok(true)` on a successful kill OR a missing scope
/// (already gone == teardown done). Non-Linux / no-busctl hosts return `Ok(false)`
/// — nothing scope-based to stop; the caller falls back to its pid path.
pub fn kill_scope(machine_id: &str) -> Result<bool> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = machine_id;
        Ok(false)
    }
    #[cfg(target_os = "linux")]
    {
        let Some(busctl) = busctl_path() else {
            return Ok(false);
        };
        let name = scope_name(machine_id);
        // KillUnit(name: s, who: s, signal: i): SIGKILL (9) every process in the
        // scope ("all"). SIGKILL is uncatchable, so a wedged VM dies immediately;
        // the emptied scope then self-GCs. `ssi` is the busctl arg signature.
        let mut cmd = Command::new(&busctl);
        cmd.args([
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "KillUnit",
            "ssi",
            &name,
            "all",
            "9",
        ]);
        let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
        if out.status.success() {
            tracing::info!(scope = %name, "SIGKILLed VM transient scope (forced teardown)");
            return Ok(true);
        }
        // A scope that already exited is not loaded — teardown is effectively done.
        if scope_already_gone(&out.stderr) {
            tracing::debug!(scope = %name, "scope already gone on kill");
            return Ok(true);
        }
        Err(Error::agent(
            "vm scope",
            format!(
                "KillUnit {name} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_property_count_matches_every_optional_cap_combination() {
        for mask in 0..16 {
            let caps = ScopeCaps {
                memory_high_bytes: (mask & 1 != 0).then_some(100),
                memory_max_bytes: (mask & 2 != 0).then_some(200),
                cpu_quota_usec_per_sec: (mask & 4 != 0).then_some(300),
                tasks_max: (mask & 8 != 0).then_some(400),
            };
            let args = scope_start_args("test", 123, &caps);
            let declared: usize = args[8].parse().unwrap();
            let mut cursor = 9;
            for _ in 0..declared {
                cursor += match args[cursor + 1].as_str() {
                    "au" => 3 + args[cursor + 2].parse::<usize>().unwrap(),
                    "s" | "t" => 3,
                    other => panic!("unexpected variant {other}"),
                };
            }
            assert_eq!(
                &args[cursor..],
                &["0"],
                "mask {mask}: malformed auxiliary array"
            );
        }
    }

    #[test]
    fn every_vm_scope_runs_in_the_vm_slice() {
        let args = scope_start_args("m", 1, &ScopeCaps::default());
        let at = args.iter().position(|a| a == "Slice").expect("Slice set");
        assert_eq!(&args[at + 1..at + 3], &["s", VM_SLICE]);
    }

    #[test]
    fn big_hosts_reserve_cpus_and_small_ones_do_not() {
        assert_eq!(host_reserved_cpus(192, None), 3);
        assert_eq!(host_reserved_cpus(96, None), 1);
        assert_eq!(host_reserved_cpus(32, None), 1);
        assert_eq!(host_reserved_cpus(16, None), 0);
        assert_eq!(host_reserved_cpus(8, None), 0);
        // An explicit count wins, 0 turns it off, junk falls back to the default.
        assert_eq!(host_reserved_cpus(192, Some("8")), 8);
        assert_eq!(host_reserved_cpus(192, Some("0")), 0);
        assert_eq!(host_reserved_cpus(8, Some("2")), 2);
        assert_eq!(host_reserved_cpus(192, Some("lots")), 3);
        // VMs always keep at least one CPU.
        assert_eq!(host_reserved_cpus(4, Some("9")), 3);
        assert_eq!(host_reserved_cpus(1, Some("1")), 0);
    }

    #[test]
    fn cpu_lists_parse_like_the_kernel_prints_them() {
        assert_eq!(parse_cpu_list("0-3\n"), Some(vec![0, 1, 2, 3]));
        assert_eq!(parse_cpu_list("0,2,4-5"), Some(vec![0, 2, 4, 5]));
        assert_eq!(parse_cpu_list("7"), Some(vec![7]));
        assert_eq!(parse_cpu_list("3-1"), None);
        assert_eq!(parse_cpu_list("a-b"), None);
    }

    #[test]
    fn the_vm_slice_mask_leaves_out_the_lowest_cpus() {
        let online: Vec<usize> = (0..16).collect();
        // CPUs 0-2 reserved: byte 0 keeps bits 3-7, byte 1 all of 8-15.
        assert_eq!(vm_slice_cpu_mask(&online, 3), vec![0b1111_1000, 0xff]);
        assert!(vm_slice_cpu_mask(&online, 0).is_empty());
        // Gaps in the online list are honored: reserve the two lowest present.
        assert_eq!(vm_slice_cpu_mask(&[0, 2, 9, 10], 2), vec![0, 0b0000_0110]);
    }

    #[test]
    fn slice_cpus_args_encode_the_mask_as_a_byte_array() {
        let args = slice_cpus_args(&[0b1111_1000, 0xff]);
        assert_eq!(
            &args[4..],
            &[
                "SetUnitProperties",
                "sba(sv)",
                VM_SLICE,
                "true",
                "1",
                "AllowedCPUs",
                "ay",
                "2",
                "248",
                "255"
            ]
        );
        // An empty mask clears any earlier restriction.
        let cleared = slice_cpus_args(&[]);
        assert_eq!(&cleared[cleared.len() - 2..], &["ay", "0"]);
    }

    #[test]
    fn big_hosts_reserve_six_percent_and_small_ones_eight_gib_at_most_a_quarter() {
        // 755 GiB worker: 6% = 46387 MiB (~45 GiB).
        assert_eq!(host_reserved_memory_mib(755 * 1024, None), 46387);
        // 1511 GiB worker: ~90.7 GiB.
        assert_eq!(host_reserved_memory_mib(1511 * 1024, None), 92835);
        // Mid-size hosts get the 8 GiB floor.
        assert_eq!(host_reserved_memory_mib(64 * 1024, None), 8192);
        // Small hosts never give up more than a quarter.
        assert_eq!(host_reserved_memory_mib(16 * 1024, None), 4096);
        // An explicit size wins, 0 turns it off, junk falls back to the default.
        assert_eq!(host_reserved_memory_mib(755 * 1024, Some("65536")), 65536);
        assert_eq!(host_reserved_memory_mib(755 * 1024, Some("0")), 0);
        assert_eq!(host_reserved_memory_mib(64 * 1024, Some("lots")), 8192);
        // VMs always keep at least 1 GiB.
        assert_eq!(host_reserved_memory_mib(4096, Some("9999")), 3072);
        assert_eq!(host_reserved_memory_mib(512, Some("1")), 0);
    }

    #[test]
    fn the_vm_slice_memory_cap_is_host_minus_reserve_and_never_throttles() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let limits = vm_slice_memory_limits(755 * GIB, 45 * GIB, Some(100 * GIB));
        assert_eq!(limits.max_bytes, 710 * GIB);
        // MemoryHigh is infinity, always written, so v1.34.1's finite one
        // (702 GiB on a 755 GiB host) is cleared on upgrade.
        assert_eq!(limits.high_bytes, MEMORY_LIMIT_INFINITY);
        assert!(!limits.raised_to_current);
        let small = vm_slice_memory_limits(16 * GIB, 4 * GIB, None);
        assert_eq!(
            (small.high_bytes, small.max_bytes),
            (MEMORY_LIMIT_INFINITY, 12 * GIB)
        );
        // No reserve clears any earlier cap.
        let off = vm_slice_memory_limits(755 * GIB, 0, None);
        assert_eq!(
            (off.high_bytes, off.max_bytes),
            (MEMORY_LIMIT_INFINITY, MEMORY_LIMIT_INFINITY)
        );
    }

    #[test]
    fn a_slice_already_near_the_cap_is_not_squeezed_on_serve_restart() {
        const GIB: u64 = 1024 * 1024 * 1024;
        // 700 GiB + the 8 GiB gap still fits under 710: the real cap applies.
        let fits = vm_slice_memory_limits(755 * GIB, 45 * GIB, Some(700 * GIB));
        assert!(!fits.raised_to_current);
        assert_eq!(fits.max_bytes, 710 * GIB);
        let near = vm_slice_memory_limits(755 * GIB, 45 * GIB, Some(705 * GIB));
        assert!(near.raised_to_current);
        assert_eq!(near.max_bytes, 713 * GIB);
        assert_eq!(near.high_bytes, MEMORY_LIMIT_INFINITY);
        let over = vm_slice_memory_limits(755 * GIB, 45 * GIB, Some(740 * GIB));
        assert_eq!(over.max_bytes, 748 * GIB);
    }

    #[test]
    fn slice_memory_args_clear_memory_high_with_infinity() {
        let limits = vm_slice_memory_limits(64 << 30, 8 << 30, None);
        let args = slice_memory_args(&limits);
        let at = args.iter().position(|a| a == "MemoryHigh").unwrap();
        assert_eq!(&args[at + 1..at + 3], &["t", &u64::MAX.to_string()]);
    }

    #[test]
    fn slice_memory_args_set_high_and_max_on_the_vm_slice() {
        let args = slice_memory_args(&VmSliceMemoryLimits {
            high_bytes: 100,
            max_bytes: 200,
            raised_to_current: false,
        });
        assert_eq!(
            &args[4..],
            &[
                "SetUnitProperties",
                "sba(sv)",
                VM_SLICE,
                "true",
                "2",
                "MemoryHigh",
                "t",
                "100",
                "MemoryMax",
                "t",
                "200"
            ]
        );
    }

    #[test]
    fn mem_total_parses_from_meminfo() {
        assert_eq!(
            parse_mem_total_bytes("MemTotal:       16384000 kB\nMemFree: 1 kB\n"),
            Some(16384000 * 1024)
        );
        assert_eq!(parse_mem_total_bytes("MemFree: 1 kB\n"), None);
    }

    // A wedged busctl (systemd stuck on a dying cgroup) must not pin the thread:
    // the call is bounded and returns promptly, well under the hang it replaces.
    #[cfg(unix)]
    #[test]
    fn busctl_bounded_kills_a_hung_call() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30"); // stand-in for a busctl call that never returns
        let start = Instant::now();
        let out = busctl_bounded(cmd, Duration::from_millis(150));
        let elapsed = start.elapsed();
        assert!(
            out.is_err(),
            "a call exceeding the bound must error, not hang"
        );
        assert!(
            out.unwrap_err().to_string().contains("timed out"),
            "the error must identify a timeout"
        );
        // Freed in ~the bound, not the child's 30s runtime — a generous ceiling.
        assert!(
            elapsed < Duration::from_secs(2),
            "bounded call took {elapsed:?}; should return near the 150ms bound"
        );
    }

    // A fast call returns its real output and status, unaffected by the bound.
    #[cfg(unix)]
    #[test]
    fn busctl_bounded_returns_fast_call_output() {
        let mut cmd = Command::new("printf");
        cmd.arg("ok");
        let out = busctl_bounded(cmd, Duration::from_secs(5)).expect("fast call");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ok");
    }

    #[test]
    fn scope_start_collision_is_recognized() {
        assert!(scope_start_collided(
            b"Call failed: Unit smolvm-vm-x.scope was already loaded or has a fragment file."
        ));
        assert!(!scope_start_collided(b"Call failed: Access denied"));
    }

    #[test]
    fn scope_stop_targets_only_the_named_unit() {
        assert_eq!(
            scope_stop_args("smolvm-vm-m.scope")[4..],
            ["StopUnit", "ss", "smolvm-vm-m.scope", "replace"]
        );
        assert!(scope_already_gone(
            b"Call failed: Unit smolvm-vm-m.scope not loaded."
        ));
        assert!(!scope_already_gone(b"Call failed: Access denied"));
    }

    /// A process that exits before systemd moves it leaves an empty scope
    /// that stays active; stopping it is what removes it.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root on a systemd host"]
    fn stop_scope_removes_a_scope_whose_process_exited_before_adoption() {
        let active = |id: &str| {
            Command::new("systemctl")
                .args(["is-active", "--quiet", &scope_name(id)])
                .status()
                .is_ok_and(|status| status.success())
        };
        let id = format!("scope-test-{}", std::process::id());
        let mut child = Command::new("true").spawn().unwrap();
        // Exited but not yet reaped, like a VM process refused at boot.
        std::thread::sleep(Duration::from_millis(200));
        adopt_into_scope(&id, child.id() as i32, &ScopeCaps::default()).unwrap();
        child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert!(active(&id), "the empty scope should still be active");
        stop_scope(&id).unwrap();
        assert!(!active(&id));
        stop_scope(&id).unwrap();
    }

    #[test]
    fn scope_name_sanitizes_and_suffixes() {
        assert_eq!(
            scope_name("machine-abc123"),
            "smolvm-vm-machine-abc123.scope"
        );
        // Illegal chars (slash, space) collapse to underscore.
        assert_eq!(scope_name("a/b c"), "smolvm-vm-a_b_c.scope");
        // Allowed punctuation is preserved.
        assert_eq!(scope_name("m_1.2:3"), "smolvm-vm-m_1.2:3.scope");
    }

    #[test]
    fn scope_name_is_bounded() {
        let long = "x".repeat(500);
        let n = scope_name(&long);
        assert!(n.starts_with("smolvm-vm-"));
        assert!(n.ends_with(".scope"));
        // sanitized body clamped to 200 chars + fixed prefix/suffix.
        assert!(n.len() <= "smolvm-vm-".len() + 200 + ".scope".len());
    }
}
