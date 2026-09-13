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
    let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
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
    // mode "fail": error if the unit already exists (a stale same-name scope must
    // have been GC'd first — it would have been, when its VM exited).
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
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("not loaded")
            || stderr.contains("NoSuchUnit")
            || stderr.contains("not found")
        {
            tracing::debug!(scope = %name, "scope already gone on kill");
            return Ok(true);
        }
        Err(Error::agent(
            "vm scope",
            format!("KillUnit {name} failed: {}", stderr.trim()),
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
