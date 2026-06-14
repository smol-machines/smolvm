//! Place a VM process in its own **systemd transient scope** so it survives a
//! `serve` restart.
//!
//! Today a VM is a child process inside `smolvm-node.service`'s delegated cgroup.
//! On `systemctl restart`, a surviving VM left in that cgroup makes systemd fail
//! to recreate the unit (`status=219/CGROUP`) → serve crash-loops. Adopting the
//! VM into its own `smolvm-vm-<id>.scope` (a sibling unit owned by PID1) moves it
//! out of the service cgroup, so serve can restart and reconnect to the still-
//! running VM. See `docs/lossless-serve-restart.md`.
//!
//! Implemented by shelling out to `busctl` (ships with systemd — no D-Bus crate
//! dependency, and absent exactly where scopes wouldn't work anyway). The caller
//! forks the VM normally (retaining stdio/fd/process-group control), then calls
//! [`adopt_into_scope`] on the resulting PID. systemd's `StartTransientUnit`
//! with a `PIDs=` property moves the process into the scope's cgroup and applies
//! the resource caps as unit properties. Scopes auto-remove when their last
//! process exits, so machine stop/delete needs no extra teardown.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// Resource caps applied to the VM's scope (as systemd unit properties).
///
/// Mirrors the per-VM cgroup limits set by [`crate::process::place_in_cgroup`]:
/// `MemoryMax` ↔ `memory.max`, `CPUQuotaPerSecUSec` ↔ `cpu.max`, `TasksMax` ↔
/// `pids.max`.
#[derive(Debug, Default, Clone)]
pub struct ScopeCaps {
    /// Hard memory ceiling in bytes (`MemoryMax`). `None` = uncapped.
    pub memory_max_bytes: Option<u64>,
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
    // SAFETY: geteuid() is always-safe (no args, no global state mutation).
    let is_root = unsafe { libc::geteuid() } == 0;
    is_root && Path::new("/run/systemd/system").is_dir() && busctl_path().is_some()
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

    let out = Command::new(&busctl)
        .args(&args)
        .output()
        .map_err(|e| Error::agent("vm scope", format!("busctl spawn failed: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::agent(
            "vm scope",
            format!("StartTransientUnit {name} failed: {}", stderr.trim()),
        ));
    }
    tracing::info!(scope = %name, pid, "adopted VM into systemd transient scope");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
