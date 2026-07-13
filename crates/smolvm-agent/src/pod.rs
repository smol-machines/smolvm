//! Kubernetes pod-container support (containerd shim v2 datapath).
//!
//! The host-side shim (`containerd-shim-smolvm-v2`) drives ordinary OCI
//! containers inside the sandbox VM through six requests: `PodCreate`
//! (validate + stash), `PodStart` (run with streaming I/O on the request
//! connection), `PodExec` (stash an exec process), `PodSignal`, `PodPids`
//! and `PodDelete`. See `docs/kubernetes-runtime.md` for the architecture.
//!
//! Unlike the existing `Run` path, the container's rootfs is NOT an image the
//! agent pulled itself: containerd unpacks the snapshotter mount on the host
//! and the shim bind-mounts it under the sandbox's single shared virtiofs dir
//! (shares are fixed at VM boot; pod containers are created afterwards). The
//! guest therefore resolves each container's rootfs as
//! `<VIRTIOFS_MOUNT_ROOT>/<POD_SHARE_TAG>/<rootfs_rel>`.
//!
//! This module follows the crate's existing conventions: plain std sync
//! primitives + threads (no async), crun via [`crate::crun::CrunCommand`],
//! and the same `Started` → `Stdout`/`Stderr` → `Exited` streaming contract
//! as interactive `Run` (the I/O pumps `run_interactive_loop` /
//! `run_interactive_loop_pty` are reused directly).

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use smolvm_protocol::{error_codes, AgentResponse};
use tracing::{info, warn};

use crate::crun;
use crate::paths;

/// The fixed virtiofs share tag the shim uses for the sandbox's single shared
/// directory. Every pod container's rootfs lives underneath it.
pub const POD_SHARE_TAG: &str = "podshare";

/// Guest directory holding per-pod-container state (crun bundle dirs).
const POD_STATE_DIR: &str = "/storage/containers/pods";

// ============================================================================
// Registry
// ============================================================================

/// Lifecycle of a pod container inside the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PodState {
    /// Stashed by `PodCreate`; nothing running.
    Created,
    /// Init process launched by `PodStart`.
    Running,
    /// Init process exited (exit status already streamed).
    Exited,
}

/// Process settings extracted from an OCI Process JSON object (the container
/// init's `process` from the spec, or an exec's `process_json`).
#[derive(Debug, Clone)]
struct StashedProcess {
    /// argv (OCI `process.args`).
    args: Vec<String>,
    /// Environment as (key, value) pairs (from OCI `process.env` "K=V" list).
    env: Vec<(String, String)>,
    /// Working directory (OCI `process.cwd`), if given.
    cwd: Option<String>,
    /// "uid[:gid]" string derived from OCI `process.user`, resolved against
    /// the rootfs at start time via `oci::resolve_process_identity`. When only a
    /// username is given (CRI `RunAsUserName`), that name is used and resolved
    /// against the rootfs /etc/passwd.
    user: Option<String>,
    /// Supplemental group IDs (OCI `process.user.additionalGids`, from the CRI
    /// `SupplementalGroups`). Applied to the container process.
    additional_gids: Vec<u32>,
}

/// A CRI mount (volume, or a generated file like resolv.conf/hosts/hostname) the
/// shim materialized into the pod share; the agent copies it into the container's
/// writable overlay at `destination` before start. `source` is the guest path of
/// the shim's copy under the virtiofs pod share.
#[derive(Debug, Clone)]
struct PodMount {
    /// Guest path of the shim's copy (under `<VIRTIOFS>/podshare/<id>/mounts/N`).
    source: String,
    /// Absolute container path to place it at.
    destination: String,
}

/// An exec process registered by `PodExec`, started by `PodStart { exec_id }`.
#[derive(Debug, Clone)]
struct ExecEntry {
    process: StashedProcess,
    /// Raw OCI Process JSON from containerd. Used to run `crun exec --process`
    /// (which honors supplemental groups) when the process has additionalGids —
    /// the flag-based path can only set uid:gid.
    process_json: String,
    /// Allocate a PTY for the exec process.
    tty: bool,
    /// PID of the `crun exec` child while the exec is running. crun cannot
    /// target exec processes by id, so `PodSignal { exec_id }` kills this pid
    /// (or its first child — the actual exec'd process — when visible in
    /// /proc) directly with kill(2).
    pid: Option<u32>,
}

/// Everything the agent knows about one pod container.
#[derive(Debug, Clone)]
struct PodContainer {
    /// Resolved guest rootfs path under the shared virtiofs mount.
    rootfs: PathBuf,
    /// Init process settings stashed at `PodCreate`.
    process: StashedProcess,
    /// Mount the rootfs read-only (OCI `root.readonly`).
    readonly_rootfs: bool,
    /// Container UTS hostname (OCI `hostname`, from the pod sandbox).
    hostname: Option<String>,
    /// CRI mounts (volumes + generated /etc files) to materialize into the
    /// writable overlay before start.
    mounts: Vec<PodMount>,
    /// OCI `process.noNewPrivileges` (CRI allowPrivilegeEscalation=false). Only
    /// set by containers that request it, so this is false for most.
    no_new_privileges: bool,
    /// The raw host OCI spec. Its securityContext fields are grafted onto the
    /// guest bundle so the container runs with exactly the capabilities,
    /// seccomp profile, rlimits, masked/readonly paths, and sysctls Kubernetes
    /// requested — not smolvm's full-capability VM default (which critest
    /// rejects). Stored whole so new fields don't need new plumbing.
    host_spec: serde_json::Value,
    /// Allocate a PTY for the init process.
    tty: bool,
    state: PodState,
    /// Container init PID (guest view), cached lazily from `crun state`.
    init_pid: Option<u32>,
    /// Registered exec processes by exec_id.
    execs: HashMap<String, ExecEntry>,
}

/// Global id → container registry. A plain Mutex-guarded map: pod request
/// rates are tiny (a handful of containers per sandbox) and every handler
/// takes the lock only to read/update bookkeeping — never across a spawned
/// process or a streaming loop.
fn registry() -> &'static Mutex<HashMap<String, PodContainer>> {
    static PODS: OnceLock<Mutex<HashMap<String, PodContainer>>> = OnceLock::new();
    PODS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Lock the registry, recovering from a poisoned lock (a panic in another
/// connection thread must not wedge every future pod request).
fn lock_registry() -> std::sync::MutexGuard<'static, HashMap<String, PodContainer>> {
    registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ============================================================================
// Validation / parsing helpers
// ============================================================================

/// Validate a container or exec id: non-empty, bounded, and made of the
/// characters containerd task ids use. The id becomes a path component of the
/// bundle dir and a crun positional, so this also keeps path traversal and
/// option injection out.
fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("id must not be empty".into());
    }
    if id.len() > 200 {
        return Err("id too long (max 200 chars)".into());
    }
    if id == "." || id == ".." || id.starts_with('-') {
        return Err(format!("invalid id: {id}"));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(format!(
            "invalid id '{id}': only [A-Za-z0-9_.-] characters allowed"
        ));
    }
    Ok(())
}

/// Resolve a container rootfs path relative to the sandbox's shared virtiofs
/// mount: `<VIRTIOFS_MOUNT_ROOT>/<POD_SHARE_TAG>/<rootfs_rel>`. Rejects
/// absolute paths and any non-plain component (`..`, etc.) so the shim can't
/// point a bundle outside the shared dir.
fn resolve_pod_rootfs(rootfs_rel: &str) -> Result<PathBuf, String> {
    if rootfs_rel.is_empty() {
        return Err("rootfs_rel must not be empty".into());
    }
    let rel = Path::new(rootfs_rel);
    if rel.is_absolute() {
        return Err("rootfs_rel must be relative to the pod share".into());
    }
    for component in rel.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(format!(
                    "rootfs_rel '{rootfs_rel}' must be a plain relative path (no '..' or '.')"
                ))
            }
        }
    }
    Ok(Path::new(paths::VIRTIOFS_MOUNT_ROOT)
        .join(POD_SHARE_TAG)
        .join(rel))
}

/// Extract the fields the agent grafts onto its own guest bundle from an OCI
/// Process JSON object: args/env/cwd/user. Host-specific fields
/// (capabilities, rlimits, apparmor, ...) are intentionally ignored — the
/// guest bundle template supplies VM-grade defaults (the microVM is the
/// security boundary).
fn parse_oci_process(process: &serde_json::Value) -> Result<StashedProcess, String> {
    let args: Vec<String> = process
        .get("args")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if args.is_empty() {
        return Err("process.args missing or empty".into());
    }

    let env: Vec<(String, String)> = process
        .get("env")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|entry| entry.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let cwd = process
        .get("cwd")
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    // OCI Process.user carries numeric uid/gid, or a username (CRI
    // RunAsUserName). Render as "uid:gid" (numeric) or the username for
    // oci::resolve_process_identity, which accepts either.
    let user = process.get("user").and_then(|u| {
        if let Some(uid) = u.get("uid").and_then(|v| v.as_u64()) {
            Some(match u.get("gid").and_then(|v| v.as_u64()) {
                Some(gid) => format!("{uid}:{gid}"),
                None => uid.to_string(),
            })
        } else {
            u.get("username")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
        }
    });

    // Supplemental groups (CRI SupplementalGroups → OCI additionalGids).
    let additional_gids: Vec<u32> = process
        .get("user")
        .and_then(|u| u.get("additionalGids"))
        .and_then(|g| g.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u32))
                .collect()
        })
        .unwrap_or_default();

    Ok(StashedProcess {
        args,
        env,
        cwd,
        user,
        additional_gids,
    })
}

/// Extract the CRI mounts the shim materialized into the pod share: those whose
/// `source` was rewritten to a path under the guest pod-share mount. Everything
/// else (proc/sysfs/tmpfs/... provided by the default OCI spec) is ignored.
fn parse_pod_mounts(spec: &serde_json::Value) -> Vec<PodMount> {
    let prefix = format!("{}/{}/", paths::VIRTIOFS_MOUNT_ROOT, POD_SHARE_TAG);
    spec.get("mounts")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let source = m.get("source").and_then(|s| s.as_str())?;
                    if !source.starts_with(&prefix) {
                        return None;
                    }
                    let destination = m.get("destination").and_then(|d| d.as_str())?;
                    if destination.is_empty() {
                        return None;
                    }
                    Some(PodMount {
                        source: source.to_string(),
                        destination: destination.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Per-container state directory (holds the crun bundle).
fn pod_dir(id: &str) -> PathBuf {
    PathBuf::from(POD_STATE_DIR).join(id)
}

// ============================================================================
// PID helpers
// ============================================================================

/// Container init PID from `crun state <id>` (guest view). None if the
/// container isn't registered/running or the state JSON is unusable.
fn crun_state_pid(id: &str) -> Option<u32> {
    let output = crun::CrunCommand::state(id)
        .capture_output()
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let pid = v.get("pid")?.as_i64()?;
    u32::try_from(pid).ok().filter(|p| *p > 0)
}

/// Block until `crun run` has registered the container (its state DB entry
/// exists, so `crun exec`/`state`/`kill` can find it) or the container exits or
/// a short deadline elapses. Returns the init pid if the container came up.
///
/// `crun run` forks and returns before the container is registered; without this
/// wait a client that execs immediately after StartContainer (critest does) hits
/// "container not found". crun writes state before starting the container's
/// process, so this is normally a few ms; the deadline caps a container that
/// exits instantly (nothing to wait for) so Start still returns promptly.
#[cfg(target_os = "linux")]
fn wait_for_crun_running(id: &str, child: &mut std::process::Child) -> Option<u32> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(pid) = crun_state_pid(id) {
            return Some(pid);
        }
        // The container already exited (instant-exit command) — crun tore down
        // its state, so there is nothing left to wait for.
        if matches!(child.try_wait(), Ok(Some(_))) {
            return None;
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Non-Linux builds don't run crun; report no pid without polling.
#[cfg(not(target_os = "linux"))]
fn wait_for_crun_running(_id: &str, _child: &mut std::process::Child) -> Option<u32> {
    None
}

/// Snapshot of (pid, ppid) pairs from /proc. Empty when /proc is unreadable
/// (non-Linux test builds).
fn proc_parent_pairs() -> Vec<(u32, u32)> {
    let mut pairs = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return pairs;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // /proc/<pid>/stat: "pid (comm) state ppid ..." — comm may itself
        // contain spaces and parens, so split at the LAST ')'.
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let _state = fields.next();
        if let Some(ppid) = fields.next().and_then(|p| p.parse::<u32>().ok()) {
            pairs.push((pid, ppid));
        }
    }
    pairs
}

/// `root` plus all its descendants, from a single /proc snapshot. Used for
/// `PodPids` — with the crun cgroup manager disabled there is no per-container
/// cgroup.procs file to read, so the process tree under init IS the container.
fn descendant_pids(root: u32) -> Vec<u32> {
    let pairs = proc_parent_pairs();
    let mut pids = vec![root];
    let mut i = 0;
    while i < pids.len() {
        let parent = pids[i];
        for (pid, ppid) in &pairs {
            if *ppid == parent && !pids.contains(pid) {
                pids.push(*pid);
            }
        }
        i += 1;
    }
    pids
}

/// First child of `parent` visible in /proc. Used to refine a tracked
/// `crun exec` monitor pid to the actual exec'd process.
fn first_child_pid(parent: u32) -> Option<u32> {
    proc_parent_pairs()
        .into_iter()
        .find(|(_, ppid)| *ppid == parent)
        .map(|(pid, _)| pid)
}

/// kill(2) wrapper. Returns true if the signal was delivered.
fn kill_pid(pid: u32, signal: u32) -> bool {
    // SAFETY: plain kill(2); no memory involved.
    unsafe { libc::kill(pid as libc::pid_t, signal as libc::c_int) == 0 }
}

// ============================================================================
// PodCreate / PodExec — stash only
// ============================================================================

/// `PodCreate`: validate the request and stash the container's launch
/// settings. Nothing runs until `PodStart`; no dirs are created either, so a
/// failed create leaves zero guest state.
pub fn handle_pod_create(id: &str, rootfs_rel: &str, spec_json: &str, tty: bool) -> AgentResponse {
    if let Err(e) = validate_id(id) {
        return AgentResponse::error(e, error_codes::INVALID_REQUEST);
    }
    let rootfs = match resolve_pod_rootfs(rootfs_rel) {
        Ok(p) => p,
        Err(e) => return AgentResponse::error(e, error_codes::INVALID_REQUEST),
    };
    let spec: serde_json::Value = match serde_json::from_str(spec_json) {
        Ok(v) => v,
        Err(e) => {
            return AgentResponse::error(
                format!("invalid spec_json: {e}"),
                error_codes::INVALID_REQUEST,
            )
        }
    };
    let Some(process_value) = spec.get("process") else {
        return AgentResponse::error("spec_json has no process", error_codes::INVALID_REQUEST);
    };
    let process = match parse_oci_process(process_value) {
        Ok(p) => p,
        Err(e) => return AgentResponse::error(e, error_codes::INVALID_REQUEST),
    };
    let readonly_rootfs = spec
        .get("root")
        .and_then(|r| r.get("readonly"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let hostname = spec
        .get("hostname")
        .and_then(|h| h.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    let mounts = parse_pod_mounts(&spec);
    let no_new_privileges = spec
        .pointer("/process/noNewPrivileges")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut reg = lock_registry();
    if reg.contains_key(id) {
        return AgentResponse::error(
            format!("pod container '{id}' already exists"),
            error_codes::INVALID_REQUEST,
        );
    }
    info!(id = %id, rootfs = %rootfs.display(), tty = tty, mounts = mounts.len(), "pod container created (stashed)");
    reg.insert(
        id.to_string(),
        PodContainer {
            rootfs,
            process,
            readonly_rootfs,
            hostname,
            mounts,
            no_new_privileges,
            host_spec: spec,
            tty,
            state: PodState::Created,
            init_pid: None,
            execs: HashMap::new(),
        },
    );
    AgentResponse::ok(None)
}

/// `PodExec`: stash an exec process spec for a known container. Started later
/// by `PodStart { exec_id }`.
pub fn handle_pod_exec(id: &str, exec_id: &str, process_json: &str, tty: bool) -> AgentResponse {
    if let Err(e) = validate_id(exec_id) {
        return AgentResponse::error(e, error_codes::INVALID_REQUEST);
    }
    let process_value: serde_json::Value = match serde_json::from_str(process_json) {
        Ok(v) => v,
        Err(e) => {
            return AgentResponse::error(
                format!("invalid process_json: {e}"),
                error_codes::INVALID_REQUEST,
            )
        }
    };
    let process = match parse_oci_process(&process_value) {
        Ok(p) => p,
        Err(e) => return AgentResponse::error(e, error_codes::INVALID_REQUEST),
    };

    let mut reg = lock_registry();
    let Some(pod) = reg.get_mut(id) else {
        return AgentResponse::error(
            format!("unknown pod container: {id}"),
            error_codes::NOT_FOUND,
        );
    };
    if pod.execs.contains_key(exec_id) {
        return AgentResponse::error(
            format!("exec '{exec_id}' already registered for container '{id}'"),
            error_codes::INVALID_REQUEST,
        );
    }
    info!(id = %id, exec_id = %exec_id, tty = tty, "pod exec process registered");
    pod.execs.insert(
        exec_id.to_string(),
        ExecEntry {
            process,
            process_json: process_json.to_string(),
            tty,
            pid: None,
        },
    );
    AgentResponse::ok(None)
}

// ============================================================================
// PodSignal / PodPids / PodDelete
// ============================================================================

/// `PodSignal`: signal the container's init (optionally the whole container
/// with `all`) or one exec process.
pub fn handle_pod_signal(id: &str, exec_id: Option<&str>, signal: u32, all: bool) -> AgentResponse {
    // Snapshot what we need under the lock; the actual kills happen after
    // release (never hold the registry across a subprocess).
    let (state, init_pid, exec_pid) = {
        let reg = lock_registry();
        let Some(pod) = reg.get(id) else {
            return AgentResponse::error(
                format!("unknown pod container: {id}"),
                error_codes::NOT_FOUND,
            );
        };
        let exec_pid = match exec_id {
            Some(e) => match pod.execs.get(e) {
                Some(entry) => Some(entry.pid),
                None => {
                    return AgentResponse::error(
                        format!("unknown exec '{e}' for container '{id}'"),
                        error_codes::NOT_FOUND,
                    )
                }
            },
            None => None,
        };
        (pod.state, pod.init_pid, exec_pid)
    };

    // Exec case: crun can't target exec processes by id, so kill(2) the
    // tracked pid directly — refined to its first child (the actual exec'd
    // process) when visible, since the tracked pid is the crun monitor.
    if let Some(tracked) = exec_pid {
        let Some(tracked) = tracked else {
            // Registered but never started (or already reaped): nothing to
            // signal; treat as success like signalling a dead process group.
            return AgentResponse::ok(None);
        };
        let target = first_child_pid(tracked).unwrap_or(tracked);
        if !kill_pid(target, signal) {
            warn!(id = %id, exec_id = ?exec_id, pid = target, signal = signal, "exec kill(2) failed (process already gone?)");
        }
        return AgentResponse::ok(None);
    }

    // Container case. Signalling a not-running container is a no-op success —
    // stop paths are retried and must be idempotent.
    if state != PodState::Running {
        return AgentResponse::ok(None);
    }
    let cmd = if all {
        crun::CrunCommand::kill_all(id, &signal.to_string())
    } else {
        crun::CrunCommand::kill(id, &signal.to_string())
    };
    match cmd.capture_output().output() {
        Ok(output) if output.status.success() => AgentResponse::ok(None),
        // crun refused (e.g. `--all` without a cgroup, or state raced away):
        // fall back to kill(2) on the tracked process tree.
        other => {
            if let Ok(output) = &other {
                warn!(id = %id, stderr = %String::from_utf8_lossy(&output.stderr).trim(), "crun kill failed; falling back to kill(2)");
            }
            let init = crun_state_pid(id).or(init_pid);
            match init {
                Some(init) => {
                    let targets = if all {
                        descendant_pids(init)
                    } else {
                        vec![init]
                    };
                    for pid in targets {
                        let _ = kill_pid(pid, signal);
                    }
                    AgentResponse::ok(None)
                }
                None => AgentResponse::ok(None), // already gone — idempotent
            }
        }
    }
}

/// `PodPids`: list the container's PIDs (guest view): init plus descendants
/// from a /proc snapshot. With the crun cgroup manager disabled there is no
/// per-container cgroup.procs, so the process tree under init is the source
/// of truth; falls back to just the tracked init pid.
pub fn handle_pod_pids(id: &str) -> AgentResponse {
    let cached = {
        let reg = lock_registry();
        let Some(pod) = reg.get(id) else {
            return AgentResponse::error(
                format!("unknown pod container: {id}"),
                error_codes::NOT_FOUND,
            );
        };
        pod.init_pid
    };

    // Prefer the live pid from crun state (survives agent bookkeeping races),
    // then the cached one.
    let init = crun_state_pid(id).or(cached);
    let Some(init) = init else {
        return AgentResponse::Pids { pids: vec![] };
    };

    // Cache for later PodSignal fallbacks.
    if cached != Some(init) {
        if let Some(pod) = lock_registry().get_mut(id) {
            pod.init_pid = Some(init);
        }
    }

    let pids = descendant_pids(init);
    AgentResponse::Pids { pids }
}

/// `PodStats`: sample the container's resource usage. crun runs with its cgroup
/// manager disabled (no per-container cgroup), so usage is summed from /proc over
/// the container's process tree. The shim maps this into containerd's cgroups
/// metrics for CRI `ContainerStats`. A stopped/absent container reports zeros
/// (still a valid, decodable sample) rather than an error, so `ListContainerStats`
/// keeps working across a container's lifecycle.
pub fn handle_pod_stats(id: &str) -> AgentResponse {
    let cached = {
        let reg = lock_registry();
        let Some(pod) = reg.get(id) else {
            return AgentResponse::error(
                format!("unknown pod container: {id}"),
                error_codes::NOT_FOUND,
            );
        };
        pod.init_pid
    };

    let Some(init) = crun_state_pid(id).or(cached) else {
        return AgentResponse::Stats {
            cpu_usage_ns: 0,
            memory_bytes: 0,
        };
    };

    let pids = descendant_pids(init);
    let (cpu_ticks, memory_bytes) = read_proc_usage(&pids);
    AgentResponse::Stats {
        cpu_usage_ns: ticks_to_ns(cpu_ticks),
        memory_bytes,
    }
}

/// Sum CPU time (clock ticks: utime+stime) and resident memory (bytes) across
/// `pids` by reading `/proc/<pid>/stat` and `/proc/<pid>/statm`.
#[cfg(target_os = "linux")]
fn read_proc_usage(pids: &[u32]) -> (u64, u64) {
    let mut cpu_ticks: u64 = 0;
    let mut memory_bytes: u64 = 0;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    for &pid in pids {
        // /proc/<pid>/stat: the comm field (2) may contain spaces and ')', so
        // parse the fields after the LAST ')'. utime (field 14) and stime (15)
        // are indices 11 and 12 of that remainder (field 3 = state is index 0).
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some((_, rest)) = stat.rsplit_once(')') {
                let f: Vec<&str> = rest.split_whitespace().collect();
                let utime = f.get(11).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                let stime = f.get(12).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                cpu_ticks = cpu_ticks.saturating_add(utime).saturating_add(stime);
            }
        }
        // /proc/<pid>/statm: field 2 (resident) is in pages.
        if let Ok(statm) = std::fs::read_to_string(format!("/proc/{pid}/statm")) {
            if let Some(res) = statm
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u64>().ok())
            {
                memory_bytes = memory_bytes.saturating_add(res.saturating_mul(page_size));
            }
        }
    }
    (cpu_ticks, memory_bytes)
}

/// Convert clock ticks (from /proc) to nanoseconds using `_SC_CLK_TCK`.
#[cfg(target_os = "linux")]
fn ticks_to_ns(ticks: u64) -> u64 {
    let hz = (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).max(1) as u64;
    ticks.saturating_mul(1_000_000_000) / hz
}

/// Non-Linux builds have no /proc process usage to read.
#[cfg(not(target_os = "linux"))]
fn read_proc_usage(_pids: &[u32]) -> (u64, u64) {
    (0, 0)
}

/// Non-Linux stub matching [`ticks_to_ns`].
#[cfg(not(target_os = "linux"))]
fn ticks_to_ns(ticks: u64) -> u64 {
    ticks
}

/// `PodDelete`: drop an exec registration, or tear down the whole container
/// (crun delete --force best-effort + bundle dir removal + registry entry).
/// Idempotent: deleting something unknown is Ok.
pub fn handle_pod_delete(id: &str, exec_id: Option<&str>) -> AgentResponse {
    if let Some(exec) = exec_id {
        if let Some(pod) = lock_registry().get_mut(id) {
            pod.execs.remove(exec);
        }
        return AgentResponse::ok(None);
    }

    let existed = lock_registry().remove(id).is_some();
    // Best-effort: `crun run` auto-deletes on exit, and the container may
    // never have started; ignore failures.
    let _ = crun::CrunCommand::delete(id, true)
        .discard_output()
        .output();
    // Only touch the bundle dir for ids we actually created (or whose dir
    // exists) — pod_dir(id) is validated-id-safe but stay conservative.
    if validate_id(id).is_ok() {
        let dir = pod_dir(id);
        if dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                warn!(id = %id, error = %e, "failed to remove pod state dir");
            }
        }
    }
    info!(id = %id, existed = existed, "pod container deleted");
    AgentResponse::ok(None)
}

// ============================================================================
// PodStart — streaming (connection-level handler)
// ============================================================================

/// `PodStart`: launch the container's init process (or a registered exec
/// process) and stream its I/O on THIS connection, exactly like interactive
/// `Run`: `Started` → `Stdout`/`Stderr`... → `Exited`, with `Stdin`/`Resize`
/// requests handled by the reused I/O pumps.
#[cfg(target_os = "linux")]
pub fn handle_pod_start(
    stream: &mut impl crate::ReadWrite,
    request: smolvm_protocol::AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let (id, exec_id) = match request {
        smolvm_protocol::AgentRequest::PodStart { id, exec_id } => (id, exec_id),
        _ => {
            crate::send_response(
                stream,
                &AgentResponse::error("expected PodStart request", error_codes::INVALID_REQUEST),
            )?;
            return Ok(());
        }
    };
    match exec_id {
        Some(exec_id) => start_exec_process(stream, &id, &exec_id),
        None => start_init_process(stream, &id),
    }
}

/// Non-Linux stub so `cargo test` on macOS compiles the dispatch.
#[cfg(not(target_os = "linux"))]
pub fn handle_pod_start(
    stream: &mut impl crate::ReadWrite,
    _request: smolvm_protocol::AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::send_response(
        stream,
        &AgentResponse::error(
            "pod containers not supported on this platform",
            error_codes::INTERNAL_ERROR,
        ),
    )?;
    Ok(())
}

/// Write the crun bundle for a pod container: the crate's standard guest spec
/// (same template + injections as `write_oci_bundle` for `Run`), with
/// `root.path` pointed at the shared-virtiofs rootfs instead of an overlay.
#[cfg(target_os = "linux")]
fn write_pod_bundle(
    pod: &PodContainer,
    id: &str,
    bundle: &Path,
    mount_binds: &[(PathBuf, String)],
) -> Result<(), String> {
    let identity = crate::oci::resolve_process_identity(&pod.rootfs, pod.process.user.as_deref())?;
    // unprivileged=false: pods get the VM-grade default capability set — the
    // microVM is the security boundary, same rationale as `Run`.
    let mut spec = crate::oci::OciSpec::new(
        &pod.process.args,
        &pod.process.env,
        pod.process.cwd.as_deref().unwrap_or("/"),
        pod.tty,
        &identity,
        false,
    );
    if pod.tty {
        // Non-zero starting size; the shim follows up with a Resize carrying
        // the real dimensions once the session starts (same as `Run`).
        spec.process.console_size = Some(crate::oci::OciConsoleSize {
            height: 24,
            width: 80,
        });
    }
    // The rootfs is an absolute path under the shared virtiofs mount, not the
    // bundle-relative "rootfs" the overlay paths use.
    spec.root.path = pod.rootfs.to_string_lossy().into_owned();
    spec.root.readonly = pod.readonly_rootfs;

    // Pod UTS hostname and supplemental groups from the CRI config.
    if pod.hostname.is_some() {
        spec.hostname = pod.hostname.clone();
    }
    spec.process.user.additional_gids = pod.process.additional_gids.clone();
    spec.process.no_new_privileges = pod.no_new_privileges;

    // Shared PID namespace (SharePidMode=POD). CRI marks it with a non-empty
    // `path` on the incoming pid namespace (that host path is meaningless in the
    // guest); when set, join the pod's guest-side pause pid namespace instead of
    // creating a fresh one, so PID 1 in the container is the pause and pod
    // containers see each other. An empty path (CONTAINER) keeps its own.
    let pod_pid_shared = matches!(
        pod.host_spec.pointer("/linux/namespaces"),
        Some(serde_json::Value::Array(ns)) if ns.iter().any(|n|
            n.get("type").and_then(|t| t.as_str()) == Some("pid")
                && n.get("path")
                    .and_then(|p| p.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false))
    );
    if pod_pid_shared {
        match ensure_pod_pause_pidns() {
            Ok(pause) => {
                let ns_path = format!("/proc/{pause}/ns/pid");
                for n in spec.linux.namespaces.iter_mut() {
                    if n.ns_type == "pid" {
                        n.path = Some(ns_path.clone());
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "pod pid share: pause namespace unavailable; container keeps its own pid namespace")
            }
        }
    }

    // Give the container its own cgroup namespace so `/sys/fs/cgroup` is rooted
    // at the container's own cgroup. Container-aware runtimes (the JVM, the Go
    // runtime, etc.) size themselves from `/sys/fs/cgroup/{memory.max,cpu.max}`;
    // without the namespace the container sees the limitless cgroup2 root, whose
    // `memory.max` doesn't exist, and mis-sizes to the whole VM. crun mounts
    // cgroup2 for the namespace when it manages the cgroup (cgroupfs).
    if !spec.linux.namespaces.iter().any(|n| n.ns_type == "cgroup") {
        spec.linux.namespaces.push(crate::oci::OciNamespace {
            ns_type: "cgroup".to_string(),
            path: None,
        });
    }

    spec.add_gpu_devices_if_available();

    // CRI mounts (volumes + generated /etc/resolv.conf, /etc/hosts) as bind mounts.
    // Added last so they layer on TOP of the default mounts (e.g. a volume at
    // /tmp/foo mounts over the default tmpfs at /tmp).
    for (source, destination) in mount_binds {
        spec.add_bind_mount(&source.to_string_lossy(), destination, false);
    }

    // Preserve synthetic CRI mounts the shim did NOT rewrite to the pod share:
    // tmpfs (and similar) at custom destinations the default bundle doesn't
    // provide. Bind mounts to host paths are the CRI volumes, already handled
    // above via the pod-share rewrite; the default proc/sys/dev/cgroup mounts
    // are already present.
    if let Some(host_mounts) = pod.host_spec.get("mounts").and_then(|m| m.as_array()) {
        let existing: std::collections::HashSet<String> =
            spec.mounts.iter().map(|m| m.destination.clone()).collect();
        for m in host_mounts {
            let ty = m.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let dest = m.get("destination").and_then(|v| v.as_str()).unwrap_or("");
            if dest.is_empty() || ty == "bind" || ty.is_empty() || existing.contains(dest) {
                continue;
            }
            let options = m
                .get("options")
                .and_then(|o| o.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            spec.mounts.push(crate::oci::OciMount {
                destination: dest.to_string(),
                mount_type: Some(ty.to_string()),
                source: m
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or(ty)
                    .to_string(),
                options,
            });
        }
    }

    // Same injections as Run's bundle build (write_oci_bundle).
    crate::ssh_agent::inject_into_container(&mut spec);
    crate::rosetta::inject_into_container(&mut spec);
    crate::cuda::inject_into_container(&mut spec, &pod.rootfs);

    // Graft the container's securityContext from the host OCI spec so the
    // container runs with exactly what Kubernetes requested. OciSpec models
    // capabilities/rlimits/masked+readonly paths but not seccomp or sysctls, so
    // serialize and merge at the JSON level uniformly.
    let mut cfg = serde_json::to_value(&spec).map_err(|e| format!("serialize OCI spec: {e}"))?;
    graft_security_context(&mut cfg, &pod.host_spec);
    // Pin the container under a known pod-cgroup parent (`/sys/fs/cgroup/smolvm/<id>`)
    // so OOM detection can read the parent's aggregate `memory.events.oom_kill`
    // after crun deletes the leaf on exit. Ignored when crun runs cgroup-disabled.
    cfg["linux"]["cgroupsPath"] =
        serde_json::Value::String(format!("{POD_CGROUP_PARENT_REL}/{id}"));
    let json =
        serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialize OCI spec: {e}"))?;
    std::fs::write(bundle.join("config.json"), json)
        .map_err(|e| format!("failed to write OCI spec: {e}"))
}

/// Overlay the container's securityContext from the host OCI spec onto the
/// serialized guest bundle. Pods must honor exactly the capabilities, seccomp
/// profile, rlimits, masked/readonly paths, sysctls, and numeric uid/gid that
/// Kubernetes requested (critest asserts each) rather than smolvm's VM-grade
/// full-capability default. Every field copied here is host-agnostic — syscall
/// names, in-container paths, capability names, numeric ids — so it transfers
/// into the guest verbatim. `/process` and `/linux` always exist in the
/// serialized spec, so keyed assignment auto-vivifies the leaf objects.
fn graft_security_context(cfg: &mut serde_json::Value, host: &serde_json::Value) {
    for key in [
        "capabilities",
        "rlimits",
        "oomScoreAdj",
        "apparmorProfile",
        "noNewPrivileges",
    ] {
        if let Some(v) = host.pointer(&format!("/process/{key}")) {
            cfg["process"][key] = v.clone();
        }
    }
    // Numeric uid/gid are authoritative (CRI RunAsUser/RunAsGroup); grafting
    // them corrects the case where identity resolution defaulted to root.
    for id in ["uid", "gid"] {
        if let Some(n) = host
            .pointer(&format!("/process/user/{id}"))
            .and_then(|v| v.as_u64())
        {
            cfg["process"]["user"][id] = n.into();
        }
    }
    for key in ["seccomp", "sysctl", "maskedPaths", "readonlyPaths"] {
        if let Some(v) = host.pointer(&format!("/linux/{key}")) {
            cfg["linux"][key] = v.clone();
        }
    }
    // Cgroup limits (memory/cpu/pids). Without these the container is
    // unbounded and the OOM/limit tests fail — the VM's memory, not the
    // container's requested limit, would decide. crun applies them in-guest.
    if let Some(res) = host.pointer("/linux/resources") {
        let mut res = res.clone();
        // The guest kernel is built without swap, so cgroup2 exposes no
        // `memory.swap.max`. kubelet nonetheless pins swap (e.g. sets it to 0 to
        // enforce no-swap under cgroup v2), and crun then aborts the container
        // with "opening file `memory.swap.max' for writing: No such file". A swap
        // cap is meaningless in a swapless VM, so drop it — from both the OCI
        // memory.swap field and the cgroup2 unified passthrough.
        if let Some(mem) = res.get_mut("memory").and_then(|m| m.as_object_mut()) {
            mem.remove("swap");
        }
        if let Some(unified) = res.get_mut("unified").and_then(|u| u.as_object_mut()) {
            unified.remove("memory.swap.max");
        }
        cfg["linux"]["resources"] = res;
    }
}

/// Copy each materialized CRI mount from the (read-only) pod share into the
/// container's writable overlay `rootfs` at its destination. `cp -aT` makes the
/// destination a faithful copy of the source whether it is a file (resolv.conf,
/// hosts, hostname) or a directory (a volume), preserving modes/owners/symlinks.
/// Parent directories are created first. Reads from the read-only virtiofs share
/// are fine — only writes to it fail — and the target lives on the writable
/// overlay upper.
#[cfg(target_os = "linux")]
fn materialize_pod_mounts(id: &str, mounts: &[PodMount]) -> Vec<(PathBuf, String)> {
    // Copy each mount from the read-only share to a per-container writable dir on
    // /storage, then bind it into the container. Bind mounts (added to the OCI
    // spec) layer ON TOP of the default mounts, so a volume at /tmp/foo survives
    // the default tmpfs at /tmp (copying into the overlay would be shadowed by it).
    // The copy makes the volume writable + guest-local (correct emptyDir/configMap
    // /secret semantics; smolvm's virtiofs share is read-only so a live bind of the
    // host source couldn't be written).
    let base = Path::new("/storage/pods").join(id).join("mnt");
    let mut binds = Vec::new();
    for (n, m) in mounts.iter().enumerate() {
        let dst = base.join(n.to_string());
        if let Some(parent) = dst.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                continue;
            }
        }
        // Native recursive copy (follows symlinks) rather than shelling out to
        // `cp` — the guest's `cp` exits non-zero with no diagnostic on some
        // virtiofs→/storage copies, and this gives precise errors and handles the
        // symlink-volume case (dereference so the container sees the content).
        match copy_tree(Path::new(&m.source), &dst) {
            Ok(()) => binds.push((dst, m.destination.clone())),
            Err(e) => warn!(
                source = %m.source, dest = %m.destination, error = %e,
                "failed to materialize mount (container starts without it)"
            ),
        }
    }
    binds
}

/// Recursively copy `src` to `dst`, following symlinks (so a symlinked volume
/// source yields the pointed-to content, matching the CRI's bind semantics).
/// Regular files and directories are copied; special files (devices/fifos/
/// sockets) are skipped. Directory permissions are preserved best-effort.
#[cfg(target_os = "linux")]
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    // metadata() follows symlinks — a symlinked source is dereferenced.
    let meta = std::fs::metadata(src)?;
    let ft = meta.file_type();
    if ft.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
        }
        let _ = std::fs::set_permissions(dst, meta.permissions());
    } else if ft.is_file() {
        std::fs::copy(src, dst)?;
    }
    // else: device/fifo/socket — nothing meaningful to copy into a volume.
    Ok(())
}

/// Non-Linux builds don't run pod containers.
#[cfg(not(target_os = "linux"))]
fn materialize_pod_mounts(_id: &str, _mounts: &[PodMount]) -> Vec<(PathBuf, String)> {
    Vec::new()
}

/// Spawn the pod's shared-PID "pause": a process that is PID 1 of a fresh PID
/// namespace and blocks forever. Pod containers running with `SharePidMode=POD`
/// join this namespace (via `/proc/<pid>/ns/pid`), so their PID 1 is the pause —
/// not the workload — and they see each other's processes. Mirrors how runc
/// backs `shareProcessNamespace`, except the pause lives in the guest.
///
/// Returns the pause pid as seen from the agent's (guest-root) PID namespace.
/// The helper child unshares a new PID namespace so its own child becomes that
/// namespace's init; the grandchild pid it reports is agent-visible because the
/// helper itself stays in the agent's namespace.
#[cfg(target_os = "linux")]
fn spawn_pod_pause_pidns() -> Result<u32, String> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pause pipe: {}", std::io::Error::last_os_error()));
    }
    let (rd, wr) = (fds[0], fds[1]);
    // SAFETY: post-fork the child touches only async-signal-safe libc calls
    // (unshare/fork/write/close/pause/_exit) — no allocation, no locks.
    let helper = unsafe { libc::fork() };
    if helper < 0 {
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return Err(format!("pause fork: {}", std::io::Error::last_os_error()));
    }
    if helper == 0 {
        unsafe {
            libc::close(rd);
            if libc::unshare(libc::CLONE_NEWPID) != 0 {
                libc::_exit(11);
            }
            let gc = libc::fork();
            if gc < 0 {
                libc::_exit(12);
            }
            if gc == 0 {
                // Grandchild: PID 1 of the new namespace. Block forever.
                libc::close(wr);
                loop {
                    libc::pause();
                }
            }
            let bytes = (gc as u32).to_ne_bytes();
            libc::write(wr, bytes.as_ptr() as *const libc::c_void, 4);
            libc::close(wr);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(wr) };
    let mut buf = [0u8; 4];
    let n = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, 4) };
    unsafe { libc::close(rd) };
    let mut status = 0;
    unsafe { libc::waitpid(helper, &mut status, 0) };
    if n != 4 {
        return Err("pause helper did not report a pid".to_string());
    }
    Ok(u32::from_ne_bytes(buf))
}

/// The pod's shared-PID pause pid, created on first `SharePidMode=POD` container
/// and reused by the rest (one pod per sandbox VM). Re-created if the recorded
/// pause is gone (its `/proc/<pid>/ns/pid` vanished).
#[cfg(target_os = "linux")]
fn ensure_pod_pause_pidns() -> Result<u32, String> {
    static PAUSE: OnceLock<Mutex<Option<u32>>> = OnceLock::new();
    let mut guard = PAUSE.get_or_init(|| Mutex::new(None)).lock().unwrap();
    if let Some(pid) = *guard {
        if Path::new(&format!("/proc/{pid}/ns/pid")).exists() {
            return Ok(pid);
        }
    }
    let pid = spawn_pod_pause_pidns()?;
    *guard = Some(pid);
    Ok(pid)
}

/// Pod-cgroup parent, relative to the cgroup2 mount root. Every pod container's
/// cgroup is created at `<POD_CGROUP_PARENT_REL>/<id>`; the parent persists after
/// crun deletes a leaf, so its aggregate `memory.events.oom_kill` still reflects
/// a container that was OOM-killed.
const POD_CGROUP_PARENT_REL: &str = "smolvm";
const POD_CGROUP_PARENT_EVENTS: &str = "/sys/fs/cgroup/smolvm/memory.events";

/// Read the cumulative `oom_kill` counter from a cgroup2 `memory.events` file.
/// Returns 0 if the file is absent or unparseable (e.g. before the first
/// container of a pod creates the parent cgroup). cgroup2 propagates the counter
/// up the hierarchy at kill time and never decrements it, so a parent's count
/// survives deletion of the leaf that was killed.
fn read_cgroup_oom_kill(path: &str) -> u64 {
    let Ok(content) = std::fs::read_to_string(path) else {
        return 0;
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("oom_kill ") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Make the guest's cgroup2 hierarchy usable by crun for pod containers.
/// libkrun mounts `/sys/fs/cgroup` read-only, and cgroup2 delegates no
/// controllers to children by default; both must be fixed once so crun (with
/// the cgroupfs manager) can create per-container cgroups that enforce memory
/// and pids limits (OOM, resource caps). Best-effort and cached: on any failure
/// pods fall back to the cgroup-disabled path — they still run, just unbounded —
/// so this never fails a container start.
#[cfg(target_os = "linux")]
fn cgroups_available() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        use std::ffi::CString;
        let Ok(target) = CString::new("/sys/fs/cgroup") else {
            return false;
        };
        // Remount read-write (libkrun mounts cgroup2 ro): MS_REMOUNT preserves
        // the mount; omitting MS_RDONLY clears the read-only flag.
        let flags = libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        // SAFETY: `target` is a valid NUL-terminated path; the agent is PID-1
        // and holds CAP_SYS_ADMIN. Null source/type/data is valid for a remount.
        let rc = unsafe {
            libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            warn!(err = %std::io::Error::last_os_error(), "cgroup: remount rw failed; pod resource limits disabled");
            return false;
        }
        // Delegate the controllers crun needs into child cgroups.
        if let Err(e) = std::fs::write("/sys/fs/cgroup/cgroup.subtree_control", "+memory +pids") {
            warn!(error = %e, "cgroup: controller delegation failed; pod resource limits disabled");
            return false;
        }
        info!("cgroup: cgroup2 delegated (memory, pids) — pod resource limits enforced");
        true
    })
}

/// Start the container's init process and pump its I/O until exit.
#[cfg(target_os = "linux")]
/// Stack a guest-writable overlayfs over the read-only virtiofs rootfs.
///
/// `lower` is the container rootfs as presented through the (read-only)
/// virtiofs share; the upperdir/workdir live on the guest's writable
/// `/storage` disk. Returns the merged mountpoint to use as the container
/// `root.path`. Idempotent-ish: a stale merged mount from a prior attempt is
/// unmounted first.
#[cfg(target_os = "linux")]
fn mount_writable_rootfs(id: &str, lower: &std::path::Path) -> Result<PathBuf, String> {
    let base = Path::new("/storage/pods").join(id);
    let upper = base.join("upper");
    let work = base.join("work");
    let merged = base.join("merged");
    for d in [&upper, &work, &merged] {
        std::fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
    }

    use std::ffi::CString;
    let cstr = |p: &str| CString::new(p).map_err(|e| format!("cstr {p}: {e}"));
    let merged_c = cstr(&merged.to_string_lossy())?;
    // Drop any leftover mount from a previous start attempt (MNT_DETACH = 2).
    unsafe { libc::umount2(merged_c.as_ptr(), 2) };

    let overlay_c = cstr("overlay")?;
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let data_c = cstr(&data)?;
    // SAFETY: all args are valid NUL-terminated C strings; the agent is PID-1
    // with CAP_SYS_ADMIN, so mounting overlayfs is permitted.
    let rc = unsafe {
        libc::mount(
            overlay_c.as_ptr(),
            merged_c.as_ptr(),
            overlay_c.as_ptr(),
            0,
            data_c.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(format!(
            "mount writable overlay over {}: {}",
            lower.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(merged)
}

#[cfg(target_os = "linux")]
fn start_init_process(
    stream: &mut impl crate::ReadWrite,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::ensure_storage_mounted();

    // Snapshot the stashed settings under the lock; spawning happens after.
    let pod = {
        let reg = lock_registry();
        match reg.get(id) {
            None => {
                crate::send_response(
                    stream,
                    &AgentResponse::error(
                        format!("unknown pod container: {id}"),
                        error_codes::NOT_FOUND,
                    ),
                )?;
                return Ok(());
            }
            Some(p) if p.state != PodState::Created => {
                crate::send_response(
                    stream,
                    &AgentResponse::error(
                        format!("pod container '{id}' already started"),
                        error_codes::INVALID_REQUEST,
                    ),
                )?;
                return Ok(());
            }
            Some(p) => p.clone(),
        }
    };

    // The rootfs is created host-side by containerd after the VM booted; it
    // must be visible through the shared virtiofs mount by start time.
    if !pod.rootfs.is_dir() {
        crate::send_response(
            stream,
            &AgentResponse::error(
                format!("pod rootfs not found: {}", pod.rootfs.display()),
                error_codes::NOT_FOUND,
            ),
        )?;
        return Ok(());
    }

    // The virtiofs share is READ-ONLY to the guest (writes EACCES), so crun
    // can't create its /proc,/sys,/dev mountpoints directly on it. Stack a
    // guest-writable overlay — lowerdir = the (read-only) virtiofs rootfs,
    // upper/work on the guest's writable /storage disk — and run the container
    // on the merged view. This mirrors how Kata backs a virtiofs rootfs, and
    // keeps container writes ephemeral + guest-local (correct k8s semantics).
    let mut pod = pod;
    match mount_writable_rootfs(id, &pod.rootfs) {
        Ok(merged) => pod.rootfs = merged,
        Err(e) => {
            crate::send_response(
                stream,
                &AgentResponse::error(e, error_codes::INTERNAL_ERROR),
            )?;
            return Ok(());
        }
    }

    // Materialize CRI mounts (volumes + generated /etc/resolv.conf, /etc/hosts,
    // /etc/hostname) into per-container writable dirs and bind them into the
    // container (layered on top of the default mounts). Best-effort: a mount that
    // can't be materialized is skipped, not fatal.
    let mount_binds = materialize_pod_mounts(id, &pod.mounts);

    let bundle = pod_dir(id).join("bundle");
    if let Err(e) = std::fs::create_dir_all(&bundle) {
        crate::send_response(
            stream,
            &AgentResponse::error(
                format!("failed to create bundle dir: {e}"),
                error_codes::INTERNAL_ERROR,
            ),
        )?;
        return Ok(());
    }
    if let Err(e) = write_pod_bundle(&pod, id, &bundle, &mount_binds) {
        crate::send_response(stream, &AgentResponse::error(e, error_codes::SPAWN_FAILED))?;
        return Ok(());
    }

    info!(
        id = %id,
        rootfs = %pod.rootfs.display(),
        command = ?pod.process.args,
        tty = pod.tty,
        "starting pod container"
    );

    // Reuse Run's crun-run spawner: console-socket PTY handshake when tty,
    // piped stdio otherwise. The provided id IS the crun container id.
    //
    // Pods get cgroupfs once delegation succeeds so crun enforces the
    // container's memory/pids limits (OOM); otherwise crun runs cgroup-disabled
    // (still works, just unbounded).
    let cgroups = cgroups_available();
    // Baseline the pod-cgroup parent's OOM counter before the container starts;
    // a post-exit increment means this container was OOM-killed (see Exited below).
    let oom_baseline = if cgroups {
        read_cgroup_oom_kill(POD_CGROUP_PARENT_EVENTS)
    } else {
        0
    };
    let (mut child, pty_master) = match crate::spawn_crun_run(&bundle, id, pod.tty, cgroups) {
        Ok(result) => result,
        Err(e) => {
            crate::send_response(
                stream,
                &AgentResponse::from_err(e, error_codes::SPAWN_FAILED),
            )?;
            return Ok(());
        }
    };

    // `crun run` registers the container in crun's state DB asynchronously (the
    // spawn above only forked crun). Wait until the container is registered
    // before reporting Started, so a client that immediately execs/signals/reads
    // stats after StartContainer finds a live container — critest races
    // StartContainer→ExecSync and would otherwise hit "container not found".
    // Bounded, and returns early if the container exits instantly.
    let init_pid = wait_for_crun_running(id, &mut child);

    if let Some(p) = lock_registry().get_mut(id) {
        p.state = PodState::Running;
        p.init_pid = init_pid;
    }

    crate::send_response(stream, &AgentResponse::Started)?;

    // Reuse Run's streaming pumps verbatim (Stdout/Stderr frames out;
    // Stdin/Resize requests in). No timeout: pod containers run until they
    // exit or are signalled.
    let loop_result = match pty_master {
        Some(pty) => crate::run_interactive_loop_pty(stream, &mut child, pty, None),
        None => crate::run_interactive_loop(stream, &mut child, None),
    };

    // Whatever happened, the init process is done (the pumps kill the child on
    // every error/disconnect path themselves; the Err arm below reaps).
    if let Some(p) = lock_registry().get_mut(id) {
        p.state = PodState::Exited;
        p.init_pid = None;
    }

    let exit_code = match loop_result {
        Ok(code) => code,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };

    // The cgroup OOM killer sends SIGKILL, so the process already exited 137;
    // check whether the kill was ours (memory limit) so the shim can surface
    // `reason=OOMKilled` rather than a bare signal exit.
    let oom = cgroups && read_cgroup_oom_kill(POD_CGROUP_PARENT_EVENTS) > oom_baseline;
    crate::send_response(stream, &AgentResponse::Exited { exit_code, oom })?;
    Ok(())
}

/// Spawn a pod exec. Uses `crun exec --process` (full OCI process, honors
/// supplemental groups) when `use_process_spec`; otherwise the flag-based
/// `spawn_exec_in_container` (unchanged for the common case).
#[cfg(target_os = "linux")]
#[allow(clippy::type_complexity)]
fn spawn_pod_exec(
    id: &str,
    exec_id: &str,
    entry: &ExecEntry,
    launch: &crate::ResolvedLaunch,
    use_process_spec: bool,
) -> Result<(std::process::Child, Option<crate::pty::PtyMaster>), Box<dyn std::error::Error>> {
    if !use_process_spec {
        return crate::spawn_exec_in_container(id, launch, entry.tty);
    }
    let bundle = pod_dir(id).join("bundle");
    std::fs::create_dir_all(&bundle)?;
    let process_file = bundle.join(format!("exec-{exec_id}.json"));
    std::fs::write(
        &process_file,
        prepare_exec_process_json(&entry.process_json)?,
    )?;
    let child = crun::CrunCommand::exec_with_process(id, &process_file)
        .stdin_piped()
        .capture_output()
        .spawn()?;
    Ok((child, None))
}

/// Normalize a containerd exec OCI Process for `crun exec --process`: force
/// `terminal:false` (we drive piped stdio) and guarantee a PATH so bare-name
/// binaries (e.g. `id`) resolve.
#[cfg(target_os = "linux")]
fn prepare_exec_process_json(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let mut v: serde_json::Value = serde_json::from_str(raw)?;
    v["terminal"] = serde_json::Value::Bool(false);
    let has_path = v
        .get("env")
        .and_then(|e| e.as_array())
        .map(|a| {
            a.iter()
                .any(|x| x.as_str().map(|s| s.starts_with("PATH=")).unwrap_or(false))
        })
        .unwrap_or(false);
    if !has_path {
        match v.get_mut("env").and_then(|e| e.as_array_mut()) {
            Some(env) => env.push(serde_json::Value::String(DEFAULT_PATH.to_string())),
            None => v["env"] = serde_json::json!([DEFAULT_PATH]),
        }
    }
    Ok(serde_json::to_string(&v)?)
}

/// Start a previously registered exec process inside the running container
/// and pump its I/O until exit. Same streaming contract as the init path.
#[cfg(target_os = "linux")]
fn start_exec_process(
    stream: &mut impl crate::ReadWrite,
    id: &str,
    exec_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::ensure_storage_mounted();

    let entry = {
        let reg = lock_registry();
        let Some(pod) = reg.get(id) else {
            crate::send_response(
                stream,
                &AgentResponse::error(
                    format!("unknown pod container: {id}"),
                    error_codes::NOT_FOUND,
                ),
            )?;
            return Ok(());
        };
        if pod.state != PodState::Running {
            crate::send_response(
                stream,
                &AgentResponse::error(
                    format!("pod container '{id}' is not running"),
                    error_codes::EXEC_FAILED,
                ),
            )?;
            return Ok(());
        }
        let Some(entry) = pod.execs.get(exec_id) else {
            crate::send_response(
                stream,
                &AgentResponse::error(
                    format!("unknown exec '{exec_id}' for container '{id}'"),
                    error_codes::NOT_FOUND,
                ),
            )?;
            return Ok(());
        };
        if entry.pid.is_some() {
            crate::send_response(
                stream,
                &AgentResponse::error(
                    format!("exec '{exec_id}' already started"),
                    error_codes::INVALID_REQUEST,
                ),
            )?;
            return Ok(());
        }
        entry.clone()
    };

    // Reuse Run's exec-in-container spawner (`crun exec`, console-socket PTY
    // when tty). ResolvedLaunch carries the stashed args/env/cwd/user; the user
    // (containerd copies the container's RunAsUser into the exec process spec) is
    // applied via `crun exec --user`, so ExecSync runs as the container's user.
    let launch = crate::ResolvedLaunch {
        command: entry.process.args.clone(),
        env: entry.process.env.clone(),
        workdir: entry.process.cwd.clone(),
        user: entry.process.user.clone(),
    };

    info!(id = %id, exec_id = %exec_id, command = ?launch.command, tty = entry.tty, "starting pod exec process");

    // When the exec has supplemental groups (CRI SupplementalGroups), run it from
    // the full OCI process via `crun exec --process` — the flag path can only set
    // uid:gid. Limited to non-TTY (execSync); TTY execs with groups fall back to
    // the flag path (rare). Everything else keeps the flag-based path unchanged.
    let use_process_spec = !entry.process.additional_gids.is_empty() && !entry.tty;

    let (mut child, pty_master) =
        match spawn_pod_exec(id, exec_id, &entry, &launch, use_process_spec) {
            Ok(result) => result,
            Err(e) => {
                crate::send_response(
                    stream,
                    &AgentResponse::from_err(e, error_codes::SPAWN_FAILED),
                )?;
                return Ok(());
            }
        };

    // Track the crun-exec pid so PodSignal { exec_id } can kill(2) it (crun
    // can't target exec processes by id). Signal delivery refines this to the
    // monitor's first child when visible in /proc.
    {
        let mut reg = lock_registry();
        if let Some(e) = reg.get_mut(id).and_then(|p| p.execs.get_mut(exec_id)) {
            e.pid = Some(child.id());
        }
    }

    crate::send_response(stream, &AgentResponse::Started)?;

    let loop_result = match pty_master {
        Some(pty) => crate::run_interactive_loop_pty(stream, &mut child, pty, None),
        None => crate::run_interactive_loop(stream, &mut child, None),
    };

    // The exec is done — clear the tracked pid.
    {
        let mut reg = lock_registry();
        if let Some(e) = reg.get_mut(id).and_then(|p| p.execs.get_mut(exec_id)) {
            e.pid = None;
        }
    }

    let exit_code = match loop_result {
        Ok(code) => code,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };

    crate::send_response(
        stream,
        &AgentResponse::Exited {
            exit_code,
            oom: false,
        },
    )?;
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_validation() {
        assert!(validate_id("abc-123_x.y").is_ok());
        assert!(validate_id("").is_err());
        assert!(validate_id("..").is_err());
        assert!(validate_id("-flag").is_err());
        assert!(validate_id("a/b").is_err());
        assert!(validate_id(&"x".repeat(201)).is_err());
    }

    #[test]
    fn rootfs_resolution_stays_under_share() {
        let p = resolve_pod_rootfs("ctr-1/rootfs").unwrap();
        assert_eq!(
            p,
            Path::new(paths::VIRTIOFS_MOUNT_ROOT)
                .join(POD_SHARE_TAG)
                .join("ctr-1/rootfs")
        );
        assert!(resolve_pod_rootfs("/abs/path").is_err());
        assert!(resolve_pod_rootfs("../escape").is_err());
        assert!(resolve_pod_rootfs("a/../../b").is_err());
        assert!(resolve_pod_rootfs("").is_err());
    }

    #[test]
    fn oci_process_parsing() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{
                "args": ["/bin/sh", "-c", "echo hi"],
                "env": ["PATH=/bin", "FOO=bar=baz", "BROKEN"],
                "cwd": "/app",
                "user": { "uid": 1000, "gid": 100 }
            }"#,
        )
        .unwrap();
        let p = parse_oci_process(&v).unwrap();
        assert_eq!(p.args, vec!["/bin/sh", "-c", "echo hi"]);
        assert_eq!(
            p.env,
            vec![
                ("PATH".to_string(), "/bin".to_string()),
                ("FOO".to_string(), "bar=baz".to_string())
            ]
        );
        assert_eq!(p.cwd.as_deref(), Some("/app"));
        assert_eq!(p.user.as_deref(), Some("1000:100"));
    }

    #[test]
    fn oci_process_requires_args() {
        let v: serde_json::Value = serde_json::from_str(r#"{ "env": [] }"#).unwrap();
        assert!(parse_oci_process(&v).is_err());
    }

    #[test]
    fn create_signal_delete_lifecycle() {
        // Registry is process-global; use unique ids to avoid cross-test
        // interference.
        let id = "test-pod-lifecycle";
        let spec = r#"{
            "process": { "args": ["sleep", "1"], "env": ["A=b"], "cwd": "/" },
            "root": { "path": "rootfs", "readonly": true }
        }"#;
        let resp = handle_pod_create(id, "ctr/rootfs", spec, false);
        assert!(matches!(resp, AgentResponse::Ok { .. }), "{resp:?}");

        // Duplicate rejected.
        let dup = handle_pod_create(id, "ctr/rootfs", spec, false);
        assert!(matches!(dup, AgentResponse::Error { .. }));

        // Exec stash + duplicate rejected.
        let proc_json = r#"{ "args": ["ls"], "env": [] }"#;
        assert!(matches!(
            handle_pod_exec(id, "e1", proc_json, false),
            AgentResponse::Ok { .. }
        ));
        assert!(matches!(
            handle_pod_exec(id, "e1", proc_json, false),
            AgentResponse::Error { .. }
        ));

        // Signal on a created (not running) container is an idempotent Ok.
        assert!(matches!(
            handle_pod_signal(id, None, 15, true),
            AgentResponse::Ok { .. }
        ));
        // Unknown exec id is NOT_FOUND.
        assert!(matches!(
            handle_pod_signal(id, Some("nope"), 9, false),
            AgentResponse::Error { .. }
        ));

        // Pids on a never-started container: empty list.
        match handle_pod_pids(id) {
            AgentResponse::Pids { pids } => assert!(pids.is_empty()),
            other => panic!("expected Pids, got {other:?}"),
        }

        // Delete exec then container; both idempotent.
        assert!(matches!(
            handle_pod_delete(id, Some("e1")),
            AgentResponse::Ok { .. }
        ));
        assert!(matches!(
            handle_pod_delete(id, None),
            AgentResponse::Ok { .. }
        ));
        assert!(matches!(
            handle_pod_delete(id, None),
            AgentResponse::Ok { .. }
        ));

        // Gone from the registry.
        assert!(matches!(handle_pod_pids(id), AgentResponse::Error { .. }));
    }

    #[test]
    fn unknown_ids_are_not_found() {
        assert!(matches!(
            handle_pod_signal("no-such-pod", None, 9, false),
            AgentResponse::Error { .. }
        ));
        assert!(matches!(
            handle_pod_pids("no-such-pod"),
            AgentResponse::Error { .. }
        ));
        assert!(matches!(
            handle_pod_exec("no-such-pod", "e", r#"{ "args": ["ls"] }"#, false),
            AgentResponse::Error { .. }
        ));
    }
}
