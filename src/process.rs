//! Process management utilities.
//!
//! This module provides utilities for managing child processes,
//! including signal handling and graceful shutdown.

#[cfg(unix)]
use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Portable process-id type. On Unix this is `libc::pid_t`; on Windows there is
/// no POSIX `pid_t`, so we use `i32` (process IDs there are `u32` but `i32`
/// matches the existing signatures and the sentinel `-1` values used here).
#[cfg(unix)]
pub type Pid = libc::pid_t;
/// Portable process-id type (Windows): there is no POSIX `pid_t`, so `i32` is
/// used (matching the existing signatures and `-1` sentinels).
#[cfg(not(unix))]
pub type Pid = i32;

/// Windows process-control helpers backing the cross-platform liveness/kill/wait
/// API. Mirror the semantics of the Unix `kill`/`waitpid` paths using the Win32
/// process APIs.
#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    // `GetExitCodeProcess` writes `STILL_ACTIVE` (= STATUS_PENDING, 0x103) while
    // the process is running.
    const STILL_RUNNING: u32 = STILL_ACTIVE as u32;

    /// Open a process handle, returning `None` if it cannot be opened.
    fn open(pid: u32, access: u32) -> Option<HANDLE> {
        // SAFETY: OpenProcess is a simple FFI call; we validate the handle.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            None
        } else {
            Some(handle)
        }
    }

    fn exit_code(handle: HANDLE) -> Option<u32> {
        let mut code: u32 = 0;
        // SAFETY: handle is a live process handle for the duration of the call.
        let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
        if ok == 0 {
            None
        } else {
            Some(code)
        }
    }

    pub fn process_is_alive(pid: u32) -> bool {
        match open(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            Some(handle) => {
                let alive = exit_code(handle)
                    .map(|c| c == STILL_RUNNING)
                    .unwrap_or(false);
                unsafe { CloseHandle(handle) };
                alive
            }
            None => false,
        }
    }

    pub fn process_try_wait(pid: u32) -> Option<i32> {
        let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let result = match exit_code(handle) {
            Some(code) if code == STILL_RUNNING => None,
            Some(code) => Some(code as i32),
            None => None,
        };
        unsafe { CloseHandle(handle) };
        result
    }

    pub fn process_wait(pid: u32) -> i32 {
        let Some(handle) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
            return -1;
        };
        // SAFETY: handle is valid; INFINITE blocks until the process exits.
        let waited = unsafe { WaitForSingleObject(handle, INFINITE) };
        let code = if waited == WAIT_OBJECT_0 {
            exit_code(handle).map(|c| c as i32).unwrap_or(-1)
        } else {
            -1
        };
        unsafe { CloseHandle(handle) };
        code
    }

    pub fn process_kill(pid: u32) -> bool {
        match open(pid, PROCESS_TERMINATE) {
            Some(handle) => {
                // SAFETY: handle has PROCESS_TERMINATE rights.
                let ok = unsafe { TerminateProcess(handle, 1) } != 0;
                unsafe { CloseHandle(handle) };
                ok
            }
            None => false,
        }
    }

    /// Process creation time as a u64 (Windows FILETIME: 100 ns ticks since
    /// 1601). Stable for the life of the process, so it pins PID identity
    /// against reuse — the same role the start-time-from-/proc plays on Linux.
    pub fn process_start_time(pid: u32) -> Option<u64> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = creation;
        let mut kernel = creation;
        let mut user = creation;
        // SAFETY: handle is a live process handle for the duration of the call;
        // all four FILETIME out-params are valid, writable locals.
        let ok =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            None
        } else {
            Some(filetime_to_u64(&creation))
        }
    }

    /// Combine a FILETIME's high/low halves into a single u64 (100 ns ticks).
    fn filetime_to_u64(ft: &windows_sys::Win32::Foundation::FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }

    /// Sample cumulative CPU time (ns) and resident set size (bytes) for a
    /// process. Mirrors the Linux `/proc/<pid>/{stat,statm}` and macOS
    /// `proc_pidinfo` sampling so `machine monitor` reports live CPU/RSS on
    /// Windows too. Returns `None` if the process is gone or stats are
    /// unavailable.
    pub fn process_stats(pid: u32) -> Option<(u64, u64)> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetProcessTimes;

        let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;

        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: handle is live for the call; all four FILETIME out-params are
        // valid, writable locals.
        let times_ok =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };

        let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let pmc_size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        pmc.cb = pmc_size;
        // SAFETY: handle is live; pmc is a valid, correctly-sized counters buffer.
        let mem_ok = unsafe { GetProcessMemoryInfo(handle, &mut pmc, pmc_size) };

        unsafe { CloseHandle(handle) };
        if times_ok == 0 || mem_ok == 0 {
            return None;
        }

        // GetProcessTimes' kernel/user are 100 ns ticks; sum and scale to ns.
        let cpu_time_ns = filetime_to_u64(&kernel)
            .saturating_add(filetime_to_u64(&user))
            .saturating_mul(100);
        Some((cpu_time_ns, pmc.WorkingSetSize as u64))
    }
}

/// Flag indicating whether SIGCHLD handler has been installed. Only the Unix
/// SIGCHLD-reaping path uses this; Windows has no zombie-reaping model.
#[cfg_attr(not(unix), allow(dead_code))]
static SIGCHLD_HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Default timeout for graceful shutdown before SIGKILL.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for SIGKILL to take effect.
pub const SIGKILL_WAIT: Duration = Duration::from_millis(50);

/// Aggressive poll interval for fast process shutdown and agent readiness.
pub const FAST_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Number of aggressive polls before backing off to slower intervals.
pub const FAST_POLL_COUNT: u32 = 10;

/// Exit code returned when the actual exit status cannot be determined.
/// This happens when a process is confirmed dead but waitpid() fails to
/// retrieve the exit status (e.g., process was reaped by another handler).
pub const UNKNOWN_EXIT_CODE: i32 = -1;

/// Close inherited file descriptors starting at `min_fd`.
///
/// This is used in freshly spawned/forked VM launcher children to avoid holding
/// parent database locks, sockets, and other resources. On Linux it uses
/// `close_range` when available. On other platforms it enumerates `/dev/fd` and
/// closes only descriptors that are actually open, avoiding an expensive loop to
/// very large `getdtablesize()` values on macOS.
#[cfg(unix)]
pub fn close_inherited_fds_from(min_fd: i32) {
    if min_fd < 0 {
        return;
    }

    #[cfg(target_os = "linux")]
    unsafe {
        let ret = libc::syscall(libc::SYS_close_range, min_fd as u32, u32::MAX, 0u32);
        if ret == 0 {
            return;
        }
    }

    if close_fds_from_dev_fd(min_fd) {
        return;
    }

    close_fds_by_range(min_fd);
}

/// Windows: file descriptors are not inherited across `CreateProcess` the way
/// POSIX fds are (handle inheritance is opt-in per-handle), so there is nothing
/// to bulk-close here.
#[cfg(not(unix))]
pub fn close_inherited_fds_from(_min_fd: i32) {}

#[cfg(unix)]
fn close_fds_from_dev_fd(min_fd: i32) -> bool {
    let entries = match std::fs::read_dir("/dev/fd") {
        Ok(entries) => entries,
        Err(_) => return false,
    };

    let mut fds: Vec<i32> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        .filter(|fd| *fd >= min_fd)
        .collect();

    // Drop the read_dir handle before closing; its fd may have appeared in the
    // collected list, and closing an already-closed fd is harmless.
    fds.sort_unstable();
    fds.dedup();

    for fd in fds {
        unsafe {
            libc::close(fd);
        }
    }

    true
}

#[cfg(unix)]
fn close_fds_by_range(min_fd: i32) {
    let max_fd = unsafe { libc::getdtablesize() };
    for fd in min_fd..max_fd {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Apply best-effort, low-risk hardening to *this* process before it becomes the
/// VMM host for an untrusted guest — the info-leak / escalation baseline that the
/// heavier work (seccomp, cgroup caps, privilege drop) builds on top of.
///
/// Effects (Linux; a near-no-op on macOS dev, which is single-tenant):
/// - `PR_SET_NO_NEW_PRIVS`: a guest→VMM escape cannot regain privileges via a
///   setuid binary. Affects nothing the VMM legitimately does.
/// - `PR_SET_DUMPABLE = 0`: not ptrace-able, and `/proc/<pid>/{mem,maps,…}`
///   become root-owned, so a compromised VMM can't read a neighbor VM's guest
///   RAM. Self-access to `/proc/self` is unaffected, so libkrun boots normally
///   (verified on Linux/KVM across bare/network/GPU VMs).
/// - `RLIMIT_CORE = 0`: never write a core dump, which would contain guest RAM
///   (the main on-crash memory-disclosure vector). POSIX — both OSes.
///
/// All calls are best-effort: failures are ignored (hardening is additive and
/// must never block boot).
pub fn harden_self() {
    #[cfg(target_os = "linux")]
    unsafe {
        // Block setuid privilege escalation after a guest→VMM escape.
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        // Non-dumpable: not ptrace-able, and /proc/<pid>/{mem,maps,…} become
        // root-owned so another same-uid VMM can't read this VM's guest RAM
        // (cross-tenant memory leak). Self-access to /proc/self stays permitted,
        // so libkrun still reads its own maps and boots normally (verified on
        // Linux/KVM across bare/network/GPU VMs).
        //
        // EXCEPTION: a forkable golden must stay dumpable. Its CoW clones map the
        // golden's guest RAM by opening /proc/<golden_pid>/fd/<memfd>, which
        // PR_SET_DUMPABLE=0 would deny (EACCES → clone can't boot). The
        // RLIMIT_CORE=0 below still prevents a core dump from leaking the
        // golden's RAM, so only same-uid /proc access + ptrace are relaxed —
        // acceptable for a fork pool whose clones legitimately share its memory.
        if std::env::var_os("SMOLVM_FORKABLE").is_none() {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
    // RLIMIT_CORE=0: never write a core dump (which would contain guest RAM).
    // POSIX-only; Windows has no rlimit and no core-dump-to-file model here.
    #[cfg(unix)]
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
    }
}

/// (Re)assert the process's `PR_SET_DUMPABLE` flag.
///
/// `setuid()` clears dumpable, after which `ptrace_may_access` denies even a
/// same-uid reader of `/proc/<pid>/{mem,fd}` without `CAP_SYS_PTRACE`. A forkable
/// golden's clones map its guest-RAM memfd via `/proc/<golden>/fd`, so the
/// forkable boot re-asserts dumpable *after* its per-VM uid drop — without this,
/// fork breaks under uid isolation. Only the golden's own uid (under per-VM uids,
/// exactly its clones) can reach it. Linux-only; no-op elsewhere.
#[cfg(target_os = "linux")]
pub fn set_dumpable(dumpable: bool) {
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, i32::from(dumpable), 0, 0, 0) };
}

/// No-op where `prctl` isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn set_dumpable(_dumpable: bool) {}

// ============================================================================
// Per-VM cgroup v2 resource caps (noisy-neighbor / host-DoS containment)
//
// Each VMM subprocess is placed in its own cgroup v2 leaf with cpu/pids/memory
// limits so an untrusted guest cannot peg host CPU, fork-bomb the host, or
// balloon VMM memory to harm neighbors. See docs/runtime-isolation-hardening.md.
//
// Two pieces, because of the cgroup v2 "no internal processes" rule (a cgroup
// may hold processes OR delegate controllers to children, not both):
//   1. `setup_cgroup_delegation_root` (supervisor): vacate our own process into
//      a leaf so the parent can become a delegated root that distributes
//      cpu/memory/pids to per-VM children.
//   2. `place_in_cgroup` (VMM subprocess): create a capped `vm-<pid>` leaf under
//      that root and join it.
// Both are best-effort and Linux-only — a near-no-op on macOS dev (single
// tenant), and on Linux they degrade to "uncapped but still booting" whenever
// cgroup v2 isn't delegated to us, since hardening must never block boot.
// ============================================================================

/// CPU accounting period for `cpu.max` (cgroup v2 default, 100 ms).
#[cfg(target_os = "linux")]
const CGROUP_CPU_PERIOD_US: u64 = 100_000;

/// Cap on host tasks (threads/processes) a single VMM may spawn. Guest processes
/// run *inside* the VM and are not host tasks, so the VMM itself needs only a few
/// dozen (one per vCPU plus virtio/vsock/gpu workers). 1024 is generous headroom
/// that still severs a host-side fork bomb after a guest→VMM escape.
#[cfg(target_os = "linux")]
const CGROUP_PIDS_MAX: u32 = 1024;

/// Extra MiB granted on top of guest RAM for VMM/virtio/gpu overhead when sizing
/// `memory.max`. This is defense-in-depth atop the guest RAM bound already
/// enforced by `krun_set_vm_config`, not the primary memory control.
#[cfg(target_os = "linux")]
const CGROUP_MEM_OVERHEAD_MIB: u64 = 768;

/// Resolve this process's cgroup v2 directory from `/proc/self/cgroup`.
///
/// Returns `None` on a cgroup v1 / hybrid host (no unified `0::` line) or if the
/// path can't be read — callers then skip cgroup caps.
#[cfg(target_os = "linux")]
fn cgroup_v2_self_dir() -> Option<std::path::PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // The unified-hierarchy entry is the line beginning with "0::".
    let rel = content.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    if rel.is_empty() {
        return None;
    }
    Some(std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Write a single cgroup control file (no trailing newline needed by the kernel).
#[cfg(target_os = "linux")]
fn write_cgroup(dir: &std::path::Path, file: &str, val: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join(file))?;
    f.write_all(val.as_bytes())
}

/// Supervisor-side: turn our current cgroup into a delegated root under which
/// per-VM subprocesses can be capped.
///
/// Because of the "no internal processes" rule, we first move *our own* process
/// into a `supervisor` leaf, then enable `cpu`/`memory`/`pids` distribution on
/// the now-empty parent. That parent is returned as the root to pass to
/// [`place_in_cgroup`]. Pass the returned path to each VMM subprocess (e.g. via
/// the `SMOLVM_CGROUP_ROOT` env var) so it can self-place.
///
/// Returns `None` (and changes nothing observable) when cgroup v2 isn't
/// delegated to us — e.g. the process isn't under a systemd unit with
/// `Delegate=yes`, or we lack write access. The caller proceeds without caps.
#[cfg(target_os = "linux")]
pub fn setup_cgroup_delegation_root() -> Option<std::path::PathBuf> {
    let root = cgroup_v2_self_dir()?;
    // Vacate our process into a leaf so `root` may distribute controllers.
    let supervisor = root.join("supervisor");
    let _ = std::fs::create_dir(&supervisor);
    let pid = unsafe { libc::getpid() };
    if write_cgroup(&supervisor, "cgroup.procs", &pid.to_string()).is_err() {
        // Not delegated / no permission — no per-VM caps available.
        return None;
    }
    // Now that `root` holds no processes, enable the controllers we cap on.
    if write_cgroup(&root, "cgroup.subtree_control", "+cpu +memory +pids").is_err() {
        return None;
    }
    Some(root)
}

/// VMM-subprocess-side: place THIS process into a capped `vm-<pid>` leaf under
/// `root`, deriving limits from the VM's resources.
///
/// Caps applied (best-effort, each independently):
/// - `cpu.max` = `vcpus * 100ms / 100ms` → bounds CPU to ~`vcpus` cores.
/// - `pids.max` = [`CGROUP_PIDS_MAX`] → caps host tasks (fork-bomb containment).
/// - `memory.max` = guest RAM + [`CGROUP_MEM_OVERHEAD_MIB`] → defense-in-depth.
///
/// `root` must be a delegated root with `cpu`/`memory`/`pids` enabled in its
/// `subtree_control` (see [`setup_cgroup_delegation_root`]); otherwise the limit
/// files won't exist and the caps silently degrade while the process still runs.
/// Never blocks boot.
#[cfg(target_os = "linux")]
pub fn place_in_cgroup(root: &std::path::Path, vcpus: u8, memory_mib: u32) {
    let pid = unsafe { libc::getpid() };
    let vm = root.join(format!("vm-{pid}"));
    if let Err(e) = std::fs::create_dir(&vm) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            tracing::debug!(error = %e, dir = %vm.display(),
                "could not create per-VM cgroup; VMM running uncapped");
            return;
        }
    }

    // Set limits on the leaf *before* joining it.
    let quota_us = (vcpus.max(1) as u64) * CGROUP_CPU_PERIOD_US;
    let _ = write_cgroup(
        &vm,
        "cpu.max",
        &format!("{quota_us} {CGROUP_CPU_PERIOD_US}"),
    );
    let _ = write_cgroup(&vm, "pids.max", &CGROUP_PIDS_MAX.to_string());
    let mem_bytes = (memory_mib as u64 + CGROUP_MEM_OVERHEAD_MIB) * 1024 * 1024;
    let _ = write_cgroup(&vm, "memory.max", &mem_bytes.to_string());

    // Join the leaf last; from here the caps above govern this process tree.
    if let Err(e) = write_cgroup(&vm, "cgroup.procs", &pid.to_string()) {
        tracing::debug!(error = %e, "failed to join per-VM cgroup; VMM running uncapped");
        let _ = std::fs::remove_dir(&vm); // leave no empty cgroup behind
        return;
    }
    tracing::info!(
        vcpus, memory_mib, cgroup = %vm.display(),
        "placed VMM subprocess in per-VM cgroup with cpu/pids/memory caps"
    );
}

// ============================================================================
// Seccomp-BPF syscall allowlist for the VM boot subprocess
//
// libkrun (unlike Firecracker) installs no seccomp filter, so a guest→VMM escape
// would inherit the host's full syscall surface. This installs a Firecracker-style
// allowlist (via the `seccompiler` crate) on the boot subprocess before it enters
// the guest run loop, confining a compromised VMM to the ~dozens of syscalls a
// running microVM legitimately needs — and denying the escape-amplifying ones
// (ptrace, kexec_load, *_module, mount, bpf, perf_event_open, process_vm_*,
// setns, unshare, …), none of which appear in a real VM's syscall trace.
//
// The allowlist was derived empirically by stracing a full VM lifecycle
// (boot + exec + stop) on a Linux/KVM host; see docs/runtime-isolation-hardening.md.
// x86_64-Linux only for now (the production target); a no-op stub elsewhere.
// Gated by SMOLVM_SECCOMP=audit|enforce so rollout is opt-in.
// ============================================================================

/// Install the seccomp allowlist on the calling thread (and, by inheritance, on
/// every thread it later spawns — the vCPU/worker threads libkrun creates). Must
/// be called while still single-threaded, before `krun_start_enter`.
///
/// `enforce = true`  → a non-allowlisted syscall kills the process (KillProcess).
/// `enforce = false` → audit mode: non-allowlisted syscalls are logged but allowed
///   (SECCOMP Log), so a run surfaces any missing syscalls without breaking the VM.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn install_seccomp_filter(enforce: bool) -> std::result::Result<(), String> {
    // Build the BPF program (allocates) and apply it (a single seccomp syscall,
    // allocation-free). Split out so tests can build in the parent and apply in a
    // forked child without allocating post-fork.
    let program = build_seccomp_program(enforce)?;
    seccompiler::apply_filter(&program).map_err(|e| e.to_string())?;
    Ok(())
}

/// Compile the syscall allowlist into a seccomp BPF program. See
/// [`install_seccomp_filter`] for the policy.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn build_seccomp_program(enforce: bool) -> std::result::Result<seccompiler::BpfProgram, String> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    // Syscalls observed across a full VM lifecycle (boot + exec + stop), plus a
    // small margin of common runtime syscalls that vDSO/timing can hide from a
    // single trace. An empty rule vec allows the syscall unconditionally.
    //
    // Kept as a hand-grouped table (rustfmt would explode it one-per-line):
    // a security allowlist is far easier to audit when related syscalls sit
    // together under a category comment.
    #[rustfmt::skip]
    let mut allowed: Vec<libc::c_long> = vec![
        // file & block I/O (storage/overlay disks, virtio-blk, layer files)
        libc::SYS_read, libc::SYS_write, libc::SYS_pread64, libc::SYS_pwrite64,
        libc::SYS_preadv, libc::SYS_pwritev, libc::SYS_openat, libc::SYS_close,
        libc::SYS_close_range, libc::SYS_lseek, libc::SYS_fsync, libc::SYS_fallocate,
        libc::SYS_ftruncate, libc::SYS_fstat, libc::SYS_newfstatat, libc::SYS_statx,
        libc::SYS_fstatfs, libc::SYS_statfs, libc::SYS_fcntl, libc::SYS_flock,
        libc::SYS_dup, libc::SYS_dup3, libc::SYS_getdents64,
        libc::SYS_readlinkat, libc::SYS_faccessat, libc::SYS_faccessat2, libc::SYS_umask,
        libc::SYS_fgetxattr, libc::SYS_flistxattr, libc::SYS_pipe2,
        // memory (guest RAM, dlopen of libkrun)
        libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_mprotect,
        libc::SYS_madvise, libc::SYS_brk,
        // memfd_create: a forkable machine (`machine start --forkable`) backs its
        // guest RAM with a memfd so clones can MAP_PRIVATE it copy-on-write. Used
        // only on the fork base, but harmless (anonymous in-memory file, no host
        // fs reach) to allow for every VM. Without it a forkable boot is SIGSYS-
        // killed under `seccomp=enforce`.
        libc::SYS_memfd_create,
        // KVM + device ioctls, eventfd plumbing
        libc::SYS_ioctl, libc::SYS_eventfd2,
        // epoll / poll event loops (virtio, vsock/TSI)
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait, libc::SYS_ppoll,
        // timerfd — the virtio-net host network stack's event loop arms timers
        // (TCP retransmit/poll) via timerfd; without these the VMM is SIGSYS-killed
        // at start as soon as a published port enables virtio-net.
        libc::SYS_timerfd_create, libc::SYS_timerfd_settime, libc::SYS_timerfd_gettime,
        // sockets (vsock/TSI data path, host networking)
        libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect, libc::SYS_bind,
        libc::SYS_listen, libc::SYS_accept, libc::SYS_sendto, libc::SYS_recvfrom,
        libc::SYS_sendmsg, libc::SYS_sendmmsg, libc::SYS_recvmsg, libc::SYS_setsockopt,
        libc::SYS_getsockopt, libc::SYS_shutdown,
        // threads & synchronization (vCPU/worker threads, render-thread priority)
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_futex, libc::SYS_set_robust_list,
        libc::SYS_set_tid_address, libc::SYS_rseq, libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity, libc::SYS_sched_setaffinity, libc::SYS_sched_getparam,
        libc::SYS_sched_setscheduler, libc::SYS_setpriority, libc::SYS_membarrier,
        libc::SYS_gettid, libc::SYS_getpid, libc::SYS_getppid,
        // signals
        libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack, libc::SYS_signalfd4, libc::SYS_kill, libc::SYS_tgkill,
        libc::SYS_tkill,
        // time
        libc::SYS_clock_nanosleep, libc::SYS_nanosleep, libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        // process lifecycle & misc identity/limits
        libc::SYS_wait4, libc::SYS_exit, libc::SYS_exit_group, libc::SYS_restart_syscall,
        libc::SYS_prctl, libc::SYS_prlimit64, libc::SYS_getrusage,
        libc::SYS_sysinfo, libc::SYS_uname, libc::SYS_getrandom,
        libc::SYS_getuid, libc::SYS_geteuid, libc::SYS_getgid, libc::SYS_getegid,
        // capget/capset: virtiofs drops CAP_FSETID around a passthrough write/
        // create (`drop_effective_cap`, via the `caps` crate) so the kernel
        // strips setuid/setgid bits on non-owner writes — same root-VMM /
        // non-root-guest passthrough path as setres{u,g}id below. A cap-dropped
        // VMM can't raise caps outside its bounding set, so this grants nothing.
        libc::SYS_capget, libc::SYS_capset, libc::SYS_setpgid,
        // accept4 + sock{name,peername}: the published-port listener threads
        // (smolvm-tcp-*) and virtio-net path. Rust's TcpListener uses accept4,
        // not accept — the audit run logged these (288/51/52 on x86_64) because
        // they post-date the original capture.
        libc::SYS_accept4, libc::SYS_getsockname, libc::SYS_getpeername,
        // virtiofs passthrough executes the guest's FS mutations on the HOST, so
        // the host VMM issues the full *at family + fd/symlink xattrs. Derived
        // from fs/linux/passthrough.rs (NOT just the audit trace, which only
        // exercised mkdirat/symlinkat) so a guest that mknod/link/setxattr/chmod
        // doesn't trip `enforce`. SYS_* exist on both arches; BTreeMap dedups any
        // overlap with the arch-gated lists below.
        libc::SYS_mkdirat, libc::SYS_mknodat, libc::SYS_symlinkat, libc::SYS_linkat,
        libc::SYS_unlinkat, libc::SYS_renameat2, libc::SYS_fchmodat, libc::SYS_fchownat,
        libc::SYS_fchmod, libc::SYS_fdatasync, libc::SYS_utimensat, libc::SYS_copy_file_range,
        libc::SYS_fsetxattr, libc::SYS_fremovexattr,
        libc::SYS_lgetxattr, libc::SYS_lsetxattr, libc::SYS_llistxattr, libc::SYS_lremovexattr,
        // virtiofs scopes each request to the guest process's uid/gid before
        // touching the host fs (so DAC checks run as the guest user, not as a
        // root VMM) via per-thread setres{u,g}id — passthrough.rs `scoped_cred!`
        // / `set_creds`. Reached only when the VMM keeps CAP_SETUID (root, no
        // per-VM uid drop) AND a NON-root guest process does fs I/O: a path a
        // single-uid (all-root) trace never exercises, which is why a diverse-
        // workload review caught it and the original audit didn't. Without these
        // an unprivileged guest writing through virtiofs SIGSYS-kills the VMM
        // under `enforce`. Safe to allow: a capability-dropped (uid-isolated)
        // VMM still can't escalate — the kernel enforces CAP_SETUID regardless,
        // so the syscall just EPERMs. Matches virtiofsd's own allowlist.
        libc::SYS_setresuid, libc::SYS_setresgid,
    ];

    // Legacy syscalls present only on x86_64; aarch64 exposes only the *at/p
    // variants (already in the common list above) plus a few of its own. These
    // libc::SYS_* constants don't exist on the other arch, so they must be
    // arch-gated. The arm64 set is a starting point — refine from an audit run.
    #[cfg(target_arch = "x86_64")]
    allowed.extend_from_slice(&[
        libc::SYS_dup2,
        libc::SYS_readlink,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_access,
        libc::SYS_epoll_wait,
        libc::SYS_poll,
        libc::SYS_arch_prctl,
    ]);
    #[cfg(target_arch = "aarch64")]
    allowed.extend_from_slice(&[libc::SYS_unlinkat, libc::SYS_renameat2, libc::SYS_mkdirat]);

    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        allowed.iter().map(|&nr| (nr, Vec::new())).collect();

    let mismatch_action = if enforce {
        SeccompAction::KillProcess
    } else {
        SeccompAction::Log
    };
    let target_arch = if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        TargetArch::x86_64
    };
    let filter = SeccompFilter::new(rules, mismatch_action, SeccompAction::Allow, target_arch)
        .map_err(|e| e.to_string())?;
    let program: BpfProgram = match filter.try_into() {
        Ok(prog) => prog,
        Err(e) => return Err(e.to_string()),
    };
    Ok(program)
}

/// No-op stub where seccomp isn't applicable (macOS dev, Linux arches other
/// than x86_64/aarch64).
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn install_seccomp_filter(_enforce: bool) -> std::result::Result<(), String> {
    Ok(())
}

// ============================================================================
// Landlock filesystem restriction for the VM boot subprocess
//
// Confines the VMM's filesystem view so a guest→VMM escape cannot read or write
// host files outside what this specific VM needs: read+exec on the rootfs / libs
// / system dirs, read-write on this VM's own data dir + the device nodes a VMM
// uses. Other tenants' VM data, host secrets, and the rest of the filesystem
// become inaccessible. Best-effort and Linux-only (Landlock LSM); a no-op stub
// elsewhere. Paths are derived per-VM from the boot config by the caller.
//
// MUST be installed AFTER cgroup placement (which writes /sys/fs/cgroup) and
// BEFORE the seccomp filter (whose allowlist omits the landlock_* syscalls).
// ============================================================================

/// Restrict this process and its descendants to the given filesystem paths via
/// Landlock: `read_exec` paths get read+execute, `read_write` paths get full
/// access; everything else on the host becomes inaccessible. Missing paths are
/// silently skipped. Returns `Err` only if the ruleset can't be created/applied
/// at all (e.g. kernel without Landlock) — the caller decides fail-open/closed.
#[cfg(target_os = "linux")]
pub fn restrict_filesystem(
    read_exec: &[std::path::PathBuf],
    read_write: &[std::path::PathBuf],
) -> std::result::Result<(), String> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };

    // ABI V1 is supported on every Landlock-capable kernel; it governs
    // read/write/execute and directory mutation — enough to confine file access.
    let abi = ABI::V1;
    let ro = AccessFs::from_read(abi);
    let rw = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| e.to_string())?
        .create()
        .map_err(|e| e.to_string())?;

    for p in read_exec {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, ro))
                .map_err(|e| e.to_string())?;
        }
    }
    for p in read_write {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, rw))
                .map_err(|e| e.to_string())?;
        }
    }

    ruleset.restrict_self().map_err(|e| e.to_string())?;
    Ok(())
}

/// No-op stub where Landlock isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn restrict_filesystem(
    _read_exec: &[std::path::PathBuf],
    _read_write: &[std::path::PathBuf],
) -> std::result::Result<(), String> {
    Ok(())
}

// ============================================================================
// Drop the VMM to an unprivileged uid (bounds escape blast radius)
//
// Run each VMM as a powerless, ideally per-VM uid so a guest→VMM escape can't
// signal/ptrace the serve process or other tenants' VMs, nor touch root-owned
// host files. Requires the spawning supervisor to be privileged
// (CAP_SETUID/SETGID — i.e. serve as root) AND this VM's data dir + disks +
// socket dir to be owned by `uid` (the VMM opens them after the drop). The
// `kvm` group is kept (supplementary) so /dev/kvm stays openable.
//
// Order in the boot path: AFTER cgroup placement (which needs privilege to write
// cgroup.procs) and BEFORE Landlock/seccomp (which work unprivileged once
// no_new_privs is set). See docs/runtime-isolation-hardening.md.
// ============================================================================

/// Look up the `kvm` group's gid, so it can be kept as a supplementary group
/// across the privilege drop (the VMM needs `/dev/kvm`).
#[cfg(target_os = "linux")]
fn kvm_group_gid() -> Option<libc::gid_t> {
    let grp = unsafe { libc::getgrnam(c"kvm".as_ptr()) };
    if grp.is_null() {
        None
    } else {
        Some(unsafe { (*grp).gr_gid })
    }
}

/// Irreversibly drop this process to (`uid`, `gid`), keeping only the `kvm`
/// supplementary group. Returns `Err` if any step fails so the caller can fail
/// closed — the VMM must never run with more privilege than requested.
///
/// Uses `setgroups` → `setgid` → `setuid` (gid before uid, since `setgid` needs
/// privilege the `setuid` would shed), then verifies uid 0 cannot be regained.
#[cfg(target_os = "linux")]
pub fn drop_privileges(uid: u32, gid: u32) -> std::result::Result<(), String> {
    unsafe {
        // Keep only kvm as a supplementary group (drop all others).
        let groups: Vec<libc::gid_t> = kvm_group_gid().into_iter().collect();
        if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
            return Err(format!("setgroups: {}", std::io::Error::last_os_error()));
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(format!(
                "setgid({gid}): {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            return Err(format!(
                "setuid({uid}): {}",
                std::io::Error::last_os_error()
            ));
        }
        // Defense-in-depth: a complete drop (real+effective+saved) means uid 0
        // can no longer be regained. If it can, the drop was partial — fail.
        if uid != 0 && libc::setuid(0) == 0 {
            return Err("privilege drop incomplete: regained uid 0".into());
        }
    }
    Ok(())
}

/// No-op stub where privilege dropping isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn drop_privileges(_uid: u32, _gid: u32) -> std::result::Result<(), String> {
    Ok(())
}

// ============================================================================
// Per-VM uid allocation (defense-in-depth for a guest→VMM escape)
//
// When the launcher runs privileged (root `serve`), each VMM is dropped to its
// own dedicated unprivileged uid so a guest→VMM escape is contained to that one
// VM: it can't ptrace/read other tenants' VMMs (different uid), reach their
// disks (different ownership), or touch root/host files. The uid is derived
// deterministically from the VM's data dir (stable across restarts, no
// allocation state), mapped into a high range well clear of system, regular,
// `nobody`, and systemd-DynamicUser uids. A fork clone uses its GOLDEN's uid so
// it can map the golden's guest-RAM memfd via /proc/<golden>/fd (same uid).
// ============================================================================

/// Base of the reserved per-VM uid range. Above normal system (<1000), user
/// (1000–60000), `nobody` (65534), and systemd DynamicUser (61184–65519) uids.
#[cfg(target_os = "linux")]
const VM_UID_BASE: u32 = 2_000_000;
/// Span of the per-VM uid range: the allocator hands out the lowest free uid in
/// `[BASE, BASE+SPAN)`. 100M is far more than any node hosts at once.
#[cfg(target_os = "linux")]
const VM_UID_SPAN: u32 = 100_000_000;

/// Whether per-VM uid isolation applies here: the launcher is privileged (so it
/// can chown + setuid) and the operator hasn't opted out with
/// `SMOLVM_VM_UID_DROP=off`.
#[cfg(target_os = "linux")]
pub fn vm_uid_drop_active() -> bool {
    let is_root = unsafe { libc::geteuid() } == 0;
    let opted_out =
        std::env::var_os("SMOLVM_VM_UID_DROP").as_deref() == Some(std::ffi::OsStr::new("off"));
    is_root && !opted_out
}

/// No-op where the uid drop isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn vm_uid_drop_active() -> bool {
    false
}

/// Relocate all smolvm state under a single system data root by pointing `HOME`
/// at it before any path is computed — every `dirs::`-derived path (VM dirs,
/// agent rootfs, templates, server DB) follows. This is what lets per-VM uid
/// isolation's dropped uids traverse to their data (an XDG-under-a-700-home
/// layout can't). `SMOLVM_DATA_DIR` is honored for **every** command (so the CLI
/// and serve agree); `allow_auto` additionally defaults to `/var/lib/smolvm` when
/// privileged with the uid drop active and no XDG override (serve only — a
/// one-off root CLI invocation shouldn't silently switch roots). Must be called
/// single-threaded, before the tokio runtime, so `set_var` is safe.
#[cfg(target_os = "linux")]
pub fn apply_system_data_root(allow_auto: bool) {
    let root = if let Some(explicit) = std::env::var_os("SMOLVM_DATA_DIR") {
        std::path::PathBuf::from(explicit)
    } else if allow_auto
        && vm_uid_drop_active()
        && std::env::var_os("XDG_CACHE_HOME").is_none()
        && std::env::var_os("XDG_DATA_HOME").is_none()
    {
        std::path::PathBuf::from("/var/lib/smolvm")
    } else {
        return;
    };
    match std::fs::create_dir_all(&root) {
        Ok(()) => {
            use std::os::unix::fs::PermissionsExt;
            // 0755 so dropped VMM uids can traverse to their data.
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755));
        }
        Err(e) => {
            tracing::warn!(root = %root.display(), error = %e, "failed to create smolvm data root")
        }
    }
    // Registry auth (crane/docker) falls back to `$HOME/.docker`, which we're about
    // to move off the operator's real home — pin DOCKER_CONFIG to the ORIGINAL
    // `~/.docker` (if it exists and the operator hasn't set DOCKER_CONFIG) so
    // private image pulls keep finding their credentials after the relocation.
    if std::env::var_os("DOCKER_CONFIG").is_none() {
        if let Some(dir) = dirs::home_dir()
            .map(|h| h.join(".docker"))
            .filter(|d| d.is_dir())
        {
            std::env::set_var("DOCKER_CONFIG", dir);
        }
    }
    std::env::set_var("HOME", &root);
    std::env::remove_var("XDG_CACHE_HOME");
    std::env::remove_var("XDG_DATA_HOME");
    std::env::remove_var("XDG_CONFIG_HOME");
    tracing::info!(data_root = %root.display(), "smolvm state rooted at a system data dir");
}

/// No-op where the data root isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn apply_system_data_root(_allow_auto: bool) {}

/// Per-VM uid isolation needs every ancestor of the data root to be traversable
/// (others-execute) by the drop uid, or the dropped VMM can't reach its own
/// files (it fails with a cryptic readiness timeout). Returns the first ancestor
/// of `path` (walking up) that a non-owner can't traverse, or `None` if the whole
/// chain is fine. `serve` uses it to warn the operator up front.
#[cfg(target_os = "linux")]
pub fn first_nontraversable_ancestor(path: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let mut cur = Some(path);
    while let Some(dir) = cur {
        if let Ok(meta) = std::fs::metadata(dir) {
            if meta.is_dir() && meta.permissions().mode() & 0o001 == 0 {
                return Some(dir.to_path_buf());
            }
        }
        cur = dir.parent();
    }
    None
}

/// No-op where the uid drop isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn first_nontraversable_ancestor(_path: &std::path::Path) -> Option<std::path::PathBuf> {
    None
}

/// The VM key recorded in registry marker `registry_dir/<uid>`, if present.
#[cfg(target_os = "linux")]
fn uid_marker_key(registry_dir: &std::path::Path, uid: u32) -> Option<String> {
    std::fs::read_to_string(registry_dir.join(uid.to_string()))
        .ok()
        .map(|s| s.trim().to_string())
}

/// The uid already registered to `vm_key` (scan), or `None` if unallocated.
#[cfg(target_os = "linux")]
fn registered_uid(registry_dir: &std::path::Path, vm_key: &str) -> Option<u32> {
    for e in std::fs::read_dir(registry_dir).ok()?.flatten() {
        let uid = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok());
        if let Some(uid) = uid {
            if uid_marker_key(registry_dir, uid).as_deref() == Some(vm_key) {
                return Some(uid);
            }
        }
    }
    None
}

/// Allocate a stable, **collision-free** unprivileged uid for the VM identified
/// by `vm_key` (its data-dir hash), recording the assignment in `registry_dir`
/// so no two live VMs ever share a uid. Idempotent — the same key returns the
/// same uid until [`free_vm_uid`] releases it; the result is cached in
/// `key_dir/.vm-uid` to skip the scan on restart. Claims the lowest free uid in
/// the reserved range atomically (`O_EXCL`) so concurrent boots can't collide.
#[cfg(target_os = "linux")]
pub fn allocate_vm_uid(
    registry_dir: &std::path::Path,
    key_dir: &std::path::Path,
    vm_key: &str,
) -> std::io::Result<u32> {
    std::fs::create_dir_all(registry_dir)?;
    let cache = key_dir.join(".vm-uid");
    // Fast path: a cached uid whose marker still belongs to us.
    if let Some(uid) = std::fs::read_to_string(&cache)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        if uid_marker_key(registry_dir, uid).as_deref() == Some(vm_key) {
            return Ok(uid);
        }
    }
    // Registered under our key already (cache lost)?
    if let Some(uid) = registered_uid(registry_dir, vm_key) {
        let _ = std::fs::write(&cache, uid.to_string());
        return Ok(uid);
    }
    // Claim the lowest free uid atomically. A uid whose marker points at a VM
    // whose data dir is gone is STALE — a delete path that didn't free it, or a
    // crash — so reclaim it. This makes the registry self-healing across every
    // delete path (no leak even if some path forgets to call `free_vm_uid`). The
    // VM data dirs are the registry's sibling (`<…>/smolvm/uids` ⇄ `…/vms`); a
    // marker only exists after its VM's data dir was created, so "marker present
    // but data dir absent" reliably means deleted, never mid-boot.
    let vms_dir = registry_dir.parent().map(|p| p.join("vms"));
    for uid in VM_UID_BASE..VM_UID_BASE.saturating_add(VM_UID_SPAN) {
        let marker = registry_dir.join(uid.to_string());
        if let Some(key) = uid_marker_key(registry_dir, uid) {
            let live = vms_dir
                .as_ref()
                .map(|v| v.join(&key).exists())
                .unwrap_or(true);
            if live {
                continue; // held by a live VM
            }
            let _ = std::fs::remove_file(&marker); // stale → reclaim below
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(vm_key.as_bytes())?;
                let _ = std::fs::write(&cache, uid.to_string());
                return Ok(uid);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue, // raced
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("per-VM uid range exhausted"))
}

/// Release the uid registered to the VM at `key_dir` (on VM delete) so it can be
/// reused. No-op if the VM had no uid (drop inactive, or a fork clone — which
/// shares its golden's uid and never claims its own). Linux-only.
#[cfg(target_os = "linux")]
pub fn free_vm_uid(registry_dir: &std::path::Path, key_dir: &std::path::Path) {
    if let Some(uid) = std::fs::read_to_string(key_dir.join(".vm-uid"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        let _ = std::fs::remove_file(registry_dir.join(uid.to_string()));
    }
}

/// No-op where the uid drop isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn free_vm_uid(_registry_dir: &std::path::Path, _key_dir: &std::path::Path) {}

/// The `(uid, gid)` a VM's VMM should drop to, allocated **collision-free** from
/// `registry_dir`. Returns:
/// - `None` — the drop doesn't apply (unprivileged launcher, or
///   `SMOLVM_VM_UID_DROP=off`); boot proceeds without a drop.
/// - `Some(Err(_))` — the drop is **active but allocation failed**; the caller
///   MUST refuse to boot (fail closed — never silently run the VMM over-
///   privileged, the same contract as `drop_privileges`).
/// - `Some(Ok((uid, gid)))` — drop to this id.
///
/// A fork clone (`snapshot_dir` set, laid out as
/// `<golden_dir>/fork-snapshots/<clone>`) resolves to the GOLDEN's uid so it can
/// map the golden's memfd. gid mirrors uid (a per-VM group).
#[cfg(target_os = "linux")]
pub fn vm_drop_ids(
    registry_dir: &std::path::Path,
    data_dir: &std::path::Path,
    snapshot_dir: Option<&std::path::Path>,
) -> Option<std::io::Result<(u32, u32)>> {
    if !vm_uid_drop_active() {
        return None;
    }
    let key_dir = match snapshot_dir {
        Some(snap) => snap.parent().and_then(|p| p.parent()).unwrap_or(data_dir),
        None => data_dir,
    };
    let Some(vm_key) = key_dir.file_name().and_then(|n| n.to_str()) else {
        return Some(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VM data dir name is not valid UTF-8",
        )));
    };
    Some(allocate_vm_uid(registry_dir, key_dir, vm_key).map(|uid| (uid, uid)))
}

/// No-op where the uid drop isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn vm_drop_ids(
    _registry_dir: &std::path::Path,
    _data_dir: &std::path::Path,
    _snapshot_dir: Option<&std::path::Path>,
) -> Option<std::io::Result<(u32, u32)>> {
    None
}

/// Add others-execute to `dir` and every ancestor that lacks it, so a dropped
/// VMM uid can traverse to it. Execute-only (no read): traversal works but the
/// dirs can't be listed and file contents stay governed by their own perms.
/// Used under uid isolation for the data/rootfs/template path chains. Idempotent,
/// best-effort. Linux-only.
#[cfg(target_os = "linux")]
pub fn ensure_traversable(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if d.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = std::fs::metadata(d) {
            let mode = meta.permissions().mode();
            if meta.is_dir() && mode & 0o001 == 0 {
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(mode | 0o001));
            }
        }
        cur = d.parent();
    }
}

/// No-op where the uid drop isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn ensure_traversable(_dir: &std::path::Path) {}

/// Recursively `lchown` `path` to `(uid, gid)` (symlinks not followed). Used by
/// the privileged launcher to hand a VM's data dir + disks + sockets to the uid
/// its VMM will drop to. Linux-only; the caller is root.
#[cfg(target_os = "linux")]
pub fn chown_tree(path: &std::path::Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Recurse into real directories only (not symlinked ones).
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_dir() {
        for entry in std::fs::read_dir(path)? {
            chown_tree(&entry?.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// No-op where chown isn't applicable (macOS dev).
#[cfg(not(target_os = "linux"))]
pub fn chown_tree(_path: &std::path::Path, _uid: u32, _gid: u32) -> std::io::Result<()> {
    Ok(())
}

/// Build a user namespace whose single-entry uid/gid maps make on-disk id 0
/// appear as `(uid, gid)` *through an idmapped mount*, and return an fd to its
/// `/proc/<pid>/ns/user` (the open fd keeps the namespace alive after the helper
/// process exits).
///
/// Mechanics (validated against kernels 6.17/6.18): fork a helper that
/// `unshare(CLONE_NEWUSER)`s and blocks; the parent (still privileged) writes the
/// child's `uid_map`/`gid_map`. A map line is `<nsid> <hostid> <count>`, and an
/// idmapped mount treats the ON-DISK id as an nsid and maps it DOWN to a host
/// kuid — so to surface on-disk 0 as host `uid` we write `0 <uid> 1` (NOT
/// `<uid> 0 1`, which surfaces the overflow uid and denies every read). The
/// parent MUST wait until the child is inside the new userns before writing the
/// maps (a two-pipe handshake), or the write races the `unshare` and fails EPERM.
/// `setgroups` is denied before `gid_map` (required to write a gid map).
#[cfg(target_os = "linux")]
fn make_idmap_userns(uid: u32, gid: u32) -> std::io::Result<libc::c_int> {
    let errno = || std::io::Error::last_os_error();
    // ready: child -> parent (userns created); go: parent -> child (maps written).
    let mut ready = [-1i32; 2];
    let mut go = [-1i32; 2];
    if unsafe { libc::pipe(ready.as_mut_ptr()) } != 0 {
        return Err(errno());
    }
    if unsafe { libc::pipe(go.as_mut_ptr()) } != 0 {
        let e = errno();
        unsafe {
            libc::close(ready[0]);
            libc::close(ready[1]);
        }
        return Err(e);
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = errno();
        unsafe {
            libc::close(ready[0]);
            libc::close(ready[1]);
            libc::close(go[0]);
            libc::close(go[1]);
        }
        return Err(e);
    }
    if pid == 0 {
        // CHILD: async-signal-safe calls only (post-fork in a possibly threaded
        // process). Become a fresh userns, signal the parent, block until the maps
        // are written, then exit — the parent's open ns fd keeps the userns alive.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            unsafe { libc::_exit(1) };
        }
        let sig: [u8; 1] = *b"r";
        unsafe {
            libc::write(ready[1], sig.as_ptr() as *const libc::c_void, 1);
        }
        let mut got = 0u8;
        unsafe {
            libc::read(go[0], &mut got as *mut u8 as *mut libc::c_void, 1);
            libc::_exit(0);
        }
    }

    // PARENT. Close the ends we don't use, then wait for the child's "ready".
    unsafe {
        libc::close(ready[1]);
        libc::close(go[0]);
    }
    let mut got = 0u8;
    let _ = unsafe { libc::read(ready[0], &mut got as *mut u8 as *mut libc::c_void, 1) };

    // Write the maps from the privileged parent. A single entry mapping host id
    // `uid`/`gid` is permitted via the ns-creator's CAP_SETUID/CAP_SETGID path.
    let finish = |result: std::io::Result<libc::c_int>| -> std::io::Result<libc::c_int> {
        let go_w: [u8; 1] = *b"x";
        unsafe {
            libc::write(go[1], go_w.as_ptr() as *const libc::c_void, 1);
            libc::close(go[1]);
            libc::close(ready[0]);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        result
    };
    if let Err(e) = std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n")) {
        return finish(Err(e));
    }
    // Must deny setgroups(2) before a gid_map may be written in a userns.
    let _ = std::fs::write(format!("/proc/{pid}/setgroups"), "deny");
    if let Err(e) = std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n")) {
        return finish(Err(e));
    }
    let ns_path = std::ffi::CString::new(format!("/proc/{pid}/ns/user")).unwrap();
    let nsfd = unsafe { libc::open(ns_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if nsfd < 0 {
        return finish(Err(errno()));
    }
    finish(Ok(nsfd))
}

/// Present the root-owned shared pack at `shared` onto the per-VM mountpoint
/// `target` via an idmapped bind mount that maps on-disk uid/gid 0 -> `(uid, gid)`
/// — so the VMM (about to drop to that uid) reads every file as its owner, while
/// the underlying shared copy stays root-only on disk (a sibling VM's uid can't
/// read it directly). This is what lets one root-owned shared copy replace the
/// per-machine extract + chown while preserving the per-VM uid isolation (#456).
///
/// The mount is made in a fresh **private** mount namespace, so it is visible only
/// to this VMM process (and the libkrun threads it later spawns) and is torn down
/// automatically when the process exits — no teardown plumbing, no propagation to
/// the host or sibling VMs. MUST run while still privileged (CAP_SYS_ADMIN) and
/// BEFORE Landlock/seccomp/`drop_privileges`. Linux ≥ 5.12.
#[cfg(target_os = "linux")]
pub fn setup_pack_idmap_mount(
    shared: &std::path::Path,
    target: &std::path::Path,
    uid: u32,
    gid: u32,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let errno = || std::io::Error::last_os_error();

    // Our own mount namespace: the idmap mount lives and dies with this process.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(errno());
    }
    // Don't propagate mounts back into the host's mount namespace.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(errno());
    }

    let userns_fd = make_idmap_userns(uid, gid)?;
    let close_userns = || unsafe {
        libc::close(userns_fd);
    };

    let shared_c = std::ffi::CString::new(shared.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let target_c = std::ffi::CString::new(target.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // Clone the shared subtree into a detached mount object. mount_setattr's idmap
    // requires a freshly-cloned mount with no other users, which OPEN_TREE_CLONE
    // provides; AT_RECURSIVE covers any submounts.
    let open_flags: libc::c_uint = libc::OPEN_TREE_CLONE
        | libc::AT_RECURSIVE as libc::c_uint
        | libc::O_CLOEXEC as libc::c_uint;
    let tree = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            shared_c.as_ptr(),
            open_flags,
        )
    } as libc::c_int;
    if tree < 0 {
        let e = errno();
        close_userns();
        return Err(e);
    }
    let close_tree = || unsafe {
        libc::close(tree);
    };

    // Attach the idmap (recursively) to the cloned tree.
    let mut attr: libc::mount_attr = unsafe { std::mem::zeroed() };
    attr.attr_set = libc::MOUNT_ATTR_IDMAP;
    attr.userns_fd = userns_fd as u64;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree,
            c"".as_ptr(),
            (libc::AT_EMPTY_PATH | libc::AT_RECURSIVE) as libc::c_uint,
            &attr as *const libc::mount_attr,
            std::mem::size_of::<libc::mount_attr>() as libc::size_t,
        )
    };
    if rc != 0 {
        let e = errno();
        close_tree();
        close_userns();
        return Err(e);
    }

    // Move the now-idmapped tree onto the per-VM mountpoint.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree,
            c"".as_ptr(),
            libc::AT_FDCWD,
            target_c.as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH as libc::c_uint,
        )
    };
    let result = if rc != 0 { Err(errno()) } else { Ok(()) };
    // The kernel holds its own references now; our fds are no longer needed.
    close_tree();
    close_userns();
    result
}

/// PIDs of detached VM boot subprocesses to reap. Registered by
/// [`register_vm_child`] right after spawn (the boot subprocess is intentionally
/// detached — own process group, never `wait()`ed — so it becomes a zombie on
/// exit). Swept by [`reap_vm_children`] from the supervisor tick.
///
/// This is the SELECTIVE reaper used by `serve`, replacing a global
/// `waitpid(-1)` SIGCHLD handler. An unscoped `waitpid(-1)` steals the exit
/// status from ANY exited child — including the `busctl` / `mkfs` / `resize2fs`
/// subprocesses that `.output()`/`.wait()` callers (e.g. systemd-scope adoption)
/// are actively waiting on — producing `ECHILD` ("No child processes") races
/// under concurrent VM boots. Reaping only registered VM PIDs leaves those
/// transient subprocesses to their own waits. Mirrors the guest agent's
/// `BG_CHILDREN` pattern (`crates/smolvm-agent/src/main.rs`).
static VM_CHILDREN: OnceLock<Mutex<Vec<i32>>> = OnceLock::new();

fn vm_children() -> &'static Mutex<Vec<i32>> {
    VM_CHILDREN.get_or_init(|| Mutex::new(Vec::new()))
}

/// Track a detached VM boot subprocess PID so a later [`reap_vm_children`] sweep
/// reaps it. The Rust `Child` handle's `Drop` does not `wait()`, so the caller
/// can let it drop after recording the PID.
pub fn register_vm_child(pid: i32) {
    vm_children().lock().unwrap().push(pid);
}

/// Reap any exited registered VM children (non-blocking, per-PID). Called from
/// the serve supervisor tick. Scoped to registered PIDs so it never steals an
/// exit status from a sibling `.output()`/`.wait()` (the `ECHILD` fix).
#[cfg(target_os = "linux")]
pub fn reap_vm_children() {
    let mut guard = vm_children().lock().unwrap();
    guard.retain(|&pid| {
        let ret = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        match ret {
            // >0 = reaped; drop from tracking.
            r if r > 0 => false,
            // 0 = still running; keep for the next sweep.
            0 => true,
            // <0 = error (typically ECHILD — already gone). Drop either way.
            _ => false,
        }
    });
}

/// No-op on non-Linux: VM scope adoption + the serve supervisor reaper are
/// Linux-only; nothing registers VM children here.
#[cfg(not(target_os = "linux"))]
pub fn reap_vm_children() {}

/// Install a GLOBAL SIGCHLD handler that reaps every terminated child via
/// `waitpid(-1, WNOHANG)`. Used only by the `pack_run` fork-pool paths (single
/// process, no concurrent `.output()` subprocesses racing it).
///
/// **Do NOT use this in `serve`** — its concurrent VM boots run `busctl`/`mkfs`
/// `.output()` calls that this handler would reap out from under, causing
/// `ECHILD`. `serve` uses the selective [`register_vm_child`]/[`reap_vm_children`]
/// pair instead.
///
/// The handler is only installed once; subsequent calls are no-ops.
///
/// # Safety
///
/// This function installs a signal handler which must be async-signal-safe.
/// The handler only calls waitpid() which is safe.
#[cfg(unix)]
pub fn install_sigchld_handler() {
    // Only install once
    if SIGCHLD_HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigchld_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
        libc::sigemptyset(&mut sa.sa_mask);

        if libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) != 0 {
            // Failed to install handler, reset flag
            SIGCHLD_HANDLER_INSTALLED.store(false, Ordering::SeqCst);
            tracing::warn!("failed to install SIGCHLD handler");
        } else {
            tracing::debug!("installed SIGCHLD handler for zombie reaping");
        }
    }
}

/// Windows has no SIGCHLD / zombie-reaping model; child cleanup is handled by
/// the OS when the last handle closes. This is a no-op.
#[cfg(not(unix))]
pub fn install_sigchld_handler() {}

/// SIGCHLD signal handler that reaps zombie children.
///
/// This handler is async-signal-safe as it only calls waitpid().
#[cfg(unix)]
extern "C" fn sigchld_handler(_sig: libc::c_int) {
    // Reap all terminated children (non-blocking)
    // Loop until no more children to reap
    loop {
        let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            // No more children to reap (0) or error (-1)
            break;
        }
        // Successfully reaped a child, continue to check for more
    }
}

/// Check if a process is alive.
///
/// Returns true if the process exists and is running.
#[cfg(unix)]
pub fn is_alive(pid: Pid) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Check if a process is alive (Windows).
///
/// Opens the process with minimal rights and checks its exit code; a process
/// that is still running reports `STILL_ACTIVE`. Falls back to `false` if the
/// handle cannot be opened (process gone or access denied).
#[cfg(windows)]
pub fn is_alive(pid: Pid) -> bool {
    win::process_is_alive(pid as u32)
}

/// Wait for a process to exit (non-blocking check).
///
/// Returns `Some(exit_code)` if the process has exited, `None` if still running.
/// Handles EINTR by retrying the waitpid call.
#[cfg(unix)]
pub fn try_wait(pid: Pid) -> Option<i32> {
    loop {
        let mut status: libc::c_int = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };

        if result == pid {
            // Process exited
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                -1
            };
            return Some(exit_code);
        } else if result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                // EINTR - interrupted by signal, retry
                continue;
            }
            // ECHILD: not our child (e.g., session-leader reparented to init).
            // Return None so callers fall back to is_alive() (kill -0) polling.
            return None;
        } else {
            // Still running
            return None;
        }
    }
}

/// Wait for a process to exit (non-blocking check) — Windows.
#[cfg(windows)]
pub fn try_wait(pid: Pid) -> Option<i32> {
    win::process_try_wait(pid as u32)
}

/// Wait for a process to exit (blocking).
///
/// Returns the exit code. Handles EINTR by retrying the waitpid call.
#[cfg(unix)]
pub fn wait(pid: Pid) -> i32 {
    loop {
        let mut status: libc::c_int = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                // EINTR - interrupted by signal, retry
                continue;
            }
            return -1;
        }

        return if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            -1
        };
    }
}

/// Wait for a process to exit (blocking) — Windows.
#[cfg(windows)]
pub fn wait(pid: Pid) -> i32 {
    win::process_wait(pid as u32)
}

/// Send SIGTERM to a process.
///
/// Returns true if the signal was sent successfully.
#[cfg(unix)]
pub fn terminate(pid: Pid) -> bool {
    unsafe { libc::kill(pid, libc::SIGTERM) == 0 }
}

/// Request termination of a process (Windows).
///
/// There is no graceful SIGTERM equivalent; this calls `TerminateProcess`.
#[cfg(windows)]
pub fn terminate(pid: Pid) -> bool {
    win::process_kill(pid as u32)
}

/// Send SIGKILL to a process.
///
/// Returns true if the signal was sent successfully.
#[cfg(unix)]
pub fn kill(pid: Pid) -> bool {
    unsafe { libc::kill(pid, libc::SIGKILL) == 0 }
}

/// Forcibly terminate a process (Windows) via `TerminateProcess`.
#[cfg(windows)]
pub fn kill(pid: Pid) -> bool {
    win::process_kill(pid as u32)
}

/// Get the start time of a process (seconds since epoch).
///
/// Used alongside PID to create a stable process identity that survives
/// PID reuse. If the process at a given PID has a different start time
/// than expected, it's a different process (PID was recycled).
#[cfg(target_os = "macos")]
pub fn process_start_time(pid: Pid) -> Option<u64> {
    // Use proc_pidinfo(PROC_PIDTBSDINFO) — the modern macOS API for
    // process information, which has stable struct layouts.
    extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    const PROC_PIDTBSDINFO: libc::c_int = 3;

    /// Subset of `struct proc_bsdinfo` from <libproc.h>.
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        _rfu_1: u32,
        pbi_comm: [u8; 16], // MAXCOMLEN
        pbi_name: [u8; 32], // 2 * MAXCOMLEN
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<ProcBsdInfo>() as libc::c_int,
        )
    };
    if ret > 0 {
        let usec = info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec;
        // proc_pidinfo can return a zeroed struct for session-leader children
        // (e.g., VM processes that called setsid()). Treat 0 as unavailable.
        if usec > 0 {
            Some(usec)
        } else {
            None
        }
    } else {
        None
    }
}

/// Get the start time of a process (clock ticks since boot from /proc/pid/stat field 22).
#[cfg(target_os = "linux")]
pub fn process_start_time(pid: Pid) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Format: pid (comm) state ppid ... starttime ...
    // comm can contain spaces and parentheses, so find the last ')' first.
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat.get(after_comm..)?.split_whitespace().collect();
    // After ") ", fields are: state(0) ppid(1) ... starttime(19)
    fields.get(19)?.parse::<u64>().ok()
}

/// Get the start time of a process (Windows process creation FILETIME).
#[cfg(windows)]
pub fn process_start_time(pid: Pid) -> Option<u64> {
    win::process_start_time(pid as u32)
}

/// Get the start time of a process (stub for unsupported platforms).
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub fn process_start_time(_pid: Pid) -> Option<u64> {
    None
}

/// Sampled stats for one process.
#[derive(Debug, Clone, Copy)]
pub struct ProcessStats {
    /// Cumulative CPU time (user + system) in nanoseconds since process start.
    pub cpu_time_ns: u64,
    /// Resident set size in bytes (physical memory currently held by the process).
    pub rss_bytes: u64,
}

/// Sample CPU time and RSS for a single process. Returns None if the PID is
/// dead or stats cannot be read. Both values are cumulative — caller must
/// compute deltas across samples to derive a rate (e.g., fractional CPUs).
#[cfg(target_os = "macos")]
pub fn process_stats(pid: Pid) -> Option<ProcessStats> {
    extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    const PROC_PIDTASKINFO: libc::c_int = 4;

    /// Subset of `struct proc_taskinfo` from <libproc.h>. CPU times are in
    /// mach_absolute_time units, which on Apple Silicon equal 1 nanosecond.
    /// (For full portability we'd convert via mach_timebase_info; on arm64
    /// macOS the ratio is 1:1, and smolvm targets Apple Silicon.)
    #[repr(C)]
    struct ProcTaskInfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }

    let mut info: ProcTaskInfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTASKINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<ProcTaskInfo>() as libc::c_int,
        )
    };
    if ret <= 0 {
        return None;
    }
    Some(ProcessStats {
        cpu_time_ns: info.pti_total_user.saturating_add(info.pti_total_system),
        rss_bytes: info.pti_resident_size,
    })
}

/// Sample CPU time and RSS for a single process on Linux via /proc/<pid>/{stat,statm}.
#[cfg(target_os = "linux")]
pub fn process_stats(pid: Pid) -> Option<ProcessStats> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Field 14 (utime) and 15 (stime) — both in clock ticks since process start.
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    if clock_ticks_per_sec == 0 {
        return None;
    }
    let cpu_time_ns = (utime + stime).saturating_mul(1_000_000_000) / clock_ticks_per_sec;

    let statm = std::fs::read_to_string(format!("/proc/{}/statm", pid)).ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    Some(ProcessStats {
        cpu_time_ns,
        rss_bytes: rss_pages.saturating_mul(page_size),
    })
}

/// Sample CPU time and RSS for a process on Windows via the Win32 process APIs
/// (`GetProcessTimes` + `GetProcessMemoryInfo`).
#[cfg(windows)]
pub fn process_stats(pid: Pid) -> Option<ProcessStats> {
    let (cpu_time_ns, rss_bytes) = win::process_stats(pid as u32)?;
    Some(ProcessStats {
        cpu_time_ns,
        rss_bytes,
    })
}

/// Sample CPU time and RSS for a process (stub on platforms without a
/// supported implementation). Always returns `None`.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub fn process_stats(_pid: Pid) -> Option<ProcessStats> {
    None
}

/// Backward-compatible start time comparison.
///
/// Handles the transition from seconds to microseconds on macOS: old records
/// stored seconds (~10^9), new code returns microseconds (~10^15). Values below
/// 10^12 are treated as seconds and compared at second granularity.
fn start_time_matches(actual: u64, expected: u64) -> bool {
    if actual == expected {
        return true;
    }
    // Backward compat: old macOS records stored seconds, new code uses microseconds.
    // Seconds-epoch values are < 10^12; microsecond values are > 10^15.
    if expected < 1_000_000_000_000 && actual >= 1_000_000_000_000 {
        return actual / 1_000_000 == expected;
    }
    false
}

/// Check if a PID belongs to our process by verifying start time.
///
/// If `expected_start_time` is None (legacy records), falls back to PID-only check.
/// Use [`is_our_process_strict`] for signal/kill paths where false positives are dangerous.
pub fn is_our_process(pid: Pid, expected_start_time: Option<u64>) -> bool {
    if !is_alive(pid) {
        return false;
    }
    if let Some(expected) = expected_start_time {
        match process_start_time(pid) {
            Some(actual) => start_time_matches(actual, expected),
            None => false,
        }
    } else {
        // Legacy record without start time — assume ours for status checks
        true
    }
}

/// Strict version of [`is_our_process`] for signal/kill paths.
///
/// Returns `false` when start time is missing (legacy records) rather than
/// assuming the PID is ours. Prevents accidentally signaling an unrelated
/// process that reused the same PID.
pub fn is_our_process_strict(pid: Pid, expected_start_time: Option<u64>) -> bool {
    if !is_alive(pid) {
        return false;
    }
    match expected_start_time {
        Some(expected) => match process_start_time(pid) {
            Some(actual) => start_time_matches(actual, expected),
            None => false,
        },
        None => {
            tracing::warn!(
                pid,
                "refusing to verify process without start time (legacy record)"
            );
            false
        }
    }
}

/// Send SIGTERM only if the PID still belongs to our process.
///
/// Uses strict verification — refuses to signal without start time.
pub fn terminate_verified(pid: Pid, start_time: Option<u64>) -> bool {
    if is_our_process_strict(pid, start_time) {
        terminate(pid)
    } else {
        false
    }
}

/// Send SIGKILL only if the PID still belongs to our process.
///
/// Uses strict verification — refuses to signal without start time.
pub fn kill_verified(pid: Pid, start_time: Option<u64>) -> bool {
    if is_our_process_strict(pid, start_time) {
        kill(pid)
    } else {
        false
    }
}

/// Identity fallback for our own VM subprocess when start-time can't be verified.
///
/// A live VM is `smolvm-bin _boot-vm <this-vm>/boot-config.json`; that config
/// path is unique per VM, so an alive PID whose argv contains it is unambiguously
/// our VM — a recycled PID belonging to an unrelated process could not carry that
/// exact argument. Lets a teardown confidently kill a VM whose agent vsock is
/// wedged (so no shutdown ack) and whose start-time record is missing, instead of
/// leaking it as an untracked orphan. Returns false if the PID is dead or its
/// argv can't be read / doesn't match.
pub fn cmdline_contains(pid: Pid, needle: &str) -> bool {
    if needle.is_empty() || !is_alive(pid) {
        return false;
    }
    match read_cmdline(pid) {
        Some(cmd) => cmd.contains(needle),
        None => false,
    }
}

/// Read a process's argv as a single space-joined string (best-effort).
#[cfg(target_os = "linux")]
fn read_cmdline(pid: Pid) -> Option<String> {
    // /proc/<pid>/cmdline is NUL-separated argv; join with spaces so a
    // `contains` on a path substring works regardless of arg boundaries.
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    Some(
        raw.split(|b| *b == 0)
            .map(|s| String::from_utf8_lossy(s))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Read a process's argv (macOS: via `ps -o command=`). Best-effort; the orphan
/// leak this guards is Linux-prod, so macOS just needs to not misfire.
#[cfg(not(target_os = "linux"))]
fn read_cmdline(pid: Pid) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Gracefully stop a process.
///
/// 1. Sends SIGTERM
/// 2. Waits up to `timeout` for graceful exit
/// 3. If still running and `force` is true, sends SIGKILL
///
/// Returns `Ok(exit_code)` on success, `Err` if timeout without force.
pub fn stop_process(pid: Pid, timeout: Duration, force: bool) -> Result<i32> {
    // Check if already dead
    if !is_alive(pid) {
        // Try to reap zombie
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }
        return Ok(0);
    }

    // Send SIGTERM
    if !terminate(pid) {
        // Process already dead - signal couldn't be sent.
        // Try to get exit code; if unavailable (e.g., already reaped), use unknown.
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    // Wait for graceful exit
    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    while start.elapsed() < timeout {
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }

        if !is_alive(pid) {
            // Process died during wait - get exit code or return unknown.
            return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
        }

        std::thread::sleep(poll_interval);
    }

    // Timeout reached
    if force {
        tracing::debug!(pid = pid, "SIGTERM timeout, sending SIGKILL");
        kill(pid);

        // Wait for SIGKILL to take effect
        std::thread::sleep(SIGKILL_WAIT);

        // Reap the process
        Ok(wait(pid))
    } else {
        Err(Error::agent(
            "stop process",
            format!("timeout waiting for process {} to stop", pid),
        ))
    }
}

/// Optimized process stop with aggressive polling for fast response.
///
/// This version uses a two-phase polling strategy:
/// 1. Aggressive polling (10ms intervals) for the first 100ms
/// 2. Backs off to 100ms intervals for the remainder
///
/// This minimizes latency for processes that exit quickly while
/// still being efficient for slower shutdowns.
pub fn stop_process_fast(pid: Pid, timeout: Duration, force: bool) -> Result<i32> {
    // Check if already dead
    if !is_alive(pid) {
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }
        return Ok(0);
    }

    // Send SIGTERM
    if !terminate(pid) {
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    // Two-phase polling: aggressive first, then back off
    let start = Instant::now();
    let mut poll_count: u32 = 0;

    while start.elapsed() < timeout {
        // Check immediately, then poll
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }

        if !is_alive(pid) {
            return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
        }

        // Aggressive polling for first ~100ms, then back off
        let poll_interval = if poll_count < FAST_POLL_COUNT {
            FAST_POLL_INTERVAL // 10ms
        } else {
            Duration::from_millis(100)
        };
        poll_count += 1;

        std::thread::sleep(poll_interval);
    }

    // Timeout reached
    if force {
        tracing::debug!(pid = pid, "SIGTERM timeout, sending SIGKILL");
        kill(pid);

        // Brief wait then poll for exit
        std::thread::sleep(SIGKILL_WAIT);
        Ok(try_wait(pid).unwrap_or_else(|| wait(pid)))
    } else {
        Err(Error::agent(
            "stop process",
            format!("timeout waiting for process {} to stop", pid),
        ))
    }
}

/// Default SIGTERM timeout for VM processes (3 seconds).
///
/// Generous to accommodate guest shutdown + Hypervisor.framework teardown.
pub const VM_SIGTERM_TIMEOUT: Duration = Duration::from_secs(3);

/// Default SIGKILL timeout for VM processes (3 seconds).
///
/// On macOS, Hypervisor.framework VMs can be in uninterruptible kernel state
/// (`hv_vcpu_run`). Even SIGKILL may take 1-3 seconds while the kernel tears
/// down VM resources. This timeout must be long enough for that cleanup.
pub const VM_SIGKILL_TIMEOUT: Duration = Duration::from_secs(3);

/// Stop a VM process with Hypervisor-aware timeouts.
///
/// Two-phase shutdown:
/// 1. SIGTERM → poll up to `sigterm_timeout` with early exit
/// 2. If still alive: SIGKILL → poll up to `sigkill_timeout` with early exit
///
/// Callers must verify process identity BEFORE calling this function.
///
/// Returns `Ok(exit_code)` if the process exited, `Err` if still alive.
pub fn stop_vm_process(
    pid: Pid,
    sigterm_timeout: Duration,
    sigkill_timeout: Duration,
) -> Result<i32> {
    if !is_alive(pid) {
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    // Phase 1: SIGTERM + poll
    if !terminate(pid) {
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    if let Some(code) = poll_for_exit(pid, sigterm_timeout) {
        return Ok(code);
    }

    // Phase 2: SIGKILL + poll
    tracing::debug!(pid, "SIGTERM timeout, sending SIGKILL");
    kill(pid);

    if let Some(code) = poll_for_exit(pid, sigkill_timeout) {
        return Ok(code);
    }

    Err(Error::agent(
        "stop vm process",
        format!("process {} still alive after SIGTERM+SIGKILL", pid),
    ))
}

/// Poll for process exit with aggressive-then-backoff strategy.
///
/// Returns `Some(exit_code)` if the process exits within the timeout.
fn poll_for_exit(pid: Pid, timeout: Duration) -> Option<i32> {
    let start = Instant::now();
    let mut poll_count: u32 = 0;

    while start.elapsed() < timeout {
        if let Some(code) = try_wait(pid) {
            return Some(code);
        }
        if !is_alive(pid) {
            return Some(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
        }

        let interval = if poll_count < FAST_POLL_COUNT {
            FAST_POLL_INTERVAL
        } else {
            Duration::from_millis(100)
        };
        poll_count += 1;
        std::thread::sleep(interval);
    }
    None
}

/// Result of a fork operation.
#[derive(Debug)]
pub enum ForkResult {
    /// This is the parent process. Contains the child's PID.
    Parent(Pid),
    /// This is the child process.
    Child,
}

/// Fork a child process that becomes a session leader.
///
/// This function provides a safe interface to fork a child process and
/// have it call `setsid()` to become a session leader. This is commonly
/// used to detach VM processes from the parent's session so they survive
/// if the parent is killed.
///
/// # Arguments
///
/// * `child_fn` - A closure to run in the child process. The closure must
///   never return - it should either call `std::process::exit()` or exec
///   another program.
///
/// # Returns
///
/// * `Ok(pid)` - The child's PID if this is the parent process
/// * `Err` - If the fork failed
///
/// # Example
///
/// ```ignore
/// let child_pid = fork_session_leader(|| {
///     // This runs in the child process as a session leader
///     launch_vm(...);
///     std::process::exit(0);
/// })?;
/// ```
#[cfg(unix)]
pub fn fork_session_leader<F>(child_fn: F) -> Result<Pid>
where
    F: FnOnce(),
{
    // SAFETY: fork() creates a new process. The child inherits the parent's
    // memory space as copy-on-write. We must be careful not to:
    // - Hold any locks across fork (we don't)
    // - Use async-signal-unsafe functions in the child before exec
    //
    // The child immediately calls setsid() and then the user-provided closure,
    // which is expected to exec or exit.
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => {
            // Fork failed
            let err = std::io::Error::last_os_error();
            Err(Error::vm_creation(format!("fork failed: {}", err)))
        }
        0 => {
            // Child process
            //
            // SAFETY: setsid() is safe to call immediately after fork.
            // It creates a new session and makes this process the session leader,
            // detaching it from the parent's controlling terminal.
            unsafe {
                libc::setsid();
            }

            // Close inherited file descriptors to prevent holding parent's
            // database locks, sockets, and other resources. Keep stdin(0),
            // stdout(1), stderr(2) for error output during child setup.
            // The child opens fresh fds for everything it needs.
            close_inherited_fds_from(3);

            // Run the user-provided closure
            child_fn();

            // If the closure returns (it shouldn't), exit with error
            //
            // SAFETY: _exit() is safe in the child after fork. We use _exit()
            // instead of exit() to avoid running atexit handlers and flushing
            // stdio buffers that were inherited from the parent.
            unsafe {
                libc::_exit(1);
            }
        }
        child_pid => {
            // Parent process
            Ok(child_pid)
        }
    }
}

/// `fork()`-based session-leader launch is a Unix-only mechanism. The Windows
/// host never uses the in-process fork launch path; it always launches the VM
/// boot as a `smolvm _boot-vm` subprocess via `Command::new`.
#[cfg(not(unix))]
pub fn fork_session_leader<F>(_child_fn: F) -> Result<Pid>
where
    F: FnOnce(),
{
    Err(Error::vm_creation(
        "fork-based launch is not supported on Windows; use the subprocess launch path",
    ))
}

/// Redirect stdin, stdout, and stderr to `/dev/null`.
///
/// Call this in a forked child process before launching a long-running
/// background task (e.g. a VM via `krun_start_enter`). Without this,
/// the child inherits the parent's terminal file descriptors and libkrun's
/// internal threads may read from stdin or set terminal attributes,
/// stealing keystrokes from the user's shell.
///
/// Must be called **after** any `eprintln!()` diagnostics that need the
/// real stderr, but **before** the point of no return (`krun_start_enter`).
#[cfg(unix)]
pub fn detach_stdio() {
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0); // stdin
            libc::dup2(devnull, 1); // stdout
            libc::dup2(devnull, 2); // stderr
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
}

/// No-op on Windows: there is no `/dev/null` fd-redirection model; the
/// subprocess launch path configures the child's stdio via `Command` instead.
#[cfg(not(unix))]
pub fn detach_stdio() {}

/// Redirect stdin/stdout to `/dev/null` and stderr to a log file.
///
/// This keeps background children detached from the user's terminal while
/// preserving boot-time diagnostics for later inspection.
#[cfg(unix)]
pub fn detach_stdio_to_stderr_file(path: &std::path::Path) -> std::io::Result<()> {
    let stderr_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let stderr_fd = stderr_file.into_raw_fd();

    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull < 0 {
            libc::close(stderr_fd);
            return Err(std::io::Error::last_os_error());
        }

        libc::dup2(devnull, 0); // stdin
        libc::dup2(devnull, 1); // stdout
        libc::dup2(stderr_fd, 2); // stderr

        if devnull > 2 {
            libc::close(devnull);
        }
        if stderr_fd > 2 {
            libc::close(stderr_fd);
        }
    }

    Ok(())
}

/// Windows: redirect this process's stderr to a log file via `SetStdHandle`.
///
/// The fd-level `dup2` of stdin/stdout to `/dev/null` has no portable analog
/// and is unnecessary here (the boot subprocess is launched with inherited or
/// null handles by the parent `Command`); only the stderr log redirection is
/// reproduced so boot diagnostics are captured.
#[cfg(not(unix))]
pub fn detach_stdio_to_stderr_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};

    let stderr_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    // Keep the file handle alive for the process lifetime by leaking it; the
    // OS handle now backs stderr.
    let handle = stderr_file.as_raw_handle();
    std::mem::forget(stderr_file);
    // SAFETY: `handle` is a valid file handle that we have intentionally leaked
    // so it outlives this call and remains valid as the process's stderr.
    let ok = unsafe { SetStdHandle(STD_ERROR_HANDLE, handle as _) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Exit the current process immediately without cleanup.
///
/// On Unix this is a safe wrapper around `libc::_exit()` for use in forked
/// child processes — it avoids running atexit handlers and flushing stdio
/// buffers inherited from the parent. On Windows (no fork) it is a plain
/// process exit.
///
/// # Safety
///
/// This function never returns.
#[cfg(unix)]
pub fn exit_child(code: i32) -> ! {
    // SAFETY: _exit() is safe in a forked child process. Using _exit() instead
    // of exit() ensures we don't run atexit handlers or flush stdio buffers
    // that were inherited from the parent process.
    unsafe {
        libc::_exit(code);
    }
}

/// Exit the current process immediately (Windows). No fork is involved, so a
/// normal `process::exit` is correct.
#[cfg(not(unix))]
pub fn exit_child(code: i32) -> ! {
    std::process::exit(code)
}

/// A handle to a running child process.
///
/// Provides methods to check status, stop, and kill the process.
#[derive(Debug)]
pub struct ChildProcess {
    pid: Pid,
    /// Start time captured at creation for PID reuse detection.
    start_time: Option<u64>,
    exit_code: Option<i32>,
}

impl ChildProcess {
    /// Create a new child process handle, capturing start time immediately.
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            start_time: process_start_time(pid),
            exit_code: None,
        }
    }

    /// Get the process ID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Get the start time captured when this handle was created.
    pub fn start_time(&self) -> Option<u64> {
        self.start_time
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        if self.exit_code.is_some() {
            return false;
        }

        if let Some(code) = try_wait(self.pid) {
            self.exit_code = Some(code);
            false
        } else {
            is_alive(self.pid)
        }
    }

    /// Get the exit code if the process has exited.
    pub fn exit_code(&mut self) -> Option<i32> {
        if self.exit_code.is_none() {
            self.exit_code = try_wait(self.pid);
        }
        self.exit_code
    }

    /// Wait for the process to exit (blocking).
    pub fn wait(&mut self) -> i32 {
        if let Some(code) = self.exit_code {
            return code;
        }

        let code = wait(self.pid);
        self.exit_code = Some(code);
        code
    }

    /// Send SIGTERM to the process.
    pub fn terminate(&self) -> bool {
        terminate(self.pid)
    }

    /// Send SIGKILL to the process.
    pub fn kill(&self) -> bool {
        kill(self.pid)
    }

    /// Gracefully stop the process.
    ///
    /// Sends SIGTERM, waits for `timeout`, then SIGKILL if `force` is true.
    pub fn stop(&mut self, timeout: Duration, force: bool) -> Result<i32> {
        if let Some(code) = self.exit_code {
            return Ok(code);
        }

        let code = stop_process(self.pid, timeout, force)?;
        self.exit_code = Some(code);
        Ok(code)
    }
}

// ============================================================================
// SIGINT guard — kill a VM child process on Ctrl+C
// ============================================================================

/// PID for the SIGINT handler to kill on Ctrl+C.
/// Set by [`SigintGuard::new`], cleared on drop/disarm.
static SIGINT_CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// RAII guard that ensures a VM child process is killed on Ctrl+C.
///
/// Without this, SIGINT terminates the parent immediately (default handler)
/// without running Rust destructors, so [`AgentManager::drop`] never fires
/// and the separate-process-group VM child is orphaned.
///
/// The signal handler only calls `kill()` and `_exit()` (async-signal-safe).
pub struct SigintGuard(());

impl SigintGuard {
    /// Install a SIGINT handler that will SIGTERM+SIGKILL the given PID.
    #[cfg(unix)]
    pub fn new(pid: Pid) -> Self {
        SIGINT_CHILD_PID.store(pid, Ordering::SeqCst);
        unsafe {
            libc::signal(
                libc::SIGINT,
                sigint_kill_handler as *const () as libc::sighandler_t,
            );
        }
        Self(())
    }

    /// Windows: POSIX signal-handler installation has no direct equivalent and
    /// the orphaned-process-group concern does not apply. The guard is inert.
    #[cfg(not(unix))]
    pub fn new(_pid: Pid) -> Self {
        Self(())
    }

    /// Disarm the guard: clear the PID, restore default handler, skip Drop.
    ///
    /// Use when transitioning to a phase with its own SIGINT handling
    /// (e.g., interactive exec).
    pub fn disarm(self) {
        SIGINT_CHILD_PID.store(0, Ordering::SeqCst);
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        std::mem::forget(self);
    }
}

impl Drop for SigintGuard {
    fn drop(&mut self) {
        SIGINT_CHILD_PID.store(0, Ordering::SeqCst);
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
    }
}

/// SIGINT handler: SIGTERM the child, brief busy-wait, escalate to SIGKILL, then _exit.
///
/// SAFETY: Only calls `kill()` and `_exit()`, both async-signal-safe.
#[cfg(unix)]
extern "C" fn sigint_kill_handler(_sig: libc::c_int) {
    let pid = SIGINT_CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
            for _ in 0..10 {
                if libc::kill(pid, 0) != 0 {
                    break;
                }
            }
            if libc::kill(pid, 0) == 0 {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    unsafe {
        libc::_exit(128 + libc::SIGINT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_alive_self() {
        // Current process should be alive
        let pid = unsafe { libc::getpid() };
        assert!(is_alive(pid));
    }

    #[test]
    fn test_is_alive_nonexistent() {
        // PID 99999999 is unlikely to exist
        assert!(!is_alive(99999999));
    }

    #[test]
    fn test_process_start_time_self() {
        let pid = unsafe { libc::getpid() };
        let start_time = process_start_time(pid);
        // On macOS and Linux this should return Some; on other platforms None
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(
            start_time.is_some(),
            "should get start time on this platform"
        );
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        assert!(start_time.is_none());
    }

    #[test]
    fn test_process_start_time_nonexistent() {
        assert!(process_start_time(99999999).is_none());
    }

    #[test]
    fn test_is_our_process_self() {
        let pid = unsafe { libc::getpid() };
        let start_time = process_start_time(pid);
        assert!(is_our_process(pid, start_time));
    }

    #[test]
    fn test_is_our_process_wrong_start_time() {
        let pid = unsafe { libc::getpid() };
        // A start time far in the future should not match
        assert!(!is_our_process(pid, Some(u64::MAX)));
    }

    #[test]
    fn test_is_our_process_nonexistent() {
        assert!(!is_our_process(99999999, None));
        assert!(!is_our_process(99999999, Some(12345)));
    }

    #[test]
    fn test_is_our_process_strict_requires_start_time() {
        let pid = unsafe { libc::getpid() };
        // Strict refuses to verify without start time
        assert!(!is_our_process_strict(pid, None));
        // But works with valid start time
        let start_time = process_start_time(pid);
        if start_time.is_some() {
            assert!(is_our_process_strict(pid, start_time));
        }
    }

    #[test]
    fn test_start_time_matches_exact() {
        assert!(start_time_matches(12345, 12345));
        assert!(!start_time_matches(12345, 12346));
    }

    #[test]
    fn test_start_time_matches_backward_compat() {
        // Old record stored seconds (1_700_000_000), new code returns microseconds
        let old_seconds = 1_700_000_000u64;
        let new_micros = old_seconds * 1_000_000 + 500_000; // same second, different usec
        assert!(start_time_matches(new_micros, old_seconds));

        // Different second should not match
        assert!(!start_time_matches(new_micros, old_seconds + 1));
    }

    /// The seccomp allowlist must actually *deny* — a syscall outside it
    /// (`kexec_load`, an escape-amplifying one we never allow) must kill the
    /// process with SIGSYS. The allowed-path is covered by the live boot+exec
    /// test on a Linux/KVM host.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn seccomp_denies_forbidden_syscall() {
        // Build the filter in the parent (allocating), then fork a child that
        // applies it (allocation-free) and attempts the forbidden syscall.
        let program = build_seccomp_program(true).expect("build seccomp program");
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                if seccompiler::apply_filter(&program).is_err() {
                    libc::_exit(2);
                }
                libc::syscall(libc::SYS_kexec_load, 0, 0, 0, 0);
                // Reached only if the filter did NOT kill us.
                libc::_exit(0);
            }
            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &mut status, 0);
            assert!(
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
                "forbidden syscall (kexec_load) should trigger SIGSYS, status={status:#x}"
            );
        }
    }

    /// Landlock must actually *deny* — after restricting to `/usr` only, opening
    /// an ungranted path (`/etc/hostname`) must fail with EACCES. Runs in a forked
    /// child so the restriction doesn't affect the test runner.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_denies_ungranted_path() {
        use std::path::PathBuf;
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // Landlock requires no_new_privs (set in production by harden_self).
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let ro = [PathBuf::from("/usr")];
                if restrict_filesystem(&ro, &[]).is_err() {
                    libc::_exit(3); // Landlock unavailable on this kernel — tolerate.
                }
                // /etc is NOT granted -> opening it must be denied.
                let path = c"/etc/hostname";
                let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
                if fd < 0 {
                    let err = *libc::__errno_location();
                    libc::_exit(if err == libc::EACCES { 0 } else { 4 });
                }
                libc::_exit(5); // opened -> NOT restricted -> failure
            }
            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &mut status, 0);
            let code = libc::WEXITSTATUS(status);
            assert!(
                code == 0 || code == 3,
                "expected EACCES denial (0) or no-landlock (3), got exit {code}"
            );
        }
    }

    /// `drop_privileges` must fail closed: an unprivileged caller cannot drop to
    /// another identity, so it returns Err (the boot path then refuses to run
    /// over-privileged). `setgroups` fails first, so the test process's own
    /// identity is left unchanged. Skipped when running as root (where it could
    /// actually drop and disrupt the test runner).
    #[cfg(target_os = "linux")]
    #[test]
    fn drop_privileges_fails_closed_without_capability() {
        if unsafe { libc::geteuid() } == 0 {
            return; // privileged runner — skip to avoid dropping the test process
        }
        assert!(
            drop_privileges(1, 1).is_err(),
            "unprivileged drop_privileges must fail (fail-closed contract)"
        );
        // Sanity: our identity is unchanged (setgroups failed before any setuid).
        assert_ne!(
            unsafe { libc::getuid() },
            1,
            "drop must not have taken effect"
        );
    }

    /// `(base, registry, vms)` laid out as production: `<base>/smolvm/{uids,vms}`,
    /// so the allocator's `registry.parent()/vms` resolves to `vms`. A VM's data
    /// dir is `vms/<vm_key>`.
    #[cfg(target_os = "linux")]
    fn tmp_uid_dirs(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let base =
            std::env::temp_dir().join(format!("smolvm-uidtest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let reg = base.join("smolvm").join("uids");
        let vms = base.join("smolvm").join("vms");
        std::fs::create_dir_all(&reg).unwrap();
        std::fs::create_dir_all(&vms).unwrap();
        (base, reg, vms)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allocate_vm_uid_is_stable_collision_free_and_freeable() {
        let (base, reg, vms) = tmp_uid_dirs("alloc");
        let a = vms.join("aaaa");
        let b = vms.join("bbbb");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        let ua = allocate_vm_uid(&reg, &a, "aaaa").unwrap();
        let ub = allocate_vm_uid(&reg, &b, "bbbb").unwrap();
        // In range, distinct (collision-free), and stable on re-allocation.
        assert!((VM_UID_BASE..VM_UID_BASE + VM_UID_SPAN).contains(&ua));
        assert_ne!(ua, ub, "distinct VMs must get distinct uids");
        assert_eq!(
            ua,
            allocate_vm_uid(&reg, &a, "aaaa").unwrap(),
            "must be stable"
        );

        // Free A, then a new VM reuses A's released uid (lowest-free).
        free_vm_uid(&reg, &a);
        let c = vms.join("cccc");
        std::fs::create_dir_all(&c).unwrap();
        assert_eq!(
            allocate_vm_uid(&reg, &c, "cccc").unwrap(),
            ua,
            "freed uid is reused"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn registered_uid_recovers_assignment_when_cache_lost() {
        let (base, reg, vms) = tmp_uid_dirs("recover");
        let a = vms.join("key-a");
        std::fs::create_dir_all(&a).unwrap();
        let ua = allocate_vm_uid(&reg, &a, "key-a").unwrap();
        // Drop the per-VM cache; the registry still maps key -> uid.
        let _ = std::fs::remove_file(a.join(".vm-uid"));
        assert_eq!(allocate_vm_uid(&reg, &a, "key-a").unwrap(), ua);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allocator_self_heals_leaked_uid_when_vm_dir_gone() {
        let (base, reg, vms) = tmp_uid_dirs("selfheal");
        let a = vms.join("aaaa");
        std::fs::create_dir_all(&a).unwrap();
        let ua = allocate_vm_uid(&reg, &a, "aaaa").unwrap();

        // Simulate a delete path that removed the VM's data dir WITHOUT calling
        // free_vm_uid: the registry marker is now leaked.
        std::fs::remove_dir_all(&a).unwrap();
        assert!(reg.join(ua.to_string()).exists(), "marker is leaked");

        // A new VM reclaims that stale uid (its VM dir is gone) — no permanent
        // leak even though the delete path forgot to free it.
        let b = vms.join("bbbb");
        std::fs::create_dir_all(&b).unwrap();
        assert_eq!(
            allocate_vm_uid(&reg, &b, "bbbb").unwrap(),
            ua,
            "stale (data-dir-gone) uid must be reclaimed"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The selective reaper drains registered VM PIDs once they exit, and a
    /// non-child PID (would-be ECHILD) is dropped without affecting others.
    #[cfg(target_os = "linux")]
    #[test]
    fn reap_vm_children_is_scoped_and_drains() {
        // A real short-lived child: register its PID and forget the handle so the
        // reaper (not Child::drop) reaps it.
        let child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let real_pid = child.id() as i32;
        std::mem::forget(child);
        register_vm_child(real_pid);
        // A PID we never parented → waitpid returns ECHILD → must be dropped.
        register_vm_child(i32::MAX);

        // Sweep until the registry drains (the real child exits ~immediately).
        let mut drained = false;
        for _ in 0..50 {
            reap_vm_children();
            if vm_children().lock().unwrap().is_empty() {
                drained = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            drained,
            "registry should drain: real child reaped, bogus PID dropped on ECHILD"
        );
    }

    /// `process_stats` must report live CPU/RSS for our own (alive) process on
    /// every supported host — macOS, Linux, and Windows (where it previously
    /// returned None). RSS is always > 0 for a running process; CPU time is
    /// cumulative and may legitimately read 0 very early, so we only assert RSS.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    #[test]
    fn process_stats_samples_self() {
        let me = std::process::id() as Pid;
        let stats = process_stats(me).expect("process_stats must sample the current process");
        assert!(
            stats.rss_bytes > 0,
            "a live process must have non-zero RSS, got {}",
            stats.rss_bytes
        );
    }

    /// A PID that does not exist must yield None, not a bogus sample.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    #[test]
    fn process_stats_dead_pid_is_none() {
        assert!(
            process_stats(i32::MAX as Pid).is_none(),
            "stats for a non-existent PID must be None"
        );
    }

    /// A live process's argv is matchable by a unique substring, and a
    /// non-matching needle / dead PID / empty needle all return false — the
    /// identity fallback must be specific enough not to misfire.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn cmdline_contains_matches_only_its_own_argv() {
        let token = format!("smolvm-cmdline-probe-{}", std::process::id());
        // A long-lived process whose argv carries our unique token. The token is
        // embedded in the `-c` script itself, and the trailing `; :` makes it a
        // COMPOUND command so the shell can't exec-optimize into `sleep` (which
        // would drop the shell's argv, and with it our token, on macOS).
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 30; : {token}"))
            .spawn()
            .expect("spawn sh");
        let pid = child.id() as Pid;
        // Give the OS a beat to expose argv.
        std::thread::sleep(std::time::Duration::from_millis(50));

        assert!(
            cmdline_contains(pid, &token),
            "argv containing the unique token must match"
        );
        assert!(
            !cmdline_contains(pid, "a-token-that-is-not-in-argv"),
            "a non-matching needle must not match"
        );
        assert!(
            !cmdline_contains(pid, ""),
            "an empty needle must never match"
        );

        let _ = child.kill();
        let _ = child.wait();
        assert!(!cmdline_contains(pid, &token), "a dead PID must not match");
    }
}
