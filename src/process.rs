//! Process management utilities.
//!
//! This module provides utilities for managing child processes,
//! including signal handling and graceful shutdown.

use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Flag indicating whether SIGCHLD handler has been installed.
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
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
    }
}

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
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
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
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
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
        libc::SYS_readlinkat, libc::SYS_faccessat, libc::SYS_umask,
        libc::SYS_fgetxattr, libc::SYS_flistxattr, libc::SYS_pipe2,
        // memory (guest RAM, dlopen of libkrun)
        libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_mprotect,
        libc::SYS_madvise, libc::SYS_brk,
        // KVM + device ioctls, eventfd plumbing
        libc::SYS_ioctl, libc::SYS_eventfd2,
        // epoll / poll event loops (virtio, vsock/TSI)
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait, libc::SYS_ppoll,
        // sockets (vsock/TSI data path, host networking)
        libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect, libc::SYS_bind,
        libc::SYS_listen, libc::SYS_accept, libc::SYS_sendto, libc::SYS_recvfrom,
        libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_setsockopt,
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
        libc::SYS_capget, libc::SYS_setpgid,
    ];

    // Legacy syscalls present only on x86_64; aarch64 exposes only the *at/p
    // variants (already in the common list above) plus a few of its own. These
    // libc::SYS_* constants don't exist on the other arch, so they must be
    // arch-gated. The arm64 set is a starting point — refine from an audit run.
    #[cfg(target_arch = "x86_64")]
    allowed.extend_from_slice(&[
        libc::SYS_dup2, libc::SYS_readlink, libc::SYS_unlink, libc::SYS_rename,
        libc::SYS_mkdir, libc::SYS_access, libc::SYS_epoll_wait, libc::SYS_poll,
        libc::SYS_arch_prctl,
    ]);
    #[cfg(target_arch = "aarch64")]
    allowed.extend_from_slice(&[
        libc::SYS_unlinkat, libc::SYS_renameat2, libc::SYS_mkdirat,
    ]);

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
    let filter = SeccompFilter::new(
        rules,
        mismatch_action,
        SeccompAction::Allow,
        target_arch,
    )
    .map_err(|e| e.to_string())?;
    let program: BpfProgram = match filter.try_into() {
        Ok(prog) => prog,
        Err(e) => return Err(e.to_string()),
    };
    Ok(program)
}

/// No-op stub where seccomp isn't applicable (macOS dev, Linux arches other
/// than x86_64/aarch64).
#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
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

/// Install a SIGCHLD handler to automatically reap zombie child processes.
///
/// This function installs a signal handler that calls waitpid(-1, WNOHANG) to
/// reap any terminated child processes, preventing zombie accumulation.
///
/// The handler is only installed once; subsequent calls are no-ops.
///
/// # Safety
///
/// This function installs a signal handler which must be async-signal-safe.
/// The handler only calls waitpid() which is safe.
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

/// SIGCHLD signal handler that reaps zombie children.
///
/// This handler is async-signal-safe as it only calls waitpid().
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
pub fn is_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait for a process to exit (non-blocking check).
///
/// Returns `Some(exit_code)` if the process has exited, `None` if still running.
/// Handles EINTR by retrying the waitpid call.
pub fn try_wait(pid: libc::pid_t) -> Option<i32> {
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

/// Wait for a process to exit (blocking).
///
/// Returns the exit code. Handles EINTR by retrying the waitpid call.
pub fn wait(pid: libc::pid_t) -> i32 {
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

/// Send SIGTERM to a process.
///
/// Returns true if the signal was sent successfully.
pub fn terminate(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, libc::SIGTERM) == 0 }
}

/// Send SIGKILL to a process.
///
/// Returns true if the signal was sent successfully.
pub fn kill(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, libc::SIGKILL) == 0 }
}

/// Get the start time of a process (seconds since epoch).
///
/// Used alongside PID to create a stable process identity that survives
/// PID reuse. If the process at a given PID has a different start time
/// than expected, it's a different process (PID was recycled).
#[cfg(target_os = "macos")]
pub fn process_start_time(pid: libc::pid_t) -> Option<u64> {
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
pub fn process_start_time(pid: libc::pid_t) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Format: pid (comm) state ppid ... starttime ...
    // comm can contain spaces and parentheses, so find the last ')' first.
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat.get(after_comm..)?.split_whitespace().collect();
    // After ") ", fields are: state(0) ppid(1) ... starttime(19)
    fields.get(19)?.parse::<u64>().ok()
}

/// Get the start time of a process (stub for unsupported platforms).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_start_time(_pid: libc::pid_t) -> Option<u64> {
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
pub fn process_stats(pid: libc::pid_t) -> Option<ProcessStats> {
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
pub fn process_stats(pid: libc::pid_t) -> Option<ProcessStats> {
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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_stats(_pid: libc::pid_t) -> Option<ProcessStats> {
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
pub fn is_our_process(pid: libc::pid_t, expected_start_time: Option<u64>) -> bool {
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
pub fn is_our_process_strict(pid: libc::pid_t, expected_start_time: Option<u64>) -> bool {
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
pub fn terminate_verified(pid: libc::pid_t, start_time: Option<u64>) -> bool {
    if is_our_process_strict(pid, start_time) {
        terminate(pid)
    } else {
        false
    }
}

/// Send SIGKILL only if the PID still belongs to our process.
///
/// Uses strict verification — refuses to signal without start time.
pub fn kill_verified(pid: libc::pid_t, start_time: Option<u64>) -> bool {
    if is_our_process_strict(pid, start_time) {
        kill(pid)
    } else {
        false
    }
}

/// Gracefully stop a process.
///
/// 1. Sends SIGTERM
/// 2. Waits up to `timeout` for graceful exit
/// 3. If still running and `force` is true, sends SIGKILL
///
/// Returns `Ok(exit_code)` on success, `Err` if timeout without force.
pub fn stop_process(pid: libc::pid_t, timeout: Duration, force: bool) -> Result<i32> {
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
pub fn stop_process_fast(pid: libc::pid_t, timeout: Duration, force: bool) -> Result<i32> {
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
    pid: libc::pid_t,
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
fn poll_for_exit(pid: libc::pid_t, timeout: Duration) -> Option<i32> {
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
    Parent(libc::pid_t),
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
pub fn fork_session_leader<F>(child_fn: F) -> Result<libc::pid_t>
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

/// Redirect stdin/stdout to `/dev/null` and stderr to a log file.
///
/// This keeps background children detached from the user's terminal while
/// preserving boot-time diagnostics for later inspection.
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

/// Exit the current process immediately without cleanup.
///
/// This is a safe wrapper around `libc::_exit()` for use in forked child
/// processes. It avoids running atexit handlers and flushing stdio buffers
/// that were inherited from the parent.
///
/// # Safety
///
/// This function never returns. It should only be called in a forked child
/// process after fork() to avoid double-flushing stdio buffers.
pub fn exit_child(code: i32) -> ! {
    // SAFETY: _exit() is safe in a forked child process. Using _exit() instead
    // of exit() ensures we don't run atexit handlers or flush stdio buffers
    // that were inherited from the parent process.
    unsafe {
        libc::_exit(code);
    }
}

/// A handle to a running child process.
///
/// Provides methods to check status, stop, and kill the process.
#[derive(Debug)]
pub struct ChildProcess {
    pid: libc::pid_t,
    /// Start time captured at creation for PID reuse detection.
    start_time: Option<u64>,
    exit_code: Option<i32>,
}

impl ChildProcess {
    /// Create a new child process handle, capturing start time immediately.
    pub fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            start_time: process_start_time(pid),
            exit_code: None,
        }
    }

    /// Get the process ID.
    pub fn pid(&self) -> libc::pid_t {
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
    pub fn new(pid: libc::pid_t) -> Self {
        SIGINT_CHILD_PID.store(pid, Ordering::SeqCst);
        unsafe {
            libc::signal(
                libc::SIGINT,
                sigint_kill_handler as *const () as libc::sighandler_t,
            );
        }
        Self(())
    }

    /// Disarm the guard: clear the PID, restore default handler, skip Drop.
    ///
    /// Use when transitioning to a phase with its own SIGINT handling
    /// (e.g., interactive exec).
    pub fn disarm(self) {
        SIGINT_CHILD_PID.store(0, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        std::mem::forget(self);
    }
}

impl Drop for SigintGuard {
    fn drop(&mut self) {
        SIGINT_CHILD_PID.store(0, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
    }
}

/// SIGINT handler: SIGTERM the child, brief busy-wait, escalate to SIGKILL, then _exit.
///
/// SAFETY: Only calls `kill()` and `_exit()`, both async-signal-safe.
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
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
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
}
