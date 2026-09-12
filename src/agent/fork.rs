//! Live fork mechanics shared by the CLI (`machine fork`) and the serve API
//! (`POST /api/v1/machines/{id}/fork`).
//!
//! A fork snapshots a running, forkable machine's RAM, device state, and disks,
//! gives the clone private copy-on-write layers, and lets the caller boot the
//! clone from that exact boundary. Linux/x86_64 and macOS resume the source
//! immediately on new private layers; other hosts retain a frozen CoW base.
//! The boot itself differs between callers (the CLI uses `start_vm_named`; the
//! API uses `AgentManager`), so it stays out of here; everything up to and
//! including the snapshot + disk clone is shared so the two entry points can
//! never silently diverge.

use crate::agent::{resolve_disk_image, vm_data_dir, AgentClient};
use crate::config::VmRecord;
use crate::data::validate_vm_name;
use crate::db::SmolvmDb;
use crate::{Error, Result};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Bound qcow2 ancestry and recursive lifecycle work. Longer chains should be
/// compacted into a new root rather than accumulating unbounded lookup cost.
const MAX_FORK_LINEAGE_DEPTH: usize = 32;

type ForkDisk = (&'static str, PathBuf, crate::data::disk::DiskFormat);

/// Cross-process guard for one source machine's fork or checkpoint transaction.
///
/// The in-process API/SDK lifecycle locks cannot serialize a separate CLI
/// process. Without this guard, two first forks can both wait in the guest;
/// after one freezes it, the other remains blocked in the now-paused VM. The
/// lock spans readiness, checkpointing, clone boot, and any rollback.
pub struct ForkSourceLock {
    _file: File,
}

impl ForkSourceLock {
    fn acquire_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::agent("fork source lock", error.to_string()))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|error| Error::agent("fork source lock", error.to_string()))?;
        lock_file_exclusive(&file)
            .map_err(|error| Error::agent("fork source lock", error.to_string()))?;
        Ok(Self { _file: file })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn try_acquire_at(path: &Path) -> Result<Option<Self>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::agent("fork source lock", error.to_string()))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|error| Error::agent("fork source lock", error.to_string()))?;
        match try_lock_file_exclusive(&file) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(Error::agent("fork source lock", error.to_string())),
        }
    }
}

/// Serialize source-state capture for `source` across CLI, SDK, and serve
/// processes. A fork retains the guard for its complete transaction; a portable
/// checkpoint releases it once the source resumes. The sibling lock file lives
/// outside the removable machine data directory, so concurrent deletion cannot
/// replace its inode.
pub fn lock_fork_source(source: &str) -> Result<ForkSourceLock> {
    validate_vm_name(source, "fork source").map_err(|error| Error::config("fork source", error))?;
    ForkSourceLock::acquire_at(&fork_source_lock_path(source))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn try_lock_fork_source(source: &str) -> Result<Option<ForkSourceLock>> {
    validate_vm_name(source, "fork source").map_err(|error| Error::config("fork source", error))?;
    ForkSourceLock::try_acquire_at(&fork_source_lock_path(source))
}

fn fork_source_lock_path(source: &str) -> PathBuf {
    let data_dir = vm_data_dir(source);
    data_dir
        .parent()
        .expect("a VM data directory always has a parent")
        .join(format!(".{source}.fork-operation.lock"))
}

#[cfg(unix)]
fn lock_file_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_file_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let result = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Turn a control-socket refusal into something the person who ran the command
/// can act on.
///
/// The VMM answers in its own vocabulary — `ERR EINVAL no memfd-backed RAM
/// (start the VM with SMOLVM_FORKABLE=1)` — which leaks an errno and points at
/// an internal environment variable rather than the flag a person types. Every
/// caller (CLI and serve API alike) funnels through here, so the mapping is
/// written once. An unrecognised reply is passed through verbatim rather than
/// guessed at, so a new VMM error is never disguised as a known one.
fn explain_fork_reply(golden: &str, reply: &str) -> String {
    if reply.contains("no memfd-backed RAM") {
        return format!(
            "machine '{golden}' was not started as branchable, so it has no copy-on-write \
             memory to branch from. Restart it with `smolvm machine start --name {golden} \
             --branchable`; branchability is decided at start time and cannot be turned on \
             for an already-running machine."
        );
    }
    format!("branching '{golden}' failed: {reply}")
}

/// Non-blocking [`lock_file_exclusive`]: fails immediately when the lock is held
/// instead of waiting for it. Lets a cleanup sweep tell "no fork is running for
/// this machine" from "one is in flight" without ever stalling behind a fork.
#[cfg(unix)]
fn try_lock_file_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn try_lock_file_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let result = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The machine name a fork-source lock file belongs to, or `None` when the path
/// is not one. The inverse of the name [`fork_source_lock_path`] builds.
fn fork_source_lock_owner(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_str()?;
    let source = file_name
        .strip_prefix('.')?
        .strip_suffix(".fork-operation.lock")?;
    (!source.is_empty()).then(|| source.to_string())
}

/// Remove fork-source lock files whose machine no longer exists.
///
/// [`fork_source_lock_path`] deliberately puts the lock file *beside* the
/// machine's data directory rather than inside it, so deleting a machine cannot
/// unlink the inode a live fork holds and let the next fork create a fresh file
/// and run in parallel with it. The cost of that choice is that removing the
/// data directory no longer removes the lock, so a node that creates and deletes
/// machines accumulates one zero-byte file per machine name, forever.
///
/// Sweeping is safe here only because both conditions must hold: the machine's
/// data directory is gone, *and* the lock can be taken without blocking, which
/// no in-flight fork or checkpoint would permit. A file failing either check is
/// left for a later sweep rather than raced against.
///
/// Best-effort by design, like [`crate::agent::prune_orphaned_ready_markers`]:
/// a lock this process cannot open or unlink is simply left in place.
pub fn prune_orphaned_fork_source_locks() {
    prune_orphaned_fork_source_locks_in(&crate::agent::vm_cache_root());
}

fn prune_orphaned_fork_source_locks_in(vms_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(vms_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(source) = fork_source_lock_owner(&path) else {
            continue;
        };
        if vms_dir.join(crate::agent::vm_dir_hash(&source)).is_dir() {
            continue;
        }
        let Ok(file) = std::fs::OpenOptions::new().write(true).open(&path) else {
            continue;
        };
        if try_lock_file_exclusive(&file).is_err() {
            continue;
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// Path to a forkable machine's control socket (pause/resume/checkpoint/FORK).
pub fn control_socket_path(name: &str) -> PathBuf {
    vm_data_dir(name).join("control.sock")
}

/// Send a single line command to a VM control socket and return its reply line.
pub fn control_socket_cmd(sock: &Path, cmd: &str) -> Result<String> {
    control_socket_cmd_with_timeout(sock, cmd, std::time::Duration::from_secs(60))
}

/// Send a control command with an operation-specific read timeout.
///
/// Durable saves stream configured guest RAM before replying and therefore
/// need a much larger bound than ordinary pause/fork/status operations.
pub fn control_socket_cmd_with_timeout(
    sock: &Path,
    cmd: &str,
    timeout: std::time::Duration,
) -> Result<String> {
    use crate::platform::uds::UdsStream;
    use std::io::{Read, Write};

    let mut stream = UdsStream::connect(sock)
        .map_err(|e| Error::agent("connect control socket", e.to_string()))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream
        .write_all(format!("{cmd}\n").as_bytes())
        .map_err(|e| Error::agent("write control socket", e.to_string()))?;
    let mut reply = String::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                reply.push(byte[0] as char);
            }
            Err(e) => return Err(Error::agent("read control socket", e.to_string())),
        }
    }
    Ok(reply)
}

/// Workload preparation choices inherited by every clone of one golden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ForkpointProfile {
    /// Load the golden's staged CUDA modules while each clone worker boots.
    pub cuda_preload_modules: bool,
}

fn parse_forkpoint_profile(marker: &[u8]) -> ForkpointProfile {
    let hint = smolvm_protocol::forkpoint::CUDA_PRELOAD_MODULES_HINT.as_bytes();
    ForkpointProfile {
        cuda_preload_modules: marker.split(|byte| *byte == b'\n').any(|line| line == hint),
    }
}

fn persist_forkpoint_profile(golden: &str, profile: ForkpointProfile) -> Result<()> {
    let updated = SmolvmDb::open()?.update_vm(golden, |record| {
        record.cuda_preload_modules = profile.cuda_preload_modules;
    })?;
    if updated.is_none() {
        return Err(Error::vm_not_found(golden));
    }
    Ok(())
}

/// Connect to a machine's agent and insist on the branch protocol. There is
/// one protocol; a machine whose agent does not speak it is refused with a
/// message that says what to update, never driven through an older mechanism.
fn branch_client(machine: &str, what: &str) -> Result<AgentClient> {
    let socket = vm_data_dir(machine).join("agent.sock");
    let mut client = AgentClient::connect_with_retry(&socket)
        .map_err(|e| Error::agent(what, format!("agent connect: {e}")))?;
    if !client
        .supports_typed_branchpoint()
        .map_err(|e| Error::agent(what, e.to_string()))?
    {
        return Err(Error::agent(
            what,
            format!(
                "machine '{machine}' runs a guest agent without the branch protocol \
                 ({}); update its agent rootfs to this smolvm version",
                smolvm_protocol::forkpoint::TYPED_BRANCHPOINT_CAPABILITY
            ),
        ));
    }
    Ok(client)
}

/// Wait until the golden workload reaches the standard live-fork boundary.
///
/// The workload signals this by calling `smolvm-fork-ready`, which writes the
/// marker and blocks. Keeping the wait in the VM namespace avoids coupling the
/// host to container logs, PIDs, or workload-specific files.
pub fn wait_for_forkpoint(golden: &str, timeout: Duration) -> Result<()> {
    let mut client = branch_client(golden, "wait for forkpoint")?;
    match client
        .branchpoint_wait(timeout)
        .map_err(|e| Error::agent("wait for forkpoint", e.to_string()))?
    {
        Ok(contents) => {
            let profile = parse_forkpoint_profile(contents.as_bytes());
            persist_forkpoint_profile(golden, profile)
        }
        Err(f) => Err(Error::agent(
            "wait for forkpoint",
            format!(
                "source '{golden}' did not reach a branchpoint within {}s: {f}\n\
                 A batch branch checkpoints the source at a point its workload declares by running \
                 `smolvm-branch-ready` after setup (see README, \"Branch a running machine\"). \
                 If the workload never calls it, either add the call, raise --ready-timeout, or \
                 take single `--name` branches, which checkpoint the source wherever it is.",
                timeout.as_secs_f64()
            ),
        )),
    }
}

/// Put the workload's helper into its restore-safe wait just before capture.
/// A branchable machine without a helper remains a valid immediate checkpoint
/// source, reported as `Ok(false)`.
fn arm_forkpoint_for_capture(golden: &str) -> Result<bool> {
    use smolvm_protocol::forkpoint::typed_error;
    let mut client = branch_client(golden, "arm branchpoint")?;
    match client
        .branchpoint_arm()
        .map_err(|e| Error::agent("arm branchpoint", e.to_string()))?
    {
        Ok(()) => Ok(true),
        // No branchpoint declared: a branchable machine without a helper is
        // a valid immediate snapshot source.
        Err(f) if f.code.as_deref() == Some(typed_error::NOT_READY) => Ok(false),
        Err(f) if f.code.as_deref() == Some(typed_error::NO_ACK) => Err(Error::agent(
            "arm branchpoint",
            format!("source '{golden}' did not acknowledge the capture arm marker: {f}"),
        )),
        Err(f) => Err(Error::agent(
            "arm branchpoint",
            format!("source '{golden}': {f}"),
        )),
    }
}

/// Park the continued source after capture. Failure is reported to the caller,
/// which can retain the valid snapshot while making the performance fault
/// visible instead of corrupting a completed branch generation.
fn park_forkpoint_after_capture(golden: &str) -> Result<()> {
    let mut client = branch_client(golden, "park branchpoint")?;
    match client
        .branchpoint_park()
        .map_err(|e| Error::agent("park branchpoint", e.to_string()))?
    {
        Ok(()) => Ok(()),
        Err(f) => Err(Error::agent(
            "park branchpoint",
            format!("source '{golden}': {f}"),
        )),
    }
}

fn fork_base_already_paused(status: &str) -> bool {
    status.trim() == "OK paused"
}

/// Linux/KVM and macOS/HVF can atomically checkpoint a fork generation and
/// resume the source on private RAM and disk layers. Other hosts retain the
/// established frozen fork-base behavior.
pub fn fork_continue_enabled() -> bool {
    cfg!(any(
        all(target_os = "linux", target_arch = "x86_64"),
        target_os = "macos"
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn kernel_fault_userfaultfd_available() -> bool {
    crate::process::open_kernel_userfaultfd().is_ok()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn kernel_fault_userfaultfd_available() -> bool {
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveBranchRamMode {
    /// Map every clone from one materialized memfd generation. Clean pages stay
    /// physically shared across active siblings and only writes allocate RAM.
    Shared,
    /// Leave clone RAM empty and fetch pages from the generation guardian as
    /// they are first touched. Best for one sparse/idle child, but every child
    /// that reads a page materializes its own copy.
    Paged,
}

fn select_live_branch_ram_mode(
    userfaultfd_available: bool,
    requested: Option<&str>,
) -> Result<LiveBranchRamMode> {
    match requested.unwrap_or("auto") {
        // Every child can become active, including a held pool slot after it is
        // leased. Compilers, browsers, and other dense workloads can turn a
        // later generation into minutes of serialized fault delivery, so auto
        // always selects the sparse materialized generation. Demand paging is
        // retained as an explicit operator/debugging choice.
        "auto" => Ok(LiveBranchRamMode::Shared),
        "shared" => Ok(LiveBranchRamMode::Shared),
        "paged" if userfaultfd_available => Ok(LiveBranchRamMode::Paged),
        "paged" => Err(Error::agent(
            "fork",
            "SMOLVM_BRANCH_RAM_MODE=paged requires kernel-fault userfaultfd; run a privileged SmolVM service or grant it read/write access to /dev/userfaultfd",
        )),
        value => Err(Error::config(
            "fork",
            format!("SMOLVM_BRANCH_RAM_MODE must be auto, shared, or paged (got '{value}')"),
        )),
    }
}

fn branch_admission_value(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value.parse::<u64>().map_err(|_| {
            Error::config(
                "fork memory admission",
                format!("{name} must be a non-negative integer MiB value"),
            )
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Error::config(
            "fork memory admission",
            format!("read {name}: {error}"),
        )),
    }
}

fn branch_admission_required_mib(
    children: usize,
    child_overhead_mib: u64,
    reserve_mib: u64,
    materialized_generation_mib: u64,
) -> Option<u64> {
    u64::try_from(children)
        .ok()?
        .checked_mul(child_overhead_mib)?
        .checked_add(reserve_mib)?
        .checked_add(materialized_generation_mib)
}

/// Refuse a fan-out before capture if it would consume the host/cgroup's safe
/// boot headroom. This intentionally reserves only measured VMM boot overhead
/// plus a fresh shared generation—not every child's configured guest ceiling,
/// which would erase COW density. Managed per-VM cgroups remain the hard bound
/// for later workload writes where the service enables them.
fn admit_branch_memory(
    record: &VmRecord,
    children: usize,
    materializes_shared_generation: bool,
) -> Result<()> {
    if std::env::var("SMOLVM_BRANCH_MEMORY_ADMISSION").as_deref() == Ok("0") {
        return Ok(());
    }
    let Some(memory) = crate::process::host_memory_stats() else {
        return Ok(());
    };
    const MIB: u64 = 1024 * 1024;
    let total_mib = memory.total_bytes / MIB;
    let available_mib = memory.available_bytes / MIB;
    let default_reserve_mib = (total_mib / 20).clamp(512, 4096).min(total_mib / 2);
    let reserve_mib =
        branch_admission_value("SMOLVM_HOST_MEMORY_RESERVE_MIB", default_reserve_mib)?;
    // H100 and ordinary Linux QA put a booted, idle VMM at roughly 39–42 MiB.
    // Reserve 64 MiB to include thread stacks and transient launch state.
    let child_overhead_mib = branch_admission_value("SMOLVM_BRANCH_ADMISSION_MIB_PER_CHILD", 64)?;
    let materialized_generation_mib = if materializes_shared_generation {
        record
            .pid
            .and_then(crate::process::process_memory_stats)
            .and_then(|stats| stats.pss_bytes)
            .map(|bytes| (bytes.saturating_add(MIB - 1)) / MIB)
            .unwrap_or(u64::from(record.mem))
            .min(u64::from(record.mem))
    } else {
        0
    };
    let required_mib = branch_admission_required_mib(
        children,
        child_overhead_mib,
        reserve_mib,
        materialized_generation_mib,
    )
    .ok_or_else(|| Error::agent("fork memory admission", "memory estimate overflow"))?;
    if available_mib < required_mib {
        return Err(Error::vm_creation(format!(
            "branch needs at least {required_mib} MiB of effective host headroom for {children} children, but only {available_mib} MiB is available; reduce the batch, free memory, or tune SMOLVM_HOST_MEMORY_RESERVE_MIB/SMOLVM_BRANCH_ADMISSION_MIB_PER_CHILD"
        )));
    }
    tracing::debug!(
        children,
        available_mib,
        required_mib,
        reserve_mib,
        child_overhead_mib,
        materialized_generation_mib,
        "branch memory admission passed"
    );
    Ok(())
}

pub(crate) fn retained_snapshot_source_continues(snapshot: &RetainedForkSnapshot) -> bool {
    snapshot.path.join("source-continues-v1").is_file()
}

fn restart_blocking_dependent_clones_in(
    db: &SmolvmDb,
    golden: &str,
    snapshot_root: &Path,
) -> Result<Vec<String>> {
    let mut blocking = db
        .list_vms()?
        .into_iter()
        .filter_map(|(name, record)| {
            if record.golden.as_deref() != Some(golden) {
                return None;
            }
            let safe_live_generation =
                record.fork_generation.as_deref().is_some_and(|generation| {
                    snapshot_root
                        .join(generation)
                        .join("source-continues-v1")
                        .is_file()
                });
            (!safe_live_generation).then_some(name)
        })
        .collect::<Vec<_>>();
    blocking.sort();
    Ok(blocking)
}

/// Return clones whose disk lineage still requires their source to remain
/// frozen. Live fork-and-continue generations pivot the source onto a new CoW
/// overlay before it resumes, so restarting that source cannot mutate a
/// clone's backing disk; older frozen generations retain the strict guard.
pub fn restart_blocking_dependent_clones(db: &SmolvmDb, golden: &str) -> Result<Vec<String>> {
    restart_blocking_dependent_clones_in(db, golden, &vm_data_dir(golden).join("s"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fork_continue_snapshot(snapshot_dir: &Path) -> bool {
    snapshot_dir.join("generation-disks.tsv").is_file()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fork_continue_snapshot(_snapshot_dir: &Path) -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn atomic_write_snapshot_file(path: &Path, contents: &[u8]) -> Result<()> {
    let partial = path.with_extension(format!(
        "{}.partial",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("tmp")
    ));
    let mut published = false;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&partial)
            .map_err(|error| Error::agent("create snapshot metadata", error.to_string()))?;
        file.write_all(contents)
            .map_err(|error| Error::agent("write snapshot metadata", error.to_string()))?;
        file.sync_all()
            .map_err(|error| Error::agent("sync snapshot metadata", error.to_string()))?;
        std::fs::hard_link(&partial, path)
            .map_err(|error| Error::agent("publish snapshot metadata", error.to_string()))?;
        published = true;
        let _ = std::fs::remove_file(&partial);
        let parent = path.parent().ok_or_else(|| {
            Error::agent("publish snapshot metadata", "metadata path has no parent")
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| Error::agent("sync snapshot directory", error.to_string()))
    })();
    if result.is_err() {
        if published {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_file(partial);
    }
    result
}

#[cfg(target_os = "linux")]
const GUARDIAN_MANIFEST_MAGIC: u64 = 0x534d4f4c4752444e;
#[cfg(target_os = "linux")]
const GUARDIAN_SOCKET_NAME: &str = "g";

#[cfg(target_os = "linux")]
fn snapshot_guardian_identity(snapshot_dir: &Path) -> Result<Option<(i32, u64, PathBuf)>> {
    let manifest_path = snapshot_dir.join("manifest.bin");
    let bytes = match std::fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::agent(
                "read RAM guardian manifest",
                error.to_string(),
            ));
        }
    };
    if bytes.len() < 72 {
        return Ok(None);
    }
    let magic = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    if magic != GUARDIAN_MANIFEST_MAGIC {
        return Ok(None);
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let pid = i32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let reserved = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let start_time = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let socket_len = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    let socket_end = 72_usize
        .checked_add(socket_len)
        .ok_or_else(|| Error::agent("read RAM guardian manifest", "socket length overflow"))?;
    if version != 1
        || flags != 0
        || reserved != 0
        || pid <= 0
        || start_time == 0
        || socket_len == 0
        || socket_len > 100
        || socket_end > bytes.len()
    {
        return Err(Error::agent(
            "read RAM guardian manifest",
            "invalid guardian process metadata",
        ));
    }
    #[cfg(unix)]
    let socket_path = {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_vec(bytes[72..socket_end].to_vec()))
    };
    if socket_path != snapshot_dir.join(GUARDIAN_SOCKET_NAME) {
        return Err(Error::agent(
            "read RAM guardian manifest",
            "guardian socket escapes its snapshot directory",
        ));
    }
    Ok(Some((pid, start_time, socket_path)))
}

#[cfg(target_os = "linux")]
fn stop_snapshot_guardian(snapshot_dir: &Path) -> Result<()> {
    let Some((pid, start_time, socket_path)) = snapshot_guardian_identity(snapshot_dir)? else {
        return Ok(());
    };
    if crate::process::is_our_process_strict(pid, Some(start_time)) {
        // The guardian inherits libkrun's SIGTERM handler from its source VMM,
        // so graceful termination can be consumed without exiting. The
        // versioned manifest, exact private socket path, executable identity,
        // PID, and process start time jointly authenticate the target; use
        // SIGKILL directly so generation cleanup is deterministic.
        if !crate::process::kill_verified(pid, Some(start_time)) {
            return Err(Error::agent(
                "stop RAM guardian",
                format!("failed to terminate verified guardian PID {pid}"),
            ));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while crate::process::is_our_process_strict(pid, Some(start_time))
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if crate::process::is_our_process_strict(pid, Some(start_time)) {
            return Err(Error::agent(
                "stop RAM guardian",
                format!("verified guardian PID {pid} did not exit after SIGKILL"),
            ));
        }
    }
    match std::fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::agent(
                "remove RAM guardian socket",
                error.to_string(),
            ))
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn stop_snapshot_guardian(_snapshot_dir: &Path) -> Result<()> {
    Ok(())
}

fn stop_snapshot_guardians(snapshot_root: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(snapshot_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::agent("list RAM guardians", error.to_string())),
    };
    for entry in entries {
        let entry = entry.map_err(|error| Error::agent("list RAM guardians", error.to_string()))?;
        if entry
            .file_type()
            .map_err(|error| Error::agent("inspect RAM guardian", error.to_string()))?
            .is_dir()
        {
            stop_snapshot_guardian(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prepare_running_disk_generation(
    gdir: &Path,
    snapshot_dir: &Path,
    vm_ids: Option<(u32, u32)>,
) -> Result<()> {
    use crate::data::disk::DiskFormat;

    ensure_fork_disk_chain_is_bounded(gdir)?;

    let generation_id = snapshot_dir.file_name().ok_or_else(|| {
        Error::agent(
            "fork-continue disk generation",
            "snapshot directory has no generation id",
        )
    })?;
    let generation_disk_dir = gdir.join("d").join(generation_id);
    std::fs::create_dir_all(gdir.join("d"))
        .map_err(|error| Error::agent("create disk generation root", error.to_string()))?;
    std::fs::create_dir(&generation_disk_dir)
        .map_err(|error| Error::agent("create disk generation", error.to_string()))?;
    let mut overlays = Vec::new();
    let mut pivot_lines = Vec::new();
    let mut generation_lines = Vec::new();
    let mut rotations = Vec::new();
    for (id, raw) in [
        ("storage", crate::data::storage::STORAGE_DISK_FILENAME),
        ("overlay", crate::data::storage::OVERLAY_DISK_FILENAME),
    ] {
        let (base, format) = resolve_disk_image(gdir, raw);
        if !base.exists() {
            continue;
        }
        let active = gdir.join(Path::new(raw).with_extension("qcow2"));
        let base = if format == DiskFormat::Qcow2 {
            let generation_base = generation_disk_dir.join(format!("{id}.base.qcow2"));
            if let Err(error) = stage_relocated_qcow2_backings(&base, &generation_base) {
                rollback_prepared_disk_generation(&overlays, &rotations, &generation_disk_dir);
                return Err(error);
            }
            if let Err(error) = std::fs::rename(&base, &generation_base) {
                rollback_prepared_disk_generation(&overlays, &rotations, &generation_disk_dir);
                return Err(Error::agent(
                    "rotate fork-continue disk",
                    format!(
                        "{} -> {}: {error}",
                        base.display(),
                        generation_base.display()
                    ),
                ));
            }
            rotations.push((generation_base.clone(), base));
            generation_base
        } else {
            base
        };
        let base = match base.canonicalize() {
            Ok(base) => base,
            Err(error) => {
                rollback_prepared_disk_generation(&overlays, &rotations, &generation_disk_dir);
                return Err(Error::agent("fork-continue disk base", error.to_string()));
            }
        };
        overlays.push((active.clone(), base.clone(), format));
        pivot_lines.push((id, active));
        generation_lines.push((raw, base, format));
    }
    if overlays.is_empty() {
        let _ = std::fs::remove_dir(&generation_disk_dir);
        return Err(Error::agent(
            "fork-continue",
            "source has no block disks to pivot",
        ));
    }

    if let Err(error) = crate::agent::create_disk_overlays(&overlays) {
        rollback_prepared_disk_generation(&overlays, &rotations, &generation_disk_dir);
        return Err(error);
    }
    if let Some((uid, gid)) = vm_ids {
        for (active, _, _) in &overlays {
            if let Err(error) = crate::process::chown_tree(active, uid, gid) {
                rollback_prepared_disk_generation(&overlays, &rotations, &generation_disk_dir);
                return Err(Error::agent(
                    "hand live-fork disk to source VMM",
                    format!("{}: {error}", active.display()),
                ));
            }
        }
    }
    let write_result = (|| {
        let mut pivots = String::new();
        for (id, active) in &pivot_lines {
            let active = active
                .canonicalize()
                .map_err(|error| Error::agent("fork-continue active disk", error.to_string()))?;
            pivots.push_str(id);
            pivots.push('\t');
            pivots.push_str(&active.to_string_lossy());
            pivots.push('\n');
        }
        atomic_write_snapshot_file(&snapshot_dir.join("block-pivots.tsv"), pivots.as_bytes())?;

        let mut generation = String::new();
        for (raw, base, format) in &generation_lines {
            let format = match format {
                DiskFormat::Raw => "raw",
                DiskFormat::Qcow2 => "qcow2",
            };
            generation.push_str(raw);
            generation.push('\t');
            generation.push_str(&base.to_string_lossy());
            generation.push('\t');
            generation.push_str(format);
            generation.push('\n');
        }
        atomic_write_snapshot_file(
            &snapshot_dir.join("generation-disks.tsv"),
            generation.as_bytes(),
        )
    })();
    if let Err(error) = write_result {
        rollback_prepared_disk_generation(&overlays, &rotations, &generation_disk_dir);
        return Err(error);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_FORK_DISK_CHAIN_DEPTH: usize = 32;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn qcow2_backing_depth(path: &Path) -> Result<usize> {
    let mut current = path.canonicalize().map_err(|error| {
        Error::agent(
            "inspect fork disk chain",
            format!("{}: {error}", path.display()),
        )
    })?;
    let mut seen = HashSet::new();
    let mut depth = 0_usize;
    loop {
        if !seen.insert(current.clone()) {
            return Err(Error::agent(
                "inspect fork disk chain",
                format!("cycle at {}", current.display()),
            ));
        }
        let Some(backing) = qcow2_backing_name(&current)? else {
            return Ok(depth);
        };
        let next = if backing.is_absolute() {
            backing
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(backing)
        };
        current = next.canonicalize().map_err(|error| {
            Error::agent(
                "inspect fork disk chain",
                format!("backing of {}: {error}", current.display()),
            )
        })?;
        depth = depth
            .checked_add(1)
            .ok_or_else(|| Error::agent("inspect fork disk chain", "backing depth overflow"))?;
        if depth > MAX_FORK_DISK_CHAIN_DEPTH {
            return Ok(depth);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn qcow2_backing_name(path: &Path) -> Result<Option<PathBuf>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(path).map_err(|error| {
        Error::agent(
            "inspect fork disk chain",
            format!("{}: {error}", path.display()),
        )
    })?;
    let mut header = [0_u8; 20];
    file.read_exact(&mut header).map_err(|error| {
        Error::agent(
            "inspect fork disk chain",
            format!("{}: {error}", path.display()),
        )
    })?;
    if header[..4] != *b"QFI\xfb" {
        return Ok(None);
    }
    let offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let length = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    if offset == 0 && length == 0 {
        return Ok(None);
    }
    if offset == 0 || length == 0 || length > 4096 {
        return Err(Error::agent(
            "inspect fork disk chain",
            format!("{} has invalid qcow2 backing metadata", path.display()),
        ));
    }
    let end = offset
        .checked_add(length as u64)
        .ok_or_else(|| Error::agent("inspect fork disk chain", "backing offset overflow"))?;
    if end
        > file
            .metadata()
            .map_err(|error| Error::agent("inspect fork disk chain", error.to_string()))?
            .len()
    {
        return Err(Error::agent(
            "inspect fork disk chain",
            format!("{} has a truncated qcow2 backing name", path.display()),
        ));
    }
    let mut name = vec![0_u8; length];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut name))
        .map_err(|error| Error::agent("inspect fork disk chain", error.to_string()))?;
    let backing = std::str::from_utf8(&name).map_err(|error| {
        Error::agent(
            "inspect fork disk chain",
            format!("{} has a non-UTF-8 backing name: {error}", path.display()),
        )
    })?;
    Ok(Some(PathBuf::from(backing)))
}

/// Preserve relative backing names when an active qcow2 image is moved into a
/// fork-generation directory. Portable checkpoint disks deliberately use
/// compact relative names (`0`, `1`, ...); moving only the top image would make
/// those names resolve inside the new directory and break the first fork of a
/// restored machine. Hard-linking the immutable backing chain keeps the move
/// O(metadata) and does not duplicate disk contents.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stage_relocated_qcow2_backings(source_top: &Path, relocated_top: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let mut source = source_top.canonicalize().map_err(|error| {
        Error::agent(
            "stage fork disk backing",
            format!("{}: {error}", source_top.display()),
        )
    })?;
    let mut relocated = relocated_top.to_path_buf();
    let mut seen = HashSet::new();
    for _ in 0..MAX_FORK_DISK_CHAIN_DEPTH {
        if !seen.insert(source.clone()) {
            return Err(Error::agent(
                "stage fork disk backing",
                format!("cycle at {}", source.display()),
            ));
        }
        let Some(backing) = qcow2_backing_name(&source)? else {
            return Ok(());
        };
        if backing.is_absolute() {
            return Ok(());
        }
        if !backing
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(Error::agent(
                "stage fork disk backing",
                format!(
                    "{} has unsafe relative backing name {}",
                    source.display(),
                    backing.display()
                ),
            ));
        }
        let source_next = source
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&backing)
            .canonicalize()
            .map_err(|error| {
                Error::agent(
                    "stage fork disk backing",
                    format!("backing of {}: {error}", source.display()),
                )
            })?;
        let relocated_next = relocated
            .parent()
            .ok_or_else(|| Error::agent("stage fork disk backing", "missing parent directory"))?
            .join(&backing);
        if let Some(parent) = relocated_next.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::agent("stage fork disk backing", error.to_string()))?;
        }
        match std::fs::hard_link(&source_next, &relocated_next) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let source_meta = std::fs::metadata(&source_next).map_err(|inspect| {
                    Error::agent("stage fork disk backing", inspect.to_string())
                })?;
                let relocated_meta = std::fs::metadata(&relocated_next).map_err(|inspect| {
                    Error::agent("stage fork disk backing", inspect.to_string())
                })?;
                if source_meta.dev() != relocated_meta.dev()
                    || source_meta.ino() != relocated_meta.ino()
                {
                    return Err(Error::agent(
                        "stage fork disk backing",
                        format!(
                            "{} already exists for a different backing file",
                            relocated_next.display()
                        ),
                    ));
                }
            }
            Err(error) => {
                return Err(Error::agent(
                    "stage fork disk backing",
                    format!(
                        "{} -> {}: {error}",
                        source_next.display(),
                        relocated_next.display()
                    ),
                ));
            }
        }
        source = source_next;
        relocated = relocated_next;
    }
    Err(Error::agent(
        "stage fork disk backing",
        format!(
            "{} exceeds the safe backing depth of {MAX_FORK_DISK_CHAIN_DEPTH}",
            source_top.display()
        ),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_fork_disk_chain_is_bounded(gdir: &Path) -> Result<()> {
    for raw in [
        crate::data::storage::STORAGE_DISK_FILENAME,
        crate::data::storage::OVERLAY_DISK_FILENAME,
    ] {
        let (disk, format) = resolve_disk_image(gdir, raw);
        if !disk.is_file() || format != crate::data::disk::DiskFormat::Qcow2 {
            continue;
        }
        let depth = qcow2_backing_depth(&disk)?;
        if depth >= MAX_FORK_DISK_CHAIN_DEPTH {
            return Err(Error::agent(
                "fork-continue",
                format!(
                    "{} already has {depth} qcow2 backing layers; the safe limit is \
                     {MAX_FORK_DISK_CHAIN_DEPTH}. Stop and pack this machine into a new root \
                     before creating another live fork",
                    disk.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Undo file preparation when the VMM never published its commit marker.
///
/// The source must first be proven running. The VMM protocol guarantees it
/// cannot resume after switching to the new active overlays until the marker
/// is durable, so a running source without the marker still owns the rotated
/// base files and this operation is safe and idempotent.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rollback_uncommitted_disk_generation(gdir: &Path, snapshot_dir: &Path) -> Result<()> {
    use crate::data::disk::DiskFormat;

    let generation_id = snapshot_dir.file_name().ok_or_else(|| {
        Error::agent(
            "recover disk generation",
            "snapshot directory has no generation id",
        )
    })?;
    let generation_disk_dir = gdir.join("d").join(generation_id);
    let contents = std::fs::read_to_string(snapshot_dir.join("generation-disks.tsv"))
        .map_err(|error| Error::agent("recover disk generation", error.to_string()))?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for (line_number, line) in contents.lines().enumerate() {
        let mut fields = line.split('\t');
        let raw = fields.next().unwrap_or_default();
        let _recorded_base = fields.next().unwrap_or_default();
        let format = fields.next().unwrap_or_default();
        if fields.next().is_some() {
            return Err(Error::agent(
                "recover disk generation",
                format!("line {} has extra fields", line_number + 1),
            ));
        }
        let (raw, role) = match raw {
            crate::data::storage::STORAGE_DISK_FILENAME => {
                (crate::data::storage::STORAGE_DISK_FILENAME, "storage")
            }
            crate::data::storage::OVERLAY_DISK_FILENAME => {
                (crate::data::storage::OVERLAY_DISK_FILENAME, "overlay")
            }
            _ => {
                return Err(Error::agent(
                    "recover disk generation",
                    format!("line {} has unknown disk role", line_number + 1),
                ));
            }
        };
        if !seen.insert(raw) {
            return Err(Error::agent(
                "recover disk generation",
                format!("line {} duplicates {raw}", line_number + 1),
            ));
        }
        let format = match format {
            "raw" => DiskFormat::Raw,
            "qcow2" => DiskFormat::Qcow2,
            _ => {
                return Err(Error::agent(
                    "recover disk generation",
                    format!("line {} has unknown disk format", line_number + 1),
                ));
            }
        };
        records.push((raw, role, format));
    }
    if records.is_empty() {
        return Err(Error::agent("recover disk generation", "manifest is empty"));
    }

    for (raw, role, format) in records {
        let active = gdir.join(Path::new(raw).with_extension("qcow2"));
        match format {
            DiskFormat::Raw => match std::fs::remove_file(&active) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Error::agent("recover disk generation", error.to_string()));
                }
            },
            DiskFormat::Qcow2 => {
                let base = generation_disk_dir.join(format!("{role}.base.qcow2"));
                if base.exists() {
                    match std::fs::remove_file(&active) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(Error::agent("recover disk generation", error.to_string()));
                        }
                    }
                    std::fs::rename(&base, &active).map_err(|error| {
                        Error::agent("recover disk generation", error.to_string())
                    })?;
                } else if !active.exists() {
                    return Err(Error::agent(
                        "recover disk generation",
                        format!(
                            "both rotated base {} and active disk {} are missing",
                            base.display(),
                            active.display()
                        ),
                    ));
                }
            }
        }
    }
    match std::fs::remove_dir_all(&generation_disk_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::agent(
                "recover disk generation",
                format!(
                    "remove {} after rollback: {error}",
                    generation_disk_dir.display()
                ),
            ));
        }
    }
    File::open(gdir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| Error::agent("sync recovered disk generation", error.to_string()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn recover_uncommitted_generations(
    db: &SmolvmDb,
    golden: &str,
    gdir: &Path,
    snapshot_root: &Path,
) -> Result<()> {
    let entries = match std::fs::read_dir(snapshot_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::agent("recover fork generations", error.to_string()));
        }
    };
    let retained = db.retained_fork_snapshot(golden)?;
    for entry in entries {
        let entry =
            entry.map_err(|error| Error::agent("recover fork generations", error.to_string()))?;
        if !entry
            .file_type()
            .map_err(|error| Error::agent("recover fork generations", error.to_string()))?
            .is_dir()
        {
            continue;
        }
        let snapshot = entry.path();
        if !fork_continue_snapshot(&snapshot) || snapshot.join("source-continues-v1").is_file() {
            continue;
        }
        rollback_uncommitted_disk_generation(gdir, &snapshot)?;
        stop_snapshot_guardian(&snapshot)?;
        std::fs::remove_dir_all(&snapshot)
            .map_err(|error| Error::agent("recover fork generation", error.to_string()))?;
        if retained
            .as_ref()
            .is_some_and(|value| value.path == snapshot)
        {
            db.remove_retained_fork_snapshot(golden)?;
        }
    }
    Ok(())
}

fn snapshot_generation_id(snapshot: &Path) -> Option<&str> {
    snapshot
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.len() == 8 && name.as_bytes().iter().all(u8::is_ascii_hexdigit))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn gc_unreferenced_fork_generations(
    db: &SmolvmDb,
    golden: &str,
    snapshot_root: &Path,
    retained: Option<&RetainedForkSnapshot>,
) -> Result<()> {
    let live_generations = db
        .list_vms()?
        .into_iter()
        .filter_map(|(_, record)| {
            (record.golden.as_deref() == Some(golden))
                .then_some(record.fork_generation)
                .flatten()
        })
        .collect::<HashSet<_>>();
    let entries = match std::fs::read_dir(snapshot_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::agent("collect fork generations", error.to_string()));
        }
    };
    for entry in entries {
        let entry =
            entry.map_err(|error| Error::agent("collect fork generations", error.to_string()))?;
        if !entry
            .file_type()
            .map_err(|error| Error::agent("collect fork generations", error.to_string()))?
            .is_dir()
        {
            continue;
        }
        let snapshot = entry.path();
        let Some(generation) = snapshot_generation_id(&snapshot) else {
            continue;
        };
        if !snapshot.join("source-continues-v1").is_file()
            || retained.is_some_and(|retained| retained.path == snapshot)
            || live_generations.contains(generation)
        {
            continue;
        }
        stop_snapshot_guardian(&snapshot)?;
        std::fs::remove_dir_all(&snapshot)
            .map_err(|error| Error::agent("collect fork generation", error.to_string()))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn referenced_fork_generation_count(
    db: &SmolvmDb,
    golden: &str,
    snapshot_root: &Path,
    retained: Option<&RetainedForkSnapshot>,
) -> Result<u64> {
    let mut generations = db
        .list_vms()?
        .into_iter()
        .filter_map(|(_, record)| {
            (record.golden.as_deref() == Some(golden))
                .then_some(record.fork_generation)
                .flatten()
        })
        .filter(|generation| {
            generation.len() == 8
                && generation.as_bytes().iter().all(u8::is_ascii_hexdigit)
                && snapshot_root
                    .join(generation)
                    .join("source-continues-v1")
                    .is_file()
        })
        .collect::<HashSet<_>>();
    if let Some(retained) = retained {
        if reusable_snapshot_path(snapshot_root, &retained.path)
            && retained_snapshot_source_continues(retained)
        {
            if let Some(generation) = snapshot_generation_id(&retained.path) {
                generations.insert(generation.to_string());
            }
        }
    }
    u64::try_from(generations.len())
        .map_err(|_| Error::agent("fork memory accounting", "generation count overflow"))
}

#[cfg(target_os = "linux")]
fn fork_lineage_memory_limit_bytes(record: &VmRecord, additional_ram_units: u64) -> Result<u64> {
    let guest_bytes = u64::from(record.mem)
        .checked_mul(1024 * 1024)
        .ok_or_else(|| Error::agent("fork memory accounting", "guest memory size overflow"))?;
    crate::process::vmm_memory_limit_bytes(record.mem, record.cuda)
        .checked_add(
            additional_ram_units
                .checked_mul(guest_bytes)
                .ok_or_else(|| {
                    Error::agent("fork memory accounting", "lineage RAM size overflow")
                })?,
        )
        .ok_or_else(|| Error::agent("fork memory accounting", "lineage memory limit overflow"))
}

#[cfg(target_os = "linux")]
fn source_has_private_ram_backing(record: &VmRecord) -> bool {
    record.pid_start_time.is_some() && record.fork_lineage_pid_start_time == record.pid_start_time
}

#[cfg(target_os = "linux")]
fn set_fork_lineage_memory_limit(
    golden: &str,
    record: &VmRecord,
    generations: u64,
) -> Result<bool> {
    let Some(pid) = record.pid else {
        return Ok(false);
    };
    if !crate::process::is_our_process_strict(pid, record.pid_start_time) {
        return Ok(false);
    }
    let limit = fork_lineage_memory_limit_bytes(record, generations)?;
    let updated = crate::process::set_managed_vmm_memory_limit(golden, pid, limit)?;
    if updated {
        tracing::debug!(%golden, generations, memory_max_bytes = limit, "sized live-branch lineage cgroup");
    }
    Ok(updated)
}

#[cfg(target_os = "linux")]
fn reconcile_fork_lineage_memory_limit(
    db: &SmolvmDb,
    golden: &str,
    record: &VmRecord,
    snapshot_root: &Path,
    retained: Option<&RetainedForkSnapshot>,
) -> Result<()> {
    let generations = referenced_fork_generation_count(db, golden, snapshot_root, retained)?;
    let additional_ram_units = generations + u64::from(source_has_private_ram_backing(record));
    set_fork_lineage_memory_limit(golden, record, additional_ram_units).map(|_| ())
}

/// Reserve one generation's worst-case resident RAM before the source resumes.
///
/// All immutable generation pages stay charged to the cgroup that originally
/// faulted the source RAM. A raw-forked guardian cannot fix that by moving to a
/// different cgroup because cgroup v2 does not migrate existing page charges.
/// Size the owned VM scope for the source, every referenced generation, and
/// the source's persistent private-over-memfd backing, then reconcile it on
/// drop after success or rollback.
#[cfg(target_os = "linux")]
struct ForkLineageMemoryReservation {
    golden: String,
    record: VmRecord,
    snapshot_dir: PathBuf,
    previous_ram_units: u64,
    source_rebased: bool,
    managed: bool,
}

#[cfg(target_os = "linux")]
impl ForkLineageMemoryReservation {
    fn reserve(
        golden: &str,
        record: &VmRecord,
        snapshot_dir: &Path,
        previous_generations: u64,
    ) -> Result<Self> {
        let already_rebased = source_has_private_ram_backing(record);
        let previous_ram_units = previous_generations
            .checked_add(u64::from(already_rebased))
            .ok_or_else(|| Error::agent("fork memory accounting", "RAM unit count overflow"))?;
        // Reserve the new immutable generation plus the source's persistent
        // private-over-memfd backing on its first continue capture. The first
        // generation overlaps that backing, so this is conservatively one
        // guest above physical use until the original generation is collected.
        let reserved = previous_ram_units
            .checked_add(1)
            .and_then(|units| units.checked_add(u64::from(!already_rebased)))
            .ok_or_else(|| Error::agent("fork memory accounting", "RAM unit count overflow"))?;
        let managed = set_fork_lineage_memory_limit(golden, record, reserved)?;
        Ok(Self {
            golden: golden.to_string(),
            record: record.clone(),
            snapshot_dir: snapshot_dir.to_path_buf(),
            previous_ram_units,
            source_rebased: false,
            managed,
        })
    }

    fn mark_source_rebased(&mut self) {
        self.source_rebased = true;
    }
}

#[cfg(target_os = "linux")]
impl Drop for ForkLineageMemoryReservation {
    fn drop(&mut self) {
        if !self.managed {
            return;
        }
        // A published commit marker means the new generation really can retain
        // one guest's worth of charged pages. Keep its bounded reservation;
        // DB-backed reconciliation after publication and GC makes it exact.
        if self.snapshot_dir.join("source-continues-v1").is_file() {
            return;
        }
        let rollback_units = self.previous_ram_units.saturating_add(u64::from(
            self.source_rebased && !source_has_private_ram_backing(&self.record),
        ));
        let result =
            set_fork_lineage_memory_limit(&self.golden, &self.record, rollback_units).map(|_| ());
        if let Err(error) = result {
            // A stale high ceiling is safer than lowering below live charged
            // memory. The next branch or child-GC pass reconciles it again.
            tracing::warn!(golden = %self.golden, %error, "could not reconcile live-branch lineage cgroup");
        }
    }
}

/// Collect generations made unreachable by deleting a child. Non-blocking lock
/// acquisition avoids deadlocking a cascading parent delete that already owns
/// the same cross-process source lock; that path removes the whole snapshot
/// tree moments later.
#[doc(hidden)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn collect_parent_generations_after_child_delete(db: &SmolvmDb, parent: &str) -> Result<()> {
    let Some(_lock) = try_lock_fork_source(parent)? else {
        tracing::debug!(%parent, "deferred fork-generation GC while source transaction is active");
        return Ok(());
    };
    let record = db.get_vm(parent)?;
    if record.is_none() {
        return Ok(());
    }
    let snapshot_root = vm_data_dir(parent).join("s");
    let retained = db.retained_fork_snapshot(parent)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    gc_unreferenced_fork_generations(db, parent, &snapshot_root, retained.as_ref())?;
    #[cfg(target_os = "linux")]
    reconcile_fork_lineage_memory_limit(
        db,
        parent,
        record.as_ref().unwrap(),
        &snapshot_root,
        retained.as_ref(),
    )?;
    Ok(())
}

#[doc(hidden)]
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_parent_generations_after_child_delete(_db: &SmolvmDb, _parent: &str) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rollback_prepared_disk_generation(
    overlays: &[(PathBuf, PathBuf, crate::data::disk::DiskFormat)],
    rotations: &[(PathBuf, PathBuf)],
    generation_disk_dir: &Path,
) {
    for (active, _, _) in overlays {
        let _ = std::fs::remove_file(active);
    }
    for (generation_base, original) in rotations.iter().rev() {
        let _ = std::fs::rename(generation_base, original);
    }
    let _ = std::fs::remove_dir_all(generation_disk_dir);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_generation_fork_disks(snapshot_dir: &Path) -> Result<Option<Vec<ForkDisk>>> {
    use crate::data::disk::DiskFormat;

    let path = snapshot_dir.join("generation-disks.tsv");
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::agent(
                "read generation disk manifest",
                error.to_string(),
            ));
        }
    };
    let mut disks = Vec::new();
    let mut seen = HashSet::new();
    for (line_number, line) in contents.lines().enumerate() {
        let mut fields = line.split('\t');
        let raw = fields.next().unwrap_or_default();
        let base = fields.next().unwrap_or_default();
        let format = fields.next().unwrap_or_default();
        if fields.next().is_some() {
            return Err(Error::agent(
                "read generation disk manifest",
                format!("line {} has extra fields", line_number + 1),
            ));
        }
        let raw = match raw {
            crate::data::storage::STORAGE_DISK_FILENAME => {
                crate::data::storage::STORAGE_DISK_FILENAME
            }
            crate::data::storage::OVERLAY_DISK_FILENAME => {
                crate::data::storage::OVERLAY_DISK_FILENAME
            }
            _ => {
                return Err(Error::agent(
                    "read generation disk manifest",
                    format!("line {} has unknown disk role", line_number + 1),
                ));
            }
        };
        if !seen.insert(raw) {
            return Err(Error::agent(
                "read generation disk manifest",
                format!("line {} duplicates {raw}", line_number + 1),
            ));
        }
        let format = match format {
            "raw" => DiskFormat::Raw,
            "qcow2" => DiskFormat::Qcow2,
            _ => {
                return Err(Error::agent(
                    "read generation disk manifest",
                    format!("line {} has unknown disk format", line_number + 1),
                ));
            }
        };
        let base = PathBuf::from(base).canonicalize().map_err(|error| {
            Error::agent(
                "read generation disk manifest",
                format!("line {}: {error}", line_number + 1),
            )
        })?;
        disks.push((raw, base, format));
    }
    if disks.is_empty() {
        return Err(Error::agent(
            "read generation disk manifest",
            "manifest is empty",
        ));
    }
    Ok(Some(disks))
}

/// Flush guest filesystems before capturing a new live checkpoint.
///
/// A branch sees dirty guest page-cache state through the RAM snapshot, but a
/// later stop/restart of the source can only reopen its host disk images. If we
/// freeze before `sync`, that restart silently loses writes that every live
/// branch appeared to inherit. Restored children also need this boundary to
/// avoid capturing an overlayfs mount whose first lookup can block. Complete
/// the guest-visible durability boundary before libkrun drains block workers
/// and freezes the vCPUs for every newly captured checkpoint.
pub fn sync_fork_source(name: &str) -> Result<()> {
    let socket = vm_data_dir(name).join("agent.sock");
    let mut client = AgentClient::connect_with_retry(&socket)
        .map_err(|error| Error::agent("sync fork source", error.to_string()))?;
    match client.vm_exec(
        vec!["/bin/sync".to_string()],
        Vec::new(),
        None,
        Some(Duration::from_secs(30)),
        None,
    ) {
        Ok((0, _, _)) => Ok(()),
        Ok((code, _, stderr)) => Err(Error::agent(
            "sync fork source",
            format!(
                "guest sync exited {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        )),
        Err(error) => Err(Error::agent("sync fork source", error.to_string())),
    }
}

/// Release the workload restored in `clone` after its identity and per-fork
/// environment are installed. The state directory is private guest RAM, so a
/// release marker wakes only this clone even though every clone inherited the
/// same blocked helper process. Success means the helper also acknowledged the
/// marker and left the fork boundary; callers may safely vend the clone.
/// Release a restored clone's parked helper. `env` is the clone's identity,
/// the same parameters [`write_fork_env`] installed; a typed agent carries it
/// inside the release marker so the helper receives both in one atomic step.
pub fn release_forkpoint(clone: &str, env: &[(String, String)]) -> Result<()> {
    let mut client = branch_client(clone, "release forkpoint")?;
    match client
        .branchpoint_release(&render_fork_env(env))
        .map_err(|e| Error::agent("release forkpoint", e.to_string()))?
    {
        Ok(()) => Ok(()),
        Err(f) => Err(Error::agent(
            "release forkpoint",
            format!("clone '{clone}': {f}"),
        )),
    }
}

/// Roll back a golden after every clone prepared from its snapshot has been
/// torn down. A completed fork checkpoint must be reapplied before resuming;
/// if capture failed before producing one, an ordinary resume is sufficient.
fn golden_resume_command(snapshot_dir: &Path) -> Result<String> {
    let checkpoint = snapshot_dir.join("checkpoint.bin");
    match std::fs::symlink_metadata(&checkpoint) {
        Ok(metadata) if metadata.file_type().is_file() => {
            Ok(format!("ROLLBACK_FORK {}", snapshot_dir.display()))
        }
        Ok(_) => Err(Error::agent(
            "resume golden",
            format!(
                "refusing non-regular rollback checkpoint {}",
                checkpoint.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("RESUME".to_string()),
        Err(error) => Err(Error::agent(
            "resume golden",
            format!("inspect rollback checkpoint: {error}"),
        )),
    }
}

/// Resume a failed fork's golden, restoring its completed checkpoint when one exists.
pub fn resume_golden(golden: &str, snapshot_dir: &Path) -> Result<()> {
    let command = golden_resume_command(snapshot_dir)?;
    let reply = control_socket_cmd(&control_socket_path(golden), &command)?;
    if reply.starts_with("OK") {
        Ok(())
    } else {
        Err(Error::agent(
            "resume golden",
            format!("golden '{golden}' RESUME failed: {reply}"),
        ))
    }
}

/// Remove every retained RAM checkpoint for a golden whose VMM is confirmed
/// dead and which has no dependent clones. A checkpoint is tied to the exact
/// golden PID/memfd identity and can never be valid after that process exits.
pub(crate) fn discard_retained_snapshots(db: &SmolvmDb, golden: &str) -> Result<()> {
    let snapshot_root = vm_data_dir(golden).join("s");
    match std::fs::symlink_metadata(&snapshot_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            stop_snapshot_guardians(&snapshot_root)?;
            std::fs::remove_dir_all(&snapshot_root).map_err(|error| {
                Error::agent("remove retained fork snapshots", error.to_string())
            })?;
        }
        Ok(_) => {
            return Err(Error::agent(
                "remove retained fork snapshots",
                format!(
                    "refusing to remove non-directory {}",
                    snapshot_root.display()
                ),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::agent(
                "inspect retained fork snapshots",
                error.to_string(),
            ));
        }
    }
    db.remove_retained_fork_snapshot(golden)?;
    Ok(())
}

/// The result of preparing a fork: the source checkpoint and the clone's DB
/// record + copy-on-write disks exist on disk. The caller boots the clone from
/// `snapshot_dir`, then calls [`rejuvenate_clone`].
pub struct PreparedFork {
    /// Directory holding the golden's checkpoint + memfd manifest. Pass it as the
    /// clone's `LaunchFeatures::snapshot_dir` to boot from it instead of cold.
    pub snapshot_dir: PathBuf,
    /// The clone's freshly-inserted DB record (golden's config, remapped ports).
    pub clone_record: VmRecord,
    /// Per-port inbound remap as `(golden_host, guest, clone_host)`, for the
    /// caller to log. Empty when the golden has no forwards. When ports were
    /// pinned, `golden_host == clone_host`.
    pub port_remaps: Vec<(u16, u16, u16)>,
}

/// A checkpoint that may be reused by a frozen source or an explicit pool
/// refill while the exact same source process remains alive. The PID start time
/// prevents an old checkpoint from being applied after restart or PID reuse.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct RetainedForkSnapshot {
    /// Directory containing the libkrun checkpoint and memfd manifest.
    pub(crate) path: PathBuf,
    /// Host process that produced the checkpoint.
    pub(crate) golden_pid: i32,
    /// Kernel process start time paired with `golden_pid`.
    pub(crate) golden_pid_start_time: u64,
}

/// Prepared batch plus the checkpoint identity that can service later refills.
pub(crate) struct PreparedForkBatch {
    /// Clones registered from one checkpoint.
    pub(crate) forks: Vec<PreparedFork>,
    /// Checkpoint bound to the current golden process, when its identity is
    /// strong enough to reuse safely.
    pub(crate) retained_snapshot: Option<RetainedForkSnapshot>,
}

/// Parameters for one clone in a single-snapshot fork operation.
pub struct ForkSpec<'a> {
    /// New machine name.
    pub clone: &'a str,
    /// Explicit inbound port mappings, or empty to remap the golden's ports.
    pub pinned_ports: &'a [(u16, u16)],
    /// Whether the clone should itself be forkable.
    pub clone_forkable: bool,
    /// Per-clone environment delivered before the workload is released.
    pub fork_env: &'a [(String, String)],
    /// Per-clone secret references resolved by later execs.
    pub fork_secrets: &'a BTreeMap<String, crate::secrets::SecretRef>,
    /// Keep the restored workload parked at its inherited forkpoint until a
    /// later assignment explicitly releases it.
    pub hold: bool,
}

/// Freeze a running, forkable `golden`, snapshot it, register `clone` in the DB
/// with copy-on-write disks, and return everything the caller needs to boot the
/// clone. Launch-agnostic: the actual boot is the caller's job (CLI via
/// `start_vm_named`, API via `AgentManager`), keyed off the returned
/// `snapshot_dir`.
///
/// On any failure after the clone record is inserted, the record and its data
/// directory are cleaned up before returning the error, so a failed fork leaves
/// no half-registered clone behind.
pub fn prepare_fork(
    db: &SmolvmDb,
    golden: &str,
    clone: &str,
    pinned_ports: &[(u16, u16)],
    clone_forkable: bool,
    fork_env: &[(String, String)],
    fork_secrets: &BTreeMap<String, crate::secrets::SecretRef>,
) -> Result<PreparedFork> {
    let mut prepared = prepare_forks(
        db,
        golden,
        &[ForkSpec {
            clone,
            pinned_ports,
            clone_forkable,
            fork_env,
            fork_secrets,
            hold: false,
        }],
    )?;
    Ok(prepared.remove(0))
}

/// Prepare one clean clone that remains parked at the inherited forkpoint.
/// Held slots are deliberately non-forkable and one-shot.
pub fn prepare_held_fork(
    db: &SmolvmDb,
    golden: &str,
    clone: &str,
    pinned_ports: &[(u16, u16)],
    fork_env: &[(String, String)],
    fork_secrets: &BTreeMap<String, crate::secrets::SecretRef>,
) -> Result<PreparedFork> {
    let mut prepared = prepare_forks(
        db,
        golden,
        &[ForkSpec {
            clone,
            pinned_ports,
            clone_forkable: false,
            fork_env,
            fork_secrets,
            hold: true,
        }],
    )?;
    Ok(prepared.remove(0))
}

/// Capture one golden generation and prepare every requested clone from it.
/// Preparation is transactional: if any clone fails, all clone records and
/// disks created by this call are removed.
///
/// Linux/x86_64 and macOS resume the source after atomically rotating its
/// writable disks; other hosts retain the source in its paused copy-on-write
/// state. A later direct fork captures current state; explicit pool
/// replenishment can reuse its retained generation.
pub fn prepare_forks(
    db: &SmolvmDb,
    golden: &str,
    specs: &[ForkSpec<'_>],
) -> Result<Vec<PreparedFork>> {
    let retained = db
        .retained_fork_snapshot(golden)
        .map_err(|error| Error::agent("read retained fork checkpoint", error.to_string()))?;
    Ok(prepare_forks_reusing(db, golden, specs, retained.as_ref(), true, false)?.forks)
}

/// Prepare a batch, optionally reusing a proven checkpoint that still belongs
/// to the exact source process. Invalid or stale hints fall back to a fresh
/// checkpoint; they can never restore state from a restarted source.
pub(crate) fn prepare_forks_reusing(
    db: &SmolvmDb,
    golden: &str,
    specs: &[ForkSpec<'_>],
    retained: Option<&RetainedForkSnapshot>,
    persist_snapshot: bool,
    reuse_live_snapshot: bool,
) -> Result<PreparedForkBatch> {
    if specs.is_empty() {
        return Err(Error::config("fork", "at least one clone is required"));
    }

    let mut names = HashSet::with_capacity(specs.len());
    let mut reserved_ports = HashSet::new();
    for spec in specs {
        validate_vm_name(spec.clone, "clone name").map_err(|e| Error::config("clone name", e))?;
        validate_fork_env(spec.fork_env)?;
        if !names.insert(spec.clone) {
            return Err(Error::config(
                "fork",
                format!("duplicate clone name '{}'", spec.clone),
            ));
        }
        if spec.hold && spec.clone_forkable {
            return Err(Error::agent(
                "fork",
                "a held pool slot cannot be forkable; release or replenish held slots instead",
            ));
        }
        if db.get_vm(spec.clone)?.is_some() {
            return Err(Error::agent(
                "fork",
                format!("machine '{}' already exists", spec.clone),
            ));
        }
        for (host, _) in spec.pinned_ports {
            if !reserved_ports.insert(*host) {
                return Err(Error::config(
                    "fork",
                    format!("host port {host} is assigned to more than one clone"),
                ));
            }
        }
    }

    let golden_rec = db
        .get_vm(golden)?
        .ok_or_else(|| Error::vm_not_found(golden))?;
    #[cfg(target_os = "linux")]
    let mut golden_rec = golden_rec;
    if !golden_rec.staged_mounts.is_empty() {
        return Err(Error::config(
            "fork",
            "staged mounts cannot be branched yet because multiple descendants would synchronize into the same host directory; use a live rw mount or remove the staged mount first",
        ));
    }
    let child_depth = db
        .fork_lineage_depth(golden)?
        .checked_add(1)
        .ok_or_else(|| Error::agent("fork", "fork lineage depth overflow"))?;
    if child_depth > MAX_FORK_LINEAGE_DEPTH {
        return Err(Error::agent(
            "fork",
            format!(
                "fork lineage would exceed {MAX_FORK_LINEAGE_DEPTH} generations; compact this state into a new root first"
            ),
        ));
    }
    if golden_rec.cuda && specs.iter().any(|spec| spec.clone_forkable) {
        return Err(Error::agent(
            "fork",
            "CUDA fork descendants are not supported yet; create a leaf clone without `forkable`",
        ));
    }
    let ctl = control_socket_path(golden);
    if !ctl.exists() {
        return Err(Error::agent(
            "fork",
            format!("golden '{golden}' is not running forkable; start it with `machine start --forkable --name {golden}`"),
        ));
    }
    let status = control_socket_cmd(&ctl, "STATUS").map_err(|e| {
        Error::agent(
            "fork",
            format!("golden '{golden}' control socket not responding ({e}); start it with `machine start --forkable --name {golden}`"),
        )
    })?;
    if !status.starts_with("OK") {
        return Err(Error::agent(
            "fork",
            format!("golden '{golden}' is not ready to fork: {status}"),
        ));
    }
    let golden_was_paused = fork_base_already_paused(&status);
    let fork_continue = fork_continue_enabled();
    let userfaultfd_available = kernel_fault_userfaultfd_available();
    let requested_ram_mode = std::env::var("SMOLVM_BRANCH_RAM_MODE").ok();
    let live_ram_mode = fork_continue
        .then(|| select_live_branch_ram_mode(userfaultfd_available, requested_ram_mode.as_deref()))
        .transpose()?;

    let gdir = vm_data_dir(golden);
    // Keep this path short and independent of clone names. libkrun and its
    // control transport encounter platform path ceilings well below PATH_MAX;
    // a long XDG_CACHE_HOME plus `fork-snapshots/<clone>` otherwise makes a
    // valid golden fail restore with EINVAL. The 8-hex component keeps the
    // snapshot path no longer than the already-required `agent.sock` path.
    // Never remove a colliding random directory because a live clone may still
    // be using an older snapshot.
    let snapshot_root = gdir.join("s");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if fork_continue && !golden_was_paused {
        recover_uncommitted_generations(db, golden, &gdir, &snapshot_root)?;
    }
    let reusable = retained.filter(|snapshot| {
        (golden_was_paused || reuse_live_snapshot)
            && retained_snapshot_is_reusable(
                &golden_rec,
                golden_was_paused,
                &snapshot_root,
                snapshot,
            )
    });
    #[cfg(target_os = "linux")]
    let reusable = match (reusable, live_ram_mode) {
        (Some(snapshot), Some(wanted)) if !golden_was_paused => {
            let retained_mode = if snapshot_guardian_identity(&snapshot.path)?.is_some() {
                LiveBranchRamMode::Paged
            } else {
                LiveBranchRamMode::Shared
            };
            if retained_mode == wanted {
                Some(snapshot)
            } else {
                tracing::debug!(
                    ?wanted,
                    ?retained_mode,
                    "fork: refreshing retained RAM generation for requested sharing policy"
                );
                None
            }
        }
        (snapshot, _) => snapshot,
    };
    if golden_was_paused && reusable.is_none() {
        return Err(Error::agent(
            "fork",
            format!("golden '{golden}' is already paused; a valid retained checkpoint is required"),
        ));
    }
    admit_branch_memory(
        &golden_rec,
        specs.len(),
        reusable.is_none() && live_ram_mode == Some(LiveBranchRamMode::Shared),
    )?;
    let (snapshot_dir, snapshot_reused) = if let Some(snapshot) = reusable {
        tracing::info!(
            golden,
            path = %snapshot.path.display(),
            clones = specs.len(),
            "fork: reusing retained golden RAM checkpoint"
        );
        (snapshot.path.clone(), true)
    } else {
        std::fs::create_dir_all(&snapshot_root)
            .map_err(|e| Error::agent("create snapshot root", e.to_string()))?;
        let snapshot_dir = (0..128)
            .find_map(|_| {
                let suffix = match host_random_hex(8) {
                    Ok(suffix) => suffix,
                    Err(error) => return Some(Err(std::io::Error::other(error.to_string()))),
                };
                let candidate = snapshot_root.join(suffix);
                match std::fs::create_dir(&candidate) {
                    Ok(()) => Some(Ok(candidate)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .transpose()
            .map_err(|e| Error::agent("create snapshot dir", e.to_string()))?
            .ok_or_else(|| Error::agent("create snapshot dir", "could not allocate a unique id"))?;
        let uid_owner = golden_rec
            .fork_overlay_owner
            .as_deref()
            .or(golden_rec.golden.as_deref())
            .unwrap_or(golden);
        let uid_owner_dir = vm_data_dir(uid_owner);
        let vm_ids = crate::process::vm_drop_ids(
            &crate::agent::vm_uid_registry_dir(),
            &gdir,
            None,
            Some(&uid_owner_dir),
        )
        .transpose()
        .map_err(|e| Error::agent("fork: resolve golden uid", e.to_string()))?;
        if let Some((uid, gid)) = vm_ids {
            crate::process::chown_tree(&snapshot_dir, uid, gid)
                .map_err(|e| Error::agent("fork: chown snapshot dir", e.to_string()))?;
        }

        if let Err(error) = sync_fork_source(golden) {
            let _ = std::fs::remove_dir_all(&snapshot_dir);
            return Err(error);
        }

        let forkpoint_armed = match arm_forkpoint_for_capture(golden) {
            Ok(armed) => armed,
            Err(error) => {
                // An acknowledgement timeout may still have left the helper in
                // its capture loop. Best-effort parking keeps a failed capture
                // from turning into a permanent host-CPU leak.
                let _ = park_forkpoint_after_capture(golden);
                let _ = std::fs::remove_dir_all(&snapshot_dir);
                return Err(error);
            }
        };

        if fork_continue {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Err(error) = prepare_running_disk_generation(&gdir, &snapshot_dir, vm_ids) {
                if forkpoint_armed {
                    let _ = park_forkpoint_after_capture(golden);
                }
                let _ = std::fs::remove_dir_all(&snapshot_dir);
                return Err(error);
            }
        }

        #[cfg(target_os = "linux")]
        let mut lineage_memory_reservation = if fork_continue {
            let reservation =
                gc_unreferenced_fork_generations(db, golden, &snapshot_root, retained)
                    .and_then(|()| {
                        referenced_fork_generation_count(db, golden, &snapshot_root, retained)
                    })
                    .and_then(|generations| {
                        ForkLineageMemoryReservation::reserve(
                            golden,
                            &golden_rec,
                            &snapshot_dir,
                            generations,
                        )
                    });
            match reservation {
                Ok(reservation) => Some(reservation),
                Err(error) => {
                    if forkpoint_armed {
                        let _ = park_forkpoint_after_capture(golden);
                    }
                    let _ = std::fs::remove_dir_all(&snapshot_dir);
                    return Err(error);
                }
            }
        } else {
            None
        };

        let t_snap = std::time::Instant::now();
        // Active children map one sparse materialized memfd generation so CPU-
        // and I/O-heavy work never serializes behind page-by-page delivery.
        // Held pool slots use the same shared generation because they may run a
        // dense workload as soon as they are leased. The environment override
        // remains an operator and debugging escape hatch.
        let fork_verb = if fork_continue {
            match live_ram_mode.expect("fork-continue mode selected before capture") {
                LiveBranchRamMode::Shared => "FORK_CONTINUE",
                LiveBranchRamMode::Paged => "FORK_CONTINUE_PAGED",
            }
        } else {
            "FORK"
        };
        let reply = control_socket_cmd(&ctl, &format!("{fork_verb} {}", snapshot_dir.display()));
        if fork_continue && forkpoint_armed {
            if let Err(error) = park_forkpoint_after_capture(golden) {
                tracing::warn!(%golden, %error, "continued source did not park after capture");
            }
        }
        #[cfg(target_os = "linux")]
        if fork_continue && fork_continue_snapshot(&snapshot_dir) {
            if let Some(reservation) = lineage_memory_reservation.as_mut() {
                reservation.mark_source_rebased();
            }
            let pid_start_time = golden_rec.pid_start_time;
            let persisted = db
                .update_vm(golden, |record| {
                    record.fork_lineage_pid_start_time = pid_start_time;
                })
                .map_err(|error| Error::agent("persist fork RAM lineage", error.to_string()))
                .and_then(|record| record.ok_or_else(|| Error::vm_not_found(golden)));
            if let Err(error) = persisted {
                return Err(rollback_new_snapshot(
                    db,
                    golden,
                    &snapshot_dir,
                    false,
                    error,
                ));
            }
            golden_rec.fork_lineage_pid_start_time = pid_start_time;
        }
        let reply = match reply {
            Ok(reply) if reply.starts_with("OK") => reply,
            Ok(reply) => {
                return Err(rollback_new_snapshot(
                    db,
                    golden,
                    &snapshot_dir,
                    false,
                    Error::agent("fork", explain_fork_reply(golden, &reply)),
                ));
            }
            Err(error) => {
                return Err(rollback_new_snapshot(
                    db,
                    golden,
                    &snapshot_dir,
                    false,
                    error,
                ));
            }
        };
        tracing::info!(
            elapsed_ms = t_snap.elapsed().as_millis() as u64,
            clones = specs.len(),
            response = %reply,
            "fork: golden RAM checkpoint written"
        );
        (snapshot_dir, false)
    };

    let retained_snapshot =
        golden_rec
            .pid
            .zip(golden_rec.pid_start_time)
            .map(|(golden_pid, golden_pid_start_time)| RetainedForkSnapshot {
                path: snapshot_dir.clone(),
                golden_pid,
                golden_pid_start_time,
            });
    if persist_snapshot && !snapshot_reused {
        let persisted = retained_snapshot
            .as_ref()
            .ok_or_else(|| {
                Error::agent(
                    "fork",
                    format!("golden '{golden}' process identity is unavailable"),
                )
            })
            .and_then(|snapshot| {
                db.set_retained_fork_snapshot(golden, snapshot)
                    .map_err(|error| {
                        Error::agent("persist retained fork checkpoint", error.to_string())
                    })
            });
        if let Err(error) = persisted {
            return Err(rollback_new_snapshot(
                db,
                golden,
                &snapshot_dir,
                false,
                error,
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        gc_unreferenced_fork_generations(db, golden, &snapshot_root, retained_snapshot.as_ref())?;
        #[cfg(target_os = "linux")]
        if let Err(error) = reconcile_fork_lineage_memory_limit(
            db,
            golden,
            &golden_rec,
            &snapshot_root,
            retained_snapshot.as_ref(),
        ) {
            // The reservation already raised the cap before capture. Failing to
            // shrink a stale allowance must not roll back a valid live branch.
            tracing::warn!(%golden, %error, "could not shrink live-branch lineage cgroup after GC");
        }
    }

    let mut prepared = Vec::with_capacity(specs.len());
    for spec in specs {
        match prepare_clone_from_snapshot(
            db,
            golden,
            &golden_rec,
            &gdir,
            &snapshot_dir,
            spec,
            &mut reserved_ports,
        ) {
            Ok(clone) => prepared.push(clone),
            Err(error) => {
                for clone in &prepared {
                    let _ = db.remove_vm(&clone.clone_record.name);
                    let _ = std::fs::remove_dir_all(vm_data_dir(&clone.clone_record.name));
                }
                return Err(if snapshot_reused || golden_was_paused {
                    error
                } else if fork_continue_snapshot(&snapshot_dir) {
                    Error::agent(
                        "fork",
                        format!(
                            "{error}; source '{golden}' continues running with its retained checkpoint so the fork can be retried safely"
                        ),
                    )
                } else {
                    Error::agent(
                        "fork",
                        format!(
                            "{error}; source '{golden}' remains frozen at its retained checkpoint so the fork can be retried safely"
                        ),
                    )
                });
            }
        }
    }
    Ok(PreparedForkBatch {
        forks: prepared,
        retained_snapshot,
    })
}

/// Restore an initially-running golden after a failed clone finalization and
/// discard the checkpoint that produced that clone. Callers must ensure no
/// successfully booted clone depends on `snapshot_dir` before invoking this.
pub(crate) fn rollback_retained_fork_snapshot(
    db: &SmolvmDb,
    golden: &str,
    snapshot_dir: &Path,
    persisted: bool,
) -> Result<()> {
    let dependent_clones = db.dependent_clones(golden)?;
    if !dependent_clones.is_empty() {
        return Err(Error::agent(
            "fork rollback",
            format!(
                "refusing to resume golden '{golden}': {} live clone(s) still depend on its checkpoint ({})",
                dependent_clones.len(),
                dependent_clones.join(", ")
            ),
        ));
    }

    let mut rollback_errors = Vec::new();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let source_continues = fork_continue_snapshot(snapshot_dir);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let source_continues = false;
    if source_continues {
        let status = control_socket_cmd(&control_socket_path(golden), "STATUS").map_err(|error| {
            Error::agent(
                "fork rollback",
                format!(
                    "could not prove continuing source state ({error}); preserved checkpoint {} for recovery",
                    snapshot_dir.display()
                ),
            )
        })?;
        if status.trim() != "OK running" {
            return Err(Error::agent(
                "fork rollback",
                format!(
                    "source '{golden}' is not proven running ({status}); preserved checkpoint {} for recovery",
                    snapshot_dir.display()
                ),
            ));
        }
        if !snapshot_dir.join("source-continues-v1").is_file() {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            rollback_uncommitted_disk_generation(&vm_data_dir(golden), snapshot_dir)?;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            unreachable!("this platform cannot carry fork-continue disk metadata");
        }
    } else if let Err(resume_error) = resume_golden(golden, snapshot_dir) {
        return Err(Error::agent(
            "fork rollback",
            format!(
                "golden rollback failed: {resume_error}; preserved checkpoint {} for recovery",
                snapshot_dir.display()
            ),
        ));
    }
    if persisted {
        if let Err(remove_error) = db.remove_retained_fork_snapshot(golden) {
            tracing::warn!(%golden, %remove_error, "failed to remove rolled-back retained fork checkpoint");
            rollback_errors.push(format!(
                "retained-checkpoint cleanup failed: {remove_error}"
            ));
        }
    }
    if let Err(stop_error) = stop_snapshot_guardian(snapshot_dir) {
        tracing::warn!(path = %snapshot_dir.display(), %stop_error, "failed to stop rolled-back RAM guardian");
        rollback_errors.push(format!("RAM guardian cleanup failed: {stop_error}"));
    } else if let Err(remove_error) = std::fs::remove_dir_all(snapshot_dir) {
        tracing::warn!(path = %snapshot_dir.display(), %remove_error, "failed to remove rolled-back fork snapshot");
        if remove_error.kind() != std::io::ErrorKind::NotFound {
            rollback_errors.push(format!("snapshot cleanup failed: {remove_error}"));
        }
    }
    if rollback_errors.is_empty() {
        Ok(())
    } else {
        Err(Error::agent("fork rollback", rollback_errors.join("; ")))
    }
}

fn rollback_new_snapshot(
    db: &SmolvmDb,
    golden: &str,
    snapshot_dir: &Path,
    persisted: bool,
    error: Error,
) -> Error {
    match rollback_retained_fork_snapshot(db, golden, snapshot_dir, persisted) {
        Ok(()) => error,
        Err(rollback_error) => Error::agent("fork", format!("{error}; {rollback_error}")),
    }
}

fn reusable_snapshot_path(snapshot_root: &Path, snapshot: &Path) -> bool {
    snapshot.parent() == Some(snapshot_root)
        && snapshot
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.len() == 8 && name.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or(false)
        && snapshot
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_dir())
            .unwrap_or(false)
}

fn retained_snapshot_is_reusable(
    golden: &VmRecord,
    golden_was_paused: bool,
    snapshot_root: &Path,
    snapshot: &RetainedForkSnapshot,
) -> bool {
    (golden_was_paused || retained_snapshot_source_continues(snapshot))
        && retained_snapshot_matches_golden(golden, snapshot_root, snapshot)
}

/// Return whether a retained checkpoint belongs to the exact live golden
/// process recorded in the registry and still occupies an owned snapshot path.
/// State probing uses this to recognize a deliberately paused fork base even
/// between pool fills, when it temporarily has no dependent clone rows.
pub(crate) fn retained_snapshot_matches_golden(
    golden: &VmRecord,
    snapshot_root: &Path,
    snapshot: &RetainedForkSnapshot,
) -> bool {
    golden.pid == Some(snapshot.golden_pid)
        && golden.pid_start_time == Some(snapshot.golden_pid_start_time)
        && reusable_snapshot_path(snapshot_root, &snapshot.path)
}

fn prepare_clone_from_snapshot(
    db: &SmolvmDb,
    golden: &str,
    golden_rec: &VmRecord,
    golden_dir: &Path,
    snapshot_dir: &Path,
    spec: &ForkSpec<'_>,
    reserved_ports: &mut HashSet<u16>,
) -> Result<PreparedFork> {
    let clone = spec.clone;
    let clone_dir = vm_data_dir(clone);
    let result = (|| {
        if clone_dir.exists() {
            std::fs::remove_dir_all(&clone_dir)
                .map_err(|e| Error::agent("clear orphan clone dir", e.to_string()))?;
        }
        std::fs::create_dir_all(&clone_dir)
            .map_err(|e| Error::agent("create clone dir", e.to_string()))?;

        let golden_layers = crate::agent::machine_layers_cache_dir(golden);
        #[cfg(target_os = "linux")]
        {
            let clone_layers = crate::agent::machine_layers_cache_dir(clone);
            let copied_shared_lease =
                crate::artifact_cache::copy_shared_pack_lease(&golden_layers, &clone_layers)
                    .map_err(|e| Error::agent("copy shared pack lease", e.to_string()))?;
            if copied_shared_lease.is_none() && smolvm_pack::extract::is_extracted(&golden_layers) {
                std::os::unix::fs::symlink(&golden_layers, &clone_layers)
                    .map_err(|e| Error::agent("link clone pack dir", e.to_string()))?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        if smolvm_pack::extract::is_extracted(&golden_layers) {
            #[cfg(unix)]
            {
                let clone_layers = crate::agent::machine_layers_cache_dir(clone);
                std::os::unix::fs::symlink(&golden_layers, &clone_layers)
                    .map_err(|e| Error::agent("link clone pack dir", e.to_string()))?;
            }
        }

        let mut clone_rec = golden_rec.clone();
        clone_rec.name = clone.to_string();
        // The record exists before its restored VMM does. Never inherit the
        // source's Running/Unreachable state: start must treat this as a clean
        // launch, and only persist Running after the clone answers its agent
        // readiness probe.
        clone_rec.state = crate::config::RecordState::Created;
        clone_rec.pid = None;
        clone_rec.pid_start_time = None;
        if !spec.fork_env.is_empty() {
            clone_rec
                .env
                .retain(|(k, _)| !spec.fork_env.iter().any(|(fk, _)| fk == k));
            clone_rec.env.extend(spec.fork_env.iter().cloned());
        }
        for (key, secret) in spec.fork_secrets {
            clone_rec.secret_refs.insert(key.clone(), secret.clone());
        }

        let mut port_remaps = Vec::new();
        if !spec.pinned_ports.is_empty() {
            clone_rec.ports = spec.pinned_ports.to_vec();
            for (host, guest) in &clone_rec.ports {
                port_remaps.push((*host, *guest, *host));
            }
        } else if !clone_rec.ports.is_empty() {
            let mut remapped = Vec::with_capacity(clone_rec.ports.len());
            for (golden_host, guest) in &clone_rec.ports {
                match alloc_free_host_port_excluding(reserved_ports) {
                    Some(host) => {
                        port_remaps.push((*golden_host, *guest, host));
                        remapped.push((host, *guest));
                    }
                    None => tracing::warn!(
                        guest,
                        "could not allocate a host port for fork clone; dropping forward"
                    ),
                }
            }
            clone_rec.ports = remapped;
        }
        clone_rec.fork_overlay_owner = Some(
            golden_rec
                .fork_overlay_owner
                .as_deref()
                .or(golden_rec.golden.as_deref())
                .unwrap_or(golden)
                .to_string(),
        );
        clone_rec.golden = Some(golden.to_string());
        clone_rec.fork_generation = snapshot_generation_id(snapshot_dir).map(str::to_string);
        clone_rec.fork_lineage_pid_start_time = None;
        // Forkability is explicit per clone. A normal clone remains a cheap
        // leaf; a forkable clone materializes its restored RAM into fresh
        // backing files at boot so it can later checkpoint its own state.
        clone_rec.forkable = spec.clone_forkable;
        clone_rec.forkpoint_held = spec.hold;
        clone_rec.fork_env = spec.fork_env.to_vec();
        db.insert_vm(clone, &clone_rec)?;

        let t_disk = std::time::Instant::now();
        clone_fork_disks(golden_dir, snapshot_dir, &clone_dir)?;
        tracing::info!(
            clone,
            elapsed_ms = t_disk.elapsed().as_millis() as u64,
            "fork: clone disk overlays created"
        );
        Ok(PreparedFork {
            snapshot_dir: snapshot_dir.to_path_buf(),
            clone_record: clone_rec,
            port_remaps,
        })
    })();

    if result.is_err() {
        let _ = db.remove_vm(clone);
        let _ = std::fs::remove_dir_all(&clone_dir);
    }
    result
}

/// Give the clone its own disks. The source's block workers were quiesced and
/// flushed at the checkpoint boundary, so the generation is a consistent
/// backing even when the source has resumed. On Linux each
/// disk is a qcow2 copy-on-write overlay over the golden's — filesystem
/// independent, so the overlay starts near-empty and the fork is O(metadata)
/// regardless of how much data the golden holds. macOS clonefiles the disks
/// (APFS CoW). Either way the `.formatted` marker is copied so the clone never
/// reformats and wipes the inherited filesystem.
fn clone_fork_disks(gdir: &Path, snapshot_dir: &Path, clone_dir: &Path) -> Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = snapshot_dir;
    // The golden's actual disks that exist, resolved by file presence (`.qcow2`
    // if the golden is itself a clone, else `.raw`) — the same single source of
    // truth the agent manager uses. Each entry pairs the canonical `.raw`
    // filename (for naming the clone's disk) with the golden's real backing file
    // and its format.
    let fallback_disks = || -> Vec<ForkDisk> {
        [
            crate::data::storage::STORAGE_DISK_FILENAME,
            crate::data::storage::OVERLAY_DISK_FILENAME,
        ]
        .into_iter()
        .map(|raw| {
            let (src, fmt) = resolve_disk_image(gdir, raw);
            (raw, src, fmt)
        })
        .filter(|(_, src, _)| src.exists())
        .collect()
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let disks = read_generation_fork_disks(snapshot_dir)?.unwrap_or_else(fallback_disks);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let disks = fallback_disks();

    #[cfg(target_os = "linux")]
    {
        // Each clone disk is a qcow2 CoW overlay over the golden's disk. Build
        // all overlay specs first so libkrun is loaded once for the batch
        // (absolute backing path: it's written verbatim into the overlay
        // header), then copy the `.formatted` markers so the clone never
        // reformats and wipes the inherited filesystem.
        let mut specs = Vec::with_capacity(disks.len());
        for (raw, src, fmt) in &disks {
            let base = src
                .canonicalize()
                .map_err(|e| Error::agent("clone disk", format!("{}: {e}", src.display())))?;
            let overlay = clone_dir.join(Path::new(raw).with_extension("qcow2"));
            specs.push((overlay, base, *fmt));
        }
        crate::agent::create_disk_overlays(&specs)?;
        for (raw, _, _) in &disks {
            // Marker basename is the disk stem + ".formatted" (same for the
            // golden's `.raw`/`.qcow2` and the clone's `.qcow2`).
            let marker = Path::new(raw).with_extension("formatted");
            let src_marker = gdir.join(&marker);
            if src_marker.exists() {
                let _ = std::fs::copy(&src_marker, clone_dir.join(&marker));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS uses clonefile (APFS CoW) over the immutable generation disk,
        // keeping its source format while the running VM writes a new overlay.
        for (raw, src, format) in &disks {
            let dst = match format {
                crate::data::disk::DiskFormat::Raw => clone_dir.join(raw),
                crate::data::disk::DiskFormat::Qcow2 => {
                    clone_dir.join(Path::new(raw).with_extension("qcow2"))
                }
            };
            crate::disk_utils::clone_or_copy_file(src, &dst)
                .map_err(|e| Error::agent("clone disk", format!("{}: {e}", src.display())))?;
            let marker = Path::new(raw).with_extension("formatted");
            let src_marker = gdir.join(&marker);
            if src_marker.exists() {
                let _ = std::fs::copy(&src_marker, clone_dir.join(&marker));
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fork-clone disk overlays rely on libkrun's qcow2 overlay (Linux) or
        // APFS clonefile (macOS); neither is wired up on Windows.
        let _ = (&disks, clone_dir);
        return Err(Error::agent(
            "clone disk",
            "live fork is not supported on this platform",
        ));
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Number of times we try to confirm a clone's identity rejuvenation before
/// giving up and failing the fork. `connect_with_retry` already rides out the
/// agent's boot; these extra attempts cover a momentarily-busy agent whose
/// `vm_exec` errors or exits non-zero transiently.
const REJUVENATE_ATTEMPTS: usize = 3;

/// Build the shell script that re-mints a clone's on-disk identity. Kept as a
/// pure function of `(clone, seed, host_epoch)` so the security-critical
/// contents (fresh machine-id, regenerated SSH host keys, wall-clock re-stamp)
/// are unit-tested without a live VM.
///
/// `clone` is a validated machine name (alphanumeric + dashes) and `seed` is
/// hex, so single-quoting both is injection-safe.
///
/// NOTE: this deliberately does NOT touch `/storage/overlays`. The clone's
/// inherited exec overlay stays under the GOLDEN's id and the restored guest
/// may still hold it mounted (or have a restored workload container running
/// from it) — renaming it on disk poisons that live overlayfs mount (ESTALE
/// in every subsequent container exec). Hosts alias the overlay lookup
/// instead (`crate::workload::persistent_overlay_owner`).
///
/// The script is fail-hard on the *unambiguously per-machine* identity material
/// (`set -e`): if a clone cannot get its own machine-id or SSH host keys, the
/// fork must fail rather than vend a clone that impersonates the golden. Steps
/// that are legitimately absent on minimal/library images (no sshd, no dbus,
/// no cloud-init) are guarded so they no-op instead of failing.
///
/// The wall-clock re-stamp is the one deliberate fail-*soft* step: a skewed
/// clock breaks apt/TLS validity but is recoverable and is not an isolation
/// breach, so it must not tear the clone down, it only leaves a `clock-failed`
/// stage marker.
fn build_rejuvenation_script(
    clone: &str,
    seed: &str,
    host_epoch: u64,
    record: &VmRecord,
) -> String {
    // An image machine's identity files live in the workload container's
    // rootfs, NOT the VM rootfs the agent execs in — writing them unprefixed
    // strands them where no workload will ever read them, leaving the clone on
    // the golden's SSH host keys. Reach the container through its overlayfs
    // `merged` mount, exactly as [`write_fork_env`] does and for the same
    // reason: a container exec would recycle the workload the fork just
    // restored. A bare VM (no image) keeps the plain VM-rootfs paths.
    let (root, require_root, runtime_hostname, restored_container) = match record.image {
        Some(_) => {
            let owner = crate::workload::persistent_overlay_owner_with_lineage(
                clone,
                record.golden.as_deref(),
                record.fork_overlay_owner.as_deref(),
            );
            let merged = format!("/storage/overlays/persistent-{owner}/merged");
            let container_id = format!("/storage/overlays/persistent-{owner}/main_container_id");
            let require = format!(
                "if [ ! -d {merged} ]; then echo \"missing {merged}; overlays:\" >&2; \
                 ls /storage/overlays >&2; exit 41; fi; "
            );
            // A restored keep-alive container has its own UTS namespace. The
            // plain `hostname` call below updates the VM/agent namespace, but
            // not that inherited namespace, so `hostname(2)` inside the clone
            // otherwise keeps reporting the golden's name. Enter only the
            // live container's UTS namespace and update it in place: no process
            // restart, heap loss, or overlay remount. A missing/stale crun state
            // is harmless because the next exec will rebuild the container; its
            // OCI spec reads the rejuvenated VM hostname (see `container_hostname`).
            let runtime_hostname = format!(
                "if [ -s '{container_id}' ]; then \
                     CID=$(cat '{container_id}'); \
                     PID=$(/usr/bin/crun --root /storage/containers/crun \
                         --cgroup-manager disabled state \"$CID\" 2>/dev/null \
                         | /usr/bin/jq -r '.pid // empty' 2>/dev/null || true); \
                     case \"$PID\" in \
                       ''|*[!0-9]*) ;; \
                       *) if [ -e \"/proc/$PID/ns/uts\" ]; then \
                            /usr/bin/nsenter --uts=\"/proc/$PID/ns/uts\" \
                                /bin/hostname '{clone}'; \
                          fi ;; \
                     esac; \
                 fi; "
            );
            let restored_container = format!(
                "mkdir -p '{state_dir}'; \
                 if [ -s '{container_id}' ]; then \
                     cat '{container_id}' > '{restored_container_path}'; \
                 else \
                     rm -f '{restored_container_path}'; \
                 fi; ",
                restored_container_path = smolvm_protocol::forkpoint::RESTORED_CONTAINER_PATH,
                state_dir = smolvm_protocol::forkpoint::STATE_DIR,
            );
            (merged, require, runtime_hostname, restored_container)
        }
        None => (String::new(), String::new(), String::new(), String::new()),
    };
    // `ssh-keygen -A` writes to a hardcoded /etc/ssh, so regenerating the
    // container's keys means running the container's own binary under chroot.
    // Both tools are probed by absolute path: the agent's exec PATH does not
    // necessarily carry /usr/sbin, and a bare `command -v chroot` that misses
    // aborts the script under `set -e` — after the old keys are already gone.
    //
    // The chroot also needs device nodes: the workload's /dev is a tmpfs mounted
    // inside the container's mount namespace, so from the agent's namespace the
    // merged rootfs has an empty /dev and `ssh-keygen` finds no entropy source.
    // Nodes this creates are removed again; the container's own /dev tmpfs hides
    // them from the workload either way.
    //
    // Availability is checked BEFORE anything is deleted so that an
    // unsatisfiable clone fails the same way on every retry. Otherwise attempt
    // one removes the keys, fails, and attempt two finds no keys to rotate and
    // reports success — laundering the failure the retry loop exists to catch.
    let ssh_block = if root.is_empty() {
        "if ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
             KG=''; for k in /usr/bin/ssh-keygen /bin/ssh-keygen /usr/local/bin/ssh-keygen; do \
                 if [ -x \"$k\" ]; then KG=\"$k\"; break; fi; \
             done; \
             if [ -z \"$KG\" ]; then echo 'no ssh-keygen to rotate the host keys' >&2; exit 42; fi; \
             rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub; \
             \"$KG\" -A >/dev/null 2>&1 || true; \
             if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
                 echo 'host key rotation produced no keys' >&2; exit 42; \
             fi; \
         fi"
            .to_string()
    } else {
        format!(
            "if ls {root}/etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
                 CH=''; for c in /usr/sbin/chroot /sbin/chroot /usr/bin/chroot; do \
                     if [ -x \"$c\" ]; then CH=\"$c\"; break; fi; \
                 done; \
                 KG=''; for k in /usr/bin/ssh-keygen /bin/ssh-keygen /usr/local/bin/ssh-keygen; do \
                     if [ -x {root}\"$k\" ]; then KG=\"$k\"; break; fi; \
                 done; \
                 if [ -z \"$CH\" ] || [ -z \"$KG\" ]; then \
                     echo 'no chroot/ssh-keygen to rotate the workload host keys' >&2; exit 42; \
                 fi; \
                 rm -f {root}/etc/ssh/ssh_host_*_key {root}/etc/ssh/ssh_host_*_key.pub; \
                 MADE=''; mkdir -p {root}/dev; \
                 for d in 'urandom c 1 9' 'random c 1 8' 'null c 1 3'; do \
                     set -- $d; \
                     if [ ! -e {root}/dev/$1 ] && mknod -m 666 {root}/dev/$1 $2 $3 $4 2>/dev/null; then \
                         MADE=\"$MADE {root}/dev/$1\"; \
                     fi; \
                 done; \
                 \"$CH\" {root} \"$KG\" -A >/dev/null 2>&1 || true; \
                 if [ -n \"$MADE\" ]; then rm -f $MADE; fi; \
                 if ! ls {root}/etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
                     echo 'host key rotation produced no keys' >&2; exit 42; \
                 fi; \
             fi"
        )
    };
    // Re-stamp the wall clock to the host's time at fork. A CoW fork restores
    // the golden's guest RAM, which carries the golden's CLOCK_REALTIME frozen
    // at forkpoint-bake time; on Linux/KVM nothing re-seeds it (the boot-time
    // seeder ran only in the golden's now-past `main()`, and libkrun pushes no
    // timesync on KVM), so the clone reads `forkpoint_bake + clone_uptime` and
    // stays that far behind real time forever — breaking apt's `Release`
    // "not valid yet" check and TLS `notBefore` inside the clone. kvmclock keeps
    // the *rate* correct, so a one-shot offset fix is sufficient (no continuous
    // pusher needed). `date` here is the VM-rootfs busybox, which accepts
    // `-s @<epoch>`; the set targets the (non-namespaced) kernel CLOCK_REALTIME,
    // so the workload container sees it too.
    //
    // FAIL-SOFT (unlike the identity scrub above): it must not abort `set -e`
    // and tear the clone down over a `date` hiccup, but it stays observable via
    // the `clock-failed` marker rather than a silent `|| true`, so a failure is
    // diagnosable instead of reproducing the very silent-skew bug this fixes.
    let clock_block = if host_epoch > 0 {
        format!(
            "date -u -s @{host_epoch} >/dev/null 2>&1 || echo 'rejuvenate-stage=clock-failed' >&2"
        )
    } else {
        "echo 'rejuvenate-stage=clock-skipped' >&2".to_string()
    };
    format!(
        "set -e; \
         echo 'rejuvenate-stage=overlay' >&2; \
         {require_root}\
         echo 'rejuvenate-stage=clock' >&2; \
         {clock_block}; \
         echo 'rejuvenate-stage=hostname' >&2; \
         hostname '{c}' 2>/dev/null || true; \
         {runtime_hostname}\
         {restored_container}\
         echo 'rejuvenate-stage=identity' >&2; \
         printf '%s' '{s}' > /dev/urandom 2>/dev/null || true; \
         MID=$(printf '%.32s' '{s}'); \
         printf '%s\\n' '{c}' > {root}/etc/hostname; \
         printf '%s\\n' \"$MID\" > {root}/etc/machine-id; \
         if [ -f {root}/var/lib/dbus/machine-id ] && [ ! -L {root}/var/lib/dbus/machine-id ]; then \
             printf '%s\\n' \"$MID\" > {root}/var/lib/dbus/machine-id; \
         fi; \
         {ssh_block}; \
         rm -rf {root}/var/lib/cloud/instance {root}/var/lib/cloud/instances/* {root}/var/lib/cloud/data/instance-id 2>/dev/null || true; \
         umask 077; \
         mkdir -p '{state_dir}'; \
         printf '%s\n' smolvm-forkpoint-restored-v1 > '{restored}'; \
         true",
        c = clone,
        s = seed,
        clock_block = clock_block,
        runtime_hostname = runtime_hostname,
        restored_container = restored_container,
        state_dir = smolvm_protocol::forkpoint::STATE_DIR,
        restored = smolvm_protocol::forkpoint::RESTORED_PATH,
    )
}

fn rejuvenation_host_epoch() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

fn clock_reset_failed(stderr: &[u8]) -> bool {
    stderr
        .split(|byte| *byte == b'\n')
        .any(|line| line == b"rejuvenate-stage=clock-failed")
}

/// Per-clone identity rejuvenation after a fork. A fork CoW-clones the golden's
/// disks wholesale, so every per-machine on-disk secret (machine-id, SSH host
/// keys, dbus id, cloud-init instance state) is byte-identical in the clone —
/// and clones can belong to *different tenants*. Left unchanged, that is a
/// cross-tenant impersonation / MITM hole (identical SSH host keys) and a
/// duplicate-identity bug. This runs over the freshly-booted clone's agent to
/// give it a fresh hostname, machine-id, SSH host keys, to re-stamp its wall
/// clock to the host's time on Linux/KVM (a fork inherits the golden's frozen
/// CLOCK_REALTIME there), and to stir the kernel RNG with fresh host entropy so
/// the random streams diverge. HVF/WHP use libkrun's host time-sync pusher
/// instead and must not be stepped backward by a second clock source here.
///
/// FAIL-CLOSED: this returns `Err` if the reset could not be *confirmed* (agent
/// unreachable, or the re-mint script exited non-zero) after
/// [`REJUVENATE_ATTEMPTS`] tries. Callers MUST treat that as a fork failure and
/// tear the clone down — a clone that still carries the golden's identity must
/// never be vended (see [`fail_closed_on_rejuvenation`]).
///
/// The lone exception is the wall-clock re-stamp, which is fail-*soft* (a skewed
/// clock is recoverable and not an impersonation vector): it cannot fail the
/// rejuvenation, only emit a `clock-failed` stage marker.
///
/// RESIDUAL LIMITATION (out of scope, intentional): this rejuvenates only
/// *on-disk* identity. It cannot scrub the golden's *in-RAM* secrets — a
/// session token, JWT, or TLS private key held in a golden-resident process's
/// memory is CoW-inherited identically by every clone. That is intrinsic to
/// fork-from-warm and is not fixable here; the mitigation is a product
/// constraint (goldens must be prepacked library base images that mint no
/// per-instance boot secrets in RAM, and/or restart key daemons post-fork), not
/// disk rejuvenation. Likewise this stirs but does not *credit* entropy
/// (no `RNDADDENTROPY`/VMGENID yet) and does not re-address the network
/// (MAC/IP; safe under the default TSI backend) — both are follow-ups.
pub fn rejuvenate_clone(clone: &str, record: &VmRecord) -> Result<()> {
    let sock = vm_data_dir(clone).join("agent.sock");
    let seed = host_random_hex(64)?;

    let mut last_err = String::from("unknown error");
    for attempt in 1..=REJUVENATE_ATTEMPTS {
        match rejuvenate_once(&sock, clone, &seed, record) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(
                    clone,
                    attempt,
                    error = %e,
                    "clone rejuvenation attempt failed"
                );
                last_err = e;
                if attempt < REJUVENATE_ATTEMPTS {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }
    Err(Error::agent(
        "rejuvenate clone",
        format!(
            "identity reset could not be confirmed after {REJUVENATE_ATTEMPTS} attempts: {last_err}"
        ),
    ))
}

/// One attempt: connect to the clone's agent and run the re-mint script. Any
/// connect error, exec error, or non-zero exit is a failure (fail-closed).
fn rejuvenate_once(
    sock: &Path,
    clone: &str,
    seed: &str,
    record: &VmRecord,
) -> std::result::Result<(), String> {
    let mut client =
        AgentClient::connect_with_retry(sock).map_err(|e| format!("agent connect: {e}"))?;
    // Capture after connection backoff and rebuild on every outer attempt. This
    // keeps the Linux/KVM correction within the exec round-trip of host time
    // instead of reusing an epoch made stale by retries. Other hosts pass zero:
    // their libkrun time-sync pusher already owns CLOCK_REALTIME correction.
    let script = build_rejuvenation_script(clone, seed, rejuvenation_host_epoch(), record);
    match client.vm_exec(
        vec![
            "/usr/bin/timeout".into(),
            "-k".into(),
            "1".into(),
            "7".into(),
            "/bin/sh".into(),
            "-c".into(),
            script,
        ],
        vec![],
        None,
        Some(std::time::Duration::from_secs(10)),
        None,
    ) {
        Ok((0, _, stderr)) => {
            if clock_reset_failed(&stderr) {
                tracing::warn!(
                    clone,
                    "clone rejuvenation succeeded but the Linux/KVM wall-clock reset failed"
                );
            }
            Ok(())
        }
        Ok((code, _, stderr)) => Err(format!(
            "re-mint script exited {code}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )),
        Err(e) => Err(format!("exec: {e}")),
    }
}

/// Guest path of the per-fork parameter file, dotenv format (`KEY=VALUE`
/// lines). A forked clone's workload resumed mid-flight from the golden's
/// snapshot, so its process env cannot carry per-clone values — sweep and
/// rollout workloads read this file instead (typically after their GO gate).
///
/// Lives under `/etc` (the workload container's overlay filesystem), NOT
/// `/run`: `/run` is a per-container-instance tmpfs, so a file there vanishes
/// if the restored container is recycled — the overlay is the only surface
/// shared by every instance and the running workload alike.
pub const FORK_ENV_GUEST_PATH: &str = smolvm_protocol::forkpoint::FORK_ENV_PATH;
/// Guest path of the same per-fork parameters in a form a POSIX shell can
/// `.`-source: every pair exported and single-quoted (see [`render_branch_env`]).
/// Not an alias of [`FORK_ENV_GUEST_PATH`]: that file stays plain dotenv for
/// machine readers; this one is for a workload that continues after
/// `smolvm-branch-ready` and needs its identity in its own environment.
pub const BRANCH_ENV_GUEST_PATH: &str = smolvm_protocol::forkpoint::BRANCH_ENV_PATH;

/// Validate per-fork parameters: keys must be non-empty `[A-Za-z_][A-Za-z0-9_]*`
/// (they double as env var names for exec sessions) and values must be free of
/// newlines (one `KEY=VALUE` per line in the delivered file).
pub fn validate_fork_env(env: &[(String, String)]) -> Result<()> {
    for (k, v) in env {
        let mut chars = k.chars();
        let head_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !head_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(Error::config(
                "fork env",
                format!("invalid key '{k}': must match [A-Za-z_][A-Za-z0-9_]*"),
            ));
        }
        if v.contains('\n') || v.contains('\r') {
            return Err(Error::config(
                "fork env",
                format!("value for '{k}' must not contain newlines"),
            ));
        }
    }
    Ok(())
}

/// Render per-fork parameters as the dotenv file content.
pub fn render_fork_env(env: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in env {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    out
}

/// Render per-fork parameters as a file a POSIX shell can `.`-source directly.
///
/// The dotenv form is not safely sourceable: a bare `KEY=VALUE` line neither
/// exports the variable (so an `exec`'d workload never sees it) nor survives a
/// value with spaces (`NOTE=a=b c` runs `c` as a command). This form exports
/// every pair and single-quotes every value, escaping embedded quotes, so
/// `. /etc/smolvm/branch-env` is correct for any value the validator admits.
pub fn render_branch_env(env: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in env {
        out.push_str("export ");
        out.push_str(k);
        out.push_str("='");
        out.push_str(&v.replace('\'', "'\\''"));
        out.push_str("'\n");
    }
    out
}

/// Shell fragment that writes the sourceable branch env to `path`.
///
/// Delivered inside the same install script as the dotenv file. A quoted
/// heredoc performs no expansion, and no rendered line can equal the
/// delimiter (every line starts with `export`), so the embedded content is
/// injection-safe for any value the validator admits.
///
/// The `&& mv` sits on the heredoc's own command line: the body follows that
/// line, so this keeps the caller's `&&` chain intact — `write_fork_env` has
/// no `set -e`, and that chain is its only error handling. A rename into
/// place makes the swap atomic for any reader. The fragment ends with the
/// delimiter on a line of its own, newline-terminated: a heredoc terminator
/// must be the whole line, so a caller continues on the next line and must
/// not append `;` or `&&` to the fragment.
fn branch_env_install_fragment(path: &str, env: &[(String, String)]) -> String {
    format!(
        "cat > '{path}.tmp' <<'SMOLVM_BRANCH_ENV_EOF' && mv '{path}.tmp' '{path}'\n{content}SMOLVM_BRANCH_ENV_EOF\n",
        content = render_branch_env(env)
    )
}

/// Merge assignment-time parameters into a held slot's initial fork
/// parameters. Later values replace same-named earlier values while preserving
/// stable ordering for every untouched entry.
pub fn merge_fork_env(
    initial: &[(String, String)],
    assignment: &[(String, String)],
) -> Vec<(String, String)> {
    let mut merged = initial.to_vec();
    for (key, value) in assignment {
        merged.retain(|(existing, _)| existing != key);
        merged.push((key.clone(), value.clone()));
    }
    merged
}

/// Persist the state transition after a held slot has been released
/// successfully. Kept in one shared helper so the CLI and HTTP API cannot
/// disagree about the one-shot flag or assignment environment.
pub fn record_fork_activation(
    record: &mut VmRecord,
    assignment: &[(String, String)],
    merged: Vec<(String, String)>,
) {
    let assignment_keys: HashSet<&str> = assignment.iter().map(|(key, _)| key.as_str()).collect();
    record.forkpoint_held = false;
    record.fork_env = merged;
    record
        .env
        .retain(|(key, _)| !assignment_keys.contains(key.as_str()));
    record.env.extend(assignment.iter().cloned());
}

/// Deliver per-fork parameters into a freshly-booted clone at
/// [`FORK_ENV_GUEST_PATH`], via a VM-namespace write THROUGH the workload
/// container's overlayfs `merged` mount. Deliberately not a container exec:
/// the restored workload container can look stale to the exec path right
/// after a fork, and exec'ing would recycle it — killing the very workload
/// that is waiting for these parameters. Writing through the merged mount
/// reaches the running container's rootfs without touching the container
/// runtime at all. Bare VMs (no image) get the file in the VM rootfs.
///
/// FAIL-CLOSED by the caller: if the user asked for parameters and they can't
/// be delivered, the fork must fail rather than vend a clone that silently
/// runs with the golden's (or a sibling's) parameters.
pub fn write_fork_env(clone: &str, record: &VmRecord, env: &[(String, String)]) -> Result<()> {
    if env.is_empty() {
        return Ok(());
    }
    let content = render_fork_env(env);
    // Overlay owner is a validated machine name (alphanumeric + dashes), so
    // splicing it into the script is injection-safe — same contract as the
    // rejuvenation script's clone name.
    let owner = crate::workload::persistent_overlay_owner_with_lineage(
        clone,
        record.golden.as_deref(),
        record.fork_overlay_owner.as_deref(),
    );
    let merged = format!("/storage/overlays/persistent-{owner}/merged");
    let sock = vm_data_dir(clone).join("agent.sock");
    let mut client = AgentClient::connect_with_retry(&sock)
        .map_err(|e| Error::agent("fork env: agent connect", e.to_string()))?;
    // The workload reads these files, and it may run as any account the
    // image or the machine names, so they are world-readable inside the VM
    // (single-tenant), not root-only.
    // Image machines MUST land the file in the workload container's rootfs
    // (the overlay merged dir): falling through silently would strand it in
    // the agent rootfs where no workload will ever look. Fail with the actual
    // overlay listing so a layout change is diagnosable, not silent.
    let script = if record.image.is_some() {
        format!(
            "if [ ! -d {merged} ]; then echo \"missing {merged}; overlays:\" >&2; \
             ls /storage/overlays >&2; exit 41; fi; \
             mkdir -p {merged}/etc/smolvm && umask 022 && \
             cat > {merged}{FORK_ENV_GUEST_PATH} && {branch_env}",
            branch_env =
                branch_env_install_fragment(&format!("{merged}{BRANCH_ENV_GUEST_PATH}"), env)
        )
    } else {
        format!(
            "mkdir -p /etc/smolvm && umask 022 && cat > {FORK_ENV_GUEST_PATH} && {branch_env}",
            branch_env = branch_env_install_fragment(BRANCH_ENV_GUEST_PATH, env)
        )
    };
    match client.vm_exec(
        vec!["/bin/sh".into(), "-c".into(), script],
        vec![],
        None,
        Some(std::time::Duration::from_secs(10)),
        Some(content),
    ) {
        Ok((0, _, _)) => Ok(()),
        Ok((code, _, stderr)) => Err(Error::agent(
            "fork env",
            format!(
                "write exited {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        )),
        Err(e) => Err(Error::agent("fork env", format!("vm exec: {e}"))),
    }
}

/// Assign and release one clean, already-booted fork-pool slot.
///
/// The guest performs the state check, fork-env replacement, and release-marker
/// publication in one agent exec. A slot can therefore be released only once;
/// a completed training worker is never reset or reused with dirty optimizer,
/// RNG, allocator, or dataset state. Callers replenish the pool by deleting the
/// consumed clone and forking a fresh held slot from its still-frozen golden.
///
/// Returns the complete merged fork parameter set that the caller should
/// persist after success.
pub fn activate_held_fork(
    clone: &str,
    record: &VmRecord,
    assignment: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    validate_fork_env(assignment)?;
    let merged = merge_fork_env(&record.fork_env, assignment);
    let content = render_fork_env(&merged);
    let owner = crate::workload::persistent_overlay_owner_with_lineage(
        clone,
        record.golden.as_deref(),
        record.fork_overlay_owner.as_deref(),
    );
    let merged_root = format!("/storage/overlays/persistent-{owner}/merged");
    let env_path = if record.image.is_some() {
        format!("{merged_root}{FORK_ENV_GUEST_PATH}")
    } else {
        FORK_ENV_GUEST_PATH.to_string()
    };
    let branch_env_path = if record.image.is_some() {
        format!("{merged_root}{BRANCH_ENV_GUEST_PATH}")
    } else {
        BRANCH_ENV_GUEST_PATH.to_string()
    };
    // The token makes this operation safe to repeat after an ambiguous socket
    // timeout. A release can wake a CUDA-heavy workload before the guest agent's
    // reply reaches the host; without an idempotency receipt, retrying could vend
    // the same clean slot twice while failing immediately could discard a slot
    // that was actually released successfully.
    let activation_token = format!(
        "{}{}",
        crate::util::generate_short_id(),
        crate::util::generate_short_id()
    );
    let (require_dir, env_dir) = if record.image.is_some() {
        (
            Some(merged_root.clone()),
            format!("{merged_root}/etc/smolvm"),
        )
    } else {
        (None, "/etc/smolvm".to_string())
    };
    let activation = crate::agent::client::BranchpointActivation {
        env_dotenv: content,
        env_sourceable: render_branch_env(&merged),
        env_path,
        branch_env_path,
        require_dir,
        env_dir,
        activation_token,
    };
    use smolvm_protocol::forkpoint::typed_error;
    for attempt in 1..=2 {
        let mut client = match branch_client(clone, "activate held fork") {
            Ok(client) => client,
            Err(error) if attempt == 1 => {
                tracing::warn!(
                    clone,
                    %error,
                    "held-fork activation connect was ambiguous; retrying idempotently"
                );
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(error),
        };
        match client.branchpoint_activate(activation.clone()) {
            // A repeat with the same token after an ambiguous reply is the
            // partial commit completing, not a second activation.
            Ok(Ok(_already_done)) => return Ok(merged),
            Ok(Err(f)) if f.code.as_deref() == Some(typed_error::TOKEN_MISMATCH) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("clone '{clone}' was already released"),
                ));
            }
            Ok(Err(f)) if f.code.as_deref() == Some(typed_error::NOT_READY) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("clone '{clone}' is not parked at a forkpoint"),
                ));
            }
            Ok(Err(f)) if attempt == 1 => {
                tracing::warn!(
                    clone,
                    error = %f,
                    "held-fork activation attempt failed; retrying idempotently"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(Err(f)) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("clone '{clone}': {f}"),
                ));
            }
            Err(error) if attempt == 1 => {
                tracing::warn!(
                    clone,
                    %error,
                    "held-fork activation reply was ambiguous; retrying idempotently"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("clone '{clone}': {error}"),
                ));
            }
        }
    }
    Err(Error::agent(
        "activate held fork",
        format!("clone '{clone}' activation did not complete"),
    ))
}

/// Guest env key telling a workload how long it has to publish readiness.
pub const WORKER_READY_TIMEOUT_ENV: &str = "SMOLVM_WORKER_READY_TIMEOUT_SECS";

/// A fresh 64-hex readiness token for a child that has no external
/// idempotency key to derive one from.
pub fn random_worker_ready_token() -> Result<String> {
    use std::io::Read as _;
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .map_err(|error| Error::agent("worker readiness", format!("generate token: {error}")))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Put the readiness contract into a child's parameters: the token its
/// `smolvm-worker-ready` call must echo and the window it has to do so.
/// Refuses parameters that already use those keys, since a caller-supplied
/// token could never be verified.
pub fn add_worker_ready_assignment(
    env: &mut Vec<(String, String)>,
    token: &str,
    timeout: Duration,
) -> Result<()> {
    for reserved in [
        smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV,
        WORKER_READY_TIMEOUT_ENV,
    ] {
        if env.iter().any(|(key, _)| key == reserved) {
            return Err(Error::config(
                "worker readiness",
                format!("{reserved} is reserved for smolvm worker readiness"),
            ));
        }
    }
    env.push((
        smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV.to_string(),
        token.to_string(),
    ));
    env.push((
        WORKER_READY_TIMEOUT_ENV.to_string(),
        timeout.as_secs().to_string(),
    ));
    Ok(())
}

/// The readiness token a child's parameters carry, if any.
pub fn worker_ready_token_of(env: &[(String, String)]) -> Option<&str> {
    env.iter()
        .find(|(key, _)| key == smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV)
        .map(|(_, token)| token.as_str())
}

/// Wait until a released workload proves that clone-local preparation finished.
pub fn wait_for_worker_ready(clone: &str, token: &str, timeout: Duration) -> Result<()> {
    use smolvm_protocol::forkpoint::typed_error;
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::config(
            "worker readiness",
            "token must contain exactly 64 hexadecimal characters",
        ));
    }
    if timeout.is_zero() {
        return Err(Error::config(
            "worker readiness",
            "timeout must be positive",
        ));
    }
    let mut client = branch_client(clone, "wait for worker readiness")?;
    match client
        .branchpoint_wait_worker_ready(&token.to_ascii_lowercase(), timeout)
        .map_err(|error| {
            Error::agent(
                "wait for worker readiness",
                format!("clone '{clone}': {error}"),
            )
        })? {
        Ok(()) => Ok(()),
        Err(f) if f.code.as_deref() == Some(typed_error::NO_ACK) => Err(Error::agent(
            "wait for worker readiness",
            format!(
                "clone '{clone}' did not signal readiness within {} seconds",
                timeout.as_secs()
            ),
        )),
        Err(f) if f.code.as_deref() == Some(typed_error::TOKEN_MISMATCH) => Err(Error::agent(
            "wait for worker readiness",
            format!("clone '{clone}' published a stale or invalid readiness token"),
        )),
        Err(f) => Err(Error::agent(
            "wait for worker readiness",
            format!("clone '{clone}': {f}"),
        )),
    }
}

/// Fail-closed fork finalizer. A clone whose identity could not be rejuvenated
/// MUST NOT be vended (it would share the golden's machine-id/hostname/SSH host
/// keys across tenants), so on any rejuvenation `Err` this runs `teardown`
/// (stop + remove the clone) and propagates the error, turning a rejuvenation
/// failure into a fork failure. On `Ok` it does nothing and the caller proceeds
/// to mark the clone ready. Extracted as a pure decision so the fail-closed
/// behavior is unit-tested independently of the VM/agent machinery.
pub fn fail_closed_on_rejuvenation<F: FnOnce()>(
    rejuvenation: Result<()>,
    teardown: F,
) -> Result<()> {
    match rejuvenation {
        Ok(()) => Ok(()),
        Err(e) => {
            teardown();
            Err(e)
        }
    }
}

/// Allocate a currently-free host TCP port by binding to port 0 and reading back
/// the OS-assigned port. Used to give each clone distinct inbound forwards.
fn alloc_free_host_port() -> Option<u16> {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|addr| addr.port())
}

fn alloc_free_host_port_excluding(reserved: &mut HashSet<u16>) -> Option<u16> {
    for _ in 0..128 {
        let port = alloc_free_host_port()?;
        if reserved.insert(port) {
            return Some(port);
        }
    }
    None
}

/// Read `hex_len/2` random bytes from the host RNG, hex-encoded. Used to seed
/// each clone's RNG with distinct host entropy.
fn host_random_hex(hex_len: usize) -> Result<String> {
    use std::io::Read;
    if hex_len == 0 || !hex_len.is_multiple_of(2) {
        return Err(Error::agent(
            "seed clone identity",
            "random hex length must be a non-zero even number",
        ));
    }
    let mut buf = vec![0u8; hex_len / 2];
    let mut random = std::fs::File::open("/dev/urandom")
        .map_err(|e| Error::agent("seed clone identity", e.to_string()))?;
    random
        .read_exact(&mut buf)
        .map_err(|e| Error::agent("seed clone identity", e.to_string()))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_branch_ram_auto_shares_active_sibling_pages() {
        assert_eq!(
            select_live_branch_ram_mode(true, None).unwrap(),
            LiveBranchRamMode::Shared
        );
        assert_eq!(
            select_live_branch_ram_mode(false, Some("auto")).unwrap(),
            LiveBranchRamMode::Shared
        );
    }

    #[test]
    fn live_branch_ram_auto_shares_single_children_and_pool_slots() {
        assert_eq!(
            select_live_branch_ram_mode(true, None).unwrap(),
            LiveBranchRamMode::Shared
        );
    }

    #[test]
    fn live_branch_ram_override_is_validated() {
        assert_eq!(
            select_live_branch_ram_mode(true, Some("paged")).unwrap(),
            LiveBranchRamMode::Paged
        );
        assert!(select_live_branch_ram_mode(false, Some("paged")).is_err());
        assert!(select_live_branch_ram_mode(true, Some("copy-everything")).is_err());
    }

    #[test]
    fn branch_memory_admission_scales_with_children_and_new_generation() {
        assert_eq!(branch_admission_required_mib(8, 64, 1024, 512), Some(2048));
        assert_eq!(branch_admission_required_mib(8, 64, 1024, 0), Some(1536));
        assert_eq!(
            branch_admission_required_mib(usize::MAX, u64::MAX, 1, 1),
            None
        );
    }

    #[test]
    fn worker_ready_assignment_carries_a_fresh_token_and_refuses_a_forged_one() {
        let token = random_worker_ready_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(token, random_worker_ready_token().unwrap());

        let mut env = vec![("LR".to_string(), "3e-4".to_string())];
        add_worker_ready_assignment(&mut env, &token, Duration::from_secs(90)).unwrap();
        assert_eq!(worker_ready_token_of(&env), Some(token.as_str()));
        assert!(env.contains(&(WORKER_READY_TIMEOUT_ENV.to_string(), "90".to_string())));

        let mut forged = vec![(
            smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV.to_string(),
            "0".repeat(64),
        )];
        let error = add_worker_ready_assignment(&mut forged, &token, Duration::from_secs(1))
            .unwrap_err()
            .to_string();
        assert!(error.contains("reserved"), "{error}");
        assert!(worker_ready_token_of(&[]).is_none());
    }
    use std::cell::Cell;

    #[cfg(target_os = "linux")]
    fn write_test_qcow2(path: &Path, backing: Option<&str>) {
        let mut bytes = vec![0_u8; 20];
        bytes[..4].copy_from_slice(b"QFI\xfb");
        if let Some(backing) = backing {
            bytes[8..16].copy_from_slice(&20_u64.to_be_bytes());
            bytes[16..20].copy_from_slice(&(backing.len() as u32).to_be_bytes());
            bytes.extend_from_slice(backing.as_bytes());
        }
        std::fs::write(path, bytes).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fork_disk_depth_resolves_relative_backings_and_rejects_cycles() {
        let temp = tempfile::tempdir().unwrap();
        let raw = temp.path().join("base.raw");
        std::fs::write(&raw, vec![0_u8; 20]).unwrap();
        let middle = temp.path().join("middle.qcow2");
        let top = temp.path().join("top.qcow2");
        write_test_qcow2(&middle, Some("base.raw"));
        write_test_qcow2(&top, Some("middle.qcow2"));
        assert_eq!(qcow2_backing_depth(&top).unwrap(), 2);

        write_test_qcow2(&middle, Some("top.qcow2"));
        assert!(qcow2_backing_depth(&top)
            .unwrap_err()
            .to_string()
            .contains("cycle"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relocating_qcow2_keeps_its_relative_backing_chain_valid() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let raw = temp.path().join("0");
        std::fs::write(&raw, vec![0_u8; 20]).unwrap();
        let top = temp.path().join("storage.qcow2");
        write_test_qcow2(&top, Some("0"));

        let generation = temp.path().join("d/generation");
        std::fs::create_dir_all(&generation).unwrap();
        let relocated = generation.join("storage.base.qcow2");
        stage_relocated_qcow2_backings(&top, &relocated).unwrap();
        std::fs::rename(&top, &relocated).unwrap();

        assert_eq!(qcow2_backing_depth(&relocated).unwrap(), 1);
        assert_eq!(
            std::fs::metadata(&raw).unwrap().ino(),
            std::fs::metadata(generation.join("0")).unwrap().ino(),
            "backing should be preserved without copying its contents"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_fork_refuses_an_unbounded_disk_chain() {
        let temp = tempfile::tempdir().unwrap();
        let raw = temp.path().join("base.raw");
        std::fs::write(&raw, vec![0_u8; 20]).unwrap();
        let mut backing = "base.raw".to_string();
        for index in 0..MAX_FORK_DISK_CHAIN_DEPTH {
            let name = if index + 1 == MAX_FORK_DISK_CHAIN_DEPTH {
                crate::data::storage::STORAGE_DISK_FILENAME.replace(".raw", ".qcow2")
            } else {
                format!("layer-{index}.qcow2")
            };
            write_test_qcow2(&temp.path().join(&name), Some(&backing));
            backing = name;
        }
        let error = ensure_fork_disk_chain_is_bounded(temp.path()).unwrap_err();
        assert!(error.to_string().contains("safe limit is 32"));
    }

    #[cfg(target_os = "linux")]
    fn write_test_guardian_manifest(snapshot_dir: &Path, pid: i32, start_time: u64) {
        let socket = snapshot_dir.join(GUARDIAN_SOCKET_NAME);
        let socket = std::os::unix::ffi::OsStrExt::as_bytes(socket.as_os_str());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GUARDIAN_MANIFEST_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&pid.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&start_time.to_le_bytes());
        bytes.extend_from_slice(&(socket.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 32]);
        bytes.extend_from_slice(socket);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&4096_u64.to_le_bytes());
        std::fs::write(snapshot_dir.join("manifest.bin"), bytes).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_cleanup_terminates_only_the_recorded_guardian_generation() {
        use std::process::Command;

        let temp = tempfile::tempdir().unwrap();
        let snapshot = temp.path().join("generation");
        std::fs::create_dir(&snapshot).unwrap();
        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id() as i32;
        let start_time = crate::process::process_start_time(pid).unwrap();
        write_test_guardian_manifest(&snapshot, pid, start_time);
        let reaper = std::thread::spawn(move || child.wait().unwrap());

        stop_snapshot_guardian(&snapshot).unwrap();
        let status = reaper.join().unwrap();
        assert!(!status.success());
        assert!(!crate::process::is_alive(pid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guardian_cleanup_rejects_a_socket_outside_the_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = temp.path().join("generation");
        std::fs::create_dir(&snapshot).unwrap();
        write_test_guardian_manifest(&snapshot, std::process::id() as i32, 1);
        let mut bytes = std::fs::read(snapshot.join("manifest.bin")).unwrap();
        let socket = b"/tmp/escaped.sock";
        bytes[32..36].copy_from_slice(&(socket.len() as u32).to_le_bytes());
        bytes.truncate(72);
        bytes.extend_from_slice(socket);
        std::fs::write(snapshot.join("manifest.bin"), bytes).unwrap();
        assert!(snapshot_guardian_identity(&snapshot).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn fork_source_lock_serializes_independent_open_handles() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source.lock");
        let first = ForkSourceLock::acquire_at(&path).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let waiter_path = path.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _second = ForkSourceLock::acquire_at(&waiter_path).unwrap();
            acquired_tx.send(()).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "a second fork transaction must wait for the first"
        );
        drop(first);
        acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        waiter.join().unwrap();
    }

    /// A lock file names its machine, and the sweep must recover that name the
    /// same way the path builds it -- including names containing dots, which the
    /// `.<name>.fork-operation.lock` shape makes ambiguous to a naive split.
    #[test]
    fn a_lock_files_owner_round_trips_through_its_path() {
        for source in ["golden", "worker.one", "a.b.c", "trailing.lock"] {
            assert_eq!(
                fork_source_lock_owner(&fork_source_lock_path(source)).as_deref(),
                Some(source)
            );
        }
        assert_eq!(fork_source_lock_owner(Path::new("/vms/notalock")), None);
        assert_eq!(
            fork_source_lock_owner(Path::new("/vms/.fork-operation.lock")),
            None
        );
    }

    /// The leak this sweep exists to stop: the lock outlives its machine because
    /// it is deliberately a sibling of the data directory, so deleting the
    /// machine never takes it.
    #[test]
    fn an_orphaned_lock_is_swept() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".gone.fork-operation.lock");
        std::fs::write(&lock, b"").unwrap();

        prune_orphaned_fork_source_locks_in(dir.path());

        assert!(
            !lock.exists(),
            "a lock whose machine is gone must be removed"
        );
    }

    /// A machine that still exists is still forkable, so its lock must survive.
    /// The data directory is hash-named, so the sweep has to hash the recovered
    /// name rather than look for a directory called after it.
    #[test]
    fn a_live_machines_lock_survives_the_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".alive.fork-operation.lock");
        std::fs::write(&lock, b"").unwrap();
        std::fs::create_dir_all(dir.path().join(crate::agent::vm_dir_hash("alive"))).unwrap();

        prune_orphaned_fork_source_locks_in(dir.path());

        assert!(lock.exists(), "a live machine's lock must not be swept");
    }

    /// The race the sibling placement exists to prevent: unlinking a lock that a
    /// fork is holding would let the next fork create a fresh inode and run in
    /// parallel. Holding it must therefore veto the sweep even when the machine
    /// directory is already gone -- which is exactly the ordering a delete
    /// racing an in-flight fork produces.
    ///
    /// Note this holds *within* one process too: flock conflicts with the holder
    /// across a second descriptor, not just across processes. `delete_vm` takes
    /// this same lock for its whole transaction, so it must drop the guard before
    /// sweeping or it vetoes the very file it is trying to clean up.
    #[cfg(unix)]
    #[test]
    fn a_held_lock_is_never_swept_even_without_its_machine() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".busy.fork-operation.lock");
        std::fs::write(&lock, b"").unwrap();
        let held = ForkSourceLock::acquire_at(&lock).unwrap();

        prune_orphaned_fork_source_locks_in(dir.path());

        assert!(lock.exists(), "an in-flight fork's lock must not be swept");
        drop(held);
        prune_orphaned_fork_source_locks_in(dir.path());
        assert!(!lock.exists(), "once released it is sweepable");
    }

    /// Unrelated files sharing the directory must be left alone -- the sweep
    /// runs in the VM cache root, which holds every machine's data directory.
    #[test]
    fn the_sweep_touches_nothing_but_lock_files() {
        let dir = tempfile::tempdir().unwrap();
        let bystanders = [".hidden", "machine-dir-ish", "name.lock", "_shared"];
        for f in bystanders {
            std::fs::write(dir.path().join(f), b"x").unwrap();
        }

        prune_orphaned_fork_source_locks_in(dir.path());

        for f in bystanders {
            assert!(dir.path().join(f).exists(), "{f} must survive the sweep");
        }
    }

    #[test]
    fn dotted_machine_names_have_distinct_fork_locks() {
        assert_ne!(
            fork_source_lock_path("worker.one"),
            fork_source_lock_path("worker.two")
        );
    }

    // Per-fork parameters double as env var names and dotenv file lines, so
    // keys must be valid identifiers and values single-line — anything else
    // must be rejected up front, before the golden is frozen.
    #[test]
    fn fork_env_validation_accepts_identifiers_and_rejects_junk() {
        let ok = vec![
            ("LR".to_string(), "3e-4".to_string()),
            ("_SEED".to_string(), "42".to_string()),
            (
                "TASK_2".to_string(),
                "spaces and = are fine in values".to_string(),
            ),
        ];
        assert!(validate_fork_env(&ok).is_ok());

        for (k, v) in [
            ("2LR", "x"),
            ("", "x"),
            ("A-B", "x"),
            ("K", "line1\nline2"),
            ("K", "cr\rvalue"),
        ] {
            assert!(
                validate_fork_env(&[(k.to_string(), v.to_string())]).is_err(),
                "expected rejection for key={k:?} value={v:?}"
            );
        }
    }

    #[test]
    fn paused_golden_reuses_the_proven_forkpoint_for_refill() {
        assert!(fork_base_already_paused("OK paused\n"));
        assert!(!fork_base_already_paused("OK running\n"));
        assert!(!fork_base_already_paused("ERR not forkable\n"));
    }

    #[test]
    fn golden_rollback_reapplies_a_completed_checkpoint_only() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(golden_resume_command(temp.path()).unwrap(), "RESUME");

        std::fs::write(temp.path().join("checkpoint.bin"), b"checkpoint").unwrap();
        assert_eq!(
            golden_resume_command(temp.path()).unwrap(),
            format!("ROLLBACK_FORK {}", temp.path().display())
        );

        std::fs::remove_file(temp.path().join("checkpoint.bin")).unwrap();
        std::fs::create_dir(temp.path().join("checkpoint.bin")).unwrap();
        assert!(golden_resume_command(temp.path()).is_err());
    }

    #[test]
    fn golden_rollback_refuses_to_invalidate_a_live_clones_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("test.db")).unwrap();
        let golden = VmRecord::new("golden".into(), 2, 1024, vec![], vec![], false);
        db.insert_vm("golden", &golden).unwrap();
        let mut clone = VmRecord::new("clone".into(), 2, 1024, vec![], vec![], false);
        clone.golden = Some("golden".into());
        db.insert_vm("clone", &clone).unwrap();
        let snapshot = temp.path().join("snapshot");
        std::fs::create_dir(&snapshot).unwrap();

        let error = rollback_retained_fork_snapshot(&db, "golden", &snapshot, true)
            .expect_err("a live clone must keep its checkpoint");

        assert!(error.to_string().contains("1 live clone(s)"));
        assert!(snapshot.exists());
    }

    #[test]
    fn forkpoint_profile_parses_optional_cuda_preload_hint() {
        assert_eq!(
            parse_forkpoint_profile(b"smolvm-forkpoint-v1\n"),
            ForkpointProfile::default()
        );
        assert!(
            parse_forkpoint_profile(b"smolvm-forkpoint-v1\ncuda-preload-modules\n")
                .cuda_preload_modules
        );
        assert!(!parse_forkpoint_profile(b"cuda-preload-modules-extra\n").cuda_preload_modules);
    }

    #[test]
    fn retained_snapshot_requires_the_same_paused_golden_process() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_root = temp.path().join("s");
        let snapshot_path = snapshot_root.join("a1b2c3d4");
        std::fs::create_dir_all(&snapshot_path).unwrap();
        let snapshot = RetainedForkSnapshot {
            path: snapshot_path,
            golden_pid: 123,
            golden_pid_start_time: 456,
        };
        let mut golden = VmRecord::new("golden".into(), 2, 1024, vec![], vec![], false);
        golden.pid = Some(123);
        golden.pid_start_time = Some(456);

        assert!(retained_snapshot_is_reusable(
            &golden,
            true,
            &snapshot_root,
            &snapshot
        ));
        assert!(retained_snapshot_matches_golden(
            &golden,
            &snapshot_root,
            &snapshot
        ));
        assert!(!retained_snapshot_is_reusable(
            &golden,
            false,
            &snapshot_root,
            &snapshot
        ));
        std::fs::write(
            snapshot.path.join("source-continues-v1"),
            b"source-continues-v1\n",
        )
        .unwrap();
        assert!(retained_snapshot_is_reusable(
            &golden,
            false,
            &snapshot_root,
            &snapshot
        ));
        golden.pid_start_time = Some(457);
        assert!(!retained_snapshot_matches_golden(
            &golden,
            &snapshot_root,
            &snapshot
        ));
        assert!(!retained_snapshot_is_reusable(
            &golden,
            true,
            &snapshot_root,
            &snapshot
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uncommitted_disk_generation_rollback_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let gdir = temp.path().join("golden");
        let snapshot = gdir.join("s").join("0123abcd");
        let generation = gdir.join("d").join("0123abcd");
        std::fs::create_dir_all(&snapshot).unwrap();
        std::fs::create_dir_all(&generation).unwrap();
        let active = gdir.join("overlay.qcow2");
        let base = generation.join("overlay.base.qcow2");
        std::fs::write(&active, b"unused-overlay").unwrap();
        std::fs::write(&base, b"live-source-disk").unwrap();
        std::fs::write(
            snapshot.join("generation-disks.tsv"),
            format!("overlay.raw\t{}\tqcow2\n", base.display()),
        )
        .unwrap();

        rollback_uncommitted_disk_generation(&gdir, &snapshot).unwrap();
        assert_eq!(std::fs::read(&active).unwrap(), b"live-source-disk");
        assert!(!generation.exists());

        rollback_uncommitted_disk_generation(&gdir, &snapshot).unwrap();
        assert_eq!(std::fs::read(&active).unwrap(), b"live-source-disk");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_removes_only_uncommitted_generations() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("test.db")).unwrap();
        let gdir = temp.path().join("golden");
        let snapshot_root = gdir.join("s");
        let abandoned = snapshot_root.join("0123abcd");
        let committed = snapshot_root.join("89abcdef");
        let abandoned_disk = gdir.join("d").join("0123abcd");
        std::fs::create_dir_all(&abandoned).unwrap();
        std::fs::create_dir_all(&committed).unwrap();
        std::fs::create_dir_all(&abandoned_disk).unwrap();
        let active = gdir.join("overlay.qcow2");
        let base = abandoned_disk.join("overlay.base.qcow2");
        std::fs::write(&active, b"unused").unwrap();
        std::fs::write(&base, b"source").unwrap();
        for snapshot in [&abandoned, &committed] {
            std::fs::write(
                snapshot.join("generation-disks.tsv"),
                format!("overlay.raw\t{}\tqcow2\n", base.display()),
            )
            .unwrap();
        }
        std::fs::write(
            committed.join("source-continues-v1"),
            b"source-continues-v1\n",
        )
        .unwrap();
        db.set_retained_fork_snapshot(
            "golden",
            &RetainedForkSnapshot {
                path: abandoned.clone(),
                golden_pid: 1,
                golden_pid_start_time: 1,
            },
        )
        .unwrap();

        recover_uncommitted_generations(&db, "golden", &gdir, &snapshot_root).unwrap();

        assert!(!abandoned.exists());
        assert!(committed.exists());
        assert_eq!(std::fs::read(active).unwrap(), b"source");
        assert!(db.retained_fork_snapshot("golden").unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generation_gc_preserves_retained_and_live_clone_snapshots() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("test.db")).unwrap();
        let snapshot_root = temp.path().join("s");
        let retained_path = snapshot_root.join("11111111");
        let live_path = snapshot_root.join("22222222");
        let stale_path = snapshot_root.join("33333333");
        for path in [&retained_path, &live_path, &stale_path] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("source-continues-v1"), b"source-continues-v1\n").unwrap();
        }
        let mut clone = VmRecord::new("clone".into(), 1, 128, vec![], vec![], false);
        clone.golden = Some("golden".into());
        clone.fork_generation = Some("22222222".into());
        db.insert_vm("clone", &clone).unwrap();
        let retained = RetainedForkSnapshot {
            path: retained_path.clone(),
            golden_pid: 1,
            golden_pid_start_time: 1,
        };

        gc_unreferenced_fork_generations(&db, "golden", &snapshot_root, Some(&retained)).unwrap();

        assert!(retained_path.exists());
        assert!(live_path.exists());
        assert!(!stale_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lineage_accounting_counts_only_referenced_committed_generations() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("test.db")).unwrap();
        let root = temp.path().join("s");
        for generation in ["11111111", "22222222"] {
            let path = root.join(generation);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("source-continues-v1"), b"source-continues-v1\n").unwrap();
        }
        std::fs::create_dir_all(root.join("33333333")).unwrap();
        let malformed = root.join("not-a-generation");
        std::fs::create_dir_all(&malformed).unwrap();
        std::fs::write(
            malformed.join("source-continues-v1"),
            b"source-continues-v1\n",
        )
        .unwrap();

        let mut child = VmRecord::new("child".into(), 1, 128, vec![], vec![], false);
        child.golden = Some("golden".into());
        child.fork_generation = Some("11111111".into());
        db.insert_vm("child", &child).unwrap();
        let retained = RetainedForkSnapshot {
            path: root.join("22222222"),
            golden_pid: 1,
            golden_pid_start_time: 1,
        };

        assert_eq!(
            referenced_fork_generation_count(&db, "golden", &root, Some(&retained)).unwrap(),
            2
        );
        db.remove_vm("child").unwrap();
        assert_eq!(
            referenced_fork_generation_count(&db, "golden", &root, Some(&retained)).unwrap(),
            1,
            "unreferenced committed directories must not expand a VM's cgroup"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lineage_memory_ceiling_includes_each_retained_guest_generation() {
        let mut record = VmRecord::new("golden".into(), 2, 1024, vec![], vec![], false);
        assert_eq!(
            fork_lineage_memory_limit_bytes(&record, 2).unwrap(),
            3840 * 1024 * 1024
        );

        record.cuda = true;
        assert_eq!(
            fork_lineage_memory_limit_bytes(&record, 2).unwrap(),
            4864 * 1024 * 1024
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_ram_backing_belongs_only_to_the_recorded_vmm_process() {
        let mut record = VmRecord::new("golden".into(), 2, 1024, vec![], vec![], false);
        assert!(!source_has_private_ram_backing(&record));

        record.pid_start_time = Some(123);
        record.fork_lineage_pid_start_time = Some(123);
        assert!(source_has_private_ram_backing(&record));

        record.pid_start_time = Some(124);
        assert!(
            !source_has_private_ram_backing(&record),
            "a restarted VMM must not inherit the previous process's RAM allowance"
        );
    }

    #[test]
    fn restart_guard_allows_live_pivoted_generations_and_blocks_legacy_ones() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("test.db")).unwrap();
        let snapshot_root = temp.path().join("s");
        let live_generation = snapshot_root.join("11111111");
        std::fs::create_dir_all(&live_generation).unwrap();
        std::fs::write(
            live_generation.join("source-continues-v1"),
            b"source-continues-v1\n",
        )
        .unwrap();

        let mut safe = VmRecord::new("safe".into(), 1, 128, vec![], vec![], false);
        safe.golden = Some("golden".into());
        safe.fork_generation = Some("11111111".into());
        db.insert_vm("safe", &safe).unwrap();

        let mut legacy = VmRecord::new("legacy".into(), 1, 128, vec![], vec![], false);
        legacy.golden = Some("golden".into());
        legacy.fork_generation = Some("22222222".into());
        db.insert_vm("legacy", &legacy).unwrap();

        assert_eq!(
            restart_blocking_dependent_clones_in(&db, "golden", &snapshot_root).unwrap(),
            vec!["legacy".to_string()]
        );

        db.remove_vm("legacy").unwrap();
        assert!(
            restart_blocking_dependent_clones_in(&db, "golden", &snapshot_root)
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn atomic_snapshot_metadata_never_overwrites_a_published_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("generation-disks.tsv");
        atomic_write_snapshot_file(&path, b"first\n").unwrap();
        let error = atomic_write_snapshot_file(&path, b"second\n").unwrap_err();
        assert!(error.to_string().contains("snapshot metadata"));
        assert_eq!(std::fs::read(&path).unwrap(), b"first\n");
        assert!(!temp.path().join("generation-disks.tsv.partial").exists());
    }

    #[test]
    fn retained_snapshot_path_must_be_a_direct_real_checkpoint_directory() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_root = temp.path().join("s");
        std::fs::create_dir_all(&snapshot_root).unwrap();
        let valid = snapshot_root.join("0123abcd");
        std::fs::create_dir(&valid).unwrap();

        assert!(reusable_snapshot_path(&snapshot_root, &valid));
        assert!(!reusable_snapshot_path(
            &snapshot_root,
            &snapshot_root.join("short")
        ));
        assert!(!reusable_snapshot_path(
            &snapshot_root,
            &temp.path().join("0123abcd")
        ));
    }

    #[test]
    fn fork_env_renders_one_pair_per_line() {
        let env = vec![
            ("LR".to_string(), "3e-4".to_string()),
            ("NOTE".to_string(), "a=b c".to_string()),
        ];
        assert_eq!(render_fork_env(&env), "LR=3e-4\nNOTE=a=b c\n");
        assert_eq!(render_fork_env(&[]), "");
    }

    /// The sourceable form must survive the values the dotenv form cannot:
    /// spaces, `=`, and single quotes — and export everything, so an `exec`'d
    /// workload sees it after a plain `. /etc/smolvm/branch-env`.
    #[test]
    fn branch_env_is_exported_and_quoted_for_any_admissible_value() {
        let env = vec![
            ("SMOLVM_BRANCH_NAME".to_string(), "agent-3".to_string()),
            ("NOTE".to_string(), "a=b c".to_string()),
            ("Q".to_string(), "it's".to_string()),
        ];
        assert_eq!(
            render_branch_env(&env),
            "export SMOLVM_BRANCH_NAME='agent-3'\nexport NOTE='a=b c'\nexport Q='it'\\''s'\n"
        );
        assert_eq!(render_branch_env(&[]), "");
        // The install fragment embeds it in a quoted heredoc and moves it into place atomically.
        let frag = branch_env_install_fragment("/etc/smolvm/branch-env", &env);
        // `&& mv` on the heredoc line, body after it, delimiter last: the
        // rename is conditional on the write, and a caller's `&&` chain holds.
        assert!(frag.starts_with(
            "cat > '/etc/smolvm/branch-env.tmp' <<'SMOLVM_BRANCH_ENV_EOF' && mv '/etc/smolvm/branch-env.tmp' '/etc/smolvm/branch-env'\n"
        ));
        assert!(frag.contains("export NOTE='a=b c'\n"));
        assert!(frag.ends_with("SMOLVM_BRANCH_ENV_EOF\n"));
        // And it really runs: a failed write must not leave the target behind.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("branch-env");
        let ok = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                &branch_env_install_fragment(target.to_str().unwrap(), &env),
            ])
            .status()
            .unwrap();
        assert!(ok.success());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            render_branch_env(&env)
        );
        assert!(
            !target.with_extension("tmp").exists() && !dir.path().join("branch-env.tmp").exists()
        );
    }

    #[test]
    fn assignment_env_overrides_only_matching_pool_values() {
        let initial = vec![
            ("SMOLVM_FORK_INDEX".to_string(), "2".to_string()),
            ("LR".to_string(), "1e-4".to_string()),
        ];
        let assignment = vec![
            ("LR".to_string(), "3e-4".to_string()),
            ("DATASET".to_string(), "math".to_string()),
        ];
        assert_eq!(
            merge_fork_env(&initial, &assignment),
            vec![
                ("SMOLVM_FORK_INDEX".to_string(), "2".to_string()),
                ("LR".to_string(), "3e-4".to_string()),
                ("DATASET".to_string(), "math".to_string()),
            ]
        );
    }

    #[cfg(unix)]
    #[cfg(unix)]
    #[cfg(unix)]
    #[test]
    fn successful_activation_is_persisted_as_one_shot() {
        let mut record = VmRecord::new("slot-0".to_string(), 2, 1024, vec![], vec![], false);
        record.forkpoint_held = true;
        record.env = vec![
            ("BASE".to_string(), "keep".to_string()),
            ("LR".to_string(), "1e-4".to_string()),
        ];
        let assignment = vec![("LR".to_string(), "3e-4".to_string())];
        let merged = vec![("LR".to_string(), "3e-4".to_string())];

        record_fork_activation(&mut record, &assignment, merged.clone());

        assert!(!record.forkpoint_held);
        assert_eq!(record.fork_env, merged);
        assert_eq!(
            record.env,
            vec![
                ("BASE".to_string(), "keep".to_string()),
                ("LR".to_string(), "3e-4".to_string()),
            ]
        );
    }

    // Fix 1: the re-mint script must regenerate the per-machine on-disk secrets
    // that a wholesale CoW disk clone would otherwise share across tenants —
    // above all the SSH host keys.
    fn bare_vm_record() -> VmRecord {
        VmRecord::new("clone-a".to_string(), 1, 512, vec![], vec![], false)
    }

    fn image_record() -> VmRecord {
        let mut record = bare_vm_record();
        record.image = Some("alpine:latest".to_string());
        record
    }

    #[test]
    fn rejuvenation_script_regenerates_per_machine_secrets() {
        let script =
            build_rejuvenation_script("clone-a", "deadbeef", 1_700_000_000, &bare_vm_record());

        // SSH host keys: delete the golden's, then regenerate fresh ones.
        assert!(
            script.contains("ssh_host_"),
            "script must remove the golden's SSH host keys: {script}"
        );
        assert!(
            script.contains("/usr/bin/ssh-keygen"),
            "script must locate ssh-keygen by absolute path: {script}"
        );
        assert!(
            script.contains(r#""$KG" -A"#),
            "script must regenerate SSH host keys: {script}"
        );
        // Fresh machine-id, hostname, and dbus id.
        assert!(script.contains("> /etc/machine-id"));
        assert!(script.contains("> /etc/hostname"));
        assert!(script.contains("/var/lib/dbus/machine-id"));
        assert!(script.contains("MID=$(printf '%.32s' 'deadbeef')"));
        assert!(
            script.find("> /dev/urandom").unwrap() < script.find(r#""$KG" -A"#).unwrap(),
            "host entropy must be mixed before SSH keys are generated: {script}"
        );
        // The clone name and RNG seed are threaded through.
        assert!(script.contains("clone-a"));
        assert!(script.contains("deadbeef"));
        assert!(script.contains(&format!(
            "mkdir -p '{}'",
            smolvm_protocol::forkpoint::STATE_DIR
        )));
        assert!(script.contains(smolvm_protocol::forkpoint::RESTORED_PATH));
        // Guarded so it fails hard on core identity but no-ops when sshd/dbus
        // are absent (minimal library images).
        assert!(script.contains("set -e"));
        // Probed by absolute path, not `command -v`: the agent's exec PATH need
        // not carry the directory, and a miss under `set -e` would abort the
        // script after the old keys were already deleted.
        assert!(!script.contains("command -v ssh-keygen"));
    }

    // The rejuvenation script must NOT touch the inherited exec overlay: the
    // restored guest may still hold it mounted, and renaming a live
    // overlayfs's backing directories breaks every subsequent container exec
    // (ESTALE). Overlay adoption is a host-side lookup alias instead.
    #[test]
    fn rejuvenation_script_leaves_the_inherited_overlay_alone() {
        let script =
            build_rejuvenation_script("clone-a", "deadbeef", 1_700_000_000, &image_record());
        // Writing files THROUGH the merged mount is how the workload's rootfs is
        // reached (same as `write_fork_env`); what breaks a live overlayfs is
        // renaming or removing its backing dirs.
        // Paths *inside* the merged mount are the workload's own files; what must
        // never happen is the overlay root itself being renamed or removed.
        let merged = "/storage/overlays/persistent-clone-a/merged";
        for destructive in [
            format!("mv {merged}"),
            format!("rmdir {merged}"),
            format!("rm -rf {merged} "),
            format!("rm -rf {merged};"),
        ] {
            assert!(
                !script.contains(&destructive),
                "script must not rename/remove the overlay root: {script}"
            );
        }
    }

    // The regression this guards: identity files written unprefixed land in the
    // VM rootfs, where no workload reads them, so every clone of an image
    // machine kept the golden's SSH host keys.
    #[test]
    fn image_clones_rejuvenate_identity_inside_the_workload_rootfs() {
        let script =
            build_rejuvenation_script("clone-a", "deadbeef", 1_700_000_000, &image_record());
        let merged = "/storage/overlays/persistent-clone-a/merged";
        assert!(
            script.contains(&format!("{merged}/etc/hostname")),
            "hostname must be written into the workload rootfs: {script}"
        );
        assert!(
            script.contains(&format!("{merged}/etc/machine-id")),
            "machine-id must be written into the workload rootfs: {script}"
        );
        assert!(
            script.contains(&format!("{merged}/etc/ssh/ssh_host_")),
            "SSH host keys must be replaced inside the workload rootfs: {script}"
        );
        // The container's own ssh-keygen, since `-A` writes to a fixed /etc/ssh.
        assert!(
            script.contains(&format!(r#""$CH" {merged}"#)),
            "keys must be regenerated by the container's own binary: {script}"
        );
        assert!(script.contains("/usr/sbin/chroot"));
        // The inherited container has a private UTS namespace. Update it in
        // place so gethostname()/`hostname` agree with the on-disk identity
        // without restarting the warm workload.
        assert!(script.contains("main_container_id"));
        assert!(script.contains(smolvm_protocol::forkpoint::RESTORED_CONTAINER_PATH));
        assert!(script.contains("--root /storage/containers/crun"));
        assert!(script.contains("/usr/bin/nsenter --uts="));
        assert!(script.contains("/bin/hostname 'clone-a'"));
        // Fail-closed: a missing overlay, or keys that could not be regenerated,
        // must abort rather than vend a clone on the golden's identity.
        assert!(
            script.contains("exit 41"),
            "missing overlay must abort: {script}"
        );
        assert!(
            script.contains("exit 42"),
            "unregenerated keys must abort: {script}"
        );
    }

    // A bare VM has no workload container, so paths stay VM-rootfs relative.
    #[test]
    fn bare_vm_clones_keep_plain_vm_paths() {
        let script =
            build_rejuvenation_script("clone-a", "deadbeef", 1_700_000_000, &bare_vm_record());
        assert!(script.contains("> /etc/hostname"));
        assert!(!script.contains("/storage/overlays"));
        assert!(script.contains(r#""$KG" -A"#));
        // No chroot on the bare-VM path: the VM rootfs is the workload's rootfs.
        assert!(!script.contains("chroot"));
    }

    // A fork restores the golden's guest RAM, so the clone inherits the golden's
    // CLOCK_REALTIME frozen at forkpoint-bake time and — on Linux/KVM, where
    // nothing re-seeds it — reads `forkpoint_bake + uptime` forever behind real
    // time. The rejuvenation script must re-stamp the wall clock to the host
    // time captured at vend, or apt's `Release` "not valid yet" check and TLS
    // `notBefore` validation break inside every clone.
    #[test]
    fn rejuvenation_script_restamps_the_wall_clock() {
        let script =
            build_rejuvenation_script("clone-a", "deadbeef", 1_700_000_000, &bare_vm_record());
        assert!(
            script.contains("date -u -s @1700000000"),
            "script must re-stamp the wall clock from the host epoch: {script}"
        );
        // FAIL-SOFT: unlike the identity scrub, a `date` failure must not abort
        // `set -e` (which tears the clone down), but must stay observable — not a
        // silent `|| true` that would reproduce the very silent-skew bug.
        assert!(
            script.contains("|| echo 'rejuvenate-stage=clock-failed' >&2"),
            "clock re-stamp must be fail-soft with an observable marker: {script}"
        );
        // Corrected before the identity writes so the RESTORED marker and the
        // rewritten identity files carry the corrected time.
        assert!(
            script.find("date -u -s @").unwrap()
                < script.find("rejuvenate-stage=identity").unwrap(),
            "clock must be re-stamped before identity files are written: {script}"
        );
        // A zero / unavailable host epoch skips rather than setting the guest to
        // 1970 (which would be worse than a stale-but-plausible inherited clock).
        let skip = build_rejuvenation_script("clone-a", "deadbeef", 0, &bare_vm_record());
        assert!(skip.contains("rejuvenate-stage=clock-skipped"));
        assert!(!skip.contains("date -u -s @"));
    }

    #[test]
    fn rejuvenation_clock_reset_is_limited_to_linux_kvm_hosts() {
        let epoch = rejuvenation_host_epoch();
        #[cfg(target_os = "linux")]
        assert!(epoch >= 1_577_836_800, "Linux must provide a current epoch");
        #[cfg(not(target_os = "linux"))]
        assert_eq!(epoch, 0, "non-KVM hosts use libkrun time synchronization");
    }

    #[test]
    fn clock_reset_failure_marker_is_detected_on_successful_exec() {
        assert!(clock_reset_failed(
            b"rejuvenate-stage=clock\nrejuvenate-stage=clock-failed\nrejuvenate-stage=hostname\n"
        ));
        assert!(!clock_reset_failed(
            b"rejuvenate-stage=clock\nrejuvenate-stage=hostname\n"
        ));
    }

    #[test]
    fn clone_identity_seed_is_exact_and_never_silently_zero_filled() {
        let seed = host_random_hex(64).expect("host RNG must be available");
        assert_eq!(seed.len(), 64);
        assert!(seed.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(host_random_hex(0).is_err());
        assert!(host_random_hex(3).is_err());
    }

    // Fix 2 (fail-closed): an Err rejuvenation must tear the clone down and
    // propagate the error — never leave it live/ready.
    #[test]
    fn rejuvenation_failure_tears_down_and_errors() {
        let torn_down = Cell::new(false);
        let result = fail_closed_on_rejuvenation(
            Err(Error::agent("rejuvenate clone", "agent unreachable")),
            || torn_down.set(true),
        );
        assert!(result.is_err(), "a rejuvenation failure must fail the fork");
        assert!(
            torn_down.get(),
            "a rejuvenation failure must tear the clone down"
        );
    }

    // Success path: the clone is kept (no teardown) and the fork proceeds.
    #[test]
    fn rejuvenation_success_keeps_clone_live() {
        let torn_down = Cell::new(false);
        let result = fail_closed_on_rejuvenation(Ok(()), || torn_down.set(true));
        assert!(result.is_ok());
        assert!(
            !torn_down.get(),
            "a successful rejuvenation must not tear the clone down"
        );
    }
}
