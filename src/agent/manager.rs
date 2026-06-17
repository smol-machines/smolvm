//! Agent VM lifecycle management.
//!
//! The AgentManager is responsible for starting and stopping the agent VM,
//! which runs the smolvm-agent for OCI image management and command execution.

use crate::data::validate_vm_name;
use crate::error::{Error, Result};
use crate::process::{self, ChildProcess};
use crate::storage::{DiskFormat, OverlayDisk, StorageDisk};
use parking_lot::Mutex;
use smolvm_protocol::AGENT_READY_MARKER;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::launcher;
use super::{HostMount, PortMapping, VmResources};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Timeout for the agent to become ready after starting.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(30);

// Re-use shared polling constants from process module.
use crate::process::FAST_POLL_INTERVAL;

/// Timeout for agent to stop gracefully before force kill.
/// Reduced from 5s - VMs typically exit within 100ms after shutdown signal.
const AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout when waiting for agent to stop.
const WAIT_FOR_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Running VM configuration persisted to disk so new CLI invocations
/// can restore the actual config of a detached VM.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RunningVmConfig {
    /// Schema version for forward compatibility.
    #[serde(default = "RunningVmConfig::default_version")]
    version: u32,
    mounts: Vec<HostMount>,
    ports: Vec<PortMapping>,
    resources: VmResources,
}

impl RunningVmConfig {
    const CURRENT_VERSION: u32 = 1;

    fn default_version() -> u32 {
        1
    }
}

/// Whether the in-memory VM config is trustworthy.
#[derive(Debug, Clone)]
enum ConfigState {
    /// Config was never populated (fresh manager, no reconnect yet).
    Unknown,
    /// Config was set during VM start or restored from disk on reconnect.
    Known,
    /// Config file was missing or corrupt on reconnect — cannot trust defaults.
    LoadFailed(String),
}

/// State of the agent VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is not running.
    Stopped,
    /// Agent is starting up.
    Starting,
    /// Agent is running and ready.
    Running,
    /// Agent is shutting down.
    Stopping,
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Stopped => write!(f, "stopped"),
            AgentState::Starting => write!(f, "starting"),
            AgentState::Running => write!(f, "running"),
            AgentState::Stopping => write!(f, "stopping"),
        }
    }
}

/// Get the Docker config directory path.
///
/// Checks DOCKER_CONFIG environment variable first, then falls back to ~/.docker/
pub fn docker_config_dir() -> Option<PathBuf> {
    // Check DOCKER_CONFIG env var first
    if let Ok(docker_config) = std::env::var("DOCKER_CONFIG") {
        let path = PathBuf::from(docker_config);
        if path.exists() {
            return Some(path);
        }
        tracing::debug!(
            path = %path.display(),
            "DOCKER_CONFIG path does not exist"
        );
    }

    // Fall back to ~/.docker/
    if let Some(home) = dirs::home_dir() {
        let docker_dir = home.join(".docker");
        if docker_dir.exists() {
            return Some(docker_dir);
        }
    }

    None
}

/// Create a HostMount for Docker config directory.
///
/// Returns Some(mount) if the Docker config directory exists,
/// None otherwise.
pub fn docker_config_mount() -> Option<HostMount> {
    let docker_dir = docker_config_dir()?;

    tracing::info!(
        path = %docker_dir.display(),
        "mounting Docker config directory"
    );

    // Mount to /root/.docker which is where crane looks by default
    // Use read-only mount to prevent modification
    Some(HostMount {
        source: docker_dir,
        target: PathBuf::from("/root/.docker"),
        read_only: true,
    })
}

/// Internal state shared between threads.
struct AgentInner {
    state: AgentState,
    /// Child process (if running).
    child: Option<ChildProcess>,
    /// Currently configured mounts.
    mounts: Vec<HostMount>,
    /// Currently configured port mappings.
    ports: Vec<PortMapping>,
    /// Currently configured VM resources.
    resources: VmResources,
    /// Whether the in-memory config is trustworthy.
    config_state: ConfigState,
    /// If true, the agent has been detached and should not be stopped on drop.
    detached: bool,
    /// Held while the VM is running. Released on stop/Drop to allow other
    /// processes to start the VM. The kernel releases the lock automatically
    /// if the process crashes.
    #[cfg(unix)]
    vm_lock_handle: Option<std::fs::File>,
}

/// Get the data directory for a named VM.
///
/// Uses a fixed-length hash of the name as the directory name so the socket
/// path length is constant regardless of the name. This lets us support
/// arbitrary-length VM names portably across hosts — the kernel's
/// `sockaddr_un.sun_path` limit (~104 bytes) applies to the full socket
/// path, and a 16-char hash keeps that path bounded.
///
/// Layout: `<cache_dir>/smolvm/vms/<hash16>/`
///   - `<hash16>` = first 16 hex chars (8 bytes) of SHA-256 of the name
///   - A plaintext `name` file inside the directory records the original
///     name. This is load-bearing: [`ensure_vm_dir`] reads it to detect
///     hash collisions. External tooling can use it for debugging too.
///
/// **No legacy fallback, no migration**: smolvm is alpha. VMs created under
/// any older layout scheme are not readable by this version — users recreate
/// them. Dual-path support would silently expire VMs when their legacy
/// name-path exceeds the kernel socket budget, so we don't offer it.
pub fn vm_data_dir(name: &str) -> PathBuf {
    vm_cache_root().join(vm_dir_hash(name))
}

/// Resolve the on-disk image for a `.raw` disk filename in `dir`. A fork clone
/// has a `.qcow2` copy-on-write overlay in place of the raw disk, so prefer that
/// when present; otherwise fall back to the raw disk. The file on disk is the
/// single source of truth for the format (no format is stored in the record).
pub fn resolve_disk_image(dir: &Path, raw_filename: &str) -> (PathBuf, DiskFormat) {
    let qcow2 = dir.join(Path::new(raw_filename).with_extension("qcow2"));
    if qcow2.exists() {
        (qcow2, DiskFormat::Qcow2)
    } else {
        (dir.join(raw_filename), DiskFormat::Raw)
    }
}

/// Per-machine extraction directory for a `.smolmachine` bundle's OCI layers.
///
/// Unlike the shared content-addressed pack cache (`smolvm-pack/<checksum>`),
/// this lives *under* the machine's own [`vm_data_dir`], which means:
/// - it is reclaimed for free when the data dir is removed on delete;
/// - it is outside `pack prune`'s scope (never reaped while the machine exists);
/// - the macOS case-sensitive layers volume is owned 1:1 by the machine, so the
///   stop/delete paths can detach it unconditionally with no co-tenant risk.
///
/// The subdir is `pack` (deliberately not `layers`) so it cannot collide with
/// the `layers/` subtree that `extract_sidecar` creates *inside* this directory.
pub fn machine_layers_cache_dir(name: &str) -> PathBuf {
    vm_data_dir(name).join("pack")
}

/// Cache root: `<cache_dir>/smolvm/vms/`.
pub fn vm_cache_root() -> PathBuf {
    dirs::cache_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("smolvm")
        .join("vms")
}

/// Compute the 16-hex-char directory name for a VM.
///
/// Uses SHA-256 truncated to 8 bytes. The specific hash function doesn't
/// matter much — we need stability (same input → same output across runs
/// and hosts) and collision resistance; SHA-256 was already in the dep
/// tree via smolvm-pack and smolvm-registry.
///
/// **Threat model**: 8 bytes = 64 bits. Accidental collisions among
/// non-adversarial names become likely around 2^32 distinct VMs — not a
/// concern. Adversarial collisions (an attacker picking a name that
/// hashes to the same directory as an existing VM) take ~2^32 work, a
/// few hours on a laptop. This is acceptable for single-user smolvm. A
/// future multi-tenant deployment (smolfleet) should add per-tenant
/// namespacing or a longer hash.
pub fn vm_dir_hash(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(name.as_bytes());
    hex::encode(&digest[..8])
}

/// Create the VM data directory and commit the `name → hash` binding.
///
/// Writes (or verifies) a plaintext `name` file inside the hash directory.
/// The file is the ground truth for collision detection: if we open a hash
/// directory whose `name` file doesn't match the requested name, it means
/// two distinct VMs have hashed to the same directory — a hard error.
///
/// Returns the created/verified directory path.
///
/// Called from the same paths that create VM storage (manager construction,
/// agent launch setup). Safe to call repeatedly: the `name` file is written
/// once and verified on subsequent calls.
pub fn ensure_vm_dir(name: &str) -> std::io::Result<PathBuf> {
    ensure_vm_dir_at(&vm_data_dir(name), name)
}

/// Lower-level form of [`ensure_vm_dir`] that operates on an explicit
/// directory path. Factored out for testability — callers in production
/// should use [`ensure_vm_dir`].
pub fn ensure_vm_dir_at(dir: &std::path::Path, name: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;

    let name_file = dir.join("name");
    match std::fs::read_to_string(&name_file) {
        Ok(existing) if existing == name => {
            // Already committed — no-op.
        }
        Ok(existing) => {
            // Collision: the hash directory already belongs to a different
            // name. Refuse with a clear error; silent sharing would corrupt
            // both VMs' storage.
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "VM directory hash collision: requested name '{}' hashes \
                     to the same directory as existing VM '{}' at {}. \
                     Rename one of them.",
                    name,
                    existing.trim_end(),
                    dir.display(),
                ),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // First time — write the binding. Done once, never overwritten.
            std::fs::write(&name_file, name.as_bytes())?;
        }
        Err(e) => return Err(e),
    }
    Ok(dir.to_path_buf())
}

/// Agent VM manager.
///
/// Manages the lifecycle of the agent VM which handles OCI image operations
/// and command execution.
///
/// Each VM gets its own agent with isolated paths under
/// `~/.cache/smolvm/vms/{name}/` (socket, PID file, storage, overlay).
pub struct AgentManager {
    /// VM name (None only for low-level `new()` callers; CLI always sets a name).
    name: Option<String>,
    /// Path to the agent rootfs.
    rootfs_path: PathBuf,
    /// Storage disk for OCI layers.
    storage_disk: StorageDisk,
    /// Overlay disk for persistent rootfs changes.
    overlay_disk: OverlayDisk,
    /// vsock socket path for control channel.
    vsock_socket: PathBuf,
    /// PID file path for tracking the VM process across CLI invocations.
    pid_file: PathBuf,
    /// Config file path for persisting running VM config across CLI invocations.
    config_file: PathBuf,
    /// Console log path (optional).
    console_log: Option<PathBuf>,
    /// Startup error log path written by the child if machine launch fails before readiness
    startup_error_log: PathBuf,
    /// Per-VM lock file for cross-process coordination.
    ///
    /// Acquired with flock(LOCK_EX) before spawn and held through PID file
    /// write. Prevents two processes from starting the same VM simultaneously.
    /// The kernel releases the lock on process exit (crash-safe).
    #[cfg(unix)]
    vm_lock: PathBuf,
    /// Internal state.
    inner: Arc<Mutex<AgentInner>>,
}

impl AgentManager {
    /// Create a new agent manager with explicit paths (low-level).
    ///
    /// # Arguments
    ///
    /// * `rootfs_path` - Path to the agent VM rootfs
    /// * `storage_disk` - Storage disk for OCI layers
    /// * `overlay_disk` - Overlay disk for persistent rootfs changes
    pub fn new(
        rootfs_path: impl Into<PathBuf>,
        storage_disk: StorageDisk,
        overlay_disk: OverlayDisk,
    ) -> Result<Self> {
        Self::new_internal(None, rootfs_path.into(), storage_disk, overlay_disk)
    }

    /// Create a new agent manager for a named VM.
    ///
    /// Each named VM gets isolated paths for socket, storage, and logs.
    pub fn new_named(
        name: impl Into<String>,
        rootfs_path: impl Into<PathBuf>,
        storage_disk: StorageDisk,
        overlay_disk: OverlayDisk,
    ) -> Result<Self> {
        Self::new_internal(
            Some(name.into()),
            rootfs_path.into(),
            storage_disk,
            overlay_disk,
        )
    }

    /// Internal constructor.
    fn new_internal(
        name: Option<String>,
        rootfs_path: PathBuf,
        storage_disk: StorageDisk,
        overlay_disk: OverlayDisk,
    ) -> Result<Self> {
        if let Some(ref vm_name) = name {
            validate_vm_name(vm_name, "machine name")
                .map_err(|e| Error::config("validate machine name", e))?;
        }

        // Named VMs colocate runtime artifacts (sockets, logs, pid, config) in
        // their hash-derived data directory — matching where `storage_disk`
        // lives via `ensure_vm_dir` and what `vm_data_dir` / `machine data-dir`
        // report. Using the hash path bounds socket paths under the
        // `sockaddr_un.sun_path` budget (104 bytes macOS / 108 Linux) for any
        // VM name length.
        //
        // Unnamed VMs (ephemeral) don't have a data dir, so they fall back to
        // the platform runtime dir (`/run/user/<uid>/smolvm` on Linux,
        // `~/Library/Caches/smolvm` on macOS) — shared across ephemeral runs.
        let smolvm_runtime = if let Some(ref vm_name) = name {
            vm_data_dir(vm_name)
        } else {
            dirs::runtime_dir()
                .or_else(dirs::cache_dir)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("smolvm")
        };
        std::fs::create_dir_all(&smolvm_runtime)?;

        let vsock_socket = smolvm_runtime.join("agent.sock");
        let pid_file = smolvm_runtime.join("agent.pid");
        let config_file = smolvm_runtime.join("agent.config.json");
        let console_log = Some(smolvm_runtime.join("agent-console.log"));
        let startup_error_log: PathBuf = smolvm_runtime.join("agent-startup-error.log");
        #[cfg(unix)]
        let vm_lock = smolvm_runtime.join("vm.lock");

        Ok(Self {
            name,
            rootfs_path,
            storage_disk,
            overlay_disk,
            vsock_socket,
            pid_file,
            config_file,
            console_log,
            startup_error_log,
            #[cfg(unix)]
            vm_lock,
            inner: Arc::new(Mutex::new(AgentInner {
                state: AgentState::Stopped,
                child: None,
                mounts: Vec::new(),
                ports: Vec::new(),
                resources: VmResources::default(),
                config_state: ConfigState::Unknown,
                detached: false,
                #[cfg(unix)]
                vm_lock_handle: None,
            })),
        })
    }

    /// Get the default agent manager.
    ///
    /// Uses default paths for rootfs and storage.
    /// `storage_gb` and `overlay_gb` override the default disk sizes (20 GiB / 10 GiB).
    ///
    /// Canonicalized to `for_vm_with_sizes("default", ...)` so that all
    /// lifecycle commands (start/stop/exec/status) use consistent paths.
    pub fn new_default_with_sizes(
        storage_gb: Option<u64>,
        overlay_gb: Option<u64>,
    ) -> Result<Self> {
        Self::for_vm_with_sizes("default", storage_gb, overlay_gb)
    }

    /// Get the default agent manager with default sizes.
    ///
    /// Canonicalized to `for_vm("default")` so that all lifecycle commands
    /// use consistent socket/PID/storage paths.
    pub fn new_default() -> Result<Self> {
        Self::for_vm("default")
    }

    /// Get an agent manager for a named VM.
    ///
    /// Each named VM gets its own isolated storage and socket.
    /// `storage_gb` and `overlay_gb` override the default disk sizes (20 GiB / 10 GiB).
    pub fn for_vm_with_sizes(
        name: impl Into<String>,
        storage_gb: Option<u64>,
        overlay_gb: Option<u64>,
    ) -> Result<Self> {
        let name = name.into();
        let rootfs_path = Self::default_rootfs_path()?;
        let sg = storage_gb.unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GIB);
        let og = overlay_gb.unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GIB);

        // Named VMs get their own storage disk. `ensure_vm_dir` commits the
        // name→hash binding on first call and detects collisions on
        // subsequent calls (refusing to open a hash dir that belongs to a
        // different name).
        let storage_dir = ensure_vm_dir(&name)?;

        // A fork clone has a `.qcow2` copy-on-write overlay in place of the
        // `.raw` disk; detect it by file presence (the on-disk file is the
        // source of truth) and open it as-is rather than creating/formatting.
        let (storage_path, storage_format) =
            resolve_disk_image(&storage_dir, crate::storage::STORAGE_DISK_FILENAME);
        let storage_disk = match storage_format {
            DiskFormat::Qcow2 => {
                StorageDisk::open_existing_with_format(&storage_path, storage_format)?
            }
            // Fresh disk: prefer an instant qcow2 CoW overlay over the template
            // (Linux, default size) instead of a raw copy, to avoid per-boot
            // host-disk thrash under concurrency. Falls back to raw otherwise.
            DiskFormat::Raw => StorageDisk::open_or_overlay_at(&storage_path, sg)?,
        };

        let (overlay_path, overlay_format) =
            resolve_disk_image(&storage_dir, crate::storage::OVERLAY_DISK_FILENAME);
        let overlay_disk = match overlay_format {
            DiskFormat::Qcow2 => {
                OverlayDisk::open_existing_with_format(&overlay_path, overlay_format)?
            }
            DiskFormat::Raw => OverlayDisk::open_or_overlay_at(&overlay_path, og)?,
        };

        Self::new_named(name, rootfs_path, storage_disk, overlay_disk)
    }

    /// Get an agent manager for a named VM with default sizes.
    pub fn for_vm(name: impl Into<String>) -> Result<Self> {
        Self::for_vm_with_sizes(name, None, None)
    }

    /// Get the VM name if this is a named agent.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Names of VMs forked from this one. Their block disks are copy-on-write
    /// overlays backed by this VM's disks, so it must not be re-launched with
    /// writable disks while they exist. Best-effort: on a registry read error,
    /// returns empty rather than blocking the launch.
    fn dependent_clones(&self) -> Vec<String> {
        let Some(name) = self.name() else {
            return Vec::new(); // the unnamed/default manager is never a fork base
        };
        match crate::db::SmolvmDb::open().and_then(|db| db.dependent_clones(name)) {
            Ok(clones) => clones,
            Err(e) => {
                tracing::warn!(vm = name, error = %e, "could not check for dependent clones");
                Vec::new()
            }
        }
    }

    /// Get the default path for the agent rootfs.
    ///
    /// Checks `SMOLVM_AGENT_ROOTFS` env var first, then falls back to the
    /// platform data directory (`~/.local/share/smolvm/agent-rootfs` on Linux,
    /// `~/Library/Application Support/smolvm/agent-rootfs` on macOS).
    pub fn default_rootfs_path() -> Result<PathBuf> {
        if let Ok(path) = std::env::var("SMOLVM_AGENT_ROOTFS") {
            return Ok(PathBuf::from(path));
        }

        // SDKs bundle the rootfs as a tarball (they can't ship a dir tree with
        // symlinks/modes through a wheel) and point us at it. Extract it once to a
        // cache dir and use that, so `npm i` / `pip install` is self-contained
        // with no separate engine install. Re-extracts when the tarball changes
        // (a new SDK version ships a newer agent).
        if let Some(tar) = std::env::var_os("SMOLVM_AGENT_ROOTFS_TAR") {
            return Self::ensure_extracted_rootfs(Path::new(&tar));
        }

        let data_dir = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| Error::storage("resolve path", "could not determine data directory"))?;

        Ok(data_dir.join("smolvm").join("agent-rootfs"))
    }

    /// Extract a bundled agent-rootfs tarball to a cache dir (idempotent) and
    /// return that dir. Keyed by the tarball's size+mtime so a newer SDK build
    /// re-extracts; extraction is staged in a temp dir then atomically renamed so
    /// concurrent SDK processes never see a half-extracted rootfs.
    fn ensure_extracted_rootfs(tar: &Path) -> Result<PathBuf> {
        let meta =
            std::fs::metadata(tar).map_err(|e| Error::storage("stat rootfs tar", e.to_string()))?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = format!("{:x}-{:x}", meta.len(), mtime);

        let base = dirs::cache_dir()
            .ok_or_else(|| Error::storage("resolve cache dir", "no cache directory"))?
            .join("smolvm")
            .join("rootfs");
        let dest = base.join(&key);
        if dest.join(".extracted").exists() {
            return Ok(dest);
        }

        std::fs::create_dir_all(&base)
            .map_err(|e| Error::storage("create rootfs cache", e.to_string()))?;
        let tmp = base.join(format!(".tmp-{}-{}", std::process::id(), key));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)
            .map_err(|e| Error::storage("create rootfs staging", e.to_string()))?;

        // Use the system `tar` — it preserves symlinks (e.g. /sbin/init) and modes
        // (the executable agent), which the tar crate handling here would not need
        // to reimplement. Extraction runs on the host before VM boot (unsandboxed).
        let status = std::process::Command::new("tar")
            .arg("-xpf")
            .arg(tar)
            .arg("-C")
            .arg(&tmp)
            .status()
            .map_err(|e| Error::storage("extract rootfs tar", e.to_string()))?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(Error::storage(
                "extract rootfs tar",
                format!("tar exited with {status}"),
            ));
        }
        let _ = std::fs::write(tmp.join(".extracted"), b"");
        // Atomic publish; if another process won the race, just use theirs.
        match std::fs::rename(&tmp, &dest) {
            Ok(()) => {}
            Err(_) if dest.join(".extracted").exists() => {
                let _ = std::fs::remove_dir_all(&tmp);
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err(Error::storage("publish extracted rootfs", e.to_string()));
            }
        }
        Ok(dest)
    }

    /// Get the current state of the agent.
    pub fn state(&self) -> AgentState {
        self.inner.lock().state
    }

    /// Check if the agent is running.
    pub fn is_running(&self) -> bool {
        self.state() == AgentState::Running
    }

    /// If cached state is Running but the process is not actually alive,
    /// reset to Stopped so that start paths can proceed. This handles the
    /// case where a VM crashed without going through `stop()`.
    fn reset_stale_running_state(&self) {
        let mut inner = self.inner.lock();
        if inner.state == AgentState::Running && !self.is_process_alive_inner(&inner) {
            tracing::info!("resetting stale Running state to Stopped (VM process is dead)");
            inner.state = AgentState::Stopped;
            inner.child = None;
            #[cfg(unix)]
            {
                inner.vm_lock_handle = None;
            }
        }
    }

    /// Force the in-memory state back to `Stopped` and release the per-VM lock,
    /// after the VM process has already been stopped out-of-band (the HTTP stop
    /// path kills the recorded PID directly rather than via this manager).
    ///
    /// The serve process holds the `vm.lock` flock for the lifetime of the
    /// registry's `AgentManager`; if `vm_lock_handle` is not dropped here, the
    /// serve process keeps holding the lock and a subsequent start fails to
    /// re-acquire it ("another process is already starting or running this VM").
    /// Only call once the process is confirmed dead.
    pub fn mark_stopped(&self) {
        let mut inner = self.inner.lock();
        inner.state = AgentState::Stopped;
        inner.child = None;
        #[cfg(unix)]
        {
            inner.vm_lock_handle = None;
        }
    }

    /// Return consistent (state, pid) for API status responses.
    ///
    /// Clears the PID when effective state is `Stopped`, so clients never
    /// see a stale PID paired with a stopped state.
    pub fn effective_status(&self) -> (AgentState, Option<i32>) {
        let inner = self.inner.lock();
        let state = if inner.state == AgentState::Running && !self.is_process_alive_inner(&inner) {
            AgentState::Stopped
        } else {
            inner.state
        };
        let pid = if state == AgentState::Stopped {
            None
        } else {
            inner.child.as_ref().map(|c| c.pid())
        };
        (state, pid)
    }

    /// Get the vsock socket path.
    pub fn vsock_socket(&self) -> &Path {
        &self.vsock_socket
    }

    /// Get the console log path.
    pub fn console_log(&self) -> Option<&Path> {
        self.console_log.as_deref()
    }

    /// Get the storage disk path.
    pub fn storage_path(&self) -> &Path {
        self.storage_disk.path()
    }

    /// Get the overlay disk path.
    pub fn overlay_path(&self) -> &Path {
        self.overlay_disk.path()
    }

    /// Check if an agent is already running (socket exists + responds to ping).
    ///
    /// Returns Some(()) if agent is running and reachable, None otherwise.
    /// This also updates the internal state to Running if successful.
    pub fn try_connect_existing(&self) -> Option<()> {
        self.try_connect_existing_with_pid(None)
    }

    /// Try to reconnect to an existing agent with a known PID.
    ///
    /// If the PID is provided and the process is alive, sets the child process.
    /// Falls back to reading the PID file if no PID is provided.
    /// Returns Some(()) if agent is running and reachable, None otherwise.
    pub fn try_connect_existing_with_pid(&self, pid: Option<i32>) -> Option<()> {
        self.try_connect_existing_with_pid_and_start_time(pid, None)
    }

    /// Try to reconnect to an existing agent with a known PID and expected start time.
    ///
    /// The `expected_start_time` is the start time stored when the VM was originally
    /// launched. If provided, it is used to verify the PID hasn't been recycled by the OS.
    pub fn try_connect_existing_with_pid_and_start_time(
        &self,
        pid: Option<i32>,
        expected_start_time: Option<u64>,
    ) -> Option<()> {
        if !self.vsock_socket.exists() {
            return None;
        }

        // Resolve PID and start time.
        // If caller provides expected_start_time, use it (DB source of truth).
        // Otherwise fall back to PID file which stores both PID and start time.
        let (effective_pid, pid_start_time) = if let Some(p) = pid {
            (
                Some(p),
                expected_start_time.or_else(|| {
                    // Caller didn't provide start time — try PID file as fallback
                    self.read_pid_file_with_start_time()
                        .and_then(|(file_pid, st)| if file_pid == p { st } else { None })
                }),
            )
        } else {
            match self.read_pid_file_with_start_time() {
                Some((p, st)) => (Some(p), st),
                None => (None, None),
            }
        };

        // Try to ping the agent
        if let Ok(mut client) = super::AgentClient::connect(&self.vsock_socket) {
            if client.ping().is_ok() {
                // Update internal state to reflect running
                let mut inner = self.inner.lock();
                inner.state = AgentState::Running;
                // Only store child PID if identity is verified via start time.
                // Without verification, stop() could signal the wrong process.
                if let Some(p) = effective_pid {
                    if process::is_our_process_strict(p, pid_start_time) {
                        inner.child = Some(ChildProcess::new(p));
                    } else {
                        tracing::debug!(
                            pid = p,
                            "skipping child PID storage: identity not verified"
                        );
                    }
                }
                // Restore the running VM config from disk so that
                // ensure_running_with_full_config can accurately compare
                // the requested config against the actual running config.
                if matches!(inner.config_state, ConfigState::Unknown) {
                    match self.load_running_config() {
                        Ok(config) => {
                            inner.mounts = config.mounts;
                            inner.ports = config.ports;
                            inner.resources = config.resources;
                            inner.config_state = ConfigState::Known;
                        }
                        Err(reason) => {
                            tracing::warn!(
                                reason = %reason,
                                "could not restore running VM config; \
                                 config changes will force restart"
                            );
                            inner.config_state = ConfigState::LoadFailed(reason);
                        }
                    }
                }
                return Some(());
            }
        }

        None
    }

    /// Read PID and start time from the PID file.
    fn read_pid_file_with_start_time(&self) -> Option<(i32, Option<u64>)> {
        let content = std::fs::read_to_string(&self.pid_file).ok()?;
        let mut lines = content.lines();
        let pid = lines.next()?.trim().parse::<i32>().ok()?;
        let start_time = lines.next().and_then(|s| s.trim().parse::<u64>().ok());
        Some((pid, start_time))
    }

    /// Save the running VM config to disk so future CLI invocations can
    /// restore the actual config of a detached VM on reconnect.
    ///
    /// Uses atomic write (tmp + rename) to avoid partial/corrupt reads.
    fn save_running_config(
        &self,
        mounts: &[HostMount],
        ports: &[PortMapping],
        resources: &VmResources,
    ) {
        let config = RunningVmConfig {
            version: RunningVmConfig::CURRENT_VERSION,
            mounts: mounts.to_vec(),
            ports: ports.to_vec(),
            resources: resources.clone(),
        };
        match serde_json::to_string(&config) {
            Ok(json) => {
                let tmp = self.config_file.with_extension("json.tmp");
                if let Err(e) = std::fs::write(&tmp, &json) {
                    tracing::warn!(error = %e, "failed to write VM config tmp file");
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, &self.config_file) {
                    tracing::warn!(error = %e, "failed to rename VM config file");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize VM config");
            }
        }
    }

    /// Load the running VM config from disk.
    ///
    /// Returns an error string describing why the load failed, so callers
    /// can log it and treat the config as unknown (fail-closed).
    fn load_running_config(&self) -> std::result::Result<RunningVmConfig, String> {
        let content = std::fs::read_to_string(&self.config_file)
            .map_err(|e| format!("config file {}: {}", self.config_file.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("invalid JSON in {}: {}", self.config_file.display(), e))
    }

    /// Get the child PID if known.
    pub fn child_pid(&self) -> Option<i32> {
        self.inner.lock().child.as_ref().map(|c| c.pid())
    }

    /// Get the VM process ID and its captured start time for verified external cleanup.
    ///
    /// Prefers the in-memory child handle (start time captured at spawn).
    /// Falls back to the PID file if no in-memory handle is present.
    /// Returns `None` if neither source has a PID.
    pub fn pid_and_start_time(&self) -> Option<(i32, Option<u64>)> {
        {
            let inner = self.inner.lock();
            if let Some(child) = &inner.child {
                return Some((child.pid(), child.start_time()));
            }
        }
        self.read_pid_file_with_start_time()
    }

    /// Check if the VM process is actually alive using start-time-aware
    /// verification.
    ///
    /// Checks in-memory child handle first, then falls back to PID file.
    /// Returns `false` when neither source provides a PID (fail-closed).
    /// Uses `is_our_process` (lenient) so that a live process without
    /// start-time data is assumed to be ours rather than silently ignored.
    pub fn is_process_alive(&self) -> bool {
        let inner = self.inner.lock();
        self.is_process_alive_inner(&inner)
    }

    /// Inner liveness check that accepts a lock guard to avoid double-locking.
    fn is_process_alive_inner(&self, inner: &AgentInner) -> bool {
        // Try in-memory child handle first (has stored start time)
        if let Some(child) = inner.child.as_ref() {
            return crate::process::is_our_process(child.pid(), child.start_time());
        }

        // Fall back to PID file (covers orphan/reconnect paths)
        if let Some((pid, start_time)) = self.read_pid_file_with_start_time() {
            return crate::process::is_our_process(pid, start_time);
        }

        // No PID source — fail closed
        false
    }

    /// Connect to the running agent and return a client.
    ///
    /// Uses retry logic to handle transient connection failures.
    pub fn connect(&self) -> crate::error::Result<super::AgentClient> {
        super::AgentClient::connect_with_retry(&self.vsock_socket)
    }

    /// Get the currently configured mounts.
    pub fn mounts(&self) -> Vec<HostMount> {
        self.inner.lock().mounts.clone()
    }

    /// Check if the given mounts match the currently running agent's mounts.
    pub fn mounts_match(&self, mounts: &[HostMount]) -> bool {
        let inner = self.inner.lock();
        inner.mounts == mounts
    }

    /// Check if the given resources match the currently running agent's resources.
    pub fn resources_match(&self, resources: VmResources) -> bool {
        let inner = self.inner.lock();
        inner.resources == resources
    }

    /// Check if the given port mappings match the currently running agent's ports.
    pub fn ports_match(&self, ports: &[PortMapping]) -> bool {
        let inner = self.inner.lock();
        inner.ports == ports
    }

    /// Ensure the agent is running with the specified mounts.
    ///
    /// If the agent is running with different mounts, it will be restarted.
    pub fn ensure_running_with_mounts(&self, mounts: Vec<HostMount>) -> Result<bool> {
        self.ensure_running_with_full_config(
            mounts,
            Vec::new(),
            VmResources::default(),
            Default::default(),
        )
    }

    /// Ensure the agent is running with the specified mounts and resources.
    ///
    /// If the agent is running with different mounts or resources, it will be restarted.
    pub fn ensure_running_with_config(
        &self,
        mounts: Vec<HostMount>,
        resources: VmResources,
    ) -> Result<bool> {
        self.ensure_running_with_full_config(mounts, Vec::new(), resources, Default::default())
    }

    /// Re-attach this machine's pre-extracted packed layers if the caller did
    /// not already wire them.
    ///
    /// The implicit-start preflight (`ensure_machine_running`) passes
    /// `default()` features when the VM is already up, to skip the macOS hdiutil
    /// mount on the exec hot path. If that preflight then detects a config
    /// change and restarts, the relaunch would otherwise drop the packed layers
    /// and the guest would fall back to a registry pull (broken offline). The
    /// layers are discoverable from the machine name alone — derive the
    /// per-machine directory, re-acquire the lease, and set `packed_layers_dir`.
    /// A no-op when layers are already wired (an explicit-start path set
    /// `packed_layers_dir` and its mount is still live), when this is not a named
    /// machine, or when nothing was extracted (image/registry-sourced machine).
    /// macOS mount cost only; a compile-time no-op on Linux.
    fn rewire_packed_layers_if_extracted(
        &self,
        features: &mut launcher::LaunchFeatures,
    ) -> Result<()> {
        if features.packed_layers_dir.is_some() {
            return Ok(());
        }
        let Some(name) = self.name.as_deref() else {
            return Ok(());
        };
        let cache_dir = machine_layers_cache_dir(name);
        if !smolvm_pack::extract::is_extracted(&cache_dir) {
            return Ok(());
        }
        // This runs only on the relaunch path, after stop()/reset_stale_running_state,
        // so no live VM is using the volume. The original start leaked a lease to keep
        // it mounted; drop that stale mount (and its lease files) before acquiring a
        // fresh one, so a config-change restart doesn't stack a second lease/mount on
        // the first. Gated by the same conditions as the re-acquire below, so the
        // explicit-start paths (features already `Some`, mount still live) return
        // early above and never detach. macOS hdiutil detach; a no-op on Linux.
        smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
        match smolvm_pack::extract::acquire_layers_lease(&cache_dir, false) {
            Ok(lease) => {
                features.packed_layers_dir = Some(lease.path.clone());
                // Keep the volume mounted for the VM's lifetime; the stop/delete
                // handlers detach it (see `machine_layers_cache_dir`).
                std::mem::forget(lease);
            }
            Err(e) => {
                return Err(Error::agent("re-attach packed layers", e.to_string()));
            }
        }
        Ok(())
    }

    /// Ensure the agent is running with the specified mounts, ports, and resources.
    ///
    /// If the agent is running with different configuration, it will be restarted.
    /// Returns `true` if the VM was freshly started/restarted, `false` if reused.
    pub fn ensure_running_with_full_config(
        &self,
        mounts: Vec<HostMount>,
        ports: Vec<PortMapping>,
        resources: VmResources,
        mut features: launcher::LaunchFeatures,
    ) -> Result<bool> {
        // Check if agent is already running with the same configuration.
        // try_connect_existing restores config from disk on reconnect,
        // so the comparison below is accurate even for detached VMs.
        if self.try_connect_existing().is_some() {
            let inner = self.inner.lock();
            match &inner.config_state {
                ConfigState::Known => {
                    if inner.mounts == mounts
                        && inner.ports == ports
                        && inner.resources == resources
                    {
                        return Ok(false);
                    }
                    // Config is known but doesn't match — fall through to restart.
                }
                ConfigState::LoadFailed(reason) => {
                    // Fail-closed: cannot verify running config matches requested,
                    // so force restart to ensure correct isolation/network settings.
                    tracing::info!(
                        reason = %reason,
                        "forcing VM restart: running config unknown"
                    );
                }
                ConfigState::Unknown => {
                    // This shouldn't happen (try_connect_existing always resolves
                    // Unknown to Known or LoadFailed), but fail-closed just in case.
                    tracing::info!("forcing VM restart: config state still unknown");
                }
            }
        }

        // If running with different/unknown config, we need to restart
        let needs_restart = {
            let inner = self.inner.lock();
            inner.state == AgentState::Running
        };

        if needs_restart {
            tracing::info!("restarting agent VM due to configuration change");
            self.stop()?;
        } else {
            // try_connect_existing failed but state may still be Running (crashed VM).
            // Reset to Stopped so start_with_full_config can proceed.
            self.reset_stale_running_state();
        }

        // Re-attach packed layers if a config-change restart dropped them
        // (see `rewire_packed_layers_if_extracted`).
        self.rewire_packed_layers_if_extracted(&mut features)?;

        // Start with new config
        self.start_with_full_config(mounts, ports, resources, features)?;
        Ok(true)
    }

    /// Ensure the agent is running.
    ///
    /// If the agent is not running, this starts it.
    /// If the agent is already running, this is a no-op.
    /// Returns `true` if the VM was freshly started, `false` if reused.
    pub fn ensure_running(&self) -> Result<bool> {
        // First, check if an agent is already running (from a previous invocation)
        if self.try_connect_existing().is_some() {
            return Ok(false);
        }

        // try_connect_existing failed — if state is stale Running (crashed VM),
        // reset to Stopped so we can start fresh.
        self.reset_stale_running_state();

        // Check internal state
        let state = self.state();

        match state {
            AgentState::Running => Ok(false), // shouldn't reach here after reset, but safe
            AgentState::Starting => {
                self.wait_for_ready()?;
                Ok(true)
            }
            AgentState::Stopped => {
                self.start()?;
                Ok(true)
            }
            AgentState::Stopping => {
                self.wait_for_stop()?;
                self.start()?;
                Ok(true)
            }
        }
    }

    /// Start the agent VM.
    pub fn start(&self) -> Result<()> {
        self.start_with_full_config(
            Vec::new(),
            Vec::new(),
            VmResources::default(),
            Default::default(),
        )
    }

    /// Start the agent VM with specified mounts.
    pub fn start_with_mounts(&self, mounts: Vec<HostMount>) -> Result<()> {
        self.start_with_full_config(
            mounts,
            Vec::new(),
            VmResources::default(),
            Default::default(),
        )
    }

    /// Start the agent VM with specified mounts and resources.
    pub fn start_with_config(&self, mounts: Vec<HostMount>, resources: VmResources) -> Result<()> {
        self.start_with_full_config(mounts, Vec::new(), resources, Default::default())
    }

    /// Common pre-launch setup: validate state, pre-format disks, clean markers.
    ///
    /// Called by both `start_with_full_config` (fork) and `start_via_subprocess`.
    /// Sets internal state to `Starting` and stores config. Returns error if
    /// the agent is not in the `Stopped` state.
    fn prepare_for_launch(
        &self,
        mounts: &[HostMount],
        ports: &[PortMapping],
        resources: VmResources,
    ) -> Result<()> {
        // Refuse to (re)launch a fork base while clones depend on it. Clones
        // CoW-read this VM's disks by path; re-running it would reopen them
        // writable and silently corrupt every clone. Clones don't need the base
        // process alive, so refusing is safe — delete the clones first to reuse
        // the name. Covers every launch path (CLI fork + subprocess) since both
        // funnel through here.
        let clones = self.dependent_clones();
        if !clones.is_empty() {
            return Err(Error::agent(
                "start agent",
                format!(
                    "'{}' is a fork base for {} live clone(s) ({}); their disks are \
                     copy-on-write overlays backed by its disks, so it cannot be \
                     re-launched while they exist — delete the clones first",
                    self.name().unwrap_or_default(),
                    clones.len(),
                    clones.join(", ")
                ),
            ));
        }

        // Validate resources before doing anything else.
        resources.validate()?;

        // Acquire the per-VM file lock BEFORE checking state. This serializes
        // concurrent start attempts across OS processes. The lock is held
        // until stop/Drop releases it. If another process already holds the
        // lock (VM is running), we block briefly then re-check state.
        #[cfg(unix)]
        let lock_handle = {
            use std::os::unix::io::AsRawFd;
            let lock_file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&self.vm_lock)
                .map_err(|e| Error::agent("acquire VM lock", e.to_string()))?;
            let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    return Err(Error::agent(
                        "start agent",
                        "another process is already starting or running this VM",
                    ));
                }
                return Err(Error::agent("acquire VM lock", err.to_string()));
            }
            lock_file
        };

        // Check and update state
        {
            let mut inner = self.inner.lock();
            if inner.state != AgentState::Stopped {
                return Err(Error::agent(
                    "start agent",
                    "agent already starting or running",
                ));
            }
            inner.state = AgentState::Starting;
            inner.mounts = mounts.to_vec();
            inner.ports = ports.to_vec();
            inner.resources = resources;
            inner.config_state = ConfigState::Known;
            #[cfg(unix)]
            {
                inner.vm_lock_handle = Some(lock_handle);
            }
        }

        tracing::info!(
            rootfs = %self.rootfs_path.display(),
            storage = %self.storage_disk.path().display(),
            socket = %self.vsock_socket.display(),
            mount_count = mounts.len(),
            "preparing agent VM launch"
        );

        // Check KVM availability on Linux
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = crate::platform::linux::check_kvm_available() {
                let mut inner = self.inner.lock();
                inner.state = AgentState::Stopped;
                return Err(e);
            }
        }

        // Validate rootfs exists
        if !self.rootfs_path.exists() {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopped;
            return Err(Error::agent(
                "verify rootfs",
                format!("agent rootfs not found: {}", self.rootfs_path.display()),
            ));
        }

        // Pre-format storage and overlay disks in parallel
        {
            let storage_disk = &self.storage_disk;
            let overlay_disk = &self.overlay_disk;
            std::thread::scope(|s| {
                let storage_handle = s.spawn(|| storage_disk.ensure_formatted());
                let overlay_result = overlay_disk.ensure_formatted();
                if let Err(e) = storage_handle.join().unwrap_or_else(|_| {
                    Err(crate::Error::storage("format storage", "thread panicked"))
                }) {
                    tracing::warn!(
                        error = %e,
                        "failed to pre-format disk on host"
                    );
                }
                if let Err(e) = overlay_result {
                    tracing::warn!(
                        error = %e,
                        "failed to pre-format overlay disk on host"
                    );
                }
            });
        }

        // Clean up old socket and stale markers
        let _ = std::fs::remove_file(&self.vsock_socket);
        let ready_marker = self.rootfs_path.join(AGENT_READY_MARKER);
        let _ = std::fs::remove_file(&ready_marker);
        let _ = std::fs::remove_file(&self.startup_error_log);

        Ok(())
    }

    /// Common post-launch bookkeeping: store child PID, write config/PID files,
    /// wait for agent ready.
    ///
    /// Called by both `start_with_full_config` (fork) and `start_via_subprocess`.
    fn finalize_launch(
        &self,
        child_pid: i32,
        mounts: &[HostMount],
        ports: &[PortMapping],
        resources: &VmResources,
    ) -> Result<()> {
        let boot_start = std::time::Instant::now();

        // Store child process handle
        {
            let mut inner = self.inner.lock();
            inner.child = Some(ChildProcess::new(child_pid));
        }

        // Write running config (for future CLI invocations to detect config changes)
        self.save_running_config(mounts, ports, resources);

        // Write PID file with start time for PID reuse detection
        let pid_content = match process::process_start_time(child_pid) {
            Some(t) => format!("{}\n{}", child_pid, t),
            None => child_pid.to_string(),
        };
        if let Err(e) = std::fs::write(&self.pid_file, pid_content) {
            tracing::warn!(error = %e, "failed to write PID file");
        }

        // Wait for the agent to be ready
        match self.wait_for_ready() {
            Ok(_) => {
                let mut inner = self.inner.lock();
                inner.state = AgentState::Running;
                let boot_secs = boot_start.elapsed().as_secs_f64();
                metrics::histogram!("smolvm_vm_boot_seconds").record(boot_secs);
                metrics::gauge!("smolvm_machines_running").increment(1.0);
                tracing::info!(
                    pid = child_pid,
                    boot_ms = boot_secs * 1000.0,
                    "agent VM is ready"
                );
                Ok(())
            }
            Err(e) => {
                process::terminate(child_pid);
                let mut inner = self.inner.lock();
                inner.state = AgentState::Stopped;
                inner.child = None;
                #[cfg(unix)]
                {
                    inner.vm_lock_handle = None;
                }
                Err(e)
            }
        }
    }

    /// Start the agent VM with specified mounts, ports, and resources.
    ///
    /// Spawns a fresh subprocess (`smolvm _boot-vm`) via `posix_spawn` to run
    /// the VM. This gives the child a completely clean process with no inherited
    /// Hypervisor.framework state, preventing VM context leaks when the child
    /// crashes (e.g., during GPU device setup).
    ///
    /// Previously used `fork()` which inherited parent state and caused
    /// unreliable GPU launches on macOS.
    pub fn start_with_full_config(
        &self,
        mounts: Vec<HostMount>,
        ports: Vec<PortMapping>,
        resources: VmResources,
        features: launcher::LaunchFeatures,
    ) -> Result<()> {
        // Delegate to subprocess launch — safe for both single-threaded (CLI)
        // and multi-threaded (API server) callers. Required for GPU support
        // (Hypervisor.framework detects forked multi-threaded state).
        self.start_via_subprocess(mounts, ports, resources, features)
    }

    /// Start the VM by spawning a fresh subprocess instead of fork().
    ///
    /// On macOS, fork() in a multi-threaded process (e.g., from within the
    /// tokio-based API server) creates unstable children: Apple frameworks
    /// like Hypervisor.framework detect the forked multi-threaded state and
    /// abort the child ~2 seconds after boot.
    ///
    /// This method avoids fork entirely by spawning a fresh `smolvm _boot-vm`
    /// process via `Command::new()` (which uses `posix_spawn` on macOS).
    /// The subprocess is single-threaded and runs `krun_start_enter` safely.
    pub fn start_via_subprocess(
        &self,
        mounts: Vec<HostMount>,
        ports: Vec<PortMapping>,
        resources: VmResources,
        features: launcher::LaunchFeatures,
    ) -> Result<()> {
        use super::boot_config::BootConfig;

        let t_launch = Instant::now();

        let resources_for_config = resources.clone();
        // Bound concurrent disk-prep across ALL boot paths (this is the chokepoint
        // they share): unbounded parallel template copies thrash the host disk so
        // each balloons (3.8s → 50s under ~13 concurrent boots) and the start
        // times out. The permit is held only across `prepare_for_launch` (the disk
        // copy), then released before the VMM spawn. Process-wide; tune with
        // SMOLVM_BOOT_CONCURRENCY.
        {
            let _boot_permit = crate::process::acquire_boot_permit();
            self.prepare_for_launch(&mounts, &ports, resources)?;
        }
        tracing::info!(
            elapsed_ms = t_launch.elapsed().as_millis(),
            "boot: disks ready"
        );

        let storage_size_gb = resources_for_config
            .storage_gib
            .unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GIB);
        let overlay_size_gb = resources_for_config
            .overlay_gib
            .unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GIB);

        // Write boot config to a file the subprocess will read
        let config = BootConfig {
            rootfs_path: self.rootfs_path.clone(),
            storage_disk_path: self.storage_disk.path().to_path_buf(),
            overlay_disk_path: self.overlay_disk.path().to_path_buf(),
            vsock_socket: self.vsock_socket.clone(),
            console_log: self.console_log.clone(),
            startup_error_log: self.startup_error_log.clone(),
            storage_size_gb,
            overlay_size_gb,
            mounts: mounts.clone(),
            ports: ports.clone(),
            resources: resources_for_config.clone(),
            ssh_agent_socket: features.ssh_agent_socket,
            dns_filter_hosts: features.dns_filter_hosts,
            packed_layers_dir: features.packed_layers_dir,
            extra_disks: features.extra_disks,
        };
        let config_path = self
            .storage_disk
            .path()
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/tmp"))
            .join("boot-config.json");
        let config_json = serde_json::to_vec(&config)
            .map_err(|e| Error::agent("serialize boot config", e.to_string()))?;
        std::fs::write(&config_path, &config_json)
            .map_err(|e| Error::agent("write boot config", e.to_string()))?;
        tracing::info!(
            elapsed_ms = t_launch.elapsed().as_millis(),
            "boot: config written"
        );

        // Spawn fresh subprocess (posix_spawn on macOS — safe for multi-threaded parents)
        let exe = std::env::current_exe()
            .map_err(|e| Error::agent("find smolvm binary", e.to_string()))?;
        let spawn_start = Instant::now();
        // Embedders (e.g. the Node SDK, where current_exe is `node`) can point the
        // boot subprocess at a `_boot-vm`-capable, signed helper binary instead of self.
        let boot_binary = std::env::var_os("SMOLVM_BOOT_BINARY");
        // An in-process embedder (the Node/Python SDK) sets SMOLVM_BOOT_BINARY and
        // owns the VM's lifetime — when that host process dies, the VM must die
        // too, or it leaks as an orphan holding the VM's full RAM. The CLI (which
        // detaches the VM on purpose) and `serve` (which reconnects to surviving
        // VMs) don't set it, so they keep today's behavior. We pass the resulting
        // flag down so the boot subprocess only arms its parent-death watchdog in
        // the embedder case. See `cli/internal_boot::run`.
        let watch_parent = boot_binary.is_some();
        let boot_exe = boot_binary
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| exe.clone());
        let child = std::process::Command::new(&boot_exe)
            .args(["_boot-vm", &config_path.to_string_lossy()])
            .env(
                "SMOLVM_BOOT_WATCH_PARENT",
                if watch_parent { "1" } else { "0" },
            )
            .stdin(std::process::Stdio::null())
            // SMOLVM_BOOT_DEBUG=1 surfaces the boot subprocess's stdout/stderr so
            // embedded-host launch failures can be diagnosed (normally silenced).
            .stdout(if std::env::var_os("SMOLVM_BOOT_DEBUG").is_some() {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            })
            .stderr(if std::env::var_os("SMOLVM_BOOT_DEBUG").is_some() {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            })
            // Own process group (pgid = child pid) so the VM is immune to
            // SIGHUP from the parent's terminal closing, without making it a
            // session leader. Session-leader status causes proc_pidinfo to
            // return a zeroed struct on macOS, breaking start-time verification
            // in _cleanup-ephemeral and leaving orphan VM processes running.
            .process_group(0)
            .spawn()
            .map_err(|e| Error::agent("spawn boot subprocess", e.to_string()))?;

        let child_pid = child.id() as i32;
        // Register the detached VM PID for the serve supervisor's selective
        // reaper. The boot subprocess owns its process group and is never
        // `wait()`ed, so it would zombie on exit; the supervisor tick reaps it.
        // (In non-serve callers without a supervisor this is a harmless no-op —
        // the sweep is only driven from serve.) The `child` handle drops without
        // waiting (Rust `Child::drop` is a no-op), leaving the PID for the sweep.
        crate::process::register_vm_child(child_pid);
        tracing::info!(
            pid = child_pid,
            spawn_ms = spawn_start.elapsed().as_millis(),
            "boot: subprocess spawned"
        );

        // Lossless-restart placement: on a systemd host, adopt the just-forked VM
        // into its own `smolvm-vm-<id>.scope` (sibling unit, owned by PID1) so a
        // later `serve` restart can't kill or `219/CGROUP`-crash on it. Serve set
        // SMOLVM_VM_USE_SCOPE at startup and did NOT set SMOLVM_CGROUP_ROOT, so the
        // boot subprocess skipped self-placement and the VM is still in serve's
        // cgroup for this microsecond window — the adopt moves it out. Caps mirror
        // process::place_in_cgroup (CGROUP_MEM_OVERHEAD_MIB=768, CGROUP_PIDS_MAX
        // =1024) as scope properties. Best-effort: on failure the VM keeps running
        // (just not restart-safe), same as an uncapped cgroup join.
        #[cfg(target_os = "linux")]
        if std::env::var_os("SMOLVM_VM_USE_SCOPE").is_some() {
            if let Some(name) = self.name() {
                let caps = crate::systemd_scope::ScopeCaps {
                    memory_max_bytes: Some(
                        (resources_for_config.memory_mib as u64 + 768) * 1024 * 1024,
                    ),
                    cpu_quota_usec_per_sec: Some(
                        (resources_for_config.cpus.max(1) as u64) * 1_000_000,
                    ),
                    tasks_max: Some(1024),
                };
                if let Err(e) = crate::systemd_scope::adopt_into_scope(name, child_pid, &caps) {
                    // Only reachable when is_available() said yes (root + systemd +
                    // busctl) but the bus call still failed — effectively a broken
                    // D-Bus. The VM keeps running but stays in serve's cgroup,
                    // uncapped and not restart-safe. Loud so the operator notices.
                    tracing::warn!(
                        error = %e, pid = child_pid,
                        "failed to adopt VM into systemd scope; VM left in service cgroup — uncapped and NOT restart-safe"
                    );
                }
            }
        }

        self.finalize_launch(child_pid, &mounts, &ports, &resources_for_config)
    }

    /// Like `ensure_running_with_full_config` but uses subprocess launch.
    ///
    /// Use this from multi-threaded contexts (API server) where fork() is
    /// unsafe on macOS. See `start_via_subprocess` for details.
    pub fn ensure_running_via_subprocess(
        &self,
        mounts: Vec<HostMount>,
        ports: Vec<PortMapping>,
        resources: VmResources,
        mut features: launcher::LaunchFeatures,
    ) -> Result<bool> {
        // Check if agent is already running (same logic as ensure_running_with_full_config)
        if self.try_connect_existing().is_some() {
            let inner = self.inner.lock();
            match &inner.config_state {
                ConfigState::Known => {
                    if inner.mounts == mounts
                        && inner.ports == ports
                        && inner.resources == resources
                    {
                        return Ok(false);
                    }
                }
                ConfigState::LoadFailed(reason) => {
                    tracing::info!(
                        reason = %reason,
                        "forcing VM restart: running config unknown"
                    );
                }
                ConfigState::Unknown => {
                    tracing::info!("forcing VM restart: config state still unknown");
                }
            }
        }

        let needs_restart = {
            let inner = self.inner.lock();
            inner.state == AgentState::Running
        };

        if needs_restart {
            tracing::info!("restarting agent VM due to configuration change");
            self.stop()?;
        } else {
            self.reset_stale_running_state();
        }

        // Re-attach packed layers if a config-change restart dropped them
        // (see `rewire_packed_layers_if_extracted`).
        self.rewire_packed_layers_if_extracted(&mut features)?;

        self.start_via_subprocess(mounts, ports, resources, features)?;
        Ok(true)
    }

    /// Verify identity of a VM process and kill it.
    ///
    /// Uses two methods to confirm the PID belongs to our VM:
    /// 1. **Vsock shutdown** — if the guest agent acknowledges, it's our VM
    /// 2. **PID start-time** — strict comparison guards against PID reuse
    ///
    /// If either method confirms identity, sends SIGTERM (then SIGKILL on timeout).
    /// Returns `Ok(())` if the process is confirmed dead, `Err` if still alive
    /// or identity could not be verified.
    fn stop_vm_process(&self, pid: libc::pid_t, start_time: Option<u64>) -> Result<()> {
        // Use short timeout — the agent may already be gone (ephemeral run exited).
        // A 100ms connect timeout avoids blocking the exit path.
        let shutdown_acked = if let Ok(mut client) =
            super::AgentClient::connect_with_short_timeout(&self.vsock_socket)
        {
            client.shutdown().is_ok()
        } else {
            false
        };

        // Identity check: vsock acknowledgement OR strict PID start-time match.
        // We intentionally do NOT use the lenient is_our_process() here because
        // it treats any alive PID as "ours" when start_time is None — which risks
        // killing an unrelated process if the OS reused the PID.
        let identity_ok = shutdown_acked || process::is_our_process_strict(pid, start_time);

        if identity_ok {
            if !process::is_our_process_strict(pid, start_time) {
                tracing::debug!(
                    pid,
                    "PID start-time not verified, identity confirmed via vsock"
                );
            }
            let _ = process::stop_vm_process(pid, AGENT_STOP_TIMEOUT, process::VM_SIGKILL_TIMEOUT);
        } else {
            tracing::warn!(
                pid,
                "skipping kill: PID identity not verified and vsock shutdown failed"
            );
        }

        if process::is_alive(pid) {
            Err(Error::agent(
                "stop agent",
                format!("process {} still alive after stop attempts", pid),
            ))
        } else {
            Ok(())
        }
    }

    /// Remove PID file, config file, and vsock socket marker files.
    ///
    /// Only call after the VM process is confirmed dead.
    fn cleanup_marker_files(&self) {
        for path in [&self.pid_file, &self.config_file, &self.vsock_socket] {
            if let Err(e) = std::fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!(error = %e, path = %path.display(), "failed to remove marker file");
                }
            }
        }
    }

    /// Kill the VM process immediately with SIGKILL. No graceful shutdown.
    ///
    /// Used for ephemeral `machine run` where the command has already finished
    /// and there's no state to preserve. Much faster than `stop()` which
    /// attempts a graceful vsock shutdown + SIGTERM + poll.
    pub fn kill(&self) {
        let pid = {
            let inner = self.inner.lock();
            inner.child.as_ref().map(|c| c.pid())
        };
        let pid = pid.or_else(|| self.read_pid_file_with_start_time().map(|(p, _)| p));

        if let Some(pid) = pid {
            if process::is_alive(pid) {
                process::kill(pid);
                // Brief wait for the kernel to reap (SIGKILL is near-instant).
                // try_wait reaps zombie children; is_alive catches non-children
                // that have been reparented to init/launchd.
                for _ in 0..10 {
                    if process::try_wait(pid).is_some() || !process::is_alive(pid) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
        self.cleanup_marker_files();
    }

    /// Remove the VM's entire data directory (storage, overlay, socket, logs).
    ///
    /// Only safe for ephemeral VMs after the process is confirmed dead.
    pub fn cleanup_data_dir(&self) {
        if let Some(ref name) = self.name {
            let dir = vm_data_dir(name);
            if dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(&dir) {
                    tracing::debug!(
                        error = %e,
                        path = %dir.display(),
                        "failed to remove ephemeral VM data directory"
                    );
                }
            }
        }
    }

    /// Stop the agent VM.
    pub fn stop(&self) -> Result<()> {
        let state = {
            let inner = self.inner.lock();
            inner.state
        };

        if state == AgentState::Stopped {
            // Even if internal state is Stopped, check PID file for orphan processes
            // from previous CLI invocations that weren't properly cleaned up.
            if let Some((pid, start_time)) = self.read_pid_file_with_start_time() {
                if let Err(e) = self.stop_vm_process(pid, start_time) {
                    tracing::warn!(
                        pid,
                        "orphan process still alive, preserving PID/socket files"
                    );
                    return Err(e);
                }
                self.cleanup_marker_files();
            }
            return Ok(());
        }

        {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopping;
        }

        tracing::info!("stopping agent VM");

        // Get the child PID and start time — try in-memory first, then PID file.
        // The PID file fallback is critical for default VMs where a fresh
        // AgentManager doesn't know the PID from a previous CLI invocation.
        let (child_pid, pid_start_time) = {
            let inner = self.inner.lock();
            if let Some(child) = inner.child.as_ref() {
                // Use the start time captured when the child handle was created,
                // not recomputed from the PID (which would be self-fulfilling
                // if the PID was recycled by the OS).
                (Some(child.pid()), child.start_time())
            } else {
                match self.read_pid_file_with_start_time() {
                    Some((pid, start_time)) => (Some(pid), start_time),
                    None => (None, None),
                }
            }
        };

        if let Some(pid) = child_pid {
            if let Err(e) = self.stop_vm_process(pid, pid_start_time) {
                // Revert to Running — don't lie about state or delete markers
                {
                    let mut inner = self.inner.lock();
                    inner.state = AgentState::Running;
                }
                return Err(e);
            }
        }

        // Defense in depth: sync host's view of the disk files
        // This catches any writes that made it to the host buffer but weren't flushed
        // Combined with agent-side sync(), this provides robust data integrity
        for (label, path) in [
            ("storage", self.storage_disk.path()),
            ("overlay", self.overlay_disk.path()),
        ] {
            if let Ok(file) = std::fs::File::open(path) {
                if file.sync_all().is_ok() {
                    tracing::debug!("{} disk synced to host", label);
                }
            }
        }

        // Clean up — safe now that process is confirmed dead
        {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopped;
            inner.child = None;
            // Release the per-VM file lock so other processes can start this VM.
            #[cfg(unix)]
            {
                inner.vm_lock_handle = None;
            }
        }

        self.cleanup_marker_files();
        metrics::gauge!("smolvm_machines_running").decrement(1.0);

        Ok(())
    }

    /// Wait for the agent to be ready.
    ///
    /// Polls the virtiofs file marker `.smolvm-ready` written by the agent
    /// after completing initialization. Includes a vsock control-channel ping
    /// fallback for agents too old to write the marker.
    ///
    /// Measured latency (macOS 26, warm boots): ~135ms total from subprocess spawn.
    ///
    /// Instrumented trace findings (May 2026):
    /// - Ready marker appears on host fs within ~1ms of the virtiofs FUSE write.
    ///   No visibility gap exists; polling interval is the only noise source.
    /// - hv_gic_set_spi() costs 0–15µs per call — SPI injection is free.
    /// - Bottleneck is setup_persistent_rootfs() block I/O on /dev/vdb:
    ///   246 requests × 83–131ms = 48ms (37% of total boot time). Skipping
    ///   the overlay disk for ephemeral runs is the highest-impact optimization.
    /// - Guest /proc/uptime runs at half real speed (CNTFRQ_EL0 2× counter rate);
    ///   this explains why guest logs show "70ms" while host measures "131ms".
    ///   It is a display artifact only and does not cause any actual delay.
    ///
    /// Polling at 1ms for the first second to give sub-poll-interval resolution
    /// for boot timing experiments. Falls back to 5ms after 1 second.
    fn wait_for_ready(&self) -> Result<()> {
        let timeout = AGENT_READY_TIMEOUT;
        let start = Instant::now();
        let socket_probe_grace = Duration::from_secs(5);

        tracing::debug!("waiting for agent to be ready");

        // Fork clone: the guest resumes past boot, so it never (re)writes the
        // `.smolvm-ready` marker. Detect readiness by pinging the restored agent
        // directly (it is already in its accept loop) — no marker, no grace.
        let is_clone = std::env::var_os("SMOLVM_SNAPSHOT_DIR").is_some_and(|v| !v.is_empty());
        if is_clone {
            while start.elapsed() < timeout {
                {
                    let mut inner = self.inner.lock();
                    if let Some(ref mut child) = inner.child {
                        if !child.is_running() {
                            return Err(Error::agent(
                                "monitor agent",
                                "clone agent process exited during startup".to_string(),
                            ));
                        }
                    }
                }
                if self.vsock_socket.exists() {
                    if let Ok(mut client) =
                        super::AgentClient::connect_with_boot_probe_timeout(&self.vsock_socket)
                    {
                        if client.ping().is_ok() {
                            tracing::info!(
                                elapsed_ms = start.elapsed().as_millis(),
                                "clone agent ready (ping)"
                            );
                            return Ok(());
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            return Err(Error::agent(
                "wait for ready",
                "clone agent did not respond to ping within timeout".to_string(),
            ));
        }

        let ready_marker = self.rootfs_path.join(AGENT_READY_MARKER);

        while start.elapsed() < timeout {
            // Check if child process is still alive
            {
                let mut inner = self.inner.lock();
                if let Some(ref mut child) = inner.child {
                    if !child.is_running() {
                        let reason = std::fs::read_to_string(&self.startup_error_log)
                            .ok()
                            .map(|content| content.trim().to_string())
                            .filter(|content| !content.is_empty());
                        return Err(Error::agent(
                            "monitor agent",
                            reason.unwrap_or_else(|| {
                                "agent process exited during startup".to_string()
                            }),
                        ));
                    }
                }
            }

            // Ready when the marker is present AND non-empty. The guest writes
            // its uptime (always non-empty) into it. Under SMOLVM_LANDLOCK the
            // confined VMM pre-creates this file empty so Landlock can grant
            // write on just this one file (see internal_boot.rs) — so existence
            // alone would false-positive; require content.
            if std::fs::metadata(&ready_marker)
                .map(|m| m.len() > 0)
                .unwrap_or(false)
            {
                let elapsed = start.elapsed();
                tracing::info!(elapsed_ms = elapsed.as_millis(), "agent ready (marker)");
                return Ok(());
            }

            // After long grace, fall back to socket ping for very old agents
            // that don't write the ready marker at all.
            if start.elapsed() >= socket_probe_grace && self.vsock_socket.exists() {
                if let Ok(mut client) =
                    super::AgentClient::connect_with_boot_probe_timeout(&self.vsock_socket)
                {
                    if client.ping().is_ok() {
                        let elapsed = start.elapsed();
                        tracing::info!(
                            elapsed_ms = elapsed.as_millis(),
                            "agent ready (socket fallback)"
                        );
                        return Ok(());
                    }
                }
            } else {
                // 1ms polling during first second for sub-interval boot timing resolution;
                // 5ms thereafter to avoid burning CPU while waiting on slow starts.
                let poll_ms = if start.elapsed() < Duration::from_secs(1) {
                    1
                } else {
                    5
                };
                std::thread::sleep(Duration::from_millis(poll_ms));
            }
        }

        Err(Error::agent(
            "wait for ready",
            format!(
                "agent did not become ready within {} seconds",
                timeout.as_secs()
            ),
        ))
    }

    /// Wait for the agent to stop.
    fn wait_for_stop(&self) -> Result<()> {
        let timeout = WAIT_FOR_STOP_TIMEOUT;
        let start = Instant::now();

        while start.elapsed() < timeout {
            if self.state() == AgentState::Stopped {
                return Ok(());
            }
            std::thread::sleep(FAST_POLL_INTERVAL);
        }

        Err(Error::agent(
            "shutdown agent",
            "timeout waiting for agent to stop",
        ))
    }

    /// Check if agent process is still running.
    pub fn check_alive(&self) -> bool {
        let mut inner = self.inner.lock();

        if let Some(ref mut child) = inner.child {
            child.is_running()
        } else {
            false
        }
    }

    /// Detach the agent manager, preventing cleanup on drop.
    ///
    /// Call this when you want the agent VM to continue running after
    /// this manager instance is dropped (e.g., for persistent VMs).
    ///
    /// This is preferred over `std::mem::forget` because:
    /// - Intent is explicit and documented
    /// - Other resources (non-child-process) are still properly cleaned up
    /// - The manager can still be used after detaching
    pub fn detach(&self) {
        let mut inner = self.inner.lock();
        inner.detached = true;
        tracing::debug!("agent manager detached, VM will continue running");
    }

    /// Check if the agent manager has been detached.
    pub fn is_detached(&self) -> bool {
        let inner = self.inner.lock();
        inner.detached
    }
}

impl Drop for AgentManager {
    fn drop(&mut self) {
        let inner = self.inner.lock();
        let detached = inner.detached;
        let has_child = inner.child.is_some();
        drop(inner);

        if detached {
            return;
        }

        // Only stop the VM if this manager actually owns the child process.
        // Managers created as observers (e.g., API read handlers, monitor
        // loop iterations) have no child handle and must NOT kill VMs they
        // didn't start.  Without this guard, dropping an observer manager
        // triggers the orphan-cleanup path in stop(), which reads the PID
        // file and kills whatever VM another manager is running.
        if has_child {
            if let Err(e) = self.stop() {
                tracing::debug!(error = %e, "failed to stop agent in drop");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_dir_hash_is_deterministic() {
        // Stability guarantee: the same name always maps to the same hash.
        // Callers rely on this to locate existing VM data across processes.
        assert_eq!(vm_dir_hash("sandbox-1"), vm_dir_hash("sandbox-1"));
        assert_eq!(vm_dir_hash("default"), vm_dir_hash("default"));
    }

    #[test]
    fn vm_dir_hash_is_16_hex_chars() {
        let h = vm_dir_hash("anything");
        assert_eq!(h.len(), 16, "expected 16 hex chars, got {}: {}", h.len(), h);
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "hash contains non-hex chars: {}",
            h
        );
    }

    #[test]
    fn vm_dir_hash_differs_for_different_names() {
        assert_ne!(vm_dir_hash("a"), vm_dir_hash("b"));
        assert_ne!(vm_dir_hash("sandbox-1"), vm_dir_hash("sandbox-2"));
    }

    #[test]
    fn vm_data_dir_path_length_is_bounded_regardless_of_name() {
        // Core correctness property: socket-path overflow is impossible
        // because the variable section is fixed at 16 chars. A 200-char name
        // produces the same-length path as a 1-char name. No legacy fallback
        // means this holds deterministically, regardless of filesystem state.
        let short = vm_data_dir("x");
        let long = vm_data_dir(&"a".repeat(200));
        assert_eq!(
            short.as_os_str().len(),
            long.as_os_str().len(),
            "path length must be independent of name length"
        );
    }

    #[test]
    fn ensure_vm_dir_writes_name_file_on_first_call() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("abc123");
        let result = ensure_vm_dir_at(&dir, "my-vm").unwrap();
        assert_eq!(result, dir);
        assert_eq!(std::fs::read_to_string(dir.join("name")).unwrap(), "my-vm");
    }

    #[test]
    fn ensure_vm_dir_is_idempotent_for_matching_name() {
        // Second call with the same name must succeed (every machine start,
        // exec, etc. re-enters this path). Must not touch the name file.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("abc123");
        ensure_vm_dir_at(&dir, "my-vm").unwrap();

        // Tamper with the mtime semantics: if we were rewriting, we'd clobber
        // any user edit. Write a sentinel and confirm it survives.
        let name_file = dir.join("name");
        let before = std::fs::metadata(&name_file).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        ensure_vm_dir_at(&dir, "my-vm").unwrap();
        let after = std::fs::metadata(&name_file).unwrap().modified().unwrap();
        assert_eq!(
            before, after,
            "name file must not be rewritten on repeat calls"
        );
    }

    #[test]
    fn ensure_vm_dir_rejects_hash_collision() {
        // Simulate two distinct VM names hashing to the same directory.
        // ensure_vm_dir_at is parameterized on the directory so we can
        // exercise this without needing a real SHA-256 collision.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("collision-dir");

        ensure_vm_dir_at(&dir, "first-vm").unwrap();

        let err = ensure_vm_dir_at(&dir, "second-vm")
            .expect_err("expected collision error for different name at same dir");
        let msg = err.to_string();
        assert!(
            msg.contains("hash collision"),
            "error should identify collision: {msg}"
        );
        assert!(
            msg.contains("first-vm") && msg.contains("second-vm"),
            "error should name both VMs: {msg}"
        );

        // The name file must still point to the first VM — we must NOT have
        // clobbered it during the failed attempt.
        assert_eq!(
            std::fs::read_to_string(dir.join("name")).unwrap(),
            "first-vm",
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rewire_packed_layers_returns_lease_failure() {
        let temp = tempfile::tempdir().unwrap();

        let name = format!(
            "review-rewire-lease-failure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        struct VmDataCleanup(String);
        impl Drop for VmDataCleanup {
            fn drop(&mut self) {
                smolvm_pack::extract::force_detach_layers_volume(&machine_layers_cache_dir(
                    &self.0,
                ));
                let _ = std::fs::remove_dir_all(vm_data_dir(&self.0));
            }
        }
        let _cleanup = VmDataCleanup(name.clone());

        let storage = StorageDisk::open_or_create_at(&temp.path().join("storage.img"), 1).unwrap();
        let overlay = OverlayDisk::open_or_create_at(&temp.path().join("overlay.img"), 1).unwrap();
        let manager =
            AgentManager::new_named(&name, temp.path().join("rootfs"), storage, overlay).unwrap();

        let cache_dir = machine_layers_cache_dir(&name);
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join(".smolvm-extracted"), "").unwrap();
        std::fs::write(cache_dir.join("layers-cs.sparseimage"), b"not a disk image").unwrap();

        let mut features = launcher::LaunchFeatures::default();
        let err = manager
            .rewire_packed_layers_if_extracted(&mut features)
            .expect_err("restart must fail when packed layers cannot be reattached");

        assert!(
            err.to_string().contains("re-attach packed layers"),
            "unexpected error: {err}"
        );
        assert!(features.packed_layers_dir.is_none());
    }
}
