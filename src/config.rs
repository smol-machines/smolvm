//! Global smolvm configuration.
//!
//! This module handles persistent configuration storage for smolvm,
//! including default settings and VM registry.
//!
//! State is persisted to a SQLite database at `~/.local/share/smolvm/server/smolvm.db`.
//! For backward compatibility, `SmolvmConfig` maintains an in-memory cache of VMs
//! and provides the same API as the old confy-based implementation.

use crate::data::network;
use crate::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use crate::db::SmolvmDb;
use crate::error::Result;
use crate::network::NetworkBackend;
use serde::{Deserialize, Serialize};
pub use smolvm_protocol::publish_socket::SocketDirection;
use std::collections::BTreeMap;

/// A user-published host↔guest Unix-socket bridge (`--expose-socket` /
/// `--mount-socket`), persisted on the VM record. The vsock port is assigned at
/// launch (not stored); only the paths and direction are durable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedSocketConfig {
    /// Bridge direction (`expose` = guest→host, `mount` = host→guest).
    pub direction: SocketDirection,
    /// Guest-side socket path: the existing app socket to expose, or the path a
    /// mounted host socket is created at inside the guest.
    pub guest_path: String,
    /// Host-side socket path. For `expose`, where the host-side socket is
    /// created (`None` → default to `<per-VM dir>/<basename of guest_path>`).
    /// For `mount`, the existing host socket to bridge in (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_path: Option<String>,
}

/// VM lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RecordState {
    /// Container exists, VM not started.
    #[default]
    Created,
    /// VM process is running.
    Running,
    /// VM exited cleanly.
    Stopped,
    /// Execution is saved durably; use resume rather than a fresh boot.
    Paused,
    /// A final execution boundary is being saved before stopping.
    Pausing,
    /// VM crashed or error.
    Failed,
    /// libkrun VMM process is alive but the guest agent is not
    /// responding to vsock pings. Typical cause: the agent crashed
    /// (OOM, panic, kernel issue) while the VMM stayed up — common
    /// aftermath of a workload that exhausted guest resources.
    /// `machine list` shows this so operators see the truth instead
    /// of a misleading "running"; `machine start` recovers by
    /// killing the zombie VMM and starting fresh.
    Unreachable,
    /// libkrun VMM process is alive but deliberately frozen as a fork
    /// base: `machine fork` snapshotted it and its clones' disk overlays
    /// are copy-on-write backed by its disks. Its guest agent is paused
    /// and never answers a vsock ping — so it is reported *without* a
    /// liveness probe (it would otherwise look identical to an
    /// `Unreachable` zombie) and is never reaped or auto-restarted: it
    /// must outlive its clones. Resolved on the fly when a record has
    /// dependent clones; not persisted.
    Frozen,
}

impl std::fmt::Display for RecordState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordState::Created => write!(f, "created"),
            RecordState::Running => write!(f, "running"),
            RecordState::Stopped => write!(f, "stopped"),
            RecordState::Paused => write!(f, "paused"),
            RecordState::Pausing => write!(f, "pausing"),
            RecordState::Failed => write!(f, "failed"),
            RecordState::Unreachable => write!(f, "unreachable"),
            RecordState::Frozen => write!(f, "frozen"),
        }
    }
}

/// Restart policy for a machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Never restart the machine automatically.
    #[default]
    Never,
    /// Always restart the machine when it exits.
    Always,
    /// Restart only if the machine exited with a non-zero exit code.
    OnFailure,
    /// Restart unless the user explicitly stopped the machine.
    UnlessStopped,
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestartPolicy::Never => write!(f, "never"),
            RestartPolicy::Always => write!(f, "always"),
            RestartPolicy::OnFailure => write!(f, "on-failure"),
            RestartPolicy::UnlessStopped => write!(f, "unless-stopped"),
        }
    }
}

impl std::str::FromStr for RestartPolicy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "never" => Ok(RestartPolicy::Never),
            "always" => Ok(RestartPolicy::Always),
            "on-failure" | "onfailure" => Ok(RestartPolicy::OnFailure),
            "unless-stopped" | "unlessstopped" => Ok(RestartPolicy::UnlessStopped),
            _ => Err(format!("invalid restart policy: {}", s)),
        }
    }
}

/// Restart configuration for a machine.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RestartConfig {
    /// The restart policy.
    #[serde(default)]
    pub policy: RestartPolicy,
    /// Maximum number of restart attempts (0 = unlimited).
    #[serde(default)]
    pub max_retries: u32,
    /// Maximum backoff duration in seconds (0 = use default 300s).
    #[serde(default)]
    pub max_backoff_secs: u64,
    /// Current restart count.
    #[serde(default)]
    pub restart_count: u32,
    /// Whether the user explicitly stopped this machine.
    #[serde(default)]
    pub user_stopped: bool,
}

impl RestartConfig {
    /// Determine whether the machine should be restarted based on the policy,
    /// exit code, and current restart count.
    pub fn should_restart(&self, exit_code: Option<i32>) -> bool {
        // An explicit user stop suppresses auto-restart for every policy until an
        // explicit start clears the flag — a machine the operator stopped must
        // stay stopped (matching `docker stop` on a restart-policy container),
        // not be resurrected by the supervisor. Only `unless-stopped` consulted
        // this flag before, so `always`/`on-failure` machines were un-stoppable.
        if self.user_stopped {
            return false;
        }
        // Check max retries limit (0 = unlimited)
        if self.max_retries > 0 && self.restart_count >= self.max_retries {
            return false;
        }
        match self.policy {
            RestartPolicy::Never => false,
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure => exit_code != Some(0),
            RestartPolicy::UnlessStopped => true,
        }
    }

    /// Default maximum backoff duration in seconds (5 minutes).
    const DEFAULT_MAX_BACKOFF_SECS: u64 = 300;

    /// Maximum exponent for backoff calculation (2^8 = 256s).
    const MAX_BACKOFF_EXPONENT: u32 = 8;

    /// Calculate exponential backoff duration for the current restart count.
    ///
    /// Formula: 2^n seconds, capped at max_backoff_secs (default 300s).
    pub fn backoff_duration(&self) -> std::time::Duration {
        let max_secs = if self.max_backoff_secs > 0 {
            self.max_backoff_secs
        } else {
            Self::DEFAULT_MAX_BACKOFF_SECS
        };
        let exponent = self.restart_count.min(Self::MAX_BACKOFF_EXPONENT);
        std::time::Duration::from_secs(2u64.pow(exponent).min(max_secs))
    }
}

/// Global smolvm configuration with database-backed persistence.
///
/// This struct provides backward-compatible access to VM records while
/// using SQLite for ACID-compliant storage. The `vms` field is an in-memory
/// cache that is kept in sync with the database.
#[derive(Debug, Clone)]
pub struct SmolvmConfig {
    /// Database handle for persistence.
    db: SmolvmDb,
    /// Configuration format version.
    pub version: u8,
    /// Default number of vCPUs for new VMs.
    pub default_cpus: u8,
    /// Default memory in MiB for new VMs.
    pub default_mem: u32,
    /// Default DNS server for VMs with network egress.
    pub default_dns: String,
    /// Storage volume path (macOS only, for case-sensitive filesystem).
    #[cfg(target_os = "macos")]
    pub storage_volume: String,
    /// Registry of known VMs (by name) - in-memory cache. Ordered by name so
    /// every listing comes out the same way; a hash map reshuffles per process.
    pub vms: BTreeMap<String, VmRecord>,
}

impl SmolvmConfig {
    /// Create a new configuration with default values.
    ///
    /// This is the fallible version of `Default::default()`. Use this when
    /// you need to handle database initialization errors.
    pub fn try_default() -> Result<Self> {
        Ok(Self {
            db: SmolvmDb::open()?,
            version: 1,
            default_cpus: DEFAULT_MICROVM_CPU_COUNT,
            default_mem: DEFAULT_MICROVM_MEMORY_MIB,
            default_dns: network::default_dns(),
            #[cfg(target_os = "macos")]
            storage_volume: String::new(),
            vms: BTreeMap::new(),
        })
    }
}

impl SmolvmConfig {
    /// Load configuration from the database.
    ///
    /// Opens the database and loads all config settings and VM records in a
    /// single database transaction (1 open/close cycle instead of 6).
    pub fn load() -> Result<Self> {
        let db = SmolvmDb::open()?;

        // Load all config + all VMs in one DB round-trip
        let (config_map, vms) = db.load_all()?;

        let version = config_map
            .get("version")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let default_cpus = config_map
            .get("default_cpus")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MICROVM_CPU_COUNT);
        let default_mem = config_map
            .get("default_mem")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MICROVM_MEMORY_MIB);
        let default_dns = config_map
            .get("default_dns")
            .cloned()
            .unwrap_or_else(network::default_dns);

        #[cfg(target_os = "macos")]
        let storage_volume = config_map
            .get("storage_volume")
            .cloned()
            .unwrap_or_default();

        Ok(Self {
            db,
            version,
            default_cpus,
            default_mem,
            default_dns,
            #[cfg(target_os = "macos")]
            storage_volume,
            vms,
        })
    }

    /// Save global configuration to the database.
    ///
    /// Persists all global config settings in a single DB transaction
    /// (1 open/close cycle instead of 4). VM records are not saved here
    /// since writes are immediate via `update_vm()` and `insert_vm()`.
    pub fn save(&self) -> Result<()> {
        let version_str = self.version.to_string();
        let cpus_str = self.default_cpus.to_string();
        let mem_str = self.default_mem.to_string();

        #[cfg(not(target_os = "macos"))]
        let settings: Vec<(&str, &str)> = vec![
            ("version", version_str.as_str()),
            ("default_cpus", cpus_str.as_str()),
            ("default_mem", mem_str.as_str()),
            ("default_dns", self.default_dns.as_str()),
        ];

        #[cfg(target_os = "macos")]
        let settings: Vec<(&str, &str)> = {
            let mut s = vec![
                ("version", version_str.as_str()),
                ("default_cpus", cpus_str.as_str()),
                ("default_mem", mem_str.as_str()),
                ("default_dns", self.default_dns.as_str()),
            ];
            if !self.storage_volume.is_empty() {
                s.push(("storage_volume", self.storage_volume.as_str()));
            }
            s
        };

        self.db.save_config(&settings)
    }

    /// Insert a VM record (persists immediately to database).
    pub fn insert_vm(&mut self, name: String, record: VmRecord) -> Result<()> {
        self.db.insert_vm(&name, &record)?;
        self.vms.insert(name, record);
        Ok(())
    }

    /// Remove a VM from the registry.
    pub fn remove_vm(&mut self, id: &str) -> Option<VmRecord> {
        // Remove from database (ignore errors, just log)
        if let Err(e) = self.db.remove_vm(id) {
            tracing::warn!(error = %e, vm = %id, "failed to remove VM from database");
        }
        self.vms.remove(id)
    }

    /// Get a VM record by ID.
    pub fn get_vm(&self, id: &str) -> Option<&VmRecord> {
        self.vms.get(id)
    }

    /// List all VM records, in name order.
    pub fn list_vms(&self) -> impl Iterator<Item = (&String, &VmRecord)> {
        self.vms.iter()
    }

    /// Update a VM record in place (persists immediately to database).
    ///
    /// Returns `None` if the record doesn't exist, `Some(Err)` if the DB write
    /// fails, `Some(Ok)` on success. Callers that need fail-closed semantics
    /// should check both.
    pub fn update_vm<F>(&mut self, id: &str, f: F) -> Option<crate::Result<()>>
    where
        F: FnOnce(&mut VmRecord),
    {
        if let Some(record) = self.vms.get_mut(id) {
            f(record);
            // Persist to database
            Some(self.db.insert_vm(id, record))
        } else {
            None
        }
    }

    /// Get the underlying database handle.
    pub fn db(&self) -> &SmolvmDb {
        &self.db
    }
}

/// One add/remove amendment to a stopped machine's egress allow list, applied
/// by [`VmRecord::updated_egress`]. Shared by `machine update` and the API's
/// egress endpoint so the two cannot drift.
#[derive(Debug, Clone, Default)]
pub struct EgressUpdate {
    /// Hostnames to allow, bare: each covers the name and its subdomains.
    pub allow_hosts: Vec<String>,
    /// Patterns to allow: an exact hostname, or `*.domain` for subdomains only.
    pub allow_host_patterns: Vec<String>,
    /// CIDR ranges to allow, already normalized by the caller's parser.
    pub allow_cidrs: Vec<String>,
    /// Allowed hostnames or patterns to remove, written as they were added.
    pub remove_allow_hosts: Vec<String>,
    /// Allowed CIDR ranges to remove.
    pub remove_allow_cidrs: Vec<String>,
    /// Restrict outbound to localhost: sugar for allowing `127.0.0.0/8` and
    /// `::1/128`, exactly as `machine create --outbound-localhost-only` adds
    /// them. Undone entry by entry through `remove_allow_cidrs`.
    pub outbound_localhost_only: bool,
    /// Permit a removal that empties the list, which allows egress to every
    /// host (`--net` on the CLI, `allowAll` on the API).
    pub allow_all: bool,
}

impl EgressUpdate {
    /// Whether this update changes nothing.
    pub fn is_empty(&self) -> bool {
        self.allow_hosts.is_empty()
            && self.allow_host_patterns.is_empty()
            && self.allow_cidrs.is_empty()
            && !self.outbound_localhost_only
            && self.remove_allow_hosts.is_empty()
            && self.remove_allow_cidrs.is_empty()
    }
}

/// Record of a VM in the registry.
///
/// This stores machine configuration only. Container configuration
/// is managed separately via the container commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRecord {
    /// VM name/ID.
    pub name: String,

    /// Creation timestamp (seconds since Unix epoch).
    #[serde(deserialize_with = "deserialize_timestamp", default)]
    pub created_at: u64,

    /// VM lifecycle state.
    #[serde(default)]
    pub state: RecordState,

    /// Durable execution state retained until a successful explicit resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_checkpoint: Option<std::path::PathBuf>,

    /// Process ID when running.
    #[serde(default)]
    pub pid: Option<i32>,

    /// Process start time (seconds since epoch) for PID verification.
    /// Used alongside PID to detect PID reuse by the OS.
    #[serde(default)]
    pub pid_start_time: Option<u64>,

    /// Number of vCPUs.
    #[serde(default = "default_cpus")]
    pub cpus: u8,

    /// Memory in MiB.
    #[serde(default = "default_mem")]
    pub mem: u32,

    /// Host engine used for writable virtio block disks.
    #[serde(default)]
    pub block_io: crate::data::resources::BlockIoEngine,

    /// Host disks attached beyond the managed storage and overlay disks
    /// (`--disk`). Persisted so every start re-attaches them in the same order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<crate::data::disk::AttachedDisk>,

    /// Volume mounts (host_path, guest_path, read_only).
    #[serde(default)]
    pub mounts: Vec<(String, String, bool)>,

    /// Guest-local working trees synchronized with host directories in
    /// batches. Kept separate from `mounts` so existing records retain their
    /// tuple encoding and cannot accidentally reinterpret a staged mount as a
    /// live writable virtiofs mount.
    #[serde(default)]
    pub staged_mounts: Vec<(usize, String, String)>,

    /// Port mappings (host_port, guest_port).
    #[serde(default)]
    pub ports: Vec<(u16, u16)>,

    /// User-published Unix-socket bridges (`--expose-socket` / `--mount-socket`).
    #[serde(default)]
    pub published_sockets: Vec<PublishedSocketConfig>,

    /// Enable outbound network access (TSI).
    #[serde(default)]
    pub network: bool,

    /// Enable GPU acceleration (virtio-gpu with Venus/Vulkan).
    #[serde(default)]
    pub gpu: Option<bool>,

    /// Expose host virtualization extensions so the guest can run KVM. Decided
    /// at create time and persisted, like `gpu`, because it changes how the VM
    /// is built rather than how it is used.
    #[serde(default)]
    pub nested_virt: Option<bool>,

    /// GPU shared-memory region size in MiB. `None` → default
    /// (`DEFAULT_GPU_VRAM_MIB`). Ignored unless `gpu` is true.
    #[serde(default)]
    pub gpu_vram_mib: Option<u32>,

    /// Enable Rosetta 2 for x86_64 binary translation on Apple Silicon.
    #[serde(default)]
    pub rosetta: Option<bool>,

    /// Restart configuration.
    #[serde(default)]
    pub restart: RestartConfig,

    /// Last exit code from the VM process.
    #[serde(default)]
    pub last_exit_code: Option<i32>,

    /// Commands to run on first VM start (via `sh -c`).
    #[serde(default)]
    pub init: Vec<String>,

    /// Whether init commands have already completed successfully.
    /// Set to true after first successful run; reset when init commands change.
    #[serde(default)]
    pub init_completed: bool,

    /// Remote volumes (S3-compatible object stores) mounted inside the guest
    /// by the agent on every start. See `crate::remote_volume`.
    #[serde(default)]
    pub remote_volumes: Vec<crate::remote_volume::RemoteVolume>,

    /// Environment variables for init commands.
    #[serde(default)]
    pub env: Vec<(String, String)>,

    /// Secret references declared by a Smolfile `[secrets]` section, keyed
    /// by the guest-side env var name. Resolved to plaintext at each VM
    /// start (and for `machine exec`) and appended to the env vector — the
    /// plaintext values never touch this record or the DB.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub secret_refs: std::collections::BTreeMap<String, crate::secrets::SecretRef>,

    /// Working directory for the container workload.
    #[serde(default)]
    pub workdir: Option<String>,

    /// Container user (UID or username). Resolved from image metadata at first
    /// launch and stored so restart can replay the same identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Storage disk size in GiB (None = default 20 GiB).
    #[serde(default)]
    pub storage_gb: Option<u64>,

    /// Overlay disk size in GiB (None = default 10 GiB).
    #[serde(default)]
    pub overlay_gb: Option<u64>,

    /// Allowed egress CIDR ranges. None = unrestricted, Some([]) = deny all.
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,

    /// Preferred network backend override for machine launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_backend: Option<NetworkBackend>,

    /// Custom DNS resolver for the guest. None = backend default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<std::net::Ipv4Addr>,

    /// Named inter-VM network this machine joins on start (virtio-net only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,

    /// IPv4 subnet for the guest link (virtio-net only). None = `100.96.0.0/30`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_subnet: Option<String>,

    /// OCI image for auto-container creation on start.
    #[serde(default)]
    pub image: Option<String>,

    /// Entrypoint for the container.
    #[serde(default)]
    pub entrypoint: Vec<String>,

    /// Default command for the container.
    #[serde(default)]
    pub cmd: Vec<String>,

    /// Caller-supplied metadata (`--label k=v`), never interpreted by smolvm.
    ///
    /// Exists so a process managing many machines can recognise its own later:
    /// which sandbox a machine belongs to, which owner created it, when it may be
    /// reclaimed. Without it the only per-machine identifier is the name, so
    /// orchestrators are forced to encode state into names (and cannot read it
    /// back, since the table view truncates them). Ordered so `machine ls --json`
    /// is stable to diff.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,

    /// Health check command (run inside VM to verify workload is healthy).
    #[serde(default)]
    pub health_cmd: Option<Vec<String>>,

    /// Health check interval in seconds.
    #[serde(default)]
    pub health_interval_secs: Option<u64>,

    /// Health check timeout in seconds.
    #[serde(default)]
    pub health_timeout_secs: Option<u64>,

    /// Health check failure threshold before marking unhealthy.
    #[serde(default)]
    pub health_retries: Option<u32>,

    /// Grace period in seconds before health checks start after boot.
    #[serde(default)]
    pub health_startup_grace_secs: Option<u64>,

    /// Enable SSH agent forwarding into the VM.
    #[serde(default)]
    pub ssh_agent: bool,

    /// Enable CUDA-over-vsock: smolvm starts a host CUDA server and remotes the
    /// guest's CUDA Driver-API calls to the host NVIDIA GPU.
    #[serde(default)]
    pub cuda: bool,

    /// Start this machine as a copy-on-write fork base by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forkable: bool,

    /// Boot without the parent-death watchdog, so the VM outlives whichever
    /// process starts it. Set by an embedder (the SDK's `detach`) whose own
    /// restarts must not take its machines down; it reattaches with
    /// `connect`. Persisted, like `forkable`, so every later start honours it
    /// and not only the creating one — a machine that survived a crash but
    /// died with the next process to `start` it would be a trap.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detached: bool,

    /// Restored from a checkpoint as the same machine going back in time, so
    /// its first start keeps the saved hostname and machine ID instead of
    /// minting a new identity for a clone (`machine create --keep-identity`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_identity: bool,

    /// Stop the machine once its workload exits, whatever the exit status.
    /// The guest flushes storage as for `machine stop`, then powers off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stop_on_exit: bool,

    /// Planned number of runnable CUDA fork clones. Persisted so every clone
    /// receives the same pre-initialization VRAM policy as its golden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cuda_fork_pool_size: Option<u32>,

    /// Explicit logical VRAM limit applied to the golden and every clone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cuda_vram_limit_mib: Option<u64>,

    /// Preload this fork lineage's staged CUDA modules while clone workers boot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cuda_preload_modules: bool,

    /// Expose the guest's Docker daemon socket to the host as a Unix socket in
    /// the VM data dir, so a host client can drive it with `DOCKER_HOST=unix://…`.
    #[serde(default)]
    pub docker_socket: bool,

    /// Hostnames for DNS filtering. When set, the guest DNS proxy filters
    /// queries against this allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_filter_hosts: Option<Vec<String>>,

    /// Credential bindings the workload may use through the host interceptor
    /// (`[[network.credentials]]` / `--credential`). Names and destinations
    /// only; values are resolved on the host per request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_policy: Option<smolvm_protocol::CredentialPolicy>,

    /// A host interceptor was bound to this machine. Future boots must supply
    /// an interceptor again; the token and endpoint remain launch-scoped and
    /// are never written to the machine record.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub external_interceptor_required: bool,

    /// Binding name → placeholder handed to the guest in the bound variable.
    /// Minted once at create and kept stable so processes captured in a
    /// checkpoint or fork keep working after restore.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub credential_placeholders: std::collections::BTreeMap<String, String>,

    /// The credential bindings came in over the HTTP API, so their values come
    /// only from that API (`PUT /machines/{name}/credential-values`) and never
    /// from this host's environment: an API caller must not be able to route a
    /// host variable to a host of its choosing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub credentials_supplied_by_api: bool,

    /// True for `machine run` VMs. Auto-deleted on exit or cleanup sweep.
    #[serde(default)]
    pub ephemeral: bool,

    /// Absolute path to the .smolmachine sidecar this machine was created from.
    /// When set, `machine start` extracts layers from the sidecar and mounts
    /// them via virtiofs instead of pulling the image from a registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_smolmachine: Option<String>,

    /// Registry reference `source_smolmachine` was pulled from, if any. Carried
    /// into a live checkpoint so another host can fetch the same pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_registry_ref: Option<String>,

    /// The registry reference a machine with no network was created from, when
    /// the host fetched that image for it (see
    /// [`VmRecord::image_needs_host_fetch`]). `image` then names the pinned
    /// local copy every start boots from; this keeps what the user asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_origin: Option<String>,

    /// Name of the golden VM this machine was forked from, if any. A clone's
    /// block disks are copy-on-write overlays backed by the golden's disks, so
    /// the golden must outlive its clones. The disk *format* is not recorded
    /// here — it is derived from the on-disk file (`.qcow2` vs `.raw`), which is
    /// the single source of truth (see `agent::resolve_disk_image`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub golden: Option<String>,

    /// Immutable RAM/disk generation inherited by this clone. This is the
    /// short directory id under the golden's `s/` tree, never a caller-supplied
    /// path. It lets the host retain a demand-paging guardian exactly while a
    /// live clone can still fault pages from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_generation: Option<String>,

    /// Process identity of a live branch source whose RAM has been rebased onto
    /// private mappings. Such a source can retain its original memfd backing in
    /// addition to its current private pages even after every older child is
    /// deleted, so Linux cgroup accounting must keep one structural RAM unit
    /// until this exact VMM process exits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_lineage_pid_start_time: Option<u64>,

    /// The checkpoint this machine's state continues from: the last checkpoint
    /// captured from it, or the one it was restored from. The next capture
    /// records it as its parent, which is what links checkpoints into history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_head: Option<String>,

    /// Persistent container-overlay owner inherited from the root of a fork
    /// lineage. A clone's live overlay keeps its original on-disk name across
    /// every generation; descendants must continue addressing that root name.
    /// Older one-level clone records omit this and fall back to `golden`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_overlay_owner: Option<String>,

    /// Host UID lineage, independent of names inside the guest filesystem.
    /// Portable restores establish a new host lineage while retaining guest names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_uid_owner: Option<String>,

    /// Whether a fork clone is still parked at the inherited workload
    /// forkpoint. Held clones are clean, already-booted pool slots: a caller
    /// installs the job-specific fork parameters and releases each slot once.
    /// A released training clone is disposable and must never be marked held
    /// again because its optimizer, RNG, and dataset state may have changed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forkpoint_held: bool,

    /// Parameters delivered through `/etc/smolvm/fork-env` for this clone.
    /// Kept separately from the machine's ordinary environment so a held slot
    /// can merge assignment-time values without copying unrelated golden env
    /// entries into the workload-facing parameter file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fork_env: Vec<(String, String)>,

    /// Set for machines created by the Kubernetes containerd shim (pod
    /// sandboxes). Scopes node-reboot reconciliation (see
    /// `control::reconcile_runtime_machines`) so it reclaims only shim-managed
    /// VMs whose process died with a crash or reboot, never a user's persistent
    /// CLI/SDK machine.
    #[serde(default)]
    pub runtime_managed: bool,
}

/// Deserialize `created_at` from either a legacy JSON string `"1705312345"` or
/// the current integer `1705312345`. Old DB records stored it as a string.
fn deserialize_timestamp<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrU64 {
        Str(String),
        U64(u64),
    }
    match StrOrU64::deserialize(deserializer)? {
        StrOrU64::U64(n) => Ok(n),
        StrOrU64::Str(s) => s.parse::<u64>().map_err(serde::de::Error::custom),
    }
}

fn default_cpus() -> u8 {
    1
}

fn default_mem() -> u32 {
    512
}

impl VmRecord {
    /// Host identity owner; guest overlay names only serve as a legacy fallback.
    pub fn vm_uid_owner(&self) -> Option<&str> {
        self.host_uid_owner
            .as_deref()
            .or(self.fork_overlay_owner.as_deref())
            .or(self.golden.as_deref())
    }

    /// Whether an ordinary start should launch this machine as a fork base.
    ///
    /// The pool check preserves the behavior of records created before the
    /// explicit `forkable` field existed. Fork clones inherit CUDA capacity
    /// settings from their golden, but remain non-forkable leaves.
    pub fn forkable_on_start(&self) -> bool {
        self.forkable || (self.golden.is_none() && self.cuda_fork_pool_size.is_some())
    }

    /// Create a new VM record.
    pub fn new(
        name: String,
        cpus: u8,
        mem: u32,
        mounts: Vec<(String, String, bool)>,
        ports: Vec<(u16, u16)>,
        network: bool,
    ) -> Self {
        Self {
            name,
            created_at: crate::util::current_timestamp(),
            state: RecordState::Created,
            paused_checkpoint: None,
            pid: None,
            pid_start_time: None,
            cpus,
            mem,
            block_io: Default::default(),
            disks: Vec::new(),
            mounts,
            staged_mounts: Vec::new(),
            ports,
            published_sockets: Vec::new(),
            network,
            gpu: None,
            gpu_vram_mib: None,
            nested_virt: None,
            rosetta: None,
            restart: RestartConfig::default(),
            last_exit_code: None,
            init: Vec::new(),
            init_completed: false,
            remote_volumes: Vec::new(),
            env: Vec::new(),
            secret_refs: std::collections::BTreeMap::new(),
            workdir: None,
            user: None,
            storage_gb: None,
            overlay_gb: None,
            allowed_cidrs: None,
            network_backend: None,
            dns: None,
            network_name: None,
            guest_subnet: None,
            image: None,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            labels: Default::default(),
            health_cmd: None,
            health_interval_secs: None,
            health_timeout_secs: None,
            health_retries: None,
            health_startup_grace_secs: None,
            ssh_agent: false,
            cuda: false,
            forkable: false,
            detached: false,
            keep_identity: false,
            stop_on_exit: false,
            cuda_fork_pool_size: None,
            cuda_vram_limit_mib: None,
            cuda_preload_modules: false,
            docker_socket: false,
            dns_filter_hosts: None,
            credential_policy: None,
            external_interceptor_required: false,
            credential_placeholders: std::collections::BTreeMap::new(),
            credentials_supplied_by_api: false,
            ephemeral: false,
            source_smolmachine: None,
            source_registry_ref: None,
            image_origin: None,
            golden: None,
            checkpoint_head: None,
            fork_generation: None,
            fork_lineage_pid_start_time: None,
            fork_overlay_owner: None,
            host_uid_owner: None,
            forkpoint_held: false,
            fork_env: Vec::new(),
            runtime_managed: false,
        }
    }

    /// Create a new VM record with restart configuration.
    pub fn new_with_restart(
        name: String,
        cpus: u8,
        mem: u32,
        mounts: Vec<(String, String, bool)>,
        ports: Vec<(u16, u16)>,
        network: bool,
        restart: RestartConfig,
    ) -> Self {
        Self {
            name,
            created_at: crate::util::current_timestamp(),
            state: RecordState::Created,
            paused_checkpoint: None,
            pid: None,
            pid_start_time: None,
            cpus,
            mem,
            block_io: Default::default(),
            disks: Vec::new(),
            mounts,
            staged_mounts: Vec::new(),
            ports,
            published_sockets: Vec::new(),
            network,
            gpu: None,
            gpu_vram_mib: None,
            nested_virt: None,
            rosetta: None,
            restart,
            last_exit_code: None,
            init: Vec::new(),
            init_completed: false,
            remote_volumes: Vec::new(),
            env: Vec::new(),
            secret_refs: std::collections::BTreeMap::new(),
            workdir: None,
            user: None,
            storage_gb: None,
            overlay_gb: None,
            allowed_cidrs: None,
            network_backend: None,
            dns: None,
            network_name: None,
            guest_subnet: None,
            image: None,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            labels: Default::default(),
            health_cmd: None,
            health_interval_secs: None,
            health_timeout_secs: None,
            health_retries: None,
            health_startup_grace_secs: None,
            ssh_agent: false,
            cuda: false,
            forkable: false,
            detached: false,
            keep_identity: false,
            stop_on_exit: false,
            cuda_fork_pool_size: None,
            cuda_vram_limit_mib: None,
            cuda_preload_modules: false,
            docker_socket: false,
            dns_filter_hosts: None,
            credential_policy: None,
            external_interceptor_required: false,
            credential_placeholders: std::collections::BTreeMap::new(),
            credentials_supplied_by_api: false,
            ephemeral: false,
            source_smolmachine: None,
            source_registry_ref: None,
            image_origin: None,
            golden: None,
            checkpoint_head: None,
            fork_generation: None,
            fork_lineage_pid_start_time: None,
            fork_overlay_owner: None,
            host_uid_owner: None,
            forkpoint_held: false,
            fork_env: Vec::new(),
            runtime_managed: false,
        }
    }

    /// Check if the VM process is still alive.
    ///
    /// Uses start time verification to detect PID reuse by the OS.
    /// Falls back to PID-only check for legacy records without start time.
    pub fn is_process_alive(&self) -> bool {
        if let Some(pid) = self.pid {
            crate::process::is_our_process(pid, self.pid_start_time)
        } else {
            false
        }
    }

    /// Get the actual state, checking if running process is still alive.
    pub fn actual_state(&self) -> RecordState {
        if self.state == RecordState::Running {
            if self.is_process_alive() {
                RecordState::Running
            } else {
                RecordState::Stopped // Process died
            }
        } else {
            self.state.clone()
        }
    }

    /// Convert stored mounts to HostMount format.
    pub fn host_mounts(&self) -> Vec<crate::data::storage::HostMount> {
        let mut live = self
            .mounts
            .iter()
            .map(|(host, guest, ro)| crate::data::storage::HostMount {
                source: std::path::PathBuf::from(host),
                target: std::path::PathBuf::from(guest),
                read_only: *ro,
                staged: false,
            })
            .collect::<std::collections::VecDeque<_>>();
        let staged = self
            .staged_mounts
            .iter()
            .map(|(index, host, guest)| {
                (
                    *index,
                    crate::data::storage::HostMount::from_staged_storage_tuple(
                        host.clone(),
                        guest.clone(),
                    ),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let total = live.len() + staged.len();
        let mut mounts = Vec::with_capacity(total);
        for index in 0..total {
            if let Some(mount) = staged.get(&index) {
                mounts.push(mount.clone());
            } else if let Some(mount) = live.pop_front() {
                mounts.push(mount);
            }
        }
        // Malformed records with duplicate/out-of-range staged indices remain
        // inspectable rather than silently dropping their live mounts.
        mounts.extend(live);
        mounts
    }

    /// Convert stored ports to PortMapping format.
    pub fn port_mappings(&self) -> Vec<crate::data::network::PortMapping> {
        self.ports
            .iter()
            .map(|(host, guest)| crate::data::network::PortMapping::new(*host, *guest))
            .collect()
    }

    /// Whether this machine's registry image must be fetched on the HOST before
    /// it boots: a REGISTRY reference, on a first boot, with no network.
    ///
    /// The pull normally runs inside the guest (the agent shells out to
    /// `crane`), so a machine with no network device cannot fetch its own image.
    /// Rather than refuse such a machine, the start path fetches the image on the
    /// host, which has network, and pins it as a local archive the guest
    /// flattens offline (see [`crate::image_store::fetch_image_archive`]). The
    /// machine itself never gets network.
    ///
    /// Deliberately narrow: only a registry reference needs fetching. A local
    /// archive or directory is already on the host, a `.smolmachine` has its
    /// layers extracted at create, and a checkpoint restore or branch resumes a
    /// guest whose image is already on its disks. A machine that has booted
    /// before keeps the image it pulled then.
    pub fn image_needs_host_fetch(&self) -> bool {
        if self.init_completed
            || self.source_smolmachine.is_some()
            || self.host_uid_owner.is_some()
            || self.vm_uid_owner().is_some()
            || self.golden.is_some()
        {
            return false;
        }
        let Some(image) = self.image.as_deref() else {
            return false;
        };
        // An ALREADY-RESOLVED local source persists as `local:<hash>` /
        // `local-dir:<path>`, and `classify` would read those as registry refs
        // (no `/`, `./` or archive suffix). Check the resolved form first.
        if crate::data::image_source::is_local_ref(image) {
            return false;
        }
        matches!(
            crate::data::image_source::classify(image),
            crate::data::image_source::ImageSource::Registry(_)
        ) && !self.launch_network_plan().has_network()
    }

    /// Whether this machine's image can be fetched. Always: a machine with no
    /// network has its registry image fetched on the host (see
    /// [`Self::image_needs_host_fetch`]). Kept so existing callers that check
    /// at create keep compiling.
    pub fn validate_image_fetchable(&self) -> crate::Result<()> {
        Ok(())
    }

    /// Boot from `local_ref`, a host-fetched copy of this machine's registry
    /// image, keeping the reference it came from as `image_origin`.
    pub fn pin_host_fetched_image(&mut self, local_ref: String) {
        if self.image_origin.is_none() {
            self.image_origin = self.image.take();
        }
        self.image = Some(local_ref);
    }

    /// The image to show for this machine: what the user asked for, even when
    /// it boots from a host-fetched copy.
    pub fn display_image(&self) -> Option<&str> {
        self.image_origin.as_deref().or(self.image.as_deref())
    }

    /// Remote volumes are mounted into the workload container's mount
    /// namespace, so there has to be a container: refuse configurations that
    /// can never mount at create instead of failing every start. Shared by the
    /// CLI and API create paths.
    pub fn validate_remote_volumes(&self) -> crate::Result<()> {
        if self.remote_volumes.is_empty() {
            return Ok(());
        }
        if self.image.is_none() {
            return Err(crate::Error::config(
                "create machine",
                "remote volumes require an image machine: they are mounted into \
                 the workload container's mount namespace",
            ));
        }
        let plan = self.launch_network_plan();
        if !plan.has_network() {
            return Err(crate::Error::config(
                "create machine",
                "remote volumes need network access: add --net (or an egress policy)",
            ));
        }
        Ok(())
    }

    /// Replace this machine's outbound network policy. The machine must be
    /// stopped; the caller persists the record.
    ///
    /// Host names are stored in the strict form (`api.github.com` exact,
    /// `*.github.com` subdomains only) and CIDRs normalized, with the same
    /// validation create applies. A credential binding must stay reachable under
    /// the new host list.
    ///
    /// A machine that resumes saved memory on its next start (restored from a
    /// checkpoint, or paused) keeps the network device it was saved with, so a
    /// policy that would need a different network backend is refused rather than
    /// booting a guest whose devices changed underneath it. Changing which
    /// hosts or addresses are allowed never needs one on such a machine: its
    /// backend is pinned.
    pub fn apply_egress_policy(&mut self, policy: &network::EgressPolicy) -> Result<()> {
        let cidrs = policy
            .cidrs
            .iter()
            .map(|cidr| crate::smolfile::parse_cidr(cidr))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|reason| crate::Error::config("egress policy", reason))?;
        let hosts = policy
            .hosts
            .iter()
            .map(|host| smolvm_protocol::host_pattern::encode_strict(host.trim()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|reason| crate::Error::config("egress policy", reason))?;
        self.replace_egress(policy.network, cidrs, hosts)
    }

    /// Replace this stopped machine's egress with normalized CIDRs and host
    /// entries as `dns_filter_hosts` stores them (bare legacy names, or
    /// strict-encoded patterns), under the same checks as
    /// [`Self::apply_egress_policy`]. Leaves the record unchanged on error.
    pub fn replace_egress(
        &mut self,
        network: bool,
        cidrs: Vec<String>,
        hosts: Vec<String>,
    ) -> Result<()> {
        let mut next = self.clone();
        next.network = network;
        next.allowed_cidrs = (!cidrs.is_empty()).then_some(cidrs);
        next.dns_filter_hosts = (!hosts.is_empty()).then_some(hosts);
        if let Some(credentials) = next.credential_policy.as_ref() {
            credentials
                .validate(next.dns_filter_hosts.as_deref())
                .map_err(|e| crate::Error::config("egress policy", e.to_string()))?;
        }
        let resumes_saved_memory =
            self.paused_checkpoint.is_some() || self.checkpoint_head.is_some();
        let before = self.launch_network_plan().backend;
        let after = next.launch_network_plan().backend;
        // An allow list (deny-all included) is enforced by virtio-net's
        // host-side stack only; on TSI it would be silently unenforced. A
        // machine pinned to TSI (explicitly, or by a checkpoint it resumes)
        // cannot take one.
        let restricted = next.allowed_cidrs.is_some() || next.dns_filter_hosts.is_some();
        if restricted && after == crate::network::EffectiveNetworkBackend::Tsi {
            return Err(crate::Error::config(
                "egress policy",
                format!(
                    "machine '{}' uses TSI networking, which cannot enforce an allow list; \
                     create it (or the machine its checkpoint came from) with the virtio-net backend",
                    self.name
                ),
            ));
        }
        if resumes_saved_memory && before != after {
            return Err(crate::Error::config(
                "egress policy",
                format!(
                    "machine '{}' resumes saved memory that was taken with {before:?} networking, \
                     and this policy needs {after:?}; keep networking on (use a deny-all policy \
                     rather than turning the network off), or recreate the machine",
                    self.name
                ),
            ));
        }
        *self = next;
        Ok(())
    }

    /// This record after one add/remove amendment of its egress allow list, or
    /// `None` when the update is empty. Hosts are stored as `machine create`
    /// stores them: `allow_hosts` bare (a name and its subdomains),
    /// `allow_host_patterns` strict-encoded. Removing the last entry would open
    /// egress to every host, so that needs `allow_all` to say so. Shared by
    /// `machine update` and the API's egress endpoint; the full replace-style
    /// checks (credentials, TSI, saved memory) run in [`Self::replace_egress`].
    pub fn updated_egress(&self, update: &EgressUpdate) -> Result<Option<VmRecord>> {
        use smolvm_protocol::host_pattern::encode_strict;
        if update.is_empty() {
            return Ok(None);
        }
        let mut hosts = self.dns_filter_hosts.clone().unwrap_or_default();
        let mut cidrs = self.allowed_cidrs.clone().unwrap_or_default();
        let was_restricted = !hosts.is_empty() || !cidrs.is_empty();

        for host in &update.remove_allow_hosts {
            let strict = encode_strict(host.trim()).ok();
            let before = hosts.len();
            hosts.retain(|stored| stored != host.trim() && Some(stored) != strict.as_ref());
            if hosts.len() == before {
                return Err(crate::Error::config(
                    "update",
                    format!("'{host}' is not in machine '{}''s allowed hosts", self.name),
                ));
            }
        }
        for cidr in &update.remove_allow_cidrs {
            let before = cidrs.len();
            cidrs.retain(|stored| stored != cidr);
            if cidrs.len() == before {
                return Err(crate::Error::config(
                    "update",
                    format!("'{cidr}' is not in machine '{}''s allowed CIDRs", self.name),
                ));
            }
        }
        for host in &update.allow_hosts {
            let host = host.trim();
            // Validate the name the way a pattern would be, then keep the bare
            // form for its apex-and-subdomains meaning.
            encode_strict(host).map_err(|e| crate::Error::config("allow host", e))?;
            if !hosts.iter().any(|stored| stored == host) {
                hosts.push(host.to_string());
            }
        }
        for pattern in &update.allow_host_patterns {
            let encoded = encode_strict(pattern.trim())
                .map_err(|e| crate::Error::config("allow host pattern", e))?;
            if !hosts.contains(&encoded) {
                hosts.push(encoded);
            }
        }
        for cidr in &update.allow_cidrs {
            if !cidrs.contains(cidr) {
                cidrs.push(cidr.clone());
            }
        }
        // `machine create --outbound-localhost-only` is sugar for these two
        // entries (see `resolve_egress_flags`); an update spells it the same way.
        if update.outbound_localhost_only {
            for cidr in ["127.0.0.0/8", "::1/128"] {
                if !cidrs.iter().any(|stored| stored == cidr) {
                    cidrs.push(cidr.to_string());
                }
            }
        }

        if was_restricted && hosts.is_empty() && cidrs.is_empty() && !update.allow_all {
            return Err(crate::Error::config(
                "update",
                "removing the last allowed host or CIDR would allow egress to every host; \
                 say so explicitly (--net on the CLI, allowAll on the API), or turn \
                 networking off instead",
            ));
        }
        let mut next = self.clone();
        next.replace_egress(true, cidrs, hosts)?;
        Ok(Some(next))
    }

    /// The network this machine launches with. A credential policy steers the
    /// default backend to virtio-net, so anything that records or checks the
    /// backend (validation, checkpoint capture) must plan it the same way the
    /// launcher does, or a restore rebuilds a different device set.
    pub fn launch_network_plan(&self) -> crate::network::LaunchNetworkPlan {
        crate::network::plan_launch_network_with(
            &self.vm_resources(),
            self.dns_filter_hosts.as_deref(),
            self.ports.len(),
            self.credential_policy.is_some(),
        )
    }

    /// Convert record fields to VmResources.
    pub fn vm_resources(&self) -> crate::agent::VmResources {
        crate::agent::VmResources {
            cpus: self.cpus,
            memory_mib: self.mem,
            network: self.network,
            network_backend: self.network_backend,
            gpu: self.gpu.unwrap_or(false),
            gpu_vram_mib: self.gpu_vram_mib,
            cuda: self.cuda,
            nested_virt: self.nested_virt.unwrap_or(false),
            rosetta: self.rosetta.unwrap_or(false),
            storage_gib: self.storage_gb,
            overlay_gib: self.overlay_gb,
            block_io: self.block_io,
            disks: self.disks.clone(),
            allowed_cidrs: self.allowed_cidrs.clone(),
            dns: self.dns,
            network_name: self.network_name.clone(),
            guest_subnet: self.guest_subnet.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine with `image`, and whatever networking the args describe.
    fn rec_with_image(image: &str, network: bool, ports: Vec<(u16, u16)>) -> VmRecord {
        let mut r = VmRecord::new("m".to_string(), 1, 512, vec![], ports, network);
        r.image = Some(image.to_string());
        r
    }

    #[test]
    fn updated_egress_merges_dedupes_and_guards_the_last_entry() {
        let mut record = VmRecord::new("e".to_string(), 1, 512, vec![], vec![], true);
        record.allowed_cidrs = Some(vec!["10.0.0.0/8".to_string()]);

        // Empty update is a no-op signal, not an error.
        assert!(record
            .updated_egress(&EgressUpdate::default())
            .unwrap()
            .is_none());

        // Adds merge and never duplicate; hosts store bare, patterns encoded.
        let next = record
            .updated_egress(&EgressUpdate {
                allow_cidrs: vec!["10.0.0.0/8".to_string(), "1.1.1.1/32".to_string()],
                allow_hosts: vec!["example.com".to_string()],
                ..Default::default()
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            next.allowed_cidrs.as_deref(),
            Some(["10.0.0.0/8".to_string(), "1.1.1.1/32".to_string()].as_slice())
        );
        assert_eq!(
            next.dns_filter_hosts.as_deref(),
            Some(["example.com".to_string()].as_slice())
        );

        // Removing an entry that is not there names the problem.
        let err = record
            .updated_egress(&EgressUpdate {
                remove_allow_cidrs: vec!["9.9.9.9/32".to_string()],
                ..Default::default()
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("9.9.9.9/32"), "{err}");

        // Removing the last entry needs allow_all to open egress on purpose.
        let last = EgressUpdate {
            remove_allow_cidrs: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        };
        assert!(record.updated_egress(&last).is_err());
        let opened = record
            .updated_egress(&EgressUpdate {
                allow_all: true,
                ..last
            })
            .unwrap()
            .unwrap();
        assert!(opened.allowed_cidrs.is_none());
        assert!(opened.network);
    }

    // `create` used to accept this and every `start` died with a raw Go DNS
    // error, because the pull runs inside a guest that has no network. Later it
    // was refused outright, which left no way to isolate a registry image. Now
    // the host fetches it.
    #[test]
    fn a_registry_image_with_no_network_is_fetched_on_the_host() {
        assert!(rec_with_image("alpine", false, vec![]).image_needs_host_fetch());
        assert!(rec_with_image(
            "alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507",
            false,
            vec![]
        )
        .image_needs_host_fetch());
    }

    #[test]
    fn granting_network_any_way_leaves_the_pull_to_the_guest() {
        // Explicit --net.
        assert!(!rec_with_image("alpine", true, vec![]).image_needs_host_fetch());
        // A published port implicitly enables networking.
        assert!(!rec_with_image("alpine", false, vec![(8080, 80)]).image_needs_host_fetch());
        // An egress policy also forces a network backend.
        let mut cidr = rec_with_image("alpine", false, vec![]);
        cidr.allowed_cidrs = Some(vec!["10.0.0.0/8".to_string()]);
        assert!(!cidr.image_needs_host_fetch());
        let mut dns = rec_with_image("alpine", false, vec![]);
        dns.dns_filter_hosts = Some(vec!["example.com".to_string()]);
        assert!(!dns.image_needs_host_fetch());
    }

    // These resolve from bytes the host already has.
    #[test]
    fn locally_sourced_images_need_no_fetch() {
        for local in [
            "-",
            "./img.tar",
            "/tmp/img.tar.gz",
            "img.tgz",
            // As they are PERSISTED after `resolve` rewrites them. These carry no
            // path prefix or archive suffix, so `classify` calls them registry
            // refs.
            "local:9f2b1c",
            "local-dir:/srv/rootfs",
        ] {
            assert!(
                !rec_with_image(local, false, vec![]).image_needs_host_fetch(),
                "{local} is already on the host"
            );
        }
    }

    #[test]
    fn a_machine_with_no_image_needs_no_fetch() {
        assert!(
            !VmRecord::new("m".to_string(), 1, 512, vec![], vec![], false).image_needs_host_fetch()
        );
    }

    #[test]
    fn a_smolmachine_source_needs_no_fetch_even_though_it_names_a_registry_image() {
        // The create path sets BOTH fields for an artifact-sourced machine: the
        // layers come from the `.smolmachine`, and `image` is provenance.
        let mut r = rec_with_image("alpine:3.20", false, vec![]);
        r.source_smolmachine = Some("library/alpine:latest".to_string());
        assert!(!r.image_needs_host_fetch());
    }

    #[test]
    fn a_checkpoint_restore_needs_no_fetch_even_though_it_names_a_registry_image() {
        // A restored guest's RAM and disks come from the checkpoint.
        let mut r = rec_with_image("alpine:3.20", false, vec![]);
        r.host_uid_owner = Some("restored".to_string());
        assert!(!r.image_needs_host_fetch());
    }

    #[test]
    fn a_machine_that_has_booted_keeps_the_image_it_has() {
        let mut r = rec_with_image("alpine:3.20", false, vec![]);
        r.init_completed = true;
        assert!(!r.image_needs_host_fetch());
    }

    #[test]
    fn a_pinned_copy_boots_while_the_origin_is_what_shows() {
        let mut r = rec_with_image("alpine:3.20", false, vec![]);
        r.pin_host_fetched_image("local:abc".to_string());
        assert_eq!(r.image.as_deref(), Some("local:abc"));
        assert_eq!(r.display_image(), Some("alpine:3.20"));
        assert!(
            !r.image_needs_host_fetch(),
            "a pinned copy is never fetched again"
        );
        // Re-pinning keeps the first origin, not the previous local copy.
        r.pin_host_fetched_image("local:def".to_string());
        assert_eq!(r.image_origin.as_deref(), Some("alpine:3.20"));
    }

    #[test]
    fn test_vm_record_serialization() {
        let mut record = VmRecord::new(
            "test".to_string(),
            2,
            512,
            vec![("/host".to_string(), "/guest".to_string(), false)],
            vec![(8080, 80)],
            false,
        );

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: VmRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, record.name);
        assert_eq!(deserialized.mounts, record.mounts);
        assert!(!deserialized.external_interceptor_required);

        record.external_interceptor_required = true;
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: VmRecord = serde_json::from_str(&json).unwrap();
        assert!(deserialized.external_interceptor_required);
    }

    #[test]
    fn test_vm_record_secret_refs_roundtrip() {
        use crate::secrets::SecretRef;
        let mut record = VmRecord::new("r".into(), 1, 256, vec![], vec![], false);
        record.secret_refs.insert(
            "TLS_KEY".into(),
            SecretRef {
                from_env: None,
                from_file: Some("/run/secrets/tls.key".into()),
            },
        );
        record.secret_refs.insert(
            "DB_URL".into(),
            SecretRef {
                from_env: Some("PROD_DB".into()),
                from_file: None,
            },
        );

        let json = serde_json::to_string(&record).unwrap();
        // Ref metadata — not sensitive — roundtrips through serde_json.
        assert!(json.contains("TLS_KEY"));
        assert!(json.contains("PROD_DB"));

        let back: VmRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.secret_refs.len(), 2);
        assert_eq!(
            back.secret_refs["TLS_KEY"]
                .from_file
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            Some("/run/secrets/tls.key".to_string())
        );
        assert_eq!(
            back.secret_refs["DB_URL"].from_env.as_deref(),
            Some("PROD_DB")
        );
    }

    #[test]
    fn test_vm_record_with_restart() {
        let restart = RestartConfig {
            policy: RestartPolicy::Always,
            max_retries: 5,
            ..Default::default()
        };
        let record =
            VmRecord::new_with_restart("test".to_string(), 2, 512, vec![], vec![], false, restart);

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: VmRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.restart.policy, RestartPolicy::Always);
        assert_eq!(deserialized.restart.max_retries, 5);
    }

    #[test]
    fn test_record_state_display() {
        assert_eq!(RecordState::Created.to_string(), "created");
        assert_eq!(RecordState::Running.to_string(), "running");
        assert_eq!(RecordState::Stopped.to_string(), "stopped");
        assert_eq!(RecordState::Failed.to_string(), "failed");
    }

    #[test]
    fn test_restart_policy_display_and_parse() {
        assert_eq!(RestartPolicy::Never.to_string(), "never");
        assert_eq!(RestartPolicy::Always.to_string(), "always");
        assert_eq!(RestartPolicy::OnFailure.to_string(), "on-failure");
        assert_eq!(RestartPolicy::UnlessStopped.to_string(), "unless-stopped");

        assert_eq!(
            "never".parse::<RestartPolicy>().unwrap(),
            RestartPolicy::Never
        );
        assert_eq!(
            "always".parse::<RestartPolicy>().unwrap(),
            RestartPolicy::Always
        );
        assert_eq!(
            "on-failure".parse::<RestartPolicy>().unwrap(),
            RestartPolicy::OnFailure
        );
        assert_eq!(
            "unless-stopped".parse::<RestartPolicy>().unwrap(),
            RestartPolicy::UnlessStopped
        );
    }

    #[test]
    fn test_restart_policy_serialization() {
        let policy = RestartPolicy::OnFailure;
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, "\"on-failure\"");

        let deserialized: RestartPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, RestartPolicy::OnFailure);
    }

    #[test]
    fn test_restart_config_default() {
        let config = RestartConfig::default();
        assert_eq!(config.policy, RestartPolicy::Never);
        assert_eq!(config.max_retries, 0);
        assert_eq!(config.restart_count, 0);
        assert!(!config.user_stopped);
    }

    #[test]
    fn test_should_restart() {
        // (policy, max_retries, restart_count, user_stopped, last_exit_code, expected, desc)
        let cases = [
            (
                RestartPolicy::Never,
                0,
                0,
                false,
                None,
                false,
                "never policy",
            ),
            (
                RestartPolicy::Always,
                0,
                5,
                false,
                None,
                true,
                "always policy",
            ),
            (
                RestartPolicy::Always,
                3,
                3,
                false,
                None,
                false,
                "max retries reached",
            ),
            (
                RestartPolicy::Always,
                3,
                2,
                false,
                None,
                true,
                "under max retries",
            ),
            (
                RestartPolicy::OnFailure,
                0,
                0,
                false,
                Some(1),
                true,
                "on-failure non-zero exit",
            ),
            (
                RestartPolicy::OnFailure,
                0,
                0,
                false,
                Some(0),
                false,
                "on-failure clean exit",
            ),
            (
                RestartPolicy::OnFailure,
                0,
                0,
                false,
                None,
                true,
                "on-failure unknown exit",
            ),
            (
                RestartPolicy::UnlessStopped,
                0,
                0,
                false,
                None,
                true,
                "unless-stopped running",
            ),
            (
                RestartPolicy::UnlessStopped,
                0,
                0,
                true,
                None,
                false,
                "unless-stopped user stopped",
            ),
            // An explicit user stop suppresses restart for every policy, not just
            // unless-stopped — otherwise always/on-failure machines can't be stopped.
            (
                RestartPolicy::Always,
                0,
                0,
                true,
                None,
                false,
                "always but user stopped",
            ),
            (
                RestartPolicy::OnFailure,
                0,
                0,
                true,
                Some(1),
                false,
                "on-failure non-zero but user stopped",
            ),
        ];

        for (policy, max_retries, restart_count, user_stopped, last_exit_code, expected, desc) in
            cases
        {
            let config = RestartConfig {
                policy,
                max_retries,
                restart_count,
                user_stopped,
                ..Default::default()
            };
            assert_eq!(config.should_restart(last_exit_code), expected, "{}", desc);
        }
    }

    #[test]
    fn test_backoff_duration() {
        use std::time::Duration;
        let make = |count| RestartConfig {
            restart_count: count,
            ..Default::default()
        };
        assert_eq!(make(0).backoff_duration(), Duration::from_secs(1));
        assert_eq!(make(1).backoff_duration(), Duration::from_secs(2));
        assert_eq!(make(2).backoff_duration(), Duration::from_secs(4));
        assert_eq!(make(3).backoff_duration(), Duration::from_secs(8));
        assert_eq!(make(8).backoff_duration(), Duration::from_secs(256));
        // Exponent capped at 8 → 256s for any count >= 8
        assert_eq!(make(9).backoff_duration(), Duration::from_secs(256));
        assert_eq!(make(100).backoff_duration(), Duration::from_secs(256));
    }

    #[test]
    fn test_backoff_duration_respects_max_backoff() {
        use std::time::Duration;
        let config = RestartConfig {
            restart_count: 8,
            max_backoff_secs: 30,
            ..Default::default()
        };
        // 2^8 = 256, but capped at 30s
        assert_eq!(config.backoff_duration(), Duration::from_secs(30));
    }

    // ========================================================================
    // Resize-related tests
    // ========================================================================

    #[test]
    fn test_vm_record_storage_overlay_fields() {
        // Test that storage_gb and overlay_gb fields work correctly
        let mut record = VmRecord::new("test-vm".to_string(), 1, 512, vec![], vec![], false);

        // Initially None (uses defaults)
        assert!(record.storage_gb.is_none());
        assert!(record.overlay_gb.is_none());

        // Set storage_gb
        record.storage_gb = Some(50);
        assert_eq!(record.storage_gb, Some(50));

        // Set overlay_gb
        record.overlay_gb = Some(20);
        assert_eq!(record.overlay_gb, Some(20));
    }

    #[test]
    fn test_vm_record_partial_update() {
        // Test that we can update only some fields (partial update pattern)
        let mut record = VmRecord::new("test-vm".to_string(), 1, 512, vec![], vec![], false);
        record.storage_gb = Some(20);
        record.overlay_gb = Some(10);

        // Simulate partial update - only storage changes
        let new_storage_gb: Option<u64> = Some(50);
        let new_overlay_gb: Option<u64> = None;

        if let Some(s) = new_storage_gb {
            record.storage_gb = Some(s);
        }
        if let Some(o) = new_overlay_gb {
            record.overlay_gb = Some(o);
        }

        assert_eq!(record.storage_gb, Some(50));
        assert_eq!(record.overlay_gb, Some(10)); // Unchanged
    }

    #[test]
    fn test_vm_record_vm_resources_includes_storage() {
        // Test that vm_resources() includes storage_gb and overlay_gb
        let mut record = VmRecord::new("test-vm".to_string(), 2, 1024, vec![], vec![], false);
        record.storage_gb = Some(50);
        record.overlay_gb = Some(20);

        let resources = record.vm_resources();
        assert_eq!(resources.cpus, 2);
        assert_eq!(resources.memory_mib, 1024);
        assert_eq!(resources.storage_gib, Some(50));
        assert_eq!(resources.overlay_gib, Some(20));
    }

    #[test]
    fn test_vm_record_serialization_with_storage_overlay() {
        // Test that storage_gb and overlay_gb serialize/deserialize correctly
        let mut record = VmRecord::new("test-vm".to_string(), 1, 512, vec![], vec![], false);
        record.storage_gb = Some(50);
        record.overlay_gb = Some(20);

        let json = serde_json::to_string(&record).unwrap();

        // Verify fields are in JSON
        assert!(json.contains("storage_gb"));
        assert!(json.contains("overlay_gb"));
        assert!(json.contains("50"));
        assert!(json.contains("20"));

        let deserialized: VmRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.storage_gb, Some(50));
        assert_eq!(deserialized.overlay_gb, Some(20));
    }

    /// Attached disks must survive the record: `start` re-attaches from the
    /// record, so a disk that round-trips badly silently disappears on restart.
    #[test]
    fn attached_disks_round_trip_and_default_to_empty() {
        let legacy = r#"{"name":"legacy"}"#;
        let record: VmRecord = serde_json::from_str(legacy).unwrap();
        assert!(
            record.disks.is_empty(),
            "a record predating --disk has none"
        );

        let mut record = VmRecord::new("db".to_string(), 2, 512, vec![], vec![], false);
        record.disks = vec![
            crate::data::disk::AttachedDisk {
                path: std::path::PathBuf::from("/dev/nvme1n1"),
                read_only: false,
            },
            crate::data::disk::AttachedDisk {
                path: std::path::PathBuf::from("/srv/golden.img"),
                read_only: true,
            },
        ];
        let decoded: VmRecord =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(decoded.disks, record.disks, "order and mode are preserved");
        assert_eq!(
            decoded.vm_resources().disks,
            record.disks,
            "and they reach the launcher through vm_resources()"
        );
    }

    #[test]
    fn block_io_defaults_to_sync_and_round_trips_async() {
        let legacy = r#"{"name":"legacy"}"#;
        let record: VmRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(record.block_io, crate::data::resources::BlockIoEngine::Sync);

        let mut record = VmRecord::new("queued".to_string(), 2, 512, vec![], vec![], false);
        record.block_io = crate::data::resources::BlockIoEngine::Async;
        let decoded: VmRecord =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(decoded.block_io, record.block_io);
        assert_eq!(decoded.vm_resources().block_io, record.block_io);
    }

    #[test]
    fn test_vm_record_gpu_field() {
        // GPU defaults to None (not set)
        let record = VmRecord::new("test".to_string(), 2, 1024, vec![], vec![], false);
        assert_eq!(record.gpu, None);
        assert!(!record.vm_resources().gpu);

        // GPU set to true
        let mut record = VmRecord::new("test".to_string(), 2, 1024, vec![], vec![], false);
        record.gpu = Some(true);
        assert!(record.vm_resources().gpu);

        // GPU serializes/deserializes
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: VmRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.gpu, Some(true));

        // New records default to gpu = None → vm_resources().gpu = false
        let default_record = VmRecord::new("default".to_string(), 1, 512, vec![], vec![], false);
        assert_eq!(default_record.gpu, None);
        assert!(!default_record.vm_resources().gpu);
    }

    #[test]
    fn cuda_fork_capacity_policy_roundtrips_and_defaults_absent() {
        let mut record = VmRecord::new("cuda-pool".to_string(), 4, 4096, vec![], vec![], false);
        record.cuda = true;
        record.forkable = true;
        record.cuda_fork_pool_size = Some(4);
        record.cuda_vram_limit_mib = Some(10240);
        record.cuda_preload_modules = true;

        let encoded = serde_json::to_vec(&record).unwrap();
        let decoded: VmRecord = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.forkable_on_start());
        assert_eq!(decoded.cuda_fork_pool_size, Some(4));
        assert_eq!(decoded.cuda_vram_limit_mib, Some(10240));
        assert!(decoded.cuda_preload_modules);

        let mut legacy_value = serde_json::to_value(VmRecord::new(
            "legacy".to_string(),
            1,
            512,
            vec![],
            vec![],
            false,
        ))
        .unwrap();
        let legacy_object = legacy_value.as_object_mut().unwrap();
        legacy_object.remove("cuda_fork_pool_size");
        legacy_object.remove("cuda_vram_limit_mib");
        legacy_object.remove("cuda_preload_modules");
        legacy_object.remove("forkable");
        let legacy: VmRecord = serde_json::from_value(legacy_value).unwrap();
        assert_eq!(legacy.cuda_fork_pool_size, None);
        assert_eq!(legacy.cuda_vram_limit_mib, None);
        assert!(!legacy.cuda_preload_modules);
        assert!(!legacy.forkable_on_start());
    }

    #[test]
    fn legacy_cuda_pool_implies_forkable_only_for_a_golden() {
        let mut golden = VmRecord::new("golden".to_string(), 4, 4096, vec![], vec![], false);
        golden.cuda_fork_pool_size = Some(8);
        assert!(golden.forkable_on_start());

        let mut clone = golden.clone();
        clone.name = "clone".to_string();
        clone.golden = Some("golden".to_string());
        assert!(!clone.forkable_on_start());
    }

    #[test]
    fn held_fork_state_roundtrips_and_legacy_records_default_released() {
        let mut record = VmRecord::new("slot-0".to_string(), 2, 1024, vec![], vec![], false);
        record.golden = Some("golden".to_string());
        record.fork_overlay_owner = Some("root".to_string());
        record.host_uid_owner = Some("local-restore".to_string());
        record.forkpoint_held = true;
        record.fork_env = vec![("SMOLVM_FORK_INDEX".to_string(), "0".to_string())];

        let encoded = serde_json::to_value(&record).unwrap();
        let decoded: VmRecord = serde_json::from_value(encoded.clone()).unwrap();
        assert!(decoded.forkpoint_held);
        assert_eq!(decoded.fork_env, record.fork_env);
        assert_eq!(decoded.fork_overlay_owner.as_deref(), Some("root"));
        assert_eq!(decoded.vm_uid_owner(), Some("local-restore"));
        let mut child = decoded.clone();
        child.name = "nested".to_string();
        child.golden = Some(decoded.name.clone());
        assert_eq!(child.vm_uid_owner(), Some("local-restore"));

        let mut legacy_value = encoded;
        let legacy_object = legacy_value.as_object_mut().unwrap();
        legacy_object.remove("forkpoint_held");
        legacy_object.remove("fork_env");
        legacy_object.remove("fork_overlay_owner");
        legacy_object.remove("host_uid_owner");
        let legacy: VmRecord = serde_json::from_value(legacy_value).unwrap();
        assert!(!legacy.forkpoint_held);
        assert!(legacy.fork_env.is_empty());
        assert!(legacy.fork_overlay_owner.is_none());
    }

    #[test]
    fn vm_record_gpu_vram_mib_flows_through_full_persistence_cycle() {
        // End-to-end plumbing test:
        //   CreateVmParams-like assignment → VmRecord → serde_json (DB)
        //   → deserialized VmRecord → vm_resources() → effective
        //
        // This is the chain that runs every time a user creates a
        // machine with `--gpu-vram N`, stops it, and starts it again.
        // A silent break anywhere in the chain (e.g., someone drops
        // the assignment, adds a new field and forgets to copy it,
        // changes the Option<u32> shape) fires this test.

        use crate::agent::VmResources;

        // 1. Start with a record, set the field the way `create_vm` does.
        let mut record = VmRecord::new("vramtest".into(), 2, 1024, vec![], vec![], false);
        record.gpu = Some(true);
        record.gpu_vram_mib = Some(1024);

        // 2. Roundtrip through JSON (the redb value format).
        let json = serde_json::to_vec(&record).unwrap();
        let back: VmRecord = serde_json::from_slice(&json).unwrap();
        assert_eq!(
            back.gpu_vram_mib,
            Some(1024),
            "gpu_vram_mib must survive DB roundtrip"
        );

        // 3. Convert to VmResources the way `start_vm_named` does.
        let res: VmResources = back.vm_resources();
        assert_eq!(res.gpu_vram_mib, Some(1024));
        assert_eq!(
            res.effective_gpu_vram_mib(),
            1024,
            "launcher will pass 1024 MiB to krun_set_gpu_options2"
        );

        // 4. And the unset path: default in, default out.
        let mut record = VmRecord::new("vramdefault".into(), 1, 512, vec![], vec![], false);
        record.gpu = Some(true);
        // gpu_vram_mib left as None
        let json = serde_json::to_vec(&record).unwrap();
        let back: VmRecord = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.gpu_vram_mib, None);
        assert_eq!(
            back.vm_resources().effective_gpu_vram_mib(),
            crate::data::resources::DEFAULT_GPU_VRAM_MIB,
        );
    }

    fn networked(name: &str) -> VmRecord {
        VmRecord::new(name.into(), 1, 512, vec![], vec![], true)
    }

    #[test]
    fn an_egress_policy_stores_strict_hosts_and_normalized_cidrs() {
        let mut record = networked("hosts");
        record
            .apply_egress_policy(&network::EgressPolicy::hosts([
                "github.com",
                "*.github.com",
            ]))
            .unwrap();
        assert_eq!(
            record.dns_filter_hosts,
            Some(vec!["=github.com".to_string(), "*.github.com".to_string()])
        );
        assert_eq!(record.allowed_cidrs, None);
        assert!(record.network);

        record
            .apply_egress_policy(&network::EgressPolicy::deny_all())
            .unwrap();
        assert_eq!(record.dns_filter_hosts, None);
        assert_eq!(
            record.allowed_cidrs,
            Some(vec!["127.0.0.0/8".to_string(), "::1/128".to_string()])
        );

        record
            .apply_egress_policy(&network::EgressPolicy::allow_all())
            .unwrap();
        assert_eq!(
            (
                record.allowed_cidrs.clone(),
                record.dns_filter_hosts.clone()
            ),
            (None, None)
        );
    }

    #[test]
    fn an_invalid_host_or_cidr_leaves_the_record_untouched() {
        let mut record = networked("invalid");
        record
            .apply_egress_policy(&network::EgressPolicy::hosts(["example.com"]))
            .unwrap();
        let before = record.clone();
        for bad in [
            network::EgressPolicy::hosts(["not a host"]),
            network::EgressPolicy {
                network: true,
                cidrs: vec!["10.0.0.0/33".into()],
                hosts: vec![],
            },
        ] {
            assert!(record.apply_egress_policy(&bad).is_err());
            assert_eq!(record.dns_filter_hosts, before.dns_filter_hosts);
            assert_eq!(record.allowed_cidrs, before.allowed_cidrs);
        }
    }

    #[test]
    fn a_machine_resuming_saved_memory_keeps_its_network_device() {
        // Restored from a checkpoint taken with virtio-net: the backend is
        // pinned, so any allow list is fine, but turning networking off would
        // remove the device the saved guest expects.
        let mut restored = networked("restored");
        restored.network_backend = Some(NetworkBackend::VirtioNet);
        restored.checkpoint_head = Some("gen-1".into());
        restored
            .apply_egress_policy(&network::EgressPolicy::hosts(["api.github.com"]))
            .unwrap();
        restored
            .apply_egress_policy(&network::EgressPolicy::deny_all())
            .unwrap();
        restored
            .apply_egress_policy(&network::EgressPolicy::allow_all())
            .unwrap();
        let err = restored
            .apply_egress_policy(&network::EgressPolicy::default())
            .unwrap_err();
        assert!(err.to_string().contains("resumes saved memory"), "{err}");
        assert!(restored.network, "a refused policy changes nothing");

        // Saved with TSI (the outbound-only default), an allow list would need
        // virtio-net: refused. A machine with no saved memory may switch.
        let mut tsi = networked("tsi");
        tsi.paused_checkpoint = Some("saved.smolcheckpoint".into());
        assert!(tsi
            .apply_egress_policy(&network::EgressPolicy::hosts(["example.com"]))
            .is_err());
        // Restored from a TSI checkpoint, the backend is pinned to TSI, which
        // cannot enforce an allow list or deny-all: refused, not silently open.
        let mut pinned_tsi = networked("pinned-tsi");
        pinned_tsi.network_backend = Some(NetworkBackend::Tsi);
        pinned_tsi.checkpoint_head = Some("gen-1".into());
        for policy in [
            network::EgressPolicy::hosts(["example.com"]),
            network::EgressPolicy::deny_all(),
        ] {
            let err = pinned_tsi.apply_egress_policy(&policy).unwrap_err();
            assert!(
                err.to_string().contains("cannot enforce an allow list"),
                "{err}"
            );
        }
        pinned_tsi
            .apply_egress_policy(&network::EgressPolicy::allow_all())
            .unwrap();
        let mut fresh = networked("fresh");
        fresh
            .apply_egress_policy(&network::EgressPolicy::hosts(["example.com"]))
            .unwrap();
    }

    #[test]
    fn a_credential_host_must_stay_reachable_under_a_new_allow_list() {
        let mut record = networked("credentialed");
        record.credential_policy = Some(
            serde_json::from_str(
                r#"{"credentials":[{"name":"gh","environment_variable":"GH_TOKEN","allowed_hosts":["api.github.com"]}]}"#,
            )
            .unwrap(),
        );
        record
            .apply_egress_policy(&network::EgressPolicy::hosts(["*.github.com"]))
            .unwrap();
        assert!(record
            .apply_egress_policy(&network::EgressPolicy::hosts(["example.com"]))
            .is_err());
    }
}
