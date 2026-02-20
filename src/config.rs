//! Global smolvm configuration.
//!
//! This module handles persistent configuration storage for smolvm,
//! including default settings and VM registry.
//!
//! State is persisted to a redb database at `~/.local/share/smolvm/server/smolvm.redb`.
//! For backward compatibility, `SmolvmConfig` maintains an in-memory cache of VMs
//! and provides the same API as the old confy-based implementation.

use crate::db::SmolvmDb;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    /// VM crashed or error.
    Failed,
}

impl std::fmt::Display for RecordState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordState::Created => write!(f, "created"),
            RecordState::Running => write!(f, "running"),
            RecordState::Stopped => write!(f, "stopped"),
            RecordState::Failed => write!(f, "failed"),
        }
    }
}

/// Restart policy for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Never restart the sandbox automatically.
    #[default]
    Never,
    /// Always restart the sandbox when it exits.
    Always,
    /// Restart only if the sandbox exited with a non-zero exit code.
    OnFailure,
    /// Restart unless the user explicitly stopped the sandbox.
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

/// Restart configuration for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RestartConfig {
    /// The restart policy.
    #[serde(default)]
    pub policy: RestartPolicy,
    /// Maximum number of restart attempts (0 = unlimited).
    #[serde(default)]
    pub max_retries: u32,
    /// Current restart count.
    #[serde(default)]
    pub restart_count: u32,
    /// Whether the user explicitly stopped this sandbox.
    #[serde(default)]
    pub user_stopped: bool,
}

/// Default vCPU count for new VMs.
pub const DEFAULT_VM_CPUS: u8 = 1;
/// Default memory in MiB for new VMs.
pub const DEFAULT_VM_MEMORY_MIB: u32 = 512;
/// Default DNS server for VMs with network egress.
pub const DEFAULT_DNS: &str = "1.1.1.1";

/// Global smolvm configuration with database-backed persistence.
///
/// This struct provides backward-compatible access to VM records while
/// using redb for ACID-compliant storage. The `vms` field is an in-memory
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
    /// Registry of known VMs (by name) - in-memory cache.
    pub vms: HashMap<String, VmRecord>,
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
            default_cpus: DEFAULT_VM_CPUS,
            default_mem: DEFAULT_VM_MEMORY_MIB,
            default_dns: DEFAULT_DNS.to_string(),
            #[cfg(target_os = "macos")]
            storage_volume: String::new(),
            vms: HashMap::new(),
        })
    }
}

impl SmolvmConfig {
    /// Load configuration from the database.
    ///
    /// Opens the database and loads all VM records into the in-memory cache.
    /// If this is the first run and an old confy config exists, it will be
    /// migrated automatically.
    pub fn load() -> Result<Self> {
        let db = SmolvmDb::open()?;

        // Load global config settings with defaults
        let version = db
            .get_config("version")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let default_cpus = db
            .get_config("default_cpus")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_VM_CPUS);
        let default_mem = db
            .get_config("default_mem")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_VM_MEMORY_MIB);
        let default_dns = db
            .get_config("default_dns")?
            .unwrap_or_else(|| DEFAULT_DNS.to_string());

        #[cfg(target_os = "macos")]
        let storage_volume = db.get_config("storage_volume")?.unwrap_or_default();

        // Load all VMs into cache
        let vms = db.load_all_vms()?;

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

    /// Close the database, releasing the file lock.
    ///
    /// The in-memory VM cache remains valid but no further DB operations
    /// are possible. Call this before long-running operations so other
    /// smolvm processes can access the database.
    pub fn close_db(&self) {
        self.db.close();
    }

    /// Save configuration to the database.
    ///
    /// This is now a no-op for VM records since writes are immediate.
    /// Global config changes are persisted here.
    pub fn save(&self) -> Result<()> {
        // Persist global config settings
        self.db.set_config("version", &self.version.to_string())?;
        self.db
            .set_config("default_cpus", &self.default_cpus.to_string())?;
        self.db
            .set_config("default_mem", &self.default_mem.to_string())?;
        self.db.set_config("default_dns", &self.default_dns)?;

        #[cfg(target_os = "macos")]
        if !self.storage_volume.is_empty() {
            self.db.set_config("storage_volume", &self.storage_volume)?;
        }

        Ok(())
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

    /// List all VM records.
    pub fn list_vms(&self) -> impl Iterator<Item = (&String, &VmRecord)> {
        self.vms.iter()
    }

    /// Update a VM record in place (persists immediately to database).
    pub fn update_vm<F>(&mut self, id: &str, f: F) -> Option<()>
    where
        F: FnOnce(&mut VmRecord),
    {
        if let Some(record) = self.vms.get_mut(id) {
            f(record);
            // Persist to database
            if let Err(e) = self.db.insert_vm(id, record) {
                tracing::warn!(error = %e, vm = %id, "failed to persist VM update");
            }
            Some(())
        } else {
            None
        }
    }

    /// Get the underlying database handle.
    pub fn db(&self) -> &SmolvmDb {
        &self.db
    }
}

/// Record of a VM in the registry.
///
/// This stores microvm configuration only. Container configuration
/// is managed separately via the container commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRecord {
    /// VM name/ID.
    pub name: String,

    /// Creation timestamp.
    pub created_at: String,

    /// VM lifecycle state.
    #[serde(default)]
    pub state: RecordState,

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

    /// Volume mounts (host_path, guest_path, read_only).
    #[serde(default)]
    pub mounts: Vec<(String, String, bool)>,

    /// Port mappings (host_port, guest_port).
    #[serde(default)]
    pub ports: Vec<(u16, u16)>,

    /// Enable outbound network access (TSI).
    #[serde(default)]
    pub network: bool,

    /// Restart configuration.
    #[serde(default)]
    pub restart: RestartConfig,

    /// Last exit code from the VM process.
    #[serde(default)]
    pub last_exit_code: Option<i32>,

    /// Commands to run on every VM start (via `sh -c`).
    #[serde(default)]
    pub init: Vec<String>,

    /// Environment variables for init commands.
    #[serde(default)]
    pub env: Vec<(String, String)>,

    /// Working directory for init commands.
    #[serde(default)]
    pub workdir: Option<String>,

    /// Storage disk size in GiB (None = default 20 GiB).
    #[serde(default)]
    pub storage_gb: Option<u64>,

    /// Overlay disk size in GiB (None = default 2 GiB).
    #[serde(default)]
    pub overlay_gb: Option<u64>,

    /// Allowed egress CIDRs for network policy.
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
}

fn default_cpus() -> u8 {
    1
}

fn default_mem() -> u32 {
    512
}

impl VmRecord {
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
            pid: None,
            pid_start_time: None,
            cpus,
            mem,
            mounts,
            ports,
            network,
            restart: RestartConfig::default(),
            last_exit_code: None,
            init: Vec::new(),
            env: Vec::new(),
            workdir: None,
            storage_gb: None,
            overlay_gb: None,
            allow_cidrs: Vec::new(),
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
            pid: None,
            pid_start_time: None,
            cpus,
            mem,
            mounts,
            ports,
            network,
            restart,
            last_exit_code: None,
            init: Vec::new(),
            env: Vec::new(),
            workdir: None,
            storage_gb: None,
            overlay_gb: None,
            allow_cidrs: Vec::new(),
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
    pub fn host_mounts(&self) -> Vec<crate::vm::config::HostMount> {
        self.mounts
            .iter()
            .map(|(host, guest, ro)| crate::vm::config::HostMount {
                source: std::path::PathBuf::from(host),
                target: std::path::PathBuf::from(guest),
                read_only: *ro,
            })
            .collect()
    }

    /// Convert stored ports to PortMapping format.
    pub fn port_mappings(&self) -> Vec<crate::agent::PortMapping> {
        self.ports
            .iter()
            .map(|(host, guest)| crate::agent::PortMapping::new(*host, *guest))
            .collect()
    }

    /// Convert record fields to VmResources.
    pub fn vm_resources(&self) -> crate::agent::VmResources {
        crate::agent::VmResources {
            cpus: self.cpus,
            mem: self.mem,
            network: self.network,
            storage_gb: self.storage_gb,
            overlay_gb: self.overlay_gb,
            allow_cidrs: self.allow_cidrs.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_record_serialization() {
        let record = VmRecord::new(
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
    }

    #[test]
    fn test_vm_record_with_restart() {
        let restart = RestartConfig {
            policy: RestartPolicy::Always,
            max_retries: 5,
            restart_count: 0,
            user_stopped: false,
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
}
