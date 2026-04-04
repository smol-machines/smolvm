//! Global smolvm configuration.
//!
//! This module handles persistent configuration storage for smolvm,
//! including default settings and VM registry.
//!
//! State is persisted to a redb database at `~/.local/share/smolvm/server/smolvm.redb`.
//! For backward compatibility, `SmolvmConfig` maintains an in-memory cache of VMs
//! and provides the same API as the old confy-based implementation.

use crate::data::network::DEFAULT_DNS;
use crate::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
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
        // Check max retries limit (0 = unlimited)
        if self.max_retries > 0 && self.restart_count >= self.max_retries {
            return false;
        }
        match self.policy {
            RestartPolicy::Never => false,
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure => exit_code != Some(0),
            RestartPolicy::UnlessStopped => !self.user_stopped,
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
            default_cpus: DEFAULT_MICROVM_CPU_COUNT,
            default_mem: DEFAULT_MICROVM_MEMORY_MIB,
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
            .unwrap_or_else(|| DEFAULT_DNS.to_string());

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
/// This stores machine configuration only. Container configuration
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

    /// Overlay disk size in GiB (None = default 10 GiB).
    #[serde(default)]
    pub overlay_gb: Option<u64>,

    /// Allowed egress CIDR ranges. None = unrestricted, Some([]) = deny all.
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,

    /// OCI image for auto-container creation on start.
    #[serde(default)]
    pub image: Option<String>,

    /// Entrypoint for the container.
    #[serde(default)]
    pub entrypoint: Vec<String>,

    /// Default command for the container.
    #[serde(default)]
    pub cmd: Vec<String>,

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

    /// Hostnames for DNS filtering. When set, the guest DNS proxy filters
    /// queries against this allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_filter_hosts: Option<Vec<String>>,
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
            allowed_cidrs: None,
            image: None,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            health_cmd: None,
            health_interval_secs: None,
            health_timeout_secs: None,
            health_retries: None,
            health_startup_grace_secs: None,
            ssh_agent: false,
            dns_filter_hosts: None,
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
            allowed_cidrs: None,
            image: None,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            health_cmd: None,
            health_interval_secs: None,
            health_timeout_secs: None,
            health_retries: None,
            health_startup_grace_secs: None,
            ssh_agent: false,
            dns_filter_hosts: None,
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
        self.mounts
            .iter()
            .map(|(host, guest, ro)| crate::data::storage::HostMount {
                source: std::path::PathBuf::from(host),
                target: std::path::PathBuf::from(guest),
                read_only: *ro,
            })
            .collect()
    }

    /// Convert stored ports to PortMapping format.
    pub fn port_mappings(&self) -> Vec<crate::data::network::PortMapping> {
        self.ports
            .iter()
            .map(|(host, guest)| crate::data::network::PortMapping::new(*host, *guest))
            .collect()
    }

    /// Convert record fields to VmResources.
    pub fn vm_resources(&self) -> crate::agent::VmResources {
        crate::agent::VmResources {
            cpus: self.cpus,
            memory_mib: self.mem,
            network: self.network,
            storage_gib: self.storage_gb,
            overlay_gib: self.overlay_gb,
            allowed_cidrs: self.allowed_cidrs.clone(),
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
}
