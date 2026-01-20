//! Global smolvm configuration.
//!
//! This module handles persistent configuration storage for smolvm,
//! including default settings and VM registry.

use crate::error::{Error, Result};
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

/// Application name for config file storage.
const APP_NAME: &str = "smolvm";

/// Global smolvm configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmolvmConfig {
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
    #[serde(default)]
    pub storage_volume: String,

    /// Registry of known VMs (by name).
    #[serde(default)]
    pub vms: HashMap<String, VmRecord>,
}

impl Default for SmolvmConfig {
    fn default() -> Self {
        Self {
            version: 1,
            default_cpus: 1,
            default_mem: 512,
            default_dns: "1.1.1.1".to_string(),
            #[cfg(target_os = "macos")]
            storage_volume: String::new(),
            vms: HashMap::new(),
        }
    }
}

impl SmolvmConfig {
    /// Load configuration from disk.
    ///
    /// If the configuration file doesn't exist, returns the default configuration.
    pub fn load() -> Result<Self> {
        confy::load(APP_NAME, None).map_err(|e| Error::ConfigLoad(e.to_string()))
    }

    /// Save configuration to disk.
    pub fn save(&self) -> Result<()> {
        confy::store(APP_NAME, None, self).map_err(|e| Error::ConfigSave(e.to_string()))
    }

    /// Remove a VM from the registry.
    pub fn remove_vm(&mut self, id: &str) -> Option<VmRecord> {
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

    /// Update a VM record in place.
    pub fn update_vm<F>(&mut self, id: &str, f: F) -> Option<()>
    where
        F: FnOnce(&mut VmRecord),
    {
        if let Some(record) = self.vms.get_mut(id) {
            f(record);
            Some(())
        } else {
            None
        }
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
    ) -> Self {
        Self {
            name,
            created_at: crate::util::current_timestamp(),
            state: RecordState::Created,
            pid: None,
            cpus,
            mem,
            mounts,
            ports,
        }
    }

    /// Check if the VM process is still alive.
    pub fn is_process_alive(&self) -> bool {
        if let Some(pid) = self.pid {
            crate::process::is_alive(pid)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_vm() {
        let mut config = SmolvmConfig::default();

        let record = VmRecord::new(
            "test-vm".to_string(),
            "alpine:latest".to_string(),
            1,
            256,
            Some(vec!["/bin/sh".to_string()]),
            None,
            vec![],
            vec![],
        );

        config.vms.insert("test-vm".to_string(), record);

        let record = config.get_vm("test-vm").expect("VM should exist");
        assert_eq!(record.name, "test-vm");
        assert_eq!(record.image, "alpine:latest");
    }

    #[test]
    fn test_remove_vm() {
        let mut config = SmolvmConfig::default();

        let record = VmRecord::new(
            "test-vm".to_string(),
            "alpine:latest".to_string(),
            1,
            256,
            None,
            None,
            vec![],
            vec![],
        );

        config.vms.insert("test-vm".to_string(), record);
        assert!(config.get_vm("test-vm").is_some());

        let removed = config.remove_vm("test-vm");
        assert!(removed.is_some());
        assert!(config.get_vm("test-vm").is_none());
    }

    #[test]
    fn test_list_vms() {
        let mut config = SmolvmConfig::default();

        for i in 0..3 {
            let record = VmRecord::new(
                format!("vm-{}", i),
                "alpine:latest".to_string(),
                1,
                256,
                None,
                None,
                vec![],
                vec![],
            );
            config.vms.insert(format!("vm-{}", i), record);
        }

        let vms: Vec<_> = config.list_vms().collect();
        assert_eq!(vms.len(), 3);
    }

    #[test]
    fn test_vm_record_serialization() {
        let record = VmRecord::new(
            "test".to_string(),
            "alpine:latest".to_string(),
            2,
            512,
            Some(vec!["/bin/echo".to_string(), "hello".to_string()]),
            Some("/app".to_string()),
            vec![("FOO".to_string(), "bar".to_string())],
            vec![("/host".to_string(), "/guest".to_string(), false)],
        );

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: VmRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, record.name);
        assert_eq!(deserialized.image, record.image);
        assert_eq!(deserialized.command, record.command);
        assert_eq!(deserialized.env, record.env);
        assert_eq!(deserialized.mounts, record.mounts);
    }

    #[test]
    fn test_config_v1_backwards_compat() {
        let v1_json = r#"{
            "version": 1,
            "default_cpus": 2,
            "default_mem": 1024,
            "default_dns": "8.8.8.8",
            "vms": {}
        }"#;

        let config: SmolvmConfig = serde_json::from_str(v1_json).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.default_cpus, 2);
        assert_eq!(config.default_mem, 1024);
        assert_eq!(config.default_dns, "8.8.8.8");
    }

    #[test]
    fn test_config_missing_optional_fields() {
        let minimal_json = r#"{
            "version": 1,
            "default_cpus": 1,
            "default_mem": 512,
            "default_dns": "1.1.1.1"
        }"#;

        let config: SmolvmConfig = serde_json::from_str(minimal_json).unwrap();
        assert!(config.vms.is_empty());
    }
}
