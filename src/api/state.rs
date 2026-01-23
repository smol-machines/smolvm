//! API server state management.

use crate::agent::{AgentManager, HostMount, PortMapping, VmResources};
use crate::api::error::ApiError;
use crate::api::types::{MountInfo, MountSpec, PortSpec, ResourceSpec, SandboxInfo};
use crate::config::{RecordState, VmRecord};
use crate::db::SmolvmDb;
use crate::mount::validate_mount;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Shared API server state.
pub struct ApiState {
    /// Registry of sandbox managers by name.
    sandboxes: RwLock<HashMap<String, Arc<parking_lot::Mutex<SandboxEntry>>>>,
    /// Database for persistent state.
    db: SmolvmDb,
}

/// Internal sandbox entry with manager and configuration.
pub struct SandboxEntry {
    /// The agent manager for this sandbox.
    pub manager: AgentManager,
    /// Host mounts configured for this sandbox.
    pub mounts: Vec<MountSpec>,
    /// Port mappings configured for this sandbox.
    pub ports: Vec<PortSpec>,
    /// VM resources configured for this sandbox.
    pub resources: ResourceSpec,
}

impl ApiState {
    /// Create a new API state, opening the database.
    pub fn new() -> Self {
        let db = SmolvmDb::open().expect("failed to open database");
        Self {
            sandboxes: RwLock::new(HashMap::new()),
            db,
        }
    }

    /// Load existing sandboxes from persistent database.
    /// Call this on server startup to reconnect to running VMs.
    pub fn load_persisted_sandboxes(&self) -> Vec<String> {
        let vms = match self.db.list_vms() {
            Ok(vms) => vms,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load VMs from database");
                return Vec::new();
            }
        };

        let mut loaded = Vec::new();

        for (name, record) in vms {
            // Check if VM process is still alive
            if !record.is_process_alive() {
                tracing::info!(sandbox = %name, "skipping dead sandbox");
                continue;
            }

            // Convert VmRecord to SandboxEntry
            let mounts: Vec<MountSpec> = record
                .mounts
                .iter()
                .map(|(source, target, readonly)| MountSpec {
                    source: source.clone(),
                    target: target.clone(),
                    readonly: *readonly,
                })
                .collect();

            let ports: Vec<PortSpec> = record
                .ports
                .iter()
                .map(|(host, guest)| PortSpec {
                    host: *host,
                    guest: *guest,
                })
                .collect();

            let resources = ResourceSpec {
                cpus: Some(record.cpus),
                memory_mb: Some(record.mem),
            };

            // Create AgentManager and try to reconnect
            match AgentManager::for_vm(&name) {
                Ok(manager) => {
                    // Try to reconnect to existing running VM
                    if manager.try_connect_existing_with_pid(record.pid).is_some() {
                        let mut sandboxes = self.sandboxes.write();
                        sandboxes.insert(
                            name.clone(),
                            Arc::new(parking_lot::Mutex::new(SandboxEntry {
                                manager,
                                mounts,
                                ports,
                                resources,
                            })),
                        );
                        loaded.push(name.clone());
                        tracing::info!(sandbox = %name, pid = ?record.pid, "reconnected to sandbox");
                    } else {
                        tracing::info!(sandbox = %name, "sandbox not running, skipping");
                    }
                }
                Err(e) => {
                    tracing::warn!(sandbox = %name, error = %e, "failed to create manager for sandbox");
                }
            }
        }

        loaded
    }

    /// Register a new sandbox (also persists to database).
    pub fn register_sandbox(
        &self,
        name: String,
        manager: AgentManager,
        mounts: Vec<MountSpec>,
        ports: Vec<PortSpec>,
        resources: ResourceSpec,
    ) -> Result<(), ApiError> {
        // Check for conflicts
        {
            let sandboxes = self.sandboxes.read();
            if sandboxes.contains_key(&name) {
                return Err(ApiError::Conflict(format!(
                    "sandbox '{}' already exists",
                    name
                )));
            }
        }

        // Persist to database
        let record = VmRecord::new(
            name.clone(),
            resources.cpus.unwrap_or(crate::agent::DEFAULT_CPUS),
            resources.memory_mb.unwrap_or(crate::agent::DEFAULT_MEMORY_MIB),
            mounts
                .iter()
                .map(|m| (m.source.clone(), m.target.clone(), m.readonly))
                .collect(),
            ports.iter().map(|p| (p.host, p.guest)).collect(),
        );

        if let Err(e) = self.db.insert_vm(&name, &record) {
            tracing::warn!(error = %e, "failed to persist sandbox to database");
        }

        // Add to in-memory registry
        let mut sandboxes = self.sandboxes.write();
        sandboxes.insert(
            name,
            Arc::new(parking_lot::Mutex::new(SandboxEntry {
                manager,
                mounts,
                ports,
                resources,
            })),
        );
        Ok(())
    }

    /// Get a sandbox entry by name.
    pub fn get_sandbox(
        &self,
        name: &str,
    ) -> Result<Arc<parking_lot::Mutex<SandboxEntry>>, ApiError> {
        let sandboxes = self.sandboxes.read();
        sandboxes
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::NotFound(format!("sandbox '{}' not found", name)))
    }

    /// Remove a sandbox from the registry (also removes from database).
    pub fn remove_sandbox(
        &self,
        name: &str,
    ) -> Result<Arc<parking_lot::Mutex<SandboxEntry>>, ApiError> {
        // Remove from in-memory registry
        let entry = {
            let mut sandboxes = self.sandboxes.write();
            sandboxes
                .remove(name)
                .ok_or_else(|| ApiError::NotFound(format!("sandbox '{}' not found", name)))?
        };

        // Remove from database
        if let Err(e) = self.db.remove_vm(name) {
            tracing::warn!(error = %e, "failed to remove sandbox from database");
        }

        Ok(entry)
    }

    /// Update sandbox state in database (call after start/stop).
    pub fn update_sandbox_state(&self, name: &str, state: RecordState, pid: Option<i32>) {
        if let Err(e) = self.db.update_vm(name, |record| {
            record.state = state;
            record.pid = pid;
        }) {
            tracing::warn!(error = %e, "failed to persist sandbox state");
        }
    }

    /// List all sandboxes.
    pub fn list_sandboxes(&self) -> Vec<SandboxInfo> {
        let sandboxes = self.sandboxes.read();
        sandboxes
            .iter()
            .map(|(name, entry)| {
                let entry = entry.lock();
                let state = format!("{:?}", entry.manager.state());
                let pid = entry.manager.child_pid();
                // Convert mounts to MountInfo with tags
                let mounts = entry
                    .mounts
                    .iter()
                    .enumerate()
                    .map(|(i, m)| MountInfo {
                        tag: format!("smolvm{}", i),
                        source: m.source.clone(),
                        target: m.target.clone(),
                        readonly: m.readonly,
                    })
                    .collect();
                SandboxInfo {
                    name: name.clone(),
                    state: state.to_lowercase(),
                    pid,
                    mounts,
                    ports: entry.ports.clone(),
                    resources: entry.resources.clone(),
                }
            })
            .collect()
    }

    /// Check if a sandbox exists.
    pub fn sandbox_exists(&self, name: &str) -> bool {
        self.sandboxes.read().contains_key(name)
    }

    /// Stop all sandboxes (for graceful shutdown).
    pub fn stop_all_sandboxes(&self) {
        let sandboxes = self.sandboxes.read();
        for (name, entry) in sandboxes.iter() {
            let entry = entry.lock();
            if entry.manager.is_running() {
                tracing::info!(sandbox = %name, "stopping sandbox");
                if let Err(e) = entry.manager.stop() {
                    tracing::warn!(sandbox = %name, error = %e, "failed to stop sandbox");
                }
            }
        }
    }

    /// Get the underlying database handle.
    pub fn db(&self) -> &SmolvmDb {
        &self.db
    }

    /// Temporarily close the database to release file locks before forking.
    ///
    /// This prevents child processes (VMs) from inheriting the database
    /// file descriptor and holding the lock after the parent reopens it.
    /// Call `reopen_db()` after the fork completes.
    pub fn close_db_temporarily(&self) {
        self.db.close_temporarily();
    }

    /// Reopen the database after a fork operation.
    ///
    /// Call this after forking to restore database access.
    pub fn reopen_db(&self) -> crate::Result<()> {
        self.db.reopen()
    }
}

impl Default for ApiState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Type Conversions
// ============================================================================

/// Convert MountSpec to HostMount.
pub fn mount_spec_to_host_mount(spec: &MountSpec) -> crate::Result<HostMount> {
    let mount = if spec.readonly {
        HostMount::new(&spec.source, &spec.target)
    } else {
        HostMount::new_writable(&spec.source, &spec.target)
    };
    validate_mount(&mount)?;
    Ok(mount)
}

/// Convert PortSpec to PortMapping.
pub fn port_spec_to_mapping(spec: &PortSpec) -> PortMapping {
    PortMapping::new(spec.host, spec.guest)
}

/// Convert ResourceSpec to VmResources.
pub fn resource_spec_to_vm_resources(spec: &ResourceSpec) -> VmResources {
    VmResources {
        cpus: spec.cpus.unwrap_or(crate::agent::DEFAULT_CPUS),
        mem: spec.memory_mb.unwrap_or(crate::agent::DEFAULT_MEMORY_MIB),
    }
}

/// Convert VmResources to ResourceSpec.
pub fn vm_resources_to_spec(res: VmResources) -> ResourceSpec {
    ResourceSpec {
        cpus: Some(res.cpus),
        memory_mb: Some(res.mem),
    }
}

/// Convert HostMount to MountSpec.
pub fn host_mount_to_spec(mount: &HostMount) -> MountSpec {
    MountSpec {
        source: mount.source.to_string_lossy().to_string(),
        target: mount.target.to_string_lossy().to_string(),
        readonly: mount.read_only,
    }
}

/// Convert PortMapping to PortSpec.
pub fn port_mapping_to_spec(mapping: &PortMapping) -> PortSpec {
    PortSpec {
        host: mapping.host,
        guest: mapping.guest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_conversions() {
        // MountSpec -> HostMount preserves readonly flag (use /tmp which exists)
        let spec = MountSpec {
            source: "/tmp".into(),
            target: "/guest".into(),
            readonly: true,
        };
        assert!(mount_spec_to_host_mount(&spec).unwrap().read_only);

        let spec = MountSpec {
            source: "/tmp".into(),
            target: "/guest".into(),
            readonly: false,
        };
        assert!(!mount_spec_to_host_mount(&spec).unwrap().read_only);

        // ResourceSpec with None uses defaults
        let spec = ResourceSpec {
            cpus: None,
            memory_mb: None,
        };
        let res = resource_spec_to_vm_resources(&spec);
        assert_eq!(res.cpus, crate::agent::DEFAULT_CPUS);
        assert_eq!(res.mem, crate::agent::DEFAULT_MEMORY_MIB);
    }

    #[test]
    fn test_sandbox_not_found() {
        let state = ApiState::new();
        assert!(matches!(
            state.get_sandbox("nope"),
            Err(ApiError::NotFound(_))
        ));
        assert!(matches!(
            state.remove_sandbox("nope"),
            Err(ApiError::NotFound(_))
        ));
    }
}
