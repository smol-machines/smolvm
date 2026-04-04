//! API server state management.

use crate::agent::{AgentManager, HostMount, PortMapping, VmResources};
use crate::api::error::ApiError;
use crate::api::types::{MachineInfo, MountSpec, PortSpec, ResourceSpec, RestartSpec};
use crate::config::{RecordState, RestartConfig, RestartPolicy, VmRecord};
use crate::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use crate::db::SmolvmDb;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// Shared API server state.
pub struct ApiState {
    /// Registry of machine managers by name.
    machines: RwLock<HashMap<String, Arc<parking_lot::Mutex<MachineEntry>>>>,
    /// Reserved machine names (creation in progress).
    /// This prevents race conditions during machine creation.
    reserved_names: RwLock<HashSet<String>>,
    /// Database for persistent state.
    db: SmolvmDb,
}

/// Internal machine entry with manager and configuration.
pub struct MachineEntry {
    /// The agent manager for this machine.
    pub manager: AgentManager,
    /// Host mounts configured for this machine.
    pub mounts: Vec<MountSpec>,
    /// Port mappings configured for this machine.
    pub ports: Vec<PortSpec>,
    /// VM resources configured for this machine.
    pub resources: ResourceSpec,
    /// Restart configuration for this machine.
    pub restart: RestartConfig,
    /// Whether outbound network access is enabled.
    pub network: bool,
}

/// Parameters for registering a new machine.
pub struct MachineRegistration {
    /// The agent manager for this machine.
    pub manager: AgentManager,
    /// Host mounts to configure.
    pub mounts: Vec<MountSpec>,
    /// Port mappings to configure.
    pub ports: Vec<PortSpec>,
    /// VM resources to configure.
    pub resources: ResourceSpec,
    /// Restart configuration.
    pub restart: RestartConfig,
    /// Whether outbound network access is enabled.
    pub network: bool,
}

/// RAII guard for machine name reservation.
///
/// Automatically releases reservation on drop unless consumed by `complete()`.
/// This ensures reservations are always cleaned up, even on panic.
///
/// # Example
///
/// ```ignore
/// let guard = ReservationGuard::new(&state, "my-machine".to_string())?;
///
/// // Create the machine manager...
/// let manager = AgentManager::for_vm(guard.name())?;
///
/// // Complete registration, consuming the guard
/// guard.complete(MachineRegistration { manager, mounts, ports, resources, restart, network })?;
/// ```
pub struct ReservationGuard<'a> {
    state: &'a ApiState,
    name: String,
    completed: bool,
}

impl<'a> ReservationGuard<'a> {
    /// Reserve a machine name. Returns a guard that auto-releases on drop.
    pub fn new(state: &'a ApiState, name: String) -> Result<Self, ApiError> {
        state.reserve_machine_name(&name)?;
        Ok(Self {
            state,
            name,
            completed: false,
        })
    }

    /// Get the reserved name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Complete registration, consuming the guard without releasing.
    ///
    /// This transfers ownership of the name to the machine registry.
    pub fn complete(mut self, registration: MachineRegistration) -> Result<(), ApiError> {
        // Mark as completed before calling complete_machine_registration
        // (which will remove from reservations internally)
        self.completed = true;
        self.state
            .complete_machine_registration(self.name.clone(), registration)
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state.release_machine_reservation(&self.name);
            tracing::debug!(machine = %self.name, "reservation guard released on drop");
        }
    }
}

impl ApiState {
    /// Create a new API state, opening the database.
    ///
    /// Returns an error if the database cannot be opened.
    pub fn new() -> Result<Self, ApiError> {
        let db = SmolvmDb::open()
            .map_err(|e| ApiError::internal(format!("failed to open database: {}", e)))?;
        // Ensure tables exist at server startup (CLI paths handle this lazily).
        db.init_tables().map_err(|e| {
            ApiError::internal(format!("failed to initialize database tables: {}", e))
        })?;
        Ok(Self {
            machines: RwLock::new(HashMap::new()),
            reserved_names: RwLock::new(HashSet::new()),
            db,
        })
    }

    /// Create a new API state with a specific database.
    ///
    /// Useful for testing with temporary databases.
    pub fn with_db(db: SmolvmDb) -> Self {
        Self {
            machines: RwLock::new(HashMap::new()),
            reserved_names: RwLock::new(HashSet::new()),
            db,
        }
    }

    /// Load existing machines from persistent database.
    /// Call this on server startup to reconnect to running VMs.
    pub fn load_persisted_machines(&self) -> Vec<String> {
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
                tracing::info!(machine = %name, "cleaning up dead machine from database");
                if let Err(e) = self.db.remove_vm(&name) {
                    tracing::warn!(machine = %name, error = %e, "failed to remove dead machine from database");
                }
                continue;
            }

            // Convert VmRecord to MachineEntry
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
                network: Some(record.network),
                storage_gb: record.storage_gb,
                overlay_gb: record.overlay_gb,
                allowed_cidrs: record.allowed_cidrs.clone(),
            };

            // Create AgentManager and try to reconnect
            match AgentManager::for_vm_with_sizes(&name, record.storage_gb, record.overlay_gb) {
                Ok(manager) => {
                    // Try to reconnect to existing running VM
                    let reconnected = manager
                        .try_connect_existing_with_pid_and_start_time(
                            record.pid,
                            record.pid_start_time,
                        )
                        .is_some();

                    if reconnected {
                        tracing::info!(machine = %name, pid = ?record.pid, "reconnected to machine");
                    } else {
                        // Process is alive but agent isn't reachable yet (transient
                        // boot/socket timing). Register the machine anyway so it's
                        // visible via APIs and the supervisor can manage it. Keep
                        // the DB record for future reconnect attempts.
                        tracing::info!(machine = %name, pid = ?record.pid, "machine alive but not yet reachable, registering for later reconnect");
                    }

                    let mut machines = self.machines.write();
                    machines.insert(
                        name.clone(),
                        Arc::new(parking_lot::Mutex::new(MachineEntry {
                            manager,
                            mounts,
                            ports,
                            resources,
                            restart: record.restart.clone(),
                            network: record.network,
                        })),
                    );
                    loaded.push(name.clone());
                }
                Err(e) => {
                    // Process is alive but manager creation failed (transient
                    // filesystem/env issue). Preserve the DB record so the VM
                    // isn't orphaned — next server restart can retry.
                    tracing::warn!(machine = %name, error = %e, "failed to create manager for alive machine, preserving DB record");
                }
            }
        }

        loaded
    }

    /// Get a machine entry by name.
    pub fn get_machine(
        &self,
        name: &str,
    ) -> Result<Arc<parking_lot::Mutex<MachineEntry>>, ApiError> {
        let machines = self.machines.read();
        machines
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))
    }

    /// Remove a machine from the registry (also removes from database).
    pub fn remove_machine(
        &self,
        name: &str,
    ) -> Result<Arc<parking_lot::Mutex<MachineEntry>>, ApiError> {
        // Hold write lock across the entire operation to prevent concurrent
        // delete races (check + DB delete + in-memory remove must be atomic).
        let mut machines = self.machines.write();

        if !machines.contains_key(name) {
            return Err(ApiError::NotFound(format!("machine '{}' not found", name)));
        }

        // Remove from database first — if this fails, in-memory state stays consistent
        match self.db.remove_vm(name) {
            Ok(Some(_)) => {} // expected: row existed and was deleted
            Ok(None) => {
                // Row was already gone from DB (concurrent delete or manual cleanup).
                // Log and continue — we still need to clean up in-memory state.
                tracing::warn!(
                    machine = name,
                    "machine not found in database during remove (already deleted?)"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, machine = name, "failed to remove machine from database");
                return Err(ApiError::Internal(format!("database error: {}", e)));
            }
        }

        // Remove from in-memory registry (guaranteed to succeed — we hold the write lock)
        let entry = machines
            .remove(name)
            .expect("machine disappeared while holding write lock");

        Ok(entry)
    }

    /// Update machine state in database (call after start/stop).
    ///
    /// Returns an error if the database write fails. Callers in API handlers
    /// should propagate this error; the supervisor can log and continue.
    pub fn update_machine_state(
        &self,
        name: &str,
        state: RecordState,
        pid: Option<i32>,
    ) -> std::result::Result<(), crate::Error> {
        let pid_start_time = pid.and_then(crate::process::process_start_time);
        let result = self.db.update_vm(name, |record| {
            record.state = state;
            record.pid = pid;
            record.pid_start_time = pid_start_time;
        })?;
        match result {
            Some(_) => Ok(()),
            None => Err(crate::Error::database(
                "update machine state",
                format!("machine '{}' not found in database", name),
            )),
        }
    }

    /// List all machines.
    pub fn list_machines(&self) -> Vec<MachineInfo> {
        let machines = self.machines.read();
        machines
            .iter()
            .map(|(name, entry)| {
                let entry = entry.lock();
                machine_entry_to_info(name.clone(), &entry)
            })
            .collect()
    }

    /// Check if a machine exists.
    pub fn machine_exists(&self, name: &str) -> bool {
        self.machines.read().contains_key(name)
    }

    // ========================================================================
    // Atomic Machine Creation (Reservation Pattern)
    // ========================================================================

    /// Reserve a machine name atomically.
    ///
    /// This prevents race conditions where two concurrent requests try to create
    /// a machine with the same name. The name is reserved until either:
    /// - `complete_machine_registration()` is called (success)
    /// - `release_machine_reservation()` is called (failure/cleanup)
    ///
    /// Returns `Err(Conflict)` if the name is already taken or reserved.
    pub fn reserve_machine_name(&self, name: &str) -> Result<(), ApiError> {
        // First check: machine existence (early exit for common case).
        // Use separate scope to release read lock before acquiring write lock.
        // This prevents lock-order inversion with complete_machine_registration.
        {
            let machines = self.machines.read();
            if machines.contains_key(name) {
                return Err(ApiError::Conflict(format!(
                    "machine '{}' already exists",
                    name
                )));
            }
        }

        // Acquire reservation lock
        let mut reserved = self.reserved_names.write();

        // Double-check machine existence (could have been added while we
        // didn't hold the machines lock). This is necessary for correctness.
        if self.machines.read().contains_key(name) {
            return Err(ApiError::Conflict(format!(
                "machine '{}' already exists",
                name
            )));
        }

        // Check if name is already reserved (creation in progress)
        if reserved.contains(name) {
            return Err(ApiError::Conflict(format!(
                "machine '{}' is being created by another request",
                name
            )));
        }

        // Also check database for persisted machines not yet loaded
        if let Ok(Some(_)) = self.db.get_vm(name) {
            return Err(ApiError::Conflict(format!(
                "machine '{}' already exists in database",
                name
            )));
        }

        // Reserve the name
        reserved.insert(name.to_string());
        tracing::debug!(machine = %name, "reserved machine name");
        Ok(())
    }

    /// Release a machine name reservation.
    ///
    /// Call this if machine creation fails after `reserve_machine_name()`.
    pub fn release_machine_reservation(&self, name: &str) {
        let mut reserved = self.reserved_names.write();
        if reserved.remove(name) {
            tracing::debug!(machine = %name, "released machine name reservation");
        }
    }

    /// Complete machine registration after successful creation.
    ///
    /// This converts a reserved name into a fully registered machine.
    /// The reservation is released and the machine entry is added.
    pub fn complete_machine_registration(
        &self,
        name: String,
        reg: MachineRegistration,
    ) -> Result<(), ApiError> {
        // Remove from reservations
        {
            let mut reserved = self.reserved_names.write();
            if !reserved.remove(&name) {
                // Name wasn't reserved - this is a programming error
                tracing::warn!(machine = %name, "completing registration for non-reserved name");
            }
        }

        // Persist to database (with conflict detection)
        let mut record = VmRecord::new_with_restart(
            name.clone(),
            reg.resources.cpus.unwrap_or(DEFAULT_MICROVM_CPU_COUNT),
            reg.resources
                .memory_mb
                .unwrap_or(DEFAULT_MICROVM_MEMORY_MIB),
            reg.mounts
                .iter()
                .map(|m| (m.source.clone(), m.target.clone(), m.readonly))
                .collect(),
            reg.ports.iter().map(|p| (p.host, p.guest)).collect(),
            reg.network,
            reg.restart.clone(),
        );
        record.storage_gb = reg.resources.storage_gb;
        record.overlay_gb = reg.resources.overlay_gb;

        // Use insert_vm_if_not_exists for atomic database insert
        match self.db.insert_vm_if_not_exists(&name, &record) {
            Ok(true) => {
                // Successfully inserted, now add to in-memory registry
                let mut machines = self.machines.write();
                machines.insert(
                    name,
                    Arc::new(parking_lot::Mutex::new(MachineEntry {
                        manager: reg.manager,
                        mounts: reg.mounts,
                        ports: reg.ports,
                        resources: reg.resources,
                        restart: reg.restart,
                        network: reg.network,
                    })),
                );
                Ok(())
            }
            Ok(false) => {
                // Name already exists in database (shouldn't happen with reservation)
                Err(ApiError::Conflict(format!(
                    "machine '{}' already exists in database",
                    name
                )))
            }
            Err(e) => {
                tracing::error!(error = %e, machine = %name, "database error during registration");
                Err(ApiError::database(e))
            }
        }
    }

    /// Get the underlying database handle.
    pub fn db(&self) -> &SmolvmDb {
        &self.db
    }

    /// Insert a machine entry directly into the in-memory registry.
    ///
    /// Used by start_machine to register a booted VM so that exec/run/container
    /// endpoints can find it without server restart.
    pub fn insert_machine(&self, name: &str, entry: MachineEntry) {
        let mut machines = self.machines.write();
        machines.insert(name.to_string(), Arc::new(parking_lot::Mutex::new(entry)));
    }

    // ========================================================================
    // Restart Management Methods
    // ========================================================================

    /// List all machine names.
    pub fn list_machine_names(&self) -> Vec<String> {
        self.machines.read().keys().cloned().collect()
    }

    /// Get restart config for a machine from the in-memory registry.
    pub fn get_restart_config(&self, name: &str) -> Option<RestartConfig> {
        let machines = self.machines.read();
        machines.get(name).map(|entry| {
            let entry = entry.lock();
            entry.restart.clone()
        })
    }

    /// Best-effort update to the VM database record. Logs warnings on
    /// `Ok(None)` (row not found) and `Err` without propagating.
    fn update_vm_best_effort(&self, name: &str, op_label: &str, f: impl FnOnce(&mut VmRecord)) {
        match self.db.update_vm(name, f) {
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!(machine = %name, op = op_label, "machine not found in database");
            }
            Err(e) => {
                tracing::warn!(error = %e, machine = %name, op = op_label, "failed to persist update");
            }
        }
    }

    /// Increment restart count for a machine.
    pub fn increment_restart_count(&self, name: &str) {
        if let Some(entry) = self.machines.read().get(name) {
            entry.lock().restart.restart_count += 1;
        }
        self.update_vm_best_effort(name, "increment_restart_count", |r| {
            r.restart.restart_count += 1;
        });
    }

    /// Mark machine as user-stopped.
    pub fn mark_user_stopped(&self, name: &str, stopped: bool) {
        if let Some(entry) = self.machines.read().get(name) {
            entry.lock().restart.user_stopped = stopped;
        }
        self.update_vm_best_effort(name, "mark_user_stopped", |r| {
            r.restart.user_stopped = stopped;
        });
    }

    /// Reset restart count (on successful start).
    pub fn reset_restart_count(&self, name: &str) {
        if let Some(entry) = self.machines.read().get(name) {
            entry.lock().restart.restart_count = 0;
        }
        self.update_vm_best_effort(name, "reset_restart_count", |r| {
            r.restart.restart_count = 0;
        });
    }

    /// Update last exit code for a machine.
    pub fn set_last_exit_code(&self, name: &str, exit_code: Option<i32>) {
        self.update_vm_best_effort(name, "set_last_exit_code", |r| {
            r.last_exit_code = exit_code;
        });
    }

    /// Get last exit code for a machine.
    pub fn get_last_exit_code(&self, name: &str) -> Option<i32> {
        self.db
            .get_vm(name)
            .ok()
            .flatten()
            .and_then(|r| r.last_exit_code)
    }

    /// Check if a machine process is alive.
    ///
    /// Delegates to `AgentManager::is_process_alive()` which checks the
    /// in-memory child handle (with stored start time) and falls back to the
    /// PID file. This is start-time-aware to avoid false positives from PID
    /// reuse, and covers orphan processes not tracked in-memory.
    pub fn is_machine_alive(&self, name: &str) -> bool {
        if let Some(entry) = self.machines.read().get(name) {
            let entry = entry.lock();
            entry.manager.is_process_alive()
        } else {
            false
        }
    }
}

/// Run a blocking operation against a machine's agent client.
///
/// Handles the common pattern: clone entry → spawn_blocking → lock → connect → op → map errors.
pub async fn with_machine_client<T, F>(
    entry: &Arc<parking_lot::Mutex<MachineEntry>>,
    op: F,
) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&mut crate::agent::AgentClient) -> crate::Result<T> + Send + 'static,
{
    let entry_clone = entry.clone();
    tokio::task::spawn_blocking(move || {
        let entry = entry_clone.lock();
        let mut client = entry.manager.connect()?;
        op(&mut client)
    })
    .await?
    .map_err(ApiError::internal)
}

// ============================================================================
// Shared Machine Helpers
// ============================================================================

/// Ensure a machine is running, starting it if needed.
///
/// This is the shared preflight check used by exec, container, and image handlers.
/// It converts the machine's mount/port/resource config and calls
/// `ensure_running_with_full_config` in a blocking task.
pub async fn ensure_machine_running(
    entry: &Arc<parking_lot::Mutex<MachineEntry>>,
) -> crate::Result<()> {
    let entry_clone = entry.clone();
    tokio::task::spawn_blocking(move || {
        let entry = entry_clone.lock();
        let mounts: Vec<_> = entry
            .mounts
            .iter()
            .map(HostMount::try_from)
            .collect::<crate::Result<Vec<_>>>()?;
        let ports: Vec<_> = entry.ports.iter().map(PortMapping::from).collect();
        let resources = resource_spec_to_vm_resources(&entry.resources, entry.network);

        // Use subprocess launch to avoid macOS fork-in-multithreaded-process issue.
        entry
            .manager
            .ensure_running_via_subprocess(mounts, ports, resources, None)?;
        Ok(())
    })
    .await
    .map_err(|e| crate::Error::agent("ensure running", e.to_string()))?
}

/// Ensure a machine is running and persist the Running state to the database.
///
/// Used by handlers that implicitly start VMs (containers, exec, images).
/// State persistence is best-effort — a DB write failure is logged but does
/// not fail the request, matching the supervisor's error-handling pattern.
pub async fn ensure_running_and_persist(
    state: &ApiState,
    name: &str,
    entry: &Arc<parking_lot::Mutex<MachineEntry>>,
) -> crate::Result<()> {
    ensure_machine_running(entry).await?;

    let pid = {
        let entry = entry.lock();
        entry.manager.child_pid()
    };
    if let Err(e) = state.update_machine_state(name, RecordState::Running, pid) {
        tracing::warn!(machine = %name, error = %e, "failed to persist Running state after implicit start");
    }

    Ok(())
}

// ============================================================================
// Type Conversions
// ============================================================================

impl TryFrom<&MountSpec> for HostMount {
    type Error = crate::Error;

    /// Validate and canonicalize a MountSpec into a HostMount.
    ///
    /// API mount specs require absolute source paths even though CLI parsing
    /// allows relative host paths that are canonicalized against the current
    /// working directory.
    fn try_from(spec: &MountSpec) -> Result<Self, Self::Error> {
        let source = Path::new(&spec.source);
        if !source.is_absolute() {
            return Err(crate::Error::mount(
                "validate source",
                format!("path must be absolute: {}", source.display()),
            ));
        }

        HostMount::new(&spec.source, &spec.target, spec.readonly)
    }
}

impl From<&HostMount> for MountSpec {
    fn from(mount: &HostMount) -> Self {
        MountSpec {
            source: mount.source.to_string_lossy().to_string(),
            target: mount.target.to_string_lossy().to_string(),
            readonly: mount.read_only,
        }
    }
}

impl From<&PortSpec> for PortMapping {
    fn from(spec: &PortSpec) -> Self {
        PortMapping::new(spec.host, spec.guest)
    }
}

impl From<&PortMapping> for PortSpec {
    fn from(mapping: &PortMapping) -> Self {
        PortSpec {
            host: mapping.host,
            guest: mapping.guest,
        }
    }
}

/// Convert multiple MountSpecs to HostMount values.
///
/// Returns an error if any mount fails validation.
pub fn mounts_to_host_mounts(specs: &[MountSpec]) -> Result<Vec<HostMount>, ApiError> {
    specs
        .iter()
        .map(|s| HostMount::try_from(s).map_err(|e| ApiError::BadRequest(e.to_string())))
        .collect()
}

/// Convert ResourceSpec to VmResources.
pub fn resource_spec_to_vm_resources(spec: &ResourceSpec, network: bool) -> VmResources {
    VmResources {
        cpus: spec.cpus.unwrap_or(DEFAULT_MICROVM_CPU_COUNT),
        memory_mib: spec.memory_mb.unwrap_or(DEFAULT_MICROVM_MEMORY_MIB),
        network,
        storage_gib: spec.storage_gb,
        overlay_gib: spec.overlay_gb,
        allowed_cidrs: spec.allowed_cidrs.clone(),
    }
}

/// Convert VmResources to ResourceSpec.
pub fn vm_resources_to_spec(res: VmResources) -> ResourceSpec {
    ResourceSpec {
        cpus: Some(res.cpus),
        memory_mb: Some(res.memory_mib),
        network: Some(res.network),
        storage_gb: res.storage_gib,
        overlay_gb: res.overlay_gib,
        allowed_cidrs: res.allowed_cidrs,
    }
}

/// Convert RestartSpec to RestartConfig.
pub fn restart_spec_to_config(spec: Option<&RestartSpec>) -> RestartConfig {
    match spec {
        Some(spec) => {
            let policy = spec
                .policy
                .as_ref()
                .and_then(|p| p.parse::<RestartPolicy>().ok())
                .unwrap_or_default();
            RestartConfig {
                policy,
                max_retries: spec.max_retries.unwrap_or(0),
                ..Default::default()
            }
        }
        None => RestartConfig::default(),
    }
}

/// Convert a MachineEntry (in-memory state) to MachineInfo (API response).
pub fn machine_entry_to_info(name: String, entry: &MachineEntry) -> MachineInfo {
    let state = if entry.manager.try_connect_existing().is_some() {
        "running"
    } else {
        "stopped"
    };

    MachineInfo {
        name,
        state: state.to_string(),
        cpus: entry.resources.cpus.unwrap_or(1),
        mem: entry.resources.memory_mb.unwrap_or(512),
        pid: entry.manager.child_pid(),
        mounts: entry
            .mounts
            .iter()
            .enumerate()
            .map(|(i, m)| crate::api::types::MountInfo {
                tag: crate::data::storage::HostMount::mount_tag(i),
                source: m.source.clone(),
                target: m.target.clone(),
                readonly: m.readonly,
            })
            .collect(),
        ports: entry.ports.clone(),
        network: entry.network,
        storage_gb: entry.resources.storage_gb,
        overlay_gb: entry.resources.overlay_gb,
        created_at: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create an ApiState with a temporary database for testing.
    fn temp_api_state() -> (TempDir, ApiState) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.redb");
        let db = SmolvmDb::open_at(&path).unwrap();
        (dir, ApiState::with_db(db))
    }

    #[test]
    fn test_type_conversions() {
        // MountSpec -> HostMount preserves readonly flag (use /tmp which exists)
        let spec = MountSpec {
            source: "/tmp".into(),
            target: "/guest".into(),
            readonly: true,
        };
        assert!(HostMount::try_from(&spec).unwrap().read_only);

        let spec = MountSpec {
            source: "/tmp".into(),
            target: "/guest".into(),
            readonly: false,
        };
        assert!(!HostMount::try_from(&spec).unwrap().read_only);

        // ResourceSpec with None uses defaults
        let spec = ResourceSpec {
            cpus: None,
            memory_mb: None,
            network: None,
            storage_gb: None,
            overlay_gb: None,
            allowed_cidrs: None,
        };
        let res = resource_spec_to_vm_resources(&spec, false);
        assert_eq!(res.cpus, DEFAULT_MICROVM_CPU_COUNT);
        assert_eq!(res.memory_mib, DEFAULT_MICROVM_MEMORY_MIB);
        assert!(!res.network);

        // Test with network enabled
        let res = resource_spec_to_vm_resources(&spec, true);
        assert!(res.network);
    }

    #[test]
    fn test_machine_not_found() {
        let (_dir, state) = temp_api_state();
        assert!(matches!(
            state.get_machine("nope"),
            Err(ApiError::NotFound(_))
        ));
        assert!(matches!(
            state.remove_machine("nope"),
            Err(ApiError::NotFound(_))
        ));
    }

    // ========================================================================
    // Startup reconciliation tests
    // ========================================================================

    #[test]
    fn test_load_persisted_machines_removes_dead_records() {
        let (_dir, state) = temp_api_state();

        // Insert a record with a PID that doesn't exist (dead process)
        let mut record = VmRecord::new("dead-machine".into(), 1, 512, vec![], vec![], false);
        record.pid = Some(i32::MAX); // PID that certainly doesn't exist
        record.state = RecordState::Running;
        state.db.insert_vm("dead-machine", &record).unwrap();

        // Verify record exists before load
        assert!(state.db.get_vm("dead-machine").unwrap().is_some());

        // Load should detect dead process and clean up DB record
        let loaded = state.load_persisted_machines();
        assert!(loaded.is_empty(), "dead machine should not be loaded");

        // DB record should be cleaned up
        assert!(
            state.db.get_vm("dead-machine").unwrap().is_none(),
            "dead machine DB record should be removed"
        );

        // Name should be available for reuse
        assert!(state.reserve_machine_name("dead-machine").is_ok());
    }

    #[test]
    fn test_load_persisted_machines_dead_record_does_not_block_name() {
        let (_dir, state) = temp_api_state();

        // Insert a dead record with no PID (definitely dead)
        let record = VmRecord::new("ghost".into(), 1, 512, vec![], vec![], false);
        state.db.insert_vm("ghost", &record).unwrap();

        // Load should remove it (no PID = dead)
        let loaded = state.load_persisted_machines();
        assert!(loaded.is_empty());

        // Name should not be blocked
        assert!(
            state.reserve_machine_name("ghost").is_ok(),
            "cleaned-up name should be available for reuse"
        );
    }

    #[test]
    fn test_load_persisted_machines_preserves_alive_unreachable_records() {
        let (_dir, state) = temp_api_state();

        // Use our own PID (always alive and owned by us, so kill(pid,0)==0).
        // AgentManager::for_vm will create a VM directory but reconnect
        // will fail (no socket/agent), so it hits the "alive but unreachable"
        // path. The DB record should be preserved.
        let our_pid = std::process::id() as i32;
        let mut record = VmRecord::new("alive-vm".into(), 1, 512, vec![], vec![], false);
        record.pid = Some(our_pid);
        record.state = RecordState::Running;
        state.db.insert_vm("alive-vm", &record).unwrap();

        // Load — reconnect will fail (no agent socket), but record should
        // be preserved in DB since process is alive
        let _loaded = state.load_persisted_machines();

        // DB record should still exist (not deleted)
        assert!(
            state.db.get_vm("alive-vm").unwrap().is_some(),
            "alive machine DB record should be preserved when reconnect fails"
        );
    }
}
