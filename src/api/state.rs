//! API server state management.

use crate::agent::{AgentManager, HostMount, PortMapping, VmResources};
use crate::api::error::ApiError;
use crate::api::types::{MountInfo, MountSpec, PortSpec, ResourceSpec, RestartSpec, SandboxInfo};
use crate::config::{RecordState, RestartConfig, RestartPolicy, VmRecord};
use crate::db::SmolvmDb;
use crate::mount::MountBinding;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Shared API server state.
pub struct ApiState {
    /// Registry of sandbox managers by name.
    sandboxes: RwLock<HashMap<String, Arc<parking_lot::Mutex<SandboxEntry>>>>,
    /// Reserved sandbox names (creation in progress).
    /// This prevents race conditions during sandbox creation.
    reserved_names: RwLock<HashSet<String>>,
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
    /// Restart configuration for this sandbox.
    pub restart: RestartConfig,
}

/// RAII guard for sandbox name reservation.
///
/// Automatically releases reservation on drop unless consumed by `complete()`.
/// This ensures reservations are always cleaned up, even on panic.
///
/// # Example
///
/// ```ignore
/// let guard = ReservationGuard::new(&state, "my-sandbox".to_string())?;
///
/// // Create the sandbox manager...
/// let manager = AgentManager::for_vm(guard.name())?;
///
/// // Complete registration, consuming the guard
/// guard.complete(manager, mounts, ports, resources, restart)?;
/// ```
pub struct ReservationGuard<'a> {
    state: &'a ApiState,
    name: String,
    completed: bool,
}

impl<'a> ReservationGuard<'a> {
    /// Reserve a sandbox name. Returns a guard that auto-releases on drop.
    pub fn new(state: &'a ApiState, name: String) -> Result<Self, ApiError> {
        state.reserve_sandbox_name(&name)?;
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
    /// This transfers ownership of the name to the sandbox registry.
    pub fn complete(
        mut self,
        manager: AgentManager,
        mounts: Vec<MountSpec>,
        ports: Vec<PortSpec>,
        resources: ResourceSpec,
        restart: RestartConfig,
    ) -> Result<(), ApiError> {
        // Mark as completed before calling complete_sandbox_registration
        // (which will remove from reservations internally)
        self.completed = true;
        self.state.complete_sandbox_registration(
            self.name.clone(),
            manager,
            mounts,
            ports,
            resources,
            restart,
        )
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state.release_sandbox_reservation(&self.name);
            tracing::debug!(sandbox = %self.name, "reservation guard released on drop");
        }
    }
}

/// RAII guard for temporarily closing the database during fork operations.
///
/// Automatically reopens the database on drop, ensuring the DB is never left
/// closed even if the operation is cancelled or panics.
///
/// # Example
///
/// ```ignore
/// // Guard closes DB on creation, reopens on drop
/// let _guard = DbCloseGuard::new(&state);
///
/// // Fork operation - even if this panics or is cancelled,
/// // the guard's Drop will reopen the database
/// let result = tokio::task::spawn_blocking(|| {
///     // fork happens here
/// }).await;
///
/// // Guard dropped here (or earlier if cancelled), DB reopened
/// ```
pub struct DbCloseGuard<'a> {
    state: &'a ApiState,
}

impl<'a> DbCloseGuard<'a> {
    /// Create a new guard, closing the database.
    ///
    /// The database will be automatically reopened when the guard is dropped.
    pub fn new(state: &'a ApiState) -> Self {
        state.db.close_temporarily();
        Self { state }
    }
}

impl Drop for DbCloseGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.state.db.reopen() {
            // Log error but don't panic - we're in a Drop impl
            tracing::error!(error = %e, "failed to reopen database in DbCloseGuard drop");
        }
    }
}

impl ApiState {
    /// Create a new API state, opening the database.
    ///
    /// Returns an error if the database cannot be opened.
    pub fn new() -> Result<Self, ApiError> {
        let db = SmolvmDb::open()
            .map_err(|e| ApiError::Internal(format!("failed to open database: {}", e)))?;
        Ok(Self {
            sandboxes: RwLock::new(HashMap::new()),
            reserved_names: RwLock::new(HashSet::new()),
            db,
        })
    }

    /// Create a new API state with a specific database.
    ///
    /// Useful for testing with temporary databases.
    pub fn with_db(db: SmolvmDb) -> Self {
        Self {
            sandboxes: RwLock::new(HashMap::new()),
            reserved_names: RwLock::new(HashSet::new()),
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
                                restart: record.restart.clone(),
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
        restart: RestartConfig,
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
        let record = VmRecord::new_with_restart(
            name.clone(),
            resources.cpus.unwrap_or(crate::agent::DEFAULT_CPUS),
            resources
                .memory_mb
                .unwrap_or(crate::agent::DEFAULT_MEMORY_MIB),
            mounts
                .iter()
                .map(|m| (m.source.clone(), m.target.clone(), m.readonly))
                .collect(),
            ports.iter().map(|p| (p.host, p.guest)).collect(),
            true, // Enable network for sandboxes
            restart.clone(),
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
                restart,
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
                let restart_count = if entry.restart.restart_count > 0 {
                    Some(entry.restart.restart_count)
                } else {
                    None
                };
                SandboxInfo {
                    name: name.clone(),
                    state: state.to_lowercase(),
                    pid,
                    mounts,
                    ports: entry.ports.clone(),
                    resources: entry.resources.clone(),
                    restart_count,
                }
            })
            .collect()
    }

    /// Check if a sandbox exists.
    pub fn sandbox_exists(&self, name: &str) -> bool {
        self.sandboxes.read().contains_key(name)
    }

    // ========================================================================
    // Atomic Sandbox Creation (Reservation Pattern)
    // ========================================================================

    /// Reserve a sandbox name atomically.
    ///
    /// This prevents race conditions where two concurrent requests try to create
    /// a sandbox with the same name. The name is reserved until either:
    /// - `complete_sandbox_registration()` is called (success)
    /// - `release_sandbox_reservation()` is called (failure/cleanup)
    ///
    /// Returns `Err(Conflict)` if the name is already taken or reserved.
    pub fn reserve_sandbox_name(&self, name: &str) -> Result<(), ApiError> {
        // First check: sandbox existence (early exit for common case).
        // Use separate scope to release read lock before acquiring write lock.
        // This prevents lock-order inversion with complete_sandbox_registration.
        {
            let sandboxes = self.sandboxes.read();
            if sandboxes.contains_key(name) {
                return Err(ApiError::Conflict(format!(
                    "sandbox '{}' already exists",
                    name
                )));
            }
        }

        // Acquire reservation lock
        let mut reserved = self.reserved_names.write();

        // Double-check sandbox existence (could have been added while we
        // didn't hold the sandboxes lock). This is necessary for correctness.
        if self.sandboxes.read().contains_key(name) {
            return Err(ApiError::Conflict(format!(
                "sandbox '{}' already exists",
                name
            )));
        }

        // Check if name is already reserved (creation in progress)
        if reserved.contains(name) {
            return Err(ApiError::Conflict(format!(
                "sandbox '{}' is being created by another request",
                name
            )));
        }

        // Also check database for persisted sandboxes not yet loaded
        if let Ok(Some(_)) = self.db.get_vm(name) {
            return Err(ApiError::Conflict(format!(
                "sandbox '{}' already exists in database",
                name
            )));
        }

        // Reserve the name
        reserved.insert(name.to_string());
        tracing::debug!(sandbox = %name, "reserved sandbox name");
        Ok(())
    }

    /// Release a sandbox name reservation.
    ///
    /// Call this if sandbox creation fails after `reserve_sandbox_name()`.
    pub fn release_sandbox_reservation(&self, name: &str) {
        let mut reserved = self.reserved_names.write();
        if reserved.remove(name) {
            tracing::debug!(sandbox = %name, "released sandbox name reservation");
        }
    }

    /// Complete sandbox registration after successful creation.
    ///
    /// This converts a reserved name into a fully registered sandbox.
    /// The reservation is released and the sandbox entry is added.
    pub fn complete_sandbox_registration(
        &self,
        name: String,
        manager: AgentManager,
        mounts: Vec<MountSpec>,
        ports: Vec<PortSpec>,
        resources: ResourceSpec,
        restart: RestartConfig,
    ) -> Result<(), ApiError> {
        // Remove from reservations
        {
            let mut reserved = self.reserved_names.write();
            if !reserved.remove(&name) {
                // Name wasn't reserved - this is a programming error
                tracing::warn!(sandbox = %name, "completing registration for non-reserved name");
            }
        }

        // Persist to database (with conflict detection)
        let record = VmRecord::new_with_restart(
            name.clone(),
            resources.cpus.unwrap_or(crate::agent::DEFAULT_CPUS),
            resources
                .memory_mb
                .unwrap_or(crate::agent::DEFAULT_MEMORY_MIB),
            mounts
                .iter()
                .map(|m| (m.source.clone(), m.target.clone(), m.readonly))
                .collect(),
            ports.iter().map(|p| (p.host, p.guest)).collect(),
            true, // Enable network for sandboxes
            restart.clone(),
        );

        // Use insert_vm_if_not_exists for atomic database insert
        match self.db.insert_vm_if_not_exists(&name, &record) {
            Ok(true) => {
                // Successfully inserted, now add to in-memory registry
                let mut sandboxes = self.sandboxes.write();
                sandboxes.insert(
                    name,
                    Arc::new(parking_lot::Mutex::new(SandboxEntry {
                        manager,
                        mounts,
                        ports,
                        resources,
                        restart,
                    })),
                );
                Ok(())
            }
            Ok(false) => {
                // Name already exists in database (shouldn't happen with reservation)
                Err(ApiError::Conflict(format!(
                    "sandbox '{}' already exists in database",
                    name
                )))
            }
            Err(e) => {
                tracing::error!(error = %e, sandbox = %name, "database error during registration");
                Err(ApiError::Internal(format!("database error: {}", e)))
            }
        }
    }

    /// Stop all sandboxes (for graceful shutdown).
    pub fn stop_all_sandboxes(&self) {
        // Collect names first to avoid holding read lock during slow stop operations.
        // This allows other sandbox operations to proceed while we're stopping.
        let names: Vec<String> = self.sandboxes.read().keys().cloned().collect();

        for name in names {
            // Re-acquire lock for each sandbox to minimize lock hold time
            let entry = match self.sandboxes.read().get(&name).cloned() {
                Some(e) => e,
                None => continue, // Sandbox was removed while we were iterating
            };

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

    // ========================================================================
    // Restart Management Methods
    // ========================================================================

    /// List all sandbox names.
    pub fn list_sandbox_names(&self) -> Vec<String> {
        self.sandboxes.read().keys().cloned().collect()
    }

    /// Get restart config for a sandbox from the in-memory registry.
    pub fn get_restart_config(&self, name: &str) -> Option<RestartConfig> {
        let sandboxes = self.sandboxes.read();
        sandboxes.get(name).map(|entry| {
            let entry = entry.lock();
            entry.restart.clone()
        })
    }

    /// Increment restart count for a sandbox.
    pub fn increment_restart_count(&self, name: &str) {
        // Update in-memory
        if let Some(entry) = self.sandboxes.read().get(name) {
            let mut entry = entry.lock();
            entry.restart.restart_count += 1;
        }
        // Update in database
        if let Err(e) = self.db.update_vm(name, |r| r.restart.restart_count += 1) {
            tracing::warn!(error = %e, sandbox = %name, "failed to persist restart count");
        }
    }

    /// Mark sandbox as user-stopped.
    pub fn mark_user_stopped(&self, name: &str, stopped: bool) {
        // Update in-memory
        if let Some(entry) = self.sandboxes.read().get(name) {
            let mut entry = entry.lock();
            entry.restart.user_stopped = stopped;
        }
        // Update in database
        if let Err(e) = self
            .db
            .update_vm(name, |r| r.restart.user_stopped = stopped)
        {
            tracing::warn!(error = %e, sandbox = %name, "failed to persist user_stopped");
        }
    }

    /// Reset restart count (on successful start).
    pub fn reset_restart_count(&self, name: &str) {
        // Update in-memory
        if let Some(entry) = self.sandboxes.read().get(name) {
            let mut entry = entry.lock();
            entry.restart.restart_count = 0;
        }
        // Update in database
        if let Err(e) = self.db.update_vm(name, |r| r.restart.restart_count = 0) {
            tracing::warn!(error = %e, sandbox = %name, "failed to reset restart count");
        }
    }

    /// Update last exit code for a sandbox.
    pub fn set_last_exit_code(&self, name: &str, exit_code: Option<i32>) {
        if let Err(e) = self.db.update_vm(name, |r| r.last_exit_code = exit_code) {
            tracing::warn!(error = %e, sandbox = %name, "failed to persist exit code");
        }
    }

    /// Get last exit code for a sandbox.
    pub fn get_last_exit_code(&self, name: &str) -> Option<i32> {
        self.db
            .get_vm(name)
            .ok()
            .flatten()
            .and_then(|r| r.last_exit_code)
    }

    /// Check if a sandbox process is alive.
    pub fn is_sandbox_alive(&self, name: &str) -> bool {
        if let Some(entry) = self.sandboxes.read().get(name) {
            let entry = entry.lock();
            entry.manager.is_running()
        } else {
            false
        }
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

impl ApiState {
    /// Create a new API state with default settings.
    ///
    /// # Panics
    /// Panics if the database cannot be opened. For fallible construction,
    /// use `ApiState::new()` instead.
    pub fn new_or_panic() -> Self {
        Self::new().expect("failed to create API state")
    }
}

// ============================================================================
// Type Conversions
// ============================================================================

/// Convert MountSpec to HostMount.
///
/// Validates and canonicalizes the mount paths.
pub fn mount_spec_to_host_mount(spec: &MountSpec) -> crate::Result<HostMount> {
    // Use MountBinding for validation and canonicalization
    let binding = MountBinding::try_from(spec)?;
    Ok(HostMount::from(&binding))
}

/// Convert multiple MountSpecs to MountBindings.
///
/// Returns an error if any mount fails validation.
pub fn mounts_to_bindings(specs: &[MountSpec]) -> Result<Vec<MountBinding>, ApiError> {
    specs
        .iter()
        .map(|s| MountBinding::try_from(s).map_err(|e| ApiError::BadRequest(e.to_string())))
        .collect()
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
        network: false, // TODO: Add network to ResourceSpec if needed
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
    // Create a MountBinding without validation (already validated)
    let binding = MountBinding::from_stored(
        mount.source.to_string_lossy().to_string(),
        mount.target.to_string_lossy().to_string(),
        mount.read_only,
    );
    MountSpec::from(&binding)
}

/// Convert PortMapping to PortSpec.
pub fn port_mapping_to_spec(mapping: &PortMapping) -> PortSpec {
    PortSpec {
        host: mapping.host,
        guest: mapping.guest,
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
                restart_count: 0,
                user_stopped: false,
            }
        }
        None => RestartConfig::default(),
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
        let (_dir, state) = temp_api_state();
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
