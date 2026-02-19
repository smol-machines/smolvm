//! API server state management.

use crate::agent::{AgentManager, HostMount, PortMapping, VmResources};
use crate::api::error::ApiError;
use crate::api::types::{MountSpec, PortSpec, ResourceSpec, RestartSpec, SandboxInfo};
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
    /// Whether outbound network access is enabled.
    pub network: bool,
}

/// Parameters for registering a new sandbox.
pub struct SandboxRegistration {
    /// The agent manager for this sandbox.
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
/// guard.complete(SandboxRegistration { manager, mounts, ports, resources, restart, network })?;
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
    pub fn complete(mut self, registration: SandboxRegistration) -> Result<(), ApiError> {
        // Mark as completed before calling complete_sandbox_registration
        // (which will remove from reservations internally)
        self.completed = true;
        self.state
            .complete_sandbox_registration(self.name.clone(), registration)
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

impl ApiState {
    /// Create a new API state, opening the database.
    ///
    /// Returns an error if the database cannot be opened.
    pub fn new() -> Result<Self, ApiError> {
        let db = SmolvmDb::open()
            .map_err(|e| ApiError::internal(format!("failed to open database: {}", e)))?;
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
                tracing::info!(sandbox = %name, "cleaning up dead sandbox from database");
                if let Err(e) = self.db.remove_vm(&name) {
                    tracing::warn!(sandbox = %name, error = %e, "failed to remove dead sandbox from database");
                }
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
                network: Some(record.network),
                storage_gb: record.storage_gb,
                overlay_gb: record.overlay_gb,
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
                        tracing::info!(sandbox = %name, pid = ?record.pid, "reconnected to sandbox");
                    } else {
                        // Process is alive but agent isn't reachable yet (transient
                        // boot/socket timing). Register the sandbox anyway so it's
                        // visible via APIs and the supervisor can manage it. Keep
                        // the DB record for future reconnect attempts.
                        tracing::info!(sandbox = %name, pid = ?record.pid, "sandbox alive but not yet reachable, registering for later reconnect");
                    }

                    let mut sandboxes = self.sandboxes.write();
                    sandboxes.insert(
                        name.clone(),
                        Arc::new(parking_lot::Mutex::new(SandboxEntry {
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
                    tracing::warn!(sandbox = %name, error = %e, "failed to create manager for alive sandbox, preserving DB record");
                }
            }
        }

        loaded
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
        // Hold write lock across the entire operation to prevent concurrent
        // delete races (check + DB delete + in-memory remove must be atomic).
        let mut sandboxes = self.sandboxes.write();

        if !sandboxes.contains_key(name) {
            return Err(ApiError::NotFound(format!("sandbox '{}' not found", name)));
        }

        // Remove from database first — if this fails, in-memory state stays consistent
        match self.db.remove_vm(name) {
            Ok(Some(_)) => {} // expected: row existed and was deleted
            Ok(None) => {
                // Row was already gone from DB (concurrent delete or manual cleanup).
                // Log and continue — we still need to clean up in-memory state.
                tracing::warn!(
                    sandbox = name,
                    "sandbox not found in database during remove (already deleted?)"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, sandbox = name, "failed to remove sandbox from database");
                return Err(ApiError::Internal(format!("database error: {}", e)));
            }
        }

        // Remove from in-memory registry (guaranteed to succeed — we hold the write lock)
        let entry = sandboxes
            .remove(name)
            .expect("sandbox disappeared while holding write lock");

        Ok(entry)
    }

    /// Update sandbox state in database (call after start/stop).
    ///
    /// Returns an error if the database write fails. Callers in API handlers
    /// should propagate this error; the supervisor can log and continue.
    pub fn update_sandbox_state(
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
            Some(()) => Ok(()),
            None => Err(crate::Error::database(
                "update sandbox state",
                format!("sandbox '{}' not found in database", name),
            )),
        }
    }

    /// List all sandboxes.
    pub fn list_sandboxes(&self) -> Vec<SandboxInfo> {
        let sandboxes = self.sandboxes.read();
        sandboxes
            .iter()
            .map(|(name, entry)| {
                let entry = entry.lock();
                crate::api::handlers::sandboxes::sandbox_entry_to_info(name.clone(), &entry)
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
        reg: SandboxRegistration,
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
        let mut record = VmRecord::new_with_restart(
            name.clone(),
            reg.resources.cpus.unwrap_or(crate::agent::DEFAULT_CPUS),
            reg.resources
                .memory_mb
                .unwrap_or(crate::agent::DEFAULT_MEMORY_MIB),
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
                let mut sandboxes = self.sandboxes.write();
                sandboxes.insert(
                    name,
                    Arc::new(parking_lot::Mutex::new(SandboxEntry {
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
                    "sandbox '{}' already exists in database",
                    name
                )))
            }
            Err(e) => {
                tracing::error!(error = %e, sandbox = %name, "database error during registration");
                Err(ApiError::database(e))
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

    /// Best-effort update to the VM database record. Logs warnings on
    /// `Ok(None)` (row not found) and `Err` without propagating.
    fn update_vm_best_effort(&self, name: &str, op_label: &str, f: impl FnOnce(&mut VmRecord)) {
        match self.db.update_vm(name, f) {
            Ok(Some(())) => {}
            Ok(None) => {
                tracing::warn!(sandbox = %name, op = op_label, "sandbox not found in database");
            }
            Err(e) => {
                tracing::warn!(error = %e, sandbox = %name, op = op_label, "failed to persist update");
            }
        }
    }

    /// Increment restart count for a sandbox.
    pub fn increment_restart_count(&self, name: &str) {
        if let Some(entry) = self.sandboxes.read().get(name) {
            entry.lock().restart.restart_count += 1;
        }
        self.update_vm_best_effort(name, "increment_restart_count", |r| {
            r.restart.restart_count += 1;
        });
    }

    /// Mark sandbox as user-stopped.
    pub fn mark_user_stopped(&self, name: &str, stopped: bool) {
        if let Some(entry) = self.sandboxes.read().get(name) {
            entry.lock().restart.user_stopped = stopped;
        }
        self.update_vm_best_effort(name, "mark_user_stopped", |r| {
            r.restart.user_stopped = stopped;
        });
    }

    /// Reset restart count (on successful start).
    pub fn reset_restart_count(&self, name: &str) {
        if let Some(entry) = self.sandboxes.read().get(name) {
            entry.lock().restart.restart_count = 0;
        }
        self.update_vm_best_effort(name, "reset_restart_count", |r| {
            r.restart.restart_count = 0;
        });
    }

    /// Update last exit code for a sandbox.
    pub fn set_last_exit_code(&self, name: &str, exit_code: Option<i32>) {
        self.update_vm_best_effort(name, "set_last_exit_code", |r| {
            r.last_exit_code = exit_code;
        });
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
    ///
    /// Delegates to `AgentManager::is_process_alive()` which checks the
    /// in-memory child handle (with stored start time) and falls back to the
    /// PID file. This is start-time-aware to avoid false positives from PID
    /// reuse, and covers orphan processes not tracked in-memory.
    pub fn is_sandbox_alive(&self, name: &str) -> bool {
        if let Some(entry) = self.sandboxes.read().get(name) {
            let entry = entry.lock();
            entry.manager.is_process_alive()
        } else {
            false
        }
    }
}

/// Run a blocking operation against a sandbox's agent client.
///
/// Handles the common pattern: clone entry → spawn_blocking → lock → connect → op → map errors.
pub async fn with_sandbox_client<T, F>(
    entry: &Arc<parking_lot::Mutex<SandboxEntry>>,
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
// Shared Sandbox Helpers
// ============================================================================

/// Ensure a sandbox is running, starting it if needed.
///
/// This is the shared preflight check used by exec, container, and image handlers.
/// It converts the sandbox's mount/port/resource config and calls
/// `ensure_running_with_full_config` in a blocking task.
pub async fn ensure_sandbox_running(
    entry: &Arc<parking_lot::Mutex<SandboxEntry>>,
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

        entry
            .manager
            .ensure_running_with_full_config(mounts, ports, resources)
    })
    .await
    .map_err(|e| crate::Error::agent("ensure running", e.to_string()))?
}

// ============================================================================
// Type Conversions
// ============================================================================

impl TryFrom<&MountSpec> for HostMount {
    type Error = crate::Error;

    /// Validate and canonicalize a MountSpec into a HostMount.
    fn try_from(spec: &MountSpec) -> Result<Self, Self::Error> {
        let binding = MountBinding::try_from(spec)?;
        Ok(HostMount::from(&binding))
    }
}

impl From<&HostMount> for MountSpec {
    fn from(mount: &HostMount) -> Self {
        let binding = MountBinding::from_stored(
            mount.source.to_string_lossy().to_string(),
            mount.target.to_string_lossy().to_string(),
            mount.read_only,
        );
        MountSpec::from(&binding)
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

/// Convert multiple MountSpecs to MountBindings.
///
/// Returns an error if any mount fails validation.
pub fn mounts_to_bindings(specs: &[MountSpec]) -> Result<Vec<MountBinding>, ApiError> {
    specs
        .iter()
        .map(|s| MountBinding::try_from(s).map_err(|e| ApiError::BadRequest(e.to_string())))
        .collect()
}

/// Convert ResourceSpec to VmResources.
pub fn resource_spec_to_vm_resources(spec: &ResourceSpec, network: bool) -> VmResources {
    VmResources {
        cpus: spec.cpus.unwrap_or(crate::agent::DEFAULT_CPUS),
        mem: spec.memory_mb.unwrap_or(crate::agent::DEFAULT_MEMORY_MIB),
        network,
        storage_gb: spec.storage_gb,
        overlay_gb: spec.overlay_gb,
    }
}

/// Convert VmResources to ResourceSpec.
pub fn vm_resources_to_spec(res: VmResources) -> ResourceSpec {
    ResourceSpec {
        cpus: Some(res.cpus),
        memory_mb: Some(res.mem),
        network: Some(res.network),
        storage_gb: res.storage_gb,
        overlay_gb: res.overlay_gb,
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
        };
        let res = resource_spec_to_vm_resources(&spec, false);
        assert_eq!(res.cpus, crate::agent::DEFAULT_CPUS);
        assert_eq!(res.mem, crate::agent::DEFAULT_MEMORY_MIB);
        assert!(!res.network);

        // Test with network enabled
        let res = resource_spec_to_vm_resources(&spec, true);
        assert!(res.network);
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

    // ========================================================================
    // Startup reconciliation tests
    // ========================================================================

    #[test]
    fn test_load_persisted_sandboxes_removes_dead_records() {
        let (_dir, state) = temp_api_state();

        // Insert a record with a PID that doesn't exist (dead process)
        let mut record = VmRecord::new("dead-sandbox".into(), 1, 512, vec![], vec![], false);
        record.pid = Some(i32::MAX); // PID that certainly doesn't exist
        record.state = RecordState::Running;
        state.db.insert_vm("dead-sandbox", &record).unwrap();

        // Verify record exists before load
        assert!(state.db.get_vm("dead-sandbox").unwrap().is_some());

        // Load should detect dead process and clean up DB record
        let loaded = state.load_persisted_sandboxes();
        assert!(loaded.is_empty(), "dead sandbox should not be loaded");

        // DB record should be cleaned up
        assert!(
            state.db.get_vm("dead-sandbox").unwrap().is_none(),
            "dead sandbox DB record should be removed"
        );

        // Name should be available for reuse
        assert!(state.reserve_sandbox_name("dead-sandbox").is_ok());
    }

    #[test]
    fn test_load_persisted_sandboxes_dead_record_does_not_block_name() {
        let (_dir, state) = temp_api_state();

        // Insert a dead record with no PID (definitely dead)
        let record = VmRecord::new("ghost".into(), 1, 512, vec![], vec![], false);
        state.db.insert_vm("ghost", &record).unwrap();

        // Load should remove it (no PID = dead)
        let loaded = state.load_persisted_sandboxes();
        assert!(loaded.is_empty());

        // Name should not be blocked
        assert!(
            state.reserve_sandbox_name("ghost").is_ok(),
            "cleaned-up name should be available for reuse"
        );
    }

    #[test]
    fn test_load_persisted_sandboxes_preserves_alive_unreachable_records() {
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
        let _loaded = state.load_persisted_sandboxes();

        // DB record should still exist (not deleted)
        assert!(
            state.db.get_vm("alive-vm").unwrap().is_some(),
            "alive sandbox DB record should be preserved when reconnect fails"
        );
    }
}
