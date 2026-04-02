//! `Smolvm` — stateful orchestration for SDKs and the API server.
//!
//! Wraps `control::` functions with a cached registry of `VmHandle`s and
//! name reservation for concurrent creation safety. This is the entry point
//! for all SDK consumers (Rust, Node via NAPI, future Go/Python/C via FFI)
//! and the API server.
//!
//! CLI does not use this — it calls `control::` functions directly.

use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::control::{self, VmHandle};
use crate::data::vm::MicroVm;
use crate::internal::agent::AgentClient;
use crate::internal::db::SmolvmDb;

/// Stateful VM orchestration for concurrent/long-lived hosts.
///
/// Owns a database handle and a registry of cached `VmHandle`s.
/// All lifecycle operations persist to DB and update the registry.
pub struct Smolvm {
    db: SmolvmDb,
    registry: RwLock<HashMap<String, Arc<Mutex<VmHandle>>>>,
    reserved: RwLock<HashSet<String>>,
}

/// RAII guard for name reservation during VM creation.
///
/// Prevents concurrent creation of VMs with the same name.
/// Automatically releases the reservation on drop unless consumed.
pub struct ReservationGuard<'a> {
    smolvm: &'a Smolvm,
    name: String,
    completed: bool,
}

impl<'a> ReservationGuard<'a> {
    /// Get the reserved name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Mark the reservation as completed (name is now in the registry).
    pub fn complete(&mut self) {
        self.completed = true;
        self.smolvm.reserved.write().remove(&self.name);
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.smolvm.reserved.write().remove(&self.name);
            tracing::debug!(vm = %self.name, "reservation guard released on drop");
        }
    }
}

impl Smolvm {
    /// Create a new Smolvm instance, opening the database.
    pub fn new() -> crate::error::Result<Self> {
        let db = SmolvmDb::open()?;
        Ok(Self {
            db,
            registry: RwLock::new(HashMap::new()),
            reserved: RwLock::new(HashSet::new()),
        })
    }

    /// Create a new Smolvm with a specific database (useful for testing).
    pub fn with_db(db: SmolvmDb) -> Self {
        Self {
            db,
            registry: RwLock::new(HashMap::new()),
            reserved: RwLock::new(HashSet::new()),
        }
    }

    /// Get a reference to the underlying database.
    pub fn db(&self) -> &SmolvmDb {
        &self.db
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /// Create a new VM. Validates name, persists to DB.
    pub fn create_vm(&self, vm: MicroVm) -> crate::error::Result<MicroVm> {
        let result = control::create_vm(&self.db, vm)?;
        Ok(result)
    }

    /// Get a VM by name.
    pub fn get_vm(&self, name: &str) -> crate::error::Result<MicroVm> {
        control::get_vm(&self.db, name)
    }

    /// List all persisted VMs.
    pub fn list_vms(&self) -> crate::error::Result<Vec<MicroVm>> {
        control::list_vms(&self.db)
    }

    /// Start a VM. Caches the VmHandle in the registry.
    ///
    /// Returns MicroVm (the handle is cached internally).
    /// Idempotent — reconnects if already running.
    pub fn start_vm(&self, name: &str) -> crate::error::Result<MicroVm> {
        let handle = control::start_vm(&self.db, name)?;
        let vm = handle.vm().clone();
        self.registry
            .write()
            .insert(name.to_string(), Arc::new(Mutex::new(handle)));
        Ok(vm)
    }

    /// Stop a VM. Removes from registry.
    pub fn stop_vm(&self, name: &str) -> crate::error::Result<MicroVm> {
        // Remove from registry first (the handle's manager will be dropped)
        self.registry.write().remove(name);
        control::stop_vm(&self.db, name)
    }

    /// Delete a VM. Removes from registry and DB.
    pub fn delete_vm(&self, name: &str, force: bool) -> crate::error::Result<()> {
        self.registry.write().remove(name);
        control::delete_vm(&self.db, name, force)
    }

    /// Resize a VM's disks.
    pub fn resize_vm(
        &self,
        name: &str,
        storage_gib: Option<u64>,
        overlay_gib: Option<u64>,
    ) -> crate::error::Result<MicroVm> {
        control::resize_vm(&self.db, name, storage_gib, overlay_gib)
    }

    /// Update a VM's spec/status in the DB.
    pub fn update_vm(&self, vm: &MicroVm) -> crate::error::Result<()> {
        control::update_vm(&self.db, vm)
    }

    // ========================================================================
    // Connection
    // ========================================================================

    /// Get an AgentClient for a running VM (from the cached registry).
    ///
    /// If the VM is not in the registry, attempts to start it first.
    pub fn connect(&self, name: &str) -> crate::error::Result<AgentClient> {
        {
            let registry = self.registry.read();
            if let Some(handle) = registry.get(name) {
                let h = handle.lock();
                return h.connect();
            }
        }

        // Not in registry — try to start and then connect
        self.start_vm(name)?;
        let registry = self.registry.read();
        let handle = registry.get(name).ok_or_else(|| {
            crate::Error::agent("connect", format!("failed to start vm '{}'", name))
        })?;
        let h = handle.lock();
        h.connect()
    }

    /// Check if a VM process is alive (from cached registry).
    pub fn is_alive(&self, name: &str) -> bool {
        let registry = self.registry.read();
        if let Some(handle) = registry.get(name) {
            let h = handle.lock();
            if let Some(status) = h.vm().status.as_ref() {
                return status.phase == crate::data::vm::VmPhase::Running;
            }
        }
        false
    }

    // ========================================================================
    // Concurrency
    // ========================================================================

    /// Reserve a VM name for creation. Prevents concurrent creation races.
    ///
    /// Returns a `ReservationGuard` that auto-releases on drop.
    pub fn reserve_name(&self, name: &str) -> crate::error::Result<ReservationGuard<'_>> {
        // Check registry
        if self.registry.read().contains_key(name) {
            return Err(crate::Error::config(
                "reserve name",
                format!("'{}' already exists", name),
            ));
        }
        // Check DB
        if self.db.get_vm(name)?.is_some() {
            return Err(crate::Error::config(
                "reserve name",
                format!("'{}' already exists", name),
            ));
        }
        // Check reservations
        let mut reserved = self.reserved.write();
        if reserved.contains(name) {
            return Err(crate::Error::config(
                "reserve name",
                format!("'{}' is being created by another request", name),
            ));
        }
        reserved.insert(name.to_string());
        Ok(ReservationGuard {
            smolvm: self,
            name: name.to_string(),
            completed: false,
        })
    }

    // ========================================================================
    // Startup recovery
    // ========================================================================

    /// Reconnect to VMs that were persisted as Running in the DB.
    ///
    /// Call on server/SDK startup. Dead processes get cleaned up.
    pub fn reconnect_persisted(&self) -> crate::error::Result<()> {
        let vms = self.db.list_vms()?;

        for (name, record) in vms {
            if record.is_process_alive() {
                // Try to reconnect
                match control::start_vm(&self.db, &name) {
                    Ok(handle) => {
                        self.registry
                            .write()
                            .insert(name.clone(), Arc::new(Mutex::new(handle)));
                        tracing::info!(vm = %name, "reconnected to running vm");
                    }
                    Err(e) => {
                        tracing::warn!(vm = %name, error = %e, "failed to reconnect to vm");
                    }
                }
            } else if record.state == crate::internal::config::RecordState::Running {
                // Process died — clean up stale record
                tracing::info!(vm = %name, "cleaning up dead vm from database");
                if let Err(e) = self.db.remove_vm(&name) {
                    tracing::warn!(vm = %name, error = %e, "failed to remove dead vm");
                }
            }
        }

        Ok(())
    }
}
