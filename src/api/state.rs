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

/// Per-PID sample for computing CPU rate across heartbeat intervals.
#[derive(Debug, Clone, Copy)]
struct CpuSample {
    /// When the sample was taken.
    at: std::time::Instant,
    /// Cumulative CPU time at that moment (nanoseconds).
    cpu_time_ns: u64,
}

/// Shared API server state.
pub struct ApiState {
    /// Registry of machine managers by name.
    machines: RwLock<HashMap<String, Arc<parking_lot::Mutex<MachineEntry>>>>,
    /// Reserved machine names (creation in progress).
    /// This prevents race conditions during machine creation.
    reserved_names: RwLock<HashSet<String>>,
    /// Per-machine lifecycle locks serializing start/stop/delete/restart.
    ///
    /// On macOS, stop/delete `hdiutil`-detach a machine's case-sensitive
    /// packed-layers volume while a concurrent start acquires+mounts+launches
    /// against it. Without exclusion a detach can pull the volume out from under
    /// a freshly-launched VM serving it over virtiofs, or a guest launched in the
    /// detach window hits the launcher's missing-dir error (review finding #3).
    /// Each lifecycle handler `.lock().await`s this per-name async mutex as its
    /// outermost lock — before any DB read or `MachineEntry` mutex — and holds it
    /// for the whole operation, so mount and detach can never interleave for one
    /// machine. Lock order is lifecycle (tokio, async) → entry (parking_lot,
    /// inside `spawn_blocking`); no entry-holding path ever takes lifecycle, so
    /// there is no inversion. On Linux the guarded detach/mount are compile-time
    /// no-ops, making this harmless serialization. Scope: the API server only —
    /// the embedded (`control.rs`) and CLI (`vm_common.rs`) paths are separate
    /// processes with no shared in-process lock.
    ///
    /// Entries are created on first use and never removed: the map is bounded by
    /// the number of distinct machine names, so a retained `Arc<Mutex<()>>` per
    /// deleted name is negligible, and never removing avoids handing two callers
    /// different mutexes for the same name (which would defeat the exclusion).
    lifecycle_locks: RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Database for persistent state.
    db: SmolvmDb,
    /// Previous CPU samples per VM PID, used to compute the fractional-CPU
    /// rate as a delta over wall time. Pruned on each sample to drop dead PIDs.
    cpu_samples: parking_lot::Mutex<HashMap<i32, CpuSample>>,
    /// Monotonic base for the runtime-liveness heartbeat. All heartbeat values
    /// are millis elapsed since this instant, so they're a single lock-free
    /// `AtomicU64` instead of a mutex-guarded `Instant`.
    started_at: std::time::Instant,
    /// Milliseconds (since `started_at`) of the supervisor's last tick. The
    /// supervisor bumps this every `CHECK_INTERVAL` from the main runtime, so a
    /// stale value means the main runtime's timer wheel stopped being driven
    /// (a reactor stall) or the supervisor task itself wedged. The loopback
    /// `/capacity` listener — which runs on its OWN runtime and so keeps
    /// answering even when the main runtime is stuck — reads this to report the
    /// node as unschedulable (HTTP 503) the moment the main runtime stops
    /// making progress, turning a silent wedge into a fast, honest drain signal.
    runtime_heartbeat_ms: std::sync::atomic::AtomicU64,
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
    /// Secret refs persisted on the VM record, cached in memory so
    /// exec handlers don't need a second DB read per request. Exec
    /// handlers resolve these under `RecordReplay` scope.
    pub secret_refs: std::collections::BTreeMap<String, smolvm_protocol::SecretRef>,
    /// Path to the `.smolmachine` sidecar this machine was created from, if any.
    /// When set, the start paths mount the bundle's pre-extracted OCI layers via
    /// virtiofs instead of having the guest pull from a registry. `None` for
    /// image/registry-sourced machines. Mirrors `VmRecord::source_smolmachine`.
    pub source_smolmachine: Option<String>,
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
    /// OCI image reference (e.g., "alpine:latest").
    pub image: Option<String>,
    /// Path to .smolmachine sidecar this machine was created from.
    pub source_smolmachine: Option<String>,
    /// Container entrypoint (from manifest).
    pub entrypoint: Vec<String>,
    /// Container cmd (from manifest).
    pub cmd: Vec<String>,
    /// Environment variables (from manifest).
    pub env: Vec<(String, String)>,
    /// Working directory (from manifest).
    pub workdir: Option<String>,
    /// Secret refs to attach to this machine (from a Smolfile or
    /// `CreateMachineRequest.secrets`).
    pub secret_refs: std::collections::BTreeMap<String, smolvm_protocol::SecretRef>,
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
    token: String,
    completed: bool,
}

impl<'a> ReservationGuard<'a> {
    /// Reserve a machine name. Returns a guard that auto-releases on drop.
    pub fn new(state: &'a ApiState, name: String) -> Result<Self, ApiError> {
        let token = SmolvmDb::create_reservation_token();
        state.reserve_machine_name(&name, &token)?;
        Ok(Self {
            state,
            name,
            token,
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
        self.state
            .complete_machine_registration(self.name.clone(), &self.token, registration)?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state
                .release_machine_reservation(&self.name, &self.token);
            tracing::debug!(machine = %self.name, "reservation guard released on drop");
        }
    }
}

/// Whether `s` is a VM data-dir name — i.e. the output shape of `vm_dir_hash`:
/// exactly 16 lowercase hex chars. Used to confine the dangling-dir sweep to VM
/// dirs, never the shared pack store (`_shared`) or other cache entries.
fn is_vm_dir_hash(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Pure reaping decision for the dangling-dir sweep: a cache entry is dangling
/// iff it has the VM-dir-hash shape AND no live machine record maps to it.
fn is_dangling_vm_dir(dir_name: &str, valid_hashes: &std::collections::HashSet<String>) -> bool {
    is_vm_dir_hash(dir_name) && !valid_hashes.contains(dir_name)
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
            lifecycle_locks: RwLock::new(HashMap::new()),
            db,
            cpu_samples: parking_lot::Mutex::new(HashMap::new()),
            started_at: std::time::Instant::now(),
            runtime_heartbeat_ms: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Create a new API state with a specific database.
    ///
    /// Useful for testing with temporary databases.
    pub fn with_db(db: SmolvmDb) -> Self {
        Self {
            machines: RwLock::new(HashMap::new()),
            reserved_names: RwLock::new(HashSet::new()),
            lifecycle_locks: RwLock::new(HashMap::new()),
            db,
            cpu_samples: parking_lot::Mutex::new(HashMap::new()),
            started_at: std::time::Instant::now(),
            runtime_heartbeat_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// How long the main runtime may go without a supervisor heartbeat before
    /// the loopback `/capacity` door reports the node as stalled. Defaults to
    /// 4× the supervisor's 5s tick (`SMOLVM_RUNTIME_STALE_SECS` overrides), so
    /// a few slow ticks never flap the node but a genuine reactor wedge drains
    /// it within ~20s + the node-agent's own cordon grace.
    fn runtime_stale_after_ms() -> u64 {
        std::env::var("SMOLVM_RUNTIME_STALE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .map(|s| s * 1000)
            .unwrap_or(20_000)
    }

    /// Record that the main runtime is making progress. Called from the
    /// supervisor's tick — a value only advances if the runtime's timer wheel
    /// fired the tick, so it is a true liveness signal for the main reactor.
    pub fn beat_runtime_heartbeat(&self) {
        let elapsed = self.started_at.elapsed().as_millis() as u64;
        self.runtime_heartbeat_ms
            .store(elapsed, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the main runtime has gone too long without a heartbeat — i.e. the
    /// supervisor tick stopped firing, which on a multi-thread runtime means the
    /// IO/timer driver is no longer being driven. Read from the loopback door's
    /// dedicated runtime so it stays accurate even when the main runtime is
    /// wedged. The window before the first heartbeat is treated as healthy
    /// (startup), since `elapsed - 0 = elapsed` only crosses the threshold once
    /// the runtime has actually been up longer than the stall window without a
    /// single supervisor tick — which is itself a real stall.
    pub fn runtime_stalled(&self) -> bool {
        let now = self.started_at.elapsed().as_millis() as u64;
        let last = self
            .runtime_heartbeat_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        now.saturating_sub(last) > Self::runtime_stale_after_ms()
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
            // Only clean up machines that have a PID (were started) but whose
            // process is no longer alive.  Machines in "created" state (pid=None)
            // have never been started and must be preserved — they are valid
            // configs waiting for a start call.
            if record.pid.is_some() && !record.is_process_alive() {
                tracing::info!(machine = %name, "cleaning up dead machine from database");
                if let Err(e) = self.db.remove_vm(&name) {
                    tracing::warn!(machine = %name, error = %e, "failed to remove dead machine from database");
                }
                // Reclaim the data dir too. Removing only the DB record leaks the
                // machine's storage + overlay images (multi-GB sparse files) — and
                // since the record is gone, nothing will ever clean them up later.
                // On a long-lived node that churns/crashes machines this is a slow
                // disk-fill across server restarts. The `pid.is_some()` guard above
                // means we only touch machines that were started and then died, not
                // intentionally-stopped (pid=None) machines whose disks must persist.
                let dir = crate::agent::vm_data_dir(&name);
                if dir.exists() {
                    if let Err(e) = std::fs::remove_dir_all(&dir) {
                        tracing::warn!(machine = %name, error = %e, "failed to remove dead machine data dir");
                    }
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
                gpu: record.gpu,
                storage_gb: record.storage_gb,
                overlay_gb: record.overlay_gb,
                allowed_cidrs: record.allowed_cidrs.clone(),
                allowed_hosts: record.dns_filter_hosts.clone(),
                network_backend: record.network_backend,
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
                            secret_refs: record.secret_refs.clone(),
                            source_smolmachine: record.source_smolmachine.clone(),
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

    /// Remove VM data dirs under the cache root that no current machine record
    /// references — a filesystem-level GC for the dirs the per-record path can't
    /// see (a dir whose record was already gone: a legacy leak, or a CLI ephemeral
    /// orphan that resolved to the wrong hash).
    ///
    /// Deliberately NOT called from `load_persisted_machines`: this is a global
    /// sweep keyed off the *current* DB, so it must only run in the real `smolvm
    /// serve` process (which owns this node's cache), never from a unit test or an
    /// embedded library user whose DB does not describe the host's dirs — there it
    /// would wipe live machines. The caller invokes it at server startup, before
    /// requests are served, so it cannot race VM creation. Returns the count
    /// removed.
    ///
    /// Safe by construction: only entries whose name is a VM data-dir hash (16
    /// lowercase hex chars, the `vm_dir_hash` shape) are candidates, so the shared
    /// pack store (`_shared`) and marker files are never touched, and every hash
    /// backing a live DB record is skipped.
    pub fn reclaim_dangling_vm_dirs(&self) -> usize {
        let valid: std::collections::HashSet<String> = match self.db.list_vms() {
            Ok(vms) => vms
                .iter()
                .map(|(name, _)| crate::agent::vm_dir_hash(name))
                .collect(),
            Err(_) => return 0,
        };
        let root = crate::agent::vm_cache_root();
        let entries = match std::fs::read_dir(&root) {
            Ok(e) => e,
            Err(_) => return 0,
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let dir_name = entry.file_name().to_string_lossy().into_owned();
            if !is_dangling_vm_dir(&dir_name, &valid) {
                continue;
            }
            if entry.path().is_dir() {
                tracing::info!(dir = %dir_name, "removing dangling VM data dir (no machine record)");
                match std::fs::remove_dir_all(entry.path()) {
                    Ok(()) => removed += 1,
                    Err(e) => {
                        tracing::warn!(dir = %dir_name, error = %e, "failed to remove dangling VM data dir")
                    }
                }
            }
        }
        removed
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

    /// Get the per-machine lifecycle lock for `name`, creating it on first use.
    ///
    /// Callers `.lock().await` the returned mutex at the top of
    /// start/stop/delete/restart and hold the guard for the whole operation so
    /// the macOS layers-volume mount (start) and detach (stop/delete) can never
    /// interleave for one machine. See the `lifecycle_locks` field docs for the
    /// lock-ordering and scope contract.
    pub fn lifecycle_lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        // Fast path: the lock already exists (the common case after first use).
        if let Some(lock) = self.lifecycle_locks.read().get(name) {
            return lock.clone();
        }
        // Slow path: create it under the write lock. `or_insert_with` collapses
        // the race where two callers reach here for the same name concurrently —
        // both end up with the same `Arc`, preserving mutual exclusion.
        self.lifecycle_locks
            .write()
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Remove a machine from the registry (also removes from database).
    ///
    /// Must NOT hold the registry write lock across the DB delete: `db.remove_vm`
    /// is synchronous disk I/O (SQLite, which under churn waits on `busy_timeout`),
    /// and spanning it with the write lock blocks every reader — including the
    /// `/health` probe (`machine_counts` takes `machines.read()`). Under delete
    /// churn on a small (2-core) worker that wedges the whole node: the reactor's
    /// threads park on the registry lock and can no longer `accept()`. The real
    /// per-machine mutual exclusion is the caller's `lifecycle_lock` (held across
    /// the entire start/stop/delete), so releasing the registry lock between the
    /// existence check, the DB delete, and the in-memory remove is safe.
    pub fn remove_machine(
        &self,
        name: &str,
    ) -> Result<Arc<parking_lot::Mutex<MachineEntry>>, ApiError> {
        // Existence check under a brief read lock (released immediately).
        if !self.machines.read().contains_key(name) {
            return Err(ApiError::NotFound(format!("machine '{}' not found", name)));
        }

        // Remove from the database first, WITHOUT the registry lock held — if this
        // fails, in-memory state stays consistent (the entry is still in the map).
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

        // Brief write lock: swap the entry out of the registry (O(1)). If a
        // concurrent path already removed it, degrade to NotFound rather than
        // panicking — correctness for the same name is guaranteed by the caller's
        // lifecycle lock, so this only fires on misuse.
        self.machines
            .write()
            .remove(name)
            .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))
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

    /// Return (total, running) machine counts for health endpoint.
    /// Uses try_lock to avoid blocking on contended machine entries.
    pub fn machine_counts(&self) -> (usize, usize) {
        let machines = self.machines.read();
        let total = machines.len();
        let running = machines
            .values()
            .filter(|e| {
                e.try_lock()
                    .map(|entry| entry.manager.is_process_alive())
                    .unwrap_or(true) // assume running if locked (active operation)
            })
            .count();
        (total, running)
    }

    /// Disarm every machine manager's `Drop` so a non-draining `serve` shutdown
    /// (e.g. a binary-upgrade restart) leaves running VMs alive for the next
    /// process to reconnect to, instead of `AgentManager::drop` tearing each one
    /// down via `stop()`. Mirrors the CLI's detach-before-exit (`SigintGuard`
    /// disarm + `manager.detach()`). The drain path does the opposite — it stops
    /// VMs cleanly — so this is invoked ONLY on the survive-and-reconnect path.
    /// Uses a blocking lock per entry: missing one would let its VM be killed.
    pub fn detach_all(&self) {
        let machines = self.machines.read();
        let mut detached = 0usize;
        for entry in machines.values() {
            entry.lock().manager.detach();
            detached += 1;
        }
        if detached > 0 {
            tracing::info!(
                count = detached,
                "detached machine managers on shutdown; VMs left running for reconnect"
            );
        }
    }

    /// Compute total allocated resources across all running machines.
    /// Returns (allocated_cpus, allocated_memory_mb).
    pub fn allocated_resources(&self) -> (u32, u64) {
        let machines = self.machines.read();
        let mut cpus: u32 = 0;
        let mut memory_mb: u64 = 0;
        for entry in machines.values() {
            if let Some(e) = entry.try_lock() {
                if e.manager.is_process_alive() {
                    cpus += e.resources.cpus.unwrap_or(1) as u32;
                    memory_mb += e.resources.memory_mb.unwrap_or(256) as u64;
                }
            }
        }
        (cpus, memory_mb)
    }

    /// Sample real CPU + memory + disk utilization across all running VM processes.
    ///
    /// Returns `(used_cpus, used_memory_mb, used_disk_gb)`:
    /// - CPU is fractional CPUs (e.g., 2.5 = 2.5 CPUs of load), computed as
    ///   `Δcpu_time / Δwall_time` since the previous sample per PID. First sample
    ///   for a new PID returns 0 CPU; subsequent samples return the real rate.
    /// - Memory is the sum of resident set sizes across VM processes.
    /// - Disk is the sum of VM storage + overlay disk file sizes on disk.
    pub fn real_utilization(&self) -> (f64, u64, u64) {
        let now = std::time::Instant::now();
        let mut total_cpus: f64 = 0.0;
        let mut total_rss_bytes: u64 = 0;
        let mut total_disk_bytes: u64 = 0;

        let pid_and_paths: Vec<(Option<i32>, std::path::PathBuf, std::path::PathBuf)> = {
            let machines = self.machines.read();
            machines
                .values()
                .filter_map(|entry| {
                    entry.try_lock().and_then(|e| {
                        if !e.manager.is_process_alive() {
                            return None;
                        }
                        Some((
                            e.manager.child_pid(),
                            e.manager.storage_path().to_path_buf(),
                            e.manager.overlay_path().to_path_buf(),
                        ))
                    })
                })
                .collect()
        };

        let mut samples = self.cpu_samples.lock();
        let mut still_alive: HashSet<i32> = HashSet::with_capacity(pid_and_paths.len());

        for (pid_opt, storage, overlay) in pid_and_paths {
            // Disk: stat the storage + overlay files. Cheap (one stat() each).
            if let Ok(meta) = std::fs::metadata(&storage) {
                total_disk_bytes = total_disk_bytes.saturating_add(meta.len());
            }
            if let Ok(meta) = std::fs::metadata(&overlay) {
                total_disk_bytes = total_disk_bytes.saturating_add(meta.len());
            }

            // CPU + memory: only if we have a PID
            let Some(pid) = pid_opt else { continue };
            still_alive.insert(pid);
            let Some(stats) = crate::process::process_stats(pid) else {
                continue;
            };
            total_rss_bytes = total_rss_bytes.saturating_add(stats.rss_bytes);

            if let Some(prev) = samples.get(&pid).copied() {
                let dt_ns = now.duration_since(prev.at).as_nanos() as u64;
                if dt_ns > 0 {
                    let dcpu_ns = stats.cpu_time_ns.saturating_sub(prev.cpu_time_ns);
                    total_cpus += dcpu_ns as f64 / dt_ns as f64;
                }
            }
            samples.insert(
                pid,
                CpuSample {
                    at: now,
                    cpu_time_ns: stats.cpu_time_ns,
                },
            );
        }

        // Drop samples for PIDs that no longer exist (avoids leaking memory
        // as VMs come and go over the lifetime of the smolvm serve process).
        samples.retain(|pid, _| still_alive.contains(pid));

        (
            total_cpus,
            total_rss_bytes / (1024 * 1024),
            total_disk_bytes / (1024 * 1024 * 1024),
        )
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
    pub fn reserve_machine_name(&self, name: &str, token: &str) -> Result<(), ApiError> {
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

        reserved.insert(name.to_string());

        match self.db.reserve_vm_create(name, token) {
            Ok(true) => {}
            Ok(false) => {
                reserved.remove(name);
                return Err(ApiError::Conflict(format!(
                    "machine '{}' already exists or is being created",
                    name
                )));
            }
            Err(e) => {
                reserved.remove(name);
                return Err(ApiError::database(e));
            }
        }

        tracing::debug!(machine = %name, "reserved machine name");
        Ok(())
    }

    /// Release a machine name reservation.
    ///
    /// Call this if machine creation fails after `reserve_machine_name()`.
    pub fn release_machine_reservation(&self, name: &str, token: &str) {
        let mut reserved = self.reserved_names.write();
        if reserved.remove(name) {
            tracing::debug!(machine = %name, "released machine name reservation");
        }
        if let Err(e) = self.db.release_vm_create_reservation(name, token) {
            tracing::warn!(machine = %name, error = %e, "failed to release DB create reservation");
        }
    }

    /// Complete machine registration after successful creation.
    ///
    /// This converts a reserved name into a fully registered machine.
    /// The reservation is released and the machine entry is added.
    pub fn complete_machine_registration(
        &self,
        name: String,
        token: &str,
        reg: MachineRegistration,
    ) -> Result<(), ApiError> {
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
        // Persist egress policy + backend selection from the request (previously
        // dropped here, so API-created machines silently lost both).
        record.allowed_cidrs = reg.resources.allowed_cidrs.clone();
        record.dns_filter_hosts = reg.resources.allowed_hosts.clone();
        record.network_backend = reg.resources.network_backend;
        record.image = reg.image;
        record.source_smolmachine = reg.source_smolmachine.clone();
        record.entrypoint = reg.entrypoint;
        record.cmd = reg.cmd;
        record.env = reg.env;
        record.workdir = reg.workdir;
        record.secret_refs = reg.secret_refs.clone();

        // Complete the cross-process create reservation and insert the VM row
        // atomically. Only after that succeeds do we publish the in-memory entry.
        match self.db.commit_reserved_vm(&name, token, &record) {
            Ok(true) => {
                {
                    let mut reserved = self.reserved_names.write();
                    if !reserved.remove(&name) {
                        // Name wasn't reserved - this is a programming error
                        tracing::warn!(machine = %name, "completing registration for non-reserved name");
                    }
                }
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
                        secret_refs: reg.secret_refs,
                        source_smolmachine: reg.source_smolmachine,
                    })),
                );
                Ok(())
            }
            Ok(false) => {
                // Name already exists or the DB reservation was lost.
                Err(ApiError::Conflict(format!(
                    "machine '{}' already exists or is no longer reserved",
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
    ///
    /// Prefer the async helpers below (`lookup_vm`/`list_vm_records`/`update_vm`)
    /// from async request handlers: `SmolvmDb`'s methods are synchronous SQLite
    /// I/O, and calling them directly on the tokio reactor lets a stalled write
    /// (under create/delete churn) park the worker pool and wedge the liveness
    /// probes. The helpers run the I/O on the blocking pool. `db()` itself is for
    /// synchronous contexts (CLI, embedded runtime, inside an existing
    /// `spawn_blocking`). See `tests/reactor_wedge.rs`.
    pub fn db(&self) -> &SmolvmDb {
        &self.db
    }

    /// Off-reactor VM lookup. Runs the blocking SQLite read on the blocking pool.
    pub async fn lookup_vm(&self, name: &str) -> Result<Option<VmRecord>, ApiError> {
        let db = self.db.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || db.get_vm(&name))
            .await
            .map_err(|e| ApiError::internal(format!("db lookup_vm task join: {e}")))?
            .map_err(ApiError::database)
    }

    /// Off-reactor full VM listing. Runs the blocking SQLite scan on the blocking
    /// pool (reads use the connection-pool, so this never serializes behind a write).
    pub async fn list_vm_records(&self) -> Result<Vec<(String, VmRecord)>, ApiError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.list_vms())
            .await
            .map_err(|e| ApiError::internal(format!("db list_vm_records task join: {e}")))?
            .map_err(ApiError::database)
    }

    /// Off-reactor read-modify-write of a VM record. Runs the synchronous
    /// transaction on the blocking pool so the write — which holds the single
    /// writer connection and may wait out `busy_timeout` under contention — never
    /// parks a reactor worker thread.
    pub async fn update_vm<F>(&self, name: &str, f: F) -> Result<Option<VmRecord>, ApiError>
    where
        F: FnOnce(&mut VmRecord) + Send + 'static,
    {
        let db = self.db.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || db.update_vm(&name, f))
            .await
            .map_err(|e| ApiError::internal(format!("db update_vm task join: {e}")))?
            .map_err(ApiError::database)
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
            // This runs on the supervisor's heartbeat path, so it must never
            // block. A `MachineEntry` whose lock is currently held is, by
            // definition, actively in use (mid agent I/O) — i.e. alive — so we
            // treat lock contention as "alive" rather than parking the
            // supervisor on it. Blocking here behind a single busy/stuck
            // machine would stall the runtime heartbeat and mark the entire
            // node unschedulable.
            match entry.try_lock() {
                Some(entry) => entry.manager.is_process_alive(),
                None => true,
            }
        } else {
            false
        }
    }
}

/// Run a blocking operation against a machine's agent client.
///
/// Handles the common pattern: clone entry → spawn_blocking → lock → connect → op → map errors.
/// Propagates an optional trace ID to the agent for request correlation.
pub async fn with_machine_client_traced<T, F>(
    entry: &Arc<parking_lot::Mutex<MachineEntry>>,
    trace_id: Option<String>,
    op: F,
) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&mut crate::agent::AgentClient) -> crate::Result<T> + Send + 'static,
{
    let entry_clone = entry.clone();
    tokio::task::spawn_blocking(move || {
        // Acquire a connected client under the per-machine lock, then RELEASE
        // the lock before running the (potentially long, unbounded-blocking)
        // agent operation. `connect()` returns an owned `AgentClient` over its
        // own socket, so `op` needs no lock once connected. Holding the
        // `MachineEntry` lock across blocking agent I/O lets a hung guest agent
        // pin the lock indefinitely, which blocks the supervisor's liveness
        // probe (`is_machine_alive`) and stalls the whole runtime heartbeat —
        // marking the node unschedulable behind a single stuck exec.
        let mut client = {
            let entry = entry_clone.lock();
            let mut client = entry.manager.connect()?;
            if let Some(tid) = trace_id {
                client.set_trace_id(tid);
            }
            client
        };
        op(&mut client)
    })
    .await?
    .map_err(ApiError::internal)
}

// ============================================================================
// Shared Machine Helpers
// ============================================================================

/// Build `LaunchFeatures` for an API-driven machine start.
///
/// Thin wrapper over [`crate::agent::LaunchFeatures::with_packed_layers`]
/// — the single source of truth shared with the CLI and embedded start paths.
/// When the machine was created from a `.smolmachine` artifact
/// (`source_smolmachine` is set), its pre-extracted OCI layers — extracted into
/// the machine's own data dir at create time, keyed by `machine_name` — are
/// mounted via virtiofs so the guest uses them instead of pulling from a
/// registry; otherwise default features are returned. Without it the three API
/// start entrypoints (`start_machine`, `ensure_machine_running`, supervisor
/// restart) would pass `packed_layers_dir = None` and the guest would fall back
/// to a network pull. Performs blocking filesystem work — call from within a
/// `spawn_blocking` context.
pub fn build_launch_features(
    machine_name: Option<&str>,
    source_smolmachine: Option<&str>,
    dns_filter_hosts: Option<Vec<String>>,
) -> crate::Result<crate::agent::LaunchFeatures> {
    let features = crate::agent::LaunchFeatures::default();
    let mut features = match machine_name {
        Some(name) => features.with_packed_layers(
            &crate::agent::machine_layers_cache_dir(name),
            source_smolmachine,
        )?,
        None => features,
    };
    // Carry the egress hostname allow-list into the boot config; `internal_boot`
    // starts the DNS filter for these names and learns their answers into the
    // egress allow-list (parity with the CLI `--allow-host` path).
    features.dns_filter_hosts = dns_filter_hosts;
    Ok(features)
}

/// Ensure a machine is running, starting it if needed.
///
/// This is the shared preflight check used by exec, container, and image handlers.
/// It converts the machine's mount/port/resource config and calls
/// `ensure_running_with_full_config` in a blocking task.
///
/// On the not-already-up path this mounts the machine's macOS layers volume, so
/// callers MUST hold the per-machine lifecycle lock (see `ensure_running_and_persist`,
/// the only caller) for the duration, or the mount can race a concurrent
/// stop/delete detach (review finding #3).
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
        //
        // Build the packed-layers features only when the VM is not already up.
        // This preflight runs on every implicit-start request (exec/run/files/
        // images); when the VM is already running `ensure_running_via_subprocess`
        // returns early (discarding `features`) as long as the mount/port/resource
        // config is unchanged. Acquiring the layers lease on that hot path is
        // wasted work — on macOS it re-mounts the case-sensitive volume via
        // hdiutil — so gate it on the same already-running check.
        //
        // The gated `default()` is safe across the relaunch branch too: if the
        // preflight detects a mount/port/resource change and restarts the VM,
        // `ensure_running_via_subprocess` re-attaches this machine's pre-extracted
        // packed layers itself (see `rewire_packed_layers_if_extracted`), so the
        // restart keeps using them instead of falling back to a registry pull.
        let features = if entry.manager.try_connect_existing().is_some() {
            crate::agent::LaunchFeatures::default()
        } else {
            build_launch_features(
                entry.manager.name(),
                entry.source_smolmachine.as_deref(),
                entry.resources.allowed_hosts.clone(),
            )?
        };
        entry
            .manager
            .ensure_running_via_subprocess(mounts, ports, resources, features)?;
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
    // Hold the per-machine lifecycle lock across the implicit-start preflight.
    // ensure_machine_running mounts the macOS layers volume (via with_packed_layers)
    // when the VM is not already up — exactly like the explicit start_machine — so
    // it must exclude against a concurrent stop/delete detach the same way (review
    // finding #3 covers "start/ensure"). Acquired before ensure_machine_running's
    // spawn_blocking takes the entry mutex, preserving the lifecycle → entry order;
    // released before the caller's actual exec/file/image op, which neither mounts
    // nor detaches. On Linux the guarded mount is a no-op, so this is harmless.
    let lifecycle = state.lifecycle_lock(name);
    let _guard = lifecycle.lock().await;

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
        network_backend: spec.network_backend,
        gpu: spec.gpu.unwrap_or(false),
        // gpu_vram_mib not currently on ResourceSpec — API callers
        // inherit the default. Add to ResourceSpec if the API ever
        // needs to expose it.
        gpu_vram_mib: None,
        // CUDA-over-vsock is exposed via the local CLI/SDK first; add to
        // ResourceSpec when the cloud transport wires it (mirrors gpu_vram_mib).
        cuda: false,
        rosetta: false,
        storage_gib: spec.storage_gb,
        overlay_gib: spec.overlay_gb,
        allowed_cidrs: spec.allowed_cidrs.clone(),
        // Custom DNS is a local-CLI feature for now; the cloud ResourceSpec
        // does not expose it, so API-launched VMs inherit the backend default.
        dns: None,
    }
}

/// Convert VmResources to ResourceSpec.
pub fn vm_resources_to_spec(res: VmResources) -> ResourceSpec {
    ResourceSpec {
        cpus: Some(res.cpus),
        memory_mb: Some(res.memory_mib),
        network: Some(res.network),
        gpu: Some(res.gpu),
        storage_gb: res.storage_gib,
        overlay_gb: res.overlay_gib,
        allowed_cidrs: res.allowed_cidrs,
        // VmResources has no hostname allow-list; callers that need it graft it
        // back from the source record (see the MachineEntry reload path).
        allowed_hosts: None,
        network_backend: res.network_backend,
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
    let egress_bytes = crate::agent::read_egress_telemetry(&name);
    // Live consumed CPU-seconds for the VMM child (host-sampled, resets on
    // restart); the control plane accumulates the durable total. None when there
    // is no live process to sample.
    let stats = entry
        .manager
        .child_pid()
        .and_then(crate::process::process_stats);
    let cpu_seconds = stats.map(|s| s.cpu_time_ns / 1_000_000_000);
    let cpu_millis = stats.map(|s| s.cpu_time_ns / 1_000_000);
    let rss_mb = stats.map(|s| s.rss_bytes / (1024 * 1024));
    // Actual used disk (sparse-image blocks) — a gauge the control integrates for
    // active-disk billing. Independent of whether there's a live VMM process.
    let disk_used_mb = crate::agent::disk_used_mb(&name);

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
        network_backend: entry.resources.network_backend,
        allowed_cidrs: entry.resources.allowed_cidrs.clone(),
        allowed_hosts: entry.resources.allowed_hosts.clone(),
        storage_gb: entry.resources.storage_gb,
        overlay_gb: entry.resources.overlay_gb,
        egress_bytes,
        cpu_seconds,
        cpu_millis,
        rss_mb,
        disk_used_mb,
        created_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create an ApiState with a temporary database for testing.
    fn temp_api_state() -> (TempDir, ApiState) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
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
            gpu: None,
            storage_gb: None,
            overlay_gb: None,
            allowed_cidrs: None,
            allowed_hosts: None,
            network_backend: None,
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
    fn build_launch_features_carries_allowed_hosts() {
        // The serve-API launch path must forward the egress hostname allow-list
        // into the boot config, so `internal_boot` starts the DNS filter for it.
        let hosts = vec!["api.anthropic.com".to_string(), "pypi.org".to_string()];
        let features = build_launch_features(None, None, Some(hosts.clone())).unwrap();
        assert_eq!(features.dns_filter_hosts, Some(hosts));

        // No hostname policy stays None (unrestricted egress, unchanged behavior).
        let features = build_launch_features(None, None, None).unwrap();
        assert_eq!(features.dns_filter_hosts, None);
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

    // remove_machine must clear BOTH the DB row and the in-memory registry entry
    // even though it no longer holds the registry write lock across the DB delete
    // (the reorder that keeps `/health` from wedging under delete churn).
    #[test]
    fn test_remove_machine_clears_db_and_registry() {
        let (_dir, state) = temp_api_state();

        // Put a machine in BOTH the DB and the in-memory registry.
        let record = VmRecord::new("remove-test-m1".into(), 1, 512, vec![], vec![], false);
        state.db.insert_vm("remove-test-m1", &record).unwrap();
        let manager = AgentManager::for_vm("remove-test-m1").unwrap();
        state.insert_machine(
            "remove-test-m1",
            MachineEntry {
                manager,
                mounts: vec![],
                ports: vec![],
                resources: ResourceSpec {
                    cpus: None,
                    memory_mb: None,
                    network: None,
                    gpu: None,
                    storage_gb: None,
                    overlay_gb: None,
                    allowed_cidrs: None,
                    allowed_hosts: None,
                    network_backend: None,
                },
                restart: RestartConfig::default(),
                network: false,
                secret_refs: Default::default(),
                source_smolmachine: None,
            },
        );

        // Remove succeeds and returns the entry.
        assert!(state.remove_machine("remove-test-m1").is_ok());

        // Gone from BOTH stores.
        assert!(
            state.db.get_vm("remove-test-m1").unwrap().is_none(),
            "DB row should be deleted"
        );
        assert!(
            matches!(
                state.get_machine("remove-test-m1"),
                Err(ApiError::NotFound(_))
            ),
            "registry entry should be removed"
        );

        // Second remove → NotFound, not a panic.
        assert!(matches!(
            state.remove_machine("remove-test-m1"),
            Err(ApiError::NotFound(_))
        ));
    }

    // REGRESSION (runtime-wedge): the supervisor's liveness probe must NEVER
    // block on the per-machine `MachineEntry` lock. A machine that is mid
    // agent-I/O (e.g. a stuck exec) holds that lock; if `is_machine_alive`
    // blocked on it, one wedged machine would stall the supervisor heartbeat
    // and mark the whole node unschedulable (the 503/black-hole wedge observed
    // under concurrent boots). With the entry lock held, `is_machine_alive`
    // must return promptly, reporting the in-use machine as alive.
    #[test]
    fn is_machine_alive_does_not_block_when_entry_locked() {
        use std::time::Duration;

        let (_dir, state) = temp_api_state();
        let record = VmRecord::new("busy-m1".into(), 1, 512, vec![], vec![], false);
        state.db.insert_vm("busy-m1", &record).unwrap();
        let manager = AgentManager::for_vm("busy-m1").unwrap();
        state.insert_machine(
            "busy-m1",
            MachineEntry {
                manager,
                mounts: vec![],
                ports: vec![],
                resources: ResourceSpec {
                    cpus: None,
                    memory_mb: None,
                    network: None,
                    gpu: None,
                    storage_gb: None,
                    overlay_gb: None,
                    allowed_cidrs: None,
                    allowed_hosts: None,
                    network_backend: None,
                },
                restart: RestartConfig::default(),
                network: false,
                secret_refs: Default::default(),
                source_smolmachine: None,
            },
        );

        // Hold the entry lock to simulate an in-flight agent op pinning it.
        let entry = state.get_machine("busy-m1").unwrap();
        let held = entry.lock();

        // The probe must finish without waiting on the held lock. If it blocked,
        // the scoped thread would still be running after the grace period.
        std::thread::scope(|s| {
            let h = s.spawn(|| state.is_machine_alive("busy-m1"));
            std::thread::sleep(Duration::from_millis(200));
            assert!(
                h.is_finished(),
                "is_machine_alive blocked on a held MachineEntry lock — would stall the supervisor"
            );
            assert!(
                h.join().unwrap(),
                "a locked (actively in-use) machine must read as alive"
            );
        });
        drop(held);
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

        // Give it a data dir with a marker file — reconciliation must reclaim it,
        // not just the DB record (otherwise the disks leak across restarts).
        let data_dir = crate::agent::vm_data_dir("dead-machine");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("storage.raw"), b"x").unwrap();

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

        // Data dir should be reclaimed too (no disk leak).
        assert!(
            !data_dir.exists(),
            "dead machine data dir should be removed, not leaked"
        );

        // Name should be available for reuse
        let token = SmolvmDb::create_reservation_token();
        assert!(state.reserve_machine_name("dead-machine", &token).is_ok());
    }

    #[test]
    fn dangling_vm_dir_reaping_policy() {
        use std::collections::HashSet;
        // VM-dir-hash shape = exactly 16 lowercase hex chars.
        assert!(is_vm_dir_hash("0213f25389658451"));
        assert!(!is_vm_dir_hash("_shared")); // shared pack store — never a candidate
        assert!(!is_vm_dir_hash("uids"));
        assert!(!is_vm_dir_hash("0213F25389658451")); // uppercase isn't our shape
        assert!(!is_vm_dir_hash("0213f253896584")); // too short
        assert!(!is_vm_dir_hash("0213f25389658451aa")); // too long
        assert!(!is_vm_dir_hash("0213f2538965845z")); // non-hex

        // A hash backing a live record is kept; an unbacked hash is dangling;
        // non-VM entries are never dangling regardless of the valid set.
        let valid: HashSet<String> = ["aaaaaaaaaaaaaaaa".to_string()].into_iter().collect();
        assert!(is_dangling_vm_dir("bbbbbbbbbbbbbbbb", &valid)); // hash, no record → reap
        assert!(!is_dangling_vm_dir("aaaaaaaaaaaaaaaa", &valid)); // hash, has record → keep
        assert!(!is_dangling_vm_dir("_shared", &valid)); // not a hash → keep
    }

    #[test]
    fn test_load_persisted_machines_preserves_created_no_pid() {
        let (_dir, state) = temp_api_state();

        // Insert a record with no PID (created but never started).
        // These must be preserved — they are valid configs waiting for
        // a start call.
        let record = VmRecord::new("ghost".into(), 1, 512, vec![], vec![], false);
        state.db.insert_vm("ghost", &record).unwrap();

        // Load should NOT remove it — no PID means "never started", not "dead".
        let _loaded = state.load_persisted_machines();
        assert!(
            state.db.get_vm("ghost").unwrap().is_some(),
            "created (no-PID) machine must be preserved across server restart"
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
