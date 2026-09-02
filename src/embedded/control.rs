//! DB-backed VM lifecycle helpers for embedded SDK backends.

use crate::agent::{AgentClient, AgentManager, HostMount, LaunchFeatures, VmResources};
use crate::config::{RecordState, VmRecord};
use crate::data::network::PortMapping;
use crate::data::validate_vm_name;
use crate::db::SmolvmDb;
use crate::embedded::handle::VmHandle;
use crate::{Error, Result};
use std::collections::BTreeMap;

/// Runtime configuration supplied by an embedded SDK constructor.
/// `Default` is derived so a new field does not break every construction site —
/// callers can spread `..MachineSpec::default()`. The shim and the examples
/// previously listed every field, which made each addition a breaking change to
/// code that only compiles on Linux (and so failed after review, not during it).
#[derive(Debug, Clone, Default)]
pub struct MachineSpec {
    /// Unique machine name.
    pub name: String,
    /// Host directory mounts to expose in the guest.
    pub mounts: Vec<HostMount>,
    /// Host-to-guest port mappings.
    pub ports: Vec<PortMapping>,
    /// VM resources for this machine.
    pub resources: VmResources,
    /// OCI image the machine boots from, when it is an image machine rather than
    /// a bare VM. Mirrors the CLI's `--image`: without it the guest comes up as a
    /// bare VM and any image the caller asked for is silently not applied.
    pub image: Option<String>,
    /// Workload command overriding the image entrypoint/CMD. Empty preserves
    /// the image defaults, matching the CLI and REST create APIs.
    pub command: Vec<String>,
    /// Hostnames permitted by the TSI egress filter. Kept outside
    /// `VmResources` because hostname rules are persisted separately from the
    /// resolved CIDRs and refreshed by the DNS filter at runtime.
    pub allowed_hosts: Vec<String>,
    /// Whether the machine should persist across stop/start.
    pub persistent: bool,
    /// Whether every start must use cloneable, memfd-backed guest RAM.
    ///
    /// This is persisted in the VM record so an SDK-created fork base remains
    /// forkable after its creating process exits and a later process reconnects.
    pub forkable: bool,
    /// Caller metadata, mirroring the CLI's `--label` and surfaced by
    /// `machine ls --json`. smolvm never interprets these.
    ///
    /// An embedder managing many machines has only the name to go on otherwise,
    /// and a name cannot be read back reliably (the table view truncates it), so
    /// without labels a process that dies cannot recognise its own machines
    /// afterwards. That is the difference between reclaiming a leaked VM and
    /// leaving it running.
    pub labels: BTreeMap<String, String>,
    /// Set by the Kubernetes containerd shim for pod-sandbox VMs. Marks the
    /// record so node-reboot reconciliation can reclaim it (and only it) when
    /// its process is gone. Defaults to false for CLI/SDK machines.
    pub runtime_managed: bool,
    /// S3-compatible volumes the agent mounts inside the guest on every start.
    pub remote_volumes: Vec<crate::remote_volume::RemoteVolume>,
}

impl MachineSpec {
    /// Convert the embedded-machine spec into the canonical DB record.
    pub fn to_record(&self) -> VmRecord {
        let mut record = VmRecord::new(
            self.name.clone(),
            self.resources.cpus,
            self.resources.memory_mib,
            self.mounts
                .iter()
                .map(HostMount::to_storage_tuple)
                .collect(),
            self.ports.iter().map(PortMapping::to_tuple).collect(),
            self.resources.network,
        );
        record.storage_gb = self.resources.storage_gib;
        record.overlay_gb = self.resources.overlay_gib;
        record.allowed_cidrs = self.resources.allowed_cidrs.clone();
        record.dns_filter_hosts = if self.allowed_hosts.is_empty() {
            None
        } else {
            Some(self.allowed_hosts.clone())
        };
        record.network_backend = self.resources.network_backend;
        record.gpu = Some(self.resources.gpu);
        record.gpu_vram_mib = self.resources.gpu_vram_mib;
        record.cuda = self.resources.cuda;
        record.image = self.image.clone();
        record.labels = self.labels.clone();
        record.ephemeral = !self.persistent;
        record.forkable = self.forkable;
        record.runtime_managed = self.runtime_managed;
        record.remote_volumes = self.remote_volumes.clone();
        record
    }
}

/// Create a DB record for a new SDK machine.
pub fn create_vm(db: &SmolvmDb, spec: &MachineSpec) -> Result<()> {
    create_vm_with_workload(db, spec, Vec::new(), None)
}

/// Create a DB record with the image workload configuration supplied by an
/// SDK, without expanding the stable `MachineSpec` struct.
pub(crate) fn create_vm_with_workload(
    db: &SmolvmDb,
    spec: &MachineSpec,
    env: Vec<(String, String)>,
    workdir: Option<String>,
) -> Result<()> {
    validate_vm_name(&spec.name, "name")
        .map_err(|reason| Error::config("validate machine name", reason))?;
    let mut record = spec.to_record();
    if let Some(cidrs) = &spec.resources.allowed_cidrs {
        record.allowed_cidrs = Some(
            cidrs
                .iter()
                .map(|cidr| crate::smolfile::parse_cidr(cidr))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|reason| Error::config("validate allowed CIDR", reason))?,
        );
    }
    record.cmd = spec.command.clone();
    record.env = env;
    record.workdir = workdir;
    if db.insert_vm_if_not_exists(&spec.name, &record)? {
        Ok(())
    } else {
        Err(Error::agent_conflict(
            "create machine",
            format!("machine '{}' already exists", spec.name),
        ))
    }
}

/// Load a persisted VM record.
pub fn get_record(db: &SmolvmDb, name: &str) -> Result<VmRecord> {
    db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))
}

/// Start or reconnect to a persisted VM and report whether this call actually
/// booted/restarted it. Callers use the status to launch image workloads exactly
/// once: a reused VM already has its workload, while a restarted VM does not.
pub(crate) fn start_vm(db: &SmolvmDb, name: &str) -> Result<StartedVm> {
    let record = get_record(db, name)?;
    let started = start_vm_from_record(&record)?;
    mark_running(db, name, started.handle.child_pid())?;
    Ok(started)
}

fn start_vm_from_record(record: &VmRecord) -> Result<StartedVm> {
    launch_from_record(record, LaunchFeatures::default())
}

fn merge_record_launch_features(record: &VmRecord, mut features: LaunchFeatures) -> LaunchFeatures {
    if features.dns_filter_hosts.is_none() {
        features.dns_filter_hosts = record.dns_filter_hosts.clone();
    }
    if !record.init_completed {
        features
            .allow_image_pull_egress(record.image.as_deref(), record.source_smolmachine.is_some());
    }
    features
}

fn record_launch_features(record: &VmRecord, features: LaunchFeatures) -> Result<LaunchFeatures> {
    let mut features = merge_record_launch_features(record, features).with_packed_layers(
        &crate::agent::machine_layers_cache_dir(&record.name),
        record.source_smolmachine.as_deref(),
    )?;
    if features.packed_layers_dir.is_none() {
        features.packed_layers_dir = record
            .image
            .as_deref()
            .and_then(crate::data::image_source::packed_layers_dir_for_ref);
    }
    Ok(features)
}

/// Result of an embedded launch attempt.
pub(crate) struct StartedVm {
    pub(crate) handle: VmHandle,
    pub(crate) freshly_started: bool,
}

/// Boot `record` with the given launch features and return a handle. Shared by
/// the plain, forkable-golden, and fork-clone start paths so they can't drift.
fn launch_from_record(record: &VmRecord, features: LaunchFeatures) -> Result<StartedVm> {
    // Reconstruct host-backed image devices on every launch.  These devices are
    // part of the libkrun snapshot topology: omitting one while restoring a
    // local-image clone makes krun reject the otherwise-valid checkpoint with
    // EINVAL.  The CLI start path performs the same two resolutions; embedded
    // SDK users must not get a subtly different VM configuration.
    let mut features = record_launch_features(record, features)?;
    if record.forkable_on_start() {
        features.forkable = true;
    }
    if features.cuda_fork_pool_size.is_none() {
        features.cuda_fork_pool_size = record.cuda_fork_pool_size;
    }
    if features.cuda_vram_limit_mib.is_none() {
        features.cuda_vram_limit_mib = record.cuda_vram_limit_mib;
    }
    // A fork clone shares its golden's uid; resolve it explicitly so a cold
    // (re)start — where no snapshot path exists to infer it — can still open
    // the golden's copy-on-write disk backing behind its 0700 data dir.
    if features.uid_share_dir.is_none() {
        if let Some(ref g) = record.golden {
            features.uid_share_dir = Some(crate::agent::vm_data_dir(g));
        }
    }
    let manager =
        AgentManager::for_vm_with_sizes(&record.name, record.storage_gb, record.overlay_gb)
            .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    let restoring_checkpoint =
        crate::portable_checkpoint::pending_dir(&crate::agent::vm_data_dir(&record.name)).is_some();
    let freshly_started = manager
        .ensure_running_with_full_config(
            record.host_mounts(),
            record.port_mappings(),
            record.vm_resources(),
            features,
        )
        .map_err(|e| Error::agent("start machine", e.to_string()))?;

    if restoring_checkpoint {
        if let Err(error) = crate::portable_checkpoint::finalize_live_restore(&record.name, record)
            .and_then(|()| {
                crate::portable_checkpoint::consume(&crate::agent::vm_data_dir(&record.name))
            })
        {
            let _ = manager.stop();
            return Err(error);
        }
    }

    Ok(StartedVm {
        handle: VmHandle::new(manager, None),
        freshly_started: freshly_started && !restoring_checkpoint,
    })
}

/// Start a persisted VM as a FORKABLE fork base: its guest RAM is backed by a
/// memfd (copy-on-write cloneable) and a control socket is exposed so the machine
/// can later be forked with [`fork_vm`]. Same mechanics as the CLI's
/// `machine start --forkable`, surfaced for the embedded SDK.
/// Start or reconnect to a forkable VM and retain the actual launch status.
pub(crate) fn start_forkable_vm(db: &SmolvmDb, name: &str) -> Result<StartedVm> {
    db.update_vm(name, |record| record.forkable = true)?
        .ok_or_else(|| Error::vm_not_found(name))?;
    let record = get_record(db, name)?;
    let features = LaunchFeatures {
        forkable: true,
        ..LaunchFeatures::default()
    };
    let started = launch_from_record(&record, features)?;
    mark_running(db, name, started.handle.child_pid())?;
    Ok(started)
}

/// Start a persisted VM attached to a Kubernetes pod network namespace: the
/// launcher bridges the guest virtio-net NIC L2 to a tap inside `netns` (against
/// the CNI-provisioned interface) so the pod carries its CNI-assigned IP and is
/// reachable at L2. Used by the containerd shim for pod sandboxes. `netns` is a
/// bind-mounted netns path (e.g. `/var/run/netns/cni-…` or `/proc/<pid>/ns/net`).
pub fn start_vm_with_netns(
    db: &SmolvmDb,
    name: &str,
    netns: std::path::PathBuf,
) -> Result<VmHandle> {
    let record = get_record(db, name)?;
    let features = LaunchFeatures {
        pod_netns: Some(netns),
        ..LaunchFeatures::default()
    };
    let started = launch_from_record(&record, features)?;
    mark_running(db, name, started.handle.child_pid())?;
    Ok(started.handle)
}

/// Fork a running, forkable `golden` into a new `clone` via copy-on-write guest
/// RAM + disks (same host). Freezes the golden (it stays paused as the shared
/// base — clones map its RAM `MAP_PRIVATE`, so it must not run again while clones
/// exist), boots the clone from the golden's snapshot, and returns the clone's
/// handle. `pinned_ports` are `(host, guest)` inbound forwards for the clone;
/// empty means the golden's forwards are remapped to freshly-allocated host
/// ports. Shares `agent::fork` with the CLI/serve fork paths.
pub fn fork_vm(
    db: &SmolvmDb,
    golden: &str,
    clone: &str,
    pinned_ports: &[(u16, u16)],
) -> Result<VmHandle> {
    fork_vm_with_options(db, golden, clone, pinned_ports, false, false, None)
}

/// Fork a machine with launch options needed by non-embedded front-ends.
pub(crate) fn fork_vm_with_options(
    db: &SmolvmDb,
    golden: &str,
    clone: &str,
    pinned_ports: &[(u16, u16)],
    clone_forkable: bool,
    share_weights: bool,
    watch_parent: Option<bool>,
) -> Result<VmHandle> {
    let _source_lock = crate::agent::fork::lock_fork_source(golden)?;
    // Freeze + snapshot the source, then register the clone and its CoW disks.
    let prep = crate::agent::fork::prepare_fork(
        db,
        golden,
        clone,
        pinned_ports,
        clone_forkable,
        &[],
        &std::collections::BTreeMap::new(),
    )?;

    boot_prepared_fork(db, clone, prep, share_weights, watch_parent, None)
}

fn boot_prepared_fork(
    db: &SmolvmDb,
    clone: &str,
    prep: crate::agent::fork::PreparedFork,
    share_weights: bool,
    watch_parent: Option<bool>,
    retry_gate: Option<&std::sync::Mutex<()>>,
) -> Result<VmHandle> {
    // Boot the clone from the golden's in-memory snapshot instead of cold-booting.
    let features = LaunchFeatures {
        forkable: prep.clone_record.forkable,
        snapshot_dir: Some(prep.snapshot_dir.clone()),
        cuda_share_weights: share_weights,
        cuda_preload_modules: prep.clone_record.cuda_preload_modules,
        watch_parent,
        ..LaunchFeatures::default()
    };
    // A restore can reach the agent socket and still fail its first command on
    // affected KVM hosts. Retry the complete boot transaction, not just VMM
    // launch: a clone is not usable until identity reset and forkpoint release
    // have both been acknowledged. The first failed attempt is stopped but its
    // prepared CoW disks and DB record are retained for the clean restore retry.
    let attempt = || {
        let started = launch_from_record(&prep.clone_record, features.clone())?;
        (|| {
            let mut handle = started.handle;
            // Fresh on-disk identity (hostname, machine-id, SSH host keys, RNG).
            // FAIL-CLOSED: if the reset can't be confirmed, stop the booted clone
            // and roll it back rather than leave it live with the golden's
            // per-machine secrets.
            if let Err(error) = crate::agent::fork::rejuvenate_clone(clone, &prep.clone_record) {
                let _ = handle.stop();
                return Err(error);
            }
            // Embedded SDK forks are immediately consumable workers (there is
            // no held-slot option on this path). A live workload may be parked
            // in `smolvm-fork-ready` in the retained snapshot; release that
            // clone-local barrier only after identity reset succeeds, matching
            // the CLI and serve fork paths. Publishing a release marker is
            // harmless for an arbitrary checkpoint with no waiting helper.
            if let Err(error) = crate::agent::fork::release_forkpoint(clone) {
                let _ = handle.stop();
                return Err(error);
            }
            if let Err(error) = mark_running(db, clone, handle.child_pid()) {
                let _ = handle.stop();
                return Err(error);
            }
            Ok(handle)
        })()
    };
    match retry_once_serialized(retry_gate, attempt) {
        Ok(handle) => Ok(handle),
        Err((first, retry)) => {
            // prepare_fork already registered the clone; fail closed only after
            // both complete boot transactions fail.
            let _ = db.remove_vm(clone);
            let _ = std::fs::remove_dir_all(crate::agent::vm_data_dir(clone));
            Err(Error::agent(
                "fork clone boot",
                format!("clone '{clone}' first attempt failed: {first}; retry failed: {retry}"),
            ))
        }
    }
}

fn retry_once_serialized<T, E>(
    gate: Option<&std::sync::Mutex<()>>,
    mut operation: impl FnMut() -> std::result::Result<T, E>,
) -> std::result::Result<T, (E, E)> {
    let first = match operation() {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let _guard = gate.map(|gate| {
        gate.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    operation().map_err(|retry| (first, retry))
}

/// Fork a group of embedded machines from one retained snapshot and boot them
/// with bounded parallelism. The operation is transactional: a preparation,
/// boot, identity-rejuvenation, or bookkeeping failure stops and removes every
/// clone created by this call. Once captured, the golden remains a paused,
/// reusable fork base even when clone boot fails; this does not require newer
/// libkrun rollback commands and lets a later batch retry from the checkpoint.
pub fn fork_vm_batch(
    db: &SmolvmDb,
    golden: &str,
    clones: &[(String, Vec<(u16, u16)>)],
    parallel: usize,
) -> Result<Vec<(String, VmHandle)>> {
    let _source_lock = crate::agent::fork::lock_fork_source(golden)?;
    if clones.is_empty() {
        return Err(Error::config(
            "fork batch",
            "at least one clone is required",
        ));
    }
    let empty_secrets = std::collections::BTreeMap::new();
    let specs: Vec<_> = clones
        .iter()
        .map(|(name, ports)| crate::agent::fork::ForkSpec {
            clone: name,
            pinned_ports: ports,
            clone_forkable: false,
            fork_env: &[],
            fork_secrets: &empty_secrets,
            hold: false,
        })
        .collect();
    let prepared = crate::agent::fork::prepare_forks(db, golden, &specs)?;
    let width = parallel.max(1).min(prepared.len());
    let queue = std::sync::Mutex::new(std::collections::VecDeque::from(
        prepared.into_iter().enumerate().collect::<Vec<_>>(),
    ));
    let stop = std::sync::atomic::AtomicBool::new(false);
    let retry_gate = std::sync::Mutex::new(());

    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..width)
            .map(|_| {
                let db = db.clone();
                let queue = &queue;
                let stop = &stop;
                let retry_gate = &retry_gate;
                scope.spawn(move || {
                    let mut results = Vec::new();
                    loop {
                        if stop.load(std::sync::atomic::Ordering::Acquire) {
                            break;
                        }
                        let job = queue
                            .lock()
                            .expect("embedded fork batch queue poisoned")
                            .pop_front();
                        let Some((index, prep)) = job else {
                            break;
                        };
                        let clone = prep.clone_record.name.clone();
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            boot_prepared_fork(&db, &clone, prep, false, None, Some(retry_gate))
                        }))
                        .unwrap_or_else(|_| {
                            Err(Error::agent(
                                "fork batch",
                                format!("clone '{clone}' boot worker panicked"),
                            ))
                        });
                        if result.is_err() {
                            stop.store(true, std::sync::atomic::Ordering::Release);
                        }
                        results.push((index, clone, result));
                    }
                    results
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| match worker.join() {
                Ok(results) => results,
                Err(_) => vec![(
                    usize::MAX,
                    "unknown".to_string(),
                    Err(Error::agent(
                        "fork batch",
                        "clone boot worker terminated unexpectedly",
                    )),
                )],
            })
            .collect::<Vec<_>>()
    });

    let first_error = results
        .iter()
        .find_map(|(_, name, result)| {
            result
                .as_ref()
                .err()
                .map(|error| Error::agent("fork batch", format!("clone '{name}' failed: {error}")))
        })
        .or_else(|| {
            (results.len() != clones.len()).then(|| {
                Error::agent(
                    "fork batch",
                    format!(
                        "only {} of {} prepared clones reached a terminal boot result",
                        results.len(),
                        clones.len()
                    ),
                )
            })
        });

    if let Some(error) = first_error {
        for (_, _, result) in results {
            if let Ok(mut handle) = result {
                let _ = handle.stop();
            }
        }
        for (name, _) in clones {
            let _ = db.remove_vm(name);
            let _ = std::fs::remove_dir_all(crate::agent::vm_data_dir(name));
        }
        return Err(error);
    }

    let mut ordered = results
        .into_iter()
        .map(|(index, name, result)| result.map(|handle| (index, name, handle)))
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by_key(|(index, _, _)| *index);
    Ok(ordered
        .into_iter()
        .map(|(_, name, handle)| (name, handle))
        .collect())
}

/// Connect to an already-running VM and return a cached handle.
pub fn connect_vm(db: &SmolvmDb, name: &str) -> Result<VmHandle> {
    let record = get_record(db, name)?;
    let manager = AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    if manager.try_connect_existing().is_none() {
        return Err(Error::agent_not_found(
            "connect machine",
            format!("machine '{}' is not running", name),
        ));
    }

    let client = AgentClient::connect_with_retry(manager.vsock_socket())?;
    Ok(VmHandle::new(manager, Some(client)))
}

/// Stop a persisted VM and update its DB state.
pub fn stop_vm(db: &SmolvmDb, name: &str) -> Result<()> {
    let record = get_record(db, name)?;
    let manager = AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;
    manager.try_connect_existing();
    manager.stop()?;
    // Detach the per-machine layers volume if a (possibly cross-tool) bundle start
    // left it mounted. Unconditional on purpose: the embedded record may carry no
    // source_smolmachine even when a CLI/API `machine create <bundle>` extracted and
    // mounted this name's volume in the shared DB, so we cannot gate on it.
    // force_detach is infallible and no-ops when unmounted; macOS hdiutil detach, a
    // compile-time no-op on Linux.
    smolvm_pack::extract::force_detach_layers_volume(&crate::agent::machine_layers_cache_dir(name));
    mark_stopped(db, name)
}

/// Remove a VM record and its storage directory.
pub fn delete_vm(db: &SmolvmDb, name: &str) -> Result<()> {
    let _source_lock = crate::agent::fork::lock_fork_source(name)?;
    delete_vm_locked(db, name)
}

/// Delete with the caller already holding this machine's fork-source lock.
pub(crate) fn delete_vm_locked(db: &SmolvmDb, name: &str) -> Result<()> {
    let dependents = db.dependent_clones(name)?;
    if !dependents.is_empty() {
        return Err(Error::agent(
            "delete machine",
            format!(
                "machine '{name}' has dependent fork(s) ({}); delete descendants first",
                dependents.join(", ")
            ),
        ));
    }
    let removed = db.remove_vm(name)?;
    if removed.is_none() {
        return Err(Error::vm_not_found(name));
    }

    let data_dir = crate::agent::vm_data_dir(name);
    // Detach the per-machine layers volume before removing the data dir, else on
    // macOS the live mountpoint under it makes remove_dir_all fail with "Resource
    // busy", stranding both the mount and the data dir. Unconditional on purpose:
    // the embedded record may carry no source_smolmachine even when a CLI/API create
    // mounted this name's volume. hdiutil detach; a no-op on Linux and when nothing
    // is mounted.
    smolvm_pack::extract::force_detach_layers_volume(&crate::agent::machine_layers_cache_dir(name));
    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir).map_err(|e| {
            Error::storage(
                "delete machine data",
                format!("{}: {}", data_dir.display(), e),
            )
        })?;
    }

    Ok(())
}

/// Reclaim shim-managed sandbox VMs whose process is gone. After a node reboot
/// every VM dies but its persistent record and disk images survive, and a shim
/// that crashed before containerd reaped it leaves the same residue. Removes only
/// `runtime_managed` records that were Running but whose process is no longer
/// alive, and only via [`delete_vm`] (DB record + disk images, never a signal) —
/// so a reused pid is never harmed and a user's CLI/SDK machine is never touched.
/// The liveness check is start-time verified, so a pid reused by an unrelated
/// process reads as not-alive. Best-effort; returns the count reclaimed.
pub fn reconcile_runtime_machines(db: &SmolvmDb) -> Result<usize> {
    let mut reclaimed = 0;
    for (name, record) in db.list_vms()? {
        if record.runtime_managed
            && record.state == RecordState::Running
            && !record.is_process_alive()
        {
            match delete_vm(db, &name) {
                Ok(()) => {
                    reclaimed += 1;
                    tracing::info!(machine = %name, "reconcile: reclaimed stale sandbox VM (record + disks)");
                }
                Err(e) => {
                    tracing::warn!(machine = %name, error = %e, "reconcile: failed to reclaim stale sandbox VM")
                }
            }
        }
    }
    Ok(reclaimed)
}

/// Mark a machine record as running.
pub fn mark_running(db: &SmolvmDb, name: &str, pid: Option<i32>) -> Result<()> {
    let pid_start_time = pid.and_then(crate::process::process_start_time);
    db.update_vm(name, |record| {
        record.state = RecordState::Running;
        record.pid = pid;
        record.pid_start_time = pid_start_time;
    })?
    .ok_or_else(|| Error::vm_not_found(name))?;
    Ok(())
}

/// Mark a machine record as stopped.
pub fn mark_stopped(db: &SmolvmDb, name: &str) -> Result<()> {
    db.update_vm(name, |record| {
        record.state = RecordState::Stopped;
        record.pid = None;
        record.pid_start_time = None;
    })?
    .ok_or_else(|| Error::vm_not_found(name))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_clone_transaction_retries_once() {
        let attempts = std::cell::Cell::new(0);
        let gate = std::sync::Mutex::new(());
        let result = retry_once_serialized(Some(&gate), || {
            let attempt = attempts.get() + 1;
            attempts.set(attempt);
            if attempt == 1 {
                Err("transient")
            } else {
                Ok("ready")
            }
        });
        assert_eq!(result, Ok("ready"));
        assert_eq!(attempts.get(), 2);
    }

    fn test_db() -> SmolvmDb {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "smolvm-embedded-control-{}-{}.db",
            std::process::id(),
            unique
        ));
        SmolvmDb::open_at(&path).unwrap()
    }

    fn test_spec(name: &str, persistent: bool) -> MachineSpec {
        MachineSpec {
            name: name.to_string(),
            mounts: Vec::new(),
            ports: Vec::new(),
            resources: VmResources::default(),
            image: None,
            persistent,
            // Spread the rest so a new spec field does not break the fixtures.
            ..MachineSpec::default()
        }
    }

    fn insert(
        db: &SmolvmDb,
        name: &str,
        runtime_managed: bool,
        state: RecordState,
        pid: Option<i32>,
    ) {
        let mut r = VmRecord::new(name.to_string(), 1, 512, vec![], vec![], false);
        r.runtime_managed = runtime_managed;
        r.state = state;
        r.pid = pid;
        db.insert_vm_if_not_exists(name, &r).unwrap();
    }

    #[test]
    fn reconcile_reclaims_only_dead_runtime_managed() {
        let db = test_db();
        // No such process: Linux pids never reach 2^31, so this reads as not-alive.
        let dead = Some(0x7fff_fff0);

        // Shim sandbox that was running but whose process is gone (reboot/crash).
        insert(&db, "sandbox-stale", true, RecordState::Running, dead);
        // A user's CLI/SDK machine, also running-but-dead — must be left alone.
        insert(&db, "cli-machine", false, RecordState::Running, dead);
        // A shim sandbox that never started (no process expected) — keep it.
        insert(&db, "sandbox-created", true, RecordState::Created, None);

        let reclaimed = reconcile_runtime_machines(&db).unwrap();

        assert_eq!(reclaimed, 1);
        assert!(
            db.get_vm("sandbox-stale").unwrap().is_none(),
            "dead sandbox reclaimed"
        );
        assert!(
            db.get_vm("cli-machine").unwrap().is_some(),
            "CLI machine untouched"
        );
        assert!(
            db.get_vm("sandbox-created").unwrap().is_some(),
            "created sandbox kept"
        );
    }

    #[test]
    fn record_ephemeral_follows_persistent_flag() {
        assert!(test_spec("ephemeral", false).to_record().ephemeral);
        assert!(!test_spec("persistent", true).to_record().ephemeral);
    }

    #[test]
    fn record_carries_durable_forkable_start() {
        let mut spec = test_spec("fork-base", true);
        spec.forkable = true;
        let record = spec.to_record();
        assert!(record.forkable);
        assert!(record.forkable_on_start());
    }

    #[test]
    fn record_carries_gpu_resources() {
        // Vulkan and CUDA must survive MachineSpec -> VmRecord (the `_boot-vm`
        // config), otherwise SDK and Kubernetes requests are silently dropped.
        let mut spec = test_spec("gpu", false);
        spec.resources.gpu = true;
        spec.resources.gpu_vram_mib = Some(512);
        spec.resources.cuda = true;
        spec.resources.allowed_cidrs = Some(vec!["10.0.0.0/8".into()]);
        spec.allowed_hosts = vec!["api.example.com".into()];
        let record = spec.to_record();
        assert_eq!(record.gpu, Some(true));
        assert_eq!(record.gpu_vram_mib, Some(512));
        assert!(record.vm_resources().gpu);
        assert!(record.cuda);
        assert!(record.vm_resources().cuda);
        assert_eq!(record.allowed_cidrs, Some(vec!["10.0.0.0/8".into()]));
        assert_eq!(
            record.dns_filter_hosts,
            Some(vec!["api.example.com".into()])
        );

        // Default (no GPU) records leave gpu off.
        let plain = test_spec("plain", false).to_record();
        assert_eq!(plain.gpu, Some(false));
        assert!(!plain.vm_resources().gpu);
        assert!(!plain.cuda);
        assert!(!plain.vm_resources().cuda);
    }

    #[test]
    fn record_carries_image_workload_configuration() {
        let mut spec = test_spec("workload", true);
        spec.image = Some("example/service:latest".into());
        spec.command = vec!["python".into(), "-m".into(), "service".into()];
        let db = test_db();
        create_vm_with_workload(
            &db,
            &spec,
            vec![("SESSION".into(), "golden".into())],
            Some("/workspace".into()),
        )
        .unwrap();
        let record = get_record(&db, "workload").unwrap();
        assert_eq!(record.image.as_deref(), Some("example/service:latest"));
        assert_eq!(record.cmd, vec!["python", "-m", "service"]);
        assert_eq!(record.env, vec![("SESSION".into(), "golden".into())]);
        assert_eq!(record.workdir.as_deref(), Some("/workspace"));
    }

    #[test]
    fn embedded_launch_restores_persisted_hostname_egress_policy() {
        let mut spec = test_spec("scoped", false);
        spec.image = Some("ghcr.io/acme/service:latest".into());
        spec.allowed_hosts = vec!["api.example.com".into()];
        let mut record = spec.to_record();

        let features = merge_record_launch_features(&record, LaunchFeatures::default());
        assert_eq!(
            features.dns_filter_hosts,
            Some(vec!["api.example.com".into(), "ghcr.io".into()])
        );

        record.init_completed = true;
        let features = merge_record_launch_features(&record, LaunchFeatures::default());
        assert_eq!(features.dns_filter_hosts, spec.allowed_hosts.clone().into());

        let explicit = LaunchFeatures {
            dns_filter_hosts: Some(vec!["override.example.com".into()]),
            ..LaunchFeatures::default()
        };
        let features = merge_record_launch_features(&record, explicit);
        assert_eq!(
            features.dns_filter_hosts,
            Some(vec!["override.example.com".into()])
        );
    }

    #[test]
    fn embedded_launch_restores_local_image_device_topology() {
        let mut record = test_spec("local-image", true).to_record();
        record.image = Some("local-dir:/srv/prepared-rootfs".into());

        let features = record_launch_features(&record, LaunchFeatures::default()).unwrap();

        assert_eq!(
            features.packed_layers_dir,
            Some(std::path::PathBuf::from("/srv/prepared-rootfs"))
        );
    }

    #[test]
    fn create_vm_rejects_duplicates() {
        let db = test_db();
        let spec = test_spec("duplicate", false);
        create_vm(&db, &spec).unwrap();

        let err = create_vm(&db, &spec).unwrap_err();
        assert!(matches!(
            err,
            Error::Agent {
                kind: crate::error::AgentErrorKind::Conflict,
                ..
            }
        ));
    }

    #[test]
    fn create_vm_normalizes_and_rejects_invalid_egress_cidrs() {
        let db = test_db();
        let mut spec = test_spec("normalized-cidr", false);
        spec.resources.allowed_cidrs = Some(vec!["192.0.2.7".into(), "10.1.2.3/8".into()]);
        create_vm(&db, &spec).unwrap();
        assert_eq!(
            get_record(&db, "normalized-cidr").unwrap().allowed_cidrs,
            Some(vec!["192.0.2.7/32".into(), "10.1.2.3/8".into()])
        );

        let mut invalid = test_spec("invalid-cidr", false);
        invalid.resources.allowed_cidrs = Some(vec!["not-a-cidr".into()]);
        assert!(create_vm(&db, &invalid)
            .unwrap_err()
            .to_string()
            .contains("invalid CIDR"));
        assert!(db.get_vm("invalid-cidr").unwrap().is_none());
    }

    #[test]
    fn embedded_batch_fork_rejects_empty_and_duplicate_groups_before_boot() {
        let db = test_db();
        assert!(fork_vm_batch(&db, "missing", &[], 4)
            .err()
            .expect("empty batch must fail")
            .to_string()
            .contains("at least one clone"));

        let clones = vec![
            ("duplicate".to_string(), Vec::new()),
            ("duplicate".to_string(), Vec::new()),
        ];
        assert!(fork_vm_batch(&db, "missing", &clones, 4)
            .err()
            .expect("duplicate batch must fail")
            .to_string()
            .contains("duplicate clone name"));
        assert!(db.get_vm("duplicate").unwrap().is_none());
    }
}
