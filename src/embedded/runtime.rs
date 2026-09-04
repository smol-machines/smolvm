//! Process-local runtime registry for embedded machines.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::Duration;

use crate::agent::{ExecEvent, RunConfig};
use crate::config::RecordState;
use crate::db::SmolvmDb;
use crate::embedded::control::{self, MachineSpec};
use crate::embedded::handle::VmHandle;
use crate::{Error, Result};
use smolvm_protocol::ImageInfo;

type SharedHandle = Arc<Mutex<VmHandle>>;

/// Stateful runtime shared by all embedded machine objects in this process.
pub struct EmbeddedRuntime {
    db: SmolvmDb,
    registry: RwLock<HashMap<String, SharedHandle>>,
    name_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
}

impl EmbeddedRuntime {
    /// Create a runtime backed by the default smolvm database.
    pub fn new() -> Result<Self> {
        Ok(Self::with_db(SmolvmDb::open()?))
    }

    /// Create a runtime backed by an explicit database handle.
    pub fn with_db(db: SmolvmDb) -> Self {
        Self {
            db,
            registry: RwLock::new(HashMap::new()),
            name_locks: RwLock::new(HashMap::new()),
        }
    }

    /// Create a persisted machine record.
    pub fn create_machine(&self, spec: MachineSpec) -> Result<()> {
        self.with_name_lock(&spec.name, || control::create_vm(&self.db, &spec))
    }

    /// Create a persisted image machine with its launch-time environment and
    /// working directory.
    pub fn create_machine_with_workload(
        &self,
        spec: MachineSpec,
        env: Vec<(String, String)>,
        workdir: Option<String>,
    ) -> Result<()> {
        self.with_name_lock(&spec.name, || {
            control::create_vm_with_workload(&self.db, &spec, env, workdir)
        })
    }

    /// Capture a running checkpointable machine into a portable artifact.
    ///
    /// The source resumes as soon as its consistent RAM/disk boundary is
    /// staged; compression continues without holding the source pause.
    pub fn checkpoint_machine(
        &self,
        name: &str,
        output: &std::path::Path,
        options: &crate::portable_checkpoint::CaptureOptions,
    ) -> Result<crate::portable_checkpoint::CaptureResult> {
        self.with_name_lock(name, || {
            crate::portable_checkpoint::capture_to_path(name, output, options)
        })
    }

    /// Create a stopped machine from a portable live checkpoint artifact.
    ///
    /// Its first start resumes the captured execution state. The restored
    /// machine is also a fork/checkpoint source, which makes it suitable as a
    /// durable rollback root.
    pub fn restore_checkpoint_machine(&self, name: &str, artifact: &std::path::Path) -> Result<()> {
        self.with_name_lock(name, || {
            crate::portable_checkpoint::restore_from_path(&self.db, name, artifact)
        })
    }

    /// Restore and start a checkpoint for a detached CLI operation.
    ///
    /// The VMM outlives the caller, unlike the process-owned SDK handle.
    pub fn restore_checkpoint_machine_detached(
        &self,
        name: &str,
        artifact: &std::path::Path,
    ) -> Result<()> {
        self.with_name_lock(name, || {
            crate::portable_checkpoint::restore_from_path(&self.db, name, artifact)?;
            let start = (|| -> Result<VmHandle> {
                let started = control::start_vm(&self.db, name)?;
                let mut handle = started.handle;
                if started.freshly_started {
                    self.launch_image_workload(name, &mut handle)?;
                }
                Ok(handle)
            })();
            match start {
                Ok(handle) => {
                    handle.detach();
                    Ok(())
                }
                Err(error) => {
                    let _ = control::delete_vm(&self.db, name);
                    Err(error)
                }
            }
        })
    }

    /// Reclaim shim-managed sandbox VMs whose process is gone (node reboot or a
    /// shim crash left the record + disks behind). See
    /// [`control::reconcile_runtime_machines`]. Returns the count reclaimed.
    pub fn reconcile_runtime_machines(&self) -> Result<usize> {
        control::reconcile_runtime_machines(&self.db)
    }

    /// Start or reconnect to a persisted machine and cache its handle.
    pub fn start_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.cached_handle(name)? {
                let alive = lock_handle(&handle)?.is_process_alive();
                if alive {
                    return Ok(());
                }
                self.remove_cached_handle(name)?;
            }

            let started = control::start_vm(&self.db, name)?;
            let mut handle = started.handle;
            if started.freshly_started {
                if let Err(error) = self.launch_image_workload(name, &mut handle) {
                    let _ = handle.stop();
                    let _ = control::mark_stopped(&self.db, name);
                    return Err(error);
                }
            }
            self.insert_handle(name, handle)?;
            Ok(())
        })
    }

    /// Attach to an existing machine, starting it only when it is not already
    /// available. A frozen fork base is intentionally not agent-reachable: its
    /// vCPUs are paused while its retained checkpoint backs future clones.
    /// Treating that state as a stopped VM launches a second VMM over the same
    /// disks and replaces its control socket, destroying the fork source.
    pub fn connect_or_start_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.cached_handle(name)? {
                if lock_handle(&handle)?.is_process_alive() {
                    return Ok(());
                }
                self.remove_cached_handle(name)?;
            }

            let record = control::get_record(&self.db, name)?;
            // The DB remains `Running` while a retained live-RAM checkpoint is
            // paused; the shared state probe resolves its control-socket state
            // to `Frozen`. Looking only at the stored enum misses the normal
            // retained-snapshot case and starts a second VMM over the golden.
            if crate::agent::state_probe::resolve_state(name, &record)
                == crate::config::RecordState::Frozen
            {
                return Ok(());
            }

            if let Ok(handle) = control::connect_vm(&self.db, name) {
                self.insert_handle(name, handle)?;
                return Ok(());
            }

            let started = control::start_vm(&self.db, name)?;
            let mut handle = started.handle;
            if started.freshly_started {
                if let Err(error) = self.launch_image_workload(name, &mut handle) {
                    let _ = handle.stop();
                    let _ = control::mark_stopped(&self.db, name);
                    return Err(error);
                }
            }
            self.insert_handle(name, handle)?;
            Ok(())
        })
    }

    /// Start a persisted machine attached to a Kubernetes pod network namespace.
    /// The launcher bridges the guest virtio-net NIC to a tap inside `netns` so
    /// the pod carries its CNI-assigned IP (see [`control::start_vm_with_netns`]).
    /// Used by the containerd shim for pod sandboxes; requires the machine to use
    /// the virtio-net backend.
    pub fn start_machine_with_netns(&self, name: &str, netns: std::path::PathBuf) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.cached_handle(name)? {
                if lock_handle(&handle)?.is_process_alive() {
                    return Ok(());
                }
                self.remove_cached_handle(name)?;
            }
            let handle = control::start_vm_with_netns(&self.db, name, netns)?;
            self.insert_handle(name, handle)?;
            Ok(())
        })
    }

    /// Start (or reconnect to) a persisted machine as a FORKABLE fork base and
    /// cache its handle. Like [`start_machine`](Self::start_machine) but boots
    /// with memfd-backed guest RAM + a control socket so it can later be forked
    /// with [`fork_machine`](Self::fork_machine) — the basis for local RL rollout
    /// branching.
    pub fn start_forkable_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.cached_handle(name)? {
                if lock_handle(&handle)?.is_process_alive() {
                    return Ok(());
                }
                self.remove_cached_handle(name)?;
            }

            let started = control::start_forkable_vm(&self.db, name)?;
            let mut handle = started.handle;
            if started.freshly_started {
                if let Err(error) = self.launch_image_workload(name, &mut handle) {
                    let _ = handle.stop();
                    let _ = control::mark_stopped(&self.db, name);
                    return Err(error);
                }
            }
            self.insert_handle(name, handle)?;
            Ok(())
        })
    }

    /// Fork a running, forkable `golden` into a new `clone` (copy-on-write guest
    /// RAM + disks, same host) and cache the clone's handle so it can be exec'd
    /// by name. `ports` are `(host, guest)` inbound forwards for the clone; empty
    /// remaps the golden's forwards to fresh host ports. Supported hosts resume
    /// the source after publishing a consistent fork generation.
    pub fn fork_machine(&self, golden: &str, clone: &str, ports: &[(u16, u16)]) -> Result<()> {
        self.with_name_locks(&[golden, clone], || {
            let handle = control::fork_vm(&self.db, golden, clone, ports)?;
            self.insert_handle(clone, handle)?;
            Ok(())
        })
    }

    /// Fork a machine and make the restored clone a new checkpoint source.
    /// This pays one eager guest-memory copy during clone boot; later forks of
    /// `clone` use the normal copy-on-write path.
    pub fn fork_checkpointable_machine(
        &self,
        source: &str,
        clone: &str,
        ports: &[(u16, u16)],
    ) -> Result<()> {
        self.with_name_locks(&[source, clone], || {
            let handle =
                control::fork_vm_with_options(&self.db, source, clone, ports, true, false, None)?;
            self.insert_handle(clone, handle)?;
            Ok(())
        })
    }

    /// Fork several clones from one retained snapshot and boot them with
    /// bounded parallelism. All names are locked together so overlapping SDK
    /// calls cannot race the golden freeze or claim the same clone name.
    pub fn fork_machines(
        &self,
        golden: &str,
        clones: &[String],
        ports: &[(u16, u16)],
        parallel: usize,
    ) -> Result<()> {
        let mut lock_names = Vec::with_capacity(clones.len() + 1);
        lock_names.push(golden);
        lock_names.extend(clones.iter().map(String::as_str));
        self.with_name_locks(&lock_names, || {
            let requests: Vec<_> = clones
                .iter()
                .map(|name| (name.clone(), ports.to_vec()))
                .collect();
            let mut started = control::fork_vm_batch(&self.db, golden, &requests, parallel)?;
            let mut registry = match self.registry.write() {
                Ok(registry) => registry,
                Err(error) => {
                    for (name, handle) in &mut started {
                        let _ = handle.stop();
                        let _ = control::delete_vm(&self.db, name);
                    }
                    return Err(Error::agent("runtime registry", error.to_string()));
                }
            };
            for (name, handle) in started {
                registry.insert(name, Arc::new(Mutex::new(handle)));
            }
            Ok(())
        })
    }

    /// Fork several machines for a detached CLI operation. The group is
    /// prepared transactionally from one generation and every successful clone
    /// outlives this process.
    pub fn fork_machines_detached(
        &self,
        golden: &str,
        clones: &[String],
        ports: &[(u16, u16)],
        parallel: usize,
    ) -> Result<()> {
        let mut lock_names = Vec::with_capacity(clones.len() + 1);
        lock_names.push(golden);
        lock_names.extend(clones.iter().map(String::as_str));
        self.with_name_locks(&lock_names, || {
            let requests: Vec<_> = clones
                .iter()
                .map(|name| (name.clone(), ports.to_vec()))
                .collect();
            for (_, handle) in control::fork_vm_batch(&self.db, golden, &requests, parallel)? {
                handle.detach();
            }
            Ok(())
        })
    }

    /// Fork a machine for a detached CLI operation. Unlike the SDK path, the
    /// clone intentionally outlives this process; all preparation, retained
    /// snapshot reuse, and fail-closed identity rejuvenation remain shared.
    pub fn fork_machine_detached(
        &self,
        golden: &str,
        clone: &str,
        ports: &[(u16, u16)],
        share_weights: bool,
    ) -> Result<()> {
        self.with_name_locks(&[golden, clone], || {
            let handle = control::fork_vm_with_options(
                &self.db,
                golden,
                clone,
                ports,
                false,
                share_weights,
                Some(false),
            )?;
            handle.detach();
            Ok(())
        })
    }

    /// Fork a checkpointable child for a detached CLI operation. The child
    /// outlives this process and can become the source of another fork.
    pub fn fork_checkpointable_machine_detached(
        &self,
        source: &str,
        clone: &str,
        ports: &[(u16, u16)],
    ) -> Result<()> {
        self.with_name_locks(&[source, clone], || {
            let handle = control::fork_vm_with_options(
                &self.db,
                source,
                clone,
                ports,
                true,
                false,
                Some(false),
            )?;
            handle.detach();
            Ok(())
        })
    }

    /// Connect to an already-running machine and cache its handle.
    pub fn connect_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.cached_handle(name)? {
                if lock_handle(&handle)?.is_process_alive() {
                    return Ok(());
                }
                self.remove_cached_handle(name)?;
            }

            let handle = control::connect_vm(&self.db, name)?;
            self.insert_handle(name, handle)?;
            Ok(())
        })
    }

    /// Stop a machine and persist stopped state.
    pub fn stop_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            let _source_lock = crate::agent::fork::lock_fork_source(name)?;
            let record = control::get_record(&self.db, name)?;
            let dependents = self.db.dependent_clones(name)?;
            if !dependents.is_empty() {
                return Err(Error::agent(
                    "stop machine",
                    format!(
                        "machine '{name}' has dependent fork(s) ({}); delete descendants first",
                        dependents.join(", ")
                    ),
                ));
            }
            if let Some(handle) = self.remove_cached_handle(name)? {
                let mut handle = lock_handle(&handle)?;
                if !record.staged_mounts.is_empty() {
                    handle.sync_staged_mounts(&record)?;
                }
                handle.stop()?;
                control::mark_stopped(&self.db, name)?;
                return Ok(());
            }

            control::stop_vm(&self.db, name)
        })
    }

    /// Stop best-effort, remove from the registry and DB, and delete storage.
    pub fn delete_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            let _source_lock = crate::agent::fork::lock_fork_source(name)?;
            let Some(record) = self.db.get_vm(name)? else {
                self.remove_name_lock(name)?;
                return Ok(());
            };

            // A parent's RAM and disks back every direct child. Check before
            // stopping it: discovering the dependency after teardown would
            // leave live descendants dangling.
            let dependents = self.db.dependent_clones(name)?;
            if !dependents.is_empty() {
                return Err(Error::agent(
                    "delete machine",
                    format!(
                        "machine '{name}' has dependent fork(s) ({}); delete descendants first",
                        dependents.join(", ")
                    ),
                ));
            }

            let state = crate::agent::state_probe::resolve_state(name, &record);
            if matches!(
                state,
                crate::config::RecordState::Frozen | crate::config::RecordState::Unreachable
            ) {
                // Paused vCPUs cannot acknowledge the normal guest shutdown.
                // Reap the verified VMM directly instead of waiting for a
                // response that cannot arrive.
                self.remove_cached_handle(name)?;
                crate::agent::state_probe::recover_unreachable_machine_in_db(&record, &self.db)?;
            } else if matches!(
                state,
                crate::config::RecordState::Stopped | crate::config::RecordState::Created
            ) {
                // A graceful stop already synchronized staged mounts. Do not
                // reconnect to the now-absent agent and fail a subsequent delete.
                self.remove_cached_handle(name)?;
            } else if let Some(handle) = self.remove_cached_handle(name)? {
                let mut handle = lock_handle(&handle)?;
                if !record.staged_mounts.is_empty() {
                    handle.sync_staged_mounts(&record)?;
                }
                handle.stop()?;
            } else {
                control::stop_vm(&self.db, name)?;
            }

            // Idempotent: deleting an already-deleted machine is a no-op success
            // (the desired end state — gone — already holds). Lets SDK callers
            // call delete() more than once without an error.
            match control::delete_vm_locked(&self.db, name) {
                Ok(()) | Err(crate::Error::VmNotFound { .. }) => {}
                Err(e) => return Err(e),
            }
            self.remove_name_lock(name)?;
            Ok(())
        })
    }

    /// Copy guest-local staged mounts back to their host sources without
    /// stopping the machine.
    pub fn sync_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            let _source_lock = crate::agent::fork::lock_fork_source(name)?;
            let record = control::get_record(&self.db, name)?;
            if record.staged_mounts.is_empty() {
                return Ok(());
            }
            let handle = self.started_handle(name)?;
            let result = lock_handle(&handle)?.sync_staged_mounts(&record);
            result
        })
    }

    /// Execute a command directly in the VM.
    pub fn exec(
        &self,
        name: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let (image, overlay_owner) = self.image_and_overlay_owner(name)?;
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        match image {
            // Image machine: run inside the machine's persistent container overlay,
            // exactly as the streaming counterpart does — and as the CLI and the
            // cloud transport already do. Without this an exec lands in the bare
            // VM's own rootfs, so the caller silently gets a different filesystem
            // than the image they asked for.
            Some(image) => {
                let config = RunConfig::new(image, command)
                    .with_env(env)
                    .with_workdir(workdir)
                    .with_timeout(timeout)
                    .with_mounts(self.mount_bindings_for(name)?)
                    .with_s3_volumes(self.s3_volumes_for(name)?)
                    .with_persistent_overlay(Some(overlay_owner));
                handle.run_config(config)
            }
            // Bare VM: exec directly against the guest.
            None => handle.exec(command, env, workdir, timeout),
        }
    }

    /// Pull an OCI image and run a command inside it.
    pub fn run(
        &self,
        name: &str,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let (_, overlay_owner) = self.image_and_overlay_owner(name)?;
        let mount_bindings = self.mount_bindings_for(name)?;
        let s3_volumes = self.s3_volumes_for(name)?;
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        if mount_bindings.is_empty() && s3_volumes.is_empty() {
            return handle.run(image, command, env, workdir, timeout);
        }
        handle.pull_image(image)?;
        handle.run_config(
            RunConfig::new(image, command)
                .with_env(env)
                .with_workdir(workdir)
                .with_timeout(timeout)
                .with_mounts(mount_bindings)
                .with_s3_volumes(s3_volumes)
                .with_persistent_overlay(Some(overlay_owner)),
        )
    }

    /// Pull an OCI image into the machine's storage.
    pub fn pull_image(&self, name: &str, image: &str) -> Result<ImageInfo> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.pull_image(image)
    }

    /// List cached OCI images in the machine's storage.
    pub fn list_images(&self, name: &str) -> Result<Vec<ImageInfo>> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.list_images()
    }

    /// Write a file into the machine.
    pub fn write_file(
        &self,
        name: &str,
        path: &str,
        data: Vec<u8>,
        mode: Option<u32>,
    ) -> Result<()> {
        let (image, overlay_owner) = self.image_and_overlay_owner(name)?;
        let mount_bindings = self.mount_bindings_for(name)?;
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        Self::activate_image_overlay(&mut handle, image, overlay_owner, mount_bindings)?;
        handle.write_file(path, &data, mode)
    }

    /// Read a file from the machine.
    pub fn read_file(&self, name: &str, path: &str) -> Result<Vec<u8>> {
        let (image, overlay_owner) = self.image_and_overlay_owner(name)?;
        let mount_bindings = self.mount_bindings_for(name)?;
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        Self::activate_image_overlay(&mut handle, image, overlay_owner, mount_bindings)?;
        handle.read_file(path)
    }

    /// Make an image machine's persistent container rootfs the active target
    /// for the file RPCs that follow. Preparing the overlay alone only mounts
    /// it; a no-op container run also switches the agent's active file root.
    fn activate_image_overlay(
        handle: &mut VmHandle,
        image: Option<String>,
        overlay_owner: String,
        mount_bindings: Vec<(String, String, bool)>,
    ) -> Result<()> {
        let Some(image) = image else {
            return Ok(());
        };
        let (code, _, stderr) = handle.run_config(
            RunConfig::new(image, vec!["/bin/true".to_string()])
                .with_mounts(mount_bindings)
                .with_persistent_overlay(Some(overlay_owner)),
        )?;
        if code == 0 {
            Ok(())
        } else {
            Err(Error::agent(
                "activate image overlay",
                format!(
                    "container probe exited {code}: {}",
                    String::from_utf8_lossy(&stderr).trim()
                ),
            ))
        }
    }

    /// Return the host port currently forwarding to `guest_port`.
    ///
    /// Forks with unpinned ports receive fresh host ports, so SDK callers must
    /// read the clone's persisted mapping instead of assuming the golden's.
    pub fn host_port(&self, name: &str, guest_port: u16) -> Result<Option<u16>> {
        Ok(control::get_record(&self.db, name)?
            .ports
            .into_iter()
            .find_map(|(host, guest)| (guest == guest_port).then_some(host)))
    }

    /// Return all published guest ports for readiness checks.
    pub fn guest_ports(&self, name: &str) -> Result<Vec<u16>> {
        Ok(control::get_record(&self.db, name)?
            .ports
            .into_iter()
            .map(|(_, guest)| guest)
            .collect())
    }

    fn launch_image_workload(&self, name: &str, handle: &mut VmHandle) -> Result<()> {
        let record = control::get_record(&self.db, name)?;
        handle.launch_image_workload(name, &record)
    }

    /// The machine's remote volumes, resolved against its own recorded env.
    ///
    /// An exec is often what establishes the workload container — the machine's
    /// command exited, or the image's own default was short-lived — and that
    /// container is where the mount lives. Carrying the volumes on every exec
    /// means the bucket is present in whichever container ends up serving the
    /// session, instead of only when a long-running workload happens to survive.
    fn s3_volumes_for(&self, name: &str) -> Result<Vec<smolvm_protocol::S3Volume>> {
        let record = control::get_record(&self.db, name)?;
        Ok(crate::remote_volume::to_s3_volumes(
            &record.remote_volumes,
            &record.env,
        ))
    }

    fn mount_bindings_for(&self, name: &str) -> Result<Vec<(String, String, bool)>> {
        let record = control::get_record(&self.db, name)?;
        Ok(crate::workload::record_mounts_to_bindings(&record))
    }

    /// The machine's image, if it is an image (container-workload) machine.
    /// Streamed execs on such a machine must run inside its persistent container
    /// overlay so their writes survive — matching non-streaming exec.
    fn image_and_overlay_owner(&self, name: &str) -> Result<(Option<String>, String)> {
        let record = control::get_record(&self.db, name)?;
        let overlay_owner = crate::workload::persistent_overlay_owner_with_lineage(
            name,
            record.golden.as_deref(),
            record.fork_overlay_owner.as_deref(),
        );
        Ok((record.image, overlay_owner))
    }

    /// Execute a command and collect streaming output events.
    pub fn exec_streaming(
        &self,
        name: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Vec<ExecEvent>> {
        let mut events = Vec::new();
        self.exec_streaming_with(name, command, env, workdir, timeout, |e| events.push(e))?;
        Ok(events)
    }

    /// Execute a command, delivering streaming output events LIVE via the
    /// callback as they arrive (no buffering). The live counterpart of
    /// `exec_streaming`; SDKs bridge the callback to a native iterator.
    pub fn exec_streaming_with<F: FnMut(ExecEvent)>(
        &self,
        name: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
        on_event: F,
    ) -> Result<()> {
        let (image, overlay_owner) = self.image_and_overlay_owner(name)?;
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        match image {
            // Image machine: stream inside the machine's persistent container
            // overlay so streamed installs/writes persist across execs and
            // restarts, like non-streaming exec. Keyed by machine name.
            Some(image) => {
                let config = RunConfig::new(image, command)
                    .with_env(env)
                    .with_workdir(workdir)
                    .with_timeout(timeout)
                    .with_mounts(self.mount_bindings_for(name)?)
                    .with_s3_volumes(self.s3_volumes_for(name)?)
                    .with_persistent_overlay(Some(overlay_owner));
                handle.run_streaming_with(config, on_event)
            }
            // Bare VM: stream directly against the guest.
            None => handle.exec_streaming_with(command, env, workdir, timeout, on_event),
        }
    }

    /// Get the child PID if the machine is running.
    pub fn pid(&self, name: &str) -> Option<i32> {
        if let Ok(Some(handle)) = self.cached_handle(name) {
            if let Ok(handle) = handle.lock() {
                if let Some(pid) = handle.child_pid() {
                    return Some(pid);
                }
            }
        }

        self.db
            .get_vm(name)
            .ok()
            .flatten()
            .and_then(|record| record.pid)
    }

    /// Return whether the machine process is currently running.
    pub fn is_running(&self, name: &str) -> bool {
        if let Ok(Some(handle)) = self.cached_handle(name) {
            if let Ok(handle) = handle.lock() {
                return handle.is_process_alive();
            }
        }

        self.db
            .get_vm(name)
            .ok()
            .flatten()
            .is_some_and(|record| record.actual_state() == RecordState::Running)
    }

    /// Get the current machine state as a string.
    pub fn state(&self, name: &str) -> String {
        if let Ok(Some(handle)) = self.cached_handle(name) {
            if let Ok(handle) = handle.lock() {
                return handle.state();
            }
        }

        match self.db.get_vm(name).ok().flatten() {
            Some(record) if record.actual_state() == RecordState::Running => "running".into(),
            Some(record) if record.actual_state() == RecordState::Failed => "failed".into(),
            _ => "stopped".into(),
        }
    }

    fn started_handle(&self, name: &str) -> Result<SharedHandle> {
        self.cached_handle(name)?
            .ok_or_else(|| Error::InvalidState {
                expected: "started".into(),
                actual: "not started".into(),
            })
    }

    fn cached_handle(&self, name: &str) -> Result<Option<SharedHandle>> {
        let registry = self
            .registry
            .read()
            .map_err(|e| Error::agent("runtime registry", e.to_string()))?;
        Ok(registry.get(name).cloned())
    }

    fn insert_handle(&self, name: &str, handle: VmHandle) -> Result<()> {
        let mut registry = self
            .registry
            .write()
            .map_err(|e| Error::agent("runtime registry", e.to_string()))?;
        registry.insert(name.to_string(), Arc::new(Mutex::new(handle)));
        Ok(())
    }

    fn remove_cached_handle(&self, name: &str) -> Result<Option<SharedHandle>> {
        let mut registry = self
            .registry
            .write()
            .map_err(|e| Error::agent("runtime registry", e.to_string()))?;
        Ok(registry.remove(name))
    }

    fn with_name_lock<T, F>(&self, name: &str, op: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.with_name_locks(&[name], op)
    }

    fn with_name_locks<T, F>(&self, names: &[&str], op: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let mut names = names.to_vec();
        names.sort_unstable();
        names.dedup();
        let locks = names
            .into_iter()
            .map(|name| self.lock_for_name(name))
            .collect::<Result<Vec<_>>>()?;
        let _guards = locks.iter().map(lock_name).collect::<Result<Vec<_>>>()?;
        op()
    }

    fn lock_for_name(&self, name: &str) -> Result<Arc<Mutex<()>>> {
        if let Some(lock) = self
            .name_locks
            .read()
            .map_err(|e| Error::agent("runtime name locks", e.to_string()))?
            .get(name)
            .cloned()
        {
            return Ok(lock);
        }

        let mut locks = self
            .name_locks
            .write()
            .map_err(|e| Error::agent("runtime name locks", e.to_string()))?;
        Ok(locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone())
    }

    fn remove_name_lock(&self, name: &str) -> Result<()> {
        let mut locks = self
            .name_locks
            .write()
            .map_err(|e| Error::agent("runtime name locks", e.to_string()))?;
        locks.remove(name);
        Ok(())
    }
}

fn lock_name(lock: &Arc<Mutex<()>>) -> Result<MutexGuard<'_, ()>> {
    lock.lock()
        .map_err(|e| Error::agent("runtime name lock", e.to_string()))
}

fn lock_handle(handle: &SharedHandle) -> Result<MutexGuard<'_, VmHandle>> {
    handle
        .lock()
        .map_err(|e| Error::agent("runtime handle", e.to_string()))
}

/// Return the process-local embedded runtime singleton.
pub fn runtime() -> Result<Arc<EmbeddedRuntime>> {
    static RUNTIME: OnceLock<Arc<EmbeddedRuntime>> = OnceLock::new();

    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime.clone());
    }

    let runtime = Arc::new(EmbeddedRuntime::new()?);
    match RUNTIME.set(runtime.clone()) {
        Ok(()) => Ok(runtime),
        Err(_) => Ok(RUNTIME
            .get()
            .expect("runtime initialized by competing thread")
            .clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SmolvmDb {
        static NEXT_DB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_DB.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "smolvm-embedded-runtime-{}-{unique}-{sequence}.db",
            std::process::id(),
        ));
        SmolvmDb::open_at(&path).unwrap()
    }

    fn test_spec(name: &str, persistent: bool) -> MachineSpec {
        MachineSpec {
            name: name.to_string(),
            mounts: Vec::new(),
            ports: Vec::new(),
            resources: crate::agent::VmResources::default(),
            image: None,
            persistent,
            // Spread the rest so a new spec field does not break the fixtures.
            ..MachineSpec::default()
        }
    }

    #[test]
    fn remove_name_lock_removes_entry() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime.lock_for_name("runtime-remove-lock").unwrap();

        runtime.remove_name_lock("runtime-remove-lock").unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());
    }

    #[test]
    fn remove_name_lock_ignores_missing_entry() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime.remove_name_lock("runtime-missing-lock").unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());
    }

    #[test]
    fn runtime_rejects_duplicate_create() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-duplicate", false))
            .unwrap();

        let err = runtime
            .create_machine(test_spec("runtime-duplicate", false))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Agent {
                kind: crate::error::AgentErrorKind::Conflict,
                ..
            }
        ));
    }

    #[test]
    fn runtime_state_defaults_to_stopped_for_created_record() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-state", true))
            .unwrap();

        assert_eq!(runtime.state("runtime-state"), "stopped");
        assert!(!runtime.is_running("runtime-state"));
        assert_eq!(runtime.pid("runtime-state"), None);
    }

    #[test]
    fn reconnect_never_restarts_a_frozen_fork_base() {
        let db = test_db();
        let mut record = test_spec("frozen-checkpoint", true).to_record();
        record.state = crate::config::RecordState::Frozen;
        db.insert_vm_if_not_exists("frozen-checkpoint", &record)
            .unwrap();
        let runtime = EmbeddedRuntime::with_db(db.clone());

        runtime
            .connect_or_start_machine("frozen-checkpoint")
            .unwrap();

        assert_eq!(
            db.get_vm("frozen-checkpoint").unwrap().unwrap().state,
            crate::config::RecordState::Frozen
        );
        assert!(runtime.registry.read().unwrap().is_empty());
    }

    #[test]
    fn image_overlay_owner_uses_machine_name_for_regular_machines() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        let mut spec = test_spec("runtime-image", true);
        spec.image = Some("example/image:latest".to_string());
        runtime.create_machine(spec).unwrap();

        assert_eq!(
            runtime.image_and_overlay_owner("runtime-image").unwrap(),
            (
                Some("example/image:latest".to_string()),
                "runtime-image".to_string()
            )
        );
    }

    #[test]
    fn image_overlay_owner_uses_golden_name_for_clones() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        let mut record = test_spec("runtime-clone", true).to_record();
        record.image = Some("example/image:latest".to_string());
        record.golden = Some("runtime-golden".to_string());
        runtime.db.insert_vm("runtime-clone", &record).unwrap();

        assert_eq!(
            runtime.image_and_overlay_owner("runtime-clone").unwrap(),
            (
                Some("example/image:latest".to_string()),
                "runtime-golden".to_string()
            )
        );
    }

    #[test]
    fn image_overlay_owner_fails_closed_for_missing_records() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        assert!(matches!(
            runtime.image_and_overlay_owner("missing"),
            Err(crate::Error::VmNotFound { .. })
        ));
    }

    #[test]
    fn host_port_reads_the_persisted_mapping() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        let mut spec = test_spec("runtime-ports", true);
        spec.ports = vec![crate::data::network::PortMapping::new(49152, 3000)];
        runtime.create_machine(spec).unwrap();

        assert_eq!(
            runtime.host_port("runtime-ports", 3000).unwrap(),
            Some(49152)
        );
        assert_eq!(runtime.host_port("runtime-ports", 9222).unwrap(), None);
    }

    #[test]
    fn delete_machine_removes_name_lock_entry() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-delete-lock", true))
            .unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .contains_key("runtime-delete-lock"));

        runtime.delete_machine("runtime-delete-lock").unwrap();

        assert!(!runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .contains_key("runtime-delete-lock"));
    }

    #[test]
    fn delete_already_stopped_staged_machine_does_not_reconnect() {
        let db = test_db();
        let runtime = EmbeddedRuntime::with_db(db.clone());
        let mut record = test_spec("delete-stopped-staged", true).to_record();
        record.state = crate::config::RecordState::Stopped;
        record.staged_mounts = vec![(0, "/host/work".into(), "/work".into())];
        db.insert_vm("delete-stopped-staged", &record).unwrap();

        runtime.delete_machine("delete-stopped-staged").unwrap();
        assert!(db.get_vm("delete-stopped-staged").unwrap().is_none());
    }

    #[test]
    fn delete_machine_refuses_a_live_fork_parent_before_teardown() {
        let db = test_db();
        let runtime = EmbeddedRuntime::with_db(db.clone());
        runtime
            .create_machine(test_spec("delete-parent", true))
            .unwrap();
        let mut child = test_spec("delete-child", true).to_record();
        child.golden = Some("delete-parent".to_string());
        db.insert_vm("delete-child", &child).unwrap();

        let error = runtime.delete_machine("delete-parent").unwrap_err();
        assert!(error.to_string().contains("dependent fork"));
        assert!(db.get_vm("delete-parent").unwrap().is_some());
        assert!(db.get_vm("delete-child").unwrap().is_some());
    }

    #[test]
    fn stop_machine_refuses_a_live_fork_parent_before_teardown() {
        let db = test_db();
        let runtime = EmbeddedRuntime::with_db(db.clone());
        runtime
            .create_machine(test_spec("stop-parent", true))
            .unwrap();
        let mut child = test_spec("stop-child", true).to_record();
        child.golden = Some("stop-parent".to_string());
        db.insert_vm("stop-child", &child).unwrap();

        let error = runtime.stop_machine("stop-parent").unwrap_err();
        assert!(error.to_string().contains("dependent fork"));
        assert!(db.get_vm("stop-parent").unwrap().is_some());
        assert!(db.get_vm("stop-child").unwrap().is_some());
    }

    #[test]
    fn delete_machine_reaps_a_frozen_checkpoint_without_guest_shutdown() {
        let db = test_db();
        let runtime = EmbeddedRuntime::with_db(db.clone());
        let mut record = test_spec("delete-frozen", true).to_record();
        record.state = crate::config::RecordState::Frozen;
        db.insert_vm("delete-frozen", &record).unwrap();

        runtime.delete_machine("delete-frozen").unwrap();
        assert!(db.get_vm("delete-frozen").unwrap().is_none());
    }
}
