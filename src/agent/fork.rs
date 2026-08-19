//! Live fork mechanics shared by the CLI (`machine fork`) and the serve API
//! (`POST /api/v1/machines/{id}/fork`).
//!
//! A fork freezes a running, forkable golden machine — it stays paused as the
//! shared copy-on-write base — snapshots its memfd-backed RAM + device state,
//! gives the clone copy-on-write disk overlays, and lets the caller boot the
//! clone from that snapshot. The boot itself differs between callers (the CLI
//! uses `start_vm_named`; the API uses `AgentManager`), so it stays out of here;
//! everything up to and including the snapshot + disk clone is shared so the two
//! entry points can never silently diverge.

use crate::agent::{resolve_disk_image, vm_data_dir, AgentClient};
use crate::config::VmRecord;
use crate::data::validate_vm_name;
use crate::db::SmolvmDb;
use crate::{Error, Result};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Path to a forkable machine's control socket (pause/resume/checkpoint/FORK).
pub fn control_socket_path(name: &str) -> PathBuf {
    vm_data_dir(name).join("control.sock")
}

/// Send a single line command to a VM control socket and return its reply line.
pub fn control_socket_cmd(sock: &Path, cmd: &str) -> Result<String> {
    use crate::platform::uds::UdsStream;
    use std::io::{Read, Write};

    let mut stream = UdsStream::connect(sock)
        .map_err(|e| Error::agent("connect control socket", e.to_string()))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .ok();
    stream
        .write_all(format!("{cmd}\n").as_bytes())
        .map_err(|e| Error::agent("write control socket", e.to_string()))?;
    let mut reply = String::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                reply.push(byte[0] as char);
            }
            Err(e) => return Err(Error::agent("read control socket", e.to_string())),
        }
    }
    Ok(reply)
}

/// Workload preparation choices inherited by every clone of one golden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ForkpointProfile {
    /// Load the golden's staged CUDA modules while each clone worker boots.
    pub cuda_preload_modules: bool,
}

fn parse_forkpoint_profile(marker: &[u8]) -> ForkpointProfile {
    let hint = smolvm_protocol::forkpoint::CUDA_PRELOAD_MODULES_HINT.as_bytes();
    ForkpointProfile {
        cuda_preload_modules: marker.split(|byte| *byte == b'\n').any(|line| line == hint),
    }
}

fn persist_forkpoint_profile(golden: &str, profile: ForkpointProfile) -> Result<()> {
    let updated = SmolvmDb::open()?.update_vm(golden, |record| {
        record.cuda_preload_modules = profile.cuda_preload_modules;
    })?;
    if updated.is_none() {
        return Err(Error::vm_not_found(golden));
    }
    Ok(())
}

/// Wait until the golden workload reaches the standard live-fork boundary.
///
/// The workload signals this by calling `smolvm-fork-ready`, which writes the
/// marker and blocks. Keeping the wait in the VM namespace avoids coupling the
/// host to container logs, PIDs, or workload-specific files.
pub fn wait_for_forkpoint(golden: &str, timeout: Duration) -> Result<()> {
    // A successful first fork leaves the golden paused permanently as the CoW
    // base. Pool replenishment must not try to run a new agent exec inside that
    // paused VM: its vCPUs cannot answer, even though the already-proven
    // forkpoint remains the exact snapshot source. The control plane is still
    // live in the VMM, so recognize that state before touching the guest.
    let control = control_socket_path(golden);
    if control.exists() {
        if let Ok(status) = control_socket_cmd(&control, "STATUS") {
            if fork_base_already_paused(&status) {
                tracing::debug!(golden, %status, "fork base is already paused; reusing its forkpoint");
                return Ok(());
            }
        }
    }

    let socket = vm_data_dir(golden).join("agent.sock");
    let mut client = AgentClient::connect_with_retry(&socket)
        .map_err(|e| Error::agent("wait for forkpoint", format!("agent connect: {e}")))?;
    let script = format!(
        "while [ ! -f '{ready}' ]; do sleep 0.05; done; cat '{ready}'",
        ready = smolvm_protocol::forkpoint::READY_PATH,
    );
    match client.vm_exec(
        vec!["/bin/sh".into(), "-c".into(), script],
        vec![],
        None,
        Some(timeout),
        None,
    ) {
        Ok((0, stdout, _)) => {
            let profile = parse_forkpoint_profile(&stdout);
            persist_forkpoint_profile(golden, profile)?;
            Ok(())
        }
        Ok((code, _, stderr)) => Err(Error::agent(
            "wait for forkpoint",
            format!(
                "golden '{golden}' did not become ready within {}s (exit {code}): {}",
                timeout.as_secs_f64(),
                String::from_utf8_lossy(&stderr).trim()
            ),
        )),
        Err(e) => Err(Error::agent(
            "wait for forkpoint",
            format!(
                "golden '{golden}' did not become ready within {}s: {e}",
                timeout.as_secs_f64()
            ),
        )),
    }
}

fn fork_base_already_paused(status: &str) -> bool {
    status.trim() == "OK paused"
}

/// Release the workload restored in `clone` after its identity and per-fork
/// environment are installed. The state directory is private guest RAM, so a
/// release marker wakes only this clone even though every clone inherited the
/// same blocked helper process.
pub fn release_forkpoint(clone: &str) -> Result<()> {
    let socket = vm_data_dir(clone).join("agent.sock");
    let mut client = AgentClient::connect_with_retry(&socket)
        .map_err(|e| Error::agent("release forkpoint", format!("agent connect: {e}")))?;
    let script = format!(
        "set -e; mkdir -p '{dir}'; umask 077; printf '%s\\n' smolvm-forkpoint-release-v1 > '{release}.tmp'; mv '{release}.tmp' '{release}'",
        dir = smolvm_protocol::forkpoint::STATE_DIR,
        release = smolvm_protocol::forkpoint::RELEASE_PATH,
    );
    match client.vm_exec(
        vec!["/bin/sh".into(), "-c".into(), script],
        vec![],
        None,
        Some(Duration::from_secs(10)),
        None,
    ) {
        Ok((0, _, _)) => Ok(()),
        Ok((code, _, stderr)) => Err(Error::agent(
            "release forkpoint",
            format!(
                "clone '{clone}' release exited {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        )),
        Err(e) => Err(Error::agent(
            "release forkpoint",
            format!("clone '{clone}': {e}"),
        )),
    }
}

/// Roll back a golden after every clone prepared from its snapshot has been
/// torn down. A completed fork checkpoint must be reapplied before resuming;
/// if capture failed before producing one, an ordinary resume is sufficient.
fn golden_resume_command(snapshot_dir: &Path) -> Result<String> {
    let checkpoint = snapshot_dir.join("checkpoint.bin");
    match std::fs::symlink_metadata(&checkpoint) {
        Ok(metadata) if metadata.file_type().is_file() => {
            Ok(format!("ROLLBACK_FORK {}", snapshot_dir.display()))
        }
        Ok(_) => Err(Error::agent(
            "resume golden",
            format!(
                "refusing non-regular rollback checkpoint {}",
                checkpoint.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("RESUME".to_string()),
        Err(error) => Err(Error::agent(
            "resume golden",
            format!("inspect rollback checkpoint: {error}"),
        )),
    }
}

/// Resume a failed fork's golden, restoring its completed checkpoint when one exists.
pub fn resume_golden(golden: &str, snapshot_dir: &Path) -> Result<()> {
    let command = golden_resume_command(snapshot_dir)?;
    let reply = control_socket_cmd(&control_socket_path(golden), &command)?;
    if reply.starts_with("OK") {
        Ok(())
    } else {
        Err(Error::agent(
            "resume golden",
            format!("golden '{golden}' RESUME failed: {reply}"),
        ))
    }
}

/// Remove every retained RAM checkpoint for a golden whose VMM is confirmed
/// dead and which has no dependent clones. A checkpoint is tied to the exact
/// golden PID/memfd identity and can never be valid after that process exits.
pub(crate) fn discard_retained_snapshots(db: &SmolvmDb, golden: &str) -> Result<()> {
    let snapshot_root = vm_data_dir(golden).join("s");
    match std::fs::symlink_metadata(&snapshot_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            std::fs::remove_dir_all(&snapshot_root).map_err(|error| {
                Error::agent("remove retained fork snapshots", error.to_string())
            })?;
        }
        Ok(_) => {
            return Err(Error::agent(
                "remove retained fork snapshots",
                format!(
                    "refusing to remove non-directory {}",
                    snapshot_root.display()
                ),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::agent(
                "inspect retained fork snapshots",
                error.to_string(),
            ));
        }
    }
    db.remove_retained_fork_snapshot(golden)?;
    Ok(())
}

/// The result of preparing a fork: the golden is frozen + snapshotted and the
/// clone's DB record + copy-on-write disks exist on disk. The caller boots the
/// clone from `snapshot_dir`, then calls [`rejuvenate_clone`].
pub struct PreparedFork {
    /// Directory holding the golden's checkpoint + memfd manifest. Pass it as the
    /// clone's `LaunchFeatures::snapshot_dir` to boot from it instead of cold.
    pub snapshot_dir: PathBuf,
    /// The clone's freshly-inserted DB record (golden's config, remapped ports).
    pub clone_record: VmRecord,
    /// Per-port inbound remap as `(golden_host, guest, clone_host)`, for the
    /// caller to log. Empty when the golden has no forwards. When ports were
    /// pinned, `golden_host == clone_host`.
    pub port_remaps: Vec<(u16, u16, u16)>,
    /// Whether a caller must resume the golden if clone boot/finalization fails.
    /// False for pool refill from an already-paused golden: resuming that base
    /// would invalidate every existing clone and retained CUDA snapshot.
    pub resume_golden_on_rollback: bool,
}

/// A checkpoint that may be reused while the exact same golden process remains
/// paused. The PID start time prevents an old on-disk checkpoint from being
/// applied after a golden restart or PID reuse.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct RetainedForkSnapshot {
    /// Directory containing the libkrun checkpoint and memfd manifest.
    pub(crate) path: PathBuf,
    /// Host process that produced the checkpoint.
    pub(crate) golden_pid: i32,
    /// Kernel process start time paired with `golden_pid`.
    pub(crate) golden_pid_start_time: u64,
}

/// Prepared batch plus the checkpoint identity that can service later refills.
pub(crate) struct PreparedForkBatch {
    /// Clones registered from one checkpoint.
    pub(crate) forks: Vec<PreparedFork>,
    /// Checkpoint bound to the current golden process, when its identity is
    /// strong enough to reuse safely.
    pub(crate) retained_snapshot: Option<RetainedForkSnapshot>,
    /// Whether this call reused `retained_snapshot` instead of checkpointing.
    pub(crate) snapshot_reused: bool,
}

/// Parameters for one clone in a single-snapshot fork operation.
pub struct ForkSpec<'a> {
    /// New machine name.
    pub clone: &'a str,
    /// Explicit inbound port mappings, or empty to remap the golden's ports.
    pub pinned_ports: &'a [(u16, u16)],
    /// Whether the clone should itself be forkable.
    pub clone_forkable: bool,
    /// Per-clone environment delivered before the workload is released.
    pub fork_env: &'a [(String, String)],
    /// Per-clone secret references resolved by later execs.
    pub fork_secrets: &'a BTreeMap<String, crate::secrets::SecretRef>,
    /// Keep the restored workload parked at its inherited forkpoint until a
    /// later assignment explicitly releases it.
    pub hold: bool,
}

/// Freeze a running, forkable `golden`, snapshot it, register `clone` in the DB
/// with copy-on-write disks, and return everything the caller needs to boot the
/// clone. Launch-agnostic: the actual boot is the caller's job (CLI via
/// `start_vm_named`, API via `AgentManager`), keyed off the returned
/// `snapshot_dir`.
///
/// On any failure after the clone record is inserted, the record and its data
/// directory are cleaned up before returning the error, so a failed fork leaves
/// no half-registered clone behind.
pub fn prepare_fork(
    db: &SmolvmDb,
    golden: &str,
    clone: &str,
    pinned_ports: &[(u16, u16)],
    clone_forkable: bool,
    fork_env: &[(String, String)],
    fork_secrets: &BTreeMap<String, crate::secrets::SecretRef>,
) -> Result<PreparedFork> {
    let mut prepared = prepare_forks(
        db,
        golden,
        &[ForkSpec {
            clone,
            pinned_ports,
            clone_forkable,
            fork_env,
            fork_secrets,
            hold: false,
        }],
    )?;
    Ok(prepared.remove(0))
}

/// Prepare one clean clone that remains parked at the inherited forkpoint.
/// Held slots are deliberately non-forkable and one-shot.
pub fn prepare_held_fork(
    db: &SmolvmDb,
    golden: &str,
    clone: &str,
    pinned_ports: &[(u16, u16)],
    fork_env: &[(String, String)],
    fork_secrets: &BTreeMap<String, crate::secrets::SecretRef>,
) -> Result<PreparedFork> {
    let mut prepared = prepare_forks(
        db,
        golden,
        &[ForkSpec {
            clone,
            pinned_ports,
            clone_forkable: false,
            fork_env,
            fork_secrets,
            hold: true,
        }],
    )?;
    Ok(prepared.remove(0))
}

/// Freeze a golden once and prepare every requested clone from the same RAM
/// snapshot. Preparation is transactional: if any clone fails, all clone
/// records and disks created by this call are removed.
///
/// A successful fork leaves the golden paused forever as the copy-on-write base,
/// so the checkpoint it just took is retained and reused by every later fork of
/// that same golden process. Without the retain a golden could be forked exactly
/// once and every call after it failed with "already paused".
pub fn prepare_forks(
    db: &SmolvmDb,
    golden: &str,
    specs: &[ForkSpec<'_>],
) -> Result<Vec<PreparedFork>> {
    let retained = db
        .retained_fork_snapshot(golden)
        .map_err(|error| Error::agent("read retained fork checkpoint", error.to_string()))?;
    Ok(prepare_forks_reusing(db, golden, specs, retained.as_ref(), true)?.forks)
}

/// Prepare a batch while reusing a proven checkpoint when it still belongs to
/// the exact paused golden process. Invalid or stale hints fall back to a fresh
/// checkpoint; they can never cause a restore from a restarted golden.
pub(crate) fn prepare_forks_reusing(
    db: &SmolvmDb,
    golden: &str,
    specs: &[ForkSpec<'_>],
    retained: Option<&RetainedForkSnapshot>,
    persist_snapshot: bool,
) -> Result<PreparedForkBatch> {
    if specs.is_empty() {
        return Err(Error::config("fork", "at least one clone is required"));
    }

    let mut names = HashSet::with_capacity(specs.len());
    let mut reserved_ports = HashSet::new();
    for spec in specs {
        validate_vm_name(spec.clone, "clone name").map_err(|e| Error::config("clone name", e))?;
        validate_fork_env(spec.fork_env)?;
        if !names.insert(spec.clone) {
            return Err(Error::config(
                "fork",
                format!("duplicate clone name '{}'", spec.clone),
            ));
        }
        if spec.clone_forkable {
            return Err(Error::agent(
                "fork",
                "nested fork is not supported: a clone cannot be re-forked, so `forkable` on a fork has no effect (drop it)",
            ));
        }
        if db.get_vm(spec.clone)?.is_some() {
            return Err(Error::agent(
                "fork",
                format!("machine '{}' already exists", spec.clone),
            ));
        }
        for (host, _) in spec.pinned_ports {
            if !reserved_ports.insert(*host) {
                return Err(Error::config(
                    "fork",
                    format!("host port {host} is assigned to more than one clone"),
                ));
            }
        }
    }

    let golden_rec = db
        .get_vm(golden)?
        .ok_or_else(|| Error::vm_not_found(golden))?;
    let ctl = control_socket_path(golden);
    if !ctl.exists() {
        return Err(Error::agent(
            "fork",
            format!("golden '{golden}' is not running forkable; start it with `machine start --forkable --name {golden}`"),
        ));
    }
    let status = control_socket_cmd(&ctl, "STATUS").map_err(|e| {
        Error::agent(
            "fork",
            format!("golden '{golden}' control socket not responding ({e}); start it with `machine start --forkable --name {golden}`"),
        )
    })?;
    if !status.starts_with("OK") {
        return Err(Error::agent(
            "fork",
            format!("golden '{golden}' is not ready to fork: {status}"),
        ));
    }
    let golden_was_paused = fork_base_already_paused(&status);

    let gdir = vm_data_dir(golden);
    // Keep this path short and independent of clone names. libkrun and its
    // control transport encounter platform path ceilings well below PATH_MAX;
    // a long XDG_CACHE_HOME plus `fork-snapshots/<clone>` otherwise makes a
    // valid golden fail restore with EINVAL. The 8-hex component keeps the
    // snapshot path no longer than the already-required `agent.sock` path.
    // Never remove a colliding random directory because a live clone may still
    // be using an older snapshot.
    let snapshot_root = gdir.join("s");
    let reusable = retained.filter(|snapshot| {
        retained_snapshot_is_reusable(&golden_rec, golden_was_paused, &snapshot_root, snapshot)
    });
    if golden_was_paused && reusable.is_none() {
        return Err(Error::agent(
            "fork",
            format!("golden '{golden}' is already paused; a valid retained checkpoint is required"),
        ));
    }
    let (snapshot_dir, snapshot_reused) = if let Some(snapshot) = reusable {
        tracing::info!(
            golden,
            path = %snapshot.path.display(),
            clones = specs.len(),
            "fork: reusing retained golden RAM checkpoint"
        );
        (snapshot.path.clone(), true)
    } else {
        std::fs::create_dir_all(&snapshot_root)
            .map_err(|e| Error::agent("create snapshot root", e.to_string()))?;
        let snapshot_dir = (0..128)
            .find_map(|_| {
                let candidate = snapshot_root.join(host_random_hex(8));
                match std::fs::create_dir(&candidate) {
                    Ok(()) => Some(Ok(candidate)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .transpose()
            .map_err(|e| Error::agent("create snapshot dir", e.to_string()))?
            .ok_or_else(|| Error::agent("create snapshot dir", "could not allocate a unique id"))?;
        if let Some(result) =
            crate::process::vm_drop_ids(&crate::agent::vm_uid_registry_dir(), &gdir, None, None)
        {
            let (uid, gid) =
                result.map_err(|e| Error::agent("fork: resolve golden uid", e.to_string()))?;
            crate::process::chown_tree(&snapshot_dir, uid, gid)
                .map_err(|e| Error::agent("fork: chown snapshot dir", e.to_string()))?;
        }

        let t_snap = std::time::Instant::now();
        let reply = control_socket_cmd(&ctl, &format!("FORK {}", snapshot_dir.display()));
        let reply = match reply {
            Ok(reply) if reply.starts_with("OK") => reply,
            Ok(reply) => {
                return Err(rollback_new_snapshot(
                    db,
                    golden,
                    &snapshot_dir,
                    false,
                    Error::agent("fork", format!("golden FORK failed: {reply}")),
                ));
            }
            Err(error) => {
                return Err(rollback_new_snapshot(
                    db,
                    golden,
                    &snapshot_dir,
                    false,
                    error,
                ));
            }
        };
        tracing::info!(
            elapsed_ms = t_snap.elapsed().as_millis() as u64,
            clones = specs.len(),
            response = %reply,
            "fork: golden RAM checkpoint written"
        );
        (snapshot_dir, false)
    };

    let retained_snapshot =
        golden_rec
            .pid
            .zip(golden_rec.pid_start_time)
            .map(|(golden_pid, golden_pid_start_time)| RetainedForkSnapshot {
                path: snapshot_dir.clone(),
                golden_pid,
                golden_pid_start_time,
            });
    if persist_snapshot && !snapshot_reused {
        let persisted = retained_snapshot
            .as_ref()
            .ok_or_else(|| {
                Error::agent(
                    "fork",
                    format!("golden '{golden}' process identity is unavailable"),
                )
            })
            .and_then(|snapshot| {
                db.set_retained_fork_snapshot(golden, snapshot)
                    .map_err(|error| {
                        Error::agent("persist retained fork checkpoint", error.to_string())
                    })
            });
        if let Err(error) = persisted {
            return Err(rollback_new_snapshot(
                db,
                golden,
                &snapshot_dir,
                false,
                error,
            ));
        }
    }

    let mut prepared = Vec::with_capacity(specs.len());
    for spec in specs {
        match prepare_clone_from_snapshot(
            db,
            golden,
            &golden_rec,
            &gdir,
            &snapshot_dir,
            spec,
            &mut reserved_ports,
        ) {
            Ok(mut clone) => {
                clone.resume_golden_on_rollback = !golden_was_paused;
                prepared.push(clone);
            }
            Err(error) => {
                for clone in &prepared {
                    let _ = db.remove_vm(&clone.clone_record.name);
                    let _ = std::fs::remove_dir_all(vm_data_dir(&clone.clone_record.name));
                }
                if snapshot_reused || golden_was_paused {
                    return Err(error);
                }
                return Err(rollback_new_snapshot(
                    db,
                    golden,
                    &snapshot_dir,
                    persist_snapshot,
                    error,
                ));
            }
        }
    }
    Ok(PreparedForkBatch {
        forks: prepared,
        retained_snapshot,
        snapshot_reused,
    })
}

/// Restore an initially-running golden after a failed clone finalization and
/// discard the checkpoint that produced that clone. Callers must ensure no
/// successfully booted clone depends on `snapshot_dir` before invoking this.
pub(crate) fn rollback_retained_fork_snapshot(
    db: &SmolvmDb,
    golden: &str,
    snapshot_dir: &Path,
    persisted: bool,
) -> Result<()> {
    let dependent_clones = db.dependent_clones(golden)?;
    if !dependent_clones.is_empty() {
        return Err(Error::agent(
            "fork rollback",
            format!(
                "refusing to resume golden '{golden}': {} live clone(s) still depend on its checkpoint ({})",
                dependent_clones.len(),
                dependent_clones.join(", ")
            ),
        ));
    }

    let mut rollback_errors = Vec::new();
    if let Err(resume_error) = resume_golden(golden, snapshot_dir) {
        return Err(Error::agent(
            "fork rollback",
            format!(
                "golden rollback failed: {resume_error}; preserved checkpoint {} for recovery",
                snapshot_dir.display()
            ),
        ));
    }
    if persisted {
        if let Err(remove_error) = db.remove_retained_fork_snapshot(golden) {
            tracing::warn!(%golden, %remove_error, "failed to remove rolled-back retained fork checkpoint");
            rollback_errors.push(format!(
                "retained-checkpoint cleanup failed: {remove_error}"
            ));
        }
    }
    if let Err(remove_error) = std::fs::remove_dir_all(snapshot_dir) {
        tracing::warn!(path = %snapshot_dir.display(), %remove_error, "failed to remove rolled-back fork snapshot");
        if remove_error.kind() != std::io::ErrorKind::NotFound {
            rollback_errors.push(format!("snapshot cleanup failed: {remove_error}"));
        }
    }
    if rollback_errors.is_empty() {
        Ok(())
    } else {
        Err(Error::agent("fork rollback", rollback_errors.join("; ")))
    }
}

fn rollback_new_snapshot(
    db: &SmolvmDb,
    golden: &str,
    snapshot_dir: &Path,
    persisted: bool,
    error: Error,
) -> Error {
    match rollback_retained_fork_snapshot(db, golden, snapshot_dir, persisted) {
        Ok(()) => error,
        Err(rollback_error) => Error::agent("fork", format!("{error}; {rollback_error}")),
    }
}

fn reusable_snapshot_path(snapshot_root: &Path, snapshot: &Path) -> bool {
    snapshot.parent() == Some(snapshot_root)
        && snapshot
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.len() == 8 && name.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or(false)
        && snapshot
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_dir())
            .unwrap_or(false)
}

fn retained_snapshot_is_reusable(
    golden: &VmRecord,
    golden_was_paused: bool,
    snapshot_root: &Path,
    snapshot: &RetainedForkSnapshot,
) -> bool {
    golden_was_paused && retained_snapshot_matches_golden(golden, snapshot_root, snapshot)
}

/// Return whether a retained checkpoint belongs to the exact live golden
/// process recorded in the registry and still occupies an owned snapshot path.
/// State probing uses this to recognize a deliberately paused fork base even
/// between pool fills, when it temporarily has no dependent clone rows.
pub(crate) fn retained_snapshot_matches_golden(
    golden: &VmRecord,
    snapshot_root: &Path,
    snapshot: &RetainedForkSnapshot,
) -> bool {
    golden.pid == Some(snapshot.golden_pid)
        && golden.pid_start_time == Some(snapshot.golden_pid_start_time)
        && reusable_snapshot_path(snapshot_root, &snapshot.path)
}

fn prepare_clone_from_snapshot(
    db: &SmolvmDb,
    golden: &str,
    golden_rec: &VmRecord,
    golden_dir: &Path,
    snapshot_dir: &Path,
    spec: &ForkSpec<'_>,
    reserved_ports: &mut HashSet<u16>,
) -> Result<PreparedFork> {
    let clone = spec.clone;
    let clone_dir = vm_data_dir(clone);
    let result = (|| {
        if clone_dir.exists() {
            std::fs::remove_dir_all(&clone_dir)
                .map_err(|e| Error::agent("clear orphan clone dir", e.to_string()))?;
        }
        std::fs::create_dir_all(&clone_dir)
            .map_err(|e| Error::agent("create clone dir", e.to_string()))?;

        let golden_layers = crate::agent::machine_layers_cache_dir(golden);
        #[cfg(target_os = "linux")]
        {
            let clone_layers = crate::agent::machine_layers_cache_dir(clone);
            let copied_shared_lease =
                crate::artifact_cache::copy_shared_pack_lease(&golden_layers, &clone_layers)
                    .map_err(|e| Error::agent("copy shared pack lease", e.to_string()))?;
            if copied_shared_lease.is_none() && smolvm_pack::extract::is_extracted(&golden_layers) {
                std::os::unix::fs::symlink(&golden_layers, &clone_layers)
                    .map_err(|e| Error::agent("link clone pack dir", e.to_string()))?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        if smolvm_pack::extract::is_extracted(&golden_layers) {
            #[cfg(unix)]
            {
                let clone_layers = crate::agent::machine_layers_cache_dir(clone);
                std::os::unix::fs::symlink(&golden_layers, &clone_layers)
                    .map_err(|e| Error::agent("link clone pack dir", e.to_string()))?;
            }
        }

        let mut clone_rec = golden_rec.clone();
        clone_rec.name = clone.to_string();
        clone_rec.pid = None;
        clone_rec.pid_start_time = None;
        if !spec.fork_env.is_empty() {
            clone_rec
                .env
                .retain(|(k, _)| !spec.fork_env.iter().any(|(fk, _)| fk == k));
            clone_rec.env.extend(spec.fork_env.iter().cloned());
        }
        for (key, secret) in spec.fork_secrets {
            clone_rec.secret_refs.insert(key.clone(), secret.clone());
        }

        let mut port_remaps = Vec::new();
        if !spec.pinned_ports.is_empty() {
            clone_rec.ports = spec.pinned_ports.to_vec();
            for (host, guest) in &clone_rec.ports {
                port_remaps.push((*host, *guest, *host));
            }
        } else if !clone_rec.ports.is_empty() {
            let mut remapped = Vec::with_capacity(clone_rec.ports.len());
            for (golden_host, guest) in &clone_rec.ports {
                match alloc_free_host_port_excluding(reserved_ports) {
                    Some(host) => {
                        port_remaps.push((*golden_host, *guest, host));
                        remapped.push((host, *guest));
                    }
                    None => tracing::warn!(
                        guest,
                        "could not allocate a host port for fork clone; dropping forward"
                    ),
                }
            }
            clone_rec.ports = remapped;
        }
        clone_rec.golden = Some(golden.to_string());
        // Clones are leaf machines. Do not inherit a Smolfile-declared
        // forkable launch default from the golden on later cold starts.
        clone_rec.forkable = spec.clone_forkable;
        clone_rec.forkpoint_held = spec.hold;
        clone_rec.fork_env = spec.fork_env.to_vec();
        db.insert_vm(clone, &clone_rec)?;

        let t_disk = std::time::Instant::now();
        clone_fork_disks(golden_dir, &clone_dir)?;
        tracing::info!(
            clone,
            elapsed_ms = t_disk.elapsed().as_millis() as u64,
            "fork: clone disk overlays created"
        );
        Ok(PreparedFork {
            snapshot_dir: snapshot_dir.to_path_buf(),
            clone_record: clone_rec,
            port_remaps,
            resume_golden_on_rollback: true,
        })
    })();

    if result.is_err() {
        let _ = db.remove_vm(clone);
        let _ = std::fs::remove_dir_all(&clone_dir);
    }
    result
}

/// Give the clone its own disks. The golden is frozen with its block workers
/// quiesced and flushed, so its images are a consistent backing. On Linux each
/// disk is a qcow2 copy-on-write overlay over the golden's — filesystem
/// independent, so the overlay starts near-empty and the fork is O(metadata)
/// regardless of how much data the golden holds. macOS clonefiles the disks
/// (APFS CoW). Either way the `.formatted` marker is copied so the clone never
/// reformats and wipes the inherited filesystem.
fn clone_fork_disks(gdir: &Path, clone_dir: &Path) -> Result<()> {
    // The golden's actual disks that exist, resolved by file presence (`.qcow2`
    // if the golden is itself a clone, else `.raw`) — the same single source of
    // truth the agent manager uses. Each entry pairs the canonical `.raw`
    // filename (for naming the clone's disk) with the golden's real backing file
    // and its format.
    let disks: Vec<(&str, PathBuf, crate::data::disk::DiskFormat)> = [
        crate::data::storage::STORAGE_DISK_FILENAME,
        crate::data::storage::OVERLAY_DISK_FILENAME,
    ]
    .into_iter()
    .map(|raw| {
        let (src, fmt) = resolve_disk_image(gdir, raw);
        (raw, src, fmt)
    })
    .filter(|(_, src, _)| src.exists())
    .collect();

    #[cfg(target_os = "linux")]
    {
        // Each clone disk is a qcow2 CoW overlay over the golden's disk. Build
        // all overlay specs first so libkrun is loaded once for the batch
        // (absolute backing path: it's written verbatim into the overlay
        // header), then copy the `.formatted` markers so the clone never
        // reformats and wipes the inherited filesystem.
        let mut specs = Vec::with_capacity(disks.len());
        for (raw, src, fmt) in &disks {
            let base = src
                .canonicalize()
                .map_err(|e| Error::agent("clone disk", format!("{}: {e}", src.display())))?;
            let overlay = clone_dir.join(Path::new(raw).with_extension("qcow2"));
            specs.push((overlay, base, *fmt));
        }
        crate::agent::create_disk_overlays(&specs)?;
        for (raw, _, _) in &disks {
            // Marker basename is the disk stem + ".formatted" (same for the
            // golden's `.raw`/`.qcow2` and the clone's `.qcow2`).
            let marker = Path::new(raw).with_extension("formatted");
            let src_marker = gdir.join(&marker);
            if src_marker.exists() {
                let _ = std::fs::copy(&src_marker, clone_dir.join(&marker));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS uses clonefile (APFS CoW), keeping the golden's disk format.
        for (_, src, _) in &disks {
            let dst = clone_dir.join(src.file_name().unwrap());
            crate::disk_utils::clone_or_copy_file(src, &dst)
                .map_err(|e| Error::agent("clone disk", format!("{}: {e}", src.display())))?;
            let src_marker = src.with_extension("formatted");
            if src_marker.exists() {
                let _ = std::fs::copy(&src_marker, dst.with_extension("formatted"));
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fork-clone disk overlays rely on libkrun's qcow2 overlay (Linux) or
        // APFS clonefile (macOS); neither is wired up on Windows.
        let _ = (&disks, clone_dir);
        return Err(Error::agent(
            "clone disk",
            "live fork is not supported on this platform",
        ));
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Number of times we try to confirm a clone's identity rejuvenation before
/// giving up and failing the fork. `connect_with_retry` already rides out the
/// agent's boot; these extra attempts cover a momentarily-busy agent whose
/// `vm_exec` errors or exits non-zero transiently.
const REJUVENATE_ATTEMPTS: usize = 3;

/// Build the shell script that re-mints a clone's on-disk identity. Kept as a
/// pure function of `(clone, seed)` so the security-critical contents (fresh
/// machine-id, regenerated SSH host keys) are unit-tested without a live VM.
///
/// `clone` is a validated machine name (alphanumeric + dashes) and `seed` is
/// hex, so single-quoting both is injection-safe.
///
/// NOTE: this deliberately does NOT touch `/storage/overlays`. The clone's
/// inherited exec overlay stays under the GOLDEN's id and the restored guest
/// may still hold it mounted (or have a restored workload container running
/// from it) — renaming it on disk poisons that live overlayfs mount (ESTALE
/// in every subsequent container exec). Hosts alias the overlay lookup
/// instead (`crate::workload::persistent_overlay_owner`).
///
/// The script is fail-hard on the *unambiguously per-machine* identity material
/// (`set -e`): if a clone cannot get its own machine-id or SSH host keys, the
/// fork must fail rather than vend a clone that impersonates the golden. Steps
/// that are legitimately absent on minimal/library images (no sshd, no dbus,
/// no cloud-init) are guarded so they no-op instead of failing.
fn build_rejuvenation_script(clone: &str, seed: &str, record: &VmRecord) -> String {
    // An image machine's identity files live in the workload container's
    // rootfs, NOT the VM rootfs the agent execs in — writing them unprefixed
    // strands them where no workload will ever read them, leaving the clone on
    // the golden's SSH host keys. Reach the container through its overlayfs
    // `merged` mount, exactly as [`write_fork_env`] does and for the same
    // reason: a container exec would recycle the workload the fork just
    // restored. A bare VM (no image) keeps the plain VM-rootfs paths.
    let (root, require_root) = match record.image {
        Some(_) => {
            let owner = crate::workload::persistent_overlay_owner(clone, record.golden.as_deref());
            let merged = format!("/storage/overlays/persistent-{owner}/merged");
            let require = format!(
                "if [ ! -d {merged} ]; then echo \"missing {merged}; overlays:\" >&2; \
                 ls /storage/overlays >&2; exit 41; fi; "
            );
            (merged, require)
        }
        None => (String::new(), String::new()),
    };
    // `ssh-keygen -A` writes to a hardcoded /etc/ssh, so regenerating the
    // container's keys means running the container's own binary under chroot.
    // Both tools are probed by absolute path: the agent's exec PATH does not
    // necessarily carry /usr/sbin, and a bare `command -v chroot` that misses
    // aborts the script under `set -e` — after the old keys are already gone.
    //
    // The chroot also needs device nodes: the workload's /dev is a tmpfs mounted
    // inside the container's mount namespace, so from the agent's namespace the
    // merged rootfs has an empty /dev and `ssh-keygen` finds no entropy source.
    // Nodes this creates are removed again; the container's own /dev tmpfs hides
    // them from the workload either way.
    //
    // Availability is checked BEFORE anything is deleted so that an
    // unsatisfiable clone fails the same way on every retry. Otherwise attempt
    // one removes the keys, fails, and attempt two finds no keys to rotate and
    // reports success — laundering the failure the retry loop exists to catch.
    let ssh_block = if root.is_empty() {
        "if ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
             KG=''; for k in /usr/bin/ssh-keygen /bin/ssh-keygen /usr/local/bin/ssh-keygen; do \
                 if [ -x \"$k\" ]; then KG=\"$k\"; break; fi; \
             done; \
             if [ -z \"$KG\" ]; then echo 'no ssh-keygen to rotate the host keys' >&2; exit 42; fi; \
             rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub; \
             \"$KG\" -A >/dev/null 2>&1 || true; \
             if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
                 echo 'host key rotation produced no keys' >&2; exit 42; \
             fi; \
         fi"
            .to_string()
    } else {
        format!(
            "if ls {root}/etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
                 CH=''; for c in /usr/sbin/chroot /sbin/chroot /usr/bin/chroot; do \
                     if [ -x \"$c\" ]; then CH=\"$c\"; break; fi; \
                 done; \
                 KG=''; for k in /usr/bin/ssh-keygen /bin/ssh-keygen /usr/local/bin/ssh-keygen; do \
                     if [ -x {root}\"$k\" ]; then KG=\"$k\"; break; fi; \
                 done; \
                 if [ -z \"$CH\" ] || [ -z \"$KG\" ]; then \
                     echo 'no chroot/ssh-keygen to rotate the workload host keys' >&2; exit 42; \
                 fi; \
                 rm -f {root}/etc/ssh/ssh_host_*_key {root}/etc/ssh/ssh_host_*_key.pub; \
                 MADE=''; mkdir -p {root}/dev; \
                 for d in 'urandom c 1 9' 'random c 1 8' 'null c 1 3'; do \
                     set -- $d; \
                     if [ ! -e {root}/dev/$1 ] && mknod -m 666 {root}/dev/$1 $2 $3 $4 2>/dev/null; then \
                         MADE=\"$MADE {root}/dev/$1\"; \
                     fi; \
                 done; \
                 \"$CH\" {root} \"$KG\" -A >/dev/null 2>&1 || true; \
                 if [ -n \"$MADE\" ]; then rm -f $MADE; fi; \
                 if ! ls {root}/etc/ssh/ssh_host_*_key >/dev/null 2>&1; then \
                     echo 'host key rotation produced no keys' >&2; exit 42; \
                 fi; \
             fi"
        )
    };
    format!(
        "set -e; \
         {require_root}\
         hostname '{c}' 2>/dev/null || true; \
         printf '%s\\n' '{c}' > {root}/etc/hostname; \
         tr -d '-' < /proc/sys/kernel/random/uuid > {root}/etc/machine-id; \
         if [ -f {root}/var/lib/dbus/machine-id ] && [ ! -L {root}/var/lib/dbus/machine-id ]; then \
             tr -d '-' < /proc/sys/kernel/random/uuid > {root}/var/lib/dbus/machine-id; \
         fi; \
         {ssh_block}; \
         rm -rf {root}/var/lib/cloud/instance {root}/var/lib/cloud/instances/* {root}/var/lib/cloud/data/instance-id 2>/dev/null || true; \
         printf '%s' '{s}' > /dev/urandom 2>/dev/null || true; \
         umask 077; \
         mkdir -p '{state_dir}'; \
         printf '%s\n' smolvm-forkpoint-restored-v1 > '{restored}'; \
         true",
        c = clone,
        s = seed,
        state_dir = smolvm_protocol::forkpoint::STATE_DIR,
        restored = smolvm_protocol::forkpoint::RESTORED_PATH,
    )
}

/// Per-clone identity rejuvenation after a fork. A fork CoW-clones the golden's
/// disks wholesale, so every per-machine on-disk secret (machine-id, SSH host
/// keys, dbus id, cloud-init instance state) is byte-identical in the clone —
/// and clones can belong to *different tenants*. Left unchanged, that is a
/// cross-tenant impersonation / MITM hole (identical SSH host keys) and a
/// duplicate-identity bug. This runs over the freshly-booted clone's agent to
/// give it a fresh hostname, machine-id, SSH host keys, and to stir the kernel
/// RNG with fresh host entropy so the random streams diverge.
///
/// FAIL-CLOSED: this returns `Err` if the reset could not be *confirmed* (agent
/// unreachable, or the re-mint script exited non-zero) after
/// [`REJUVENATE_ATTEMPTS`] tries. Callers MUST treat that as a fork failure and
/// tear the clone down — a clone that still carries the golden's identity must
/// never be vended (see [`fail_closed_on_rejuvenation`]).
///
/// RESIDUAL LIMITATION (out of scope, intentional): this rejuvenates only
/// *on-disk* identity. It cannot scrub the golden's *in-RAM* secrets — a
/// session token, JWT, or TLS private key held in a golden-resident process's
/// memory is CoW-inherited identically by every clone. That is intrinsic to
/// fork-from-warm and is not fixable here; the mitigation is a product
/// constraint (goldens must be prepacked library base images that mint no
/// per-instance boot secrets in RAM, and/or restart key daemons post-fork), not
/// disk rejuvenation. Likewise this stirs but does not *credit* entropy
/// (no `RNDADDENTROPY`/VMGENID yet) and does not re-address the network
/// (MAC/IP; safe under the default TSI backend) — both are follow-ups.
pub fn rejuvenate_clone(clone: &str, record: &VmRecord) -> Result<()> {
    let sock = vm_data_dir(clone).join("agent.sock");
    let seed = host_random_hex(64);
    let script = build_rejuvenation_script(clone, &seed, record);

    let mut last_err = String::from("unknown error");
    for attempt in 1..=REJUVENATE_ATTEMPTS {
        match rejuvenate_once(&sock, &script) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(
                    clone,
                    attempt,
                    error = %e,
                    "clone rejuvenation attempt failed"
                );
                last_err = e;
                if attempt < REJUVENATE_ATTEMPTS {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }
    Err(Error::agent(
        "rejuvenate clone",
        format!(
            "identity reset could not be confirmed after {REJUVENATE_ATTEMPTS} attempts: {last_err}"
        ),
    ))
}

/// One attempt: connect to the clone's agent and run the re-mint script. Any
/// connect error, exec error, or non-zero exit is a failure (fail-closed).
fn rejuvenate_once(sock: &Path, script: &str) -> std::result::Result<(), String> {
    let mut client =
        AgentClient::connect_with_retry(sock).map_err(|e| format!("agent connect: {e}"))?;
    match client.vm_exec(
        vec!["/bin/sh".into(), "-c".into(), script.to_string()],
        vec![],
        None,
        Some(std::time::Duration::from_secs(10)),
        None,
    ) {
        Ok((0, _, _)) => Ok(()),
        Ok((code, _, stderr)) => Err(format!(
            "re-mint script exited {code}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )),
        Err(e) => Err(format!("exec: {e}")),
    }
}

/// Guest path of the per-fork parameter file, dotenv format (`KEY=VALUE`
/// lines). A forked clone's workload resumed mid-flight from the golden's
/// snapshot, so its process env cannot carry per-clone values — sweep and
/// rollout workloads read this file instead (typically after their GO gate).
///
/// Lives under `/etc` (the workload container's overlay filesystem), NOT
/// `/run`: `/run` is a per-container-instance tmpfs, so a file there vanishes
/// if the restored container is recycled — the overlay is the only surface
/// shared by every instance and the running workload alike.
pub const FORK_ENV_GUEST_PATH: &str = smolvm_protocol::forkpoint::FORK_ENV_PATH;

/// Validate per-fork parameters: keys must be non-empty `[A-Za-z_][A-Za-z0-9_]*`
/// (they double as env var names for exec sessions) and values must be free of
/// newlines (one `KEY=VALUE` per line in the delivered file).
pub fn validate_fork_env(env: &[(String, String)]) -> Result<()> {
    for (k, v) in env {
        let mut chars = k.chars();
        let head_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !head_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(Error::config(
                "fork env",
                format!("invalid key '{k}': must match [A-Za-z_][A-Za-z0-9_]*"),
            ));
        }
        if v.contains('\n') || v.contains('\r') {
            return Err(Error::config(
                "fork env",
                format!("value for '{k}' must not contain newlines"),
            ));
        }
    }
    Ok(())
}

/// Render per-fork parameters as the dotenv file content.
pub fn render_fork_env(env: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in env {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    out
}

/// Merge assignment-time parameters into a held slot's initial fork
/// parameters. Later values replace same-named earlier values while preserving
/// stable ordering for every untouched entry.
pub fn merge_fork_env(
    initial: &[(String, String)],
    assignment: &[(String, String)],
) -> Vec<(String, String)> {
    let mut merged = initial.to_vec();
    for (key, value) in assignment {
        merged.retain(|(existing, _)| existing != key);
        merged.push((key.clone(), value.clone()));
    }
    merged
}

/// Persist the state transition after a held slot has been released
/// successfully. Kept in one shared helper so the CLI and HTTP API cannot
/// disagree about the one-shot flag or assignment environment.
pub fn record_fork_activation(
    record: &mut VmRecord,
    assignment: &[(String, String)],
    merged: Vec<(String, String)>,
) {
    let assignment_keys: HashSet<&str> = assignment.iter().map(|(key, _)| key.as_str()).collect();
    record.forkpoint_held = false;
    record.fork_env = merged;
    record
        .env
        .retain(|(key, _)| !assignment_keys.contains(key.as_str()));
    record.env.extend(assignment.iter().cloned());
}

/// Deliver per-fork parameters into a freshly-booted clone at
/// [`FORK_ENV_GUEST_PATH`], via a VM-namespace write THROUGH the workload
/// container's overlayfs `merged` mount. Deliberately not a container exec:
/// the restored workload container can look stale to the exec path right
/// after a fork, and exec'ing would recycle it — killing the very workload
/// that is waiting for these parameters. Writing through the merged mount
/// reaches the running container's rootfs without touching the container
/// runtime at all. Bare VMs (no image) get the file in the VM rootfs.
///
/// FAIL-CLOSED by the caller: if the user asked for parameters and they can't
/// be delivered, the fork must fail rather than vend a clone that silently
/// runs with the golden's (or a sibling's) parameters.
pub fn write_fork_env(clone: &str, record: &VmRecord, env: &[(String, String)]) -> Result<()> {
    if env.is_empty() {
        return Ok(());
    }
    let content = render_fork_env(env);
    // Overlay owner is a validated machine name (alphanumeric + dashes), so
    // splicing it into the script is injection-safe — same contract as the
    // rejuvenation script's clone name.
    let owner = crate::workload::persistent_overlay_owner(clone, record.golden.as_deref());
    let merged = format!("/storage/overlays/persistent-{owner}/merged");
    // Image machines MUST land the file in the workload container's rootfs
    // (the overlay merged dir): falling through silently would strand it in
    // the agent rootfs where no workload will ever look. Fail with the actual
    // overlay listing so a layout change is diagnosable, not silent.
    let script = if record.image.is_some() {
        format!(
            "if [ ! -d {merged} ]; then echo \"missing {merged}; overlays:\" >&2; \
             ls /storage/overlays >&2; exit 41; fi; \
             mkdir -p {merged}/etc/smolvm && umask 077 && cat > {merged}{FORK_ENV_GUEST_PATH}"
        )
    } else {
        format!("mkdir -p /etc/smolvm && umask 077 && cat > {FORK_ENV_GUEST_PATH}")
    };
    let sock = vm_data_dir(clone).join("agent.sock");
    let mut client = AgentClient::connect_with_retry(&sock)
        .map_err(|e| Error::agent("fork env: agent connect", e.to_string()))?;
    match client.vm_exec(
        vec!["/bin/sh".into(), "-c".into(), script],
        vec![],
        None,
        Some(std::time::Duration::from_secs(10)),
        Some(content),
    ) {
        Ok((0, _, _)) => Ok(()),
        Ok((code, _, stderr)) => Err(Error::agent(
            "fork env",
            format!(
                "write exited {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        )),
        Err(e) => Err(Error::agent("fork env", format!("vm exec: {e}"))),
    }
}

/// Assign and release one clean, already-booted fork-pool slot.
///
/// The guest performs the state check, fork-env replacement, and release-marker
/// publication in one agent exec. A slot can therefore be released only once;
/// a completed training worker is never reset or reused with dirty optimizer,
/// RNG, allocator, or dataset state. Callers replenish the pool by deleting the
/// consumed clone and forking a fresh held slot from its still-frozen golden.
///
/// Returns the complete merged fork parameter set that the caller should
/// persist after success.
pub fn activate_held_fork(
    clone: &str,
    record: &VmRecord,
    assignment: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    validate_fork_env(assignment)?;
    let merged = merge_fork_env(&record.fork_env, assignment);
    let content = render_fork_env(&merged);
    let owner = crate::workload::persistent_overlay_owner(clone, record.golden.as_deref());
    let merged_root = format!("/storage/overlays/persistent-{owner}/merged");
    let env_path = if record.image.is_some() {
        format!("{merged_root}{FORK_ENV_GUEST_PATH}")
    } else {
        FORK_ENV_GUEST_PATH.to_string()
    };
    let ensure_env_parent = if record.image.is_some() {
        format!(
            "if [ ! -d '{merged_root}' ]; then echo 'missing {merged_root}' >&2; exit 41; fi; \
             mkdir -p '{merged_root}/etc/smolvm'"
        )
    } else {
        "mkdir -p /etc/smolvm".to_string()
    };
    // The token makes this operation safe to repeat after an ambiguous socket
    // timeout. A release can wake a CUDA-heavy workload before the guest agent's
    // reply reaches the host; without an idempotency receipt, retrying could vend
    // the same clean slot twice while failing immediately could discard a slot
    // that was actually released successfully.
    let activation_token = format!(
        "{}{}",
        crate::util::generate_short_id(),
        crate::util::generate_short_id()
    );
    let receipt = format!("{}/activation", smolvm_protocol::forkpoint::STATE_DIR);
    let script = build_activation_script(
        smolvm_protocol::forkpoint::READY_PATH,
        smolvm_protocol::forkpoint::RELEASE_PATH,
        smolvm_protocol::forkpoint::WORKER_READY_PATH,
        &receipt,
        &ensure_env_parent,
        &env_path,
        &activation_token,
    );
    let socket = vm_data_dir(clone).join("agent.sock");
    for attempt in 1..=2 {
        let mut client = match AgentClient::connect_with_retry(&socket) {
            Ok(client) => client,
            Err(error) if attempt == 1 => {
                tracing::warn!(
                    clone,
                    %error,
                    "held-fork activation connect was ambiguous; retrying idempotently"
                );
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("agent connect: {error}"),
                ));
            }
        };
        match client.vm_exec(
            vec!["/bin/sh".into(), "-c".into(), script.clone()],
            vec![],
            None,
            Some(Duration::from_secs(10)),
            Some(content.clone()),
        ) {
            Ok((0, _, _)) => return Ok(merged),
            Ok((42, _, _)) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("clone '{clone}' was already released"),
                ));
            }
            Ok((43, _, _)) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("clone '{clone}' is not parked at a forkpoint"),
                ));
            }
            Ok((code, _, stderr)) if attempt == 1 => {
                tracing::warn!(
                    clone,
                    code,
                    stderr = %String::from_utf8_lossy(&stderr).trim(),
                    "held-fork activation attempt failed; retrying idempotently"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok((code, _, stderr)) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!(
                        "clone '{clone}' activation exited {code}: {}",
                        String::from_utf8_lossy(&stderr).trim()
                    ),
                ));
            }
            Err(error) if attempt == 1 => {
                tracing::warn!(
                    clone,
                    %error,
                    "held-fork activation reply was ambiguous; retrying idempotently"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(Error::agent(
                    "activate held fork",
                    format!("clone '{clone}': {error}"),
                ));
            }
        }
    }
    unreachable!("held-fork activation loop always returns")
}

const WORKER_READY_TRANSPORT_MARGIN: Duration = Duration::from_secs(30);

fn worker_ready_command_timeout(timeout: Duration) -> Result<Duration> {
    timeout
        .checked_add(WORKER_READY_TRANSPORT_MARGIN)
        .ok_or_else(|| Error::config("worker readiness", "timeout is too large"))
}

/// Wait until a released workload proves that clone-local preparation finished.
pub fn wait_for_worker_ready(clone: &str, token: &str, timeout: Duration) -> Result<()> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::config(
            "worker readiness",
            "token must contain exactly 64 hexadecimal characters",
        ));
    }
    if timeout.is_zero() {
        return Err(Error::config(
            "worker readiness",
            "timeout must be positive",
        ));
    }
    let polls = timeout
        .as_secs()
        .checked_mul(10)
        .ok_or_else(|| Error::config("worker readiness", "timeout is too large"))?;
    let script = build_worker_ready_wait_script(smolvm_protocol::forkpoint::WORKER_READY_PATH);
    let socket = vm_data_dir(clone).join("agent.sock");
    let mut client = AgentClient::connect_with_retry(&socket)
        .map_err(|error| Error::agent("wait for worker readiness", error.to_string()))?;
    if !client
        .supports_capability(smolvm_protocol::forkpoint::WORKER_READY_CAPABILITY)
        .map_err(|error| Error::agent("check worker readiness capability", error.to_string()))?
    {
        return Err(Error::agent(
            "wait for worker readiness",
            format!(
                "clone '{clone}' uses an incompatible guest agent without the worker-readiness capability; rebuild the agent rootfs or remove the stale SMOLVM_AGENT_ROOTFS override"
            ),
        ));
    }
    let command = vec![
        "/bin/sh".into(),
        "-c".into(),
        script,
        "smolvm-worker-ready-wait".into(),
        token.to_ascii_lowercase(),
        polls.to_string(),
    ];
    // The guest poll loop launches `sleep` on every iteration, so its elapsed
    // wall time can exceed the nominal polling window under CPU contention.
    // Keep this transport deadline within the controller's reserved activation
    // grace while allowing the script to report its specific timeout code.
    let command_timeout = worker_ready_command_timeout(timeout)?;
    match client.vm_exec(command, vec![], None, Some(command_timeout), None) {
        Ok((0, _, _)) => Ok(()),
        Ok((44, _, _)) => Err(Error::agent(
            "wait for worker readiness",
            format!(
                "clone '{clone}' did not signal readiness within {} seconds",
                timeout.as_secs()
            ),
        )),
        Ok((45, _, _)) => Err(Error::agent(
            "wait for worker readiness",
            format!("clone '{clone}' published a stale or invalid readiness token"),
        )),
        Ok((code, _, stderr)) => Err(Error::agent(
            "wait for worker readiness",
            format!(
                "clone '{clone}' readiness wait exited {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        )),
        Err(error) => Err(Error::agent(
            "wait for worker readiness",
            format!("clone '{clone}': {error}"),
        )),
    }
}

fn build_worker_ready_wait_script(worker_ready: &str) -> String {
    format!(
        "set -e; i=0; while [ \"$i\" -lt \"$2\" ]; do \
         if [ -f '{worker_ready}' ]; then \
           [ \"$(cat '{worker_ready}')\" = \"$1\" ] && exit 0; exit 45; \
         fi; \
         i=$((i + 1)); sleep 0.1; \
         done; exit 44"
    )
}

fn build_activation_script(
    ready: &str,
    release: &str,
    worker_ready: &str,
    receipt: &str,
    ensure_env_parent: &str,
    env_path: &str,
    activation_token: &str,
) -> String {
    format!(
        "set -e; \
         if [ -f '{release}' ]; then \
           [ \"$(cat '{receipt}' 2>/dev/null)\" = '{activation_token}' ] && exit 0; \
           exit 42; \
         fi; \
         if [ ! -f '{ready}' ]; then exit 43; fi; \
         rm -f '{worker_ready}'; \
         receipt_tmp='{receipt}.{activation_token}.'$$; \
         printf '%s\\n' '{activation_token}' > \"$receipt_tmp\"; \
         if ! ln \"$receipt_tmp\" '{receipt}' 2>/dev/null; then \
           rm -f \"$receipt_tmp\"; \
           [ \"$(cat '{receipt}' 2>/dev/null)\" = '{activation_token}' ] || exit 42; \
         else rm -f \"$receipt_tmp\"; fi; \
         {ensure_env_parent}; umask 077; \
         env_tmp='{env_path}.{activation_token}.'$$; \
         release_tmp='{release}.{activation_token}.'$$; \
         trap 'rm -f \"$env_tmp\" \"$release_tmp\"' EXIT; \
         cat > \"$env_tmp\"; mv \"$env_tmp\" '{env_path}'; \
         printf '%s\\n' smolvm-forkpoint-release-v1 > \"$release_tmp\"; \
         mv \"$release_tmp\" '{release}'"
    )
}

/// Fail-closed fork finalizer. A clone whose identity could not be rejuvenated
/// MUST NOT be vended (it would share the golden's machine-id/hostname/SSH host
/// keys across tenants), so on any rejuvenation `Err` this runs `teardown`
/// (stop + remove the clone) and propagates the error, turning a rejuvenation
/// failure into a fork failure. On `Ok` it does nothing and the caller proceeds
/// to mark the clone ready. Extracted as a pure decision so the fail-closed
/// behavior is unit-tested independently of the VM/agent machinery.
pub fn fail_closed_on_rejuvenation<F: FnOnce()>(
    rejuvenation: Result<()>,
    teardown: F,
) -> Result<()> {
    match rejuvenation {
        Ok(()) => Ok(()),
        Err(e) => {
            teardown();
            Err(e)
        }
    }
}

/// Allocate a currently-free host TCP port by binding to port 0 and reading back
/// the OS-assigned port. Used to give each clone distinct inbound forwards.
fn alloc_free_host_port() -> Option<u16> {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|addr| addr.port())
}

fn alloc_free_host_port_excluding(reserved: &mut HashSet<u16>) -> Option<u16> {
    for _ in 0..128 {
        let port = alloc_free_host_port()?;
        if reserved.insert(port) {
            return Some(port);
        }
    }
    None
}

/// Read `hex_len/2` random bytes from the host RNG, hex-encoded. Used to seed
/// each clone's RNG with distinct host entropy.
fn host_random_hex(hex_len: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; hex_len / 2];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Per-fork parameters double as env var names and dotenv file lines, so
    // keys must be valid identifiers and values single-line — anything else
    // must be rejected up front, before the golden is frozen.
    #[test]
    fn fork_env_validation_accepts_identifiers_and_rejects_junk() {
        let ok = vec![
            ("LR".to_string(), "3e-4".to_string()),
            ("_SEED".to_string(), "42".to_string()),
            (
                "TASK_2".to_string(),
                "spaces and = are fine in values".to_string(),
            ),
        ];
        assert!(validate_fork_env(&ok).is_ok());

        for (k, v) in [
            ("2LR", "x"),
            ("", "x"),
            ("A-B", "x"),
            ("K", "line1\nline2"),
            ("K", "cr\rvalue"),
        ] {
            assert!(
                validate_fork_env(&[(k.to_string(), v.to_string())]).is_err(),
                "expected rejection for key={k:?} value={v:?}"
            );
        }
    }

    #[test]
    fn paused_golden_reuses_the_proven_forkpoint_for_refill() {
        assert!(fork_base_already_paused("OK paused\n"));
        assert!(!fork_base_already_paused("OK running\n"));
        assert!(!fork_base_already_paused("ERR not forkable\n"));
    }

    #[test]
    fn golden_rollback_reapplies_a_completed_checkpoint_only() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(golden_resume_command(temp.path()).unwrap(), "RESUME");

        std::fs::write(temp.path().join("checkpoint.bin"), b"checkpoint").unwrap();
        assert_eq!(
            golden_resume_command(temp.path()).unwrap(),
            format!("ROLLBACK_FORK {}", temp.path().display())
        );

        std::fs::remove_file(temp.path().join("checkpoint.bin")).unwrap();
        std::fs::create_dir(temp.path().join("checkpoint.bin")).unwrap();
        assert!(golden_resume_command(temp.path()).is_err());
    }

    #[test]
    fn golden_rollback_refuses_to_invalidate_a_live_clones_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("test.db")).unwrap();
        let golden = VmRecord::new("golden".into(), 2, 1024, vec![], vec![], false);
        db.insert_vm("golden", &golden).unwrap();
        let mut clone = VmRecord::new("clone".into(), 2, 1024, vec![], vec![], false);
        clone.golden = Some("golden".into());
        db.insert_vm("clone", &clone).unwrap();
        let snapshot = temp.path().join("snapshot");
        std::fs::create_dir(&snapshot).unwrap();

        let error = rollback_retained_fork_snapshot(&db, "golden", &snapshot, true)
            .expect_err("a live clone must keep its checkpoint");

        assert!(error.to_string().contains("1 live clone(s)"));
        assert!(snapshot.exists());
    }

    #[test]
    fn forkpoint_profile_parses_optional_cuda_preload_hint() {
        assert_eq!(
            parse_forkpoint_profile(b"smolvm-forkpoint-v1\n"),
            ForkpointProfile::default()
        );
        assert!(
            parse_forkpoint_profile(b"smolvm-forkpoint-v1\ncuda-preload-modules\n")
                .cuda_preload_modules
        );
        assert!(!parse_forkpoint_profile(b"cuda-preload-modules-extra\n").cuda_preload_modules);
    }

    #[test]
    fn retained_snapshot_requires_the_same_paused_golden_process() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_root = temp.path().join("s");
        let snapshot_path = snapshot_root.join("a1b2c3d4");
        std::fs::create_dir_all(&snapshot_path).unwrap();
        let snapshot = RetainedForkSnapshot {
            path: snapshot_path,
            golden_pid: 123,
            golden_pid_start_time: 456,
        };
        let mut golden = VmRecord::new("golden".into(), 2, 1024, vec![], vec![], false);
        golden.pid = Some(123);
        golden.pid_start_time = Some(456);

        assert!(retained_snapshot_is_reusable(
            &golden,
            true,
            &snapshot_root,
            &snapshot
        ));
        assert!(retained_snapshot_matches_golden(
            &golden,
            &snapshot_root,
            &snapshot
        ));
        assert!(!retained_snapshot_is_reusable(
            &golden,
            false,
            &snapshot_root,
            &snapshot
        ));
        golden.pid_start_time = Some(457);
        assert!(!retained_snapshot_matches_golden(
            &golden,
            &snapshot_root,
            &snapshot
        ));
        assert!(!retained_snapshot_is_reusable(
            &golden,
            true,
            &snapshot_root,
            &snapshot
        ));
    }

    #[test]
    fn retained_snapshot_path_must_be_a_direct_real_checkpoint_directory() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot_root = temp.path().join("s");
        std::fs::create_dir_all(&snapshot_root).unwrap();
        let valid = snapshot_root.join("0123abcd");
        std::fs::create_dir(&valid).unwrap();

        assert!(reusable_snapshot_path(&snapshot_root, &valid));
        assert!(!reusable_snapshot_path(
            &snapshot_root,
            &snapshot_root.join("short")
        ));
        assert!(!reusable_snapshot_path(
            &snapshot_root,
            &temp.path().join("0123abcd")
        ));
    }

    #[test]
    fn fork_env_renders_one_pair_per_line() {
        let env = vec![
            ("LR".to_string(), "3e-4".to_string()),
            ("NOTE".to_string(), "a=b c".to_string()),
        ];
        assert_eq!(render_fork_env(&env), "LR=3e-4\nNOTE=a=b c\n");
        assert_eq!(render_fork_env(&[]), "");
    }

    #[test]
    fn assignment_env_overrides_only_matching_pool_values() {
        let initial = vec![
            ("SMOLVM_FORK_INDEX".to_string(), "2".to_string()),
            ("LR".to_string(), "1e-4".to_string()),
        ];
        let assignment = vec![
            ("LR".to_string(), "3e-4".to_string()),
            ("DATASET".to_string(), "math".to_string()),
        ];
        assert_eq!(
            merge_fork_env(&initial, &assignment),
            vec![
                ("SMOLVM_FORK_INDEX".to_string(), "2".to_string()),
                ("LR".to_string(), "3e-4".to_string()),
                ("DATASET".to_string(), "math".to_string()),
            ]
        );
    }

    #[cfg(unix)]
    fn run_activation_script(script: &str, stdin: &str) -> std::process::Output {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn activation script");
        child
            .stdin
            .take()
            .expect("activation stdin")
            .write_all(stdin.as_bytes())
            .expect("write activation input");
        child
            .wait_with_output()
            .expect("wait for activation script")
    }

    #[cfg(unix)]
    #[test]
    fn held_fork_activation_is_idempotent_after_an_ambiguous_reply() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("ready"), b"ready\n").unwrap();
        let ready = state.join("ready");
        let release = state.join("release");
        let worker_ready = state.join("worker-ready");
        let receipt = state.join("activation");
        let env_path = workspace.join("fork-env");
        let ensure_parent = format!("mkdir -p '{}'", workspace.display());
        let token = "0123456789abcdef";
        std::fs::write(&worker_ready, b"stale\n").unwrap();
        let script = build_activation_script(
            ready.to_str().unwrap(),
            release.to_str().unwrap(),
            worker_ready.to_str().unwrap(),
            receipt.to_str().unwrap(),
            &ensure_parent,
            env_path.to_str().unwrap(),
            token,
        );

        let first = run_activation_script(&script, "LR=1e-4\n");
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(std::fs::read_to_string(&env_path).unwrap(), "LR=1e-4\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            std::fs::read_to_string(&receipt).unwrap(),
            format!("{token}\n")
        );
        assert!(release.is_file());
        assert!(!worker_ready.exists());

        // A lost reply may cause the host to send the same activation again.
        // The receipt proves ownership and makes that retry a successful no-op.
        let retry = run_activation_script(&script, "LR=changed\n");
        assert!(retry.status.success());
        assert_eq!(std::fs::read_to_string(&env_path).unwrap(), "LR=1e-4\n");

        let other = build_activation_script(
            ready.to_str().unwrap(),
            release.to_str().unwrap(),
            worker_ready.to_str().unwrap(),
            receipt.to_str().unwrap(),
            &ensure_parent,
            env_path.to_str().unwrap(),
            "fedcba9876543210",
        );
        assert_eq!(
            run_activation_script(&other, "LR=other\n").status.code(),
            Some(42)
        );
    }

    #[cfg(unix)]
    #[test]
    fn held_fork_activation_retry_finishes_a_partial_commit() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("ready"), b"ready\n").unwrap();
        let ready = state.join("ready");
        let release = state.join("release");
        let worker_ready = state.join("worker-ready");
        let receipt = state.join("activation");
        let env_path = workspace.join("fork-env");
        let ensure_parent = format!("mkdir -p '{}'", workspace.display());
        let token = "0123456789abcdef";
        std::fs::write(&receipt, format!("{token}\n")).unwrap();
        let script = build_activation_script(
            ready.to_str().unwrap(),
            release.to_str().unwrap(),
            worker_ready.to_str().unwrap(),
            receipt.to_str().unwrap(),
            &ensure_parent,
            env_path.to_str().unwrap(),
            token,
        );

        let retry = run_activation_script(&script, "LR=3e-4\n");
        assert!(
            retry.status.success(),
            "{}",
            String::from_utf8_lossy(&retry.stderr)
        );
        assert_eq!(std::fs::read_to_string(&env_path).unwrap(), "LR=3e-4\n");
        assert!(release.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn worker_ready_wait_requires_the_exact_token_and_has_a_bounded_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("worker-ready");
        let script = build_worker_ready_wait_script(marker.to_str().unwrap());
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        std::fs::write(&marker, format!("{expected}\n")).unwrap();
        let success = std::process::Command::new("/bin/sh")
            .args(["-c", &script, "wait", expected, "1"])
            .output()
            .unwrap();
        assert!(success.status.success());

        std::fs::write(&marker, format!("{}\n", "f".repeat(64))).unwrap();
        let stale = std::process::Command::new("/bin/sh")
            .args(["-c", &script, "wait", expected, "1"])
            .output()
            .unwrap();
        assert_eq!(stale.status.code(), Some(45));

        std::fs::remove_file(marker).unwrap();
        let timeout = std::process::Command::new("/bin/sh")
            .args(["-c", &script, "wait", expected, "1"])
            .output()
            .unwrap();
        assert_eq!(timeout.status.code(), Some(44));
        assert!(!script.contains(expected));
    }

    #[test]
    fn worker_ready_transport_deadline_allows_poll_loop_overhead() {
        assert_eq!(
            worker_ready_command_timeout(Duration::from_secs(120)).unwrap(),
            Duration::from_secs(150)
        );
    }

    #[test]
    fn successful_activation_is_persisted_as_one_shot() {
        let mut record = VmRecord::new("slot-0".to_string(), 2, 1024, vec![], vec![], false);
        record.forkpoint_held = true;
        record.env = vec![
            ("BASE".to_string(), "keep".to_string()),
            ("LR".to_string(), "1e-4".to_string()),
        ];
        let assignment = vec![("LR".to_string(), "3e-4".to_string())];
        let merged = vec![("LR".to_string(), "3e-4".to_string())];

        record_fork_activation(&mut record, &assignment, merged.clone());

        assert!(!record.forkpoint_held);
        assert_eq!(record.fork_env, merged);
        assert_eq!(
            record.env,
            vec![
                ("BASE".to_string(), "keep".to_string()),
                ("LR".to_string(), "3e-4".to_string()),
            ]
        );
    }

    // Fix 1: the re-mint script must regenerate the per-machine on-disk secrets
    // that a wholesale CoW disk clone would otherwise share across tenants —
    // above all the SSH host keys.
    fn bare_vm_record() -> VmRecord {
        VmRecord::new("clone-a".to_string(), 1, 512, vec![], vec![], false)
    }

    fn image_record() -> VmRecord {
        let mut record = bare_vm_record();
        record.image = Some("alpine:latest".to_string());
        record
    }

    #[test]
    fn rejuvenation_script_regenerates_per_machine_secrets() {
        let script = build_rejuvenation_script("clone-a", "deadbeef", &bare_vm_record());

        // SSH host keys: delete the golden's, then regenerate fresh ones.
        assert!(
            script.contains("ssh_host_"),
            "script must remove the golden's SSH host keys: {script}"
        );
        assert!(
            script.contains("/usr/bin/ssh-keygen"),
            "script must locate ssh-keygen by absolute path: {script}"
        );
        assert!(
            script.contains(r#""$KG" -A"#),
            "script must regenerate SSH host keys: {script}"
        );
        // Fresh machine-id, hostname, and dbus id.
        assert!(script.contains("> /etc/machine-id"));
        assert!(script.contains("> /etc/hostname"));
        assert!(script.contains("/var/lib/dbus/machine-id"));
        // The clone name and RNG seed are threaded through.
        assert!(script.contains("clone-a"));
        assert!(script.contains("deadbeef"));
        assert!(script.contains(&format!(
            "mkdir -p '{}'",
            smolvm_protocol::forkpoint::STATE_DIR
        )));
        assert!(script.contains(smolvm_protocol::forkpoint::RESTORED_PATH));
        // Guarded so it fails hard on core identity but no-ops when sshd/dbus
        // are absent (minimal library images).
        assert!(script.contains("set -e"));
        // Probed by absolute path, not `command -v`: the agent's exec PATH need
        // not carry the directory, and a miss under `set -e` would abort the
        // script after the old keys were already deleted.
        assert!(!script.contains("command -v ssh-keygen"));
    }

    // The rejuvenation script must NOT touch the inherited exec overlay: the
    // restored guest may still hold it mounted, and renaming a live
    // overlayfs's backing directories breaks every subsequent container exec
    // (ESTALE). Overlay adoption is a host-side lookup alias instead.
    #[test]
    fn rejuvenation_script_leaves_the_inherited_overlay_alone() {
        let script = build_rejuvenation_script("clone-a", "deadbeef", &image_record());
        // Writing files THROUGH the merged mount is how the workload's rootfs is
        // reached (same as `write_fork_env`); what breaks a live overlayfs is
        // renaming or removing its backing dirs.
        // Paths *inside* the merged mount are the workload's own files; what must
        // never happen is the overlay root itself being renamed or removed.
        let merged = "/storage/overlays/persistent-clone-a/merged";
        for destructive in [
            format!("mv {merged}"),
            format!("rmdir {merged}"),
            format!("rm -rf {merged} "),
            format!("rm -rf {merged};"),
        ] {
            assert!(
                !script.contains(&destructive),
                "script must not rename/remove the overlay root: {script}"
            );
        }
    }

    // The regression this guards: identity files written unprefixed land in the
    // VM rootfs, where no workload reads them, so every clone of an image
    // machine kept the golden's SSH host keys.
    #[test]
    fn image_clones_rejuvenate_identity_inside_the_workload_rootfs() {
        let script = build_rejuvenation_script("clone-a", "deadbeef", &image_record());
        let merged = "/storage/overlays/persistent-clone-a/merged";
        assert!(
            script.contains(&format!("{merged}/etc/hostname")),
            "hostname must be written into the workload rootfs: {script}"
        );
        assert!(
            script.contains(&format!("{merged}/etc/machine-id")),
            "machine-id must be written into the workload rootfs: {script}"
        );
        assert!(
            script.contains(&format!("{merged}/etc/ssh/ssh_host_")),
            "SSH host keys must be replaced inside the workload rootfs: {script}"
        );
        // The container's own ssh-keygen, since `-A` writes to a fixed /etc/ssh.
        assert!(
            script.contains(&format!(r#""$CH" {merged}"#)),
            "keys must be regenerated by the container's own binary: {script}"
        );
        assert!(script.contains("/usr/sbin/chroot"));
        // Fail-closed: a missing overlay, or keys that could not be regenerated,
        // must abort rather than vend a clone on the golden's identity.
        assert!(
            script.contains("exit 41"),
            "missing overlay must abort: {script}"
        );
        assert!(
            script.contains("exit 42"),
            "unregenerated keys must abort: {script}"
        );
    }

    // A bare VM has no workload container, so paths stay VM-rootfs relative.
    #[test]
    fn bare_vm_clones_keep_plain_vm_paths() {
        let script = build_rejuvenation_script("clone-a", "deadbeef", &bare_vm_record());
        assert!(script.contains("> /etc/hostname"));
        assert!(!script.contains("/storage/overlays"));
        assert!(script.contains(r#""$KG" -A"#));
        // No chroot on the bare-VM path: the VM rootfs is the workload's rootfs.
        assert!(!script.contains("chroot"));
    }

    // Fix 2 (fail-closed): an Err rejuvenation must tear the clone down and
    // propagate the error — never leave it live/ready.
    #[test]
    fn rejuvenation_failure_tears_down_and_errors() {
        let torn_down = Cell::new(false);
        let result = fail_closed_on_rejuvenation(
            Err(Error::agent("rejuvenate clone", "agent unreachable")),
            || torn_down.set(true),
        );
        assert!(result.is_err(), "a rejuvenation failure must fail the fork");
        assert!(
            torn_down.get(),
            "a rejuvenation failure must tear the clone down"
        );
    }

    // Success path: the clone is kept (no teardown) and the fork proceeds.
    #[test]
    fn rejuvenation_success_keeps_clone_live() {
        let torn_down = Cell::new(false);
        let result = fail_closed_on_rejuvenation(Ok(()), || torn_down.set(true));
        assert!(result.is_ok());
        assert!(
            !torn_down.get(),
            "a successful rejuvenation must not tear the clone down"
        );
    }
}
