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
use std::path::{Path, PathBuf};

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
) -> Result<PreparedFork> {
    validate_vm_name(clone, "clone name").map_err(|e| Error::config("clone name", e))?;

    // Nested fork is unsupported: a clone boots from a copy-on-write MAP_PRIVATE
    // mapping of the golden's RAM, not a fresh memfd, so it cannot itself be
    // re-forked (its FORK would fail with "no memfd-backed RAM"). Reject
    // `forkable` up front instead of producing a clone that looks forkable but
    // isn't.
    if clone_forkable {
        return Err(Error::agent(
            "fork",
            "nested fork is not supported: a clone cannot be re-forked, so `forkable` \
             on a fork has no effect (drop it)",
        ));
    }

    let golden_rec = db
        .get_vm(golden)?
        .ok_or_else(|| Error::vm_not_found(golden))?;

    // The golden must be alive and forkable. We probe the control socket rather
    // than the vsock agent: after its first fork the golden is frozen (paused)
    // as the shared base, so an agent ping would fail — but STATUS still answers
    // (running or paused), and we can fork it again.
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
    if db.get_vm(clone)?.is_some() {
        return Err(Error::agent(
            "fork",
            format!("machine '{clone}' already exists"),
        ));
    }

    // Clone dir + snapshot dir. A leftover data directory with no DB record is
    // an orphan from a previously crashed fork; its stale qcow2 overlays would
    // make `krun_create_disk_overlay` fail (rc=-5, it refuses to overwrite an
    // existing target). The DB check above guarantees no live clone owns this
    // name, so clearing the directory is safe.
    let clone_dir = vm_data_dir(clone);
    if clone_dir.exists() {
        std::fs::remove_dir_all(&clone_dir)
            .map_err(|e| Error::agent("clear orphan clone dir", e.to_string()))?;
    }
    std::fs::create_dir_all(&clone_dir)
        .map_err(|e| Error::agent("create clone dir", e.to_string()))?;

    // A pack-backed golden (created `--from <.smolmachine>`) resolves its layers
    // either through the shared content-addressed store (privileged installs: a
    // pointer file beside its data dir) or from its own pre-extracted `pack`
    // dir (rootless installs). The clone record inherits `source_smolmachine`
    // but a fork never runs the create-time extraction, so without one of those
    // the clone's start falls into the sidecar re-extraction fallback — seconds
    // of host-side work per fork for read-only state the golden already has.
    // Give the clone the golden's resolution in O(1):
    //  - shared store: replicate the pointer file (the entry is no-evict while
    //    referenced and start self-heals a missing one, so the copied pointer
    //    can never point at anything the golden's own couldn't);
    //  - per-machine layout: symlink the clone's `pack` dir to the golden's
    //    extracted layers. The layers are read-only lowerdir content, the
    //    golden is frozen, and its deletion is refused while clones exist, so
    //    the target outlives every reader. `force_detach_layers_volume` no-ops
    //    on symlinks, so a clone's stop/delete can't detach the golden's macOS
    //    layers volume through the link.
    let golden_layers = crate::agent::machine_layers_cache_dir(golden);
    let golden_ptr = crate::agent::shared_pack_pointer_path(&golden_layers);
    if golden_ptr.exists() {
        let clone_layers = crate::agent::machine_layers_cache_dir(clone);
        std::fs::create_dir_all(&clone_layers)
            .map_err(|e| Error::agent("create clone pack dir", e.to_string()))?;
        std::fs::copy(
            &golden_ptr,
            crate::agent::shared_pack_pointer_path(&clone_layers),
        )
        .map_err(|e| Error::agent("copy shared pack pointer", e.to_string()))?;
    } else if smolvm_pack::extract::is_extracted(&golden_layers) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            &golden_layers,
            crate::agent::machine_layers_cache_dir(clone),
        )
        .map_err(|e| Error::agent("link clone pack dir", e.to_string()))?;
    }

    // The golden writes its frozen snapshot (checkpoint + memfd manifest) here.
    // It lives under the GOLDEN's data dir, not the clone's: under Landlock the
    // frozen golden VMM is confined to its own data dir, so it can write here but
    // could not write into a separate clone's dir. The clone — which already needs
    // read access to the golden's dir for its copy-on-write disk backing — reads
    // the snapshot from the same place. See `internal_boot`'s Landlock grants.
    let gdir = vm_data_dir(golden);
    let snapshot_dir = gdir.join("fork-snapshots").join(clone);
    std::fs::create_dir_all(&snapshot_dir)
        .map_err(|e| Error::agent("create snapshot dir", e.to_string()))?;
    // Under per-VM uid isolation (privileged launcher) the frozen golden VMM runs
    // as its own unprivileged uid and writes the snapshot here via the FORK
    // command below, so hand this dir to that uid. No-op unless privileged; if the
    // drop is active the golden's uid lookup must succeed (fail closed).
    if let Some(result) =
        crate::process::vm_drop_ids(&crate::agent::vm_uid_registry_dir(), &gdir, None, None)
    {
        let (uid, gid) =
            result.map_err(|e| Error::agent("fork: resolve golden uid", e.to_string()))?;
        crate::process::chown_tree(&snapshot_dir, uid, gid)
            .map_err(|e| Error::agent("fork: chown snapshot dir", e.to_string()))?;
    }

    // Register the clone in the DB with the golden's config, no running-state,
    // and its port forwards remapped to fresh host ports. With the default TSI
    // backend outbound is proxied per-process (each clone gets it for free, no
    // guest MAC/IP involved); only inbound host ports must be made distinct so
    // the clone is reachable without colliding with the still-running golden or
    // sibling clones.
    let mut clone_rec = golden_rec.clone();
    clone_rec.name = clone.to_string();
    clone_rec.pid = None;
    clone_rec.pid_start_time = None;
    let mut port_remaps = Vec::new();
    if !pinned_ports.is_empty() {
        // User pinned the clone's forwards explicitly — use them as-is.
        clone_rec.ports = pinned_ports.to_vec();
        for (h, g) in &clone_rec.ports {
            port_remaps.push((*h, *g, *h));
        }
    } else if !clone_rec.ports.is_empty() {
        let mut remapped = Vec::with_capacity(clone_rec.ports.len());
        for (golden_host, guest) in &clone_rec.ports {
            match alloc_free_host_port() {
                Some(h) => {
                    port_remaps.push((*golden_host, *guest, h));
                    remapped.push((h, *guest));
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
    db.insert_vm(clone, &clone_rec)?;

    // Freeze the golden and write its snapshot (checkpoint + memfd manifest).
    let cleanup = || {
        let _ = db.remove_vm(clone);
        let _ = std::fs::remove_dir_all(&clone_dir);
        let _ = std::fs::remove_dir_all(&snapshot_dir);
    };
    let reply = match control_socket_cmd(&ctl, &format!("FORK {}", snapshot_dir.display())) {
        Ok(r) => r,
        Err(e) => {
            cleanup();
            return Err(e);
        }
    };
    if !reply.starts_with("OK") {
        cleanup();
        return Err(Error::agent("fork", format!("golden FORK failed: {reply}")));
    }

    if let Err(e) = clone_fork_disks(&gdir, &clone_dir) {
        cleanup();
        return Err(e);
    }

    Ok(PreparedFork {
        snapshot_dir,
        clone_record: clone_rec,
        port_remaps,
    })
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
fn build_rejuvenation_script(clone: &str, seed: &str) -> String {
    format!(
        "set -e; \
         hostname '{c}' 2>/dev/null || true; \
         printf '%s\\n' '{c}' > /etc/hostname; \
         tr -d '-' < /proc/sys/kernel/random/uuid > /etc/machine-id; \
         if [ -f /var/lib/dbus/machine-id ] && [ ! -L /var/lib/dbus/machine-id ]; then \
             tr -d '-' < /proc/sys/kernel/random/uuid > /var/lib/dbus/machine-id; \
         fi; \
         if [ -d /etc/ssh ] && command -v ssh-keygen >/dev/null 2>&1; then \
             rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub; \
             ssh-keygen -A >/dev/null 2>&1; \
         fi; \
         rm -rf /var/lib/cloud/instance /var/lib/cloud/instances/* /var/lib/cloud/data/instance-id 2>/dev/null || true; \
         printf '%s' '{s}' > /dev/urandom 2>/dev/null || true; \
         true",
        c = clone,
        s = seed,
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
pub fn rejuvenate_clone(clone: &str) -> Result<()> {
    let sock = vm_data_dir(clone).join("agent.sock");
    let seed = host_random_hex(64);
    let script = build_rejuvenation_script(clone, &seed);

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

    // Fix 1: the re-mint script must regenerate the per-machine on-disk secrets
    // that a wholesale CoW disk clone would otherwise share across tenants —
    // above all the SSH host keys.
    #[test]
    fn rejuvenation_script_regenerates_per_machine_secrets() {
        let script = build_rejuvenation_script("clone-a", "deadbeef");

        // SSH host keys: delete the golden's, then regenerate fresh ones.
        assert!(
            script.contains("ssh_host_"),
            "script must remove the golden's SSH host keys: {script}"
        );
        assert!(
            script.contains("ssh-keygen -A"),
            "script must regenerate SSH host keys: {script}"
        );
        // Fresh machine-id, hostname, and dbus id.
        assert!(script.contains("> /etc/machine-id"));
        assert!(script.contains("> /etc/hostname"));
        assert!(script.contains("/var/lib/dbus/machine-id"));
        // The clone name and RNG seed are threaded through.
        assert!(script.contains("clone-a"));
        assert!(script.contains("deadbeef"));
        // Guarded so it fails hard on core identity but no-ops when sshd/dbus
        // are absent (minimal library images).
        assert!(script.contains("set -e"));
        assert!(script.contains("command -v ssh-keygen"));
    }

    // The rejuvenation script must NOT touch the inherited exec overlay: the
    // restored guest may still hold it mounted, and renaming a live
    // overlayfs's backing directories breaks every subsequent container exec
    // (ESTALE). Overlay adoption is a host-side lookup alias instead.
    #[test]
    fn rejuvenation_script_leaves_the_inherited_overlay_alone() {
        let script = build_rejuvenation_script("clone-a", "deadbeef");
        assert!(
            !script.contains("/storage/overlays"),
            "script must not rename/touch overlay dirs: {script}"
        );
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
