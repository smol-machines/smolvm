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
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock)
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
        crate::process::vm_drop_ids(&crate::agent::vm_uid_registry_dir(), &gdir, None)
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
    Ok(())
}

/// Best-effort per-clone identity rejuvenation after a fork. A clone inherits
/// the golden's hostname, machine-id, and (critically) RNG state, so without
/// this every clone would share the golden's random stream — a security problem
/// and a source of duplicate-identity bugs across a pool. Run over the
/// freshly-booted clone's agent: set a unique hostname, mint a fresh machine-id,
/// and stir the kernel RNG with fresh host entropy so the streams diverge.
/// Failures are warnings, not fatal (the clone still works).
///
/// Note: this stirs but does not *credit* entropy (no `RNDADDENTROPY`/VMGENID
/// yet), and does not re-address the network (MAC/IP) — both are follow-ups.
pub fn rejuvenate_clone(clone: &str) {
    let sock = vm_data_dir(clone).join("agent.sock");
    let seed = host_random_hex(64);
    // Names are validated (alphanumeric + dashes), so single-quoting is safe.
    let script = format!(
        "hostname '{c}' 2>/dev/null; printf '%s\\n' '{c}' > /etc/hostname 2>/dev/null; \
         (cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' > /etc/machine-id) 2>/dev/null; \
         printf '%s' '{s}' > /dev/urandom 2>/dev/null; true",
        c = clone,
        s = seed,
    );
    let mut client = match AgentClient::connect_with_retry(&sock) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(clone, error = %e, "clone rejuvenation skipped (agent connect)");
            return;
        }
    };
    match client.vm_exec(
        vec!["/bin/sh".into(), "-c".into(), script],
        vec![],
        None,
        Some(std::time::Duration::from_secs(10)),
        None,
    ) {
        Ok((0, _, _)) => {}
        Ok((code, _, stderr)) => tracing::warn!(
            clone,
            code,
            stderr = %String::from_utf8_lossy(&stderr).trim(),
            "clone rejuvenation exited non-zero"
        ),
        Err(e) => tracing::warn!(clone, error = %e, "clone rejuvenation failed"),
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
