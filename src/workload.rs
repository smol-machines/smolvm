//! Shared machine-workload launch: run an image machine's persistent
//! container (its ENTRYPOINT+CMD) after the VM boots.
//!
//! Every front-end that starts machines (the engine CLI, the HTTP API, the
//! smol CLI) must launch the workload the same way — a front-end that skips
//! it boots a bare agent VM whose published ports forward to nothing. Keeping
//! the launch here, in the lib, is what stops front-ends from drifting apart.

use crate::agent::{AgentClient, RunConfig, WorkloadTarget};
use crate::config::VmRecord;

/// Convert a record's live and staged host mounts to the agent's binding form.
/// Reconstructing the rich list preserves original device order, while staged
/// mounts use their stable runtime identity instead of a plain virtiofs tag.
pub fn record_mounts_to_bindings(record: &VmRecord) -> Vec<(String, String, bool)> {
    record
        .host_mounts()
        .iter()
        .enumerate()
        .map(|(i, mount)| {
            (
                mount.runtime_mount_tag(i),
                mount.target.to_string_lossy().into_owned(),
                mount.read_only,
            )
        })
        .collect()
}

/// The id under which a machine's persistent exec overlay lives on its
/// `/storage` disk. Normally the machine's own name; for a fork clone it is
/// the GOLDEN's name: a fork CoW-clones the golden's disks, so the inherited
/// overlay — everything the golden wrote via exec — sits at
/// `/storage/overlays/persistent-<golden>` inside the clone's own disk, and
/// the restored guest may still hold that overlay *mounted* (or a restored
/// workload container running from it). Aliasing the lookup, instead of
/// renaming the directory on disk, keeps that live mount valid while making
/// the clone's execs land in the inherited state.
pub fn persistent_overlay_owner(name: &str, golden: Option<&str>) -> String {
    persistent_overlay_owner_with_lineage(name, golden, None)
}

/// Resolve the persistent overlay owner for a machine whose immediate parent
/// may itself be a fork. `fork_overlay_owner` keeps every generation pointed
/// at the root overlay inherited by the live restored workload.
pub fn persistent_overlay_owner_with_lineage(
    name: &str,
    golden: Option<&str>,
    fork_overlay_owner: Option<&str>,
) -> String {
    fork_overlay_owner.or(golden).unwrap_or(name).to_string()
}

/// The persistent overlay owner for a machine record (see
/// [`persistent_overlay_owner_with_lineage`]).
pub fn record_overlay_owner(record: &VmRecord) -> String {
    persistent_overlay_owner_with_lineage(
        &record.name,
        record.golden.as_deref(),
        record.fork_overlay_owner.as_deref(),
    )
}

/// The filesystem a machine's commands run in, and so the one its file
/// operations act on: the VM's own root for a bare machine, or its image
/// container's persistent overlay. Every exec and file path asks this, so a
/// file written one way is the file every other way reads.
pub fn machine_target(record: &VmRecord) -> WorkloadTarget {
    match &record.image {
        None => WorkloadTarget::Vm,
        Some(image) => WorkloadTarget::Container {
            image: image.clone(),
            overlay_id: record_overlay_owner(record),
        },
    }
}

/// The container `run(image, ...)` uses on a machine. Running the machine's
/// own image is its workload container; any other image gets an overlay of its
/// own for this machine, so its changes persist across runs of that image
/// without ever mixing two images' filesystems.
pub fn run_target(record: &VmRecord, image: &str) -> WorkloadTarget {
    let owner = record_overlay_owner(record);
    let canonical = smolvm_protocol::normalize_image_ref(image);
    let own_image = record
        .image
        .as_deref()
        .is_some_and(|own| smolvm_protocol::normalize_image_ref(own) == canonical);
    WorkloadTarget::Container {
        image: image.to_string(),
        overlay_id: if own_image {
            owner
        } else {
            run_overlay_id(&owner, &canonical)
        },
    }
}

/// The overlay id for running `canonical_image` on a machine whose overlay
/// owner is `owner`. Machine names cannot contain `.`, so this id never
/// collides with a machine's own overlay.
fn run_overlay_id(owner: &str, canonical_image: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(canonical_image.as_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{owner}.{hex}")
}

/// Launch an image machine's workload container in the background.
///
/// `exec_env` is the record env with secrets already resolved — resolution is
/// a host-side concern the caller owns. An empty entrypoint+cmd makes the
/// agent resolve the image's own ENTRYPOINT+CMD, so service-style images
/// start as their authors intended. The persistent overlay is keyed by
/// [`persistent_overlay_owner_with_lineage`] (the machine name, or the root
/// golden's for a fork clone) so filesystem state survives restarts and forks.
///
/// Returns `Ok(false)` (no launch) for machines without an image, and for
/// image machines where neither the record nor the image supplies a command —
/// a bare rootfs directory has no OCI config at all, so failing the whole
/// start over a missing ENTRYPOINT would make such images unusable as
/// machines. They boot to the bare agent instead; `exec`/`shell` provide the
/// commands.
pub fn launch_image_workload(
    client: &mut AgentClient,
    machine_name: &str,
    record: &VmRecord,
    exec_env: Vec<(String, String)>,
) -> crate::Result<bool> {
    let Some(ref image) = record.image else {
        // Remote volumes mount inside a workload container, which a machine with
        // no image never launches — honoring the volume is impossible. Fail
        // loudly instead of silently dropping it.
        if !record.remote_volumes.is_empty() {
            return Err(crate::Error::agent(
                "launch workload",
                "remote volumes require an image-backed machine — there is no \
                 workload container to mount into",
            ));
        }
        return Ok(false);
    };
    let mut command = record.entrypoint.clone();
    command.extend(record.cmd.clone());
    // Remote volumes are mounted by the agent itself, natively, between the
    // container's create and start — so the workload sees its data from its
    // first instruction and its command is never rewritten.
    let _ticker =
        WaitTicker::start("preparing the workload (a first start unpacks the machine image)");
    let launch = |client: &mut AgentClient| {
        client.run_container_detached(
            RunConfig::new(image, command.clone())
                .with_workdir(record.workdir.clone())
                .with_user(record.user.clone())
                .with_mounts(record_mounts_to_bindings(record))
                .in_machine(record, machine_name, &exec_env)
                .with_env(exec_env.clone())
                .with_stop_vm_on_exit(record.stop_on_exit),
        )
    };
    match launch(client) {
        Ok(_) => Ok(true),
        Err(e) if is_missing_launch_metadata(&e.to_string()) => {
            tracing::info!(
                machine = machine_name,
                image = %image,
                "image defines no entrypoint or cmd and none was given; booting bare agent without a workload"
            );
            Ok(false)
        }
        Err(e) if is_image_missing(&e.to_string()) => {
            // The agent discards a cached image whose layers no longer verify
            // — an unclean shutdown can leave a layer without its completion
            // marker — and then reports the image as missing. It has no way to
            // fetch a replacement on its own, so pull it again here and launch
            // once more. Without this a machine whose host was killed mid-run
            // stays permanently unstartable, reporting only "image not found"
            // for an image it holds a record of.
            tracing::info!(
                machine = machine_name,
                image = %image,
                "cached image is no longer usable; pulling it again before launching"
            );
            client
                .pull_with_registry_config(image)
                .map_err(|e| crate::Error::agent("start background CMD", format!("{e}")))?;
            launch(client)
                .map(|_| true)
                .map_err(|e| crate::Error::agent("start background CMD", format!("{e}")))
        }
        Err(e) => Err(crate::Error::agent("start background CMD", format!("{e}"))),
    }
}

/// Whether a detached-run failure means "nothing to launch" rather than a
/// real error. The image is only known inside the guest (it may be imported
/// during the run request itself), so the agent's error message — kept stable
/// on its side for this match — is the reliable signal.
fn is_missing_launch_metadata(message: &str) -> bool {
    message.contains("defines no entrypoint or cmd")
}

/// Whether a detached-run failure means the guest no longer holds the image.
/// Matched on the agent's message for the same reason as
/// [`is_missing_launch_metadata`]: only the guest knows its image store.
fn is_image_missing(message: &str) -> bool {
    message.contains("image not found")
}

/// Progress heartbeat for a long workload launch.
///
/// A pack machine's first start unpacks the whole flattened image before the
/// workload can run — minutes of silence that read as a hang. After a short
/// grace period this prints an elapsed-time line to stderr: rewritten in
/// place on a terminal, one line every 30 s when piped. Dropping the guard
/// stops the ticker and clears the line. The ticker waits on a channel rather
/// than sleeping, so dropping it returns at once: an ordinary start finishes
/// well inside one tick and must not wait out the rest of it.
struct WaitTicker {
    stop: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl WaitTicker {
    fn start(what: &'static str) -> Self {
        use std::io::{IsTerminal, Write};
        use std::sync::mpsc::RecvTimeoutError;
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let tty = std::io::stderr().is_terminal();
            let grace = std::time::Duration::from_secs(3);
            let step = if tty {
                std::time::Duration::from_secs(1)
            } else {
                std::time::Duration::from_secs(30)
            };
            let mut printed = false;
            // Wakes on the tick, or at once when the guard drops the sender.
            while let Err(RecvTimeoutError::Timeout) =
                stopped.recv_timeout(std::time::Duration::from_millis(250))
            {
                if started.elapsed() < grace {
                    continue;
                }
                let due = match printed {
                    false => true,
                    true => started.elapsed().as_millis() % step.as_millis() < 250,
                };
                if !due {
                    continue;
                }
                let secs = started.elapsed().as_secs();
                let mut err = std::io::stderr();
                if tty {
                    let _ = write!(err, "\r  {what}... {secs}s");
                } else {
                    let _ = writeln!(err, "  {what}... {secs}s");
                }
                let _ = err.flush();
                printed = true;
            }
            if printed && tty {
                let mut err = std::io::stderr();
                let _ = write!(err, "\r{}\r", " ".repeat(what.len() + 16));
                let _ = err.flush();
            }
        });
        Self {
            stop: Some(stop),
            handle: Some(handle),
        }
    }
}

impl Drop for WaitTicker {
    fn drop(&mut self) {
        // Disconnecting the channel wakes the ticker immediately.
        drop(self.stop.take());
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    // Dropping the ticker used to wait out the rest of a 250 ms sleep, which
    // every quick workload launch paid.
    #[test]
    fn dropping_the_ticker_returns_at_once() {
        let ticker = super::WaitTicker::start("test");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let started = std::time::Instant::now();
        drop(ticker);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "{:?}",
            started.elapsed()
        );
    }

    use super::*;

    // An image the guest dropped (its layers stopped verifying after an
    // unclean shutdown) must be recognised so the launcher re-pulls it
    // instead of leaving the machine unstartable. The agent's own
    // "defines no entrypoint or cmd" case must not be mistaken for it.
    #[test]
    fn missing_image_is_told_apart_from_a_commandless_image() {
        assert!(is_image_missing(
            "run container detached: image not found: docker.io/library/ubuntu:latest"
        ));
        assert!(!is_image_missing(
            "run container detached: image defines no entrypoint or cmd"
        ));
        assert!(!is_missing_launch_metadata(
            "run container detached: image not found: docker.io/library/ubuntu:latest"
        ));
    }

    fn record(name: &str, image: Option<&str>, golden: Option<&str>) -> VmRecord {
        let mut record = VmRecord::new(name.to_string(), 1, 512, vec![], vec![], false);
        record.image = image.map(str::to_string);
        record.golden = golden.map(str::to_string);
        record
    }

    // A bare machine's commands and files are the VM's own; an image machine's
    // are its workload container's, keyed like every other overlay lookup.
    #[test]
    fn a_machine_targets_the_filesystem_its_commands_run_in() {
        assert_eq!(
            machine_target(&record("bare", None, None)),
            WorkloadTarget::Vm
        );
        assert_eq!(
            machine_target(&record("web", Some("alpine:3.20"), None)),
            WorkloadTarget::Container {
                image: "alpine:3.20".into(),
                overlay_id: "web".into()
            }
        );
        assert_eq!(
            machine_target(&record("clone", Some("alpine:3.20"), Some("web"))),
            WorkloadTarget::Container {
                image: "alpine:3.20".into(),
                overlay_id: "web".into()
            }
        );
    }

    // Running a machine's own image is its workload container. Any other image
    // gets an overlay per machine and image: stable across runs, distinct
    // between images, and never a machine's own overlay id.
    #[test]
    fn run_keys_its_overlay_by_machine_and_image() {
        let web = record("web", Some("alpine:3.20"), None);
        let own = |t: WorkloadTarget| match t {
            WorkloadTarget::Container { overlay_id, .. } => overlay_id,
            WorkloadTarget::Vm => panic!("run is always a container"),
        };
        assert_eq!(
            own(run_target(&web, "docker.io/library/alpine:3.20")),
            "web"
        );

        let bare = record("bare", None, None);
        let alpine = own(run_target(&bare, "alpine:3.20"));
        let python = own(run_target(&bare, "python:3.12-alpine"));
        assert_ne!(alpine, python);
        assert_eq!(
            alpine,
            own(run_target(&bare, "docker.io/library/alpine:3.20"))
        );
        assert!(
            alpine.starts_with("bare.") && alpine.len() == "bare.".len() + 16,
            "{alpine}"
        );
        assert!(crate::data::validate_vm_name(&alpine, "name").is_err());
        assert!(smolvm_protocol::workload_target::validate_overlay_id(&alpine).is_ok());

        // A clone runs other images in its golden's overlays, as it execs there.
        let clone = record("clone", None, Some("bare"));
        assert_eq!(own(run_target(&clone, "alpine:3.20")), alpine);
    }

    // A plain machine's overlay is keyed by its own name; a fork clone's by
    // its golden's name, so clone execs land in the CoW-inherited overlay
    // (and its still-live restored mount) instead of a fresh empty one.
    #[test]
    fn overlay_owner_aliases_fork_clones_to_their_golden() {
        assert_eq!(persistent_overlay_owner("m1", None), "m1");
        assert_eq!(
            persistent_overlay_owner("clone-a", Some("golden-a")),
            "golden-a"
        );
        assert_eq!(
            persistent_overlay_owner_with_lineage("grandchild", Some("child"), Some("root")),
            "root"
        );
    }

    #[test]
    fn bindings_preserve_staged_mount_order_and_identity() {
        let mut record = VmRecord::new(
            "test".into(),
            1,
            256,
            vec![("/host/live".into(), "/live".into(), true)],
            Vec::new(),
            false,
        );
        record.staged_mounts = vec![(0, "/host/staged".into(), "/work".into())];

        let bindings = record_mounts_to_bindings(&record);
        assert_eq!(bindings.len(), 2);
        assert!(bindings[0].0.starts_with("staged+"));
        assert!(bindings[0].0.ends_with("+smolvm0"));
        assert_eq!(bindings[0].1, "/work");
        assert!(!bindings[0].2);
        assert_eq!(bindings[1], ("smolvm1".into(), "/live".into(), true));
    }

    // Only the agent's metadata-less-image failure downgrades a machine start
    // to a bare-agent boot; every other launch failure must stay fatal.
    #[test]
    fn only_the_missing_metadata_error_is_downgraded() {
        assert!(is_missing_launch_metadata(
            "agent operation failed: run container detached: no command given \
             and image 'local-dir:/images/ubuntu' defines no entrypoint or cmd"
        ));
        assert!(!is_missing_launch_metadata("image not found: whatever"));
        assert!(!is_missing_launch_metadata(
            "run container detached: crun exited with status 1"
        ));
    }
}
