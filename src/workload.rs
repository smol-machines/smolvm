//! Shared machine-workload launch: run an image machine's persistent
//! container (its ENTRYPOINT+CMD) after the VM boots.
//!
//! Every front-end that starts machines (the engine CLI, the HTTP API, the
//! smol CLI) must launch the workload the same way — a front-end that skips
//! it boots a bare agent VM whose published ports forward to nothing. Keeping
//! the launch here, in the lib, is what stops front-ends from drifting apart.

use crate::agent::{AgentClient, RunConfig};
use crate::config::VmRecord;
use crate::data::storage::HostMount;

/// Convert a `VmRecord` mount list (`(host_source, guest_target, read_only)`
/// triples) to the agent's virtiofs binding format. The host source is
/// dropped — the agent only needs the guest-facing target and the positional
/// `smolvm{i}` tag.
pub fn record_mounts_to_bindings(mounts: &[(String, String, bool)]) -> Vec<(String, String, bool)> {
    mounts
        .iter()
        .enumerate()
        .map(|(i, (_host, target, ro))| (HostMount::mount_tag(i), target.clone(), *ro))
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
    match client.run_container_detached(
        RunConfig::new(image, command)
            .with_workdir(record.workdir.clone())
            .with_user(record.user.clone())
            .with_mounts(record_mounts_to_bindings(&record.mounts))
            .in_machine(record, machine_name, &exec_env)
            .with_env(exec_env),
    ) {
        Ok(_) => Ok(true),
        Err(e) if is_missing_launch_metadata(&e.to_string()) => {
            tracing::info!(
                machine = machine_name,
                image = %image,
                "image defines no entrypoint or cmd and none was given; booting bare agent without a workload"
            );
            Ok(false)
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

/// Progress heartbeat for a long workload launch.
///
/// A pack machine's first start unpacks the whole flattened image before the
/// workload can run — minutes of silence that read as a hang. After a short
/// grace period this prints an elapsed-time line to stderr: rewritten in
/// place on a terminal, one line every 30 s when piped. Dropping the guard
/// stops the ticker and clears the line.
struct WaitTicker {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl WaitTicker {
    fn start(what: &'static str) -> Self {
        use std::io::{IsTerminal, Write};
        use std::sync::atomic::Ordering;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag = stop.clone();
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
            while !stop_flag.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(250));
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
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for WaitTicker {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
