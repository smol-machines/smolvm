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
    golden.unwrap_or(name).to_string()
}

/// Launch an image machine's workload container in the background.
///
/// `exec_env` is the record env with secrets already resolved — resolution is
/// a host-side concern the caller owns. An empty entrypoint+cmd makes the
/// agent resolve the image's own ENTRYPOINT+CMD, so service-style images
/// start as their authors intended. The persistent overlay is keyed by
/// [`persistent_overlay_owner`] (the machine name, or the golden's for a fork
/// clone) so filesystem state survives restarts and forks.
///
/// Returns `Ok(false)` (no launch) for machines without an image; callers
/// handle bare-VM entrypoints themselves.
pub fn launch_image_workload(
    client: &mut AgentClient,
    machine_name: &str,
    record: &VmRecord,
    exec_env: Vec<(String, String)>,
) -> crate::Result<bool> {
    let Some(ref image) = record.image else {
        return Ok(false);
    };
    let mut command = record.entrypoint.clone();
    command.extend(record.cmd.clone());
    let config = RunConfig::new(image, command)
        .with_env(exec_env)
        .with_workdir(record.workdir.clone())
        .with_user(record.user.clone())
        .with_mounts(record_mounts_to_bindings(&record.mounts))
        .with_persistent_overlay(Some(persistent_overlay_owner(
            machine_name,
            record.golden.as_deref(),
        )));
    client
        .run_container_detached(config)
        .map(|_| true)
        .map_err(|e| crate::Error::agent("start background CMD", format!("{e}")))
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
    }
}
