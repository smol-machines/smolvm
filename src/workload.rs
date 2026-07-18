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

/// Launch an image machine's workload container in the background.
///
/// `exec_env` is the record env with secrets already resolved — resolution is
/// a host-side concern the caller owns. An empty entrypoint+cmd makes the
/// agent resolve the image's own ENTRYPOINT+CMD, so service-style images
/// start as their authors intended. The persistent overlay is keyed by the
/// machine name so filesystem state survives restarts.
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
        .with_persistent_overlay(Some(machine_name.to_string()));
    client
        .run_container_detached(config)
        .map(|_| true)
        .map_err(|e| crate::Error::agent("start background CMD", format!("{e}")))
}
