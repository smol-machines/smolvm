//! Attached mounts: host directories mounted into a running machine.
//!
//! Every machine boots with two live virtio-fs devices that start empty (see
//! the launcher). Attaching a directory adds it to one of them through the
//! VMM's control socket (`SHARE_ADD`), then asks the guest agent to bind it
//! onto the requested path. Detaching runs the other way: the agent unmounts
//! it, then `SHARE_REMOVE` revokes the guest's access to everything under it,
//! open files included. Read-only mounts go to the read-only device, so the
//! host enforces them.
//!
//! An attached mount lasts until the machine stops; it never touches the
//! machine's record, whose mounts decide the devices a start, branch or
//! restore builds. The guest agent is the record of what is attached, and a
//! checkpoint carries it, so a branch keeps its source's attached mounts.

use std::path::{Path, PathBuf};

use crate::agent::fork::{control_socket_cmd, control_socket_path};
use crate::agent::{AgentClient, AgentManager};
use crate::{Error, Result};

pub use smolvm_protocol::AttachedMount;

fn tag(read_only: bool) -> &'static str {
    if read_only {
        smolvm_protocol::ATTACH_TAG_RO
    } else {
        smolvm_protocol::ATTACH_TAG_RW
    }
}

/// The share name a target gets: one per target, and valid on the live device.
fn share_name(target: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    target.hash(&mut hasher);
    format!("m{:016x}", hasher.finish())
}

/// A guest path as the agent expects it: absolute, without `.`, `..` or a
/// trailing slash.
pub fn normalize_target(target: &Path) -> Result<PathBuf> {
    if !target.is_absolute() {
        return Err(Error::config(
            "attach mount",
            format!("guest path {} must be absolute", target.display()),
        ));
    }
    let mut out = PathBuf::from("/");
    for component in target.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::RootDir => {}
            _ => {
                return Err(Error::config(
                    "attach mount",
                    format!(
                        "guest path {} may not contain '.' or '..'",
                        target.display()
                    ),
                ))
            }
        }
    }
    if out == Path::new("/") {
        return Err(Error::config(
            "attach mount",
            "cannot mount over the guest root",
        ));
    }
    Ok(out)
}

const RESTART_HINT: &str =
    "this machine was started before attached mounts were supported; restart it";

fn control(name: &str, command: &str) -> Result<String> {
    let reply = control_socket_cmd(&control_socket_path(name), command)?;
    let reply = reply.trim().to_string();
    if reply.starts_with("OK") {
        Ok(reply)
    } else if reply.contains("no live virtio-fs device") {
        Err(Error::agent("attach mount", RESTART_HINT))
    } else {
        Err(Error::agent(
            "attach mount",
            reply.strip_prefix("ERR ").unwrap_or(&reply).to_string(),
        ))
    }
}

/// A client for the running machine's agent, and whether it supports
/// attached mounts.
fn connect(name: &str) -> Result<(AgentClient, bool)> {
    let mut client = AgentManager::for_vm(name)?.connect()?;
    let supported = client.supports_capability(smolvm_protocol::ATTACH_MOUNT_CAPABILITY)?;
    Ok((client, supported))
}

/// Whether one of two canonical directories is, or lies inside, the other.
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Directories attached to the running machine `name`.
pub fn list(name: &str) -> Result<Vec<AttachedMount>> {
    let (mut client, supported) = connect(name)?;
    if !supported {
        return Ok(Vec::new());
    }
    client.attached_mounts()
}

/// Mount the host directory `source` at `target` in the running machine `name`.
/// `boot_targets` are the guest paths of the mounts it started with, which an
/// attached mount may not cover.
pub fn attach(
    name: &str,
    source: &Path,
    target: &Path,
    read_only: bool,
    boot_targets: &[String],
) -> Result<AttachedMount> {
    let source = std::fs::canonicalize(source).map_err(|e| {
        Error::config(
            "attach mount",
            format!("host path {}: {e}", source.display()),
        )
    })?;
    if !source.is_dir() {
        return Err(Error::config(
            "attach mount",
            format!("host path {} is not a directory", source.display()),
        ));
    }
    let target = normalize_target(target)?;
    let target_str = target.to_string_lossy().into_owned();
    if boot_targets
        .iter()
        .any(|t| Path::new(t.trim_end_matches('/')) == target)
    {
        return Err(Error::config(
            "attach mount",
            format!("{target_str} is already mounted from the machine's configuration"),
        ));
    }

    let (mut client, supported) = connect(name)?;
    if !supported {
        return Err(Error::agent("attach mount", RESTART_HINT));
    }
    let attached = client.attached_mounts()?;
    if attached.iter().any(|m| m.target == target_str) {
        return Err(Error::config(
            "attach mount",
            format!("{target_str} already has an attached mount"),
        ));
    }
    // A live device serves each host inode under one share, so a directory
    // cannot be attached twice, nor inside or around one already attached.
    if let Some(m) = attached
        .iter()
        .find(|m| m.read_only == read_only && overlaps(&source, Path::new(&m.source)))
    {
        return Err(Error::config(
            "attach mount",
            format!(
                "{} overlaps {}, already attached at {}; a directory can be attached once, and not inside or around another attached directory",
                source.display(),
                m.source,
                m.target
            ),
        ));
    }

    let share = share_name(&target);
    let source_str = source.to_string_lossy().into_owned();
    let tag = tag(read_only);
    control(name, &format!("SHARE_ADD {tag} {share} {source_str}"))?;
    if let Err(error) = client.attach_mount(&share, &source_str, read_only, &target_str) {
        // Never leave a share the guest can reach but did not ask for.
        let _ = control(name, &format!("SHARE_REMOVE {tag} {share}"));
        return Err(error);
    }
    Ok(AttachedMount {
        share,
        source: source_str,
        target: target_str,
        read_only,
    })
}

/// Unmount the attached mount at `target` from the running machine `name`.
pub fn detach(name: &str, target: &Path) -> Result<AttachedMount> {
    let target = normalize_target(target)?;
    let target_str = target.to_string_lossy().into_owned();
    let (mut client, supported) = connect(name)?;
    let attached = if supported {
        client.attached_mounts()?
    } else {
        Vec::new()
    };
    let Some(mount) = attached.into_iter().find(|m| m.target == target_str) else {
        return Err(Error::config(
            "detach mount",
            format!(
                "nothing is attached at {target_str}; a mount from the machine's configuration is removed with `machine update` while it is stopped"
            ),
        ));
    };
    client.detach_mount(&mount.target)?;
    control(
        name,
        &format!("SHARE_REMOVE {} {}", tag(mount.read_only), mount.share),
    )?;
    Ok(mount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_overlaps_itself_its_parents_and_its_children_only() {
        assert!(overlaps(Path::new("/srv/a"), Path::new("/srv/a")));
        assert!(overlaps(Path::new("/srv/a/sub"), Path::new("/srv/a")));
        assert!(overlaps(Path::new("/srv"), Path::new("/srv/a")));
        assert!(!overlaps(Path::new("/srv/ab"), Path::new("/srv/a")));
        assert!(!overlaps(Path::new("/srv/b"), Path::new("/srv/a")));
    }

    #[test]
    fn targets_are_normalized_and_get_stable_device_safe_share_names() {
        assert_eq!(
            normalize_target(Path::new("/app/")).unwrap(),
            PathBuf::from("/app")
        );
        assert_eq!(
            normalize_target(Path::new("/a//b")).unwrap(),
            PathBuf::from("/a/b")
        );
        assert!(normalize_target(Path::new("app")).is_err());
        assert!(normalize_target(Path::new("/a/../b")).is_err());
        assert!(normalize_target(Path::new("/")).is_err());
        let share = share_name(Path::new("/app"));
        assert_eq!(share, share_name(Path::new("/app")));
        assert_ne!(share, share_name(Path::new("/data")));
        assert!(share.len() <= 64);
        assert!(share.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
}
