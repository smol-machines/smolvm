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
    let _admission = crate::db::SmolvmDb::open()?
        .admit_workload_mutation(Some(name), &[source.to_path_buf()])?;
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
    let source_arg = share_source_arg(&source)?;
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
    control(name, &format!("SHARE_ADD {tag} {share} {source_arg}"))?;
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

/// Add the host directory `source` to the running machine `name`'s live
/// device under `share`, without binding it anywhere: the caller binds it
/// into a container itself (the Docker engine's containers that run in
/// another container's machine). `share` is ASCII letters and digits.
pub fn add_share(name: &str, share: &str, source: &Path, read_only: bool) -> Result<()> {
    let _admission = crate::db::SmolvmDb::open()?
        .admit_workload_mutation(Some(name), &[source.to_path_buf()])?;
    if share.is_empty() || !share.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::config(
            "attach share",
            format!("invalid share name {share:?}"),
        ));
    }
    let source = std::fs::canonicalize(source).map_err(|e| {
        Error::config(
            "attach share",
            format!("host path {}: {e}", source.display()),
        )
    })?;
    control(
        name,
        &format!(
            "SHARE_ADD {} {share} {}",
            tag(read_only),
            share_source_arg(&source)?
        ),
    )
    .map(|_| ())
}

// The existing VMM control protocol trims its command argument. A final /.
// retains the exact directory identity when its name ends in whitespace;
// canonicalization in LiveShares::attach removes it before recording the path.
fn share_source_arg(source: &Path) -> Result<String> {
    let source = source
        .to_str()
        .filter(|path| !path.chars().any(char::is_control))
        .ok_or_else(|| {
            Error::config(
                "attach share",
                "host path must be UTF-8 without control characters",
            )
        })?;
    Ok(format!("{source}/."))
}

/// Remove a share [`add_share`] added, revoking the guest's access to it.
pub fn remove_share(name: &str, share: &str, read_only: bool) -> Result<()> {
    let _admission = crate::db::SmolvmDb::open()?.admit_workload_mutation(Some(name), &[])?;
    control(name, &format!("SHARE_REMOVE {} {share}", tag(read_only))).map(|_| ())
}

/// Live device exports, including shares bound by the container engine.
#[cfg(unix)]
pub(crate) fn shared_directories(name: &str, read_only: bool) -> Result<Vec<(String, PathBuf)>> {
    shared_directories_with_timeout(name, read_only, std::time::Duration::from_secs(60))
}

#[cfg(unix)]
pub(crate) fn shared_directories_with_timeout(
    name: &str,
    read_only: bool,
    timeout: std::time::Duration,
) -> Result<Vec<(String, PathBuf)>> {
    let reply = crate::agent::fork::control_socket_cmd_with_timeout(
        &control_socket_path(name),
        &format!("SHARE_LIST {}", tag(read_only)),
        timeout,
    )?;
    parse_shared_directories(&reply)
}

#[cfg(unix)]
fn parse_shared_directories(reply: &str) -> Result<Vec<(String, PathBuf)>> {
    // Do not trim: a host directory may end in spaces. Only the transport
    // removes the newline delimiting the control reply.
    let invalid = || Error::config("attach share", "invalid or unsupported live share listing");
    let entries = reply
        .strip_prefix("OK ")
        .or_else(|| (reply == "OK").then_some(""))
        .ok_or_else(invalid)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut shares = Vec::new();
    for entry in entries.split('\t') {
        let (share, source) = entry.split_once('=').ok_or_else(invalid)?;
        if share.is_empty() || share.len() > 64 || matches!(share, "." | "..")
            || !share.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !seen.insert(share) || seen.len() > 64
            || !Path::new(source).is_absolute() || source.chars().any(char::is_control)
            // The legacy wire format renders paths with Display. Refuse a
            // lossy path instead of mistaking it for a different real path.
            || source.contains('\u{fffd}')
        {
            return Err(invalid());
        }
        shares.push((share.to_owned(), PathBuf::from(source)));
    }
    shares.sort();
    Ok(shares)
}

/// Unmount the attached mount at `target` from the running machine `name`.
pub fn detach(name: &str, target: &Path) -> Result<AttachedMount> {
    let _admission = crate::db::SmolvmDb::open()?.admit_workload_mutation(Some(name), &[])?;
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
    #[cfg(unix)]
    #[test]
    fn live_share_listing_preserves_unicode_equals_and_trailing_spaces() {
        assert_eq!(
            parse_shared_directories("OK g._-=/tmp/é a= b ").unwrap(),
            vec![("g._-".into(), PathBuf::from("/tmp/é a= b "))]
        );
        assert!(parse_shared_directories("OK ").unwrap().is_empty());
        assert!(parse_shared_directories("OK").unwrap().is_empty());
        assert_eq!(
            parse_shared_directories("OK b=/tmp/b\ta=/tmp/a").unwrap()[0].0,
            "a"
        );
    }

    #[cfg(unix)]
    #[test]
    fn live_share_listing_refuses_partial_ambiguous_or_lossy_inventory() {
        for reply in [
            "",
            "OKevil",
            "ERR EINVAL unknown command",
            "OK a",
            "OK a=relative",
            "OK =/tmp/a",
            "OK ../=/tmp/a",
            "OK ..=/tmp/a",
            "OK a=/tmp/a\ta=/tmp/b",
            "OK a=/tmp/a\t",
            "OK a=/tmp/a\n",
            "OK a=/tmp/\u{fffd}",
        ] {
            assert!(
                parse_shared_directories(reply).is_err(),
                "accepted {reply:?}"
            );
        }
        let too_many = format!(
            "OK {}",
            (0..65)
                .map(|n| format!("s{n}=/tmp/{n}"))
                .collect::<Vec<_>>()
                .join("\t")
        );
        assert!(parse_shared_directories(&too_many).is_err());
    }
    #[test]
    fn share_attachment_keeps_trailing_spaces_and_refuses_unrepresentable_paths() {
        assert_eq!(
            share_source_arg(Path::new("/tmp/é= ")).unwrap(),
            "/tmp/é= /."
        );
        for path in ["/tmp/new\nline", "/tmp/tab\tname", "/tmp/nul\0name"] {
            assert!(share_source_arg(Path::new(path)).is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(
                share_source_arg(Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff"))).is_err()
            );
        }
    }
}
