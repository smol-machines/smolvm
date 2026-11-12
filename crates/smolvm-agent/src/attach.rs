//! Host directories attached to the running machine.
//!
//! The host boots every machine with two live virtio-fs devices (see
//! [`smolvm_protocol::ATTACH_TAG_RW`]) that start empty. To attach a host
//! directory, the host first adds it to one of them, where it appears as
//! `<device>/<share>`, then asks the agent to bind it onto the requested path.
//! Detaching runs the other way round: the agent unmounts it, then the host
//! removes it from the device, which also revokes any access the guest still
//! holds.
//!
//! The devices are mounted once at boot under [`ATTACH_ROOT`], readable only by
//! root. A machine running a workload container gets the bind inside every
//! container's mount namespace, since that is where its commands run; a bare
//! machine gets it in the machine root. Containers created later get every
//! attached mount in their spec ([`container_binds`]).
//!
//! What is attached lives here, in the agent: it is part of every checkpoint,
//! so a branch or a restored machine lists exactly what its guest has mounted.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use smolvm_protocol::AttachedMount;

/// Where the two live devices are mounted.
pub const ATTACH_ROOT: &str = "/run/smolvm/attach";

/// Set by the host when it attached the live devices to this machine.
const ENV_ATTACH: &str = "SMOLVM_ATTACH";

static DEVICES_MOUNTED: OnceLock<bool> = OnceLock::new();

/// Mounts attached in this boot, in the order they were attached.
static ATTACHED: Mutex<Vec<AttachedMount>> = Mutex::new(Vec::new());

/// The mounts attached in this boot.
pub fn list() -> Vec<AttachedMount> {
    ATTACHED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Bind mounts (source, target, read-only) a new workload container gets for
/// the attached mounts, leaving out targets its spec already mounts.
pub fn container_binds(existing_targets: &[&str]) -> Vec<(PathBuf, String, bool)> {
    list()
        .into_iter()
        .filter(|m| !existing_targets.contains(&m.target.as_str()))
        .map(|m| {
            (
                device_dir(m.read_only).join(&m.share),
                m.target,
                m.read_only,
            )
        })
        .collect()
}

/// Whether attached mounts work in this boot.
pub fn available() -> bool {
    DEVICES_MOUNTED.get().copied().unwrap_or(false)
}

fn device_dir(read_only: bool) -> PathBuf {
    Path::new(ATTACH_ROOT).join(if read_only { "ro" } else { "rw" })
}

/// Mount both live devices, when the host attached them. Called once at boot.
pub fn mount_devices_at_boot() {
    let requested = std::env::var(ENV_ATTACH).as_deref() == Ok("1");
    let mounted = requested
        && mount_devices()
            .map_err(|e| tracing::warn!(error = %e, "attached mounts unavailable"))
            .is_ok();
    let _ = DEVICES_MOUNTED.set(mounted);
}

#[cfg(target_os = "linux")]
fn mount_devices() -> Result<(), String> {
    use smolvm_protocol::{ATTACH_TAG_RO, ATTACH_TAG_RW};
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(ATTACH_ROOT).map_err(|e| format!("create {ATTACH_ROOT}: {e}"))?;
    std::fs::set_permissions(ATTACH_ROOT, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod {ATTACH_ROOT}: {e}"))?;
    for (tag, read_only) in [(ATTACH_TAG_RW, false), (ATTACH_TAG_RO, true)] {
        let dir = device_dir(read_only);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let source = cstring(tag)?;
        let target = cstring(&dir.to_string_lossy())?;
        let fstype = cstring("virtiofs")?;
        let mut flags = libc::MS_NOSUID | libc::MS_NODEV;
        if read_only {
            flags |= libc::MS_RDONLY;
        }
        // SAFETY: NUL-terminated strings that outlive the call.
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(format!(
                "mount {tag} at {}: {}",
                dir.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_devices() -> Result<(), String> {
    Err("attached mounts need a Linux guest".to_string())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn cstring(s: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(s).map_err(|_| format!("{s:?} contains a NUL byte"))
}

/// The names the host gives shares on the live devices.
fn valid_share(share: &str) -> bool {
    !share.is_empty()
        && share.len() <= 64
        && share != "."
        && share != ".."
        && share
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_target(target: &str) -> Result<(), String> {
    let path = Path::new(target);
    if !path.is_absolute() {
        return Err(format!("mount target {target} is not absolute"));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("mount target {target} contains '..'"));
    }
    if path == Path::new("/") || path.starts_with(ATTACH_ROOT) {
        return Err(format!("{target} cannot be a mount target"));
    }
    Ok(())
}

/// Bind the attached `share` onto `target`. `source` is the host directory,
/// kept only to list it.
pub fn attach(share: &str, source: &str, read_only: bool, target: &str) -> Result<(), String> {
    if !available() {
        return Err(
            "this machine was booted without attached mount support; restart it".to_string(),
        );
    }
    if !valid_share(share) {
        return Err(format!("invalid share name {share:?}"));
    }
    valid_target(target)?;
    let mut attached = ATTACHED.lock().unwrap_or_else(|e| e.into_inner());
    if attached.iter().any(|m| m.target == target) {
        return Err(format!("{target} already has an attached mount"));
    }
    let device_path = device_dir(read_only).join(share);
    if !device_path.is_dir() {
        return Err(format!("share {share} is not attached to this machine"));
    }
    if crate::nsfile::has_live_containers() {
        crate::nsfile::attach_in_every_container(&device_path, target, read_only)?;
    } else {
        bind_in_root(&device_path, target, read_only)?;
    }
    attached.push(AttachedMount {
        share: share.to_string(),
        source: source.to_string(),
        target: target.to_string(),
        read_only,
    });
    Ok(())
}

/// Unmount the attached mount at `target`, from the machine root and from every
/// workload container, wherever it was bound.
pub fn detach(target: &str) -> Result<(), String> {
    valid_target(target)?;
    let mut attached = ATTACHED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(index) = attached.iter().position(|m| m.target == target) else {
        return Err(format!("nothing is attached at {target}"));
    };
    if crate::nsfile::has_live_containers() {
        crate::nsfile::detach_in_every_container(target)?;
    }
    unmount_in_root(target)?;
    let mount = attached.remove(index);
    // The host removes the share next; nothing here may keep it mounted.
    crate::mount_owner::forget(&device_dir(mount.read_only).join(&mount.share));
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_in_root(source: &Path, target: &str, read_only: bool) -> Result<(), String> {
    std::fs::create_dir_all(target).map_err(|e| format!("create {target}: {e}"))?;
    let source_c = cstring(&source.to_string_lossy())?;
    let target_c = cstring(target)?;
    // SAFETY: NUL-terminated strings that outlive the calls.
    unsafe {
        if libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        ) != 0
        {
            return Err(format!(
                "bind {target}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // The host already refuses writes; this makes the guest report them
        // as a read-only filesystem instead of a failed write.
        if read_only
            && libc::mount(
                std::ptr::null(),
                target_c.as_ptr(),
                std::ptr::null(),
                // A bind remount replaces every per-mount flag, so
                // keep the ones the device was mounted with.
                libc::MS_REMOUNT
                    | libc::MS_BIND
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                std::ptr::null(),
            ) != 0
        {
            let error = std::io::Error::last_os_error();
            libc::umount2(target_c.as_ptr(), libc::MNT_DETACH);
            return Err(format!("make {target} read-only: {error}"));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn bind_in_root(_source: &Path, _target: &str, _read_only: bool) -> Result<(), String> {
    Err("attached mounts need a Linux guest".to_string())
}

/// Lazily unmount `target` in the agent's namespace; one that is not a mount
/// point (the bind went to the containers) is left alone.
#[cfg(target_os = "linux")]
fn unmount_in_root(target: &str) -> Result<(), String> {
    let target_c = cstring(target)?;
    // SAFETY: a NUL-terminated path; a lazy unmount lets open files finish.
    if unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) } != 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINVAL) | Some(libc::ENOENT)
        ) {
            return Err(format!("unmount {target}: {error}"));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn unmount_in_root(_target: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_host_share_names_and_plain_absolute_targets_are_accepted() {
        assert!(valid_share("m0123abcd"));
        assert!(!valid_share(""));
        assert!(!valid_share(".."));
        assert!(!valid_share("a/b"));
        assert!(valid_target("/app").is_ok());
        assert!(valid_target("relative").is_err());
        assert!(valid_target("/app/../etc").is_err());
        assert!(valid_target("/").is_err());
        assert!(valid_target("/run/smolvm/attach/rw").is_err());
    }

    #[test]
    fn new_containers_get_every_attached_mount_their_spec_does_not_already_have() {
        ATTACHED.lock().unwrap().extend([
            AttachedMount {
                share: "ma".into(),
                source: "/host/a".into(),
                target: "/a".into(),
                read_only: false,
            },
            AttachedMount {
                share: "mb".into(),
                source: "/host/b".into(),
                target: "/b".into(),
                read_only: true,
            },
        ]);
        let binds = container_binds(&["/a"]);
        ATTACHED.lock().unwrap().clear();
        assert_eq!(
            binds,
            vec![(
                PathBuf::from("/run/smolvm/attach/ro/mb"),
                "/b".to_string(),
                true
            )]
        );
    }
}
