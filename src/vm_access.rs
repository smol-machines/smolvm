//! What a VMM can reach once it drops to its machine's own uid.
//!
//! Under the per-VM uid drop, every host path a machine uses is opened by the
//! VMM as that uid. Those paths get their modes from many places: the process
//! umask, the `tempfile` crate (always 0600), the modes a pack archived, an
//! explicit 0700 in smolvm's own code. Nothing tied them to what the dropped uid
//! needs, so each mismatch surfaced as a bare EACCES after boot, and only in
//! some setups: a pack built under umask 077, an archive staged from stdin, a
//! cache made under a root umask of 077.
//!
//! [`ensure`] closes that class at the one place that knows every path: just
//! before the drop, still root, it asks the kernel whether the VM's uid can do
//! what each path needs (`faccessat(AT_EACCESS)` under the VM's fs ids and
//! groups, so ancestors, ACLs and idmapped mounts all count). A denial on a
//! path smolvm owns is repaired by adding the missing read or search bits for
//! others, never write. Anything else stops the boot with the exact component
//! that blocks it, instead of an EACCES nobody can trace. User mounts and the
//! SSH agent socket only warn: a machine that never touches them boots today.

use std::path::{Path, PathBuf};

use crate::agent::boot_config::BootConfig;

/// The access a path needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// Read a file.
    Read,
    /// Read and write a file.
    ReadWrite,
    /// List and enter a directory.
    List,
    /// List, enter and create in a directory.
    ListWrite,
    /// Create entries in a directory (a socket, a log).
    Create,
}

// Only the Linux check uses the mode and repair helpers; the uid drop is Linux's.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Need {
    #[cfg(target_os = "linux")]
    fn mode(self) -> libc::c_int {
        match self {
            Need::Read => libc::R_OK,
            Need::ReadWrite => libc::R_OK | libc::W_OK,
            Need::List => libc::R_OK | libc::X_OK,
            Need::ListWrite => libc::R_OK | libc::W_OK | libc::X_OK,
            Need::Create => libc::W_OK | libc::X_OK,
        }
    }

    /// The bits for others a repair may add: read and search, never write.
    fn repair_bits(self, is_dir: bool) -> u32 {
        match (self, is_dir) {
            (Need::Read, _) => 0o004,
            (Need::List, true) => 0o005,
            _ => 0,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Need::Read => "read",
            Need::ReadWrite => "read and write",
            Need::List => "list",
            Need::ListWrite => "list and write",
            Need::Create => "create files in",
        }
    }
}

/// What a denial does to the boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// The machine cannot run without it.
    Required,
    /// Only the workload that uses it fails; warn.
    Optional,
}

/// One path the VM's uid must be able to use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    /// The path as the VMM opens it.
    pub path: PathBuf,
    /// What it must be able to do there.
    pub need: Need,
    /// What the path is, for messages.
    pub what: &'static str,
    /// Stop the boot, or warn.
    pub severity: Severity,
    /// The smolvm-owned tree a repair may change, as `(root as the VMM sees
    /// it, root on disk)`: components of `path` at or below the first are
    /// repaired at the same place under the second. The two differ for an
    /// idmapped mount, which refuses changes made through it. `None`: never
    /// repaired.
    pub repair: Option<(PathBuf, PathBuf)>,
}

/// Every path `config` hands the VMM, and what it needs there.
pub fn requirements(config: &BootConfig) -> Vec<Requirement> {
    let mut reqs = Vec::new();
    let required = |path: &Path, need, what| Requirement {
        path: path.to_path_buf(),
        need,
        what,
        severity: Severity::Required,
        repair: None,
    };
    reqs.push(Requirement {
        repair: Some((config.rootfs_path.clone(), config.rootfs_path.clone())),
        ..required(&config.rootfs_path, Need::List, "agent rootfs")
    });
    reqs.push(required(
        &config.storage_disk_path,
        Need::ReadWrite,
        "storage disk",
    ));
    reqs.push(required(
        &config.overlay_disk_path,
        Need::ReadWrite,
        "overlay disk",
    ));
    for (disk, read_only, _) in &config.extra_disks {
        let need = if *read_only {
            Need::Read
        } else {
            Need::ReadWrite
        };
        reqs.push(required(disk, need, "extra disk"));
    }
    if let Some(dir) = config.vsock_socket.parent() {
        reqs.push(required(dir, Need::Create, "machine directory"));
    }
    if let Some(layers) = &config.packed_layers_dir {
        // Who owns what is here decides what may be repaired: a pack, through
        // its idmap source (the mount refuses changes); a staged image archive,
        // anywhere in smolvm's archive cache; a user's own rootfs directory
        // (`--image ./rootfs/`), never.
        let archive_cache = crate::data::image_source::archive_cache_base()
            .ok()
            .filter(|cache| layers.starts_with(cache));
        let repair = match (&config.pack_idmap_source, archive_cache) {
            (Some(source), _) => Some((layers.clone(), source.clone())),
            (None, Some(cache)) => Some((cache.clone(), cache)),
            (None, None) => None,
        };
        reqs.push(Requirement {
            repair: repair.clone(),
            ..required(layers, Need::List, "packed layers")
        });
        // What the guest opens directly under it: each layer of a pack (its
        // extracted directory or staged tar, and `layer-order`), or a local
        // image's `archive.tar`. What is inside a layer keeps the image's own
        // modes and is not checked.
        if let Ok(entries) = std::fs::read_dir(layers) {
            for entry in entries.flatten() {
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                let need = if kind.is_dir() {
                    Need::List
                } else if kind.is_file() {
                    Need::Read
                } else {
                    continue;
                };
                reqs.push(Requirement {
                    repair: repair.clone(),
                    ..required(&entry.path(), need, "packed layer")
                });
            }
        }
    }
    for mount in &config.mounts {
        let need = if mount.read_only {
            Need::List
        } else {
            Need::ListWrite
        };
        if mount.source.is_dir() {
            reqs.push(Requirement {
                severity: Severity::Optional,
                ..required(&mount.source, need, "mounted directory")
            });
        }
    }
    if let Some(socket) = &config.ssh_agent_socket {
        reqs.push(Requirement {
            severity: Severity::Optional,
            ..required(socket, Need::ReadWrite, "SSH agent socket")
        });
    }
    reqs
}

/// A path the VM's uid cannot use, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    /// The path and what it needed.
    pub requirement: Requirement,
    /// The component that blocks: an ancestor it cannot enter, or the path.
    pub blocked_at: PathBuf,
    /// `ls -l`-style mode and owner of that component.
    pub detail: String,
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = &self.requirement;
        write!(
            f,
            "the machine's uid cannot {} its {} {}",
            r.need.describe(),
            r.what,
            r.path.display()
        )?;
        if self.blocked_at == r.path {
            write!(f, " ({})", self.detail)
        } else {
            write!(
                f,
                ": {} blocks it ({})",
                self.blocked_at.display(),
                self.detail
            )
        }
    }
}

/// Check `reqs` as the VM's uid, repair what smolvm owns, and return what is
/// still denied, split into (required, optional). Linux, as root, just before
/// the drop; the supplementary groups are set to the drop's own.
#[cfg(target_os = "linux")]
pub fn check_and_repair(uid: u32, gid: u32, reqs: &[Requirement]) -> (Vec<Denial>, Vec<Denial>) {
    let groups = crate::process::vm_supplementary_groups();
    // SAFETY: setgroups on a local vector; the drop sets the same list next.
    unsafe {
        libc::setgroups(groups.len(), groups.as_ptr());
    }
    let mut required = Vec::new();
    let mut optional = Vec::new();
    for req in reqs {
        let Some(mut denial) = as_vm(uid, gid, || first_denial(req)) else {
            continue;
        };
        if repair(&denial, uid, gid, &groups) {
            match as_vm(uid, gid, || first_denial(req)) {
                None => {
                    eprintln!(
                        "[vm-access] made {} reachable for the machine's uid ({})",
                        denial.blocked_at.display(),
                        denial.detail
                    );
                    continue;
                }
                Some(still) => denial = still,
            }
        }
        match req.severity {
            Severity::Required => required.push(denial),
            Severity::Optional => optional.push(denial),
        }
    }
    (required, optional)
}

/// Run `f` with this thread's filesystem uid and gid set to the VM's, so
/// `faccessat(AT_EACCESS)` answers for that uid. Changing fsuid away from 0
/// also clears the DAC override capabilities, restored on the way back.
#[cfg(target_os = "linux")]
fn as_vm<T>(uid: u32, gid: u32, f: impl FnOnce() -> T) -> T {
    // SAFETY: setfsuid/setfsgid only change this thread's filesystem ids.
    unsafe {
        libc::setfsgid(gid);
        libc::setfsuid(uid);
    }
    let result = f();
    // SAFETY: as above; back to root's.
    unsafe {
        libc::setfsuid(0);
        libc::setfsgid(0);
    }
    result
}

#[cfg(target_os = "linux")]
fn can(path: &Path, mode: libc::c_int) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a valid NUL-terminated path.
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), mode, libc::AT_EACCESS) == 0 }
}

/// The first component of `req.path` the current fs ids cannot use: an
/// ancestor that cannot be entered, or the path itself.
#[cfg(target_os = "linux")]
fn first_denial(req: &Requirement) -> Option<Denial> {
    if can(&req.path, req.need.mode()) {
        return None;
    }
    let blocked_at = req
        .path
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .find(|dir| !dir.as_os_str().is_empty() && !can(dir, libc::X_OK))
        .unwrap_or(&req.path)
        .to_path_buf();
    Some(Denial {
        detail: describe_mode(&blocked_at),
        blocked_at,
        requirement: req.clone(),
    })
}

#[cfg(target_os = "linux")]
fn describe_mode(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => format!(
            "mode {:o}, owner {}:{}",
            m.mode() & 0o7777,
            m.uid(),
            m.gid()
        ),
        Err(e) => e.to_string(),
    }
}

/// How far to shift an others-class mode bit so it lands in the class the
/// kernel checks for the VM: the owner's bits when the VM's uid owns the file,
/// the group's when the file's group is one of the VM's groups, else others'.
/// Adding a bit to any other class changes nothing for the VM (a 0640 file
/// whose group is the VM's gid stays unreadable after o+r).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn class_shift(file_uid: u32, file_gid: u32, uid: u32, gid: u32, groups: &[u32]) -> u32 {
    if file_uid == uid {
        6
    } else if file_gid == gid || groups.contains(&file_gid) {
        3
    } else {
        0
    }
}

/// Add the missing read or search bits, in the class the kernel checks for the
/// VM, to the blocking component when it lies in a tree smolvm owns. True when
/// something changed.
#[cfg(target_os = "linux")]
fn repair(denial: &Denial, uid: u32, gid: u32, groups: &[u32]) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let req = &denial.requirement;
    let Some((seen_root, disk_root)) = &req.repair else {
        return false;
    };
    let Ok(rel) = denial.blocked_at.strip_prefix(seen_root) else {
        return false;
    };
    let target = disk_root.join(rel);
    // Never follow a link: a repair must not reach outside the tree.
    let Ok(meta) = std::fs::symlink_metadata(&target) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        return false;
    }
    let is_dir = meta.is_dir();
    let bits = if denial.blocked_at == req.path {
        req.need.repair_bits(is_dir)
    } else if is_dir {
        0o001 // an ancestor only needs search
    } else {
        0
    };
    // The class comes from the path as the VM sees it: through an idmapped mount
    // the on-disk owner is not the one the kernel checks (a group-root file shows
    // the VM's gid there), so the on-disk ids would pick the wrong class.
    let Ok(seen) = std::fs::symlink_metadata(&denial.blocked_at) else {
        return false;
    };
    let bits = bits << class_shift(seen.uid(), seen.gid(), uid, gid, groups);
    let mode = meta.permissions().mode() & 0o7777;
    if bits == 0 || mode & bits == bits {
        return false;
    }
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode | bits)).is_ok()
}

/// [`requirements`] then [`check_and_repair`]: warn about optional paths,
/// and refuse the boot with every required one still denied.
#[cfg(target_os = "linux")]
pub fn ensure(config: &BootConfig, uid: u32, gid: u32) -> Result<(), String> {
    let (required, optional) = check_and_repair(uid, gid, &requirements(config));
    for denial in &optional {
        eprintln!("[vm-access] warning: {denial}");
    }
    if required.is_empty() {
        return Ok(());
    }
    Err(required
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repairs_add_read_and_search_but_never_write() {
        assert_eq!(Need::Read.repair_bits(false), 0o004);
        assert_eq!(Need::List.repair_bits(true), 0o005);
        for need in [Need::ReadWrite, Need::ListWrite, Need::Create] {
            assert_eq!(need.repair_bits(true), 0);
            assert_eq!(need.repair_bits(false), 0);
        }
        // A file is never made searchable by a List repair.
        assert_eq!(Need::List.repair_bits(false), 0);
    }

    #[test]
    fn a_repair_lands_in_the_class_the_kernel_checks_for_the_vm() {
        let (uid, gid) = (2_000_079, 2_000_079);
        // Others' bits only help a VM that neither owns the file nor shares its group.
        assert_eq!(class_shift(0, 0, uid, gid, &[]), 0);
        assert_eq!(class_shift(uid, 0, uid, gid, &[]), 6);
        // A pack layer owned by nobody with the VM's gid (seen as 0604 in production).
        assert_eq!(class_shift(65_534, gid, uid, gid, &[]), 3);
        assert_eq!(
            Need::Read.repair_bits(false) << class_shift(65_534, gid, uid, gid, &[]),
            0o040
        );
        assert_eq!(class_shift(0, 36, uid, gid, &[36]), 3);
    }

    #[test]
    fn a_denial_names_the_component_that_blocks() {
        let req = Requirement {
            path: PathBuf::from("/cache/hash/archive.tar"),
            need: Need::Read,
            what: "packed layer",
            severity: Severity::Required,
            repair: None,
        };
        let at_ancestor = Denial {
            requirement: req.clone(),
            blocked_at: PathBuf::from("/cache"),
            detail: "mode 700, owner 0:0".into(),
        };
        assert_eq!(
            at_ancestor.to_string(),
            "the machine's uid cannot read its packed layer /cache/hash/archive.tar: \
             /cache blocks it (mode 700, owner 0:0)"
        );
        let at_path = Denial {
            blocked_at: req.path.clone(),
            ..at_ancestor
        };
        assert!(at_path
            .to_string()
            .ends_with("archive.tar (mode 700, owner 0:0)"));
    }
}
