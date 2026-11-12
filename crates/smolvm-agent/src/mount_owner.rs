//! The owner a non-root workload sees on a host directory.
//!
//! A host directory reaches the guest over virtio-fs with the host's owner on
//! it: the Mac user's uid 501 on macOS, the uid smolvm runs as on Linux. A
//! workload that runs as another non-root user (uid 1000 in most images) sees a
//! directory it does not own and cannot write to it. Nothing on the host can
//! fix that: the directory has to keep belonging to the host user there.
//!
//! So the workload container binds an id-mapped clone of the share instead of
//! the share itself (`mount_setattr(MOUNT_ATTR_IDMAP)`). The mapping swaps two
//! ids and leaves every other one alone: the owner of the share's root shows up
//! as the workload user, and what the workload user creates is stored as the
//! owner of the share's root, so the host keeps seeing its own files. The group
//! is swapped the same way, which also covers a Linux host whose user has the
//! workload's uid but another group: such a host refuses a file created with a
//! group other than its user's own.
//!
//! Nothing is mapped for a root workload, or when the share's root already
//! belongs to the workload user and group, or for anything that is not a
//! virtio-fs share (a staged copy, a disk volume, the cache disk). Nothing is
//! mapped for a share whose root belongs to root either: a host that runs
//! smolvm as root stores each file under the id the workload used, the way a
//! container bind mount does, and directories prepared for that keep working;
//! a host user that is not root could not write to such a directory anyway. A
//! share that cannot be mapped is bound as it is, with a warning: the workload
//! starts either way.
//!
//! The swap is exact both ways, which has one visible edge: a file the host
//! records as owned by the workload's uid shows up as owned by the host uid
//! through the mapped mount.

use std::path::{Path, PathBuf};

/// How many ids a mapping has to cover: every id but 4294967295, which the
/// kernel keeps as "no id".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ID_COUNT: u64 = u32::MAX as u64;

/// The two ids swapped for the user and for the group, each when it differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct OwnerMapping {
    /// (owner of the share's root, workload uid), when they differ.
    uid: Option<(u32, u32)>,
    /// (group of the share's root, workload gid), when they differ.
    gid: Option<(u32, u32)>,
}

/// The mapping a workload running as `workload` (uid, gid) needs for a share
/// whose root belongs to `share` (uid, gid), or `None` when it is bound as it is.
///
/// A root workload reads and writes anything already, a share whose root has
/// the workload's user and group needs nothing, and a share whose root belongs
/// to root keeps the host's ids as they are. Swapping the group as well
/// gives new files the group the host's own files have, so group permissions
/// keep meaning what they mean on the host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn owner_mapping(share: (u32, u32), workload: (u32, u32)) -> Option<OwnerMapping> {
    let (share_uid, share_gid) = share;
    let (uid, gid) = workload;
    if uid == 0 || uid == u32::MAX || share_uid == 0 || share_uid == u32::MAX {
        return None;
    }
    let uid = (uid != share_uid).then_some((share_uid, uid));
    let gid =
        (gid != share_gid && gid != u32::MAX && share_gid != u32::MAX).then_some((share_gid, gid));
    (uid.is_some() || gid.is_some()).then_some(OwnerMapping { uid, gid })
}

/// The ranges (first id, mapped first id, count) of a map that swaps `a` and
/// `b` and maps every other id to itself, in ascending order with no gaps.
/// With `a == b` that is the identity map.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn swap_ranges(a: u32, b: u32) -> Vec<(u64, u64, u64)> {
    let (low, high) = (u64::from(a.min(b)), u64::from(a.max(b)));
    if low == high {
        return vec![(0, 0, ID_COUNT)];
    }
    [
        (0, 0, low),
        (low, high, 1),
        (low + 1, low + 1, high - low - 1),
        (high, low, 1),
        (high + 1, high + 1, ID_COUNT.saturating_sub(high + 1)),
    ]
    .into_iter()
    .filter(|(_, _, count)| *count > 0)
    .collect()
}

/// The text of a `uid_map` or `gid_map` that swaps `pair`, or maps every id to
/// itself without one. A swap is its own inverse, so it does not matter which
/// column the kernel reads as the id on disk.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn id_map(pair: Option<(u32, u32)>) -> String {
    let (a, b) = pair.unwrap_or((0, 0));
    swap_ranges(a, b)
        .into_iter()
        .map(|(first, mapped, count)| format!("{first} {mapped} {count}\n"))
        .collect()
}

/// Where the mapped clone of `share` is mounted. The mapping is part of the
/// path, so a clone is only ever reused for the mapping it was made with.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn staged_path(share: &Path, mapping: OwnerMapping) -> PathBuf {
    let name = [("uid", mapping.uid), ("gid", mapping.gid)]
        .into_iter()
        .filter_map(|(kind, pair)| {
            pair.map(|(share, workload)| format!("{kind}-{share}-{workload}"))
        })
        .collect::<Vec<_>>()
        .join(".");
    Path::new(crate::paths::IDMAPPED_MOUNT_ROOT)
        .join(name)
        .join(share.strip_prefix("/").unwrap_or(share))
}

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct MountEntry {
    /// `major:minor` of the filesystem.
    device: String,
    /// The directory of the filesystem this mount shows.
    root: String,
    mount_point: String,
    options: String,
    fstype: String,
}

/// Undo the octal escapes mountinfo uses for space, tab, newline and backslash.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|digits| bytes[i] == b'\\' && digits.iter().all(|d| (b'0'..=b'7').contains(d)));
        match octal.and_then(|digits| u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok())
        {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_mountinfo(mountinfo: &str) -> Vec<MountEntry> {
    mountinfo
        .lines()
        .filter_map(|line| {
            // id parent major:minor root mount-point options [optional...] - fstype source super-options
            let (mount, filesystem) = line.split_once(" - ")?;
            let mut fields = mount.split(' ');
            let device = fields.nth(2)?.to_string();
            let root = unescape(fields.next()?);
            let mount_point = unescape(fields.next()?);
            let options = fields.next()?.to_string();
            let fstype = filesystem.split(' ').next()?.to_string();
            Some(MountEntry {
                device,
                root,
                mount_point,
                options,
                fstype,
            })
        })
        .collect()
}

/// The mount `path` is on, and the directory of that filesystem `path` is:
/// what a mount made from `path` reports as its root.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn locate<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<(&'a MountEntry, String)> {
    // The longest mount point that contains the path; of several mounts
    // stacked on one mount point, the last listed is the one on top.
    let covering = mounts
        .iter()
        .filter(|m| path.starts_with(&m.mount_point))
        .rev()
        .max_by_key(|m| Path::new(&m.mount_point).components().count())?;
    let below = path.strip_prefix(&covering.mount_point).ok()?;
    let root = Path::new(&covering.root).join(below);
    Some((covering, root.to_string_lossy().into_owned()))
}

/// Whether the mount on top of `staged` is an id-mapped mount of the same
/// directory of the same filesystem as the share. `None` when nothing is
/// mounted there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn staged_mount_is_current(
    mounts: &[MountEntry],
    staged: &Path,
    share_device: &str,
    share_root: &str,
) -> Option<bool> {
    let entry = mounts
        .iter()
        .rev()
        .find(|m| Path::new(&m.mount_point) == staged)?;
    Some(
        entry.device == share_device
            && entry.root == share_root
            && entry.options.split(',').any(|option| option == "idmapped"),
    )
}

/// The directory a container whose process runs as `uid:gid` binds for the
/// host directory mounted at `share`: a clone that maps the directory's owner
/// to that user when the two differ, else `share` itself. Never fails: a share
/// that cannot be mapped is bound unmapped, which is what every container got
/// before.
#[cfg(target_os = "linux")]
pub fn bind_source(share: &Path, uid: u32, gid: u32) -> PathBuf {
    if uid == 0 {
        return share.to_path_buf();
    }
    match linux::mapped_clone(share, uid, gid) {
        Ok(Some(staged)) => staged,
        Ok(None) => share.to_path_buf(),
        Err(reason) => {
            tracing::warn!(
                share = %share.display(),
                uid,
                gid,
                %reason,
                "could not map the host directory's owner to the workload user; mounting it unmapped"
            );
            share.to_path_buf()
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn bind_source(share: &Path, _uid: u32, _gid: u32) -> PathBuf {
    share.to_path_buf()
}

/// Drop every mapped clone of `share`. Called when the share itself goes away
/// (a detached mount, a virtio-fs session that died with the machine this one
/// was branched from) so no clone keeps the old directory alive or gets reused
/// for a new share of the same name.
#[cfg(target_os = "linux")]
pub fn forget(share: &Path) {
    linux::forget(share);
}

#[cfg(not(target_os = "linux"))]
pub fn forget(_share: &Path) {}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::nsfile::{
        AGENT_BINARY, MOVE_MOUNT_F_EMPTY_PATH, OPEN_TREE_CLONE, SYS_MOVE_MOUNT, SYS_OPEN_TREE,
        USERNS_HOLD_ARGS,
    };
    use std::ffi::CString;
    use std::fs::File;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    /// `mount_setattr(2)`: the same number on x86_64 and aarch64, and like its
    /// neighbours in [`crate::nsfile`] not exported by the musl `libc`.
    const SYS_MOUNT_SETATTR: libc::c_long = 442;
    const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;

    /// `struct mount_attr`.
    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    /// Containers are created from several threads; one clone is staged at a time
    /// so two of them never race to mount the same path.
    static STAGING: Mutex<()> = Mutex::new(());

    fn mountinfo() -> Result<Vec<MountEntry>, String> {
        std::fs::read_to_string("/proc/self/mountinfo")
            .map(|text| parse_mountinfo(&text))
            .map_err(|e| format!("read /proc/self/mountinfo: {e}"))
    }

    fn cstring(path: &Path) -> Result<CString, String> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("{} contains a NUL byte", path.display()))
    }

    fn detach(path: &Path) -> Result<(), String> {
        let path_c = cstring(path)?;
        // SAFETY: a NUL-terminated path; a lazy unmount never reads the
        // filesystem, so it returns even when the share behind it is dead.
        if unsafe { libc::umount2(path_c.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(format!(
                "unmount {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(super) fn mapped_clone(
        share: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<Option<PathBuf>, String> {
        let _staging = STAGING.lock().unwrap_or_else(|e| e.into_inner());
        let mounts = mountinfo()?;
        let Some((mount, share_root)) = locate(&mounts, share) else {
            return Ok(None);
        };
        if mount.fstype != "virtiofs" {
            return Ok(None);
        }
        let owner = std::fs::metadata(share).map_err(|e| format!("stat: {e}"))?;
        let Some(mapping) = owner_mapping((owner.uid(), owner.gid()), (uid, gid)) else {
            return Ok(None);
        };

        // Only the mount table says whether the staged clone can be reused: a
        // clone of a share that died (a branch resumes with fresh virtio-fs
        // devices) must not be touched, a lookup through it may never return.
        let staged = staged_path(share, mapping);
        match staged_mount_is_current(&mounts, &staged, &mount.device, &share_root) {
            Some(true) => return Ok(Some(staged)),
            Some(false) => detach(&staged)?,
            None => {}
        }
        std::fs::create_dir_all(&staged)
            .map_err(|e| format!("create {}: {e}", staged.display()))?;
        std::fs::set_permissions(
            crate::paths::IDMAPPED_MOUNT_ROOT,
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(|e| format!("chmod {}: {e}", crate::paths::IDMAPPED_MOUNT_ROOT))?;

        let userns = user_namespace(&id_map(mapping.uid), &id_map(mapping.gid))?;
        mount_mapped(share, &staged, &userns)?;
        tracing::info!(
            share = %share.display(),
            owner = %format_args!("{}:{}", owner.uid(), owner.gid()),
            workload = %format_args!("{uid}:{gid}"),
            "mapped the host directory's owner to the workload user"
        );
        Ok(Some(staged))
    }

    /// A user namespace with the given id maps, as a descriptor for
    /// `mount_setattr`. A namespace only comes into being with a process in it,
    /// and the agent cannot `fork` and keep running (it is multithreaded), so a
    /// re-exec of this binary is started in a new one and waits on its stdin
    /// while the agent, as root outside it, writes the maps. The descriptor
    /// keeps the namespace alive after the helper is gone.
    fn user_namespace(uid_map: &str, gid_map: &str) -> Result<File, String> {
        let mut helper = Command::new(AGENT_BINARY);
        helper
            .args(USERNS_HOLD_ARGS)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: unshare is a plain system call, safe between fork and exec.
        unsafe {
            helper.pre_exec(|| {
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut helper = helper
            .spawn()
            .map_err(|e| format!("start a process in a new user namespace: {e}"))?;
        let pid = helper.id();
        let namespace = (|| {
            for (file, map) in [("uid_map", uid_map), ("gid_map", gid_map)] {
                std::fs::write(format!("/proc/{pid}/{file}"), map)
                    .map_err(|e| format!("write {file}: {e}"))?;
            }
            File::open(format!("/proc/{pid}/ns/user"))
                .map_err(|e| format!("open user namespace: {e}"))
        })();
        // Closing its stdin ends the helper.
        drop(helper.stdin.take());
        let _ = helper.wait();
        namespace
    }

    /// Clone the mount at `share`, give the clone the id maps of `userns`, and
    /// mount it at `staged`.
    fn mount_mapped(share: &Path, staged: &Path, userns: &File) -> Result<(), String> {
        let share_c = cstring(share)?;
        // SAFETY: a NUL-terminated path; the result is checked before use.
        let fd = unsafe {
            libc::syscall(
                SYS_OPEN_TREE,
                libc::AT_FDCWD,
                share_c.as_ptr(),
                OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(format!("open_tree: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: open_tree returned a new descriptor this function owns.
        let tree = unsafe { File::from_raw_fd(fd as libc::c_int) };
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: userns.as_raw_fd() as u64,
        };
        let empty = c"";
        // SAFETY: `tree` is a live detached mount, the path is NUL-terminated
        // and `attr` is a `struct mount_attr` of the size passed.
        let rc = unsafe {
            libc::syscall(
                SYS_MOUNT_SETATTR,
                tree.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH,
                &attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            )
        };
        if rc != 0 {
            return Err(format!(
                "mount_setattr: {}",
                std::io::Error::last_os_error()
            ));
        }
        let staged_c = cstring(staged)?;
        // SAFETY: as above; `staged` is a directory this module created.
        let rc = unsafe {
            libc::syscall(
                SYS_MOVE_MOUNT,
                tree.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_FDCWD,
                staged_c.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            )
        };
        if rc != 0 {
            return Err(format!(
                "move_mount to {}: {}",
                staged.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(super) fn forget(share: &Path) {
        let _staging = STAGING.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(mounts) = mountinfo() else {
            return;
        };
        let below_share = share.strip_prefix("/").unwrap_or(share);
        for mount in mounts.iter().rev() {
            // <root>/<mapping>/<share path>
            let is_clone = Path::new(&mount.mount_point)
                .strip_prefix(crate::paths::IDMAPPED_MOUNT_ROOT)
                .ok()
                .and_then(|below_root| {
                    let mut components = below_root.components();
                    components.next()?;
                    Some(components.as_path() == below_share)
                })
                .unwrap_or(false);
            if is_clone {
                if let Err(reason) = detach(Path::new(&mount.mount_point)) {
                    tracing::warn!(%reason, "could not drop the mapped clone of a host directory");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_non_root_workload_that_does_not_own_the_share_gets_a_mapping() {
        // A Mac user's directory (501:20) for the usual image user.
        assert_eq!(
            owner_mapping((501, 20), (1000, 1000)),
            Some(OwnerMapping {
                uid: Some((501, 1000)),
                gid: Some((20, 1000)),
            })
        );
        // Root reads and writes it as it is.
        assert_eq!(owner_mapping((501, 20), (0, 0)), None);
        // The workload user and group already own it.
        assert_eq!(owner_mapping((1000, 1000), (1000, 1000)), None);
        // Same user, another group: only the group is swapped.
        assert_eq!(
            owner_mapping((1000, 1001), (1000, 1000)),
            Some(OwnerMapping {
                uid: None,
                gid: Some((1001, 1000)),
            })
        );
        // Same group: only the user is swapped.
        assert_eq!(
            owner_mapping((501, 1000), (1000, 1000)),
            Some(OwnerMapping {
                uid: Some((501, 1000)),
                gid: None,
            })
        );
        // A root-owned share keeps the host's ids, whatever its group.
        assert_eq!(owner_mapping((0, 0), (1000, 1000)), None);
        assert_eq!(owner_mapping((0, 20), (1000, 1000)), None);
        // Only the owner decides that: a group of 0 is swapped like any other.
        assert_eq!(
            owner_mapping((501, 0), (1000, 1000)),
            Some(OwnerMapping {
                uid: Some((501, 1000)),
                gid: Some((0, 1000)),
            })
        );
        // 4294967295 is not an id.
        assert_eq!(owner_mapping((u32::MAX, 20), (1000, 1000)), None);
        assert_eq!(
            owner_mapping((501, u32::MAX), (1000, 1000)),
            Some(OwnerMapping {
                uid: Some((501, 1000)),
                gid: None,
            })
        );
    }

    /// What `ranges` maps `id` to, checking on the way that they are in order
    /// and leave no gap, which is what the kernel accepts.
    fn mapped(ranges: &[(u64, u64, u64)], id: u64) -> u64 {
        let mut next = 0;
        let mut result = None;
        for (first, to, count) in ranges {
            assert_eq!(*first, next, "ranges are contiguous");
            assert!(*count > 0);
            if (*first..first + count).contains(&id) {
                result = Some(to + (id - first));
            }
            next = first + count;
        }
        assert_eq!(next, ID_COUNT, "ranges cover every id");
        result.expect("every id is mapped")
    }

    #[test]
    fn a_swap_exchanges_two_ids_and_keeps_every_other_one() {
        for (a, b) in [
            (501, 1000),
            (1000, 501),
            (0, 1000),
            (1000, 1001),
            (0, 1),
            (5, u32::MAX - 1),
            (0, u32::MAX - 1),
        ] {
            let ranges = swap_ranges(a, b);
            assert!(ranges.len() <= 5);
            assert_eq!(mapped(&ranges, a.into()), u64::from(b));
            assert_eq!(mapped(&ranges, b.into()), u64::from(a));
            for other in [0, 1, 500, 502, 999, 1002, 65534, ID_COUNT - 1] {
                if other != u64::from(a) && other != u64::from(b) {
                    assert_eq!(mapped(&ranges, other), other);
                }
            }
            // Mapped ids must not repeat either: summed, they are every id once.
            let total: u64 = ranges.iter().map(|(_, _, count)| count).sum();
            assert_eq!(total, ID_COUNT);
        }
        assert_eq!(swap_ranges(7, 7), vec![(0, 0, ID_COUNT)]);
    }

    #[test]
    fn id_maps_are_written_one_range_per_line() {
        assert_eq!(
            id_map(Some((501, 1000))),
            "0 0 501\n501 1000 1\n502 502 498\n1000 501 1\n1001 1001 4294966294\n"
        );
        assert_eq!(
            id_map(Some((0, 1000))),
            "0 1000 1\n1 1 999\n1000 0 1\n1001 1001 4294966294\n"
        );
        assert_eq!(id_map(None), "0 0 4294967295\n");
    }

    #[test]
    fn a_clone_is_staged_per_share_and_mapping_outside_the_user_mount_tree() {
        let share = Path::new("/run/smolvm/virtiofs/smolvm0");
        let both = OwnerMapping {
            uid: Some((501, 1000)),
            gid: Some((20, 1000)),
        };
        let user_only = OwnerMapping {
            uid: Some((501, 1000)),
            gid: None,
        };
        let group_only = OwnerMapping {
            uid: None,
            gid: Some((1001, 1000)),
        };
        assert_eq!(
            staged_path(share, both),
            Path::new("/run/smolvm/idmapped/uid-501-1000.gid-20-1000/run/smolvm/virtiofs/smolvm0")
        );
        assert_eq!(
            staged_path(share, user_only),
            Path::new("/run/smolvm/idmapped/uid-501-1000/run/smolvm/virtiofs/smolvm0")
        );
        assert_eq!(
            staged_path(share, group_only),
            Path::new("/run/smolvm/idmapped/gid-1001-1000/run/smolvm/virtiofs/smolvm0")
        );
    }

    const MOUNTINFO: &str = "\
22 1 0:20 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b
30 22 0:25 / /run rw,nosuid,nodev - tmpfs tmpfs rw,mode=755
41 30 0:38 / /run/smolvm/virtiofs/smolvm0 rw,relatime - virtiofs smolvm0 rw
42 30 0:39 / /run/smolvm/attach/rw rw,nosuid,nodev,relatime - virtiofs smolvm_attach_rw rw
43 30 254:16 / /run/smolvm/virtiofs/smolvm_cache rw,relatime shared:5 - ext4 /dev/vdc rw
44 30 0:38 / /run/smolvm/idmapped/uid-501-1000/run/smolvm/virtiofs/smolvm0 rw,relatime,idmapped - virtiofs smolvm0 rw
45 30 0:39 /m1 /run/smolvm/idmapped/uid-501-1000/run/smolvm/attach/rw/m1 rw,nosuid,nodev,relatime,idmapped - virtiofs smolvm_attach_rw rw
46 22 0:38 / /mnt/with\\040space rw,relatime - virtiofs smolvm0 rw
";

    #[test]
    fn a_path_is_located_on_the_mount_that_covers_it() {
        let mounts = parse_mountinfo(MOUNTINFO);
        assert_eq!(mounts.len(), 8);

        let (mount, root) = locate(&mounts, Path::new("/run/smolvm/virtiofs/smolvm0")).unwrap();
        assert_eq!(
            (mount.fstype.as_str(), mount.device.as_str()),
            ("virtiofs", "0:38")
        );
        assert_eq!(root, "/");

        // A share on a live device is a directory of that device's filesystem.
        let (mount, root) = locate(&mounts, Path::new("/run/smolvm/attach/rw/m1")).unwrap();
        assert_eq!(
            (mount.fstype.as_str(), mount.device.as_str()),
            ("virtiofs", "0:39")
        );
        assert_eq!(root, "/m1");

        // Not host shares: the cache disk, and a staging directory nothing is
        // mounted on.
        let (mount, _) = locate(&mounts, Path::new("/run/smolvm/virtiofs/smolvm_cache")).unwrap();
        assert_eq!(mount.fstype, "ext4");
        let (mount, _) = locate(&mounts, Path::new("/run/smolvm/virtiofs/smolvm9")).unwrap();
        assert_eq!(mount.fstype, "tmpfs");

        let (mount, _) = locate(&mounts, Path::new("/mnt/with space/sub")).unwrap();
        assert_eq!(mount.mount_point, "/mnt/with space");
    }

    #[test]
    fn a_staged_clone_is_reused_only_for_the_same_directory_of_the_same_filesystem() {
        let mounts = parse_mountinfo(MOUNTINFO);
        let staged = Path::new("/run/smolvm/idmapped/uid-501-1000/run/smolvm/virtiofs/smolvm0");
        assert_eq!(
            staged_mount_is_current(&mounts, staged, "0:38", "/"),
            Some(true)
        );
        // The share was mounted again (a branch resumed with a new device).
        assert_eq!(
            staged_mount_is_current(&mounts, staged, "0:51", "/"),
            Some(false)
        );
        let attached = Path::new("/run/smolvm/idmapped/uid-501-1000/run/smolvm/attach/rw/m1");
        assert_eq!(
            staged_mount_is_current(&mounts, attached, "0:39", "/m1"),
            Some(true)
        );
        assert_eq!(
            staged_mount_is_current(&mounts, attached, "0:39", "/m2"),
            Some(false)
        );
        // Nothing staged yet.
        let missing = Path::new("/run/smolvm/idmapped/uid-501-1001/run/smolvm/virtiofs/smolvm0");
        assert_eq!(staged_mount_is_current(&mounts, missing, "0:38", "/"), None);
        // A mount that is not id-mapped is not one of ours.
        assert_eq!(
            staged_mount_is_current(
                &mounts,
                Path::new("/run/smolvm/virtiofs/smolvm0"),
                "0:38",
                "/"
            ),
            Some(false)
        );
    }
}
