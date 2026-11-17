//! Quiesce internal disks for shutdown without freezing host-shared filesystems.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Mount {
    device: String,
    target: PathBuf,
    storage: bool,
}

fn internal_mounts(mountinfo: &str) -> io::Result<Vec<Mount>> {
    let mut devices = BTreeMap::<String, Mount>::new();
    for line in mountinfo.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(separator) = fields.iter().position(|s| *s == "-") else {
            continue;
        };
        if separator < 6 || fields.len() <= separator + 3 || fields[separator + 1] != "ext4" {
            continue;
        }
        let source = fields[separator + 2];
        if !matches!(source, "/dev/vda" | "/dev/vdb")
            || !fields[5].split(',').any(|s| s == "rw")
            || !fields[separator + 3].split(',').any(|s| s == "rw")
        {
            continue;
        }
        let mount = Mount {
            device: fields[2].into(),
            target: PathBuf::from(unescape_mount_path(fields[4])?),
            storage: source == "/dev/vda",
        };
        // A bind mount refers to the same superblock. Prefer the original
        // whole-filesystem mount over a bind of one of its subdirectories.
        match devices.entry(mount.device.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(mount);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if preferred(&mount) < preferred(entry.get()) {
                    entry.insert(mount);
                }
            }
        }
    }
    let mut mounts: Vec<_> = devices.into_values().collect();
    mounts.sort_by_key(|m| (!m.storage, m.target.clone()));
    if mounts.is_empty() {
        return Err(io::Error::other(
            "no writable internal ext4 filesystem found for shutdown",
        ));
    }
    Ok(mounts)
}

fn preferred(mount: &Mount) -> (bool, usize) {
    let canonical = matches!(
        mount.target.to_str(),
        Some("/storage" | "/oldroot/mnt/overlay" | "/mnt/overlay")
    );
    (!canonical, mount.target.as_os_str().len())
}

fn unescape_mount_path(path: &str) -> io::Result<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 3 >= bytes.len()
                || !bytes[i + 1..i + 4]
                    .iter()
                    .all(|b| (b'0'..=b'7').contains(b))
            {
                return Err(io::Error::other("invalid mountinfo path escape"));
            }
            let value = ((bytes[i + 1] - b'0') as u16 * 64)
                + ((bytes[i + 2] - b'0') as u16 * 8)
                + (bytes[i + 3] - b'0') as u16;
            decoded.push(u8::try_from(value).map_err(io::Error::other)?);
            i += 4;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).map_err(io::Error::other)
}

trait Operations {
    fn freeze(&mut self, mount: &Mount) -> io::Result<()>;
    fn thaw(&mut self, mount: &Mount) -> io::Result<()>;
}

#[derive(Default)]
struct State {
    frozen: Vec<Mount>,
    complete: bool,
}

impl State {
    fn rollback(&mut self, ops: &mut impl Operations) -> io::Result<()> {
        let mut errors = Vec::new();
        for i in (0..self.frozen.len()).rev() {
            match ops.thaw(&self.frozen[i]) {
                Ok(()) => {
                    self.frozen.remove(i);
                }
                Err(error) => {
                    errors.push(format!("thaw {}: {error}", self.frozen[i].target.display()))
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    fn freeze(&mut self, mounts: &[Mount], ops: &mut impl Operations) -> io::Result<()> {
        if self.complete {
            return Ok(());
        }
        // Failed rollback is remembered; do not proceed with a partly frozen
        // machine until these filesystems have been recovered.
        self.rollback(ops)?;
        for mount in mounts {
            if let Err(error) = ops.freeze(mount) {
                let rollback = self.rollback(ops).err();
                return Err(io::Error::other(format!(
                    "freeze {}: {error}{}",
                    mount.target.display(),
                    rollback.map(|e| format!("; {e}")).unwrap_or_default()
                )));
            }
            self.frozen.push(mount.clone());
        }
        self.complete = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn freeze_internal_filesystems() -> io::Result<()> {
    use std::os::fd::AsRawFd;
    static STATE: std::sync::Mutex<State> = std::sync::Mutex::new(State {
        frozen: Vec::new(),
        complete: false,
    });
    let mut state = STATE
        .lock()
        .map_err(|_| io::Error::other("shutdown freeze state poisoned"))?;
    if state.complete {
        return Ok(());
    }
    // Freezing a superblock acquires its three freeze levels through a percpu
    // rwsem, and each acquisition waits out a full RCU grace period. On an
    // idle guest those grace periods are ~300ms of pure waiting across the two
    // disks, nearly the whole cost of a machine stop. Expedited RCU replaces
    // the waits with IPIs, which is what the kernel itself does around
    // suspend (rcu_pm_notify). Both callers power the VM off right after the
    // freeze, so the setting is never restored; if a failed freeze leaves the
    // guest running, staying expedited costs a few IPIs per grace period and
    // nothing in correctness. Best effort: without the knob the freeze runs
    // at the normal pace.
    let _ = std::fs::write("/sys/kernel/rcu_expedited", "1");
    let mounts = internal_mounts(&std::fs::read_to_string("/proc/self/mountinfo")?)?;
    struct DiskOperations(BTreeMap<String, std::fs::File>);
    impl DiskOperations {
        fn call(&self, mount: &Mount, freeze: bool) -> io::Result<()> {
            let file = self
                .0
                .get(&mount.device)
                .ok_or_else(|| io::Error::other("frozen filesystem no longer accessible"))?;
            let request = if freeze {
                nix::request_code_readwrite!(b'X', 119, std::mem::size_of::<libc::c_int>())
            } else {
                nix::request_code_readwrite!(b'X', 120, std::mem::size_of::<libc::c_int>())
            };
            // SAFETY: file is an open directory FD; Linux FIFREEZE/FITHAW
            // take no pointed-to payload despite their ioctl encoding.
            if unsafe { libc::ioctl(file.as_raw_fd(), request as _, 0) } != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
    impl Operations for DiskOperations {
        fn freeze(&mut self, mount: &Mount) -> io::Result<()> {
            self.call(mount, true)
        }
        fn thaw(&mut self, mount: &Mount) -> io::Result<()> {
            self.call(mount, false)
        }
    }
    let mut ops = DiskOperations(BTreeMap::new());
    // Open every directory before freezing either filesystem. No executable
    // launch or writable-file creation is required after the root upper freezes.
    for mount in mounts.iter().chain(state.frozen.iter()) {
        ops.0
            .insert(mount.device.clone(), std::fs::File::open(&mount.target)?);
    }
    state.freeze(&mounts, &mut ops)
}

#[cfg(not(target_os = "linux"))]
pub fn freeze_internal_filesystems() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "filesystem freeze requires a Linux guest",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mounts() -> Vec<Mount> {
        internal_mounts("1 0 252:16 / /oldroot/mnt/overlay rw - ext4 /dev/vdb rw\n2 0 252:0 /docker /var/lib/docker rw - ext4 /dev/vda rw\n3 0 252:0 / /storage rw - ext4 /dev/vda rw\n4 0 0:1 / /shared rw - virtiofs /dev/vdc rw\n5 0 0:2 / /remote rw - fuse.s3fs bucket rw\n6 0 252:32 / /other rw - ext4 /dev/vdc rw\n7 0 252:48 / /readonly ro - ext4 /dev/vda ro").unwrap()
    }

    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        fail_freeze: Option<String>,
        fail_thaw: bool,
    }
    impl Operations for Fake {
        fn freeze(&mut self, mount: &Mount) -> io::Result<()> {
            self.calls
                .push(format!("freeze {}", mount.target.display()));
            if self.fail_freeze.as_deref() == mount.target.to_str() {
                Err(io::Error::other("freeze failed"))
            } else {
                Ok(())
            }
        }
        fn thaw(&mut self, mount: &Mount) -> io::Result<()> {
            self.calls.push(format!("thaw {}", mount.target.display()));
            if self.fail_thaw {
                Err(io::Error::other("thaw failed"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn internal_only_deduplicated_storage_first() {
        let mounts = mounts();
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].target, PathBuf::from("/storage"));
        assert_eq!(mounts[1].target, PathBuf::from("/oldroot/mnt/overlay"));
        assert!(internal_mounts("1 0 0:1 / /remote rw - virtiofs root rw").is_err());
        assert_eq!(
            unescape_mount_path("/path\\040with\\134slash").unwrap(),
            "/path with\\slash"
        );
    }

    #[test]
    fn success_is_idempotent() {
        let mut state = State::default();
        let mut ops = Fake::default();
        state.freeze(&mounts(), &mut ops).unwrap();
        state.freeze(&mounts(), &mut ops).unwrap();
        assert_eq!(
            ops.calls,
            ["freeze /storage", "freeze /oldroot/mnt/overlay"]
        );
    }

    #[test]
    fn partial_failure_rolls_back_and_retry_succeeds() {
        let mut state = State::default();
        let mut ops = Fake {
            fail_freeze: Some("/oldroot/mnt/overlay".into()),
            ..Fake::default()
        };
        assert!(state.freeze(&mounts(), &mut ops).is_err());
        assert_eq!(
            ops.calls,
            [
                "freeze /storage",
                "freeze /oldroot/mnt/overlay",
                "thaw /storage"
            ]
        );
        assert!(state.frozen.is_empty());
        ops.fail_freeze = None;
        state.freeze(&mounts(), &mut ops).unwrap();
        assert!(state.complete);
    }

    #[test]
    fn failed_thaw_is_retained_until_recovered() {
        let mut state = State::default();
        let mut ops = Fake {
            fail_freeze: Some("/oldroot/mnt/overlay".into()),
            fail_thaw: true,
            ..Fake::default()
        };
        assert!(state
            .freeze(&mounts(), &mut ops)
            .unwrap_err()
            .to_string()
            .contains("thaw failed"));
        assert_eq!(state.frozen.len(), 1);
        ops.calls.clear();
        assert!(state.freeze(&mounts(), &mut ops).is_err());
        assert_eq!(ops.calls, ["thaw /storage"]);
        ops.fail_thaw = false;
        ops.fail_freeze = None;
        state.freeze(&mounts(), &mut ops).unwrap();
        assert!(state.complete);
    }
}
