//! Reference-counted read-only image exports across container supervisors.
//! The preparation lock also serializes archive extraction for the same image.
use super::store::{read_json, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

#[derive(Default, Serialize, Deserialize)]
struct Owners {
    generation: String,
    source: PathBuf,
    containers: BTreeSet<String>,
}

pub(super) fn name(reference: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "i{}",
        hex::encode(&Sha256::digest(reference.as_bytes())[..24])
    )
}

trait Exports {
    fn source(&self, name: &str) -> crate::Result<Option<PathBuf>>;
    fn add(&self, name: &str, source: &Path) -> crate::Result<()>;
    fn remove(&self, name: &str) -> crate::Result<()>;
}
struct Machine<'a>(&'a str);

// None means the original VM record is gone; only its old ownership metadata
// can remain, and no name-derived control operation is authorized.
struct CleanupExports<'a>(Option<&'a crate::attach::OwnedShares>);
impl Exports for CleanupExports<'_> {
    fn source(&self, name: &str) -> crate::Result<Option<PathBuf>> {
        self.0.map_or(Ok(None), |shares| shares.source(name, true))
    }
    fn add(&self, _name: &str, _source: &Path) -> crate::Result<()> {
        Err(crate::Error::config(
            "image share",
            "cleanup cannot add exports",
        ))
    }
    fn remove(&self, name: &str) -> crate::Result<()> {
        if let Some(shares) = self.0 {
            if let Some(source) = shares.source(name, true)? {
                shares.remove(name, &source, true)?;
            }
        }
        Ok(())
    }
}

impl Exports for Machine<'_> {
    fn source(&self, name: &str) -> crate::Result<Option<PathBuf>> {
        Ok(crate::attach::shared_directories(self.0, true)?
            .into_iter()
            .find(|(share, _)| share == name)
            .map(|(_, source)| source))
    }
    fn add(&self, name: &str, source: &Path) -> crate::Result<()> {
        crate::attach::add_share(self.0, name, source, true)
    }
    fn remove(&self, name: &str) -> crate::Result<()> {
        crate::attach::remove_share(self.0, name, true)
    }
}

/// One container's reference; the VM boot generation fences delayed cleanup.
pub(super) struct Lease {
    path: PathBuf,
    machine: String,
    name: String,
    owner: String,
    generation: String,
    preparing: Option<File>,
}

fn lock(path: &Path) -> crate::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path.with_extension("lock"))?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

impl Lease {
    pub(super) fn generation(&self) -> &str {
        &self.generation
    }

    /// Replay terminal cleanup, including a crash after the export disappeared
    /// but before its retained owner was removed. A newer boot's lease is kept.
    pub(super) fn release_retained(
        root: &Path,
        machine: &str,
        host: &str,
        generation: &str,
        owner: &str,
        name: String,
        exports: Option<&crate::attach::OwnedShares>,
    ) -> crate::Result<()> {
        let path = root
            .join("guest-image-shares")
            .join(host)
            .join(format!("{name}.json"));
        if !path.try_exists()? {
            return Ok(());
        }
        Self {
            path,
            machine: machine.to_owned(),
            name,
            owner: owner.to_owned(),
            generation: generation.to_owned(),
            preparing: None,
        }
        .unclaim(&CleanupExports(exports))
    }

    /// Recover an existing reference without changing the running guest's exports.
    pub(super) fn recover(
        root: &Path,
        machine: String,
        host: &str,
        generation: String,
        owner: String,
        name: String,
    ) -> crate::Result<Self> {
        let lease = Self {
            path: root
                .join("guest-image-shares")
                .join(host)
                .join(format!("{name}.json")),
            machine,
            name,
            owner,
            generation,
            preparing: None,
        };
        lease.verify_retained(&Machine(&lease.machine))?;
        Ok(lease)
    }

    fn verify_retained(&self, exports: &impl Exports) -> crate::Result<()> {
        let _guard = lock(&self.path)?;
        let owners: Owners = read_json(&self.path)?.ok_or_else(|| {
            crate::Error::config("image share", "retained image ownership is missing")
        })?;
        if owners.generation != self.generation
            || !owners.containers.contains(&self.owner)
            || exports.source(&self.name)?.as_ref() != Some(&owners.source)
        {
            return Err(crate::Error::config(
                "image share",
                "retained image ownership or live export changed",
            ));
        }
        Ok(())
    }

    pub(super) fn acquire(
        root: &Path,
        machine: String,
        host: &str,
        generation: String,
        owner: String,
        name: String,
        source: &Path,
    ) -> crate::Result<Self> {
        let directory = root.join("guest-image-shares").join(host);
        std::fs::create_dir_all(&directory)?;
        let mut lease = Self {
            path: directory.join(format!("{name}.json")),
            machine,
            name,
            owner,
            generation,
            preparing: None,
        };
        let machine = lease.machine.clone();
        lease.claim(source, &Machine(&machine))?;
        Ok(lease)
    }

    fn claim(&mut self, source: &Path, exports: &impl Exports) -> crate::Result<()> {
        let guard = lock(&self.path)?;
        let source = std::fs::canonicalize(source)?;
        let mut owners: Owners = read_json(&self.path)?.unwrap_or_default();
        if owners.generation != self.generation {
            owners = Owners {
                generation: self.generation.clone(),
                source: source.clone(),
                ..Default::default()
            };
        }
        if owners.source != source {
            return Err(crate::Error::config(
                "image share",
                "image export source changed",
            ));
        }
        let existing = exports.source(&self.name)?;
        if existing.as_ref().is_some_and(|path| path != &source) {
            return Err(crate::Error::config(
                "image share",
                "live image export points to another directory",
            ));
        }
        if existing.is_none() {
            exports.add(&self.name, &source)?;
        }
        let was_empty = owners.containers.is_empty();
        owners.containers.insert(self.owner.clone());
        if let Err(error) = write_json(&self.path, &owners) {
            if existing.is_none() && was_empty {
                let _ = exports.remove(&self.name);
            }
            return Err(error);
        }
        self.preparing = Some(guard);
        Ok(())
    }

    /// Release the preparation lock after the guest has opened its rootfs.
    pub(super) fn prepared(&mut self) {
        self.preparing = None;
    }

    fn unclaim(&mut self, exports: &impl Exports) -> crate::Result<()> {
        self.prepared();
        let _guard = lock(&self.path)?;
        let Some(mut owners) = read_json::<Owners>(&self.path)? else {
            return Ok(());
        };
        if owners.generation != self.generation {
            return Ok(());
        }
        if !owners.containers.remove(&self.owner) {
            // A previous rename may have succeeded before its directory sync
            // failed. Complete durability before clearing the exit journal.
            File::open(&self.path)?.sync_all()?;
            File::open(self.path.parent().unwrap())?.sync_all()?;
            return Ok(());
        }
        if owners.containers.is_empty() {
            if let Some(source) = exports.source(&self.name)? {
                if source != owners.source {
                    return Err(crate::Error::config(
                        "image share",
                        "refusing to remove a replaced image export",
                    ));
                }
                exports.remove(&self.name)?;
            }
        }
        let mut staged = tempfile::NamedTempFile::new_in(self.path.parent().unwrap())?;
        use std::io::Write;
        serde_json::to_writer_pretty(&mut staged, &owners)
            .map_err(|error| crate::Error::config("image share", error.to_string()))?;
        staged.flush()?;
        staged.as_file().sync_all()?;
        staged.persist(&self.path).map_err(|error| error.error)?;
        File::open(self.path.parent().unwrap())?.sync_all()?;
        Ok(())
    }

    pub(super) async fn release(mut self) {
        self.prepared();
        let machine = self.machine.clone();
        match tokio::task::spawn_blocking(move || self.unclaim(&Machine(&machine))).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "could not release container image share"),
            Err(error) => tracing::warn!(%error, "image share cleanup stopped"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[derive(Default)]
    struct Device(Mutex<BTreeMap<String, PathBuf>>);
    impl Exports for Device {
        fn source(&self, name: &str) -> crate::Result<Option<PathBuf>> {
            Ok(self.0.lock().unwrap().get(name).cloned())
        }
        fn add(&self, name: &str, source: &Path) -> crate::Result<()> {
            let mut shares = self.0.lock().unwrap();
            assert!(
                !shares.values().any(|existing| existing == source),
                "duplicate host directory export"
            );
            assert!(shares.insert(name.into(), source.into()).is_none());
            Ok(())
        }
        fn remove(&self, name: &str) -> crate::Result<()> {
            assert!(self.0.lock().unwrap().remove(name).is_some());
            Ok(())
        }
    }
    fn lease(directory: &Path, owner: &str, generation: &str) -> Lease {
        Lease {
            path: directory.join("image.json"),
            machine: "fixture".into(),
            name: name("local:test-image"),
            owner: owner.into(),
            generation: generation.into(),
            preparing: None,
        }
    }

    #[test]
    fn independent_supervisors_reuse_one_export_until_the_last_owner_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let device = Device::default();
        let mut first = lease(dir.path(), "first", "boot1");
        first.claim(&source, &device).unwrap();
        first.prepared();
        let mut second = lease(dir.path(), "second", "boot1");
        second.claim(&source, &device).unwrap();
        second.prepared();
        assert_eq!(device.0.lock().unwrap().len(), 1);
        first.unclaim(&device).unwrap();
        assert_eq!(device.0.lock().unwrap().len(), 1);
        // Repeated cleanup cannot consume someone else's reference.
        first.unclaim(&device).unwrap();
        assert_eq!(device.0.lock().unwrap().len(), 1);
        second.unclaim(&device).unwrap();
        assert!(device.0.lock().unwrap().is_empty());
    }

    #[test]
    fn an_old_vm_cleanup_cannot_revoke_a_new_vm_export() {
        let dir = tempfile::tempdir().unwrap();
        let device = Device::default();
        let mut old = lease(dir.path(), "same-container", "boot1");
        old.claim(dir.path(), &device).unwrap();
        old.prepared();
        device.0.lock().unwrap().clear(); // The old VM stopped.
        let mut new = lease(dir.path(), "same-container", "boot2");
        new.claim(dir.path(), &device).unwrap();
        new.prepared();
        old.unclaim(&device).unwrap();
        assert_eq!(device.0.lock().unwrap().len(), 1);
        new.unclaim(&device).unwrap();
        assert!(device.0.lock().unwrap().is_empty());
    }

    #[test]
    fn saved_owner_keeps_its_export_until_recovered_execution_exits() {
        let dir = tempfile::tempdir().unwrap();
        let device = Device::default();
        let mut original = lease(dir.path(), "saved", "boot1");
        original.claim(dir.path(), &device).unwrap();
        original.prepared();
        drop(original); // Saving execution must not release its durable reference.
        let mut recovered = lease(dir.path(), "saved", "boot1");
        recovered.verify_retained(&device).unwrap();
        assert!(lease(dir.path(), "other", "boot1")
            .verify_retained(&device)
            .is_err());
        assert!(lease(dir.path(), "saved", "boot2")
            .verify_retained(&device)
            .is_err());
        assert_eq!(device.0.lock().unwrap().len(), 1);
        recovered.unclaim(&device).unwrap();
        assert!(device.0.lock().unwrap().is_empty());
        assert!(recovered.verify_retained(&device).is_err());
    }

    #[test]
    fn failed_export_removal_keeps_ownership_for_a_later_retry() {
        struct Refuse<'a>(&'a Device);
        impl Exports for Refuse<'_> {
            fn source(&self, name: &str) -> crate::Result<Option<PathBuf>> {
                self.0.source(name)
            }
            fn add(&self, name: &str, source: &Path) -> crate::Result<()> {
                self.0.add(name, source)
            }
            fn remove(&self, _name: &str) -> crate::Result<()> {
                Err(crate::Error::agent_conflict("fixture", "reserved export"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let device = Device::default();
        let mut first = lease(dir.path(), "exited", "boot1");
        first.claim(dir.path(), &device).unwrap();
        first.prepared();
        assert!(first.unclaim(&Refuse(&device)).is_err());
        assert!(read_json::<Owners>(&first.path)
            .unwrap()
            .unwrap()
            .containers
            .contains("exited"));
        drop(first);
        let mut recovered = lease(dir.path(), "exited", "boot1");
        recovered.verify_retained(&device).unwrap();
        recovered.unclaim(&device).unwrap();
        assert!(device.0.lock().unwrap().is_empty());
        recovered.unclaim(&device).unwrap();
    }

    #[test]
    fn terminal_cleanup_replays_after_an_export_was_already_removed() {
        let dir = tempfile::tempdir().unwrap();
        let device = Device::default();
        let mut first = lease(dir.path(), "exited", "boot1");
        first.claim(dir.path(), &device).unwrap();
        first.prepared();
        device.remove(&first.name).unwrap();
        drop(first); // Crash before the ownership file was updated.
        let mut recovered = lease(dir.path(), "exited", "boot1");
        recovered.unclaim(&device).unwrap();
        assert!(read_json::<Owners>(&recovered.path)
            .unwrap()
            .unwrap()
            .containers
            .is_empty());
        recovered.unclaim(&device).unwrap();
    }

    #[test]
    fn preparation_is_serialized_across_independent_lock_holders() {
        let dir = tempfile::tempdir().unwrap();
        let device = Arc::new(Device::default());
        let mut first = lease(dir.path(), "first", "boot1");
        first.claim(dir.path(), device.as_ref()).unwrap();
        let path = dir.path().to_owned();
        let other = device.clone();
        let (started_tx, started) = std::sync::mpsc::channel();
        let (acquired_tx, acquired) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut second = lease(&path, "second", "boot1");
            started_tx.send(()).unwrap();
            second.claim(&path, other.as_ref()).unwrap();
            second.prepared();
            acquired_tx.send(()).unwrap();
            second
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(acquired.recv_timeout(Duration::from_millis(50)).is_err());
        first.prepared();
        acquired.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut second = thread.join().unwrap();
        first.unclaim(device.as_ref()).unwrap();
        assert_eq!(device.0.lock().unwrap().len(), 1);
        second.unclaim(device.as_ref()).unwrap();
    }

    #[test]
    fn corrupted_ownership_or_replaced_exports_are_not_silently_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let device = Device::default();
        let mut owner = lease(dir.path(), "owner", "boot1");
        owner.claim(dir.path(), &device).unwrap();
        owner.prepared();
        device
            .0
            .lock()
            .unwrap()
            .insert(owner.name.clone(), other.path().into());
        assert!(owner.unclaim(&device).is_err());
        assert_eq!(
            device.source(&owner.name).unwrap(),
            Some(other.path().into())
        );
        std::fs::write(&owner.path, b"invalid json").unwrap();
        assert!(owner.claim(dir.path(), &device).is_err());
        assert!(owner.unclaim(&device).is_err());
        assert_eq!(
            device.source(&owner.name).unwrap(),
            Some(other.path().into())
        );
    }
}
