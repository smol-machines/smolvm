//! Named volumes: host directories under the engine root, shared into every
//! machine that mounts them, so several containers can use one at once.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::filters::Filters;
use super::store::Store;
use super::util::{ApiError, ApiResult};

/// One volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VolumeRecord {
    pub name: String,
    pub created: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    /// Created for a container's anonymous volume; removed with it on
    /// `docker rm -v`.
    #[serde(default)]
    pub anonymous: bool,
}

/// The label Docker puts on the volumes it names itself.
const ANONYMOUS_LABEL: &str = "com.docker.volume.anonymous";

/// The engine's volumes.
pub(crate) struct Volumes {
    records: parking_lot::RwLock<HashMap<String, VolumeRecord>>,
    root: PathBuf,
}

impl Volumes {
    pub(crate) fn refresh(&self, store: &Store) -> crate::Result<()> {
        *self.records.write() = store
            .load_objects::<VolumeRecord>("volumes")?
            .into_iter()
            .map(|r| (r.name.clone(), r))
            .collect();
        Ok(())
    }

    pub(crate) fn load(store: &Store) -> crate::Result<Self> {
        let records = store
            .load_objects::<VolumeRecord>("volumes")?
            .into_iter()
            .map(|r| (r.name.clone(), r))
            .collect();
        Ok(Self {
            records: parking_lot::RwLock::new(records),
            root: store.root().join("volumes"),
        })
    }

    /// Host directory holding the volume's data.
    pub(crate) fn mountpoint(&self, name: &str) -> PathBuf {
        self.root.join(name).join("_data")
    }

    pub(crate) fn get(&self, name: &str) -> Option<VolumeRecord> {
        self.records.read().get(name).cloned()
    }

    pub(crate) fn all(&self) -> Vec<VolumeRecord> {
        self.records.read().values().cloned().collect()
    }

    /// Create the volume, or return the existing one of that name. Returns
    /// the record and whether it was created now.
    pub(crate) fn create(
        &self,
        store: &Store,
        name: Option<&str>,
        labels: BTreeMap<String, String>,
        options: BTreeMap<String, String>,
        anonymous: bool,
    ) -> ApiResult<(VolumeRecord, bool)> {
        let name = match name.filter(|n| !n.is_empty()) {
            Some(n) => {
                if !valid_volume_name(n) {
                    return Err(ApiError::bad_request(format!(
                        "create {n}: \"{n}\" includes invalid characters for a local volume name, only \"[a-zA-Z0-9][a-zA-Z0-9_.-]\" are allowed"
                    )));
                }
                n.to_string()
            }
            None => super::util::new_id(),
        };
        if let Some(existing) = self.get(&name) {
            return Ok((existing, false));
        }
        // Docker marks the volumes it names itself.
        let mut labels = labels;
        if anonymous {
            labels.insert(ANONYMOUS_LABEL.to_string(), String::new());
        }
        std::fs::create_dir_all(self.mountpoint(&name))
            .map_err(|e| ApiError::internal(format!("create volume directory for {name}: {e}")))?;
        let record = VolumeRecord {
            name: name.clone(),
            created: super::util::now_rfc3339(),
            labels,
            options,
            anonymous,
        };
        store
            .save_object("volumes", &name, &record)
            .map_err(ApiError::from)?;
        self.records.write().insert(name, record.clone());
        Ok((record, true))
    }

    /// Remove the volume and its data.
    pub(crate) fn remove(&self, store: &Store, name: &str) -> ApiResult<()> {
        let mut records = self.records.write();
        if !records.contains_key(name) {
            return Err(ApiError::not_found(format!("get {name}: no such volume")));
        }
        // Keep the record discoverable if either deletion fails, so callers can
        // repair the filesystem and retry. Recursive deletion may be partial.
        remove_tree(&self.root.join(name))
            .map_err(|e| ApiError::internal(format!("remove volume data for {name}: {e}")))?;
        store
            .remove_object("volumes", name)
            .map_err(ApiError::from)?;
        records.remove(name);
        Ok(())
    }

    /// `GET /volumes` entry and `GET /volumes/{name}` body.
    pub(crate) fn inspect(&self, record: &VolumeRecord) -> serde_json::Value {
        serde_json::json!({
            "Name": record.name,
            "Driver": "local",
            "Mountpoint": self.mountpoint(&record.name),
            "CreatedAt": record.created,
            "Labels": record.labels,
            "Scope": "local",
            "Options": if record.options.is_empty() { serde_json::Value::Null } else { serde_json::json!(record.options) },
            "UsageData": null,
        })
    }
}

/// Docker's rule for local volume names.
pub(crate) fn valid_volume_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Whether `volume` passes the `docker volume ls` filters; `in_use` says
/// whether any container mounts it.
pub(crate) fn matches(volume: &VolumeRecord, filters: &Filters, in_use: bool) -> bool {
    filters.any("name", |n| volume.name.contains(n))
        && filters.any("driver", |d| d == "local")
        && filters.any("dangling", |d| (d == "true" || d == "1") != in_use)
        && filters.labels_match("label", &volume.labels)
}

/// Remove a volume's directory even where a container left directories its
/// owner may not enter (an overlayfs work directory is mode 0): those get
/// their owner's access back first.
fn remove_tree(path: &std::path::Path) -> std::io::Result<()> {
    if std::fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }
    // `Path::exists` also returns false on permission errors. Check the entry
    // itself so permission failures and dangling symlinks are not absent paths.
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(());
    }
    fn open_up(dir: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::symlink_metadata(dir) else {
            return;
        };
        if !meta.is_dir() {
            return;
        }
        let mode = meta.permissions().mode() | 0o700;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode));
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                open_up(&entry.path());
            }
        }
    }
    open_up(path);
    std::fs::remove_dir_all(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Store, Volumes) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let volumes = Volumes::load(&store).unwrap();
        volumes
            .create(
                &store,
                Some("data"),
                BTreeMap::new(),
                BTreeMap::new(),
                false,
            )
            .unwrap();
        (dir, store, volumes)
    }

    #[test]
    fn failed_data_removal_preserves_records_for_retry() {
        let (_dir, store, volumes) = fixture();
        let path = volumes.root.join("data");
        std::fs::remove_dir_all(&path).unwrap();
        std::fs::write(&path, b"must not be orphaned").unwrap();
        let error = volumes.remove(&store, "data").unwrap_err();
        assert!(error.message.contains("remove volume data"));
        assert!(volumes.get("data").is_some());
        assert!(Volumes::load(&store).unwrap().get("data").is_some());
        assert_eq!(std::fs::read(&path).unwrap(), b"must not be orphaned");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir_all(path.join("_data")).unwrap();
        volumes.remove(&store, "data").unwrap();
        assert!(volumes.get("data").is_none());
        assert!(Volumes::load(&store).unwrap().get("data").is_none());
        assert!(!path.exists());
    }

    #[test]
    fn missing_volume_data_is_successfully_removed_from_inventory() {
        let (_dir, store, volumes) = fixture();
        std::fs::remove_dir_all(volumes.root.join("data")).unwrap();
        volumes.remove(&store, "data").unwrap();
        assert!(volumes.get("data").is_none());
        assert!(Volumes::load(&store).unwrap().get("data").is_none());
    }

    #[test]
    fn permission_errors_are_not_mistaken_for_missing_data() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_dir, store, volumes) = fixture();
        let file = volumes.mountpoint("data").join("payload");
        std::fs::write(&file, b"retained").unwrap();
        std::fs::set_permissions(&volumes.root, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = volumes.remove(&store, "data");
        std::fs::set_permissions(&volumes.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"retained");
        assert!(volumes.get("data").is_some());
        assert!(Volumes::load(&store).unwrap().get("data").is_some());
        volumes.remove(&store, "data").unwrap();
    }

    #[test]
    fn metadata_unlink_failure_preserves_records_for_retry() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_dir, store, volumes) = fixture();
        std::fs::remove_dir_all(volumes.root.join("data")).unwrap();
        std::fs::set_permissions(&volumes.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = volumes.remove(&store, "data");
        std::fs::set_permissions(&volumes.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert!(volumes.get("data").is_some());
        assert!(Volumes::load(&store).unwrap().get("data").is_some());
        volumes.remove(&store, "data").unwrap();
        assert!(Volumes::load(&store).unwrap().get("data").is_none());
    }

    #[test]
    fn removal_does_not_follow_volume_symlinks() {
        use std::os::unix::fs::symlink;
        let (_dir, store, volumes) = fixture();
        let outside = tempfile::tempdir().unwrap();
        let payload = outside.path().join("payload");
        std::fs::write(&payload, b"unrelated data").unwrap();
        symlink(outside.path(), volumes.mountpoint("data").join("linked")).unwrap();
        volumes.remove(&store, "data").unwrap();
        assert_eq!(std::fs::read(&payload).unwrap(), b"unrelated data");
        volumes
            .create(
                &store,
                Some("data"),
                BTreeMap::new(),
                BTreeMap::new(),
                false,
            )
            .unwrap();
        std::fs::remove_dir_all(volumes.root.join("data")).unwrap();
        symlink(outside.path(), volumes.root.join("data")).unwrap();
        volumes.remove(&store, "data").unwrap();
        assert_eq!(std::fs::read(&payload).unwrap(), b"unrelated data");
    }

    #[test]
    fn a_volume_with_closed_directories_is_removed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let vol = dir.path().join("v");
        std::fs::create_dir_all(vol.join("work/work")).unwrap();
        std::fs::write(vol.join("work/work/f"), b"x").unwrap();
        std::fs::set_permissions(
            vol.join("work/work"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        std::fs::set_permissions(vol.join("work"), std::fs::Permissions::from_mode(0o000)).unwrap();
        remove_tree(&vol).unwrap();
        assert!(!vol.exists());
    }

    #[test]
    fn create_is_idempotent_and_remove_deletes_data() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let volumes = Volumes::load(&store).unwrap();
        let (v, created) = volumes
            .create(
                &store,
                Some("data"),
                BTreeMap::new(),
                BTreeMap::new(),
                false,
            )
            .unwrap();
        assert!(created);
        assert!(volumes.mountpoint(&v.name).is_dir());
        let (_, again) = volumes
            .create(
                &store,
                Some("data"),
                BTreeMap::new(),
                BTreeMap::new(),
                false,
            )
            .unwrap();
        assert!(!again);
        assert!(volumes
            .create(
                &store,
                Some("bad/name"),
                BTreeMap::new(),
                BTreeMap::new(),
                false
            )
            .is_err());
        let reloaded = Volumes::load(&store).unwrap();
        assert!(reloaded.get("data").is_some());
        volumes.remove(&store, "data").unwrap();
        assert!(!volumes.mountpoint("data").exists());
    }
}
