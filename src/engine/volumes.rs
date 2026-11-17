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
        if self.records.write().remove(name).is_none() {
            return Err(ApiError::not_found(format!("get {name}: no such volume")));
        }
        store.remove_object("volumes", name);
        remove_tree(&self.root.join(name));
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
fn remove_tree(path: &std::path::Path) {
    if std::fs::remove_dir_all(path).is_ok() || !path.exists() {
        return;
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
    if let Err(e) = std::fs::remove_dir_all(path) {
        tracing::warn!(path = %path.display(), error = %e, "could not remove a volume's directory");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        remove_tree(&vol);
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
