//! The engine's records on disk: one JSON file per object, written atomically.

use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};

use super::containers::ContainerRecord;

/// Directory layout under the engine root.
pub(crate) struct Store {
    root: PathBuf,
}

impl Store {
    pub(crate) fn open(root: &Path) -> crate::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        for dir in [
            "containers",
            "images",
            "volumes",
            "networks",
            "execs",
            "events",
        ] {
            std::fs::create_dir_all(root.join(dir))?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub(crate) fn container_dir(&self, id: &str) -> PathBuf {
        self.root.join("containers").join(id)
    }

    pub(crate) fn container_log(&self, id: &str) -> PathBuf {
        self.container_dir(id).join(format!("{id}-json.log"))
    }

    pub(crate) fn save_container(&self, record: &ContainerRecord) -> crate::Result<()> {
        let dir = self.container_dir(&record.id);
        std::fs::create_dir_all(&dir)?;
        write_json(&dir.join("config.json"), record)
    }

    pub(crate) fn remove_container(&self, id: &str) {
        let _ = std::fs::remove_dir_all(self.container_dir(id));
    }

    pub(crate) fn load_containers(&self) -> crate::Result<Vec<ContainerRecord>> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(self.root.join("containers"))? {
            let path = entry?.path().join("config.json");
            match read_json::<ContainerRecord>(&path) {
                Ok(Some(record)) => records.push(record),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "skipping unreadable container record")
                }
            }
        }
        Ok(records)
    }

    /// `<root>/<kind>/<name>.json` for the flat object kinds.
    pub(crate) fn object_path(&self, kind: &str, name: &str) -> PathBuf {
        self.root.join(kind).join(format!("{name}.json"))
    }

    pub(crate) fn save_object<T: Serialize>(
        &self,
        kind: &str,
        name: &str,
        value: &T,
    ) -> crate::Result<()> {
        write_json(&self.object_path(kind, name), value)
    }

    pub(crate) fn remove_object(&self, kind: &str, name: &str) {
        let _ = std::fs::remove_file(self.object_path(kind, name));
    }

    pub(crate) fn load_objects<T: DeserializeOwned>(&self, kind: &str) -> crate::Result<Vec<T>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.root.join(kind))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                match read_json::<T>(&path) {
                    Ok(Some(value)) => out.push(value),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "skipping unreadable record")
                    }
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> crate::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| crate::Error::config("engine record", e.to_string()))?;
    let tmp = path.with_extension(format!("{}.tmp", super::util::new_id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> crate::Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| crate::Error::config("engine record", e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
