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
        // Only the container's own directory: a record saved after the engine
        // state was deleted must not bring part of that state back.
        match std::fs::create_dir(&dir) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e.into()),
            _ => {}
        }
        write_json(&dir.join("config.json"), record)
    }

    pub(crate) fn save_container_durable(&self, record: &ContainerRecord) -> crate::Result<()> {
        let dir = self.container_dir(&record.id);
        // Do not recreate a removed container or engine while relinquishing its execution.
        let path = dir.join("config.json");
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|error| crate::Error::config("engine execution", error.to_string()))?;
        let mut staged = tempfile::NamedTempFile::new_in(&dir)?;
        use std::io::Write;
        staged.write_all(&bytes)?;
        staged.as_file().sync_all()?;
        staged.persist(&path).map_err(|error| error.error)?;
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn remove_container(&self, id: &str) {
        let _ = std::fs::remove_dir_all(self.container_dir(id));
    }

    pub(crate) fn load_container(&self, id: &str) -> crate::Result<Option<ContainerRecord>> {
        read_json(&self.container_dir(id).join("config.json"))
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

    /// Transfer preflight must see every possible volume user. Ordinary listing
    /// tolerates damaged records; a transfer must refuse to proceed if one could
    /// conceal a writer or a machine-sharing dependency.
    pub(crate) fn transfer_containers(&self) -> crate::Result<Vec<ContainerRecord>> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(self.root.join("containers"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(crate::Error::config(
                    "plan transfer",
                    "invalid container record directory",
                ));
            }
            let path = entry.path().join("config.json");
            let record: ContainerRecord = required_record(&path)?;
            if !valid_id(&record.id) || entry.file_name() != record.id.as_str() {
                return Err(crate::Error::config(
                    "plan transfer",
                    "container record identity does not match its directory",
                ));
            }
            records.push(record);
        }
        records.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(records)
    }

    /// Strict flat-object reader, returning the on-disk key for identity checks.
    pub(crate) fn transfer_objects<T: DeserializeOwned>(
        &self,
        kind: &str,
    ) -> crate::Result<Vec<(String, T)>> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(self.root.join(kind))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let key = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
                    crate::Error::config("plan transfer", "invalid object record name")
                })?;
                records.push((key.to_owned(), required_record(&path)?));
            }
        }
        records.sort_by(|a, b| a.0.cmp(&b.0));
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

    pub(crate) fn remove_object(&self, kind: &str, name: &str) -> crate::Result<()> {
        match std::fs::remove_file(self.object_path(kind, name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(crate::Error::config(
                "engine record",
                format!("remove {kind}/{name}: {e}"),
            )),
        }
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

pub(super) fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn required_record<T: DeserializeOwned>(path: &Path) -> crate::Result<T> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(crate::Error::config(
            "plan transfer",
            "object record is not a regular file",
        ));
    }
    serde_json::from_reader(file).map_err(|error| {
        crate::Error::config(
            "plan transfer",
            format!("unreadable record {}: {error}", path.display()),
        )
    })
}

pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> crate::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| crate::Error::config("engine record", e.to_string()))?;
    let tmp = path.with_extension(format!("{}.tmp", super::util::new_id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub(super) fn read_json<T: DeserializeOwned>(path: &Path) -> crate::Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| crate::Error::config("engine record", e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
