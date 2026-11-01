//! Agent rootfs trees a machine is pinned to, kept by content digest.
//!
//! A checkpoint (and a pause) freezes processes that keep the agent rootfs they
//! booted with mapped: busybox, musl, the agent's own files. The host serves
//! that rootfs over virtio-fs, so a restore under a rootfs with other bytes at
//! the same paths gives those processes pages from the wrong userland, and the
//! first program the guest runs dies with a signal. Every machine therefore
//! records the digest of the rootfs it booted with ([`VmRecord::agent_rootfs_digest`]),
//! every checkpoint carries that digest and a copy of the tree, and a live
//! restore boots the tree with that digest: the host's installed rootfs when it
//! still matches, else a copy kept here, installed from the checkpoint by the
//! first restore that needs it. A cold start always takes the installed rootfs,
//! which is how a machine moves onto an upgraded one.
//!
//! Layout: `<cache_dir>/smolvm/agent-rootfs-store/<hex>/`, one tree per
//! digest, written under a staging name and renamed into place once its digest
//! has been checked.
//!
//! [`VmRecord::agent_rootfs_digest`]: crate::config::VmRecord::agent_rootfs_digest

use crate::{Error, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The store at one root directory.
pub struct Store {
    root: PathBuf,
}

/// The host's store, `<cache_dir>/smolvm/agent-rootfs-store`.
pub fn host() -> Store {
    Store::at(
        dirs::cache_dir()
            .or_else(dirs::data_local_dir)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("smolvm")
            .join("agent-rootfs-store"),
    )
}

/// The digest of the host's installed rootfs, `None` when it cannot be read.
pub fn installed_default_digest() -> Option<String> {
    let dir = super::AgentManager::default_rootfs_path().ok()?;
    smolvm_pack::assets::cached_agent_rootfs_digest(&dir).ok()
}

/// The rootfs a machine pinned to `digest` boots: the host's installed one when
/// its digest matches, else the host store's copy.
pub fn resolve(digest: &str) -> Result<PathBuf> {
    host().resolve_with(digest, &super::AgentManager::default_rootfs_path()?)
}

/// The hex part of a `sha256:<hex>` digest, refusing anything that could name
/// a path outside the store.
fn hex_of(digest: &str) -> Result<&str> {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex)
    } else {
        Err(Error::agent(
            "agent rootfs store",
            format!("'{digest}' is not a sha256 rootfs digest"),
        ))
    }
}

impl Store {
    /// The store rooted at `root`.
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// The directory the trees live under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where the tree with `digest` lives, installed or not.
    pub fn path_for(&self, digest: &str) -> Result<PathBuf> {
        Ok(self.root.join(hex_of(digest)?))
    }

    /// The installed tree with `digest`, if the store has one.
    pub fn installed(&self, digest: &str) -> Option<PathBuf> {
        let dir = self.path_for(digest).ok()?;
        std::fs::symlink_metadata(dir.join("sbin/init"))
            .is_ok()
            .then_some(dir)
    }

    /// The rootfs a machine pinned to `digest` boots: `default` when its digest
    /// matches, else this store's copy.
    pub fn resolve_with(&self, digest: &str, default: &Path) -> Result<PathBuf> {
        if smolvm_pack::assets::cached_agent_rootfs_digest(default)
            .ok()
            .as_deref()
            == Some(digest)
        {
            return Ok(default.to_path_buf());
        }
        self.installed(digest).ok_or_else(|| {
            Error::agent(
                "agent rootfs",
                format!(
                    "this machine's live state was captured with agent rootfs {digest}, which this \
                     host no longer has (its installed rootfs differs and the store at {} holds no \
                     copy); stop and start the machine to boot it cold on the installed rootfs, or \
                     restore the checkpoint again, which installs the copy it carries",
                    self.root.display()
                ),
            )
        })
    }

    /// Keep a copy of the tree at `source` as the store's copy for `digest`,
    /// if the store does not have one. The tree's digest is checked first, so
    /// a checkpoint that carries one rootfs and names another installs nothing.
    /// `source` is left as it is: it may be a shared extraction other restores
    /// read.
    pub fn install_from_dir(&self, digest: &str, source: &Path) -> Result<PathBuf> {
        if let Some(installed) = self.installed(digest) {
            return Ok(installed);
        }
        let actual = smolvm_pack::assets::agent_rootfs_digest(source)
            .map_err(|e| Error::agent("read agent rootfs", e.to_string()))?;
        if actual != digest {
            return Err(Error::agent(
                "agent rootfs store",
                format!(
                    "the rootfs at {} has digest {actual}, not {digest}",
                    source.display()
                ),
            ));
        }
        let staging = self.staging_dir(digest, "copy")?;
        let result = copy_tree(source, &staging).and_then(|()| self.publish(digest, &staging));
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&staging);
        }
        result
    }

    /// [`Self::install_from_dir`] from the `agent-rootfs.tar` a checkpoint
    /// carries, which must unpack to a tree with `digest`.
    pub fn install_from_tar(&self, digest: &str, tar: &Path) -> Result<PathBuf> {
        if let Some(installed) = self.installed(digest) {
            return Ok(installed);
        }
        let (actual, path) = self.install_tar(tar)?;
        if actual != digest {
            let _ = std::fs::remove_dir_all(&path);
            return Err(Error::agent(
                "agent rootfs store",
                format!(
                    "the rootfs in {} has digest {actual}, not {digest}",
                    tar.display()
                ),
            ));
        }
        Ok(path)
    }

    /// Keep the tree the `agent-rootfs.tar` at `tar` unpacks to, under the
    /// digest it turns out to have (a checkpoint from before the digest was
    /// recorded). Returns that digest and the installed tree.
    pub fn install_tar(&self, tar: &Path) -> Result<(String, PathBuf)> {
        let unpacked = self.staging_dir("unknown", "unpack")?;
        let result = (|| -> Result<(String, PathBuf)> {
            std::fs::create_dir(&unpacked)?;
            let mut archive = tar::Archive::new(std::fs::File::open(tar)?);
            archive.set_preserve_permissions(true);
            archive.set_overwrite(true);
            archive
                .unpack(&unpacked)
                .map_err(|e| Error::agent("unpack agent rootfs", e.to_string()))?;
            let digest = smolvm_pack::assets::agent_rootfs_digest(&unpacked)
                .map_err(|e| Error::agent("read agent rootfs", e.to_string()))?;
            let path = self.publish(&digest, &unpacked)?;
            Ok((digest, path))
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&unpacked);
        }
        result
    }

    /// A free staging path under the store for a tree being installed.
    fn staging_dir(&self, label: &str, what: &str) -> Result<PathBuf> {
        std::fs::create_dir_all(&self.root)?;
        let label = hex_of(label).map(|hex| &hex[..16]).unwrap_or(label);
        let staging = self
            .root
            .join(format!(".{label}-{}.{what}", std::process::id()));
        let _ = std::fs::remove_dir_all(&staging);
        Ok(staging)
    }

    /// Move the staged tree into place as the store's copy for `digest`.
    fn publish(&self, digest: &str, staging: &Path) -> Result<PathBuf> {
        let destination = self.path_for(digest)?;
        match std::fs::rename(staging, &destination) {
            Ok(()) => Ok(destination),
            // another process installed the same digest meanwhile: theirs is as good
            Err(_) if self.installed(digest).is_some() => {
                let _ = std::fs::remove_dir_all(staging);
                Ok(destination)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Remove every installed tree whose digest is not in `referenced` (the
    /// digests machines are pinned to) and is not `keep` (the installed
    /// rootfs's own). Best effort.
    pub fn prune(&self, referenced: &HashSet<String>, keep: Option<&str>) {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                // a staging tree from a process that died: gone after a day
                let stale = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|m| m.elapsed().ok())
                    .is_some_and(|age| age > std::time::Duration::from_secs(24 * 3600));
                if stale {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
                continue;
            }
            let digest = format!("sha256:{name}");
            if referenced.contains(&digest) || keep == Some(digest.as_str()) {
                continue;
            }
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Copy a tree with its symlinks and permission bits.
fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    std::fs::set_permissions(destination, std::fs::metadata(source)?.permissions())?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(std::fs::read_link(entry.path())?, &target)?;
            #[cfg(not(unix))]
            std::fs::copy(entry.path(), &target)?;
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn rootfs(dir: &Path, agent: &[u8]) {
        std::fs::create_dir_all(dir.join("sbin")).unwrap();
        std::fs::create_dir_all(dir.join("usr/local/bin")).unwrap();
        std::fs::write(dir.join("usr/local/bin/smolvm-agent"), agent).unwrap();
        std::os::unix::fs::symlink("/usr/local/bin/smolvm-agent", dir.join("sbin/init")).unwrap();
    }

    #[test]
    fn a_tree_is_installed_once_under_its_digest_and_a_wrong_digest_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let source = temp.path().join("rootfs");
        rootfs(&source, b"agent v1");
        let digest = smolvm_pack::assets::agent_rootfs_digest(&source).unwrap();
        assert!(store.installed(&digest).is_none());

        let wrong = format!("sha256:{}", "0".repeat(64));
        let err = store
            .install_from_dir(&wrong, &source)
            .unwrap_err()
            .to_string();
        assert!(err.contains("has digest"), "{err}");

        // a default rootfs with the same content is preferred over the store
        let default = temp.path().join("default");
        rootfs(&default, b"agent v1");
        assert_eq!(store.resolve_with(&digest, &default).unwrap(), default);
        // one with other content leaves the pin unresolved until the store has a copy
        std::fs::write(default.join("usr/local/bin/smolvm-agent"), b"agent v3").unwrap();
        let err = store
            .resolve_with(&digest, &default)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no longer has"), "{err}");

        let installed_at = store.install_from_dir(&digest, &source).unwrap();
        assert!(
            std::fs::symlink_metadata(source.join("sbin/init")).is_ok(),
            "the source is copied, not moved"
        );
        assert_eq!(store.installed(&digest), Some(installed_at.clone()));
        assert_eq!(
            smolvm_pack::assets::agent_rootfs_digest(&installed_at).unwrap(),
            digest
        );
        assert_eq!(store.resolve_with(&digest, &default).unwrap(), installed_at);

        // from the tar a checkpoint carries, for a second digest; and by the
        // digest it turns out to have, for a checkpoint that recorded none
        let other = temp.path().join("other");
        rootfs(&other, b"agent v2");
        let other_digest = smolvm_pack::assets::agent_rootfs_digest(&other).unwrap();
        let tar_path = temp.path().join("agent-rootfs.tar");
        let mut builder = tar::Builder::new(std::fs::File::create(&tar_path).unwrap());
        builder.follow_symlinks(false);
        builder.append_dir_all("sbin", other.join("sbin")).unwrap();
        builder.append_dir_all("usr", other.join("usr")).unwrap();
        builder.finish().unwrap();
        let err = store
            .install_from_tar(&wrong, &tar_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("has digest"), "{err}");
        assert!(store.installed(&other_digest).is_none());
        let from_tar = store.install_from_tar(&other_digest, &tar_path).unwrap();
        assert_eq!(store.installed(&other_digest), Some(from_tar.clone()));
        assert_eq!(
            store.install_tar(&tar_path).unwrap(),
            (other_digest.clone(), from_tar)
        );
        assert!(
            std::fs::read_dir(store.root()).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with('.')),
            "no staging directories remain"
        );

        // pruning keeps the referenced tree and drops the other
        store.prune(&HashSet::from([digest.clone()]), None);
        assert!(store.installed(&digest).is_some());
        assert!(store.installed(&other_digest).is_none());
    }

    #[test]
    fn a_digest_that_is_not_hex_names_no_path() {
        let store = Store::at(PathBuf::from("/nonexistent"));
        assert!(store.path_for("sha256:../../etc").is_err());
        assert!(store.path_for("latest").is_err());
        assert!(store
            .path_for(&format!("sha256:{}", "a".repeat(64)))
            .is_ok());
    }
}
