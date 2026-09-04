//! Batched synchronization for guest-local staged mounts.
//!
//! A staged mount runs from a guest-local working copy. Synchronization streams
//! one tar archive over vsock, then applies it on the host in a filesystem
//! batch. This avoids one virtiofs round trip per small file while keeping the
//! mode explicit.

use crate::agent::AgentClient;
use crate::config::VmRecord;
use crate::HostMount;
use crate::{Error, Result};
use std::collections::HashSet;
use std::path::Component;
use std::path::{Path, PathBuf};

/// Synchronize every staged mount in `record` back to its host source.
///
/// Live `rw` and `ro` mounts are ignored. The caller must hold the machine's
/// lifecycle lock (or otherwise serialize agent operations) while this runs.
pub fn sync_staged_mounts(record: &VmRecord, client: &mut AgentClient) -> Result<()> {
    sync_mounts(&record.host_mounts(), client)
}

/// Synchronize staged mounts from a launch configuration that has not yet been
/// persisted as a named machine (the foreground `machine run` path).
pub fn sync_mounts(mounts: &[HostMount], client: &mut AgentClient) -> Result<()> {
    for mount in mounts {
        if !mount.staged {
            continue;
        }
        sync_one(&mount.source, &mount.target, client)?;
    }
    Ok(())
}

fn sync_one(host_source: &Path, guest_target: &Path, client: &mut AgentClient) -> Result<()> {
    let temporary = tempfile::Builder::new()
        .prefix("smolvm-staged-sync-")
        .tempdir()
        .map_err(|error| Error::agent("sync staged mount", error.to_string()))?;
    let archive_path = temporary.path().join("contents.tar");
    client.archive_directory_to_path(&guest_target.to_string_lossy(), &archive_path, |_| {})?;
    apply_archive(&archive_path, host_source)
}

fn apply_archive(archive_path: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)
        .map_err(|error| Error::agent("create sync destination", error.to_string()))?;

    // Validate the complete archive before touching the host tree. Besides
    // blocking special files, this first pass records the desired entry types
    // so the extraction pass can safely replace file <-> directory changes.
    let file = std::fs::File::open(archive_path)
        .map_err(|error| Error::agent("open staged archive", error.to_string()))?;
    let mut archive = tar::Archive::new(file);
    let mut wanted = HashSet::<PathBuf>::new();
    let mut desired_types = Vec::new();
    for entry in archive
        .entries()
        .map_err(|error| Error::agent("read staged archive", error.to_string()))?
    {
        let entry =
            entry.map_err(|error| Error::agent("read staged archive", error.to_string()))?;
        let raw_path = entry
            .path()
            .map_err(|error| Error::agent("read staged archive path", error.to_string()))?
            .into_owned();
        let relative = normalize_archive_path(&raw_path)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() && !entry_type.is_dir() && !entry_type.is_symlink() {
            return Err(Error::agent(
                "sync staged mount",
                format!(
                    "unsupported special file in staged tree: {}",
                    raw_path.display()
                ),
            ));
        }
        desired_types.push((relative.clone(), entry_type));
        let mut ancestor = Some(relative.as_path());
        while let Some(path) = ancestor {
            if !path.as_os_str().is_empty() {
                wanted.insert(path.to_path_buf());
            }
            ancestor = path.parent();
        }
    }

    drop(archive);
    let file = std::fs::File::open(archive_path)
        .map_err(|error| Error::agent("reopen staged archive", error.to_string()))?;
    let mut archive = tar::Archive::new(file);
    let mut desired_types = desired_types.into_iter();
    for entry in archive
        .entries()
        .map_err(|error| Error::agent("read staged archive", error.to_string()))?
    {
        let mut entry =
            entry.map_err(|error| Error::agent("read staged archive", error.to_string()))?;
        let raw_path = entry
            .path()
            .map_err(|error| Error::agent("read staged archive path", error.to_string()))?
            .into_owned();
        let relative = normalize_archive_path(&raw_path)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let (validated_path, entry_type) = desired_types.next().ok_or_else(|| {
            Error::agent(
                "sync staged mount",
                "archive changed between validation and extraction",
            )
        })?;
        if relative != validated_path {
            return Err(Error::agent(
                "sync staged mount",
                "archive changed between validation and extraction",
            ));
        }
        prepare_entry_destination(destination, &relative, entry_type)?;
        if !entry
            .unpack_in(destination)
            .map_err(|error| Error::agent("extract staged archive", error.to_string()))?
        {
            return Err(Error::agent(
                "extract staged archive",
                format!(
                    "archive path '{}' escaped the destination",
                    relative.display()
                ),
            ));
        }
    }
    if desired_types.next().is_some() {
        return Err(Error::agent(
            "sync staged mount",
            "archive changed between validation and extraction",
        ));
    }

    drop(archive);
    std::fs::remove_file(archive_path)
        .map_err(|error| Error::agent("remove staged archive", error.to_string()))?;
    prune_stale_paths(destination, Path::new(""), &wanted)
}

fn prepare_entry_destination(root: &Path, relative: &Path, desired: tar::EntryType) -> Result<()> {
    let path = root.join(relative);
    let Ok(existing) = std::fs::symlink_metadata(&path) else {
        return Ok(());
    };
    let existing_is_dir = existing.is_dir() && !existing.file_type().is_symlink();
    let desired_is_dir = desired.is_dir();
    if existing_is_dir != desired_is_dir
        || existing.file_type().is_symlink()
        || desired.is_symlink()
    {
        remove_path(&path)?;
    }
    Ok(())
}

fn normalize_archive_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::agent(
                    "sync staged mount",
                    format!("archive contains unsafe path '{}'", path.display()),
                ));
            }
        }
    }
    Ok(normalized)
}

fn prune_stale_paths(root: &Path, relative: &Path, wanted: &HashSet<PathBuf>) -> Result<()> {
    let directory = root.join(relative);
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| Error::agent("read sync destination", error.to_string()))?
    {
        let entry =
            entry.map_err(|error| Error::agent("read sync destination", error.to_string()))?;
        let name = entry.file_name();
        let child_relative = relative.join(name);
        if !wanted.contains(&child_relative) {
            remove_path(&entry.path())?;
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|error| Error::agent("inspect staged path", error.to_string()))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            prune_stale_paths(root, &child_relative, wanted)?;
        }
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::agent("inspect stale staged path", error.to_string()))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
            .map_err(|error| Error::agent("remove stale staged directory", error.to_string()))
    } else {
        std::fs::remove_file(path)
            .map_err(|error| Error::agent("remove stale staged file", error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_updates_creates_and_deletes_without_following_symlinks() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("changed"), b"new").unwrap();
        std::fs::create_dir(source.path().join("dir")).unwrap();
        std::fs::write(source.path().join("dir/added"), b"added").unwrap();
        std::fs::write(destination.path().join("changed"), b"old").unwrap();
        std::fs::write(destination.path().join("deleted"), b"delete me").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("changed", source.path().join("link")).unwrap();

        let archive_path = destination.path().join(".smolvm-staged-sync-test.tar");
        let archive_file = std::fs::File::create(&archive_path).unwrap();
        let mut builder = tar::Builder::new(archive_file);
        builder.follow_symlinks(false);
        builder.append_dir_all(".", source.path()).unwrap();
        builder.finish().unwrap();
        drop(builder);

        apply_archive(&archive_path, destination.path()).unwrap();

        assert_eq!(
            std::fs::read(destination.path().join("changed")).unwrap(),
            b"new"
        );
        assert_eq!(
            std::fs::read(destination.path().join("dir/added")).unwrap(),
            b"added"
        );
        assert!(!destination.path().join("deleted").exists());
        #[cfg(unix)]
        assert_eq!(
            std::fs::read_link(destination.path().join("link")).unwrap(),
            PathBuf::from("changed")
        );
    }

    #[test]
    fn mirror_replaces_files_and_directories_in_both_directions() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("was-file")).unwrap();
        std::fs::write(source.path().join("was-file/child"), b"child").unwrap();
        std::fs::write(source.path().join("was-dir"), b"file now").unwrap();
        std::fs::write(destination.path().join("was-file"), b"old file").unwrap();
        std::fs::create_dir(destination.path().join("was-dir")).unwrap();
        std::fs::write(destination.path().join("was-dir/old"), b"old child").unwrap();

        let archive_path = destination.path().join(".smolvm-staged-types.tar");
        let archive_file = std::fs::File::create(&archive_path).unwrap();
        let mut builder = tar::Builder::new(archive_file);
        builder.append_dir_all(".", source.path()).unwrap();
        builder.finish().unwrap();
        drop(builder);

        apply_archive(&archive_path, destination.path()).unwrap();

        assert_eq!(
            std::fs::read(destination.path().join("was-file/child")).unwrap(),
            b"child"
        );
        assert_eq!(
            std::fs::read(destination.path().join("was-dir")).unwrap(),
            b"file now"
        );
    }
}
