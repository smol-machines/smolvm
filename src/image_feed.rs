//! Read-only archives for a managed Kubernetes guest's image watcher.
//!
//! Publication runs in the existing image mutation, not a background service.
//! This is an import feed, not a shared containerd store: deleting an archive
//! prevents future imports but does not delete an image already in a guest.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Read only the image fields needed by the feed. The Docker API is Unix-only,
// while managed Kubernetes and this archive publisher also compile on Windows.
#[derive(Clone, Deserialize)]
struct ImageRecord {
    id: String,
    repo_tags: Vec<String>,
    pull_ref: String,
}

/// The image catalog directory shared with the Docker-compatible adapter.
pub fn default_root() -> crate::Result<PathBuf> {
    dirs::data_local_dir()
        .map(|path| path.join("smolvm").join("engine"))
        .ok_or_else(|| crate::Error::config("image feed", "no data directory"))
}

const DIRECTORY: &str = "image-feed";
const GUEST_PATH: &str = "/run/smolvm/image-feed";
const MAX_MANIFEST: u64 = 8 * 1024 * 1024;

/// A snapshot of archives available for local Kubernetes import.
#[derive(Debug, Serialize)]
pub struct ImageFeed {
    /// Mount this directory read-only outside the guest's `/workspace`.
    pub path: PathBuf,
    /// Number of tagged local images published in the feed.
    pub images: usize,
    /// Tagged images whose layers are not cached as a host archive.
    /// Registry pulls currently live in VM image seeds, not host archives.
    pub unavailable: Vec<String>,
    /// Managed clusters with a persistent, read-only mount of this feed.
    pub consumers: usize,
    /// Whether the requested machine already has the required mount.
    pub attached: bool,
}

/// Host publication state; guest import readiness must be checked separately.
#[derive(Debug, Serialize)]
pub struct ImageFeedStatus {
    /// Whether the selected cluster has this feed mounted read-only.
    pub attached: bool,
    /// Tagged host images and their current publication state.
    pub images: Vec<PublishedImage>,
}

/// One tagged host image, without reading or modifying its archive contents.
#[derive(Debug, Serialize)]
pub struct PublishedImage {
    /// Image configuration digest.
    pub id: String,
    /// Current image tags, sorted and deduplicated.
    pub tags: Vec<String>,
    /// Whether an archive for this exact image and tag set has been published.
    pub published: bool,
}

/// Observe the catalog without acquiring a publication lock or changing archives.
pub fn inspect(root: &Path, machine: Option<&str>) -> crate::Result<ImageFeedStatus> {
    let config = crate::config::SmolvmConfig::load()?;
    let attached = match machine {
        Some(name) => {
            let record = config
                .get_vm(name)
                .filter(|record| managed(record))
                .ok_or_else(|| {
                    invalid("image feed requires an owned managed Kubernetes machine")
                })?;
            root.join(DIRECTORY)
                .canonicalize()
                .is_ok_and(|path| consumes(record, &path))
        }
        None => false,
    };
    inspect_catalog(root, attached)
}

fn inspect_catalog(root: &Path, attached: bool) -> crate::Result<ImageFeedStatus> {
    let mut images = Vec::new();
    for record in read_images(root)?
        .into_iter()
        .filter(|record| !record.repo_tags.is_empty())
    {
        let mut tags = record.repo_tags.clone();
        tags.sort();
        tags.dedup();
        let path = root.join(DIRECTORY).join(archive_name(&record, &tags)?);
        let published = match fs::symlink_metadata(path) {
            Ok(meta) => meta.file_type().is_file(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        images.push(PublishedImage {
            id: record.id,
            tags,
            published,
        });
    }
    images.sort_by(|left, right| left.tags.cmp(&right.tags).then(left.id.cmp(&right.id)));
    Ok(ImageFeedStatus { attached, images })
}

fn archive_name(record: &ImageRecord, tags: &[String]) -> crate::Result<String> {
    let key =
        serde_json::to_vec(&(&record.id, &record.pull_ref, tags)).map_err(std::io::Error::other)?;
    Ok(format!("{}.tar", hex::encode(Sha256::digest(key))))
}

/// Prepare the default feed without starting the engine or fetching images.
pub fn prepare(root: &Path, machine: Option<&str>) -> crate::Result<ImageFeed> {
    fs::create_dir_all(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    refresh(root, machine)
}

/// Once a consumer has prepared the feed, maintain it on image changes.
#[cfg(unix)]
pub(crate) fn changed(root: &Path) -> crate::Result<()> {
    if root.join(DIRECTORY).try_exists()? {
        refresh(root, None)?;
    }
    Ok(())
}

fn refresh(root: &Path, machine: Option<&str>) -> crate::Result<ImageFeed> {
    // Every publisher reads disk *after* taking this lock. A publisher queued
    // behind another mutation must not re-publish its older in-memory snapshot.
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(root.join("image-feed.lock"))?;
    lock.lock()?;
    let config = crate::config::SmolvmConfig::load()?;
    let path = root.join(DIRECTORY);
    fs::create_dir_all(&path)?;
    let path = path.canonicalize()?;
    let attached = match machine {
        Some(name) => {
            let record = config
                .get_vm(name)
                .filter(|record| managed(record))
                .ok_or_else(|| {
                    invalid("image feed requires an owned managed Kubernetes machine")
                })?;
            let mounted = consumes(record, &path);
            if !mounted
                && record
                    .host_mounts()
                    .iter()
                    .any(|mount| mount.target == Path::new(GUEST_PATH))
            {
                return Err(invalid(
                    "another mount occupies the managed Kubernetes image-feed path",
                )
                .into());
            }
            mounted
        }
        None => false,
    };
    let consumers = config
        .list_vms()
        .filter(|(_, record)| consumes(record, &path))
        .count();
    // Derive consumers from durable VM records rather than a second registry
    // that could survive a crash or a direct `machine delete`. Stopped clusters
    // still consume the feed; deleting the last one releases archived layers.
    let records = if consumers == 0 {
        Vec::new()
    } else {
        read_images(root)?
    };
    // A cancelled publisher may leave a staging directory, but never a partial
    // watched archive. The lock proves none of these publishers is still live.
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".image-feed-stage-")
            && entry.file_type()?.is_dir()
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    let mut result = reconcile(root, &records, |record| {
        crate::data::image_source::archive_file_for_ref(&record.pull_ref)
    })?;
    result.path = path;
    result.consumers = consumers;
    result.attached = attached;
    Ok(result)
}

fn read_images(root: &Path) -> crate::Result<Vec<ImageRecord>> {
    let entries = match fs::read_dir(root.join("images")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut records = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            match fs::read(&path) {
                Ok(bytes) => {
                    records.push(serde_json::from_slice(&bytes).map_err(std::io::Error::other)?)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(records)
}

fn managed(record: &crate::config::VmRecord) -> bool {
    record
        .labels
        .get("smol.workload")
        .is_some_and(|kind| kind == "kubernetes")
        && record
            .labels
            .get("smol.kubernetes.format")
            .is_some_and(|format| format == "1")
        && record
            .labels
            .get("smol.kubernetes.name")
            .is_some_and(|name| !name.is_empty())
}

fn consumes(record: &crate::config::VmRecord, path: &Path) -> bool {
    managed(record)
        && record.host_mounts().iter().any(|mount| {
            mount.read_only
                && !mount.staged
                && mount.target == Path::new(GUEST_PATH)
                && mount
                    .source
                    .canonicalize()
                    .is_ok_and(|source| source == path)
        })
}

fn reconcile(
    root: &Path,
    records: &[ImageRecord],
    archive: impl Fn(&ImageRecord) -> Option<PathBuf>,
) -> crate::Result<ImageFeed> {
    let path = root.join(DIRECTORY);
    if !fs::symlink_metadata(&path)?.file_type().is_dir() {
        return Err(invalid("image feed must be a real directory").into());
    }
    let mut result = ImageFeed {
        path,
        images: 0,
        unavailable: Vec::new(),
        consumers: 0,
        attached: false,
    };
    let mut pending = Vec::new();
    let mut desired = HashSet::new();
    for record in records.iter().filter(|record| !record.repo_tags.is_empty()) {
        let Some(source) = archive(record).filter(|path| path.is_file()) else {
            result.unavailable.push(record.id.clone());
            continue;
        };
        let mut tags = record.repo_tags.clone();
        tags.sort();
        tags.dedup();
        // A different name for every tag set avoids K3s's whole-second mtime
        // cache missing a rebuild/retag of equal size within the same second.
        let name = archive_name(record, &tags)?;
        desired.insert(name.clone());
        pending.push((name, source, record, tags));
    }
    // Remove superseded manifests first, including when producing a replacement
    // fails, so a cold start cannot replay an old archive and restore an old tag.
    for entry in fs::read_dir(&result.path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if owned_archive(name) && !desired.contains(name) {
            fs::remove_file(entry.path())?;
        }
    }
    for (name, source, record, tags) in pending {
        let destination = result.path.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(_) => return Err(invalid("image feed archive is not a regular file").into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                publish(root, &source, &destination, &record.id, &tags)?;
            }
            Err(error) => return Err(error.into()),
        }
        result.images += 1;
    }
    result.unavailable.sort();
    Ok(result)
}

fn owned_archive(name: &str) -> bool {
    name.strip_suffix(".tar")
        .is_some_and(|stem| stem.len() == 64 && stem.bytes().all(|c| c.is_ascii_hexdigit()))
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn publish(
    root: &Path,
    source: &Path,
    destination: &Path,
    id: &str,
    tags: &[String],
) -> crate::Result<()> {
    if !fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(invalid("image source is not a regular archive").into());
    }
    let mut archive = tar::Archive::new(File::open(source)?);
    let mut manifest = None;
    let mut members = HashSet::new();
    let mut manifest_last = false;
    let hex = id
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("invalid image config digest"))?;
    let config_names = [
        format!("blobs/sha256/{hex}"),
        format!("sha256-{hex}"),
        format!("{hex}.json"),
    ];
    let mut verified_configs = HashSet::new();
    // Seek over layer bodies: publication must not read GBs of image data.
    for entry in archive.entries_with_seek()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if !entry.header().entry_type().is_file()
            || !path
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            || !members.insert(path.clone())
        {
            return Err(invalid("unsafe or duplicate image archive member").into());
        }
        manifest_last = path == Path::new("manifest.json");
        if config_names.iter().any(|name| path == Path::new(name)) {
            if entry.size() > 16 * 1024 * 1024 {
                return Err(invalid("image config exceeds 16 MiB").into());
            }
            let mut hasher = Sha256::new();
            std::io::copy(&mut entry, &mut hasher)?;
            if hex::encode(hasher.finalize()) != hex {
                return Err(invalid("image config digest mismatch").into());
            }
            verified_configs.insert(path.clone());
        }
        if manifest_last {
            if entry.size() > MAX_MANIFEST {
                return Err(invalid("image manifest exceeds 8 MiB").into());
            }
            let offset = entry.raw_header_position();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            manifest = Some((
                offset,
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .map_err(std::io::Error::other)?,
            ));
        }
    }
    let (offset, mut manifest) = manifest.ok_or_else(|| invalid("missing image manifest"))?;
    let entries = manifest
        .as_array_mut()
        .filter(|items| items.len() == 1)
        .ok_or_else(|| invalid("image feed requires a single-image archive"))?;
    let image = &mut entries[0];
    if image["Config"]
        .as_str()
        .is_none_or(|config| !verified_configs.contains(Path::new(config)))
    {
        return Err(invalid("archive config does not match the image record").into());
    }
    let layers = image["Layers"]
        .as_array()
        .ok_or_else(|| invalid("missing image layers"))?;
    if layers.iter().any(|layer| {
        layer
            .as_str()
            .is_none_or(|name| !members.contains(Path::new(name)))
    }) {
        return Err(invalid("image archive has missing layers").into());
    }
    let existing: Vec<String> =
        serde_json::from_value(image["RepoTags"].clone()).unwrap_or_default();
    let mut sorted = existing;
    sorted.sort();
    sorted.dedup();
    // Staging stays outside the watched directory: no partial archive events.
    let staging = tempfile::Builder::new()
        .prefix(".image-feed-stage-")
        .tempdir_in(root)?;
    let staged = staging.path().join("image.tar");
    if sorted == tags {
        if fs::hard_link(source, &staged).is_err() {
            crate::disk_utils::clone_or_copy_file(source, &staged)?;
        }
    } else {
        image["RepoTags"] = serde_json::json!(tags);
        let bytes = serde_json::to_vec(&manifest).map_err(std::io::Error::other)?;
        let mut tar = if manifest_last {
            // APFS clonefile / Linux reflink when supported. Never edit a hard
            // link to the cache; only the small trailing manifest changes.
            crate::disk_utils::clone_or_copy_file(source, &staged)?;
            let mut file = OpenOptions::new().write(true).open(&staged)?;
            file.set_len(offset)?;
            file.seek(SeekFrom::Start(offset))?;
            tar::Builder::new(file)
        } else {
            // Host-fetched registry archives put their manifest first. Stream
            // these once, keeping memory bounded; later refreshes reuse the file.
            let mut output = tar::Builder::new(File::create(&staged)?);
            let mut source = tar::Archive::new(File::open(source)?);
            for entry in source.entries()? {
                let mut entry = entry?;
                let path = entry.path()?.into_owned();
                if path != Path::new("manifest.json") {
                    output.append_data(&mut entry.header().clone(), path, &mut entry)?;
                }
            }
            output
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "manifest.json", bytes.as_slice())?;
        tar.into_inner()?.sync_all()?;
    }
    fs::rename(staged, destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn observing_an_absent_feed_does_not_create_it() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("engine");
        assert!(inspect_catalog(&root, false).unwrap().images.is_empty());
        assert!(!root.exists());
    }

    #[test]
    fn observed_publication_requires_the_current_tag_set_without_reconciling() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(DIRECTORY)).unwrap();
        fs::create_dir(root.path().join("images")).unwrap();
        let (record, source) = fixture(root.path(), "v1", &["app:dev"]);
        reconcile(root.path(), std::slice::from_ref(&record), |_| {
            Some(source.clone())
        })
        .unwrap();
        let catalog = root.path().join("images/image.json");
        let mut value = serde_json::json!({"id":record.id,"repo_tags":record.repo_tags,"pull_ref":record.pull_ref});
        fs::write(&catalog, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(inspect_catalog(root.path(), true).unwrap().images[0].published);
        value["repo_tags"] = serde_json::json!(["app:dev", "app:stable"]);
        fs::write(&catalog, serde_json::to_vec(&value).unwrap()).unwrap();
        let before = archives(root.path());
        let status = inspect_catalog(root.path(), true).unwrap();
        assert!(!status.images[0].published);
        assert_eq!(status.images[0].tags, ["app:dev", "app:stable"]);
        assert_eq!(
            archives(root.path()),
            before,
            "observation reconciled archives"
        );
        assert!(!root.path().join("image-feed.lock").exists());
    }

    #[test]
    fn only_managed_clusters_with_a_live_readonly_mount_keep_the_feed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        let mut record = crate::config::VmRecord::new("test".into(), 2, 2048, vec![], vec![], true);
        record
            .mounts
            .push((path.to_string_lossy().into_owned(), GUEST_PATH.into(), true));
        assert!(!consumes(&record, &path), "unmanaged VM claimed the feed");
        record.labels.extend([
            ("smol.workload".into(), "kubernetes".into()),
            ("smol.kubernetes.format".into(), "1".into()),
            ("smol.kubernetes.name".into(), "test".into()),
        ]);
        assert!(
            consumes(&record, &path),
            "stopped clusters need rebuilds too"
        );
        assert!(!consumes(&record, &path.join("another-engine")));
        record.mounts[0].2 = false;
        assert!(!consumes(&record, &path), "writable feed is not supported");
        record.mounts.clear();
        record
            .staged_mounts
            .push((0, path.to_string_lossy().into_owned(), GUEST_PATH.into()));
        assert!(
            !consumes(&record, &path),
            "staged mounts cannot receive rebuilds"
        );
    }

    fn fixture(root: &Path, marker: &str, tags: &[&str]) -> (ImageRecord, PathBuf) {
        let config =
            serde_json::to_vec(&serde_json::json!({"architecture":"amd64", "marker":marker}))
                .unwrap();
        let id = format!("sha256:{}", hex::encode(Sha256::digest(&config)));
        let tags: Vec<_> = tags.iter().map(|s| s.to_string()).collect();
        let path = root.join(format!("{marker}.tar"));
        let config_name = format!("blobs/sha256/{}", id.trim_start_matches("sha256:"));
        let layer_name = format!(
            "blobs/sha256/{}",
            hex::encode(Sha256::digest(marker.as_bytes()))
        );
        let manifest = serde_json::to_vec(&serde_json::json!([{
            "Config":config_name,"RepoTags":tags,"Layers":[layer_name],
        }]))
        .unwrap();
        let mut tar = tar::Builder::new(File::create(&path).unwrap());
        for (name, bytes) in [
            (config_name.as_str(), config.as_slice()),
            (layer_name.as_str(), marker.as_bytes()),
            ("manifest.json", manifest.as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes).unwrap();
        }
        tar.finish().unwrap();
        drop(tar);
        let record = ImageRecord {
            id,
            repo_tags: tags,
            pull_ref: format!("local:{marker}"),
        };
        (record, path)
    }

    fn archives(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root.join(DIRECTORY))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    fn manifest(path: &Path) -> serde_json::Value {
        let mut tar = tar::Archive::new(File::open(path).unwrap());
        for entry in tar.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() == Path::new("manifest.json") {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                return serde_json::from_slice(&bytes).unwrap();
            }
        }
        panic!("no manifest");
    }

    #[test]
    fn rebuild_retag_and_remove_do_not_replay_stale_tags_or_modify_source() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(DIRECTORY)).unwrap();
        let (mut old, first) = fixture(root.path(), "v1", &["app:dev", "app:keep"]);
        let (new, second) = fixture(root.path(), "v2", &["app:dev"]);
        let original = fs::read(&first).unwrap();
        let source = |record: &ImageRecord| {
            Some(if record.id == old.id {
                first.clone()
            } else {
                second.clone()
            })
        };
        let result = reconcile(root.path(), &[old.clone()], source).unwrap();
        assert_eq!(result.images, 1);
        assert!(result.unavailable.is_empty());
        let initial = archives(root.path()).pop().unwrap();
        // Common builds share the source inode; layer bytes aren't recopied.
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&initial).unwrap().ino(),
            fs::metadata(&first).unwrap().ino()
        );
        old.repo_tags = vec!["app:keep".into()];
        let source = |record: &ImageRecord| {
            Some(if record.id == old.id {
                first.clone()
            } else {
                second.clone()
            })
        };
        reconcile(root.path(), &[old.clone(), new.clone()], source).unwrap();
        assert!(!initial.exists());
        let current = archives(root.path());
        assert_eq!(current.len(), 2);
        let mut tags: Vec<_> = current
            .iter()
            .map(|path| manifest(path)[0]["RepoTags"].clone())
            .collect();
        tags.sort_by_key(|value| value.to_string());
        assert_eq!(
            tags,
            vec![
                serde_json::json!(["app:dev"]),
                serde_json::json!(["app:keep"])
            ]
        );
        assert_eq!(fs::read(&first).unwrap(), original, "retag mutated cache");
        let before: HashSet<_> = current.into_iter().collect();
        reconcile(root.path(), &[old.clone(), new.clone()], source).unwrap();
        assert_eq!(
            archives(root.path()).into_iter().collect::<HashSet<_>>(),
            before
        );
        reconcile(root.path(), &[new], source).unwrap();
        assert_eq!(archives(root.path()).len(), 1);
        reconcile(root.path(), &[], source).unwrap();
        assert!(archives(root.path()).is_empty());
    }

    #[test]
    fn unavailable_images_are_reported_without_fetching_and_stale_feed_is_removed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(DIRECTORY)).unwrap();
        let (record, source) = fixture(root.path(), "v1", &["app:dev"]);
        reconcile(root.path(), std::slice::from_ref(&record), |_| {
            Some(source.clone())
        })
        .unwrap();
        fs::remove_file(source).unwrap();
        let result = reconcile(root.path(), std::slice::from_ref(&record), |_| None).unwrap();
        assert_eq!(result.unavailable, vec![record.id]);
        assert_eq!(result.images, 0);
        assert!(archives(root.path()).is_empty());
    }

    #[test]
    fn failed_publication_never_exposes_partial_archives() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(DIRECTORY)).unwrap();
        let (record, source) = fixture(root.path(), "v1", &["app:dev"]);
        let mut invalid_record = record.clone();
        invalid_record.id = format!("sha256:{}", "a".repeat(64));
        assert!(reconcile(root.path(), &[invalid_record], |_| Some(source.clone())).is_err());
        assert!(archives(root.path()).is_empty());
        #[cfg(unix)]
        {
            let linked = root.path().join("linked.tar");
            std::os::unix::fs::symlink(&source, &linked).unwrap();
            assert!(reconcile(root.path(), &[record], |_| Some(linked.clone())).is_err());
            assert!(archives(root.path()).is_empty());
        }
    }

    #[test]
    fn manifest_first_registry_archive_can_be_retagged_without_losing_layers() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(DIRECTORY)).unwrap();
        let (record, original) = fixture(root.path(), "v1", &[]);
        let source = root.path().join("registry.tar");
        let mut doc = manifest(&original);
        let config_name = record.id.replace(':', "-");
        doc[0]["Config"] = serde_json::json!(config_name);
        let bytes = serde_json::to_vec(&doc).unwrap();
        let mut output = tar::Builder::new(File::create(&source).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        output
            .append_data(&mut header, "manifest.json", bytes.as_slice())
            .unwrap();
        let mut input = tar::Archive::new(File::open(&original).unwrap());
        let canonical_config = format!("blobs/sha256/{}", record.id.trim_start_matches("sha256:"));
        for entry in input.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            if path == Path::new("manifest.json") {
                continue;
            }
            let name = if path == Path::new(&canonical_config) {
                PathBuf::from(&config_name)
            } else {
                path
            };
            output
                .append_data(&mut entry.header().clone(), name, &mut entry)
                .unwrap();
        }
        output.finish().unwrap();
        drop(output);
        let before = fs::read(&source).unwrap();
        let mut record = record;
        record.repo_tags = vec!["registry.example/app:dev".into()];
        reconcile(root.path(), &[record], |_| Some(source.clone())).unwrap();
        let published = archives(root.path()).pop().unwrap();
        assert_eq!(
            manifest(&published)[0]["RepoTags"],
            serde_json::json!(["registry.example/app:dev"])
        );
        let mut tar = tar::Archive::new(File::open(published).unwrap());
        let layers: Vec<_> = tar
            .entries()
            .unwrap()
            .map(|entry| {
                let mut entry = entry.unwrap();
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                bytes
            })
            .collect();
        assert!(layers.iter().any(|bytes| bytes == b"v1"));
        assert_eq!(fs::read(source).unwrap(), before);
    }
}
