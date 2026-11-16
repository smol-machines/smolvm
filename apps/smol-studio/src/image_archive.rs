//! Reviewed Docker/OCI imports and atomic publication of Docker image exports.
use crate::{command_progress::Progress, runtime::capture_process};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

#[derive(Clone, Debug)]
pub enum Request {
    Import(PathBuf),
    Export { image_id: String, path: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    size: u64,
    modified: SystemTime,
    #[cfg(unix)]
    identity: (u64, u64),
}
impl Stamp {
    fn read(meta: Metadata) -> Result<Self, String> {
        if !meta.is_file() {
            return Err("Choose a regular file.".into());
        }
        Ok(Self {
            size: meta.len(),
            modified: meta.modified().map_err(|e| e.to_string())?,
            #[cfg(unix)]
            identity: {
                use std::os::unix::fs::MetadataExt;
                (meta.dev(), meta.ino())
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub path: PathBuf,
    /// None for import; an immutable image ID for export.
    pub image_id: Option<String>,
    pub tags: Vec<String>,
    pub size: u64,
    previous: Option<Stamp>,
    input: Option<Arc<File>>,
}
impl Plan {
    pub fn importing(&self) -> bool {
        self.image_id.is_none()
    }
    pub fn replaces_file(&self) -> bool {
        !self.importing() && self.previous.is_some()
    }
}

fn target_stamp(path: &Path) -> Result<Option<Stamp>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("Choose a file, not a symbolic link.".into())
        }
        Ok(meta) => Stamp::read(meta).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Cannot inspect {}: {e}", path.display())),
    }
}

fn image(id: &str, shutdown: &AtomicBool) -> Result<(Vec<String>, u64), String> {
    crate::storage::validate_image_id(id)?;
    let mut cmd = crate::docker::docker_command();
    cmd.args([
        "--context",
        "smol",
        "image",
        "inspect",
        "--format",
        "{{json .}}",
        id,
    ]);
    let out = capture_process(&mut cmd, Duration::from_secs(20), 2 * 1024 * 1024, shutdown)?;
    if !out.success {
        return Err(crate::runtime::runtime_error(&out.stderr, out.code));
    }
    let doc: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("Cannot read image details: {e}"))?;
    if doc["Id"].as_str() != Some(id) {
        return Err("The selected image changed. Refresh the image list.".into());
    }
    let mut tags: Vec<String> = match doc.get("RepoTags") {
        Some(Value::Null) => vec![],
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|e| format!("Cannot read image tags: {e}"))?,
        None => return Err("The engine did not report this image's tags.".into()),
    };
    tags.retain(|t| t != "<none>:<none>");
    for tag in &tags {
        crate::storage::validate_reference(tag)?;
    }
    tags.sort();
    tags.dedup();
    Ok((tags, doc["Size"].as_u64().unwrap_or(0)))
}

pub fn review(request: &Request, shutdown: &AtomicBool) -> Result<Plan, String> {
    let (path, id) = match request {
        Request::Import(path) => (path, None),
        Request::Export { image_id, path } => (path, Some(image_id)),
    };
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("Choose a file using an absolute path.".into());
    }
    let parent = path
        .parent()
        .unwrap()
        .canonicalize()
        .map_err(|e| format!("Cannot open the containing folder: {e}"))?;
    if !parent.is_dir() {
        return Err("The containing folder is not a directory.".into());
    }
    let path = parent.join(path.file_name().unwrap());
    let previous = target_stamp(&path)?;
    if let Some(id) = id {
        let (tags, size) = image(id, shutdown)?;
        Ok(Plan {
            path,
            image_id: Some(id.clone()),
            tags,
            size,
            previous,
            input: None,
        })
    } else {
        let stamp = previous.as_ref().ok_or("This archive does not exist.")?;
        if stamp.size == 0 {
            return Err("This archive is empty.".into());
        }
        let file = File::open(&path).map_err(|e| format!("Cannot open the archive: {e}"))?;
        if Stamp::read(file.metadata().map_err(|e| e.to_string())?)? != *stamp {
            return Err("This archive changed during review. Review it again.".into());
        }
        Ok(Plan {
            path,
            image_id: None,
            tags: vec![],
            size: stamp.size,
            previous,
            input: Some(Arc::new(file)),
        })
    }
}

fn unchanged(plan: &Plan) -> Result<(), String> {
    if target_stamp(&plan.path)? != plan.previous {
        return Err("This file changed after review. Review it again before continuing.".into());
    }
    Ok(())
}

pub(crate) fn apply(plan: &Plan, progress: &Progress, shutdown: &AtomicBool) -> Result<(), String> {
    unchanged(plan)?;
    let mut command = crate::docker::docker_command();
    command.args(["--context", "smol", "image"]);
    if let Some(id) = &plan.image_id {
        if image(id, shutdown)?.0 != plan.tags {
            return Err("Image tags changed after review. Review the export again.".into());
        }
        let parent = plan
            .path
            .parent()
            .ok_or("The destination has no parent folder.")?;
        let mut staging = tempfile::Builder::new()
            .prefix(".smol-image-")
            .suffix(".tar")
            .tempfile_in(parent)
            .map_err(|e| format!("Cannot write to the destination folder: {e}"))?;
        command.arg("save");
        if plan.tags.is_empty() {
            command.arg(id);
        } else {
            command.args(&plan.tags);
        }
        // Stream directly into Studio's staging handle: no full-memory buffer
        // or Docker-owned output tempfile is left behind if the command fails.
        let output = staging
            .as_file()
            .try_clone()
            .map_err(|e| format!("Cannot write the archive: {e}"))?;
        progress.capture_to_file(command, output, Duration::from_secs(1800), shutdown)?;
        verify_export(staging.as_file_mut(), id, &plan.tags)?;
        if image(id, shutdown)?.0 != plan.tags {
            return Err("Image tags changed during export. Review the export again.".into());
        }
        staging
            .as_file()
            .sync_all()
            .map_err(|e| format!("Cannot finish the archive: {e}"))?;
        unchanged(plan)?;
        // New destinations cannot overwrite a file created after review. Existing
        // destinations are explicitly reviewed and rechecked; Docker/filesystems
        // do not provide an atomic compare-and-swap against external writers.
        if plan.previous.is_some() {
            staging
                .persist(&plan.path)
                .map_err(|e| format!("Cannot replace the destination: {}", e.error))?;
        } else {
            staging
                .persist_noclobber(&plan.path)
                .map_err(|e| format!("Cannot publish the archive: {}", e.error))?;
        }
    } else {
        let file = plan
            .input
            .as_ref()
            .ok_or("Review the archive before importing it.")?;
        if Some(Stamp::read(file.metadata().map_err(|e| e.to_string())?)?) != plan.previous {
            return Err("This archive changed after review. Review it again.".into());
        }
        // The opened handle pins the reviewed file even if its path is replaced.
        command.arg("load");
        let mut input = file
            .try_clone()
            .map_err(|e| format!("Cannot read the archive: {e}"))?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("Cannot read the archive: {e}"))?;
        progress
            .capture_with_input(
                command,
                Stdio::from(input),
                Duration::from_secs(1800),
                shutdown,
            )
            .map_err(|e| {
                format!("{e}\nImport may have partially completed. Refresh images before retrying.")
            })?;
        if Some(Stamp::read(file.metadata().map_err(|e| e.to_string())?)?) != plan.previous {
            return Err("The archive changed while it was being imported. Refresh images and review the result before retrying.".into());
        }
    }
    Ok(())
}

fn member_name(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => normalized.push(p),
            Component::CurDir => {}
            _ => return Err("Export contains an invalid member path.".into()),
        }
    }
    Ok(normalized)
}

/// Validate the selected image and tags without extracting or reading layer
/// payloads: seek over blobs, then hash only the referenced configuration files.
fn verify_export(file: &mut File, id: &str, tags: &[String]) -> Result<(), String> {
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut archive = tar::Archive::new(&mut *file);
    let mut manifest = None;
    for entry in archive.entries_with_seek().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| format!("Invalid exported archive: {e}"))?;
        if entry
            .raw_file_position()
            .checked_add(entry.size())
            .is_none_or(|end| end > length)
        {
            return Err("The exported archive is truncated.".into());
        }
        if member_name(&entry.path().map_err(|e| e.to_string())?)? == Path::new("manifest.json") {
            if manifest.is_some()
                || !entry.header().entry_type().is_file()
                || entry.size() > 1024 * 1024
            {
                return Err("The export has invalid or oversized image metadata.".into());
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            manifest = Some(bytes);
        }
    }
    let docs: Vec<Value> =
        serde_json::from_slice(&manifest.ok_or("The export has no image manifest.")?)
            .map_err(|e| format!("Invalid exported image manifest: {e}"))?;
    let mut configs = HashMap::new();
    let mut layers = HashMap::new();
    let mut actual_tags = BTreeSet::new();
    for doc in docs {
        let config = doc["Config"]
            .as_str()
            .ok_or("The export has no image configuration.")?;
        configs.insert(member_name(Path::new(config))?, false);
        let list: Vec<String> = if doc["RepoTags"].is_null() {
            vec![]
        } else {
            serde_json::from_value(doc["RepoTags"].clone())
                .map_err(|e| format!("Invalid exported tags: {e}"))?
        };
        actual_tags.extend(list);
        for layer in doc["Layers"]
            .as_array()
            .ok_or("The export has no layer list.")?
        {
            layers.insert(
                member_name(Path::new(
                    layer.as_str().ok_or("Invalid exported layer path.")?,
                ))?,
                false,
            );
        }
    }
    if configs.is_empty() || actual_tags != tags.iter().cloned().collect() {
        return Err("The exported image tags differ from the reviewed image.".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries_with_seek().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let name = member_name(&entry.path().map_err(|e| e.to_string())?)?;
        if let Some(found) = layers.get_mut(&name) {
            if *found || !entry.header().entry_type().is_file() {
                return Err("The export has an invalid or duplicate layer.".into());
            }
            *found = true;
        }
        if let Some(found) = configs.get_mut(&name) {
            if *found || !entry.header().entry_type().is_file() || entry.size() > 16 * 1024 * 1024 {
                return Err("The exported image configuration is invalid or oversized.".into());
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            if format!("sha256:{:x}", Sha256::digest(bytes)) != id {
                return Err(
                    "The archive contains a different image. Review the export again.".into(),
                );
            }
            *found = true;
        }
    }
    if layers.values().any(|found| !found) {
        return Err("An exported image layer is missing.".into());
    }
    if configs.values().any(|found| !found) {
        return Err("An exported image configuration is missing.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(file: &mut File, config: &[u8], tags: &[&str], layers: &[&str]) {
        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut tar = tar::Builder::new(file);
        for (name, bytes) in [
            ("config.json", config.to_vec()),
            (
                "manifest.json",
                serde_json::to_vec(
                    &serde_json::json!([{"Config":"config.json","Layers":layers,"RepoTags":tags}]),
                )
                .unwrap(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes.as_slice())
                .unwrap();
        }
        tar.finish().unwrap();
    }
    #[test]
    fn exported_image_identity_and_all_tags_are_verified() {
        let mut file = tempfile::tempfile().unwrap();
        let id = format!("sha256:{:x}", Sha256::digest(b"{}"));
        archive(&mut file, b"{}", &["app:one", "app:two"], &[]);
        verify_export(&mut file, &id, &["app:one".into(), "app:two".into()]).unwrap();
        assert!(
            verify_export(&mut file, &id, &["app:one".into()])
                .unwrap_err()
                .contains("tags differ")
        );
        assert!(
            verify_export(
                &mut file,
                &format!("sha256:{}", "a".repeat(64)),
                &["app:one".into(), "app:two".into()]
            )
            .unwrap_err()
            .contains("different image")
        );
        archive(&mut file, b"{}", &[], &[]);
        verify_export(&mut file, &id, &[]).unwrap();
        archive(&mut file, b"{}", &[], &["missing-layer.tar"]);
        assert!(
            verify_export(&mut file, &id, &[])
                .unwrap_err()
                .contains("layer is missing")
        );
        file.set_len(513).unwrap();
        assert!(verify_export(&mut file, &id, &[]).is_err());
    }
    #[test]
    fn review_detects_changed_input_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image with spaces.tar");
        std::fs::write(&path, b"archive input").unwrap();
        let plan = review(&Request::Import(path.clone()), &AtomicBool::new(false)).unwrap();
        assert_eq!(plan.size, 13);
        unchanged(&plan).unwrap();
        std::fs::write(&path, b"different archive").unwrap();
        assert!(unchanged(&plan).unwrap_err().contains("changed"));
        assert!(
            review(
                &Request::Import(dir.path().to_owned()),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert!(
            review(
                &Request::Import("relative.tar".into()),
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn links_cannot_redirect_a_reviewed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.tar");
        std::fs::write(&path, b"original").unwrap();
        let plan = review(&Request::Import(path.clone()), &AtomicBool::new(false)).unwrap();
        std::fs::rename(&path, dir.path().join("original.tar")).unwrap();
        std::os::unix::fs::symlink("original.tar", &path).unwrap();
        assert!(unchanged(&plan).unwrap_err().contains("symbolic link"));
        assert!(member_name(Path::new("../outside")).is_err());
        assert!(member_name(Path::new("/outside")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn command_input_is_streamed_from_the_opened_archive() {
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("source");
            std::fs::write(&path, b"reviewed input\n").unwrap();
            let plan = review(&Request::Import(path.clone()), &AtomicBool::new(false)).unwrap();
            let input = plan.input.as_ref().unwrap().try_clone().unwrap();
            std::fs::rename(&path, dir.path().join("moved")).unwrap();
            std::fs::write(&path, b"replacement input\n").unwrap();
            let progress = Progress::new(|| {});
            progress.begin("Input fixture".into());
            let mut command = std::process::Command::new("/bin/sh");
            command.args(["-c", "cat"]);
            progress
                .capture_with_input(
                    command,
                    input.into(),
                    Duration::from_secs(5),
                    &AtomicBool::new(false),
                )
                .unwrap();
            assert_eq!(progress.snapshot_after(0).unwrap().text, "reviewed input\n");
        }
    }

    #[cfg(unix)]
    #[test]
    fn binary_exports_bypass_transcript_limits_and_keep_error_diagnostics() {
        let file = tempfile::tempfile().unwrap();
        let progress = Progress::new(|| {});
        progress.begin("Binary export fixture".into());
        let mut command = std::process::Command::new("/bin/sh");
        command.args([
            "-c",
            "dd if=/dev/zero bs=65536 count=8 2>/dev/null; printf 'save failed\\n' >&2; exit 7",
        ]);
        let error = progress
            .capture_to_file(
                command,
                file.try_clone().unwrap(),
                Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert!(error.contains("code 7") && error.contains("save failed"));
        assert_eq!(file.metadata().unwrap().len(), 512 * 1024);
        assert_eq!(progress.snapshot_after(0).unwrap().text, "save failed\n");
    }

    #[test]
    #[ignore = "requires an isolated Smol Docker engine and owned image"]
    fn live_image_archive_roundtrip_and_review_conflicts() {
        let id = std::env::var("SMOL_STUDIO_ARCHIVE_IMAGE_ID").expect("owned image ID");
        let dir =
            PathBuf::from(std::env::var("SMOL_STUDIO_ARCHIVE_ROOT").expect("owned test folder"));
        std::fs::create_dir_all(&dir).unwrap();
        let stop = AtomicBool::new(false);
        let progress = Progress::new(|| {});
        let path = dir.join("archive with spaces.tar");
        let plan = review(
            &Request::Export {
                image_id: id.clone(),
                path: path.clone(),
            },
            &stop,
        )
        .unwrap();
        assert!(!plan.tags.is_empty());
        progress.begin("Export owned image".into());
        apply(&plan, &progress, &stop).unwrap();
        let saved = std::fs::read(&path).unwrap();
        assert!(!saved.is_empty());
        let replace = review(
            &Request::Export {
                image_id: id.clone(),
                path: path.clone(),
            },
            &stop,
        )
        .unwrap();
        assert!(replace.replaces_file());
        std::fs::write(&path, b"external change").unwrap();
        assert!(
            apply(&replace, &progress, &stop)
                .unwrap_err()
                .contains("changed")
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"external change");
        std::fs::write(&path, &saved).unwrap();
        let replace = review(
            &Request::Export {
                image_id: id.clone(),
                path: path.clone(),
            },
            &stop,
        )
        .unwrap();
        apply(&replace, &progress, &stop).unwrap();
        let import = review(&Request::Import(path.clone()), &stop).unwrap();
        let mut command = crate::docker::docker_command();
        command.args(["--context", "smol", "image", "rm", "--force", &id]);
        assert!(command.output().unwrap().status.success());
        progress.begin("Import owned image".into());
        apply(&import, &progress, &stop).unwrap();
        assert_eq!(image(&id, &stop).unwrap().0, plan.tags);
        // A tag added after review invalidates the export before publication.
        let stale = review(
            &Request::Export {
                image_id: id.clone(),
                path: path.clone(),
            },
            &stop,
        )
        .unwrap();
        let changed_tag = format!(
            "studio-archive-owned:changed-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut command = crate::docker::docker_command();
        command.args(["--context", "smol", "image", "tag", &id, &changed_tag]);
        assert!(command.output().unwrap().status.success());
        let before = std::fs::read(&path).unwrap();
        assert!(
            apply(&stale, &progress, &stop)
                .unwrap_err()
                .contains("tags changed")
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // Malformed import reports a failure while preserving the original file.
        let bad = dir.join("bad.tar");
        std::fs::write(&bad, b"not an image archive").unwrap();
        let bad_plan = review(&Request::Import(bad.clone()), &stop).unwrap();
        assert!(apply(&bad_plan, &progress, &stop).is_err());
        assert_eq!(std::fs::read(bad).unwrap(), b"not an image archive");
        assert!(!std::fs::read_dir(&dir).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".smol-image-")
        }));
    }
}
