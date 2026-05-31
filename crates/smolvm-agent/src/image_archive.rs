//! Guest-side image archive ingestion.
//!
//! Handles extracting, decompressing, and flattening Docker/OCI image archives
//! staged via virtiofs. Spawns `crane` and `tar` inside the guest to assemble
//! a local rootfs inside the microvm's persistent /storage disk.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::debug;

use crate::storage::StorageError;

type Result<T> = std::result::Result<T, StorageError>;

pub const IMAGE_ARCHIVE_FILE: &str = "archive.tar";
pub const IMAGE_ARCHIVE_DIR: &str = "image-archive";
pub const IMAGE_ARCHIVE_MARKER: &str = ".extracted";
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const STORAGE_ROOT: &str = "/storage";

/// Flatten a host-staged image archive into a single rootfs layer using
/// `crane`, returning a packed-layers directory the rest of the pipeline can
/// consume unchanged.
///
/// Extraction, layer ordering, and whiteout handling are delegated entirely to
/// `crane export` (already bundled for registry pulls); the agent only stages
/// I/O and reads the image config blob to recover Entrypoint/Cmd/Env. The
/// result lives on the storage disk and is guarded by a completion marker, so
/// for named machines `crane` runs only on first boot.
///
/// Only the Docker `save` archive format (top-level `manifest.json`) is
/// supported, which is what `docker save` and `podman save` (default) produce.
/// OCI-layout archives (`index.json`) are rejected with a clear error, since
/// `crane export` cannot read them from a tar stream.
#[cfg(target_os = "linux")]
pub fn materialize_image_archive(archive_mount: &Path) -> Result<PathBuf> {
    let target = Path::new(STORAGE_ROOT).join(IMAGE_ARCHIVE_DIR);
    let layer_dir = target.join("0000_rootfs");
    let marker = target.join(IMAGE_ARCHIVE_MARKER);

    // Cache hit: a previous boot already flattened this archive onto the
    // (persistent) storage disk.
    if marker.exists() && layer_dir.exists() {
        debug!(target = %target.display(), "reusing previously flattened image archive");
        return Ok(target);
    }

    // Clear any partial/stale extraction before re-flattening.
    if target.exists() {
        let _ = std::fs::remove_dir_all(&target);
    }
    std::fs::create_dir_all(&layer_dir)?;

    let archive_path = archive_mount.join(IMAGE_ARCHIVE_FILE);

    // `crane export` and `tar -xO` both need an uncompressed tar. `docker save
    // | gzip` and `.tar.gz` inputs are gzip-wrapped, so decompress once with
    // the bundled busybox `gunzip` rather than re-implementing gzip.
    let plain_tar = target.join(".plain.tar");
    let used_plain = if is_gzip(&archive_path)? {
        decompress_gzip(&archive_path, &plain_tar)?;
        true
    } else {
        false
    };
    let source_tar = if used_plain {
        plain_tar.as_path()
    } else {
        archive_path.as_path()
    };

    flatten_with_crane(source_tar, &layer_dir)?;
    write_archive_config(source_tar, &target)?;

    if used_plain {
        let _ = std::fs::remove_file(&plain_tar);
    }

    std::fs::write(&marker, b"")?;
    // SAFETY: sync() is always safe to call; ensures the flattened rootfs is
    // durable before the overlay is assembled on top of it.
    unsafe {
        libc::sync();
    }

    Ok(target)
}

/// True when `path` begins with the gzip magic bytes.
#[cfg(target_os = "linux")]
fn is_gzip(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|e| StorageError::read_error(path.display().to_string(), e))?;
    let mut magic = [0u8; 2];
    let n = file.read(&mut magic).unwrap_or(0);
    Ok(n == 2 && magic == GZIP_MAGIC)
}

/// Decompress a gzip file to `dest` using the bundled `gunzip`.
#[cfg(target_os = "linux")]
fn decompress_gzip(src: &Path, dest: &Path) -> Result<()> {
    let input = std::fs::File::open(src)
        .map_err(|e| StorageError::read_error(src.display().to_string(), e))?;
    let output = std::fs::File::create(dest)
        .map_err(|e| StorageError::write_error(dest.display().to_string(), e))?;
    let status = Command::new("gunzip")
        .arg("-c")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::null())
        .status()
        .map_err(|e| StorageError::new(format!("failed to spawn gunzip: {}", e)))?;
    if !status.success() {
        return Err(StorageError::new(
            "gunzip failed to decompress image archive".to_string(),
        ));
    }
    Ok(())
}

/// Flatten a Docker `save` tarball into `layer_dir` by piping
/// `crane export - -` into `tar -x`.
#[cfg(target_os = "linux")]
fn flatten_with_crane(source_tar: &Path, layer_dir: &Path) -> Result<()> {
    let archive = std::fs::File::open(source_tar)
        .map_err(|e| StorageError::read_error(source_tar.display().to_string(), e))?;

    // Read the image tarball from stdin, write the flattened rootfs to stdout.
    // Stderr is directed to Stdio::null() to prevent a potential OS pipe-buffer
    // deadlock when crane writes logs concurrently while tar blocks on stdin.
    let mut crane = Command::new("crane")
        .args(["export", "-", "-"])
        .stdin(Stdio::from(archive))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crane: {}", e)))?;

    let crane_stdout = crane
        .stdout
        .take()
        .ok_or_else(|| StorageError::new("failed to capture crane stdout".to_string()))?;

    let tar_output = Command::new("tar")
        .arg("-x")
        .arg("-f")
        .arg("-")
        .arg("-C")
        .arg(layer_dir)
        .stdin(Stdio::from(crane_stdout))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| StorageError::new(format!("failed to run tar: {}", e)))?;

    let crane_status = crane
        .wait()
        .map_err(|e| StorageError::new(format!("failed to wait for crane: {}", e)))?;

    if !crane_status.success() {
        // Since crane's stderr is Stdio::null() to prevent deadlock, we provide
        // a clean format error suggestion. OCI-layout archives (index.json)
        // are not supported by crane export.
        return Err(StorageError::new(
            "crane could not read the image archive. \
             Only the Docker 'save' format is supported \
             (docker save / podman save); re-export with that format."
                .to_string(),
        ));
    }

    if !tar_output.status.success() {
        let stderr = String::from_utf8_lossy(&tar_output.stderr);
        return Err(StorageError::new(format!(
            "failed to extract flattened rootfs: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Read the image config blob from a Docker `save` tarball (located via its
/// top-level `manifest.json`) and write it to `<target>/config.json`, the file
/// `create_packed_image_info` reads to recover image metadata.
#[cfg(target_os = "linux")]
fn write_archive_config(source_tar: &Path, target: &Path) -> Result<()> {
    let manifest_bytes = read_tar_member(source_tar, "manifest.json")?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| StorageError::parse_error("manifest.json", e))?;

    let config_member = manifest
        .as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry["Config"].as_str())
        .ok_or_else(|| StorageError::new("manifest.json missing Config entry".to_string()))?;

    let config_bytes = read_tar_member(source_tar, config_member)?;
    std::fs::write(target.join("config.json"), &config_bytes).map_err(|e| {
        StorageError::write_error(target.join("config.json").display().to_string(), e)
    })?;
    Ok(())
}

/// Extract a single named member from a tar archive to memory via `tar -xO`.
#[cfg(target_os = "linux")]
fn read_tar_member(source_tar: &Path, member: &str) -> Result<Vec<u8>> {
    let output = Command::new("tar")
        .arg("-xOf")
        .arg(source_tar)
        .arg(member)
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| StorageError::new(format!("failed to run tar: {}", e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError::new(format!(
            "failed to read '{}' from image archive: {}",
            member,
            stderr.trim()
        )));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn crane_available() -> bool {
        Command::new("crane")
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Build a minimal Docker `save` tarball (flat `manifest.json` naming) at
    /// `dest` containing a single layer with `hello.txt`. crane does not
    /// validate `diff_ids`, so a placeholder digest is fine for tests.
    #[cfg(target_os = "linux")]
    fn make_docker_save_tar(work: &Path, dest: &Path) {
        let layer_root = work.join("layerroot");
        std::fs::create_dir_all(&layer_root).unwrap();
        std::fs::write(layer_root.join("hello.txt"), b"hi from layer").unwrap();

        let build = work.join("build");
        std::fs::create_dir_all(&build).unwrap();
        // Layer tar (contents become the flattened rootfs).
        assert!(Command::new("tar")
            .arg("-cf")
            .arg(build.join("layer.tar"))
            .arg("-C")
            .arg(&layer_root)
            .arg(".")
            .status()
            .unwrap()
            .success());

        std::fs::write(
            build.join("config.json"),
            br#"{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/entry"],"Cmd":["run"],"Env":["K=V"]},"rootfs":{"type":"layers","diff_ids":["sha256:0000000000000000000000000000000000000000000000000000000000000000"]}}"#,
        )
        .unwrap();
        std::fs::write(
            build.join("manifest.json"),
            br#"[{"Config":"config.json","RepoTags":["test:latest"],"Layers":["layer.tar"]}]"#,
        )
        .unwrap();

        // Flat member names (manifest.json, not ./manifest.json) — crane's
        // tarball reader requires this, matching real docker/podman output.
        assert!(Command::new("tar")
            .arg("-cf")
            .arg(dest)
            .arg("-C")
            .arg(&build)
            .arg("manifest.json")
            .arg("config.json")
            .arg("layer.tar")
            .status()
            .unwrap()
            .success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_flatten_docker_save_and_recover_config() {
        if !crane_available() {
            eprintln!("skipping: crane not on PATH");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let archive = work.path().join("archive.tar");
        make_docker_save_tar(work.path(), &archive);

        // Flatten the rootfs via crane.
        let layer_dir = work.path().join("rootfs");
        std::fs::create_dir_all(&layer_dir).unwrap();
        flatten_with_crane(&archive, &layer_dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(layer_dir.join("hello.txt")).unwrap(),
            "hi from layer"
        );

        // Recover the image config beside the layer.
        let target = work.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        write_archive_config(&archive, &target).unwrap();

        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(target.join("config.json")).unwrap()).unwrap();
        let config_val = &config["config"];
        let entrypoint: Vec<String> = config_val["Entrypoint"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let cmd: Vec<String> = config_val["Cmd"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let env: Vec<String> = config_val["Env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert_eq!(entrypoint, vec!["/entry"]);
        assert_eq!(cmd, vec!["run"]);
        assert_eq!(env, vec!["K=V"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_flatten_handles_gzipped_archive() {
        if !crane_available() {
            eprintln!("skipping: crane not on PATH");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let archive = work.path().join("archive.tar");
        make_docker_save_tar(work.path(), &archive);

        // gzip the outer archive (docker save | gzip / .tar.gz).
        let gz = work.path().join("archive.tar.gz");
        let input = std::fs::File::open(&archive).unwrap();
        let output = std::fs::File::create(&gz).unwrap();
        assert!(Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .status()
            .unwrap()
            .success());

        assert!(is_gzip(&gz).unwrap());
        assert!(!is_gzip(&archive).unwrap());

        let plain = work.path().join("plain.tar");
        decompress_gzip(&gz, &plain).unwrap();

        let layer_dir = work.path().join("rootfs");
        std::fs::create_dir_all(&layer_dir).unwrap();
        flatten_with_crane(&plain, &layer_dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(layer_dir.join("hello.txt")).unwrap(),
            "hi from layer"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_oci_layout_archive_rejected_with_clear_error() {
        if !crane_available() {
            eprintln!("skipping: crane not on PATH");
            return;
        }
        // An OCI-layout archive has index.json but no top-level manifest.json,
        // which crane's tar reader cannot consume from a stream.
        let work = tempfile::tempdir().unwrap();
        let build = work.path().join("oci");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(
            build.join("index.json"),
            br#"{"schemaVersion":2,"manifests":[]}"#,
        )
        .unwrap();
        std::fs::write(
            build.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        let archive = work.path().join("oci.tar");
        assert!(Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&build)
            .arg("index.json")
            .arg("oci-layout")
            .status()
            .unwrap()
            .success());

        let layer_dir = work.path().join("rootfs");
        std::fs::create_dir_all(&layer_dir).unwrap();
        let err = flatten_with_crane(&archive, &layer_dir).unwrap_err();
        assert!(
            err.to_string().contains("Docker 'save' format"),
            "expected a clear docker-save guidance error, got: {}",
            err
        );
    }
}
