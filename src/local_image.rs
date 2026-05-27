//! Local Docker/Podman image and Dockerfile support.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use sha2::{Digest, Sha256};

/// Prepare a local Docker/Podman image or Dockerfile for mounting via virtiofs.
/// Returns the path to the layers directory (`~/.cache/smolvm/local-images/<image_id_hex>/layers`).
pub fn prepare_local_image(image_ref: &str) -> crate::error::Result<(PathBuf, String)> {
    // 1. Check if the image reference is a path to a Dockerfile or a directory containing one
    let mut resolved_image_ref = image_ref.to_string();
    let path = Path::new(image_ref);
    let mut is_dockerfile = false;

    if path.exists() {
        if path.is_file() && path.file_name().map_or(false, |n| n == "Dockerfile") {
            is_dockerfile = true;
        } else if path.is_dir() && path.join("Dockerfile").exists() {
            is_dockerfile = true;
        }
    }

    let backend = detect_backend();

    if is_dockerfile {
        let canonical_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let canonical_str = canonical_path.to_string_lossy();
        
        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        let hash = hex::encode(hasher.finalize());
        let short_hash = &hash[..12];
        let build_tag = format!("smolvm-build:{}", short_hash);

        println!("Building Dockerfile via {} (tag: {})...", backend, build_tag);

        let build_dir = if path.is_file() {
            path.parent().unwrap_or(Path::new("."))
        } else {
            path
        };

        let mut build_cmd = Command::new(backend);
        build_cmd.arg("build");
        build_cmd.arg("-t").arg(&build_tag);
        if path.is_file() {
            build_cmd.arg("-f").arg(path);
        }
        build_cmd.arg(build_dir);

        let status = build_cmd
            .status()
            .map_err(|e| crate::error::Error::config("prepare_local_image", format!("Failed to spawn {} build: {}", backend, e)))?;

        if !status.success() {
            return Err(crate::error::Error::config(
                "prepare_local_image",
                format!("{} build failed for Dockerfile at {}", backend, path.display()),
            ));
        }

        resolved_image_ref = format!("{}:{}", backend, build_tag);
    }

    // 2. Determine backend (docker or podman) and the raw image name/tag
    let (backend, image_name) = if let Some(rest) = resolved_image_ref.strip_prefix("docker:") {
        ("docker", rest)
    } else if let Some(rest) = resolved_image_ref.strip_prefix("podman:") {
        ("podman", rest)
    } else if let Some(rest) = resolved_image_ref.strip_prefix("local:") {
        (backend, rest)
    } else if resolved_image_ref.ends_with(".tar") || resolved_image_ref.ends_with(".tar.gz") {
        // Pre-saved tarball path (doesn't require a daemon prefix)
        (backend, resolved_image_ref.as_str())
    } else {
        return Err(crate::error::Error::config(
            "prepare_local_image",
            format!("Invalid local image reference: {}", image_ref),
        ));
    };

    // 3. Query the unique image ID / file hash
    let (image_id, is_pre_saved_tar): (String, bool) = if image_name.ends_with(".tar") || image_name.ends_with(".tar.gz") {
        let tar_path = Path::new(image_name);
        if !tar_path.exists() {
            return Err(crate::error::Error::config(
                "prepare_local_image",
                format!("Pre-saved image tarball not found: {}", image_name),
            ));
        }
        let canonical = fs::canonicalize(tar_path).unwrap_or_else(|_| tar_path.to_path_buf());
        let metadata = fs::metadata(&canonical).map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to read metadata of tar: {}", e))
        })?;
        let mtime = metadata.modified()
            .map(|t| t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
            .unwrap_or(0);
        
        let mut hasher = Sha256::new();
        hasher.update(canonical.to_string_lossy().as_bytes());
        hasher.update(&mtime.to_be_bytes());
        let hash = hex::encode(hasher.finalize());
        (format!("tar-{}", &hash[..16]), true)
    } else {
        (get_local_image_id(backend, image_name)?, false)
    };

    let image_id_clean = image_id
        .strip_prefix("sha256:")
        .unwrap_or(&image_id)
        .replace(":", "_");

    // 4. Locate the cache directories
    let cache_base = dirs::cache_dir()
        .ok_or_else(|| crate::error::Error::config("prepare_local_image", "No cache directory found"))?;
    let image_cache_dir = cache_base.join("smolvm").join("local-images").join(&image_id_clean);
    let layers_dir = image_cache_dir.join("layers");
    let marker_file = image_cache_dir.join(".smolvm-extracted");

    // 5. Check if already extracted
    if marker_file.exists() && layers_dir.exists() {
        tracing::debug!("Local image '{}' already cached at {}", image_name, layers_dir.display());
        let final_image_ref = if is_pre_saved_tar {
            format!("local:{}", image_id)
        } else {
            resolved_image_ref
        };
        return Ok((layers_dir, final_image_ref));
    }

    // Clean up stale/partial extraction
    if image_cache_dir.exists() {
        let _ = fs::remove_dir_all(&image_cache_dir);
    }
    fs::create_dir_all(&layers_dir).map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to create layers directory: {}", e))
    })?;

    let tmp_dir = tempfile::tempdir().map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to create temp directory: {}", e))
    })?;

    let save_tar_path = if is_pre_saved_tar {
        PathBuf::from(image_name)
    } else {
        println!("Extracting local image '{}' (using {})...", image_name, backend);
        let path = tmp_dir.path().join("image.tar");
        let mut child = Command::new(backend)
            .args(["save", image_name, "-o"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| crate::error::Error::config("prepare_local_image", format!("Failed to spawn {} save: {}", backend, e)))?;

        let status = child.wait().map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to wait for {} save: {}", backend, e))
        })?;

        if !status.success() {
            let output = child.wait_with_output().unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(crate::error::Error::config(
                "prepare_local_image",
                format!("{} save failed: {}", backend, stderr),
            ));
        }
        path
    };

    // Extract outer tarball
    let tar_file = fs::File::open(&save_tar_path).map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to open saved tarball: {}", e))
    })?;
    let mut outer_archive = tar::Archive::new(tar_file);
    let outer_extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir_all(&outer_extract_dir).unwrap();
    outer_archive.unpack(&outer_extract_dir).map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to unpack outer tarball: {}", e))
    })?;

    // Parse manifest.json
    let manifest_path = outer_extract_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(crate::error::Error::config(
            "prepare_local_image",
            "manifest.json not found in saved tarball".to_string(),
        ));
    }
    let manifest_content = fs::read_to_string(&manifest_path).map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to read manifest.json: {}", e))
    })?;
    let manifest_json: serde_json::Value = serde_json::from_str(&manifest_content).map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to parse manifest.json: {}", e))
    })?;

    let first_image = manifest_json
        .as_array()
        .and_then(|arr: &Vec<serde_json::Value>| arr.first())
        .ok_or_else(|| {
            crate::error::Error::config("prepare_local_image", "Empty or invalid manifest.json format".to_string())
        })?;

    let config_file_name = first_image["Config"]
        .as_str()
        .ok_or_else(|| {
            crate::error::Error::config("prepare_local_image", "Missing Config in manifest.json".to_string())
        })?;

    let layers_list = first_image["Layers"]
        .as_array()
        .ok_or_else(|| {
            crate::error::Error::config("prepare_local_image", "Missing Layers in manifest.json".to_string())
        })?;

    // Copy config JSON to config.json inside the layers folder
    let src_config_path = outer_extract_dir.join(config_file_name);
    let dst_config_path = layers_dir.join("config.json");
    if src_config_path.exists() {
        fs::copy(&src_config_path, &dst_config_path).map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to copy config.json: {}", e))
        })?;
    }

    // Extract each layer tarball into its own indexed folder under layers_dir
    for (index, layer_rel_path_val) in layers_list.iter().enumerate() {
        let layer_rel_path = layer_rel_path_val.as_str().ok_or_else(|| {
            crate::error::Error::config("prepare_local_image", "Invalid layer path in manifest.json".to_string())
        })?;
        let src_layer_tar = outer_extract_dir.join(layer_rel_path);
        
        let sanitized_name = layer_rel_path.replace("/", "_").replace(".tar", "");
        let layer_dest_dir = layers_dir.join(format!("{:04}_{}", index, sanitized_name));
        fs::create_dir_all(&layer_dest_dir).map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to create layer destination directory: {}", e))
        })?;

        let layer_file = fs::File::open(&src_layer_tar).map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to open layer tarball: {}", e))
        })?;
        let mut layer_archive = tar::Archive::new(layer_file);
        layer_archive.unpack(&layer_dest_dir).map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to extract layer {}: {}", index, e))
        })?;
    }

    // Write completion marker
    fs::write(&marker_file, "").map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to write extraction marker: {}", e))
    })?;

    let final_image_ref = if is_pre_saved_tar {
        format!("local:{}", image_id)
    } else {
        resolved_image_ref
    };

    Ok((layers_dir, final_image_ref))
}

fn detect_backend() -> &'static str {
    if Command::new("podman")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_or(false, |s| s.success())
    {
        "podman"
    } else {
        "docker"
    }
}

fn get_local_image_id(backend: &str, image_name: &str) -> crate::error::Result<String> {
    let output = Command::new(backend)
        .args(["inspect", "--format", "{{.Id}}", image_name])
        .output()
        .map_err(|e| {
            crate::error::Error::config("get_local_image_id", format!("Failed to run {} inspect: {}", backend, e))
        })?;

    if !output.status.success() {
        return Err(crate::error::Error::config(
            "get_local_image_id",
            format!(
                "Local image '{}' not found in {} daemon: {}",
                image_name,
                backend,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }

    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if id.is_empty() {
        return Err(crate::error::Error::config(
            "get_local_image_id",
            format!("Empty ID returned by {} inspect for '{}'", backend, image_name),
        ));
    }
    Ok(id)
}
