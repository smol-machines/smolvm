//! Local OCI image support via streamed stdin pipes or pre-saved tarball archives.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};

/// Prepare a local OCI image tarball (from stdin or a file path) for mounting via virtiofs.
/// Returns the path to the layers directory (`~/.cache/smolvm/local-images/<image_id_hex>/layers`)
/// and a resolved image reference string (e.g. `local:stdin-<hash>` or `local:tar-<hash>`).
pub fn prepare_local_image(image_ref: &str) -> crate::error::Result<(PathBuf, String)> {
    let is_stdin = image_ref == "-";
    let is_tar = image_ref.ends_with(".tar") || image_ref.ends_with(".tar.gz");
    let is_oci_dir = {
        let path = Path::new(image_ref);
        path.is_dir() && path.join("index.json").exists()
    };

    if !is_stdin && !is_tar && !is_oci_dir {
        return Err(crate::error::Error::config(
            "prepare_local_image",
            format!("Invalid local image reference (must be '-' for stdin, a .tar/.tar.gz file, or an OCI layout directory): {}", image_ref),
        ));
    }

    let mut tmp_dir_opt = None;
    if !is_oci_dir {
        let tmp_dir = tempfile::tempdir().map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to create temp directory: {}", e))
        })?;
        tmp_dir_opt = Some(tmp_dir);
    }

    let (tar_path, image_id) = if is_oci_dir {
        let index_path = Path::new(image_ref).join("index.json");
        let index_content = fs::read(&index_path).map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to read index.json: {}", e))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&index_content);
        let hash = hex::encode(hasher.finalize());
        (PathBuf::new(), format!("oci-{}", &hash[..16]))
    } else if is_stdin {
        println!("Reading OCI image tarball from stdin...");
        let tmp_dir = tmp_dir_opt.as_ref().ok_or_else(|| {
            crate::error::Error::config("prepare_local_image", "Temporary workspace directory not initialized".to_string())
        })?;
        let path = tmp_dir.path().join("stdin.tar");
        let mut file = fs::File::create(&path).map_err(|e| {
            crate::error::Error::config("prepare_local_image", format!("Failed to create temp stdin file: {}", e))
        })?;
        
        let mut stdin = std::io::stdin();
        let mut hasher = Sha256::new();
        let mut buffer = [0; 65536];
        let mut total_bytes = 0;
        loop {
            let n = stdin.read(&mut buffer).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to read from stdin: {}", e))
            })?;
            if n == 0 {
                break;
            }
            file.write_all(&buffer[..n]).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to write to temp stdin file: {}", e))
            })?;
            hasher.update(&buffer[..n]);
            total_bytes += n;
        }
        
        if total_bytes == 0 {
            return Err(crate::error::Error::config(
                "prepare_local_image",
                "stdin is empty, no OCI image data received".to_string(),
            ));
        }
        
        drop(file);

        let hash = hex::encode(hasher.finalize());
        (path, format!("stdin-{}", &hash[..16]))
    } else {
        // Local tar/tar.gz file path
        let path = Path::new(image_ref);
        if !path.exists() {
            return Err(crate::error::Error::config(
                "prepare_local_image",
                format!("Pre-saved image tarball not found: {}", image_ref),
            ));
        }
        let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
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
        (canonical, format!("tar-{}", &hash[..16]))
    };

    let image_id_clean = image_id
        .strip_prefix("sha256:")
        .unwrap_or(&image_id)
        .replace(":", "_");

    // Locate the cache directories
    let cache_base = dirs::cache_dir()
        .ok_or_else(|| crate::error::Error::config("prepare_local_image", "No cache directory found"))?;
    let image_cache_dir = cache_base.join("smolvm").join("local-images").join(&image_id_clean);
    let layers_dir = image_cache_dir.join("layers");
    let marker_file = image_cache_dir.join(".smolvm-extracted");

    // Check if already extracted
    if marker_file.exists() && layers_dir.exists() {
        tracing::debug!("Local image already cached at {}", layers_dir.display());
        let final_image_ref = format!("local:{}", image_id);
        return Ok((layers_dir, final_image_ref));
    }

    // Clean up stale/partial extraction
    if image_cache_dir.exists() {
        let _ = fs::remove_dir_all(&image_cache_dir);
    }
    fs::create_dir_all(&layers_dir).map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to create layers directory: {}", e))
    })?;

    // Perform extraction in a fallible closure so we can clean up the partial extraction on failure
    let extract_result = (|| -> crate::error::Result<()> {
        if is_oci_dir {
            println!("Extracting local OCI layout directory...");
            let index_path = Path::new(image_ref).join("index.json");
            let index_content = fs::read(&index_path).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to read index.json: {}", e))
            })?;
            let index_json: serde_json::Value = serde_json::from_slice(&index_content).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to parse index.json: {}", e))
            })?;
            let manifest_digest = index_json["manifests"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|m| m["digest"].as_str())
                .ok_or_else(|| {
                    crate::error::Error::config("prepare_local_image", "Missing or invalid manifest digest in index.json".to_string())
                })?;
            let manifest_hash = manifest_digest
                .strip_prefix("sha256:")
                .unwrap_or(manifest_digest);
            let oci_base_path = Path::new(image_ref);
            let manifest_file_path = oci_base_path.join("blobs").join("sha256").join(manifest_hash);
            if !manifest_file_path.exists() {
                return Err(crate::error::Error::config(
                    "prepare_local_image",
                    format!("Manifest file not found: {}", manifest_file_path.display()),
                ));
            }
            let manifest_content = fs::read_to_string(&manifest_file_path).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to read manifest file {}: {}", manifest_file_path.display(), e))
            })?;
            let manifest_json: serde_json::Value = serde_json::from_str(&manifest_content).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to parse manifest: {}", e))
            })?;
            let config_digest = manifest_json["config"]["digest"]
                .as_str()
                .ok_or_else(|| {
                    crate::error::Error::config("prepare_local_image", "Missing config digest in manifest".to_string())
                })?;
            let config_hash = config_digest.strip_prefix("sha256:").unwrap_or(config_digest);
            let config_file_path = oci_base_path.join("blobs").join("sha256").join(config_hash);
            if !config_file_path.exists() {
                return Err(crate::error::Error::config(
                    "prepare_local_image",
                    format!("Config file not found: {}", config_file_path.display()),
                ));
            }
            let dst_config_path = layers_dir.join("config.json");
            fs::copy(&config_file_path, &dst_config_path).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to copy config.json: {}", e))
            })?;

            let layers = manifest_json["layers"]
                .as_array()
                .ok_or_else(|| {
                    crate::error::Error::config("prepare_local_image", "Missing layers in manifest".to_string())
                })?;

            for (index, layer_val) in layers.iter().enumerate() {
                let layer_digest = layer_val["digest"]
                    .as_str()
                    .ok_or_else(|| {
                        crate::error::Error::config("prepare_local_image", "Missing digest in layer".to_string())
                    })?;
                let layer_hash = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
                let layer_file_path = oci_base_path.join("blobs").join("sha256").join(layer_hash);
                if !layer_file_path.exists() {
                    return Err(crate::error::Error::config(
                        "prepare_local_image",
                        format!("Layer file not found: {}", layer_file_path.display()),
                    ));
                }
                
                let hash_prefix = if layer_hash.len() > 12 { &layer_hash[..12] } else { layer_hash };
                let layer_dest_dir = layers_dir.join(format!("{:04}_{}", index, hash_prefix));
                
                fs::create_dir_all(&layer_dest_dir).map_err(|e| {
                    crate::error::Error::config(
                        "prepare_local_image",
                        format!("Failed to create layer directory {}: {}", layer_dest_dir.display(), e),
                    )
                })?;

                let file = fs::File::open(&layer_file_path).map_err(|e| {
                    crate::error::Error::config("prepare_local_image", format!("Failed to open layer file: {}", e))
                })?;
                
                let decoder = flate2::read::GzDecoder::new(file);
                let mut archive = tar::Archive::new(decoder);
                archive.unpack(&layer_dest_dir).map_err(|e| {
                    crate::error::Error::config("prepare_local_image", format!("Failed to extract layer {}: {}", index, e))
                })?;
            }
        } else {
            println!("Extracting local image tarball...");
            let tmp_dir = tmp_dir_opt.as_ref().ok_or_else(|| {
                crate::error::Error::config("prepare_local_image", "Temporary workspace directory not initialized".to_string())
            })?;
            let outer_extract_dir = tmp_dir.path().join("extracted");
            fs::create_dir_all(&outer_extract_dir).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to create extraction dir: {}", e))
            })?;

            // Extract outer tarball
            let tar_file = fs::File::open(&tar_path).map_err(|e| {
                crate::error::Error::config("prepare_local_image", format!("Failed to open OCI tarball: {}", e))
            })?;
            let mut outer_archive = tar::Archive::new(tar_file);
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
                .and_then(|arr| arr.first())
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
        }
        Ok(())
    })();

    if let Err(e) = extract_result {
        let _ = fs::remove_dir_all(&image_cache_dir);
        return Err(e);
    }

    // Write completion marker
    fs::write(&marker_file, "").map_err(|e| {
        crate::error::Error::config("prepare_local_image", format!("Failed to write extraction marker: {}", e))
    })?;

    let final_image_ref = format!("local:{}", image_id);
    Ok((layers_dir, final_image_ref))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_invalid_image_ref_rejected() {
        let result = prepare_local_image("not-a-tarball");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid local image reference"));
    }

    #[test]
    fn test_prepare_local_image_tar_extraction_and_caching() {
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("mock_image.tar");
        let file = fs::File::create(&tar_path).unwrap();
        let mut archive = tar::Builder::new(file);

        // 1. Create a dummy config JSON
        let config_data = b"{\"architecture\":\"amd64\",\"os\":\"linux\"}";
        let mut header1 = tar::Header::new_gnu();
        header1.set_size(config_data.len() as u64);
        header1.set_mode(0o644);
        header1.set_cksum();
        archive.append_data(&mut header1, "config.json", &config_data[..]).unwrap();

        // 2. Create a dummy layer tarball
        let mut layer_builder = tar::Builder::new(Vec::new());
        let layer_content = b"hello world";
        let mut layer_header = tar::Header::new_gnu();
        layer_header.set_size(layer_content.len() as u64);
        layer_header.set_mode(0o644);
        layer_header.set_cksum();
        layer_builder.append_data(&mut layer_header, "app/main.py", &layer_content[..]).unwrap();
        let layer_bytes = layer_builder.into_inner().unwrap();

        let mut header2 = tar::Header::new_gnu();
        header2.set_size(layer_bytes.len() as u64);
        header2.set_mode(0o644);
        header2.set_cksum();
        archive.append_data(&mut header2, "layer1/layer.tar", &layer_bytes[..]).unwrap();

        // 3. Create manifest.json
        let manifest_content = r#"[
            {
                "Config": "config.json",
                "RepoTags": ["mock:latest"],
                "Layers": ["layer1/layer.tar"]
            }
        ]"#;
        let mut header3 = tar::Header::new_gnu();
        header3.set_size(manifest_content.len() as u64);
        header3.set_mode(0o644);
        header3.set_cksum();
        archive.append_data(&mut header3, "manifest.json", manifest_content.as_bytes()).unwrap();
        archive.finish().unwrap();

        // Run prepare_local_image on this tar file!
        let (layers_dir, resolved_ref) = prepare_local_image(tar_path.to_str().unwrap()).unwrap();
        
        assert!(resolved_ref.starts_with("local:tar-"));
        assert!(layers_dir.exists());
        assert!(layers_dir.join("config.json").exists());
        
        // Check that the layer directory is extracted
        let layer_extracted_dir = layers_dir.join("0000_layer1_layer");
        assert!(layer_extracted_dir.exists());
        assert!(layer_extracted_dir.join("app/main.py").exists());
        
        // Run it a second time and check that we hit the cache immediately
        let (layers_dir2, resolved_ref2) = prepare_local_image(tar_path.to_str().unwrap()).unwrap();
        assert_eq!(layers_dir, layers_dir2);
        assert_eq!(resolved_ref, resolved_ref2);
    }

    #[test]
    fn test_prepare_local_image_oci_directory_extraction_and_caching() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let tmp = tempdir().unwrap();
        let oci_dir = tmp.path().join("oci-layout");
        fs::create_dir_all(&oci_dir).unwrap();
        
        let blobs_dir = oci_dir.join("blobs").join("sha256");
        fs::create_dir_all(&blobs_dir).unwrap();

        // 1. Create a dummy config JSON
        let config_data = b"{\"architecture\":\"amd64\",\"os\":\"linux\"}";
        let mut hasher = Sha256::new();
        hasher.update(config_data);
        let config_hash = hex::encode(hasher.finalize());
        fs::write(blobs_dir.join(&config_hash), config_data).unwrap();

        // 2. Create a dummy layer tar, gzip compress it, and save it under blobs/sha256/
        let layer_content = b"hello from oci layout layer";
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(layer_content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append_data(&mut header, "etc/greeting.txt", &layer_content[..]).unwrap();
        let tar_bytes = tar_builder.into_inner().unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&gzip_bytes);
        let layer_hash = hex::encode(hasher.finalize());
        fs::write(blobs_dir.join(&layer_hash), &gzip_bytes).unwrap();

        // 3. Create the manifest blob listing the config and layer digests, saving it under blobs/sha256/<manifest-hash>
        let manifest_content = format!(
            r#"{{
                "schemaVersion": 2,
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:{}",
                    "size": {}
                }},
                "layers": [
                    {{
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": "sha256:{}",
                        "size": {}
                    }}
                ]
            }}"#,
            config_hash, config_data.len(), layer_hash, gzip_bytes.len()
        );
        let mut hasher = Sha256::new();
        hasher.update(manifest_content.as_bytes());
        let manifest_hash = hex::encode(hasher.finalize());
        fs::write(blobs_dir.join(&manifest_hash), manifest_content.as_bytes()).unwrap();

        // 4. Create index.json referencing the manifest digest
        let index_content = format!(
            r#"{{
                "schemaVersion": 2,
                "manifests": [
                    {{
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:{}",
                        "size": {}
                    }}
                ]
            }}"#,
            manifest_hash, manifest_content.len()
        );
        fs::write(oci_dir.join("index.json"), index_content.as_bytes()).unwrap();

        // Run prepare_local_image!
        let (layers_dir, resolved_ref) = prepare_local_image(oci_dir.to_str().unwrap()).unwrap();

        // Assert that:
        // - The cache key starts with local:oci-
        assert!(resolved_ref.starts_with("local:oci-"));
        assert!(layers_dir.exists());
        
        // - Config and decompressed layers are successfully unpacked in the cache directory.
        assert!(layers_dir.join("config.json").exists());
        let config_read = fs::read_to_string(layers_dir.join("config.json")).unwrap();
        assert_eq!(config_read, "{\"architecture\":\"amd64\",\"os\":\"linux\"}");

        let layer_prefix = &layer_hash[..12];
        let layer_extracted_dir = layers_dir.join(format!("0000_{}", layer_prefix));
        assert!(layer_extracted_dir.exists());
        assert!(layer_extracted_dir.join("etc/greeting.txt").exists());
        let greeting = fs::read_to_string(layer_extracted_dir.join("etc/greeting.txt")).unwrap();
        assert_eq!(greeting, "hello from oci layout layer");

        // - Calling it a second time hits the cache instantly (skipping decompression)
        let (layers_dir2, resolved_ref2) = prepare_local_image(oci_dir.to_str().unwrap()).unwrap();
        assert_eq!(layers_dir, layers_dir2);
        assert_eq!(resolved_ref, resolved_ref2);
    }
}
