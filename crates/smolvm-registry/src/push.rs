//! Push a `.smolmachine` artifact to an OCI registry.
//!
//! The push flow:
//! 1. Compute SHA256 digest of the sidecar (streamed, no full-file buffer)
//! 2. Parse PackManifest from the footer for the OCI config blob
//! 3. Stream-upload the sidecar as a single OCI layer blob
//! 4. Upload the PackManifest JSON as the OCI config blob
//! 5. Build and PUT the OCI Image Manifest referencing both blobs

use crate::client::RegistryClient;
use crate::{
    OciDescriptor, OciIndex, OciIndexManifest, OciManifest, OciPlatform, Result, CONFIG_MEDIA_TYPE,
    INDEX_MEDIA_TYPE, LAYER_MEDIA_TYPE, MANIFEST_MEDIA_TYPE,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncReadExt;

/// Result of a successful push.
#[derive(Debug)]
pub struct PushResult {
    /// Digest of the uploaded sidecar blob.
    pub layer_digest: String,
    /// Size of the sidecar blob in bytes.
    pub layer_size: u64,
    /// Digest of the OCI manifest.
    pub manifest_digest: String,
    /// Host platform this artifact targets (e.g. `linux/amd64`).
    pub platform: String,
    /// The per-platform tag the manifest was also tagged under (e.g.
    /// `latest-linux-amd64`).
    pub platform_tag: String,
}

/// Push a `.smolmachine` sidecar to the registry.
///
/// Uses a two-pass approach: pass 1 computes the SHA256 digest by streaming
/// through the file, pass 2 streams the file to the registry. The OS page
/// cache makes the second read essentially free.
pub async fn push(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    smolmachine_path: &Path,
) -> Result<PushResult> {
    // 1. Compute SHA256 digest (pass 1: stream through hasher, no full-file buffer).
    let file = tokio::fs::File::open(smolmachine_path).await?;
    let file_meta = file.metadata().await?;
    let layer_size = file_meta.len();

    let mut reader = tokio::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let layer_digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    tracing::info!(
        path = %smolmachine_path.display(),
        size = layer_size,
        digest = %layer_digest,
        "computed sidecar digest"
    );

    // 2. Parse PackManifest from the footer to use as OCI config.
    let manifest = smolvm_pack::read_manifest_from_sidecar(smolmachine_path)?;
    let config_json = serde_json::to_vec_pretty(&manifest)?;

    // 3. Stream-upload sidecar as the layer blob.
    //
    // The factory reopens the file on each call so that a 401 mid-upload can be
    // retried with a fresh stream. The OS page cache makes repeated opens cheap.
    tracing::info!("uploading sidecar blob...");
    let path = smolmachine_path.to_path_buf();
    client
        .push_blob_stream(repo, &layer_digest, layer_size, move || {
            // std::fs::File::open is synchronous but fast (just a syscall).
            let file = std::fs::File::open(&path).map_err(crate::RegistryError::from)?;
            let async_file = tokio::fs::File::from_std(file);
            let stream = tokio_util::io::ReaderStream::with_capacity(async_file, 256 * 1024);
            Ok(reqwest::Body::wrap_stream(stream))
        })
        .await?;

    // 4. Upload config blob (small, buffered is fine).
    tracing::info!("uploading config blob...");
    let config_digest = client.push_blob(repo, &config_json).await?;
    let config_size = config_json.len() as u64;

    // 5. Build OCI Image Manifest.
    let oci_manifest = OciManifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.to_string(),
        config: OciDescriptor {
            media_type: CONFIG_MEDIA_TYPE.to_string(),
            digest: config_digest,
            size: config_size,
        },
        layers: vec![OciDescriptor {
            media_type: LAYER_MEDIA_TYPE.to_string(),
            digest: layer_digest.clone(),
            size: layer_size,
        }],
    };

    let manifest_json = serde_json::to_vec_pretty(&oci_manifest)?;
    let manifest_size = manifest_json.len() as u64;
    let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_json)));

    // 6. Store the single-platform manifest content-addressably (by digest), and
    //    also tag it per platform (e.g. `latest-linux-amd64`) so a specific
    //    platform is directly pullable.
    let platform = OciPlatform::parse(&manifest.host_platform);
    let platform_tag = format!("{reference}-{}-{}", platform.os, platform.architecture);
    tracing::info!(digest = %manifest_digest, platform = %platform.label(), "uploading manifest...");
    client
        .put_manifest(repo, &manifest_digest, &manifest_json)
        .await?;
    client
        .put_manifest(repo, &platform_tag, &manifest_json)
        .await?;

    // 7. Maintain an image index at `reference` so the tag fans out by platform.
    //    Merge with any existing index (replacing this platform's entry); a
    //    legacy single-manifest tag is replaced by a fresh index.
    let entry = OciIndexManifest {
        media_type: MANIFEST_MEDIA_TYPE.to_string(),
        digest: manifest_digest.clone(),
        size: manifest_size,
        platform: Some(platform.clone()),
    };
    let mut manifests = match client.get_manifest_raw(repo, reference).await {
        Ok((bytes, ct)) if ct.contains(INDEX_MEDIA_TYPE) => {
            serde_json::from_slice::<OciIndex>(&bytes)
                .map(|i| i.manifests)
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };
    manifests.retain(|m| m.platform.as_ref() != Some(&platform));
    manifests.push(entry);
    let index = OciIndex {
        schema_version: 2,
        media_type: INDEX_MEDIA_TYPE.to_string(),
        manifests,
    };
    let index_json = serde_json::to_vec_pretty(&index)?;
    tracing::info!(reference = %reference, platforms = index.manifests.len(), "updating image index...");
    client.put_manifest(repo, reference, &index_json).await?;

    tracing::info!(digest = %manifest_digest, layer_size, "push complete");

    Ok(PushResult {
        layer_digest,
        layer_size,
        manifest_digest,
        platform: platform.label(),
        platform_tag,
    })
}
