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
    OciDescriptor, OciManifest, Result, CONFIG_MEDIA_TYPE, LAYER_MEDIA_TYPE, MANIFEST_MEDIA_TYPE,
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

    // 3. Stream-upload sidecar as the layer blob (pass 2: re-read file as stream).
    tracing::info!("uploading sidecar blob...");
    let file = tokio::fs::File::open(smolmachine_path).await?;
    let stream = tokio_util::io::ReaderStream::with_capacity(file, 256 * 1024);
    let body = reqwest::Body::wrap_stream(stream);
    client
        .push_blob_stream(repo, &layer_digest, layer_size, body)
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
    let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_json)));

    // 6. PUT manifest.
    tracing::info!(reference = %reference, "uploading manifest...");
    client.put_manifest(repo, reference, &manifest_json).await?;

    tracing::info!(
        digest = %manifest_digest,
        layer_size,
        "push complete"
    );

    Ok(PushResult {
        layer_digest,
        layer_size,
        manifest_digest,
    })
}
