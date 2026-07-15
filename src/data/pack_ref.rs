//! Routing registry references that name smolmachine PACK artifacts.
//!
//! A repository on the smolmachines registry (e.g. `library/alpine`, or a
//! tenant export) is not an OCI container image: its single "layer" blob
//! (mediaType `application/vnd.smolmachines.smolmachine.v1`) is a complete
//! `.smolmachine` sidecar — `agent-rootfs.tar`, `layers/*.tar`, and a
//! multi-GiB non-sparse `storage.ext4` disk template. Handing such a ref to
//! the in-guest OCI puller tar-unpacks the sidecar generically, and the
//! `storage.ext4` fills the guest disk before anything boots.
//!
//! This module probes a registry image reference's manifest on the HOST and,
//! when the layers carry a smolmachines media type, downloads the sidecar
//! blob so the caller can continue through the proven from-`.smolmachine`
//! flow (`machine create --from` / the serve API `from` path) instead.
//!
//! The probe is deliberately fail-open: any parse/auth/network failure means
//! "not a pack" and the caller proceeds with the normal in-guest pull, so the
//! probe can never break docker.io/GHCR/other-registry images. Only a pull
//! failure AFTER a positive probe is an error — falling back at that point
//! would just reproduce the disk-fill.

use crate::{Error, Result};
use std::path::PathBuf;

/// Media-type prefix that marks a manifest layer as a smolmachines artifact
/// (`application/vnd.smolmachines.smolmachine.v1` today; treat the vendor
/// prefix as the trigger so future versions route the same way).
pub const PACK_MEDIA_TYPE_PREFIX: &str = "application/vnd.smolmachines.";

/// Whether a (platform-resolved) OCI manifest describes a smolmachine pack:
/// any layer whose mediaType carries the smolmachines vendor prefix.
///
/// Parses leniently (`serde_json::Value`) so Docker v2 / OCI manifests that
/// don't match our strict `OciManifest` struct still classify as "not a pack"
/// rather than erroring.
pub fn manifest_has_pack_layer(manifest_bytes: &[u8]) -> bool {
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(manifest_bytes) else {
        return false;
    };
    doc.get("layers")
        .and_then(|l| l.as_array())
        .is_some_and(|layers| {
            layers.iter().any(|layer| {
                layer
                    .get("mediaType")
                    .and_then(|m| m.as_str())
                    .is_some_and(|m| m.starts_with(PACK_MEDIA_TYPE_PREFIX))
            })
        })
}

/// The explicit registry host of an `--image` value, if it names one
/// (`host.tld/...`, `host:port/...`, `localhost/...`).
///
/// Docker-convention bare names (`alpine`, `library/ubuntu:24.04`) return
/// `None`: to the in-guest puller they mean Docker Hub, while
/// [`crate::registry::Reference::parse`] defaults them to the smolmachines
/// registry (pack-ref convention). Probing them would re-interpret
/// `--image alpine` as `registry.smolmachines.com/library/alpine` — a pack —
/// and silently hijack a Docker Hub pull, so only explicit hosts are probed.
fn explicit_registry_host(image: &str) -> Option<&str> {
    let (first, rest) = image.split_once('/')?;
    if rest.is_empty() {
        return None;
    }
    if first.contains('.') || first.contains(':') || first == "localhost" {
        Some(first)
    } else {
        None
    }
}

/// Docker Hub aliases — never serve packs, so skip the probe entirely rather
/// than pay a cold manifest round-trip on every Hub pull.
fn is_docker_hub(host: &str) -> bool {
    matches!(
        host,
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
    )
}

/// Probe `image`'s manifest and, if it is a smolmachine pack artifact, pull
/// the sidecar blob into the blob cache and return its path for the caller to
/// route through the from-`.smolmachine` flow.
///
/// Returns `Ok(None)` when the ref is not a pack — including every probe
/// failure (no explicit registry host, Docker Hub, unreadable settings,
/// manifest fetch error) — so callers always have the in-guest pull to fall
/// back on. A request-supplied `identity_token` (the control plane's
/// short-lived pull token) takes precedence over persisted credentials,
/// mirroring the serve `registryRef` path.
pub async fn resolve_pack_ref(
    image: &str,
    identity_token: Option<&str>,
    blob_peers: &[String],
) -> Result<Option<PathBuf>> {
    let Some(host) = explicit_registry_host(image) else {
        return Ok(None);
    };
    if is_docker_hub(host) {
        return Ok(None);
    }
    let Ok(parsed) = crate::registry::Reference::parse(image) else {
        return Ok(None); // the in-guest puller surfaces its own parse error
    };
    let Ok(settings) = crate::settings::SmolSettings::load() else {
        return Ok(None);
    };

    let effective_registry = settings
        .machines
        .get_mirror(&parsed.registry)
        .unwrap_or(&parsed.registry);
    if is_docker_hub(effective_registry) {
        return Ok(None);
    }

    let base_url = if smolvm_registry::is_local_registry(effective_registry) {
        format!("http://{}", effective_registry)
    } else {
        format!("https://{}", effective_registry)
    };
    let mut client = smolvm_registry::RegistryClient::new(base_url);
    if let Some(token) = identity_token {
        client = client.with_identity_token(token.to_string());
    } else if let Some(entry) = settings.machines.registries.get(&parsed.registry) {
        if let Some(ref token) = entry.identity_token {
            client = client.with_identity_token(token.clone());
        } else if let Some(auth) = settings.machines.get_credentials(&parsed.registry) {
            if auth.username == "token" {
                // Legacy direct-bearer convention: the password IS the bearer.
                client = client.with_token(auth.password);
            } else {
                client = client.with_basic_credentials(auth.username, auth.password);
            }
        }
    }

    let repo = parsed.repository();
    let reference = parsed
        .digest
        .as_deref()
        .or(parsed.tag.as_deref())
        .unwrap_or("latest");

    let manifest_bytes = match client.get_manifest_resolved(&repo, reference).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // Fail open: an unreachable/denying registry falls back to the
            // in-guest pull, which reports its own (authoritative) error.
            tracing::debug!(image = %image, error = %e, "pack probe failed; using in-guest pull");
            return Ok(None);
        }
    };
    if !manifest_has_pack_layer(&manifest_bytes) {
        return Ok(None);
    }

    // Positive probe: this IS a pack, so the in-guest path is guaranteed to
    // fail (disk-fill) — a pull error from here on is the real error.
    tracing::info!(image = %image, "reference is a smolmachine pack; pulling sidecar on the host");
    let cache = smolvm_registry::BlobCache::open_default()
        .map_err(|e| Error::agent("open blob cache", e.to_string()))?;
    let result = smolvm_registry::pull(&client, &repo, reference, None, &cache, blob_peers)
        .await
        .map_err(|e| Error::agent("pull smolmachine artifact", e.to_string()))?;
    Ok(Some(result.path))
}

/// Blocking wrapper for the synchronous CLI paths (`machine run`/`create`).
/// Skips spinning up a runtime for refs that can never probe (bare Docker
/// Hub-style names).
pub fn resolve_pack_ref_blocking(image: &str) -> Result<Option<PathBuf>> {
    if explicit_registry_host(image).is_none() {
        return Ok(None);
    }
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| Error::agent("create tokio runtime", e.to_string()))?;
    rt.block_on(resolve_pack_ref(image, None, &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_manifests_are_detected_by_layer_media_type() {
        // The exact shape `smolvm pack push` produces.
        let pack = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.smolmachines.machine.config.v1+json",
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 2
            },
            "layers": [{
                "mediaType": "application/vnd.smolmachines.smolmachine.v1",
                "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "size": 123
            }]
        });
        assert!(manifest_has_pack_layer(&serde_json::to_vec(&pack).unwrap()));

        // An ordinary container manifest (gzip layers) must not match.
        let oci = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:aa", "size": 1 },
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:bb", "size": 1 },
                { "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": "sha256:cc", "size": 1 }
            ]
        });
        assert!(!manifest_has_pack_layer(&serde_json::to_vec(&oci).unwrap()));

        // Layerless docs (an image index) and garbage are "not a pack".
        let index = serde_json::json!({ "schemaVersion": 2, "manifests": [] });
        assert!(!manifest_has_pack_layer(
            &serde_json::to_vec(&index).unwrap()
        ));
        assert!(!manifest_has_pack_layer(b"not json"));
    }

    #[test]
    fn only_explicit_non_hub_hosts_are_probed() {
        // Bare Docker-convention names mean Docker Hub to the in-guest puller —
        // probing them against the smolmachines default would hijack the pull.
        assert_eq!(explicit_registry_host("alpine"), None);
        assert_eq!(explicit_registry_host("alpine:3.20"), None);
        assert_eq!(explicit_registry_host("library/ubuntu:24.04"), None);

        assert_eq!(
            explicit_registry_host("registry.smolmachines.com/library/alpine:latest"),
            Some("registry.smolmachines.com")
        );
        assert_eq!(
            explicit_registry_host("localhost:5000/myimage:dev"),
            Some("localhost:5000")
        );
        assert_eq!(explicit_registry_host("ghcr.io/o/r:v1"), Some("ghcr.io"));

        // Explicit Docker Hub spellings short-circuit without a probe.
        assert!(is_docker_hub("docker.io"));
        assert!(is_docker_hub("index.docker.io"));
        assert!(is_docker_hub("registry-1.docker.io"));
        assert!(!is_docker_hub("registry.smolmachines.com"));
    }
}
