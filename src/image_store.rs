//! Host-side registry authorization for OCI images, shared by the local CLI and
//! the cloud worker path so both authorize identically (issue #756).
//!
//! [`authorized_digest`] resolves an image reference with the CALLER's
//! credentials and returns its manifest digest. Two properties fall out:
//!
//! * **Authorization is the registry's own decision.** Resolving the manifest
//!   makes the registry authorize `repository:<repo>:pull` for these
//!   credentials, so a caller who cannot pull the image is rejected here (401/
//!   403) before anything is cached or booted on their behalf.
//! * **The digest is a content address.** Callers key their caches on it, so an
//!   entry tracks the image's CONTENT rather than a mutable tag: when `:latest`
//!   moves upstream the digest changes and the stale entry is not reused.
//!
//! A caller that caches image CONTENT keyed by this digest must also bind the
//! entry to the registry and repository that authorized it — resolution accepts
//! the first candidate registry that answers, including one the caller controls,
//! so a digest alone is not proof of entitlement to previously cached bytes.

use sha2::{Digest, Sha256};

use crate::registry::{registry_client, PullAuth, Reference};
use crate::{Error, Result};

/// Resolve `reference` against the candidate registries the guest would try and
/// return its manifest digest, authorized with `auth`.
///
/// The registry authorizes `repository:<repo>:pull` for the caller's credentials
/// during resolution; an unauthorized caller is rejected here.
pub async fn authorized_digest(reference: &str, auth: &PullAuth) -> Result<String> {
    let manifest_bytes = resolved_manifest(reference, auth, None).await?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(&manifest_bytes))
    ))
}

/// Resolve `reference` to its platform manifest and return the summed
/// `layers[].size` — the image's total COMPRESSED footprint, authorized with
/// `auth`. `oci_platform` selects the index entry the way the guest's pull
/// would (`None` = this host's architecture, matching `authorized_digest`).
///
/// Callers use this to provision for an image BEFORE it is pulled: the
/// manifest is the only pre-pull bound on how much data the pull will write.
/// The returned bytes are compressed; extraction inflates them.
pub async fn image_compressed_size(
    reference: &str,
    auth: &PullAuth,
    oci_platform: Option<&str>,
) -> Result<u64> {
    let manifest_bytes = resolved_manifest(reference, auth, oci_platform).await?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Error::agent("image-size", format!("bad manifest JSON: {e}")))?;
    let layers = manifest["layers"].as_array().ok_or_else(|| {
        Error::agent(
            "image-size",
            "resolved manifest has no layers array".to_string(),
        )
    })?;
    Ok(layers.iter().map(|l| l["size"].as_u64().unwrap_or(0)).sum())
}

/// Resolve `reference` against the candidate registries the guest would try and
/// return the platform manifest's bytes, authorized with `auth`.
///
/// The registry authorizes `repository:<repo>:pull` for the caller's credentials
/// during resolution; an unauthorized caller is rejected here.
async fn resolved_manifest(
    reference: &str,
    auth: &PullAuth,
    oci_platform: Option<&str>,
) -> Result<Vec<u8>> {
    let parsed = Reference::parse(reference)
        .map_err(|e| Error::config("image-auth", format!("bad reference: {}", e.reason)))?;
    let want = parsed
        .digest
        .clone()
        .or_else(|| parsed.tag.clone())
        .unwrap_or_else(|| "latest".to_string());
    // OCI-image credentials live under `images` (docker.io/ghcr/...), the same
    // config the in-guest pull consults.
    let config = crate::SmolSettings::load()?.images;

    // Resolve the registry the way the GUEST does — via `registry_pull_hosts`, not
    // the configured default — so the host-side gate targets the same registry the
    // in-guest pull would (a bare `alpine` is Docker Hub, not the smol registry).
    let platform = oci_platform.map(smolvm_registry::OciPlatform::parse);
    let mut first_err: Option<String> = None;
    for host in &crate::registry::registry_pull_hosts(reference) {
        let client = registry_client(host, &config, auth);
        let repo = repo_for(host, &parsed);
        let resolved = match &platform {
            Some(p) => client.get_manifest_resolved_platform(&repo, &want, p).await,
            None => client.get_manifest_resolved(&repo, &want).await,
        };
        match resolved {
            Ok(manifest_bytes) => {
                return Ok(manifest_bytes);
            }
            // Keep the FIRST failure. `registry_pull_hosts` is a DNS allow-list,
            // not a list of real endpoints — Docker Hub yields
            // ["docker.io", "docker.com"] — so letting the later marketing-host
            // failure overwrite the real 401/429 would surface a nonsense error.
            Err(e) => {
                let _ = first_err.get_or_insert_with(|| e.to_string());
            }
        }
    }
    Err(Error::agent(
        "image-auth",
        first_err.unwrap_or_else(|| "no candidate registry resolved the image".to_string()),
    ))
}

/// The repository path for a reference against a candidate `host`. Docker Hub
/// official images (no namespace) live under the implicit `library/` namespace,
/// so a bare `alpine` becomes `library/alpine` — without which the pull-scope is
/// wrong and the registry answers 401.
fn repo_for(host: &str, r: &Reference) -> String {
    let docker_hub = matches!(
        host,
        "docker.io" | "docker.com" | "index.docker.io" | "registry-1.docker.io"
    );
    match &r.namespace {
        Some(ns) => format!("{}/{}", ns, r.name),
        None if docker_hub => format!("library/{}", r.name),
        None => r.name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_for_maps_docker_hub_and_namespaced_refs() {
        // Docker Hub official image (no namespace) → implicit `library/`.
        let bare = Reference::parse("alpine").unwrap();
        assert_eq!(repo_for("docker.io", &bare), "library/alpine");
        // A namespaced ref keeps its namespace on any host.
        let ns = Reference::parse("ghcr.io/org/tool:v1").unwrap();
        assert_eq!(repo_for("ghcr.io", &ns), "org/tool");
        // A bare name on a non-Docker-Hub host is not `library/`-prefixed.
        assert_eq!(repo_for("ghcr.io", &bare), "alpine");
    }

    /// THE security property: authorization is the registry's decision, made with
    /// the CALLER's credentials on every call. An unauthorized caller is rejected
    /// even though the image plainly exists and another caller can resolve it.
    #[test]
    fn resolution_requires_authorization() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            let body = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0},"layers":[]}"#.to_vec();

            // Authorized bearer → 200 with the manifest.
            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/latest"))
                .and(header("authorization", "Bearer good-token"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                        .set_body_bytes(body.clone()),
                )
                .with_priority(1)
                .mount(&server)
                .await;
            // Anyone else → 401 (no challenge header → the client does not retry).
            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/latest"))
                .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
                .with_priority(5)
                .mount(&server)
                .await;

            let host = server.uri().strip_prefix("http://").unwrap().to_string();
            let reference = format!("{host}/myrepo:latest");

            // DENY: an unauthorized caller cannot resolve the image at all.
            let denied = authorized_digest(&reference, &PullAuth::Anonymous).await;
            assert!(denied.is_err(), "unauthorized caller must be rejected");

            // ALLOW: the authorized caller gets the manifest's content digest.
            let digest = authorized_digest(&reference, &PullAuth::Bearer("good-token".into()))
                .await
                .expect("authorized caller should resolve");
            assert_eq!(
                digest,
                format!("sha256:{}", hex::encode(Sha256::digest(&body))),
                "the digest is the content address of the manifest"
            );
        });
    }
}
