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

use serde::Deserialize;
use sha2::{Digest, Sha256};
use smolvm_registry::{OciManifest, RegistryClient};

use crate::registry::{registry_client, PullAuth, Reference};
use crate::{Error, Result};

/// Resolve `reference` against the candidate registries the guest would try and
/// return its manifest digest, authorized with `auth`.
///
/// The registry authorizes `repository:<repo>:pull` for the caller's credentials
/// during resolution; an unauthorized caller is rejected here.
pub async fn authorized_digest(reference: &str, auth: &PullAuth) -> Result<String> {
    let (_client, _repo, manifest_bytes) = resolve_manifest(reference, auth).await?;
    Ok(manifest_digest(&manifest_bytes))
}

/// The image's default command, resolved without pulling its layers.
///
/// The `--oci-cache` run path needs the image's declared ENTRYPOINT/CMD to run
/// it as a workload, but must not re-pull the image on a cache hit. Fetching the
/// manifest and config blob is a few hundred bytes over the same authorized
/// round-trip that resolves the digest — never the layer pull the cache avoids.
#[derive(Debug, Clone, Default)]
pub struct ImageRunConfig {
    /// Manifest digest — the content address callers key their cache on.
    pub digest: String,
    /// The image's ENTRYPOINT; empty when the image declares none.
    pub entrypoint: Vec<String>,
    /// The image's CMD; empty when the image declares none.
    pub cmd: Vec<String>,
}

/// Resolve `reference`'s digest AND its declared ENTRYPOINT/CMD, authorized with
/// `auth`. Same authorization gate as [`authorized_digest`] — the registry
/// authorizes the pull during manifest resolution — plus one small config-blob
/// fetch. No image layers are pulled.
pub async fn authorized_image_config(reference: &str, auth: &PullAuth) -> Result<ImageRunConfig> {
    let (client, repo, manifest_bytes) = resolve_manifest(reference, auth).await?;
    let digest = manifest_digest(&manifest_bytes);
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Error::agent("parse image manifest", e.to_string()))?;
    let config_bytes = client
        .pull_blob(&repo, &manifest.config.digest)
        .await
        .map_err(|e| Error::agent("fetch image config", e.to_string()))?;
    let blob: OciImageConfigBlob = serde_json::from_slice(&config_bytes)
        .map_err(|e| Error::agent("parse image config", e.to_string()))?;
    Ok(ImageRunConfig {
        digest,
        entrypoint: blob.config.entrypoint.unwrap_or_default(),
        cmd: blob.config.cmd.unwrap_or_default(),
    })
}

fn manifest_digest(manifest_bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)))
}

/// The winning registry client, its repo path, and the resolved (single-
/// platform) manifest bytes for `reference`. Shared by [`authorized_digest`] and
/// [`authorized_image_config`] so both authorize identically and so the config
/// fetch reuses the same client/repo that resolved the manifest.
async fn resolve_manifest(
    reference: &str,
    auth: &PullAuth,
) -> Result<(RegistryClient, String, Vec<u8>)> {
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
    let mut first_err: Option<String> = None;
    for host in &crate::registry::registry_pull_hosts(reference) {
        let client = registry_client(host, &config, auth);
        let repo = repo_for(host, &parsed);
        match client.get_manifest_resolved(&repo, &want).await {
            Ok(manifest_bytes) => return Ok((client, repo, manifest_bytes)),
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

/// The slice of an OCI image config blob the run path needs: its default
/// command. OCI/Docker spell these fields `Entrypoint`/`Cmd` (PascalCase), and
/// either may be absent.
#[derive(Deserialize)]
struct OciImageConfigBlob {
    #[serde(default)]
    config: OciImageConfigInner,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct OciImageConfigInner {
    #[serde(default)]
    entrypoint: Option<Vec<String>>,
    #[serde(default)]
    cmd: Option<Vec<String>>,
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

    /// Regression for #1334: `--oci-cache` lost the image's own ENTRYPOINT/CMD
    /// because the bake records `/bin/true`. `authorized_image_config` recovers
    /// them from the image config over the same authorized round-trip, without
    /// pulling layers, so the run path can run the image's command.
    #[test]
    fn image_config_resolves_entrypoint_and_cmd() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;

            // The image config blob, with a real ENTRYPOINT + CMD. pull_blob
            // verifies the blob hashes to the digest the manifest names, so the
            // manifest below must reference this content's actual sha256.
            let config_body =
                br#"{"config":{"Entrypoint":["/usr/local/bin/greet"],"Cmd":["--loud"]}}"#.to_vec();
            let config_digest =
                format!("sha256:{}", hex::encode(Sha256::digest(&config_body)));
            let manifest = format!(
                r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[]}}"#,
                config_body.len()
            )
            .into_bytes();

            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/latest"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                        .set_body_bytes(manifest.clone()),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v2/myrepo/blobs/{config_digest}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(config_body.clone()))
                .mount(&server)
                .await;

            let host = server.uri().strip_prefix("http://").unwrap().to_string();
            let reference = format!("{host}/myrepo:latest");

            let cfg = authorized_image_config(&reference, &PullAuth::Anonymous)
                .await
                .expect("config should resolve");
            assert_eq!(cfg.entrypoint, vec!["/usr/local/bin/greet".to_string()]);
            assert_eq!(cfg.cmd, vec!["--loud".to_string()]);
            assert_eq!(
                cfg.digest,
                format!("sha256:{}", hex::encode(Sha256::digest(&manifest))),
                "digest still tracks the manifest content, as the cache key needs"
            );
        });
    }

    /// An image that declares neither ENTRYPOINT nor CMD yields empty vectors
    /// (not an error), so the run path falls through to its shell/idle default
    /// exactly as the non-cached path does.
    #[test]
    fn image_config_tolerates_missing_command() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            let config_body = br#"{"config":{}}"#.to_vec();
            let config_digest =
                format!("sha256:{}", hex::encode(Sha256::digest(&config_body)));
            let manifest = format!(
                r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[]}}"#,
                config_body.len()
            )
            .into_bytes();

            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/latest"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                        .set_body_bytes(manifest),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v2/myrepo/blobs/{config_digest}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(config_body))
                .mount(&server)
                .await;

            let host = server.uri().strip_prefix("http://").unwrap().to_string();
            let reference = format!("{host}/myrepo:latest");

            let cfg = authorized_image_config(&reference, &PullAuth::Anonymous)
                .await
                .expect("config should resolve");
            assert!(cfg.entrypoint.is_empty());
            assert!(cfg.cmd.is_empty());
        });
    }
}
