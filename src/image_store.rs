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
    let (_client, _repo, manifest_bytes) = resolve_manifest(reference, auth, None).await?;
    Ok(manifest_digest(&manifest_bytes))
}

/// The digest `reference` currently points to (for a multi-arch tag, its image
/// index), authorized with `auth`, from a single manifest HEAD. The registry
/// authorizes `repository:<repo>:pull` for the request exactly as it does for a
/// GET, so this is the same gate as [`authorized_digest`] at a fraction of the
/// cost. A caller keying cached content on it must add the platform.
pub async fn authorized_reference_digest(reference: &str, auth: &PullAuth) -> Result<String> {
    let reference = &without_pinned_tag(reference);
    let parsed = Reference::parse(reference)
        .map_err(|e| Error::config("image-auth", format!("bad reference: {}", e.reason)))?;
    let want = parsed
        .digest
        .clone()
        .or_else(|| parsed.tag.clone())
        .unwrap_or_else(|| "latest".to_string());
    let config = crate::SmolSettings::load()?.images;
    let host = crate::registry::extract_registry(reference);
    let client = registry_client(&host, &config, auth);
    let repo = repo_for(&host, &parsed);
    client
        .head_manifest_digest(&repo, &want)
        .await
        .map_err(|e| Error::agent("image-auth", e.to_string()))
}

/// The config and ordered layers of the platform image the caller can pull.
/// This identifies the bytes the guest actually stores even when a tag moves
/// during a seed build or a registry mirror serves different content.
pub async fn authorized_image_content(
    reference: &str,
    auth: &PullAuth,
) -> Result<(String, Vec<String>)> {
    let (_, _, bytes) = resolve_manifest(reference, auth, None).await?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| Error::agent("image-auth", e.to_string()))?;
    let config = manifest["config"]["digest"]
        .as_str()
        .ok_or_else(|| Error::agent("image-auth", "manifest lacks config digest"))?;
    let layers = manifest["layers"]
        .as_array()
        .ok_or_else(|| Error::agent("image-auth", "manifest lacks layers"))?
        .iter()
        .map(|layer| layer["digest"].as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::agent("image-auth", "manifest layer lacks digest"))?;
    Ok((config.to_string(), layers))
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
    let (client, repo, manifest_bytes) = resolve_manifest(reference, auth, None).await?;
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
    let (_client, _repo, manifest_bytes) = resolve_manifest(reference, auth, oci_platform).await?;
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

fn manifest_digest(manifest_bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)))
}

/// The winning registry client, its repo path, and the resolved (single-
/// platform) manifest bytes for `reference`. Shared by [`authorized_digest`],
/// [`authorized_image_config`] and [`image_compressed_size`] so all authorize
/// identically and so the config fetch reuses the same client/repo that
/// resolved the manifest. `oci_platform` selects an index entry; `None` is this
/// host's architecture.
async fn resolve_manifest(
    reference: &str,
    auth: &PullAuth,
    oci_platform: Option<&str>,
) -> Result<(RegistryClient, String, Vec<u8>)> {
    let reference = &without_pinned_tag(reference);
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

    // Ask the reference's own registry, as the in-guest pull does. Not
    // `registry_pull_hosts`: that is an egress allow-list of DNS apexes (Docker
    // Hub's includes its `docker.com` blob CDN, whose website answers any path
    // with a 200 page), and querying it masked the real 401/404/429.
    let host = crate::registry::extract_registry(reference);
    let client = registry_client(&host, &config, auth);
    let repo = repo_for(&host, &parsed);
    let platform = oci_platform.map(smolvm_registry::OciPlatform::parse);
    let manifest_bytes = match &platform {
        Some(p) => client.get_manifest_resolved_platform(&repo, &want, p).await,
        None => client.get_manifest_resolved(&repo, &want).await,
    }
    .map_err(|e| Error::agent("image-auth", e.to_string()))?;
    // A manifest is a JSON object. Anything else is not from a registry, and
    // must not be hashed into a digest or trusted as one.
    if !matches!(
        serde_json::from_slice::<serde_json::Value>(&manifest_bytes),
        Ok(serde_json::Value::Object(_))
    ) {
        return Err(Error::agent(
            "image-auth",
            format!("{host} did not return an image manifest for {reference}"),
        ));
    }
    Ok((client, repo, manifest_bytes))
}

/// Fetch `reference` on the HOST into a `docker save` archive and stage it in
/// the local image cache, returning the `local:<hash>` reference to boot from.
///
/// This is how a machine with no network gets a registry image: the guest
/// would pull it itself, but it has no network to pull with. The archive is
/// what `--image ./saved.tar` would have produced, so the guest flattens it
/// offline exactly as it does a user's own `docker save`.
///
/// Authorization is the registry's, with `auth`, on every call, as for the
/// guest's own pull. Every blob is checked against its manifest digest and
/// size before anything is staged. A repeat fetch of the same image from the
/// same registry and repository reuses the staged archive.
pub async fn fetch_image_archive(reference: &str, auth: &PullAuth) -> Result<String> {
    let (client, repo, manifest_bytes) =
        resolve_manifest(reference, auth, None)
            .await
            .map_err(|error| match &error {
                // Say what the guest's own pull says for a reference that does not
                // exist, so callers tell a typo (never retryable) from a fault.
                Error::Agent { reason, .. }
                    if reason.contains("registry returned 404")
                        || reason.contains("blob not found")
                        || reason.contains("MANIFEST_UNKNOWN")
                        || reason.contains("NAME_UNKNOWN") =>
                {
                    Error::agent_not_found(
                        "fetch image",
                        format!("image not found in the registry: {reference}"),
                    )
                }
                _ => error,
            })?;
    let host = crate::registry::extract_registry(reference);
    let key = hex::encode(Sha256::digest(format!(
        "{host}/{repo}@{}",
        manifest_digest(&manifest_bytes)
    )));
    if let Some(staged) = crate::data::image_source::fetched_archive(&key) {
        return Ok(staged);
    }
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Error::agent("fetch image", format!("parse manifest: {e}")))?;
    let total = manifest.config.size + manifest.layers.iter().map(|l| l.size).sum::<u64>();
    let limit = crate::data::image_source::max_archive_bytes();
    if total > limit {
        return Err(Error::config(
            "fetch image",
            format!("{reference} is {total} bytes, over the {limit}-byte image limit"),
        ));
    }

    let staging = crate::data::image_source::archive_staging_dir()?;
    let blobs = std::iter::once(&manifest.config).chain(manifest.layers.iter());
    futures_util::future::try_join_all(
        blobs.map(|blob| download_blob(&client, &repo, blob, staging.path().join(blob_file(blob)))),
    )
    .await?;

    let dir = staging.path().to_path_buf();
    let OciManifest { config, layers, .. } = manifest;
    let local = tokio::task::spawn_blocking(move || -> Result<String> {
        let archive = dir.join("image.tar");
        write_save_archive(&dir, &archive, &config, &layers)?;
        match crate::data::image_source::resolve(crate::data::image_source::ImageSource::Archive(
            crate::data::image_source::ArchiveInput::File(archive),
        ))? {
            crate::data::image_source::ResolvedImage::Local { reference, .. } => Ok(reference),
            crate::data::image_source::ResolvedImage::Registry(_) => {
                unreachable!("an archive resolves to a local reference")
            }
        }
    })
    .await
    .map_err(|e| Error::agent("fetch image", e.to_string()))??;
    crate::data::image_source::record_fetched_archive(&key, &local)?;
    drop(staging);
    Ok(local)
}

/// The local reference `record` should boot from when its registry image must
/// be fetched on the host (see [`crate::config::VmRecord::image_needs_host_fetch`]),
/// or `None` when the guest pulls it as usual. For the synchronous start
/// paths; the caller persists the pin with
/// [`crate::config::VmRecord::pin_host_fetched_image`].
pub fn host_fetch_for(record: &crate::config::VmRecord, auth: &PullAuth) -> Result<Option<String>> {
    if !record.image_needs_host_fetch() {
        return Ok(None);
    }
    let Some(image) = record.image.as_deref() else {
        return Ok(None);
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::agent("fetch image", e.to_string()))?;
    rt.block_on(fetch_image_archive(image, auth)).map(Some)
}

/// [`host_fetch_for`], then persist the pin on `name`'s record so this and every
/// later start boot the same bytes. Returns the record to launch.
pub fn pin_for_start(
    db: &crate::db::SmolvmDb,
    name: &str,
    record: crate::config::VmRecord,
    auth: &PullAuth,
) -> Result<crate::config::VmRecord> {
    let Some(local) = host_fetch_for(&record, auth)? else {
        return Ok(record);
    };
    db.update_vm_durable(name, |r| r.pin_host_fetched_image(local.clone()))?
        .ok_or_else(|| Error::vm_not_found(name))
}

/// The file a blob is written to in a staged archive: its digest, which the
/// archive's `manifest.json` names.
fn blob_file(blob: &smolvm_registry::OciDescriptor) -> String {
    blob.digest.replace(':', "-")
}

/// Stream one blob to `dest`, refusing it unless it is exactly the bytes the
/// manifest names.
async fn download_blob(
    client: &RegistryClient,
    repo: &str,
    blob: &smolvm_registry::OciDescriptor,
    dest: std::path::PathBuf,
) -> Result<()> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let fail = |message: String| Error::agent("fetch image", message);
    let mut stream = client
        .pull_blob_stream(repo, &blob.digest)
        .await
        .map_err(|e| fail(format!("{}: {e}", blob.digest)))?;
    let mut file = tokio::fs::File::create(&dest).await?;
    let mut hasher = Sha256::new();
    let mut written = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| fail(format!("{}: {e}", blob.digest)))?;
        written += chunk.len() as u64;
        if written > blob.size {
            return Err(fail(format!(
                "{} is larger than the {} bytes its manifest declares",
                blob.digest, blob.size
            )));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    let got = format!("sha256:{}", hex::encode(hasher.finalize()));
    if got != blob.digest || written != blob.size {
        return Err(fail(format!(
            "{} arrived as {got} ({written} bytes); refusing it",
            blob.digest
        )));
    }
    Ok(())
}

/// Write the blobs downloaded into `dir` as a `docker save` archive at
/// `archive`: a `manifest.json` naming the config and the layers in order,
/// beside the blobs themselves. This is the format the guest's `crane export`
/// flattens and its config recovery reads.
fn write_save_archive(
    dir: &std::path::Path,
    archive: &std::path::Path,
    config: &smolvm_registry::OciDescriptor,
    layers: &[smolvm_registry::OciDescriptor],
) -> Result<()> {
    let manifest = serde_json::json!([{
        "Config": blob_file(config),
        "RepoTags": [],
        "Layers": layers.iter().map(blob_file).collect::<Vec<_>>(),
    }]);
    let manifest =
        serde_json::to_vec(&manifest).map_err(|e| Error::agent("fetch image", e.to_string()))?;
    let mut tar = tar::Builder::new(std::fs::File::create(archive)?);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "manifest.json", manifest.as_slice())?;
    for blob in std::iter::once(config).chain(layers) {
        let name = blob_file(blob);
        tar.append_path_with_name(dir.join(&name), &name)?;
        // The archive now holds the blob; drop the loose copy as we go so
        // staging peaks near one image's size, not two.
        std::fs::remove_file(dir.join(&name))?;
    }
    tar.into_inner()?.sync_all()?;
    Ok(())
}

/// `reference` without its tag when a digest also pins it (`alpine:3.21@sha256:…`
/// → `alpine@sha256:…`). The digest decides the content, as it does for Docker
/// and `crane`; the tag is only a label, and the parser takes one or the other.
fn without_pinned_tag(reference: &str) -> String {
    let Some((name, digest)) = reference.split_once('@') else {
        return reference.to_string();
    };
    let tag_at = name
        .rfind(':')
        .filter(|at| name.rfind('/').is_none_or(|slash| *at > slash));
    match tag_at {
        Some(at) => format!("{}@{digest}", &name[..at]),
        None => reference.to_string(),
    }
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
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
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

    fn descriptor(bytes: &[u8]) -> smolvm_registry::OciDescriptor {
        smolvm_registry::OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            size: bytes.len() as u64,
        }
    }

    #[test]
    fn a_digest_pinned_reference_drops_its_tag() {
        assert_eq!(
            without_pinned_tag("alpine:3.21@sha256:ab"),
            "alpine@sha256:ab"
        );
        assert_eq!(
            without_pinned_tag("reg.io:5000/org/app:v1@sha256:ab"),
            "reg.io:5000/org/app@sha256:ab"
        );
        // A registry port is not a tag.
        assert_eq!(
            without_pinned_tag("reg.io:5000/app@sha256:ab"),
            "reg.io:5000/app@sha256:ab"
        );
        assert_eq!(without_pinned_tag("alpine:3.21"), "alpine:3.21");
        assert!(Reference::parse(&without_pinned_tag(
            "alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507"
        ))
        .is_ok());
    }

    #[test]
    fn a_fetched_image_is_written_as_a_docker_save_archive() {
        let dir = tempfile::tempdir().unwrap();
        let config = descriptor(br#"{"architecture":"arm64"}"#);
        let layer = descriptor(b"layer bytes");
        std::fs::write(
            dir.path().join(blob_file(&config)),
            br#"{"architecture":"arm64"}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join(blob_file(&layer)), b"layer bytes").unwrap();
        let archive = dir.path().join("image.tar");
        write_save_archive(dir.path(), &archive, &config, std::slice::from_ref(&layer)).unwrap();

        let mut entries = std::collections::HashMap::new();
        for entry in tar::Archive::new(std::fs::File::open(&archive).unwrap())
            .entries()
            .unwrap()
        {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut body).unwrap();
            entries.insert(name, body);
        }
        // What the guest's config recovery and `crane export` read.
        let manifest: serde_json::Value =
            serde_json::from_slice(&entries["manifest.json"]).unwrap();
        assert_eq!(manifest[0]["Config"], blob_file(&config));
        assert_eq!(manifest[0]["Layers"][0], blob_file(&layer));
        assert_eq!(entries[&blob_file(&layer)], b"layer bytes");
        assert!(
            !dir.path().join(blob_file(&layer)).exists(),
            "loose blobs are dropped once archived"
        );
    }

    #[test]
    fn a_blob_that_is_not_what_the_manifest_names_is_refused() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            let wanted = descriptor(b"the real layer");
            Mock::given(method("GET"))
                .and(path(format!("/v2/library/x/blobs/{}", wanted.digest)))
                .respond_with(
                    ResponseTemplate::new(200).set_body_bytes(b"a substituted layer".to_vec()),
                )
                .mount(&server)
                .await;
            let client = RegistryClient::new(server.uri());
            let dir = tempfile::tempdir().unwrap();
            let error = download_blob(&client, "library/x", &wanted, dir.path().join("blob"))
                .await
                .expect_err("substituted bytes must be refused");
            assert!(error.to_string().contains(&wanted.digest), "{error}");

            Mock::given(method("GET"))
                .and(path(
                    "/v2/library/x/blobs/sha256:".to_string() + &hex::encode(Sha256::digest(b"ok")),
                ))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec()))
                .mount(&server)
                .await;
            download_blob(
                &client,
                "library/x",
                &descriptor(b"ok"),
                dir.path().join("ok"),
            )
            .await
            .unwrap();
            assert_eq!(std::fs::read(dir.path().join("ok")).unwrap(), b"ok");
        });
    }

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
            let content = authorized_image_content(
                &reference,
                &PullAuth::Bearer("good-token".into()),
            )
            .await
            .expect("authorized caller should resolve image content");
            assert_eq!(
                content,
                (format!("sha256:{}", "0".repeat(64)), Vec::new())
            );
        });
    }

    /// A host that answers 200 with something other than a manifest, like the
    /// web page Docker Hub's `docker.com` returns for any path, is not a
    /// registry: its body must never become a digest.
    #[test]
    fn non_manifest_response_is_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/latest"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "text/html")
                        .set_body_string("<!doctype html><title>Docker</title>"),
                )
                .mount(&server)
                .await;
            let host = server.uri().strip_prefix("http://").unwrap().to_string();
            let err = authorized_digest(&format!("{host}/myrepo:latest"), &PullAuth::Anonymous)
                .await
                .expect_err("a web page is not a manifest");
            assert!(
                err.to_string().contains("did not return an image manifest"),
                "{err}"
            );
        });
    }

    /// The registry's own failure reaches the caller: nothing else is asked
    /// that could replace a real "not found" with an unrelated error.
    #[test]
    fn registry_error_is_reported_as_is() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/no-such-tag"))
                .respond_with(ResponseTemplate::new(404))
                .expect(1)
                .mount(&server)
                .await;
            let host = server.uri().strip_prefix("http://").unwrap().to_string();
            let err =
                authorized_digest(&format!("{host}/myrepo:no-such-tag"), &PullAuth::Anonymous)
                    .await
                    .expect_err("a missing tag must fail");
            assert!(err.to_string().contains("myrepo:no-such-tag"), "{err}");
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
