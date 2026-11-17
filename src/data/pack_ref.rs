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
//!
//! An AUTH denial is the uncomfortable case. It does NOT mean "not a pack"; it
//! means "I couldn't look". Falling back is still right — the in-guest puller
//! resolves credentials from a different settings section and may have one the
//! probe lacked — but it is logged at WARN naming the missing credential,
//! because when the in-guest pull has no credential either, its `crane ... 401`
//! is the only thing the user sees and it explains nothing. See
//! `RCA-tenant-image-pull-401-2026-07-26.md`.

use crate::{Error, Result};
use std::path::PathBuf;

/// Media-type prefix that marks a manifest layer as a smolmachines artifact
/// (`application/vnd.smolmachines.smolmachine.v1` today; treat the vendor
/// prefix as the trigger so future versions route the same way).
pub const PACK_MEDIA_TYPE_PREFIX: &str = "application/vnd.smolmachines.";

/// A credential for the pack probe, in whichever form `RegistryClient` accepts.
enum ProbeCredential {
    /// Upstream JWT exchanged at the registry's token service.
    Identity(String),
    /// A bearer sent straight to the registry (legacy `username = "token"`).
    Bearer(String),
    Basic {
        username: String,
        password: String,
    },
}

impl ProbeCredential {
    fn apply(self, client: smolvm_registry::RegistryClient) -> smolvm_registry::RegistryClient {
        match self {
            Self::Identity(t) => client.with_identity_token(t),
            Self::Bearer(t) => client.with_token(t),
            Self::Basic { username, password } => client.with_basic_credentials(username, password),
        }
    }
}

/// Pull a configured credential for `registry` out of one settings section.
fn credential_from(
    config: &crate::registry::RegistryConfig,
    registry: &str,
) -> Option<ProbeCredential> {
    if let Some(token) = config
        .registries
        .get(registry)
        .and_then(|e| e.identity_token.clone())
    {
        return Some(ProbeCredential::Identity(token));
    }
    let auth = config.get_credentials(registry)?;
    if auth.username == "token" {
        // Legacy direct-bearer convention: the password IS the bearer.
        Some(ProbeCredential::Bearer(auth.password))
    } else {
        Some(ProbeCredential::Basic {
            username: auth.username,
            password: auth.password,
        })
    }
}

/// Find a credential for `registry`, preferring the `machines` section but
/// falling back to `images`.
///
/// The two sections exist because a `.smolmachine` artifact registry and a
/// container-image registry are usually different things. But ONE host can
/// serve both — ours does — and a reference alone doesn't say which it is; the
/// probe is what finds out. Consulting only `machines` means a user who logged
/// in for image pulls gets an unauthenticated probe, a 401, and a fall-through
/// to the in-guest pull, whose failure names nothing useful. Both sections are
/// the same user's credentials for the same host they typed, so trying the
/// other one crosses no trust boundary — it only removes a trap where a
/// credential the user has already provided goes unused.
fn configured_credential(
    settings: &crate::settings::SmolSettings,
    registry: &str,
) -> Option<ProbeCredential> {
    configured_credential_with(settings, registry, docker_credential)
}

/// [`configured_credential`] with the host Docker lookup injected, so tests
/// stay independent of whatever `docker login` left on the machine.
fn configured_credential_with(
    settings: &crate::settings::SmolSettings,
    registry: &str,
    docker: impl Fn(&str) -> Option<ProbeCredential>,
) -> Option<ProbeCredential> {
    credential_from(&settings.machines, registry)
        .or_else(|| credential_from(&settings.images, registry))
        .or_else(|| docker(registry))
}

/// The credential `docker login` stored for `registry` on this host, when
/// smolvm's own config has none. Identity tokens need an OAuth exchange the
/// probe client does not implement, so they are left to the in-guest pull.
fn docker_credential(registry: &str) -> Option<ProbeCredential> {
    let cred = crate::docker_config::credential_for(registry)?;
    if cred.is_identity_token() {
        return None;
    }
    Some(ProbeCredential::Basic {
        username: cred.username,
        password: cred.secret,
    })
}

/// Whether a registry error means "you are not authorized" rather than
/// "something went wrong". These are the failures a missing or unscoped pull
/// credential produces, and the only ones worth shouting about when the probe
/// falls back — every other failure really is best-effort noise.
fn is_auth_denial(err: &smolvm_registry::RegistryError) -> bool {
    matches!(
        err,
        smolvm_registry::RegistryError::Authentication { .. }
            | smolvm_registry::RegistryError::ApiError {
                status: 401 | 403,
                ..
            }
    )
}

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
    } else if let Some(cred) = configured_credential(&settings, effective_registry) {
        // A configured mirror is a different endpoint: never send the source
        // registry's saved credentials to its mirror during the pack probe.
        client = cred.apply(client);
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
            //
            // An AUTH denial is logged loudly rather than at debug. It means the
            // probe held no usable credential for this repository, and the
            // in-guest puller resolves credentials from a DIFFERENT settings
            // section (`images` vs `machines`) — so it may or may not have one.
            // When it doesn't, the customer's only symptom is an opaque
            // `crane manifest failed: ... 401` with no hint that the real cause
            // was a missing pull token. Naming it here is the difference between
            // a one-line diagnosis and an outage investigation.
            if is_auth_denial(&e) {
                tracing::warn!(
                    image = %image,
                    error = %e,
                    "registry denied the pack probe: no usable credential for this \
                     repository. Falling back to the in-guest pull, which will fail \
                     the same way unless it has separate credentials configured."
                );
            } else {
                tracing::debug!(image = %image, error = %e, "pack probe failed; using in-guest pull");
            }
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

    /// Build a settings object with a direct-bearer credential for `registry`
    /// in whichever section the caller names.
    fn settings_with_credential(
        section: fn(&mut crate::settings::SmolSettings) -> &mut crate::registry::RegistryConfig,
        registry: &str,
        password: &str,
    ) -> crate::settings::SmolSettings {
        let mut settings = crate::settings::SmolSettings::default();
        let entry = crate::registry::RegistryEntry {
            username: Some("token".to_string()),
            password: Some(password.to_string()),
            ..Default::default()
        };
        section(&mut settings)
            .registries
            .insert(registry.to_string(), entry);
        settings
    }

    #[test]
    fn a_probe_credential_falls_back_to_the_image_section() {
        const REG: &str = "registry.smolmachines.com";

        // Configured under `machines` — the section a pack probe expects.
        let s = settings_with_credential(|s| &mut s.machines, REG, "from-machines");
        assert!(matches!(
            configured_credential_with(&s, REG, |_| None),
            Some(ProbeCredential::Bearer(t)) if t == "from-machines"
        ));

        // Configured only under `images`. One host can serve both artifact
        // kinds, and the user already gave us a credential for it — using it
        // beats an anonymous probe that 401s and fails over to an error message
        // naming nothing useful.
        let s = settings_with_credential(|s| &mut s.images, REG, "from-images");
        assert!(matches!(
            configured_credential_with(&s, REG, |_| None),
            Some(ProbeCredential::Bearer(t)) if t == "from-images"
        ));

        // `machines` still wins when both are present.
        let mut s = settings_with_credential(|s| &mut s.machines, REG, "from-machines");
        s.images.registries.insert(
            REG.to_string(),
            crate::registry::RegistryEntry {
                username: Some("token".to_string()),
                password: Some("from-images".to_string()),
                ..Default::default()
            },
        );
        assert!(matches!(
            configured_credential_with(&s, REG, |_| None),
            Some(ProbeCredential::Bearer(t)) if t == "from-machines"
        ));
    }

    #[test]
    fn a_mirrored_pack_probe_only_uses_the_destination_credential() {
        let source = "origin.example.invalid";
        let mirror = "mirror.example.invalid";
        let mut settings = settings_with_credential(|s| &mut s.machines, source, "source-secret");
        settings.machines.registries.get_mut(source).unwrap().mirror = Some(mirror.into());
        settings.machines.registries.insert(
            mirror.into(),
            crate::registry::RegistryEntry {
                username: Some("token".into()),
                password: Some("mirror-secret".into()),
                ..Default::default()
            },
        );
        let effective = settings
            .machines
            .get_mirror(source)
            .unwrap_or(source)
            .to_string();
        assert!(matches!(
            configured_credential_with(&settings, &effective, |_| None),
            Some(ProbeCredential::Bearer(t)) if t == "mirror-secret"
        ));
        settings.machines.registries.remove(mirror);
        assert!(configured_credential_with(&settings, &effective, |_| None).is_none());
    }

    #[test]
    fn a_credential_is_never_borrowed_across_registries() {
        // The fallback crosses SECTIONS, never HOSTS: a credential for one
        // registry must not be presented to a different one.
        let s = settings_with_credential(|s| &mut s.images, "ghcr.io", "ghcr-secret");
        assert!(configured_credential_with(&s, "registry.smolmachines.com", |_| None).is_none());
        assert!(configured_credential_with(&s, "docker.io", |_| None).is_none());
        assert!(configured_credential_with(&s, "ghcr.io", |_| None).is_some());
    }

    #[test]
    fn docker_credentials_are_the_last_resort_and_host_scoped() {
        let s = settings_with_credential(|s| &mut s.images, "ghcr.io", "ghcr-secret");
        let docker = |registry: &str| {
            (registry == "docker.io").then(|| ProbeCredential::Basic {
                username: "hub-user".into(),
                password: "hub-secret".into(),
            })
        };
        // smolvm's own config wins for the registry it names…
        assert!(matches!(
            configured_credential_with(&s, "ghcr.io", docker),
            Some(ProbeCredential::Bearer(t)) if t == "ghcr-secret"
        ));
        // …Docker's credential covers a registry smolvm has nothing for…
        assert!(matches!(
            configured_credential_with(&s, "docker.io", docker),
            Some(ProbeCredential::Basic { username, .. }) if username == "hub-user"
        ));
        // …and neither leaks to a registry nobody has logged in to.
        assert!(configured_credential_with(&s, "registry.smolmachines.com", docker).is_none());
    }

    #[test]
    fn auth_denials_are_distinguished_from_ordinary_probe_failures() {
        use smolvm_registry::RegistryError;

        // A missing/unscoped credential — the case worth warning about.
        assert!(is_auth_denial(&RegistryError::Authentication {
            message: "no token".into()
        }));
        assert!(is_auth_denial(&RegistryError::ApiError {
            status: 401,
            body: "UNAUTHORIZED".into()
        }));
        assert!(is_auth_denial(&RegistryError::ApiError {
            status: 403,
            body: "DENIED".into()
        }));

        // Ordinary best-effort noise stays at debug: a 404 means the ref really
        // isn't there, and a 500 means the registry is unwell — neither implies
        // a credential problem.
        assert!(!is_auth_denial(&RegistryError::ApiError {
            status: 404,
            body: "NAME_UNKNOWN".into()
        }));
        assert!(!is_auth_denial(&RegistryError::ApiError {
            status: 500,
            body: "boom".into()
        }));
        assert!(!is_auth_denial(&RegistryError::InvalidManifest(
            "garbage".into()
        )));
    }

    /// Sentinel the tests hand in as the minted pull token, so the stub can tell
    /// an authenticated probe from an anonymous one by content rather than by
    /// the mere presence of an `Authorization` header (the client always ends up
    /// sending SOME bearer once it has danced with the token realm).
    const TEST_IDENTITY_TOKEN: &str = "minted-pull-token-sentinel";

    /// Stub of the smolmachines registry + its token service, wired the way prod
    /// is: a private repo 401s with a `WWW-Authenticate` challenge, and the realm
    /// it advertises points back at this same stub (so the probe never leaves the
    /// test). The token service always issues a token; the registry always 401s,
    /// modelling a repo the caller has no grant for.
    ///
    /// Returns the bound address, plus flags for "a request arrived" and "the
    /// identity token reached the token service".
    async fn stub_private_registry() -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let saw_request = Arc::new(AtomicBool::new(false));
        let saw_identity_token = Arc::new(AtomicBool::new(false));
        let (req, ident, realm) = (
            saw_request.clone(),
            saw_identity_token.clone(),
            addr.clone(),
        );

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (req, ident, realm) = (req.clone(), ident.clone(), realm.clone());
                tokio::spawn(async move {
                    // reqwest keeps the connection alive, so serve in a loop.
                    loop {
                        let mut buf = [0u8; 8192];
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        let head = String::from_utf8_lossy(&buf[..n]).to_string();
                        req.store(true, Ordering::SeqCst);
                        if head.contains(TEST_IDENTITY_TOKEN) {
                            ident.store(true, Ordering::SeqCst);
                        }

                        let resp = if head.starts_with("GET /v2/auth") {
                            let body = r#"{"access_token":"stub-access","token":"stub-access"}"#;
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                                 content-length: {}\r\n\r\n{body}",
                                body.len()
                            )
                        } else {
                            // The shape prod returns for a private repo, with the
                            // realm pointed back at this stub.
                            let body =
                                r#"{"code":"UNAUTHORIZED","message":"authentication required"}"#;
                            format!(
                                "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\n\
                                 www-authenticate: Bearer realm=\"http://{realm}/v2/auth\",service=\"{realm}\"\r\n\
                                 content-length: {}\r\n\r\n{body}",
                                body.len()
                            )
                        };
                        if sock.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        (addr, saw_request, saw_identity_token)
    }

    /// Regression guard for the outage that blocked a tenant's private packs:
    /// with no identity token the probe goes out ANONYMOUS, the registry
    /// correctly 401s, and the probe reports "not a pack" — handing a private
    /// `.smolmachine` to the in-guest OCI puller, which has no credentials
    /// either and dies with an opaque `crane manifest failed: ... 401`.
    ///
    /// The fail-open is right for third-party registries (a 401 there really
    /// does mean "I can't tell, let the in-guest puller try"), so this test
    /// pins the CURRENT behavior as the thing a fix must change deliberately.
    #[tokio::test]
    async fn an_unauthorized_probe_is_swallowed_as_not_a_pack() {
        use std::sync::atomic::Ordering;

        let (addr, saw_request, saw_identity_token) = stub_private_registry().await;
        let image = format!("{addr}/tenants/tenant-abc/e2smoke:v1");

        let resolved = resolve_pack_ref(&image, None, &[]).await.unwrap();

        assert!(
            saw_request.load(Ordering::SeqCst),
            "the probe must actually reach the registry, else this proves nothing"
        );
        assert!(
            !saw_identity_token.load(Ordering::SeqCst),
            "no token was supplied, so nothing tenant-scoped went to the token service"
        );
        assert_eq!(
            resolved, None,
            "the 401 is swallowed as 'not a pack' and the caller falls through to \
             the in-guest pull — which is where the opaque crane 401 comes from"
        );
    }

    /// The other half: a supplied identity token DOES reach the token service.
    /// The engine side was never the blocker — the control plane simply never
    /// minted a token for an `image`-typed source.
    #[tokio::test]
    async fn a_supplied_identity_token_reaches_the_token_service() {
        use std::sync::atomic::Ordering;

        let (addr, saw_request, saw_identity_token) = stub_private_registry().await;
        let image = format!("{addr}/tenants/tenant-abc/e2smoke:v1");

        let _ = resolve_pack_ref(&image, Some(TEST_IDENTITY_TOKEN), &[]).await;

        assert!(saw_request.load(Ordering::SeqCst));
        assert!(
            saw_identity_token.load(Ordering::SeqCst),
            "a supplied identity token must be exchanged at the token service"
        );
    }
}
