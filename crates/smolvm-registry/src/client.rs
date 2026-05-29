//! OCI Distribution Spec HTTP client.
//!
//! Implements the subset of the OCI Distribution Spec needed for
//! single-blob artifact push and pull:
//! - Blob existence check (HEAD)
//! - Monolithic blob upload (POST + PUT)
//! - Blob download (GET)
//! - Manifest put/get (PUT/GET)

use crate::{RegistryError, Result, MANIFEST_MEDIA_TYPE};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Validate that a digest string matches the expected `sha256:<64 hex chars>` format.
pub(crate) fn validate_digest(digest: &str) -> Result<()> {
    if let Some(hex_part) = digest.strip_prefix("sha256:") {
        if hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(());
        }
    }
    Err(RegistryError::InvalidManifest(format!(
        "invalid digest format: {digest}"
    )))
}

/// HTTP client for an OCI Distribution registry.
pub struct RegistryClient {
    http: reqwest::Client,
    /// Base URL including scheme (e.g., "http://localhost:5000" or "https://registry.smolmachines.com").
    base_url: String,
    /// Optional Bearer token sent directly to the registry for authenticated requests.
    auth_token: Option<String>,
    /// Optional identity token exchanged with a registry token service after
    /// a `WWW-Authenticate: Bearer ...` challenge.
    /// Used for smolmachines registries (Auth0 JWT → token service → OCI bearer).
    identity_token: Option<String>,
    /// Optional Basic credentials (username, password) exchanged with the registry's
    /// own auth service after a `WWW-Authenticate: Bearer ...` challenge.
    /// Used for Docker Hub, GHCR, ECR, GCR, and any standard OCI registry.
    basic_credentials: Option<(String, String)>,
    token_cache: Mutex<HashMap<TokenCacheKey, CachedToken>>,
    /// The most recent Bearer challenge received from this registry.
    ///
    /// Stored after each successful challenge exchange so that subsequent
    /// requests can attach a preemptive bearer token (cache hit → no 401 round
    /// trip). This is especially important for non-replayable streaming uploads,
    /// where a 401 on the PUT body cannot be retried.
    last_challenge: Mutex<Option<BearerChallenge>>,
}

impl RegistryClient {
    /// Create a new client for the given registry base URL.
    pub fn new(base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            auth_token: None,
            identity_token: None,
            basic_credentials: None,
            token_cache: Mutex::new(HashMap::new()),
            last_challenge: Mutex::new(None),
        }
    }

    /// Return the base URL this client is configured for.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the identity token, if one was configured via [`Self::with_identity_token`].
    ///
    /// Useful for inspecting whether the client is in upstream token-exchange mode
    /// (identity token path) vs direct bearer mode.
    pub fn identity_token(&self) -> Option<&str> {
        self.identity_token.as_deref()
    }

    /// Set a Bearer token for authenticated requests.
    pub fn with_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Set an identity token used only to fetch OCI bearer tokens from a
    /// registry token service. This token is not sent directly to the registry.
    pub fn with_identity_token(mut self, token: String) -> Self {
        self.identity_token = Some(token);
        self
    }

    /// Set Basic credentials for standard Docker/OCI registry Bearer challenge auth.
    ///
    /// These credentials are sent to the registry's own token endpoint when the
    /// registry returns `WWW-Authenticate: Bearer ...`. The resulting short-lived
    /// OCI bearer token is then used for the actual registry request.
    ///
    /// This is the standard path for Docker Hub, GHCR, ECR, GCR/Artifact Registry,
    /// ACR, Harbor, Quay, and any OCI-compliant registry.
    pub fn with_basic_credentials(mut self, username: String, password: String) -> Self {
        self.basic_credentials = Some((username, password));
        self
    }

    /// Return the Basic credentials, if configured via [`Self::with_basic_credentials`].
    pub fn basic_credentials(&self) -> Option<(&str, &str)> {
        self.basic_credentials
            .as_ref()
            .map(|(u, p)| (u.as_str(), p.as_str()))
    }

    /// Check connectivity: `GET /v2/` must return 200.
    pub async fn ping(&self) -> Result<()> {
        let url = format!("{}/v2/", self.base_url);
        let resp = self
            .send_replayable(self.request(reqwest::Method::GET, &url))
            .await?;
        if !resp.status().is_success() {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// Check if a blob exists. Returns true if HEAD returns 200.
    pub async fn blob_exists(&self, repo: &str, digest: &str) -> Result<bool> {
        validate_digest(digest)?;
        let url = format!("{}/v2/{}/blobs/{}", self.base_url, repo, digest);
        let resp = self
            .send_replayable(self.request(reqwest::Method::HEAD, &url))
            .await?;
        Ok(resp.status() == reqwest::StatusCode::OK)
    }

    /// Upload a blob using monolithic upload (POST + PUT).
    ///
    /// Returns the sha256 digest of the uploaded blob.
    pub async fn push_blob(&self, repo: &str, data: &[u8]) -> Result<String> {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));

        // Check if already present (skip upload).
        if self.blob_exists(repo, &digest).await? {
            tracing::debug!(digest = %digest, "blob already exists, skipping upload");
            return Ok(digest);
        }

        // Step 1: POST to initiate upload.
        let post_url = format!("{}/v2/{}/blobs/uploads/", self.base_url, repo);
        let resp = self
            .send_replayable(
                self.request(reqwest::Method::POST, &post_url)
                    .header(CONTENT_LENGTH, 0),
            )
            .await?;

        if resp.status() != reqwest::StatusCode::ACCEPTED {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        // Get the upload URL from Location header.
        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| RegistryError::ApiError {
                status: 202,
                body: "upload accepted but missing Location header".into(),
            })?
            .to_string();

        // Resolve Location — validates same-origin for absolute URLs.
        let put_url = self.resolve_location(&location)?;

        // Step 2: PUT the blob data with digest.
        let separator = if put_url.contains('?') { "&" } else { "?" };
        let put_url = format!("{}{}digest={}", put_url, separator, digest);

        let resp = self
            .send_replayable(
                self.request(reqwest::Method::PUT, &put_url)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(CONTENT_LENGTH, data.len())
                    .body(data.to_vec()),
            )
            .await?;

        if resp.status() != reqwest::StatusCode::CREATED {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        Ok(digest)
    }

    /// Download a blob by digest. Returns the raw bytes.
    ///
    /// NOTE: buffers entire blob in memory. For large artifacts, switch to
    /// streaming to disk with digest verification via `AsyncRead`.
    pub async fn pull_blob(&self, repo: &str, digest: &str) -> Result<Vec<u8>> {
        validate_digest(digest)?;
        let url = format!("{}/v2/{}/blobs/{}", self.base_url, repo, digest);
        let resp = self
            .send_replayable(self.request(reqwest::Method::GET, &url))
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::BlobNotFound(digest.to_string()));
        }

        if !resp.status().is_success() {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let data = resp.bytes().await?.to_vec();

        // Verify digest.
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        if actual != digest {
            return Err(RegistryError::DigestMismatch {
                expected: digest.to_string(),
                actual,
            });
        }

        Ok(data)
    }

    /// Upload a blob from a streamed body with a pre-computed digest.
    ///
    /// Unlike `push_blob`, this does not buffer the entire blob in memory.
    /// The caller pre-computes the digest and provides a **body factory** that
    /// can produce a fresh `reqwest::Body` on each call. The factory may be
    /// called up to 3 times (initial attempt + 2 auth retries), so it must be
    /// able to reopen or rewind the source (e.g., reopen the file).
    ///
    /// The PUT request is routed through [`send_nonreplayable`], which guarantees
    /// that a 401 challenge is always handled correctly: the factory produces a
    /// fresh body for each retry, so no data is lost regardless of whether the
    /// preemptive token cache held the right scope.
    pub async fn push_blob_stream<F>(
        &self,
        repo: &str,
        digest: &str,
        size: u64,
        make_body: F,
    ) -> Result<()>
    where
        F: Fn() -> Result<reqwest::Body>,
    {
        validate_digest(digest)?;

        // Skip if already present.
        if self.blob_exists(repo, digest).await? {
            tracing::debug!(digest = %digest, "blob already exists, skipping upload");
            return Ok(());
        }

        // Step 1: POST to initiate upload (empty body — always replayable).
        let post_url = format!("{}/v2/{}/blobs/uploads/", self.base_url, repo);
        let resp = self
            .send_replayable(
                self.request(reqwest::Method::POST, &post_url)
                    .header(CONTENT_LENGTH, 0),
            )
            .await?;

        if resp.status() != reqwest::StatusCode::ACCEPTED {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| RegistryError::ApiError {
                status: 202,
                body: "upload accepted but missing Location header".into(),
            })?
            .to_string();

        // Resolve Location — validates same origin for absolute URLs.
        let put_url = self.resolve_location(&location)?;
        let separator = if put_url.contains('?') { "&" } else { "?" };
        let put_url = format!("{}{}digest={}", put_url, separator, digest);

        // Step 2: PUT with streaming body via factory.
        // Content-Length is set explicitly — reqwest defaults to chunked transfer
        // encoding for streamed bodies, which some registries reject.
        // The factory is called once per attempt (preemptive + up to 2 retries).
        let base_req = self
            .request(reqwest::Method::PUT, &put_url)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, size);

        let resp = self.send_nonreplayable(base_req, make_body).await?;

        if resp.status() != reqwest::StatusCode::CREATED {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        Ok(())
    }

    /// Download a blob as a byte stream.
    ///
    /// Returns the stream after verifying the response status. The caller is
    /// responsible for digest verification (hash while writing to disk).
    pub async fn pull_blob_stream(
        &self,
        repo: &str,
        digest: &str,
    ) -> Result<impl futures_util::Stream<Item = reqwest::Result<bytes::Bytes>>> {
        validate_digest(digest)?;
        let url = format!("{}/v2/{}/blobs/{}", self.base_url, repo, digest);
        let resp = self
            .send_replayable(self.request(reqwest::Method::GET, &url))
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::BlobNotFound(digest.to_string()));
        }

        if !resp.status().is_success() {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        Ok(resp.bytes_stream())
    }

    /// Upload a manifest for the given reference (tag or digest).
    pub async fn put_manifest(&self, repo: &str, reference: &str, manifest: &[u8]) -> Result<()> {
        let url = format!("{}/v2/{}/manifests/{}", self.base_url, repo, reference);
        let resp = self
            .send_replayable(
                self.request(reqwest::Method::PUT, &url)
                    .header(CONTENT_TYPE, MANIFEST_MEDIA_TYPE)
                    .body(manifest.to_vec()),
            )
            .await?;

        if !resp.status().is_success() {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// Fetch a manifest by reference (tag or digest).
    pub async fn get_manifest(&self, repo: &str, reference: &str) -> Result<Vec<u8>> {
        let url = format!("{}/v2/{}/manifests/{}", self.base_url, repo, reference);
        let resp = self
            .send_replayable(
                self.request(reqwest::Method::GET, &url)
                    .header(ACCEPT, MANIFEST_MEDIA_TYPE),
            )
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::BlobNotFound(format!(
                "{}:{}",
                repo, reference
            )));
        }

        if !resp.status().is_success() {
            return Err(RegistryError::ApiError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        // Detect OCI image indexes and Docker manifest lists — smolvm artifacts are
        // always single-manifest; an index means the caller referenced a multi-arch
        // Docker image rather than a .smolmachine artifact.
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if content_type.contains("application/vnd.oci.image.index.v1+json")
            || content_type.contains("application/vnd.docker.distribution.manifest.list.v2+json")
        {
            return Err(RegistryError::InvalidManifest(
                "OCI image indexes (multi-arch manifests) are not supported; \
                 this reference points to a Docker image, not a .smolmachine artifact"
                    .into(),
            ));
        }

        Ok(resp.bytes().await?.to_vec())
    }

    /// Resolve a Location header value against the registry base URL.
    ///
    /// Relative paths (with or without a leading `/`) are resolved via
    /// `Url::join`. Absolute `http(s)://` URLs are parsed and checked against
    /// the base origin (scheme + host + port).
    ///
    /// Cross-origin upload locations are rejected. Registries that return signed
    /// storage URLs (S3, GCS) would need an explicit policy allowance here.
    fn resolve_location(&self, location: &str) -> Result<String> {
        let base = reqwest::Url::parse(&self.base_url).map_err(|e| RegistryError::ApiError {
            status: 202,
            body: format!("client base URL is not valid: {e}"),
        })?;

        let resolved = if location.starts_with("http://") || location.starts_with("https://") {
            reqwest::Url::parse(location).map_err(|e| RegistryError::ApiError {
                status: 202,
                body: format!("Location is not a valid URL '{location}': {e}"),
            })?
        } else {
            // Relative path (with or without leading slash): join against base.
            base.join(location).map_err(|e| RegistryError::ApiError {
                status: 202,
                body: format!("Location is not a valid relative path '{location}': {e}"),
            })?
        };

        // Enforce same-origin (scheme + host + port).
        if resolved.origin() != base.origin() {
            return Err(RegistryError::ApiError {
                status: 202,
                body: format!(
                    "Location points to a different origin ('{}'), expected '{}'",
                    resolved.origin().unicode_serialization(),
                    base.origin().unicode_serialization(),
                ),
            });
        }

        Ok(resolved.to_string())
    }

    /// Extract the registry hostname from `base_url` (strips scheme).
    ///
    /// `"https://registry-1.docker.io"` → `"registry-1.docker.io"`
    fn registry_host(&self) -> &str {
        self.base_url.split("//").nth(1).unwrap_or(&self.base_url)
    }

    /// Build a request with optional auth header.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }
        req
    }

    /// Send a cloneable (replayable) request through the full OCI auth protocol.
    ///
    /// Use this for requests whose body can be replayed (GET, HEAD, POST with
    /// empty body, PUT with a buffered `Vec<u8>`). For streaming bodies that
    /// cannot be cloned, use [`send_nonreplayable`] with a body factory instead.
    ///
    /// Protocol steps:
    ///  1. Attach a preemptive bearer from the `last_challenge` cache if available
    ///     (optimization — skips the 401 round trip for warm-cache requests).
    ///  2. Send; if not 401, return immediately.
    ///  3. Parse `WWW-Authenticate`; exchange credentials for a token
    ///     (`get_token(false)` — returns cached token if still valid).
    ///  4. First retry with that token (uses the pre-cloned builder).
    ///  5. If still 401: force-evict the cache entry, fetch a genuinely fresh
    ///     token (`get_token(true)`), second retry.
    ///  6. No third attempt — a freshly-fetched token that is also rejected means
    ///     the credentials themselves are wrong.
    async fn send_replayable(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        // Clone BEFORE applying the preemptive bearer so that retry clones
        // start clean. If we cloned after bearer_auth, every subsequent
        // `.bearer_auth(new_token)` call would produce a doubled Authorization
        // header ("Bearer stale, Bearer fresh"), which breaks header matching.
        let first_retry = req.try_clone();
        let second_retry = req.try_clone();

        // Step 1: attach a preemptive bearer to the initial send only.
        // A valid cached token skips the 401 round trip — especially important
        // for non-replayable streaming PUT bodies that cannot be replayed.
        let initial_req = if let Some(token) = self.preemptive_token() {
            req.bearer_auth(token)
        } else {
            req
        };

        // Step 2: send.
        let resp = initial_req.send().await?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // If we already have a static bearer, the registry is rejecting the token
        // itself — no challenge exchange will help.
        if self.auth_token.is_some() {
            return Ok(resp);
        }

        let Some(www_auth) = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(resp);
        };

        let challenge = BearerChallenge::parse(www_auth)?;

        // Steps 3–4: exchange credentials → first retry.
        let token = self.get_token(&challenge, false).await?;
        let first_retry = first_retry.ok_or_else(|| RegistryError::Authentication {
            message: "registry challenged a non-replayable request; \
                      ensure credentials are warm before streaming uploads"
                .into(),
        })?;
        let resp = first_retry.bearer_auth(token).send().await?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // Step 5: force-evict and fetch a genuinely fresh token → second retry.
        let token = self.get_token(&challenge, true).await?;
        let second_retry = second_retry.ok_or_else(|| RegistryError::Authentication {
            message: "registry challenged a non-replayable request on second attempt".into(),
        })?;
        Ok(second_retry.bearer_auth(token).send().await?)
    }

    /// Send a non-replayable request (e.g., a streaming PUT body) with full auth retry support.
    ///
    /// Unlike [`send_replayable`], this method does not rely on `try_clone()` of a
    /// pre-built body. Instead, the caller supplies a **factory** that produces a
    /// fresh `reqwest::Body` on each call. The factory may be invoked up to 3 times.
    ///
    /// Protocol steps:
    ///  1. Attach a preemptive bearer from `last_challenge` cache if available
    ///     (optimization for the common warm-cache case; may have wrong scope).
    ///  2. Call factory for a fresh body; send.
    ///  3. On 401: parse the challenge from *this specific request* (correct scope),
    ///     fetch/cache a token, call factory again, retry.
    ///  4. On second 401: force-evict the cache entry, fresh token, factory again, final retry.
    ///
    /// Correctness is guaranteed by the challenge from step 3, not by the preemptive
    /// hint from step 1. A wrong-scope preemptive token just costs one extra round trip.
    async fn send_nonreplayable<F>(
        &self,
        req: reqwest::RequestBuilder,
        make_body: F,
    ) -> Result<reqwest::Response>
    where
        F: Fn() -> Result<reqwest::Body>,
    {
        // Clone the body-less base builder for retries before attaching auth or body.
        // try_clone() returns None only for builders that already hold a non-replayable
        // streaming body — callers of send_nonreplayable must not pre-attach a body.
        let clone_err = || RegistryError::Authentication {
            message: "send_nonreplayable called with a non-cloneable request builder; \
                      attach the body via the factory, not before calling this method"
                .into(),
        };
        let retry1 = req.try_clone().ok_or_else(clone_err)?;
        let retry2 = req.try_clone().ok_or_else(clone_err)?;

        // Step 1: attach preemptive bearer (optimization — wrong scope → extra 401, not corruption).
        let initial = if let Some(token) = self.preemptive_token() {
            req.bearer_auth(token)
        } else {
            req
        };

        // Step 2: send with a fresh body from the factory.
        let resp = initial.body(make_body()?).send().await?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // Static auth_token rejected — challenge exchange won't help.
        if self.auth_token.is_some() {
            return Ok(resp);
        }

        let Some(www_auth) = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(resp);
        };

        let challenge = BearerChallenge::parse(www_auth)?;

        // Step 3: token for the scope this request actually needs, fresh body.
        let token = self.get_token(&challenge, false).await?;
        let resp = retry1.bearer_auth(token).body(make_body()?).send().await?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // Step 4: force-evict stale cache entry, genuinely fresh token, final body.
        let token = self.get_token(&challenge, true).await?;
        Ok(retry2.bearer_auth(token).body(make_body()?).send().await?)
    }

    /// Fetch (or return a cached) OCI bearer token for the given challenge.
    ///
    /// If `force_refresh` is true the cache entry for this challenge is evicted
    /// first, guaranteeing a fresh token from the token service. This is used
    /// on the second 401 retry, when a cached token has just proven invalid.
    async fn get_token(&self, challenge: &BearerChallenge, force_refresh: bool) -> Result<String> {
        let key = TokenCacheKey {
            realm: challenge.realm.clone(),
            service: challenge.service.clone(),
            scope: challenge.scope.clone(),
        };

        {
            let mut cache = self
                .token_cache
                .lock()
                .map_err(|_| RegistryError::Authentication {
                    message: "registry token cache lock poisoned".into(),
                })?;
            if force_refresh {
                cache.remove(&key);
            } else if let Some(cached) = cache.get(&key) {
                if cached.is_valid() {
                    return Ok(cached.token.clone());
                }
                // Stale entry — fall through to fetch a fresh token.
            }
        }

        let mut url =
            reqwest::Url::parse(&challenge.realm).map_err(|e| RegistryError::Authentication {
                message: format!("invalid token service realm: {e}"),
            })?;
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(service) = &challenge.service {
                pairs.append_pair("service", service);
            }
            if let Some(scope) = &challenge.scope {
                pairs.append_pair("scope", scope);
            }
        }

        let req = self.http.get(url.clone());
        let resp = if let Some(identity_token) = &self.identity_token {
            // smolmachines path: upstream JWT exchanged with the token service.
            req.bearer_auth(identity_token).send().await?
        } else if let Some((username, password)) = &self.basic_credentials {
            // Standard Docker/OCI path: Basic credentials sent to the registry's
            // own auth service.
            //
            // Security checks before sending the PAT:
            // 1. HTTPS-only: never send credentials to a plaintext endpoint.
            // 2. Realm host allowlist for known registries: a compromised registry
            //    could serve a valid HTTPS WWW-Authenticate challenge pointing to an
            //    attacker-controlled token service. For known registries we verify the
            //    realm host matches the expected auth service.
            if url.scheme() != "https" {
                return Err(RegistryError::Authentication {
                    message: format!(
                        "refusing Basic credentials for non-HTTPS realm: {}",
                        url.as_str()
                    ),
                });
            }
            validate_realm_host(self.registry_host(), &url)?;
            req.basic_auth(username, Some(password)).send().await?
        } else {
            // Anonymous token request — works for public repositories.
            req.send().await?
        };

        if !resp.status().is_success() {
            return Err(RegistryError::Authentication {
                message: format!(
                    "token service returned {}: {}",
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                ),
            });
        }

        let token_response: TokenResponse = resp.json().await?;
        let token = token_response
            .token
            .or(token_response.access_token)
            .ok_or_else(|| RegistryError::Authentication {
                message: "token service response did not include token".into(),
            })?;

        // Store the raw server-reported expiry. The 30-second safety buffer
        // is applied only in `CachedToken::is_valid()`, not here, so that
        // short-lived tokens (< 30 s) are immediately stale rather than
        // producing expires_at = None (which means "valid forever").
        let expires_at = token_response
            .expires_in
            .map(|secs| Instant::now() + Duration::from_secs(secs));

        self.token_cache
            .lock()
            .map_err(|_| RegistryError::Authentication {
                message: "registry token cache lock poisoned".into(),
            })?
            .insert(
                key,
                CachedToken {
                    token: token.clone(),
                    expires_at,
                },
            );

        // Record the challenge so future requests can attach a preemptive bearer
        // token without waiting for a 401 round trip (especially important for
        // non-replayable streaming uploads).
        if let Ok(mut lc) = self.last_challenge.lock() {
            *lc = Some(challenge.clone());
        }

        Ok(token)
    }

    /// Return a valid cached bearer token from the most recent challenge exchange,
    /// or `None` if the cache is empty, the entry is stale, or `auth_token` is set
    /// (in which case `request()` already attaches the static bearer).
    ///
    /// Called at the top of `send_replayable()` to skip the 401 round trip for
    /// authenticated operations — particularly important for streaming PUT bodies
    /// that cannot be retried after a 401.
    fn preemptive_token(&self) -> Option<String> {
        // Static auth_token is always attached by request() — no preemptive needed.
        if self.auth_token.is_some() {
            return None;
        }
        let challenge = self.last_challenge.lock().ok()?.as_ref()?.clone();
        let cache = self.token_cache.lock().ok()?;
        let key = TokenCacheKey {
            realm: challenge.realm,
            service: challenge.service,
            scope: challenge.scope,
        };
        let cached = cache.get(&key)?;
        if cached.is_valid() {
            Some(cached.token.clone())
        } else {
            None
        }
    }
}

/// Validate the realm host against an allowlist of known registries.
///
/// For registries whose auth host is well-known, a compromised registry could
/// send a valid HTTPS `WWW-Authenticate` challenge pointing to an attacker's
/// token service. This check prevents PAT exfiltration in that scenario.
///
/// Unknown registries are not checked — we cannot enumerate every self-hosted
/// registry's auth topology. The HTTPS-only guard in the caller handles those.
fn validate_realm_host(registry_host: &str, realm_url: &reqwest::Url) -> Result<()> {
    let realm_host = realm_url.host_str().unwrap_or("");

    // Map known registry API hosts to their expected auth service host.
    let expected_auth_host: Option<&str> = match registry_host {
        "registry-1.docker.io" => Some("auth.docker.io"),
        "ghcr.io" => Some("ghcr.io"),
        "quay.io" => Some("quay.io"),
        // ECR: auth endpoint is on *.amazonaws.com — allow any amazonaws.com subdomain.
        h if h.ends_with(".amazonaws.com") => {
            if realm_host.ends_with(".amazonaws.com") {
                return Ok(());
            }
            return Err(RegistryError::Authentication {
                message: format!(
                    "ECR realm host '{realm_host}' is not on amazonaws.com (registry: {registry_host})"
                ),
            });
        }
        // GCR / Artifact Registry: auth is on oauth2.googleapis.com or the same host.
        h if h == "gcr.io" || h.ends_with(".gcr.io") || h.ends_with(".pkg.dev") => {
            if realm_host == "oauth2.googleapis.com"
                || realm_host.ends_with(".gcr.io")
                || realm_host.ends_with(".pkg.dev")
            {
                return Ok(());
            }
            return Err(RegistryError::Authentication {
                message: format!(
                    "GCR realm host '{realm_host}' is not on googleapis.com or gcr.io (registry: {registry_host})"
                ),
            });
        }
        _ => None,
    };

    if let Some(expected) = expected_auth_host {
        if realm_host != expected {
            return Err(RegistryError::Authentication {
                message: format!(
                    "realm host '{realm_host}' does not match expected auth host '{expected}' for registry '{registry_host}'"
                ),
            });
        }
    }

    Ok(())
}

/// A cached OCI bearer token with optional expiry.
///
/// `expires_at` is stored as the raw server-reported expiry (`now + expires_in`).
/// The 30-second safety buffer lives exclusively in `is_valid()`, so short-lived
/// tokens (< 30 s) are immediately considered stale rather than being cached
/// with `expires_at = None` (which would incorrectly mean "valid forever").
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Option<Instant>,
}

impl CachedToken {
    /// Returns `true` if the token is still usable (at least 30 s remain).
    fn is_valid(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(exp) => Instant::now() + Duration::from_secs(30) < exp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TokenCacheKey {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

impl BearerChallenge {
    fn parse(header: &str) -> Result<Self> {
        let header = header.trim();
        let params = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or_else(|| RegistryError::Authentication {
                message: format!("unsupported authenticate challenge: {header}"),
            })?;

        let mut values = HashMap::new();
        for part in split_auth_params(params) {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            values.insert(key.trim().to_ascii_lowercase(), unquote(value.trim()));
        }

        let realm = values
            .remove("realm")
            .ok_or_else(|| RegistryError::Authentication {
                message: "bearer challenge missing realm".into(),
            })?;

        Ok(Self {
            realm,
            service: values.remove("service"),
            scope: values.remove("scope"),
        })
    }
}

fn split_auth_params(params: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;

    for (idx, ch) in params.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quote => escaped = true,
            '"' => in_quote = !in_quote,
            ',' if !in_quote => {
                parts.push(params[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(params[start..].trim());
    parts
}

fn unquote(value: &str) -> String {
    let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return value.to_string();
    };

    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    out
}

#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    /// Token lifetime in seconds, as returned by the token service.
    /// Used to populate `CachedToken::expires_at` with a 30-second safety buffer.
    expires_in: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_digest_accepts_valid_sha256() {
        let valid = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(validate_digest(valid).is_ok());
        // Uppercase hex is also accepted
        let upper = "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(validate_digest(upper).is_ok());
    }

    #[test]
    fn validate_digest_rejects_invalid() {
        // Wrong/missing prefix
        assert!(validate_digest("").is_err());
        assert!(validate_digest("sha256:").is_err());
        assert!(validate_digest(
            "sha512:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )
        .is_err());
        assert!(validate_digest(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )
        .is_err());
        // Wrong length
        assert!(validate_digest("sha256:abcdef").is_err());
        assert!(validate_digest(
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890"
        )
        .is_err());
        // Non-hex chars
        assert!(validate_digest(
            "sha256:gggggg0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )
        .is_err());
    }

    fn client(base: &str) -> RegistryClient {
        RegistryClient::new(base.to_string())
    }

    #[test]
    fn resolve_location_allows_relative_and_same_host() {
        let c = client("https://registry.example.com");
        // Relative path
        let r = c
            .resolve_location("/v2/repo/blobs/uploads/abc?state=xyz")
            .unwrap();
        assert_eq!(
            r,
            "https://registry.example.com/v2/repo/blobs/uploads/abc?state=xyz"
        );
        // Absolute same host
        let r = c
            .resolve_location("https://registry.example.com/v2/uploads/abc")
            .unwrap();
        assert_eq!(r, "https://registry.example.com/v2/uploads/abc");
        // Absolute same host with port
        let c2 = client("http://localhost:5050");
        let r = c2
            .resolve_location("http://localhost:5050/v2/uploads/xyz")
            .unwrap();
        assert_eq!(r, "http://localhost:5050/v2/uploads/xyz");
    }

    #[test]
    fn resolve_location_blocks_different_host() {
        let c = client("https://registry.example.com");
        // Different host
        assert!(c
            .resolve_location("https://evil.attacker.com/steal-data")
            .is_err());
        // Same host but different port (different origin)
        let c2 = client("http://localhost:5050");
        assert!(c2
            .resolve_location("http://localhost:9999/v2/uploads/xyz")
            .is_err());
    }

    #[test]
    fn client_auth_token() {
        let c = RegistryClient::new("https://r.example.com".to_string());
        assert!(c.auth_token.is_none());
        let c = c.with_token("secret".to_string());
        assert_eq!(c.auth_token.as_deref(), Some("secret"));
    }

    #[test]
    fn client_identity_token_accessor() {
        let c = RegistryClient::new("https://registry.smolmachines.com".to_string());
        assert!(c.identity_token().is_none());
        let c = c.with_identity_token("eyJhbG".to_string());
        assert_eq!(c.identity_token(), Some("eyJhbG"));
    }

    #[test]
    fn client_basic_credentials_accessor() {
        let c = RegistryClient::new("https://registry-1.docker.io".to_string());
        assert!(c.basic_credentials().is_none());
        let c = c.with_basic_credentials("alice".to_string(), "ghp_secret".to_string());
        assert_eq!(c.basic_credentials(), Some(("alice", "ghp_secret")));
    }

    #[test]
    fn client_credential_modes_are_independent() {
        // identity_token and basic_credentials are separate fields; setting one
        // does not affect the other.
        let c = RegistryClient::new("https://r.example.com".to_string())
            .with_identity_token("jwt".to_string());
        assert_eq!(c.identity_token(), Some("jwt"));
        assert!(c.basic_credentials().is_none());

        let c = RegistryClient::new("https://r.example.com".to_string())
            .with_basic_credentials("user".to_string(), "pass".to_string());
        assert!(c.identity_token().is_none());
        assert_eq!(c.basic_credentials(), Some(("user", "pass")));
    }

    #[test]
    fn bearer_challenge_parses_registry_params() {
        let challenge = BearerChallenge::parse(
            r#"Bearer realm="https://token.smolmachines.com/v2/auth",service="registry.smolmachines.com",scope="repository:binsquare/app:pull,push""#,
        )
        .unwrap();

        assert_eq!(challenge.realm, "https://token.smolmachines.com/v2/auth");
        assert_eq!(
            challenge.service.as_deref(),
            Some("registry.smolmachines.com")
        );
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:binsquare/app:pull,push")
        );
    }

    #[test]
    fn bearer_challenge_handles_quoted_commas() {
        let parts = split_auth_params(r#"realm="https://t.example/auth",scope="a:b:c,d""#);
        assert_eq!(
            parts,
            vec![r#"realm="https://t.example/auth""#, r#"scope="a:b:c,d""#]
        );
    }

    // ---------------------------------------------------------------------------
    // validate_realm_host
    // ---------------------------------------------------------------------------

    fn url(s: &str) -> reqwest::Url {
        reqwest::Url::parse(s).unwrap()
    }

    #[test]
    fn realm_host_docker_hub_allows_auth_endpoint() {
        assert!(
            validate_realm_host("registry-1.docker.io", &url("https://auth.docker.io/token"))
                .is_ok()
        );
    }

    #[test]
    fn realm_host_docker_hub_rejects_attacker_endpoint() {
        let err = validate_realm_host(
            "registry-1.docker.io",
            &url("https://evil.attacker.com/steal"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("auth.docker.io"), "{err}");
    }

    #[test]
    fn realm_host_ghcr_allows_self() {
        assert!(validate_realm_host("ghcr.io", &url("https://ghcr.io/token")).is_ok());
    }

    #[test]
    fn realm_host_ghcr_rejects_other() {
        assert!(validate_realm_host("ghcr.io", &url("https://malicious.io/token")).is_err());
    }

    #[test]
    fn realm_host_ecr_allows_amazonaws_subdomain() {
        assert!(validate_realm_host(
            "123456789.dkr.ecr.us-east-1.amazonaws.com",
            &url("https://123456789.dkr.ecr.us-east-1.amazonaws.com/token")
        )
        .is_ok());
    }

    #[test]
    fn realm_host_ecr_rejects_non_amazonaws() {
        let err = validate_realm_host(
            "123456789.dkr.ecr.us-east-1.amazonaws.com",
            &url("https://evil.notamazonaws.com/token"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("amazonaws.com"), "{err}");
    }

    #[test]
    fn realm_host_gcr_allows_oauth2_googleapis() {
        assert!(validate_realm_host("gcr.io", &url("https://oauth2.googleapis.com/token")).is_ok());
    }

    #[test]
    fn realm_host_gcr_allows_gcr_subdomain() {
        assert!(validate_realm_host("us.gcr.io", &url("https://us.gcr.io/v2/token")).is_ok());
    }

    #[test]
    fn realm_host_gcr_rejects_arbitrary() {
        assert!(validate_realm_host("gcr.io", &url("https://evil.com/token")).is_err());
    }

    #[test]
    fn realm_host_unknown_registry_allows_any_https_realm() {
        // Self-hosted registries are not enumerated; HTTPS alone is sufficient.
        assert!(validate_realm_host(
            "my-registry.internal",
            &url("https://auth.my-registry.internal/token")
        )
        .is_ok());
        assert!(validate_realm_host(
            "harbor.company.io",
            &url("https://harbor.company.io/service/token")
        )
        .is_ok());
    }

    // ---------------------------------------------------------------------------
    // CachedToken expiry
    // ---------------------------------------------------------------------------

    #[test]
    fn cached_token_valid_without_expiry() {
        let t = CachedToken {
            token: "tok".into(),
            expires_at: None,
        };
        assert!(t.is_valid());
    }

    #[test]
    fn cached_token_valid_with_future_expiry() {
        let t = CachedToken {
            token: "tok".into(),
            expires_at: Some(Instant::now() + Duration::from_secs(300)),
        };
        assert!(t.is_valid());
    }

    #[test]
    fn cached_token_invalid_when_within_buffer() {
        // expires_at is 10 s from now, but the buffer is 30 s → stale
        let t = CachedToken {
            token: "tok".into(),
            expires_at: Some(Instant::now() + Duration::from_secs(10)),
        };
        assert!(!t.is_valid());
    }

    #[test]
    fn cached_token_invalid_when_past() {
        let t = CachedToken {
            token: "tok".into(),
            // Already expired — Instant::now() - 1 s; use checked_sub to avoid panic
            expires_at: Instant::now().checked_sub(Duration::from_secs(1)),
        };
        assert!(!t.is_valid());
    }
}

// ---------------------------------------------------------------------------
// Mock HTTP tests — prove the protocol flow, not just helpers
// ---------------------------------------------------------------------------
//
// These tests start a real local HTTP server (wiremock) and drive the
// RegistryClient through the OCI auth protocol. They verify:
//
//   1. 401 → WWW-Authenticate → token exchange → retry → success
//   2. Cached token reused on the second request (token endpoint called once)
//   3. Preemptive token attached on second request (no 401 round trip)
//   4. Stale-cached token evicted and re-fetched on repeated 401
//
// Identity-token mode is used (no HTTPS restriction on the realm URL)
// so the tests work against a plain HTTP wiremock server.

#[cfg(test)]
mod http_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn token_body(tok: &str, expires_in: u64) -> serde_json::Value {
        serde_json::json!({ "token": tok, "expires_in": expires_in })
    }

    /// Set up HEAD mocks using wiremock priority ordering.
    ///
    /// Wiremock tries mocks in FIFO order (first mounted = first tried).
    /// Mount the `times_401`-shot 401 first (highest priority), then the 404
    /// fallback. The first N HEAD requests get 401; once those shots are
    /// exhausted wiremock falls through to the 404 mock.
    async fn mount_head_sequence(server: &MockServer, times_401: u64) {
        let challenge = format!(
            "Bearer realm=\"{}/token\",service=\"test\",scope=\"repository:myrepo:pull\"",
            server.uri()
        );
        // High-priority N-shot 401 (mounted first = tried first).
        Mock::given(method("HEAD"))
            .and(path(format!("/v2/myrepo/blobs/{DIGEST}")))
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .up_to_n_times(times_401)
            .mount(server)
            .await;
        // Low-priority fallback: 404 once the 401 shots are exhausted.
        Mock::given(method("HEAD"))
            .and(path(format!("/v2/myrepo/blobs/{DIGEST}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(server)
            .await;
    }

    // -----------------------------------------------------------------------
    // Test 1: 401 → token exchange → retry → success.
    // Token endpoint called exactly once.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_auth_challenge_and_retry() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("tok", 300)))
            .expect(1)
            .mount(&server)
            .await;
        // first HEAD → 401, second HEAD (retry with bearer) → 404.
        mount_head_sequence(&server, 1).await;

        let client =
            RegistryClient::new(server.uri().to_string()).with_identity_token("jwt".to_string());

        let exists = client.blob_exists("myrepo", DIGEST).await.unwrap();
        assert!(!exists);
        // MockServer drop asserts expect(1) was satisfied.
    }

    // -----------------------------------------------------------------------
    // Test 2: cached token reused across two calls.
    // Token endpoint called exactly once total.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_cached_token_not_refetched() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("tok", 300)))
            .expect(1)
            .mount(&server)
            .await;
        // Only the very first HEAD returns 401; all others return 404.
        mount_head_sequence(&server, 1).await;

        let client =
            RegistryClient::new(server.uri().to_string()).with_identity_token("jwt".to_string());

        // Call 1: auth dance → token cached, last_challenge recorded.
        client.blob_exists("myrepo", DIGEST).await.unwrap();
        // Call 2: preemptive_token() finds the cached token → initial send returns 404
        //         immediately, no auth dance, token endpoint NOT called again.
        client.blob_exists("myrepo", DIGEST).await.unwrap();
        // Drop asserts expect(1).
    }

    // -----------------------------------------------------------------------
    // Test 3: stale cached token → 401 on retry → force-refresh → success.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_stale_token_force_refreshed() {
        let server = MockServer::start().await;

        // Priority: first mounted = first tried (wiremock FIFO).
        // stale-tok (first) → served on initial fetch; fresh-tok (second) → served on force-refresh.
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("stale-tok", 0)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("fresh-tok", 300)))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // First 2 HEADs → 401 (initial + first_retry with stale token).
        // Third HEAD (second_retry with fresh token) → 404.
        mount_head_sequence(&server, 2).await;

        let client =
            RegistryClient::new(server.uri().to_string()).with_identity_token("jwt".to_string());

        // initial → 401 → stale-tok (expires_in=0, immediately stale)
        // retry#1 → 401 → get_token(true) force-evict → fresh-tok
        // retry#2 → 404 → return Ok
        let exists = client.blob_exists("myrepo", DIGEST).await.unwrap();
        assert!(!exists);
    }

    // -----------------------------------------------------------------------
    // Test 4: streaming PUT 401 → body factory produces fresh body for retry.
    //
    // Covers the critical upload path: a non-replayable PUT body that triggers
    // a 401 challenge. The factory must be called twice (initial + one retry).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_streaming_put_retries_with_fresh_body() {
        let server = MockServer::start().await;

        let challenge = format!(
            "Bearer realm=\"{}/token\",service=\"test\",scope=\"repository:myrepo:push,pull\"",
            server.uri()
        );

        // Token endpoint — must be called exactly once (first retry after 401).
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("push-tok", 300)))
            .expect(1)
            .mount(&server)
            .await;

        // blob_exists HEAD → 404 (blob absent; proceed to upload).
        Mock::given(method("HEAD"))
            .and(path(format!("/v2/myrepo/blobs/{DIGEST}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // POST to initiate upload → 202 with upload Location.
        Mock::given(method("POST"))
            .and(path("/v2/myrepo/blobs/uploads/"))
            .respond_with(
                ResponseTemplate::new(202)
                    .insert_header("Location", "/v2/myrepo/blobs/uploads/sess-1"),
            )
            .mount(&server)
            .await;

        // PUT: first attempt → 401 (unauthenticated); second attempt → 201 Created.
        // FIFO order: 401 mock first (higher priority, exhausts after 1 hit), 201 fallback second.
        Mock::given(method("PUT"))
            .and(path("/v2/myrepo/blobs/uploads/sess-1"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/v2/myrepo/blobs/uploads/sess-1"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let client =
            RegistryClient::new(server.uri().to_string()).with_identity_token("jwt".to_string());

        let body_data: &[u8] = b"fake blob content for upload";
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        client
            .push_blob_stream("myrepo", DIGEST, body_data.len() as u64, move || {
                call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(reqwest::Body::from(body_data))
            })
            .await
            .unwrap();

        // Factory called twice: once for the unauthenticated 401 attempt,
        // once for the authenticated retry that succeeds.
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 2);
        // MockServer drop asserts token endpoint expect(1) was satisfied.
    }

    // -----------------------------------------------------------------------
    // Test 5: POST warms the token; PUT uses preemptive bearer — no 401 on PUT.
    //
    // Verifies that after send_replayable does a challenge dance for the POST,
    // last_challenge is set, and send_nonreplayable attaches the token
    // preemptively so the PUT body is never sent unauthenticated.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_streaming_put_uses_preemptive_token_from_post() {
        let server = MockServer::start().await;

        let challenge = format!(
            "Bearer realm=\"{}/token\",service=\"test\",scope=\"repository:myrepo:push,pull\"",
            server.uri()
        );

        // Token endpoint — called once during the POST auth dance.
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body("shared-tok", 300)))
            .expect(1)
            .mount(&server)
            .await;

        // blob_exists HEAD → 404.
        Mock::given(method("HEAD"))
            .and(path(format!("/v2/myrepo/blobs/{DIGEST}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // POST → 401 first (triggers auth dance), then 202 with Location.
        // FIFO order: 401 first (exhausts after 1 hit), 202 fallback second.
        Mock::given(method("POST"))
            .and(path("/v2/myrepo/blobs/uploads/"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v2/myrepo/blobs/uploads/"))
            .respond_with(
                ResponseTemplate::new(202)
                    .insert_header("Location", "/v2/myrepo/blobs/uploads/sess-2"),
            )
            .mount(&server)
            .await;

        // PUT → 201 directly (preemptive token from POST dance).
        Mock::given(method("PUT"))
            .and(path("/v2/myrepo/blobs/uploads/sess-2"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let client =
            RegistryClient::new(server.uri().to_string()).with_identity_token("jwt".to_string());

        let body_data: &[u8] = b"fake blob content";
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        client
            .push_blob_stream("myrepo", DIGEST, body_data.len() as u64, move || {
                call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(reqwest::Body::from(body_data))
            })
            .await
            .unwrap();

        // Factory called exactly once — PUT succeeded on first attempt with preemptive token.
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        // MockServer drop asserts token endpoint expect(1) was satisfied.
    }
}
