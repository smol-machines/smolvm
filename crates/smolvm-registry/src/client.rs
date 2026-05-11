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
    identity_token: Option<String>,
    token_cache: Mutex<HashMap<TokenCacheKey, String>>,
}

impl RegistryClient {
    /// Create a new client for the given registry base URL.
    pub fn new(base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            auth_token: None,
            identity_token: None,
            token_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Return the base URL this client is configured for.
    pub fn base_url(&self) -> &str {
        &self.base_url
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

    /// Check connectivity: `GET /v2/` must return 200.
    pub async fn ping(&self) -> Result<()> {
        let url = format!("{}/v2/", self.base_url);
        let resp = self.send(self.request(reqwest::Method::GET, &url)).await?;
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
        let resp = self.send(self.request(reqwest::Method::HEAD, &url)).await?;
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
            .send(
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
            .send(
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
        let resp = self.send(self.request(reqwest::Method::GET, &url)).await?;

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
    /// The caller pre-computes the digest (two-pass) and provides a streaming body.
    pub async fn push_blob_stream(
        &self,
        repo: &str,
        digest: &str,
        size: u64,
        body: reqwest::Body,
    ) -> Result<()> {
        validate_digest(digest)?;

        // Skip if already present.
        if self.blob_exists(repo, digest).await? {
            tracing::debug!(digest = %digest, "blob already exists, skipping upload");
            return Ok(());
        }

        // Step 1: POST to initiate upload.
        let post_url = format!("{}/v2/{}/blobs/uploads/", self.base_url, repo);
        let resp = self
            .send(
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

        // Resolve Location — validates same-origin for absolute URLs.
        let put_url = self.resolve_location(&location)?;

        let separator = if put_url.contains('?') { "&" } else { "?" };
        let put_url = format!("{}{}digest={}", put_url, separator, digest);

        // Step 2: PUT with streamed body.
        // Set Content-Length explicitly — reqwest defaults to chunked transfer
        // for streamed bodies, which some registries reject.
        let resp = self
            .send(
                self.request(reqwest::Method::PUT, &put_url)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(CONTENT_LENGTH, size)
                    .body(body),
            )
            .await?;

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
        let resp = self.send(self.request(reqwest::Method::GET, &url)).await?;

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
            .send(
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
            .send(
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

        Ok(resp.bytes().await?.to_vec())
    }

    /// Resolve a Location header value against the base URL.
    ///
    /// Relative paths are joined to base_url. Absolute URLs are validated
    /// to ensure they point to the same registry host (prevents SSRF via
    /// malicious registry redirects).
    fn resolve_location(&self, location: &str) -> Result<String> {
        if location.starts_with("http") {
            // Absolute URL — validate same origin.
            // Extract host from both URLs for comparison.
            let loc_host = location
                .split("//")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("");
            let base_host = self
                .base_url
                .split("//")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("");

            if loc_host != base_host {
                return Err(RegistryError::ApiError {
                    status: 202,
                    body: format!(
                        "Location header points to different host ({loc_host}), expected {base_host}"
                    ),
                });
            }
            Ok(location.to_string())
        } else {
            Ok(format!("{}{}", self.base_url, location))
        }
    }

    /// Build a request with optional auth header.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }
        req
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let retry_req = req.try_clone();
        let resp = req.send().await?;

        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        if self.identity_token.is_none() || self.auth_token.is_some() {
            return Ok(resp);
        }

        let Some(header) = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(resp);
        };

        let challenge = BearerChallenge::parse(header)?;
        let token = self.oci_token(&challenge).await?;
        let retry_req = retry_req.ok_or_else(|| RegistryError::Authentication {
            message: "registry requested authentication for a non-retryable request".into(),
        })?;

        Ok(retry_req.bearer_auth(token).send().await?)
    }

    async fn oci_token(&self, challenge: &BearerChallenge) -> Result<String> {
        let key = TokenCacheKey {
            realm: challenge.realm.clone(),
            service: challenge.service.clone(),
            scope: challenge.scope.clone(),
        };

        if let Some(token) = self
            .token_cache
            .lock()
            .map_err(|_| RegistryError::Authentication {
                message: "registry token cache lock poisoned".into(),
            })?
            .get(&key)
            .cloned()
        {
            return Ok(token);
        }

        let identity_token =
            self.identity_token
                .as_deref()
                .ok_or_else(|| RegistryError::Authentication {
                    message: "registry requested authentication but no identity token is configured"
                        .into(),
                })?;

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

        let resp = self
            .http
            .get(url)
            .bearer_auth(identity_token)
            .send()
            .await?;

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

        self.token_cache
            .lock()
            .map_err(|_| RegistryError::Authentication {
                message: "registry token cache lock poisoned".into(),
            })?
            .insert(key, token.clone());

        Ok(token)
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
    fn bearer_challenge_parses_registry_params() {
        let challenge = BearerChallenge::parse(
            r#"Bearer realm="https://token.smolmachines.com/v2/auth",service="registry.smolmachines.com",scope="repository:binsquare/app:pull,push""#,
        )
        .unwrap();

        assert_eq!(
            challenge.realm,
            "https://token.smolmachines.com/v2/auth"
        );
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
}
