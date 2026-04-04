//! OCI Distribution Spec HTTP client.
//!
//! Implements the subset of the OCI Distribution Spec needed for
//! single-blob artifact push and pull:
//! - Blob existence check (HEAD)
//! - Monolithic blob upload (POST + PUT)
//! - Blob download (GET)
//! - Manifest put/get (PUT/GET)

use crate::{RegistryError, Result, MANIFEST_MEDIA_TYPE};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use sha2::{Digest, Sha256};

/// HTTP client for an OCI Distribution registry.
pub struct RegistryClient {
    http: reqwest::Client,
    /// Base URL including scheme (e.g., "http://localhost:5000" or "https://registry.smolmachines.com").
    base_url: String,
    /// Optional Bearer token for authenticated requests.
    auth_token: Option<String>,
}

impl RegistryClient {
    /// Create a new client for the given registry base URL.
    pub fn new(base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            auth_token: None,
        }
    }

    /// Set a Bearer token for authenticated requests.
    pub fn with_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Check connectivity: `GET /v2/` must return 200.
    pub async fn ping(&self) -> Result<()> {
        let url = format!("{}/v2/", self.base_url);
        let resp = self.request(reqwest::Method::GET, &url).send().await?;
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
        let url = format!("{}/v2/{}/blobs/{}", self.base_url, repo, digest);
        let resp = self.request(reqwest::Method::HEAD, &url).send().await?;
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
            .request(reqwest::Method::POST, &post_url)
            .header(CONTENT_LENGTH, 0)
            .send()
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

        // Resolve relative Location against base URL.
        let put_url = if location.starts_with("http") {
            location
        } else {
            format!("{}{}", self.base_url, location)
        };

        // Step 2: PUT the blob data with digest.
        let separator = if put_url.contains('?') { "&" } else { "?" };
        let put_url = format!("{}{}digest={}", put_url, separator, digest);

        let resp = self
            .request(reqwest::Method::PUT, &put_url)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, data.len())
            .body(data.to_vec())
            .send()
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
        let url = format!("{}/v2/{}/blobs/{}", self.base_url, repo, digest);
        let resp = self.request(reqwest::Method::GET, &url).send().await?;

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
        // Skip if already present.
        if self.blob_exists(repo, digest).await? {
            tracing::debug!(digest = %digest, "blob already exists, skipping upload");
            return Ok(());
        }

        // Step 1: POST to initiate upload.
        let post_url = format!("{}/v2/{}/blobs/uploads/", self.base_url, repo);
        let resp = self
            .request(reqwest::Method::POST, &post_url)
            .header(CONTENT_LENGTH, 0)
            .send()
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

        let put_url = if location.starts_with("http") {
            location
        } else {
            format!("{}{}", self.base_url, location)
        };

        let separator = if put_url.contains('?') { "&" } else { "?" };
        let put_url = format!("{}{}digest={}", put_url, separator, digest);

        // Step 2: PUT with streamed body.
        // Set Content-Length explicitly — reqwest defaults to chunked transfer
        // for streamed bodies, which some registries reject.
        let resp = self
            .request(reqwest::Method::PUT, &put_url)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, size)
            .body(body)
            .send()
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
        let url = format!("{}/v2/{}/blobs/{}", self.base_url, repo, digest);
        let resp = self.request(reqwest::Method::GET, &url).send().await?;

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
            .request(reqwest::Method::PUT, &url)
            .header(CONTENT_TYPE, MANIFEST_MEDIA_TYPE)
            .body(manifest.to_vec())
            .send()
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
            .request(reqwest::Method::GET, &url)
            .header(ACCEPT, MANIFEST_MEDIA_TYPE)
            .send()
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

    /// Build a request with optional auth header.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }
        req
    }
}
