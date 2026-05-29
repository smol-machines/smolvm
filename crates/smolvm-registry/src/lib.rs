//! OCI Distribution client for the smolmachines registry.
//!
//! Implements push and pull of `.smolmachine` artifacts as single-blob
//! OCI artifacts, compatible with any OCI Distribution Spec registry.

pub mod cache;
pub mod client;
pub mod pull;
pub mod push;

pub use cache::BlobCache;
pub use client::RegistryClient;
pub use pull::{pull, PullResult};
pub use push::{push, PushResult};

use serde::{Deserialize, Serialize};

/// OCI media type for the smolmachine config blob.
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.smolmachines.machine.config.v1+json";

/// OCI media type for the smolmachine sidecar layer blob.
pub const LAYER_MEDIA_TYPE: &str = "application/vnd.smolmachines.smolmachine.v1";

/// OCI manifest media type.
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// OCI Image Manifest (minimal, single-layer).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    pub schema_version: u32,
    pub media_type: String,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
}

/// OCI content descriptor.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// Error type for registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("registry returned {status}: {body}")]
    ApiError { status: u16, body: String },

    #[error("registry authentication failed: {message}")]
    Authentication { message: String },

    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("blob not found: {0}")]
    BlobNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("pack format error: {0}")]
    Pack(#[from] smolvm_pack::PackError),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

/// Return `true` if `host` refers to a loopback or any-address that should be
/// reached over plain HTTP rather than HTTPS.
///
/// Handles all common local registry forms:
/// - `localhost`, `localhost:PORT`
/// - `127.x.x.x`, `127.x.x.x:PORT`   (entire 127/8 block is loopback)
/// - `::1`, `[::1]`, `[::1]:PORT`     (IPv6 loopback)
/// - `0.0.0.0`, `0.0.0.0:PORT`        (bind-all, common in dev)
pub fn is_local_registry(host: &str) -> bool {
    // Bare IPv6 (e.g. "::1") must be checked before splitting on ':' because
    // "::1".split(':').next() yields "" (the empty token before the first colon).
    if host.contains("::") && !host.starts_with('[') {
        return host == "::1";
    }

    // Strip port and brackets from bracketed IPv6: [::1]:5000 → ::1
    let bare = if host.starts_with('[') {
        host.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host)
    } else {
        // hostname or IPv4, split off port
        host.split(':').next().unwrap_or(host)
    };

    bare == "localhost" || bare == "::1" || bare == "0.0.0.0" || is_loopback_ipv4(bare)
}

/// Return true if `s` is a dotted-decimal IPv4 address in the loopback block (127.0.0.0/8).
///
/// Rejects hostnames that merely start with "127." (e.g. "127.example.com").
fn is_loopback_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts[0] == "127" && parts[1..].iter().all(|p| p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod is_local_tests {
    use super::*;

    #[test]
    fn local_variants() {
        assert!(is_local_registry("localhost"));
        assert!(is_local_registry("localhost:5000"));
        assert!(is_local_registry("127.0.0.1"));
        assert!(is_local_registry("127.0.0.1:5000"));
        assert!(is_local_registry("127.1.2.3:9000"));
        assert!(is_local_registry("::1"));
        assert!(is_local_registry("[::1]"));
        assert!(is_local_registry("[::1]:5000"));
        assert!(is_local_registry("0.0.0.0:5000"));
    }

    #[test]
    fn remote_variants() {
        assert!(!is_local_registry("registry.smolmachines.com"));
        assert!(!is_local_registry("ghcr.io"));
        assert!(!is_local_registry("docker.io"));
        assert!(!is_local_registry("registry-1.docker.io"));
        assert!(!is_local_registry("192.168.1.10:5000"));
        // hostname that starts with "127." but is not an IPv4 address
        assert!(!is_local_registry("127.example.com"));
        assert!(!is_local_registry("127.example.com:5000"));
    }
}
