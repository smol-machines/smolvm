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
