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

/// OCI image index media type — a multi-platform "fan-out" manifest that points
/// at one single-platform manifest per (os, arch). A single tag (e.g.
/// `alpine:latest`) can carry an index so `pull` auto-selects the caller's
/// platform, exactly like a Docker manifest list.
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// The platform a manifest targets, as it appears in an index entry. For
/// smolmachines this is the **host** platform the artifact runs on (it bundles
/// host-specific libkrun), e.g. `os=linux, architecture=amd64`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciPlatform {
    pub os: String,
    pub architecture: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub variant: Option<String>,
}

impl OciPlatform {
    /// The platform of the process running right now, in OCI form (`darwin`/
    /// `linux`, `arm64`/`amd64`) — matches `PackManifest.host_platform`.
    pub fn current() -> Self {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let architecture = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        };
        Self {
            os: os.to_string(),
            architecture: architecture.to_string(),
            variant: None,
        }
    }

    /// Parse a `host_platform` string (`"darwin/arm64"`, `"linux/x86_64"`) into a
    /// platform descriptor, normalizing the arch (`x86_64`→`amd64`,
    /// `aarch64`→`arm64`) so index entries and `current()` always agree.
    pub fn parse(host_platform: &str) -> Self {
        let (os, arch) = host_platform
            .split_once('/')
            .unwrap_or(("linux", host_platform));
        let architecture = match arch {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self {
            os: os.to_string(),
            architecture: architecture.to_string(),
            variant: None,
        }
    }

    /// Human label, e.g. `linux/amd64`.
    pub fn label(&self) -> String {
        format!("{}/{}", self.os, self.architecture)
    }
}

/// One entry in an [`OciIndex`]: a manifest descriptor plus the platform it
/// targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciIndexManifest {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub platform: Option<OciPlatform>,
}

/// OCI image index — references one manifest per platform so a single tag fans
/// out by architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciIndex {
    pub schema_version: u32,
    pub media_type: String,
    pub manifests: Vec<OciIndexManifest>,
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
mod platform_tests {
    use super::*;

    #[test]
    fn parse_normalizes_arch_and_os() {
        // host_platform strings (as written into PackManifest) → OCI platform.
        let p = OciPlatform::parse("darwin/arm64");
        assert_eq!(
            (p.os.as_str(), p.architecture.as_str()),
            ("darwin", "arm64")
        );
        // x86_64/aarch64 normalize to amd64/arm64 so index entries and current()
        // always compare equal.
        assert_eq!(OciPlatform::parse("linux/x86_64").architecture, "amd64");
        assert_eq!(OciPlatform::parse("linux/aarch64").architecture, "arm64");
        assert_eq!(OciPlatform::parse("linux/amd64").label(), "linux/amd64");
        // Missing slash → defaults os to linux.
        assert_eq!(OciPlatform::parse("amd64").os, "linux");
    }

    #[test]
    fn current_matches_parse_of_its_own_label() {
        // The selection in pull compares an index entry to current(); a manifest
        // pushed FROM this machine must therefore round-trip equal.
        let cur = OciPlatform::current();
        assert_eq!(OciPlatform::parse(&cur.label()), cur);
        assert!(matches!(cur.architecture.as_str(), "arm64" | "amd64"));
        assert!(matches!(cur.os.as_str(), "darwin" | "linux" | "windows"));
    }

    #[test]
    fn index_round_trips_and_entry_selection_works() {
        let index = OciIndex {
            schema_version: 2,
            media_type: INDEX_MEDIA_TYPE.to_string(),
            manifests: vec![
                OciIndexManifest {
                    media_type: MANIFEST_MEDIA_TYPE.to_string(),
                    digest: "sha256:aaa".into(),
                    size: 10,
                    platform: Some(OciPlatform::parse("linux/arm64")),
                },
                OciIndexManifest {
                    media_type: MANIFEST_MEDIA_TYPE.to_string(),
                    digest: "sha256:bbb".into(),
                    size: 20,
                    platform: Some(OciPlatform::parse("linux/amd64")),
                },
            ],
        };
        // serde round-trip (camelCase mediaType/schemaVersion).
        let json = serde_json::to_vec(&index).unwrap();
        assert!(String::from_utf8_lossy(&json).contains("\"mediaType\""));
        let back: OciIndex = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.manifests.len(), 2);
        // pull's selection: find the entry whose platform == the wanted one.
        let want = OciPlatform::parse("linux/amd64");
        let hit = back
            .manifests
            .iter()
            .find(|m| m.platform.as_ref() == Some(&want))
            .unwrap();
        assert_eq!(hit.digest, "sha256:bbb");
        // a platform not present → no match (pull would 404 with the available list).
        let miss = OciPlatform::parse("windows/amd64");
        assert!(back
            .manifests
            .iter()
            .all(|m| m.platform.as_ref() != Some(&miss)));
    }
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
