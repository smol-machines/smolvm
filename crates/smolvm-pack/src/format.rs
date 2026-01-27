//! Binary format definitions for packed executables.
//!
//! This module defines the footer and manifest structures that describe
//! the contents of a packed smolvm executable.

use serde::{Deserialize, Serialize};

use crate::{PackError, Result};

/// Magic bytes identifying a packed smolvm binary.
pub const MAGIC: &[u8; 8] = b"SMOLPACK";

/// Current format version.
/// Version 1: Assets appended to binary
/// Version 2: Assets in sidecar file (.smoldata)
pub const FORMAT_VERSION: u32 = 2;

/// Extension for sidecar assets file.
pub const SIDECAR_EXTENSION: &str = ".smoldata";

/// Footer size in bytes (fixed).
pub const FOOTER_SIZE: usize = 64;

/// Fixed-size footer at the end of a packed binary.
///
/// Layout (64 bytes total):
/// ```text
/// Offset  Size  Field
/// 0       8     magic ("SMOLPACK")
/// 8       4     version (u32 LE)
/// 12      8     stub_size (u64 LE) - size of stub executable
/// 20      8     assets_offset (u64 LE) - offset to compressed assets
/// 28      8     assets_size (u64 LE) - size of compressed assets
/// 36      8     manifest_offset (u64 LE) - offset to manifest JSON
/// 44      8     manifest_size (u64 LE) - size of manifest JSON
/// 52      4     checksum (u32 LE) - CRC32 of assets + manifest
/// 56      8     reserved (zeroes)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct PackFooter {
    /// Size of the stub executable.
    pub stub_size: u64,
    /// Offset to compressed assets blob.
    pub assets_offset: u64,
    /// Size of compressed assets blob.
    pub assets_size: u64,
    /// Offset to manifest JSON.
    pub manifest_offset: u64,
    /// Size of manifest JSON.
    pub manifest_size: u64,
    /// CRC32 checksum of assets + manifest.
    pub checksum: u32,
}

impl PackFooter {
    /// Serialize footer to bytes.
    pub fn to_bytes(&self) -> [u8; FOOTER_SIZE] {
        let mut buf = [0u8; FOOTER_SIZE];

        // Magic
        buf[0..8].copy_from_slice(MAGIC);

        // Version
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());

        // Stub size
        buf[12..20].copy_from_slice(&self.stub_size.to_le_bytes());

        // Assets offset and size
        buf[20..28].copy_from_slice(&self.assets_offset.to_le_bytes());
        buf[28..36].copy_from_slice(&self.assets_size.to_le_bytes());

        // Manifest offset and size
        buf[36..44].copy_from_slice(&self.manifest_offset.to_le_bytes());
        buf[44..52].copy_from_slice(&self.manifest_size.to_le_bytes());

        // Checksum
        buf[52..56].copy_from_slice(&self.checksum.to_le_bytes());

        // Reserved (already zeroed)

        buf
    }

    /// Deserialize footer from bytes.
    pub fn from_bytes(buf: &[u8; FOOTER_SIZE]) -> Result<Self> {
        // Validate magic
        if &buf[0..8] != MAGIC {
            return Err(PackError::InvalidMagic);
        }

        // Check version
        let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if version != FORMAT_VERSION {
            return Err(PackError::UnsupportedVersion(version));
        }

        Ok(Self {
            stub_size: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            assets_offset: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            assets_size: u64::from_le_bytes(buf[28..36].try_into().unwrap()),
            manifest_offset: u64::from_le_bytes(buf[36..44].try_into().unwrap()),
            manifest_size: u64::from_le_bytes(buf[44..52].try_into().unwrap()),
            checksum: u32::from_le_bytes(buf[52..56].try_into().unwrap()),
        })
    }
}

/// Manifest describing the packed image and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifest {
    /// Original image reference (e.g., "alpine:latest").
    pub image: String,

    /// Image digest (sha256:...).
    pub digest: String,

    /// Target platform (e.g., "linux/arm64").
    pub platform: String,

    /// Entrypoint command (from image config or override).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,

    /// Default command arguments (from image config or override).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmd: Vec<String>,

    /// Default environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,

    /// Working directory (from image config or override).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,

    /// Default number of vCPUs.
    pub cpus: u8,

    /// Default memory in MiB.
    pub mem: u32,

    /// Asset inventory - files included in the assets blob.
    pub assets: AssetInventory,
}

/// Inventory of assets included in the packed binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInventory {
    /// Runtime libraries (relative paths within assets).
    pub libraries: Vec<AssetEntry>,

    /// Agent rootfs tarball.
    pub agent_rootfs: AssetEntry,

    /// OCI layer tarballs.
    pub layers: Vec<LayerEntry>,
}

/// An asset file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEntry {
    /// Path within the assets archive.
    pub path: String,

    /// Uncompressed size in bytes.
    pub size: u64,
}

/// An OCI layer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerEntry {
    /// Layer digest (sha256:...).
    pub digest: String,

    /// Path within the assets archive.
    pub path: String,

    /// Uncompressed size in bytes.
    pub size: u64,
}

impl PackManifest {
    /// Create a new manifest with default values.
    pub fn new(image: String, digest: String, platform: String) -> Self {
        Self {
            image,
            digest,
            platform,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            env: Vec::new(),
            workdir: None,
            cpus: 1,
            mem: 256,
            assets: AssetInventory {
                libraries: Vec::new(),
                agent_rootfs: AssetEntry {
                    path: "agent-rootfs.tar".to_string(),
                    size: 0,
                },
                layers: Vec::new(),
            },
        }
    }

    /// Serialize manifest to JSON.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Deserialize manifest from JSON.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_roundtrip() {
        let footer = PackFooter {
            stub_size: 512 * 1024,
            assets_offset: 512 * 1024,
            assets_size: 50 * 1024 * 1024,
            manifest_offset: 512 * 1024 + 50 * 1024 * 1024,
            manifest_size: 2048,
            checksum: 0xDEADBEEF,
        };

        let bytes = footer.to_bytes();
        assert_eq!(bytes.len(), FOOTER_SIZE);

        let restored = PackFooter::from_bytes(&bytes).unwrap();
        assert_eq!(restored.stub_size, footer.stub_size);
        assert_eq!(restored.assets_offset, footer.assets_offset);
        assert_eq!(restored.assets_size, footer.assets_size);
        assert_eq!(restored.manifest_offset, footer.manifest_offset);
        assert_eq!(restored.manifest_size, footer.manifest_size);
        assert_eq!(restored.checksum, footer.checksum);
    }

    #[test]
    fn test_footer_invalid_magic() {
        let mut bytes = [0u8; FOOTER_SIZE];
        bytes[0..8].copy_from_slice(b"BADMAGIC");

        let result = PackFooter::from_bytes(&bytes);
        assert!(matches!(result, Err(PackError::InvalidMagic)));
    }

    #[test]
    fn test_footer_unsupported_version() {
        let mut bytes = [0u8; FOOTER_SIZE];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&99u32.to_le_bytes()); // Bad version

        let result = PackFooter::from_bytes(&bytes);
        assert!(matches!(result, Err(PackError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_manifest_roundtrip() {
        let mut manifest = PackManifest::new(
            "alpine:latest".to_string(),
            "sha256:abc123".to_string(),
            "linux/arm64".to_string(),
        );
        manifest.cpus = 2;
        manifest.mem = 1024;
        manifest.entrypoint = vec!["/bin/sh".to_string()];
        manifest.env = vec!["PATH=/usr/local/bin:/usr/bin:/bin".to_string()];
        manifest.assets.libraries.push(AssetEntry {
            path: "lib/libkrun.dylib".to_string(),
            size: 4 * 1024 * 1024,
        });

        let json = manifest.to_json().unwrap();
        let restored = PackManifest::from_json(&json).unwrap();

        assert_eq!(restored.image, "alpine:latest");
        assert_eq!(restored.digest, "sha256:abc123");
        assert_eq!(restored.cpus, 2);
        assert_eq!(restored.mem, 1024);
        assert_eq!(restored.entrypoint, vec!["/bin/sh"]);
        assert_eq!(restored.assets.libraries.len(), 1);
    }

    #[test]
    fn test_manifest_json_format() {
        let manifest = PackManifest::new(
            "ubuntu:22.04".to_string(),
            "sha256:def456".to_string(),
            "linux/amd64".to_string(),
        );

        let json = String::from_utf8(manifest.to_json().unwrap()).unwrap();
        assert!(json.contains("\"image\": \"ubuntu:22.04\""));
        assert!(json.contains("\"platform\": \"linux/amd64\""));
    }
}
