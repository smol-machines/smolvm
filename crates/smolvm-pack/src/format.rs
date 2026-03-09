//! Binary format definitions for packed executables.
//!
//! This module defines the footer and manifest structures that describe
//! the contents of a packed smolvm executable.

use serde::{Deserialize, Serialize};

use crate::{PackError, Result};

/// Magic bytes identifying a packed smolvm binary.
pub const MAGIC: &[u8; 8] = b"SMOLPACK";

/// Magic bytes for embedded section header.
pub const SECTION_MAGIC: &[u8; 8] = b"SMOLSECT";

/// Current format version.
/// Version 1: Assets appended to binary
/// Version 2: Assets in sidecar file (.smolmachine)
pub const FORMAT_VERSION: u32 = 2;

/// Extension for sidecar assets file.
pub const SIDECAR_EXTENSION: &str = ".smolmachine";

/// Footer size in bytes (fixed).
pub const FOOTER_SIZE: usize = 64;

/// Embedded section header size (fixed).
pub const SECTION_HEADER_SIZE: usize = 32;

/// Header for data embedded in the __SMOLVM,__smolvm Mach-O section.
///
/// This format is used for macOS single-file binaries where assets are
/// stored inside the executable's Mach-O structure, allowing proper code signing.
///
/// Layout (32 bytes total):
/// ```text
/// Offset  Size  Field
/// 0       8     magic ("SMOLSECT")
/// 8       4     version (u32 LE)
/// 12      4     manifest_size (u32 LE)
/// 16      8     assets_size (u64 LE)
/// 24      4     checksum (u32 LE)
/// 28      4     reserved (zeroes)
/// ```
///
/// Following the header:
/// - Manifest JSON (manifest_size bytes)
/// - Compressed assets (assets_size bytes)
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    /// Size of manifest JSON in bytes.
    pub manifest_size: u32,
    /// Size of compressed assets in bytes.
    pub assets_size: u64,
    /// CRC32 checksum of manifest + assets.
    pub checksum: u32,
}

impl SectionHeader {
    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; SECTION_HEADER_SIZE] {
        let mut buf = [0u8; SECTION_HEADER_SIZE];

        // Magic
        buf[0..8].copy_from_slice(SECTION_MAGIC);

        // Version
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());

        // Manifest size
        buf[12..16].copy_from_slice(&self.manifest_size.to_le_bytes());

        // Assets size
        buf[16..24].copy_from_slice(&self.assets_size.to_le_bytes());

        // Checksum
        buf[24..28].copy_from_slice(&self.checksum.to_le_bytes());

        // Reserved (already zeroed)

        buf
    }

    /// Deserialize header from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < SECTION_HEADER_SIZE {
            return Err(PackError::InvalidMagic);
        }

        // Validate magic
        if &buf[0..8] != SECTION_MAGIC {
            return Err(PackError::InvalidMagic);
        }

        // Check version
        let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if version != FORMAT_VERSION {
            return Err(PackError::UnsupportedVersion(version));
        }

        Ok(Self {
            manifest_size: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            assets_size: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            checksum: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        })
    }
}

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
            stub_size: u64::from_le_bytes([
                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
            ]),
            assets_offset: u64::from_le_bytes([
                buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
            ]),
            assets_size: u64::from_le_bytes([
                buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
            ]),
            manifest_offset: u64::from_le_bytes([
                buf[36], buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43],
            ]),
            manifest_size: u64::from_le_bytes([
                buf[44], buf[45], buf[46], buf[47], buf[48], buf[49], buf[50], buf[51],
            ]),
            checksum: u32::from_le_bytes([buf[52], buf[53], buf[54], buf[55]]),
        })
    }
}

/// Execution mode for packed binaries.
///
/// Determines how commands are executed at runtime:
/// - `Container`: commands run inside a crun container (OCI layers)
/// - `Vm`: commands run directly in the VM rootfs (overlay disk)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PackMode {
    /// Container mode: OCI image layers + crun container execution.
    #[default]
    Container,
    /// VM mode: overlay disk + direct VM execution.
    Vm,
}

/// Manifest describing the packed image and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifest {
    /// Execution mode (container or VM).
    #[serde(default)]
    pub mode: PackMode,

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

    /// Pre-formatted storage disk template (optional).
    /// When present, copied to cache on first run instead of formatting at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_template: Option<AssetEntry>,

    /// Overlay disk template (optional, VM mode only).
    /// Contains the VM's persistent rootfs state from a `--from-vm` pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_template: Option<AssetEntry>,
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
            mode: PackMode::default(),
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
                storage_template: None,
                overlay_template: None,
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

    #[test]
    fn test_pack_mode_default_is_container() {
        assert_eq!(PackMode::default(), PackMode::Container);
    }

    #[test]
    fn test_pack_mode_backward_compat() {
        // Old manifests without a "mode" field should deserialize as Container
        let json = r#"{
            "image": "alpine:latest",
            "digest": "sha256:abc",
            "platform": "linux/arm64",
            "cpus": 1,
            "mem": 256,
            "entrypoint": [],
            "cmd": [],
            "env": [],
            "assets": {
                "libraries": [],
                "agent_rootfs": { "path": "rootfs.tar", "size": 1024 },
                "layers": []
            }
        }"#;

        let manifest: PackManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.mode, PackMode::Container);
        assert!(manifest.assets.overlay_template.is_none());
    }

    #[test]
    fn test_pack_mode_vm_roundtrip() {
        let mut manifest = PackManifest::new(
            "vm://myvm".to_string(),
            "none".to_string(),
            "linux/arm64".to_string(),
        );
        manifest.mode = PackMode::Vm;
        manifest.assets.overlay_template = Some(AssetEntry {
            path: "overlay.raw".to_string(),
            size: 2 * 1024 * 1024 * 1024,
        });

        let json = manifest.to_json().unwrap();
        let restored = PackManifest::from_json(&json).unwrap();
        assert_eq!(restored.mode, PackMode::Vm);
        assert!(restored.assets.overlay_template.is_some());
        assert_eq!(
            restored.assets.overlay_template.unwrap().path,
            "overlay.raw"
        );
    }
}
