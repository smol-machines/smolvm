//! Binary packer for assembling packed executables.
//!
//! This module handles combining the stub executable, compressed assets,
//! manifest, and footer into a self-contained package.
//!
//! Format version 2 uses a sidecar file for assets (.smoldata) to allow
//! proper code signing on macOS.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::assets::{crc32_file_range, AssetCollector};
use crate::format::{PackFooter, PackManifest, FOOTER_SIZE, SIDECAR_EXTENSION};
use crate::Result;

/// Binary packer for creating self-contained executables.
pub struct Packer {
    stub_path: Option<std::path::PathBuf>,
    manifest: PackManifest,
    asset_collector: Option<AssetCollector>,
}

impl Packer {
    /// Create a new packer with the given manifest.
    pub fn new(manifest: PackManifest) -> Self {
        Self {
            stub_path: None,
            manifest,
            asset_collector: None,
        }
    }

    /// Set the path to the stub executable.
    pub fn with_stub(mut self, stub_path: impl AsRef<Path>) -> Self {
        self.stub_path = Some(stub_path.as_ref().to_path_buf());
        self
    }

    /// Set the asset collector.
    pub fn with_assets(mut self, collector: AssetCollector) -> Self {
        // Update manifest with the collector's inventory
        self.manifest.assets = collector.inventory().clone();
        self.asset_collector = Some(collector);
        self
    }

    /// Get a mutable reference to the manifest.
    pub fn manifest_mut(&mut self) -> &mut PackManifest {
        &mut self.manifest
    }

    /// Pack everything into the output file using sidecar format.
    ///
    /// Creates two files:
    /// 1. `output` - Stub executable (pure Mach-O, signable)
    /// 2. `output.smoldata` - Compressed assets + manifest + footer
    ///
    /// This keeps the binary as a pure Mach-O executable that can be
    /// properly code-signed on macOS.
    pub fn pack(self, output: impl AsRef<Path>) -> Result<PackedInfo> {
        let output = output.as_ref();
        let temp_dir = tempfile::tempdir()?;

        // Get stub executable
        let stub_path = self
            .stub_path
            .as_ref()
            .ok_or_else(|| crate::PackError::AssetNotFound("stub executable".to_string()))?;

        // 1. Copy stub executable to output (pure Mach-O, no modifications)
        let stub_data = fs::read(stub_path)?;
        let stub_size = stub_data.len() as u64;
        fs::write(output, &stub_data)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(output)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(output, perms)?;
        }

        // 2. Build sidecar file with: assets + manifest + footer
        let sidecar_path = sidecar_path_for(output);
        let mut sidecar_file = File::create(&sidecar_path)?;

        // 2a. Write compressed assets
        let assets_temp = temp_dir.path().join("assets.tar.zst");
        let assets_size = if let Some(collector) = &self.asset_collector {
            collector.compress(&assets_temp)?
        } else {
            let empty_file = File::create(&assets_temp)?;
            let encoder = zstd::stream::Encoder::new(empty_file, 1)?;
            let tar_builder = tar::Builder::new(encoder);
            let encoder = tar_builder.into_inner()?;
            encoder.finish()?;
            fs::metadata(&assets_temp)?.len()
        };

        let mut assets_file = File::open(&assets_temp)?;
        std::io::copy(&mut assets_file, &mut sidecar_file)?;

        // 2b. Write manifest JSON
        let manifest_offset = assets_size;
        let manifest_json = self.manifest.to_json()?;
        let manifest_size = manifest_json.len() as u64;
        sidecar_file.write_all(&manifest_json)?;

        // 2c. Calculate checksum of assets + manifest
        sidecar_file.flush()?;
        drop(sidecar_file);
        let checksum_size = assets_size + manifest_size;
        let checksum = crc32_file_range(&sidecar_path, 0, checksum_size)?;

        // 2d. Write footer to sidecar
        let footer = PackFooter {
            stub_size: 0,               // Not used in sidecar mode
            assets_offset: 0,           // Assets start at beginning of sidecar
            assets_size,
            manifest_offset,
            manifest_size,
            checksum,
        };

        let mut sidecar_file = fs::OpenOptions::new().append(true).open(&sidecar_path)?;
        sidecar_file.write_all(&footer.to_bytes())?;

        let sidecar_total = assets_size + manifest_size + FOOTER_SIZE as u64;
        let total_size = stub_size + sidecar_total;

        Ok(PackedInfo {
            stub_size,
            assets_size,
            manifest_size,
            total_size,
            checksum,
            sidecar_path: Some(sidecar_path),
        })
    }
}

/// Get the sidecar path for a packed binary.
pub fn sidecar_path_for(binary_path: impl AsRef<Path>) -> PathBuf {
    let mut path = binary_path.as_ref().to_path_buf();
    let filename = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    path.set_file_name(format!("{}{}", filename, SIDECAR_EXTENSION));
    path
}

/// Information about a packed binary.
#[derive(Debug, Clone)]
pub struct PackedInfo {
    /// Size of stub executable.
    pub stub_size: u64,
    /// Size of compressed assets.
    pub assets_size: u64,
    /// Size of manifest JSON.
    pub manifest_size: u64,
    /// Total size (binary + sidecar).
    pub total_size: u64,
    /// CRC32 checksum of assets.
    pub checksum: u32,
    /// Path to sidecar file (if using sidecar mode).
    pub sidecar_path: Option<PathBuf>,
}

/// Read footer from a sidecar file.
pub fn read_footer_from_sidecar(sidecar_path: impl AsRef<Path>) -> Result<PackFooter> {
    let mut file = File::open(sidecar_path.as_ref())?;
    let file_size = file.metadata()?.len();

    if file_size < FOOTER_SIZE as u64 {
        return Err(crate::PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sidecar file too small to contain footer",
        )));
    }

    file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))?;
    let mut footer_bytes = [0u8; FOOTER_SIZE];
    file.read_exact(&mut footer_bytes)?;

    PackFooter::from_bytes(&footer_bytes)
}

/// Read manifest from a sidecar file.
pub fn read_manifest_from_sidecar(sidecar_path: impl AsRef<Path>) -> Result<PackManifest> {
    let footer = read_footer_from_sidecar(sidecar_path.as_ref())?;

    let mut file = File::open(sidecar_path.as_ref())?;
    file.seek(SeekFrom::Start(footer.manifest_offset))?;

    let mut manifest_bytes = vec![0u8; footer.manifest_size as usize];
    file.read_exact(&mut manifest_bytes)?;

    PackManifest::from_json(&manifest_bytes)
}

/// Read footer from a packed binary (deprecated - use sidecar instead).
pub fn read_footer(path: impl AsRef<Path>) -> Result<PackFooter> {
    // Try sidecar first
    let sidecar = sidecar_path_for(path.as_ref());
    if sidecar.exists() {
        return read_footer_from_sidecar(&sidecar);
    }

    // Fall back to embedded (v1 format)
    let mut file = File::open(path.as_ref())?;
    let file_size = file.metadata()?.len();

    if file_size < FOOTER_SIZE as u64 {
        return Err(crate::PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file too small to contain footer",
        )));
    }

    file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))?;
    let mut footer_bytes = [0u8; FOOTER_SIZE];
    file.read_exact(&mut footer_bytes)?;

    PackFooter::from_bytes(&footer_bytes)
}

/// Read manifest from a packed binary (deprecated - use sidecar instead).
pub fn read_manifest(path: impl AsRef<Path>) -> Result<PackManifest> {
    // Try sidecar first
    let sidecar = sidecar_path_for(path.as_ref());
    if sidecar.exists() {
        return read_manifest_from_sidecar(&sidecar);
    }

    // Fall back to embedded (v1 format)
    let footer = read_footer(path.as_ref())?;

    let mut file = File::open(path.as_ref())?;
    file.seek(SeekFrom::Start(footer.manifest_offset))?;

    let mut manifest_bytes = vec![0u8; footer.manifest_size as usize];
    file.read_exact(&mut manifest_bytes)?;

    PackManifest::from_json(&manifest_bytes)
}

/// Check if a packed binary uses sidecar mode.
pub fn is_sidecar_mode(footer: &PackFooter) -> bool {
    footer.assets_offset == 0
}

/// Verify checksum of a packed binary.
pub fn verify_checksum(path: impl AsRef<Path>) -> Result<bool> {
    let footer = read_footer(path.as_ref())?;

    if is_sidecar_mode(&footer) {
        // Sidecar mode: checksum is of assets + manifest (not the footer)
        let sidecar = sidecar_path_for(path.as_ref());
        if !sidecar.exists() {
            return Ok(false);
        }
        let checksum_size = footer.assets_size + footer.manifest_size;
        let actual = crc32_file_range(&sidecar, 0, checksum_size)?;
        Ok(actual == footer.checksum)
    } else {
        // Embedded mode: checksum is of assets + manifest
        let checksum_size = footer.assets_size + footer.manifest_size;
        let actual = crc32_file_range(path.as_ref(), footer.assets_offset, checksum_size)?;
        Ok(actual == footer.checksum)
    }
}

/// Extract assets from a packed binary to a directory.
pub fn extract_assets(packed_path: impl AsRef<Path>, output_dir: impl AsRef<Path>) -> Result<()> {
    let footer = read_footer(packed_path.as_ref())?;

    if is_sidecar_mode(&footer) {
        // Sidecar mode: read from .smoldata file
        let sidecar = sidecar_path_for(packed_path.as_ref());
        crate::assets::decompress_assets_from_file(&sidecar, output_dir.as_ref())?;
    } else {
        // Embedded mode: read from the binary itself
        let mut file = File::open(packed_path.as_ref())?;
        file.seek(SeekFrom::Start(footer.assets_offset))?;

        // Read compressed assets
        let mut compressed = vec![0u8; footer.assets_size as usize];
        file.read_exact(&mut compressed)?;

        // Decompress
        crate::assets::decompress_assets(&compressed, output_dir.as_ref())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_pack_and_read() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        let mut stub_file = File::create(&stub_path).unwrap();
        stub_file.write_all(b"#!/bin/sh\necho stub").unwrap();

        // Create manifest
        let manifest = PackManifest::new(
            "alpine:latest".to_string(),
            "sha256:abc123".to_string(),
            "linux/arm64".to_string(),
        );

        // Pack
        let output_path = temp_dir.path().join("packed");
        let packer = Packer::new(manifest).with_stub(&stub_path);
        let info = packer.pack(&output_path).unwrap();

        assert!(info.stub_size > 0);
        assert!(info.total_size > info.stub_size);

        // Verify sidecar file exists
        let sidecar = sidecar_path_for(&output_path);
        assert!(sidecar.exists());

        // Read back - sidecar mode has stub_size=0 in footer
        let footer = read_footer(&output_path).unwrap();
        assert_eq!(footer.stub_size, 0); // Sidecar mode doesn't track stub size in footer
        assert_eq!(footer.assets_offset, 0); // Sidecar mode indicator

        let manifest = read_manifest(&output_path).unwrap();
        assert_eq!(manifest.image, "alpine:latest");

        // Verify checksum
        assert!(verify_checksum(&output_path).unwrap());
    }

    #[test]
    fn test_pack_with_assets() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

        // Create staging directory with a test file
        let staging = temp_dir.path().join("staging");
        let mut collector = AssetCollector::new(staging).unwrap();

        // Add a fake layer
        collector
            .add_layer("sha256:abc123def456", b"layer content")
            .unwrap();

        // Create manifest
        let manifest = PackManifest::new(
            "test:latest".to_string(),
            "sha256:test".to_string(),
            "linux/arm64".to_string(),
        );

        // Pack with assets
        let output_path = temp_dir.path().join("packed");
        let packer = Packer::new(manifest).with_stub(&stub_path).with_assets(collector);
        packer.pack(&output_path).unwrap();

        // Verify we can read the manifest with layer info
        let manifest = read_manifest(&output_path).unwrap();
        assert_eq!(manifest.assets.layers.len(), 1);
        assert_eq!(manifest.assets.layers[0].digest, "sha256:abc123def456");

        // Extract and verify assets
        let extract_dir = temp_dir.path().join("extracted");
        extract_assets(&output_path, &extract_dir).unwrap();

        let layer_file = extract_dir.join("layers/abc123def456.tar");
        assert!(layer_file.exists());
        assert_eq!(fs::read_to_string(&layer_file).unwrap(), "layer content");
    }
}
