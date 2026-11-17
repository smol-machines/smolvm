//! `.smolmachine` packaging for smolvm.
//!
//! This crate provides functionality to package an OCI image and all runtime assets
//! into a portable `.smolmachine` artifact that can be pushed to a registry,
//! distributed, and run without smolvm installed.
//!
//! See [`format`] for the full binary format specification.

#![deny(missing_docs)]

mod artifact_writer;
pub mod assets;
pub mod checkpoint_stream;
pub mod detect;
pub mod extract;
pub mod format;
#[cfg(target_os = "macos")]
pub mod macho;
pub mod packer;
pub mod signing;

pub use detect::{detect_packed_mode, PackedMode};
pub use format::{
    PackFooter, PackManifest, PackMode, SectionHeader, FOOTER_SIZE, MAGIC, SECTION_HEADER_SIZE,
    SECTION_MAGIC, SIDECAR_EXTENSION,
};
pub use packer::{
    read_footer, read_footer_from_sidecar, read_manifest, read_manifest_from_sidecar,
    sidecar_path_for, verify_sidecar_checksum, Packer,
};

use thiserror::Error;

/// Errors that can occur during pack operations.
#[derive(Debug, Error)]
pub enum PackError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid magic bytes in footer.
    #[error("invalid magic: expected SMOLPACK")]
    InvalidMagic,

    /// Unsupported format version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),

    /// Checksum mismatch.
    #[error("checksum mismatch: expected {expected:08x}, got {actual:08x}")]
    ChecksumMismatch {
        /// Expected checksum.
        expected: u32,
        /// Actual checksum.
        actual: u32,
    },

    /// Asset not found.
    #[error("asset not found: {0}")]
    AssetNotFound(String),

    /// Compression error.
    #[error("compression error: {0}")]
    Compression(String),

    /// Signing error.
    #[error("signing error: {0}")]
    Signing(String),

    /// Tar archive error.
    #[error("tar error: {0}")]
    Tar(String),
}

/// Result type for pack operations.
pub type Result<T> = std::result::Result<T, PackError>;

/// Return whether every byte is zero, without assuming alignment or padding.
///
/// Bounded slice comparisons allow the platform's optimized byte comparison
/// implementation to scan sparse checkpoint data instead of branching per byte.
pub fn is_zero_filled(bytes: &[u8]) -> bool {
    static ZERO: [u8; 64 * 1024] = [0; 64 * 1024];
    bytes
        .chunks(ZERO.len())
        .all(|chunk| chunk == &ZERO[..chunk.len()])
}

#[cfg(test)]
mod zero_tests {
    use super::is_zero_filled;

    #[test]
    fn zero_detection_preserves_unaligned_and_partial_chunk_boundaries() {
        for len in [
            0, 1, 7, 8, 15, 16, 63, 64, 65, 4095, 4096, 65535, 65536, 65537, 524301, 1048577,
        ] {
            for shift in 0..16 {
                let mut storage = vec![0; len + shift];
                let bytes = &mut storage[shift..];
                assert!(is_zero_filled(bytes));
                for position in [0, len / 2, len.saturating_sub(1), 65535, 65536] {
                    if position >= len {
                        continue;
                    }
                    for value in [1, 128, 255] {
                        bytes[position] = value;
                        assert_eq!(is_zero_filled(bytes), bytes.iter().all(|b| *b == 0));
                        bytes[position] = 0;
                    }
                }
            }
        }
    }
}
