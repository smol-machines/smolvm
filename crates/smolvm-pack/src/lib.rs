//! Single-binary packaging for smolvm.
//!
//! This crate provides functionality to package an OCI image and all runtime assets
//! into a self-contained executable that can be distributed and run without smolvm installed.
//!
//! # Binary Format (Version 2 - Sidecar)
//!
//! Two files are created:
//!
//! **Binary file:**
//! ```text
//! +---------------------------+
//! | Stub Executable           |  ~500KB
//! +---------------------------+
//! | Manifest (JSON)           |  ~2KB
//! +---------------------------+
//! | Footer (64 bytes)         |
//! |  - magic: "SMOLPACK"      |
//! |  - version, offsets       |
//! |  - checksum               |
//! +---------------------------+
//! ```
//!
//! **Sidecar file (.smolmachine):**
//! ```text
//! +---------------------------+
//! | Assets Blob (zstd)        |  30-150MB
//! |  - lib/libkrun.dylib      |
//! |  - lib/libkrunfw.5.dylib  |
//! |  - agent-rootfs.tar       |
//! |  - layers/*.tar           |
//! +---------------------------+
//! ```
//!
//! This allows proper code signing on macOS while keeping distribution simple.

#![deny(missing_docs)]

pub mod assets;
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
