//! Canonical shared disk type metadata.

use crate::data::storage::{
    DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB, OVERLAY_DISK_FILENAME,
    STORAGE_DISK_FILENAME,
};

/// Marker type for the persistent rootfs overlay disk.
#[derive(Debug, Clone, Copy)]
pub enum Overlay {}

/// Marker type for the shared storage disk.
#[derive(Debug, Clone, Copy)]
pub enum Storage {}

/// Compile-time metadata for a typed VM disk.
pub trait DiskType {
    /// Human-readable disk type name used in logs and errors.
    const NAME: &'static str;
    /// Default filename for this disk type.
    const DEFAULT_FILENAME: &'static str;
    /// Default size for this disk type, in GiB.
    const DEFAULT_SIZE_GIB: u64;
    /// Preformatted template filename for this disk type.
    const TEMPLATE_FILENAME: &'static str;
    /// ext4 volume label used when formatting this disk type.
    const VOLUME_LABEL: &'static str;
}

impl DiskType for Overlay {
    const NAME: &'static str = "overlay";
    const DEFAULT_FILENAME: &'static str = OVERLAY_DISK_FILENAME;
    const DEFAULT_SIZE_GIB: u64 = DEFAULT_OVERLAY_SIZE_GIB;
    const TEMPLATE_FILENAME: &'static str = "overlay-template.ext4";
    const VOLUME_LABEL: &'static str = "smolvm-overlay";
}

impl DiskType for Storage {
    const NAME: &'static str = "storage";
    const DEFAULT_FILENAME: &'static str = STORAGE_DISK_FILENAME;
    const DEFAULT_SIZE_GIB: u64 = DEFAULT_STORAGE_SIZE_GIB;
    const TEMPLATE_FILENAME: &'static str = "storage-template.ext4";
    const VOLUME_LABEL: &'static str = "smolvm";
}
