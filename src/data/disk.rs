//! Canonical shared disk type metadata.

use serde::{Deserialize, Serialize};

use crate::data::storage::{
    DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB, OVERLAY_DISK_FILENAME,
    STORAGE_DISK_FILENAME,
};

/// On-disk image format for a VM's block disks. Fork clones attach a `Qcow2`
/// copy-on-write overlay backed by the golden's `Raw` disk; every other VM uses
/// `Raw` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskFormat {
    /// A flat raw disk image.
    #[default]
    Raw,
    /// A qcow2 image, used as a copy-on-write overlay over a backing disk.
    Qcow2,
}

impl DiskFormat {
    /// File extension used for disks of this format.
    pub fn extension(self) -> &'static str {
        match self {
            DiskFormat::Raw => "raw",
            DiskFormat::Qcow2 => "qcow2",
        }
    }

    /// The disk-format integer libkrun's `krun_add_disk2` expects.
    pub fn to_krun_u32(self) -> u32 {
        match self {
            DiskFormat::Raw => 0,
            DiskFormat::Qcow2 => 1,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_format_defaults_to_raw() {
        assert_eq!(DiskFormat::default(), DiskFormat::Raw);
    }

    #[test]
    fn disk_format_extension_and_krun_value() {
        assert_eq!(DiskFormat::Raw.extension(), "raw");
        assert_eq!(DiskFormat::Qcow2.extension(), "qcow2");
        // Must match libkrun's ImageType: Raw=0, Qcow2=1.
        assert_eq!(DiskFormat::Raw.to_krun_u32(), 0);
        assert_eq!(DiskFormat::Qcow2.to_krun_u32(), 1);
    }

    #[test]
    fn disk_format_serde_roundtrip_lowercase() {
        assert_eq!(
            serde_json::to_string(&DiskFormat::Qcow2).unwrap(),
            "\"qcow2\""
        );
        let parsed: DiskFormat = serde_json::from_str("\"raw\"").unwrap();
        assert_eq!(parsed, DiskFormat::Raw);
    }
}
