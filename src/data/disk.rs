/// Default size for the rootfs overlay disk (10 GiB sparse).
///
/// This is a sparse file. Only actually-written data consumes host disk space.
/// 10 GiB provides headroom for package installation (`apk add`, `pip install`,
/// etc.) without hitting "No space left on device" during typical development
/// workflows.
pub const DEFAULT_OVERLAY_SIZE_GIB: u64 = 10;

/// Default size for the shared storage disk (20 GiB sparse).
pub const DEFAULT_STORAGE_SIZE_GIB: u64 = 20;

/// Overlay disk filename.
pub const OVERLAY_DISK_FILENAME: &str = "overlay.raw";

/// Storage disk filename.
pub const STORAGE_DISK_FILENAME: &str = "storage.raw";

/// Marker type for the persistent rootfs overlay disk.
pub enum Overlay {}

/// Marker type for the shared storage disk.
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
