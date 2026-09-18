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

/// A host disk attached to a machine alongside its managed storage and overlay
/// disks, surfacing in the guest as `/dev/vdc`, `/dev/vdd`, ... in order.
///
/// The path may be a regular file (a disk image) or a host block device. It is
/// handed to the guest raw: smolvm never formats, mounts or resizes it, so the
/// guest owns its filesystem. That is the point — a database wants its WAL on a
/// device with different latency from its data, which a single managed storage
/// disk cannot express.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachedDisk {
    /// Absolute host path to the disk image or block device.
    pub path: std::path::PathBuf,
    /// Attach read-only. The guest sees a device it cannot write.
    #[serde(default)]
    pub read_only: bool,
}

impl AttachedDisk {
    /// Parse a `--disk` value: an absolute path, optionally suffixed `:ro` or
    /// `:rw`.
    ///
    /// Only those two exact suffixes are treated as a mode, so a path that
    /// merely contains a colon is still addressable.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("disk path is empty".to_string());
        }
        let (raw, read_only) = match spec.strip_suffix(":ro") {
            Some(p) => (p, true),
            None => (spec.strip_suffix(":rw").unwrap_or(spec), false),
        };
        if raw.is_empty() {
            return Err(format!("{spec}: disk path is empty"));
        }
        let path = std::path::PathBuf::from(raw);
        if !path.is_absolute() {
            return Err(format!(
                "{raw}: disk path must be absolute (the VM is launched from a different working directory)"
            ));
        }
        Ok(Self { path, read_only })
    }

    /// Reject anything that cannot be attached, with the reason a caller can act
    /// on. Checked at create time so a machine is never recorded pointing at a
    /// disk that will fail at every start.
    pub fn validate(&self) -> Result<(), String> {
        let display = self.path.display();
        let meta = std::fs::metadata(&self.path)
            .map_err(|e| format!("{display}: cannot stat disk ({e})"))?;
        if meta.is_dir() {
            return Err(format!("{display}: is a directory, not a disk"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let ft = meta.file_type();
            if !ft.is_file() && !ft.is_block_device() {
                return Err(format!(
                    "{display}: must be a regular file or a block device"
                ));
            }
            if ft.is_block_device() {
                if let Some(mount) = host_mount_of(&self.path) {
                    return Err(format!(
                        "{display}: is mounted on the host at {mount}. Attaching a mounted device to a guest corrupts it — unmount it first"
                    ));
                }
            }
        }
        // Opening is the only honest accessibility test: under per-VM uid
        // isolation the VMM runs as a dropped uid, and a host device is
        // typically root-owned, so a readable-looking path can still fail at
        // boot while configuring virtio-blk.
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        if !self.read_only {
            opts.write(true);
        }
        opts.open(&self.path).map_err(|e| {
            format!(
                "{display}: cannot open for {} ({e})",
                if self.read_only {
                    "reading"
                } else {
                    "read-write"
                }
            )
        })?;
        Ok(())
    }
}

/// The host mount point currently using `device`, if any (Linux only).
#[cfg(target_os = "linux")]
fn host_mount_of(device: &std::path::Path) -> Option<String> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    let want = device.to_str()?;
    mounts.lines().find_map(|line| {
        let mut cols = line.split_whitespace();
        let src = cols.next()?;
        let dst = cols.next()?;
        (src == want).then(|| dst.to_string())
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn host_mount_of(_device: &std::path::Path) -> Option<String> {
    None
}

/// The on-disk format of `path`, read from its magic bytes.
///
/// Mirrors the launcher's own detection so an attached disk is declared the way
/// libkrun will parse it. A block device, or anything unreadable, is `Raw`.
pub fn detect_disk_format(path: &std::path::Path) -> DiskFormat {
    use std::io::Read;
    const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xfb];
    let mut magic = [0u8; 4];
    let is_qcow2 = std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == QCOW2_MAGIC;
    if is_qcow2 {
        DiskFormat::Qcow2
    } else {
        DiskFormat::Raw
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

#[cfg(test)]
mod attached_disk_tests {
    use super::*;

    #[test]
    fn parses_a_plain_path_as_read_write() {
        let d = AttachedDisk::parse("/dev/nvme1n1").unwrap();
        assert_eq!(d.path, std::path::PathBuf::from("/dev/nvme1n1"));
        assert!(!d.read_only);
    }

    #[test]
    fn ro_and_rw_suffixes_set_the_mode() {
        assert!(AttachedDisk::parse("/data/wal.img:ro").unwrap().read_only);
        let rw = AttachedDisk::parse("/data/wal.img:rw").unwrap();
        assert!(!rw.read_only);
        assert_eq!(rw.path, std::path::PathBuf::from("/data/wal.img"));
    }

    /// Only the two exact mode suffixes are a mode, so a path that merely
    /// contains a colon stays addressable.
    #[test]
    fn a_colon_that_is_not_a_mode_stays_part_of_the_path() {
        let d = AttachedDisk::parse("/data/snap:2026/disk.img").unwrap();
        assert_eq!(d.path, std::path::PathBuf::from("/data/snap:2026/disk.img"));
        assert!(!d.read_only);
    }

    /// The VM launches from a different working directory, so a relative path
    /// would resolve somewhere the caller did not mean.
    #[test]
    fn a_relative_path_is_refused_with_the_reason() {
        let err = AttachedDisk::parse("disk.img").unwrap_err();
        assert!(err.contains("must be absolute"), "{err}");
        assert!(AttachedDisk::parse("").is_err());
        assert!(AttachedDisk::parse(":ro").is_err());
    }

    #[test]
    fn validate_rejects_a_missing_path_and_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = AttachedDisk {
            path: dir.path().join("nope.img"),
            read_only: false,
        };
        assert!(missing.validate().unwrap_err().contains("cannot stat"));

        let as_dir = AttachedDisk {
            path: dir.path().to_path_buf(),
            read_only: false,
        };
        assert!(as_dir.validate().unwrap_err().contains("is a directory"));
    }

    #[test]
    fn validate_accepts_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("wal.img");
        std::fs::write(&img, [0u8; 64]).unwrap();
        AttachedDisk {
            path: img,
            read_only: false,
        }
        .validate()
        .expect("a writable regular file is a valid disk");
    }

    /// A read-only attachment must not demand write access: attaching someone
    /// else's image or a read-only mount is the whole point of `:ro`.
    #[cfg(unix)]
    #[test]
    fn a_read_only_disk_validates_without_write_permission() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("golden.img");
        std::fs::write(&img, [0u8; 64]).unwrap();
        std::fs::set_permissions(&img, std::fs::Permissions::from_mode(0o444)).unwrap();

        AttachedDisk {
            path: img.clone(),
            read_only: true,
        }
        .validate()
        .expect("read-only attach only needs read access");

        // Running as root bypasses the mode, so only assert the negative case
        // where the mode is actually enforced.
        if unsafe { libc::geteuid() } != 0 {
            let err = AttachedDisk {
                path: img,
                read_only: false,
            }
            .validate()
            .unwrap_err();
            assert!(err.contains("cannot open for read-write"), "{err}");
        }
    }

    /// An attached qcow2 must be declared qcow2: told it is raw, libkrun exposes
    /// the header as the whole device and the guest sees a few hundred KiB.
    #[test]
    fn format_is_read_from_the_magic_not_the_extension() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("plain.qcow2");
        std::fs::write(&raw, [0u8; 8]).unwrap();
        assert_eq!(detect_disk_format(&raw), DiskFormat::Raw);

        let qcow = dir.path().join("image.img");
        std::fs::write(&qcow, [0x51, 0x46, 0x49, 0xfb, 0, 0, 0, 3]).unwrap();
        assert_eq!(detect_disk_format(&qcow), DiskFormat::Qcow2);

        // A device that cannot be read is treated as raw rather than failing.
        assert_eq!(
            detect_disk_format(std::path::Path::new("/nonexistent/disk")),
            DiskFormat::Raw
        );
    }
}
