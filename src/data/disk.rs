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

/// A cache disk: a shared, read-only base image under the machine's own
/// copy-on-write layer, mounted in the guest at `mount_path`.
///
/// Many machines, on one host, read the same base: container images, build
/// layers and dependency caches a run starts from. Each machine writes only to
/// its own local layer (`cache.qcow2` in its data directory), so a write never
/// touches the base or another machine, and a branch gets its own layer over
/// its source's the way it does for the machine's other disks. The base is
/// never written; a new cache version is a new base file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheDisk {
    /// Absolute host path of the base image (raw or qcow2). Read only.
    pub base: std::path::PathBuf,
    /// Absolute guest path the cache filesystem is mounted at.
    pub mount_path: String,
    /// A slot: attached but left unmounted, so a checkpoint of the machine can
    /// be restored with a different cache under it. The guest mounts it only
    /// once a restore supplies that cache.
    #[serde(default)]
    pub slot: bool,
}

/// Guest paths a cache disk may not be mounted over: the root, the kernel's
/// pseudo-filesystems, and the paths smolvm's own disks and runtime use.
const RESERVED_CACHE_MOUNTS: &[&str] = &["/proc", "/sys", "/dev", "/run", "/storage", "/workspace"];

impl CacheDisk {
    /// Parse a `--cache-disk` value, `BASE:/guest/path`. The guest path is
    /// what follows the last colon, so a base path may itself contain one.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        let (base, mount_path) = spec
            .rsplit_once(':')
            .ok_or_else(|| format!("{spec}: expected BASE:/guest/path"))?;
        let base = std::path::PathBuf::from(base);
        if !base.is_absolute() {
            return Err(format!(
                "{}: cache base must be an absolute path (the VM is launched from a different working directory)",
                base.display()
            ));
        }
        if !mount_path.starts_with('/') || mount_path.contains('\0') {
            return Err(format!(
                "{mount_path:?}: cache mount path must be an absolute guest path"
            ));
        }
        let mount_path = mount_path.trim_end_matches('/').to_string();
        if mount_path.is_empty() {
            return Err("cache disk cannot be mounted over the guest's root".to_string());
        }
        let target = std::path::Path::new(&mount_path);
        if let Some(reserved) = RESERVED_CACHE_MOUNTS
            .iter()
            .find(|reserved| target.starts_with(reserved))
        {
            return Err(format!(
                "{mount_path}: cache disk cannot be mounted at or under {reserved}"
            ));
        }
        Ok(Self {
            base,
            mount_path,
            slot: false,
        })
    }

    /// Reject a base that cannot serve as one, with the reason a caller can
    /// act on: checked at create time, so a machine is never recorded pointing
    /// at a base that will fail at every start.
    pub fn validate(&self) -> Result<(), String> {
        let display = self.base.display();
        let meta = std::fs::metadata(&self.base)
            .map_err(|e| format!("{display}: cannot stat cache base ({e})"))?;
        if !meta.is_file() {
            return Err(format!(
                "{display}: cache base must be a regular file (a disk image)"
            ));
        }
        std::fs::File::open(&self.base)
            .map_err(|e| format!("{display}: cannot open cache base for reading ({e})"))?;
        Ok(())
    }

    /// Resolve a cache disk named by a remote caller: `name` is a file in
    /// `dir`, never a path, and the base must read only itself.
    ///
    /// A qcow2 header can name a backing file or an external data file, and
    /// libkrun follows either, so a base carrying one would let a caller read
    /// another host file through its machine. Bases published by smolvm never
    /// carry one; anything that does is refused.
    pub fn in_dir(dir: &std::path::Path, name: &str, mount_path: &str) -> Result<Self, String> {
        validate_base_name(name)?;
        let cache = Self::parse(&format!("{}:{mount_path}", dir.join(name).display()))?;
        cache.validate()?;
        ensure_self_contained(&cache.base)?;
        Ok(cache)
    }

    /// The size of the device the base presents: a qcow2's virtual size, a
    /// raw image's length.
    pub fn virtual_size(&self) -> crate::Result<u64> {
        use std::io::Read;
        let fail = |e: std::io::Error| {
            crate::Error::agent("cache disk size", format!("{}: {e}", self.base.display()))
        };
        let mut file = std::fs::File::open(&self.base).map_err(fail)?;
        let mut header = [0u8; 32];
        if file.read_exact(&mut header).is_ok() && header[..4] == *b"QFI\xfb" {
            return Ok(u64::from_be_bytes(
                header[24..32].try_into().expect("8 bytes"),
            ));
        }
        Ok(file.metadata().map_err(fail)?.len())
    }

    /// The base's file name, the form a remote caller names it by.
    pub fn base_name(&self) -> String {
        self.base
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Where the machine's own layer over the base lives in `vm_dir`.
    pub fn layer_path(vm_dir: &std::path::Path) -> std::path::PathBuf {
        vm_dir.join(
            std::path::Path::new(crate::data::storage::CACHE_DISK_FILENAME).with_extension("qcow2"),
        )
    }

    /// The machine's own layer over the base in `vm_dir`, created on first use.
    ///
    /// An existing layer is kept as is: it holds what this machine wrote, and a
    /// branch arrives with its own layer already made over its source's.
    pub fn prepare_layer(&self, vm_dir: &std::path::Path) -> crate::Result<std::path::PathBuf> {
        let layer = Self::layer_path(vm_dir);
        if layer.exists() {
            return Ok(layer);
        }
        let base = self.base.canonicalize().map_err(|e| {
            crate::Error::agent("cache disk", format!("{}: {e}", self.base.display()))
        })?;
        let format = detect_disk_format(&base);
        crate::agent::create_disk_overlays(&[(layer.clone(), base, format)])?;
        Ok(layer)
    }
}

impl CacheDisk {
    /// SHA-256 (hex) of the base: what a checkpoint records so a restore can
    /// attach the same base. Bases are immutable, so the digest is kept beside
    /// the base and hashed again only when the file is no longer the one it
    /// describes.
    pub fn base_digest(&self) -> crate::Result<String> {
        if let Some(digest) = recorded_base_digest(&self.base) {
            return Ok(digest);
        }
        use sha2::Digest;
        use std::io::Read;
        let mut file = std::fs::File::open(&self.base).map_err(|e| {
            crate::Error::agent("hash cache base", format!("{}: {e}", self.base.display()))
        })?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0_u8; 1 << 20];
        loop {
            let read = file.read(&mut buffer).map_err(|e| {
                crate::Error::agent("hash cache base", format!("{}: {e}", self.base.display()))
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let digest = hex::encode(hasher.finalize());
        record_base_digest(&self.base, &digest);
        Ok(digest)
    }
}

/// Where a base's digest is kept: a hidden file beside it, a name no base can
/// have.
fn base_digest_path(base: &std::path::Path) -> Option<std::path::PathBuf> {
    let name = base.file_name()?.to_str()?;
    Some(base.with_file_name(format!(".{name}.sha256")))
}

/// What the recorded digest is bound to: the file it was computed from.
fn base_identity(base: &std::path::Path) -> Option<String> {
    let meta = std::fs::metadata(base).ok()?;
    let modified = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0_u64;
    Some(format!(
        "{} {}.{:09} {inode}",
        meta.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    ))
}

/// The digest recorded for `base`, when it still describes that file.
fn recorded_base_digest(base: &std::path::Path) -> Option<String> {
    let recorded = std::fs::read_to_string(base_digest_path(base)?).ok()?;
    let (identity, digest) = recorded.trim_end().split_once('\n')?;
    let valid = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
    (valid && identity == base_identity(base)?).then(|| digest.to_ascii_lowercase())
}

/// Record `digest` as the SHA-256 of `base`, for [`CacheDisk::base_digest`].
/// Best-effort: a directory this process cannot write only costs a rehash.
pub fn record_base_digest(base: &std::path::Path, digest: &str) {
    let (Some(path), Some(identity)) = (base_digest_path(base), base_identity(base)) else {
        return;
    };
    let staging = path.with_extension(format!("sha256.{}", std::process::id()));
    let written = std::fs::write(&staging, format!("{identity}\n{digest}\n"))
        .and_then(|()| std::fs::rename(&staging, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
}

/// Check that `name` names a cache base as a remote caller must: one file name
/// in the cache disk directory, never a path.
pub fn validate_base_name(name: &str) -> Result<(), String> {
    let single_component = !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.contains(['/', '\\', '\0']);
    if single_component {
        Ok(())
    } else {
        Err(format!(
            "{name:?}: cache base must be a file name (not a path, not starting with '.')"
        ))
    }
}

/// Refuse a disk image that reads any file but itself: a qcow2 naming a
/// backing file or an external data file.
fn ensure_self_contained(path: &std::path::Path) -> Result<(), String> {
    use std::io::Read;
    const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xfb];
    const EXTERNAL_DATA_FILE: u64 = 1 << 2;
    let display = path.display();
    let mut header = [0u8; 80];
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("{display}: cannot open ({e})"))?;
    let read = file
        .read(&mut header)
        .map_err(|e| format!("{display}: cannot read ({e})"))?;
    if read < 4 || header[..4] != QCOW2_MAGIC {
        return Ok(());
    }
    if read < 72 {
        return Err(format!("{display}: truncated qcow2 header"));
    }
    let be64 = |at: usize| u64::from_be_bytes(header[at..at + 8].try_into().unwrap());
    let backing_offset = be64(8);
    let backing_len = u32::from_be_bytes(header[16..20].try_into().unwrap());
    if backing_offset != 0 || backing_len != 0 {
        return Err(format!(
            "{display}: cache base names a backing file; publish a self-contained base"
        ));
    }
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
    if version >= 3 {
        if read < 80 {
            return Err(format!("{display}: truncated qcow2 header"));
        }
        if be64(72) & EXTERNAL_DATA_FILE != 0 {
            return Err(format!(
                "{display}: cache base uses an external data file; publish a self-contained base"
            ));
        }
    }
    Ok(())
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

    fn qcow2_header(backing: bool, external_data: bool) -> Vec<u8> {
        let mut h = vec![0u8; 104];
        h[..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        h[4..8].copy_from_slice(&3u32.to_be_bytes());
        if backing {
            h[8..16].copy_from_slice(&512u64.to_be_bytes());
            h[16..20].copy_from_slice(&11u32.to_be_bytes());
        }
        if external_data {
            h[72..80].copy_from_slice(&(1u64 << 2).to_be_bytes());
        }
        h
    }

    #[test]
    fn api_cache_bases_are_plain_file_names() {
        for ok in ["deps-v1.qcow2", "base.raw", "a"] {
            assert!(validate_base_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "a/b",
            "../etc/passwd",
            "/etc/passwd",
            "a\\b",
            "x\0",
        ] {
            assert!(validate_base_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn api_cache_bases_must_read_only_themselves() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("raw.img"), vec![0u8; 4096]).unwrap();
        std::fs::write(dir.path().join("plain.qcow2"), qcow2_header(false, false)).unwrap();
        std::fs::write(dir.path().join("backed.qcow2"), qcow2_header(true, false)).unwrap();
        std::fs::write(dir.path().join("external.qcow2"), qcow2_header(false, true)).unwrap();

        assert!(CacheDisk::in_dir(dir.path(), "raw.img", "/cache").is_ok());
        let plain = CacheDisk::in_dir(dir.path(), "plain.qcow2", "/cache").unwrap();
        assert_eq!(plain.base_name(), "plain.qcow2");
        assert_eq!(plain.mount_path, "/cache");
        let backed = CacheDisk::in_dir(dir.path(), "backed.qcow2", "/cache").unwrap_err();
        assert!(backed.contains("backing file"), "{backed}");
        let external = CacheDisk::in_dir(dir.path(), "external.qcow2", "/cache").unwrap_err();
        assert!(external.contains("external data file"), "{external}");
        assert!(CacheDisk::in_dir(dir.path(), "missing.qcow2", "/cache").is_err());
        assert!(CacheDisk::in_dir(dir.path(), "../raw.img", "/cache").is_err());
        assert!(CacheDisk::in_dir(dir.path(), "raw.img", "/proc/x").is_err());
    }

    #[test]
    fn a_cache_disk_is_an_absolute_base_and_an_absolute_guest_path() {
        let cache = CacheDisk::parse("/var/caches/proj:v7.img:/cache/").unwrap();
        assert_eq!(
            cache.base,
            std::path::PathBuf::from("/var/caches/proj:v7.img")
        );
        assert_eq!(cache.mount_path, "/cache");
        for (spec, why) in [
            ("/base.img", "expected BASE:/guest/path"),
            ("base.img:/cache", "absolute path"),
            ("/base.img:cache", "absolute guest path"),
            ("/base.img:/", "root"),
            ("/base.img:/proc/x", "at or under /proc"),
            ("/base.img:/storage", "at or under /storage"),
            ("/base.img:/workspace/cache", "at or under /workspace"),
        ] {
            let err = CacheDisk::parse(spec).unwrap_err();
            assert!(err.contains(why), "{spec}: {err}");
        }
        // A path that merely starts with a reserved name is not under it.
        assert!(CacheDisk::parse("/base.img:/devcache").is_ok());
    }

    #[test]
    fn a_cache_base_must_be_a_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = CacheDisk {
            base: dir.path().join("missing.img"),
            mount_path: "/cache".into(),
            slot: false,
        };
        assert!(missing.validate().unwrap_err().contains("cannot stat"));
        let directory = CacheDisk {
            base: dir.path().to_path_buf(),
            mount_path: "/cache".into(),
            slot: false,
        };
        assert!(directory.validate().unwrap_err().contains("regular file"));
        let image = dir.path().join("base.img");
        std::fs::write(&image, [0u8; 512]).unwrap();
        assert!(CacheDisk {
            base: image,
            mount_path: "/cache".into(),
            slot: false,
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn a_cache_disk_round_trips_on_the_record_and_is_absent_by_default() {
        let legacy: crate::config::VmRecord = serde_json::from_str(r#"{"name":"legacy"}"#).unwrap();
        assert!(legacy.cache_disk.is_none());
        let mut record = crate::config::VmRecord::new("c".into(), 1, 512, vec![], vec![], false);
        record.cache_disk = Some(CacheDisk {
            base: "/var/caches/v1.img".into(),
            mount_path: "/cache".into(),
            slot: false,
        });
        let decoded: crate::config::VmRecord =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(decoded.cache_disk, record.cache_disk);
        assert_eq!(decoded.vm_resources().cache_disk, record.cache_disk);
    }

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
    fn a_base_digest_is_kept_beside_it_until_the_base_changes() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("deps-v1.raw");
        std::fs::write(&base, b"cache contents").unwrap();
        let cache = CacheDisk {
            base: base.clone(),
            mount_path: "/cache".into(),
            slot: false,
        };
        let digest = cache.base_digest().unwrap();
        assert_eq!(
            digest,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"cache contents"))
        );
        let recorded = dir.path().join(".deps-v1.raw.sha256");
        assert!(
            recorded.is_file(),
            "the digest was not kept beside the base"
        );
        // A kept digest is used as is while it still describes the file.
        let kept = std::fs::read_to_string(&recorded).unwrap();
        let (identity, _) = kept.trim_end().split_once('\n').unwrap();
        std::fs::write(&recorded, format!("{identity}\n{}\n", "ab".repeat(32))).unwrap();
        assert_eq!(cache.base_digest().unwrap(), "ab".repeat(32));
        // A base that changed is hashed again.
        std::fs::remove_file(&base).unwrap();
        std::fs::write(&base, b"other contents, longer").unwrap();
        assert_eq!(
            cache.base_digest().unwrap(),
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                b"other contents, longer"
            ))
        );
        // The kept digest can never be taken for a base.
        assert!(validate_base_name(".deps-v1.raw.sha256").is_err());
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
