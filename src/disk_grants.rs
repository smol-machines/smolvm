//! Root's record of the disk backings it attached itself.
//!
//! Under the per-VM uid drop a machine's top disk layers belong to its VMM,
//! which can rewrite their qcow2 headers to name any file as a backing. Root
//! follows those chains at boot, capture, compaction and branching, so a name
//! in a VMM-writable header is no evidence that the machine was given that
//! file. Whenever root creates a layer over a backing it records the pair
//! here, keyed by the layer's identity, in a root-only directory beside the
//! machine directories. A walk admits a backing the chain's own uid owns (its
//! VMM can open it anyway), one named by a layer root wrote and nobody else
//! can, or the one recorded for the layer that names it.
//!
//! Walks report what they could not admit and change nothing yet.

use std::path::{Path, PathBuf};

/// Record the backing root just attached under `layer`. Best effort: a missing
/// record shows up as a report from the next walk, never as a failure here.
pub fn record(layer: &Path, backing: &Path) {
    #[cfg(target_os = "linux")]
    if crate::process::vm_uid_drop_active() {
        if let Err(error) = imp::record_in(&grants_root(), layer, backing) {
            tracing::warn!(
                layer = %layer.display(),
                backing = %backing.display(),
                %error,
                "could not record disk backing grant"
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (layer, backing);
}

/// Record the backing that `layer`'s own header names, for a layer root has
/// just written or rebased.
pub fn record_named(layer: &Path) {
    #[cfg(target_os = "linux")]
    if crate::process::vm_uid_drop_active() {
        if let Ok(Some(backing)) = imp::named_backing(layer) {
            record(layer, &backing);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = layer;
}

/// Walk the chain under `top` and report each backing root did not attach for
/// it. `owner` is the uid the chain belongs to, by default the owner of `top`.
/// Returns the backings it could not admit; the walk stops at the first.
pub fn report_chain(top: &Path, owner: Option<u32>, site: &str) -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    if crate::process::vm_uid_drop_active() {
        let found = imp::unadmitted_in(&grants_root(), top, owner);
        for finding in &found {
            tracing::warn!(
                site,
                layer = %finding.layer.display(),
                backing = %finding.backing.display(),
                owner = finding.owner,
                "disk chain names a backing root did not attach"
            );
        }
        return found.into_iter().map(|finding| finding.backing).collect();
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (top, owner, site);
    Vec::new()
}

/// Bring the record up to date with the machines on this node, once per
/// serve start: chains created before grants existed are recorded as they
/// stand (once per node), and records whose layer is gone are dropped.
pub fn reconcile() {
    #[cfg(target_os = "linux")]
    if crate::process::vm_uid_drop_active() {
        match imp::reconcile_in(&grants_root(), &crate::agent::vm_cache_root()) {
            Ok((recorded, dropped)) => tracing::info!(
                recorded,
                dropped,
                "disk backing grants reconciled"
            ),
            Err(error) => tracing::warn!(%error, "could not reconcile disk backing grants"),
        }
    }
}

/// `<cache_dir>/smolvm/disk-grants/`, a root-only sibling of the VM data
/// dirs that no VMM can reach.
pub fn grants_root() -> PathBuf {
    crate::agent::vm_cache_root()
        .parent()
        .map(|smolvm| smolvm.join("disk-grants"))
        .unwrap_or_else(|| PathBuf::from("/tmp/smolvm-disk-grants"))
}

#[cfg(target_os = "linux")]
mod imp {
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// Marks a node whose pre-existing chains have been recorded.
    const BACKFILLED: &str = ".backfilled-v1";
    /// Deepest chain a walk follows; branching keeps real chains far shallower.
    const MAX_DEPTH: usize = 256;

    /// A file by device, inode and, where the filesystem keeps one, birth
    /// time, so an inode number reused by a later file is not the same file.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(super) struct Identity {
        dev: u64,
        ino: u64,
        born: Option<(i64, u32)>,
    }

    impl Identity {
        fn of(metadata: &std::fs::Metadata) -> Self {
            let born = metadata
                .created()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|since| (since.as_secs() as i64, since.subsec_nanos()));
            Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
                born,
            }
        }

        fn file_name(&self) -> String {
            format!("{}-{}", self.dev, self.ino)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Grant {
        layer: Identity,
        backing: Identity,
        backing_path: PathBuf,
    }

    #[derive(Debug)]
    pub(super) struct Finding {
        pub layer: PathBuf,
        pub backing: PathBuf,
        pub owner: u32,
    }

    fn open(path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
    }

    /// The backing name in a qcow2 header, and whether the header declares
    /// that backing raw. `None` for anything that is not a qcow2 with one.
    fn backing_of(file: &mut File) -> std::io::Result<Option<(String, bool)>> {
        const BACKING_FORMAT: u32 = 0xE279_2ACA;
        file.seek(SeekFrom::Start(0))?;
        let mut header = Vec::with_capacity(104);
        file.by_ref().take(104).read_to_end(&mut header)?;
        if header.len() < 72 || header[..4] != *b"QFI\xfb" {
            return Ok(None);
        }
        let offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
        let length = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
        if offset == 0 || length == 0 || length > 4096 {
            return Ok(None);
        }
        let mut name = vec![0_u8; length];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut name)?;
        let Ok(name) = String::from_utf8(name) else {
            return Ok(None);
        };
        // Header extensions follow a v3 header; the backing format is one.
        let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let mut raw = false;
        if version >= 3 && header.len() == 104 {
            let mut at = u64::from(u32::from_be_bytes(header[100..104].try_into().unwrap()));
            for _ in 0..64 {
                let mut head = [0_u8; 8];
                file.seek(SeekFrom::Start(at))?;
                if file.read_exact(&mut head).is_err() {
                    break;
                }
                let kind = u32::from_be_bytes(head[..4].try_into().unwrap());
                let len = u32::from_be_bytes(head[4..].try_into().unwrap());
                if kind == 0 || len > 4096 {
                    break;
                }
                if kind == BACKING_FORMAT {
                    let mut value = vec![0_u8; len as usize];
                    file.read_exact(&mut value)?;
                    raw = value == b"raw";
                    break;
                }
                at += 8 + u64::from(len.div_ceil(8) * 8);
            }
        }
        Ok(Some((name, raw)))
    }

    fn resolve(layer: &Path, name: &str) -> PathBuf {
        let name = Path::new(name);
        if name.is_absolute() {
            name.to_path_buf()
        } else {
            layer.parent().unwrap_or_else(|| Path::new(".")).join(name)
        }
    }

    pub(super) fn named_backing(layer: &Path) -> std::io::Result<Option<PathBuf>> {
        let mut file = open(layer)?;
        Ok(backing_of(&mut file)?.map(|(name, _)| resolve(layer, &name)))
    }

    pub(super) fn record_in(root: &Path, layer: &Path, backing: &Path) -> std::io::Result<()> {
        let layer = Identity::of(&open(layer)?.metadata()?);
        let backing_path = resolve(layer, &backing.to_string_lossy()).canonicalize()?;
        let backing = Identity::of(&open(&backing_path)?.metadata()?);
        write_grant(
            root,
            &Grant {
                layer,
                backing,
                backing_path,
            },
        )
    }

    fn write_grant(root: &Path, grant: &Grant) -> std::io::Result<()> {
        ensure_root(root)?;
        let body = serde_json::to_vec(grant)?;
        let mut staged = tempfile::NamedTempFile::new_in(root)?;
        std::io::Write::write_all(&mut staged, &body)?;
        staged
            .persist(root.join(grant.layer.file_name()))
            .map_err(|error| error.error)?;
        Ok(())
    }

    fn ensure_root(root: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(root)?;
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::other(format!(
                "{} is not a directory this process owns",
                root.display()
            )));
        }
        if metadata.mode() & 0o777 != 0o700 {
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn granted(root: &Path, layer: &Identity) -> Option<Identity> {
        let body = std::fs::read(root.join(layer.file_name())).ok()?;
        let grant: Grant = serde_json::from_slice(&body).ok()?;
        (grant.layer == *layer).then_some(grant.backing)
    }

    pub(super) fn unadmitted_in(root: &Path, top: &Path, owner: Option<u32>) -> Vec<Finding> {
        let Ok(mut file) = open(top) else {
            return Vec::new();
        };
        let Ok(mut metadata) = file.metadata() else {
            return Vec::new();
        };
        let owner = owner.unwrap_or(metadata.uid());
        if owner == 0 {
            return Vec::new();
        }
        let mut current = top.to_path_buf();
        for _ in 0..MAX_DEPTH {
            let Ok(Some((name, raw))) = backing_of(&mut file) else {
                break;
            };
            let backing = resolve(&current, &name);
            // A missing backing is the consumer's own error to report.
            let Ok(next) = open(&backing) else {
                break;
            };
            let Ok(next_metadata) = next.metadata() else {
                break;
            };
            let root_wrote_layer = metadata.uid() == 0 && metadata.mode() & 0o022 == 0;
            let admitted = next_metadata.is_file()
                && (next_metadata.uid() == owner
                    || root_wrote_layer
                    || granted(root, &Identity::of(&metadata))
                        == Some(Identity::of(&next_metadata)));
            if !admitted {
                return vec![Finding {
                    layer: current,
                    backing,
                    owner,
                }];
            }
            if raw {
                break;
            }
            current = backing;
            file = next;
            metadata = next_metadata;
        }
        Vec::new()
    }

    /// Every qcow2 layer in a machine directory: its own disks, and those of
    /// its branch generations and checkpoint state a few levels down.
    fn machine_layers(dir: &Path, depth: usize, into: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() && depth > 0 {
                machine_layers(&path, depth - 1, into);
            } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "qcow2") {
                into.push(path);
            }
        }
    }

    pub(super) fn reconcile_in(root: &Path, vms: &Path) -> std::io::Result<(usize, usize)> {
        ensure_root(root)?;
        let started = std::time::SystemTime::now();
        let backfill = !root.join(BACKFILLED).exists();
        let mut layers = Vec::new();
        for entry in std::fs::read_dir(vms)?.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                machine_layers(&entry.path(), 3, &mut layers);
            }
        }
        let mut live = HashSet::new();
        let mut recorded = 0;
        for layer in layers {
            let Ok(file) = open(&layer) else {
                continue;
            };
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            let identity = Identity::of(&metadata);
            live.insert(identity.file_name());
            if !backfill || metadata.uid() == 0 {
                continue;
            }
            // Recorded as found: these chains predate grants on this node.
            let Ok(Some(backing)) = named_backing(&layer) else {
                continue;
            };
            let foreign = std::fs::metadata(&backing).is_ok_and(|b| b.uid() != metadata.uid());
            if foreign
                && granted(root, &identity).is_none()
                && record_in(root, &layer, &backing).is_ok()
            {
                recorded += 1;
            }
        }
        if backfill {
            std::fs::write(root.join(BACKFILLED), b"")?;
        }
        let mut dropped = 0;
        for entry in std::fs::read_dir(root)?.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with('.') || live.contains(name) {
                continue;
            }
            // A layer created while this pass ran was not in its scan.
            let fresh = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|modified| modified >= started);
            if !fresh && std::fs::remove_file(entry.path()).is_ok() {
                dropped += 1;
            }
        }
        Ok((recorded, dropped))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn qcow2(path: &Path, backing: Option<&str>, raw_backing: bool) {
            let mut bytes = vec![0_u8; 512];
            bytes[..4].copy_from_slice(b"QFI\xfb");
            bytes[4..8].copy_from_slice(&3_u32.to_be_bytes());
            bytes[100..104].copy_from_slice(&104_u32.to_be_bytes());
            if raw_backing {
                bytes[104..108].copy_from_slice(&0xE279_2ACA_u32.to_be_bytes());
                bytes[108..112].copy_from_slice(&3_u32.to_be_bytes());
                bytes[112..115].copy_from_slice(b"raw");
            }
            if let Some(name) = backing {
                bytes[8..16].copy_from_slice(&256_u64.to_be_bytes());
                bytes[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
                bytes[256..256 + name.len()].copy_from_slice(name.as_bytes());
            }
            std::fs::write(path, bytes).unwrap();
        }

        /// As root every file here is one root wrote, which a walk trusts.
        fn running_as_root() -> bool {
            unsafe { libc::geteuid() } == 0
        }

        #[test]
        fn the_header_names_its_backing_and_declared_format() {
            let dir = tempfile::tempdir().unwrap();
            let layer = dir.path().join("top.qcow2");
            qcow2(&layer, Some("base.raw"), true);
            let mut file = open(&layer).unwrap();
            assert_eq!(
                backing_of(&mut file).unwrap(),
                Some(("base.raw".to_string(), true))
            );
            qcow2(&layer, Some("/abs/base.qcow2"), false);
            let mut file = open(&layer).unwrap();
            assert_eq!(
                backing_of(&mut file).unwrap(),
                Some(("/abs/base.qcow2".to_string(), false))
            );
            std::fs::write(&layer, b"not a disk").unwrap();
            let mut file = open(&layer).unwrap();
            assert_eq!(backing_of(&mut file).unwrap(), None);
        }

        #[test]
        fn a_chain_the_owner_holds_needs_no_grant() {
            let dir = tempfile::tempdir().unwrap();
            let grants = dir.path().join("grants");
            let base = dir.path().join("base.qcow2");
            let top = dir.path().join("top.qcow2");
            qcow2(&base, None, false);
            qcow2(&top, Some("base.qcow2"), false);
            if running_as_root() {
                return;
            }
            let me = unsafe { libc::geteuid() };
            assert!(unadmitted_in(&grants, &top, None).is_empty());
            // Seen as another uid's chain, the same backing is foreign and
            // stays so until root records it for this layer.
            let other = me + 1;
            let found = unadmitted_in(&grants, &top, Some(other));
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].backing, base);
            record_in(&grants, &top, &base).unwrap();
            assert!(unadmitted_in(&grants, &top, Some(other)).is_empty());
        }

        #[test]
        fn a_rewritten_header_loses_its_grant() {
            if running_as_root() {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let grants = dir.path().join("grants");
            let given = dir.path().join("given.qcow2");
            let secret = dir.path().join("secret.raw");
            let top = dir.path().join("top.qcow2");
            qcow2(&given, None, false);
            std::fs::write(&secret, b"secret").unwrap();
            qcow2(&top, Some("given.qcow2"), false);
            record_in(&grants, &top, &given).unwrap();
            let other = unsafe { libc::geteuid() } + 1;
            assert!(unadmitted_in(&grants, &top, Some(other)).is_empty());

            // The VMM points its own top layer, same inode, somewhere else.
            let mut bytes = std::fs::read(&top).unwrap();
            let name = secret.to_str().unwrap();
            bytes[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
            bytes[256..256 + name.len()].copy_from_slice(name.as_bytes());
            std::fs::OpenOptions::new()
                .write(true)
                .open(&top)
                .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
                .unwrap();
            let found = unadmitted_in(&grants, &top, Some(other));
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].backing, secret);

            // A new file under the old name carries no grant either.
            std::fs::remove_file(&top).unwrap();
            qcow2(&top, Some("given.qcow2"), false);
            assert_eq!(unadmitted_in(&grants, &top, Some(other)).len(), 1);
        }

        #[test]
        fn a_raw_backing_ends_the_walk() {
            if running_as_root() {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let grants = dir.path().join("grants");
            // Raw bytes that look like a qcow2 naming something else.
            let base = dir.path().join("base.raw");
            qcow2(&base, Some("/etc/hostname"), false);
            let top = dir.path().join("top.qcow2");
            qcow2(&top, Some("base.raw"), true);
            record_in(&grants, &top, &base).unwrap();
            let other = unsafe { libc::geteuid() } + 1;
            assert!(unadmitted_in(&grants, &top, Some(other)).is_empty());
        }

        #[test]
        fn reconcile_backfills_once_and_drops_records_of_removed_layers() {
            let dir = tempfile::tempdir().unwrap();
            let grants = dir.path().join("grants");
            let vms = dir.path().join("vms");
            let vm = vms.join("0123456789abcdef");
            let generation = vm.join("d").join("g1");
            std::fs::create_dir_all(&generation).unwrap();
            let shared = dir.path().join("shared.qcow2");
            qcow2(&shared, None, false);
            let top = generation.join("storage.base.qcow2");
            qcow2(&top, Some(shared.to_str().unwrap()), false);

            // Same owner here, so nothing is foreign and nothing recorded,
            // but the pass marks the node backfilled.
            assert_eq!(reconcile_in(&grants, &vms).unwrap(), (0, 0));
            assert!(grants.join(BACKFILLED).exists());

            record_in(&grants, &top, &shared).unwrap();
            let record = grants.join(
                Identity::of(&std::fs::metadata(&top).unwrap()).file_name(),
            );
            assert!(record.exists());
            assert_eq!(reconcile_in(&grants, &vms).unwrap(), (0, 0));
            assert!(record.exists(), "a live layer keeps its record");

            std::fs::remove_file(&top).unwrap();
            // Age the record past the start of the next pass.
            let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
            File::options()
                .write(true)
                .open(&record)
                .unwrap()
                .set_modified(old)
                .unwrap();
            assert_eq!(reconcile_in(&grants, &vms).unwrap(), (0, 1));
            assert!(!record.exists());
        }
    }
}
