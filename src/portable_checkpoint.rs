//! Portable live-checkpoint compatibility and installation.
//!
//! A checkpoint file (`.checkpoint`) uses the ordinary pack container for files and disks,
//! plus a durable libkrun memory/device snapshot. The container can be copied
//! anywhere; live state is restored only under a versioned, fail-closed runtime
//! compatibility contract.

use crate::config::{RecordState, SmolvmConfig, VmRecord};
use crate::{Error, Result};
use imago::file::File as ImagoFile;
use imago::qcow2::Qcow2;
use imago::{FormatDriverBuilder, PermissiveImplicitOpenGate};
use sha2::{Digest, Sha256};
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::format::{
    CheckpointAsset, CheckpointCpuContract, CheckpointDisk, CheckpointDiskFile,
    CheckpointHostImage, CheckpointNetwork, CheckpointPackedLayers, CheckpointPort,
    CheckpointWorkload, PackManifest, PackMode, PortableCheckpointManifest,
};
use smolvm_pack::packer::Packer;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Current portable-checkpoint metadata version.
pub const FORMAT_VERSION: u32 = 4;
/// Format version of a checkpoint file that carries its history (a packed
/// checkpoint store, see `CheckpointLayout::Chunked`). Distinct from
/// [`FORMAT_VERSION`] so runtimes that predate history refuse such files with
/// a version message instead of failing on missing assets.
pub const HISTORY_FORMAT_VERSION: u32 = 5;
/// Format version of a `Chunked` file that holds only the objects its base
/// lacks. Runtimes that cannot complete one from its base refuse it by version.
pub const DELTA_FORMAT_VERSION: u32 = 6;
/// libkrun VM/vCPU/device-state compatibility identifier.
pub const RUNTIME_ABI: &str = "libkrun-portable-snapshot-v1";
/// Device topology supported by the initial portable checkpoint profile.
pub const DEVICE_PROFILE: &str = "smolvm-basic-v1";
/// The basic profile plus one read-only virtio-fs device serving a pack's image
/// layers. Distinct so a runtime that cannot re-attach the pack refuses the
/// checkpoint instead of resuming into a device layout it does not reproduce.
pub const DEVICE_PROFILE_PACKED_LAYERS: &str = "smolvm-packed-layers-v1";
const FIXED_MEMORY_OVERHEAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Directory inside an extracted artifact containing live state.
pub const ASSET_DIR: &str = "checkpoint";

const INSTALLED_DIR: &str = "portable-checkpoint";
const PENDING_MARKER: &str = "pending";
const RETAINED_MEMORY_BACKING: &str = ".portable-checkpoint-memory.bin";
pub(crate) const READONLY_INPUT_DIR: &str = ".restore-input";
const READONLY_INPUT_MARKER: &str = "readonly-memory";
/// Marker in a read-only RAM input whose bytes were still being written back
/// when it was installed; it names the boot that installed it.
#[cfg(target_os = "linux")]
const UNSYNCED_INPUT_MARKER: &str = "unsynced";
/// Suffix of the file beside a paused machine's data directory that records
/// its disk chains' identity once it has stopped.
const PAUSED_DISKS_SUFFIX: &str = ".paused-disks";
/// Suffix of the directory beside a paused machine's data directory that pins
/// the backing layers its pause artifact references instead of carrying.
const PAUSED_LAYERS_SUFFIX: &str = ".paused-layers";
/// The pinned layers' index inside that directory.
const PAUSED_LAYERS_INDEX: &str = "layers";
/// Service-owned tmpfs directory where a resume stages its checkpoint, so the
/// RAM image it hands the VMM is never written to disk.
#[cfg(target_os = "linux")]
const RESTORE_TMPFS_ROOT: &str = "/dev/shm/smolvm-restore";

/// [`RESTORE_TMPFS_ROOT`], created if needed, when it is usable: the service
/// runs as root, `/dev/shm` is tmpfs, and the directory is root-owned mode
/// 0700. `SMOLVM_RESTORE_TMPFS=0` disables it.
#[cfg(target_os = "linux")]
fn restore_tmpfs_root() -> Option<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    if std::env::var_os("SMOLVM_RESTORE_TMPFS").is_some_and(|value| value == "0")
        || unsafe { libc::geteuid() } != 0
    {
        return None;
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c"/dev/shm".as_ptr(), &mut stat) } != 0
        || stat.f_type != libc::TMPFS_MAGIC
    {
        return None;
    }
    let root = PathBuf::from(RESTORE_TMPFS_ROOT);
    match std::fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    restore_tmpfs_root_is_trusted(&root).then_some(root)
}

#[cfg(target_os = "linux")]
fn restore_tmpfs_root_is_trusted(root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(root).is_ok_and(|metadata| {
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o777 == 0o700
    })
}

/// Bytes free in the filesystem holding `path`.
#[cfg(target_os = "linux")]
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statvfs(path.as_ptr(), &mut stat) } == 0)
        .then(|| stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// Where a machine's read-only restore RAM input may live: its data directory,
/// or the restore tmpfs when the checkpoint was staged there.
fn readonly_input_dirs(vm_dir: &Path) -> Vec<PathBuf> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut dirs = vec![vm_dir.join(READONLY_INPUT_DIR)];
    #[cfg(target_os = "linux")]
    if let Some(name) = vm_dir.file_name() {
        let mut tmpfs_name = name.to_os_string();
        tmpfs_name.push(READONLY_INPUT_DIR);
        dirs.push(Path::new(RESTORE_TMPFS_ROOT).join(tmpfs_name));
    }
    dirs
}

fn remove_readonly_input(vm_dir: &Path) -> std::io::Result<()> {
    for dir in readonly_input_dirs(vm_dir) {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if staged_by_root_only(&dir, &error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Only root stages restore input on the shared tmpfs, and that directory is
/// root-owned mode 0700. Another user cannot look inside it, and none of their
/// machines' input can be there, so a denied lookup means there is nothing to
/// remove rather than a failed resume.
#[cfg(target_os = "linux")]
fn staged_by_root_only(dir: &Path, error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
        && dir.starts_with(RESTORE_TMPFS_ROOT)
        && unsafe { libc::geteuid() } != 0
}

#[cfg(not(target_os = "linux"))]
fn staged_by_root_only(_dir: &Path, _error: &std::io::Error) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn readonly_restore_supported() -> bool {
    if !crate::process::vm_uid_drop_active()
        || std::env::var_os("SMOLVM_DISABLE_READONLY_RESTORE").is_some()
    {
        return false;
    }
    crate::agent::find_lib_dir()
        .and_then(|dir| {
            // The same runtime discovery used by the launcher; old libraries retain
            // the ordinary private-copy installation path.
            unsafe { crate::agent::KrunFunctions::load(&dir) }.ok()
        })
        .is_some_and(|krun| krun.set_snapshot_memory_fd.is_some())
}

/// Link the extracted RAM image in as this machine's read-only restore input.
///
/// `sync_pending` says the extraction is still writing that image back in the
/// background. The input is then published with a marker naming this boot
/// instead of waiting for the write-back, and `deferred` (or, without one, a
/// write-back started here) clears the marker once the RAM is durable. Until
/// then a start after a host restart refuses the input rather than resuming
/// from RAM the restart may have lost.
#[cfg(target_os = "linux")]
fn stage_readonly_memory(
    source: &Path,
    vm_dir: &Path,
    asset: &CheckpointAsset,
    sync_pending: bool,
    deferred: Option<&mut DeferredRestoreSync>,
) -> Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !asset.sha256.is_empty() || !readonly_restore_supported() {
        return Ok(false);
    }
    let metadata = std::fs::symlink_metadata(source)?;
    if !metadata.is_file() || metadata.len() != asset.size {
        return Err(Error::agent(
            "retain restore RAM",
            "RAM image type or size mismatch",
        ));
    }
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Ok(false);
    }
    // An image extracted onto the restore tmpfs stays there: linking it into
    // the data directory would cross filesystems and fall back to a disk copy.
    let tmpfs = restore_tmpfs_root()
        .filter(|root| std::fs::metadata(root).is_ok_and(|root| root.dev() == metadata.dev()));
    let [on_disk, on_tmpfs]: [PathBuf; 2] = readonly_input_dirs(vm_dir)
        .try_into()
        .expect("disk and tmpfs input directories");
    let (parent, destination) = match &tmpfs {
        Some(root) => (root.as_path(), on_tmpfs),
        None => (vm_dir, on_disk),
    };
    let staging = tempfile::Builder::new()
        .prefix(".restore-input-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    let input = staging.path().join("memory.bin");
    match std::fs::hard_link(source, &input) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    // Durability still matters: the retained image must survive a service/host
    // restart between import and start. Subsequent cache hits sync clean pages.
    // While the extraction is still writing it back, the marker stands in.
    let memory = std::fs::File::open(&input)?;
    if sync_pending {
        smolvm_pack::extract::mark_unsynced(&staging.path().join(UNSYNCED_INPUT_MARKER))?;
    } else {
        memory.sync_all()?;
    }
    std::fs::File::open(staging.path())?.sync_all()?;
    if readonly_input_dirs(vm_dir)
        .iter()
        .any(|dir| std::fs::symlink_metadata(dir).is_ok())
    {
        return Err(Error::agent("retain restore RAM", "input already exists"));
    }
    std::fs::rename(staging.path(), &destination)?;
    std::fs::File::open(parent)?.sync_all()?;
    if sync_pending {
        match deferred {
            Some(deferred) => deferred.inputs.push((memory, destination)),
            None => DeferredRestoreSync {
                shared: None,
                inputs: vec![(memory, destination)],
            }
            .start(),
        }
    }
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn stage_readonly_memory(
    _: &Path,
    _: &Path,
    _: &CheckpointAsset,
    _: bool,
    _: Option<&mut DeferredRestoreSync>,
) -> Result<bool> {
    Ok(false)
}

/// Checkpoint RAM a restore installed before it reached the disk, still to be
/// written back: the shared extraction it came from and the machine inputs
/// linked to it. [`Self::start`] runs the write-back in the background and
/// clears each marker once its data is durable.
#[derive(Default)]
pub struct DeferredRestoreSync {
    shared: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    inputs: Vec<(std::fs::File, PathBuf)>,
}

impl DeferredRestoreSync {
    /// Write-back owed for `extracted`, if the extraction deferred it.
    pub fn for_extraction(extracted: &Path) -> Self {
        Self {
            shared: smolvm_pack::extract::memory_sync_pending(extracted)
                .then(|| extracted.to_path_buf()),
            #[cfg(target_os = "linux")]
            inputs: Vec::new(),
        }
    }

    /// Start the write-back on a background thread.
    ///
    /// Writing gigabytes back stalls every other fsync on the filesystem while
    /// it runs (an ext4 journal commit waits for it), including the installs of
    /// restores that arrived together with this one. So it waits a moment for
    /// those to finish first; the kernel's own write-back would start no sooner.
    pub fn start(self) {
        #[cfg(target_os = "linux")]
        {
            if self.shared.is_none() && self.inputs.is_empty() {
                return;
            }
            let run = move || {
                std::thread::sleep(DEFERRED_SYNC_GRACE);
                if let Some(shared) = &self.shared {
                    if let Err(error) = smolvm_pack::extract::sync_extracted_memory(shared) {
                        tracing::warn!(extraction = %shared.display(), %error, "checkpoint RAM could not be written to disk; it will be extracted again on next use");
                    }
                }
                for (memory, input_dir) in self.inputs {
                    clear_synced_input(&memory, &input_dir);
                }
            };
            if let Err(error) = std::thread::Builder::new()
                .name("restore-ram-sync".into())
                .spawn(run)
            {
                tracing::warn!(%error, "could not start checkpoint RAM write-back");
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = self.shared;
    }
}

/// Finish the write-backs an earlier run of this server deferred but did not
/// complete because it stopped first. Only markers written in this boot are
/// taken up: an earlier boot's mark RAM the restart may have lost, which must
/// keep refusing rather than be declared durable now.
pub fn resume_deferred_restore_syncs() {
    #[cfg(target_os = "linux")]
    {
        let current = |marker: &Path| {
            marker.exists() && !smolvm_pack::extract::unsynced_before_this_boot(marker)
        };
        let shared_root = crate::agent::shared_pack_cache_root();
        if let Ok(entries) = std::fs::read_dir(&shared_root) {
            for entry in entries.flatten() {
                let marker = entry.path();
                if marker.extension().is_some_and(|ext| ext == "unsynced") && current(&marker) {
                    DeferredRestoreSync::for_extraction(&marker.with_extension("")).start();
                }
            }
        }
        let mut inputs = Vec::new();
        if let Ok(entries) = std::fs::read_dir(crate::agent::vm_cache_root()) {
            for entry in entries.flatten() {
                let input_dir = entry.path().join(READONLY_INPUT_DIR);
                if current(&input_dir.join(UNSYNCED_INPUT_MARKER)) {
                    if let Ok(memory) = std::fs::File::open(input_dir.join("memory.bin")) {
                        inputs.push((memory, input_dir));
                    }
                }
            }
        }
        DeferredRestoreSync {
            shared: None,
            inputs,
        }
        .start();
    }
}

/// How long a deferred write-back waits for concurrent restores to install.
#[cfg(target_os = "linux")]
const DEFERRED_SYNC_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Clear a machine input's marker once its RAM is durable, unless the input
/// has since been replaced by another restore's.
#[cfg(target_os = "linux")]
fn clear_synced_input(memory: &std::fs::File, input_dir: &Path) {
    use std::os::unix::fs::MetadataExt;
    if let Err(error) =
        smolvm_pack::extract::write_back_paced(memory).and_then(|()| memory.sync_all())
    {
        tracing::warn!(input = %input_dir.display(), %error, "restore RAM could not be written to disk; a start after a host restart will refuse it");
        return;
    }
    let same_input = match (
        memory.metadata(),
        std::fs::symlink_metadata(input_dir.join("memory.bin")),
    ) {
        (Ok(ours), Ok(current)) => (ours.dev(), ours.ino()) == (current.dev(), current.ino()),
        _ => false,
    };
    if same_input {
        if let Err(error) =
            smolvm_pack::extract::clear_unsynced(&input_dir.join(UNSYNCED_INPUT_MARKER))
        {
            tracing::warn!(input = %input_dir.display(), %error, "could not clear restore RAM sync marker");
        }
    }
}

/// Open a retained RAM image while the boot process still has service privileges.
#[cfg(target_os = "linux")]
pub(crate) fn open_readonly_memory(vm_dir: &Path) -> Result<std::fs::File> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let [on_disk, on_tmpfs]: [PathBuf; 2] = readonly_input_dirs(vm_dir)
        .try_into()
        .expect("disk and tmpfs input directories");
    let input_dir = if std::fs::symlink_metadata(&on_disk).is_err()
        && std::fs::symlink_metadata(&on_tmpfs).is_ok()
    {
        if !restore_tmpfs_root_is_trusted(Path::new(RESTORE_TMPFS_ROOT)) {
            return Err(Error::agent(
                "open restore RAM",
                "restore tmpfs must be service-owned mode 0700",
            ));
        }
        on_tmpfs
    } else {
        on_disk
    };
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&input_dir)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err(Error::agent(
            "open restore RAM",
            "input directory must be service-owned mode 0700",
        ));
    }
    if smolvm_pack::extract::unsynced_before_this_boot(&input_dir.join(UNSYNCED_INPUT_MARKER)) {
        return Err(Error::agent(
            "open restore RAM",
            "this machine's checkpoint RAM had not reached the disk when the host restarted; \
             restore the checkpoint again",
        ));
    }
    // Anchor the lookup to the validated directory and never follow a symlink.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"memory.bin".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(Error::agent(
            "open restore RAM",
            "input must be a protected regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn has_readonly_memory(snapshot: &Path) -> bool {
    snapshot.join(READONLY_INPUT_MARKER).is_file()
}

/// Downgrading the runtime or explicitly requesting a leaf restore remains safe.
pub(crate) fn prepare_memory_backend(snapshot: &Path, branchable: bool) -> Result<()> {
    if !has_readonly_memory(snapshot) {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        if branchable && readonly_restore_supported() {
            return Ok(());
        }
        let vm_dir = snapshot
            .parent()
            .ok_or_else(|| Error::agent("prepare restore RAM", "missing VM directory"))?;
        let input = open_readonly_memory(vm_dir)?;
        use std::os::fd::AsRawFd;
        // Copy from the checked descriptor, not a second unvalidated path lookup.
        crate::disk_utils::clone_or_copy_file(
            Path::new(&format!("/proc/self/fd/{}", input.as_raw_fd())),
            &snapshot.join("memory.bin"),
        )?;
        std::fs::File::open(snapshot.join("memory.bin"))?.sync_all()?;
        std::fs::File::open(snapshot)?.sync_all()?;
        std::fs::remove_file(snapshot.join(READONLY_INPUT_MARKER))?;
        std::fs::File::open(snapshot)?.sync_all()?;
        remove_readonly_input(vm_dir)?;
        std::fs::File::open(vm_dir)?.sync_all()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = branchable;
        Err(Error::agent(
            "prepare restore RAM",
            "read-only input is Linux-only",
        ))
    }
}

// FINISH_SAVE consumes and closes its output file before replying. Only use
// this handoff after that reply, under the source lock. Taking ownership of the
// inode prevents the isolated VMM uid from reopening it after publication.
#[cfg(target_os = "linux")]
fn link_completed_memory(source: &Path, staged: &Path) -> Result<bool> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if unsafe { libc::geteuid() } != 0 {
        return Ok(false);
    }
    let file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(Error::agent(
            "stage checkpoint RAM",
            "memory image is not a regular file",
        ));
    }
    if before.nlink() != 1 {
        return Ok(false);
    }
    match std::fs::hard_link(source, staged) {
        Ok(()) => {}
        Err(error) if matches!(error.raw_os_error(), Some(libc::EXDEV | libc::EOPNOTSUPP)) => {
            return Ok(false)
        }
        Err(error) => return Err(error.into()),
    }
    let result = (|| -> std::io::Result<()> {
        let linked = std::fs::symlink_metadata(staged)?;
        if (linked.dev(), linked.ino()) != (before.dev(), before.ino()) {
            return Err(std::io::Error::other(
                "checkpoint RAM identity changed during staging",
            ));
        }
        if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(staged);
        return Err(error.into());
    }
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn link_completed_memory(_: &Path, _: &Path) -> Result<bool> {
    Ok(false)
}

/// How many restored checkpoints stay ready for a fast revisit, and within how
/// much space. Each entry holds a whole checkpoint's RAM and disks, so the count
/// alone could keep tens of GiB for large machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RestoreCache {
    /// Checkpoints kept; 0 turns the cache off.
    pub entries: usize,
    /// Allocated bytes the kept checkpoints may hold together.
    pub max_bytes: u64,
}

impl Default for RestoreCache {
    fn default() -> Self {
        Self {
            entries: 3,
            max_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
}

static PROCESS_RESTORE_CACHE: std::sync::OnceLock<RestoreCache> = std::sync::OnceLock::new();

/// Where a server records the restore cache policy it sized for this node.
const NODE_RESTORE_CACHE_POLICY: &str = ".restore-cache-policy.json";

impl RestoreCache {
    /// The policy this process set at startup with [`RestoreCache::set_process`];
    /// otherwise the one a server recorded for this node; otherwise the default.
    ///
    /// The cache belongs to the data directory, not to a process. Every smolvm
    /// process on a server's node trims it (a `machine delete` run by the image
    /// seed builder, for one), and with the small CLI default each such run cut
    /// the node's cache to three small checkpoints, throwing away every large
    /// restored checkpoint so the next restore unpacked it again.
    pub fn process() -> Self {
        PROCESS_RESTORE_CACHE
            .get()
            .copied()
            .or_else(|| Self::node_policy_in(&crate::agent::vm_cache_root()))
            .unwrap_or_default()
    }

    /// Record `self` as this node's policy, for every other smolvm process
    /// that shares the cache to follow.
    pub fn persist_for_node(self) -> std::io::Result<()> {
        self.persist_in(&crate::agent::vm_cache_root())
    }

    fn persist_in(self, cache_root: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(cache_root)?;
        let path = cache_root.join(NODE_RESTORE_CACHE_POLICY);
        let staging = cache_root.join(format!(
            "{NODE_RESTORE_CACHE_POLICY}.{}.tmp",
            std::process::id()
        ));
        std::fs::write(&staging, serde_json::to_vec(&self)?)?;
        std::fs::rename(&staging, &path)
    }

    fn node_policy_in(cache_root: &Path) -> Option<Self> {
        let raw = std::fs::read(cache_root.join(NODE_RESTORE_CACHE_POLICY)).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Set the policy [`RestoreCache::process`] returns. The first call wins.
    pub fn set_process(cache: Self) {
        let _ = PROCESS_RESTORE_CACHE.set(cache);
    }
}

/// Default space for captured checkpoints kept beside their extraction so a
/// restore on the same host skips the download.
pub const DEFAULT_PREPARED_CHECKPOINT_BUDGET: u64 = 8 * 1024 * 1024 * 1024;

static PROCESS_PREPARED_CHECKPOINT_BUDGET: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Space this process keeps for prepared captures: what it set at startup with
/// [`set_prepared_checkpoint_budget`], or [`DEFAULT_PREPARED_CHECKPOINT_BUDGET`].
pub fn prepared_checkpoint_budget() -> u64 {
    PROCESS_PREPARED_CHECKPOINT_BUDGET
        .get()
        .copied()
        .unwrap_or(DEFAULT_PREPARED_CHECKPOINT_BUDGET)
}

/// Set the budget [`prepared_checkpoint_budget`] returns. The first call wins.
pub fn set_prepared_checkpoint_budget(bytes: u64) {
    let _ = PROCESS_PREPARED_CHECKPOINT_BUDGET.set(bytes);
}

/// Materialize a stored checkpoint for restore, diffing against the node's
/// bounded cache of pristine checkpoint materializations. Exact revisits clone
/// without rewriting RAM; misses diff against a recent checkpoint. Both the CLI
/// and API use the same cache policy; `restore_cache` bounds it, and zero entries
/// disables retention and falls back to the legacy base.
pub fn materialize_for_restore(
    artifact: &Path,
    cache_dir: &Path,
    restore_cache: RestoreCache,
) -> Result<()> {
    materialize_for_restore_at(artifact, cache_dir, None, restore_cache)
}

/// [`materialize_for_restore`] for a retained ancestor generation. Ancestors
/// skip the restore base: the base tracks the checkpoint's own generation.
pub fn materialize_for_restore_at(
    artifact: &Path,
    cache_dir: &Path,
    generation: Option<&str>,
    restore_cache: RestoreCache,
) -> Result<()> {
    if let Some(generation) = generation {
        return crate::checkpoint_store::materialize_at(artifact, generation, cache_dir)
            .map(|_| ())
            .map_err(|error| Error::agent("materialize checkpoint generation", error.to_string()));
    }
    let base = crate::agent::restore_base_dir();
    let cache = base.with_file_name("_restore-checkpoints");
    crate::checkpoint_store::materialize_cached(
        artifact,
        cache_dir,
        &cache,
        Some(&base),
        restore_cache.entries,
        restore_cache.max_bytes,
    )
    .map_err(|error| Error::agent("materialize checkpoint", error.to_string()))?;
    Ok(())
}

/// Read a pending restore's RAM file into the page cache on a background
/// thread. Restored guest RAM is mapped lazily, so the first commands after
/// boot otherwise page it in from disk: about 0.6 s for a 2 GiB desktop, against
/// 0.05 s once cached. Started before boot so the read overlaps it; best-effort,
/// and a read cut short when the process exits only leaves pages to fault in.
pub fn prefetch_restore_memory(vm_data_dir: &Path) {
    let Some(dir) = pending_dir(vm_data_dir) else {
        return;
    };
    let path = dir.join("memory.bin");
    std::thread::spawn(move || {
        use std::io::Read;
        let started = std::time::Instant::now();
        let Ok(mut file) = std::fs::File::open(&path) else {
            return;
        };
        let mut buffer = vec![0u8; 8 << 20];
        let mut bytes = 0u64;
        while let Ok(read) = file.read(&mut buffer) {
            if read == 0 {
                break;
            }
            bytes += read as u64;
        }
        tracing::debug!(
            bytes,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "prefetched restore memory"
        );
    });
}

/// Log how long one checkpoint phase took and restart the clock for the next.
pub fn log_phase(name: &str, phase: &str, started: &mut std::time::Instant) {
    tracing::info!(
        machine = name,
        phase,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "checkpoint phase completed"
    );
    *started = std::time::Instant::now();
}

/// Optional host paths used while building a portable checkpoint artifact.
#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    /// Maximum unreferenced prepared-checkpoint bytes to retain on this node.
    pub prepared_cache_budget_bytes: Option<u64>,
    /// Reuse content-addressed objects in this directory and publish a
    /// self-contained checkpoint directory instead of a compressed file.
    pub store_dir: Option<PathBuf>,
    /// Disk-backed directory used for the temporary, uncompressed image.
    pub staging_dir: Option<PathBuf>,
    /// Directory containing libkrun and libkrunfw.
    pub lib_dir: Option<PathBuf>,
    /// Directory containing the guest agent root filesystem.
    pub rootfs_dir: Option<PathBuf>,
}

/// Timings and size returned by a completed portable checkpoint capture.
#[derive(Debug, Clone)]
pub struct CaptureResult {
    /// Logical bytes reused from earlier checkpoints (zero for standalone exports).
    pub reused_bytes: u64,
    /// Compressed artifact size, or new compressed object bytes for a store capture.
    pub size_bytes: u64,
    /// Time for which the source's vCPUs and disks were frozen.
    pub source_pause: std::time::Duration,
    /// Complete capture and compression time.
    pub elapsed: std::time::Duration,
}

/// Restore a portable live checkpoint into a new stopped machine record.
///
/// The restored machine preserves the checkpoint's CPU, memory, disks,
/// workload, and network topology. Its first start resumes the captured live
/// state, and the machine remains checkpointable so it can immediately serve
/// as a reusable rollback/fork root.
pub fn restore_from_path(db: &crate::db::SmolvmDb, name: &str, artifact: &Path) -> Result<()> {
    restore_from_path_at(db, name, artifact, None)
}

/// Resolve `--at` against a checkpoint: `None` (or `~0`) is the checkpoint's
/// own generation; anything else must name an ancestor a stored checkpoint
/// retains. A single-file checkpoint holds exactly one generation.
pub fn resolve_generation(artifact: &Path, at: Option<&str>) -> Result<Option<String>> {
    let Some(at) = at.map(str::trim).filter(|at| !at.is_empty()) else {
        return Ok(None);
    };
    if artifact.is_dir() {
        return crate::checkpoint_store::resolve_generation(artifact, at)
            .map_err(|error| Error::config("checkpoint generation", error.to_string()));
    }
    if at == "~0" {
        return Ok(None);
    }
    Err(Error::config(
        "checkpoint generation",
        "a single-file checkpoint holds one generation; earlier ones are kept only by \
         checkpoints captured with --store",
    ))
}

/// If `artifact` is a single file carrying its history (`Chunked` payload),
/// unpack it into a private directory checkpoint and return that directory;
/// restore and export then treat it exactly like a stored checkpoint. `None`
/// for directories and classic single-generation files.
pub fn unpack_history_file(artifact: &Path) -> Result<Option<tempfile::TempDir>> {
    if !artifact.is_file() {
        return Ok(None);
    }
    // Integrity first: nothing in the file is parsed before its checksum holds.
    verified_sidecar_footer(artifact)?;
    unpack_verified_history_file(artifact)
}

/// [`unpack_history_file`] for a file whose checksum the caller has already
/// verified, so the file is read only once more.
pub fn unpack_verified_history_file(artifact: &Path) -> Result<Option<tempfile::TempDir>> {
    let manifest = smolvm_pack::packer::read_manifest_from_sidecar(artifact)
        .map_err(|error| Error::agent("read checkpoint manifest", error.to_string()))?;
    let Some(checkpoint) = manifest.checkpoint.as_ref() else {
        return Ok(None);
    };
    let footer = ensure_checkpoint_layout(artifact)?;
    if checkpoint.payload != smolvm_pack::format::CheckpointLayout::Chunked {
        return Ok(None);
    }
    validate_compatibility(checkpoint)?;
    let root = crate::agent::vm_cache_root().join("checkpoint-unpack");
    std::fs::create_dir_all(&root)
        .map_err(|error| Error::agent("prepare checkpoint unpack", error.to_string()))?;
    let directory = tempfile::Builder::new()
        .prefix(".unpack-")
        .tempdir_in(&root)
        .map_err(|error| Error::agent("prepare checkpoint unpack", error.to_string()))?;
    smolvm_pack::extract::unpack_checkpoint_history(artifact, &footer, directory.path())
        .map_err(|error| Error::agent("unpack checkpoint history", error.to_string()))?;
    if !directory.path().join("checkpoint.json").is_file() {
        return Err(Error::agent(
            "unpack checkpoint history",
            "the file's payload is not a checkpoint store",
        ));
    }
    Ok(Some(directory))
}

/// Export from a stored checkpoint (or a history file): one generation when
/// `at` is given, otherwise a single file carrying up to `history` earlier
/// generations. Returns the file size and how many earlier generations it
/// carries.
pub fn export_checkpoint(
    source: &Path,
    at: Option<&str>,
    history: usize,
    output: &Path,
) -> Result<(u64, usize)> {
    let unpacked = unpack_history_file(source)?;
    let source: &Path = unpacked.as_ref().map(|d| d.path()).unwrap_or(source);
    if !source.is_dir() {
        return Err(Error::config(
            "export checkpoint",
            "the source must be a stored checkpoint directory or a file that carries its history",
        ));
    }
    if let Some(at) = at {
        let generation = resolve_generation(source, Some(at))?;
        return crate::checkpoint_store::export_at(source, generation.as_deref(), output)
            .map(|bytes| (bytes, 0))
            .map_err(|error| Error::agent("export checkpoint", error.to_string()));
    }
    crate::checkpoint_store::export_with_history(source, history, output, |manifest| {
        if let Some(checkpoint) = manifest.checkpoint.as_mut() {
            checkpoint.version = HISTORY_FORMAT_VERSION;
        }
    })
    .map_err(|error| Error::agent("export checkpoint", error.to_string()))
}

/// [`restore_from_path`] at a chosen generation (see [`resolve_generation`]).
pub fn restore_from_path_at(
    db: &crate::db::SmolvmDb,
    name: &str,
    artifact: &Path,
    at: Option<&str>,
) -> Result<()> {
    let mut phase = std::time::Instant::now();
    crate::data::validate_vm_name(name, "machine name")
        .map_err(|reason| Error::config("restore checkpoint", reason))?;
    if !artifact.is_file() && !artifact.is_dir() {
        return Err(Error::config(
            "restore checkpoint",
            format!("file not found: {}", artifact.display()),
        ));
    }

    let footer = if artifact.is_file() {
        Some(verified_sidecar_footer(artifact)?)
    } else {
        None
    };
    // A verified history file becomes a directory checkpoint for the rest of
    // the restore; classic files and directories pass through unchanged.
    let unpacked = match footer {
        Some(_) => unpack_verified_history_file(artifact)?,
        None => None,
    };
    let artifact: &Path = unpacked.as_ref().map(|d| d.path()).unwrap_or(artifact);
    let footer = if unpacked.is_some() { None } else { footer };
    let generation = resolve_generation(artifact, at)?;
    let manifest = if footer.is_none() {
        crate::checkpoint_store::read_manifest_at(artifact, generation.as_deref())
            .map_err(|error| Error::agent("read stored checkpoint", error.to_string()))?
    } else {
        smolvm_pack::packer::read_manifest_from_sidecar(artifact)
            .map_err(|error| Error::agent("read checkpoint manifest", error.to_string()))?
    };
    let checkpoint = manifest.checkpoint.as_ref().ok_or_else(|| {
        Error::config(
            "restore checkpoint",
            format!("{} is not a checkpoint", artifact.display()),
        )
    })?;
    validate_compatibility(checkpoint)?;
    crate::platform::ensure_artifact_arch_matches_host(&manifest.platform)?;
    log_phase(name, "restore_verify", &mut phase);

    // Reserve the name before touching its data directory. SDKs and CLIs may
    // run in separate processes, so a process-local lifecycle mutex is not a
    // sufficient creation boundary.
    let token = crate::db::SmolvmDb::create_reservation_token();
    if !db.reserve_vm_create(name, &token)? {
        return Err(Error::agent_conflict(
            "restore checkpoint",
            format!("machine '{name}' already exists or is being created"),
        ));
    }
    let mut reservation = RestoreReservation {
        db: db.clone(),
        name: name.to_string(),
        token,
        committed: false,
    };

    let mut record = restored_record(name, &manifest, checkpoint)?;
    let vm_data = crate::agent::vm_data_dir(name);
    let cache_dir = crate::agent::machine_layers_cache_dir(name);
    let result = (|| -> Result<()> {
        let _manager = crate::agent::AgentManager::for_vm_with_sizes(
            name,
            checkpoint.storage_gib,
            checkpoint.overlay_gib,
        )?;
        smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
        match std::fs::remove_dir_all(&cache_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::agent(
                    "clear checkpoint extraction",
                    error.to_string(),
                ));
            }
        }
        log_phase(name, "restore_prepare", &mut phase);
        if let Some(footer) = &footer {
            smolvm_pack::extract::extract_sidecar(artifact, &cache_dir, footer, false, false)
                .map_err(|error| Error::agent("extract checkpoint", error.to_string()))?;
        } else {
            materialize_for_restore_at(
                artifact,
                &cache_dir,
                generation.as_deref(),
                RestoreCache::process(),
            )?;
        }
        log_phase(name, "restore_extract", &mut phase);
        install(&cache_dir, &vm_data, checkpoint)?;
        log_phase(name, "restore_install", &mut phase);
        discard_transport_pack(&vm_data)?;
        if let Some((sidecar, reference)) = attach_cached_checkpoint_pack(name, checkpoint)? {
            record.source_smolmachine = Some(sidecar);
            record.source_registry_ref = reference;
        }
        if let Some(image) = fetch_checkpoint_host_image_blocking(checkpoint)? {
            image.apply(&mut record);
        }
        if !reservation
            .db
            .commit_reserved_vm(name, &reservation.token, &record)?
        {
            return Err(Error::agent_conflict(
                "restore checkpoint",
                format!("machine '{name}' is no longer reserved"),
            ));
        }
        reservation.committed = true;
        Ok(())
    })();
    smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
    if let Err(error) = result {
        if let Err(remove_error) = std::fs::remove_dir_all(&vm_data) {
            if remove_error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    machine = %name,
                    error = %remove_error,
                    "failed to clean checkpoint restore after error"
                );
            }
        }
        return Err(error);
    }
    Ok(())
}

/// The file extension a checkpoint is written with.
pub const CHECKPOINT_EXTENSION: &str = "checkpoint";

/// Whether `path` names a checkpoint output: `.checkpoint`, or the earlier
/// `.smolcheckpoint`, which stays accepted. Readers never depend on the name.
pub fn has_checkpoint_extension(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case(CHECKPOINT_EXTENSION)
            || extension.eq_ignore_ascii_case("smolcheckpoint")
    })
}

/// Require the exact layout a checkpoint writer produces: the payload at
/// offset 0, the manifest right after it, and the footer ending the file.
/// Every byte of such a file except the footer is covered by the checksum.
/// The general pack reader tolerates other layouts, which a checkpoint never
/// has.
pub fn ensure_checkpoint_layout(artifact: &Path) -> Result<smolvm_pack::format::PackFooter> {
    let footer = smolvm_pack::packer::read_footer_from_sidecar(artifact)
        .map_err(|error| Error::agent("read checkpoint footer", error.to_string()))?;
    let len = std::fs::metadata(artifact)
        .map_err(|error| Error::agent("inspect checkpoint artifact", error.to_string()))?
        .len();
    check_checkpoint_layout(&footer, len)?;
    Ok(footer)
}

fn check_checkpoint_layout(footer: &smolvm_pack::format::PackFooter, len: u64) -> Result<()> {
    let expected = footer
        .assets_size
        .checked_add(footer.manifest_size)
        .and_then(|end| end.checked_add(smolvm_pack::format::FOOTER_SIZE as u64));
    if footer.stub_size != 0
        || footer.assets_offset != 0
        || footer.manifest_offset != footer.assets_size
        || expected != Some(len)
    {
        return Err(Error::agent(
            "verify checkpoint layout",
            "not a checkpoint layout: expected payload, manifest and footer with nothing between or after them",
        ));
    }
    Ok(())
}

/// Verify a single-file artifact before reading its manifest or extracting it.
pub fn verified_sidecar_footer(artifact: &Path) -> Result<smolvm_pack::format::PackFooter> {
    #[cfg(unix)]
    if let Some(footer) = remembered_verification(artifact) {
        return Ok(footer);
    }
    let verified = verify_sidecar_pinned(artifact)?;
    #[cfg(unix)]
    remember_verification(artifact, &verified);
    Ok(verified.footer)
}

/// Footers this process verified in full, by the exact inode it read. A
/// server creating many machines from one pack verifies it once instead of
/// reading the whole pack on every create (#1454).
#[cfg(unix)]
static VERIFIED_SIDECARS: std::sync::Mutex<
    Vec<(SidecarIdentity, smolvm_pack::format::PackFooter)>,
> = std::sync::Mutex::new(Vec::new());

/// Bound on remembered verifications; the oldest is forgotten first.
#[cfg(unix)]
const MAX_VERIFIED_SIDECARS: usize = 64;

/// A remembered verification that still covers `artifact`: the same inode,
/// unchanged, and writable by nobody but the service, so its bytes are the
/// ones that were verified.
#[cfg(unix)]
fn remembered_verification(artifact: &Path) -> Option<smolvm_pack::format::PackFooter> {
    if !smolvm_pack::extract::only_service_can_write(artifact) {
        return None;
    }
    let identity = SidecarIdentity::of(&std::fs::File::open(artifact).ok()?).ok()?;
    let verified = VERIFIED_SIDECARS.lock().ok()?;
    verified
        .iter()
        .find(|(known, _)| *known == identity)
        .map(|(_, footer)| *footer)
}

/// Remember a full verification if nobody but the service could write the
/// artifact while it was read. (Its identity was stable across the read.)
#[cfg(unix)]
fn remember_verification(artifact: &Path, verified: &VerifiedSidecar) {
    if !smolvm_pack::extract::only_service_can_write(artifact) || !verified.covers(artifact) {
        return;
    }
    let Ok(mut remembered) = VERIFIED_SIDECARS.lock() else {
        return;
    };
    remembered.retain(|(known, _)| *known != verified.identity);
    if remembered.len() >= MAX_VERIFIED_SIDECARS {
        remembered.remove(0);
    }
    remembered.push((verified.identity, verified.footer));
}

/// The exact inode a verification read, as the kernel reports it. `ctime` is
/// kernel-maintained and moves on every content write, relink, unlink or
/// timestamp change, so an equal identity means the same unchanged bytes.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SidecarIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

#[cfg(unix)]
impl SidecarIdentity {
    fn of(file: &std::fs::File) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|error| Error::agent("inspect checkpoint artifact", error.to_string()))?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

/// A single-file artifact whose footer checksum was verified through a
/// descriptor the holder keeps open, pinning the very inode that was read.
///
/// This exists so one request can verify a cached artifact once and hand the
/// result to the machine-creation path without a second full pass over the
/// payload. Reuse is bound to the inode, never to a path or cache key:
/// [`VerifiedSidecar::covers`] must hold for the path about to be used, or
/// that path is verified from scratch.
#[derive(Debug)]
pub struct VerifiedSidecar {
    file: std::fs::File,
    footer: smolvm_pack::format::PackFooter,
    #[cfg(unix)]
    identity: SidecarIdentity,
    /// SHA-256 of the same bytes, when it was taken while they were received.
    sha256: Option<String>,
}

pub(crate) enum SidecarVerification {
    Stable(VerifiedSidecar),
    #[cfg(unix)]
    ChangedDuringRead,
}

/// Open `artifact` read-only and verify its footer checksum through that
/// descriptor. Fails if the inode changed while it was being read.
pub fn verify_sidecar_pinned(artifact: &Path) -> Result<VerifiedSidecar> {
    match classify_sidecar_verification(artifact)? {
        SidecarVerification::Stable(verified) => Ok(verified),
        #[cfg(unix)]
        SidecarVerification::ChangedDuringRead => Err(Error::agent(
            "verify checkpoint checksum",
            format!("{} changed while it was being verified", artifact.display()),
        )),
    }
}

pub(crate) fn classify_sidecar_verification(artifact: &Path) -> Result<SidecarVerification> {
    classify_sidecar_verification_after_read(artifact, || {})
}

fn classify_sidecar_verification_after_read(
    artifact: &Path,
    after_read: impl FnOnce(),
) -> Result<SidecarVerification> {
    let mut file = std::fs::File::open(artifact)
        .map_err(|error| Error::agent("read checkpoint footer", error.to_string()))?;
    #[cfg(unix)]
    let before = SidecarIdentity::of(&file)?;
    let footer = smolvm_pack::packer::read_footer_from_file(&mut file)
        .map_err(|error| Error::agent("read checkpoint footer", error.to_string()))?;
    if !smolvm_pack::packer::verify_sidecar_checksum_file(&mut file, &footer)
        .map_err(|error| Error::agent("verify checkpoint checksum", error.to_string()))?
    {
        return Err(Error::agent(
            "verify checkpoint checksum",
            format!("checksum mismatch for {}", artifact.display()),
        ));
    }
    after_read();
    #[cfg(unix)]
    let identity = {
        let after = SidecarIdentity::of(&file)?;
        if after != before {
            return Ok(SidecarVerification::ChangedDuringRead);
        }
        after
    };
    Ok(SidecarVerification::Stable(VerifiedSidecar {
        file,
        footer,
        #[cfg(unix)]
        identity,
        sha256: None,
    }))
}

/// Verification of a checkpoint the service has just written itself, from
/// checksums taken over the bytes as they were written, so it is not read
/// back. `None` whenever those checksums cannot stand in for a read of the
/// file: another layout than a checkpoint's, a checksum mismatch, or a file
/// someone other than the service could have written. The caller then
/// verifies it the ordinary way, which also reports any mismatch.
#[cfg(unix)]
pub fn verified_from_received(
    artifact: &Path,
    hashes: &smolvm_pack::extract::ReceivedArtifactHashes,
    service_only_since_creation: bool,
) -> Option<VerifiedSidecar> {
    if !service_only_since_creation || !smolvm_pack::extract::only_service_can_write(artifact) {
        return None;
    }
    let mut file = std::fs::File::open(artifact).ok()?;
    let before = SidecarIdentity::of(&file).ok()?;
    if before.len != hashes.len {
        return None;
    }
    let footer = smolvm_pack::packer::read_footer_from_file(&mut file).ok()?;
    // In a checkpoint's layout the footer checksum covers every byte before
    // the footer, which is exactly what the stream's CRC covered.
    check_checkpoint_layout(&footer, before.len).ok()?;
    if hashes.crc32_before_footer != Some(footer.checksum) {
        return None;
    }
    if SidecarIdentity::of(&file).ok()? != before
        || !smolvm_pack::extract::only_service_can_write(artifact)
    {
        return None;
    }
    Some(VerifiedSidecar {
        file,
        footer,
        identity: before,
        sha256: Some(hashes.sha256.clone()),
    })
}

/// Hashes taken while receiving are not trusted on this platform, so the
/// artifact is always read again to verify it.
#[cfg(not(unix))]
pub fn verified_from_received(
    _: &Path,
    _: &smolvm_pack::extract::ReceivedArtifactHashes,
    _: bool,
) -> Option<VerifiedSidecar> {
    None
}

impl VerifiedSidecar {
    /// The same proof over a duplicate of the pinned descriptor, for another
    /// request using the very same inode. Reuse still requires [`Self::covers`].
    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            footer: self.footer,
            #[cfg(unix)]
            identity: self.identity,
            sha256: self.sha256.clone(),
        })
    }

    /// The SHA-256 taken while this artifact was received, bound to the
    /// pinned inode, for the shared extraction to use instead of hashing the
    /// file again. Only meaningful after [`Self::covers`] held for the path.
    pub(crate) fn digest_proof(&self) -> Option<smolvm_pack::extract::ArtifactDigestProof> {
        #[cfg(unix)]
        {
            let digest = self.sha256.clone()?;
            let file = self.file.try_clone().ok()?;
            let proof =
                smolvm_pack::extract::ArtifactDigestProof::received(file, digest, true).ok()?;
            // The proof records the inode as it is now; it must still be the
            // one whose bytes were hashed.
            (SidecarIdentity::of(&self.file).ok()? == self.identity).then_some(proof)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// The verified footer.
    pub fn footer(&self) -> &smolvm_pack::format::PackFooter {
        &self.footer
    }

    /// Whether `path` currently names exactly the inode this verification read,
    /// and that inode is unchanged since (device, inode, length, mtime and ctime
    /// all equal, for both the pinned descriptor and a fresh open of `path`).
    /// A replacement at `path`, an in-place write, a relink, an unlink of any
    /// other name (eviction) or a timestamp change all make this false, and the
    /// caller must then verify `path` afresh. Never true off Unix.
    pub fn covers(&self, path: &Path) -> bool {
        #[cfg(unix)]
        {
            let pinned = SidecarIdentity::of(&self.file).ok() == Some(self.identity);
            let current = std::fs::File::open(path)
                .ok()
                .and_then(|file| SidecarIdentity::of(&file).ok())
                == Some(self.identity);
            pinned && current
        }
        #[cfg(not(unix))]
        {
            let _ = (path, &self.file);
            false
        }
    }
}

struct RestoreReservation {
    db: crate::db::SmolvmDb,
    name: String,
    token: String,
    committed: bool,
}

impl Drop for RestoreReservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self
                .db
                .release_vm_create_reservation(&self.name, &self.token)
            {
                tracing::warn!(
                    machine = %self.name,
                    %error,
                    "failed to release checkpoint restore reservation"
                );
            }
        }
    }
}

/// Guest subnet a checkpoint must be restored on.
///
/// The restored guest keeps its captured address in memory, so the host side
/// of the link has to come back on the same subnet, whatever the restore asks.
pub fn restored_guest_subnet(checkpoint: &PortableCheckpointManifest) -> Result<Option<String>> {
    checkpoint
        .network
        .as_ref()
        .and_then(|network| network.guest_subnet.as_deref())
        .map(|subnet| {
            subnet
                .parse::<smolvm_network::GuestSubnet>()
                .map(|subnet| subnet.to_string())
                .map_err(|error| Error::config("restore checkpoint guest subnet", error))
        })
        .transpose()
}

fn restored_record(
    name: &str,
    manifest: &PackManifest,
    checkpoint: &PortableCheckpointManifest,
) -> Result<VmRecord> {
    let network = checkpoint.network.as_ref();
    let mut record = VmRecord::new(
        name.to_string(),
        checkpoint.cpus,
        checkpoint.memory_mib,
        Vec::new(),
        network
            .into_iter()
            .flat_map(|network| network.ports.iter())
            .map(|port| (port.host, port.guest))
            .collect(),
        network.is_some_and(|network| network.enabled),
    );
    record.storage_gb = checkpoint.storage_gib;
    record.overlay_gb = checkpoint.overlay_gib;
    record.allowed_cidrs = network.and_then(|network| network.allowed_cidrs.clone());
    record.dns_filter_hosts = network.and_then(|network| network.dns_filter_hosts.clone());
    if let Some(policy) = network.and_then(|network| network.credential_policy.clone()) {
        // The artifact is untrusted: hold its policy to the same rules create
        // enforces, so a hand-edited checkpoint cannot carry a shape the CLI
        // would refuse. The policy holds no secrets — values are resolved from
        // this host's environment at request time — and the placeholders come
        // along unchanged so the captured workload's copies keep matching.
        policy
            .validate(record.dns_filter_hosts.as_deref())
            .map_err(|error| Error::config("restore checkpoint credentials", error.to_string()))?;
        record.credential_placeholders = network
            .map(|network| network.credential_placeholders.clone())
            .unwrap_or_default();
        record.credential_policy = Some(policy);
    }
    record.network_backend = restored_network_backend(checkpoint)?;
    record.dns = network
        .and_then(|network| network.dns.as_deref())
        .map(str::parse)
        .transpose()
        .map_err(|error: std::net::AddrParseError| {
            Error::config("restore checkpoint DNS", error.to_string())
        })?;
    record.network_name = network.and_then(|network| network.network_name.clone());
    record.guest_subnet = restored_guest_subnet(checkpoint)?;
    // The restored machine continues this checkpoint's history.
    record.checkpoint_head = checkpoint
        .lineage
        .as_ref()
        .map(|lineage| lineage.id.clone());
    record.entrypoint = manifest.entrypoint.clone();
    record.cmd = manifest.cmd.clone();
    record.env = crate::util::parse_env_list(&manifest.env);
    record.workdir = manifest.workdir.clone();
    record.secret_refs = manifest.secret_refs.clone();
    for (key, reference) in &record.secret_refs {
        crate::secrets::validate_ref(reference, crate::secrets::ResolutionScope::Untrusted)
            .map_err(|error| {
                Error::config(
                    "restore checkpoint",
                    format!("secret '{key}': {error} (checkpoints may not carry host secret refs)"),
                )
            })?;
    }
    if let Some(workload) = &checkpoint.workload {
        record.image = Some(workload.image.clone());
        record.user = workload.user.clone();
        record.fork_overlay_owner = Some(workload.overlay_owner.clone());
        record.restart.policy = workload
            .restart_policy
            .parse()
            .map_err(|error: String| Error::config("restore checkpoint restart policy", error))?;
        record.restart.max_retries = workload.restart_max_retries;
        record.restart.max_backoff_secs = workload.restart_max_backoff_secs;
    }
    // The live guest already contains the initialized workload. Re-running
    // image pull/init on its first start would duplicate side effects.
    record.init_completed = true;
    record.forkable = true;
    record.host_uid_owner = Some(name.to_string());
    Ok(record)
}

struct SavedVmPause {
    control: PathBuf,
    prepared_save: Option<PathBuf>,
    armed: bool,
}

impl SavedVmPause {
    fn stop(&mut self, name: &str, record: &VmRecord) -> Result<()> {
        crate::agent::AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)?
            .stop_paused()?;
        self.armed = false;
        Ok(())
    }

    fn resume(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        let reply = crate::agent::fork::control_socket_cmd(&self.control, "RESUME")?;
        if !reply.starts_with("OK") {
            return Err(Error::agent(
                "resume checkpoint source",
                format!("libkrun returned: {reply}"),
            ));
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for SavedVmPause {
    fn drop(&mut self) {
        if self.armed {
            match crate::agent::fork::control_socket_cmd(&self.control, "RESUME") {
                Ok(reply) if reply.starts_with("OK") => {}
                Ok(reply) => tracing::warn!(%reply, "failed to resume checkpoint source"),
                Err(error) => tracing::warn!(%error, "failed to resume checkpoint source"),
            }
        }
        if let Some(dir) = self.prepared_save.take() {
            let _ = crate::agent::fork::control_socket_cmd(
                &self.control,
                &format!("CANCEL_SAVE {}", dir.display()),
            );
        }
    }
}

fn staging_root(options: &CaptureOptions) -> Result<PathBuf> {
    let root = options
        .staging_dir
        .clone()
        .or_else(|| std::env::var_os("SMOLVM_PACK_STAGING").map(PathBuf::from))
        .or_else(|| dirs::cache_dir().map(|cache| cache.join("smolvm")))
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&root)
        .map_err(|error| Error::agent("create checkpoint staging root", error.to_string()))?;
    Ok(root)
}

// SAVE runs in the already-confined VMM, not in the privileged API service.
// Its output must be inside the machine's writable directory and owned by the
// same lineage UID. Never grant the VMM access to service-owned pack libraries.
fn runtime_capture_dir(name: &str, vm: &VmRecord) -> Result<tempfile::TempDir> {
    let data = crate::agent::vm_data_dir(name);
    let owner = vm.vm_uid_owner().unwrap_or(name);
    let owner_data = crate::agent::vm_data_dir(owner);
    let ids = crate::process::vm_drop_ids(
        &crate::agent::vm_uid_registry_dir(),
        &data,
        None,
        Some(&owner_data),
    )
    .transpose()
    .map_err(|error| Error::agent("resolve checkpoint uid", error.to_string()))?;
    runtime_capture_dir_at(&data, ids)
}

/// Service-owned tmpfs directory for transient runtime captures. Searchable
/// (0711) so a VMM running as its own uid can reach the private directory
/// made for it inside.
#[cfg(target_os = "linux")]
const CAPTURE_TMPFS_ROOT: &str = "/dev/shm/smolvm-capture";

/// The tmpfs capture root, created if needed, when it is usable: the caller
/// runs as root, `/dev/shm` is tmpfs, and the directory is root-owned 0711.
#[cfg(target_os = "linux")]
pub fn capture_tmpfs_root() -> Option<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let root = PathBuf::from(CAPTURE_TMPFS_ROOT);
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let usable = unsafe { libc::geteuid() } == 0
        && unsafe { libc::statfs(c"/dev/shm".as_ptr(), &mut stat) } == 0
        && stat.f_type == libc::TMPFS_MAGIC
        && match std::fs::DirBuilder::new().mode(0o711).create(&root) {
            Ok(()) => true,
            Err(error) => error.kind() == std::io::ErrorKind::AlreadyExists,
        }
        && std::fs::symlink_metadata(&root).is_ok_and(|metadata| {
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o777 == 0o711
        });
    usable.then_some(root)
}

/// The tmpfs capture root for a VMM's filesystem confinement: created when
/// still privileged, granted whenever it exists as a directory.
#[cfg(target_os = "linux")]
pub(crate) fn capture_tmpfs_grant() -> Option<PathBuf> {
    capture_tmpfs_root().or_else(|| {
        let root = PathBuf::from(CAPTURE_TMPFS_ROOT);
        std::fs::symlink_metadata(&root)
            .is_ok_and(|metadata| metadata.is_dir())
            .then_some(root)
    })
}

/// No tmpfs capture root off Linux.
#[cfg(not(target_os = "linux"))]
pub fn capture_tmpfs_root() -> Option<PathBuf> {
    None
}

/// [`runtime_capture_dir`] on tmpfs when the service runs as root and tmpfs
/// has room for the whole RAM image with margin; otherwise in the VM's data
/// directory as usual.
fn runtime_capture_dir_preferring_tmpfs(name: &str, vm: &VmRecord) -> Result<tempfile::TempDir> {
    #[cfg(target_os = "linux")]
    {
        let needed = u64::from(vm.mem) * 1024 * 1024 * 5 / 4 + (1 << 30);
        let root = capture_tmpfs_root();
        let usable = root.is_some()
            && free_bytes(Path::new("/dev/shm")).is_some_and(|free| free > needed)
            // tmpfs pages are RAM: never push the host into swap for this.
            && std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|meminfo| {
                    meminfo
                        .lines()
                        .find_map(|line| line.strip_prefix("MemAvailable:"))
                        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
                })
                .is_some_and(|available_kib| available_kib * 1024 > needed * 2);
        if let Some(root) = root.filter(|_| usable) {
            let data = crate::agent::vm_data_dir(name);
            let owner = vm.vm_uid_owner().unwrap_or(name);
            let owner_data = crate::agent::vm_data_dir(owner);
            let ids = crate::process::vm_drop_ids(
                &crate::agent::vm_uid_registry_dir(),
                &data,
                None,
                Some(&owner_data),
            )
            .transpose()
            .map_err(|error| Error::agent("resolve checkpoint uid", error.to_string()))?;
            match runtime_capture_dir_at(&root, ids) {
                Ok(directory) => return Ok(directory),
                Err(error) => {
                    tracing::warn!(%error, "tmpfs runtime capture unavailable; using the data directory")
                }
            }
        }
    }
    runtime_capture_dir(name, vm)
}

fn runtime_capture_dir_at(data: &Path, ids: Option<(u32, u32)>) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("checkpoint-capture-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let temporary = builder
        .tempdir_in(data)
        .map_err(|error| Error::agent("create runtime checkpoint directory", error.to_string()))?;
    if let Some((uid, gid)) = ids {
        crate::process::chown_tree(temporary.path(), uid, gid)
            .map_err(|error| Error::agent("own runtime checkpoint directory", error.to_string()))?;
    }
    Ok(temporary)
}

fn checkpoint_lib_dir(options: &CaptureOptions) -> Result<PathBuf> {
    options
        .lib_dir
        .clone()
        .or_else(crate::agent::find_lib_dir)
        .ok_or_else(|| {
            Error::agent(
                "find checkpoint runtime libraries",
                "could not find libkrun; set SMOLVM_LIB_DIR",
            )
        })
}

fn checkpoint_rootfs_dir(options: &CaptureOptions) -> Result<PathBuf> {
    // The same resolver a machine boots with; see `AgentManager::resolve_rootfs_path`.
    crate::agent::AgentManager::resolve_rootfs_path(
        options.rootfs_dir.clone(),
        "find checkpoint agent rootfs",
    )
}

fn validated_capture_source(name: &str) -> Result<SmolvmConfig> {
    let config = SmolvmConfig::load()?;
    config.db().require_completed_resize(name)?;
    let vm = config
        .vms
        .get(name)
        .ok_or_else(|| Error::vm_not_found(name))?;
    if crate::agent::state_probe::resolve_state(name, vm) != RecordState::Running {
        return Err(Error::agent_conflict(
            "checkpoint machine",
            format!("machine '{name}' must be running"),
        ));
    }
    validate_capture_profile(vm)?;

    let control = crate::agent::fork::control_socket_path(name);
    let status = crate::agent::fork::control_socket_cmd(&control, "STATUS").map_err(|error| {
        Error::agent_conflict(
            "checkpoint machine",
            format!(
                "machine '{name}' has no checkpoint control socket ({error}); start it with --forkable"
            ),
        )
    })?;
    if status.trim() != "OK running" {
        return Err(Error::agent_conflict(
            "checkpoint machine",
            format!("machine '{name}' is not checkpointable: {status}"),
        ));
    }
    crate::agent::fork::validate_checkpoint_agent(name)?;
    Ok(config)
}

/// Capture a running checkpointable machine into a self-contained artifact.
///
/// The source is paused only while libkrun saves execution state and the exact
/// disk chains are cloned. Hashing and compression continue after it resumes.
pub fn capture_to_path(
    name: &str,
    output: &Path,
    options: &CaptureOptions,
) -> Result<CaptureResult> {
    capture_to_path_with_history(name, output, options, DEFAULT_HISTORY)
}

/// Ancestor generations a stored checkpoint retains unless told otherwise —
/// the same depth the live branch lineage allows.
pub const DEFAULT_HISTORY: usize = 32;

/// [`capture_to_path`] with an explicit number of ancestor generations to
/// retain in a stored checkpoint (`0` keeps none; standalone files never
/// retain any). Lineage ids and parents are recorded either way.
pub fn capture_to_path_with_history(
    name: &str,
    output: &Path,
    options: &CaptureOptions,
    history: usize,
) -> Result<CaptureResult> {
    capture_to_path_with_source_release(name, output, options, history, || {})
}

/// A fresh checkpoint id: 128 random bits as lowercase hex.
fn new_checkpoint_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("operating system randomness");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Move the machine's checkpoint head to `id` after a capture or restore.
fn set_checkpoint_head(name: &str, id: &str) {
    let result = crate::db::SmolvmDb::open().and_then(|db| {
        db.update_vm(name, |record| record.checkpoint_head = Some(id.to_string()))
            .map(|_| ())
    });
    if let Err(error) = result {
        tracing::warn!(machine = %name, %error, "checkpoint head not recorded");
    }
}

/// Release API lifecycle ownership only after all input state belongs to this
/// capture. The closure also owns the guard on errors or client disconnects.
pub(crate) fn capture_to_path_with_source_release(
    name: &str,
    output: &Path,
    options: &CaptureOptions,
    history: usize,
    release_source: impl FnOnce(),
) -> Result<CaptureResult> {
    capture_with_completion(
        name,
        output,
        options,
        history,
        release_source,
        false,
        |_| Ok(()),
        None,
        crate::checkpoint_store::WriteOptions::default(),
    )
}

/// Retention of a capture's unpacked state in the node's prepared cache, handed
/// back to the caller instead of run inline.
///
/// Retaining verifies and fsyncs the whole unpacked state, which costs about as
/// much as the capture itself, and nothing waits on it: a restore that arrives
/// first reads the packed artifact instead. The caller runs it once it has
/// replied, while it still owns the artifact.
pub(crate) struct DeferredRetain(Box<dyn FnOnce(&Path) + Send>);

impl DeferredRetain {
    /// Retain against `artifact`, which must still be the capture's output.
    pub(crate) fn run(self, artifact: &Path) {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // One at a time, so bursts of captures do not stack multi-gigabyte fsyncs.
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        (self.0)(artifact)
    }
}

/// Whether the VMM declined a deferred RAM save in a way a synchronous SAVE
/// covers: it lacks the command, or the guest's RAM cannot be retained as a
/// generation (a fork clone's). A stored checkpoint ingests a synchronous
/// SAVE's RAM image as well as a streamed one, so the store needs no exception.
fn declined_deferred_save(reply: &str) -> bool {
    reply.starts_with("ERR ENOTSUP") || reply.trim() == "ERR EINVAL unknown command"
}

fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// [`capture_to_path_with_source_release`], leaving prepared-cache retention
/// to the caller.
pub(crate) fn capture_to_path_deferring_retention(
    name: &str,
    output: &Path,
    options: &CaptureOptions,
    history: usize,
    release_source: impl FnOnce(),
) -> Result<(CaptureResult, Option<DeferredRetain>)> {
    let mut deferred = None;
    let result = capture_with_completion(
        name,
        output,
        options,
        history,
        release_source,
        false,
        |_| Ok(()),
        Some(&mut deferred),
        crate::checkpoint_store::WriteOptions::default(),
    )?;
    Ok((result, deferred))
}

/// Capture a live checkpoint into the content-addressed `store`, publishing
/// the stored checkpoint directory at `output`. Only chunks the store lacks
/// are compressed and written; no ancestor generations are retained in it.
pub(crate) fn capture_to_store(
    name: &str,
    output: &Path,
    store: &Path,
    release_source: impl FnOnce(),
) -> Result<CaptureResult> {
    capture_with_completion(
        name,
        output,
        &CaptureOptions {
            store_dir: Some(store.to_path_buf()),
            ..Default::default()
        },
        0,
        release_source,
        false,
        |_| Ok(()),
        None,
        crate::checkpoint_store::WriteOptions {
            trust_existing_objects: true,
            defer_object_sync: true,
        },
    )
}

/// Durable lifecycle boundaries for an owner coordinating a pause.
pub enum PauseCaptureStage {
    /// Persist intent before freezing the guest.
    Capturing,
    /// Persist the resume point before terminating the frozen VM.
    Durable,
}

/// Capture one final execution boundary and stop without running the guest again.
/// `publish_resume_point` must durably record how to resume before the VM exits.
/// Any error before that commit resumes the original guest.
pub fn capture_and_stop_to_path(
    name: &str,
    output: &Path,
    options: &CaptureOptions,
    publish_resume_point: impl FnMut(PauseCaptureStage) -> Result<()>,
) -> Result<CaptureResult> {
    capture_with_completion(
        name,
        output,
        options,
        DEFAULT_HISTORY,
        || {},
        true,
        publish_resume_point,
        None,
        crate::checkpoint_store::WriteOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn capture_with_completion(
    name: &str,
    output: &Path,
    options: &CaptureOptions,
    history: usize,
    release_source: impl FnOnce(),
    stop_after_capture: bool,
    mut publish_resume_point: impl FnMut(PauseCaptureStage) -> Result<()>,
    defer_retain: Option<&mut Option<DeferredRetain>>,
    writer_options: crate::checkpoint_store::WriteOptions,
) -> Result<CaptureResult> {
    let started = std::time::Instant::now();
    let mut phase = started;
    if options.store_dir.is_some() && options.staging_dir.is_some() {
        return Err(Error::config(
            "checkpoint machine",
            "stored checkpoints stage inside the store; omit staging_dir",
        ));
    }
    if !has_checkpoint_extension(output) {
        return Err(Error::config(
            "checkpoint machine",
            "output must end in .checkpoint",
        ));
    }
    if output.exists() {
        return Err(Error::config(
            "checkpoint machine",
            format!("refusing to overwrite {}", output.display()),
        ));
    }

    // Fail before staging runtime assets when the source is already known to
    // be ineligible. The source is revalidated under the cross-process lock
    // immediately before capture so this fast preflight is never trusted for
    // the consistency boundary.
    let _ = validated_capture_source(name)?;
    if options.store_dir.is_some() {
        let reply = crate::agent::fork::control_socket_cmd(
            &crate::agent::fork::control_socket_path(name),
            "SAVE_CAPABILITIES",
        )?;
        if reply.trim() != "OK deferred-stream-v1" {
            return Err(Error::config("incremental checkpoint", "this machine's runtime does not support incremental checkpoint streaming; restart it with an updated libkrun, or omit --store for a standalone checkpoint"));
        }
    }

    let stored = options
        .store_dir
        .as_ref()
        .map(|store| -> Result<_> {
            let parent = output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::create_dir_all(store)
                .map_err(|e| Error::agent("create checkpoint store", e.to_string()))?;
            let store = store
                .canonicalize()
                .map_err(|e| Error::agent("resolve checkpoint store", e.to_string()))?;
            let parent = parent
                .canonicalize()
                .map_err(|e| Error::agent("resolve checkpoint output", e.to_string()))?;
            if parent.starts_with(store.join("staging"))
                || parent.starts_with(store.join("objects"))
            {
                return Err(Error::config(
                    "checkpoint output",
                    "output cannot be inside the store's reserved staging or objects directories",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if std::fs::metadata(&parent)?.dev() != std::fs::metadata(&store)?.dev() {
                    return Err(Error::config(
                        "checkpoint output",
                        "output and store must be on the same filesystem",
                    ));
                }
            }
            let capture_root = store.join("staging");
            std::fs::create_dir_all(&capture_root)
                .map_err(|e| Error::agent("create checkpoint staging", e.to_string()))?;
            let directory = tempfile::Builder::new()
                .prefix(".checkpoint-")
                .tempdir_in(capture_root)
                .map_err(|e| Error::agent("stage stored checkpoint", e.to_string()))?;
            let writer = crate::checkpoint_store::Writer::new_with_options(
                &store,
                directory.path(),
                writer_options,
            )
            .map_err(|e| Error::agent("open checkpoint store", e.to_string()))?;
            Ok((directory, writer))
        })
        .transpose()?;

    let asset_staging_root = match stored.as_ref() {
        Some((directory, _)) => directory.path().to_path_buf(),
        None => staging_root(options)?,
    };
    let temp_dir = tempfile::Builder::new()
        .prefix("checkpoint-staging-")
        .tempdir_in(asset_staging_root)
        .map_err(|error| Error::agent("create checkpoint staging", error.to_string()))?;
    let staging_dir = temp_dir.path().join("staging");
    let mut collector = AssetCollector::new(staging_dir.clone())
        .map_err(|error| Error::agent("collect checkpoint assets", error.to_string()))?;
    // Staging is only packed and discarded unless a store ingests it or the
    // prepared cache retains it; then the host's asset files can be linked in.
    let discard_staging = stored.is_none()
        && !options
            .prepared_cache_budget_bytes
            .is_some_and(|bytes| bytes > 0);
    // A store only reads its staging tree before removing it, so it may link
    // host assets and shared backing copies exactly like a discarded staging.
    let read_only_staging = discard_staging || stored.is_some();
    if read_only_staging {
        collector = collector.with_linked_host_assets();
    }
    collector
        .collect_libraries(&checkpoint_lib_dir(options)?)
        .map_err(|error| Error::agent("collect checkpoint libraries", error.to_string()))?;
    collector
        .collect_agent_rootfs(&checkpoint_rootfs_dir(options)?)
        .map_err(|error| Error::agent("collect checkpoint rootfs", error.to_string()))?;
    collector
        .create_storage_template()
        .map_err(|error| Error::agent("create checkpoint storage template", error.to_string()))?;
    log_phase(name, "capture_assets", &mut phase);

    // A serve process has its own lifecycle mutex, but another CLI process
    // does not share it. Use the same source lock as `machine fork` so SAVE and
    // fork can never overlap or produce two competing source generations.
    // Hold it through the RAM worker: its cgroup reservation must not race a
    // fork resizing the same scope. Release before packaging and compression.
    let mut source_lock = Some(crate::agent::fork::lock_fork_source(name)?);
    let mut release_source = Some(release_source);
    let config = validated_capture_source(name)?;
    let vm = config
        .vms
        .get(name)
        .expect("validated checkpoint source must remain in its loaded config");
    // This capture's place in the machine's history: a new node whose parent
    // is whatever the machine was last captured to or restored from.
    let checkpoint_id = new_checkpoint_id();
    let checkpoint_created_at =
        humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    // Ask while the guest still runs: its agent answers for the kernel it is on.
    let (clock, guest_cpu_features) = checkpoint_guest_view(name);
    if stop_after_capture {
        let db = crate::db::SmolvmDb::open()?;
        if !db.dependent_clones(name)?.is_empty() {
            return Err(Error::agent_conflict(
                "pause machine",
                "cannot pause a machine while branches depend on its live state",
            ));
        }
    }
    let control = crate::agent::fork::control_socket_path(name);
    // A store capture consumes the runtime's RAM image and deletes it: on
    // tmpfs it never reaches (or queues behind) the disk.
    let runtime_capture = if options.store_dir.is_some() {
        runtime_capture_dir_preferring_tmpfs(name, vm)?
    } else {
        runtime_capture_dir(name, vm)?
    };
    let runtime_snapshot = runtime_capture.path().join(ASSET_DIR);
    #[cfg(target_os = "linux")]
    let mut memory_reservation = Some(
        crate::agent::fork::ForkLineageMemoryReservation::checkpoint(name, &runtime_snapshot)?,
    );
    let retain = cfg!(target_os = "linux")
        && options
            .prepared_cache_budget_bytes
            .is_some_and(|bytes| bytes > 0)
        && smolvm_pack::extract::shared_extract_enabled();
    let sparse_capable =
        cfg!(any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )) && crate::agent::fork::control_socket_cmd(&control, "SAVE_SPARSE_CAPABILITIES")?.trim()
            == "OK sparse-stream-v1 ownership-v1";
    let max_memory_image = max_checkpoint_memory_image(vm.mem, mounts_image_layers(vm))?;
    crate::agent::fork::sync_fork_source(name)?;
    log_phase(name, "capture_sync", &mut phase);
    if stop_after_capture {
        remove_paused_disks_marker(&crate::agent::vm_data_dir(name))?;
        publish_resume_point(PauseCaptureStage::Capturing)?;
    }
    let snapshot_dir = staging_dir.join(ASSET_DIR);
    let pause_started = std::time::Instant::now();
    // Deferred RAM capture rebases the live source's mappings. A packed
    // image's virtio-fs DAX window contains file mappings that must remain
    // intact for the source to keep executing after the checkpoint.
    // WHP only implements the eager, frozen save. Send SAVE directly rather
    // than probing deferred commands that the Windows VMM cannot handle.
    let use_deferred_save = !cfg!(target_os = "windows")
        && (!cfg!(all(target_os = "linux", target_arch = "x86_64")) || !mounts_image_layers(vm));
    // A capture that stops the VM keeps it paused until the RAM is written, so
    // libkrun can read RAM it cannot retain as a generation (a fork clone's)
    // in place instead of falling back to a synchronous save.
    // A pause never resumes the source, so a VMM that reads a held guest's
    // device windows in place can save a packed machine without the
    // synchronous SAVE's extra copy. Older VMMs would rebase first, so packed
    // machines use it only when the VMM says so.
    let held_in_place = !use_deferred_save
        && stop_after_capture
        && crate::agent::fork::control_socket_cmd(&control, "SAVE_HELD_CAPABILITIES")
            .is_ok_and(|reply| reply.trim() == "OK held-windows-in-place-v1");
    let command = if held_in_place {
        "PREPARE_SAVE_HELD"
    } else if !use_deferred_save {
        "SAVE"
    } else if stop_after_capture {
        "PREPARE_SAVE_HELD"
    } else {
        "PREPARE_SAVE"
    };
    let send = |command: &str| {
        crate::agent::fork::control_socket_cmd_with_timeout(
            &control,
            &format!("{command} {}", runtime_snapshot.display()),
            std::time::Duration::from_secs(30 * 60),
        )
    };
    // A live checkpoint resumes the source and packs SAVE's files into its own
    // durable artifact, so syncing them first would only hold the source paused
    // at the host disk's flush rate. A pause stops the source on those files,
    // so it keeps the durable SAVE. An older VMM without SAVE_UNSYNCED gets SAVE.
    let synchronous_save = || -> Result<String> {
        if stop_after_capture {
            return send("SAVE");
        }
        let reply = send("SAVE_UNSYNCED")?;
        if reply.trim() == "ERR EINVAL unknown command" {
            return send("SAVE");
        }
        Ok(reply)
    };
    let mut reply = if command == "SAVE" {
        synchronous_save()?
    } else {
        send(command)?
    };
    if command == "PREPARE_SAVE_HELD"
        && !held_in_place
        && reply.trim() == "ERR EINVAL unknown command"
    {
        reply = send("PREPARE_SAVE")?;
    }
    let prepared = (use_deferred_save || held_in_place) && reply.starts_with("OK");
    tracing::info!(machine = name, command, reply = ?reply.trim(), "checkpoint memory protocol reply");
    // A packed machine whose held save failed goes back to SAVE, never to the
    // rebasing PREPARE_SAVE.
    if !prepared && (held_in_place || declined_deferred_save(&reply)) {
        reply = synchronous_save()?;
        tracing::info!(machine = name, command = "SAVE", reply = ?reply.trim(), "checkpoint memory protocol reply");
    }
    if !reply.starts_with("OK") {
        return Err(Error::agent(
            "checkpoint machine",
            format!("libkrun save failed: {reply}"),
        ));
    }
    let mut pause = SavedVmPause {
        control,
        prepared_save: prepared.then(|| runtime_snapshot.clone()),
        armed: true,
    };
    #[cfg(target_os = "linux")]
    if prepared {
        memory_reservation.as_mut().unwrap().checkpoint_prepared()?;
    }
    log_phase(
        name,
        if prepared {
            "capture_prepare_memory_deferred"
        } else {
            "capture_prepare_memory_synchronous"
        },
        &mut phase,
    );
    // The source is quiesced: its disks are what the checkpoint captures.
    #[cfg(unix)]
    let captured_disks = stop_after_capture
        .then(|| disk_chain_identity(&crate::agent::vm_data_dir(name)))
        .transpose()?;
    #[cfg(not(unix))]
    let captured_disks: Option<String> = None;
    // A pause references shared fork layers rather than copying them into
    // every artifact. Stored captures reuse unchanged backing chunks by inode.
    #[cfg(unix)]
    let mut pins = (stop_after_capture && stored.is_none())
        .then(|| LayerPins::new(&crate::agent::vm_data_dir(name)))
        .transpose()?;
    #[cfg(not(unix))]
    let mut pins: Option<LayerPins> = None;
    let mut linked_heads = std::collections::HashMap::new();
    let (checkpoint_disks, deferred_backings) = stage_disk_chains_with_links(
        &crate::agent::vm_data_dir(name),
        &snapshot_dir,
        pins.as_mut(),
        stored.is_some().then_some(&mut linked_heads),
    )?;
    if !stop_after_capture {
        pause.resume()?;
    }
    log_phase(
        name,
        if stop_after_capture {
            "capture_disks_held"
        } else {
            "capture_disks_and_resume"
        },
        &mut phase,
    );
    let source_pause = pause_started.elapsed();
    // The store ingests the staging tree, so it needs every layer as a file.
    // A packed artifact takes backing layers straight from the source.
    let deferred_backings = if stored.is_some() {
        deferred_backings.stage_copies()?;
        log_phase(name, "capture_backings", &mut phase);
        None
    } else {
        Some(deferred_backings)
    };

    let mut sparse_socket = if prepared && sparse_capable {
        let mut stream = crate::platform::uds::UdsStream::connect(&pause.control)
            .map_err(|e| Error::agent("connect sparse checkpoint stream", e.to_string()))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30 * 60)))
            .map_err(|e| Error::agent("configure sparse checkpoint stream", e.to_string()))?;
        writeln!(stream, "FINISH_SAVE_SPARSE {}", runtime_snapshot.display())
            .map_err(|e| Error::agent("request sparse checkpoint stream", e.to_string()))?;
        Some(stream)
    } else {
        None
    };
    let mut streamed_memory = match sparse_socket.as_mut() {
        Some(stream) => Some(
            smolvm_pack::checkpoint_stream::CheckpointStream::read(stream, max_memory_image)
                .map_err(|e| Error::agent("read sparse checkpoint boundary", e.to_string()))?,
        ),
        None => None,
    };
    // Retention needs the unpacked RAM image the streamed path never writes, so
    // the stream writes it too: only the pages in use, beside the staging tree
    // so packing does not pick it up. Sparse, it is a fraction of full RAM.
    let prepared_memory = temp_dir.path().join("prepared-memory.bin");
    if let Some(stream) = streamed_memory.as_mut().filter(|_| retain) {
        match create_private_file(&prepared_memory) {
            Ok(file) => stream.copy_memory_to(file),
            Err(error) => tracing::warn!(%error, "streamed checkpoint will not be retained"),
        }
    }

    let mut stored = stored;
    let stored_memory = if let Some((_, writer)) = stored.as_mut() {
        if let Some(stream) = streamed_memory.as_mut() {
            let memory = writer
                .ingest_sparse_memory(stream)
                .map_err(|e| Error::agent("store sparse checkpoint memory", e.to_string()))?;
            pause.prepared_save = None;
            Some(memory)
        } else if prepared {
            let mut stream = crate::platform::uds::UdsStream::connect(&pause.control)
                .map_err(|e| Error::agent("connect checkpoint stream", e.to_string()))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(30 * 60)))
                .map_err(|e| Error::agent("configure checkpoint stream", e.to_string()))?;
            writeln!(stream, "FINISH_SAVE_STREAM {}", runtime_snapshot.display())
                .map_err(|e| Error::agent("request checkpoint stream", e.to_string()))?;
            let memory = writer
                .ingest_memory(&mut stream, max_memory_image)
                .map_err(|e| Error::agent("store checkpoint memory", e.to_string()))?;
            let mut reply = String::new();
            stream
                .take(4096)
                .read_to_string(&mut reply)
                .map_err(|e| Error::agent("complete checkpoint stream", e.to_string()))?;
            tracing::info!(machine = name, command = "FINISH_SAVE_STREAM", reply = ?reply.trim(), "checkpoint memory protocol reply");
            if !reply.starts_with("OK saved (") {
                return Err(Error::agent("complete checkpoint stream", reply));
            }
            pause.prepared_save = None;
            Some(memory)
        } else {
            let path = runtime_snapshot.join("memory.bin");
            let mut file = std::fs::File::open(&path)
                .map_err(|e| Error::agent("read checkpoint memory", e.to_string()))?;
            let size = file
                .metadata()
                .map_err(|e| Error::agent("inspect checkpoint memory", e.to_string()))?
                .len();
            if size == 0 || size > max_memory_image {
                return Err(Error::agent(
                    "store checkpoint memory",
                    "checkpoint RAM image exceeds configured memory layout",
                ));
            }
            Some(
                writer
                    .ingest_sparse_file("checkpoint/memory.bin", 0o600, &mut file)
                    .map_err(|e| Error::agent("store checkpoint memory", e.to_string()))?,
            )
        }
    } else {
        if prepared && streamed_memory.is_none() {
            let reply = crate::agent::fork::control_socket_cmd_with_timeout(
                &pause.control,
                &format!("FINISH_SAVE {}", runtime_snapshot.display()),
                std::time::Duration::from_secs(30 * 60),
            )?;
            tracing::info!(machine = name, command = "FINISH_SAVE", reply = ?reply.trim(), "checkpoint memory protocol reply");
            if !reply.starts_with("OK") {
                return Err(Error::agent("finish checkpoint", reply));
            }
            pause.prepared_save = None;
        }
        None
    };
    log_phase(
        name,
        if streamed_memory.is_some() {
            "capture_stream_boundary"
        } else {
            "capture_finish_memory"
        },
        &mut phase,
    );
    #[cfg(target_os = "linux")]
    if streamed_memory.is_none() {
        drop(memory_reservation.take());
    }
    // Export sparse files after resume; streamed RAM is already in the store.
    for file in ["checkpoint.bin", "memory.bin", "manifest.bin"] {
        if file == "memory.bin" && (stored_memory.is_some() || streamed_memory.is_some()) {
            continue;
        }
        if let Some(stream) = &streamed_memory {
            let bytes = match file {
                "checkpoint.bin" => stream.state(),
                "manifest.bin" => stream.layout(),
                _ => unreachable!("memory payload is streamed separately"),
            };
            std::fs::write(snapshot_dir.join(file), bytes)
                .map_err(|e| Error::agent("stage streamed checkpoint metadata", e.to_string()))?;
            continue;
        }
        if file == "memory.bin"
            && prepared
            && link_completed_memory(&runtime_snapshot.join(file), &snapshot_dir.join(file))?
        {
            continue;
        }
        // A tree that is only packed reads the saved RAM where it is, rather
        // than copying gigabytes the packer reads once anyway.
        if file == "memory.bin"
            && discard_staging
            && std::fs::hard_link(runtime_snapshot.join(file), snapshot_dir.join(file)).is_ok()
        {
            continue;
        }
        crate::disk_utils::clone_or_copy_file(
            &runtime_snapshot.join(file),
            &snapshot_dir.join(file),
        )?;
    }
    log_phase(name, "capture_stage_memory", &mut phase);

    let assets = crate::pack_export::FromVmAssets {
        mode: PackMode::Vm,
        image: None,
        image_env: Vec::new(),
        image_user: None,
        layer_bytes: 0,
    };
    let platform = format!("linux/{}", crate::platform::Arch::current().oci_arch());
    let host_platform = crate::platform::Platform::current()
        .host_oci_platform()
        .to_string();
    let mut manifest = PackManifest::new(
        format!("vm://{name}"),
        "none".to_string(),
        platform,
        host_platform.clone(),
    );
    crate::pack_export::seed_manifest_from_vm(&mut manifest, vm, &assets);
    // A normal VM-mode pack supplies `/bin/sh` when the source has no explicit
    // entrypoint because it packages a flattened rootfs. A live checkpoint must
    // preserve the exact OCI launch vector instead: injecting `/bin/sh` turns a
    // valid `python3 ...` workload into the invalid `/bin/sh python3 ...` after
    // the restored machine's first ordinary cold restart.
    manifest.entrypoint = vm.entrypoint.clone();
    manifest.cpus = vm.cpus;
    manifest.mem = vm.mem;
    let packed_layers = checkpoint_packed_layers(name, vm)?;
    let host_image = checkpoint_host_image(vm)?;
    let credential_ca = checkpoint_credential_ca(name, vm, &snapshot_dir)?;
    manifest.checkpoint = Some(PortableCheckpointManifest {
        version: FORMAT_VERSION,
        runtime_abi: RUNTIME_ABI.to_string(),
        host_platform,
        cpu_contract: checkpoint_cpu_contract()?,
        cpus: vm.cpus,
        memory_mib: vm.mem,
        // Persist the effective sizes, not the optional user overrides. This
        // keeps the artifact self-describing if runtime defaults change before
        // it is restored on another host.
        storage_gib: Some(
            vm.storage_gb
                .unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GIB),
        ),
        overlay_gib: Some(
            vm.overlay_gb
                .unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GIB),
        ),
        device_profile: if packed_layers.is_some() || host_image.is_some() {
            DEVICE_PROFILE_PACKED_LAYERS
        } else {
            DEVICE_PROFILE
        }
        .to_string(),
        state: describe_asset(
            &snapshot_dir.join("checkpoint.bin"),
            "checkpoint/checkpoint.bin",
        )?,
        // Guest RAM is a sparse logical image and may be many GiB even when
        // very little is resident. The pack container verifies its compressed
        // bytes; hashing the expanded holes again makes import scale with the
        // configured RAM limit instead of the checkpoint's physical size.
        memory: match stored_memory.as_ref() {
            Some(memory) => CheckpointAsset {
                path: "checkpoint/memory.bin".into(),
                size: crate::checkpoint_store::logical_size(memory),
                sha256: String::new(),
            },
            None => match &streamed_memory {
                Some(stream) => CheckpointAsset {
                    path: "checkpoint/memory.bin".into(),
                    size: stream.memory_len(),
                    sha256: String::new(),
                },
                None => describe_sparse_asset(
                    &snapshot_dir.join("memory.bin"),
                    "checkpoint/memory.bin",
                )?,
            },
        },
        layout: describe_asset(
            &snapshot_dir.join("manifest.bin"),
            "checkpoint/manifest.bin",
        )?,
        disks: checkpoint_disks,
        workload: checkpoint_workload(name, vm),
        network: Some(checkpoint_network(vm)),
        packed_layers,
        host_image,
        lineage: Some(smolvm_pack::format::CheckpointLineage {
            id: checkpoint_id.clone(),
            parent: vm.checkpoint_head.clone(),
            machine: name.to_string(),
            created_at: checkpoint_created_at.clone(),
        }),
        payload: Default::default(),
        history: Vec::new(),
        base: None,
        credential_ca,
        clock,
        guest_cpu_features,
    });
    manifest.assets = collector.into_inventory();
    log_phase(name, "capture_manifest", &mut phase);
    // Everything consumed below is capture-owned. Packaging and publication
    // must not serialize new branches or other operations on the live source.
    if !stop_after_capture {
        #[cfg(target_os = "linux")]
        if streamed_memory.is_some() {
            // Pause keeps this lock through durability and shutdown. Marking
            // it released would make reservation cleanup lock it a second time.
            memory_reservation
                .as_mut()
                .unwrap()
                .allow_concurrent_branches();
        }
        drop(source_lock.take());
        release_source.take().unwrap()();
    }

    if let Some((directory, mut writer)) = stored {
        // A restored machine's read-only disk bases are inodes of the tree
        // it was restored from; their chunks are already known.
        let known = match (options.store_dir.as_ref(), vm.checkpoint_head.as_deref()) {
            (Some(store), Some(parent)) => crate::checkpoint_delta::known_files_for(store, parent),
            _ => Default::default(),
        };
        let mut files = writer
            .ingest_tree_known(&staging_dir, &known, &linked_heads)
            .map_err(|e| Error::agent("store checkpoint assets", e.to_string()))?;
        files.push(stored_memory.expect("stored capture has a RAM index"));
        log_phase(name, "capture_store_assets", &mut phase);
        // Only compressed objects and the index are published. Keeping these
        // assets inside owned staging also makes interrupted captures reclaimable.
        temp_dir
            .close()
            .map_err(|e| Error::agent("remove checkpoint staging", e.to_string()))?;
        // Keep the parent's generations in this checkpoint so it can restore
        // any point in its history on its own; unchanged chunks are links.
        let store = options
            .store_dir
            .as_ref()
            .and_then(|store| store.canonicalize().ok());
        if let (Some(store), Some(parent)) = (store.as_ref(), vm.checkpoint_head.as_deref()) {
            match crate::checkpoint_store::find_generation_source(store, parent) {
                Ok(Some((source, own))) => {
                    let start = (!own).then_some(parent);
                    match writer.retain_generations_from(directory.path(), &source, start, history)
                    {
                        Ok(retained) => {
                            tracing::info!(retained, parent, "checkpoint history retained")
                        }
                        Err(error) => {
                            tracing::warn!(%error, parent, "checkpoint history not retained")
                        }
                    }
                }
                Ok(None) => tracing::info!(
                    parent,
                    "parent checkpoint not in this store; history starts here"
                ),
                Err(error) => {
                    tracing::warn!(%error, parent, "checkpoint lineage index unreadable")
                }
            }
        }
        let stats = writer
            .finish(directory.path(), manifest, files)
            .map_err(|e| Error::agent("finish checkpoint index", e.to_string()))?;
        tracing::info!(
            new_logical_bytes = stats.new_logical_bytes,
            new_compressed_bytes = stats.new_bytes,
            reused_bytes = stats.reused_bytes,
            zero_bytes = stats.zero_bytes,
            "checkpoint objects stored"
        );
        crate::checkpoint_store::publish(directory.path(), output)
            .map_err(|e| Error::agent("publish stored checkpoint", e.to_string()))?;
        log_phase(name, "capture_store_publish", &mut phase);
        if let Some(store) = store.as_ref() {
            let published = output
                .canonicalize()
                .unwrap_or_else(|_| output.to_path_buf());
            if let Err(error) = crate::checkpoint_store::record_lineage(
                store,
                &crate::checkpoint_store::LineageRecord {
                    id: checkpoint_id.clone(),
                    parent: vm.checkpoint_head.clone(),
                    machine: name.to_string(),
                    created_at: checkpoint_created_at.clone(),
                    path: published.to_string_lossy().into_owned(),
                },
            ) {
                tracing::warn!(%error, "checkpoint lineage not recorded in store");
            }
        }
        if stop_after_capture {
            publish_resume_point(PauseCaptureStage::Durable)?;
            pause.stop(name, vm)?;
            record_paused_disks(
                &crate::agent::vm_data_dir(name),
                output,
                captured_disks.as_deref(),
            );
        }
        set_checkpoint_head(name, &checkpoint_id);
        return Ok(CaptureResult {
            size_bytes: stats.new_bytes,
            reused_bytes: stats.reused_bytes,
            source_pause: if stop_after_capture {
                pause_started.elapsed()
            } else {
                source_pause
            },
            elapsed: started.elapsed(),
        });
    }

    let mut collector = AssetCollector::new(staging_dir.clone())
        .map_err(|error| Error::agent("collect checkpoint assets", error.to_string()))?;
    // Retention keeps the staging tree as this artifact's extraction, so it
    // gets the layers as files too, but only after the artifact is published.
    let retained_backings = match deferred_backings {
        Some(deferred) => {
            let copies = retain.then(|| deferred.try_clone()).transpose()?;
            deferred.pack_from_source(&mut collector)?;
            copies
        }
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    let _ = retained_backings;
    let packer = Packer::new(manifest)
        .with_asset_collector(collector)
        .with_direct_artifact_io();
    let (info, identity) = if let Some(stream) = streamed_memory.as_mut() {
        packer
            .pack_checkpoint_stream(output, stream)
            .map(|info| (info, None))
    } else if retain {
        packer
            .pack_artifact_with_identity(output)
            .map(|(info, identity)| (info, Some(identity)))
    } else {
        packer.pack_artifact(output).map(|info| (info, None))
    }
    .map_err(|error| Error::agent("pack checkpoint", error.to_string()))?;
    // A streamed capture is retainable only once its RAM copy is complete.
    #[cfg(target_os = "linux")]
    let retain = retain
        && streamed_memory
            .as_ref()
            .is_none_or(|stream| stream.memory_copied());
    #[cfg(target_os = "linux")]
    let streamed = streamed_memory.is_some();
    if streamed_memory.is_some() {
        pause.prepared_save = None;
        #[cfg(target_os = "linux")]
        drop(memory_reservation.take());
    }
    log_phase(name, "capture_pack", &mut phase);
    #[cfg(not(target_os = "linux"))]
    let _ = identity;
    #[cfg(not(target_os = "linux"))]
    let _ = defer_retain;
    #[cfg(target_os = "linux")]
    if retain {
        let budget = options.prepared_cache_budget_bytes.unwrap_or(0);
        let job = DeferredRetain(Box::new(move |artifact: &Path| {
            if let Some(Err(error)) = retained_backings.map(DeferredBackings::stage_copies) {
                tracing::warn!(%error, "prepared checkpoint unavailable; durable artifact remains usable");
                return;
            }
            if streamed {
                if let Err(error) =
                    std::fs::rename(&prepared_memory, snapshot_dir.join("memory.bin"))
                {
                    tracing::warn!(%error, "prepared checkpoint unavailable; durable artifact remains usable");
                    return;
                }
            }
            if let Err(error) = crate::artifact_cache::retain_prepared_checkpoint_with_identity(
                artifact,
                &staging_dir,
                identity.as_ref(),
            ) {
                tracing::warn!(%error, "prepared checkpoint unavailable; durable artifact remains usable");
            }
            if let Err(error) = crate::artifact_cache::prune_prepared_checkpoints(budget) {
                tracing::warn!(%error, "could not prune prepared checkpoints");
            }
            // The staging tree is consumed by retention or discarded here.
            drop(temp_dir);
        }));
        match defer_retain {
            Some(slot) => *slot = Some(job),
            None => job.run(output),
        }
        log_phase(name, "capture_retain_prepared", &mut phase);
    }
    if stop_after_capture {
        #[cfg(unix)]
        if let Some(pins) = &pins {
            pins.commit(output)?;
        }
        publish_resume_point(PauseCaptureStage::Durable)?;
        pause.stop(name, vm)?;
        record_paused_disks(
            &crate::agent::vm_data_dir(name),
            output,
            captured_disks.as_deref(),
        );
    }
    set_checkpoint_head(name, &checkpoint_id);
    Ok(CaptureResult {
        reused_bytes: 0,
        size_bytes: info.total_size,
        source_pause: if stop_after_capture {
            pause_started.elapsed()
        } else {
            source_pause
        },
        elapsed: started.elapsed(),
    })
}

fn checkpoint_workload(name: &str, vm: &VmRecord) -> Option<CheckpointWorkload> {
    // A host-fetched image is named by the registry reference it came from:
    // its local archive exists only on this host.
    let image = vm.host_fetched_origin().or_else(|| vm.image.clone())?;
    Some(CheckpointWorkload {
        image,
        user: vm.user.clone(),
        overlay_owner: crate::workload::persistent_overlay_owner_with_lineage(
            name,
            vm.golden.as_deref(),
            vm.fork_overlay_owner.as_deref(),
        ),
        restart_policy: vm.restart.policy.to_string(),
        restart_max_retries: vm.restart.max_retries,
        restart_max_backoff_secs: vm.restart.max_backoff_secs,
    })
}

/// Return the strict host CPU feature fingerprint used for snapshot matching.
pub fn cpu_fingerprint() -> Result<String> {
    let mut identity = format!(
        "platform={}\n",
        crate::platform::Platform::current().host_oci_platform()
    );
    #[cfg(target_os = "linux")]
    {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
            .map_err(|error| Error::agent("fingerprint CPU", error.to_string()))?;
        let accepted = [
            "vendor_id",
            "cpu family",
            "model",
            "stepping",
            "flags",
            "Features",
            "CPU implementer",
            "CPU architecture",
            "CPU variant",
            "CPU part",
            "CPU revision",
        ];
        for line in cpuinfo.lines().take_while(|line| !line.trim().is_empty()) {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if accepted.contains(&key.trim()) {
                identity.push_str(key.trim());
                identity.push('=');
                identity.push_str(
                    value
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .as_str(),
                );
                identity.push('\n');
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string", "hw.model"])
            .output()
            .map_err(|error| Error::agent("fingerprint CPU", error.to_string()))?;
        if !output.status.success() {
            return Err(Error::agent(
                "fingerprint CPU",
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        identity.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    #[cfg(target_os = "windows")]
    {
        identity.push_str(&std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default());
        identity.push('\n');
        identity.push_str(&std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default());
    }
    Ok(hex::encode(Sha256::digest(identity.as_bytes())))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn linux_cpu_vendor(cpuinfo: &str) -> Option<String> {
    cpuinfo
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "vendor_id")
                .then(|| value.trim().to_string())
                .filter(|vendor| !vendor.is_empty() && vendor.len() <= 64)
        })
}

fn cpu_vendor() -> Result<Option<String>> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
            .map_err(|error| Error::agent("identify CPU vendor", error.to_string()))?;
        Ok(linux_cpu_vendor(&cpuinfo))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Ok(None)
    }
}

/// Architectural features a guest on this aarch64 host can use, by name.
///
/// The guest sees the host's own ID registers, so the host's feature set is the
/// guest's feature set — with one deliberate subtraction: libkrun masks SME out
/// of `ID_AA64PFR1_EL1` before the guest runs, because a guest that sees SME
/// "will break after enabling the MMU". Anything SME is therefore invisible to
/// the guest on every host and must not enter the contract, or checkpoints would
/// be refused over a feature no guest can reach.
///
/// Names are the ARM `FEAT_*` identifiers, which both platforms already speak:
/// macOS publishes them through `sysctl hw.optional.arm.*`, Linux through the
/// `Features` line in `/proc/cpuinfo`.
#[cfg(target_arch = "aarch64")]
fn aarch64_guest_features() -> Result<Vec<String>> {
    let mut features = collect_aarch64_host_features()?;
    features.retain(|name| !is_masked_from_guest(name));
    features.sort();
    features.dedup();
    Ok(features)
}

/// Features the VMM removes before the guest ever sees them. Keep in step with
/// libkrun's vCPU setup.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
fn is_masked_from_guest(name: &str) -> bool {
    // libkrun: `val & !AA64PFR1_EL1_SMEMASK`. Covers FEAT_SME, FEAT_SME2 and
    // every SME_* sub-feature.
    name.contains("SME")
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn collect_aarch64_host_features() -> Result<Vec<String>> {
    let output = std::process::Command::new("sysctl")
        .arg("-a")
        .output()
        .map_err(|error| Error::agent("read CPU features", error.to_string()))?;
    if !output.status.success() {
        return Err(Error::agent(
            "read CPU features",
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(parse_macos_features(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Pull the enabled `FEAT_*` names out of `sysctl -a`.
///
/// macOS reports one line per feature, `hw.optional.arm.FEAT_X: 1`, where 0
/// means the silicon lacks it. Separated from the command so the parsing is
/// testable against recorded output from real machines.
// The two parsers below are pure string functions. They are compiled on every
// aarch64 host and under `cfg(test)` everywhere, so macOS CI exercises the Linux
// parser and vice versa; each is used by exactly one OS at runtime, hence the
// dead-code allowance.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
fn parse_macos_features(sysctl_output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in sysctl_output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(name) = key.trim().strip_prefix("hw.optional.arm.") else {
            continue;
        };
        if value.trim() == "1" && !name.is_empty() {
            out.push(name.to_string());
        }
    }
    out
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn collect_aarch64_host_features() -> Result<Vec<String>> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
        .map_err(|error| Error::agent("read CPU features", error.to_string()))?;
    Ok(parse_linux_features(&cpuinfo))
}

/// Pull the HWCAP names out of `/proc/cpuinfo`'s `Features` line.
///
/// Linux prints lowercase HWCAP tokens (`asimd`, `bf16`, `i8mm`) rather than
/// ARM's `FEAT_*` spelling, so they are normalised to a common form. Only the
/// first processor block is read: every core in a machine smolvm will run on
/// presents the same features.
fn parse_linux_features(cpuinfo: &str) -> Vec<String> {
    for line in cpuinfo.lines().take_while(|line| !line.trim().is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != "Features" {
            continue;
        }
        return value
            .split_whitespace()
            .map(|token| format!("FEAT_{}", token.to_ascii_uppercase()))
            .collect();
    }
    Vec::new()
}

/// What the running guest tells about itself that a restore on another
/// platform needs: whether its kernel follows a change of counter rate, and
/// the CPU features it was given. Both `None` on x86_64, where the TSC and
/// CPUID contracts cover them.
fn checkpoint_guest_view(
    name: &str,
) -> (
    Option<smolvm_pack::format::CheckpointClock>,
    Option<Vec<String>>,
) {
    let Some(counter_hz) = host_counter_hz() else {
        return (None, None);
    };
    let client = crate::agent::AgentManager::for_vm(name)
        .and_then(|manager| crate::agent::AgentClient::connect(manager.vsock_socket()));
    let Ok(mut client) = client else {
        let clock = smolvm_pack::format::CheckpointClock {
            counter_hz,
            follows_counter_rate: false,
        };
        return (Some(clock), None);
    };
    let follows_counter_rate = client
        .supports_capability(smolvm_protocol::COUNTER_RATE_FOLLOW_CAPABILITY)
        .unwrap_or(false);
    let features = client
        .vm_exec(
            vec!["cat".into(), "/proc/cpuinfo".into()],
            Vec::new(),
            None,
            Some(std::time::Duration::from_secs(10)),
            None,
        )
        .ok()
        .filter(|(code, _, _)| *code == 0)
        .map(|(_, stdout, _)| {
            let mut features = parse_linux_features(&String::from_utf8_lossy(&stdout));
            features.sort();
            features
        })
        .filter(|features| !features.is_empty());
    (
        Some(smolvm_pack::format::CheckpointClock {
            counter_hz,
            follows_counter_rate,
        }),
        features,
    )
}

/// The host's system counter frequency (`CNTFRQ_EL0`), readable from user
/// space on Linux and macOS.
#[cfg(target_arch = "aarch64")]
fn host_counter_hz() -> Option<u64> {
    let hz: u64;
    // SAFETY: reads a system register EL0 is allowed to read; no memory access.
    unsafe { std::arch::asm!("mrs {}, cntfrq_el0", out(reg) hz) };
    (hz != 0).then_some(hz)
}

#[cfg(not(target_arch = "aarch64"))]
fn host_counter_hz() -> Option<u64> {
    None
}

/// libkrun's tag on VM state written by its macOS backend, which other
/// backends translate rather than parse (see libkrun's `VmCheckpoint`).
const HVF_STATE_TAG: &[u8; 8] = b"SMVCHVF1";

/// Refuse VM state from another platform that its runtime did not tag for
/// translation. A Mac machine started by an older libkrun writes untagged
/// state, which this host's runtime would misread as its own format.
fn validate_state_origin(checkpoint: &PortableCheckpointManifest, state: &Path) -> Result<()> {
    let host_platform = crate::platform::Platform::current()
        .host_oci_platform()
        .to_string();
    if checkpoint.host_platform == host_platform {
        return Ok(());
    }
    let mut tag = [0u8; 8];
    let tagged = std::fs::File::open(state)
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut tag))
        .is_ok()
        && &tag == HVF_STATE_TAG;
    if tagged {
        return Ok(());
    }
    Err(Error::agent(
        "restore checkpoint",
        "the checkpoint's VM state was written by a runtime that cannot be restored on this platform; restart the machine with a newer smolvm and checkpoint it again",
    ))
}

/// Whether a checkpoint captured on `source` may be restored on `host`. An
/// arm64 Mac checkpoint restores on arm64 Linux: libkrun recreates the Mac's
/// virtual board under KVM and the CPU and clock checks below cover the rest.
fn host_platform_compatible(source: &str, host: &str) -> bool {
    source == host || (source == "darwin/arm64" && host == "linux/arm64")
}

/// Refuse a restore whose guest would keep time at the wrong rate.
fn validate_clock(checkpoint: &PortableCheckpointManifest) -> Result<()> {
    let Some(host_hz) = host_counter_hz() else {
        return Ok(());
    };
    let Some(clock) = checkpoint.clock else {
        // Captured before the clock was recorded: the counter rate is unknown,
        // which only a same-platform restore has always assumed away.
        let host_platform = crate::platform::Platform::current()
            .host_oci_platform()
            .to_string();
        if checkpoint.host_platform != host_platform {
            return Err(Error::agent(
                "restore checkpoint",
                "the checkpoint does not record its guest clock; capture it again with a newer smolvm",
            ));
        }
        return Ok(());
    };
    if clock.counter_hz != host_hz && !clock.follows_counter_rate {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "this host's clock runs at {host_hz} Hz but the checkpoint's guest kernel \
                 only keeps time at {} Hz; restart the machine with a newer smolvm and \
                 checkpoint it again",
                clock.counter_hz
            ),
        ));
    }
    Ok(())
}

fn checkpoint_cpu_contract() -> Result<CheckpointCpuContract> {
    if cpu_vendor()?.as_deref() == Some("GenuineIntel") {
        return Ok(CheckpointCpuContract::LinuxKvmIntelPortableV1);
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Ok(CheckpointCpuContract::Aarch64FeaturesV1 {
            features: aarch64_guest_features()?,
        });
    }
    #[allow(unreachable_code)]
    Ok(CheckpointCpuContract::ExactV1 {
        fingerprint: cpu_fingerprint()?,
    })
}

/// Accept a checkpoint whose recorded features this host also provides.
///
/// A superset is enough: extra features on the destination are harmless, since
/// the guest already decided at boot what it would use. Anything missing is
/// named, because "does not match this host" gives an operator nothing to act
/// on, while "missing FEAT_BF16, FEAT_I8MM" says which machines can take it.
///
/// Note this is a genuine set comparison, not a generation ordering. Newer
/// silicon is not automatically a superset: an M4 Max provides twenty features
/// an M1 Pro lacks, yet lacks FEAT_SSBS that the M1 Pro has, so neither
/// direction is safe between them and both are correctly refused.
#[cfg(target_arch = "aarch64")]
fn validate_aarch64_features(required: &[String]) -> Result<()> {
    let available = aarch64_guest_features()?;
    let missing = missing_features(required, &available);
    if missing.is_empty() {
        return Ok(());
    }
    Err(Error::agent(
        "restore checkpoint",
        format!(
            "this host does not provide {} the checkpoint's guest was given: {}",
            if missing.len() == 1 {
                "a CPU feature"
            } else {
                "CPU features"
            },
            missing.join(", ")
        ),
    ))
}

/// On a non-aarch64 host an aarch64 feature contract can never be satisfied;
/// the architecture check upstream already refuses it, so this only keeps the
/// match exhaustive.
#[cfg(not(target_arch = "aarch64"))]
fn validate_aarch64_features(_required: &[String]) -> Result<()> {
    Err(Error::agent(
        "restore checkpoint",
        "checkpoint requires an aarch64 host",
    ))
}

/// Recorded features this host does not provide. Pure, so the comparison is
/// testable against feature sets captured from real machines.
///
/// Gated to match its only caller — the aarch64 validator — plus tests, so a
/// non-aarch64 cross build does not see it as dead code.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
fn missing_features(required: &[String], available: &[String]) -> Vec<String> {
    let have: std::collections::HashSet<&str> = available.iter().map(String::as_str).collect();
    required
        .iter()
        .filter(|name| !have.contains(name.as_str()))
        .cloned()
        .collect()
}

fn validate_cpu_compatibility(checkpoint: &PortableCheckpointManifest) -> Result<()> {
    match &checkpoint.cpu_contract {
        CheckpointCpuContract::ExactV1 { fingerprint } => {
            if fingerprint == &cpu_fingerprint()? {
                return Ok(());
            }
            return Err(Error::agent(
                "restore checkpoint",
                "checkpoint CPU feature contract does not match this host",
            ));
        }
        CheckpointCpuContract::Aarch64FeaturesV1 { features } => {
            // A Mac contract names the Mac's own features, spelled the macOS
            // way and including ones its hypervisor hides from guests. On
            // Linux, check the features the guest itself reported instead.
            #[cfg(target_os = "linux")]
            if checkpoint.host_platform.starts_with("darwin/") {
                let guest = checkpoint.guest_cpu_features.as_ref().ok_or_else(|| {
                    Error::agent(
                        "restore checkpoint",
                        "the checkpoint does not record its guest's CPU features; capture it again with a newer smolvm",
                    )
                })?;
                return validate_aarch64_features(guest);
            }
            return validate_aarch64_features(features);
        }
        CheckpointCpuContract::LinuxKvmIntelPortableV1 => {
            let current_vendor = cpu_vendor()?.ok_or_else(|| {
                Error::agent(
                    "restore checkpoint",
                    "checkpoint CPU contract requires Linux KVM on x86_64",
                )
            })?;
            if current_vendor != "GenuineIntel" {
                return Err(Error::agent(
                    "restore checkpoint",
                    format!("checkpoint requires an Intel KVM host, found '{current_vendor}'"),
                ));
            }
        }
    }

    // The durable vCPU state contains the exact guest CPUID and MSR contract.
    // KVM validates those values when libkrun applies the checkpoint, so a
    // destination missing any required architectural feature still fails
    // closed even though host model/stepping differences are accepted here.
    Ok(())
}

/// Whether a machine mounts image layers from the host over the packed-layers
/// virtio-fs device: a `.smolmachine`'s layers, or a local image archive or
/// directory (including a registry image the host fetched for it).
fn mounts_image_layers(vm: &VmRecord) -> bool {
    vm.source_smolmachine.is_some()
        || vm
            .image
            .as_deref()
            .and_then(crate::data::image_source::packed_layers_dir_for_ref)
            .is_some()
}

/// Identify the registry image a machine boots from a host-fetched archive, if
/// any, so a restore can fetch it again and serve the guest the archive it
/// read.
fn checkpoint_host_image(vm: &VmRecord) -> Result<Option<CheckpointHostImage>> {
    if vm.source_smolmachine.is_some() {
        return Ok(None);
    }
    let Some(reference) = vm.host_fetched_origin() else {
        return Ok(None);
    };
    let archive = vm
        .image
        .as_deref()
        .and_then(crate::data::image_source::archive_file_for_ref)
        .ok_or_else(|| Error::agent("checkpoint machine", "image archive has no cache entry"))?;
    let (archive_size, archive_mtime) = crate::data::image_source::archive_signature(&archive)
        .map_err(|error| {
            Error::agent(
                "checkpoint machine",
                format!(
                    "the archive of {reference} is missing from this host's image cache ({}): {error}",
                    archive.display()
                ),
            )
        })?;
    Ok(Some(CheckpointHostImage {
        config_digest: crate::image_store::archive_config_digest(&archive)?,
        reference,
        archive_size,
        archive_mtime,
    }))
}

/// The machine image to boot after restoring a checkpoint whose machine booted
/// a host-fetched registry image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredHostImage {
    /// The `local:` reference serving the archive the captured guest read.
    pub local: String,
    /// The registry reference it came from, as the checkpoint names it.
    pub origin: String,
    /// The manifest digest this host fetched.
    pub digest: String,
}

impl RestoredHostImage {
    /// Point a restored machine's record at this image.
    pub fn apply(self, record: &mut VmRecord) {
        record.image = Some(self.local);
        record.image_origin = Some(self.origin);
        record.image_origin_digest = Some(self.digest);
    }
}

/// Fetch the registry image a checkpoint's machine booted from a host-fetched
/// archive, whatever the restored machine's network, and serve it the way the
/// captured guest read it. The guest's state holds that archive's virtio-fs
/// device and keys its flattened image on the archive's size and time, so the
/// restore needs the same image at the same size and time. Returns `None` when
/// the checkpoint has no host-fetched image.
pub async fn fetch_checkpoint_host_image(
    checkpoint: &PortableCheckpointManifest,
    auth: &crate::registry::PullAuth,
) -> Result<Option<RestoredHostImage>> {
    let Some(host) = &checkpoint.host_image else {
        return Ok(None);
    };
    let fetched = crate::image_store::fetch_checkpoint_image(&host.reference, auth)
        .await
        .map_err(|error| {
            Error::agent(
                "restore checkpoint",
                format!(
                    "fetch {} for the restored machine's image: {error}",
                    host.reference
                ),
            )
        })?;
    let host = host.clone();
    tokio::task::spawn_blocking(move || serve_checkpoint_host_image(&host, fetched))
        .await
        .map_err(|error| Error::agent("restore checkpoint", error.to_string()))?
        .map(Some)
}

/// [`fetch_checkpoint_host_image`] for a synchronous caller.
pub fn fetch_checkpoint_host_image_blocking(
    checkpoint: &PortableCheckpointManifest,
) -> Result<Option<RestoredHostImage>> {
    if checkpoint.host_image.is_none() {
        return Ok(None);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| Error::agent("restore checkpoint", error.to_string()))?
        .block_on(fetch_checkpoint_host_image(
            checkpoint,
            &crate::registry::PullAuth::FromConfig,
        ))
}

fn serve_checkpoint_host_image(
    host: &CheckpointHostImage,
    fetched: crate::image_store::FetchedImage,
) -> Result<RestoredHostImage> {
    let archive = crate::data::image_source::archive_file_for_ref(&fetched.local)
        .ok_or_else(|| Error::agent("restore checkpoint", "fetched image has no cache entry"))?;
    let config = crate::image_store::archive_config_digest(&archive)?;
    let (size, _) = crate::data::image_source::archive_signature(&archive)?;
    if config != host.config_digest || size != host.archive_size {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "{} is no longer the image this checkpoint was captured with \
                 (config {config}, {size} bytes; expected {}, {} bytes)",
                host.reference, host.config_digest, host.archive_size
            ),
        ));
    }
    Ok(RestoredHostImage {
        local: crate::data::image_source::archive_with_mtime(&fetched.local, host.archive_mtime)?,
        origin: host.reference.clone(),
        digest: fetched.digest,
    })
}

/// Identify the pack a machine mounts its image layers from, if any, so a
/// restore can attach the same layers again.
fn checkpoint_packed_layers(name: &str, vm: &VmRecord) -> Result<Option<CheckpointPackedLayers>> {
    let Some(sidecar) = vm.source_smolmachine.as_deref() else {
        return Ok(None);
    };
    let sidecar = Path::new(sidecar);
    let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar)
        .map_err(|error| Error::agent("read pack footer", error.to_string()))?;
    // The shared store records the artifact digest when it extracts a pack;
    // hash the sidecar only when that record is unavailable.
    let recorded =
        crate::agent::read_shared_pack_pointer(&crate::agent::machine_layers_cache_dir(name))
            .and_then(|shared| smolvm_pack::extract::read_shared_artifact_sha256(&shared).ok());
    let artifact_sha256 = match recorded {
        Some(digest) => digest,
        None => sha256_file(sidecar)?,
    };
    let digest = format!(
        "sha256:{}",
        artifact_sha256
            .trim_start_matches("sha256:")
            .to_ascii_lowercase()
    );
    let cache = smolvm_registry::BlobCache::open_default()
        .map_err(|error| Error::agent("open pack cache", error.to_string()))?;
    if cache.get(&digest).is_none() {
        cache
            .put_file_verified(&digest, sidecar)
            .map_err(|error| Error::agent("cache checkpoint pack", error.to_string()))?;
    }
    // The window this machine's running guest booted with, when recorded for
    // its current VMM; otherwise restores use the legacy window.
    let dax_window_bytes = vm.pid.zip(vm.pid_start_time).and_then(|(pid, start)| {
        crate::agent::virtiofs::running_window(&crate::agent::vm_data_dir(name), pid as u32, start)
    });
    Ok(Some(CheckpointPackedLayers {
        artifact_sha256: digest.trim_start_matches("sha256:").to_string(),
        footer_checksum: footer.checksum,
        registry_ref: vm.source_registry_ref.clone(),
        dax_window_bytes,
    }))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).map_err(|error| Error::agent("hash pack", error.to_string()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .map_err(|error| Error::agent("hash pack", error.to_string()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// The locally cached `.smolmachine` a checkpoint's layers came from, found by
/// its content digest so no registry is involved when this host has it.
pub fn cached_checkpoint_pack(packed: &CheckpointPackedLayers) -> Option<PathBuf> {
    let cache = smolvm_registry::BlobCache::open_default().ok()?;
    cache.get(&format!("sha256:{}", packed.artifact_sha256))
}

/// Confirm that `sidecar` is the pack a checkpoint was captured with.
pub fn verify_checkpoint_pack(sidecar: &Path, packed: &CheckpointPackedLayers) -> Result<()> {
    let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar)
        .map_err(|error| Error::agent("read pack footer", error.to_string()))?;
    if footer.checksum != packed.footer_checksum {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "pack {} is not the one this checkpoint was captured with",
                sidecar.display()
            ),
        ));
    }
    Ok(())
}

/// Serve a pack's image layers to a machine: extracted once per host into the
/// shared store where it is available, otherwise into the machine's own
/// directory. Used both when a machine is created from a pack and when a
/// checkpoint of one is restored.
pub fn materialize_pack_layers(name: &str, sidecar: &Path) -> Result<()> {
    materialize_pack_layers_with_options(
        name,
        sidecar,
        smolvm_pack::extract::SharedExtractOptions::default(),
    )
}

/// [`materialize_pack_layers`] with the shortcuts a restore can take: a
/// SHA-256 already known for the artifact's inode (see
/// [`VerifiedSidecar::digest_proof`]), and, for a long-lived server, leaving
/// checkpoint RAM to reach the disk in the background.
pub fn materialize_pack_layers_with_options(
    name: &str,
    sidecar: &Path,
    options: smolvm_pack::extract::SharedExtractOptions,
) -> Result<()> {
    let cache_dir = crate::agent::machine_layers_cache_dir(name);
    let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar)
        .map_err(|error| Error::agent("read sidecar footer", error.to_string()))?;
    if smolvm_pack::extract::shared_extract_enabled() {
        #[cfg(target_os = "linux")]
        {
            crate::artifact_cache::materialize_shared_pack_lease_with_options(
                sidecar, &footer, &cache_dir, false, options,
            )
            .map_err(|error| Error::agent("extract sidecar (shared)", error.to_string()))?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!("shared pack extraction is Linux-only")
    }
    // A private extraction neither hashes the artifact nor defers its sync.
    drop(options);
    smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
    match std::fs::remove_dir_all(&cache_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::agent("clear packed layers cache", error.to_string())),
    }
    smolvm_pack::extract::extract_sidecar(sidecar, &cache_dir, &footer, false, false)
        .map_err(|error| Error::agent("extract sidecar", error.to_string()))
}

/// After a checkpoint is installed, mount the pack its image layers came from,
/// using this host's copy. Returns the sidecar and registry reference to record
/// on the restored machine, or `None` when the checkpoint mounts no pack.
pub fn attach_cached_checkpoint_pack(
    name: &str,
    checkpoint: &PortableCheckpointManifest,
) -> Result<Option<(String, Option<String>)>> {
    let Some(packed) = &checkpoint.packed_layers else {
        return Ok(None);
    };
    let sidecar = cached_checkpoint_pack(packed).ok_or_else(|| {
        let source = packed
            .registry_ref
            .as_deref()
            .map(|reference| format!(" ({reference})"))
            .unwrap_or_default();
        Error::agent(
            "restore checkpoint",
            format!(
                "this checkpoint mounts image layers from pack sha256:{}{source}, which this \
                 host does not have; pull that pack first",
                packed.artifact_sha256
            ),
        )
    })?;
    verify_checkpoint_pack(&sidecar, packed)?;
    materialize_pack_layers(name, &sidecar)?;
    Ok(Some((
        sidecar.to_string_lossy().into_owned(),
        packed.registry_ref.clone(),
    )))
}

/// Reject host-bound device state that cannot yet be resumed from an artifact.
pub fn validate_capture_profile(vm: &VmRecord) -> Result<()> {
    let mut unsupported = Vec::new();
    if !vm.mounts.is_empty() || !vm.staged_mounts.is_empty() {
        unsupported.push("host mounts");
    }
    if !vm.published_sockets.is_empty() {
        unsupported.push("published sockets");
    }
    if !vm.remote_volumes.is_empty() {
        unsupported.push("remote volumes");
    }
    if !vm.secret_refs.is_empty() {
        unsupported.push("host secret references");
    }
    // A `.smolmachine` source is recorded in the checkpoint and attached again
    // on restore, and so is a registry image the host fetched for a machine
    // with no network. Layers found only under a host path named by the image
    // are not, so they stay unsupported.
    if vm.source_smolmachine.is_none()
        && vm.host_fetched_origin().is_none()
        && vm
            .image
            .as_deref()
            .and_then(crate::data::image_source::packed_layers_dir_for_ref)
            .is_some()
    {
        unsupported.push("host-backed image layers");
    }
    if vm.dns.is_some() {
        unsupported.push("custom DNS");
    }
    if vm.network_name.is_some() {
        unsupported.push("named inter-VM networking");
    }
    if vm.gpu.unwrap_or(false) {
        unsupported.push("Vulkan GPU state");
    }
    if vm.cuda {
        unsupported.push("CUDA state");
    }
    if vm.rosetta.unwrap_or(false) {
        unsupported.push("Rosetta");
    }
    if vm.ssh_agent {
        unsupported.push("SSH agent forwarding");
    }
    if vm.docker_socket {
        unsupported.push("Docker socket forwarding");
    }
    // A checkpoint would carry the machine's cache layer without the shared
    // base it is a layer over, and restore a disk that reads as garbage.
    if vm.cache_disk.is_some() {
        unsupported.push("cache disks (branch the machine instead)");
    }
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(Error::config(
        "checkpoint machine",
        format!(
            "the initial portable checkpoint profile does not support {}; stop or detach these resources before capture",
            unsupported.join(", ")
        ),
    ))
}

/// Parse the effective network backend persisted by a version-two checkpoint.
pub fn restored_network_backend(
    checkpoint: &PortableCheckpointManifest,
) -> Result<Option<crate::network::NetworkBackend>> {
    let Some(label) = checkpoint
        .network
        .as_ref()
        .and_then(|network| network.backend.as_deref())
    else {
        return Ok(None);
    };
    match label {
        "tsi" => Ok(Some(crate::network::NetworkBackend::Tsi)),
        "virtio-net" => Ok(Some(crate::network::NetworkBackend::VirtioNet)),
        other => Err(Error::agent(
            "restore checkpoint",
            format!("checkpoint uses unknown network backend '{other}'"),
        )),
    }
}

/// Artifact path of a captured machine's credential CA.
const CREDENTIAL_CA_ASSET: &str = "checkpoint/credential-ca.json";
/// An exported CA is a name, one certificate and one key; anything larger is
/// not one.
const MAX_CREDENTIAL_CA_BYTES: u64 = 64 * 1024;

/// Stage the machine's credential CA beside the captured state. The guest in
/// this checkpoint trusts that CA (its trust bundle is in the captured RAM),
/// so a restore must keep signing with it; a freshly minted CA would make
/// every intercepted request fail TLS. `None` without a credential policy or
/// before the CA was first created.
fn checkpoint_credential_ca(
    name: &str,
    vm: &VmRecord,
    snapshot_dir: &Path,
) -> Result<Option<CheckpointAsset>> {
    let Some(launch) = crate::credentials::CredentialLaunch::for_record(name, vm) else {
        return Ok(None);
    };
    if !smolvm_credentials::MachineCa::exists(&launch.ca_dir) {
        return Ok(None);
    }
    let ca = smolvm_credentials::MachineCa::load(&launch.ca_dir, &launch.ca_owner)
        .map_err(|e| Error::agent("capture credential CA", format!("{e:#}")))?;
    let path = snapshot_dir.join("credential-ca.json");
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .and_then(|mut file| file.write_all(ca.export().as_bytes()))
            .map_err(|e| Error::agent("stage credential CA", e.to_string()))?;
    }
    describe_asset(&path, CREDENTIAL_CA_ASSET).map(Some)
}

/// Install a checkpoint's credential CA as the restored machine's own, so its
/// interceptor signs with the CA the captured guest already trusts. The staged
/// copy is removed once the CA is in place.
fn install_credential_ca(
    extracted: &Path,
    vm_data_dir: &Path,
    partial: &Path,
    asset: &CheckpointAsset,
) -> Result<()> {
    if asset.path != CREDENTIAL_CA_ASSET || asset.size > MAX_CREDENTIAL_CA_BYTES {
        return Err(Error::agent(
            "install checkpoint",
            format!("unexpected credential CA asset '{}'", asset.path),
        ));
    }
    let staged = partial.join("credential-ca.json");
    copy_verified(&extracted.join(CREDENTIAL_CA_ASSET), &staged, asset, false)?;
    let document = zeroize::Zeroizing::new(
        std::fs::read_to_string(&staged)
            .map_err(|e| Error::agent("read checkpoint credential CA", e.to_string()))?,
    );
    let _ = std::fs::remove_file(&staged);
    smolvm_credentials::MachineCa::import(&document)
        .and_then(|ca| ca.save(&vm_data_dir.join(crate::credentials::CA_DIR_NAME)))
        .map_err(|e| Error::agent("install checkpoint credential CA", format!("{e:#}")))
}

fn checkpoint_network(vm: &VmRecord) -> CheckpointNetwork {
    let effective = vm.launch_network_plan();
    let backend = match effective.backend {
        crate::network::EffectiveNetworkBackend::None => None,
        crate::network::EffectiveNetworkBackend::Tsi => Some("tsi".to_string()),
        crate::network::EffectiveNetworkBackend::VirtioNet => Some("virtio-net".to_string()),
    };
    CheckpointNetwork {
        enabled: effective.has_network(),
        ports: vm
            .ports
            .iter()
            .map(|(host, guest)| CheckpointPort {
                host: *host,
                guest: *guest,
            })
            .collect(),
        backend,
        dns: vm.dns.map(|dns| dns.to_string()),
        network_name: vm.network_name.clone(),
        guest_subnet: vm.guest_subnet.clone(),
        allowed_cidrs: vm.allowed_cidrs.clone(),
        dns_filter_hosts: vm.dns_filter_hosts.clone(),
        // The captured workload holds its placeholders (in its environment and
        // possibly its RAM), so the policy and the exact placeholders must
        // travel with the checkpoint or the restored machine runs with no
        // interceptor and the workload's requests carry the bare placeholder
        // upstream. Bindings and placeholders are not secret; the value is
        // resolved from the restore host's environment.
        credential_policy: vm.credential_policy.clone().filter(|p| !p.is_empty()),
        credential_placeholders: vm.credential_placeholders.clone(),
    }
}

fn disk_target(role: &str, index: usize, format: &str) -> Result<String> {
    if index == 0 {
        return match (role, format) {
            ("storage", "qcow2") => Ok("storage.qcow2".to_string()),
            ("storage", "raw") => Ok("storage.raw".to_string()),
            ("overlay", "qcow2") => Ok("overlay.qcow2".to_string()),
            ("overlay", "raw") => Ok("overlay.raw".to_string()),
            _ => Err(Error::agent(
                "checkpoint disk",
                format!("invalid disk role/format {role}/{format}"),
            )),
        };
    }
    if role != "storage" && role != "overlay" {
        return Err(Error::agent(
            "checkpoint disk",
            format!("invalid disk role '{role}'"),
        ));
    }
    if format != "raw" && format != "qcow2" {
        return Err(Error::agent(
            "checkpoint disk",
            format!("invalid disk format '{format}'"),
        ));
    }
    if index >= 64 {
        return Err(Error::agent(
            "checkpoint disk",
            format!("{role} backing chain is too deep"),
        ));
    }
    // Backings live beside the active top layer because qcow2 backing paths
    // are relative to the image that references them. Use an explicit reserved
    // namespace: the earlier single-character names eventually collided with
    // live-fork's `d/` disk-generation directory at deeper lineage depths.
    Ok(format!(".smolcheckpoint-{role}-{index}.{format}"))
}

fn inspect_qcow2(path: &Path) -> Result<(Option<String>, Option<String>)> {
    let qcow = Qcow2::<ImagoFile>::builder_path(path)
        .backing(None)
        .data_file(None)
        // The gate opens only the explicitly supplied top-level path here;
        // backing and external-data auto-open are both disabled above.
        .open_sync(PermissiveImplicitOpenGate::default())
        .map_err(|error| Error::agent("inspect checkpoint qcow2", error.to_string()))?;
    if qcow.requires_external_data_file() {
        return Err(Error::agent(
            "checkpoint disk",
            format!("{} uses an unsupported external data file", path.display()),
        ));
    }
    Ok((
        qcow.implicit_backing_file().cloned(),
        qcow.implicit_backing_format().cloned(),
    ))
}

fn detect_disk_format(path: &Path, declared: Option<&str>) -> Result<&'static str> {
    match declared {
        Some("raw" | "file") => return Ok("raw"),
        Some("qcow2") => return Ok("qcow2"),
        Some(other) => {
            return Err(Error::agent(
                "checkpoint disk",
                format!("unsupported backing format '{other}'"),
            ));
        }
        None => {}
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    let mut magic = [0_u8; 4];
    let count = file
        .read(&mut magic)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    Ok(if count == magic.len() && magic == *b"QFI\xfb" {
        "qcow2"
    } else {
        "raw"
    })
}

fn resolve_backing_path(image: &Path, backing: &str) -> PathBuf {
    let backing = PathBuf::from(backing);
    if backing.is_absolute() {
        backing
    } else {
        image
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(backing)
    }
}

/// The first MiB of qcow2 image `path` with its backing name replaced by
/// `backing`, as [`rewrite_qcow2_backing`] would leave it, without touching
/// the file. `None` when the image is shorter than a qcow2 header or its
/// header cluster extends past the first MiB.
fn qcow2_head_with_backing(path: &Path, backing: &str) -> Result<Option<Vec<u8>>> {
    const HEAD: u64 = 1024 * 1024;
    let size = std::fs::metadata(path)
        .map_err(|error| Error::agent("inspect qcow2", error.to_string()))?
        .len();
    let mut head = vec![0_u8; size.min(HEAD) as usize];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .map_err(|error| Error::agent("read qcow2 header", error.to_string()))?;
    if head.len() < 104 {
        return Ok(None);
    }
    let cluster_bits = u32::from_be_bytes(head[20..24].try_into().unwrap());
    if !(9..=20).contains(&cluster_bits) || (1_u64 << cluster_bits) > head.len() as u64 {
        return Ok(None);
    }
    // Apply the exact file rewrite to a scratch copy of the header cluster.
    let scratch = tempfile::NamedTempFile::new()
        .map_err(|error| Error::agent("stage qcow2 header", error.to_string()))?;
    std::fs::write(scratch.path(), &head[..1 << cluster_bits])
        .map_err(|error| Error::agent("stage qcow2 header", error.to_string()))?;
    rewrite_qcow2_backing(scratch.path(), backing)?;
    let cluster = std::fs::read(scratch.path())
        .map_err(|error| Error::agent("stage qcow2 header", error.to_string()))?;
    head[..cluster.len()].copy_from_slice(&cluster);
    Ok(Some(head))
}

fn rewrite_qcow2_backing(path: &Path, backing: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| Error::agent("rewrite qcow2 backing", error.to_string()))?;
    for (offset, bytes) in qcow2_backing_patches(&mut file, path, backing)? {
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(&bytes))
            .map_err(|error| Error::agent("rewrite qcow2 backing", error.to_string()))?;
    }
    file.sync_all()
        .map_err(|error| Error::agent("rewrite qcow2 backing", error.to_string()))
}

/// The `(offset, bytes)` writes that make the qcow2 image in `file` name
/// `backing` as its backing file. Only the header's backing name, its
/// zero padding and its length field change.
fn qcow2_backing_patches(
    file: &mut std::fs::File,
    path: &Path,
    backing: &str,
) -> Result<Vec<(u64, Vec<u8>)>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| Error::agent("read qcow2 header", error.to_string()))?;
    let mut header = [0_u8; 104];
    file.read_exact(&mut header)
        .map_err(|error| Error::agent("read qcow2 header", error.to_string()))?;
    if header[..4] != *b"QFI\xfb" {
        return Err(Error::agent(
            "rewrite qcow2 backing",
            format!("{} is not qcow2", path.display()),
        ));
    }
    let offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let old_len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let cluster_bits = u32::from_be_bytes(header[20..24].try_into().unwrap());
    let header_len = match version {
        2 => 72,
        3 => u64::from(u32::from_be_bytes(header[100..104].try_into().unwrap())),
        _ => 0,
    };
    if !(9..=21).contains(&cluster_bits)
        || header_len < if version == 3 { 104 } else { 72 }
        || offset < header_len
        || old_len == 0
        || old_len > 1023
        || backing.is_empty()
        || backing.len() > 1023
    {
        return Err(Error::agent(
            "rewrite qcow2 backing",
            format!(
                "{} cannot replace its {}-byte backing name with {} bytes",
                path.display(),
                old_len,
                backing.len()
            ),
        ));
    }
    let end = offset
        .checked_add(old_len.max(backing.len()) as u64)
        .ok_or_else(|| Error::agent("rewrite qcow2 backing", "header offset overflow"))?;
    if end > (1_u64 << cluster_bits)
        || end
            > file
                .metadata()
                .map_err(|e| Error::agent("inspect qcow2", e.to_string()))?
                .len()
    {
        return Err(Error::agent(
            "rewrite qcow2 backing",
            "backing filename lies outside the qcow2 header cluster or file",
        ));
    }
    // QCOW2 stores extensions before the backing name, which may grow into
    // the remaining first-cluster padding. Never overwrite another cluster
    // or non-padding bytes when rebasing a staged copy.
    let mut extension = header_len;
    while extension < offset {
        if offset - extension < 8 {
            return Err(Error::agent(
                "rewrite qcow2 backing",
                "truncated header extension",
            ));
        }
        let mut ext = [0_u8; 8];
        file.seek(SeekFrom::Start(extension))
            .and_then(|_| file.read_exact(&mut ext))
            .map_err(|e| Error::agent("read qcow2 extension", e.to_string()))?;
        if ext[..4] == [0; 4] {
            break;
        }
        let size = u64::from(u32::from_be_bytes(ext[4..8].try_into().unwrap()));
        extension += 8 + ((size + 7) & !7);
        if extension > offset {
            return Err(Error::agent(
                "rewrite qcow2 backing",
                "backing filename overlaps a header extension",
            ));
        }
    }
    if backing.len() > old_len {
        let mut padding = vec![0_u8; backing.len() - old_len];
        file.seek(SeekFrom::Start(offset + old_len as u64))
            .and_then(|_| file.read_exact(&mut padding))
            .map_err(|e| Error::agent("read qcow2 padding", e.to_string()))?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::agent(
                "rewrite qcow2 backing",
                "backing filename would overwrite non-padding bytes",
            ));
        }
    }
    let mut name = backing.as_bytes().to_vec();
    name.resize(old_len.max(backing.len()), 0);
    Ok(vec![
        (offset, name),
        (16, (backing.len() as u32).to_be_bytes().to_vec()),
    ])
}

/// Identity of every file in a machine's storage and overlay disk chains, top
/// to base, one line each: role, format, device, inode, size, modification
/// and status change times, and path. Any write to a file changes its line.
/// The status change time of a backing only the service can write, such as a
/// storage template, is left out: staging hard-links raw backings, which
/// changes it. So is that of a backing another machine owns, such as a fork's
/// golden: every pause of every fork pins it with a hard link.
#[cfg(unix)]
fn disk_chain_identity(vm_data: &Path) -> Result<String> {
    use std::fmt::Write as _;
    use std::os::unix::fs::MetadataExt;
    let own = vm_data.canonicalize()?;
    let mut identity = String::new();
    for (role, raw_name) in [
        ("storage", crate::storage::STORAGE_DISK_FILENAME),
        ("overlay", crate::storage::OVERLAY_DISK_FILENAME),
    ] {
        let (mut source, initial_format) = crate::agent::resolve_disk_image(vm_data, raw_name);
        if !source.is_file() {
            continue;
        }
        let mut format = match initial_format {
            crate::data::disk::DiskFormat::Raw => "raw",
            crate::data::disk::DiskFormat::Qcow2 => "qcow2",
        };
        for index in 0..64 {
            let metadata = std::fs::metadata(&source)
                .map_err(|error| Error::agent("inspect machine disk", error.to_string()))?;
            let service_only =
                metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0;
            let anothers = source
                .canonicalize()
                .is_ok_and(|source| !source.starts_with(&own));
            let changed = if index == 0 || !(service_only || anothers) {
                format!("{}.{}", metadata.ctime(), metadata.ctime_nsec())
            } else {
                "-".to_string()
            };
            let _ = writeln!(
                identity,
                "{role}\t{format}\t{}\t{}\t{}\t{}.{}\t{changed}\t{}",
                metadata.dev(),
                metadata.ino(),
                metadata.size(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                source.display()
            );
            if format != "qcow2" {
                break;
            }
            let (backing, backing_format) = inspect_qcow2(&source)?;
            let Some(backing) = backing else {
                break;
            };
            let backing_source = resolve_backing_path(&source, &backing);
            format = detect_disk_format(&backing_source, backing_format.as_deref())?;
            source = backing_source;
        }
    }
    Ok(identity)
}

/// After a pause has stopped the machine, record that its own disk chains are
/// still exactly what the checkpoint captured, so resume can keep them rather
/// than install the checkpoint's copies. Nothing is recorded if they changed.
#[cfg(unix)]
fn record_paused_disks(vm_data: &Path, artifact: &Path, captured: Option<&str>) {
    let Some(captured) = captured else {
        return;
    };
    let result = (|| -> Result<()> {
        if disk_chain_identity(vm_data)? != captured {
            tracing::info!(vm_data = %vm_data.display(), "disks changed after capture; resume installs the checkpoint's");
            return Ok(());
        }
        let marker = paused_disks_marker(vm_data)?;
        let partial = marker.with_extension(format!("{}", std::process::id()));
        let mut file = std::fs::File::create(&partial)?;
        writeln!(file, "{}", artifact.display())?;
        file.write_all(captured.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&partial, &marker)?;
        Ok(())
    })();
    if let Err(error) = result {
        tracing::warn!(vm_data = %vm_data.display(), %error, "could not record paused disks; resume installs the checkpoint's");
        let _ = remove_paused_disks_marker(vm_data);
    }
}

/// Where [`record_paused_disks`] keeps a machine's record: beside its data
/// directory, which its VMM's uid owns, so that the VMM cannot write it.
fn paused_disks_marker(vm_data: &Path) -> Result<PathBuf> {
    match (vm_data.parent(), vm_data.file_name()) {
        (Some(parent), Some(name)) => {
            Ok(parent.join(format!(".{}{PAUSED_DISKS_SUFFIX}", name.to_string_lossy())))
        }
        _ => Err(Error::agent(
            "record paused disks",
            format!("{} has no parent", vm_data.display()),
        )),
    }
}

/// The data directory name a paused-disks record belongs to, or `None` when
/// `path` is not one.
pub(crate) fn paused_disks_marker_owner(path: &Path) -> Option<&str> {
    path.file_name()?
        .to_str()?
        .strip_prefix('.')?
        .strip_suffix(PAUSED_DISKS_SUFFIX)
        .filter(|name| !name.is_empty())
}

fn remove_paused_disks_marker(vm_data: &Path) -> Result<()> {
    match std::fs::remove_file(paused_disks_marker(vm_data)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Where a paused machine pins the backing layers its artifact references:
/// beside its data directory, like [`paused_disks_marker`], so its VMM cannot
/// replace them.
fn paused_layers_dir(vm_data: &Path) -> Result<PathBuf> {
    match (vm_data.parent(), vm_data.file_name()) {
        (Some(parent), Some(name)) => {
            Ok(parent.join(format!(".{}{PAUSED_LAYERS_SUFFIX}", name.to_string_lossy())))
        }
        _ => Err(Error::agent(
            "pin paused layers",
            format!("{} has no parent", vm_data.display()),
        )),
    }
}

/// The data directory name a paused-layers directory belongs to, or `None`
/// when `path` is not one.
pub(crate) fn paused_layers_owner(path: &Path) -> Option<&str> {
    path.file_name()?
        .to_str()?
        .strip_prefix('.')?
        .strip_suffix(PAUSED_LAYERS_SUFFIX)
        .filter(|name| !name.is_empty())
}

/// Drop a machine's pinned layers. A layer stays on disk while its owner or
/// any other pin still links it.
pub(crate) fn remove_paused_layers(vm_data: &Path) -> Result<()> {
    match std::fs::remove_dir_all(paused_layers_dir(vm_data)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// A backing layer a pause artifact references rather than carries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedLayer {
    /// The artifact path the layer would have been packed under.
    archive_path: String,
    /// The pin's file name in the paused-layers directory.
    pin: String,
    /// The backing filename to write into a qcow2 layer when it is installed.
    next_target: Option<String>,
    dev: u64,
    ino: u64,
    size: u64,
}

/// Backing layers another machine owns that a pause links instead of
/// packing.
///
/// A fork's chain ends in layers its source (a golden) owns. Every pause of
/// every fork would otherwise compress the same immutable bytes into its own
/// artifact again. A hard link keeps the layer alive however its owner fares,
/// at no cost, and the artifact carries only what the machine itself wrote.
/// Resume reads none of it while the machine's own disks are intact; when they
/// are not, it installs the layer from its pin. Off-host export needs a
/// complete artifact, built from the pins on demand.
#[cfg(unix)]
struct LayerPins {
    vm_data: PathBuf,
    dir: PathBuf,
    layers: Vec<PinnedLayer>,
}

#[cfg(unix)]
impl LayerPins {
    /// Pins for a pause of the machine whose data directory is `vm_data`,
    /// dropping any a failed earlier pause left.
    fn new(vm_data: &Path) -> Result<Self> {
        remove_paused_layers(vm_data)?;
        Ok(Self {
            vm_data: vm_data.canonicalize()?,
            dir: paused_layers_dir(vm_data)?,
            layers: Vec::new(),
        })
    }

    /// Pin `source` as the layer at `archive_path` when another machine owns
    /// it. `false` means the caller packs it as before.
    fn pin(
        &mut self,
        source: &Path,
        archive_path: &str,
        next_target: Option<&str>,
    ) -> Result<bool> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        // The machine's own layers are its to change; another's are immutable.
        match source.canonicalize() {
            Ok(source) if !source.starts_with(&self.vm_data) => {}
            _ => return Ok(false),
        }
        if self.layers.is_empty() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&self.dir)
                .map_err(|error| Error::agent("pin paused layers", error.to_string()))?;
        }
        let pin = archive_path.replace('/', "-");
        if let Err(error) = std::fs::hard_link(source, self.dir.join(&pin)) {
            tracing::info!(%error, layer = archive_path, "backing layer packed: it cannot be pinned");
            return Ok(false);
        }
        let metadata = std::fs::metadata(self.dir.join(&pin))
            .map_err(|error| Error::agent("pin paused layers", error.to_string()))?;
        self.layers.push(PinnedLayer {
            archive_path: archive_path.to_string(),
            pin,
            next_target: next_target.map(str::to_string),
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
        });
        Ok(true)
    }

    /// Durably record the pins for `artifact`, before it becomes the
    /// machine's resume point.
    fn commit(&self, artifact: &Path) -> Result<()> {
        if self.layers.is_empty() {
            return Ok(());
        }
        let mut index = format!("{}\n", artifact.display());
        for layer in &self.layers {
            index.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\n",
                layer.archive_path,
                layer.pin,
                layer.next_target.as_deref().unwrap_or(""),
                layer.dev,
                layer.ino,
                layer.size
            ));
        }
        let path = self.dir.join(PAUSED_LAYERS_INDEX);
        let partial = path.with_extension(format!("{}", std::process::id()));
        let mut file = std::fs::File::create(&partial)?;
        file.write_all(index.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&partial, &path)?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

/// Without Unix file identities nothing is pinned: pauses pack every layer.
#[cfg(not(unix))]
struct LayerPins;

#[cfg(not(unix))]
impl LayerPins {
    fn pin(&mut self, _: &Path, _: &str, _: Option<&str>) -> Result<bool> {
        Ok(false)
    }
}

/// The layers pinned for `artifact`, the machine's current pause. None when
/// it pinned nothing, or the pins belong to another pause.
fn paused_layers(vm_data: &Path, artifact: &Path) -> Result<Vec<PinnedLayer>> {
    let dir = paused_layers_dir(vm_data)?;
    let index = match std::fs::read_to_string(dir.join(PAUSED_LAYERS_INDEX)) {
        Ok(index) => index,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let invalid = || Error::agent("read paused layers", "malformed pinned-layer index");
    let mut lines = index.lines();
    if lines.next().map(Path::new) != Some(artifact) {
        return Ok(Vec::new());
    }
    lines
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            let [archive_path, pin, next_target, dev, ino, size] = fields[..] else {
                return Err(invalid());
            };
            if pin.contains('/') || pin.starts_with('.') {
                return Err(invalid());
            }
            Ok(PinnedLayer {
                archive_path: archive_path.to_string(),
                pin: pin.to_string(),
                next_target: (!next_target.is_empty()).then(|| next_target.to_string()),
                dev: dev.parse().map_err(|_| invalid())?,
                ino: ino.parse().map_err(|_| invalid())?,
                size: size.parse().map_err(|_| invalid())?,
            })
        })
        .collect()
}

/// A paused machine's saved execution as a self-contained artifact, for use
/// on another host: the artifact itself when its pause pinned nothing, or else
/// a new one with the pinned layers packed back in, open and already unlinked.
/// Building it costs what packing those layers at pause would have, paid only
/// by a pause that leaves the host.
pub(crate) fn exportable_paused_artifact(vm_data: &Path, artifact: &Path) -> Result<std::fs::File> {
    let pinned = paused_layers(vm_data, artifact)?;
    if pinned.is_empty() {
        return Ok(std::fs::File::open(artifact)?);
    }
    let footer = ensure_checkpoint_layout(artifact)?;
    let manifest = smolvm_pack::packer::read_manifest_from_sidecar(artifact)
        .map_err(|error| Error::agent("read paused checkpoint", error.to_string()))?;
    // Beside the pins, so raw layers link instead of copying.
    let work = tempfile::Builder::new()
        .prefix(".export-")
        .tempdir_in(vm_data)?;
    let staging = work.path().join("assets");
    smolvm_pack::extract::extract_verified_checkpoint_sidecar(
        artifact,
        &staging,
        &footer,
        &[],
        &[],
    )
    .map_err(|error| Error::agent("extract paused checkpoint", error.to_string()))?;
    for layer in &pinned {
        install_pinned_layer(vm_data, layer, &staging)?;
    }
    let output = work.path().join("complete.smolcheckpoint");
    let collector = AssetCollector::new(staging)
        .map_err(|error| Error::agent("collect checkpoint assets", error.to_string()))?;
    Packer::new(manifest)
        .with_asset_collector(collector)
        .with_direct_artifact_io()
        .pack_artifact(&output)
        .map_err(|error| Error::agent("pack checkpoint", error.to_string()))?;
    // The open file outlives the work directory.
    Ok(std::fs::File::open(&output)?)
}

/// Put a pinned layer where extraction would have: at its archive path under
/// `extracted`, with its backing filename rewritten as packing would have.
#[cfg(unix)]
fn install_pinned_layer(vm_data: &Path, layer: &PinnedLayer, extracted: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let pin = paused_layers_dir(vm_data)?.join(&layer.pin);
    let metadata = std::fs::symlink_metadata(&pin)
        .map_err(|error| Error::agent("install pinned layer", error.to_string()))?;
    if !metadata.is_file()
        || (metadata.dev(), metadata.ino(), metadata.len()) != (layer.dev, layer.ino, layer.size)
    {
        return Err(Error::agent(
            "install pinned layer",
            format!("{} is not the layer that was pinned", pin.display()),
        ));
    }
    let destination = extracted.join(&layer.archive_path);
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match &layer.next_target {
        Some(target) => {
            crate::disk_utils::clone_or_copy_file(&pin, &destination)?;
            rewrite_qcow2_backing(&destination, target)?;
        }
        // A raw layer has nothing to rewrite, and installs as a link.
        None => {
            if std::fs::hard_link(&pin, &destination).is_err() {
                crate::disk_utils::clone_or_copy_file(&pin, &destination)?;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_pinned_layer(_vm_data: &Path, _layer: &PinnedLayer, _extracted: &Path) -> Result<()> {
    Err(Error::agent(
        "install pinned layer",
        "pinned layers are Unix-only",
    ))
}

/// Whether a paused machine's own disk chains are still the ones `artifact`
/// captured: recorded when it stopped, unchanged since, and shaped as the
/// checkpoint's chains are.
#[cfg(unix)]
fn paused_disks_intact(vm_data: &Path, artifact: &Path, disks: &[CheckpointDisk]) -> bool {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let Ok(marker) = paused_disks_marker(vm_data) else {
        return false;
    };
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(marker)
    else {
        return false;
    };
    // Only a record this service wrote counts.
    match file.metadata() {
        Ok(metadata)
            if metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0 => {}
        _ => return false,
    }
    let mut recorded = String::new();
    if file.read_to_string(&mut recorded).is_err() {
        return false;
    }
    let Some((recorded_artifact, recorded)) = recorded.split_once('\n') else {
        return false;
    };
    if Path::new(recorded_artifact) != artifact {
        return false;
    }
    match disk_chain_identity(vm_data) {
        Ok(current) if current == recorded => {}
        _ => return false,
    }
    let shape: Vec<(&str, &str)> = recorded
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            Some((fields.next()?, fields.next()?))
        })
        .collect();
    let expected: Vec<(&str, &str)> = disks
        .iter()
        .flat_map(|disk| {
            disk.files
                .iter()
                .map(|file| (disk.role.as_str(), file.format.as_str()))
        })
        .collect();
    shape == expected
}

/// Without Unix file identities there is no record: resume installs disks.
#[cfg(not(unix))]
fn record_paused_disks(_vm_data: &Path, _artifact: &Path, _captured: Option<&str>) {}

#[cfg(not(unix))]
fn paused_disks_intact(_vm_data: &Path, _artifact: &Path, _disks: &[CheckpointDisk]) -> bool {
    false
}

/// Stage exact, self-contained disk chains without flattening them.
///
/// Each layer is rebased to a reserved relative filename. This preserves the
/// block backend's allocation/topology state, avoids multi-gigabyte logical
/// scans, and prevents restored images from retaining absolute references to
/// the capture host.
///
/// Only each chain's writable top is copied here, while the source is paused:
/// it is the one layer that changes once the source resumes. Backing layers
/// are immutable. Raw ones are hard-linked; on Linux qcow2 ones are held open
/// and staged by [`DeferredBackings`] after the source resumes, so the pause
/// does not grow with the data a restored machine inherited from its
/// checkpoint.
///
/// Backing layers that `pins` takes are pinned instead of staged: their
/// manifest entries stay, but their bytes are not packed.
#[cfg(all(test, target_os = "linux"))]
fn stage_disk_chains(
    vm_data: &Path,
    checkpoint_dir: &Path,
    pins: Option<&mut LayerPins>,
) -> Result<(Vec<CheckpointDisk>, DeferredBackings)> {
    stage_disk_chains_with_links(vm_data, checkpoint_dir, pins, None)
}

/// Stage immutable qcow2 backing layers by hard link for stored captures;
/// record the patched header separately so their shared source stays intact.
fn stage_disk_chains_with_links(
    vm_data: &Path,
    checkpoint_dir: &Path,
    mut pins: Option<&mut LayerPins>,
    mut linked_heads: Option<&mut std::collections::HashMap<String, Vec<u8>>>,
) -> Result<(Vec<CheckpointDisk>, DeferredBackings)> {
    let mut disks = Vec::new();
    let mut deferred = DeferredBackings::default();
    for (role, raw_name) in [
        ("storage", crate::storage::STORAGE_DISK_FILENAME),
        ("overlay", crate::storage::OVERLAY_DISK_FILENAME),
    ] {
        let (mut source, initial_format) = crate::agent::resolve_disk_image(vm_data, raw_name);
        if !source.is_file() {
            continue;
        }
        let mut format = match initial_format {
            crate::data::disk::DiskFormat::Raw => "raw",
            crate::data::disk::DiskFormat::Qcow2 => "qcow2",
        };
        let disk_staging = checkpoint_dir.join("disks").join(role);
        std::fs::create_dir_all(&disk_staging)
            .map_err(|error| Error::agent("stage checkpoint disk", error.to_string()))?;
        let mut files = Vec::new();
        for index in 0..64 {
            let started = std::time::Instant::now();
            let target = disk_target(role, index, format)?;
            let artifact_path = format!("checkpoint/disks/{role}/{index}");
            let staged = disk_staging.join(index.to_string());

            let next = if format == "qcow2" {
                let (backing, backing_format) = inspect_qcow2(&source)?;
                match backing {
                    Some(backing) => {
                        let backing_source = resolve_backing_path(&source, &backing);
                        if !backing_source.is_file() {
                            return Err(Error::agent(
                                "stage checkpoint disk",
                                format!("missing qcow2 backing image {}", backing_source.display()),
                            ));
                        }
                        let next_format =
                            detect_disk_format(&backing_source, backing_format.as_deref())?;
                        let next_target = disk_target(role, index + 1, next_format)?;
                        Some((backing_source, next_format, next_target))
                    }
                    None => None,
                }
            } else {
                None
            };
            let next_target = next.as_ref().map(|(_, _, target)| target.clone());
            let pinned = match pins.as_deref_mut() {
                Some(pins) if index > 0 => {
                    pins.pin(&source, &artifact_path, next_target.as_deref())?
                }
                _ => false,
            };
            let linked = match (linked_heads.as_deref_mut(), next_target.as_deref()) {
                (Some(heads), Some(target)) if index > 0 && format == "qcow2" => {
                    match qcow2_head_with_backing(&source, target)? {
                        Some(head) if std::fs::hard_link(&source, &staged).is_ok() => {
                            heads.insert(artifact_path.clone(), head);
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            };
            let method = if pinned {
                "pinned"
            } else if linked {
                "linked"
            } else if cfg!(target_os = "linux") && index > 0 && format == "qcow2" {
                let file = std::fs::File::open(&source)
                    .map_err(|error| Error::agent("stage checkpoint disk", error.to_string()))?;
                deferred.0.push(DeferredBacking {
                    file,
                    source: source.clone(),
                    staged: staged.clone(),
                    archive_path: artifact_path.clone(),
                    next_target,
                });
                "deferred"
            } else {
                let method = stage_checkpoint_disk_layer(&source, &staged, index, format)?;
                if let Some(next_target) = &next_target {
                    rewrite_qcow2_backing(&staged, next_target)?;
                }
                method
            };

            let metadata = std::fs::metadata(&source)
                .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
            tracing::info!(
                role,
                index,
                format,
                method,
                bytes = allocated_bytes(&metadata),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "checkpoint disk layer staged"
            );
            // The pack footer authenticates the entire compressed asset blob.
            // Avoid hashing a 20 GiB logical raw backing full of sparse holes.
            let asset = CheckpointAsset {
                path: artifact_path,
                size: metadata.len(),
                sha256: String::new(),
            };
            files.push(CheckpointDiskFile {
                asset,
                target,
                format: format.to_string(),
            });
            match next {
                Some((next_source, next_format, _)) => {
                    source = next_source;
                    format = next_format;
                }
                None => break,
            }
        }
        if files.is_empty() || files.len() == 64 {
            return Err(Error::agent(
                "stage checkpoint disk",
                format!("invalid or unterminated {role} disk chain"),
            ));
        }
        disks.push(CheckpointDisk {
            role: role.to_string(),
            files,
        });
    }
    if disks.len() != 2 {
        return Err(Error::agent(
            "stage checkpoint disk",
            "portable checkpoints require storage and overlay disks",
        ));
    }
    Ok((disks, deferred))
}

/// Bytes a file occupies on disk, which for a sparse image is its data.
fn allocated_bytes(metadata: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().saturating_mul(512)
    }
    #[cfg(not(unix))]
    {
        metadata.len()
    }
}

/// A qcow2 backing layer held open while the source was paused. Backing
/// layers are never written, so the open file keeps exactly the captured
/// bytes even if the source's chain is later rotated or merged.
struct DeferredBacking {
    file: std::fs::File,
    source: PathBuf,
    staged: PathBuf,
    archive_path: String,
    next_target: Option<String>,
}

/// The qcow2 backing layers [`stage_disk_chains`] left to stage after the
/// source resumes.
#[derive(Default)]
#[must_use]
struct DeferredBackings(Vec<DeferredBacking>);

impl DeferredBackings {
    /// Pack each layer straight from its open file with its backing name
    /// patched in the archive. Nothing is copied and the layer itself is
    /// never modified. For a staging tree that is packed and then discarded.
    fn pack_from_source(self, collector: &mut AssetCollector) -> Result<()> {
        for mut layer in self.0 {
            let patches = match &layer.next_target {
                Some(target) => qcow2_backing_patches(&mut layer.file, &layer.source, target)?,
                None => Vec::new(),
            };
            collector
                .add_patched_file(smolvm_pack::assets::PatchedFile {
                    archive_path: layer.archive_path,
                    source: layer.file,
                    mode: 0o600,
                    patches,
                })
                .map_err(|error| Error::agent("stage checkpoint disk", error.to_string()))?;
        }
        Ok(())
    }

    /// The same layers through new handles to the same open files.
    fn try_clone(&self) -> Result<Self> {
        self.0
            .iter()
            .map(|layer| {
                Ok(DeferredBacking {
                    file: layer.file.try_clone().map_err(|error| {
                        Error::agent("stage checkpoint disk", error.to_string())
                    })?,
                    source: layer.source.clone(),
                    staged: layer.staged.clone(),
                    archive_path: layer.archive_path.clone(),
                    next_target: layer.next_target.clone(),
                })
            })
            .collect::<Result<_>>()
            .map(Self)
    }

    /// Stage a private, rebased copy of each layer in the staging tree, for
    /// a staging tree that outlives packing.
    fn stage_copies(self) -> Result<()> {
        for layer in self.0 {
            let started = std::time::Instant::now();
            copy_open_file(&layer.file, &layer.staged)?;
            if let Some(target) = &layer.next_target {
                rewrite_qcow2_backing(&layer.staged, target)?;
            }
            tracing::info!(
                path = %layer.archive_path,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "checkpoint disk layer copied after resume"
            );
        }
        Ok(())
    }
}

/// Copy the file behind `file` to `destination`, keeping its holes.
#[cfg(target_os = "linux")]
fn copy_open_file(file: &std::fs::File, destination: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    crate::disk_utils::clone_or_copy_file(
        Path::new(&format!("/proc/self/fd/{}", file.as_raw_fd())),
        destination,
    )
}

/// Only Linux defers backing layers.
#[cfg(not(target_os = "linux"))]
fn copy_open_file(_file: &std::fs::File, _destination: &Path) -> Result<()> {
    Err(Error::agent(
        "stage checkpoint disk",
        "deferred backing layers are Linux-only",
    ))
}

fn stage_checkpoint_disk_layer(
    source: &Path,
    staged: &Path,
    index: usize,
    format: &str,
) -> Result<&'static str> {
    if index == 0 || format == "qcow2" {
        // The active top is writable, and every qcow2 layer below it has a
        // backing filename that is rewritten for the self-contained artifact.
        // Both therefore need a private inode. Hard-linking a qcow2 backing and
        // editing its header corrupts the live source's disk chain.
        crate::disk_utils::clone_or_copy_file(source, staged)?;
        return Ok("copy");
    }

    // Terminal raw backings are immutable and carry no header to rewrite. An
    // owned hard link is an exact O(1) snapshot and survives source deletion.
    match std::fs::hard_link(source, staged) {
        Ok(()) => Ok("link"),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            crate::disk_utils::clone_or_copy_file(source, staged)?;
            Ok("copy")
        }
        Err(error) => Err(Error::agent("stage checkpoint disk", error.to_string())),
    }
}

/// Build an integrity entry for a staged checkpoint payload.
pub fn describe_asset(path: &Path, relative_path: &str) -> Result<CheckpointAsset> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::agent("inspect checkpoint payload", error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(Error::agent(
            "inspect checkpoint payload",
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::agent("open checkpoint payload", error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::agent("hash checkpoint payload", error.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(CheckpointAsset {
        path: relative_path.to_string(),
        size: metadata.len(),
        sha256: hex::encode(hasher.finalize()),
    })
}

fn describe_sparse_asset(path: &Path, relative_path: &str) -> Result<CheckpointAsset> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::agent("inspect checkpoint payload", error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(Error::agent(
            "inspect checkpoint payload",
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(CheckpointAsset {
        path: relative_path.to_string(),
        size: metadata.len(),
        sha256: String::new(),
    })
}

/// Bound a RAM image by configured guest RAM and the devices' mapped windows.
/// Capture and restore must use the same bound for packed-layer machines.
fn max_checkpoint_memory_image(memory_mib: u32, packed_layers: bool) -> Result<u64> {
    // Bound by the largest window a packed-layer guest has booted with, so
    // checkpoints taken before the window shrank still pass.
    let packed_layers_window = if packed_layers {
        crate::agent::virtiofs::legacy_packed_layers_dax_window()
    } else {
        0
    };
    u64::from(memory_mib)
        .checked_mul(1024 * 1024)
        .and_then(|bytes| bytes.checked_add(FIXED_MEMORY_OVERHEAD_BYTES))
        .and_then(|bytes| bytes.checked_add(packed_layers_window))
        .ok_or_else(|| Error::agent("checkpoint memory", "memory size overflow"))
}

/// Whether a checkpoint's machine had the packed-layers virtio-fs device.
fn mounts_checkpoint_image_layers(checkpoint: &PortableCheckpointManifest) -> bool {
    checkpoint.packed_layers.is_some() || checkpoint.host_image.is_some()
}

/// Validate that a checkpoint may be restored by this host and runtime.
pub fn validate_compatibility(checkpoint: &PortableCheckpointManifest) -> Result<()> {
    let required = match checkpoint.payload {
        smolvm_pack::format::CheckpointLayout::Assets => FORMAT_VERSION,
        smolvm_pack::format::CheckpointLayout::Chunked if checkpoint.base.is_some() => {
            DELTA_FORMAT_VERSION
        }
        smolvm_pack::format::CheckpointLayout::Chunked => HISTORY_FORMAT_VERSION,
    };
    if checkpoint.version != required {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "unsupported checkpoint version {} (runtime requires {})",
                checkpoint.version, required
            ),
        ));
    }
    if checkpoint.runtime_abi != RUNTIME_ABI {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "checkpoint requires runtime ABI '{}', this runtime provides '{}'",
                checkpoint.runtime_abi, RUNTIME_ABI
            ),
        ));
    }
    let host_platform = crate::platform::Platform::current()
        .host_oci_platform()
        .to_string();
    if !host_platform_compatible(&checkpoint.host_platform, &host_platform) {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "checkpoint host platform '{}' does not match '{}'",
                checkpoint.host_platform, host_platform
            ),
        ));
    }
    validate_clock(checkpoint)?;
    if checkpoint.packed_layers.is_some() && checkpoint.host_image.is_some() {
        return Err(Error::agent(
            "restore checkpoint",
            "checkpoint names both a pack and a fetched image as its image layers",
        ));
    }
    let expected_profile = if mounts_checkpoint_image_layers(checkpoint) {
        DEVICE_PROFILE_PACKED_LAYERS
    } else {
        DEVICE_PROFILE
    };
    if checkpoint.device_profile != expected_profile {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "unsupported checkpoint device profile '{}'",
                checkpoint.device_profile
            ),
        ));
    }
    if checkpoint.version >= 2 {
        let network = checkpoint.network.as_ref().ok_or_else(|| {
            Error::agent(
                "restore checkpoint",
                "version-two checkpoint is missing its network descriptor",
            )
        })?;
        let backend = restored_network_backend(checkpoint)?;
        let mut hosts = std::collections::HashSet::new();
        for port in &network.ports {
            if port.host == 0 || port.guest == 0 || !hosts.insert(port.host) {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint contains an invalid or duplicate port mapping",
                ));
            }
        }
        if !network.ports.is_empty() && backend != Some(crate::network::NetworkBackend::VirtioNet) {
            return Err(Error::agent(
                "restore checkpoint",
                "checkpoint port mappings require the virtio-net backend",
            ));
        }
        if !network.enabled && (!network.ports.is_empty() || backend.is_some()) {
            return Err(Error::agent(
                "restore checkpoint",
                "checkpoint network descriptor is internally inconsistent",
            ));
        }
        if let Some(workload) = checkpoint.workload.as_ref() {
            if workload.image.trim().is_empty() {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint workload image is empty",
                ));
            }
            if crate::data::validate_vm_name(&workload.overlay_owner, "overlay owner").is_err() {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint workload overlay owner is invalid",
                ));
            }
            if workload
                .restart_policy
                .parse::<crate::config::RestartPolicy>()
                .is_err()
            {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint workload restart policy is invalid",
                ));
            }
        }
    }
    if checkpoint.cpus == 0 || checkpoint.memory_mib == 0 {
        return Err(Error::agent(
            "restore checkpoint",
            "checkpoint has invalid zero CPU or memory resources",
        ));
    }
    // Reject resource-exhaustion artifacts before extracting or mapping their
    // memory image. The current device profile maps configured RAM plus rootfs
    // DAX and small fixed regions; 2 GiB is a deliberately generous ceiling
    // for those non-configured mappings.
    const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_LAYOUT_BYTES: u64 = 1024 * 1024;
    let max_memory_image = max_checkpoint_memory_image(
        checkpoint.memory_mib,
        mounts_checkpoint_image_layers(checkpoint),
    )?;
    if checkpoint.state.size == 0
        || checkpoint.state.size > MAX_STATE_BYTES
        || checkpoint.layout.size == 0
        || checkpoint.layout.size > MAX_LAYOUT_BYTES
        || checkpoint.memory.size == 0
        || checkpoint.memory.size > max_memory_image
    {
        return Err(Error::agent(
            "restore checkpoint",
            "checkpoint payload sizes are inconsistent with the captured machine",
        ));
    }
    validate_cpu_compatibility(checkpoint)
}

fn expected_assets(
    checkpoint: &PortableCheckpointManifest,
) -> [(&CheckpointAsset, &'static str); 3] {
    [
        (&checkpoint.state, "checkpoint/checkpoint.bin"),
        (&checkpoint.memory, "checkpoint/memory.bin"),
        (&checkpoint.layout, "checkpoint/manifest.bin"),
    ]
}

fn validate_disk_manifest(disks: &[CheckpointDisk]) -> Result<()> {
    if disks.len() != 2 {
        return Err(Error::agent(
            "install checkpoint",
            "checkpoint must contain storage and overlay disk chains",
        ));
    }
    for (expected_role, disk) in ["storage", "overlay"].into_iter().zip(disks) {
        if disk.role != expected_role || disk.files.is_empty() {
            return Err(Error::agent(
                "install checkpoint",
                format!("invalid {} disk chain", disk.role),
            ));
        }
        for (index, file) in disk.files.iter().enumerate() {
            if file.format != "raw" && file.format != "qcow2" {
                return Err(Error::agent(
                    "install checkpoint",
                    format!("unsupported checkpoint disk format '{}'", file.format),
                ));
            }
            let expected_target = disk_target(&disk.role, index, &file.format)?;
            let expected_path = format!("checkpoint/disks/{}/{index}", disk.role);
            if file.target != expected_target || file.asset.path != expected_path {
                return Err(Error::agent(
                    "install checkpoint",
                    format!(
                        "invalid checkpoint disk mapping '{} -> {}'",
                        file.asset.path, file.target
                    ),
                ));
            }
            if file.format == "raw" && index + 1 != disk.files.len() {
                return Err(Error::agent(
                    "install checkpoint",
                    "a raw disk must terminate its image chain",
                ));
            }
        }
    }
    Ok(())
}

fn copy_verified(
    source: &Path,
    destination: &Path,
    asset: &CheckpointAsset,
    writable: bool,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| Error::agent("inspect checkpoint payload", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() != asset.size {
        return Err(Error::agent(
            "verify checkpoint payload",
            format!("{} has an unexpected type or size", source.display()),
        ));
    }
    if asset.sha256.is_empty() {
        if !writable {
            return Err(Error::agent(
                "verify checkpoint payload",
                format!("{} is missing its SHA-256 digest", source.display()),
            ));
        }
    } else {
        let mut input = std::fs::File::open(source)
            .map_err(|error| Error::agent("open checkpoint payload", error.to_string()))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|error| Error::agent("read checkpoint payload", error.to_string()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        if hex::encode(hasher.finalize()) != asset.sha256 {
            return Err(Error::agent(
                "verify checkpoint payload",
                format!("SHA-256 mismatch for {}", source.display()),
            ));
        }
    }

    if writable || cfg!(target_os = "linux") {
        // Restored guest RAM is mapped writable and becomes backing for future
        // forks. It must never alias the immutable extraction cache. Prefer a
        // filesystem reflink so even a multi-GiB sparse image stays cheap; the
        // fallback preserves holes while copying only allocated extents.
        // Linux also chowns device/layout metadata to each isolated VMM UID.
        // Sharing those inodes would transfer ownership away from a sibling
        // during concurrent startup, denying it access under a private umask.
        crate::disk_utils::clone_or_copy_file(source, destination)?;
        // FlushFileBuffers on Windows requires a writable handle. These
        // payloads are private writable copies, so reopen them for writing.
        #[cfg(target_os = "windows")]
        let copied = std::fs::OpenOptions::new().write(true).open(destination);
        #[cfg(not(target_os = "windows"))]
        let copied = std::fs::File::open(destination);
        copied
            .and_then(|file| file.sync_all())
            .map_err(|error| Error::agent("sync checkpoint payload", error.to_string()))?;
        return Ok(());
    }

    // VM/device state and the memory-layout manifest stay read-only. Keep an
    // owned hard link when the extraction cache shares this filesystem; cache
    // eviction unlinks only its name.
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            let mut input = std::fs::File::open(source)
                .map_err(|error| Error::agent("open checkpoint payload", error.to_string()))?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .map_err(|error| Error::agent("create checkpoint payload", error.to_string()))?;
            std::io::copy(&mut input, &mut output)
                .map_err(|error| Error::agent("copy checkpoint payload", error.to_string()))?;
            output
                .sync_all()
                .map_err(|error| Error::agent("sync checkpoint payload", error.to_string()))?;
            Ok(())
        }
        Err(error) => Err(Error::agent("link checkpoint payload", error.to_string())),
    }
}

fn copy_verified_sparse(source: &Path, destination: &Path, asset: &CheckpointAsset) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() != asset.size {
        return Err(Error::agent(
            "verify checkpoint disk",
            format!("size/type mismatch for {}", source.display()),
        ));
    }
    // Disk assets are already covered by the pack's whole-blob SHA-256. A
    // second logical-file hash would read every sparse hole and turn a small
    // qcow2 chain into minutes of CPU work.
    if !asset.sha256.is_empty() {
        return Err(Error::agent(
            "verify checkpoint disk",
            "sparse disk assets must use container-level integrity",
        ));
    }
    crate::disk_utils::clone_or_copy_file(source, destination)?;
    #[cfg(target_os = "windows")]
    let copied = std::fs::OpenOptions::new().write(true).open(destination);
    #[cfg(not(target_os = "windows"))]
    let copied = std::fs::File::open(destination);
    copied
        .and_then(|file| file.sync_all())
        .map_err(|error| Error::agent("sync checkpoint disk", error.to_string()))?;
    Ok(())
}

/// Publish an immutable backing image without copying its sparse address space.
///
/// Extracted artifacts and VM data normally share a filesystem, so a hard link
/// makes even a multi-gigabyte sparse raw backing an O(1) install. The VM owns a
/// second link after the extraction cache is pruned. Cross-filesystem/private
/// extraction falls back to the ordinary reflink/sparse-copy path.
fn link_or_copy_verified_sparse(
    source: &Path,
    destination: &Path,
    asset: &CheckpointAsset,
) -> Result<()> {
    // Only service-owned, explicitly immutable inodes can retain shared
    // ownership across isolated Linux launches; all other inputs stay private.
    #[cfg(target_os = "linux")]
    if share_service_owned_backing(source, destination, asset)? {
        return Ok(());
    }
    if cfg!(target_os = "linux") {
        return copy_verified_sparse(source, destination, asset);
    }
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() != asset.size {
        return Err(Error::agent(
            "verify checkpoint disk",
            format!("size/type mismatch for {}", source.display()),
        ));
    }
    if !asset.sha256.is_empty() {
        return Err(Error::agent(
            "verify checkpoint disk",
            "sparse disk assets must use container-level integrity",
        ));
    }
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            copy_verified_sparse(source, destination, asset)
        }
        Err(error) => Err(Error::agent("link checkpoint disk", error.to_string())),
    }
}

#[cfg(target_os = "linux")]
fn share_service_owned_backing(
    source: &Path,
    destination: &Path,
    asset: &CheckpointAsset,
) -> Result<bool> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if !crate::process::vm_uid_drop_active() {
        return Ok(false);
    }
    let input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() != asset.size || !asset.sha256.is_empty() {
        return Err(Error::agent(
            "share checkpoint backing",
            "invalid verified disk asset",
        ));
    }
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Ok(false);
    }
    let parent = source
        .parent()
        .ok_or_else(|| Error::agent("share checkpoint backing", "missing cache directory"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.uid() != 0 {
        return Ok(false);
    }
    // Protect the cache's original name before making this inode readable.
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    std::fs::File::open(parent)?.sync_all()?;
    if !crate::process::mark_checkpoint_backing(&input)? {
        return Ok(false);
    }
    // The parent cache and each VM directory remain private. Read access here
    // lets each isolated VMM use its own link; root ownership denies chmod/write.
    input.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    match std::fs::hard_link(source, destination) {
        Ok(()) => {}
        // A different filesystem, or a base already linked into as many
        // machines as the filesystem allows (ext4: 65,000), gets a private copy.
        Err(error) if matches!(error.raw_os_error(), Some(libc::EXDEV | libc::EMLINK)) => {
            return Ok(false)
        }
        Err(error) => return Err(error.into()),
    }
    let linked = std::fs::symlink_metadata(destination)?;
    if linked.dev() != metadata.dev() || linked.ino() != metadata.ino() {
        let _ = std::fs::remove_file(destination);
        return Err(Error::agent(
            "share checkpoint backing",
            "source changed during publication",
        ));
    }
    input.sync_all()?;
    Ok(true)
}

/// Retention may link a source-VMM-owned raw backing. Replace only the cache
/// name, never chown that shared inode or change the source machine's access.
#[cfg(target_os = "linux")]
fn promote_retained_backing(
    extracted: &Path,
    source: &Path,
    asset: &CheckpointAsset,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !crate::process::vm_uid_drop_active() || std::fs::symlink_metadata(source)?.uid() == 0 {
        return Ok(());
    }
    let Some(_lock) = crate::artifact_cache::lock_checkpoint_entry(extracted)? else {
        return Ok(());
    };
    promote_retained_backing_locked(extracted, source, asset, |source, destination| {
        copy_verified_sparse(source, destination, asset)
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn promote_retained_backing_locked(
    extracted: &Path,
    source: &Path,
    asset: &CheckpointAsset,
    copy: impl FnOnce(&Path, &Path) -> Result<()>,
) -> Result<bool> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let parent = source
        .parent()
        .ok_or_else(|| Error::agent("promote checkpoint disk", "missing parent"))?;
    if !parent.starts_with(extracted) {
        return Err(Error::agent(
            "promote checkpoint disk",
            "disk is outside the cache",
        ));
    }
    let mut directory = parent;
    loop {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Ok(false);
        }
        if directory == extracted {
            break;
        }
        directory = directory
            .parent()
            .ok_or_else(|| Error::agent("promote checkpoint disk", "invalid cache path"))?;
    }
    let input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() != asset.size || !asset.sha256.is_empty() {
        return Err(Error::agent(
            "promote checkpoint disk",
            "invalid verified disk asset",
        ));
    }
    if metadata.uid() == 0 {
        return Ok(false);
    }
    let identity = SidecarIdentity::of(&input)?;
    // The entry lock excludes another promotion. Reclaim only our abandoned
    // staging directories; interrupted copies must not grow a leased cache.
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".checkpoint-disk-")
        {
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(Error::agent(
                    "promote checkpoint disk",
                    "invalid abandoned staging directory",
                ));
            }
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    let staging = tempfile::Builder::new()
        .prefix(".checkpoint-disk-")
        .tempdir_in(parent)?;
    let staged = staging.path().join("disk");
    copy(source, &staged)?;
    let current = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    if SidecarIdentity::of(&input)? != identity || SidecarIdentity::of(&current)? != identity {
        return Err(Error::agent(
            "promote checkpoint disk",
            "source changed while preparing immutable backing",
        ));
    }
    let output = std::fs::File::open(&staged)?;
    if output.metadata()?.len() != asset.size || output.metadata()?.uid() != 0 {
        return Err(Error::agent(
            "promote checkpoint disk",
            "invalid promoted backing",
        ));
    }
    if !crate::process::mark_checkpoint_backing(&output)? {
        return Ok(false);
    }
    // All cache parents stay private before the immutable inode becomes readable.
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    std::fs::File::open(parent)?.sync_all()?;
    output.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    output.sync_all()?;
    std::fs::rename(&staged, source)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(true)
}

/// Make the restore private before publishing readable shared backing links.
#[cfg(target_os = "linux")]
fn protect_restore_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    // Persist privacy before any globally readable immutable inode acquires a
    // name here. Waiting until VMM launch leaves stopped restores exposed.
    directory.sync_all()?;
    Ok(())
}

/// Whether a restore may give the captured writable disk a copy-on-write top
/// instead of copying it. On by default; `SMOLVM_RESTORE_COW_DISK=0` restores
/// the full copy.
#[cfg(target_os = "linux")]
/// Deepest captured chain a restore still layers over instead of copying its
/// top. Each such restore adds one layer, so this bounds the chain's depth.
#[cfg(target_os = "linux")]
const MAX_COW_CHAIN_FILES: usize = 4;

/// Check that the qcow2 `staged` (file `index` of `disk`) is backed by exactly
/// the next file of the captured chain.
fn verify_qcow2_backing(staged: &Path, disk: &CheckpointDisk, index: usize) -> Result<()> {
    let (backing, _) = inspect_qcow2(staged)?;
    let expected = disk.files.get(index + 1).map(|next| next.target.as_str());
    if backing.as_deref() != expected {
        return Err(Error::agent(
            "install checkpoint",
            format!(
                "qcow2 '{}' references {:?}, expected {:?}",
                disk.files[index].target, backing, expected
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cow_restore_enabled() -> bool {
    std::env::var("SMOLVM_RESTORE_COW_DISK").map_or(true, |value| value != "0")
}

/// Whether two paths name the same file.
#[cfg(target_os = "linux")]
fn same_inode(a: &Path, b: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (a, b) = (std::fs::metadata(a)?, std::fs::metadata(b)?);
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

/// Install verified checkpoint state before a machine is launched.
pub fn install(
    extracted: &Path,
    vm_data_dir: &Path,
    checkpoint: &PortableCheckpointManifest,
) -> Result<()> {
    install_with(extracted, vm_data_dir, checkpoint, false, None)
}

/// [`install`], leaving any write-back of RAM the extraction deferred to
/// `deferred`, for the caller to start once the install is done.
pub fn install_deferring_sync(
    extracted: &Path,
    vm_data_dir: &Path,
    checkpoint: &PortableCheckpointManifest,
    deferred: &mut DeferredRestoreSync,
) -> Result<()> {
    install_with(extracted, vm_data_dir, checkpoint, false, Some(deferred))
}

/// [`install`]; with `keep_disks`, the machine keeps the disk chains it has,
/// which must be the ones the checkpoint captured, and none are extracted.
fn install_with(
    extracted: &Path,
    vm_data_dir: &Path,
    checkpoint: &PortableCheckpointManifest,
    keep_disks: bool,
    mut deferred: Option<&mut DeferredRestoreSync>,
) -> Result<()> {
    validate_compatibility(checkpoint)?;
    validate_disk_manifest(&checkpoint.disks)?;
    #[cfg(target_os = "linux")]
    protect_restore_directory(vm_data_dir)?;
    let destination = vm_data_dir.join(INSTALLED_DIR);
    if destination.exists() {
        return Err(Error::agent(
            "install checkpoint",
            format!("{} already exists", destination.display()),
        ));
    }
    let partial = vm_data_dir.join(format!(".{INSTALLED_DIR}-{}-partial", std::process::id()));
    let _ = std::fs::remove_dir_all(&partial);
    std::fs::create_dir(&partial)
        .map_err(|error| Error::agent("create checkpoint directory", error.to_string()))?;

    let result = (|| -> Result<()> {
        // The restore launches from this directory: record the window its
        // guest booted with, so the restored VM maps at least that much.
        if let Some(packed) = &checkpoint.packed_layers {
            crate::agent::virtiofs::record_snapshot_window(
                &partial,
                packed
                    .dax_window_bytes
                    .unwrap_or(crate::agent::virtiofs::LEGACY_PACKED_LAYERS_DAX_WINDOW),
            )
            .map_err(|e| Error::agent("record checkpoint DAX window", e.to_string()))?;
        }
        for (asset, expected) in expected_assets(checkpoint) {
            let started = std::time::Instant::now();
            if asset.path != expected {
                return Err(Error::agent(
                    "install checkpoint",
                    format!("unexpected checkpoint asset path '{}'", asset.path),
                ));
            }
            let filename = Path::new(expected)
                .file_name()
                .expect("fixed checkpoint asset path");
            if expected == "checkpoint/memory.bin"
                && stage_readonly_memory(
                    &extracted.join(expected),
                    vm_data_dir,
                    asset,
                    smolvm_pack::extract::memory_sync_pending(extracted),
                    deferred.as_deref_mut(),
                )?
            {
                std::fs::write(partial.join(READONLY_INPUT_MARKER), b"1\n")?;
                tracing::info!(
                    asset = expected,
                    elapsed_ms = started.elapsed().as_millis(),
                    method = "readonly_link",
                    "checkpoint payload installed"
                );
                continue;
            }
            copy_verified(
                &extracted.join(expected),
                &partial.join(filename),
                asset,
                expected == "checkpoint/memory.bin",
            )?;
            tracing::info!(
                asset = expected,
                elapsed_ms = started.elapsed().as_millis(),
                method = "copy_or_link",
                "checkpoint payload installed"
            );
        }
        if let Some(asset) = &checkpoint.credential_ca {
            install_credential_ca(extracted, vm_data_dir, &partial, asset)?;
        }
        validate_state_origin(checkpoint, &partial.join("checkpoint.bin"))?;

        // Names to move into the machine directory, and the copy-on-write tops
        // to create over a captured writable disk once its base is in place.
        let mut staged_names: Vec<String> = Vec::new();
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut cow_tops: Vec<crate::agent::DiskOverlaySpec> = Vec::new();
        if !keep_disks {
            let staged_disks = partial.join("disks");
            std::fs::create_dir(&staged_disks)
                .map_err(|error| Error::agent("stage checkpoint disks", error.to_string()))?;
            for disk in &checkpoint.disks {
                for (index, file) in disk.files.iter().enumerate() {
                    let started = std::time::Instant::now();
                    let staged = staged_disks.join(&file.target);
                    let source = extracted.join(&file.asset.path);
                    #[cfg(target_os = "linux")]
                    if index == 0
                        && disk.files.len() == 1
                        && file.format == "raw"
                        && cow_restore_enabled()
                    {
                        // Copying the captured disk is most of a restore. Share it
                        // as an immutable base instead, like a deeper layer, and
                        // give this machine a thin qcow2 top of its own. Only a
                        // base that really is shared earns the extra layer; a
                        // private copy is simply this machine's writable disk.
                        let base_name = format!(".smolcheckpoint-{}-base.raw", disk.role);
                        let staged_base = staged_disks.join(&base_name);
                        promote_retained_backing(extracted, &source, &file.asset)?;
                        link_or_copy_verified_sparse(&source, &staged_base, &file.asset)?;
                        if same_inode(&source, &staged_base)? {
                            cow_tops.push((
                                vm_data_dir.join(Path::new(&file.target).with_extension("qcow2")),
                                vm_data_dir.join(&base_name),
                                crate::data::disk::DiskFormat::Raw,
                            ));
                            staged_names.push(base_name);
                            tracing::info!(asset = %file.asset.path, elapsed_ms = started.elapsed().as_millis(), method = "cow_top", "checkpoint disk installed");
                        } else {
                            std::fs::rename(&staged_base, &staged).map_err(|error| {
                                Error::agent("stage checkpoint disk", error.to_string())
                            })?;
                            staged_names.push(file.target.clone());
                            tracing::info!(asset = %file.asset.path, elapsed_ms = started.elapsed().as_millis(), writable = true, "checkpoint disk installed");
                        }
                        continue;
                    }
                    // A captured chain's top is copied in full so it stays
                    // private, which is most of the restore. Like the single-file
                    // case above, share it as one more immutable layer instead and
                    // give this machine a thin top of its own. Bounded, so repeated
                    // rewinds can't deepen the chain without limit.
                    #[cfg(target_os = "linux")]
                    if index == 0
                        && file.format == "qcow2"
                        && (2..=MAX_COW_CHAIN_FILES).contains(&disk.files.len())
                        && cow_restore_enabled()
                    {
                        let layer_name = format!(
                            ".smolcheckpoint-{}-layer{}.qcow2",
                            disk.role,
                            disk.files.len()
                        );
                        if !disk.files.iter().any(|f| f.target == layer_name) {
                            let staged_layer = staged_disks.join(&layer_name);
                            promote_retained_backing(extracted, &source, &file.asset)?;
                            link_or_copy_verified_sparse(&source, &staged_layer, &file.asset)?;
                            if same_inode(&source, &staged_layer)? {
                                verify_qcow2_backing(&staged_layer, disk, index)?;
                                cow_tops.push((
                                    vm_data_dir.join(&file.target),
                                    vm_data_dir.join(&layer_name),
                                    crate::data::disk::DiskFormat::Qcow2,
                                ));
                                staged_names.push(layer_name);
                                tracing::info!(asset = %file.asset.path, elapsed_ms = started.elapsed().as_millis(), method = "cow_top", "checkpoint disk installed");
                                continue;
                            }
                            // Not shared with the cache, so it's a private copy
                            // already: use it as the writable top.
                            std::fs::rename(&staged_layer, &staged).map_err(|error| {
                                Error::agent("stage checkpoint disk", error.to_string())
                            })?;
                            verify_qcow2_backing(&staged, disk, index)?;
                            staged_names.push(file.target.clone());
                            tracing::info!(asset = %file.asset.path, elapsed_ms = started.elapsed().as_millis(), writable = true, "checkpoint disk installed");
                            continue;
                        }
                    }
                    staged_names.push(file.target.clone());
                    if index == 0 {
                        // The active top layer is writable after resume and must
                        // never alias the immutable extraction cache.
                        copy_verified_sparse(&source, &staged, &file.asset)?;
                    } else {
                        // Backings remain immutable. Linking them avoids scanning
                        // tens of GiB of sparse holes during every import.
                        #[cfg(target_os = "linux")]
                        if file.format == "raw" {
                            promote_retained_backing(extracted, &source, &file.asset)?;
                        }
                        link_or_copy_verified_sparse(&source, &staged, &file.asset)?;
                    }
                    if file.format == "qcow2" {
                        verify_qcow2_backing(&staged, disk, index)?;
                    }
                    tracing::info!(asset = %file.asset.path, elapsed_ms = started.elapsed().as_millis(), writable = index == 0, "checkpoint disk installed");
                }
            }
        }
        std::fs::write(partial.join(PENDING_MARKER), b"1\n")
            .map_err(|error| Error::agent("mark checkpoint pending", error.to_string()))?;
        std::fs::rename(&partial, &destination)
            .map_err(|error| Error::agent("publish checkpoint", error.to_string()))?;

        // The machine's disks now belong to this resume, kept or replaced.
        remove_paused_disks_marker(vm_data_dir)?;
        if keep_disks {
            return Ok(());
        }
        // Publish the exact captured block chains into the paths the launcher
        // attaches. Creation is still private/uncommitted at this point, so a
        // failure causes the entire machine reservation to be rolled back.
        for raw_name in [
            crate::storage::STORAGE_DISK_FILENAME,
            crate::storage::OVERLAY_DISK_FILENAME,
        ] {
            for path in [
                vm_data_dir.join(raw_name),
                vm_data_dir.join(Path::new(raw_name).with_extension("qcow2")),
            ] {
                if path.exists() {
                    std::fs::remove_file(&path).map_err(|error| {
                        Error::agent("replace checkpoint disk", error.to_string())
                    })?;
                }
            }
        }
        // The staged chain is already private (top) or has an owned hard link
        // (immutable backing). Move those exact inodes into the launcher's disk
        // namespace instead of copying them again.
        for name in &staged_names {
            std::fs::rename(destination.join("disks").join(name), vm_data_dir.join(name))
                .map_err(|error| Error::agent("publish checkpoint disk", error.to_string()))?;
        }
        crate::agent::create_disk_overlays(&cow_tops)?;
        for disk in &checkpoint.disks {
            std::fs::write(vm_data_dir.join(format!("{}.formatted", disk.role)), b"1").map_err(
                |error| Error::agent("mark checkpoint disk formatted", error.to_string()),
            )?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&partial);
        let _ = std::fs::remove_dir_all(&destination);
        let _ = remove_readonly_input(vm_data_dir);
    }
    result
}

/// Remove the extracted pack used only to transport a portable checkpoint.
///
/// All checkpoint state and disk chains have their own links or private copies
/// in the machine data directory after [`install`] succeeds. Leaving the pack
/// marker behind is not harmless: the generic restart path interprets any
/// extracted pack as OCI layers and attaches an extra virtio-fs device. That
/// changes the captured device/IRQ topology and makes the restored guest unable
/// to receive its vsock interrupt.
pub fn discard_transport_pack(vm_data_dir: &Path) -> Result<()> {
    let pack_dir = vm_data_dir.join("pack");
    smolvm_pack::extract::force_detach_layers_volume(&pack_dir);
    match std::fs::remove_dir_all(&pack_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::agent(
            "discard checkpoint transport pack",
            error.to_string(),
        )),
    }
}

/// Finish a portable live restore before exposing the machine to callers.
///
/// The restored guest still contains the source machine's live container and
/// per-machine identity. Rejuvenation re-mints that identity and records the
/// inherited crun container ID so later `machine exec` calls join the restored
/// workload instead of silently creating a second container.
pub fn finalize_live_restore(name: &str, record: &VmRecord) -> Result<()> {
    let mut phase = std::time::Instant::now();
    // A clone gets its own identity; a resumed or rewound machine keeps its own.
    if record.paused_checkpoint.is_none() && !record.keep_identity {
        crate::agent::fork::rejuvenate_clone(name, record)?;
        log_phase(name, "restore_rejuvenate", &mut phase);
    }
    crate::agent::fork::release_forkpoint(name, &record.fork_env)?;
    log_phase(name, "restore_release_forkpoint", &mut phase);
    Ok(())
}

/// Prepare an explicit same-machine resume. The durable artifact stays intact
/// if extraction, installation, or the subsequent boot fails.
pub(crate) fn prepare_paused_restore(record: &VmRecord) -> Result<()> {
    let artifact = record.paused_checkpoint.as_ref().ok_or_else(|| {
        Error::agent_conflict("resume machine", "machine has no saved execution state")
    })?;
    if record.is_process_alive() {
        return Err(Error::agent_conflict(
            "resume machine",
            "source VM has not stopped",
        ));
    }
    let footer = ensure_checkpoint_layout(artifact)?;
    // Treat this manifest as untrusted until extraction verifies the full
    // sidecar checksum. No machine state changes before that verification.
    let manifest = smolvm_pack::packer::read_manifest_from_sidecar(artifact)
        .map_err(|e| Error::agent("read paused checkpoint", e.to_string()))?;
    let checkpoint = manifest
        .checkpoint
        .as_ref()
        .ok_or_else(|| Error::agent("resume machine", "artifact has no execution state"))?;
    validate_compatibility(checkpoint)?;
    let vm_data = crate::agent::vm_data_dir(&record.name);
    // A pause leaves the machine's own disks exactly as captured unless
    // something wrote to them since; then they need not be installed again.
    let keep_disks = paused_disks_intact(&vm_data, artifact, &checkpoint.disks);
    // Resuming here uses this host's runtime, so the libraries, agent rootfs
    // and storage template the artifact carries for other hosts stay packed.
    let mut skip: Vec<PathBuf> = manifest
        .assets
        .libraries
        .iter()
        .map(|asset| PathBuf::from(&asset.path))
        .collect();
    skip.push(PathBuf::from("lib"));
    skip.push(PathBuf::from(&manifest.assets.agent_rootfs.path));
    if let Some(template) = &manifest.assets.storage_template {
        skip.push(PathBuf::from(&template.path));
    }
    if keep_disks {
        skip.push(PathBuf::from("checkpoint/disks"));
    }
    // Extract only the files the installer will read. The extractor verifies
    // every compressed and manifest byte before any state is installed.
    let mut required: Vec<PathBuf> = expected_assets(checkpoint)
        .into_iter()
        .map(|(_, path)| PathBuf::from(path))
        .collect();
    if let Some(asset) = &checkpoint.credential_ca {
        required.push(PathBuf::from(&asset.path));
    }
    // Layers the pause pinned rather than packed come from their pins.
    let pinned = if keep_disks {
        Vec::new()
    } else {
        paused_layers(&vm_data, artifact)?
    };
    if !keep_disks {
        required.extend(
            checkpoint
                .disks
                .iter()
                .flat_map(|disk| disk.files.iter())
                .filter(|file| {
                    !pinned
                        .iter()
                        .any(|layer| layer.archive_path == file.asset.path)
                })
                .map(|file| PathBuf::from(&file.asset.path)),
        );
    }
    let extract_and_install = |parent: &Path| -> Result<()> {
        let staged = tempfile::Builder::new()
            .prefix("resume-")
            .tempdir_in(parent)?;
        let extract_started = std::time::Instant::now();
        smolvm_pack::extract::extract_verified_checkpoint_sidecar(
            artifact,
            staged.path(),
            &footer,
            &skip,
            &required,
        )
        .map_err(|e| Error::agent("extract paused checkpoint", e.to_string()))?;
        for layer in &pinned {
            install_pinned_layer(&vm_data, layer, staged.path())?;
        }
        tracing::info!(machine = %record.name, phase = "extract", elapsed_ms = extract_started.elapsed().as_millis(), "paused resume phase completed");
        clear_stale_restore_state(&vm_data)?;
        install_with(staged.path(), &vm_data, checkpoint, keep_disks, None)
    };
    // Stage on tmpfs when there is room, so the RAM image handed to the VMM
    // is never written to disk. Its RAM is freed once the VMM has read it.
    // Pinned layers are not in the artifact's size, and link only on disk.
    #[cfg(target_os = "linux")]
    if let Some(root) = restore_tmpfs_root().filter(|_| pinned.is_empty()) {
        let needed = footer
            .assets_size
            .saturating_mul(4)
            .saturating_add(64 << 20);
        if free_bytes(&root).is_some_and(|free| free >= needed) {
            match extract_and_install(&root) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    tracing::warn!(machine = %record.name, %error, "restore on tmpfs failed; staging on disk");
                    clear_stale_restore_state(&vm_data)?;
                }
            }
        }
    }
    extract_and_install(&vm_data)
}

/// Remove what an earlier restore left in a stopped machine's data dir before
/// installing a new checkpoint: a partial installation from a failed restore,
/// and the memory backing a previous restore retained as the machine's RAM. No
/// VMM is alive (the caller checked), so nothing maps that backing any more —
/// and leaving it makes the new restore refuse to retain its own, so a machine
/// restored from a checkpoint could be paused but never resumed.
fn clear_stale_restore_state(vm_data: &Path) -> Result<()> {
    match std::fs::remove_dir_all(vm_data.join(INSTALLED_DIR)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    remove_readonly_input(vm_data)?;
    match std::fs::remove_file(vm_data.join(RETAINED_MEMORY_BACKING)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Return the pending one-shot checkpoint directory for a machine, if any.
pub fn pending_dir(vm_data_dir: &Path) -> Option<PathBuf> {
    let dir = vm_data_dir.join(INSTALLED_DIR);
    let marker = dir.join(PENDING_MARKER);
    if marker.is_file()
        && dir.join("checkpoint.bin").is_file()
        && (dir.join("memory.bin").is_file() || has_readonly_memory(&dir))
        && dir.join("manifest.bin").is_file()
    {
        Some(dir)
    } else {
        None
    }
}

/// Consume a successfully restored checkpoint so later starts cold-boot from
/// the machine's current disks rather than replaying stale live state.
pub fn consume(vm_data_dir: &Path) -> Result<()> {
    consume_with_retained_backing(vm_data_dir, cfg!(target_os = "macos"))
}

fn consume_with_retained_backing(vm_data_dir: &Path, retain_memory: bool) -> Result<()> {
    let Some(dir) = pending_dir(vm_data_dir) else {
        return Ok(());
    };
    let mut retained_memory = None;
    let readonly_input = has_readonly_memory(&dir);
    if retain_memory && !readonly_input {
        let source = dir.join("memory.bin");
        let destination = vm_data_dir.join(RETAINED_MEMORY_BACKING);
        if destination.exists() {
            return Err(Error::agent(
                "consume checkpoint",
                format!(
                    "retained memory backing already exists: {}",
                    destination.display()
                ),
            ));
        }
        std::fs::rename(&source, &destination)
            .map_err(|error| Error::agent("retain checkpoint memory", error.to_string()))?;
        retained_memory = Some((source, destination));
    }
    std::fs::remove_file(dir.join(PENDING_MARKER)).map_err(|error| {
        if let Some((source, destination)) = retained_memory.as_ref() {
            if let Err(rollback_error) = std::fs::rename(destination, source) {
                tracing::warn!(
                    source = %source.display(),
                    destination = %destination.display(),
                    %rollback_error,
                    "failed to roll back retained checkpoint memory"
                );
            }
        }
        Error::agent("consume checkpoint", error.to_string())
    })?;
    if readonly_input {
        if let Err(error) = remove_readonly_input(vm_data_dir) {
            tracing::warn!(%error, "checkpoint consumed but retained RAM cleanup failed");
        }
    }
    if let Err(error) = std::fs::remove_dir_all(&dir) {
        tracing::warn!(path = %dir.display(), %error, "checkpoint consumed but payload cleanup failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_declined_deferred_save_falls_back_to_a_synchronous_one() {
        // libkrun's reply for a fork clone, whose RAM has no file generation.
        assert!(declined_deferred_save(
            "ERR ENOTSUP deferred durable save requires file-backed guest RAM\n"
        ));
        assert!(declined_deferred_save("ERR EINVAL unknown command\n"));
        assert!(!declined_deferred_save("OK prepared\n"));
        assert!(!declined_deferred_save("ERR EIO save failed\n"));
    }

    #[test]
    fn a_node_policy_recorded_by_a_server_is_what_other_processes_use() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(RestoreCache::node_policy_in(root.path()), None);
        let server = RestoreCache {
            entries: 32,
            max_bytes: 256 * 1024 * 1024 * 1024,
        };
        server.persist_in(root.path()).unwrap();
        assert_eq!(RestoreCache::node_policy_in(root.path()), Some(server));
        // A damaged record falls back to the default rather than failing.
        std::fs::write(root.path().join(NODE_RESTORE_CACHE_POLICY), b"{").unwrap();
        assert_eq!(RestoreCache::node_policy_in(root.path()), None);
    }

    use super::*;

    /// `/proc/cpuinfo` of an M4 Max guest booted with pointer authentication off.
    const M4_MAX_GUEST_CPUINFO: &str = "processor\t: 0\nFeatures\t: fp asimd evtstrm aes \
        pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 \
        asimddp sha512 asimdfhm dit uscat ilrcpc flagm sb dcpodp flagm2 frint bf16 afp\n\n";

    /// `/proc/cpuinfo` Features of a Google Axion (c4a) host.
    const AXION_CPUINFO: &str = "processor\t: 0\nFeatures\t: fp asimd evtstrm aes pmull sha1 \
        sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 \
        asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm sb paca pacg dcpodp sve2 sveaes \
        svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh rng bti \
        ecv afp wfxt\n\n";

    #[test]
    fn an_m4_max_guest_fits_an_axion_host() {
        let guest = parse_linux_features(M4_MAX_GUEST_CPUINFO);
        assert!(guest.contains(&"FEAT_ATOMICS".to_string()));
        let host = parse_linux_features(AXION_CPUINFO);
        assert_eq!(missing_features(&guest, &host), Vec::<String>::new());
    }

    #[test]
    fn an_m4_max_guest_names_what_a_cortex_a72_lacks() {
        let guest = parse_linux_features(M4_MAX_GUEST_CPUINFO);
        let pi = parse_linux_features("Features\t: fp asimd evtstrm crc32 cpuid\n");
        let missing = missing_features(&guest, &pi);
        assert!(missing.contains(&"FEAT_ATOMICS".to_string()), "{missing:?}");
        assert!(missing.contains(&"FEAT_USCAT".to_string()), "{missing:?}");
    }

    #[test]
    fn foreign_state_must_carry_the_translation_tag() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("checkpoint.bin");
        let mut checkpoint = minimal_checkpoint_manifest();

        // This host's own state is never inspected.
        std::fs::write(&state, b"untagged").unwrap();
        validate_state_origin(&checkpoint, &state).unwrap();

        checkpoint.host_platform = "other/arch".into();
        let err = validate_state_origin(&checkpoint, &state).unwrap_err();
        assert!(err.to_string().contains("newer smolvm"), "{err}");

        let mut tagged = HVF_STATE_TAG.to_vec();
        tagged.extend_from_slice(b"rest of the state");
        std::fs::write(&state, tagged).unwrap();
        validate_state_origin(&checkpoint, &state).unwrap();
    }

    #[test]
    fn only_mac_to_linux_crosses_platforms() {
        assert!(host_platform_compatible("darwin/arm64", "darwin/arm64"));
        assert!(host_platform_compatible("darwin/arm64", "linux/arm64"));
        assert!(!host_platform_compatible("linux/arm64", "darwin/arm64"));
        assert!(!host_platform_compatible("darwin/arm64", "linux/amd64"));
        assert!(!host_platform_compatible("linux/amd64", "linux/arm64"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_denied_root_only_restore_tmpfs_is_not_a_cleanup_failure() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let staged = Path::new(RESTORE_TMPFS_ROOT).join("abc.restore-input");
        let expected = unsafe { libc::geteuid() } != 0;
        assert_eq!(staged_by_root_only(&staged, &denied), expected);
        // Anywhere else, and any other error, still fails cleanup.
        assert!(!staged_by_root_only(
            Path::new("/var/lib/vm/.restore-input"),
            &denied
        ));
        let other = std::io::Error::from(std::io::ErrorKind::Other);
        assert!(!staged_by_root_only(&staged, &other));
    }

    #[test]
    fn checkpoints_are_written_as_dot_checkpoint_and_the_earlier_name_still_works() {
        for name in [
            "a.checkpoint",
            "A.CHECKPOINT",
            "dir/a.checkpoint",
            "a.smolcheckpoint",
        ] {
            assert!(has_checkpoint_extension(Path::new(name)), "{name}");
        }
        for name in ["a.smolmachine", "a", "a.checkpoint.tmp", "checkpoint"] {
            assert!(!has_checkpoint_extension(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn a_checkpoint_has_nothing_outside_its_checksummed_bytes() {
        let footer = smolvm_pack::format::PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 1000,
            manifest_offset: 1000,
            manifest_size: 200,
            checksum: 0,
        };
        let exact = 1000 + 200 + smolvm_pack::format::FOOTER_SIZE as u64;
        assert!(check_checkpoint_layout(&footer, exact).is_ok());
        assert!(
            check_checkpoint_layout(&footer, exact + 1).is_err(),
            "bytes between the manifest and the footer are not checksummed"
        );
        let shifted = smolvm_pack::format::PackFooter {
            assets_offset: 8,
            ..footer
        };
        assert!(check_checkpoint_layout(&shifted, exact).is_err());
        let gap = smolvm_pack::format::PackFooter {
            manifest_offset: 1008,
            ..footer
        };
        assert!(check_checkpoint_layout(&gap, exact).is_err());
        let stub = smolvm_pack::format::PackFooter {
            stub_size: 4096,
            ..footer
        };
        assert!(check_checkpoint_layout(&stub, exact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_received_checkpoint_is_verified_from_its_stream_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let assets: Vec<u8> = (0..1000_u32).map(|i| (i * 13 % 251) as u8).collect();
        let manifest = vec![b'm'; 200];
        let mut prefix = assets.clone();
        prefix.extend_from_slice(&manifest);
        // The CRC the stream reports for these bytes followed by any footer.
        let mut probe = smolvm_pack::extract::ArtifactStreamHasher::new();
        probe.update(&prefix);
        probe.update(&[0; smolvm_pack::format::FOOTER_SIZE]);
        let checksum = probe.finish().crc32_before_footer.unwrap();
        let footer = smolvm_pack::format::PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: assets.len() as u64,
            manifest_offset: assets.len() as u64,
            manifest_size: manifest.len() as u64,
            checksum,
        };
        let mut bytes = prefix.clone();
        bytes.extend_from_slice(&footer.to_bytes());
        let artifact = dir.path().join("upload.smolcheckpoint");
        std::fs::write(&artifact, &bytes).unwrap();
        let streamed = |data: &[u8]| {
            let mut hasher = smolvm_pack::extract::ArtifactStreamHasher::new();
            for chunk in data.chunks(97) {
                hasher.update(chunk);
            }
            hasher.finish()
        };
        let hashes = streamed(&bytes);

        let verified = verified_from_received(&artifact, &hashes, true).expect("verified");
        assert_eq!(verified.footer().checksum, checksum);
        assert!(verified.covers(&artifact));
        assert!(verified.digest_proof().is_some());
        // The full-read verification agrees with the streamed one.
        assert!(verify_sidecar_pinned(&artifact).is_ok());

        // Anything that breaks the correspondence falls back to a real read.
        assert!(verified_from_received(&artifact, &hashes, false).is_none());
        let mut wrong = hashes.clone();
        wrong.crc32_before_footer = Some(checksum ^ 1);
        assert!(verified_from_received(&artifact, &wrong, true).is_none());
        let mut short = hashes.clone();
        short.len -= 1;
        assert!(verified_from_received(&artifact, &short, true).is_none());
        let mut padded = bytes.clone();
        padded.insert(prefix.len(), 0);
        std::fs::write(&artifact, &padded).unwrap();
        assert!(verified_from_received(&artifact, &streamed(&padded), true).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_received_verification_stops_covering_a_rewritten_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let mut probe = smolvm_pack::extract::ArtifactStreamHasher::new();
        probe.update(b"payload");
        probe.update(&[0; smolvm_pack::format::FOOTER_SIZE]);
        let footer = smolvm_pack::format::PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 7,
            manifest_offset: 7,
            manifest_size: 0,
            checksum: probe.finish().crc32_before_footer.unwrap(),
        };
        let mut bytes = b"payload".to_vec();
        bytes.extend_from_slice(&footer.to_bytes());
        let artifact = dir.path().join("upload.smolcheckpoint");
        std::fs::write(&artifact, &bytes).unwrap();
        let mut hasher = smolvm_pack::extract::ArtifactStreamHasher::new();
        hasher.update(&bytes);
        let verified = verified_from_received(&artifact, &hasher.finish(), true).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&artifact, &bytes).unwrap();
        assert!(!verified.covers(&artifact));
        assert!(verified.digest_proof().is_none());
    }

    #[test]
    fn resuming_clears_the_memory_a_previous_restore_retained() {
        let vm = tempfile::tempdir().unwrap();
        std::fs::write(vm.path().join(RETAINED_MEMORY_BACKING), b"old guest ram").unwrap();
        std::fs::create_dir_all(vm.path().join(INSTALLED_DIR)).unwrap();
        clear_stale_restore_state(vm.path()).unwrap();
        assert!(!vm.path().join(RETAINED_MEMORY_BACKING).exists());
        assert!(!vm.path().join(INSTALLED_DIR).exists());
        // Nothing to clear is not an error.
        clear_stale_restore_state(vm.path()).unwrap();
    }

    #[test]
    fn single_file_checkpoints_hold_one_generation() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("one.smolcheckpoint");
        std::fs::write(&file, b"not really a checkpoint").unwrap();
        assert_eq!(resolve_generation(&file, None).unwrap(), None);
        assert_eq!(resolve_generation(&file, Some("~0")).unwrap(), None);
        assert_eq!(resolve_generation(&file, Some(" ")).unwrap(), None);
        assert!(resolve_generation(&file, Some("~1")).is_err());
        assert!(resolve_generation(&file, Some("0123456789ab")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completed_memory_staging_preserves_owned_inode_after_source_removal() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("runtime-memory");
        let staged = dir.path().join("staged-memory");
        std::fs::write(&source, b"captured RAM").unwrap();
        let linked = link_completed_memory(&source, &staged).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(!linked);
            assert!(!staged.exists());
            return;
        }
        assert!(linked);
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&staged).unwrap().ino()
        );
        let metadata = std::fs::metadata(&staged).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        std::fs::remove_file(source).unwrap();
        assert_eq!(std::fs::read(staged).unwrap(), b"captured RAM");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completed_memory_staging_declines_preexisting_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"RAM").unwrap();
        std::fs::hard_link(&source, dir.path().join("alias")).unwrap();
        let staged = dir.path().join("staged");
        assert!(!link_completed_memory(&source, &staged).unwrap());
        assert!(!staged.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completed_memory_staging_never_clobbers_destination() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let staged = dir.path().join("staged");
        std::fs::write(&source, b"RAM").unwrap();
        std::fs::write(&staged, b"existing").unwrap();
        let result = link_completed_memory(&source, &staged);
        if unsafe { libc::geteuid() } == 0 {
            assert!(result.is_err());
        } else {
            assert!(!result.unwrap());
        }
        assert_eq!(std::fs::read(staged).unwrap(), b"existing");
    }

    fn packed_sidecar(dir: &Path, name: &str, tag: &str) -> PathBuf {
        let artifact = dir.join(name);
        let manifest = smolvm_pack::format::PackManifest::new(
            format!("vm://{tag}"),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        Packer::new(manifest).pack_artifact(&artifact).unwrap();
        artifact
    }

    /// A registry-cache hit on the artifact being verified must leave the
    /// verification stable. The hit used to set the blob's atime for LRU, which
    /// moves ctime on Linux, so a burst of creates from one cached pack failed
    /// with "changed while it was being verified" whenever two overlapped.
    #[cfg(unix)]
    #[test]
    fn registry_cache_hit_during_checksum_keeps_verification_stable() {
        let dir = tempfile::tempdir().unwrap();
        let cache = smolvm_registry::BlobCache::open(dir.path().to_path_buf(), u64::MAX).unwrap();
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let staged = packed_sidecar(dir.path(), "staged.smolcheckpoint", "cache-hit");
        let blob = cache.blob_path_for(digest);
        std::fs::rename(&staged, &blob).unwrap();

        let outcome = classify_sidecar_verification_after_read(&blob, || {
            for _ in 0..8 {
                assert_eq!(cache.get(digest).as_deref(), Some(blob.as_path()));
            }
        })
        .unwrap();
        assert!(
            matches!(outcome, SidecarVerification::Stable(_)),
            "a concurrent cache hit must not invalidate the verification"
        );
    }

    #[cfg(unix)]
    #[test]
    fn link_during_checksum_requires_new_proof_not_corruption_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = packed_sidecar(dir.path(), "a.smolcheckpoint", "concurrent-link");
        let alias = dir.path().join("second-reader");
        let outcome = classify_sidecar_verification_after_read(&artifact, || {
            std::fs::hard_link(&artifact, &alias).unwrap();
        })
        .unwrap();
        assert!(matches!(outcome, SidecarVerification::ChangedDuringRead));
        assert!(verified_sidecar_footer(&artifact).is_ok());
        assert!(verified_sidecar_footer(&alias).is_ok());
    }

    /// Creates from one private pack verify it once, not on every create
    /// (#1454); any change to the pack or to who may write it ends the reuse.
    #[cfg(unix)]
    #[test]
    fn a_private_sidecar_is_verified_once_per_unchanged_inode() {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let artifact = packed_sidecar(dir.path(), "a.smolcheckpoint", "verified-once");
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(remembered_verification(&artifact).is_none());
        let footer = verified_sidecar_footer(&artifact).unwrap();
        assert_eq!(
            remembered_verification(&artifact).map(|known| known.checksum),
            Some(footer.checksum)
        );

        // Once others may write it, the earlier verification no longer
        // vouches for its bytes, even after it is made private again.
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(remembered_verification(&artifact).is_none());
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(remembered_verification(&artifact).is_none());
        verified_sidecar_footer(&artifact).unwrap();
        assert!(remembered_verification(&artifact).is_some());

        // A write in place is caught by a fresh verification.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&artifact)
            .unwrap();
        file.seek(SeekFrom::Start(footer.assets_offset)).unwrap();
        file.write_all(b"corrupt").unwrap();
        drop(file);
        assert!(remembered_verification(&artifact).is_none());
        assert!(verified_sidecar_footer(&artifact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn write_after_checksum_cannot_produce_a_reusable_proof() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = packed_sidecar(dir.path(), "a.smolcheckpoint", "changed-bytes");
        let outcome = classify_sidecar_verification_after_read(&artifact, || {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .open(&artifact)
                .unwrap()
                .write_all(b"invalid")
                .unwrap();
        })
        .unwrap();
        assert!(matches!(outcome, SidecarVerification::ChangedDuringRead));
        assert!(verified_sidecar_footer(&artifact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_verification_covers_only_the_unchanged_inode() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = packed_sidecar(dir.path(), "a.smolcheckpoint", "pinned");
        let link = dir.path().join("link");
        std::fs::hard_link(&artifact, &link).unwrap();
        let verified = verify_sidecar_pinned(&link).unwrap();
        assert_eq!(
            verified.footer().checksum,
            smolvm_pack::packer::read_footer_from_sidecar(&artifact)
                .unwrap()
                .checksum
        );
        // Every name of the verified inode is covered; a different, equally
        // valid artifact is not, whatever path it sits at.
        assert!(verified.covers(&link));
        assert!(verified.covers(&artifact));
        let other = packed_sidecar(dir.path(), "other.smolcheckpoint", "other");
        assert!(verified_sidecar_footer(&other).is_ok());
        assert!(!verified.covers(&other));
        // Replacement between validation and use: the new file at `link` is a
        // different inode, and losing the `link` name moved the verified
        // inode's ctime, so even its surviving name is no longer covered
        // (conservative: a fresh verification of it still passes).
        std::fs::rename(&other, &link).unwrap();
        assert!(!verified.covers(&link));
        assert!(!verified.covers(&artifact));
        assert!(verified_sidecar_footer(&artifact).is_ok());
        // In-place mutation of the pinned inode through another name.
        let verified = verify_sidecar_pinned(&artifact).unwrap();
        assert!(verified.covers(&artifact));
        std::thread::sleep(std::time::Duration::from_millis(50));
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&artifact)
                .unwrap();
            file.write_all(b"x").unwrap();
        }
        assert!(!verified.covers(&artifact));
        assert!(verified_sidecar_footer(&artifact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_verification_is_conservative_across_eviction() {
        // Unlinking another name (cache eviction or a cache put that relinks)
        // changes the inode's ctime, so a handed-over verification stops
        // covering it and the caller falls back to a full verification.
        let dir = tempfile::tempdir().unwrap();
        let artifact = packed_sidecar(dir.path(), "a.smolcheckpoint", "evict");
        let staged = dir.path().join("staged");
        std::fs::hard_link(&artifact, &staged).unwrap();
        let verified = verify_sidecar_pinned(&staged).unwrap();
        assert!(verified.covers(&staged));
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::remove_file(&artifact).unwrap();
        assert!(!verified.covers(&staged));
        // The staged link is still a valid artifact; fresh verification passes.
        assert!(verified_sidecar_footer(&staged).is_ok());
    }

    #[test]
    fn pinned_verification_rejects_a_corrupt_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = packed_sidecar(dir.path(), "a.smolcheckpoint", "corrupt");
        let mut bytes = std::fs::read(&artifact).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        std::fs::write(&artifact, &bytes).unwrap();
        let error = verify_sidecar_pinned(&artifact).unwrap_err().to_string();
        assert!(error.contains("checksum mismatch"), "{error}");
        std::fs::write(&artifact, b"short").unwrap();
        assert!(verify_sidecar_pinned(&artifact).is_err());
    }

    #[test]
    fn readonly_restore_consumption_preserves_shared_input() {
        let machine = tempfile::tempdir().unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"checkpoint RAM").unwrap();
        let snapshot = machine.path().join(INSTALLED_DIR);
        std::fs::create_dir(&snapshot).unwrap();
        for name in [
            PENDING_MARKER,
            READONLY_INPUT_MARKER,
            "checkpoint.bin",
            "manifest.bin",
        ] {
            std::fs::write(snapshot.join(name), b"").unwrap();
        }
        let retained = machine.path().join(READONLY_INPUT_DIR);
        std::fs::create_dir(&retained).unwrap();
        std::fs::hard_link(source.path(), retained.join("memory.bin")).unwrap();
        assert_eq!(pending_dir(machine.path()), Some(snapshot));
        consume_with_retained_backing(machine.path(), false).unwrap();
        assert!(pending_dir(machine.path()).is_none());
        assert!(!retained.exists());
        assert_eq!(std::fs::read(source.path()).unwrap(), b"checkpoint RAM");
        consume_with_retained_backing(machine.path(), false).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn readonly_restore_rejects_directory_symlink() {
        let machine = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), machine.path().join(READONLY_INPUT_DIR)).unwrap();
        assert!(open_readonly_memory(machine.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn readonly_restore_rejects_unprotected_directory() {
        use std::os::unix::fs::PermissionsExt;
        let machine = tempfile::tempdir().unwrap();
        let retained = machine.path().join(READONLY_INPUT_DIR);
        std::fs::create_dir(&retained).unwrap();
        std::fs::set_permissions(&retained, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(retained.join("memory.bin"), b"RAM").unwrap();
        assert!(open_readonly_memory(machine.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root for per-VM ownership validation"]
    fn readonly_restore_rejects_mutable_input_and_retains_opened_inode() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let machine = tempfile::tempdir().unwrap();
        let retained = machine.path().join(READONLY_INPUT_DIR);
        std::fs::create_dir(&retained).unwrap();
        std::fs::set_permissions(&retained, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"original immutable RAM").unwrap();
        let input = retained.join("memory.bin");

        std::os::unix::fs::symlink(source.path(), &input).unwrap();
        assert!(open_readonly_memory(machine.path()).is_err());
        std::fs::remove_file(&input).unwrap();
        std::fs::hard_link(source.path(), &input).unwrap();
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(open_readonly_memory(machine.path()).is_err());
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::chown(&input, Some(2000000), Some(2000000)).unwrap();
        assert!(open_readonly_memory(machine.path()).is_err());
        std::os::unix::fs::chown(&input, Some(0), Some(0)).unwrap();

        let mut opened = open_readonly_memory(machine.path()).unwrap();
        // Cache eviction or path replacement cannot redirect an already
        // retained descriptor to a different generation's bytes.
        std::fs::remove_file(&input).unwrap();
        std::fs::write(&input, b"replacement generation").unwrap();
        source.close().unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original immutable RAM");
        assert_eq!(std::fs::read(&input).unwrap(), b"replacement generation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root for per-VM ownership validation"]
    fn readonly_restore_root_isolation_and_fallback() {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt},
        };
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let machine = tempfile::tempdir().unwrap();
        let retained = machine.path().join(READONLY_INPUT_DIR);
        std::fs::create_dir(&retained).unwrap();
        std::fs::set_permissions(&retained, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"immutable RAM").unwrap();
        let input = retained.join("memory.bin");
        std::fs::hard_link(source.path(), &input).unwrap();
        crate::process::chown_tree_except(machine.path(), 2000000, 2000000, Some(&retained))
            .unwrap();
        assert_eq!(std::fs::metadata(&retained).unwrap().uid(), 0);
        assert_eq!(std::fs::metadata(&input).unwrap().uid(), 0);
        let opened = open_readonly_memory(machine.path()).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(opened.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        let snapshot = machine.path().join(INSTALLED_DIR);
        std::fs::create_dir(&snapshot).unwrap();
        std::fs::write(snapshot.join(READONLY_INPUT_MARKER), b"").unwrap();
        prepare_memory_backend(&snapshot, false).unwrap();
        assert!(!has_readonly_memory(&snapshot));
        assert!(!retained.exists());
        std::fs::write(snapshot.join("memory.bin"), b"private RAM").unwrap();
        assert_eq!(std::fs::read(source.path()).unwrap(), b"immutable RAM");
    }

    #[test]
    fn restore_checks_sidecar_checksum_before_manifest_or_machine_creation() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("state.checkpoint");
        let manifest = PackManifest::new(
            "vm://checksum-test".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        Packer::new(manifest).pack_artifact(&artifact).unwrap();
        let db = crate::db::SmolvmDb::open_at(&temp.path().join("test.db")).unwrap();
        let error = restore_from_path(&db, "checksum-test", &artifact).unwrap_err();
        assert!(error.to_string().contains("is not a checkpoint"), "{error}");
        let original = std::fs::read(&artifact).unwrap();
        let footer = smolvm_pack::packer::read_footer_from_sidecar(&artifact).unwrap();
        for offset in [0, footer.manifest_offset as usize] {
            let mut damaged = original.clone();
            damaged[offset] ^= 0xff;
            std::fs::write(&artifact, damaged).unwrap();
            let error = restore_from_path(&db, "checksum-test", &artifact).unwrap_err();
            assert!(error.to_string().contains("checksum mismatch"), "{error}");
            assert!(db.get_vm("checksum-test").unwrap().is_none());
        }
    }

    #[test]
    fn runtime_capture_is_private_machine_local_and_removed_on_drop() {
        let data = tempfile::tempdir().unwrap();
        let capture = runtime_capture_dir_at(data.path(), None).unwrap();
        let path = capture.path().to_path_buf();
        assert_eq!(path.parent(), Some(data.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::create_dir(path.join(ASSET_DIR)).unwrap();
        std::fs::write(path.join(ASSET_DIR).join("memory.bin"), b"private state").unwrap();
        drop(capture);
        assert!(!path.exists());
    }

    #[test]
    fn a_checkpoint_credential_ca_becomes_the_restored_machines_ca() {
        let extracted = tempfile::tempdir().unwrap();
        std::fs::create_dir(extracted.path().join(ASSET_DIR)).unwrap();
        let source = extracted.path().join(CREDENTIAL_CA_ASSET);
        let original =
            smolvm_credentials::MachineCa::generate("cred", &["httpbin.org".to_string()]).unwrap();
        std::fs::write(&source, original.export().as_bytes()).unwrap();
        let asset = describe_asset(&source, CREDENTIAL_CA_ASSET).unwrap();
        assert!(!asset.sha256.is_empty(), "the CA asset is checksummed");

        let machine = tempfile::tempdir().unwrap();
        let partial = tempfile::tempdir().unwrap();
        install_credential_ca(extracted.path(), machine.path(), partial.path(), &asset).unwrap();
        let ca_dir = machine.path().join(crate::credentials::CA_DIR_NAME);
        let installed = smolvm_credentials::MachineCa::load(&ca_dir, "cred-restored").unwrap();
        assert_eq!(installed.certificate_pem(), original.certificate_pem());
        assert!(
            std::fs::read_dir(partial.path()).unwrap().next().is_none(),
            "the staged copy holding the key is removed"
        );

        // A tampered CA fails its checksum; a CA under another path is refused.
        std::fs::write(&source, b"{}").unwrap();
        let other = tempfile::tempdir().unwrap();
        assert!(
            install_credential_ca(extracted.path(), other.path(), partial.path(), &asset).is_err()
        );
        let misplaced = CheckpointAsset {
            path: "checkpoint/memory.bin".into(),
            ..asset
        };
        assert!(
            install_credential_ca(extracted.path(), other.path(), partial.path(), &misplaced)
                .is_err()
        );
    }

    /// An extracted checkpoint with raw storage and overlay disks, ready to install.
    fn installable_checkpoint() -> (tempfile::TempDir, PortableCheckpointManifest) {
        let extracted = tempfile::tempdir().unwrap();
        let source = extracted.path().join(ASSET_DIR);
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("checkpoint.bin"), b"state").unwrap();
        std::fs::write(source.join("memory.bin"), b"memory").unwrap();
        std::fs::write(source.join("manifest.bin"), b"layout").unwrap();
        for role in ["storage", "overlay"] {
            let disk_dir = source.join("disks").join(role);
            std::fs::create_dir_all(&disk_dir).unwrap();
            std::fs::write(disk_dir.join("0"), format!("{role}-disk")).unwrap();
        }
        let disk = |role: &str, target: &str| CheckpointDisk {
            role: role.to_string(),
            files: vec![CheckpointDiskFile {
                asset: CheckpointAsset {
                    path: format!("checkpoint/disks/{role}/0"),
                    size: std::fs::metadata(source.join("disks").join(role).join("0"))
                        .unwrap()
                        .len(),
                    sha256: String::new(),
                },
                target: target.to_string(),
                format: "raw".to_string(),
            }],
        };
        let metadata = PortableCheckpointManifest {
            version: FORMAT_VERSION,
            runtime_abi: RUNTIME_ABI.to_string(),
            host_platform: crate::platform::Platform::current()
                .host_oci_platform()
                .to_string(),
            cpu_contract: checkpoint_cpu_contract().unwrap(),
            cpus: 2,
            memory_mib: 512,
            storage_gib: None,
            overlay_gib: None,
            device_profile: DEVICE_PROFILE.to_string(),
            state: describe_asset(&source.join("checkpoint.bin"), "checkpoint/checkpoint.bin")
                .unwrap(),
            memory: describe_sparse_asset(&source.join("memory.bin"), "checkpoint/memory.bin")
                .unwrap(),
            layout: describe_asset(&source.join("manifest.bin"), "checkpoint/manifest.bin")
                .unwrap(),
            disks: vec![
                disk("storage", "storage.raw"),
                disk("overlay", "overlay.raw"),
            ],
            workload: None,
            network: Some(CheckpointNetwork::default()),
            packed_layers: None,
            host_image: None,
            lineage: None,
            payload: Default::default(),
            history: Vec::new(),
            base: None,
            credential_ca: None,
            clock: None,
            guest_cpu_features: None,
        };
        (extracted, metadata)
    }

    #[test]
    fn install_verifies_and_consumes_checkpoint() {
        let (extracted, metadata) = installable_checkpoint();
        let source = extracted.path().join(ASSET_DIR);
        let machine = tempfile::tempdir().unwrap();
        install(extracted.path(), machine.path(), &metadata).unwrap();
        assert!(metadata.memory.sha256.is_empty());
        assert!(pending_dir(machine.path()).is_some());
        assert_eq!(
            std::fs::read(machine.path().join("storage.raw")).unwrap(),
            b"storage-disk"
        );
        assert_eq!(
            std::fs::read(machine.path().join("overlay.raw")).unwrap(),
            b"overlay-disk"
        );
        assert!(machine.path().join("storage.formatted").is_file());
        assert!(machine.path().join("overlay.formatted").is_file());
        // A base this host cannot share stays a private writable copy: no
        // copy-on-write layer, and never an alias of the extraction cache.
        #[cfg(target_os = "linux")]
        let shared = crate::process::vm_uid_drop_active();
        #[cfg(not(target_os = "linux"))]
        let shared = false;
        if !shared {
            assert!(!machine.path().join("storage.qcow2").exists());
            assert!(!machine
                .path()
                .join(".smolcheckpoint-storage-base.raw")
                .exists());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !shared {
                assert_ne!(
                    std::fs::metadata(source.join("disks/storage/0"))
                        .unwrap()
                        .ino(),
                    std::fs::metadata(machine.path().join("storage.raw"))
                        .unwrap()
                        .ino()
                );
            }
            assert_ne!(
                std::fs::metadata(source.join("memory.bin")).unwrap().ino(),
                std::fs::metadata(machine.path().join(INSTALLED_DIR).join("memory.bin"))
                    .unwrap()
                    .ino()
            );
        }
        std::fs::write(
            machine.path().join(INSTALLED_DIR).join("memory.bin"),
            b"private",
        )
        .unwrap();
        assert_eq!(std::fs::read(source.join("memory.bin")).unwrap(), b"memory");
        consume(machine.path()).unwrap();
        assert!(pending_dir(machine.path()).is_none());
        assert_eq!(
            machine.path().join(RETAINED_MEMORY_BACKING).exists(),
            cfg!(target_os = "macos")
        );
        assert_eq!(
            std::fs::read(machine.path().join("storage.raw")).unwrap(),
            b"storage-disk"
        );

        let mut remote = metadata.clone();
        let mut source_record = VmRecord::new(
            "remote-source".into(),
            2,
            512,
            Vec::new(),
            Vec::new(),
            false,
        );
        source_record.image = Some("alpine:3.20".into());
        remote.workload = checkpoint_workload(&source_record.name, &source_record);
        let manifest = PackManifest::new(
            "vm://remote-source".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        remote.lineage = Some(smolvm_pack::format::CheckpointLineage {
            id: "0123456789abcdef0123456789abcdef".into(),
            parent: None,
            machine: "remote-source".into(),
            created_at: "2026-09-22T00:00:00Z".into(),
        });
        remote.network = Some(CheckpointNetwork {
            enabled: true,
            backend: Some("virtio-net".into()),
            guest_subnet: Some("10.200.0.0/30".into()),
            ..Default::default()
        });
        let restored = restored_record("local-restore", &manifest, &remote).unwrap();
        // The restored guest still has its captured address, so the host side
        // must come back on the same subnet.
        assert_eq!(restored.guest_subnet.as_deref(), Some("10.200.0.0/30"));
        // The restored machine continues the checkpoint's history.
        assert_eq!(
            restored.checkpoint_head.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            restored.fork_overlay_owner.as_deref(),
            Some("remote-source")
        );
        assert_eq!(restored.vm_uid_owner(), Some("local-restore"));
        let roundtrip: VmRecord =
            serde_json::from_str(&serde_json::to_string(&restored).unwrap()).unwrap();
        assert_eq!(roundtrip.vm_uid_owner(), Some("local-restore"));

        let mut oversized = metadata.clone();
        oversized.memory.size =
            u64::from(oversized.memory_mib) * 1024 * 1024 + 2 * 1024 * 1024 * 1024 + 1;
        assert!(validate_compatibility(&oversized).is_err());

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            validate_compatibility(&metadata).expect("capturing host satisfies its CPU contract");
            match cpu_vendor().unwrap().as_deref() {
                Some("GenuineIntel") => assert_eq!(
                    metadata.cpu_contract,
                    CheckpointCpuContract::LinuxKvmIntelPortableV1
                ),
                _ => assert_eq!(
                    metadata.cpu_contract,
                    CheckpointCpuContract::ExactV1 {
                        fingerprint: cpu_fingerprint().unwrap(),
                    }
                ),
            }
        }

        let mut exact_mismatch = metadata.clone();
        exact_mismatch.cpu_contract = CheckpointCpuContract::ExactV1 {
            fingerprint: "different-host".to_string(),
        };
        assert!(validate_compatibility(&exact_mismatch).is_err());

        let mut incompatible = metadata;
        incompatible.runtime_abi.push_str("-other");
        assert!(validate_compatibility(&incompatible).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_installed_checkpoint_restores_with_the_window_its_guest_booted_with() {
        if crate::agent::virtiofs::legacy_packed_layers_dax_window() == 0 {
            return;
        }
        let (extracted, mut metadata) = installable_checkpoint();
        metadata.device_profile = DEVICE_PROFILE_PACKED_LAYERS.to_string();
        let mut installed_window = |dax_window_bytes: Option<u64>| {
            metadata.packed_layers = Some(CheckpointPackedLayers {
                artifact_sha256: "ab".repeat(32),
                footer_checksum: 7,
                registry_ref: None,
                dax_window_bytes,
            });
            let machine = tempfile::tempdir().unwrap();
            install_with(extracted.path(), machine.path(), &metadata, true, None).unwrap();
            let pending = pending_dir(machine.path()).unwrap();
            crate::agent::virtiofs::packed_layers_window_for_launch(Some(&pending))
        };
        // A guest that booted in the small window restores into it.
        assert_eq!(
            installed_window(Some(crate::agent::virtiofs::PACKED_LAYERS_DAX_WINDOW)),
            crate::agent::virtiofs::PACKED_LAYERS_DAX_WINDOW
        );
        // A checkpoint taken before windows were recorded gets the legacy window.
        assert_eq!(
            installed_window(None),
            crate::agent::virtiofs::LEGACY_PACKED_LAYERS_DAX_WINDOW
        );
        // So does one recording a window libkrun cannot map.
        assert_eq!(
            installed_window(Some(12345)),
            crate::agent::virtiofs::LEGACY_PACKED_LAYERS_DAX_WINDOW
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_private_metadata_does_not_share_ownership_with_cache_or_siblings() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("checkpoint.bin");
        std::fs::write(&source, b"device state").unwrap();
        let asset = describe_asset(&source, "checkpoint/checkpoint.bin").unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        copy_verified(&source, &first, &asset, false).unwrap();
        copy_verified(&source, &second, &asset, false).unwrap();
        assert_ne!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&first).unwrap().ino()
        );
        assert_ne!(
            std::fs::metadata(&first).unwrap().ino(),
            std::fs::metadata(&second).unwrap().ino()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_disk_backings_have_independent_ownership() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("backing.raw");
        let file = std::fs::File::create(&source).unwrap();
        file.set_len(1024 * 1024).unwrap();
        // Writable or untrusted input is never eligible for immutable sharing.
        file.set_permissions(std::fs::Permissions::from_mode(0o666))
            .unwrap();
        let asset = describe_sparse_asset(&source, "checkpoint/disks/storage/1").unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        link_or_copy_verified_sparse(&source, &first, &asset).unwrap();
        link_or_copy_verified_sparse(&source, &second, &asset).unwrap();
        assert_ne!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&first).unwrap().ino()
        );
        assert_ne!(
            std::fs::metadata(&first).unwrap().ino(),
            std::fs::metadata(&second).unwrap().ino()
        );
        std::fs::write(&first, b"private change").unwrap();
        assert_eq!(std::fs::metadata(&source).unwrap().len(), asset.size);
        assert_eq!(std::fs::metadata(&second).unwrap().len(), asset.size);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restore_directory_is_private_and_does_not_follow_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("restore");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let alias = root.path().join("alias");
        symlink(&directory, &alias).unwrap();
        assert!(protect_restore_directory(&alias).is_err());
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
        protect_restore_directory(&directory).unwrap();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root to exercise retained VMM ownership"]
    fn retained_backing_promotion_preserves_source_and_reuses_cache_inode() {
        use std::os::unix::fs::MetadataExt;
        assert!(crate::process::vm_uid_drop_active());
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        let live = root.path().join("live.raw");
        let source = cache.join("disk");
        std::fs::write(&live, b"immutable snapshot").unwrap();
        crate::process::chown_tree(&live, 2_000_000, 2_000_000).unwrap();
        std::fs::hard_link(&live, &source).unwrap();
        let abandoned = cache.join(".checkpoint-disk-abandoned");
        std::fs::create_dir(&abandoned).unwrap();
        std::fs::set_permissions(
            &abandoned,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(abandoned.join("disk"), b"incomplete").unwrap();
        let asset = CheckpointAsset {
            path: "disk".into(),
            size: 18,
            sha256: String::new(),
        };
        let before = std::fs::metadata(&live).unwrap();
        assert!(
            promote_retained_backing_locked(&cache, &source, &asset, |s, d| copy_verified_sparse(
                s, d, &asset
            ))
            .unwrap()
        );
        let promoted = std::fs::metadata(&source).unwrap();
        assert!(!abandoned.exists());
        assert_ne!(promoted.ino(), before.ino());
        assert_eq!(promoted.uid(), 0);
        assert_eq!(promoted.mode() & 0o777, 0o444);
        let after = std::fs::metadata(&live).unwrap();
        assert_eq!(
            (after.ino(), after.uid(), after.mode()),
            (before.ino(), before.uid(), before.mode())
        );
        assert_eq!(
            std::fs::read(&source).unwrap(),
            std::fs::read(&live).unwrap()
        );
        assert!(
            !promote_retained_backing_locked(&cache, &source, &asset, |_, _| panic!(
                "second restore must not copy"
            ))
            .unwrap()
        );
        let child = root.path().join("child.raw");
        assert!(share_service_owned_backing(&source, &child, &asset).unwrap());
        std::fs::remove_file(&source).unwrap();
        assert_eq!(std::fs::read(&child).unwrap(), b"immutable snapshot");
        std::fs::write(&live, b"source-owned data!").unwrap();
        assert_eq!(std::fs::read(&child).unwrap(), b"immutable snapshot");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root to exercise retained VMM ownership"]
    fn retained_backing_promotion_refuses_changed_source_and_cleans_partial_copy() {
        use std::os::unix::fs::MetadataExt;
        assert!(crate::process::vm_uid_drop_active());
        for changed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("disk");
            std::fs::write(&source, b"before").unwrap();
            crate::process::chown_tree(&source, 2_000_000, 2_000_000).unwrap();
            let before = std::fs::metadata(&source).unwrap().ino();
            let asset = CheckpointAsset {
                path: "disk".into(),
                size: 6,
                sha256: String::new(),
            };
            let result = promote_retained_backing_locked(root.path(), &source, &asset, |s, d| {
                copy_verified_sparse(s, d, &asset)?;
                if changed {
                    std::fs::write(s, b"after!")?;
                    Ok(())
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into())
                }
            });
            assert!(result.is_err());
            assert_eq!(std::fs::metadata(&source).unwrap().ino(), before);
            assert_eq!(std::fs::metadata(&source).unwrap().uid(), 2_000_000);
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root to exercise isolated VMM ownership"]
    fn shared_backings_remain_readonly_across_uid_changes_and_cache_eviction() {
        use std::os::unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        };
        assert!(crate::process::vm_uid_drop_active());
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
        let cache = root.path().join("cache");
        let unrelated = root.path().join("ordinary-readonly-file");
        std::fs::write(&unrelated, b"ordinary file").unwrap();
        std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0o444)).unwrap();
        crate::process::chown_tree(&unrelated, 2_000_000, 2_000_000).unwrap();
        assert_eq!(std::fs::metadata(&unrelated).unwrap().uid(), 2_000_000);
        std::fs::create_dir(&cache).unwrap();
        let source = cache.join("disk");
        std::fs::write(&source, b"immutable disk").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let asset = describe_sparse_asset(&source, "checkpoint/disks/storage/1").unwrap();
        for uid in [2_000_000, 2_000_001] {
            let vm = root.path().join(uid.to_string());
            std::fs::create_dir(&vm).unwrap();
            std::fs::set_permissions(&vm, std::fs::Permissions::from_mode(0o755)).unwrap();
            protect_restore_directory(&vm).unwrap();
            assert!(share_service_owned_backing(&source, &vm.join("disk"), &asset).unwrap());
            // The VM is not launched yet: even its future UID must not read
            // the checkpoint until ownership is deliberately transferred.
            assert!(!std::process::Command::new("/bin/cat")
                .arg(vm.join("disk"))
                .uid(uid)
                .gid(uid)
                .output()
                .unwrap()
                .status
                .success());
            crate::process::chown_tree(&vm, uid, uid).unwrap();
        }
        let first = root.path().join("2000000/disk");
        let second = root.path().join("2000001/disk");
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&first).unwrap().ino()
        );
        assert_eq!(std::fs::metadata(&first).unwrap().uid(), 0);
        assert_eq!(std::fs::metadata(&cache).unwrap().mode() & 0o777, 0o700);
        let owner_read = std::process::Command::new("/bin/cat")
            .arg(&first)
            .uid(2_000_000)
            .gid(2_000_000)
            .output()
            .unwrap();
        assert!(owner_read.status.success());
        assert_eq!(owner_read.stdout, b"immutable disk");
        assert!(!std::process::Command::new("/bin/chmod")
            .args(["600"])
            .arg(&first)
            .uid(2_000_000)
            .gid(2_000_000)
            .output()
            .unwrap()
            .status
            .success());
        assert!(!std::process::Command::new("/bin/sh")
            .args(["-c", "printf bad > \"$1\"", "--"])
            .arg(&first)
            .uid(2_000_000)
            .gid(2_000_000)
            .output()
            .unwrap()
            .status
            .success());
        assert!(!std::process::Command::new("/bin/cat")
            .arg(&second)
            .uid(2_000_000)
            .gid(2_000_000)
            .output()
            .unwrap()
            .status
            .success());
        std::fs::remove_file(source).unwrap();
        std::fs::remove_file(second).unwrap();
        crate::process::chown_tree(first.parent().unwrap(), 2_000_000, 2_000_000).unwrap();
        assert_eq!(std::fs::metadata(&first).unwrap().uid(), 0);
        assert_eq!(std::fs::read(first).unwrap(), b"immutable disk");
    }

    #[test]
    fn immutable_checkpoint_payload_requires_digest() {
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"state").unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let destination = destination_dir.path().join("state-copy");
        let asset = CheckpointAsset {
            path: "checkpoint/checkpoint.bin".to_string(),
            size: 5,
            sha256: String::new(),
        };

        let error = copy_verified(source.path(), &destination, &asset, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing its SHA-256 digest"), "{error}");
    }

    #[test]
    fn checkpoint_transport_pack_is_removed_after_install() {
        let machine = tempfile::tempdir().unwrap();
        let pack = machine.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        std::fs::write(pack.join(".smolvm-extracted"), b"").unwrap();
        std::fs::write(pack.join("transport-only"), b"payload").unwrap();

        discard_transport_pack(machine.path()).unwrap();

        assert!(!pack.exists());
    }

    #[cfg(unix)]
    #[test]
    fn qcow2_backing_staging_never_aliases_the_live_header() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let qcow_staged = dir.path().join("qcow-staged");
        let raw_staged = dir.path().join("raw-staged");
        std::fs::write(&source, b"disk-layer").unwrap();

        stage_checkpoint_disk_layer(&source, &qcow_staged, 1, "qcow2").unwrap();
        assert_ne!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&qcow_staged).unwrap().ino()
        );

        stage_checkpoint_disk_layer(&source, &raw_staged, 1, "raw").unwrap();
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&raw_staged).unwrap().ino()
        );
    }

    /// Create a 64 MiB qcow2 image at `path` over `backing`.
    #[cfg(target_os = "linux")]
    fn create_qcow2(path: &Path, backing: &str, format: &str) {
        use imago::FormatCreateBuilder;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let file = ImagoFile::try_from(file).unwrap();
        let builder = Qcow2::<ImagoFile>::create_builder(file)
            .size(64 * 1024 * 1024)
            .backing(backing.to_string(), format.to_string());
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(builder.create())
            .unwrap();
    }

    /// A storage chain like a restored machine's: a writable qcow2 top over
    /// the checkpoint's former top over its raw base, and a raw overlay.
    #[cfg(target_os = "linux")]
    fn restored_disk_chain(vm: &Path) -> Vec<u8> {
        let create = create_qcow2;
        std::fs::create_dir_all(vm).unwrap();
        let base = vm.join(".smolcheckpoint-storage-1.raw");
        let file = std::fs::File::create(&base).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        std::fs::write(vm.join(crate::storage::OVERLAY_DISK_FILENAME), b"overlay").unwrap();
        let layer = vm.join(".smolcheckpoint-storage-layer2.qcow2");
        create(&layer, ".smolcheckpoint-storage-1.raw", "raw");
        // Data past the header the archive must carry unchanged.
        let mut bytes = std::fs::read(&layer).unwrap();
        bytes.extend((0..200_000_u32).map(|i| (i % 251) as u8));
        std::fs::write(&layer, &bytes).unwrap();
        create(
            &vm.join("storage.qcow2"),
            ".smolcheckpoint-storage-layer2.qcow2",
            "qcow2",
        );
        bytes
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn backing_layers_are_packed_from_the_source_with_their_names_patched() {
        let dir = tempfile::tempdir().unwrap();
        let vm = dir.path().join("vm");
        let live = restored_disk_chain(&vm);
        let layer = vm.join(".smolcheckpoint-storage-layer2.qcow2");
        let staging = dir.path().join("staging");
        let (disks, deferred) = stage_disk_chains(&vm, &staging.join("checkpoint"), None).unwrap();
        let storage = &disks[0].files;
        assert_eq!(
            storage
                .iter()
                .map(|f| f.format.as_str())
                .collect::<Vec<_>>(),
            ["qcow2", "qcow2", "raw"]
        );
        assert_eq!(deferred.0.len(), 1, "the qcow2 backing was not deferred");
        // Only the writable top is copied while the source is paused.
        let staged = staging.join("checkpoint/disks/storage");
        assert!(!staged.join("1").exists());
        assert_eq!(
            inspect_qcow2(&staged.join("0")).unwrap().0.as_deref(),
            Some(storage[1].target.as_str())
        );

        let mut collector = AssetCollector::new(staging.clone()).unwrap();
        deferred.pack_from_source(&mut collector).unwrap();
        let archive = dir.path().join("assets.tar.zst");
        collector.compress(&archive, false).unwrap();
        assert_eq!(
            std::fs::read(&layer).unwrap(),
            live,
            "the live layer changed"
        );

        let out = dir.path().join("out");
        smolvm_pack::assets::decompress_assets_from_file(&archive, &out).unwrap();
        let packed = out.join("checkpoint/disks/storage/1");
        assert_eq!(
            inspect_qcow2(&packed).unwrap(),
            (Some(storage[2].target.clone()), Some("raw".to_string()))
        );
        // Exactly what the earlier copy-then-rewrite staging produced.
        let expected = dir.path().join("expected");
        std::fs::write(&expected, &live).unwrap();
        rewrite_qcow2_backing(&expected, &storage[2].target).unwrap();
        assert_eq!(
            std::fs::read(&packed).unwrap(),
            std::fs::read(&expected).unwrap()
        );
        assert_eq!(storage[1].asset.size, live.len() as u64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_pause_pins_the_layers_another_machine_owns_instead_of_packing_them() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        // A golden's chain, and a fork whose own top is backed by it.
        let golden = dir.path().join("golden");
        let live = restored_disk_chain(&golden);
        let fork = dir.path().join("fork");
        std::fs::create_dir(&fork).unwrap();
        std::fs::write(fork.join(crate::storage::OVERLAY_DISK_FILENAME), b"overlay").unwrap();
        create_qcow2(
            &fork.join("storage.qcow2"),
            golden.join("storage.qcow2").to_str().unwrap(),
            "qcow2",
        );

        // Owned by the golden's VMM, not the service alone.
        for entry in std::fs::read_dir(&golden).unwrap() {
            use std::os::unix::fs::PermissionsExt;
            let path = entry.unwrap().path();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        }
        let captured = disk_chain_identity(&fork).unwrap();

        let checkpoint = dir.path().join("staging/checkpoint");
        let mut pins = LayerPins::new(&fork).unwrap();
        let (disks, deferred) = stage_disk_chains(&fork, &checkpoint, Some(&mut pins)).unwrap();
        // Pinning, by this pause or another fork's, leaves the fork's disks as
        // captured, so resume still keeps them.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::hard_link(golden.join("storage.qcow2"), dir.path().join("other-pin")).unwrap();
        assert_eq!(disk_chain_identity(&fork).unwrap(), captured);
        let storage = &disks[0].files;
        assert_eq!(storage.len(), 4, "the manifest still lists the whole chain");
        assert!(deferred.0.is_empty(), "a pinned layer was also deferred");
        // The fork's own top and its overlay are staged; the golden's are not.
        assert!(checkpoint.join("disks/storage/0").is_file());
        assert!(checkpoint.join("disks/overlay/0").is_file());
        for index in 1..4 {
            assert!(!checkpoint.join(format!("disks/storage/{index}")).exists());
        }
        assert_eq!(
            pins.layers
                .iter()
                .map(|layer| layer.archive_path.as_str())
                .collect::<Vec<_>>(),
            [
                "checkpoint/disks/storage/1",
                "checkpoint/disks/storage/2",
                "checkpoint/disks/storage/3"
            ]
        );
        let artifact = fork.join("pause-1.smolcheckpoint");
        pins.commit(&artifact).unwrap();

        // The golden can go: its pinned layers stay.
        std::fs::remove_dir_all(&golden).unwrap();
        let layers = paused_layers(&fork, &artifact).unwrap();
        assert_eq!(layers, pins.layers);
        assert!(paused_layers(&fork, &fork.join("pause-2.smolcheckpoint"))
            .unwrap()
            .is_empty());

        // Installing one puts it where extraction would have, patched as
        // packing would have.
        let extracted = dir.path().join("extracted");
        for layer in &layers {
            install_pinned_layer(&fork, layer, &extracted).unwrap();
        }
        let installed = extracted.join("checkpoint/disks/storage/2");
        assert_eq!(
            inspect_qcow2(&installed).unwrap(),
            (Some(storage[3].target.clone()), Some("raw".to_string()))
        );
        let expected = dir.path().join("expected");
        std::fs::write(&expected, &live).unwrap();
        rewrite_qcow2_backing(&expected, &storage[3].target).unwrap();
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            std::fs::read(&expected).unwrap()
        );
        // A raw base is installed as the pinned inode itself.
        let pin = paused_layers_dir(&fork).unwrap().join(&layers[2].pin);
        assert_eq!(
            std::fs::metadata(extracted.join("checkpoint/disks/storage/3"))
                .unwrap()
                .ino(),
            std::fs::metadata(&pin).unwrap().ino()
        );

        // A pin that is not the recorded layer is refused.
        std::fs::remove_file(&pin).unwrap();
        std::fs::write(&pin, b"other").unwrap();
        assert!(install_pinned_layer(&fork, &layers[2], &dir.path().join("again")).is_err());

        remove_paused_layers(&fork).unwrap();
        assert!(!paused_layers_dir(&fork).unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_pause_does_not_pin_its_own_layers() {
        let dir = tempfile::tempdir().unwrap();
        let vm = dir.path().join("vm");
        std::fs::create_dir(&vm).unwrap();
        std::fs::write(vm.join("own.raw"), b"own").unwrap();
        let mut pins = LayerPins::new(&vm).unwrap();
        assert!(!pins
            .pin(&vm.join("own.raw"), "checkpoint/disks/storage/1", None)
            .unwrap());
        pins.commit(&vm.join("pause-1.smolcheckpoint")).unwrap();
        assert!(!paused_layers_dir(&vm).unwrap().exists());
        assert_eq!(
            paused_layers_owner(&paused_layers_dir(&vm).unwrap()),
            Some("vm")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kept_staging_gets_private_rebased_copies_of_backing_layers() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let vm = dir.path().join("vm");
        let live = restored_disk_chain(&vm);
        let layer = vm.join(".smolcheckpoint-storage-layer2.qcow2");
        let checkpoint = dir.path().join("staging/checkpoint");
        let (disks, deferred) = stage_disk_chains(&vm, &checkpoint, None).unwrap();
        // The source may be replaced after it resumes; the held file is not.
        std::fs::rename(&layer, vm.join("rotated")).unwrap();
        deferred.stage_copies().unwrap();
        let staged = checkpoint.join("disks/storage/1");
        assert_ne!(
            std::fs::metadata(&staged).unwrap().ino(),
            std::fs::metadata(vm.join("rotated")).unwrap().ino()
        );
        assert_eq!(
            inspect_qcow2(&staged).unwrap().0.as_deref(),
            Some(disks[0].files[2].target.as_str())
        );
        assert_eq!(std::fs::read(vm.join("rotated")).unwrap(), live);
    }

    #[cfg(unix)]
    #[test]
    fn paused_disks_are_kept_only_while_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let vm = &dir.path().join("0123abcd");
        std::fs::create_dir(vm).unwrap();
        std::fs::write(vm.join(crate::storage::STORAGE_DISK_FILENAME), b"storage").unwrap();
        std::fs::write(vm.join(crate::storage::OVERLAY_DISK_FILENAME), b"overlay").unwrap();
        let artifact = vm.join("pause-1.smolcheckpoint");
        let disk = |role: &str| CheckpointDisk {
            role: role.to_string(),
            files: vec![CheckpointDiskFile {
                asset: CheckpointAsset {
                    path: format!("checkpoint/disks/{role}/0"),
                    size: 7,
                    sha256: String::new(),
                },
                target: format!("{role}.raw"),
                format: "raw".to_string(),
            }],
        };
        let disks = [disk("storage"), disk("overlay")];

        let captured = disk_chain_identity(vm).unwrap();
        record_paused_disks(vm, &artifact, Some(&captured));
        assert!(paused_disks_intact(vm, &artifact, &disks));
        assert!(!paused_disks_intact(
            vm,
            &vm.join("other.smolcheckpoint"),
            &disks
        ));
        assert!(!paused_disks_intact(vm, &artifact, &disks[..1]));

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(vm.join(crate::storage::STORAGE_DISK_FILENAME), b"written").unwrap();
        assert!(!paused_disks_intact(vm, &artifact, &disks));

        // Disks that changed between capture and stop are never recorded.
        remove_paused_disks_marker(vm).unwrap();
        record_paused_disks(vm, &artifact, Some(&captured));
        assert!(!paused_disks_marker(vm).unwrap().exists());
        assert_eq!(
            paused_disks_marker_owner(&paused_disks_marker(vm).unwrap()),
            Some("0123abcd")
        );
    }

    fn qcow2_header_fixture() -> Vec<u8> {
        let old = disk_target("storage", 9, "qcow2").unwrap();
        let mut bytes = vec![0_u8; 8192];
        bytes[..4].copy_from_slice(b"QFI\xfb");
        bytes[4..8].copy_from_slice(&3_u32.to_be_bytes());
        bytes[8..16].copy_from_slice(&128_u64.to_be_bytes());
        bytes[16..20].copy_from_slice(&(old.len() as u32).to_be_bytes());
        bytes[20..24].copy_from_slice(&12_u32.to_be_bytes());
        bytes[100..104].copy_from_slice(&104_u32.to_be_bytes());
        bytes[128..128 + old.len()].copy_from_slice(old.as_bytes());
        bytes[4096..].fill(0xa5);
        bytes
    }

    #[test]
    fn checkpoint_backing_name_can_grow_across_ten_layers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.qcow2");
        let new = disk_target("storage", 10, "qcow2").unwrap();
        let mut bytes = qcow2_header_fixture();
        std::fs::write(&path, &bytes).unwrap();

        rewrite_qcow2_backing(&path, &new).unwrap();

        bytes[16..20].copy_from_slice(&(new.len() as u32).to_be_bytes());
        bytes[128..128 + new.len()].copy_from_slice(new.as_bytes());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        rewrite_qcow2_backing(&path, "x").unwrap();
        bytes[16..20].copy_from_slice(&1_u32.to_be_bytes());
        bytes[128..128 + new.len()].fill(0);
        bytes[128] = b'x';
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn checkpoint_backing_growth_reopens_with_qcow2_driver() {
        use imago::FormatCreateBuilder;

        let image = tempfile::NamedTempFile::new().unwrap();
        let file = ImagoFile::try_from(image.reopen().unwrap()).unwrap();
        let builder = Qcow2::<ImagoFile>::create_builder(file)
            .size(1024 * 1024)
            .backing("a".to_string(), "raw".to_string());
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(builder.create())
            .unwrap();
        let before = std::fs::read(image.path()).unwrap();
        let target = disk_target("storage", 10, "raw").unwrap();
        rewrite_qcow2_backing(image.path(), &target).unwrap();
        assert_eq!(
            inspect_qcow2(image.path()).unwrap(),
            (Some(target), Some("raw".to_string()))
        );
        let after = std::fs::read(image.path()).unwrap();
        assert_eq!(&before[65536..], &after[65536..]);
    }

    #[test]
    fn checkpoint_backing_rewrite_rejects_unsafe_growth_without_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.qcow2");
        let new = disk_target("storage", 10, "qcow2").unwrap();
        for case in 0..8 {
            let mut bytes = qcow2_header_fixture();
            match case {
                0 => bytes[159] = 1, // Growth would overwrite non-padding data.
                1 => bytes[8..16].copy_from_slice(&4090_u64.to_be_bytes()),
                2 => bytes[20..24].copy_from_slice(&64_u32.to_be_bytes()),
                3 => bytes[8..16].copy_from_slice(&32_u64.to_be_bytes()),
                4 => bytes[100..104].copy_from_slice(&4096_u32.to_be_bytes()),
                5 => bytes[4..8].copy_from_slice(&4_u32.to_be_bytes()),
                6 => bytes.truncate(159),
                7 => {
                    bytes[104..108].copy_from_slice(&1_u32.to_be_bytes());
                    bytes[108..112].copy_from_slice(&32_u32.to_be_bytes());
                }
                _ => unreachable!(),
            }
            std::fs::write(&path, &bytes).unwrap();
            assert!(rewrite_qcow2_backing(&path, &new).is_err(), "case {case}");
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "case {case}");
        }
    }

    #[test]
    fn checkpoint_backings_do_not_collide_with_runtime_directories() {
        for role in ["storage", "overlay"] {
            for index in 1..64 {
                let target = disk_target(role, index, "qcow2").unwrap();
                assert_ne!(target, "d");
                assert_ne!(target, "s");
                assert!(target.starts_with(".smolcheckpoint-"));
            }
        }
    }

    #[test]
    fn consume_can_retain_a_live_memory_backing() {
        let machine = tempfile::tempdir().unwrap();
        let pending = machine.path().join(INSTALLED_DIR);
        std::fs::create_dir(&pending).unwrap();
        std::fs::write(pending.join(PENDING_MARKER), b"1\n").unwrap();
        std::fs::write(pending.join("checkpoint.bin"), b"state").unwrap();
        std::fs::write(pending.join("manifest.bin"), b"layout").unwrap();
        std::fs::write(pending.join("memory.bin"), b"live-memory").unwrap();

        consume_with_retained_backing(machine.path(), true).unwrap();

        assert!(pending_dir(machine.path()).is_none());
        assert!(!pending.exists());
        assert_eq!(
            std::fs::read(machine.path().join(RETAINED_MEMORY_BACKING)).unwrap(),
            b"live-memory"
        );
    }

    #[test]
    fn common_image_service_is_checkpoint_eligible() {
        let mut record = VmRecord::new(
            "image-service".to_string(),
            2,
            1024,
            Vec::new(),
            vec![(18080, 8080)],
            true,
        );
        record.image = Some("python:3.12-alpine".to_string());
        record.network_backend = Some(crate::network::NetworkBackend::VirtioNet);
        record.restart.policy = crate::config::RestartPolicy::OnFailure;
        record.restart.max_retries = 7;
        record.restart.max_backoff_secs = 19;
        record.guest_subnet = Some("10.200.0.0/30".to_string());

        validate_capture_profile(&record).expect("image + network + ports must be portable");
        let workload = checkpoint_workload(&record.name, &record).unwrap();
        assert_eq!(workload.image, "python:3.12-alpine");
        assert_eq!(workload.overlay_owner, "image-service");
        assert_eq!(workload.restart_policy, "on-failure");
        assert_eq!(workload.restart_max_retries, 7);
        assert_eq!(workload.restart_max_backoff_secs, 19);
        let network = checkpoint_network(&record);
        assert!(network.enabled);
        assert_eq!(network.backend.as_deref(), Some("virtio-net"));
        assert_eq!(network.guest_subnet.as_deref(), Some("10.200.0.0/30"));
        assert_eq!(
            network.ports,
            vec![CheckpointPort {
                host: 18080,
                guest: 8080
            }]
        );
    }

    #[test]
    fn a_credentialed_machine_records_the_virtio_net_backend_it_runs_on() {
        // `--net` alone launches on TSI, but a credential policy steers the
        // default backend to virtio-net. The checkpoint must record the
        // backend the machine actually ran on, or the restore launches TSI and
        // libkrun cannot match the snapshot's virtio-net device.
        let mut record = VmRecord::new(
            "credentialed".to_string(),
            1,
            512,
            Vec::new(),
            Vec::new(),
            true,
        );
        assert_eq!(checkpoint_network(&record).backend.as_deref(), Some("tsi"));

        record.credential_policy = Some(crate::credentials::CredentialPolicy {
            credentials: vec![crate::credentials::parse_credential_flag(
                "mytok=MY_API_TOKEN@httpbin.org",
            )
            .unwrap()],
        });
        let network = checkpoint_network(&record);
        assert_eq!(network.backend.as_deref(), Some("virtio-net"));
        assert_eq!(
            restored_network_backend(&PortableCheckpointManifest {
                network: Some(network),
                ..minimal_checkpoint_manifest()
            })
            .unwrap(),
            Some(crate::network::NetworkBackend::VirtioNet)
        );
    }

    #[test]
    fn host_bound_attachments_remain_ineligible() {
        let mut record = VmRecord::new(
            "host-bound".to_string(),
            2,
            1024,
            vec![("/host".to_string(), "/guest".to_string(), true)],
            Vec::new(),
            false,
        );
        record.image = Some("alpine:3.20".to_string());
        let error = validate_capture_profile(&record).unwrap_err().to_string();
        assert!(error.contains("host mounts"), "{error}");

        // A pack source is recorded in the checkpoint and reattached on restore.
        record.mounts.clear();
        record.source_smolmachine = Some("/tmp/source.smolmachine".to_string());
        validate_capture_profile(&record).unwrap();
    }

    fn no_network_machine(image: &str) -> VmRecord {
        let mut record = VmRecord::new(
            "fetched".to_string(),
            2,
            1024,
            Vec::new(),
            Vec::new(),
            false,
        );
        record.image = Some(image.to_string());
        record
    }

    #[test]
    fn a_host_fetched_registry_image_can_be_captured() {
        let mut record = no_network_machine("python:3.12-slim-bookworm");
        record.pin_host_fetched_image("local:abc".to_string(), "sha256:feedface".to_string());
        validate_capture_profile(&record).expect("a host-fetched registry image is portable");
        assert!(mounts_image_layers(&record));
        // The checkpoint names the registry image at the fetched digest, never
        // this host's archive.
        let workload = checkpoint_workload(&record.name, &record).unwrap();
        assert_eq!(workload.image, "python:3.12-slim-bookworm@sha256:feedface");
    }

    #[test]
    fn a_users_own_local_image_still_cannot_be_captured() {
        for image in ["local:abc", "local-dir:/srv/rootfs"] {
            let record = no_network_machine(image);
            let error = validate_capture_profile(&record).unwrap_err().to_string();
            assert!(
                error.contains(
                    "the initial portable checkpoint profile does not support host-backed image layers"
                ),
                "{image}: {error}"
            );
        }
        // An origin that is itself a local source is not a registry origin.
        let mut record = no_network_machine("./saved.tar");
        record.pin_host_fetched_image("local:abc".to_string(), "sha256:aa".to_string());
        let error = validate_capture_profile(&record).unwrap_err().to_string();
        assert!(error.contains("host-backed image layers"), "{error}");
    }

    #[test]
    fn a_registry_image_the_guest_pulled_keeps_its_reference() {
        let record = no_network_machine("alpine:3.20");
        assert!(!mounts_image_layers(&record));
        let workload = checkpoint_workload(&record.name, &record).unwrap();
        assert_eq!(workload.image, "alpine:3.20");
    }

    #[test]
    fn a_host_image_checkpoint_needs_the_packed_layers_device_profile() {
        let host_image = CheckpointHostImage {
            reference: "python:3.12-slim-bookworm@sha256:feedface".to_string(),
            config_digest: "sha256:c0ffee".to_string(),
            archive_size: 42,
            archive_mtime: 7,
        };
        let mut metadata = minimal_checkpoint_manifest();
        metadata.host_image = Some(host_image.clone());
        // Without the profile, a runtime would resume without the device.
        let error = validate_compatibility(&metadata).unwrap_err().to_string();
        assert!(error.contains("device profile"), "{error}");

        metadata.device_profile = DEVICE_PROFILE_PACKED_LAYERS.to_string();
        validate_compatibility(&metadata).unwrap();
        metadata.memory.size = max_checkpoint_memory_image(metadata.memory_mib, true).unwrap();
        validate_compatibility(&metadata).unwrap();
        metadata.memory.size = 1;

        // A runtime that predates host images expects a pack with this
        // profile, so it refuses the checkpoint rather than resume without
        // the image's device.
        let mut older = metadata.clone();
        older.host_image = None;
        let error = validate_compatibility(&older).unwrap_err().to_string();
        assert!(error.contains("device profile"), "{error}");

        // Never both a pack and a fetched image.
        metadata.packed_layers = Some(CheckpointPackedLayers {
            artifact_sha256: "ab".repeat(32),
            footer_checksum: 7,
            registry_ref: None,
            dax_window_bytes: None,
        });
        assert!(validate_compatibility(&metadata).is_err());

        // The manifest round-trips the image, and omits it when absent.
        metadata.packed_layers = None;
        let json = serde_json::to_value(&metadata).unwrap();
        assert_eq!(
            json["host_image"]["reference"],
            "python:3.12-slim-bookworm@sha256:feedface"
        );
        let back: PortableCheckpointManifest = serde_json::from_value(json).unwrap();
        assert_eq!(back.host_image, Some(host_image));
        let json = serde_json::to_value(minimal_checkpoint_manifest()).unwrap();
        assert!(json.get("host_image").is_none());
    }

    #[test]
    fn a_restored_host_image_points_the_record_at_its_archive() {
        let mut record = no_network_machine("python:3.12-slim-bookworm@sha256:feedface");
        RestoredHostImage {
            local: "local:abc".to_string(),
            origin: "python:3.12-slim-bookworm@sha256:feedface".to_string(),
            digest: "sha256:feedface".to_string(),
        }
        .apply(&mut record);
        assert_eq!(record.image.as_deref(), Some("local:abc"));
        assert_eq!(
            record.display_image(),
            Some("python:3.12-slim-bookworm@sha256:feedface")
        );
        // A restored machine can be captured again under the same reference.
        validate_capture_profile(&record).unwrap();
        assert_eq!(
            checkpoint_workload(&record.name, &record).unwrap().image,
            "python:3.12-slim-bookworm@sha256:feedface"
        );
    }

    #[test]
    fn a_packed_layers_checkpoint_needs_its_own_device_profile() {
        let packed = CheckpointPackedLayers {
            artifact_sha256: "ab".repeat(32),
            footer_checksum: 7,
            registry_ref: Some("registry.example/library/alpine:latest".to_string()),
            dax_window_bytes: None,
        };
        let mut metadata = minimal_checkpoint_manifest();
        validate_compatibility(&metadata).unwrap();

        // The pack without the profile that says a restore must reattach it.
        metadata.packed_layers = Some(packed.clone());
        let error = validate_compatibility(&metadata).unwrap_err().to_string();
        assert!(error.contains("device profile"), "{error}");

        metadata.device_profile = DEVICE_PROFILE_PACKED_LAYERS.to_string();
        validate_compatibility(&metadata).unwrap();
        metadata.memory.size = max_checkpoint_memory_image(metadata.memory_mib, true).unwrap();
        validate_compatibility(&metadata).unwrap();
        metadata.memory.size += 1;
        assert!(validate_compatibility(&metadata).is_err());
        metadata.memory.size = 1;

        // And the profile without a pack to reattach.
        metadata.packed_layers = None;
        let error = validate_compatibility(&metadata).unwrap_err().to_string();
        assert!(error.contains("device profile"), "{error}");
    }

    #[test]
    fn checkpoints_without_a_pack_still_read_and_write_the_same() {
        let metadata = minimal_checkpoint_manifest();
        let json = serde_json::to_value(&metadata).unwrap();
        assert!(json.get("packed_layers").is_none());
        let back: PortableCheckpointManifest = serde_json::from_value(json).unwrap();
        assert_eq!(back.packed_layers, None);
    }

    /// The smallest manifest this host accepts, for tests of the validator.
    fn minimal_checkpoint_manifest() -> PortableCheckpointManifest {
        PortableCheckpointManifest {
            version: FORMAT_VERSION,
            runtime_abi: RUNTIME_ABI.to_string(),
            host_platform: crate::platform::Platform::current()
                .host_oci_platform()
                .to_string(),
            cpu_contract: checkpoint_cpu_contract().unwrap(),
            cpus: 1,
            memory_mib: 1,
            storage_gib: None,
            overlay_gib: None,
            device_profile: DEVICE_PROFILE.to_string(),
            state: CheckpointAsset {
                path: "checkpoint/checkpoint.bin".to_string(),
                size: 1,
                sha256: "00".repeat(32),
            },
            memory: CheckpointAsset {
                path: "checkpoint/memory.bin".to_string(),
                size: 1,
                sha256: "00".repeat(32),
            },
            layout: CheckpointAsset {
                path: "checkpoint/manifest.bin".to_string(),
                size: 1,
                sha256: "00".repeat(32),
            },
            disks: Vec::new(),
            workload: None,
            network: Some(CheckpointNetwork::default()),
            packed_layers: None,
            host_image: None,
            lineage: None,
            payload: Default::default(),
            history: Vec::new(),
            base: None,
            credential_ca: None,
            clock: None,
            guest_cpu_features: None,
        }
    }

    #[test]
    fn credential_bindings_survive_capture_and_restore() {
        let mut record = VmRecord::new("cred".to_string(), 2, 1024, Vec::new(), Vec::new(), true);
        record.image = Some("alpine:3.20".to_string());
        let policy: smolvm_protocol::CredentialPolicy = serde_json::from_str(
            r#"{"credentials":[{"name":"mytok","environment_variable":"MY_API_TOKEN","allowed_hosts":["httpbin.org"]}]}"#,
        )
        .unwrap();
        record.credential_policy = Some(policy.clone());
        record.credential_placeholders =
            [("mytok".to_string(), "SMOL_PLACEHOLDER_MYTOK_AA".to_string())].into();

        // Capture: the envelope carries the policy and the exact placeholders
        // the captured workload holds.
        let network = checkpoint_network(&record);
        assert_eq!(network.credential_policy.as_ref(), Some(&policy));
        assert_eq!(
            network
                .credential_placeholders
                .get("mytok")
                .map(String::as_str),
            Some("SMOL_PLACEHOLDER_MYTOK_AA")
        );

        // Restore: the record gets them back unchanged, so a placeholder the
        // workload kept (in captured RAM or a config file) still matches the
        // interceptor instead of traveling upstream verbatim.
        let mut checkpoint = minimal_checkpoint_manifest();
        checkpoint.network = Some(network);
        let manifest = smolvm_pack::format::PackManifest::new(
            "alpine:3.20".to_string(),
            "sha256:0".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );
        let restored = restored_record("cred-restored", &manifest, &checkpoint).unwrap();
        assert_eq!(restored.credential_policy.as_ref(), Some(&policy));
        assert_eq!(
            restored.credential_placeholders,
            record.credential_placeholders
        );

        // A hand-edited artifact carrying a policy `create` would refuse is
        // refused at restore too.
        let bad: smolvm_protocol::CredentialPolicy = serde_json::from_str(
            r#"{"credentials":[{"name":"mytok","environment_variable":"MY_API_TOKEN","allowed_hosts":["*"]}]}"#,
        )
        .unwrap();
        let mut checkpoint = minimal_checkpoint_manifest();
        checkpoint.network = Some(CheckpointNetwork {
            credential_policy: Some(bad),
            ..CheckpointNetwork::default()
        });
        assert!(restored_record("cred-restored", &manifest, &checkpoint).is_err());
    }

    #[test]
    fn unreleased_checkpoint_versions_are_rejected() {
        let mut metadata = minimal_checkpoint_manifest();
        validate_compatibility(&metadata).unwrap();
        metadata.version = FORMAT_VERSION - 1;
        assert!(validate_compatibility(&metadata).is_err());
        // A history file needs its own version, and only that version.
        metadata.payload = smolvm_pack::format::CheckpointLayout::Chunked;
        metadata.version = FORMAT_VERSION;
        assert!(validate_compatibility(&metadata).is_err());
        metadata.version = HISTORY_FORMAT_VERSION;
        validate_compatibility(&metadata).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_cpu_vendor_parser_is_bounded_and_first_processor_only() {
        assert_eq!(
            linux_cpu_vendor(
                "processor: 0\nvendor_id: GenuineIntel\n\nprocessor: 1\nvendor_id: Other\n"
            ),
            Some("GenuineIntel".to_string())
        );
        assert_eq!(linux_cpu_vendor("processor: 0\nmodel: 1\n\n"), None);
        let oversized = "x".repeat(65);
        assert_eq!(
            linux_cpu_vendor(&format!("vendor_id: {oversized}\n\n")),
            None
        );
    }
}

#[cfg(test)]
mod aarch64_feature_contract_tests {
    //! Fixtures are real `sysctl -a` output shapes from an M1 Pro
    //! (MacBookPro18,3) and an M4 Max (Mac16,6), captured 2026-08-30.
    use super::missing_features;

    fn v(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// The twenty features an M4 Max has that an M1 Pro does not, minus SME
    /// (masked from every guest), leaves these ten.
    const M4_ONLY: &[&str] = &[
        "FEAT_AFP",
        "FEAT_BF16",
        "FEAT_BTI",
        "FEAT_ECV",
        "FEAT_FPAC",
        "FEAT_FPACCOMBINE",
        "FEAT_I8MM",
        "FEAT_PAuth2",
        "FEAT_RPRES",
        "FEAT_WFxT",
    ];
    /// The one feature an M1 Pro has that an M4 Max does not.
    const M1_ONLY: &[&str] = &["FEAT_SSBS"];
    const SHARED: &[&str] = &["FEAT_LSE", "FEAT_FP16", "FEAT_DotProd", "FEAT_PAuth"];

    fn m4() -> Vec<String> {
        let mut f = v(SHARED);
        f.extend(v(M4_ONLY));
        f
    }
    fn m1() -> Vec<String> {
        let mut f = v(SHARED);
        f.extend(v(M1_ONLY));
        f
    }

    #[test]
    fn a_host_with_the_same_features_accepts_the_checkpoint() {
        assert!(missing_features(&m4(), &m4()).is_empty());
    }

    /// Extra features on the destination are harmless: the guest already decided
    /// at boot what it would use.
    #[test]
    fn a_richer_host_accepts_a_leaner_checkpoint() {
        let lean = v(SHARED);
        assert!(missing_features(&lean, &m4()).is_empty());
    }

    /// The case the whole contract exists for: a guest that probed an M4 cannot
    /// resume where those instructions do not exist.
    #[test]
    fn an_m4_checkpoint_is_refused_on_an_m1() {
        let missing = missing_features(&m4(), &m1());
        assert_eq!(
            missing,
            v(M4_ONLY),
            "every M4-only feature must be reported"
        );
        assert!(missing.contains(&"FEAT_BF16".to_string()));
        assert!(missing.contains(&"FEAT_I8MM".to_string()));
    }

    /// Newer is NOT automatically a superset, so "older to newer is safe" is
    /// wrong as a rule. The M4 Max lacks FEAT_SSBS, which the M1 Pro has — these
    /// two are unordered and both directions must be refused.
    #[test]
    fn newer_silicon_is_not_automatically_a_superset() {
        let missing = missing_features(&m1(), &m4());
        assert_eq!(
            missing,
            v(M1_ONLY),
            "an M1 checkpoint must be refused on an M4 over FEAT_SSBS"
        );
    }

    /// SME must never reach the contract: libkrun masks it out of every guest,
    /// so recording it would refuse checkpoints over a feature no guest can use.
    #[test]
    fn sme_is_excluded_from_the_contract() {
        use super::is_masked_from_guest;
        for name in [
            "FEAT_SME",
            "FEAT_SME2",
            "FEAT_SME_F64F64",
            "SME_I8I32",
            "SME_B16F32",
        ] {
            assert!(is_masked_from_guest(name), "{name} must be masked");
        }
        for name in ["FEAT_BF16", "FEAT_I8MM", "FEAT_SSBS", "FEAT_LSE"] {
            assert!(!is_masked_from_guest(name), "{name} must be kept");
        }
    }

    #[test]
    fn macos_sysctl_output_is_parsed() {
        use super::parse_macos_features;
        let out = "hw.optional.arm.FEAT_BF16: 1\n\
                   hw.optional.arm.FEAT_SSBS: 0\n\
                   hw.optional.arm.FEAT_I8MM: 1\n\
                   hw.optional.floatingpoint: 1\n\
                   hw.memsize: 38654705664\n";
        let got = parse_macos_features(out);
        assert_eq!(got, vec!["FEAT_BF16".to_string(), "FEAT_I8MM".to_string()]);
    }

    #[test]
    fn linux_cpuinfo_features_are_normalised() {
        use super::parse_linux_features;
        let cpuinfo = "processor\t: 0\n\
                       Features\t: fp asimd bf16 i8mm\n\
                       CPU part\t: 0xd4f\n\
                       \n\
                       processor\t: 1\n\
                       Features\t: fp\n";
        let got = parse_linux_features(cpuinfo);
        assert_eq!(
            got,
            vec![
                "FEAT_FP".to_string(),
                "FEAT_ASIMD".to_string(),
                "FEAT_BF16".to_string(),
                "FEAT_I8MM".to_string()
            ],
            "only the first processor block, upper-cased"
        );
    }
}

#[cfg(test)]
mod aarch64_live_host_tests {
    /// Enumerates THIS machine. Proves the contract is built from real hardware
    /// rather than only from fixtures, and that SME never reaches it.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn this_host_reports_a_usable_feature_set() {
        let features = super::aarch64_guest_features().expect("enumerate host features");
        assert!(
            features.len() > 10,
            "expected a real feature set, got {features:?}"
        );
        assert!(
            !features.iter().any(|f| f.contains("SME")),
            "SME is masked from guests and must not be in the contract: {features:?}"
        );
        let mut sorted = features.clone();
        sorted.sort();
        assert_eq!(sorted, features, "contract must be sorted for stability");
        eprintln!("host provides {} guest-visible features", features.len());
    }
}
