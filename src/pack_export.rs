//! Shared from-VM pack export: turn a stopped machine into `.smolmachine`
//! assets.
//!
//! This is the single implementation behind every CLI's `pack create
//! --from-vm` (and the cloud export path). It lives in the lib — not a CLI —
//! so front-ends cannot fork-and-drift the export semantics: the bare-VM /
//! image-machine / artifact-sourced dispatch, the manifest seeding, and the
//! layer flattening below are all decided here.
//!
//! Image-based exports produce ONE flattened layer. Multi-layer packs cannot
//! overlay-mount virtiofs-backed lowers at import time, so the guest falls
//! back to physically merging every layer file-by-file through virtiofs —
//! pathologically slow for file-heavy layers (a node_modules-scale overlay
//! reads as a boot hang). The from-image pack path already pre-merges for
//! exactly this reason; flattening here gives from-VM exports the same
//! import-time behavior: a single lowerdir that mounts instantly.

use crate::agent::{
    machine_layers_cache_dir, read_shared_pack_pointer, resolve_disk_image, vm_data_dir,
    AgentClient, AgentManager, LaunchFeatures, VmResources,
};
use crate::config::VmRecord;
use crate::data::disk::DiskFormat;
use crate::storage::{OVERLAY_DISK_FILENAME, STORAGE_DISK_FILENAME};
use crate::Error;
use sha2::{Digest, Sha256};
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::format::{PackManifest, PackMode};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Options for a from-VM export.
#[derive(Debug, Default, Clone)]
pub struct FromVmExportOptions {
    /// HTTP(S) proxy for the in-VM registry pull (registry-image machines).
    pub proxy: Option<String>,
    /// NO_PROXY for the in-VM registry pull.
    pub no_proxy: Option<String>,
    /// Rebuild base layers from `vm.image` (re-pull from the registry)
    /// instead of preserving the machine's cached or imported layers.
    pub rebase_from_image: bool,
    /// Also capture the machine's `/workspace` so a machine made from the pack
    /// starts with those files. It lives on the storage disk, which container
    /// packs otherwise never carry, so without this a pack silently loses it.
    pub include_workspace: bool,
}

/// What the export decided about the machine, for the caller's manifest.
#[derive(Debug, Clone)]
pub struct FromVmAssets {
    /// `Container` for image-based machines, `Vm` for bare machines.
    pub mode: PackMode,
    /// The machine's image reference (image-based machines only).
    pub image: Option<String>,
    /// The image's OCI `ENV`, as `KEY=VALUE`.
    ///
    /// A running machine gets these because the agent reads the image config at
    /// exec time, but flattening the layers leaves the pack with no image config
    /// to read — so they have to travel in the manifest instead, or the packed
    /// machine loses the image's `PATH` and every other declared variable.
    ///
    /// Empty for a bare machine, and for a machine created from a `.smolmachine`:
    /// that path already copied the source manifest's env into the record, so the
    /// machine's own env is the complete set.
    pub image_env: Vec<String>,
    /// The image's OCI `USER`, for the same reason as `image_env`: a running
    /// machine takes it from the image config at exec time, and a pack has no
    /// image config left, so the manifest has to carry who the workload runs
    /// as when the machine itself named nobody.
    pub image_user: Option<String>,
    /// Total bytes of the layer tars collected for this pack.
    ///
    /// Recorded as the manifest's `image_size` so the run-time storage
    /// auto-sizer reserves room for them; without it a from-vm pack falls back
    /// to the minimal default disk, which cannot hold the layers when the
    /// guest has to unpack staged tars onto it.
    pub layer_bytes: u64,
}

/// The persistent overlay a machine's rootfs writes live in. A branched or
/// checkpoint-restored machine keeps its source's overlay rather than getting
/// one named after itself, so the directory is a property of lineage, not of
/// the machine's current name. Every other reader resolves it this way; export
/// must too, or a restored machine flattens an empty overlay and silently
/// loses every rootfs change made through exec.
pub fn export_overlay_owner(vm_name: &str, vm: &VmRecord) -> String {
    crate::workload::persistent_overlay_owner_with_lineage(
        vm_name,
        vm.golden.as_deref(),
        vm.fork_overlay_owner.as_deref(),
    )
}

/// Collect a stopped machine's pack assets into `collector` and report the
/// pack mode. The caller has already: loaded the record, verified the machine
/// is stopped, and collected its base assets (runtime libs, agent rootfs,
/// templates). `staging_dir` hosts temporary extractions and must live until
/// the pack is finalized.
pub fn collect_from_vm_assets(
    collector: &mut AssetCollector,
    vm_name: &str,
    vm: &VmRecord,
    staging_dir: &Path,
    opts: &FromVmExportOptions,
) -> crate::Result<FromVmAssets> {
    let overlay_owner = export_overlay_owner(vm_name, vm);

    let vm_dir = vm_data_dir(vm_name);
    let (overlay_disk, overlay_fmt) = resolve_disk_image(&vm_dir, OVERLAY_DISK_FILENAME);
    let (storage_disk, storage_fmt) = resolve_disk_image(&vm_dir, STORAGE_DISK_FILENAME);
    let is_image_based = vm.image.is_some();
    let is_artifact_sourced = is_image_based && vm.source_smolmachine.is_some();

    if !is_image_based && !overlay_disk.exists() {
        return Err(Error::agent(
            "pack from VM",
            format!(
                "overlay disk not found at {}. The VM may not have been started yet.",
                overlay_disk.display()
            ),
        ));
    }

    // Only the registry path can report the image's declared env: an artifact
    // machine already carries the source manifest's env in its own record, and a
    // bare machine has no image at all.
    let mut image_env: Vec<String> = Vec::new();
    let mut image_user: Option<String> = None;

    if is_artifact_sourced && !opts.rebase_from_image {
        export_flattened_from_artifact_sourced(
            collector,
            vm_name,
            &overlay_owner,
            &vm_dir,
            staging_dir,
            vm.source_smolmachine.as_deref(),
            opts.include_workspace,
        )?;
    } else if is_image_based {
        let image = vm.image.clone().unwrap();
        // A locally-sourced image (`--image -` / `--image file.tar` / a rootfs
        // dir) is flattened on boot and has no registry manifest, so the
        // in-VM re-pull below cannot source it. Fail with a clear, actionable
        // message instead of a confusing registry "UNAUTHORIZED" on
        // `local:<hash>`.
        if crate::data::image_source::is_local_ref(&image) {
            // No registry manifest to re-pull, but the base rootfs is still
            // reachable: an archive was flattened onto the machine's own storage
            // disk at boot, and a rootfs dir is still the host directory the
            // machine boots from. Either can be the lower layer.
            export_flattened_from_local_image(
                collector,
                vm_name,
                &overlay_owner,
                &vm_dir,
                &image,
                opts.include_workspace,
            )?;
        } else {
            (image_env, image_user) = export_flattened_from_registry_image(
                collector,
                vm_name,
                &overlay_owner,
                &vm_dir,
                &image,
                opts,
            )?;
        }
    } else {
        // Bare VM: its state is the rootfs overlay disk. VM-mode restores boot
        // from the template; a default-size overlay is a qcow2 CoW image and
        // must be flattened to a raw before it can be a template.
        let overlay_for_pack = match overlay_fmt {
            DiskFormat::Raw => overlay_disk.clone(),
            DiskFormat::Qcow2 => {
                let flat = staging_dir.join("overlay-flat.raw");
                flatten_qcow2_to_raw(&overlay_disk, &flat)?;
                flat
            }
        };
        println!("Copying overlay disk ({})...", overlay_for_pack.display());
        collector
            .add_overlay_template(&overlay_for_pack)
            .map_err(|e| Error::agent("collect overlay", e.to_string()))?;

        if !storage_disk.exists() {
            return Err(Error::agent(
                "collect storage",
                format!("storage disk not found at {}", storage_disk.display()),
            ));
        }
        let storage_for_pack = match storage_fmt {
            DiskFormat::Raw => storage_disk.clone(),
            DiskFormat::Qcow2 => {
                let flat = staging_dir.join("storage-flat.raw");
                flatten_qcow2_to_raw(&storage_disk, &flat)?;
                flat
            }
        };
        println!("Copying storage disk ({})...", storage_for_pack.display());
        collector
            .add_vm_storage_template(&storage_for_pack)
            .map_err(|e| Error::agent("collect storage", e.to_string()))?;
    }

    Ok(FromVmAssets {
        mode: if is_image_based {
            PackMode::Container
        } else {
            PackMode::Vm
        },
        image: vm.image.clone(),
        image_env,
        image_user,
        layer_bytes: collector.staged_layer_bytes(),
    })
}

/// Seed a pack manifest with the source machine's runtime identity. CLI /
/// Smolfile overrides layer on top of this baseline at the call site.
pub fn seed_manifest_from_vm(manifest: &mut PackManifest, vm: &VmRecord, assets: &FromVmAssets) {
    manifest.mode = assets.mode.clone();
    // Without this the run-time storage auto-sizer sees a legacy manifest and
    // creates the minimal default disk — too small to hold the layers when the
    // guest unpacks staged tars onto it.
    manifest.image_size = assets.layer_bytes;
    if let Some(ref image) = assets.image {
        manifest.image = image.clone();
    }
    manifest.network = vm.network;
    manifest.gpu = vm.gpu.unwrap_or(false);
    manifest.cuda = vm.cuda;
    // Carry the record's (entrypoint, cmd) through as-is. An empty entrypoint
    // is meaningful: a machine created with trailing args stores them as `cmd`
    // with no entrypoint, and an image machine with neither lets the agent use
    // the image's own ENTRYPOINT+CMD. Synthesising `/bin/sh` here turned the
    // former into `/bin/sh sh -c ...` (a shell trying to run a script named
    // `sh`) and the latter into a bare shell instead of the image's service.
    manifest.entrypoint = vm.entrypoint.clone();
    manifest.cmd = vm.cmd.clone();
    manifest.env = merge_env(&assets.image_env, &vm.env);
    manifest.workdir = vm.workdir.clone();
    // The account the workload runs as, resolved the way a running machine
    // resolves it: the machine's own user wins, else the image's USER.
    manifest.user = vm.user.clone().or_else(|| assets.image_user.clone());
    manifest.secret_refs = vm.secret_refs.clone();
}

/// Layer a machine's own env over the image's declared env, as `KEY=VALUE`.
///
/// This is the order a running machine resolves: the agent applies the image
/// config first, then whatever the machine was created with. Packing has to
/// reproduce it, because flattening the layers leaves no image config for the
/// packed machine to read — the image's `PATH` in particular only survives if it
/// travels in the manifest.
fn merge_env(image_env: &[String], vm_env: &[(String, String)]) -> Vec<String> {
    let mut merged = image_env.to_vec();
    for (key, value) in vm_env {
        merged.retain(|entry| {
            entry
                .split_once('=')
                .map(|(existing, _)| existing != key)
                .unwrap_or(true)
        });
        merged.push(format!("{key}={value}"));
    }
    merged
}

/// Floor for the export helper's storage disk, in GiB.
///
/// The helper extracts the source image's layers onto its OWN disk and then
/// flattens them with the machine's overlay, so it needs room for several
/// copies of the source's content — not the one-size-fits-all default a fresh
/// machine gets.
const EXPORT_HELPER_MIN_STORAGE_GIB: u64 = 64;

/// How many times the source's own storage the helper is given, to cover the
/// extracted layers plus the flattened output built alongside them.
const EXPORT_HELPER_STORAGE_FACTOR: u64 = 3;

/// Overrides the helper's storage disk, in GiB, for an export the heuristic
/// below sizes too small. The disk is sparse, so a generous value costs
/// nothing on the host until it is written.
const EXPORT_HELPER_STORAGE_ENV: &str = "SMOLVM_EXPORT_HELPER_STORAGE_GIB";

/// Overrides the helper's memory, in MiB.
const EXPORT_HELPER_MEMORY_ENV: &str = "SMOLVM_EXPORT_HELPER_MEMORY_MIB";

/// What the helper asks for when the host has the memory to spare. Flattening
/// streams its output to the host rather than buffering it, so this is page
/// cache and mount bookkeeping, not a working set — and a helper that asks for
/// more than a laptop or CI runner can seat fails the export outright, which
/// is worse than running it with a smaller page cache.
const EXPORT_HELPER_MEMORY_MIB: u64 = 4096;

/// Floor for the helper's memory: below this the guest cannot mount the
/// overlay and tar the merged tree.
const EXPORT_HELPER_MIN_MEMORY_MIB: u64 = 1024;

/// How large the export helper's storage disk should be.
///
/// The helper holds the image's layers plus the flattened output, so the size
/// has to follow the image, not the one-size-fits-all default a fresh machine
/// gets. Neither input alone describes it: a machine that pulled its image
/// carries it on its own disk (`source_apparent_gib`), while one created from
/// an artifact carries it in the host layer directory the helper mounts
/// (`packed_layers_gib`) and can have a small disk of its own. Take whichever
/// is larger, and keep a floor for machines whose disks are both small.
/// How much memory the export helper's VM should have.
///
/// A fixed 8 GiB is more than a small host has to spare, and a helper that
/// cannot be admitted fails as a bare readiness timeout naming neither the
/// memory it asked for nor a way to lower it. Ask for less than the host has
/// free instead: the helper streams its output, so a smaller VM makes an
/// export slower, not impossible.
fn export_helper_memory_mib() -> u32 {
    let mib = parse_helper_override(std::env::var(EXPORT_HELPER_MEMORY_ENV).ok().as_deref())
        .unwrap_or_else(|| helper_memory_for(host_available_memory_mib()));
    mib.try_into().unwrap_or(u32::MAX)
}

/// The policy above, separated from the host state it reads, so the whole
/// table can be asserted without a particular machine.
fn helper_memory_for(available_mib: Option<u64>) -> u64 {
    let Some(available_mib) = available_mib else {
        return EXPORT_HELPER_MEMORY_MIB;
    };
    // Leave the host at least as much as the helper takes: an export runs
    // beside whatever asked for it.
    EXPORT_HELPER_MEMORY_MIB
        .min(available_mib / 2)
        .max(EXPORT_HELPER_MIN_MEMORY_MIB)
}

/// Memory the host can spare right now, in MiB, where that can be read.
fn host_available_memory_mib() -> Option<u64> {
    crate::process::host_memory_stats().map(|stats| stats.available_bytes / (1024 * 1024))
}

fn export_helper_storage_gib(source_apparent_gib: u64, packed_layers_gib: u64) -> u64 {
    parse_helper_override(std::env::var(EXPORT_HELPER_STORAGE_ENV).ok().as_deref())
        .unwrap_or_else(|| helper_storage_for(source_apparent_gib, packed_layers_gib))
}

/// The policy above, separated from the environment it reads, so the whole
/// table can be asserted without mutating process-global state (which races
/// with every other test in the binary).
fn helper_storage_for(source_apparent_gib: u64, packed_layers_gib: u64) -> u64 {
    source_apparent_gib
        .max(packed_layers_gib)
        .saturating_mul(EXPORT_HELPER_STORAGE_FACTOR)
        .max(EXPORT_HELPER_MIN_STORAGE_GIB)
}

/// A usable [`EXPORT_HELPER_STORAGE_ENV`] value. Anything unparsable or zero
/// is ignored rather than failing the export: the heuristic still produces a
/// working disk, and refusing to run would be a worse answer than a typo.
fn parse_helper_override(value: Option<&str>) -> Option<u64> {
    value?.trim().parse::<u64>().ok().filter(|gib| *gib > 0)
}

/// Apparent bytes held under `dir`, used to size the helper for an
/// artifact-sourced machine whose image lives here rather than on its disk.
/// Unreadable entries are skipped: this only feeds a disk-size heuristic.
fn directory_apparent_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => directory_apparent_bytes(&entry.path()),
            Ok(kind) if kind.is_file() => entry.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// A helper VM used to read the source machine's disks and flatten layers.
/// Stops the VM and removes its scratch data dir on drop.
struct ExportVm {
    manager: AgentManager,
    data_dir: PathBuf,
    /// Size of the disk the helper writes the image and flattened output to,
    /// so a failure that fills it can say so.
    storage_gib: u64,
}

impl ExportVm {
    /// Boot a scratch agent VM with a private COW view of the source storage
    /// as `/dev/vdc`, plus (optionally) a host layer dir shared as
    /// `/packed_layers`.
    fn start(
        vm_name: &str,
        source_vm_dir: &Path,
        packed_layers_dir: Option<PathBuf>,
        network: bool,
    ) -> crate::Result<Self> {
        let (storage_disk, storage_fmt) = resolve_disk_image(source_vm_dir, STORAGE_DISK_FILENAME);
        // A machine that has never been started has no disks yet — attaching
        // the nonexistent image would boot the helper into a cryptic libkrun
        // EINVAL. Fail with the actionable story instead.
        if !storage_disk.exists() {
            return Err(Error::agent(
                "pack from VM",
                format!(
                    "machine '{vm_name}' has no storage disk yet ({}) — it has \
                     never been started. Start it once so its state exists, or \
                     pack the image directly with `pack create -I <image>`.",
                    storage_disk.display()
                ),
            ));
        }
        // Before allocating another full-size scratch disk, take back the space
        // any abandoned one is still holding.
        reap_stale_export_scratch();

        let scratch_name = format!(
            "pack-fromvm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let data_dir = vm_data_dir(&scratch_name);

        // Size the helper's disk from the source rather than taking the default
        // a fresh machine gets: a large export filled that fixed disk mid-pull
        // and the agent died, surfacing as a bare "connection closed" with
        // nothing naming the disk. These disks are sparse, so a generous
        // virtual size costs nothing on the host until it is actually written.
        let source_apparent_gib = disk_virtual_size(&storage_disk, storage_fmt)
            .map(|bytes| bytes.div_ceil(1024 * 1024 * 1024))
            .unwrap_or(0);
        let packed_layers_gib = packed_layers_dir
            .as_deref()
            .map(|dir| directory_apparent_bytes(dir).div_ceil(1024 * 1024 * 1024))
            .unwrap_or(0);
        let helper_storage_gib = export_helper_storage_gib(source_apparent_gib, packed_layers_gib);
        tracing::debug!(
            source_apparent_gib,
            packed_layers_gib,
            helper_storage_gib,
            "sizing the export helper's disk"
        );

        println!("Starting agent VM to export machine state...");
        // Both halves matter: this call creates the backing disk, the
        // `VmResources` below tells the guest how large it is.
        let manager =
            AgentManager::for_vm_with_sizes(&scratch_name, Some(helper_storage_gib), None)?;
        std::fs::write(data_dir.join(EXPORT_SCRATCH_MARKER), &scratch_name)?;
        // Mounting ext4 can replay its journal and update metadata. Keep those
        // writes in scratch storage, never in the stopped machine's disk.
        let source_view = data_dir.join("export-source.qcow2");
        if let Err(error) =
            crate::agent::create_disk_overlays(&[(source_view.clone(), storage_disk, storage_fmt)])
        {
            let _ = std::fs::remove_dir_all(&data_dir);
            return Err(error);
        }
        let features = LaunchFeatures {
            extra_disks: vec![(source_view, false, DiskFormat::Qcow2)],
            packed_layers_dir,
            // Under per-VM uid isolation the source VM's dir is 0700/its-own-uid;
            // this helper's whole job is reading that VM's disks, so run it as
            // the source's uid (a fresh sibling uid can't open the disk and the
            // boot dies configuring virtio-blk).
            uid_share_dir: Some(source_vm_dir.to_path_buf()),
            ..Default::default()
        };
        #[cfg(target_os = "linux")]
        let features = match prepare_export_layer_mount(features, source_vm_dir, &data_dir) {
            Ok(features) => features,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&data_dir);
                return Err(error);
            }
        };
        let helper_memory_mib = export_helper_memory_mib();
        if let Err(e) = manager.start_with_full_config(
            Vec::new(),
            Vec::new(),
            VmResources {
                cpus: 4,
                memory_mib: helper_memory_mib,
                network,
                network_backend: None,
                dns: None,
                gpu: false,
                cuda: false,
                gpu_vram_mib: None,
                nested_virt: false,
                rosetta: false,
                storage_gib: Some(helper_storage_gib),
                overlay_gib: None,
                block_io: Default::default(),
                disks: Vec::new(),
                allowed_cidrs: None,
                network_name: None,
            },
            features,
        ) {
            // The Drop cleanup only arms once Self exists — a failed boot must
            // clean its own scratch dir or every failed export leaks one.
            let _ = std::fs::remove_dir_all(&data_dir);
            // A host that cannot seat the helper reports only that the agent
            // never became ready, which names neither what was asked for nor
            // the knobs that lower it.
            return Err(Error::agent(
                "pack from VM",
                format!(
                    "{e}. The export helper asked for {} MiB of memory and a {} GiB disk. If this host cannot seat that, set {}=<MiB> and/or {}=<GiB> and retry.",
                    helper_memory_mib,
                    helper_storage_gib,
                    EXPORT_HELPER_MEMORY_ENV,
                    EXPORT_HELPER_STORAGE_ENV,
                ),
            ));
        }
        Ok(Self {
            manager,
            data_dir,
            storage_gib: helper_storage_gib,
        })
    }

    fn connect(&self) -> crate::Result<AgentClient> {
        self.manager.connect()
    }

    /// Name the disk that filled. The guest reports a full disk as a writeback
    /// EIO, which on its own says neither which disk ran out nor how to give
    /// the helper a bigger one — the export's user has no way to see either.
    fn explain_storage_exhaustion(&self, error: crate::Error) -> crate::Error {
        let message = error.to_string();
        if !message.contains("out of space") && !message.contains("No space left") {
            return error;
        }
        Error::agent(
            "pack from VM",
            format!(
                "{message}. The export helper's {} GiB disk filled while it held the image. Set {}=<GiB> to give it a larger one; the disk is sparse, so a generous                  value costs nothing on the host until it is written.",
                self.storage_gib, EXPORT_HELPER_STORAGE_ENV
            ),
        )
    }

    /// Mount the source machine's storage disk at `/mnt/source-storage`.
    fn mount_source_storage(&self, client: &mut AgentClient) -> crate::Result<()> {
        let (exit_code, _, stderr) = client.vm_exec(
            vec!["sh".to_string(), "-c".to_string(), source_mount_command()],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "mount source storage in temp VM",
                format!(
                    "mount failed (exit {}): {}{}",
                    exit_code,
                    String::from_utf8_lossy(&stderr),
                    self.describe_source_device(client),
                ),
            ));
        }
        Ok(())
    }

    /// What the helper actually sees, appended to a mount failure.
    ///
    /// The source disk is attached at a fixed device name, so `mount` failing
    /// says nothing about which of the possible causes it was: no device, the
    /// wrong device, a device with no filesystem on it, or a host that ran out
    /// of room to back it. Reporting the block devices, their sizes, whether an
    /// ext4 superblock is actually present, and the helper's free space means
    /// the next occurrence arrives already diagnosed instead of needing the
    /// machine that produced it.
    fn describe_source_device(&self, client: &mut AgentClient) -> String {
        // ext4 writes magic 0xEF53 little-endian at byte 1080 (superblock at
        // 1024, magic at offset 56), so those two bytes separate "not a
        // filesystem" from "a filesystem this kernel would not mount".
        let probe = format!(
            "echo '- block devices:'; ls -l /dev/vd* 2>&1; \
             echo '- sizes (512-byte sectors):'; \
             for d in /sys/block/vd*; do echo \"  $(basename \"$d\") $(cat \"$d/size\" 2>/dev/null)\"; done; \
             echo '- blkid {dev}:'; blkid {dev} 2>&1; \
             echo '- ext4 magic at byte 1080 (expect ef53):'; \
             dd if={dev} bs=1 skip=1080 count=2 2>/dev/null | od -An -tx1 2>&1; \
             echo '- helper free space:'; df -h /storage 2>&1",
            dev = SOURCE_DISK_DEVICE
        );
        match client.vm_exec(
            vec!["sh".to_string(), "-c".to_string(), probe],
            vec![],
            None,
            None,
            None,
        ) {
            Ok((_, stdout, _)) => {
                let seen = String::from_utf8_lossy(&stdout);
                let seen = seen.trim_end();
                if seen.is_empty() {
                    String::new()
                } else {
                    format!("\n\nWhat the export helper sees:\n{seen}")
                }
            }
            // The probe is a courtesy; its own failure must not replace the
            // mount error the caller came here for.
            Err(_) => String::new(),
        }
    }
}

#[cfg(target_os = "linux")]
fn prepare_export_layer_mount(
    mut features: LaunchFeatures,
    source_vm_dir: &Path,
    helper_dir: &Path,
) -> crate::Result<LaunchFeatures> {
    let source_layers = source_vm_dir.join("pack");
    if read_shared_pack_pointer(&source_layers).as_ref() == features.packed_layers_dir.as_ref()
        && features.packed_layers_dir.is_some()
    {
        let helper_layers = helper_dir.join("pack");
        let lease = crate::artifact_cache::copy_shared_pack_lease(&source_layers, &helper_layers)
            .map_err(|error| Error::agent("lease export layers", error.to_string()))?
            .ok_or_else(|| Error::agent("lease export layers", "source lease disappeared"))?;
        // The helper drops to the source UID; root-owned shared layers must
        // reach it through an idmapped mount, not the private cache path.
        features.packed_layers_dir = Some(helper_layers);
        features.pack_idmap_source = Some(lease.shared_dir);
    }
    Ok(features)
}

#[cfg(all(test, target_os = "linux"))]
mod export_layer_mount_tests {
    use super::*;

    #[test]
    fn private_layers_keep_their_existing_mount() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let layers = source.join("local-layers");
        std::fs::create_dir_all(&layers).unwrap();
        let features = LaunchFeatures {
            packed_layers_dir: Some(layers.clone()),
            ..Default::default()
        };
        let features =
            prepare_export_layer_mount(features, &source, &root.path().join("helper")).unwrap();
        assert_eq!(features.packed_layers_dir, Some(layers));
        assert!(features.pack_idmap_source.is_none());
    }

    #[test]
    fn export_without_layers_does_not_acquire_a_pack_mount() {
        let root = tempfile::tempdir().unwrap();
        let features = prepare_export_layer_mount(
            LaunchFeatures::default(),
            &root.path().join("source"),
            &root.path().join("helper"),
        )
        .unwrap();
        assert!(features.packed_layers_dir.is_none());
        assert!(features.pack_idmap_source.is_none());
    }
}

/// The shell the helper runs to mount the source machine's storage read-only.
///
/// Built here rather than inline so a test can assert the command is
/// well-formed: it is the first thing every export runs, so a malformed one
/// fails every export rather than an unusual one.
fn source_mount_command() -> String {
    format!("mkdir -p {SOURCE_MOUNTPOINT} && mount -o ro {SOURCE_DISK_DEVICE} {SOURCE_MOUNTPOINT}")
}

/// Where the source machine's storage disk is mounted inside the helper.
const SOURCE_MOUNTPOINT: &str = "/mnt/source-storage";

/// Guest device the source machine's storage disk is attached at.
///
/// The helper is launched with its own storage and overlay disks first, so the
/// single extra disk lands third.
const SOURCE_DISK_DEVICE: &str = "/dev/vdc";

/// The virtual size of a disk image, whatever its on-disk format.
///
/// A raw disk's apparent length *is* its virtual size, but a qcow2's is the size
/// of the container: a fresh copy-on-write overlay is a few hundred KiB however
/// large the disk it presents. Measuring a clone's disk with plain file length
/// therefore hands the export helper the minimum size instead of room for the
/// filesystem it is about to read, which is its own way of running out of space.
fn disk_virtual_size(path: &Path, format: DiskFormat) -> Option<u64> {
    match format {
        DiskFormat::Raw => std::fs::metadata(path).ok().map(|m| m.len()),
        DiskFormat::Qcow2 => read_qcow2_virtual_size(path).ok(),
    }
}

/// Remove scratch directories left behind by export helpers that are gone.
///
/// A helper that outlives its shutdown deadline keeps its disks so they can be
/// cleaned up by hand, but nothing ever came back for them. Each one is as large
/// as the export that failed, so a few failed exports in a row is enough to take
/// a host's free space with them — and the next export then fails for lack of
/// space rather than for its own reason. Creator death alone is insufficient:
/// the helper can outlive its creator and still have these disks open.
fn reap_stale_export_scratch() {
    reap_stale_export_scratch_in(&crate::agent::vm_cache_root());
}

const EXPORT_SCRATCH_MARKER: &str = ".export-scratch";

#[cfg(unix)]
fn process_definitely_gone(pid: crate::process::Pid) -> bool {
    pid > 0
        && unsafe { libc::kill(pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(unix)]
fn reap_stale_export_scratch_in(root: &Path) {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let dir = entry.path();
        let Ok(name) = std::fs::read_to_string(dir.join("name")) else {
            continue;
        };
        let Some(pid) = name
            .trim_end()
            .strip_prefix("pack-fromvm-")
            .and_then(|rest| rest.split('-').next())
            .and_then(|pid| pid.parse::<crate::process::Pid>().ok())
        else {
            continue;
        };
        // Names alone do not identify internal scratch: users can choose the
        // same prefix. Old, unmarked directories require manual cleanup.
        if std::fs::read_to_string(dir.join(EXPORT_SCRATCH_MARKER))
            .ok()
            .as_deref()
            != Some(name.trim_end())
            || !process_definitely_gone(pid)
        {
            continue;
        }
        let Ok(lock) = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join("vm.lock"))
        else {
            continue;
        };
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            continue;
        }
        // The launch lock belongs to the creator, not the helper. Check the
        // recorded helper too, under the lock, and retain ambiguous state.
        let helper_pid = std::fs::read_to_string(dir.join("agent.pid"))
            .ok()
            .and_then(|text| text.lines().next()?.trim().parse().ok());
        if !helper_pid.is_some_and(process_definitely_gone) {
            continue;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => tracing::debug!(
                path = %dir.display(), pid,
                "reclaimed an abandoned export helper's scratch disks"
            ),
            Err(error) => tracing::debug!(
                path = %dir.display(), %error,
                "could not reclaim an abandoned export helper's scratch disks"
            ),
        }
    }
}

// Retain scratch until equivalent nonblocking launch-lock checks are available.
#[cfg(not(unix))]
fn reap_stale_export_scratch_in(_root: &Path) {}

impl Drop for ExportVm {
    fn drop(&mut self) {
        // Only scratch disks are writable, and the exported bytes are already
        // on the host. Flushing this disposable filesystem before deleting it
        // can exceed the shutdown deadline after a large export.
        self.manager
            .kill_and_wait(std::time::Duration::from_secs(5));
        if self.manager.is_process_alive() {
            warn!(path = %self.data_dir.display(), "export helper still alive; retaining scratch disks for cleanup");
            return;
        }
        self.manager.detach();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Export the cached base image and persistent overlay without resolving tags
/// again. Only an explicit rebase may replace the base from the registry.
fn export_flattened_from_registry_image(
    collector: &mut AssetCollector,
    vm_name: &str,
    overlay_owner: &str,
    vm_dir: &Path,
    image: &str,
    opts: &FromVmExportOptions,
) -> crate::Result<(Vec<String>, Option<String>)> {
    let export_vm = ExportVm::start(vm_name, vm_dir, None, opts.rebase_from_image)?;
    let mut client = export_vm.connect()?;
    export_vm.mount_source_storage(&mut client)?;

    let image_info = if opts.rebase_from_image {
        eprintln!("Pulling {} in export VM...", image);
        client
            .pull_with_registry_config_and_progress(
                image,
                None,
                opts.proxy.as_deref(),
                opts.no_proxy.as_deref(),
                |_, _, _| {},
            )
            .map_err(|error| export_vm.explain_storage_exhaustion(error))?
    } else {
        cached_export_image(&mut client, vm_name, image)?
    };

    // Lower dirs in the helper's store, bottom -> top in manifest order.
    let lowers: Vec<String> = image_info
        .layers
        .iter()
        .map(|d| {
            let id = d.strip_prefix("sha256:").unwrap_or(d);
            format!("/storage/layers/{}", id)
        })
        .collect();

    flatten_and_export(
        collector,
        &mut client,
        overlay_owner,
        &lowers,
        opts.include_workspace,
    )?;
    Ok((image_info.env, image_info.user))
}

fn cached_export_image(
    client: &mut AgentClient,
    vm_name: &str,
    image: &str,
) -> crate::Result<smolvm_protocol::ImageInfo> {
    // The source view is mounted read-only; the helper keeps separate writable
    // storage for the flattened tar. Query validates config and layer markers.
    let (code, _, stderr) = client.vm_exec(
        vec![
            "sh".into(),
            "-ec".into(),
            "for dir in layers configs manifests; do mount --bind /mnt/source-storage/$dir /storage/$dir; done".into(),
        ],
        vec![], None, None, None,
    )?;
    if code != 0 {
        return Err(Error::agent(
            "mount cached image",
            String::from_utf8_lossy(&stderr),
        ));
    }
    println!("Reusing the machine's cached image layers...");
    client.query(image)?.ok_or_else(|| Error::agent(
        "export cached image",
        format!("machine '{vm_name}' has no complete cached image for '{image}'; restore its image cache before exporting, or explicitly rebase from the registry"),
    ))
}

#[cfg(test)]
mod cached_export_tests {
    use super::*;
    use crate::platform::uds::UdsStream;
    use smolvm_protocol::{encode_message, AgentRequest, AgentResponse, Envelope};
    use std::io::{Read, Write};

    fn exercise(
        mount_code: i32,
        response: AgentResponse,
    ) -> crate::Result<smolvm_protocol::ImageInfo> {
        let (stream, mut peer) = UdsStream::pair().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let server = std::thread::spawn(move || {
            let mut receive = || {
                let mut header = [0; 4];
                peer.read_exact(&mut header).unwrap();
                let mut body = vec![0; u32::from_be_bytes(header) as usize];
                peer.read_exact(&mut body).unwrap();
                serde_json::from_slice::<Envelope<AgentRequest>>(&body)
                    .unwrap()
                    .body
            };
            match receive() {
                AgentRequest::VmExec { command, .. } => {
                    assert_eq!(command[0..2], ["sh", "-ec"]);
                    assert!(
                        command[2].contains("mount --bind /mnt/source-storage/$dir /storage/$dir")
                    );
                }
                request => panic!("expected cache mounts, got {request:?}"),
            }
            peer.write_all(
                &encode_message(&AgentResponse::Completed {
                    exit_code: mount_code,
                    stdout: vec![],
                    stderr: b"mount failed".to_vec(),
                })
                .unwrap(),
            )
            .unwrap();
            if mount_code == 0 {
                let mut header = [0; 4];
                peer.read_exact(&mut header).unwrap();
                let mut body = vec![0; u32::from_be_bytes(header) as usize];
                peer.read_exact(&mut body).unwrap();
                match serde_json::from_slice::<Envelope<AgentRequest>>(&body)
                    .unwrap()
                    .body
                {
                    AgentRequest::Query { image } => assert_eq!(image, "example:mutable"),
                    request => panic!("must query the cache, not pull: {request:?}"),
                }
                peer.write_all(&encode_message(&response).unwrap()).unwrap();
            }
            let mut byte = [0];
            assert_eq!(
                peer.read(&mut byte).unwrap(),
                0,
                "unexpected fallback request"
            );
        });
        let mut client = AgentClient::from_stream(stream);
        let result = cached_export_image(&mut client, "source", "example:mutable");
        drop(client);
        server.join().unwrap();
        result
    }

    #[test]
    fn cached_export_preserves_layer_order_and_image_identity() {
        let info = exercise(0, AgentResponse::Ok { data: Some(serde_json::json!({
            "reference": "example:mutable", "digest": "sha256:original", "size": 123,
            "created": null, "architecture": "amd64", "os": "linux", "layer_count": 2,
            "layers": ["sha256:bottom", "sha256:top"], "env": ["ORIGINAL=yes"], "user": "1001",
        })) }).unwrap();
        assert_eq!(info.digest, "sha256:original");
        assert_eq!(info.layers, ["sha256:bottom", "sha256:top"]);
        assert_eq!(info.env, ["ORIGINAL=yes"]);
        assert_eq!(info.user.as_deref(), Some("1001"));
    }

    #[test]
    fn missing_cached_image_does_not_fall_back_to_registry() {
        let error = exercise(
            0,
            AgentResponse::Error {
                message: "not found".into(),
                code: Some("NOT_FOUND".into()),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("no complete cached image"));
    }

    #[test]
    fn invalid_cached_image_does_not_fall_back_to_registry() {
        let error = exercise(
            0,
            AgentResponse::Error {
                message: "invalid config".into(),
                code: None,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid config"));
    }

    #[test]
    fn cache_mount_failure_stops_export() {
        let error = exercise(1, AgentResponse::Ok { data: None }).unwrap_err();
        assert!(error.to_string().contains("mount failed"));
    }
}

/// Artifact-sourced machine: its extracted layer dirs live in the host-side
/// machine layers cache; share them into the helper VM, stage them onto its
/// local disk (overlayfs cannot use virtiofs-backed lowers), and flatten with
/// the current container overlay.
/// Export a machine created from a local image (`--image ./x.tar`, `--image -`,
/// or `--image ./rootfs/`).
///
/// There is no registry manifest to re-pull, but the base rootfs is still
/// available in one of two places depending on how it was supplied:
///
/// - **archive** (`local:<hash>`): flattened onto the machine's own storage disk
///   at boot, under `image-archives/<key>/0000_rootfs`. The helper already
///   mounts that disk read-only, so the layer is read straight from it.
/// - **rootfs dir** (`local-dir:<path>`): never copied into the machine at all —
///   the guest boots from the host directory over virtiofs, so the export shares
///   that same directory into the helper.
///
/// Either way the machine's persistent container overlay goes on top, exactly as
/// the registry and artifact paths do, so the packed result is the machine as it
/// actually is rather than as it was first created.
fn export_flattened_from_local_image(
    collector: &mut AssetCollector,
    vm_name: &str,
    overlay_owner: &str,
    vm_dir: &Path,
    image: &str,
    include_workspace: bool,
) -> crate::Result<()> {
    let host_dir = crate::data::image_source::packed_layers_dir_for_ref(image);
    let is_dir_source = image.starts_with("local-dir:");

    // A rootfs dir is the only source of its own base layer: if the host
    // directory is gone, nothing on the machine can stand in for it.
    if is_dir_source {
        match host_dir.as_deref() {
            Some(dir) if dir.is_dir() => {}
            _ => {
                return Err(Error::agent(
                    "pack from VM",
                    format!(
                        "machine '{vm_name}' was created from the rootfs directory {image}, \
                         but that directory is no longer present. The machine boots its base \
                         layer from there, so it has to exist to export. Restore it, or \
                         recreate the machine from an image that carries its own layers."
                    ),
                ));
            }
        }
    }

    let export_vm = ExportVm::start(vm_name, vm_dir, host_dir.clone(), false)?;
    let mut client = export_vm.connect()?;
    export_vm.mount_source_storage(&mut client)?;

    // An archive image's rootfs is already sitting on the source machine's
    // storage disk, which the helper has mounted read-only. overlayfs stacks that
    // directly — a lower is read-only by definition, and whiteout devices and
    // opaque-dir xattrs read back from ext4 exactly as they were written.
    //
    // A rootfs dir arrives over virtiofs instead, which overlayfs refuses as a
    // lower, so that source still has to be copied onto the helper's own disk.
    // The copy is confined to that case deliberately: it is a second full-size
    // copy of the image on a disk whose size was guessed from the source, and
    // taking it for an archive too is what runs a large export out of space.
    let lower = if is_dir_source {
        println!("Staging the machine's base layer for flatten...");
        let dst = "/storage/stage/0".to_string();
        let stage_cmd = format!(
            "mkdir -p '{dst}' && (cd '/packed_layers' && tar cf - .) | (cd '{dst}' && tar xf -)"
        );
        let (exit_code, _, stderr) = client.vm_exec(
            vec!["sh".to_string(), "-c".to_string(), stage_cmd],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "stage local base layer",
                format!(
                    "staging /packed_layers failed (exit {}): {}",
                    exit_code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        dst
    } else {
        locate_flattened_archive_rootfs(&mut client, vm_name)?
    };

    flatten_and_export(
        collector,
        &mut client,
        overlay_owner,
        &[lower],
        include_workspace,
    )
}

/// The flattened rootfs of a local *archive* image on the source machine's
/// storage disk, as a helper-local path.
///
/// The directory is keyed by a content hash the exporter does not have, so it is
/// discovered rather than computed; a machine boots exactly one local archive,
/// so a single match is expected.
fn locate_flattened_archive_rootfs(
    client: &mut AgentClient,
    vm_name: &str,
) -> crate::Result<String> {
    let (exit_code, stdout, _) = client.vm_exec(
        vec![
            "sh".to_string(),
            "-c".to_string(),
            "ls -d /mnt/source-storage/image-archives/*/0000_rootfs 2>/dev/null".to_string(),
        ],
        vec![],
        None,
        None,
        None,
    )?;
    let found: Vec<String> = String::from_utf8_lossy(&stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    match found.as_slice() {
        [one] if exit_code == 0 => Ok(one.clone()),
        [] => Err(Error::agent(
            "pack from VM",
            format!(
                "machine '{vm_name}' was created from a local image archive, but no flattened \
                 rootfs was found on its storage disk. The archive is flattened on first boot — \
                 start the machine once, then re-run the export."
            ),
        )),
        many => Err(Error::agent(
            "pack from VM",
            format!(
                "machine '{vm_name}' has {} flattened image archives on its storage disk, so \
                 the base layer is ambiguous. Recreate the machine from a single image and \
                 export that.",
                many.len()
            ),
        )),
    }
}

fn export_flattened_from_artifact_sourced(
    collector: &mut AssetCollector,
    vm_name: &str,
    overlay_owner: &str,
    vm_dir: &Path,
    _staging_dir: &Path,
    source_smolmachine: Option<&str>,
    include_workspace: bool,
) -> crate::Result<()> {
    let cache_dir = machine_layers_cache_dir(vm_name);
    let pack_content_dir = read_shared_pack_pointer(&cache_dir).unwrap_or(cache_dir.clone());
    let mut layer_ids = ordered_cached_layer_ids(&pack_content_dir);
    // Self-heal a missing or damaged layer cache from the machine's source
    // artifact (a cache cleaner can delete the layer files while leaving the
    // extraction marker, in which case a start does NOT re-extract either —
    // the old "start the machine once" advice was a dead end there). Only the
    // per-machine cache is healed here; a shared-store entry heals at boot.
    if layer_ids.is_none() && pack_content_dir == cache_dir {
        if let Some(sidecar) = source_smolmachine.map(Path::new).filter(|s| s.exists()) {
            eprintln!("Imported layer cache is missing; re-extracting from the source artifact...");
            let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar)
                .map_err(|e| Error::agent("read sidecar footer", e.to_string()))?;
            smolvm_pack::extract::extract_sidecar(sidecar, &cache_dir, &footer, true, false)
                .map_err(|e| Error::agent("re-extract source artifact", e.to_string()))?;
            layer_ids = ordered_cached_layer_ids(&pack_content_dir);
        }
    }
    let layer_ids = layer_ids.ok_or_else(|| {
        Error::agent(
            "pack from VM",
            format!(
                "VM '{vm_name}' was created from a .smolmachine artifact, but its \
                 imported layer cache is missing ({}) and could not be rebuilt: \
                 the source artifact ({}) is not available. Restore the source \
                 .smolmachine at that path, or start the machine once to \
                 re-extract, then re-run the export.",
                pack_content_dir.display(),
                source_smolmachine.unwrap_or("unknown path"),
            ),
        )
    })?;

    let export_vm = ExportVm::start(vm_name, vm_dir, Some(pack_content_dir.clone()), false)?;
    let mut client = export_vm.connect()?;
    export_vm.mount_source_storage(&mut client)?;

    // Stage each virtiofs layer dir onto the helper's local disk. A tar pipe
    // preserves overlayfs whiteout devices and opaque-dir xattrs, which a
    // later overlay mount needs intact.
    println!(
        "Staging {} imported layer(s) for flatten...",
        layer_ids.len()
    );
    let mut lowers = Vec::new();
    for (i, id) in layer_ids.iter().enumerate() {
        let src = format!("/packed_layers/{}", id);
        let dst = format!("/storage/stage/{}", i);
        // A tar-form layer extracts directly; a dir-form layer streams
        // through tar so whiteout devices and opaque-dir xattrs stay intact.
        let stage_cmd = if id.ends_with(".tar") {
            format!("mkdir -p '{dst}' && tar xf '{src}' -C '{dst}'")
        } else {
            format!("mkdir -p '{dst}' && (cd '{src}' && tar cf - .) | (cd '{dst}' && tar xf -)")
        };
        let (exit_code, _, stderr) = client.vm_exec(
            vec!["sh".to_string(), "-c".to_string(), stage_cmd],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "stage imported layer",
                format!(
                    "layer {} stage failed (exit {}): {}",
                    id,
                    exit_code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        lowers.push(dst);
    }

    flatten_and_export(
        collector,
        &mut client,
        overlay_owner,
        &lowers,
        include_workspace,
    )
}

/// The cached layers of an imported pack, bottom -> top, as paths relative to
/// the pack content dir. A layer is either an extracted dir (`layers/<id>`,
/// hosts that can reproduce archived ownership) or a staged tar
/// (`layers/<id>.tar`, hosts that leave extraction to the guest) — both forms
/// are written by the artifact import, so both must be exportable. `None`
/// when the cache (or its ordering) is gone.
fn ordered_cached_layer_ids(pack_content_dir: &Path) -> Option<Vec<String>> {
    let layers_dir = pack_content_dir.join("layers");
    let order_path = layers_dir.join("layer-order");
    let cached_form = |id: &str| -> Option<String> {
        if layers_dir.join(id).is_dir() {
            Some(format!("layers/{}", id))
        } else if layers_dir.join(format!("{id}.tar")).is_file() {
            Some(format!("layers/{}.tar", id))
        } else {
            None
        }
    };
    if let Ok(contents) = std::fs::read_to_string(&order_path) {
        let ids: Vec<&str> = contents
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        if ids.is_empty() {
            return None;
        }
        return ids.iter().map(|id| cached_form(id)).collect();
    }
    // No order file: only unambiguous for a single cached layer.
    let mut entries: Vec<String> = std::fs::read_dir(&layers_dir)
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter_map(|name| cached_form(name.strip_suffix(".tar").unwrap_or(&name)))
        .collect();
    entries.sort();
    entries.dedup();
    if entries.len() != 1 {
        return None;
    }
    Some(entries)
}

/// Overlay-mount `lowers` (bottom -> top, helper-local paths) with the source
/// machine's persistent container overlay on top, tar the merged view, and
/// register the stream as the pack's single layer. The overlay mount applies
/// whiteouts/opaque markers exactly as the runtime would, so the flattened
/// tree is byte-equivalent to what the machine's container saw.
fn flatten_and_export(
    collector: &mut AssetCollector,
    client: &mut AgentClient,
    overlay_owner: &str,
    lowers: &[String],
    include_workspace: bool,
) -> crate::Result<()> {
    if lowers.is_empty() {
        return Err(Error::agent("flatten layers", "no layers to flatten"));
    }
    // Topmost first, which is the order the agent stacks them in: the machine's
    // own writes outrank every image layer, then the image layers from top down.
    // `lowers` arrives bottom-up as the image lists them, so it has to be
    // reversed — leaving it as-is makes the base layer win every conflict.
    // The agent drops the overlay if the machine never wrote to it, so it needs
    // no probe from here.
    let upper = format!("/mnt/source-storage/overlays/persistent-{overlay_owner}/upper");
    let mut stack: Vec<String> = vec![upper];
    stack.extend(lowers.iter().rev().cloned());

    println!(
        "Flattening {} layer(s) + container overlay...",
        lowers.len()
    );
    // Driven agent-side rather than through `mount(8)` over VmExec: `mount(8)`
    // rejects a `lowerdir=` value past ~255 bytes, which any image with four or
    // more layers exceeds. The merged tree streams straight to the host — never
    // staged as an archive in the guest, never buffered whole in memory — and is
    // content-addressed on the way past. Stage in the layers dir so the final
    // rename is atomic on the same filesystem.
    let tmp_file = collector
        .layer_staging_path(&format!("sha256:{}", "0".repeat(64)))
        .with_file_name("flat-export.tmp");
    let total = client
        .flatten_layers_to_path(
            &stack,
            &tmp_file,
            crate::agent::pack_export_max_total(),
            |_| {},
        )
        .map_err(|e| Error::agent("export flattened layer", e.to_string()))?;
    if total == 0 {
        let _ = std::fs::remove_file(&tmp_file);
        return Err(Error::agent(
            "export flattened layer",
            "flattened layer tar is empty",
        ));
    }

    let mut hasher = Sha256::new();
    {
        use std::io::Read;
        let mut f = std::fs::File::open(&tmp_file)
            .map_err(|e| Error::agent("read flattened layer", e.to_string()))?;
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| Error::agent("hash flattened layer", e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    let layer_file = collector.layer_staging_path(&digest);
    std::fs::rename(&tmp_file, &layer_file)
        .map_err(|e| Error::agent("write flattened layer", e.to_string()))?;
    collector
        .register_layer(&digest)
        .map_err(|e| Error::agent("register flattened layer", e.to_string()))?;
    println!("  Flattened layer: {} bytes", total);
    if include_workspace {
        export_workspace_seed(collector, client)?;
    }
    Ok(())
}

/// Capture the source machine's `/workspace` as the pack's workspace seed.
///
/// The flattened layer above is the container's root filesystem; `/workspace`
/// is a directory on the machine's storage disk, mounted at
/// `/mnt/source-storage` in the helper, and is not part of any layer. Same
/// mechanics as the layer: the agent tars it in the guest (so ownership is
/// exactly what the machine had) and the host streams the result to disk. An
/// empty workspace records nothing.
fn export_workspace_seed(
    collector: &mut AssetCollector,
    client: &mut AgentClient,
) -> crate::Result<()> {
    const GUEST_WORKSPACE: &str = "/mnt/source-storage/workspace";
    let listing = client
        .vm_exec(
            vec![
                "sh".into(),
                "-c".into(),
                format!("find {GUEST_WORKSPACE} -mindepth 1 -print -quit 2>/dev/null"),
            ],
            vec![],
            None,
            None,
            None,
        )
        .map_err(|e| Error::agent("inspect workspace", e.to_string()))?;
    if String::from_utf8_lossy(&listing.1).trim().is_empty() {
        return Ok(());
    }
    println!("Capturing /workspace...");
    let tmp_file = collector
        .layer_staging_path(&format!("sha256:{}", "0".repeat(64)))
        .with_file_name("workspace-seed.tmp");
    let total = client
        .flatten_layers_to_path(
            &[GUEST_WORKSPACE.to_string()],
            &tmp_file,
            crate::agent::pack_export_max_total(),
            |_| {},
        )
        .map_err(|e| Error::agent("export workspace", e.to_string()))?;
    if total == 0 {
        let _ = std::fs::remove_file(&tmp_file);
        return Ok(());
    }
    collector
        .add_workspace_seed(&tmp_file)
        .map_err(|e| Error::agent("register workspace seed", e.to_string()))?;
    println!("  Workspace seed: {} bytes", total);
    Ok(())
}

/// Flatten a qcow2 CoW overlay into a standalone raw disk image (bare VMs).
///
/// There is no host-side qcow2 reader (smolvm deliberately takes no qemu-img
/// dependency), so the conversion runs inside a throwaway agent VM: the source
/// qcow2 is attached read-only (libkrun resolves its backing chain) as
/// `/dev/vdc` alongside a fresh raw output as `/dev/vdd`, and the guest `dd`s
/// one into the other.
fn flatten_qcow2_to_raw(qcow2_path: &Path, dest_raw: &Path) -> crate::Result<()> {
    let virtual_size = read_qcow2_virtual_size(qcow2_path)?;
    let dest = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dest_raw)
        .map_err(|e| Error::agent("create flat overlay", e.to_string()))?;
    dest.set_len(virtual_size)
        .map_err(|e| Error::agent("size flat overlay", e.to_string()))?;
    drop(dest);

    let scratch_name = format!(
        "pack-flatten-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let data_dir = vm_data_dir(&scratch_name);
    println!("Flattening qcow2 overlay to raw...");
    let manager = AgentManager::for_vm_with_sizes(&scratch_name, None, None)?;
    let features = LaunchFeatures {
        extra_disks: vec![
            (qcow2_path.to_path_buf(), true, DiskFormat::Qcow2),
            (dest_raw.to_path_buf(), false, DiskFormat::Raw),
        ],
        ..Default::default()
    };
    manager.start_with_full_config(
        Vec::new(),
        Vec::new(),
        VmResources {
            cpus: 2,
            memory_mib: 2048,
            network: false,
            network_backend: None,
            dns: None,
            gpu: false,
            cuda: false,
            gpu_vram_mib: None,
            nested_virt: false,
            rosetta: false,
            storage_gib: None,
            overlay_gib: None,
            block_io: Default::default(),
            disks: Vec::new(),
            allowed_cidrs: None,
            network_name: None,
        },
        features,
    )?;

    let result: crate::Result<()> = (|| {
        let mut client = manager.connect()?;
        let (exit_code, _, stderr) = client.vm_exec(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                // busybox dd lacks GNU `conv=sparse`, so do a plain full copy
                // and `sync`. The output is dense on the temp disk, but
                // `add_overlay_template` strips trailing zeros so the pack stays
                // small; the imported overlay is re-sparsified on extraction.
                "dd if=/dev/vdc of=/dev/vdd bs=1M && sync".to_string(),
            ],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "flatten overlay qcow2",
                format!(
                    "dd failed (exit {}): {}",
                    exit_code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        Ok(())
    })();

    if let Err(e) = manager.stop() {
        warn!(error = %e, "failed to stop flatten temp VM");
    }
    let _ = std::fs::remove_dir_all(&data_dir);
    result
}

/// Read a qcow2 header's virtual size (big-endian u64 at offset 24).
fn read_qcow2_virtual_size(path: &Path) -> crate::Result<u64> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| Error::agent("open qcow2", e.to_string()))?;
    let mut header = [0u8; 32];
    f.read_exact(&mut header)
        .map_err(|e| Error::agent("read qcow2 header", e.to_string()))?;
    if &header[0..4] != b"QFI\xfb" {
        return Err(Error::agent(
            "read qcow2 header",
            format!("{} is not a qcow2 image", path.display()),
        ));
    }
    Ok(u64::from_be_bytes(header[24..32].try_into().unwrap()))
}

#[cfg(test)]
mod env_merge_tests {
    use super::{merge_env, seed_manifest_from_vm, FromVmAssets};
    use crate::config::VmRecord;
    use smolvm_pack::format::{PackManifest, PackMode};

    /// The image's `PATH` is what makes its binaries resolve, so a machine that
    /// set no env of its own must still carry the image's.
    #[test]
    fn packed_user_is_the_machine_user_or_else_the_image_user() {
        let mut vm = VmRecord::new("m".to_string(), 1, 512, vec![], vec![], false);
        let mut assets = FromVmAssets {
            mode: PackMode::Container,
            image: Some("nginx".to_string()),
            image_env: vec![],
            image_user: Some("nginx".to_string()),
            layer_bytes: 0,
        };
        let mut manifest = PackManifest::new(
            "vm://m".to_string(),
            "none".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );
        seed_manifest_from_vm(&mut manifest, &vm, &assets);
        assert_eq!(manifest.user.as_deref(), Some("nginx"));

        vm.user = Some("501:20".to_string());
        seed_manifest_from_vm(&mut manifest, &vm, &assets);
        assert_eq!(manifest.user.as_deref(), Some("501:20"));

        vm.user = None;
        assets.image_user = None;
        seed_manifest_from_vm(&mut manifest, &vm, &assets);
        assert!(manifest.user.is_none());
    }

    #[test]
    fn image_env_survives_when_the_machine_adds_none() {
        let image = vec![
            "PATH=/usr/local/bin:/usr/bin:/usr/lib/postgresql/16/bin".to_string(),
            "PG_VERSION=16.14".to_string(),
        ];
        assert_eq!(merge_env(&image, &[]), image);
    }

    /// A machine created with `-e` overrides the image rather than appending a
    /// second entry for the same key, which would leave the winner to whichever
    /// end of the vector the consumer happens to read last.
    #[test]
    fn machine_env_replaces_the_image_entry_for_the_same_key() {
        let image = vec!["PATH=/usr/bin".to_string(), "LANG=C".to_string()];
        let vm = vec![
            ("PATH".to_string(), "/opt/bin".to_string()),
            ("EXTRA".to_string(), "1".to_string()),
        ];

        let merged = merge_env(&image, &vm);

        assert_eq!(
            merged,
            vec![
                "LANG=C".to_string(),
                "PATH=/opt/bin".to_string(),
                "EXTRA=1".to_string()
            ]
        );
        assert_eq!(
            merged.iter().filter(|e| e.starts_with("PATH=")).count(),
            1,
            "exactly one PATH entry"
        );
    }

    /// A bare machine has no image, so the machine's env is the whole set.
    #[test]
    fn machine_env_stands_alone_without_an_image() {
        let vm = vec![("FOO".to_string(), "bar".to_string())];
        assert_eq!(merge_env(&[], &vm), vec!["FOO=bar".to_string()]);
    }
}

#[cfg(test)]
mod from_vm_manifest_tests {
    use super::{export_overlay_owner, seed_manifest_from_vm, FromVmAssets};
    use crate::config::VmRecord;
    use smolvm_pack::{PackManifest, PackMode};

    fn record(name: &str) -> VmRecord {
        VmRecord::new(name.to_string(), 1, 512, vec![], vec![], false)
    }

    fn assets() -> FromVmAssets {
        FromVmAssets {
            mode: PackMode::Container,
            image: Some("alpine".to_string()),
            image_env: vec![],
            image_user: None,
            layer_bytes: 0,
        }
    }

    fn manifest() -> PackManifest {
        PackManifest::new(
            "vm://m".to_string(),
            "none".to_string(),
            "linux/amd64".to_string(),
            "linux/amd64".to_string(),
        )
    }

    /// A machine created with trailing args stores them as `cmd` with no
    /// entrypoint. Export used to invent `/bin/sh` for the missing entrypoint,
    /// so the pack launched `/bin/sh sh -c ...`: a shell trying to run a script
    /// named `sh`, exiting at once. The record's split must survive as-is.
    #[test]
    fn a_missing_entrypoint_is_not_replaced_with_a_shell() {
        let mut rec = record("m");
        rec.image = Some("alpine".to_string());
        rec.entrypoint = vec![];
        rec.cmd = vec!["sh".into(), "-c".into(), "run-the-workload".into()];

        let mut m = manifest();
        seed_manifest_from_vm(&mut m, &rec, &assets());

        assert!(
            m.entrypoint.is_empty(),
            "entrypoint was synthesised: {:?}",
            m.entrypoint
        );
        assert_eq!(m.cmd, rec.cmd);

        // What the runtime will actually exec: entrypoint + cmd.
        let mut launched = m.entrypoint.clone();
        launched.extend(m.cmd.clone());
        assert_eq!(launched, vec!["sh", "-c", "run-the-workload"]);
    }

    /// An image machine with neither entrypoint nor cmd relies on the agent
    /// using the image's own ENTRYPOINT+CMD; a synthesised shell would have
    /// replaced a service image's process with a bare shell.
    #[test]
    fn an_image_default_entrypoint_is_left_to_the_image() {
        let mut rec = record("m");
        rec.image = Some("nginx".to_string());

        let mut m = manifest();
        seed_manifest_from_vm(&mut m, &rec, &assets());

        assert!(m.entrypoint.is_empty() && m.cmd.is_empty());
    }

    /// A record that does carry an entrypoint keeps it verbatim.
    #[test]
    fn an_explicit_entrypoint_is_preserved() {
        let mut rec = record("m");
        rec.entrypoint = vec!["/app/server".into()];
        rec.cmd = vec!["--port".into(), "8080".into()];

        let mut m = manifest();
        seed_manifest_from_vm(&mut m, &rec, &assets());

        assert_eq!(m.entrypoint, vec!["/app/server"]);
        assert_eq!(m.cmd, vec!["--port", "8080"]);
    }

    /// A branched or checkpoint-restored machine keeps writing to its source's
    /// overlay. Export used to look up `persistent-<own-name>`, found nothing,
    /// and flattened an empty overlay, silently dropping every exec-made change.
    #[test]
    fn export_reads_the_overlay_the_machine_actually_writes_to() {
        let plain = record("orig");
        assert_eq!(export_overlay_owner("orig", &plain), "orig");

        let mut restored = record("restored");
        restored.golden = Some("orig".to_string());
        assert_eq!(
            export_overlay_owner("restored", &restored),
            "orig",
            "a restored machine's changes live in its source's overlay"
        );

        // A fork clone records its overlay owner explicitly; that wins over golden.
        let mut clone = record("clone");
        clone.golden = Some("orig".to_string());
        clone.fork_overlay_owner = Some("shared-owner".to_string());
        assert_eq!(export_overlay_owner("clone", &clone), "shared-owner");
    }
}

#[cfg(test)]
mod export_helper_sizing_tests {
    use super::{
        export_helper_storage_gib, helper_memory_for, helper_storage_for, parse_helper_override,
        EXPORT_HELPER_MEMORY_MIB, EXPORT_HELPER_MIN_MEMORY_MIB, EXPORT_HELPER_MIN_STORAGE_GIB,
    };

    #[test]
    fn a_big_machine_gets_a_helper_disk_bigger_than_itself() {
        // The export failure that prompted the sizing: a machine holding
        // ~13 GiB on a 50 GiB disk, whose helper used to get the fixed default
        // and filled up mid-pull.
        assert!(helper_storage_for(50, 0) > 50);
        assert_eq!(helper_storage_for(50, 0), 150);
        assert_eq!(helper_storage_for(100, 0), 300);
    }

    #[test]
    fn a_small_machine_still_gets_the_floor() {
        assert_eq!(helper_storage_for(0, 0), EXPORT_HELPER_MIN_STORAGE_GIB);
        assert_eq!(helper_storage_for(1, 0), EXPORT_HELPER_MIN_STORAGE_GIB);
    }

    /// A machine created from an artifact keeps its image in the host layer
    /// directory, not on its own disk, so its disk says nothing about how much
    /// the helper has to hold. Sizing from the disk alone is what left a small
    /// machine carrying a large image with a helper that could not fit it.
    #[test]
    fn a_small_machine_with_large_packed_layers_is_sized_from_the_layers() {
        assert_eq!(helper_storage_for(10, 60), 180);
        assert_eq!(helper_storage_for(60, 10), 180);
    }

    #[test]
    fn a_huge_source_does_not_overflow_the_size() {
        assert!(helper_storage_for(u64::MAX, 0) >= EXPORT_HELPER_MIN_STORAGE_GIB);
    }

    /// Memory follows the same shape as the disk: ask for the comfortable
    /// size when the host can spare it, never more than half of what is free,
    /// and never below what mounting and tarring needs. A host whose memory
    /// cannot be read keeps the old fixed size rather than guessing low.
    #[test]
    fn helper_memory_follows_what_the_host_can_spare() {
        assert_eq!(helper_memory_for(None), EXPORT_HELPER_MEMORY_MIB);
        // Plenty free: the comfortable size, not half of a huge number.
        assert_eq!(helper_memory_for(Some(64 * 1024)), EXPORT_HELPER_MEMORY_MIB);
        // The reported failure: a host that cannot seat the comfortable size.
        assert_eq!(helper_memory_for(Some(4096)), 2048);
        assert_eq!(helper_memory_for(Some(3000)), 1500);
        // Very little free still asks for something that can do the work.
        assert_eq!(helper_memory_for(Some(512)), EXPORT_HELPER_MIN_MEMORY_MIB);
        assert_eq!(helper_memory_for(Some(0)), EXPORT_HELPER_MIN_MEMORY_MIB);
    }

    #[test]
    fn only_a_usable_override_is_honored() {
        assert_eq!(parse_helper_override(Some("512")), Some(512));
        assert_eq!(parse_helper_override(Some("  512  ")), Some(512));
        // A typo or a zero falls back to the heuristic instead of failing the
        // export or booting a helper with no disk.
        assert_eq!(parse_helper_override(Some("0")), None);
        assert_eq!(parse_helper_override(Some("512G")), None);
        assert_eq!(parse_helper_override(Some("")), None);
        assert_eq!(parse_helper_override(None), None);
    }

    /// Without the variable set, the public entry point is the heuristic.
    #[test]
    fn the_default_path_is_the_heuristic() {
        if std::env::var(super::EXPORT_HELPER_STORAGE_ENV).is_ok() {
            return;
        }
        assert_eq!(export_helper_storage_gib(50, 0), helper_storage_for(50, 0));
    }
}
