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
    /// For artifact-sourced machines: rebuild base layers from `vm.image`
    /// (re-pull from the registry) instead of preserving imported layers.
    pub rebase_from_image: bool,
}

/// What the export decided about the machine, for the caller's manifest.
#[derive(Debug, Clone)]
pub struct FromVmAssets {
    /// `Container` for image-based machines, `Vm` for bare machines.
    pub mode: PackMode,
    /// The machine's image reference (image-based machines only).
    pub image: Option<String>,
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
    // A fork clone's disks are CoW qcow2 overlays that only the fork/resume
    // machinery can assemble — the export helper cold-boots them and libkrun
    // rejects the stack with an opaque -22 EINVAL (same class as clone
    // auto-standby wake). Refuse with the real story until overlay-chain boot
    // is supported.
    if let Some(ref golden) = vm.golden {
        return Err(Error::agent(
            "pack from VM",
            format!(
                "machine '{vm_name}' is a fork clone of '{golden}'; its copy-on-write \
                 disks cannot be exported directly. Export the golden instead, or \
                 recreate the state in a non-clone machine and export that."
            ),
        ));
    }

    let vm_dir = vm_data_dir(vm_name);
    let (overlay_disk, overlay_fmt) = resolve_disk_image(&vm_dir, OVERLAY_DISK_FILENAME);
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

    if is_artifact_sourced && !opts.rebase_from_image {
        export_flattened_from_artifact_sourced(collector, vm_name, &vm_dir, staging_dir)?;
    } else if is_image_based {
        let image = vm.image.clone().unwrap();
        // A locally-sourced image (`--image -` / `--image file.tar` / a rootfs
        // dir) is flattened on boot and has no registry manifest, so the
        // in-VM re-pull below cannot source it. Fail with a clear, actionable
        // message instead of a confusing registry "UNAUTHORIZED" on
        // `local:<hash>`.
        if crate::data::image_source::is_local_ref(&image) {
            return Err(Error::agent(
                "pack from VM",
                format!(
                    "VM '{vm_name}' was created from a local image ({image}). \
                     `pack create --from-vm` can only snapshot VMs created from a \
                     REGISTRY image — local archives and rootfs directories are \
                     flattened on boot and have no registry manifest to re-pull. \
                     Recreate the machine from a registry reference to pack it."
                ),
            ));
        }
        export_flattened_from_registry_image(collector, vm_name, &vm_dir, &image, opts)?;
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
    }

    Ok(FromVmAssets {
        mode: if is_image_based {
            PackMode::Container
        } else {
            PackMode::Vm
        },
        image: vm.image.clone(),
    })
}

/// Seed a pack manifest with the source machine's runtime identity. CLI /
/// Smolfile overrides layer on top of this baseline at the call site.
pub fn seed_manifest_from_vm(manifest: &mut PackManifest, vm: &VmRecord, assets: &FromVmAssets) {
    manifest.mode = assets.mode.clone();
    if let Some(ref image) = assets.image {
        manifest.image = image.clone();
    }
    manifest.network = vm.network;
    manifest.gpu = vm.gpu.unwrap_or(false);
    manifest.cuda = vm.cuda;
    manifest.entrypoint = if !vm.entrypoint.is_empty() {
        vm.entrypoint.clone()
    } else {
        vec!["/bin/sh".to_string()]
    };
    manifest.cmd = vm.cmd.clone();
    manifest.env = vm.env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
    manifest.workdir = vm.workdir.clone();
    manifest.secret_refs = vm.secret_refs.clone();
}

/// A helper VM used to read the source machine's disks and flatten layers.
/// Stops the VM and removes its scratch data dir on drop.
struct ExportVm {
    manager: AgentManager,
    data_dir: PathBuf,
}

impl ExportVm {
    /// Boot a scratch agent VM with the source machine's storage disk attached
    /// read-only as `/dev/vdc`, plus (optionally) a host layer dir shared as
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
        let scratch_name = format!(
            "pack-fromvm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let data_dir = vm_data_dir(&scratch_name);

        println!("Starting agent VM to export machine state...");
        let manager = AgentManager::for_vm(&scratch_name)?;
        let features = LaunchFeatures {
            extra_disks: vec![(storage_disk, false, storage_fmt)],
            packed_layers_dir,
            // Under per-VM uid isolation the source VM's dir is 0700/its-own-uid;
            // this helper's whole job is reading that VM's disks, so run it as
            // the source's uid (a fresh sibling uid can't open the disk and the
            // boot dies configuring virtio-blk).
            uid_share_dir: Some(source_vm_dir.to_path_buf()),
            ..Default::default()
        };
        if let Err(e) = manager.start_with_full_config(
            Vec::new(),
            Vec::new(),
            VmResources {
                cpus: 4,
                memory_mib: 8192,
                network,
                network_backend: None,
                dns: None,
                gpu: false,
                cuda: false,
                gpu_vram_mib: None,
                rosetta: false,
                storage_gib: None,
                overlay_gib: None,
                allowed_cidrs: None,
            },
            features,
        ) {
            // The Drop cleanup only arms once Self exists — a failed boot must
            // clean its own scratch dir or every failed export leaks one.
            let _ = std::fs::remove_dir_all(&data_dir);
            return Err(e);
        }
        Ok(Self { manager, data_dir })
    }

    fn connect(&self) -> crate::Result<AgentClient> {
        self.manager.connect()
    }

    /// Mount the source machine's storage disk at `/mnt/source-storage`.
    fn mount_source_storage(&self, client: &mut AgentClient) -> crate::Result<()> {
        let (exit_code, _, stderr) = client.vm_exec(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "mkdir -p /mnt/source-storage && mount /dev/vdc /mnt/source-storage".to_string(),
            ],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "mount source storage in temp VM",
                format!(
                    "mount failed (exit {}): {}",
                    exit_code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        Ok(())
    }
}

impl Drop for ExportVm {
    fn drop(&mut self) {
        if let Err(e) = self.manager.stop() {
            warn!(error = %e, "failed to stop pack temp VM");
        }
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Registry-image machine: pull the base image inside the helper VM (layers
/// extract to its local disk), then flatten base layers + the machine's
/// persistent container overlay into a single exported layer.
fn export_flattened_from_registry_image(
    collector: &mut AssetCollector,
    vm_name: &str,
    vm_dir: &Path,
    image: &str,
    opts: &FromVmExportOptions,
) -> crate::Result<()> {
    let export_vm = ExportVm::start(vm_name, vm_dir, None, true)?;
    let mut client = export_vm.connect()?;
    export_vm.mount_source_storage(&mut client)?;

    eprintln!("Pulling {} in export VM...", image);
    let image_info = client.pull_with_registry_config_and_progress(
        image,
        None,
        opts.proxy.as_deref(),
        opts.no_proxy.as_deref(),
        |_, _, _| {},
    )?;

    // Lower dirs on the helper's own disk, bottom -> top as pulled.
    let lowers: Vec<String> = image_info
        .layers
        .iter()
        .map(|d| {
            let id = d.strip_prefix("sha256:").unwrap_or(d);
            format!("/storage/layers/{}", id)
        })
        .collect();

    flatten_and_export(collector, &mut client, vm_name, &lowers)
}

/// Artifact-sourced machine: its extracted layer dirs live in the host-side
/// machine layers cache; share them into the helper VM, stage them onto its
/// local disk (overlayfs cannot use virtiofs-backed lowers), and flatten with
/// the current container overlay.
fn export_flattened_from_artifact_sourced(
    collector: &mut AssetCollector,
    vm_name: &str,
    vm_dir: &Path,
    _staging_dir: &Path,
) -> crate::Result<()> {
    let cache_dir = machine_layers_cache_dir(vm_name);
    let pack_content_dir = read_shared_pack_pointer(&cache_dir).unwrap_or(cache_dir);
    let layer_ids = ordered_cached_layer_ids(&pack_content_dir).ok_or_else(|| {
        Error::agent(
            "pack from VM",
            format!(
                "VM '{vm_name}' was created from a .smolmachine artifact, but its \
                 imported layer cache is missing ({}). Start the machine once to \
                 re-extract it, then re-run the export.",
                pack_content_dir.display()
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
        let (exit_code, _, stderr) = client.vm_exec(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!(
                    "mkdir -p '{dst}' && (cd '{src}' && tar cf - .) | (cd '{dst}' && tar xf -)"
                ),
            ],
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

    flatten_and_export(collector, &mut client, vm_name, &lowers)
}

/// The extracted layer dirs of an imported pack, bottom -> top, as short ids.
/// `None` when the cache (or its ordering) is gone.
fn ordered_cached_layer_ids(pack_content_dir: &Path) -> Option<Vec<String>> {
    let layers_dir = pack_content_dir.join("layers");
    let order_path = layers_dir.join("layer-order");
    let ids: Vec<String> = if let Ok(contents) = std::fs::read_to_string(&order_path) {
        contents
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        // No order file: only unambiguous for a single extracted layer dir.
        let mut dirs: Vec<String> = std::fs::read_dir(&layers_dir)
            .ok()?
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        if dirs.len() != 1 {
            return None;
        }
        vec![dirs.pop().unwrap()]
    };
    if ids.is_empty() || !ids.iter().all(|id| layers_dir.join(id).is_dir()) {
        return None;
    }
    Some(ids.iter().map(|id| format!("layers/{}", id)).collect())
}

/// Overlay-mount `lowers` (bottom -> top, helper-local paths) with the source
/// machine's persistent container overlay on top, tar the merged view, and
/// register the stream as the pack's single layer. The overlay mount applies
/// whiteouts/opaque markers exactly as the runtime would, so the flattened
/// tree is byte-equivalent to what the machine's container saw.
fn flatten_and_export(
    collector: &mut AssetCollector,
    client: &mut AgentClient,
    vm_name: &str,
    lowers: &[String],
) -> crate::Result<()> {
    if lowers.is_empty() {
        return Err(Error::agent("flatten layers", "no layers to flatten"));
    }
    let upper = format!("/mnt/source-storage/overlays/persistent-{}/upper", vm_name);
    // overlayfs wants topmost-first in `lowerdir=`.
    let base_chain: Vec<&str> = lowers.iter().rev().map(String::as_str).collect();
    let base_chain = base_chain.join(":");

    println!(
        "Flattening {} layer(s) + container overlay...",
        lowers.len()
    );
    let script = format!(
        "set -e\n\
         low='{base_chain}'\n\
         n={n}\n\
         if [ -d '{upper}' ] && [ -n \"$(ls -A '{upper}' 2>/dev/null)\" ]; then\n\
           low=\"{upper}:$low\"; n=$((n+1))\n\
         fi\n\
         if [ \"$n\" -eq 1 ]; then\n\
           tar cf /storage/flat-export.tar -C \"${{low%%:*}}\" .\n\
         else\n\
           mkdir -p /tmp/flatview\n\
           mount -t overlay overlay -o lowerdir=\"$low\" /tmp/flatview\n\
           tar cf /storage/flat-export.tar -C /tmp/flatview .\n\
           umount /tmp/flatview\n\
         fi\n\
         echo FLAT_OK\n",
        n = lowers.len(),
    );
    let (exit_code, stdout, stderr) = client.vm_exec(
        vec!["sh".to_string(), "-c".to_string(), script],
        vec![],
        None,
        None,
        None,
    )?;
    let stdout_str = String::from_utf8_lossy(&stdout);
    if exit_code != 0 || !stdout_str.contains("FLAT_OK") {
        return Err(Error::agent(
            "flatten layers",
            format!(
                "flatten failed (exit {}): {}",
                exit_code,
                String::from_utf8_lossy(&stderr)
            ),
        ));
    }

    // Stream the flattened tar to disk (never buffered whole in memory), then
    // content-address it. Stage in the layers dir so the final rename is
    // atomic on the same filesystem.
    let tmp_file = collector
        .layer_staging_path(&format!("sha256:{}", "0".repeat(64)))
        .with_file_name("flat-export.tmp");
    let total = client
        .read_file_to_path("/storage/flat-export.tar", &tmp_file, |_| {})
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
    let manager = AgentManager::for_vm(&scratch_name)?;
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
            rosetta: false,
            storage_gib: None,
            overlay_gib: None,
            allowed_cidrs: None,
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
