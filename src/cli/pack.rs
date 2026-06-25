//! Pack command for creating self-contained binaries.
//!
//! Creates a packed binary that contains:
//! - A stub executable
//! - Runtime libraries (libkrun, libkrunfw)
//! - Agent rootfs
//! - OCI image layers
//! - Configuration manifest

use clap::{Args, Subcommand};
use smolvm::agent::{resolve_disk_image, AgentClient, AgentManager, VmResources};
use smolvm::data::disk::DiskFormat;
use smolvm::data::resources::DEFAULT_MICROVM_CPU_COUNT;
use smolvm::storage::{OVERLAY_DISK_FILENAME, STORAGE_DISK_FILENAME};

/// Default memory for packed VMs. Same as machine create — memory is elastic
/// via virtio balloon, so the host only commits what the guest actually uses.
pub(crate) const PACK_DEFAULT_MEMORY_MIB: u32 = 8192;
use sha2::{Digest, Sha256};
use smolvm::config::{RecordState, SmolvmConfig};
use smolvm::platform::{Arch, Os, Platform, VmExecutor};
use smolvm::Error;
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::format::{PackManifest, PackMode};
use smolvm_pack::packer::Packer;
use smolvm_pack::signing::sign_with_hypervisor_entitlements;
use smolvm_protocol::AgentResponse;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Package and run self-contained VM executables.
#[derive(Subcommand, Debug)]
pub enum PackCmd {
    /// Package an OCI image or VM snapshot into a self-contained executable
    Create(PackCreateCmd),

    /// Run a VM from a packed .smolmachine sidecar file
    Run(super::pack_run::PackRunCmd),

    /// Push a .smolmachine artifact to a registry
    Push(PackPushCmd),

    /// Pull a .smolmachine artifact from a registry
    Pull(PackPullCmd),

    /// Inspect a .smolmachine artifact in a registry (without downloading)
    Inspect(PackInspectCmd),

    /// Clean up cached pack extractions to free disk space
    Prune(PackPruneCmd),
}

impl PackCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            PackCmd::Create(cmd) => cmd.run(),
            PackCmd::Run(cmd) => cmd.run(),
            PackCmd::Push(cmd) => cmd.run(),
            PackCmd::Pull(cmd) => cmd.run(),
            PackCmd::Inspect(cmd) => cmd.run(),
            PackCmd::Prune(cmd) => cmd.run(),
        }
    }
}

/// Package an OCI image or VM snapshot into a self-contained executable.
///
/// Creates a single binary that can be distributed and run without smolvm installed.
/// The packed binary includes:
/// - Runtime libraries (libkrun, libkrunfw)
/// - Agent rootfs
/// - OCI image layers or VM overlay disk
/// - Default configuration
///
/// Examples:
///   smolvm pack create alpine:latest -o my-alpine
///   smolvm pack create python:3.11-slim -o my-python --cpus 2 --mem 1024
///   smolvm pack create myapp:latest -o myapp --entrypoint /app/run.sh
///   smolvm pack create --from-vm myvm -o my-devenv
#[derive(Args, Debug)]
pub struct PackCreateCmd {
    /// Container image to pack (e.g., alpine:latest, python:3.11-slim)
    #[arg(
        long,
        short = 'I',
        value_name = "IMAGE",
        required_unless_present_any = ["from_vm", "smolfile"],
        conflicts_with = "from_vm"
    )]
    pub image: Option<String>,

    /// Pack from a stopped VM snapshot instead of an OCI image
    #[arg(long = "from-vm", value_name = "VM_NAME")]
    pub from_vm: Option<String>,

    /// Output file path for the packed binary
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: PathBuf,

    /// Default number of vCPUs for the packed VM
    #[arg(long, default_value_t = DEFAULT_MICROVM_CPU_COUNT, value_name = "N")]
    pub cpus: u8,

    /// Default memory in MiB for the packed VM
    #[arg(long, default_value_t = PACK_DEFAULT_MEMORY_MIB, value_name = "MiB")]
    pub mem: u32,

    /// Target OCI platform for multi-arch images (e.g., linux/arm64, linux/amd64)
    ///
    /// By default, uses the host architecture. Use this to override, for example
    /// to pack x86_64 images for Rosetta on Apple Silicon.
    #[arg(long = "oci-platform", value_name = "OS/ARCH")]
    pub oci_platform: Option<String>,

    /// Override the image entrypoint
    #[arg(long, value_name = "CMD")]
    pub entrypoint: Option<String>,

    /// Skip code signing (macOS only)
    #[arg(long)]
    pub no_sign: bool,

    /// Pack as a single file (no sidecar)
    ///
    /// Creates one executable instead of binary + .smolmachine sidecar.
    /// Simpler to distribute but may have issues with macOS notarization.
    #[arg(long)]
    pub single_file: bool,

    /// Path to stub executable (defaults to built-in)
    #[arg(long, value_name = "PATH", hide = true)]
    pub stub: Option<PathBuf>,

    /// Path to library directory containing libkrun and libkrunfw
    #[arg(long, value_name = "DIR", hide = true)]
    pub lib_dir: Option<PathBuf>,

    /// Path to agent rootfs directory
    #[arg(long, value_name = "DIR", hide = true)]
    pub rootfs_dir: Option<PathBuf>,

    /// Load workload configuration from a Smolfile (TOML)
    #[arg(long = "smolfile", visible_short_alias = 's', value_name = "PATH")]
    pub smolfile: Option<PathBuf>,

    /// Enable GPU acceleration (Vulkan via virtio-gpu) in the packed VM
    ///
    /// The packed binary will launch with a virtio-gpu device. The guest image
    /// must include a compatible Vulkan ICD (e.g., Mesa Venus on Fedora via
    /// the slp/mesa-libkrun-vulkan COPR, or standard Mesa on Linux hosts).
    #[arg(long)]
    pub gpu: bool,

    /// Directory under which to stage pack assets (pulled layers, the merged
    /// layer, agent rootfs, and the ext4 template). Defaults to the smolvm cache
    /// dir; point this at a roomy disk-backed path when the default filesystem is
    /// small. Overrides the `SMOLVM_PACK_STAGING` env var.
    #[arg(long = "staging-dir", value_name = "DIR")]
    pub staging_dir: Option<PathBuf>,

    #[command(flatten, next_help_heading = "Network")]
    pub proxy_opts: crate::cli::proxy_opts::ProxyOpts,
}

impl PackCreateCmd {
    /// Resolve the directory under which the staging temp dir is created.
    ///
    /// Precedence: `--staging-dir` → `SMOLVM_PACK_STAGING` → the disk-backed
    /// cache dir (`<cache>/smolvm`) → `$TMPDIR`. The default must NOT be
    /// `$TMPDIR`: staging holds the whole image (the pulled layers, a merged
    /// copy, the agent rootfs, and the ext4 template), and on most Linux distros
    /// `$TMPDIR` is tmpfs (RAM-backed, small), so large images fail there with
    /// ENOSPC/EDQUOT.
    fn staging_root(&self) -> smolvm::Result<PathBuf> {
        let root = self
            .staging_dir
            .clone()
            .or_else(|| std::env::var_os("SMOLVM_PACK_STAGING").map(PathBuf::from))
            .or_else(|| dirs::cache_dir().map(|c| c.join("smolvm")))
            .unwrap_or_else(std::env::temp_dir);
        std::fs::create_dir_all(&root)
            .map_err(|e| Error::agent("create staging root", e.to_string()))?;
        Ok(root)
    }

    pub fn run(self) -> smolvm::Result<()> {
        if let Some(vm_name) = self.from_vm.clone() {
            if self.oci_platform.is_some() {
                warn!("--oci-platform is ignored with --from-vm (VM snapshot is arch-fixed)");
            }
            info!(vm = %vm_name, output = %self.output.display(), "packing from VM");
            return self.pack_from_vm(vm_name);
        }

        // Resolve config from Smolfile + CLI
        let pack_config = crate::cli::smolfile::resolve_pack_config(
            self.image.clone(),
            self.entrypoint.clone(),
            self.cpus,
            self.mem,
            self.oci_platform.clone(),
            self.gpu,
            self.smolfile.clone(),
        )?;

        let image = pack_config.image.ok_or_else(|| {
            Error::config(
                "pack create",
                "no image specified. Provide IMAGE argument or set 'image' in Smolfile",
            )
        })?;
        info!(image = %image, output = %self.output.display(), "packing image");

        // Create temporary staging directory
        let temp_dir = tempfile::Builder::new()
            .prefix("pack-staging-")
            .tempdir_in(self.staging_root()?)
            .map_err(|e| Error::agent("create temp directory", e.to_string()))?;
        let staging_dir = temp_dir.path().join("staging");

        // Start a temporary agent VM with a unique identity so concurrent
        // pack runs and the user's "default" VM don't collide. The prefix
        // must start with an ascii-alphanumeric character to satisfy
        // `validate_vm_name` when `AgentManager::for_vm` receives the name
        // (see src/data/mod.rs). A leading underscore — the previous
        // `__pack_` convention — was rejected outright and made every
        // `smolvm pack create` invocation fail.
        // Use PID + epoch nanos to avoid PID-reuse collisions with orphaned VMs.
        let pack_vm_name = format!(
            "pack-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        // Guard ensures VM is stopped on early error. Only removes temp data
        // dir after confirmed stop — never deletes while VM may still be running.
        let vm_data_dir = smolvm::agent::vm_data_dir(&pack_vm_name);
        struct PackVmGuard {
            manager: AgentManager,
            data_dir: std::path::PathBuf,
            finalized: bool,
        }
        impl PackVmGuard {
            /// Stop VM and clean up temp dir. Propagates stop errors.
            fn stop_and_cleanup(&mut self) -> smolvm::Result<()> {
                self.manager.stop()?;
                self.finalized = true;
                if let Err(e) = std::fs::remove_dir_all(&self.data_dir) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            error = %e,
                            dir = %self.data_dir.display(),
                            "failed to remove pack temp dir"
                        );
                    }
                }
                Ok(())
            }
        }
        impl Drop for PackVmGuard {
            fn drop(&mut self) {
                if self.finalized {
                    return;
                }
                match self.manager.stop() {
                    Ok(()) => {
                        if let Err(e) = std::fs::remove_dir_all(&self.data_dir) {
                            if e.kind() != std::io::ErrorKind::NotFound {
                                tracing::warn!(
                                    error = %e,
                                    dir = %self.data_dir.display(),
                                    "failed to remove pack temp dir"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "failed to stop pack VM; preserving temp data dir"
                        );
                    }
                }
            }
        }

        println!("Starting agent VM...");
        let manager = AgentManager::for_vm(&pack_vm_name)?;
        manager.start_with_config(
            Vec::new(),
            VmResources {
                cpus: 4,
                memory_mib: 8192,
                network: true,
                network_backend: None,
                gpu: false,
                storage_gib: None,
                overlay_gib: None,
                gpu_vram_mib: None,
                allowed_cidrs: None,
            },
        )?;
        let mut guard = PackVmGuard {
            manager,
            data_dir: vm_data_dir,
            finalized: false,
        };
        let mut client = guard.manager.connect()?;

        // Pull image
        let image_info = crate::cli::pull_with_progress(
            &mut client,
            &image,
            pack_config.oci_platform.as_deref(),
            self.proxy_opts.proxy(),
            self.proxy_opts.no_proxy(),
        )?;
        debug!(image_info = ?image_info, "image pulled");

        println!(
            "Image: {} ({} layers, {} bytes)",
            image, image_info.layer_count, image_info.size
        );

        // Create asset collector and collect base assets
        let mut collector = AssetCollector::new(staging_dir.clone())
            .map_err(|e| Error::agent("collect assets", e.to_string()))?;
        self.collect_base_assets(&mut collector)?;

        // Export layers. For images with many layers (e.g., rocker/tidyverse
        // has 20), we pre-merge all layers into a single directory in the VM
        // so the packed binary has one lowerdir at runtime. Without this, the
        // overlayfs multi-lowerdir mount fails on virtiofs-backed layers and
        // falls back to a 15-second physical merge on every first exec.
        if image_info.layer_count <= 1 {
            // Single layer — export directly, no merge needed.
            let layer_digest = &image_info.layers[0];
            let prefix = format!("  Layer 1/1: {}", &layer_digest[..19]);
            print!("{}...", prefix);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let layer_file = collector.layer_staging_path(layer_digest);
            self.export_layer_to_file(&mut client, &image_info.digest, 0, &layer_file, &prefix)?;
            collector
                .register_layer(layer_digest)
                .map_err(|e| Error::agent("collect layers", e.to_string()))?;
        } else {
            // Multiple layers — merge in the VM so runtime gets a single
            // lowerdir that always mounts instantly.
            println!(
                "Merging {} layers in VM (one-time cost)...",
                image_info.layer_count
            );

            // Build the merge command: extract each layer in order (bottom
            // first), then tar the result. Layer order in image_info.layers
            // is bottom-to-top, which is the correct copy order.
            let layer_paths: Vec<String> = image_info
                .layers
                .iter()
                .map(|d| {
                    let id = d.strip_prefix("sha256:").unwrap_or(d);
                    format!("/storage/layers/{}", id)
                })
                .collect();

            // Copy layers bottom-up into /tmp/merged, then tar
            let mut merge_script = String::from("set -e\nmkdir -p /tmp/merged\n");
            for (i, layer_path) in layer_paths.iter().enumerate() {
                // cp -a preserves symlinks, permissions, ownership.
                // Ignore exit code: cp may fail on device files or sockets
                // that can't be copied, but the layer content is intact.
                // Redirect stderr so warnings are visible in the output.
                merge_script.push_str(&format!(
                    "echo 'Merging layer {}/{}...'\n\
                     cp -a {}/. /tmp/merged/ || true\n",
                    i + 1,
                    image_info.layer_count,
                    layer_path
                ));
            }
            // Verify disk space wasn't exhausted during merge
            merge_script.push_str(
                "if ! df /tmp/merged | awk 'NR==2{if($4<1024){exit 1}}'; then\n\
                 echo 'MERGE_FAIL: disk full'; exit 1\nfi\n\
                 echo 'Creating merged tar...'\n\
                 tar cf /tmp/merged-layers.tar -C /tmp/merged .\n\
                 echo 'MERGE_OK'\n",
            );

            let (exit_code, stdout, stderr) = client.vm_exec(
                vec!["sh".to_string(), "-c".to_string(), merge_script],
                vec![],
                None,
                None,
                None,
            )?;

            // stdout/stderr from vm_exec are now Vec<u8>; convert lossily
            // for content checks and error messages (merge output is ASCII).
            let stdout_str = String::from_utf8_lossy(&stdout);
            let stderr_str = String::from_utf8_lossy(&stderr);
            if exit_code != 0 || !stdout_str.contains("MERGE_OK") {
                return Err(Error::agent(
                    "merge layers",
                    format!(
                        "layer merge failed (exit {}): {}",
                        exit_code,
                        if stderr_str.is_empty() {
                            &stdout_str
                        } else {
                            &stderr_str
                        }
                    ),
                ));
            }

            // Download the merged tar — streamed to disk (16 MB chunks,
            // never holds the full tar in memory).
            print!("  Exporting merged layer...");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let merged_hash = hex::encode(Sha256::digest(
                format!("merged-{}", image_info.digest).as_bytes(),
            ));
            let merged_digest = format!("sha256:{}", merged_hash);
            let merged_file = collector.layer_staging_path(&merged_digest);

            let total_bytes = client
                .read_file_to_path("/tmp/merged-layers.tar", &merged_file, |_| {})
                .map_err(|e| Error::agent("export merged layer", e.to_string()))?;
            println!(" {} MB done", total_bytes / (1024 * 1024));

            collector
                .register_layer(&merged_digest)
                .map_err(|e| Error::agent("register merged layer", e.to_string()))?;
        }

        // Stop agent and clean up temp VM data. Propagates stop errors
        // so pack fails visibly if VM cannot be stopped.
        guard.stop_and_cleanup()?;

        // Build manifest
        let platform = format!("{}/{}", image_info.os, image_info.architecture);
        let host_platform = Platform::current().host_oci_platform().to_string();
        let mut manifest =
            PackManifest::new(image, image_info.digest.clone(), platform, host_platform);
        manifest.image_size = image_info.size;
        manifest.cpus = pack_config.cpus;
        manifest.mem = pack_config.mem;
        manifest.network = pack_config.net.unwrap_or(false);
        manifest.gpu = pack_config.gpu;

        // Start with OCI image config as baseline
        manifest.entrypoint = image_info.entrypoint.clone();
        manifest.cmd = image_info.cmd.clone();
        manifest.env = image_info.env.clone();
        manifest.workdir = image_info.workdir.clone();

        // Layer Smolfile top-level env on top of image env
        if !pack_config.env.is_empty() {
            for e in &pack_config.env {
                if let Some((key, _)) = e.split_once('=') {
                    // Remove any existing image env with the same key
                    manifest
                        .env
                        .retain(|existing| !existing.starts_with(&format!("{}=", key)));
                }
                manifest.env.push(e.clone());
            }
        }

        // Carry Smolfile [secrets] refs into the manifest. Refs only — the
        // plaintext is resolved on the run host at exec time, never packed.
        manifest.secret_refs = pack_config.secret_refs.clone();

        // Smolfile workdir overrides image workdir
        if pack_config.workdir.is_some() {
            manifest.workdir = pack_config.workdir;
        }

        // Override entrypoint from Smolfile or CLI
        if !pack_config.entrypoint.is_empty() {
            manifest.entrypoint = pack_config.entrypoint;
        }

        // Override cmd from Smolfile
        if !pack_config.cmd.is_empty() {
            manifest.cmd = pack_config.cmd;
        }

        self.finalize_pack(manifest, collector, staging_dir)
    }

    /// Pack from a stopped VM's overlay disk.
    fn pack_from_vm(self, vm_name: String) -> smolvm::Result<()> {
        // 1. Load config and verify VM exists and is stopped
        let config = SmolvmConfig::load()?;
        let vm = config
            .vms
            .get(&vm_name)
            .ok_or_else(|| Error::agent("pack from VM", format!("VM '{}' not found", vm_name)))?;

        if vm.actual_state() == RecordState::Running {
            return Err(Error::agent(
                "pack from VM",
                format!(
                    "VM '{}' is running. Stop it first with: smolvm machine stop --name {}",
                    vm_name, vm_name
                ),
            ));
        }

        // 2. Locate the VM's disks. Default-size machines on Linux get qcow2 CoW
        // overlays (overlay.qcow2 / storage.qcow2), not `.raw`, so resolve whichever
        // format exists rather than hardcoding `.raw`. The overlay template is only
        // consumed by VM-mode (bare) restores — container restores ignore it — so it
        // is required only for non-image VMs.
        let vm_dir = smolvm::agent::vm_data_dir(&vm_name);
        let (overlay_disk, overlay_fmt) = resolve_disk_image(&vm_dir, OVERLAY_DISK_FILENAME);
        let is_image_based = vm.image.is_some();
        if !is_image_based && !overlay_disk.exists() {
            return Err(Error::agent(
                "pack from VM",
                format!(
                    "overlay disk not found at {}. The VM may not have been started yet.",
                    overlay_disk.display()
                ),
            ));
        }

        println!("Packing VM '{}' snapshot...", vm_name);

        // 3. Create temporary staging directory
        let temp_dir = tempfile::Builder::new()
            .prefix("pack-staging-")
            .tempdir_in(self.staging_root()?)
            .map_err(|e| Error::agent("create temp directory", e.to_string()))?;
        let staging_dir = temp_dir.path().join("staging");

        let mut collector = AssetCollector::new(staging_dir.clone())
            .map_err(|e| Error::agent("collect assets", e.to_string()))?;

        // 4. For image-based VMs, export OCI layers + container overlay via temp VM.
        // The container overlay (installed packages) lives inside the VM's ext4
        // storage disk which can't be read on macOS — a temp VM mounts it for us.
        if is_image_based {
            let image = vm.image.clone().unwrap();
            // A locally-sourced image (`--image -` / `--image file.tar` / a rootfs
            // dir) is flattened on boot and has no registry manifest, so the
            // layer-export path below — which pulls that manifest to enumerate base
            // layers — cannot source it. Fail with a clear, actionable message
            // instead of a confusing registry "UNAUTHORIZED" on `local:<hash>`.
            if smolvm::data::image_source::is_local_ref(&image) {
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
            // Attach the source storage disk with its real on-disk format so a
            // qcow2 (default-size) disk is presented correctly and mounts in the
            // temp VM — hardcoding raw would hand libkrun qcow2 bytes as raw.
            let (storage_disk, storage_fmt) = resolve_disk_image(&vm_dir, STORAGE_DISK_FILENAME);

            self.collect_base_assets(&mut collector)?;

            // Start temp VM with source VM's storage disk attached as an extra
            // virtio-blk device. virtiofs can only share directories, not files,
            // so we pass the ext4 disk image as a third block device (/dev/vdc).
            // Same alphanumeric-first-char constraint as the image-pack
            // path above; see the comment there for rationale.
            let pack_vm_name = format!(
                "pack-fromvm-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            let vm_data = smolvm::agent::vm_data_dir(&pack_vm_name);

            println!("Starting agent VM to export layers...");
            let manager = AgentManager::for_vm(&pack_vm_name)?;
            let features = smolvm::agent::LaunchFeatures {
                extra_disks: vec![(storage_disk.clone(), false, storage_fmt)],
                ..Default::default()
            };
            manager.start_with_full_config(
                Vec::new(),
                Vec::new(),
                VmResources {
                    cpus: 4,
                    memory_mib: 8192,
                    network: true,
                    network_backend: None,
                    gpu: false,
                    gpu_vram_mib: None,
                    storage_gib: None,
                    overlay_gib: None,
                    allowed_cidrs: None,
                },
                features,
            )?;

            // Closure ensures the temp VM is always stopped, even on early errors
            // (pull failure, export failure, etc.). Export errors propagate; stop
            // failures are logged but don't mask the original error.
            let export_result: smolvm::Result<()> = (|| {
                let mut client = manager.connect()?;

                // Mount the source VM's storage disk inside the guest.
                // It appears as /dev/vdc (3rd block device after storage + overlay).
                let (exit_code, _, stderr) = client.vm_exec(
                    vec![
                        "sh".to_string(),
                        "-c".to_string(),
                        "mkdir -p /mnt/source-storage && mount /dev/vdc /mnt/source-storage"
                            .to_string(),
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

                // Pull the same image (layers are cached on the source storage,
                // but the agent needs the manifest to know the layer list).
                let image_info = crate::cli::pull_with_progress(
                    &mut client,
                    &image,
                    None,
                    self.proxy_opts.proxy(),
                    self.proxy_opts.no_proxy(),
                )?;

                // Export base image layers
                println!("Exporting {} layers...", image_info.layer_count);
                for (i, layer_digest) in image_info.layers.iter().enumerate() {
                    let prefix = format!(
                        "  Layer {}/{}: {}",
                        i + 1,
                        image_info.layer_count,
                        &layer_digest[..std::cmp::min(19, layer_digest.len())]
                    );
                    print!("{}...", prefix);
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    let layer_file = collector.layer_staging_path(layer_digest);
                    self.export_layer_to_file(
                        &mut client,
                        &image_info.digest,
                        i,
                        &layer_file,
                        &prefix,
                    )?;
                    collector
                        .register_layer(layer_digest)
                        .map_err(|e| Error::agent("collect layers", e.to_string()))?;
                }

                // Export the container overlay upper dir as an additional layer.
                // The source VM's storage disk is mounted at /mnt/source-storage.
                let overlay_dir =
                    format!("/mnt/source-storage/overlays/persistent-{}/upper", vm_name);
                println!("Exporting container overlay...");
                let overlay_hash =
                    hex::encode(Sha256::digest(format!("overlay-{}", vm_name).as_bytes()));
                let overlay_digest = format!("sha256:{}", overlay_hash);
                let overlay_layer_file = collector.layer_staging_path(&overlay_digest);

                // Use the agent to tar the overlay dir
                let (exit_code, _, stderr) = client.vm_exec(
                    vec![
                        "sh".to_string(),
                        "-c".to_string(),
                        format!(
                            "if [ -d '{}' ] && [ \"$(ls -A '{}')\" ]; then \
                             tar cf /tmp/overlay-export.tar -C '{}' . 2>/dev/null; \
                             echo OVERLAY_OK; \
                             else echo OVERLAY_EMPTY; fi",
                            overlay_dir, overlay_dir, overlay_dir
                        ),
                    ],
                    vec![],
                    None,
                    None,
                    None,
                )?;

                if exit_code == 0 {
                    // Download the tar from the temp VM
                    let tar_data = client.read_file("/tmp/overlay-export.tar")?;
                    if !tar_data.is_empty() {
                        std::fs::write(&overlay_layer_file, &tar_data)
                            .map_err(|e| Error::agent("write overlay layer", e.to_string()))?;
                        collector
                            .register_layer(&overlay_digest)
                            .map_err(|e| Error::agent("register overlay layer", e.to_string()))?;
                        println!("  Overlay layer: {} bytes", tar_data.len());
                    }
                } else {
                    tracing::debug!(stderr = %String::from_utf8_lossy(&stderr), "overlay export: no container changes found");
                }

                Ok(())
            })();

            // Always stop the temp VM and clean up
            if let Err(e) = manager.stop() {
                warn!(error = %e, "failed to stop pack temp VM");
            }
            let _ = std::fs::remove_dir_all(&vm_data);
            export_result?;
        } else {
            // Bare VM: just collect base assets, no layers needed.
            self.collect_base_assets(&mut collector)?;
        }

        // Add the overlay template (the VM's rootfs state). VM-mode restores boot
        // from it; container restores ignore it entirely (every import path gates
        // `overlay_template` on `PackMode::Vm`), so skip it for image-based VMs
        // rather than flatten a qcow2 for nothing. A default-size overlay is a qcow2
        // CoW image, which must be flattened to a raw before it can be a template.
        if !is_image_based {
            let overlay_for_pack = match overlay_fmt {
                DiskFormat::Raw => overlay_disk.clone(),
                DiskFormat::Qcow2 => {
                    let flat = temp_dir.path().join("overlay-flat.raw");
                    self.flatten_qcow2_to_raw(&overlay_disk, &flat)?;
                    flat
                }
            };
            println!("Copying overlay disk ({})...", overlay_for_pack.display());
            collector
                .add_overlay_template(&overlay_for_pack)
                .map_err(|e| Error::agent("collect overlay", e.to_string()))?;
        }

        // 5. Resolve Smolfile overrides if provided
        //    Precedence: CLI > [artifact] > Smolfile top-level > VmRecord > default
        let pack_config = crate::cli::smolfile::resolve_pack_config(
            None, // no image for --from-vm
            self.entrypoint.clone(),
            self.cpus,
            self.mem,
            self.oci_platform.clone(),
            self.gpu,
            self.smolfile.clone(),
        )?;

        // 6. Build manifest
        let platform = format!("linux/{}", Arch::current().oci_arch());
        let host_platform = Platform::current().host_oci_platform().to_string();
        let mut manifest = PackManifest::new(
            format!("vm://{}", vm_name),
            "none".to_string(),
            platform,
            host_platform,
        );
        if is_image_based {
            manifest.mode = PackMode::Container;
            manifest.image = vm.image.clone().unwrap_or_default();
        } else {
            manifest.mode = PackMode::Vm;
        }
        manifest.cpus = pack_config.cpus;
        manifest.mem = pack_config.mem;
        // Smolfile > source VM record > default
        manifest.network = pack_config.net.unwrap_or(vm.network);
        // CLI --gpu > Smolfile gpu > source VM record gpu > false
        manifest.gpu = pack_config.gpu || vm.gpu.unwrap_or(false);

        // Entrypoint baseline: VmRecord > /bin/sh default
        manifest.entrypoint = if !vm.entrypoint.is_empty() {
            vm.entrypoint.clone()
        } else {
            vec!["/bin/sh".to_string()]
        };
        manifest.cmd = vm.cmd.clone();

        // Start with VmRecord env/workdir as baseline
        manifest.env = vm.env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        manifest.workdir = vm.workdir.clone();

        // Layer Smolfile env on top of VmRecord env
        if !pack_config.env.is_empty() {
            for e in &pack_config.env {
                if let Some((key, _)) = e.split_once('=') {
                    manifest
                        .env
                        .retain(|existing| !existing.starts_with(&format!("{}=", key)));
                }
                manifest.env.push(e.clone());
            }
        }

        // Baseline secret refs from the source VM record, then layer the
        // Smolfile [secrets] on top (Smolfile wins on key collisions). Refs
        // only — plaintext is resolved on the run host, never packed.
        manifest.secret_refs = vm.secret_refs.clone();
        manifest.secret_refs.extend(pack_config.secret_refs.clone());

        // Smolfile workdir overrides VmRecord workdir
        if pack_config.workdir.is_some() {
            manifest.workdir = pack_config.workdir;
        }

        // Override entrypoint from Smolfile/[artifact] or CLI
        if !pack_config.entrypoint.is_empty() {
            manifest.entrypoint = pack_config.entrypoint;
        }

        // Override cmd from Smolfile/[artifact]
        if !pack_config.cmd.is_empty() {
            manifest.cmd = pack_config.cmd;
        }

        self.finalize_pack(manifest, collector, staging_dir)
    }

    /// Flatten a qcow2 CoW overlay into a standalone raw disk image.
    ///
    /// Default-size machines use a qcow2 overlay backed by the install's default
    /// template, but a pack's overlay template must be a flat raw. There is no
    /// host-side qcow2 reader (smolvm deliberately takes no qemu-img dependency),
    /// so the conversion runs inside a throwaway agent VM: the source qcow2 is
    /// attached read-only (libkrun resolves its backing chain) as `/dev/vdc`
    /// alongside a fresh raw output as `/dev/vdd`, and the guest `dd`s one into the
    /// other. `add_overlay_template` then strips trailing zeros so a mostly-empty
    /// overlay still packs small, and extraction re-sparsifies it on import.
    fn flatten_qcow2_to_raw(&self, qcow2_path: &Path, dest_raw: &Path) -> smolvm::Result<()> {
        let virtual_size = read_qcow2_virtual_size(qcow2_path)?;
        {
            let f = std::fs::File::create(dest_raw)
                .map_err(|e| Error::agent("create flatten target", e.to_string()))?;
            f.set_len(virtual_size)
                .map_err(|e| Error::agent("size flatten target", e.to_string()))?;
        }

        let flatten_vm_name = format!(
            "pack-flatten-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let vm_data = smolvm::agent::vm_data_dir(&flatten_vm_name);
        println!("Flattening qcow2 overlay to raw...");
        let manager = AgentManager::for_vm(&flatten_vm_name)?;
        let features = smolvm::agent::LaunchFeatures {
            // vdc = source qcow2 (read-only), vdd = fresh raw output.
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
                gpu: false,
                gpu_vram_mib: None,
                storage_gib: None,
                overlay_gib: None,
                allowed_cidrs: None,
            },
            features,
        )?;

        let result: smolvm::Result<()> = (|| {
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
                    "flatten qcow2 overlay",
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
            warn!(error = %e, "failed to stop pack flatten VM");
        }
        let _ = std::fs::remove_dir_all(&vm_data);
        result
    }

    /// Collect base assets shared by both image and VM packing modes:
    /// runtime libraries, agent rootfs, and a pre-formatted storage template.
    fn collect_base_assets(&self, collector: &mut AssetCollector) -> smolvm::Result<()> {
        println!("Collecting runtime libraries...");
        let lib_dir = self.find_lib_dir()?;
        collector
            .collect_libraries(&lib_dir)
            .map_err(|e| Error::agent("collect libraries", e.to_string()))?;

        println!("Collecting agent rootfs...");
        let rootfs_dir = self.find_rootfs_dir()?;
        collector
            .collect_agent_rootfs(&rootfs_dir)
            .map_err(|e| Error::agent("collect rootfs", e.to_string()))?;

        println!("Creating storage template...");
        collector
            .create_storage_template()
            .map_err(|e| Error::agent("create storage template", e.to_string()))?;

        Ok(())
    }

    /// Finalize pack: set inventory, assemble binary, print summary, and sign.
    fn finalize_pack(
        &self,
        mut manifest: PackManifest,
        collector: AssetCollector,
        staging_dir: PathBuf,
    ) -> smolvm::Result<()> {
        let stub_path = self.find_smolvm_binary()?;

        manifest.assets = collector.into_inventory();

        let collector = AssetCollector::new(staging_dir.clone())
            .map_err(|e| Error::agent("collect assets", e.to_string()))?;

        let packer = Packer::new(manifest)
            .with_stub(&stub_path)
            .with_asset_collector(collector);

        let label = if self.single_file {
            "Assembling single-file packed binary"
        } else {
            "Assembling packed binary"
        };
        let spinner = Spinner::start(label);
        let info = if self.single_file {
            packer
                .pack_embedded(&self.output)
                .map_err(|e| Error::agent("pack binary", e.to_string()))?
        } else {
            packer
                .pack(&self.output)
                .map_err(|e| Error::agent("pack binary", e.to_string()))?
        };
        spinner.stop();

        println!(
            "Packed: {} (stub: {}KB, total: {}KB)",
            self.output.display(),
            info.stub_size / 1024,
            info.total_size / 1024
        );
        if let Some(ref sidecar) = info.sidecar_path {
            println!(
                "Assets: {} ({}KB compressed)",
                sidecar.display(),
                info.assets_size / 1024
            );
        } else {
            println!("Mode: single-file (no sidecar)");
        }

        // Sign on macOS
        if Os::current().is_macos() && !self.no_sign {
            println!("Signing binary with hypervisor entitlements...");
            if let Err(e) = sign_with_hypervisor_entitlements(&self.output) {
                warn!(error = %e, "signing failed (binary may not run on fresh macOS)");
                eprintln!("Warning: Signing failed: {}", e);
                eprintln!("The binary may require manual signing to use Hypervisor.framework");
            } else {
                println!("Signed successfully");
            }
        }

        // Embed libs in stub AFTER signing — SMOLLIBS footer must be at end of file
        if !self.single_file {
            smolvm_pack::packer::embed_libs_in_binary(&self.output, &staging_dir)
                .map_err(|e| Error::agent("embed libraries", e.to_string()))?;
        }

        println!("\nRun with: {}", self.output.display());
        if info.sidecar_path.is_some() {
            println!("Note: Keep the .smolmachine file alongside the binary");
        }
        println!("Options: --help for usage");

        Ok(())
    }

    /// Find the library directory containing libkrun and libkrunfw.
    fn find_lib_dir(&self) -> smolvm::Result<PathBuf> {
        if let Some(ref dir) = self.lib_dir {
            return Ok(dir.clone());
        }

        // Use the same canonical resolver as the launcher and embedded runtime so
        // `pack create` finds libkrun anywhere the rest of smolvm does: it honors
        // the explicit `$SMOLVM_LIB_DIR` override (e.g. a distro libkrun, or a
        // non-standard install dir) and the installed/exe-relative `lib/` layout.
        // Without this, packing a build whose libs live outside the hardcoded
        // candidates below required `--lib-dir`, even though the env var was set.
        if let Some(dir) = smolvm::agent::find_lib_dir() {
            debug!(lib_dir = %dir.display(), "found library directory via canonical resolver");
            return Ok(dir);
        }

        // Next best: use the exact libkrun that this process has loaded, which
        // guarantees the packed binary gets a library with all required symbols.
        // (Rarely fires for `pack create`: the builder VM boots in a subprocess,
        // so the packer process itself never dlopens libkrun.)
        if let Some(dir) = Self::find_loaded_libkrun_dir() {
            debug!(lib_dir = %dir.display(), "using libkrun from running process");
            return Ok(dir);
        }

        // Fallback: a few well-known locations the canonical resolver does not
        // check (Homebrew, /usr/local/lib, and the current working directory).
        let platform_lib = format!("lib/linux-{}", std::env::consts::ARCH);
        let candidates = [
            // Relative to executable
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("lib"))),
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().and_then(|d| d.parent()).map(|d| d.join("lib"))),
            // Source tree dev builds: <exe_dir>/../../lib/linux-<arch>/
            std::env::current_exe().ok().and_then(|p| {
                p.parent()
                    .and_then(|d| d.parent())
                    .map(|d| d.join(&platform_lib))
            }),
            // Source tree (CWD)
            Some(PathBuf::from("lib")),
            Some(PathBuf::from("./lib")),
            Some(PathBuf::from(&platform_lib)),
            // Homebrew
            Some(PathBuf::from("/opt/homebrew/lib")),
            Some(PathBuf::from("/usr/local/lib")),
        ];

        let lib_name = format!(
            "libkrun.{}",
            smolvm::platform::vm_executor().dylib_extension()
        );

        for candidate in candidates.into_iter().flatten() {
            if candidate.join(&lib_name).exists() {
                debug!(lib_dir = %candidate.display(), "found library directory");
                return Ok(candidate);
            }
        }

        Err(Error::agent(
            "find libkrun",
            "could not find libkrun library. Set SMOLVM_LIB_DIR or pass --lib-dir to specify the location.",
        ))
    }

    /// Find the directory of the libkrun that this process has already loaded.
    ///
    /// Uses `dlopen(RTLD_NOLOAD)` to get a handle to the already-loaded library
    /// (without loading a new one), then `dladdr` to resolve the symbol back to
    /// a filesystem path. This ensures the packer bundles the exact same library
    /// that smolvm itself linked against — no version mismatches possible.
    fn find_loaded_libkrun_dir() -> Option<PathBuf> {
        use std::ffi::{CStr, CString};

        unsafe {
            let name = CString::new(smolvm::util::libkrun_filename()).ok()?;
            let handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOLOAD | libc::RTLD_LAZY);
            if handle.is_null() {
                return None;
            }

            let sym_name = CString::new("krun_create_ctx").ok()?;
            let sym = libc::dlsym(handle, sym_name.as_ptr());
            libc::dlclose(handle);

            if sym.is_null() {
                return None;
            }

            let mut info = std::mem::MaybeUninit::<libc::Dl_info>::uninit();
            if libc::dladdr(sym, info.as_mut_ptr()) != 0 {
                let info = info.assume_init();
                if !info.dli_fname.is_null() {
                    let lib_path = CStr::from_ptr(info.dli_fname).to_string_lossy();
                    return std::path::Path::new(lib_path.as_ref())
                        .parent()
                        .map(|p| p.to_path_buf());
                }
            }
        }

        None
    }

    /// Find the agent rootfs directory.
    ///
    /// Resolution order:
    /// 1. Explicit `--rootfs-dir` flag
    /// 2. `SMOLVM_AGENT_ROOTFS` env var
    /// 3. Installed location (`~/.local/share/smolvm/agent-rootfs` on Linux,
    ///    `~/Library/Application Support/smolvm/agent-rootfs` on macOS)
    ///
    /// `target/agent-rootfs` is NOT checked — it can contain stale builds.
    /// Use `--rootfs-dir` or `SMOLVM_AGENT_ROOTFS` env var to override.
    fn find_rootfs_dir(&self) -> smolvm::Result<PathBuf> {
        if let Some(ref dir) = self.rootfs_dir {
            return Ok(dir.clone());
        }

        let candidates = [
            // SMOLVM_AGENT_ROOTFS env var
            std::env::var("SMOLVM_AGENT_ROOTFS").ok().map(PathBuf::from),
            // Installed location (canonical)
            dirs::data_dir().map(|d| d.join("smolvm/agent-rootfs")),
            // Next to the executable (for distribution tarballs)
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("agent-rootfs"))),
        ];

        for candidate in candidates.into_iter().flatten() {
            // Use symlink_metadata instead of exists() because sbin/init
            // is a symlink to a guest-only path (/usr/local/bin/smolvm-agent)
            // that doesn't exist on the host. exists() follows symlinks and
            // returns false for broken symlinks.
            if std::fs::symlink_metadata(candidate.join("sbin/init")).is_ok() {
                debug!(rootfs_dir = %candidate.display(), "found agent rootfs");
                return Ok(candidate);
            }
        }

        Err(Error::agent(
            "find agent rootfs",
            "could not find agent rootfs. Use --rootfs-dir to specify the location.",
        ))
    }

    /// Find the smolvm binary to embed as the packed runtime.
    ///
    /// The main smolvm binary auto-detects packed mode at startup, so it
    /// serves as both the normal CLI and the packed binary runtime.
    fn find_smolvm_binary(&self) -> smolvm::Result<PathBuf> {
        if let Some(ref path) = self.stub {
            return Ok(path.clone());
        }

        let candidates = [
            // Build output
            Some(PathBuf::from("target/release/smolvm")),
            Some(PathBuf::from("target/debug/smolvm")),
            // Distribution layout: smolvm-bin next to the wrapper script
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("smolvm-bin"))),
            // The running executable itself
            std::env::current_exe().ok(),
            // User data dir
            dirs::data_dir().map(|d| d.join("smolvm/smolvm-bin")),
        ];

        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                debug!(stub = %candidate.display(), "found smolvm binary for packing");
                return Ok(candidate);
            }
        }

        Err(Error::agent(
            "find smolvm binary",
            "could not find smolvm binary. Build it with:\n  \
             cargo build --release\n\
             Or use --stub to specify the path.",
        ))
    }

    /// Export a layer from the agent.
    ///
    /// The agent streams the layer as a sequence of `LayerData` chunks.
    /// Export a layer from the agent, streaming chunks directly to a file on disk.
    ///
    /// No memory buffering — each 16MB chunk is written to disk as it arrives.
    /// This supports layers of any size without hitting host memory limits.
    fn export_layer_to_file(
        &self,
        client: &mut AgentClient,
        image_digest: &str,
        layer_index: usize,
        dest: &std::path::Path,
        progress_prefix: &str,
    ) -> smolvm::Result<()> {
        use smolvm_protocol::AgentRequest;
        use std::io::Write;
        use std::time::{Duration, Instant};

        const LAYER_EXPORT_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes

        let request = AgentRequest::ExportLayer {
            image_digest: image_digest.to_string(),
            layer_index,
        };

        let _timeout_guard = client.set_extended_read_timeout(LAYER_EXPORT_TIMEOUT)?;
        client.send_raw(&request)?;

        let mut file = std::fs::File::create(dest).map_err(|e| {
            Error::agent(
                "export layer",
                format!("failed to create {}: {}", dest.display(), e),
            )
        })?;

        let start = Instant::now();
        let mut total_bytes = 0u64;
        let mut last_progress = Instant::now();
        loop {
            if start.elapsed() > LAYER_EXPORT_TIMEOUT {
                return Err(Error::agent(
                    "export layer",
                    format!(
                        "layer export timed out after {}s (received {} bytes so far)",
                        LAYER_EXPORT_TIMEOUT.as_secs(),
                        total_bytes
                    ),
                ));
            }

            let response = client.recv_raw()?;
            match response {
                AgentResponse::DataChunk { data, done } => {
                    if !data.is_empty() {
                        file.write_all(&data).map_err(|e| {
                            Error::agent("export layer", format!("write failed: {}", e))
                        })?;
                        total_bytes += data.len() as u64;

                        // Update progress every 500ms
                        if last_progress.elapsed() >= Duration::from_millis(500) {
                            print!("\r{}... {}", progress_prefix, fmt_bytes(total_bytes));
                            let _ = std::io::stdout().flush();
                            last_progress = Instant::now();
                        }
                    }
                    if done {
                        file.flush().map_err(|e| {
                            Error::agent("export layer", format!("flush failed: {}", e))
                        })?;
                        println!("\r{}... {} done", progress_prefix, fmt_bytes(total_bytes));
                        return Ok(());
                    }
                }
                AgentResponse::Error { message, .. } => {
                    return Err(Error::agent("export layer", message));
                }
                _ => {
                    return Err(Error::agent("export layer", "unexpected response type"));
                }
            }
        }
    }
}

// ============================================================================
// Pack Prune Command
// ============================================================================

/// Clean up cached pack extractions to free disk space.
///
/// Removes old extracted pack caches from ~/.cache/smolvm-pack/ and
/// ~/.cache/smolvm-libs/. By default keeps the 5 most recently used.
///
/// Examples:
///   smolvm pack prune              # keep 5 most recent
///   smolvm pack prune --keep 2     # keep 2 most recent
///   smolvm pack prune --all        # remove everything
///   smolvm pack prune --dry-run    # show what would be removed
#[derive(Args, Debug)]
pub struct PackPruneCmd {
    /// Number of cached extractions to keep (default: 5)
    #[arg(long, default_value = "5", value_name = "N")]
    pub keep: usize,

    /// Remove all cached extractions
    #[arg(long)]
    pub all: bool,

    /// Show what would be removed without actually removing
    #[arg(long)]
    pub dry_run: bool,
}

impl PackPruneCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let keep = if self.all { 0 } else { self.keep };

        let mut total_freed: u64 = 0;
        let mut total_removed: usize = 0;

        // Clean pack sidecar cache
        if let Some(base) = dirs::cache_dir() {
            let pack_cache = base.join("smolvm-pack");
            let (freed, removed) = self.prune_cache_dir(&pack_cache, keep, "pack cache")?;
            total_freed += freed;
            total_removed += removed;

            // Clean libs cache
            let libs_cache = base.join("smolvm-libs");
            let (freed, removed) = self.prune_cache_dir(&libs_cache, keep, "libs cache")?;
            total_freed += freed;
            total_removed += removed;
        }

        if total_removed > 0 {
            if self.dry_run {
                println!(
                    "Would remove {} cached entries ({})",
                    total_removed,
                    crate::cli::format_bytes(total_freed)
                );
            } else {
                println!(
                    "Removed {} cached entries, freed {}",
                    total_removed,
                    crate::cli::format_bytes(total_freed)
                );
            }
        } else {
            println!("No cached entries to remove.");
        }

        Ok(())
    }

    fn prune_cache_dir(
        &self,
        base: &std::path::Path,
        keep: usize,
        label: &str,
    ) -> smolvm::Result<(u64, usize)> {
        if !base.exists() {
            return Ok((0, 0));
        }

        // Collect entries with modification time (skip entries we can't stat)
        let mut entries: Vec<(std::path::PathBuf, std::time::SystemTime, u64)> = vec![];
        let read_dir = match std::fs::read_dir(base) {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!(error = %e, path = %base.display(), "cannot read {}", label);
                return Ok((0, 0));
            }
        };
        for entry in read_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let metadata = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "skipping unreadable entry in {}", label);
                    continue;
                }
            };
            let modified = metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let size = dir_size(&path);
            entries.push((path, modified, size));
        }

        // Sort by most recently modified (newest first)
        entries.sort_by_key(|b| std::cmp::Reverse(b.1));

        // Remove entries beyond keep count
        let to_remove = if entries.len() > keep {
            &entries[keep..]
        } else {
            return Ok((0, 0));
        };

        let mut freed: u64 = 0;
        let mut removed: usize = 0;

        for (path, _, size) in to_remove {
            // Skip caches that have active leases (running VMs or daemons).
            if smolvm_pack::extract::has_active_leases(path) {
                println!("  skipping in-use cache: {} (active lease)", path.display());
                continue;
            }

            if self.dry_run {
                println!(
                    "  would remove: {} ({})",
                    path.display(),
                    crate::cli::format_bytes(*size)
                );
            } else {
                // Detach any mounted case-sensitive volume before removing.
                // Safe because we verified no active leases above.
                smolvm_pack::extract::force_detach_layers_volume(path);
                if let Err(e) = std::fs::remove_dir_all(path) {
                    tracing::warn!(error = %e, path = %path.display(), "failed to remove {}", label);
                    continue;
                }
                // Also remove lock file if present
                let lock = path.with_extension("lock");
                let _ = std::fs::remove_file(&lock);
            }
            freed += size;
            removed += 1;
        }

        Ok((freed, removed))
    }
}

// ============================================================================
// Push / Pull — registry operations for .smolmachine artifacts
// ============================================================================

/// Push a .smolmachine artifact to a registry.
///
/// Examples:
///   smolvm pack push myapp:v1 -f ./my-app.smolmachine
///   smolvm pack push registry.example.com/myapp:latest -f ./app.smolmachine
#[derive(Args, Debug)]
pub struct PackPushCmd {
    /// Artifact reference (e.g., myapp:v1, registry.example.com/myapp:latest)
    #[arg(value_name = "REFERENCE")]
    pub reference: String,

    /// Path to the .smolmachine file to push
    #[arg(short = 'f', long, value_name = "PATH")]
    pub file: PathBuf,
}

impl PackPushCmd {
    pub fn run(self) -> smolvm::Result<()> {
        if !self.file.exists() {
            return Err(Error::agent(
                "push",
                format!("file not found: {}", self.file.display()),
            ));
        }

        let parsed = smolvm::registry::Reference::parse(&self.reference)
            .map_err(|e| Error::agent("parse reference", e.to_string()))?;
        let settings = smolvm::SmolSettings::load()?;
        let client = build_registry_client(&parsed.registry, &settings.machines)?;

        let repo = parsed.repository();
        let tag = parsed.tag.as_deref().unwrap_or("latest");

        eprintln!(
            "Pushing {} to {}/{}:{}",
            self.file.display(),
            parsed.registry,
            repo,
            tag
        );

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::agent("create tokio runtime", e.to_string()))?;

        let result = rt
            .block_on(smolvm_registry::push(&client, &repo, tag, &self.file))
            .map_err(|e| Error::agent("registry push", e.to_string()))?;

        eprintln!(
            "Pushed successfully\n  Layer:    {} ({} bytes)\n  Manifest: {}",
            result.layer_digest, result.layer_size, result.manifest_digest,
        );
        Ok(())
    }
}

/// Pull a .smolmachine artifact from a registry.
///
/// Examples:
///   smolvm pack pull myapp:v1
///   smolvm pack pull myapp:v1 -o ./my-app.smolmachine
///   smolvm pack pull registry.example.com/myapp@sha256:abc123...
#[derive(Args, Debug)]
pub struct PackPullCmd {
    /// Artifact reference (e.g., myapp:v1, registry.example.com/myapp:latest)
    #[arg(value_name = "REFERENCE")]
    pub reference: String,

    /// Output path for the downloaded .smolmachine file
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

impl PackPullCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let parsed = smolvm::registry::Reference::parse(&self.reference)
            .map_err(|e| Error::agent("parse reference", e.to_string()))?;
        let settings = smolvm::SmolSettings::load()?;
        let client = build_registry_client(&parsed.registry, &settings.machines)?;

        let repo = parsed.repository();
        let tag_or_digest = parsed
            .digest
            .as_deref()
            .or(parsed.tag.as_deref())
            .unwrap_or("latest");

        eprintln!("Pulling {}/{}:{}", parsed.registry, repo, tag_or_digest);

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::agent("create tokio runtime", e.to_string()))?;

        let cache = smolvm_registry::BlobCache::open_default()
            .map_err(|e| Error::agent("open blob cache", e.to_string()))?;

        let result = rt
            .block_on(smolvm_registry::pull(
                &client,
                &repo,
                tag_or_digest,
                self.output.as_deref(),
                &cache,
            ))
            .map_err(|e| Error::agent("registry pull", e.to_string()))?;

        if result.cached {
            eprintln!("Using cached blob ({})", result.digest);
        }

        let dest = self.output.unwrap_or(result.path);
        eprintln!(
            "Pulled successfully -> {} ({} bytes)",
            dest.display(),
            result.size,
        );

        // Warn if the artifact targets a different host platform.
        // This is not an error — the user may be inspecting or transferring
        // the artifact — but it will not run on this host as-is.
        if let Ok(manifest) = smolvm_pack::read_manifest_from_sidecar(&dest) {
            let current = Platform::current().host_oci_platform();
            if manifest.host_platform != current {
                eprintln!(
                    "Warning: this artifact was built for {} and will not run on {} (current platform).\
                     \nTo run on {}, create a new pack:\
                     \n\n  smolvm pack create --image {} -o <output>",
                    manifest.host_platform, current, current, manifest.image,
                );
            }
        }

        Ok(())
    }
}

/// Inspect a .smolmachine artifact in a registry without downloading the full artifact.
///
/// Fetches only the OCI manifest and config blob (~1KB total) to display
/// metadata about the packed machine.
///
/// Examples:
///   smolvm pack inspect myapp:v1
///   smolvm pack inspect myapp:v1 --json
#[derive(Args, Debug)]
pub struct PackInspectCmd {
    /// Artifact reference (e.g., myapp:v1, registry.example.com/myapp:latest)
    #[arg(value_name = "REFERENCE")]
    pub reference: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

impl PackInspectCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let parsed = smolvm::registry::Reference::parse(&self.reference)
            .map_err(|e| Error::agent("parse reference", e.to_string()))?;
        let settings = smolvm::SmolSettings::load()?;
        let client = build_registry_client(&parsed.registry, &settings.machines)?;

        let repo = parsed.repository();
        let tag_or_digest = parsed
            .digest
            .as_deref()
            .or(parsed.tag.as_deref())
            .unwrap_or("latest");

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::agent("create tokio runtime", e.to_string()))?;

        rt.block_on(run_inspect(
            &client,
            &parsed,
            &repo,
            tag_or_digest,
            self.json,
        ))
    }
}

async fn run_inspect(
    client: &smolvm_registry::RegistryClient,
    parsed: &smolvm::registry::Reference,
    repo: &str,
    tag_or_digest: &str,
    json_output: bool,
) -> smolvm::Result<()> {
    // Fetch the OCI manifest (~200 bytes), resolving a multi-platform index to
    // this machine's host-platform entry — same as `pull`, so inspect agrees with
    // what pull would actually download instead of rejecting multi-arch tags.
    let manifest_bytes = client
        .get_manifest_resolved(repo, tag_or_digest)
        .await
        .map_err(|e| Error::agent("fetch manifest", e.to_string()))?;

    let oci_manifest: smolvm_registry::OciManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Error::agent("parse manifest", e.to_string()))?;

    // Extract layer size from OCI manifest.
    let layer_size = oci_manifest.layers.first().map(|l| l.size).unwrap_or(0);
    let layer_digest = oci_manifest
        .layers
        .first()
        .map(|l| l.digest.as_str())
        .unwrap_or("unknown");

    // Fetch config blob (~500 bytes) — contains the PackManifest.
    let config_bytes = client
        .pull_blob(repo, &oci_manifest.config.digest)
        .await
        .map_err(|e| Error::agent("fetch config", e.to_string()))?;

    let pack_manifest: smolvm_pack::PackManifest = serde_json::from_slice(&config_bytes)
        .map_err(|e| Error::agent("parse config", e.to_string()))?;

    if json_output {
        // Include layer size/digest in JSON output.
        let mut json_val: serde_json::Value = serde_json::to_value(&pack_manifest)
            .map_err(|e| Error::agent("serialize", e.to_string()))?;
        if let Some(obj) = json_val.as_object_mut() {
            obj.insert(
                "layer_size".to_string(),
                serde_json::Value::Number(layer_size.into()),
            );
            obj.insert(
                "layer_digest".to_string(),
                serde_json::Value::String(layer_digest.to_string()),
            );
        }
        let json_str = serde_json::to_string_pretty(&json_val)
            .map_err(|e| Error::agent("serialize inspect output", e.to_string()))?;
        println!("{}", json_str);
    } else {
        let full_ref = format!("{}/{}:{}", parsed.registry, repo, tag_or_digest);
        println!("Reference:  {}", full_ref);
        println!("Image:      {}", pack_manifest.image);
        println!("Platform:   {}", pack_manifest.platform);
        {
            let current = Platform::current().host_oci_platform();
            if pack_manifest.host_platform == current {
                println!("Host:       {}", pack_manifest.host_platform);
            } else {
                println!(
                    "Host:       {}  [incompatible — current platform: {}]",
                    pack_manifest.host_platform, current
                );
            }
        }
        println!("CPUs:       {}", pack_manifest.cpus);
        println!("Memory:     {} MiB", pack_manifest.mem);
        if !pack_manifest.entrypoint.is_empty() {
            println!("Entrypoint: {}", pack_manifest.entrypoint.join(" "));
        }
        if !pack_manifest.cmd.is_empty() {
            println!("Cmd:        {}", pack_manifest.cmd.join(" "));
        }
        if let Some(ref wd) = pack_manifest.workdir {
            println!("Workdir:    {}", wd);
        }
        println!("Created:    {}", pack_manifest.created);
        println!("Version:    {}", pack_manifest.smolvm_version);
        println!("Size:       {}", crate::cli::format_bytes(layer_size));
        println!("Digest:     {}", layer_digest);
    }

    Ok(())
}

/// Build a `RegistryClient` from a registry hostname, applying auth from config.
fn build_registry_client(
    registry: &str,
    config: &smolvm::registry::RegistryConfig,
) -> smolvm::Result<smolvm_registry::RegistryClient> {
    let effective = config.get_mirror(registry).unwrap_or(registry);

    // Docker Hub: the user-facing name is "docker.io" but the Distribution API
    // endpoint is "registry-1.docker.io". The config key stays "docker.io" so
    // credential lookup is consistent; only the HTTP endpoint changes.
    let api_host = match effective {
        "docker.io" => "registry-1.docker.io",
        h => h,
    };

    let base_url = if smolvm_registry::is_local_registry(api_host) {
        format!("http://{}", api_host)
    } else {
        format!("https://{}", api_host)
    };

    let mut client = smolvm_registry::RegistryClient::new(base_url);

    if let Some(entry) = config.registries.get(registry) {
        if let Some(identity_token) = &entry.identity_token {
            // Upstream credential (e.g. Auth0 JWT): exchanged with the token service
            // per-operation to obtain a short-lived OCI bearer token.
            client = client.with_identity_token(identity_token.clone());
        } else if let Some(auth) = config.get_credentials(registry) {
            if auth.username == "token" {
                // Legacy direct-bearer convention: username="token" means the
                // password value IS the bearer token, sent on every request.
                client = client.with_token(auth.password);
            } else {
                // Standard Docker/OCI path: username+password are sent as Basic auth
                // to the registry's token endpoint after a 401 Bearer challenge.
                // Used for Docker Hub, GHCR, ECR, GCR, ACR, Harbor, and Quay.
                client = client.with_basic_credentials(auth.username, auth.password);
            }
        }
    }

    Ok(client)
}

/// Format a byte count as a human-readable string (KB for < 1 MB, MB otherwise).
fn fmt_bytes(bytes: u64) -> String {
    if bytes < 1024 * 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} MB", bytes / (1024 * 1024))
    }
}

/// Read a qcow2 image's virtual (guest-visible) size from its header — the
/// big-endian `u64` at byte offset 24, per the qcow2 spec. Lets the flatten path
/// size its raw output correctly without a qcow2 library.
fn read_qcow2_virtual_size(path: &Path) -> smolvm::Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| Error::agent("open qcow2", e.to_string()))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .map_err(|e| Error::agent("read qcow2 magic", e.to_string()))?;
    if &magic != b"QFI\xfb" {
        return Err(Error::agent(
            "read qcow2",
            format!("{} is not a qcow2 image (bad magic)", path.display()),
        ));
    }
    f.seek(SeekFrom::Start(24))
        .map_err(|e| Error::agent("seek qcow2 size", e.to_string()))?;
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)
        .map_err(|e| Error::agent("read qcow2 size", e.to_string()))?;
    Ok(u64::from_be_bytes(buf))
}

/// A simple terminal spinner that prints a rotating character every 200ms.
/// Stops automatically on drop (error paths) or via explicit `stop()`.
struct Spinner {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Spinner {
    fn start(label: &str) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let label = label.to_string();

        let handle = std::thread::spawn(move || {
            let frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
            let mut i = 0;
            while !stop_clone.load(Ordering::Relaxed) {
                print!("\r{} {}\x1b[K", frames[i % frames.len()], label);
                let _ = std::io::Write::flush(&mut std::io::stdout());
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            print!("\r\x1b[K");
            println!("{} done", label);
        });

        Spinner {
            stop,
            handle: Some(handle),
        }
    }

    fn stop(self) {
        // Drop impl handles the actual shutdown
        drop(self);
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Calculate the total size of a directory (recursive).
fn dir_size(path: &std::path::Path) -> u64 {
    std::fs::read_dir(path)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| {
                    let meta = e.metadata().ok();
                    if e.path().is_dir() {
                        dir_size(&e.path())
                    } else {
                        meta.map(|m| m.len()).unwrap_or(0)
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that dladdr-based libkrun discovery finds the loaded library.
    ///
    /// This test works because the test binary links against libkrun the same
    /// way the smolvm binary does (via build.rs). If the library is loaded,
    /// find_loaded_libkrun_dir() must return its directory.
    #[test]
    fn find_loaded_libkrun_dir_returns_valid_path() {
        let dir = PackCreateCmd::find_loaded_libkrun_dir();

        // On CI without libkrun, the function returns None — that's fine,
        // the fallback search handles it. But when libkrun IS loaded
        // (which it is for any machine that can run smolvm), it must return
        // a valid directory containing the library.
        if let Some(ref dir) = dir {
            assert!(dir.exists(), "dladdr returned non-existent dir: {:?}", dir);

            let lib_name = smolvm::util::libkrun_filename();
            let lib_path = dir.join(lib_name);
            assert!(
                lib_path.exists(),
                "dladdr dir {:?} does not contain {}",
                dir,
                lib_name
            );
        }
        // If None, libkrun wasn't loaded (e.g., weak link + library not found).
        // This is expected in some CI environments and is not a failure.
    }

    // ── build_registry_client auth path selection ────────────────────────────

    #[test]
    fn build_registry_client_uses_identity_token_when_set() {
        let mut config = smolvm::registry::RegistryConfig::default();
        config.registries.insert(
            "registry.smolmachines.com".to_string(),
            smolvm::registry::RegistryEntry {
                identity_token: Some("eyJ_upstream_jwt".to_string()),
                ..Default::default()
            },
        );

        let client = build_registry_client("registry.smolmachines.com", &config).unwrap();
        assert_eq!(
            client.identity_token(),
            Some("eyJ_upstream_jwt"),
            "identity_token must be passed to with_identity_token()"
        );
    }

    #[test]
    fn build_registry_client_standard_credentials_use_basic_auth() {
        // A real username (not "token") triggers the Docker/OCI Basic challenge path.
        let mut config = smolvm::registry::RegistryConfig::default();
        config.registries.insert(
            "ghcr.io".to_string(),
            smolvm::registry::RegistryEntry {
                username: Some("github_user".to_string()),
                password: Some("ghp_secret".to_string()),
                ..Default::default()
            },
        );

        let client = build_registry_client("ghcr.io", &config).unwrap();
        assert_eq!(client.identity_token(), None);
        assert_eq!(
            client.basic_credentials(),
            Some(("github_user", "ghp_secret")),
            "standard username must route to with_basic_credentials()"
        );
    }

    #[test]
    fn build_registry_client_token_username_sends_direct_bearer() {
        // username="token" is the legacy direct-bearer convention.
        let mut config = smolvm::registry::RegistryConfig::default();
        config.registries.insert(
            "custom.registry.io".to_string(),
            smolvm::registry::RegistryEntry {
                username: Some("token".to_string()),
                password: Some("bearer_value".to_string()),
                ..Default::default()
            },
        );

        let client = build_registry_client("custom.registry.io", &config).unwrap();
        assert_eq!(client.identity_token(), None);
        assert_eq!(client.basic_credentials(), None);
    }

    #[test]
    fn build_registry_client_docker_hub_uses_api_endpoint() {
        // docker.io must map to registry-1.docker.io for Distribution API calls.
        let config = smolvm::registry::RegistryConfig::default();
        let client = build_registry_client("docker.io", &config).unwrap();
        assert_eq!(
            client.base_url(),
            "https://registry-1.docker.io",
            "docker.io must map to registry-1.docker.io"
        );
    }

    #[test]
    fn build_registry_client_identity_token_wins_over_password() {
        // When both are set (shouldn't happen in practice after set_credentials clears
        // identity_token, but we verify the precedence rule is enforced).
        let mut config = smolvm::registry::RegistryConfig::default();
        config.registries.insert(
            "registry.smolmachines.com".to_string(),
            smolvm::registry::RegistryEntry {
                username: Some("user".to_string()),
                password: Some("stale_password".to_string()),
                identity_token: Some("eyJ_identity".to_string()),
                ..Default::default()
            },
        );

        let client = build_registry_client("registry.smolmachines.com", &config).unwrap();
        assert_eq!(
            client.identity_token(),
            Some("eyJ_identity"),
            "identity_token must take precedence over password"
        );
    }
}
