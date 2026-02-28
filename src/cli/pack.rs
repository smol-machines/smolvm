//! Pack command for creating self-contained binaries.
//!
//! Creates a packed binary that contains:
//! - A stub executable
//! - Runtime libraries (libkrun, libkrunfw)
//! - Agent rootfs
//! - OCI image layers
//! - Configuration manifest

use clap::Args;
use smolvm::agent::{AgentClient, AgentManager, PullOptions, VmResources};

/// Default memory for packed VMs (lower than sandbox/microvm because
/// packed VMs are typically single-purpose, minimal workloads).
const PACK_DEFAULT_MEMORY_MIB: u32 = 256;
use smolvm::config::{RecordState, SmolvmConfig};
use smolvm::platform::{Arch, Os, VmExecutor};
use smolvm::Error;
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::format::{PackManifest, PackMode};
use smolvm_pack::packer::Packer;
use smolvm_pack::signing::sign_with_hypervisor_entitlements;
use smolvm_protocol::AgentResponse;
use std::path::PathBuf;
use tracing::{debug, info, warn};

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
///   smolvm pack alpine:latest -o my-alpine
///   smolvm pack python:3.11-slim -o my-python --cpus 2 --mem 1024
///   smolvm pack myapp:latest -o myapp --entrypoint /app/run.sh
///   smolvm pack --from-vm myvm -o my-devenv
#[derive(Args, Debug)]
pub struct PackCmd {
    /// Container image to pack (e.g., alpine:latest, python:3.11-slim)
    #[arg(
        value_name = "IMAGE",
        required_unless_present = "from_vm",
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
    #[arg(long, default_value_t = smolvm::agent::DEFAULT_CPUS, value_name = "N")]
    pub cpus: u8,

    /// Default memory in MiB for the packed VM (lower than sandbox/microvm
    /// because packed VMs are typically single-purpose, minimal workloads)
    #[arg(long, default_value_t = PACK_DEFAULT_MEMORY_MIB, value_name = "MiB")]
    pub mem: u32,

    /// Target platform for multi-arch images (e.g., linux/arm64, linux/amd64)
    ///
    /// By default, uses the host architecture. Use this to override, for example
    /// to pack x86_64 images for Rosetta on Apple Silicon.
    #[arg(long, value_name = "OS/ARCH")]
    pub platform: Option<String>,

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
}

impl PackCmd {
    pub fn run(self) -> smolvm::Result<()> {
        if let Some(vm_name) = self.from_vm.clone() {
            info!(vm = %vm_name, output = %self.output.display(), "packing from VM");
            return self.pack_from_vm(vm_name);
        }

        let image = self.image.clone().unwrap();
        info!(image = %image, output = %self.output.display(), "packing image");

        // Create temporary staging directory
        let temp_dir = tempfile::tempdir()
            .map_err(|e| Error::agent("create temp directory", e.to_string()))?;
        let staging_dir = temp_dir.path().join("staging");

        // Start a temporary agent VM with a unique identity so concurrent
        // pack runs and the user's "default" VM don't collide.
        // Use PID + epoch nanos to avoid PID-reuse collisions with orphaned VMs.
        let pack_vm_name = format!(
            "__pack_{}_{}",
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
                cpus: 2,
                mem: 512,
                network: true,
                storage_gb: None,
                overlay_gb: None,
            },
        )?;
        let mut guard = PackVmGuard {
            manager,
            data_dir: vm_data_dir,
            finalized: false,
        };
        let mut client = guard.manager.connect()?;

        // Pull image
        println!("Pulling {}...", image);
        let mut pull_opts = PullOptions::new().use_registry_config(true);
        if let Some(ref platform) = self.platform {
            pull_opts = pull_opts.platform(platform);
        }
        let image_info = client.pull(&image, pull_opts)?;
        debug!(image_info = ?image_info, "image pulled");

        println!(
            "Image: {} ({} layers, {} bytes)",
            image, image_info.layer_count, image_info.size
        );

        // Create asset collector and collect base assets
        let mut collector = AssetCollector::new(staging_dir.clone())
            .map_err(|e| Error::agent("collect assets", e.to_string()))?;
        self.collect_base_assets(&mut collector)?;

        // Export and collect layers
        println!("Exporting {} layers...", image_info.layer_count);
        for (i, layer_digest) in image_info.layers.iter().enumerate() {
            println!(
                "  Layer {}/{}: {}...",
                i + 1,
                image_info.layer_count,
                &layer_digest[..19]
            );

            // Export layer via agent
            let layer_data = self.export_layer(&mut client, &image_info.digest, i)?;

            // Add to collector
            collector
                .add_layer(layer_digest, &layer_data)
                .map_err(|e| Error::agent("collect layers", e.to_string()))?;
        }

        // Stop agent and clean up temp VM data. Propagates stop errors
        // so pack fails visibly if VM cannot be stopped.
        guard.stop_and_cleanup()?;

        // Build manifest
        let platform = format!("{}/{}", image_info.os, image_info.architecture);
        let mut manifest = PackManifest::new(image, image_info.digest.clone(), platform);
        manifest.cpus = self.cpus;
        manifest.mem = self.mem;

        // Copy OCI config fields from image (CMD, ENTRYPOINT, ENV, WORKDIR)
        manifest.entrypoint = image_info.entrypoint.clone();
        manifest.cmd = image_info.cmd.clone();
        manifest.env = image_info.env.clone();
        manifest.workdir = image_info.workdir.clone();

        // Override entrypoint if user provided one
        if let Some(ref ep) = self.entrypoint {
            manifest.entrypoint = vec![ep.clone()];
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
                    "VM '{}' is running. Stop it first with: smolvm microvm stop {}",
                    vm_name, vm_name
                ),
            ));
        }

        // 2. Locate overlay disk
        let overlay_path = smolvm::agent::vm_data_dir(&vm_name).join("overlay.raw");
        if !overlay_path.exists() {
            return Err(Error::agent(
                "pack from VM",
                format!(
                    "overlay disk not found at {}. The VM may not have been started yet.",
                    overlay_path.display()
                ),
            ));
        }

        println!("Packing VM '{}' snapshot...", vm_name);

        // 3. Create temporary staging directory
        let temp_dir = tempfile::tempdir()
            .map_err(|e| Error::agent("create temp directory", e.to_string()))?;
        let staging_dir = temp_dir.path().join("staging");

        // 4. Collect base assets + overlay template
        let mut collector = AssetCollector::new(staging_dir.clone())
            .map_err(|e| Error::agent("collect assets", e.to_string()))?;
        self.collect_base_assets(&mut collector)?;

        // Add overlay template from VM
        println!("Copying overlay disk ({})...", overlay_path.display());
        collector
            .add_overlay_template(&overlay_path)
            .map_err(|e| Error::agent("collect overlay", e.to_string()))?;

        // 5. Build manifest
        let platform = format!("linux/{}", Arch::current().oci_arch());
        let mut manifest =
            PackManifest::new(format!("vm://{}", vm_name), "none".to_string(), platform);
        manifest.mode = PackMode::Vm;
        manifest.cpus = self.cpus;
        manifest.mem = self.mem;
        manifest.entrypoint = vec!["/bin/sh".to_string()];

        // Inherit env/workdir from VmRecord
        manifest.env = vm.env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        manifest.workdir = vm.workdir.clone();

        // Override entrypoint if user provided one
        if let Some(ref ep) = self.entrypoint {
            manifest.entrypoint = vec![ep.clone()];
        }

        self.finalize_pack(manifest, collector, staging_dir)
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

        let collector = AssetCollector::new(staging_dir)
            .map_err(|e| Error::agent("collect assets", e.to_string()))?;

        let packer = Packer::new(manifest)
            .with_stub(&stub_path)
            .with_asset_collector(collector);

        let info = if self.single_file {
            println!("Assembling single-file packed binary...");
            packer
                .pack_embedded(&self.output)
                .map_err(|e| Error::agent("pack binary", e.to_string()))?
        } else {
            println!("Assembling packed binary...");
            packer
                .pack(&self.output)
                .map_err(|e| Error::agent("pack binary", e.to_string()))?
        };

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

        // Check common locations
        let candidates = [
            // Relative to executable
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("lib"))),
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().and_then(|d| d.parent()).map(|d| d.join("lib"))),
            // Source tree
            Some(PathBuf::from("lib")),
            Some(PathBuf::from("./lib")),
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
            "could not find libkrun library. Use --lib-dir to specify the location.",
        ))
    }

    /// Find the agent rootfs directory.
    fn find_rootfs_dir(&self) -> smolvm::Result<PathBuf> {
        if let Some(ref dir) = self.rootfs_dir {
            return Ok(dir.clone());
        }

        // Check common locations
        let candidates = [
            // Build output
            Some(PathBuf::from("target/agent-rootfs/rootfs")),
            // Distribution
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("agent-rootfs"))),
            // User data dir
            dirs::data_dir().map(|d| d.join("smolvm/agent-rootfs")),
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
    /// We accumulate them into a single `Vec<u8>`.
    fn export_layer(
        &self,
        client: &mut AgentClient,
        image_digest: &str,
        layer_index: usize,
    ) -> smolvm::Result<Vec<u8>> {
        use smolvm_protocol::AgentRequest;
        use std::time::{Duration, Instant};

        const LAYER_EXPORT_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes

        let request = AgentRequest::ExportLayer {
            image_digest: image_digest.to_string(),
            layer_index,
        };

        // Extend socket read timeout for the duration of the export.
        // The default 30s timeout would fire before our wall-clock guard
        // if the agent stalls between chunks.
        let _timeout_guard = client.set_extended_read_timeout(LAYER_EXPORT_TIMEOUT)?;

        client.send_raw(&request)?;

        let start = Instant::now();
        let mut result = Vec::new();
        loop {
            if start.elapsed() > LAYER_EXPORT_TIMEOUT {
                return Err(Error::agent(
                    "export layer",
                    format!(
                        "layer export timed out after {}s (received {} bytes so far)",
                        LAYER_EXPORT_TIMEOUT.as_secs(),
                        result.len()
                    ),
                ));
            }

            let response = client.recv_raw()?;
            match response {
                AgentResponse::LayerData { data, done } => {
                    result.extend_from_slice(&data);
                    if done {
                        return Ok(result);
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
