//! Pack command for creating self-contained binaries.
//!
//! Creates a packed binary that contains:
//! - A stub executable
//! - Runtime libraries (libkrun, libkrunfw)
//! - Agent rootfs
//! - OCI image layers
//! - Configuration manifest

use clap::Args;
use smolvm::agent::{AgentClient, AgentManager, VmResources};
use smolvm::Error;
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::format::PackManifest;
use smolvm_pack::packer::Packer;
use smolvm_pack::signing::sign_with_hypervisor_entitlements;
use smolvm_protocol::AgentResponse;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Package an OCI image into a self-contained executable.
///
/// Creates a single binary that can be distributed and run without smolvm installed.
/// The packed binary includes:
/// - Runtime libraries (libkrun, libkrunfw)
/// - Agent rootfs
/// - OCI image layers
/// - Default configuration
///
/// Examples:
///   smolvm pack alpine:latest -o my-alpine
///   smolvm pack python:3.11-slim -o my-python --cpus 2 --mem 1024
///   smolvm pack myapp:latest -o myapp --entrypoint /app/run.sh
#[derive(Args, Debug)]
pub struct PackCmd {
    /// Container image to pack (e.g., alpine:latest, python:3.11-slim)
    #[arg(value_name = "IMAGE")]
    pub image: String,

    /// Output file path for the packed binary
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: PathBuf,

    /// Default number of vCPUs for the packed VM
    #[arg(long, default_value = "1", value_name = "N")]
    pub cpus: u8,

    /// Default memory in MiB for the packed VM
    #[arg(long, default_value = "256", value_name = "MiB")]
    pub mem: u32,

    /// Override the image entrypoint
    #[arg(long, value_name = "CMD")]
    pub entrypoint: Option<String>,

    /// Skip code signing (macOS only)
    #[arg(long)]
    pub no_sign: bool,

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
        info!(image = %self.image, output = %self.output.display(), "packing image");

        // Create temporary staging directory
        let temp_dir = tempfile::tempdir().map_err(|e| Error::AgentError(e.to_string()))?;
        let staging_dir = temp_dir.path().join("staging");

        // Start agent to pull image and export layers
        println!("Starting agent VM...");
        let manager = AgentManager::new_default()?;
        manager.start_with_config(
            Vec::new(),
            VmResources { cpus: 2, mem: 512 },
        )?;
        let mut client = manager.connect()?;

        // Pull image
        println!("Pulling {}...", self.image);
        let image_info = client.pull(&self.image, None)?;
        debug!(image_info = ?image_info, "image pulled");

        println!(
            "Image: {} ({} layers, {} bytes)",
            self.image, image_info.layer_count, image_info.size
        );

        // Create asset collector
        let mut collector = AssetCollector::new(staging_dir.clone())
            .map_err(|e| Error::AgentError(e.to_string()))?;

        // Find and collect libraries
        println!("Collecting runtime libraries...");
        let lib_dir = self.find_lib_dir()?;
        collector
            .collect_libraries(&lib_dir)
            .map_err(|e| Error::AgentError(e.to_string()))?;

        // Find and collect agent rootfs
        println!("Collecting agent rootfs...");
        let rootfs_dir = self.find_rootfs_dir()?;
        collector
            .collect_agent_rootfs(&rootfs_dir)
            .map_err(|e| Error::AgentError(e.to_string()))?;

        // Export and collect layers
        println!("Exporting {} layers...", image_info.layer_count);
        for (i, layer_digest) in image_info.layers.iter().enumerate() {
            println!("  Layer {}/{}: {}...", i + 1, image_info.layer_count, &layer_digest[..19]);

            // Export layer via agent
            let layer_data = self.export_layer(&mut client, &image_info.digest, i)?;

            // Add to collector
            collector
                .add_layer(layer_digest, &layer_data)
                .map_err(|e| Error::AgentError(e.to_string()))?;
        }

        // Stop agent
        manager.stop()?;

        // Build manifest
        let platform = format!("{}/{}", image_info.os, image_info.architecture);
        let mut manifest = PackManifest::new(self.image.clone(), image_info.digest.clone(), platform);
        manifest.cpus = self.cpus;
        manifest.mem = self.mem;

        // Set entrypoint if provided
        if let Some(ref ep) = self.entrypoint {
            manifest.entrypoint = vec![ep.clone()];
        }

        // Get stub executable path
        let stub_path = self.find_stub()?;

        // Update manifest with inventory
        manifest.assets = collector.into_inventory();

        // Recreate collector for compression (we consumed it above)
        let collector = AssetCollector::new(staging_dir)
            .map_err(|e| Error::AgentError(e.to_string()))?;

        // Pack the binary
        println!("Assembling packed binary...");
        let packer = Packer::new(manifest)
            .with_stub(&stub_path)
            .with_assets(collector);

        let info = packer
            .pack(&self.output)
            .map_err(|e| Error::AgentError(e.to_string()))?;

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
        }

        // Sign on macOS
        if cfg!(target_os = "macos") && !self.no_sign {
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
            println!("Note: Keep the .smoldata file alongside the binary");
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

        let lib_name = if cfg!(target_os = "macos") {
            "libkrun.dylib"
        } else {
            "libkrun.so"
        };

        for candidate in candidates.into_iter().flatten() {
            if candidate.join(lib_name).exists() {
                debug!(lib_dir = %candidate.display(), "found library directory");
                return Ok(candidate);
            }
        }

        Err(Error::AgentError(
            "Could not find libkrun library. Use --lib-dir to specify the location.".to_string(),
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
            if candidate.join("sbin/init").exists() {
                debug!(rootfs_dir = %candidate.display(), "found agent rootfs");
                return Ok(candidate);
            }
        }

        Err(Error::AgentError(
            "Could not find agent rootfs. Use --rootfs-dir to specify the location.".to_string(),
        ))
    }

    /// Find the stub executable.
    fn find_stub(&self) -> smolvm::Result<PathBuf> {
        if let Some(ref path) = self.stub {
            return Ok(path.clone());
        }

        // Check for pre-built stub
        let candidates = [
            // Build output
            Some(PathBuf::from("target/release/smolvm-stub")),
            Some(PathBuf::from("target/debug/smolvm-stub")),
            // Distribution
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("smolvm-stub"))),
            // User data dir
            dirs::data_dir().map(|d| d.join("smolvm/stubs/smolvm-stub")),
        ];

        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                debug!(stub = %candidate.display(), "found stub executable");
                return Ok(candidate);
            }
        }

        Err(Error::AgentError(
            "Could not find smolvm-stub executable. Build it with:\n  \
             cargo build --release -p smolvm-stub\n\
             Or use --stub to specify the path."
                .to_string(),
        ))
    }

    /// Export a layer from the agent.
    fn export_layer(
        &self,
        client: &mut AgentClient,
        image_digest: &str,
        layer_index: usize,
    ) -> smolvm::Result<Vec<u8>> {
        use smolvm_protocol::AgentRequest;

        let request = AgentRequest::ExportLayer {
            image_digest: image_digest.to_string(),
            layer_index,
        };

        client.send_raw(&request)?;

        let response = client.recv_raw()?;
        match response {
            AgentResponse::LayerData { data, done: true } => Ok(data),
            AgentResponse::LayerData { .. } => {
                Err(Error::AgentError("unexpected chunked response".to_string()))
            }
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response type".to_string())),
        }
    }
}
