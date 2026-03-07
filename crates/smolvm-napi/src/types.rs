//! NAPI-visible types mirroring smolvm Rust types.
//!
//! These structs are exposed to JavaScript via `#[napi(object)]` and include
//! conversion impls to/from the corresponding smolvm types.

use napi_derive::napi;
use smolvm::agent::{HostMount, PortMapping, VmResources};

// ============================================================================
// Input types (JS → Rust)
// ============================================================================

/// Configuration for creating a sandbox.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Unique sandbox name. Used as the VM identifier.
    pub name: String,
    /// Host directories to mount into the VM.
    pub mounts: Option<Vec<HostMountConfig>>,
    /// Port mappings from host to guest.
    pub ports: Option<Vec<PortMappingConfig>>,
    /// VM resource allocation.
    pub resources: Option<VmResourcesConfig>,
}

/// A host directory mount specification.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct HostMountConfig {
    /// Absolute path on the host.
    pub source: String,
    /// Absolute path inside the guest.
    pub target: String,
    /// Mount as read-only (default: true).
    pub read_only: Option<bool>,
}

/// A port mapping from host to guest.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct PortMappingConfig {
    /// Port on the host.
    pub host: u16,
    /// Port inside the guest.
    pub guest: u16,
}

/// VM resource allocation.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct VmResourcesConfig {
    /// Number of vCPUs (default: 1).
    pub cpus: Option<u8>,
    /// Memory in MiB (default: 512).
    pub memory_mb: Option<u32>,
    /// Enable outbound network access (default: false).
    pub network: Option<bool>,
    /// Storage disk size in GiB (default: 20).
    pub storage_gb: Option<f64>,
    /// Overlay disk size in GiB (default: 2).
    pub overlay_gb: Option<f64>,
}

/// Options for executing a command.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Environment variables as key-value pairs.
    pub env: Option<Vec<EnvVar>>,
    /// Working directory inside the VM/container.
    pub workdir: Option<String>,
    /// Timeout in seconds.
    pub timeout_secs: Option<u32>,
}

/// An environment variable key-value pair.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

// ============================================================================
// Output types (Rust → JS)
// ============================================================================

/// Result of executing a command.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Process exit code.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Information about a pulled/cached OCI image.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// Image reference (e.g., "alpine:latest").
    pub reference: String,
    /// Image digest (sha256:...).
    pub digest: String,
    /// Image size in bytes.
    pub size: f64,
    /// Platform architecture (e.g., "arm64").
    pub architecture: String,
    /// Platform OS (e.g., "linux").
    pub os: String,
}

// ============================================================================
// Conversion impls
// ============================================================================

impl From<&HostMountConfig> for HostMount {
    fn from(m: &HostMountConfig) -> Self {
        let mount = HostMount::new(&m.source, &m.target);
        if m.read_only.unwrap_or(true) {
            mount
        } else {
            mount.writable()
        }
    }
}

impl From<&PortMappingConfig> for PortMapping {
    fn from(p: &PortMappingConfig) -> Self {
        PortMapping::new(p.host, p.guest)
    }
}

impl VmResourcesConfig {
    pub fn to_vm_resources(&self) -> VmResources {
        VmResources {
            cpus: self.cpus.unwrap_or(1),
            mem: self.memory_mb.unwrap_or(512),
            network: self.network.unwrap_or(false),
            storage_gb: self.storage_gb.map(|g| g as u64),
            overlay_gb: self.overlay_gb.map(|g| g as u64),
        }
    }
}

impl From<smolvm_protocol::ImageInfo> for ImageInfo {
    fn from(info: smolvm_protocol::ImageInfo) -> Self {
        ImageInfo {
            reference: info.reference,
            digest: info.digest,
            size: info.size as f64,
            architecture: info.architecture,
            os: info.os,
        }
    }
}

/// Parse ExecOptions into the components needed by AgentClient::vm_exec().
pub fn parse_exec_options(
    options: &Option<ExecOptions>,
) -> (
    Vec<(String, String)>,
    Option<String>,
    Option<std::time::Duration>,
) {
    match options {
        Some(opts) => {
            let env = opts
                .env
                .as_ref()
                .map(|vars| {
                    vars.iter()
                        .map(|v| (v.key.clone(), v.value.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let workdir = opts.workdir.clone();

            let timeout = opts
                .timeout_secs
                .map(|s| std::time::Duration::from_secs(s as u64));

            (env, workdir, timeout)
        }
        None => (Vec::new(), None, None),
    }
}
