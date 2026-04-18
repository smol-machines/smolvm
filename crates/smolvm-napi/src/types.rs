//! NAPI-visible types mirroring smolvm Rust types.
//!
//! These structs are exposed to JavaScript via `#[napi(object)]` and include
//! conversion impls to/from the corresponding smolvm types.

use napi_derive::napi;
use smolvm::agent::{ExecEvent as AgentExecEvent, HostMount, VmResources};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};

// ============================================================================
// Input types (JS → Rust)
// ============================================================================

/// Configuration for creating a machine.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct MachineConfig {
    /// Unique machine name. Used as the VM identifier.
    pub name: String,
    /// Host directories to mount into the VM.
    pub mounts: Option<Vec<HostMountConfig>>,
    /// Port mappings from host to guest.
    pub ports: Option<Vec<PortMappingConfig>>,
    /// VM resource allocation.
    pub resources: Option<VmResourcesConfig>,
    /// If true, the DB record is kept as a persistent machine.
    pub persistent: Option<bool>,
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
    /// Number of vCPUs (default: src/data/resources.rs default).
    pub cpus: Option<u8>,
    /// Memory in MiB (default: src/data/resources.rs default).
    pub memory_mib: Option<u32>,
    /// Enable outbound network access (default: false).
    pub network: Option<bool>,
    /// Storage disk size in GiB (default: 20).
    pub storage_gib: Option<f64>,
    /// Overlay disk size in GiB (default: 10).
    pub overlay_gib: Option<f64>,
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

/// Options for writing a file into the VM.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct FileWriteOptions {
    /// Optional octal file mode (for example, 0o644).
    pub mode: Option<u32>,
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

/// Event from a streaming exec session.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExecStreamEvent {
    /// Event kind: stdout, stderr, exit, or error.
    pub kind: String,
    /// Text payload for stdout/stderr events.
    pub data: Option<String>,
    /// Exit code for exit events.
    pub exit_code: Option<i32>,
    /// Error message for error events.
    pub message: Option<String>,
}

// ============================================================================
// Conversion impls
// ============================================================================

impl TryFrom<&HostMountConfig> for HostMount {
    type Error = smolvm::error::Error;

    fn try_from(m: &HostMountConfig) -> Result<Self, Self::Error> {
        HostMount::new(&m.source, &m.target, m.read_only.unwrap_or(true))
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
            cpus: self.cpus.unwrap_or(DEFAULT_MICROVM_CPU_COUNT),
            memory_mib: self.memory_mib.unwrap_or(DEFAULT_MICROVM_MEMORY_MIB),
            network: self.network.unwrap_or(false),
            network_backend: None,
            storage_gib: self.storage_gib.map(|g| g as u64),
            overlay_gib: self.overlay_gib.map(|g| g as u64),
            allowed_cidrs: None,
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

impl From<AgentExecEvent> for ExecStreamEvent {
    fn from(event: AgentExecEvent) -> Self {
        match event {
            AgentExecEvent::Stdout(data) => Self {
                kind: "stdout".to_string(),
                data: Some(String::from_utf8_lossy(&data).into_owned()),
                exit_code: None,
                message: None,
            },
            AgentExecEvent::Stderr(data) => Self {
                kind: "stderr".to_string(),
                data: Some(String::from_utf8_lossy(&data).into_owned()),
                exit_code: None,
                message: None,
            },
            AgentExecEvent::Exit(exit_code) => Self {
                kind: "exit".to_string(),
                data: None,
                exit_code: Some(exit_code),
                message: None,
            },
            AgentExecEvent::Error(message) => Self {
                kind: "error".to_string(),
                data: None,
                exit_code: None,
                message: Some(message),
            },
        }
    }
}

/// Parse ExecOptions into the components needed by AgentClient::vm_exec().
pub fn parse_exec_options(
    options: Option<ExecOptions>,
) -> (
    Vec<(String, String)>,
    Option<String>,
    Option<std::time::Duration>,
) {
    match options {
        Some(opts) => {
            let env = opts
                .env
                .map(|vars| vars.into_iter().map(|v| (v.key, v.value)).collect())
                .unwrap_or_default();

            let timeout = opts
                .timeout_secs
                .map(|s| std::time::Duration::from_secs(s as u64));

            (env, opts.workdir, timeout)
        }
        None => (Vec::new(), None, None),
    }
}
