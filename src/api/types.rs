//! JSON request and response types for the API.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ============================================================================
// Machine Types
// ============================================================================

/// Restart policy specification for machine creation.
#[derive(Debug, Clone, Deserialize, Serialize, Default, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestartSpec {
    /// Restart policy: "never", "always", "on-failure", "unless-stopped".
    #[serde(default)]
    pub policy: Option<String>,
    /// Maximum restart attempts (0 = unlimited).
    #[serde(default)]
    pub max_retries: Option<u32>,
}

/// Mount specification (for requests).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct MountSpec {
    /// Host path to mount.
    #[schema(example = "/Users/me/code")]
    pub source: String,
    /// Path inside the machine.
    #[schema(example = "/workspace")]
    pub target: String,
    /// Read-only mount.
    #[serde(default)]
    pub readonly: bool,
}

/// Mount information (for responses, includes virtiofs tag).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MountInfo {
    /// Virtiofs tag (e.g., "smolvm0"). Use this in container mounts.
    #[schema(example = "smolvm0")]
    pub tag: String,
    /// Host path.
    #[schema(example = "/Users/me/code")]
    pub source: String,
    /// Path inside the machine.
    #[schema(example = "/workspace")]
    pub target: String,
    /// Read-only mount.
    pub readonly: bool,
}

/// Port mapping specification.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct PortSpec {
    /// Port on the host.
    #[schema(example = 8080)]
    pub host: u16,
    /// Port inside the machine.
    #[schema(example = 80)]
    pub guest: u16,
}

/// VM resource specification.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSpec {
    /// Number of vCPUs.
    #[serde(default)]
    #[schema(example = 2)]
    pub cpus: Option<u8>,
    /// Memory in MiB.
    #[serde(default)]
    #[schema(example = 1024)]
    pub memory_mb: Option<u32>,
    /// Enable outbound network access (TSI).
    /// Note: Only TCP/UDP supported, not ICMP (ping).
    #[serde(default)]
    pub network: Option<bool>,
    /// Storage disk size in GiB (default: 20).
    #[serde(default)]
    #[schema(example = 20)]
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB (default: 10).
    #[serde(default)]
    #[schema(example = 10)]
    pub overlay_gb: Option<u64>,
    /// Allowed egress CIDR ranges. When set, only these IP ranges are reachable.
    /// Omit for unrestricted egress. Empty list denies all egress.
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,
}

// ============================================================================
// Exec Types
// ============================================================================

/// Request to execute a command in a machine.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecRequest {
    /// Command and arguments.
    #[schema(example = json!(["echo", "hello"]))]
    pub command: Vec<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Working directory.
    #[serde(default)]
    #[schema(example = "/workspace")]
    pub workdir: Option<String>,
    /// Timeout in seconds.
    #[serde(default)]
    #[schema(example = 30)]
    pub timeout_secs: Option<u64>,
}

/// Environment variable.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct EnvVar {
    /// Variable name.
    #[schema(example = "MY_VAR")]
    pub name: String,
    /// Variable value.
    #[schema(example = "my_value")]
    pub value: String,
}

impl EnvVar {
    /// Convert a slice of EnvVar to (name, value) tuples for the agent protocol.
    pub fn to_tuples(env: &[EnvVar]) -> Vec<(String, String)> {
        env.iter()
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect()
    }
}

/// Command execution result.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecResponse {
    /// Exit code.
    #[schema(example = 0)]
    pub exit_code: i32,
    /// Standard output.
    #[schema(example = "hello\n")]
    pub stdout: String,
    /// Standard error.
    #[schema(example = "")]
    pub stderr: String,
}

/// Request to run a command in an image.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunRequest {
    /// Image to run in.
    #[schema(example = "python:3.12-alpine")]
    pub image: String,
    /// Command and arguments.
    #[schema(example = json!(["python", "-c", "print('hello')"]))]
    pub command: Vec<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Working directory.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Timeout in seconds.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

// ============================================================================
// Container Types
// ============================================================================

/// Request to create a container.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateContainerRequest {
    /// Image to use.
    #[schema(example = "alpine:latest")]
    pub image: String,
    /// Command and arguments.
    #[serde(default)]
    #[schema(example = json!(["sleep", "infinity"]))]
    pub command: Vec<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Working directory.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Volume mounts.
    #[serde(default)]
    pub mounts: Vec<ContainerMountSpec>,
}

/// Container mount specification.
///
/// Note: The `source` field is the virtiofs tag, which corresponds to
/// host mounts configured on the machine. Tags are assigned in order:
/// `smolvm0`, `smolvm1`, etc. based on the machine's mount configuration.
/// Use `GET /api/v1/machines/:id` to see the tag-to-path mapping.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ContainerMountSpec {
    /// Virtiofs tag (e.g., "smolvm0", "smolvm1").
    /// These correspond to machine mounts in order.
    #[schema(example = "smolvm0")]
    pub source: String,
    /// Target path in container.
    #[schema(example = "/app")]
    pub target: String,
    /// Read-only mount.
    #[serde(default)]
    pub readonly: bool,
}

/// Container information.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContainerInfo {
    /// Container ID.
    #[schema(example = "abc123")]
    pub id: String,
    /// Image.
    #[schema(example = "alpine:latest")]
    pub image: String,
    /// State (created, running, stopped).
    #[schema(example = "running")]
    pub state: String,
    /// Creation timestamp.
    pub created_at: u64,
    /// Command.
    pub command: Vec<String>,
}

/// List containers response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListContainersResponse {
    /// List of containers.
    pub containers: Vec<ContainerInfo>,
}

/// Request to exec in a container.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContainerExecRequest {
    /// Command and arguments.
    #[schema(example = json!(["ls", "-la"]))]
    pub command: Vec<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Working directory.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Timeout in seconds.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Request to stop a container.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StopContainerRequest {
    /// Timeout before force kill (seconds).
    #[serde(default)]
    #[schema(example = 10)]
    pub timeout_secs: Option<u64>,
}

/// Request to delete a container.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteContainerRequest {
    /// Force delete even if running.
    #[serde(default)]
    pub force: bool,
}

// ============================================================================
// Image Types
// ============================================================================

/// Image information.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageInfo {
    /// Image reference.
    #[schema(example = "alpine:latest")]
    pub reference: String,
    /// Image digest.
    #[schema(example = "sha256:abc123...")]
    pub digest: String,
    /// Size in bytes.
    #[schema(example = 7500000)]
    pub size: u64,
    /// Architecture.
    #[schema(example = "arm64")]
    pub architecture: String,
    /// OS.
    #[schema(example = "linux")]
    pub os: String,
    /// Number of layers.
    #[schema(example = 3)]
    pub layer_count: usize,
}

/// List images response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListImagesResponse {
    /// List of images.
    pub images: Vec<ImageInfo>,
}

/// Request to pull an image.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PullImageRequest {
    /// Image reference.
    #[schema(example = "python:3.12-alpine")]
    pub image: String,
    /// OCI platform for multi-arch images (e.g., "linux/arm64").
    #[serde(default)]
    #[schema(example = "linux/arm64")]
    pub oci_platform: Option<String>,
}

/// Pull image response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PullImageResponse {
    /// Information about the pulled image.
    pub image: ImageInfo,
}

// ============================================================================
// Logs Types
// ============================================================================

/// Query parameters for logs endpoint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LogsQuery {
    /// If true, follow the logs (like tail -f). Default: false.
    #[serde(default)]
    pub follow: bool,
    /// Number of lines to show from the end (like tail -n). Default: all.
    #[serde(default)]
    #[schema(example = 100)]
    pub tail: Option<usize>,
}

// ============================================================================
// Delete Types
// ============================================================================

/// Query parameters for delete machine endpoint.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DeleteQuery {
    /// If true, force delete even if stop fails and VM is still running.
    /// This may orphan the VM process. Default: false.
    #[serde(default)]
    pub force: bool,
}

// ============================================================================
// Health Types
// ============================================================================

/// Health check response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Health status (e.g., "ok").
    #[schema(example = "ok")]
    pub status: &'static str,
    /// Server version.
    #[schema(example = "0.1.6")]
    pub version: &'static str,
}

// ============================================================================
// Error Types
// ============================================================================

/// API error response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiErrorResponse {
    /// Error message.
    #[schema(example = "machine 'test' not found")]
    pub error: String,
    /// Error code.
    #[schema(example = "NOT_FOUND")]
    pub code: String,
}

// ============================================================================
// Machine Types
// ============================================================================

fn default_cpus() -> u8 {
    1
}

fn default_mem() -> u32 {
    512
}

/// Request to create a new machine.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateMachineRequest {
    /// Unique name for the machine.
    #[schema(example = "my-vm")]
    pub name: String,
    /// Number of vCPUs.
    #[serde(default = "default_cpus")]
    #[schema(example = 2)]
    pub cpus: u8,
    /// Memory in MiB.
    #[serde(default = "default_mem", rename = "memoryMb")]
    #[schema(example = 1024)]
    pub mem: u32,
    /// Host mounts to attach.
    #[serde(default)]
    pub mounts: Vec<MountSpec>,
    /// Port mappings (host:guest).
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// Enable outbound network access (TSI).
    /// Note: Only TCP/UDP supported, not ICMP (ping).
    #[serde(default)]
    pub network: bool,
    /// Storage disk size in GiB (default: 20).
    #[serde(default)]
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB (default: 10).
    #[serde(default)]
    pub overlay_gb: Option<u64>,
    /// Allowed egress CIDR ranges.
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,
}

/// Request to execute a command in a machine.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineExecRequest {
    /// Command and arguments.
    #[schema(example = json!(["echo", "hello"]))]
    pub command: Vec<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Working directory.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Timeout in seconds.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Machine status information.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineInfo {
    /// Machine name.
    #[schema(example = "my-vm")]
    pub name: String,
    /// Current state ("created", "running", "stopped").
    #[schema(example = "running")]
    pub state: String,
    /// Number of vCPUs.
    #[schema(example = 2)]
    pub cpus: u8,
    /// Memory in MiB.
    #[serde(rename = "memoryMb")]
    #[schema(example = 1024)]
    pub mem: u32,
    /// Process ID (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 12345)]
    pub pid: Option<i32>,
    /// Configured mounts (with virtiofs tags for container use).
    pub mounts: Vec<MountInfo>,
    /// Configured port mappings.
    pub ports: Vec<PortSpec>,
    /// Whether outbound network access is enabled.
    pub network: bool,
    /// Storage disk size in GiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 20)]
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 2)]
    pub overlay_gb: Option<u64>,
    /// Creation timestamp.
    pub created_at: String,
}

/// List machines response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListMachinesResponse {
    /// List of machines.
    pub machines: Vec<MachineInfo>,
}

/// Generic delete response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteResponse {
    /// Name of deleted resource.
    #[schema(example = "my-machine")]
    pub deleted: String,
}

/// Generic start response.
#[derive(Debug, Serialize, ToSchema)]
pub struct StartResponse {
    /// Identifier of started resource.
    #[schema(example = "abc123")]
    pub started: String,
}

/// Generic stop response.
#[derive(Debug, Serialize, ToSchema)]
pub struct StopResponse {
    /// Identifier of stopped resource.
    #[schema(example = "abc123")]
    pub stopped: String,
}

// ============================================================================
// Resize Types
// ============================================================================

/// Request to resize a machine's disk resources.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResizeMachineRequest {
    /// Storage disk size in GiB (expand only, optional).
    #[serde(default)]
    #[schema(example = 50)]
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB (expand only, optional).
    #[serde(default)]
    #[schema(example = 20)]
    pub overlay_gb: Option<u64>,
}
