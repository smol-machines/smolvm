//! JSON request and response types for the API.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

/// Map of guest-side env var names to secret refs.
///
/// Present on every exec-like endpoint and on `CreateMachineRequest`.
/// Every entry is validated under `ResolutionScope::Untrusted` before
/// it's acted on — the HTTP API treats every caller as untrusted
/// regardless of where the server is bound, so no ref source kind is
/// accepted — `from_env` and `from_file` are both rejected with 400.
/// Configure secrets locally via the CLI instead.
///
/// Capped at `MAX_REQ_SECRETS_PER_REQUEST` entries per request.
pub type RequestSecretRefs = BTreeMap<String, smolvm_protocol::SecretRef>;

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
    /// Enable GPU acceleration (Vulkan via virtio-gpu).
    #[serde(default)]
    pub gpu: Option<bool>,
    /// Enable CUDA remoting (the guest sees the host NVIDIA GPU through the
    /// bundled shims). Required on a golden that fork clones will train on.
    #[serde(default)]
    pub cuda: Option<bool>,
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
    /// Allowed egress hostnames. When set, DNS answers for these names (and their
    /// subdomains) are learned into the egress allow-list so the machine can reach
    /// them by name. Combine with `allowed_cidrs` to also permit fixed ranges.
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Network backend: `tsi` (outbound-only) or `virtio-net`.
    ///
    /// When omitted the backend is chosen from context: machines managed by
    /// `smolvm serve` (every API machine), machines with published `ports`,
    /// an egress policy (`allowedCidrs`/`allowedHosts`) or fleet mode default
    /// to `virtio-net`; only outbound-only machines launched outside `serve`
    /// (plain CLI) default to `tsi`. Set `tsi` explicitly to force the
    /// lighter outbound-only backend (rejected alongside published `ports`).
    #[serde(default)]
    pub network_backend: Option<crate::network::NetworkBackend>,
}

// ============================================================================
// Exec Types
// ============================================================================

/// Request to execute a command in a machine.
///
/// `deny_unknown_fields`: an unknown or mis-cased field is a hard 400, not a
/// silent no-op. This matters for the safety fields (`timeoutSecs`, etc.) — a
/// caller who writes `timeout_secs` must be told, not left running an untrusted
/// command with no timeout because the field was quietly dropped.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecRequest {
    /// Command and arguments.
    #[schema(example = json!(["echo", "hello"]))]
    pub command: Vec<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Ad-hoc secret refs. Rejected unless empty: an untrusted HTTP
    /// caller cannot read this host's env/files. See `RequestSecretRefs`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub secrets: RequestSecretRefs,
    /// Working directory.
    #[serde(default)]
    #[schema(example = "/workspace")]
    pub workdir: Option<String>,
    /// Timeout in seconds.
    #[serde(default)]
    #[schema(example = 30)]
    pub timeout_secs: Option<u64>,
    /// Data to pipe to the command's stdin.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Run the command detached: spawn it in the background and return its PID
    /// immediately instead of waiting. The process keeps running (a long-lived
    /// daemon — dev server, agent runner) until it exits or the machine stops.
    #[serde(default)]
    pub background: bool,
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
///
/// **Encoding note**: `stdout`/`stderr` are a lossy UTF-8 view (non-UTF-8 bytes
/// become U+FFFD) kept for older clients. `stdoutB64`/`stderrB64` carry the raw,
/// byte-exact output (base64) and should be preferred by callers that need
/// binary-safe results (image bytes, tarballs, etc.) — the agent preserves
/// bytes end-to-end and these fields do too.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecResponse {
    /// Exit code.
    #[schema(example = 0)]
    pub exit_code: i32,
    /// Standard output, lossy UTF-8 (non-UTF-8 bytes → U+FFFD). Prefer `stdoutB64`.
    #[schema(example = "hello\n")]
    pub stdout: String,
    /// Standard error, lossy UTF-8 (non-UTF-8 bytes → U+FFFD). Prefer `stderrB64`.
    #[schema(example = "")]
    pub stderr: String,
    /// Raw stdout bytes, base64-encoded — byte-exact, binary-safe.
    #[serde(with = "smolvm_protocol::base64_bytes")]
    #[schema(value_type = String)]
    pub stdout_b64: Vec<u8>,
    /// Raw stderr bytes, base64-encoded — byte-exact, binary-safe.
    #[serde(with = "smolvm_protocol::base64_bytes")]
    #[schema(value_type = String)]
    pub stderr_b64: Vec<u8>,
}

/// Request to export a stopped machine to a `.smolmachine` and push it to a
/// registry. The control plane mints a pre-scoped OCI bearer (`push_token`)
/// that authorizes the write against `reference_host`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    /// Repository to push into (e.g. `tenant/my-machine`).
    #[schema(example = "tenant/my-machine")]
    pub repo: String,
    /// Tag to push under (e.g. `latest`).
    #[schema(example = "latest")]
    pub tag: String,
    /// Pre-scoped OCI bearer token minted by the control plane.
    pub push_token: String,
    /// Registry host to push to (e.g. `registry.smolmachines.com`).
    #[schema(example = "registry.smolmachines.com")]
    pub reference_host: String,
}

/// Result of exporting a machine to a registry.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExportResponse {
    /// Digest of the pushed OCI manifest (reference as `repo@<digest>`).
    #[schema(example = "sha256:abc123")]
    pub digest: String,
    /// Size of the `.smolmachine` sidecar blob in bytes.
    #[schema(example = 104857600)]
    pub size_bytes: u64,
    /// Host platform the artifact targets (e.g. `linux/amd64`).
    #[schema(example = "linux/amd64")]
    pub platform: String,
    /// The `PackManifest` JSON carried in the sidecar footer.
    pub manifest: String,
}

/// Request to pull a `.smolmachine` artifact into this node's blob cache ahead
/// of any machine that needs it. See [`crate::api::handlers::prewarm`].
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WarmArtifactRequest {
    /// Full registry reference of the artifact to cache.
    #[schema(example = "registry.example.com/tenants/t/app:latest")]
    pub reference: String,
    /// Short-lived, scoped registry token authorizing the pull. Omitted for a
    /// reference this node already holds a persisted credential for.
    #[serde(default)]
    pub identity_token: Option<String>,
    /// Sibling nodes to try before the registry, same as the create path. Warming
    /// the second and later nodes from a peer keeps the fan-out off the registry
    /// link entirely.
    #[serde(default)]
    pub blob_peers: Vec<String>,
}

/// Result of pre-warming an artifact into the node's blob cache.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WarmArtifactResponse {
    /// Digest of the cached layer blob.
    #[schema(example = "sha256:abc123")]
    pub digest: String,
    /// Size of the cached layer blob in bytes.
    #[schema(example = 104857600)]
    pub size_bytes: u64,
    /// True when the blob was already cached and no transfer was needed — the
    /// signal that a repeat warm cost nothing.
    pub already_cached: bool,
}

/// Request to run a command in an image.
///
/// `deny_unknown_fields`: like `ExecRequest`, a mis-cased safety field
/// (`timeout_secs` for `timeoutSecs`) is a 400, never a silent drop.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    /// Ad-hoc secret refs. Rejected unless empty (untrusted scope).
    #[serde(default)]
    #[schema(value_type = Object)]
    pub secrets: RequestSecretRefs,
    /// Working directory.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Timeout in seconds.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
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
    /// Proxy URL applied to the in-VM registry client
    /// (sets HTTP_PROXY and HTTPS_PROXY).
    #[serde(default)]
    #[schema(example = "http://192.168.127.254:3128")]
    pub proxy: Option<String>,
    /// Comma-separated NO_PROXY list of hosts/CIDRs that bypass the proxy.
    #[serde(default)]
    #[schema(example = "127.0.0.1,localhost,.internal")]
    pub no_proxy: Option<String>,
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
    /// Output format: "raw" (default) or "json" (only emit valid JSON lines).
    #[serde(default)]
    pub format: Option<String>,
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
    /// If true, also delete any clones forked from this machine before removing
    /// it. A fork base cannot be removed while its clones' overlays depend on
    /// its disks; cascade removes those clones first. Default: false.
    #[serde(default)]
    pub cascade: bool,
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
    #[schema(example = "0.5.2")]
    pub version: &'static str,
    /// Machine counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machines: Option<MachineCountsResponse>,
    /// Server uptime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
}

/// Machine counts for health response.
#[derive(Debug, Serialize, ToSchema)]
pub struct MachineCountsResponse {
    /// Total machines in the database.
    pub total: usize,
    /// Currently running machines.
    pub running: usize,
}

/// Live node capacity: current allocations and real utilization across all
/// running machines on this host. Read-only introspection — a fleet control
/// plane (or any operator) polls this to gauge node load. The reporter owns
/// totals/reserved; this endpoint reports only what the runtime itself knows.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CapacityResponse {
    /// CPUs allocated to running machines (sum of per-machine cpu requests).
    pub allocated_cpus: u32,
    /// Memory (MB) allocated to running machines.
    pub allocated_memory_mb: u64,
    /// Real fractional CPU load across VM processes (e.g. 2.5 = 2.5 CPUs).
    pub used_cpus: f64,
    /// Real resident memory (MB) across VM processes.
    pub used_memory_mb: u64,
    /// Real disk (GB) consumed by VM storage + overlay files.
    pub used_disk_gb: u64,
    /// Opaque id minted once per serve process. It changes iff the serve restarts
    /// — the signal the control uses to detect that this node's warm pool (and any
    /// in-memory VM state) was wiped, so it can prune the now-stale pool records.
    #[serde(default)]
    pub boot_id: String,
    /// CUDA devices currently visible to this runtime. Omitted when NVML is
    /// unavailable, no CUDA device is visible, or the latest sample failed.
    /// Device ordinals use the same CUDA-visible ordering as
    /// `SMOLVM_CUDA_DEVICE` and fork-pool admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cuda_devices: Option<Vec<CudaDeviceCapacity>>,
}

/// Live capacity and identity for one host CUDA device.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CudaDeviceCapacity {
    /// CUDA-visible ordinal used to assign a machine or pool to this device.
    pub ordinal: u32,
    /// Stable NVIDIA GPU or MIG UUID.
    pub uuid: String,
    /// Device model reported by NVML.
    pub name: String,
    /// Current streaming-multiprocessor utilization percentage.
    pub utilization_percent: f64,
    /// Current device-memory usage in MiB.
    pub memory_used_mib: u64,
    /// Current free device memory in MiB.
    pub memory_free_mib: u64,
    /// Total device-memory capacity in MiB.
    pub memory_total_mib: u64,
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

/// Request to create a new machine.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateMachineRequest {
    /// Machine name. Auto-generated if omitted.
    #[serde(default)]
    #[schema(example = "my-vm")]
    pub name: Option<String>,
    /// Number of vCPUs.
    #[serde(default)]
    #[schema(example = 4)]
    pub cpus: Option<u8>,
    /// Memory in MiB.
    #[serde(default, rename = "memoryMb")]
    #[schema(example = 8192)]
    pub mem: Option<u32>,
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
    /// Enable GPU acceleration (Vulkan via virtio-gpu).
    #[serde(default)]
    pub gpu: bool,
    /// Enable CUDA remoting (host NVIDIA GPU via the bundled shims).
    #[serde(default)]
    pub cuda: bool,
    /// Ask compatible CUDA frameworks to graph safe compiled regions.
    /// Implies CUDA; arbitrary eager CUDA calls are not captured.
    #[serde(default)]
    pub auto_graph: bool,
    /// Workload entrypoint. With `cmd`, overrides the image's (or the
    /// `.smolmachine` artifact's) own entrypoint+cmd, matching the CLI's
    /// `machine create -- <command>` precedence. Empty = use the image's.
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Workload command run when the machine starts (see `entrypoint`).
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Expose the guest's Docker daemon socket to the host as a Unix socket in
    /// the VM data dir, so a host client can drive it with `DOCKER_HOST=unix://…`.
    /// Off by default.
    #[serde(default)]
    pub docker_socket: bool,
    /// Storage disk size in GiB (default: 20).
    #[serde(default)]
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB (default: 10).
    #[serde(default)]
    pub overlay_gb: Option<u64>,
    /// Allowed egress CIDR ranges.
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,
    /// Allowed egress hostnames (and their subdomains); DNS answers for these
    /// names are learned into the egress allow-list.
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Network backend: `tsi` (outbound-only) or `virtio-net`.
    ///
    /// When omitted, machines created through the API default to `virtio-net`:
    /// the server configures a guest host-service (the rollout ingress), and
    /// published `ports`, egress policies and fleet mode need virtio-net too.
    /// (`tsi` is the default only for outbound-only machines launched outside
    /// `smolvm serve`.) Set `tsi` explicitly for the lighter outbound-only
    /// backend; published `ports` require `virtio-net` (TSI has no inbound
    /// path), so that combination is rejected.
    #[serde(default)]
    pub network_backend: Option<crate::network::NetworkBackend>,
    /// Restart policy configuration.
    #[serde(default)]
    pub restart: Option<RestartSpec>,
    /// OCI image reference (e.g., "alpine:latest"). Mutually exclusive with `from`.
    #[serde(default)]
    pub image: Option<String>,
    /// Path to a .smolmachine sidecar file. Creates the machine from pre-packed
    /// layers instead of pulling from a registry. Mutually exclusive with `image`.
    #[serde(default)]
    pub from: Option<String>,
    /// Registry reference to a .smolmachine artifact (e.g., "myapp:v1").
    /// Pulls from the registry before creating the VM.
    /// Mutually exclusive with `image` and `from`.
    #[serde(default)]
    pub registry_ref: Option<String>,
    /// Bearer credential (an OCI Distribution `identity_token`) to present when
    /// pulling `registry_ref`. The control plane supplies a short-lived,
    /// tenant-scoped token here so a node can fetch a tenant's private
    /// `.smolmachine`. Takes precedence over any persisted registry credential.
    #[serde(default)]
    pub registry_identity_token: Option<String>,
    /// Brokered P2P blob peers: node base URLs (`https://<addr>:<port>`) supplied
    /// by the control plane. On a cache miss the layer blob is fetched from a
    /// peer's `GET /p2p/blob/<digest>` (over node→node mTLS) before the registry.
    /// Empty (the default) ⇒ registry-only, byte-for-byte as before.
    #[serde(default)]
    pub blob_peers: Vec<String>,
    /// Secret refs attached to the machine. Resolved at every
    /// subsequent exec against the host's env/files. Rejected unless empty;
    /// accepted — `from_env`/`from_file` on the API surface would let
    /// an untrusted caller exfiltrate the server process's env or
    /// read arbitrary host files; use the CLI `machine create` path
    /// for those source kinds.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub secrets: RequestSecretRefs,
    /// Environment variables for the machine's workload (init commands and the
    /// entrypoint). For `from`/`registry_ref` machines these layer on top of
    /// the artifact manifest's env; a request variable wins on name collision.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Working directory for the machine's workload. Overrides the artifact
    /// manifest's workdir when set.
    #[serde(default)]
    pub workdir: Option<String>,
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
    /// Whether Vulkan/graphics GPU acceleration is enabled for this machine.
    pub gpu: bool,
    /// Whether transparent CUDA remoting is enabled for this machine.
    pub cuda: bool,
    /// Network backend the machine runs (`tsi` or `virtio-net`). Echoes back
    /// what `create` accepted; omitted when `create` left it unset (the
    /// launch then picks the contextual default — `virtio-net` under
    /// `smolvm serve`, with ports, or with an egress policy; `tsi` otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_backend: Option<crate::network::NetworkBackend>,
    /// Allowed egress CIDRs. Omitted when unrestricted; an empty list denies all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_cidrs: Option<Vec<String>>,
    /// Allowed egress hostnames. Omitted when unset. Echoes back what `create` accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<String>>,
    /// Storage disk size in GiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 20)]
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 2)]
    pub overlay_gb: Option<u64>,
    /// Whether ordinary starts launch this machine as a fork base.
    pub forkable: bool,
    /// Planned runnable CUDA clone count used for automatic capacity budgeting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cuda_fork_pool_size: Option<u32>,
    /// Explicit logical CUDA memory limit per golden/clone session, in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cuda_vram_limit_mib: Option<u64>,
    /// True while this clone is an already-booted clean slot parked at the
    /// workload forkpoint and available for one assignment.
    pub forkpoint_held: bool,
    /// Cumulative guest-outbound (egress) bytes since boot, for billing. Present
    /// only for virtio-net machines that have reported a value; omitted for TSI
    /// or machines that haven't flushed yet. Surfaced the same way `storage_gb`
    /// is, so the control plane reads both from the machine list.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 1048576)]
    pub egress_bytes: Option<u64>,
    /// Consumed CPU-seconds (user+system) of the machine's CURRENT VMM process,
    /// sampled live from the host. Resets to 0 on a VM restart — it's a stateless
    /// snapshot; the control plane accumulates a durable total from it. Omitted
    /// for stopped machines (no live process to sample).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 42)]
    pub cpu_seconds: Option<u64>,
    /// Same consumed CPU but in MILLISECONDS — sub-second precision so consumers
    /// integrating this don't quantize a barely-busy process up to a whole second.
    /// Derived from the same nanosecond sample as `cpu_seconds`. Omitted for
    /// stopped machines (no live process to sample).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 42830)]
    pub cpu_millis: Option<u64>,
    /// Current resident memory (RSS) of the machine's VMM process, in MiB, sampled
    /// live from the host. Unlike CPU this is an instantaneous gauge (not a
    /// counter); the control plane integrates it over time for active-memory
    /// billing. Omitted for stopped machines (no live process to sample).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 128)]
    pub rss_mb: Option<u64>,
    /// Actual host disk consumed by this machine's data dir, in MiB (real blocks of
    /// the sparse disk images, not provisioned capacity). An instantaneous gauge the
    /// control integrates over time for active-disk billing. Omitted when the data
    /// dir can't be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 256)]
    pub disk_used_mb: Option<u64>,
    /// Creation timestamp (seconds since Unix epoch).
    pub created_at: u64,
}

/// One egress denial: the machine's egress policy refused an outbound
/// connect or sendto. These are the machine's only record of blocked
/// traffic, read from the VMM's log.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressDenialInfo {
    /// Denial time (RFC 3339, microsecond precision), or empty when the
    /// log line carried no parseable timestamp.
    #[schema(example = "2026-08-13T02:31:05.123456Z")]
    pub timestamp: String,
    /// The refused operation: `connect` (TCP) or `sendto` (UDP).
    #[schema(example = "connect")]
    pub operation: String,
    /// The destination the guest tried to reach.
    #[schema(example = "93.184.215.14:443")]
    pub dest: String,
}

impl From<crate::agent::EgressDenial> for EgressDenialInfo {
    fn from(d: crate::agent::EgressDenial) -> Self {
        Self {
            timestamp: d.timestamp,
            operation: d.operation,
            dest: d.dest,
        }
    }
}

/// Egress denial events response.
#[derive(Debug, Serialize, ToSchema)]
pub struct EgressEventsResponse {
    /// Denials oldest-first, capped by the `limit` query parameter.
    pub events: Vec<EgressDenialInfo>,
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

/// Query string for `POST /machines/{name}/start`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct StartMachineQuery {
    /// Start as a fork base: back the guest RAM with a memfd (copy-on-write
    /// cloneable) and expose a control socket so the machine can later be forked
    /// with `POST /machines/{name}/fork`. The golden freezes after its first fork.
    #[serde(default)]
    pub forkable: bool,
    /// Number of runnable CUDA fork clones planned for this golden. Supplying
    /// it enables forkable launch and transparent pre-initialization VRAM
    /// budgeting for cache-sizing frameworks.
    #[serde(default, rename = "forkPoolSize")]
    pub fork_pool_size: Option<u32>,
    /// Explicit logical VRAM limit per golden/clone session, in MiB.
    #[serde(default, rename = "cudaVramLimitMib")]
    pub cuda_vram_limit_mib: Option<u64>,
}

/// Credentials for the registry a machine's image lives in.
///
/// Supplied per-start rather than stored on the machine record: a customer's
/// registry password must not be written to node disk, and the caller (the
/// control plane) already re-sends it on every dispatch. The username is
/// conventional for token-style credentials (`token`, `oauth2accesstoken`,
/// a GitHub PAT username); what matters is the password.
#[derive(Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryAuthSpec {
    /// Registry username.
    pub username: String,
    /// Registry password, token, or PAT.
    pub password: String,
}

// Hand-written so a credential can never reach a log line through `{:?}` on a
// request struct — the derived Debug would print the password verbatim.
impl std::fmt::Debug for RegistryAuthSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryAuthSpec")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl From<RegistryAuthSpec> for crate::registry::RegistryAuth {
    fn from(s: RegistryAuthSpec) -> Self {
        Self {
            username: s.username,
            password: s.password,
        }
    }
}

/// Optional body for `POST /machines/{name}/start`.
///
/// Entirely optional so an older caller that sends no body keeps working
/// unchanged — the route accepted only a query string before this existed.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartMachineRequest {
    /// Credentials for the image's registry, used for THIS start only.
    ///
    /// Takes precedence over any registry credentials configured on the node,
    /// which are operator-level and therefore cannot be per-tenant. Without
    /// this, a private image on a third-party registry (a customer's own
    /// `ghcr.io/<org>/<img>`) has no way to authenticate and the in-guest pull
    /// fails with an opaque DENIED.
    #[serde(default)]
    pub registry_auth: Option<RegistryAuthSpec>,
}

/// Request to fork a running, forkable golden machine into a new clone.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForkRequest {
    /// Name for the new clone machine.
    #[schema(example = "clone-1")]
    pub name: String,
    /// Materialize the restored clone as a new checkpoint source so it can be
    /// forked again. This pays one eager guest-memory copy at clone boot;
    /// descendants remain copy-on-write.
    #[serde(default)]
    pub forkable: bool,
    /// Pin the clone's inbound port forwards. Without this, the golden's
    /// forwards are remapped to freshly-allocated host ports so the clone does
    /// not collide with the still-running golden or sibling clones.
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// Share the golden's loaded CUDA weights with this clone instead of
    /// copying them (one base copy in VRAM across sibling clones). Correct when
    /// the base stays frozen (LoRA/QLoRA fine-tuning, inference).
    #[serde(default)]
    pub share_weights: bool,
    /// Wait for the workload's standard forkpoint before snapshotting, then
    /// release the clone only after identity and fork parameters are installed.
    #[serde(default)]
    pub wait_ready: bool,
    /// Keep the clone parked at the inherited forkpoint as an already-booted
    /// pool slot. Implies `waitReady`; release it exactly once through the
    /// fork-release endpoint after assigning job-specific parameters.
    #[serde(default)]
    pub hold: bool,
    /// Maximum seconds to wait for the golden workload's forkpoint. Defaults
    /// to 240 when `waitReady` or `hold` is enabled.
    #[serde(default)]
    pub ready_timeout_secs: Option<u64>,
    /// Per-fork parameters as KEY=VALUE strings. Delivered to the clone at
    /// `/etc/smolvm/fork-env` (dotenv format) for the already-running workload
    /// to read, and merged into the clone's env for later exec sessions.
    #[serde(default)]
    pub env: Vec<String>,
    /// Per-fork secrets as `SecretRef`s (host env var / absolute file). Merged
    /// into the clone's persisted `secret_refs`, overriding same-named refs
    /// inherited from the golden — so each clone gets its OWN secrets, resolved
    /// fresh on every `exec`, never written to the overlay/artifact or a guest
    /// file, and isolated from the golden and sibling clones. This is the
    /// fork-safe path: unlike `env`, the plaintext never lands at rest.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub secrets: RequestSecretRefs,
}

/// Assignment for one already-booted held fork slot.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForkReleaseRequest {
    /// Job-specific KEY=VALUE parameters. A value replaces a same-named value
    /// installed while provisioning the slot.
    #[serde(default)]
    pub env: Vec<String>,
}

// ============================================================================
// Automatic fork-pool types
// ============================================================================

/// Request to create an automatically replenished pool of held fork workers.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateForkPoolRequest {
    /// Stable pool name.
    #[schema(example = "grpo-rollouts")]
    pub name: String,
    /// Existing running forkable machine whose workload is at the forkpoint.
    #[schema(example = "policy-golden")]
    pub golden: String,
    /// Number of clean workers kept booted and ready.
    #[schema(example = 8)]
    pub desired_ready: u32,
    /// Optional maximum number of simultaneously active leases.
    #[serde(default)]
    pub max_active: Option<u32>,
    /// Automatically calibrate resident CUDA leases. Defaults on for shared
    /// CUDA pools when omitted; set false for full residency.
    #[serde(default)]
    pub auto_admission: Option<bool>,
    /// Share immutable CUDA allocations with the golden and sibling workers.
    #[serde(default)]
    pub share_weights: bool,
    /// Maximum seconds to wait for the golden workload forkpoint.
    #[serde(default)]
    pub ready_timeout_secs: Option<u64>,
    /// Default seconds an acquired worker may run without a heartbeat.
    #[serde(default)]
    pub lease_ttl_secs: Option<u64>,
}

/// Query parameters for deleting a fork pool.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct DeleteForkPoolQuery {
    /// Cancel active leases and delete their workers as well.
    #[serde(default)]
    pub force: bool,
}

/// Request to change a pool's clean-worker target.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResizeForkPoolRequest {
    /// New number of clean workers to keep booted and ready.
    pub desired_ready: u32,
}

/// Current size and lifecycle state of an automatic fork pool.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForkPoolInfo {
    /// Stable pool name.
    pub name: String,
    /// Forkable source machine.
    pub golden: String,
    /// Configured clean-worker target.
    pub desired_ready: u32,
    /// Optional simultaneous active-lease limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_active: Option<u32>,
    /// Whether lease residency is calibrated automatically.
    pub auto_admission: bool,
    /// Current dynamic resident limit when automatic admission is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_active_limit: Option<u32>,
    /// Aggregate dynamic resident limit shared by pools on this CUDA device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_device_limit: Option<u32>,
    /// Host CUDA device inherited from the pool golden.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cuda_device_ordinal: Option<u32>,
    /// Human-readable reason for the current automatic limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_reason: Option<String>,
    /// True while the controller is comparing resident levels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_calibrating: Option<bool>,
    /// Latest utilization of this pool's CUDA device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_utilization_percent: Option<f64>,
    /// Latest memory use on this pool's CUDA device in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_memory_used_mib: Option<u64>,
    /// Memory capacity of this pool's CUDA device in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_memory_total_mib: Option<u64>,
    /// Latest host CPU busy percentage used by admission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_cpu_percent: Option<f64>,
    /// Whether immutable CUDA allocations are shared.
    pub share_weights: bool,
    /// Default lease heartbeat duration.
    pub lease_ttl_secs: u64,
    /// Workers still being forked and booted.
    pub provisioning: u32,
    /// Clean held workers immediately available for acquisition.
    pub ready: u32,
    /// Workers durably claimed while guest release is in progress.
    pub activating: u32,
    /// Workers currently owned by active leases.
    pub active: u32,
    /// Workers being destroyed before replacement or pool deletion.
    pub retiring: u32,
    /// True after asynchronous deletion has begun.
    pub deleting: bool,
    /// Unix timestamp when the pool was created.
    pub created_at: u64,
}

/// List response for automatic fork pools.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ListForkPoolsResponse {
    /// All pools on this node.
    pub pools: Vec<ForkPoolInfo>,
}

/// Request to acquire one clean worker from a fork pool.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AcquireForkLeaseRequest {
    /// Retry key unique within the pool. Repeating it returns the same lease.
    #[schema(example = "rollout-batch-42-worker-3")]
    pub idempotency_key: String,
    /// Job-specific KEY=VALUE parameters installed before the workload runs.
    #[serde(default)]
    pub env: Vec<String>,
    /// Small files written atomically under `/workspace` before the workload is
    /// released. The entire worker is discarded if any file cannot be staged.
    #[serde(default)]
    pub files: Vec<ForkLeasePayloadFile>,
    /// Optional lease duration override for this worker.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Keep the lease activating until the workload calls `smolvm-worker-ready`.
    #[serde(default)]
    pub await_worker_ready: bool,
    /// Optional readiness timeout in seconds; defaults to 240 when enabled. The
    /// acquisition request can remain open for this duration, so clients must use
    /// a longer request deadline.
    #[serde(default)]
    pub worker_ready_timeout_secs: Option<u64>,
    /// Optional fused-rollout access granted only to this lease's executor and policy.
    #[serde(default)]
    pub rollout_access: Option<RolloutLeaseAccess>,
}

/// A bounded group of ordinary fork-pool lease requests.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AcquireForkLeaseBatchRequest {
    /// Independent lease requests. Each item retains its normal idempotency semantics;
    /// at most 32 items may wait for workload readiness in one call.
    pub leases: Vec<AcquireForkLeaseRequest>,
}

/// One ordered result from a fork-pool lease batch.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForkLeaseBatchItemResponse {
    /// Retry key from the submitted lease request.
    pub idempotency_key: String,
    /// Activated worker lease when acquisition succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<ForkLeaseInfo>,
    /// Stable API error category when this item failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable failure for this item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Ordered results from a bounded fork-pool lease batch.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AcquireForkLeaseBatchResponse {
    /// One result per submitted lease request, in input order.
    pub leases: Vec<ForkLeaseBatchItemResponse>,
}

/// Least-privilege fused-rollout scope injected into one pool worker.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RolloutLeaseAccess {
    /// Existing rollout executor this worker may call.
    pub executor: String,
    /// Logical policy this worker may publish, generate, and retire.
    pub policy: String,
}

/// One file staged into a held worker before lease activation.
#[derive(Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForkLeasePayloadFile {
    /// Relative path below `/workspace`, such as `jobs/episode.json`.
    #[schema(example = "jobs/episode.json")]
    pub path: String,
    /// Standard base64-encoded file contents.
    #[schema(example = "eyJlcGlzb2RlIjo0Mn0K")]
    pub data_base64: String,
    /// Optional Unix permission bits in decimal; defaults to 420 (`0644`).
    #[serde(default)]
    #[schema(example = 420)]
    pub mode: Option<u32>,
}

impl std::fmt::Debug for ForkLeasePayloadFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkLeasePayloadFile")
            .field("path", &self.path)
            .field("data_base64", &"<redacted>")
            .field("mode", &self.mode)
            .finish()
    }
}

/// Public state of one one-shot fork worker lease.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForkLeaseInfo {
    /// Opaque lease identifier used for heartbeat and completion.
    pub id: String,
    /// Pool that supplied the worker.
    pub pool: String,
    /// Machine name usable with existing exec, file, and log APIs.
    pub machine: String,
    /// Lease state: activating, active, completed, expired, failed, or cancelled.
    pub state: String,
    /// Unix timestamp when the lease was acquired.
    pub created_at: u64,
    /// Unix timestamp after which a missing heartbeat retires the worker.
    pub expires_at: u64,
    /// Activation failure, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod deny_unknown_field_tests {
    use super::*;

    /// The correct camelCase `timeoutSecs` deserializes and applies.
    #[test]
    fn exec_request_accepts_camelcase_timeout() {
        let req: ExecRequest = serde_json::from_value(
            serde_json::json!({"command": ["sleep", "30"], "timeoutSecs": 5}),
        )
        .expect("camelCase timeoutSecs should parse");
        assert_eq!(req.timeout_secs, Some(5));
    }

    /// A mis-cased safety field is REJECTED, not silently dropped — otherwise an
    /// untrusted command runs with no timeout because the caller wrote
    /// `timeout_secs`. This is the regression this test guards.
    #[test]
    fn exec_request_rejects_snake_case_timeout() {
        let err = serde_json::from_value::<ExecRequest>(
            serde_json::json!({"command": ["sleep", "30"], "timeout_secs": 5}),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("timeout_secs"),
            "error should name the offending field: {err}"
        );
    }

    /// Any unknown field is a hard error, not ignored.
    #[test]
    fn run_request_rejects_unknown_field() {
        assert!(serde_json::from_value::<RunRequest>(
            serde_json::json!({"image": "alpine", "command": ["true"], "bogus": 1})
        )
        .is_err());
    }
}

#[cfg(test)]
mod registry_auth_tests {
    use super::*;

    /// A registry password must never be printable via `Debug`.
    ///
    /// `StartMachineRequest` is exactly the kind of struct that ends up in a
    /// `tracing::debug!(?req)` during a future debugging session, and the
    /// derived Debug would put a customer's PAT straight into the node's
    /// journal — which is shipped to Cloud Logging and retained.
    #[test]
    fn debug_never_prints_the_password() {
        let spec = RegistryAuthSpec {
            username: "bhbryant".into(),
            password: "ghp_super_secret_value".into(),
        };
        let shown = format!("{spec:?}");
        assert!(
            !shown.contains("ghp_super_secret_value"),
            "password leaked into Debug output: {shown}"
        );
        assert!(shown.contains("<redacted>"), "got: {shown}");
        // The username is not a secret and stays visible for debugging.
        assert!(shown.contains("bhbryant"));

        // And it must stay redacted when nested in the request struct.
        let req = StartMachineRequest {
            registry_auth: Some(spec),
        };
        assert!(!format!("{req:?}").contains("ghp_super_secret_value"));
    }

    /// The body is optional and additive: absent, empty, or unrelated JSON all
    /// deserialize to "no credentials", so an older control plane that sends
    /// nothing keeps starting machines exactly as before.
    #[test]
    fn body_is_optional_and_backwards_compatible() {
        let empty: StartMachineRequest = serde_json::from_str("{}").unwrap();
        assert!(empty.registry_auth.is_none());

        let unrelated: StartMachineRequest =
            serde_json::from_str(r#"{"somethingElse":1}"#).unwrap();
        assert!(unrelated.registry_auth.is_none());

        let with_auth: StartMachineRequest =
            serde_json::from_str(r#"{"registryAuth":{"username":"token","password":"pat"}}"#)
                .unwrap();
        let auth = with_auth.registry_auth.expect("registryAuth parsed");
        assert_eq!(auth.username, "token");
        assert_eq!(auth.password, "pat");
    }

    /// Converting into the protocol type preserves both fields verbatim — a
    /// silent truncation here would authenticate as the wrong principal.
    #[test]
    fn converts_to_the_protocol_credential_unchanged() {
        let a: crate::registry::RegistryAuth = RegistryAuthSpec {
            username: "oauth2accesstoken".into(),
            password: "p:with:colons".into(),
        }
        .into();
        assert_eq!(a.username, "oauth2accesstoken");
        assert_eq!(a.password, "p:with:colons");
    }

    #[test]
    fn legacy_fork_request_preserves_uncoordinated_behavior() {
        let request: ForkRequest = serde_json::from_value(serde_json::json!({
            "name": "clone-1"
        }))
        .unwrap();
        assert!(!request.wait_ready);
        assert!(!request.hold);
        assert_eq!(request.ready_timeout_secs, None);
    }
}
