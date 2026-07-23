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
    /// Network backend: `tsi` (default, outbound-only) or `virtio-net`
    /// (required for published `ports`). Omit for the default (TSI).
    #[serde(default)]
    pub network_backend: Option<crate::network::NetworkBackend>,
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
    /// Network backend: `tsi` (default, outbound-only) or `virtio-net`.
    /// Published `ports` require `virtio-net` (TSI has no inbound path).
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
    /// Network backend the machine runs (`tsi` or `virtio-net`). Omitted when
    /// unset (the default TSI). Echoes back what `create` accepted.
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
}

/// Request to fork a running, forkable golden machine into a new clone.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForkRequest {
    /// Name for the new clone machine.
    #[schema(example = "clone-1")]
    pub name: String,
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
    /// Per-fork parameters as KEY=VALUE strings. Delivered to the clone at
    /// `/run/smolvm/fork-env` (dotenv format) for the already-running workload
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
