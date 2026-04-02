//! Core MicroVm data types.
//!
//! These types define the public-facing VM object model used across all
//! boundaries (CLI, API, SDKs). Internal persistence uses `VmRecord`;
//! conversions live in `internal::convert`.

use crate::data::mount::HostMount;
use crate::data::network::PortMapping;
use crate::data::resources::VmResources;

// ============================================================================
// MicroVm — the universal VM object
// ============================================================================

/// A MicroVm definition. Same shape in (create), same shape out (get/list).
///
/// Follows a K8s-style pattern: `name` + `spec` (desired state) + `status`
/// (observed state). When creating a VM, callers set `status: None`; the
/// control layer fills it in.
#[derive(Debug, Clone)]
pub struct MicroVm {
    /// Unique name for this VM.
    pub name: String,
    /// Desired configuration.
    pub spec: VmSpec,
    /// Observed runtime state. `None` when used as create input.
    pub status: Option<VmStatus>,
}

// ============================================================================
// VmSpec — desired state
// ============================================================================

/// Desired VM configuration — what the user wants.
#[derive(Debug, Clone, Default)]
pub struct VmSpec {
    /// Resource allocation (cpus, memory, network, storage, overlay).
    pub resources: VmResources,
    /// Host directory mounts.
    pub mounts: Vec<HostMount>,
    /// Port mappings (host → guest).
    pub ports: Vec<PortMapping>,
    /// OCI image for auto-container creation on start.
    pub image: Option<String>,
    /// Container entrypoint override.
    pub entrypoint: Vec<String>,
    /// Container command override.
    pub cmd: Vec<String>,
    /// Environment variables.
    pub env: Vec<(String, String)>,
    /// Working directory for init commands.
    pub workdir: Option<String>,
    /// Commands to run on every VM start (via `sh -c`).
    pub init: Vec<String>,
}

// ============================================================================
// VmStatus — observed state
// ============================================================================

/// Observed runtime state — what the system reports.
#[derive(Debug, Clone)]
pub struct VmStatus {
    /// High-level lifecycle phase.
    pub phase: VmPhase,
    /// Process ID when running.
    pub pid: Option<i32>,
    /// Process start time (seconds since epoch) for PID reuse detection.
    pub pid_start_time: Option<u64>,
    /// Creation timestamp.
    pub created_at: String,
    /// Last exit code from the VM process.
    pub last_exit_code: Option<i32>,
}

// ============================================================================
// VmPhase — lifecycle phase
// ============================================================================

/// High-level VM lifecycle phase.
///
/// Maps 1:1 to the existing `RecordState` in the persistence layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmPhase {
    /// VM created but not started.
    #[default]
    Created,
    /// VM process is running.
    Running,
    /// VM exited cleanly.
    Stopped,
    /// VM crashed or error.
    Failed,
}

impl std::fmt::Display for VmPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmPhase::Created => write!(f, "created"),
            VmPhase::Running => write!(f, "running"),
            VmPhase::Stopped => write!(f, "stopped"),
            VmPhase::Failed => write!(f, "failed"),
        }
    }
}
