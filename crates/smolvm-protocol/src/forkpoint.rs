//! Stable guest paths used to coordinate a live fork.

/// Directory privately inherited by each restored VM.
pub const STATE_DIR: &str = "/run/smolvm/forkpoint";

/// Marker written by the workload when it reaches a safe fork boundary.
pub const READY_PATH: &str = "/run/smolvm/forkpoint/ready";

/// Marker written after a restored clone can safely enter ordinary timed waits.
pub const RESTORED_PATH: &str = "/run/smolvm/forkpoint/restored";

/// Marker written by the host after a clone is ready to resume.
pub const RELEASE_PATH: &str = "/run/smolvm/forkpoint/release";

/// Marker written after a released worker finishes clone-local preparation.
pub const WORKER_READY_PATH: &str = "/run/smolvm/forkpoint/worker-ready";

/// Per-clone environment installed by the host before workload release.
pub const FORK_ENV_PATH: &str = "/etc/smolvm/fork-env";

/// Host-generated readiness token delivered through [`FORK_ENV_PATH`].
pub const WORKER_READY_TOKEN_ENV: &str = "SMOLVM_WORKER_READY_TOKEN";

/// Workload-facing helper installed in bare VMs and workload containers.
pub const HELPER_PATH: &str = "/usr/local/bin/smolvm-fork-ready";

/// Helper used by a released workload after clone-local preparation finishes.
pub const WORKER_READY_HELPER_PATH: &str = "/usr/local/bin/smolvm-worker-ready";
