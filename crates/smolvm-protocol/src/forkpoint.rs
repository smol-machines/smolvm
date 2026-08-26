//! Stable guest paths used to coordinate a live fork.

/// Directory privately inherited by each restored VM.
pub const STATE_DIR: &str = "/run/smolvm/forkpoint";

/// Marker written by the workload when it reaches a safe fork boundary.
pub const READY_PATH: &str = "/run/smolvm/forkpoint/ready";

/// First line of every supported forkpoint readiness marker.
pub const READY_VERSION: &str = "smolvm-forkpoint-v1";

/// Prefix of the per-invocation token in a readiness marker. The token lets a
/// releaser distinguish a new forkpoint from the previous helper's marker.
pub const GENERATION_PREFIX: &str = "generation=";

/// Optional readiness-marker capability requesting eager clone module loading.
pub const CUDA_PRELOAD_MODULES_HINT: &str = "cuda-preload-modules";

/// Agent capability required by readiness-gated fork-pool leases.
pub const WORKER_READY_CAPABILITY: &str = "fork-worker-ready-v1";

/// Marker written after a restored clone can safely enter ordinary timed waits.
pub const RESTORED_PATH: &str = "/run/smolvm/forkpoint/restored";

/// Container ID inherited with a live VM snapshot.
///
/// The restored container remains the owner of the workload's live process
/// state, but new commands must join its namespaces directly: a post-restore
/// `crun exec` can fail after trivial commands have already succeeded.
pub const RESTORED_CONTAINER_PATH: &str = "/run/smolvm/forkpoint/restored-container";

/// Marker written by the host after a clone is ready to resume.
pub const RELEASE_PATH: &str = "/run/smolvm/forkpoint/release";

/// Release token used before generation-addressed forkpoints. Accepting it in
/// newer guests keeps independently-updated host and agent packages compatible.
pub const LEGACY_RELEASE_TOKEN: &str = "smolvm-forkpoint-release-v1";

/// Prefix of a generation-addressed release marker.
pub const RELEASE_PREFIX: &str = "smolvm-forkpoint-release-v2:";

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
