//! Durable records for automatic held-fork pools and their one-shot leases.

use serde::{Deserialize, Serialize};

/// Maximum time a durably claimed worker may remain in the activation handoff.
/// The user-facing lease TTL starts only after this phase commits.
pub(crate) const FORK_LEASE_ACTIVATION_GRACE_SECS: u64 = 5 * 60;

/// Configuration and lifecycle state for one automatic fork pool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkPoolRecord {
    /// Stable API name for the pool.
    pub name: String,
    /// Forkable machine used to replenish clean slots.
    pub golden: String,
    /// Number of clean, held workers the controller keeps ready.
    pub desired_ready: u32,
    /// Optional limit on simultaneously active leases.
    pub max_active: Option<u32>,
    /// Dynamically calibrate the active-lease limit from host/GPU telemetry.
    /// Absent on records written before automatic admission was introduced.
    #[serde(default)]
    pub auto_admission: bool,
    /// Host CUDA device ordinal inherited from the golden workload.
    ///
    /// Older shared-CUDA pool records predate this field and used CUDA's
    /// default device, so a missing value on those records resolves to zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cuda_device_ordinal: Option<u32>,
    /// Share the golden's immutable CUDA allocations with each worker.
    pub share_weights: bool,
    /// Keep the source paused while refilling this pool.
    #[serde(default)]
    pub freeze_source: bool,
    /// Maximum time to wait for the golden's workload forkpoint.
    pub ready_timeout_secs: u64,
    /// Default time an acquired worker may run without a heartbeat.
    pub lease_ttl_secs: u64,
    /// Unix timestamp when the pool was created.
    pub created_at: u64,
    /// True after deletion has begun; no new workers or leases are admitted.
    pub deleting: bool,
}

impl ForkPoolRecord {
    /// Device whose telemetry and active-lease budget govern this pool.
    pub fn admission_device_ordinal(&self) -> Option<u32> {
        self.cuda_device_ordinal
            .or_else(|| self.share_weights.then_some(0))
    }
}

/// Resolve the host CUDA device selected by a workload environment.
///
/// The CUDA shims expose one guest device and interpret an absent selector as
/// host ordinal zero. An explicitly malformed selector must not silently join
/// the wrong admission domain.
pub fn cuda_device_ordinal_from_env(env: &[(String, String)]) -> Result<u32, String> {
    let Some(value) = env
        .iter()
        .rev()
        .find_map(|(key, value)| (key == "SMOLVM_CUDA_DEVICE").then_some(value))
    else {
        return Ok(0);
    };
    value.parse::<u32>().map_err(|_| {
        format!("SMOLVM_CUDA_DEVICE must be a non-negative host CUDA device ordinal, got '{value}'")
    })
}

/// Runtime-calibrated limits checked together with a durable pool claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkPoolAdmissionLimit {
    /// Fair-share ceiling for this pool while multiple pools have demand.
    pub pool: u32,
    /// Aggregate active-lease ceiling for every pool on the same CUDA device.
    pub device: u32,
}

/// Controller lifecycle state for one machine owned by a fork pool.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForkPoolSlotState {
    /// A machine name is reserved and the held fork is being created.
    Provisioning,
    /// The machine is booted and parked at its inherited forkpoint.
    Ready,
    /// The durable claim committed and guest activation is in progress.
    Activating,
    /// The worker was released to exactly one lease.
    Leased,
    /// The worker must be deleted and replaced, never reused.
    Retiring,
}

impl ForkPoolSlotState {
    /// Stable database representation used for indexed state queries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Activating => "activating",
            Self::Leased => "leased",
            Self::Retiring => "retiring",
        }
    }
}

/// Durable ownership record for one pool-managed machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkPoolSlotRecord {
    /// Pool that owns the machine.
    pub pool_name: String,
    /// Machine name in the normal smolvm machine registry.
    pub machine_name: String,
    /// Current controller lifecycle state.
    pub state: ForkPoolSlotState,
    /// Lease currently owning the machine, if it has been claimed.
    pub lease_id: Option<String>,
    /// Unix timestamp when the slot reservation was created.
    pub created_at: u64,
    /// Unix timestamp of the last state transition.
    pub updated_at: u64,
    /// Last provisioning or activation error, if any.
    pub last_error: Option<String>,
}

/// Lifecycle state for a one-shot worker lease.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForkLeaseState {
    /// The durable claim committed and guest activation is in progress.
    Activating,
    /// The guest was released and the caller owns the worker.
    Active,
    /// The caller completed the lease normally.
    Completed,
    /// The caller stopped heartbeating before the deadline.
    Expired,
    /// Activation failed after the slot was consumed.
    Failed,
    /// Pool deletion revoked the lease.
    Cancelled,
}

impl ForkLeaseState {
    /// Stable database representation used for indexed state queries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activating => "activating",
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Durable exactly-once claim for one pool worker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkLeaseRecord {
    /// Opaque lease identifier.
    pub id: String,
    /// Pool the worker came from.
    pub pool_name: String,
    /// Claimed worker machine name.
    pub machine_name: String,
    /// Caller-provided retry key, unique within the pool.
    pub idempotency_key: String,
    /// Current lease lifecycle state.
    pub state: ForkLeaseState,
    /// Canonical assignment environment written before guest release.
    pub assignment: Vec<(String, String)>,
    /// Digest of the canonical pre-release file payload, for retry validation.
    #[serde(default)]
    pub payload_sha256: Option<String>,
    /// Unix timestamp when the claim was created.
    pub created_at: u64,
    /// Unix timestamp of the last state transition or heartbeat.
    pub updated_at: u64,
    /// Unix timestamp after which the controller may retire the worker.
    pub expires_at: u64,
    /// Lease duration applied by each heartbeat.
    pub ttl_secs: u64,
    /// Activation failure, when the lease ended in `failed`.
    pub last_error: Option<String>,
}

/// Result of an atomic lease acquisition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimForkPoolSlot {
    /// A new slot was durably consumed for this request.
    Claimed(ForkLeaseRecord),
    /// The same idempotency key already owns this lease.
    Existing(ForkLeaseRecord),
    /// No clean held slot is currently ready.
    NoReadySlot,
    /// The pool reached its configured active-lease limit.
    AtCapacity,
    /// The pool was removed between request validation and claim.
    PoolNotFound,
    /// Pool deletion began before the claim committed.
    PoolDeleting,
    /// Payload staging cannot safely target an externally mounted workspace.
    WorkspaceExternallyMounted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_lease_without_payload_digest_still_deserializes() {
        let lease: ForkLeaseRecord = serde_json::from_str(
            r#"{
                "id":"lease-1",
                "pool_name":"pool",
                "machine_name":"worker",
                "idempotency_key":"request",
                "state":"active",
                "assignment":[],
                "created_at":1,
                "updated_at":1,
                "expires_at":61,
                "ttl_secs":60,
                "last_error":null
            }"#,
        )
        .unwrap();
        assert_eq!(lease.payload_sha256, None);
    }

    #[test]
    fn legacy_pool_without_auto_admission_stays_full_residency() {
        let pool: ForkPoolRecord = serde_json::from_str(
            r#"{
                "name":"rollouts",
                "golden":"golden",
                "desired_ready":8,
                "max_active":null,
                "share_weights":true,
                "ready_timeout_secs":240,
                "lease_ttl_secs":300,
                "created_at":1,
                "deleting":false
            }"#,
        )
        .unwrap();
        assert!(!pool.auto_admission);
        assert!(!pool.freeze_source);
        assert_eq!(pool.cuda_device_ordinal, None);
        assert_eq!(pool.admission_device_ordinal(), Some(0));
    }

    #[test]
    fn cuda_device_selector_defaults_to_zero_and_rejects_invalid_values() {
        assert_eq!(cuda_device_ordinal_from_env(&[]).unwrap(), 0);
        assert_eq!(
            cuda_device_ordinal_from_env(&[("SMOLVM_CUDA_DEVICE".into(), "3".into())]).unwrap(),
            3
        );
        assert!(
            cuda_device_ordinal_from_env(&[("SMOLVM_CUDA_DEVICE".into(), "-1".into())])
                .unwrap_err()
                .contains("non-negative")
        );
    }
}
