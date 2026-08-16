//! Automatic held-fork pool and one-shot lease handlers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use base64::Engine as _;
use futures_util::{stream, StreamExt};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::api::types::{
    AcquireForkLeaseBatchRequest, AcquireForkLeaseBatchResponse, AcquireForkLeaseRequest,
    ApiErrorResponse, CreateForkPoolRequest, DeleteForkPoolQuery, DeleteResponse,
    ForkLeaseBatchItemResponse, ForkLeaseInfo, ForkPoolInfo, ListForkPoolsResponse,
    ResizeForkPoolRequest,
};
use crate::data::validate_vm_name;
use crate::db::ForkPoolSlotClaim;
use crate::pool::{
    ClaimForkPoolSlot, ForkLeaseRecord, ForkLeaseState, ForkPoolRecord, ForkPoolSlotState,
};

const DEFAULT_READY_TIMEOUT_SECS: u64 = 240;
const MAX_READY_TIMEOUT_SECS: u64 = 60 * 60;
const DEFAULT_LEASE_TTL_SECS: u64 = 300;
const MAX_POOL_READY: u32 = 256;
const MIN_LEASE_TTL_SECS: u64 = 30;
const MAX_LEASE_TTL_SECS: u64 = 24 * 60 * 60;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_LEASE_BATCH_SIZE: usize = MAX_POOL_READY as usize;
const MAX_CONCURRENT_LEASE_ACTIVATIONS: usize = 32;
const MAX_LEASE_PAYLOAD_FILES: usize = 32;
const MAX_LEASE_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_LEASE_PAYLOAD_PATH_BYTES: usize = 512;
const DEFAULT_LEASE_PAYLOAD_MODE: u32 = 0o644;
const LEASE_PAYLOAD_STAGE_ATTEMPTS: usize = 2;
// Leave one minute for payload staging, guest release, and the durable commit
// before the controller's five-minute activating-lease grace period expires.
const MAX_WORKER_READY_TIMEOUT_SECS: u64 = crate::pool::FORK_LEASE_ACTIVATION_GRACE_SECS - 60;
const DEFAULT_WORKER_READY_TIMEOUT_SECS: u64 = MAX_WORKER_READY_TIMEOUT_SECS;
const WORKER_READY_TIMEOUT_ENV: &str = "SMOLVM_WORKER_READY_TIMEOUT_SECS";

const RESERVED_LEASE_ENV: &[&str] = &[
    smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV,
    WORKER_READY_TIMEOUT_ENV,
    crate::api::guest_rollout::ROLLOUT_TOKEN_ENV,
    crate::api::guest_rollout::ROLLOUT_URL_ENV,
    crate::api::guest_rollout::ROLLOUT_EXECUTOR_ENV,
    crate::api::guest_rollout::ROLLOUT_POLICY_ENV,
];

#[derive(Clone)]
struct StagedLeaseFile {
    path: String,
    data: Vec<u8>,
    mode: u32,
}

fn validate_worker_ready_request(
    await_worker_ready: bool,
    requested_timeout: Option<u64>,
) -> Result<Option<u64>, ApiError> {
    if !await_worker_ready {
        if requested_timeout.is_some() {
            return Err(ApiError::BadRequest(
                "workerReadyTimeoutSecs requires awaitWorkerReady=true".into(),
            ));
        }
        return Ok(None);
    }
    let timeout = requested_timeout.unwrap_or(DEFAULT_WORKER_READY_TIMEOUT_SECS);
    if !(1..=MAX_WORKER_READY_TIMEOUT_SECS).contains(&timeout) {
        return Err(ApiError::BadRequest(format!(
            "workerReadyTimeoutSecs must be between 1 and {MAX_WORKER_READY_TIMEOUT_SECS}"
        )));
    }
    Ok(Some(timeout))
}

fn worker_ready_token(pool: &str, idempotency_key: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"smolvm-worker-ready-v1\0");
    digest.update((pool.len() as u64).to_le_bytes());
    digest.update(pool.as_bytes());
    digest.update((idempotency_key.len() as u64).to_le_bytes());
    digest.update(idempotency_key.as_bytes());
    hex::encode(digest.finalize())
}

fn add_worker_ready_assignment(
    assignment: &mut Vec<(String, String)>,
    pool: &str,
    idempotency_key: &str,
    timeout_secs: u64,
) -> Result<String, ApiError> {
    for reserved in [
        smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV,
        WORKER_READY_TIMEOUT_ENV,
    ] {
        if assignment.iter().any(|(key, _)| key == reserved) {
            return Err(ApiError::BadRequest(format!(
                "{reserved} is reserved for smolvm worker readiness"
            )));
        }
    }
    let token = worker_ready_token(pool, idempotency_key);
    assignment.push((
        smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV.into(),
        token.clone(),
    ));
    assignment.push((WORKER_READY_TIMEOUT_ENV.into(), timeout_secs.to_string()));
    Ok(token)
}

fn add_rollout_access_assignment(
    assignment: &mut Vec<(String, String)>,
    lease_id: &str,
    access: &crate::api::types::RolloutLeaseAccess,
) -> Result<(), ApiError> {
    crate::api::rollout::validate_name("rollout executor", &access.executor)
        .map_err(ApiError::from)?;
    crate::api::rollout::validate_name("rollout policy", &access.policy).map_err(ApiError::from)?;
    let credential = crate::api::guest_rollout::issue_lease_credential(lease_id)
        .map_err(|error| ApiError::internal(format!("issue rollout lease credential: {error}")))?;
    assignment.extend([
        (
            crate::api::guest_rollout::ROLLOUT_TOKEN_ENV.into(),
            credential,
        ),
        (
            crate::api::guest_rollout::ROLLOUT_URL_ENV.into(),
            crate::api::guest_rollout::lease_rollout_url(&access.executor),
        ),
        (
            crate::api::guest_rollout::ROLLOUT_EXECUTOR_ENV.into(),
            access.executor.clone(),
        ),
        (
            crate::api::guest_rollout::ROLLOUT_POLICY_ENV.into(),
            access.policy.clone(),
        ),
    ]);
    Ok(())
}

fn validate_rollout_access_target(
    golden: &crate::config::VmRecord,
    guest_host_service: Option<smolvm_network::GatewayHostService>,
) -> Result<(), ApiError> {
    if !guest_host_service
        .is_some_and(|service| service.guest_port == crate::api::guest_rollout::GUEST_ROLLOUT_PORT)
    {
        return Err(ApiError::Conflict(
            "rolloutAccess is unavailable because guest rollout ingress is not enabled on this node"
                .into(),
        ));
    }
    if !golden.network {
        return Err(ApiError::Conflict(
            "rolloutAccess requires a pool golden with networking enabled".into(),
        ));
    }
    if golden.network_backend == Some(crate::network::NetworkBackend::Tsi) {
        return Err(ApiError::Conflict(
            "rolloutAccess requires the virtio-net backend; recreate the pool golden without an explicit TSI backend"
                .into(),
        ));
    }
    if golden.runtime_managed {
        return Err(ApiError::Conflict(
            "rolloutAccess is not supported for Kubernetes pod-network machines".into(),
        ));
    }
    Ok(())
}

fn idempotent_assignment_matches(
    existing: &[(String, String)],
    requested: &[(String, String)],
) -> bool {
    existing
        .iter()
        .filter(|(key, _)| key != crate::api::guest_rollout::ROLLOUT_TOKEN_ENV)
        .eq(requested
            .iter()
            .filter(|(key, _)| key != crate::api::guest_rollout::ROLLOUT_TOKEN_ENV))
}

fn validate_lease_payload(
    files: &[crate::api::types::ForkLeasePayloadFile],
) -> Result<(Vec<StagedLeaseFile>, Option<String>), ApiError> {
    if files.len() > MAX_LEASE_PAYLOAD_FILES {
        return Err(ApiError::BadRequest(format!(
            "lease payload may contain at most {MAX_LEASE_PAYLOAD_FILES} files"
        )));
    }

    let mut staged = Vec::with_capacity(files.len());
    let mut paths = std::collections::HashSet::with_capacity(files.len());
    let mut total = 0usize;
    for file in files {
        let path = file.path.as_str();
        let valid_path = !path.is_empty()
            && path.len() <= MAX_LEASE_PAYLOAD_PATH_BYTES
            && !path.starts_with('/')
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && path
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..");
        if !valid_path {
            return Err(ApiError::BadRequest(format!(
                "lease payload path '{path}' must be a safe relative path under /workspace"
            )));
        }
        if !paths.insert(path.to_string()) {
            return Err(ApiError::BadRequest(format!(
                "lease payload path '{path}' is duplicated"
            )));
        }
        let mode = file.mode.unwrap_or(DEFAULT_LEASE_PAYLOAD_MODE);
        if mode & !0o777 != 0 {
            return Err(ApiError::BadRequest(format!(
                "lease payload mode for '{path}' must contain only Unix permission bits"
            )));
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(&file.data_base64)
            .map_err(|_| {
                ApiError::BadRequest(format!(
                    "lease payload dataBase64 for '{path}' is not valid standard base64"
                ))
            })?;
        total = total
            .checked_add(data.len())
            .ok_or_else(|| ApiError::BadRequest("lease payload decoded size overflowed".into()))?;
        if total > MAX_LEASE_PAYLOAD_BYTES {
            return Err(ApiError::BadRequest(format!(
                "lease payload decoded contents must total at most {MAX_LEASE_PAYLOAD_BYTES} bytes"
            )));
        }
        staged.push(StagedLeaseFile {
            path: path.to_string(),
            data,
            mode,
        });
    }
    if staged.is_empty() {
        return Ok((staged, None));
    }

    // File order is not semantically meaningful because the workload remains
    // parked until every write succeeds. Canonicalize it so idempotent retries
    // may send the same file set in any order.
    staged.sort_by(|left, right| left.path.cmp(&right.path));
    let mut digest = Sha256::new();
    for file in &staged {
        digest.update((file.path.len() as u64).to_le_bytes());
        digest.update(file.path.as_bytes());
        digest.update(file.mode.to_le_bytes());
        digest.update((file.data.len() as u64).to_le_bytes());
        digest.update(&file.data);
    }
    Ok((staged, Some(hex::encode(digest.finalize()))))
}

fn lease_info(lease: ForkLeaseRecord) -> ForkLeaseInfo {
    ForkLeaseInfo {
        id: lease.id,
        pool: lease.pool_name,
        machine: lease.machine_name,
        state: lease.state.as_str().to_string(),
        created_at: lease.created_at,
        expires_at: lease.expires_at,
        error: lease.last_error,
    }
}

fn retry_transient_lease_stage(
    mut operation: impl FnMut() -> crate::Result<()>,
) -> crate::Result<()> {
    for attempt in 1..=LEASE_PAYLOAD_STAGE_ATTEMPTS {
        match operation() {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt < LEASE_PAYLOAD_STAGE_ATTEMPTS
                    && crate::util::is_transient_network_error(&error.to_string()) =>
            {
                tracing::warn!(
                    attempt,
                    max_attempts = LEASE_PAYLOAD_STAGE_ATTEMPTS,
                    %error,
                    "lease payload staging reply was ambiguous; retrying atomically"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("lease payload staging retry loop always returns")
}

fn stage_lease_payload(machine: &str, files: &[StagedLeaseFile]) -> crate::Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let socket = crate::agent::vm_data_dir(machine).join("agent.sock");
    retry_transient_lease_stage(|| {
        // Reconnect for every attempt. FileWrite installs with an atomic rename,
        // so repeating the same validated bytes after a lost acknowledgment is
        // safe even when the first request committed inside the guest.
        let mut client = crate::agent::AgentClient::connect_with_retry(&socket)
            .map_err(|e| crate::Error::agent("stage lease payload", e.to_string()))?;
        for file in files {
            let path = format!("/workspace/{}", file.path);
            client
                .write_file(&path, &file.data, Some(file.mode))
                .map_err(|e| {
                    crate::Error::agent("stage lease payload", format!("write '{path}': {e}"))
                })?;
        }
        Ok(())
    })
}

async fn activate_claimed_lease(
    state: Arc<ApiState>,
    lease: ForkLeaseRecord,
    assignment: Vec<(String, String)>,
    files: Vec<StagedLeaseFile>,
    worker_ready: Option<(String, Duration)>,
) -> Result<ForkLeaseRecord, String> {
    let record = match state.lookup_vm(&lease.machine_name).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            let message = "claimed pool worker disappeared".to_string();
            let db = state.db().clone();
            let lease_id = lease.id.clone();
            let persisted = message.clone();
            tokio::task::spawn_blocking(move || {
                db.fail_fork_lease(&lease_id, crate::util::current_timestamp(), persisted)
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
            state.notify_pool_reconcile();
            return Err(message);
        }
        Err(error) => return Err(format!("pool worker lookup failed: {error:?}")),
    };
    let machine = lease.machine_name.clone();
    let activation = tokio::task::spawn_blocking(move || {
        stage_lease_payload(&machine, &files)?;
        crate::agent::fork::activate_held_fork(&machine, &record, &assignment)?;
        if let Some((token, timeout)) = worker_ready {
            crate::agent::fork::wait_for_worker_ready(&machine, &token, timeout)?;
        }
        Ok::<(), crate::Error>(())
    })
    .await
    .map_err(|e| format!("pool activation task failed: {e}"))?;
    if let Err(error) = activation {
        let message = error.to_string();
        let db = state.db().clone();
        let lease_id = lease.id.clone();
        let persisted = message.clone();
        tokio::task::spawn_blocking(move || {
            db.fail_fork_lease(&lease_id, crate::util::current_timestamp(), persisted)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
        state.notify_pool_reconcile();
        return Err(format!(
            "pool worker was consumed and will be replaced after activation failed: {message}"
        ));
    }
    let db = state.db().clone();
    let lease_id = lease.id.clone();
    let active = tokio::task::spawn_blocking(move || {
        db.mark_fork_lease_active(&lease_id, crate::util::current_timestamp())
    })
    .await
    .map_err(|e| format!("lease activation commit task failed: {e}"))?
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "claimed lease disappeared".to_string())?;
    if active.state != ForkLeaseState::Active {
        return Err(format!(
            "lease changed to '{}' before activation completed",
            active.state.as_str()
        ));
    }
    Ok(active)
}

async fn wait_for_existing_activation(
    state: &ApiState,
    mut lease: ForkLeaseRecord,
    timeout: Duration,
) -> Result<ForkLeaseRecord, ApiError> {
    let deadline = tokio::time::Instant::now() + timeout + Duration::from_secs(5);
    loop {
        match lease.state {
            ForkLeaseState::Active => return Ok(lease),
            ForkLeaseState::Activating if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let db = state.db().clone();
                let pool = lease.pool_name.clone();
                let id = lease.id.clone();
                lease = tokio::task::spawn_blocking(move || db.get_fork_lease(&pool, &id))
                    .await
                    .map_err(|error| {
                        ApiError::internal(format!(
                            "existing lease activation query task failed: {error}"
                        ))
                    })?
                    .map_err(ApiError::database)?
                    .ok_or_else(|| ApiError::internal("existing fork lease disappeared"))?;
            }
            ForkLeaseState::Activating => {
                return Err(ApiError::internal(format!(
                    "fork lease '{}' remained activating after its worker readiness timeout",
                    lease.id
                )));
            }
            _ => {
                return Err(ApiError::internal(format!(
                    "fork lease '{}' ended in state '{}'{}",
                    lease.id,
                    lease.state.as_str(),
                    lease
                        .last_error
                        .as_deref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                )));
            }
        }
    }
}

async fn pool_info(state: &ApiState, pool: ForkPoolRecord) -> Result<ForkPoolInfo, ApiError> {
    let admission = state.admission().snapshot(&pool);
    let cuda_device_ordinal = pool.admission_device_ordinal();
    let db = state.db().clone();
    let pool_name = pool.name.clone();
    let slots = tokio::task::spawn_blocking(move || db.list_fork_pool_slots(&pool_name))
        .await
        .map_err(|e| ApiError::internal(format!("pool slot query task failed: {e}")))?
        .map_err(ApiError::database)?;
    let mut provisioning = 0;
    let mut ready = 0;
    let mut activating = 0;
    let mut active = 0;
    let mut retiring = 0;
    for slot in slots {
        match slot.state {
            ForkPoolSlotState::Provisioning => provisioning += 1,
            ForkPoolSlotState::Ready => ready += 1,
            ForkPoolSlotState::Activating => activating += 1,
            ForkPoolSlotState::Leased => active += 1,
            ForkPoolSlotState::Retiring => retiring += 1,
        }
    }
    Ok(ForkPoolInfo {
        name: pool.name,
        golden: pool.golden,
        desired_ready: pool.desired_ready,
        max_active: pool.max_active,
        auto_admission: pool.auto_admission,
        effective_active_limit: admission.as_ref().map(|state| state.effective_limit),
        effective_device_limit: admission.as_ref().map(|state| state.device_limit),
        cuda_device_ordinal,
        admission_reason: admission.as_ref().map(|state| state.reason.clone()),
        admission_calibrating: admission.as_ref().map(|state| state.calibrating),
        gpu_utilization_percent: admission
            .as_ref()
            .and_then(|state| state.gpu_utilization_percent),
        gpu_memory_used_mib: admission
            .as_ref()
            .and_then(|state| state.gpu_memory_used_mib),
        gpu_memory_total_mib: admission
            .as_ref()
            .and_then(|state| state.gpu_memory_total_mib),
        host_cpu_percent: admission.as_ref().and_then(|state| state.host_cpu_percent),
        share_weights: pool.share_weights,
        lease_ttl_secs: pool.lease_ttl_secs,
        provisioning,
        ready,
        activating,
        active,
        retiring,
        deleting: pool.deleting,
        created_at: pool.created_at,
    })
}

fn validate_ttl(ttl: u64) -> Result<u64, ApiError> {
    if !(MIN_LEASE_TTL_SECS..=MAX_LEASE_TTL_SECS).contains(&ttl) {
        return Err(ApiError::BadRequest(format!(
            "lease TTL must be between {MIN_LEASE_TTL_SECS} and {MAX_LEASE_TTL_SECS} seconds"
        )));
    }
    Ok(ttl)
}

/// Create an automatically replenished held-fork pool.
#[utoipa::path(
    post,
    path = "/api/v1/pools",
    tag = "Pools",
    request_body = CreateForkPoolRequest,
    responses(
        (status = 200, description = "Pool accepted for asynchronous fill", body = ForkPoolInfo),
        (status = 400, description = "Invalid pool configuration", body = ApiErrorResponse),
        (status = 404, description = "Golden machine not found", body = ApiErrorResponse),
        (status = 409, description = "Pool already exists or golden is invalid", body = ApiErrorResponse)
    )
)]
pub async fn create_pool(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateForkPoolRequest>,
) -> Result<Json<ForkPoolInfo>, ApiError> {
    validate_vm_name(&req.name, "pool name").map_err(ApiError::BadRequest)?;
    validate_vm_name(&req.golden, "golden machine name").map_err(ApiError::BadRequest)?;
    if req.desired_ready == 0 || req.desired_ready > MAX_POOL_READY {
        return Err(ApiError::BadRequest(format!(
            "desiredReady must be between 1 and {MAX_POOL_READY}"
        )));
    }
    if matches!(req.max_active, Some(0)) {
        return Err(ApiError::BadRequest(
            "maxActive must be greater than zero when set".into(),
        ));
    }
    let auto_admission = req.auto_admission.unwrap_or(req.share_weights);
    if auto_admission && !req.share_weights {
        return Err(ApiError::BadRequest(
            "autoAdmission requires shareWeights so residency controls CUDA workers".into(),
        ));
    }
    let ready_timeout_secs = req.ready_timeout_secs.unwrap_or(DEFAULT_READY_TIMEOUT_SECS);
    if ready_timeout_secs == 0 || ready_timeout_secs > MAX_READY_TIMEOUT_SECS {
        return Err(ApiError::BadRequest(format!(
            "readyTimeoutSecs must be between 1 and {MAX_READY_TIMEOUT_SECS}"
        )));
    }
    let lease_ttl_secs = validate_ttl(req.lease_ttl_secs.unwrap_or(DEFAULT_LEASE_TTL_SECS))?;
    let golden = state
        .lookup_vm(&req.golden)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", req.golden)))?;
    if golden.golden.is_some() {
        return Err(ApiError::Conflict(
            "a fork clone cannot be used as a pool golden".into(),
        ));
    }
    if !golden.is_process_alive() {
        return Err(ApiError::Conflict(format!(
            "golden machine '{}' is not running",
            req.golden
        )));
    }
    if req.share_weights && !golden.cuda {
        return Err(ApiError::Conflict(format!(
            "golden machine '{}' does not have CUDA enabled",
            req.golden
        )));
    }
    let golden_name = req.golden.clone();
    let forkable = tokio::task::spawn_blocking(move || {
        let control = crate::agent::fork::control_socket_path(&golden_name);
        if !control.exists() {
            return false;
        }
        crate::agent::fork::control_socket_cmd(&control, "STATUS")
            .map(|status| status.starts_with("OK"))
            .unwrap_or(false)
    })
    .await
    .map_err(|e| ApiError::internal(format!("golden forkability task failed: {e}")))?;
    if !forkable {
        return Err(ApiError::Conflict(format!(
            "golden machine '{}' is not running forkable",
            req.golden
        )));
    }
    let cuda_device_ordinal = if golden.cuda {
        Some(crate::pool::cuda_device_ordinal_from_env(&golden.env).map_err(ApiError::BadRequest)?)
    } else {
        None
    };
    let pool = ForkPoolRecord {
        name: req.name,
        golden: req.golden,
        desired_ready: req.desired_ready,
        max_active: req.max_active,
        auto_admission,
        cuda_device_ordinal,
        share_weights: req.share_weights,
        ready_timeout_secs,
        lease_ttl_secs,
        created_at: crate::util::current_timestamp(),
        deleting: false,
    };
    let db = state.db().clone();
    let inserted_pool = pool.clone();
    let inserted =
        tokio::task::spawn_blocking(move || db.insert_fork_pool_if_not_exists(&inserted_pool))
            .await
            .map_err(|e| ApiError::internal(format!("pool insert task failed: {e}")))?
            .map_err(ApiError::database)?;
    if !inserted {
        return Err(ApiError::Conflict(format!(
            "fork pool '{}' already exists",
            pool.name
        )));
    }
    let info = pool_info(&state, pool).await?;
    state.notify_pool_reconcile();
    Ok(Json(info))
}

/// List automatic fork pools.
#[utoipa::path(
    get,
    path = "/api/v1/pools",
    tag = "Pools",
    responses((status = 200, description = "Pool list", body = ListForkPoolsResponse))
)]
pub async fn list_pools(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ListForkPoolsResponse>, ApiError> {
    let db = state.db().clone();
    let pools = tokio::task::spawn_blocking(move || db.list_fork_pools())
        .await
        .map_err(|e| ApiError::internal(format!("pool list task failed: {e}")))?
        .map_err(ApiError::database)?;
    let mut infos = Vec::with_capacity(pools.len());
    for pool in pools {
        infos.push(pool_info(&state, pool).await?);
    }
    Ok(Json(ListForkPoolsResponse { pools: infos }))
}

/// Get one automatic fork pool.
#[utoipa::path(
    get,
    path = "/api/v1/pools/{name}",
    tag = "Pools",
    params(("name" = String, Path, description = "Pool name")),
    responses(
        (status = 200, description = "Pool state", body = ForkPoolInfo),
        (status = 404, description = "Pool not found", body = ApiErrorResponse)
    )
)]
pub async fn get_pool(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<ForkPoolInfo>, ApiError> {
    let db = state.db().clone();
    let lookup = name.clone();
    let pool = tokio::task::spawn_blocking(move || db.get_fork_pool(&lookup))
        .await
        .map_err(|e| ApiError::internal(format!("pool lookup task failed: {e}")))?
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("fork pool '{name}' not found")))?;
    Ok(Json(pool_info(&state, pool).await?))
}

/// Change a pool's clean-worker target.
#[utoipa::path(
    put,
    path = "/api/v1/pools/{name}/size",
    tag = "Pools",
    params(("name" = String, Path, description = "Pool name")),
    request_body = ResizeForkPoolRequest,
    responses(
        (status = 200, description = "Updated pool state", body = ForkPoolInfo),
        (status = 400, description = "Invalid target", body = ApiErrorResponse),
        (status = 404, description = "Pool not found", body = ApiErrorResponse),
        (status = 409, description = "Pool is deleting", body = ApiErrorResponse)
    )
)]
pub async fn resize_pool(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(req): Json<ResizeForkPoolRequest>,
) -> Result<Json<ForkPoolInfo>, ApiError> {
    if req.desired_ready > MAX_POOL_READY {
        return Err(ApiError::BadRequest(format!(
            "desiredReady must be at most {MAX_POOL_READY}"
        )));
    }
    let db = state.db().clone();
    let pool_name = name.clone();
    let pool = tokio::task::spawn_blocking(move || {
        db.resize_fork_pool(
            &pool_name,
            req.desired_ready,
            crate::util::current_timestamp(),
        )
    })
    .await
    .map_err(|e| ApiError::internal(format!("pool resize task failed: {e}")))?
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::NotFound(format!("fork pool '{name}' not found")))?;
    if pool.deleting {
        return Err(ApiError::Conflict(format!(
            "fork pool '{name}' is deleting"
        )));
    }
    let info = pool_info(&state, pool).await?;
    state.notify_pool_reconcile();
    Ok(Json(info))
}

/// Begin asynchronous pool deletion.
#[utoipa::path(
    delete,
    path = "/api/v1/pools/{name}",
    tag = "Pools",
    params(
        ("name" = String, Path, description = "Pool name"),
        ("force" = Option<bool>, Query, description = "Cancel active leases")
    ),
    responses(
        (status = 200, description = "Pool deletion started", body = DeleteResponse),
        (status = 404, description = "Pool not found", body = ApiErrorResponse),
        (status = 409, description = "Pool has active leases", body = ApiErrorResponse)
    )
)]
pub async fn delete_pool(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Query(query): Query<DeleteForkPoolQuery>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let db = state.db().clone();
    let pool_name = name.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        db.begin_delete_fork_pool(&pool_name, query.force, crate::util::current_timestamp())
    })
    .await
    .map_err(|e| ApiError::internal(format!("pool deletion task failed: {e}")))?
    .map_err(ApiError::database)?;
    match outcome {
        None => Err(ApiError::NotFound(format!("fork pool '{name}' not found"))),
        Some(false) => Err(ApiError::Conflict(format!(
            "fork pool '{name}' has active leases; complete them or use force=true"
        ))),
        Some(true) => {
            state.notify_pool_reconcile();
            Ok(Json(DeleteResponse { deleted: name }))
        }
    }
}

/// Acquire and release one clean worker exactly once.
#[utoipa::path(
    post,
    path = "/api/v1/pools/{name}/leases",
    tag = "Pools",
    params(("name" = String, Path, description = "Pool name")),
    request_body = AcquireForkLeaseRequest,
    responses(
        (status = 200, description = "Worker lease", body = ForkLeaseInfo),
        (status = 400, description = "Invalid assignment or payload", body = ApiErrorResponse),
        (status = 404, description = "Pool not found", body = ApiErrorResponse),
        (status = 409, description = "Lease request conflicts with pool state", body = ApiErrorResponse),
        (status = 503, description = "No clean worker ready yet", body = ApiErrorResponse)
    )
)]
pub async fn acquire_lease(
    State(state): State<Arc<ApiState>>,
    Path(pool_name): Path<String>,
    Json(req): Json<AcquireForkLeaseRequest>,
) -> Result<Json<ForkLeaseInfo>, ApiError> {
    Ok(Json(acquire_lease_inner(state, pool_name, req).await?))
}

async fn acquire_lease_inner(
    state: Arc<ApiState>,
    pool_name: String,
    req: AcquireForkLeaseRequest,
) -> Result<ForkLeaseInfo, ApiError> {
    if req.idempotency_key.is_empty()
        || req.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || req.idempotency_key.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "idempotencyKey must contain 1-{MAX_IDEMPOTENCY_KEY_BYTES} non-control bytes"
        )));
    }
    let lease_id = format!(
        "lease-{}{}",
        crate::util::generate_short_id(),
        crate::util::generate_short_id()
    );
    let worker_ready_timeout =
        validate_worker_ready_request(req.await_worker_ready, req.worker_ready_timeout_secs)?;
    let mut assignment = crate::util::parse_env_list(&req.env);
    crate::agent::fork::validate_fork_env(&assignment)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    for reserved in RESERVED_LEASE_ENV {
        if assignment.iter().any(|(key, _)| key == reserved) {
            return Err(ApiError::BadRequest(format!(
                "{reserved} is reserved for smolvm lease activation"
            )));
        }
    }
    if let Some(access) = &req.rollout_access {
        crate::api::rollout::validate_name("rollout executor", &access.executor)
            .map_err(ApiError::from)?;
        crate::api::rollout::validate_name("rollout policy", &access.policy)
            .map_err(ApiError::from)?;
    }
    let worker_ready = worker_ready_timeout.map(|timeout| {
        add_worker_ready_assignment(&mut assignment, &pool_name, &req.idempotency_key, timeout)
            .map(|token| (token, Duration::from_secs(timeout)))
    });
    let worker_ready = match worker_ready {
        Some(result) => Some(result?),
        None => None,
    };
    let (files, payload_sha256) = validate_lease_payload(&req.files)?;
    let db = state.db().clone();
    let lookup = pool_name.clone();
    let pool = tokio::task::spawn_blocking(move || db.get_fork_pool(&lookup))
        .await
        .map_err(|e| ApiError::internal(format!("pool lookup task failed: {e}")))?
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("fork pool '{pool_name}' not found")))?;
    if let Some(access) = &req.rollout_access {
        let golden = state.lookup_vm(&pool.golden).await?.ok_or_else(|| {
            ApiError::Conflict(format!("pool golden '{}' no longer exists", pool.golden))
        })?;
        let guest_host_service =
            crate::network::launch::guest_host_service().map_err(|reason| {
                ApiError::internal(format!("read guest rollout ingress: {reason}"))
            })?;
        validate_rollout_access_target(&golden, guest_host_service)?;
        state
            .rollout()
            .get(&access.executor)
            .await
            .map_err(ApiError::from)?;
        add_rollout_access_assignment(&mut assignment, &lease_id, access)?;
    }
    if pool.admission_device_ordinal().is_some()
        && assignment
            .iter()
            .any(|(key, _)| key == "SMOLVM_CUDA_DEVICE")
    {
        return Err(ApiError::BadRequest(
            "SMOLVM_CUDA_DEVICE is inherited from the pool golden and cannot be changed by a lease"
                .into(),
        ));
    }
    let ttl = validate_ttl(req.ttl_secs.unwrap_or(pool.lease_ttl_secs))?;
    let now = crate::util::current_timestamp();
    let db = state.db().clone();
    let pool_for_claim = pool_name.clone();
    let key = req.idempotency_key.clone();
    let assignment_for_claim = assignment.clone();
    let payload_for_claim = payload_sha256.clone();
    let require_private_workspace = !files.is_empty();
    let admission_limit = state.admission().limit(&pool);
    let claim = tokio::task::spawn_blocking(move || {
        db.claim_fork_pool_slot(ForkPoolSlotClaim {
            pool_name: &pool_for_claim,
            lease_id: &lease_id,
            idempotency_key: &key,
            assignment: &assignment_for_claim,
            payload_sha256: payload_for_claim.as_deref(),
            require_private_workspace,
            admission_limit,
            ttl_secs: ttl,
            now,
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("pool claim task failed: {e}")))?
    .map_err(ApiError::database)?;
    let lease = match claim {
        ClaimForkPoolSlot::Existing(lease) => {
            if !idempotent_assignment_matches(&lease.assignment, &assignment)
                || lease.payload_sha256 != payload_sha256
                || lease.ttl_secs != ttl
            {
                return Err(ApiError::Conflict(
                    "idempotencyKey was already used with a different assignment, payload, or TTL"
                        .into(),
                ));
            }
            let lease = if let Some((_, timeout)) = worker_ready.as_ref() {
                wait_for_existing_activation(&state, lease, *timeout).await?
            } else {
                lease
            };
            return Ok(lease_info(lease));
        }
        ClaimForkPoolSlot::NoReadySlot => {
            return Err(ApiError::Unavailable(format!(
                "fork pool '{pool_name}' has no clean worker ready"
            )))
        }
        ClaimForkPoolSlot::AtCapacity => {
            state.admission().note_blocked(&pool_name);
            let limit = admission_limit
                .map(|limit| limit.pool)
                .or(pool.max_active);
            return Err(ApiError::Conflict(format!(
                "fork pool '{pool_name}' reached active lease limit{}",
                limit.map(|value| format!(" ({value})")).unwrap_or_default()
            )))
        }
        ClaimForkPoolSlot::PoolNotFound => {
            return Err(ApiError::NotFound(format!(
                "fork pool '{pool_name}' not found"
            )))
        }
        ClaimForkPoolSlot::PoolDeleting => {
            return Err(ApiError::Conflict(format!(
                "fork pool '{pool_name}' is deleting"
            )))
        }
        ClaimForkPoolSlot::WorkspaceExternallyMounted => {
            return Err(ApiError::Conflict(
                "lease payload staging requires smolvm's private /workspace; this pool's worker mounts external storage inside /workspace"
                    .into(),
            ))
        }
        ClaimForkPoolSlot::Claimed(lease) => lease,
    };
    // Reflect the durable claim in the in-memory fast path before publishing
    // the guest release marker. The authoritative held bit is already false in
    // SQLite, so a restart cannot resurrect this worker as ready.
    if let Ok(entry) = state.get_machine(&lease.machine_name) {
        entry.lock().forkpoint_held = false;
    }
    // Run activation in its own task. Dropping an HTTP request future does not
    // cancel this task, so a client disconnect after the durable claim cannot
    // strand a successfully released guest forever in `activating` state.
    let active = tokio::spawn(activate_claimed_lease(
        state.clone(),
        lease,
        assignment,
        files,
        worker_ready,
    ))
    .await
    .map_err(|e| ApiError::internal(format!("pool activation task failed: {e}")))?
    .map_err(ApiError::Internal)?;
    // The durable claim removed one ready slot. Refill it only after payload
    // staging and any requested worker-readiness wait complete. Starting
    // replacement VMs earlier can starve the held workers' control channels.
    state.notify_pool_reconcile();
    Ok(lease_info(active))
}

/// Acquire and activate a bounded group of independently idempotent workers.
#[utoipa::path(
    post,
    path = "/api/v1/pools/{name}/lease-batches",
    tag = "Pools",
    params(("name" = String, Path, description = "Pool name")),
    request_body = AcquireForkLeaseBatchRequest,
    responses(
        (status = 200, description = "Ordered per-request lease results", body = AcquireForkLeaseBatchResponse),
        (status = 400, description = "Invalid or oversized batch", body = ApiErrorResponse)
    )
)]
pub async fn acquire_lease_batch(
    State(state): State<Arc<ApiState>>,
    Path(pool_name): Path<String>,
    Json(req): Json<AcquireForkLeaseBatchRequest>,
) -> Result<Json<AcquireForkLeaseBatchResponse>, ApiError> {
    validate_lease_batch(&req.leases)?;
    metrics::counter!("smolvm_fork_lease_batches_total").increment(1);
    metrics::histogram!("smolvm_fork_lease_batch_size").record(req.leases.len() as f64);

    let mut results = stream::iter(req.leases.into_iter().enumerate().map(|(index, request)| {
        let state = state.clone();
        let pool_name = pool_name.clone();
        async move {
            let idempotency_key = request.idempotency_key.clone();
            let result = match acquire_lease_inner(state, pool_name, request).await {
                Ok(lease) => ForkLeaseBatchItemResponse {
                    idempotency_key,
                    lease: Some(lease),
                    error_code: None,
                    error: None,
                },
                Err(error) => {
                    let (error_code, error) = lease_batch_error(error);
                    ForkLeaseBatchItemResponse {
                        idempotency_key,
                        lease: None,
                        error_code: Some(error_code.into()),
                        error: Some(error),
                    }
                }
            };
            (index, result)
        }
    }))
    .buffer_unordered(MAX_CONCURRENT_LEASE_ACTIVATIONS)
    .collect::<Vec<_>>()
    .await;
    results.sort_unstable_by_key(|(index, _)| *index);
    let leases = results
        .into_iter()
        .map(|(_, result)| result)
        .collect::<Vec<_>>();
    let succeeded = leases
        .iter()
        .filter(|result| result.lease.is_some())
        .count();
    metrics::counter!("smolvm_fork_lease_batch_items_total", "status" => "succeeded")
        .increment(succeeded as u64);
    metrics::counter!("smolvm_fork_lease_batch_items_total", "status" => "failed")
        .increment((leases.len() - succeeded) as u64);
    Ok(Json(AcquireForkLeaseBatchResponse { leases }))
}

fn validate_lease_batch(leases: &[AcquireForkLeaseRequest]) -> Result<(), ApiError> {
    if leases.is_empty() || leases.len() > MAX_LEASE_BATCH_SIZE {
        return Err(ApiError::BadRequest(format!(
            "leases must contain between 1 and {MAX_LEASE_BATCH_SIZE} items"
        )));
    }
    let mut keys = std::collections::HashSet::with_capacity(leases.len());
    if let Some(duplicate) = leases
        .iter()
        .map(|lease| lease.idempotency_key.as_str())
        .find(|key| !keys.insert((*key).to_string()))
    {
        return Err(ApiError::BadRequest(format!(
            "idempotencyKey '{duplicate}' is duplicated within the lease batch"
        )));
    }
    let readiness_waiters = leases
        .iter()
        .filter(|lease| lease.await_worker_ready)
        .count();
    if readiness_waiters > MAX_CONCURRENT_LEASE_ACTIVATIONS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_CONCURRENT_LEASE_ACTIVATIONS} batch items may set awaitWorkerReady=true"
        )));
    }
    Ok(())
}

fn lease_batch_error(error: ApiError) -> (&'static str, String) {
    match error {
        ApiError::Unauthorized(message) => ("UNAUTHORIZED", message),
        ApiError::Forbidden(message) => ("FORBIDDEN", message),
        ApiError::NotFound(message) => ("NOT_FOUND", message),
        ApiError::Conflict(message) => ("CONFLICT", message),
        ApiError::PortConflict(message) => ("PORT_IN_USE", message),
        ApiError::CloneIdentityRejuvenationFailed(message) => {
            ("CLONE_IDENTITY_REJUVENATION_FAILED", message)
        }
        ApiError::BadRequest(message) => ("BAD_REQUEST", message),
        ApiError::Timeout => ("TIMEOUT", "request timed out".into()),
        ApiError::Unavailable(message) => ("UNAVAILABLE", message),
        ApiError::Internal(message) => ("INTERNAL_ERROR", message),
    }
}

/// Get one lease's durable state.
#[utoipa::path(
    get,
    path = "/api/v1/pools/{name}/leases/{lease}",
    tag = "Pools",
    params(
        ("name" = String, Path, description = "Pool name"),
        ("lease" = String, Path, description = "Lease ID")
    ),
    responses(
        (status = 200, description = "Lease state", body = ForkLeaseInfo),
        (status = 404, description = "Lease not found", body = ApiErrorResponse)
    )
)]
pub async fn get_lease(
    State(state): State<Arc<ApiState>>,
    Path((pool_name, lease_id)): Path<(String, String)>,
) -> Result<Json<ForkLeaseInfo>, ApiError> {
    let db = state.db().clone();
    let lookup_pool = pool_name.clone();
    let lookup_lease = lease_id.clone();
    let lease = tokio::task::spawn_blocking(move || db.get_fork_lease(&lookup_pool, &lookup_lease))
        .await
        .map_err(|e| ApiError::internal(format!("lease lookup task failed: {e}")))?
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "lease '{lease_id}' not found in fork pool '{pool_name}'"
            ))
        })?;
    Ok(Json(lease_info(lease)))
}

/// Extend one active lease's expiry.
#[utoipa::path(
    post,
    path = "/api/v1/pools/{name}/leases/{lease}/heartbeat",
    tag = "Pools",
    params(
        ("name" = String, Path, description = "Pool name"),
        ("lease" = String, Path, description = "Lease ID")
    ),
    responses(
        (status = 200, description = "Extended lease", body = ForkLeaseInfo),
        (status = 404, description = "Lease not found", body = ApiErrorResponse),
        (status = 409, description = "Lease is no longer active", body = ApiErrorResponse)
    )
)]
pub async fn heartbeat_lease(
    State(state): State<Arc<ApiState>>,
    Path((pool_name, lease_id)): Path<(String, String)>,
) -> Result<Json<ForkLeaseInfo>, ApiError> {
    let now = crate::util::current_timestamp();
    let db = state.db().clone();
    let lookup_pool = pool_name.clone();
    let lookup_lease = lease_id.clone();
    let lease = tokio::task::spawn_blocking(move || {
        db.heartbeat_fork_lease(&lookup_pool, &lookup_lease, now)
    })
    .await
    .map_err(|e| ApiError::internal(format!("lease heartbeat task failed: {e}")))?
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::NotFound(format!("fork lease '{lease_id}' not found")))?;
    if lease.state != ForkLeaseState::Active || lease.expires_at <= now {
        return Err(ApiError::Conflict(format!(
            "fork lease '{lease_id}' is no longer active"
        )));
    }
    let worker_alive = state
        .lookup_vm(&lease.machine_name)
        .await?
        .map(|record| record.is_process_alive())
        .unwrap_or(false);
    if !worker_alive {
        let db = state.db().clone();
        let failed_lease = lease.id.clone();
        tokio::task::spawn_blocking(move || {
            db.fail_active_fork_lease(
                &failed_lease,
                crate::util::current_timestamp(),
                "leased worker process exited".into(),
            )
        })
        .await
        .map_err(|e| ApiError::internal(format!("failed lease task failed: {e}")))?
        .map_err(ApiError::database)?;
        state.notify_pool_reconcile();
        return Err(ApiError::Conflict(format!(
            "fork lease '{lease_id}' worker is no longer running"
        )));
    }
    Ok(Json(lease_info(lease)))
}

/// Complete one active lease and asynchronously replace its worker.
#[utoipa::path(
    post,
    path = "/api/v1/pools/{name}/leases/{lease}/complete",
    tag = "Pools",
    params(
        ("name" = String, Path, description = "Pool name"),
        ("lease" = String, Path, description = "Lease ID")
    ),
    responses(
        (status = 200, description = "Completed lease", body = ForkLeaseInfo),
        (status = 404, description = "Lease not found", body = ApiErrorResponse),
        (status = 409, description = "Lease is not active", body = ApiErrorResponse)
    )
)]
pub async fn complete_lease(
    State(state): State<Arc<ApiState>>,
    Path((pool_name, lease_id)): Path<(String, String)>,
) -> Result<Json<ForkLeaseInfo>, ApiError> {
    let db = state.db().clone();
    let complete_pool = pool_name.clone();
    let complete_lease = lease_id.clone();
    let lease = tokio::task::spawn_blocking(move || {
        db.complete_fork_lease(
            &complete_pool,
            &complete_lease,
            crate::util::current_timestamp(),
        )
    })
    .await
    .map_err(|e| ApiError::internal(format!("lease completion task failed: {e}")))?
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::NotFound(format!("fork lease '{lease_id}' not found")))?;
    if lease.state != ForkLeaseState::Completed {
        return Err(ApiError::Conflict(format!(
            "fork lease '{lease_id}' is '{}', not active",
            lease.state.as_str()
        )));
    }
    state.notify_pool_reconcile();
    Ok(Json(lease_info(lease)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{ForkLeasePayloadFile, RolloutLeaseAccess};

    fn payload(path: &str, data: &[u8], mode: Option<u32>) -> ForkLeasePayloadFile {
        ForkLeasePayloadFile {
            path: path.into(),
            data_base64: base64::engine::general_purpose::STANDARD.encode(data),
            mode,
        }
    }

    fn bad_request(error: ApiError) -> String {
        match error {
            ApiError::BadRequest(message) => message,
            other => panic!("expected bad request, got {other:?}"),
        }
    }

    fn lease_request(idempotency_key: &str) -> AcquireForkLeaseRequest {
        AcquireForkLeaseRequest {
            idempotency_key: idempotency_key.into(),
            env: Vec::new(),
            files: Vec::new(),
            ttl_secs: None,
            await_worker_ready: false,
            worker_ready_timeout_secs: None,
            rollout_access: None,
        }
    }

    #[test]
    fn lease_batch_requires_a_bounded_nonempty_group() {
        let error = validate_lease_batch(&[]).unwrap_err();
        assert!(bad_request(error).contains("between 1 and 256"));

        let oversized = (0..=MAX_LEASE_BATCH_SIZE)
            .map(|index| lease_request(&format!("request-{index}")))
            .collect::<Vec<_>>();
        let error = validate_lease_batch(&oversized).unwrap_err();
        assert!(bad_request(error).contains("between 1 and 256"));

        let readiness_waiters = (0..=MAX_CONCURRENT_LEASE_ACTIVATIONS)
            .map(|index| AcquireForkLeaseRequest {
                await_worker_ready: true,
                ..lease_request(&format!("ready-{index}"))
            })
            .collect::<Vec<_>>();
        let error = validate_lease_batch(&readiness_waiters).unwrap_err();
        assert!(bad_request(error).contains("at most 32 batch items"));

        let bounded_readiness_waiters = readiness_waiters
            .into_iter()
            .take(MAX_CONCURRENT_LEASE_ACTIVATIONS)
            .collect::<Vec<_>>();
        assert!(validate_lease_batch(&bounded_readiness_waiters).is_ok());
    }

    #[test]
    fn lease_batch_rejects_duplicate_retry_keys_before_claiming() {
        let error =
            validate_lease_batch(&[lease_request("same"), lease_request("same")]).unwrap_err();
        assert!(bad_request(error).contains("'same' is duplicated"));
        assert!(validate_lease_batch(&[lease_request("first"), lease_request("second"),]).is_ok());
    }

    #[test]
    fn lease_batch_error_codes_match_the_public_api() {
        let cases = [
            (ApiError::BadRequest("bad".into()), "BAD_REQUEST", "bad"),
            (ApiError::Conflict("busy".into()), "CONFLICT", "busy"),
            (
                ApiError::CloneIdentityRejuvenationFailed("reset failed".into()),
                "CLONE_IDENTITY_REJUVENATION_FAILED",
                "reset failed",
            ),
            (
                ApiError::Unavailable("empty".into()),
                "UNAVAILABLE",
                "empty",
            ),
            (ApiError::Timeout, "TIMEOUT", "request timed out"),
        ];
        for (error, expected_code, expected_message) in cases {
            let (code, message) = lease_batch_error(error);
            assert_eq!(code, expected_code);
            assert_eq!(message, expected_message);
        }
    }

    #[test]
    fn lease_batch_request_debug_redacts_nested_payloads() {
        let request = AcquireForkLeaseBatchRequest {
            leases: vec![AcquireForkLeaseRequest {
                files: vec![payload("job.json", b"private-job-data", None)],
                rollout_access: Some(RolloutLeaseAccess {
                    executor: "rollouts".into(),
                    policy: "policy-a".into(),
                }),
                ..lease_request("request-1")
            }],
        };
        let shown = format!("{request:?}");
        assert!(!shown.contains("private-job-data"));
        assert!(shown.contains("<redacted>"));
    }

    #[tokio::test]
    async fn lease_batch_preserves_input_order_for_independent_failures() {
        let directory = tempfile::TempDir::new().unwrap();
        let db = crate::db::SmolvmDb::open_at(&directory.path().join("test.db")).unwrap();
        let state = Arc::new(ApiState::with_db(db));
        let response = acquire_lease_batch(
            State(state),
            Path("missing-pool".into()),
            Json(AcquireForkLeaseBatchRequest {
                leases: vec![
                    lease_request("first"),
                    lease_request("second"),
                    lease_request("third"),
                ],
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(
            response
                .leases
                .iter()
                .map(|item| item.idempotency_key.as_str())
                .collect::<Vec<_>>(),
            ["first", "second", "third"]
        );
        assert!(
            response.leases.iter().all(|item| {
                item.lease.is_none()
                    && item.error_code.as_deref() == Some("NOT_FOUND")
                    && item.error.as_deref().is_some_and(|message| {
                        message.contains("fork pool 'missing-pool' not found")
                    })
            }),
            "{:?}",
            response.leases
        );
    }

    #[test]
    fn lease_payload_stage_retries_an_ambiguous_agent_reply() {
        let mut attempts = 0;
        retry_transient_lease_stage(|| {
            attempts += 1;
            if attempts == 1 {
                Err(crate::Error::agent(
                    "write file",
                    "Resource temporarily unavailable (os error 11)",
                ))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, 2);
    }

    #[test]
    fn lease_payload_stage_does_not_retry_a_guest_rejection() {
        let mut attempts = 0;
        let error = retry_transient_lease_stage(|| {
            attempts += 1;
            Err(crate::Error::agent("write file", "permission denied"))
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert!(error.to_string().contains("permission denied"));
    }

    #[test]
    fn lease_payload_is_canonical_and_order_independent() {
        let first = vec![
            payload("jobs/z.json", b"z", Some(0o600)),
            payload("jobs/a.json", b"a", None),
        ];
        let second = vec![first[1].clone(), first[0].clone()];
        let (staged_first, digest_first) = validate_lease_payload(&first).unwrap();
        let (staged_second, digest_second) = validate_lease_payload(&second).unwrap();

        assert_eq!(digest_first, digest_second);
        assert_eq!(staged_first[0].path, "jobs/a.json");
        assert_eq!(staged_first[0].mode, 0o644);
        assert_eq!(staged_second[1].path, "jobs/z.json");
    }

    #[test]
    fn lease_payload_rejects_unsafe_or_ambiguous_paths() {
        for path in [
            "",
            "/absolute",
            "../escape",
            "jobs/../escape",
            "jobs/./file",
            "jobs//file",
            "jobs\\file",
            "jobs/file/",
        ] {
            let error = validate_lease_payload(&[payload(path, b"x", None)])
                .err()
                .expect("unsafe path should fail");
            assert!(bad_request(error).contains("safe relative path"), "{path}");
        }

        let duplicate = vec![
            payload("job.json", b"a", None),
            payload("job.json", b"b", None),
        ];
        assert!(bad_request(
            validate_lease_payload(&duplicate)
                .err()
                .expect("duplicate path should fail")
        )
        .contains("duplicated"));
    }

    #[test]
    fn lease_payload_enforces_encoding_mode_and_size_limits() {
        let invalid_base64 = ForkLeasePayloadFile {
            path: "job.json".into(),
            data_base64: "***".into(),
            mode: None,
        };
        assert!(bad_request(
            validate_lease_payload(&[invalid_base64])
                .err()
                .expect("invalid base64 should fail")
        )
        .contains("not valid standard base64"));

        let invalid_mode = payload("job.sh", b"x", Some(0o1000));
        assert!(bad_request(
            validate_lease_payload(&[invalid_mode])
                .err()
                .expect("invalid mode should fail")
        )
        .contains("permission bits"));

        let oversized = payload("large.bin", &vec![0u8; MAX_LEASE_PAYLOAD_BYTES + 1], None);
        assert!(bad_request(
            validate_lease_payload(&[oversized])
                .err()
                .expect("oversized payload should fail")
        )
        .contains("must total at most"));

        let too_many: Vec<_> = (0..=MAX_LEASE_PAYLOAD_FILES)
            .map(|index| payload(&format!("{index}.json"), b"x", None))
            .collect();
        assert!(bad_request(
            validate_lease_payload(&too_many)
                .err()
                .expect("too many files should fail")
        )
        .contains("at most"));

        let long_path = "a".repeat(MAX_LEASE_PAYLOAD_PATH_BYTES + 1);
        assert!(bad_request(
            validate_lease_payload(&[payload(&long_path, b"x", None)])
                .err()
                .expect("long path should fail")
        )
        .contains("safe relative path"));
    }

    #[test]
    fn lease_payload_debug_redacts_contents() {
        let file = ForkLeasePayloadFile {
            path: "job.json".into(),
            data_base64: "customer-secret".into(),
            mode: None,
        };
        let shown = format!("{file:?}");
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("customer-secret"));
    }

    #[test]
    fn legacy_lease_request_defaults_to_no_payload() {
        let request: AcquireForkLeaseRequest = serde_json::from_str(
            r#"{"idempotencyKey":"request-a","env":["EPISODE=42"],"ttlSecs":60}"#,
        )
        .unwrap();
        assert!(request.files.is_empty());
        assert!(!request.await_worker_ready);
        assert_eq!(request.worker_ready_timeout_secs, None);
        assert_eq!(request.rollout_access, None);
    }

    #[test]
    fn worker_ready_timeout_is_explicit_bounded_and_opt_in() {
        assert_eq!(validate_worker_ready_request(false, None).unwrap(), None);
        assert_eq!(
            validate_worker_ready_request(true, None).unwrap(),
            Some(DEFAULT_WORKER_READY_TIMEOUT_SECS)
        );
        assert_eq!(
            validate_worker_ready_request(true, Some(37)).unwrap(),
            Some(37)
        );
        assert!(
            bad_request(validate_worker_ready_request(false, Some(1)).unwrap_err())
                .contains("requires awaitWorkerReady=true")
        );
        assert!(
            bad_request(validate_worker_ready_request(true, Some(0)).unwrap_err())
                .contains("between 1")
        );
        assert!(bad_request(
            validate_worker_ready_request(true, Some(MAX_WORKER_READY_TIMEOUT_SECS + 1))
                .unwrap_err()
        )
        .contains("between 1"));
    }

    #[test]
    fn worker_ready_assignment_is_retry_stable_and_pool_scoped() {
        let first = worker_ready_token("pool-a", "request-1");
        assert_eq!(first, worker_ready_token("pool-a", "request-1"));
        assert_ne!(first, worker_ready_token("pool-b", "request-1"));
        assert_ne!(first, worker_ready_token("pool-a", "request-2"));
        assert_eq!(first.len(), 64);

        let mut assignment = vec![("LEARNER".into(), "3".into())];
        let token = add_worker_ready_assignment(
            &mut assignment,
            "pool-a",
            "request-1",
            DEFAULT_WORKER_READY_TIMEOUT_SECS,
        )
        .unwrap();
        assert_eq!(token, first);
        assert!(assignment.contains(&(
            smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV.into(),
            first
        )));
        assert!(assignment.contains(&(
            WORKER_READY_TIMEOUT_ENV.into(),
            DEFAULT_WORKER_READY_TIMEOUT_SECS.to_string()
        )));

        let mut reserved = vec![(
            smolvm_protocol::forkpoint::WORKER_READY_TOKEN_ENV.into(),
            "user-value".into(),
        )];
        assert!(bad_request(
            add_worker_ready_assignment(&mut reserved, "pool", "request", 1).unwrap_err()
        )
        .contains("reserved"));
    }

    #[test]
    fn rollout_assignment_is_scoped_and_idempotency_ignores_only_its_secret() {
        let access = crate::api::types::RolloutLeaseAccess {
            executor: "executor-a".into(),
            policy: "policy-3".into(),
        };
        let mut first = vec![("LEARNER".into(), "3".into())];
        let mut retry = first.clone();
        add_rollout_access_assignment(&mut first, "lease-1111111111111111", &access).unwrap();
        add_rollout_access_assignment(&mut retry, "lease-2222222222222222", &access).unwrap();
        assert!(idempotent_assignment_matches(&first, &retry));
        assert_ne!(
            first
                .iter()
                .find(|(key, _)| key == crate::api::guest_rollout::ROLLOUT_TOKEN_ENV),
            retry
                .iter()
                .find(|(key, _)| key == crate::api::guest_rollout::ROLLOUT_TOKEN_ENV)
        );
        assert!(first.contains(&(
            crate::api::guest_rollout::ROLLOUT_URL_ENV.into(),
            crate::api::guest_rollout::lease_rollout_url("executor-a")
        )));

        retry
            .iter_mut()
            .find(|(key, _)| key == crate::api::guest_rollout::ROLLOUT_POLICY_ENV)
            .unwrap()
            .1 = "another-policy".into();
        assert!(!idempotent_assignment_matches(&first, &retry));
    }

    #[test]
    fn rollout_access_requires_reachable_non_pod_virtio_networking() {
        let mut golden =
            crate::config::VmRecord::new("golden".into(), 2, 1024, vec![], vec![], false);
        assert!(matches!(
            validate_rollout_access_target(
                &golden,
                Some(smolvm_network::GatewayHostService {
                    guest_port: crate::api::guest_rollout::GUEST_ROLLOUT_PORT,
                    host_port: 40_081,
                })
            ),
            Err(ApiError::Conflict(_))
        ));

        golden.network = true;
        assert!(validate_rollout_access_target(
            &golden,
            Some(smolvm_network::GatewayHostService {
                guest_port: crate::api::guest_rollout::GUEST_ROLLOUT_PORT,
                host_port: 40_081,
            })
        )
        .is_ok());
        assert!(matches!(
            validate_rollout_access_target(&golden, None),
            Err(ApiError::Conflict(_))
        ));

        golden.network_backend = Some(crate::network::NetworkBackend::Tsi);
        assert!(matches!(
            validate_rollout_access_target(
                &golden,
                Some(smolvm_network::GatewayHostService {
                    guest_port: crate::api::guest_rollout::GUEST_ROLLOUT_PORT,
                    host_port: 40_081,
                })
            ),
            Err(ApiError::Conflict(_))
        ));

        golden.network_backend = Some(crate::network::NetworkBackend::VirtioNet);
        golden.runtime_managed = true;
        assert!(matches!(
            validate_rollout_access_target(
                &golden,
                Some(smolvm_network::GatewayHostService {
                    guest_port: crate::api::guest_rollout::GUEST_ROLLOUT_PORT,
                    host_port: 40_081,
                })
            ),
            Err(ApiError::Conflict(_))
        ));
    }
}
