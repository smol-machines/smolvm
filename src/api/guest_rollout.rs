//! Lease-authenticated guest ingress for fused rollout workers.

use axum::{
    extract::{DefaultBodyLimit, Extension, Path, Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{delete, post},
    Json, Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::api::error::ApiError;
use crate::api::handlers;
use crate::api::rollout::{
    PublishDeviceRolloutPolicyRequest, RolloutBatchRequest, RolloutBatchResponse,
    RolloutGenerateRequest, RolloutGenerateResponse, RolloutPolicyInfo,
};
use crate::api::state::ApiState;
use crate::pool::{ForkLeaseRecord, ForkLeaseState};

/// Dedicated loopback port reachable only through a VM's virtio gateway.
pub const GUEST_ROLLOUT_PORT: u16 = 10_081;
/// Operator override for the rollout listener's host loopback port.
pub const GUEST_ROLLOUT_HOST_PORT_ENV: &str = "SMOLVM_GUEST_ROLLOUT_HOST_PORT";
/// Host-only gateway mapping inherited by VMM subprocesses.
pub const GUEST_HOST_SERVICE_ENV: &str = "SMOLVM_GUEST_HOST_SERVICE";
/// Bearer credential injected into the claimed worker.
pub const ROLLOUT_TOKEN_ENV: &str = "SMOLVM_ROLLOUT_TOKEN";
/// Lease-scoped executor URL injected into the claimed worker.
pub const ROLLOUT_URL_ENV: &str = "SMOLVM_ROLLOUT_URL";
/// Executor scope retained in the durable lease assignment.
pub const ROLLOUT_EXECUTOR_ENV: &str = "SMOLVM_ROLLOUT_EXECUTOR";
/// Policy scope retained in the durable lease assignment.
pub const ROLLOUT_POLICY_ENV: &str = "SMOLVM_ROLLOUT_POLICY";

const MAX_ROLLOUT_REQUEST_BYTES: usize = 20 * 1024 * 1024;
const TOKEN_SECRET_BYTES: usize = 32;
const MAX_CONCURRENT_AUTH_LOOKUPS: usize = 64;
const AUTH_LOOKUP_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone)]
struct RolloutAuthState {
    api: Arc<ApiState>,
    lookup_permits: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
struct RolloutLeaseScope {
    executor: String,
    policy: String,
}

impl RolloutLeaseScope {
    fn require_executor(&self, executor: &str) -> Result<(), ApiError> {
        if self.executor == executor {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "lease credential is not authorized for this rollout executor".into(),
            ))
        }
    }

    fn require_policy(&self, policy: &str) -> Result<(), ApiError> {
        if self.policy == policy {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "lease credential is not authorized for this rollout policy".into(),
            ))
        }
    }
}

/// Issue a high-entropy bearer whose prefix makes its durable lease lookup O(1).
pub(crate) fn issue_lease_credential(lease_id: &str) -> Result<String, getrandom::Error> {
    let mut secret = [0_u8; TOKEN_SECRET_BYTES];
    getrandom::fill(&mut secret)?;
    Ok(format!("{lease_id}.{}", hex::encode(secret)))
}

/// URL presented to a guest after its rollout scope has been validated.
pub(crate) fn lease_rollout_url(executor: &str) -> String {
    format!("http://100.96.0.1:{GUEST_ROLLOUT_PORT}/api/v1/rollout-executors/{executor}")
}

fn assignment_value<'a>(lease: &'a ForkLeaseRecord, key: &str) -> Option<&'a str> {
    let mut values = lease
        .assignment
        .iter()
        .filter_map(|(candidate, value)| (candidate == key).then_some(value.as_str()));
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn lease_scope(lease: &ForkLeaseRecord, presented: &str, now: u64) -> Option<RolloutLeaseScope> {
    if !matches!(
        lease.state,
        ForkLeaseState::Activating | ForkLeaseState::Active
    ) || lease.expires_at <= now
    {
        return None;
    }
    let expected = assignment_value(lease, ROLLOUT_TOKEN_ENV)?;
    if !constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
        return None;
    }
    Some(RolloutLeaseScope {
        executor: assignment_value(lease, ROLLOUT_EXECUTOR_ENV)?.to_string(),
        policy: assignment_value(lease, ROLLOUT_POLICY_ENV)?.to_string(),
    })
}

fn credential_lease_id(credential: &str) -> Option<&str> {
    let (lease_id, secret) = credential.split_once('.')?;
    let valid_lease = lease_id.starts_with("lease-")
        && lease_id.len() <= 128
        && lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    let valid_secret = secret.len() == TOKEN_SECRET_BYTES * 2
        && secret.bytes().all(|byte| byte.is_ascii_hexdigit());
    (valid_lease && valid_secret).then_some(lease_id)
}

fn bearer_credential(request: &Request) -> Option<&str> {
    let value = request.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credential) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !credential.is_empty()).then_some(credential)
}

async fn authenticate_lease(
    State(auth): State<RolloutAuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let credential = bearer_credential(&request).ok_or_else(|| {
        ApiError::Unauthorized("a valid rollout lease bearer credential is required".into())
    })?;
    let lease_id = credential_lease_id(credential).ok_or_else(|| {
        ApiError::Unauthorized("a valid rollout lease bearer credential is required".into())
    })?;
    let lookup = lease_id.to_string();
    let presented = credential.to_string();
    let _lookup_permit =
        tokio::time::timeout(AUTH_LOOKUP_QUEUE_TIMEOUT, auth.lookup_permits.acquire())
            .await
            .map_err(|_| {
                ApiError::Unavailable("rollout authentication is busy; retry shortly".into())
            })?
            .map_err(|_| ApiError::internal("rollout authentication is shutting down"))?;
    let db = auth.api.db().clone();
    let lease = tokio::task::spawn_blocking(move || db.get_fork_lease_by_id(&lookup))
        .await
        .map_err(|error| ApiError::internal(format!("rollout lease lookup task failed: {error}")))?
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::Unauthorized("a valid rollout lease bearer credential is required".into())
        })?;
    let scope =
        lease_scope(&lease, &presented, crate::util::current_timestamp()).ok_or_else(|| {
            ApiError::Unauthorized("a valid rollout lease bearer credential is required".into())
        })?;
    drop(_lookup_permit);
    request.extensions_mut().insert(scope);
    Ok(next.run(request).await)
}

async fn publish_device_policy(
    Extension(scope): Extension<RolloutLeaseScope>,
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(request): Json<PublishDeviceRolloutPolicyRequest>,
) -> Result<(StatusCode, Json<RolloutPolicyInfo>), ApiError> {
    scope.require_executor(&name)?;
    scope.require_policy(&request.policy)?;
    handlers::rollouts::publish_device_policy(State(state), Path(name), Json(request)).await
}

async fn retire_policy(
    Extension(scope): Extension<RolloutLeaseScope>,
    State(state): State<Arc<ApiState>>,
    Path((name, policy, version)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    scope.require_executor(&name)?;
    scope.require_policy(&policy)?;
    handlers::rollouts::retire_policy(State(state), Path((name, policy, version))).await
}

async fn generate(
    Extension(scope): Extension<RolloutLeaseScope>,
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(request): Json<RolloutGenerateRequest>,
) -> Result<Json<RolloutGenerateResponse>, ApiError> {
    scope.require_executor(&name)?;
    scope.require_policy(&request.policy)?;
    handlers::rollouts::generate(State(state), Path(name), Json(request)).await
}

async fn generate_batch(
    Extension(scope): Extension<RolloutLeaseScope>,
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(request): Json<RolloutBatchRequest>,
) -> Result<Json<RolloutBatchResponse>, ApiError> {
    scope.require_executor(&name)?;
    for job in &request.jobs {
        scope.require_policy(&job.policy)?;
    }
    handlers::rollouts::generate_batch(State(state), Path(name), Json(request)).await
}

/// Build the dedicated guest-only router; no machine or executor-management routes exist here.
pub fn create_router(state: Arc<ApiState>) -> Router {
    let auth = RolloutAuthState {
        api: state.clone(),
        lookup_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_AUTH_LOOKUPS)),
    };
    let protected = Router::new()
        .route("/{name}/device-policies", post(publish_device_policy))
        .route("/{name}/policies/{policy}/{version}", delete(retire_policy))
        .route("/{name}/generate", post(generate))
        .route("/{name}/batches", post(generate_batch))
        .layer(DefaultBodyLimit::max(MAX_ROLLOUT_REQUEST_BYTES))
        .layer(middleware::from_fn_with_state(auth, authenticate_lease));
    Router::new()
        .nest("/api/v1/rollout-executors", protected)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    fn lease(state: ForkLeaseState, expires_at: u64, token: &str) -> ForkLeaseRecord {
        ForkLeaseRecord {
            id: "lease-0123456789abcdef".into(),
            pool_name: "pool".into(),
            machine_name: "worker".into(),
            idempotency_key: "request".into(),
            state,
            assignment: vec![
                (ROLLOUT_TOKEN_ENV.into(), token.into()),
                (ROLLOUT_EXECUTOR_ENV.into(), "executor".into()),
                (ROLLOUT_POLICY_ENV.into(), "policy".into()),
            ],
            payload_sha256: None,
            created_at: 1,
            updated_at: 1,
            expires_at,
            ttl_secs: 60,
            last_error: None,
        }
    }

    #[test]
    fn credential_is_random_and_parseable() {
        let first = issue_lease_credential("lease-0123456789abcdef").unwrap();
        let second = issue_lease_credential("lease-0123456789abcdef").unwrap();
        assert_ne!(first, second);
        assert_eq!(credential_lease_id(&first), Some("lease-0123456789abcdef"));
        assert_eq!(first.len(), "lease-0123456789abcdef.".len() + 64);
    }

    #[test]
    fn scope_requires_live_lease_and_exact_token() {
        let token = format!("lease-0123456789abcdef.{}", "a".repeat(64));
        let activating = lease(ForkLeaseState::Activating, 20, &token);
        let active = lease(ForkLeaseState::Active, 20, &token);
        assert_eq!(
            lease_scope(&activating, &token, 10).unwrap().policy,
            "policy"
        );
        assert_eq!(
            lease_scope(&active, &token, 10).unwrap().executor,
            "executor"
        );
        assert!(lease_scope(&active, "wrong", 10).is_none());
        assert!(lease_scope(&active, &token, 20).is_none());
        assert!(lease_scope(&lease(ForkLeaseState::Completed, 20, &token), &token, 10).is_none());

        let mut ambiguous = active;
        ambiguous
            .assignment
            .push((ROLLOUT_TOKEN_ENV.into(), token.clone()));
        assert!(lease_scope(&ambiguous, &token, 10).is_none());
    }

    #[tokio::test]
    async fn guest_router_exposes_no_control_plane_routes_and_requires_auth() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::db::SmolvmDb::open_at(&dir.path().join("state.db")).unwrap();
        let router = create_router(Arc::new(ApiState::with_db(db.clone())));
        let control = HttpRequest::builder()
            .method("GET")
            .uri("/api/v1/machines")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(control).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let rollout = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/rollout-executors/executor/generate")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            router.oneshot(rollout).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn live_lease_authenticates_and_scope_blocks_other_executors() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::db::SmolvmDb::open_at(&dir.path().join("state.db")).unwrap();
        let now = crate::util::current_timestamp();
        db.insert_fork_pool_if_not_exists(&crate::pool::ForkPoolRecord {
            name: "pool".into(),
            golden: "golden".into(),
            desired_ready: 1,
            max_active: None,
            auto_admission: false,
            cuda_device_ordinal: None,
            share_weights: false,
            ready_timeout_secs: 30,
            lease_ttl_secs: 60,
            created_at: now,
            deleting: false,
        })
        .unwrap();
        let mut vm = crate::config::VmRecord::new("worker".into(), 2, 1024, vec![], vec![], false);
        vm.golden = Some("golden".into());
        vm.forkpoint_held = true;
        db.insert_vm("worker", &vm).unwrap();
        assert!(db.reserve_fork_pool_slot("pool", "worker", now).unwrap());
        assert!(db.mark_fork_pool_slot_ready("worker", now).unwrap());
        let token = format!("lease-0123456789abcdef.{}", "a".repeat(64));
        let assignment = vec![
            (ROLLOUT_TOKEN_ENV.into(), token.clone()),
            (ROLLOUT_EXECUTOR_ENV.into(), "executor".into()),
            (ROLLOUT_POLICY_ENV.into(), "policy".into()),
        ];
        let claimed = db
            .claim_fork_pool_slot(crate::db::ForkPoolSlotClaim {
                pool_name: "pool",
                lease_id: "lease-0123456789abcdef",
                idempotency_key: "request",
                assignment: &assignment,
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: None,
                ttl_secs: 60,
                now,
            })
            .unwrap();
        assert!(matches!(
            claimed,
            crate::pool::ClaimForkPoolSlot::Claimed(_)
        ));
        db.mark_fork_lease_active("lease-0123456789abcdef", now)
            .unwrap();
        let router = create_router(Arc::new(ApiState::with_db(db.clone())));
        let body = r#"{"idempotencyKey":"request","policy":"policy","prompts":[{"text":"hi"}],"sampling":{"maxTokens":1}}"#;

        let correct = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/rollout-executors/executor/generate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(correct).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "valid scoped auth must reach the handler"
        );

        let wrong_executor = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/rollout-executors/other/generate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            router
                .clone()
                .oneshot(wrong_executor)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );

        let wrong_policy_body = r#"{"idempotencyKey":"request-2","policy":"other","prompts":[{"text":"hi"}],"sampling":{"maxTokens":1}}"#;
        let wrong_policy = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/rollout-executors/executor/generate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(wrong_policy_body))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(wrong_policy).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        db.complete_fork_lease("pool", "lease-0123456789abcdef", now + 1)
            .unwrap();
        let revoked = HttpRequest::builder()
            .method("POST")
            .uri("/api/v1/rollout-executors/executor/generate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            router.oneshot(revoked).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
