//! Framework-neutral control plane for fused multi-policy rollout engines.
//!
//! smolvm does not attempt to infer framework semantics from CUDA calls. A
//! supported framework publishes immutable policy adapters here and submits
//! generation requests through one engine. The first backend is vLLM's
//! OpenAI-compatible completion API; isolated fork pools remain the advertised
//! fallback for requests a fused backend cannot represent.

use futures_util::StreamExt;
use parking_lot::Mutex as SyncMutex;
use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, OnceCell, RwLock, Semaphore};
use utoipa::ToSchema;

#[cfg(target_os = "linux")]
use crate::api::device_handoff::DeviceHandoffClient;

const DEFAULT_MAX_CONCURRENT: u32 = 32;
const MAX_CONCURRENT: u32 = 1024;
const DEFAULT_MAX_QUEUE_DEPTH: u32 = 256;
const MAX_QUEUE_DEPTH: u32 = 16_384;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;
const MAX_REQUEST_TIMEOUT_SECS: u64 = 60 * 60;
const MAX_NAME_BYTES: usize = 128;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_POLICY_VERSIONS: usize = 4096;
const MAX_PROMPTS: usize = 4096;
const MAX_PROMPT_TOKENS: usize = 1_048_576;
const MAX_PROMPT_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMPLETION_TOKENS: u32 = 65_536;
const MAX_BACKEND_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_ADAPTER_FILES: usize = 4096;
const MAX_ADAPTER_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const IDEMPOTENCY_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_IDEMPOTENCY_ENTRIES: usize = 8192;
const MAX_COHORT_SIZE: u32 = 256;

/// Request to register one local fused rollout engine.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateRolloutExecutorRequest {
    /// Stable executor name.
    pub name: String,
    /// Backend kind. Only `vllm` is currently supported.
    pub backend: String,
    /// Loopback HTTP endpoint of the backend, for example `http://127.0.0.1:8000`.
    pub endpoint: String,
    /// Host directory beneath which adapter paths must resolve.
    pub adapter_root: String,
    /// Optional private Unix socket for device-resident LoRA handoff without host staging.
    #[serde(default)]
    pub device_adapter_socket: Option<String>,
    /// Optional ordinary fork pool used by framework adapters as a compatibility fallback.
    #[serde(default)]
    pub fallback_pool: Option<String>,
    /// Maximum backend requests in flight.
    #[serde(default)]
    pub max_concurrent_requests: Option<u32>,
    /// Maximum requests waiting behind active work.
    #[serde(default)]
    pub max_queue_depth: Option<u32>,
    /// Whole-request deadline used when a caller supplies no shorter deadline.
    #[serde(default)]
    pub request_timeout_secs: Option<u64>,
}

/// Runtime state and capabilities for one fused rollout engine.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutExecutorInfo {
    /// Stable executor name.
    pub name: String,
    /// Backend kind.
    pub backend: String,
    /// Local backend endpoint.
    pub endpoint: String,
    /// Confined adapter root.
    pub adapter_root: String,
    /// Private device-adapter sidecar socket, when enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_adapter_socket: Option<String>,
    /// Optional isolated-worker fallback pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_pool: Option<String>,
    /// Maximum concurrent backend requests.
    pub max_concurrent_requests: u32,
    /// Maximum queued requests.
    pub max_queue_depth: u32,
    /// Default whole-request deadline.
    pub request_timeout_secs: u64,
    /// Requests currently executing.
    pub active_requests: u32,
    /// Requests currently waiting for an execution permit.
    pub queued_requests: u32,
    /// Whether the executor accepts new publication and generation work.
    pub accepting: bool,
    /// Published policy versions currently routable.
    pub policies: Vec<RolloutPolicyInfo>,
    /// Backend capabilities understood by the stable API.
    pub capabilities: Vec<String>,
}

/// Request to publish one immutable LoRA policy version.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublishRolloutPolicyRequest {
    /// Logical policy or experiment identifier.
    pub policy: String,
    /// Immutable version identifier, normally the optimizer step or content digest.
    pub version: String,
    /// Relative directory beneath the executor's configured adapter root.
    pub adapter_path: String,
    /// Expected deterministic SHA-256 of the adapter directory contents.
    pub adapter_sha256: String,
    /// Keep the previous current version routable instead of retiring it.
    #[serde(default)]
    pub retain_previous: bool,
}

/// Request to publish one immutable LoRA policy directly from clone GPU memory.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublishDeviceRolloutPolicyRequest {
    /// Logical policy or experiment identifier.
    pub policy: String,
    /// Immutable version identifier, normally the optimizer step.
    pub version: String,
    /// Hex-encoded one-use token returned by the clone's CUDA publisher.
    pub tensor_bundle_token: String,
    /// Keep the previous current version routable instead of retiring it.
    #[serde(default)]
    pub retain_previous: bool,
}

/// Published policy metadata.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutPolicyInfo {
    /// Logical policy identifier.
    pub policy: String,
    /// Immutable version identifier.
    pub version: String,
    /// Verified file-adapter digest or controller-derived device-publication digest.
    pub adapter_sha256: String,
    /// Opaque backend model name assigned by smolvm.
    pub backend_model: String,
    /// Policy transport: `filesystem` or `device`.
    pub source: String,
    /// Whether this is the default version for the policy.
    pub current: bool,
    /// Requests using this version right now.
    pub active_requests: u32,
    /// Whether this version is draining before backend unload.
    pub retiring: bool,
}

/// One text or pre-tokenized prompt.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutPrompt {
    /// Text prompt. Exactly one of `text` and `tokenIds` must be set.
    #[serde(default)]
    pub text: Option<String>,
    /// Tokenized prompt. Exactly one of `text` and `tokenIds` must be set.
    #[serde(default)]
    pub token_ids: Option<Vec<u32>>,
}

/// Sampling parameters shared by every prompt in one request.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutSamplingParams {
    /// Completions per prompt.
    #[serde(default = "default_one")]
    pub n: u32,
    /// Maximum generated tokens per completion.
    pub max_tokens: u32,
    /// Sampling temperature.
    #[serde(default)]
    pub temperature: Option<f64>,
    /// Nucleus sampling probability.
    #[serde(default)]
    pub top_p: Option<f64>,
    /// Top-k sampling cutoff.
    #[serde(default)]
    pub top_k: Option<i64>,
    /// Minimum-token probability cutoff.
    #[serde(default)]
    pub min_p: Option<f64>,
    /// Repetition penalty.
    #[serde(default)]
    pub repetition_penalty: Option<f64>,
    /// Deterministic seed.
    #[serde(default)]
    pub seed: Option<i64>,
    /// Number of per-token alternatives to return.
    #[serde(default)]
    pub logprobs: Option<u32>,
    /// Return prompt-token log probabilities.
    #[serde(default)]
    pub prompt_logprobs: Option<u32>,
}

fn default_one() -> u32 {
    1
}

/// One idempotent fused generation request.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutGenerateRequest {
    /// Retry key unique within the executor.
    pub idempotency_key: String,
    /// Logical policy identifier.
    pub policy: String,
    /// Explicit immutable version, or the current version when omitted.
    #[serde(default)]
    pub version: Option<String>,
    /// Text or tokenized prompts. A request cannot mix the two representations.
    pub prompts: Vec<RolloutPrompt>,
    /// Generation parameters.
    pub sampling: RolloutSamplingParams,
    /// Optional shorter whole-request deadline.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// Optional distributed admission cohort for independently submitted jobs.
    #[serde(default)]
    pub cohort: Option<RolloutCohort>,
}

/// A distributed batch boundary shared by independent rollout workers.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutCohort {
    /// Unique identifier for one logical rollout round.
    pub id: String,
    /// Exact number of independent jobs required before any member executes.
    pub size: u32,
}

/// A cohort of independent policy requests submitted together for backend fusion.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutBatchRequest {
    /// Independent generation jobs. Results retain this order.
    pub jobs: Vec<RolloutGenerateRequest>,
}

/// One completion returned by the backend.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutCompletion {
    /// Backend choice index.
    pub index: u32,
    /// Decoded completion text.
    pub text: String,
    /// Exact generated token IDs when supplied by the backend.
    #[serde(default, alias = "token_ids", skip_serializing_if = "Option::is_none")]
    pub token_ids: Option<Vec<u32>>,
    /// Exact prompt token IDs when supplied by the backend.
    #[serde(
        default,
        alias = "prompt_token_ids",
        skip_serializing_if = "Option::is_none"
    )]
    pub prompt_token_ids: Option<Vec<u32>>,
    /// Backend log-probability payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub logprobs: Option<serde_json::Value>,
    /// Backend finish reason.
    #[serde(
        default,
        alias = "finish_reason",
        skip_serializing_if = "Option::is_none"
    )]
    pub finish_reason: Option<String>,
    /// Token or string that stopped generation.
    #[serde(
        default,
        alias = "stop_reason",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<Object>)]
    pub stop_reason: Option<serde_json::Value>,
}

/// Token accounting returned by a rollout backend.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutUsage {
    /// Prompt tokens consumed.
    #[serde(default, alias = "prompt_tokens")]
    pub prompt_tokens: u64,
    /// Completion tokens produced.
    #[serde(default, alias = "completion_tokens")]
    pub completion_tokens: u64,
    /// Total tokens processed.
    #[serde(default, alias = "total_tokens")]
    pub total_tokens: u64,
}

/// Stable fused generation response.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutGenerateResponse {
    /// Executor that handled the request.
    pub executor: String,
    /// Routed logical policy.
    pub policy: String,
    /// Routed immutable version.
    pub version: String,
    /// Backend request identifier.
    pub backend_request_id: String,
    /// Generated choices.
    pub choices: Vec<RolloutCompletion>,
    /// Backend token usage.
    pub usage: RolloutUsage,
    /// True when an idempotent retry reused an earlier result.
    pub cached: bool,
}

/// One ordered item in a cohort response.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutBatchItemResponse {
    /// Retry key from the submitted job.
    pub idempotency_key: String,
    /// Successful result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RolloutGenerateResponse>,
    /// Stable error category for a failed item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Ordered results for one submitted cohort.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutBatchResponse {
    /// Per-job results in submission order.
    pub jobs: Vec<RolloutBatchItemResponse>,
}

#[derive(Debug, Clone)]
pub(crate) enum RolloutError {
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    Unavailable(String),
    Timeout(String),
    Backend(String),
}

impl RolloutError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::Unavailable(_) => "UNAVAILABLE",
            Self::Timeout(_) => "TIMEOUT",
            Self::Backend(_) => "BACKEND_ERROR",
        }
    }

    pub(crate) fn message(&self) -> &str {
        match self {
            Self::BadRequest(v)
            | Self::NotFound(v)
            | Self::Conflict(v)
            | Self::Unavailable(v)
            | Self::Timeout(v)
            | Self::Backend(v) => v,
        }
    }
}

impl From<RolloutError> for crate::api::error::ApiError {
    fn from(value: RolloutError) -> Self {
        match value {
            RolloutError::BadRequest(v) => Self::BadRequest(v),
            RolloutError::NotFound(v) => Self::NotFound(v),
            RolloutError::Conflict(v) => Self::Conflict(v),
            RolloutError::Unavailable(v) => Self::Unavailable(v),
            RolloutError::Timeout(_) => Self::Timeout,
            RolloutError::Backend(v) => Self::Unavailable(v),
        }
    }
}

#[derive(Clone)]
struct CachedError {
    value: RolloutError,
}

struct IdempotencyEntry {
    digest: [u8; 32],
    created: Instant,
    result: OnceCell<Result<Arc<RolloutGenerateResponse>, CachedError>>,
}

struct PolicyEntry {
    policy: String,
    version: String,
    adapter_sha256: String,
    backend_model: String,
    source: AdapterSource,
    #[cfg(target_os = "linux")]
    device_token_fingerprint: Option<[u8; 32]>,
    active: AtomicUsize,
    retiring: AtomicBool,
    drained: Notify,
    retirement: Mutex<()>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdapterSource {
    Filesystem,
    #[cfg(target_os = "linux")]
    Device,
}

impl AdapterSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            #[cfg(target_os = "linux")]
            Self::Device => "device",
        }
    }
}

struct PolicyGuard {
    policy: Arc<PolicyEntry>,
}

const COHORT_WAITING: usize = 0;
const COHORT_READY: usize = 1;
const COHORT_FAILED: usize = 2;

struct CohortEntry {
    id: String,
    expected: u32,
    members: SyncMutex<HashSet<String>>,
    state: AtomicUsize,
    changed: Notify,
}

#[derive(Default)]
struct CohortAdmission {
    entries: SyncMutex<HashMap<String, Arc<CohortEntry>>>,
}

impl CohortAdmission {
    fn join(
        self: &Arc<Self>,
        cohort: &RolloutCohort,
        member: &str,
    ) -> Result<CohortTicket, RolloutError> {
        let mut entries = self.entries.lock();
        let entry = entries
            .entry(cohort.id.clone())
            .or_insert_with(|| {
                Arc::new(CohortEntry {
                    id: cohort.id.clone(),
                    expected: cohort.size,
                    members: SyncMutex::new(HashSet::new()),
                    state: AtomicUsize::new(COHORT_WAITING),
                    changed: Notify::new(),
                })
            })
            .clone();
        if entry.expected != cohort.size {
            return Err(RolloutError::Conflict(format!(
                "rollout cohort '{}' expected {} jobs, not {}",
                cohort.id, entry.expected, cohort.size
            )));
        }
        let ready = {
            let mut members = entry.members.lock();
            if !members.insert(member.to_string()) {
                return Err(RolloutError::Conflict(format!(
                    "rollout cohort '{}' already contains member '{}'",
                    cohort.id, member
                )));
            }
            members.len() == entry.expected as usize
        };
        if ready
            && entry
                .state
                .compare_exchange(
                    COHORT_WAITING,
                    COHORT_READY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            entries.remove(&cohort.id);
            entry.changed.notify_waiters();
            metrics::counter!("smolvm_rollout_cohorts_total", "status" => "ready").increment(1);
            metrics::histogram!("smolvm_rollout_cohort_size").record(cohort.size as f64);
        }
        Ok(CohortTicket {
            admission: self.clone(),
            entry,
            completed: false,
        })
    }

    fn cancel_all(&self) {
        let entries = {
            let mut current = self.entries.lock();
            std::mem::take(&mut *current)
        };
        for entry in entries.into_values() {
            if entry
                .state
                .compare_exchange(
                    COHORT_WAITING,
                    COHORT_FAILED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                entry.changed.notify_waiters();
                metrics::counter!("smolvm_rollout_cohorts_total", "status" => "cancelled")
                    .increment(1);
            }
        }
    }
}

struct CohortTicket {
    admission: Arc<CohortAdmission>,
    entry: Arc<CohortEntry>,
    completed: bool,
}

impl CohortTicket {
    async fn wait(mut self) -> Result<(), RolloutError> {
        loop {
            let changed = self.entry.changed.notified();
            match self.entry.state.load(Ordering::Acquire) {
                COHORT_READY => {
                    self.completed = true;
                    return Ok(());
                }
                COHORT_FAILED => {
                    self.completed = true;
                    return Err(RolloutError::Unavailable(format!(
                        "rollout cohort '{}' lost a member before admission",
                        self.entry.id
                    )));
                }
                _ => changed.await,
            }
        }
    }
}

impl Drop for CohortTicket {
    fn drop(&mut self) {
        if self.completed
            || self
                .entry
                .state
                .compare_exchange(
                    COHORT_WAITING,
                    COHORT_FAILED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return;
        }
        let mut entries = self.admission.entries.lock();
        if entries
            .get(&self.entry.id)
            .is_some_and(|current| Arc::ptr_eq(current, &self.entry))
        {
            entries.remove(&self.entry.id);
        }
        drop(entries);
        self.entry.changed.notify_waiters();
        metrics::counter!("smolvm_rollout_cohorts_total", "status" => "failed").increment(1);
    }
}

impl Drop for PolicyGuard {
    fn drop(&mut self) {
        if self.policy.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.policy.drained.notify_waiters();
        }
    }
}

struct ExecutorConfig {
    name: String,
    endpoint: String,
    adapter_root: PathBuf,
    #[cfg(target_os = "linux")]
    device_handoff: Option<DeviceHandoffClient>,
    fallback_pool: Option<String>,
    max_concurrent: u32,
    max_queue_depth: u32,
    request_timeout: Duration,
}

struct PolicyState {
    versions: HashMap<(String, String), Arc<PolicyEntry>>,
    current: HashMap<String, String>,
}

pub(crate) struct RolloutExecutor {
    config: ExecutorConfig,
    http: Client,
    permits: Semaphore,
    queued: AtomicU32,
    active: AtomicU32,
    accepting: AtomicBool,
    policy_state: RwLock<PolicyState>,
    publish_lock: Mutex<()>,
    cohort_admission: Arc<CohortAdmission>,
    idempotency: Mutex<HashMap<String, Arc<IdempotencyEntry>>>,
}

/// In-memory executor registry. The framework client re-registers declaratively
/// after a node restart, while immutable policy state remains in its adapter root.
#[derive(Default)]
pub struct RolloutRegistry {
    executors: RwLock<HashMap<String, Arc<RolloutExecutor>>>,
}

impl RolloutRegistry {
    /// Register an executor after validating its local trust boundary and health.
    pub(crate) async fn create(
        &self,
        request: CreateRolloutExecutorRequest,
    ) -> Result<RolloutExecutorInfo, RolloutError> {
        let executor = Arc::new(RolloutExecutor::new(request)?);
        executor.health().await?;
        let mut executors = self.executors.write().await;
        if executors.contains_key(&executor.config.name) {
            return Err(RolloutError::Conflict(format!(
                "rollout executor '{}' already exists",
                executor.config.name
            )));
        }
        let info = executor.info().await;
        executors.insert(executor.config.name.clone(), executor);
        Ok(info)
    }

    /// List registered executors.
    pub async fn list(&self) -> Vec<RolloutExecutorInfo> {
        let values: Vec<_> = self.executors.read().await.values().cloned().collect();
        let mut infos = Vec::with_capacity(values.len());
        for executor in values {
            infos.push(executor.info().await);
        }
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        infos
    }

    /// Resolve one registered executor.
    pub(crate) async fn get(&self, name: &str) -> Result<Arc<RolloutExecutor>, RolloutError> {
        self.executors
            .read()
            .await
            .get(name)
            .cloned()
            .ok_or_else(|| RolloutError::NotFound(format!("rollout executor '{name}' not found")))
    }

    /// Remove an executor and retire its loaded adapters.
    pub(crate) async fn delete(&self, name: &str) -> Result<(), RolloutError> {
        let executor = self
            .executors
            .read()
            .await
            .get(name)
            .cloned()
            .ok_or_else(|| {
                RolloutError::NotFound(format!("rollout executor '{name}' not found"))
            })?;
        executor.accepting.store(false, Ordering::Release);
        executor.cohort_admission.cancel_all();
        executor.shutdown().await?;
        let mut executors = self.executors.write().await;
        if executors
            .get(name)
            .is_some_and(|current| Arc::ptr_eq(current, &executor))
        {
            executors.remove(name);
        }
        Ok(())
    }
}

impl RolloutExecutor {
    fn new(request: CreateRolloutExecutorRequest) -> Result<Self, RolloutError> {
        validate_name("executor", &request.name)?;
        if request.backend != "vllm" {
            return Err(RolloutError::BadRequest(format!(
                "unsupported rollout backend '{}'; expected 'vllm'",
                request.backend
            )));
        }
        let endpoint = validate_loopback_endpoint(&request.endpoint)?;
        let root = Path::new(&request.adapter_root);
        if !root.is_absolute() {
            return Err(RolloutError::BadRequest(
                "adapterRoot must be an absolute directory".into(),
            ));
        }
        let adapter_root = root.canonicalize().map_err(|error| {
            RolloutError::BadRequest(format!("canonicalize adapterRoot: {error}"))
        })?;
        if !adapter_root.is_dir() {
            return Err(RolloutError::BadRequest(
                "adapterRoot must resolve to a directory".into(),
            ));
        }
        let max_concurrent = request
            .max_concurrent_requests
            .unwrap_or(DEFAULT_MAX_CONCURRENT);
        if !(1..=MAX_CONCURRENT).contains(&max_concurrent) {
            return Err(RolloutError::BadRequest(format!(
                "maxConcurrentRequests must be between 1 and {MAX_CONCURRENT}"
            )));
        }
        let max_queue_depth = request.max_queue_depth.unwrap_or(DEFAULT_MAX_QUEUE_DEPTH);
        if max_queue_depth > MAX_QUEUE_DEPTH {
            return Err(RolloutError::BadRequest(format!(
                "maxQueueDepth must be at most {MAX_QUEUE_DEPTH}"
            )));
        }
        let timeout_secs = request
            .request_timeout_secs
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS);
        if !(1..=MAX_REQUEST_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(RolloutError::BadRequest(format!(
                "requestTimeoutSecs must be between 1 and {MAX_REQUEST_TIMEOUT_SECS}"
            )));
        }
        if let Some(pool) = &request.fallback_pool {
            validate_name("fallback pool", pool)?;
        }
        let http = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| RolloutError::Backend(format!("build rollout client: {error}")))?;
        #[cfg(target_os = "linux")]
        let device_handoff = request
            .device_adapter_socket
            .as_deref()
            .map(|path| {
                DeviceHandoffClient::new(Path::new(path), Duration::from_secs(timeout_secs))
            })
            .transpose()?;
        #[cfg(not(target_os = "linux"))]
        if request.device_adapter_socket.is_some() {
            return Err(RolloutError::BadRequest(
                "device-resident rollout handoff requires Linux".into(),
            ));
        }
        Ok(Self {
            config: ExecutorConfig {
                name: request.name,
                endpoint,
                adapter_root,
                #[cfg(target_os = "linux")]
                device_handoff,
                fallback_pool: request.fallback_pool,
                max_concurrent,
                max_queue_depth,
                request_timeout: Duration::from_secs(timeout_secs),
            },
            http,
            permits: Semaphore::new(max_concurrent as usize),
            queued: AtomicU32::new(0),
            active: AtomicU32::new(0),
            accepting: AtomicBool::new(true),
            policy_state: RwLock::new(PolicyState {
                versions: HashMap::new(),
                current: HashMap::new(),
            }),
            publish_lock: Mutex::new(()),
            cohort_admission: Arc::new(CohortAdmission::default()),
            idempotency: Mutex::new(HashMap::new()),
        })
    }

    async fn health(&self) -> Result<(), RolloutError> {
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            self.http
                .get(format!("{}/health", self.config.endpoint))
                .send(),
        )
        .await
        .map_err(|_| RolloutError::Timeout("rollout backend health check timed out".into()))?
        .map_err(|error| {
            RolloutError::Unavailable(format!("rollout backend health check failed: {error}"))
        })?;
        if !response.status().is_success() {
            return Err(RolloutError::Unavailable(format!(
                "rollout backend health check returned {}",
                response.status()
            )));
        }
        #[cfg(target_os = "linux")]
        if let Some(handoff) = &self.config.device_handoff {
            handoff.health().await?;
        }
        Ok(())
    }

    pub(crate) async fn info(&self) -> RolloutExecutorInfo {
        let state = self.policy_state.read().await;
        let mut policies: Vec<_> = state
            .versions
            .values()
            .map(|entry| RolloutPolicyInfo {
                policy: entry.policy.clone(),
                version: entry.version.clone(),
                adapter_sha256: entry.adapter_sha256.clone(),
                backend_model: entry.backend_model.clone(),
                source: entry.source.as_str().into(),
                current: state.current.get(&entry.policy) == Some(&entry.version),
                active_requests: entry.active.load(Ordering::Acquire) as u32,
                retiring: entry.retiring.load(Ordering::Acquire),
            })
            .collect();
        policies.sort_by(|a, b| (&a.policy, &a.version).cmp(&(&b.policy, &b.version)));
        let device_handoff_enabled = {
            #[cfg(target_os = "linux")]
            {
                self.config.device_handoff.is_some()
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };
        let capabilities = vec![
            "multi_lora".into(),
            "text_prompts".into(),
            "token_id_prompts".into(),
            "token_id_outputs".into(),
            "logprobs".into(),
            "continuous_batching".into(),
        ]
        .into_iter()
        .chain(device_handoff_enabled.then(|| "device_lora_handoff".into()))
        .collect();
        RolloutExecutorInfo {
            name: self.config.name.clone(),
            backend: "vllm".into(),
            endpoint: self.config.endpoint.clone(),
            adapter_root: self.config.adapter_root.display().to_string(),
            device_adapter_socket: {
                #[cfg(target_os = "linux")]
                {
                    self.config
                        .device_handoff
                        .as_ref()
                        .map(|client| client.path().display().to_string())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    None
                }
            },
            fallback_pool: self.config.fallback_pool.clone(),
            max_concurrent_requests: self.config.max_concurrent,
            max_queue_depth: self.config.max_queue_depth,
            request_timeout_secs: self.config.request_timeout.as_secs(),
            active_requests: self.active.load(Ordering::Acquire),
            queued_requests: self.queued.load(Ordering::Acquire),
            accepting: self.accepting.load(Ordering::Acquire),
            policies,
            capabilities,
        }
    }

    pub(crate) async fn publish_policy(
        self: &Arc<Self>,
        request: PublishRolloutPolicyRequest,
    ) -> Result<RolloutPolicyInfo, RolloutError> {
        validate_name("policy", &request.policy)?;
        validate_name("version", &request.version)?;
        validate_sha256(&request.adapter_sha256)?;
        let _publish = self.publish_lock.lock().await;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RolloutError::Unavailable(format!(
                "rollout executor '{}' is draining",
                self.config.name
            )));
        }
        {
            let state = self.policy_state.read().await;
            if let Some(existing) = state
                .versions
                .get(&(request.policy.clone(), request.version.clone()))
            {
                if existing.source != AdapterSource::Filesystem
                    || existing.adapter_sha256 != request.adapter_sha256
                {
                    return Err(RolloutError::Conflict(format!(
                        "policy '{}:{}' already exists with a different digest",
                        request.policy, request.version
                    )));
                }
                if existing.retiring.load(Ordering::Acquire) {
                    return Err(RolloutError::Unavailable(format!(
                        "policy '{}:{}' is retiring",
                        request.policy, request.version
                    )));
                }
                return Ok(RolloutPolicyInfo {
                    policy: existing.policy.clone(),
                    version: existing.version.clone(),
                    adapter_sha256: existing.adapter_sha256.clone(),
                    backend_model: existing.backend_model.clone(),
                    source: existing.source.as_str().into(),
                    current: state.current.get(&existing.policy) == Some(&existing.version),
                    active_requests: existing.active.load(Ordering::Acquire) as u32,
                    retiring: false,
                });
            }
            if state.versions.len() >= MAX_POLICY_VERSIONS {
                return Err(RolloutError::Unavailable(format!(
                    "executor reached its {MAX_POLICY_VERSIONS}-policy-version limit"
                )));
            }
        }
        let adapter_path = resolve_adapter_path(&self.config.adapter_root, &request.adapter_path)?;
        let expected = request.adapter_sha256.clone();
        let hash_path = adapter_path.clone();
        let actual = tokio::task::spawn_blocking(move || hash_adapter_dir(&hash_path))
            .await
            .map_err(|error| {
                RolloutError::Backend(format!("adapter hash task failed: {error}"))
            })??;
        if actual != expected {
            return Err(RolloutError::BadRequest(format!(
                "adapter digest mismatch: expected {expected}, computed {actual}"
            )));
        }
        let backend_model = backend_model_name(
            &self.config.name,
            &request.policy,
            &request.version,
            &request.adapter_sha256,
        );
        self.load_adapter(&backend_model, &adapter_path).await?;
        let entry = Arc::new(PolicyEntry {
            policy: request.policy.clone(),
            version: request.version.clone(),
            adapter_sha256: request.adapter_sha256,
            backend_model: backend_model.clone(),
            source: AdapterSource::Filesystem,
            #[cfg(target_os = "linux")]
            device_token_fingerprint: None,
            active: AtomicUsize::new(0),
            retiring: AtomicBool::new(false),
            drained: Notify::new(),
            retirement: Mutex::new(()),
        });
        let previous = {
            let mut state = self.policy_state.write().await;
            let previous_version = state
                .current
                .insert(request.policy.clone(), request.version.clone());
            state.versions.insert(
                (request.policy.clone(), request.version.clone()),
                entry.clone(),
            );
            if request.retain_previous {
                None
            } else {
                previous_version.and_then(|version| {
                    if version == request.version {
                        None
                    } else {
                        state
                            .versions
                            .get(&(request.policy.clone(), version))
                            .cloned()
                            .inspect(|entry| entry.retiring.store(true, Ordering::Release))
                    }
                })
            }
        };
        if let Some(previous) = previous {
            let executor = self.clone();
            tokio::spawn(async move {
                if let Err(error) = executor.retire_tracked_entry(previous).await {
                    tracing::warn!(
                        executor = %executor.config.name,
                        error = %error.message(),
                        "failed to retire previous rollout policy version"
                    );
                }
            });
        }
        metrics::counter!("smolvm_rollout_policy_publications_total", "executor" => self.config.name.clone(), "source" => "filesystem").increment(1);
        Ok(RolloutPolicyInfo {
            policy: entry.policy.clone(),
            version: entry.version.clone(),
            adapter_sha256: entry.adapter_sha256.clone(),
            backend_model,
            source: AdapterSource::Filesystem.as_str().into(),
            current: true,
            active_requests: 0,
            retiring: false,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn publish_device_policy(
        self: &Arc<Self>,
        request: PublishDeviceRolloutPolicyRequest,
    ) -> Result<RolloutPolicyInfo, RolloutError> {
        validate_name("policy", &request.policy)?;
        validate_name("version", &request.version)?;
        let token = hex::decode(&request.tensor_bundle_token).map_err(|_| {
            RolloutError::BadRequest("tensorBundleToken must be hexadecimal".into())
        })?;
        if token.len() != 32 {
            return Err(RolloutError::BadRequest(
                "tensorBundleToken must contain exactly 32 bytes".into(),
            ));
        }
        let token_fingerprint: [u8; 32] = Sha256::digest(&token).into();
        let _publish = self.publish_lock.lock().await;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RolloutError::Unavailable(format!(
                "rollout executor '{}' is draining",
                self.config.name
            )));
        }
        {
            let state = self.policy_state.read().await;
            if let Some(existing) = state
                .versions
                .get(&(request.policy.clone(), request.version.clone()))
            {
                if existing.source != AdapterSource::Device
                    || existing.device_token_fingerprint != Some(token_fingerprint)
                {
                    return Err(RolloutError::Conflict(format!(
                        "policy '{}:{}' already exists with a different device publication",
                        request.policy, request.version
                    )));
                }
                if existing.retiring.load(Ordering::Acquire) {
                    return Err(RolloutError::Unavailable(format!(
                        "policy '{}:{}' is retiring",
                        request.policy, request.version
                    )));
                }
                return Ok(RolloutPolicyInfo {
                    policy: existing.policy.clone(),
                    version: existing.version.clone(),
                    adapter_sha256: existing.adapter_sha256.clone(),
                    backend_model: existing.backend_model.clone(),
                    source: existing.source.as_str().into(),
                    current: state.current.get(&existing.policy) == Some(&existing.version),
                    active_requests: existing.active.load(Ordering::Acquire) as u32,
                    retiring: false,
                });
            }
            if state.versions.len() >= MAX_POLICY_VERSIONS {
                return Err(RolloutError::Unavailable(format!(
                    "executor reached its {MAX_POLICY_VERSIONS}-policy-version limit"
                )));
            }
        }
        let handoff = self.config.device_handoff.as_ref().ok_or_else(|| {
            RolloutError::BadRequest(format!(
                "rollout executor '{}' has no deviceAdapterSocket",
                self.config.name
            ))
        })?;
        let redeem_token = token.clone();
        let bundle = tokio::task::spawn_blocking(move || {
            crate::cuda_daemon::redeem_tensor_bundle(&redeem_token)
        })
        .await
        .map_err(|error| RolloutError::Backend(format!("tensor redemption task failed: {error}")))?
        .map_err(|error| {
            RolloutError::Unavailable(format!("redeem device tensor bundle: {error}"))
        })?;
        let mut digest = Sha256::new();
        digest.update(b"smolvm-device-publication-v1\0");
        digest.update(&token);
        digest.update(&bundle.metadata);
        let publication_sha256 = hex::encode(digest.finalize());
        let backend_model = backend_model_name(
            &self.config.name,
            &request.policy,
            &request.version,
            &publication_sha256,
        );
        if let Err(error) = handoff.load(&backend_model, bundle).await {
            if let Err(cleanup) = handoff.unload(&backend_model).await {
                let handoff = handoff.clone();
                let executor = self.config.name.clone();
                let cleanup_model = backend_model.clone();
                tokio::spawn(async move {
                    let mut last = cleanup;
                    for attempt in 1..=3 {
                        tokio::time::sleep(Duration::from_secs(attempt)).await;
                        match handoff.unload(&cleanup_model).await {
                            Ok(()) => return,
                            Err(error) => last = error,
                        }
                    }
                    tracing::warn!(
                        %executor,
                        model = %cleanup_model,
                        error = %last.message(),
                        "failed to clean up an uncertain device-adapter load"
                    );
                });
            }
            return Err(error);
        }
        let entry = Arc::new(PolicyEntry {
            policy: request.policy.clone(),
            version: request.version.clone(),
            adapter_sha256: publication_sha256,
            backend_model: backend_model.clone(),
            source: AdapterSource::Device,
            device_token_fingerprint: Some(token_fingerprint),
            active: AtomicUsize::new(0),
            retiring: AtomicBool::new(false),
            drained: Notify::new(),
            retirement: Mutex::new(()),
        });
        let previous = {
            let mut state = self.policy_state.write().await;
            let previous_version = state
                .current
                .insert(request.policy.clone(), request.version.clone());
            state.versions.insert(
                (request.policy.clone(), request.version.clone()),
                entry.clone(),
            );
            if request.retain_previous {
                None
            } else {
                previous_version.and_then(|version| {
                    if version == request.version {
                        None
                    } else {
                        state
                            .versions
                            .get(&(request.policy.clone(), version))
                            .cloned()
                            .inspect(|entry| entry.retiring.store(true, Ordering::Release))
                    }
                })
            }
        };
        if let Some(previous) = previous {
            let executor = self.clone();
            tokio::spawn(async move {
                if let Err(error) = executor.retire_tracked_entry(previous).await {
                    tracing::warn!(
                        executor = %executor.config.name,
                        error = %error.message(),
                        "failed to retire previous rollout policy version"
                    );
                }
            });
        }
        metrics::counter!("smolvm_rollout_policy_publications_total", "executor" => self.config.name.clone(), "source" => "device").increment(1);
        Ok(RolloutPolicyInfo {
            policy: entry.policy.clone(),
            version: entry.version.clone(),
            adapter_sha256: entry.adapter_sha256.clone(),
            backend_model,
            source: AdapterSource::Device.as_str().into(),
            current: true,
            active_requests: 0,
            retiring: false,
        })
    }

    pub(crate) async fn retire_policy(
        &self,
        policy: &str,
        version: &str,
    ) -> Result<(), RolloutError> {
        validate_name("policy", policy)?;
        validate_name("version", version)?;
        let entry = {
            let mut state = self.policy_state.write().await;
            let key = (policy.to_string(), version.to_string());
            let entry = state.versions.get(&key).cloned().ok_or_else(|| {
                RolloutError::NotFound(format!("policy '{policy}:{version}' not found"))
            })?;
            entry.retiring.store(true, Ordering::Release);
            if state
                .current
                .get(policy)
                .is_some_and(|value| value == version)
            {
                state.current.remove(policy);
            }
            entry
        };
        self.retire_tracked_entry(entry).await
    }

    async fn retire_tracked_entry(&self, entry: Arc<PolicyEntry>) -> Result<(), RolloutError> {
        let _retirement = entry.retirement.lock().await;
        {
            let state = self.policy_state.read().await;
            let key = (entry.policy.clone(), entry.version.clone());
            if !state
                .versions
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                return Ok(());
            }
        }
        loop {
            let notified = entry.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if entry.active.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
        match entry.source {
            AdapterSource::Filesystem => self.unload_adapter(&entry.backend_model).await?,
            #[cfg(target_os = "linux")]
            AdapterSource::Device => {
                self.config
                    .device_handoff
                    .as_ref()
                    .ok_or_else(|| {
                        RolloutError::Unavailable(
                            "device adapter sidecar is no longer configured".into(),
                        )
                    })?
                    .unload(&entry.backend_model)
                    .await?;
            }
        }
        let mut state = self.policy_state.write().await;
        let key = (entry.policy.clone(), entry.version.clone());
        if state
            .versions
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &entry))
        {
            state.versions.remove(&key);
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), RolloutError> {
        // Wait for a publication already in flight, then prevent any later
        // publication from inserting an adapter after this snapshot.
        let _publish = self.publish_lock.lock().await;
        let entries = {
            let mut state = self.policy_state.write().await;
            state.current.clear();
            state
                .versions
                .values()
                .inspect(|entry| entry.retiring.store(true, Ordering::Release))
                .cloned()
                .collect::<Vec<_>>()
        };
        drop(_publish);
        let mut first = None;
        for entry in entries {
            if let Err(error) = self.retire_tracked_entry(entry).await {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }

    async fn load_adapter(&self, model: &str, path: &Path) -> Result<(), RolloutError> {
        let response = self
            .http
            .post(format!("{}/v1/load_lora_adapter", self.config.endpoint))
            .json(&serde_json::json!({
                "lora_name": model,
                "lora_path": path,
            }))
            .timeout(self.config.request_timeout)
            .send()
            .await
            .map_err(|error| backend_send_error("load adapter", error))?;
        let status = response.status();
        let bytes = read_body_capped(response, 1024 * 1024).await?;
        if status.is_success() || self.backend_has_model(model).await? {
            Ok(())
        } else {
            Err(RolloutError::Backend(format!(
                "rollout backend load adapter returned {status}: {}",
                body_excerpt(&bytes)
            )))
        }
    }

    async fn unload_adapter(&self, model: &str) -> Result<(), RolloutError> {
        let response = self
            .http
            .post(format!("{}/v1/unload_lora_adapter", self.config.endpoint))
            .json(&serde_json::json!({"lora_name": model}))
            .timeout(self.config.request_timeout)
            .send()
            .await
            .map_err(|error| backend_send_error("unload adapter", error))?;
        let status = response.status();
        let bytes = read_body_capped(response, 1024 * 1024).await?;
        if status.is_success() || !self.backend_has_model(model).await? {
            Ok(())
        } else {
            Err(RolloutError::Backend(format!(
                "rollout backend unload adapter returned {status}: {}",
                body_excerpt(&bytes)
            )))
        }
    }

    async fn backend_has_model(&self, model: &str) -> Result<bool, RolloutError> {
        let response = self
            .http
            .get(format!("{}/v1/models", self.config.endpoint))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| backend_send_error("list models", error))?;
        let status = response.status();
        let bytes = read_body_capped(response, 4 * 1024 * 1024).await?;
        if !status.is_success() {
            return Err(RolloutError::Backend(format!(
                "rollout backend list models returned {status}: {}",
                body_excerpt(&bytes)
            )));
        }
        #[derive(Deserialize)]
        struct Models {
            data: Vec<Model>,
        }
        #[derive(Deserialize)]
        struct Model {
            id: String,
        }
        let models: Models = serde_json::from_slice(&bytes).map_err(|error| {
            RolloutError::Backend(format!("decode rollout backend models: {error}"))
        })?;
        Ok(models.data.iter().any(|candidate| candidate.id == model))
    }

    pub(crate) async fn generate(
        self: &Arc<Self>,
        request: RolloutGenerateRequest,
    ) -> Result<RolloutGenerateResponse, RolloutError> {
        validate_generate_request(&request)?;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(RolloutError::Unavailable(format!(
                "rollout executor '{}' is draining",
                self.config.name
            )));
        }
        let digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&request)
                .map_err(|error| RolloutError::BadRequest(error.to_string()))?,
        )
        .into();
        let (entry, created) = {
            let mut cache = self.idempotency.lock().await;
            let now = Instant::now();
            if cache.len() >= MAX_IDEMPOTENCY_ENTRIES {
                cache.retain(|_, item| now.duration_since(item.created) < IDEMPOTENCY_TTL);
                if cache.len() >= MAX_IDEMPOTENCY_ENTRIES {
                    let completed_oldest = cache
                        .iter()
                        .filter(|(_, item)| item.result.get().is_some())
                        .min_by_key(|(_, item)| item.created)
                        .map(|(key, _)| key.clone());
                    if let Some(key) = completed_oldest {
                        cache.remove(&key);
                    }
                }
                if cache.len() >= MAX_IDEMPOTENCY_ENTRIES {
                    return Err(RolloutError::Unavailable(
                        "rollout idempotency cache is temporarily full".into(),
                    ));
                }
            }
            if let Some(existing) = cache.get(&request.idempotency_key) {
                if existing.digest != digest {
                    return Err(RolloutError::Conflict(format!(
                        "idempotency key '{}' was reused with a different request",
                        request.idempotency_key
                    )));
                }
                (existing.clone(), false)
            } else {
                let entry = Arc::new(IdempotencyEntry {
                    digest,
                    created: now,
                    result: OnceCell::new(),
                });
                cache.insert(request.idempotency_key.clone(), entry.clone());
                (entry, true)
            }
        };
        let executor = self.clone();
        let request_for_run = request.clone();
        let result = entry
            .result
            .get_or_init(|| async move {
                executor
                    .execute_generate(request_for_run)
                    .await
                    .map(Arc::new)
                    .map_err(|value| CachedError { value })
            })
            .await;
        match result {
            Ok(response) => {
                let mut response = response.as_ref().clone();
                response.cached = !created;
                Ok(response)
            }
            Err(error) => {
                let mut cache = self.idempotency.lock().await;
                if cache
                    .get(&request.idempotency_key)
                    .is_some_and(|current| Arc::ptr_eq(current, &entry))
                {
                    cache.remove(&request.idempotency_key);
                }
                Err(error.value.clone())
            }
        }
    }

    async fn execute_generate(
        self: &Arc<Self>,
        request: RolloutGenerateRequest,
    ) -> Result<RolloutGenerateResponse, RolloutError> {
        let deadline = request
            .deadline_ms
            .map(Duration::from_millis)
            .unwrap_or(self.config.request_timeout)
            .min(self.config.request_timeout);
        tokio::time::timeout(deadline, self.execute_generate_inner(request))
            .await
            .map_err(|_| RolloutError::Timeout("rollout request deadline exceeded".into()))?
    }

    async fn execute_generate_inner(
        self: &Arc<Self>,
        request: RolloutGenerateRequest,
    ) -> Result<RolloutGenerateResponse, RolloutError> {
        let policy = self
            .acquire_policy(&request.policy, request.version.as_deref())
            .await?;
        let _policy_guard = PolicyGuard {
            policy: policy.clone(),
        };
        if let Some(cohort) = &request.cohort {
            self.cohort_admission
                .join(cohort, &request.idempotency_key)?
                .wait()
                .await?;
        }
        let _permit = self.acquire_queue_permit().await?;
        let body = completion_body(&request, &policy.backend_model)?;
        let started = Instant::now();
        let response = self
            .http
            .post(format!("{}/v1/completions", self.config.endpoint))
            .json(&body)
            .send()
            .await
            .map_err(|error| backend_send_error("generate", error))?;
        let status = response.status();
        let bytes = read_body_capped(response, MAX_BACKEND_BODY_BYTES).await?;
        if !status.is_success() {
            return Err(RolloutError::Backend(format!(
                "rollout backend generate returned {status}: {}",
                body_excerpt(&bytes)
            )));
        }
        let backend: BackendCompletionResponse =
            serde_json::from_slice(&bytes).map_err(|error| {
                RolloutError::Backend(format!("decode rollout backend response: {error}"))
            })?;
        let response = RolloutGenerateResponse {
            executor: self.config.name.clone(),
            policy: policy.policy.clone(),
            version: policy.version.clone(),
            backend_request_id: backend.id,
            choices: backend.choices,
            usage: backend.usage,
            cached: false,
        };
        let elapsed = started.elapsed().as_secs_f64();
        metrics::counter!("smolvm_rollout_requests_total", "executor" => self.config.name.clone(), "status" => "ok").increment(1);
        metrics::histogram!("smolvm_rollout_request_seconds", "executor" => self.config.name.clone()).record(elapsed);
        metrics::counter!("smolvm_rollout_tokens_total", "executor" => self.config.name.clone())
            .increment(response.usage.completion_tokens);
        Ok(response)
    }

    async fn acquire_policy(
        &self,
        policy: &str,
        version: Option<&str>,
    ) -> Result<Arc<PolicyEntry>, RolloutError> {
        let state = self.policy_state.read().await;
        let version = match version {
            Some(value) => value.to_string(),
            None => state.current.get(policy).cloned().ok_or_else(|| {
                RolloutError::NotFound(format!("policy '{policy}' has no current version"))
            })?,
        };
        let entry = state
            .versions
            .get(&(policy.to_string(), version.clone()))
            .cloned()
            .ok_or_else(|| {
                RolloutError::NotFound(format!("policy '{policy}:{version}' not found"))
            })?;
        if entry.retiring.load(Ordering::Acquire) {
            return Err(RolloutError::Unavailable(format!(
                "policy '{policy}:{version}' is retiring"
            )));
        }
        entry.active.fetch_add(1, Ordering::AcqRel);
        Ok(entry)
    }

    async fn acquire_queue_permit(&self) -> Result<ActivePermit<'_>, RolloutError> {
        if let Ok(permit) = self.permits.try_acquire() {
            self.active.fetch_add(1, Ordering::AcqRel);
            return Ok(ActivePermit {
                _permit: permit,
                active: &self.active,
            });
        }
        self.queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                (queued < self.config.max_queue_depth).then_some(queued + 1)
            })
            .map_err(|_| {
                RolloutError::Unavailable(format!(
                    "rollout executor '{}' queue is full",
                    self.config.name
                ))
            })?;
        let mut queued = QueuedGuard {
            queued: &self.queued,
            armed: true,
        };
        let permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| RolloutError::Unavailable("rollout executor is closed".into()))?;
        queued.disarm();
        self.active.fetch_add(1, Ordering::AcqRel);
        Ok(ActivePermit {
            _permit: permit,
            active: &self.active,
        })
    }
}

struct QueuedGuard<'a> {
    queued: &'a AtomicU32,
    armed: bool,
}

impl QueuedGuard<'_> {
    fn disarm(&mut self) {
        if self.armed {
            self.queued.fetch_sub(1, Ordering::AcqRel);
            self.armed = false;
        }
    }
}

impl Drop for QueuedGuard<'_> {
    fn drop(&mut self) {
        self.disarm();
    }
}

struct ActivePermit<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
    active: &'a AtomicU32,
}

impl Drop for ActivePermit<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Deserialize)]
struct BackendCompletionResponse {
    id: String,
    choices: Vec<RolloutCompletion>,
    #[serde(default)]
    usage: RolloutUsage,
}

pub(crate) fn validate_name(kind: &str, value: &str) -> Result<(), RolloutError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(RolloutError::BadRequest(format!(
            "{kind} must be 1-{MAX_NAME_BYTES} ASCII letters, digits, '.', '_' or '-'"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), RolloutError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RolloutError::BadRequest(
            "adapterSha256 must be exactly 64 hexadecimal characters".into(),
        ));
    }
    Ok(())
}

fn validate_loopback_endpoint(value: &str) -> Result<String, RolloutError> {
    let address = value.strip_prefix("http://").ok_or_else(|| {
        RolloutError::BadRequest("endpoint must use http:// with a loopback IP literal".into())
    })?;
    if address.contains('/')
        || address.contains('?')
        || address.contains('#')
        || address.contains('@')
    {
        return Err(RolloutError::BadRequest(
            "endpoint must contain only a loopback socket address".into(),
        ));
    }
    let socket: SocketAddr = address.parse().map_err(|_| {
        RolloutError::BadRequest("endpoint must contain a loopback IP literal and port".into())
    })?;
    if !socket.ip().is_loopback() || socket.port() == 0 {
        return Err(RolloutError::BadRequest(
            "endpoint must target a nonzero loopback port".into(),
        ));
    }
    Ok(format!("http://{socket}"))
}

fn resolve_adapter_path(root: &Path, relative: &str) -> Result<PathBuf, RolloutError> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(RolloutError::BadRequest(
            "adapterPath must be a safe relative directory".into(),
        ));
    }
    let path = root
        .join(relative)
        .canonicalize()
        .map_err(|error| RolloutError::BadRequest(format!("canonicalize adapterPath: {error}")))?;
    if !path.is_dir() || !path.starts_with(root) {
        return Err(RolloutError::BadRequest(
            "adapterPath must resolve to a directory beneath adapterRoot".into(),
        ));
    }
    Ok(path)
}

/// Deterministically hash relative names, lengths, and bytes of regular files.
pub(crate) fn hash_adapter_dir(path: &Path) -> Result<String, RolloutError> {
    fn walk(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<(), RolloutError> {
        for item in std::fs::read_dir(current)
            .map_err(|error| RolloutError::BadRequest(format!("read adapter directory: {error}")))?
        {
            let item = item.map_err(|error| {
                RolloutError::BadRequest(format!("read adapter directory entry: {error}"))
            })?;
            let file_type = item.file_type().map_err(|error| {
                RolloutError::BadRequest(format!("read adapter file type: {error}"))
            })?;
            if file_type.is_symlink() {
                return Err(RolloutError::BadRequest(format!(
                    "adapter directory contains symlink '{}'",
                    item.path().display()
                )));
            }
            if file_type.is_dir() {
                walk(root, &item.path(), files)?;
            } else if file_type.is_file() {
                let _ = item.path().strip_prefix(root).map_err(|_| {
                    RolloutError::BadRequest("adapter file escaped adapter root".into())
                })?;
                files.push(item.path());
                if files.len() > MAX_ADAPTER_FILES {
                    return Err(RolloutError::BadRequest(format!(
                        "adapter contains more than {MAX_ADAPTER_FILES} files"
                    )));
                }
            } else {
                return Err(RolloutError::BadRequest(
                    "adapter directory contains a non-regular file".into(),
                ));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(path, path, &mut files)?;
    if files.is_empty() {
        return Err(RolloutError::BadRequest(
            "adapter directory contains no files".into(),
        ));
    }
    files.sort_by(|left, right| {
        left.strip_prefix(path)
            .unwrap_or(left)
            .cmp(right.strip_prefix(path).unwrap_or(right))
    });
    let mut total = 0u64;
    let mut digest = Sha256::new();
    for file in files {
        let relative = file.strip_prefix(path).map_err(|_| {
            RolloutError::BadRequest("adapter file escaped adapter directory".into())
        })?;
        let name = relative.to_string_lossy();
        let metadata = std::fs::metadata(&file)
            .map_err(|error| RolloutError::BadRequest(format!("stat adapter file: {error}")))?;
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| RolloutError::BadRequest("adapter byte count overflowed".into()))?;
        if total > MAX_ADAPTER_BYTES {
            return Err(RolloutError::BadRequest(format!(
                "adapter exceeds {MAX_ADAPTER_BYTES} bytes"
            )));
        }
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update(metadata.len().to_le_bytes());
        let mut input = std::fs::File::open(&file)
            .map_err(|error| RolloutError::BadRequest(format!("open adapter file: {error}")))?;
        std::io::copy(&mut input, &mut DigestWriter(&mut digest))
            .map_err(|error| RolloutError::BadRequest(format!("hash adapter file: {error}")))?;
    }
    Ok(hex::encode(digest.finalize()))
}

struct DigestWriter<'a, D: Digest>(&'a mut D);

impl<D: Digest> std::io::Write for DigestWriter<'_, D> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn backend_model_name(executor: &str, policy: &str, version: &str, digest: &str) -> String {
    let hash = Sha256::digest(format!("{executor}\0{policy}\0{version}\0{digest}"));
    format!("smolvm-{}", &hex::encode(hash)[..32])
}

fn validate_generate_request(request: &RolloutGenerateRequest) -> Result<(), RolloutError> {
    if request.idempotency_key.is_empty()
        || request.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || request.idempotency_key.chars().any(char::is_control)
    {
        return Err(RolloutError::BadRequest(format!(
            "idempotencyKey must be 1-{MAX_IDEMPOTENCY_KEY_BYTES} bytes without control characters"
        )));
    }
    validate_name("policy", &request.policy)?;
    if let Some(version) = &request.version {
        validate_name("version", version)?;
    }
    if request.prompts.is_empty() || request.prompts.len() > MAX_PROMPTS {
        return Err(RolloutError::BadRequest(format!(
            "prompts must contain between 1 and {MAX_PROMPTS} items"
        )));
    }
    let mut text_bytes = 0usize;
    let mut token_count = 0usize;
    let mut kind = None;
    for prompt in &request.prompts {
        let prompt_kind = match (&prompt.text, &prompt.token_ids) {
            (Some(text), None) if !text.is_empty() => {
                text_bytes = text_bytes.saturating_add(text.len());
                0
            }
            (None, Some(tokens)) if !tokens.is_empty() => {
                token_count = token_count.saturating_add(tokens.len());
                1
            }
            _ => {
                return Err(RolloutError::BadRequest(
                    "each prompt must set exactly one non-empty text or tokenIds value".into(),
                ))
            }
        };
        if kind
            .replace(prompt_kind)
            .is_some_and(|value| value != prompt_kind)
        {
            return Err(RolloutError::BadRequest(
                "one generation request cannot mix text and tokenIds prompts".into(),
            ));
        }
    }
    if text_bytes > MAX_PROMPT_TEXT_BYTES || token_count > MAX_PROMPT_TOKENS {
        return Err(RolloutError::BadRequest(
            "prompt payload exceeds the executor safety limit".into(),
        ));
    }
    let sampling = &request.sampling;
    if sampling.n == 0 || sampling.n > 256 {
        return Err(RolloutError::BadRequest(
            "sampling.n must be between 1 and 256".into(),
        ));
    }
    if sampling.max_tokens == 0 || sampling.max_tokens > MAX_COMPLETION_TOKENS {
        return Err(RolloutError::BadRequest(format!(
            "sampling.maxTokens must be between 1 and {MAX_COMPLETION_TOKENS}"
        )));
    }
    if sampling
        .temperature
        .is_some_and(|value| !value.is_finite() || value < 0.0)
        || sampling
            .top_p
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        || sampling
            .min_p
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        || sampling
            .repetition_penalty
            .is_some_and(|value| !value.is_finite() || value <= 0.0)
    {
        return Err(RolloutError::BadRequest(
            "sampling parameters are outside their finite valid ranges".into(),
        ));
    }
    if request.deadline_ms == Some(0) {
        return Err(RolloutError::BadRequest(
            "deadlineMs must be greater than zero".into(),
        ));
    }
    if let Some(cohort) = &request.cohort {
        validate_name("cohort.id", &cohort.id)?;
        if !(1..=MAX_COHORT_SIZE).contains(&cohort.size) {
            return Err(RolloutError::BadRequest(format!(
                "cohort.size must be between 1 and {MAX_COHORT_SIZE}"
            )));
        }
    }
    Ok(())
}

fn completion_body(
    request: &RolloutGenerateRequest,
    backend_model: &str,
) -> Result<serde_json::Value, RolloutError> {
    let prompt = if request.prompts[0].text.is_some() {
        serde_json::to_value(
            request
                .prompts
                .iter()
                .map(|prompt| prompt.text.as_deref().unwrap_or_default())
                .collect::<Vec<_>>(),
        )
    } else {
        serde_json::to_value(
            request
                .prompts
                .iter()
                .map(|prompt| prompt.token_ids.as_deref().unwrap_or_default())
                .collect::<Vec<_>>(),
        )
    }
    .map_err(|error| RolloutError::BadRequest(error.to_string()))?;
    let sampling = &request.sampling;
    let mut body = serde_json::json!({
        "model": backend_model,
        "prompt": prompt,
        "n": sampling.n,
        "max_tokens": sampling.max_tokens,
        "stream": false,
        "return_token_ids": true,
    });
    let object = body.as_object_mut().expect("completion body is an object");
    macro_rules! optional {
        ($field:ident, $wire:literal) => {
            if let Some(value) = sampling.$field {
                object.insert($wire.into(), serde_json::json!(value));
            }
        };
    }
    optional!(temperature, "temperature");
    optional!(top_p, "top_p");
    optional!(top_k, "top_k");
    optional!(min_p, "min_p");
    optional!(repetition_penalty, "repetition_penalty");
    optional!(seed, "seed");
    optional!(logprobs, "logprobs");
    optional!(prompt_logprobs, "prompt_logprobs");
    Ok(body)
}

fn backend_send_error(operation: &str, error: reqwest::Error) -> RolloutError {
    if error.is_timeout() {
        RolloutError::Timeout(format!("rollout backend {operation} timed out"))
    } else {
        RolloutError::Unavailable(format!("rollout backend {operation} failed: {error}"))
    }
}

async fn read_body_capped(
    response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, RolloutError> {
    if response
        .content_length()
        .is_some_and(|length| length > cap as u64)
    {
        return Err(RolloutError::Backend(format!(
            "rollout backend response exceeds {cap} bytes"
        )));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            RolloutError::Unavailable(format!("read rollout backend response: {error}"))
        })?;
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(RolloutError::Backend(format!(
                "rollout backend response exceeds {cap} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn body_excerpt(body: &[u8]) -> String {
    const LIMIT: usize = 1024;
    String::from_utf8_lossy(&body[..body.len().min(LIMIT)]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use std::io::Write as _;

    #[derive(Default)]
    struct MockBackend {
        loads: Mutex<Vec<serde_json::Value>>,
        unloads: Mutex<Vec<serde_json::Value>>,
        block_load: AtomicBool,
        load_started: Notify,
        release_load: Notify,
        unload_failures: AtomicUsize,
        generations: AtomicUsize,
    }

    async fn start_mock_backend() -> (SocketAddr, Arc<MockBackend>, tokio::task::JoinHandle<()>) {
        async fn health() -> StatusCode {
            StatusCode::OK
        }
        async fn load(
            State(state): State<Arc<MockBackend>>,
            Json(body): Json<serde_json::Value>,
        ) -> StatusCode {
            state.loads.lock().await.push(body);
            if state.block_load.load(Ordering::Acquire) {
                state.load_started.notify_one();
                state.release_load.notified().await;
            }
            StatusCode::OK
        }
        async fn unload(
            State(state): State<Arc<MockBackend>>,
            Json(body): Json<serde_json::Value>,
        ) -> StatusCode {
            state.unloads.lock().await.push(body);
            if state
                .unload_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            }
        }
        async fn completion(
            State(state): State<Arc<MockBackend>>,
            Json(body): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            state.generations.fetch_add(1, Ordering::AcqRel);
            assert_eq!(body["return_token_ids"], true);
            Json(serde_json::json!({
                "id": "cmpl-1",
                "choices": [{
                    "index": 0,
                    "text": "ok",
                    "token_ids": [7, 8],
                    "prompt_token_ids": [1, 2],
                    "finish_reason": "length",
                    "stop_reason": null,
                    "logprobs": {"token_logprobs": [-0.1, -0.2]}
                }],
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 2,
                    "total_tokens": 4
                }
            }))
        }

        async fn models(State(state): State<Arc<MockBackend>>) -> Json<serde_json::Value> {
            let models = state
                .loads
                .lock()
                .await
                .iter()
                .filter_map(|body| body["lora_name"].as_str())
                .map(|name| serde_json::json!({"id": name}))
                .collect::<Vec<_>>();
            Json(serde_json::json!({"data": models}))
        }

        let state = Arc::new(MockBackend::default());
        let app = Router::new()
            .route("/health", get(health))
            .route("/v1/load_lora_adapter", post(load))
            .route("/v1/unload_lora_adapter", post(unload))
            .route("/v1/completions", post(completion))
            .route("/v1/models", get(models))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (address, state, handle)
    }

    fn sample_generate(key: &str) -> RolloutGenerateRequest {
        RolloutGenerateRequest {
            idempotency_key: key.into(),
            policy: "policy".into(),
            version: None,
            prompts: vec![RolloutPrompt {
                text: None,
                token_ids: Some(vec![1, 2]),
            }],
            sampling: RolloutSamplingParams {
                n: 1,
                max_tokens: 2,
                temperature: Some(0.0),
                top_p: None,
                top_k: None,
                min_p: None,
                repetition_penalty: None,
                seed: Some(9),
                logprobs: Some(1),
                prompt_logprobs: None,
            },
            deadline_ms: Some(5_000),
            cohort: None,
        }
    }

    #[tokio::test]
    async fn distributed_cohort_releases_only_at_exact_membership() {
        let admission = Arc::new(CohortAdmission::default());
        let cohort = RolloutCohort {
            id: "round-1".into(),
            size: 2,
        };
        let first = admission.join(&cohort, "request-1").unwrap();
        let first = tokio::spawn(first.wait());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!first.is_finished());

        admission
            .join(&cohort, "request-2")
            .unwrap()
            .wait()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(50), first)
            .await
            .expect("a complete cohort must release every member")
            .unwrap()
            .unwrap();
        assert!(admission.entries.lock().is_empty());
    }

    #[tokio::test]
    async fn distributed_cohort_fails_all_members_when_one_leaves() {
        let admission = Arc::new(CohortAdmission::default());
        let cohort = RolloutCohort {
            id: "round-2".into(),
            size: 3,
        };
        let first = admission.join(&cohort, "request-1").unwrap();
        let first = tokio::spawn(first.wait());
        let second = admission.join(&cohort, "request-2").unwrap();
        drop(second);

        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(50), first)
                .await
                .expect("a failed member must wake the cohort")
                .unwrap(),
            Err(RolloutError::Unavailable(_))
        ));
        assert!(admission.entries.lock().is_empty());
    }

    #[tokio::test]
    async fn distributed_cohort_shutdown_wakes_waiters() {
        let admission = Arc::new(CohortAdmission::default());
        let cohort = RolloutCohort {
            id: "round-shutdown".into(),
            size: 2,
        };
        let waiting = admission.join(&cohort, "request-1").unwrap();
        let waiting = tokio::spawn(waiting.wait());

        admission.cancel_all();

        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(50), waiting)
                .await
                .expect("executor shutdown must wake cohort members")
                .unwrap(),
            Err(RolloutError::Unavailable(_))
        ));
        assert!(admission.entries.lock().is_empty());
    }

    #[test]
    fn distributed_cohort_rejects_inconsistent_membership() {
        let admission = Arc::new(CohortAdmission::default());
        let first = RolloutCohort {
            id: "round-3".into(),
            size: 2,
        };
        let inconsistent = RolloutCohort {
            id: first.id.clone(),
            size: 3,
        };
        let _ticket = admission.join(&first, "request-1").unwrap();
        assert!(matches!(
            admission.join(&inconsistent, "request-2"),
            Err(RolloutError::Conflict(_))
        ));
    }

    async fn create_published_executor(
        address: SocketAddr,
    ) -> (RolloutRegistry, Arc<RolloutExecutor>, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let adapter = root.path().join("adapter-v1");
        std::fs::create_dir(&adapter).unwrap();
        std::fs::write(adapter.join("adapter_config.json"), b"{}").unwrap();
        std::fs::write(adapter.join("adapter_model.safetensors"), b"weights").unwrap();
        let digest = hash_adapter_dir(&adapter).unwrap();
        let registry = RolloutRegistry::default();
        registry
            .create(CreateRolloutExecutorRequest {
                name: "fused".into(),
                backend: "vllm".into(),
                endpoint: format!("http://{address}"),
                adapter_root: root.path().display().to_string(),
                device_adapter_socket: None,
                fallback_pool: None,
                max_concurrent_requests: Some(2),
                max_queue_depth: Some(2),
                request_timeout_secs: Some(5),
            })
            .await
            .unwrap();
        let executor = registry.get("fused").await.unwrap();
        executor
            .publish_policy(PublishRolloutPolicyRequest {
                policy: "policy".into(),
                version: "step-1".into(),
                adapter_path: "adapter-v1".into(),
                adapter_sha256: digest,
                retain_previous: false,
            })
            .await
            .unwrap();
        (registry, executor, root)
    }

    #[tokio::test]
    async fn executor_holds_distributed_cohort_before_backend_generation() {
        let (address, backend, server) = start_mock_backend().await;
        let (_registry, executor, _root) = create_published_executor(address).await;
        let mut first = sample_generate("cohort-request-1");
        first.cohort = Some(RolloutCohort {
            id: "training-step-1".into(),
            size: 2,
        });
        let first_executor = executor.clone();
        let first = tokio::spawn(async move { first_executor.generate(first).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(backend.generations.load(Ordering::Acquire), 0);

        let mut second = sample_generate("cohort-request-2");
        second.cohort = Some(RolloutCohort {
            id: "training-step-1".into(),
            size: 2,
        });
        let (first, second) = tokio::join!(first, executor.generate(second));
        first.unwrap().unwrap();
        second.unwrap();
        assert_eq!(backend.generations.load(Ordering::Acquire), 2);
        server.abort();
    }

    #[tokio::test]
    async fn timed_out_cohort_can_retry_without_stale_membership() {
        let (address, backend, server) = start_mock_backend().await;
        let (_registry, executor, _root) = create_published_executor(address).await;
        let mut abandoned = sample_generate("retry-request-1");
        abandoned.deadline_ms = Some(20);
        abandoned.cohort = Some(RolloutCohort {
            id: "retry-round".into(),
            size: 2,
        });
        assert!(matches!(
            executor.generate(abandoned.clone()).await,
            Err(RolloutError::Timeout(_))
        ));
        assert!(executor.cohort_admission.entries.lock().is_empty());
        assert_eq!(backend.generations.load(Ordering::Acquire), 0);

        abandoned.deadline_ms = Some(5_000);
        let mut peer = sample_generate("retry-request-2");
        peer.cohort = abandoned.cohort.clone();
        let (first, second) = tokio::join!(executor.generate(abandoned), executor.generate(peer));
        first.unwrap();
        second.unwrap();
        assert_eq!(backend.generations.load(Ordering::Acquire), 2);
        server.abort();
    }

    #[tokio::test]
    async fn publish_generate_retry_and_retire_are_end_to_end_safe() {
        let (address, backend, server) = start_mock_backend().await;
        let root = tempfile::tempdir().unwrap();
        let adapter = root.path().join("adapter-v1");
        std::fs::create_dir(&adapter).unwrap();
        std::fs::write(adapter.join("adapter_config.json"), b"{}").unwrap();
        std::fs::write(adapter.join("adapter_model.safetensors"), b"weights").unwrap();
        let digest = hash_adapter_dir(&adapter).unwrap();

        let registry = RolloutRegistry::default();
        let created = registry
            .create(CreateRolloutExecutorRequest {
                name: "fused".into(),
                backend: "vllm".into(),
                endpoint: format!("http://{address}"),
                adapter_root: root.path().display().to_string(),
                device_adapter_socket: None,
                fallback_pool: None,
                max_concurrent_requests: Some(2),
                max_queue_depth: Some(2),
                request_timeout_secs: Some(5),
            })
            .await
            .unwrap();
        assert_eq!(created.name, "fused");
        assert_eq!(created.request_timeout_secs, 5);
        let executor = registry.get("fused").await.unwrap();
        let published = executor
            .publish_policy(PublishRolloutPolicyRequest {
                policy: "policy".into(),
                version: "step-1".into(),
                adapter_path: "adapter-v1".into(),
                adapter_sha256: digest,
                retain_previous: false,
            })
            .await
            .unwrap();
        assert!(published.current);
        assert_eq!(backend.loads.lock().await.len(), 1);

        let first = executor
            .generate(sample_generate("request-1"))
            .await
            .unwrap();
        assert!(!first.cached);
        assert_eq!(first.version, "step-1");
        assert_eq!(first.choices[0].token_ids, Some(vec![7, 8]));
        assert_eq!(first.usage.completion_tokens, 2);
        let retry = executor
            .generate(sample_generate("request-1"))
            .await
            .unwrap();
        assert!(retry.cached);
        assert_eq!(backend.generations.load(Ordering::Acquire), 1);

        let mut conflicting = sample_generate("request-1");
        conflicting.sampling.seed = Some(10);
        assert!(matches!(
            executor.generate(conflicting).await,
            Err(RolloutError::Conflict(_))
        ));

        executor.retire_policy("policy", "step-1").await.unwrap();
        assert_eq!(backend.unloads.lock().await.len(), 1);
        registry.delete("fused").await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn failed_policy_unload_stays_tracked_and_can_be_retried() {
        let (address, backend, server) = start_mock_backend().await;
        let (_registry, executor, _root) = create_published_executor(address).await;
        backend.unload_failures.store(1, Ordering::Release);

        assert!(matches!(
            executor.retire_policy("policy", "step-1").await,
            Err(RolloutError::Backend(_))
        ));
        let info = executor.info().await;
        assert_eq!(info.policies.len(), 1);
        assert!(info.policies[0].retiring);
        assert!(!info.policies[0].current);

        let mut explicit = sample_generate("request-after-retire");
        explicit.version = Some("step-1".into());
        assert!(matches!(
            executor.generate(explicit).await,
            Err(RolloutError::Unavailable(_))
        ));

        executor.retire_policy("policy", "step-1").await.unwrap();
        assert!(executor.info().await.policies.is_empty());
        assert_eq!(backend.unloads.lock().await.len(), 2);
        server.abort();
    }

    #[tokio::test]
    async fn failed_executor_shutdown_stays_registered_and_can_be_retried() {
        let (address, backend, server) = start_mock_backend().await;
        let (registry, executor, _root) = create_published_executor(address).await;
        backend.unload_failures.store(1, Ordering::Release);

        assert!(matches!(
            registry.delete("fused").await,
            Err(RolloutError::Backend(_))
        ));
        let retained = registry.get("fused").await.unwrap();
        assert!(Arc::ptr_eq(&retained, &executor));
        let info = retained.info().await;
        assert!(!info.accepting);
        assert_eq!(info.policies.len(), 1);
        assert!(info.policies[0].retiring);
        assert!(matches!(
            retained
                .generate(sample_generate("request-after-shutdown"))
                .await,
            Err(RolloutError::Unavailable(_))
        ));

        registry.delete("fused").await.unwrap();
        assert!(matches!(
            registry.get("fused").await,
            Err(RolloutError::NotFound(_))
        ));
        assert_eq!(backend.unloads.lock().await.len(), 2);
        server.abort();
    }

    #[tokio::test]
    async fn shutdown_waits_for_inflight_publication_and_unloads_it() {
        let (address, backend, server) = start_mock_backend().await;
        let root = tempfile::tempdir().unwrap();
        let adapter = root.path().join("adapter-v1");
        std::fs::create_dir(&adapter).unwrap();
        std::fs::write(adapter.join("adapter_config.json"), b"{}").unwrap();
        std::fs::write(adapter.join("adapter_model.safetensors"), b"weights").unwrap();
        let digest = hash_adapter_dir(&adapter).unwrap();
        let registry = Arc::new(RolloutRegistry::default());
        registry
            .create(CreateRolloutExecutorRequest {
                name: "fused".into(),
                backend: "vllm".into(),
                endpoint: format!("http://{address}"),
                adapter_root: root.path().display().to_string(),
                device_adapter_socket: None,
                fallback_pool: None,
                max_concurrent_requests: Some(2),
                max_queue_depth: Some(2),
                request_timeout_secs: Some(5),
            })
            .await
            .unwrap();
        let executor = registry.get("fused").await.unwrap();
        let observer = executor.clone();
        backend.block_load.store(true, Ordering::Release);

        let publication = tokio::spawn(async move {
            executor
                .publish_policy(PublishRolloutPolicyRequest {
                    policy: "policy".into(),
                    version: "step-1".into(),
                    adapter_path: "adapter-v1".into(),
                    adapter_sha256: digest,
                    retain_previous: false,
                })
                .await
        });
        backend.load_started.notified().await;
        let registry_for_delete = registry.clone();
        let deletion = tokio::spawn(async move { registry_for_delete.delete("fused").await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while observer.accepting.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        backend.release_load.notify_one();

        publication.await.unwrap().unwrap();
        deletion.await.unwrap().unwrap();
        assert_eq!(backend.unloads.lock().await.len(), 1);
        assert!(matches!(
            registry.get("fused").await,
            Err(RolloutError::NotFound(_))
        ));
        server.abort();
    }

    #[test]
    fn endpoints_are_confined_to_ip_literal_loopback() {
        assert_eq!(
            validate_loopback_endpoint("http://127.0.0.1:8000").unwrap(),
            "http://127.0.0.1:8000"
        );
        assert!(validate_loopback_endpoint("https://127.0.0.1:8000").is_err());
        assert!(validate_loopback_endpoint("http://localhost:8000").is_err());
        assert!(validate_loopback_endpoint("http://10.0.0.1:8000").is_err());
        assert!(validate_loopback_endpoint("http://127.0.0.1:8000/path").is_err());
    }

    #[test]
    fn adapter_digest_is_deterministic_and_rejects_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::File::create(root.path().join("adapter_config.json"))
            .unwrap()
            .write_all(b"config")
            .unwrap();
        std::fs::File::create(root.path().join("nested/adapter.bin"))
            .unwrap()
            .write_all(b"weights")
            .unwrap();
        let first = hash_adapter_dir(root.path()).unwrap();
        let second = hash_adapter_dir(root.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("adapter_config.json", root.path().join("link")).unwrap();
            assert!(hash_adapter_dir(root.path()).is_err());
        }
    }

    #[test]
    fn adapter_digest_matches_the_python_sdk_contract() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("adapter_config.json"), b"{}").unwrap();
        std::fs::write(root.path().join("adapter_model.safetensors"), b"weights").unwrap();
        assert_eq!(
            hash_adapter_dir(root.path()).unwrap(),
            "26d1c7593b9650cb489a9a1fe2fad9def32c75ec2685cf8261c3c0fa3b73e315"
        );
    }

    #[tokio::test]
    async fn zero_queue_depth_still_allows_immediate_capacity() {
        let root = tempfile::tempdir().unwrap();
        let executor = RolloutExecutor::new(CreateRolloutExecutorRequest {
            name: "bounded".into(),
            backend: "vllm".into(),
            endpoint: "http://127.0.0.1:1".into(),
            adapter_root: root.path().display().to_string(),
            device_adapter_socket: None,
            fallback_pool: None,
            max_concurrent_requests: Some(1),
            max_queue_depth: Some(0),
            request_timeout_secs: Some(1),
        })
        .unwrap();
        let first = executor.acquire_queue_permit().await.unwrap();
        assert!(matches!(
            executor.acquire_queue_permit().await,
            Err(RolloutError::Unavailable(_))
        ));
        drop(first);
        assert!(executor.acquire_queue_permit().await.is_ok());
    }

    #[test]
    fn prompt_validation_rejects_mixed_representations() {
        let request = RolloutGenerateRequest {
            idempotency_key: "key".into(),
            policy: "policy".into(),
            version: None,
            prompts: vec![
                RolloutPrompt {
                    text: Some("hello".into()),
                    token_ids: None,
                },
                RolloutPrompt {
                    text: None,
                    token_ids: Some(vec![1, 2]),
                },
            ],
            sampling: RolloutSamplingParams {
                n: 1,
                max_tokens: 16,
                temperature: None,
                top_p: None,
                top_k: None,
                min_p: None,
                repetition_penalty: None,
                seed: None,
                logprobs: None,
                prompt_logprobs: None,
            },
            deadline_ms: None,
            cohort: None,
        };
        assert!(validate_generate_request(&request).is_err());
    }

    #[test]
    fn completion_body_uses_vllm_token_id_contract() {
        let request = RolloutGenerateRequest {
            idempotency_key: "key".into(),
            policy: "policy".into(),
            version: Some("7".into()),
            prompts: vec![RolloutPrompt {
                text: None,
                token_ids: Some(vec![1, 2, 3]),
            }],
            sampling: RolloutSamplingParams {
                n: 2,
                max_tokens: 8,
                temperature: Some(0.9),
                top_p: Some(0.95),
                top_k: None,
                min_p: None,
                repetition_penalty: None,
                seed: Some(42),
                logprobs: Some(1),
                prompt_logprobs: None,
            },
            deadline_ms: None,
            cohort: None,
        };
        let body = completion_body(&request, "adapter").unwrap();
        assert_eq!(body["prompt"], serde_json::json!([[1, 2, 3]]));
        assert_eq!(body["return_token_ids"], true);
        assert_eq!(body["model"], "adapter");
        assert_eq!(body["seed"], 42);
    }
}
