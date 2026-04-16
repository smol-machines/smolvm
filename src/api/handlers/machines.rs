//! Machine lifecycle handlers.
//!
//! These handlers manage persistent machines via the shared database,
//! accessible to both API and CLI commands.
//!
//! ## Limitations
//!
//! ### Name Length Limit
//!
//! Machine name length is bounded by the kernel's `sockaddr_un.sun_path`
//! limit (104 bytes on macOS, 108 on Linux). The full socket path is:
//!
//! ```text
//! ~/Library/Caches/smolvm/vms/{name}/agent.sock
//! ```
//!
//! Maximum usable name length therefore depends on the user's home directory.
//! For a typical macOS home (`/Users/<username>/`, ~20 chars), names can be
//! 50+ characters. The actual socket path is validated at create time via
//! [`crate::data::validate_socket_path_fits`] so overly-long names are
//! rejected with a clear error up front.
//!
//! Recommended: keep names short and descriptive (e.g., "dev-vm", "test-1").

use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use std::time::Duration;

use crate::agent::{AgentClient, AgentManager, HostMount};
use crate::api::error::ApiError;
use crate::api::state::{
    vm_resources_to_spec, ApiState, MachineEntry, MachineRegistration, ReservationGuard,
};
use crate::api::types::{
    ApiErrorResponse, CreateMachineRequest, DeleteResponse, EnvVar, ExecResponse,
    ListMachinesResponse, MachineExecRequest, MachineInfo, MountInfo, MountSpec, PortSpec,
    ResizeMachineRequest, ResourceSpec,
};
use crate::api::validate_command;
use crate::api::TraceId;
use crate::config::{RecordState, RestartConfig, VmRecord};
use crate::data::disk::{Overlay, Storage};
use crate::data::validate_vm_name;
use crate::process::{
    is_alive, is_our_process_strict, process_start_time, stop_vm_process, VM_SIGKILL_TIMEOUT,
    VM_SIGTERM_TIMEOUT,
};
use crate::storage::{expand_disk, DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};
use crate::util::generate_machine_name;
use crate::Error as SmolvmError;

/// Re-export of the shared resolver. The CLI and API list endpoints
/// must compute state the same way, otherwise `machine list` (CLI)
/// and `GET /api/v1/machines` (API) can disagree about whether a VM
/// is `Running`, `Stopped`, or `Unreachable`. Single source of truth
/// lives in `agent::state_probe`.
use crate::agent::state_probe::resolve_state as resolve_machine_state;

/// Convert VmRecord to MachineInfo (pure mapping, no I/O).
fn record_to_info(name: &str, record: &VmRecord) -> MachineInfo {
    let actual_state = resolve_machine_state(name, record);
    // Clear stale PID when the process is not actually running, so clients
    // never see state=stopped paired with a PID.
    let pid = if actual_state == RecordState::Stopped {
        None
    } else {
        record.pid
    };
    MachineInfo {
        name: name.to_string(),
        state: actual_state.to_string(),
        cpus: record.cpus,
        mem: record.mem,
        pid,
        mounts: record
            .mounts
            .iter()
            .enumerate()
            .map(|(i, (source, target, readonly))| MountInfo {
                tag: HostMount::mount_tag(i),
                source: source.clone(),
                target: target.clone(),
                readonly: *readonly,
            })
            .collect(),
        ports: record
            .ports
            .iter()
            .map(|(host, guest)| PortSpec {
                host: *host,
                guest: *guest,
            })
            .collect(),
        network: record.network,
        storage_gb: record.storage_gb,
        overlay_gb: record.overlay_gb,
        created_at: record.created_at.clone(),
    }
}

/// Build a MachineEntry from a VmRecord and AgentManager.
///
/// Used by `start_machine` to register a machine in ApiState after boot
/// or during registry repair. Centralizes the record→entry conversion
/// so the two branches don't drift.
fn machine_entry_from_record(record: &VmRecord, manager: AgentManager) -> MachineEntry {
    let mounts = record
        .mounts
        .iter()
        .map(|(s, t, ro)| MountSpec {
            source: s.clone(),
            target: t.clone(),
            readonly: *ro,
        })
        .collect();
    let ports = record
        .ports
        .iter()
        .map(|(h, g)| PortSpec {
            host: *h,
            guest: *g,
        })
        .collect();
    MachineEntry {
        manager,
        mounts,
        ports,
        resources: vm_resources_to_spec(record.vm_resources()),
        restart: record.restart.clone(),
        network: record.network,
    }
}

/// Attempt graceful shutdown, then force-terminate if still running.
///
/// Uses verified signals to prevent killing an unrelated process if the
/// PID was recycled by the OS. Returns true if the process is confirmed
/// dead (or was never running), false if it may still be alive.
fn shutdown_machine_process(name: &str, pid: Option<i32>, pid_start_time: Option<u64>) -> bool {
    // Try graceful shutdown via vsock first.
    // If vsock connects, this confirms the process is our VM (identity verification).
    let manager = AgentManager::for_vm(name).ok();
    let mut vsock_confirmed = false;
    if let Some(ref manager) = manager {
        if let Ok(mut client) = AgentClient::connect(manager.vsock_socket()) {
            vsock_confirmed = true;
            let _ = client.shutdown();
        }
    }

    // PID-based signal handling.
    if let Some(pid) = pid {
        // Identity check: vsock acknowledgement OR strict PID start-time match.
        // We intentionally do NOT use the lenient is_our_process() here because
        // it treats any alive PID as "ours" when start_time is None — which risks
        // killing an unrelated process if the OS reused the PID.
        let identity_ok = vsock_confirmed || is_our_process_strict(pid, pid_start_time);

        if identity_ok {
            let _ = stop_vm_process(pid, VM_SIGTERM_TIMEOUT, VM_SIGKILL_TIMEOUT);
        } else {
            tracing::debug!(pid, name, "PID already dead");
        }

        // Post-check: verify the process is actually gone.
        if is_alive(pid) {
            tracing::warn!(pid, name, "process still alive after shutdown attempts");
            return false;
        }
    } else {
        // No PID available — check if VM is still reachable via vsock.
        if let Some(ref manager) = manager {
            if let Ok(mut client) = AgentClient::connect(manager.vsock_socket()) {
                if client.ping().is_ok() {
                    tracing::warn!(name, "VM still reachable via vsock but no PID to signal");
                    return false;
                }
            }
        }
    }

    true
}

/// Create a new machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines",
    tag = "Machines",
    request_body = CreateMachineRequest,
    responses(
        (status = 200, description = "Machine created", body = MachineInfo),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 409, description = "Machine already exists", body = ApiErrorResponse)
    )
)]
pub async fn create_machine(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateMachineRequest>,
) -> Result<Json<MachineInfo>, ApiError> {
    // Validate: --from and --image are mutually exclusive
    if req.from.is_some() && req.image.is_some() {
        return Err(ApiError::BadRequest(
            "'from' and 'image' are mutually exclusive".to_string(),
        ));
    }

    // Generate name if not provided, then validate. The on-disk layout uses
    // a hash-derived directory (see `vm_data_dir`) so name length doesn't
    // affect the socket path — only character sanity + a generous length
    // cap are needed.
    let name = req.name.clone().unwrap_or_else(generate_machine_name);
    validate_vm_name(&name, "machine name").map_err(ApiError::BadRequest)?;

    // Validate mount paths
    for mount_spec in &req.mounts {
        HostMount::try_from(mount_spec).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }

    // If --from is set, read manifest and extract sidecar
    let (
        image,
        source_smolmachine,
        entrypoint,
        cmd,
        env,
        workdir,
        manifest_cpus,
        manifest_mem,
        manifest_net,
    ) = if let Some(ref sidecar_path) = req.from {
        let path = std::path::Path::new(sidecar_path);
        if !path.exists() {
            return Err(ApiError::BadRequest(format!(
                "sidecar file not found: {}",
                sidecar_path
            )));
        }
        let manifest = smolvm_pack::packer::read_manifest_from_sidecar(path)
            .map_err(|e| ApiError::internal(format!("read .smolmachine: {}", e)))?;
        let footer = smolvm_pack::packer::read_footer_from_sidecar(path)
            .map_err(|e| ApiError::internal(format!("read sidecar footer: {}", e)))?;
        let cache_dir = smolvm_pack::extract::get_cache_dir(footer.checksum)
            .map_err(|e| ApiError::internal(format!("get cache dir: {}", e)))?;
        smolvm_pack::extract::extract_sidecar(path, &cache_dir, &footer, false, false)
            .map_err(|e| ApiError::internal(format!("extract sidecar: {}", e)))?;
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned();
        let env_parsed: Vec<(String, String)> = manifest
            .env
            .iter()
            .filter_map(|e| {
                e.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect();
        (
            Some(manifest.image),
            Some(canonical),
            manifest.entrypoint,
            manifest.cmd,
            env_parsed,
            manifest.workdir,
            manifest.cpus,
            manifest.mem,
            manifest.network,
        )
    } else {
        (
            req.image.clone(),
            None,
            vec![],
            vec![],
            vec![],
            None,
            req.cpus,
            req.mem,
            req.network,
        )
    };

    // Use manifest defaults if user didn't override
    let cpus =
        if req.from.is_some() && req.cpus == crate::data::resources::DEFAULT_MICROVM_CPU_COUNT {
            manifest_cpus
        } else {
            req.cpus
        };
    let mem = if req.from.is_some() && req.mem == crate::data::resources::DEFAULT_MICROVM_MEMORY_MIB
    {
        manifest_mem
    } else {
        req.mem
    };
    let network = req.network || manifest_net;

    // Reserve the name atomically (prevents concurrent creation)
    let guard = ReservationGuard::new(&state, name.clone())?;

    // Create manager (does not boot the VM)
    let manager = tokio::task::spawn_blocking({
        let name = name.clone();
        let storage_gb = req.storage_gb;
        let overlay_gb = req.overlay_gb;
        move || {
            AgentManager::for_vm_with_sizes(&name, storage_gb, overlay_gb)
                .map_err(|e| ApiError::internal(format!("failed to create agent manager: {}", e)))
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))??;

    let resources = ResourceSpec {
        cpus: Some(cpus),
        memory_mb: Some(mem),
        network: Some(network),
        storage_gb: req.storage_gb,
        overlay_gb: req.overlay_gb,
        allowed_cidrs: req.allowed_cidrs.clone(),
    };

    // Complete registration: persists to DB + registers in ApiState
    guard.complete(MachineRegistration {
        manager,
        mounts: req.mounts.clone(),
        ports: req.ports.clone(),
        resources: resources.clone(),
        restart: RestartConfig::default(),
        network,
        image,
        source_smolmachine,
        entrypoint,
        cmd,
        env,
        workdir,
    })?;

    // Fetch the persisted record for the response
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::internal("machine disappeared after creation".to_string()))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// List all machines.
#[utoipa::path(
    get,
    path = "/api/v1/machines",
    tag = "Machines",
    responses(
        (status = 200, description = "List of machines", body = ListMachinesResponse),
        (status = 500, description = "Database error", body = ApiErrorResponse)
    )
)]
pub async fn list_machines(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ListMachinesResponse>, ApiError> {
    let db = state.db();
    let vms = db.list_vms().map_err(ApiError::database)?;

    let machines: Vec<MachineInfo> = vms
        .iter()
        .map(|(name, record)| record_to_info(name, record))
        .collect();

    Ok(Json(ListMachinesResponse { machines }))
}

/// Get machine status.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{name}",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine details", body = MachineInfo),
        (status = 404, description = "Machine not found", body = ApiErrorResponse)
    )
)]
pub async fn get_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MachineInfo>, ApiError> {
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Start a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/start",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine started", body = MachineInfo),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to start", body = ApiErrorResponse)
    )
)]
pub async fn start_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MachineInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Resolve via the shared probe (PID + vsock ping) so we don't
    // mistake a zombie VMM (live PID, dead agent) for Running — the
    // CLI's `start --name` handles this same case; the API must
    // match or a REST caller ends up with "start succeeded" followed
    // by every subsequent /exec failing.
    //
    // `resolve_state` does a short vsock ping, so run it on the
    // blocking pool rather than in the async task.
    let name_probe = name.clone();
    let record_probe = record.clone();
    let resolved = tokio::task::spawn_blocking(move || {
        crate::agent::state_probe::resolve_state(&name_probe, &record_probe)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if resolved == RecordState::Running {
        if !state.machine_exists(&name) {
            // Running in DB but not in registry (startup recovery case).
            let name_for_repair = name.clone();
            let storage_gb = record.storage_gb;
            let overlay_gb = record.overlay_gb;
            let manager = tokio::task::spawn_blocking(move || {
                AgentManager::for_vm_with_sizes(&name_for_repair, storage_gb, overlay_gb)
            })
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
            .map_err(|e| {
                ApiError::internal(format!(
                    "machine '{}' is running but registry repair failed: {}",
                    name, e
                ))
            })?;

            state.insert_machine(&name, machine_entry_from_record(&record, manager));
        }
        return Ok(Json(record_to_info(&name, &record)));
    }

    if resolved == RecordState::Unreachable {
        // Zombie: verified-kill the VMM and clear the DB record
        // before falling through to a clean fresh start. Any stale
        // in-memory registry entry gets overwritten by the
        // `insert_machine` call later in this handler.
        let name_recover = name.clone();
        tokio::task::spawn_blocking(move || {
            crate::agent::state_probe::recover_if_unreachable(&name_recover);
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;
    }

    let mounts = record.host_mounts();
    let ports = record.port_mappings();
    let resources = record.vm_resources();

    // Start agent VM in blocking task.
    // Uses subprocess launch to avoid macOS fork-in-multithreaded-process issue.
    let name_clone = name.clone();
    let storage_gb = record.storage_gb;
    let overlay_gb = record.overlay_gb;
    let (manager, pid) = tokio::task::spawn_blocking(move || {
        let manager = AgentManager::for_vm_with_sizes(&name_clone, storage_gb, overlay_gb)
            .map_err(|e| format!("failed to create agent manager: {}", e))?;

        let _ = manager
            .ensure_running_via_subprocess(mounts, ports, resources, Default::default())
            .map_err(|e| format!("failed to start machine: {}", e))?;

        let pid = manager.child_pid();
        Ok::<_, String>((manager, pid))
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
    .map_err(ApiError::internal)?;

    // Register in ApiState so exec/run/container endpoints can find it
    state.insert_machine(&name, machine_entry_from_record(&record, manager));

    // Capture start time for PID verification
    let pid_start_time = pid.and_then(process_start_time);

    // Persist state to database
    let record = db
        .update_vm(&name, |r| {
            r.state = RecordState::Running;
            r.pid = pid;
            r.pid_start_time = pid_start_time;
        })
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "machine '{}' disappeared from database during start",
                name
            ))
        })?;

    // Build response directly with state=running. We just confirmed the VM
    // is running (wait_for_ready passed), so we bypass actual_state() which
    // may falsely report "stopped" on macOS due to setsid/session-leader
    // PID visibility issues.
    let mut info = record_to_info(&name, &record);
    info.state = "running".to_string();
    info.pid = pid;
    Ok(Json(info))
}

/// Stop a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/stop",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine stopped", body = MachineInfo),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to stop", body = ApiErrorResponse)
    )
)]
pub async fn stop_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MachineInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Check state
    let actual_state = record.actual_state();
    if actual_state != RecordState::Running {
        // Already stopped, just return current info
        return Ok(Json(record_to_info(&name, &record)));
    }

    // Get PID and start time from database record - this is the source of truth
    let pid = record.pid;
    let pid_start_time = record.pid_start_time;

    // Stop VM in blocking task
    let name_clone = name.clone();
    let stopped = tokio::task::spawn_blocking(move || {
        shutdown_machine_process(&name_clone, pid, pid_start_time)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if !stopped {
        return Err(ApiError::Internal(format!(
            "machine '{}' process may still be running after stop attempt",
            name
        )));
    }

    // Persist state to database and get updated record — only after confirmed stop
    let record = db
        .update_vm(&name, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        })
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "machine '{}' disappeared from database during stop",
                name
            ))
        })?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Delete a machine.
#[utoipa::path(
    delete,
    path = "/api/v1/machines/{name}",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine deleted", body = DeleteResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to delete", body = ApiErrorResponse)
    )
)]
pub async fn delete_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let db = state.db();

    // Check if VM exists and get its state
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Get PID and start time from database record
    let pid = record.pid;
    let pid_start_time = record.pid_start_time;

    // Stop if running (in blocking task)
    let name_clone = name.clone();
    let stopped = tokio::task::spawn_blocking(move || {
        shutdown_machine_process(&name_clone, pid, pid_start_time)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if !stopped {
        return Err(ApiError::Internal(format!(
            "machine '{}' process (pid {}) is still alive after shutdown; not removing",
            name,
            pid.map(|p| p.to_string())
                .unwrap_or_else(|| "unknown".into()),
        )));
    }

    // Remove from registry (in-memory + database)
    match state.remove_machine(&name) {
        Ok(_) => {}
        Err(ApiError::NotFound(_)) => {
            // Machine exists in DB but not in registry (startup recovery case).
            // Remove directly from DB.
            let removed = db.remove_vm(&name).map_err(ApiError::database)?;
            if removed.is_none() {
                return Err(ApiError::NotFound(format!("machine '{}' not found", name)));
            }
        }
        Err(e) => return Err(e),
    }

    Ok(Json(DeleteResponse { deleted: name }))
}

/// Execute a command in a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/exec",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    request_body = MachineExecRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine not running", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn exec_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    trace_id: Option<axum::Extension<TraceId>>,
    Json(req): Json<MachineExecRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    validate_command(&req.command)?;

    // Check if VM exists
    let db = state.db();
    if db.get_vm(&name).map_err(ApiError::database)?.is_none() {
        return Err(ApiError::NotFound(format!("machine '{}' not found", name)));
    }

    let name_clone = name.clone();
    let command = req.command.clone();
    let env = EnvVar::to_tuples(&req.env);
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    let result = tokio::task::spawn_blocking(move || {
        // Get manager and check if running
        let manager = AgentManager::for_vm(&name_clone)
            .map_err(|e| SmolvmError::agent("create agent manager", e.to_string()))?;

        if manager.try_connect_existing().is_none() {
            return Err(SmolvmError::InvalidState {
                expected: "running".into(),
                actual: "stopped".into(),
            });
        }

        // Execute command
        let mut client = manager
            .connect()
            .map_err(|e| SmolvmError::agent("connect", e.to_string()))?;
        if let Some(tid) = tid {
            client.set_trace_id(tid);
        }
        let (exit_code, stdout, stderr) = client
            .vm_exec(command, env, workdir, timeout)
            .map_err(|e| SmolvmError::agent("exec", e.to_string()))?;

        // Keep VM running (persistent)
        manager.detach();

        Ok(ExecResponse {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    result.map(Json).map_err(ApiError::from)
}

/// Resize a machine's disk resources.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/resize",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    request_body = ResizeMachineRequest,
    responses(
        (status = 200, description = "Machine resized", body = MachineInfo),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine is running", body = ApiErrorResponse),
        (status = 500, description = "Resize failed", body = ApiErrorResponse)
    )
)]
pub async fn resize_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(req): Json<ResizeMachineRequest>,
) -> Result<Json<MachineInfo>, ApiError> {
    let db = state.db();

    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?
        .clone();

    let actual_state = record.actual_state();
    match actual_state {
        RecordState::Stopped | RecordState::Created => {}
        _ => {
            return Err(ApiError::Conflict(format!(
                "machine '{}' must be stopped before resizing. Current state: {:?}",
                name, actual_state
            )));
        }
    }

    let current_storage_gb = record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
    let current_overlay_gb = record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);

    if req.storage_gb.unwrap_or(current_storage_gb) < current_storage_gb {
        return Err(ApiError::BadRequest(format!(
            "storageGb cannot be smaller than current size ({} GiB)",
            current_storage_gb
        )));
    }
    if req.overlay_gb.unwrap_or(current_overlay_gb) < current_overlay_gb {
        return Err(ApiError::BadRequest(format!(
            "overlayGb cannot be smaller than current size ({} GiB)",
            current_overlay_gb
        )));
    }

    if req.storage_gb.is_none() && req.overlay_gb.is_none() {
        return Err(ApiError::BadRequest(
            "at least one of storageGb or overlayGb must be specified".into(),
        ));
    }

    let manager = AgentManager::for_vm(&name)
        .map_err(|e| ApiError::internal(format!("failed to get agent manager: {}", e)))?;

    if let Some(storage_gb) = req.storage_gb {
        if storage_gb > current_storage_gb {
            let storage_path = manager.storage_path();
            expand_disk::<Storage>(storage_path, storage_gb)
                .map_err(|e| ApiError::internal(format!("failed to expand storage: {}", e)))?;
        }
    }

    if let Some(overlay_gb) = req.overlay_gb {
        if overlay_gb > current_overlay_gb {
            let overlay_path = manager.overlay_path();
            expand_disk::<Overlay>(overlay_path, overlay_gb)
                .map_err(|e| ApiError::internal(format!("failed to expand overlay: {}", e)))?;
        }
    }

    let record = db
        .update_vm(&name, |r| {
            if let Some(s) = req.storage_gb {
                r.storage_gb = Some(s);
            }
            if let Some(o) = req.overlay_gb {
                r.overlay_gb = Some(o);
            }
        })
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("machine '{}' disappeared during resize", name))
        })?;

    Ok(Json(record_to_info(&name, &record)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SmolvmDb;
    use tempfile::TempDir;

    #[test]
    fn test_record_to_info() {
        let record = VmRecord::new(
            "test-vm".to_string(),
            2,
            1024,
            vec![
                ("/host/path".to_string(), "/guest/path".to_string(), false),
                ("/host/ro".to_string(), "/guest/ro".to_string(), true),
            ],
            vec![(8080, 80), (3000, 3000)],
            false,
        );

        let info = record_to_info("test-vm", &record);

        assert_eq!(info.name, "test-vm");
        assert_eq!(info.state, "created");
        assert_eq!(info.cpus, 2);
        assert_eq!(info.mem, 1024);
        assert_eq!(info.mounts.len(), 2);
        assert_eq!(info.ports.len(), 2);
        assert!(!info.network);
        assert!(info.pid.is_none());
    }

    #[test]
    fn test_record_to_info_with_running_state() {
        let mut record = VmRecord::new("running-vm".to_string(), 1, 512, vec![], vec![], false);
        record.state = RecordState::Running;
        record.pid = Some(12345);

        let info = record_to_info("running-vm", &record);

        assert_eq!(info.name, "running-vm");
        // Note: actual_state() checks if process is alive, which won't be true in test
        // So it will show as "stopped" even though record state is Running
        assert_eq!(info.cpus, 1);
        assert_eq!(info.mem, 512);
        assert_eq!(info.mounts.len(), 0);
        assert_eq!(info.ports.len(), 0);
    }

    #[test]
    fn test_record_to_info_default_values() {
        let record = VmRecord::new("minimal-vm".to_string(), 1, 512, vec![], vec![], false);

        let info = record_to_info("minimal-vm", &record);

        assert_eq!(info.name, "minimal-vm");
        assert_eq!(info.state, "created");
        assert_eq!(info.cpus, 1);
        assert_eq!(info.mem, 512);
        assert_eq!(info.mounts.len(), 0);
        assert_eq!(info.ports.len(), 0);
        assert!(!info.network);
        assert!(info.pid.is_none());
        assert!(!info.created_at.is_empty());
    }

    #[test]
    fn test_record_to_info_with_network() {
        let record = VmRecord::new("network-vm".to_string(), 1, 512, vec![], vec![], true);

        let info = record_to_info("network-vm", &record);

        assert_eq!(info.name, "network-vm");
        assert!(info.network);
    }

    /// Helper to create a test database and API state.
    #[allow(dead_code)]
    fn setup_test_state() -> (TempDir, Arc<ApiState>) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let db_path = dir.path().join("test.redb");
        let db = SmolvmDb::open_at(&db_path).expect("failed to open test db");
        let state = Arc::new(ApiState::with_db(db));
        (dir, state)
    }

    #[tokio::test]
    async fn test_resize_validation_shrink_storage_rejected() {
        let (_dir, state) = setup_test_state();
        let db = state.db();
        create_test_vm(db, "test-vm", Some(20), Some(5));

        let req = ResizeMachineRequest {
            storage_gb: Some(10),
            overlay_gb: None,
        };
        let result = resize_machine(State(state), Path("test-vm".to_string()), Json(req)).await;
        assert!(matches!(result.unwrap_err(), ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_resize_validation_no_params_rejected() {
        let (_dir, state) = setup_test_state();
        let db = state.db();
        create_test_vm(db, "test-vm", Some(20), Some(5));

        let req = ResizeMachineRequest {
            storage_gb: None,
            overlay_gb: None,
        };
        let result = resize_machine(State(state), Path("test-vm".to_string()), Json(req)).await;
        assert!(matches!(result.unwrap_err(), ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_resize_not_found() {
        let (_dir, state) = setup_test_state();
        let req = ResizeMachineRequest {
            storage_gb: Some(30),
            overlay_gb: None,
        };
        let result = resize_machine(State(state), Path("nonexistent".to_string()), Json(req)).await;
        assert!(matches!(result.unwrap_err(), ApiError::NotFound(_)));
    }

    /// Helper to create a VM record in the database.
    fn create_test_vm(db: &SmolvmDb, name: &str, storage_gb: Option<u64>, overlay_gb: Option<u64>) {
        let mut record = VmRecord::new(name.to_string(), 1, 512, vec![], vec![], false);
        record.storage_gb = storage_gb;
        record.overlay_gb = overlay_gb;
        db.insert_vm(name, &record)
            .expect("failed to insert test vm");
    }
}
