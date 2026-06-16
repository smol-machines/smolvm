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

use crate::agent::{vm_data_dir, AgentClient, AgentManager, HostMount};
use crate::api::error::ApiError;
use crate::api::state::{
    vm_resources_to_spec, with_machine_client_traced, ApiState, MachineEntry, MachineRegistration,
    ReservationGuard,
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
        network_backend: record.network_backend,
        allowed_cidrs: record.allowed_cidrs.clone(),
        storage_gb: record.storage_gb,
        overlay_gb: record.overlay_gb,
        created_at: record.created_at,
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
        secret_refs: record.secret_refs.clone(),
        source_smolmachine: record.source_smolmachine.clone(),
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
    // Validate: registry_ref, from, and image are mutually exclusive
    let source_count = [
        req.registry_ref.is_some(),
        req.from.is_some(),
        req.image.is_some(),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    if source_count > 1 {
        return Err(ApiError::BadRequest(
            "'registryRef', 'from', and 'image' are mutually exclusive".to_string(),
        ));
    }

    // Published ports need the inbound path that only virtio-net has. With an
    // UNSET backend the launcher auto-selects virtio-net when ports are present
    // (see `plan_launch_network`), so ports "just work" without per-request
    // wiring — mirroring the CLI and `validate_requested_network_backend`. Only
    // an EXPLICIT TSI choice alongside ports is a misconfig (TSI is
    // outbound-only and would silently never accept connections).
    if !req.ports.is_empty() && req.network_backend == Some(crate::network::NetworkBackend::Tsi) {
        return Err(ApiError::BadRequest(
            "published ports require networkBackend 'virtio-net' (TSI is outbound-only); \
             omit networkBackend or set it to 'virtio-net'"
                .to_string(),
        ));
    }

    // If registry_ref is set, pull the artifact from the registry and treat as `from`
    let mut req = req;
    if let Some(ref registry_ref) = req.registry_ref.clone() {
        let pulled_path =
            pull_from_registry(registry_ref, req.registry_identity_token.as_deref()).await?;
        req.from = Some(pulled_path);
        req.registry_ref = None;
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
        manifest_secret_refs,
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
        // Extraction happens after the agent manager creates this machine's data
        // dir (below), so the layers land in the machine's own dir, not here.
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
        // A .smolmachine is an untrusted, portable artifact: validate its secret
        // refs Untrusted, which rejects every source kind, so a packed
        // from_env/from_file can't read this host's env/files at exec time.
        // Reject rather than carry/exfil.
        for (key, r) in &manifest.secret_refs {
            crate::secrets::validate_ref(r, crate::secrets::ResolutionScope::Untrusted).map_err(
                |e| {
                    ApiError::BadRequest(format!(
                        "packed secret '{}': {} (packs may not carry secret refs)",
                        key, e
                    ))
                },
            )?;
        }
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
            manifest.secret_refs,
        )
    } else {
        (
            req.image.clone(),
            None,
            vec![],
            vec![],
            vec![],
            None,
            crate::data::resources::DEFAULT_MICROVM_CPU_COUNT,
            crate::data::resources::DEFAULT_MICROVM_MEMORY_MIB,
            req.network,
            Default::default(),
        )
    };

    // Use explicit API resources when provided. Otherwise, preserve packed
    // artifact manifest defaults, or the high VM defaults for non-artifact
    // machines. Memory is ballooned, so a generous default does not imply
    // immediate host commitment.
    let (cpus, mem) = resolve_create_resources(&req, manifest_cpus, manifest_mem);
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

    // Extract the bundle's OCI layers into this machine's own data dir (created
    // by the manager above) rather than the shared pack cache, so every start is
    // independent of the .smolmachine file surviving and the macOS layers volume
    // is owned 1:1 by the machine. Extraction mounts the case-sensitive volume on
    // macOS; detach it immediately so a created-but-unstarted machine leaves
    // nothing mounted (invariant: the per-machine layers volume is mounted iff
    // the VM is running). The name was reserved above, so this never clobbers
    // another machine's layers.
    if let Some(ref sidecar_path) = source_smolmachine {
        let name = name.clone();
        let sidecar_path = sidecar_path.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
            let path = std::path::Path::new(&sidecar_path);
            let cache_dir = crate::agent::machine_layers_cache_dir(&name);
            let result = (|| {
                smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
                match std::fs::remove_dir_all(&cache_dir) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(ApiError::internal(format!(
                            "clear packed layers cache: {}",
                            e
                        )));
                    }
                }
                let footer = smolvm_pack::packer::read_footer_from_sidecar(path)
                    .map_err(|e| ApiError::internal(format!("read sidecar footer: {}", e)))?;
                smolvm_pack::extract::extract_sidecar(path, &cache_dir, &footer, false, false)
                    .map_err(|e| ApiError::internal(format!("extract sidecar: {}", e)))
            })();
            // Detach the case-sensitive volume mounted during extraction so a
            // created-but-unstarted machine leaves nothing mounted, and so the
            // rollback below can remove the data dir cleanly (macOS; no-op on Linux).
            smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
            if let Err(e) = result {
                // Extraction failed after the manager created the machine's data
                // dir. guard.complete() will not run, so no DB record persists and
                // the name is released on drop — but the on-disk dir would be left
                // orphaned. Roll it back so a retry starts clean. Best-effort: a
                // remove failure only leaves the orphan, never a worse state.
                // cache_dir is <vm_data_dir>/pack, so its parent is the data dir.
                if let Some(vm_dir) = cache_dir.parent() {
                    let _ = std::fs::remove_dir_all(vm_dir);
                }
                return Err(e);
            }
            Ok(())
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {}", e)))??;
    }

    let resources = ResourceSpec {
        cpus: Some(cpus),
        memory_mb: Some(mem),
        network: Some(network),
        gpu: Some(req.gpu),
        storage_gb: req.storage_gb,
        overlay_gb: req.overlay_gb,
        allowed_cidrs: req.allowed_cidrs.clone(),
        network_backend: req.network_backend,
    };

    // Validate request-body secret refs before persisting. Untrusted
    // scope rejects every source kind, so any non-empty `secrets` map on
    // the API surface is refused regardless of server binding — secrets
    // must be configured locally via the CLI.
    crate::api::handlers::validate_request_secrets(&req.secrets)?;

    // Complete registration: persists to DB + registers in ApiState
    let complete_result = guard.complete(MachineRegistration {
        manager,
        mounts: req.mounts.clone(),
        ports: req.ports.clone(),
        resources: resources.clone(),
        restart: match req.restart {
            Some(ref spec) => {
                let policy = spec
                    .policy
                    .as_deref()
                    .unwrap_or("never")
                    .parse()
                    .map_err(|e: String| ApiError::BadRequest(e))?;
                RestartConfig {
                    policy,
                    max_retries: spec.max_retries.unwrap_or(0),
                    ..Default::default()
                }
            }
            None => RestartConfig::default(),
        },
        network,
        image,
        source_smolmachine,
        entrypoint,
        cmd,
        env,
        workdir,
        // Record secrets = packed refs from --from (validated Untrusted above)
        // merged with request refs (validated Untrusted at ~line 333); request
        // refs win on key collision. Both sources are store-only, so RecordReplay
        // resolution at exec time stays safe.
        secret_refs: {
            let mut s = manifest_secret_refs;
            s.extend(req.secrets.clone());
            s
        },
    });
    if let Err(e) = complete_result {
        let data_dir = vm_data_dir(&name);
        smolvm_pack::extract::force_detach_layers_volume(&crate::agent::machine_layers_cache_dir(
            &name,
        ));
        if let Err(remove_err) = std::fs::remove_dir_all(&data_dir) {
            if remove_err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    machine = %name,
                    dir = %data_dir.display(),
                    error = %remove_err,
                    "failed to remove machine data dir after create commit failure"
                );
            }
        }
        return Err(e);
    }

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

/// Classify a VM launch/boot failure. A published host-port bind conflict — the
/// virtio-net runtime couldn't bind `0.0.0.0:<hostPort>` because something
/// (typically an orphaned VMM) still holds it — is surfaced as `PortConflict`
/// (409 `PORT_IN_USE`), which the control plane recognizes and retries on a
/// freshly-allocated port. Everything else stays a 500. Matching is scoped to
/// the virtio-net path so an unrelated AddrInUse can't be mistaken for it.
fn classify_launch_error(e: String) -> ApiError {
    let lc = e.to_ascii_lowercase();
    if lc.contains("address already in use") && lc.contains("virtio") {
        ApiError::PortConflict(e)
    } else {
        ApiError::Internal(e)
    }
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
        (status = 409, description = "A published host port is already in use (PORT_IN_USE)", body = ApiErrorResponse),
        (status = 500, description = "Failed to start", body = ApiErrorResponse)
    )
)]
pub async fn start_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MachineInfo>, ApiError> {
    // Hold the per-machine lifecycle lock across the whole start so a concurrent
    // stop/delete cannot detach the macOS layers volume between our acquire+mount
    // and the launch, nor launch a guest into the launcher's missing-dir error
    // (review finding #3). Acquired before the DB read and resolve_state probe
    // below so the "is it running?" decision and the launch happen under one held
    // lock; it is the outermost lock (the entry mutex is taken later, inside the
    // spawn_blocking). Linux: the guarded detach/mount are no-ops.
    let lifecycle = state.lifecycle_lock(&name);
    let _guard = lifecycle.lock().await;

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

    // Note: concurrent-boot bounding lives at the chokepoint all boot paths share
    // (`AgentManager::start_via_subprocess` → a process-wide sync gate), not here,
    // so the supervisor + reconnect boot paths are bounded too. See
    // `smolvm::process::acquire_boot_permit`.

    // Start agent VM in blocking task.
    // Uses subprocess launch to avoid macOS fork-in-multithreaded-process issue.
    let name_clone = name.clone();
    let storage_gb = record.storage_gb;
    let overlay_gb = record.overlay_gb;
    let source_smolmachine = record.source_smolmachine.clone();
    let (manager, pid) = tokio::task::spawn_blocking(move || {
        let manager = AgentManager::for_vm_with_sizes(&name_clone, storage_gb, overlay_gb)
            .map_err(|e| format!("failed to create agent manager: {}", e))?;

        // Wire pre-extracted layers if this machine was created from a .smolmachine.
        let features = crate::api::state::build_launch_features(
            Some(&name_clone),
            source_smolmachine.as_deref(),
        )
        .map_err(|e| format!("failed to prepare packed layers: {}", e))?;
        let _ = manager
            .ensure_running_via_subprocess(mounts, ports, resources, features)
            .map_err(|e| format!("failed to start machine: {}", e))?;

        let pid = manager.child_pid();
        Ok::<_, String>((manager, pid))
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
    .map_err(classify_launch_error)?;

    // Register in ApiState so exec/run/container endpoints can find it
    state.insert_machine(&name, machine_entry_from_record(&record, manager));

    // Image machines: launch the image's workload (its ENTRYPOINT+CMD) as a
    // detached container now that the VM is up — mirroring the CLI start path
    // (`vm_common.rs`). Without this, an image machine started via the API boots
    // only the bare agent VM and never runs its server, so a published port
    // forwards to a guest socket nothing is listening on (connection reset →
    // proxy 502). An empty command lets the agent resolve the image's own
    // ENTRYPOINT+CMD. This runs once per fresh start: the handler returns early
    // above when the machine is already Running, so the container is never
    // double-launched. Best-effort: a launch failure leaves a reachable VM
    // (Running, exec-able) rather than failing the start and stranding a retry
    // on the early-return path where the workload would never get launched.
    if let Some(image) = record.image.clone() {
        let entry = state.get_machine(&name)?;
        let mut command = record.entrypoint.clone();
        command.extend(record.cmd.clone());
        let mut env = record.env.clone();
        env.extend(crate::secrets::expose_into_env(
            super::record_secret_refs_env(&entry)?,
        ));
        let workdir = record.workdir.clone();
        let user = record.user.clone();
        let mounts_config = {
            let e = entry.lock();
            e.mounts
                .iter()
                .enumerate()
                .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
                .collect::<Vec<_>>()
        };
        let overlay_id = name.clone();
        let launch = with_machine_client_traced(&entry, None, move |c| {
            if c.query(&image)?.is_none() {
                c.pull_with_registry_config(&image)?;
            }
            let config = crate::agent::RunConfig::new(image, command)
                .with_env(env)
                .with_workdir(workdir)
                .with_user(user)
                .with_mounts(mounts_config)
                .with_persistent_overlay(Some(overlay_id));
            c.run_container_detached(config).map(|_| ())
        })
        .await;
        if let Err(e) = launch {
            tracing::warn!(
                machine = %name,
                error = ?e,
                "failed to launch image workload after start; VM is up but its server is not running"
            );
        }
    }

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
    // Hold the per-machine lifecycle lock across the whole stop so the layers
    // volume detach below cannot race a concurrent start's acquire+mount+launch
    // (review finding #3). Acquired before the DB read and actual_state() probe
    // so the liveness check and the detach act on the same held lock — without
    // it, stop could decide "running" off a snapshot a concurrent start has
    // already superseded, then detach a volume that start just mounted. Outermost
    // lock; the entry mutex is not taken here. Linux: detach is a no-op.
    let lifecycle = state.lifecycle_lock(&name);
    let _guard = lifecycle.lock().await;

    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Check state
    let actual_state = record.actual_state();
    if actual_state != RecordState::Running {
        // Not running. If a prior start mounted the layers volume but the VM
        // then failed to boot (or the server crashed while running), the volume
        // could still be mounted — detach it so a stopped machine never holds a
        // mount (invariant: the per-machine layers volume is mounted iff the VM
        // is running). Safe: actual_state() probed liveness, so the process is
        // confirmed dead and nothing is using the volume. macOS hdiutil detach;
        // a no-op on Linux.
        if record.source_smolmachine.is_some() {
            let name_clone = name.clone();
            tokio::task::spawn_blocking(move || {
                smolvm_pack::extract::force_detach_layers_volume(
                    &crate::agent::machine_layers_cache_dir(&name_clone),
                );
            })
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;
        }
        return Ok(Json(record_to_info(&name, &record)));
    }

    // Get PID and start time from database record - this is the source of truth
    let pid = record.pid;
    let pid_start_time = record.pid_start_time;

    // Stop VM — prefer using the registered manager (which holds the flock)
    // over creating a throwaway one. This ensures the flock is released so
    // a subsequent start can re-acquire it.
    let entry = state.get_machine(&name).ok();
    let name_clone = name.clone();
    let stopped = tokio::task::spawn_blocking(move || {
        let ok = if let Some(ref entry) = entry {
            let e = entry.lock();
            match e.manager.stop() {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(name = %name_clone, error = %err, "manager.stop() failed, falling back to process kill");
                    shutdown_machine_process(&name_clone, pid, pid_start_time)
                }
            }
        } else {
            shutdown_machine_process(&name_clone, pid, pid_start_time)
        };
        if ok {
            // Process is gone — detach this machine's case-sensitive layers
            // volume (macOS hdiutil mount; no-op on Linux). The volume lives
            // under the machine's own data dir and is owned 1:1 by it, so the
            // detach is unconditional and re-acquired on the next start.
            smolvm_pack::extract::force_detach_layers_volume(
                &crate::agent::machine_layers_cache_dir(&name_clone),
            );
        }
        ok
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if !stopped {
        return Err(ApiError::Internal(format!(
            "machine '{}' process may still be running after stop attempt",
            name
        )));
    }

    // The VM process is confirmed dead, but the long-lived registry manager for
    // this machine still holds the per-VM `vm.lock` flock in this serve process.
    // Release it so a subsequent start can re-acquire the lock; otherwise start
    // fails with "another process is already starting or running this VM".
    if let Ok(entry) = state.get_machine(&name) {
        entry.lock().manager.mark_stopped();
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

/// `POST /drain` — explicit, control-initiated node drain (decommission).
///
/// Once serve restarts are lossless (per-VM systemd scopes + detach), drain is no
/// longer a side-effect of process shutdown — it's a deliberate decommission step.
/// The control plane (autoscaler scale-in) calls this BEFORE terminating the host
/// so VMs flush cleanly. Control-only by construction: the serve listener is mTLS-
/// gated, and the loopback door is localhost. See docs/lossless-serve-restart.md.
pub async fn drain_node(State(state): State<Arc<ApiState>>) -> axum::http::StatusCode {
    tracing::info!("drain requested via API (node decommission)");
    drain_machines(&state).await;
    axum::http::StatusCode::OK
}

/// Gracefully stop every running VM. Two callers: the opt-in shutdown path
/// (`SMOLVM_DRAIN_ON_SHUTDOWN`, legacy — being retired now that restart is
/// lossless) and the explicit `POST /drain` decommission endpoint ([`drain_node`]).
/// Draining stops VMs cleanly — flushing disk state and marking them stopped so
/// the control plane can reschedule. Best-effort, concurrent, and bounded so it
/// fits inside the host's termination grace period.
pub async fn drain_machines(state: &Arc<ApiState>) {
    let running: Vec<(String, Option<i32>, Option<u64>)> = match state.db().list_vms() {
        Ok(vms) => vms
            .into_iter()
            .filter(|(_, r)| r.actual_state() == RecordState::Running && r.is_process_alive())
            .map(|(name, r)| (name, r.pid, r.pid_start_time))
            .collect(),
        Err(e) => {
            tracing::error!(error = %e, "drain: failed to list machines");
            return;
        }
    };
    if running.is_empty() {
        return;
    }
    tracing::info!(
        count = running.len(),
        "draining running machines before shutdown"
    );

    let mut handles = Vec::with_capacity(running.len());
    for (name, pid, pid_start_time) in running {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let name_for_kill = name.clone();
            let entry = state.get_machine(&name).ok();
            let stopped = tokio::task::spawn_blocking(move || {
                // Prefer the registered manager (holds the flock); fall back to a
                // PID-verified signal — same path as the stop handler.
                let via_manager = entry
                    .as_ref()
                    .map(|e| e.lock().manager.stop().is_ok())
                    .unwrap_or(false);
                via_manager || shutdown_machine_process(&name_for_kill, pid, pid_start_time)
            })
            .await
            .unwrap_or(false);
            if let Ok(entry) = state.get_machine(&name) {
                entry.lock().manager.mark_stopped();
            }
            let _ = state.db().update_vm(&name, |r| {
                r.state = RecordState::Stopped;
                r.pid = None;
                r.pid_start_time = None;
            });
            tracing::info!(machine = %name, stopped, "drain: machine stopped");
        }));
    }

    let drain_all = async {
        for h in handles {
            let _ = h.await;
        }
    };
    if tokio::time::timeout(std::time::Duration::from_secs(25), drain_all)
        .await
        .is_err()
    {
        tracing::warn!("drain: deadline reached before all machines stopped");
    }
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
    // Hold the per-machine lifecycle lock across the whole delete so the layers
    // volume detach (before the data-dir removal) cannot race a concurrent
    // start's acquire+mount+launch (review finding #3). Acquired before the DB
    // read so the existence check, shutdown, detach, and removal all happen under
    // one held lock. Outermost lock; the entry mutex is not taken here. Linux:
    // detach is a no-op.
    let lifecycle = state.lifecycle_lock(&name);
    let _guard = lifecycle.lock().await;

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
        let ok = shutdown_machine_process(&name_clone, pid, pid_start_time);
        if ok {
            // Process is gone — detach this machine's case-sensitive layers
            // volume (macOS hdiutil mount; no-op on Linux) before the data dir is
            // removed below, otherwise `rm -rf` fails with "Resource busy". The
            // volume is owned 1:1 by this machine, so the detach is unconditional.
            smolvm_pack::extract::force_detach_layers_volume(
                &crate::agent::machine_layers_cache_dir(&name_clone),
            );
        }
        ok
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

    // Remove VM data directory (disk images, sockets, etc.)
    let data_dir = vm_data_dir(&name);
    if data_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&data_dir) {
            tracing::warn!(error = %e, "failed to remove VM data directory: {}", data_dir.display());
        }
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

    // Load the in-memory machine entry; its `secret_refs` were
    // populated at create time and updated via start/stop handlers.
    // This avoids a second DB read per request.
    let entry = state.get_machine(&name)?;
    crate::api::handlers::validate_request_secrets(&req.secrets)?;
    let record_env = crate::api::handlers::record_secret_refs_env(&entry)?;
    let req_env = crate::api::handlers::resolve_request_secrets(&req.secrets)?;

    let name_clone = name.clone();
    let command = req.command.clone();
    let mut env = EnvVar::to_tuples(&req.env);
    env.extend(crate::secrets::expose_into_env(record_env));
    env.extend(crate::secrets::expose_into_env(req_env));
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);
    let stdin_data = req.stdin.clone();

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
            .vm_exec(command, env, workdir, timeout, stdin_data)
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

async fn pull_from_registry(
    registry_ref: &str,
    identity_token: Option<&str>,
) -> Result<String, ApiError> {
    let parsed = crate::registry::Reference::parse(registry_ref)
        .map_err(|e| ApiError::BadRequest(format!("invalid registry reference: {}", e)))?;

    let settings = crate::settings::SmolSettings::load()
        .map_err(|e| ApiError::internal(format!("load settings: {}", e)))?;

    let effective_registry = settings
        .machines
        .get_mirror(&parsed.registry)
        .unwrap_or(&parsed.registry);
    let api_host = match effective_registry {
        "docker.io" => "registry-1.docker.io",
        h => h,
    };
    let base_url = if smolvm_registry::is_local_registry(api_host) {
        format!("http://{}", api_host)
    } else {
        format!("https://{}", api_host)
    };

    let mut client = smolvm_registry::RegistryClient::new(base_url);

    // A request-supplied identity token (the control plane's short-lived,
    // tenant-scoped pull token) takes precedence over any persisted credential.
    if let Some(token) = identity_token {
        client = client.with_identity_token(token.to_string());
    } else if let Some(entry) = settings.machines.registries.get(effective_registry) {
        if let Some(ref token) = entry.identity_token {
            client = client.with_identity_token(token.clone());
        }
    }

    let cache = smolvm_registry::BlobCache::open_default()
        .map_err(|e| ApiError::internal(format!("blob cache: {}", e)))?;

    let repo = parsed.repository();
    let tag_or_digest = registry_reference_tag_or_digest(&parsed);

    tracing::info!(
        registry_ref = %registry_ref,
        repo = %repo,
        reference = %tag_or_digest,
        "pulling .smolmachine from registry"
    );

    let result = smolvm_registry::pull(&client, &repo, tag_or_digest, None, &cache)
        .await
        .map_err(|e| ApiError::internal(format!("registry pull failed: {}", e)))?;

    tracing::info!(path = %result.path.display(), cached = result.cached, "pull complete");

    Ok(result.path.to_string_lossy().into_owned())
}

fn registry_reference_tag_or_digest(parsed: &crate::registry::Reference) -> &str {
    parsed
        .digest
        .as_deref()
        .or(parsed.tag.as_deref())
        .unwrap_or("latest")
}

fn resolve_create_resources(
    req: &CreateMachineRequest,
    manifest_cpus: u8,
    manifest_mem: u32,
) -> (u8, u32) {
    (
        req.cpus.unwrap_or(manifest_cpus),
        req.mem.unwrap_or(manifest_mem),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SmolvmDb;
    use tempfile::TempDir;

    #[test]
    fn classify_launch_error_flags_virtio_port_conflict() {
        // The real virtio-net host-port bind failure → retryable PortConflict.
        let e = "agent operation failed: configure virtio-net: failed to start virtio network \
                 runtime: Address already in use (os error 98)"
            .to_string();
        assert!(matches!(
            classify_launch_error(e),
            ApiError::PortConflict(_)
        ));
    }

    #[test]
    fn classify_launch_error_keeps_others_internal() {
        // An unrelated AddrInUse (no virtio context) must NOT be treated as a
        // published-port conflict — reallocating a port wouldn't help.
        assert!(matches!(
            classify_launch_error("bind vsock: Address already in use".to_string()),
            ApiError::Internal(_)
        ));
        // A generic boot failure stays a 500.
        assert!(matches!(
            classify_launch_error("failed to start machine: kernel panic".to_string()),
            ApiError::Internal(_)
        ));
    }

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
        assert!(info.created_at > 0);
    }

    #[test]
    fn test_record_to_info_with_network() {
        let record = VmRecord::new("network-vm".to_string(), 1, 512, vec![], vec![], true);

        let info = record_to_info("network-vm", &record);

        assert_eq!(info.name, "network-vm");
        assert!(info.network);
    }

    #[test]
    fn test_record_to_info_echoes_backend_and_cidrs() {
        let mut record = VmRecord::new("policy-vm".to_string(), 1, 512, vec![], vec![], true);
        record.network_backend = Some(crate::network::NetworkBackend::VirtioNet);
        record.allowed_cidrs = Some(vec!["10.0.0.0/8".to_string()]);

        let info = record_to_info("policy-vm", &record);

        assert_eq!(
            info.network_backend,
            Some(crate::network::NetworkBackend::VirtioNet)
        );
        assert_eq!(
            info.allowed_cidrs.as_deref(),
            Some(["10.0.0.0/8".to_string()].as_slice())
        );

        // Unset config stays absent so the JSON omits the fields entirely.
        let bare = VmRecord::new("bare-vm".to_string(), 1, 512, vec![], vec![], false);
        let bare_info = record_to_info("bare-vm", &bare);
        assert!(bare_info.network_backend.is_none());
        assert!(bare_info.allowed_cidrs.is_none());
    }

    #[test]
    fn registry_reference_uses_digest_before_tag_or_latest() {
        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let digest_ref =
            crate::registry::Reference::parse(&format!("python-dev@{digest}")).unwrap();
        assert_eq!(registry_reference_tag_or_digest(&digest_ref), digest);

        let tagged_ref = crate::registry::Reference::parse("python-dev:v1").unwrap();
        assert_eq!(registry_reference_tag_or_digest(&tagged_ref), "v1");

        let latest_ref = crate::registry::Reference::parse("python-dev").unwrap();
        assert_eq!(registry_reference_tag_or_digest(&latest_ref), "latest");
    }

    fn minimal_create_request() -> CreateMachineRequest {
        CreateMachineRequest {
            name: Some("test-vm".to_string()),
            cpus: None,
            mem: None,
            mounts: vec![],
            ports: vec![],
            network: false,
            gpu: false,
            storage_gb: None,
            overlay_gb: None,
            allowed_cidrs: None,
            network_backend: None,
            restart: None,
            image: None,
            from: None,
            registry_ref: None,
            registry_identity_token: None,
            secrets: Default::default(),
        }
    }

    #[test]
    fn create_resources_use_high_defaults_when_omitted() {
        let req = minimal_create_request();

        assert_eq!(
            resolve_create_resources(
                &req,
                crate::data::resources::DEFAULT_MICROVM_CPU_COUNT,
                crate::data::resources::DEFAULT_MICROVM_MEMORY_MIB,
            ),
            (
                crate::data::resources::DEFAULT_MICROVM_CPU_COUNT,
                crate::data::resources::DEFAULT_MICROVM_MEMORY_MIB,
            )
        );
    }

    #[test]
    fn create_resources_preserve_manifest_defaults_when_omitted() {
        let req = minimal_create_request();

        assert_eq!(resolve_create_resources(&req, 6, 12_288), (6, 12_288));
    }

    #[test]
    fn create_resources_explicit_api_values_override_manifest_defaults() {
        let mut req = minimal_create_request();
        req.cpus = Some(2);
        req.mem = Some(2048);

        assert_eq!(resolve_create_resources(&req, 6, 12_288), (2, 2048));
    }

    #[test]
    fn create_request_deserialization_keeps_resource_omission_distinct() {
        let req: CreateMachineRequest = serde_json::from_value(serde_json::json!({
            "name": "api-vm"
        }))
        .unwrap();

        assert_eq!(req.cpus, None);
        assert_eq!(req.mem, None);

        let req: CreateMachineRequest = serde_json::from_value(serde_json::json!({
            "name": "api-vm",
            "cpus": 2,
            "memoryMb": 2048
        }))
        .unwrap();

        assert_eq!(req.cpus, Some(2));
        assert_eq!(req.mem, Some(2048));
    }

    /// Helper to create a test database and API state.
    #[allow(dead_code)]
    fn setup_test_state() -> (TempDir, Arc<ApiState>) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let db_path = dir.path().join("test.db");
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
