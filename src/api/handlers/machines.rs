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
    extract::{Path, Query, State},
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
    ApiErrorResponse, CreateMachineRequest, DeleteResponse, EnvVar, ExecResponse, ExportRequest,
    ExportResponse, ForkRequest, ListMachinesResponse, MachineExecRequest, MachineInfo, MountInfo,
    MountSpec, PortSpec, ResizeMachineRequest, ResourceSpec, StartMachineQuery,
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
        allowed_hosts: record.dns_filter_hosts.clone(),
        // Report the RESOLVED provisioned disk sizes, not the request echo: a
        // machine created without an explicit size still gets a real disk at the
        // node default, and billing/telemetry need the actual allocated GiB, not
        // `None`. `open_or_create` provisions every VM a storage disk at
        // `DEFAULT_STORAGE_SIZE_GIB` (and an overlay at `DEFAULT_OVERLAY_SIZE_GIB`)
        // when unset.
        storage_gb: Some(record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB)),
        overlay_gb: Some(record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB)),
        // Cumulative egress, read from the per-VM telemetry file the subprocess
        // flushes. Surfaced here so the control plane reads it from the machine
        // list exactly like disk size — no bespoke endpoint.
        egress_bytes: crate::agent::read_egress_telemetry(name),
        // Live consumed CPU-seconds for the VMM child, sampled from the host
        // (user+system CPU time). Resets on restart — the control plane treats it
        // as a monotonic-with-resets counter and accumulates the durable total.
        // `None` when stopped (pid cleared) or the process vanished mid-sample.
        cpu_seconds: pid
            .and_then(crate::process::process_stats)
            .map(|s| s.cpu_time_ns / 1_000_000_000),
        // Same consumed CPU in milliseconds — sub-second precision so consumers
        // don't quantize a barely-busy process up to a whole second.
        cpu_millis: pid
            .and_then(crate::process::process_stats)
            .map(|s| s.cpu_time_ns / 1_000_000),
        // Current RSS (MiB) of the VMM process — an instantaneous gauge the
        // control plane integrates over time for active-memory billing.
        rss_mb: pid
            .and_then(crate::process::process_stats)
            .map(|s| s.rss_bytes / (1024 * 1024)),
        // Actual used disk (sparse-image blocks) — a gauge for active-disk billing,
        // measured from the data dir regardless of whether the VMM is running.
        disk_used_mb: crate::agent::disk_used_mb(name),
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
        resources: ResourceSpec {
            // VmResources carries no hostname allow-list, so graft it back from the
            // record — otherwise a reloaded machine would silently lose allowed_hosts.
            allowed_hosts: record.dns_filter_hosts.clone(),
            ..vm_resources_to_spec(record.vm_resources())
        },
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
/// `graceful`: when true (stop), give the guest a SIGTERM grace period to flush
/// to its persistent overlay before SIGKILL. When false (delete), the machine's
/// disks are discarded immediately after, so there is nothing to flush — SIGKILL
/// at once instead of waiting out the guest's graceful shutdown (the bulk of the
/// ~1.9s DELETE latency on metal).
fn shutdown_machine_process(
    name: &str,
    pid: Option<i32>,
    pid_start_time: Option<u64>,
    graceful: bool,
) -> bool {
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
            // On delete the disks are removed right after, so skip the SIGTERM
            // grace and SIGKILL immediately (ZERO grace). On stop keep the grace
            // so the guest can flush to its persistent overlay first.
            let sigterm = if graceful {
                VM_SIGTERM_TIMEOUT
            } else {
                Duration::ZERO
            };
            let _ = stop_vm_process(pid, sigterm, VM_SIGKILL_TIMEOUT);
        } else {
            tracing::debug!(pid, name, "PID already dead");
        }

        // Post-check: verify the process is actually gone. If it outlived the
        // pid-targeted SIGKILL (or the recorded pid is wrong), fall back to
        // killing the systemd transient scope — its cgroup owns every process the
        // VM spawned — then wait briefly for the SIGKILL to land. Only give up if
        // STILL alive.
        if is_alive(pid) {
            let _ = crate::systemd_scope::kill_scope(name);
            for _ in 0..10 {
                if !is_alive(pid) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            if is_alive(pid) {
                tracing::warn!(pid, name, "process still alive after shutdown + scope kill");
                return false;
            }
        }
    } else {
        // No recorded pid — the pid-based kill can't run at all, which is exactly
        // how a stuck/crash-looping VM becomes an un-deletable orphan (delete 500s
        // "still alive; not removing" while the node keeps running the VM). Kill
        // the transient scope's cgroup directly and confirm via vsock that the VM
        // is actually gone.
        let _ = crate::systemd_scope::kill_scope(name);
        for _ in 0..10 {
            let reachable = manager
                .as_ref()
                .and_then(|m| AgentClient::connect(m.vsock_socket()).ok())
                .map(|mut c| c.ping().is_ok())
                .unwrap_or(false);
            if !reachable {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        tracing::warn!(
            name,
            "VM still reachable via vsock after scope kill; no PID to signal"
        );
        return false;
    }

    true
}

/// Disks to restore for a VM-mode (`--from-vm`) pack. Unlike an image pack (OCI
/// layers), a VM-mode `.smolmachine` carries the source VM's overlay + storage
/// DISKS — the actual rootfs (`/bin/sh`, files written before packing). They must
/// be seeded onto the new machine's disks or it boots with only the bare
/// agent-rootfs. `pack run` does this; the API create path must too.
struct VmModeSeed {
    overlay_template: Option<String>,
    storage_template: Option<String>,
    /// Original (pre-truncation) virtual size of the overlay disk. The packed
    /// template has its trailing zero extent stripped, so the disk must be
    /// ftruncated back to this before boot or it isn't a valid full filesystem.
    overlay_logical_size: Option<u64>,
    /// Requested disk sizes (GiB) from the create request, honored as a lower
    /// bound on the seeded disks (the guest grows the inherited fs with resize2fs).
    storage_gb: Option<u64>,
    overlay_gb: Option<u64>,
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
        vm_seed,
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
        // Reject a cross-architecture artifact up front (400, not a mid-boot 500):
        // a packed VM/image carries native binaries that cannot run under a
        // different-arch guest kernel. Guest arch must match; host OS need not.
        crate::platform::ensure_artifact_arch_matches_host(&manifest.platform)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
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
        // VM-mode packs carry disks, not layers — capture the templates so the
        // machine's overlay/storage disks can be seeded from them below.
        let vm_seed = if manifest.mode == smolvm_pack::format::PackMode::Vm {
            Some(VmModeSeed {
                overlay_template: manifest
                    .assets
                    .overlay_template
                    .as_ref()
                    .map(|t| t.path.clone()),
                storage_template: manifest
                    .assets
                    .storage_template
                    .as_ref()
                    .map(|t| t.path.clone()),
                overlay_logical_size: manifest.assets.overlay_logical_size,
                storage_gb: req.storage_gb,
                overlay_gb: req.overlay_gb,
            })
        } else {
            None
        };
        // A VM-mode pack is NOT a container/image machine: its `image` is the
        // synthetic `vm://<name>` label, not a pullable ref. `record.image.is_some()`
        // is the universal "container machine" signal (exec routing, workload
        // launch, pull-on-start, re-pack), so storing the vm:// label would make
        // exec run `crun` over a nonexistent image instead of `vm_exec` in the VM
        // (the /bin/sh-not-found bug). Store None so every consumer treats it as a
        // VM; provenance lives in `source_smolmachine`.
        let image = if vm_seed.is_some() {
            None
        } else {
            Some(manifest.image)
        };
        (
            image,
            Some(canonical),
            manifest.entrypoint,
            manifest.cmd,
            env_parsed,
            manifest.workdir,
            manifest.cpus,
            manifest.mem,
            manifest.network,
            manifest.secret_refs,
            vm_seed,
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
            None,
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
                let footer = smolvm_pack::packer::read_footer_from_sidecar(path)
                    .map_err(|e| ApiError::internal(format!("read sidecar footer: {}", e)))?;
                if smolvm_pack::extract::shared_extract_enabled() {
                    // Shared content-addressed store: extract the build-constant
                    // pack ONCE per node into `_shared/<checksum>` (root-owned,
                    // read-only) instead of a private per-machine copy, and drop a
                    // pointer beside this machine. The per-machine `pack` dir is
                    // left an empty mountpoint that the boot path idmap-binds the
                    // shared copy onto (mapping on-disk uid 0 -> the VM's dropped
                    // uid), so a 28.6 MB / 362-file agent-rootfs decodes once per
                    // node rather than once per machine — the cold-start tax this
                    // removes — with the per-VM uid isolation (#456) preserved.
                    let shared_root = crate::agent::shared_pack_cache_root();
                    let shared_dir = smolvm_pack::extract::extract_sidecar_shared(
                        path,
                        &shared_root,
                        &footer,
                        false,
                    )
                    .map_err(|e| ApiError::internal(format!("extract sidecar (shared): {}", e)))?;
                    std::fs::create_dir_all(&cache_dir).map_err(|e| {
                        ApiError::internal(format!("create pack mountpoint: {}", e))
                    })?;
                    let pointer = crate::agent::shared_pack_pointer_path(&cache_dir);
                    std::fs::write(&pointer, shared_dir.to_string_lossy().as_bytes()).map_err(
                        |e| ApiError::internal(format!("write shared pack pointer: {}", e)),
                    )?;
                    Ok(())
                } else {
                    // Per-machine extraction: macOS case-sensitive layers volume
                    // (owned 1:1 by the machine), or the `SMOLVM_DISABLE_SHARED_EXTRACT`
                    // kill-switch. Wipe any prior cache first for a clean slate.
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
                    smolvm_pack::extract::extract_sidecar(path, &cache_dir, &footer, false, false)
                        .map_err(|e| ApiError::internal(format!("extract sidecar: {}", e)))
                }
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

    // VM-mode pack: seed this machine's overlay + storage disks from the packed
    // templates (extracted above) so a start boots the source VM's rootfs rather
    // than the bare agent-rootfs (the /bin/sh-missing bug). `open_or_create_at`
    // reuses an existing disk, so seeding once at create persists across starts.
    // Mirrors `pack_run`'s VM-mode disk restore (`setup_vm_overlay` +
    // `create_or_copy_storage_disk`).
    if let Some(seed) = vm_seed {
        let name2 = name.clone();
        let disk_dir = manager
            .storage_path()
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| vm_data_dir(&name));
        let seed_result = tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
            let cache_dir = crate::agent::machine_layers_cache_dir(&name2);
            // With the shared store, the pack contents live in `_shared/<checksum>`
            // (the per-machine `pack` dir is an empty mountpoint), so seed the
            // VM-mode disk templates from the shared copy. Falls back to the
            // per-machine dir when no pointer was written (macOS / kill-switch).
            let pack_content_dir =
                crate::agent::read_shared_pack_pointer(&cache_dir).unwrap_or(cache_dir);
            crate::storage::seed_vm_mode_disks(
                &disk_dir,
                &pack_content_dir,
                seed.overlay_template.as_deref(),
                seed.storage_template.as_deref(),
                seed.overlay_logical_size,
                seed.overlay_gb,
                seed.storage_gb,
            )
            .map_err(|e| ApiError::internal(format!("seed VM-mode disks: {}", e)))
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;
        // On failure roll back the data dir the manager created, so a retry starts
        // clean (the reservation guard releases the name but leaves the dir).
        if let Err(e) = seed_result {
            let _ = std::fs::remove_dir_all(vm_data_dir(&name));
            return Err(e);
        }
    }

    let resources = ResourceSpec {
        cpus: Some(cpus),
        memory_mb: Some(mem),
        network: Some(network),
        gpu: Some(req.gpu),
        storage_gb: req.storage_gb,
        overlay_gb: req.overlay_gb,
        allowed_cidrs: req.allowed_cidrs.clone(),
        allowed_hosts: req.allowed_hosts.clone(),
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

    // Fetch the persisted record for the response (off the reactor).
    let record = state
        .lookup_vm(&name)
        .await?
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
    // Read off the reactor: an inline synchronous `list_vms()` here let a stalled
    // write park the worker pool and wedge the liveness probes (this is the path
    // the control plane polls every reconcile). See tests/reactor_wedge.rs.
    let vms = state.list_vm_records().await?;
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
    let record = state
        .lookup_vm(&name)
        .await?
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
        ("name" = String, Path, description = "Machine name"),
        ("forkable" = Option<bool>, Query, description = "Start as a fork base (memfd RAM + control socket)")
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
    Query(query): Query<StartMachineQuery>,
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

    // Get VM record from database (off the reactor)
    let record = state
        .lookup_vm(&name)
        .await?
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
    let source_smolmachine = record.source_smolmachine.clone();
    let dns_filter_hosts = record.dns_filter_hosts.clone();
    let forkable = query.forkable;
    let (manager, pid) = tokio::task::spawn_blocking(move || {
        let manager = AgentManager::for_vm_with_sizes(&name_clone, storage_gb, overlay_gb)
            .map_err(|e| format!("failed to create agent manager: {}", e))?;

        // Wire pre-extracted layers if this machine was created from a .smolmachine.
        let mut features = crate::api::state::build_launch_features(
            Some(&name_clone),
            source_smolmachine.as_deref(),
            dns_filter_hosts,
        )
        .map_err(|e| format!("failed to prepare packed layers: {}", e))?;
        // Forkable start: memfd-back guest RAM and expose a control socket at the
        // machine's known path so it can later be forked via the fork endpoint.
        if forkable {
            features.forkable = true;
            features.control_socket = Some(crate::agent::fork::control_socket_path(&name_clone));
        }
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

    // Persist state to database (off the reactor)
    let record = state
        .update_vm(&name, move |r| {
            r.state = RecordState::Running;
            r.pid = pid;
            r.pid_start_time = pid_start_time;
        })
        .await?
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

/// Classify a fork-preparation failure into the right HTTP status. The golden
/// missing is a 404; the golden not being forkable / not yet ready, or the clone
/// name already being taken, is a 409; a nested-fork request is a 400; anything
/// else is a 500.
fn classify_fork_error(e: SmolvmError) -> ApiError {
    let msg = e.to_string();
    let lc = msg.to_ascii_lowercase();
    if lc.contains("nested fork") {
        ApiError::BadRequest(msg)
    } else if lc.contains("already exists")
        || lc.contains("not running forkable")
        || lc.contains("control socket not responding")
        || lc.contains("not ready to fork")
    {
        // Clone name taken, or the golden isn't a ready fork base — both 409.
        ApiError::Conflict(msg)
    } else if lc.contains("not found") {
        ApiError::NotFound(msg)
    } else {
        ApiError::Internal(msg)
    }
}

/// Fork a running, forkable golden machine into a new clone (copy-on-write
/// memory + disks).
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/fork",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Golden (source) machine name")
    ),
    request_body = ForkRequest,
    responses(
        (status = 200, description = "Clone forked and running", body = MachineInfo),
        (status = 400, description = "Invalid request (e.g. nested fork)", body = ApiErrorResponse),
        (status = 404, description = "Golden machine not found", body = ApiErrorResponse),
        (status = 409, description = "Golden not forkable, or clone name already exists", body = ApiErrorResponse),
        (status = 500, description = "Fork failed", body = ApiErrorResponse)
    )
)]
pub async fn fork_machine(
    State(state): State<Arc<ApiState>>,
    Path(golden): Path<String>,
    Json(req): Json<ForkRequest>,
) -> Result<Json<MachineInfo>, ApiError> {
    let clone = req.name.clone();
    let pinned_ports: Vec<(u16, u16)> = req.ports.iter().map(|p| (p.host, p.guest)).collect();

    // Serialize lifecycle on the CLONE name so a concurrent start/stop/delete of
    // the same clone can't race the fork's register + boot. The golden is only
    // read + frozen via its control socket, which tolerates concurrent forks.
    let lifecycle = state.lifecycle_lock(&clone);
    let _guard = lifecycle.lock().await;

    // Phase 1: freeze + snapshot the golden, register the clone with CoW disks.
    // This is unix-socket IO + disk work, so it runs on the blocking pool. Its
    // failures carry precondition semantics (404/409/400), mapped distinctly
    // from the boot failures below.
    let prep = {
        let db = state.db().clone();
        let golden_b = golden.clone();
        let clone_b = clone.clone();
        let ports = pinned_ports.clone();
        tokio::task::spawn_blocking(move || {
            crate::agent::fork::prepare_fork(
                &db, &golden_b, &clone_b, &ports, /* clone_forkable */ false,
            )
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
        .map_err(classify_fork_error)?
    };

    // Phase 2: boot the clone from the golden's in-memory snapshot (warm — its
    // processes are already running in the restored RAM, so unlike a cold start
    // there is no image workload to launch), then rejuvenate its identity.
    let clone_b = clone.clone();
    let db = state.db().clone();
    let (manager, pid, clone_record) = tokio::task::spawn_blocking(move || {
        let record = prep.clone_record;
        let mounts = record.host_mounts();
        let ports = record.port_mappings();
        let resources = record.vm_resources();

        let manager =
            AgentManager::for_vm_with_sizes(&clone_b, record.storage_gb, record.overlay_gb)
                .map_err(|e| format!("failed to create agent manager: {}", e))?;

        let mut features = crate::api::state::build_launch_features(
            Some(&clone_b),
            record.source_smolmachine.as_deref(),
            record.dns_filter_hosts.clone(),
        )
        .map_err(|e| format!("failed to prepare packed layers: {}", e))?;
        // Boot from the golden's snapshot instead of cold-booting.
        features.snapshot_dir = Some(prep.snapshot_dir);

        if let Err(e) = manager.ensure_running_via_subprocess(mounts, ports, resources, features) {
            // Boot failed: roll back the clone registration so a failed fork
            // leaves nothing half-created.
            let _ = db.remove_vm(&clone_b);
            let _ = std::fs::remove_dir_all(vm_data_dir(&clone_b));
            return Err(format!("failed to boot clone: {}", e));
        }

        // Give the clone a fresh on-disk identity (hostname, machine-id, SSH
        // host keys, RNG) so it does not carry the golden's per-machine secrets
        // into a (possibly different) tenant. FAIL-CLOSED: if the reset can't be
        // confirmed, tear the booted clone down and fail the fork rather than
        // vend a clone that impersonates the golden.
        crate::agent::fork::fail_closed_on_rejuvenation(
            crate::agent::fork::rejuvenate_clone(&clone_b),
            || {
                manager.kill();
                manager.cleanup_data_dir();
                let _ = db.remove_vm(&clone_b);
            },
        )
        .map_err(|e| format!("clone identity rejuvenation failed: {}", e))?;

        let pid = manager.child_pid();
        Ok::<_, String>((manager, pid, record))
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
    .map_err(classify_launch_error)?;

    // Register the clone so exec/run endpoints can reach it.
    state.insert_machine(&clone, machine_entry_from_record(&clone_record, manager));

    // Persist the running state.
    let pid_start_time = pid.and_then(process_start_time);
    let record = state
        .update_vm(&clone, move |r| {
            r.state = RecordState::Running;
            r.pid = pid;
            r.pid_start_time = pid_start_time;
        })
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "clone '{}' disappeared from database during fork",
                clone
            ))
        })?;

    let mut info = record_to_info(&clone, &record);
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

    // Get VM record from database (off the reactor)
    let record = state
        .lookup_vm(&name)
        .await?
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
                    shutdown_machine_process(&name_clone, pid, pid_start_time, true)
                }
            }
        } else {
            shutdown_machine_process(&name_clone, pid, pid_start_time, true)
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
    let record = state
        .update_vm(&name, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        })
        .await?
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
    let running: Vec<(String, Option<i32>, Option<u64>)> = match state.list_vm_records().await {
        Ok(vms) => vms
            .into_iter()
            .filter(|(_, r)| r.actual_state() == RecordState::Running && r.is_process_alive())
            .map(|(name, r)| (name, r.pid, r.pid_start_time))
            .collect(),
        Err(e) => {
            tracing::error!(error = ?e, "drain: failed to list machines");
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
                via_manager || shutdown_machine_process(&name_for_kill, pid, pid_start_time, true)
            })
            .await
            .unwrap_or(false);
            if let Ok(entry) = state.get_machine(&name) {
                entry.lock().manager.mark_stopped();
            }
            let _ = state
                .update_vm(&name, |r| {
                    r.state = RecordState::Stopped;
                    r.pid = None;
                    r.pid_start_time = None;
                })
                .await;
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

    // Check if VM exists and get its state (off the reactor)
    let record = state
        .lookup_vm(&name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Get PID and start time from database record
    let pid = record.pid;
    let pid_start_time = record.pid_start_time;

    // Stop if running (in blocking task)
    let name_clone = name.clone();
    let stopped = tokio::task::spawn_blocking(move || {
        let ok = shutdown_machine_process(&name_clone, pid, pid_start_time, false);
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

    // Remove from registry (in-memory + database) in a blocking task: the DB
    // delete is synchronous disk I/O and must not run on an async worker thread,
    // where it would starve the small per-node reactor under delete churn.
    let state_rm = state.clone();
    let name_rm = name.clone();
    tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
        match state_rm.remove_machine(&name_rm) {
            Ok(_) => Ok(()),
            Err(ApiError::NotFound(_)) => {
                // Machine exists in DB but not in registry (startup recovery case).
                // Remove directly from DB.
                let removed = state_rm
                    .db()
                    .remove_vm(&name_rm)
                    .map_err(ApiError::database)?;
                if removed.is_none() {
                    return Err(ApiError::NotFound(format!(
                        "machine '{}' not found",
                        name_rm
                    )));
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))??;

    // Remove VM data directory (disk images, sockets, etc.)
    let data_dir = vm_data_dir(&name);
    if data_dir.exists() {
        // Release this VM's per-VM uid (if any) back to the allocator before the
        // dir holding its `.vm-uid` record is removed, so a high-churn cloud node
        // doesn't leak the uid range. A fork clone has no uid of its own (it
        // shares its golden's). See process::free_vm_uid.
        crate::process::free_vm_uid(&crate::agent::vm_uid_registry_dir(), &data_dir);
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
    let record = state
        .lookup_vm(&name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

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

    let (storage_gb, overlay_gb) = (req.storage_gb, req.overlay_gb);
    let record = state
        .update_vm(&name, move |r| {
            if let Some(s) = storage_gb {
                r.storage_gb = Some(s);
            }
            if let Some(o) = overlay_gb {
                r.overlay_gb = Some(o);
            }
        })
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("machine '{}' disappeared during resize", name))
        })?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Export a stopped machine to a `.smolmachine` and push it directly to a
/// registry.
///
/// The machine must be stopped: exporting a running VM would snapshot an
/// inconsistent overlay. The `.smolmachine` is produced by subprocessing this
/// same binary's `pack create --from-vm <name>` (the tested path that boots a
/// helper VM to export the container overlay), then streamed to the registry
/// with the control-plane-minted, pre-scoped OCI bearer.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/export",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    request_body = ExportRequest,
    responses(
        (status = 200, description = "Machine exported and pushed", body = ExportResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine is not stopped", body = ApiErrorResponse),
        (status = 500, description = "Export or push failed", body = ApiErrorResponse)
    )
)]
pub async fn export_machine(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    // Resolve the machine record; the path id is the machine name in this API.
    let record = state
        .lookup_vm(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", id)))?;
    let name = id;

    // Require STOPPED via the shared probe so a running VM (whose overlay is
    // still being written) can't be snapshotted into an inconsistent image.
    let name_probe = name.clone();
    let record_probe = record.clone();
    let resolved =
        tokio::task::spawn_blocking(move || resolve_machine_state(&name_probe, &record_probe))
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;
    if resolved != RecordState::Stopped {
        return Err(ApiError::Conflict(
            "machine must be stopped to export".to_string(),
        ));
    }

    // Build the .smolmachine by subprocessing this binary's tested export path.
    // The serve handlers and the pack CLI share the same on-disk SmolvmDb, so
    // `pack create --from-vm <name>` sees the serve-managed machine.
    let tmp = tempfile::Builder::new()
        .suffix(".smolmachine")
        .tempfile()
        .map_err(|e| ApiError::internal(format!("create temp file: {}", e)))?;
    let tmp_path = tmp.path().to_path_buf();
    let exe =
        std::env::current_exe().map_err(|e| ApiError::internal(format!("current_exe: {}", e)))?;

    let output = tokio::process::Command::new(&exe)
        .args([
            "pack",
            "create",
            "--from-vm",
            &name,
            "-o",
            &tmp_path.to_string_lossy(),
        ])
        .output()
        .await
        .map_err(|e| ApiError::internal(format!("spawn pack export: {}", e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::internal(format!(
            "pack export failed: {}",
            stderr
        )));
    }

    // Read back the PackManifest from the sidecar footer for the response.
    let manifest = smolvm_pack::read_manifest_from_sidecar(&tmp_path)
        .map_err(|e| ApiError::internal(format!("read exported manifest: {}", e)))?;
    let manifest_json = serde_json::to_string(&manifest)
        .map_err(|e| ApiError::internal(format!("serialize manifest: {}", e)))?;

    // Push directly to the registry using the pre-scoped bearer token. The
    // control mints a tenant-scoped OCI bearer, so use the raw token path
    // (.with_token), not /v2/auth.
    let base_url = if smolvm_registry::is_local_registry(&req.reference_host) {
        format!("http://{}", req.reference_host)
    } else {
        format!("https://{}", req.reference_host)
    };
    let client = smolvm_registry::RegistryClient::new(base_url).with_token(req.push_token.clone());

    let result = smolvm_registry::push(&client, &req.repo, &req.tag, &tmp_path)
        .await
        .map_err(|e| ApiError::internal(format!("registry push failed: {}", e)))?;

    // tmp drops here, deleting the sidecar.
    Ok(Json(ExportResponse {
        digest: result.manifest_digest,
        size_bytes: result.layer_size,
        platform: result.platform,
        manifest: manifest_json,
    }))
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
        // A machine created without explicit disk sizes still reports the RESOLVED
        // provisioned sizes (the node default), not None — billing/telemetry need
        // the actual allocated GiB.
        assert_eq!(info.storage_gb, Some(DEFAULT_STORAGE_SIZE_GIB));
        assert_eq!(info.overlay_gb, Some(DEFAULT_OVERLAY_SIZE_GIB));
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
            allowed_hosts: None,
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
