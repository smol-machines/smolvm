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
use futures_util::StreamExt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

use crate::agent::{vm_data_dir, AgentClient, AgentManager, HostMount, PortMapping};
use crate::api::error::ApiError;
use crate::api::state::{
    vm_resources_to_spec, with_machine_client_traced, ApiState, MachineEntry, MachineRegistration,
    ReservationGuard,
};
use crate::api::types::{
    ApiErrorResponse, CreateMachineRequest, DeleteQuery, DeleteResponse, EgressEventsResponse,
    ExportRequest, ExportResponse, ForkReleaseRequest, ForkRequest, ListMachinesResponse,
    MachineInfo, MountInfo, MountSpec, PortSpec, ResizeMachineRequest, ResourceSpec,
    StartMachineQuery,
};
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
        forkable: record.forkable_on_start(),
        cuda_fork_pool_size: record.cuda_fork_pool_size,
        cuda_vram_limit_mib: record.cuda_vram_limit_mib,
        forkpoint_held: record.forkpoint_held,
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
        forkable: record.forkable_on_start(),
        cuda_fork_pool_size: record.cuda_fork_pool_size,
        cuda_vram_limit_mib: record.cuda_vram_limit_mib,
        forkpoint_held: record.forkpoint_held,
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
                if let Err(error) = crate::agent::cleanup_dead_vm_runtime(name) {
                    tracing::warn!(%name, %error, "failed to clean runtime after VM teardown");
                }
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

    if let Err(error) = crate::agent::cleanup_dead_vm_runtime(name) {
        tracing::warn!(%name, %error, "failed to clean runtime after VM teardown");
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
    /// Original virtual size of the packed persistent storage disk.
    storage_logical_size: Option<u64>,
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
        let pulled_path = pull_from_registry(
            registry_ref,
            req.registry_identity_token.as_deref(),
            &req.blob_peers,
        )
        .await?;
        req.from = Some(pulled_path);
        req.registry_ref = None;
    }

    // An `image` can also name a smolmachine pack artifact (e.g.
    // registry.smolmachines.com/library/alpine), whose single "layer" is a
    // full .smolmachine sidecar, not an OCI filesystem layer — the in-guest
    // OCI puller would unpack its multi-GiB storage.ext4 into the guest disk.
    // Probe the manifest on the host and reroute through the same from-sidecar
    // flow as `registryRef`; a failed probe falls back to the in-guest pull.
    if let Some(image) = req.image.clone() {
        let sidecar = crate::data::pack_ref::resolve_pack_ref(
            &image,
            req.registry_identity_token.as_deref(),
            &req.blob_peers,
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        if let Some(sidecar) = sidecar {
            req.from = Some(sidecar.to_string_lossy().into_owned());
            req.image = None;
        }
    }

    // `cmd`/`entrypoint` are the machine's persistent workload, launched only as
    // a container from an image or `.smolmachine` artifact (registryRef and any
    // image-pack-ref have already been folded into `from` above). Reject them on
    // an imageless machine up front — it boots the bare-agent rootfs with nothing
    // to launch them in, so silently accepting them would strand a caller whose
    // command never runs (drive an imageless machine via `exec` instead).
    validate_workload_image_source(
        req.image.is_some(),
        req.from.is_some(),
        &req.cmd,
        &req.entrypoint,
    )
    .map_err(ApiError::BadRequest)?;

    // Generate name if not provided, then validate. The on-disk layout uses
    // a hash-derived directory (see `vm_data_dir`) so name length doesn't
    // affect the socket path — only character sanity + a generous length
    // cap are needed.
    let name = req.name.clone().unwrap_or_else(generate_machine_name);
    validate_vm_name(&name, "machine name").map_err(ApiError::BadRequest)?;

    // Validate mount paths
    let host_mounts: Vec<HostMount> = req
        .mounts
        .iter()
        .map(|m| HostMount::try_from(m).map_err(|e| ApiError::BadRequest(e.to_string())))
        .collect::<Result<_, _>>()?;
    // Reject duplicate guest targets, matching the CLI (HostMount::parse) so an
    // ambiguous same-target mount is a clean 400 rather than a silent shadow.
    HostMount::ensure_unique_targets(&host_mounts)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Validate published ports, matching the CLI (which rejects these before
    // launch): port 0 is invalid for forwarding, and each host port may be
    // mapped only once — two guest ports on one host port can't both bind, so
    // reject it as a clean 400 rather than an ambiguous mid-boot bind failure.
    for p in &req.ports {
        if p.host == 0 || p.guest == 0 {
            return Err(ApiError::BadRequest(
                "port 0 is not valid for VM port forwarding".to_string(),
            ));
        }
    }
    let port_mappings: Vec<PortMapping> = req
        .ports
        .iter()
        .map(|p| PortMapping::new(p.host, p.guest))
        .collect();
    PortMapping::check_duplicates(&port_mappings).map_err(ApiError::BadRequest)?;

    // Validate and normalize egress CIDRs, matching the CLI's --allow-cidr
    // parser. Without this a malformed entry is silently dropped at launch
    // (EgressPolicy::new filter_maps unparseable CIDRs, logging only a warn to
    // the discarded boot log), leaving egress MORE restrictive than requested
    // with no error. Normalizing (bare IP -> /32) keeps the stored policy
    // identical to what the CLI persists.
    let normalized_cidrs = match &req.allowed_cidrs {
        Some(cidrs) => Some(
            cidrs
                .iter()
                .map(|c| crate::smolfile::parse_cidr(c))
                .collect::<Result<Vec<_>, _>>()
                .map_err(ApiError::BadRequest)?,
        ),
        None => None,
    };

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
                storage_logical_size: manifest.assets.storage_logical_size,
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
        // CLI-parity precedence: a request-supplied workload overrides the
        // artifact's baked (entrypoint, cmd).
        let (ep, cmd) = if req.entrypoint.is_empty() && req.cmd.is_empty() {
            (manifest.entrypoint, manifest.cmd)
        } else {
            (req.entrypoint.clone(), req.cmd.clone())
        };
        (
            image,
            Some(canonical),
            ep,
            cmd,
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
            req.entrypoint.clone(),
            req.cmd.clone(),
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
    // Reject invalid resources up front (as the CLI does at create time), so the
    // API returns a clear 400 here instead of persisting an unbootable machine
    // that only fails with a deferred 500 when it is later started.
    crate::data::resources::VmResources {
        cpus,
        memory_mib: mem,
        storage_gib: req.storage_gb,
        overlay_gib: req.overlay_gb,
        ..Default::default()
    }
    .validate()
    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
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
                    #[cfg(target_os = "linux")]
                    {
                        // Shared content-addressed store: extract the build-constant
                        // pack ONCE per node into `_shared/<checksum>` (root-owned,
                        // read-only) instead of a private per-machine copy, and drop a
                        // pointer beside this machine. The per-machine `pack` dir is
                        // left an empty mountpoint that the boot path idmap-binds the
                        // shared copy onto (mapping on-disk uid 0 -> the VM's dropped
                        // uid), so a 28.6 MB / 362-file agent-rootfs decodes once per
                        // node rather than once per machine — the cold-start tax this
                        // removes — with the per-VM uid isolation (#456) preserved.
                        crate::artifact_cache::materialize_shared_pack_lease(
                            path, &footer, &cache_dir, false,
                        )
                        .map_err(|e| {
                            ApiError::internal(format!("extract sidecar (shared): {}", e))
                        })?;
                        Ok(())
                    }
                    #[cfg(not(target_os = "linux"))]
                    unreachable!("shared pack extraction is Linux-only")
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
            let (pack_content_dir, artifact_sha256) =
                if let Some(shared_dir) = crate::agent::read_shared_pack_pointer(&cache_dir) {
                    let digest = smolvm_pack::extract::read_shared_artifact_sha256(&shared_dir)
                        .map_err(|e| {
                            ApiError::internal(format!(
                                "read shared artifact SHA-256 {}: {e}",
                                shared_dir.display()
                            ))
                        })?;
                    (shared_dir, Some(digest))
                } else {
                    (cache_dir, None)
                };
            crate::storage::seed_vm_mode_disks(
                &disk_dir,
                &pack_content_dir,
                crate::storage::VmModeDiskSeedSpec {
                    artifact_sha256: artifact_sha256.as_deref(),
                    overlay_template: seed.overlay_template.as_deref(),
                    storage_template: seed.storage_template.as_deref(),
                    overlay_logical_size: seed.overlay_logical_size,
                    storage_logical_size: seed.storage_logical_size,
                    overlay_gb: seed.overlay_gb,
                    storage_gb: seed.storage_gb,
                },
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
        cuda: Some(req.cuda || req.auto_graph),
        storage_gb: req.storage_gb,
        overlay_gb: req.overlay_gb,
        allowed_cidrs: normalized_cidrs,
        allowed_hosts: req.allowed_hosts.clone(),
        network_backend: req.network_backend,
    };

    // Validate request-body secret refs before persisting. Untrusted
    // scope rejects every source kind, so any non-empty `secrets` map on
    // the API surface is refused regardless of server binding — secrets
    // must be configured locally via the CLI.
    crate::api::handlers::validate_request_secrets(&req.secrets)?;
    crate::api::handlers::validate_request_env(&req.env)?;
    let mut workload_env = merge_request_env(env, &req.env);
    if req.auto_graph {
        crate::util::enable_cuda_auto_graph_env(&mut workload_env);
    }

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
        docker_socket: req.docker_socket,
        image,
        source_smolmachine,
        entrypoint,
        cmd,
        env: workload_env,
        workdir: req.workdir.clone().or(workdir),
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

/// Query string for `GET /machines/{name}/egress-events`.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct EgressEventsQuery {
    /// Maximum number of events to return (newest kept). Default 200.
    pub limit: Option<usize>,
}

/// List the machine's egress denials — outbound connects and sendtos its
/// egress policy refused. Empty for a machine with no policy, no denials, or
/// one that has never booted.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{name}/egress-events",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name"),
        EgressEventsQuery
    ),
    responses(
        (status = 200, description = "Egress denial events", body = EgressEventsResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse)
    )
)]
pub async fn get_machine_egress_events(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<EgressEventsQuery>,
) -> Result<Json<EgressEventsResponse>, ApiError> {
    state
        .lookup_vm(&name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    let limit = query.limit.unwrap_or(200);
    let events = crate::agent::read_egress_denials(&name, limit)
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(EgressEventsResponse { events }))
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

/// Reject `cmd`/`entrypoint` on a create request that names no image source.
///
/// A machine's `cmd`/`entrypoint` are launched only as a container workload from
/// an image or `.smolmachine` artifact (see the image-launch path in
/// [`start_machine`]). An imageless machine boots the bare-agent rootfs with
/// nothing to run them in, so accepting them silently would strand a caller whose
/// command never executes. Callers should fold `registryRef` and any pack-ref
/// into `from`/`image` before this check so only a genuinely imageless request is
/// rejected.
fn validate_workload_image_source(
    has_image: bool,
    has_from: bool,
    cmd: &[String],
    entrypoint: &[String],
) -> Result<(), String> {
    if !has_image && !has_from && (!cmd.is_empty() || !entrypoint.is_empty()) {
        return Err(
            "cmd/entrypoint require an image, from, or registryRef; an imageless \
             machine has no workload to launch them in (use exec instead)"
                .to_string(),
        );
    }
    Ok(())
}

/// Start a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/start",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name"),
        ("forkable" = Option<bool>, Query, description = "Start as a fork base (memfd RAM + control socket)"),
        ("forkPoolSize" = Option<u32>, Query, description = "Planned runnable CUDA clones; implies forkable and enables automatic VRAM budgeting"),
        ("cudaVramLimitMib" = Option<u64>, Query, description = "Optional logical VRAM limit per golden/clone session; requires forkPoolSize")
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
    // Optional: the route took only a query string before this existed, so a
    // caller that sends no body (or a non-JSON one) still starts normally.
    body: Option<Json<crate::api::types::StartMachineRequest>>,
) -> Result<Json<MachineInfo>, ApiError> {
    let registry_auth: Option<crate::registry::RegistryAuth> =
        body.and_then(|Json(b)| b.registry_auth).map(Into::into);
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
    let mut record = state
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

    if resolved == RecordState::Frozen {
        let db = state.db().clone();
        let golden = name.clone();
        let clones = tokio::task::spawn_blocking(move || db.dependent_clones(&golden))
            .await
            .map_err(|e| ApiError::internal(format!("task error: {e}")))?
            .map_err(ApiError::database)?;
        let reason = if clones.is_empty() {
            "it retains a reusable fork checkpoint; stop it before restarting, or fork it again"
                .to_string()
        } else {
            format!(
                "it is the fork base for {} live clone(s) ({}); delete the clones first",
                clones.len(),
                clones.join(", ")
            )
        };
        return Err(ApiError::Conflict(format!(
            "machine '{name}' is frozen because {reason}"
        )));
    }

    if resolved == RecordState::Unreachable {
        // Zombie: verified-kill the VMM and clear the DB record
        // before falling through to a clean fresh start. Any stale
        // in-memory registry entry gets overwritten by the
        // `insert_machine` call later in this handler. If the zombie
        // cannot be confirmed dead, refuse the start instead of
        // booting on top of it.
        let name_recover = name.clone();
        tokio::task::spawn_blocking(move || {
            crate::agent::state_probe::recover_if_unreachable(&name_recover)
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
        .map_err(|e| {
            ApiError::internal(format!(
                "machine '{name}' is unreachable and zombie cleanup failed: {e}"
            ))
        })?;
    }

    if let Some(pool_size) = query.fork_pool_size {
        if pool_size == 0 {
            return Err(ApiError::BadRequest(
                "forkPoolSize must be greater than zero".to_string(),
            ));
        }
        if !record.cuda {
            return Err(ApiError::BadRequest(
                "forkPoolSize requires a CUDA-enabled machine".to_string(),
            ));
        }
        record.cuda_fork_pool_size = Some(pool_size);
        state
            .update_vm(&name, move |r| r.cuda_fork_pool_size = Some(pool_size))
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;
    }
    if let Some(limit_mib) = query.cuda_vram_limit_mib {
        if limit_mib == 0 {
            return Err(ApiError::BadRequest(
                "cudaVramLimitMib must be greater than zero".to_string(),
            ));
        }
        if query.fork_pool_size.is_none() {
            return Err(ApiError::BadRequest(
                "cudaVramLimitMib requires forkPoolSize".to_string(),
            ));
        }
        record.cuda_vram_limit_mib = Some(limit_mib);
        state
            .update_vm(&name, move |r| r.cuda_vram_limit_mib = Some(limit_mib))
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;
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
    let record_golden = record.golden.clone();
    let cuda_fork_pool_size = record.cuda_fork_pool_size;
    let cuda_vram_limit_mib = record.cuda_vram_limit_mib;
    let forkable = query.forkable || query.fork_pool_size.is_some() || record.forkable_on_start();
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
        // A fork clone shares its golden's uid. On a cold (re)start there is no
        // snapshot path to resolve it from, so pass the golden's data dir
        // explicitly — without it the clone claims a fresh uid that cannot
        // traverse the golden's 0700 dir to open its copy-on-write disk
        // backing, and the boot dies configuring virtio-blk.
        if let Some(ref g) = record_golden {
            features.uid_share_dir = Some(crate::agent::vm_data_dir(g));
        }
        // Forkable start: memfd-back guest RAM and expose a control socket at the
        // machine's known path so it can later be forked via the fork endpoint.
        if forkable {
            features.forkable = true;
        }
        features.cuda_fork_pool_size = cuda_fork_pool_size;
        features.cuda_vram_limit_mib = cuda_vram_limit_mib;
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
        let overlay_id = crate::workload::persistent_overlay_owner(&name, record.golden.as_deref());
        // Pull the image FIRST, as a FATAL step. A pull failure — the image /
        // tag doesn't exist, is private without access, or the machine has no
        // network to reach the registry — is a permanent, user-fixable
        // condition. Failing the start here surfaces it to the control as a
        // clear 4xx and marks the machine `error`, instead of proceeding to
        // `Running` below and leaving a `started` ZOMBIE whose every exec then
        // fails (and, once billing is on, meters a machine that never worked).
        // A cached image (`query` returns Some) skips the pull, so this is a
        // no-op on the stop→restart path. Mirrors how the smolmachine source
        // fails a bad artifact at create.
        let image_pull = image.clone();
        // Caller-supplied credentials win over the node's own registry config:
        // that config is operator-level and shared by every tenant, so it can
        // never hold a customer's private-registry password. `PullOptions::auth`
        // is consulted before the config inside `pull`, so passing it here is
        // enough — and passing `None` leaves the previous behaviour untouched.
        let pull_auth = registry_auth.clone();
        let pull = with_machine_client_traced(&entry, None, move |c| {
            if c.query(&image_pull)?.is_none() {
                let mut opts = crate::agent::PullOptions::new().use_registry_config(true);
                if let Some(auth) = pull_auth {
                    opts = opts.auth(auth);
                }
                c.pull(&image_pull, opts)?;
            }
            Ok(())
        })
        .await;
        if let Err(e) = pull {
            // The agent VM booted above, but the image can't be pulled (bad or
            // private ref, or no route to the registry). The Running state + pid
            // are only persisted AFTER this block, so returning now would strand
            // the booted VM as an untracked orphan — its pid never reaches the
            // record, and a later delete then reports "process still alive after
            // shutdown; not removing" while the VM leaks. Tear the VM down so the
            // machine is left exactly like a never-started one (`created`, no live
            // process) — cleanly retryable (e.g. once a transient registry outage
            // clears) and deletable — then surface the pull failure.
            let st = pid.and_then(process_start_time);
            let name_rb = name.clone();
            tokio::task::spawn_blocking(move || {
                shutdown_machine_process(&name_rb, pid, st, false);
            })
            .await
            .ok();
            return Err(e);
        }
        // Launch the workload container. Best-effort past the pull: a transient
        // crun/overlay hiccup leaves a reachable (exec-able) VM rather than
        // failing an otherwise-pullable start — the image is already local, so a
        // retry or the health loop can bring the workload up.
        let launch = with_machine_client_traced(&entry, None, move |c| {
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
            // An explicit start re-enables supervision: clear the user-stopped
            // flag and reset the retry budget so a machine that previously
            // exhausted max_retries can be restarted and supervised again.
            r.restart.user_stopped = false;
            r.restart.restart_count = 0;
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
        || lc.contains("no memfd-backed ram")
        || lc.contains("control socket not responding")
        || lc.contains("not ready to fork")
    {
        // Clone name taken, or the golden isn't a ready fork base (never started
        // forkable, so it has no memfd-backed RAM to CoW-fork) — both 409, a
        // caller-fixable precondition, not a server fault a client should retry.
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
    fork_machine_inner(state, golden, req).await.map(Json)
}

/// Internal fork entry point shared by the HTTP handler and pool reconciler.
pub(crate) async fn fork_machine_inner(
    state: Arc<ApiState>,
    golden: String,
    req: ForkRequest,
) -> Result<MachineInfo, ApiError> {
    let clone = req.name.clone();
    let pinned_ports: Vec<(u16, u16)> = req.ports.iter().map(|p| (p.host, p.guest)).collect();
    let req_share_weights = req.share_weights;
    let req_hold = req.hold;
    let wait_ready = req.wait_ready || req_hold;
    let ready_timeout = std::time::Duration::from_secs(req.ready_timeout_secs.unwrap_or(240));
    let fork_env = crate::util::parse_env_list(&req.env);
    // Per-fork secrets become the clone's persisted secret_refs (resolved fresh
    // on each exec, never at rest) — validate them at TrustedLocal like the
    // Smolfile-declared refs they join.
    crate::api::handlers::validate_fork_secrets(&req.secrets)?;
    let fork_secrets = req.secrets.clone();
    crate::agent::fork::validate_fork_env(&fork_env)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    if clone == golden {
        return Err(ApiError::Conflict(format!(
            "clone name '{clone}' is already used by the golden"
        )));
    }

    // Validate pinned ports as the create path does: fork uses these host ports
    // as-is (no remapping), so port 0 or a duplicated host port would otherwise
    // surface only as a confusing clone-boot bind failure instead of a clean 400.
    for (h, g) in &pinned_ports {
        if *h == 0 || *g == 0 {
            return Err(ApiError::BadRequest(
                "port 0 is not valid for VM port forwarding".to_string(),
            ));
        }
    }
    {
        let mut seen = std::collections::HashSet::new();
        for (h, _) in &pinned_ports {
            if !seen.insert(*h) {
                return Err(ApiError::BadRequest(format!(
                    "duplicate host port {h}: each host port can only be mapped once"
                )));
            }
        }
    }

    // A failed clone finalization may need to roll back the golden and discard
    // the retained checkpoint that produced it. Keep that state transition in
    // one owner-level critical section so another fork/start/stop/delete cannot
    // observe the golden between failed-clone teardown and rollback.
    let golden_lifecycle = state.lifecycle_lock(&golden);
    let _golden_guard = golden_lifecycle.lock().await;

    // Reject an already-registered target before taking its lifecycle lock.
    // Besides avoiding a pointless forkpoint wait, this prevents two invalid
    // cross-forks (X -> Y and Y -> X) from each holding one golden while waiting
    // forever on the other machine's clone lock.
    if state.lookup_vm(&clone).await?.is_some() {
        return Err(ApiError::Conflict(format!(
            "machine '{clone}' already exists"
        )));
    }

    if wait_ready {
        let golden_b = golden.clone();
        tokio::task::spawn_blocking(move || {
            crate::agent::fork::wait_for_forkpoint(&golden_b, ready_timeout)
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {e}")))?
        .map_err(classify_fork_error)?;
    }

    // Serialize lifecycle on the CLONE name so a concurrent start/stop/delete of
    // the same clone can't race the fork's register + boot. Golden is always
    // acquired before clone, matching the fork-pool lock order.
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
        let env = fork_env.clone();
        let secrets = fork_secrets.clone();
        tokio::task::spawn_blocking(move || {
            if req_hold {
                crate::agent::fork::prepare_held_fork(
                    &db, &golden_b, &clone_b, &ports, &env, &secrets,
                )
            } else {
                crate::agent::fork::prepare_fork(
                    &db, &golden_b, &clone_b, &ports, /* clone_forkable */ false, &env,
                    &secrets,
                )
            }
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
        .map_err(classify_fork_error)?
    };

    let snapshot_dir = prep.snapshot_dir.clone();
    let resume_golden_on_rollback = prep.resume_golden_on_rollback;
    let result = boot_prepared_fork_inner(
        state.clone(),
        clone,
        prep,
        PreparedForkBoot {
            share_weights: req_share_weights,
            fork_env,
            wait_ready,
            hold: req_hold,
            cuda_worker_ready_timeout: None,
            boot_permit: None,
        },
    )
    .await;

    let Err(ApiError::CloneIdentityRejuvenationFailed(message)) = result else {
        return result;
    };
    if !resume_golden_on_rollback {
        return Err(ApiError::CloneIdentityRejuvenationFailed(message));
    }

    // `fail_closed_on_rejuvenation` has torn down the only clone prepared from
    // this new checkpoint. It is therefore safe to restore the initially-running
    // golden and invalidate the checkpoint before releasing its lifecycle lock.
    let db = state.db().clone();
    let golden_for_rollback = golden.clone();
    let rollback = match tokio::task::spawn_blocking(move || {
        crate::agent::fork::rollback_retained_fork_snapshot(
            &db,
            &golden_for_rollback,
            &snapshot_dir,
            true,
        )
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(SmolvmError::agent(
            "fork rollback",
            format!("task error: {error}"),
        )),
    };
    match rollback {
        Ok(()) => Err(ApiError::CloneIdentityRejuvenationFailed(message)),
        Err(rollback_error) => Err(ApiError::Internal(format!("{message}; {rollback_error}"))),
    }
}

/// Prepare several clean held workers from one golden checkpoint and boot them
/// through a bounded queue. Preparation is all-or-nothing; once booting begins,
/// each result is reported as soon as it completes so successful workers can be
/// leased while the remainder of the batch is still restoring.
pub(crate) struct ForkBatchOutcome {
    pub retained_snapshot: Option<crate::agent::fork::RetainedForkSnapshot>,
}

pub(crate) struct ForkHeldBatch {
    pub golden: String,
    pub clones: Vec<String>,
    pub share_weights: bool,
    pub ready_timeout: std::time::Duration,
    pub retained_snapshot: Option<crate::agent::fork::RetainedForkSnapshot>,
    pub boot_slots: Arc<tokio::sync::Semaphore>,
    pub snapshot_ready:
        Option<tokio::sync::oneshot::Sender<crate::agent::fork::RetainedForkSnapshot>>,
}

pub(crate) async fn fork_held_machines_inner(
    state: Arc<ApiState>,
    batch: ForkHeldBatch,
    result_tx: UnboundedSender<(String, Result<MachineInfo, ApiError>)>,
) -> Result<ForkBatchOutcome, ApiError> {
    let ForkHeldBatch {
        golden,
        clones,
        share_weights,
        ready_timeout,
        retained_snapshot,
        boot_slots,
        mut snapshot_ready,
    } = batch;
    if clones.is_empty() {
        return Ok(ForkBatchOutcome { retained_snapshot });
    }

    let golden_for_wait = golden.clone();
    tokio::task::spawn_blocking(move || {
        crate::agent::fork::wait_for_forkpoint(&golden_for_wait, ready_timeout)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {e}")))?
    .map_err(classify_fork_error)?;

    // Keep every clone lifecycle locked through registration and boot. Names are
    // sorted so this remains deadlock-free if another internal batch ever
    // overlaps it; pool-generated names are unique in normal operation.
    let mut lock_names = clones.clone();
    lock_names.sort();
    lock_names.dedup();
    let mut guards = Vec::with_capacity(lock_names.len());
    for clone in &lock_names {
        guards.push(state.lifecycle_lock(clone).lock_owned().await);
    }

    let prepared = {
        let db = state.db().clone();
        let golden_for_prep = golden.clone();
        let clones_for_prep = clones.clone();
        tokio::task::spawn_blocking(move || {
            let empty_secrets = std::collections::BTreeMap::new();
            let specs: Vec<_> = clones_for_prep
                .iter()
                .map(|clone| crate::agent::fork::ForkSpec {
                    clone,
                    pinned_ports: &[],
                    clone_forkable: false,
                    fork_env: &[],
                    fork_secrets: &empty_secrets,
                    hold: true,
                })
                .collect();
            crate::agent::fork::prepare_forks_reusing(
                &db,
                &golden_for_prep,
                &specs,
                retained_snapshot.as_ref(),
                true,
            )
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {e}")))?
        .map_err(classify_fork_error)?
    };

    let snapshot_dir = prepared.forks[0].snapshot_dir.clone();
    let resume_golden_on_rollback = prepared.forks[0].resume_golden_on_rollback;
    let snapshot_reused = prepared.snapshot_reused;
    let reusable_snapshot = prepared.retained_snapshot.clone();
    let pending_boots = prepared.forks.len();
    let boots = prepared.forks.into_iter().zip(clones).map(|(prep, clone)| {
        let state = state.clone();
        let boot_slots = boot_slots.clone();
        async move {
            let result = match boot_slots.acquire_owned().await {
                Ok(boot_permit) => {
                    boot_prepared_fork_inner(
                        state,
                        clone.clone(),
                        prep,
                        PreparedForkBoot {
                            share_weights,
                            fork_env: Vec::new(),
                            wait_ready: true,
                            hold: true,
                            cuda_worker_ready_timeout: Some(ready_timeout),
                            boot_permit: Some(boot_permit),
                        },
                    )
                    .await
                }
                Err(error) => Err(ApiError::internal(format!(
                    "fork boot scheduler closed: {error}"
                ))),
            };
            (clone, result)
        }
    });
    // Poll every boot future so an agent-ready clone can release its launch
    // permit and wait for CUDA reconstruction without blocking the next VM.
    // The semaphore, not this result stream, preserves the qualified launch
    // width; completed results are still reported as soon as each is usable.
    let any_succeeded = run_bounded_futures(boots, pending_boots, |result| {
        let succeeded = result.1.is_ok();
        if succeeded {
            if let (Some(sender), Some(snapshot)) =
                (snapshot_ready.take(), reusable_snapshot.clone())
            {
                let _ = sender.send(snapshot);
            }
        }
        if result_tx.send(result).is_err() {
            tracing::warn!("fork pool result receiver closed before provisioning completed");
        }
        succeeded
    })
    .await;

    // If every restore failed, no clone depends on this checkpoint and an
    // initially-running golden can safely resume for a later retry. A partial
    // success must retain the paused golden and shared snapshot.
    let mut rollback_completed = true;
    if !any_succeeded && !snapshot_reused {
        if resume_golden_on_rollback {
            if let Err(error) = crate::agent::fork::resume_golden(&golden, &snapshot_dir) {
                tracing::warn!(%golden, %error, "failed to resume golden after batch restore failure");
                rollback_completed = false;
            }
        }
        if rollback_completed {
            if let Err(error) = state.db().remove_retained_fork_snapshot(&golden) {
                tracing::warn!(%golden, %error, "failed to remove rolled-back fork pool checkpoint");
            }
            if let Err(error) = std::fs::remove_dir_all(&snapshot_dir) {
                tracing::warn!(path = %snapshot_dir.display(), %error, "failed to remove unused batch fork snapshot");
            }
        }
    }

    drop(guards);
    Ok(ForkBatchOutcome {
        retained_snapshot: retained_snapshot_after_boots(
            snapshot_reused,
            any_succeeded,
            rollback_completed,
            reusable_snapshot,
        ),
    })
}

fn retained_snapshot_after_boots(
    snapshot_reused: bool,
    any_succeeded: bool,
    rollback_completed: bool,
    reusable_snapshot: Option<crate::agent::fork::RetainedForkSnapshot>,
) -> Option<crate::agent::fork::RetainedForkSnapshot> {
    // A failed boot does not invalidate a checkpoint that preparation just
    // verified against the paused golden. Keep it so a transient KVM or guest
    // readiness failure cannot strand that golden without a refill path.
    (snapshot_reused || any_succeeded || !rollback_completed)
        .then_some(reusable_snapshot)
        .flatten()
}

async fn run_bounded_futures<F, T>(
    futures: impl IntoIterator<Item = F>,
    max_parallel: usize,
    mut on_complete: impl FnMut(T) -> bool,
) -> bool
where
    F: Future<Output = T>,
{
    let mut pending = futures_util::stream::iter(futures).buffer_unordered(max_parallel.max(1));
    let mut any_succeeded = false;
    while let Some(result) = pending.next().await {
        any_succeeded |= on_complete(result);
    }
    any_succeeded
}

struct PreparedForkBoot {
    share_weights: bool,
    fork_env: Vec<(String, String)>,
    wait_ready: bool,
    hold: bool,
    cuda_worker_ready_timeout: Option<std::time::Duration>,
    boot_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

enum PreparedForkBootError {
    Launch(String),
    CloneIdentityRejuvenation(String),
}

impl From<String> for PreparedForkBootError {
    fn from(message: String) -> Self {
        Self::Launch(message)
    }
}

fn classify_prepared_fork_boot_error(error: PreparedForkBootError) -> ApiError {
    match error {
        PreparedForkBootError::Launch(message) => classify_launch_error(message),
        PreparedForkBootError::CloneIdentityRejuvenation(message) => {
            ApiError::CloneIdentityRejuvenationFailed(message)
        }
    }
}

async fn boot_prepared_fork_inner(
    state: Arc<ApiState>,
    clone: String,
    prep: crate::agent::fork::PreparedFork,
    boot: PreparedForkBoot,
) -> Result<MachineInfo, ApiError> {
    let PreparedForkBoot {
        share_weights,
        fork_env,
        wait_ready,
        hold,
        cuda_worker_ready_timeout,
        mut boot_permit,
    } = boot;
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
        features.cuda_share_weights = share_weights;
        features.cuda_preload_modules = record.cuda_preload_modules;
        features.cuda_fork_pool_size = record.cuda_fork_pool_size;
        features.cuda_vram_limit_mib = record.cuda_vram_limit_mib;

        if let Err(e) = manager.ensure_running_via_subprocess(mounts, ports, resources, features) {
            // Boot failed: roll back the clone registration so a failed fork
            // leaves nothing half-created.
            let _ = db.remove_vm(&clone_b);
            let _ = std::fs::remove_dir_all(vm_data_dir(&clone_b));
            return Err(format!("failed to boot clone: {}", e).into());
        }

        let pid = manager.child_pid();

        // Give the clone a fresh on-disk identity (hostname, machine-id, SSH
        // host keys, RNG) so it does not carry the golden's per-machine secrets
        // into a (possibly different) tenant. FAIL-CLOSED: if the reset can't be
        // confirmed, tear the booted clone down and fail the fork rather than
        // vend a clone that impersonates the golden.
        let teardown = || {
            manager.kill();
            manager.cleanup_data_dir();
            let _ = db.remove_vm(&clone_b);
        };
        crate::agent::fork::fail_closed_on_rejuvenation(
            crate::agent::fork::rejuvenate_clone(&clone_b, &record),
            teardown,
        )
        .map_err(|e| {
            PreparedForkBootError::CloneIdentityRejuvenation(format!(
                "clone identity rejuvenation failed: {e}"
            ))
        })?;
        // Per-fork parameters: same fail-closed contract — a clone that asked
        // for parameters but can't receive them must not be vended.
        crate::agent::fork::fail_closed_on_rejuvenation(
            crate::agent::fork::write_fork_env(&clone_b, &record, &fork_env),
            teardown,
        )
        .map_err(|e| format!("fork env delivery failed: {}", e))?;

        // Preserve the measured VM-launch bound, but do not make CUDA
        // reconstruction occupy that scarce slot. At this point the guest
        // agent and per-clone setup are complete, so another VM can safely
        // boot while this clone finishes rebuilding its isolated GPU state.
        drop(boot_permit.take());
        #[cfg(unix)]
        if record.cuda
            && cuda_worker_ready_timeout.is_some()
            && crate::cuda_daemon::clone_worker_readiness_supported()
            && std::env::var("SMOLVM_CUDA_WARM_DIAL").as_deref() != Ok("0")
        {
            let worker_ready = pid
                .and_then(|pid| process_start_time(pid).map(|started| (pid, started)))
                .ok_or_else(|| "clone process identity unavailable for CUDA readiness".to_string())
                .and_then(|(pid, started)| {
                    crate::cuda_daemon::wait_for_clone_worker_ready(
                        pid,
                        started,
                        cuda_worker_ready_timeout.expect("checked above"),
                    )
                    .map_err(|error| error.to_string())
                });
            if let Err(error) = worker_ready {
                teardown();
                return Err(format!("CUDA clone worker readiness failed: {error}").into());
            }
        }
        #[cfg(not(unix))]
        let _ = cuda_worker_ready_timeout;
        if wait_ready && !hold {
            crate::agent::fork::fail_closed_on_rejuvenation(
                crate::agent::fork::release_forkpoint(&clone_b),
                teardown,
            )
            .map_err(|e| format!("forkpoint release failed: {e}"))?;
        }

        Ok::<_, PreparedForkBootError>((manager, pid, record))
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
    .map_err(classify_prepared_fork_boot_error)?;

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
    Ok(info)
}

/// Assign job parameters and release one held fork-pool slot.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/fork-release",
    tag = "Machines",
    params(("name" = String, Path, description = "Held clone name")),
    request_body = ForkReleaseRequest,
    responses(
        (status = 200, description = "Held clone assigned and released", body = MachineInfo),
        (status = 404, description = "Clone not found", body = ApiErrorResponse),
        (status = 409, description = "Machine is not a held fork slot", body = ApiErrorResponse),
        (status = 500, description = "Activation failed", body = ApiErrorResponse)
    )
)]
pub async fn release_held_fork(
    State(state): State<Arc<ApiState>>,
    Path(clone): Path<String>,
    Json(req): Json<ForkReleaseRequest>,
) -> Result<Json<MachineInfo>, ApiError> {
    let lifecycle = state.lifecycle_lock(&clone);
    let _guard = lifecycle.lock().await;
    let db = state.db().clone();
    let clone_for_pool = clone.clone();
    let pool_slot = tokio::task::spawn_blocking(move || db.get_fork_pool_slot(&clone_for_pool))
        .await
        .map_err(|e| ApiError::internal(format!("pool ownership task failed: {e}")))?
        .map_err(ApiError::database)?;
    if let Some(slot) = pool_slot {
        return Err(ApiError::Conflict(format!(
            "machine '{clone}' is managed by fork pool '{}'; acquire it through the pool lease API",
            slot.pool_name
        )));
    }
    let record = state
        .lookup_vm(&clone)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{clone}' not found")))?;
    if record.golden.is_none() || !record.forkpoint_held {
        return Err(ApiError::Conflict(format!(
            "machine '{clone}' is not a held fork-pool slot"
        )));
    }

    let assignment = crate::util::parse_env_list(&req.env);
    crate::agent::fork::validate_fork_env(&assignment)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let merged = crate::agent::fork::merge_fork_env(&record.fork_env, &assignment);
    // Claim in durable state before publishing the guest release marker. A
    // crash can strand one slot, but can never leave a running workload marked
    // assignable and run it twice. Replenishment from the golden is the safe
    // recovery for any ambiguous activation failure.
    let assignment_for_record = assignment.clone();
    let merged_for_record = merged.clone();
    let claimed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let claimed_in_update = claimed.clone();
    let updated = state
        .update_vm(&clone, move |entry| {
            if entry.forkpoint_held {
                crate::agent::fork::record_fork_activation(
                    entry,
                    &assignment_for_record,
                    merged_for_record,
                );
                claimed_in_update.store(true, std::sync::atomic::Ordering::Release);
            }
        })
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("clone '{clone}' disappeared before activation"))
        })?;
    if !claimed.load(std::sync::atomic::Ordering::Acquire) {
        return Err(ApiError::Conflict(format!(
            "held fork-pool slot '{clone}' was already claimed"
        )));
    }
    if let Ok(entry) = state.get_machine(&clone) {
        entry.lock().forkpoint_held = false;
    }

    let clone_b = clone.clone();
    let record_b = record.clone();
    let assignment_b = assignment.clone();
    let activated = tokio::task::spawn_blocking(move || {
        crate::agent::fork::activate_held_fork(&clone_b, &record_b, &assignment_b)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {e}")))?
    .map_err(|error| {
        ApiError::Internal(format!(
            "slot '{clone}' was claimed and will not be reused after activation failed: {error}"
        ))
    })?;
    debug_assert_eq!(activated, merged);
    Ok(Json(record_to_info(&clone, &updated)))
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

    // A frozen fork base must outlive its clones: they CoW-map its guest RAM
    // (memfd) and CoW-back their disks onto its disks, so stopping it — which
    // kills the VMM and frees the memfd — corrupts every live clone. `actual_state`
    // does not resolve the on-the-fly `Frozen` state, so a golden with clones
    // looks `Running` here and would be torn down. Refuse, mirroring `delete` and
    // the CLI stop guard.
    {
        let db = state.db().clone();
        let golden = name.clone();
        let clones = tokio::task::spawn_blocking(move || db.dependent_clones(&golden))
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
            .map_err(ApiError::database)?;
        if !clones.is_empty() {
            return Err(ApiError::Conflict(format!(
                "machine '{}' is the fork base of {} live clone(s) ({}); they CoW-map its \
                 memory and disks — stop or delete the clones first",
                name,
                clones.len(),
                clones.join(", ")
            )));
        }
    }

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
            // Record the explicit stop so the restart supervisor does not
            // resurrect this machine (any policy) until an explicit start.
            r.restart.user_stopped = true;
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
                    // A drain is a deliberate decommission: mark the machine
                    // user-stopped so the restart supervisor does not resurrect it
                    // in the window before the host is terminated (or if drain is
                    // used standalone). An explicit start elsewhere clears this.
                    r.restart.user_stopped = true;
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
        ("name" = String, Path, description = "Machine name"),
        ("cascade" = Option<bool>, Query, description = "Also delete clones forked from this machine (fork base cannot be removed while its clones depend on it)")
    ),
    responses(
        (status = 200, description = "Machine deleted", body = DeleteResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine is a fork base with live clones (use cascade)", body = ApiErrorResponse),
        (status = 500, description = "Failed to delete", body = ApiErrorResponse)
    )
)]
pub async fn delete_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<DeleteResponse>, ApiError> {
    // Cascade: remove each dependent clone before the golden so its own delete
    // (below) sees no dependents. Clones are leaves (launched non-forkable), so
    // one level is exhaustive; the read is unlocked but delete_one re-checks
    // under the golden's lifecycle lock, so a clone forked in the race still
    // refuses rather than dangling.
    if query.cascade {
        let db = state.db().clone();
        let golden = name.clone();
        let clones = tokio::task::spawn_blocking(move || db.dependent_clones(&golden))
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
            .map_err(ApiError::database)?;
        for clone in clones {
            delete_one(state.clone(), clone).await?;
        }
    }
    delete_one(state, name).await.map(Json)
}

/// Delete a single machine (no cascade): stop it, remove it from the registry
/// and database, and delete its data directory. Refuses if it is a fork base
/// with live clones. Shared by [`delete_machine`] (once per golden, and once per
/// clone during a cascade).
pub(crate) async fn delete_one(
    state: Arc<ApiState>,
    name: String,
) -> Result<DeleteResponse, ApiError> {
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

    // A forked clone's block disks are copy-on-write overlays backed by this
    // machine's disks, so deleting a golden with live clones would destroy
    // their backing files (silent data loss the moment a clone re-opens its
    // disks). Refuse — mirroring the CLI `machine rm` guard.
    {
        let db = state.db().clone();
        let golden = name.clone();
        let clones = tokio::task::spawn_blocking(move || db.dependent_clones(&golden))
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
            .map_err(ApiError::database)?;
        if !clones.is_empty() {
            return Err(ApiError::Conflict(format!(
                "machine '{}' is the fork base of {} live clone(s) ({}); their disks are \
                 backed by its disks — delete the clones first",
                name,
                clones.len(),
                clones.join(", ")
            )));
        }
    }

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

    // Re-check for dependent clones now that the golden's process (and its fork
    // control socket) is down. API forks share the lifecycle lock held here, but
    // a separate CLI/embedded process has no access to that in-process lock and
    // could have registered a clone after the initial check. Abort BEFORE
    // removing the DB record or data dir — the clones' copy-on-write disks are
    // backed by this golden's disks, so removing them would be silent data loss.
    // The golden is left stopped with its disks intact; delete the clones and
    // retry.
    {
        let db = state.db().clone();
        let golden = name.clone();
        let clones = tokio::task::spawn_blocking(move || db.dependent_clones(&golden))
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
            .map_err(ApiError::database)?;
        if !clones.is_empty() {
            return Err(ApiError::Conflict(format!(
                "machine '{}' gained {} clone(s) during deletion ({}); their disks are backed by \
                 its disks — delete the clones first",
                name,
                clones.len(),
                clones.join(", ")
            )));
        }
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

    Ok(DeleteResponse { deleted: name })
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
    // Serialize against start/stop/delete/clone on the same machine: resize
    // reads the state, then grows the disk files and rewrites the record. Without
    // the per-machine lifecycle lock a concurrent start could boot the VM between
    // our "must be stopped" check and the on-disk expansion (and race the record
    // update), so hold the lock across the whole operation as the other lifecycle
    // handlers do — the state check below is only meaningful under it.
    let lifecycle = state.lifecycle_lock(&name);
    let _guard = lifecycle.lock().await;

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

    // A fork base's disks are the copy-on-write backing for its clones' disks, so
    // growing them corrupts the clones. The state check above is not enough: a
    // golden whose VMM has died (e.g. after a host reboot) resolves to Stopped
    // while its clones still depend on it, so `actual_state` would pass. Refuse
    // explicitly, mirroring delete/stop and the CLI resize guard.
    {
        let db = state.db().clone();
        let golden = name.clone();
        let clones = tokio::task::spawn_blocking(move || db.dependent_clones(&golden))
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
            .map_err(ApiError::database)?;
        if !clones.is_empty() {
            return Err(ApiError::Conflict(format!(
                "machine '{}' is the fork base of {} live clone(s) ({}); their disks are backed \
                 by its disks — delete the clones first",
                name,
                clones.len(),
                clones.join(", ")
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

/// Where the export subprocess writes its executable stub. `pack create -o X` derives the
/// real artifact as `X.smolmachine`, so this must NOT already end in that extension or the
/// CLI rejects it outright.
fn export_stub_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("export")
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
    // Hold the per-machine lifecycle lock across BOTH the stopped-check and the
    // pack export below so a concurrent start cannot boot the VM in between and
    // leave `pack create --from-vm` reading disks that are being written — the
    // inconsistent-snapshot race the stopped-check alone can't close (start
    // acquires this same lock). Mirrors start/stop/delete/resize.
    let lifecycle = state.lifecycle_lock(&id);
    let _guard = lifecycle.lock().await;

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
    // `pack create -o X` names the executable STUB and derives the sidecar as
    // X.smolmachine, rejecting an `-o` that already carries that extension. Stage both
    // inside a temp dir so the sidecar is cleaned up with the stub rather than left behind.
    let tmp_dir =
        tempfile::tempdir().map_err(|e| ApiError::internal(format!("create temp dir: {}", e)))?;
    let tmp_path = export_stub_path(tmp_dir.path());
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

    // `pack create -o X` emits an executable stub at X and the actual pack data
    // at X.smolmachine (the sidecar carrying the SMOLPACK footer). The manifest
    // and the pushed blob must come from the SIDECAR — reading the stub fails
    // with "invalid magic". Resolve it exactly like `smol pack push` does, with
    // the pre-sidecar single-file layout as the fallback.
    let sidecar = smolvm_pack::sidecar_path_for(&tmp_path);
    let artifact = if sidecar.exists() {
        sidecar.clone()
    } else {
        tmp_path.clone()
    };

    // Read back the PackManifest from the sidecar footer for the response.
    let manifest = smolvm_pack::read_manifest_from_sidecar(&artifact)
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

    let result = smolvm_registry::push(&client, &req.repo, &req.tag, &artifact)
        .await
        .map_err(|e| ApiError::internal(format!("registry push failed: {}", e)))?;

    // The tempfile guard only removes the stub path; clean the sidecar too so
    // exports don't accumulate multi-GB files in /tmp.
    let _ = std::fs::remove_file(&sidecar);

    // tmp drops here, deleting the stub.
    Ok(Json(ExportResponse {
        digest: result.manifest_digest,
        size_bytes: result.layer_size,
        platform: result.platform,
        manifest: manifest_json,
    }))
}

/// True if `host` is a loopback, link-local, or private-range address — an
/// SSRF-prone pull destination on a fleet node (its own `127.0.0.1` services, the
/// cloud metadata endpoint at `169.254.169.254`, or a neighbour on the private
/// network). Hostnames that are not IP literals return false (a DNS-rebind to a
/// private address is a residual not covered here).
fn is_ssrf_prone_registry_host(host: &str) -> bool {
    // localhost / 127.0.0.0/8 / ::1 / 0.0.0.0 — reuse the registry classifier.
    if smolvm_registry::is_local_registry(host) {
        return true;
    }
    // Extract the bare host (strip IPv6 brackets and any :port), then classify it
    // only if it parses as an IP literal.
    let bare = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (first & 0xfe00) == 0xfc00 // unique-local fc00::/7
        }
        Err(_) => false,
    }
}

async fn pull_from_registry(
    registry_ref: &str,
    identity_token: Option<&str>,
    blob_peers: &[String],
) -> Result<String, ApiError> {
    let result = pull_smolmachine(registry_ref, identity_token, blob_peers).await?;
    tracing::info!(path = %result.path.display(), cached = result.cached, "pull complete");
    Ok(result.path.to_string_lossy().into_owned())
}

/// Resolve `registry_ref` and pull its `.smolmachine` layer into this node's
/// blob cache, returning the full [`smolvm_registry::PullResult`].
///
/// Split out of [`pull_from_registry`] so the pre-warm endpoint
/// ([`crate::api::handlers::prewarm`]) reaches the registry through byte-for-byte
/// the same reference parsing, mirror lookup, credential precedence, cache, and
/// peer fallback that a real create uses. A warm path that resolved references
/// even slightly differently would cache a blob under one key and leave the
/// create looking for another — a silent no-op that still looks like a success.
pub(crate) async fn pull_smolmachine(
    registry_ref: &str,
    identity_token: Option<&str>,
    blob_peers: &[String],
) -> Result<smolvm_registry::PullResult, ApiError> {
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

    // A control-plane tenant pull (identity_token present) must never target a
    // loopback/link-local/private-range host: on a fleet node that is an SSRF
    // pivot into node-local services, not a real registry. Local dev (no token)
    // is unaffected, and legitimate tenant pulls resolve public registries.
    if identity_token.is_some() && is_ssrf_prone_registry_host(api_host) {
        return Err(ApiError::BadRequest(format!(
            "registry host '{}' is a private/loopback address and is not permitted for tenant image pulls",
            api_host
        )));
    }

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

    let result = smolvm_registry::pull(&client, &repo, tag_or_digest, None, &cache, blob_peers)
        .await
        .map_err(|e| match &e {
            // A missing image/manifest is the caller's mistake (typo'd ref, or a
            // bare name that resolved to an empty repo) — surface it as 404, not a
            // 500. A 500 here misreports a client error as a server fault and
            // pollutes the fleet error-rate SLO on every bad reference.
            smolvm_registry::RegistryError::BlobNotFound(_)
            | smolvm_registry::RegistryError::ApiError { status: 404, .. } => {
                ApiError::NotFound(format!("image not found in registry: {}", e))
            }
            _ => ApiError::internal(format!("registry pull failed: {}", e)),
        })?;

    Ok(result)
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

/// Manifest env is the baseline; request env layers on top and wins on name
/// collision, so a control plane can override a packed default.
fn merge_request_env(
    manifest_env: Vec<(String, String)>,
    request_env: &[crate::api::types::EnvVar],
) -> Vec<(String, String)> {
    let mut merged = manifest_env;
    for (name, value) in crate::api::types::EnvVar::to_tuples(request_env) {
        merged.retain(|(existing, _)| existing != &name);
        merged.push((name, value));
    }
    merged
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::db::SmolvmDb;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    fn retained_snapshot() -> crate::agent::fork::RetainedForkSnapshot {
        crate::agent::fork::RetainedForkSnapshot {
            path: std::path::PathBuf::from("/golden/s/12345678"),
            golden_pid: 123,
            golden_pid_start_time: 456,
        }
    }

    #[test]
    fn failed_reused_checkpoint_remains_available_for_retry() {
        let snapshot = retained_snapshot();
        assert_eq!(
            retained_snapshot_after_boots(true, false, true, Some(snapshot.clone())),
            Some(snapshot)
        );
    }

    #[test]
    fn failed_new_checkpoint_is_not_retained() {
        assert_eq!(
            retained_snapshot_after_boots(false, false, true, Some(retained_snapshot())),
            None
        );
    }

    #[test]
    fn successful_new_checkpoint_is_retained() {
        let snapshot = retained_snapshot();
        assert_eq!(
            retained_snapshot_after_boots(false, true, true, Some(snapshot.clone())),
            Some(snapshot)
        );
    }

    #[test]
    fn failed_new_checkpoint_remains_available_when_rollback_fails() {
        let snapshot = retained_snapshot();
        assert_eq!(
            retained_snapshot_after_boots(false, false, false, Some(snapshot.clone())),
            Some(snapshot)
        );
    }

    #[tokio::test]
    async fn bounded_futures_stream_results_without_exceeding_the_limit() {
        const TOTAL: usize = 8;
        const WIDTH: usize = 4;

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (started_tx, mut started_rx) = tokio::sync::watch::channel(0usize);
        let jobs = (0..TOTAL)
            .map(|index| {
                let active = active.clone();
                let peak = peak.clone();
                let gate = gate.clone();
                let started_tx = started_tx.clone();
                async move {
                    let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now_active, Ordering::SeqCst);
                    started_tx.send_modify(|started| *started += 1);
                    let permit = gate.acquire().await.expect("test gate closed");
                    permit.forget();
                    active.fetch_sub(1, Ordering::SeqCst);
                    index
                }
            })
            .collect::<Vec<_>>();
        drop(started_tx);

        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let runner = tokio::spawn(async move {
            run_bounded_futures(jobs, WIDTH, move |result| {
                result_tx.send(result).expect("result receiver open");
                true
            })
            .await
        });

        while *started_rx.borrow() < WIDTH {
            started_rx.changed().await.expect("workers still pending");
        }
        assert_eq!(*started_rx.borrow(), WIDTH);
        assert_eq!(active.load(Ordering::SeqCst), WIDTH);
        assert!(!runner.is_finished());

        gate.add_permits(1);
        let first = result_rx.recv().await.expect("first result");
        assert!(first < TOTAL);
        while *started_rx.borrow() < WIDTH + 1 {
            started_rx.changed().await.expect("workers still pending");
        }
        assert_eq!(active.load(Ordering::SeqCst), WIDTH);

        gate.add_permits(TOTAL);
        let mut received = 1;
        while received < TOTAL {
            result_rx.recv().await.expect("remaining result");
            received += 1;
        }
        assert!(runner.await.expect("runner task"));
        assert_eq!(peak.load(Ordering::SeqCst), WIDTH);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn boot_slots_release_while_prior_workers_wait_for_readiness() {
        const TOTAL: usize = 8;
        const WIDTH: usize = 2;

        let boot_slots = Arc::new(tokio::sync::Semaphore::new(WIDTH));
        let boot_release = Arc::new(tokio::sync::Semaphore::new(0));
        let readiness_release = Arc::new(tokio::sync::Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = tokio::sync::watch::channel(0usize);
        let jobs = (0..TOTAL)
            .map(|index| {
                let boot_slots = boot_slots.clone();
                let boot_release = boot_release.clone();
                let readiness_release = readiness_release.clone();
                let active = active.clone();
                let peak = peak.clone();
                let started_tx = started_tx.clone();
                async move {
                    let boot_permit = boot_slots.acquire_owned().await.expect("scheduler open");
                    let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now_active, Ordering::SeqCst);
                    started_tx.send_modify(|started| *started += 1);

                    let permit = boot_release.acquire().await.expect("test gate open");
                    permit.forget();
                    active.fetch_sub(1, Ordering::SeqCst);
                    drop(boot_permit);

                    let permit = readiness_release
                        .acquire()
                        .await
                        .expect("readiness gate open");
                    permit.forget();
                    index
                }
            })
            .collect::<Vec<_>>();
        drop(started_tx);

        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let runner = tokio::spawn(async move {
            run_bounded_futures(jobs, TOTAL, move |result| {
                result_tx.send(result).expect("result receiver open");
                true
            })
            .await
        });

        for expected in (WIDTH..=TOTAL).step_by(WIDTH) {
            while *started_rx.borrow() < expected {
                started_rx.changed().await.expect("boots still pending");
            }
            assert_eq!(active.load(Ordering::SeqCst), WIDTH);
            boot_release.add_permits(WIDTH);
        }
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
        assert!(!runner.is_finished());
        assert_eq!(peak.load(Ordering::SeqCst), WIDTH);

        readiness_release.add_permits(TOTAL);
        for _ in 0..TOTAL {
            result_rx.recv().await.expect("remaining result");
        }
        assert!(runner.await.expect("runner task"));
    }

    #[tokio::test]
    async fn shared_boot_slots_bound_independent_batches() {
        const WIDTH: usize = 2;
        const PER_BATCH: usize = 4;

        let boot_slots = Arc::new(tokio::sync::Semaphore::new(WIDTH));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = tokio::sync::watch::channel(0usize);
        let build_batch = |offset| {
            (0..PER_BATCH)
                .map(|index| {
                    let boot_slots = boot_slots.clone();
                    let release = release.clone();
                    let active = active.clone();
                    let peak = peak.clone();
                    let started_tx = started_tx.clone();
                    async move {
                        let permit = boot_slots.acquire_owned().await.expect("scheduler open");
                        let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now_active, Ordering::SeqCst);
                        started_tx.send_modify(|started| *started += 1);
                        let gate = release.acquire().await.expect("test gate open");
                        gate.forget();
                        active.fetch_sub(1, Ordering::SeqCst);
                        drop(permit);
                        offset + index
                    }
                })
                .collect::<Vec<_>>()
        };
        let first = build_batch(0);
        let second = build_batch(PER_BATCH);
        drop(started_tx);

        let first =
            tokio::spawn(async move { run_bounded_futures(first, PER_BATCH, |_| true).await });
        let second =
            tokio::spawn(async move { run_bounded_futures(second, PER_BATCH, |_| true).await });

        while *started_rx.borrow() < WIDTH {
            started_rx.changed().await.expect("boots still pending");
        }
        assert_eq!(active.load(Ordering::SeqCst), WIDTH);
        assert_eq!(peak.load(Ordering::SeqCst), WIDTH);

        release.add_permits(PER_BATCH * 2);
        assert!(first.await.expect("first batch task"));
        assert!(second.await.expect("second batch task"));
        assert_eq!(peak.load(Ordering::SeqCst), WIDTH);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ssrf_prone_registry_host_flags_loopback_linklocal_and_private() {
        for host in [
            "127.0.0.1:8081",
            "localhost:5000",
            "0.0.0.0",
            "169.254.169.254", // cloud metadata
            "10.0.0.5",
            "172.16.4.4",
            "192.168.1.10",
            "[::1]:5000",
            "[fe80::1]",
            "[fc00::1]:443",
        ] {
            assert!(
                is_ssrf_prone_registry_host(host),
                "{host} should be flagged"
            );
        }
        for host in [
            "registry-1.docker.io",
            "registry.smolmachines.com",
            "ghcr.io",
            "8.8.8.8",
            "203.0.113.7:5000",
        ] {
            assert!(
                !is_ssrf_prone_registry_host(host),
                "{host} should NOT be flagged"
            );
        }
    }

    #[test]
    fn export_stub_path_is_not_the_sidecar_name() {
        // Regression: the handler used to hand `pack create` a temp file that already
        // ended in `.smolmachine`, which the CLI rejects because `-o` names the stub.
        let dir = std::path::Path::new("/tmp/export-test");
        let stub = export_stub_path(dir);
        assert!(
            stub.extension()
                .is_none_or(|e| !e.eq_ignore_ascii_case("smolmachine")),
            "-o must name the stub, not the sidecar: {}",
            stub.display()
        );
        let sidecar = smolvm_pack::sidecar_path_for(&stub);
        assert_eq!(
            sidecar.extension().and_then(|e| e.to_str()),
            Some("smolmachine"),
            "the derived sidecar must be the .smolmachine artifact"
        );
        assert_ne!(stub, sidecar);
    }

    #[test]
    fn classify_fork_error_maps_precondition_failures_to_conflict() {
        // A golden started without SMOLVM_FORKABLE has no memfd RAM to CoW-fork —
        // a caller-fixable precondition (409), not a 500 a client would retry.
        let e = SmolvmError::agent(
            "fork",
            "golden FORK failed: ERR EINVAL no memfd-backed RAM (start the golden VM with SMOLVM_FORKABLE=1)",
        );
        assert!(matches!(classify_fork_error(e), ApiError::Conflict(_)));
        // A stopped golden's dead control socket is likewise a 409.
        let e = SmolvmError::agent("fork", "golden 'g' control socket not responding");
        assert!(matches!(classify_fork_error(e), ApiError::Conflict(_)));
        // An unrelated fork failure stays a 500.
        let e = SmolvmError::agent("fork", "disk write failed");
        assert!(matches!(classify_fork_error(e), ApiError::Internal(_)));
    }

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
    fn prepared_fork_boot_error_preserves_clone_rejuvenation_identity() {
        let error = PreparedForkBootError::CloneIdentityRejuvenation(
            "clone identity rejuvenation failed: identity reset could not be confirmed".to_string(),
        );
        assert!(matches!(
            classify_prepared_fork_boot_error(error),
            ApiError::CloneIdentityRejuvenationFailed(_)
        ));
    }

    #[test]
    fn validate_workload_image_source_rejects_imageless_workload() {
        let cmd = vec!["python".to_string(), "app.py".to_string()];
        let ep = vec!["/bin/sh".to_string()];
        // Imageless (no image, no from) + a command/entrypoint → rejected.
        assert!(validate_workload_image_source(false, false, &cmd, &[]).is_err());
        assert!(validate_workload_image_source(false, false, &[], &ep).is_err());
        // With an image or a from source, the workload has somewhere to run.
        assert!(validate_workload_image_source(true, false, &cmd, &[]).is_ok());
        assert!(validate_workload_image_source(false, true, &cmd, &ep).is_ok());
        // Imageless with no workload is the ordinary exec-driven machine.
        assert!(validate_workload_image_source(false, false, &[], &[]).is_ok());
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
            cuda: false,
            auto_graph: false,
            entrypoint: vec![],
            cmd: vec![],
            docker_socket: false,
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
            blob_peers: vec![],
            secrets: Default::default(),
            env: vec![],
            workdir: None,
        }
    }

    #[test]
    fn request_env_layers_over_manifest_env_and_wins_collisions() {
        let manifest_env = vec![
            ("KEEP".to_string(), "manifest".to_string()),
            ("OVERRIDE".to_string(), "manifest".to_string()),
        ];
        let request_env = vec![
            crate::api::types::EnvVar {
                name: "OVERRIDE".to_string(),
                value: "request".to_string(),
            },
            crate::api::types::EnvVar {
                name: "NEW".to_string(),
                value: "request".to_string(),
            },
        ];

        let merged = merge_request_env(manifest_env, &request_env);

        assert_eq!(
            merged,
            vec![
                ("KEEP".to_string(), "manifest".to_string()),
                ("OVERRIDE".to_string(), "request".to_string()),
                ("NEW".to_string(), "request".to_string()),
            ]
        );
    }

    #[test]
    fn create_request_accepts_env_and_workdir() {
        let req: CreateMachineRequest = serde_json::from_value(serde_json::json!({
            "name": "api-vm",
            "env": [{"name": "FOO", "value": "bar"}],
            "workdir": "/app"
        }))
        .unwrap();

        assert_eq!(req.env.len(), 1);
        assert_eq!(req.env[0].name, "FOO");
        assert_eq!(req.env[0].value, "bar");
        assert_eq!(req.workdir.as_deref(), Some("/app"));
    }

    #[test]
    fn create_request_auto_graph_is_opt_in() {
        let enabled: CreateMachineRequest = serde_json::from_value(serde_json::json!({
            "name": "api-vm",
            "autoGraph": true
        }))
        .unwrap();
        assert!(enabled.auto_graph);

        let defaulted: CreateMachineRequest = serde_json::from_value(serde_json::json!({
            "name": "api-vm"
        }))
        .unwrap();
        assert!(!defaulted.auto_graph);
    }

    #[test]
    fn auto_graph_policy_overrides_conflicting_request_env() {
        let mut env = merge_request_env(
            vec![(
                crate::util::CUDA_AUTO_GRAPH_ENV.to_string(),
                "0".to_string(),
            )],
            &[crate::api::types::EnvVar {
                name: crate::util::TORCHINDUCTOR_CUDAGRAPHS_ENV.to_string(),
                value: "0".to_string(),
            }],
        );

        crate::util::enable_cuda_auto_graph_env(&mut env);

        assert_eq!(
            env,
            vec![
                (
                    crate::util::CUDA_AUTO_GRAPH_ENV.to_string(),
                    "1".to_string()
                ),
                (
                    crate::util::TORCHINDUCTOR_CUDAGRAPHS_ENV.to_string(),
                    "1".to_string(),
                ),
            ]
        );
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
