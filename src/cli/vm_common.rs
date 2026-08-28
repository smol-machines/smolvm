//! Shared helpers for machine CLI commands.
//!
//! The `machine` subcommand exposes lifecycle commands
//! (create, start, stop, delete, ls). This module provides the common
//! implementations used by those commands.

use crate::cli::{format_pid_suffix, truncate};
use smolvm::agent::{vm_data_dir, AgentManager};
use smolvm::config::{RecordState, SmolvmConfig, VmRecord};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::storage::HostMount;
use smolvm::data::validate_vm_name;
use smolvm::db::SmolvmDb;
use smolvm::network::NetworkBackend;
use smolvm::secrets::SecretRef;
use smolvm::storage::{DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};
use smolvm_protocol::ImageInfo;
use std::collections::BTreeMap;
use std::io::Write;

// ============================================================================
// Shared helpers
// ============================================================================

/// Resolve an optional VM name: if no name is given and a VM named "default"
/// exists in the config database, return `Some("default")` so callers route
/// through the named-VM code path (which loads config, init commands, network
/// settings, etc.). Otherwise returns the input unchanged.
pub fn resolve_vm_name(name: Option<String>) -> smolvm::Result<Option<String>> {
    if name.is_some() {
        return Ok(name);
    }
    // Use direct DB lookup instead of SmolvmConfig::load() to avoid
    // loading all config + all VMs just to check if "default" exists.
    let db = SmolvmDb::open()?;
    if db.get_vm("default")?.is_some() {
        Ok(Some("default".to_string()))
    } else {
        Ok(None)
    }
}

/// Get the agent manager for an optional name (default if `None`).
///
/// When no name is given, uses `AgentManager::new_default()` which is
/// canonicalized to `for_vm("default")` — same socket/PID/storage paths
/// regardless of whether the caller specifies a name or not.
pub fn get_vm_manager(name: &Option<String>) -> smolvm::Result<AgentManager> {
    if let Some(name) = name {
        AgentManager::for_vm(name)
    } else {
        AgentManager::new_default()
    }
}

/// Return the display label for an optional VM name.
pub fn vm_label(name: &Option<String>) -> String {
    name.as_deref().unwrap_or("default").to_string()
}

/// Ensure a VM is running and return a connected client.
///
/// This is the common pattern used by exec commands in the machine subcommand.
/// It resolves the VM manager, checks connectivity, and establishes a client connection.
pub fn ensure_running_and_connect(
    name: &Option<String>,
) -> smolvm::Result<(AgentManager, smolvm::agent::AgentClient)> {
    let manager = get_vm_manager(name)?;
    let label = vm_label(name);
    let start_hint = match name {
        Some(name) => format!("smolvm machine start --name {}", name),
        None => "smolvm machine start".to_string(),
    };

    if manager.try_connect_existing().is_none() {
        // Distinguish "machine not found" from "machine stopped"
        // so a typo in the name gives a clear error rather than the
        // generic "not running / use start" message.
        if let Some(ref n) = name {
            let record = SmolvmDb::open()
                .ok()
                .and_then(|db| db.get_vm(n).ok().flatten());
            let Some(record) = record else {
                return Err(smolvm::Error::vm_not_found(n));
            };
            if smolvm::agent::state_probe::resolve_state(n, &record) == RecordState::Frozen {
                return Err(smolvm::Error::agent(
                    "connect",
                    format!(
                        "machine '{n}' is frozen as a reusable fork base; fork it again, or delete its descendants and stop it before restarting"
                    ),
                ));
            }
        }

        // Best-effort reconcile: if we can't connect to the agent
        // but the libkrun PID is alive, we're in the bug 2 zombie
        // state — record says "running" but agent is dead. Mark
        // the record `Unreachable` so subsequent `machine list`
        // calls reflect truth without re-pinging. DB write is
        // best-effort: we ignore failures so a bad DB doesn't mask
        // the real "can't connect" error the user is about to see.
        mark_unreachable_if_zombie(&label);

        // Distinguish "machine does not exist" from "machine exists but is
        // stopped". Without this a typo in --name reports "is not running"
        // and points at `start`, which then fails differently (QA BUG-45).
        let exists = SmolvmDb::open()
            .ok()
            .and_then(|db| db.get_vm(&label).ok().flatten())
            .is_some();
        if !exists {
            return Err(smolvm::Error::agent(
                "connect",
                format!("machine '{}' not found", label),
            ));
        }

        return Err(smolvm::Error::agent(
            "connect",
            format!(
                "machine '{}' is not running. Use '{}' first.",
                label, start_hint
            ),
        ));
    }

    let client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;
    Ok((manager, client))
}

/// CLI wrapper around `state_probe::recover_if_unreachable` that
/// prints a one-line notice when recovery actually runs. The shared
/// helper is silent (the HTTP API doesn't have a stdout to write
/// to); CLI callers want the operator to see the zombie teardown.
/// A failed recovery propagates: the caller must not report the
/// machine as stopped, detach its volumes, or start over the zombie.
fn cli_recover_if_unreachable(name: &str) -> smolvm::Result<()> {
    // Peek at the record before recovery so we can show the PID in
    // the notice. Losing the PID after recovery is fine — the DB
    // gets cleared — but we want the operator to know *which*
    // process got killed.
    let pid_for_notice = SmolvmDb::open()
        .ok()
        .and_then(|db| db.get_vm(name).ok().flatten())
        .and_then(|r| r.pid);

    if smolvm::agent::state_probe::recover_if_unreachable(name)? {
        println!(
            "Machine '{}' is unreachable (PID {} alive but agent unresponsive); \
             cleaning up.",
            name,
            pid_for_notice.unwrap_or(0)
        );
    }
    Ok(())
}

/// If the VM record says `Running` and the libkrun PID is alive but
/// the agent isn't responding, transition the record to
/// `Unreachable`. Caller invokes this on `ensure_running_and_connect`
/// failure so the next `machine list` is honest.
///
/// All errors are swallowed (logged at debug level) — this is a
/// best-effort cleanup, not a critical path.
fn mark_unreachable_if_zombie(name: &str) {
    let Ok(mut config) = SmolvmConfig::load() else {
        return;
    };
    let Some(record) = config.get_vm(name) else {
        return;
    };
    // Only transition Running → Unreachable. Stopped/Created/Failed
    // are already accurate.
    if record.state != RecordState::Running {
        return;
    }
    if !record.is_process_alive() {
        // PID dead → next list will see Stopped without our help.
        return;
    }
    // A fork base is intentionally paused and cannot answer its agent socket.
    // Treating that expected silence as a zombie corrupts the source record to
    // Unreachable and makes later retained-checkpoint forks inherit bad state.
    if smolvm::agent::state_probe::is_frozen_fork_base(name, record) {
        return;
    }
    // PID alive + ensure_running_and_connect failed → zombie. Persist
    // the new state. Update via the closure-based helper if available;
    // fall back to nothing on failure (best-effort).
    let _ = config.update_vm(name, |r| {
        r.state = RecordState::Unreachable;
    });
    tracing::debug!(
        machine = %name,
        "marked machine Unreachable: PID alive but agent not responding"
    );
}

/// Print command output and exit with the given code.
///
/// Prints stdout to stdout, stderr to stderr, detaches the manager
/// (keeping the VM running), and exits the process.
pub fn print_output_and_exit(
    manager: &AgentManager,
    exit_code: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> ! {
    // write_all on raw bytes preserves binary output (image bytes, tarballs,
    // etc.) that print!("{}", ...) would corrupt or refuse to write.
    if !stdout.is_empty() {
        let _ = std::io::stdout().write_all(stdout);
    }
    if !stderr.is_empty() {
        let _ = std::io::stderr().write_all(stderr);
    }
    crate::cli::flush_output();
    manager.detach();
    std::process::exit(exit_code);
}

// ============================================================================
// Init runner
// ============================================================================

/// Run a machine's `init` commands list against the agent.
///
/// Branches on `image`:
///
/// - `Some(img)`: each command runs *inside* the container's rootfs via
///   `client.run_non_interactive`. `record_mounts` are bind-mounted into
///   the container (so `[dev].volumes` like `.:/app` are visible to init,
///   not just to later `machine exec` calls). `overlay_id` ensures
///   filesystem changes (e.g. `pacman -Syu` package installs) persist
///   across this init invocation and into future `machine exec` calls —
///   matches the convention `machine exec` already uses
///   (`src/cli/machine.rs:750`).
///
/// - `None`: each command runs in the agent's bare VM filesystem via
///   `client.vm_exec`. There's no container, so `record_mounts` and
///   `overlay_id` are unused on this branch.
///
pub(crate) struct InitRunContext<'a> {
    pub(crate) image: Option<&'a str>,
    pub(crate) image_info: Option<&'a ImageInfo>,
    pub(crate) env: &'a [(String, String)],
    pub(crate) workdir: Option<&'a str>,
    pub(crate) record_mounts: &'a [(String, String, bool)],
    pub(crate) overlay_id: &'a str,
}

/// On the first non-zero exit, returns an error containing the command
/// index, exit code, and any stdout/stderr the command produced.
/// **Both** streams are surfaced because package managers often write
/// the actual failure reason to stdout (`pacman`'s "target not found",
/// `apt`'s resolver diagnostics) — surfacing only stderr would leave
/// the operator with an exit code and no explanation. The caller is
/// responsible for stopping the VM if appropriate.
pub(crate) fn run_init_commands(
    client: &mut smolvm::agent::AgentClient,
    init: &[String],
    context: InitRunContext<'_>,
) -> smolvm::Result<()> {
    if init.is_empty() {
        return Ok(());
    }
    println!("Running {} init command(s)...", init.len());
    for (i, cmd) in init.iter().enumerate() {
        if let Some(image) = context.image {
            let defaults =
                resolve_image_runtime_defaults(context.image_info, context.env, context.workdir);
            let config = build_init_run_config(
                image,
                cmd,
                &defaults,
                context.record_mounts,
                context.overlay_id,
            )
            .with_tty(true);
            // Interactive run streams the command's output live so the user sees
            // progress (a slow compile, apt-get, etc.). The output isn't buffered
            // here, so on a non-zero exit we report just the code — the detail was
            // already printed above. Not checking the exit code would silently
            // ignore a failed init command (e.g. a broken `apt install`).
            let exit_code = client.run_interactive(config)?;
            if exit_code != 0 {
                return Err(smolvm::Error::agent(
                    "init",
                    format_init_failure(i, exit_code, "", ""),
                ));
            }
        } else {
            let (exit_code, stdout, stderr) = client.vm_exec(
                init_argv(cmd),
                context.env.to_vec(),
                context.workdir.map(|s| s.to_string()),
                None,
                None,
            )?;
            if exit_code != 0 {
                // Init output is generally text — lossy conversion is fine for
                // error messages. Binary init output isn't a real use case.
                return Err(smolvm::Error::agent(
                    "init",
                    format_init_failure(
                        i,
                        exit_code,
                        &String::from_utf8_lossy(&stdout),
                        &String::from_utf8_lossy(&stderr),
                    ),
                ));
            }
        };
    }
    Ok(())
}

/// Wrap a single init command line in `sh -c` argv form. Init commands
/// are user-supplied shell snippets (e.g. `"pacman -Sy && pacman -S git"`)
/// — we intentionally route them through `sh` so operators can use shell
/// features (`&&`, `|`, env expansion) without quoting gymnastics.
fn init_argv(cmd: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), cmd.to_string()]
}

/// Resolve effective env/workdir for image-backed execution.
///
/// Image metadata provides the baseline defaults. Explicit values from the
/// CLI/Smolfile/persisted machine config override those defaults by key, while
/// workdir uses the explicit value when present and otherwise falls back to the
/// image's `WorkingDir`. Image `User` flows through unchanged because there is
/// no CLI or persisted override for it today.
pub(crate) struct ImageRuntimeDefaults {
    pub(crate) env: Vec<(String, String)>,
    pub(crate) workdir: Option<String>,
    pub(crate) user: Option<String>,
}

pub(crate) fn resolve_image_runtime_defaults(
    image_info: Option<&ImageInfo>,
    env: &[(String, String)],
    explicit_workdir: Option<&str>,
) -> ImageRuntimeDefaults {
    let mut resolved_env = Vec::new();

    if let Some(image_info) = image_info {
        for spec in &image_info.env {
            if let Some((key, value)) = smolvm::util::parse_env_spec(spec) {
                apply_env_override(&mut resolved_env, key, value);
            }
        }
    }

    resolved_env = merge_env_overrides(&resolved_env, env);

    let workdir = explicit_workdir
        .map(str::to_string)
        .or_else(|| image_info.and_then(|info| info.workdir.clone()));

    let user = image_info.and_then(|info| info.user.clone());

    ImageRuntimeDefaults {
        env: resolved_env,
        workdir,
        user,
    }
}

pub(crate) fn merge_env_overrides(
    base_env: &[(String, String)],
    overrides: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env = base_env.to_vec();
    for (key, value) in overrides {
        apply_env_override(&mut env, key.clone(), value.clone());
    }
    env
}

fn apply_env_override(env: &mut Vec<(String, String)>, key: String, value: String) {
    env.retain(|(existing, _)| existing != &key);
    env.push((key, value));
}

/// Build the `RunConfig` an image-based init command runs under.
///
/// Pure function so the *shape* of the request (overlay ID, mount tags,
/// env, workdir, the `sh -c` wrap) can be unit-tested without mocking
/// `AgentClient`. Any of these silently regressing — e.g. mounts not
/// flowing through, or overlay ID drifting from the machine name —
/// would leave init working but `machine exec` no longer seeing init's
/// effects, exactly the class of bug that would lurk for months.
fn build_init_run_config(
    image: &str,
    cmd: &str,
    defaults: &ImageRuntimeDefaults,
    record_mounts: &[(String, String, bool)],
    overlay_id: &str,
) -> smolvm::agent::RunConfig {
    let mounts = crate::cli::parsers::record_mounts_to_runconfig_bindings(record_mounts);
    smolvm::agent::RunConfig::new(image, init_argv(cmd))
        .with_env(defaults.env.clone())
        .with_workdir(defaults.workdir.clone())
        .with_user(defaults.user.clone())
        .with_mounts(mounts)
        .with_persistent_overlay(Some(overlay_id.to_string()))
}

/// Compose the user-facing init-failure message. Pure function — split
/// out for testability and so the formatting choice (which stream goes
/// in which order, separators, trimming) is in one place.
fn format_init_failure(index: usize, exit_code: i32, stdout: &str, stderr: &str) -> String {
    let so = stdout.trim();
    let se = stderr.trim();
    let suffix = match (so, se) {
        ("", "") => String::new(),
        (so, "") => format!(": {}", so),
        ("", se) => format!(": {}", se),
        // Both populated: keep stderr first (canonical error channel)
        // but include stdout because `pacman`/`apt`/`dnf` often put the
        // real reason there. Single line, semicolon-separated, so the
        // message stays grep-friendly.
        (so, se) => format!(": {}; stdout: {}", se, so),
    };
    format!("init[{}] failed (exit {}){}", index, exit_code, suffix)
}

// ============================================================================
// Create
// ============================================================================

/// Parameters for [`create_vm`].
pub struct CreateVmParams {
    pub name: String,
    /// Caller metadata, passed through to [`VmRecord::labels`] verbatim.
    pub labels: std::collections::BTreeMap<String, String>,
    pub image: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub cpus: u8,
    pub mem: u32,
    pub volume: Vec<String>,
    pub port: Vec<PortMapping>,
    pub net: bool,
    pub network_backend: Option<NetworkBackend>,
    pub dns: Option<std::net::Ipv4Addr>,
    pub network_name: Option<String>,
    pub init: Vec<String>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
    pub storage_gb: Option<u64>,
    pub overlay_gb: Option<u64>,
    pub allowed_cidrs: Option<Vec<String>>,
    pub restart_policy: Option<smolvm::config::RestartPolicy>,
    pub restart_max_retries: Option<u32>,
    pub restart_max_backoff_secs: Option<u64>,
    pub health_cmd: Option<Vec<String>>,
    pub health_interval_secs: Option<u64>,
    pub health_timeout_secs: Option<u64>,
    pub health_retries: Option<u32>,
    pub health_startup_grace_secs: Option<u64>,
    pub ssh_agent: bool,
    /// Enable CUDA-over-vsock (remote guest CUDA Driver-API to the host GPU).
    pub cuda: bool,
    /// Start this machine as a copy-on-write fork base by default.
    pub forkable: bool,
    /// Planned number of runnable CUDA fork clones.
    pub cuda_fork_pool_size: Option<u32>,
    /// Explicit logical VRAM limit for each golden/clone CUDA session.
    pub cuda_vram_limit_mib: Option<u64>,
    /// Expose the guest's Docker daemon socket to the host as a Unix socket.
    pub docker_socket: bool,
    /// Enable GPU acceleration (virtio-gpu with Venus/Vulkan).
    pub gpu: bool,
    /// GPU VRAM size in MiB (None = default). Ignored when gpu is false.
    pub gpu_vram_mib: Option<u32>,
    /// Enable Rosetta 2 for x86_64 binary translation on Apple Silicon.
    pub rosetta: bool,
    /// Hostnames for DNS filtering (from --allow-host / [network].allow_hosts).
    pub dns_filter_hosts: Option<Vec<String>>,
    /// User-published Unix-socket bridges (`--expose-socket` / `--mount-socket`).
    pub published_sockets: Vec<smolvm::config::PublishedSocketConfig>,
    /// Absolute path to .smolmachine sidecar (for machines created with --from).
    pub source_smolmachine: Option<String>,
    /// Secret refs from Smolfile `[secrets]`. The refs themselves are
    /// persisted to the VM record (they are not sensitive); resolved
    /// plaintext values are produced per-launch and never touch the DB.
    pub secret_refs: BTreeMap<String, SecretRef>,
}

/// Resolve refs supplied by a trusted-local caller (CLI with a Smolfile passed
/// by the host user) into `(name, value)` env pairs. Empty vec if no refs, so
/// callers can unconditionally `.extend()`. Resolved values live in a
/// `Zeroizing<String>` inside `resolve_refs_to_env` and are scrubbed as soon as
/// it returns — the caller must not log them.
pub fn resolve_secret_refs_for_env(
    refs: &BTreeMap<String, SecretRef>,
) -> smolvm::Result<Vec<(String, String)>> {
    smolvm::secrets::resolve_refs_to_env(refs, smolvm::secrets::ResolutionScope::TrustedLocal)
        .map(smolvm::secrets::expose_into_env)
}

/// Build the exec-time env for a persistent VM: the record's own `env`
/// (`KEY=VALUE` strings) plus freshly resolved `secret_refs`, formatted the
/// same way. Called at `machine start` (init + entrypoint) and `machine exec`.
/// Scope is `RecordReplay` — the refs were written by a trusted-local actor at
/// create time. The resolved plaintext stays in the returned vector and never
/// touches the record or the DB.
pub fn record_env_with_secrets(record: &VmRecord) -> smolvm::Result<Vec<(String, String)>> {
    let mut env = record.env.clone();
    env.extend(smolvm::secrets::expose_into_env(
        smolvm::secrets::resolve_refs_to_env(
            &record.secret_refs,
            smolvm::secrets::ResolutionScope::RecordReplay,
        )?,
    ));
    Ok(env)
}

/// Create a named machine configuration (does not start it).
pub fn create_vm(params: CreateVmParams) -> smolvm::Result<()> {
    let record = build_vm_record(&params)?;
    let reservation = CreateVmReservation::reserve(&params.name)?;
    reservation.commit(&record)?;
    print_create_success(&params);
    Ok(())
}

/// Cross-process reservation held while a create operation prepares any
/// name-derived on-disk state. Dropping it releases the DB reservation unless
/// it was committed.
pub(crate) struct CreateVmReservation {
    db: SmolvmDb,
    name: String,
    token: String,
    completed: bool,
}

impl CreateVmReservation {
    pub(crate) fn reserve(name: &str) -> smolvm::Result<Self> {
        let db = SmolvmDb::open()?;
        let token = SmolvmDb::create_reservation_token();
        if !db.reserve_vm_create(name, &token)? {
            return Err(smolvm::Error::config(
                "create machine",
                format!("machine '{}' already exists or is being created", name),
            ));
        }
        Ok(Self {
            db,
            name: name.to_string(),
            token,
            completed: false,
        })
    }

    pub(crate) fn commit(mut self, record: &VmRecord) -> smolvm::Result<()> {
        if !self
            .db
            .commit_reserved_vm(&self.name, &self.token, record)?
        {
            return Err(smolvm::Error::config(
                "create machine",
                format!(
                    "machine '{}' already exists or is no longer reserved",
                    self.name
                ),
            ));
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for CreateVmReservation {
    fn drop(&mut self) {
        if !self.completed {
            if let Err(e) = self
                .db
                .release_vm_create_reservation(&self.name, &self.token)
            {
                tracing::warn!(
                    machine = %self.name,
                    error = %e,
                    "failed to release DB create reservation"
                );
            }
        }
    }
}

pub(crate) fn build_vm_record(params: &CreateVmParams) -> smolvm::Result<VmRecord> {
    // Validate name before touching the database. The on-disk layout uses
    // a hash-derived directory (see `vm_data_dir`), so the name itself has
    // no impact on socket path length — only character sanity + a generous
    // length cap are needed here.
    validate_vm_name(&params.name, "machine name")
        .map_err(|reason| smolvm::Error::config("create machine", reason))?;

    // Peel off remote volume specs (`s3://`) before the host-directory parse;
    // they mount inside the guest at start instead of through virtiofs.
    let (host_volume_specs, remote_volumes) = smolvm::remote_volume::split_specs(&params.volume)?;

    // Parse and validate volume mounts
    let mounts: Vec<(String, String, bool)> = HostMount::parse(&host_volume_specs)?
        .into_iter()
        .map(|m| m.to_storage_tuple())
        .collect();
    for volume in &remote_volumes {
        if mounts.iter().any(|(_, target, _)| target == &volume.target) {
            return Err(smolvm::Error::config(
                "create machine",
                format!(
                    "duplicate mount target: {} is specified more than once",
                    volume.target
                ),
            ));
        }
    }

    // Convert port mappings to tuple format for storage
    let ports = PortMapping::to_tuples(&params.port);

    // Parse environment variables for init
    let env = smolvm::util::parse_env_list(&params.env);

    // Validate every ref against the CLI trust scope before persisting.
    // The CLI caller is `TrustedLocal`, so all source kinds are allowed,
    // but structural rules (exactly one source, absolute from_file paths)
    // still apply and catch Smolfile typos before they reach the DB.
    for (name, r) in &params.secret_refs {
        smolvm::secrets::validate_ref(r, smolvm::secrets::ResolutionScope::TrustedLocal).map_err(
            |e| smolvm::Error::config("create machine", format!("secret '{}': {}", name, e)),
        )?;
    }

    if params.cuda_fork_pool_size == Some(0) {
        return Err(smolvm::Error::config(
            "create machine",
            "fork pool size must be greater than zero",
        ));
    }
    if params.cuda_vram_limit_mib == Some(0) {
        return Err(smolvm::Error::config(
            "create machine",
            "CUDA VRAM limit must be greater than zero",
        ));
    }
    if params.cuda_fork_pool_size.is_some() && !params.cuda {
        return Err(smolvm::Error::config(
            "create machine",
            "fork pool size requires a CUDA-enabled machine",
        ));
    }
    if params.cuda_vram_limit_mib.is_some() && params.cuda_fork_pool_size.is_none() {
        return Err(smolvm::Error::config(
            "create machine",
            "CUDA VRAM limit requires a fork pool size",
        ));
    }

    // Create record with restart policy if configured
    let restart = smolvm::config::RestartConfig {
        policy: params
            .restart_policy
            .clone()
            .unwrap_or(smolvm::config::RestartPolicy::Never),
        max_retries: params.restart_max_retries.unwrap_or(0),
        max_backoff_secs: params.restart_max_backoff_secs.unwrap_or(0),
        ..Default::default()
    };
    let mut record = VmRecord::new_with_restart(
        params.name.clone(),
        params.cpus,
        params.mem,
        mounts,
        ports,
        params.net,
        restart,
    );
    record.init = params.init.clone();
    record.remote_volumes = remote_volumes;
    record.env = env;
    record.secret_refs = params.secret_refs.clone();
    record.workdir = params.workdir.clone();
    record.storage_gb = params.storage_gb;
    record.overlay_gb = params.overlay_gb;
    record.allowed_cidrs = params.allowed_cidrs.clone();
    record.network_backend = params.network_backend;
    record.dns = params.dns;
    record.network_name = params.network_name.clone();
    record.gpu = if params.gpu { Some(true) } else { None };
    record.rosetta = if params.rosetta { Some(true) } else { None };
    // Same invariant the CLI enforces, applied again here because
    // Smolfile values arrive through `params.gpu_vram_mib` without
    // passing through the clap value_parser.
    record.gpu_vram_mib = smolvm::data::resources::validate_gpu_vram_mib(params.gpu_vram_mib)
        .map_err(|e| smolvm::Error::config("create machine", format!("gpu_vram: {}", e)))?;
    record.image = params.image.clone();
    record.entrypoint = params.entrypoint.clone();
    record.cmd = params.cmd.clone();
    record.health_cmd = params.health_cmd.clone();
    record.health_interval_secs = params.health_interval_secs;
    record.health_timeout_secs = params.health_timeout_secs;
    record.health_retries = params.health_retries;
    record.health_startup_grace_secs = params.health_startup_grace_secs;
    record.ssh_agent = params.ssh_agent;
    record.cuda = params.cuda;
    record.forkable = params.forkable || params.cuda_fork_pool_size.is_some();
    record.cuda_fork_pool_size = params.cuda_fork_pool_size;
    record.cuda_vram_limit_mib = params.cuda_vram_limit_mib;
    record.docker_socket = params.docker_socket;
    record.dns_filter_hosts = params.dns_filter_hosts.clone();
    record.published_sockets = params.published_sockets.clone();
    record.source_smolmachine = params.source_smolmachine.clone();
    record.labels = params.labels.clone();

    // A registry image with no network can never be pulled (the guest runs the
    // pull), so refuse here rather than deferring to a `start` that must fail.
    record.validate_image_fetchable()?;

    // Remote volumes mount into the workload container's namespace, so an
    // imageless machine has nowhere to put them, and they need network to
    // reach the bucket. Refuse at create instead of failing every start.
    record.validate_remote_volumes()?;

    Ok(record)
}

pub(crate) fn print_create_success(params: &CreateVmParams) {
    println!("Created machine: {}", params.name);
    println!("  CPUs: {}, Memory: {} MiB", params.cpus, params.mem);
    if !params.volume.is_empty() {
        println!("  Mounts: {}", params.volume.len());
    }
    if !params.port.is_empty() {
        println!("  Ports: {}", params.port.len());
    }
    if !params.init.is_empty() {
        println!("  Init commands: {}", params.init.len());
    }
    println!(
        "\nUse 'smolvm machine start --name {}' to start the machine",
        params.name
    );
    println!(
        "Then use 'smolvm machine exec --name {} -- <command>' to run commands",
        params.name
    );
}

// ============================================================================
// Fork
// ============================================================================

/// Per-launch fork parameters, threaded into `start_vm_named` instead of mutating
/// process-global env vars. The launcher (in the spawned `_boot-vm`) reads these
/// from its own env, which the manager now sets explicitly on the child — so the
/// long-lived `serve` process never does a racy `std::env::set_var`.
#[derive(Debug, Default, Clone)]
pub struct ForkLaunch {
    /// Start as a fork base: memfd-back guest RAM and expose `control_socket`.
    pub forkable: bool,
    /// Boot as a fork clone, restoring from the golden's snapshot at this dir.
    pub snapshot_dir: Option<std::path::PathBuf>,
    /// Clone boot only: share the golden's loaded CUDA weights instead of
    /// copying them (`machine fork --share-weights`).
    pub share_weights: bool,
    /// Preload the golden's staged CUDA modules while this clone boots.
    pub preload_modules: bool,
    /// Planned number of runnable CUDA clones. Set only when starting a golden;
    /// the value is persisted on its record and inherited by clone records.
    pub pool_size: Option<u32>,
    /// Optional explicit logical VRAM limit per golden/clone session.
    pub vram_limit_mib: Option<u64>,
}

/// Fork parameters for starting a machine as a forkable base (memfd RAM), so
/// `machine fork` can later freeze it. The control socket it relies on is
/// created for every machine by the launcher at the well-known per-VM path.
pub fn forkable_launch() -> ForkLaunch {
    ForkLaunch {
        forkable: true,
        snapshot_dir: None,
        share_weights: false,
        preload_modules: false,
        pool_size: None,
        vram_limit_mib: None,
    }
}

/// Fork a running, forkable `golden` machine into a new `clone`.
///
/// Freezes the golden (it stays paused as the shared copy-on-write base — its
/// guest RAM is mapped `MAP_PRIVATE` by clones, so it must not run again while
/// clones exist), copy-on-write clones its disks, and boots the clone from the
/// golden's in-memory snapshot.
pub struct ForkVmOptions<'a> {
    pub clone_forkable: bool,
    pub pinned_ports: &'a [(u16, u16)],
    pub share_weights: bool,
    pub fork_env: &'a [(String, String)],
    pub fork_secrets: &'a BTreeMap<String, SecretRef>,
    pub wait_ready: Option<std::time::Duration>,
    pub hold: bool,
}

pub fn fork_vm(golden: &str, clone: &str, options: ForkVmOptions<'_>) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;
    let _source_lock = smolvm::agent::fork::lock_fork_source(golden)?;

    // A live FUSE mount does not survive the freeze/restore: the restored
    // clone's mount wedges its container namespace and every exec hangs.
    // Refuse cleanly until fork remounts remote volumes on restore.
    if let Some(record) = db.get_vm(golden)? {
        if !record.remote_volumes.is_empty() {
            return Err(smolvm::Error::config(
                "machine fork",
                format!(
                    "machine '{golden}' has remote volumes, which cannot be forked yet: \
                     a mounted remote filesystem does not survive the freeze/restore"
                ),
            ));
        }
    }

    if let Some(timeout) = options.wait_ready {
        eprintln!("Waiting for golden '{golden}' to reach its forkpoint...");
        smolvm::agent::fork::wait_for_forkpoint(golden, timeout)?;
    }

    // Freeze + snapshot the golden, register the clone (CoW disks + DB record).
    // The launch-agnostic mechanics live in the lib (`agent::fork`) so the CLI
    // and the serve API share one implementation.
    eprintln!("Freezing golden '{golden}' as fork base...");
    let prep = if options.hold {
        smolvm::agent::fork::prepare_held_fork(
            &db,
            golden,
            clone,
            options.pinned_ports,
            options.fork_env,
            options.fork_secrets,
        )?
    } else {
        smolvm::agent::fork::prepare_fork(
            &db,
            golden,
            clone,
            options.pinned_ports,
            options.clone_forkable,
            options.fork_env,
            options.fork_secrets,
        )?
    };
    for (golden_host, guest, clone_host) in &prep.port_remaps {
        if options.pinned_ports.is_empty() {
            eprintln!(
                "  port {golden_host}->{guest} (golden) remapped to {clone_host}->{guest} (clone)"
            );
        } else {
            eprintln!("  port {clone_host}->{guest} (pinned)");
        }
    }

    let snapshot_dir = prep.snapshot_dir.clone();
    if let Err(error) = boot_prepared_fork(
        &db,
        clone,
        prep,
        options.share_weights,
        options.fork_env,
        None,
    ) {
        return retain_failed_fork(golden, &snapshot_dir, error);
    }
    if options.wait_ready.is_some() && !options.hold {
        if let Err(error) = smolvm::agent::fork::fail_closed_on_rejuvenation(
            smolvm::agent::fork::release_forkpoint(clone),
            || teardown_fork_clone(&db, clone),
        ) {
            return retain_failed_fork(golden, &snapshot_dir, error);
        }
    }
    if options.hold {
        eprintln!(
            "Forked '{golden}' -> held slot '{clone}'. Release it with \
             `smolvm machine fork-release --name {clone}`."
        );
    } else {
        eprintln!(
            "Forked '{golden}' -> '{clone}'. Golden stays frozen as the fork base \
             (do not start it again while clones exist)."
        );
    }
    Ok(())
}

/// Fork several indexed clones from one snapshot and boot them with bounded
/// concurrency. All clone workloads remain at the forkpoint until every clone
/// has booted, received a fresh identity, and received its per-clone env.
pub fn fork_vm_batch(
    golden: &str,
    clones: &[(String, Vec<(String, String)>)],
    share_weights: bool,
    fork_secrets: &BTreeMap<String, SecretRef>,
    wait_ready: Option<std::time::Duration>,
    parallel: usize,
    hold: bool,
) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;
    let _source_lock = smolvm::agent::fork::lock_fork_source(golden)?;

    // A live FUSE mount does not survive the freeze/restore: the restored
    // clone's mount wedges its container namespace and every exec hangs.
    // Refuse cleanly until fork remounts remote volumes on restore.
    if let Some(record) = db.get_vm(golden)? {
        if !record.remote_volumes.is_empty() {
            return Err(smolvm::Error::config(
                "machine fork",
                format!(
                    "machine '{golden}' has remote volumes, which cannot be forked yet: \
                     a mounted remote filesystem does not survive the freeze/restore"
                ),
            ));
        }
    }

    if let Some(timeout) = wait_ready {
        eprintln!("Waiting for golden '{golden}' to reach its forkpoint...");
        smolvm::agent::fork::wait_for_forkpoint(golden, timeout)?;
    }

    let specs: Vec<_> = clones
        .iter()
        .map(|(name, env)| smolvm::agent::fork::ForkSpec {
            clone: name,
            pinned_ports: &[],
            clone_forkable: false,
            fork_env: env,
            fork_secrets,
            hold,
        })
        .collect();
    eprintln!(
        "Freezing golden '{golden}' once for {} clones...",
        clones.len()
    );
    let prepared = smolvm::agent::fork::prepare_forks(&db, golden, &specs)?;
    let snapshot_dir = prepared[0].snapshot_dir.clone();
    let all_names: Vec<String> = clones.iter().map(|(name, _)| name.clone()).collect();
    let jobs: Vec<_> = prepared
        .into_iter()
        .zip(clones.iter())
        .map(|(prep, (name, env))| (name.clone(), prep, env.clone()))
        .collect();
    let width = parallel.max(1).min(jobs.len());
    let mut first_error = None;

    let queue = std::sync::Mutex::new(std::collections::VecDeque::from(jobs));
    // Initial boots retain the requested width. Only failed boots retry one at
    // a time so a transient launch-pressure failure cannot amplify the burst.
    let retry_gate = std::sync::Mutex::new(());
    let stop = std::sync::atomic::AtomicBool::new(false);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..width)
            .map(|_| {
                let db = db.clone();
                let queue = &queue;
                let retry_gate = &retry_gate;
                let stop = &stop;
                scope.spawn(move || {
                    let mut results = Vec::new();
                    loop {
                        if stop.load(std::sync::atomic::Ordering::Acquire) {
                            break;
                        }
                        let job = queue.lock().expect("batch fork queue poisoned").pop_front();
                        let Some((name, prep, env)) = job else {
                            break;
                        };
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            boot_prepared_fork(
                                &db,
                                &name,
                                prep,
                                share_weights,
                                &env,
                                Some(retry_gate),
                            )
                        }))
                        .unwrap_or_else(|_| {
                            Err(smolvm::Error::agent(
                                "batch fork",
                                format!("clone '{name}' boot worker panicked"),
                            ))
                        });
                        if result.is_err() {
                            stop.store(true, std::sync::atomic::Ordering::Release);
                        }
                        results.push((name, result));
                    }
                    results
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| match handle.join() {
                Ok(results) => results,
                Err(_) => vec![(
                    "unknown".to_string(),
                    Err(smolvm::Error::agent(
                        "batch fork",
                        "boot worker terminated unexpectedly",
                    )),
                )],
            })
            .collect::<Vec<_>>()
    });
    for (name, result) in results {
        if let Err(error) = result {
            first_error.get_or_insert_with(|| {
                smolvm::Error::agent("batch fork", format!("clone '{name}' failed: {error}"))
            });
        }
    }

    if first_error.is_none() {
        for name in &all_names {
            if let Err(error) = persist_batch_clone_running(&db, name) {
                first_error = Some(error);
                break;
            }
        }
    }

    if first_error.is_none() && wait_ready.is_some() && !hold {
        for name in &all_names {
            if let Err(error) = smolvm::agent::fork::release_forkpoint(name) {
                first_error = Some(smolvm::Error::agent(
                    "batch fork",
                    format!("clone '{name}' release failed: {error}"),
                ));
                break;
            }
        }
    }

    if let Some(error) = first_error {
        for name in &all_names {
            teardown_fork_clone(&db, name);
        }
        return retain_failed_fork(golden, &snapshot_dir, error);
    }

    if hold {
        eprintln!(
            "Provisioned {} held slots from '{golden}' with one snapshot.",
            all_names.len()
        );
    } else {
        eprintln!(
            "Forked {} clones from '{golden}' with one snapshot.",
            all_names.len()
        );
    }
    Ok(())
}

/// Assign and release one held clone. This is intentionally one-way: after the
/// workload begins, the clone is dirty and must be replaced from its golden
/// before it can serve another independent job.
pub fn release_held_fork(clone: &str, assignment: &[(String, String)]) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;
    let record = db
        .get_vm(clone)?
        .ok_or_else(|| smolvm::Error::vm_not_found(clone))?;
    if record.golden.is_none() {
        return Err(smolvm::Error::agent(
            "release held fork",
            format!("machine '{clone}' is not a fork clone"),
        ));
    }
    if !record.forkpoint_held {
        return Err(smolvm::Error::agent(
            "release held fork",
            format!("clone '{clone}' is not a held pool slot"),
        ));
    }

    smolvm::agent::fork::validate_fork_env(assignment)?;
    let merged = smolvm::agent::fork::merge_fork_env(&record.fork_env, assignment);
    let claimed = std::cell::Cell::new(false);
    db.update_vm(clone, |updated| {
        if updated.forkpoint_held {
            smolvm::agent::fork::record_fork_activation(updated, assignment, merged.clone());
            claimed.set(true);
        }
    })?
    .ok_or_else(|| smolvm::Error::vm_not_found(clone))?;
    if !claimed.get() {
        return Err(smolvm::Error::agent(
            "release held fork",
            format!("clone '{clone}' was already claimed"),
        ));
    }
    let activated = smolvm::agent::fork::activate_held_fork(clone, &record, assignment).map_err(
        |error| {
            smolvm::Error::agent(
                "release held fork",
                format!(
                    "slot '{clone}' was claimed and will not be reused after activation failed: {error}"
                ),
            )
        },
    )?;
    debug_assert_eq!(activated, merged);
    eprintln!(
        "Released held slot '{clone}'. Replace it from '{}' after the workload completes.",
        record.golden.as_deref().unwrap_or("its golden")
    );
    Ok(())
}

fn boot_prepared_fork(
    db: &SmolvmDb,
    clone: &str,
    prep: smolvm::agent::fork::PreparedFork,
    share_weights: bool,
    fork_env: &[(String, String)],
    retry_gate: Option<&std::sync::Mutex<()>>,
) -> smolvm::Result<()> {
    let preload_modules = prep.clone_record.cuda_preload_modules;
    let clone_forkable = prep.clone_record.forkable;
    eprintln!("Booting clone '{clone}' from snapshot...");
    let mut start = || {
        start_vm_named_with_db(
            db,
            clone,
            None,
            None,
            true,
            ForkLaunch {
                forkable: clone_forkable,
                snapshot_dir: Some(prep.snapshot_dir.clone()),
                share_weights,
                preload_modules,
                ..Default::default()
            },
        )
    };
    let started = match retry_gate {
        Some(gate) => retry_once_serialized(gate, &mut start, |error| {
            eprintln!("Clone '{clone}' boot failed once; retrying serially: {error}");
            std::thread::sleep(std::time::Duration::from_millis(100));
        })
        .map_err(|(first, retry)| {
            smolvm::Error::agent(
                "batch fork boot",
                format!("clone '{clone}' first attempt failed: {first}; retry failed: {retry}"),
            )
        }),
        None => start(),
    };
    if let Err(error) = started {
        teardown_fork_clone(db, clone);
        return Err(error);
    }

    smolvm::agent::fork::fail_closed_on_rejuvenation(
        smolvm::agent::fork::rejuvenate_clone(clone, &prep.clone_record),
        || teardown_fork_clone(db, clone),
    )?;
    smolvm::agent::fork::fail_closed_on_rejuvenation(
        smolvm::agent::fork::write_fork_env(clone, &prep.clone_record, fork_env),
        || teardown_fork_clone(db, clone),
    )
}

fn retry_once_serialized<T, E>(
    gate: &std::sync::Mutex<()>,
    mut operation: impl FnMut() -> Result<T, E>,
    before_retry: impl FnOnce(&E),
) -> Result<T, (E, E)> {
    let first = match operation() {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    let _guard = gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    before_retry(&first);
    operation().map_err(|retry| (first, retry))
}

fn teardown_fork_clone(db: &SmolvmDb, clone: &str) {
    if let Ok(manager) = AgentManager::for_vm(clone) {
        manager.kill();
        manager.cleanup_data_dir();
    }
    let _ = db.remove_vm(clone);
    let _ = std::fs::remove_dir_all(vm_data_dir(clone));
}

fn retain_failed_fork(
    golden: &str,
    snapshot_dir: &std::path::Path,
    error: smolvm::Error,
) -> smolvm::Result<()> {
    Err(smolvm::Error::agent(
        "fork clone boot",
        format!(
            "{error}; source '{golden}' remains frozen at retained checkpoint {} so the fork can be retried safely",
            snapshot_dir.display()
        ),
    ))
}

fn persist_batch_clone_running(db: &SmolvmDb, clone: &str) -> smolvm::Result<()> {
    let manager = AgentManager::for_vm(clone)
        .map_err(|error| smolvm::Error::agent("batch fork", error.to_string()))?;
    let (pid, pid_start_time) = manager.pid_and_start_time().ok_or_else(|| {
        smolvm::Error::agent(
            "batch fork",
            format!("clone '{clone}' has no running process after boot"),
        )
    })?;
    db.update_vm(clone, |record| {
        record.state = RecordState::Running;
        record.pid = Some(pid);
        record.pid_start_time = pid_start_time;
    })?;
    Ok(())
}

// ============================================================================
// Start
// ============================================================================

/// Resolve a machine's persistent-workload command, docker-style: use the
/// machine's own `(entrypoint, cmd)` if it set either of them, otherwise fall
/// back to the image's OCI `(entrypoint, cmd)`. Returns the `(entrypoint, cmd)`
/// to persist and run. An explicit machine command always wins over the image's.
pub(crate) fn default_workload_to_image(
    record_entrypoint: Vec<String>,
    record_cmd: Vec<String>,
    image_entrypoint: &[String],
    image_cmd: &[String],
) -> (Vec<String>, Vec<String>) {
    if !record_entrypoint.is_empty() || !record_cmd.is_empty() {
        (record_entrypoint, record_cmd)
    } else {
        (image_entrypoint.to_vec(), image_cmd.to_vec())
    }
}

/// Start a named machine that has a config record.
///
/// Uses direct DB operations instead of SmolvmConfig::load() to avoid
/// loading all config settings and all VM records. Only reads the single
/// named record (1 DB cycle) and updates it after start (1 DB cycle).
pub fn start_vm_named(
    name: &str,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    from_snapshot: bool,
    fork: ForkLaunch,
) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;
    start_vm_named_with_db(&db, name, proxy, no_proxy, from_snapshot, fork)
}

fn start_vm_named_with_db(
    db: &SmolvmDb,
    name: &str,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    from_snapshot: bool,
    mut fork: ForkLaunch,
) -> smolvm::Result<()> {
    use smolvm::Error;

    // Direct DB lookup — 1 read cycle instead of loading everything
    let mut record = db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))?;
    // A durable checkpoint restores the already-running guest and workload just
    // like an in-memory fork snapshot. Capture this before finalization consumes
    // the one-shot payload, so the workload is not launched twice.
    let restoring_checkpoint =
        smolvm::portable_checkpoint::pending_dir(&smolvm::agent::vm_data_dir(name)).is_some();
    let from_snapshot = from_snapshot || restoring_checkpoint;
    // A Smolfile-declared fork base starts forkable without requiring the user
    // to repeat `--forkable`. Older records that persisted a CUDA pool before
    // the explicit field existed get the same behavior, but clones remain
    // leaves even though they inherit the golden's CUDA capacity policy.
    if record.forkable_on_start() {
        fork.forkable = true;
    }

    // Resolve via the shared probe (PID + vsock ping). The plain
    // `actual_state()` is PID-only and would treat a zombie VMM
    // (alive process, dead agent) as Running — exactly the bug 2
    // case where `start` later said "already running" but every
    // `exec` failed.
    match smolvm::agent::state_probe::resolve_state(name, &record) {
        RecordState::Running => {
            let pid_suffix = format_pid_suffix(record.pid);
            println!("Machine '{}' already running{}", name, pid_suffix);
            return Ok(());
        }
        RecordState::Unreachable => {
            // Zombie VMM: kill it, clear the record, fall through to
            // a clean fresh start.
            // If the zombie cannot be confirmed dead, fail instead of
            // starting on top of it (socket/pid-file conflicts).
            cli_recover_if_unreachable(name)?;
        }
        RecordState::Frozen => {
            let clones = db.dependent_clones(name).unwrap_or_default();
            let reason = if clones.is_empty() {
                "it retains a reusable fork checkpoint; stop it before restarting, or fork it again"
                    .to_string()
            } else {
                format!(
                    "it is the fork base for {} live clone(s) ({}); their disks are copy-on-write overlays backed by its disks, so it cannot be re-launched while they exist — delete the clones first",
                    clones.len(),
                    clones.join(", ")
                )
            };
            return Err(Error::agent(
                "start",
                format!("'{name}' is frozen because {reason}"),
            ));
        }
        RecordState::Stopped | RecordState::Created | RecordState::Failed => {
            // Normal start path. Kill any orphaned _boot-vm process left by
            // a previous failed start — if one is holding ports/sockets, this
            // fresh start would hit the same error without this cleanup.
            kill_orphaned_boot_process(name);
        }
    }

    if let Some(pool_size) = fork.pool_size {
        if !record.cuda {
            return Err(Error::config(
                "fork pool",
                "--fork-pool-size requires a CUDA-enabled machine",
            ));
        }
        record.cuda_fork_pool_size = Some(pool_size);
        db.update_vm(name, |r| r.cuda_fork_pool_size = Some(pool_size))?;
    }
    if let Some(limit_mib) = fork.vram_limit_mib {
        record.cuda_vram_limit_mib = Some(limit_mib);
        db.update_vm(name, |r| r.cuda_vram_limit_mib = Some(limit_mib))?;
    }

    let mounts = record.host_mounts();
    let ports = record.port_mappings();
    let mut resources = record.vm_resources();

    // Re-resolve allow_hosts to fresh CIDRs at start time.
    // Hostnames for CDN-backed services (e.g. dl-cdn.alpinelinux.org) rotate
    // IPs — storing resolved CIDRs at `machine create` time means the egress
    // policy goes stale. We re-resolve here so the policy always reflects
    // current DNS, then merge with any explicit allow_cidrs stored in the DB.
    //
    // IMPORTANT: always initialize allowed_cidrs (even to an empty Vec) when
    // dns_filter_hosts is set. This ensures launcher.rs always calls
    // krun_set_egress_policy, even when every hostname fails to resolve.
    // Without this, a DNS outage at start time causes the VM to boot with no
    // egress restriction at all (fail-open). With it, the policy starts as
    // deny-all and launcher.rs's ensure_dns_in_cidrs adds 1.1.1.1/32 as the
    // minimum (fail-closed: only DNS reachable until resolution succeeds).
    if let Some(ref hosts) = record.dns_filter_hosts {
        if !hosts.is_empty() {
            let existing = resources.allowed_cidrs.get_or_insert_with(Vec::new);
            for host in hosts {
                match crate::cli::parsers::resolve_host_to_cidrs(host) {
                    Ok(cidrs) => existing.extend(cidrs),
                    Err(e) => eprintln!(
                        "Warning: could not resolve '{}' for egress policy: {}",
                        host, e
                    ),
                }
            }
        }
    }

    // Check for host port conflicts with other running VMs.
    if !ports.is_empty() {
        check_port_conflicts(name, &ports, db)?;
    }

    // Start agent VM
    let manager = AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    let mount_info = if !mounts.is_empty() {
        format!(" with {} mount(s)", mounts.len())
    } else {
        String::new()
    };
    let port_info = if !ports.is_empty() {
        format!(" and {} port mapping(s)", ports.len())
    } else {
        String::new()
    };
    eprintln!("Starting machine '{}'{}{}...", name, mount_info, port_info);

    // Resolve SSH agent socket path if enabled
    let ssh_agent_socket = if record.ssh_agent {
        match std::env::var("SSH_AUTH_SOCK") {
            Ok(path) => Some(std::path::PathBuf::from(path)),
            Err(_) => {
                return Err(Error::config(
                    "ssh-agent",
                    "SSH_AUTH_SOCK is not set. Start an SSH agent with: eval $(ssh-agent) && ssh-add",
                ));
            }
        }
    } else {
        None
    };

    // If the machine was created from a .smolmachine, this acquires a lease on
    // the machine's own pre-extracted layers (extracted at create time) and sets
    // packed_layers_dir so the launcher mounts them via virtiofs — the guest uses
    // the pre-extracted layers instead of pulling, with no dependency on the
    // original bundle file. Shared with the API and embedded start paths.
    let mut features = smolvm::agent::LaunchFeatures {
        ssh_agent_socket,
        cuda: record.cuda,
        expose_docker: record.docker_socket,
        published_sockets: record.published_sockets.clone(),
        dns_filter_hosts: record.dns_filter_hosts.clone(),
        // A fork clone shares its golden's uid; resolve it explicitly so a
        // cold (re)start can open the golden's CoW disk backing behind its
        // 0700 data dir.
        uid_share_dir: record.golden.as_deref().map(smolvm::agent::vm_data_dir),
        ..Default::default()
    }
    .with_packed_layers(
        &smolvm::agent::machine_layers_cache_dir(name),
        record.source_smolmachine.as_deref(),
    )?;
    // Fork params (forkable base / clone-from-snapshot) — carried per-launch into
    // the boot subprocess's env by the manager, not via process-global env vars.
    features.forkable = fork.forkable;
    features.snapshot_dir = fork.snapshot_dir;
    features.cuda_share_weights = fork.share_weights;
    features.cuda_preload_modules = fork.preload_modules;
    features.cuda_fork_pool_size = record.cuda_fork_pool_size;
    features.cuda_vram_limit_mib = record.cuda_vram_limit_mib;
    // A machine created from a local image archive/dir persists a `local:…`
    // reference; re-derive its virtiofs mount dir so the guest assembles the
    // rootfs from it instead of pulling.
    if features.packed_layers_dir.is_none() {
        if let Some(dir) = record
            .image
            .as_deref()
            .and_then(smolvm::data::image_source::packed_layers_dir_for_ref)
        {
            features.packed_layers_dir = Some(dir);
        }
    }

    // First boot pulls the base image in-guest, subject to the egress filter —
    // fold the image's registry into the enforced policy so a hostname scope
    // doesn't block its own pull. Subsequent starts skip the pull, so they keep
    // the user's scope unwidened.
    if !record.init_completed {
        features.allow_image_pull_egress(
            record.image.as_deref(),
            features.packed_layers_dir.is_some(),
        );
    }

    let _ = manager
        .ensure_running_with_full_config(mounts, ports, resources, features)
        .map_err(|e| Error::agent("start machine", e.to_string()))?;

    // Get PID immediately (cheap) and print output before DB write
    let pid = manager.child_pid();

    // Install SIGINT guard so Ctrl+C during init/pull kills the VM process
    // instead of orphaning it. Disarmed before detach.
    let _sigint_guard = pid.map(smolvm::process::SigintGuard::new);

    // Pull image first (if configured), then run init. Init can
    // target the container's rootfs (via `run_non_interactive`) when
    // an image is set, so the container layers must be in place
    // before init runs — otherwise any init command referencing the
    // image's filesystem (package managers, distro-specific paths)
    // would hit the bare Alpine agent and fail with "not found".
    let mut client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;

    if restoring_checkpoint {
        if let Err(error) = smolvm::portable_checkpoint::finalize_live_restore(name, &record)
            .and_then(|()| smolvm::portable_checkpoint::consume(&smolvm::agent::vm_data_dir(name)))
        {
            let _ = manager.stop();
            return Err(error);
        }
    }

    // Resolve secret refs to plaintext on the host and inject them only into
    // the env handed to guest commands (init + workload entrypoint). Only the
    // refs persist on the record/DB; the resolved plaintext lives in `exec_env`
    // for the duration of this call and never leaves the host or reaches the DB.
    let exec_env = record_env_with_secrets(&record)?;

    // On first boot, pull the image and run init commands. On subsequent
    // starts, skip both — image manifests/layers persist on the storage disk
    // and the container overlay is remounted (not recreated).
    if !record.init_completed {
        let uses_packed_layers = record.source_smolmachine.is_some()
            || record
                .image
                .as_deref()
                .is_some_and(smolvm::data::image_source::is_local_ref);
        let image_info = if uses_packed_layers {
            // Layers already mounted via virtiofs — no pull needed.
            None
        } else if let Some(ref image) = record.image {
            eprintln!("Pulling {}...", image);
            Some(crate::cli::pull_with_progress(
                &mut client,
                image,
                None,
                proxy,
                no_proxy,
            )?)
        } else {
            None
        };

        if let Err(e) = run_init_commands(
            &mut client,
            &record.init,
            InitRunContext {
                image: record.image.as_deref(),
                image_info: image_info.as_ref(),
                env: &exec_env,
                workdir: record.workdir.as_deref(),
                record_mounts: &record.mounts,
                overlay_id: name,
            },
        ) {
            if let Err(stop_err) = manager.stop() {
                tracing::warn!(error = %stop_err, "failed to stop machine after init failure");
            }
            return Err(e);
        }

        // Docker-like default: if the machine has no command of its own, adopt
        // the image's OCI entrypoint+cmd as its persistent workload so an image
        // VM runs its image's program on start (and forked clones inherit it).
        // Persisted here on first boot (where the image config is available) so
        // later starts reuse it without re-pulling.
        if let Some(info) = image_info.as_ref() {
            let (ep, cmd) = default_workload_to_image(
                record.entrypoint.clone(),
                record.cmd.clone(),
                &info.entrypoint,
                &info.cmd,
            );
            if ep != record.entrypoint || cmd != record.cmd {
                record.entrypoint = ep.clone();
                record.cmd = cmd.clone();
                let _ = db.update_vm(name, |r| {
                    r.entrypoint = ep.clone();
                    r.cmd = cmd.clone();
                });
            }
        }

        // Mark init as completed so subsequent starts skip pull + init.
        // Done before workload start so a CMD failure doesn't re-trigger init.
        if !record.init.is_empty() || record.image.is_some() {
            let _ = db.update_vm(name, |r| {
                r.init_completed = true;
            });
        }
    } else if !record.init.is_empty() {
        println!(
            "Init already completed, skipping {} command(s)",
            record.init.len()
        );
    }

    if let Some(ref img) = record.image {
        // Image-based machine: launch the workload container in the background.
        // An empty command → the agent resolves the image's own ENTRYPOINT+CMD,
        // so service-style images start as their authors intended. But a clone
        // booted from a fork snapshot already has the golden's workload running
        // in its restored memory; relaunching here would double-manage the crun
        // container and hang every later `machine exec`, so skip the (re)launch
        // entirely when restoring from a snapshot — the forked container is
        // inherited as-is.
        let _ = img;
        // Remote volumes are mounted natively by the agent between the
        // container's create and start, and a mount that never appears
        // fails the start there — so no host-side preflight is needed.
        if !from_snapshot {
            if let Err(e) = smolvm::workload::launch_image_workload(
                &mut client,
                name,
                &record,
                exec_env.clone(),
            ) {
                if let Err(stop_err) = manager.stop() {
                    tracing::warn!(error = %stop_err, "failed to stop machine after CMD launch failure");
                }
                return Err(e);
            }
        } else {
            tracing::info!(
                "clone booted from snapshot: workload container inherited from fork, skipping relaunch"
            );
        }
        println!("Machine '{}' running (PID: {})", name, pid.unwrap_or(0));
    } else {
        // No image — bare VM mode. Run entrypoint+cmd if configured. As with the
        // image branch, a snapshot-restored clone already ran this on the golden
        // (its effects are in the restored memory/disk), so don't re-run it.
        let mut bare_cmd = record.entrypoint.clone();
        bare_cmd.extend(record.cmd.clone());
        if !bare_cmd.is_empty() && !from_snapshot {
            // Reuse the secrets already resolved into `exec_env` above — avoids
            // a second store load + decrypt and a duplicate audit-log record.
            // The plaintext stays in this vector and never touches the record/DB.
            let (exit_code, stdout, stderr) =
                client.vm_exec(bare_cmd, exec_env, record.workdir.clone(), None, None)?;
            if !stdout.is_empty() {
                let _ = std::io::stdout().write_all(&stdout);
            }
            if !stderr.is_empty() {
                let _ = std::io::stderr().write_all(&stderr);
            }
            if exit_code != 0 {
                eprintln!("workload exited with code {}", exit_code);
            }
        }
        println!("Machine '{}' running (PID: {})", name, pid.unwrap_or(0));
    }

    // Persist running state. The 15s busy_timeout handles SQLite contention
    // from concurrent starts — no application-level retry needed.
    let pid_start_time = pid.and_then(smolvm::process::process_start_time);
    if let Err(e) = db.update_vm(name, |r| {
        r.state = RecordState::Running;
        r.pid = pid;
        r.pid_start_time = pid_start_time;
    }) {
        tracing::warn!(error = %e, vm = %name, "failed to persist running state");
    }

    // Keep VM running (persistent)
    manager.detach();
    Ok(())
}

/// Persist a named VM as running in the database.
///
/// Creates the record if it doesn't exist, then updates state to Running
/// with the current PID and optional config overrides (cpus, mem, etc.).
pub fn persist_named_running(
    config: &mut SmolvmConfig,
    name: &str,
    pid: Option<i32>,
    overrides: Option<DefaultVmOverrides>,
) -> smolvm::Result<()> {
    if config.get_vm(name).is_none() {
        let record = VmRecord::new(
            name.to_string(),
            DEFAULT_MICROVM_CPU_COUNT,
            DEFAULT_MICROVM_MEMORY_MIB,
            vec![],
            vec![],
            false,
        );
        config.insert_vm(name.to_string(), record)?;
    }
    let pid_start_time = pid.and_then(smolvm::process::process_start_time);
    config
        .update_vm(name, |r| {
            r.state = RecordState::Running;
            r.pid = pid;
            r.pid_start_time = pid_start_time;
            if let Some(ref o) = overrides {
                r.cpus = o.cpus;
                r.mem = o.mem;
                r.mounts = o.mounts.clone();
                r.ports = o.ports.clone();
                r.network = o.network;
                r.network_backend = o.network_backend;
                r.dns = o.dns;
                r.network_name = o.network_name.clone();
                r.storage_gb = o.storage_gb;
                r.overlay_gb = o.overlay_gb;
                r.allowed_cidrs = o.allowed_cidrs.clone();
                r.init = o.init.clone();
                r.init_completed = false;
                r.env = o.env.clone();
                r.secret_refs = o.secret_refs.clone();
                r.workdir = o.workdir.clone();
                r.user = o.user.clone();
                r.image = o.image.clone();
                r.entrypoint = o.entrypoint.clone();
                r.cmd = o.cmd.clone();
                r.ssh_agent = o.ssh_agent;
                r.cuda = o.cuda;
                r.docker_socket = o.docker_socket;
                r.dns_filter_hosts = o.dns_filter_hosts.clone();
                r.gpu = if o.gpu { Some(true) } else { None };
                r.gpu_vram_mib = o.gpu_vram_mib;
                r.rosetta = if o.rosetta { Some(true) } else { None };
            }
        })
        .ok_or_else(|| smolvm::Error::config(
            "persist machine record",
            format!("VM record for '{}' missing after insert", name),
        ))?
        // Flatten: Option<Result<()>> → the ok_or_else above handles None,
        // now propagate the inner Result (DB write failure).
        ?;
    Ok(())
}

/// Config overrides for a VM record.
pub struct DefaultVmOverrides {
    pub cpus: u8,
    pub mem: u32,
    pub mounts: Vec<(String, String, bool)>,
    pub ports: Vec<(u16, u16)>,
    pub network: bool,
    pub network_backend: Option<NetworkBackend>,
    pub dns: Option<std::net::Ipv4Addr>,
    pub network_name: Option<String>,
    pub storage_gb: Option<u64>,
    pub overlay_gb: Option<u64>,
    pub allowed_cidrs: Option<Vec<String>>,
    pub init: Vec<String>,
    pub env: Vec<(String, String)>,
    pub secret_refs: BTreeMap<String, SecretRef>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    pub image: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub ssh_agent: bool,
    pub cuda: bool,
    pub docker_socket: bool,
    pub dns_filter_hosts: Option<Vec<String>>,
    pub gpu: bool,
    pub gpu_vram_mib: Option<u32>,
    pub rosetta: bool,
}

/// Check if any running VM already binds to the same host ports.
///
/// Iterates all VM records, skipping the current VM (`self_name`), and checks
/// for host port overlaps with running VMs. This prevents silent port binding
/// failures where two VMs claim the same host port but only one succeeds.
fn check_port_conflicts(
    self_name: &str,
    ports: &[PortMapping],
    db: &SmolvmDb,
) -> smolvm::Result<()> {
    let host_ports: std::collections::HashSet<u16> = ports.iter().map(|p| p.host).collect();
    if host_ports.is_empty() {
        return Ok(());
    }

    let all_vms = db.list_vms()?;
    for (name, record) in &all_vms {
        if name == self_name {
            continue;
        }
        // Only check running VMs (PID-based quick check).
        if record.actual_state() != smolvm::config::RecordState::Running {
            continue;
        }
        for (host, _guest) in &record.ports {
            if host_ports.contains(host) {
                return Err(smolvm::Error::config(
                    "start machine",
                    format!(
                        "host port {} is already in use by running machine '{}'",
                        host, name
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Start the default machine.
pub fn start_vm_default(proxy: Option<&str>, no_proxy: Option<&str>) -> smolvm::Result<()> {
    let manager = AgentManager::new_default()?;

    if manager.try_connect_existing().is_some() {
        let pid_suffix = format_pid_suffix(manager.child_pid());
        println!("Machine 'default' already running{}", pid_suffix);
        manager.detach();
        return Ok(());
    }

    // try_connect_existing failed — could be "really stopped" or
    // "zombie VMM with dead agent". Recover the zombie case before
    // starting fresh; no-op otherwise.
    // A failed recovery must abort the start: booting over a live
    // zombie would collide on its sockets and pid files.
    cli_recover_if_unreachable("default")?;

    eprintln!("Starting machine 'default'...");
    manager.ensure_running()?;

    let mut config = SmolvmConfig::load()?;
    persist_named_running(&mut config, "default", manager.child_pid(), None)?;

    // Pull image (if persisted via `machine run -d -s`) before running
    // init, then run init through the shared runner — same fix as
    // `start_vm_named`. Both paths must agree so an init that works on
    // a named machine also works on the default one.
    let record = config.get_vm("default").cloned();

    if let Some(record) = record {
        let needs_pull = record.image.is_some();
        let needs_init = !record.init.is_empty();

        if needs_pull || needs_init {
            let mut client =
                smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;

            // Resolve secret refs to plaintext on the host for init only; refs
            // (not values) persist on the record, the plaintext stays here.
            let exec_env = record_env_with_secrets(&record)?;

            let image_info = if let Some(ref image) = record.image {
                eprintln!("Pulling {}...", image);
                Some(crate::cli::pull_with_progress(
                    &mut client,
                    image,
                    None,
                    proxy,
                    no_proxy,
                )?)
            } else {
                None
            };

            if let Err(e) = run_init_commands(
                &mut client,
                &record.init,
                InitRunContext {
                    image: record.image.as_deref(),
                    image_info: image_info.as_ref(),
                    env: &exec_env,
                    workdir: record.workdir.as_deref(),
                    record_mounts: &record.mounts,
                    overlay_id: "default",
                },
            ) {
                if let Err(stop_err) = manager.stop() {
                    tracing::warn!(error = %stop_err, "failed to stop machine after init failure");
                }
                return Err(e);
            }
        }
    }

    println!(
        "Machine 'default' running (PID: {})",
        manager.child_pid().unwrap_or(0)
    );

    manager.detach();
    Ok(())
}

// ============================================================================
// Stop
// ============================================================================

/// Stop a named machine that has a config record (or fall back to
/// agent-only stop if the name is not in config).
pub fn stop_vm_named(name: &str) -> smolvm::Result<()> {
    let mut config = SmolvmConfig::load()?;

    // Check config for the named VM
    let record = match config.get_vm(name) {
        Some(r) => r.clone(),
        None => {
            // Not in config — try to stop a running VM with this name directly
            let manager = AgentManager::for_vm(name)?;
            if manager.try_connect_existing().is_some() {
                println!("Stopping machine '{}'...", name);
                manager.stop()?;
                println!("Machine '{}' stopped", name);
                return Ok(());
            }
            // Not in config and no running VM with this name — genuinely
            // not found. Exit non-zero, consistent with status/start/delete.
            return Err(smolvm::Error::vm_not_found(name));
        }
    };

    // Resolve via the shared probe so an `Unreachable` VM (live PID,
    // dead agent) is correctly stopped instead of skipped with a
    // misleading "not running" message. `cli_recover_if_unreachable`
    // handles that case by killing the zombie VMM; after it runs the
    // record is `Stopped` and `manager.stop()` becomes a no-op.
    let resolved = smolvm::agent::state_probe::resolve_state(name, &record);
    match resolved {
        RecordState::Unreachable => {
            // Only past this point is the zombie confirmed dead. On
            // failure we return the error without claiming the machine
            // stopped and without detaching its volumes.
            cli_recover_if_unreachable(name)?;
            // Process is gone — detach the layers volume so a non-running
            // machine never holds a mount (invariant: mounted iff running).
            // macOS hdiutil detach; a no-op on Linux.
            if record.source_smolmachine.is_some() {
                smolvm_pack::extract::force_detach_layers_volume(
                    &smolvm::agent::machine_layers_cache_dir(name),
                );
            }
            println!("Stopped machine: {}", name);
            return Ok(());
        }
        RecordState::Running => {
            // fall through to the normal stop path
        }
        RecordState::Frozen => {
            let clones = SmolvmDb::open()?.dependent_clones(name).unwrap_or_default();
            if !clones.is_empty() {
                // A snapshot-frozen fork base must outlive its clones: their
                // disks CoW-back onto its disks and their RAM maps its memfd.
                return Err(smolvm::Error::agent(
                    "stop",
                    format!(
                        "machine '{name}' is the fork base for {} live clone(s) ({}); \
                         stop or delete the clones first",
                        clones.len(),
                        clones.join(", ")
                    ),
                ));
            }
            // A retained checkpoint deliberately keeps the golden frozen
            // between fills even when no clones exist. It is now safe to kill
            // the paused VMM; AgentManager::stop removes the exact retained
            // checkpoint only after confirming process death.
        }
        other => {
            // Not running. If a prior start mounted the layers volume but the
            // VM failed to boot, it could still be mounted — detach it. Safe:
            // resolve_state() probed liveness, so the process is confirmed dead.
            // macOS hdiutil detach; a no-op on Linux.
            if record.source_smolmachine.is_some() {
                smolvm_pack::extract::force_detach_layers_volume(
                    &smolvm::agent::machine_layers_cache_dir(name),
                );
            }
            // Defense-in-depth: a failed `machine start` may have left an
            // orphaned _boot-vm process that the DB doesn't know about (PID
            // never persisted). Check the on-disk PID file and, if the
            // process is alive and its argv matches this VM's boot config
            // path, kill it so the user doesn't have to hunt it manually.
            kill_orphaned_boot_process(name);
            println!("Machine '{}' is not running (state: {})", name, other);
            return Ok(());
        }
    }

    println!("Stopping machine '{}'...", name);

    let manager = AgentManager::for_vm(name)
        .map_err(|e| smolvm::Error::agent("create agent manager", e.to_string()))?;
    manager.stop()?;

    // Detach the machine's case-sensitive layers volume now that its process is
    // gone (macOS hdiutil mount; no-op on Linux). The volume is owned 1:1 by this
    // machine, so the detach is safe and re-acquired on the next start.
    if record.source_smolmachine.is_some() {
        smolvm_pack::extract::force_detach_layers_volume(&smolvm::agent::machine_layers_cache_dir(
            name,
        ));
    }

    config.update_vm(name, |r| {
        r.state = RecordState::Stopped;
        r.pid = None;
        r.pid_start_time = None;
    });

    println!("Stopped machine: {}", name);
    Ok(())
}

/// Kill an orphaned `_boot-vm` process for a machine that the DB thinks is
/// not running.
///
/// When `machine start` fails after spawning the `_boot-vm` child (e.g.,
/// EADDRINUSE in the virtio-net runtime), `finalize_launch` kills the child
/// with SIGTERM + SIGKILL. But if that cleanup itself fails (or a pre-fix
/// binary left an orphan), this fallback catches it: read the on-disk PID
/// file, verify the process argv matches this VM's boot-config path, and
/// kill it. Best-effort — never fails the caller.
fn kill_orphaned_boot_process(name: &str) {
    let data_dir = smolvm::agent::vm_data_dir(name);
    let pid_file = data_dir.join("agent.pid");
    let boot_config = data_dir.join("boot-config.json");

    let content = match std::fs::read_to_string(&pid_file) {
        Ok(c) => c,
        Err(_) => return,
    };
    let pid: i32 = match content.lines().next().and_then(|l| l.trim().parse().ok()) {
        Some(p) => p,
        None => return,
    };

    if !smolvm::process::is_alive(pid) {
        // Stale PID file — clean it up.
        let _ = std::fs::remove_file(&pid_file);
        return;
    }

    // Verify the process is actually our _boot-vm for this VM (not a
    // recycled PID belonging to something else).
    if !smolvm::process::cmdline_contains(pid, &boot_config.to_string_lossy()) {
        return;
    }

    eprintln!(
        "Killing orphaned _boot-vm process (PID {}) for machine '{}'",
        pid, name
    );
    if let Err(e) = smolvm::process::stop_vm_process(
        pid,
        std::time::Duration::from_secs(2),
        smolvm::process::VM_SIGKILL_TIMEOUT,
    ) {
        tracing::warn!(
            pid, error = %e,
            "failed to kill orphaned _boot-vm process"
        );
    }
    let _ = std::fs::remove_file(&pid_file);
}

/// Stop the default machine.
pub fn stop_vm_default() -> smolvm::Result<()> {
    let manager = AgentManager::new_default()?;

    // try_connect_existing sets internal state if agent is reachable;
    // stop() handles both responsive agents and orphans via PID file.
    manager.try_connect_existing();
    println!("Stopping machine 'default'...");
    manager.stop()?;

    // Update database record if it exists
    if let Ok(mut config) = SmolvmConfig::load() {
        // Detach the per-machine layers volume now that the process is gone, so a
        // bundle-sourced default machine never holds a mount while stopped (macOS
        // hdiutil; no-op on Linux). Gated on the record so non-bundle machines are
        // untouched; the volume is owned 1:1 by "default" and re-acquired on start.
        let is_bundle = config
            .get_vm("default")
            .map(|r| r.source_smolmachine.is_some())
            .unwrap_or(false);
        if is_bundle {
            smolvm_pack::extract::force_detach_layers_volume(
                &smolvm::agent::machine_layers_cache_dir("default"),
            );
        }
        config.update_vm("default", |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        });
    }

    println!("Machine 'default' stopped");

    Ok(())
}

// ============================================================================
// Delete
// ============================================================================

/// Host-side paths behind which a `--mount-socket` publish may have left a
/// placeholder for this machine: the guest agent bind-mounts its VM-private
/// listener node at the caller's guest path, a file bind mount needs the
/// destination to exist, and inside a `--volume` (virtiofs) share that
/// destination lands on the host filesystem as a 0-byte regular file.
///
/// Only mount-direction sockets create placeholders, only for guest paths
/// inside a declared volume (otherwise the node lives on the VM's own rootfs).
/// When volumes nest, the deepest guest mountpoint owns the path. Volume host
/// paths are canonicalized so differently-spelled references (`/tmp` vs
/// `/private/tmp`) to the same share compare equal.
fn mount_socket_placeholder_paths(record: &VmRecord) -> Vec<std::path::PathBuf> {
    use smolvm::config::SocketDirection;
    use std::path::{Path, PathBuf};

    let mut out = Vec::new();
    for sock in &record.published_sockets {
        if sock.direction != SocketDirection::Mount {
            continue;
        }
        let guest_path = Path::new(&sock.guest_path);
        if !guest_path.is_absolute() {
            continue;
        }
        let deepest = record
            .mounts
            .iter()
            .filter(|(_, guest_target, _)| guest_path.starts_with(Path::new(guest_target)))
            .max_by_key(|(_, guest_target, _)| guest_target.len());
        let Some((host_source, guest_target, _)) = deepest else {
            continue;
        };
        let Ok(rel) = guest_path.strip_prefix(guest_target) else {
            continue;
        };
        let host_source: PathBuf =
            std::fs::canonicalize(host_source).unwrap_or_else(|_| PathBuf::from(host_source));
        out.push(host_source.join(rel));
    }
    out
}

/// Remove mount-socket placeholder files this machine left in shared `--volume`
/// dirs (see [`mount_socket_placeholder_paths`]), except any `claimed` by
/// another machine. Best-effort housekeeping: failures are debug-logged, never
/// fatal to machine deletion.
fn remove_mount_socket_placeholders_except(
    record: &VmRecord,
    claimed: &std::collections::HashSet<std::path::PathBuf>,
) {
    for placeholder in mount_socket_placeholder_paths(record) {
        if claimed.contains(&placeholder) {
            continue;
        }
        // Only ever remove provably-inert nodes: zero-byte *regular files*, not
        // symlinks. Anything else at that path is the user's, not ours.
        let Ok(meta) = std::fs::symlink_metadata(&placeholder) else {
            continue; // never created, or already gone
        };
        if !meta.file_type().is_file() || meta.len() != 0 {
            continue;
        }
        match std::fs::remove_file(&placeholder) {
            Ok(()) => {
                tracing::debug!(
                    path = %placeholder.display(),
                    "removed mount-socket placeholder from shared volume"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %placeholder.display(),
                    error = %e,
                    "failed to remove mount-socket placeholder"
                );
            }
        }
    }
}

/// Remove machine `record`'s mount-socket placeholders from shared `--volume`
/// dirs — but only those no other machine record claims.
///
/// The claim check is load-bearing, not just tidiness: over virtiofs, removing
/// the placeholder on the host invalidates the mountpoint dentry of a *running*
/// VM that bind-mounted over it, severing its guest path with ENOENT. A
/// placeholder is inert once every machine declaring the same path is deleted,
/// so cleanup converges instead of racing co-mounted machines.
pub fn remove_mount_socket_placeholders(record: &VmRecord) {
    let claimed: std::collections::HashSet<std::path::PathBuf> = match SmolvmConfig::load() {
        Ok(cfg) => cfg
            .list_vms()
            .filter(|(name, _)| name.as_str() != record.name)
            .flat_map(|(_, other)| mount_socket_placeholder_paths(other))
            .collect(),
        // Can't enumerate other machines? Remove nothing — leaving litter is the
        // fail-safe direction; deleting under a running VM is not.
        Err(e) => {
            tracing::debug!(error = %e, "skipping placeholder cleanup: cannot list machines");
            return;
        }
    };
    remove_mount_socket_placeholders_except(record, &claimed);
}

/// Options for machine delete behavior.
pub struct DeleteVmOptions {
    /// If true, stop the VM before deleting when it is running.
    pub stop_if_running: bool,
    /// If true, delete any clones forked from this machine before removing it
    /// (children before the fork base) instead of refusing. Implies no
    /// interactive confirmation.
    pub cascade: bool,
}

fn remove_vm_data_and_record(
    db: &SmolvmDb,
    name: &str,
    data_dir: &std::path::Path,
) -> smolvm::Result<()> {
    if data_dir.exists() {
        std::fs::remove_dir_all(data_dir).map_err(|e| {
            smolvm::Error::storage(
                "delete machine data",
                format!("{}: {e}", data_dir.display()),
            )
        })?;
    }
    db.remove_vm(name)?;
    Ok(())
}

fn ensure_fork_base_delete_is_safe(
    name: &str,
    dependent_clones: &[String],
    cascade: bool,
) -> smolvm::Result<()> {
    if dependent_clones.is_empty() || cascade {
        return Ok(());
    }
    Err(smolvm::Error::agent(
        "delete",
        format!(
            "machine '{name}' is the fork base for {} clone(s) ({}); \
             delete the clones first or use --cascade to remove them too",
            dependent_clones.len(),
            dependent_clones.join(", ")
        ),
    ))
}

/// Delete a named machine configuration.
pub fn delete_vm(name: &str, force: bool, options: DeleteVmOptions) -> smolvm::Result<()> {
    let _fork_source_lock = smolvm::agent::fork::lock_fork_source(name)?;
    let config = SmolvmConfig::load()?;

    // Check if exists
    let record = config
        .get_vm(name)
        .ok_or_else(|| smolvm::Error::vm_not_found(name))?
        .clone();

    // A golden's disks are the copy-on-write backing for its clones' overlays,
    // so it must outlive them. `--force` only suppresses confirmation; it must
    // never bypass this storage-integrity boundary. `--cascade` is the explicit
    // operation that removes descendants deepest-first.
    let db = SmolvmDb::open()?;
    let dependent_clones = db.dependent_clones(name)?;
    ensure_fork_base_delete_is_safe(name, &dependent_clones, options.cascade)?;
    if !dependent_clones.is_empty() && options.cascade {
        // Delete the full lineage deepest-first. Every qcow2 overlay must
        // disappear before the parent image that backs it.
        for clone in db.dependent_descendants_postorder(name)? {
            println!("Deleting dependent clone '{clone}' (cascade)...");
            delete_vm(
                &clone,
                true, // no per-clone confirmation during a cascade
                DeleteVmOptions {
                    stop_if_running: true,
                    cascade: false,
                },
            )?;
        }
    }

    // Stop if running (machine run does this). Use the shared
    // resolver so an `Unreachable` VM (live PID, dead agent) is also
    // torn down — otherwise the record gets deleted while the zombie
    // libkrun process keeps running, orphaned forever.
    if options.stop_if_running {
        match smolvm::agent::state_probe::resolve_state(name, &record) {
            RecordState::Running => {
                let manager = AgentManager::for_vm(name)?;
                println!("Stopping machine '{}'...", name);
                manager.stop()?;
                if record.pid.is_some_and(smolvm::process::is_alive) {
                    return Err(smolvm::Error::agent(
                        "delete machine",
                        format!("machine '{name}' process is still alive after stop"),
                    ));
                }
            }
            RecordState::Unreachable => {
                // Reap unconditionally: we're past the dependent-clones
                // guard above, so this machine has no live child dependency.
                // The guarded `cli_recover_if_unreachable` would skip a frozen
                // fork base, orphaning its VMM after we remove the record below.
                smolvm::agent::state_probe::recover_unreachable_machine(&record)?;
            }
            RecordState::Frozen => {
                // All descendants are gone (or a cascade removed them above),
                // so reap the paused VMM before removing its record.
                smolvm::agent::state_probe::recover_unreachable_machine(&record)?;
            }
            _ => {}
        }
    }

    // Confirm deletion unless --force (or --cascade, which is already an
    // explicit "remove this and its clones" and runs unattended).
    if !force && !options.cascade {
        eprint!("Delete machine '{}'? [y/N] ", name);
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let input = input.trim().to_lowercase();
            if input != "y" && input != "yes" {
                println!("Cancelled");
                return Ok(());
            }
        } else {
            println!("Cancelled");
            return Ok(());
        }
    }

    // If the machine was created from a .smolmachine, detach its case-sensitive
    // layers volume (macOS hdiutil mount; no-op on Linux) before removing the
    // data dir below — otherwise the `rm -rf` fails with "Resource busy". The
    // lease was intentionally leaked with `std::mem::forget` at start time so the
    // volume stayed mounted while the VM ran. The volume lives under this
    // machine's own data dir and is owned 1:1 by it, so the detach is
    // unconditional and cannot affect any other machine.
    if record.source_smolmachine.is_some() {
        smolvm_pack::extract::force_detach_layers_volume(&smolvm::agent::machine_layers_cache_dir(
            name,
        ));
    }

    // Drop mount-socket placeholder files this machine left in shared --volume
    // dirs. Runs after the VM is confirmed stopped (or was never running), so
    // no live bind mount can reference the host-side node; a machine that still
    // declares the same socket recreates its placeholder at its next boot.
    remove_mount_socket_placeholders(&record);

    let data_dir = vm_data_dir(name);
    if data_dir.exists() {
        println!("Cleaning up data directory for vm: {}", name);
        // Release this VM's per-VM uid (if any) before the dir holding its
        // `.vm-uid` record is removed. See process::free_vm_uid.
        smolvm::process::free_vm_uid(&smolvm::agent::vm_uid_registry_dir(), &data_dir);
    }

    // Keep the record until process death and storage removal are both confirmed,
    // so a failed delete remains visible and can be retried safely.
    remove_vm_data_and_record(&SmolvmDb::open()?, name, &data_dir)?;

    // The VM's readiness marker lives in the *shared* agent rootfs, not its data
    // dir, so the removal above doesn't take it. Sweep it (and any other markers
    // orphaned by a crash/kill) now that this VM's data dir is gone, so the
    // rootfs doesn't accumulate stale markers (which also broke `pack create`).
    smolvm::agent::prune_orphaned_ready_markers();

    println!("Deleted machine: {}", name);
    Ok(())
}

// ============================================================================
// Status
// ============================================================================

/// Show status of a named or default machine.
///
/// The `extra` callback is invoked when the VM is running, allowing callers
/// to display additional information (e.g., machine lists containers).
pub fn status_vm<F>(name: &Option<String>, extra: F) -> smolvm::Result<()>
where
    F: FnOnce(&AgentManager),
{
    let label = vm_label(name);

    // A frozen fork base's paused agent never answers; connecting to it
    // would block for the full vsock timeout (the `machine status` hang).
    // Detect it cheaply from the record (no probe) and report Frozen
    // without attempting a connection.
    if let Some(n) = name {
        if let Some(record) = SmolvmDb::open()
            .ok()
            .and_then(|db| db.get_vm(n).ok().flatten())
        {
            if smolvm::agent::state_probe::is_frozen_fork_base(n, &record) {
                println!("Machine '{}': {}", label, RecordState::Frozen);
                return Ok(());
            }
        }
    }

    let manager = get_vm_manager(name)?;

    if manager.try_connect_existing().is_some() {
        let pid_suffix = crate::cli::format_pid_suffix(manager.child_pid());
        println!("Machine '{}': running{}", label, pid_suffix);
        extra(&manager);
        manager.detach();
    } else if let Some(ref n) = name {
        // Agent not reachable. Report the precise state from the registry
        // (stopped / failed / created / unreachable), consistent with
        // `machine list`, instead of a flat "not running". A missing record
        // with an explicit name is "not found".
        match SmolvmDb::open()
            .ok()
            .and_then(|db| db.get_vm(n).ok().flatten())
        {
            Some(record) => {
                let state = smolvm::agent::state_probe::resolve_state(n, &record);
                println!("Machine '{}': {}", label, state);
            }
            None => return Err(smolvm::Error::vm_not_found(n)),
        }
    } else {
        // Default/unnamed VM: no record to resolve.
        println!("Machine '{}': not running", label);
    }

    Ok(())
}

/// Build the per-machine JSON object shared by `machine list --json` and
/// `machine status --json` so the two outputs never drift apart.
fn machine_status_json(name: &str, record: &VmRecord) -> serde_json::Value {
    // Resolve via vsock probe so the JSON reflects truth (Unreachable vs
    // Running) instead of trusting the PID-only check.
    let actual_state = smolvm::agent::state_probe::resolve_state(name, record);
    // Expose the persisted health command as a single shell-friendly string
    // when it was stored as `["sh", "-c", "<cmd>"]`; otherwise a space-joined
    // argv so the field is always a string.
    let health_cmd_str = record.health_cmd.as_ref().map(|argv| {
        if argv.len() == 3 && argv[0] == "sh" && argv[1] == "-c" {
            argv[2].clone()
        } else {
            argv.join(" ")
        }
    });

    let mut obj = serde_json::json!({
        "name": name,
        "state": actual_state.to_string(),
        "cpus": record.cpus,
        "memory_mib": record.mem,
        "pid": record.pid,
        "mounts": record.mounts.len(),
        "ports": record.ports.len(),
        "created_at": record.created_at,
        "storage_gb": record.storage_gb,
        "overlay_gb": record.overlay_gb,
        "image": record.image,
        "entrypoint": record.entrypoint,
        "cmd": record.cmd,
        "ephemeral": record.ephemeral,
        "gpu": record.gpu.unwrap_or(false),
        "gpu_vram_mib": record.gpu_vram_mib,
        "cuda": record.cuda,
        "forkable": record.forkable_on_start(),
        "cuda_fork_pool_size": record.cuda_fork_pool_size,
        "cuda_vram_limit_mib": record.cuda_vram_limit_mib,
        "forkpoint_held": record.forkpoint_held,
        "labels": record.labels,
        "restart_policy": record.restart.policy.to_string(),
        "restart_max_retries": record.restart.max_retries,
        "restart_count": record.restart.restart_count,
        "health_cmd": health_cmd_str,
        "health_interval_secs": record.health_interval_secs,
        "health_timeout_secs": record.health_timeout_secs,
        "health_retries": record.health_retries,
        "health_startup_grace_secs": record.health_startup_grace_secs,
    });
    obj.as_object_mut()
        .unwrap()
        .insert("network".into(), serde_json::json!(record.network));
    obj
}

/// Emit a single machine's status as JSON — the same object shape as
/// `machine list --json`. Errors if the machine does not exist.
pub fn status_vm_json(name: &Option<String>) -> smolvm::Result<()> {
    let label = vm_label(name);
    let config = SmolvmConfig::load()?;
    // Build the owned JSON value inside the match so the borrow of `config`
    // ends before `config` is dropped.
    let obj = match config.list_vms().find(|(n, _)| *n == &label) {
        Some((_, record)) => machine_status_json(&label, record),
        None => {
            return Err(smolvm::Error::config(
                "machine status",
                format!("machine '{}' not found", label),
            ))
        }
    };
    let json = serde_json::to_string_pretty(&obj)
        .map_err(|e| smolvm::Error::config("serialize json", e.to_string()))?;
    println!("{}", json);
    Ok(())
}

// ============================================================================
// List
// ============================================================================

/// List all machines.
pub fn list_vms(verbose: bool, json: bool) -> smolvm::Result<()> {
    let config = SmolvmConfig::load()?;
    let vms: Vec<_> = config.list_vms().collect();

    let empty_label = "No machines found";

    if vms.is_empty() {
        if !json {
            println!("{}", empty_label);
        } else {
            println!("[]");
        }
        return Ok(());
    }

    if json {
        let json_vms: Vec<_> = vms
            .iter()
            .map(|(name, record)| machine_status_json(name, record))
            .collect();
        let json = serde_json::to_string_pretty(&json_vms)
            .map_err(|e| smolvm::Error::config("serialize json", e.to_string()))?;
        println!("{}", json);
    } else {
        println!(
            "{:<20} {:<12} {:>5} {:>10} {:>7} {:>7} {:>8} {:>8}",
            "NAME", "STATE", "CPUS", "MEMORY", "MOUNTS", "PORTS", "STORAGE", "OVERLAY"
        );
        println!("{}", "-".repeat(88));

        for (name, record) in vms {
            let actual_state = smolvm::agent::state_probe::resolve_state(name, record);
            let state_display = if record.ephemeral {
                format!("{} (eph)", actual_state)
            } else {
                actual_state.to_string()
            };
            let storage_gb = record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
            let overlay_gb = record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);
            println!(
                "{:<20} {:<12} {:>5} {:>10} {:>7} {:>7} {:>8} {:>8}",
                truncate(name, 18),
                state_display,
                record.cpus,
                format!("{} MiB", record.mem),
                record.mounts.len(),
                record.ports.len(),
                format!("{} GiB", storage_gb),
                format!("{} GiB", overlay_gb),
            );

            if verbose {
                if let Some(pid) = record.pid {
                    println!("  PID: {}", pid);
                }
                for (host, guest, ro) in &record.mounts {
                    let ro_str = if *ro { " (ro)" } else { "" };
                    println!("  Mount: {} -> {}{}", host, guest, ro_str);
                }
                for (host, guest) in &record.ports {
                    println!("  Port: {} -> {}", host, guest);
                }
                if record.network {
                    println!("  Network: enabled");
                }
                if record.gpu.unwrap_or(false) {
                    match record.gpu_vram_mib {
                        Some(vram) => println!("  GPU: enabled ({} MiB VRAM)", vram),
                        None => println!("  GPU: enabled"),
                    }
                }
                if record.forkable_on_start() {
                    println!("  Forkable: enabled");
                }
                if let Some(pool_size) = record.cuda_fork_pool_size {
                    println!("  CUDA fork pool: {} clone(s)", pool_size);
                }
                if let Some(limit_mib) = record.cuda_vram_limit_mib {
                    println!("  CUDA VRAM limit: {} MiB per session", limit_mib);
                }
                if record.forkpoint_held {
                    println!("  Fork slot: held");
                }
                for cmd in &record.init {
                    println!("  Init: {}", cmd);
                }
                for (k, v) in &record.env {
                    println!("  Env: {}={}", k, v);
                }
                if let Some(wd) = &record.workdir {
                    println!("  Workdir: {}", wd);
                }
                let created =
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(record.created_at);
                println!("  Created: {}", humantime::format_rfc3339_seconds(created));
                println!();
            }
        }
    }

    Ok(())
}

// ============================================================================
// Resize
// ============================================================================

/// Resize a microVM's disk resources.
///
/// The VM must be stopped before resizing. Only expansion is supported
/// (no shrinking to prevent data loss).
/// Expand physical disk files for a VM. Does NOT update the DB record —
/// the caller is responsible for persisting the new sizes.
///
/// Returns a list of human-readable change descriptions for display.
/// Validates no-shrink and performs the physical I/O.
pub fn expand_disks(
    name: &str,
    record: &smolvm::config::VmRecord,
    new_storage_gb: Option<u64>,
    new_overlay_gb: Option<u64>,
) -> smolvm::Result<Vec<String>> {
    use smolvm::data::disk::{Overlay, Storage};
    use smolvm::storage::{expand_disk, DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};

    // A fork base's disks are the copy-on-write backing for its clones' disks, so
    // growing them corrupts the clones' overlays. Refuse if any clone still
    // depends on this machine. Guarded independently of run state: a golden whose
    // VMM has died (e.g. after a host reboot) resolves to Stopped, not Frozen, so
    // a state check alone would let the resize through.
    let clones = SmolvmDb::open()?.dependent_clones(name).unwrap_or_default();
    if !clones.is_empty() {
        return Err(smolvm::Error::config(
            "resize",
            format!(
                "machine '{name}' is the fork base for {} live clone(s) ({}); their disks are \
                 copy-on-write overlays backed by its disks — delete the clones first",
                clones.len(),
                clones.join(", ")
            ),
        ));
    }

    let current_storage_gb = record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
    let current_overlay_gb = record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);

    // Validate no shrinking
    if let Some(s) = new_storage_gb {
        if s < current_storage_gb {
            return Err(smolvm::Error::config(
                "resize",
                format!(
                    "storage disk cannot be shrunk from {} GiB to {} GiB. Only expanding is supported to prevent data loss.",
                    current_storage_gb, s
                ),
            ));
        }
    }
    if let Some(o) = new_overlay_gb {
        if o < current_overlay_gb {
            return Err(smolvm::Error::config(
                "resize",
                format!(
                    "overlay disk cannot be shrunk from {} GiB to {} GiB. Only expanding is supported to prevent data loss.",
                    current_overlay_gb, o
                ),
            ));
        }
    }

    let manager = AgentManager::for_vm(name)
        .map_err(|e| smolvm::Error::agent("get agent manager", e.to_string()))?;

    let mut changes = Vec::new();

    if let Some(storage_gb) = new_storage_gb {
        if storage_gb > current_storage_gb {
            let storage_path = manager.storage_path();
            expand_disk::<Storage>(storage_path, storage_gb)
                .map_err(|e| smolvm::Error::storage("expand storage disk", e.to_string()))?;
            changes.push(format!(
                "  storage: {} GiB → {} GiB",
                current_storage_gb, storage_gb
            ));
        }
    }

    if let Some(overlay_gb) = new_overlay_gb {
        if overlay_gb > current_overlay_gb {
            let overlay_path = manager.overlay_path();
            expand_disk::<Overlay>(overlay_path, overlay_gb)
                .map_err(|e| smolvm::Error::storage("expand overlay disk", e.to_string()))?;
            changes.push(format!(
                "  overlay: {} GiB → {} GiB",
                current_overlay_gb, overlay_gb
            ));
        }
    }

    Ok(changes)
}

/// Legacy wrapper: expand disks AND update the DB in one call.
/// Used by the hidden `machine resize` backward-compat command.
pub fn resize_vm(
    name: &str,
    new_storage_gb: Option<u64>,
    new_overlay_gb: Option<u64>,
) -> smolvm::Result<()> {
    use smolvm::config::RecordState;
    use smolvm::db::SmolvmDb;

    let db = SmolvmDb::open()?;
    let record = db
        .get_vm(name)?
        .ok_or_else(|| smolvm::Error::vm_not_found(name))?
        .clone();

    let actual_state = record.actual_state();
    match actual_state {
        RecordState::Stopped | RecordState::Created => {}
        _ => {
            return Err(smolvm::Error::InvalidState {
                expected: "stopped".into(),
                actual: format!("{:?}", actual_state),
            });
        }
    }

    let changes = expand_disks(name, &record, new_storage_gb, new_overlay_gb)?;

    db.update_vm(name, |r| {
        if let Some(s) = new_storage_gb {
            r.storage_gb = Some(s);
        }
        if let Some(o) = new_overlay_gb {
            r.overlay_gb = Some(o);
        }
    })?;

    if changes.is_empty() {
        println!("No disk changes needed.");
    } else {
        println!("Resized machine '{}':", name);
        for c in &changes {
            println!("{}", c);
        }
        println!("Filesystem will expand on next boot.");
    }

    Ok(())
}

// ============================================================================
// Ephemeral VM Tracking
// ============================================================================

/// Register an ephemeral VM in the database for tracking.
///
/// Called by `machine run` after the VM is forked. The record is removed
/// on clean exit. Stale records from crashes are cleaned up by
/// `cleanup_orphaned_ephemeral_vms()`.
pub fn register_ephemeral_vm(
    name: &str,
    pid: Option<i32>,
    cpus: u8,
    mem: u32,
    network: bool,
    image: Option<String>,
) {
    let mut record = VmRecord::new(name.to_string(), cpus, mem, vec![], vec![], network);
    record.ephemeral = true;
    record.state = RecordState::Running;
    record.pid = pid;
    record.image = image;

    if let Ok(db) = SmolvmDb::open() {
        if let Err(e) = db.insert_vm(name, &record) {
            tracing::debug!(error = %e, name, "failed to register ephemeral VM");
        }
    }
}

/// Remove an ephemeral VM record from the database.
pub fn deregister_ephemeral_vm(name: &str) {
    if let Ok(db) = SmolvmDb::open() {
        if let Err(e) = db.remove_vm(name) {
            tracing::debug!(error = %e, name, "failed to deregister ephemeral VM");
        }
    }
}

/// Names of ephemeral VMs that are orphans (dead or PID-less), capped at `limit`.
///
/// Pure (no I/O) so the reaping policy is unit-testable: given the VM list and a
/// liveness probe, it returns at most `limit` orphan names in list order. A
/// non-ephemeral or still-alive record is never returned.
fn orphaned_ephemeral_names(
    vms: &[(String, VmRecord)],
    is_alive: impl Fn(i32) -> bool,
    limit: usize,
) -> Vec<&str> {
    let mut out = Vec::new();
    for (name, record) in vms {
        if out.len() >= limit {
            break;
        }
        if !record.ephemeral {
            continue;
        }
        let is_orphan = match record.pid {
            Some(pid) => !is_alive(pid),
            None => true, // No PID recorded — stale
        };
        if is_orphan {
            out.push(name.as_str());
        }
    }
    out
}

/// Clean up ALL orphaned ephemeral VM records.
///
/// Called at the start of every machine command EXCEPT `machine run` (which uses
/// the bounded variant on its hot path). Fast path: if no ephemeral records
/// exist, this is a single DB read (~0.2ms).
pub fn cleanup_orphaned_ephemeral_vms() {
    cleanup_orphaned_ephemeral_vms_bounded(usize::MAX);
}

/// Clean up orphaned ephemeral VM records, removing at most `limit` of them.
///
/// `machine run` is the one hot-path caller and passes a small cap: a workflow
/// that ONLY ever calls `machine run` (e.g. a wrapper that spawns a fresh
/// ephemeral VM per task) never reaches the unbounded sweep above, so any run
/// whose detached `_cleanup-ephemeral` helper didn't finish (Ctrl-C / SIGKILL /
/// host sleep mid-run) would leak its data dir forever. The cap lets such a
/// backlog self-heal over a few runs instead of stalling one boot on a large
/// `remove_dir_all` storm. Removal order follows the DB list order. Fast path:
/// no ephemeral records → a single DB read.
pub fn cleanup_orphaned_ephemeral_vms_bounded(limit: usize) {
    if limit == 0 {
        return;
    }
    let db = match SmolvmDb::open() {
        Ok(db) => db,
        Err(_) => return,
    };
    let vms = match db.list_vms() {
        Ok(vms) => vms,
        Err(_) => return,
    };
    for name in orphaned_ephemeral_names(&vms, smolvm::process::is_alive, limit) {
        tracing::debug!(name = %name, "cleaning up orphaned ephemeral VM");
        let _ = db.remove_vm(name);
        let dir = smolvm::agent::vm_data_dir(name);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[cfg(test)]
mod init_runner_tests {
    use super::*;

    #[test]
    fn batch_boot_retry_is_skipped_after_success() {
        let gate = std::sync::Mutex::new(());
        let mut attempts = 0;
        let result = retry_once_serialized(
            &gate,
            || {
                attempts += 1;
                Ok::<_, &'static str>("ready")
            },
            |_| panic!("successful boots must not enter the retry path"),
        );
        assert_eq!(result, Ok("ready"));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn batch_boot_retry_recovers_after_one_failure() {
        let gate = std::sync::Mutex::new(());
        let mut attempts = 0;
        let mut observed = None;
        let result = retry_once_serialized(
            &gate,
            || {
                attempts += 1;
                if attempts == 1 {
                    Err("launch pressure")
                } else {
                    Ok("ready")
                }
            },
            |first| observed = Some(*first),
        );
        assert_eq!(result, Ok("ready"));
        assert_eq!(observed, Some("launch pressure"));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn batch_boot_retry_preserves_both_failures() {
        let gate = std::sync::Mutex::new(());
        let mut attempts = 0;
        let mut observed = None;
        let result = retry_once_serialized(
            &gate,
            || {
                attempts += 1;
                Err::<(), _>(attempts)
            },
            |first| observed = Some(*first),
        );
        assert_eq!(result, Err((1, 2)));
        assert_eq!(observed, Some(1));
        assert_eq!(attempts, 2);
    }

    // The ephemeral-reap policy: only ephemeral + (dead or PID-less) records, in
    // list order, capped at `limit`. Persistent and still-alive VMs are never
    // returned — this is what keeps the bounded `machine run` sweep from touching
    // a concurrent run's live VM.
    #[test]
    fn orphaned_ephemeral_names_filters_and_caps() {
        use smolvm::config::VmRecord;
        let mk = |name: &str, ephemeral: bool, pid: Option<i32>| {
            let mut r = VmRecord::new(name.to_string(), 1, 256, vec![], vec![], false);
            r.ephemeral = ephemeral;
            r.pid = pid;
            (name.to_string(), r)
        };
        let vms = vec![
            mk("persistent", false, Some(10)), // not ephemeral -> skip
            mk("alive", true, Some(20)),       // ephemeral but alive -> skip
            mk("dead1", true, Some(30)),       // ephemeral + dead -> orphan
            mk("nopid", true, None),           // ephemeral + no PID -> orphan
            mk("dead2", true, Some(40)),       // ephemeral + dead -> orphan
        ];
        let alive = |pid: i32| pid == 20; // only the live VM's PID is alive

        assert_eq!(
            orphaned_ephemeral_names(&vms, alive, usize::MAX),
            vec!["dead1", "nopid", "dead2"]
        );
        assert_eq!(
            orphaned_ephemeral_names(&vms, alive, 2),
            vec!["dead1", "nopid"],
            "cap limits how many are reaped per call"
        );
        assert!(orphaned_ephemeral_names(&vms, alive, 0).is_empty());
    }

    #[test]
    fn failed_data_removal_preserves_machine_record() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = SmolvmDb::open_at(&dir.path().join("test.db")).unwrap();
        let name = "delete-failure";
        let record = VmRecord::new(name.to_string(), 1, 256, vec![], vec![], false);
        db.insert_vm(name, &record).unwrap();

        let data_path = dir.path().join("not-a-directory");
        std::fs::write(&data_path, b"occupied").unwrap();
        assert!(remove_vm_data_and_record(&db, name, &data_path).is_err());
        assert!(db.get_vm(name).unwrap().is_some());
    }

    fn sample_image_info(env: Vec<&str>, workdir: Option<&str>, user: Option<&str>) -> ImageInfo {
        ImageInfo {
            reference: "alpine:latest".to_string(),
            digest: "sha256:test".to_string(),
            size: 0,
            created: None,
            architecture: "x86_64".to_string(),
            os: "linux".to_string(),
            layer_count: 0,
            layers: Vec::new(),
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            env: env.into_iter().map(str::to_string).collect(),
            workdir: workdir.map(str::to_string),
            user: user.map(str::to_string),
        }
    }

    #[test]
    fn default_workload_to_image_falls_back_to_image_when_machine_has_none() {
        let (ep, cmd) = default_workload_to_image(
            Vec::new(),
            Vec::new(),
            &["/entry".to_string()],
            &["arg".to_string()],
        );
        assert_eq!(ep, ["/entry"]);
        assert_eq!(cmd, ["arg"]);
    }

    #[test]
    fn default_workload_to_image_prefers_explicit_machine_command() {
        // An explicit machine command always wins over the image's defaults,
        // even if only one of entrypoint/cmd is set.
        let (ep, cmd) = default_workload_to_image(
            Vec::new(),
            vec!["own-cmd".to_string()],
            &["/image-entry".to_string()],
            &["image-arg".to_string()],
        );
        assert!(ep.is_empty());
        assert_eq!(cmd, ["own-cmd"]);
    }

    #[test]
    fn default_workload_to_image_empty_when_neither_has_a_command() {
        let (ep, cmd) = default_workload_to_image(Vec::new(), Vec::new(), &[], &[]);
        assert!(ep.is_empty());
        assert!(cmd.is_empty());
    }

    #[test]
    fn format_init_failure_includes_stderr_only() {
        // Single stream → no "stdout:" / "stderr:" labels needed; the
        // colon-prefixed form keeps the message compact for the common
        // case of a tool writing only to stderr.
        let msg = format_init_failure(0, 1, "", "command not found");
        assert_eq!(msg, "init[0] failed (exit 1): command not found");
    }

    #[test]
    fn format_init_failure_includes_stdout_only() {
        // Some tools emit their failure reason on stdout instead of
        // stderr (curl with -s, certain pacman/apt failure modes).
        // Dropping stdout would leave the operator with just an exit
        // code and no explanation.
        let msg = format_init_failure(2, 127, "could not resolve mirror", "");
        assert_eq!(msg, "init[2] failed (exit 127): could not resolve mirror");
    }

    #[test]
    fn format_init_failure_combines_both_streams() {
        // Both populated: stderr leads (canonical error channel) but
        // stdout follows so package-manager errors that put the real
        // reason on stdout are still visible. Single-line for greppability.
        let msg = format_init_failure(0, 2, "saw 3 errors", "fatal: aborting");
        assert_eq!(
            msg,
            "init[0] failed (exit 2): fatal: aborting; stdout: saw 3 errors"
        );
    }

    #[test]
    fn format_init_failure_handles_empty_streams() {
        // Some commands exit non-zero with no output (e.g. `false`).
        // The error must still be informative — the index + exit code
        // alone tell the user which command failed and how.
        let msg = format_init_failure(5, 1, "", "");
        assert_eq!(msg, "init[5] failed (exit 1)");
    }

    #[test]
    fn format_init_failure_trims_whitespace() {
        // Subprocess output usually ends in a trailing newline; the
        // formatter trims so the assembled message doesn't have weird
        // mid-line breaks.
        let msg = format_init_failure(0, 1, "  ", "  bad thing happened  \n");
        assert_eq!(msg, "init[0] failed (exit 1): bad thing happened");
    }

    #[test]
    fn init_argv_routes_through_sh_dash_c() {
        // Shell wrapping is load-bearing: user init strings commonly
        // chain commands with `&&`, pipe through tools, rely on env
        // expansion. If a future refactor "simplifies" by passing the
        // command argv directly to exec, those features break silently.
        assert_eq!(
            init_argv("pacman -Sy && pacman -S git"),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "pacman -Sy && pacman -S git".to_string(),
            ]
        );
    }

    #[test]
    fn build_init_run_config_overlay_matches_machine_name() {
        // The overlay ID is what makes init's filesystem changes visible
        // to subsequent `machine exec`. If this drifts (e.g. someone
        // hardcodes "init-overlay"), `pacman -S git` during init would
        // succeed but `git --version` post-start would fail with "not
        // found" — exactly the user-confusing regression we're guarding
        // against.
        let config = build_init_run_config(
            "alpine",
            "true",
            &ImageRuntimeDefaults {
                env: vec![],
                workdir: None,
                user: None,
            },
            &[],
            "my-vm",
        );
        assert_eq!(config.persistent_overlay_id.as_deref(), Some("my-vm"));
    }

    #[test]
    fn build_init_run_config_threads_env_workdir_image() {
        // Each input must reach the agent untouched. The runner passes
        // record values verbatim; if a `with_*` call gets dropped in a
        // refactor, the user's `[dev].env` or `[dev].workdir` would
        // silently stop applying to init.
        let env = vec![("HTTP_PROXY".to_string(), "http://proxy:3128".to_string())];
        let config = build_init_run_config(
            "debian:slim",
            "apt update",
            &ImageRuntimeDefaults {
                env: env.clone(),
                workdir: Some("/work".to_string()),
                user: Some("steam".to_string()),
            },
            &[],
            "vm",
        );
        // Image is canonicalized by `RunConfig::new` (normalize_image_ref):
        // bare `debian:slim` → fully-qualified `docker.io/library/debian:slim`.
        assert_eq!(config.image, "docker.io/library/debian:slim");
        assert_eq!(config.env, env);
        assert_eq!(config.workdir.as_deref(), Some("/work"));
        assert_eq!(config.user.as_deref(), Some("steam"));
        // Command is sh-wrapped; assert the wrapped form arrives.
        assert_eq!(
            config.command,
            vec!["sh".to_string(), "-c".to_string(), "apt update".to_string(),]
        );
    }

    #[test]
    fn build_init_run_config_assigns_virtiofs_tags_to_mounts() {
        // Mount tags are positional and must align with the virtiofs
        // devices libkrun set up at VM start. If the converter were
        // skipped (or renamed and not rewired), init would still run
        // but mounted volumes wouldn't be visible inside the container.
        let mounts = vec![
            ("/host/src".to_string(), "/app".to_string(), false),
            ("/host/data".to_string(), "/data".to_string(), true),
        ];
        let config = build_init_run_config(
            "alpine",
            "true",
            &ImageRuntimeDefaults {
                env: vec![],
                workdir: None,
                user: None,
            },
            &mounts,
            "vm",
        );
        assert_eq!(
            config.mounts,
            vec![
                ("smolvm0".to_string(), "/app".to_string(), false),
                ("smolvm1".to_string(), "/data".to_string(), true),
            ]
        );
    }

    #[test]
    fn build_init_run_config_no_mounts_no_workdir() {
        // The image path is also the bare-minimum path: image + cmd is
        // a valid init invocation. No mounts, no workdir, no env — must
        // still produce a usable RunConfig (vs. e.g. panicking on
        // `unwrap` somewhere in the builder).
        let config = build_init_run_config(
            "alpine",
            "echo hi",
            &ImageRuntimeDefaults {
                env: vec![],
                workdir: None,
                user: None,
            },
            &[],
            "vm",
        );
        assert!(config.mounts.is_empty());
        assert!(config.workdir.is_none());
        assert!(config.env.is_empty());
        assert!(config.user.is_none());
        assert_eq!(config.persistent_overlay_id.as_deref(), Some("vm"));
    }

    #[test]
    fn resolve_image_runtime_defaults_uses_image_env_workdir_and_user() {
        let image_info = sample_image_info(
            vec!["FOO=from-image", "BAR=from-image"],
            Some("/image-workdir"),
            Some("steam"),
        );

        let defaults = resolve_image_runtime_defaults(Some(&image_info), &[], None);

        assert_eq!(
            defaults.env,
            vec![
                ("FOO".to_string(), "from-image".to_string()),
                ("BAR".to_string(), "from-image".to_string()),
            ]
        );
        assert_eq!(defaults.workdir.as_deref(), Some("/image-workdir"));
        assert_eq!(defaults.user.as_deref(), Some("steam"));
    }

    #[test]
    fn image_workdir_flows_into_init_run_config_when_no_explicit_workdir_is_set() {
        let image_info = sample_image_info(
            vec!["FOO=from-image"],
            Some("/image-workdir"),
            Some("steam"),
        );
        let defaults = resolve_image_runtime_defaults(Some(&image_info), &[], None);
        let config = build_init_run_config("alpine:latest", "pwd", &defaults, &[], "vm");

        assert_eq!(config.workdir.as_deref(), Some("/image-workdir"));
        assert_eq!(config.user.as_deref(), Some("steam"));
        assert_eq!(
            config.env,
            vec![("FOO".to_string(), "from-image".to_string())]
        );
    }

    #[test]
    fn resolve_image_runtime_defaults_explicit_values_override_image_defaults() {
        let image_info = sample_image_info(
            vec!["FOO=from-image", "BAR=from-image"],
            Some("/image-workdir"),
            Some("steam"),
        );
        let env = vec![
            ("BAR".to_string(), "from-cli".to_string()),
            ("BAZ".to_string(), "from-cli".to_string()),
        ];

        let defaults =
            resolve_image_runtime_defaults(Some(&image_info), &env, Some("/explicit-workdir"));

        assert_eq!(
            defaults.env,
            vec![
                ("FOO".to_string(), "from-image".to_string()),
                ("BAR".to_string(), "from-cli".to_string()),
                ("BAZ".to_string(), "from-cli".to_string()),
            ]
        );
        assert_eq!(defaults.workdir.as_deref(), Some("/explicit-workdir"));
        assert_eq!(defaults.user.as_deref(), Some("steam"));
    }

    #[test]
    fn resolve_image_runtime_defaults_ignores_invalid_image_env_and_last_value_wins() {
        let image_info = sample_image_info(
            vec!["BROKEN", "=empty-key", "FOO=from-image", "FOO=last-image"],
            Some("/image-workdir"),
            Some("1000:1000"),
        );
        let env = vec![
            ("BAR".to_string(), "from-cli".to_string()),
            ("BAR".to_string(), "last-cli".to_string()),
        ];

        let defaults = resolve_image_runtime_defaults(Some(&image_info), &env, None);

        assert_eq!(
            defaults.env,
            vec![
                ("FOO".to_string(), "last-image".to_string()),
                ("BAR".to_string(), "last-cli".to_string()),
            ]
        );
        assert_eq!(defaults.workdir.as_deref(), Some("/image-workdir"));
        assert_eq!(defaults.user.as_deref(), Some("1000:1000"));
    }

    #[test]
    fn resolve_image_runtime_defaults_falls_back_to_explicit_values_without_image_info() {
        let env = vec![("FOO".to_string(), "from-explicit".to_string())];

        let defaults = resolve_image_runtime_defaults(None, &env, Some("/explicit-workdir"));

        assert_eq!(defaults.env, env);
        assert_eq!(defaults.workdir.as_deref(), Some("/explicit-workdir"));
        assert!(defaults.user.is_none());
    }

    #[test]
    fn merge_env_overrides_last_value_wins_by_key() {
        let base_env = vec![
            ("FOO".to_string(), "from-record".to_string()),
            ("BAR".to_string(), "from-record".to_string()),
        ];
        let overrides = vec![
            ("BAR".to_string(), "from-cli".to_string()),
            ("BAZ".to_string(), "from-cli".to_string()),
        ];

        let merged = merge_env_overrides(&base_env, &overrides);

        assert_eq!(
            merged,
            vec![
                ("FOO".to_string(), "from-record".to_string()),
                ("BAR".to_string(), "from-cli".to_string()),
                ("BAZ".to_string(), "from-cli".to_string()),
            ]
        );
    }
}

#[cfg(test)]
mod delete_lineage_tests {
    use super::{ensure_fork_base_delete_is_safe, retain_failed_fork};

    #[test]
    fn force_cannot_bypass_a_live_fork_dependency() {
        // `force` deliberately is not an input to the safety gate: it controls
        // confirmation only and cannot make a dangling qcow2 chain acceptable.
        let children = vec!["child-a".to_string(), "child-b".to_string()];
        let error = ensure_fork_base_delete_is_safe("root", &children, false)
            .expect_err("a live child must protect its parent");
        let message = error.to_string();
        assert!(message.contains("child-a, child-b"));
        assert!(message.contains("--cascade"));
    }

    #[test]
    fn cascade_and_childless_deletes_pass_the_lineage_gate() {
        let children = vec!["child".to_string()];
        ensure_fork_base_delete_is_safe("root", &children, true).unwrap();
        ensure_fork_base_delete_is_safe("leaf", &[], false).unwrap();
    }

    #[test]
    fn failed_clone_boot_preserves_the_retry_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = temp.path().join("checkpoint.bin");
        std::fs::write(&checkpoint, b"checkpoint").unwrap();
        let error = retain_failed_fork(
            "root",
            temp.path(),
            smolvm::Error::agent("clone boot", "injected failure"),
        )
        .expect_err("the original boot failure must be returned");

        assert!(checkpoint.exists(), "the retry checkpoint must survive");
        assert!(error.to_string().contains("remains frozen"));
        assert!(error.to_string().contains("retried safely"));
    }
}

#[cfg(test)]
mod mount_socket_placeholder_tests {
    use super::{mount_socket_placeholder_paths, remove_mount_socket_placeholders_except};
    use smolvm::config::{PublishedSocketConfig, SocketDirection, VmRecord};
    use std::collections::HashSet;

    fn remove_placeholders(record: &VmRecord) {
        remove_mount_socket_placeholders_except(record, &HashSet::new());
    }

    fn mount_sock(guest_path: &str) -> PublishedSocketConfig {
        PublishedSocketConfig {
            direction: SocketDirection::Mount,
            guest_path: guest_path.to_string(),
            host_path: Some("/tmp/host.sock".to_string()),
        }
    }

    fn record_with(
        share: &std::path::Path,
        guest_target: &str,
        sockets: Vec<PublishedSocketConfig>,
    ) -> VmRecord {
        let mut record = VmRecord::new(
            "t".to_string(),
            1,
            256,
            vec![(
                share.to_string_lossy().into_owned(),
                guest_target.to_string(),
                false,
            )],
            vec![],
            false,
        );
        record.published_sockets = sockets;
        record
    }

    #[test]
    fn removes_only_inert_placeholder_files() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("shared");
        std::fs::create_dir_all(&share).unwrap();
        let placeholder = share.join("engine.sock");
        std::fs::write(&placeholder, b"").unwrap(); // the 0-byte node the agent leaves
        let user_data = share.join("real.sock");
        std::fs::write(&user_data, b"user data").unwrap();
        let dir = share.join("dir.sock");
        std::fs::create_dir(&dir).unwrap();

        let record = record_with(
            &share,
            "/run/control",
            vec![
                mount_sock("/run/control/engine.sock"),
                mount_sock("/run/control/real.sock"),
                mount_sock("/run/control/dir.sock"),
                // Expose entries only dial; they never create placeholders.
                PublishedSocketConfig {
                    direction: SocketDirection::Expose,
                    guest_path: "/run/control/exposed.sock".to_string(),
                    host_path: None,
                },
                // A socket whose guest path is inside no volume touches nothing.
                mount_sock("/elsewhere/engine.sock"),
                // Pre-fix records could hold relative paths; never follow them.
                mount_sock("relative/engine.sock"),
            ],
        );
        remove_placeholders(&record);

        assert!(!placeholder.exists(), "inert 0-byte placeholder must go");
        assert!(user_data.exists(), "user data must survive");
        assert!(dir.is_dir(), "directories must survive");
    }

    #[test]
    #[cfg(unix)]
    fn symlink_at_placeholder_path_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("shared");
        std::fs::create_dir_all(&share).unwrap();
        let target = share.join("target-empty");
        std::fs::write(&target, b"").unwrap();
        let link = share.join("engine.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let record = record_with(
            &share,
            "/run/control",
            vec![mount_sock("/run/control/engine.sock")],
        );
        remove_placeholders(&record);

        // We only ever recognize our own placeholders — a symlink is the user's
        // and both it and its target survive.
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(target.exists());
    }

    #[test]
    fn deepest_volume_wins_when_mounts_nest() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("shared");
        let deep = tmp.path().join("deep");
        std::fs::create_dir_all(share.join("sub")).unwrap();
        std::fs::create_dir_all(&deep).unwrap();
        // Same guest path maps to different host files depending on which
        // volume owns the prefix; only the deepest mount is authoritative.
        let shallow_file = share.join("sub/engine.sock");
        std::fs::write(&shallow_file, b"").unwrap();
        let real = deep.join("engine.sock");
        std::fs::write(&real, b"").unwrap();

        let mut record = record_with(
            &share,
            "/run/control",
            vec![mount_sock("/run/control/sub/engine.sock")],
        );
        record.mounts.push((
            deep.to_string_lossy().into_owned(),
            "/run/control/sub".to_string(),
            false,
        ));
        remove_placeholders(&record);

        assert!(!real.exists(), "deepest volume's placeholder must go");
        assert!(shallow_file.exists(), "shallow mapping's file must survive");
    }

    #[test]
    fn shared_placeholder_survives_while_another_machine_claims_it() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("shared");
        std::fs::create_dir_all(&share).unwrap();
        let placeholder = share.join("engine.sock");
        std::fs::write(&placeholder, b"").unwrap();

        let mut record_a = record_with(
            &share,
            "/run/control",
            vec![mount_sock("/run/control/engine.sock")],
        );
        record_a.name = "sock-a".to_string();
        let mut record_b = record_with(
            &share,
            "/run/control",
            vec![mount_sock("/run/control/engine.sock")],
        );
        record_b.name = "sock-b".to_string();

        // Deleting A while B still exists must NOT remove the placeholder:
        // over virtiofs that invalidates the running B's mountpoint dentry.
        let claimed: HashSet<_> = mount_socket_placeholder_paths(&record_b)
            .into_iter()
            .collect();
        remove_mount_socket_placeholders_except(&record_a, &claimed);
        assert!(
            placeholder.exists(),
            "placeholder must survive while another machine claims it"
        );

        // Once B is the last one left, its delete cleans up.
        remove_mount_socket_placeholders_except(&record_b, &HashSet::new());
        assert!(
            !placeholder.exists(),
            "last machine's delete removes the placeholder"
        );
    }

    #[test]
    fn missing_placeholder_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("shared");
        std::fs::create_dir_all(&share).unwrap();
        let record = record_with(
            &share,
            "/run/control",
            vec![mount_sock("/run/control/engine.sock")],
        );
        remove_placeholders(&record); // nothing present: no failure
    }
}
