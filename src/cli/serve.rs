//! HTTP API server command.

use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use smolvm::api::state::ApiState;
use smolvm::Result;

use super::openapi::OpenapiCmd;

/// Start the HTTP API server for programmatic control.
#[derive(Parser, Debug)]
#[command(about = "Start the HTTP API server for programmatic machine management")]
pub enum ServeCmd {
    /// Start the HTTP API server
    #[command(after_long_help = "\
Machines persist independently of the server - they continue running even if the server stops.

API ENDPOINTS:
  GET    /health                      Health check
  POST   /api/v1/machines             Create machine
  GET    /api/v1/machines             List machines
  GET    /api/v1/machines/:id         Get machine status
  POST   /api/v1/machines/:id/start   Start machine
  POST   /api/v1/machines/:id/branches Create a copy-on-write child
  POST   /api/v1/machines/:id/checkpoint Capture a durable checkpoint
  POST   /api/v1/machines/:id/sync    Synchronize staged mounts
  POST   /api/v1/machines/:id/stop    Stop machine
  POST   /api/v1/machines/:id/exec    Execute command
  DELETE /api/v1/machines/:id         Delete machine

EXAMPLES:
  smolvm serve start                                Listen on the default address (shown under --listen)
  smolvm serve start -l 0.0.0.0:9000                Listen on all interfaces, port 9000
  smolvm serve start -l unix:///tmp/smol.sock       Listen on a Unix domain socket
  smolvm serve start -v                             Enable verbose logging")]
    Start(ServeStartCmd),

    /// Export OpenAPI specification for SDK generation
    Openapi(OpenapiCmd),
}

impl ServeCmd {
    pub fn run(self) -> Result<()> {
        match self {
            ServeCmd::Start(cmd) => cmd.run(),
            ServeCmd::Openapi(cmd) => cmd.run(),
        }
    }
}

#[derive(Parser, Debug)]
pub struct ServeStartCmd {
    /// Address and port or Unix socket path to listen on
    #[arg(
        short,
        long,
        default_value_t = default_listen_value(),
        value_name = "ADDR:PORT|PATH"
    )]
    listen: String,

    /// Enable debug logging (or set RUST_LOG=debug)
    #[arg(short, long)]
    verbose: bool,

    /// CORS allowed origins (repeatable). Defaults to localhost:8080 and localhost:3000.
    #[arg(long = "cors-origin", value_name = "ORIGIN")]
    cors_origins: Vec<String>,

    /// Output logs as structured JSON (for log aggregators)
    #[arg(long)]
    json_logs: bool,

    /// Seccomp syscall-allowlist mode for VM boot subprocesses (untrusted-guest
    /// hardening): `enforce` kills the VMM on a disallowed syscall, `audit` logs
    /// only, `off` disables. Linux (x86_64 and arm64) only; ignored elsewhere. A
    /// pre-set SMOLVM_SECCOMP env var takes precedence.
    #[arg(long, value_name = "MODE", default_value = "enforce")]
    seccomp: String,

    /// Landlock filesystem-confinement mode for VM boot subprocesses: `enforce`
    /// restricts each VMM to its own rootfs/disks/devices (denying the rest of
    /// the host fs), `off` disables. Linux-only; ignored elsewhere. A pre-set
    /// SMOLVM_LANDLOCK env var takes precedence.
    #[arg(long, value_name = "MODE", default_value = "enforce")]
    landlock: String,

    /// Let machines run with nested virtualization (`nestedVirt` on create).
    /// Off by default: it exposes the host kernel's nested-KVM code to the
    /// guest, so enable it only on a server that runs trusted workloads. Turning
    /// it off again also stops existing nested machines from starting.
    #[arg(long = "allow-nested-virt")]
    allow_nested_virt: bool,

    /// Flag, or block, guest traffic to destinations on this watchlist. Each line
    /// is `<label> dns-sha256:<hex>` or `<label> ip-sha256:<hex>`: SHA-256 of a
    /// lowercased DNS name (its subdomains match too) or of an IP address's text.
    /// Matches are recorded per machine and reported as `egressSignals` in the
    /// machine API. A line ending in `block` also answers a matching lookup as
    /// nonexistent and drops matching connections. The file is re-read when it
    /// changes. Applies to virtio-net machines. Off by default.
    #[arg(long = "egress-watchlist", value_name = "PATH")]
    egress_watchlist: Option<std::path::PathBuf>,

    /// Require the mTLS client certificate's subject CN to equal this value
    /// for API access. Only applies when serve TLS is configured
    /// (SMOLVM_SERVE_TLS_CERT/_KEY/_CLIENT_CA). Unset (the default), every
    /// client certificate signed by the client CA is accepted for every route.
    #[arg(
        long = "mtls-client-cn",
        value_name = "CN",
        env = "SMOLVM_SERVE_TLS_CLIENT_CN"
    )]
    mtls_client_cn: Option<String>,

    /// With --mtls-client-cn, also accept other client certificates signed by
    /// the client CA, but only for the peer blob routes (/p2p/). Use this when
    /// sibling hosts fetch cached layers from this one. Without it, such
    /// certificates are refused at the TLS handshake.
    #[arg(
        long = "mtls-allow-peer-blobs",
        env = "SMOLVM_SERVE_TLS_ALLOW_PEER_BLOBS",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue
    )]
    mtls_allow_peer_blobs: bool,

    /// Seconds a stopping server gives in-flight requests to finish once it has
    /// stopped accepting connections. Whatever still runs after that is dropped
    /// and the process exits. Without the flag, SMOLVM_SERVE_SHUTDOWN_GRACE_SECS
    /// is read, then the default of 5. Capped at 3600. Connections are refused
    /// for as long as the grace lasts, so to restart without cutting off a long
    /// exec, wait for `GET /inflight` on the loopback door to report nothing in
    /// flight before stopping serve rather than raising this.
    #[arg(long = "shutdown-grace", value_name = "SECS")]
    shutdown_grace: Option<u64>,

    /// Restored checkpoints to keep extracted after their machines are gone,
    /// so restoring one again reuses it instead of fetching and unpacking it
    /// again (0 keeps none). A server restores far more than a CLI session,
    /// so this is larger than `machine create`'s default.
    #[arg(
        long = "restore-cache-entries",
        value_name = "N",
        default_value_t = 32,
        value_parser = clap::value_parser!(u16).range(0..=1024)
    )]
    restore_cache_entries: u16,

    /// Space those kept checkpoints may hold together, in GiB. Each holds a
    /// whole checkpoint's RAM and disks.
    #[arg(long = "restore-cache-gib", value_name = "GiB", default_value_t = 256)]
    restore_cache_gib: u64,

    /// Space for captured checkpoints kept beside the machine's host, in GiB, so
    /// restoring one here skips the download. SMOLVM_PREPARED_CHECKPOINT_CACHE_MAX_BYTES,
    /// when set, still takes precedence.
    #[arg(
        long = "prepared-checkpoint-cache-gib",
        value_name = "GiB",
        default_value_t = 64
    )]
    prepared_checkpoint_cache_gib: u64,
}

/// The restore cache a server keeps, from its flags.
fn server_restore_cache(entries: u16, gib: u64) -> smolvm::portable_checkpoint::RestoreCache {
    smolvm::portable_checkpoint::RestoreCache {
        entries: usize::from(entries),
        max_bytes: gib.saturating_mul(1024 * 1024 * 1024),
    }
}

impl ServeStartCmd {
    /// Run the serve command.
    pub fn run(self) -> Result<()> {
        // Set JSON log format for the logging initializer to pick up
        if self.json_logs {
            std::env::set_var("SMOLVM_LOG_FORMAT", "json");
        }

        // Data root. Per-VM uid isolation needs every smolvm path traversable by
        // the dropped uids; XDG-under-a-700-home isn't, a system data root is.
        // serve additionally auto-defaults to /var/lib/smolvm when privileged
        // (allow_auto = true). An explicit SMOLVM_DATA_DIR was already applied for
        // every command in main(); calling again is idempotent. Single-threaded
        // before the tokio runtime, so set_var is safe.
        smolvm::process::apply_system_data_root(/* allow_auto */ true);

        // Size the checkpoint caches for a server before any request can restore
        // or capture one.
        let restore_cache =
            server_restore_cache(self.restore_cache_entries, self.restore_cache_gib);
        smolvm::portable_checkpoint::RestoreCache::set_process(restore_cache);
        // Other smolvm processes on this node trim the same cache; they follow
        // this sizing rather than the CLI's.
        if let Err(error) = restore_cache.persist_for_node() {
            tracing::warn!(%error, "could not record the restore cache policy for this node");
        }
        smolvm::portable_checkpoint::set_prepared_checkpoint_budget(
            self.prepared_checkpoint_cache_gib
                .saturating_mul(1024 * 1024 * 1024),
        );

        // Lock the state dirs holding machine records / credentials / config down
        // to 0700 so a Landlock-exempt fork clone (which runs as its golden's uid)
        // can't read other tenants' data through the now world-traversable data
        // root. These sit OUTSIDE the traversable VM-data/rootfs chains, so this
        // doesn't affect VM boots.
        #[cfg(target_os = "linux")]
        if smolvm::process::vm_uid_drop_active() {
            use std::os::unix::fs::PermissionsExt;
            let mut sensitive: Vec<std::path::PathBuf> = Vec::new();
            if let Some(d) = dirs::data_local_dir().or_else(dirs::data_dir) {
                sensitive.push(d.join("smolvm").join("server"));
                sensitive.push(d.join("smolvm").join("node-credentials"));
            }
            if let Some(h) = dirs::home_dir() {
                sensitive.push(h.join(".config").join("smolvm"));
            }
            for dir in sensitive {
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
        }

        let listen_target = ListenTarget::parse(&self.listen)?;

        // Set up verbose logging if requested
        if self.verbose {
            // Re-initialize logging at debug level
            // Note: This won't work if logging is already initialized,
            // but the RUST_LOG env var can be used instead
            tracing::info!("verbose logging enabled");
        }

        // Per-VM resource isolation + lossless-restart placement. Two paths:
        //
        // - systemd host: adopt each VM into its OWN `smolvm-vm-<id>.scope` after
        //   fork (a sibling unit owned by PID1), so a `serve` restart doesn't kill
        //   or orphan it — the VM isn't in the service cgroup, so systemd won't hit
        //   `219/CGROUP` recreating the unit. Caps become scope properties. We do
        //   NOT set SMOLVM_CGROUP_ROOT here so the VM boot subprocess skips
        //   self-placement; the parent adopts it instead.
        // - non-systemd (dev/containers): fall back to a delegated cgroup root
        //   advertised via SMOLVM_CGROUP_ROOT so every VM boot subprocess places
        //   itself in a per-VM cgroup. No lossless restart there, which is fine.
        //
        // Done here — single-threaded, before the tokio runtime — so set_var is
        // safe. See docs/runtime-isolation-hardening.md.
        #[cfg(target_os = "linux")]
        if smolvm::systemd_scope::is_available() {
            std::env::set_var("SMOLVM_VM_USE_SCOPE", "1");
            tracing::info!("per-VM systemd transient scopes enabled (lossless serve restart)");
        } else if let Some(root) = smolvm::process::setup_cgroup_delegation_root() {
            tracing::info!(cgroup_root = %root.display(), "per-VM cgroup resource caps enabled");
            std::env::set_var("SMOLVM_CGROUP_ROOT", &root);
        }

        // Default-on: enable the seccomp syscall allowlist on every VM boot
        // subprocess. `--seccomp` selects enforce|audit|off (default enforce); a
        // pre-set SMOLVM_SECCOMP env wins for ad-hoc overrides. Inherited by the
        // spawned `_boot-vm`. See docs/runtime-isolation-hardening.md.
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if std::env::var_os("SMOLVM_SECCOMP").is_none() {
            std::env::set_var("SMOLVM_SECCOMP", &self.seccomp);
            if self.seccomp != "off" {
                tracing::info!(mode = %self.seccomp, "VM seccomp syscall filtering enabled");
            }
        }

        // Default-on: confine each VM boot subprocess's filesystem view via
        // Landlock. `--landlock` selects enforce|off (default enforce); a pre-set
        // SMOLVM_LANDLOCK env wins. Inherited by the spawned `_boot-vm`.
        #[cfg(target_os = "linux")]
        if std::env::var_os("SMOLVM_LANDLOCK").is_none() {
            std::env::set_var("SMOLVM_LANDLOCK", &self.landlock);
            if self.landlock != "off" {
                tracing::info!(mode = %self.landlock, "VM filesystem confinement (Landlock) enabled");
            }
        }

        // Default-on, fail-closed: a `serve` node hosts untrusted tenant guests,
        // so force the STRICT egress floor (blocks cloud metadata, host LAN, the
        // control plane, loopback, and co-resident tenants) rather than inferring
        // it from `SMOLVM_PUBLISH_ADDR`. A dropped publish-addr must NOT silently
        // downgrade the floor to metadata-only and expose the host loopback door
        // to a guest. Single-tenant/self-host operators can opt down with
        // `SMOLVM_EGRESS_FLOOR=metadata|off`. Inherited by the spawned `_boot-vm`.
        if std::env::var_os("SMOLVM_EGRESS_FLOOR").is_none() {
            std::env::set_var("SMOLVM_EGRESS_FLOOR", "strict");
            tracing::info!("egress floor set to strict (multi-tenant serve default)");
        }

        // VMM subprocesses may route exactly one gateway port to the
        // lease-authenticated rollout listener started below. This is internal
        // node configuration, never a guest-supplied egress exception.
        let guest_rollout_host_port =
            std::env::var(smolvm::api::guest_rollout::GUEST_ROLLOUT_HOST_PORT_ENV)
                .ok()
                .map(|value| {
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or_else(|| {
                            smolvm::error::Error::config(
                                "configure guest rollout ingress",
                                format!(
                                    "{} must be an integer between 1 and 65535",
                                    smolvm::api::guest_rollout::GUEST_ROLLOUT_HOST_PORT_ENV
                                ),
                            )
                        })
                })
                .transpose()?
                .unwrap_or(smolvm::api::guest_rollout::GUEST_ROLLOUT_PORT);
        smolvm::network::launch::configure_guest_host_service(
            smolvm::api::guest_rollout::GUEST_ROLLOUT_PORT,
            guest_rollout_host_port,
        )
        .map_err(|reason| {
            smolvm::error::Error::config("configure guest rollout ingress", reason)
        })?;

        // Per-VM uid isolation preflight. When serve is privileged each VMM drops
        // to its own unprivileged uid (process::vm_drop_ids), containing a
        // guest→VMM escape to one VM. That only works if the data root is
        // traversable (others-execute) by the drop uid — an XDG-under-a-700-home
        // layout is not, and the VMM would die with a cryptic readiness timeout.
        // Warn loudly with the fix instead. Opt out with SMOLVM_VM_UID_DROP=off.
        #[cfg(target_os = "linux")]
        if smolvm::process::vm_uid_drop_active() {
            let cache_root = smolvm::agent::vm_cache_root();
            match smolvm::process::first_nontraversable_ancestor(&cache_root) {
                Some(blocker) => tracing::warn!(
                    blocker = %blocker.display(),
                    "per-VM uid isolation is active but {b} is not traversable (o+x) by \
                     unprivileged uids — VMMs will fail to start. Use a world-traversable data \
                     root (e.g. run serve with HOME=/var/lib/smolvm) or `chmod o+x {b}`, or \
                     disable with SMOLVM_VM_UID_DROP=off",
                    b = blocker.display(),
                ),
                None => tracing::info!(
                    "per-VM uid isolation active (each VMM drops to its own unprivileged uid)"
                ),
            }
        }

        // Create the runtime with signal handling enabled
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(smolvm::error::Error::Io)?;

        let result = runtime.block_on(async move { self.run_server(listen_target).await });
        // A request dropped at the end of the grace can leave its agent call
        // running on a blocking thread: a buffered exec waits there for its
        // command to finish. Dropping the runtime waits for every such thread
        // without limit, which kept a stopped server's process alive, and its
        // replacement from starting, until the abandoned command ended. Give
        // blocking work a brief moment, then exit regardless.
        runtime.shutdown_timeout(BLOCKING_WORK_EXIT_WAIT);
        result
    }

    async fn run_server(self, listen_target: ListenTarget) -> Result<()> {
        // On Windows `ListenTarget` has only the `Tcp` variant (Unix-socket
        // listening is unix-gated), making this match irrefutable there.
        #[cfg_attr(not(unix), allow(irrefutable_let_patterns))]
        if let ListenTarget::Tcp(addr) = &listen_target {
            if addr.ip().is_unspecified() {
                eprintln!(
                    "WARNING: Server is listening on all interfaces ({}).",
                    addr.ip()
                );
                eprintln!("         The API has no authentication - any network client can control this host.");
                eprintln!("         Consider using the default Unix socket or --listen 127.0.0.1:8080 for local-only access.");
            }
        }

        // VM boot subprocesses are detached and would zombie on exit; they are
        // reaped SELECTIVELY (per registered PID) by the supervisor tick via
        // smolvm::process::reap_vm_children(). We deliberately do NOT install the
        // global waitpid(-1) SIGCHLD handler here: serve's concurrent boots run
        // busctl/mkfs `.output()` subprocesses that a global reaper would steal,
        // causing ECHILD ("No child processes") and failed scope adoption.

        // Install Prometheus metrics recorder and mark start time
        if let Some(handle) = smolvm::api::install_metrics_recorder() {
            let _ = smolvm::api::METRICS_HANDLE.set(handle);
        }
        smolvm::api::handlers::health::mark_server_start();

        // Create shared state and load persisted machines
        let state = Arc::new(ApiState::new().map_err(|e| {
            smolvm::error::Error::config("initialize api state", format!("{:?}", e))
        })?);
        state.set_allow_nested_virt(self.allow_nested_virt);
        if let Some(path) = &self.egress_watchlist {
            smolvm::agent::egress_watchlist::enable(path.clone())
                .map_err(|e| smolvm::error::Error::config("load egress watchlist", e))?;
            println!("Egress watchlist enabled from {}", path.display());
        }
        if self.allow_nested_virt {
            println!(
                "Nested virtualization is enabled: guests can reach this host's nested-KVM code"
            );
        }
        let loaded = state.load_persisted_machines();
        if !loaded.is_empty() {
            println!(
                "Reconnected to {} existing machine(es): {}",
                loaded.len(),
                loaded.join(", ")
            );
        }
        // GC VM data dirs no machine record references (legacy/orphan disk leaks).
        // Server-only: this owns the node's cache and runs before serving requests.
        let reclaimed = state.reclaim_dangling_vm_dirs();
        if reclaimed > 0 {
            println!("Reclaimed {reclaimed} dangling VM data dir(es)");
        }
        // A previous run may have stopped while restored checkpoint RAM was
        // still being written back; finish that in the background.
        smolvm::portable_checkpoint::resume_deferred_restore_syncs();

        // Create shutdown channel for supervisor
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // A dedicated loopback listener carries only lease-authenticated rollout
        // operations. The virtio gateway maps its internal host-service port to
        // this socket while the normal strict egress floor remains unchanged.
        let guest_rollout_host_port = smolvm::network::launch::guest_host_service()
            .map_err(|reason| smolvm::error::Error::config("read guest rollout ingress", reason))?
            .ok_or_else(|| {
                smolvm::error::Error::config(
                    "read guest rollout ingress",
                    "guest host service is not configured",
                )
            })?
            .host_port;
        let guest_rollout_addr = SocketAddr::from(([127, 0, 0, 1], guest_rollout_host_port));
        let guest_rollout_listener = tokio::net::TcpListener::bind(guest_rollout_addr)
            .await
            .map_err(|error| {
                smolvm::error::Error::config(
                    "bind guest rollout ingress",
                    format!("{guest_rollout_addr}: {error}"),
                )
            })?;
        let guest_rollout_app = smolvm::api::guest_rollout::create_router(state.clone());
        let guest_rollout_shutdown = shutdown_rx.clone();
        let guest_rollout_failure = shutdown_tx.clone();
        let guest_rollout_handle = tokio::spawn(async move {
            tracing::info!(address = %guest_rollout_addr, "starting lease-authenticated guest rollout ingress");
            let result = axum::serve(guest_rollout_listener, guest_rollout_app)
                .with_graceful_shutdown(wait_for_shutdown(guest_rollout_shutdown))
                .await;
            if result.is_err() {
                let _ = guest_rollout_failure.send(true);
            }
            result
        });

        // Spawn supervisor task
        let supervisor_state = state.clone();
        let supervisor_shutdown = shutdown_rx.clone();
        let supervisor_handle = tokio::spawn(async move {
            let supervisor =
                smolvm::api::supervisor::Supervisor::new(supervisor_state, supervisor_shutdown);
            supervisor.run().await;
        });

        // Automatic fork-pool reconciliation has its own task so slow worker
        // creation or deletion never delays the machine health supervisor.
        let pool_state = state.clone();
        let pool_shutdown = shutdown_rx.clone();
        let pool_controller_handle = tokio::spawn(async move {
            let controller =
                smolvm::api::pool_controller::ForkPoolController::new(pool_state, pool_shutdown);
            controller.run().await;
        });
        let resize_controller_handle = tokio::spawn(smolvm::api::resize_controller::run(
            state.clone(),
            shutdown_rx.clone(),
        ));

        // A new smolvm version makes every image seed stale, so the first
        // machine of each image would wait for a seed build. Rebuild the seeds
        // machines used recently, in the background, once startup has settled.
        #[cfg(unix)]
        {
            let spawned = std::thread::Builder::new()
                .name("image-seed-prewarm".into())
                .spawn(|| {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    match smolvm::image_seed::builder_exe() {
                        Ok(exe) => smolvm::image_seed::prewarm_recent_seeds(&exe),
                        Err(error) => {
                            tracing::warn!(%error, "no smolvm binary to prewarm image seeds with")
                        }
                    }
                });
            if let Err(error) = spawned {
                tracing::warn!(%error, "could not start image seed prewarm");
            }
        }

        // Create router
        let drain_state = state.clone();
        // The loopback plain-HTTP door (fleet mode) serves a RESTRICTED router —
        // liveness/capacity/metrics only — so the unauthenticated local surface
        // cannot reach the machine/file/exec API. The full API stays on the mTLS
        // network port (`app`). See `create_local_router`.
        let local_app = smolvm::api::create_local_router(state.clone(), self.cors_origins.clone());
        let app = smolvm::api::create_router(state, self.cors_origins.clone());

        // Resolve the serve API's TLS posture before binding. In fleet mode this
        // is fail-closed: a missing/partial mTLS config aborts startup rather
        // than silently serving plain HTTP (control↔node mTLS, increment 3).
        let tls = super::serve_tls::resolve_tls(super::serve_tls::ClientIdentityPolicy {
            client_cn: self.mtls_client_cn.clone(),
            allow_peer_blobs: self.mtls_allow_peer_blobs,
        })
        .map_err(|e| smolvm::error::Error::Config {
            operation: "serve tls".to_string(),
            reason: e.to_string(),
        })?;

        // Listen server on TCP or Unix socket
        let grace = resolve_shutdown_grace(
            self.shutdown_grace,
            std::env::var("SMOLVM_SERVE_SHUTDOWN_GRACE_SECS")
                .ok()
                .as_deref(),
        );
        let server_result = match listen_target {
            ListenTarget::Tcp(addr) => {
                self.serve_tcp(addr, app, local_app, tls, shutdown_rx.clone(), grace)
                    .await
            }
            #[cfg(unix)]
            ListenTarget::Unix(path) => {
                self.serve_unix(path, app, shutdown_rx.clone(), grace).await
            }
        };

        // The HTTP server has stopped accepting (graceful shutdown on SIGTERM).
        // Stop reconcilers before detaching or draining machine managers. In
        // particular, a pool fill must not register a newly booted worker after
        // `detach_all` has already walked the registry.
        let _ = shutdown_tx.send(true);
        let guest_rollout_result = guest_rollout_handle.await.map_err(|error| {
            smolvm::error::Error::config("guest rollout ingress task", error.to_string())
        })?;
        if let Err(error) = guest_rollout_result {
            tracing::error!(%error, "guest rollout ingress stopped unexpectedly");
            if server_result.is_ok() {
                return Err(smolvm::error::Error::Io(error));
            }
        }
        server_result?;
        // A blocking resize retains lifecycle ownership until its bounded
        // runtime/agent calls finish. Do not drain/detach underneath that work.
        if let Err(error) = resize_controller_handle.await {
            tracing::error!(%error, "resize recovery controller failed during shutdown");
        }
        let mut pool_controller_handle = pool_controller_handle;
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            &mut pool_controller_handle,
        )
        .await
        {
            Ok(_) => tracing::debug!("fork pool controller shut down cleanly"),
            Err(_) => {
                tracing::warn!("fork pool controller did not shut down within 5 seconds");
                pool_controller_handle.abort();
            }
        }
        let mut supervisor_handle = supervisor_handle;
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut supervisor_handle).await
        {
            Ok(_) => tracing::debug!("supervisor shut down cleanly"),
            Err(_) => {
                tracing::warn!("supervisor did not shut down within 5 seconds");
                supervisor_handle.abort();
            }
        }

        // VMs survive a normal `serve` restart (reconnect on next start), so this
        // is opt-in: on a host teardown (autoscaler scale-in) set
        // SMOLVM_DRAIN_ON_SHUTDOWN to stop running VMs cleanly — flushing disk
        // state — instead of letting the host hard-kill them.
        let drain = std::env::var("SMOLVM_DRAIN_ON_SHUTDOWN")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
        if drain {
            if !smolvm::api::handlers::machines::drain_machines(&drain_state).await {
                tracing::warn!("drain incomplete; preserving remaining VMs for retry");
            }
            drain_state.detach_all();
        } else {
            // Non-draining shutdown (a binary-upgrade restart): VMs must survive
            // for the next `serve` process to reconnect to. Skipping drain isn't
            // enough — `AgentManager::drop` stops any VM it owns, so tearing down
            // `ApiState` would kill every running VM. Disarm each manager's Drop
            // first, mirroring the CLI's detach-before-exit.
            drain_state.detach_all();
        }

        Ok(())
    }

    async fn serve_tcp(
        &self,
        addr: SocketAddr,
        app: Router,
        local_app: Router,
        tls: Option<super::serve_tls::ServeTls>,
        internal_shutdown: tokio::sync::watch::Receiver<bool>,
        grace: std::time::Duration,
    ) -> Result<()> {
        if let Some(tls) = tls {
            return Self::serve_tcp_tls(addr, app, local_app, tls, internal_shutdown, grace).await;
        }

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(smolvm::error::Error::Io)?;

        tracing::info!(address = %addr, "starting HTTP API server");
        println!("smolvm API server listening on http://{}", addr);

        let (signal, started) = signal_and_notice(shutdown_signal_or_internal(internal_shutdown));
        let serve = axum::serve(listener, app).with_graceful_shutdown(signal);
        finish_within_grace(async move { serve.await }, started, grace)
            .await
            .map_err(smolvm::error::Error::Io)
    }

    /// HTTPS variant with mutual TLS (fleet mode). `axum-server`'s rustls
    /// acceptor performs the handshake + client-cert verification configured in
    /// `tls_config`; graceful shutdown is driven through its `Handle` (the
    /// `axum::serve` graceful-shutdown future doesn't apply here).
    ///
    /// Because mTLS locks the whole network port to CA-signed clients, we ALSO
    /// bind a plain-HTTP listener on loopback (see `serve_tls::local_plain_addr`)
    /// so the node's own agent can keep polling `/capacity` locally — it is not
    /// an mTLS client and is unreachable from the network anyway.
    async fn serve_tcp_tls(
        addr: SocketAddr,
        app: Router,
        local_app: Router,
        tls: super::serve_tls::ServeTls,
        internal_shutdown: tokio::sync::watch::Receiver<bool>,
        grace: std::time::Duration,
    ) -> Result<()> {
        // Loopback plain-HTTP door for the local node-agent.
        if let Some(local_addr) = super::serve_tls::local_plain_addr(addr) {
            if !local_addr.ip().is_loopback() {
                return Err(smolvm::error::Error::config(
                    "serve local addr",
                    format!("SMOLVM_SERVE_LOCAL_ADDR {local_addr} must be loopback"),
                ));
            }
            // Bind synchronously, then hand the std listener to a DEDICATED
            // single-thread runtime on its own OS thread. The loopback door's
            // whole job is liveness (`/capacity`), and it must keep answering
            // even when the main multi-thread runtime's reactor stalls under
            // load — which is exactly when the node-agent most needs a truthful
            // answer. Sharing the main runtime lets a stall silently wedge the
            // accept loop (a TCP timeout the agent can't distinguish from a dead
            // node); an isolated reactor turns that into a fast `503` driven by
            // the runtime-liveness heartbeat (see `ApiState::runtime_stalled`).
            let std_listener =
                std::net::TcpListener::bind(local_addr).map_err(smolvm::error::Error::Io)?;
            std_listener
                .set_nonblocking(true)
                .map_err(smolvm::error::Error::Io)?;
            // `local_app` (restricted: liveness/capacity/metrics) is moved in here;
            // it deliberately does NOT carry the /api/v1 machine/file/exec routes.
            tracing::info!(address = %local_addr, "starting loopback HTTP door (local node-agent, isolated runtime)");
            println!(
                "smolvm local API (loopback, plain) on http://{}",
                local_addr
            );
            let local_shutdown = internal_shutdown.clone();
            std::thread::Builder::new()
                .name("smolvm-loopback-api".to_string())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            tracing::error!(error = %e, "loopback door runtime failed to build");
                            return;
                        }
                    };
                    rt.block_on(async move {
                        // Register the listener with THIS runtime's reactor.
                        let listener = match tokio::net::TcpListener::from_std(std_listener) {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::error!(error = %e, "loopback door listener registration failed");
                                return;
                            }
                        };
                        let _ = axum::serve(listener, local_app)
                            .with_graceful_shutdown(shutdown_signal_or_internal(local_shutdown))
                            .await;
                    });
                })
                .map_err(smolvm::error::Error::Io)?;
        }

        // The acceptor tags each connection with its client certificate's
        // identity; the middleware limits clients without full access to the
        // peer blob routes.
        let acceptor = super::serve_tls::IdentityAcceptor::new(&tls);
        let app = app.layer(axum::middleware::from_fn(
            super::serve_tls::enforce_client_identity,
        ));
        match &tls.policy.client_cn {
            Some(cn) => tracing::info!(
                client_cn = %cn,
                allow_peer_blobs = tls.policy.allow_peer_blobs,
                "mTLS client identity restricted by subject CN"
            ),
            None => tracing::warn!(
                "any client certificate signed by the client CA has full API access; \
                 set --mtls-client-cn to restrict it"
            ),
        }
        let handle = axum_server::Handle::new();

        // Trip graceful shutdown on the same signal the plain path observes.
        arm_graceful_shutdown(
            handle.clone(),
            shutdown_signal_or_internal(internal_shutdown),
            grace,
        );

        tracing::info!(address = %addr, "starting HTTPS API server (mTLS, client cert required)");
        println!("smolvm API server listening on https://{} (mTLS)", addr);

        let result = axum_server::bind(addr)
            .acceptor(acceptor)
            .handle(handle)
            .serve(app.into_make_service())
            .await;
        log_requests_cut_off();
        result.map_err(smolvm::error::Error::Io)
    }

    #[cfg(unix)]
    async fn serve_unix(
        &self,
        path: PathBuf,
        app: Router,
        internal_shutdown: tokio::sync::watch::Receiver<bool>,
        grace: std::time::Duration,
    ) -> Result<()> {
        let socket_guard = UnixSocketGuard::bind(&path)?;
        let listener =
            tokio::net::UnixListener::bind(&socket_guard.path).map_err(smolvm::error::Error::Io)?;

        tracing::info!(path = %socket_guard.path.display(), "starting HTTP API server");
        println!(
            "smolvm API server listening on unix://{}",
            socket_guard.path.display()
        );

        let (signal, started) = signal_and_notice(shutdown_signal_or_internal(internal_shutdown));
        let serve = axum::serve(listener, app).with_graceful_shutdown(signal);
        finish_within_grace(async move { serve.await }, started, grace)
            .await
            .map_err(smolvm::error::Error::Io)
    }
}

#[derive(Debug, Clone)]
enum ListenTarget {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ListenTarget {
    fn parse(value: &str) -> Result<Self> {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::Tcp(addr));
        }

        #[cfg(unix)]
        {
            // If the value looks like an intended IP:PORT (contains ':'
            // but failed SocketAddr parsing), report the parse failure
            // rather than silently treating it as a Unix socket path.
            if !value.starts_with("unix://") && !value.starts_with('/') && value.contains(':') {
                return Err(smolvm::error::Error::config(
                    "parse listen address",
                    format!(
                        "invalid address '{}': expected a valid ADDR:PORT or a unix:// path",
                        value
                    ),
                ));
            }
            let path = value.strip_prefix("unix://").unwrap_or(value);
            Ok(Self::Unix(PathBuf::from(path)))
        }

        #[cfg(not(unix))]
        {
            Err(smolvm::error::Error::config(
                "parse listen address",
                format!("invalid address '{}': expected ADDR:PORT", value),
            ))
        }
    }
}

fn default_listen_value() -> String {
    #[cfg(unix)]
    {
        let path = dirs::runtime_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("smolvm.sock")
            .display()
            .to_string();
        format!("unix://{path}")
    }

    #[cfg(not(unix))]
    {
        String::from("127.0.0.1:8080")
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct UnixSocketGuard {
    path: PathBuf,
}

#[cfg(unix)]
impl UnixSocketGuard {
    fn bind(path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(smolvm::error::Error::Io)?;
        }

        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(smolvm::error::Error::Io(e)),
        }

        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %self.path.display(), error = %e, "failed to remove unix socket");
            }
        }
    }
}

/// Wait for shutdown signal.
/// Note: VMs run independently and survive a normal shutdown/restart; they are
/// only stopped when SMOLVM_DRAIN_ON_SHUTDOWN is set (see run_server).
/// Use DELETE /api/v1/machines/:id to stop specific VMs.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "failed to listen for Ctrl+C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
    eprintln!("\nShutting down server (VMs continue running)...");
}

/// Default time a stopping server gives in-flight requests to finish.
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 5;
/// Upper bound on a configured grace, so a typo cannot make a stop hang for days.
const MAX_SHUTDOWN_GRACE_SECS: u64 = 3600;
/// How long a stopped server waits for blocking work its dropped requests left
/// behind before the process exits anyway.
const BLOCKING_WORK_EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a stopping server lets in-flight requests finish before it drops
/// them: `--shutdown-grace`, else `SMOLVM_SERVE_SHUTDOWN_GRACE_SECS`, else 5 s.
/// The server stops accepting connections as soon as it is asked to stop, so a
/// longer grace finishes more of the work already started at the cost of
/// refusing new work for longer.
fn resolve_shutdown_grace(flag: Option<u64>, env: Option<&str>) -> std::time::Duration {
    match flag {
        Some(secs) => std::time::Duration::from_secs(secs.min(MAX_SHUTDOWN_GRACE_SECS)),
        None => parse_shutdown_grace(env),
    }
}

fn parse_shutdown_grace(value: Option<&str>) -> std::time::Duration {
    let secs = value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SHUTDOWN_GRACE_SECS)
        .min(MAX_SHUTDOWN_GRACE_SECS);
    std::time::Duration::from_secs(secs)
}

/// Log what the shutdown is about to cut off (or has cut off): the requests the
/// main API router still counts as in flight.
fn log_inflight(message: &'static str) {
    let s = smolvm::api::inflight::global().snapshot();
    if s.in_flight > 0 || s.open_streams > 0 {
        tracing::warn!(
            in_flight = s.in_flight,
            execs = s.execs,
            open_streams = s.open_streams,
            oldest_ms = s.oldest_ms,
            "{message}"
        );
    }
}

fn log_requests_cut_off() {
    log_inflight("requests still running at the end of the shutdown grace were cut off");
}

/// Start the HTTPS server's graceful shutdown when `signal` resolves: stop
/// accepting, then give in-flight requests `grace` before dropping them.
fn arm_graceful_shutdown<S>(handle: axum_server::Handle, signal: S, grace: std::time::Duration)
where
    S: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        signal.await;
        tracing::info!(
            grace_secs = grace.as_secs(),
            "finishing in-flight requests before exit"
        );
        log_inflight("stopping with requests in flight");
        handle.graceful_shutdown(Some(grace));
    });
}

/// Wrap a shutdown signal so the caller also learns when it fired.
fn signal_and_notice<S>(
    signal: S,
) -> (
    impl std::future::Future<Output = ()> + Send + 'static,
    tokio::sync::oneshot::Receiver<()>,
)
where
    S: std::future::Future<Output = ()> + Send + 'static,
{
    let (fired_tx, fired_rx) = tokio::sync::oneshot::channel();
    let signal = async move {
        signal.await;
        let _ = fired_tx.send(());
    };
    (signal, fired_rx)
}

/// Drive a gracefully-shutting-down plain server, but give up on it `grace`
/// after its shutdown signal fired. axum's own graceful shutdown waits for every
/// open connection without limit, so one long exec would hold the stop open.
async fn finish_within_grace<F>(
    serve: F,
    signal_fired: tokio::sync::oneshot::Receiver<()>,
    grace: std::time::Duration,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    let deadline = async move {
        match signal_fired.await {
            Ok(()) => {
                tracing::info!(
                    grace_secs = grace.as_secs(),
                    "finishing in-flight requests before exit"
                );
                log_inflight("stopping with requests in flight");
                tokio::time::sleep(grace).await
            }
            // The server ended without being asked to stop; let it report why.
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        result = serve => result,
        () = deadline => {
            log_requests_cut_off();
            Ok(())
        }
    }
}

async fn wait_for_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn shutdown_signal_or_internal(shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::select! {
        () = shutdown_signal() => {},
        () = wait_for_shutdown(shutdown) => {},
    }
}

#[cfg(test)]
mod tests {
    use super::ListenTarget;
    use std::time::{Duration, Instant};

    #[test]
    fn a_server_keeps_larger_checkpoint_caches_than_the_cli() {
        use clap::Parser;
        let gib = 1024 * 1024 * 1024;
        let defaults = super::ServeStartCmd::try_parse_from(["serve"]).unwrap();
        let cache =
            super::server_restore_cache(defaults.restore_cache_entries, defaults.restore_cache_gib);
        assert_eq!(cache.entries, 32);
        assert_eq!(cache.max_bytes, 256 * gib);
        assert_eq!(defaults.prepared_checkpoint_cache_gib, 64);
        let cli = smolvm::portable_checkpoint::RestoreCache::default();
        assert!(cache.entries > cli.entries && cache.max_bytes > cli.max_bytes);

        let sized = super::ServeStartCmd::try_parse_from([
            "serve",
            "--restore-cache-entries",
            "0",
            "--restore-cache-gib",
            "512",
            "--prepared-checkpoint-cache-gib",
            "1",
        ])
        .unwrap();
        let cache =
            super::server_restore_cache(sized.restore_cache_entries, sized.restore_cache_gib);
        assert_eq!(cache.entries, 0);
        assert_eq!(cache.max_bytes, 512 * gib);
        assert_eq!(sized.prepared_checkpoint_cache_gib, 1);
        assert!(
            super::ServeStartCmd::try_parse_from(["serve", "--restore-cache-entries", "2000"])
                .is_err()
        );
    }

    #[test]
    fn shutdown_grace_defaults_and_is_bounded() {
        use super::parse_shutdown_grace as grace;
        assert_eq!(grace(None).as_secs(), 5);
        assert_eq!(grace(Some("")).as_secs(), 5);
        assert_eq!(grace(Some("not a number")).as_secs(), 5);
        assert_eq!(grace(Some(" 300 ")).as_secs(), 300);
        assert_eq!(grace(Some("0")).as_secs(), 0);
        assert_eq!(grace(Some("999999")).as_secs(), 3600);
    }

    #[test]
    fn shutdown_grace_flag_wins_over_env() {
        use super::resolve_shutdown_grace as grace;
        assert_eq!(grace(Some(12), Some("300")).as_secs(), 12);
        assert_eq!(grace(Some(0), Some("300")).as_secs(), 0);
        assert_eq!(grace(None, Some("300")).as_secs(), 300);
        assert_eq!(grace(None, None).as_secs(), 5);
        assert_eq!(grace(Some(999_999), None).as_secs(), 3600);
    }

    fn slow_app(delay: Duration) -> axum::Router {
        axum::Router::new().route(
            "/slow",
            axum::routing::get(move || async move {
                tokio::time::sleep(delay).await;
                "done"
            }),
        )
    }

    /// The mTLS server's shutdown path (`arm_graceful_shutdown` driving an
    /// axum-server `Handle`), served over plain TCP so no certificates are
    /// needed. Returns the server task, the address, and the trigger.
    async fn https_style_server(
        handler_delay: Duration,
        grace: Duration,
    ) -> (
        tokio::task::JoinHandle<std::io::Result<()>>,
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = axum_server::Handle::new();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        super::arm_graceful_shutdown(
            handle.clone(),
            async move {
                let _ = stop_rx.await;
            },
            grace,
        );
        let server = tokio::spawn(
            axum_server::from_tcp(listener)
                .handle(handle.clone())
                .serve(slow_app(handler_delay).into_make_service()),
        );
        handle.listening().await.expect("server listening");
        (server, addr, stop_tx)
    }

    /// The Unix-socket/plain-TCP shutdown path (`finish_within_grace` around
    /// axum's own graceful shutdown).
    async fn plain_server(
        handler_delay: Duration,
        grace: Duration,
    ) -> (
        tokio::task::JoinHandle<std::io::Result<()>>,
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (signal, fired) = super::signal_and_notice(async move {
            let _ = stop_rx.await;
        });
        let serve = axum::serve(listener, slow_app(handler_delay)).with_graceful_shutdown(signal);
        let server = tokio::spawn(super::finish_within_grace(
            async move { serve.await },
            fired,
            grace,
        ));
        (server, addr, stop_tx)
    }

    type Reply = tokio::task::JoinHandle<Result<String, String>>;

    /// Send `GET /slow`, ask the server to stop while it runs, and return the
    /// pending reply plus how long the server took to return after being asked
    /// to stop.
    async fn stop_during_request(
        server: tokio::task::JoinHandle<std::io::Result<()>>,
        addr: std::net::SocketAddr,
        stop: tokio::sync::oneshot::Sender<()>,
    ) -> (Reply, Duration) {
        let request = tokio::spawn(async move {
            let response = reqwest::Client::new()
                .get(format!("http://{addr}/slow"))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            response.text().await.map_err(|e| e.to_string())
        });
        // Let the request reach the handler before the stop.
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.send(()).unwrap();
        let asked = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(20), server)
            .await
            .expect("server returned")
            .expect("server task");
        let took = asked.elapsed();
        result.expect("server result");
        // A stopped server refuses new connections.
        assert!(
            reqwest::Client::new()
                .get(format!("http://{addr}/slow"))
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .is_err(),
            "a stopped server must not accept new requests"
        );
        (request, took)
    }

    async fn reply(request: Reply) -> Result<String, String> {
        tokio::time::timeout(Duration::from_secs(20), request)
            .await
            .expect("request finished")
            .expect("request task")
    }

    // A request already running when the stop arrives finishes and its response
    // is delivered, and the server returns as soon as it has, not at the end of
    // the grace.
    #[tokio::test]
    async fn https_shutdown_delivers_an_inflight_response_then_returns() {
        let (server, addr, stop) =
            https_style_server(Duration::from_millis(800), Duration::from_secs(10)).await;
        let (request, took) = stop_during_request(server, addr, stop).await;
        assert_eq!(reply(request).await.as_deref(), Ok("done"));
        assert!(took < Duration::from_secs(3), "returned after {took:?}");
    }

    #[tokio::test]
    async fn plain_shutdown_delivers_an_inflight_response_then_returns() {
        let (server, addr, stop) =
            plain_server(Duration::from_millis(800), Duration::from_secs(10)).await;
        let (request, took) = stop_during_request(server, addr, stop).await;
        assert_eq!(reply(request).await.as_deref(), Ok("done"));
        assert!(took < Duration::from_secs(3), "returned after {took:?}");
    }

    // A request that outlives the grace is dropped and the server returns right
    // after the grace instead of waiting for it.
    #[tokio::test]
    async fn https_shutdown_drops_a_request_that_outlives_the_grace() {
        let (server, addr, stop) =
            https_style_server(Duration::from_secs(60), Duration::from_millis(300)).await;
        let (request, took) = stop_during_request(server, addr, stop).await;
        let response = reply(request).await;
        assert!(response.is_err(), "{response:?}");
        assert!(took < Duration::from_secs(3), "returned after {took:?}");
    }

    #[tokio::test]
    async fn plain_shutdown_drops_a_request_that_outlives_the_grace() {
        let (server, addr, stop) =
            plain_server(Duration::from_secs(60), Duration::from_millis(300)).await;
        let (request, took) = stop_during_request(server, addr, stop).await;
        assert!(took < Duration::from_secs(3), "returned after {took:?}");
        // axum's serve spawns each connection, so the abandoned one ends when the
        // runtime shuts down; the server itself must not have waited for it.
        request.abort();
    }

    // Blocking work left behind by a dropped request (an exec waiting for its
    // command) must not keep the process from exiting.
    #[test]
    fn runtime_exit_does_not_wait_for_abandoned_blocking_work() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(60)));
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let started = Instant::now();
        runtime.shutdown_timeout(super::BLOCKING_WORK_EXIT_WAIT);
        assert!(
            started.elapsed() < super::BLOCKING_WORK_EXIT_WAIT + Duration::from_secs(1),
            "exit waited {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn parse_tcp_listen_target() {
        let target = ListenTarget::parse("127.0.0.1:8080").expect("tcp target should parse");
        match target {
            ListenTarget::Tcp(addr) => assert_eq!(addr.to_string(), "127.0.0.1:8080"),
            #[cfg(unix)]
            ListenTarget::Unix(path) => panic!("expected tcp, got unix path {}", path.display()),
        }
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_listen_target() {
        let target = ListenTarget::parse("/tmp/smol.sock").expect("unix target should parse");
        match target {
            ListenTarget::Unix(path) => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/smol.sock"))
            }
            ListenTarget::Tcp(addr) => panic!("expected unix, got tcp address {addr}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_listen_target_with_prefix() {
        let target =
            ListenTarget::parse("unix:///tmp/smol.sock").expect("unix target should parse");
        match target {
            ListenTarget::Unix(path) => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/smol.sock"))
            }
            ListenTarget::Tcp(addr) => panic!("expected unix, got tcp address {addr}"),
        }
    }
}
