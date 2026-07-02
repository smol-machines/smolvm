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
  POST   /api/v1/machines/:id/stop    Stop machine
  POST   /api/v1/machines/:id/exec    Execute command
  DELETE /api/v1/machines/:id         Delete machine

EXAMPLES:
  smolvm serve start                                Listen on the default Unix socket (unix:///$XDG_RUNTIME_DIR/smolvm.sock)
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
    /// only, `off` disables. x86_64-Linux only; ignored elsewhere. A pre-set
    /// SMOLVM_SECCOMP env var takes precedence.
    #[arg(long, value_name = "MODE", default_value = "enforce")]
    seccomp: String,

    /// Landlock filesystem-confinement mode for VM boot subprocesses: `enforce`
    /// restricts each VMM to its own rootfs/disks/devices (denying the rest of
    /// the host fs), `off` disables. Linux-only; ignored elsewhere. A pre-set
    /// SMOLVM_LANDLOCK env var takes precedence.
    #[arg(long, value_name = "MODE", default_value = "enforce")]
    landlock: String,
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
        //   self-placement; the parent adopts it instead. See
        //   docs/lossless-serve-restart.md.
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
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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

        runtime.block_on(async move { self.run_server(listen_target).await })
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

        // Create shutdown channel for supervisor
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn supervisor task
        let supervisor_state = state.clone();
        let supervisor_shutdown = shutdown_rx.clone();
        let supervisor_handle = tokio::spawn(async move {
            let supervisor =
                smolvm::api::supervisor::Supervisor::new(supervisor_state, supervisor_shutdown);
            supervisor.run().await;
        });

        // Create router
        let drain_state = state.clone();
        let app = smolvm::api::create_router(state, self.cors_origins.clone());

        // Resolve the serve API's TLS posture before binding. In fleet mode this
        // is fail-closed: a missing/partial mTLS config aborts startup rather
        // than silently serving plain HTTP (control↔node mTLS, increment 3).
        let tls = super::serve_tls::resolve_tls().map_err(|e| smolvm::error::Error::Config {
            operation: "serve tls".to_string(),
            reason: e.to_string(),
        })?;

        // Listen server on TCP or Unix socket
        match listen_target {
            ListenTarget::Tcp(addr) => self.serve_tcp(addr, app, tls).await?,
            #[cfg(unix)]
            ListenTarget::Unix(path) => self.serve_unix(path, app).await?,
        }

        // The HTTP server has stopped accepting (graceful shutdown on SIGTERM).
        // VMs survive a normal `serve` restart (reconnect on next start), so this
        // is opt-in: on a host teardown (autoscaler scale-in) set
        // SMOLVM_DRAIN_ON_SHUTDOWN to stop running VMs cleanly — flushing disk
        // state — instead of letting the host hard-kill them.
        let drain = std::env::var("SMOLVM_DRAIN_ON_SHUTDOWN")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
        if drain {
            smolvm::api::handlers::machines::drain_machines(&drain_state).await;
        } else {
            // Non-draining shutdown (a binary-upgrade restart): VMs must survive
            // for the next `serve` process to reconnect to. Skipping drain isn't
            // enough — `AgentManager::drop` stops any VM it owns, so tearing down
            // `ApiState` would kill every running VM. Disarm each manager's Drop
            // first, mirroring the CLI's detach-before-exit.
            drain_state.detach_all();
        }

        // Signal all background tasks to stop
        let _ = shutdown_tx.send(true);

        // Wait for supervisor to finish (with timeout)
        match tokio::time::timeout(std::time::Duration::from_secs(5), supervisor_handle).await {
            Ok(_) => tracing::debug!("supervisor shut down cleanly"),
            Err(_) => tracing::warn!("supervisor did not shut down within 5 seconds"),
        }

        Ok(())
    }

    async fn serve_tcp(
        &self,
        addr: SocketAddr,
        app: Router,
        tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    ) -> Result<()> {
        if let Some(tls_config) = tls {
            return Self::serve_tcp_tls(addr, app, tls_config).await;
        }

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(smolvm::error::Error::Io)?;

        tracing::info!(address = %addr, "starting HTTP API server");
        println!("smolvm API server listening on http://{}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
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
        tls_config: std::sync::Arc<rustls::ServerConfig>,
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
            let local_app = app.clone();
            tracing::info!(address = %local_addr, "starting loopback HTTP door (local node-agent, isolated runtime)");
            println!(
                "smolvm local API (loopback, plain) on http://{}",
                local_addr
            );
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
                            .with_graceful_shutdown(shutdown_signal())
                            .await;
                    });
                })
                .map_err(smolvm::error::Error::Io)?;
        }

        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);
        let handle = axum_server::Handle::new();

        // Trip graceful shutdown on the same signal the plain path observes.
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });

        tracing::info!(address = %addr, "starting HTTPS API server (mTLS, client cert required)");
        println!("smolvm API server listening on https://{} (mTLS)", addr);

        axum_server::bind_rustls(addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .map_err(smolvm::error::Error::Io)
    }

    #[cfg(unix)]
    async fn serve_unix(&self, path: PathBuf, app: Router) -> Result<()> {
        let socket_guard = UnixSocketGuard::bind(&path)?;
        let listener =
            tokio::net::UnixListener::bind(&socket_guard.path).map_err(smolvm::error::Error::Io)?;

        tracing::info!(path = %socket_guard.path.display(), "starting HTTP API server");
        println!(
            "smolvm API server listening on unix://{}",
            socket_guard.path.display()
        );

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
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

#[cfg(test)]
mod tests {
    use super::ListenTarget;

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
