//! HTTP API server command.

use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
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
}

impl ServeStartCmd {
    /// Run the serve command.
    pub fn run(self) -> Result<()> {
        // Set JSON log format for the logging initializer to pick up
        if self.json_logs {
            std::env::set_var("SMOLVM_LOG_FORMAT", "json");
        }

        let listen_target = ListenTarget::parse(&self.listen)?;

        // Set up verbose logging if requested
        if self.verbose {
            // Re-initialize logging at debug level
            // Note: This won't work if logging is already initialized,
            // but the RUST_LOG env var can be used instead
            tracing::info!("verbose logging enabled");
        }

        // Create the runtime with signal handling enabled
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(smolvm::error::Error::Io)?;

        runtime.block_on(async move { self.run_server(listen_target).await })
    }

    async fn run_server(self, listen_target: ListenTarget) -> Result<()> {
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

        // Install SIGCHLD handler to reap zombie VM child processes.
        smolvm::process::install_sigchld_handler();

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

        // Create shutdown channel for supervisor
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn supervisor task
        let supervisor_state = state.clone();
        let supervisor_handle = tokio::spawn(async move {
            let supervisor =
                smolvm::api::supervisor::Supervisor::new(supervisor_state, shutdown_rx);
            supervisor.run().await;
        });

        // Create router
        let app = smolvm::api::create_router(state, self.cors_origins.clone());

        // Listen server on TCP or Unix socket
        match listen_target {
            ListenTarget::Tcp(addr) => self.serve_tcp(addr, app).await?,
            #[cfg(unix)]
            ListenTarget::Unix(path) => self.serve_unix(path, app).await?,
        }

        // Signal supervisor to stop
        let _ = shutdown_tx.send(true);

        // Wait for supervisor to finish (with timeout)
        match tokio::time::timeout(std::time::Duration::from_secs(5), supervisor_handle).await {
            Ok(_) => tracing::debug!("supervisor shut down cleanly"),
            Err(_) => tracing::warn!("supervisor did not shut down within 5 seconds"),
        }

        Ok(())
    }

    async fn serve_tcp(&self, addr: SocketAddr, app: Router) -> Result<()> {
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
/// Note: VMs are NOT stopped on server shutdown - they run independently.
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
