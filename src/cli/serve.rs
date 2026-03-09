//! HTTP API server command.

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;

use smolvm::api::state::ApiState;
use smolvm::Result;

use super::openapi::OpenapiCmd;

/// Start the HTTP API server for programmatic control.
#[derive(Parser, Debug)]
#[command(about = "Start the HTTP API server for programmatic sandbox management")]
pub enum ServeCmd {
    /// Start the HTTP API server
    #[command(after_long_help = "\
Sandboxes persist independently of the server - they continue running even if the server stops.

API ENDPOINTS:
  GET    /health                       Health check
  POST   /api/v1/sandboxes             Create sandbox
  GET    /api/v1/sandboxes             List sandboxes
  GET    /api/v1/sandboxes/:id         Get sandbox status
  POST   /api/v1/sandboxes/:id/start   Start sandbox
  POST   /api/v1/sandboxes/:id/stop    Stop sandbox
  POST   /api/v1/sandboxes/:id/exec    Execute command
  DELETE /api/v1/sandboxes/:id         Delete sandbox

EXAMPLES:
  smolvm serve start                         Listen on 127.0.0.1:8080 (default)
  smolvm serve start -l 0.0.0.0:9000         Listen on all interfaces, port 9000
  smolvm serve start -v                      Enable verbose logging")]
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
    /// Address and port to listen on
    #[arg(
        short,
        long,
        default_value = "127.0.0.1:8080",
        value_name = "ADDR:PORT"
    )]
    listen: String,

    /// Enable debug logging (or set RUST_LOG=debug)
    #[arg(short, long)]
    verbose: bool,

    /// CORS allowed origins (repeatable). Defaults to localhost:8080 and localhost:3000.
    #[arg(long = "cors-origin", value_name = "ORIGIN")]
    cors_origins: Vec<String>,
}

impl ServeStartCmd {
    /// Run the serve command.
    pub fn run(self) -> Result<()> {
        // Parse listen address
        let addr: SocketAddr = self.listen.parse().map_err(|e| {
            smolvm::error::Error::config(
                "parse listen address",
                format!("invalid address '{}': {}", self.listen, e),
            )
        })?;

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

        runtime.block_on(async move { self.run_server(addr).await })
    }

    async fn run_server(self, addr: SocketAddr) -> Result<()> {
        // Security warning if binding to all interfaces
        if addr.ip().is_unspecified() {
            eprintln!(
                "WARNING: Server is listening on all interfaces ({}).",
                addr.ip()
            );
            eprintln!("         The API has no authentication - any network client can control this host.");
            eprintln!("         Consider using --listen 127.0.0.1:8080 for local-only access.");
        }

        // Create shared state and load persisted sandboxes
        let state = Arc::new(ApiState::new().map_err(|e| {
            smolvm::error::Error::config("initialize api state", format!("{:?}", e))
        })?);
        let loaded = state.load_persisted_sandboxes();
        if !loaded.is_empty() {
            println!(
                "Reconnected to {} existing sandbox(es): {}",
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
        let app = smolvm::api::create_router(state, self.cors_origins);

        // Create listener
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(smolvm::error::Error::Io)?;

        tracing::info!(address = %addr, "starting HTTP API server");
        println!("smolvm API server listening on http://{}", addr);

        // Run the server with graceful shutdown (VMs keep running independently)
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(smolvm::error::Error::Io)?;

        // Signal supervisor to stop
        let _ = shutdown_tx.send(true);

        // Wait for supervisor to finish (with timeout)
        match tokio::time::timeout(std::time::Duration::from_secs(5), supervisor_handle).await {
            Ok(_) => tracing::debug!("supervisor shut down cleanly"),
            Err(_) => tracing::warn!("supervisor did not shut down within 5 seconds"),
        }

        Ok(())
    }
}

/// Wait for shutdown signal.
/// Note: VMs are NOT stopped on server shutdown - they run independently.
/// Use DELETE /api/v1/sandboxes/:id to stop specific VMs.
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
