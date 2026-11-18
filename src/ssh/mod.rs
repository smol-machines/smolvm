//! On-demand SSH connections carried by the invoking client's standard I/O.
mod context;
mod forward;
mod guest;
mod handler;
mod identity;
#[cfg(unix)]
pub(crate) mod ownership;
mod startup;
mod transport;

use anyhow::{Context, Result};
use russh::{
    keys::{PrivateKey, PublicKey},
    server,
};
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
};

/// Files and host alias used by standard SSH clients for one machine.
pub use identity::Connection;

/// Create or reuse private per-machine keys and generate an SSH client config.
pub fn configure(machine: &str) -> Result<Connection> {
    identity::configure(machine)
}

/// Apply only the generated proxy's non-secret path context during CLI startup.
/// Call on the initial thread, before resolving paths or starting any threads.
pub fn apply_proxy_context(args: &[std::ffi::OsString]) -> Result<()> {
    context::apply(args)
}

/// Validate the already-applied context and saved identity before starting a VM.
pub fn proxy_machine(encoded: &str) -> Result<String> {
    let selected = context::Context::applied(encoded)?;
    let expected = PublicKey::from_openssh(&selected.host_key)?;
    identity::verify(&selected.machine, &expected)?;
    Ok(selected.machine)
}

/// Serve one authenticated SSH connection, returning when its client exits.
///
/// This owns its runtime so canceled standard-I/O reads cannot keep the CLI
/// alive during runtime shutdown; guest workers are reaped before shutdown.
pub fn proxy(machine: &str) -> Result<()> {
    let keys = identity::load(machine)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    let result = runtime.block_on(async {
        let mut interrupts = startup::Interrupts::new()?;
        let input = startup::prepare(machine, tokio::io::stdin(), &mut interrupts).await?;
        let manager = crate::agent::AgentManager::for_vm(machine)?;
        let mut client = crate::agent::AgentClient::connect(manager.vsock_socket())?;
        anyhow::ensure!(
            client.supports_capability(crate::agent::interactive_control::CAPABILITY)?,
            "this running machine needs an updated runtime before using SSH"
        );
        drop(client);
        serve(
            machine.to_string(),
            keys.0,
            keys.1,
            tokio::io::join(input, tokio::io::stdout()),
            &mut interrupts,
        )
        .await
    });
    // Tokio's standard-I/O implementation uses blocking OS reads, which cannot
    // always be canceled. They belong only to this short-lived proxy process.
    runtime.shutdown_background();
    result
}

async fn serve<T>(
    machine: String,
    host: PrivateKey,
    allowed: PublicKey,
    stream: T,
    interrupts: &mut startup::Interrupts,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let expected_host = Arc::new(host.public_key().clone());
    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::PublicKey);
    let config = Arc::new(server::Config {
        keys: vec![host],
        methods,
        window_size: handler::WINDOW as u32,
        maximum_packet_size: 32768,
        manual_receive_window: true,
        channel_buffer_size: 1,
        event_buffer_size: 32,
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: 3,
        inactivity_timeout: None,
        ..Default::default()
    });
    let metrics = Arc::new(handler::Metrics::default());
    let (authenticated, auth) = oneshot::channel();
    let handler = handler::Handler {
        machine,
        expected_host,
        allowed: Arc::new(allowed),
        authenticated: Some(authenticated),
        inputs: HashMap::new(),
        metrics: metrics.clone(),
    };
    let cancellation = transport::Cancellation::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let started = tokio::select! {
        started = tokio::time::timeout_at(deadline, server::run_stream(config, cancellation.wrap(stream), handler)) => Some(started),
        _ = interrupts.wait() => None,
    };
    let result = match started {
        Some(Ok(Ok(mut running))) => {
            let ready = tokio::select! {
                finished = &mut running => Some(finished.map_err(anyhow::Error::from)),
                _ = interrupts.wait() => Some(Ok(())),
                authenticated = tokio::time::timeout_at(deadline, auth) => {
                    if matches!(authenticated, Ok(Ok(()))) { None }
                    else { Some(Err(anyhow::anyhow!("SSH authentication timed out"))) }
                }
            };
            match ready {
                Some(result) => {
                    cancellation.cancel();
                    result
                }
                None => tokio::select! {
                    finished = &mut running => finished.map_err(anyhow::Error::from),
                    _ = interrupts.wait() => {
                        cancellation.cancel();
                        let _ = tokio::time::timeout(Duration::from_secs(3), &mut running).await;
                        Ok(())
                    }
                },
            }
        }
        Some(Ok(Err(error))) => Err(error.into()),
        Some(Err(_)) => Err(anyhow::anyhow!("SSH handshake timed out")),
        None => Ok(()),
    };
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(3), async {
        while metrics.channels.load(Ordering::SeqCst) != 0
            || metrics.guest_threads.load(Ordering::SeqCst) != 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("SSH guest cleanup did not finish")?;
    result
}
