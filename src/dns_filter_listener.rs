//! Host-side DNS filter listener.
//!
//! Starts a Unix socket listener that accepts connections from the guest
//! DNS proxy and filters DNS queries against a hostname allowlist.

use crate::dns_filter::{handle_connection, DnsFilter};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;

/// Start the DNS filter listener on a Unix socket.
///
/// The listener runs in a background thread and handles DNS queries from
/// the guest agent's DNS proxy.
///
/// The caller should pass the socket path to `LaunchConfig::dns_filter_socket`
/// so libkrun maps it to vsock port 6002.
pub fn start(socket_path: &Path, allowed_hosts: Vec<String>) -> std::io::Result<()> {
    // Clean up stale socket
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;

    let filter = Arc::new(DnsFilter::new(
        allowed_hosts,
        crate::data::network::DEFAULT_DNS.to_string(),
    ));

    let path_display = socket_path.display().to_string();

    thread::Builder::new()
        .name("dns-filter-host".into())
        .spawn(move || {
            tracing::info!(path = path_display, "DNS filter listener started");

            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let filter = Arc::clone(&filter);
                        if let Err(e) = handle_connection(&filter, &mut stream) {
                            tracing::debug!(error = %e, "DNS filter connection error");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "DNS filter accept error");
                    }
                }
            }
        })?;

    Ok(())
}
