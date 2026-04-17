//! vsock client for communicating with the smolvm-agent.
//!
//! This module provides a client for sending requests to the agent
//! and receiving responses.

use crate::error::{Error, Result};
use crate::registry::{extract_registry, rewrite_image_registry, RegistryAuth, RegistryConfig};
use smolvm_protocol::{
    encode_message, AgentRequest, AgentResponse, Envelope, ImageInfo, OverlayInfo, StorageStatus,
    FILE_TRANSFER_MAX_TOTAL, FILE_WRITE_CHUNK_SIZE, FILE_WRITE_SINGLE_SHOT_MAX, MAX_FRAME_SIZE,
    PROTOCOL_VERSION,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Events from a streaming exec session.
#[derive(Debug, Clone)]
pub enum ExecEvent {
    /// Standard output data.
    Stdout(Vec<u8>),
    /// Standard error data.
    Stderr(Vec<u8>),
    /// Command exited with this code.
    Exit(i32),
    /// An error occurred.
    Error(String),
}

// ============================================================================
// Socket Timeout Constants
// ============================================================================
//
// These timeouts control how long the client waits for various operations.
// They balance between allowing slow operations to complete and failing fast
// when the agent is unresponsive.

/// Default socket read timeout (30 seconds).
/// Used for most request/response operations. Long enough for the agent to
/// process requests, short enough to detect hung connections.
const DEFAULT_READ_TIMEOUT_SECS: u64 = 30;

/// Default socket write timeout (10 seconds).
/// Writes should complete quickly - if they don't, the connection is likely broken.
const DEFAULT_WRITE_TIMEOUT_SECS: u64 = 10;

/// Read timeout for image pull operations (10 minutes).
/// Image pulls can take a long time for large images over slow connections.
const IMAGE_PULL_TIMEOUT_SECS: u64 = 600;

// (Removed INTERACTIVE_TIMEOUT_SECS — no-user-timeout execs now disable
// the socket read timeout entirely, matching interactive_session behavior.)

/// Buffer time added to user-specified timeouts (5 seconds).
/// When users specify a command timeout, we add this buffer to the socket
/// timeout to allow for protocol overhead and response transmission.
const TIMEOUT_BUFFER_SECS: u64 = 5;

/// Timeout for shutdown acknowledgment (5 seconds).
/// sync() + ack transmission is typically <100ms, but heavy writes or
/// large journals may take longer. If no ack within 5s, the VM has
/// likely already torn down — safe to proceed with SIGTERM.
const SHUTDOWN_ACK_TIMEOUT_SECS: u64 = 5;

// ============================================================================
// I/O Constants
// ============================================================================

/// Buffer size for reading stdin during interactive sessions.
const STDIN_BUF_SIZE: usize = 4096;

/// Poll timeout in milliseconds for interactive I/O loops.
/// Short enough for responsive SIGWINCH handling, long enough to avoid busy-waiting.
const POLL_TIMEOUT_MS: i32 = 100;

/// RAII guard that resets the socket read timeout on drop.
///
/// Ensures the timeout is always restored, even if the operation
/// returns early due to an error. Uses a cloned UnixStream handle
/// (shares the underlying fd) to avoid borrow conflicts.
pub struct ReadTimeoutGuard {
    stream: UnixStream,
}

impl ReadTimeoutGuard {
    /// Create a guard from a reference to the stream.
    /// Clones the underlying fd so the guard doesn't borrow the original.
    fn new(stream: &UnixStream) -> Option<Self> {
        stream.try_clone().ok().map(|s| Self { stream: s })
    }
}

impl Drop for ReadTimeoutGuard {
    fn drop(&mut self) {
        if let Err(e) = self
            .stream
            .set_read_timeout(Some(Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS)))
        {
            tracing::warn!(error = %e, "failed to reset socket read timeout to default");
        }
    }
}

/// Configuration for running a command interactively.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// OCI image to run.
    pub image: String,
    /// Command and arguments to execute.
    pub command: Vec<String>,
    /// Environment variables as (key, value) pairs.
    pub env: Vec<(String, String)>,
    /// Working directory inside the container.
    pub workdir: Option<String>,
    /// Volume mounts as (tag, guest_path, read_only) tuples.
    pub mounts: Vec<(String, String, bool)>,
    /// Timeout for command execution.
    pub timeout: Option<Duration>,
    /// Whether to allocate a TTY.
    pub tty: bool,
    /// Persistent overlay ID. If set, the overlay persists across exec sessions
    /// so filesystem changes (e.g. package installs) survive.
    pub persistent_overlay_id: Option<String>,
}

impl RunConfig {
    /// Create a new run configuration with the given image and command.
    pub fn new(image: impl Into<String>, command: Vec<String>) -> Self {
        Self {
            image: image.into(),
            command,
            env: Vec::new(),
            workdir: None,
            mounts: Vec::new(),
            timeout: None,
            tty: false,
            persistent_overlay_id: None,
        }
    }

    /// Set environment variables.
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// Set working directory.
    pub fn with_workdir(mut self, workdir: Option<String>) -> Self {
        self.workdir = workdir;
        self
    }

    /// Set volume mounts.
    pub fn with_mounts(mut self, mounts: Vec<(String, String, bool)>) -> Self {
        self.mounts = mounts;
        self
    }

    /// Set timeout.
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable TTY mode.
    pub fn with_tty(mut self, tty: bool) -> Self {
        self.tty = tty;
        self
    }

    /// Set persistent overlay ID for cross-session filesystem persistence.
    pub fn with_persistent_overlay(mut self, id: Option<String>) -> Self {
        self.persistent_overlay_id = id;
        self
    }
}

/// Options for pulling an OCI image.
///
/// Use `PullOptions::new()` to create with defaults, then chain methods
/// to customize behavior.
///
/// # Example
///
/// ```ignore
/// let options = PullOptions::new()
///     .oci_platform("linux/arm64")
///     .use_registry_config(true)
///     .progress(|cur, total, layer| println!("{}/{}: {}", cur, total, layer));
///
/// client.pull("alpine:latest", options)?;
/// ```
#[derive(Default)]
pub struct PullOptions<F = fn(usize, usize, &str)>
where
    F: FnMut(usize, usize, &str),
{
    /// OCI platform to pull (e.g., "linux/arm64").
    pub oci_platform: Option<String>,
    /// Explicit authentication credentials.
    pub auth: Option<RegistryAuth>,
    /// Whether to load credentials from registry config file.
    pub use_registry_config: bool,
    /// Progress callback: (current, total, layer_id).
    pub progress: Option<F>,
}

impl PullOptions<fn(usize, usize, &str)> {
    /// Create new pull options with defaults.
    pub fn new() -> Self {
        Self {
            oci_platform: None,
            auth: None,
            use_registry_config: false,
            progress: None,
        }
    }
}

impl<F: FnMut(usize, usize, &str)> PullOptions<F> {
    /// Set the target OCI platform (e.g., "linux/arm64").
    pub fn oci_platform(mut self, oci_platform: impl Into<String>) -> Self {
        self.oci_platform = Some(oci_platform.into());
        self
    }

    /// Set explicit authentication credentials.
    pub fn auth(mut self, auth: RegistryAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Enable loading credentials from registry config file.
    ///
    /// When enabled, loads `~/.config/smolvm/registries.toml` and
    /// automatically provides credentials for matching registries.
    /// Also applies registry mirrors if configured.
    pub fn use_registry_config(mut self, enabled: bool) -> Self {
        self.use_registry_config = enabled;
        self
    }

    /// Set a progress callback.
    ///
    /// The callback receives (current_percent, total=100, layer_id) for each layer.
    pub fn progress<G: FnMut(usize, usize, &str)>(self, callback: G) -> PullOptions<G> {
        PullOptions {
            oci_platform: self.oci_platform,
            auth: self.auth,
            use_registry_config: self.use_registry_config,
            progress: Some(callback),
        }
    }
}

/// Check if a shutdown receive error is a benign race condition.
///
/// During shutdown the VM may tear down before the ack response is flushed,
/// causing EAGAIN, connection reset, or similar errors. These are expected
/// and don't indicate a problem — sync() has likely already completed.
fn is_benign_shutdown_error(error_str: &str) -> bool {
    error_str.contains("os error 35") // EAGAIN on macOS
        || error_str.contains("os error 11") // EAGAIN on Linux
        || error_str.contains("temporarily unavailable")
        || error_str.contains("Connection reset")
        || error_str.contains("connection reset")
}

/// Client for communicating with the smolvm-agent.
pub struct AgentClient {
    stream: UnixStream,
    /// Trace ID for correlating this client session's requests with host API calls.
    trace_id: Option<String>,
}

// ============================================================================
// Response match helpers
// ============================================================================

/// Extract typed data from an `Ok` response.
fn expect_data<T: serde::de::DeserializeOwned>(resp: AgentResponse, op: &str) -> Result<T> {
    match resp {
        AgentResponse::Ok {
            data: Some(data), ..
        } => {
            serde_json::from_value(data).map_err(|e| Error::agent("parse response", e.to_string()))
        }
        AgentResponse::Error { message, .. } => Err(Error::agent(op, message)),
        _ => Err(Error::agent(op, "unexpected response type")),
    }
}

/// Expect an `Ok` response, ignoring any data.
fn expect_ok(resp: AgentResponse, op: &str) -> Result<()> {
    match resp {
        AgentResponse::Ok { .. } => Ok(()),
        AgentResponse::Error { message, .. } => Err(Error::agent(op, message)),
        _ => Err(Error::agent(op, "unexpected response type")),
    }
}

/// Extract exit code, stdout, stderr from a `Completed` response.
fn expect_completed(resp: AgentResponse, op: &str) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    match resp {
        AgentResponse::Completed {
            exit_code,
            stdout,
            stderr,
        } => Ok((exit_code, stdout, stderr)),
        AgentResponse::Error { message, .. } => Err(Error::agent(op, message)),
        _ => Err(Error::agent(op, "unexpected response type")),
    }
}

impl AgentClient {
    /// Set socket read timeout, returning an error if it fails.
    ///
    /// This is a helper to ensure timeout failures are always handled properly,
    /// preventing indefinite hangs on read operations.
    fn set_read_timeout(&self, timeout: Duration) -> Result<()> {
        self.stream.set_read_timeout(Some(timeout)).map_err(|e| {
            Error::agent(
                "set read timeout",
                format!("failed to set socket read timeout to {:?}: {}", timeout, e),
            )
        })
    }

    /// Connect to the agent via Unix socket.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the vsock Unix socket
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection to the socket fails
    /// - Socket timeouts cannot be configured (prevents indefinite hangs)
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self> {
        Self::connect_once(socket_path.as_ref())
    }

    /// Connect to the agent with retry logic for transient failures.
    ///
    /// This is useful when the agent might be temporarily unavailable
    /// (e.g., during high load or brief network issues).
    pub fn connect_with_retry(socket_path: impl AsRef<Path>) -> Result<Self> {
        use crate::util::{retry_with_backoff, RetryConfig};

        let path = socket_path.as_ref();

        retry_with_backoff(
            RetryConfig::for_connection(),
            "agent connect",
            || Self::connect_once(path),
            |e| {
                // Check if this is a transient error worth retrying
                let error_msg = e.to_string();
                // Connection refused/reset are transient during VM startup
                error_msg.contains("Connection refused")
                    || error_msg.contains("connection refused")
                    || error_msg.contains("Connection reset")
                    || error_msg.contains("connection reset")
                    || error_msg.contains("Broken pipe")
                    || error_msg.contains("Resource temporarily unavailable")
            },
        )
    }

    /// Connect with a short timeout, for use during startup ping probes.
    /// Uses 100ms read timeout instead of 30s to fail fast during boot.
    /// The agent completes init in ~130ms of guest uptime, so 100ms is enough
    /// to detect a ready agent without wasting time on a full 1s timeout.
    pub fn connect_with_short_timeout(socket_path: impl AsRef<Path>) -> Result<Self> {
        Self::connect_with_timeouts_ms(socket_path.as_ref(), 100, 100)
    }

    /// Connect with a moderate timeout, for state-probe "is this agent alive"
    /// checks from `machine ls` / `machine status`. 3 seconds is long enough
    /// to avoid false "unreachable" readings when the agent is momentarily
    /// busy (e.g., processing a Run request's overlayfs setup), but short
    /// enough to not make `ls` feel sluggish when the agent is truly dead.
    pub fn connect_for_state_probe(socket_path: impl AsRef<Path>) -> Result<Self> {
        Self::connect_with_timeouts_ms(socket_path.as_ref(), 3000, 3000)
    }

    /// Connect with a very short timeout for boot-time probe cycles.
    /// Uses 5ms timeout to minimize blocking between ready-marker checks.
    /// Only used in the fallback path (old agents without ready markers).
    pub fn connect_with_boot_probe_timeout(socket_path: impl AsRef<Path>) -> Result<Self> {
        Self::connect_with_timeouts_ms(socket_path.as_ref(), 5, 5)
    }

    /// Internal connect implementation (single attempt).
    fn connect_once(socket_path: &Path) -> Result<Self> {
        Self::connect_with_timeouts(
            socket_path,
            DEFAULT_READ_TIMEOUT_SECS,
            DEFAULT_WRITE_TIMEOUT_SECS,
        )
    }

    /// Connect to the agent socket and configure read/write timeouts (in seconds).
    fn connect_with_timeouts(socket_path: &Path, read_secs: u64, write_secs: u64) -> Result<Self> {
        Self::connect_with_timeouts_ms(socket_path, read_secs * 1000, write_secs * 1000)
    }

    /// Connect to the agent socket and configure read/write timeouts (in milliseconds).
    fn connect_with_timeouts_ms(socket_path: &Path, read_ms: u64, write_ms: u64) -> Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|e| Error::agent("connect to agent", e.to_string()))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(read_ms)))
            .map_err(|e| Error::agent("set read timeout", e.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_millis(write_ms)))
            .map_err(|e| Error::agent("set write timeout", e.to_string()))?;

        Ok(Self {
            stream,
            trace_id: None,
        })
    }

    /// Set a trace ID for correlating this client session's requests with host API calls.
    /// All subsequent requests will include this trace_id in the Envelope.
    pub fn set_trace_id(&mut self, trace_id: String) {
        self.trace_id = Some(trace_id);
    }

    /// Encode a request wrapped in an Envelope with the current trace_id.
    fn encode_traced(&self, req: &AgentRequest) -> Result<Vec<u8>> {
        let envelope = Envelope::with_trace_id(req, self.trace_id.clone());
        encode_message(&envelope).map_err(|e| Error::agent("encode message", e.to_string()))
    }

    /// Send a request and receive a response.
    fn request(&mut self, req: &AgentRequest) -> Result<AgentResponse> {
        // Encode and send request
        let data = self.encode_traced(req)?;
        self.stream
            .write_all(&data)
            .map_err(|e| Error::agent("send message", e.to_string()))?;

        // Read response
        self.receive()
    }

    /// Ping the helper daemon and validate the protocol version.
    ///
    /// Returns the agent's protocol version. Logs a warning if the version
    /// doesn't match the host's expected version.
    pub fn ping(&mut self) -> Result<u32> {
        let resp = self.request(&AgentRequest::Ping)?;

        match resp {
            AgentResponse::Pong { version } => {
                if version != PROTOCOL_VERSION {
                    tracing::warn!(
                        host_version = PROTOCOL_VERSION,
                        agent_version = version,
                        "protocol version mismatch — agent may be outdated or newer than host"
                    );
                }
                Ok(version)
            }
            AgentResponse::Error { message, .. } => Err(Error::agent("ping", message)),
            _ => Err(Error::agent("ping", "unexpected response type")),
        }
    }

    /// Pull an OCI image with the given options.
    ///
    /// This is the primary pull method. Use `PullOptions` to configure
    /// authentication, platform, and progress tracking.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Simple pull
    /// client.pull("alpine:latest", PullOptions::new())?;
    ///
    /// // Pull with registry config (loads credentials from config file)
    /// client.pull("ghcr.io/owner/repo", PullOptions::new().use_registry_config(true))?;
    ///
    /// // Pull with explicit auth and progress
    /// client.pull("private.registry/image", PullOptions::new()
    ///     .auth(RegistryAuth { username: "user".into(), password: "pass".into() })
    ///     .progress(|cur, total, layer| eprintln!("{}%", cur)))?;
    /// ```
    ///
    /// # Note
    ///
    /// This operation uses a 10-minute timeout to accommodate large images.
    pub fn pull<F: FnMut(usize, usize, &str)>(
        &mut self,
        image: &str,
        options: PullOptions<F>,
    ) -> Result<ImageInfo> {
        // Resolve effective image and auth based on options
        let (effective_image, effective_auth) = if options.use_registry_config {
            let registry_config = RegistryConfig::load().unwrap_or_default();
            let registry = extract_registry(image);

            // Get credentials from config if not explicitly provided
            let auth = options.auth.or_else(|| {
                registry_config.get_credentials(&registry).inspect(|creds| {
                    tracing::debug!(
                        registry = %registry,
                        username = %creds.username,
                        "using configured registry credentials"
                    );
                })
            });

            // Apply mirror if configured
            let img = if let Some(mirror) = registry_config.get_mirror(&registry) {
                let mirrored = rewrite_image_registry(image, mirror);
                tracing::debug!(
                    original = %image,
                    mirrored = %mirrored,
                    mirror = %mirror,
                    "using registry mirror"
                );
                mirrored
            } else {
                image.to_string()
            };

            (img, auth)
        } else {
            (image.to_string(), options.auth)
        };

        self.pull_image_internal(
            &effective_image,
            options.oci_platform.as_deref(),
            effective_auth.as_ref(),
            options.progress,
        )
    }

    /// Internal implementation of image pull.
    fn pull_image_internal<F: FnMut(usize, usize, &str)>(
        &mut self,
        image: &str,
        oci_platform: Option<&str>,
        auth: Option<&RegistryAuth>,
        mut progress: Option<F>,
    ) -> Result<ImageInfo> {
        // Use a long timeout for pull - large images can take minutes to download/extract.
        // The guard resets the timeout on drop (including error paths).
        self.set_read_timeout(Duration::from_secs(IMAGE_PULL_TIMEOUT_SECS))?;
        let _timeout_guard = ReadTimeoutGuard::new(&self.stream);

        // Send the pull request
        let data = self.encode_traced(&AgentRequest::Pull {
            image: image.to_string(),
            oci_platform: oci_platform.map(String::from),
            auth: auth.cloned(),
        })?;

        self.stream
            .write_all(&data)
            .map_err(|e| Error::agent("send request", e.to_string()))?;

        // Read responses - loop until we get Ok or Error (skip Progress)
        loop {
            match self.receive()? {
                AgentResponse::Progress {
                    percent,
                    layer,
                    message: _,
                } => {
                    if let Some(ref mut cb) = progress {
                        let current = percent.unwrap_or(0) as usize;
                        let layer_id = layer.as_deref().unwrap_or("");
                        cb(current, 100, layer_id);
                    }
                }
                AgentResponse::Ok { data: Some(data) } => {
                    return serde_json::from_value(data)
                        .map_err(|e| Error::agent("parse response", e.to_string()));
                }
                AgentResponse::Error { message, .. } => {
                    return Err(Error::agent("pull image", message));
                }
                _ => {
                    return Err(Error::agent("pull image", "unexpected response type"));
                }
            }
        }
    }

    // =========================================================================
    // Convenience methods for common pull patterns
    // =========================================================================

    /// Pull an OCI image with default options.
    ///
    /// Shorthand for `pull(image, PullOptions::new())`.
    pub fn pull_simple(&mut self, image: &str) -> Result<ImageInfo> {
        self.pull(image, PullOptions::new())
    }

    /// Pull an OCI image with automatic registry credential lookup.
    ///
    /// Loads credentials from `~/.config/smolvm/registries.toml` and applies
    /// registry mirrors if configured.
    ///
    /// Shorthand for `pull(image, PullOptions::new().use_registry_config(true))`.
    pub fn pull_with_registry_config(&mut self, image: &str) -> Result<ImageInfo> {
        self.pull(image, PullOptions::new().use_registry_config(true))
    }

    /// Pull an OCI image with registry config and progress callback.
    pub fn pull_with_registry_config_and_progress<F: FnMut(usize, usize, &str)>(
        &mut self,
        image: &str,
        oci_platform: Option<&str>,
        progress: F,
    ) -> Result<ImageInfo> {
        let mut opts = PullOptions::new()
            .use_registry_config(true)
            .progress(progress);
        if let Some(p) = oci_platform {
            opts = opts.oci_platform(p);
        }
        self.pull(image, opts)
    }

    /// Query if an image exists locally.
    pub fn query(&mut self, image: &str) -> Result<Option<ImageInfo>> {
        let resp = self.request(&AgentRequest::Query {
            image: image.to_string(),
        })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                let info: ImageInfo = serde_json::from_value(data)
                    .map_err(|e| Error::agent("parse response", e.to_string()))?;
                Ok(Some(info))
            }
            AgentResponse::Error { code, .. } if code.as_deref() == Some("NOT_FOUND") => Ok(None),
            AgentResponse::Error { message, .. } => Err(Error::agent("query image", message)),
            _ => Err(Error::agent("query image", "unexpected response type")),
        }
    }

    /// List all cached images.
    pub fn list_images(&mut self) -> Result<Vec<ImageInfo>> {
        let resp = self.request(&AgentRequest::ListImages)?;
        expect_data(resp, "list images")
    }

    /// Run garbage collection.
    ///
    /// # Arguments
    ///
    /// * `dry_run` - If true, only report what would be deleted
    pub fn garbage_collect(&mut self, dry_run: bool) -> Result<u64> {
        let resp = self.request(&AgentRequest::GarbageCollect { dry_run })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                let freed = data["freed_bytes"].as_u64().unwrap_or(0);
                Ok(freed)
            }
            AgentResponse::Error { message, .. } => Err(Error::agent("garbage collect", message)),
            _ => Err(Error::agent("garbage collect", "unexpected response type")),
        }
    }

    /// Prepare an overlay filesystem for a workload.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference
    /// * `workload_id` - Unique workload identifier
    pub fn prepare_overlay(&mut self, image: &str, workload_id: &str) -> Result<OverlayInfo> {
        let resp = self.request(&AgentRequest::PrepareOverlay {
            image: image.to_string(),
            workload_id: workload_id.to_string(),
        })?;
        expect_data(resp, "prepare overlay")
    }

    /// Clean up an overlay filesystem.
    pub fn cleanup_overlay(&mut self, workload_id: &str) -> Result<()> {
        let resp = self.request(&AgentRequest::CleanupOverlay {
            workload_id: workload_id.to_string(),
        })?;
        expect_ok(resp, "cleanup overlay")
    }

    /// Format the storage disk.
    pub fn format_storage(&mut self) -> Result<()> {
        let resp = self.request(&AgentRequest::FormatStorage)?;
        expect_ok(resp, "format storage")
    }

    /// Get storage status.
    pub fn storage_status(&mut self) -> Result<StorageStatus> {
        let resp = self.request(&AgentRequest::StorageStatus)?;
        expect_data(resp, "storage status")
    }

    /// Test network connectivity directly from the agent (not via chroot).
    /// Used to debug TSI networking.
    pub fn network_test(&mut self, url: &str) -> Result<serde_json::Value> {
        let resp = self.request(&AgentRequest::NetworkTest {
            url: url.to_string(),
        })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => Ok(data),
            AgentResponse::Error { message, .. } => Err(Error::agent("network test", message)),
            _ => Err(Error::agent("network test", "unexpected response type")),
        }
    }

    /// Request agent shutdown.
    ///
    /// Waits for the agent to acknowledge the shutdown request before returning.
    /// This ensures the agent has called sync() to flush filesystem caches
    /// before we send SIGTERM to terminate the VM.
    ///
    /// The acknowledgment is critical for data integrity - without it, the VM
    /// may be killed before ext4 journal commits are flushed, causing layer
    /// corruption on next boot.
    pub fn shutdown(&mut self) -> Result<()> {
        // Set a timeout for shutdown acknowledgment.
        // The agent calls sync() then sends the ack — typically <100ms,
        // but heavy writes or large journals may take longer.
        // If no ack within 5s, the VM has likely already torn down.
        let _ = self
            .stream
            .set_read_timeout(Some(Duration::from_secs(SHUTDOWN_ACK_TIMEOUT_SECS)));

        let data = self.encode_traced(&AgentRequest::Shutdown)?;
        self.stream
            .write_all(&data)
            .map_err(|e| Error::agent("send shutdown", e.to_string()))?;

        // Wait for acknowledgment - this confirms sync() completed.
        // Returns Ok only when the ack is actually received, so callers
        // can distinguish "sync confirmed" from "sync unknown".
        match self.receive() {
            Ok(_) => {
                tracing::debug!("agent acknowledged shutdown (sync complete)");
                Ok(())
            }
            Err(e) => {
                let error_str = e.to_string();
                if is_benign_shutdown_error(&error_str) {
                    tracing::debug!(
                        "shutdown ack not received (connection closed) - sync may have completed"
                    );
                } else {
                    tracing::warn!(error = %e, "shutdown acknowledgment failed");
                }
                Err(Error::agent("shutdown ack", error_str))
            }
        }
    }

    // ========================================================================
    // VM-Level Exec (Direct Execution in VM)
    // ========================================================================

    /// Execute a command directly in the VM (not in a container).
    ///
    /// Runs the command in the agent's Alpine rootfs without container
    /// isolation. Returns `(exit_code, stdout_bytes, stderr_bytes)`. Output
    /// is raw bytes — binary data (image bytes, tarballs) is preserved.
    /// Callers that need a string can use `String::from_utf8_lossy(&bytes)`.
    pub fn vm_exec(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let _timeout_guard = self.set_exec_timeout(timeout)?;
        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            interactive: false,
            tty: false,
            background: false,
        })?;

        expect_completed(resp, "vm exec")
    }

    /// Execute a command in the background inside the VM.
    ///
    /// Spawns the process and returns immediately with the PID.
    /// The process runs detached — stdout/stderr go to /dev/null.
    pub fn vm_exec_background(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
    ) -> Result<u32> {
        let resp = self.request(&AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms: None,
            interactive: false,
            tty: false,
            background: true,
        })?;

        let (exit_code, stdout, _stderr) = expect_completed(resp, "vm exec background")?;
        if exit_code != 0 {
            return Err(Error::agent("vm exec background", "spawn failed"));
        }
        // PID output is always ASCII digits — lossy conversion is safe.
        let pid: u32 = String::from_utf8_lossy(&stdout)
            .trim()
            .parse()
            .map_err(|_| Error::agent("vm exec background", "invalid PID in response"))?;
        Ok(pid)
    }

    /// Run an interactive I/O session.
    ///
    /// Sends `request`, waits for `Started`, then runs the poll loop
    /// streaming stdout/stderr and forwarding stdin until `Exited`.
    fn interactive_session(&mut self, request: AgentRequest, tty: bool, op: &str) -> Result<i32> {
        use crate::agent::terminal::{
            check_sigwinch, flush_retry, get_terminal_size, install_sigwinch_handler, poll_io,
            stdin_is_tty, write_all_retry, NonBlockingStdin, RawModeGuard,
        };
        use std::io::{stderr, stdin, stdout, Read};
        use std::os::unix::io::AsRawFd;

        // Disable socket read timeout for interactive sessions — the poll loop
        // handles readiness checking, and the session runs until the user exits.
        self.stream
            .set_read_timeout(None)
            .map_err(|e| Error::agent("set read timeout", e.to_string()))?;

        self.send(&request)?;

        // Wait for Started response
        let started = self.receive()?;
        match started {
            AgentResponse::Started => {}
            AgentResponse::Error { message, .. } => {
                return Err(Error::agent(op, message));
            }
            _ => {
                return Err(Error::agent(op, "expected Started response"));
            }
        }

        // Enable raw mode if TTY requested and stdin is a TTY
        // The guard will restore terminal settings on drop (even on panic)
        let _raw_mode = if tty && stdin_is_tty() {
            RawModeGuard::new(stdin().as_raw_fd())
        } else {
            None
        };

        // Send initial terminal size so PTY starts at the right dimensions
        if tty {
            if let Some((cols, rows)) = get_terminal_size() {
                self.send(&AgentRequest::Resize { cols, rows })?;
            }
            install_sigwinch_handler();
        }

        // Set stdin to non-blocking (guard restores on drop)
        let _nonblock_stdin = NonBlockingStdin::new()
            .map_err(|e| Error::agent("set stdin nonblocking", e.to_string()))?;

        // Socket stays blocking — poll() determines readiness, then blocking
        // read/write completes immediately. This avoids partial-read/write bugs
        // that occur with non-blocking read_exact/write_all.
        let mut stdin_handle = stdin();
        let stdin_fd = stdin_handle.as_raw_fd();
        let socket_fd = self.stream.as_raw_fd();
        let mut stdin_buf = [0u8; STDIN_BUF_SIZE];
        let mut stdin_eof = false;

        let exit_code = loop {
            let effective_stdin_fd = if stdin_eof { -1 } else { stdin_fd };
            let poll_result = poll_io(effective_stdin_fd, socket_fd, POLL_TIMEOUT_MS)
                .map_err(|e| Error::agent("poll", e.to_string()))?;

            // Check for terminal resize (SIGWINCH)
            if tty && check_sigwinch() {
                if let Some((cols, rows)) = get_terminal_size() {
                    self.send(&AgentRequest::Resize { cols, rows })?;
                }
            }

            // Handle socket data FIRST — drain agent output before writing stdin
            // to prevent deadlock when send buffer is full
            if poll_result.socket_ready {
                match self.receive() {
                    Ok(AgentResponse::Stdout { data }) => {
                        write_all_retry(&mut stdout(), &data)?;
                        flush_retry(&mut stdout())?;
                    }
                    Ok(AgentResponse::Stderr { data }) => {
                        write_all_retry(&mut stderr(), &data)?;
                        flush_retry(&mut stderr())?;
                    }
                    Ok(AgentResponse::Exited { exit_code }) => {
                        break exit_code;
                    }
                    Ok(AgentResponse::Error { message, .. }) => {
                        return Err(Error::agent(op, message));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        // EAGAIN/WouldBlock can occur when poll() reports readiness
                        // but the data isn't available yet (common with vsock on macOS).
                        // Retry on next poll iteration instead of crashing.
                        if e.is_io()
                            && matches!(
                                e.source_io_error_kind(),
                                Some(std::io::ErrorKind::WouldBlock)
                            )
                        {
                            tracing::debug!("socket read returned EAGAIN, retrying");
                            continue;
                        }
                        return Err(e);
                    }
                }
            }

            // Socket peer closed without sending Exited — VM crashed or was killed
            if poll_result.socket_hangup && !poll_result.socket_ready {
                return Err(Error::agent(op, "connection to VM lost".to_string()));
            }

            // Handle stdin input — send to agent
            if poll_result.stdin_ready && !stdin_eof {
                match stdin_handle.read(&mut stdin_buf) {
                    Ok(0) => {
                        stdin_eof = true;
                        self.send(&AgentRequest::Stdin { data: Vec::new() })?;
                    }
                    Ok(n) => {
                        self.send(&AgentRequest::Stdin {
                            data: stdin_buf[..n].to_vec(),
                        })?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "error reading stdin");
                    }
                }
            }
        };

        Ok(exit_code)
    }

    /// Execute a command directly in the VM with interactive I/O.
    pub fn vm_exec_interactive(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
        tty: bool,
    ) -> Result<i32> {
        let timeout_ms = timeout.map(|t| t.as_millis() as u64);
        self.interactive_session(
            AgentRequest::VmExec {
                command,
                env,
                workdir,
                timeout_ms,
                interactive: true,
                tty,
                background: false,
            },
            tty,
            "vm exec interactive",
        )
    }

    /// Run a command in an image's rootfs (non-interactive).
    ///
    /// This is the non-interactive counterpart to `run_interactive()`.
    /// Both accept a `RunConfig` for consistency.
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn run_non_interactive(&mut self, config: RunConfig) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let _timeout_guard = self.set_exec_timeout(config.timeout)?;
        let timeout_ms = config.timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::Run {
            image: config.image,
            command: config.command,
            env: config.env,
            workdir: config.workdir,
            mounts: config.mounts,
            timeout_ms,
            interactive: false,
            tty: false,
            persistent_overlay_id: config.persistent_overlay_id,
        })?;

        expect_completed(resp, "run command")
    }

    /// Run a command interactively with streaming I/O.
    ///
    /// This method streams output directly to stdout/stderr and forwards stdin.
    /// It blocks until the command exits.
    ///
    /// # Arguments
    ///
    /// * `config` - Run configuration including image, command, environment, etc.
    ///
    /// # Returns
    ///
    /// The exit code of the command
    pub fn run_interactive(&mut self, config: RunConfig) -> Result<i32> {
        let timeout_ms = config.timeout.map(|t| t.as_millis() as u64);
        let tty = config.tty;
        self.interactive_session(
            AgentRequest::Run {
                image: config.image,
                command: config.command,
                env: config.env,
                workdir: config.workdir,
                mounts: config.mounts,
                timeout_ms,
                interactive: true,
                tty,
                persistent_overlay_id: config.persistent_overlay_id,
            },
            tty,
            "run interactive",
        )
    }

    /// Send stdin data to a running interactive command.
    pub fn send_stdin(&mut self, data: &[u8]) -> Result<()> {
        self.send(&AgentRequest::Stdin {
            data: data.to_vec(),
        })
    }

    /// Send a window resize event to a running interactive command.
    pub fn send_resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.send(&AgentRequest::Resize { cols, rows })
    }

    // ========================================================================
    // File I/O
    // ========================================================================

    /// Write a file into the VM.
    ///
    /// Transparently dispatches between single-shot and streaming
    /// based on `data.len()`:
    ///
    /// - Files ≤ [`FILE_WRITE_SINGLE_SHOT_MAX`] (1 MiB): one
    ///   [`AgentRequest::FileWrite`] message — the lowest-latency
    ///   path and what 99% of `cp` calls hit.
    /// - Files larger than that: a sequence of
    ///   [`AgentRequest::FileWriteBegin`] +
    ///   [`AgentRequest::FileWriteChunk`] messages, each under
    ///   [`MAX_FRAME_SIZE`]. This is the only correct way to upload
    ///   files whose base64-encoded form would exceed the frame
    ///   limit — without it the send blocks the socket (EAGAIN
    ///   after write timeout) and risks OOMing the guest agent.
    pub fn write_file(&mut self, path: &str, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.write_file_with_progress(path, data, mode, |_| {})
    }

    /// Write a file into the VM with a progress callback.
    ///
    /// `on_progress` is called after each chunk is acked by the
    /// agent, with the running byte total. Single-shot writes (small
    /// files) call it once at the end. Callers who don't need
    /// progress should use [`Self::write_file`] which passes a no-op.
    pub fn write_file_with_progress<F: FnMut(u64)>(
        &mut self,
        path: &str,
        data: &[u8],
        mode: Option<u32>,
        mut on_progress: F,
    ) -> Result<()> {
        if data.len() <= FILE_WRITE_SINGLE_SHOT_MAX {
            let resp = self.request(&AgentRequest::FileWrite {
                path: path.to_string(),
                data: data.to_vec(),
                mode,
            })?;
            expect_ok(resp, "write file")?;
            on_progress(data.len() as u64);
            Ok(())
        } else {
            self.write_file_streaming(path, data, mode, &mut on_progress)
        }
    }

    /// Streaming file upload from a `&[u8]` slice.
    fn write_file_streaming<F: FnMut(u64)>(
        &mut self,
        path: &str,
        data: &[u8],
        mode: Option<u32>,
        on_progress: &mut F,
    ) -> Result<()> {
        self.write_file_streaming_from_reader(
            path,
            &mut std::io::Cursor::new(data),
            data.len() as u64,
            mode,
            on_progress,
        )
    }

    /// Stream a file from a [`Read`] source into the VM.
    ///
    /// Reads `FILE_WRITE_CHUNK_SIZE` bytes at a time from `reader`,
    /// sending each chunk over the protocol. Only one chunk is in
    /// memory at a time — the caller doesn't need to buffer the
    /// entire file.
    pub fn write_file_from_reader<R: std::io::Read>(
        &mut self,
        path: &str,
        reader: R,
        total_size: u64,
        mode: Option<u32>,
    ) -> Result<()> {
        self.write_file_from_reader_with_progress(path, reader, total_size, mode, |_| {})
    }

    /// Stream a file from a [`Read`] source with progress callback.
    pub fn write_file_from_reader_with_progress<R: std::io::Read, F: FnMut(u64)>(
        &mut self,
        path: &str,
        reader: R,
        total_size: u64,
        mode: Option<u32>,
        mut on_progress: F,
    ) -> Result<()> {
        if total_size <= FILE_WRITE_SINGLE_SHOT_MAX as u64 {
            // Small file: read into memory and use single-shot path.
            let mut data = Vec::with_capacity(total_size as usize);
            std::io::Read::read_to_end(&mut std::io::Read::take(reader, total_size + 1), &mut data)
                .map_err(|e| Error::agent("read source file", e.to_string()))?;
            return self.write_file_with_progress(path, &data, mode, on_progress);
        }
        self.write_file_streaming_from_reader(
            path,
            &mut { reader },
            total_size,
            mode,
            &mut on_progress,
        )
    }

    /// Core streaming upload loop. Reads chunks from `reader` and
    /// sends them over the protocol. Only one chunk buffer is live
    /// at a time (~1 MiB).
    fn write_file_streaming_from_reader<R: std::io::Read, F: FnMut(u64)>(
        &mut self,
        path: &str,
        reader: &mut R,
        total_size: u64,
        mode: Option<u32>,
        on_progress: &mut F,
    ) -> Result<()> {
        let resp = self.request(&AgentRequest::FileWriteBegin {
            path: path.to_string(),
            mode,
            total_size,
        })?;
        expect_ok(resp, "begin streaming write")?;

        let mut buf = vec![0u8; FILE_WRITE_CHUNK_SIZE];
        let mut bytes_sent = 0u64;

        loop {
            // Fill the chunk buffer.
            let mut filled = 0;
            while filled < buf.len() {
                match reader.read(&mut buf[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(Error::agent("read source file", e.to_string())),
                }
            }

            if filled == 0 {
                // EOF — send final empty chunk to finalize.
                let resp = self.request(&AgentRequest::FileWriteChunk {
                    data: Vec::new(),
                    done: true,
                })?;
                expect_ok(resp, "finalize streaming write")?;
                break;
            }

            bytes_sent += filled as u64;
            let done = bytes_sent >= total_size;

            let resp = self.request(&AgentRequest::FileWriteChunk {
                data: buf[..filled].to_vec(),
                done,
            })?;
            expect_ok(resp, "stream write chunk")?;
            on_progress(bytes_sent);

            if done {
                break;
            }
        }
        Ok(())
    }

    /// Read a file from the VM.
    ///
    /// Consumes the streamed `DataChunk` responses the agent emits
    /// (see `handle_streaming_file_read` in the agent). The agent
    /// sends one or more chunks, with `done: true` on the final
    /// frame — possibly empty. This method concatenates chunks and
    /// returns the full contents.
    ///
    /// Two safety bounds:
    /// - Receive timeout extended to 600 s so large files don't
    ///   spuriously fail on slow storage; a 200 MB file at 10 MB/s
    ///   would exceed the default 30 s receive timeout otherwise.
    /// - Total size capped at [`FILE_TRANSFER_MAX_TOTAL`] (4 GiB) —
    ///   symmetric with the write path. A misbehaving or compromised
    ///   guest can't OOM the host by streaming unbounded data.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.read_file_with_progress(path, |_| {})
    }

    /// Read a file from the VM with a progress callback.
    ///
    /// `on_progress` is called with the running byte total after
    /// each `DataChunk` is received. Use [`Self::read_file`] if you
    /// don't need progress.
    pub fn read_file_with_progress<F: FnMut(u64)>(
        &mut self,
        path: &str,
        on_progress: F,
    ) -> Result<Vec<u8>> {
        const FILE_READ_TIMEOUT: Duration = Duration::from_secs(600);

        let _timeout_guard = self.set_extended_read_timeout(FILE_READ_TIMEOUT)?;
        self.send_raw(&AgentRequest::FileRead {
            path: path.to_string(),
        })?;

        consume_streamed_read_with_progress(|| self.recv_raw(), on_progress)
    }

    /// Download a file from the VM directly to a local path.
    ///
    /// Unlike [`Self::read_file`] which accumulates the entire file
    /// in memory, this writes each chunk to disk as it arrives —
    /// only one 16 MiB chunk is in memory at a time.
    pub fn read_file_to_path<F: FnMut(u64)>(
        &mut self,
        guest_path: &str,
        local_path: &std::path::Path,
        mut on_progress: F,
    ) -> Result<u64> {
        use std::io::Write;
        const FILE_READ_TIMEOUT: Duration = Duration::from_secs(600);

        let _timeout_guard = self.set_extended_read_timeout(FILE_READ_TIMEOUT)?;
        self.send_raw(&AgentRequest::FileRead {
            path: guest_path.to_string(),
        })?;

        let mut file = std::fs::File::create(local_path).map_err(|e| {
            Error::agent(
                "write local file",
                format!("{}: {}", local_path.display(), e),
            )
        })?;

        let mut total = 0u64;
        loop {
            match self.recv_raw()? {
                AgentResponse::DataChunk { data, done } => {
                    let next_total = total.saturating_add(data.len() as u64);
                    if next_total > FILE_TRANSFER_MAX_TOTAL {
                        let _ = std::fs::remove_file(local_path);
                        return Err(Error::agent(
                            "read file",
                            format!(
                                "guest streamed {} bytes, exceeding the {} byte cap",
                                next_total, FILE_TRANSFER_MAX_TOTAL
                            ),
                        ));
                    }
                    if !data.is_empty() {
                        file.write_all(&data)
                            .map_err(|e| Error::agent("write local file", e.to_string()))?;
                        total = next_total;
                        on_progress(total);
                    }
                    if done {
                        file.flush()
                            .map_err(|e| Error::agent("flush local file", e.to_string()))?;
                        return Ok(total);
                    }
                }
                AgentResponse::Error { message, .. } => {
                    let _ = std::fs::remove_file(local_path);
                    return Err(Error::agent("read file", message));
                }
                _ => {
                    let _ = std::fs::remove_file(local_path);
                    return Err(Error::agent("read file", "unexpected response"));
                }
            }
        }
    }

    // ========================================================================
    // Streaming Exec
    // ========================================================================

    /// Execute a command with streaming output.
    ///
    /// Sends a VmExec request with interactive=true, tty=false. Reads
    /// Stdout/Stderr/Exited responses and sends them as `ExecEvent` on
    /// the returned receiver. Blocks the current thread until the command
    /// finishes — call from a blocking context (e.g., `spawn_blocking`).
    pub fn vm_exec_streaming(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Vec<ExecEvent>> {
        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        self.stream
            .set_read_timeout(None)
            .map_err(|e| Error::agent("set read timeout", e.to_string()))?;

        self.send(&AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            interactive: true,
            tty: false,
            background: false,
        })?;

        // Wait for Started
        match self.receive()? {
            AgentResponse::Started => {}
            AgentResponse::Error { message, .. } => {
                return Err(Error::agent("streaming exec", message));
            }
            _ => return Err(Error::agent("streaming exec", "expected Started")),
        }

        let mut events = Vec::new();

        loop {
            match self.receive() {
                Ok(AgentResponse::Stdout { data }) => {
                    events.push(ExecEvent::Stdout(data));
                }
                Ok(AgentResponse::Stderr { data }) => {
                    events.push(ExecEvent::Stderr(data));
                }
                Ok(AgentResponse::Exited { exit_code }) => {
                    events.push(ExecEvent::Exit(exit_code));
                    break;
                }
                Ok(AgentResponse::Error { message, .. }) => {
                    events.push(ExecEvent::Error(message));
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    events.push(ExecEvent::Error(e.to_string()));
                    break;
                }
            }
        }

        Ok(events)
    }

    /// Low-level send without waiting for response (public).
    pub fn send_raw(&mut self, request: &AgentRequest) -> Result<()> {
        self.send(request)
    }

    /// Low-level receive a single response (public).
    pub fn recv_raw(&mut self) -> Result<AgentResponse> {
        self.receive()
    }

    /// Set a command-execution timeout and return a guard that resets it on drop.
    ///
    /// If `timeout` is Some, the socket deadline is `timeout + TIMEOUT_BUFFER_SECS`.
    /// If None, the socket read timeout is disabled entirely — the command runs
    /// until completion (or the VM dies, triggering EOF). This matches
    /// `interactive_session`'s behavior and avoids any implicit ceiling on how
    /// long a non-interactive command can run. The `ReadTimeoutGuard` restores
    /// `DEFAULT_READ_TIMEOUT_SECS` on drop so subsequent operations get the
    /// normal 30-second timeout.
    fn set_exec_timeout(&self, timeout: Option<Duration>) -> Result<Option<ReadTimeoutGuard>> {
        match timeout {
            Some(t) => {
                self.set_read_timeout(t + Duration::from_secs(TIMEOUT_BUFFER_SECS))?;
            }
            None => {
                self.stream.set_read_timeout(None).map_err(|e| {
                    Error::agent(
                        "set read timeout",
                        format!("failed to clear socket read timeout: {}", e),
                    )
                })?;
            }
        }
        Ok(ReadTimeoutGuard::new(&self.stream))
    }

    /// Set an extended read timeout and return a guard that resets it on drop.
    ///
    /// Used for long-running streaming operations (e.g., layer export) where
    /// individual chunks may take longer than the default 30s timeout.
    pub fn set_extended_read_timeout(&self, timeout: Duration) -> Result<Option<ReadTimeoutGuard>> {
        self.set_read_timeout(timeout)?;
        Ok(ReadTimeoutGuard::new(&self.stream))
    }

    /// Low-level send without waiting for response.
    fn send(&mut self, request: &AgentRequest) -> Result<()> {
        let data = self.encode_traced(request)?;
        self.stream.write_all(&data)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Read exactly `buf.len()` bytes, retrying on EAGAIN/WouldBlock.
    ///
    /// Unlike `read_exact`, this never loses partially-read data on EAGAIN.
    /// On macOS, vsock sockets can spuriously return WouldBlock even in
    /// blocking mode, so we must handle it without corrupting the stream.
    ///
    /// If `propagate_initial_wouldblock` is true and WouldBlock occurs before
    /// any bytes are read, the error is propagated (preserves read timeout
    /// behavior). Once any bytes are consumed, EAGAIN is always retried.
    fn read_exact_retry(
        &mut self,
        buf: &mut [u8],
        propagate_initial_wouldblock: bool,
    ) -> std::io::Result<()> {
        let mut pos = 0;
        while pos < buf.len() {
            match self.stream.read(&mut buf[pos..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ));
                }
                Ok(n) => pos += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if pos == 0 && propagate_initial_wouldblock {
                        // No data consumed yet and caller wants timeout errors — propagate
                        return Err(e);
                    }
                    // Either mid-read or caller wants full retry — must retry
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Low-level receive a single response.
    fn receive(&mut self) -> Result<AgentResponse> {
        // Check if a read timeout is set — if so, WouldBlock before any data
        // means a real timeout and should be propagated. If no timeout (interactive
        // sessions), WouldBlock is always a spurious macOS vsock EAGAIN.
        let has_timeout = self.stream.read_timeout().ok().flatten().is_some();

        let mut header = [0u8; 4];
        self.read_exact_retry(&mut header, has_timeout)?;
        let len = u32::from_be_bytes(header) as usize;

        // Validate frame size to prevent OOM from malicious/buggy responses
        if len > MAX_FRAME_SIZE as usize {
            // Header consumed but body not read — stream is desynchronized.
            // Shut down the read half so all future reads fail immediately
            // rather than interpreting body bytes as a frame header.
            let _ = self.stream.shutdown(std::net::Shutdown::Read);
            return Err(Error::agent(
                "validate frame",
                format!(
                    "frame too large: {} bytes (max: {} bytes)",
                    len, MAX_FRAME_SIZE
                ),
            ));
        }

        let mut buf = vec![0u8; len];
        // Always retry body reads — header is already consumed so we can't
        // propagate an error without corrupting the stream.
        if let Err(e) = self.read_exact_retry(&mut buf, false) {
            // Body read failed — stream is desynchronized. Shut down the
            // read half so future reads fail cleanly.
            let _ = self.stream.shutdown(std::net::Shutdown::Read);
            return Err(e.into());
        }

        let resp: AgentResponse = serde_json::from_slice(&buf)
            .map_err(|e| Error::agent("deserialize response", e.to_string()))?;
        Ok(resp)
    }
}

/// Consume streamed `DataChunk` responses, enforcing the per-transfer
/// size cap and returning the concatenated bytes.
///
/// Pulled out of `AgentClient::read_file` so it can be unit-tested
/// against synthetic response sequences without booting a VM, and
/// against a small cap so the test doesn't have to allocate 4 GiB
/// just to exercise the cap branch.
///
/// Two small variants on the same loop:
/// - [`consume_streamed_read_with_progress`]: production cap, with
///   a progress callback (used by [`AgentClient::read_file`] +
///   [`AgentClient::read_file_with_progress`]).
/// - [`consume_streamed_read_with_cap`]: parameterized cap, no
///   progress (used by tests so they can exercise the cap branch
///   with kilobytes instead of gigabytes).
///
/// Both delegate to [`consume_streamed_read_inner`].
fn consume_streamed_read_with_progress<F, P>(next_response: F, on_progress: P) -> Result<Vec<u8>>
where
    F: FnMut() -> Result<AgentResponse>,
    P: FnMut(u64),
{
    consume_streamed_read_inner(next_response, FILE_TRANSFER_MAX_TOTAL, on_progress)
}

#[cfg(test)]
fn consume_streamed_read_with_cap<F>(next_response: F, cap: u64) -> Result<Vec<u8>>
where
    F: FnMut() -> Result<AgentResponse>,
{
    consume_streamed_read_inner(next_response, cap, |_| {})
}

fn consume_streamed_read_inner<F, P>(
    mut next_response: F,
    cap: u64,
    mut on_progress: P,
) -> Result<Vec<u8>>
where
    F: FnMut() -> Result<AgentResponse>,
    P: FnMut(u64),
{
    let mut out: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    loop {
        match next_response()? {
            AgentResponse::DataChunk { data, done } => {
                // Cap *before* extending so a single oversized chunk
                // can't push us past the limit.
                let next_total = total.saturating_add(data.len() as u64);
                if next_total > cap {
                    return Err(Error::agent(
                        "read file",
                        format!(
                            "guest streamed {} bytes, exceeding the {} byte cap; \
                             use a virtiofs mount for larger files",
                            next_total, cap
                        ),
                    ));
                }
                out.extend_from_slice(&data);
                total = next_total;
                on_progress(total);
                if done {
                    return Ok(out);
                }
            }
            AgentResponse::Error { message, .. } => {
                return Err(Error::agent("read file", message));
            }
            other => {
                return Err(Error::agent(
                    "read file",
                    format!("unexpected response: {:?}", other),
                ));
            }
        }
    }
}

#[cfg(test)]
mod read_cap_tests {
    use super::*;

    /// Build a `DataChunk` response with `n` zero bytes.
    fn chunk(n: usize, done: bool) -> AgentResponse {
        AgentResponse::DataChunk {
            data: vec![0u8; n],
            done,
        }
    }

    /// Drive the consumer over a fixed list of responses with a
    /// small (1 KiB) cap. Tests only need to exercise the size
    /// arithmetic; the production cap of 4 GiB would need the test
    /// to allocate a Vec that big to trip — wasteful and unnecessary.
    /// The cap is parameterized on the internal helper precisely so
    /// this test can scale down.
    const TEST_CAP: u64 = 1024;

    fn drive(responses: Vec<AgentResponse>) -> Result<Vec<u8>> {
        let mut iter = responses.into_iter();
        consume_streamed_read_with_cap(
            || {
                iter.next()
                    .ok_or_else(|| Error::agent("test", "no more responses"))
            },
            TEST_CAP,
        )
    }

    #[test]
    fn read_cap_terminator_returns_full_buffer() {
        let out = drive(vec![chunk(100, false), chunk(50, true)]).unwrap();
        assert_eq!(out.len(), 150);
    }

    #[test]
    fn read_cap_empty_terminator_is_valid_eof() {
        let out = drive(vec![chunk(100, false), chunk(0, true)]).unwrap();
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn read_cap_rejects_single_chunk_at_or_above_limit() {
        // Single chunk that on its own pushes past the cap. We're at
        // 1024-byte cap so this chunk is 1025 bytes — trivial to
        // allocate in tests, exercises the same arithmetic that
        // would catch a 4 GiB+ chunk in production.
        let err = drive(vec![chunk(TEST_CAP as usize + 1, true)]).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("exceeding") && msg.contains("byte cap"),
            "expected size-cap error, got: {}",
            msg
        );
    }

    #[test]
    fn read_cap_rejects_when_accumulated_chunks_exceed_limit() {
        // Two chunks under the cap individually but exceeding it
        // combined. This is the realistic exhaustion vector — a
        // misbehaving guest streaming "fine-sized" chunks forever.
        let half = (TEST_CAP / 2) as usize;
        let err = drive(vec![
            chunk(half, false),
            chunk(half, false),
            chunk(half, false), // would push past the cap
        ])
        .unwrap_err();
        assert!(format!("{}", err).contains("byte cap"));
    }

    #[test]
    fn read_cap_chunk_at_exactly_limit_is_accepted() {
        // Boundary: a chunk that lands the accumulated total at
        // exactly the cap is fine. Only > cap is rejected.
        let out = drive(vec![chunk(TEST_CAP as usize, true)]).unwrap();
        assert_eq!(out.len(), TEST_CAP as usize);
    }

    #[test]
    fn read_cap_propagates_agent_error_response() {
        let err = drive(vec![AgentResponse::Error {
            message: "no such file".to_string(),
            code: None,
        }])
        .unwrap_err();
        assert!(format!("{}", err).contains("no such file"));
    }

    #[test]
    fn read_cap_rejects_unexpected_response_type() {
        let err = drive(vec![AgentResponse::Pong { version: 1 }]).unwrap_err();
        assert!(format!("{}", err).contains("unexpected response"));
    }
}
