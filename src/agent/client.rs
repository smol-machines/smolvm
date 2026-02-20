//! vsock client for communicating with the smolvm-agent.
//!
//! This module provides a client for sending requests to the agent
//! and receiving responses.

use crate::error::{Error, Result};
use crate::registry::{extract_registry, rewrite_image_registry, RegistryAuth, RegistryConfig};
use smolvm_protocol::{
    encode_message, AgentRequest, AgentResponse, ContainerInfo, ImageInfo, OverlayInfo,
    StorageStatus, MAX_FRAME_SIZE,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

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

/// Read timeout for interactive/long-running sessions (1 hour).
/// Used for exec, run, and container exec operations where the user may be
/// running long commands or interactive shells.
const INTERACTIVE_TIMEOUT_SECS: u64 = 3600;

/// Buffer time added to user-specified timeouts (5 seconds).
/// When users specify a command timeout, we add this buffer to the socket
/// timeout to allow for protocol overhead and response transmission.
const TIMEOUT_BUFFER_SECS: u64 = 5;

/// Short read timeout for status checks (5 seconds).
/// Used when checking agent status where we want to fail fast.
const STATUS_CHECK_TIMEOUT_SECS: u64 = 5;

/// RAII guard that resets the socket read timeout on drop.
///
/// Ensures the timeout is always restored, even if the operation
/// returns early due to an error. Uses a cloned UnixStream handle
/// (shares the underlying fd) to avoid borrow conflicts.
struct ReadTimeoutGuard {
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
///     .platform("linux/arm64")
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
    /// Platform to pull (e.g., "linux/arm64").
    pub platform: Option<String>,
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
            platform: None,
            auth: None,
            use_registry_config: false,
            progress: None,
        }
    }
}

impl<F: FnMut(usize, usize, &str)> PullOptions<F> {
    /// Set the target platform (e.g., "linux/arm64").
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
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
            platform: self.platform,
            auth: self.auth,
            use_registry_config: self.use_registry_config,
            progress: Some(callback),
        }
    }
}

/// Client for communicating with the smolvm-agent.
pub struct AgentClient {
    stream: UnixStream,
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
fn expect_completed(resp: AgentResponse, op: &str) -> Result<(i32, String, String)> {
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

    /// Internal connect implementation (single attempt).
    fn connect_once(socket_path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|e| Error::agent("connect to agent", e.to_string()))?;

        // Set timeouts - fail early if we can't set them to prevent indefinite hangs
        stream
            .set_read_timeout(Some(Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS)))
            .map_err(|e| {
                Error::agent(
                    "set read timeout",
                    format!("{} (prevents indefinite hangs)", e),
                )
            })?;

        stream
            .set_write_timeout(Some(Duration::from_secs(DEFAULT_WRITE_TIMEOUT_SECS)))
            .map_err(|e| {
                Error::agent(
                    "set write timeout",
                    format!("{} (prevents indefinite hangs)", e),
                )
            })?;

        Ok(Self { stream })
    }

    /// Send a request and receive a response.
    fn request(&mut self, req: &AgentRequest) -> Result<AgentResponse> {
        // Encode and send request
        let data =
            encode_message(req).map_err(|e| Error::agent("encode message", e.to_string()))?;
        self.stream
            .write_all(&data)
            .map_err(|e| Error::agent("send message", e.to_string()))?;

        // Read response
        self.receive()
    }

    /// Ping the helper daemon.
    pub fn ping(&mut self) -> Result<u32> {
        let resp = self.request(&AgentRequest::Ping)?;

        match resp {
            AgentResponse::Pong { version } => Ok(version),
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
            options.platform.as_deref(),
            effective_auth.as_ref(),
            options.progress,
        )
    }

    /// Internal implementation of image pull.
    fn pull_image_internal<F: FnMut(usize, usize, &str)>(
        &mut self,
        image: &str,
        platform: Option<&str>,
        auth: Option<&RegistryAuth>,
        mut progress: Option<F>,
    ) -> Result<ImageInfo> {
        // Use a long timeout for pull - large images can take minutes to download/extract.
        // The guard resets the timeout on drop (including error paths).
        self.set_read_timeout(Duration::from_secs(IMAGE_PULL_TIMEOUT_SECS))?;
        let _timeout_guard = ReadTimeoutGuard::new(&self.stream);

        // Send the pull request
        let data = encode_message(&AgentRequest::Pull {
            image: image.to_string(),
            platform: platform.map(String::from),
            auth: auth.cloned(),
        })
        .map_err(|e| Error::agent("encode message", e.to_string()))?;

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
        platform: Option<&str>,
        progress: F,
    ) -> Result<ImageInfo> {
        let mut opts = PullOptions::new()
            .use_registry_config(true)
            .progress(progress);
        if let Some(p) = platform {
            opts = opts.platform(p);
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
        // Set a short timeout for shutdown acknowledgment
        // The agent just needs to call sync() which is fast
        let _ = self
            .stream
            .set_read_timeout(Some(Duration::from_secs(STATUS_CHECK_TIMEOUT_SECS)));

        let data = encode_message(&AgentRequest::Shutdown)
            .map_err(|e| Error::agent("encode message", e.to_string()))?;
        self.stream
            .write_all(&data)
            .map_err(|e| Error::agent("send shutdown", e.to_string()))?;

        // Wait for acknowledgment - this confirms sync() completed.
        // If the agent crashes or times out, we proceed anyway since
        // the sync() happens before the response is sent.
        //
        // Note: EAGAIN (os error 35) is common here because the VM may be
        // torn down before the response arrives - this is benign since
        // sync() has already completed by that point.
        match self.receive() {
            Ok(_) => {
                tracing::debug!("agent acknowledged shutdown (sync complete)");
            }
            Err(e) => {
                // Check if this is EAGAIN/EWOULDBLOCK - a common benign race
                let error_str = e.to_string();
                if error_str.contains("os error 35")
                    || error_str.contains("temporarily unavailable")
                {
                    tracing::debug!(
                        "shutdown ack not received (connection closed) - sync likely completed"
                    );
                } else {
                    tracing::warn!(error = %e, "shutdown acknowledgment failed, proceeding anyway");
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // VM-Level Exec (Direct Execution in VM)
    // ========================================================================

    /// Execute a command directly in the VM (not in a container).
    ///
    /// This runs the command in the agent's Alpine rootfs without any
    /// container isolation. Useful for VM-level operations and debugging.
    ///
    /// # Arguments
    ///
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory in the VM
    /// * `timeout` - Optional timeout duration
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn vm_exec(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        // Set socket read timeout based on command timeout (with buffer for response).
        // The guard resets the timeout on drop (including error paths).
        let socket_timeout = match timeout {
            Some(t) => t + Duration::from_secs(TIMEOUT_BUFFER_SECS),
            None => Duration::from_secs(INTERACTIVE_TIMEOUT_SECS),
        };
        self.set_read_timeout(socket_timeout)?;
        let _timeout_guard = ReadTimeoutGuard::new(&self.stream);

        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            interactive: false,
            tty: false,
        })?;

        expect_completed(resp, "vm exec")
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
        let mut stdin_buf = [0u8; 4096];
        let mut stdin_eof = false;

        let exit_code = loop {
            let effective_stdin_fd = if stdin_eof { -1 } else { stdin_fd };
            let poll_result = poll_io(effective_stdin_fd, socket_fd, 100)
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
            },
            tty,
            "vm exec interactive",
        )
    }

    /// Run a command in an image's rootfs.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the rootfs
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn run(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
    ) -> Result<(i32, String, String)> {
        self.run_with_mounts(image, command, env, workdir, Vec::new())
    }

    /// Run a command in an image's rootfs with volume mounts.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the rootfs
    /// * `mounts` - Volume mounts as (virtiofs_tag, container_path, read_only)
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn run_with_mounts(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        mounts: Vec<(String, String, bool)>,
    ) -> Result<(i32, String, String)> {
        self.run_with_mounts_and_timeout(image, command, env, workdir, mounts, None)
    }

    /// Run a command in an image's rootfs with volume mounts and optional timeout.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the rootfs
    /// * `mounts` - Volume mounts as (virtiofs_tag, container_path, read_only)
    /// * `timeout` - Optional timeout duration. If exceeded, command is killed with exit code 124.
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn run_with_mounts_and_timeout(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        mounts: Vec<(String, String, bool)>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        // Set socket read timeout based on command timeout (with buffer for response).
        // The guard resets the timeout on drop (including error paths).
        let socket_timeout = match timeout {
            Some(t) => t + Duration::from_secs(TIMEOUT_BUFFER_SECS),
            None => Duration::from_secs(INTERACTIVE_TIMEOUT_SECS),
        };
        self.set_read_timeout(socket_timeout)?;
        let _timeout_guard = ReadTimeoutGuard::new(&self.stream);

        // Convert timeout to milliseconds for protocol
        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::Run {
            image: image.to_string(),
            command,
            env,
            workdir,
            mounts,
            timeout_ms,
            interactive: false,
            tty: false,
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
    // Container Lifecycle
    // ========================================================================

    /// Create a long-running container from an image.
    ///
    /// The container is created and started, ready for exec.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command to run (e.g., ["sleep", "infinity"])
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the container
    /// * `mounts` - Volume mounts as (virtiofs_tag, container_path, read_only)
    ///
    /// # Returns
    ///
    /// ContainerInfo with the container ID
    pub fn create_container(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        mounts: Vec<(String, String, bool)>,
    ) -> Result<ContainerInfo> {
        let resp = self.request(&AgentRequest::CreateContainer {
            image: image.to_string(),
            command,
            env,
            workdir,
            mounts,
        })?;

        expect_data(resp, "create container")
    }

    /// Start a created container.
    pub fn start_container(&mut self, container_id: &str) -> Result<()> {
        let resp = self.request(&AgentRequest::StartContainer {
            container_id: container_id.to_string(),
        })?;
        expect_ok(resp, "start container")
    }

    /// Stop a running container.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Container ID (full or prefix)
    /// * `timeout_secs` - Timeout before force kill (default: 10)
    pub fn stop_container(&mut self, container_id: &str, timeout_secs: Option<u64>) -> Result<()> {
        let resp = self.request(&AgentRequest::StopContainer {
            container_id: container_id.to_string(),
            timeout_secs,
        })?;
        expect_ok(resp, "stop container")
    }

    /// Delete a container.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Container ID (full or prefix)
    /// * `force` - Force delete even if running
    pub fn delete_container(&mut self, container_id: &str, force: bool) -> Result<()> {
        let resp = self.request(&AgentRequest::DeleteContainer {
            container_id: container_id.to_string(),
            force,
        })?;
        expect_ok(resp, "delete container")
    }

    /// List all containers.
    pub fn list_containers(&mut self) -> Result<Vec<ContainerInfo>> {
        let resp = self.request(&AgentRequest::ListContainers)?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => serde_json::from_value(data)
                .map_err(|e| Error::agent("parse response", e.to_string())),
            AgentResponse::Ok { data: None } => Ok(Vec::new()),
            AgentResponse::Error { message, .. } => Err(Error::agent("list containers", message)),
            _ => Err(Error::agent("list containers", "unexpected response type")),
        }
    }

    /// Execute a command in a running container.
    ///
    /// Unlike `run`, this executes in an existing container created with `create_container`.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Container ID (full or prefix)
    /// * `command` - Command and arguments to execute
    /// * `env` - Environment variables for this exec
    /// * `workdir` - Working directory for this exec
    /// * `timeout` - Optional timeout duration
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn exec(
        &mut self,
        container_id: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        // Set socket read timeout based on command timeout (with buffer for response).
        // The guard resets the timeout on drop (including error paths).
        let socket_timeout = match timeout {
            Some(t) => t + Duration::from_secs(TIMEOUT_BUFFER_SECS),
            None => Duration::from_secs(INTERACTIVE_TIMEOUT_SECS),
        };
        self.set_read_timeout(socket_timeout)?;
        let _timeout_guard = ReadTimeoutGuard::new(&self.stream);

        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::Exec {
            container_id: container_id.to_string(),
            command,
            env,
            workdir,
            timeout_ms,
            interactive: false,
            tty: false,
        })?;

        expect_completed(resp, "exec command")
    }

    /// Execute a command interactively in a running container with streaming I/O.
    ///
    /// This method streams output directly to stdout/stderr.
    /// It blocks until the command exits.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Container ID (full or prefix)
    /// * `command` - Command and arguments to execute
    /// * `env` - Environment variables for this exec
    /// * `workdir` - Working directory for this exec
    /// * `timeout` - Optional timeout duration
    /// * `tty` - Whether to allocate a PTY
    ///
    /// # Returns
    ///
    /// The exit code of the command
    pub fn exec_interactive(
        &mut self,
        container_id: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
        tty: bool,
    ) -> Result<i32> {
        let timeout_ms = timeout.map(|t| t.as_millis() as u64);
        self.interactive_session(
            AgentRequest::Exec {
                container_id: container_id.to_string(),
                command,
                env,
                workdir,
                timeout_ms,
                interactive: true,
                tty,
            },
            tty,
            "exec interactive",
        )
    }

    /// Low-level send without waiting for response (public).
    pub fn send_raw(&mut self, request: &AgentRequest) -> Result<()> {
        self.send(request)
    }

    /// Low-level receive a single response (public).
    pub fn recv_raw(&mut self) -> Result<AgentResponse> {
        self.receive()
    }

    /// Low-level send without waiting for response.
    fn send(&mut self, request: &AgentRequest) -> Result<()> {
        let json = serde_json::to_vec(request)
            .map_err(|e| Error::agent("serialize request", e.to_string()))?;
        let len = json.len() as u32;

        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(&json)?;
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
        self.read_exact_retry(&mut buf, false)?;

        let resp: AgentResponse = serde_json::from_slice(&buf)
            .map_err(|e| Error::agent("deserialize response", e.to_string()))?;
        Ok(resp)
    }
}
