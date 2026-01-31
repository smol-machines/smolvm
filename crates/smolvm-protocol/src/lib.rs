//! Protocol types for smolvm host-guest communication.
//!
//! This crate defines the wire protocol for vsock communication between
//! the smolvm host and the guest agent (smolvm-agent).
//!
//! # Protocol Overview
//!
//! Communication uses JSON-encoded messages over vsock. Each message is
//! prefixed with a 4-byte big-endian length header.
//!
//! ```text
//! +----------------+-------------------+
//! | Length (4 BE)  | JSON payload      |
//! +----------------+-------------------+
//! ```

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// Protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum frame size (256 MB - increased to support large OCI layers for pack).
pub const MAX_FRAME_SIZE: u32 = 256 * 1024 * 1024;

/// Well-known vsock ports.
pub mod ports {
    /// Control channel for workload VMs.
    pub const WORKLOAD_CONTROL: u32 = 5000;
    /// Log streaming from workload VMs.
    pub const WORKLOAD_LOGS: u32 = 5001;
    /// Agent control port (for OCI operations and management).
    pub const AGENT_CONTROL: u32 = 6000;
}

/// vsock CID constants.
pub mod cid {
    /// Host CID (always 2).
    pub const HOST: u32 = 2;
    /// Guest CID (always 3 for the first/only guest).
    pub const GUEST: u32 = 3;
    /// Any CID (for listening).
    pub const ANY: u32 = u32::MAX;
}

// ============================================================================
// Agent Protocol (OCI Operations)
// ============================================================================

/// Agent request types (for image management and OCI operations).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AgentRequest {
    /// Ping to check if agent is alive.
    Ping,

    /// Pull an OCI image and extract layers.
    Pull {
        /// Image reference (e.g., "alpine:latest", "docker.io/library/ubuntu:22.04").
        image: String,
        /// Platform to pull (e.g., "linux/arm64", "linux/amd64").
        platform: Option<String>,
        /// Optional registry authentication credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<RegistryAuth>,
    },

    /// Query if an image exists locally.
    Query {
        /// Image reference.
        image: String,
    },

    /// List all cached images.
    ListImages,

    /// Run garbage collection on unused layers.
    GarbageCollect {
        /// If true, only report what would be deleted.
        dry_run: bool,
    },

    /// Prepare overlay rootfs for a workload.
    PrepareOverlay {
        /// Image reference.
        image: String,
        /// Unique workload ID for the overlay.
        workload_id: String,
    },

    /// Clean up overlay rootfs for a workload.
    CleanupOverlay {
        /// Workload ID to clean up.
        workload_id: String,
    },

    /// Format the storage disk (first-time setup).
    FormatStorage,

    /// Get storage disk status.
    StorageStatus,

    /// Test network connectivity directly from the agent (not via chroot).
    /// Used to debug TSI networking.
    NetworkTest {
        /// URL to test (e.g., "http://1.1.1.1")
        url: String,
    },

    /// Shutdown the agent.
    Shutdown,

    /// Export a layer as a tar archive.
    ///
    /// Used by `smolvm pack` to extract OCI layers for packaging.
    /// The agent streams the layer tar data back via LayerData responses.
    ExportLayer {
        /// Image digest (sha256:...).
        image_digest: String,
        /// Layer index (0-based).
        layer_index: usize,
    },

    /// Execute a command directly in the VM (not in a container).
    ///
    /// This runs the command in the agent's Alpine rootfs without any
    /// container isolation. Useful for VM-level operations and debugging.
    VmExec {
        /// Command and arguments.
        command: Vec<String>,
        /// Environment variables.
        #[serde(default)]
        env: Vec<(String, String)>,
        /// Working directory in the VM.
        workdir: Option<String>,
        /// Timeout in milliseconds.
        #[serde(default)]
        timeout_ms: Option<u64>,
        /// Interactive mode - stream I/O instead of buffering.
        #[serde(default)]
        interactive: bool,
        /// Allocate a pseudo-TTY for the command.
        #[serde(default)]
        tty: bool,
    },

    /// Run a command in an image's rootfs.
    ///
    /// This prepares an overlay, chroots into it, and executes the command.
    /// Returns stdout, stderr, and exit code when the command completes.
    Run {
        /// Image reference (must be pulled first).
        image: String,
        /// Command and arguments.
        command: Vec<String>,
        /// Environment variables.
        #[serde(default)]
        env: Vec<(String, String)>,
        /// Working directory inside the rootfs.
        workdir: Option<String>,
        /// Volume mounts to bind into the container.
        /// Each tuple is (virtiofs_tag, container_path, read_only).
        #[serde(default)]
        mounts: Vec<(String, String, bool)>,
        /// Timeout in milliseconds. If the command exceeds this duration,
        /// it will be killed and return exit code 124.
        #[serde(default)]
        timeout_ms: Option<u64>,
        /// Interactive mode - stream I/O instead of buffering.
        /// When true, output is streamed via Stdout/Stderr responses,
        /// and stdin can be sent via the Stdin request.
        #[serde(default)]
        interactive: bool,
        /// Allocate a pseudo-TTY for the command.
        /// Enables terminal features like colors, line editing, and signal handling.
        #[serde(default)]
        tty: bool,
    },

    /// Send stdin data to a running interactive command.
    Stdin {
        /// Input data to send to the command's stdin.
        data: Vec<u8>,
    },

    /// Resize the PTY window (for TTY mode).
    Resize {
        /// New width in columns.
        cols: u16,
        /// New height in rows.
        rows: u16,
    },

    // ========================================================================
    // Container Lifecycle
    // ========================================================================
    /// Create a long-running container from an image.
    ///
    /// The container is created but not started. Use StartContainer to start it.
    /// This enables exec'ing into the same container multiple times.
    CreateContainer {
        /// Image reference (must be pulled first).
        image: String,
        /// Command and arguments to run (e.g., ["sleep", "infinity"]).
        command: Vec<String>,
        /// Environment variables.
        #[serde(default)]
        env: Vec<(String, String)>,
        /// Working directory inside the container.
        workdir: Option<String>,
        /// Volume mounts (virtiofs_tag, container_path, read_only).
        #[serde(default)]
        mounts: Vec<(String, String, bool)>,
    },

    /// Start a created container.
    StartContainer {
        /// Container ID (full or prefix).
        container_id: String,
    },

    /// Stop a running container.
    StopContainer {
        /// Container ID (full or prefix).
        container_id: String,
        /// Timeout in seconds before force killing (default: 10).
        #[serde(default)]
        timeout_secs: Option<u64>,
    },

    /// Delete a container.
    DeleteContainer {
        /// Container ID (full or prefix).
        container_id: String,
        /// Force delete even if running.
        #[serde(default)]
        force: bool,
    },

    /// List all containers.
    ListContainers,

    /// Execute a command in a running container.
    ///
    /// Unlike Run, this executes in an existing container created with CreateContainer.
    Exec {
        /// Container ID (full or prefix).
        container_id: String,
        /// Command and arguments to execute.
        command: Vec<String>,
        /// Environment variables for this exec.
        #[serde(default)]
        env: Vec<(String, String)>,
        /// Working directory for this exec.
        workdir: Option<String>,
        /// Timeout in milliseconds.
        #[serde(default)]
        timeout_ms: Option<u64>,
        /// Interactive mode - stream I/O instead of buffering.
        /// When true, output is streamed via Stdout/Stderr responses,
        /// and stdin can be sent via the Stdin request.
        #[serde(default)]
        interactive: bool,
        /// Allocate a pseudo-TTY for the command.
        /// Enables terminal features like colors, line editing, and signal handling.
        #[serde(default)]
        tty: bool,
    },
}

/// Agent response types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentResponse {
    /// Operation completed successfully.
    Ok {
        /// Response data (varies by request type).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },

    /// Pong response to ping.
    Pong {
        /// Protocol version.
        version: u32,
    },

    /// Progress update (for long operations like pull).
    Progress {
        /// Human-readable message.
        message: String,
        /// Completion percentage (0-100).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        percent: Option<u8>,
        /// Current layer being processed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        layer: Option<String>,
    },

    /// Operation failed.
    Error {
        /// Error message.
        message: String,
        /// Error code (for programmatic handling).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },

    /// Command execution completed (non-interactive mode).
    Completed {
        /// Exit code from the command.
        exit_code: i32,
        /// Standard output (may be truncated).
        stdout: String,
        /// Standard error (may be truncated).
        stderr: String,
    },

    /// Command started (interactive mode).
    /// Indicates the command is running and ready to receive stdin.
    Started,

    /// Stdout data from a running command (interactive mode).
    Stdout {
        /// Output data.
        data: Vec<u8>,
    },

    /// Stderr data from a running command (interactive mode).
    Stderr {
        /// Error output data.
        data: Vec<u8>,
    },

    /// Command exited (interactive mode).
    Exited {
        /// Exit code from the command.
        exit_code: i32,
    },

    /// Layer data chunk (for ExportLayer).
    LayerData {
        /// Binary data chunk.
        data: Vec<u8>,
        /// Whether this is the last chunk.
        done: bool,
    },
}

/// Image information returned by Query/ListImages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image reference.
    pub reference: String,
    /// Image digest (sha256:...).
    pub digest: String,
    /// Image size in bytes.
    pub size: u64,
    /// Creation timestamp (ISO 8601).
    pub created: Option<String>,
    /// Platform architecture.
    pub architecture: String,
    /// Platform OS.
    pub os: String,
    /// Number of layers.
    pub layer_count: usize,
    /// Layer digests in order.
    pub layers: Vec<String>,
}

/// Overlay preparation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// Path to the merged overlay rootfs.
    pub rootfs_path: String,
    /// Path to the upper (writable) directory.
    pub upper_path: String,
    /// Path to the work directory.
    pub work_path: String,
}

/// Storage status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatus {
    /// Whether the storage is formatted and ready.
    pub ready: bool,
    /// Total size in bytes.
    pub total_bytes: u64,
    /// Used size in bytes.
    pub used_bytes: u64,
    /// Number of cached layers.
    pub layer_count: usize,
    /// Number of cached images.
    pub image_count: usize,
}

/// Container information returned by ListContainers/CreateContainer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Unique container ID.
    pub id: String,
    /// Image the container was created from.
    pub image: String,
    /// Current container state (created, running, stopped).
    pub state: String,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Command the container is running.
    pub command: Vec<String>,
}

/// Registry authentication credentials for pulling images.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAuth {
    /// Username for authentication.
    pub username: String,
    /// Password or token for authentication.
    pub password: String,
}

// ============================================================================
// Workload VM Protocol (Command Execution)
// ============================================================================

/// Messages from host to workload VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    /// Authentication request.
    Auth {
        /// Authentication token (base64).
        token: String,
        /// Protocol version.
        protocol_version: u32,
    },

    /// Run a command.
    Run {
        /// Request ID for correlating responses.
        request_id: u64,
        /// Command and arguments.
        command: Vec<String>,
        /// Environment variables.
        env: Vec<(String, String)>,
        /// Working directory.
        workdir: Option<String>,
    },

    /// Execute a command in running VM.
    Exec {
        /// Request ID.
        request_id: u64,
        /// Command and arguments.
        command: Vec<String>,
        /// Allocate a TTY.
        tty: bool,
    },

    /// Send a signal to a running command.
    Signal {
        /// Request ID of the command.
        request_id: u64,
        /// Signal number.
        signal: i32,
    },

    /// Request graceful shutdown.
    Stop {
        /// Timeout in milliseconds.
        timeout_ms: u64,
    },
}

/// Messages from workload VM to host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestMessage {
    /// Authentication successful.
    AuthOk,

    /// Authentication failed.
    AuthFailed,

    /// VM is ready to receive commands.
    Ready,

    /// Command started.
    Started {
        /// Request ID.
        request_id: u64,
    },

    /// Stdout data from command.
    Stdout {
        /// Request ID.
        request_id: u64,
        /// Output data.
        data: Vec<u8>,
        /// Whether output was truncated.
        truncated: bool,
    },

    /// Stderr data from command.
    Stderr {
        /// Request ID.
        request_id: u64,
        /// Output data.
        data: Vec<u8>,
        /// Whether output was truncated.
        truncated: bool,
    },

    /// Command exited.
    Exit {
        /// Request ID.
        request_id: u64,
        /// Exit code.
        code: i32,
        /// Exit reason.
        reason: String,
    },

    /// Error occurred.
    Error {
        /// Request ID (if applicable).
        request_id: Option<u64>,
        /// Error message.
        message: String,
    },
}

// ============================================================================
// Wire Format Helpers
// ============================================================================

/// Encode a message to wire format (length-prefixed JSON).
pub fn encode_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;

    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);

    Ok(buf)
}

/// Decode a message from wire format.
pub fn decode_message<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, DecodeError> {
    if data.len() < 4 {
        return Err(DecodeError::TooShort);
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if len > MAX_FRAME_SIZE as usize {
        return Err(DecodeError::TooLarge(len));
    }

    if data.len() < 4 + len {
        return Err(DecodeError::Incomplete {
            expected: len,
            got: data.len() - 4,
        });
    }

    serde_json::from_slice(&data[4..4 + len]).map_err(DecodeError::Json)
}

/// Error decoding a wire message.
#[derive(Debug)]
pub enum DecodeError {
    /// Data too short to contain length header.
    TooShort,
    /// Frame size exceeds maximum.
    TooLarge(usize),
    /// Incomplete frame.
    Incomplete {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// JSON parse error.
    Json(serde_json::Error),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "data too short for length header"),
            DecodeError::TooLarge(size) => write!(f, "frame too large: {} bytes", size),
            DecodeError::Incomplete { expected, got } => {
                write!(
                    f,
                    "incomplete frame: expected {} bytes, got {}",
                    expected, got
                )
            }
            DecodeError::Json(e) => write!(f, "JSON decode error: {}", e),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let req = AgentRequest::Pull {
            image: "alpine:latest".to_string(),
            platform: Some("linux/arm64".to_string()),
            auth: None,
        };

        let encoded = encode_message(&req).unwrap();
        let decoded: AgentRequest = decode_message(&encoded).unwrap();

        let AgentRequest::Pull {
            image,
            platform,
            auth,
        } = decoded
        else {
            panic!("expected Pull variant, got {:?}", decoded);
        };
        assert_eq!(image, "alpine:latest");
        assert_eq!(platform, Some("linux/arm64".to_string()));
        assert!(auth.is_none());
    }

    #[test]
    fn test_encode_decode_with_auth() {
        let req = AgentRequest::Pull {
            image: "ghcr.io/owner/repo:latest".to_string(),
            platform: None,
            auth: Some(RegistryAuth {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            }),
        };

        let encoded = encode_message(&req).unwrap();
        let decoded: AgentRequest = decode_message(&encoded).unwrap();

        let AgentRequest::Pull {
            image,
            platform,
            auth,
        } = decoded
        else {
            panic!("expected Pull variant, got {:?}", decoded);
        };
        assert_eq!(image, "ghcr.io/owner/repo:latest");
        assert!(platform.is_none());
        let auth = auth.expect("auth should be Some");
        assert_eq!(auth.username, "testuser");
        assert_eq!(auth.password, "testpass");
    }

    #[test]
    fn test_decode_too_short() {
        let data = [0u8; 2];
        let result: Result<AgentRequest, _> = decode_message(&data);
        assert!(matches!(result, Err(DecodeError::TooShort)));
    }

    #[test]
    fn test_decode_incomplete() {
        let mut data = vec![0, 0, 0, 100]; // claims 100 bytes
        data.extend_from_slice(b"{}"); // only 2 bytes of payload
        let result: Result<AgentRequest, _> = decode_message(&data);
        assert!(matches!(result, Err(DecodeError::Incomplete { .. })));
    }

    #[test]
    fn test_agent_request_serialization() {
        let req = AgentRequest::Ping;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("ping"));

        let req = AgentRequest::PrepareOverlay {
            image: "ubuntu:22.04".to_string(),
            workload_id: "wl-123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("prepare_overlay"));
    }

    #[test]
    fn test_agent_response_serialization() {
        let resp = AgentResponse::Pong {
            version: PROTOCOL_VERSION,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("pong"));

        let resp = AgentResponse::Progress {
            message: "Pulling layer 1/3".to_string(),
            percent: Some(33),
            layer: Some("sha256:abc123".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("progress"));
    }

    #[test]
    fn test_ports_constants() {
        assert_eq!(ports::WORKLOAD_CONTROL, 5000);
        assert_eq!(ports::WORKLOAD_LOGS, 5001);
        assert_eq!(ports::AGENT_CONTROL, 6000);
    }

    #[test]
    fn test_cid_constants() {
        assert_eq!(cid::HOST, 2);
        assert_eq!(cid::GUEST, 3);
    }
}
