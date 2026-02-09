//! Error types for smolvm.
//!
//! # Error Message Style Guide
//!
//! All error messages follow a consistent format for clarity and actionability:
//!
//! - **Format**: `"<operation> failed: <reason>"` or `"<entity> not found: <identifier>"`
//! - **Case**: All lowercase (Rust convention for error messages)
//! - **Context**: Include relevant identifiers (VM name, path, key) when available
//! - **Actionability**: Messages should help users understand what went wrong and how to fix it
//!
//! ## Preferred Patterns
//!
//! ```text
//! // Operation failures (use "failed" consistently)
//! "vm creation failed: insufficient memory"
//! "database write failed: disk full"
//!
//! // Not found errors (use structured variants)
//! "vm not found: my-vm"
//! "mount source not found: /path/to/dir"
//!
//! // Invalid state/input errors
//! "invalid vm state: expected running, got stopped"
//! "invalid mount path: source must be absolute"
//! ```
//!
//! ## Anti-patterns to Avoid
//!
//! ```text
//! // Don't use "error" as a suffix - redundant
//! "storage error: ..."  // Bad
//! "storage operation failed: ..."  // Good
//!
//! // Don't omit context when available
//! "failed to open database"  // Bad - which database?
//! "database open failed: /path/to/db"  // Good
//! ```

use std::path::PathBuf;
use thiserror::Error;

/// Classification for agent errors, used to map to HTTP status codes
/// without fragile string matching on error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentErrorKind {
    /// Resource not found (maps to 404).
    NotFound,
    /// Conflict / resource already exists (maps to 409).
    Conflict,
    /// General error (maps to 500).
    #[default]
    Other,
}

/// Result type alias using smolvm's Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in smolvm operations.
///
/// Error messages follow a consistent format. See module documentation for style guide.
#[derive(Error, Debug)]
pub enum Error {
    // ========================================================================
    // VM Lifecycle Errors
    // ========================================================================
    /// Failed to create a VM.
    #[error("vm creation failed: {0}")]
    VmCreation(String),

    /// Failed to boot a VM.
    #[error("vm boot failed: {0}")]
    BootFailed(String),

    /// VM not found by name.
    #[error("vm not found: {name}")]
    VmNotFound {
        /// Name of the VM that was not found.
        name: String,
    },

    /// Hypervisor is not available on this system.
    #[error("hypervisor not available: {0}")]
    HypervisorUnavailable(String),

    /// VM is in an invalid state for the requested operation.
    #[error("invalid vm state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state.
        expected: String,
        /// Actual state.
        actual: String,
    },

    // ========================================================================
    // Rootfs Errors
    // ========================================================================
    /// Rootfs operation failed.
    #[error("rootfs operation failed: {0}")]
    Rootfs(String),

    /// Rootfs path does not exist.
    #[error("rootfs not found: {}", path.display())]
    RootfsNotFound {
        /// Path that was not found.
        path: PathBuf,
    },

    // ========================================================================
    // Storage Errors
    // ========================================================================
    /// Storage operation failed.
    #[error("storage operation failed: {operation}: {reason}")]
    Storage {
        /// The operation that failed (e.g., "create directory", "copy template").
        operation: String,
        /// The reason for the failure.
        reason: String,
    },

    /// Disk not found at expected path.
    #[error("disk not found: {}", path.display())]
    DiskNotFound {
        /// Path to the disk.
        path: PathBuf,
    },

    // ========================================================================
    // Mount Errors
    // ========================================================================
    /// Mount operation failed.
    #[error("mount operation failed: {operation}: {reason}")]
    Mount {
        /// The operation that failed (e.g., "validate source", "canonicalize path").
        operation: String,
        /// The reason for the failure.
        reason: String,
    },

    /// Invalid mount path specification.
    #[error("invalid mount path: {reason}")]
    InvalidMountPath {
        /// Explanation of why the path is invalid.
        reason: String,
    },

    /// Mount source path does not exist.
    #[error("mount source not found: {}", path.display())]
    MountSourceNotFound {
        /// Path that was not found.
        path: PathBuf,
    },

    // ========================================================================
    // Configuration Errors
    // ========================================================================
    /// Configuration operation failed.
    #[error("config operation failed: {operation}: {reason}")]
    Config {
        /// The operation that failed (e.g., "load", "save", "parse").
        operation: String,
        /// The reason for the failure.
        reason: String,
    },

    // ========================================================================
    // Database Errors
    // ========================================================================
    /// Database operation failed.
    #[error("database operation failed: {operation}: {reason}")]
    Database {
        /// The operation that failed (e.g., "open", "read", "write").
        operation: String,
        /// The reason for the failure.
        reason: String,
    },

    /// Database is not available (closed or not initialized).
    #[error("database not available: {0}")]
    DatabaseUnavailable(String),

    // ========================================================================
    // Command Execution Errors
    // ========================================================================
    /// External command failed.
    #[error("command '{command}' failed: {reason}")]
    CommandFailed {
        /// The command that failed.
        command: String,
        /// Error message or reason for failure.
        reason: String,
    },

    // ========================================================================
    // Agent VM Errors
    // ========================================================================
    /// Agent operation failed (structured).
    #[error("agent operation failed: {operation}: {reason}")]
    Agent {
        /// The operation that failed (e.g., "start", "connect", "pull image").
        operation: String,
        /// The reason for the failure.
        reason: String,
        /// Classification for HTTP status mapping.
        kind: AgentErrorKind,
    },

    // ========================================================================
    // KVM Errors (Linux)
    // ========================================================================
    /// KVM is not available (module not loaded).
    #[error("kvm not available: {0}")]
    KvmUnavailable(String),

    /// KVM permission denied (user not in kvm group).
    #[error("kvm permission denied: {0}")]
    KvmPermission(String),

    // ========================================================================
    // IO Errors
    // ========================================================================
    /// IO error wrapper.
    #[error("io operation failed: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    // ========================================================================
    // VM Error Constructors
    // ========================================================================

    /// Create a VM creation error.
    pub fn vm_creation(reason: impl Into<String>) -> Self {
        Self::VmCreation(reason.into())
    }

    /// Create a VM not found error.
    pub fn vm_not_found(name: impl Into<String>) -> Self {
        Self::VmNotFound { name: name.into() }
    }

    // ========================================================================
    // Rootfs Error Constructors
    // ========================================================================

    /// Create a rootfs operation error.
    pub fn rootfs(reason: impl Into<String>) -> Self {
        Self::Rootfs(reason.into())
    }

    // ========================================================================
    // Storage Error Constructors
    // ========================================================================

    /// Create a storage operation error.
    pub fn storage(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Storage {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    // ========================================================================
    // Mount Error Constructors
    // ========================================================================

    /// Create a mount operation error.
    pub fn mount(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Mount {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid mount path error.
    pub fn invalid_mount_path(reason: impl Into<String>) -> Self {
        Self::InvalidMountPath {
            reason: reason.into(),
        }
    }

    // ========================================================================
    // Config Error Constructors
    // ========================================================================

    /// Create a config operation error.
    pub fn config(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Config {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    // ========================================================================
    // Database Error Constructors
    // ========================================================================

    /// Create a database operation error.
    pub fn database(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Database {
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// Create a database unavailable error.
    pub fn database_unavailable(reason: impl Into<String>) -> Self {
        Self::DatabaseUnavailable(reason.into())
    }

    // ========================================================================
    // Command Error Constructors
    // ========================================================================

    /// Create a command failed error.
    pub fn command_failed(command: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CommandFailed {
            command: command.into(),
            reason: reason.into(),
        }
    }

    // ========================================================================
    // Agent Error Constructors
    // ========================================================================

    /// Create an agent operation error.
    pub fn agent(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Agent {
            operation: operation.into(),
            reason: reason.into(),
            kind: AgentErrorKind::Other,
        }
    }

    /// Create an agent "not found" error (maps to 404).
    pub fn agent_not_found(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Agent {
            operation: operation.into(),
            reason: reason.into(),
            kind: AgentErrorKind::NotFound,
        }
    }

    /// Create an agent "conflict" error (maps to 409).
    pub fn agent_conflict(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Agent {
            operation: operation.into(),
            reason: reason.into(),
            kind: AgentErrorKind::Conflict,
        }
    }

    // ========================================================================
    // KVM Error Constructors
    // ========================================================================

    /// Create a KVM unavailable error.
    pub fn kvm_unavailable(reason: impl Into<String>) -> Self {
        Self::KvmUnavailable(reason.into())
    }

    /// Create a KVM permission error.
    pub fn kvm_permission(reason: impl Into<String>) -> Self {
        Self::KvmPermission(reason.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Error messages should include context that helps users fix the problem.
    /// These tests verify that error messages contain actionable information.

    // ========================================================================
    // VM Error Tests
    // ========================================================================

    #[test]
    fn test_vm_not_found_includes_name() {
        let err = Error::vm_not_found("my-test-vm");
        let msg = err.to_string();
        assert!(msg.contains("my-test-vm"), "Error should include VM name");
        assert!(msg.contains("not found"), "Error should indicate not found");
    }

    #[test]
    fn test_vm_creation_includes_reason() {
        let err = Error::vm_creation("insufficient memory");
        let msg = err.to_string();
        assert!(
            msg.contains("creation failed"),
            "Error should indicate creation failed"
        );
        assert!(
            msg.contains("insufficient memory"),
            "Error should include reason"
        );
    }

    #[test]
    fn test_invalid_state_includes_both_states() {
        let err = Error::InvalidState {
            expected: "running".to_string(),
            actual: "stopped".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("running"),
            "Error should include expected state"
        );
        assert!(msg.contains("stopped"), "Error should include actual state");
    }

    // ========================================================================
    // Storage Error Tests
    // ========================================================================

    #[test]
    fn test_storage_error_includes_operation_and_reason() {
        let err = Error::storage("create directory", "permission denied");
        let msg = err.to_string();
        assert!(
            msg.contains("create directory"),
            "Error should include operation"
        );
        assert!(
            msg.contains("permission denied"),
            "Error should include reason"
        );
        assert!(
            msg.contains("operation failed"),
            "Error should indicate failure"
        );
    }

    // ========================================================================
    // Mount Error Tests
    // ========================================================================

    #[test]
    fn test_mount_source_not_found_includes_path() {
        let err = Error::MountSourceNotFound {
            path: PathBuf::from("/nonexistent/path"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/path"),
            "Error should include the path"
        );
        assert!(msg.contains("not found"), "Error should indicate not found");
    }

    #[test]
    fn test_mount_error_includes_operation_and_reason() {
        let err = Error::mount("validate source", "path does not exist");
        let msg = err.to_string();
        assert!(
            msg.contains("validate source"),
            "Error should include operation"
        );
        assert!(
            msg.contains("path does not exist"),
            "Error should include reason"
        );
    }

    #[test]
    fn test_invalid_mount_path_includes_reason() {
        let err = Error::invalid_mount_path("source must be absolute");
        let msg = err.to_string();
        assert!(
            msg.contains("absolute"),
            "Error should explain what's wrong"
        );
        assert!(
            msg.contains("invalid mount path"),
            "Error should indicate invalid path"
        );
    }

    // ========================================================================
    // Rootfs Error Tests
    // ========================================================================

    #[test]
    fn test_rootfs_not_found_includes_path() {
        let err = Error::RootfsNotFound {
            path: PathBuf::from("/my/rootfs"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/my/rootfs"),
            "Error should include rootfs path"
        );
    }

    // ========================================================================
    // Database Error Tests
    // ========================================================================

    #[test]
    fn test_database_error_includes_operation_and_reason() {
        let err = Error::database("open", "file locked by another process");
        let msg = err.to_string();
        assert!(msg.contains("open"), "Error should include operation");
        assert!(msg.contains("file locked"), "Error should include reason");
        assert!(
            msg.contains("operation failed"),
            "Error should indicate failure"
        );
    }

    #[test]
    fn test_database_unavailable_includes_reason() {
        let err = Error::database_unavailable("database is closed");
        let msg = err.to_string();
        assert!(msg.contains("closed"), "Error should include reason");
        assert!(
            msg.contains("not available"),
            "Error should indicate unavailable"
        );
    }

    // ========================================================================
    // Command Error Tests
    // ========================================================================

    #[test]
    fn test_command_failed_includes_command_and_reason() {
        let err = Error::command_failed("crane", "image not found");
        let msg = err.to_string();
        assert!(msg.contains("crane"), "Error should include command name");
        assert!(
            msg.contains("image not found"),
            "Error should include reason"
        );
        assert!(msg.contains("failed"), "Error should indicate failure");
    }

    // ========================================================================
    // Agent Error Tests
    // ========================================================================

    #[test]
    fn test_agent_error_includes_operation_and_reason() {
        let err = Error::agent("pull image", "registry unavailable");
        let msg = err.to_string();
        assert!(msg.contains("pull image"), "Error should include operation");
        assert!(
            msg.contains("registry unavailable"),
            "Error should include reason"
        );
        assert!(
            msg.contains("operation failed"),
            "Error should indicate failure"
        );
    }

    // ========================================================================
    // Config Error Tests
    // ========================================================================

    #[test]
    fn test_config_error_includes_operation_and_reason() {
        let err = Error::config("load", "file not found");
        let msg = err.to_string();
        assert!(msg.contains("load"), "Error should include operation");
        assert!(
            msg.contains("file not found"),
            "Error should include reason"
        );
    }

    // ========================================================================
    // Error Message Format Consistency Tests
    // ========================================================================

    #[test]
    fn test_all_errors_are_lowercase() {
        // Verify error messages don't start with capital letters (Rust convention)
        let errors: Vec<Error> = vec![
            Error::vm_creation("test"),
            Error::vm_not_found("test"),
            Error::rootfs("test"),
            Error::storage("op", "reason"),
            Error::mount("op", "reason"),
            Error::invalid_mount_path("reason"),
            Error::config("op", "reason"),
            Error::database("op", "reason"),
            Error::database_unavailable("reason"),
            Error::command_failed("cmd", "reason"),
            Error::agent("op", "reason"),
            Error::kvm_unavailable("reason"),
            Error::kvm_permission("reason"),
        ];

        for err in errors {
            let msg = err.to_string();
            let first_char = msg.chars().next().unwrap();
            assert!(
                first_char.is_lowercase(),
                "Error message should start lowercase: {}",
                msg
            );
        }
    }

    #[test]
    fn test_error_messages_contain_failed_or_not_found() {
        // Verify error messages follow our convention of "failed" or "not found"
        let operation_errors: Vec<Error> = vec![
            Error::vm_creation("test"),
            Error::storage("op", "reason"),
            Error::mount("op", "reason"),
            Error::database("op", "reason"),
            Error::command_failed("cmd", "reason"),
            Error::agent("op", "reason"),
        ];

        for err in operation_errors {
            let msg = err.to_string();
            assert!(
                msg.contains("failed"),
                "Operation error should contain 'failed': {}",
                msg
            );
        }

        let not_found_errors: Vec<Error> = vec![
            Error::vm_not_found("test"),
            Error::MountSourceNotFound {
                path: PathBuf::from("/test"),
            },
            Error::RootfsNotFound {
                path: PathBuf::from("/test"),
            },
            Error::DiskNotFound {
                path: PathBuf::from("/test"),
            },
        ];

        for err in not_found_errors {
            let msg = err.to_string();
            assert!(
                msg.contains("not found"),
                "Not found error should contain 'not found': {}",
                msg
            );
        }
    }
}
