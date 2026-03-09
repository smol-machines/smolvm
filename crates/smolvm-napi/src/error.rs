//! Error conversion from smolvm::Error to napi::Error.

use napi::Status;
use smolvm::error::{AgentErrorKind, Error as SmolvmError};

/// Error codes exposed to JavaScript as `error.code`.
pub const NOT_FOUND: &str = "NOT_FOUND";
pub const INVALID_STATE: &str = "INVALID_STATE";
pub const HYPERVISOR_UNAVAILABLE: &str = "HYPERVISOR_UNAVAILABLE";
pub const CONFLICT: &str = "CONFLICT";
pub const STORAGE_ERROR: &str = "STORAGE_ERROR";
pub const MOUNT_ERROR: &str = "MOUNT_ERROR";
pub const CONFIG_ERROR: &str = "CONFIG_ERROR";
pub const COMMAND_FAILED: &str = "COMMAND_FAILED";
pub const KVM_UNAVAILABLE: &str = "KVM_UNAVAILABLE";
pub const SMOLVM_ERROR: &str = "SMOLVM_ERROR";

/// Convert a smolvm::Error into a napi::Error with an appropriate error code.
pub fn to_napi_error(err: SmolvmError) -> napi::Error {
    let (code, msg) = match &err {
        SmolvmError::VmNotFound { name } => (NOT_FOUND, format!("VM not found: {}", name)),

        SmolvmError::InvalidState { expected, actual } => (
            INVALID_STATE,
            format!("Invalid state: expected {}, got {}", expected, actual),
        ),

        SmolvmError::HypervisorUnavailable(reason) => (
            HYPERVISOR_UNAVAILABLE,
            format!("Hypervisor unavailable: {}", reason),
        ),

        SmolvmError::Agent {
            operation,
            reason,
            kind,
        } => {
            let code = match kind {
                AgentErrorKind::NotFound => NOT_FOUND,
                AgentErrorKind::Conflict => CONFLICT,
                AgentErrorKind::Other => SMOLVM_ERROR,
            };
            (code, format!("Agent error ({}): {}", operation, reason))
        }

        SmolvmError::RootfsNotFound { path } => {
            (NOT_FOUND, format!("Rootfs not found: {}", path.display()))
        }

        SmolvmError::DiskNotFound { path } => {
            (NOT_FOUND, format!("Disk not found: {}", path.display()))
        }

        SmolvmError::MountSourceNotFound { path } => (
            NOT_FOUND,
            format!("Mount source not found: {}", path.display()),
        ),

        SmolvmError::Storage { operation, reason } => (
            STORAGE_ERROR,
            format!("Storage ({}): {}", operation, reason),
        ),

        SmolvmError::Mount { operation, reason } => {
            (MOUNT_ERROR, format!("Mount ({}): {}", operation, reason))
        }

        SmolvmError::InvalidMountPath { reason } => {
            (MOUNT_ERROR, format!("Invalid mount path: {}", reason))
        }

        SmolvmError::Config { operation, reason } => {
            (CONFIG_ERROR, format!("Config ({}): {}", operation, reason))
        }

        SmolvmError::CommandFailed { command, reason } => (
            COMMAND_FAILED,
            format!("Command '{}' failed: {}", command, reason),
        ),

        SmolvmError::KvmUnavailable(reason) => {
            (KVM_UNAVAILABLE, format!("KVM unavailable: {}", reason))
        }

        SmolvmError::KvmPermission(reason) => (
            KVM_UNAVAILABLE,
            format!("KVM permission denied: {}", reason),
        ),

        _ => (SMOLVM_ERROR, err.to_string()),
    };

    napi::Error::new(Status::GenericFailure, format!("[{}] {}", code, msg))
}

/// Extension trait for converting smolvm::Result<T> to napi::Result<T>.
pub trait IntoNapiResult<T> {
    fn into_napi(self) -> napi::Result<T>;
}

impl<T> IntoNapiResult<T> for smolvm::error::Result<T> {
    fn into_napi(self) -> napi::Result<T> {
        self.map_err(to_napi_error)
    }
}
