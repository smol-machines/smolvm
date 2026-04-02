//! VM lifecycle state types.

use serde::{Deserialize, Serialize};

/// VM lifecycle states (from DESIGN.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum VmState {
    /// VM created but not started.
    Created,

    /// VM is booting.
    Booting,

    /// VM is ready (guest agent connected).
    Ready,

    /// VM is running workload.
    Running,

    /// VM is shutting down.
    Stopping,

    /// VM has stopped cleanly.
    Stopped,

    /// VM failed with error.
    Failed {
        /// Reason for failure.
        reason: String,
    },
}

impl VmState {
    /// Check if the VM is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, VmState::Stopped | VmState::Failed { .. })
    }

    /// Check if the VM is currently running (Ready or Running).
    pub fn is_running(&self) -> bool {
        matches!(self, VmState::Running | VmState::Ready)
    }

    /// Check if the VM can be started.
    pub fn can_start(&self) -> bool {
        matches!(self, VmState::Created)
    }

    /// Check if the VM can be stopped.
    pub fn can_stop(&self) -> bool {
        matches!(self, VmState::Booting | VmState::Ready | VmState::Running)
    }

    /// Get the state name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            VmState::Created => "created",
            VmState::Booting => "booting",
            VmState::Ready => "ready",
            VmState::Running => "running",
            VmState::Stopping => "stopping",
            VmState::Stopped => "stopped",
            VmState::Failed { .. } => "failed",
        }
    }
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmState::Failed { reason } => write!(f, "failed: {}", reason),
            _ => write!(f, "{}", self.name()),
        }
    }
}

/// Exit reason for a VM (from DESIGN.md).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExitReason {
    /// Clean exit with code.
    Exited {
        /// Exit code from the process.
        code: i32,
    },

    /// Killed by signal.
    Signaled {
        /// Signal number.
        signal: i32,
    },

    /// Execution timeout reached.
    Timeout,

    /// Out of memory.
    OomKilled,

    /// Disk full (exit code 200 per DESIGN.md).
    DiskFull,

    /// VM crashed.
    VmCrash {
        /// Details about the crash.
        details: String,
    },

    /// Protocol/communication error.
    ProtocolError {
        /// Details about the error.
        details: String,
    },
}

impl ExitReason {
    /// Map to exit code for CLI (per DESIGN.md conventions).
    pub fn exit_code(&self) -> i32 {
        match self {
            ExitReason::Exited { code } => *code,
            ExitReason::Signaled { signal } => 128 + signal,
            ExitReason::Timeout => 124,   // Standard timeout exit code
            ExitReason::OomKilled => 137, // 128 + SIGKILL(9)
            ExitReason::DiskFull => 200,  // Per DESIGN.md
            ExitReason::VmCrash { .. } => 1,
            ExitReason::ProtocolError { .. } => 1,
        }
    }

    /// Check if this represents a successful exit.
    pub fn is_success(&self) -> bool {
        matches!(self, ExitReason::Exited { code: 0 })
    }

    /// Create an exited reason with the given code.
    pub fn exited(code: i32) -> Self {
        Self::Exited { code }
    }

    /// Create a signaled reason with the given signal.
    pub fn signaled(signal: i32) -> Self {
        Self::Signaled { signal }
    }

    /// Create a VM crash reason with details.
    pub fn vm_crash(details: impl Into<String>) -> Self {
        Self::VmCrash {
            details: details.into(),
        }
    }

    /// Create a protocol error reason with details.
    pub fn protocol_error(details: impl Into<String>) -> Self {
        Self::ProtocolError {
            details: details.into(),
        }
    }
}

impl std::fmt::Display for ExitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitReason::Exited { code } => write!(f, "exited with code {}", code),
            ExitReason::Signaled { signal } => write!(f, "killed by signal {}", signal),
            ExitReason::Timeout => write!(f, "execution timeout"),
            ExitReason::OomKilled => write!(f, "out of memory"),
            ExitReason::DiskFull => write!(f, "disk full"),
            ExitReason::VmCrash { details } => write!(f, "vm crash: {}", details),
            ExitReason::ProtocolError { details } => write!(f, "protocol error: {}", details),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_state_transitions() {
        // (state, is_terminal, can_start, can_stop)
        let cases = [
            (VmState::Created, false, true, false),
            (VmState::Booting, false, false, true),
            (VmState::Running, false, false, true),
            (VmState::Stopped, true, false, false),
            (
                VmState::Failed {
                    reason: "test".to_string(),
                },
                true,
                false,
                false,
            ),
        ];

        for (state, terminal, start, stop) in cases {
            assert_eq!(state.is_terminal(), terminal, "{:?}.is_terminal()", state);
            assert_eq!(state.can_start(), start, "{:?}.can_start()", state);
            assert_eq!(state.can_stop(), stop, "{:?}.can_stop()", state);
        }
    }

    #[test]
    fn test_exit_reason_exit_codes() {
        // Documents DESIGN.md exit code contract
        assert_eq!(ExitReason::exited(0).exit_code(), 0);
        assert_eq!(ExitReason::exited(1).exit_code(), 1);
        assert_eq!(ExitReason::signaled(9).exit_code(), 137); // 128 + SIGKILL
        assert_eq!(ExitReason::Timeout.exit_code(), 124);
        assert_eq!(ExitReason::OomKilled.exit_code(), 137);
        assert_eq!(ExitReason::DiskFull.exit_code(), 200);
    }

    #[test]
    fn test_exit_reason_serialization() {
        let reason = ExitReason::exited(42);
        let json = serde_json::to_string(&reason).unwrap();
        let deserialized: ExitReason = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, reason);
    }
}
