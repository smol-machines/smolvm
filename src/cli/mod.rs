//! CLI command implementations.

pub mod container;
pub mod microvm;
pub mod pack;
pub mod parsers;
pub mod sandbox;
pub mod serve;

use std::io::Write;

// ============================================================================
// Display Constants
// ============================================================================

/// Display width for container IDs (first 12 characters).
pub const CONTAINER_ID_WIDTH: usize = 12;

/// Display width for image names.
pub const IMAGE_NAME_WIDTH: usize = 18;

/// Display width for command strings.
pub const COMMAND_WIDTH: usize = 28;

// ============================================================================
// Display Helpers
// ============================================================================

/// Truncate a string to max length, adding "..." if needed.
///
/// If the string fits within `max` characters, returns it unchanged.
/// Otherwise, truncates to `max - 3` characters and appends "...".
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

/// Truncate a container ID for display (first 12 characters).
pub fn truncate_id(id: &str) -> &str {
    if id.len() > CONTAINER_ID_WIDTH {
        &id[..CONTAINER_ID_WIDTH]
    } else {
        id
    }
}

/// Format an optional PID as a suffix string.
///
/// Returns " (PID: N)" if pid is Some, or empty string if None.
pub fn format_pid_suffix(pid: Option<i32>) -> String {
    pid.map(|p| format!(" (PID: {})", p)).unwrap_or_default()
}

/// Flush stdout and stderr, ignoring errors.
///
/// Used to ensure output is visible before blocking operations.
pub fn flush_output() {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}
