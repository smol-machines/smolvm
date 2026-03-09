//! Shared utility functions.

use std::time::{SystemTime, UNIX_EPOCH};

// Re-export retry utilities from the protocol crate for convenience.
// This provides a single source of truth for retry logic across the codebase.
pub use smolvm_protocol::retry::{
    is_transient_io_error, is_transient_network_error, retry_with_backoff, RetryConfig,
};

/// Get current timestamp as seconds since Unix epoch.
///
/// Returns the timestamp as a simple string (e.g., "1705312345").
pub fn current_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    format!("{}", duration.as_secs())
}

/// Get the filename of libkrunfw dynamic lib
pub fn libkrunfw_filename() -> &'static str {
    #[cfg(target_os = "macos")]
    let lib_name = "libkrunfw.5.dylib";
    #[cfg(target_os = "linux")]
    let lib_name = "libkrunfw.so.5";
    lib_name
}

/// Get the filename of the libkrun dynamic lib
pub fn libkrun_filename() -> &'static str {
    #[cfg(target_os = "macos")]
    let lib_name = "libkrun.dylib";
    #[cfg(target_os = "linux")]
    let lib_name = "libkrun.so";
    lib_name
}
