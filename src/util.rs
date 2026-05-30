//! Shared utility functions.

use std::time::{SystemTime, UNIX_EPOCH};

// Re-export retry utilities from the protocol crate for convenience.
// This provides a single source of truth for retry logic across the codebase.
pub use smolvm_protocol::retry::{
    is_transient_io_error, is_transient_network_error, retry_with_backoff, RetryConfig,
};

/// Generate a short random ID for auto-naming machines.
///
/// Produces an 8-character hex string (e.g., "a1b2c3d4") from 4 bytes
/// of OS entropy. Falls back to time+pid if /dev/urandom is unavailable.
pub fn generate_short_id() -> String {
    let mut buf = [0u8; 4];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut buf)
        })
        .is_ok()
    {
        return format!("{:08x}", u32::from_le_bytes(buf));
    }
    // Fallback: time + pid (less random but functional)
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}", (nanos as u32) ^ std::process::id())
}

/// Generate an auto machine name (e.g., "vm-a1b2c3d4").
pub fn generate_machine_name() -> String {
    format!("vm-{}", generate_short_id())
}

/// Get current timestamp as seconds since Unix epoch.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

/// Parse a single environment variable specification.
///
/// - `KEY=VALUE` → `Some((KEY, VALUE))`.
/// - `KEY` (no `=`) → forwards the host's current value for `KEY` (Docker
///   `-e KEY` semantics); `None` if the host variable is unset.
/// - empty key (`=VALUE`) or empty spec → `None`.
pub fn parse_env_spec(spec: &str) -> Option<(String, String)> {
    match spec.split_once('=') {
        Some((key, value)) => {
            if key.is_empty() {
                None
            } else {
                Some((key.to_string(), value.to_string()))
            }
        }
        None => {
            if spec.is_empty() {
                None
            } else {
                // Key-only form: forward the value from the host environment.
                std::env::var(spec).ok().map(|v| (spec.to_string(), v))
            }
        }
    }
}

/// Parse a list of `KEY=VALUE` strings into `(key, value)` tuples.
///
/// Silently skips malformed entries (no `=` or empty key).
pub fn parse_env_list(env_args: &[String]) -> Vec<(String, String)> {
    env_args.iter().filter_map(|e| parse_env_spec(e)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn parse_env_spec_key_value() {
        assert_eq!(
            parse_env_spec("FOO=bar"),
            Some(("FOO".to_string(), "bar".to_string()))
        );
        // Empty value is allowed.
        assert_eq!(
            parse_env_spec("FOO="),
            Some(("FOO".to_string(), String::new()))
        );
        // Empty key is rejected.
        assert_eq!(parse_env_spec("=bar"), None);
        assert_eq!(parse_env_spec(""), None);
    }

    #[test]
    fn parse_env_spec_key_only_forwards_host_value() {
        let key = "SMOLVM_TEST_ENV_FWD_XYZ";
        std::env::set_var(key, "host_value");
        assert_eq!(
            parse_env_spec(key),
            Some((key.to_string(), "host_value".to_string()))
        );
        std::env::remove_var(key);
        // Unset host var → skipped.
        assert_eq!(parse_env_spec(key), None);
    }

    #[test]
    fn test_generate_ids() {
        // Generate 100 IDs and validate all of them
        let ids: Vec<String> = (0..100).map(|_| generate_short_id()).collect();

        for id in &ids {
            assert_eq!(id.len(), 8, "should be 8 hex chars: {id}");
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "not hex: {id}");
        }

        // All unique
        let unique: HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), 100, "100 IDs should all be unique");

        // Machine name wraps the ID correctly
        let name = generate_machine_name();
        assert!(name.starts_with("vm-"), "prefix: {name}");
        assert_eq!(name.len(), 11, "length: {name}");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));

        // Two names differ
        assert_ne!(generate_machine_name(), generate_machine_name());
    }
}
