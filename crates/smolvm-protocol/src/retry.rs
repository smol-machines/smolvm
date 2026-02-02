//! Retry utilities for transient failure recovery.
//!
//! Provides exponential backoff retry logic for operations that may fail
//! transiently (network issues, resource contention, etc.).
//!
//! This module is shared between the host and agent to ensure consistent
//! retry behavior across the system.

use std::thread;
use std::time::Duration;
use tracing::{debug, warn};

// ============================================================================
// Retry Configuration Constants
// ============================================================================
//
// These values control retry behavior for different operation types.
// They balance between recovering from transient failures and failing fast
// for permanent errors.

/// Default maximum retry attempts for general operations.
/// 3 attempts = 1 initial + 2 retries, typically sufficient for transient issues.
const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// Default initial delay between retries (100ms).
/// Short enough to not add noticeable latency, long enough to let transient
/// issues resolve (e.g., brief network hiccups).
const DEFAULT_INITIAL_DELAY_MS: u64 = 100;

/// Default maximum delay cap (5 seconds).
/// Prevents exponential backoff from growing too large while keeping
/// total retry time reasonable.
const DEFAULT_MAX_DELAY_SECS: u64 = 5;

/// Standard exponential backoff multiplier.
/// Each retry waits 2x longer than the previous (100ms -> 200ms -> 400ms...).
const BACKOFF_MULTIPLIER: f64 = 2.0;

/// Maximum retry attempts for network operations (image pulls, registry calls).
/// 4 attempts allows recovery from longer network interruptions while still
/// failing within a reasonable time (~45 seconds worst case).
const NETWORK_MAX_ATTEMPTS: u32 = 4;

/// Initial delay for network operations (500ms).
/// Longer than default because network issues often need more time to resolve
/// (DNS propagation, connection pool recovery, rate limit windows).
const NETWORK_INITIAL_DELAY_MS: u64 = 500;

/// Maximum delay for network operations (5 seconds).
/// Capped to keep total retry time reasonable. If network issues persist
/// beyond this, they're likely not transient.
const NETWORK_MAX_DELAY_SECS: u64 = 5;

/// Initial delay for connection operations (50ms).
/// Very short because the agent should already be running - we're just handling
/// brief unavailability during high load or socket setup.
const CONNECTION_INITIAL_DELAY_MS: u64 = 50;

/// Maximum delay for connection operations (2 seconds).
/// If the agent isn't responding within 2 seconds between retries, something
/// is likely wrong beyond a transient issue.
const CONNECTION_MAX_DELAY_SECS: u64 = 2;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of attempts (including the initial attempt).
    pub max_attempts: u32,
    /// Initial delay between retries.
    pub initial_delay: Duration,
    /// Maximum delay between retries (caps exponential growth).
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (typically 2.0).
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_delay: Duration::from_millis(DEFAULT_INITIAL_DELAY_MS),
            max_delay: Duration::from_secs(DEFAULT_MAX_DELAY_SECS),
            backoff_multiplier: BACKOFF_MULTIPLIER,
        }
    }
}

impl RetryConfig {
    /// Create a config optimized for network operations (image pulls, registry calls).
    ///
    /// Uses longer delays and more attempts because network issues often need
    /// more time to resolve (DNS, rate limits, connection pool recovery).
    pub fn for_network() -> Self {
        Self {
            max_attempts: NETWORK_MAX_ATTEMPTS,
            initial_delay: Duration::from_millis(NETWORK_INITIAL_DELAY_MS),
            max_delay: Duration::from_secs(NETWORK_MAX_DELAY_SECS),
            backoff_multiplier: BACKOFF_MULTIPLIER,
        }
    }

    /// Create a config for socket/connection operations.
    ///
    /// Uses short delays because the agent should already be running.
    /// These retries handle brief unavailability during high load.
    pub fn for_connection() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_delay: Duration::from_millis(CONNECTION_INITIAL_DELAY_MS),
            max_delay: Duration::from_secs(CONNECTION_MAX_DELAY_SECS),
            backoff_multiplier: BACKOFF_MULTIPLIER,
        }
    }
}

/// Execute an operation with retry logic.
///
/// The `should_retry` function determines whether a given error is transient
/// and worth retrying.
///
/// # Example
///
/// ```ignore
/// let result = retry_with_backoff(
///     RetryConfig::for_network(),
///     "fetch manifest",
///     || fetch_manifest(image),
///     |e| is_transient_network_error(&e.to_string()),
/// );
/// ```
pub fn retry_with_backoff<T, E, F, R>(
    config: RetryConfig,
    operation_name: &str,
    mut operation: F,
    should_retry: R,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    R: Fn(&E) -> bool,
    E: std::fmt::Display,
{
    let mut attempt = 0;
    let mut delay = config.initial_delay;

    loop {
        attempt += 1;

        match operation() {
            Ok(result) => {
                if attempt > 1 {
                    debug!(
                        operation = %operation_name,
                        attempts = attempt,
                        "operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                if attempt >= config.max_attempts {
                    warn!(
                        operation = %operation_name,
                        attempts = attempt,
                        error = %e,
                        "operation failed after max attempts"
                    );
                    return Err(e);
                }

                if !should_retry(&e) {
                    debug!(
                        operation = %operation_name,
                        attempt = attempt,
                        error = %e,
                        "operation failed with non-retryable error"
                    );
                    return Err(e);
                }

                warn!(
                    operation = %operation_name,
                    attempt = attempt,
                    max_attempts = config.max_attempts,
                    delay_ms = delay.as_millis(),
                    error = %e,
                    "operation failed, will retry"
                );

                thread::sleep(delay);

                // Exponential backoff with cap
                delay = Duration::from_secs_f64(
                    (delay.as_secs_f64() * config.backoff_multiplier)
                        .min(config.max_delay.as_secs_f64()),
                );
            }
        }
    }
}

/// Check if an error message indicates a transient network failure.
///
/// This is a heuristic based on common error messages from network tools
/// and registries.
pub fn is_transient_network_error(error_msg: &str) -> bool {
    let error_lower = error_msg.to_lowercase();

    // Connection errors (transient)
    if error_lower.contains("connection refused")
        || error_lower.contains("connection reset")
        || error_lower.contains("connection timed out")
        || error_lower.contains("network is unreachable")
        || error_lower.contains("no route to host")
        || error_lower.contains("temporary failure")
        || error_lower.contains("try again")
        || error_lower.contains("resource temporarily unavailable")
    {
        return true;
    }

    // DNS errors (often transient)
    if error_lower.contains("name resolution")
        || error_lower.contains("dns")
        || error_lower.contains("could not resolve")
        || error_lower.contains("no such host")
    {
        return true;
    }

    // HTTP errors that may be transient
    if error_lower.contains("502 bad gateway")
        || error_lower.contains("503 service unavailable")
        || error_lower.contains("504 gateway timeout")
        || error_lower.contains("429 too many requests")
    {
        return true;
    }

    // Registry-specific transient errors
    if error_lower.contains("toomanyrequests")
        || error_lower.contains("rate limit")
        || error_lower.contains("quota exceeded")
    {
        return true;
    }

    // I/O errors that may be transient
    if error_lower.contains("broken pipe")
        || error_lower.contains("interrupted")
        || error_lower.contains("eagain")
        || error_lower.contains("ewouldblock")
    {
        return true;
    }

    false
}

/// Check if an error message indicates a permanent failure (don't retry).
pub fn is_permanent_error(error_msg: &str) -> bool {
    let error_lower = error_msg.to_lowercase();

    // Authentication/authorization errors
    if error_lower.contains("401 unauthorized")
        || error_lower.contains("403 forbidden")
        || error_lower.contains("authentication required")
        || error_lower.contains("access denied")
    {
        return true;
    }

    // Not found errors
    if error_lower.contains("404 not found")
        || error_lower.contains("manifest unknown")
        || error_lower.contains("name unknown")
        || error_lower.contains("repository does not exist")
    {
        return true;
    }

    // Invalid input
    if error_lower.contains("invalid reference")
        || error_lower.contains("invalid image")
        || error_lower.contains("malformed")
    {
        return true;
    }

    false
}

/// Check if an I/O error is likely transient and worth retrying.
pub fn is_transient_io_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn test_retry_success_first_attempt() {
        let result: Result<i32, &str> =
            retry_with_backoff(RetryConfig::default(), "test", || Ok(42), |_| true);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_retry_success_after_failures() {
        let attempts = RefCell::new(0);
        let result: Result<i32, &str> = retry_with_backoff(
            RetryConfig {
                max_attempts: 3,
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(10),
                backoff_multiplier: 2.0,
            },
            "test",
            || {
                *attempts.borrow_mut() += 1;
                if *attempts.borrow() < 3 {
                    Err("transient error")
                } else {
                    Ok(42)
                }
            },
            |_| true,
        );
        assert_eq!(result.unwrap(), 42);
        assert_eq!(*attempts.borrow(), 3);
    }

    #[test]
    fn test_retry_exhausted() {
        let attempts = RefCell::new(0);
        let result: Result<i32, &str> = retry_with_backoff(
            RetryConfig {
                max_attempts: 3,
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(10),
                backoff_multiplier: 2.0,
            },
            "test",
            || {
                *attempts.borrow_mut() += 1;
                Err("always fails")
            },
            |_| true,
        );
        assert!(result.is_err());
        assert_eq!(*attempts.borrow(), 3);
    }

    #[test]
    fn test_retry_non_retryable_error() {
        let attempts = RefCell::new(0);
        let result: Result<i32, &str> = retry_with_backoff(
            RetryConfig::default(),
            "test",
            || {
                *attempts.borrow_mut() += 1;
                Err("permanent error")
            },
            |_| false, // Never retry
        );
        assert!(result.is_err());
        assert_eq!(*attempts.borrow(), 1);
    }

    #[test]
    fn test_transient_network_errors() {
        assert!(is_transient_network_error("connection refused"));
        assert!(is_transient_network_error("Connection timed out"));
        assert!(is_transient_network_error("503 Service Unavailable"));
        assert!(is_transient_network_error("rate limit exceeded"));
        assert!(!is_transient_network_error("404 not found"));
        assert!(!is_transient_network_error("some random error"));
    }

    #[test]
    fn test_permanent_errors() {
        assert!(is_permanent_error("401 Unauthorized"));
        assert!(is_permanent_error("404 Not Found"));
        assert!(is_permanent_error("manifest unknown"));
        assert!(!is_permanent_error("connection refused"));
        assert!(!is_permanent_error("503 Service Unavailable"));
    }

    #[test]
    fn test_config_presets() {
        let network = RetryConfig::for_network();
        assert_eq!(network.max_attempts, 4);
        assert_eq!(network.initial_delay, Duration::from_millis(500));

        let connection = RetryConfig::for_connection();
        assert_eq!(connection.max_attempts, 3);
        assert_eq!(connection.initial_delay, Duration::from_millis(50));
    }
}
