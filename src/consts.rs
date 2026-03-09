//! Shared constants used across smolvm.
//!
//! # Environment Variables
//!
//! This section defines the names of environment variables recognized by
//! smolvm. Keep all environment variable constants here so runtime behavior
//! and documentation stay in sync.

/// Name of the environment variable that overrides the directory used to
/// locate bundled native libraries for smolvm.
///
/// If set, smolvm checks this directory before falling back to paths
/// relative to the current executable. This is primarily used by embedded runtimes.
pub const ENV_SMOLVM_LIB_DIR: &str = "SMOLVM_LIB_DIR";
