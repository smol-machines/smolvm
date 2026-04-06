/// Bytes per mebibyte
pub const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Bytes per gibibyte (GiB).
pub const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;

/// Name of the environment variable that overrides the directory used to
/// locate bundled native libraries for smolvm.
///
/// If set, smolvm checks this directory before falling back to paths relative
/// to the current executable. This is primarily used by embedded runtimes.
pub const ENV_SMOLVM_LIB_DIR: &str = "SMOLVM_LIB_DIR";

/// Name of the environment variable that controls libkrun's log level.
///
/// Accepted values are integer levels understood by libkrun
/// (`0 = off`, `1 = error`, `2 = warn`, `3 = info`, `4 = debug`).
pub const ENV_SMOLVM_KRUN_LOG_LEVEL: &str = "SMOLVM_KRUN_LOG_LEVEL";

/// Default name of a microvm.
pub const DEFAULT_MACHINE_NAME: &str = "default";
