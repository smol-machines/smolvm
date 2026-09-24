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

/// Default machine name for `machine` subcommands that take `--name`.
///
/// An explicit `--name` always wins. Meant for per-workspace tooling (direnv
/// and friends) that pins a shell to one long-running machine, so `machine
/// exec`/`shell`/`stop` need no flag. Deliberately not read by `machine run`
/// (every run would collide on one ephemeral name), `machine checkpoint`
/// (a set variable would trip its `--export-from` conflict rule), or
/// `machine branch` (its `--name` mints the child, not selects a machine).
pub const ENV_SMOLVM_MACHINE_NAME: &str = "SMOLVM_MACHINE_NAME";

/// Name of the environment variable that controls libkrun's log level.
///
/// Accepted values are integer levels understood by libkrun
/// (`0 = off`, `1 = error`, `2 = warn`, `3 = info`, `4 = debug`).
pub const ENV_SMOLVM_KRUN_LOG_LEVEL: &str = "SMOLVM_KRUN_LOG_LEVEL";
