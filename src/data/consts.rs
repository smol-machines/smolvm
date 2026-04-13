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

/// Name of the environment variable the host sets on guest init to
/// signal GPU acceleration was requested (`--gpu` or `gpu = true`).
///
/// Present means "host asked for GPU"; the guest agent reads this and
/// emits a post-boot sanity log confirming whether `/dev/dri/*` nodes
/// actually appeared. Absent means no GPU was requested.
///
/// This is a boolean sentinel, not a count — the value is `ENV_VALUE_ON`
/// ("1") when set. Multi-GPU (if ever supported) would use a distinct
/// variable like `SMOLVM_GPU_COUNT`.
///
/// Host writer: `src/agent/launcher.rs::launch_agent_vm` when
/// `resources.gpu == true`.
/// Guest reader: `crates/smolvm-agent/src/main.rs::main` on startup.
/// The agent crate duplicates the literal string because it does not
/// depend on this crate; both sides must agree on the name.
pub const ENV_SMOLVM_GPU: &str = "SMOLVM_GPU";

/// Standard "enabled" value for boolean SMOLVM_* sentinel env vars.
///
/// The host writes this when a feature is enabled and the guest agent
/// compares against it. Having a single canonical value means
/// `SMOLVM_FEATURE=true` or `SMOLVM_FEATURE=yes` don't silently match
/// or miss depending on who parses them.
pub const ENV_VALUE_ON: &str = "1";

#[cfg(test)]
mod tests {
    use super::*;

    /// The guest agent crate (`crates/smolvm-agent/src/main.rs`)
    /// redeclares these literals locally because it doesn't depend on
    /// the host crate. This test pins the host-side values so a
    /// rename here fails CI and forces the agent side to be updated
    /// in the same change. Wire drift between host and guest on a
    /// feature sentinel would be silent otherwise.
    #[test]
    fn host_guest_env_literals_are_stable() {
        assert_eq!(ENV_SMOLVM_GPU, "SMOLVM_GPU");
        assert_eq!(ENV_VALUE_ON, "1");
    }
}
