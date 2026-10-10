//! Paths an in-process embedder (the Python or Node SDK) bundles for the engine: the signed
//! `smol-vmm` boot helper, the directory holding libkrun and libkrunfw, and the guest agent
//! rootfs tarball. An embedder hands them over once with [`set_bundle`]; the engine consults
//! them before the `SMOLVM_BOOT_BINARY`, `SMOLVM_LIB_DIR` and `SMOLVM_AGENT_ROOTFS_TAR`
//! environment variables, which remain the CLI-facing overrides.
//!
//! They are kept out of the process environment on purpose. When an SDK exported them as
//! environment variables, every `smolvm` CLI the embedding program spawned inherited them, so a
//! branch made from a Python script booted with the SDK's helper, which arms a parent-death
//! watchdog and exits as soon as the CLI that spawned it returns. The machine died within
//! seconds, and the SDK's bundled libraries and agent rootfs shadowed the CLI's own.
use std::path::PathBuf;
use std::sync::OnceLock;

/// What an embedder bundles. Every field is optional: a missing one falls back to the
/// environment variable and then to the engine's own layout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bundle {
    /// A `_boot-vm`-capable helper to spawn instead of `current_exe`.
    pub boot_binary: Option<PathBuf>,
    /// Directory holding libkrun and libkrunfw.
    pub lib_dir: Option<PathBuf>,
    /// Guest agent rootfs as a tarball, extracted on first use.
    pub agent_rootfs_tar: Option<PathBuf>,
}

static BUNDLE: OnceLock<Bundle> = OnceLock::new();

/// Record the embedder's bundle for this process. The first call wins; a later call with a
/// different bundle returns it as the error so the caller can report the conflict.
pub fn set_bundle(bundle: Bundle) -> Result<(), Bundle> {
    match BUNDLE.set(bundle.clone()) {
        Ok(()) => Ok(()),
        Err(_) if BUNDLE.get() == Some(&bundle) => Ok(()),
        Err(rejected) => Err(rejected),
    }
}

/// The bundle an embedder registered, if any.
pub fn bundle() -> Option<&'static Bundle> {
    BUNDLE.get()
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The boot helper to spawn: the embedder's, else `SMOLVM_BOOT_BINARY`, else none (spawn self).
pub fn boot_binary() -> Option<PathBuf> {
    bundle()
        .and_then(|b| b.boot_binary.clone())
        .or_else(|| env_path("SMOLVM_BOOT_BINARY"))
}

/// Where libkrun and libkrunfw live: the embedder's directory, else `SMOLVM_LIB_DIR`.
pub fn lib_dir() -> Option<PathBuf> {
    bundle()
        .and_then(|b| b.lib_dir.clone())
        .or_else(|| env_path(crate::data::consts::ENV_SMOLVM_LIB_DIR))
}

/// The guest agent rootfs tarball: the embedder's, else `SMOLVM_AGENT_ROOTFS_TAR`.
pub fn agent_rootfs_tar() -> Option<PathBuf> {
    bundle()
        .and_then(|b| b.agent_rootfs_tar.clone())
        .or_else(|| env_path("SMOLVM_AGENT_ROOTFS_TAR"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_identical_bundle_is_accepted_and_a_different_one_is_refused() {
        let b = Bundle {
            boot_binary: Some(PathBuf::from("/pkg/smol-vmm")),
            lib_dir: Some(PathBuf::from("/pkg")),
            agent_rootfs_tar: None,
        };
        // Whatever another test registered first, registering the same thing twice must be fine
        // and registering something else must be refused rather than silently ignored.
        let first = set_bundle(b.clone());
        let again = set_bundle(b.clone());
        assert_eq!(first.is_ok(), again.is_ok());
        let other = Bundle {
            boot_binary: Some(PathBuf::from("/elsewhere")),
            ..Default::default()
        };
        assert!(set_bundle(other.clone()).is_err() || bundle() == Some(&other));
    }
}
