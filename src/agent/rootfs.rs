//! The one place a host process decides which guest agent rootfs to boot.
//!
//! Every command that starts a guest (`machine start`), builds one into an
//! artifact (`pack create`), or captures one (a portable checkpoint) must boot
//! the *same* agent as the machines it operates on. Until now each had its own
//! search with a different order and a different data directory, so on one box
//! `pack create` could export a machine through an older agent than
//! `machine start` had booted it with, failing deep inside the export with an
//! unknown-request error the moment the agent protocol grew. Routing them all
//! through [`resolve`] makes that disagreement impossible by construction.

use std::path::{Path, PathBuf};

use super::manager::AgentManager;
use crate::{Error, Result};

/// Locate the agent rootfs this host should boot.
///
/// An explicit `override_dir` (a `--rootfs-dir` flag) wins outright. Otherwise
/// the search is the one `machine start` uses: `SMOLVM_AGENT_ROOTFS`, then
/// `SMOLVM_AGENT_ROOTFS_TAR`, then a rootfs directory or bundled tarball next
/// to the executable (extracted once and refreshed when the tarball changes),
/// then the platform data directory. The result is checked to actually hold an
/// agent (`sbin/init` is present) so a caller that copies it, rather than boots
/// it, cannot silently package an empty directory.
pub fn resolve(override_dir: Option<&Path>) -> Result<PathBuf> {
    let dir = match override_dir {
        Some(dir) => dir.to_path_buf(),
        None => AgentManager::default_rootfs_path()?,
    };
    // `symlink_metadata`, not `exists`: `sbin/init` is a symlink to a guest-only
    // target that does not exist on the host, and `exists` would follow it.
    if std::fs::symlink_metadata(dir.join("sbin/init")).is_ok() {
        return Ok(dir);
    }
    Err(Error::agent(
        "find agent rootfs",
        format!(
            "no agent rootfs at {} (no sbin/init); set SMOLVM_AGENT_ROOTFS or pass --rootfs-dir",
            dir.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rootfs_with_init(root: &Path) -> PathBuf {
        let dir = root.join("agent-rootfs");
        std::fs::create_dir_all(dir.join("sbin")).unwrap();
        // A dangling symlink, exactly as a real rootfs carries it on the host.
        #[cfg(unix)]
        std::os::unix::fs::symlink("/usr/local/bin/smolvm-agent", dir.join("sbin/init")).unwrap();
        #[cfg(not(unix))]
        std::fs::write(dir.join("sbin/init"), b"").unwrap();
        dir
    }

    // An explicit directory is taken as given, but still has to be a rootfs:
    // the point of one resolver is that no caller can be handed something that
    // is not bootable.
    #[test]
    fn an_explicit_dir_wins_but_must_hold_an_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let good = rootfs_with_init(tmp.path());
        assert_eq!(resolve(Some(&good)).unwrap(), good);

        let empty = tmp.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let err = resolve(Some(&empty)).unwrap_err().to_string();
        assert!(err.contains("no sbin/init"), "got: {err}");
    }

    // The dangling `sbin/init` symlink must count as present. A resolver that
    // used `exists()` here would reject every genuine rootfs on the host.
    #[cfg(unix)]
    #[test]
    fn a_dangling_init_symlink_counts_as_present() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = rootfs_with_init(tmp.path());
        assert!(!dir.join("sbin/init").exists(), "fixture must dangle");
        assert!(resolve(Some(&dir)).is_ok());
    }
}
