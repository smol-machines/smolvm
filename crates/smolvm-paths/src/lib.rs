//! State directories shared by the engine, registry and pack libraries.
//!
//! Unix startup already relocates the process home for an explicit state root.
//! Windows known-folder APIs ignore that environment change, so resolve the
//! same state-root setting here without changing the user's Windows profile.

use std::path::PathBuf;

fn directory(_suffix: &str, default: fn() -> Option<PathBuf>) -> Option<PathBuf> {
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SMOLVM_DATA_DIR") {
        // An invalid explicit root must not fall back to the user's live state.
        let root = std::path::absolute(root).ok()?;
        return Some(root.join(_suffix));
    }
    default()
}

/// Home for engine configuration, honoring an explicit Windows state root.
pub fn home_dir() -> Option<PathBuf> {
    directory("", dirs::home_dir)
}

/// Per-user cache directory, or the cache inside the explicit state root.
pub fn cache_dir() -> Option<PathBuf> {
    directory("AppData/Local", dirs::cache_dir)
}

/// Local application data, including the machine database.
pub fn data_local_dir() -> Option<PathBuf> {
    directory("AppData/Local", dirs::data_local_dir)
}

/// Roaming application data, or its counterpart in the explicit state root.
pub fn data_dir() -> Option<PathBuf> {
    directory("AppData/Roaming", dirs::data_dir)
}

/// Application configuration directory.
pub fn config_dir() -> Option<PathBuf> {
    directory("AppData/Roaming", dirs::config_dir)
}

/// Runtime directory for transient engine files.
pub fn runtime_dir() -> Option<PathBuf> {
    directory("run", dirs::runtime_dir)
}

/// The actual user's home, for carrying existing registry authentication into
/// an isolated state root without copying or relocating those credentials.
pub fn user_home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults_match_platform() {
        assert_eq!(home_dir(), dirs::home_dir());
        assert_eq!(cache_dir(), dirs::cache_dir());
        assert_eq!(data_local_dir(), dirs::data_local_dir());
        assert_eq!(data_dir(), dirs::data_dir());
        assert_eq!(config_dir(), dirs::config_dir());
        assert_eq!(runtime_dir(), dirs::runtime_dir());
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_keeps_platform_directory_resolution() {
        defaults_match_platform();
    }

    #[cfg(windows)]
    #[test]
    fn windows_directories_are_isolated_without_changing_known_folders() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state with spaces-é");
        for override_root in [None, Some(root.clone()), Some("relative state".into())] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "tests::windows_child", "--nocapture"])
                .current_dir(temp.path())
                .env("SMOLVM_PATHS_CHILD", "1")
                .env_remove("SMOLVM_DATA_DIR");
            if let Some(root) = override_root {
                command.env("SMOLVM_DATA_DIR", root);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_child() {
        if std::env::var_os("SMOLVM_PATHS_CHILD").is_none() {
            return;
        }
        let Some(root) = std::env::var_os("SMOLVM_DATA_DIR") else {
            defaults_match_platform();
            return;
        };
        let root = std::path::absolute(root).unwrap();
        assert_eq!(home_dir(), Some(root.clone()));
        assert_eq!(cache_dir(), Some(root.join("AppData/Local")));
        assert_eq!(data_local_dir(), Some(root.join("AppData/Local")));
        assert_eq!(data_dir(), Some(root.join("AppData/Roaming")));
        assert_eq!(config_dir(), Some(root.join("AppData/Roaming")));
        assert_eq!(runtime_dir(), Some(root.join("run")));
        assert_eq!(user_home_dir(), dirs::home_dir());
        assert_ne!(dirs::home_dir(), home_dir());
    }
}
