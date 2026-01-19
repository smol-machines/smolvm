//! Rosetta 2 support for running x86_64 binaries on Apple Silicon.
//!
//! This module provides detection and configuration for Apple's Rosetta 2
//! translation layer, allowing x86_64 container images to run on ARM Macs.
//!
//! # How it works
//!
//! When Rosetta is available and enabled, smolvm mounts the Rosetta runtime
//! directory into the guest VM via virtiofs. The guest can then execute
//! x86_64 binaries by registering Rosetta with binfmt_misc.
//!
//! # Requirements
//!
//! - Apple Silicon Mac (M1/M2/M3)
//! - Rosetta 2 installed (`softwareupdate --install-rosetta`)
//! - macOS 11.0 or later

use crate::platform::{self, RosettaSupport};

/// Virtiofs tag for the Rosetta mount.
pub const ROSETTA_TAG: &str = "rosetta";

/// Guest mount path for Rosetta runtime.
pub const ROSETTA_GUEST_PATH: &str = "/mnt/rosetta";

/// binfmt_misc registration command for the guest.
///
/// This command should be run inside the guest VM to register Rosetta
/// as the interpreter for x86_64 ELF binaries.
pub const BINFMT_REGISTER_CMD: &str = r#"
if [ -d /mnt/rosetta ] && [ -f /mnt/rosetta/rosetta ]; then
    if [ -d /proc/sys/fs/binfmt_misc ]; then
        mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null || true
        echo ':rosetta:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/mnt/rosetta/rosetta:OCF' > /proc/sys/fs/binfmt_misc/register 2>/dev/null || true
    fi
fi
"#;

/// Check if Rosetta 2 is available on this system.
///
/// Returns `true` only on Apple Silicon Macs with Rosetta installed.
pub fn is_available() -> bool {
    platform::rosetta().is_available()
}

/// Get the path to the Rosetta runtime directory.
///
/// Returns `None` if Rosetta is not available.
pub fn runtime_path() -> Option<&'static str> {
    platform::rosetta().runtime_path()
}

/// Guest init script snippet for enabling Rosetta.
///
/// This should be included in the guest's init process when Rosetta is enabled.
pub fn init_script() -> &'static str {
    BINFMT_REGISTER_CMD
}

/// Platform strings that require Rosetta on ARM Macs.
pub fn needs_rosetta(platform_str: &str) -> bool {
    platform::rosetta().needs_rosetta(platform_str)
}

/// Get the native platform string for this system.
///
/// Returns "linux/arm64" or "linux/amd64" based on host architecture.
/// Note: Always returns a Linux platform since VMs run Linux guests.
pub fn native_platform() -> &'static str {
    platform::native_platform()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_rosetta() {
        // Platform detection logic for cross-architecture support
        assert!(needs_rosetta("linux/amd64"));
        assert!(needs_rosetta("linux/x86_64"));
        assert!(needs_rosetta("LINUX/AMD64"));
        assert!(!needs_rosetta("linux/arm64"));
        assert!(!needs_rosetta("linux/aarch64"));
    }

    #[test]
    fn test_native_platform_format() {
        let platform = native_platform();
        assert!(platform.starts_with("linux/"));
        assert!(
            platform == "linux/arm64" || platform == "linux/amd64",
            "unexpected platform: {}",
            platform
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(ROSETTA_TAG, "rosetta");
        assert_eq!(ROSETTA_GUEST_PATH, "/mnt/rosetta");
        assert!(!BINFMT_REGISTER_CMD.is_empty());
    }
}
