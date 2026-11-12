//! Rosetta 2 support for running x86_64 binaries on Apple Silicon.
//!
//! This module provides detection and configuration for Apple's Rosetta 2
//! translation layer, allowing x86_64 container images to run on ARM Macs.
//!
//! # How it works
//!
//! When Rosetta is available and enabled, smolvm mounts the Rosetta runtime
//! directory into the guest VM via virtiofs and the guest agent registers an
//! interpreter for x86_64 ELF binaries with binfmt_misc (see the agent's
//! `rosetta` module). Rosetta asks the share it was started from a start-up
//! question that Virtualization.framework answers; smolvm runs on
//! Hypervisor.framework, so either libkrun's virtiofs server answers it, and
//! the translator itself is the interpreter, or a ptrace wrapper
//! (`/usr/bin/rosetta-wrapper`) answers it in the guest.
//!
//! A Rosetta machine pulls its image for `linux/amd64` unless another platform
//! is asked for; see [`image_platform`].
//!
//! # Requirements
//!
//! - Apple Silicon Mac (M1/M2/M3/M4)
//! - Rosetta 2 installed (`softwareupdate --install-rosetta`)
//! - macOS 11.0 or later

use crate::platform::{self, RosettaSupport};

/// Virtiofs tag for the Rosetta mount. Re-exported from the wire protocol so the
/// host launcher and guest agent share one definition.
pub use smolvm_protocol::ROSETTA_TAG;

/// Guest mount path for the Rosetta runtime. Re-exported from the wire protocol.
pub use smolvm_protocol::ROSETTA_GUEST_PATH;

/// binfmt_misc registration command for the guest.
///
/// Registers the ptrace wrapper as the interpreter for x86_64 ELF binaries.
/// The wrapper intercepts Rosetta's validation ioctl, then detaches for
/// full-speed execution. The `F` flag keeps the interpreter fd open at
/// registration time (required since the wrapper lives on the rootfs, not
/// the virtiofs mount).
pub const BINFMT_REGISTER_CMD: &str = r#"
if [ -d /mnt/rosetta ] && [ -f /mnt/rosetta/rosetta ] && [ -x /usr/bin/rosetta-wrapper ]; then
    if [ -d /proc/sys/fs/binfmt_misc ]; then
        mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null || true
        echo ':rosetta:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/rosetta-wrapper:F' > /proc/sys/fs/binfmt_misc/register 2>/dev/null || true
    fi
fi
"#;

/// The image platform Rosetta translates.
pub const TRANSLATED_PLATFORM: &str = "linux/amd64";

/// The platform to pull a machine's image for, or `None` for the guest's own
/// architecture. The platform asked for wins. Otherwise a machine with Rosetta
/// pulls [`TRANSLATED_PLATFORM`]: a multi-arch reference would resolve to the
/// arm64 variant and leave Rosetta nothing to translate, and an amd64-only one
/// would not resolve at all.
pub fn image_platform(asked: Option<&str>, rosetta: bool) -> Option<&str> {
    asked.or_else(|| rosetta.then_some(TRANSLATED_PLATFORM))
}

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
    fn a_rosetta_machine_pulls_amd64_unless_a_platform_is_asked_for() {
        assert_eq!(image_platform(None, false), None);
        assert_eq!(image_platform(None, true), Some("linux/amd64"));
        assert_eq!(
            image_platform(Some("linux/arm64"), true),
            Some("linux/arm64")
        );
        assert_eq!(
            image_platform(Some("linux/amd64"), false),
            Some("linux/amd64")
        );
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
}
