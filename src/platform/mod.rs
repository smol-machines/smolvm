//! Platform abstraction for smolvm.
//!
//! This module provides compile-time and runtime platform detection,
//! along with traits for platform-specific behaviors.
//!
//! # Architecture
//!
//! The platform module centralizes all platform-specific logic that was
//! previously scattered across multiple files. It provides:
//!
//! - **Enums**: `Os`, `Arch`, and `Platform` for type-safe platform identification
//! - **Traits**: `VmExecutor` and `RosettaSupport` for platform-specific behaviors
//! - **Implementations**: macOS and Linux implementations of these traits
//!
//! # Example
//!
//! ```
//! use smolvm::platform::{Os, Arch, Platform, native_platform};
//!
//! // Get current platform info
//! let os = Os::current();
//! let arch = Arch::current();
//! let platform = Platform::current();
//!
//! // Get OCI platform string for container images
//! let oci = native_platform(); // e.g., "linux/arm64"
//! ```
//!
//! # Platform Support
//!
//! | OS | Arch | Supported |
//! |----|------|-----------|
//! | macOS | ARM64 (Apple Silicon) | ✅ |
//! | macOS | x86_64 (Intel) | ✅ |
//! | Linux | ARM64 | ✅ |
//! | Linux | x86_64 | ✅ |

mod traits;

pub mod async_uds;
pub mod uds;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

pub use traits::{RosettaSupport, VmExecutor};

/// Host operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    /// macOS (Darwin)
    MacOs,
    /// Linux
    Linux,
    /// Windows
    Windows,
}

impl Os {
    /// Get the current OS at compile time.
    #[cfg(target_os = "macos")]
    pub const fn current() -> Self {
        Os::MacOs
    }

    /// Get the current OS at compile time.
    #[cfg(target_os = "linux")]
    pub const fn current() -> Self {
        Os::Linux
    }

    /// Get the current OS at compile time.
    #[cfg(target_os = "windows")]
    pub const fn current() -> Self {
        Os::Windows
    }

    /// Returns true if running on macOS.
    pub const fn is_macos(&self) -> bool {
        matches!(self, Os::MacOs)
    }

    /// Returns true if running on Linux.
    pub const fn is_linux(&self) -> bool {
        matches!(self, Os::Linux)
    }

    /// Returns true if running on Windows.
    pub const fn is_windows(&self) -> bool {
        matches!(self, Os::Windows)
    }
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Os::MacOs => write!(f, "macos"),
            Os::Linux => write!(f, "linux"),
            Os::Windows => write!(f, "windows"),
        }
    }
}

/// Host CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    /// ARM 64-bit (aarch64)
    Arm64,
    /// x86 64-bit (amd64)
    X86_64,
}

impl Arch {
    /// Get the current architecture at compile time.
    #[cfg(target_arch = "aarch64")]
    pub const fn current() -> Self {
        Arch::Arm64
    }

    /// Get the current architecture at compile time.
    #[cfg(target_arch = "x86_64")]
    pub const fn current() -> Self {
        Arch::X86_64
    }

    /// Convert to OCI platform architecture string.
    ///
    /// Returns "arm64" or "amd64" as used in OCI image manifests.
    pub const fn oci_arch(&self) -> &'static str {
        match self {
            Arch::Arm64 => "arm64",
            Arch::X86_64 => "amd64",
        }
    }

    /// Returns true if running on ARM64.
    pub const fn is_arm64(&self) -> bool {
        matches!(self, Arch::Arm64)
    }

    /// Returns true if running on x86_64.
    pub const fn is_x86_64(&self) -> bool {
        matches!(self, Arch::X86_64)
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::Arm64 => write!(f, "arm64"),
            Arch::X86_64 => write!(f, "x86_64"),
        }
    }
}

/// Combined platform identifier (OS + architecture).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Platform {
    /// Operating system
    pub os: Os,
    /// CPU architecture
    pub arch: Arch,
}

impl Platform {
    /// Get the current platform at compile time.
    pub const fn current() -> Self {
        Self {
            os: Os::current(),
            arch: Arch::current(),
        }
    }

    /// Convert to OCI platform string (e.g., "linux/arm64").
    ///
    /// Note: The OS is always "linux" for container images,
    /// regardless of the host OS, since VMs run Linux guests.
    pub const fn oci_platform(&self) -> &'static str {
        match self.arch {
            Arch::Arm64 => "linux/arm64",
            Arch::X86_64 => "linux/amd64",
        }
    }

    /// OCI platform string for the **host** (e.g., "darwin/arm64").
    ///
    /// Used for registry Image Index resolution — tells the registry which
    /// host OS+arch this `.smolmachine` runs on. Distinct from `oci_platform()`
    /// which always returns `linux/*` (the guest).
    pub const fn host_oci_platform(&self) -> &'static str {
        match (self.os, self.arch) {
            (Os::MacOs, Arch::Arm64) => "darwin/arm64",
            (Os::MacOs, Arch::X86_64) => "darwin/amd64",
            (Os::Linux, Arch::Arm64) => "linux/arm64",
            (Os::Linux, Arch::X86_64) => "linux/amd64",
            (Os::Windows, Arch::Arm64) => "windows/arm64",
            (Os::Windows, Arch::X86_64) => "windows/amd64",
        }
    }

    /// Check if this platform supports Rosetta 2.
    ///
    /// Rosetta 2 is only available on Apple Silicon Macs.
    pub const fn supports_rosetta(&self) -> bool {
        matches!((self.os, self.arch), (Os::MacOs, Arch::Arm64))
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)
    }
}

/// Current platform constant (zero-cost at runtime).
pub const CURRENT_PLATFORM: Platform = Platform::current();

/// Get native platform string for OCI images.
///
/// Returns "linux/arm64" or "linux/amd64" based on host architecture.
/// This is the platform string to use when pulling container images.
pub fn native_platform() -> &'static str {
    CURRENT_PLATFORM.oci_platform()
}

/// Reject a packed artifact whose guest CPU architecture differs from this host's.
///
/// A `.smolmachine` carries architecture-specific native binaries — a VM-mode pack
/// holds a compiled guest rootfs, an image-mode pack holds per-arch OCI layers — so
/// an `arm64` artifact cannot run under an `amd64` guest kernel, or vice versa. Used
/// by `machine create --from` and the serve create handler before they extract or
/// boot, so the failure is an immediate, actionable message rather than a cryptic
/// exec-format crash mid-boot.
///
/// Unlike the single-file `pack run` path — which additionally requires a matching
/// host OS because it dlopens the libs bundled *into* the executable — a sidecar
/// rehydrated via `create --from` boots through the HOST's own libkrun, so only the
/// guest ARCHITECTURE must match; the host OS (macOS vs Linux) is irrelevant. That
/// is what lets a VM packed on a Mac rehydrate on a same-arch Linux node.
///
/// `artifact_platform` is the manifest's guest platform (e.g. `"linux/arm64"`). A
/// blank or unrecognized arch is allowed through rather than risk falsely rejecting
/// an otherwise-valid artifact.
pub fn ensure_artifact_arch_matches_host(artifact_platform: &str) -> crate::Result<()> {
    let host_arch = Arch::current().oci_arch();
    let artifact_arch = artifact_platform.rsplit('/').next().unwrap_or("").trim();
    if matches!(artifact_arch, "amd64" | "arm64") && artifact_arch != host_arch {
        return Err(crate::Error::agent(
            "platform mismatch",
            format!(
                "this artifact is built for architecture '{artifact_arch}' (platform \
                 '{artifact_platform}'), but this host is '{host_arch}'. A packed VM or image \
                 carries native binaries and cannot run on a different CPU architecture — re-pack \
                 on an '{artifact_arch}' host, or use an '{host_arch}' artifact."
            ),
        ));
    }
    Ok(())
}

/// Get the platform-specific VM executor.
///
/// Returns an executor that handles platform differences in VM execution,
/// particularly around virtiofs mount handling.
#[cfg(target_os = "macos")]
pub fn vm_executor() -> macos::MacOsExecutor {
    macos::MacOsExecutor
}

/// Get the platform-specific VM executor.
#[cfg(target_os = "linux")]
pub fn vm_executor() -> linux::LinuxExecutor {
    linux::LinuxExecutor
}

/// Get the platform-specific Rosetta support handler.
#[cfg(target_os = "macos")]
pub fn rosetta() -> macos::MacOsRosetta {
    macos::rosetta_support()
}

/// Get the platform-specific Rosetta support handler.
#[cfg(target_os = "linux")]
pub fn rosetta() -> linux::LinuxRosetta {
    linux::rosetta_support()
}

/// Get the platform-specific VM executor.
#[cfg(target_os = "windows")]
pub fn vm_executor() -> windows::WindowsExecutor {
    windows::WindowsExecutor
}

/// Get the platform-specific Rosetta support handler.
#[cfg(target_os = "windows")]
pub fn rosetta() -> windows::WindowsRosetta {
    windows::rosetta_support()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_arch_guard() {
        let host = Arch::current().oci_arch();
        let other = if host == "amd64" { "arm64" } else { "amd64" };

        // Matching arch (with the linux/ prefix) is accepted.
        assert!(ensure_artifact_arch_matches_host(&format!("linux/{host}")).is_ok());
        // Bare arch string also accepted when it matches.
        assert!(ensure_artifact_arch_matches_host(host).is_ok());
        // The opposite arch is rejected.
        assert!(ensure_artifact_arch_matches_host(&format!("linux/{other}")).is_err());
        // Host OS is irrelevant — only the arch matters (Mac-built pack on Linux).
        assert!(ensure_artifact_arch_matches_host(&format!("darwin/{host}")).is_ok());
        // Blank / unrecognized arch is allowed through rather than false-rejected.
        assert!(ensure_artifact_arch_matches_host("").is_ok());
        assert!(ensure_artifact_arch_matches_host("linux/riscv64").is_ok());
    }

    #[test]
    fn test_current_platform_is_valid() {
        let platform = Platform::current();
        // Should not panic and should have valid values
        let _ = platform.oci_platform();
        let _ = platform.os.to_string();
        let _ = platform.arch.to_string();
    }

    #[test]
    fn test_oci_platform_format() {
        let platform_str = native_platform();
        assert!(platform_str.starts_with("linux/"));
        assert!(
            platform_str == "linux/arm64" || platform_str == "linux/amd64",
            "unexpected platform: {}",
            platform_str
        );
    }

    #[test]
    fn test_arch_oci_strings() {
        assert_eq!(Arch::Arm64.oci_arch(), "arm64");
        assert_eq!(Arch::X86_64.oci_arch(), "amd64");
    }

    #[test]
    fn test_platform_supports_rosetta() {
        let macos_arm = Platform {
            os: Os::MacOs,
            arch: Arch::Arm64,
        };
        let macos_intel = Platform {
            os: Os::MacOs,
            arch: Arch::X86_64,
        };
        let linux_arm = Platform {
            os: Os::Linux,
            arch: Arch::Arm64,
        };
        let linux_x86 = Platform {
            os: Os::Linux,
            arch: Arch::X86_64,
        };

        assert!(macos_arm.supports_rosetta());
        assert!(!macos_intel.supports_rosetta());
        assert!(!linux_arm.supports_rosetta());
        assert!(!linux_x86.supports_rosetta());
    }

    #[test]
    fn test_os_helpers() {
        assert!(Os::MacOs.is_macos());
        assert!(!Os::MacOs.is_linux());
        assert!(Os::Linux.is_linux());
        assert!(!Os::Linux.is_macos());
    }

    #[test]
    fn test_arch_helpers() {
        assert!(Arch::Arm64.is_arm64());
        assert!(!Arch::Arm64.is_x86_64());
        assert!(Arch::X86_64.is_x86_64());
        assert!(!Arch::X86_64.is_arm64());
    }

    #[test]
    fn test_platform_display() {
        let platform = Platform {
            os: Os::MacOs,
            arch: Arch::Arm64,
        };
        assert_eq!(platform.to_string(), "macos/arm64");
    }

    #[test]
    fn test_host_oci_platform_all_combos() {
        let cases = [
            (Os::MacOs, Arch::Arm64, "darwin/arm64"),
            (Os::MacOs, Arch::X86_64, "darwin/amd64"),
            (Os::Linux, Arch::Arm64, "linux/arm64"),
            (Os::Linux, Arch::X86_64, "linux/amd64"),
        ];
        for (os, arch, expected) in cases {
            let p = Platform { os, arch };
            assert_eq!(
                p.host_oci_platform(),
                expected,
                "failed for {:?}/{:?}",
                os,
                arch
            );
        }
    }
}
