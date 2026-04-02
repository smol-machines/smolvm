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

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

pub use traits::{RosettaSupport, VmExecutor};

/// Host operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    /// macOS (Darwin)
    MacOs,
    /// Linux
    Linux,
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

    /// Returns true if running on macOS.
    pub const fn is_macos(&self) -> bool {
        matches!(self, Os::MacOs)
    }

    /// Returns true if running on Linux.
    pub const fn is_linux(&self) -> bool {
        matches!(self, Os::Linux)
    }
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Os::MacOs => write!(f, "macos"),
            Os::Linux => write!(f, "linux"),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
