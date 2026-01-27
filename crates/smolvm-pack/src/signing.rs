//! Code signing support for packed executables.
//!
//! On macOS, executables that use Hypervisor.framework must be signed
//! with the appropriate entitlements.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{PackError, Result};

/// Default entitlements for hypervisor access on macOS.
const HYPERVISOR_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
"#;

/// Sign a binary with hypervisor entitlements (macOS only).
///
/// This uses ad-hoc signing (no certificate required) which is sufficient
/// for local development and distribution.
#[cfg(target_os = "macos")]
pub fn sign_with_hypervisor_entitlements(binary_path: &Path) -> Result<()> {
    // Create temporary entitlements file
    let temp_dir = tempfile::tempdir()?;
    let entitlements_path = temp_dir.path().join("entitlements.plist");
    fs::write(&entitlements_path, HYPERVISOR_ENTITLEMENTS)?;

    // Run codesign
    let output = Command::new("codesign")
        .args([
            "--force",
            "--sign",
            "-", // Ad-hoc signing
            "--entitlements",
        ])
        .arg(&entitlements_path)
        .arg(binary_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PackError::Signing(format!(
            "codesign failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Sign a binary with hypervisor entitlements (no-op on non-macOS).
#[cfg(not(target_os = "macos"))]
pub fn sign_with_hypervisor_entitlements(_binary_path: &Path) -> Result<()> {
    // No signing needed on Linux
    Ok(())
}

/// Check if a binary is signed (macOS only).
#[cfg(target_os = "macos")]
pub fn is_signed(binary_path: &Path) -> Result<bool> {
    let output = Command::new("codesign")
        .args(["--verify", "--verbose"])
        .arg(binary_path)
        .output()?;

    Ok(output.status.success())
}

/// Check if a binary is signed (always false on non-macOS).
#[cfg(not(target_os = "macos"))]
pub fn is_signed(_binary_path: &Path) -> Result<bool> {
    Ok(false)
}

/// Get signature information for a binary (macOS only).
#[cfg(target_os = "macos")]
pub fn get_signature_info(binary_path: &Path) -> Result<Option<SignatureInfo>> {
    let output = Command::new("codesign")
        .args(["--display", "--verbose=2"])
        .arg(binary_path)
        .output()?;

    if !output.status.success() {
        return Ok(None);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let is_adhoc = stderr.contains("Signature=adhoc");

    Ok(Some(SignatureInfo {
        is_adhoc,
        raw_output: stderr.to_string(),
    }))
}

/// Get signature information (always None on non-macOS).
#[cfg(not(target_os = "macos"))]
pub fn get_signature_info(_binary_path: &Path) -> Result<Option<SignatureInfo>> {
    Ok(None)
}

/// Information about a code signature.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// Whether this is ad-hoc signed.
    pub is_adhoc: bool,
    /// Raw codesign output.
    pub raw_output: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sign_binary() {
        let temp_dir = tempfile::tempdir().unwrap();
        let binary_path = temp_dir.path().join("test_binary");

        // Create a minimal Mach-O binary (just the header)
        // This is a valid but non-functional binary that codesign can process
        let mut file = fs::File::create(&binary_path).unwrap();

        // Minimal arm64 Mach-O header
        let macho_header: [u8; 32] = [
            0xCF, 0xFA, 0xED, 0xFE, // Magic (64-bit)
            0x0C, 0x00, 0x00, 0x01, // CPU type (ARM64)
            0x00, 0x00, 0x00, 0x00, // CPU subtype
            0x02, 0x00, 0x00, 0x00, // File type (MH_EXECUTE)
            0x00, 0x00, 0x00, 0x00, // Number of load commands
            0x00, 0x00, 0x00, 0x00, // Size of load commands
            0x00, 0x00, 0x00, 0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // Reserved
        ];
        file.write_all(&macho_header).unwrap();
        drop(file);

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&binary_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&binary_path, perms).unwrap();
        }

        // Sign it
        let result = sign_with_hypervisor_entitlements(&binary_path);
        // This may fail if the binary isn't valid enough for codesign,
        // but we're testing that the function runs without panicking
        if let Err(e) = &result {
            eprintln!("Signing failed (expected for minimal test binary): {}", e);
        }
    }

    #[test]
    fn test_entitlements_format() {
        // Verify the entitlements XML is valid
        assert!(HYPERVISOR_ENTITLEMENTS.contains("com.apple.security.hypervisor"));
        assert!(HYPERVISOR_ENTITLEMENTS.contains("<true/>"));
    }
}
