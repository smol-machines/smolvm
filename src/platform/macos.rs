//! macOS-specific platform implementations.
//!
//! This module provides macOS implementations for VM execution and Rosetta support.
//! The key difference from Linux is that macOS requires explicit virtiofs mounting
//! via a wrapper script, as the kernel doesn't auto-mount virtiofs devices.

use crate::error::{Error, Result};
use crate::platform::traits::{RosettaSupport, VmExecutor};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// macOS VM executor implementation.
///
/// On macOS, virtiofs devices need to be explicitly mounted by the guest.
/// This executor wraps user commands with a mount script when virtiofs
/// mounts are present.
pub struct MacOsExecutor;

impl VmExecutor for MacOsExecutor {
    fn requires_mount_wrapper(&self) -> bool {
        true
    }

    fn build_exec_command(
        &self,
        command: &Option<Vec<String>>,
        mounts: &[(String, String)],
        rootfs: &Path,
        rosetta: bool,
    ) -> Result<(CString, Vec<*const libc::c_char>, Vec<CString>)> {
        // Need mount wrapper if we have mounts OR if rosetta is enabled
        if mounts.is_empty() && !rosetta {
            return build_exec_args_direct(command);
        }

        // Write mount script and use it as the command
        let script_path = write_mount_script(rootfs, mounts, rosetta)?;

        let default_cmd = vec!["/bin/sh".to_string()];
        let user_cmd = command.as_ref().unwrap_or(&default_cmd);

        // exec_path is the mount script
        let exec_path = CString::new(script_path.as_str())
            .map_err(|_| Error::vm_creation("invalid script path"))?;

        // argv is the user's command and arguments (passed to the script via $@)
        // Note: For the mount wrapper, we pass ALL args including argv[0]
        // because the script uses exec "$@" which expects the full command
        let cstrings: Vec<CString> = user_cmd
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::vm_creation("invalid command argument"))?;

        let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        tracing::debug!("using mount wrapper with {} virtiofs mounts", mounts.len());
        Ok((exec_path, argv, cstrings))
    }

    fn tool_search_paths(&self) -> &'static [&'static str] {
        &[
            "/opt/homebrew/opt/e2fsprogs/sbin",
            "/usr/local/opt/e2fsprogs/sbin",
            "/opt/homebrew/sbin",
            "/usr/local/sbin",
            "/sbin",
            "/usr/sbin",
        ]
    }

    fn dylib_extension(&self) -> &'static str {
        "dylib"
    }

    fn library_search_paths(&self) -> &'static [&'static str] {
        &[
            "/opt/homebrew/lib",
            "/usr/local/lib",
            "/opt/homebrew/opt/libkrun/lib",
            "/usr/local/opt/libkrun/lib",
        ]
    }
}

/// macOS Rosetta 2 support implementation.
///
/// Rosetta 2 allows running x86_64 binaries on Apple Silicon Macs.
/// This is only available on ARM64 macOS systems with Rosetta installed.
pub struct MacOsRosetta;

/// Path to the Rosetta runtime on macOS.
const ROSETTA_RUNTIME_PATH: &str = "/Library/Apple/usr/libexec/oah";

impl RosettaSupport for MacOsRosetta {
    #[cfg(target_arch = "aarch64")]
    fn is_available(&self) -> bool {
        Path::new(ROSETTA_RUNTIME_PATH).exists()
            && Path::new("/Library/Apple/usr/libexec/oah/libRosettaRuntime").exists()
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn is_available(&self) -> bool {
        false // Rosetta only available on ARM64
    }

    #[cfg(target_arch = "aarch64")]
    fn runtime_path(&self) -> Option<&'static str> {
        if self.is_available() {
            Some(ROSETTA_RUNTIME_PATH)
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn runtime_path(&self) -> Option<&'static str> {
        None
    }
}

/// Get the Rosetta support instance for macOS.
pub fn rosetta_support() -> MacOsRosetta {
    MacOsRosetta
}

/// Write a mount helper script to the rootfs.
///
/// This script mounts all virtiofs volumes before executing the user's command.
/// It's written to /tmp inside the rootfs to avoid mutating the container image.
/// If rosetta is enabled, it also mounts the Rosetta runtime and registers binfmt_misc.
fn write_mount_script(rootfs: &Path, mounts: &[(String, String)], rosetta: bool) -> Result<String> {
    let tmp_dir = rootfs.join("tmp");
    if !tmp_dir.exists() {
        fs::create_dir_all(&tmp_dir)
            .map_err(|e| Error::vm_creation(format!("failed to create /tmp in rootfs: {}", e)))?;
    }

    let host_path = tmp_dir.join("smolvm-mount.sh");
    let guest_path = "/tmp/smolvm-mount.sh";

    let mut file = File::create(&host_path)
        .map_err(|e| Error::vm_creation(format!("failed to create mount script: {}", e)))?;

    // Helper to write lines with proper error handling
    let write_line = |file: &mut File, line: &str| -> Result<()> {
        writeln!(file, "{}", line)
            .map_err(|e| Error::vm_creation(format!("failed to write mount script: {}", e)))
    };

    write_line(&mut file, "#!/bin/sh")?;
    write_line(&mut file, "set -e")?;

    // Mount each virtiofs volume.
    // Both tag and guest_mount are single-quoted to prevent shell injection.
    // Any embedded single quotes are escaped as `'\''` (end quote, literal
    // quote via backslash, restart quote).
    for (tag, guest_mount) in mounts {
        write_line(
            &mut file,
            &format!("mkdir -p '{}'", shell_escape(guest_mount)),
        )?;
        write_line(
            &mut file,
            &format!(
                "mount -t virtiofs '{}' '{}'",
                shell_escape(tag),
                shell_escape(guest_mount)
            ),
        )?;
    }

    // If Rosetta is enabled, mount the runtime and register binfmt_misc
    if rosetta {
        write_line(&mut file, "# Mount Rosetta runtime")?;
        write_line(
            &mut file,
            &format!(
                "mkdir -p '{}'",
                shell_escape(crate::vm::rosetta::ROSETTA_GUEST_PATH)
            ),
        )?;
        write_line(
            &mut file,
            &format!(
                "mount -t virtiofs '{}' '{}'",
                shell_escape(crate::vm::rosetta::ROSETTA_TAG),
                shell_escape(crate::vm::rosetta::ROSETTA_GUEST_PATH)
            ),
        )?;

        // Register Rosetta with binfmt_misc for x86_64 ELF binaries
        write_line(&mut file, "# Register Rosetta with binfmt_misc")?;
        write_line(&mut file, crate::vm::rosetta::BINFMT_REGISTER_CMD)?;
    }

    // Clean up the mount script after execution
    write_line(&mut file, "rm -f \"$0\"")?;

    // Execute the user's command
    write_line(&mut file, "exec \"$@\"")?;

    // Make executable
    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&host_path, perms).map_err(|e| {
        Error::vm_creation(format!("failed to set mount script permissions: {}", e))
    })?;

    tracing::debug!(
        "wrote mount script to {:?} (rosetta={})",
        host_path,
        rosetta
    );
    Ok(guest_path.to_string())
}

/// Escape a string for safe inclusion inside single quotes in a shell script.
///
/// Single-quoting in POSIX shell prevents all interpretation except for the
/// single-quote character itself. To include a literal `'`, we end the
/// current quoted segment, insert an escaped quote (`\'`), and restart
/// quoting: `'foo'\''bar'` produces the literal string `foo'bar`.
fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Build exec arguments without mount wrapper (for no-mounts case).
///
/// Note: libkrun expects argv to NOT include argv[0] - only arguments.
/// The command path is passed separately via exec_path/KRUN_INIT.
fn build_exec_args_direct(
    command: &Option<Vec<String>>,
) -> Result<(CString, Vec<*const libc::c_char>, Vec<CString>)> {
    let default_cmd = vec!["/bin/sh".to_string()];
    let cmd = command.as_ref().unwrap_or(&default_cmd);

    if cmd.is_empty() {
        return Err(Error::vm_creation("command cannot be empty"));
    }

    let exec_path =
        CString::new(cmd[0].as_str()).map_err(|_| Error::vm_creation("invalid command path"))?;

    // Skip argv[0] - libkrun/init.krun handles it via KRUN_INIT
    let cstrings: Vec<CString> = cmd
        .iter()
        .skip(1)
        .map(|s| CString::new(s.as_str()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::vm_creation("invalid command argument"))?;

    let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    Ok((exec_path, argv, cstrings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_macos_executor_requires_mount_wrapper() {
        let executor = MacOsExecutor;
        assert!(executor.requires_mount_wrapper());
    }

    #[test]
    fn test_macos_dylib_extension() {
        let executor = MacOsExecutor;
        assert_eq!(executor.dylib_extension(), "dylib");
    }

    #[test]
    fn test_rosetta_needs_rosetta() {
        let rosetta = MacOsRosetta;
        assert!(rosetta.needs_rosetta("linux/amd64"));
        assert!(rosetta.needs_rosetta("linux/x86_64"));
        assert!(!rosetta.needs_rosetta("linux/arm64"));
    }

    #[test]
    fn test_build_exec_no_mounts_returns_direct_command() {
        let executor = MacOsExecutor;
        let tmp = TempDir::new().unwrap();
        let cmd = Some(vec!["/bin/echo".to_string(), "hello".to_string()]);

        let (exec_path, argv, cstrings) = executor
            .build_exec_command(&cmd, &[], tmp.path(), false)
            .unwrap();

        // With no mounts, should return direct command
        assert_eq!(exec_path.to_str().unwrap(), "/bin/echo");
        // argv should have 1 arg + null terminator (argv[0] skipped per libkrun convention)
        assert_eq!(cstrings.len(), 1);
        assert_eq!(cstrings[0].to_str().unwrap(), "hello");
        assert_eq!(argv.len(), 2); // ["hello", null]
    }

    #[test]
    fn test_build_exec_with_mounts_creates_script() {
        let executor = MacOsExecutor;
        let tmp = TempDir::new().unwrap();
        let cmd = Some(vec!["/bin/cat".to_string(), "/data/file.txt".to_string()]);
        let mounts = vec![("smolvm0".to_string(), "/data".to_string())];

        let (exec_path, _argv, _cstrings) = executor
            .build_exec_command(&cmd, &mounts, tmp.path(), false)
            .unwrap();

        // With mounts, should return mount script path
        assert_eq!(exec_path.to_str().unwrap(), "/tmp/smolvm-mount.sh");

        // Verify script was created with correct content
        let script_path = tmp.path().join("tmp/smolvm-mount.sh");
        assert!(script_path.exists(), "mount script should be created");

        let content = std::fs::read_to_string(&script_path).unwrap();
        assert!(content.contains("#!/bin/sh"), "script should have shebang");
        assert!(
            content.contains("mkdir -p '/data'"),
            "script should create mount point"
        );
        assert!(
            content.contains("mount -t virtiofs 'smolvm0' '/data'"),
            "script should mount virtiofs"
        );
        assert!(
            content.contains("exec \"$@\""),
            "script should exec user command"
        );
    }

    #[test]
    fn test_build_exec_default_command() {
        let executor = MacOsExecutor;
        let tmp = TempDir::new().unwrap();

        let (exec_path, _argv, _cstrings) = executor
            .build_exec_command(&None, &[], tmp.path(), false)
            .unwrap();

        // Default command should be /bin/sh
        assert_eq!(exec_path.to_str().unwrap(), "/bin/sh");
    }

    #[test]
    fn test_build_exec_with_rosetta_creates_script() {
        let executor = MacOsExecutor;
        let tmp = TempDir::new().unwrap();
        let cmd = Some(vec!["/bin/sh".to_string()]);

        // With rosetta=true but no mounts, should still create wrapper script
        let (exec_path, _argv, _cstrings) = executor
            .build_exec_command(&cmd, &[], tmp.path(), true)
            .unwrap();

        assert_eq!(exec_path.to_str().unwrap(), "/tmp/smolvm-mount.sh");

        // Verify script was created with Rosetta setup
        let script_path = tmp.path().join("tmp/smolvm-mount.sh");
        assert!(script_path.exists(), "mount script should be created");

        let content = std::fs::read_to_string(&script_path).unwrap();
        assert!(
            content.contains("/mnt/rosetta"),
            "script should mount Rosetta"
        );
        assert!(
            content.contains("binfmt_misc"),
            "script should register binfmt_misc"
        );
    }

    #[test]
    fn test_shell_escape_no_special_chars() {
        assert_eq!(shell_escape("smolvm0"), "smolvm0");
        assert_eq!(shell_escape("/data/dir"), "/data/dir");
    }

    #[test]
    fn test_shell_escape_single_quotes() {
        assert_eq!(shell_escape("it's"), "it'\\''s");
    }

    #[test]
    fn test_mount_script_escapes_malicious_input() {
        let tmp = TempDir::new().unwrap();
        let mounts = vec![(
            "smolvm0".to_string(),
            "/data'; rm -rf /; echo '".to_string(),
        )];
        let cmd = Some(vec!["/bin/sh".to_string()]);

        let executor = MacOsExecutor;
        let _ = executor
            .build_exec_command(&cmd, &mounts, tmp.path(), false)
            .unwrap();

        let content = std::fs::read_to_string(tmp.path().join("tmp/smolvm-mount.sh")).unwrap();

        // The single quotes in the malicious input must be escaped as '\''
        // so the shell never sees an unquoted semicolon.
        assert!(content.contains("'\\''"), "single quotes should be escaped");
        // The mount command must NOT contain unescaped single-quote boundaries
        // that would let the injected semicolon run as a separate command.
        // In the escaped form, the sequence is: '/data'\''...' which is safe.
        // Verify the mkdir and mount both use the escaped path:
        assert!(
            content.contains("mkdir -p '/data'\\''"),
            "mkdir should use escaped path, got: {}",
            content
        );
        assert!(
            content.contains("mount -t virtiofs 'smolvm0' '/data'\\''"),
            "mount should use escaped path, got: {}",
            content
        );
    }
}
