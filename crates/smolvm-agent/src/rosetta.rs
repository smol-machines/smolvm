//! Guest-side Rosetta 2 setup.
//!
//! When the host attaches the RosettaLinux runtime (virtiofs tag
//! [`smolvm_protocol::ROSETTA_TAG`]) and signals [`guest_env::ROSETTA`], this
//! module mounts that runtime at [`smolvm_protocol::ROSETTA_GUEST_PATH`] and
//! registers the ptrace wrapper (`/usr/bin/rosetta-wrapper`, shipped in the
//! agent rootfs) with `binfmt_misc` as the interpreter for x86_64 ELF binaries.
//!
//! libkrun runs under Hypervisor.framework, not Virtualization.framework, so
//! Rosetta's runtime-validation ioctl fails; the wrapper intercepts that ioctl
//! via ptrace, returns the expected magic, then detaches for full-speed
//! execution. The `F` (fix-binary) flag pins the wrapper fd at registration
//! time so it keeps working inside crun containers whose mount namespaces don't
//! include the agent rootfs.

use smolvm_protocol::guest_env;

/// Guest path of the ptrace wrapper (installed into the agent rootfs by
/// `scripts/build-agent-rootfs.sh`).
#[cfg(target_os = "linux")]
const WRAPPER_PATH: &str = "/usr/bin/rosetta-wrapper";

/// binfmt_misc control directory and its registration file.
#[cfg(target_os = "linux")]
const BINFMT_MISC_DIR: &str = "/proc/sys/fs/binfmt_misc";
#[cfg(target_os = "linux")]
const BINFMT_REGISTER_FILE: &str = "/proc/sys/fs/binfmt_misc/register";

/// binfmt_misc registration line: match x86_64 ELF — both `ET_EXEC` and `ET_DYN`
/// (PIE), via the `\xfe` byte in the e_type mask — and route to the wrapper. The
/// magic/mask are literal `\xNN` escapes; the kernel's binfmt parser unescapes
/// them. Same magic/mask qemu-user uses for `qemu-x86_64`.
#[cfg(target_os = "linux")]
const BINFMT_REGISTER: &str = ":rosetta:M::\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff:/usr/bin/rosetta-wrapper:F";

/// Whether the host requested Rosetta translation for this VM.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::ROSETTA).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Bind-mount the Rosetta runtime into a workload container so the wrapper's
/// `execve("/mnt/rosetta/rosetta")` resolves inside the container's mount
/// namespace. binfmt_misc's `F` flag pins the wrapper fd itself, but the
/// translator it execs is an ordinary path lookup in the container's ns, so the
/// runtime must be visible there too. No-op unless Rosetta is enabled.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    inject_into_container_if(spec, is_enabled());
}

/// Testable core of [`inject_into_container`]: adds the read-only runtime
/// bind-mount when `enabled`. Split out so tests don't touch the process-wide
/// `SMOLVM_ROSETTA` env var.
fn inject_into_container_if(spec: &mut crate::oci::OciSpec, enabled: bool) {
    if !enabled {
        return;
    }
    // Read-only: the container only execs the translator, never writes it. Skip
    // if the workload already mounts something at this path so a user mount wins.
    if spec
        .mounts
        .iter()
        .any(|m| m.destination == smolvm_protocol::ROSETTA_GUEST_PATH)
    {
        return;
    }
    spec.add_bind_mount(
        smolvm_protocol::ROSETTA_GUEST_PATH,
        smolvm_protocol::ROSETTA_GUEST_PATH,
        true,
    );
}

/// Mount the Rosetta runtime and register the `binfmt_misc` handler.
///
/// Best-effort: every failure is logged and swallowed so a Rosetta problem never
/// blocks the VM from booting (x86_64 workloads simply won't translate). A no-op
/// on non-Linux (the agent builds a macOS stub for host-side unit tests).
pub fn setup() {
    #[cfg(target_os = "linux")]
    {
        use smolvm_protocol::ROSETTA_GUEST_PATH;

        if let Err(e) = mount_runtime() {
            tracing::warn!(error = %e, "rosetta: runtime mount failed; x86_64 translation unavailable");
            return;
        }
        if !std::path::Path::new(WRAPPER_PATH).exists() {
            tracing::warn!(
                wrapper = WRAPPER_PATH,
                "rosetta: wrapper missing from rootfs; x86_64 translation unavailable"
            );
            return;
        }
        if let Err(e) = register_binfmt() {
            tracing::warn!(error = %e, "rosetta: binfmt_misc registration failed; x86_64 translation unavailable");
            return;
        }
        tracing::info!(
            mount = ROSETTA_GUEST_PATH,
            "rosetta: x86_64 translation enabled"
        );
    }
}

/// Mount virtiofs tag [`ROSETTA_TAG`] at [`ROSETTA_GUEST_PATH`]. Idempotent: if
/// the translator is already visible there, the mount is left as-is.
#[cfg(target_os = "linux")]
fn mount_runtime() -> std::io::Result<()> {
    use smolvm_protocol::{ROSETTA_GUEST_PATH, ROSETTA_TAG};
    use std::ffi::CString;

    std::fs::create_dir_all(ROSETTA_GUEST_PATH)?;

    if std::path::Path::new(ROSETTA_GUEST_PATH)
        .join("rosetta")
        .exists()
    {
        return Ok(());
    }

    let src = CString::new(ROSETTA_TAG).expect("rosetta tag has no null byte");
    let dst = CString::new(ROSETTA_GUEST_PATH).expect("rosetta path has no null byte");
    let fstype = CString::new("virtiofs").expect("literal has no null byte");
    // SAFETY: all args are valid null-terminated C strings; virtiofs takes no
    // mount data (matches storage::setup_packed_layers).
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Mount `binfmt_misc` if needed and write the x86_64→wrapper registration.
/// Idempotent: skips if a `rosetta` handler is already registered on this kernel.
#[cfg(target_os = "linux")]
fn register_binfmt() -> std::io::Result<()> {
    use std::ffi::CString;

    // The /register control file only exists once binfmt_misc is mounted. Some
    // kernels auto-mount it; mount it ourselves otherwise.
    if !std::path::Path::new(BINFMT_REGISTER_FILE).exists() {
        std::fs::create_dir_all(BINFMT_MISC_DIR)?;
        let src = CString::new("binfmt_misc").unwrap();
        let dst = CString::new(BINFMT_MISC_DIR).unwrap();
        let fstype = CString::new("binfmt_misc").unwrap();
        // SAFETY: valid C strings; binfmt_misc takes no mount data.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                fstype.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    if std::path::Path::new(BINFMT_MISC_DIR)
        .join("rosetta")
        .exists()
    {
        return Ok(());
    }

    std::fs::write(BINFMT_REGISTER_FILE, BINFMT_REGISTER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    fn empty_spec() -> OciSpec {
        OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        )
    }

    #[test]
    fn inject_is_noop_when_disabled() {
        let mut spec = empty_spec();
        let mounts_before = spec.mounts.len();
        inject_into_container_if(&mut spec, false);
        assert_eq!(spec.mounts.len(), mounts_before);
    }

    #[test]
    fn inject_adds_readonly_runtime_mount_when_enabled() {
        let mut spec = empty_spec();
        inject_into_container_if(&mut spec, true);

        let mount = spec
            .mounts
            .iter()
            .find(|m| m.destination == smolvm_protocol::ROSETTA_GUEST_PATH)
            .expect("rosetta runtime bind mount not found");
        assert_eq!(mount.source, smolvm_protocol::ROSETTA_GUEST_PATH);
        assert_eq!(mount.mount_type.as_deref(), Some("bind"));
        // Read-only: the container only execs the translator.
        assert!(mount.options.iter().any(|o| o == "ro"));
        assert!(mount.options.iter().any(|o| o == "bind"));
    }

    #[test]
    fn inject_does_not_duplicate_existing_mount() {
        let mut spec = empty_spec();
        // A user mount already claims the path; injection must not add a second.
        spec.add_bind_mount(
            smolvm_protocol::ROSETTA_GUEST_PATH,
            smolvm_protocol::ROSETTA_GUEST_PATH,
            false,
        );
        let mounts_before = spec.mounts.len();
        inject_into_container_if(&mut spec, true);
        assert_eq!(spec.mounts.len(), mounts_before);
    }

    #[test]
    fn is_enabled_reflects_env_sentinel() {
        // Save/restore to avoid cross-test env bleed.
        let prev = std::env::var(guest_env::ROSETTA).ok();

        std::env::remove_var(guest_env::ROSETTA);
        assert!(!is_enabled(), "unset must be disabled");

        std::env::set_var(guest_env::ROSETTA, guest_env::VALUE_ON);
        assert!(is_enabled(), "sentinel value must enable");

        std::env::set_var(guest_env::ROSETTA, "0");
        assert!(!is_enabled(), "non-sentinel value must be disabled");

        match prev {
            Some(v) => std::env::set_var(guest_env::ROSETTA, v),
            None => std::env::remove_var(guest_env::ROSETTA),
        }
    }
}
