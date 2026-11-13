//! Guest-side Rosetta 2 setup.
//!
//! When the host attaches the RosettaLinux runtime (virtiofs tag
//! [`smolvm_protocol::ROSETTA_TAG`]) and signals [`guest_env::ROSETTA`], this
//! module mounts that runtime at [`smolvm_protocol::ROSETTA_GUEST_PATH`] and
//! registers an interpreter for x86_64 ELF binaries with `binfmt_misc`.
//!
//! Before it translates anything, Rosetta asks the file system holding its own
//! binary for a key (an ioctl on the binary) and aborts without it. Which
//! interpreter is registered depends on whether the host answers:
//!
//! - It does (libkrun's virtiofs server answers for the Rosetta share): Rosetta
//!   itself is the interpreter, with the `C` (credentials) flag. A translated
//!   program is then an ordinary process: it keeps the pid it was started with
//!   (so it can be pid 1 of a new pid namespace, which Chrome's sandbox
//!   requires of its zygote), receives its own signals, and a setuid binary
//!   such as `sudo` runs with the file's owner as its effective uid.
//! - It does not (an older libkrun): the ptrace wrapper
//!   (`/usr/bin/rosetta-wrapper`, shipped in the agent rootfs) is the
//!   interpreter. It embeds the translator for nested mount namespaces and
//!   uses a machine-wide tracer to answer the key request without changing
//!   the program PID. If the tracer cannot start, it falls back to a child
//!   process. Setuid bits are ignored on this legacy path.
//!
//! The `F` (fix-binary) flag pins the interpreter at registration time so it
//! keeps working inside crun containers whose mount namespaces don't include
//! the agent rootfs.

use smolvm_protocol::guest_env;

/// Guest path of the ptrace wrapper (installed into the agent rootfs by
/// `scripts/build-agent-rootfs.sh`).
#[cfg(any(target_os = "linux", test))]
const WRAPPER_PATH: &str = "/usr/bin/rosetta-wrapper";

/// Where the interpreter (wrapper plus appended translator) is written before
/// registration. A tmpfs in the agent's own root; the file is unlinked once
/// binfmt_misc has pinned it, so nothing is left behind.
#[cfg(target_os = "linux")]
const EMBEDDED_INTERPRETER: &str = "/tmp/smolvm-rosetta-interpreter";

/// Trailer magic after the appended translator. Keep in sync with
/// `EMBED_MAGIC` in `scripts/rosetta/rosetta-wrapper.c`.
#[cfg(any(target_os = "linux", test))]
const EMBED_MAGIC: &[u8; 16] = b"SMOLVM-ROSETTA\0\x01";

/// The registration line routing x86_64 ELF to `interpreter`, pinned (`F`).
#[cfg(target_os = "linux")]
fn binfmt_register_line(interpreter: &str) -> String {
    format!("{BINFMT_X86_64_MATCH}:{interpreter}:F")
}

/// Trailer flag: the tracer helper runs and will seize every wrapper. Keep in
/// sync with `EMBED_FLAG_TRACER` in `rosetta-wrapper.c`.
#[cfg(any(target_os = "linux", test))]
const EMBED_FLAG_TRACER: u64 = 1;

/// Size of the trailer: offset, size, flags (u64 each) and the magic.
#[cfg(any(target_os = "linux", test))]
const TRAILER_LEN: usize = 40;

/// Write `wrapper` followed by `translator` and a trailer naming where the
/// translator starts, how long it is and `flags`, the layout
/// `rosetta-wrapper.c` reads back from its own executable. The wrapper is an
/// ELF executable, so the bytes after it are never loaded; the translator
/// starts 8-byte aligned.
#[cfg(any(target_os = "linux", test))]
fn embedded_interpreter_bytes(wrapper: &[u8], translator: &[u8], flags: u64) -> Vec<u8> {
    let offset = wrapper.len().next_multiple_of(8);
    let mut out = Vec::with_capacity(offset + translator.len() + TRAILER_LEN);
    out.extend_from_slice(wrapper);
    out.resize(offset, 0);
    out.extend_from_slice(translator);
    out.extend_from_slice(&(offset as u64).to_le_bytes());
    out.extend_from_slice(&(translator.len() as u64).to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(EMBED_MAGIC);
    out
}

/// binfmt_misc control directory and its registration file.
#[cfg(target_os = "linux")]
const BINFMT_MISC_DIR: &str = "/proc/sys/fs/binfmt_misc";
#[cfg(target_os = "linux")]
const BINFMT_REGISTER_FILE: &str = "/proc/sys/fs/binfmt_misc/register";

/// The x86_64 ELF match of the binfmt_misc registration line: both `ET_EXEC`
/// and `ET_DYN` (PIE), via the `\xfe` byte in the e_type mask. The magic/mask
/// are literal `\xNN` escapes; the kernel's binfmt parser unescapes them. Same
/// magic/mask qemu-user uses for `qemu-x86_64`.
#[cfg(any(target_os = "linux", test))]
const BINFMT_X86_64_MATCH: &str = ":rosetta:M::\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff";

/// Rosetta's key request on its own binary: `_IOR('a', 0x25, [u8; 69])`. The
/// request number has changed between macOS releases; the host tells the
/// request apart by its type and reply size, so this one is answered either way.
#[cfg(target_os = "linux")]
const KEY_REQUEST: u32 = 0x8045_6125;
#[cfg(target_os = "linux")]
const KEY_REPLY_LEN: usize = 69;

/// What `binfmt_misc` runs an x86_64 binary with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
enum Interpreter {
    /// Rosetta itself. Needs the host to answer Rosetta's key request.
    Translator,
    /// The ptrace wrapper, which answers the key request in the guest.
    Wrapper,
}

#[cfg(any(target_os = "linux", test))]
impl Interpreter {
    /// The registration line written to `binfmt_misc`'s `register` file.
    ///
    /// Only the translator gets `C`: the kernel then takes credentials from
    /// the x86_64 binary, so a setuid program runs as the file's owner. The
    /// wrapper stays without it: with `C` the wrapper itself would run
    /// setuid, as the ptrace tracer of the program it starts.
    fn registration(self) -> String {
        match self {
            Interpreter::Translator => format!(
                "{BINFMT_X86_64_MATCH}:{}/rosetta:CF",
                smolvm_protocol::ROSETTA_GUEST_PATH
            ),
            Interpreter::Wrapper => format!("{BINFMT_X86_64_MATCH}:{WRAPPER_PATH}:F"),
        }
    }
}

/// Whether the host requested Rosetta translation for this VM.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::ROSETTA).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Bind-mount the Rosetta runtime into a workload container so the wrapper's
/// `execve("/mnt/rosetta/rosetta")` resolves inside the container's mount
/// namespace. binfmt_misc's `F` flag pins the interpreter fd itself, but the
/// translator the wrapper execs is an ordinary path lookup in the container's
/// ns, so the runtime must be visible there too. No-op unless Rosetta is
/// enabled.
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
        let interpreter = if host_answers_key_request() {
            Interpreter::Translator
        } else if std::path::Path::new(WRAPPER_PATH).exists() {
            Interpreter::Wrapper
        } else {
            tracing::warn!(
                wrapper = WRAPPER_PATH,
                "rosetta: host does not answer the key request and the wrapper is missing from rootfs; x86_64 translation unavailable"
            );
            return;
        };
        if let Err(e) = register_binfmt(interpreter) {
            tracing::warn!(error = %e, "rosetta: binfmt_misc registration failed; x86_64 translation unavailable");
            return;
        }
        tracing::info!(
            mount = ROSETTA_GUEST_PATH,
            ?interpreter,
            "rosetta: x86_64 translation enabled"
        );
    }
}

/// Whether the host answers Rosetta's key request on the mounted translator.
///
/// The reply is the key as a C string. A host that does not know the request
/// reports success with the buffer left empty, so an empty reply means no.
#[cfg(target_os = "linux")]
fn host_answers_key_request() -> bool {
    use std::os::fd::AsRawFd;

    let translator = std::path::Path::new(smolvm_protocol::ROSETTA_GUEST_PATH).join("rosetta");
    let Ok(file) = std::fs::File::open(translator) else {
        return false;
    };
    let mut reply = [0u8; KEY_REPLY_LEN];
    // SAFETY: the request reads KEY_REPLY_LEN bytes into `reply`, which is
    // that long and outlives the call.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), KEY_REQUEST as _, reply.as_mut_ptr()) };
    rc >= 0 && reply[0] != 0
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

/// Mount `binfmt_misc` if needed and write the x86_64 registration for
/// `interpreter`. Idempotent: skips if a `rosetta` handler is already
/// registered on this kernel.
#[cfg(target_os = "linux")]
fn register_binfmt(interpreter: Interpreter) -> std::io::Result<()> {
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

    if interpreter == Interpreter::Translator {
        return std::fs::write(BINFMT_REGISTER_FILE, interpreter.registration());
    }

    // Prefer the self-contained interpreter so nested containers translate
    // too; fall back to the bare wrapper (smolvm's own containers only).
    match write_embedded_interpreter(EMBED_FLAG_TRACER) {
        Ok(identity) => {
            if let Err(e) = start_tracer(identity) {
                tracing::warn!(error = %e, "rosetta: tracer helper unavailable; translated programs get a new PID");
                if let Err(e) = write_embedded_interpreter(0) {
                    tracing::warn!(error = %e, "rosetta: could not rewrite the embedded interpreter");
                }
            }
            let registered = std::fs::write(
                BINFMT_REGISTER_FILE,
                binfmt_register_line(EMBEDDED_INTERPRETER),
            );
            // `F` keeps the kernel's own reference: the file is not needed now.
            let _ = std::fs::remove_file(EMBEDDED_INTERPRETER);
            match registered {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(error = %e, "rosetta: registering the embedded interpreter failed; nested containers will not translate")
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "rosetta: could not build the embedded interpreter; nested containers will not translate")
        }
    }
    std::fs::write(BINFMT_REGISTER_FILE, binfmt_register_line(WRAPPER_PATH))
}

/// Write the wrapper with the translator appended to [`EMBEDDED_INTERPRETER`];
/// returns the file's (device, inode), which identify it as a running
/// process's `/proc/<pid>/exe`.
#[cfg(target_os = "linux")]
fn write_embedded_interpreter(flags: u64) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let wrapper = std::fs::read(WRAPPER_PATH)?;
    let translator =
        std::fs::read(std::path::Path::new(smolvm_protocol::ROSETTA_GUEST_PATH).join("rosetta"))?;
    let bytes = embedded_interpreter_bytes(&wrapper, &translator, flags);
    let _ = std::fs::remove_file(EMBEDDED_INTERPRETER);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(EMBEDDED_INTERPRETER)?;
    std::io::Write::write_all(&mut file, &bytes)?;
    file.sync_all()?;
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

/// Start the machine's tracer helper for the interpreter `(dev, ino)` and wait
/// until it listens for execs.
#[cfg(target_os = "linux")]
fn start_tracer((dev, ino): (u64, u64)) -> std::io::Result<()> {
    use std::io::Read;
    let mut child = std::process::Command::new("/proc/self/exe")
        .arg(crate::rosetta_tracer::TRACER_ARG)
        .arg(dev.to_string())
        .arg(ino.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    // Bounded: a helper that never answers must not hold up the boot.
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(mut out) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut ready = [0u8; 1];
            let _ = tx.send(matches!(out.read(&mut ready), Ok(1) if ready[0] == b'R'));
        });
    }
    let listening = rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap_or(false);
    if !listening {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other("the tracer helper did not start"));
    }
    // It runs for the life of the machine; keep the handle so it is not
    // mistaken for a finished child.
    static TRACER: std::sync::OnceLock<std::sync::Mutex<std::process::Child>> =
        std::sync::OnceLock::new();
    let _ = TRACER.set(std::sync::Mutex::new(child));
    Ok(())
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
    fn translator_registration_carries_credentials() {
        let line = Interpreter::Translator.registration();
        // name, type, offset, magic, mask, interpreter, flags
        let fields: Vec<&str> = line.split(':').collect();
        assert_eq!(fields.len(), 8, "{line}");
        assert_eq!(fields[1], "rosetta");
        assert_eq!(fields[2], "M");
        assert_eq!(fields[6], "/mnt/rosetta/rosetta");
        // C: setuid binaries get their owner's uid. F: usable in any mount ns.
        assert_eq!(fields[7], "CF");
    }

    #[test]
    fn wrapper_registration_has_no_credentials() {
        let line = Interpreter::Wrapper.registration();
        let fields: Vec<&str> = line.split(':').collect();
        assert_eq!(fields.len(), 8, "{line}");
        assert_eq!(fields[6], WRAPPER_PATH);
        // With C the wrapper itself would run setuid.
        assert_eq!(fields[7], "F");
    }

    #[test]
    fn both_registrations_match_the_same_binaries() {
        let translator = Interpreter::Translator.registration();
        let wrapper = Interpreter::Wrapper.registration();
        assert!(translator.starts_with(BINFMT_X86_64_MATCH));
        assert!(wrapper.starts_with(BINFMT_X86_64_MATCH));
        // x86_64 (EM_X86_64 = 0x3e), 64-bit little-endian ELF.
        assert!(BINFMT_X86_64_MATCH.contains("\\x7fELF\\x02\\x01"));
        assert!(BINFMT_X86_64_MATCH.contains("\\x3e\\x00:"));
    }

    #[test]
    fn embedded_interpreter_trailer_locates_the_translator() {
        let wrapper = b"\x7fELF-wrapper-13";
        let translator = b"rosetta-bytes";
        let bytes = embedded_interpreter_bytes(wrapper, translator, EMBED_FLAG_TRACER);
        assert!(
            bytes.starts_with(wrapper),
            "the wrapper stays an executable"
        );
        let trailer = &bytes[bytes.len() - TRAILER_LEN..];
        let offset = u64::from_le_bytes(trailer[..8].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(trailer[8..16].try_into().unwrap()) as usize;
        let flags = u64::from_le_bytes(trailer[16..24].try_into().unwrap());
        assert_eq!(&trailer[24..], EMBED_MAGIC);
        assert_eq!(flags, EMBED_FLAG_TRACER);
        assert_eq!(offset % 8, 0);
        assert!(offset >= wrapper.len());
        assert_eq!(&bytes[offset..offset + size], translator);
        assert_eq!(offset + size + TRAILER_LEN, bytes.len());
    }

    #[test]
    fn the_c_wrapper_reads_the_same_magic() {
        let source = include_str!("../../../scripts/rosetta/rosetta-wrapper.c");
        assert!(
            source.contains(r#""SMOLVM-ROSETTA\0\1";"#),
            "rosetta-wrapper.c and rosetta.rs must agree on the trailer magic"
        );
        assert!(source.contains("#define EMBED_FLAG_TRACER 1"));
        assert!(
            source.contains("uint64_t flags;\n    char magic[16];"),
            "the C trailer is offset, size, flags, magic"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_registration_pins_the_interpreter() {
        let line = binfmt_register_line("/tmp/x");
        assert!(line.starts_with(":rosetta:M::\\x7fELF"));
        assert!(line.ends_with(":/tmp/x:F"));
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
