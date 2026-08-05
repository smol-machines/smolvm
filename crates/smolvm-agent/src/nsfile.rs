//! File operations performed inside the workload container's mount namespace.
//!
//! The files API used to write at the requested path in the AGENT's mount
//! namespace — the VM rootfs. On a persistent machine that path lands in the
//! overlay's *upper* layer, while the workload's root is the *merged* overlay
//! mount. Writing into a layer beneath a live overlayfs is unsupported by the
//! kernel, so the merged view never observed the write: an upload reported
//! success and the container saw nothing, and a file the container created was
//! invisible to a download. The two sides addressed different filesystems.
//!
//! The fix is to do the work where the workload lives. `setns(CLONE_NEWMNT)`
//! into the container's mount namespace gives exactly the view the workload has
//! — the merged overlay *and* every volume, bind and tmpfs mounted inside it,
//! in the right order. Resolving `/data/x` there hits the volume mounted at
//! `/data`, not the directory buried underneath it.
//!
//! Two properties fall out of doing it this way rather than joining paths from
//! outside:
//!
//! * **Symlink containment is the kernel's job.** Path resolution runs against
//!   the container's own root, so a planted `/tmp -> /storage` symlink cannot
//!   redirect an upload out of the container. A `<overlay>/merged/<path>` join
//!   would follow it — the escape class `safe_unpack` exists to defend against.
//! * **No mount is invisible.** Anything the container gains later is handled
//!   without changes here.
//!
//! `setns(CLONE_NEWMNT)` is refused for a multithreaded caller, and the agent
//! runs a threaded async runtime, so the work happens in a fresh single-threaded
//! re-exec of this same binary (`smolvm-agent ns-file …`) — dispatched at the
//! very top of `main` before any thread starts, the same idiom
//! [`crate::forkpoint`] uses. Bytes move over pipes so neither side buffers a
//! whole file.
//!
//! WHEN THE WORKLOAD IS NOT RUNNING the old behavior is correct and is kept:
//! overlayfs reads `upper` at mount time, so populating it *before* the overlay
//! is mounted is exactly how a rootfs is pre-seeded. Only writes *beneath a
//! live* overlay are lost. That is why this routes into the container only when
//! one is actually running.

use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// argv marker selecting the namespace helper instead of the PID-1 agent.
const HELPER_ARG: &str = "ns-file";
/// This binary, re-executed for the helper.
const AGENT_BINARY: &str = "/usr/local/bin/smolvm-agent";

/// Whether this invocation is the namespace file helper.
///
/// Checked before the async runtime starts: `setns(CLONE_NEWMNT)` requires a
/// single-threaded process, so the helper must never have spawned a thread.
pub fn helper_requested() -> bool {
    std::env::args().nth(1).as_deref() == Some(HELPER_ARG)
}

/// Entry point for `smolvm-agent ns-file <op> <pid> <path> [mode]`.
///
/// Protocol, chosen so the parent never buffers a whole file:
/// * `read`  — stdout gets `OK <size>\n` then exactly `<size>` raw bytes, or
///   `ERR <message>\n`.
/// * `write` — raw bytes arrive on stdin until EOF; stdout gets `OK\n` or
///   `ERR <message>\n`.
pub fn run_helper() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    // argv: [bin, "ns-file", op, pid, path, (mode)]
    if args.len() < 5 {
        eprintln!("ns-file: usage: ns-file <read|write> <pid> <path> [mode]");
        return 2;
    }
    let op = args[2].as_str();
    let Ok(pid) = args[3].parse::<u32>() else {
        eprintln!("ns-file: bad pid");
        return 2;
    };
    let path = args[4].clone();
    let mode = args.get(5).and_then(|m| u32::from_str_radix(m, 8).ok());

    if let Err(e) = enter_mount_namespace(pid) {
        // Report through the protocol so the parent surfaces one clean error.
        let _ = std::io::stdout().write_all(format!("ERR {e}\n").as_bytes());
        return 1;
    }

    let result = match op {
        "read" => helper_read(&path),
        "write" => helper_write(&path, mode),
        "connect" => helper_connect(&path),
        _ => Err("unknown op".to_string()),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            let _ = std::io::stdout().write_all(format!("ERR {e}\n").as_bytes());
            1
        }
    }
}

/// Join `pid`'s mount namespace.
///
/// The container carries no user namespace (the OCI spec requests only
/// pid/mount/ipc/uts), so uid/gid stay meaningful across the switch and only the
/// mount namespace has to be entered.
#[cfg(target_os = "linux")]
fn enter_mount_namespace(pid: u32) -> Result<(), String> {
    let ns = format!("/proc/{pid}/ns/mnt");
    let file = std::fs::File::open(&ns).map_err(|e| format!("open {ns}: {e}"))?;
    // SAFETY: `fd` is a live descriptor for a mount-namespace file; setns only
    // reads it. Single-threaded by construction (dispatched before any thread).
    let rc = unsafe {
        libc::setns(
            std::os::unix::io::AsRawFd::as_raw_fd(&file),
            libc::CLONE_NEWNS,
        )
    };
    if rc != 0 {
        return Err(format!("setns({ns}): {}", std::io::Error::last_os_error()));
    }
    // The old cwd belongs to the namespace we just left; a relative path or a
    // `..` walk from it would resolve outside the container.
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    Ok(())
}

/// Non-Linux stub. `setns`/`CLONE_NEWNS` are Linux-only, and the agent's unit
/// tests build on macOS. Unreachable in practice: the agent runs in a Linux
/// guest, and [`workload_container_pid`] already yields `None` elsewhere, so no
/// caller ever spawns the helper off Linux.
#[cfg(not(target_os = "linux"))]
fn enter_mount_namespace(_pid: u32) -> Result<(), String> {
    Err("mount namespaces are Linux-only".to_string())
}

fn helper_read(path: &str) -> Result<(), String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("stat {path}: {e}"))?;
    // Same guard the in-VM path applies, and for the same reason: a directory
    // opens fine but fails with EISDIR only once reading starts, and a character
    // device never EOFs. Both must be refused BEFORE the header commits us to a
    // byte count.
    if !meta.is_file() {
        return Err(format!("not a regular file: {path}"));
    }
    let size = meta.len();
    let mut out = std::io::stdout().lock();
    out.write_all(format!("OK {size}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    std::io::copy(&mut file, &mut out).map_err(|e| format!("read {path}: {e}"))?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn helper_write(path: &str, mode: Option<u32>) -> Result<(), String> {
    let target = Path::new(path);
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    // Stage beside the target so the rename is same-filesystem and atomic: a
    // reader in the container sees either the old file or the whole new one.
    let tmp = target.with_file_name(format!(
        ".smolvm-upload.{}.{}",
        std::process::id(),
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create staging: {e}"))?;
    let mut stdin = std::io::stdin().lock();
    let copied = std::io::copy(&mut stdin, &mut file);
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {path}: {e}"));
    }
    if let Err(e) = file.sync_all() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("fsync {path}: {e}"));
    }
    drop(file);
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(m)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("chmod {path}: {e}"));
        }
    }
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("rename into {path}: {e}"));
    }
    let mut out = std::io::stdout().lock();
    out.write_all(b"OK\n").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(())
}

/// Dial a Unix socket inside the container and hand the connected descriptor
/// back to the parent over stdin, which the parent made a socketpair.
///
/// Only the *connect* needs the container's namespace: once the socket is
/// established the path is spent, so the parent relays over an ordinary
/// `UnixStream` with no namespace involvement. That is why a descriptor is
/// passed rather than the helper proxying bytes — no extra hop in the data path,
/// and no second process alive for the life of the connection.
#[cfg(target_os = "linux")]
fn helper_connect(path: &str) -> Result<(), String> {
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    let app = UnixStream::connect(path).map_err(|e| format!("connect {path}: {e}"))?;

    // One byte of payload: SCM_RIGHTS needs a non-empty iovec to travel, and it
    // doubles as the parent's "the fd is coming" signal.
    let fds = [app.as_raw_fd()];
    let cmsg = [nix::sys::socket::ControlMessage::ScmRights(&fds)];
    let iov = [IoSlice::new(b"K")];
    nix::sys::socket::sendmsg::<()>(
        std::io::stdin().as_raw_fd(),
        &iov,
        &cmsg,
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .map_err(|e| format!("send fd for {path}: {e}"))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn helper_connect(_path: &str) -> Result<(), String> {
    Err("mount namespaces are Linux-only".to_string())
}

// ===========================================================================
// Parent side
// ===========================================================================

/// The init PID of this machine's running workload container, if there is
/// exactly one.
///
/// Discovered from the overlay tree because a file request carries no workload
/// id. Ambiguity is not guessed at: with several live workloads (a pod) the
/// caller falls back to the VM-namespace path rather than pick one.
#[cfg(target_os = "linux")]
pub fn workload_container_pid() -> Option<u32> {
    let entries = std::fs::read_dir(crate::paths::OVERLAYS_DIR).ok()?;
    let mut found: Option<u32> = None;
    for entry in entries.flatten() {
        let id_file = entry.path().join("main_container_id");
        let Ok(cid) = std::fs::read_to_string(&id_file) else {
            continue;
        };
        let cid = cid.trim();
        if cid.is_empty() {
            continue;
        }
        let Some(pid) = crate::crun_container_pid(cid) else {
            continue;
        };
        if found.is_some() {
            tracing::debug!("several live workload containers; file ops stay in the VM namespace");
            return None;
        }
        found = Some(pid);
    }
    found
}

#[cfg(not(target_os = "linux"))]
pub fn workload_container_pid() -> Option<u32> {
    None
}

/// A file opened inside the container, streaming over the helper's pipe.
///
/// The bytes are NOT buffered: `reader` is the live pipe, bounded to the size
/// the helper reported, so the existing chunked send streams straight through it
/// exactly as it did from a `File`.
pub struct ContainerFile {
    /// Kept so the helper is reaped when the transfer ends (or is abandoned).
    _child: std::process::Child,
    /// Size reported by the helper's `stat` inside the container.
    pub size: u64,
    /// Payload, capped at `size` so a misbehaving helper cannot overrun.
    pub reader: std::io::Take<std::io::BufReader<std::process::ChildStdout>>,
}

/// Open `path` inside the container for reading. `None` means "no single
/// running workload" — the caller keeps the VM-namespace behavior.
pub fn open_in_container(path: &str) -> Option<Result<ContainerFile, String>> {
    let pid = workload_container_pid()?;
    Some(open_via_helper(pid, path))
}

fn open_via_helper(pid: u32, path: &str) -> Result<ContainerFile, String> {
    let mut child = Command::new(AGENT_BINARY)
        .args([HELPER_ARG, "read", &pid.to_string(), path])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn ns-file helper: {e}"))?;
    let stdout = child.stdout.take().expect("piped");
    let mut reader = std::io::BufReader::new(stdout);
    let mut header = String::new();
    reader
        .read_line(&mut header)
        .map_err(|e| format!("ns-file helper: {e}"))?;
    let header = header.trim_end();
    if let Some(msg) = header.strip_prefix("ERR ") {
        return Err(msg.to_string());
    }
    let size: u64 = header
        .strip_prefix("OK ")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("ns-file helper: bad header {header:?}"))?;
    Ok(ContainerFile {
        _child: child,
        size,
        reader: reader.take(size),
    })
}

/// Write `data` to `path` inside the container. `Ok(None)` means "no single
/// running workload" — the caller keeps the VM-namespace behavior.
pub fn write_to_container(
    path: &str,
    data: &[u8],
    mode: Option<u32>,
) -> Option<Result<(), String>> {
    let pid = workload_container_pid()?;
    Some(write_via_helper(pid, path, data, mode))
}

fn write_via_helper(pid: u32, path: &str, data: &[u8], mode: Option<u32>) -> Result<(), String> {
    let mut args = vec![
        HELPER_ARG.to_string(),
        "write".to_string(),
        pid.to_string(),
        path.to_string(),
    ];
    if let Some(m) = mode {
        args.push(format!("{m:o}"));
    }
    let mut child = Command::new(AGENT_BINARY)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn ns-file helper: {e}"))?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        stdin
            .write_all(data)
            .map_err(|e| format!("ns-file helper write: {e}"))?;
    } // drop closes stdin → helper sees EOF
    let out = child
        .wait_with_output()
        .map_err(|e| format!("ns-file helper: {e}"))?;
    let reply = String::from_utf8_lossy(&out.stdout);
    let reply = reply.trim_end();
    if reply == "OK" {
        return Ok(());
    }
    Err(reply
        .strip_prefix("ERR ")
        .unwrap_or("ns-file helper failed")
        .to_string())
}

/// Connect to a Unix socket at `path` inside the workload container.
///
/// `None` means "no single running workload" — the caller keeps whatever it does
/// in the agent's own namespace. Used by the `--expose-socket` bridge, whose app
/// socket lives in the container's mount namespace on an `--image` machine (a
/// private tmpfs `/run`, or the container rootfs) and therefore does not resolve
/// for the agent at all.
#[cfg(target_os = "linux")]
pub fn connect_in_container(path: &str) -> Option<Result<std::os::unix::net::UnixStream, String>> {
    let pid = workload_container_pid()?;
    Some(connect_via_helper(pid, path))
}

#[cfg(not(target_os = "linux"))]
pub fn connect_in_container(_path: &str) -> Option<Result<std::os::unix::net::UnixStream, String>> {
    None
}

#[cfg(target_os = "linux")]
fn connect_via_helper(pid: u32, path: &str) -> Result<std::os::unix::net::UnixStream, String> {
    use std::io::IoSliceMut;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    // The helper returns the descriptor over SCM_RIGHTS, which needs a socket
    // rather than a pipe — so its stdin is one end of a socketpair instead of
    // the pipe `read`/`write` use.
    let (ours, theirs) =
        UnixStream::pair().map_err(|e| format!("socketpair for ns-file connect: {e}"))?;
    let child = Command::new(AGENT_BINARY)
        .args([HELPER_ARG, "connect", &pid.to_string(), path])
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn ns-file helper: {e}"))?;

    let mut byte = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut cmsg_buf = nix::cmsg_space!(std::os::unix::io::RawFd);
    let received = nix::sys::socket::recvmsg::<()>(
        ours.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        nix::sys::socket::MsgFlags::empty(),
    );

    let mut app_fd = None;
    if let Ok(msg) = received {
        for cmsg in msg.cmsgs() {
            if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                // SAFETY: SCM_RIGHTS installed these descriptors in this process,
                // which owns them from here. Exactly one is expected; close any
                // extra rather than leak it.
                for (i, fd) in fds.iter().enumerate() {
                    let owned = unsafe { OwnedFd::from_raw_fd(*fd) };
                    if i == 0 {
                        app_fd = Some(owned);
                    }
                }
            }
        }
    }

    // The helper is short-lived either way; reap it before reporting.
    let output = child.wait_with_output();
    match app_fd {
        Some(fd) => Ok(UnixStream::from(fd)),
        None => {
            let reply = output
                .as_ref()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim_end().to_string())
                .unwrap_or_default();
            Err(reply
                .strip_prefix("ERR ")
                .unwrap_or_else(|| {
                    if reply.is_empty() {
                        "ns-file helper sent no descriptor"
                    } else {
                        &reply
                    }
                })
                .to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_is_selected_only_by_the_exact_marker() {
        // Guards the dispatch in `main`: matching too loosely would turn a normal
        // agent boot into a helper run.
        assert_eq!(HELPER_ARG, "ns-file");
    }

    #[test]
    fn a_write_reply_is_parsed_strictly() {
        // The parent must not read a truncated or unexpected reply as success.
        for bad in ["", "ERR boom", "OKAY", "ERR "] {
            assert_ne!(bad.trim_end(), "OK", "{bad:?} must not look like success");
        }
    }

    #[test]
    fn connect_reports_an_error_when_no_descriptor_arrives() {
        // The connect op signals success by SENDING A DESCRIPTOR, not by a reply
        // string, so "nothing came back" is the failure the parent must name
        // rather than treat as an empty-but-fine result. Mirrors the fallback in
        // `connect_via_helper` when `app_fd` is None and stdout was empty.
        let reply = "";
        let msg = reply
            .strip_prefix("ERR ")
            .unwrap_or(if reply.is_empty() {
                "ns-file helper sent no descriptor"
            } else {
                reply
            })
            .to_string();
        assert!(
            !msg.is_empty(),
            "a missing descriptor must produce a reason"
        );
        assert!(msg.contains("no descriptor"));
    }

    #[test]
    fn connect_surfaces_the_helper_error_text() {
        // A failed in-container dial reports through stdout like the other ops.
        let reply = "ERR connect /run/control/app.sock: No such file or directory";
        let msg = reply.strip_prefix("ERR ").unwrap_or(reply);
        assert_eq!(
            msg,
            "connect /run/control/app.sock: No such file or directory"
        );
    }
}
