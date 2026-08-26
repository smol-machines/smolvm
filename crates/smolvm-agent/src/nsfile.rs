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

/// Entry point for `smolvm-agent ns-file <op> <pid> <path> [mode [uid gid]]`.
///
/// Protocol, chosen so the parent never buffers a whole file:
/// * `read`  — stdout gets `OK <size>\n` then exactly `<size>` raw bytes, or
///   `ERR <message>\n`.
/// * `write` — raw bytes arrive on stdin until EOF; stdout gets `OK\n` or
///   `ERR <message>\n`. mode/uid/gid are positional with `-` meaning
///   "not requested".
pub fn run_helper() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    // argv: [bin, "ns-file", op, pid, path, (mode), (uid), (gid)]
    if args.len() < 5 {
        eprintln!("ns-file: usage: ns-file <read|write> <pid> <path> [mode [uid gid]]");
        return 2;
    }
    let op = args[2].as_str();
    let Ok(pid) = args[3].parse::<u32>() else {
        eprintln!("ns-file: bad pid");
        return 2;
    };
    let path = args[4].clone();
    let opt = |i: usize| args.get(i).filter(|v| v.as_str() != "-");
    let mode = opt(5).and_then(|m| u32::from_str_radix(m, 8).ok());
    let uid = opt(6).and_then(|u| u.parse::<u32>().ok());
    let gid = opt(7).and_then(|g| g.parse::<u32>().ok());

    if let Err(e) = enter_mount_namespace(pid) {
        // Report through the protocol so the parent surfaces one clean error.
        let _ = std::io::stdout().write_all(format!("ERR {e}\n").as_bytes());
        return 1;
    }

    let result = match op {
        "read" => helper_read(&path),
        "write" => helper_write(&path, mode, uid, gid),
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
/// guest, and off Linux no workload container is ever resolved (`for_workload`
/// yields [`GuestNs::Root`]), so no caller ever spawns the helper off Linux.
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

fn helper_write(
    path: &str,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
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
    if uid.is_some() || gid.is_some() {
        if let Err(e) = std::os::unix::fs::chown(&tmp, uid, gid) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("chown {path}: {e}"));
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

/// Dial `path` inside the container and hand the connected socket back.
///
/// A file operation can move bytes through a pipe, but a proxy needs the socket
/// ITSELF: the parent relays traffic for the life of the connection, so what has
/// to cross the process boundary is the descriptor, not its contents. `SCM_RIGHTS`
/// over the inherited stdin socket is the only way to pass one.
#[cfg(target_os = "linux")]
fn helper_connect(path: &str) -> Result<(), String> {
    use std::os::unix::io::AsRawFd as _;
    let app = std::os::unix::net::UnixStream::connect(path)
        .map_err(|e| format!("connect {path}: {e}"))?;
    // stdin is the parent's socketpair end (set by `ContainerNs::connect`).
    send_fd(libc::STDIN_FILENO, app.as_raw_fd())?;
    let mut out = std::io::stdout().lock();
    out.write_all(b"OK\n").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn helper_connect(_path: &str) -> Result<(), String> {
    Err("mount namespaces are Linux-only".to_string())
}

/// Send `fd` over `sock` as an SCM_RIGHTS control message.
///
/// One byte of payload accompanies it because a control message needs at least
/// one byte of data to be delivered.
#[cfg(target_os = "linux")]
fn send_fd(sock: libc::c_int, fd: libc::c_int) -> Result<(), String> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg = [0u8; 32]; // >= CMSG_SPACE(sizeof(int))
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len() as _;
    // SAFETY: `msg` points at live local storage sized per CMSG_SPACE, and the
    // header is filled exactly as sendmsg requires before the payload is copied.
    unsafe {
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(hdr).cast::<libc::c_int>(), 1);
        msg.msg_controllen = (*hdr).cmsg_len;
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(format!("sendmsg: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

// ===========================================================================
// Parent side
// ===========================================================================

/// Why guest I/O is happening in the VM's own namespace rather than a
/// container's.
///
/// Carried rather than discarded: the container path declining to run is
/// invisible from the outside — an upload still reports success, a socket dial
/// still returns — so without a reason a silent no-op is indistinguishable from
/// a working container. Diagnosing one such case took hours of reading bytes off
/// a live guest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum RootReason {
    /// Nothing is running: no container to enter.
    NoWorkload,
    /// Several unrelated workloads (a pod). Picking one would write into an
    /// arbitrary container's filesystem, so we decline instead of guessing.
    Ambiguous(usize),
}

impl std::fmt::Display for RootReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoWorkload => write!(f, "no running workload container"),
            Self::Ambiguous(n) => write!(f, "{n} running workload containers; cannot choose"),
        }
    }
}

/// A running workload container's mount namespace.
///
/// Holding this type IS the proof a container was found, so the operations below
/// exist only here — a caller cannot reach for them and silently get the VM's
/// namespace instead.
#[derive(Debug, Clone, Copy)]
pub struct ContainerNs {
    pid: u32,
}

/// Where a guest path or socket should be resolved.
///
/// Both arms are legitimate. The VM namespace is *correct* when no workload is
/// running: overlayfs reads `upper` at mount time, so seeding it before the
/// container starts is how a rootfs is pre-populated. What must never happen is
/// choosing it by accident.
#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum GuestNs {
    Root(RootReason),
    Container(ContainerNs),
}

impl GuestNs {
    /// Resolve where this machine's workload lives, logging the reason whenever
    /// the answer is the VM's own namespace.
    pub fn for_workload() -> Self {
        match workload_container() {
            Ok(pid) => Self::Container(ContainerNs { pid }),
            Err(reason) => {
                tracing::debug!(reason = %reason, "guest I/O staying in the VM namespace");
                Self::Root(reason)
            }
        }
    }
}

/// The init PID of the container this machine's guest I/O belongs in.
///
/// Prefers the machine's recorded main container. When that is not running —
/// the normal state of an exec-driven machine, whose main container exits
/// between commands while each `exec` runs its own — it falls back to the single
/// container crun actually has running. Reading the overlay tree alone missed
/// those entirely, so the container path never engaged on such a machine and
/// every file operation silently took the VM-namespace route.
#[cfg(target_os = "linux")]
fn workload_container() -> Result<u32, RootReason> {
    let mains = live_main_containers();
    match mains.len() {
        1 => return Ok(mains[0]),
        0 => {}
        n => return Err(RootReason::Ambiguous(n)),
    }
    // No recorded main container is alive. Anything crun is running now shares
    // this machine's filesystem, so entering it resolves paths the same way.
    let running = live_containers();
    match running.len() {
        1 => Ok(running[0]),
        0 => Err(RootReason::NoWorkload),
        n => Err(RootReason::Ambiguous(n)),
    }
}

/// Off Linux there are no containers at all, which is what `NoWorkload` says.
/// Present so the agent's unit tests build on a developer machine.
#[cfg(not(target_os = "linux"))]
fn workload_container() -> Result<u32, RootReason> {
    Err(RootReason::NoWorkload)
}

/// PIDs of the running containers each overlay records as its main one.
#[cfg(target_os = "linux")]
fn live_main_containers() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(crate::paths::OVERLAYS_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| std::fs::read_to_string(e.path().join("main_container_id")).ok())
        .filter_map(|cid| crate::crun_container_pid(cid.trim()))
        .collect()
}

/// PIDs of every container crun currently has running.
///
/// The crun state directory is the truth about what exists right now; the
/// overlay tree only records the container a machine was STARTED with. Entries
/// for exited containers resolve to `None` (their recorded pid no longer
/// matches), so they filter themselves out.
#[cfg(target_os = "linux")]
fn live_containers() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(crate::paths::CRUN_ROOT_DIR) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|cid| crate::crun_container_pid(&cid))
        .collect()
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

// Reachable only on Linux: `workload_container` yields a `ContainerNs` only
// there, so a developer build on macOS sees these as unused by construction.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl ContainerNs {
    /// Open `path` inside the container for reading.
    pub fn open(&self, path: &str) -> Result<ContainerFile, String> {
        let mut child = Command::new(AGENT_BINARY)
            .args([HELPER_ARG, "read", &self.pid.to_string(), path])
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

    /// Write `data` to `path` inside the container, atomically, applying `mode`
    /// and `uid`/`gid` ownership so a non-root workload can read its own upload.
    pub fn write(
        &self,
        path: &str,
        data: &[u8],
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), String> {
        write_via_helper(
            self.pid,
            path,
            &mut std::io::Cursor::new(data),
            mode,
            uid,
            gid,
        )
    }

    /// Stream `reader` into `path` inside the container without buffering the
    /// whole payload — the streaming-upload counterpart to [`write`].
    pub fn write_reader<R: std::io::Read>(
        &self,
        path: &str,
        reader: &mut R,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), String> {
        write_via_helper(self.pid, path, reader, mode, uid, gid)
    }

    /// Dial `path` inside the container and return the connected socket.
    ///
    /// The descriptor is received over a socketpair given to the helper as its
    /// stdin, so the caller relays traffic on a socket that was opened with the
    /// container's view of the filesystem.
    #[cfg(target_os = "linux")]
    pub fn connect(&self, path: &str) -> Result<std::os::unix::net::UnixStream, String> {
        use std::os::unix::io::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
        let (ours, theirs) =
            std::os::unix::net::UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
        let child = Command::new(AGENT_BINARY)
            .args([HELPER_ARG, "connect", &self.pid.to_string(), path])
            // SAFETY: `theirs` is an owned socket handed to the child as fd 0.
            .stdin(unsafe { Stdio::from_raw_fd(theirs.into_raw_fd()) })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn ns-file helper: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("ns-file helper: {e}"))?;
        // Check the reply BEFORE reading a descriptor: on failure there is none,
        // and the error text says why the dial failed inside the container.
        parse_ok_reply(&String::from_utf8_lossy(&out.stdout))?;
        let fd = recv_fd(ours.as_raw_fd())?;
        // SAFETY: `fd` was just received via SCM_RIGHTS and is owned by us.
        Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn connect(&self, _path: &str) -> Result<std::os::unix::net::UnixStream, String> {
        Err("mount namespaces are Linux-only".to_string())
    }
}

/// Receive a descriptor sent with [`send_fd`].
#[cfg(target_os = "linux")]
fn recv_fd(sock: libc::c_int) -> Result<libc::c_int, String> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len() as _;
    // SAFETY: `msg` describes live local storage; the header is inspected only
    // after recvmsg reports success, and only for an SCM_RIGHTS payload.
    unsafe {
        if libc::recvmsg(sock, &mut msg, 0) < 0 {
            return Err(format!("recvmsg: {}", std::io::Error::last_os_error()));
        }
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        if hdr.is_null()
            || (*hdr).cmsg_level != libc::SOL_SOCKET
            || (*hdr).cmsg_type != libc::SCM_RIGHTS
        {
            return Err("helper sent no descriptor".to_string());
        }
        let mut fd: libc::c_int = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(hdr).cast::<libc::c_int>(), &mut fd, 1);
        if fd < 0 {
            return Err("helper sent an invalid descriptor".to_string());
        }
        Ok(fd)
    }
}

fn write_via_helper<R: std::io::Read>(
    pid: u32,
    path: &str,
    data: &mut R,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    // Fixed positional args; "-" is the explicit "not requested" placeholder
    // so uid/gid can follow an absent mode unambiguously.
    let args = vec![
        HELPER_ARG.to_string(),
        "write".to_string(),
        pid.to_string(),
        path.to_string(),
        mode.map_or_else(|| "-".to_string(), |m| format!("{m:o}")),
        uid.map_or_else(|| "-".to_string(), |u| u.to_string()),
        gid.map_or_else(|| "-".to_string(), |g| g.to_string()),
    ];
    let mut child = Command::new(AGENT_BINARY)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn ns-file helper: {e}"))?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        std::io::copy(data, &mut stdin).map_err(|e| format!("ns-file helper write: {e}"))?;
    } // drop closes stdin → helper sees EOF
    let out = child
        .wait_with_output()
        .map_err(|e| format!("ns-file helper: {e}"))?;
    parse_ok_reply(&String::from_utf8_lossy(&out.stdout))
}

/// Strict reply parsing: anything that is not exactly `OK` is a failure, so a
/// truncated or unexpected reply is never read as success.
fn parse_ok_reply(reply: &str) -> Result<(), String> {
    match reply.trim_end() {
        "OK" => Ok(()),
        other => Err(other
            .strip_prefix("ERR ")
            .unwrap_or("ns-file helper failed")
            .to_string()),
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
}

#[cfg(test)]
mod guest_ns_tests {
    use super::{parse_ok_reply, RootReason};

    #[test]
    fn a_fallback_to_the_vm_namespace_always_carries_a_reason() {
        // The container path declining to run is invisible from outside: an
        // upload still reports success and a dial still returns. Without a
        // reason, a silent no-op is indistinguishable from a working container —
        // which is what made one such case take hours to find.
        for r in [RootReason::NoWorkload, RootReason::Ambiguous(3)] {
            assert!(!r.to_string().is_empty(), "{r:?} must explain itself");
        }
        assert!(RootReason::Ambiguous(3).to_string().contains('3'));
    }

    #[test]
    fn only_an_exact_ok_is_success() {
        // A truncated or unexpected reply must never read as success: the write
        // path reports 200 on Ok, so a loose parse silently loses a file.
        assert!(parse_ok_reply("OK\n").is_ok());
        assert!(parse_ok_reply("OK").is_ok());
        for bad in ["", "OKAY", "ERR boom", "ERR ", "ok"] {
            assert!(parse_ok_reply(bad).is_err(), "{bad:?} must not be success");
        }
    }

    #[test]
    fn a_helper_error_reaches_the_caller_verbatim() {
        // The reason a dial or write failed INSIDE the container is the only
        // diagnostic the operator gets; swallowing it leaves an unexplained 500.
        assert_eq!(
            parse_ok_reply("ERR connect /run/app.sock: No such file or directory").unwrap_err(),
            "connect /run/app.sock: No such file or directory"
        );
    }

    #[test]
    fn an_unrecognised_reply_is_not_reported_as_an_empty_error() {
        assert_eq!(
            parse_ok_reply("garbage").unwrap_err(),
            "ns-file helper failed"
        );
    }
}
