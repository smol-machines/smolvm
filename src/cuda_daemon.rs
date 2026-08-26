//! smolvm-managed shared CUDA daemon.
//!
//! One process holding a single GPU context, serving every CUDA VM's proxied
//! connection (see [`crate::cuda_host`]'s proxy path). Because all connections
//! live in this one process, they share the device primary context — which is
//! what lets a forked VM clone reconnect and reuse its golden's device memory.
//!
//! Lifecycle is lazy and self-managing: the first CUDA VM that needs the daemon
//! calls [`ensure_running`], which spawns `smolvm _cuda-daemon <socket>` if the
//! socket isn't already live. The daemon then persists across VMs (it is not
//! tied to any single VM's boot subprocess) until the host shuts down.

use crate::platform::uds::UdsListener;
use smolvm_cuda::host::{serve, serve_with_options, Backend, CpuBackend, GpuBackend, ServeOptions};
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Stable host-device enumeration shared with device-scoped admission.
const CUDA_DEVICE_ORDER: &str = "PCI_BUS_ID";
const CUDA_WORKER_STATUS_SOCKET_ENV: &str = "SMOLVM_CUDA_WORKER_STATUS_SOCKET";
const CUDA_CLONE_RESERVATION_REEXEC_ENV: &str = "SMOLVM_CUDA_CLONE_RESERVATION_REEXEC";
const MAX_CUDA_CLONE_RESERVATION_REEXECS: u8 = 2;
const CLONE_WORKER_READINESS_CAPABILITY_VERSION: u32 = 1;
const CLONE_WORKER_CAPABILITY_FILE: &str = "daemon.capability";

/// Control-socket path for the shared daemon, under the smolvm data dir (so the
/// daemon and every boot subprocess agree on one location).
pub fn socket_path() -> PathBuf {
    let root = std::env::var_os("SMOLVM_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("smolvm"));
    root.join("cuda-daemon.sock")
}

#[cfg(target_os = "linux")]
fn daemon_socket_access(
    effective_uid: u32,
    kvm_gid: Option<libc::gid_t>,
) -> io::Result<(u32, Option<libc::gid_t>)> {
    if effective_uid != 0 {
        return Ok((0o600, None));
    }
    let gid = kvm_gid.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privileged shared CUDA daemon requires a kvm group for isolated VMM access",
        )
    })?;
    Ok((0o660, Some(gid)))
}

#[cfg(target_os = "linux")]
fn current_daemon_socket_access() -> io::Result<(u32, Option<libc::gid_t>)> {
    daemon_socket_access(unsafe { libc::geteuid() }, crate::process::kvm_group_gid())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn current_daemon_socket_access() -> io::Result<(u32, Option<libc::gid_t>)> {
    Ok((0o600, None))
}

#[cfg(unix)]
fn configure_daemon_socket_access(
    sock: &Path,
    mode: u32,
    group: Option<libc::gid_t>,
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    if let Some(gid) = group {
        let path = std::ffi::CString::new(sock.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CUDA daemon socket contains NUL",
            )
        })?;
        if unsafe { libc::chown(path.as_ptr(), u32::MAX, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(mode))
}

#[cfg(unix)]
fn bind_daemon_listener(sock: &Path) -> io::Result<UdsListener> {
    let (mode, group) = current_daemon_socket_access()?;
    // AF_UNIX socket nodes start at 0777 minus umask. Restrict the node during
    // bind/listen itself so an unrelated process cannot queue a connection in
    // the interval before the final ownership update.
    let socket_umask = libc::mode_t::try_from(0o777_u32 & !mode).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid CUDA daemon socket mode",
        )
    })?;
    let old_umask = unsafe { libc::umask(socket_umask) };
    let listener = UdsListener::bind(sock);
    unsafe { libc::umask(old_umask) };
    let listener = listener?;
    configure_daemon_socket_access(sock, mode, group)?;
    Ok(listener)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloneWorkerStatus {
    Ready,
    Failed,
}

fn local_cuda_daemon_socket(explicit: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    match explicit {
        Some(value) => {
            let path = PathBuf::from(value);
            path.is_absolute().then_some(path)
        }
        None => Some(socket_path()),
    }
}

fn clone_worker_status_socket() -> PathBuf {
    std::env::var_os(CUDA_WORKER_STATUS_SOCKET_ENV)
        .and_then(|value| local_cuda_daemon_socket(Some(&value)))
        .or_else(|| {
            std::env::var_os("SMOLVM_CUDA_DAEMON")
                .and_then(|value| local_cuda_daemon_socket(Some(&value)))
        })
        .unwrap_or_else(socket_path)
}

fn clone_worker_status_dir_for(cuda_socket: &Path) -> PathBuf {
    let mut name = cuda_socket
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("cuda-daemon.sock"))
        .to_os_string();
    name.push(".workers");
    cuda_socket
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

fn clone_worker_status_path(vm_pid: u32) -> PathBuf {
    clone_worker_status_dir_for(&clone_worker_status_socket()).join(vm_pid.to_string())
}

fn clone_worker_capability_path(cuda_socket: &Path) -> PathBuf {
    clone_worker_status_dir_for(cuda_socket).join(CLONE_WORKER_CAPABILITY_FILE)
}

fn encode_clone_worker_capability(pid: u32, start_time: u64) -> String {
    format!(
        "{CLONE_WORKER_READINESS_CAPABILITY_VERSION} {pid} {start_time} {:016x}\n",
        smolvm_cuda::PROTO_HASH
    )
}

fn decode_clone_worker_capability(value: &str) -> Option<(u32, u64)> {
    let mut fields = value.split_whitespace();
    let version = fields.next()?.parse::<u32>().ok()?;
    let pid = fields.next()?.parse::<u32>().ok()?;
    let start_time = fields.next()?.parse::<u64>().ok()?;
    let protocol = u64::from_str_radix(fields.next()?, 16).ok()?;
    (fields.next().is_none()
        && version == CLONE_WORKER_READINESS_CAPABILITY_VERSION
        && protocol == smolvm_cuda::PROTO_HASH)
        .then_some((pid, start_time))
}

fn publish_clone_worker_capability(cuda_socket: &Path) -> io::Result<()> {
    let pid = std::process::id();
    let start_time = crate::process::process_start_time(pid as i32).ok_or_else(|| {
        io::Error::other("CUDA daemon process identity is unavailable for worker readiness")
    })?;
    let path = clone_worker_capability_path(cuda_socket);
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("CUDA worker capability path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".daemon.{pid}.tmp"));
    std::fs::write(&temporary, encode_clone_worker_capability(pid, start_time))?;
    if let Err(error) = std::fs::rename(&temporary, &path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn clone_worker_readiness_supported_at(
    cuda_socket: &Path,
    mut process_is_alive: impl FnMut(i32, u64) -> bool,
) -> bool {
    std::fs::read_to_string(clone_worker_capability_path(cuda_socket))
        .ok()
        .and_then(|value| decode_clone_worker_capability(&value))
        .and_then(|(pid, start_time)| i32::try_from(pid).ok().map(|pid| (pid, start_time)))
        .is_some_and(|(pid, start_time)| process_is_alive(pid, start_time))
}

/// Whether the configured daemon can publish host-local clone-worker readiness.
pub(crate) fn clone_worker_readiness_supported() -> bool {
    let explicit = std::env::var_os("SMOLVM_CUDA_DAEMON");
    let Some(cuda_socket) = local_cuda_daemon_socket(explicit.as_deref()) else {
        return false;
    };
    // The managed daemon is always the current binary and preserves the
    // existing fail-closed barrier. Explicit local daemons opt in by publishing
    // a live, protocol-matched capability; remote TCP and legacy daemons do not.
    explicit.is_none()
        || clone_worker_readiness_supported_at(&cuda_socket, |pid, start_time| {
            crate::process::is_our_process_strict(pid, Some(start_time))
        })
}

fn encode_clone_worker_status(start_time: u64, status: CloneWorkerStatus) -> String {
    let status = match status {
        CloneWorkerStatus::Ready => "ready",
        CloneWorkerStatus::Failed => "failed",
    };
    format!("{start_time} {status}\n")
}

fn decode_clone_worker_status(value: &str) -> Option<(u64, CloneWorkerStatus)> {
    let mut fields = value.split_whitespace();
    let start_time = fields.next()?.parse().ok()?;
    let status = match fields.next()? {
        "ready" => CloneWorkerStatus::Ready,
        "failed" => CloneWorkerStatus::Failed,
        _ => return None,
    };
    fields.next().is_none().then_some((start_time, status))
}

fn publish_clone_worker_status(vm_pid: u32, status: CloneWorkerStatus) -> io::Result<()> {
    let start_time = crate::process::process_start_time(vm_pid as i32).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("clone VM process {vm_pid} exited before CUDA worker readiness"),
        )
    })?;
    let path = clone_worker_status_path(vm_pid);
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("CUDA worker status path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{vm_pid}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, encode_clone_worker_status(start_time, status))?;
    if let Err(error) = std::fs::rename(&temporary, &path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn prune_dead_clone_worker_statuses() {
    let Some(directory) = clone_worker_status_path(0).parent().map(Path::to_path_buf) else {
        return;
    };
    prune_dead_clone_worker_statuses_in(&directory);
}

fn prune_dead_clone_worker_statuses_in(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_name() == std::ffi::OsStr::new(CLONE_WORKER_CAPABILITY_FILE) {
            continue;
        }
        // Publication uses a same-directory temporary file so rename is
        // atomic. Do not race that write: only reap a stranded temporary after
        // it is far older than the sub-millisecond publication window.
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with('.'))
        {
            let stale = entry
                .metadata()
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_secs(60));
            if stale {
                let _ = std::fs::remove_file(path);
            }
            continue;
        }
        let live = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .zip(
                std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|value| decode_clone_worker_status(&value))
                    .map(|(started, _)| started),
            )
            .is_some_and(|(pid, started)| {
                crate::process::is_our_process_strict(pid, Some(started))
            });
        if !live {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(crate) fn wait_for_clone_worker_ready(
    vm_pid: i32,
    vm_start_time: u64,
    timeout: Duration,
) -> io::Result<()> {
    let vm_pid_u32 = u32::try_from(vm_pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid clone VM pid"))?;
    let path = clone_worker_status_path(vm_pid_u32);
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::read_to_string(&path) {
            Ok(value) => {
                if let Some((start_time, status)) = decode_clone_worker_status(&value) {
                    if start_time == vm_start_time {
                        let _ = std::fs::remove_file(&path);
                        return match status {
                            CloneWorkerStatus::Ready => Ok(()),
                            CloneWorkerStatus::Failed => Err(io::Error::other(
                                "CUDA clone worker failed during reconstruction",
                            )),
                        };
                    }
                    let _ = std::fs::remove_file(&path);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if !crate::process::is_our_process_strict(vm_pid, Some(vm_start_time)) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "clone VM exited before its CUDA worker became ready",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "CUDA clone worker did not become ready within {}s",
                    timeout.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

const TENSOR_PUBLISH_MAGIC: [u8; 4] = *b"TBP1";
const TENSOR_CONSUME_MAGIC: [u8; 4] = *b"TBC1";
const TENSOR_RESPONSE_MAGIC: [u8; 4] = *b"TBR1";
const MAX_TENSOR_BUNDLE_METADATA: usize = (2 << 20) + 64;
const MAX_PENDING_TENSOR_BUNDLES: usize = 64;
const MAX_PENDING_TENSOR_BYTES: u64 = 32 << 30;
const DEFAULT_TENSOR_BUNDLE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_TENSOR_BUNDLE_TTL_SECS: u64 = 60 * 60;
static TENSOR_BUNDLE_SERVICE_READY: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
const MAX_MODULE_HANDOFF_BLOB_BYTES: u64 = 32 << 30;
#[cfg(unix)]
const EXTERNAL_MODULE_IMAGES_MAGIC: [u8; 4] = *b"MHI2";

#[derive(Debug)]
struct PendingTensorBundle {
    allocation: OwnedFd,
    allocation_size: u64,
    metadata: Vec<u8>,
    created: Instant,
}

fn pending_tensor_bundles(
) -> &'static Mutex<std::collections::HashMap<Vec<u8>, PendingTensorBundle>> {
    static BUNDLES: OnceLock<Mutex<std::collections::HashMap<Vec<u8>, PendingTensorBundle>>> =
        OnceLock::new();
    BUNDLES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn tensor_bundle_ttl_from(value: Option<&str>) -> Duration {
    value
        .map(str::trim)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=MAX_TENSOR_BUNDLE_TTL_SECS).contains(seconds))
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_TENSOR_BUNDLE_TTL)
}

fn tensor_bundle_ttl() -> Duration {
    static TTL: OnceLock<Duration> = OnceLock::new();
    *TTL.get_or_init(|| {
        tensor_bundle_ttl_from(
            std::env::var("SMOLVM_CUDA_TENSOR_BUNDLE_TTL_SECS")
                .ok()
                .as_deref(),
        )
    })
}

fn tensor_bundle_socket_path(cuda_socket: &Path) -> PathBuf {
    PathBuf::from(format!("{}.tensors", cuda_socket.display()))
}

/// One immutable device allocation redeemed from a clone worker publication.
///
/// The descriptor is owned by the caller. Dropping it releases only this
/// process's reference; a descriptor already transferred with `SCM_RIGHTS`
/// remains valid in the receiving process.
#[cfg(target_os = "linux")]
pub(crate) struct RedeemedTensorBundle {
    pub(crate) allocation: OwnedFd,
    pub(crate) allocation_size: u64,
    pub(crate) metadata: Vec<u8>,
}

fn prune_tensor_bundles(
    bundles: &mut std::collections::HashMap<Vec<u8>, PendingTensorBundle>,
    now: Instant,
) {
    bundles.retain(|_, bundle| now.duration_since(bundle.created) < tensor_bundle_ttl());
}

fn pending_tensor_bytes(bundles: &std::collections::HashMap<Vec<u8>, PendingTensorBundle>) -> u64 {
    bundles.values().map(|bundle| bundle.allocation_size).sum()
}

fn fresh_tensor_token() -> io::Result<Vec<u8>> {
    let mut token = vec![0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut token)?;
    Ok(token)
}

fn encode_tensor_bundle_metadata(bundle: &smolvm_cuda::host::DeviceTensorBundle) -> Vec<u8> {
    let mut metadata = Vec::with_capacity(8 + bundle.manifest.len() + bundle.tensors.len() * 16);
    metadata.extend_from_slice(&(bundle.manifest.len() as u32).to_le_bytes());
    metadata.extend_from_slice(&(bundle.tensors.len() as u32).to_le_bytes());
    metadata.extend_from_slice(&bundle.manifest);
    for tensor in &bundle.tensors {
        metadata.extend_from_slice(&tensor.offset.to_le_bytes());
        metadata.extend_from_slice(&tensor.size.to_le_bytes());
    }
    metadata
}

fn validate_tensor_bundle_metadata(metadata: &[u8], allocation_size: u64) -> io::Result<()> {
    if metadata.len() < 8 || metadata.len() > MAX_TENSOR_BUNDLE_METADATA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tensor-bundle metadata length",
        ));
    }
    let manifest_len = u32::from_le_bytes(metadata[0..4].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(metadata[4..8].try_into().unwrap()) as usize;
    let expected = 8usize
        .checked_add(manifest_len)
        .and_then(|size| size.checked_add(count.checked_mul(16)?))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "metadata overflow"))?;
    if expected != metadata.len() || manifest_len > 1 << 20 || count == 0 || count > 65_536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inconsistent tensor-bundle metadata",
        ));
    }
    let mut prior_end = 0u64;
    for tensor in metadata[8 + manifest_len..].as_chunks::<16>().0 {
        let offset = u64::from_le_bytes(tensor[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(tensor[8..16].try_into().unwrap());
        let end = offset
            .checked_add(size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "tensor range overflow"))?;
        if size == 0 || offset != prior_end || end > allocation_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tensor range falls outside its allocation",
            ));
        }
        prior_end = end;
    }
    Ok(())
}

fn send_fd_header(stream: &UnixStream, fd: i32, header: &[u8; 16]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: header.as_ptr() as *mut libc::c_void,
        iov_len: header.len(),
    };
    // SAFETY: standard sendmsg with one immutable header and one owned fd. The
    // receiving process gets its own descriptor reference through SCM_RIGHTS.
    unsafe {
        let mut cmsgbuf = [0u8; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping((&fd as *const i32).cast::<u8>(), libc::CMSG_DATA(cmsg), 4);
        let sent = libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != header.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short tensor-bundle control header",
            ));
        }
    }
    Ok(())
}

fn recv_fd_header(stream: &mut UnixStream) -> io::Result<Option<(OwnedFd, [u8; 16])>> {
    let mut header = [0u8; 16];
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    // SAFETY: recvmsg writes within the fixed header/control buffers. A valid
    // SCM_RIGHTS message transfers ownership of exactly one descriptor.
    let (received, fd) = unsafe {
        let mut cmsgbuf = [0u8; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        let received = libc::recvmsg(stream.as_raw_fd(), &mut msg, flags);
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received == 0 {
            return Ok(None);
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || msg.msg_flags & libc::MSG_CTRUNC != 0
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_len as usize != libc::CMSG_LEN(4) as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tensor-bundle message did not contain one fd",
            ));
        }
        let mut fd = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), (&mut fd as *mut i32).cast(), 4);
        (received as usize, fd)
    };
    if received < header.len() {
        stream.read_exact(&mut header[received..])?;
    }
    // SAFETY: SCM_RIGHTS returned a new descriptor owned by this process.
    Ok(Some((unsafe { OwnedFd::from_raw_fd(fd) }, header)))
}

fn send_tensor_bundle_to_parent(
    stream: &mut UnixStream,
    bundle: smolvm_cuda::host::DeviceTensorBundle,
) -> smolvm_cuda::host::CuResult<Vec<u8>> {
    let channel_error = |stage: &'static str, error: io::Error| {
        tracing::warn!(%error, stage, "tensor-bundle publication channel failed");
        999
    };
    let metadata = encode_tensor_bundle_metadata(&bundle);
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&TENSOR_PUBLISH_MAGIC);
    header[4..8].copy_from_slice(&(metadata.len() as u32).to_le_bytes());
    header[8..16].copy_from_slice(&bundle.allocation_size.to_le_bytes());
    send_fd_header(stream, bundle.allocation.as_raw_fd(), &header)
        .map_err(|error| channel_error("descriptor", error))?;
    stream
        .write_all(&metadata)
        .map_err(|error| channel_error("metadata", error))?;
    let mut ack = [0u8; 8];
    stream
        .read_exact(&mut ack)
        .map_err(|error| channel_error("acknowledgement", error))?;
    let status = i32::from_le_bytes(ack[..4].try_into().unwrap());
    let token_len = u32::from_le_bytes(ack[4..].try_into().unwrap()) as usize;
    if status != 0 {
        return Err(status);
    }
    if token_len == 0 || token_len > 256 {
        return Err(999);
    }
    let mut token = vec![0u8; token_len];
    stream
        .read_exact(&mut token)
        .map_err(|error| channel_error("token", error))?;
    Ok(token)
}

fn tensor_bundle_receiver(mut stream: UnixStream, worker_pid: u32) {
    loop {
        let received = match recv_fd_header(&mut stream) {
            Ok(Some(received)) => received,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, worker_pid, "tensor-bundle worker channel ended");
                break;
            }
        };
        let (allocation, header) = received;
        let mut status = 0i32;
        let mut token = Vec::new();
        let mut close_after_ack = false;
        let metadata_len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let allocation_size = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let mut metadata = vec![0u8; metadata_len.min(MAX_TENSOR_BUNDLE_METADATA)];
        if header[..4] != TENSOR_PUBLISH_MAGIC
            || metadata_len == 0
            || metadata_len > MAX_TENSOR_BUNDLE_METADATA
            || allocation_size == 0
        {
            status = 1;
            close_after_ack = true;
        } else if stream.read_exact(&mut metadata).is_err() {
            status = 999;
            close_after_ack = true;
        } else if validate_tensor_bundle_metadata(&metadata, allocation_size).is_err() {
            status = 1;
        } else {
            let mut bundles = pending_tensor_bundles().lock().unwrap();
            prune_tensor_bundles(&mut bundles, Instant::now());
            let capacity_available = bundles.len() < MAX_PENDING_TENSOR_BUNDLES
                && pending_tensor_bytes(&bundles)
                    .checked_add(allocation_size)
                    .is_some_and(|total| total <= MAX_PENDING_TENSOR_BYTES);
            if !capacity_available {
                status = 2;
            } else {
                for _ in 0..4 {
                    match fresh_tensor_token() {
                        Ok(candidate) if !bundles.contains_key(&candidate) => {
                            token = candidate;
                            break;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                if token.is_empty() {
                    status = 999;
                } else {
                    bundles.insert(
                        token.clone(),
                        PendingTensorBundle {
                            allocation,
                            allocation_size,
                            metadata,
                            created: Instant::now(),
                        },
                    );
                }
            }
        }
        let mut ack = [0u8; 8];
        ack[..4].copy_from_slice(&status.to_le_bytes());
        ack[4..].copy_from_slice(&(token.len() as u32).to_le_bytes());
        if stream.write_all(&ack).is_err()
            || (!token.is_empty() && stream.write_all(&token).is_err())
            || close_after_ack
        {
            if !token.is_empty() {
                pending_tensor_bundles().lock().unwrap().remove(&token);
            }
            break;
        }
    }
}

fn spawn_tensor_bundle_receiver(stream: UnixStream, worker_pid: u32) -> io::Result<()> {
    thread::Builder::new()
        .name(format!("cuda-tensor-publisher-{worker_pid}"))
        .spawn(move || tensor_bundle_receiver(stream, worker_pid))?;
    Ok(())
}

fn send_tensor_bundle_to_consumer(
    stream: &mut UnixStream,
    bundle: &PendingTensorBundle,
) -> io::Result<()> {
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&TENSOR_RESPONSE_MAGIC);
    header[4..8].copy_from_slice(&(bundle.metadata.len() as u32).to_le_bytes());
    header[8..16].copy_from_slice(&bundle.allocation_size.to_le_bytes());
    send_fd_header(stream, bundle.allocation.as_raw_fd(), &header)?;
    stream.write_all(&bundle.metadata)
}

fn serve_tensor_bundle_consumer(mut stream: UnixStream) -> io::Result<()> {
    let mut header = [0u8; 6];
    stream.read_exact(&mut header)?;
    if header[..4] != TENSOR_CONSUME_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tensor-bundle consume request",
        ));
    }
    let token_len = u16::from_le_bytes(header[4..6].try_into().unwrap()) as usize;
    if token_len == 0 || token_len > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tensor-bundle token length",
        ));
    }
    let mut token = vec![0u8; token_len];
    stream.read_exact(&mut token)?;
    let bundle = {
        let mut bundles = pending_tensor_bundles().lock().unwrap();
        prune_tensor_bundles(&mut bundles, Instant::now());
        bundles.remove(&token)
    }
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tensor bundle expired"))?;
    // Once SCM_RIGHTS starts, the receiver may own a descriptor even when a
    // later metadata write fails. Never restore the token and risk two
    // consumers observing one supposedly one-use publication.
    send_tensor_bundle_to_consumer(&mut stream, &bundle)
}

#[cfg(target_os = "linux")]
fn redeem_tensor_bundle_from_stream(
    mut stream: UnixStream,
    token: &[u8],
) -> io::Result<RedeemedTensorBundle> {
    if token.is_empty() || token.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tensor-bundle token length",
        ));
    }
    stream.write_all(&TENSOR_CONSUME_MAGIC)?;
    stream.write_all(&(token.len() as u16).to_le_bytes())?;
    stream.write_all(token)?;
    let (allocation, header) = recv_fd_header(&mut stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "tensor-bundle service closed without a response",
        )
    })?;
    if header[..4] != TENSOR_RESPONSE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tensor-bundle response",
        ));
    }
    let metadata_len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    let allocation_size = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if metadata_len == 0 || metadata_len > MAX_TENSOR_BUNDLE_METADATA || allocation_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tensor-bundle response dimensions",
        ));
    }
    let mut metadata = vec![0u8; metadata_len];
    stream.read_exact(&mut metadata)?;
    validate_tensor_bundle_metadata(&metadata, allocation_size)?;
    Ok(RedeemedTensorBundle {
        allocation,
        allocation_size,
        metadata,
    })
}

/// Redeem a clone worker's random one-use publication token into an owned GPU
/// allocation. This is intentionally crate-private: only smolvm's managed
/// rollout executor may cross the daemon's bearer-token boundary.
#[cfg(target_os = "linux")]
pub(crate) fn redeem_tensor_bundle(token: &[u8]) -> io::Result<RedeemedTensorBundle> {
    let stream = UnixStream::connect(tensor_bundle_socket_path(&socket_path()))?;
    redeem_tensor_bundle_from_stream(stream, token)
}

fn spawn_tensor_bundle_service(cuda_socket: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = tensor_bundle_socket_path(cuda_socket);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let service_path = path.clone();
    thread::Builder::new()
        .name("cuda-tensor-consumer".into())
        .spawn(move || {
            for connection in listener.incoming() {
                match connection {
                    Ok(stream) => {
                        let _ = thread::Builder::new()
                            .name("cuda-tensor-consume".into())
                            .spawn(move || {
                                if let Err(error) = serve_tensor_bundle_consumer(stream) {
                                    tracing::debug!(%error, "tensor-bundle consume failed");
                                }
                            });
                    }
                    Err(error) => {
                        tracing::debug!(%error, "tensor-bundle listener ended");
                        break;
                    }
                }
            }
        })?;
    thread::Builder::new()
        .name("cuda-tensor-reaper".into())
        .spawn(|| loop {
            thread::sleep(Duration::from_secs(5));
            let mut bundles = pending_tensor_bundles().lock().unwrap();
            prune_tensor_bundles(&mut bundles, Instant::now());
        })?;
    Ok(service_path)
}

/// Pure policy helper for the managed MPS default.
///
/// Fork-worker pools opt in automatically because that is the configuration in
/// which separate clone contexts contend for GPU scheduling. An explicit value
/// always wins, including opt-in for a manually started shared daemon.
#[cfg(target_os = "linux")]
fn mps_enabled(mode: Option<&str>, fork_workers: bool) -> bool {
    match mode.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("0" | "off" | "false" | "no") => false,
        Some("1" | "on" | "true" | "yes" | "force") => true,
        Some(_) => fork_workers,
        None => fork_workers,
    }
}

/// Frozen fork pools can release the golden's CUDA context after every initial
/// worker is resident. The host snapshot is automatic for pools; the explicit
/// setting is a rollback switch, not an opt-in requirement.
fn golden_eviction_enabled(mode: Option<&str>, fork_pool_size: Option<u32>) -> bool {
    let pool_enabled = fork_pool_size.is_some_and(|size| size > 0);
    match mode.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("0" | "off" | "false" | "no") => false,
        Some("1" | "on" | "true" | "yes" | "force") => pool_enabled,
        Some(_) | None => pool_enabled,
    }
}

fn fork_snapshot_enabled(golden_eviction: bool, share_weights: bool) -> bool {
    golden_eviction || share_weights
}

#[cfg(target_os = "linux")]
fn host_snapshot_fits(required: u64, meminfo: &str) -> bool {
    let available_kib = meminfo.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == "MemAvailable:")
            .then(|| fields.next()?.parse::<u64>().ok())
            .flatten()
    });
    let Some(available) = available_kib.and_then(|kib| kib.checked_mul(1024)) else {
        return false;
    };
    // Leave meaningful room for the host, VMs, and page cache. The snapshot is
    // anonymous memory and must not turn a GPU-density optimization into host
    // memory pressure.
    let reserve = (required / 4).max(1 << 30);
    required
        .checked_add(reserve)
        .is_some_and(|needed| needed <= available)
}

#[cfg(target_os = "linux")]
fn host_snapshot_capacity_available(required: u64) -> bool {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .is_some_and(|meminfo| host_snapshot_fits(required, &meminfo))
}

fn host_snapshot_reconstructable(vmm_maps: usize, ordinary_allocs: usize) -> bool {
    // Both paths restore at the golden virtual addresses. Ordinary CUDA
    // allocations previously relied on RPC-boundary pointer translation, which
    // could not repair embedded device pointers or TMA descriptors and made an
    // ordinary-only snapshot unsafe. Exact-address VMM backing removes that
    // distinction, so either memory class can durably own the frozen state.
    vmm_maps > 0 || ordinary_allocs > 0
}

#[cfg(target_os = "linux")]
fn mps_control_binary() -> std::ffi::OsString {
    std::env::var_os("SMOLVM_CUDA_MPS_CONTROL").unwrap_or_else(|| "nvidia-cuda-mps-control".into())
}

/// The daemon keeps this channel open for its lifetime. The supervisor owns the
/// other end and shuts down only the private MPS controller it started when it
/// observes EOF, including daemon SIGKILL, crash, or `process::exit`.
#[cfg(target_os = "linux")]
struct MpsOwnership {
    _lifecycle: UnixStream,
}

/// Remove only the controller artifacts that NVIDIA may create inside
/// smolvm's private, PID-scoped directories. Directory removal is deliberately
/// non-recursive: an unexpected entry is preserved instead of being deleted.
#[cfg(target_os = "linux")]
fn cleanup_private_mps_paths() {
    if let Some(pipe) = std::env::var_os("CUDA_MPS_PIPE_DIRECTORY") {
        let pipe = PathBuf::from(pipe);
        for name in [
            "control",
            "control_privileged",
            "control_lock",
            "log",
            "nvidia-cuda-mps-control.pid",
        ] {
            let _ = std::fs::remove_file(pipe.join(name));
        }
        let _ = std::fs::remove_dir(pipe);
    }

    if let Some(logs) = std::env::var_os("CUDA_MPS_LOG_DIRECTORY") {
        let logs = PathBuf::from(logs);
        for name in ["control.log", "server.log"] {
            let _ = std::fs::remove_file(logs.join(name));
        }
        let _ = std::fs::remove_dir(logs);
    }
}

#[cfg(target_os = "linux")]
fn create_private_mps_paths(pipe: &Path, log_root: &Path, logs: &Path) -> io::Result<()> {
    std::fs::create_dir_all(log_root)?;

    // Refuse a PID-path collision instead of adopting or cleaning an existing
    // directory. That keeps the ownership guarantee true even after PID reuse.
    std::fs::create_dir(pipe)?;
    if let Err(e) = std::fs::create_dir(logs) {
        let _ = std::fs::remove_dir(pipe);
        return Err(e);
    }

    use std::os::unix::fs::PermissionsExt as _;
    for dir in [pipe, logs] {
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            let _ = std::fs::remove_dir(logs);
            let _ = std::fs::remove_dir(pipe);
            return Err(e);
        }
    }
    Ok(())
}

/// Start a private, uncapped NVIDIA MPS controller before this process loads
/// libcuda. Failure is deliberately non-fatal: with no live controller the
/// NVIDIA driver uses ordinary contexts, which is the existing safe path.
#[cfg(target_os = "linux")]
fn start_managed_mps(sock: &Path) -> Option<MpsOwnership> {
    let fork_workers = std::env::var_os("SMOLVM_CUDA_FORK_WORKERS").is_some();
    let mode = std::env::var("SMOLVM_CUDA_MPS").ok();
    if !mps_enabled(mode.as_deref(), fork_workers) {
        tracing::info!("cuda-daemon: managed NVIDIA MPS disabled");
        return None;
    }

    // An explicit pipe directory is externally owned. Use it but never start,
    // stop, or otherwise mutate that controller.
    if let Some(pipe) = std::env::var_os("CUDA_MPS_PIPE_DIRECTORY") {
        tracing::info!(
            pipe = %PathBuf::from(pipe).display(),
            "cuda-daemon: using externally managed NVIDIA MPS"
        );
        return None;
    }

    let uid = unsafe { libc::geteuid() };
    let pid = std::process::id();
    let pipe_dir = std::env::temp_dir().join(format!("smolvm-mps-{uid}-{pid}"));
    let log_root = sock
        .parent()
        .unwrap_or_else(|| Path::new("/tmp"))
        .join("cuda-mps-logs");
    let log_dir = log_root.join(pid.to_string());
    if let Err(e) = create_private_mps_paths(&pipe_dir, &log_root, &log_dir) {
        tracing::warn!(
            pipe = %pipe_dir.display(),
            logs = %log_dir.display(),
            error = %e,
            "cuda-daemon: cannot create private MPS directories; using ordinary contexts"
        );
        return None;
    }

    // This is an internal daemon subcommand at single-threaded startup, before
    // any CUDA backend or worker thread exists. The variables must be in this
    // process so every subsequently spawned clone worker inherits the same MPS
    // endpoint.
    unsafe {
        std::env::set_var("CUDA_MPS_PIPE_DIRECTORY", &pipe_dir);
        std::env::set_var("CUDA_MPS_LOG_DIRECTORY", &log_dir);
    }

    let (mut daemon_end, supervisor_end) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, "cuda-daemon: MPS lifecycle channel failed");
            cleanup_private_mps_paths();
            unsafe {
                std::env::remove_var("CUDA_MPS_PIPE_DIRECTORY");
                std::env::remove_var("CUDA_MPS_LOG_DIRECTORY");
            }
            return None;
        }
    };
    let _ = daemon_end.set_read_timeout(Some(Duration::from_secs(10)));

    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let supervisor_fd = supervisor_end.as_raw_fd();
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            tracing::warn!(error = %e, "cuda-daemon: cannot locate MPS supervisor");
            cleanup_private_mps_paths();
            unsafe {
                std::env::remove_var("CUDA_MPS_PIPE_DIRECTORY");
                std::env::remove_var("CUDA_MPS_LOG_DIRECTORY");
            }
            return None;
        }
    };
    let mut cmd = Command::new(exe);
    cmd.args(["_cuda-mps-supervisor", "3"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // A separate process group is essential: the daemon's SIGTERM handler
        // kills its own group (daemon + clone workers). The supervisor must
        // survive long enough to observe EOF and send `quit` to MPS.
        .process_group(0);
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(supervisor_fd, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if let Err(e) = cmd.spawn() {
        tracing::warn!(
            error = %e,
            "cuda-daemon: cannot spawn MPS supervisor; using ordinary contexts"
        );
        cleanup_private_mps_paths();
        unsafe {
            std::env::remove_var("CUDA_MPS_PIPE_DIRECTORY");
            std::env::remove_var("CUDA_MPS_LOG_DIRECTORY");
        }
        return None;
    }
    drop(supervisor_end);

    use std::io::Read as _;
    let mut ready = [0u8; 1];
    if daemon_end.read_exact(&mut ready).is_err() || ready[0] != 1 {
        tracing::warn!("cuda-daemon: NVIDIA MPS unavailable; falling back to ordinary contexts");
        drop(daemon_end);
        unsafe {
            std::env::remove_var("CUDA_MPS_PIPE_DIRECTORY");
            std::env::remove_var("CUDA_MPS_LOG_DIRECTORY");
        }
        return None;
    }

    tracing::info!(
        pipe = %pipe_dir.display(),
        logs = %log_dir.display(),
        "cuda-daemon: private uncapped NVIDIA MPS active"
    );
    Some(MpsOwnership {
        _lifecycle: daemon_end,
    })
}

/// Hidden supervisor entry point. It starts one controller in the private pipe
/// directory inherited from the daemon, reports readiness over `fd`, and then
/// blocks until the daemon closes its channel. It never quits a controller it
/// did not successfully start.
#[cfg(target_os = "linux")]
pub fn run_mps_supervisor(fd: i32) -> io::Result<()> {
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd as _;

    // SAFETY: the daemon handed this process an owned dup of its UnixStream at
    // exactly `fd`; this function is the sole owner in the exec'd supervisor.
    let mut lifecycle = unsafe { UnixStream::from_raw_fd(fd) };
    let started = Command::new(mps_control_binary())
        .arg("-d")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    let _ = lifecycle.write_all(&[u8::from(started)]);
    if !started {
        cleanup_private_mps_paths();
        return Ok(());
    }

    // No messages are expected. EOF is the lifecycle signal and is guaranteed
    // by the kernel even when the parent is killed without running destructors.
    let mut discard = [0u8; 64];
    while lifecycle.read(&mut discard)? != 0 {}

    let mut stop = Command::new(mps_control_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = stop.stdin.take() {
        let _ = stdin.write_all(b"quit\n");
    }
    let _ = stop.wait();

    // NVIDIA leaves control nodes behind after a graceful quit. It also keeps
    // per-controller logs that would otherwise accumulate across daemon
    // restarts, so reclaim both private PID-scoped directories.
    cleanup_private_mps_paths();
    Ok(())
}

/// True if a daemon is already listening on `sock` (a probe connect succeeds).
fn is_alive(sock: &Path) -> bool {
    UnixStream::connect(sock).is_ok()
}

/// How long the daemon may sit with ZERO open connections before it exits and
/// releases the GPU context. `None` (env set to `0`) disables the timeout.
///
/// Counting open connections, clone workers, and retained golden snapshots
/// makes this fork-safe: a frozen golden remains represented after its CUDA
/// channels are intentionally evicted, so the daemon stays available for later
/// pool replenishment until that golden VM exits.
fn idle_timeout() -> Option<Duration> {
    let secs = std::env::var("SMOLVM_CUDA_DAEMON_IDLE_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(300);
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Exit the process once `active` has been 0 for `timeout`. Polls slowly (the
/// timeout is coarse) and resets the idle clock whenever CUDA state is live.
fn spawn_idle_watchdog(active: Arc<AtomicUsize>, timeout: Duration) {
    thread::Builder::new()
        .name("cuda-daemon-idle".into())
        .spawn(move || {
            let mut idle_since = Instant::now();
            loop {
                thread::sleep(Duration::from_secs(5));
                #[cfg(unix)]
                prune_dead_metadata_layout_waiters();
                let live_workers = live_clone_worker_count();
                #[cfg(unix)]
                let live_snapshots = live_host_snapshot_count();
                #[cfg(not(unix))]
                let live_snapshots = 0;
                if daemon_has_live_cuda_clients(
                    active.load(Ordering::SeqCst),
                    live_workers,
                    live_snapshots,
                ) {
                    idle_since = Instant::now();
                } else if idle_since.elapsed() >= timeout {
                    tracing::info!(
                        timeout_secs = timeout.as_secs(),
                        "shared CUDA daemon idle with no connections — exiting"
                    );
                    std::process::exit(0);
                }
            }
        })
        .ok();
}

/// Reap dead clone-worker children so they don't accumulate as zombies. The
/// daemon forks a worker per clone; the reconnect path reaps a worker only if
/// that clone reconnects (see route_clone_connection), but a worker that dies
/// at teardown — including the teardown SIGSEGV — with no reconnect was never
/// waited on and became a zombie. Over a long run these fill the process table
/// (observed: 288 `<defunct>` after ~42 fork cycles), risking PID exhaustion
/// and fork failures that slow clone startup. A background reaper drains all
/// exited children; it coexists with the targeted reconnect reap (whichever
/// waits first wins; the other simply sees the child already gone).
#[cfg(unix)]
fn spawn_child_reaper() {
    thread::Builder::new()
        .name("cuda-daemon-reaper".into())
        .spawn(|| loop {
            // Drain every exited child without blocking.
            loop {
                let mut status: libc::c_int = 0;
                // SAFETY: WNOHANG waitpid(-1) on our own children; never blocks.
                let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                // 0 = children exist but none exited yet; <=0 (incl. -1/ECHILD
                // when there are no children) = nothing to reap right now.
                if r <= 0 {
                    break;
                }
            }
            // Snapshot cleanup must not depend on the optional idle watchdog.
            // Long-lived daemons use IDLE_SECS=0, but their completed fork
            // lineages must still release retained descriptors and metadata.
            prune_dead_metadata_layout_waiters();
            prune_dead_clone_worker_statuses();
            let _ = live_clone_worker_count();
            let _ = live_host_snapshot_count();
            thread::sleep(Duration::from_secs(2));
        })
        .ok();
}

#[cfg(not(unix))]
fn spawn_child_reaper() {}

/// Sweep clone-worker processes left behind by a PRIOR daemon that died without
/// reaping them (crash or SIGKILL — neither runs the clean-shutdown handler).
/// Called at startup ONLY when no live daemon answers the socket, so any process
/// still running `_cuda-clone-worker` is orphaned and is pinning a GPU context;
/// killing it lets the next golden's CUDA init proceed cleanly. Identifies
/// workers by argv (NUL-separated `/proc/<pid>/cmdline`) rather than a registry,
/// so it catches workers from a daemon instance that is already gone.
#[cfg(unix)]
fn reap_orphan_workers() {
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut killed = 0u32;
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid as u32 == me {
            continue;
        }
        let Ok(cmdline) = std::fs::read(ent.path().join("cmdline")) else {
            continue;
        };
        if cmdline
            .split(|&b| b == 0)
            .any(|arg| arg == b"_cuda-clone-worker")
        {
            // SAFETY: kill(pid, SIGKILL) on a process we identified by argv as an
            // orphaned clone worker; the daemon that parented it is already gone.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            killed += 1;
        }
    }
    if killed > 0 {
        tracing::warn!(
            count = killed,
            "swept orphaned clone-worker(s) from a dead prior daemon"
        );
        // Let the driver release the killed workers' GPU contexts before we serve.
        thread::sleep(Duration::from_millis(500));
    }
}

/// Install a clean-shutdown handler for SIGTERM/SIGINT: unlink the control
/// socket and SIGKILL our own process group (this daemon + its clone workers),
/// so a `pkill`/`kill` of the daemon never leaves GPU-pinning workers or a stale
/// socket node behind. Without this a killed daemon orphaned its workers and the
/// next golden's CUDA init stalled on their lingering context.
#[cfg(unix)]
fn install_shutdown_handler(sock: &Path) {
    use std::os::unix::ffi::OsStrExt;
    static SOCK_C: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    let _ = SOCK_C.set(std::ffi::CString::new(sock.as_os_str().as_bytes()).unwrap_or_default());
    unsafe extern "C" fn on_term(_sig: libc::c_int) {
        // async-signal-safe only: OnceLock::get (atomic load) + unlink + getpgrp
        // + getpid + kill + _exit.
        if let Some(c) = SOCK_C.get() {
            unsafe {
                libc::unlink(c.as_ptr());
            }
        }
        // Only group-kill when we actually lead our own group — never nuke the
        // shell/ssh that launched us if setpgid(0, 0) did not take.
        if unsafe { libc::getpgrp() } == unsafe { libc::getpid() } {
            unsafe {
                libc::kill(0, libc::SIGKILL);
            }
        }
        unsafe {
            libc::_exit(0);
        }
    }
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: installing a handler that only unlinks + group-kills + _exits.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_term as *const () as usize;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Run the daemon body: bind `sock` and serve every connection in its own
/// thread against a fresh backend — all in this process, so they share one GPU
/// context. Returns only on listener failure; otherwise exits via the idle
/// watchdog (or runs until the host shuts down when the timeout is disabled).
/// Fatal-signal backtrace: the daemon and its clone workers host large unsafe
/// surfaces (the CUDA driver itself, raw-pointer translation, IPC mappings). A
/// SIGSEGV/SIGABRT/SIGBUS here previously died SILENTLY — a daemon segfault
/// under concurrent 7B vLLM engines left a 933-byte log and no evidence. The
/// handler writes the signal and a native backtrace to stderr (async-signal-
/// unsafe in principle, but we are crashing anyway — best-effort output beats
/// none) and then re-raises with the default action so wait() sees the truth.
#[cfg(unix)]
pub(crate) fn install_crash_handler(role: &'static str) {
    static ROLE: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    let _ = ROLE.set(role);
    unsafe extern "C" fn on_fatal(sig: libc::c_int) {
        use std::sync::atomic::{AtomicBool, Ordering};
        // A fault raised while already handling one (the capture itself
        // faulted — e.g. the original crash was inside malloc and the
        // allocating Backtrace deadlocked or re-crashed) must not recurse:
        // go straight to the default action so the process dies and dumps.
        static IN_HANDLER: AtomicBool = AtomicBool::new(false);
        if IN_HANDLER.swap(true, Ordering::SeqCst) {
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
            return;
        }
        // If the capture deadlocks (malloc lock held by the faulting thread),
        // SIGALRM's default action ends the process instead of wedging the
        // worker forever ("FATAL signal 11; backtrace:" with no frames).
        unsafe { libc::alarm(5) };
        let role = ROLE.get().copied().unwrap_or("cuda-proc");
        eprintln!("[{role}] FATAL signal {sig}; backtrace:");
        smolvm_cuda::host::op_ring_dump();
        eprintln!("{}", std::backtrace::Backtrace::force_capture());
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
    // A stack-overflow SIGSEGV cannot run its handler on the overflowed
    // stack; SA_ONSTACK only helps if an alternate stack is registered on
    // the thread. Best-effort: register one for this (installing) thread.
    unsafe {
        static mut ALT_STACK: [u8; 256 * 1024] = [0; 256 * 1024];
        let ss = libc::stack_t {
            ss_sp: std::ptr::addr_of_mut!(ALT_STACK) as *mut libc::c_void,
            ss_flags: 0,
            ss_size: 256 * 1024,
        };
        libc::sigaltstack(&ss, std::ptr::null_mut());
    }
    for sig in [libc::SIGSEGV, libc::SIGABRT, libc::SIGBUS, libc::SIGILL] {
        // SAFETY: installing a handler that only formats + re-raises.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_fatal as *const () as usize;
            sa.sa_flags = libc::SA_ONSTACK;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Serve the shared CUDA daemon on `sock` (spawned as `smolvm _cuda-daemon`).
pub fn run(sock: &Path) -> io::Result<()> {
    // Admission maps logical CUDA ordinals to NVML devices without loading
    // libcuda in the control plane. Pinning the daemon to PCI order makes that
    // mapping deterministic while still honoring CUDA_VISIBLE_DEVICES order.
    std::env::set_var("CUDA_DEVICE_ORDER", CUDA_DEVICE_ORDER);
    // Clone workers inherit this exact bound path. An explicit daemon can live
    // outside SMOLVM_DATA_DIR, so deriving readiness files from the default
    // socket would make the control plane wait in the wrong directory.
    std::env::set_var(CUDA_WORKER_STATUS_SOCKET_ENV, sock);
    // Become our own process-group leader so a clean-shutdown signal can take the
    // whole group (this daemon + its clone workers) down together without ever
    // touching the shell/ssh session that launched us. The `ensure_running` spawn
    // path already sets this at fork; this also covers a direct `_cuda-daemon &`.
    // SAFETY: setpgid(0, 0) on self; harmless best-effort (ignore EPERM if we are
    // already a session leader).
    #[cfg(unix)]
    unsafe {
        libc::setpgid(0, 0);
    }
    #[cfg(unix)]
    install_crash_handler("cuda-daemon");
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Refuse to double-bind: a live daemon on this socket already owns the GPU.
    // Clobbering its socket node would orphan it (still holding the GPU context)
    // and split state across two daemons — the "new golden hangs forever" bug.
    if is_alive(sock) {
        tracing::warn!(socket = %sock.display(),
            "a CUDA daemon already owns this socket; not starting a second one");
        return Ok(());
    }
    // No live daemon answered, but a prior one may have died (crash / SIGKILL)
    // without reaping its clone-worker children. Those workers still pin the GPU
    // context, so the next golden's CUDA init stalls on it. Sweep them before we
    // bind — this is the self-heal for stale post-fork daemon/IPC state.
    #[cfg(unix)]
    reap_orphan_workers();
    // Drop any stale socket node, then arm the clean-shutdown handler (unlink the
    // socket + take the process group down on SIGTERM/SIGINT) so a `pkill` of the
    // daemon never leaks workers or a stale socket node.
    let _ = std::fs::remove_file(sock);
    #[cfg(unix)]
    install_shutdown_handler(sock);
    #[cfg(unix)]
    let listener = bind_daemon_listener(sock)?;
    #[cfg(not(unix))]
    let listener = UdsListener::bind(sock)?;
    // Per-VM uid isolation deliberately gives every VMM a distinct uid while
    // retaining only the shared kvm supplementary group. Grant that group
    // access to the daemon boundary without exposing it to unrelated host users.
    if let Err(error) = publish_clone_worker_capability(sock) {
        let _ = std::fs::remove_file(sock);
        return Err(error);
    }
    match spawn_tensor_bundle_service(sock) {
        Ok(path) => {
            TENSOR_BUNDLE_SERVICE_READY.store(true, Ordering::Release);
            tracing::info!(socket = %path.display(), "device-resident tensor service listening");
        }
        Err(error) => tracing::warn!(
            %error,
            "device-resident tensor publication disabled; CUDA serving remains available"
        ),
    }
    // Must precede listener threads and the first GpuBackend::load. Clone
    // workers inherit the endpoint from this daemon. Starting only after the
    // socket is exclusively bound avoids briefly starting MPS in a losing
    // double-daemon process.
    #[cfg(target_os = "linux")]
    let _mps_ownership = start_managed_mps(sock);
    tracing::info!(socket = %sock.display(), "shared CUDA daemon listening");
    let active = Arc::new(AtomicUsize::new(0));
    // Optional network transport (P1): also accept CUDA-RPC over TCP so a remote,
    // GPU-less client (e.g. a Mac running the shim with SMOLVM_CUDA_RPC=tcp:HOST:PORT)
    // can drive this GPU. Trusted single-tenant only — NO TLS/auth yet; that is the
    // hosted-service layer, intentionally deferred. Bind e.g. `0.0.0.0:7001`.
    let tcp_addr = std::env::var("SMOLVM_CUDA_DAEMON_TCP").ok();
    if let Some(ref addr) = tcp_addr {
        match std::net::TcpListener::bind(addr) {
            Ok(tcp) => {
                tracing::info!(%addr, "CUDA daemon ALSO listening on TCP (network transport)");
                let active_tcp = active.clone();
                thread::Builder::new()
                    .name("cuda-daemon-tcp".into())
                    .spawn(move || {
                        for stream in tcp.incoming() {
                            match stream {
                                Ok(s) => {
                                    let _ = s.set_nodelay(true); // low-latency RPC
                                                                 // Path 3: a REMOTE isolating fork clone (its VM
                                                                 // proxies here over TCP) gets a worker process
                                                                 // exactly like a local one — the golden's memory
                                                                 // and the clone worker both live on THIS GPU
                                                                 // host; only the RPC crosses the network.
                                    #[cfg(unix)]
                                    let policy = {
                                        use std::os::unix::io::AsRawFd;
                                        // Clone-marked connections (preamble from the
                                        // remote clone VM's proxy) route to a worker or
                                        // are rejected; a golden's reconnect (token, no
                                        // preamble) falls through to in-daemon serving.
                                        let mut policy = consume_policy_preamble(s.as_raw_fd());
                                        let rdir = consume_ring_dir_preamble(s.as_raw_fd());
                                        if route_clone_connection(
                                            s.as_raw_fd(),
                                            rdir.as_deref(),
                                            None,
                                            &mut policy,
                                        ) {
                                            drop(s); // worker owns it / rejected
                                            continue;
                                        }
                                        policy
                                    };
                                    #[cfg(not(unix))]
                                    let policy = ServeOptions::default();
                                    spawn_serve(s, &active_tcp, None, None, policy, None);
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "CUDA daemon TCP accept error")
                                }
                            }
                        }
                    })
                    .ok();
            }
            Err(e) => tracing::warn!(%addr, error = %e, "CUDA daemon TCP bind failed"),
        }
    }
    // A network daemon should persist even with no client yet, so only run the
    // idle watchdog when there is no TCP listener holding the door open.
    if tcp_addr.is_none() {
        if let Some(timeout) = idle_timeout() {
            spawn_idle_watchdog(active.clone(), timeout);
        }
    }
    spawn_child_reaper();
    for stream in listener.incoming() {
        match stream {
            // Count the connection open for the whole serve loop so a frozen golden
            // (idle but connected) keeps the daemon alive for its clones.
            Ok(stream) => {
                // Path 3 (M1): an isolating fork clone (its VM's proxy sends a
                // clone preamble) is served in its own worker PROCESS (own
                // context/UVA) so it can hold memory at the golden's exact VAs.
                // A GOLDEN's reconnect — same lineage token, NO preamble —
                // falls through and resumes in-daemon: routing it to a worker
                // would silently serve it a reconstructed COPY of its memory.
                // Only fires under SMOLVM_CUDA_FORK_WORKERS; otherwise legacy.
                #[cfg(unix)]
                let (guest_ram, ring_dir, policy, golden_connection) = {
                    use std::os::unix::io::AsRawFd;
                    let mut policy = consume_policy_preamble(stream.as_raw_fd());
                    let ram = consume_ram_preamble(stream.as_raw_fd());
                    let rdir = consume_ring_dir_preamble(stream.as_raw_fd());
                    let procmem = consume_procmem_preamble(stream.as_raw_fd());
                    if route_clone_connection(
                        stream.as_raw_fd(),
                        rdir.as_deref(),
                        procmem,
                        &mut policy,
                    ) {
                        drop(stream); // worker owns it / rejected
                        continue;
                    }
                    let golden_connection = ram.as_ref().map(|(pid, _)| {
                        let token = peek_clone_token(stream.as_raw_fd()).unwrap_or(0);
                        (*pid, token, stream.as_raw_fd())
                    });
                    (
                        ram.map(|(_, regions)| regions),
                        rdir,
                        policy,
                        golden_connection,
                    )
                };
                #[cfg(not(unix))]
                let (guest_ram, ring_dir, policy, golden_connection) =
                    (None, None::<String>, ServeOptions::default(), None);
                spawn_serve(
                    stream,
                    &active,
                    guest_ram,
                    ring_dir,
                    policy,
                    golden_connection,
                );
            }
            Err(e) => tracing::debug!(error = %e, "CUDA daemon accept error"),
        }
    }
    Ok(())
}

/// Serve one accepted connection on its own thread with a fresh backend, counting
/// it against `active` for the idle watchdog. Generic over the stream type so the
/// local UDS listener and the optional TCP listener share one path.
/// `guest_ram`: daemon-local mappings of the VM's guest RAM (from the RAM
/// preamble) — installing them enables the ring transport + zero-copy GPA
/// memcpys for this connection.
fn spawn_serve<S>(
    stream: S,
    active: &Arc<AtomicUsize>,
    guest_ram: Option<Vec<(u64, u64, u64)>>,
    ring_dir: Option<String>,
    options: ServeOptions,
    #[cfg(unix)] golden_connection: Option<(u32, u64, std::os::unix::io::RawFd)>,
    #[cfg(not(unix))] _golden_connection: Option<(u32, u64, i32)>,
) where
    S: std::io::Read + std::io::Write + Send + 'static,
{
    let guard = ConnGuard::new(active);
    #[cfg(unix)]
    let golden_guard = golden_connection
        .and_then(|(pid, token, fd)| GoldenConnectionGuard::register(pid, token, fd));
    thread::Builder::new()
        .name("cuda-daemon-conn".into())
        .spawn(move || {
            let _guard = guard;
            #[cfg(unix)]
            let _golden_guard = golden_guard;
            let mut backend = make_backend();
            if let Some(regions) = guest_ram {
                tracing::info!(
                    count = regions.len(),
                    "guest-RAM mapped: zero-copy + rings enabled"
                );
                backend.set_guest_ram(regions);
            }
            smolvm_cuda::host::ring_dir_set(ring_dir);
            if let Err(e) = serve_with_options(stream, backend.as_mut(), options) {
                tracing::debug!(error = %e, "CUDA daemon connection ended");
            }
        })
        .ok();
}

/// Consume a fork-CLONE proc-mem advertisement (`SMVGPVM1`) if present: the
/// clone proxy sends `(pid, gpa, host_va, len)` for its LIVE private (COW) guest
/// RAM after its clone preamble, so the worker can pread/pwrite /proc/<pid>/mem
/// (a memfd map would be STALE golden bytes). Peek-based; `None` on any old proxy
/// or golden connection (leaves the bytes untouched for the RPC serve loop).
/// A fork clone's live-RAM advert: its pid + (gpa, host_va, len) regions.
type ProcMemAdvert = (u32, Vec<(u64, u64, u64)>);
type GuestRamAdvert = (u32, Vec<(u64, u64, u64)>);

/// Consume the per-VM CUDA capacity policy (`SMVCPOL1`) when present. Older
/// proxies send no policy; the peek leaves their first preamble or RPC frame
/// untouched and preserves the previous unlimited behavior.
#[cfg(unix)]
fn consume_policy_preamble(fd: std::os::unix::io::RawFd) -> ServeOptions {
    let mut buf = [0u8; 24];
    let mut n = 0isize;
    for _ in 0..200 {
        // SAFETY: MSG_PEEK into a fixed stack buffer on an accepted socket.
        n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 8 && &buf[..8] != b"SMVCPOL1" {
            return ServeOptions::default();
        }
        if n >= 24 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 24 || &buf[..8] != b"SMVCPOL1" {
        return ServeOptions::default();
    }
    // SAFETY: consume exactly the complete preamble just observed.
    let read = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MSG_WAITALL,
        )
    };
    if read != buf.len() as isize {
        return ServeOptions::default();
    }
    let limit = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let pool = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    ServeOptions {
        vram_limit_bytes: (limit > 0).then_some(limit),
        fork_pool_size: (pool > 0).then_some(pool),
        fork_clone: false,
    }
}

/// Serialize a proc-mem advert into the worker env value (see `procmem_from_env`).
fn procmem_to_env(pid: u32, regions: &[(u64, u64, u64)]) -> String {
    let mut out = pid.to_string();
    for (g, h, l) in regions {
        out.push_str(&format!(";{g},{h},{l}"));
    }
    out
}

/// Parse the `SMOLVM_CUDA_CLONE_PROCMEM` worker env back into a proc-mem advert.
fn procmem_from_env() -> Option<ProcMemAdvert> {
    let v = std::env::var("SMOLVM_CUDA_CLONE_PROCMEM").ok()?;
    let mut it = v.split(';');
    let pid: u32 = it.next()?.parse().ok()?;
    if pid == 0 {
        return None;
    }
    let mut regions = Vec::new();
    for part in it {
        let mut c = part.split(',');
        let g: u64 = c.next()?.parse().ok()?;
        let h: u64 = c.next()?.parse().ok()?;
        let l: u64 = c.next()?.parse().ok()?;
        regions.push((g, h, l));
    }
    Some((pid, regions))
}

fn consume_procmem_preamble(fd: std::os::unix::io::RawFd) -> Option<ProcMemAdvert> {
    let mut hdr = [0u8; 20];
    let mut n = 0isize;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                hdr.as_mut_ptr() as *mut libc::c_void,
                hdr.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 8 && &hdr[..8] != b"SMVGPVM1" {
            return None; // not ours; leave the bytes untouched
        }
        if n >= 20 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 20 || &hdr[..8] != b"SMVGPVM1" {
        return None;
    }
    let pid = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
    if pid == 0 || count > 64 {
        return None;
    }
    let total = 20 + count * 24;
    let mut buf = vec![0u8; total];
    let mut got = 0usize;
    while got < total {
        let r = unsafe {
            libc::recv(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                total - got,
                0,
            )
        };
        if r <= 0 {
            return None;
        }
        got += r as usize;
    }
    let mut regions = Vec::with_capacity(count);
    for i in 0..count {
        let o = 20 + i * 24;
        let gpa = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
        let hva = u64::from_le_bytes(buf[o + 8..o + 16].try_into().unwrap());
        let len = u64::from_le_bytes(buf[o + 16..o + 24].try_into().unwrap());
        if len == 0 {
            return None;
        }
        regions.push((gpa, hva, len));
    }
    Some((pid, regions))
}

/// Consume a guest-RAM advertisement preamble if present (peek-based; absent on
/// old proxies and non-memfd VMs). Maps the advertised regions of
/// `/proc/<pid>/fd/<memfd>` MAP_SHARED into THIS process and returns them as
/// `(gpa, daemon_va, len)` for `Backend::set_guest_ram`. Mappings are leaked
/// (VM-lifetime; bounded by connections-with-adverts). Same-uid access only —
/// exactly the trust boundary the daemon already has with its VMs.
/// Consume a ring-dir advertisement (`SMVRDIR1` + u16 len + host path) if
/// present. Returns the HOST directory backing the VM's dax ring mount, which
/// `RingSetupFile` on this connection resolves file names against.
#[cfg(unix)]
fn consume_ring_dir_preamble(fd: std::os::unix::io::RawFd) -> Option<String> {
    let mut hdr = [0u8; 10];
    let mut n: isize = 0;
    // SAFETY: MSG_PEEK of the fixed header on a valid fd; loop because proxied
    // bytes can arrive in pieces.
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                hdr.as_mut_ptr() as *mut libc::c_void,
                hdr.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 8 && &hdr[..8] != b"SMVRDIR1" {
            return None; // not ours; leave the bytes untouched
        }
        if n >= 10 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 10 || &hdr[..8] != b"SMVRDIR1" {
        return None;
    }
    let len = u16::from_le_bytes(hdr[8..10].try_into().unwrap()) as usize;
    if len == 0 || len > 512 {
        return None;
    }
    let total = 10 + len;
    let mut buf = vec![0u8; total];
    let mut got = 0usize;
    while got < total {
        // SAFETY: plain recv into our buffer.
        let r = unsafe {
            libc::recv(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                total - got,
                0,
            )
        };
        if r <= 0 {
            return None;
        }
        got += r as usize;
    }
    String::from_utf8(buf[10..].to_vec()).ok()
}

#[cfg(unix)]
fn consume_ram_preamble(fd: std::os::unix::io::RawFd) -> Option<GuestRamAdvert> {
    let mut hdr = [0u8; 20];
    // SAFETY: MSG_PEEK of the fixed header on a valid fd; loops like
    // peek_clone_token because proxied bytes can arrive in pieces.
    let mut n: isize = 0;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                hdr.as_mut_ptr() as *mut libc::c_void,
                hdr.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 8 && &hdr[..8] != b"SMVGRAM2" {
            return None; // not ours; leave the bytes untouched
        }
        if n >= 20 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 20 || &hdr[..8] != b"SMVGRAM2" {
        return None;
    }
    let pid = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
    if count == 0 || count > 64 {
        return None;
    }
    let total = 20 + count * 28;
    let mut buf = vec![0u8; total];
    let mut got = 0usize;
    while got < total {
        // SAFETY: plain recv consuming the preamble we just validated.
        let r = unsafe {
            libc::recv(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                total - got,
                0,
            )
        };
        if r <= 0 {
            return None;
        }
        got += r as usize;
    }
    // One memfd PER REGION (libkrun's layout): open each via /proc and map
    // MAP_SHARED at the advertised offset.
    let mut files: std::collections::HashMap<u32, std::fs::File> = std::collections::HashMap::new();
    let mut regions = Vec::with_capacity(count);
    for i in 0..count {
        let o = 20 + i * 28;
        let gpa = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
        let fd_no = u32::from_le_bytes(buf[o + 8..o + 12].try_into().unwrap());
        let off = u64::from_le_bytes(buf[o + 12..o + 20].try_into().unwrap());
        let len = u64::from_le_bytes(buf[o + 20..o + 28].try_into().unwrap());
        if len == 0 || off % 4096 != 0 {
            return None;
        }
        use std::os::unix::io::AsRawFd as _;
        let file = match files.entry(fd_no) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(format!("/proc/{pid}/fd/{fd_no}"))
                    .ok()?;
                v.insert(f)
            }
        };
        // SAFETY: MAP_SHARED of the VM's guest-RAM memfd at the advertised
        // offset; failure aborts the whole advert. Mappings are leaked
        // (VM-lifetime; bounded by connections that advertise).
        let va = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                off as i64,
            )
        };
        if va == libc::MAP_FAILED {
            tracing::warn!(pid, fd_no, off, len, "guest-RAM mmap failed; sockets only");
            return None;
        }
        regions.push((gpa, va as u64, len));
    }
    Some((pid, regions))
}

/// Keeps the daemon's open-connection count accurate: +1 on construction, -1 on
/// drop (whether the serve thread finished or never started).
struct ConnGuard(Arc<AtomicUsize>);

impl ConnGuard {
    fn new(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        ConnGuard(active.clone())
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn make_backend() -> Box<dyn Backend> {
    match GpuBackend::load() {
        Ok(gpu) => {
            tracing::info!("cuda-daemon: GPU driver backend ready");
            Box::new(gpu)
        }
        Err(e) => {
            tracing::info!("cuda-daemon: no GPU driver ({e}) — CPU emulation backend");
            Box::<CpuBackend>::default()
        }
    }
}

/// Per-thread state that cannot use the clone worker's process-global fallback.
/// Module/function images and stream/event maps are installed process-wide by
/// `set_handle_trans`, so copying them into every attached channel is wasteful.
type CloneChannelSeed = (
    Option<std::collections::HashMap<u64, u64>>,
    Vec<(u64, u64, u64)>,
);

struct CloneWorkerReadiness {
    vm_pid: Option<u32>,
    published: bool,
}

impl CloneWorkerReadiness {
    fn new(vm_pid: Option<u32>) -> Self {
        Self {
            vm_pid,
            published: false,
        }
    }

    fn publish_ready(&mut self) {
        let Some(vm_pid) = self.vm_pid else {
            return;
        };
        match publish_clone_worker_status(vm_pid, CloneWorkerStatus::Ready) {
            Ok(()) => self.published = true,
            Err(error) => {
                tracing::warn!(vm_pid, %error, "failed to publish CUDA clone-worker readiness")
            }
        }
    }
}

impl Drop for CloneWorkerReadiness {
    fn drop(&mut self) {
        let Some(vm_pid) = self.vm_pid else {
            return;
        };
        let path = clone_worker_status_path(vm_pid);
        if self.published && !path.exists() {
            return;
        }
        if self.published && crate::process::process_start_time(vm_pid as i32).is_none() {
            let _ = std::fs::remove_file(path);
            return;
        }
        if let Err(error) = publish_clone_worker_status(vm_pid, CloneWorkerStatus::Failed) {
            tracing::debug!(vm_pid, %error, "failed to publish CUDA clone-worker failure");
        }
    }
}

fn next_clone_reservation_reexec(
    attempt: Option<&str>,
    has_layout: bool,
    reservation_succeeded: bool,
) -> Option<u8> {
    if !has_layout || reservation_succeeded {
        return None;
    }
    let attempt = attempt.and_then(|value| value.parse().ok()).unwrap_or(0);
    (attempt < MAX_CUDA_CLONE_RESERVATION_REEXECS).then_some(attempt + 1)
}

/// Replace the worker image without changing its PID or inherited clone fds.
#[cfg(unix)]
fn reexec_clone_worker(fd: std::os::unix::io::RawFd, attempt: u8) -> io::Result<()> {
    use std::os::unix::process::CommandExt as _;

    let executable = std::env::current_exe()?;
    let fd = fd.to_string();
    let error = Command::new(executable)
        .args(["_cuda-clone-worker", fd.as_str()])
        .env(CUDA_CLONE_RESERVATION_REEXEC_ENV, attempt.to_string())
        .exec();
    Err(error)
}

/// Path 3 (M1): serve one isolating fork-clone connection in THIS separate worker
/// process. A per-clone process has its own CUDA primary context and thus its own
/// UVA space, so it can place memory at the golden's exact virtual addresses
/// (address-preserving isolation — no per-op pointer translation). The daemon
/// spawns us with the accepted connection's fd (see the clone routing in
/// `spawn_serve`). M2 (golden-state reconstruction) and M3 (module/graph rebuild)
/// hook in before the serve loop; establishing the process boundary comes first.
pub fn run_clone_worker(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    use std::os::unix::io::FromRawFd;
    install_crash_handler("cuda-clone-worker");
    // File-ring transport (per-worker: one worker == one clone VM == one dir).
    smolvm_cuda::host::ring_dir_set(std::env::var("SMOLVM_CUDA_CLONE_RING_DIR").ok());
    let clone_procmem = procmem_from_env();
    let clone_vm_pid = clone_procmem.as_ref().map(|(pid, _)| *pid);
    let mut readiness = CloneWorkerReadiness::new(clone_vm_pid);
    let mut backend = make_backend();
    // Our own primary context (separate process ⇒ own UVA), so we can place memory
    // at the golden's exact VAs.
    let _ = backend.init();
    if let Some(fd) = std::env::var("SMOLVM_CUDA_CLONE_PUBLISH_CTRL")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
    {
        // SAFETY: spawn_clone_worker transfers sole ownership of this inherited
        // descriptor to the worker and clears CLOEXEC before exec.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let stream = Arc::new(Mutex::new(stream));
        let publisher: Arc<smolvm_cuda::host::TensorBundlePublisher> = Arc::new(move |bundle| {
            let mut stream = stream.lock().map_err(|_| 999)?;
            send_tensor_bundle_to_parent(&mut stream, bundle)
        });
        smolvm_cuda::host::set_tensor_bundle_publisher(Some(publisher));
    }
    // Reconstruct on the GOLDEN's GPU: the exported physical lives there.
    let clone_dev: i32 = std::env::var("SMOLVM_CUDA_CLONE_DEVICE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // Reserve the golden's address ranges before retaining this worker's CUDA
    // context, so context initialization cannot occupy them. Some drivers
    // require non-zero address hints to use a coarser boundary than the
    // allocation granularity, so probe aligned envelopes from small to large.
    let clone_layout = std::env::var("SMOLVM_CUDA_CLONE_LAYOUT").ok();
    let mut pre_reserved = Vec::new();
    if let Some(layout) = clone_layout.as_deref() {
        let (ranges, granularity) = reserve_clone_layout_exact(backend.as_mut(), layout, clone_dev);
        pre_reserved = ranges;
        tracing::info!(
            exact = pre_reserved.len(),
            granularity,
            "clone-worker: reserved golden address ranges before context creation"
        );
        let has_layout =
            !clone_layout_reservation_envelopes(layout, MIN_CLONE_RESERVATION_GRANULARITY)
                .is_empty();
        if let Some(next_attempt) = next_clone_reservation_reexec(
            std::env::var(CUDA_CLONE_RESERVATION_REEXEC_ENV)
                .ok()
                .as_deref(),
            has_layout,
            !pre_reserved.is_empty(),
        ) {
            tracing::warn!(
                next_attempt,
                granularity,
                "clone-worker: re-executing after CUDA address collision"
            );
            return reexec_clone_worker(fd, next_attempt);
        }
    }
    let _ = backend.primary_ctx_retain(clone_dev);
    // Clone transport: consume the proc-mem advert (SMVGPVM1) the clone proxy
    // sent right after its clone preamble, so D2H/H2D reach the clone's LIVE
    // guest RAM via /proc/<pid>/mem instead of the ring-copy fallback.
    if let Some((pid, regions)) = clone_procmem {
        let n = regions.len();
        if regions.is_empty() {
            tracing::info!(
                pid,
                "cuda clone-worker: tracking clone VM lifetime before live-RAM attach"
            );
        } else if backend.set_guest_ram_procmem(pid, regions) {
            tracing::info!(
                pid,
                count = n,
                "cuda clone-worker: proc-mem live-RAM transport enabled"
            );
        } else {
            tracing::warn!(
                pid,
                "cuda clone-worker: proc-mem unavailable; ring-copy fallback"
            );
        }
    }
    // Seed state for late-attached guest channels (see the attach listener
    // below). VMM handle translation is thread-local; module/function and
    // stream/event translation have process-global fallbacks.
    let mut seed_vmm: Option<std::collections::HashMap<u64, u64>> = None;
    // M2: reconstruct the golden's memory at its exact VAs from the layout the
    // daemon passed (SMOLVM_CUDA_CLONE_LAYOUT) + the golden's physical exported to
    // fds 4.. — BEFORE serving, so the clone's inherited pointers are valid verbatim.
    if let Some(layout) = clone_layout.as_deref() {
        let (n, vmm_trans) =
            reconstruct_golden_memory(backend.as_mut(), layout, clone_dev, &pre_reserved)?;
        tracing::info!(
            maps = n,
            vmm_handles = vmm_trans.len(),
            "cuda clone-worker: reconstructed golden memory at its VAs"
        );
        seed_vmm = Some(vmm_trans.clone());
        // The clone unmaps/releases inherited chunks by their GOLDEN handle
        // values (torch expandable_segments trims segments under pressure);
        // untranslated, cuMemRelease segfaults on the foreign-context handle.
        smolvm_cuda::host::set_vmm_trans(vmm_trans);
        // Barrier: VMM reconstruction must fully settle before the clone runs, or a
        // later cuModuleLoadData surfaces a sticky async fault from the copies.
        if let Err(e) = backend.ctx_synchronize() {
            tracing::warn!(e, "clone-worker: sync after memory reconstruction failed");
        }
    }
    // M3a: STAGE the golden's modules/functions for LAZY reload in OUR context
    // (reloading all up front stalls serving ~2s and breaks the clone connection)
    // + recreate streams/events, then install the translation so the clone's
    // inherited kernel launches resolve (each module reloads on first use).
    #[cfg(target_os = "linux")]
    let inherited_module_blob =
        if let Some(value) = std::env::var_os("SMOLVM_CUDA_CLONE_MODULES_FD") {
            let value = value.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CUDA module handoff fd is not valid UTF-8",
                )
            })?;
            let module_fd = value.parse::<std::os::fd::RawFd>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CUDA module handoff fd is invalid",
                )
            })?;
            Some(map_module_blob_fd(module_fd)?)
        } else {
            None
        };
    #[cfg(not(target_os = "linux"))]
    let inherited_module_blob: Option<smolvm_cuda::host::ModuleHandoffBytes> = None;
    #[cfg(target_os = "linux")]
    let inherited_module_images =
        if let Some(value) = std::env::var_os("SMOLVM_CUDA_CLONE_MODULE_IMAGES_FD") {
            let value = value.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CUDA module image-store fd is not valid UTF-8",
                )
            })?;
            let image_fd = value.parse::<std::os::fd::RawFd>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CUDA module image-store fd is invalid",
                )
            })?;
            Some(map_module_blob_fd(image_fd)?)
        } else {
            None
        };
    #[cfg(not(target_os = "linux"))]
    let inherited_module_images: Option<smolvm_cuda::host::ModuleHandoffBytes> = None;
    let module_blob = if inherited_module_blob.is_some() {
        inherited_module_blob
    } else if let Ok(modpath) = std::env::var("SMOLVM_CUDA_CLONE_MODULES") {
        let result = std::fs::read(&modpath);
        let _ = std::fs::remove_file(&modpath);
        Some(smolvm_cuda::host::ModuleHandoffBytes::from_owned(result?))
    } else {
        None
    };
    if let Some(module_blob) = module_blob {
        let (mod_images, func_meta, streams, events, graphs, lib_handles) =
            reconstruct_golden_modules(
                backend.as_mut(),
                &module_blob,
                inherited_module_images.as_ref(),
            )?;
        let (nm, nf, ns, ne, ng, nlh) = (
            mod_images.len(),
            func_meta.len(),
            streams.len(),
            events.len(),
            graphs.len(),
            lib_handles.len(),
        );
        // This installs immutable process-global fallbacks as well as the main
        // thread's fast-path maps. Attached channels use those fallbacks rather
        // than deep-copying every module image and function record.
        smolvm_cuda::host::set_shared_handle_trans(mod_images, func_meta, streams, events);
        // Re-create the golden's top-level cuBLAS/cuBLASLt/cuDNN handles in
        // THIS process and map the clone's inherited values to them — library
        // handles are process-local, so a pre-fork handle would otherwise fail
        // the clone's first post-fork library call.
        let nseeded = smolvm_cuda::host::replay_lib_handles(backend.as_mut(), &lib_handles);
        // M3b: rebuild the golden's captured CUDA graphs in THIS context, now
        // that modules can lazily reload and memory is reconstructed (kernel-arg
        // pointers reference the golden VAs, valid here). Maps the clone's
        // inherited graph/exec handles to the worker's rebuilt reals.
        let nrebuilt = smolvm_cuda::host::rebuild_clone_graphs(backend.as_mut(), graphs);
        // Pre-warm now (module reloads + graph re-capture into the
        // process-wide registries), while the guest VM is still resuming —
        // serving sessions adopt the results instead of doing this work on
        // the guest's first CUDA call.
        smolvm_cuda::host::prewarm_clone_worker(backend.as_mut());
        tracing::info!(
            modules = nm,
            functions = nf,
            streams = ns,
            events = ne,
            graphs = ng,
            graphs_rebuilt = nrebuilt,
            lib_handles = nlh,
            lib_handles_seeded = nseeded,
            "cuda clone-worker: staged modules for lazy reload + remapped handles"
        );
    }
    // Late-attached guest channels: the guest dials fresh daemon connections
    // after the fork (first-ever cuBLAS init inside a clone does exactly
    // this); the daemon forwards each such fd over the control channel and we
    // serve it on its own thread, seeded with the same translation state.
    let active_channels = Arc::new(AtomicUsize::new(1));
    let attach_listener = if let Some(ctrl) = std::env::var("SMOLVM_CUDA_CLONE_CTRL")
        .ok()
        .and_then(|v| v.parse::<std::os::unix::io::RawFd>().ok())
    {
        let seed_alloc = smolvm_cuda::host::worker_alloc_trans_snapshot();
        let seed = std::sync::Arc::new((seed_vmm, seed_alloc));
        Some(spawn_clone_attach_listener(
            ctrl,
            clone_dev,
            seed,
            active_channels.clone(),
            clone_vm_pid,
        )?)
    } else {
        None
    };
    readiness.publish_ready();
    // The handed-off connection may be a local UDS (VM on this host) or a TCP
    // socket (remote client driving this GPU host) — wrap by actual domain.
    // (getsockname is portable unix; SO_DOMAIN would be Linux-only.)
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: plain getsockname on a valid fd with a correctly-sized out buffer.
    unsafe {
        libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len);
    }
    let domain = libc::c_int::from(addr.ss_family);
    tracing::info!(
        fd,
        tcp = domain != libc::AF_UNIX,
        "cuda clone-worker: serving in its own context / UVA space"
    );
    let result = if domain == libc::AF_UNIX {
        // SAFETY: the daemon handed us sole ownership of the accepted fd.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        serve(stream, backend.as_mut())
    } else {
        // SAFETY: as above; a TCP connection from the daemon's network listener.
        let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let _ = stream.set_nodelay(true);
        serve(stream, backend.as_mut())
    };
    active_channels.fetch_sub(1, Ordering::SeqCst);
    if let Some(listener) = attach_listener {
        // A clone's startup warm-dial can close just as its first real CUDA
        // channel is handed to the listener. Keep the reconstructed context
        // alive while the clone VM or any attached channel is alive. A timeout
        // is only the fallback for remote transports without a local VM PID.
        // Returning here immediately used to kill attached sessions and
        // trigger a full 20k-function reconstruction every few seconds.
        let _ = listener.join();
    }
    result
}

/// Keep a reconstructed clone worker available across clean channel turnover.
/// A local worker follows its clone VM's lifetime; remote transports without a
/// local VM PID use a bounded idle fallback so dead clients cannot pin contexts.
#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn spawn_clone_attach_listener(
    ctrl: std::os::unix::io::RawFd,
    clone_dev: i32,
    seed: Arc<CloneChannelSeed>,
    active_channels: Arc<AtomicUsize>,
    clone_vm_pid: Option<u32>,
) -> io::Result<std::thread::JoinHandle<()>> {
    spawn_clone_attach_listener_with_timeout(
        ctrl,
        clone_dev,
        seed,
        active_channels,
        clone_vm_pid,
        clone_worker_idle_timeout(),
    )
}

#[cfg(unix)]
fn clone_worker_vm_is_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 performs a liveness/permission check without delivering
    // a signal. EPERM still proves that the process exists.
    (unsafe { libc::kill(pid, 0) == 0 })
        || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn clone_worker_idle_expired(
    active_channels: usize,
    clone_vm_alive: Option<bool>,
    idle_elapsed: Duration,
    fallback_timeout: Duration,
) -> bool {
    if active_channels > 0 || clone_vm_alive == Some(true) {
        return false;
    }
    let timeout = if clone_vm_alive == Some(false) {
        Duration::from_secs(5)
    } else {
        fallback_timeout
    };
    idle_elapsed >= timeout
}

#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn spawn_clone_attach_listener_with_timeout(
    ctrl: std::os::unix::io::RawFd,
    clone_dev: i32,
    seed: Arc<CloneChannelSeed>,
    active_channels: Arc<AtomicUsize>,
    clone_vm_pid: Option<u32>,
    idle_timeout: Duration,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("cuda-clone-attach".into())
        .spawn(move || {
            let mut idle_since = Instant::now();
            loop {
                let active = active_channels.load(Ordering::SeqCst);
                let clone_vm_alive = clone_vm_pid.map(clone_worker_vm_is_alive);
                if active > 0 || clone_vm_alive == Some(true) {
                    idle_since = Instant::now();
                } else if clone_worker_idle_expired(
                    active,
                    clone_vm_alive,
                    idle_since.elapsed(),
                    idle_timeout,
                ) {
                    tracing::info!(
                        clone_vm_pid,
                        fallback_idle_secs = idle_timeout.as_secs(),
                        "clone-worker: clone lifetime ended"
                    );
                    break;
                }

                let mut pollfd = libc::pollfd {
                    fd: ctrl,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: poll reads one valid pollfd for at most one second.
                let ready = unsafe { libc::poll(&mut pollfd, 1, 1_000) };
                if ready == 0 {
                    continue;
                }
                if ready < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    tracing::info!(error = %e, "clone-worker: control poll ended");
                    break;
                }

                match recv_fd(ctrl) {
                    Ok((nfd, procmem)) => {
                        active_channels.fetch_add(1, Ordering::SeqCst);
                        let seed = seed.clone();
                        let active = active_channels.clone();
                        let spawned = std::thread::Builder::new()
                            .name("cuda-clone-channel".into())
                            .spawn(move || {
                                serve_attached_channel(nfd, clone_dev, &seed, procmem);
                                active.fetch_sub(1, Ordering::SeqCst);
                            });
                        if let Err(e) = spawned {
                            active_channels.fetch_sub(1, Ordering::SeqCst);
                            // SAFETY: recv_fd transferred sole ownership to us.
                            unsafe { libc::close(nfd) };
                            tracing::warn!(error = %e, "clone-worker: channel thread spawn failed");
                        }
                    }
                    Err(e) => {
                        tracing::info!(error = %e, "clone-worker: control channel closed");
                        break;
                    }
                }
            }
            // SAFETY: the worker owns the inherited child end of the control
            // socket and no longer accepts attachments after this loop.
            unsafe { libc::close(ctrl) };
        })
}

fn clone_worker_idle_timeout() -> Duration {
    clone_worker_idle_timeout_from(std::env::var("SMOLVM_CUDA_CLONE_IDLE_SECS").ok().as_deref())
}

fn clone_worker_idle_timeout_from(value: Option<&str>) -> Duration {
    let secs = value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(300);
    Duration::from_secs(secs)
}

/// Serve one late-attached guest channel inside the clone worker. Own backend
/// handle, same primary context (same UVA space), and only the thread-local
/// translations that lack process-global fallbacks.
#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn serve_attached_channel(
    fd: std::os::unix::io::RawFd,
    dev: i32,
    seed: &CloneChannelSeed,
    attached_procmem: Option<ProcMemAdvert>,
) {
    use std::os::unix::io::FromRawFd;
    let mut backend = make_backend();
    let _ = backend.init();
    let _ = backend.primary_ctx_retain(dev);
    if let Some((pid, regions)) = attached_procmem
        .or_else(procmem_from_env)
        .filter(|(_, regions)| !regions.is_empty())
    {
        backend.set_guest_ram_procmem(pid, regions);
    }
    // File-ring transport: attached channels serve on their own threads, and
    // the ring dir is per-worker (thread-local install per serve thread).
    smolvm_cuda::host::ring_dir_set(std::env::var("SMOLVM_CUDA_CLONE_RING_DIR").ok());
    let (vmm, alloc) = seed;
    if let Some(v) = vmm {
        smolvm_cuda::host::set_vmm_trans(v.clone());
    }
    if !alloc.is_empty() {
        smolvm_cuda::host::set_worker_alloc_trans(alloc.clone());
    }
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: plain getsockname on a valid fd with a correctly-sized out buffer.
    unsafe {
        libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len);
    }
    let domain = libc::c_int::from(addr.ss_family);
    tracing::info!(
        fd,
        tcp = domain != libc::AF_UNIX,
        "cuda clone-worker: serving attached channel"
    );
    let r = if domain == libc::AF_UNIX {
        // SAFETY: recv_fd handed us sole ownership of the received fd.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        smolvm_cuda::host::serve(stream, backend.as_mut())
    } else {
        // SAFETY: as above; a TCP connection forwarded by the daemon.
        let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let _ = stream.set_nodelay(true);
        smolvm_cuda::host::serve(stream, backend.as_mut())
    };
    if let Err(e) = r {
        tracing::info!(error = %e, fd, "clone-worker: attached channel ended");
    }
}

/// IPC-import a golden physical from `fd`, retrying on transient failure with a
/// ctx_synchronize between attempts. Defense-in-depth: the deterministic e=999
/// import failure was the CLOEXEC fd handoff (fixed in spawn_clone_worker); this
/// guards the remaining first-import-in-fresh-context warm-up window.
#[cfg(unix)]
fn import_with_retry(b: &mut dyn Backend, fd: i32) -> Result<u64, i32> {
    let mut last = 0;
    for attempt in 0..5 {
        match b.mem_import_handle(fd) {
            Ok(h) => {
                if attempt > 0 {
                    tracing::info!(fd, attempt, "M2: import succeeded on retry");
                }
                return Ok(h);
            }
            Err(e) => {
                last = e;
                let _ = b.ctx_synchronize();
            }
        }
    }
    Err(last)
}

/// Map an imported CUDA allocation, retrying the transient CUDA 801 failures
/// observed when many MPS clients reconstruct a fork pool concurrently.
#[cfg(unix)]
fn map_import_with_retry(
    b: &mut dyn Backend,
    va: u64,
    size: u64,
    offset: u64,
    handle: u64,
) -> Result<(), i32> {
    let mut last = 0;
    for attempt in 0..5 {
        match b.mem_map(va, size, offset, handle) {
            Ok(()) => {
                if attempt > 0 {
                    tracing::info!(va, size, attempt, "M2: map succeeded on retry");
                }
                return Ok(());
            }
            Err(error) => {
                last = error;
                let _ = b.ctx_synchronize();
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    Err(last)
}

#[cfg(unix)]
fn read_host_snapshot(fd: i32, offset: u64, size: u64) -> io::Result<Vec<u8>> {
    let len = usize::try_from(size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "snapshot range too large"))?;
    let mut bytes = vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        // SAFETY: pread writes at most the remaining initialized Vec capacity;
        // the inherited memfd stays open for the worker's reconstruction phase.
        let n = unsafe {
            libc::pread(
                fd,
                bytes[done..].as_mut_ptr().cast(),
                len - done,
                i64::try_from(offset.saturating_add(done as u64)).unwrap_or(i64::MAX),
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short CUDA host snapshot",
            ));
        }
        done += n as usize;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn append_host_snapshot(fd: i32, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < bytes.len() {
        // SAFETY: pwrite reads from a valid byte slice and writes to our memfd.
        let n = unsafe {
            libc::pwrite(
                fd,
                bytes[done..].as_ptr().cast(),
                bytes.len() - done,
                i64::try_from(offset.saturating_add(done as u64)).unwrap_or(i64::MAX),
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short CUDA host snapshot write",
            ));
        }
        done += n as usize;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn seal_host_snapshot(fd: i32) -> io::Result<()> {
    let seals = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    // SAFETY: F_ADD_SEALS only changes the write policy of the owned memfd.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_host_snapshot_memfd() -> io::Result<i32> {
    let name = std::ffi::CString::new("smolvm-cuda-golden-snapshot").unwrap();
    // SAFETY: memfd_create returns a new anonymous file descriptor owned by
    // the clone spawn path and later inherited by its worker.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    (fd >= 0).then_some(fd).ok_or_else(io::Error::last_os_error)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn seal_host_snapshot(_fd: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host CUDA snapshots require Linux",
    ))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn create_host_snapshot_memfd() -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host CUDA snapshots require Linux",
    ))
}

#[cfg(unix)]
fn clone_layout_reservations(layout: &str) -> Vec<(u64, u64)> {
    let hx = |s: &str| u64::from_str_radix(s, 16).ok();
    let mut ranges = Vec::new();
    for part in layout.split('|') {
        if let Some(entries) = part.strip_prefix("resv=") {
            ranges.extend(entries.split(',').filter_map(|entry| {
                let (va, size) = entry.split_once(':')?;
                Some((hx(va)?, hx(size)?))
            }));
        }
        if let Some(entries) = part.strip_prefix("aregions=") {
            ranges.extend(entries.split(',').filter_map(|entry| {
                let mut fields = entry.split(':');
                Some((hx(fields.next()?)?, hx(fields.next()?)?))
            }));
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

#[cfg(unix)]
fn clone_layout_reservation_envelopes(layout: &str, granularity: u64) -> Vec<(u64, u64)> {
    let mask = granularity - 1;
    let mut spans: Vec<(u64, u64)> = clone_layout_reservations(layout)
        .into_iter()
        .map(|(va, size)| {
            let base = va & !mask;
            let end = va.saturating_add(size).saturating_add(mask) & !mask;
            (base, end)
        })
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (base, end) in spans {
        match merged.last_mut() {
            Some((_, prior_end)) if base <= *prior_end => *prior_end = (*prior_end).max(end),
            _ => merged.push((base, end)),
        }
    }
    merged
        .into_iter()
        .map(|(base, end)| (base, end - base))
        .collect()
}

#[cfg(unix)]
fn range_is_reserved(ranges: &[(u64, u64)], va: u64, size: u64) -> bool {
    ranges
        .iter()
        .any(|&(base, span)| va >= base && va.saturating_add(size) <= base.saturating_add(span))
}

#[cfg(unix)]
fn ordinary_regions_are_reserved(regions: &[(u64, u64, u64)], reserved: &[(u64, u64)]) -> bool {
    regions
        .iter()
        .all(|&(base, size, _)| range_is_reserved(reserved, base, size))
}

#[cfg(unix)]
fn reserve_clone_address_exact(b: &mut dyn Backend, va: u64, size: u64, align: u64) -> bool {
    match b.mem_address_reserve_fixed(size, align, va) {
        Ok(actual) if actual == va => true,
        Ok(actual) => {
            let _ = b.mem_address_free(actual, size);
            tracing::warn!(
                requested = va,
                actual,
                size,
                "clone-worker: CUDA moved an exact-address reservation"
            );
            false
        }
        Err(e) => {
            tracing::warn!(e, va, size, "clone-worker: exact-address reserve failed");
            false
        }
    }
}

#[cfg(unix)]
const MIN_CLONE_RESERVATION_GRANULARITY: u64 = 1 << 16;
#[cfg(unix)]
const MAX_CLONE_RESERVATION_GRANULARITY: u64 = 1 << 31;

#[cfg(unix)]
fn reserve_clone_layout_exact(
    b: &mut dyn Backend,
    layout: &str,
    device: i32,
) -> (Vec<(u64, u64)>, u64) {
    let mut granularity = b
        .mem_get_allocation_granularity(device, 0)
        .unwrap_or(1 << 21)
        .max(MIN_CLONE_RESERVATION_GRANULARITY)
        .next_power_of_two();
    // Most workers resolve at 32 MiB. Keep one validated 2 GiB envelope as a
    // final fallback, then re-exec the worker if its address space collides.
    while granularity <= MAX_CLONE_RESERVATION_GRANULARITY {
        let envelopes = clone_layout_reservation_envelopes(layout, granularity);
        let mut reserved = Vec::with_capacity(envelopes.len());
        let mut complete = true;
        for &(va, size) in &envelopes {
            if reserve_clone_address_exact(b, va, size, granularity) {
                reserved.push((va, size));
            } else {
                complete = false;
                break;
            }
        }
        if complete {
            return (reserved, granularity);
        }
        for (va, size) in reserved {
            let _ = b.mem_address_free(va, size);
        }
        granularity = granularity.saturating_mul(2);
    }
    (Vec::new(), granularity)
}

/// M2: rebuild the golden's VMM layout in THIS worker's context at the golden's
/// EXACT VAs. `layout` = `"resv=va:size,…|maps=va:size:fdidx:loaded:ghandle,…"` (hex);
/// each map's physical was exported by the daemon to fd `4 + fdidx`. We import +
/// map at the same VA — address-preserving, so inherited pointers and rebuilt
/// graphs are valid verbatim. (Weights are shared here; private-mutable copy for
/// full isolation is the next refinement.)
///
/// Also returns the golden-handle → worker-handle map (from `ghandle`): the
/// clone's torch later unmaps/releases inherited chunks by their GOLDEN handle
/// values, and cuMemRelease on a foreign-context handle SEGFAULTS the worker.
#[cfg(unix)]
fn reconstruct_golden_memory(
    b: &mut dyn Backend,
    layout: &str,
    device: i32,
    pre_reserved: &[(u64, u64)],
) -> io::Result<(usize, std::collections::HashMap<u64, u64>)> {
    let mut vmm_trans = std::collections::HashMap::new();
    let (mut resv_s, mut maps_s, mut aregions_s, mut allocs_s) = ("", "", "", "");
    let mut astage: Option<i32> = None;
    let mut ahost: Option<i32> = None;
    for part in layout.split('|') {
        if let Some(r) = part.strip_prefix("resv=") {
            resv_s = r;
        }
        if let Some(m) = part.strip_prefix("maps=") {
            maps_s = m;
        }
        if let Some(a) = part.strip_prefix("astage=") {
            astage = a.parse().ok();
        }
        if let Some(a) = part.strip_prefix("ahost=") {
            ahost = a.parse().ok();
        }
        if let Some(a) = part.strip_prefix("aregions=") {
            aregions_s = a;
        }
        if let Some(a) = part.strip_prefix("allocs=") {
            allocs_s = a;
        }
    }
    let hx = |s: &str| u64::from_str_radix(s, 16).ok();
    for e in resv_s.split(',').filter(|s| !s.is_empty()) {
        if let Some((va, size)) = e.split_once(':') {
            if let (Some(va), Some(size)) = (hx(va), hx(size)) {
                if !range_is_reserved(pre_reserved, va, size)
                    && !reserve_clone_address_exact(b, va, size, 0)
                {
                    tracing::warn!(va, size, "M2: reservation unavailable at golden VA");
                }
            }
        }
    }
    let share_weights = smolvm_cuda::host::path3_share_weights_enabled();
    let (mut count, mut shared) = (0, 0);
    let mut shared_ranges = Vec::new();
    for e in maps_s.split(',').filter(|s| !s.is_empty()) {
        let f: Vec<&str> = e.split(':').collect();
        if f.len() < 3 {
            continue;
        }
        let (Some(va), Some(size), Ok(idx)) = (hx(f[0]), hx(f[1]), f[2].parse::<i32>()) else {
            continue;
        };
        // 4th field (loaded) marks a fully-H2D-covered weight range; 5th is the
        // golden's handle value for this chunk (hex).
        let loaded = f.get(3).map(|s| *s == "1").unwrap_or(false);
        let golden_h = f.get(4).and_then(|s| hx(s));
        let host_offset = f.get(5).and_then(|s| hx(s));

        // A fully loaded range is frozen at the snapshot boundary, so every
        // clone can import the same physical memory at the golden VA. Shared
        // mappings remain read-only until an explicit post-fork write replaces
        // the affected VMM chunk with a private, address-preserving copy.
        if share_weights && loaded {
            let mut ok = false;
            if let Ok(gh) = import_with_retry(b, 4 + idx) {
                match map_import_with_retry(b, va, size, 0, gh) {
                    Ok(()) => {
                        // Kernel writes cannot be intercepted for COW, so keep
                        // shared physical memory read-only and fail locally instead
                        // of allowing one clone to corrupt its siblings.
                        let set = b.mem_set_access_ro(va, size, device);
                        if set.is_ok() {
                            ok = true;
                        } else {
                            let _ = b.mem_unmap(va, size); // roll back for the fallback
                        }
                    }
                    Err(error) => tracing::warn!(
                        error,
                        idx,
                        va,
                        size,
                        "M2-share: imported allocation map failed"
                    ),
                }
                match (ok, golden_h) {
                    // Keep gh held and record golden→worker: the clone later
                    // releases this chunk by the GOLDEN's handle value.
                    (true, Some(g)) => {
                        vmm_trans.insert(g, gh);
                    }
                    // Legacy layout (no handle field) or failure: the va mapping
                    // holds its own ref, so drop ours.
                    _ => {
                        let _ = b.mem_release(gh);
                    }
                }
            }
            if ok {
                shared_ranges.push((va, size));
                shared += 1;
                count += 1;
                continue;
            }
            tracing::warn!(idx, "M2-share: share failed → private-copy fallback");
            // fall through to the private path (va stays reserved + unmapped)
        }
        // Private-mutable, address-preserving: map a PRIVATE physical at the golden
        // VA, then copy the golden's bytes in via a temp mapping of the imported
        // physical. Reads see the golden's data; writes hit the clone's own copy,
        // so a clone can't corrupt the frozen golden.
        let priv_h = match b.mem_create(size, device) {
            Ok(h) => h,
            Err(e) => {
                return Err(io::Error::other(format!(
                    "private CUDA snapshot allocation failed at {va:#x}: {e}"
                )));
            }
        };
        if let Err(e) = b.mem_map(va, size, 0, priv_h) {
            let _ = b.mem_release(priv_h);
            return Err(io::Error::other(format!(
                "private CUDA snapshot map failed at {va:#x}: {e}"
            )));
        }
        // priv_h stays held (never released here): the clone releases this chunk
        // post-fork by the GOLDEN's handle value, translated to priv_h.
        if let Some(g) = golden_h {
            vmm_trans.insert(g, priv_h);
        }
        if let Err(e) = b.mem_set_access(va, size, device) {
            return Err(io::Error::other(format!(
                "private CUDA snapshot access failed at {va:#x}: {e}"
            )));
        }
        if let Some(offset) = host_offset {
            let bytes = read_host_snapshot(4 + idx, offset, size)?;
            b.memcpy_htod(va, &bytes, 0).map_err(|error| {
                io::Error::other(format!(
                    "CUDA host snapshot restore failed at {va:#x}: {error}"
                ))
            })?;
        } else {
            let gh = import_with_retry(b, 4 + idx).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot import failed for range {idx}: {error}"
                ))
            })?;
            let tmp = b.mem_address_reserve(size, 0).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot temporary reservation failed at {va:#x}: {error}"
                ))
            })?;
            map_import_with_retry(b, tmp, size, 0, gh).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot temporary map failed at {va:#x}: {error}"
                ))
            })?;
            b.mem_set_access(tmp, size, device).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot temporary access failed at {va:#x}: {error}"
                ))
            })?;
            b.memcpy_dtod(va, tmp, size).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot copy failed at {va:#x}: {error}"
                ))
            })?;
            // The copy must finish before unmapping the temporary source.
            b.ctx_synchronize().map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot synchronization failed at {va:#x}: {error}"
                ))
            })?;
            b.mem_unmap(tmp, size).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot temporary unmap failed at {va:#x}: {error}"
                ))
            })?;
            b.mem_address_free(tmp, size).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot temporary release failed at {va:#x}: {error}"
                ))
            })?;
            b.mem_release(gh).map_err(|error| {
                io::Error::other(format!(
                    "private CUDA snapshot handle release failed at {va:#x}: {error}"
                ))
            })?;
        }
        count += 1;
    }
    // Emit the verdict in both modes. Private-copy controls need positive
    // evidence (`shared=0`) rather than inferring policy from a missing line.
    tracing::info!(shared, private = count - shared, "M2: shared weight ranges");
    smolvm_cuda::host::set_worker_shared_vmm_ranges(shared_ranges);
    // Non-VMM golden allocations (`cudaMalloc` — a plain-torch golden keeps ALL
    // its tensors here): copy each from the daemon's staged export into a fresh
    // private buffer and record a POINTER TRANSLATION, exactly like the
    // in-daemon isolate path. cudaMalloc VAs can't be address-preserved — they
    // collide with the worker's own host mappings (cuMemAddressReserve treats
    // the address as a hint) — but every op already translates through
    // `dptr_trans`, so translated copies are equivalent.
    if let (true, false) = (astage.is_some() || ahost.is_some(), aregions_s.is_empty()) {
        let regions: Vec<(u64, u64, u64)> = aregions_s
            .split(',')
            .filter(|e| !e.is_empty())
            .filter_map(|e| {
                let f: Vec<&str> = e.split(':').collect();
                match (
                    hx(f[0]),
                    f.get(1).and_then(|v| hx(v)),
                    f.get(2).and_then(|v| hx(v)),
                ) {
                    (Some(b0), Some(sz), Some(off)) => Some((b0, sz, off)),
                    _ => None,
                }
            })
            .collect();
        let allocs: Vec<(u64, u64, Option<u64>)> = allocs_s
            .split(',')
            .filter(|e| !e.is_empty())
            .filter_map(|e| {
                let mut fields = e.split(':');
                Some((
                    hx(fields.next()?)?,
                    hx(fields.next()?)?,
                    fields.next().and_then(hx),
                ))
            })
            .collect();
        // VA guard: reserve every golden non-VMM span at its exact address so
        // fresh allocations in this worker can never land inside one. The
        // session's dptr translation is RANGE-based — an untranslated fresh
        // pointer inside a golden range gets rewritten into the staged copy
        // (silent corruption) or past its end (async illegal address that
        // poisons the context: e=700 on every later op — found via QA-1l,
        // first-ever cuBLAS init inside a clone).
        for &(b0, sz, _) in &regions {
            if !range_is_reserved(pre_reserved, b0, sz)
                && !reserve_clone_address_exact(b, b0, sz, 0)
            {
                tracing::warn!(va = b0, size = sz, "M2-alloc: VA guard reserve failed");
            }
        }
        let total: u64 = regions.iter().map(|r| r.1).sum();
        // Ordinary cudaMalloc buffers can contain device-resident pointers and
        // TMA descriptors whose embedded addresses never cross an RPC boundary.
        // Rewriting only top-level kernel arguments is therefore insufficient.
        // The worker reserved these spans before creating its context; back the
        // same VAs with private VMM allocations so every embedded address stays
        // valid while each clone still owns independent physical memory.
        if ordinary_regions_are_reserved(&regions, pre_reserved) {
            for &(base, size, _) in &regions {
                let handle = b.mem_create(size, device).map_err(|error| {
                    io::Error::other(format!(
                        "address-preserving CUDA allocation failed for {base:#x}: {error}"
                    ))
                })?;
                b.mem_map(base, size, 0, handle).map_err(|error| {
                    io::Error::other(format!(
                        "address-preserving CUDA map failed for {base:#x}: {error}"
                    ))
                })?;
                b.mem_set_access(base, size, device).map_err(|error| {
                    io::Error::other(format!(
                        "address-preserving CUDA access failed for {base:#x}: {error}"
                    ))
                })?;
                // The mapping retains the allocation; drop the creation
                // handle now. The mapped region intentionally lives for the
                // clone worker's lifetime, and inherited cudaMalloc frees are
                // handled by the identity allocation registry below.
                b.mem_release(handle).map_err(|error| {
                    io::Error::other(format!(
                        "address-preserving CUDA handle release failed for {base:#x}: {error}"
                    ))
                })?;
            }
            if let Some(sidx) = ahost {
                for &(dptr, size, offset) in &allocs {
                    let Some(offset) = offset else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("missing host snapshot offset for CUDA allocation {dptr:#x}"),
                        ));
                    };
                    let bytes = read_host_snapshot(4 + sidx, offset, size)?;
                    b.memcpy_htod(dptr, &bytes, 0).map_err(|error| {
                        io::Error::other(format!(
                            "address-preserving CUDA restore failed for {dptr:#x}: {error}"
                        ))
                    })?;
                }
            } else if let Some(sidx) = astage {
                let source_handle = import_with_retry(b, 4 + sidx).map_err(|error| {
                    io::Error::other(format!("CUDA staging import failed: {error}"))
                })?;
                let source = b.mem_address_reserve(total, 0).map_err(|error| {
                    io::Error::other(format!("CUDA staging reservation failed: {error}"))
                })?;
                map_import_with_retry(b, source, total, 0, source_handle).map_err(|error| {
                    io::Error::other(format!("CUDA staging map failed: {error}"))
                })?;
                b.mem_set_access(source, total, device).map_err(|error| {
                    io::Error::other(format!("CUDA staging access failed: {error}"))
                })?;
                for &(base, size, offset) in &regions {
                    b.memcpy_dtod(base, source + offset, size)
                        .map_err(|error| {
                            io::Error::other(format!(
                                "address-preserving CUDA copy failed for {base:#x}: {error}"
                            ))
                        })?;
                }
                b.ctx_synchronize().map_err(|error| {
                    io::Error::other(format!(
                        "address-preserving CUDA synchronization failed: {error}"
                    ))
                })?;
                b.mem_unmap(source, total).map_err(|error| {
                    io::Error::other(format!("CUDA staging unmap failed: {error}"))
                })?;
                b.mem_address_free(source, total).map_err(|error| {
                    io::Error::other(format!("CUDA staging release failed: {error}"))
                })?;
                b.mem_release(source_handle).map_err(|error| {
                    io::Error::other(format!("CUDA staging handle release failed: {error}"))
                })?;
            }
            b.ctx_synchronize().map_err(|error| {
                io::Error::other(format!(
                    "address-preserving CUDA restore synchronization failed: {error}"
                ))
            })?;
            let identity = allocs
                .iter()
                .map(|&(dptr, size, _)| (dptr, size, dptr))
                .collect();
            smolvm_cuda::host::set_worker_alloc_trans(identity);
            tracing::info!(
                allocations = allocs.len(),
                regions = regions.len(),
                bytes = total,
                "M2-alloc: restored ordinary allocations at their golden addresses"
            );
            count += allocs.len();
            return Ok((count, vmm_trans));
        }
        if ahost.is_some() {
            return Err(io::Error::other(
                "ordinary CUDA host snapshot could not reserve every golden address",
            ));
        }
        let mut trans: Vec<(u64, u64, u64)> = Vec::new();
        if let Some(sidx) = ahost {
            for &(d, sz, offset) in &allocs {
                let Some(offset) = offset else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("missing host snapshot offset for CUDA allocation {d:#x}"),
                    ));
                };
                let cdptr = b.mem_alloc(sz).map_err(|error| {
                    io::Error::other(format!(
                        "CUDA allocation restore failed for {d:#x}: {error}"
                    ))
                })?;
                let bytes = read_host_snapshot(4 + sidx, offset, sz)?;
                b.memcpy_htod(cdptr, &bytes, 0).map_err(|error| {
                    io::Error::other(format!(
                        "CUDA allocation snapshot restore failed for {d:#x}: {error}"
                    ))
                })?;
                trans.push((d, sz, cdptr));
            }
            let _ = b.ctx_synchronize();
        } else if let Some(sidx) = astage {
            match import_with_retry(b, 4 + sidx) {
                Ok(sh) => {
                    if let Ok(tmp) = b.mem_address_reserve(total, 0) {
                        if b.mem_map(tmp, total, 0, sh).is_ok() {
                            let _ = b.mem_set_access(tmp, total, device);
                            for &(d, sz, _) in &allocs {
                                // Staging offset: region offset + intra-region delta.
                                let Some(&(base, _, off)) =
                                    regions.iter().find(|&&(b0, rs, _)| d >= b0 && d < b0 + rs)
                                else {
                                    continue;
                                };
                                let cdptr = match b.mem_alloc(sz) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        tracing::warn!(e, d, "M2-alloc: copy alloc failed");
                                        continue;
                                    }
                                };
                                if let Err(e) = b.memcpy_dtod(cdptr, tmp + off + (d - base), sz) {
                                    tracing::warn!(e, d, "M2-alloc: dtod failed");
                                }
                                trans.push((d, sz, cdptr));
                            }
                            let _ = b.ctx_synchronize();
                            let _ = b.mem_unmap(tmp, total);
                        } else {
                            tracing::warn!("M2-alloc: staging map failed");
                        }
                        let _ = b.mem_address_free(tmp, total);
                    }
                    let _ = b.mem_release(sh);
                }
                Err(e) => tracing::warn!(e, "M2-alloc: staging import failed"),
            }
        }
        tracing::info!(
            copies = trans.len(),
            of = allocs.len(),
            bytes = total,
            "M2-alloc: private translated copies of the golden's non-VMM allocations"
        );
        count += trans.len();
        smolvm_cuda::host::set_worker_alloc_trans(trans);
    }
    Ok((count, vmm_trans))
}

#[cfg(target_os = "linux")]
fn map_module_blob_fd(fd: std::os::fd::RawFd) -> io::Result<smolvm_cuda::host::ModuleHandoffBytes> {
    // Take an independent owned descriptor before closing the inherited slot.
    // Every worker maps the same immutable file pages, so staging does not
    // allocate and copy the entire handoff into private anonymous memory.
    let owned = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    let duplicate_error = io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if owned < 0 {
        return Err(duplicate_error);
    }
    let file = unsafe { std::fs::File::from_raw_fd(owned) };
    let metadata = file.metadata()?;
    let bytes = metadata.len();
    if !metadata.file_type().is_file() || bytes == 0 || bytes > MAX_MODULE_HANDOFF_BLOB_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CUDA module handoff source has invalid size or type",
        ));
    }
    let bytes = usize::try_from(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "CUDA module handoff source does not fit in address space",
        )
    })?;
    // SAFETY: `file` is a read-only reopen of the daemon-owned unnamed handoff
    // inode. Its only writable descriptor was dropped before caching, so the
    // inode cannot be changed or truncated while workers map it.
    unsafe { smolvm_cuda::host::ModuleHandoffBytes::map_read_only(&file, bytes) }
}

/// M3a: parse the golden's module IMAGES + function METADATA (for LAZY reload in
/// THIS worker at first use — reloading ~400 modules up front stalls the clone
/// ~2s and breaks its connection) and RECREATE its streams/events now (few,
/// cheap). Returns `(mod_images, func_meta, streams, events)`. Parses the blob
/// inherited from the daemon:
/// `[u32 nmods]([u64 h][u32 len][image])* [u32 nfuncs]([u64 fn][u64 mod][u32 len][name])*
///  [u32 nstreams]([u64 h][u32 flags])* [u32 nevents]([u64 h][u32 flags])*`.
#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn reconstruct_golden_modules(
    b: &mut dyn Backend,
    source: &smolvm_cuda::host::ModuleHandoffBytes,
    external_module_images: Option<&smolvm_cuda::host::ModuleHandoffBytes>,
) -> io::Result<(
    Vec<(u64, smolvm_cuda::host::ModuleHandoffBytes)>,
    Vec<smolvm_cuda::host::FuncMeta>,
    Vec<(u64, u64)>,
    Vec<(u64, u64)>,
    Vec<(u64, u64, smolvm_cuda::host::GraphSer)>,
    Vec<(u8, u16, u64, Vec<u8>)>,
)> {
    let buf = source.as_slice();
    let mut mod_images = Vec::new();
    let mut func_meta = Vec::new();
    let mut stream_trans = Vec::new();
    let mut event_trans = Vec::new();
    let mut graphs: Vec<(u64, u64, smolvm_cuda::host::GraphSer)> = Vec::new();
    let mut lib_handles: Vec<(u8, u16, u64, Vec<u8>)> = Vec::new();
    let mut p = 0usize;
    macro_rules! need {
        ($n:expr) => {
            if p.checked_add($n).is_none_or(|end| end > buf.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CUDA module handoff is truncated",
                ));
            }
        };
    }
    macro_rules! ru32 {
        () => {{
            need!(4);
            let v = u32::from_le_bytes(buf[p..p + 4].try_into().unwrap());
            p += 4;
            v
        }};
    }
    macro_rules! ru64 {
        () => {{
            need!(8);
            let v = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
            p += 8;
            v
        }};
    }
    let uses_external_images = buf.starts_with(&EXTERNAL_MODULE_IMAGES_MAGIC);
    if uses_external_images {
        p += EXTERNAL_MODULE_IMAGES_MAGIC.len();
        if external_module_images.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CUDA module handoff requires a missing external image store",
            ));
        }
    }
    // Modules: just STAGE the images (reloaded lazily on first use in the worker).
    let nmods = ru32!();
    for _ in 0..nmods {
        let gh = ru64!();
        if uses_external_images {
            let offset = usize::try_from(ru64!()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CUDA module image offset does not fit in address space",
                )
            })?;
            let length = ru32!() as usize;
            let image = external_module_images
                .and_then(|images| images.slice(offset, length))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "CUDA module image range exceeds its external store",
                    )
                })?;
            mod_images.push((gh, image));
        } else {
            let ilen = ru32!() as usize;
            need!(ilen);
            // `need!` proved this range is within the immutable source.
            mod_images.push((gh, source.slice(p, ilen).unwrap()));
            p += ilen;
        }
    }
    // Functions: stage golden fn → (golden module, name); resolved lazily.
    let nfuncs = ru32!();
    for _ in 0..nfuncs {
        let gf = ru64!();
        let gm = ru64!();
        let nlen = ru32!() as usize;
        need!(nlen);
        let name = String::from_utf8_lossy(&buf[p..p + nlen]).into_owned();
        p += nlen;
        let nattrs = ru32!();
        let mut attrs = Vec::with_capacity(nattrs as usize);
        for _ in 0..nattrs {
            let a = ru32!() as i32;
            let v = ru32!() as i32;
            attrs.push((a, v));
        }
        func_meta.push((gf, gm, name, attrs));
    }
    // Streams + events: recreate each with its golden create flags in OUR context,
    // mapping the golden's inherited raw handle → our own (same M3a pattern).
    let nstreams = ru32!();
    for _ in 0..nstreams {
        let gs = ru64!();
        let flags = ru32!();
        match b.stream_create(flags) {
            Ok(ws) => stream_trans.push((gs, ws)),
            Err(e) => tracing::warn!(e, "M3a: stream recreate failed"),
        }
    }
    let nevents = ru32!();
    for _ in 0..nevents {
        let ge = ru64!();
        let flags = ru32!();
        match b.event_create(flags) {
            Ok(we) => event_trans.push((ge, we)),
            Err(e) => tracing::warn!(e, "M3a: event recreate failed"),
        }
    }
    // M3b: parse captured graphs (rebuilt later, after set_handle_trans). Absent
    // in older blobs → the `p < buf.len()` guard leaves `graphs` empty.
    if p < buf.len() {
        let ngraphs = ru32!();
        for _ in 0..ngraphs {
            let graph_vh = ru64!();
            let exec_vh = ru64!();
            let nnodes = ru32!();
            let mut nodes = Vec::with_capacity(nnodes as usize);
            for _ in 0..nnodes {
                let func = ru64!();
                let mut d = [0u32; 7];
                for v in d.iter_mut() {
                    *v = ru32!();
                }
                let nparams = ru32!();
                let mut params = Vec::with_capacity(nparams as usize);
                for _ in 0..nparams {
                    let plen = ru32!() as usize;
                    need!(plen);
                    params.push(buf[p..p + plen].to_vec());
                    p += plen;
                }
                nodes.push(smolvm_cuda::host::GraphKernelNode {
                    func,
                    grid: [d[0], d[1], d[2]],
                    block: [d[3], d[4], d[5]],
                    shared_mem: d[6],
                    params,
                });
            }
            let nedges = ru32!();
            let mut edges = Vec::with_capacity(nedges as usize);
            for _ in 0..nedges {
                let f = ru32!();
                let t = ru32!();
                edges.push((f, t));
            }
            graphs.push((
                graph_vh,
                exec_vh,
                smolvm_cuda::host::GraphSer { nodes, edges },
            ));
        }
    }
    // Library-handle creates to replay in this worker (absent in older blobs).
    if p < buf.len() {
        let nlh = ru32!();
        for _ in 0..nlh {
            need!(1);
            let lib = buf[p];
            p += 1;
            need!(2);
            let func = u16::from_le_bytes(buf[p..p + 2].try_into().unwrap());
            p += 2;
            let h = ru64!();
            let alen = ru32!() as usize;
            need!(alen);
            let args = buf[p..p + alen].to_vec();
            p += alen;
            lib_handles.push((lib, func, h, args));
        }
    }
    // P3b: capture-replay op-logs (absent in older blobs). Installed into a
    // thread-local for the serving session to drain and replay lazily.
    let mut noplogs = 0usize;
    if p < buf.len() {
        let ng = ru32!();
        let mut oplogs: Vec<(u64, u64, Vec<Vec<u8>>)> = Vec::with_capacity(ng as usize);
        for _ in 0..ng {
            let graph_vh = ru64!();
            let exec_vh = ru64!();
            let nops = ru32!();
            let mut ops = Vec::with_capacity(nops as usize);
            for _ in 0..nops {
                let olen = ru32!() as usize;
                need!(olen);
                ops.push(buf[p..p + olen].to_vec());
                p += olen;
            }
            oplogs.push((graph_vh, exec_vh, ops));
        }
        noplogs = oplogs.len();
        smolvm_cuda::host::set_worker_graph_oplogs(oplogs);
    }
    tracing::info!(
        nmods,
        nfuncs,
        nstreams,
        nevents,
        ngraphs = graphs.len(),
        noplogs,
        streams = stream_trans.len(),
        events = event_trans.len(),
        lib_handles = lib_handles.len(),
        "M3a: staged golden modules/functions for lazy reload + recreated streams/events"
    );
    Ok((
        mod_images,
        func_meta,
        stream_trans,
        event_trans,
        graphs,
        lib_handles,
    ))
}

/// Strip a fork-clone connection preamble (magic + clone id) if present,
/// returning the clone id. The preamble is sent by a CLONE VM's proxy before
/// any RPC frames (see `cuda_host::proxy_to_daemon`); the GOLDEN's connections
/// never carry it. Must run on every accepted connection REGARDLESS of routing
/// mode — an unconsumed preamble would corrupt the frame stream. Non-preamble
/// connections are left untouched (peek only).
#[cfg(unix)]
fn consume_clone_preamble(fd: std::os::unix::io::RawFd) -> Option<(u64, u8)> {
    let mut buf = [0u8; 17];
    // Same buffered-in-pieces caveat as peek_clone_token: retry the peek
    // briefly so a slow proxy write can't make us misread the magic.
    let mut n: isize = 0;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        // Enough to decide: 8 bytes tells us magic-or-not; 16 is the full
        // preamble. A legit first frame is ≥ 5 bytes, so a short non-magic
        // prefix resolves as soon as the magic mismatches.
        if n >= 8 && buf[..(n as usize).min(8)] != smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC {
            return None;
        }
        if n >= 17 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 17 || buf[..8] != smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC {
        return None;
    }
    // Consume exactly the 17 preamble bytes, leaving the RPC stream intact.
    // SAFETY: plain recv on a valid fd; MSG_WAITALL for the already-peeked bytes.
    let c = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            17,
            libc::MSG_WAITALL,
        )
    };
    if c != 17 {
        return None;
    }
    Some((u64::from_le_bytes(buf[8..16].try_into().unwrap()), buf[16]))
}

/// Live clone workers keyed by (lineage token, clone id) → (worker pid,
/// control fd). New connections from a clone whose worker is STILL ALIVE are
/// ATTACHED to that worker over the control fd (SCM_RIGHTS) — guests open
/// fresh daemon channels after the fork (first-ever cuBLAS init inside a
/// clone does), and a fresh worker would re-reconstruct from the golden and
/// silently DISCARD the clone's accumulated GPU state. Dead entries are
/// replaced (worker crash → a fresh worker is the best recovery available).
#[cfg(unix)]
type CloneWorkerEntry = (u32, std::os::unix::io::RawFd);
#[cfg(unix)]
fn clone_worker_registry() -> &'static Mutex<std::collections::HashMap<(u64, u64), CloneWorkerEntry>>
{
    static REG: OnceLock<Mutex<std::collections::HashMap<(u64, u64), CloneWorkerEntry>>> =
        OnceLock::new();
    REG.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn daemon_has_live_cuda_clients(connections: usize, workers: usize, snapshots: usize) -> bool {
    connections > 0 || workers > 0 || snapshots > 0
}

#[cfg(unix)]
fn live_clone_worker_count() -> usize {
    let mut reg = clone_worker_registry().lock().unwrap();
    reg.retain(|_, entry| {
        let (pid, ctrl) = *entry;
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            true
        } else {
            unsafe { libc::close(ctrl) };
            false
        }
    });
    reg.len()
}

#[cfg(unix)]
struct GoldenConnectionEntry {
    id: u64,
    token: u64,
    fd: std::os::unix::io::RawFd,
}

#[cfg(unix)]
fn golden_connection_registry(
) -> &'static Mutex<std::collections::HashMap<u32, Vec<GoldenConnectionEntry>>> {
    static REG: OnceLock<Mutex<std::collections::HashMap<u32, Vec<GoldenConnectionEntry>>>> =
        OnceLock::new();
    REG.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(unix)]
fn golden_token_owners() -> &'static Mutex<std::collections::HashMap<u64, u32>> {
    static OWNERS: OnceLock<Mutex<std::collections::HashMap<u64, u32>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(unix)]
struct GoldenConnectionGuard {
    pid: u32,
    id: u64,
}

#[cfg(unix)]
impl GoldenConnectionGuard {
    fn register(pid: u32, token: u64, fd: std::os::unix::io::RawFd) -> Option<Self> {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        // A duplicate lets the pool coordinator shut down the socket while the
        // serving thread owns the accepted fd. shutdown(2) affects the shared
        // socket endpoint and wakes the blocked serve loop; this duplicate is
        // otherwise closed when the connection ends.
        let duplicate = unsafe { libc::dup(fd) };
        if duplicate < 0 {
            return None;
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        golden_connection_registry()
            .lock()
            .unwrap()
            .entry(pid)
            .or_default()
            .push(GoldenConnectionEntry {
                id,
                token,
                fd: duplicate,
            });
        if token != 0 {
            golden_token_owners().lock().unwrap().insert(token, pid);
        }
        Some(Self { pid, id })
    }
}

#[cfg(unix)]
impl Drop for GoldenConnectionGuard {
    fn drop(&mut self) {
        let mut registry = golden_connection_registry().lock().unwrap();
        let mut remove_pid = false;
        if let Some(entries) = registry.get_mut(&self.pid) {
            if let Some(index) = entries.iter().position(|entry| entry.id == self.id) {
                let entry = entries.swap_remove(index);
                unsafe { libc::close(entry.fd) };
            }
            remove_pid = entries.is_empty();
        }
        if remove_pid {
            registry.remove(&self.pid);
            golden_token_owners()
                .lock()
                .unwrap()
                .retain(|_, owner| *owner != self.pid);
        }
    }
}

#[cfg(unix)]
fn select_golden_owner(
    mut matching: Vec<u32>,
    known_owner: Option<u32>,
    registered: &[u32],
) -> Option<u32> {
    if let Some(owner) = known_owner.filter(|owner| registered.contains(owner)) {
        matching.push(owner);
    }
    if matching.is_empty() && registered.len() == 1 {
        matching.push(registered[0]);
    }
    matching.sort_unstable();
    matching.dedup();
    let [owner] = matching.as_slice() else {
        return None;
    };
    Some(*owner)
}

#[cfg(unix)]
fn evict_golden_cuda_connections(token: u64) -> usize {
    let mut registry = golden_connection_registry().lock().unwrap();
    let matching: Vec<u32> = registry
        .iter()
        .filter_map(|(&pid, entries)| {
            entries
                .iter()
                .any(|entry| {
                    entry.token == token
                        || smolvm_cuda::host::layout_handoff_same_process(entry.token, token)
                })
                .then_some(pid)
        })
        .collect();
    let known_owner = golden_token_owners().lock().unwrap().get(&token).copied();
    let registered: Vec<u32> = registry.keys().copied().collect();
    // The initial golden channel legitimately carries token 0: the daemon
    // assigns the process lineage during Init. If no later token-bearing
    // channel established the owner mapping, fail closed unless exactly one
    // golden VMM is registered with this single-tenant CUDA daemon.
    let Some(owner) = select_golden_owner(matching, known_owner, &registered) else {
        return 0;
    };
    golden_token_owners().lock().unwrap().insert(token, owner);
    bind_host_snapshot_owner(token, owner);
    let mut closed = 0;
    if let Some(entries) = registry.remove(&owner) {
        for entry in entries {
            // SAFETY: a duplicate owned by this registry. shutdown wakes
            // both relay directions; close releases our duplicate.
            unsafe {
                libc::shutdown(entry.fd, libc::SHUT_RDWR);
                libc::close(entry.fd);
            }
            closed += 1;
        }
    }
    closed
}

#[cfg(unix)]
fn maybe_evict_frozen_golden(
    token: u64,
    options: &ServeOptions,
    workers: &std::collections::HashMap<(u64, u64), CloneWorkerEntry>,
) {
    let mode = std::env::var("SMOLVM_CUDA_GOLDEN_EVICT").ok();
    if !golden_eviction_enabled(mode.as_deref(), options.fork_pool_size) {
        return;
    }
    let Some(pool_size) = options.fork_pool_size else {
        return;
    };
    let residents = workers
        .keys()
        .filter(|&&(candidate, _)| {
            candidate == token || smolvm_cuda::host::layout_handoff_same_process(candidate, token)
        })
        .count();
    if residents < pool_size as usize {
        return;
    }
    if cached_host_snapshot(token).is_none() {
        tracing::debug!(
            token,
            residents,
            pool_size,
            "golden eviction skipped because this process has no host snapshot"
        );
        return;
    }
    let closed = evict_golden_cuda_connections(token);
    if closed > 0 {
        tracing::info!(
            token,
            residents,
            pool_size,
            connections = closed,
            "evicted frozen golden CUDA connections after pool residency"
        );
    }
}

#[cfg(not(unix))]
fn live_clone_worker_count() -> usize {
    0
}

/// Metadata-only golden layouts retained for clones whose corresponding helper
/// process has not connected yet: token -> (clone id -> local VMM pid). The
/// strong layout reference is released after every waiter either starts its
/// helper worker or its VMM exits.
#[cfg(unix)]
fn metadata_layout_waiters(
) -> &'static Mutex<std::collections::HashMap<u64, std::collections::HashMap<u64, u32>>> {
    static WAITERS: OnceLock<
        Mutex<std::collections::HashMap<u64, std::collections::HashMap<u64, u32>>>,
    > = OnceLock::new();
    WAITERS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(unix)]
fn retain_metadata_layout_for_clone(token: u64, clone_id: u64, vm_pid: u32) -> bool {
    // A frozen memory-bearing layout is also held strongly by the metadata
    // cache after golden eviction, but its ordinary-allocation handoff has
    // already moved into host_snapshot_cache. Do not reclassify that layout as
    // a metadata-only helper: completing the resulting waiter set would drop
    // the module/function/handle metadata needed by later pool replacements.
    if cached_host_snapshot(token).is_some() {
        return false;
    }
    let mut waiters = metadata_layout_waiters().lock().unwrap();
    if !smolvm_cuda::host::cache_metadata_only_layout(token) {
        return false;
    }
    waiters.entry(token).or_default().insert(clone_id, vm_pid);
    true
}

#[cfg(unix)]
fn complete_metadata_layout_waiter(token: u64, clone_id: u64) {
    let releases = {
        let mut waiters = metadata_layout_waiters().lock().unwrap();
        let matching: Vec<u64> = waiters
            .keys()
            .copied()
            .filter(|&candidate| {
                candidate == token
                    || smolvm_cuda::host::layout_handoff_same_process(candidate, token)
            })
            .collect();
        let mut releases = Vec::new();
        for candidate in matching {
            if let Some(clones) = waiters.get_mut(&candidate) {
                clones.remove(&clone_id);
                if clones.is_empty() {
                    releases.push(candidate);
                }
            }
        }
        for candidate in &releases {
            waiters.remove(candidate);
        }
        releases
    };
    for candidate in releases {
        if smolvm_cuda::host::release_metadata_only_layout(candidate) {
            tracing::info!(
                token = candidate,
                "released metadata-only process layout after all waiting clones connected"
            );
        }
    }
}

#[cfg(unix)]
fn prune_dead_metadata_layout_waiters() {
    let releases = {
        let mut waiters = metadata_layout_waiters().lock().unwrap();
        let mut releases = Vec::new();
        for (&token, clones) in waiters.iter_mut() {
            clones.retain(|_, &mut pid| {
                pid == 0 || unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
            });
            if clones.is_empty() {
                releases.push(token);
            }
        }
        for token in &releases {
            waiters.remove(token);
        }
        releases
    };
    for token in releases {
        if smolvm_cuda::host::release_metadata_only_layout(token) {
            tracing::info!(
                token,
                "released metadata-only process layout after clone exit"
            );
        }
    }
}

#[cfg(unix)]
fn unique_live_clone_worker(
    reg: &std::collections::HashMap<(u64, u64), CloneWorkerEntry>,
    clone_id: u64,
    mut is_live: impl FnMut(u32) -> bool,
) -> Result<Option<CloneWorkerEntry>, usize> {
    let mut live = reg
        .iter()
        .filter_map(|(&(_, cid), &entry)| (cid == clone_id && is_live(entry.0)).then_some(entry))
        .collect::<Vec<_>>();
    match live.len() {
        0 => Ok(None),
        1 => Ok(live.pop()),
        n => Err(n),
    }
}

fn clone_worker_share_env(requested: bool, configured: Option<&str>) -> Option<&'static str> {
    if matches!(configured, Some("0" | "false" | "off")) {
        Some("0")
    } else if requested {
        Some("1")
    } else {
        None
    }
}

#[cfg(unix)]
fn clone_worker_spawn_pace(pool_size: Option<u32>) -> Duration {
    #[cfg(target_os = "linux")]
    if pool_size.is_some_and(|size| size > 4) {
        // Launching more than four reconstructed CUDA contexts in one burst
        // can starve concurrent KVM first-entry long enough to exhaust its
        // bounded transient-ENOMEM retry window. The old fork/exec path paced
        // workers accidentally while copying the daemon's page tables; retain
        // only the measured minimum interval after switching to posix_spawn.
        return Duration::from_millis(20);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = pool_size;
    Duration::ZERO
}

/// Decide whether a clone-marked connection should bypass worker routing when
/// worker mode is disabled. Real channels fall through to ordinary serving;
/// warm dials carry no Init and must be consumed instead of parking forever.
fn disabled_worker_route(flags: u8, workers: bool, isolate: bool) -> Option<bool> {
    (!workers || !isolate).then_some(flags & 2 != 0)
}

/// Route one just-accepted connection: strip the clone preamble (always), and
/// when it marks an isolating fork clone, spawn/refuse its worker. Returns
/// `true` when the connection was consumed (routed or rejected); `false` means
/// the caller serves it normally — including a GOLDEN's own reconnect, whose
/// token-bearing Init WITHOUT the preamble must resume in-daemon (a worker
/// would silently serve it a reconstructed COPY of its memory).
#[cfg(unix)]
fn route_clone_connection(
    fd: std::os::unix::io::RawFd,
    ring_dir: Option<&str>,
    procmem: Option<ProcMemAdvert>,
    options: &mut ServeOptions,
) -> bool {
    let Some((clone_id, flags)) = consume_clone_preamble(fd) else {
        return false;
    };
    // Shared-context clones fall through to ordinary serving, while isolated
    // clones route into a worker process. Both need a per-clone private-growth
    // budget rather than the golden's model-load budget.
    options.fork_clone = true;
    // The preamble must always be stripped, but a warm-dial connection must
    // not bypass the worker-mode gate below. Previously the warm branch spawned
    // a Path-3 worker unconditionally, so `SMOLVM_CUDA_FORK_WORKERS` unset still
    // mixed worker contexts into the legacy single-context path.
    if let Some(consumed) = disabled_worker_route(
        flags,
        std::env::var_os("SMOLVM_CUDA_FORK_WORKERS").is_some(),
        std::env::var_os("SMOLVM_CUDA_FORK_ISOLATE").is_some(),
    ) {
        // Real clone connections still fall through to the shared-context
        // server. A warm dial has no Init payload, so consume it instead of
        // parking an otherwise permanent server thread on an idle socket.
        return consumed;
    }
    let share_weights = flags & 1 != 0;
    let preload_modules = flags & 4 != 0;
    // Warm dial (flag bit 1): the clone VM's proxy dials at STARTUP so worker
    // spawn (CUDA init + memory reconstruction + module/graph pre-warm) runs
    // concurrent with guest resume instead of on the guest's first CUDA call.
    // No Init ever arrives on this connection — it parks as the worker's idle
    // primary channel. A metadata-only helper layout is retained for lazy
    // reconstruction instead of being initialized here: creating a helper's
    // CUDA context before that guest process runs can poison its later module
    // state. Only an unambiguous memory-bearing layout is safe to pre-warm.
    if flags & 2 != 0 {
        let mut reg = clone_worker_registry().lock().unwrap();
        let live = reg.iter().find_map(|(&(_, cid), &(pid, ctrl))| {
            // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
            (cid == clone_id && unsafe { libc::kill(pid as i32, 0) } == 0).then_some((pid, ctrl))
        });
        if let Some((_pid, ctrl)) = live {
            // Worker already up (a real channel won the race): park there.
            let _ = send_fd(ctrl, fd, procmem.as_ref());
            return true;
        }
        let tokens = smolvm_cuda::host::layout_tokens();
        if tokens.is_empty() {
            if let Some((vm_pid, _)) = procmem.as_ref() {
                if let Err(error) = publish_clone_worker_status(*vm_pid, CloneWorkerStatus::Ready) {
                    tracing::warn!(vm_pid, %error, "failed to publish empty CUDA clone readiness");
                }
            }
            tracing::info!(
                clone_id,
                "warm dial: no golden process layouts yet; deferring spawn to first real channel"
            );
            return true;
        }
        let mut memory_tokens = Vec::new();
        let clone_vm_pid = procmem.as_ref().map_or(0, |(pid, _)| *pid);
        for token in tokens {
            if retain_metadata_layout_for_clone(token, clone_id, clone_vm_pid) {
                tracing::info!(
                    token,
                    clone_id,
                    "warm dial: retained metadata-only process layout for lazy reconstruction"
                );
            } else {
                memory_tokens.push(token);
            }
        }
        let [token] = memory_tokens.as_slice() else {
            if memory_tokens.is_empty() {
                if let Some((vm_pid, _)) = procmem.as_ref() {
                    if let Err(error) =
                        publish_clone_worker_status(*vm_pid, CloneWorkerStatus::Ready)
                    {
                        tracing::warn!(vm_pid, %error, "failed to publish metadata-only CUDA clone readiness");
                    }
                }
            }
            tracing::info!(
                clone_id,
                layouts = memory_tokens.len(),
                "warm dial: memory-bearing process layout is ambiguous; deferring spawn to first real channel"
            );
            return true;
        };
        return match spawn_clone_worker(
            fd,
            *token,
            share_weights,
            preload_modules,
            ring_dir,
            procmem.clone(),
            *options,
        ) {
            Ok((pid, ctrl)) => {
                reg.insert((*token, clone_id), (pid, ctrl));
                tracing::info!(
                    token,
                    clone_id,
                    worker_pid = pid,
                    "warm dial: spawned clone process worker ahead of its first CUDA call"
                );
                std::thread::sleep(clone_worker_spawn_pace(options.fork_pool_size));
                maybe_evict_frozen_golden(*token, options, &reg);
                true
            }
            Err(e) => {
                if let Some((vm_pid, _)) = procmem.as_ref() {
                    let _ = publish_clone_worker_status(*vm_pid, CloneWorkerStatus::Failed);
                }
                tracing::warn!(error = %e, token, clone_id, "warm dial: process worker spawn failed");
                true
            }
        };
    }
    let Some(token) = peek_clone_token(fd) else {
        // A clone VM's connection whose Init carries no lineage token. The
        // guest treats CUDA state as process-global, so if this clone already
        // has exactly one live worker, the channel MUST serve there: a cuBLAS
        // handle created through an in-daemon session is invisible to the
        // worker's sessions (vh-miss → NOT_INITIALIZED on the compute
        // channel). A real VM can contain multiple CUDA processes and thus
        // multiple workers, however. With no token there is no safe way to
        // select between them; reject that ambiguous connection rather than
        // silently grafting it onto an unrelated process/context.
        let reg = clone_worker_registry().lock().unwrap();
        let live = unique_live_clone_worker(&reg, clone_id, |pid| {
            // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
            unsafe { libc::kill(pid as i32, 0) == 0 }
        });
        let (pid, ctrl) = match live {
            Err(workers) => {
                tracing::warn!(
                    clone_id,
                    workers,
                    "rejecting ambiguous token-less clone channel"
                );
                return true;
            }
            Ok(None) => return false,
            Ok(Some(worker)) => worker,
        };
        {
            match send_fd(ctrl, fd, procmem.as_ref()) {
                Ok(()) => {
                    tracing::info!(
                        clone_id,
                        worker_pid = pid,
                        "attached token-less clone channel to its live worker"
                    );
                    return true; // worker owns an in-flight dup; caller drops its copy
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        clone_id,
                        worker_pid = pid,
                        "token-less channel attach failed; rejecting the connection"
                    );
                    return true;
                }
            }
        }
    };
    let mut reg = clone_worker_registry().lock().unwrap();
    if let Some(&(pid, ctrl)) = reg.get(&(token, clone_id)) {
        // Reap first: an exited worker stays a ZOMBIE (the daemon is its parent
        // and nothing waits on it), and kill(pid, 0) reports zombies as alive —
        // without this, one worker death makes every reconnect of that clone
        // rejected forever (observed as a 54/s reconnect storm on H100).
        // Reaping also surfaces HOW it died, which nothing logged before.
        let mut status: libc::c_int = 0;
        // SAFETY: WNOHANG waitpid on our own child; no blocking, no signals.
        let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if r == pid as i32 {
            let (code, sig) = (
                libc::WEXITSTATUS(status),
                if libc::WIFSIGNALED(status) {
                    libc::WTERMSIG(status)
                } else {
                    0
                },
            );
            tracing::warn!(
                token,
                clone_id,
                worker_pid = pid,
                exit_code = code,
                signal = sig,
                "clone worker had exited; reaped — spawning a fresh worker for the reconnect"
            );
        }
        // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
        else if unsafe { libc::kill(pid as i32, 0) } == 0 {
            // The clone opened ANOTHER channel (guests dial fresh connections
            // post-fork — e.g. first cuBLAS init). Hand the fd to the live
            // worker so the channel serves in the clone's context; a fresh
            // worker would silently reset the clone's GPU state, and serving
            // in-daemon would split the guest across two UVA spaces.
            match send_fd(ctrl, fd, procmem.as_ref()) {
                Ok(()) => {
                    tracing::info!(
                        token,
                        clone_id,
                        worker_pid = pid,
                        "attached new clone channel to its live worker"
                    );
                    return true; // worker owns an in-flight dup; caller drops its copy
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        token,
                        clone_id,
                        worker_pid = pid,
                        "channel attach to live worker failed; rejecting the connection"
                    );
                    return true; // consumed: caller drops the stream (fail fast)
                }
            }
        }
        reg.remove(&(token, clone_id));
        // SAFETY: control fd of a dead/reaped worker.
        unsafe { libc::close(ctrl) };
    }
    // A warm-dial worker may be registered under an INFERRED token. Attach
    // across tokens only when both tokens share the same process-scoped
    // GoldenLayout. Real workloads can have several CUDA processes inside one
    // VM (observed with Unsloth SFT preprocessing); blindly attaching the
    // trainer to the preprocessing worker reconstructs the wrong address space
    // and crashes the worker.
    let live = reg.iter().find_map(|(&(t, cid), &(pid, ctrl))| {
        // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
        (cid == clone_id
            && t != token
            && smolvm_cuda::host::layout_handoff_same_process(t, token)
            && unsafe { libc::kill(pid as i32, 0) } == 0)
            .then_some((pid, ctrl))
    });
    if let Some((pid, ctrl)) = live {
        match send_fd(ctrl, fd, procmem.as_ref()) {
            Ok(()) => {
                tracing::info!(
                    token,
                    clone_id,
                    worker_pid = pid,
                    "attached tokened clone channel to its (warm-spawned) live worker"
                );
                return true;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    token,
                    clone_id,
                    worker_pid = pid,
                    "attach to warm worker failed; spawning fresh"
                );
            }
        }
    }
    match spawn_clone_worker(
        fd,
        token,
        share_weights,
        preload_modules,
        ring_dir,
        procmem.clone(),
        *options,
    ) {
        Ok((pid, ctrl)) => {
            reg.insert((token, clone_id), (pid, ctrl));
            complete_metadata_layout_waiter(token, clone_id);
            tracing::info!(
                token,
                clone_id,
                worker_pid = pid,
                share_weights,
                "routed isolating clone to a worker process"
            );
            maybe_evict_frozen_golden(token, options, &reg);
        }
        Err(e) => {
            if let Some((vm_pid, _)) = procmem.as_ref() {
                let _ = publish_clone_worker_status(*vm_pid, CloneWorkerStatus::Failed);
            }
            // REJECT rather than serve in-process: this IS an isolating clone
            // (preamble matched), and the legacy shared path can't serve it —
            // its inherited pointers are garbage in a fresh context, so the
            // guest would wedge mid-training. Closing makes it fail fast.
            tracing::warn!(error = %e, token, "clone-worker spawn failed; rejecting the clone connection");
        }
    }
    true
}

const ATTACH_PROCMEM_MAGIC: [u8; 4] = *b"PMV1";

fn encode_attach_procmem(procmem: Option<&ProcMemAdvert>) -> Vec<u8> {
    let mut data = Vec::with_capacity(12 + procmem.map_or(0, |(_, r)| r.len() * 24));
    data.extend_from_slice(&ATTACH_PROCMEM_MAGIC);
    match procmem {
        Some((pid, regions)) => {
            data.extend_from_slice(&pid.to_le_bytes());
            data.extend_from_slice(&(regions.len() as u32).to_le_bytes());
            for (gpa, hva, len) in regions {
                data.extend_from_slice(&gpa.to_le_bytes());
                data.extend_from_slice(&hva.to_le_bytes());
                data.extend_from_slice(&len.to_le_bytes());
            }
        }
        None => {
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    data
}

fn decode_attach_procmem(data: &[u8]) -> io::Result<Option<ProcMemAdvert>> {
    if data.len() < 12 || data[..4] != ATTACH_PROCMEM_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid clone attach metadata (len={}, head={:02x?})",
                data.len(),
                &data[..data.len().min(12)]
            ),
        ));
    }
    let pid = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let n = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let expected = 12usize
        .checked_add(n.checked_mul(24).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "clone attach region overflow")
        })?)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "clone attach metadata overflow")
        })?;
    if data.len() != expected || (pid == 0) != (n == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inconsistent clone attach metadata",
        ));
    }
    if n == 0 {
        return Ok(None);
    }
    let mut regions = Vec::with_capacity(n);
    for chunk in data[12..].as_chunks::<24>().0 {
        regions.push((
            u64::from_le_bytes(chunk[0..8].try_into().unwrap()),
            u64::from_le_bytes(chunk[8..16].try_into().unwrap()),
            u64::from_le_bytes(chunk[16..24].try_into().unwrap()),
        ));
    }
    Ok(Some((pid, regions)))
}

/// SCM_RIGHTS-send one fd plus the accepted clone connection's live-RAM
/// advert. A warm-spawned worker predates that advert, so forwarding it here
/// is what lets late-attached channels use the clone's COW guest pages rather
/// than failing every GPA copy with CUDA_ERROR_NOT_FOUND.
#[cfg(unix)]
fn send_fd(
    chan: std::os::unix::io::RawFd,
    fd: std::os::unix::io::RawFd,
    procmem: Option<&ProcMemAdvert>,
) -> io::Result<()> {
    let mut data = encode_attach_procmem(procmem);
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: standard sendmsg with a single SCM_RIGHTS cmsg over buffers that
    // outlive the call; CMSG_* macros compute the layout.
    unsafe {
        let mut cmsgbuf = [0u8; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&fd as *const i32 as *const u8, libc::CMSG_DATA(c), 4);
        let n = libc::sendmsg(chan, &msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short clone attach control message",
            ));
        }
    }
    Ok(())
}

/// Blocking receive of one SCM_RIGHTS fd and its optional live-RAM advert;
/// `Err` on close/garbage ends the worker's attach listener.
#[cfg(unix)]
fn recv_fd(
    chan: std::os::unix::io::RawFd,
) -> io::Result<(std::os::unix::io::RawFd, Option<ProcMemAdvert>)> {
    let mut data = [0u8; 4096];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: standard recvmsg with room for one SCM_RIGHTS cmsg; buffers
    // outlive the call.
    unsafe {
        let mut cmsgbuf = [0u8; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let n = libc::recvmsg(chan, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "control channel closed",
            ));
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control message without an fd",
            ));
        }
        let mut fd: i32 = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut i32 as *mut u8, 4);
        match decode_attach_procmem(&data[..n as usize]) {
            Ok(procmem) => Ok((fd, procmem)),
            Err(e) => {
                // We own the SCM_RIGHTS duplicate once recvmsg succeeds.
                // Malformed metadata must not leak one fd per bad packet.
                libc::close(fd);
                Err(e)
            }
        }
    }
}

/// Path 3 (M1): peek a just-accepted connection's first message; true iff it's an
/// isolating fork-clone Init (`op == Init`, `resume_token != 0`) that should be
/// served in a dedicated worker process. `MSG_PEEK` leaves the bytes on the
/// socket so the worker reads them fresh. Gated behind `SMOLVM_CUDA_FORK_WORKERS` (unset
/// = legacy shared-context path) so partial Path-3 wiring can't disturb serving.
#[cfg(unix)]
fn peek_clone_token(fd: std::os::unix::io::RawFd) -> Option<u64> {
    if std::env::var_os("SMOLVM_CUDA_FORK_WORKERS").is_none()
        || std::env::var_os("SMOLVM_CUDA_FORK_ISOLATE").is_none()
    {
        return None;
    }
    // framing: [u32 le len][op][proto_hash u64][resume_token u64]
    let mut buf = [0u8; 21];
    // The connection is often proxied (guest vsock → per-VM cuda_host proxy →
    // daemon unix socket), so the 21-byte Init can arrive in pieces AFTER accept.
    // A one-shot peek that saw a short read here would MISROUTE the isolating
    // clone to the legacy shared-context path (which fails for expandable_segments
    // → CUDA_ERROR_UNKNOWN, esp. at larger models). Retry the non-consuming peek
    // until the full header is buffered (or the peer closes / we time out ~1s).
    let mut n: isize = 0;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 21 || n == 0 {
            break; // full header buffered, or peer closed
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 21 || buf[4] != 0x01 {
        tracing::warn!(
            n,
            op = buf[4],
            "peek_clone_token: not routed (short read / non-Init)"
        );
        return None;
    }
    let token = u64::from_le_bytes(buf[13..21].try_into().unwrap());
    (token != 0).then_some(token)
}

/// Fork-time share-safety check: D2H the chunk and confirm every recorded
/// upload segment still hashes to its H2D-time CRC. Any mismatch (or D2H
/// failure) → not shareable.
#[cfg(unix)]
fn verify_chunk_content(b: &mut dyn Backend, ch: &smolvm_cuda::host::HandoffChunk) -> bool {
    match b.memcpy_dtoh(ch.va, ch.size, 0) {
        Ok(bytes) => ch.segs.iter().all(|&(s, e, crc)| {
            crc != 0
                && e as usize <= bytes.len()
                && smolvm_cuda::proto::fnv64(&bytes[s as usize..e as usize]) == crc
        }),
        Err(e) => {
            tracing::warn!(e, va = ch.va, "M2-share: verify D2H failed → private");
            false
        }
    }
}

/// Stage private copies of the golden's non-VMM (`cudaMalloc`) allocations into
/// one exportable physical the worker can import. Regions are
/// granularity-aligned merged spans of the allocations' VAs; each allocation's
/// bytes are copied at `region_off + (dptr - region_base)` so the worker can
/// blit whole regions back to the golden's exact VAs. Returns the export fd.
#[cfg(unix)]
fn stage_alloc_copies(
    b: &mut dyn smolvm_cuda::host::Backend,
    device: i32,
    allocs: &[(u64, u64, bool)],
    regions: &[(u64, u64)], // (base, end)
    total: u64,
) -> Result<i32, String> {
    let h = b
        .mem_create_exportable(total, device)
        .map_err(|e| format!("stage create: {e}"))?;
    let tmp = match b.mem_address_reserve(total, 0) {
        Ok(t) => t,
        Err(e) => {
            let _ = b.mem_release(h);
            return Err(format!("stage reserve: {e}"));
        }
    };
    let mut copy = || -> Result<(), String> {
        b.mem_map(tmp, total, 0, h)
            .map_err(|e| format!("stage map: {e}"))?;
        b.mem_set_access(tmp, total, device)
            .map_err(|e| format!("stage access: {e}"))?;
        for &(d, sz, _) in allocs {
            // Locate the containing region and its offset into the staging chunk.
            let mut off = 0u64;
            for &(base, end) in regions {
                if d >= base && d < end {
                    b.memcpy_dtod(tmp + off + (d - base), d, sz)
                        .map_err(|e| format!("stage dtod {d:#x}: {e}"))?;
                    break;
                }
                off += end - base;
            }
        }
        let _ = b.ctx_synchronize();
        Ok(())
    };
    let res = copy();
    let _ = b.mem_unmap(tmp, total);
    let _ = b.mem_address_free(tmp, total);
    match res.and_then(|()| {
        b.mem_export_handle(h)
            .map_err(|e| format!("stage export: {e}"))
    }) {
        Ok(fd) => {
            // The fd holds its own driver reference; drop ours.
            let _ = b.mem_release(h);
            Ok(fd)
        }
        Err(e) => {
            let _ = b.mem_release(h);
            Err(e)
        }
    }
}

#[cfg(unix)]
struct CachedHostSnapshot {
    layout: String,
    device: i32,
    fds: Vec<std::os::unix::io::RawFd>,
    host_bytes: u64,
    golden_pid: std::sync::atomic::AtomicU32,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct CachedModuleBlob {
    file: std::fs::File,
    bytes: u64,
    revision: u64,
    image_file: Option<std::fs::File>,
    image_bytes: u64,
}

#[cfg(target_os = "linux")]
impl CachedModuleBlob {
    fn total_bytes(&self) -> u64 {
        self.bytes.saturating_add(self.image_bytes)
    }
}

#[cfg(target_os = "linux")]
const MAX_CACHED_MODULE_BLOBS: usize = 32;

#[cfg(unix)]
impl CachedHostSnapshot {
    fn duplicate_fds(&self) -> io::Result<Vec<std::os::unix::io::RawFd>> {
        let mut duplicates = Vec::with_capacity(self.fds.len());
        for &fd in &self.fds {
            // SAFETY: dup creates an independently-owned descriptor for the
            // next worker spawn; the cache keeps its original descriptor.
            let duplicate = unsafe { libc::dup(fd) };
            if duplicate < 0 {
                for fd in duplicates {
                    unsafe { libc::close(fd) };
                }
                return Err(io::Error::last_os_error());
            }
            duplicates.push(duplicate);
        }
        Ok(duplicates)
    }
}

#[cfg(unix)]
impl Drop for CachedHostSnapshot {
    fn drop(&mut self) {
        for &fd in &self.fds {
            unsafe { libc::close(fd) };
        }
    }
}

/// Move owned descriptor sources above every `dup2` destination used by a
/// clone worker. Otherwise an early `dup2` can overwrite a later source and
/// make the worker import the wrong GPU allocation.
#[cfg(unix)]
fn lift_owned_fds(fds: Vec<std::os::unix::io::RawFd>, minimum: i32) -> io::Result<Vec<i32>> {
    let mut lifted = Vec::with_capacity(fds.len());
    for &fd in &fds {
        // CLOEXEC is intentional on the temporary source. `dup2` creates the
        // final destination and the child explicitly clears CLOEXEC there.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
        if duplicate < 0 {
            let error = io::Error::last_os_error();
            for duplicate in lifted {
                unsafe { libc::close(duplicate) };
            }
            for fd in fds {
                unsafe { libc::close(fd) };
            }
            return Err(error);
        }
        lifted.push(duplicate);
    }
    for fd in fds {
        unsafe { libc::close(fd) };
    }
    Ok(lifted)
}

#[cfg(unix)]
fn host_snapshot_cache() -> &'static Mutex<std::collections::HashMap<u64, Arc<CachedHostSnapshot>>>
{
    static CACHE: OnceLock<Mutex<std::collections::HashMap<u64, Arc<CachedHostSnapshot>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(unix)]
fn cached_host_snapshot(token: u64) -> Option<Arc<CachedHostSnapshot>> {
    let cache = host_snapshot_cache().lock().unwrap();
    if let Some(snapshot) = cache.get(&token) {
        return Some(snapshot.clone());
    }
    cache.iter().find_map(|(&candidate, snapshot)| {
        smolvm_cuda::host::layout_handoff_same_process(candidate, token).then(|| snapshot.clone())
    })
}

#[cfg(target_os = "linux")]
fn module_blob_cache() -> &'static Mutex<std::collections::HashMap<u64, Arc<CachedModuleBlob>>> {
    static CACHE: OnceLock<Mutex<std::collections::HashMap<u64, Arc<CachedModuleBlob>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "linux")]
fn module_blob_build_gates(
) -> &'static Mutex<std::collections::HashMap<u64, std::sync::Weak<Mutex<()>>>> {
    static GATES: OnceLock<Mutex<std::collections::HashMap<u64, std::sync::Weak<Mutex<()>>>>> =
        OnceLock::new();
    GATES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "linux")]
fn module_blob_build_gate(token: u64) -> Arc<Mutex<()>> {
    let mut gates = module_blob_build_gates().lock().unwrap();
    gates.retain(|candidate, gate| {
        gate.strong_count() > 0 && smolvm_cuda::host::layout_handoff_present(*candidate)
    });
    if let Some(gate) = gates.get(&token).and_then(std::sync::Weak::upgrade) {
        return gate;
    }
    if let Some(gate) = gates.iter().find_map(|(&candidate, gate)| {
        smolvm_cuda::host::layout_handoff_same_process(candidate, token)
            .then(|| gate.upgrade())
            .flatten()
    }) {
        return gate;
    }
    let gate = Arc::new(Mutex::new(()));
    gates.insert(token, Arc::downgrade(&gate));
    gate
}

#[cfg(target_os = "linux")]
fn prune_module_blob_cache(cache: &mut std::collections::HashMap<u64, Arc<CachedModuleBlob>>) {
    let before = cache.len();
    let before_bytes = cache
        .values()
        .fold(0u64, |total, blob| total.saturating_add(blob.total_bytes()));
    cache.retain(|token, blob| {
        smolvm_cuda::host::module_handoff_revision(*token) == Some(blob.revision)
    });
    if cache.len() != before {
        let retained_bytes = cache
            .values()
            .fold(0u64, |total, blob| total.saturating_add(blob.total_bytes()));
        tracing::info!(
            entries = before - cache.len(),
            bytes = before_bytes.saturating_sub(retained_bytes),
            "released stale CUDA module handoffs"
        );
    }
}

#[cfg(target_os = "linux")]
fn cached_module_blob(token: u64) -> Option<Arc<CachedModuleBlob>> {
    let mut cache = module_blob_cache().lock().unwrap();
    prune_module_blob_cache(&mut cache);
    if let Some(blob) = cache.get(&token) {
        return Some(blob.clone());
    }
    cache.iter().find_map(|(&candidate, blob)| {
        smolvm_cuda::host::layout_handoff_same_process(candidate, token).then(|| blob.clone())
    })
}

#[cfg(all(test, target_os = "linux"))]
fn prepare_module_blob(
    token: u64,
    revision: u64,
    bytes: &[u8],
) -> io::Result<Arc<CachedModuleBlob>> {
    if let Some(blob) = cached_module_blob(token) {
        return Ok(blob);
    }
    let directory = std::env::temp_dir().join("smolvm");
    std::fs::create_dir_all(&directory)?;
    let mut writable = tempfile::tempfile_in(&directory)?;
    writable.write_all(bytes)?;
    finish_module_blob(token, revision, writable, bytes.len() as u64, None)
}

#[cfg(target_os = "linux")]
fn prepare_streamed_module_blob(
    token: u64,
    revision: u64,
    snapshot: &CapturedModuleHandoff,
    oplogs: &CapturedGraphOplogs,
    module_images: Option<smolvm_cuda::host::ModuleImageStoreSnapshot>,
) -> io::Result<Arc<CachedModuleBlob>> {
    if let Some(blob) = cached_module_blob(token) {
        return Ok(blob);
    }
    let directory = std::env::temp_dir().join("smolvm");
    std::fs::create_dir_all(&directory)?;
    let mut writable = tempfile::tempfile_in(&directory)?;
    let bytes = {
        let mut output = std::io::BufWriter::with_capacity(1 << 20, &mut writable);
        let bytes = write_module_handoff(&mut output, snapshot, oplogs, module_images.as_ref())?;
        output.flush()?;
        bytes
    };
    finish_module_blob(token, revision, writable, bytes, module_images)
}

#[cfg(target_os = "linux")]
fn finish_module_blob(
    token: u64,
    revision: u64,
    writable: std::fs::File,
    bytes: u64,
    module_images: Option<smolvm_cuda::host::ModuleImageStoreSnapshot>,
) -> io::Result<Arc<CachedModuleBlob>> {
    let read_path = format!("/proc/self/fd/{}", writable.as_raw_fd());
    let file = std::fs::OpenOptions::new().read(true).open(read_path)?;
    let blob = Arc::new(CachedModuleBlob {
        file,
        bytes,
        revision,
        image_bytes: module_images.as_ref().map_or(0, |store| store.bytes),
        image_file: module_images.map(|store| store.file),
    });
    drop(writable);

    let mut cache = module_blob_cache().lock().unwrap();
    prune_module_blob_cache(&mut cache);
    if let Some(existing) = cache.get(&token) {
        return Ok(existing.clone());
    }
    if let Some(existing) = cache.iter().find_map(|(&candidate, cached)| {
        smolvm_cuda::host::layout_handoff_same_process(candidate, token).then(|| cached.clone())
    }) {
        return Ok(existing);
    }
    let cached_bytes = cache.values().fold(0u64, |total, entry| {
        total.saturating_add(entry.total_bytes())
    });
    let revision_current = smolvm_cuda::host::module_handoff_revision(token) == Some(revision);
    if revision_current
        && cache.len() < MAX_CACHED_MODULE_BLOBS
        && cached_bytes.saturating_add(blob.total_bytes()) <= MAX_MODULE_HANDOFF_BLOB_BYTES
    {
        cache.insert(token, blob.clone());
    } else if revision_current {
        tracing::warn!(
            token,
            metadata_bytes = blob.bytes,
            image_bytes = blob.image_bytes,
            cached_bytes,
            "CUDA module handoff cache is full; retaining this source for one worker"
        );
    }
    Ok(blob)
}

#[cfg(target_os = "linux")]
fn module_blob_for_token(token: u64) -> io::Result<Option<Arc<CachedModuleBlob>>> {
    if let Some(blob) = cached_module_blob(token) {
        tracing::info!(
            token,
            metadata_bytes = blob.bytes,
            image_bytes = blob.image_bytes,
            "reusing serialized CUDA module handoff"
        );
        return Ok(Some(blob));
    }

    // Serialize a lineage at most once even when several clone connections
    // arrive together. Different lineages retain independent build gates.
    let gate = module_blob_build_gate(token);
    let _build = gate.lock().unwrap();
    if let Some(blob) = cached_module_blob(token) {
        tracing::info!(
            token,
            metadata_bytes = blob.bytes,
            image_bytes = blob.image_bytes,
            "reusing serialized CUDA module handoff after concurrent build"
        );
        return Ok(Some(blob));
    }
    for _ in 0..3 {
        let Some((revision, snapshot, oplogs)) = capture_module_handoff(token)? else {
            return Ok(None);
        };
        let module_images = smolvm_cuda::host::module_image_store_snapshot(token)?;
        if smolvm_cuda::host::module_handoff_revision(token) != Some(revision) {
            continue;
        }
        let blob =
            prepare_streamed_module_blob(token, revision, &snapshot, &oplogs, module_images)?;
        if smolvm_cuda::host::module_handoff_revision(token) == Some(revision) {
            tracing::info!(
                token,
                revision,
                metadata_bytes = blob.bytes,
                image_bytes = blob.image_bytes,
                "prepared reusable CUDA module handoff"
            );
            return Ok(Some(blob));
        }
    }
    Err(io::Error::other(
        "CUDA module state changed repeatedly while preparing handoff",
    ))
}

#[cfg(unix)]
fn bind_host_snapshot_owner(token: u64, pid: u32) {
    if let Some(snapshot) = cached_host_snapshot(token) {
        let _ = snapshot
            .golden_pid
            .compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst);
    }
}

#[cfg(unix)]
fn bind_host_snapshot_to_golden(token: u64) -> Option<u32> {
    let (matching, registered) = {
        let registry = golden_connection_registry().lock().unwrap();
        let matching = registry
            .iter()
            .filter_map(|(&pid, entries)| {
                entries
                    .iter()
                    .any(|entry| {
                        entry.token == token
                            || smolvm_cuda::host::layout_handoff_same_process(entry.token, token)
                    })
                    .then_some(pid)
            })
            .collect();
        (matching, registry.keys().copied().collect::<Vec<_>>())
    };
    let known_owner = golden_token_owners().lock().unwrap().get(&token).copied();
    let owner = select_golden_owner(matching, known_owner, &registered)?;
    golden_token_owners().lock().unwrap().insert(token, owner);
    bind_host_snapshot_owner(token, owner);
    Some(owner)
}

#[cfg(unix)]
fn live_host_snapshot_count() -> usize {
    let snapshots: Vec<(u64, Arc<CachedHostSnapshot>)> = host_snapshot_cache()
        .lock()
        .unwrap()
        .iter()
        .map(|(&token, snapshot)| (token, snapshot.clone()))
        .collect();
    let workers = clone_worker_registry().lock().unwrap();
    let mut expired = Vec::new();
    let mut live = 0;
    for (token, snapshot) in snapshots {
        let pid = snapshot.golden_pid.load(Ordering::SeqCst);
        if pid == 0 {
            continue;
        }
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            live += 1;
            continue;
        }
        let has_workers = workers.keys().any(|&(candidate, _)| {
            candidate == token || smolvm_cuda::host::layout_handoff_same_process(candidate, token)
        });
        if !has_workers {
            expired.push((token, pid));
        }
    }
    drop(workers);
    if !expired.is_empty() {
        let mut cache = host_snapshot_cache().lock().unwrap();
        let mut owners = golden_token_owners().lock().unwrap();
        for (token, pid) in expired {
            if let Some(snapshot) = cache.remove(&token) {
                tracing::info!(
                    token,
                    host_bytes = snapshot.host_bytes,
                    "released frozen golden host snapshot after VM exit"
                );
            }
            owners.retain(|_, owner| *owner != pid);
            smolvm_cuda::host::release_metadata_only_layout(token);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut cache = module_blob_cache().lock().unwrap();
        prune_module_blob_cache(&mut cache);
    }
    live
}

#[cfg(unix)]
fn retain_host_snapshot(
    token: u64,
    layout: &str,
    device: i32,
    source_fds: &[std::os::unix::io::RawFd],
    host_bytes: u64,
) -> io::Result<()> {
    if cached_host_snapshot(token).is_some() {
        return Ok(());
    }
    let mut fds = Vec::with_capacity(source_fds.len());
    for &fd in source_fds {
        let duplicate = unsafe { libc::dup(fd) };
        if duplicate < 0 {
            for fd in fds {
                unsafe { libc::close(fd) };
            }
            return Err(io::Error::last_os_error());
        }
        fds.push(duplicate);
    }
    if !smolvm_cuda::host::cache_frozen_layout(token) {
        for fd in fds {
            unsafe { libc::close(fd) };
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "golden process layout disappeared before host snapshot retention",
        ));
    }
    host_snapshot_cache().lock().unwrap().insert(
        token,
        Arc::new(CachedHostSnapshot {
            layout: layout.to_owned(),
            device,
            fds,
            host_bytes,
            golden_pid: std::sync::atomic::AtomicU32::new(0),
        }),
    );
    Ok(())
}

#[cfg(unix)]
fn module_handoff_len(value: usize) -> io::Result<[u8; 4]> {
    Ok(u32::try_from(value)
        .map_err(|_| io::Error::other("CUDA module handoff field exceeds 4 GiB"))?
        .to_le_bytes())
}

#[cfg(unix)]
type CapturedModuleHandoff = (
    Vec<(u64, Arc<[u8]>)>,
    Vec<smolvm_cuda::host::FuncMeta>,
    Vec<(u64, u32)>,
    Vec<(u64, u32)>,
    Vec<(u64, u64, smolvm_cuda::host::GraphSer)>,
    Vec<(u8, u16, u64, Vec<u8>)>,
);

#[cfg(unix)]
type CapturedGraphOplogs = Vec<(u64, u64, Vec<Vec<u8>>)>;

#[cfg(unix)]
fn capture_module_handoff(
    token: u64,
) -> io::Result<Option<(u64, CapturedModuleHandoff, CapturedGraphOplogs)>> {
    let (revision, snapshot, oplogs) = {
        let mut attempts = 0;
        loop {
            let Some(before) = smolvm_cuda::host::module_handoff_revision(token) else {
                return Ok(None);
            };
            let Some(snapshot) = smolvm_cuda::host::module_handoff_snapshot(token) else {
                return Ok(None);
            };
            let oplogs = smolvm_cuda::host::graph_oplogs_snapshot(token);
            if smolvm_cuda::host::module_handoff_revision(token) == Some(before) {
                break (before, snapshot, oplogs);
            }
            attempts += 1;
            if attempts == 3 {
                return Err(io::Error::other(
                    "CUDA module state changed repeatedly during handoff",
                ));
            }
        }
    };
    let (modules, funcs, streams, events, graphs, lib_handles) = snapshot;
    tracing::info!(
        revision,
        modules = modules.len(),
        funcs = funcs.len(),
        streams = streams.len(),
        events = events.len(),
        graphs = graphs.len(),
        lib_handles = lib_handles.len(),
        "M3a: gathered golden modules/functions/streams/events"
    );
    Ok(Some((
        revision,
        (modules, funcs, streams, events, graphs, lib_handles),
        oplogs,
    )))
}

#[cfg(unix)]
fn write_module_handoff(
    mut output: impl Write,
    snapshot: &CapturedModuleHandoff,
    oplogs: &CapturedGraphOplogs,
    #[cfg(target_os = "linux")] module_images: Option<&smolvm_cuda::host::ModuleImageStoreSnapshot>,
) -> io::Result<u64> {
    let (modules, funcs, streams, events, graphs, lib_handles) = snapshot;
    let mut written = 0_u64;
    macro_rules! put {
        ($bytes:expr) => {{
            let bytes: &[u8] = $bytes;
            written = written
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("CUDA module handoff size overflow"))?;
            if written > MAX_MODULE_HANDOFF_BLOB_BYTES {
                return Err(io::Error::other("CUDA module handoff exceeds cache limit"));
            }
            output.write_all(bytes)?;
        }};
    }

    #[cfg(target_os = "linux")]
    if module_images.is_some() {
        put!(&EXTERNAL_MODULE_IMAGES_MAGIC);
    }
    put!(&module_handoff_len(modules.len())?);
    for (handle, image) in modules {
        put!(&handle.to_le_bytes());
        #[cfg(target_os = "linux")]
        if let Some(store) = module_images {
            let &(offset, length) = store.ranges.get(handle).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CUDA module image is missing from its append-only store",
                )
            })?;
            if length != image.len() as u64
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > store.bytes)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CUDA module image store range does not match its captured image",
                ));
            }
            put!(&offset.to_le_bytes());
            put!(&module_handoff_len(image.len())?);
            continue;
        }
        put!(&module_handoff_len(image.len())?);
        put!(image);
    }
    put!(&module_handoff_len(funcs.len())?);
    for (handle, module, name, attrs) in funcs {
        put!(&handle.to_le_bytes());
        put!(&module.to_le_bytes());
        put!(&module_handoff_len(name.len())?);
        put!(name.as_bytes());
        // Per-function attribute replays ([i32 attr][i32 value] each) —
        // e.g. FlashAttention's MaxDynamicSharedMemorySize opt-in.
        put!(&module_handoff_len(attrs.len())?);
        for &(attribute, value) in attrs {
            put!(&attribute.to_le_bytes());
            put!(&value.to_le_bytes());
        }
    }
    // Streams + events: [u64 golden handle][u32 create flags] each.
    put!(&module_handoff_len(streams.len())?);
    for (handle, flags) in streams {
        put!(&handle.to_le_bytes());
        put!(&flags.to_le_bytes());
    }
    put!(&module_handoff_len(events.len())?);
    for (handle, flags) in events {
        put!(&handle.to_le_bytes());
        put!(&flags.to_le_bytes());
    }
    // M3b: captured graphs. Per graph: [u64 graph_vh][u64 exec_vh]
    //   [u32 nnodes]([u64 func][u32*3 grid][u32*3 block][u32 shmem]
    //                [u32 nparams]([u32 len][bytes])* )*
    //   [u32 nedges]([u32 from][u32 to])*
    put!(&module_handoff_len(graphs.len())?);
    for (graph_vh, exec_vh, graph) in graphs {
        put!(&graph_vh.to_le_bytes());
        put!(&exec_vh.to_le_bytes());
        put!(&module_handoff_len(graph.nodes.len())?);
        for node in &graph.nodes {
            put!(&node.func.to_le_bytes());
            for value in node.grid.iter().chain(node.block.iter()) {
                put!(&value.to_le_bytes());
            }
            put!(&node.shared_mem.to_le_bytes());
            put!(&module_handoff_len(node.params.len())?);
            for param in &node.params {
                put!(&module_handoff_len(param.len())?);
                put!(param);
            }
        }
        put!(&module_handoff_len(graph.edges.len())?);
        for &(from, to) in &graph.edges {
            put!(&from.to_le_bytes());
            put!(&to.to_le_bytes());
        }
    }
    // Library-handle creates for the worker to replay:
    //   [u32 n]([u8 lib][u16 func][u64 handle][u32 len][args])*
    put!(&module_handoff_len(lib_handles.len())?);
    for (library, function, handle, args) in lib_handles {
        put!(std::slice::from_ref(library));
        put!(&function.to_le_bytes());
        put!(&handle.to_le_bytes());
        put!(&module_handoff_len(args.len())?);
        put!(args);
    }
    // P3b: capture-replay op-logs. Per graph:
    //   [u64 graph_vh][u64 exec_vh][u32 nops]([u32 len][op bytes])*
    put!(&module_handoff_len(oplogs.len())?);
    for (graph_vh, exec_vh, ops) in oplogs {
        put!(&graph_vh.to_le_bytes());
        put!(&exec_vh.to_le_bytes());
        put!(&module_handoff_len(ops.len())?);
        for op in ops {
            put!(&module_handoff_len(op.len())?);
            put!(op);
        }
    }
    Ok(written)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn serialize_module_handoff(token: u64) -> io::Result<Option<(u64, Vec<u8>)>> {
    let Some((revision, snapshot, oplogs)) = capture_module_handoff(token)? else {
        return Ok(None);
    };
    let mut blob = Vec::new();
    write_module_handoff(&mut blob, &snapshot, &oplogs)?;
    Ok(Some((revision, blob)))
}

#[cfg(unix)]
struct PosixSpawnActions(libc::posix_spawn_file_actions_t);

#[cfg(unix)]
impl PosixSpawnActions {
    fn new() -> io::Result<Self> {
        let mut actions = unsafe { std::mem::zeroed() };
        // SAFETY: `actions` points to writable storage of the libc-declared type.
        let error = unsafe { libc::posix_spawn_file_actions_init(&mut actions) };
        if error == 0 {
            Ok(Self(actions))
        } else {
            Err(io::Error::from_raw_os_error(error))
        }
    }

    fn dup2(&mut self, source: i32, destination: i32) -> io::Result<()> {
        // SAFETY: the actions object is initialized and both descriptors are
        // copied by value into the action list.
        let error =
            unsafe { libc::posix_spawn_file_actions_adddup2(&mut self.0, source, destination) };
        if error == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(error))
        }
    }
}

#[cfg(unix)]
impl Drop for PosixSpawnActions {
    fn drop(&mut self) {
        // SAFETY: this object is constructed only after a successful init and
        // destroyed exactly once here.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

#[cfg(unix)]
struct CloneWorkerSpawnFds<'a> {
    connection: i32,
    exports: &'a [i32],
    control: (i32, i32),
    publish: Option<(i32, i32)>,
    module: Option<(i32, i32)>,
    module_images: Option<(i32, i32)>,
}

/// Launch a clone worker without copying the CUDA daemon's large address space.
///
/// `Command::pre_exec` forces fork/exec, whose page-table copy becomes visible
/// once the daemon retains multi-gigabyte CUDA snapshots. `posix_spawn`
/// preserves the exact descriptor and environment contract while Linux libc
/// can use its vfork-style path.
#[cfg(unix)]
fn posix_spawn_clone_worker(
    exe: &Path,
    env_overrides: &[(std::ffi::OsString, std::ffi::OsString)],
    fds: CloneWorkerSpawnFds<'_>,
) -> io::Result<u32> {
    use std::os::unix::ffi::OsStrExt;

    let mut actions = PosixSpawnActions::new()?;
    actions.dup2(fds.connection, 3)?;
    for (index, source) in fds.exports.iter().copied().enumerate() {
        actions.dup2(source, 4 + index as i32)?;
    }
    actions.dup2(fds.control.0, fds.control.1)?;
    if let Some((source, slot)) = fds.publish {
        actions.dup2(source, slot)?;
    }
    if let Some((source, slot)) = fds.module {
        actions.dup2(source, slot)?;
    }
    if let Some((source, slot)) = fds.module_images {
        actions.dup2(source, slot)?;
    }

    let exe = std::ffi::CString::new(exe.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "clone-worker executable path contains NUL",
        )
    })?;
    let argv_storage = [
        exe.clone(),
        std::ffi::CString::new("_cuda-clone-worker").unwrap(),
        std::ffi::CString::new("3").unwrap(),
    ];
    let mut argv = argv_storage
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect::<Vec<_>>();

    let mut environment = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    for (key, value) in env_overrides {
        environment.insert(key.clone(), value.clone());
    }
    let env_storage = environment
        .into_iter()
        .map(|(key, value)| {
            let key = key.as_os_str().as_bytes();
            let value = value.as_os_str().as_bytes();
            let mut entry = Vec::with_capacity(key.len() + value.len() + 1);
            entry.extend_from_slice(key);
            entry.push(b'=');
            entry.extend_from_slice(value);
            std::ffi::CString::new(entry).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "clone-worker environment contains NUL",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut envp = env_storage
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect::<Vec<_>>();

    let mut pid = 0;
    // SAFETY: all C strings and pointer arrays live through the call, are NUL
    // terminated, and the initialized action list contains valid descriptors.
    let error = unsafe {
        libc::posix_spawn(
            &mut pid,
            exe.as_ptr(),
            &actions.0,
            std::ptr::null(),
            argv.as_mut_ptr(),
            envp.as_mut_ptr(),
        )
    };
    if error == 0 {
        u32::try_from(pid).map_err(|_| io::Error::other("clone-worker pid is out of range"))
    } else {
        Err(io::Error::from_raw_os_error(error))
    }
}

/// Path 3 (M1): hand the accepted connection to a fresh worker PROCESS (its own
/// CUDA context, hence its own UVA — so it can place memory at the golden's exact
/// VAs). `dup2` the socket fd onto fd 3 in the child (clears CLOEXEC) and exec
/// `smolvm _cuda-clone-worker 3`; the daemon then drops its own copy.
#[cfg(unix)]
fn spawn_clone_worker(
    conn_fd: std::os::unix::io::RawFd,
    token: u64,
    share_weights: bool,
    preload_modules: bool,
    ring_dir: Option<&str>,
    procmem: Option<ProcMemAdvert>,
    options: ServeOptions,
) -> io::Result<(u32, std::os::unix::io::RawFd)> {
    let exe = std::env::current_exe()?;
    let eviction_mode = std::env::var("SMOLVM_CUDA_GOLDEN_EVICT").ok();
    let configured_sharing = std::env::var("SMOLVM_CUDA_FORK_SHARE_WEIGHTS").ok();
    let sharing_active =
        share_weights && !matches!(configured_sharing.as_deref(), Some("0" | "false" | "off"));
    let snapshot_requested = fork_snapshot_enabled(
        golden_eviction_enabled(eviction_mode.as_deref(), options.fork_pool_size),
        sharing_active,
    );
    #[cfg(target_os = "linux")]
    let module_blob_build = if cached_module_blob(token).is_none() {
        // Capturing module metadata briefly shares the frozen layout lock, but
        // writing the immutable images is independent of the device-to-host
        // memory snapshot below. Overlap both first-worker costs; later workers
        // continue to use the two single-flight caches.
        match std::thread::Builder::new()
            .name("cuda-module-handoff".into())
            .spawn(move || module_blob_for_token(token))
        {
            Ok(build) => Some(build),
            Err(error) => {
                tracing::warn!(%error, token, "could not parallelize CUDA module handoff");
                None
            }
        }
    } else {
        None
    };
    let (golden_dev, layout, export_fds) = if let Some(cached) = cached_host_snapshot(token) {
        tracing::info!(
            token,
            bytes = cached.layout.len(),
            "reusing retained golden host snapshot"
        );
        (
            cached.device,
            cached.layout.clone(),
            cached.duplicate_fds()?,
        )
    } else {
        // Gather the golden's VMM layout (reservations + maps→physical handle).
        let (resvs, maps, golden_dev) = smolvm_cuda::host::layout_handoff_snapshot(token)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no golden layout for token"))?;
        let allocs = smolvm_cuda::host::alloc_handoff_snapshot(token).unwrap_or_default();
        // Export each map's physical to a POSIX fd (in the golden's shared
        // context) and build the worker's reconstruction layout.
        let mut backend = make_backend();
        backend
            .init()
            .map_err(|e| io::Error::other(format!("worker-export init: {e}")))?;
        backend
            .primary_ctx_retain(golden_dev)
            .map_err(|e| io::Error::other(format!("ctx retain: {e}")))?;
        let _ = backend.ctx_synchronize();
        let safe_maps: Vec<bool> = maps
            .iter()
            .map(|chunk| match (chunk.candidate, chunk.verified) {
                (false, _) => false,
                (true, Some(verdict)) => verdict,
                (true, None) => {
                    let verdict = verify_chunk_content(backend.as_mut(), chunk);
                    smolvm_cuda::host::layout_set_share_verdict(token, chunk.va, verdict);
                    verdict
                }
            })
            .collect();
        let snapshot_required = maps
            .iter()
            .zip(&safe_maps)
            .filter_map(|(chunk, &safe)| (!(sharing_active && safe)).then_some(chunk.size))
            .chain(allocs.iter().map(|(_, size, _)| *size))
            .fold(0u64, u64::saturating_add);
        let memory_bearing = !maps.is_empty() || !allocs.is_empty();
        // Every retained memory class must have an address-preserving restore
        // contract before the host snapshot may replace its live golden source.
        let snapshot_reconstructable = host_snapshot_reconstructable(maps.len(), allocs.len());
        #[cfg(target_os = "linux")]
        let host_snapshot = snapshot_requested
            && memory_bearing
            && snapshot_reconstructable
            && host_snapshot_capacity_available(snapshot_required);
        #[cfg(not(target_os = "linux"))]
        let host_snapshot = false;
        if snapshot_requested && memory_bearing && !host_snapshot {
            tracing::warn!(
                token,
                snapshot_required,
                "keeping frozen golden resident because host snapshot capacity is unavailable"
            );
        }
        let mut layout = String::from("resv=");
        for (va, size) in &resvs {
            layout.push_str(&format!("{va:x}:{size:x},"));
        }
        layout.push_str("|maps=");
        let mut export_fds: Vec<i32> = Vec::new();
        let mut snapshot_fd = None;
        let mut snapshot_offset = 0u64;
        let mut snapshot_complete = host_snapshot;
        if host_snapshot {
            match create_host_snapshot_memfd() {
                Ok(fd) => {
                    let idx = export_fds.len();
                    export_fds.push(fd);
                    snapshot_fd = Some((fd, idx));
                }
                Err(error) => {
                    snapshot_complete = false;
                    tracing::warn!(%error, "host snapshot memfd unavailable");
                }
            }
        }
        for (ch, safe) in maps.iter().zip(safe_maps) {
            // Share-safety: a candidate chunk is shared only if its device content
            // still equals what the H2Ds uploaded. All other chunks may be staged
            // to host RAM for an address-preserving private restore.
            if host_snapshot && !(sharing_active && safe) {
                if let Some((fd, idx)) = snapshot_fd {
                    match backend.memcpy_dtoh(ch.va, ch.size, 0) {
                        Ok(bytes) => match append_host_snapshot(fd, snapshot_offset, &bytes) {
                            Ok(()) => {
                                layout.push_str(&format!(
                                    "{:x}:{:x}:{}:0:{:x}:{:x},",
                                    ch.va, ch.size, idx, ch.ghandle, snapshot_offset
                                ));
                                snapshot_offset += ch.size;
                                continue;
                            }
                            Err(error) => tracing::warn!(
                                %error,
                                va = ch.va,
                                size = ch.size,
                                "host snapshot write failed; keeping the golden resident"
                            ),
                        },
                        Err(error) => tracing::warn!(
                            error,
                            va = ch.va,
                            size = ch.size,
                            "device-to-host snapshot failed; keeping the golden resident"
                        ),
                    }
                    snapshot_complete = false;
                } else {
                    snapshot_complete = false;
                }
            }
            let efd = backend.mem_export_handle(ch.handle).map_err(|error| {
                io::Error::other(format!(
                    "failed to export golden VMM range {:#x}+{:#x}: {error}",
                    ch.va, ch.size
                ))
            })?;
            let idx = export_fds.len();
            export_fds.push(efd);
            let ld = u8::from(safe);
            layout.push_str(&format!(
                "{:x}:{:x}:{}:{}:{:x},",
                ch.va, ch.size, idx, ld, ch.ghandle
            ));
        }
        // Non-VMM golden memory: a plain-torch golden (no expandable_segments) keeps
        // every tensor in cudaMalloc'd blocks that never enter the VMM layout, so a
        // worker-mode clone would lose them all (illegal address on first touch —
        // the maps above only cover VMM). Stage private copies for the worker.
        if !allocs.is_empty() {
            let gran = backend
                .mem_get_allocation_granularity(golden_dev, 0)
                .unwrap_or(1 << 21)
                .max(1 << 16);
            let mut spans: Vec<(u64, u64)> = allocs
                .iter()
                .map(|&(d, sz, _)| (d & !(gran - 1), (d + sz + gran - 1) & !(gran - 1)))
                .collect();
            spans.sort_unstable();
            let mut regions: Vec<(u64, u64)> = Vec::new();
            for (b0, e0) in spans {
                match regions.last_mut() {
                    Some((_, e)) if b0 <= *e => *e = (*e).max(e0),
                    _ => regions.push((b0, e0)),
                }
            }
            let total: u64 = regions.iter().map(|&(b0, e0)| e0 - b0).sum();
            let host_staged = if host_snapshot {
                snapshot_fd.and_then(|(fd, idx)| {
                    let mut entries = Vec::with_capacity(allocs.len());
                    for &(d, sz, _) in &allocs {
                        let bytes = backend.memcpy_dtoh(d, sz, 0).ok()?;
                        append_host_snapshot(fd, snapshot_offset, &bytes).ok()?;
                        entries.push((d, sz, snapshot_offset));
                        snapshot_offset += sz;
                    }
                    layout.push_str(&format!("|ahost={idx}|aregions="));
                    let mut off = 0u64;
                    for &(b0, e0) in &regions {
                        layout.push_str(&format!("{:x}:{:x}:{:x},", b0, e0 - b0, off));
                        off += e0 - b0;
                    }
                    layout.push_str("|allocs=");
                    for (d, sz, host_off) in entries {
                        layout.push_str(&format!("{d:x}:{sz:x}:{host_off:x},"));
                    }
                    Some(())
                })
            } else {
                None
            };
            if host_staged.is_some() {
                tracing::info!(
                    allocs = allocs.len(),
                    bytes = allocs.iter().map(|(_, size, _)| *size).sum::<u64>(),
                    "staged the golden's non-VMM allocations in host RAM"
                );
            } else {
                if host_snapshot {
                    snapshot_complete = false;
                }
                match stage_alloc_copies(backend.as_mut(), golden_dev, &allocs, &regions, total) {
                    Ok(efd) => {
                        let idx = export_fds.len();
                        export_fds.push(efd);
                        layout.push_str(&format!("|astage={idx}|aregions="));
                        let mut off = 0u64;
                        for &(b0, e0) in &regions {
                            layout.push_str(&format!("{:x}:{:x}:{:x},", b0, e0 - b0, off));
                            off += e0 - b0;
                        }
                        layout.push_str("|allocs=");
                        for &(d, sz, _) in &allocs {
                            layout.push_str(&format!("{d:x}:{sz:x},"));
                        }
                        tracing::info!(
                            allocs = allocs.len(),
                            regions = regions.len(),
                            bytes = total,
                            "staged the golden's non-VMM allocations for the worker"
                        );
                    }
                    Err(error) => {
                        return Err(io::Error::other(format!(
                            "failed to stage non-VMM golden allocations: {error}"
                        )))
                    }
                }
            }
        }
        if snapshot_complete {
            let Some((fd, _)) = snapshot_fd else {
                return Err(io::Error::other("host snapshot fd disappeared"));
            };
            if let Err(error) = seal_host_snapshot(fd) {
                snapshot_complete = false;
                tracing::warn!(
                    %error,
                    "host snapshot sealing failed; keeping the golden resident"
                );
            }
        }
        if snapshot_complete {
            match retain_host_snapshot(token, &layout, golden_dev, &export_fds, snapshot_offset) {
                Ok(()) => {
                    let owner = bind_host_snapshot_to_golden(token);
                    if owner.is_some() {
                        tracing::info!(
                            token,
                            ?owner,
                            fds = export_fds.len(),
                            host_bytes = snapshot_offset,
                            "retained golden host snapshot for clone reuse"
                        );
                    } else {
                        host_snapshot_cache().lock().unwrap().remove(&token);
                        smolvm_cuda::host::release_metadata_only_layout(token);
                        tracing::warn!(
                            token,
                            "golden snapshot owner is ambiguous; disabling snapshot reuse"
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        token,
                        "host snapshot retention failed; keeping the golden resident"
                    );
                }
            }
        } else if snapshot_requested && memory_bearing && snapshot_reconstructable {
            tracing::warn!(
                token,
                "golden eviction disabled because its host snapshot was incomplete"
            );
        }
        (golden_dev, layout, export_fds)
    };
    // Serialize immutable module state once per live lineage. Linux workers
    // inherit a read-only descriptor for an unnamed file; other Unix hosts keep
    // the legacy unique-path handoff.
    #[cfg(target_os = "linux")]
    let module_blob_result = match module_blob_build {
        Some(build) => match build.join() {
            Ok(result) => result,
            Err(_) => {
                for &fd in &export_fds {
                    unsafe { libc::close(fd) };
                }
                return Err(io::Error::other("CUDA module handoff builder panicked"));
            }
        },
        None => module_blob_for_token(token),
    };
    #[cfg(target_os = "linux")]
    let module_blob = match module_blob_result {
        Ok(blob) => blob,
        Err(error) => {
            for &fd in &export_fds {
                unsafe { libc::close(fd) };
            }
            return Err(error);
        }
    };
    #[cfg(not(target_os = "linux"))]
    let modpath = if let Some((_revision, blob)) = serialize_module_handoff(token)? {
        let directory = std::env::temp_dir().join("smolvm");
        std::fs::create_dir_all(&directory)?;
        static SPAWN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SPAWN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = directory.join(format!("clone-mods-{token}-{seq}.bin"));
        std::fs::write(&path, blob)?;
        Some(path)
    } else {
        None
    };
    // Control channel for late-attached guest channels: the daemon keeps sp[0]
    // and SCM_RIGHTS-sends each additional connection fd from the same clone;
    // the worker inherits sp[1] and serves every received fd in-process.
    let mut sp = [0i32; 2];
    // SAFETY: plain socketpair; fds checked below.
    // SEQPACKET preserves the boundary between each SCM_RIGHTS fd and its
    // variable-length proc-mem advert. A byte stream could split/coalesce the
    // metadata and associate the next channel's live-RAM map with the wrong fd.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sp.as_mut_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        for fd in export_fds {
            unsafe { libc::close(fd) };
        }
        return Err(error);
    }
    let publish_enabled = TENSOR_BUNDLE_SERVICE_READY.load(Ordering::Acquire);
    let mut publish_sp = [-1i32; 2];
    if publish_enabled
        && unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, publish_sp.as_mut_ptr()) }
            != 0
    {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(sp[0]);
            libc::close(sp[1]);
        }
        for fd in export_fds {
            unsafe { libc::close(fd) };
        }
        return Err(error);
    }
    let ctrl_slot = 4 + export_fds.len() as i32;
    let publish_slot = ctrl_slot + 1;
    #[cfg(target_os = "linux")]
    let module_slot = publish_slot + i32::from(publish_enabled);
    #[cfg(target_os = "linux")]
    let module_images_slot = module_slot + i32::from(module_blob.is_some());
    #[cfg(target_os = "linux")]
    let has_module_images = module_blob
        .as_ref()
        .is_some_and(|blob| blob.image_file.is_some());
    #[cfg(target_os = "linux")]
    let source_minimum = module_images_slot + i32::from(has_module_images);
    #[cfg(not(target_os = "linux"))]
    let source_minimum = publish_slot + i32::from(publish_enabled);
    #[cfg(target_os = "linux")]
    let module_child = if let Some(blob) = &module_blob {
        let fd =
            unsafe { libc::fcntl(blob.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, source_minimum) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(sp[0]);
                libc::close(sp[1]);
                if publish_enabled {
                    libc::close(publish_sp[0]);
                    libc::close(publish_sp[1]);
                }
            }
            for fd in export_fds {
                unsafe { libc::close(fd) };
            }
            return Err(error);
        }
        fd
    } else {
        -1
    };
    #[cfg(target_os = "linux")]
    let module_images_child = if let Some(file) = module_blob
        .as_ref()
        .and_then(|blob| blob.image_file.as_ref())
    {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, source_minimum) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(sp[0]);
                libc::close(sp[1]);
                if publish_enabled {
                    libc::close(publish_sp[0]);
                    libc::close(publish_sp[1]);
                }
                if module_child >= 0 {
                    libc::close(module_child);
                }
            }
            for fd in export_fds {
                unsafe { libc::close(fd) };
            }
            return Err(error);
        }
        fd
    } else {
        -1
    };
    // Lift the control source and every exported-memory source above the whole
    // dup2 destination range. Hundreds of VMM chunks can extend beyond any
    // fixed descriptor floor.
    let ctrl_child = unsafe { libc::fcntl(sp[1], libc::F_DUPFD_CLOEXEC, source_minimum) };
    // SAFETY: closing our original child-end copy.
    unsafe { libc::close(sp[1]) };
    if ctrl_child < 0 {
        let error = io::Error::last_os_error();
        // SAFETY: closing the parent end we created above.
        unsafe { libc::close(sp[0]) };
        if publish_enabled {
            unsafe {
                libc::close(publish_sp[0]);
                libc::close(publish_sp[1]);
            }
        }
        #[cfg(target_os = "linux")]
        if module_child >= 0 {
            unsafe { libc::close(module_child) };
        }
        #[cfg(target_os = "linux")]
        if module_images_child >= 0 {
            unsafe { libc::close(module_images_child) };
        }
        for fd in export_fds {
            unsafe { libc::close(fd) };
        }
        return Err(error);
    }
    let publish_child = if publish_enabled {
        let fd = unsafe { libc::fcntl(publish_sp[1], libc::F_DUPFD_CLOEXEC, source_minimum) };
        unsafe { libc::close(publish_sp[1]) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(sp[0]);
                libc::close(ctrl_child);
                libc::close(publish_sp[0]);
            }
            #[cfg(target_os = "linux")]
            if module_child >= 0 {
                unsafe { libc::close(module_child) };
            }
            #[cfg(target_os = "linux")]
            if module_images_child >= 0 {
                unsafe { libc::close(module_images_child) };
            }
            for fd in export_fds {
                unsafe { libc::close(fd) };
            }
            return Err(error);
        }
        fd
    } else {
        -1
    };
    let export_fds = match lift_owned_fds(export_fds, source_minimum) {
        Ok(fds) => fds,
        Err(error) => {
            unsafe {
                libc::close(sp[0]);
                libc::close(ctrl_child);
                if publish_enabled {
                    libc::close(publish_sp[0]);
                    libc::close(publish_child);
                }
                #[cfg(target_os = "linux")]
                if module_child >= 0 {
                    libc::close(module_child);
                }
                #[cfg(target_os = "linux")]
                if module_images_child >= 0 {
                    libc::close(module_images_child);
                }
            }
            return Err(error);
        }
    };
    let mut worker_env = vec![
        (
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_LAYOUT"),
            std::ffi::OsString::from(layout),
        ),
        (
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_DEVICE"),
            std::ffi::OsString::from(golden_dev.to_string()),
        ),
        (
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_CTRL"),
            std::ffi::OsString::from(ctrl_slot.to_string()),
        ),
    ];
    if preload_modules {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_PRELOAD_MODULES"),
            std::ffi::OsString::from("1"),
        ));
    }
    if publish_enabled {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_PUBLISH_CTRL"),
            std::ffi::OsString::from(publish_slot.to_string()),
        ));
    }
    if let Some(limit) = options.vram_limit_bytes {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_VRAM_LIMIT_BYTES"),
            std::ffi::OsString::from(limit.to_string()),
        ));
    }
    if let Some(pool) = options.fork_pool_size {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_FORK_POOL_SIZE"),
            std::ffi::OsString::from(pool.to_string()),
        ));
    }
    // Clone live-RAM transport: hand the worker our (pid, gpa, host_va, len) so
    // it can pread/pwrite /proc/<pid>/mem for D2H/H2D instead of ring-copying.
    if let Some((pid, regions)) = &procmem {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_PROCMEM"),
            std::ffi::OsString::from(procmem_to_env(*pid, regions)),
        ));
    }
    if let Some(rd) = ring_dir {
        // File-ring transport: the worker resolves RingSetupFile names
        // against the clone VM's advertised host ring dir.
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_RING_DIR"),
            std::ffi::OsString::from(rd),
        ));
    }
    // Per-fork density: --share-weights requests sharing, but the documented
    // daemon kill switch remains authoritative. This is needed for safe
    // all-private controls and emergency rollback; blindly replacing an
    // inherited "0" here made SMOLVM_CUDA_FORK_SHARE_WEIGHTS=0 ineffective.
    if let Some(setting) = clone_worker_share_env(share_weights, configured_sharing.as_deref()) {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_FORK_SHARE_WEIGHTS"),
            std::ffi::OsString::from(setting),
        ));
    }
    #[cfg(target_os = "linux")]
    if module_blob.is_some() {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_MODULES_FD"),
            std::ffi::OsString::from(module_slot.to_string()),
        ));
    }
    #[cfg(target_os = "linux")]
    if has_module_images {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_MODULE_IMAGES_FD"),
            std::ffi::OsString::from(module_images_slot.to_string()),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    if let Some(mp) = &modpath {
        worker_env.push((
            std::ffi::OsString::from("SMOLVM_CUDA_CLONE_MODULES"),
            mp.as_os_str().to_os_string(),
        ));
    }
    // Parent copies of the exported-physical fds, to close once the child has
    // spawned (it inherits its own set). Every open export fd holds a DRIVER
    // REFERENCE on the golden's physical allocation — leaking them in the
    // daemon pins the golden's VRAM long after the golden is torn down and its
    // session reclaimed (found: two dead goldens left ~3.2 GB resident).
    let parent_fds = export_fds.clone();
    #[cfg(target_os = "linux")]
    let module_action = (module_child >= 0).then_some((module_child, module_slot));
    #[cfg(not(target_os = "linux"))]
    let module_action = None;
    #[cfg(target_os = "linux")]
    let module_images_action =
        (module_images_child >= 0).then_some((module_images_child, module_images_slot));
    #[cfg(not(target_os = "linux"))]
    let module_images_action = None;
    let spawned = posix_spawn_clone_worker(
        &exe,
        &worker_env,
        CloneWorkerSpawnFds {
            connection: conn_fd,
            exports: &export_fds,
            control: (ctrl_child, ctrl_slot),
            publish: publish_enabled.then_some((publish_child, publish_slot)),
            module: module_action,
            module_images: module_images_action,
        },
    );
    // The child (if any) forked with its own copies; drop ours either way so
    // the golden's physicals can actually be released at teardown.
    for efd in parent_fds {
        // SAFETY: fds we created via mem_export_handle and no longer use.
        unsafe { libc::close(efd) };
    }
    // SAFETY: the child inherited its own copy of the control child-end.
    unsafe { libc::close(ctrl_child) };
    if publish_enabled {
        // SAFETY: as above for the dedicated publication child-end.
        unsafe { libc::close(publish_child) };
    }
    #[cfg(target_os = "linux")]
    if module_child >= 0 {
        // SAFETY: the child inherited its own copy at module_slot.
        unsafe { libc::close(module_child) };
    }
    #[cfg(target_os = "linux")]
    if module_images_child >= 0 {
        // SAFETY: the child inherited its own copy at module_images_slot.
        unsafe { libc::close(module_images_child) };
    }
    match spawned {
        Ok(pid) => {
            if publish_enabled {
                // SAFETY: the parent owns this socketpair end after spawn.
                let stream = unsafe { UnixStream::from_raw_fd(publish_sp[0]) };
                if let Err(error) = spawn_tensor_bundle_receiver(stream, pid) {
                    unsafe {
                        libc::close(sp[0]);
                        libc::kill(pid as libc::pid_t, libc::SIGTERM);
                    }
                    return Err(error);
                }
            }
            Ok((pid, sp[0]))
        }
        Err(e) => {
            // SAFETY: no worker took ownership; close the parent control end.
            unsafe {
                libc::close(sp[0]);
                if publish_enabled {
                    libc::close(publish_sp[0]);
                }
            }
            Err(e)
        }
    }
}

/// Ensure the shared daemon is running and return its socket path. Serialized by
/// an exclusive lock on `<socket>.lock` so concurrent CUDA VMs can't spawn two
/// daemons (a second would bind-fail and exit, but the lock avoids the churn and
/// the stale-socket-removal race).
pub fn ensure_running() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    ensure_running_with_executable(&executable, false)
}

/// Ensure the shared daemon is running by launching `executable` when a new
/// daemon is required.
///
/// Embedders use this entry point because their current executable is the host
/// runtime (for example Node or Python), while `SMOLVM_BOOT_BINARY` names the
/// bundled helper that implements the `_cuda-daemon` subcommand.
pub(crate) fn ensure_running_with_executable(
    executable: &Path,
    automatic_fork_workers: bool,
) -> io::Result<PathBuf> {
    let sock = socket_path();
    // A privileged node launches the daemon before dropping each VMM to its
    // dedicated uid. Those VMMs may connect to the live socket but must not
    // need write access to the shared data directory merely to create/open the
    // spawn lock. Check the read-only fast path first; the lock still
    // serializes every absent/stale-daemon spawn below.
    if is_alive(&sock) {
        return Ok(sock);
    }
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _guard = FileLock::acquire(&sock.with_extension("lock"))?;
    if is_alive(&sock) {
        return Ok(sock);
    }
    let _ = std::fs::remove_file(&sock); // stale node from a dead daemon
    use std::os::unix::process::CommandExt;
    // Dev diagnostic: SMOLVM_CUDA_DAEMON_STDERR=<path> captures the daemon's
    // stderr (fork-isolation traces, backend selection) instead of dropping it.
    let stderr = match std::env::var_os("SMOLVM_CUDA_DAEMON_STDERR") {
        Some(p) => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null()),
        None => Stdio::null(),
    };
    let mut command = Command::new(executable);
    command
        .args(["_cuda-daemon", &sock.to_string_lossy()])
        .env("CUDA_DEVICE_ORDER", CUDA_DEVICE_ORDER)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        // Own process group so the daemon outlives the VM that first spawned it.
        .process_group(0);
    if automatic_fork_workers {
        for flag in ["SMOLVM_CUDA_FORK_WORKERS", "SMOLVM_CUDA_FORK_ISOLATE"] {
            if std::env::var_os(flag).is_none() {
                command.env(flag, "1");
            }
        }
    }
    command.spawn()?;
    for _ in 0..200 {
        if is_alive(&sock) {
            return Ok(sock);
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "shared CUDA daemon did not come up",
    ))
}

/// Minimal RAII `flock(LOCK_EX)` guard on a lock file.
struct FileLock(std::fs::File);

impl FileLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileLock(f))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(all(test, target_os = "linux"))]
mod mps_tests {
    use super::{
        clone_layout_reservation_envelopes, clone_layout_reservations, clone_worker_idle_expired,
        clone_worker_idle_timeout_from, clone_worker_share_env, clone_worker_spawn_pace,
        clone_worker_status_dir_for, clone_worker_vm_is_alive, consume_procmem_preamble,
        create_host_snapshot_memfd, create_private_mps_paths, daemon_has_live_cuda_clients,
        daemon_socket_access, decode_attach_procmem, decode_clone_worker_capability,
        decode_clone_worker_status, disabled_worker_route, encode_attach_procmem,
        encode_clone_worker_capability, encode_clone_worker_status, fork_snapshot_enabled,
        golden_eviction_enabled, host_snapshot_fits, host_snapshot_reconstructable, lift_owned_fds,
        live_host_snapshot_count, local_cuda_daemon_socket, map_module_blob_fd, mps_enabled,
        next_clone_reservation_reexec, ordinary_regions_are_reserved, posix_spawn_clone_worker,
        prepare_module_blob, prepare_streamed_module_blob, prune_dead_clone_worker_statuses_in,
        publish_clone_worker_capability, range_is_reserved, read_host_snapshot,
        reconstruct_golden_modules, recv_fd, redeem_tensor_bundle_from_stream, seal_host_snapshot,
        select_golden_owner, send_fd, send_tensor_bundle_to_parent, serve_tensor_bundle_consumer,
        spawn_clone_attach_listener_with_timeout, spawn_tensor_bundle_receiver,
        tensor_bundle_ttl_from, unique_live_clone_worker, validate_tensor_bundle_metadata,
        write_module_handoff, CloneWorkerSpawnFds, CloneWorkerStatus, DEFAULT_TENSOR_BUNDLE_TTL,
        MAX_CLONE_RESERVATION_GRANULARITY, TENSOR_CONSUME_MAGIC,
    };
    use std::collections::HashMap;
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn daemon_socket_is_private_or_limited_to_the_vmm_group() {
        assert_eq!(daemon_socket_access(1000, None).unwrap(), (0o600, None));
        assert_eq!(
            daemon_socket_access(0, Some(123)).unwrap(),
            (0o660, Some(123))
        );
        assert!(daemon_socket_access(0, None).is_err());
    }

    #[test]
    fn high_fanout_clone_workers_keep_a_bounded_spawn_interval() {
        assert_eq!(clone_worker_spawn_pace(None), Duration::ZERO);
        assert_eq!(clone_worker_spawn_pace(Some(4)), Duration::ZERO);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(clone_worker_spawn_pace(Some(5)), Duration::from_millis(20));
            assert_eq!(clone_worker_spawn_pace(Some(64)), Duration::from_millis(20));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(clone_worker_spawn_pace(Some(5)), Duration::ZERO);
            assert_eq!(clone_worker_spawn_pace(Some(64)), Duration::ZERO);
        }
    }

    #[test]
    fn clone_worker_posix_spawn_preserves_the_descriptor_contract() {
        let mut connection = [-1; 2];
        let mut control = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET,
                    0,
                    connection.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, control.as_mut_ptr())
            },
            0
        );
        let pid = posix_spawn_clone_worker(
            std::path::Path::new("/bin/true"),
            &[("SMOLVM_SPAWN_TEST".into(), "1".into())],
            CloneWorkerSpawnFds {
                connection: connection[1],
                exports: &[],
                control: (control[1], 4),
                publish: None,
                module: None,
                module_images: None,
            },
        )
        .unwrap();
        unsafe {
            for fd in connection.into_iter().chain(control) {
                libc::close(fd);
            }
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, 0) },
            pid as i32
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn worker_fd_sources_are_lifted_above_every_dup_destination() {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
        use std::os::fd::{FromRawFd as _, IntoRawFd as _};

        let mut sources = Vec::new();
        for value in [11_u8, 22, 33] {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(&[value]).unwrap();
            sources.push(file.into_raw_fd());
        }
        let lifted = lift_owned_fds(sources, 512).unwrap();
        assert!(lifted.iter().all(|&fd| fd >= 512));
        for (fd, value) in lifted.into_iter().zip([11_u8, 22, 33]) {
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut got = [0_u8; 1];
            file.read_exact(&mut got).unwrap();
            assert_eq!(got, [value]);
        }
    }

    #[test]
    fn module_blob_fd_mappings_are_offset_independent() {
        use std::io::{Seek as _, Write as _};
        use std::os::fd::AsRawFd as _;

        let expected = b"immutable cuda module handoff";
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(expected).unwrap();
        assert_eq!(file.stream_position().unwrap(), expected.len() as u64);
        let first = unsafe { libc::dup(file.as_raw_fd()) };
        let second = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(first >= 0 && second >= 0);

        let first = map_module_blob_fd(first).unwrap();
        let second = map_module_blob_fd(second).unwrap();
        assert_eq!(first.as_slice(), expected);
        assert_eq!(second.as_slice(), expected);
        assert_eq!(file.stream_position().unwrap(), expected.len() as u64);
    }

    #[test]
    fn module_blob_mapping_rejects_empty_and_non_file_sources() {
        use std::os::fd::IntoRawFd as _;

        let empty = tempfile::tempfile().unwrap();
        assert_eq!(
            map_module_blob_fd(empty.into_raw_fd())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::File::open(directory.path()).unwrap();
        assert_eq!(
            map_module_blob_fd(directory.into_raw_fd())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn parsed_module_images_keep_the_mapped_blob_alive() {
        use std::io::Write as _;
        use std::os::fd::IntoRawFd as _;

        let image = b"mapped-cubin";
        let mut blob = Vec::new();
        blob.extend_from_slice(&1_u32.to_le_bytes());
        blob.extend_from_slice(&0x1234_u64.to_le_bytes());
        blob.extend_from_slice(&(image.len() as u32).to_le_bytes());
        blob.extend_from_slice(image);
        blob.extend_from_slice(&0_u32.to_le_bytes()); // functions
        blob.extend_from_slice(&0_u32.to_le_bytes()); // streams
        blob.extend_from_slice(&0_u32.to_le_bytes()); // events

        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&blob).unwrap();
        let source = map_module_blob_fd(file.into_raw_fd()).unwrap();
        let mut backend = smolvm_cuda::host::CpuBackend::default();
        let (images, functions, streams, events, graphs, handles) =
            reconstruct_golden_modules(&mut backend, &source, None).unwrap();
        drop(source);

        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, 0x1234);
        assert_eq!(images[0].1.as_slice(), image);
        assert!(functions.is_empty());
        assert!(streams.is_empty());
        assert!(events.is_empty());
        assert!(graphs.is_empty());
        assert!(handles.is_empty());
    }

    #[test]
    fn external_module_image_store_keeps_handoff_metadata_small() {
        use std::io::Write as _;
        use std::os::fd::IntoRawFd as _;

        let image: Arc<[u8]> = b"external-module-image".as_slice().into();
        let snapshot = (
            vec![(0x1234, image.clone())],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut image_file = tempfile::tempfile().unwrap();
        image_file.write_all(&image).unwrap();
        let image_store = smolvm_cuda::host::ModuleImageStoreSnapshot {
            file: image_file.try_clone().unwrap(),
            ranges: std::collections::HashMap::from([(0x1234, (0, image.len() as u64))]),
            bytes: image.len() as u64,
        };
        let mut metadata = Vec::new();
        write_module_handoff(&mut metadata, &snapshot, &Vec::new(), Some(&image_store)).unwrap();
        assert!(metadata.starts_with(&super::EXTERNAL_MODULE_IMAGES_MAGIC));
        assert!(!metadata
            .windows(image.len())
            .any(|window| window == image.as_ref()));

        let mut metadata_file = tempfile::tempfile().unwrap();
        metadata_file.write_all(&metadata).unwrap();
        let metadata_source = map_module_blob_fd(metadata_file.into_raw_fd()).unwrap();
        let image_source = map_module_blob_fd(image_file.into_raw_fd()).unwrap();
        let mut backend = smolvm_cuda::host::CpuBackend::default();
        assert_eq!(
            reconstruct_golden_modules(&mut backend, &metadata_source, None)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut invalid_range = metadata.clone();
        invalid_range[16..24].copy_from_slice(&1_u64.to_le_bytes());
        let invalid_range = smolvm_cuda::host::ModuleHandoffBytes::from_owned(invalid_range);
        assert_eq!(
            reconstruct_golden_modules(&mut backend, &invalid_range, Some(&image_source))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let (images, functions, streams, events, graphs, handles) =
            reconstruct_golden_modules(&mut backend, &metadata_source, Some(&image_source))
                .unwrap();
        drop(metadata_source);
        drop(image_source);

        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, 0x1234);
        assert_eq!(images[0].1.as_slice(), image.as_ref());
        assert!(functions.is_empty());
        assert!(streams.is_empty());
        assert!(events.is_empty());
        assert!(graphs.is_empty());
        assert!(handles.is_empty());
    }

    #[test]
    fn truncated_module_handoff_fails_closed() {
        let source = smolvm_cuda::host::ModuleHandoffBytes::from_owned(vec![1, 0, 0]);
        let mut backend = smolvm_cuda::host::CpuBackend::default();
        assert_eq!(
            reconstruct_golden_modules(&mut backend, &source, None)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn dead_lineages_do_not_retain_module_blobs() {
        let token = u64::MAX - 91;
        let blob = prepare_module_blob(token, 0, b"short-lived module state").unwrap();
        assert_eq!(blob.bytes, 24);
        assert!(super::cached_module_blob(token).is_none());
    }

    #[test]
    fn streamed_module_handoff_preserves_the_wire_format() {
        use smolvm_cuda::host::{GraphKernelNode, GraphSer};

        let snapshot = (
            vec![(0x10, Arc::<[u8]>::from(&b"module-image"[..]))],
            vec![(0x20, 0x10, "kernel".to_owned(), vec![(8, 49_152), (-1, -2)])],
            vec![(0x30, 1)],
            vec![(0x40, 2)],
            vec![(
                0x50,
                0x51,
                GraphSer {
                    nodes: vec![GraphKernelNode {
                        func: 0x20,
                        grid: [2, 3, 4],
                        block: [5, 6, 7],
                        shared_mem: 8,
                        params: vec![vec![1, 2], vec![3, 4, 5]],
                    }],
                    edges: vec![(0, 0)],
                },
            )],
            vec![(3, 0x1234, 0x60, vec![9, 8])],
        );
        let oplogs = vec![(0x50, 0x51, vec![vec![7, 6, 5]])];

        let mut actual = Vec::new();
        let written = write_module_handoff(&mut actual, &snapshot, &oplogs, None).unwrap();

        fn u16_field(output: &mut Vec<u8>, value: u16) {
            output.extend_from_slice(&value.to_le_bytes());
        }
        fn u32_field(output: &mut Vec<u8>, value: u32) {
            output.extend_from_slice(&value.to_le_bytes());
        }
        fn i32_field(output: &mut Vec<u8>, value: i32) {
            output.extend_from_slice(&value.to_le_bytes());
        }
        fn u64_field(output: &mut Vec<u8>, value: u64) {
            output.extend_from_slice(&value.to_le_bytes());
        }
        fn bytes_field(output: &mut Vec<u8>, value: &[u8]) {
            u32_field(output, value.len() as u32);
            output.extend_from_slice(value);
        }

        let mut expected = Vec::new();
        u32_field(&mut expected, 1); // modules
        u64_field(&mut expected, 0x10);
        bytes_field(&mut expected, b"module-image");
        u32_field(&mut expected, 1); // functions
        u64_field(&mut expected, 0x20);
        u64_field(&mut expected, 0x10);
        bytes_field(&mut expected, b"kernel");
        u32_field(&mut expected, 2); // attributes
        i32_field(&mut expected, 8);
        i32_field(&mut expected, 49_152);
        i32_field(&mut expected, -1);
        i32_field(&mut expected, -2);
        u32_field(&mut expected, 1); // streams
        u64_field(&mut expected, 0x30);
        u32_field(&mut expected, 1);
        u32_field(&mut expected, 1); // events
        u64_field(&mut expected, 0x40);
        u32_field(&mut expected, 2);
        u32_field(&mut expected, 1); // graphs
        u64_field(&mut expected, 0x50);
        u64_field(&mut expected, 0x51);
        u32_field(&mut expected, 1); // nodes
        u64_field(&mut expected, 0x20);
        for value in [2, 3, 4, 5, 6, 7, 8] {
            u32_field(&mut expected, value);
        }
        u32_field(&mut expected, 2); // parameters
        bytes_field(&mut expected, &[1, 2]);
        bytes_field(&mut expected, &[3, 4, 5]);
        u32_field(&mut expected, 1); // edges
        u32_field(&mut expected, 0);
        u32_field(&mut expected, 0);
        u32_field(&mut expected, 1); // library handles
        expected.push(3);
        u16_field(&mut expected, 0x1234);
        u64_field(&mut expected, 0x60);
        bytes_field(&mut expected, &[9, 8]);
        u32_field(&mut expected, 1); // op-log graphs
        u64_field(&mut expected, 0x50);
        u64_field(&mut expected, 0x51);
        u32_field(&mut expected, 1);
        bytes_field(&mut expected, &[7, 6, 5]);

        assert_eq!(written, expected.len() as u64);
        assert_eq!(actual, expected);

        let token = u64::MAX - 92;
        let blob = prepare_streamed_module_blob(token, 0, &snapshot, &oplogs, None).unwrap();
        assert_eq!(blob.bytes, expected.len() as u64);
        assert_eq!(blob.file.metadata().unwrap().len(), expected.len() as u64);
        let mapped = unsafe {
            smolvm_cuda::host::ModuleHandoffBytes::map_read_only(&blob.file, expected.len())
        }
        .unwrap();
        assert_eq!(mapped.as_slice(), expected);
        assert!(super::cached_module_blob(token).is_none());
    }

    #[test]
    fn capacity_policy_preamble_roundtrips() {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;

        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(b"SMVCPOL1");
        bytes[8..16].copy_from_slice(&(10_u64 * 1024 * 1024 * 1024).to_le_bytes());
        bytes[16..20].copy_from_slice(&2_u32.to_le_bytes());
        writer.write_all(&bytes).unwrap();

        let policy = super::consume_policy_preamble(reader.as_raw_fd());
        assert_eq!(policy.vram_limit_bytes, Some(10_u64 * 1024 * 1024 * 1024));
        assert_eq!(policy.fork_pool_size, Some(2));
        assert!(!policy.fork_clone);
    }

    #[test]
    fn zero_region_procmem_preamble_carries_clone_lifetime() {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;

        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut bytes = [0u8; 20];
        bytes[..8].copy_from_slice(b"SMVGPVM1");
        bytes[8..12].copy_from_slice(&4242_u32.to_le_bytes());
        writer.write_all(&bytes).unwrap();

        assert_eq!(
            consume_procmem_preamble(reader.as_raw_fd()),
            Some((4242, Vec::new()))
        );
    }

    #[test]
    fn clone_worker_idle_grace_has_bounded_default_and_override() {
        assert_eq!(clone_worker_idle_timeout_from(None).as_secs(), 300);
        assert_eq!(clone_worker_idle_timeout_from(Some(" 7 ")).as_secs(), 7);
        assert_eq!(
            clone_worker_idle_timeout_from(Some("invalid")).as_secs(),
            300
        );
    }

    #[test]
    fn tensor_bundle_lifetime_covers_delayed_cohort_consumers() {
        assert_eq!(tensor_bundle_ttl_from(None), Duration::from_secs(300));
        assert_eq!(
            tensor_bundle_ttl_from(Some(" 600 ")),
            Duration::from_secs(600)
        );
        assert_eq!(tensor_bundle_ttl_from(Some("0")), DEFAULT_TENSOR_BUNDLE_TTL);
        assert_eq!(
            tensor_bundle_ttl_from(Some("3601")),
            DEFAULT_TENSOR_BUNDLE_TTL
        );
        assert_eq!(
            tensor_bundle_ttl_from(Some("invalid")),
            DEFAULT_TENSOR_BUNDLE_TTL
        );
    }

    #[test]
    fn daemon_idle_watchdog_counts_routed_clone_workers() {
        assert!(!daemon_has_live_cuda_clients(0, 0, 0));
        assert!(daemon_has_live_cuda_clients(1, 0, 0));
        assert!(daemon_has_live_cuda_clients(0, 1, 0));
        assert!(daemon_has_live_cuda_clients(0, 0, 1));
    }

    #[test]
    fn golden_eviction_is_automatic_for_fork_pools_with_a_kill_switch() {
        assert!(golden_eviction_enabled(None, Some(4)));
        assert!(golden_eviction_enabled(Some("on"), Some(4)));
        assert!(!golden_eviction_enabled(Some("off"), Some(4)));
        assert!(!golden_eviction_enabled(None, None));
        assert!(!golden_eviction_enabled(Some("force"), None));
    }

    #[test]
    fn shared_forks_retain_one_reusable_snapshot_without_requiring_a_pool() {
        assert!(fork_snapshot_enabled(false, true));
        assert!(fork_snapshot_enabled(true, false));
        assert!(!fork_snapshot_enabled(false, false));
    }

    #[test]
    fn golden_eviction_requires_one_unambiguous_vm_owner() {
        assert_eq!(select_golden_owner(vec![7], None, &[7, 8]), Some(7));
        assert_eq!(select_golden_owner(Vec::new(), Some(8), &[7, 8]), Some(8));
        assert_eq!(select_golden_owner(Vec::new(), None, &[7]), Some(7));
        assert_eq!(select_golden_owner(vec![7, 8], None, &[7, 8]), None);
        assert_eq!(select_golden_owner(Vec::new(), None, &[7, 8]), None);
    }

    #[test]
    fn host_snapshot_capacity_preserves_a_host_reserve() {
        let eight_gib_kib = 8 * 1024 * 1024;
        let meminfo =
            format!("MemTotal:       {eight_gib_kib} kB\nMemAvailable:   {eight_gib_kib} kB\n");
        assert!(host_snapshot_fits(2 << 30, &meminfo));
        assert!(!host_snapshot_fits(7 << 30, &meminfo));
        assert!(!host_snapshot_fits(1, "MemTotal: 8192 kB\n"));
    }

    #[test]
    fn host_snapshot_requires_address_preserved_device_memory() {
        assert!(!host_snapshot_reconstructable(0, 0));
        assert!(host_snapshot_reconstructable(1, 0));
        assert!(host_snapshot_reconstructable(0, 1));
    }

    #[test]
    fn frozen_memory_layout_is_not_reclassified_as_metadata_only() {
        let token = u64::MAX - 41;
        super::host_snapshot_cache().lock().unwrap().insert(
            token,
            Arc::new(super::CachedHostSnapshot {
                layout: String::new(),
                device: 0,
                fds: Vec::new(),
                host_bytes: 1,
                golden_pid: std::sync::atomic::AtomicU32::new(0),
            }),
        );

        assert!(!super::retain_metadata_layout_for_clone(token, 7, 11));
        assert!(!super::metadata_layout_waiters()
            .lock()
            .unwrap()
            .contains_key(&token));

        super::host_snapshot_cache().lock().unwrap().remove(&token);
    }

    #[test]
    fn dead_golden_snapshot_is_released_without_the_idle_watchdog() {
        let token = u64::MAX - 42;
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        super::host_snapshot_cache().lock().unwrap().insert(
            token,
            Arc::new(super::CachedHostSnapshot {
                layout: String::new(),
                device: 0,
                fds: Vec::new(),
                host_bytes: 1,
                golden_pid: std::sync::atomic::AtomicU32::new(pid),
            }),
        );

        assert_eq!(live_host_snapshot_count(), 0);
        assert!(!super::host_snapshot_cache()
            .lock()
            .unwrap()
            .contains_key(&token));
    }

    #[test]
    fn host_snapshot_roundtrips_and_is_immutable_after_sealing() {
        let fd = create_host_snapshot_memfd().unwrap();
        super::append_host_snapshot(fd, 0, b"frozen cuda state").unwrap();
        seal_host_snapshot(fd).unwrap();
        assert_eq!(read_host_snapshot(fd, 0, 17).unwrap(), b"frozen cuda state");
        assert!(super::append_host_snapshot(fd, 0, b"changed").is_err());
        unsafe { libc::close(fd) };
    }

    #[test]
    fn live_clone_vm_prevents_worker_idle_expiry() {
        let elapsed = Duration::from_secs(600);
        let fallback = Duration::from_secs(300);
        assert!(!clone_worker_idle_expired(0, Some(true), elapsed, fallback));
        assert!(!clone_worker_idle_expired(
            1,
            Some(false),
            elapsed,
            fallback
        ));
        assert!(clone_worker_idle_expired(
            0,
            Some(false),
            Duration::from_secs(5),
            fallback
        ));
        assert!(clone_worker_idle_expired(0, None, elapsed, fallback));
    }

    #[test]
    fn clone_vm_liveness_uses_the_advertised_host_pid() {
        assert!(clone_worker_vm_is_alive(std::process::id()));
        assert!(!clone_worker_vm_is_alive(u32::MAX));
    }

    #[test]
    fn clone_worker_waits_for_every_active_channel_before_idle_exit() {
        let mut sockets = [-1; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sockets.as_mut_ptr())
        };
        assert_eq!(rc, 0);

        // Model one primary channel and one already-attached channel. The
        // listener must outlive primary EOF while the attached session runs.
        let active = Arc::new(AtomicUsize::new(2));
        let listener = spawn_clone_attach_listener_with_timeout(
            sockets[1],
            0,
            Arc::new((None, Vec::new())),
            active.clone(),
            None,
            Duration::ZERO,
        )
        .unwrap();
        active.fetch_sub(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(!listener.is_finished());

        active.fetch_sub(1, Ordering::SeqCst);
        listener.join().unwrap();
        unsafe { libc::close(sockets[0]) };
    }

    #[test]
    fn clone_attach_procmem_metadata_roundtrips() {
        let advert = (
            4242,
            vec![
                (0, 0x7f00_0000, 0x1000),
                (0x1_0000_0000, 0x7f10_0000, 0x20_0000),
            ],
        );
        assert_eq!(
            decode_attach_procmem(&encode_attach_procmem(Some(&advert))).unwrap(),
            Some(advert)
        );
        assert_eq!(
            decode_attach_procmem(&encode_attach_procmem(None)).unwrap(),
            None
        );
        assert!(decode_attach_procmem(b"bad").is_err());
    }

    #[test]
    fn clone_attach_fd_and_procmem_stay_in_one_packet() {
        use std::os::fd::AsRawFd;

        let mut sockets = [-1; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sockets.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        let file = tempfile::tempfile().unwrap();
        let advert = (4242, vec![(0x1000, 0x2000, 0x3000)]);

        send_fd(sockets[0], file.as_raw_fd(), Some(&advert)).unwrap();
        let (received, got) = recv_fd(sockets[1]).unwrap();

        assert_eq!(got, Some(advert));
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(received, &mut stat) }, 0);
        assert!(stat.st_size >= 0);
        unsafe {
            libc::close(received);
            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
    }

    #[test]
    fn tensor_bundle_metadata_rejects_ranges_outside_the_export() {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&2u32.to_le_bytes());
        metadata.extend_from_slice(&2u32.to_le_bytes());
        metadata.extend_from_slice(b"{}");
        metadata.extend_from_slice(&0u64.to_le_bytes());
        metadata.extend_from_slice(&64u64.to_le_bytes());
        metadata.extend_from_slice(&64u64.to_le_bytes());
        metadata.extend_from_slice(&32u64.to_le_bytes());
        validate_tensor_bundle_metadata(&metadata, 128).unwrap();

        metadata[26..34].copy_from_slice(&96u64.to_le_bytes());
        assert!(validate_tensor_bundle_metadata(&metadata, 128).is_err());
    }

    #[test]
    fn tensor_bundle_token_transfers_one_fd_once() {
        use smolvm_cuda::host::{DeviceTensorBundle, PublishedTensorRange};
        use std::os::fd::OwnedFd;

        let (mut worker, parent) = std::os::unix::net::UnixStream::pair().unwrap();
        spawn_tensor_bundle_receiver(parent, std::process::id()).unwrap();
        let allocation: OwnedFd = tempfile::tempfile().unwrap().into();
        let token = send_tensor_bundle_to_parent(
            &mut worker,
            DeviceTensorBundle {
                allocation,
                allocation_size: 4096,
                manifest: br#"{"name":"adapter"}"#.to_vec(),
                tensors: vec![
                    PublishedTensorRange {
                        offset: 0,
                        size: 64,
                    },
                    PublishedTensorRange {
                        offset: 64,
                        size: 32,
                    },
                ],
            },
        )
        .unwrap();
        assert_eq!(token.len(), 32);

        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let served = std::thread::spawn(move || serve_tensor_bundle_consumer(server));
        let redeemed = redeem_tensor_bundle_from_stream(client, &token).unwrap();
        assert_eq!(redeemed.allocation_size, 4096);
        validate_tensor_bundle_metadata(&redeemed.metadata, redeemed.allocation_size).unwrap();
        drop(redeemed);
        served.join().unwrap().unwrap();

        let (mut retry, retry_server) = std::os::unix::net::UnixStream::pair().unwrap();
        retry.write_all(&TENSOR_CONSUME_MAGIC).unwrap();
        retry
            .write_all(&(token.len() as u16).to_le_bytes())
            .unwrap();
        retry.write_all(&token).unwrap();
        assert!(serve_tensor_bundle_consumer(retry_server).is_err());
    }

    #[test]
    fn published_tensor_bundle_outlives_its_clone_worker_channel() {
        use smolvm_cuda::host::{DeviceTensorBundle, PublishedTensorRange};
        use std::os::fd::OwnedFd;

        let (mut worker, parent) = std::os::unix::net::UnixStream::pair().unwrap();
        spawn_tensor_bundle_receiver(parent, u32::MAX).unwrap();
        let allocation: OwnedFd = tempfile::tempfile().unwrap().into();
        let token = send_tensor_bundle_to_parent(
            &mut worker,
            DeviceTensorBundle {
                allocation,
                allocation_size: 4096,
                manifest: br#"{"name":"adapter"}"#.to_vec(),
                tensors: vec![PublishedTensorRange {
                    offset: 0,
                    size: 64,
                }],
            },
        )
        .unwrap();
        drop(worker);

        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let served = std::thread::spawn(move || serve_tensor_bundle_consumer(server));
        let redeemed = redeem_tensor_bundle_from_stream(client, &token).unwrap();
        assert_eq!(redeemed.allocation_size, 4096);
        served.join().unwrap().unwrap();
    }

    #[test]
    fn tokenless_clone_worker_selection_fails_closed_when_ambiguous() {
        let mut workers = HashMap::new();
        workers.insert((10, 7), (101, 201));
        workers.insert((20, 8), (102, 202));

        assert_eq!(unique_live_clone_worker(&workers, 9, |_| true), Ok(None));
        assert_eq!(
            unique_live_clone_worker(&workers, 7, |_| true),
            Ok(Some((101, 201)))
        );

        workers.insert((30, 7), (103, 203));
        assert_eq!(unique_live_clone_worker(&workers, 7, |_| true), Err(2));
        assert_eq!(
            unique_live_clone_worker(&workers, 7, |pid| pid == 103),
            Ok(Some((103, 203)))
        );
    }

    #[test]
    fn clone_share_kill_switch_overrides_fork_request() {
        assert_eq!(clone_worker_share_env(true, None), Some("1"));
        assert_eq!(clone_worker_share_env(true, Some("0")), Some("0"));
        assert_eq!(clone_worker_share_env(true, Some("false")), Some("0"));
        assert_eq!(clone_worker_share_env(true, Some("off")), Some("0"));
        assert_eq!(clone_worker_share_env(false, None), None);
    }

    #[test]
    fn clone_worker_status_round_trips_and_rejects_ambiguous_records() {
        for status in [CloneWorkerStatus::Ready, CloneWorkerStatus::Failed] {
            let encoded = encode_clone_worker_status(42, status);
            assert_eq!(decode_clone_worker_status(&encoded), Some((42, status)));
        }
        assert_eq!(decode_clone_worker_status("42 ready trailing"), None);
        assert_eq!(decode_clone_worker_status("42 unknown"), None);
        assert_eq!(decode_clone_worker_status("ready"), None);
    }

    #[test]
    fn explicit_daemon_readiness_uses_a_socket_scoped_directory() {
        let socket = std::path::Path::new("/run/smolvm/custom.sock");
        assert_eq!(
            clone_worker_status_dir_for(socket),
            std::path::Path::new("/run/smolvm/custom.sock.workers")
        );
        assert_eq!(
            local_cuda_daemon_socket(Some(std::ffi::OsStr::new("/run/smolvm/custom.sock"))),
            Some(socket.to_path_buf())
        );
        assert_eq!(
            local_cuda_daemon_socket(Some(std::ffi::OsStr::new("gpu.example:7001"))),
            None
        );
        assert_eq!(
            local_cuda_daemon_socket(Some(std::ffi::OsStr::new("relative.sock"))),
            None
        );
    }

    #[test]
    fn readiness_capability_is_protocol_bound_and_unambiguous() {
        let encoded = encode_clone_worker_capability(42, 99);
        assert_eq!(decode_clone_worker_capability(&encoded), Some((42, 99)));
        assert_eq!(
            decode_clone_worker_capability("1 42 99 0000000000000000\n"),
            None
        );
        assert_eq!(
            decode_clone_worker_capability(&format!("{} trailing", encoded.trim_end())),
            None
        );
    }

    #[test]
    fn published_readiness_capability_identifies_the_live_daemon() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("external.sock");
        publish_clone_worker_capability(&socket).unwrap();
        let capability = super::clone_worker_capability_path(&socket);
        assert!(super::clone_worker_readiness_supported_at(
            &socket,
            |pid, started| pid == std::process::id() as i32
                && crate::process::process_start_time(pid) == Some(started)
        ));
        assert!(!super::clone_worker_readiness_supported_at(
            &socket,
            |_, _| false
        ));
        prune_dead_clone_worker_statuses_in(capability.parent().unwrap());
        assert!(capability.is_file());
    }

    #[test]
    fn disabled_worker_mode_consumes_only_warm_dials() {
        assert_eq!(disabled_worker_route(1, false, true), Some(false));
        assert_eq!(disabled_worker_route(3, false, true), Some(true));
        assert_eq!(disabled_worker_route(3, true, false), Some(true));
        assert_eq!(disabled_worker_route(3, true, true), None);
    }

    #[test]
    fn clone_address_envelopes_align_merge_and_cover_original_ranges() {
        let layout = concat!(
            "resv=312400000:200000,314000000:1400000,|maps=|",
            "aregions=7a5ed2400000:200000:0,7a5ed2600000:200000:200000,"
        );
        let ranges = clone_layout_reservation_envelopes(layout, 0x2000000);

        assert_eq!(
            ranges,
            vec![(0x312000000, 0x4000000), (0x7a5ed2000000, 0x2000000)]
        );
        assert!(range_is_reserved(&ranges, 0x312400000, 0x200000));
        assert!(range_is_reserved(&ranges, 0x314000000, 0x1400000));
        assert!(range_is_reserved(&ranges, 0x7a5ed2600000, 0x200000));
        assert!(!range_is_reserved(&ranges, 0x316000000, 0x200000));

        let fallback =
            clone_layout_reservation_envelopes(layout, MAX_CLONE_RESERVATION_GRANULARITY);
        for (base, size) in clone_layout_reservations(layout) {
            assert!(range_is_reserved(&fallback, base, size));
        }
    }

    #[test]
    fn clone_address_collision_reexec_is_bounded() {
        assert_eq!(next_clone_reservation_reexec(None, true, false), Some(1));
        assert_eq!(
            next_clone_reservation_reexec(Some("1"), true, false),
            Some(2)
        );
        assert_eq!(next_clone_reservation_reexec(Some("2"), true, false), None);
        assert_eq!(
            next_clone_reservation_reexec(Some("invalid"), true, false),
            Some(1)
        );
        assert_eq!(next_clone_reservation_reexec(None, false, false), None);
        assert_eq!(next_clone_reservation_reexec(None, true, true), None);
    }

    #[test]
    fn ordinary_restore_requires_every_region_to_keep_its_golden_address() {
        let reserved = vec![(0x1000, 0x4000), (0x8000, 0x2000)];
        assert!(ordinary_regions_are_reserved(
            &[(0x1000, 0x2000, 0), (0x8000, 0x1000, 0x2000)],
            &reserved,
        ));
        assert!(!ordinary_regions_are_reserved(
            &[(0x1000, 0x2000, 0), (0xa000, 0x1000, 0x2000)],
            &reserved,
        ));
    }

    #[test]
    fn mps_defaults_to_fork_worker_pools() {
        assert!(mps_enabled(None, true));
        assert!(!mps_enabled(None, false));
    }

    #[test]
    fn explicit_mps_mode_overrides_pool_default() {
        for off in ["0", "off", "FALSE", " no "] {
            assert!(!mps_enabled(Some(off), true), "{off}");
        }
        for on in ["1", "on", "TRUE", " yes ", "force"] {
            assert!(mps_enabled(Some(on), false), "{on}");
        }
    }

    #[test]
    fn private_mps_paths_are_new_and_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let pipe = tmp.path().join("pipe");
        let log_root = tmp.path().join("log-root");
        let logs = log_root.join("123");

        create_private_mps_paths(&pipe, &log_root, &logs).unwrap();

        assert!(pipe.is_dir());
        assert!(logs.is_dir());
        assert_eq!(
            std::fs::metadata(&pipe).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&logs).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn private_mps_path_collision_is_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let pipe = tmp.path().join("pipe");
        let log_root = tmp.path().join("log-root");
        let logs = log_root.join("123");
        std::fs::create_dir(&pipe).unwrap();
        std::fs::write(pipe.join("owner-sentinel"), b"keep").unwrap();

        let error = create_private_mps_paths(&pipe, &log_root, &logs).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(pipe.join("owner-sentinel")).unwrap(), b"keep");
        assert!(!logs.exists());
    }
}
