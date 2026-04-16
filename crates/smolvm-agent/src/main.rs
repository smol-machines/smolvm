//! smolvm guest agent.
//!
//! This agent runs inside smolvm VMs and handles:
//! - OCI image pulling via crane
//! - Layer extraction and storage management
//! - Overlay filesystem preparation for workloads
//! - Command execution with optional interactive/TTY support
//!
//! Communication is via vsock on port 6000.

use smolvm_protocol::{
    error_codes, ports, AgentRequest, AgentResponse, Envelope, RegistryAuth, LAYER_CHUNK_SIZE,
    PROTOCOL_VERSION,
};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};

mod crun;

/// Ensures storage disk is mounted exactly once. The mount happens either during
/// deferred init (the common case) or on the first request that needs storage
/// (if a request arrives before deferred init reaches the mount step).
/// This eliminates the race between early ready signaling and storage access.
static STORAGE_MOUNTED: OnceLock<bool> = OnceLock::new();

fn ensure_storage_mounted() -> bool {
    *STORAGE_MOUNTED.get_or_init(|| {
        let t0 = uptime_ms();
        let ok = mount_storage_disk();
        // Log after tracing may or may not be initialized — use boot_log for safety.
        if ok {
            boot_log(
                "INFO",
                &format!("storage disk mounted (duration_ms={})", uptime_ms() - t0),
            );
        } else {
            boot_log(
                "ERROR",
                "storage disk NOT mounted — image pulls and container overlays will fail",
            );
        }
        ok
    })
}

/// Format a structured JSON log line for early boot (before tracing is up).
fn format_boot_log(level: &str, msg: &str) -> String {
    let escaped = serde_json::to_string(msg).unwrap_or_else(|_| format!("\"{}\"", msg));
    format!(
        r#"{{"level":"{}","message":{},"target":"smolvm_agent::boot"}}"#,
        level, escaped
    )
}

/// Write a structured JSON log line to stderr during early boot,
/// before tracing_subscriber is initialized. This keeps
/// agent-console.log as valid JSON throughout.
fn boot_log(level: &str, msg: &str) {
    eprintln!("{}", format_boot_log(level, msg));
}
mod dns_proxy;
mod network;
mod oci;
mod paths;
mod process;
#[cfg(target_os = "linux")]
mod pty;
mod retry;
mod ssh_agent;
mod storage;
mod vsock;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Initial buffer size for reading requests from the vsock socket.
const REQUEST_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Maximum allowed message size to prevent DoS via memory exhaustion.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB

/// Buffer size for streaming stdout/stderr in interactive mode.
const IO_BUFFER_SIZE: usize = 4096;

/// Default poll timeout in milliseconds for interactive I/O loop.
const INTERACTIVE_POLL_TIMEOUT_MS: i32 = 100;

/// Timeout for network connectivity test operations.
/// Used in diagnostics/troubleshooting functions.
const NETWORK_TEST_TIMEOUT_SECS: u64 = 10;

/// Poll interval for checking process completion in VM exec.
const PROCESS_POLL_INTERVAL_MS: u64 = 10;

/// Get system uptime in milliseconds (for timing relative to boot).
fn uptime_ms() -> u64 {
    if let Ok(contents) = std::fs::read_to_string("/proc/uptime") {
        if let Some(uptime_str) = contents.split_whitespace().next() {
            if let Ok(uptime_secs) = uptime_str.parse::<f64>() {
                return (uptime_secs * 1000.0) as u64;
            }
        }
    }
    0
}

fn main() {
    // Quick --version check (used by init script to detect rootfs updates)
    if std::env::args().any(|a| a == "--version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    // CRITICAL: Mount essential filesystems FIRST, before anything else.
    // When running as init (PID 1), we need these for the system to function.
    // This must happen before logging (which needs /dev for output).
    mount_essential_filesystems();

    // Set up persistent rootfs overlay (if /dev/vdb exists).
    // This does overlayfs + pivot_root before anything else touches the filesystem.
    setup_persistent_rootfs();

    // CRITICAL: Create vsock listener IMMEDIATELY after mounts.
    // This must happen before logging setup to minimize time to listener ready.
    // The kernel boots in ~30ms and host connects immediately after.
    let listener = match vsock::listen(ports::AGENT_CONTROL) {
        Ok(l) => l,
        Err(e) => {
            boot_log("ERROR", &format!("FAILED to create vsock listener: {}", e));
            std::process::exit(1);
        }
    };

    // Set up signal handlers for graceful shutdown (sync before exit)
    setup_signal_handlers();

    // Signal readiness to host IMMEDIATELY after vsock listener is active.
    // The host detects this marker, then connects and sends its first request.
    // That connection takes ~10-30ms, giving us time to finish deferred init
    // below before the first request arrives.
    signal_ready_to_host();

    // --- Deferred init: runs while host is detecting marker + connecting ---
    // Storage mount is behind a OnceLock (ensure_storage_mounted) so it
    // happens exactly once — either here or on first storage-dependent request.

    let start_uptime = uptime_ms();

    // Initialize logging (deferred past ready signal — uses boot_log before this).
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("smolvm_agent=info".parse().expect("valid directive")),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        uptime_ms = start_uptime,
        "smolvm-agent started, vsock listener already ready"
    );

    let t0 = uptime_ms();
    match network::configure_from_env() {
        Ok(true) => {
            info!(
                duration_ms = uptime_ms() - t0,
                "guest virtio network configured"
            );
        }
        Ok(false) => {}
        Err(err) => {
            error!(error = %err, "failed to configure guest network");
            std::process::exit(1);
        }
    }

    // Mount storage disk eagerly during deferred init. If a request arrives
    // before this point, ensure_storage_mounted() handles the mount on demand.
    ensure_storage_mounted();

    // Create /workspace symlink for bare VMs. Image-based VMs get /workspace
    // via a bind mount in the container spec, but bare VMs run directly in the
    // VM rootfs where /workspace doesn't exist. The symlink makes /workspace
    // available in both modes.
    {
        let workspace_link = std::path::Path::new("/workspace");
        let workspace_target = std::path::Path::new("/storage/workspace");
        if !workspace_link.exists() && workspace_target.exists() {
            let _ = std::os::unix::fs::symlink(workspace_target, workspace_link);
        }
    }

    // Initialize packed layers support (if SMOLVM_PACKED_LAYERS env var is set)
    let t0 = uptime_ms();
    if let Some(packed_dir) = storage::get_packed_layers_dir() {
        info!(
            duration_ms = uptime_ms() - t0,
            packed_dir = %packed_dir.display(),
            "packed layers initialized"
        );
    }

    // Initialize volume mounts from SMOLVM_MOUNT_* env vars
    let t0 = uptime_ms();
    let boot_mounts = storage::init_volume_mounts();
    if !boot_mounts.is_empty() {
        info!(
            duration_ms = uptime_ms() - t0,
            mount_count = boot_mounts.len(),
            "volume mounts initialized at boot"
        );
    }

    // Registry load+reconcile deferred to first container operation via
    // REGISTRY.ensure_loaded(). On fresh boot, no containers from a previous
    // instance survive, so this work (~30-50ms for crun list + JSON parse)
    // is wasted if no container operations are requested.

    // Start SSH agent forwarding bridge if enabled by host
    if ssh_agent::is_enabled() {
        info!("SSH agent forwarding enabled, starting guest bridge");
        ssh_agent::start();
        // Set env so all child processes (git, ssh, etc.) find the agent socket
        std::env::set_var("SSH_AUTH_SOCK", ssh_agent::GUEST_SSH_AUTH_SOCK);
    }

    // Start DNS filtering proxy if enabled by host (when --allow-host is used)
    if dns_proxy::is_enabled() {
        info!("DNS filtering enabled, starting guest proxy");
        dns_proxy::start();
    }

    info!(
        total_startup_ms = uptime_ms() - start_uptime,
        uptime_ms = uptime_ms(),
        "agent init complete, entering accept loop"
    );

    // Start accepting connections (listener already bound)
    if let Err(e) = run_server_with_listener(listener) {
        error!(error = %e, "server error");
        std::process::exit(1);
    }
}

/// Well-known filename for the ready marker.
/// The agent creates this file in the virtiofs rootfs to signal readiness.
/// The host watches for it via inotify/kqueue instead of the vsock socket.
const READY_MARKER_FILENAME: &str = ".smolvm-ready";

/// Signal to the host that the agent is fully initialized and ready.
///
/// Creates a marker file in the virtiofs rootfs directory. Since virtiofs is
/// shared between host and guest, the host can detect this file instantly
/// via inotify/kqueue. This is more reliable than watching the vsock socket
/// file (which is created by libkrun's muxer thread before the agent boots).
///
/// After pivot_root, the virtiofs root is mounted at /oldroot.
/// Without overlay, the virtiofs root is /.
fn signal_ready_to_host() {
    use std::path::Path;

    let content = uptime_ms().to_string();

    // Try /oldroot first (overlay mode: virtiofs is the lower layer after pivot_root)
    // Before pivot_root: virtiofs is at /, so the / path works.
    let paths = [
        format!("/oldroot/{}", READY_MARKER_FILENAME),
        format!("/{}", READY_MARKER_FILENAME),
    ];

    for path in &paths {
        if Path::new(path).parent().map_or(false, |p| p.exists()) {
            if std::fs::write(path, content.as_bytes()).is_ok() {
                debug!(path = path, "ready marker written");
                return;
            }
        }
    }
}

/// Helper to create a CString from a static str.
/// Used by boot functions that call libc mount/mknod/pivot_root.
#[cfg(target_os = "linux")]
fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("static string without null bytes")
}

/// A single mount entry for `mount_essential_filesystems`.
#[cfg(target_os = "linux")]
struct MountEntry {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    flags: libc::c_ulong,
    data: Option<&'static str>,
}

#[cfg(target_os = "linux")]
impl MountEntry {
    fn mount(&self) -> Result<(), String> {
        if let Err(e) = std::fs::create_dir_all(self.target) {
            // Clean up any partial directories left by create_dir_all
            let _ = std::fs::remove_dir(self.target);
            return Err(format!("failed to create {}: {}", self.target, e));
        }

        // Bind the optional data CString so it lives through the libc::mount call.
        let data_cstr = self.data.map(cstr);
        let data_ptr = match &data_cstr {
            Some(d) => d.as_ptr() as *const libc::c_void,
            None => std::ptr::null(),
        };

        // SAFETY: libc::mount with valid CString pointers for filesystem mounting.
        // All CString values (from cstr() calls and data_cstr) are alive for the
        // duration of this call.
        let ret = unsafe {
            libc::mount(
                cstr(self.source).as_ptr(),
                cstr(self.target).as_ptr(),
                cstr(self.fstype).as_ptr(),
                self.flags,
                data_ptr,
            )
        };

        if ret != 0 {
            return Err(format!(
                "failed to mount {} at {}: {}",
                self.fstype,
                self.target,
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}

/// Mount essential filesystems (proc, sysfs, devtmpfs, devpts).
/// This must be done first when running as init (PID 1).
/// Uses direct syscalls to avoid any overhead.
#[cfg(target_os = "linux")]
fn mount_essential_filesystems() {
    // libkrun's init.c mounts /proc, /sys, /dev, /dev/pts before exec'ing
    // the agent. Skip redundant mounts if already present.
    if std::path::Path::new("/proc/uptime").exists() {
        // Ensure /dev/ptmx symlink exists (not set up by init.c)
        let _ = std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx");
        return;
    }

    let mounts = [
        MountEntry {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            flags: 0,
            data: None,
        },
        MountEntry {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            flags: 0,
            data: None,
        },
        MountEntry {
            source: "devtmpfs",
            target: "/dev",
            fstype: "devtmpfs",
            flags: 0,
            data: None,
        },
        MountEntry {
            source: "devpts",
            target: "/dev/pts",
            fstype: "devpts",
            flags: 0,
            data: Some("mode=0620,ptmxmode=0666"),
        },
    ];

    for entry in &mounts {
        if let Err(e) = entry.mount() {
            error!("smolvm-agent: {}", e);
            return;
        }
    }

    // Create /dev/ptmx symlink pointing to pts/ptmx
    // This ensures openpty() can find the PTY multiplexer
    let _ = std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx");

    // Set up loopback interface (non-blocking, best effort)
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd >= 0 {
            // This would require more complex ioctl calls, skip for now
            // The networking will be set up by TSI anyway
            libc::close(fd);
        }
    }
}

/// Stub for non-Linux platforms (agent only runs on Linux inside VM).
#[cfg(not(target_os = "linux"))]
fn mount_essential_filesystems() {
    // No-op on non-Linux platforms
}

/// Set up persistent rootfs overlay using overlayfs on /dev/vdb.
///
/// If /dev/vdb exists (overlay disk attached by host), this function:
/// 1. Mounts /dev/vdb as ext4 (formats on first boot)
/// 2. Creates overlayfs with initramfs as lower layer, /dev/vdb as upper
/// 3. Moves /proc, /sys, /dev into the new root
/// 4. Calls pivot_root to switch to the overlayfs root
///
/// After pivot_root, the old initramfs stays at /oldroot (needed as
/// overlay lower layer). All subsequent writes go through overlayfs
/// and are persisted to /dev/vdb.
///
/// If /dev/vdb doesn't exist, this is a no-op (backward compatible).
#[cfg(target_os = "linux")]
fn setup_persistent_rootfs() {
    use std::path::Path;

    const OVERLAY_DEVICE: &str = "/dev/vdb";
    const OVERLAY_MOUNT: &str = "/mnt/overlay";
    const STORAGE_DEVICE: &str = "/dev/vda";
    const STORAGE_TEMP_MOUNT: &str = "/mnt/storage";
    const NEWROOT: &str = "/mnt/newroot";

    // Make root mount private — required for mount --move and pivot_root.
    // libkrun's init.c sets MS_SHARED; we override with MS_PRIVATE.
    let root = cstr("/");
    // SAFETY: mount with MS_PRIVATE|MS_REC on root, no filesystem type
    unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        );
    }

    // If overlay device doesn't exist, no overlay disk attached — skip.
    // On devtmpfs, the kernel creates /dev/vdb automatically when libkrun
    // attaches a second virtio-blk disk. No mknod needed.
    if !Path::new(OVERLAY_DEVICE).exists() {
        return;
    }

    let _ = std::fs::create_dir_all(OVERLAY_MOUNT);

    // Resize ext4 on the UNMOUNTED device before mounting. The host copies
    // from a small template (~512MB) then extends the sparse file. resize2fs
    // on a mounted device fails with "Resource busy" — must resize first.
    // Skip if filesystem already fills the device (subsequent boots).
    // If resize fails (macOS-created template), the mount+mkfs fallback below handles it.
    if !ext4_already_full_size(OVERLAY_DEVICE) {
        let _ = resize_ext4_if_needed(OVERLAY_DEVICE, "overlay");
    }

    // Try to mount overlay disk (should be pre-formatted ext4)
    let dev = cstr(OVERLAY_DEVICE);
    let mnt = cstr(OVERLAY_MOUNT);
    let ext4 = cstr("ext4");
    // SAFETY: mount /dev/vdb as ext4 at /mnt/overlay with noatime
    let mounted = unsafe {
        libc::mount(
            dev.as_ptr(),
            mnt.as_ptr(),
            ext4.as_ptr(),
            libc::MS_NOATIME,
            std::ptr::null(),
        ) == 0
    };

    if !mounted {
        // First boot — format the disk
        let _ = std::process::Command::new("mkfs.ext4")
            .args([
                "-F",
                "-q",
                "-O",
                "^has_journal",
                "-L",
                "smolvm-overlay",
                OVERLAY_DEVICE,
            ])
            .status();

        let dev = cstr(OVERLAY_DEVICE);
        let mnt = cstr(OVERLAY_MOUNT);
        let ext4 = cstr("ext4");
        // SAFETY: retry mount after formatting with noatime
        if unsafe {
            libc::mount(
                dev.as_ptr(),
                mnt.as_ptr(),
                ext4.as_ptr(),
                libc::MS_NOATIME,
                std::ptr::null(),
            )
        } != 0
        {
            boot_log("ERROR", "failed to mount overlay disk after formatting");
            return;
        }
    }

    // Resize + mount storage disk in parallel while we set up overlayfs.
    // The resize + ext4 mount of /dev/vda overlaps with overlayfs setup
    // and overlay dir creation, saving that time from the critical path.
    let storage_handle = if Path::new(STORAGE_DEVICE).exists() {
        let _ = std::fs::create_dir_all(STORAGE_TEMP_MOUNT);
        Some(std::thread::spawn(|| {
            // Resize before mount — template may be smaller than device.
            // Skip if filesystem already fills the device (subsequent boots).
            // If resize fails (e.g. macOS-created template with incompatible features),
            // skip mount — mount_storage_disk() will handle mkfs fallback.
            if !ext4_already_full_size(STORAGE_DEVICE)
                && !resize_ext4_if_needed(STORAGE_DEVICE, "storage")
            {
                boot_log(
                    "WARN",
                    "storage: resize failed, deferring to mount_storage_disk",
                );
                return false;
            }

            let dev = cstr(STORAGE_DEVICE);
            let mnt = cstr(STORAGE_TEMP_MOUNT);
            let ext4 = cstr("ext4");
            // SAFETY: mount /dev/vda as ext4 at /mnt/storage with noatime
            let mounted = unsafe {
                libc::mount(
                    dev.as_ptr(),
                    mnt.as_ptr(),
                    ext4.as_ptr(),
                    libc::MS_NOATIME,
                    std::ptr::null(),
                ) == 0
            };
            if !mounted {
                let err = std::io::Error::last_os_error();
                boot_log(
                    "WARN",
                    &format!(
                        "storage: parallel mount failed ({}), deferring to mount_storage_disk",
                        err
                    ),
                );
            }
            mounted
        }))
    } else {
        None
    };

    // Create overlay directories
    let _ = std::fs::create_dir_all(format!("{}/upper", OVERLAY_MOUNT));
    let _ = std::fs::create_dir_all(format!("{}/work", OVERLAY_MOUNT));
    let _ = std::fs::create_dir_all(NEWROOT);

    // Mount overlayfs: initramfs (lower, read-only) + persistent disk (upper)
    let overlay_src = cstr("overlay");
    let newroot = cstr(NEWROOT);
    let overlay_type = cstr("overlay");
    let overlay_opts = cstr(&format!(
        "lowerdir=/,upperdir={}/upper,workdir={}/work",
        OVERLAY_MOUNT, OVERLAY_MOUNT
    ));
    // SAFETY: mount overlayfs with the specified options
    let result = unsafe {
        libc::mount(
            overlay_src.as_ptr(),
            newroot.as_ptr(),
            overlay_type.as_ptr(),
            0,
            overlay_opts.as_ptr() as *const libc::c_void,
        )
    };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        boot_log("ERROR", &format!("failed to mount overlayfs: {}", err));
        // Clean up parallel storage mount to avoid double-mount in
        // mount_storage_disk() fallback path.
        if let Some(handle) = storage_handle {
            if handle.join().unwrap_or(false) {
                let mnt = cstr(STORAGE_TEMP_MOUNT);
                // SAFETY: umount the temp storage mount
                unsafe {
                    libc::umount(mnt.as_ptr());
                }
            }
        }
        return;
    }

    // Create mount point directories in new root and move special mounts
    for dir in &["proc", "sys", "dev"] {
        let _ = std::fs::create_dir_all(format!("{}/{}", NEWROOT, dir));
        let src = cstr(&format!("/{}", dir));
        let dst = cstr(&format!("{}/{}", NEWROOT, dir));
        // SAFETY: mount --move for each special filesystem
        unsafe {
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                std::ptr::null(),
                libc::MS_MOVE,
                std::ptr::null(),
            );
        }
    }

    // Join parallel storage mount and move it into new root.
    // On subsequent boots, the ext4 mount succeeds and overlaps with the
    // overlayfs setup above. On first boot from macOS template, mount fails
    // and mount_storage_disk() handles it with full fsck/mkfs recovery.
    if let Some(handle) = storage_handle {
        match handle.join() {
            Ok(true) => {
                let _ = std::fs::create_dir_all(format!("{}/storage", NEWROOT));
                let src = cstr(STORAGE_TEMP_MOUNT);
                let dst = cstr(&format!("{}/storage", NEWROOT));
                // SAFETY: mount --move /mnt/storage to newroot/storage
                let result = unsafe {
                    libc::mount(
                        src.as_ptr(),
                        dst.as_ptr(),
                        std::ptr::null(),
                        libc::MS_MOVE,
                        std::ptr::null(),
                    )
                };
                if result != 0 {
                    let err = std::io::Error::last_os_error();
                    boot_log(
                        "WARN",
                        &format!(
                        "storage: mount-move to newroot failed ({}), will retry after pivot_root",
                        err
                    ),
                    );
                    // Unmount temp so mount_storage_disk() can try fresh
                    let mnt = cstr(STORAGE_TEMP_MOUNT);
                    unsafe {
                        libc::umount(mnt.as_ptr());
                    }
                }
            }
            Ok(false) => {
                // Thread reported failure — mount_storage_disk() will handle it
            }
            Err(_) => {
                boot_log("WARN", "storage: parallel mount thread panicked");
            }
        }
    }

    // Prepare for pivot_root
    let _ = std::fs::create_dir_all(format!("{}/oldroot", NEWROOT));

    if std::env::set_current_dir(NEWROOT).is_err() {
        boot_log("ERROR", "failed to chdir to new root");
        return;
    }

    // pivot_root — switch to overlayed root.
    // Old root stays at /oldroot (needed as overlay lower layer, ~44MB RAM).
    let dot = cstr(".");
    let oldroot = cstr("oldroot");
    // SAFETY: pivot_root syscall with valid path arguments
    let result = unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), oldroot.as_ptr()) };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        boot_log("ERROR", &format!("pivot_root failed: {}", err));
        return;
    }

    // Set working directory to new root
    let _ = std::env::set_current_dir("/");
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn setup_persistent_rootfs() {
    // No-op on non-Linux platforms
}

/// Sync filesystem caches before shutdown.
/// This prevents ext4 corruption when the VM is terminated.
#[cfg(target_os = "linux")]
fn sync_and_unmount_storage() {
    info!("syncing filesystems before shutdown");

    // Sync all filesystem caches to disk
    // SAFETY: sync() is always safe to call
    unsafe {
        libc::sync();
    }

    // Note: We don't unmount /storage here because:
    // 1. The overlay filesystem uses /storage/layers and /storage/overlays
    // 2. Unmounting /storage while overlay is active causes issues
    // 3. The sync() call ensures all pending writes are flushed to disk
    // 4. When the VM terminates, the kernel will clean up mounts
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn sync_and_unmount_storage() {
    // No-op on non-Linux platforms
}

/// Set up signal handlers to sync filesystem on SIGTERM/SIGINT.
/// This prevents ext4 corruption when the VM is forcefully stopped.
#[cfg(target_os = "linux")]
fn setup_signal_handlers() {
    // SAFETY: Signal handler that calls sync() - sync is async-signal-safe
    unsafe extern "C" fn handle_term_signal(_sig: libc::c_int) {
        // sync() is async-signal-safe, so we can call it from a signal handler
        libc::sync();
        // Exit cleanly
        libc::_exit(0);
    }

    // SAFETY: Setting up signal handlers with valid function pointers
    unsafe {
        // Handle SIGTERM (sent by VM stop)
        libc::signal(
            libc::SIGTERM,
            handle_term_signal as *const () as libc::sighandler_t,
        );
        // Handle SIGINT (Ctrl+C, if attached to console)
        libc::signal(
            libc::SIGINT,
            handle_term_signal as *const () as libc::sighandler_t,
        );
        // Note: We do NOT install a SIGCHLD handler here because it would
        // race with Child::wait() in synchronous exec paths. Instead,
        // background exec children are reaped by reap_background_children()
        // called periodically in the accept loop.
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn setup_signal_handlers() {
    // No-op on non-Linux platforms
}

/// Resize an ext4 filesystem on an unmounted device to fill the block device.
///
/// The host creates disks by copying a small pre-formatted template (~512MB)
/// then extending the sparse file to the target size (e.g. 20GB). The ext4
/// filesystem inside still thinks it's 512MB. This function expands it to
/// fill the full block device.
///
/// MUST be called BEFORE mounting — resize2fs on a mounted device fails with
/// "Resource busy" because the kernel holds the block device exclusively.
///
/// Tries resize2fs directly first. Only falls back to e2fsck if resize2fs
/// fails (e.g., due to actual corruption). ext4 journal replay handles
/// `needs_recovery` on mount in ~1-2ms, so a full e2fsck is unnecessary
/// on the happy path. Uses boot_log instead of tracing because this runs
/// before tracing_subscriber is initialized.
fn resize_ext4_if_needed(device: &str, label: &str) -> bool {
    use std::process::Command;

    // Try resize2fs directly — skip e2fsck on the happy path.
    // ext4 journal replay handles needs_recovery on mount, so resize2fs
    // usually succeeds without a prior fsck.
    match Command::new("resize2fs").arg(device).output() {
        Ok(output) if output.status.success() => {
            let msg = String::from_utf8_lossy(&output.stderr);
            if msg.contains("Nothing to do") {
                boot_log(
                    "DEBUG",
                    &format!("{} filesystem already at full device size", label),
                );
            } else {
                boot_log(
                    "INFO",
                    &format!("{} filesystem resized to fill block device", label),
                );
            }
            return true;
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            boot_log(
                "WARN",
                &format!(
                    "{} resize2fs failed (exit {}): {}, trying e2fsck",
                    label,
                    output.status.code().unwrap_or(-1),
                    stderr.trim()
                ),
            );
        }
        Err(e) => {
            boot_log("WARN", &format!("{} resize2fs not found: {}", label, e));
            return false;
        }
    }

    // Fallback: resize2fs failed, run e2fsck -y (without -f) then retry.
    // Without -f, e2fsck skips clean filesystems instantly. With needs_recovery,
    // it replays the journal (~10ms) instead of a full forced scan (~128ms).
    match Command::new("e2fsck").args(["-y", device]).output() {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            // e2fsck exit codes (bit flags, may be OR'd together):
            //   0 = clean
            //   1 = errors corrected
            //   2 = errors corrected, reboot needed (unsafe to proceed)
            //   4 = errors left uncorrected
            //   8 = operational error
            if code >= 2 {
                let stderr = String::from_utf8_lossy(&output.stderr);
                boot_log(
                    "WARN",
                    &format!(
                        "{} e2fsck could not fully repair (exit {}): {}",
                        label,
                        code,
                        stderr.trim()
                    ),
                );
                return false;
            }
            if code == 1 {
                boot_log("INFO", &format!("{} e2fsck fixed errors", label));
            }
        }
        Err(e) => {
            boot_log("WARN", &format!("{} e2fsck not found: {}", label, e));
            return false;
        }
    }

    // Retry resize2fs after e2fsck
    match Command::new("resize2fs").arg(device).output() {
        Ok(output) if output.status.success() => {
            boot_log(
                "INFO",
                &format!("{} filesystem resized after e2fsck", label),
            );
            true
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            boot_log(
                "WARN",
                &format!(
                    "{} resize2fs still failed after e2fsck (exit {}): {}",
                    label,
                    output.status.code().unwrap_or(-1),
                    stderr.trim()
                ),
            );
            false
        }
        Err(e) => {
            boot_log("WARN", &format!("{} resize2fs failed: {}", label, e));
            false
        }
    }
}

/// Check if ext4 filesystem already fills the block device.
///
/// Reads the ext4 superblock (at offset 1024) to get block_count and block_size,
/// then compares against the device size. Returns true if the filesystem already
/// spans the full device, meaning resize2fs would be a no-op. This avoids the
/// ~5ms cost of spawning resize2fs on every subsequent boot.
///
/// Returns false (conservative, triggers resize path) on any error: unformatted
/// device, non-ext4 filesystem, corrupt superblock, or I/O failure.
fn ext4_already_full_size(device: &str) -> bool {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut f = match File::open(device) {
        Ok(f) => f,
        Err(_) => return false,
    };

    // For block devices, metadata().len() returns 0. Use seek to find size.
    let dev_size = match f.seek(SeekFrom::End(0)) {
        Ok(s) if s > 0 => s,
        _ => return false,
    };

    // ext4 superblock starts at byte offset 1024. We need:
    //   offset  4: s_blocks_count_lo (4 bytes)
    //   offset 24: s_log_block_size  (4 bytes)
    //   offset 56: s_magic           (2 bytes) — must be 0xEF53
    let mut sb = [0u8; 64];
    if f.seek(SeekFrom::Start(1024)).is_err() || f.read_exact(&mut sb).is_err() {
        return false;
    }

    // Validate ext4 magic number before trusting any fields.
    let magic = u16::from_le_bytes([sb[56], sb[57]]);
    if magic != 0xEF53 {
        return false;
    }

    let log_block_size = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
    // Sanity check: log_block_size > 6 means block_size > 64 MB, not valid ext4.
    if log_block_size > 6 {
        return false;
    }
    let block_size: u64 = 1024u64 << log_block_size;

    let blocks_lo = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]) as u64;
    let fs_size = blocks_lo * block_size;

    // Allow 1 block of slack — filesystem may not use the very last block.
    // Note: only uses s_blocks_count_lo (sufficient for disks up to 16 TB at 4K blocks).
    fs_size + block_size >= dev_size
}

/// Check /proc/mounts to see if anything is mounted at the given path.
fn is_mounted_at(mount_point: &str) -> bool {
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        return mounts
            .lines()
            .any(|line| line.split_whitespace().nth(1) == Some(mount_point));
    }
    false
}

/// Create required subdirectories under the storage mount point.
fn create_storage_dirs(mount_point: &str) {
    let dirs = [
        "layers",
        "configs",
        "manifests",
        "overlays",
        "workspace",
        "containers/run",
        "containers/logs",
        "containers/exit",
        "containers/crun",
    ];
    for dir in dirs {
        let _ = std::fs::create_dir_all(std::path::Path::new(mount_point).join(dir));
    }
}

/// Mount ext4 /dev/vda at /storage using direct syscall (avoids ~3-5ms fork+exec).
fn try_mount_storage_ext4() -> bool {
    let dev = cstr("/dev/vda");
    let mnt = cstr("/storage");
    let ext4 = cstr("ext4");
    // SAFETY: mount /dev/vda as ext4 at /storage with noatime
    unsafe {
        libc::mount(
            dev.as_ptr(),
            mnt.as_ptr(),
            ext4.as_ptr(),
            libc::MS_NOATIME,
            std::ptr::null(),
        ) == 0
    }
}

/// Mount the storage disk at /storage. Returns true if successfully mounted.
///
/// Three-attempt fallback chain:
/// 1. resize + mount (works on subsequent boots with Linux-native FS)
/// 2. fsck + resize + mount (may fix minor corruption)
/// 3. mkfs + mount (first boot from macOS template, or unrecoverable)
fn mount_storage_disk() -> bool {
    use std::process::Command;

    const STORAGE_DEVICE: &str = "/dev/vda";
    const STORAGE_MOUNT: &str = "/storage";

    // Create mount point if needed
    let _ = std::fs::create_dir_all(STORAGE_MOUNT);

    // Check if device exists
    if !std::path::Path::new(STORAGE_DEVICE).exists() {
        let dev_path = cstr(STORAGE_DEVICE);
        // SAFETY: mknod with block device type, major 253 minor 0
        unsafe {
            libc::mknod(
                dev_path.as_ptr(),
                libc::S_IFBLK | 0o660,
                libc::makedev(253, 0),
            );
        }
    }

    // Check if already mounted (pre-mounted during setup_persistent_rootfs)
    if is_mounted_at(STORAGE_MOUNT) {
        debug!("storage already mounted at /storage");
        create_storage_dirs(STORAGE_MOUNT);
        return true;
    }

    // --- Attempt 1: resize (if needed) + mount (works on subsequent boots) ---
    let resized =
        ext4_already_full_size(STORAGE_DEVICE) || resize_ext4_if_needed(STORAGE_DEVICE, "storage");
    if resized && try_mount_storage_ext4() {
        info!("storage disk mounted after resize");
        create_storage_dirs(STORAGE_MOUNT);
        return true;
    }

    // --- Attempt 2: fsck + resize + mount ---
    if resized {
        warn!("mount failed after resize, attempting fsck repair");
    } else {
        warn!("resize failed, attempting fsck repair before mount");
    }

    let fsck_ok = match Command::new("fsck.ext4")
        .args(["-y", "-f", STORAGE_DEVICE])
        .status()
    {
        Ok(status) => {
            let code = status.code().unwrap_or(-1);
            if code <= 1 {
                info!(exit_code = code, "fsck completed");
                true
            } else {
                warn!(exit_code = code, "fsck could not fully repair filesystem");
                false
            }
        }
        Err(e) => {
            warn!(error = %e, "fsck.ext4 not available");
            false
        }
    };

    if fsck_ok {
        let _ = resize_ext4_if_needed(STORAGE_DEVICE, "storage");
        if try_mount_storage_ext4() {
            info!("storage disk mounted after fsck repair");
            create_storage_dirs(STORAGE_MOUNT);
            return true;
        }
        warn!("mount still failed after fsck, will format");
    }

    // --- Attempt 3: mkfs (last resort, destroys data) ---
    info!("formatting storage disk (first boot or unrecoverable)");
    match Command::new("mkfs.ext4")
        .args(["-F", "-q", "-O", "^has_journal", STORAGE_DEVICE])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            error!(exit_code = status.code().unwrap_or(-1), "mkfs.ext4 failed");
            return false;
        }
        Err(e) => {
            error!(error = %e, "mkfs.ext4 not available");
            return false;
        }
    }

    if try_mount_storage_ext4() {
        info!("storage disk mounted after format");
        create_storage_dirs(STORAGE_MOUNT);
        return true;
    }

    error!("CRITICAL: could not mount storage disk after all recovery attempts");
    false
}

/// Run the vsock server with a pre-created listener.
/// The listener is created early (before initialization) to ensure the kernel
/// has a listener ready when the host connects.
fn run_server_with_listener(
    listener: vsock::VsockListener,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first_connection = true;
    let listen_start = uptime_ms();

    info!(uptime_ms = uptime_ms(), "entering vsock accept loop");

    loop {
        // Reap any exited background children to prevent zombie accumulation
        reap_background_children();

        match listener.accept() {
            Ok(mut stream) => {
                if first_connection {
                    info!(
                        wait_for_first_connection_ms = uptime_ms() - listen_start,
                        uptime_ms = uptime_ms(),
                        "first connection accepted"
                    );
                    first_connection = false;
                }
                info!("accepted connection");

                if let Err(e) = handle_connection(&mut stream) {
                    warn!(error = %e, "connection error");
                }
            }
            Err(e) => {
                warn!(error = %e, "accept error");
            }
        }
    }
}

/// Handle a single connection.
fn handle_connection(stream: &mut impl ReadWrite) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; REQUEST_BUFFER_SIZE];

    // Per-connection streaming-upload session. `Option<WriteSession>`
    // guarantees cleanup via Drop when the connection closes, when
    // the session is replaced, or when a protocol violation (e.g.,
    // another request type arriving mid-stream) takes it.
    let mut write_session: Option<WriteSession> = None;

    loop {
        // Read length header
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("connection closed");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_be_bytes(header) as usize;

        // Validate message size to prevent DoS via memory exhaustion
        if len > MAX_MESSAGE_SIZE {
            warn!(
                len = len,
                max = MAX_MESSAGE_SIZE,
                "message too large, rejecting"
            );
            send_response(
                stream,
                &AgentResponse::error(
                    format!("message size {} exceeds maximum {}", len, MAX_MESSAGE_SIZE),
                    error_codes::MESSAGE_TOO_LARGE,
                ),
            )?;
            continue;
        }

        if len > buf.len() {
            buf.resize(len, 0);
        }

        // Read payload
        stream.read_exact(&mut buf[..len])?;

        // Parse request (Envelope wraps the request with an optional trace_id).
        // Falls back to bare AgentRequest for backward compatibility with old hosts.
        let (request, trace_id) =
            match serde_json::from_slice::<Envelope<AgentRequest>>(&buf[..len]) {
                Ok(env) => (env.body, env.trace_id),
                Err(_) => match serde_json::from_slice::<AgentRequest>(&buf[..len]) {
                    Ok(req) => (req, None),
                    Err(e) => {
                        warn!(error = %e, "invalid request");
                        send_response(
                            stream,
                            &AgentResponse::error(
                                format!("invalid request: {}", e),
                                error_codes::INVALID_REQUEST,
                            ),
                        )?;
                        continue;
                    }
                },
            };

        let _span = if let Some(ref tid) = trace_id {
            tracing::info_span!("request", trace_id = %tid, method = ?request)
        } else {
            tracing::info_span!("request", method = ?request)
        };
        let _guard = _span.enter();

        debug!(?request, "received request");

        // Check if this is an interactive run request
        if let AgentRequest::Run {
            interactive: true, ..
        }
        | AgentRequest::Run { tty: true, .. } = &request
        {
            // Handle interactive session
            handle_interactive_run(stream, request)?;
            continue;
        }

        // Check if this is an interactive VM exec request
        if let AgentRequest::VmExec {
            interactive: true, ..
        }
        | AgentRequest::VmExec { tty: true, .. } = &request
        {
            // Handle interactive VM exec session
            handle_interactive_vm_exec(stream, request)?;
            continue;
        }

        // Handle Pull with progress streaming
        if let AgentRequest::Pull {
            ref image,
            ref oci_platform,
            ref auth,
        } = request
        {
            handle_streaming_pull(stream, image, oci_platform.as_deref(), auth.as_ref())?;
            continue;
        }

        // Handle ExportLayer with chunked streaming
        if let AgentRequest::ExportLayer {
            ref image_digest,
            layer_index,
        } = request
        {
            handle_streaming_export_layer(stream, image_digest, layer_index)?;
            continue;
        }

        // Handle FileRead with chunked streaming (replaces the old
        // single-shot FileData path that capped files at ~16 MiB).
        if let AgentRequest::FileRead { ref path } = request {
            handle_streaming_file_read(stream, path)?;
            continue;
        }

        // Streaming file upload: Begin opens a session, Chunk appends
        // or finalizes. Any other request type closes the session
        // implicitly (Drop runs on the Option assignment to None).
        if let AgentRequest::FileWriteBegin {
            path,
            mode,
            total_size,
        } = request
        {
            // Drop any leftover session (Drop cleans its tmp file).
            write_session = None;
            let (new_session, response) = handle_file_write_begin(path, mode, total_size);
            write_session = new_session;
            send_response(stream, &response)?;
            continue;
        }
        if let AgentRequest::FileWriteChunk { data, done } = request {
            let (new_session, response) =
                handle_file_write_chunk(write_session.take(), &data, done);
            write_session = new_session;
            send_response(stream, &response)?;
            continue;
        }

        // Any other request mid-session is a protocol error. Drop the
        // session (Drop cleans the staging file) and proceed — the
        // operator's new request is honored rather than failed; the
        // alternative (error out) buys no safety since the drop
        // already handled cleanup.
        if write_session.is_some() {
            debug!(
                method = ?request,
                "dropping in-flight FileWrite session: non-chunk request arrived"
            );
            write_session = None;
        }

        // Handle regular request. Pass the stream's fd so long-running
        // commands (exec, run) can detect client disconnect and kill their
        // children instead of blocking the accept loop.
        let client_fd = stream.as_raw_fd();
        let response = handle_request(request, Some(client_fd));

        // Check for client disconnection BEFORE writing — if the peer is gone,
        // write_all may succeed (kernel buffers) but the next read_exact would
        // block forever waiting for bytes that will never arrive. Close the
        // connection now and let the accept loop pick up the next client.
        if process::is_peer_closed(client_fd) {
            debug!("client disconnected during request, closing connection");
            return Ok(());
        }

        if let Err(e) = send_response(stream, &response) {
            debug!(error = %e, "send_response failed (client disconnected?)");
            return Ok(());
        }

        // Check for shutdown
        if matches!(response, AgentResponse::Ok { .. }) {
            if let AgentResponse::Ok { data: Some(ref d) } = response {
                if d.get("shutdown").and_then(|v| v.as_bool()) == Some(true) {
                    info!("shutdown requested");
                    return Ok(());
                }
            }
        }
    }
}

/// Handle a single non-interactive request.
///
/// `client_fd` is the vsock file descriptor of the requesting client. It's
/// used by long-running handlers (Run, VmExec) to detect when the client
/// disconnects so the child process can be killed promptly — freeing the
/// accept loop for the next request instead of waiting for the orphan.
fn handle_request(
    request: AgentRequest,
    client_fd: Option<std::os::unix::io::RawFd>,
) -> AgentResponse {
    // Ensure storage is mounted for operations that need it.
    // Ping, NetworkTest, VmExec, and Shutdown don't access /storage.
    match &request {
        AgentRequest::Ping
        | AgentRequest::NetworkTest { .. }
        | AgentRequest::VmExec { .. }
        | AgentRequest::Shutdown => {}
        _ => {
            ensure_storage_mounted();
        }
    }

    match request {
        AgentRequest::Ping => AgentResponse::Pong {
            version: PROTOCOL_VERSION,
        },

        // Pull is handled separately in handle_streaming_pull for progress streaming
        AgentRequest::Pull { .. } => unreachable!("Pull handled before match"),

        AgentRequest::Query { image } => handle_query(&image),

        AgentRequest::ListImages => handle_list_images(),

        AgentRequest::GarbageCollect { dry_run } => handle_gc(dry_run),

        AgentRequest::PrepareOverlay { image, workload_id } => {
            handle_prepare_overlay(&image, &workload_id)
        }

        AgentRequest::CleanupOverlay { workload_id } => handle_cleanup_overlay(&workload_id),

        AgentRequest::FormatStorage => handle_format_storage(),

        AgentRequest::StorageStatus => handle_storage_status(),

        AgentRequest::NetworkTest { url } => {
            info!(url = %url, "testing network connectivity directly from agent");

            // Extract host:port for TCP test from URL
            let tcp_target = extract_host_port(&url).unwrap_or_else(|| "1.1.1.1:80".to_string());

            // Test 1: Pure syscall TCP connect test (bypass C library)
            let syscall_result = test_tcp_syscall(&tcp_target);

            // Test 2: Try wget (busybox/musl)
            let wget_result = match std::process::Command::new("wget")
                .args(["-q", "-O-", "-T", "10", &url])
                .output()
            {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    serde_json::json!({
                        "tool": "wget",
                        "success": output.status.success(),
                        "exit_code": output.status.code(),
                        "stdout_len": output.stdout.len(),
                        "stderr": stderr,
                    })
                }
                Err(e) => serde_json::json!({
                    "tool": "wget",
                    "error": format!("{}", e),
                }),
            };

            // Test 3: Try crane (Go static binary) - fetch manifest
            let crane_result = match std::process::Command::new("crane")
                .args(["manifest", "alpine:latest"])
                .env("HOME", "/root")
                .output()
            {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    serde_json::json!({
                        "tool": "crane",
                        "success": output.status.success(),
                        "exit_code": output.status.code(),
                        "stdout_len": output.stdout.len(),
                        "stderr": stderr,
                    })
                }
                Err(e) => serde_json::json!({
                    "tool": "crane",
                    "error": format!("{}", e),
                }),
            };

            AgentResponse::Ok {
                data: Some(serde_json::json!({
                    "syscall_tcp": syscall_result,
                    "wget": wget_result,
                    "crane": crane_result,
                })),
            }
        }

        AgentRequest::Shutdown => {
            info!("shutdown requested");
            // Sync filesystem before shutdown to prevent corruption
            sync_and_unmount_storage();
            AgentResponse::Ok {
                data: Some(serde_json::json!({"shutdown": true})),
            }
        }

        // VM-level background exec — spawn and return PID immediately
        AgentRequest::VmExec {
            command,
            env,
            workdir,
            background: true,
            ..
        } => handle_vm_exec_background(&command, &env, workdir.as_deref()),

        // VM-level exec (direct command execution in VM, not container)
        AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            interactive: false,
            tty: false,
            ..
        } => handle_vm_exec(&command, &env, workdir.as_deref(), timeout_ms, client_fd),

        AgentRequest::VmExec { .. } => {
            // Interactive mode should be handled by handle_interactive_vm_exec
            AgentResponse::error(
                "interactive VM exec not handled here",
                error_codes::INTERNAL_ERROR,
            )
        }

        AgentRequest::Run {
            image,
            command,
            env,
            workdir,
            mounts,
            timeout_ms,
            interactive: false,
            tty: false,
            persistent_overlay_id,
        } => handle_run(
            &image,
            &command,
            &env,
            workdir.as_deref(),
            &mounts,
            timeout_ms,
            persistent_overlay_id.as_deref(),
            client_fd,
        ),

        AgentRequest::Run { .. } => {
            // Interactive mode should be handled by handle_interactive_run
            AgentResponse::error(
                "interactive mode not handled here",
                error_codes::INTERNAL_ERROR,
            )
        }

        AgentRequest::Stdin { .. } | AgentRequest::Resize { .. } => AgentResponse::error(
            "stdin/resize only valid during interactive session",
            error_codes::INVALID_REQUEST,
        ),

        AgentRequest::ExportLayer { .. } => {
            // Streaming export is handled by handle_streaming_export_layer
            AgentResponse::error("export layer not handled here", error_codes::INTERNAL_ERROR)
        }

        AgentRequest::FileWrite { path, data, mode } => handle_file_write(&path, &data, mode),

        // Streaming uploads go through `handle_connection`'s
        // per-connection session state so they can't land here.
        AgentRequest::FileWriteBegin { .. } | AgentRequest::FileWriteChunk { .. } => {
            AgentResponse::error(
                "streaming file write must be handled at connection level",
                error_codes::INTERNAL_ERROR,
            )
        }

        // Streaming read goes through `handle_connection`'s explicit
        // dispatch so it can emit multiple responses per request.
        AgentRequest::FileRead { .. } => AgentResponse::error(
            "streaming file read must be handled at connection level",
            error_codes::INTERNAL_ERROR,
        ),
    }
}

// ============================================================================
// File I/O Handlers
// ============================================================================

/// Unique-per-call staging suffix. Using the PID + a counter avoids
/// collisions when two connections write to the same path and avoids
/// the predictable-filename class of symlink races.
fn staging_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".smolvm-upload.{}.{}", std::process::id(), n)
}

/// Ensure `path`'s parent exists, returning an AgentResponse on error
/// (so the two file-write entry points don't duplicate this block).
fn ensure_parent_dir(path: &std::path::Path) -> std::result::Result<(), AgentResponse> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Err(AgentResponse::error(
                    format!("failed to create directory {}: {}", parent.display(), e),
                    error_codes::FILE_IO_FAILED,
                ));
            }
        }
    }
    Ok(())
}

/// Apply a Unix mode, logging but not failing if the permissions
/// can't be set (matches prior single-shot behavior).
#[cfg(unix)]
fn apply_mode_best_effort(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        info!(path = %path.display(), error = %e, "failed to set file mode (non-fatal)");
    }
}
#[cfg(not(unix))]
fn apply_mode_best_effort(_path: &std::path::Path, _mode: u32) {}

/// Resolve a guest path through the active persistent container overlay.
///
/// When an image-based VM has a mounted persistent overlay, file I/O
/// paths (from `machine cp`) target the overlay's merged directory so
/// files are visible inside the container. The host ensures the overlay
/// is mounted before sending file I/O requests (via `PrepareOverlay`).
///
/// Returns the path unchanged for bare VMs (no overlay) or paths that
/// target the VM's internal directories (`/storage/...`).
fn resolve_container_path(path: &str) -> std::path::PathBuf {
    // Don't redirect VM-internal paths.
    if path.starts_with("/storage/") || path.starts_with("/proc/") || path.starts_with("/sys/") {
        return std::path::PathBuf::from(path);
    }

    // /workspace is bind-mounted from /storage/workspace into the container.
    // Rewrite so the agent writes to the bind-mount source.
    if let Some(relative) =
        path.strip_prefix("/workspace/").or_else(
            || {
                if path == "/workspace" {
                    Some("")
                } else {
                    None
                }
            },
        )
    {
        return std::path::PathBuf::from("/storage/workspace").join(relative);
    }

    let overlays_dir = std::path::Path::new("/storage/overlays");
    if let Ok(entries) = std::fs::read_dir(overlays_dir) {
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("persistent-")
            {
                continue;
            }
            let merged = entry.path().join("merged");
            if merged.join("bin").exists() || merged.join("usr").exists() {
                let relative = path.strip_prefix('/').unwrap_or(path);
                return merged.join(relative);
            }
        }
    }
    std::path::PathBuf::from(path)
}

/// Shared between single-shot [`handle_file_write`] and the streaming
/// finalize step. The atomic-rename pattern is the thing both paths
/// need to guarantee: partial contents never appear at `path` under
/// any error or kill scenario.
fn install_file_atomic(path: &str, data: &[u8], mode: Option<u32>) -> AgentResponse {
    let resolved = resolve_container_path(path);
    let target = resolved.as_path();
    if let Err(resp) = ensure_parent_dir(target) {
        return resp;
    }

    let tmp_name = format!(
        "{}{}",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        staging_suffix()
    );
    let tmp_path = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.join(&tmp_name))
        .unwrap_or_else(|| std::path::PathBuf::from(&tmp_name));

    if let Err(e) = std::fs::write(&tmp_path, data) {
        let _ = std::fs::remove_file(&tmp_path);
        return AgentResponse::error(
            format!("failed to write {}: {}", tmp_path.display(), e),
            error_codes::FILE_IO_FAILED,
        );
    }

    if let Err(e) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        return AgentResponse::error(
            format!("failed to rename onto {}: {}", path, e),
            error_codes::FILE_IO_FAILED,
        );
    }

    if let Some(m) = mode {
        apply_mode_best_effort(target, m);
    }
    info!(path = %path, size = data.len(), "file written");
    AgentResponse::Ok { data: None }
}

/// Write a file inside the VM filesystem (single-shot path).
fn handle_file_write(path: &str, data: &[u8], mode: Option<u32>) -> AgentResponse {
    install_file_atomic(path, data, mode)
}

/// State for an in-progress streaming file upload on one connection.
///
/// One session lives inside `handle_connection`'s stack, so it's
/// scoped to a single client. `Drop` cleans up the staging file if
/// the connection drops (or the session is replaced) before the
/// final chunk arrives — this is how we guarantee no partial file
/// ever appears at the target path.
struct WriteSession {
    /// User-requested target path inside the guest.
    target: std::path::PathBuf,
    /// Staging file we append to; renamed to `target` on done.
    tmp_path: std::path::PathBuf,
    /// Handle we keep open for the lifetime of the session.
    tmp_file: std::fs::File,
    /// Permissions to apply after rename.
    mode: Option<u32>,
    /// Running total — compared against `total_size` as a DoS guard.
    bytes_written: u64,
    /// Caller-declared total; the agent refuses chunks that would
    /// push `bytes_written` past it.
    total_size: u64,
}

impl WriteSession {
    /// Open a fresh staging file for `target`.
    fn open(
        target: std::path::PathBuf,
        mode: Option<u32>,
        total_size: u64,
    ) -> std::io::Result<Self> {
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp_name = format!(
            "{}{}",
            target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            staging_suffix()
        );
        let tmp_path = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.join(&tmp_name))
            .unwrap_or_else(|| std::path::PathBuf::from(&tmp_name));

        let tmp_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        Ok(Self {
            target,
            tmp_path,
            tmp_file,
            mode,
            bytes_written: 0,
            total_size,
        })
    }

    /// Append a chunk; returns AgentResponse on error.
    fn write_chunk(&mut self, data: &[u8]) -> std::result::Result<(), AgentResponse> {
        let new_total = self.bytes_written.saturating_add(data.len() as u64);
        if new_total > self.total_size {
            return Err(AgentResponse::error(
                format!(
                    "chunk overflows declared total_size ({} > {})",
                    new_total, self.total_size
                ),
                error_codes::INVALID_REQUEST,
            ));
        }
        use std::io::Write;
        if let Err(e) = self.tmp_file.write_all(data) {
            return Err(AgentResponse::error(
                format!("failed to write chunk to staging file: {}", e),
                error_codes::FILE_IO_FAILED,
            ));
        }
        self.bytes_written = new_total;
        Ok(())
    }

    /// Fsync, rename onto target, apply mode. Consumes the session.
    ///
    /// Takes `&mut self` rather than `self` so we can do a
    /// `mem::take` on `tmp_path` to disarm the Drop-based cleanup
    /// after the rename has moved the file onto its final path.
    /// (Moving individual fields out of a struct with Drop isn't
    /// allowed — `mem::take` swaps in a default `PathBuf` so the
    /// subsequent Drop is a no-op.)
    ///
    /// Linux + macOS allow renaming an open file, so we don't need
    /// to close the handle first; it drops naturally when this
    /// function returns via the by-value caller pattern.
    fn finalize(&mut self) -> AgentResponse {
        use std::io::Write;
        if let Err(e) = self.tmp_file.flush() {
            return AgentResponse::error(
                format!("failed to flush staging file: {}", e),
                error_codes::FILE_IO_FAILED,
            );
        }
        if let Err(e) = self.tmp_file.sync_all() {
            return AgentResponse::error(
                format!("failed to sync staging file: {}", e),
                error_codes::FILE_IO_FAILED,
            );
        }
        // Disarm Drop before rename; if the rename fails we'll
        // re-arm below by restoring the path.
        let tmp = std::mem::take(&mut self.tmp_path);
        if let Err(e) = std::fs::rename(&tmp, &self.target) {
            // Re-arm Drop so the staging file still gets cleaned up
            // when the session is dropped by the caller.
            self.tmp_path = tmp;
            return AgentResponse::error(
                format!("failed to rename onto {}: {}", self.target.display(), e),
                error_codes::FILE_IO_FAILED,
            );
        }
        if let Some(m) = self.mode {
            apply_mode_best_effort(&self.target, m);
        }
        info!(
            path = %self.target.display(),
            size = self.bytes_written,
            "file written (streaming)"
        );
        AgentResponse::Ok { data: None }
    }
}

impl Drop for WriteSession {
    fn drop(&mut self) {
        // If finalize consumed the session, `tmp_path` was emptied.
        if !self.tmp_path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}

/// Open a streaming upload session. Called from the connection loop.
///
/// Returns the new session plus the response to send back. On error
/// the session is not created.
fn handle_file_write_begin(
    path: String,
    mode: Option<u32>,
    total_size: u64,
) -> (Option<WriteSession>, AgentResponse) {
    if total_size > smolvm_protocol::FILE_TRANSFER_MAX_TOTAL {
        return (
            None,
            AgentResponse::error(
                format!(
                    "total_size {} exceeds maximum {}",
                    total_size,
                    smolvm_protocol::FILE_TRANSFER_MAX_TOTAL
                ),
                error_codes::INVALID_REQUEST,
            ),
        );
    }
    let resolved = resolve_container_path(&path);
    match WriteSession::open(resolved, mode, total_size) {
        Ok(session) => (Some(session), AgentResponse::Ok { data: None }),
        Err(e) => (
            None,
            AgentResponse::error(
                format!("failed to open staging file: {}", e),
                error_codes::FILE_IO_FAILED,
            ),
        ),
    }
}

/// Append a chunk to the open session (if any). Called from the
/// connection loop. On `done`, the session is consumed and the file
/// is finalized.
///
/// Returns the (possibly consumed) session plus the response.
fn handle_file_write_chunk(
    session: Option<WriteSession>,
    data: &[u8],
    done: bool,
) -> (Option<WriteSession>, AgentResponse) {
    let Some(mut s) = session else {
        return (
            None,
            AgentResponse::error(
                "no FileWriteBegin issued on this connection",
                error_codes::INVALID_REQUEST,
            ),
        );
    };
    if let Err(resp) = s.write_chunk(data) {
        // Session is dropped by returning None, cleaning the tmp file.
        return (None, resp);
    }
    if done {
        let resp = s.finalize();
        // On success `tmp_path` was cleared so Drop is a no-op;
        // on failure the session Drop will still clean the staging
        // file when `s` falls out of scope here.
        (None, resp)
    } else {
        (Some(s), AgentResponse::Ok { data: None })
    }
}

/// Stream a reader's bytes to the client as a sequence of
/// `AgentResponse::DataChunk` responses.
///
/// Shared between `FileRead` (reader = open file) and `ExportLayer`
/// (reader = `tar` child stdout). Each chunk is at most `chunk_size`
/// bytes; EOF is always signaled with a trailing `done: true` frame
/// (possibly empty) so the client's receive loop terminates uniformly.
///
/// On read error, emits a structured Error response with the
/// caller-supplied `error_code` (so operators can distinguish
/// "file-IO failed" from "export failed" in logs and status codes)
/// and returns the `io::Error` to the caller for producer-specific
/// cleanup (e.g., killing a child process).
fn send_data_chunks<R: Read>(
    stream: &mut impl Write,
    reader: &mut R,
    chunk_size: usize,
    error_context: &str,
    error_code: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; chunk_size];
    loop {
        // Fill as much of the buffer as possible in one chunk.
        // Partial reads are common when the source is a pipe
        // (e.g. tar subprocess) — we keep reading until the buffer
        // is full or EOF arrives.
        let mut pending = 0;
        while pending < buf.len() {
            match reader.read(&mut buf[pending..]) {
                Ok(0) => break,
                Ok(n) => pending += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    send_response(
                        stream,
                        &AgentResponse::error(format!("{}: {}", error_context, e), error_code),
                    )?;
                    return Err(Box::new(e));
                }
            }
        }

        if pending == 0 {
            // EOF — emit the terminator frame.
            send_response(
                stream,
                &AgentResponse::DataChunk {
                    data: vec![],
                    done: true,
                },
            )?;
            return Ok(());
        }

        send_response(
            stream,
            &AgentResponse::DataChunk {
                data: buf[..pending].to_vec(),
                done: false,
            },
        )?;
    }
}

/// Stream a file from the guest filesystem to the host as a
/// sequence of `DataChunk` responses. Called from the connection
/// loop (not the generic `handle_request` match) so it can emit
/// multiple responses per request.
fn handle_streaming_file_read(
    stream: &mut impl ReadWrite,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = resolve_container_path(path);
    let mut file = match std::fs::File::open(&resolved) {
        Ok(f) => f,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::error(
                    format!("failed to open {}: {}", path, e),
                    error_codes::FILE_IO_FAILED,
                ),
            )?;
            return Ok(());
        }
    };
    let size = file.metadata().ok().map(|m| m.len()).unwrap_or(0);
    info!(path = %path, size, "streaming file read");
    send_data_chunks(
        stream,
        &mut file,
        smolvm_protocol::LAYER_CHUNK_SIZE,
        "failed to read file",
        error_codes::FILE_IO_FAILED,
    )
}

/// Handle an interactive run session with streaming I/O.
fn handle_interactive_run(
    stream: &mut impl ReadWrite,
    request: AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_storage_mounted();
    let (image, command, env, workdir, mounts, timeout_ms, tty, persistent_overlay_id) =
        match request {
            AgentRequest::Run {
                image,
                command,
                env,
                workdir,
                mounts,
                timeout_ms,
                tty,
                persistent_overlay_id,
                ..
            } => (
                image,
                command,
                env,
                workdir,
                mounts,
                timeout_ms,
                tty,
                persistent_overlay_id,
            ),
            _ => {
                send_response(
                    stream,
                    &AgentResponse::error("expected Run request", error_codes::INVALID_REQUEST),
                )?;
                return Ok(());
            }
        };

    let is_persistent = persistent_overlay_id.is_some();
    info!(image = %image, command = ?command, tty = tty, persistent = is_persistent, "starting interactive run");

    // Prepare the overlay and get the rootfs path
    let prepared = match &persistent_overlay_id {
        Some(id) => storage::prepare_for_run_persistent(&image, id),
        None => storage::prepare_for_run(&image),
    };
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(e) => {
            send_response(stream, &AgentResponse::from_err(e, error_codes::RUN_FAILED))?;
            return Ok(());
        }
    };

    // Setup virtiofs mounts at staging area (crun will bind-mount them via OCI spec)
    // Helper: only clean up ephemeral overlays, not persistent ones
    let maybe_cleanup = |wid: &str| {
        if !is_persistent {
            let _ = storage::cleanup_overlay(wid);
        }
    };

    if let Err(e) = storage::setup_mounts(&prepared.rootfs_path, &mounts) {
        maybe_cleanup(&prepared.workload_id);
        send_response(
            stream,
            &AgentResponse::from_err(e, error_codes::MOUNT_FAILED),
        )?;
        return Ok(());
    }

    // Spawn the command with crun
    let (mut child, pty_master) = match spawn_interactive_command(
        &prepared.rootfs_path,
        &command,
        &env,
        workdir.as_deref(),
        &mounts,
        tty,
    ) {
        Ok(result) => result,
        Err(e) => {
            maybe_cleanup(&prepared.workload_id);
            send_response(
                stream,
                &AgentResponse::from_err(e, error_codes::SPAWN_FAILED),
            )?;
            return Ok(());
        }
    };

    // Send Started response
    send_response(stream, &AgentResponse::Started)?;

    // Run the appropriate interactive I/O loop
    let exit_code = match pty_master {
        #[cfg(target_os = "linux")]
        Some(pty) => match run_interactive_loop_pty(stream, &mut child, pty, timeout_ms) {
            Ok(exit_code) => exit_code,
            Err(e) => {
                maybe_cleanup(&prepared.workload_id);
                return Err(e);
            }
        },
        _ => match run_interactive_loop(stream, &mut child, timeout_ms) {
            Ok(exit_code) => exit_code,
            Err(e) => {
                maybe_cleanup(&prepared.workload_id);
                return Err(e);
            }
        },
    };

    // Send Exited response
    send_response(stream, &AgentResponse::Exited { exit_code })?;
    maybe_cleanup(&prepared.workload_id);

    Ok(())
}

/// Spawn a command for interactive execution using crun OCI runtime.
///
/// When `tty` is true, allocates a PTY pair and attaches the slave to crun's
/// stdio. The OCI spec sets `terminal: true` so that crun handles the
/// controlling terminal setup (setsid + TIOCSCTTY) inside the container.
/// In foreground `crun run` mode, this doesn't require `--console-socket`.
#[cfg(target_os = "linux")]
fn spawn_interactive_command(
    rootfs: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    tty: bool,
) -> Result<(Child, Option<pty::PtyMaster>), Box<dyn std::error::Error>> {
    use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
    use std::path::Path;

    if command.is_empty() {
        return Err("empty command".into());
    }

    let rootfs_path = Path::new(rootfs);
    let overlay_root = rootfs_path
        .parent()
        .ok_or("invalid rootfs path: no parent")?;
    let bundle_path = overlay_root.join("bundle");

    if !bundle_path.exists() {
        return Err(format!("bundle directory not found: {}", bundle_path.display()).into());
    }

    let workdir_str = workdir.unwrap_or("/");
    // terminal: true tells crun to set up a controlling terminal (setsid + TIOCSCTTY)
    let mut spec = oci::OciSpec::new(command, env, workdir_str, tty);

    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    // Shared workspace: /storage/workspace → /workspace inside container
    let workspace_src = std::path::Path::new("/storage/workspace");
    if workspace_src.exists() {
        spec.add_bind_mount(&workspace_src.to_string_lossy(), "/workspace", false);
    }

    spec.write_to(&bundle_path)
        .map_err(|e| format!("failed to write OCI spec: {}", e))?;

    let container_id = oci::generate_container_id();

    info!(
        command = ?command,
        container_id = %container_id,
        bundle = %bundle_path.display(),
        mounts = mounts.len(),
        tty = tty,
        "spawning interactive container with crun"
    );

    if tty {
        // Allocate a PTY pair — slave goes to crun's stdio, master returned to caller.
        // With terminal:true in the OCI spec, crun sets up the controlling terminal
        // for the container process.
        let (pty_master, slave_fd) = pty::open_pty(80, 24)?;
        let slave_raw = slave_fd.as_raw_fd();

        // SAFETY: slave_fd is a valid open fd from openpty.
        let child = unsafe {
            crun::CrunCommand::run(&bundle_path, &container_id)
                .stdin_from_fd(libc::dup(slave_raw))
                .stdout_from_fd(libc::dup(slave_raw))
                .stderr_from_fd(libc::dup(slave_raw))
                .spawn()?
        };

        // Close slave in parent — crun has its own copies.
        drop(slave_fd);

        Ok((child, Some(pty_master)))
    } else {
        let child = crun::CrunCommand::run(&bundle_path, &container_id)
            .stdin_piped()
            .capture_output()
            .spawn()?;
        Ok((child, None))
    }
}

/// Non-Linux stub for spawn_interactive_command.
#[cfg(not(target_os = "linux"))]
fn spawn_interactive_command(
    rootfs: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    _tty: bool,
) -> Result<(Child, Option<()>), Box<dyn std::error::Error>> {
    use std::path::Path;

    if command.is_empty() {
        return Err("empty command".into());
    }

    let rootfs_path = Path::new(rootfs);
    let overlay_root = rootfs_path
        .parent()
        .ok_or("invalid rootfs path: no parent")?;
    let bundle_path = overlay_root.join("bundle");

    if !bundle_path.exists() {
        return Err(format!("bundle directory not found: {}", bundle_path.display()).into());
    }

    let workdir_str = workdir.unwrap_or("/");
    let mut spec = oci::OciSpec::new(command, env, workdir_str, false);

    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    // Shared workspace: /storage/workspace → /workspace inside container
    let workspace_src = std::path::Path::new("/storage/workspace");
    if workspace_src.exists() {
        spec.add_bind_mount(&workspace_src.to_string_lossy(), "/workspace", false);
    }

    spec.write_to(&bundle_path)
        .map_err(|e| format!("failed to write OCI spec: {}", e))?;

    let container_id = oci::generate_container_id();

    let child = crun::CrunCommand::run(&bundle_path, &container_id)
        .stdin_piped()
        .capture_output()
        .spawn()?;

    Ok((child, None))
}

/// Run the interactive I/O loop using poll() for efficient I/O multiplexing.
/// Kill a child process and return a timeout exit code. Used when the host
/// disconnects during an interactive exec — the agent must clean up the
/// child and continue accepting new connections rather than propagating
/// the I/O error.
fn kill_child_on_disconnect(child: &mut Child) -> i32 {
    let _ = child.kill();
    let _ = child.wait();
    124
}

fn run_interactive_loop(
    stream: &mut impl ReadWrite,
    child: &mut Child,
    timeout_ms: Option<u64>,
) -> Result<i32, Box<dyn std::error::Error>> {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let deadline = timeout_ms.map(|ms| start + Duration::from_millis(ms));

    // Get handles to child's stdio
    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();
    let mut child_stdin = child.stdin.take();

    // Set non-blocking mode on stdout/stderr
    if let Some(ref stdout) = child_stdout {
        if !set_nonblocking(stdout.as_raw_fd()) {
            warn!("failed to set stdout to non-blocking mode");
        }
    }
    if let Some(ref stderr) = child_stderr {
        if !set_nonblocking(stderr.as_raw_fd()) {
            warn!("failed to set stderr to non-blocking mode");
        }
    }

    let mut stdout_buf = [0u8; IO_BUFFER_SIZE];
    let mut stderr_buf = [0u8; IO_BUFFER_SIZE];

    loop {
        // Check if child has exited
        if let Some(status) = child.try_wait()? {
            // Drain any remaining output
            drain_remaining_output(
                stream,
                &mut child_stdout,
                &mut child_stderr,
                &mut stdout_buf,
                &mut stderr_buf,
            )?;
            return Ok(status.code().unwrap_or(-1));
        }

        // Check timeout
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                warn!("interactive command timed out, killing process");
                if let Err(e) = child.kill() {
                    warn!(error = %e, "failed to kill timed out process");
                }
                // Wait to reap the process and avoid zombies
                if let Err(e) = child.wait() {
                    warn!(error = %e, "failed to wait for killed process");
                }
                return Ok(124); // Timeout exit code
            }
        }

        // Calculate poll timeout: either remaining time until deadline, or 100ms default
        let poll_timeout_ms = match deadline {
            Some(dl) => {
                let remaining = dl.saturating_duration_since(Instant::now());
                // Cap at 100ms to periodically check child exit status
                remaining
                    .as_millis()
                    .min(INTERACTIVE_POLL_TIMEOUT_MS as u128) as i32
            }
            None => INTERACTIVE_POLL_TIMEOUT_MS,
        };

        // Build poll fds array for stdout, stderr, and vsock stream
        let stdout_fd = child_stdout.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1);
        let stderr_fd = child_stderr.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1);
        let stream_fd = stream.as_raw_fd();

        let mut poll_fds = [
            libc::pollfd {
                fd: stdout_fd,
                events: if stdout_fd >= 0 { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: stderr_fd,
                events: if stderr_fd >= 0 { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: stream_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // Wait for I/O or timeout using poll()
        let poll_result = unsafe { libc::poll(poll_fds.as_mut_ptr(), 3, poll_timeout_ms) };

        if poll_result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                debug!(error = %err, "poll error");
            }
            continue;
        }

        // Read available stdout. If send_response fails (host disconnected),
        // kill the child and return gracefully.
        if poll_fds[0].revents & libc::POLLIN != 0 {
            if let Some(ref mut stdout) = child_stdout {
                loop {
                    match stdout.read(&mut stdout_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if send_response(
                                stream,
                                &AgentResponse::Stdout {
                                    data: stdout_buf[..n].to_vec(),
                                },
                            )
                            .is_err()
                            {
                                debug!("host disconnected while sending stdout");
                                return Ok(kill_child_on_disconnect(child));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            debug!(error = %e, "stdout read error");
                            break;
                        }
                    }
                }
            }
        }

        // Read available stderr. Same disconnection handling as stdout.
        if poll_fds[1].revents & libc::POLLIN != 0 {
            if let Some(ref mut stderr) = child_stderr {
                loop {
                    match stderr.read(&mut stderr_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if send_response(
                                stream,
                                &AgentResponse::Stderr {
                                    data: stderr_buf[..n].to_vec(),
                                },
                            )
                            .is_err()
                            {
                                debug!("host disconnected while sending stderr");
                                return Ok(kill_child_on_disconnect(child));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            debug!(error = %e, "stderr read error");
                            break;
                        }
                    }
                }
            }
        }

        // Read incoming request from host (stdin data, resize) — only when
        // poll confirms data is available, then use blocking read_exact which
        // is safe because the data is already in the kernel buffer.
        //
        // If the host disconnects (client killed, timeout), read_exact returns
        // an error. In that case, kill the child and return gracefully — the
        // agent must survive client disconnections.
        if poll_fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut header = [0u8; 4];
            if let Err(e) = stream.read_exact(&mut header) {
                debug!(error = %e, "host disconnected during interactive exec");
                return Ok(kill_child_on_disconnect(child));
            }
            let len = u32::from_be_bytes(header) as usize;
            if len > MAX_MESSAGE_SIZE {
                return Err(format!("message too large: {} bytes", len).into());
            }
            let mut buf = vec![0u8; len];
            if let Err(e) = stream.read_exact(&mut buf) {
                debug!(error = %e, "host disconnected during interactive exec payload");
                return Ok(kill_child_on_disconnect(child));
            }
            let request: AgentRequest = serde_json::from_slice(&buf)?;

            match request {
                AgentRequest::Stdin { data } => {
                    if data.is_empty() {
                        drop(child_stdin.take());
                    } else if let Some(ref mut stdin) = child_stdin {
                        let _ = stdin.write_all(&data);
                        let _ = stdin.flush();
                    }
                }
                AgentRequest::Resize { cols, rows } => {
                    debug!(cols, rows, "resize requested (no PTY in pipe mode)");
                }
                _ => {
                    warn!("unexpected request during interactive session");
                }
            }
        }
    }
}

/// Run the interactive I/O loop for PTY-based sessions.
///
/// Unlike `run_interactive_loop`, this polls a single PTY master fd
/// (PTY merges stdout and stderr) and supports terminal resize.
#[cfg(target_os = "linux")]
fn run_interactive_loop_pty(
    stream: &mut impl ReadWrite,
    child: &mut Child,
    pty_master: pty::PtyMaster,
    timeout_ms: Option<u64>,
) -> Result<i32, Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let deadline = timeout_ms.map(|ms| start + Duration::from_millis(ms));

    // Set the master fd to non-blocking so we can poll it.
    if !set_nonblocking(pty_master.as_raw_fd()) {
        warn!("failed to set PTY master to non-blocking mode");
    }

    let mut buf = [0u8; IO_BUFFER_SIZE];

    loop {
        // Check if child has exited.
        if let Some(status) = child.try_wait()? {
            // Drain remaining PTY output.
            loop {
                match pty_master.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        send_response(
                            stream,
                            &AgentResponse::Stdout {
                                data: buf[..n].to_vec(),
                            },
                        )?;
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.raw_os_error() == Some(libc::EIO) =>
                    {
                        // EIO is expected when the slave side is closed.
                        break;
                    }
                    Err(_) => break,
                }
            }
            return Ok(status.code().unwrap_or(-1));
        }

        // Check timeout.
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                warn!("interactive PTY command timed out, killing process");
                if let Err(e) = child.kill() {
                    warn!(error = %e, "failed to kill timed out process");
                }
                if let Err(e) = child.wait() {
                    warn!(error = %e, "failed to wait for killed process");
                }
                return Ok(124);
            }
        }

        // Poll the PTY master fd for readable data.
        let poll_timeout_ms = match deadline {
            Some(dl) => {
                let remaining = dl.saturating_duration_since(Instant::now());
                remaining
                    .as_millis()
                    .min(INTERACTIVE_POLL_TIMEOUT_MS as u128) as i32
            }
            None => INTERACTIVE_POLL_TIMEOUT_MS,
        };

        // Poll PTY master and vsock stream for readable data.
        let stream_fd = stream.as_raw_fd();
        let mut poll_fds = [
            libc::pollfd {
                fd: pty_master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let poll_result = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, poll_timeout_ms) };

        if poll_result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                debug!(error = %err, "poll error on PTY master");
            }
            continue;
        }

        // Read available data from PTY master. If send_response fails
        // (host disconnected), kill the child and return gracefully.
        let mut slave_closed = false;
        if poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            loop {
                match pty_master.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if send_response(
                            stream,
                            &AgentResponse::Stdout {
                                data: buf[..n].to_vec(),
                            },
                        )
                        .is_err()
                        {
                            debug!("host disconnected while sending PTY stdout");
                            return Ok(kill_child_on_disconnect(child));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                        // Slave side closed — child is exiting. Reap immediately
                        // instead of waiting for the next poll cycle.
                        slave_closed = true;
                        break;
                    }
                    Err(e) => {
                        debug!(error = %e, "PTY master read error");
                        slave_closed = true;
                        break;
                    }
                }
            }
        }

        // If the slave closed, the process is exiting — reap it now.
        if slave_closed {
            let status = child.wait()?;
            return Ok(status.code().unwrap_or(-1));
        }

        // Read incoming request from host — only when poll confirms data
        // is available, then use blocking read_exact (safe, data is buffered).
        // If the host disconnects, kill the child and return gracefully.
        if poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut header = [0u8; 4];
            if let Err(e) = stream.read_exact(&mut header) {
                debug!(error = %e, "host disconnected during PTY interactive exec");
                return Ok(kill_child_on_disconnect(child));
            }
            let len = u32::from_be_bytes(header) as usize;
            if len > MAX_MESSAGE_SIZE {
                return Err(format!("message too large: {} bytes", len).into());
            }
            let mut msg_buf = vec![0u8; len];
            if let Err(e) = stream.read_exact(&mut msg_buf) {
                debug!(error = %e, "host disconnected during PTY interactive exec payload");
                return Ok(kill_child_on_disconnect(child));
            }
            let request: AgentRequest = serde_json::from_slice(&msg_buf)?;

            match request {
                AgentRequest::Stdin { data } => {
                    // For PTY, empty stdin is not EOF (Ctrl+D is a byte).
                    if !data.is_empty() {
                        let _ = pty_master.write_all(&data);
                    }
                }
                AgentRequest::Resize { cols, rows } => {
                    if let Err(e) = pty_master.set_window_size(cols, rows) {
                        debug!(error = %e, cols, rows, "failed to set PTY window size");
                    }
                }
                _ => {
                    warn!("unexpected request during interactive PTY session");
                }
            }
        }
    }
}

/// Drain any remaining output from stdout/stderr after child exits.
fn drain_remaining_output(
    stream: &mut impl Write,
    child_stdout: &mut Option<std::process::ChildStdout>,
    child_stderr: &mut Option<std::process::ChildStderr>,
    stdout_buf: &mut [u8],
    stderr_buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read as _;

    if let Some(ref mut stdout) = child_stdout {
        loop {
            match stdout.read(stdout_buf) {
                Ok(0) => break,
                Ok(n) => {
                    send_response(
                        stream,
                        &AgentResponse::Stdout {
                            data: stdout_buf[..n].to_vec(),
                        },
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }
    if let Some(ref mut stderr) = child_stderr {
        loop {
            match stderr.read(stderr_buf) {
                Ok(0) => break,
                Ok(n) => {
                    send_response(
                        stream,
                        &AgentResponse::Stderr {
                            data: stderr_buf[..n].to_vec(),
                        },
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }
    Ok(())
}

/// Set a file descriptor to non-blocking mode.
///
/// Returns true if successful, false if fcntl() failed.
fn set_nonblocking(fd: i32) -> bool {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            debug!(fd, "fcntl(F_GETFL) failed");
            return false;
        }
        let result = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        if result < 0 {
            debug!(fd, "fcntl(F_SETFL, O_NONBLOCK) failed");
            return false;
        }
        true
    }
}

/// Extract host:port from a URL for TCP connection testing.
///
/// Supports URLs like:
/// - `http://example.com` -> `example.com:80`
/// - `https://example.com` -> `example.com:443`
/// - `http://example.com:8080` -> `example.com:8080`
/// - `example.com:80` -> `example.com:80`
fn extract_host_port(url: &str) -> Option<String> {
    // Remove protocol prefix if present
    let without_proto = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    // Extract host (remove path)
    let host_port = without_proto.split('/').next()?;

    // If no port, add default based on protocol
    if host_port.contains(':') {
        Some(host_port.to_string())
    } else if url.starts_with("https://") {
        Some(format!("{}:443", host_port))
    } else {
        Some(format!("{}:80", host_port))
    }
}

/// Test TCP connection using pure syscalls (bypass C library).
/// Connects to the specified target and sends HTTP GET request.
///
/// # Arguments
/// * `target` - Host:port to connect to (e.g., "1.1.1.1:80", "example.com:443")
fn test_tcp_syscall(target: &str) -> serde_json::Value {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    use std::time::Duration;

    info!(target = %target, "testing TCP with pure Rust std::net");

    // Resolve the target to socket address
    let addr: SocketAddr = match target.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                return serde_json::json!({
                    "success": false,
                    "error": "could not resolve target address",
                    "target": target,
                });
            }
        },
        Err(e) => {
            return serde_json::json!({
                "success": false,
                "error": format!("failed to resolve {}: {}", target, e),
                "target": target,
            });
        }
    };

    // Extract host for HTTP Host header
    let host = target.split(':').next().unwrap_or(target);

    let connect_result =
        match TcpStream::connect_timeout(&addr, Duration::from_secs(NETWORK_TEST_TIMEOUT_SECS)) {
            Ok(mut stream) => {
                // Try to set timeouts
                let _ =
                    stream.set_read_timeout(Some(Duration::from_secs(NETWORK_TEST_TIMEOUT_SECS)));
                let _ =
                    stream.set_write_timeout(Some(Duration::from_secs(NETWORK_TEST_TIMEOUT_SECS)));

                // Send a simple HTTP request
                let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
                match stream.write_all(request.as_bytes()) {
                    Ok(_) => {
                        // Try to read the response
                        let mut response = vec![0u8; 1024];
                        match stream.read(&mut response) {
                            Ok(n) => {
                                let response_str =
                                    String::from_utf8_lossy(&response[..n.min(200)]).to_string();
                                serde_json::json!({
                                    "success": true,
                                    "connected": true,
                                    "sent_request": true,
                                    "received_bytes": n,
                                    "response_preview": response_str,
                                })
                            }
                            Err(e) => {
                                serde_json::json!({
                                    "success": false,
                                    "connected": true,
                                    "sent_request": true,
                                    "read_error": format!("{}", e),
                                    "read_error_kind": format!("{:?}", e.kind()),
                                })
                            }
                        }
                    }
                    Err(e) => {
                        serde_json::json!({
                            "success": false,
                            "connected": true,
                            "write_error": format!("{}", e),
                        })
                    }
                }
            }
            Err(e) => {
                // Get more details about the error
                let raw_os_error = e.raw_os_error();
                serde_json::json!({
                    "success": false,
                    "connected": false,
                    "error": format!("{}", e),
                    "error_kind": format!("{:?}", e.kind()),
                    "raw_os_error": raw_os_error,
                })
            }
        };

    // Also test socket syscall and lseek behavior using safe nix APIs
    #[cfg(target_os = "linux")]
    let socket_test = {
        use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
        use nix::unistd::{lseek, Whence};
        use std::os::fd::AsRawFd;

        match socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        ) {
            Ok(fd) => {
                let raw_fd = fd.as_raw_fd();

                // Test lseek on the socket - this should return ESPIPE (29) for normal sockets
                let (lseek_result, lseek_errno) = match lseek(raw_fd, 0, Whence::SeekCur) {
                    Ok(offset) => (offset, None),
                    Err(e) => (-1, Some((e as i32, e.desc().to_string()))),
                };

                // fd is automatically closed when OwnedFd drops
                serde_json::json!({
                    "socket_created": true,
                    "fd": raw_fd,
                    "sock_type": libc::SOCK_STREAM,  // We know we created SOCK_STREAM
                    "lseek_result": lseek_result,
                    "lseek_errno": lseek_errno.map(|(e, s)| serde_json::json!({"code": e, "str": s})),
                    "expected_errno_espipe": 29,  // ESPIPE = 29 on Linux
                })
            }
            Err(e) => {
                serde_json::json!({
                    "socket_created": false,
                    "errno": e as i32,
                    "errno_str": e.desc().to_string(),
                })
            }
        }
    };

    #[cfg(not(target_os = "linux"))]
    let socket_test = serde_json::json!({
        "skipped": true,
        "reason": "socket test only available on Linux"
    });

    // Test 3: Try nc (netcat) if available
    let nc_result = match std::process::Command::new("nc")
        .args(["-w", "5", "1.1.1.1", "80"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            // Send HTTP request via stdin
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(b"GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n");
            }
            drop(child.stdin.take());

            match child.wait_with_output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    serde_json::json!({
                        "tool": "nc",
                        "success": output.status.success(),
                        "exit_code": output.status.code(),
                        "stdout_preview": stdout.chars().take(200).collect::<String>(),
                        "stderr": stderr.to_string(),
                    })
                }
                Err(e) => serde_json::json!({
                    "tool": "nc",
                    "error": format!("wait error: {}", e),
                }),
            }
        }
        Err(e) => serde_json::json!({
            "tool": "nc",
            "error": format!("spawn error: {}", e),
        }),
    };

    // Test 4: Try curl if available
    let curl_result = match std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--connect-timeout",
            "10",
            "http://1.1.1.1",
        ])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            serde_json::json!({
                "tool": "curl",
                "success": output.status.success(),
                "exit_code": output.status.code(),
                "http_code": stdout,
                "stderr": stderr,
            })
        }
        Err(e) => serde_json::json!({
            "tool": "curl",
            "error": format!("{}", e),
        }),
    };

    serde_json::json!({
        "rust_std_net": connect_result,
        "raw_socket": socket_test,
        "nc": nc_result,
        "curl": curl_result,
    })
}

/// Handle command execution request (non-interactive).
fn handle_run(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    timeout_ms: Option<u64>,
    persistent_overlay_id: Option<&str>,
    client_fd: Option<std::os::unix::io::RawFd>,
) -> AgentResponse {
    info!(image = %image, command = ?command, mounts = ?mounts, timeout_ms = ?timeout_ms, persistent = persistent_overlay_id.is_some(), "running command");

    match storage::run_command(
        image,
        command,
        env,
        workdir,
        mounts,
        timeout_ms,
        persistent_overlay_id,
        client_fd,
    ) {
        Ok(result) => AgentResponse::Completed {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        },
        Err(e) => AgentResponse::from_err(e, error_codes::RUN_FAILED),
    }
}

/// Handle image pull request with progress streaming.
fn handle_streaming_pull<S: Read + Write>(
    stream: &mut S,
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_storage_mounted();
    info!(
        image = %image,
        ?oci_platform,
        has_auth = auth.is_some(),
        "pulling image with progress"
    );

    // Create a progress callback that sends updates over the stream
    let progress_callback = |current: usize, total: usize, layer: &str| {
        let percent = if total > 0 {
            ((current as f64 / total as f64) * 100.0) as u8
        } else {
            0
        };
        let response = AgentResponse::Progress {
            message: format!("Pulling layer {}/{}", current, total),
            percent: Some(percent),
            layer: Some(layer.to_string()),
        };
        // Ignore errors from progress updates - non-critical
        let _ = send_response(stream, &response);
    };

    let response = AgentResponse::from_result(
        storage::pull_image_with_progress_and_auth(image, oci_platform, auth, progress_callback),
        error_codes::PULL_FAILED,
    );

    send_response(stream, &response)
}

/// Handle image query request.
fn handle_query(image: &str) -> AgentResponse {
    match storage::query_image(image) {
        Ok(Some(info)) => AgentResponse::ok_with_data(info),
        Ok(None) => AgentResponse::error(
            format!("image not found: {}", image),
            error_codes::NOT_FOUND,
        ),
        Err(e) => AgentResponse::from_err(e, error_codes::QUERY_FAILED),
    }
}

/// Handle list images request.
fn handle_list_images() -> AgentResponse {
    AgentResponse::from_result(storage::list_images(), error_codes::LIST_FAILED)
}

/// Handle garbage collection request.
fn handle_gc(dry_run: bool) -> AgentResponse {
    match storage::garbage_collect(dry_run) {
        Ok(freed) => AgentResponse::ok_with_data(serde_json::json!({
            "freed_bytes": freed,
            "dry_run": dry_run,
        })),
        Err(e) => AgentResponse::from_err(e, error_codes::GC_FAILED),
    }
}

/// Handle overlay preparation request.
fn handle_prepare_overlay(image: &str, workload_id: &str) -> AgentResponse {
    info!(image = %image, workload_id = %workload_id, "preparing overlay");
    AgentResponse::from_result(
        storage::prepare_overlay(image, workload_id),
        error_codes::OVERLAY_FAILED,
    )
}

/// Handle overlay cleanup request.
fn handle_cleanup_overlay(workload_id: &str) -> AgentResponse {
    info!(workload_id = %workload_id, "cleaning up overlay");
    match storage::cleanup_overlay(workload_id) {
        Ok(_) => AgentResponse::ok(None),
        Err(e) => AgentResponse::from_err(e, error_codes::CLEANUP_FAILED),
    }
}

/// Handle storage format request.
fn handle_format_storage() -> AgentResponse {
    info!("formatting storage");
    match storage::format() {
        Ok(_) => AgentResponse::ok(None),
        Err(e) => AgentResponse::from_err(e, error_codes::FORMAT_FAILED),
    }
}

/// Handle export layer request with chunked streaming.
///
/// Pipes `tar -cf -` stdout directly to the vsock stream in LAYER_CHUNK_SIZE
/// chunks. No temp tar file is created — this allows exporting layers of any
/// size without filling the storage disk.
fn handle_streaming_export_layer(
    stream: &mut impl Write,
    image_digest: &str,
    layer_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_storage_mounted();
    info!(image_digest = %image_digest, layer_index = layer_index, "exporting layer (streamed)");

    // Find the layer directory without creating a temp tar file.
    let layer_dir = match storage::find_layer_path(image_digest, layer_index) {
        Ok(path) => path,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::from_err(e, error_codes::EXPORT_FAILED),
            )?;
            return Ok(());
        }
    };

    // Pipe tar stdout directly — no temp file on disk.
    let mut child = match std::process::Command::new("tar")
        .args(["-cf", "-", "-C"])
        .arg(&layer_dir)
        .arg(".")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::error(
                    format!("failed to spawn tar: {}", e),
                    error_codes::EXPORT_FAILED,
                ),
            )?;
            return Ok(());
        }
    };

    let mut stdout = child.stdout.take().unwrap();

    // Shared streaming path — same helper used by FileRead.
    let result = send_data_chunks(
        stream,
        &mut stdout,
        LAYER_CHUNK_SIZE,
        "failed to read tar output",
        error_codes::EXPORT_FAILED,
    );
    // If the helper returned an Err, it already sent an Error
    // response; we still need to clean up the tar subprocess.
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

/// Handle storage status request.
fn handle_storage_status() -> AgentResponse {
    AgentResponse::from_result(storage::status(), error_codes::STATUS_FAILED)
}

// ============================================================================
// VM-Level Exec Handlers (Direct Execution in VM)
// ============================================================================

/// Handle VM-level exec (non-interactive).
/// Executes command directly in the VM's rootfs without any container isolation.
/// Reap any exited background children to prevent zombie accumulation.
///
/// Called periodically in the accept loop. Uses `waitpid(-1, WNOHANG)`
/// to collect all exited children without blocking. Safe to call even
/// when no background children exist.
#[cfg(target_os = "linux")]
fn reap_background_children() {
    loop {
        let ret = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if ret <= 0 {
            break;
        }
        debug!(pid = ret, "reaped background child");
    }
}

#[cfg(not(target_os = "linux"))]
fn reap_background_children() {}

/// Handle background VM exec — spawn and return PID immediately.
///
/// The process runs detached from the agent's control. stdout/stderr
/// go to /dev/null. Zombie children are reaped by reap_background_children()
/// in the accept loop.
fn handle_vm_exec_background(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
) -> AgentResponse {
    info!(command = ?command, "background VM exec");

    if command.is_empty() {
        return AgentResponse::error("command cannot be empty", error_codes::INVALID_REQUEST);
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, value) in env {
        cmd.env(key, value);
    }
    if let Some(wd) = workdir {
        cmd.current_dir(wd);
    }

    // Detach: stdout/stderr to /dev/null so the process doesn't block on pipe writes
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd.stdin(Stdio::null());

    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            // Don't wait — let the child run independently.
            // reap_background_children() in the accept loop collects the exit status.
            std::mem::forget(child);
            info!(pid = pid, "background process started");
            AgentResponse::Completed {
                exit_code: 0,
                stdout: format!("{}", pid).into_bytes(),
                stderr: Vec::new(),
            }
        }
        Err(e) => AgentResponse::error(
            format!("failed to spawn background command: {}", e),
            error_codes::SPAWN_FAILED,
        ),
    }
}

fn handle_vm_exec(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    timeout_ms: Option<u64>,
    client_fd: Option<std::os::unix::io::RawFd>,
) -> AgentResponse {
    info!(command = ?command, "executing directly in VM");

    if command.is_empty() {
        return AgentResponse::error("command cannot be empty", error_codes::INVALID_REQUEST);
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Set environment variables
    for (key, value) in env {
        cmd.env(key, value);
    }

    // Set working directory
    if let Some(wd) = workdir {
        cmd.current_dir(wd);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Put the child in its own process group so we can signal the whole
    // tree (e.g., `sh -c 'sleep 30'` — killing sh alone leaves sleep
    // orphaned and holding the stdout pipe, blocking reader threads).
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                // setsid creates a new session and process group rooted at
                // this child. killpg(pgid, SIGKILL) later hits all descendants.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    // Spawn the command
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return AgentResponse::error(
                format!("failed to spawn command: {}", e),
                error_codes::SPAWN_FAILED,
            );
        }
    };

    // Drain stdout and stderr concurrently in background threads to prevent
    // pipe deadlock. Without this, a child writing >64KB to stderr blocks on
    // write() while the agent blocks waiting for the child to exit — neither
    // side makes progress. See docs/exec-streaming-unification.md for the
    // long-term fix (streaming exec).
    const MAX_OUTPUT: usize = 16 * 1024 * 1024;

    // Use read_to_end (not read_to_string) so binary output (image bytes,
    // tarballs, any non-UTF-8 data) is preserved through the protocol.
    // The protocol serializes Vec<u8> as base64 JSON string.
    let stdout_handle = child.stdout.take().map(|out| {
        std::thread::Builder::new()
            .name("exec-stdout".into())
            .spawn(move || {
                let mut buf = Vec::new();
                let _ = out.take(MAX_OUTPUT as u64).read_to_end(&mut buf);
                buf
            })
    });

    let stderr_handle = child.stderr.take().map(|err| {
        std::thread::Builder::new()
            .name("exec-stderr".into())
            .spawn(move || {
                let mut buf = Vec::new();
                let _ = err.take(MAX_OUTPUT as u64).read_to_end(&mut buf);
                buf
            })
    });

    // Wait for exit with timeout
    let deadline =
        timeout_ms.map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));

    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(-1),
            Ok(None) => {
                // Client disconnected — kill the orphan child so the accept
                // loop isn't blocked waiting for it. Fixes BUG-12/20: SIGTERM
                // on the host-side exec client used to leave the agent stuck.
                if let Some(fd) = client_fd {
                    if process::is_peer_closed(fd) {
                        warn!(
                            pid = child.id(),
                            "client disconnected during VM exec, killing child group"
                        );
                        // Kill the entire process group — `sh -c 'sleep 30'`
                        // creates child processes that inherit the stdout pipe.
                        // Killing just `sh` leaves `sleep` holding the pipe,
                        // blocking the reader threads' EOF. killpg hits them all.
                        #[cfg(target_os = "linux")]
                        unsafe {
                            libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        break 129; // SIGHUP convention: killed by disconnect
                    }
                }
                if let Some(deadline) = deadline {
                    if std::time::Instant::now() >= deadline {
                        warn!("VM exec command timed out, killing process group");
                        #[cfg(target_os = "linux")]
                        unsafe {
                            libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        break 124; // Standard timeout exit code
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(PROCESS_POLL_INTERVAL_MS));
            }
            Err(e) => {
                return AgentResponse::error(
                    format!("failed to check process status: {}", e),
                    error_codes::WAIT_FAILED,
                );
            }
        }
    };

    // Join reader threads — they return EOF because the child and all its
    // descendants in the process group have been killed (pipes closed).
    let stdout = stdout_handle
        .and_then(|h| h.ok())
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.ok())
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    AgentResponse::Completed {
        exit_code,
        stdout,
        stderr,
    }
}

/// Handle interactive VM-level exec with streaming I/O.
fn handle_interactive_vm_exec(
    stream: &mut impl ReadWrite,
    request: AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let (command, env, workdir, timeout_ms, tty) = match request {
        AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            tty,
            ..
        } => (command, env, workdir, timeout_ms, tty),
        _ => {
            send_response(
                stream,
                &AgentResponse::error("expected VmExec request", error_codes::INVALID_REQUEST),
            )?;
            return Ok(());
        }
    };

    info!(command = ?command, tty = tty, "starting interactive VM exec");

    if command.is_empty() {
        send_response(
            stream,
            &AgentResponse::error("command cannot be empty", error_codes::INVALID_REQUEST),
        )?;
        return Ok(());
    }

    // Spawn the command directly
    let (mut child, pty_master) =
        match spawn_direct_interactive_command(&command, &env, workdir.as_deref(), tty) {
            Ok(result) => result,
            Err(e) => {
                send_response(
                    stream,
                    &AgentResponse::from_err(e, error_codes::SPAWN_FAILED),
                )?;
                return Ok(());
            }
        };

    // Send Started response
    send_response(stream, &AgentResponse::Started)?;

    // Run the appropriate interactive I/O loop
    let exit_code = match pty_master {
        #[cfg(target_os = "linux")]
        Some(pty) => run_interactive_loop_pty(stream, &mut child, pty, timeout_ms)?,
        _ => run_interactive_loop(stream, &mut child, timeout_ms)?,
    };

    // Send Exited response
    send_response(stream, &AgentResponse::Exited { exit_code })?;

    Ok(())
}

/// Spawn a command directly in the VM for interactive execution.
///
/// When `tty` is true, allocates a PTY pair and attaches the slave side
/// to the child process. Returns the child and an optional `PtyMaster`.
#[cfg(target_os = "linux")]
fn spawn_direct_interactive_command(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    tty: bool,
) -> Result<(Child, Option<pty::PtyMaster>), Box<dyn std::error::Error>> {
    use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, value) in env {
        cmd.env(key, value);
    }
    if let Some(wd) = workdir {
        cmd.current_dir(wd);
    }

    if tty {
        // Allocate a PTY pair with default 80x24 size (host will send Resize).
        let (pty_master, slave_fd) = pty::open_pty(80, 24)?;
        let slave_raw = slave_fd.as_raw_fd();

        // Set up stdio from the slave fd. We dup because Stdio::from_raw_fd
        // takes ownership and we need the fd for all three handles + pre_exec.
        // SAFETY: slave_fd is a valid open fd from openpty.
        unsafe {
            cmd.stdin(Stdio::from_raw_fd(libc::dup(slave_raw)));
            cmd.stdout(Stdio::from_raw_fd(libc::dup(slave_raw)));
            cmd.stderr(Stdio::from_raw_fd(libc::dup(slave_raw)));
        }

        // SAFETY: pre_exec closure calls only async-signal-safe functions.
        unsafe {
            cmd.pre_exec(pty::slave_pre_exec(slave_raw));
        }

        let child = cmd.spawn()?;

        // Close the slave fd in the parent — the child has its own copies.
        drop(slave_fd);

        Ok((child, Some(pty_master)))
    } else {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn()?;
        Ok((child, None))
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn spawn_direct_interactive_command(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    _tty: bool,
) -> Result<(Child, Option<()>), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, value) in env {
        cmd.env(key, value);
    }
    if let Some(wd) = workdir {
        cmd.current_dir(wd);
    }

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn()?;
    Ok((child, None))
}

/// Send a response to the client.
fn send_response(
    stream: &mut impl Write,
    response: &AgentResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_vec(response)?;
    let len = json.len() as u32;

    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&json)?;
    stream.flush()?;

    debug!(?response, "sent response");
    Ok(())
}

/// Trait for read+write streams with raw fd access.
trait ReadWrite: Read + Write + AsRawFd {}
impl<T: Read + Write + AsRawFd> ReadWrite for T {}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Streaming file-upload session tests
    //
    // These exercise the agent-side state machine in isolation — no
    // vsock, no connection, just the handlers and the WriteSession
    // struct. End-to-end protocol testing would require booting a
    // real VM, which is covered by the integration harness.
    // ========================================================================

    fn tmp_target(tmp: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        tmp.path().join(name)
    }

    /// Collect every file in a directory whose name starts with the
    /// staging prefix. Used to assert there are no orphan staging
    /// files after a test runs.
    fn staging_files_in(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().contains(".smolvm-upload."))
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Decode a length-prefixed (4-byte BE) JSON response from a
    /// byte slice. Returns the response and how many bytes it
    /// consumed. Used by the `send_data_chunks` tests to walk the
    /// stream of frames the helper wrote into a buffer.
    fn pop_one_response(buf: &[u8]) -> (AgentResponse, usize) {
        assert!(buf.len() >= 4, "buffer too short for length header");
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert!(buf.len() >= 4 + len, "incomplete frame in buffer");
        let resp: AgentResponse =
            serde_json::from_slice(&buf[4..4 + len]).expect("decode response");
        (resp, 4 + len)
    }

    #[test]
    fn send_data_chunks_emits_terminator_for_empty_source() {
        // Source is empty → exactly one DataChunk { data: [], done: true }.
        let mut sink: Vec<u8> = Vec::new();
        let mut empty: &[u8] = &[];
        send_data_chunks(
            &mut sink,
            &mut empty,
            4096,
            "test",
            error_codes::FILE_IO_FAILED,
        )
        .unwrap();

        let (resp, consumed) = pop_one_response(&sink);
        match resp {
            AgentResponse::DataChunk { data, done } => {
                assert!(data.is_empty());
                assert!(done);
            }
            other => panic!("wrong variant: {:?}", other),
        }
        assert_eq!(consumed, sink.len(), "exactly one frame expected");
    }

    #[test]
    fn send_data_chunks_concatenates_in_order_with_done_terminator() {
        // 1024 bytes through a 256-byte chunk → 4 full chunks + 1
        // empty terminator. The agent's implementation always emits a
        // separate done-frame on EOF, even when EOF lands on a chunk
        // boundary; the host's read_file relies on that.
        let payload: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
        let mut sink: Vec<u8> = Vec::new();
        let mut src = std::io::Cursor::new(payload.clone());
        send_data_chunks(
            &mut sink,
            &mut src,
            256,
            "test",
            error_codes::FILE_IO_FAILED,
        )
        .unwrap();

        let mut offset = 0usize;
        let mut reconstructed: Vec<u8> = Vec::new();
        let mut saw_done = false;
        while offset < sink.len() {
            let (resp, consumed) = pop_one_response(&sink[offset..]);
            match resp {
                AgentResponse::DataChunk { data, done } => {
                    reconstructed.extend_from_slice(&data);
                    if done {
                        saw_done = true;
                    }
                }
                other => panic!("wrong variant: {:?}", other),
            }
            offset += consumed;
        }
        assert!(saw_done, "stream missing done terminator");
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn send_data_chunks_partial_final_chunk_is_handled() {
        // 1000 bytes through a 256-byte chunk → 3 full chunks (768
        // bytes) + 1 partial chunk (232 bytes, done: false) + 1
        // empty terminator (done: true). This separates the
        // "partial chunk" case from the "EOF" case so the helper
        // doesn't have to detect short reads.
        let payload: Vec<u8> = (0..1000).map(|i| (i & 0xFF) as u8).collect();
        let mut sink: Vec<u8> = Vec::new();
        let mut src = std::io::Cursor::new(payload.clone());
        send_data_chunks(
            &mut sink,
            &mut src,
            256,
            "test",
            error_codes::FILE_IO_FAILED,
        )
        .unwrap();

        let mut offset = 0usize;
        let mut chunks: Vec<(Vec<u8>, bool)> = Vec::new();
        while offset < sink.len() {
            let (resp, consumed) = pop_one_response(&sink[offset..]);
            if let AgentResponse::DataChunk { data, done } = resp {
                chunks.push((data, done));
            }
            offset += consumed;
        }
        // Last frame must be the empty terminator.
        let last = chunks.last().expect("at least one frame");
        assert!(
            last.0.is_empty() && last.1,
            "last frame must be empty + done"
        );
        // All earlier frames carry data and are not done.
        for c in &chunks[..chunks.len() - 1] {
            assert!(!c.1, "non-final chunk had done=true");
            assert!(!c.0.is_empty(), "non-final chunk was empty");
        }
        // Concatenated data matches the source.
        let concatenated: Vec<u8> = chunks.iter().flat_map(|(d, _)| d.iter().copied()).collect();
        assert_eq!(concatenated, payload);
    }

    #[test]
    fn streaming_write_rejects_when_total_size_exceeds_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp_target(&tmp, "big");
        let (session, resp) = handle_file_write_begin(
            target.to_string_lossy().into(),
            None,
            smolvm_protocol::FILE_TRANSFER_MAX_TOTAL + 1,
        );
        assert!(session.is_none(), "session must not be created");
        assert!(
            matches!(resp, AgentResponse::Error { .. }),
            "expected error, got {:?}",
            resp
        );
    }

    #[test]
    fn streaming_write_happy_path_writes_file_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp_target(&tmp, "hello.bin");

        // Build a recognizable payload that also crosses a chunk boundary
        // via the test-only helper. Use a known-odd size so no power-of-
        // two alignment could accidentally hide a bug.
        let payload = {
            let mut v = Vec::with_capacity(37);
            for i in 0..37u8 {
                v.push(i);
            }
            v
        };

        let (session, resp) = handle_file_write_begin(
            target.to_string_lossy().into(),
            Some(0o600),
            payload.len() as u64,
        );
        assert!(matches!(resp, AgentResponse::Ok { .. }));

        let (session, resp) = handle_file_write_chunk(session, &payload, true);
        assert!(
            matches!(resp, AgentResponse::Ok { .. }),
            "finalize failed: {:?}",
            resp
        );
        assert!(session.is_none());

        // File exists with correct contents.
        let got = std::fs::read(&target).unwrap();
        assert_eq!(got, payload);

        // No staging file left behind.
        assert!(
            staging_files_in(tmp.path()).is_empty(),
            "staging file leaked"
        );

        // Mode applied (unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn streaming_write_multi_chunk_concatenates_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp_target(&tmp, "multi.bin");
        let total = 1024usize;

        let (mut session, resp) =
            handle_file_write_begin(target.to_string_lossy().into(), None, total as u64);
        assert!(matches!(resp, AgentResponse::Ok { .. }));

        // Three chunks: 400 + 400 + 224 bytes, each a distinct fill byte.
        let chunks: [(&[u8], bool); 3] = [
            (&[b'A'; 400], false),
            (&[b'B'; 400], false),
            (&[b'C'; 224], true),
        ];
        for (data, done) in chunks {
            let (new_session, resp) = handle_file_write_chunk(session, data, done);
            assert!(
                matches!(resp, AgentResponse::Ok { .. }),
                "chunk failed: {:?}",
                resp
            );
            session = new_session;
        }
        assert!(session.is_none(), "session must be consumed on done");

        let got = std::fs::read(&target).unwrap();
        let mut expected = Vec::with_capacity(total);
        expected.extend(std::iter::repeat(b'A').take(400));
        expected.extend(std::iter::repeat(b'B').take(400));
        expected.extend(std::iter::repeat(b'C').take(224));
        assert_eq!(got, expected);
        assert!(staging_files_in(tmp.path()).is_empty());
    }

    #[test]
    fn streaming_write_overflow_aborts_with_no_partial_file() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp_target(&tmp, "overflow.bin");

        let (session, _resp) = handle_file_write_begin(target.to_string_lossy().into(), None, 10);
        assert!(session.is_some());

        // First chunk fits.
        let (session, resp) = handle_file_write_chunk(session, &[0u8; 5], false);
        assert!(matches!(resp, AgentResponse::Ok { .. }));
        assert!(session.is_some());

        // Second chunk would push bytes_written to 15, over total_size=10.
        let (session, resp) = handle_file_write_chunk(session, &[0u8; 10], false);
        assert!(matches!(resp, AgentResponse::Error { .. }));
        // Session must be dropped (cleans staging).
        assert!(session.is_none());

        // Target never appeared (promise: no partial file).
        assert!(!target.exists());
        // Staging file cleaned up via Drop.
        assert!(staging_files_in(tmp.path()).is_empty());
    }

    #[test]
    fn streaming_write_drop_cleans_staging_file() {
        // Simulates connection dropping mid-stream. We open a session,
        // write one chunk, then drop the session without calling done.
        // The Drop impl must unlink the staging file so no partial
        // content lingers.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp_target(&tmp, "dropped.bin");

        let (session, _) = handle_file_write_begin(target.to_string_lossy().into(), None, 100);
        let (session, _) = handle_file_write_chunk(session, &[0u8; 50], false);
        assert!(session.is_some());
        // Staging file exists mid-stream.
        assert_eq!(staging_files_in(tmp.path()).len(), 1);

        drop(session);
        // After drop, the staging file is gone and target never
        // appeared.
        assert!(staging_files_in(tmp.path()).is_empty());
        assert!(!target.exists());
    }

    #[test]
    fn streaming_write_chunk_without_begin_errors() {
        let (session, resp) = handle_file_write_chunk(None, &[0u8; 10], true);
        assert!(session.is_none());
        assert!(matches!(resp, AgentResponse::Error { .. }));
    }

    #[test]
    fn streaming_write_zero_length_file() {
        // Host sends empty `FileWriteChunk { data: [], done: true }`
        // to finalize an empty file. Agent must create an empty file
        // at the target, not leave it missing.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp_target(&tmp, "empty.bin");

        let (session, _) = handle_file_write_begin(target.to_string_lossy().into(), None, 0);
        let (session, resp) = handle_file_write_chunk(session, &[], true);
        assert!(matches!(resp, AgentResponse::Ok { .. }));
        assert!(session.is_none());

        assert!(target.exists());
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
        assert!(staging_files_in(tmp.path()).is_empty());
    }

    #[test]
    fn single_shot_write_uses_atomic_rename_too() {
        // Regression guard on the shared finalizer: handle_file_write
        // and handle_file_write_chunk(done=true) both go through
        // install_file_atomic / WriteSession::finalize, so a failure
        // mid-rename must leave no partial file at the target.
        // Here we just verify the success path — install_file_atomic
        // produces a correct file — and that no staging artifact
        // leaks.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp_target(&tmp, "single.bin");
        let payload = b"small file contents".to_vec();

        let resp = handle_file_write(&target.to_string_lossy(), &payload, Some(0o644));
        assert!(
            matches!(resp, AgentResponse::Ok { .. }),
            "write failed: {:?}",
            resp
        );
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        assert!(staging_files_in(tmp.path()).is_empty());
    }

    #[test]
    fn test_boot_log_valid_json() {
        let line = format_boot_log("ERROR", "something failed");
        let parsed: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("Invalid JSON: {}\nLine: {}", e, line));
        assert_eq!(parsed["level"], "ERROR");
        assert_eq!(parsed["message"], "something failed");
        assert_eq!(parsed["target"], "smolvm_agent::boot");
    }

    #[test]
    fn test_boot_log_escapes_quotes() {
        let line = format_boot_log("ERROR", r#"failed: "device" not found"#);
        let parsed: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("Invalid JSON: {}\nLine: {}", e, line));
        assert!(parsed["message"].as_str().unwrap().contains("\"device\""));
    }
}
