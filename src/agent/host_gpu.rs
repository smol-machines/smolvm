//! Check that the host's graphics device nodes can be opened before a VM
//! process is started with host GPU acceleration.
//!
//! With `--gpu` on Linux, libkrun's "gpu worker" thread initialises
//! virglrenderer inside the VM process. virglrenderer opens the DRM render
//! nodes under `/dev/dri` itself, and the EGL and Vulkan drivers it loads
//! (in the VM process and in `virgl_render_server`) open render and card
//! nodes of their own. When the host graphics driver is not responding, such
//! an `open()` blocks inside the kernel and cannot be interrupted, not even
//! by SIGKILL: the VM process then never gets a working display and can
//! never be stopped.
//!
//! [`probe_nodes`] performs the same opens first, in a separate process that
//! nothing waits on. If that process does not report back in time, the VM
//! process is not allowed to touch the device: the machine starts with a
//! software-rendered display when it asked for one, and is refused otherwise.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::data::resources::VmResources;
use crate::error::{Error, Result};

/// How long the probe may take in total before the device counts as not
/// responding. Opening a healthy DRM node takes milliseconds, or about a
/// second when the GPU has to leave a low-power state first.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Directory holding the DRM device nodes.
const DRM_DIR: &str = "/dev/dri";

/// A device node the GPU path opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeNode {
    /// Path of the node.
    pub path: PathBuf,
    /// Whether a failed `open()` on this node counts. Render nodes are what
    /// virglrenderer itself opens. Card nodes are opened only by drivers,
    /// which tolerate a refusal (they are often not accessible to the user),
    /// so on a card node only an open that never returns counts.
    pub open_must_succeed: bool,
}

/// Why the host GPU cannot be used.
#[derive(Debug)]
pub enum NodeFailure {
    /// `open()` did not return within the wait.
    NotResponding {
        /// How long the probe waited.
        waited: Duration,
    },
    /// `open()` returned this error.
    Open(std::io::Error),
}

/// The host GPU cannot be used, and the node that showed it.
#[derive(Debug)]
pub struct GpuUnavailable {
    /// The device node.
    pub node: PathBuf,
    /// What happened when it was opened.
    pub failure: NodeFailure,
}

impl std::fmt::Display for GpuUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.failure {
            NodeFailure::NotResponding { waited } => write!(
                f,
                "opening {} did not return within {} s: the host graphics driver is not \
                 responding (rebooting the host usually clears this)",
                self.node.display(),
                waited.as_secs_f32().ceil() as u64
            ),
            NodeFailure::Open(error) => {
                write!(f, "cannot open {}: {error}", self.node.display())
            }
        }
    }
}

/// Result of a probe.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// Every node answered, and a render node could be opened if one exists.
    Usable,
    /// The host GPU cannot be used.
    Unavailable(GpuUnavailable),
    /// The probe process could not be run or ended without a result. This
    /// says nothing about the device.
    Inconclusive(String),
}

/// The nodes the GPU path opens on this host: every character device named
/// `renderD*` or `card*` in `/dev/dri`. Listing the directory does not open
/// any of them.
pub fn host_gpu_nodes() -> Vec<ProbeNode> {
    nodes_in(Path::new(DRM_DIR))
}

fn nodes_in(dir: &Path) -> Vec<ProbeNode> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut nodes: Vec<ProbeNode> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let render = name.starts_with("renderD");
            if !render && !name.starts_with("card") {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if !entry.file_type().ok()?.is_char_device() {
                    return None;
                }
            }
            Some(ProbeNode {
                path: entry.path(),
                open_must_succeed: render,
            })
        })
        .collect();
    // Render nodes first: they are the ones the renderer itself opens.
    nodes.sort_by(|a, b| {
        b.open_must_succeed
            .cmp(&a.open_must_succeed)
            .then_with(|| a.path.cmp(&b.path))
    });
    nodes
}

/// Open each node the way virglrenderer does, in a process nothing waits on,
/// and report whether the host GPU can be used.
///
/// The host GPU is unavailable when any node's `open()` does not return
/// within `timeout` in total, or when render nodes exist and none of them
/// can be opened. A host with no nodes at all is reported usable: the
/// renderer then runs on the host's software drivers and opens no device.
pub fn probe_nodes(nodes: &[ProbeNode], timeout: Duration) -> ProbeOutcome {
    #[cfg(target_os = "linux")]
    {
        linux::probe(nodes, timeout, linux::RENDERER_OPEN_FLAGS)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (nodes, timeout);
        ProbeOutcome::Usable
    }
}

/// Decide, before the VM process exists, whether this boot may use the host
/// GPU, and change `resources` when it may not.
///
/// Every start path calls this: the engine's launch for the CLI, the API
/// server and embedders, and the packed-binary launch.
///
/// - No `--gpu`: nothing to check.
/// - `--gpu` and the host device answers: unchanged.
/// - `--gpu`, the host device is unusable, and a display was requested on a
///   fresh boot: the machine starts with the software display (`gpu` is
///   cleared for this boot only) and one warning names the node.
/// - `--gpu`, the host device is unusable, and there is no display, or the
///   boot restores a snapshot taken with the accelerated device: an error.
///   GPU rendering has nothing to fall back to, and a snapshot's device
///   state cannot be restored onto a different device.
pub fn resolve_for_boot(
    machine: &str,
    resources: &mut VmResources,
    display_requested: bool,
    restores_snapshot: bool,
) -> Result<()> {
    if !resources.gpu || !cfg!(target_os = "linux") {
        return Ok(());
    }
    let outcome = probe_nodes(&host_gpu_nodes(), PROBE_TIMEOUT);
    apply_probe_outcome(
        machine,
        resources,
        display_requested,
        restores_snapshot,
        outcome,
    )
}

fn apply_probe_outcome(
    machine: &str,
    resources: &mut VmResources,
    display_requested: bool,
    restores_snapshot: bool,
    outcome: ProbeOutcome,
) -> Result<()> {
    let unavailable = match outcome {
        ProbeOutcome::Usable => return Ok(()),
        ProbeOutcome::Inconclusive(reason) => {
            tracing::debug!(%reason, "host GPU probe was inconclusive; starting as requested");
            return Ok(());
        }
        ProbeOutcome::Unavailable(unavailable) => unavailable,
    };
    if restores_snapshot {
        return Err(Error::agent(
            "start machine",
            format!(
                "host GPU acceleration is unavailable: {unavailable}. Machine '{machine}' \
                 resumes a snapshot taken with GPU acceleration, which cannot continue \
                 without it, so it was not started."
            ),
        ));
    }
    if !display_requested {
        return Err(Error::agent(
            "start machine",
            format!(
                "host GPU acceleration is unavailable: {unavailable}. Machine '{machine}' \
                 was created with --gpu and has no display to fall back to \
                 (SMOLVM_DISPLAY is not set), so it was not started."
            ),
        ));
    }
    tracing::warn!(
        "host GPU acceleration is unavailable: {unavailable}. Machine '{machine}' starts \
         with a software-rendered display instead; the guest has no GPU rendering."
    );
    resources.gpu = false;
    Ok(())
}

/// Whether a single device node answers an `open()` in time. Used before a
/// helper that would open the node is started.
pub fn node_responds(path: &Path) -> bool {
    let node = ProbeNode {
        path: path.to_path_buf(),
        open_must_succeed: false,
    };
    match probe_nodes(&[node], PROBE_TIMEOUT) {
        ProbeOutcome::Unavailable(unavailable) => {
            tracing::warn!("{unavailable}");
            false
        }
        ProbeOutcome::Usable | ProbeOutcome::Inconclusive(_) => true,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{GpuUnavailable, NodeFailure, ProbeNode, ProbeOutcome};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    /// The flags virglrenderer opens a render node with.
    pub(super) const RENDERER_OPEN_FLAGS: libc::c_int =
        libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK;

    /// `DRM_IOCTL_VERSION`: `_IOWR('d', 0x00, struct drm_version)`. The
    /// renderer issues it right after the open, so the probe does too.
    const DRM_IOCTL_VERSION: libc::c_ulong = 0xC040_6400;

    /// Record index the probe process writes once every node is done.
    const DONE: u32 = u32::MAX;
    /// Record index the probe process writes before the first open.
    const STARTED: u32 = u32::MAX - 1;

    /// Mirrors the kernel's `struct drm_version` on 64-bit targets.
    #[repr(C)]
    struct DrmVersion {
        version_major: libc::c_int,
        version_minor: libc::c_int,
        version_patchlevel: libc::c_int,
        name_len: libc::size_t,
        name: *mut libc::c_char,
        date_len: libc::size_t,
        date: *mut libc::c_char,
        desc_len: libc::size_t,
        desc: *mut libc::c_char,
    }

    pub(super) fn probe(
        nodes: &[ProbeNode],
        timeout: Duration,
        open_flags: libc::c_int,
    ) -> ProbeOutcome {
        if nodes.is_empty() {
            return ProbeOutcome::Usable;
        }
        // Everything the probe process needs is allocated before the fork:
        // after it, that process may only make async-signal-safe calls.
        let paths: Vec<CString> = match nodes
            .iter()
            .map(|node| CString::new(node.path.as_os_str().as_bytes()))
            .collect()
        {
            Ok(paths) => paths,
            Err(_) => return ProbeOutcome::Inconclusive("device path contains NUL".into()),
        };
        let dev_null = c"/dev/null";
        // The probe process ends itself this long after it started if its
        // open was interruptible. An open the kernel will not interrupt
        // keeps it until the host reboots, which is why nothing waits on it.
        let alarm_secs = timeout.as_secs().saturating_add(2) as libc::c_uint;

        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a valid two-element array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return ProbeOutcome::Inconclusive(format!(
                "pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // Fork twice so the probe process is not a child of this one: the
        // intermediate process exits at once and is reaped here, and the
        // probe process is then owned by init. This process never has to
        // wait on it, and a probe the kernel never releases is not left as a
        // child of a long-running server.
        // SAFETY: the child only makes async-signal-safe calls before _exit.
        let intermediate = unsafe { libc::fork() };
        if intermediate < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors were returned by pipe2 above.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return ProbeOutcome::Inconclusive(format!("fork: {error}"));
        }
        if intermediate == 0 {
            // SAFETY: async-signal-safe calls only; never returns.
            unsafe {
                if libc::fork() == 0 {
                    run_probe(&paths, dev_null, write_fd, open_flags, alarm_secs);
                }
                libc::_exit(0);
            }
        }
        // SAFETY: `write_fd` is ours; `intermediate` is our child. ECHILD
        // (a SIGCHLD handler reaped it first) is fine.
        unsafe {
            libc::close(write_fd);
            let mut status = 0;
            while libc::waitpid(intermediate, &mut status, 0) < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {}
        }

        let outcome = read_outcome(nodes, read_fd, timeout);
        // SAFETY: `read_fd` is ours and no longer used.
        unsafe { libc::close(read_fd) };
        outcome
    }

    /// Body of the probe process. Only async-signal-safe calls.
    ///
    /// # Safety
    /// Must run in a freshly forked process; never returns.
    unsafe fn run_probe(
        paths: &[CString],
        dev_null: &std::ffi::CStr,
        write_fd: libc::c_int,
        open_flags: libc::c_int,
        alarm_secs: libc::c_uint,
    ) -> ! {
        // Leave the caller's session and terminal, and hold none of its
        // files: this process may never exit, and must not keep a caller's
        // output pipe, socket or lock open while it lingers.
        libc::setsid();
        let null = libc::open(dev_null.as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
            libc::dup2(null, 1);
            libc::dup2(null, 2);
        }
        // Keep only the pipe, moved to descriptor 3.
        let pipe_fd = if write_fd == 3 {
            3
        } else {
            let moved = libc::dup2(write_fd, 3);
            if moved < 0 {
                libc::_exit(1);
            }
            moved
        };
        if libc::syscall(
            libc::SYS_close_range,
            4 as libc::c_uint,
            libc::c_uint::MAX,
            0,
        ) != 0
        {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let max = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                limit.rlim_cur.min(65_536) as libc::c_int
            } else {
                1024
            };
            let mut fd = 4;
            while fd < max {
                libc::close(fd);
                fd += 1;
            }
        }

        // End this process by SIGALRM if an open can be interrupted but
        // never completes.
        libc::signal(libc::SIGALRM, libc::SIG_DFL);
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::sigprocmask(libc::SIG_UNBLOCK, &all, std::ptr::null_mut());
        libc::alarm(alarm_secs);

        write_record(pipe_fd, STARTED, 0);
        for (index, path) in paths.iter().enumerate() {
            let fd = libc::open(path.as_ptr(), open_flags);
            let errno = if fd < 0 {
                *libc::__errno_location()
            } else {
                let mut version: DrmVersion = std::mem::zeroed();
                // The result is not needed: only whether the call returns.
                libc::ioctl(fd, DRM_IOCTL_VERSION, &mut version);
                libc::close(fd);
                0
            };
            write_record(pipe_fd, index as u32, errno);
        }
        write_record(pipe_fd, DONE, 0);
        libc::_exit(0)
    }

    unsafe fn write_record(fd: libc::c_int, index: u32, errno: i32) {
        let mut record = [0u8; 8];
        record[..4].copy_from_slice(&index.to_ne_bytes());
        record[4..].copy_from_slice(&errno.to_ne_bytes());
        // An 8-byte write to a pipe is atomic.
        libc::write(fd, record.as_ptr().cast(), record.len());
    }

    fn read_outcome(nodes: &[ProbeNode], read_fd: libc::c_int, timeout: Duration) -> ProbeOutcome {
        let deadline = Instant::now() + timeout;
        // Per node: `None` until the probe process reports it.
        let mut results: Vec<Option<i32>> = vec![None; nodes.len()];
        let mut started = false;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let mut pollfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let wait_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            // SAFETY: `pollfd` is a valid single entry.
            let ready = unsafe { libc::poll(&mut pollfd, 1, wait_ms) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return ProbeOutcome::Inconclusive(format!("poll: {error}"));
            }
            if ready == 0 {
                break;
            }
            let mut record = [0u8; 8];
            // SAFETY: `record` is a valid 8-byte buffer.
            let read = unsafe { libc::read(read_fd, record.as_mut_ptr().cast(), record.len()) };
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return ProbeOutcome::Inconclusive(format!("read: {error}"));
            }
            if read != record.len() as isize {
                // End of file before the final record: the probe process
                // ended early, which is not evidence about the device.
                return ProbeOutcome::Inconclusive("probe process ended without a result".into());
            }
            let index = u32::from_ne_bytes([record[0], record[1], record[2], record[3]]);
            let errno = i32::from_ne_bytes([record[4], record[5], record[6], record[7]]);
            match index {
                STARTED => started = true,
                DONE => return judge(nodes, &results),
                index => {
                    if let Some(slot) = results.get_mut(index as usize) {
                        *slot = Some(errno);
                    }
                }
            }
        }
        if !started {
            return ProbeOutcome::Inconclusive("probe process did not start in time".into());
        }
        // Timed out: the node being opened is the first without a result.
        let stuck = results.iter().position(Option::is_none).unwrap_or(0);
        ProbeOutcome::Unavailable(GpuUnavailable {
            node: nodes[stuck].path.clone(),
            failure: NodeFailure::NotResponding { waited: timeout },
        })
    }

    /// Every open returned. Unusable only when render nodes exist and none
    /// of them opened.
    fn judge(nodes: &[ProbeNode], results: &[Option<i32>]) -> ProbeOutcome {
        let mut first_failure = None;
        for (node, result) in nodes.iter().zip(results) {
            if !node.open_must_succeed {
                continue;
            }
            match result {
                Some(0) => return ProbeOutcome::Usable,
                Some(errno) if first_failure.is_none() => {
                    first_failure = Some((node.path.clone(), *errno));
                }
                _ => {}
            }
        }
        match first_failure {
            Some((node, errno)) => ProbeOutcome::Unavailable(GpuUnavailable {
                node,
                failure: NodeFailure::Open(std::io::Error::from_raw_os_error(errno)),
            }),
            None => ProbeOutcome::Usable,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::{Path, PathBuf};

        fn node(path: &Path, open_must_succeed: bool) -> ProbeNode {
            ProbeNode {
                path: path.to_path_buf(),
                open_must_succeed,
            }
        }

        /// A FIFO nobody reads: opening it write-only blocks, which stands in
        /// for a device node whose open never returns.
        fn blocking_fifo(dir: &Path, name: &str) -> PathBuf {
            let path = dir.join(name);
            let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: `c_path` is a valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
            path
        }

        #[test]
        fn open_that_never_returns_is_reported_with_its_node() {
            let dir = tempfile::tempdir().unwrap();
            let ok = dir.path().join("renderD128");
            std::fs::write(&ok, b"").unwrap();
            let stuck = blocking_fifo(dir.path(), "card1");
            let started = Instant::now();
            let outcome = probe(
                &[node(&ok, true), node(&stuck, false)],
                Duration::from_millis(300),
                libc::O_WRONLY | libc::O_CLOEXEC,
            );
            // Bounded: the caller is not held by the blocked open.
            assert!(started.elapsed() < Duration::from_secs(3));
            match outcome {
                ProbeOutcome::Unavailable(unavailable) => {
                    assert_eq!(unavailable.node, stuck);
                    assert!(matches!(
                        unavailable.failure,
                        NodeFailure::NotResponding { .. }
                    ));
                    let text = unavailable.to_string();
                    assert!(text.contains(&stuck.display().to_string()), "{text}");
                    assert!(text.contains("not responding"), "{text}");
                }
                other => panic!("expected unavailable, got {other:?}"),
            }
        }

        #[test]
        fn render_node_that_cannot_be_opened_reports_the_errno() {
            let dir = tempfile::tempdir().unwrap();
            let missing = dir.path().join("renderD128");
            let outcome = probe(
                &[node(&missing, true)],
                Duration::from_secs(5),
                RENDERER_OPEN_FLAGS,
            );
            match outcome {
                ProbeOutcome::Unavailable(unavailable) => {
                    assert_eq!(unavailable.node, missing);
                    match &unavailable.failure {
                        NodeFailure::Open(error) => {
                            assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
                        }
                        other => panic!("expected an open error, got {other:?}"),
                    }
                    assert!(unavailable.to_string().starts_with("cannot open "));
                }
                other => panic!("expected unavailable, got {other:?}"),
            }
        }

        #[test]
        fn nodes_that_open_are_usable() {
            let dir = tempfile::tempdir().unwrap();
            let render = dir.path().join("renderD128");
            let card = dir.path().join("card0");
            std::fs::write(&render, b"").unwrap();
            std::fs::write(&card, b"").unwrap();
            let outcome = probe(
                &[node(&render, true), node(&card, false)],
                Duration::from_secs(5),
                RENDERER_OPEN_FLAGS,
            );
            assert!(matches!(outcome, ProbeOutcome::Usable), "{outcome:?}");
        }

        #[test]
        fn one_working_render_node_is_enough() {
            let dir = tempfile::tempdir().unwrap();
            let broken = dir.path().join("renderD128");
            let working = dir.path().join("renderD129");
            std::fs::write(&working, b"").unwrap();
            let outcome = probe(
                &[node(&broken, true), node(&working, true)],
                Duration::from_secs(5),
                RENDERER_OPEN_FLAGS,
            );
            assert!(matches!(outcome, ProbeOutcome::Usable), "{outcome:?}");
        }

        #[test]
        fn card_node_that_refuses_the_open_does_not_count() {
            let dir = tempfile::tempdir().unwrap();
            let render = dir.path().join("renderD128");
            std::fs::write(&render, b"").unwrap();
            let card = dir.path().join("card0");
            let outcome = probe(
                &[node(&render, true), node(&card, false)],
                Duration::from_secs(5),
                RENDERER_OPEN_FLAGS,
            );
            assert!(matches!(outcome, ProbeOutcome::Usable), "{outcome:?}");
        }

        #[test]
        fn no_nodes_is_usable() {
            assert!(matches!(
                probe(&[], Duration::from_secs(1), RENDERER_OPEN_FLAGS),
                ProbeOutcome::Usable
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpu_resources() -> VmResources {
        VmResources {
            gpu: true,
            ..Default::default()
        }
    }

    fn not_responding() -> ProbeOutcome {
        ProbeOutcome::Unavailable(GpuUnavailable {
            node: PathBuf::from("/dev/dri/renderD128"),
            failure: NodeFailure::NotResponding {
                waited: Duration::from_secs(5),
            },
        })
    }

    #[test]
    fn usable_host_gpu_leaves_the_request_unchanged() {
        let mut resources = gpu_resources();
        apply_probe_outcome("m", &mut resources, false, false, ProbeOutcome::Usable).unwrap();
        assert!(resources.gpu);
    }

    #[test]
    fn inconclusive_probe_leaves_the_request_unchanged() {
        let mut resources = gpu_resources();
        let outcome = ProbeOutcome::Inconclusive("fork: out of processes".into());
        apply_probe_outcome("m", &mut resources, true, false, outcome).unwrap();
        assert!(resources.gpu);
    }

    #[test]
    fn unusable_host_gpu_with_a_display_starts_without_acceleration() {
        let mut resources = gpu_resources();
        apply_probe_outcome("m", &mut resources, true, false, not_responding()).unwrap();
        assert!(!resources.gpu);
    }

    #[test]
    fn unusable_host_gpu_without_a_display_is_refused_and_names_the_node() {
        let mut resources = gpu_resources();
        let error = apply_probe_outcome("m", &mut resources, false, false, not_responding())
            .unwrap_err()
            .to_string();
        assert!(resources.gpu);
        assert!(error.contains("/dev/dri/renderD128"), "{error}");
        assert!(
            error.contains("the host graphics driver is not responding"),
            "{error}"
        );
        assert!(error.contains("no display to fall back to"), "{error}");
    }

    #[test]
    fn unusable_host_gpu_refuses_a_snapshot_restore_even_with_a_display() {
        let mut resources = gpu_resources();
        let error = apply_probe_outcome("m", &mut resources, true, true, not_responding())
            .unwrap_err()
            .to_string();
        assert!(resources.gpu);
        assert!(error.contains("resumes a snapshot"), "{error}");
    }

    #[test]
    fn open_error_is_reported_with_the_node_and_the_errno() {
        let unavailable = GpuUnavailable {
            node: PathBuf::from("/dev/dri/renderD128"),
            failure: NodeFailure::Open(std::io::Error::from_raw_os_error(libc_eacces())),
        };
        let text = unavailable.to_string();
        assert!(
            text.starts_with("cannot open /dev/dri/renderD128: "),
            "{text}"
        );
        assert!(text.contains("ermission denied"), "{text}");
    }

    fn libc_eacces() -> i32 {
        13
    }

    #[test]
    fn listing_keeps_only_render_and_card_character_devices() {
        let dir = tempfile::tempdir().unwrap();
        // Regular files are not device nodes and must not be listed.
        std::fs::write(dir.path().join("renderD128"), b"").unwrap();
        std::fs::write(dir.path().join("card0"), b"").unwrap();
        std::fs::create_dir(dir.path().join("by-path")).unwrap();
        #[cfg(unix)]
        assert!(nodes_in(dir.path()).is_empty());
        assert!(nodes_in(&dir.path().join("absent")).is_empty());
    }
}
