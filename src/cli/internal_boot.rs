//! Internal boot subprocess for the API server.
//!
//! This command is NOT for direct user invocation. It's spawned by the API
//! server to launch a VM in a fresh single-threaded process, avoiding the
//! macOS fork-in-multithreaded-process issue.
//!
//! Usage: smolvm _boot-vm <config-path>

use smolvm::agent::boot_config::BootConfig;
use smolvm::agent::{launch_agent_vm, LaunchConfig, VmDisks};
use smolvm::data::disk::{DiskFormat, DiskType};
use smolvm::storage::VmDisk;
use std::path::{Path, PathBuf};

/// Open a boot disk honoring its on-disk format. A fork clone's disk path ends
/// in `.qcow2` (a copy-on-write overlay, opened as-is over its backing image);
/// every other disk is a raw image that may need creating/formatting. The path
/// is the single source of truth for the format — see `agent::resolve_disk_image`.
fn open_boot_disk<K: DiskType>(path: &Path, size_gb: u64) -> smolvm::Result<VmDisk<K>> {
    if path.extension().and_then(|e| e.to_str()) == Some("qcow2") {
        VmDisk::<K>::open_existing_with_format(path, DiskFormat::Qcow2)
    } else {
        VmDisk::<K>::open_or_create_at(path, size_gb)
    }
}

/// Run the boot subprocess.
///
/// Reads the boot config from the given path, sets up libkrun, and calls
/// `krun_start_enter` which blocks forever (or until the VM exits).
pub fn run(config_path: PathBuf) -> smolvm::Result<()> {
    let t_proc = std::time::Instant::now();

    // --- Parent-death watchdog ---------------------------------------------
    // This VMM (`smol-vmm _boot-vm`) is always spawned by an embedding parent:
    // the API server, a fleet node, or — for the SDKs — the Node/Python
    // in-process runtime. If that parent dies *abnormally* (panic, uncaught
    // exception, `process.exit`/`os._exit`, crash, or SIGKILL) it never runs
    // teardown, so without this watchdog the VMM would be reparented to init and
    // keep running forever, holding the VM's full RAM — an orphaned-process leak.
    //
    // Detection is by reparenting: when the real parent dies the kernel reparents
    // this process (to init/launchd, or a subreaper), so `getppid()` changes from
    // the value captured here at startup. The watcher polls for that change and
    // exits; the OS then tears the VM down with us. Polling (rather than an
    // inherited-pipe EOF) needs no fd plumbing, survives the
    // `close_inherited_fds_from(3)` call below, and uses only syscalls already in
    // the seccomp allowlist (`getppid`, `nanosleep`). Catches every death mode,
    // including SIGKILL, which no parent-side exit handler can. Started first so
    // it also covers a parent dying mid-boot.
    //
    // Armed only when an in-process embedder (the SDK) owns the VM's lifetime —
    // the manager signals this via SMOLVM_BOOT_WATCH_PARENT=1. The CLI detaches
    // its VM on purpose and `serve` reconnects to surviving VMs, so for those the
    // parent exiting is normal and the watchdog stays off.
    // The getppid()-based reparenting check is POSIX-specific; on Windows the
    // parent-death watchdog is not wired up (the SDK in-process embedder path is
    // a Unix concern here).
    #[cfg(unix)]
    if std::env::var_os("SMOLVM_BOOT_WATCH_PARENT").as_deref() == Some(std::ffi::OsStr::new("1")) {
        let original_ppid = unsafe { libc::getppid() };
        let _ = std::thread::Builder::new()
            .name("parent-death-watch".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if unsafe { libc::getppid() } != original_ppid {
                    smolvm::process::exit_child(0);
                }
            });
    }

    // Read boot config
    let config_data = std::fs::read(&config_path)
        .map_err(|e| smolvm::Error::agent("read boot config", e.to_string()))?;
    let config: BootConfig = serde_json::from_slice(&config_data)
        .map_err(|e| smolvm::Error::agent("parse boot config", e.to_string()))?;

    // Clean up the config file — it's no longer needed
    let _ = std::fs::remove_file(&config_path);

    // Redirect stdio. When SMOLVM_GPU_DEBUG=1, keep stderr pointed at a
    // debug log file so virglrenderer/MoltenVK errors are captured.
    // The GPU-debug stdio redirection uses POSIX fd dup2 and is part of the
    // (Unix-only) GPU path; on Windows it falls through to the portable stderr
    // log redirection below.
    #[cfg(unix)]
    let gpu_debug = std::env::var_os("SMOLVM_GPU_DEBUG").is_some();
    #[cfg(not(unix))]
    let gpu_debug = false;
    if gpu_debug {
        #[cfg(unix)]
        {
            if let Some(ref log) = config.console_log {
                let debug_path = log.with_file_name("gpu-debug.log");
                if let Ok(cpath) = std::ffi::CString::new(debug_path.to_string_lossy().as_bytes()) {
                    unsafe {
                        let fd = libc::open(
                            cpath.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                            0o644,
                        );
                        if fd >= 0 {
                            libc::dup2(fd, 2);
                            libc::close(fd);
                        }
                    }
                }
            }
            // Detach stdin/stdout only — keep stderr for GPU debug output
            unsafe {
                let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if devnull >= 0 {
                    libc::dup2(devnull, 0);
                    libc::dup2(devnull, 1);
                    libc::close(devnull);
                }
            }
        }
    } else if let Err(e) = smolvm::process::detach_stdio_to_stderr_file(&config.startup_error_log) {
        let _ = std::fs::write(
            &config.startup_error_log,
            format!("failed to redirect stdio: {}", e),
        );
        smolvm::process::exit_child(1);
    }

    // Close inherited file descriptors from the parent (server).
    // Without this, the subprocess holds database locks, network sockets, etc.
    // that can interfere with libkrun's operation. Keep stdin/stdout/stderr (0-2)
    // which now point to /dev/null.
    smolvm::process::close_inherited_fds_from(3);

    // Defense-in-depth before this process becomes the VMM host for an untrusted
    // guest: block setuid privilege escalation and core dumps (which would leak
    // guest RAM). See docs/runtime-isolation-hardening.md for the full roadmap.
    smolvm::process::harden_self();

    // If the supervisor delegated a cgroup v2 root (via SMOLVM_CGROUP_ROOT),
    // place this VMM in a per-VM cgroup with cpu/pids/memory caps so an untrusted
    // guest can't peg host CPU, fork-bomb the host, or balloon VMM memory. Inert
    // when the env var is unset (no delegation) — never blocks boot.
    #[cfg(target_os = "linux")]
    if let Some(cgroup_root) = std::env::var_os("SMOLVM_CGROUP_ROOT") {
        smolvm::process::place_in_cgroup(
            std::path::Path::new(&cgroup_root),
            config.resources.cpus,
            config.resources.memory_mib,
        );
    }

    // Shared pack store: present the node's root-owned shared pack copy at this
    // VM's `packed_layers_dir` via a per-VM idmapped bind mount (on-disk uid 0 ->
    // this VM's uid), in a private mount namespace that's torn down on exit. Done
    // here while still privileged (needs CAP_SYS_ADMIN) and BEFORE the uid drop
    // and Landlock/seccomp. The manager only sets `pack_idmap_source` when the uid
    // drop is active, so SMOLVM_VM_UID is guaranteed present; fail closed if not.
    #[cfg(target_os = "linux")]
    if let Some(ref shared) = config.pack_idmap_source {
        let target = match config.packed_layers_dir {
            Some(ref t) => t,
            None => {
                eprintln!("[pack-idmap] idmap source set without a mountpoint; refusing to boot");
                smolvm::process::exit_child(1);
            }
        };
        let uid: u32 = std::env::var("SMOLVM_VM_UID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                eprintln!("[pack-idmap] idmap source set without SMOLVM_VM_UID; refusing to boot");
                smolvm::process::exit_child(1);
            });
        let gid: u32 = std::env::var("SMOLVM_VM_GID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(uid);
        if let Err(e) = smolvm::process::setup_pack_idmap_mount(shared, target, uid, gid) {
            eprintln!("[pack-idmap] failed to mount shared pack, refusing to boot: {e}");
            smolvm::process::exit_child(1);
        }
    }

    // Kubernetes pod networking: while still privileged (needs CAP_NET_ADMIN +
    // CAP_SYS_ADMIN, and BEFORE the uid drop and Landlock/seccomp), attach this
    // sandbox to its CNI netns — open a tap there, tc-redirect it against the CNI
    // interface, and discover the pod's L3 config. The tap fd + config flow to the
    // launcher, which bridges the guest NIC to the tap. The attachment is held for
    // the VM's lifetime (owns the tap fd); dropping it tears the datapath down.
    #[cfg(target_os = "linux")]
    let pod_net_attachment = match config.pod_netns.as_deref() {
        Some(netns) => {
            let ns = netns.to_string_lossy();
            match smolvm::agent::pod_net::attach_pod_netns(&ns) {
                Ok(a) => Some(a),
                Err(e) => {
                    eprintln!(
                        "[pod-net] failed to attach pod netns {}: {e}",
                        netns.display()
                    );
                    smolvm::process::exit_child(1);
                }
            }
        }
        None => None,
    };
    #[cfg(target_os = "linux")]
    let pod_net_launch = pod_net_attachment.as_ref().map(|a| a.launch());
    #[cfg(not(target_os = "linux"))]
    let pod_net_launch: Option<smolvm::agent::pod_net::PodNetLaunch> = None;

    // Drop to an unprivileged uid before touching the guest, so a guest→VMM
    // escape can't signal/ptrace the supervisor or neighbor VMs nor reach
    // root-owned host files. Gated by SMOLVM_VM_UID (+ optional SMOLVM_VM_GID,
    // default = uid). Requires a privileged supervisor and this VM's data
    // dir/disks owned by the uid (see docs/runtime-isolation-hardening.md).
    // Fails closed. Placed AFTER cgroup placement (needs privilege), BEFORE
    // Landlock/seccomp (work unprivileged once no_new_privs is set).
    #[cfg(target_os = "linux")]
    if let Some(uid_str) = std::env::var_os("SMOLVM_VM_UID") {
        let uid: u32 = match uid_str.to_str().and_then(|s| s.parse().ok()) {
            Some(u) => u,
            None => {
                eprintln!("[uid-drop] invalid SMOLVM_VM_UID; refusing to boot");
                smolvm::process::exit_child(1);
            }
        };
        let gid: u32 = std::env::var("SMOLVM_VM_GID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(uid);
        if let Err(e) = smolvm::process::drop_privileges(uid, gid) {
            eprintln!("[uid-drop] failed, refusing to boot over-privileged: {e}");
            smolvm::process::exit_child(1);
        }
        // The setuid above clears the dumpable flag. A forkable golden's clones
        // map its guest-RAM memfd via /proc/<golden>/fd, which ptrace_may_access
        // denies on a non-dumpable target even at a uid match — so re-assert
        // dumpable here (after the drop) for a forkable VM, or fork breaks under
        // per-VM uid isolation. See process::set_dumpable.
        #[cfg(target_os = "linux")]
        if std::env::var_os("SMOLVM_FORKABLE").is_some() {
            smolvm::process::set_dumpable(true);
        }
    }

    // A fork clone restores by mapping the golden's guest-RAM memfd, opened via
    // /proc/<golden_pid>/fd/<N> — an anonymous inode with no filesystem path.
    // Landlock is path-based and cannot grant access to a pathless object, so a
    // Landlock-confined clone can never open the memfd (EACCES → can't boot).
    // Clones therefore skip Landlock; they stay confined by seccomp, the per-VM
    // uid drop, and the cgroup. Goldens and normal VMs are unaffected.
    #[cfg(target_os = "linux")]
    let is_fork_clone = std::env::var_os("SMOLVM_SNAPSHOT_DIR").is_some();

    // Confine the VMM's filesystem view via Landlock — BEFORE seccomp (whose
    // allowlist omits the landlock_* syscalls) and before libkrun loads. Granted:
    // read+exec on rootfs/libs/system dirs, read-write on this VM's own data dir
    // and the device nodes a VMM needs; the rest of the host fs is denied so a
    // guest→VMM escape can't read other tenants' data or host secrets. Paths are
    // derived per-VM from the boot config. Gated by SMOLVM_LANDLOCK=enforce
    // (unset = off); fails closed. See docs/runtime-isolation-hardening.md.
    #[cfg(target_os = "linux")]
    if std::env::var("SMOLVM_LANDLOCK").as_deref() == Ok("enforce") && is_fork_clone {
        eprintln!(
            "[landlock] fork clone skips Landlock (must map the golden's pathless \
             memfd); still confined by seccomp + uid drop + cgroup"
        );
    }
    #[cfg(target_os = "linux")]
    if std::env::var("SMOLVM_LANDLOCK").as_deref() == Ok("enforce") && !is_fork_clone {
        let mut read_exec: Vec<std::path::PathBuf> = [
            "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/proc", "/sys",
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
        read_exec.push(config.rootfs_path.clone());
        if let Some(ref d) = config.packed_layers_dir {
            read_exec.push(d.clone());
        }
        // Grant read+exec on the directory libkrun/libkrunfw are actually
        // dlopen'd from, resolved EXACTLY like the loader (`find_lib_dir`):
        // `SMOLVM_LIB_DIR` if it holds the libs, else exe-relative bundle paths
        // (`lib/`, `../../lib/linux-<arch>`, …). Consulting only `SMOLVM_LIB_DIR`
        // denied the bundled/dev layout — where the libs live in an exe-relative
        // `lib/` dir and the env var is unset — making `libkrunfw.so` fail to
        // load under enforce ("cannot open shared object file: Permission denied").
        if let Some(lib_dir) = smolvm::agent::find_lib_dir() {
            read_exec.push(lib_dir);
        }
        if let Some(libdir) = std::env::var_os("SMOLVM_LIB_DIR") {
            read_exec.push(std::path::PathBuf::from(libdir));
        }
        // A fresh VM's storage/overlay disk may be a qcow2 copy-on-write overlay
        // backed by a read-only disk template in ~/.smolvm; the confined VMM must
        // be able to open that backing file. Grant the template directory
        // read-only — it is the install dir (same trust level as SMOLVM_LIB_DIR,
        // which lives under it) and holds no secrets. A no-op for the copy path.
        if let Some(home) = dirs::home_dir() {
            read_exec.push(home.join(".smolvm"));
        }

        let mut read_write: Vec<std::path::PathBuf> = [
            "/dev/kvm",
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/urandom",
            "/dev/random",
            "/dev/dri",
            "/dev/ptmx",
            "/tmp",
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
        for p in [
            &config.storage_disk_path,
            &config.overlay_disk_path,
            &config.vsock_socket,
            &config.startup_error_log,
        ] {
            if let Some(parent) = p.parent() {
                read_write.push(parent.to_path_buf());
            }
        }
        if let Some(parent) = config.console_log.as_ref().and_then(|c| c.parent()) {
            read_write.push(parent.to_path_buf());
        }
        if let Some(parent) = config.ssh_agent_socket.as_ref().and_then(|s| s.parent()) {
            read_write.push(parent.to_path_buf());
        }
        for (path, read_only, _format) in &config.extra_disks {
            if *read_only {
                read_exec.push(path.clone());
            } else {
                read_write.push(path.clone());
            }
        }
        // A fork clone's disks are qcow2 copy-on-write overlays whose backing
        // files live in the GOLDEN's data dir (and may chain further, e.g.
        // golden qcow2 -> shared disk template). libkrun resolves the whole
        // chain inside this confined process, so every backing file must be
        // readable or the cold (re)start of a clone dies with "Error
        // configuring virtio-blk". Walk each disk's backing chain and grant
        // the files read-only. (The fork-restore boot path skips Landlock
        // entirely; this covers the plain stop -> start path.)
        for disk in [&config.storage_disk_path, &config.overlay_disk_path] {
            for backing in qcow2_backing_chain(disk) {
                read_exec.push(backing);
            }
        }
        for m in &config.mounts {
            if m.read_only {
                read_exec.push(m.source.clone());
            } else {
                read_write.push(m.source.clone());
            }
        }

        // The guest agent signals boot-readiness by writing a marker file into
        // the virtiofs rootfs, which the host polls. The rootfs is granted
        // read-exec above, so that FUSE write would be denied here. Carve out
        // write on JUST that one marker file — never the rootfs dir, which
        // holds the shared agent binary/init/libs a guest→VMM escape must not
        // be able to tamper with. Landlock needs an existing path to build the
        // rule, so pre-create it empty; the guest overwrites it with content
        // and the host treats non-empty as ready (see manager.rs wait loop).
        // The marker name is per-VM (the host passes it via SMOLVM_READY_MARKER so
        // concurrent boots don't share one file); fall back to the shared constant
        // if unset. Granting/pre-creating the WRONG name would leave the agent's
        // real (per-VM) write Landlock-denied → readiness limps to the vsock grace.
        let marker_name = std::env::var(smolvm_protocol::guest_env::READY_MARKER)
            .unwrap_or_else(|_| smolvm_protocol::AGENT_READY_MARKER.to_string());
        let ready_marker = config.rootfs_path.join(marker_name);
        let _ = std::fs::File::create(&ready_marker);
        read_write.push(ready_marker);

        if let Err(e) = smolvm::process::restrict_filesystem(&read_exec, &read_write) {
            eprintln!("[landlock] restriction failed, refusing to boot unconfined: {e}");
            smolvm::process::exit_child(1);
        }
    }

    // Confine this VMM to a syscall allowlist before it loads libkrun and
    // enters the guest run loop, so a guest→VMM escape can't reach dangerous host
    // syscalls. Gated by SMOLVM_SECCOMP=audit|enforce (unset = off). Installed
    // while single-threaded so libkrun's vCPU/worker threads inherit the filter.
    // Enforce mode fails closed (a filter that won't install must not silently run
    // unconfined). See docs/runtime-isolation-hardening.md.
    //
    // The call site is gated for BOTH x86_64 and aarch64 (AWS Graviton / GCP
    // Axion). The allowlist is arch-neutral (`libc::SYS_*` names resolve per
    // arch) with the x86_64-only legacy syscalls cfg-gated in build_seccomp_program;
    // `enforce` is validated to boot cleanly on aarch64 — bare VM, image-based
    // container (crun), and networked image pull all run under enforce with zero
    // SIGSYS on a Graviton-class host.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    match std::env::var("SMOLVM_SECCOMP").as_deref() {
        Ok("enforce") => {
            // CUDA + enforce: the shared CUDA daemon is spawned (fork+exec) on
            // first use, but exec is — rightly — not in the sandbox allowlist,
            // so a CUDA boot was SIGSYS-killed the moment cuda_host started.
            // Ensure the daemon BEFORE the filter goes on; the confined VMM
            // then only ever connect()s to its socket. Fail loud if it can't
            // start: an enforced CUDA boot without it would die anyway, later
            // and less legibly.
            #[cfg(unix)]
            if config.cuda
                && std::env::var_os("SMOLVM_CUDA_DAEMON").is_none()
                && std::env::var_os("SMOLVM_CUDA_SOCK").is_none()
            {
                match smolvm::cuda_daemon::ensure_running() {
                    Ok(sock) => {
                        // Single-threaded here (the filter install below relies
                        // on the same invariant), so set_var is race-free.
                        std::env::set_var("SMOLVM_CUDA_DAEMON", &sock);
                        tracing::info!(socket = %sock.display(),
                            "CUDA daemon pre-started for the sandboxed boot");
                    }
                    Err(e) => {
                        eprintln!(
                            "[seccomp] CUDA daemon pre-start failed ({e}); refusing to boot a \
                             CUDA machine that would be SIGSYS-killed under enforce"
                        );
                        smolvm::process::exit_child(1);
                    }
                }
            }
            if let Err(e) = smolvm::process::install_seccomp_filter(true) {
                eprintln!("[seccomp] enforce install failed, refusing to boot unconfined: {e}");
                smolvm::process::exit_child(1);
            }
        }
        Ok("audit") => {
            if let Err(e) = smolvm::process::install_seccomp_filter(false) {
                eprintln!("[seccomp] audit install failed: {e}");
            }
        }
        _ => {}
    }

    // Emit subprocess startup timing to the startup error log (stderr after
    // the stdio redirect above). These lines decompose the dark window between
    // parent's spawn() returning and launch_agent_vm() being called.
    // Emit when RUST_LOG contains "info" — check env var directly since the
    // tracing dispatch may be unusable after close_inherited_fds_from invalidates
    // macOS framework file descriptors held by the parent process.
    let rust_log = std::env::var("RUST_LOG").unwrap_or_default();
    let proc_timing_on = rust_log.contains("info");
    macro_rules! proc_timing {
        ($label:expr) => {
            if proc_timing_on {
                eprintln!("[proc] {:25} {}ms", $label, t_proc.elapsed().as_millis());
            }
        };
    }
    proc_timing!("fds closed");

    // Open storage and overlay disks, honoring qcow2 fork-clone overlays.
    let storage_disk = match open_boot_disk::<smolvm::storage::Storage>(
        &config.storage_disk_path,
        config.storage_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::write(
                &config.startup_error_log,
                format!("failed to open storage disk: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };
    proc_timing!("storage opened");

    let overlay_disk = match open_boot_disk::<smolvm::storage::Overlay>(
        &config.overlay_disk_path,
        config.overlay_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::write(
                &config.startup_error_log,
                format!("failed to open overlay disk: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };
    proc_timing!("overlay opened");

    // Launch the VM (never returns on success)
    let disks = VmDisks {
        storage: &storage_disk,
        overlay: Some(&overlay_disk),
    };

    // Start DNS filter listener if configured
    let dns_filter_socket_path = if let Some(ref hosts) = config.dns_filter_hosts {
        if !hosts.is_empty() {
            let socket_path = config
                .vsock_socket
                .parent()
                .unwrap_or(std::path::Path::new("/tmp"))
                .join("dns-filter.sock");
            if let Err(e) = smolvm::dns_filter_listener::start(&socket_path, hosts.clone()) {
                tracing::warn!(error = %e, "failed to start DNS filter listener");
                None
            } else {
                Some(socket_path)
            }
        } else {
            None
        }
    } else {
        None
    };

    // CUDA-over-vsock opt-in, resolved once here at the boot-config boundary so
    // the launcher receives a typed socket path (it never reads the environment).
    // Two ways in, both inherited by this boot subprocess from the manager:
    //   * SMOLVM_CUDA_SOCK=<path> — attach to an externally-managed host server
    //     at that AF_UNIX path (smolvm does not spawn one).
    //   * the machine's `cuda` flag (--cuda at create) — smolvm owns the
    //     lifecycle: derive a per-VM socket in this machine's dir and start the
    //     in-tree host server on it.
    let cuda_socket: Option<std::path::PathBuf> = if let Some(p) = std::env::var("SMOLVM_CUDA_SOCK")
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(std::path::PathBuf::from(p))
    } else if config.cuda {
        // Before booting: if the CUDA guest shims baked into this rootfs were
        // built from different wire source than this host binary, say so now with
        // the exact fix — otherwise the skew only surfaces as an opaque cuInit
        // failure deep inside the guest's first real CUDA call. The connect
        // handshake still hard-rejects a mismatch; this is the early, legible heads-up.
        fn warn_if_stale_cuda_shim(rootfs: &std::path::Path) {
            let stamp = rootfs.join("usr/local/lib/smolvm-cuda/proto-hash");
            let Ok(text) = std::fs::read_to_string(&stamp) else {
                return; // pre-stamp rootfs (no marker) — handshake still guards it
            };
            let Ok(shim) = u64::from_str_radix(text.trim(), 16) else {
                return; // unrecognized marker — don't second-guess it
            };
            if shim != smolvm::cuda_host::PROTO_HASH {
                let msg = format!(
                    "CUDA guest shim in the agent rootfs is STALE: rootfs wire hash {:016x} != \
                     this host {:016x}. The guest's CUDA calls will fail at cuInit. Rebuild the \
                     rootfs from the same source: scripts/build-agent-rootfs.sh --install",
                    shim,
                    smolvm::cuda_host::PROTO_HASH
                );
                tracing::warn!("{msg}");
                eprintln!("[smolvm] WARNING: {msg}");
            }
        }
        warn_if_stale_cuda_shim(&config.rootfs_path);

        let path = config
            .vsock_socket
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/tmp"))
            .join("cuda.sock");
        match smolvm::cuda_host::start(&path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "CUDA host server started");
                Some(path)
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to start CUDA host server — CUDA disabled");
                None
            }
        }
    } else {
        None
    };

    // Docker socket bridge: expose the guest's dockerd socket to the host as a
    // Unix socket in the per-VM dir. libkrun listens on this path (listen=true),
    // so we only need to hand it the path and clear any stale socket first.
    let docker_socket: Option<std::path::PathBuf> = if config.expose_docker {
        config.vsock_socket.parent().map(|dir| {
            let path = dir.join("docker.sock");
            let _ = std::fs::remove_file(&path);
            path
        })
    } else {
        None
    };

    proc_timing!("ready to launch");

    // Egress telemetry lands in the per-VM dir (the vsock socket's parent), the
    // same dir serve resolves from the machine name — so no name needs threading
    // across the process boundary.
    let egress_telemetry_path = config.vsock_socket.parent().map(|dir| dir.join("egress"));

    let result = launch_agent_vm(&LaunchConfig {
        rootfs_path: &config.rootfs_path,
        disks: &disks,
        vsock_socket: &config.vsock_socket,
        console_log: config.console_log.as_deref(),
        egress_telemetry: egress_telemetry_path.as_deref(),
        mounts: &config.mounts,
        port_mappings: &config.ports,
        resources: config.resources,
        ssh_agent_socket: config.ssh_agent_socket.as_deref(),
        dns_filter_socket: dns_filter_socket_path.as_deref(),
        cuda_socket: cuda_socket.as_deref(),
        docker_socket: docker_socket.as_deref(),
        published_sockets: &config.published_sockets,
        packed_layers_dir: config.packed_layers_dir.as_deref(),
        extra_disks: &config.extra_disks,
        dns_filter_enabled: config
            .dns_filter_hosts
            .as_ref()
            .is_some_and(|hosts| !hosts.is_empty()),
        egress_refresh_hosts: config.dns_filter_hosts.clone(),
        pod_net: pod_net_launch,
    });

    // If we get here, launch_agent_vm returned (should only happen on error)
    if let Err(ref e) = result {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.startup_error_log)
            .and_then(|mut file| {
                use std::io::Write;
                writeln!(file, "{e}")
            });
    }

    smolvm::process::exit_child(1);
}

/// Resolve the qcow2 backing-file chain of `path`: if the file is a qcow2 with
/// a backing file, return that path and recurse into it (bounded). Non-qcow2
/// files, unreadable files, and files without a backing entry yield nothing.
/// Used to pre-grant Landlock read access on every image the confined VMM's
/// block layer will open — a fork clone's disks are backed by files in the
/// golden's data dir, outside the clone's own granted paths.
#[cfg(target_os = "linux")]
fn qcow2_backing_chain(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    use std::io::{Read, Seek, SeekFrom};
    let mut chain = Vec::new();
    let mut current = path.to_path_buf();
    // A backing chain deeper than a handful of links is not something this
    // engine produces; the bound only guards against cycles.
    for _ in 0..8 {
        let Ok(mut f) = std::fs::File::open(&current) else {
            break;
        };
        let mut header = [0u8; 20];
        if f.read_exact(&mut header).is_err() {
            break;
        }
        // qcow2: magic "QFI\xfb", then version; backing offset at 8, size at 16.
        if header[0..4] != [0x51, 0x46, 0x49, 0xfb] {
            break;
        }
        let offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
        let size = u32::from_be_bytes(header[16..20].try_into().unwrap());
        if offset == 0 || size == 0 || size > 4096 {
            break;
        }
        let mut name = vec![0u8; size as usize];
        if f.seek(SeekFrom::Start(offset)).is_err() || f.read_exact(&mut name).is_err() {
            break;
        }
        let Ok(backing) = String::from_utf8(name) else {
            break;
        };
        let backing = std::path::PathBuf::from(backing);
        if chain.contains(&backing) {
            break;
        }
        chain.push(backing.clone());
        current = backing;
    }
    chain
}

#[cfg(all(test, target_os = "linux"))]
mod backing_chain_tests {
    use super::qcow2_backing_chain;
    use std::io::Write;

    fn fake_qcow2(
        dir: &std::path::Path,
        name: &str,
        backing: Option<&std::path::Path>,
    ) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut h = vec![0u8; 128];
        h[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        h[4..8].copy_from_slice(&3u32.to_be_bytes());
        if let Some(b) = backing {
            let bs = b.as_os_str().to_str().unwrap().as_bytes();
            h[8..16].copy_from_slice(&128u64.to_be_bytes());
            h[16..20].copy_from_slice(&(bs.len() as u32).to_be_bytes());
            h.extend_from_slice(bs);
        }
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&h).unwrap();
        p
    }

    // A clone's disk chains through its golden's qcow2 to the shared raw
    // template; the Landlock grant must surface every link so the confined
    // VMM can open the whole chain on a cold restart.
    #[test]
    fn resolves_two_level_chain_and_stops_at_raw() {
        let dir = std::env::temp_dir().join(format!("smolvm-bc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("template.raw");
        std::fs::write(&raw, b"not a qcow2").unwrap();
        let golden = fake_qcow2(&dir, "golden.qcow2", Some(&raw));
        let clone = fake_qcow2(&dir, "clone.qcow2", Some(&golden));
        assert_eq!(
            qcow2_backing_chain(&clone),
            vec![golden.clone(), raw.clone()]
        );
        // Non-qcow2 and backing-less files yield nothing.
        assert!(qcow2_backing_chain(&raw).is_empty());
        let solo = fake_qcow2(&dir, "solo.qcow2", None);
        assert!(qcow2_backing_chain(&solo).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
