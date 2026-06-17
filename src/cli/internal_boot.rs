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
    if std::env::var_os("SMOLVM_GPU_DEBUG").is_some() {
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
    }

    // Confine the VMM's filesystem view via Landlock — BEFORE seccomp (whose
    // allowlist omits the landlock_* syscalls) and before libkrun loads. Granted:
    // read+exec on rootfs/libs/system dirs, read-write on this VM's own data dir
    // and the device nodes a VMM needs; the rest of the host fs is denied so a
    // guest→VMM escape can't read other tenants' data or host secrets. Paths are
    // derived per-VM from the boot config. Gated by SMOLVM_LANDLOCK=enforce
    // (unset = off); fails closed. See docs/runtime-isolation-hardening.md.
    #[cfg(target_os = "linux")]
    if std::env::var("SMOLVM_LANDLOCK").as_deref() == Ok("enforce") {
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
        for (path, read_only) in &config.extra_disks {
            if *read_only {
                read_exec.push(path.clone());
            } else {
                read_write.push(path.clone());
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
        let ready_marker = config.rootfs_path.join(smolvm_protocol::AGENT_READY_MARKER);
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    match std::env::var("SMOLVM_SECCOMP").as_deref() {
        Ok("enforce") => {
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

    proc_timing!("ready to launch");

    let result = launch_agent_vm(&LaunchConfig {
        rootfs_path: &config.rootfs_path,
        disks: &disks,
        vsock_socket: &config.vsock_socket,
        console_log: config.console_log.as_deref(),
        mounts: &config.mounts,
        port_mappings: &config.ports,
        resources: config.resources,
        ssh_agent_socket: config.ssh_agent_socket.as_deref(),
        dns_filter_socket: dns_filter_socket_path.as_deref(),
        packed_layers_dir: config.packed_layers_dir.as_deref(),
        extra_disks: &config.extra_disks,
        dns_filter_enabled: config
            .dns_filter_hosts
            .as_ref()
            .is_some_and(|hosts| !hosts.is_empty()),
        egress_refresh_hosts: config.dns_filter_hosts.clone(),
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
