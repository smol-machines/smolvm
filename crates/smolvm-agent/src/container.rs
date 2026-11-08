//! Containers started the way a Docker engine starts them.
//!
//! `ContainerStart` runs the caller's command as the container's own init
//! (PID 1) on a persistent image overlay, so the command's exit is the
//! container's exit, its status is reported, and its stdout and stderr stay
//! separate. The I/O streams on the request connection with the same
//! `Started` → `Stdout`/`Stderr` → `Exited` contract as an interactive `Run`,
//! and reuses its pumps. While it runs, the container is the overlay's main
//! container, so `Run` requests on the same overlay (`docker exec`) join it.
//!
//! The other requests here act on that container: `ContainerSignal`
//! (`docker kill`), `ContainerTop` (`docker top`), and
//! `SetInterfaceAddresses`, which lets a running machine join and leave
//! networks.

use smolvm_protocol::{error_codes, AgentResponse, ContainerStartSpec};

/// Guest directory for per-container generated files (`/etc/hosts`,
/// `/etc/hostname`) bound into the container.
#[cfg(target_os = "linux")]
const CONTAINER_FILES_DIR: &str = "/run/smolvm/containers";

/// Run a container's command as its init and stream its I/O until it exits.
#[cfg(target_os = "linux")]
pub fn handle_container_start(
    stream: &mut impl crate::ReadWrite,
    spec: ContainerStartSpec,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut started = match prepare(&spec) {
        Ok(started) => started,
        Err(e) => {
            crate::send_response(
                stream,
                &AgentResponse::error(e.to_string(), error_codes::SPAWN_FAILED),
            )?;
            return Ok(());
        }
    };
    crate::send_response(stream, &AgentResponse::Started)?;

    let oom_before = oom_kills();
    let result = match started.pty.take() {
        Some(pty) => crate::run_interactive_loop_pty(stream, &mut started.child, pty, None),
        None => crate::run_interactive_loop(stream, &mut started.child, None),
    };
    // The container is gone however the loop ended (exit, or the host went
    // away and the loop killed it); clear its runtime state so the overlay's
    // next start or exec does not find a dead main container.
    let _ = crate::crun::CrunCommand::delete(&started.container_id, true).output();
    let _ = std::fs::remove_file(crate::paths::main_container_id_path(&started.workload_id));
    let exit_code = result?;
    let oom = (exit_code == 137 || exit_code == -9) && oom_kills() > oom_before;
    crate::send_response(stream, &AgentResponse::Exited { exit_code, oom })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn handle_container_start(
    stream: &mut impl crate::ReadWrite,
    _spec: ContainerStartSpec,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::send_response(
        stream,
        &AgentResponse::error(
            "containers are not supported on this platform",
            error_codes::INTERNAL_ERROR,
        ),
    )?;
    Ok(())
}

/// A container whose command is running.
#[cfg(target_os = "linux")]
struct Started {
    child: std::process::Child,
    pty: Option<crate::pty::PtyMaster>,
    container_id: String,
    workload_id: String,
}

/// Everything up to the running command: overlay, mounts, bundle, spawn.
#[cfg(target_os = "linux")]
fn prepare(spec: &ContainerStartSpec) -> Result<Started, Box<dyn std::error::Error>> {
    use smolvm_protocol::ContainerMount;
    use std::path::Path;

    if spec.command.is_empty() {
        return Err("no command to run".into());
    }
    if spec.id.is_empty()
        || !spec
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("invalid container id '{}'", spec.id).into());
    }
    crate::ensure_storage_mounted();
    let prepared = crate::storage::prepare_for_run_persistent(&spec.image, &spec.overlay_id)
        .map_err(|e| format!("prepare the container filesystem: {e}"))?;
    let rootfs = Path::new(&prepared.rootfs_path);
    let workload_id = format!("persistent-{}", spec.overlay_id);

    // A previous run of this container that the host lost track of (it was
    // killed with the VM still up) would otherwise hold the overlay.
    if let Some(old) = crate::resolve_main_container(Some(&spec.overlay_id)) {
        let _ = crate::crun::CrunCommand::kill(&old, "SIGKILL").status();
        let _ = crate::crun::CrunCommand::delete(&old, true).output();
    }

    // Whole-directory shares go through the regular volume path; files and
    // subdirectories of a share, and tmpfs, are added to the spec below.
    let mut volumes: Vec<(String, String, bool)> = Vec::new();
    let mut extra_binds: Vec<(String, String, bool)> = Vec::new();
    let mut tmpfs: Vec<(String, Vec<String>)> = Vec::new();
    for mount in &spec.mounts {
        match mount {
            ContainerMount::Share {
                tag,
                subpath,
                target,
                read_only,
                copy_up,
            } => {
                let share = crate::storage::mount_share(tag)?;
                if *copy_up {
                    copy_up_into(rootfs, target, &share);
                }
                match subpath.as_deref().filter(|s| !s.is_empty()) {
                    None => volumes.push((tag.clone(), target.clone(), *read_only)),
                    Some(sub) => {
                        let source = safe_join(&share, sub)?;
                        if source.is_file() {
                            crate::storage::ensure_file_mount_target_under_root(rootfs, target)?;
                        }
                        extra_binds.push((
                            source.to_string_lossy().into_owned(),
                            target.clone(),
                            *read_only,
                        ));
                    }
                }
            }
            ContainerMount::Tmpfs { target, options } => {
                tmpfs.push((target.clone(), options.clone()));
            }
        }
    }
    crate::storage::setup_mounts(&prepared.rootfs_path, &volumes)
        .map_err(|e| format!("mount volumes: {e}"))?;

    let mut env = spec.env.clone();
    crate::oci::apply_process_env(rootfs, spec.user.as_deref(), &mut env);
    // Fail the start, as a container engine does, when the command cannot
    // run at all, instead of reporting a started container that exits.
    let path = env
        .iter()
        .rev()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    check_executable(rootfs, &spec.command[0], spec.workdir.as_deref(), &path)?;
    let launch = crate::ResolvedLaunch {
        command: spec.command.clone(),
        env,
        workdir: spec.workdir.clone(),
        user: spec.user.clone(),
    };
    let mut oci = crate::build_oci_spec(rootfs, &launch, &volumes, spec.tty, false, false)?;
    oci.root.readonly = spec.read_only_rootfs;
    if let Some(hostname) = spec.hostname.as_deref().filter(|h| !h.is_empty()) {
        oci.hostname = Some(hostname.to_string());
    }
    if let Some(size) = spec.shm_size.filter(|s| *s > 0) {
        for mount in oci.mounts.iter_mut() {
            if mount.destination == "/dev/shm" {
                mount.options.retain(|o| !o.starts_with("size="));
                mount.options.push(format!("size={size}"));
            }
        }
    }
    for (source, target, read_only) in &extra_binds {
        oci.add_bind_mount(source, target, *read_only);
    }
    for (target, options) in &tmpfs {
        oci.mounts.retain(|m| &m.destination != target);
        let mut options = options.clone();
        if !options.iter().any(|o| o == "nosuid") {
            options.push("nosuid".into());
        }
        if !options.iter().any(|o| o == "nodev") {
            options.push("nodev".into());
        }
        oci.mounts.push(crate::oci::OciMount {
            destination: target.clone(),
            mount_type: Some("tmpfs".into()),
            source: "tmpfs".into(),
            options,
        });
    }
    // Docker binds a generated /etc/hosts and /etc/hostname into every
    // container; so do we, so the container's own name and the caller's extra
    // hosts resolve without touching the image.
    let files = Path::new(CONTAINER_FILES_DIR).join(&spec.id);
    std::fs::create_dir_all(&files)?;
    let hostname = spec
        .hostname
        .clone()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(crate::oci::container_hostname);
    std::fs::write(files.join("hosts"), hosts_file(&hostname, &spec.hosts))?;
    std::fs::write(files.join("hostname"), format!("{hostname}\n"))?;
    for name in ["hosts", "hostname"] {
        let target = format!("/etc/{name}");
        if !spec.mounts.iter().any(|m| mount_target(m) == target) {
            crate::storage::ensure_file_mount_target_under_root(rootfs, &target)?;
            oci.mounts.retain(|m| m.destination != target);
            oci.add_bind_mount(&files.join(name).to_string_lossy(), &target, false);
        }
    }

    let bundle = rootfs
        .parent()
        .ok_or("invalid rootfs path: no parent")?
        .join("bundle");
    std::fs::create_dir_all(&bundle)?;
    oci.write_to(&bundle)
        .map_err(|e| format!("failed to write OCI spec: {e}"))?;
    let container_id = crate::oci::generate_container_id();
    tracing::info!(id = %spec.id, container_id = %container_id, command = ?spec.command, tty = spec.tty, "starting container");
    let (mut child, pty) = crate::spawn_crun_run(&bundle, &container_id, spec.tty, false)?;
    // Only a running container becomes the overlay's main container: a `Run`
    // that looked it up while crun was still creating it would find it not
    // running and delete its state, failing the start.
    if crate::pod::wait_for_crun_running(&container_id, &mut child).is_some() {
        std::fs::write(
            crate::paths::main_container_id_path(&workload_id),
            container_id.as_bytes(),
        )?;
    }
    if !spec.tty && !spec.open_stdin {
        // Closing the pipe gives the command end of file on stdin, as a
        // container started without -i sees.
        drop(child.stdin.take());
    }
    Ok(Started {
        child,
        pty,
        container_id,
        workload_id,
    })
}

/// `Ok` when `program` names an executable file in `rootfs`: a path (relative
/// to `workdir` when it has no leading slash), or a name found on `path`.
/// The error text is what Docker reports, which clients match on.
#[cfg(target_os = "linux")]
pub(crate) fn check_executable(
    rootfs: &std::path::Path,
    program: &str,
    workdir: Option<&str>,
    path: &str,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let candidates: Vec<String> = if program.contains('/') {
        if program.starts_with('/') {
            vec![program.to_string()]
        } else {
            vec![format!(
                "{}/{program}",
                workdir.unwrap_or("/").trim_end_matches('/')
            )]
        }
    } else {
        path.split(':')
            .filter(|d| !d.is_empty())
            .map(|d| format!("{}/{program}", d.trim_end_matches('/')))
            .collect()
    };
    let mut denied = false;
    for candidate in &candidates {
        if let Some(found) = resolve_in_root(rootfs, candidate) {
            match std::fs::metadata(&found) {
                Ok(m) if m.is_file() && m.permissions().mode() & 0o111 != 0 => return Ok(()),
                Ok(m) if m.is_file() => denied = true,
                _ => {}
            }
        }
    }
    if denied {
        Err(format!("exec: \"{program}\": permission denied"))
    } else if program.contains('/') {
        Err(format!(
            "exec: \"{program}\": stat {program}: no such file or directory"
        ))
    } else {
        Err(format!(
            "exec: \"{program}\": executable file not found in $PATH"
        ))
    }
}

/// `path` inside `rootfs`, following symlinks as the container would see
/// them (an absolute link target is relative to `rootfs`).
#[cfg(target_os = "linux")]
fn resolve_in_root(rootfs: &std::path::Path, path: &str) -> Option<std::path::PathBuf> {
    use std::path::{Component, PathBuf};
    let mut parts: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    parts.reverse();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops = 0;
    while let Some(part) = parts.pop() {
        match part.as_str() {
            "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => {}
        }
        resolved.push(part);
        let host: PathBuf = rootfs.join(resolved.join("/"));
        let meta = std::fs::symlink_metadata(&host).ok()?;
        if meta.file_type().is_symlink() {
            hops += 1;
            if hops > 40 {
                return None;
            }
            let target = std::fs::read_link(&host).ok()?;
            resolved.pop();
            if target.is_absolute() {
                resolved.clear();
            }
            let mut more: Vec<String> = target
                .components()
                .filter_map(|c| match c {
                    Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
                    Component::ParentDir => Some("..".into()),
                    _ => None,
                })
                .collect();
            more.reverse();
            parts.extend(more);
        }
    }
    Some(rootfs.join(resolved.join("/")))
}

#[cfg(target_os = "linux")]
fn mount_target(mount: &smolvm_protocol::ContainerMount) -> &str {
    match mount {
        smolvm_protocol::ContainerMount::Share { target, .. }
        | smolvm_protocol::ContainerMount::Tmpfs { target, .. } => target,
    }
}

/// The container's `/etc/hosts`: loopback names, its own hostname, then the
/// caller's entries.
fn hosts_file(hostname: &str, extra: &[(String, String)]) -> String {
    let mut hosts = String::from(
        "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n\
         fe00::0\tip6-localnet\nff00::0\tip6-mcastprefix\nff02::1\tip6-allnodes\n\
         ff02::2\tip6-allrouters\n",
    );
    let own = extra
        .iter()
        .any(|(_, names)| names.split_whitespace().any(|n| n == hostname));
    if !own && !hostname.is_empty() && hostname != "localhost" {
        hosts.push_str(&format!("127.0.1.1\t{hostname}\n"));
    }
    for (address, names) in extra {
        hosts.push_str(&format!("{address}\t{names}\n"));
    }
    hosts
}

/// `base/sub`, refusing a `sub` that climbs out of `base`.
#[cfg(target_os = "linux")]
fn safe_join(
    base: &std::path::Path,
    sub: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use std::path::Component;
    let mut path = base.to_path_buf();
    for component in std::path::Path::new(sub).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir | Component::RootDir => {}
            _ => return Err(format!("mount subpath '{sub}' leaves its share").into()),
        }
    }
    Ok(path)
}

/// A new, empty volume takes the image's content at its mount point, owner
/// and mode included, the way a container engine fills a new volume.
#[cfg(target_os = "linux")]
fn copy_up_into(rootfs: &std::path::Path, target: &str, share: &std::path::Path) {
    let Ok(mut entries) = std::fs::read_dir(share) else {
        return;
    };
    if entries.next().is_some() {
        return;
    }
    let Ok(source) = safe_join(rootfs, target) else {
        return;
    };
    if !source.is_dir() {
        return;
    }
    if let Err(e) = copy_tree(&source, share) {
        tracing::warn!(error = %e, target, "could not fill a new volume from the image");
    }
    if let Ok(meta) = std::fs::symlink_metadata(&source) {
        copy_owner_and_mode(share, &meta);
    }
}

#[cfg(target_os = "linux")]
fn copy_owner_and_mode(path: &std::path::Path, meta: &std::fs::Metadata) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let _ = std::os::unix::fs::lchown(path, Some(meta.uid()), Some(meta.gid()));
    if !meta.file_type().is_symlink() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(meta.mode()));
    }
}

#[cfg(target_os = "linux")]
fn copy_tree(source: &std::path::Path, dest: &std::path::Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&from)?;
        let kind = meta.file_type();
        if kind.is_dir() {
            std::fs::create_dir_all(&to)?;
            copy_tree(&from, &to)?;
        } else if kind.is_symlink() {
            let link = std::fs::read_link(&from)?;
            let _ = std::fs::remove_file(&to);
            std::os::unix::fs::symlink(link, &to)?;
        } else if kind.is_file() {
            std::fs::copy(&from, &to)?;
        } else {
            continue;
        }
        copy_owner_and_mode(&to, &meta);
    }
    Ok(())
}

/// Unpack a tar archive into `destination` below the container root.
#[cfg(target_os = "linux")]
fn unpack_archive(
    rootfs: &std::path::Path,
    archive: &str,
    destination: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest = safe_join(rootfs, destination)?;
    std::fs::create_dir_all(&dest)?;
    let file = std::fs::File::open(archive).map_err(|e| format!("open archive {archive}: {e}"))?;
    let mut tar = tar::Archive::new(file);
    tar.set_preserve_permissions(true);
    tar.set_preserve_ownerships(true);
    tar.set_unpack_xattrs(false);
    tar.set_overwrite(true);
    tar.unpack(&dest)
        .map_err(|e| format!("unpack archive into {destination}: {e}"))?;
    let _ = std::fs::remove_file(archive);
    Ok(())
}

/// Unpack an uploaded archive into a container's root filesystem.
pub fn handle_container_archive(
    image: &str,
    overlay_id: &str,
    archive: &str,
    destination: &str,
) -> AgentResponse {
    #[cfg(target_os = "linux")]
    {
        crate::ensure_storage_mounted();
        let result = crate::storage::prepare_for_run_persistent(image, overlay_id)
            .map_err(|e| e.to_string())
            .and_then(|prepared| {
                unpack_archive(
                    std::path::Path::new(&prepared.rootfs_path),
                    archive,
                    destination,
                )
                .map_err(|e| e.to_string())
            });
        match result {
            Ok(()) => AgentResponse::Ok { data: None },
            Err(e) => {
                let _ = std::fs::remove_file(archive);
                AgentResponse::error(e, error_codes::INTERNAL_ERROR)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (image, overlay_id, archive, destination);
        AgentResponse::error(
            "not supported on this platform",
            error_codes::INTERNAL_ERROR,
        )
    }
}

/// The guest kernel's count of OOM kills so far.
#[cfg(target_os = "linux")]
fn oom_kills() -> u64 {
    std::fs::read_to_string("/proc/vmstat")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("oom_kill "))
                .and_then(|n| n.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// Signal the init process of the overlay's running container.
pub fn handle_container_signal(overlay_id: &str, signal: &str, all: bool) -> AgentResponse {
    #[cfg(target_os = "linux")]
    {
        let Some(id) = crate::resolve_main_container(Some(overlay_id)) else {
            return AgentResponse::error("container is not running", error_codes::NOT_FOUND);
        };
        if all {
            // Without a per-container cgroup the process tree under init is
            // the container; signal each one directly.
            let Some(number) = signal_number(signal) else {
                return AgentResponse::error(
                    format!("unknown signal {signal}"),
                    error_codes::INVALID_REQUEST,
                );
            };
            let Some(init) = crate::crun_container_pid(&id) else {
                return AgentResponse::error("container is not running", error_codes::NOT_FOUND);
            };
            for pid in crate::pod::descendant_pids(init) {
                // SAFETY: kill(2) on a pid from this snapshot; a pid that has
                // exited since only makes the call fail.
                unsafe { libc::kill(pid as libc::pid_t, number) };
            }
            return AgentResponse::Ok { data: None };
        }
        let signal = signal.trim().trim_start_matches("SIG");
        let signal = if signal.chars().all(|c| c.is_ascii_digit()) {
            signal.to_string()
        } else {
            format!("SIG{}", signal.to_ascii_uppercase())
        };
        match crate::crun::CrunCommand::kill(&id, &signal).output() {
            Ok(out) if out.status.success() => AgentResponse::Ok { data: None },
            Ok(out) => AgentResponse::error(
                format!(
                    "signal {signal}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                error_codes::INTERNAL_ERROR,
            ),
            Err(e) => {
                AgentResponse::error(format!("signal {signal}: {e}"), error_codes::INTERNAL_ERROR)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (overlay_id, signal, all);
        AgentResponse::error(
            "not supported on this platform",
            error_codes::INTERNAL_ERROR,
        )
    }
}

/// A signal by name (`SIGSTOP`, `STOP`) or number.
#[cfg(target_os = "linux")]
fn signal_number(signal: &str) -> Option<libc::c_int> {
    let s = signal.trim();
    if let Ok(n) = s.parse::<libc::c_int>() {
        return (1..=64).contains(&n).then_some(n);
    }
    let upper = s.to_ascii_uppercase();
    Some(match upper.strip_prefix("SIG").unwrap_or(&upper) {
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        "KILL" => libc::SIGKILL,
        "TERM" => libc::SIGTERM,
        "INT" => libc::SIGINT,
        "HUP" => libc::SIGHUP,
        "QUIT" => libc::SIGQUIT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        _ => return None,
    })
}

/// `ps -ef`-style rows for every process of the overlay's running container.
pub fn handle_container_top(overlay_id: &str) -> AgentResponse {
    #[cfg(target_os = "linux")]
    {
        let Some(id) = crate::resolve_main_container(Some(overlay_id)) else {
            return AgentResponse::error("container is not running", error_codes::NOT_FOUND);
        };
        let Some(init) = crate::crun_container_pid(&id) else {
            return AgentResponse::error("container is not running", error_codes::NOT_FOUND);
        };
        let pids = crate::pod::descendant_pids(init);
        let processes: Vec<Vec<String>> = pids.iter().filter_map(|pid| top_row(*pid)).collect();
        AgentResponse::Ok {
            data: Some(serde_json::json!({
                "titles": ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"],
                "processes": processes,
            })),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = overlay_id;
        AgentResponse::error(
            "not supported on this platform",
            error_codes::INTERNAL_ERROR,
        )
    }
}

#[cfg(target_os = "linux")]
fn top_row(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid ...`: comm may hold spaces and parentheses.
    let close = stat.rfind(')')?;
    let comm = stat[stat.find('(')? + 1..close].to_string();
    let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    let ppid = fields.get(1)?.to_string();
    let ticks = clock_ticks();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let secs = (utime + stime) / ticks;
    let time = format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    );
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("0")
        .to_string();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let cmd = if cmdline.is_empty() {
        format!("[{comm}]")
    } else {
        cmdline
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    };
    Some(vec![
        uid,
        pid.to_string(),
        ppid,
        "0".into(),
        "-".into(),
        "?".into(),
        time,
        cmd,
    ])
}

#[cfg(target_os = "linux")]
fn clock_ticks() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as u64
    } else {
        100
    }
}

/// Make the interface's extra addresses exactly `addresses`.
pub fn handle_set_interface_addresses(addresses: &[String]) -> AgentResponse {
    match crate::network::set_extra_addresses(addresses) {
        Ok(()) => AgentResponse::Ok { data: None },
        Err(e) => AgentResponse::error(e, error_codes::INTERNAL_ERROR),
    }
}

/// Move the guest's primary address to another network.
pub fn handle_set_primary_address(
    address: &str,
    gateway: &str,
    dns: &str,
    dns_options: &[String],
) -> AgentResponse {
    match crate::network::set_primary_address(address, gateway, dns, dns_options) {
        Ok(()) => AgentResponse::Ok { data: None },
        Err(e) => AgentResponse::error(e, error_codes::INTERNAL_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_file_names_the_container_and_lists_extra_hosts() {
        let hosts = hosts_file(
            "web",
            &[("192.168.65.254".into(), "host.docker.internal".into())],
        );
        assert!(hosts.starts_with("127.0.0.1\tlocalhost\n"));
        assert!(hosts.contains("127.0.1.1\tweb\n"));
        assert!(hosts.ends_with("192.168.65.254\thost.docker.internal\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executables_resolve_through_links_inside_the_root() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("busybox"), b"x").unwrap();
        std::fs::set_permissions(bin.join("busybox"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::os::unix::fs::symlink("/bin/busybox", bin.join("sh")).unwrap();
        std::fs::write(bin.join("plain"), b"x").unwrap();
        assert!(check_executable(root.path(), "sh", None, "/usr/bin:/bin").is_ok());
        assert!(check_executable(root.path(), "/bin/sh", None, "").is_ok());
        let missing = check_executable(root.path(), "nope", None, "/bin").unwrap_err();
        assert!(missing.contains("executable file not found in $PATH"));
        let denied = check_executable(root.path(), "/bin/plain", None, "").unwrap_err();
        assert!(denied.contains("permission denied"));
    }

    #[test]
    fn hosts_file_skips_the_loopback_name_when_the_hostname_has_an_address() {
        let hosts = hosts_file("web", &[("172.18.0.2".into(), "web".into())]);
        assert!(!hosts.contains("127.0.1.1"));
        assert!(hosts.contains("172.18.0.2\tweb\n"));
    }
}
