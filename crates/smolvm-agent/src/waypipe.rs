//! Guest-side waypipe Wayland forwarding.
//!
//! The Wayland analog of the X11 bridge, but with a different mechanism.
//! Wayland cannot be byte-relayed the way X11 can: every frame, keymap, and
//! clipboard transfer rides as an `SCM_RIGHTS` file descriptor (shm/dmabuf)
//! over the socket, and a raw relay drops those fds. So instead of the agent
//! relaying bytes itself (as [`crate::x11`] does), we run
//! [waypipe](https://gitlab.freedesktop.org/mstoeckl/waypipe), which terminates
//! the protocol on each side and re-materializes the buffers across the
//! transport.
//!
//! libkrun already bridges the guest's outbound [`ports::WAYPIPE`] vsock port to
//! a host Unix socket where the user runs a listening `waypipe client` next to
//! the host compositor. The guest's job is to run `waypipe server` in daemon
//! mode: with `--display` it creates a Wayland display socket and forwards
//! *every* client that connects to it (one daemon for all apps, like the X11
//! display socket), connecting out over vsock to the host client. The container
//! workload gets `WAYLAND_DISPLAY` set automatically, so guest GUI apps just
//! work.
//!
//! ## Why the daemon runs *inside the container*
//!
//! The agent's own rootfs is musl Alpine; a glibc `waypipe` (the host binary, or
//! a Debian/Ubuntu image's) cannot be exec'd there (missing `/lib64` loader). So
//! the daemon runs inside the workload container, which has a matching libc.
//! [`start_daemon_in_container`] fires one detached `crun exec` after the
//! keep-alive container is up; the daemon persists across subsequent execs and
//! its display socket lives in the container's own `/tmp/waypipe`.
//!
//! ## Binary source
//!
//! [`guest_env::WAYPIPE_BIN`] selects which binary the daemon runs. When set to
//! an absolute path (the host binary the launcher shared via
//! [`smolvm_protocol::WAYPIPE_TAG`], bind-mounted into the container by
//! [`inject_into_container`]), the daemon execs that; otherwise it uses
//! `waypipe` from the container's `PATH` (the image's own install).

use smolvm_protocol::{guest_env, ports};

/// `WAYLAND_DISPLAY` value exported into the workload env. Relative, so it
/// resolves under `XDG_RUNTIME_DIR` per the Wayland convention.
pub const GUEST_WAYLAND_DISPLAY: &str = "wayland-waypipe";

/// Directory used as `XDG_RUNTIME_DIR` for the daemon and workloads, so
/// `--display wayland-waypipe` lands at a deterministic path. Lives inside the
/// container's own filesystem (created by the daemon exec).
pub const GUEST_WAYLAND_DIR: &str = "/tmp/waypipe";

/// Whether waypipe Wayland forwarding is enabled for this launch.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::WAYPIPE).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Mount the shared host `waypipe` binary at boot, when forwarding is enabled in
/// shared-host-binary mode (an absolute [`guest_env::WAYPIPE_BIN`]). The
/// launcher attached it as virtiofs tag [`smolvm_protocol::WAYPIPE_TAG`]; this
/// mounts it in the agent namespace so [`inject_into_container`] can bind-mount
/// it into the workload container. No-op in container-PATH mode (nothing shared)
/// or when disabled. Mirrors [`crate::rosetta`]. Best-effort: logs on failure.
#[cfg(target_os = "linux")]
pub fn mount_shared_binary_at_boot() {
    if !is_enabled() {
        return;
    }
    let Some(dir) = shared_binary_dir() else {
        return; // container-PATH mode: nothing to mount.
    };
    if let Err(e) = mount_tag(&dir) {
        tracing::warn!(error = %e, dir = %dir, "failed to mount shared waypipe binary; forwarding may fall back to container PATH");
    }
}

#[cfg(not(target_os = "linux"))]
pub fn mount_shared_binary_at_boot() {}

/// Mount virtiofs tag [`smolvm_protocol::WAYPIPE_TAG`] at `dir`. Idempotent: if
/// the binary is already visible there, the mount is left as-is.
#[cfg(target_os = "linux")]
fn mount_tag(dir: &str) -> std::io::Result<()> {
    use std::ffi::CString;

    std::fs::create_dir_all(dir)?;
    if std::path::Path::new(dir).join("waypipe").exists() {
        return Ok(());
    }

    let src = CString::new(smolvm_protocol::WAYPIPE_TAG).expect("tag has no null byte");
    let dst = CString::new(dir).expect("path has no null byte");
    let fstype = CString::new("virtiofs").expect("literal has no null byte");
    // SAFETY: all args are valid null-terminated C strings; virtiofs takes no
    // mount data (matches rosetta::mount_runtime).
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

/// The `waypipe` binary the daemon should run inside the container.
///
/// A non-empty [`guest_env::WAYPIPE_BIN`] is the absolute path of the shared
/// host binary (bind-mounted in); otherwise the container's own `waypipe` on
/// `PATH` is used.
fn daemon_binary() -> String {
    match std::env::var(guest_env::WAYPIPE_BIN) {
        Ok(p) if !p.is_empty() => p,
        _ => "waypipe".to_string(),
    }
}

/// The in-container path of the shared host binary, if one was shared (i.e.
/// [`guest_env::WAYPIPE_BIN`] is a non-empty path). Used to bind-mount it into
/// the container. `None` in container-PATH mode.
fn shared_binary_dir() -> Option<String> {
    match std::env::var(guest_env::WAYPIPE_BIN) {
        Ok(p) if !p.is_empty() => std::path::Path::new(&p)
            .parent()
            .map(|d| d.to_string_lossy().into_owned()),
        _ => None,
    }
}

/// Outcome of a [`start_daemon_in_container`] attempt, so callers can decide
/// whether to surface something to the user. The forwarding daemon is lazy and
/// self-healing, so most outcomes are silent; only a genuine failure with
/// waypipe actually present warrants a user-visible warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStartOutcome {
    /// Forwarding is off, or the daemon is already running (socket present), or
    /// it started cleanly. Nothing to report.
    Ok,
    /// The daemon exec failed and `waypipe` is NOT present in the container yet.
    /// Expected while the user has not installed it; the next exec retries. The
    /// contained string is the binary name/path that was looked for.
    WaypipeMissing(String),
    /// `waypipe` IS present in the container but the daemon still failed to
    /// start (e.g. a glibc mismatch in host-binary mode, or it exited before
    /// creating its display socket). Retrying will not help; surface this. The
    /// string is a short human-readable reason.
    Failed(String),
}

/// Start the waypipe forwarding daemon inside the running keep-alive container.
///
/// Fires one detached `crun exec` running `waypipe server` in daemon mode. The
/// daemon persists after this exec returns (it is re-parented to the container's
/// init), so subsequent workload execs find its display socket. Best-effort: it
/// never fails the launch, but returns a [`DaemonStartOutcome`] so the caller
/// can surface a genuine failure to the user. No-op when forwarding is disabled.
#[cfg(target_os = "linux")]
pub fn start_daemon_in_container(container_id: &str) -> DaemonStartOutcome {
    if !is_enabled() {
        return DaemonStartOutcome::Ok;
    }

    // Idempotent: if the daemon's display socket already exists in the
    // container, a daemon is already running - don't spawn a duplicate. Every
    // exec calls this, so the check must be cheap (one `test -S`).
    if daemon_socket_present(container_id) {
        return DaemonStartOutcome::Ok;
    }

    let bin = daemon_binary();
    // Set up the runtime dir, drop any stale socket, then run the daemon.
    // `setsid` detaches it from the exec's session so it outlives this call;
    // `nohup`-style stdio redirection keeps it from holding the exec's fds.
    // `--display` makes waypipe create a Wayland display socket (under
    // XDG_RUNTIME_DIR) and forward every client that connects, rather than
    // wrapping a single child app. `-s 2:<port>` connects out over vsock to
    // host CID 2, where libkrun bridges to the host `waypipe client`. See the
    // man page's --display example.
    let script = format!(
        "mkdir -p {dir}; rm -f {dir}/{disp}; \
         XDG_RUNTIME_DIR={dir} setsid {bin} --vsock -s 2:{port} --display {disp} \
         server -- sleep infinity </dev/null >/dev/null 2>&1 &",
        dir = GUEST_WAYLAND_DIR,
        disp = GUEST_WAYLAND_DISPLAY,
        bin = bin,
        port = ports::WAYPIPE,
    );

    let command = [
        "/bin/sh".to_string(),
        "-c".to_string(),
        script,
    ];
    let env: [(String, String); 0] = [];

    // `crun start` returns before the container is necessarily ready for exec
    // (a fresh `crun exec` races it and fails with status 255). Wait briefly for
    // the container to reach the running state before firing the daemon.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !crate::is_container_running(container_id) {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                container_id = %container_id,
                "container not running in time; waypipe daemon not started"
            );
            return DaemonStartOutcome::Failed(
                "container did not reach the running state in time".to_string(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // The `&` backgrounds the daemon inside the container, so this `sh -c` exits
    // promptly with status 0; a non-zero status means the exec itself could not
    // run (e.g. `waypipe` not yet installed in container-PATH mode), which is a
    // best-effort miss - the next exec retries via the socket-presence check.
    let spawn_result = crate::crun::CrunCommand::exec(container_id, &env, &command, None, false)
        .stdin_null()
        .discard_output()
        .spawn()
        .and_then(|mut c| c.wait());

    // The daemon is backgrounded with `&` inside `sh -c`, so the exec returns
    // status 0 as soon as the shell forks it - regardless of whether `waypipe`
    // was found or started. So a status 0 tells us little; the real signal is
    // whether the display socket appears. Classify by socket + binary presence:
    //  - socket appears            -> Ok (daemon up)
    //  - no socket, no binary       -> WaypipeMissing (expected; silent retry)
    //  - no socket, binary present  -> Failed (present but broken; surface it)
    match spawn_result {
        Ok(status) if status.success() => {
            if wait_for_socket(container_id) {
                tracing::info!(
                    display = GUEST_WAYLAND_DISPLAY,
                    binary = %bin,
                    vsock_port = ports::WAYPIPE,
                    "started waypipe daemon in container"
                );
                DaemonStartOutcome::Ok
            } else if binary_present(container_id, &bin) {
                tracing::warn!(
                    binary = %bin,
                    "waypipe is present but its daemon exited without creating a display socket"
                );
                DaemonStartOutcome::Failed(format!(
                    "the waypipe daemon ({bin}) is present but exited without creating a \
                     display socket (in host-binary mode this is often a glibc mismatch \
                     between host and guest image; try --waypipe=container with waypipe \
                     installed in the image)"
                ))
            } else {
                tracing::info!(
                    binary = %bin,
                    "waypipe not present in container yet; will retry on next exec"
                );
                DaemonStartOutcome::WaypipeMissing(bin)
            }
        }
        Ok(status) => {
            // The exec itself could not run at all (e.g. crun error). Rare on
            // this path; treat as a real failure worth surfacing.
            tracing::warn!(
                binary = %bin,
                status = %status,
                "waypipe daemon exec exited non-zero"
            );
            DaemonStartOutcome::Failed(format!(
                "the daemon exec exited {status} (could not run waypipe in the container)"
            ))
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start waypipe daemon in container; Wayland forwarding unavailable");
            DaemonStartOutcome::Failed(format!("could not exec into the container: {e}"))
        }
    }
}

/// Poll briefly for the daemon's display socket to appear after a successful
/// daemon exec, so we can distinguish a daemon that stayed up from one that
/// exited immediately. Short deadline: the socket is created as one of the
/// daemon's first actions.
#[cfg(target_os = "linux")]
fn wait_for_socket(container_id: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if daemon_socket_present(container_id) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Whether `bin` resolves to an executable in the container: an absolute path
/// (host-binary mode) is tested directly; a bare name (`waypipe`, container-PATH
/// mode) is resolved via `command -v`.
#[cfg(target_os = "linux")]
fn binary_present(container_id: &str, bin: &str) -> bool {
    let probe = if bin.starts_with('/') {
        format!("test -x {bin}")
    } else {
        format!("command -v {bin} >/dev/null 2>&1")
    };
    let command = [
        "/bin/sh".to_string(),
        "-c".to_string(),
        probe,
    ];
    let env: [(String, String); 0] = [];
    crate::crun::CrunCommand::exec(container_id, &env, &command, None, false)
        .stdin_null()
        .discard_output()
        .spawn()
        .and_then(|mut c| c.wait())
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Whether the daemon's display socket already exists in the container (i.e. a
/// daemon is already running there). One cheap `crun exec test -S`.
#[cfg(target_os = "linux")]
fn daemon_socket_present(container_id: &str) -> bool {
    let sock = format!("{}/{}", GUEST_WAYLAND_DIR, GUEST_WAYLAND_DISPLAY);
    let command = [
        "test".to_string(),
        "-S".to_string(),
        sock,
    ];
    let env: [(String, String); 0] = [];
    crate::crun::CrunCommand::exec(container_id, &env, &command, None, false)
        .stdin_null()
        .discard_output()
        .spawn()
        .and_then(|mut c| c.wait())
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
pub fn start_daemon_in_container(_container_id: &str) -> DaemonStartOutcome {
    DaemonStartOutcome::Ok
}

impl DaemonStartOutcome {
    /// A one-line, user-facing warning for this outcome, or `None` when nothing
    /// should be surfaced. Only `Ok` (daemon up) is silent. `WaypipeMissing`
    /// warns too: forwarding retries lazily, but until waypipe is installed GUI
    /// apps will not appear on the host, so the user needs to know why. `Failed`
    /// reports the concrete reason.
    pub fn user_warning(&self) -> Option<String> {
        match self {
            DaemonStartOutcome::Ok => None,
            DaemonStartOutcome::WaypipeMissing(bin) => Some(format!(
                "smolvm: waypipe forwarding is not active yet: {bin} is not installed in \
                 the container, so guest GUI apps will not appear on the host. Install \
                 waypipe in the guest (e.g. `apt-get install -y waypipe`); it starts \
                 automatically on the next command with no restart."
            )),
            DaemonStartOutcome::Failed(reason) => {
                Some(format!("smolvm: waypipe forwarding is not available: {reason}"))
            }
        }
    }
}

/// Inject waypipe Wayland forwarding into an OCI container spec.
///
/// Sets `WAYLAND_DISPLAY` / `XDG_RUNTIME_DIR` so guest GUI apps find the daemon's
/// display socket, and - in shared-host-binary mode - bind-mounts the shared
/// binary's directory into the container so the daemon exec can run it. No-op
/// when forwarding is disabled. Mirrors [`crate::x11::inject_into_container`].
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    inject_into_container_if(spec, is_enabled(), shared_binary_dir());
}

/// Testable core of [`inject_into_container`].
fn inject_into_container_if(
    spec: &mut crate::oci::OciSpec,
    enabled: bool,
    shared_dir: Option<String>,
) {
    if !enabled {
        return;
    }
    // Share the host binary's mount into the container (rw not needed; the
    // binary is executed, not written). Only in shared-host-binary mode.
    if let Some(dir) = shared_dir {
        spec.add_bind_mount(&dir, &dir, true);
    }
    spec.add_env("XDG_RUNTIME_DIR", GUEST_WAYLAND_DIR);
    spec.add_env("WAYLAND_DISPLAY", GUEST_WAYLAND_DISPLAY);
}

/// Add the Wayland env to a command's env list when forwarding is enabled.
///
/// The keep-alive container's `crun exec` path (#542) and the interactive `-it`
/// join build a fresh process env rather than inheriting the container's, so the
/// spec injection never reaches them. This wires `WAYLAND_DISPLAY` /
/// `XDG_RUNTIME_DIR` into that exec/run env. No-op when disabled; never
/// overrides a user-supplied value. Mirrors [`crate::x11::inject_into_env`].
pub fn inject_into_env(env: &mut Vec<(String, String)>) {
    inject_into_env_if(env, is_enabled());
}

/// Testable core of [`inject_into_env`].
fn inject_into_env_if(env: &mut Vec<(String, String)>, enabled: bool) {
    if !enabled {
        return;
    }
    if !env.iter().any(|(k, _)| k == "WAYLAND_DISPLAY") {
        env.push((
            "WAYLAND_DISPLAY".to_string(),
            GUEST_WAYLAND_DISPLAY.to_string(),
        ));
    }
    if !env.iter().any(|(k, _)| k == "XDG_RUNTIME_DIR") {
        env.push(("XDG_RUNTIME_DIR".to_string(), GUEST_WAYLAND_DIR.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    #[test]
    fn inject_into_env_adds_wayland_only_when_enabled() {
        // Enabled -> injected.
        let mut env = vec![("PATH".to_string(), "/usr/bin".to_string())];
        inject_into_env_if(&mut env, true);
        assert!(
            env.iter()
                .any(|(k, v)| k == "WAYLAND_DISPLAY" && v == GUEST_WAYLAND_DISPLAY),
            "WAYLAND_DISPLAY must be injected when forwarding is enabled"
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "XDG_RUNTIME_DIR" && v == GUEST_WAYLAND_DIR),
            "XDG_RUNTIME_DIR must be injected when forwarding is enabled"
        );

        // Disabled -> no-op.
        let mut env = vec![("PATH".to_string(), "/usr/bin".to_string())];
        inject_into_env_if(&mut env, false);
        assert!(!env.iter().any(|(k, _)| k == "WAYLAND_DISPLAY"));
        assert!(!env.iter().any(|(k, _)| k == "XDG_RUNTIME_DIR"));
    }

    #[test]
    fn inject_into_env_never_overrides_user_value() {
        let mut env = vec![
            ("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string()),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
        ];
        inject_into_env_if(&mut env, true);
        assert_eq!(
            env.iter().filter(|(k, _)| k == "WAYLAND_DISPLAY").count(),
            1
        );
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "WAYLAND_DISPLAY")
                .map(|(_, v)| v.as_str()),
            Some("wayland-0")
        );
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "XDG_RUNTIME_DIR")
                .map(|(_, v)| v.as_str()),
            Some("/run/user/1000")
        );
    }

    #[test]
    fn inject_is_noop_when_disabled() {
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        );
        let mounts_before = spec.mounts.len();
        let envs_before = spec.process.env.len();

        inject_into_container_if(&mut spec, false, None);

        assert_eq!(spec.mounts.len(), mounts_before);
        assert_eq!(spec.process.env.len(), envs_before);
        assert!(!spec
            .process
            .env
            .iter()
            .any(|e| e.starts_with("WAYLAND_DISPLAY=")));
    }

    #[test]
    fn inject_sets_env_and_no_mount_in_container_mode() {
        // Container-PATH mode (no shared binary): env set, no bind mount added.
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        );
        let mounts_before = spec.mounts.len();

        inject_into_container_if(&mut spec, true, None);

        assert!(spec
            .process
            .env
            .iter()
            .any(|e| e == &format!("WAYLAND_DISPLAY={}", GUEST_WAYLAND_DISPLAY)));
        assert!(spec
            .process
            .env
            .iter()
            .any(|e| e == &format!("XDG_RUNTIME_DIR={}", GUEST_WAYLAND_DIR)));
        assert_eq!(
            spec.mounts.len(),
            mounts_before,
            "container-PATH mode must not add a bind mount"
        );
    }

    #[test]
    fn user_warning_silent_only_when_daemon_up() {
        // Only Ok (daemon up) is silent.
        assert_eq!(DaemonStartOutcome::Ok.user_warning(), None);

        // WaypipeMissing warns: names the binary and how to fix it.
        let missing = DaemonStartOutcome::WaypipeMissing("waypipe".to_string())
            .user_warning()
            .expect("WaypipeMissing must warn - GUI apps will not forward");
        assert!(missing.contains("waypipe"));
        assert!(missing.contains("install"));

        // Failed surfaces the concrete reason.
        let msg = DaemonStartOutcome::Failed("boom".to_string())
            .user_warning()
            .expect("Failed must produce a warning");
        assert!(msg.contains("boom"));
        assert!(msg.contains("waypipe"));
    }

    #[test]
    fn inject_binds_shared_binary_dir_in_host_mode() {
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        );

        inject_into_container_if(&mut spec, true, Some("/mnt/waypipe".to_string()));

        let mount = spec
            .mounts
            .iter()
            .find(|m| m.destination == "/mnt/waypipe")
            .expect("bind mount for shared waypipe binary not found");
        assert_eq!(mount.source, "/mnt/waypipe");
        assert_eq!(mount.mount_type.as_deref(), Some("bind"));
    }
}
