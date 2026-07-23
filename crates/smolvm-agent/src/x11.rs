//! Guest-side raw X11 socket bridge.
//!
//! The X11 analog of the SSH agent bridge (same outbound direction): instead of
//! the user wiring `socat` by hand, the guest agent creates a local X11 display
//! socket and, for each connection an X client opens, relays bytes out to the
//! host X server over the [`ports::X11`] vsock port. libkrun bridges that port
//! straight to the host X server's Unix socket (resolved from the host
//! `$DISPLAY`), so guest X clients render on the host X server transparently.
//!
//! Enabled by [`guest_env::X11`]. The agent binds the display socket for
//! [`GUEST_DISPLAY`] (`/tmp/.X11-unix/X10`) and exports `DISPLAY=:10` into the
//! workload env, so an X client just works with no manual setup.
//!
//! Note: a plain byte relay cannot carry `SCM_RIGHTS` ancillary fds, so MIT-SHM
//! and DRI3 fall back to wire-image transport (correct, just slower). For
//! per-window Wayland integration and correct fd/GPU handling, prefer waypipe.

use smolvm_protocol::{guest_env, ports};
use std::io;
use std::os::unix::net::UnixListener;
use std::thread;

/// `DISPLAY` value exported into the workload env when the bridge is enabled.
/// Hardcoded for now; the display socket lives at [`GUEST_X11_SOCK`].
pub const GUEST_DISPLAY: &str = ":10";

/// In-guest path of the X11 display socket the bridge listens on. X clients
/// resolve `DISPLAY=:10` to this path.
pub const GUEST_X11_SOCK: &str = "/tmp/.X11-unix/X10";

/// Whether the X11 socket bridge is enabled for this launch.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::X11).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Start the guest-side X11 socket bridge in a background thread.
///
/// Binds a Unix socket at [`GUEST_X11_SOCK`] and, for each incoming connection,
/// opens a vsock connection to the host-side bridge on [`ports::X11`] and relays
/// bytes bidirectionally.
pub fn start() {
    thread::Builder::new()
        .name("x11-bridge-guest".into())
        .spawn(|| {
            if let Err(e) = run_bridge() {
                tracing::warn!(error = %e, "guest X11 socket bridge stopped");
            }
        })
        .ok();
}

/// Inject `DISPLAY` into an OCI container spec when the bridge is enabled.
///
/// The container lives in its own mount namespace, so the display socket at
/// [`GUEST_X11_SOCK`] must be bind-mounted in, and it gets env from the image +
/// request (not the agent's own env), so `DISPLAY` has to be set explicitly.
/// No-op when the bridge is disabled. Mirrors [`crate::ssh_agent::inject_into_container`].
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    inject_into_container_if(spec, is_enabled());
}

/// Testable core of [`inject_into_container`]. Bind-mounts the display socket
/// and sets `DISPLAY` when `enabled`; no-op otherwise. Split out so tests can
/// exercise the injection without mutating the process-wide `SMOLVM_X11` env.
fn inject_into_container_if(spec: &mut crate::oci::OciSpec, enabled: bool) {
    if !enabled {
        return;
    }
    // Bind-mount the display socket; rw because the X11 protocol is bidirectional.
    spec.add_bind_mount(GUEST_X11_SOCK, GUEST_X11_SOCK, false);
    spec.add_env("DISPLAY", GUEST_DISPLAY);
}

/// Add `DISPLAY` to a command's env list when the bridge is enabled.
///
/// The keep-alive container's `crun exec` path (#542) builds a fresh process env
/// rather than inheriting the container's, so the spec injection never reaches
/// it. This wires `DISPLAY` into that exec/run env. No-op when disabled; never
/// overrides an existing value (e.g. a user-supplied `-e DISPLAY`). Mirrors
/// [`crate::ssh_agent::inject_into_env`].
pub fn inject_into_env(env: &mut Vec<(String, String)>) {
    inject_into_env_if(env, is_enabled());
}

/// Testable core of [`inject_into_env`].
fn inject_into_env_if(env: &mut Vec<(String, String)>, enabled: bool) {
    if enabled && !env.iter().any(|(k, _)| k == "DISPLAY") {
        env.push(("DISPLAY".to_string(), GUEST_DISPLAY.to_string()));
    }
}

fn run_bridge() -> io::Result<()> {
    let sock_path = std::path::Path::new(GUEST_X11_SOCK);

    // Clean up any stale socket (e.g. a guest-native X server slot).
    let _ = std::fs::remove_file(sock_path);

    // Ensure the X11 socket directory exists (/tmp/.X11-unix).
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(sock_path)?;

    // Make the socket accessible to all users in the VM (workloads may run as
    // non-root), matching the mode the manual `socat` recipe used.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o777))?;
    }

    tracing::info!(
        path = GUEST_X11_SOCK,
        display = GUEST_DISPLAY,
        vsock_port = ports::X11,
        "guest X11 socket bridge listening"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(local_conn) => {
                thread::Builder::new()
                    .name("x11-bridge-fwd".into())
                    .spawn(move || {
                        if let Err(e) = relay_to_host(local_conn) {
                            tracing::debug!(error = %e, "X11 bridge relay ended");
                        }
                    })
                    .ok();
            }
            Err(e) => {
                tracing::debug!(error = %e, "guest X11 accept error");
                if e.kind() == io::ErrorKind::InvalidInput {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Relay one X client connection (arriving on the local display socket) to the
/// host X server over vsock, forwarding bytes in both directions with
/// independent half-close.
///
/// X11 connections are long-lived and often idle (a window sits open waiting for
/// events), so - like the Docker relay and unlike the short-lived SSH agent
/// relay - this blocks on `poll` indefinitely and only exits once both
/// directions have closed.
#[cfg(target_os = "linux")]
fn relay_to_host(local: std::os::unix::net::UnixStream) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let mut host = crate::vsock::connect(ports::X11)?;
    let mut local = local;

    let local_fd = local.as_raw_fd();
    let host_fd = host.as_raw_fd();

    let mut buf = [0u8; 65536];

    // Track each direction independently so a half-close is mirrored, not
    // treated as a full teardown.
    let mut local_read_open = true;
    let mut host_read_open = true;

    while local_read_open || host_read_open {
        let mut poll_fds = [
            libc::pollfd {
                // A negative fd is ignored by poll(), so a closed read side
                // stops waking the loop while the other direction drains.
                fd: if local_read_open { local_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if host_read_open { host_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // Block until an open side is readable/closed (no idle timeout).
        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // local -> host
        if local_read_open
            && poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = io::Read::read(&mut local, &mut buf)?;
            if n == 0 {
                local_read_open = false;
                // SAFETY: host_fd is the valid, open fd owned by `host`.
                unsafe { libc::shutdown(host_fd, libc::SHUT_WR) };
            } else {
                io::Write::write_all(&mut host, &buf[..n])?;
            }
        }

        // host -> local
        if host_read_open
            && poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = io::Read::read(&mut host, &mut buf)?;
            if n == 0 {
                host_read_open = false;
                let _ = local.shutdown(std::net::Shutdown::Write);
            } else {
                io::Write::write_all(&mut local, &buf[..n])?;
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn relay_to_host(_local: std::os::unix::net::UnixStream) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "X11 socket bridge only supported on Linux guests",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    #[test]
    fn inject_into_env_adds_display_only_when_enabled() {
        // Enabled -> injected.
        let mut env = vec![("PATH".to_string(), "/usr/bin".to_string())];
        inject_into_env_if(&mut env, true);
        assert!(
            env.iter().any(|(k, v)| k == "DISPLAY" && v == GUEST_DISPLAY),
            "DISPLAY must be injected into the exec/run env when the bridge is enabled"
        );

        // Disabled -> no-op.
        let mut env = vec![("PATH".to_string(), "/usr/bin".to_string())];
        inject_into_env_if(&mut env, false);
        assert!(!env.iter().any(|(k, _)| k == "DISPLAY"));

        // Never overrides a user-supplied value.
        let mut env = vec![("DISPLAY".to_string(), ":99".to_string())];
        inject_into_env_if(&mut env, true);
        assert_eq!(env.iter().filter(|(k, _)| k == "DISPLAY").count(), 1);
        assert_eq!(env[0].1, ":99");
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

        inject_into_container_if(&mut spec, false);

        assert_eq!(spec.mounts.len(), mounts_before);
        assert_eq!(spec.process.env.len(), envs_before);
        assert!(!spec.process.env.iter().any(|e| e.starts_with("DISPLAY=")));
    }

    #[test]
    fn inject_adds_env_and_mount_when_enabled() {
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        );

        inject_into_container_if(&mut spec, true);

        // Env must point at the guest display.
        assert!(spec
            .process
            .env
            .iter()
            .any(|e| e == &format!("DISPLAY={}", GUEST_DISPLAY)));

        // Mount must bind the display socket at the same path inside the container.
        let mount = spec
            .mounts
            .iter()
            .find(|m| m.destination == GUEST_X11_SOCK)
            .expect("bind mount for X11 display socket not found");
        assert_eq!(mount.source, GUEST_X11_SOCK);
        assert_eq!(mount.mount_type.as_deref(), Some("bind"));
        // rw: the X11 protocol is bidirectional.
        assert!(!mount.options.iter().any(|o| o == "ro"));
        assert!(mount.options.iter().any(|o| o == "bind"));
    }

    #[test]
    fn inject_replaces_existing_display() {
        // An image whose config already exports a stale DISPLAY: keep exactly
        // one entry (duplicate keys leave the effective value shell-dependent).
        let mut spec = OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        );
        spec.process.env.push("DISPLAY=:99".to_string());

        inject_into_container_if(&mut spec, true);

        let matches: Vec<_> = spec
            .process
            .env
            .iter()
            .filter(|e| e.starts_with("DISPLAY="))
            .collect();
        assert_eq!(matches.len(), 1, "duplicate DISPLAY entries");
        assert_eq!(matches[0], &format!("DISPLAY={}", GUEST_DISPLAY));
    }
}
