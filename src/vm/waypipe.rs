//! Host-side staging for the shared `waypipe` binary.
//!
//! When `--waypipe` is enabled, the guest agent runs `waypipe server` as the
//! forwarding daemon. To avoid wire-version drift between a waypipe bundled in
//! the guest and the user's host `waypipe client`, the guest reuses the *host*
//! binary: this module locates it on the host and stages it in a dedicated
//! directory that the launcher shares into the guest via virtiofs (virtiofs
//! shares a directory, not a single file, hence the staging dir).

use std::path::{Path, PathBuf};
use std::process::Child;

/// Locate the host `waypipe` binary on `PATH`.
pub fn host_binary() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("waypipe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Stage a host `waypipe` binary (`src`) into a virtiofs-shareable directory
/// under the VM data dir, returning that directory. The guest mounts it
/// read-only at [`smolvm_protocol::WAYPIPE_GUEST_PATH`] and runs `<dir>/waypipe`.
///
/// Copies rather than symlinks so the shared tree is self-contained (virtiofs
/// would otherwise expose a dangling link into the host filesystem). Skips the
/// copy when an up-to-date staged binary is already present.
pub fn stage_host_binary(vmdir: &Path, src: &Path) -> std::io::Result<PathBuf> {
    if !src.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("waypipe binary not found at {}", src.display()),
        ));
    }

    let dir = vmdir.join("waypipe-bin");
    std::fs::create_dir_all(&dir)?;
    let dst = dir.join("waypipe");

    // Re-copy only when missing or the source is newer / a different size, so
    // repeated boots do not pay the copy each time.
    if needs_copy(&src, &dst)? {
        std::fs::copy(&src, &dst)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(dir)
}

/// Whether `dst` must be (re)written from `src`.
fn needs_copy(src: &Path, dst: &Path) -> std::io::Result<bool> {
    let dst_meta = match std::fs::metadata(dst) {
        Ok(m) => m,
        Err(_) => return Ok(true),
    };
    let src_meta = std::fs::metadata(src)?;
    if src_meta.len() != dst_meta.len() {
        return Ok(true);
    }
    // If we can compare mtimes and the source is newer, recopy; otherwise trust
    // the size match (a same-size, same-or-older staged copy is good enough).
    match (src_meta.modified(), dst_meta.modified()) {
        (Ok(s), Ok(d)) => Ok(s > d),
        _ => Ok(false),
    }
}

/// Spawn a host `waypipe client` that listens on `socket` (plain unix mode) and
/// forwards to the host Wayland compositor. libkrun bridges the guest's outbound
/// waypipe vsock port to `socket`, so the client speaks plain unix here and
/// libkrun handles the vsock translation. Returns the child so the boot process
/// can keep it alive for the VM's lifetime; the child is armed with
/// `PR_SET_PDEATHSIG` so the kernel kills it when the boot process dies (the
/// boot path exits via `_exit`, which skips Drop, so kill-on-drop is not enough).
///
/// Linux-only: the host client only makes sense where a Wayland compositor runs.
/// Returns `None` (with a warning) when the host has no `waypipe`, no
/// `WAYLAND_DISPLAY`, or the spawn fails — a misconfigured host disables the
/// host-side automation rather than aborting the boot, matching the X11 bridge.
#[cfg(target_os = "linux")]
pub fn spawn_client(socket: &Path) -> Option<Child> {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        tracing::warn!(
            "waypipe host client requested but $WAYLAND_DISPLAY is unset - \
             not starting a host client (run `waypipe -s {} client` yourself)",
            socket.display()
        );
        return None;
    }

    let bin = match host_binary() {
        Some(bin) => bin,
        None => {
            tracing::warn!(
                "waypipe host client requested but no `waypipe` binary is on the host PATH - \
                 not starting a host client"
            );
            return None;
        }
    };

    // The client creates the socket; remove any stale one first so `waypipe`
    // does not refuse to bind. `internal_boot` also clears it, but this keeps
    // the spawn self-contained.
    let _ = std::fs::remove_file(socket);

    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("-s")
        .arg(socket)
        .arg("client")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // Tie the client's lifetime to this boot process: when the boot process
    // dies, the kernel sends SIGKILL to the client. Without this the client
    // would be reparented to init and leak after the VM is gone.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                // SIGKILL == 9. prctl(PR_SET_PDEATHSIG, ...) is async-signal-safe.
                if libc::prctl(libc::PR_SET_PDEATHSIG, 9) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    match cmd.spawn() {
        Ok(child) => {
            tracing::info!(
                socket = %socket.display(),
                binary = %bin.display(),
                "waypipe host client started"
            );
            Some(child)
        }
        Err(e) => {
            tracing::warn!("failed to start waypipe host client: {e} - not forwarding");
            None
        }
    }
}

/// Non-Linux hosts have no Wayland compositor to forward to, so the host client
/// is never started there.
#[cfg(not(target_os = "linux"))]
pub fn spawn_client(_socket: &Path) -> Option<Child> {
    None
}
