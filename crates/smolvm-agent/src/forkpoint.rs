//! Workload-facing live-fork coordination.
//!
//! A workload calls `smolvm-fork-ready` after initialization. The helper writes
//! a marker and blocks, so the application cannot mutate training state while
//! the host freezes the golden. Restored clones are released independently by
//! the host through a VM-private directory bind-mounted into the container.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

const AGENT_BINARY: &str = "/usr/local/bin/smolvm-agent";
use smolvm_protocol::forkpoint::{
    FORK_ENV_PATH, HELPER_PATH, READY_PATH, RELEASE_PATH, RESTORED_PATH, STATE_DIR,
    WORKER_READY_HELPER_PATH, WORKER_READY_PATH, WORKER_READY_TOKEN_ENV,
};
const READY_CONTENT: &[u8] = b"smolvm-forkpoint-v1\n";

fn enabled() -> bool {
    std::env::var(smolvm_protocol::guest_env::FORKABLE).as_deref()
        == Ok(smolvm_protocol::guest_env::VALUE_ON)
}

/// Whether this process invocation is the workload-facing helper rather than
/// the PID-1 guest agent.
pub fn helper_requested() -> bool {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_default();
    let helper_argv0 = Path::new(&argv0)
        .file_name()
        .is_some_and(|name| name == "smolvm-fork-ready");
    helper_argv0 || args.next().is_some_and(|arg| arg == "fork-ready")
}

/// Whether this invocation is the post-restore worker-readiness helper.
pub fn worker_ready_helper_requested() -> bool {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_default();
    let helper_argv0 = Path::new(&argv0)
        .file_name()
        .is_some_and(|name| name == "smolvm-worker-ready");
    helper_argv0 || args.next().is_some_and(|arg| arg == "worker-ready")
}

/// Prepare the VM-private coordination directory and the bare-VM helper name.
/// Container workloads receive the same directory and binary through OCI bind
/// mounts in [`inject_into_container`].
pub fn setup() {
    if !enabled() {
        return;
    }
    if let Err(error) = std::fs::create_dir_all(STATE_DIR) {
        tracing::warn!(%error, "failed to create forkpoint state directory");
        return;
    }
    if let Err(error) = std::fs::set_permissions(STATE_DIR, std::fs::Permissions::from_mode(0o1777))
    {
        tracing::warn!(%error, "failed to set forkpoint state permissions");
    }
    let _ = std::fs::remove_file(READY_PATH);
    let _ = std::fs::remove_file(RESTORED_PATH);
    let _ = std::fs::remove_file(RELEASE_PATH);
    let _ = std::fs::remove_file(WORKER_READY_PATH);

    for helper in [HELPER_PATH, WORKER_READY_HELPER_PATH] {
        if !Path::new(helper).exists() {
            if let Err(error) = std::os::unix::fs::symlink(AGENT_BINARY, helper) {
                tracing::warn!(%error, helper, "failed to install bare-VM forkpoint helper");
            }
        }
    }
}

/// Expose the forkpoint helper and its VM-private state directory inside a
/// workload container. No-op for ordinary machines.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    inject_into_container_if(spec, enabled(), AGENT_BINARY, STATE_DIR);
}

fn inject_into_container_if(
    spec: &mut crate::oci::OciSpec,
    enabled: bool,
    agent_binary: &str,
    state_dir: &str,
) {
    if !enabled || !Path::new(agent_binary).is_file() || !Path::new(state_dir).is_dir() {
        return;
    }
    spec.add_bind_mount(agent_binary, HELPER_PATH, true);
    spec.add_bind_mount(agent_binary, WORKER_READY_HELPER_PATH, true);
    spec.add_bind_mount(state_dir, STATE_DIR, false);
}

/// Mark the workload ready and block until this VM is a released clone.
pub fn run_helper() -> i32 {
    if let Err(error) = run_helper_inner() {
        eprintln!("smolvm-fork-ready: {error}");
        return 1;
    }
    0
}

fn run_helper_inner() -> Result<(), String> {
    run_helper_at(
        Path::new(STATE_DIR),
        Path::new(READY_PATH),
        Path::new(RESTORED_PATH),
        Path::new(RELEASE_PATH),
        Duration::from_millis(20),
    )
}

fn run_helper_at(
    state_dir: &Path,
    ready_path: &Path,
    restored_path: &Path,
    release_path: &Path,
    poll_interval: Duration,
) -> Result<(), String> {
    std::fs::create_dir_all(state_dir)
        .map_err(|error| format!("create {}: {error}", state_dir.display()))?;
    let _ = std::fs::remove_file(release_path);

    let mut ready = std::fs::File::create(ready_path)
        .map_err(|error| format!("create {}: {error}", ready_path.display()))?;
    ready
        .write_all(READY_CONTENT)
        .map_err(|error| format!("write {}: {error}", ready_path.display()))?;
    ready
        .sync_all()
        .map_err(|error| format!("sync {}: {error}", ready_path.display()))?;
    println!("smolvm forkpoint ready; waiting for clone release");
    let _ = std::io::stdout().flush();

    // Keep the snapshot boundary out of a timed kernel wait. Some VMM restore
    // paths cannot reliably re-arm an inherited sleeping thread, which can
    // leave every clone from that checkpoint parked after a successful host
    // release. A restored clone writes RESTORED_PATH during identity setup;
    // waits started after that point are native to the clone and safe to use.
    while !restored_path.is_file() {
        if release_path.is_file() {
            let _ = std::fs::remove_file(ready_path);
            return Ok(());
        }
        std::thread::yield_now();
    }

    loop {
        if release_path.is_file() {
            let _ = std::fs::remove_file(ready_path);
            return Ok(());
        }
        std::thread::sleep(poll_interval);
    }
}

/// Publish the host-issued activation token after clone-local setup completes.
pub fn run_worker_ready_helper() -> i32 {
    if let Err(error) = write_worker_ready_at(
        Path::new(STATE_DIR),
        Path::new(FORK_ENV_PATH),
        Path::new(WORKER_READY_PATH),
    ) {
        eprintln!("smolvm-worker-ready: {error}");
        return 1;
    }
    0
}

fn worker_ready_token(env_path: &Path) -> Result<String, String> {
    let contents = std::fs::read_to_string(env_path)
        .map_err(|error| format!("read {}: {error}", env_path.display()))?;
    let prefix = format!("{WORKER_READY_TOKEN_ENV}=");
    let mut matches = contents
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix));
    let token = matches
        .next()
        .ok_or_else(|| format!("{WORKER_READY_TOKEN_ENV} is not configured for this lease"))?;
    if matches.next().is_some() {
        return Err(format!("{WORKER_READY_TOKEN_ENV} is duplicated"));
    }
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{WORKER_READY_TOKEN_ENV} must be 64 hexadecimal characters"
        ));
    }
    Ok(token.to_ascii_lowercase())
}

fn write_worker_ready_at(
    state_dir: &Path,
    env_path: &Path,
    worker_ready_path: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(state_dir)
        .map_err(|error| format!("create {}: {error}", state_dir.display()))?;
    let token = worker_ready_token(env_path)?;
    let temporary = state_dir.join(format!(".worker-ready.{}", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    if let Err(error) = marker
        .write_all(format!("{token}\n").as_bytes())
        .and_then(|()| marker.sync_all())
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("write {}: {error}", temporary.display()));
    }
    std::fs::rename(&temporary, worker_ready_path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("publish {}: {error}", worker_ready_path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    fn spec() -> OciSpec {
        OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        )
    }

    #[test]
    fn ordinary_container_does_not_receive_helper() {
        let mut spec = spec();
        inject_into_container_if(&mut spec, false, "/missing-agent", "/missing-state");
        assert!(spec
            .mounts
            .iter()
            .all(|mount| mount.destination != HELPER_PATH
                && mount.destination != WORKER_READY_HELPER_PATH));
    }

    #[test]
    fn forkable_container_mounts_helper_and_state() {
        let temp = tempfile::tempdir().unwrap();
        let agent = temp.path().join("smolvm-agent");
        let state = temp.path().join("forkpoint");
        std::fs::write(&agent, b"agent").unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(&state).unwrap();
        let mut spec = spec();
        inject_into_container_if(
            &mut spec,
            true,
            agent.to_str().unwrap(),
            state.to_str().unwrap(),
        );
        let helper = spec
            .mounts
            .iter()
            .find(|mount| mount.destination == HELPER_PATH)
            .unwrap();
        assert_eq!(helper.source, agent.to_str().unwrap());
        assert!(helper.options.iter().any(|option| option == "ro"));
        let worker_ready_helper = spec
            .mounts
            .iter()
            .find(|mount| mount.destination == WORKER_READY_HELPER_PATH)
            .unwrap();
        assert_eq!(worker_ready_helper.source, agent.to_str().unwrap());
        assert!(worker_ready_helper
            .options
            .iter()
            .any(|option| option == "ro"));
        let state_mount = spec
            .mounts
            .iter()
            .find(|mount| mount.destination == STATE_DIR)
            .unwrap();
        assert_eq!(state_mount.source, state.to_str().unwrap());
        assert!(!state_mount.options.iter().any(|option| option == "ro"));
    }

    #[test]
    fn helper_blocks_until_release_marker() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let ready = state.join("ready");
        let restored = state.join("restored");
        let release = state.join("release");
        std::fs::create_dir(&state).unwrap();

        let state_thread = state.clone();
        let ready_thread = ready.clone();
        let release_thread = release.clone();
        let helper = std::thread::spawn(move || {
            run_helper_at(
                &state_thread,
                &ready_thread,
                &state_thread.join("restored"),
                &release_thread,
                Duration::from_millis(1),
            )
        });
        for _ in 0..100 {
            if ready.is_file() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(ready.is_file());
        assert!(!helper.is_finished());
        std::fs::write(&restored, b"restored\n").unwrap();
        std::fs::write(&release, b"release\n").unwrap();
        helper.join().unwrap().unwrap();
        assert!(!ready.exists());
    }

    #[test]
    fn helper_can_release_before_restored_waits_are_armed() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let ready = state.join("ready");
        let restored = state.join("restored");
        let release = state.join("release");
        std::fs::create_dir(&state).unwrap();

        let state_thread = state.clone();
        let ready_thread = ready.clone();
        let restored_thread = restored.clone();
        let release_thread = release.clone();
        let helper = std::thread::spawn(move || {
            run_helper_at(
                &state_thread,
                &ready_thread,
                &restored_thread,
                &release_thread,
                Duration::from_secs(60),
            )
        });
        for _ in 0..100 {
            if ready.is_file() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(ready.is_file());
        assert!(!restored.exists());
        std::fs::write(&release, b"release\n").unwrap();
        helper.join().unwrap().unwrap();
        assert!(!ready.exists());
    }

    #[test]
    fn worker_ready_helper_atomically_publishes_the_lease_token() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let env = temp.path().join("fork-env");
        let marker = state.join("worker-ready");
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(
            &env,
            format!("LEARNER=3\n{WORKER_READY_TOKEN_ENV}={token}\n"),
        )
        .unwrap();

        write_worker_ready_at(&state, &env, &marker).unwrap();

        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            format!("{token}\n")
        );
        assert!(std::fs::read_dir(state).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
    }

    #[test]
    fn worker_ready_helper_rejects_missing_duplicate_or_invalid_tokens() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let env = temp.path().join("fork-env");
        let marker = state.join("worker-ready");
        for contents in [
            "LEARNER=3\n".to_string(),
            format!(
                "{WORKER_READY_TOKEN_ENV}={}\n{WORKER_READY_TOKEN_ENV}={}\n",
                "a".repeat(64),
                "b".repeat(64)
            ),
            format!("{WORKER_READY_TOKEN_ENV}=not-a-token\n"),
        ] {
            std::fs::write(&env, contents).unwrap();
            assert!(write_worker_ready_at(&state, &env, &marker).is_err());
            assert!(!marker.exists());
        }
    }
}
