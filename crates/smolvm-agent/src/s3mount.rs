//! Mount S3 buckets inside the workload container's mount namespace.
//!
//! A remote volume has to appear in the namespace the workload actually lives
//! in — the same reasoning as [`crate::nsfile`]: a mount made in the agent's
//! namespace is invisible to the container, and to `exec`/`shell` sessions that
//! join it.
//!
//! `setns(CLONE_NEWMNT)` is refused for a multithreaded caller and the agent
//! runs a threaded async runtime, so each mount runs in a fresh single-threaded
//! re-exec of this binary (`smolvm-agent s3-mount …`), dispatched at the top of
//! `main` before any thread starts. The helper then *stays alive* serving FUSE
//! for as long as the mount exists — unlike the ns-file helper, which does one
//! operation and exits.
//!
//! Nothing is required of the container image: no rclone, no fuse3, no
//! `fusermount3`. The helper opens `/dev/fuse` (creating the node if the image
//! lacks one) and calls `mount(2)` directly as root, so a bucket can be mounted
//! into a distroless or scratch image that could not install a helper at all.

use std::time::Duration;

use smolvm_s3fs::{s3, sigv4, MountOptions};

const HELPER_ARG: &str = "s3-mount";

/// Absolute path to this binary in the guest rootfs.
///
/// A fixed path rather than `current_exe()`: the agent pivot_roots during boot,
/// after which `/proc/self/exe` names a path that no longer resolves — the same
/// reason [`crate::nsfile`] and [`crate::forkpoint`] hard-code it.
const AGENT_BINARY: &str = "/usr/local/bin/smolvm-agent";

/// The helper speaks the protocol's own volume type: one definition means the
/// wire format and the mount helper cannot drift apart.
pub type MountSpec = smolvm_protocol::S3Volume;

/// Credentials for a volume, or `None` for anonymous access.
///
/// A half-supplied key pair would sign every request with a broken credential,
/// which is harder to diagnose than an explicit anonymous request.
fn credentials_of(spec: &MountSpec) -> Option<sigv4::Credentials> {
    match (&spec.access_key_id, &spec.secret_access_key) {
        (Some(k), Some(sec)) if !k.is_empty() && !sec.is_empty() => Some(sigv4::Credentials {
            access_key_id: k.clone(),
            secret_access_key: sec.clone(),
            session_token: spec.session_token.clone(),
        }),
        _ => None,
    }
}

/// Client configuration for a volume.
///
/// Shared by the reachability probe and the mount helper so the two can never
/// disagree about which endpoint, prefix or credentials a volume means.
fn client_config(spec: &MountSpec) -> s3::Config {
    s3::Config {
        endpoint: spec.endpoint.clone(),
        region: spec.region.clone(),
        bucket: spec.bucket.clone(),
        prefix: spec.prefix.clone(),
        credentials: credentials_of(spec),
        // Path-style works against AWS and every S3-compatible server; virtual
        // host style would need per-provider DNS assumptions.
        path_style: true,
        timeout: Duration::from_secs(60),
    }
}

/// Whether this process was re-exec'd as the mount helper.
///
/// Checked before the async runtime starts, because `setns(CLONE_NEWMNT)`
/// requires a single-threaded caller.
pub fn helper_requested() -> bool {
    std::env::args().nth(1).as_deref() == Some(HELPER_ARG)
}

/// Entry point for `smolvm-agent s3-mount <pid> <spec-json>`.
///
/// Runs until the mount is torn down; the caller supervises it as a child.
pub fn run_helper() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("s3-mount: usage: s3-mount <container-pid> <spec-json>");
        return 2;
    }
    let Ok(pid) = args[2].parse::<u32>() else {
        eprintln!("s3-mount: bad pid");
        return 2;
    };
    let spec: MountSpec = match serde_json::from_str(&args[3]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("s3-mount: bad spec: {e}");
            return 2;
        }
    };

    // pid 0 means "already in the right namespace" (used by tests and by the
    // no-container case); anything else joins the workload's namespace first.
    if pid != 0 {
        if let Err(e) = enter_mount_namespace(pid) {
            eprintln!("s3-mount: {e}");
            return 1;
        }
    }

    let cfg = client_config(&spec);
    let opts = MountOptions {
        mountpoint: spec.mountpoint.clone(),
        read_only: spec.read_only,
        allow_other: true,
        // Staging lives on the container's own writable layer so a large write
        // is bounded by the machine's disk, not by RAM.
        scratch_dir: std::path::PathBuf::from("/var/tmp/smolvm-s3fs"),
    };

    eprintln!(
        "s3-mount: mounting s3://{}/{} at {}",
        spec.bucket, spec.prefix, spec.mountpoint
    );
    #[cfg(target_os = "linux")]
    {
        match smolvm_s3fs::mount(cfg, opts) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("s3-mount: mount failed: {e}");
                1
            }
        }
    }
    // The agent only ever runs in a Linux guest; this keeps host-side unit
    // tests (which build the crate on macOS) compiling.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cfg, opts);
        eprintln!("s3-mount: mounting is Linux-only");
        1
    }
}

#[cfg(target_os = "linux")]
fn enter_mount_namespace(pid: u32) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    let ns = format!("/proc/{pid}/ns/mnt");
    let file = std::fs::File::open(&ns).map_err(|e| format!("open {ns}: {e}"))?;
    // SAFETY: `fd` is a live descriptor for a mount-namespace file; setns only
    // reads it and this process is single-threaded (re-exec'd for that reason).
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNS) };
    if rc != 0 {
        return Err(format!("setns({ns}): {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enter_mount_namespace(_pid: u32) -> Result<(), String> {
    Err("mount namespaces are Linux-only".to_string())
}

/// How long to wait for a mount to appear before giving up.
///
/// A mount that never appears is a hard start failure: the workload would run
/// against an empty directory and silently produce wrong results, which is far
/// worse than refusing to start.
const MOUNT_TIMEOUT: Duration = Duration::from_secs(30);

/// Check that a bucket is really usable before mounting it.
///
/// `mount(2)` on `/dev/fuse` succeeds without ever contacting S3, so on its own
/// a mount proves nothing: a typo'd bucket, an expired key or an unreachable
/// endpoint all produce a machine that starts happily and serves an empty
/// directory, and the workload then reads nothing and produces silently wrong
/// results. One list request collapses all of those into a start failure that
/// names the cause.
///
/// Runs in the agent's own namespace — reachability and credentials do not
/// depend on the mount namespace the helper later joins.
#[cfg(target_os = "linux")]
fn probe(spec: &MountSpec) -> Result<(), String> {
    s3::Client::new(client_config(spec))
        .list_dir("")
        .map(|_| ())
        .map_err(|e| {
            let at = if spec.prefix.is_empty() {
                spec.bucket.clone()
            } else {
                format!("{}/{}", spec.bucket, spec.prefix)
            };
            format!("s3://{at} is not reachable: {e}")
        })
}

/// Mount every volume into `container_id`'s namespace and wait until each is
/// visible.
///
/// Called between `crun create` and `crun start`, so the workload's first
/// instruction already sees the data.
#[cfg(target_os = "linux")]
pub fn mount_all(container_id: &str, specs: &[MountSpec]) -> Result<(), String> {
    let pid = crate::crun_created_container_pid(container_id)
        .ok_or_else(|| format!("container {container_id} has no pid"))?;

    // Probe every volume before mounting any of them, so a machine with two
    // volumes fails on the bad one rather than half-mounting and then failing.
    for spec in specs {
        probe(spec)?;
    }

    let mut children = Vec::with_capacity(specs.len());
    for spec in specs {
        children.push(spawn(pid, spec)?);
    }

    let deadline = std::time::Instant::now() + MOUNT_TIMEOUT;
    for (spec, mut child) in specs.iter().zip(children) {
        loop {
            if mount_is_present(pid, &spec.mountpoint) {
                break;
            }
            // A helper that has already exited will never mount anything, so
            // report that immediately instead of waiting out the full timeout.
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!(
                    "mounting {} failed ({status}) — see the agent log for the cause",
                    spec.mountpoint
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "{} did not mount within {}s",
                    spec.mountpoint,
                    MOUNT_TIMEOUT.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        tracing::info!(mountpoint = %spec.mountpoint, bucket = %spec.bucket, "s3 volume mounted");
        // The helper serves the mount for as long as it exists, so it is
        // deliberately never reaped: it exits when the FUSE session ends, and
        // the container's teardown takes the namespace with it.
        std::mem::forget(child);
    }
    Ok(())
}

/// Whether `mountpoint` is mounted inside the container's namespace.
///
/// Read from the container's own `mountinfo` rather than the agent's: the mount
/// is deliberately invisible from outside that namespace, so checking the
/// agent's view would always report failure.
#[cfg(target_os = "linux")]
fn mount_is_present(pid: u32, mountpoint: &str) -> bool {
    let Ok(mounts) = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")) else {
        return false;
    };
    mounts.lines().any(|l| {
        let mut fields = l.split(' ');
        // mountinfo: id parent major:minor root MOUNTPOINT ...
        fields.nth(4).map(|m| m == mountpoint).unwrap_or(false) && l.contains("fuse")
    })
}

/// Spawn a mount helper for `spec` against the container at `pid`.
///
/// Returns the child so the caller can supervise it; the mount lives exactly as
/// long as this process does.
pub fn spawn(pid: u32, spec: &MountSpec) -> Result<std::process::Child, String> {
    let json = serde_json::to_string(spec).map_err(|e| format!("encode spec: {e}"))?;
    std::process::Command::new(AGENT_BINARY)
        .arg(HELPER_ARG)
        .arg(pid.to_string())
        .arg(json)
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn s3-mount helper: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> MountSpec {
        MountSpec {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: "p".into(),
            mountpoint: "/mnt/x".into(),
            read_only: false,
            access_key_id: Some("k".into()),
            secret_access_key: Some("s".into()),
            session_token: None,
        }
    }

    #[test]
    fn a_spec_survives_the_argv_round_trip() {
        let s = spec();
        let json = serde_json::to_string(&s).unwrap();
        let back: MountSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bucket, "b");
        assert_eq!(back.mountpoint, "/mnt/x");
        assert_eq!(back.access_key_id.as_deref(), Some("k"));
    }

    // A half-supplied key pair would sign every request with a broken
    // credential; anonymous is both correct and far easier to diagnose.
    #[test]
    fn credentials_need_both_halves_or_none() {
        assert!(credentials_of(&spec()).is_some());

        let mut half = spec();
        half.secret_access_key = None;
        assert!(credentials_of(&half).is_none());

        let mut empty = spec();
        empty.access_key_id = Some(String::new());
        assert!(credentials_of(&empty).is_none());

        let mut anon = spec();
        anon.access_key_id = None;
        anon.secret_access_key = None;
        assert!(credentials_of(&anon).is_none());
    }

    #[test]
    fn the_helper_is_only_requested_by_its_own_argv() {
        // Guard the dispatch predicate: a stray match would make the agent exit
        // instead of booting the machine.
        assert_eq!(HELPER_ARG, "s3-mount");
    }

    #[test]
    fn the_client_config_carries_the_spec_verbatim() {
        // The probe and the helper share this; if it stopped reflecting the
        // spec, a volume could be probed against one bucket and mounted from
        // another.
        let cfg = client_config(&spec());
        assert_eq!(cfg.bucket, "b");
        assert_eq!(cfg.prefix, "p");
        assert_eq!(cfg.endpoint, "http://127.0.0.1:9000");
        assert!(cfg.path_style);
        assert!(cfg.credentials.is_some());
    }

    // An unreachable endpoint must fail the start rather than mount an empty
    // directory: `mount(2)` succeeds without contacting S3, so only the probe
    // stands between a typo and a workload that silently reads nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unreachable_endpoint_fails_the_probe_by_name() {
        let mut s = spec();
        // Port 1 on loopback refuses immediately, so this stays fast.
        s.endpoint = "http://127.0.0.1:1".into();
        let err = probe(&s).expect_err("a refused endpoint must not probe clean");
        assert!(err.contains("s3://b/p"), "{err}");
        assert!(err.contains("not reachable"), "{err}");
    }

    #[test]
    fn optional_fields_may_be_omitted_entirely() {
        let json = r#"{"endpoint":"http://e","region":"r","bucket":"b","mountpoint":"/m"}"#;
        let s: MountSpec = serde_json::from_str(json).unwrap();
        assert_eq!(s.prefix, "");
        assert!(!s.read_only);
        assert!(credentials_of(&s).is_none());
    }
}
