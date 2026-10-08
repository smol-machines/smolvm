//! Mount an S3-compatible bucket as a POSIX filesystem.
//!
//! Self-contained by design: no libfuse, no `fusermount3`, no external binary,
//! and no async runtime. A privileged process can mount a bucket into any
//! filesystem — including a distroless or scratch container image, where no
//! helper could be installed.
//!
//! ```ignore
//! # use std::time::Duration;
//! use smolvm_s3fs::{mount, MountOptions, s3, sigv4};
//!
//! let cfg = s3::Config {
//!     endpoint: "https://s3.us-east-1.amazonaws.com".into(),
//!     region: "us-east-1".into(),
//!     bucket: "my-bucket".into(),
//!     prefix: String::new(),
//!     credentials: Some(sigv4::Credentials {
//!         access_key_id: "AKIA…".into(),
//!         secret_access_key: "…".into(),
//!         session_token: None,
//!     }),
//!     path_style: true,
//!     timeout: Duration::from_secs(30),
//! };
//! mount(cfg, MountOptions { mountpoint: "/mnt/data".into(), ..Default::default() })?;
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod fs;
pub mod fuse;
pub mod s3;
pub mod sigv4;

/// How to mount.
#[derive(Clone, Debug)]
pub struct MountOptions {
    pub mountpoint: String,
    pub read_only: bool,
    /// Let users other than the mounting one see the mount. Needed when the
    /// workload runs as a non-root user inside the container.
    pub allow_other: bool,
    /// Where in-flight writes are staged before upload.
    pub scratch_dir: std::path::PathBuf,
    /// How long lookups, misses and small files' bytes are trusted, here and
    /// by the kernel. A change made by another writer shows up within it;
    /// zero asks the bucket every time.
    pub cache_ttl: std::time::Duration,
    /// Requests served at once, so one slow request does not hold up others.
    pub workers: usize,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mountpoint: String::new(),
            read_only: false,
            allow_other: true,
            scratch_dir: std::path::PathBuf::from("/var/tmp/smolvm-s3fs"),
            cache_ttl: std::time::Duration::from_secs(10),
            workers: 8,
        }
    }
}

/// Mount and serve until unmounted. Blocks; callers run it on its own thread.
#[cfg(target_os = "linux")]
pub fn mount(cfg: s3::Config, opts: MountOptions) -> std::io::Result<()> {
    let client = s3::Client::new(cfg);
    let filesystem = fs::S3Fs::new(client, opts.read_only, opts.scratch_dir, opts.cache_ttl)?;
    let mut session = fuse::Session::mount(
        &opts.mountpoint,
        opts.read_only,
        opts.allow_other,
        opts.cache_ttl,
    )?;
    session.run(&filesystem, opts.workers.min(s3::MAX_IN_FLIGHT));
    Ok(())
}
