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
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mountpoint: String::new(),
            read_only: false,
            allow_other: true,
            scratch_dir: std::path::PathBuf::from("/var/tmp/smolvm-s3fs"),
        }
    }
}

/// Mount and serve until unmounted. Blocks; callers run it on its own thread.
#[cfg(target_os = "linux")]
pub fn mount(cfg: s3::Config, opts: MountOptions) -> std::io::Result<()> {
    let client = s3::Client::new(cfg);
    let filesystem = fs::S3Fs::new(client, opts.read_only, opts.scratch_dir)?;
    let mut session = fuse::Session::mount(&opts.mountpoint, opts.read_only, opts.allow_other)?;
    session.run(&filesystem);
    Ok(())
}
