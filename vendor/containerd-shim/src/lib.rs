/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#![cfg_attr(feature = "docs", doc = include_str!("../README.md"))]

use std::{fs::File, path::PathBuf};
#[cfg(windows)]
use std::{fs::OpenOptions, os::windows::prelude::OpenOptionsExt};
#[cfg(unix)]
use std::{os::unix::net::UnixListener, path::Path};

pub use containerd_shim_protos as protos;
pub use protos::{
    shim::shim::DeleteResponse,
    ttrpc::{context::Context, Result as TtrpcResult},
};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

#[cfg(feature = "async")]
pub use crate::asynchronous::*;
pub use crate::error::{Error, Result};
#[cfg(not(feature = "async"))]
pub use crate::synchronous::*;

#[macro_use]
pub mod error;

mod args;
pub use args::{parse, Flags};
#[cfg(feature = "async")]
pub mod asynchronous;
pub mod cgroup;
pub mod event;
pub mod logger;
pub mod monitor;
#[cfg(target_os = "linux")]
pub mod mount_linux;
#[cfg(not(target_os = "linux"))]
pub mod mount_other;
#[cfg(target_os = "linux")]
pub use mount_linux as mount;
#[cfg(not(target_os = "linux"))]
pub use mount_other as mount;
mod reap;
#[cfg(not(feature = "async"))]
pub mod synchronous;
pub mod util;

/// Generated request/response structures.
pub mod api {
    pub use super::protos::{
        api::Status,
        shim::{oci::Options, shim::*},
        types::empty::Empty,
    };
}

macro_rules! cfg_not_async {
    ($($item:item)*) => {
        $(
            #[cfg(not(feature = "async"))]
            #[cfg_attr(docsrs, doc(cfg(not(feature = "async"))))]
            $item
        )*
    }
}

macro_rules! cfg_async {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "async")]
            #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
            $item
        )*
    }
}

cfg_not_async! {
    pub use crate::synchronous::publisher;
    pub use protos::shim::shim_ttrpc::Task;
    pub use protos::ttrpc::TtrpcContext;
}

cfg_async! {
    pub use crate::asynchronous::publisher;
    pub use protos::shim_async::Task;
    pub use protos::ttrpc::r#async::TtrpcContext;
}

const TTRPC_ADDRESS: &str = "TTRPC_ADDRESS";

/// Config of shim binary options provided by shim implementations
#[derive(Debug)]
pub struct Config {
    /// Disables automatic configuration of logrus to use the shim FIFO
    pub no_setup_logger: bool,
    // Sets the the default log level. Default is info
    pub default_log_level: String,
    /// Disables the shim binary from reaping any child process implicitly
    pub no_reaper: bool,
    /// Disables setting the shim as a child subreaper.
    pub no_sub_reaper: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            no_setup_logger: false,
            default_log_level: "info".to_string(),
            no_reaper: false,
            no_sub_reaper: false,
        }
    }
}

/// Startup options received from containerd to start new shim instance.
///
/// These will be passed via [`Shim::start_shim`] to shim.
#[derive(Debug, Default)]
pub struct StartOpts {
    /// ID of the container.
    pub id: String,
    /// Binary path to publish events back to containerd.
    pub publish_binary: String,
    /// Address of the containerd's main socket.
    pub address: String,
    /// TTRPC socket address.
    pub ttrpc_address: String,
    /// Namespace for the container.
    pub namespace: String,

    pub debug: bool,
}

#[cfg(target_os = "linux")]
pub const SOCKET_ROOT: &str = "/run/containerd";

#[cfg(target_os = "macos")]
pub const SOCKET_ROOT: &str = "/var/run/containerd";

#[cfg(target_os = "windows")]
pub const SOCKET_ROOT: &str = r"\\.\pipe\containerd-containerd";

/// Make socket path from containerd socket path, namespace and id.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "Info"))]
pub fn socket_address(socket_path: &str, namespace: &str, id: &str) -> String {
    let path = PathBuf::from(socket_path)
        .join(namespace)
        .join(id)
        .display()
        .to_string();
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(path);
        hasher.finalize()
    };
    if cfg!(unix) {
        format!("unix://{}/s/{:x}", SOCKET_ROOT, hash)
    } else if cfg!(windows) {
        format!(r"\\.\pipe\containerd-shim-{:x}-pipe", hash)
    } else {
        panic!("unsupported platform")
    }
}

#[cfg(unix)]
fn parse_sockaddr(addr: &str) -> &str {
    if let Some(addr) = addr.strip_prefix("unix://") {
        return addr;
    }

    if let Some(addr) = addr.strip_prefix("vsock://") {
        return addr;
    }

    addr
}

#[cfg(windows)]
fn start_listener(address: &str) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OVERLAPPED);
    if let Ok(f) = opts.open(address) {
        info!("found existing named pipe: {}", address);
        drop(f);
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "address already exists",
        ));
    }

    // windows starts the listener on the second invocation of the shim
    Ok(())
}

#[cfg(unix)]
fn start_listener(address: &str) -> std::io::Result<UnixListener> {
    let path = parse_sockaddr(address);
    // Try to create the needed directory hierarchy.
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    UnixListener::bind(path)
}

pub struct Console {
    pub file: File,
}

#[cfg(test)]
mod tests {
    use crate::start_listener;

    #[test]
    #[cfg(unix)]
    fn test_start_listener() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().to_str().unwrap().to_owned();

        // A little dangerous, may be turned on under controlled environment.
        //assert!(start_listener("/").is_err());
        //assert!(start_listener("/tmp").is_err());

        let socket = path + "/ns1/id1/socket";
        let _listener = start_listener(&socket).unwrap();
        let _listener2 = start_listener(&socket).expect_err("socket should already in use");

        let socket2 = socket + "/socket";
        assert!(start_listener(&socket2).is_err());

        let path = tmpdir.path().to_str().unwrap().to_owned();
        let txt_file = path + "demo.txt";
        std::fs::write(&txt_file, "test").unwrap();
        assert!(start_listener(&txt_file).is_err());
        let context = std::fs::read_to_string(&txt_file).unwrap();
        assert_eq!(context, "test");
    }

    #[test]
    #[cfg(windows)]
    fn test_start_listener_windows() {
        use mio::windows::NamedPipe;

        let named_pipe = "\\\\.\\pipe\\test-pipe-duplicate".to_string();

        start_listener(&named_pipe).unwrap();
        let _pipe_server = NamedPipe::new(named_pipe.clone()).unwrap();
        start_listener(&named_pipe).expect_err("address already exists");
    }
}
