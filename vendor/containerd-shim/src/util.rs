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

#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[cfg(feature = "async")]
pub use crate::asynchronous::util::*;
#[cfg(not(feature = "async"))]
pub use crate::synchronous::util::*;
use crate::{
    api::Options,
    error::Result,
    protos::protobuf::{
        well_known_types::{any::Any, timestamp::Timestamp},
        MessageDyn,
    },
};

pub const CONFIG_FILE_NAME: &str = "config.json";
pub const OPTIONS_FILE_NAME: &str = "options.json";
pub const RUNTIME_FILE_NAME: &str = "runtime";

// Define JsonOptions here for Json serialize and deserialize
// as rust-protobuf hasn't released serde_derive feature,
// see https://github.com/stepancheg/rust-protobuf/#serde_derive-support
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonOptions {
    #[serde(default)]
    pub no_pivot_root: bool,
    #[serde(default)]
    pub no_new_keyring: bool,
    pub shim_cgroup: ::std::string::String,
    #[serde(default)]
    pub io_uid: u32,
    #[serde(default)]
    pub io_gid: u32,
    pub binary_name: ::std::string::String,
    pub root: ::std::string::String,
    #[serde(default)]
    pub systemd_cgroup: bool,
    pub criu_image_path: ::std::string::String,
    pub criu_work_path: ::std::string::String,
    #[serde(default)]
    pub task_api_address: ::std::string::String,
    #[serde(default)]
    pub task_api_version: u32,
}

impl From<Options> for JsonOptions {
    fn from(o: Options) -> Self {
        Self {
            no_pivot_root: o.no_pivot_root,
            no_new_keyring: o.no_new_keyring,
            shim_cgroup: o.shim_cgroup,
            io_uid: o.io_uid,
            io_gid: o.io_gid,
            binary_name: o.binary_name,
            root: o.root,
            systemd_cgroup: o.systemd_cgroup,
            criu_image_path: o.criu_image_path,
            criu_work_path: o.criu_work_path,
            task_api_address: o.task_api_address,
            task_api_version: o.task_api_version,
        }
    }
}

impl From<JsonOptions> for Options {
    fn from(j: JsonOptions) -> Self {
        Self {
            no_pivot_root: j.no_pivot_root,
            no_new_keyring: j.no_new_keyring,
            shim_cgroup: j.shim_cgroup,
            io_uid: j.io_uid,
            io_gid: j.io_gid,
            binary_name: j.binary_name,
            root: j.root,
            systemd_cgroup: j.systemd_cgroup,
            criu_image_path: j.criu_image_path,
            criu_work_path: j.criu_work_path,
            task_api_address: j.task_api_address,
            task_api_version: j.task_api_version,
            ..Default::default()
        }
    }
}

#[cfg(unix)]
pub fn connect(address: impl AsRef<str>) -> Result<RawFd> {
    use std::os::fd::IntoRawFd;

    use nix::{sys::socket::*, unistd::close};

    let unix_addr = UnixAddr::new(address.as_ref())?;

    // SOCK_CLOEXEC flag is Linux specific
    #[cfg(target_os = "linux")]
    const SOCK_CLOEXEC: SockFlag = SockFlag::SOCK_CLOEXEC;

    #[cfg(not(target_os = "linux"))]
    const SOCK_CLOEXEC: SockFlag = SockFlag::empty();

    let fd = socket(AddressFamily::Unix, SockType::Stream, SOCK_CLOEXEC, None)?.into_raw_fd();

    // MacOS doesn't support atomic creation of a socket descriptor with `SOCK_CLOEXEC` flag,
    // so there is a chance of leak if fork + exec happens in between of these calls.
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::fd::BorrowedFd;

        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        // SAFETY: fd is a valid file descriptor that we just created
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
        fcntl(borrowed_fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).inspect_err(|_| {
            let _ = close(fd);
        })?;
    }

    connect(fd, &unix_addr).inspect_err(|_| {
        let _ = close(fd);
    })?;

    Ok(fd)
}

pub fn timestamp() -> Result<Timestamp> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;

    let ts = Timestamp {
        seconds: now.as_secs() as _,
        nanos: now.subsec_nanos() as _,
        ..Default::default()
    };

    Ok(ts)
}

pub fn convert_to_timestamp(exited_at: Option<OffsetDateTime>) -> Timestamp {
    let mut ts = Timestamp::new();
    if let Some(ea) = exited_at {
        ts.seconds = ea.unix_timestamp();
        ts.nanos = ea.nanosecond() as i32;
    }
    ts
}

pub fn convert_to_any(obj: Box<dyn MessageDyn>) -> Result<Any> {
    let mut data = Vec::new();
    obj.write_to_vec_dyn(&mut data)?;

    let mut any = Any::new();
    any.value = data;
    any.type_url = obj.descriptor_dyn().full_name().to_string();

    Ok(any)
}

pub trait IntoOption
where
    Self: Sized,
{
    fn none_if<F>(self, callback: F) -> Option<Self>
    where
        F: Fn(&Self) -> bool,
    {
        if callback(&self) {
            None
        } else {
            Some(self)
        }
    }
}

impl<T> IntoOption for T {}

pub trait AsOption {
    fn as_option(&self) -> Option<&Self>;
}

impl AsOption for str {
    fn as_option(&self) -> Option<&Self> {
        if self.is_empty() {
            None
        } else {
            Some(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp() {
        let ts = timestamp().unwrap();
        assert!(ts.seconds > 0);
    }
}
