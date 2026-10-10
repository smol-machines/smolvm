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

use std::ffi::OsStr;

use crate::error::{Error, Result};

/// Flags to be passed from containerd daemon to a shim binary.
/// Reflects <https://github.com/containerd/containerd/blob/master/runtime/v2/shim/shim.go#L100>
#[derive(Debug, Default)]
pub struct Flags {
    /// Enable debug output in logs.
    pub debug: bool,
    /// Namespace that owns the shim.
    pub namespace: String,
    /// Id of the task.
    pub id: String,
    /// Abstract socket path to serve.
    pub socket: String,
    /// Path to the bundle if not workdir.
    pub bundle: String,
    /// GRPC address back to main containerd.
    pub address: String,
    /// Path to publish binary (used for publishing events).
    pub publish_binary: String,
    /// Shim action (start / delete).
    /// See <https://github.com/containerd/containerd/blob/master/runtime/v2/shim/shim.go#L191>
    pub action: String,
    /// Version of the shim.
    pub version: bool,
    /// get the option protobuf from stdin, print the shim info protobuf to stdout, and exit
    pub info: bool,
}

/// Parses command line arguments passed to the shim.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "Info"))]
pub fn parse<S: AsRef<OsStr>>(args: &[S]) -> Result<Flags> {
    let mut flags = Flags::default();

    let mut version_short = false;
    let mut version_long = false;
    let args: Vec<String> = go_flag::parse_args(args, |f| {
        f.add_flag("debug", &mut flags.debug);
        f.add_flag("v", &mut version_short);
        f.add_flag("version", &mut version_long);
        f.add_flag("namespace", &mut flags.namespace);
        f.add_flag("id", &mut flags.id);
        f.add_flag("socket", &mut flags.socket);
        f.add_flag("bundle", &mut flags.bundle);
        f.add_flag("address", &mut flags.address);
        f.add_flag("publish-binary", &mut flags.publish_binary);
        f.add_flag("info", &mut flags.info);
    })
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;

    flags.version = version_short || version_long;

    if let Some(action) = args.first() {
        flags.action = action.into();
    }

    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all() {
        let args = [
            "-debug",
            "-id",
            "123",
            "-namespace",
            "default",
            "-socket",
            "/path/to/socket",
            "-publish-binary",
            "/path/to/binary",
            "-bundle",
            "bundle",
            "-address",
            "address",
            "delete",
        ];

        let flags = parse(&args).unwrap();

        assert!(flags.debug);
        assert!(!flags.version);
        assert_eq!(flags.id, "123");
        assert_eq!(flags.namespace, "default");
        assert_eq!(flags.socket, "/path/to/socket");
        assert_eq!(flags.publish_binary, "/path/to/binary");
        assert_eq!(flags.bundle, "bundle");
        assert_eq!(flags.address, "address");
        assert_eq!(flags.action, "delete");
    }

    #[test]
    fn parse_flags() {
        let args = ["-id", "123", "-namespace", "default"];

        let flags = parse(&args).unwrap();

        assert!(!flags.debug);
        assert_eq!(flags.id, "123");
        assert_eq!(flags.namespace, "default");
        assert_eq!(flags.action, "");
    }

    #[test]
    fn parse_action() {
        let args = ["-namespace", "1", "start"];

        let flags = parse(&args).unwrap();
        assert_eq!(flags.action, "start");
        assert_eq!(flags.id, "");
    }

    #[test]
    fn parse_version_long_flag() {
        let flags = parse(&["-version"]).unwrap();
        assert!(flags.version);
    }

    #[test]
    fn parse_version_short_flag() {
        let flags = parse(&["-v"]).unwrap();
        assert!(flags.version);
    }
}
