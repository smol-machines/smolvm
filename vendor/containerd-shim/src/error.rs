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

use thiserror::Error;

use crate::{
    monitor::ExitEvent,
    protos::{protobuf, ttrpc},
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid command line arguments.
    #[error("Failed to parse command line: {0}")]
    InvalidArgument(String),

    /// TTRPC specific error.
    #[error("TTRPC error: {0}")]
    Ttrpc(#[from] ttrpc::Error),

    #[error("Protobuf error: {0}")]
    Protobuf(#[from] protobuf::Error),

    #[error("{context} error: {err}")]
    IoError {
        context: String,
        #[source]
        err: std::io::Error,
    },

    #[error("Env error: {0}")]
    Env(#[from] std::env::VarError),

    #[error("Failed to setup logger: {0}")]
    Setup(#[from] log::SetLoggerError),

    #[cfg(unix)]
    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error),

    #[error("Failed to get envelope timestamp: {0}")]
    Timestamp(#[from] std::time::SystemTimeError),

    #[error("Not Found: {0}")]
    NotFoundError(String),

    #[error("Failed pre condition: {0}")]
    FailedPreconditionError(String),

    #[cfg(unix)]
    #[error("{context} error: {err}")]
    MountError {
        context: String,
        #[source]
        err: nix::Error,
    },

    #[error("Failed to convert json object: {0}")]
    JSON(#[from] serde_json::Error),

    #[error("Failed to parse integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("Failed to send exit event: {0}")]
    Send(#[from] std::sync::mpsc::SendError<ExitEvent>),

    #[error("Deadline exceeded: {0}")]
    DeadlineExceeded(String),

    #[error("Other: {0}")]
    Other(String),

    #[error("Unimplemented method: {0}")]
    Unimplemented(String),
}

impl From<Error> for ttrpc::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidArgument(ref s) => {
                ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::INVALID_ARGUMENT, s))
            }
            Error::NotFoundError(ref s) => {
                ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::NOT_FOUND, s))
            }
            Error::FailedPreconditionError(ref s) => {
                ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::FAILED_PRECONDITION, s))
            }
            Error::Ttrpc(e) => e,
            _ => ttrpc::Error::Others(e.to_string()),
        }
    }
}

#[macro_export]
macro_rules! io_error {
    ($e:ident, $($args:tt)+) => {
        |$e| Error::IoError {
            context: format_args!($($args)+).to_string(),
            err: $e,
        }
    };
}

#[macro_export]
macro_rules! mount_error {
    ($e:ident, $($args:tt)+) => {
        |$e| Error::MountError {
            context: format_args!($($args)+).to_string(),
            err: $e,
        }
    };
}

#[macro_export]
macro_rules! other {
    ($($args:tt)*) => {
        Error::Other(format_args!($($args)*).to_string())
    };
}

#[macro_export]
macro_rules! other_error {
    ($s:expr) => {
        |e| Error::Other(format!("{}: {}", $s, e))
    };
}
