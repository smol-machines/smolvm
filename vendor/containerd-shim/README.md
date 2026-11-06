# Shim extension for containerd

[![Crates.io](https://img.shields.io/crates/v/containerd-shim)](https://crates.io/crates/containerd-shim)
[![docs.rs](https://img.shields.io/docsrs/containerd-shim)](https://docs.rs/containerd-shim/latest/containerd_shim/)
[![Crates.io](https://img.shields.io/crates/l/containerd-shim)](https://github.com/containerd/rust-extensions/blob/main/LICENSE)
[![CI](https://github.com/containerd/rust-extensions/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/containerd/rust-extensions/actions/workflows/ci.yml)

Rust crate to ease runtime v2 shim implementation.

It replicates same [shim.Run](https://github.com/containerd/containerd/blob/dbef1d56d7ebc05bc4553d72c419ed5ce025b05d/runtime/v2/example/cmd/main.go)
API offered by containerd's shim v2 runtime implementation written in Go.

## Runtime

Runtime v2 introduces a first class shim API for runtime authors to integrate with containerd.
The shim API is minimal and scoped to the execution lifecycle of a container.

This crate simplifies shim v2 runtime development for containerd. It handles common tasks such
as command line parsing, setting up shim's TTRPC server, logging, events, etc.

Clients are expected to implement [Shim] and [Task] traits with task handling routines.
This generally replicates same API as in Go [version](https://github.com/containerd/containerd/blob/main/core/runtime/v2/example/cmd/main.go).

Once implemented, shim's bootstrap code is as easy as:
```text
shim::run::<Service>("io.containerd.empty.v1")
```

## Look and feel

The API is very similar to the one offered by Go version:

```rust,no_run
use std::sync::Arc;

use async_trait::async_trait;
use containerd_shim::{
    asynchronous::{run, spawn, ExitSignal, Shim},
    publisher::RemotePublisher,
    Config, Error, Flags, StartOpts, TtrpcResult,
};
use containerd_shim_protos::{
    api, api::DeleteResponse, shim_async::Task, ttrpc::r#async::TtrpcContext,
};
use log::info;

#[derive(Clone)]
struct Service {
    exit: Arc<ExitSignal>,
}

#[async_trait]
impl Shim for Service {
    type T = Service;

    async fn new(_runtime_id: &str, _args: &Flags, _config: &mut Config) -> Self {
        Service {
            exit: Arc::new(ExitSignal::default()),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        let grouping = opts.id.clone();
        let address = spawn(opts, &grouping, Vec::new()).await?;
        Ok(address)
    }

    async fn delete_shim(&mut self) -> Result<DeleteResponse, Error> {
        Ok(DeleteResponse::new())
    }

    async fn wait(&mut self) {
        self.exit.wait().await;
    }

    async fn create_task_service(&self, _publisher: RemotePublisher) -> Self::T {
        self.clone()
    }
}

#[async_trait]
impl Task for Service {
    async fn connect(
        &self,
        _ctx: &TtrpcContext,
        _req: api::ConnectRequest,
    ) -> TtrpcResult<api::ConnectResponse> {
        info!("Connect request");
        Ok(api::ConnectResponse {
            version: String::from("example"),
            ..Default::default()
        })
    }

    async fn shutdown(
        &self,
        _ctx: &TtrpcContext,
        _req: api::ShutdownRequest,
    ) -> TtrpcResult<api::Empty> {
        info!("Shutdown request");
        self.exit.signal();
        Ok(api::Empty::default())
    }
}

#[tokio::main]
async fn main() {
    run::<Service>("io.containerd.empty.v1", None).await;
}

```

## How to use with containerd

**Note**: All operations are in the root directory of `rust-extensions`.

With shim v2 runtime:

```bash
$ cargo build --example skeleton
$ sudo cp ./target/debug/examples/skeleton /usr/local/bin/containerd-shim-skeleton-v1
$ sudo ctr run --rm --runtime io.containerd.skeleton.v1 -t docker.io/library/hello-world:latest hello
```

Or if on 1.6+

```bash
$ cargo build --example skeleton
$ sudo ctr run --rm --runtime ./target/debug/examples/skeleton docker.io/library/hello-world:latest hello
```

Or manually:

```bash
$ touch log

# Run containerd in background
$ sudo TTRPC_ADDRESS="/var/run/containerd/containerd.sock.ttrpc" \
    cargo run --example skeleton -- \
    -namespace default \
    -id 1234 \
    -address /var/run/containerd/containerd.sock \
    -publish-binary ./bin/containerd \
    start
unix:///var/run/containerd/eb8e7d1c48c2a1ec.sock

$ cargo build --example shim-proto-connect
$ sudo ./target/debug/examples/shim-proto-connect unix:///var/run/containerd/eb8e7d1c48c2a1ec.sock
Connecting to unix:///var/run/containerd/eb8e7d1c48c2a1ec.sock...
Sending `Connect` request...
Connect response: version: "example"
Sending `Shutdown` request...
Shutdown response: ""

$ cat log
[INFO] server listen started
[INFO] server started
[INFO] Shim successfully started, waiting for exit signal...
[INFO] Connect request
[INFO] Shutdown request
[INFO] Shutting down shim instance
[INFO] close monitor
[INFO] listener shutdown for quit flag
[INFO] ttrpc server listener stopped
[INFO] listener thread stopped
[INFO] begin to shutdown connection
[INFO] connections closed
[INFO] reaper thread exited
[INFO] reaper thread stopped
```

### Running on Windows
```powershell
# Run containerd in background
$env:TTRPC_ADDRESS="\\.\pipe\containerd-containerd.ttrpc"

$ cargo run --example skeleton -- -namespace default -id 1234 -address "\\.\pipe\containerd-containerd" start
\\.\pipe\containerd-shim-bc764c65e177434fcefe8257dc440be8b8acf7c96156320d965938f7e9ae1a35-pipe

# (Optional) Run the log collector in a separate command window
# note: log reader won't work if containerd is connected to the named pipe, this works when running manually to help debug locally
$ cargo run --example windows-log-reader \\.\pipe\containerd-shim-default-1234-log
Reading logs from: \\.\pipe\containerd-shim-default-1234-log
<logs will appear after next command>

$ cargo run --example shim-proto-connect \\.\pipe\containerd-shim-bc764c65e177434fcefe8257dc440be8b8acf7c96156320d965938f7e9ae1a35-pipe
Connecting to \\.\pipe\containerd-shim-bc764c65e177434fcefe8257dc440be8b8acf7c96156320d965938f7e9ae1a35-pipe...
Sending `Connect` request...
Connect response: version: "example"
Sending `Shutdown` request...
Shutdown response: ""
```

## Supported Platforms
Currently, following OSs and hardware architectures are supported, and more efforts are needed to enable and validate other OSs and architectures.
- Linux
- Mac OS
- Windows
