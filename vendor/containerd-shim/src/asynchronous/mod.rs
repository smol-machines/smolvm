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

use std::{
    env,
    io::Read,
    os::unix::{fs::FileTypeExt, net::UnixListener},
    path::Path,
    process::{self, Command as StdCommand, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{ready, Poll},
};

use async_trait::async_trait;
use containerd_shim_protos::{
    api::DeleteResponse,
    protobuf::{well_known_types::any::Any, Message, MessageField},
    shim::oci::Options,
    shim_async::{create_task, Client, Task},
    ttrpc::r#async::Server,
    types::introspection::{self, RuntimeInfo},
};
use futures::stream::{poll_fn, BoxStream, SelectAll, StreamExt};
use libc::{SIGCHLD, SIGINT, SIGPIPE, SIGTERM};
use log::{debug, error, info, warn};
use nix::{
    errno::Errno,
    sys::{
        signal::Signal,
        wait::{self, WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};
use oci_spec::runtime::Features;
use tokio::{io::AsyncWriteExt, process::Command, sync::Notify};
use which::which;

const DEFAULT_BINARY_NAME: &str = "runc";

use crate::{
    args,
    asynchronous::{monitor::monitor_notify_by_pid, publisher::RemotePublisher},
    error::{Error, Result},
    logger, parse_sockaddr, reap, socket_address,
    util::{asyncify, read_file_to_str, write_str_to_file},
    Config, Flags, StartOpts, TTRPC_ADDRESS,
};

pub mod monitor;
pub mod publisher;
pub mod util;

/// Asynchronous Main shim interface that must be implemented by all async shims.
///
/// Start and delete routines will be called to handle containerd's shim lifecycle requests.
#[async_trait]
pub trait Shim {
    /// Type to provide task service for the shim.
    type T: Task + Send + Sync;

    /// Create a new instance of  async Shim.
    ///
    /// # Arguments
    /// - `runtime_id`: identifier of the container runtime.
    /// - `id`: identifier of the shim/container, passed in from Containerd.
    /// - `namespace`: namespace of the shim/container, passed in from Containerd.
    /// - `config`: for the shim to pass back configuration information
    async fn new(runtime_id: &str, args: &Flags, config: &mut Config) -> Self;

    /// Start shim will be called by containerd when launching new shim instance.
    ///
    /// It expected to return TTRPC address containerd daemon can use to communicate with
    /// the given shim instance.
    /// See <https://github.com/containerd/containerd/tree/master/runtime/v2#start>
    /// this is an asynchronous call
    async fn start_shim(&mut self, opts: StartOpts) -> Result<String>;

    /// Delete shim will be called by containerd after shim shutdown to cleanup any leftovers.
    /// this is an asynchronous call
    async fn delete_shim(&mut self) -> Result<DeleteResponse>;

    /// Wait for the shim to exit asynchronously.
    async fn wait(&mut self);

    /// Create the task service object asynchronously.
    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T;
}

/// Async Shim entry point that must be invoked from tokio `main`.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
pub async fn run<T>(runtime_id: &str, opts: Option<Config>)
where
    T: Shim + Send + Sync + 'static,
{
    if let Some(err) = bootstrap::<T>(runtime_id, opts).await.err() {
        eprintln!("{}: {:?}", runtime_id, err);
        process::exit(1);
    }
}
/// get runtime info
pub fn run_info() -> Result<RuntimeInfo> {
    let mut info = introspection::RuntimeInfo {
        name: "containerd-shim-runc-v2-rs".to_string(),
        version: MessageField::some(introspection::RuntimeVersion {
            version: env!("CARGO_PKG_VERSION").to_string(),
            revision: String::default(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut binary_name = DEFAULT_BINARY_NAME.to_string();
    let mut data: Vec<u8> = Vec::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .map_err(io_error!(e, "read stdin"))?;
    // get BinaryName from stdin
    if !data.is_empty() {
        let opts =
            Any::parse_from_bytes(&data).and_then(|any| Options::parse_from_bytes(&any.value))?;
        if !opts.binary_name().is_empty() {
            binary_name = opts.binary_name().to_string();
        }
    }
    let binary_path = which(binary_name).unwrap();

    // get features
    let output = StdCommand::new(binary_path)
        .arg("features")
        .output()
        .unwrap();

    let features: Features = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))?;

    // set features
    let features_any = Any {
        type_url: "types.containerd.io/opencontainers/runtime-spec/1/features/Features".to_string(),
        // features to json
        value: serde_json::to_vec(&features)?,
        ..Default::default()
    };
    info.features = MessageField::some(features_any);

    Ok(info)
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
async fn bootstrap<T>(runtime_id: &str, opts: Option<Config>) -> Result<()>
where
    T: Shim + Send + Sync + 'static,
{
    // Parse command line
    let os_args: Vec<_> = env::args_os().collect();
    let flags = args::parse(&os_args[1..])?;

    let ttrpc_address = env::var(TTRPC_ADDRESS)?;
    // Create shim instance
    let mut config = opts.unwrap_or_default();

    // Setup signals
    let signals = setup_signals_tokio(&config);

    if !config.no_sub_reaper {
        reap::set_subreaper()?;
    }

    let mut shim = T::new(runtime_id, &flags, &mut config).await;

    match flags.action.as_str() {
        "start" => {
            let args = StartOpts {
                id: flags.id,
                publish_binary: flags.publish_binary,
                address: flags.address,
                ttrpc_address,
                namespace: flags.namespace,
                debug: flags.debug,
            };

            let address = shim.start_shim(args).await?;
            let mut stdout = tokio::io::stdout();
            stdout
                .write_all(address.as_bytes())
                .await
                .map_err(io_error!(e, "write stdout"))?;
            // containerd occasionally read an empty string without flushing the stdout
            stdout.flush().await.map_err(io_error!(e, "flush stdout"))?;
            Ok(())
        }
        "delete" => {
            tokio::spawn(async move {
                handle_signals(signals).await;
            });
            let response = shim.delete_shim().await?;
            let resp_bytes = response.write_to_bytes()?;
            tokio::io::stdout()
                .write_all(resp_bytes.as_slice())
                .await
                .map_err(io_error!(e, "failed to write response"))?;

            Ok(())
        }
        _ => {
            if flags.socket.is_empty() {
                return Err(Error::InvalidArgument(String::from(
                    "Shim socket cannot be empty",
                )));
            }

            if !config.no_setup_logger {
                logger::init(
                    flags.debug,
                    &config.default_log_level,
                    &flags.namespace,
                    &flags.id,
                )?;
            }

            let publisher = RemotePublisher::new(&ttrpc_address).await?;
            let task = Box::new(shim.create_task_service(publisher).await)
                as Box<dyn containerd_shim_protos::shim_async::Task + Send + Sync>;
            let task_service = create_task(Arc::from(task));
            let Some(mut server) = create_server_with_retry(&flags).await? else {
                signal_server_started();
                return Ok(());
            };
            server = server.register_service(task_service);
            server.start().await?;

            signal_server_started();

            info!("Shim successfully started, waiting for exit signal...");
            tokio::spawn(async move {
                handle_signals(signals).await;
            });
            shim.wait().await;

            info!("Shutting down shim instance");
            server.shutdown().await.unwrap_or_default();

            // NOTE: If the shim server is down(like oom killer), the address
            // socket might be leaking.
            if let Ok(address) = read_file_to_str("address").await {
                remove_socket_silently(&address).await;
            }
            Ok(())
        }
    }
}

/// Helper structure that wraps atomic bool to signal shim server when to shutdown the TTRPC server.
///
/// Shim implementations are responsible for calling [`Self::signal`].
pub struct ExitSignal {
    notifier: Notify,
    exited: AtomicBool,
}

impl Default for ExitSignal {
    fn default() -> Self {
        ExitSignal {
            notifier: Notify::new(),
            exited: AtomicBool::new(false),
        }
    }
}

impl ExitSignal {
    /// Set exit signal to shutdown shim server.
    pub fn signal(&self) {
        self.exited.store(true, Ordering::SeqCst);
        self.notifier.notify_waiters();
    }

    /// Wait for the exit signal to be set.
    pub async fn wait(&self) {
        loop {
            let notified = self.notifier.notified();
            if self.exited.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// Spawn is a helper func to launch shim process asynchronously.
/// Typically this expected to be called from `StartShim`.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
pub async fn spawn(opts: StartOpts, grouping: &str, vars: Vec<(&str, &str)>) -> Result<String> {
    let cmd = env::current_exe().map_err(io_error!(e, ""))?;
    let cwd = env::current_dir().map_err(io_error!(e, ""))?;
    let address = socket_address(&opts.address, &opts.namespace, grouping);

    // Activation pattern comes from the hcsshim: https://github.com/microsoft/hcsshim/blob/v0.10.0-rc.7/cmd/containerd-shim-runhcs-v1/serve.go#L57-L70
    // another way to do it would to create named pipe and pass it to the child process through handle inheritence but that would require duplicating
    // the logic in Rust's 'command' for process creation.  There is an  issue in Rust to make it simplier to specify handle inheritence and this could
    // be revisited once https://github.com/rust-lang/rust/issues/54760 is implemented.

    let mut command = Command::new(cmd);
    command
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .envs(vars)
        .args([
            "-namespace",
            &opts.namespace,
            "-id",
            &opts.id,
            "-address",
            &opts.address,
            "-socket",
            &address,
        ]);

    if opts.debug {
        command.arg("-debug");
    }

    let mut child = command.spawn().map_err(io_error!(e, "spawn shim"))?;

    #[cfg(target_os = "linux")]
    crate::cgroup::set_cgroup_and_oom_score(child.id().unwrap())?;

    let mut reader = child.stdout.take().unwrap();
    tokio::io::copy(&mut reader, &mut tokio::io::stderr())
        .await
        .unwrap();

    Ok(address)
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
async fn create_server(flags: &args::Flags) -> Result<Server> {
    use containerd_shim_protos::ttrpc::r#async::transport::Listener;
    let listener = start_listener(&flags.socket).await?;
    let listener = Listener::try_from(listener).map_err(io_error!(e, "creating ttrpc listener"))?;
    let server = Server::new().add_listener(listener);
    Ok(server)
}

async fn create_server_with_retry(flags: &args::Flags) -> Result<Option<Server>> {
    // Really try to create a server.
    let server = match create_server(flags).await {
        Ok(server) => server,
        Err(Error::IoError { err, .. }) if err.kind() == std::io::ErrorKind::AddrInUse => {
            // If the address is already in use then make sure it is up and running and return the address
            // This allows for running a single shim per container scenarios
            if let Ok(()) = wait_socket_working(&flags.socket, 5, 200).await {
                write_str_to_file("address", &flags.socket).await?;
                return Ok(None);
            }
            remove_socket(&flags.socket).await?;
            create_server(flags).await?
        }
        Err(e) => return Err(e),
    };

    Ok(Some(server))
}

fn signal_server_started() {
    use libc::{dup2, STDERR_FILENO, STDOUT_FILENO};

    unsafe {
        if dup2(STDERR_FILENO, STDOUT_FILENO) < 0 {
            panic!("Error closing pipe: {}", std::io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
fn signal_stream(kind: i32) -> std::io::Result<BoxStream<'static, i32>> {
    use tokio::signal::unix::{signal, SignalKind};
    let kind = SignalKind::from_raw(kind);
    signal(kind).map(|mut sig| {
        // The object returned by `signal` is not a `Stream`.
        // The `poll_fn` function constructs a `Stream` based on a polling function.
        // We need to create a `Stream` so that we can use the `SelectAll` stream "merge"
        // all the signal streams.
        poll_fn(move |cx| {
            ready!(sig.poll_recv(cx));
            Poll::Ready(Some(kind.as_raw_value()))
        })
        .boxed()
    })
}

#[cfg(windows)]
fn signal_stream(kind: i32) -> std::io::Result<BoxStream<'static, i32>> {
    use tokio::signal::windows::ctrl_c;

    // Windows doesn't have similar signal like SIGCHLD
    // We could implement something if required but for now
    // just implement support for SIGINT
    if kind != SIGINT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Invalid signal {kind}"),
        ));
    }

    ctrl_c().map(|mut sig| {
        // The object returned by `signal` is not a `Stream`.
        // The `poll_fn` function constructs a `Stream` based on a polling function.
        // We need to create a `Stream` so that we can use the `SelectAll` stream "merge"
        // all the signal streams.
        poll_fn(move |cx| {
            ready!(sig.poll_recv(cx));
            Poll::Ready(Some(kind))
        })
        .boxed()
    })
}

type Signals = SelectAll<BoxStream<'static, i32>>;

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
fn setup_signals_tokio(config: &Config) -> Signals {
    #[cfg(unix)]
    let signals: &[i32] = if config.no_reaper {
        &[SIGTERM, SIGINT, SIGPIPE]
    } else {
        &[SIGTERM, SIGINT, SIGPIPE, SIGCHLD]
    };

    // Windows doesn't have similar signal like SIGCHLD
    // We could implement something if required but for now
    // just listen for SIGINT
    // Note: see comment at the counterpart in synchronous/mod.rs for details.
    #[cfg(windows)]
    let signals: &[i32] = &[SIGINT];

    let signals: Vec<_> = signals
        .iter()
        .copied()
        .map(signal_stream)
        .collect::<std::io::Result<_>>()
        .expect("signal setup failed");

    SelectAll::from_iter(signals)
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
async fn handle_signals(signals: Signals) {
    let mut signals = signals.fuse();
    while let Some(sig) = signals.next().await {
        match sig {
            SIGPIPE => {}
            SIGTERM | SIGINT => {
                debug!("received {}", sig);
            }
            SIGCHLD => loop {
                // Note: see comment at the counterpart in synchronous/mod.rs for details.
                match wait::waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, status)) => {
                        monitor_notify_by_pid(pid.as_raw(), status)
                            .await
                            .unwrap_or_else(|e| error!("failed to send exit event {}", e))
                    }
                    Ok(WaitStatus::Signaled(pid, sig, _)) => {
                        debug!("child {} terminated({})", pid, sig);
                        let exit_code = 128 + sig as i32;
                        monitor_notify_by_pid(pid.as_raw(), exit_code)
                            .await
                            .unwrap_or_else(|e| error!("failed to send signal event {}", e))
                    }
                    Ok(WaitStatus::StillAlive) => {
                        break;
                    }
                    Err(Errno::ECHILD) => {
                        break;
                    }
                    Err(e) => {
                        warn!("error occurred in signal handler: {}", e);
                    }
                    _ => {}
                }
            },
            _ => {
                if let Ok(sig) = Signal::try_from(sig) {
                    debug!("received {}", sig);
                } else {
                    warn!("received invalid signal {}", sig);
                }
            }
        }
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
async fn remove_socket_silently(address: &str) {
    remove_socket(address)
        .await
        .unwrap_or_else(|e| warn!("failed to remove socket: {}", e))
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
async fn remove_socket(address: &str) -> Result<()> {
    let path = parse_sockaddr(address);
    if let Ok(md) = Path::new(path).metadata() {
        if md.file_type().is_socket() {
            tokio::fs::remove_file(path).await.map_err(io_error!(
                e,
                "failed to remove socket {}",
                address
            ))?;
        }
    }
    Ok(())
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
async fn start_listener(address: &str) -> Result<UnixListener> {
    let addr = address.to_string();
    asyncify(move || -> Result<UnixListener> {
        crate::start_listener(&addr).map_err(|e| Error::IoError {
            context: format!("failed to start listener {}", addr),
            err: e,
        })
    })
    .await
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
async fn wait_socket_working(address: &str, interval_in_ms: u64, count: u32) -> Result<()> {
    for _i in 0..count {
        match Client::connect(address).await {
            Ok(_) => {
                return Ok(());
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(interval_in_ms)).await;
            }
        }
    }
    Err(other!("time out waiting for socket {}", address))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::asynchronous::{start_listener, ExitSignal};

    #[tokio::test]
    async fn test_exit_signal() {
        let signal = Arc::new(ExitSignal::default());

        let cloned = signal.clone();
        let handle = tokio::spawn(async move {
            cloned.wait().await;
        });

        signal.signal();

        if let Err(err) = handle.await {
            panic!("{:?}", err);
        }
    }

    #[tokio::test]
    async fn test_start_listener() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().to_str().unwrap().to_owned();

        let socket = path + "/ns1/id1/socket";
        let _listener = start_listener(&socket).await.unwrap();
        let _listener2 = start_listener(&socket)
            .await
            .expect_err("socket should already in use");

        let socket2 = socket + "/socket";
        assert!(start_listener(&socket2).await.is_err());

        let path = tmpdir.path().to_str().unwrap().to_owned();
        let txt_file = path + "/demo.txt";
        tokio::fs::write(&txt_file, "test").await.unwrap();
        assert!(start_listener(&txt_file).await.is_err());
        let context = tokio::fs::read_to_string(&txt_file).await.unwrap();
        assert_eq!(context, "test");
    }
}
