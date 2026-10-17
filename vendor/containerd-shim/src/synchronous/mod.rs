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

//! A library to implement custom runtime v2 shims for containerd.
//!
//! # Runtime
//! Runtime v2 introduces a first class shim API for runtime authors to integrate with containerd.
//! The shim API is minimal and scoped to the execution lifecycle of a container.
//!
//! This crate simplifies shim v2 runtime development for containerd. It handles common tasks such
//! as command line parsing, setting up shim's TTRPC server, logging, events, etc.
//!
//! Clients are expected to implement [Shim] and [Task] traits with task handling routines.
//! This generally replicates same API as in Go [version](https://github.com/containerd/containerd/blob/main/runtime/v2/example/cmd/main.go).
//!
//! Once implemented, shim's bootstrap code is as easy as:
//! ```text
//! shim::run::<Service>("io.containerd.empty.v1")
//! ```
//!

macro_rules! cfg_unix {
    ($($item:item)*) => {
        $(
            #[cfg(unix)]
            $item
        )*
    }
}

macro_rules! cfg_windows {
    ($($item:item)*) => {
        $(
            #[cfg(windows)]
            $item
        )*
    }
}

use std::{
    env,
    io::Write,
    process::{self, Command, Stdio},
    sync::{Arc, Condvar, Mutex},
};

pub use log::{debug, error, info, warn};
use util::{read_address, write_address};

use crate::{
    api::DeleteResponse,
    args::{self, Flags},
    logger,
    protos::{
        protobuf::Message,
        shim::shim_ttrpc::{create_task, Task},
        ttrpc::{Client, Server},
    },
    reap, socket_address, start_listener,
    synchronous::publisher::RemotePublisher,
    Config, Error, Result, StartOpts, TTRPC_ADDRESS,
};

cfg_unix! {
    use crate::parse_sockaddr;
    use libc::{SIGCHLD, SIGINT, SIGPIPE, SIGTERM};
    use nix::{
        errno::Errno,
        sys::{
            signal::Signal,
            wait::{self, WaitPidFlag, WaitStatus},
        },
        unistd::Pid,
    };
    use signal_hook::iterator::Signals;
    use std::os::unix::fs::FileTypeExt;
    use std::{convert::TryFrom, fs, path::Path};
}

cfg_windows! {
    use std::{
        io, ptr,
        fs::OpenOptions,
        os::windows::prelude::{AsRawHandle, OpenOptionsExt},
    };

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Console::SetConsoleCtrlHandler,
            Threading::{CreateSemaphoreA, ReleaseSemaphore, WaitForSingleObject, INFINITE},
        },
        Storage::FileSystem::FILE_FLAG_OVERLAPPED
    };

    static mut SEMAPHORE: HANDLE = 0 as HANDLE;
    const MAX_SEM_COUNT: i32 = 255;
}

pub mod monitor;
pub mod publisher;
pub mod util;

/// Helper structure that wraps atomic bool to signal shim server when to shutdown the TTRPC server.
///
/// Shim implementations are responsible for calling [`Self::signal`].
#[allow(clippy::mutex_atomic)] // Condvar expected to be used with Mutex, not AtomicBool.
#[derive(Default)]
pub struct ExitSignal(Mutex<bool>, Condvar);

// Wrapper type to help hide platform specific signal handling.
struct AppSignals {
    #[cfg(unix)]
    signals: Signals,
}

#[allow(clippy::mutex_atomic)]
impl ExitSignal {
    /// Set exit signal to shutdown shim server.
    pub fn signal(&self) {
        let (lock, cvar) = (&self.0, &self.1);
        let mut exit = lock.lock().unwrap();
        *exit = true;
        cvar.notify_all();
    }

    /// Wait for the exit signal to be set.
    pub fn wait(&self) {
        let (lock, cvar) = (&self.0, &self.1);
        let mut started = lock.lock().unwrap();
        while !*started {
            started = cvar.wait(started).unwrap();
        }
    }
}

/// Main shim interface that must be implemented by all shims.
///
/// Start and delete routines will be called to handle containerd's shim lifecycle requests.
pub trait Shim {
    /// Type to provide task service for the shim.
    type T: Task + Send + Sync;

    /// Create a new instance of Shim.
    ///
    /// # Arguments
    /// - `runtime_id`: identifier of the container runtime.
    /// - `args`: command line arguments passed to the shim which includes namespace and id
    /// - `config`: for the shim to pass back configuration information
    fn new(runtime_id: &str, args: &Flags, config: &mut Config) -> Self;

    /// Start shim will be called by containerd when launching new shim instance.
    ///
    /// It expected to return TTRPC address containerd daemon can use to communicate with
    /// the given shim instance.
    ///
    /// See <https://github.com/containerd/containerd/tree/master/runtime/v2#start>
    fn start_shim(&mut self, opts: StartOpts) -> Result<String>;

    /// Delete shim will be called by containerd after shim shutdown to cleanup any leftovers.
    fn delete_shim(&mut self) -> Result<DeleteResponse>;

    /// Wait for the shim to exit.
    fn wait(&mut self);

    /// Create the task service object.
    fn create_task_service(&self, publisher: RemotePublisher) -> Self::T;
}

/// Shim entry point that must be invoked from `main`.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
pub fn run<T>(runtime_id: &str, opts: Option<Config>)
where
    T: Shim + Send + Sync + 'static,
{
    if let Some(err) = bootstrap::<T>(runtime_id, opts).err() {
        eprintln!("{}: {:?}", runtime_id, err);
        process::exit(1);
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn bootstrap<T>(runtime_id: &str, opts: Option<Config>) -> Result<()>
where
    T: Shim + Send + Sync + 'static,
{
    // Parse command line
    let os_args: Vec<_> = env::args_os().collect();
    let flags = args::parse(&os_args[1..])?;

    if flags.namespace.is_empty() {
        return Err(Error::InvalidArgument(String::from(
            "Shim namespace cannot be empty",
        )));
    }

    let ttrpc_address = env::var(TTRPC_ADDRESS)?;

    // Create shim instance
    let mut config = opts.unwrap_or_default();

    // Setup signals (On Linux need register signals before start main app according to signal_hook docs)
    let signals = setup_signals(&config);

    if !config.no_sub_reaper {
        reap::set_subreaper()?;
    }

    let mut shim = T::new(runtime_id, &flags, &mut config);

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

            let address = shim.start_shim(args)?;

            std::io::stdout()
                .lock()
                .write_fmt(format_args!("{}", address))
                .map_err(io_error!(e, "write stdout"))?;

            Ok(())
        }
        "delete" => {
            std::thread::spawn(move || handle_signals(signals));
            let response = shim.delete_shim()?;
            let stdout = std::io::stdout();
            let mut locked = stdout.lock();
            response.write_to_writer(&mut locked)?;

            Ok(())
        }
        _ => {
            if flags.socket.is_empty() {
                return Err(Error::InvalidArgument(String::from(
                    "Shim socket cannot be empty",
                )));
            }

            #[cfg(windows)]
            util::setup_debugger_event();

            if !config.no_setup_logger {
                logger::init(
                    flags.debug,
                    &config.default_log_level,
                    &flags.namespace,
                    &flags.id,
                )?;
            }

            let publisher = publisher::RemotePublisher::new(&ttrpc_address)?;
            let task = Box::new(shim.create_task_service(publisher))
                as Box<dyn containerd_shim_protos::Task + Send + Sync + 'static>;
            let task_service = create_task(Arc::from(task));
            let Some(mut server) = create_server_with_retry(&flags)? else {
                signal_server_started();
                return Ok(());
            };
            server = server.register_service(task_service);
            server.start()?;

            signal_server_started();

            info!("Shim successfully started, waiting for exit signal...");
            #[cfg(unix)]
            std::thread::spawn(move || handle_signals(signals));
            shim.wait();

            info!("Shutting down shim instance");
            server.shutdown();

            // NOTE: If the shim server is down(like oom killer), the address
            // socket might be leaking.
            let address = read_address()?;
            remove_socket_silently(&address);
            Ok(())
        }
    }
}

#[cfg(windows)]
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
fn create_server(flags: &args::Flags) -> Result<Server> {
    start_listener(&flags.socket).map_err(io_error!(e, "starting listener"))?;
    let mut server = Server::new();
    server = server.bind(&flags.socket)?;
    Ok(server)
}

#[cfg(unix)]
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
fn create_server(flags: &args::Flags) -> Result<Server> {
    use std::os::fd::IntoRawFd;
    let listener = start_listener(&flags.socket).map_err(io_error!(e, "starting listener"))?;
    let mut server = Server::new();
    server = server.add_listener(listener.into_raw_fd())?;
    Ok(server)
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
fn create_server_with_retry(flags: &args::Flags) -> Result<Option<Server>> {
    // Really try to create a server.
    let server = match create_server(flags) {
        Ok(server) => server,
        Err(Error::IoError { err, .. }) if err.kind() == std::io::ErrorKind::AddrInUse => {
            // If the address is already in use then make sure it is up and running and return the address
            // This allows for running a single shim per container scenarios
            if let Ok(()) = wait_socket_working(&flags.socket, 5, 200) {
                write_address(&flags.socket)?;
                return Ok(None);
            }
            remove_socket(&flags.socket)?;
            create_server(flags)?
        }
        Err(e) => return Err(e),
    };

    Ok(Some(server))
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
fn setup_signals(_config: &Config) -> Option<AppSignals> {
    #[cfg(unix)]
    {
        let signals = Signals::new([SIGTERM, SIGINT, SIGPIPE]).expect("new signal failed");
        if !_config.no_reaper {
            signals.add_signal(SIGCHLD).expect("add signal failed");
        }
        Some(AppSignals { signals })
    }

    #[cfg(windows)]
    {
        unsafe {
            SEMAPHORE = CreateSemaphoreA(ptr::null_mut(), 0, MAX_SEM_COUNT, ptr::null());
            if SEMAPHORE == 0 {
                panic!("Failed to create semaphore: {}", io::Error::last_os_error());
            }

            if SetConsoleCtrlHandler(Some(signal_handler), 1) == 0 {
                let e = io::Error::last_os_error();
                CloseHandle(SEMAPHORE);
                SEMAPHORE = 0 as HANDLE;
                panic!("Failed to set console handler: {}", e);
            }
        }
        None
    }
}

#[cfg(windows)]
unsafe extern "system" fn signal_handler(_: u32) -> i32 {
    ReleaseSemaphore(SEMAPHORE, 1, ptr::null_mut());
    1
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, level = "info"))]
fn handle_signals(mut _signals: Option<AppSignals>) {
    #[cfg(unix)]
    {
        let mut app_signals = _signals.take().unwrap();
        loop {
            for sig in app_signals.signals.wait() {
                match sig {
                    SIGTERM | SIGINT => {
                        debug!("received {}", sig);
                    }
                    SIGCHLD => loop {
                        // Note that this thread sticks to child even it is suspended.
                        match wait::waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::Exited(pid, status)) => {
                                monitor::monitor_notify_by_pid(pid.as_raw(), status)
                                    .unwrap_or_else(|e| error!("failed to send exit event {}", e))
                            }
                            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                                debug!("child {} terminated({})", pid, sig);
                                let exit_code = 128 + sig as i32;
                                monitor::monitor_notify_by_pid(pid.as_raw(), exit_code)
                                    .unwrap_or_else(|e| error!("failed to send signal event {}", e))
                            }
                            Ok(WaitStatus::StillAlive) => {
                                break;
                            }
                            Err(Errno::ECHILD) => {
                                break;
                            }
                            Err(e) => {
                                // stick until all children will be successfully waited, even some unexpected error occurs.
                                warn!("error occurred in signal handler: {}", e);
                            }
                            _ => {} // stick until exit
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
    }

    #[cfg(windows)]
    {
        // must start on thread as waitforSingleObject puts the current thread to sleep
        loop {
            unsafe {
                WaitForSingleObject(SEMAPHORE, INFINITE);
                //Windows doesn't have similar signal like SIGCHLD
                // We could implement something if required but for now
            }
        }
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn wait_socket_working(address: &str, interval_in_ms: u64, count: u32) -> Result<()> {
    for _i in 0..count {
        match Client::connect(address) {
            Ok(_) => {
                return Ok(());
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(interval_in_ms));
            }
        }
    }
    Err(other!("time out waiting for socket {}", address))
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn remove_socket_silently(address: &str) {
    remove_socket(address).unwrap_or_else(|e| warn!("failed to remove file {} {:?}", address, e))
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn remove_socket(address: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let path = parse_sockaddr(address);
        if let Ok(md) = Path::new(path).metadata() {
            if md.file_type().is_socket() {
                fs::remove_file(path).map_err(io_error!(e, "remove socket"))?;
            }
        }
    }

    #[cfg(windows)]
    {
        let mut opts = OpenOptions::new();
        opts.read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED);
        if let Ok(f) = opts.open(address) {
            info!("attempting to remove existing named pipe: {}", address);
            unsafe { CloseHandle(f.as_raw_handle() as isize) };
        }
    }

    Ok(())
}

/// Spawn is a helper func to launch shim process.
/// Typically this expected to be called from `StartShim`.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
pub fn spawn(opts: StartOpts, grouping: &str, vars: Vec<(&str, &str)>) -> Result<(u32, String)> {
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

    // On Windows Rust currently sets the `HANDLE_FLAG_INHERIT` flag to true when using Command::spawn.
    // When a child process is spawned by another process (containerd) the child process inherits the parent's stdin, stdout, and stderr handles.
    // Due to the HANDLE_FLAG_INHERIT flag being set to true this will cause containerd to hand until the child process closes the handles.
    // As a workaround we can Disables inheritance on the io pipe handles.
    // This workaround comes from https://github.com/rust-lang/rust/issues/54760#issuecomment-1045940560
    #[cfg(windows)]
    disable_handle_inheritance();

    let mut child = command.spawn().map_err(io_error!(e, "spawn shim"))?;

    let mut reader = child.stdout.take().unwrap();
    std::io::copy(&mut reader, &mut std::io::stderr()).unwrap();

    Ok((child.id(), address))
}

#[cfg(windows)]
fn disable_handle_inheritance() {
    use windows_sys::Win32::{
        Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT},
        System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
    };

    unsafe {
        let std_err = GetStdHandle(STD_ERROR_HANDLE);
        let std_in = GetStdHandle(STD_INPUT_HANDLE);
        let std_out = GetStdHandle(STD_OUTPUT_HANDLE);

        for handle in [std_err, std_in, std_out] {
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            //info!(" handle for... {:?}", handle);
            //CloseHandle(handle);
        }
    }
}

// This closes the stdout handle which was mapped to the stderr on the first invocation of the shim.
// This releases first process which will give containerd the address of the namedpipe.
#[cfg(windows)]
fn signal_server_started() {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};

    unsafe {
        let std_out = GetStdHandle(STD_OUTPUT_HANDLE);

        {
            let handle = std_out;
            CloseHandle(handle);
        }
    }
}

// This closes the stdout handle which was mapped to the stderr on the first invocation of the shim.
// This releases first process which will give containerd the address of the namedpipe.
#[cfg(unix)]
fn signal_server_started() {
    use libc::{dup2, STDERR_FILENO, STDOUT_FILENO};

    unsafe {
        if dup2(STDERR_FILENO, STDOUT_FILENO) < 0 {
            panic!("Error closing pipe: {}", std::io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn exit_signal() {
        let signal = Arc::new(ExitSignal::default());

        let cloned = Arc::clone(&signal);
        let handle = thread::spawn(move || {
            cloned.signal();
        });

        signal.wait();

        if let Err(err) = handle.join() {
            panic!("{:?}", err);
        }
    }

    struct Nop {}

    struct NopTask {}
    impl Task for NopTask {}

    impl Shim for Nop {
        type T = NopTask;

        fn new(_runtime_id: &str, _args: &Flags, _config: &mut Config) -> Self {
            Nop {}
        }

        fn start_shim(&mut self, _opts: StartOpts) -> Result<String> {
            Ok("".to_string())
        }

        fn delete_shim(&mut self) -> Result<DeleteResponse> {
            Ok(DeleteResponse::default())
        }

        fn wait(&mut self) {}

        fn create_task_service(&self, _publisher: RemotePublisher) -> Self::T {
            NopTask {}
        }
    }

    #[test]
    fn no_namespace() {
        let runtime_id = "test";
        let res = bootstrap::<Nop>(runtime_id, None);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Shim namespace cannot be empty"));
    }
}
