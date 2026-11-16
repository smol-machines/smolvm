use crate::model::{Machine, Operation, parse_machines};
use std::{
    ffi::OsString,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const INVENTORY_LIMIT: u64 = 4 * 1024 * 1024;
const LOG_LIMIT: u64 = 256 * 1024;
const ERROR_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Debug)]
pub struct Runtime {
    pub executable: PathBuf,
    pub state_dir: Option<PathBuf>,
}

impl Runtime {
    pub fn discover() -> Self {
        let executable = std::env::var_os("SMOL_STUDIO_CLI")
            .map(PathBuf::from)
            .unwrap_or_else(|| find_tool(executable_name()));
        Self {
            executable,
            state_dir: None,
        }
    }

    pub fn args(&self, op: &Operation) -> Result<Vec<OsString>, String> {
        let mut args: Vec<OsString> = Vec::new();
        // The SDK documents this engine entry point for introspection that
        // the public machine noun does not expose without starting a guest.
        if matches!(
            op,
            Operation::Logs(_)
                | Operation::Stats(_)
                | Operation::ListFiles { .. }
                | Operation::TransferFile { .. }
        ) {
            args.push("_engine".into());
        }
        args.push("machine".into());
        match op {
            Operation::ListFiles { name, path } => {
                crate::files::validate_path(path)?;
                args.extend([
                    "files".into(),
                    "--name".into(),
                    name.into(),
                    "list".into(),
                    path.into(),
                    "--json".into(),
                ]);
            }
            Operation::TransferFile {
                name,
                guest,
                local,
                upload,
            } => {
                crate::files::validate_path(guest)?;
                if !local.is_absolute() {
                    return Err("Choose an absolute local file path.".into());
                }
                args.extend(["files".into(), "--name".into(), name.into()]);
                if *upload {
                    args.extend(["upload".into(), local.as_os_str().to_owned(), guest.into()]);
                } else {
                    args.extend([
                        "download".into(),
                        guest.into(),
                        local.as_os_str().to_owned(),
                    ]);
                }
            }
            Operation::ReadSettings(name) => args.extend([
                "status".into(),
                "--local".into(),
                "--name".into(),
                name.into(),
                "--json".into(),
            ]),
            Operation::UpdateSettings { original, updated } => {
                args.extend([
                    "update".into(),
                    "--local".into(),
                    "--name".into(),
                    original.name.clone().into(),
                ]);
                let changes = original.update_args(updated)?;
                if changes.is_empty() {
                    return Err("No settings have changed.".into());
                }
                args.extend(changes);
            }
            Operation::Resume(name) => args.extend([
                "resume".into(),
                "--local".into(),
                "--name".into(),
                name.into(),
            ]),
            Operation::Pause(name) => args.extend([
                "pause".into(),
                "--local".into(),
                "--name".into(),
                name.into(),
            ]),
            Operation::Stats(name) => args.extend([
                "stats".into(),
                "--name".into(),
                name.into(),
                "--json".into(),
            ]),
            Operation::Exec { name, command } => {
                if command.trim().is_empty() || command.contains('\0') {
                    return Err("Enter a shell command.".into());
                }
                args.extend([
                    "exec".into(),
                    "--local".into(),
                    "--name".into(),
                    name.into(),
                    "--timeout".into(),
                    "60".into(),
                    "--".into(),
                    "/bin/sh".into(),
                    "-lc".into(),
                    command.into(),
                ]);
            }
            Operation::Refresh => args.extend(["ls".into(), "--local".into(), "--json".into()]),
            Operation::Logs(name) => args.extend([
                "logs".into(),
                "--name".into(),
                name.into(),
                "--tail".into(),
                "200".into(),
            ]),
            Operation::Start(name) => args.extend([
                "start".into(),
                "--local".into(),
                "--name".into(),
                name.into(),
            ]),
            Operation::Stop(name) => args.extend([
                "stop".into(),
                "--local".into(),
                "--name".into(),
                name.into(),
            ]),
            Operation::Delete(name) => args.extend([
                "rm".into(),
                "--local".into(),
                "--name".into(),
                name.into(),
                "--yes".into(),
            ]),
            Operation::Create(m) => {
                m.validate()?;
                args.extend([
                    "create".into(),
                    "--local".into(),
                    "--name".into(),
                    m.name.clone().into(),
                    "--cpus".into(),
                    m.cpus.to_string().into(),
                    "--mem".into(),
                    m.memory_mib.to_string().into(),
                ]);
                if !m.image.trim().is_empty() {
                    args.extend(["--image".into(), m.image.trim().into()]);
                }
                if m.network || !m.ports.is_empty() {
                    args.push("--net".into());
                }
                for folder in &m.folders {
                    args.extend([
                        "--volume".into(),
                        format!(
                            "{}:{}:{}",
                            folder.host,
                            folder.guest,
                            if folder.read_only { "ro" } else { "rw" }
                        )
                        .into(),
                    ]);
                }
                for port in &m.ports {
                    args.extend([
                        "--port".into(),
                        format!("{}:{}", port.host, port.guest).into(),
                    ]);
                }
            }
        }
        Ok(args)
    }

    pub(crate) fn command(&self, op: &Operation) -> Result<Command, String> {
        #[cfg(windows)]
        if self
            .executable
            .extension()
            .is_none_or(|ext| !ext.eq_ignore_ascii_case("exe"))
        {
            return Err("Choose smol.exe; script launchers are not supported.".into());
        }
        let args = self.args(op)?;
        let mut command = Command::new(&self.executable);
        if let Some(path) = &self.state_dir {
            command.env("SMOLVM_DATA_DIR", path);
            // Released 1.35 CLIs predate the data-root entry-point fix.
            // XDG paths also isolate those builds on Linux.
            #[cfg(target_os = "linux")]
            command
                .env("XDG_DATA_HOME", path.join("data"))
                .env("XDG_CONFIG_HOME", path.join("config"))
                .env("XDG_CACHE_HOME", path.join("cache"));
        }
        command
            .args(args)
            .env("NO_COLOR", "1")
            .env("RUST_LOG", "error");
        // Do not flash a console window for each inventory refresh on Windows.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        Ok(command)
    }

    fn execute(&self, op: &Operation, shutdown: &AtomicBool) -> Result<Payload, String> {
        if let Operation::UpdateSettings { original, .. } = op {
            let Payload::Settings(current) =
                self.execute(&Operation::ReadSettings(original.name.clone()), shutdown)?
            else {
                return Err("Cannot recheck the machine's current settings.".into());
            };
            if current.as_ref() != original.as_ref() {
                return Err("This machine changed since you opened its settings. Reload before applying changes.".into());
            }
        }
        let mut command = self.command(op)?;
        let limit = match op {
            Operation::Refresh | Operation::ReadSettings(_) | Operation::ListFiles { .. } => {
                INVENTORY_LIMIT
            }
            Operation::Logs(_) | Operation::Exec { .. } => LOG_LIMIT,
            _ => ERROR_LIMIT,
        };
        let timeout = if op.is_mutation() {
            Duration::from_secs(600)
        } else {
            Duration::from_secs(15)
        };
        if let Operation::Exec { name, .. } = op {
            let output = capture_process(&mut command, Duration::from_secs(75), limit, shutdown)?;
            return Ok(Payload::Output {
                name: name.clone(),
                text: format!(
                    "{}{}\nExit status: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                    output
                        .code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "interrupted".into())
                ),
            });
        }
        let output = capture(&mut command, timeout, limit, shutdown)?;
        match op {
            Operation::Refresh => parse_machines(&output).map(Payload::Machines),
            Operation::ListFiles { name, path } => {
                crate::files::Listing::parse(&output, path).map(|listing| Payload::Files {
                    name: name.clone(),
                    listing,
                })
            }
            Operation::ReadSettings(name) => {
                crate::machine_settings::Settings::parse(&output, name)
                    .map(|settings| Payload::Settings(Box::new(settings)))
            }
            Operation::Stats(name) => {
                let value: serde_json::Value = serde_json::from_slice(&output)
                    .map_err(|e| format!("Cannot read machine statistics: {e}"))?;
                Ok(Payload::Output {
                    name: name.clone(),
                    text: serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?,
                })
            }
            Operation::Logs(name) => Ok(Payload::Logs {
                name: name.clone(),
                text: String::from_utf8_lossy(&output).into_owned(),
            }),
            _ => Ok(Payload::Completed),
        }
    }
}

/// GUI launches often have a minimal PATH, especially from Finder on macOS.
pub fn find_tool(name: &str) -> PathBuf {
    let mut candidates = Vec::new();
    if let Some(parent) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        candidates.push(parent.join(name));
        candidates.push(parent.join("runtime").join(name));
        #[cfg(target_os = "macos")]
        if let Some(contents) = parent.parent() {
            candidates.push(contents.join("Resources/runtime").join(name));
        }

        candidates.push(parent.join("runtime/bin").join(name));
        candidates.push(parent.join("engine").join(name));
        #[cfg(target_os = "macos")]
        if let Some(contents) = parent.parent() {
            candidates.push(contents.join("Resources/engine").join(name));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|p| p.join(name)));
    }
    if let Some(base) = directories::BaseDirs::new() {
        for relative in [".smolvm", ".local/bin", ".docker/bin", ".smol/bin"] {
            candidates.push(base.home_dir().join(relative).join(name));
        }
    }
    #[cfg(unix)]
    for directory in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        candidates.push(PathBuf::from(directory).join(name));
    }
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("ProgramFiles") {
        candidates.push(
            PathBuf::from(path)
                .join("Docker/Docker/resources/bin")
                .join(name),
        );
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| name.into())
}

fn executable_name() -> &'static str {
    if cfg!(windows) { "smol.exe" } else { "smol" }
}

/// File captures avoid pipe-reader threads and inherited pipes held open by
/// long-lived VMM children. Only bounded output is ever loaded into memory.
/// Files are anonymous/owner-only and removed when the command completes.
pub(crate) struct Captured {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) code: Option<i32>,
    pub(crate) success: bool,
}
pub(crate) fn capture(
    command: &mut Command,
    timeout: Duration,
    limit: u64,
    shutdown: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let output = capture_process(command, timeout, limit, shutdown)?;
    if !output.success {
        return Err(runtime_error(&output.stderr, output.code));
    }
    Ok(output.stdout)
}
pub(crate) fn capture_process(
    command: &mut Command,
    timeout: Duration,
    limit: u64,
    shutdown: &AtomicBool,
) -> Result<Captured, String> {
    let mut stdout = tempfile::tempfile().map_err(|e| e.to_string())?;
    let mut stderr = tempfile::tempfile().map_err(|e| e.to_string())?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().map_err(|e| e.to_string())?)
        .stderr(stderr.try_clone().map_err(|e| e.to_string())?);
    let mut child = command.spawn().map_err(|e| {
        format!(
            "Cannot launch {}: {e}. Check the installed executable and Settings.",
            command.get_program().to_string_lossy()
        )
    })?;
    let start = Instant::now();
    let outcome = loop {
        let reason = if shutdown.load(Ordering::Relaxed) {
            Some("Studio closed; the command was interrupted. Check machine state before retrying.")
        } else if start.elapsed() >= timeout {
            Some(
                "The runtime command timed out. Its operation may have partially completed; refresh machine state before retrying.",
            )
        } else if stdout.metadata().map(|m| m.len() > limit).unwrap_or(true)
            || stderr
                .metadata()
                .map(|m| m.len() > ERROR_LIMIT)
                .unwrap_or(true)
        {
            Some(
                "Runtime output exceeded Studio's display limit. Use the CLI to inspect the full output.",
            )
        } else {
            None
        };
        if let Some(reason) = reason {
            let _ = child.kill();
            let _ = child.wait();
            break Err(reason.to_string());
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("Could not wait for the runtime: {e}"));
            }
        }
    }?;
    Ok(Captured {
        stdout: read_limited(&mut stdout, limit)?,
        stderr: read_limited(&mut stderr, ERROR_LIMIT)?,
        code: outcome.code(),
        success: outcome.success(),
    })
}

fn read_limited(file: &mut std::fs::File, limit: u64) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("Runtime output exceeded Studio's display limit.".into());
    }
    Ok(bytes)
}

pub(crate) fn runtime_error(bytes: &[u8], code: Option<i32>) -> String {
    let text = String::from_utf8_lossy(bytes);
    // Structured errors may follow tracing/provisioning output on stderr.
    for line in text.lines().rev() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(message) = v["error"]["message"].as_str()
        {
            return message.to_owned();
        }
    }
    if text.trim().is_empty() {
        format!("SmolVM exited unsuccessfully (code {code:?}).")
    } else {
        text.trim().chars().take(4096).collect()
    }
}

#[derive(Debug)]
pub enum Payload {
    Machines(Vec<Machine>),
    Files {
        name: String,
        listing: crate::files::Listing,
    },
    Settings(Box<crate::machine_settings::Settings>),
    Logs {
        name: String,
        text: String,
    },
    Output {
        name: String,
        text: String,
    },
    Completed,
}

pub struct Completion {
    pub operation: Operation,
    pub elapsed: Duration,
    pub result: Result<Payload, String>,
}

pub struct Worker {
    requests: Option<mpsc::SyncSender<(Runtime, Operation)>>,
    pub responses: mpsc::Receiver<Completion>,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    pub fn new(wake: impl Fn() + Send + 'static) -> Self {
        let (requests, incoming) = mpsc::sync_channel::<(Runtime, Operation)>(1);
        let (outgoing, responses) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let thread = thread::spawn(move || {
            while let Ok((runtime, operation)) = incoming.recv() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let started = Instant::now();
                let result = runtime.execute(&operation, &stop);
                if outgoing
                    .send(Completion {
                        operation,
                        elapsed: started.elapsed(),
                        result,
                    })
                    .is_err()
                {
                    break;
                }
                wake();
            }
        });
        Self {
            requests: Some(requests),
            responses,
            shutdown,
            thread: Some(thread),
        }
    }

    pub fn submit(&self, runtime: Runtime, operation: Operation) -> Result<(), String> {
        self.requests
            .as_ref()
            .ok_or("Runtime worker is closed")?
            .try_send((runtime, operation))
            .map_err(|_| "The runtime is busy. Wait for the current operation.".into())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.requests.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NewMachine;

    #[test]
    #[ignore = "requires an updated public Smol CLI and a working local hypervisor"]
    fn live_machine_settings_preserve_data_and_reject_stale_edits() {
        use crate::machine_settings::{Folder, FolderMode, Port, Protocol, Settings};
        let executable =
            std::env::var_os("SMOL_STUDIO_SETTINGS_CLI").expect("SMOL_STUDIO_SETTINGS_CLI");
        // macOS's default temporary directory is too long for a nested vsock
        // socket; keep this isolated hypervisor fixture under the short /tmp.
        #[cfg(target_os = "macos")]
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(target_os = "macos"))]
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let host = temp.path().join("host folder with spaces");
        let staged = temp.path().join("staged folder");
        std::fs::create_dir_all(&host).unwrap();
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(host.join("input"), "host-input").unwrap();
        std::fs::write(staged.join("input"), "staged-input").unwrap();
        let runtime = Runtime {
            executable: executable.into(),
            state_dir: Some(state.clone()),
        };
        let name = "studio-settings-owned".to_string();
        let stop = AtomicBool::new(false);
        struct Cleanup(Runtime, String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let stop = AtomicBool::new(false);
                let _ = self.0.execute(&Operation::Stop(self.1.clone()), &stop);
                let _ = self.0.execute(&Operation::Delete(self.1.clone()), &stop);
            }
        }
        let read = |runtime: &Runtime| -> Settings {
            let Payload::Settings(settings) = runtime
                .execute(&Operation::ReadSettings(name.clone()), &stop)
                .unwrap()
            else {
                panic!("expected settings")
            };
            *settings
        };
        let mut create = Command::new(&runtime.executable);
        create
            .args(
                runtime
                    .args(&Operation::Create(NewMachine {
                        name: name.clone(),
                        cpus: 1,
                        memory_mib: 512,
                        folders: vec![crate::model::SharedFolder {
                            host: host.to_str().unwrap().into(),
                            guest: "/shared".into(),
                            read_only: true,
                        }],
                        ..Default::default()
                    }))
                    .unwrap(),
            )
            .args([
                "--storage",
                "1",
                "--overlay",
                "1",
                "--label",
                "studio-settings-kept=retained",
            ])
            .env("SMOLVM_DATA_DIR", &state);
        #[cfg(target_os = "linux")]
        create
            .env("XDG_DATA_HOME", state.join("data"))
            .env("XDG_CONFIG_HOME", state.join("config"))
            .env("XDG_CACHE_HOME", state.join("cache"));
        capture(&mut create, Duration::from_secs(120), ERROR_LIMIT, &stop).unwrap();
        let cleanup = Cleanup(runtime.clone(), name.clone());
        let labels = || {
            let mut status = Command::new(&runtime.executable);
            status
                .args(
                    runtime
                        .args(&Operation::ReadSettings(name.clone()))
                        .unwrap(),
                )
                .envs(
                    create
                        .get_envs()
                        .filter_map(|(key, value)| value.map(|value| (key, value))),
                );
            let bytes =
                capture(&mut status, Duration::from_secs(15), INVENTORY_LIMIT, &stop).unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["labels"].clone()
        };
        assert_eq!(labels()["studio-settings-kept"], "retained");
        runtime
            .execute(&Operation::Start(name.clone()), &stop)
            .unwrap();
        runtime
            .execute(
                &Operation::Exec {
                    name: name.clone(),
                    command: "printf before-growth > /workspace/before-growth".into(),
                },
                &stop,
            )
            .unwrap();
        runtime
            .execute(&Operation::Stop(name.clone()), &stop)
            .unwrap();
        let original = read(&runtime);
        assert_eq!(original.shared_folders[0].mode, FolderMode::ReadOnly);
        let mut updated = original.clone();
        updated.cpus = 2;
        updated.memory_mib = 768;
        updated.network = true;
        updated.storage_gb = Some(2);
        updated.overlay_gb = Some(2);
        updated.shared_folders[0].mode = FolderMode::ReadWrite;
        updated.shared_folders.push(Folder {
            host: std::fs::canonicalize(&staged)
                .unwrap()
                .to_str()
                .unwrap()
                .into(),
            guest: "/staged".into(),
            mode: FolderMode::Staged,
        });
        let (listener, udp, host_port) = (0..32)
            .find_map(|_| {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
                let port = listener.local_addr().ok()?.port();
                let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).ok()?;
                Some((listener, udp, port))
            })
            .expect("an unused TCP and UDP port");
        updated.port_mappings = vec![
            Port {
                host: host_port,
                guest: 8080,
                protocol: Protocol::Tcp,
            },
            Port {
                host: host_port,
                guest: 5353,
                protocol: Protocol::Udp,
            },
        ];
        runtime
            .execute(
                &Operation::UpdateSettings {
                    original: Box::new(original.clone()),
                    updated: Box::new(updated.clone()),
                },
                &stop,
            )
            .unwrap();
        assert_eq!(labels()["studio-settings-kept"], "retained");
        let saved = read(&runtime);
        assert_eq!(saved, updated);
        let error = runtime
            .execute(
                &Operation::UpdateSettings {
                    original: Box::new(original),
                    updated: Box::new(updated.clone()),
                },
                &stop,
            )
            .unwrap_err();
        assert!(error.contains("changed since"), "{error}");
        drop((listener, udp));
        runtime
            .execute(&Operation::Start(name.clone()), &stop)
            .unwrap();
        let error = runtime
            .execute(
                &Operation::UpdateSettings {
                    original: Box::new(updated.clone()),
                    updated: Box::new(updated.clone()),
                },
                &stop,
            )
            .unwrap_err();
        assert!(error.contains("changed since"), "{error}");
        let Payload::Output { text, .. } = runtime.execute(&Operation::Exec { name: name.clone(), command: "set -x; test \"$(cat /workspace/before-growth)\" = before-growth && test \"$(cat /shared/input)\" = host-input && test \"$(cat /staged/input)\" = staged-input && printf shared-write > /shared/output && printf staged-write > /staged/output && printf persistent-data > /workspace/settings-payload && printf settings-ok".into() }, &stop).unwrap() else { panic!("expected output") };
        assert!(text.contains("settings-ok"), "{text}");
        assert_eq!(
            std::fs::read_to_string(host.join("output")).unwrap(),
            "shared-write"
        );
        runtime
            .execute(&Operation::Stop(name.clone()), &stop)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(staged.join("output")).unwrap(),
            "staged-write"
        );
        let original = read(&runtime);
        let mut updated = original.clone();
        updated.shared_folders.clear();
        updated.port_mappings.clear();
        updated.network = false;
        runtime
            .execute(
                &Operation::UpdateSettings {
                    original: Box::new(original),
                    updated: Box::new(updated.clone()),
                },
                &stop,
            )
            .unwrap();
        assert_eq!(read(&runtime), updated);
        runtime
            .execute(&Operation::Start(name.clone()), &stop)
            .unwrap();
        let Payload::Output { text, .. } = runtime
            .execute(
                &Operation::Exec {
                    name: name.clone(),
                    command: "set -x; cat /workspace/settings-payload".into(),
                },
                &stop,
            )
            .unwrap()
        else {
            panic!("expected output")
        };
        assert!(text.contains("persistent-data"), "{text}");
        drop(cleanup);
        let Payload::Machines(machines) = runtime.execute(&Operation::Refresh, &stop).unwrap()
        else {
            panic!("expected inventory")
        };
        assert!(machines.is_empty());
    }

    #[test]
    #[ignore = "requires updated public Smol CLI, working hypervisor and registry access"]
    fn live_files_browse_transfer_and_preserve_failed_download() {
        let executable = std::env::var_os("SMOL_STUDIO_FILES_CLI").expect("SMOL_STUDIO_FILES_CLI");
        #[cfg(target_os = "macos")]
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(target_os = "macos"))]
        let temp = tempfile::tempdir().unwrap();
        let runtime = Runtime {
            executable: executable.into(),
            state_dir: Some(temp.path().join("state")),
        };
        let stop = AtomicBool::new(false);
        struct Cleanup(Runtime, String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let stop = AtomicBool::new(false);
                let _ = self.0.execute(&Operation::Stop(self.1.clone()), &stop);
                let _ = self.0.execute(&Operation::Delete(self.1.clone()), &stop);
            }
        }
        for (name, image) in [("files-bare", ""), ("files-image", "alpine:3.21")] {
            runtime
                .execute(
                    &Operation::Create(NewMachine {
                        name: name.into(),
                        image: image.into(),
                        network: !image.is_empty(),
                        cpus: 1,
                        memory_mib: 512,
                        ..Default::default()
                    }),
                    &stop,
                )
                .unwrap();
            let cleanup = Cleanup(runtime.clone(), name.into());
            let list = |path: &str| Operation::ListFiles {
                name: name.into(),
                path: path.into(),
            };
            assert!(runtime.execute(&list("/workspace"), &stop).is_err());
            let Payload::Machines(rows) = runtime.execute(&Operation::Refresh, &stop).unwrap()
            else {
                panic!("inventory")
            };
            assert_eq!(rows[0].state, "created");
            runtime
                .execute(&Operation::Start(name.into()), &stop)
                .unwrap();
            let Payload::Output { text, .. } = runtime.execute(&Operation::Exec { name: name.into(), command: "mkdir -p /workspace/folder; printf hidden > /workspace/.hidden; printf workload > /root/studio-file-probe; ln -s /missing /workspace/dangling; printf prepared".into() }, &stop).unwrap() else { panic!("output") };
            assert!(text.contains("prepared"), "{text}");
            let source = temp.path().join("payload ; $(true).bin");
            let payload: Vec<u8> = (0..18 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
            std::fs::write(&source, &payload).unwrap();
            let guest = "/workspace/payload ; $(true).bin";
            let transfer = |guest: &str, local: &std::path::Path, upload| Operation::TransferFile {
                name: name.into(),
                guest: guest.into(),
                local: local.into(),
                upload,
            };
            runtime
                .execute(&transfer(guest, &source, true), &stop)
                .unwrap();
            let Payload::Files { listing, .. } =
                runtime.execute(&list("/workspace"), &stop).unwrap()
            else {
                panic!("listing")
            };
            assert!(
                listing
                    .entries
                    .iter()
                    .any(|e| e.name == "payload ; $(true).bin"
                        && e.kind == "file"
                        && e.size == payload.len() as u64)
            );
            assert!(listing.entries.iter().any(|e| e.name == ".hidden"));
            assert!(
                listing
                    .entries
                    .iter()
                    .any(|e| e.name == "dangling" && e.kind == "symlink")
            );
            assert!(
                listing
                    .entries
                    .iter()
                    .any(|e| e.name == "folder" && e.kind == "dir")
            );
            let Payload::Files { listing, .. } = runtime.execute(&list("/root"), &stop).unwrap()
            else {
                panic!("root listing")
            };
            assert!(
                listing
                    .entries
                    .iter()
                    .any(|e| e.name == "studio-file-probe")
            );
            let download = temp.path().join("download.bin");
            std::fs::write(&download, b"existing data").unwrap();
            assert!(
                runtime
                    .execute(&transfer("/workspace/missing", &download, false), &stop)
                    .is_err()
            );
            assert_eq!(std::fs::read(&download).unwrap(), b"existing data");
            runtime
                .execute(&transfer(guest, &download, false), &stop)
                .unwrap();
            assert_eq!(std::fs::read(&download).unwrap(), payload);
            assert!(
                runtime
                    .execute(
                        &transfer("/workspace/no-directory-upload", temp.path(), true),
                        &stop
                    )
                    .is_err()
            );
            assert!(!std::fs::read_dir(temp.path()).unwrap().any(|e| {
                e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".smol-download-")
            }));
            runtime
                .execute(&Operation::Stop(name.into()), &stop)
                .unwrap();
            assert!(runtime.execute(&list("/workspace"), &stop).is_err());
            drop(cleanup);
        }
        let Payload::Machines(rows) = runtime.execute(&Operation::Refresh, &stop).unwrap() else {
            panic!("inventory")
        };
        assert!(rows.is_empty());
    }

    #[test]
    fn arguments_preserve_spaces_and_metacharacters_without_shell() {
        let runtime = Runtime {
            executable: "/path with spaces/smolvm".into(),
            state_dir: Some("/state with spaces".into()),
        };
        let args = runtime
            .args(&Operation::Create(NewMachine {
                name: "dev".into(),
                image: "/images/a $(touch bad).tar".into(),
                ..Default::default()
            }))
            .unwrap();
        assert!(args.contains(&"--local".into()));
        assert!(!args.contains(&"--state-dir".into()));
        assert_eq!(args.last().unwrap(), "/images/a $(touch bad).tar");
        assert!(!args.iter().any(|a| a == "--net"));
        let logs = runtime
            .args(&Operation::Logs("name; echo bad".into()))
            .unwrap();
        assert!(logs.iter().any(|a| a == "name; echo bad"));
        assert!(logs.ends_with(&["--tail".into(), "200".into()]));
    }

    #[test]
    fn structured_errors_survive_diagnostic_prefixes() {
        assert_eq!(runtime_error(b"diagnostic\n{\"error\":{\"code\":\"CONFLICT\",\"message\":\"Machine is busy\"}}\n", Some(1)), "Machine is busy");
    }

    #[cfg(unix)]
    fn fixture(body: &str) -> (tempfile::TempDir, Command) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime fixture");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Read fixture scripts through a stable interpreter: executing a newly
        // written temporary file is filesystem-dependent on CI runners.
        let mut command = Command::new("/bin/sh");
        command.arg(path);
        (dir, command)
    }

    #[cfg(unix)]
    #[test]
    fn command_deadlines_output_limits_and_failure_are_enforced() {
        let stop = AtomicBool::new(false);
        let (_dir, mut command) = fixture("exec sleep 10");
        let t = Instant::now();
        let error = capture(&mut command, Duration::from_millis(60), 1024, &stop).unwrap_err();
        assert!(
            error.contains("timed out"),
            "Unexpected deadline failure: {error}"
        );
        assert!(t.elapsed() < Duration::from_secs(2));
        let (_dir, mut command) = fixture("printf 'too much output'");
        assert!(capture(&mut command, Duration::from_secs(1), 4, &stop).is_err());
        let (_dir, mut command) =
            fixture("printf '%s' '{\"error\":{\"message\":\"denied\"}}' >&2; exit 1");
        assert_eq!(
            capture(&mut command, Duration::from_secs(1), 1024, &stop).unwrap_err(),
            "denied"
        );
        let (_dir, mut command) = fixture("printf '[]'");
        assert_eq!(
            capture(&mut command, Duration::from_secs(1), 1024, &stop).unwrap(),
            b"[]"
        );
    }

    #[cfg(unix)]
    #[test]
    fn close_cancels_an_inflight_read_without_waiting_for_deadline() {
        let (_dir, mut command) = fixture("exec sleep 10");
        let stop = AtomicBool::new(true);
        assert!(
            capture(&mut command, Duration::from_secs(10), 1024, &stop)
                .unwrap_err()
                .contains("interrupted")
        );
    }
    #[test]
    fn guest_shell_text_remains_one_argument_and_has_a_deadline() {
        let runtime = Runtime {
            executable: "smolvm".into(),
            state_dir: None,
        };
        let script = "printf '%s' '$HOME; $(touch /tmp/not-on-host)'";
        let args = runtime
            .args(&Operation::Exec {
                name: "dev".into(),
                command: script.into(),
            })
            .unwrap();
        assert_eq!(args.last().unwrap(), script);
        assert!(args.windows(2).any(|w| w == ["--timeout", "60"]));
    }
    #[test]
    #[cfg(unix)]
    fn unsuccessful_commands_preserve_both_output_streams_and_status() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "printf out; printf err >&2; exit 7"]);
        let result = capture_process(
            &mut cmd,
            Duration::from_secs(2),
            1024,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(result.stdout, b"out");
        assert_eq!(result.stderr, b"err");
        assert_eq!(result.code, Some(7));
        assert!(!result.success);
    }
    #[test]
    #[ignore = "boots an isolated local VM through the Smol CLI"]
    fn live_public_smol_cli_lifecycle() {
        let executable = std::env::var_os("SMOL_STUDIO_TEST_CLI").expect("matching Smol CLI path");
        let directory = tempfile::tempdir().unwrap();
        let runtime = Runtime {
            executable: executable.into(),
            state_dir: Some(directory.path().into()),
        };
        let shutdown = AtomicBool::new(false);
        let rows = runtime.execute(&Operation::Refresh, &shutdown).unwrap();
        assert!(
            matches!(rows, Payload::Machines(rows) if rows.is_empty()),
            "Fixture must be isolated before any mutation"
        );
        let name = "studio-cli-smoke".to_string();
        let machine = NewMachine {
            name: name.clone(),
            image: "alpine:3.22".into(),
            cpus: 1,
            memory_mib: 512,
            ..Default::default()
        };
        runtime
            .execute(&Operation::Create(machine), &shutdown)
            .unwrap();
        let result: Result<(), String> = (|| {
            runtime.execute(&Operation::Logs(name.clone()), &shutdown)?;
            let rows = runtime.execute(&Operation::Refresh, &shutdown)?;
            if !matches!(rows, Payload::Machines(rows) if rows.len() == 1 && rows[0].state == "created")
            {
                return Err("Reading logs changed machine state".into());
            }
            runtime.execute(&Operation::Start(name.clone()), &shutdown)?;
            let output = runtime.execute(
                &Operation::Exec {
                    name: name.clone(),
                    command: "printf studio-cli-ok; exit 7".into(),
                },
                &shutdown,
            )?;
            if !matches!(output, Payload::Output { text, .. } if text.contains("studio-cli-ok") && text.contains("Exit status: 7"))
            {
                return Err("Unexpected command output".into());
            }
            runtime.execute(&Operation::Stats(name.clone()), &shutdown)?;
            runtime.execute(&Operation::Pause(name.clone()), &shutdown)?;
            runtime.execute(&Operation::Resume(name.clone()), &shutdown)?;
            runtime.execute(&Operation::Stop(name.clone()), &shutdown)?;
            runtime.execute(&Operation::Logs(name.clone()), &shutdown)?;
            Ok(())
        })();
        if let Err(error) = runtime.execute(&Operation::Delete(name), &shutdown) {
            let retained = directory.keep();
            panic!("Cleanup failed; retained {}: {error}", retained.display());
        }
        result.unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(runtime.execute(&Operation::Refresh, &shutdown).unwrap(), Payload::Machines(rows) if rows.is_empty())
        );
        println!(
            "Smol CLI create/start/exec/stats/pause/resume/stop/delete passed; logs did not start the guest."
        );
    }
}
