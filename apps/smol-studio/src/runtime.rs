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
        let executable = std::env::var_os("SMOL_STUDIO_RUNTIME")
            .map(PathBuf::from)
            .unwrap_or_else(|| find_tool(executable_name()));
        Self {
            executable,
            state_dir: None,
        }
    }

    pub fn args(&self, op: &Operation) -> Result<Vec<OsString>, String> {
        let mut args: Vec<OsString> = vec!["--error-format".into(), "json".into()];
        if let Some(path) = &self.state_dir {
            args.extend(["--state-dir".into(), path.as_os_str().to_owned()]);
        }
        args.push("machine".into());
        match op {
            Operation::Resume(name) => args.extend(["resume".into(), "--name".into(), name.into()]),
            Operation::Pause(name) => args.extend(["pause".into(), "--name".into(), name.into()]),
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
                    "--name".into(),
                    name.into(),
                    "--timeout".into(),
                    "60s".into(),
                    "--".into(),
                    "/bin/sh".into(),
                    "-lc".into(),
                    command.into(),
                ]);
            }
            Operation::Refresh => args.extend(["ls".into(), "--json".into()]),
            Operation::Logs(name) => args.extend([
                "logs".into(),
                "--name".into(),
                name.into(),
                "--tail".into(),
                "200".into(),
            ]),
            Operation::Start(name) => args.extend(["start".into(), "--name".into(), name.into()]),
            Operation::Stop(name) => args.extend(["stop".into(), "--name".into(), name.into()]),
            Operation::Delete(name) => args.extend([
                "delete".into(),
                "--name".into(),
                name.into(),
                "--force".into(),
            ]),
            Operation::Create(m) => {
                m.validate()?;
                args.extend([
                    "create".into(),
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

    fn execute(&self, op: &Operation, shutdown: &AtomicBool) -> Result<Payload, String> {
        #[cfg(windows)]
        if self
            .executable
            .extension()
            .is_none_or(|ext| !ext.eq_ignore_ascii_case("exe"))
        {
            return Err("Choose smolvm.exe; script launchers are not supported.".into());
        }
        let args = self.args(op)?;
        let mut command = Command::new(&self.executable);
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
        let limit = match op {
            Operation::Refresh => INVENTORY_LIMIT,
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
        candidates.push(parent.join("runtime/bin").join(name));
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
    if cfg!(windows) {
        "smolvm.exe"
    } else {
        "smolvm"
    }
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
    Logs { name: String, text: String },
    Output { name: String, text: String },
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
        assert_eq!(args[3], "/state with spaces");
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
        (dir, Command::new(path))
    }

    #[cfg(unix)]
    #[test]
    fn command_deadlines_output_limits_and_failure_are_enforced() {
        let stop = AtomicBool::new(false);
        let (_dir, mut command) = fixture("exec sleep 10");
        let t = Instant::now();
        assert!(
            capture(&mut command, Duration::from_millis(60), 1024, &stop)
                .unwrap_err()
                .contains("timed out")
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
        assert!(args.windows(2).any(|w| w == ["--timeout", "60s"]));
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
}
