//! Docker/Compose commands always target Smol explicitly, never the user's
//! current Docker context or DOCKER_HOST. No background inventory polling.
use crate::runtime::{Runtime, capture};
use serde_json::Value;
use std::{
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Containers,
    Images,
    Volumes,
    Networks,
}
impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Containers => "Containers",
            Self::Images => "Images",
            Self::Volumes => "Volumes",
            Self::Networks => "Networks",
        }
    }
}
#[derive(Clone, Debug)]
pub enum Action {
    Status,
    Configure,
    List(Kind),
    Start(String),
    Stop(String),
    Delete(String),
    Logs(String),
    Compose { file: PathBuf, up: bool },
}
impl Action {
    pub fn mutates(&self) -> bool {
        !matches!(self, Self::Status | Self::List(_) | Self::Logs(_))
    }
}
pub enum Output {
    Rows(Kind, Vec<Value>),
    Text(String),
    Completed,
}
pub struct Completion {
    pub action: Action,
    pub result: Result<Output, String>,
}
fn docker_args(action: &Action) -> Result<Vec<String>, String> {
    let mut args = vec!["--context".into(), "smol".into()];
    match action {
        Action::List(kind) => {
            let prefix = match kind {
                Kind::Containers => vec!["container", "ls", "--all", "--no-trunc"],
                Kind::Images => vec!["image", "ls", "--no-trunc"],
                Kind::Volumes => vec!["volume", "ls"],
                Kind::Networks => vec!["network", "ls", "--no-trunc"],
            };
            args.extend(prefix.iter().map(|s| s.to_string()));
            args.extend(["--format".into(), "{{json .}}".into()]);
        }
        Action::Start(id) | Action::Stop(id) | Action::Delete(id) | Action::Logs(id) => {
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Invalid container ID.".into());
            }
            let command = match action {
                Action::Start(_) => "start",
                Action::Stop(_) => "stop",
                Action::Delete(_) => "rm",
                _ => "logs",
            };
            args.extend(["container".into(), command.into()]);
            if matches!(action, Action::Logs(_)) {
                args.extend(["--tail".into(), "200".into()]);
            }
            args.push(id.clone());
        }
        Action::Compose { file, up } => {
            if !file.is_absolute() || !file.is_file() {
                return Err("Choose the absolute path to an existing Compose file.".into());
            }
            args.extend([
                "compose".into(),
                "--file".into(),
                file.to_string_lossy().into_owned(),
            ]);
            if *up {
                args.extend(["up".into(), "--detach".into()]);
            } else {
                args.push("down".into());
            }
        }
        _ => return Err("This action requires the Smol runtime.".into()),
    }
    Ok(args)
}
fn execute(runtime: &Runtime, action: &Action, shutdown: &AtomicBool) -> Result<Output, String> {
    let mut command;
    if matches!(action, Action::Status | Action::Configure) {
        command = Command::new(crate::runtime::find_tool(if cfg!(windows) {
            "smolvm.exe"
        } else {
            "smolvm"
        }));
        command.args(["--error-format", "json"]);
        if let Some(path) = &runtime.state_dir {
            command.arg("--state-dir").arg(path);
        }
        command.arg("engine");
        if matches!(action, Action::Status) {
            command.args(["status", "--json"]);
        }
    } else {
        command = Command::new(crate::runtime::find_tool(if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        }));
        command.args(docker_args(action)?);
        // Docker's explicit context wins; remove environment ambiguity as well.
        command
            .env_remove("DOCKER_HOST")
            .env_remove("DOCKER_CONTEXT");
        if let Action::Compose { file, .. } = action
            && let Some(parent) = file.parent()
        {
            command.current_dir(parent);
        }
    }
    command.env("NO_COLOR", "1").env("RUST_LOG", "error");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    if matches!(action, Action::Logs(_)) {
        let output = crate::runtime::capture_process(
            &mut command,
            Duration::from_secs(20),
            256 * 1024,
            shutdown,
        )?;
        if !output.success {
            return Err(crate::runtime::runtime_error(&output.stderr, output.code));
        }
        return Ok(Output::Text(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let bytes = capture(
        &mut command,
        Duration::from_secs(if action.mutates() { 600 } else { 20 }),
        4 * 1024 * 1024,
        shutdown,
    )?;
    match action {
        Action::List(kind) => {
            let rows = bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .map(serde_json::from_slice)
                .collect::<Result<Vec<Value>, _>>()
                .map_err(|_| "Docker returned an invalid inventory.".to_string())?;
            Ok(Output::Rows(*kind, rows))
        }
        Action::Status => {
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| "Runtime returned an invalid engine status.".to_string())?;
            Ok(Output::Text(
                serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?,
            ))
        }
        _ => Ok(Output::Completed),
    }
}
pub struct DockerWorker {
    sender: Option<mpsc::SyncSender<(Runtime, Action)>>,
    pub events: mpsc::Receiver<Completion>,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl DockerWorker {
    pub fn new(wake: impl Fn() + Send + 'static) -> Self {
        let (sender, requests) = mpsc::sync_channel::<(Runtime, Action)>(1);
        let (responses, events) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let thread = thread::spawn(move || {
            while let Ok((runtime, action)) = requests.recv() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let result = execute(&runtime, &action, &stop);
                if responses.send(Completion { action, result }).is_err() {
                    break;
                }
                wake();
            }
        });
        Self {
            sender: Some(sender),
            events,
            shutdown,
            thread: Some(thread),
        }
    }
    pub fn submit(&self, runtime: Runtime, action: Action) -> Result<(), String> {
        self.sender
            .as_ref()
            .ok_or("Container worker closed")?
            .try_send((runtime, action))
            .map_err(|_| "Container worker is busy.".into())
    }
}
impl Drop for DockerWorker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.sender.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn docker_never_uses_ambient_context_or_forced_removal() {
        for action in [
            Action::Start("ab12".into()),
            Action::Stop("ab12".into()),
            Action::Delete("ab12".into()),
            Action::List(Kind::Containers),
        ] {
            let args = docker_args(&action).unwrap();
            assert_eq!(&args[..2], ["--context", "smol"]);
            assert!(!args.iter().any(|a| a == "--force" || a == "-f"));
        }
        assert!(docker_args(&Action::Delete("--force".into())).is_err());
    }
    #[test]
    fn compose_paths_preserve_spaces_and_do_not_remove_volumes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("project with spaces.yml");
        std::fs::write(&file, "services: {}").unwrap();
        let args = docker_args(&Action::Compose {
            file: file.clone(),
            up: false,
        })
        .unwrap();
        assert_eq!(args[4], file.to_string_lossy());
        assert_eq!(args.last().unwrap(), "down");
        assert!(!args.iter().any(|a| a == "--volumes"));
    }
    #[test]
    #[ignore = "uses a preconfigured isolated smol Docker context and test container"]
    fn live_isolated_container_and_compose() {
        let executable = std::env::var_os("SMOL_STUDIO_TEST_RUNTIME").expect("test runtime path");
        let id = std::env::var("SMOL_STUDIO_TEST_CONTAINER").expect("owned fixture container ID");
        let runtime = Runtime {
            executable: executable.into(),
            state_dir: None,
        };
        let shutdown = AtomicBool::new(false);
        for kind in [
            Kind::Containers,
            Kind::Images,
            Kind::Volumes,
            Kind::Networks,
        ] {
            match execute(&runtime, &Action::List(kind), &shutdown).unwrap() {
                Output::Rows(_, rows) => {
                    if kind == Kind::Containers {
                        assert!(rows.iter().any(|r| r["ID"].as_str() == Some(&id)));
                    }
                }
                _ => panic!("Expected inventory"),
            }
        }
        execute(&runtime, &Action::Start(id.clone()), &shutdown).unwrap();
        execute(&runtime, &Action::Logs(id.clone()), &shutdown).unwrap();
        execute(&runtime, &Action::Stop(id.clone()), &shutdown).unwrap();
        execute(&runtime, &Action::Delete(id), &shutdown).unwrap();
        if let Some(file) = std::env::var_os("SMOL_STUDIO_TEST_COMPOSE") {
            let file = PathBuf::from(file);
            execute(
                &runtime,
                &Action::Compose {
                    file: file.clone(),
                    up: true,
                },
                &shutdown,
            )
            .unwrap();
            execute(&runtime, &Action::Compose { file, up: false }, &shutdown).unwrap();
        }
    }
}
