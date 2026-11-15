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
    time::{Duration, Instant},
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
pub enum ProjectAction {
    Start,
    Stop,
    Logs,
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
    Inspect(String),
    Stats(String),
    StorageInspect {
        kind: Kind,
        id: String,
    },
    StorageRemove {
        kind: Kind,
        id: String,
        created: String,
    },
    PullImage(String),
    CreateVolume(String),
    Projects,
    Project {
        name: String,
        action: ProjectAction,
    },
    Compose {
        file: PathBuf,
        up: bool,
    },
}
impl Action {
    pub fn mutates(&self) -> bool {
        !matches!(
            self,
            Self::Status
                | Self::List(_)
                | Self::Logs(_)
                | Self::Inspect(_)
                | Self::Stats(_)
                | Self::StorageInspect { .. }
                | Self::Projects
                | Self::Project {
                    action: ProjectAction::Logs,
                    ..
                }
        )
    }
}
pub enum Output {
    Rows(Kind, Vec<Value>),
    Projects(Vec<crate::compose::Project>),
    Storage(crate::storage::Details),
    Text(String),
    Details(Box<crate::container_details::ContainerDetails>),
    Stats { id: String, value: Value },
    Completed,
}
pub struct Completion {
    pub action: Action,
    pub result: Result<Output, String>,
}
pub fn validate_container_id(id: &str) -> Result<(), String> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err("Invalid container ID.".into())
    } else {
        Ok(())
    }
}
fn docker_args(action: &Action) -> Result<Vec<String>, String> {
    let mut args = vec!["--context".into(), "smol".into()];
    match action {
        Action::StorageInspect { kind, id } | Action::StorageRemove { kind, id, .. } => {
            let resource = match kind {
                Kind::Images => {
                    crate::storage::validate_image_id(id)?;
                    "image"
                }
                Kind::Volumes => {
                    crate::storage::validate_volume(id)?;
                    "volume"
                }
                _ => return Err("Choose an image or volume.".into()),
            };
            args.push(resource.into());
            if matches!(action, Action::StorageInspect { .. }) {
                args.extend(["inspect".into(), "--format".into(), "{{json .}}".into()]);
            } else {
                args.push("rm".into());
                if *kind == Kind::Images {
                    args.push("--no-prune".into());
                }
            }
            args.push(id.clone());
        }
        Action::PullImage(reference) => {
            crate::storage::validate_reference(reference)?;
            args.extend(["image".into(), "pull".into(), reference.clone()]);
        }
        Action::CreateVolume(name) => {
            crate::storage::validate_volume(name)?;
            args.extend(["volume".into(), "create".into(), name.clone()]);
        }
        Action::Projects => args.extend(
            [
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                "label=com.docker.compose.project",
                "--format",
                crate::compose::LIST_FORMAT,
            ]
            .map(str::to_owned),
        ),
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
        Action::Start(id)
        | Action::Stop(id)
        | Action::Delete(id)
        | Action::Logs(id)
        | Action::Inspect(id)
        | Action::Stats(id) => {
            validate_container_id(id)?;
            let command = match action {
                Action::Start(_) => "start",
                Action::Stop(_) => "stop",
                Action::Delete(_) => "rm",
                Action::Logs(_) => "logs",
                Action::Inspect(_) => "inspect",
                _ => "stats",
            };
            args.extend(["container".into(), command.into()]);
            match action {
                Action::Logs(_) => args.extend(["--tail".into(), "200".into()]),
                Action::Inspect(_) => args.extend(["--format".into(), "{{json .}}".into()]),
                Action::Stats(_) => {
                    args.extend(["--no-stream".into(), "--format".into(), "{{json .}}".into()])
                }
                _ => {}
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
    if let Action::StorageRemove { kind, id, created } = action {
        let Output::Storage(details) = execute(
            runtime,
            &Action::StorageInspect {
                kind: *kind,
                id: id.clone(),
            },
            shutdown,
        )?
        else {
            unreachable!();
        };
        if !details.users.is_empty() {
            return Err("This resource is still used by a container, including stopped containers. Remove those containers first.".into());
        }
        if *kind == Kind::Volumes && (created.is_empty() || details.created != *created) {
            return Err(
                "This volume changed since you selected it. Refresh and review it again.".into(),
            );
        }
    }
    if let Action::Project { name, action } = action {
        return project_action(runtime, name, action, shutdown);
    }
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
        Action::StorageInspect { kind, id } => {
            let mut details = crate::storage::Details::parse(*kind, id, &bytes)?;
            let mut command = docker_command();
            command.args([
                "--context",
                "smol",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
            ]);
            command.arg(format!(
                "{}={id}",
                if *kind == Kind::Images {
                    "ancestor"
                } else {
                    "volume"
                }
            ));
            command.args(["--format", "{{json .}}"]);
            let users = capture(
                &mut command,
                Duration::from_secs(20),
                4 * 1024 * 1024,
                shutdown,
            )?;
            for line in users.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                let row: Value = serde_json::from_slice(line)
                    .map_err(|_| "Docker returned an invalid storage usage list.")?;
                let id = row["ID"]
                    .as_str()
                    .ok_or("Container ID missing from usage list.")?;
                validate_container_id(id)?;
                details.users.push(crate::storage::User {
                    id: id.into(),
                    name: row["Names"].as_str().unwrap_or(id).into(),
                    state: row["State"].as_str().unwrap_or("unknown").into(),
                });
            }
            Ok(Output::Storage(details))
        }
        Action::Projects => Ok(Output::Projects(crate::compose::parse(&bytes)?)),
        Action::List(kind) => {
            let rows = bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .map(serde_json::from_slice)
                .collect::<Result<Vec<Value>, _>>()
                .map_err(|_| "Docker returned an invalid inventory.".to_string())?;
            Ok(Output::Rows(*kind, rows))
        }
        Action::Inspect(id) => {
            let details = crate::container_details::ContainerDetails::parse(&bytes)?;
            if !details.id.starts_with(id) {
                return Err("Docker returned details for a different container.".into());
            }
            Ok(Output::Details(Box::new(details)))
        }
        Action::Stats(id) => {
            let value = serde_json::from_slice(&bytes)
                .map_err(|_| "Docker returned an invalid usage snapshot.")?;
            Ok(Output::Stats {
                id: id.clone(),
                value,
            })
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

fn project_action(
    runtime: &Runtime,
    name: &str,
    action: &ProjectAction,
    shutdown: &AtomicBool,
) -> Result<Output, String> {
    // Resolve exact project membership again when the action executes, rather
    // than trusting a stale UI selection or Docker's substring name filters.
    let Output::Projects(projects) = execute(runtime, &Action::Projects, shutdown)? else {
        unreachable!();
    };
    let project = projects
        .into_iter()
        .find(|p| p.name == name)
        .ok_or("This Compose project no longer has containers. Refresh the project list.")?;
    let deadline = Instant::now()
        + Duration::from_secs(if matches!(action, ProjectAction::Logs) {
            20
        } else {
            600
        });
    if matches!(action, ProjectAction::Logs) {
        let mut text = String::new();
        for container in &project.containers {
            if text.len() >= 192 * 1024 || Instant::now() >= deadline {
                text.push_str(
                    "\nMore project logs are available from the individual containers.\n",
                );
                break;
            }
            text.push_str(&format!(
                "\n── {} / {} ──\n",
                container.service, container.name
            ));
            let mut command = docker_command();
            command.args(docker_args(&Action::Logs(container.id.clone()))?);
            match crate::runtime::capture_process(
                &mut command,
                deadline.saturating_duration_since(Instant::now()),
                32 * 1024,
                shutdown,
            ) {
                Ok(output) => {
                    text.push_str(&String::from_utf8_lossy(&output.stdout));
                    text.push_str(&String::from_utf8_lossy(&output.stderr));
                    if !output.success {
                        text.push_str("\nCould not load all logs for this container.\n");
                    }
                }
                Err(error) => {
                    text.push_str(&error);
                    text.push('\n');
                }
            }
            if shutdown.load(Ordering::Relaxed) {
                return Err("Project logs cancelled.".into());
            }
            if text.len() > 256 * 1024 {
                let mut end = 256 * 1024 - 100;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
                text.push_str(
                    "\nProject output truncated. Open individual containers for more logs.\n",
                );
                break;
            }
        }
        return Ok(Output::Text(text));
    }
    let ids: Vec<_> = project
        .containers
        .iter()
        .filter(|c| match action {
            ProjectAction::Start => c.can_start(),
            ProjectAction::Stop => c.can_stop(),
            ProjectAction::Logs => false,
        })
        .map(|c| c.id.as_str())
        .collect();
    // Bound command-line size; Docker accepts multiple explicit container IDs.
    for batch in ids.chunks(128) {
        let mut command = docker_command();
        command.args([
            "--context",
            "smol",
            "container",
            if matches!(action, ProjectAction::Start) {
                "start"
            } else {
                "stop"
            },
        ]);
        command.args(batch);
        capture(
            &mut command,
            deadline.saturating_duration_since(Instant::now()),
            64 * 1024,
            shutdown,
        )
        .map_err(|e| {
            format!("Project operation did not finish; some containers may have changed. {e}")
        })?;
    }
    Ok(Output::Completed)
}

fn docker_command() -> Command {
    let mut command = Command::new(crate::runtime::find_tool(if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    }));
    command
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env("NO_COLOR", "1")
        .env("RUST_LOG", "error");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
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
    fn storage_commands_are_explicit_and_never_force_or_prune() {
        let id = format!("sha256:{}", "a".repeat(64));
        for action in [
            Action::StorageInspect {
                kind: Kind::Images,
                id: id.clone(),
            },
            Action::StorageRemove {
                kind: Kind::Images,
                id,
                created: String::new(),
            },
            Action::StorageRemove {
                kind: Kind::Volumes,
                id: "app-data".into(),
                created: "now".into(),
            },
            Action::CreateVolume("app-data".into()),
            Action::PullImage("registry.example:5000/app:tag".into()),
        ] {
            let args = docker_args(&action).unwrap();
            assert_eq!(&args[..2], ["--context", "smol"]);
            assert!(
                !args
                    .iter()
                    .any(|a| matches!(a.as_str(), "--force" | "-f" | "prune"))
            );
        }
        assert!(docker_args(&Action::CreateVolume("--help".into())).is_err());
        assert!(
            docker_args(&Action::StorageInspect {
                kind: Kind::Networks,
                id: "app".into()
            })
            .is_err()
        );
    }

    #[test]
    #[ignore = "pulls an image and creates/removes owned storage in an explicitly isolated smol context"]
    fn live_storage_lifecycle() {
        let runtime = Runtime {
            executable: std::env::var_os("SMOL_STUDIO_TEST_RUNTIME")
                .expect("runtime")
                .into(),
            state_dir: None,
        };
        let image = std::env::var("SMOL_STUDIO_TEST_STORAGE_IMAGE").expect("fixture image");
        let name = "studio-storage-data";
        let shutdown = AtomicBool::new(false);
        execute(&runtime, &Action::PullImage(image.clone()), &shutdown).unwrap();
        let mut command = docker_command();
        command.args([
            "--context",
            "smol",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            &image,
        ]);
        let image_id = String::from_utf8(
            capture(&mut command, Duration::from_secs(20), 4096, &shutdown).unwrap(),
        )
        .unwrap()
        .trim()
        .to_owned();
        execute(&runtime, &Action::CreateVolume(name.into()), &shutdown).unwrap();
        let inspect = |kind, id: &str| match execute(
            &runtime,
            &Action::StorageInspect {
                kind,
                id: id.into(),
            },
            &shutdown,
        )
        .unwrap()
        {
            Output::Storage(details) => details,
            _ => panic!("Expected storage details"),
        };
        let volume = inspect(Kind::Volumes, name);
        let path = PathBuf::from(
            &volume
                .fields
                .iter()
                .find(|(key, _)| key == "Storage path")
                .unwrap()
                .1,
        );
        std::fs::write(path.join("keep.txt"), "retained until deletion").unwrap();
        let mut command = docker_command();
        command.args([
            "--context",
            "smol",
            "container",
            "create",
            "--name",
            "studio-storage-owner",
            "--mount",
            &format!("type=volume,source={name},target=/data"),
            &image,
            "sleep",
            "300",
        ]);
        let id = String::from_utf8(
            capture(&mut command, Duration::from_secs(60), 4096, &shutdown).unwrap(),
        )
        .unwrap()
        .trim()
        .to_owned();
        for (kind, key) in [(Kind::Images, image_id.as_str()), (Kind::Volumes, name)] {
            let details = inspect(kind, key);
            assert!(details.users.iter().any(|user| user.id == id)); // includes created/stopped containers
            assert!(
                execute(
                    &runtime,
                    &Action::StorageRemove {
                        kind,
                        id: key.into(),
                        created: details.created
                    },
                    &shutdown
                )
                .is_err()
            );
        }
        assert_eq!(
            std::fs::read_to_string(path.join("keep.txt")).unwrap(),
            "retained until deletion"
        );
        execute(&runtime, &Action::Delete(id), &shutdown).unwrap();
        assert!(
            execute(
                &runtime,
                &Action::StorageRemove {
                    kind: Kind::Volumes,
                    id: name.into(),
                    created: "stale creation time".into()
                },
                &shutdown
            )
            .is_err()
        );
        assert!(path.join("keep.txt").exists());
        execute(
            &runtime,
            &Action::StorageRemove {
                kind: Kind::Volumes,
                id: name.into(),
                created: volume.created,
            },
            &shutdown,
        )
        .unwrap();
        assert!(!path.exists());
        assert!(
            execute(
                &runtime,
                &Action::StorageInspect {
                    kind: Kind::Volumes,
                    id: name.into()
                },
                &shutdown
            )
            .is_err()
        );
        execute(
            &runtime,
            &Action::StorageRemove {
                kind: Kind::Images,
                id: image_id.clone(),
                created: String::new(),
            },
            &shutdown,
        )
        .unwrap();
        assert!(
            execute(
                &runtime,
                &Action::StorageInspect {
                    kind: Kind::Images,
                    id: image_id
                },
                &shutdown
            )
            .is_err()
        );
    }
    #[test]
    fn docker_never_uses_ambient_context_or_forced_removal() {
        for action in [
            Action::Start("ab12".into()),
            Action::Stop("ab12".into()),
            Action::Delete("ab12".into()),
            Action::List(Kind::Containers),
            Action::Inspect("ab12".into()),
            Action::Stats("ab12".into()),
            Action::Projects,
        ] {
            let args = docker_args(&action).unwrap();
            assert_eq!(&args[..2], ["--context", "smol"]);
            assert!(!args.iter().any(|a| a == "--force" || a == "-f"));
        }
        assert!(docker_args(&Action::Delete("--force".into())).is_err());
    }

    #[test]
    #[ignore = "requires two explicitly owned Compose projects in an isolated smol context"]
    fn live_compose_project_isolation() {
        let runtime = Runtime {
            executable: std::env::var_os("SMOL_STUDIO_TEST_RUNTIME")
                .expect("runtime")
                .into(),
            state_dir: None,
        };
        let name = std::env::var("SMOL_STUDIO_TEST_PROJECT").expect("owned project");
        let other = std::env::var("SMOL_STUDIO_TEST_OTHER_PROJECT").expect("other owned project");
        assert_ne!(name, other);
        let shutdown = AtomicBool::new(false);
        let inventory = || match execute(&runtime, &Action::Projects, &shutdown).unwrap() {
            Output::Projects(projects) => projects,
            _ => panic!("Expected Compose projects"),
        };
        let initial = inventory();
        let project = initial.iter().find(|p| p.name == name).unwrap();
        assert_eq!(project.services()["web"].len(), 3); // two replicas and a completed one-off job
        assert!(
            project
                .containers
                .iter()
                .any(|c| c.is_job() && c.state == "exited")
        );
        let other_running = initial.iter().find(|p| p.name == other).unwrap().running();
        assert!(other_running > 0);
        let action = |action| Action::Project {
            name: name.clone(),
            action,
        };
        execute(&runtime, &action(ProjectAction::Stop), &shutdown).unwrap();
        let stopped = inventory();
        assert_eq!(
            stopped.iter().find(|p| p.name == name).unwrap().running(),
            0
        );
        assert_eq!(
            stopped.iter().find(|p| p.name == other).unwrap().running(),
            other_running
        );
        execute(&runtime, &action(ProjectAction::Start), &shutdown).unwrap();
        let started = inventory();
        let project = started.iter().find(|p| p.name == name).unwrap();
        assert!(
            project
                .containers
                .iter()
                .filter(|c| !c.is_job())
                .all(|c| c.state == "running")
        );
        assert!(
            project
                .containers
                .iter()
                .filter(|c| c.is_job())
                .all(|c| c.state == "exited")
        );
        assert_eq!(
            started.iter().find(|p| p.name == other).unwrap().running(),
            other_running
        );
        let Output::Text(logs) =
            execute(&runtime, &action(ProjectAction::Logs), &shutdown).unwrap()
        else {
            panic!("Expected project logs");
        };
        assert!(logs.contains("studio-web-ready"), "{logs}");
        assert!(logs.contains("migration-done"), "{logs}");
        assert!(
            execute(
                &runtime,
                &Action::Project {
                    name: format!("{name}-missing"),
                    action: ProjectAction::Stop
                },
                &shutdown
            )
            .is_err()
        );
        assert_eq!(
            inventory()
                .iter()
                .find(|p| p.name == other)
                .unwrap()
                .running(),
            other_running
        );
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
        match execute(&runtime, &Action::Inspect(id.clone()), &shutdown).unwrap() {
            Output::Details(d) => {
                assert_eq!(d.id, id);
                assert_eq!(d.state, "running");
            }
            _ => panic!("Expected details"),
        }
        match execute(&runtime, &Action::Stats(id.clone()), &shutdown).unwrap() {
            Output::Stats { id: actual, value } => {
                assert_eq!(actual, id);
                assert!(value["MemUsage"].is_string());
            }
            _ => panic!("Expected stats"),
        }
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
