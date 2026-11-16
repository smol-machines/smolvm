//! Docker/Compose commands always target Smol explicitly, never the user's
//! current Docker context or DOCKER_HOST. Visible-workspace events trigger refreshes.
use crate::runtime::{Runtime, capture};
use serde_json::Value;
use std::{
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
}
#[derive(Clone, Debug)]
pub enum Action {
    Status,
    Configure,
    RunImages,
    RunContainer(crate::container_run::Draft),
    List(Kind),
    Start(String),
    Stop(String),
    Restart(String),
    Resume(String),
    Rename {
        id: String,
        name: String,
    },
    Delete(String),
    Logs(String),
    Inspect(String),
    NetworkInspect(String),
    Stats(String),
    Files(crate::files::Request),
    StorageInspect {
        kind: Kind,
        id: String,
    },
    StorageRemove {
        kind: Kind,
        id: String,
        created: String,
    },
    ReviewImageTag {
        id: String,
        reference: String,
    },
    TagImage(crate::image_tag::Plan),
    ReviewImageArchive(crate::image_archive::Request),
    TransferImageArchive(crate::image_archive::Plan),
    PullImage(String),
    CreateVolume(String),
    Projects,
    DiscoverProject(String),
    Project {
        name: String,
        action: ProjectAction,
    },
    Compose {
        source: crate::compose::Source,
        up: bool,
    },
    ForgetProject(String),
}
impl Action {
    pub fn progress_title(&self) -> Option<String> {
        match self {
            Self::Compose { source, up } => Some(format!(
                "{} {}",
                if *up {
                    "Apply"
                } else {
                    "Remove containers for"
                },
                source.name.as_deref().unwrap_or("Compose project")
            )),
            Self::PullImage(reference) => Some(format!("Pull {reference}")),
            Self::TransferImageArchive(plan) => Some(format!(
                "{} {}",
                if plan.importing() { "Import" } else { "Export" },
                plan.path.file_name().unwrap_or_default().to_string_lossy()
            )),
            _ => None,
        }
    }
    pub fn mutates(&self) -> bool {
        if let Self::Files(request) = self {
            return request.mutates();
        }
        !matches!(
            self,
            Self::Status
                | Self::RunImages
                | Self::List(_)
                | Self::Logs(_)
                | Self::Inspect(_)
                | Self::NetworkInspect(_)
                | Self::Stats(_)
                | Self::StorageInspect { .. }
                | Self::Projects
                | Self::DiscoverProject(_)
                | Self::ReviewImageTag { .. }
                | Self::ReviewImageArchive(_)
        )
    }
}
pub enum Output {
    Files {
        id: String,
        listing: crate::files::Listing,
    },
    FileTransferred {
        id: String,
        local: std::path::PathBuf,
        upload: bool,
    },
    Connection(crate::docker_connection::Connection),
    RunImages(Vec<crate::container_run::Image>),
    ContainerCreated(crate::container_run::Created),
    Rows(Kind, Vec<Value>),
    Projects(Vec<crate::compose::Project>, Option<String>),
    DiscoveredSource(crate::compose::Source),
    ComposeApplied {
        name: String,
        warning: Option<String>,
    },
    ImageTagPlan(crate::image_tag::Plan),
    ImageArchivePlan(crate::image_archive::Plan),
    Storage(crate::storage::Details),
    Network(crate::network::Details),
    Text(String),
    Details(Box<crate::container_details::ContainerDetails>),
    Stats {
        id: String,
        value: Value,
    },
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
pub fn validate_container_name(name: &str) -> Result<(), String> {
    crate::storage::validate_volume(name).map_err(|_| {
        "Use letters, numbers, dots, underscores or dashes; start with a letter or number.".into()
    })
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
        Action::NetworkInspect(id) => {
            crate::network::validate_id(id)?;
            args.extend([
                "network".into(),
                "inspect".into(),
                "--format".into(),
                "{{json .}}".into(),
                id.clone(),
            ]);
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
        Action::Rename { id, name } => {
            validate_container_id(id)?;
            validate_container_name(name)?;
            args.extend([
                "container".into(),
                "rename".into(),
                id.clone(),
                name.clone(),
            ]);
        }
        Action::Start(id)
        | Action::Restart(id)
        | Action::Resume(id)
        | Action::Stop(id)
        | Action::Delete(id)
        | Action::Logs(id)
        | Action::Inspect(id)
        | Action::Stats(id) => {
            validate_container_id(id)?;
            let command = match action {
                Action::Start(_) => "start",
                Action::Restart(_) => "restart",
                Action::Resume(_) => "unpause",
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
        Action::Compose { source, up } => {
            args = source.args()?;
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
    let progress = crate::command_progress::Progress::new(|| {});
    if let Some(title) = action.progress_title() {
        progress.begin(title);
    }
    execute_with_progress(runtime, action, shutdown, &progress)
}
fn execute_with_progress(
    runtime: &Runtime,
    action: &Action,
    shutdown: &AtomicBool,
    progress: &crate::command_progress::Progress,
) -> Result<Output, String> {
    if let Action::Files(request) = action {
        return crate::container_files::execute(request, shutdown);
    }
    if matches!(action, Action::RunImages) {
        return crate::container_run::images(shutdown).map(Output::RunImages);
    }
    if let Action::RunContainer(draft) = action {
        return crate::container_run::run(draft, shutdown).map(Output::ContainerCreated);
    }
    if let Action::ReviewImageArchive(request) = action {
        return crate::image_archive::review(request, shutdown).map(Output::ImageArchivePlan);
    }
    if let Action::TransferImageArchive(plan) = action {
        crate::image_archive::apply(plan, progress, shutdown)?;
        return Ok(Output::Completed);
    }
    if let Action::ReviewImageTag { id, reference } = action {
        return crate::image_tag::review(id, reference, shutdown).map(Output::ImageTagPlan);
    }
    if let Action::TagImage(plan) = action {
        crate::image_tag::apply(plan, shutdown)?;
        return Ok(Output::Completed);
    }
    if let Action::DiscoverProject(name) = action {
        let Output::Projects(projects, _) = execute(runtime, &Action::Projects, shutdown)? else {
            unreachable!()
        };
        let project = projects
            .iter()
            .find(|p| &p.name == name)
            .ok_or("This project no longer exists. Refresh the project list.")?;
        return Ok(Output::DiscoveredSource(project.discover_source()?));
    }
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
    if let Action::Compose { source, up } = action {
        return apply_compose(runtime, source, *up, shutdown, progress);
    }
    if let Action::ForgetProject(name) = action {
        crate::compose::save_source(&crate::compose::source_store(runtime)?, name, None)?;
        return Ok(Output::Completed);
    }
    if matches!(action, Action::Status) {
        return Ok(Output::Connection(crate::docker_connection::check(
            shutdown,
        )));
    }
    let mut command;
    if matches!(action, Action::Configure) {
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
    if matches!(action, Action::PullImage(_)) {
        progress.capture(command, Duration::from_secs(600), shutdown)?;
        return Ok(Output::Completed);
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
        Action::NetworkInspect(id) => {
            Ok(Output::Network(crate::network::Details::parse(id, &bytes)?))
        }
        Action::Projects => {
            let mut projects = crate::compose::parse(&bytes)?;
            let warning = match crate::compose::source_store(runtime)
                .and_then(|path| crate::compose::load_sources(&path))
            {
                Ok(sources) => {
                    crate::compose::attach_sources(&mut projects, sources);
                    None
                }
                Err(error) => Some(error),
            };
            Ok(Output::Projects(projects, warning))
        }
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
        _ => Ok(Output::Completed),
    }
}

fn compose_command(source: &crate::compose::Source) -> Result<Command, String> {
    let mut command = docker_command();
    command.args(source.args()?);
    command.current_dir(
        source
            .project_dir
            .as_deref()
            .or_else(|| source.files[0].parent())
            .ok_or("Compose file has no parent directory.")?,
    );
    // The Studio form defines the files and identity; unrelated shell control
    // variables must not silently change which project or services are applied.
    for key in [
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "COMPOSE_ENV_FILES",
        "COMPOSE_DISABLE_ENV_FILE",
        "COMPOSE_PATH_SEPARATOR",
    ] {
        command.env_remove(key);
    }
    command.env("COMPOSE_PROFILES", source.profiles.join(","));
    Ok(command)
}

fn apply_compose(
    runtime: &Runtime,
    source: &crate::compose::Source,
    up: bool,
    shutdown: &AtomicBool,
    progress: &crate::command_progress::Progress,
) -> Result<Output, String> {
    let mut source = source.clone();
    if source.name.is_none() {
        let mut command = compose_command(&source)?;
        command.args(["config", "--format", "json"]);
        let bytes = capture(
            &mut command,
            Duration::from_secs(30),
            4 * 1024 * 1024,
            shutdown,
        )?;
        // Deserialize only identity, never retain or display expanded environment.
        source.name = Some(crate::compose::resolved_name(&bytes)?);
    }
    let name = source.name.clone().unwrap();
    let mut command = compose_command(&source)?;
    command.args(["--ansi", "never", "--progress", "plain"]);
    if up {
        command.args(["up", "--detach"]);
    } else {
        command.arg("down");
    }
    progress.capture(command, Duration::from_secs(600), shutdown)?;
    let warning = crate::compose::source_store(runtime)
        .and_then(|path| crate::compose::save_source(&path, &name, Some(source)))
        .err()
        .map(|e| {
            format!(
                "Project {name} was {}, but Studio could not remember its files: {e}",
                if up { "applied" } else { "removed" }
            )
        });
    Ok(Output::ComposeApplied { name, warning })
}

fn project_action(
    runtime: &Runtime,
    name: &str,
    action: &ProjectAction,
    shutdown: &AtomicBool,
) -> Result<Output, String> {
    // Resolve exact project membership again when the action executes, rather
    // than trusting a stale UI selection or Docker's substring name filters.
    let Output::Projects(projects, _) = execute(runtime, &Action::Projects, shutdown)? else {
        unreachable!();
    };
    let project = projects
        .into_iter()
        .find(|p| p.name == name)
        .ok_or("This Compose project no longer has containers. Refresh the project list.")?;
    let deadline = Instant::now() + Duration::from_secs(600);
    let ids: Vec<_> = project
        .containers
        .iter()
        .filter(|c| match action {
            ProjectAction::Start => c.can_start(),
            ProjectAction::Stop => c.can_stop(),
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

pub(crate) fn docker_command() -> Command {
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
    pub progress: crate::command_progress::Progress,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl DockerWorker {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        let wake = Arc::new(wake);
        let notify = wake.clone();
        let progress = crate::command_progress::Progress::new(move || notify());
        let report = progress.clone();
        let (sender, requests) = mpsc::sync_channel::<(Runtime, Action)>(1);
        let (responses, events) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let thread = thread::spawn(move || {
            while let Ok((runtime, action)) = requests.recv() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let title = action.progress_title();
                let tracked = title.is_some();
                if let Some(title) = title {
                    report.begin(title);
                }
                let result = execute_with_progress(&runtime, &action, &stop, &report);
                if tracked {
                    report.finish(result.is_ok());
                }
                if responses.send(Completion { action, result }).is_err() {
                    break;
                }
                wake();
            }
        });
        Self {
            sender: Some(sender),
            events,
            progress,
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
    use std::path::PathBuf;
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
            Action::Restart("ab12".into()),
            Action::Resume("ab12".into()),
            Action::Rename {
                id: "ab12".into(),
                name: "new-name".into(),
            },
            Action::Delete("ab12".into()),
            Action::List(Kind::Containers),
            Action::Inspect("ab12".into()),
            Action::Stats("ab12".into()),
            Action::NetworkInspect("a".repeat(64)),
            Action::Projects,
        ] {
            let args = docker_args(&action).unwrap();
            assert_eq!(&args[..2], ["--context", "smol"]);
            assert!(!args.iter().any(|a| a == "--force" || a == "-f"));
        }
        assert!(docker_args(&Action::Delete("--force".into())).is_err());
    }

    #[test]
    #[ignore = "creates an explicitly owned counter container in an isolated smol context"]
    fn live_resume_continues_work_without_restarting_and_paused_stop_exits() {
        let image = std::env::var("SMOL_STUDIO_LIFECYCLE_IMAGE").expect("owned local image");
        let name = std::env::var("SMOL_STUDIO_LIFECYCLE_NAME").expect("unique fixture name");
        let shutdown = AtomicBool::new(false);
        let runtime = Runtime::discover();
        let command = |args: &[&str]| -> Result<String, String> {
            capture(
                docker_command().args(["--context", "smol"]).args(args),
                Duration::from_secs(30),
                65536,
                &shutdown,
            )
            .map(|bytes| String::from_utf8(bytes).unwrap().trim().to_owned())
        };
        let id = command(&[
            "run",
            "--detach",
            "--name",
            &name,
            "--stop-timeout",
            "1",
            &image,
            "sh",
            "-c",
            "n=0; while :; do n=$((n+1)); echo $n; sleep 0.1; done",
        ])
        .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let started = command(&["inspect", "--format", "{{.State.StartedAt}}", &id]).unwrap();
            let count = || {
                command(&["logs", "--tail", "1", &id])
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            };
            for _ in 0..50 {
                if command(&["logs", "--tail", "1", &id])
                    .unwrap()
                    .parse::<u64>()
                    .unwrap_or(0)
                    >= 3
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert!(count() >= 3);
            command(&["pause", &id]).unwrap();
            assert_eq!(
                command(&["inspect", "--format", "{{.State.Status}}", &id]).unwrap(),
                "paused"
            );
            std::thread::sleep(Duration::from_millis(300));
            let paused = count();
            std::thread::sleep(Duration::from_secs(1));
            assert_eq!(count(), paused, "work must actually pause");
            execute(&runtime, &Action::Resume(id.clone()), &shutdown).unwrap();
            for _ in 0..50 {
                if count() > paused {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert!(
                count() > paused,
                "resume must continue the original process"
            );
            assert_eq!(
                command(&[
                    "inspect",
                    "--format",
                    "{{.Id}} {{.State.Status}} {{.State.StartedAt}}",
                    &id
                ])
                .unwrap(),
                format!("{id} running {started}")
            );
            assert!(
                execute(&runtime, &Action::Resume(id.clone()), &shutdown).is_err(),
                "already running must report the engine conflict"
            );
            command(&["pause", &id]).unwrap();
            execute(&runtime, &Action::Stop(id.clone()), &shutdown).unwrap();
            assert_eq!(
                command(&["inspect", "--format", "{{.State.Status}}", &id]).unwrap(),
                "exited"
            );
        }));
        command(&["rm", "--force", &id]).expect("remove owned counter fixture");
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }

    #[test]
    #[ignore = "creates explicitly owned containers in an isolated smol context"]
    fn live_rename_and_restart_preserve_identity_and_files() {
        let image = std::env::var("SMOL_STUDIO_LIFECYCLE_IMAGE").expect("owned local image");
        let name = std::env::var("SMOL_STUDIO_LIFECYCLE_NAME").expect("unique fixture name");
        let shutdown = AtomicBool::new(false);
        let runtime = Runtime::discover();
        let command = |args: &[&str]| -> Result<String, String> {
            capture(
                docker_command().args(["--context", "smol"]).args(args),
                Duration::from_secs(120),
                65536,
                &shutdown,
            )
            .map(|bytes| String::from_utf8(bytes).unwrap().trim().to_owned())
        };
        let mut owned = Vec::<String>::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let conflict = format!("{name}-taken");
            let renamed = format!("{name}-renamed");
            let other = command(&["create", "--name", &conflict, &image, "true"]).unwrap();
            owned.push(other.clone());
            let id = command(&["run", "--detach", "--name", &name, "--stop-timeout", "1", &image, "sh", "-c", "n=$(cat /tmp/studio-start-count 2>/dev/null || echo 0); echo $((n+1)) > /tmp/studio-start-count; exec sleep 600"]).unwrap();
            owned.push(id.clone());
            for _ in 0..30 {
                if command(&["exec", &id, "cat", "/tmp/studio-start-count"]).as_deref() == Ok("1") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_eq!(
                command(&["exec", &id, "cat", "/tmp/studio-start-count"]).unwrap(),
                "1"
            );
            command(&[
                "exec",
                &id,
                "sh",
                "-c",
                "printf preserved > /tmp/studio-lifecycle-marker",
            ])
            .unwrap();
            let before = command(&["inspect", "--format", "{{.State.StartedAt}}", &id]).unwrap();
            execute(
                &runtime,
                &Action::Rename {
                    id: id.clone(),
                    name: renamed.clone(),
                },
                &shutdown,
            )
            .unwrap();
            assert_eq!(
                command(&["inspect", "--format", "{{.Name}}", &id]).unwrap(),
                format!("/{renamed}")
            );
            assert_eq!(
                command(&["inspect", "--format", "{{.State.StartedAt}}", &id]).unwrap(),
                before
            );
            assert!(
                execute(
                    &runtime,
                    &Action::Rename {
                        id: id.clone(),
                        name: conflict.clone()
                    },
                    &shutdown
                )
                .is_err()
            );
            assert_eq!(
                command(&["inspect", "--format", "{{.Name}}", &id]).unwrap(),
                format!("/{renamed}")
            );
            assert_eq!(
                command(&["inspect", "--format", "{{.Id}}", &conflict]).unwrap(),
                other
            );
            execute(&runtime, &Action::Restart(id.clone()), &shutdown).unwrap();
            for _ in 0..30 {
                if command(&["exec", &id, "cat", "/tmp/studio-start-count"]).as_deref() == Ok("2") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_eq!(
                command(&["exec", &id, "cat", "/tmp/studio-start-count"]).unwrap(),
                "2"
            );
            assert_eq!(
                command(&["exec", &id, "cat", "/tmp/studio-lifecycle-marker"]).unwrap(),
                "preserved"
            );
            assert_eq!(
                command(&["inspect", "--format", "{{.Id}} {{.State.Status}}", &renamed]).unwrap(),
                format!("{id} running")
            );
            execute(&runtime, &Action::Stop(id.clone()), &shutdown).unwrap();
            let copied = tempfile::tempdir().unwrap();
            let target = copied.path().join("marker");
            command(&[
                "cp",
                &format!("{id}:/tmp/studio-lifecycle-marker"),
                target.to_str().unwrap(),
            ])
            .unwrap();
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "preserved");
            execute(&runtime, &Action::Start(id.clone()), &shutdown).unwrap();
            assert_eq!(
                command(&["exec", &id, "cat", "/tmp/studio-start-count"]).unwrap(),
                "3"
            );
            assert_eq!(
                command(&["inspect", "--format", "{{.State.Status}}", &other]).unwrap(),
                "created"
            );
        }));
        for id in owned {
            command(&["rm", "--force", &id]).expect("remove owned lifecycle fixture");
        }
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }

    #[test]
    fn rename_rejects_option_injection_and_preserves_target_identity() {
        for name in [
            "",
            "--help",
            "/other",
            "has space",
            "a;command",
            "line\nbreak",
        ] {
            assert!(
                docker_args(&Action::Rename {
                    id: "ab12".into(),
                    name: name.into()
                })
                .is_err()
            );
        }
        assert!(
            docker_args(&Action::Rename {
                id: "--help".into(),
                name: "valid".into()
            })
            .is_err()
        );
        assert_eq!(
            docker_args(&Action::Rename {
                id: "ab12".into(),
                name: "api.v2_test-1".into()
            })
            .unwrap(),
            [
                "--context",
                "smol",
                "container",
                "rename",
                "ab12",
                "api.v2_test-1"
            ]
        );
        assert!(
            Action::Rename {
                id: "ab12".into(),
                name: "api".into()
            }
            .mutates()
        );
        assert!(Action::Restart("ab12".into()).mutates());
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
            Output::Projects(projects, _) => projects,
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
        let stream = crate::log_stream::LogStream::project(&name, None, || {}).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(snapshot) = stream.snapshot_after(0)
                && snapshot.text.contains("studio-web-ready")
            {
                assert!(!snapshot.text.contains("migration-done"));
                break;
            }
            assert!(Instant::now() < deadline, "Project logs did not arrive");
            thread::sleep(Duration::from_millis(20));
        }
        drop(stream);
        let job = project.containers.iter().find(|c| c.is_job()).unwrap();
        let Output::Text(logs) =
            execute(&runtime, &Action::Logs(job.id.clone()), &shutdown).unwrap()
        else {
            panic!("Expected job logs")
        };
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
            source: crate::compose::Source::single(file.clone()),
            up: false,
        })
        .unwrap();
        assert_eq!(args[4], file.to_string_lossy());
        assert_eq!(args.last().unwrap(), "down");
        assert!(!args.iter().any(|a| a == "--volumes"));
    }

    #[test]
    #[ignore = "creates and removes an explicitly owned multi-file Compose project in an isolated smol context"]
    fn live_compose_sources() {
        use crate::compose::{Source, load_sources, source_store};
        let root = PathBuf::from(
            std::env::var_os("SMOL_STUDIO_SOURCE_TEST_ROOT").expect("isolated state directory"),
        );
        let image = std::env::var("SMOL_STUDIO_SOURCE_TEST_IMAGE").expect("fixture image");
        std::fs::create_dir_all(&root).unwrap();
        let runtime = Runtime {
            executable: "unused-by-compose".into(),
            state_dir: Some(root.clone()),
        };
        let shutdown = AtomicBool::new(false);
        let base = root.join("base, with spaces.yaml");
        let overlay = root.join("override.yaml");
        std::fs::write(&base, format!("name: studio-sources-base\nservices:\n  web:\n    image: {image}\n    command: [sleep, '300']\n    environment:\n      SOURCE_VALUE: base\n")).unwrap();
        std::fs::write(&overlay, "name: studio-sources-owned\nservices:\n  web:\n    environment:\n      SOURCE_VALUE: override\n").unwrap();
        let env_base = root.join("base environment.env");
        let env_override = root.join("override environment.env");
        std::fs::write(&env_base, "STUDIO_TEST_VALUE=first\n").unwrap();
        std::fs::write(&env_override, "STUDIO_TEST_VALUE=last\n").unwrap();
        std::fs::write(&overlay, "name: studio-sources-owned\nservices:\n  web:\n    profiles: [debug]\n    environment:\n      SOURCE_VALUE: ${STUDIO_TEST_VALUE:?missing fixture value}\n").unwrap();
        let workdir = root.join("project working directory");
        std::fs::create_dir_all(&workdir).unwrap();
        let source = Source {
            files: vec![base.clone(), overlay.clone()],
            name: None,
            env_files: vec![env_base.clone(), env_override.clone()],
            profiles: vec!["debug".into()],
            project_dir: Some(workdir.clone()),
        };
        let mut default = source.clone();
        default.profiles.clear();
        let mut config = compose_command(&default).unwrap();
        config.args(["config", "--services"]);
        assert!(
            capture(&mut config, Duration::from_secs(30), 4096, &shutdown)
                .unwrap()
                .is_empty()
        );
        // Create through Compose itself: Studio has not saved any source yet.
        let mut cli = compose_command(&source).unwrap();
        cli.args(["up", "--detach"]);
        capture(
            &mut cli,
            Duration::from_secs(600),
            4 * 1024 * 1024,
            &shutdown,
        )
        .unwrap();
        let Output::DiscoveredSource(discovered) = execute(
            &runtime,
            &Action::DiscoverProject("studio-sources-owned".into()),
            &shutdown,
        )
        .unwrap() else {
            panic!("Expected detected configuration")
        };
        assert_eq!(discovered.files, source.files);
        assert_eq!(discovered.env_files, source.env_files);
        assert_eq!(discovered.project_dir, source.project_dir);
        assert!(discovered.profiles.is_empty());
        assert_eq!(discovered.name.as_deref(), Some("studio-sources-owned"));
        assert!(
            load_sources(&source_store(&runtime).unwrap())
                .unwrap()
                .is_empty()
        );
        match execute(
            &runtime,
            &Action::Compose {
                source: source.clone(),
                up: true,
            },
            &shutdown,
        )
        .unwrap()
        {
            Output::ComposeApplied { name, warning } => {
                assert_eq!(name, "studio-sources-owned");
                assert!(warning.is_none());
            }
            _ => panic!("Expected resolved project identity"),
        }
        let stored = load_sources(&source_store(&runtime).unwrap())
            .unwrap()
            .remove("studio-sources-owned")
            .unwrap();
        assert_eq!(stored.files, source.files);
        assert_eq!(stored.env_files, source.env_files);
        assert_eq!(stored.profiles, source.profiles);
        assert_eq!(stored.name.as_deref(), Some("studio-sources-owned"));
        let Output::Projects(projects, None) =
            execute(&runtime, &Action::Projects, &shutdown).unwrap()
        else {
            panic!("Expected projects")
        };
        let project = projects
            .iter()
            .find(|p| p.name == "studio-sources-owned")
            .unwrap();
        assert_eq!(project.source.as_ref(), Some(&stored));
        assert_eq!(project.running(), 1);
        let mut inspect = docker_command();
        inspect.args([
            "--context",
            "smol",
            "inspect",
            &project.containers[0].id,
            "--format",
            "{{json .Config.Env}}",
        ]);
        let env: Vec<String> = serde_json::from_slice(
            &capture(&mut inspect, Duration::from_secs(20), 4096, &shutdown).unwrap(),
        )
        .unwrap();
        assert!(env.iter().any(|v| v == "SOURCE_VALUE=last"));
        // A name edit in the source must not redirect a saved project's actions.
        std::fs::write(&overlay, "name: studio-sources-unexpected\nservices:\n  web:\n    environment:\n      SOURCE_VALUE: changed\n").unwrap();
        execute(
            &runtime,
            &Action::Compose {
                source: stored.clone(),
                up: true,
            },
            &shutdown,
        )
        .unwrap();
        let Output::Projects(projects, _) =
            execute(&runtime, &Action::Projects, &shutdown).unwrap()
        else {
            unreachable!()
        };
        assert!(
            !projects
                .iter()
                .any(|p| p.name == "studio-sources-unexpected")
        );
        assert_eq!(
            projects
                .iter()
                .find(|p| p.name == "studio-sources-owned")
                .unwrap()
                .running(),
            1
        );
        execute(
            &runtime,
            &Action::Compose {
                source: stored.clone(),
                up: false,
            },
            &shutdown,
        )
        .unwrap();
        let Output::Projects(projects, _) =
            execute(&runtime, &Action::Projects, &shutdown).unwrap()
        else {
            unreachable!()
        };
        let project = projects
            .iter()
            .find(|p| p.name == "studio-sources-owned")
            .unwrap();
        assert!(project.containers.is_empty());
        assert_eq!(project.source.as_ref(), Some(&stored));
        assert!(
            !std::fs::read_to_string(source_store(&runtime).unwrap())
                .unwrap()
                .contains("SOURCE_VALUE")
        );
        execute(
            &runtime,
            &Action::ForgetProject("studio-sources-owned".into()),
            &shutdown,
        )
        .unwrap();
        assert!(
            load_sources(&source_store(&runtime).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(base.exists() && overlay.exists());
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
            let file = std::path::PathBuf::from(file);
            execute(
                &runtime,
                &Action::Compose {
                    source: crate::compose::Source::single(file.clone()),
                    up: true,
                },
                &shutdown,
            )
            .unwrap();
            execute(
                &runtime,
                &Action::Compose {
                    source: crate::compose::Source::single(file),
                    up: false,
                },
                &shutdown,
            )
            .unwrap();
        }
    }
}
