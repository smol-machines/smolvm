//! `smolvm engine`: serve the Docker Engine API from smolvm itself.
//!
//! `smolvm engine` registers an on-demand API socket, creates and
//! selects the `smol` docker context, and names the socket for
//! Testcontainers, so `docker`, `docker compose`, Testcontainers and Dev
//! Containers use it with nothing else set. Every container is a machine.
//!
//! Only the default install changes the user's Docker setup. An engine with
//! its own state directory or socket (`--state-dir`, `SMOLVM_DATA_DIR`)
//! runs beside it: it registers its socket and prints how to reach it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Subcommand};

use super::engine_integration as integration;

/// `/var/run/docker.sock`, the path tools fall back to when nothing names
/// another.
const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

/// Configure automatic Docker API activation: every container is a machine
#[derive(Args, Debug)]
pub struct EngineCmd {
    #[command(subcommand)]
    action: Option<EngineAction>,
}

#[derive(Subcommand, Debug)]
enum EngineAction {
    /// Register the on-demand Docker socket and point docker at it
    #[command(hide = true)]
    Start(SocketArg),
    #[command(hide = true)]
    Register(SocketArg),
    /// Disconnect the adapter; machines continue running
    #[command(hide = true)]
    Stop(SocketArg),
    /// Show whether the engine runs and where it listens
    Status {
        #[command(flatten)]
        socket: SocketArg,
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Run the engine in the foreground
    #[command(hide = true)]
    Serve(SocketArg),
    #[command(hide = true)]
    BuildkitServe(SocketArg),
    #[command(hide = true)]
    Supervise {
        #[command(flatten)]
        socket: SocketArg,
        #[arg(long)]
        id: String,
    },
    /// Link /var/run/docker.sock to the engine's socket (runs sudo)
    LinkSocket {
        #[command(flatten)]
        socket: SocketArg,
        /// Print the command instead of running it
        #[arg(long)]
        print: bool,
        /// Replace a /var/run/docker.sock that belongs to something else
        #[arg(long)]
        force: bool,
    },
    /// Remove the Docker socket registration; machines continue running
    Unregister(SocketArg),
}

#[derive(Args, Debug, Clone)]
struct SocketArg {
    /// Unix socket the engine listens on [default: ~/.smolvm/run/docker.sock]
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    #[arg(long, hide = true)]
    root: Option<PathBuf>,
}

impl SocketArg {
    fn config(&self) -> smolvm::Result<smolvm::engine::EngineConfig> {
        let mut config = smolvm::engine::EngineConfig::default_paths()?;
        if let Some(socket) = &self.socket {
            config.socket = socket.clone();
        }
        if let Some(root) = &self.root {
            config.root = root.clone();
        }
        Ok(config)
    }
}

impl EngineCmd {
    /// Run the subcommand.
    pub fn run(self) -> smolvm::Result<()> {
        let action = self.action.unwrap_or(EngineAction::Start(SocketArg {
            socket: None,
            root: None,
        }));
        match action {
            EngineAction::Supervise { socket, id } => {
                let config = socket.config()?;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                let result = runtime.block_on(smolvm::engine::supervise(config.clone(), id));
                forget_deleted(&config);
                result
            }
            EngineAction::Serve(s) => serve(s.config()?),
            EngineAction::BuildkitServe(s) => tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(smolvm::engine::builder::serve(s.config()?)),
            EngineAction::Start(s) => start(s.config()?),
            EngineAction::Register(s) => register(&s.config()?),
            EngineAction::Unregister(s) => unregister(&s.config()?),
            EngineAction::Stop(s) => stop(s.config()?),
            EngineAction::Status { socket, json } => status(socket.config()?, json),
            EngineAction::LinkSocket {
                socket,
                print,
                force,
            } => link_socket(&socket.config()?.socket, print, force),
        }
    }
}

fn serve(config: smolvm::engine::EngineConfig) -> smolvm::Result<()> {
    std::fs::create_dir_all(&config.root)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(smolvm::Error::Io)?;
    let result = runtime.block_on(smolvm::engine::serve(config.clone()));
    forget_deleted(&config);
    result
}

fn unregister(config: &smolvm::engine::EngineConfig) -> smolvm::Result<()> {
    super::engine_activation::uninstall(&smolvm::engine::builder::config(config))?;
    super::engine_activation::uninstall(config)?;
    // `--state-dir` creates the directory it names. Unregistering an engine
    // whose state was already deleted must not leave an empty one behind.
    if smolvm::process::data_root_is_explicit() {
        if let Some(dir) = std::env::var_os("SMOLVM_DATA_DIR") {
            let _ = std::fs::remove_dir(dir);
        }
    }
    Ok(())
}

/// Remove the registration of an engine whose socket and state directory
/// were deleted: nothing can connect to it again, and the service manager
/// would otherwise list it until the user logs out.
fn forget_deleted(config: &smolvm::engine::EngineConfig) {
    if config.socket.exists() || config.root.exists() {
        return;
    }
    for config in [&smolvm::engine::builder::config(config), config] {
        if super::engine_activation::registered(config) {
            super::engine_activation::forget(config);
        }
    }
}

/// Whether `config` is the default install's engine: the default socket and
/// state directory, with no data root the user named. Only that engine may
/// change the user's Docker context, Buildx builder and Testcontainers
/// settings; any other one runs beside it.
fn is_default_install(
    config: &smolvm::engine::EngineConfig,
    default: &smolvm::engine::EngineConfig,
    explicit_data_root: bool,
) -> bool {
    !explicit_data_root && config.socket == default.socket && config.root == default.root
}

/// The arguments that name this engine again, for the commands setup prints.
fn engine_flags(
    config: &smolvm::engine::EngineConfig,
    default: &smolvm::engine::EngineConfig,
    data_root: Option<&Path>,
) -> (String, String) {
    let global = data_root
        .map(|dir| format!(" --state-dir {}", dir.display()))
        .unwrap_or_default();
    let mut local = String::new();
    if config.socket != default.socket {
        local.push_str(&format!(" --socket {}", config.socket.display()));
    }
    if config.root != default.root {
        local.push_str(&format!(" --root {}", config.root.display()));
    }
    (global, local)
}

/// What setup prints for an engine beside the default install.
fn side_by_side_note(
    config: &smolvm::engine::EngineConfig,
    default: &smolvm::engine::EngineConfig,
    data_root: Option<&Path>,
) -> String {
    let (global, local) = engine_flags(config, default, data_root);
    format!(
        "Docker API ready on {socket} (starts automatically).\n\
         This engine does not use the default socket and state directory, so your Docker context, \
         Buildx builder and Testcontainers settings are unchanged. To use it:\n  \
         export DOCKER_HOST={url}\n\
         To remove its registration:\n  \
         smolvm{global} engine unregister{local}",
        socket = config.socket.display(),
        url = integration::socket_url(&config.socket),
    )
}

fn pid_file(config: &smolvm::engine::EngineConfig) -> PathBuf {
    config.root.join("engine.pid")
}

fn start(config: smolvm::engine::EngineConfig) -> smolvm::Result<()> {
    register(&config)?;
    let default = smolvm::engine::EngineConfig::default_paths()?;
    let explicit = smolvm::process::data_root_is_explicit();
    if !is_default_install(&config, &default, explicit) {
        let data_root = explicit
            .then(|| std::env::var_os("SMOLVM_DATA_DIR").map(PathBuf::from))
            .flatten();
        println!(
            "{}",
            side_by_side_note(&config, &default, data_root.as_deref())
        );
        return Ok(());
    }
    let home = smolvm_paths::home_dir()
        .ok_or_else(|| smolvm::Error::config("engine", "no home directory"))?;
    let docker_dir =
        integration::docker_config_dir(&home, std::env::var("DOCKER_CONFIG").ok().as_deref());
    match integration::install_context(
        &docker_dir,
        &config.socket,
        &integration::homebrew_plugin_dirs(),
    ) {
        Ok(outcome) => {
            println!(
                "The docker context '{}' is selected: docker and docker compose use the engine.",
                integration::CONTEXT_NAME
            );
            if let Some(previous) = outcome.previous {
                println!("  (it was '{previous}'; `docker context use {previous}` switches back)");
            }
        }
        Err(e) => eprintln!("warning: could not set up the docker context: {e}"),
    }
    let builder_config = smolvm::engine::builder::config(&config);
    if let Err(error) = install_builder(&builder_config, &docker_dir) {
        eprintln!("warning: Buildx setup did not complete: {error}");
    }
    let properties = home.join(".testcontainers.properties");
    match integration::ensure_testcontainers_host(&properties, &config.socket) {
        Ok(integration::PropertiesOutcome::Other(other)) => eprintln!(
            "note: {} names another engine ({other}); Testcontainers keeps using it",
            properties.display()
        ),
        Ok(_) => {}
        Err(e) => eprintln!("warning: could not write {}: {e}", properties.display()),
    }
    println!(
        "Tools that read only DOCKER_HOST:\n  export DOCKER_HOST={}",
        integration::socket_url(&config.socket)
    );
    Ok(())
}

fn engine_pid(config: &smolvm::engine::EngineConfig) -> Option<i32> {
    let pid: i32 = std::fs::read_to_string(pid_file(config))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    // SAFETY: signal 0 only checks that the process exists.
    (unsafe { libc::kill(pid, 0) } == 0).then_some(pid)
}

fn stop(config: smolvm::engine::EngineConfig) -> smolvm::Result<()> {
    let Some(pid) = engine_pid(&config) else {
        println!("The engine is not running.");
        let _ = std::fs::remove_file(pid_file(&config));
        return Ok(());
    };
    // SAFETY: SIGTERM to the engine process this command recorded starting.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    // Only the adapter exits; workload supervisors continue running.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while std::time::Instant::now() < deadline {
        // SAFETY: signal 0 only checks that the process exists.
        if unsafe { libc::kill(pid, 0) } != 0 {
            let _ = std::fs::remove_file(pid_file(&config));
            println!("The engine stopped.");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(smolvm::Error::config(
        "stop engine",
        format!("the engine (pid {pid}) is still running after 120 s"),
    ))
}

fn status(config: smolvm::engine::EngineConfig, json: bool) -> smolvm::Result<()> {
    let ready = super::engine_activation::registered(&config);
    let pid = engine_pid(&config);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ready": ready, "running": pid.is_some(), "socket": config.socket,
                "root": config.root, "pid": pid, "dockerVersion": smolvm::engine::API_VERSION,
            })
        );
    } else if ready {
        println!(
            "Docker API ready on {} (starts automatically; adapter {}).",
            config.socket.display(),
            if pid.is_some() { "active" } else { "idle" }
        );
    } else {
        println!("Docker socket is not registered. Run `smolvm engine` once to configure it.");
    }
    Ok(())
}

fn link_socket(socket: &Path, print: bool, force: bool) -> smolvm::Result<()> {
    if std::fs::read_link(DEFAULT_SOCKET).is_ok_and(|target| target == socket) {
        println!("{DEFAULT_SOCKET} already links to {}.", socket.display());
        return Ok(());
    }
    if std::fs::symlink_metadata(DEFAULT_SOCKET).is_ok() && !force {
        return Err(smolvm::Error::config(
            "link /var/run/docker.sock",
            format!("{DEFAULT_SOCKET} already exists; pass --force to replace it"),
        ));
    }
    let command = format!("sudo ln -sfn {} {DEFAULT_SOCKET}", socket.display());
    if print {
        println!("{command}");
        return Ok(());
    }
    eprintln!("Running: {command}");
    let status = std::process::Command::new("sudo")
        .args(["ln", "-sfn"])
        .arg(socket)
        .arg(DEFAULT_SOCKET)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(smolvm::Error::config(
            "link /var/run/docker.sock",
            "sudo ln failed",
        ))
    }
}

/// Register one native builder with Buildx; ordinary Docker volumes are unaffected.
fn install_builder(config: &smolvm::engine::EngineConfig, docker_dir: &Path) -> smolvm::Result<()> {
    let endpoint = integration::socket_url(&config.socket);
    let mut inspect = std::process::Command::new("docker");
    let result = inspect
        .env("DOCKER_CONFIG", docker_dir)
        .args(["buildx", "inspect", "smol-builder"])
        .output()?;
    if result.status.success() {
        if !matches_native_builder(&String::from_utf8_lossy(&result.stdout), &endpoint) {
            return Err(smolvm::Error::config(
                "Buildx registration",
                "a different builder named smol-builder already exists; it was not replaced",
            ));
        }
    } else {
        let output = std::process::Command::new("docker")
            .env("DOCKER_CONFIG", docker_dir)
            .args([
                "buildx",
                "create",
                "--name",
                "smol-builder",
                "--driver",
                "remote",
                "--driver-opt",
                "default-load=true",
                &endpoint,
            ])
            .output()?;
        if !output.status.success() {
            return Err(smolvm::Error::config(
                "Buildx registration",
                String::from_utf8_lossy(&output.stderr),
            ));
        }
    }
    let output = std::process::Command::new("docker")
        .env("DOCKER_CONFIG", docker_dir)
        .args(["buildx", "use", "smol-builder"])
        .output()?;
    if !output.status.success() {
        return Err(smolvm::Error::config(
            "select Buildx builder",
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    println!("Buildx uses smol-builder: guest-local build cache, automatic image loading, and shutdown when idle.");
    Ok(())
}

fn register(config: &smolvm::engine::EngineConfig) -> smolvm::Result<()> {
    super::engine_activation::install(config)?;
    super::engine_activation::install_command(
        &smolvm::engine::builder::config(config),
        "buildkit-serve",
    )
}

// `buildx inspect` has no --format flag. Require exactly one matching endpoint;
// never repurpose an existing builder that belongs to another engine or user.
fn matches_native_builder(text: &str, endpoint: &str) -> bool {
    let fields: Vec<_> = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    fields
        .iter()
        .filter(|(key, _)| *key == "Driver")
        .map(|(_, value)| *value)
        .collect::<Vec<_>>()
        == ["remote"]
        && fields
            .iter()
            .filter(|(key, _)| *key == "Endpoint")
            .map(|(_, value)| *value)
            .collect::<Vec<_>>()
            == [endpoint]
}

#[cfg(test)]
mod side_by_side_tests {
    use super::*;
    use smolvm::engine::EngineConfig;

    fn default() -> EngineConfig {
        EngineConfig {
            socket: "/home/me/.smolvm/run/docker.sock".into(),
            root: "/home/me/.local/share/smolvm/engine".into(),
        }
    }

    #[test]
    fn only_the_default_install_changes_the_docker_setup() {
        assert!(is_default_install(&default(), &default(), false));
        // --state-dir or SMOLVM_DATA_DIR: the defaults themselves moved.
        assert!(!is_default_install(&default(), &default(), true));
        let socket = EngineConfig {
            socket: "/tmp/test/docker.sock".into(),
            ..default()
        };
        assert!(!is_default_install(&socket, &default(), false));
        let root = EngineConfig {
            root: "/tmp/test/engine".into(),
            ..default()
        };
        assert!(!is_default_install(&root, &default(), false));
    }

    #[test]
    fn a_side_by_side_engine_is_told_its_socket_and_how_to_remove_it() {
        let moved = EngineConfig {
            socket: "/srv/s/.smolvm/run/docker.sock".into(),
            root: "/srv/s/.local/share/smolvm/engine".into(),
        };
        let note = side_by_side_note(&moved, &moved, Some(Path::new("/srv/s")));
        assert!(note.contains("export DOCKER_HOST=unix:///srv/s/.smolvm/run/docker.sock"));
        assert!(note.ends_with("smolvm --state-dir /srv/s engine unregister"));
        let custom = EngineConfig {
            socket: "/tmp/x/docker.sock".into(),
            root: "/tmp/x/engine".into(),
        };
        let note = side_by_side_note(&custom, &default(), None);
        assert!(note.ends_with(
            "smolvm engine unregister --socket /tmp/x/docker.sock --root /tmp/x/engine"
        ));
    }
}

#[cfg(test)]
mod builder_tests {
    use super::matches_native_builder;
    #[test]
    fn existing_builders_are_only_reused_for_the_same_single_endpoint() {
        let text = "Name: smol-builder\nDriver: remote\nNodes:\nName: smol-builder0\nEndpoint: unix:///tmp/smol.sock\nStatus: running\n";
        assert!(matches_native_builder(text, "unix:///tmp/smol.sock"));
        assert!(!matches_native_builder(text, "unix:///tmp/other.sock"));
        assert!(!matches_native_builder(
            &text.replace("Driver: remote", "Driver: docker-container"),
            "unix:///tmp/smol.sock"
        ));
        assert!(!matches_native_builder(
            &format!("{text}Endpoint: unix:///tmp/smol.sock\n"),
            "unix:///tmp/smol.sock"
        ));
        assert!(!matches_native_builder("", "unix:///tmp/smol.sock"));
    }
}
