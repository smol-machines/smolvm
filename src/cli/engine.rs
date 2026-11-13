//! `smolvm engine`: serve the Docker Engine API from smolvm itself.
//!
//! `smolvm engine start` runs the engine in the background, creates and
//! selects the `smol` docker context, and names the socket for
//! Testcontainers, so `docker`, `docker compose`, Testcontainers and Dev
//! Containers use it with nothing else set. Every container is a machine.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Subcommand};

use super::engine_integration as integration;

/// `/var/run/docker.sock`, the path tools fall back to when nothing names
/// another.
const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

/// Serve the Docker Engine API: every container is a machine
#[derive(Args, Debug)]
pub struct EngineCmd {
    #[command(subcommand)]
    action: EngineAction,
}

#[derive(Subcommand, Debug)]
enum EngineAction {
    /// Start the engine in the background and point docker at it
    Start(SocketArg),
    /// Stop the engine; running containers stop with it
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
    Serve(SocketArg),
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
}

#[derive(Args, Debug, Clone)]
struct SocketArg {
    /// Unix socket the engine listens on [default: ~/.smolvm/run/docker.sock]
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

impl SocketArg {
    fn config(&self) -> smolvm::Result<smolvm::engine::EngineConfig> {
        let mut config = smolvm::engine::EngineConfig::default_paths()?;
        if let Some(socket) = &self.socket {
            config.socket = socket.clone();
        }
        Ok(config)
    }
}

impl EngineCmd {
    /// Run the subcommand.
    pub fn run(self) -> smolvm::Result<()> {
        match self.action {
            EngineAction::Serve(s) => serve(s.config()?),
            EngineAction::Start(s) => start(s.config()?),
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
    runtime.block_on(smolvm::engine::serve(config))
}

fn pid_file(config: &smolvm::engine::EngineConfig) -> PathBuf {
    config.root.join("engine.pid")
}

fn log_file(config: &smolvm::engine::EngineConfig) -> PathBuf {
    config.root.join("engine.log")
}

fn start(config: smolvm::engine::EngineConfig) -> smolvm::Result<()> {
    if integration::engine_ready(&config.socket) {
        println!(
            "The engine is already running on {}.",
            config.socket.display()
        );
    } else {
        spawn_engine(&config)?;
    }
    let home =
        dirs::home_dir().ok_or_else(|| smolvm::Error::config("engine", "no home directory"))?;
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

/// Run `smolvm engine serve` detached, logging to the engine's log file, and
/// wait until it answers.
fn spawn_engine(config: &smolvm::engine::EngineConfig) -> smolvm::Result<()> {
    use std::os::unix::process::CommandExt;
    std::fs::create_dir_all(&config.root)?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file(config))?;
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("engine")
        .arg("serve")
        .arg("--socket")
        .arg(&config.socket)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // SAFETY: setsid in the child before exec; no allocation or locking.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    std::fs::write(pid_file(config), child.id().to_string())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        if integration::engine_ready(&config.socket) {
            println!("The engine is running on {}.", config.socket.display());
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(smolvm::Error::config(
                "start engine",
                format!(
                    "the engine exited ({status}); see {}",
                    log_file(config).display()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(smolvm::Error::config(
        "start engine",
        format!(
            "the engine did not answer within 60 s; see {}",
            log_file(config).display()
        ),
    ))
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
    // Running containers get their stop timeout to exit first.
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
    let running = integration::engine_ready(&config.socket);
    let version = running
        .then(|| integration::engine_version(&config.socket))
        .flatten();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "running": running,
                "socket": config.socket,
                "root": config.root,
                "pid": engine_pid(&config),
                "dockerVersion": version,
            })
        );
    } else if running {
        println!(
            "The engine is running on {} (Docker API {}).",
            config.socket.display(),
            smolvm::engine::API_VERSION
        );
    } else {
        println!("The engine is not running. Start it with `smolvm engine start`.");
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
