//! `smolvm docker`: a Docker engine in a managed machine, usable after one
//! command.
//!
//! `smolvm docker` creates a machine named `docker` from `docker:29-dind`, starts
//! it and waits until the engine answers. It then:
//!
//! - links the engine's socket to a stable path, `~/.smolvm/run/docker.sock`;
//! - creates and selects a docker context named `smol`, so `docker` and
//!   `docker compose` need no `DOCKER_HOST`;
//! - names that socket in `~/.testcontainers.properties`, which Testcontainers
//!   reads before it probes the default socket.
//!
//! Inside the machine:
//!
//! - the home directory is shared at the same path, so bind mounts of absolute
//!   host paths and Dev Containers work unchanged;
//! - the stable socket path resolves to the daemon too, so a container that
//!   mounts `$DOCKER_HOST`'s path (Testcontainers' Ryuk) reaches it, as does one
//!   that mounts `/var/run/docker.sock`;
//! - the machine uses the virtio-net backend, whose gateway answers
//!   `host.docker.internal` for every container and relays it to the host's
//!   loopback, and dockerd's `host-gateway` (compose `extra_hosts`) points at
//!   that gateway.
//!
//! Docker's data lives on two disk volumes (`/var/lib/docker`,
//! `/var/lib/containerd`) on the machine's storage disk. `reset` recreates the
//! machine around the same storage disk, so images, containers and volumes
//! survive unless `--volumes` is given.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};

use super::docker_integration as integration;
use super::vm_common;
use smolvm::config::{RecordState, VmRecord};
use smolvm::db::SmolvmDb;
use smolvm::Error;

/// Name of the managed machine.
pub const MACHINE_NAME: &str = "docker";

/// Label marking a machine as the one `smolvm docker` manages, so a user's own
/// machine that happens to be called `docker` is never adopted or deleted.
const MANAGED_LABEL: &str = "smolvm.docker";
const MANAGED_VALUE: &str = "managed";

/// Label recording that the image was chosen with `--image`, so `reset` keeps
/// it instead of moving to the new default.
const PINNED_IMAGE_LABEL: &str = "smolvm.docker.image";

/// Image the engine runs from. Pinned to a major version so a reset never
/// jumps to an engine that changes behaviour.
pub const DEFAULT_IMAGE: &str = "docker:29-dind";

/// Storage disk size in GiB. Sparse: only what Docker writes takes host space.
pub const DEFAULT_DISK_GIB: u64 = 64;

/// Memory cap in MiB: half of the host's memory, at most this.
pub const MAX_DEFAULT_MEM_MIB: u32 = 8192;

/// How long `start` waits for the engine to answer.
const READY_TIMEOUT: Duration = Duration::from_secs(120);

/// Machine env naming the host's stable socket path, which the boot script
/// makes resolve to the daemon inside the machine.
const ENV_HOST_SOCKET: &str = "SMOLVM_DOCKER_HOST_SOCKET";

/// Machine env listing registry mirrors (space separated) for dockerd.
const ENV_MIRRORS: &str = "SMOLVM_DOCKER_REGISTRY_MIRRORS";

/// The machine's workload. It runs before dockerd, as root, in the machine's
/// container:
///
/// 1. The host's stable socket path resolves to the daemon here too. The home
///    directory is shared, so `~/.smolvm/run` is the host's own directory; a
///    small tmpfs over it keeps the host's link out of reach, and a link in it
///    points at `/var/run/docker.sock`. dockerd resolves bind-mount sources
///    in this namespace, so `-v $SOCK:/var/run/docker.sock` mounts the daemon.
/// 2. `host-gateway` (compose `extra_hosts`, `--add-host x:host-gateway`) maps
///    to the machine's default gateway, which the virtio-net backend relays to
///    the host's loopback.
/// 3. dockerd listens only on the Unix socket: the image's default adds a TCP
///    listener with generated certificates that nothing here uses.
const BOOT_SCRIPT: &str = r#"set -eu
sock="${SMOLVM_DOCKER_HOST_SOCKET:-}"
if [ -n "$sock" ]; then
  dir="${sock%/*}"
  mkdir -p "$dir"
  mountpoint -q "$dir" || mount -t tmpfs -o mode=0755,size=1m smolvm-docker-run "$dir"
  ln -sfn /var/run/docker.sock "$sock"
fi
set -- dockerd --host=unix:///var/run/docker.sock
gateway="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
if [ -n "$gateway" ]; then
  set -- "$@" --host-gateway-ip="$gateway"
fi
for mirror in ${SMOLVM_DOCKER_REGISTRY_MIRRORS:-}; do
  set -- "$@" --registry-mirror="$mirror"
done
exec dockerd-entrypoint.sh "$@"
"#;

/// Run a Docker engine in a managed machine
///
/// With no subcommand, `smolvm docker` is `smolvm docker start`: it creates the
/// machine on first use, starts it, and points the docker CLI at it.
#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct DockerCmd {
    #[command(subcommand)]
    action: Option<DockerAction>,

    #[command(flatten)]
    start: StartArgs,
}

#[derive(Subcommand, Debug)]
enum DockerAction {
    /// Create the Docker machine if needed, start it, and select the `smol`
    /// docker context
    Start(StartArgs),
    /// Stop the Docker machine; images, containers and volumes are kept
    Stop {
        /// Seconds the engine gets to stop its containers
        #[arg(short = 't', long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
    /// Show whether the machine and the engine are up, and where the socket is
    Status {
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Print the engine's log (dockerd's output)
    Logs {
        /// Keep printing new lines
        #[arg(short = 'f', long)]
        follow: bool,
        /// Print only the last N lines
        #[arg(long, value_name = "N")]
        tail: Option<usize>,
    },
    /// Recreate the Docker machine with fresh settings, keeping images,
    /// containers and volumes unless --volumes is given
    Reset(ResetArgs),
    /// Delete the Docker machine and all of its data, the `smol` context and
    /// the socket link
    Delete {
        /// Do not ask for confirmation
        #[arg(short, long)]
        force: bool,
    },
    /// Link /var/run/docker.sock to the engine for tools that only look there
    /// (runs `sudo ln`, which asks for your password)
    LinkSocket {
        /// Print the command instead of running it
        #[arg(long)]
        print: bool,
        /// Replace /var/run/docker.sock even when it is not a link to smolvm
        #[arg(long)]
        force: bool,
    },
}

/// Settings for a new Docker machine. On an existing machine they take effect
/// at the next `smolvm docker reset`.
#[derive(Args, Debug, Default, Clone)]
pub struct StartArgs {
    /// vCPUs (default: every host CPU)
    #[arg(long, value_name = "N")]
    cpus: Option<u8>,
    /// Memory in MiB (default: half the host's memory, at most 8192)
    #[arg(long, value_name = "MiB")]
    mem: Option<u32>,
    /// Size of the disk holding images, containers and volumes, in GiB
    /// (default: 64; sparse)
    #[arg(long, value_name = "GiB")]
    disk: Option<u64>,
    /// Engine image (default: docker:29-dind)
    #[arg(long, value_name = "IMAGE")]
    image: Option<String>,
    /// Registry mirror for the engine, e.g. https://mirror.gcr.io (repeatable)
    #[arg(long = "registry-mirror", value_name = "URL")]
    registry_mirrors: Vec<String>,
    /// Do not share the home directory with containers
    #[arg(long)]
    no_home: bool,
}

/// Arguments of `smolvm docker reset`.
#[derive(Args, Debug, Clone)]
struct ResetArgs {
    /// Also delete images, containers, volumes and build cache
    #[arg(long)]
    volumes: bool,
    #[command(flatten)]
    settings: StartArgs,
}

impl DockerCmd {
    pub fn run(self) -> smolvm::Result<()> {
        refuse_unsupported_host()?;
        let env = HostEnv::detect()?;
        match self.action {
            None => start(&env, &self.start),
            Some(DockerAction::Start(args)) => start(&env, &args),
            Some(DockerAction::Stop { timeout }) => stop(timeout),
            Some(DockerAction::Status { json }) => status(&env, json),
            Some(DockerAction::Logs { follow, tail }) => super::machine::LogsCmd {
                name: Some(managed_record()?.name),
                follow,
                tail,
            }
            .run(),
            Some(DockerAction::Reset(args)) => reset(&env, &args),
            Some(DockerAction::Delete { force }) => delete(&env, force),
            Some(DockerAction::LinkSocket { print, force }) => {
                link_default_socket(&env, print, force)
            }
        }
    }
}

#[cfg(windows)]
fn refuse_unsupported_host() -> smolvm::Result<()> {
    Err(Error::config(
        "Docker machine",
        "the Windows guest kernel has no bridge networking, so dockerd cannot run in a \
         machine on a Windows host (docs/docker-in-machine/references/windows.md)",
    ))
}

#[cfg(not(windows))]
fn refuse_unsupported_host() -> smolvm::Result<()> {
    Ok(())
}

/// The host paths `smolvm docker` touches, resolved once.
struct HostEnv {
    home: PathBuf,
    /// `~/.smolvm/run/docker.sock`, what clients use.
    socket: PathBuf,
    /// The docker CLI's configuration directory.
    docker_config: PathBuf,
    /// `~/.testcontainers.properties`.
    testcontainers: PathBuf,
}

impl HostEnv {
    fn detect() -> smolvm::Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("Docker machine", "no home directory found"))?;
        let docker_config =
            integration::docker_config_dir(&home, std::env::var("DOCKER_CONFIG").ok().as_deref());
        Ok(Self {
            socket: stable_socket_path(&home),
            testcontainers: home.join(".testcontainers.properties"),
            docker_config,
            home,
        })
    }

    /// The socket libkrun serves for the machine, in its data directory.
    fn machine_socket(&self) -> PathBuf {
        smolvm::agent::vm_data_dir(MACHINE_NAME).join("docker.sock")
    }
}

/// The command the user typed this through, `smol` or `smolvm`, for the hints
/// this module prints.
fn cli() -> &'static str {
    let stem = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.file_stem().map(|s| s.to_string_lossy().into_owned()));
    front_end_name(stem.as_deref())
}

fn front_end_name(exe_stem: Option<&str>) -> &'static str {
    match exe_stem {
        Some("smol") | Some("smol-bin") => "smol",
        _ => "smolvm",
    }
}

/// The stable socket path clients use.
pub fn stable_socket_path(home: &Path) -> PathBuf {
    home.join(".smolvm").join("run").join("docker.sock")
}

/// The settings a machine is created with, after defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MachineSettings {
    cpus: u8,
    mem: u32,
    disk_gib: u64,
    image: String,
    image_pinned: bool,
    registry_mirrors: Vec<String>,
    share_home: bool,
}

impl MachineSettings {
    /// Defaults for this host, overridden by explicit arguments.
    fn new(args: &StartArgs, host: &HostResources) -> Self {
        Self {
            cpus: args.cpus.unwrap_or_else(|| host.default_cpus()),
            mem: args.mem.unwrap_or_else(|| host.default_mem_mib()),
            disk_gib: args.disk.unwrap_or(DEFAULT_DISK_GIB),
            image: args
                .image
                .clone()
                .unwrap_or_else(|| DEFAULT_IMAGE.to_string()),
            image_pinned: args.image.is_some(),
            registry_mirrors: args.registry_mirrors.clone(),
            share_home: !args.no_home,
        }
    }

    /// The settings an existing machine was created with, so `reset` keeps
    /// them; explicit arguments win.
    fn from_record(record: &VmRecord, home: &Path, args: &StartArgs) -> Self {
        let image_pinned = record.labels.contains_key(PINNED_IMAGE_LABEL);
        let home_target = home.display().to_string();
        let mirrors = record
            .env
            .iter()
            .find(|(key, _)| key == ENV_MIRRORS)
            .map(|(_, value)| value.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        Self {
            cpus: args.cpus.unwrap_or(record.cpus),
            mem: args.mem.unwrap_or(record.mem),
            disk_gib: args
                .disk
                .unwrap_or_else(|| record.storage_gb.unwrap_or(DEFAULT_DISK_GIB)),
            image: match (&args.image, image_pinned, &record.image) {
                (Some(image), _, _) => image.clone(),
                (None, true, Some(image)) => image.clone(),
                _ => DEFAULT_IMAGE.to_string(),
            },
            image_pinned: args.image.is_some() || image_pinned,
            registry_mirrors: if args.registry_mirrors.is_empty() {
                mirrors
            } else {
                args.registry_mirrors.clone()
            },
            share_home: !args.no_home
                && record
                    .mounts
                    .iter()
                    .any(|(_, target, _)| *target == home_target),
        }
    }

    /// `machine create` arguments for this machine, after the subcommand.
    fn create_args(&self, home: &Path, socket: &Path) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "--name".into(),
            MACHINE_NAME.into(),
            "--label".into(),
            format!("{MANAGED_LABEL}={MANAGED_VALUE}"),
            "--image".into(),
            self.image.clone(),
            "--cpus".into(),
            self.cpus.to_string(),
            "--mem".into(),
            self.mem.to_string(),
            "--storage".into(),
            self.disk_gib.to_string(),
            "--net".into(),
            // The virtio-net gateway answers host.docker.internal and relays
            // the gateway address to the host's loopback; Docker's bridge NAT
            // runs over a real interface.
            "--net-backend".into(),
            "virtio-net".into(),
            "--docker-socket".into(),
            "-v".into(),
            "/var/lib/docker".into(),
            "-v".into(),
            "/var/lib/containerd".into(),
        ];
        if self.image_pinned {
            args.extend(["--label".into(), format!("{PINNED_IMAGE_LABEL}=pinned")]);
        }
        if self.share_home {
            let home = home.display().to_string();
            args.extend(["-v".into(), format!("{home}:{home}")]);
        }
        args.extend([
            "-e".into(),
            format!("{ENV_HOST_SOCKET}={}", socket.display()),
        ]);
        if !self.registry_mirrors.is_empty() {
            args.extend([
                "-e".into(),
                format!("{ENV_MIRRORS}={}", self.registry_mirrors.join(" ")),
            ]);
        }
        args.extend([
            "--".into(),
            "/bin/sh".into(),
            "-c".into(),
            BOOT_SCRIPT.into(),
        ]);
        args
    }
}

/// Host size, for the default caps.
struct HostResources {
    cpus: usize,
    mem_bytes: Option<u64>,
}

impl HostResources {
    fn detect() -> Self {
        Self {
            cpus: std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(smolvm::data::resources::DEFAULT_MICROVM_CPU_COUNT as usize),
            mem_bytes: host_memory_bytes(),
        }
    }

    fn default_cpus(&self) -> u8 {
        u8::try_from(self.cpus.max(1)).unwrap_or(u8::MAX)
    }

    /// min(50% of RAM, 8 GiB). An 8 GB Mac keeps half its memory for itself
    /// instead of handing all of it to the engine.
    fn default_mem_mib(&self) -> u32 {
        match self.mem_bytes {
            Some(bytes) => {
                let half_mib = bytes / 2 / (1024 * 1024);
                u32::try_from(half_mib)
                    .unwrap_or(u32::MAX)
                    .clamp(1024, MAX_DEFAULT_MEM_MIB)
            }
            None => MAX_DEFAULT_MEM_MIB / 2,
        }
    }
}

#[cfg(target_os = "macos")]
fn host_memory_bytes() -> Option<u64> {
    let mut total = 0u64;
    let mut len = std::mem::size_of_val(&total);
    // SAFETY: `total` is a u64 and `len` its size, as hw.memsize expects.
    let rc = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut total as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == 8 && total > 0).then_some(total)
}

#[cfg(target_os = "linux")]
fn host_memory_bytes() -> Option<u64> {
    smolvm::process::host_memory_stats().map(|stats| stats.total_bytes)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn host_memory_bytes() -> Option<u64> {
    None
}

/// The managed machine's record, or `None` when there is none. A machine
/// called `docker` that `smolvm docker` did not create is an error, never
/// adopted.
fn find_managed(db: &SmolvmDb) -> smolvm::Result<Option<VmRecord>> {
    let Some(record) = db.get_vm(MACHINE_NAME)? else {
        return Ok(None);
    };
    if record.labels.get(MANAGED_LABEL).map(String::as_str) != Some(MANAGED_VALUE) {
        return Err(Error::config(
            "Docker machine",
            format!(
                "a machine named '{MACHINE_NAME}' exists that `{cli} docker` did not create; \
                 rename or delete it (`{cli} machine delete --name {MACHINE_NAME}`) first",
                cli = cli()
            ),
        ));
    }
    Ok(Some(record))
}

fn managed_record() -> smolvm::Result<VmRecord> {
    find_managed(&SmolvmDb::open()?)?.ok_or_else(|| {
        Error::config(
            "Docker machine",
            format!(
                "there is no Docker machine yet; run `{} docker` to create it",
                cli()
            ),
        )
    })
}

fn is_running(record: &VmRecord) -> bool {
    smolvm::agent::state_probe::resolve_state(&record.name, record) == RecordState::Running
}

/// Create the machine through `machine create`'s own path, so every option is
/// validated and recorded exactly as the CLI does it.
fn create_machine(settings: &MachineSettings, env: &HostEnv) -> smolvm::Result<VmRecord> {
    #[derive(Parser)]
    #[command(name = "smolvm-docker-create", no_binary_name = true)]
    struct CreateArgv {
        #[command(flatten)]
        create: super::machine::CreateCmd,
    }
    let argv = settings.create_args(&env.home, &env.socket);
    let parsed = CreateArgv::try_parse_from(&argv)
        .map_err(|e| Error::config("create the Docker machine", e.to_string()))?;
    parsed.create.create()
}

fn start_machine(env: &HostEnv) -> smolvm::Result<()> {
    // The boot script mounts over the socket's directory inside the machine;
    // with the home directory shared, that is this directory.
    if let Some(dir) = env.socket.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::config("create the socket directory", e.to_string()))?;
    }
    vm_common::start_vm_named(
        MACHINE_NAME,
        None,
        None,
        false,
        vm_common::ForkLaunch::default(),
        vm_common::StartOptions::default(),
    )
}

fn start(env: &HostEnv, args: &StartArgs) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;
    let existing = find_managed(&db)?;
    let created = existing.is_none();
    let record = match existing {
        Some(record) => {
            if args_given(args) {
                eprintln!(
                    "note: the Docker machine already exists; `{} docker reset` applies \
                     new settings and keeps your images, containers and volumes",
                    cli()
                );
            }
            record
        }
        None => {
            let settings = MachineSettings::new(args, &HostResources::detect());
            eprintln!(
                "Creating the Docker machine ({}, {} CPUs, {} MiB, {} GiB disk)...",
                settings.image, settings.cpus, settings.mem, settings.disk_gib
            );
            let record = create_machine(&settings, env)?;
            restore_held_storage(MACHINE_NAME)?;
            record
        }
    };
    drop(db);

    if !created && held_storage_dir().exists() {
        eprintln!(
            "warning: storage kept from an interrupted reset is still at {}; \
             `{} docker reset` finishes it",
            held_storage_dir().display(),
            cli()
        );
    }

    if !is_running(&record) {
        start_machine(env)?;
    }
    wire_host(env)?;
    wait_until_ready(env)?;
    Ok(())
}

fn args_given(args: &StartArgs) -> bool {
    args.cpus.is_some()
        || args.mem.is_some()
        || args.disk.is_some()
        || args.image.is_some()
        || !args.registry_mirrors.is_empty()
        || args.no_home
}

/// Link the stable socket, select the context, name the socket for
/// Testcontainers, and say what changed.
fn wire_host(env: &HostEnv) -> smolvm::Result<()> {
    integration::link_socket(&env.socket, &env.machine_socket())
        .map_err(|e| Error::config("link the Docker socket", e.to_string()))?;
    let outcome = integration::install_context(
        &env.docker_config,
        &env.socket,
        &integration::homebrew_plugin_dirs(),
    )
    .map_err(|e| Error::config("set up the docker context", e.to_string()))?;
    if let Some(previous) = outcome.previous {
        eprintln!(
            "Switched the docker context from '{previous}' to '{}' \
             (`docker context use {previous}` switches back)",
            integration::CONTEXT_NAME
        );
    }
    if let Some(dir) = outcome.plugin_dir_added {
        eprintln!("Pointed the docker CLI at its plugins in {dir} (docker compose, buildx)");
    }
    if std::env::var_os("DOCKER_HOST").is_some() {
        eprintln!(
            "note: DOCKER_HOST is set in this shell and overrides the '{}' context; \
             unset it to use the Docker machine",
            integration::CONTEXT_NAME
        );
    }
    match integration::ensure_testcontainers_host(&env.testcontainers, &env.socket) {
        Ok(integration::PropertiesOutcome::Other(host)) => eprintln!(
            "note: {} sends Testcontainers to {host}; set docker.host={} to use this engine",
            env.testcontainers.display(),
            integration::socket_url(&env.socket)
        ),
        Ok(_) => {}
        Err(e) => eprintln!(
            "warning: could not update {}: {e}",
            env.testcontainers.display()
        ),
    }
    Ok(())
}

fn wait_until_ready(env: &HostEnv) -> smolvm::Result<()> {
    let started = Instant::now();
    while !integration::engine_ready(&env.socket) {
        if started.elapsed() > READY_TIMEOUT {
            return Err(Error::agent(
                "start the Docker engine",
                format!(
                    "the engine did not answer within {}s; see `{} docker logs`",
                    READY_TIMEOUT.as_secs(),
                    cli()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let version = integration::engine_version(&env.socket).unwrap_or_else(|| "?".into());
    println!(
        "Docker {version} is ready ({:.1}s). The '{}' context is selected: docker and docker \
         compose work with no DOCKER_HOST.",
        started.elapsed().as_secs_f64(),
        integration::CONTEXT_NAME
    );
    println!("Socket: {}", env.socket.display());
    if !default_socket_is_ours(env) {
        println!(
            "Tools that only look at /var/run/docker.sock: `{} docker link-socket` \
             (asks for your password).",
            cli()
        );
    }
    Ok(())
}

fn stop(timeout: Option<u64>) -> smolvm::Result<()> {
    let record = managed_record()?;
    if !is_running(&record) {
        println!("The Docker machine is not running.");
        return Ok(());
    }
    vm_common::stop_vm_named_with_timeout(MACHINE_NAME, timeout.map(Duration::from_secs))?;
    println!("Stopped the Docker machine. Images, containers and volumes are kept.");
    Ok(())
}

fn status(env: &HostEnv, json: bool) -> smolvm::Result<()> {
    let record = find_managed(&SmolvmDb::open()?)?;
    let state = record
        .as_ref()
        .map(|r| smolvm::agent::state_probe::resolve_state(&r.name, r).to_string());
    let engine = record
        .as_ref()
        .filter(|r| is_running(r))
        .and_then(|_| integration::engine_version(&env.socket));
    let context = integration::current_context(&env.docker_config);
    let context_selected = context.as_deref() == Some(integration::CONTEXT_NAME);
    if json {
        let value = serde_json::json!({
            "machine": record.as_ref().map(|r| r.name.clone()),
            "state": state,
            "engine_version": engine,
            "socket": env.socket,
            "context": integration::CONTEXT_NAME,
            "context_selected": context_selected,
            "default_socket_linked": default_socket_is_ours(env),
            "image": record.as_ref().and_then(|r| r.image.clone()),
            "cpus": record.as_ref().map(|r| r.cpus),
            "mem_mib": record.as_ref().map(|r| r.mem),
            "disk_gib": record.as_ref().and_then(|r| r.storage_gb),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
        return Ok(());
    }
    let Some(record) = record else {
        println!(
            "No Docker machine. `{} docker` creates and starts one.",
            cli()
        );
        return Ok(());
    };
    println!(
        "Machine: {} ({}, {} CPUs, {} MiB, {} GiB disk)",
        state.unwrap_or_default(),
        record.image.as_deref().unwrap_or("?"),
        record.cpus,
        record.mem,
        record.storage_gb.unwrap_or(DEFAULT_DISK_GIB)
    );
    println!(
        "Engine:  {}",
        engine.map_or_else(|| "not answering".to_string(), |v| format!("Docker {v}"))
    );
    println!("Socket:  {}", env.socket.display());
    println!(
        "Context: {}{}",
        integration::CONTEXT_NAME,
        if context_selected {
            " (selected)".to_string()
        } else {
            format!(
                " (not selected; current is '{}')",
                context.as_deref().unwrap_or("default")
            )
        }
    );
    println!(
        "/var/run/docker.sock: {}",
        if default_socket_is_ours(env) {
            "linked".to_string()
        } else {
            format!("not linked (`{} docker link-socket`)", cli())
        }
    );
    Ok(())
}

/// Where `reset` keeps the storage disk while it recreates the machine. On the
/// same filesystem as machine data directories, so moving is a rename.
fn held_storage_dir() -> PathBuf {
    smolvm::agent::vm_cache_root().join("docker-reset-storage")
}

/// The storage disk's files in a machine data directory: the disk
/// (`storage.raw` or `storage.qcow2`) and its markers (`storage.formatted`,
/// the seed source).
fn storage_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("storage.") {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Move every storage file from `from` into `to` (created), refusing to
/// overwrite.
fn move_storage(from: &Path, to: &Path) -> std::io::Result<usize> {
    let files = storage_files(from)?;
    std::fs::create_dir_all(to)?;
    for file in &files {
        let Some(name) = file.file_name() else {
            continue;
        };
        let dest = to.join(name);
        if dest.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", dest.display()),
            ));
        }
        std::fs::rename(file, &dest)?;
    }
    Ok(files.len())
}

/// Put storage held by an interrupted or in-progress reset into the new
/// machine's data directory, before its first start.
fn restore_held_storage(name: &str) -> smolvm::Result<()> {
    let held = held_storage_dir();
    if !held.exists() {
        return Ok(());
    }
    let dir = smolvm::agent::ensure_vm_dir(name)
        .map_err(|e| Error::config("restore Docker data", e.to_string()))?;
    if !storage_files(&dir)
        .map_err(|e| Error::config("restore Docker data", e.to_string()))?
        .is_empty()
    {
        return Err(Error::config(
            "restore Docker data",
            format!(
                "the new machine already has a storage disk; the previous one is still at {}",
                held.display()
            ),
        ));
    }
    move_storage(&held, &dir).map_err(|e| {
        Error::config(
            "restore Docker data",
            format!("{e}; the previous disk is still at {}", held.display()),
        )
    })?;
    std::fs::remove_dir(&held).map_err(|e| Error::config("restore Docker data", e.to_string()))
}

fn reset(env: &HostEnv, args: &ResetArgs) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;
    let Some(record) = find_managed(&db)? else {
        drop(db);
        if args.volumes {
            discard_held_storage()?;
        }
        return start(env, &args.settings);
    };
    drop(db);
    let mut settings = MachineSettings::from_record(&record, &env.home, &args.settings);
    let existing_disk = record.storage_gb.unwrap_or(DEFAULT_DISK_GIB);
    if !args.volumes && settings.disk_gib < existing_disk {
        return Err(Error::config(
            "reset the Docker machine",
            format!(
                "the disk holding your Docker data is {existing_disk} GiB and cannot shrink to \
                 {} GiB; pass --volumes to start over with an empty disk",
                settings.disk_gib
            ),
        ));
    }
    if !args.volumes {
        settings.disk_gib = settings.disk_gib.max(existing_disk);
    }

    if is_running(&record) {
        eprintln!("Stopping the Docker machine...");
        vm_common::stop_vm_named(MACHINE_NAME)?;
    }
    if args.volumes {
        discard_held_storage()?;
    } else {
        let held = held_storage_dir();
        if held.exists() {
            return Err(Error::config(
                "reset the Docker machine",
                format!(
                    "storage from an earlier reset is still at {}; remove it or run \
                     `{} docker reset --volumes`",
                    held.display(),
                    cli()
                ),
            ));
        }
        let moved = move_storage(&smolvm::agent::vm_data_dir(MACHINE_NAME), &held)
            .map_err(|e| Error::config("keep Docker data", e.to_string()))?;
        tracing::debug!(files = moved, "held the Docker machine's storage disk");
    }
    vm_common::delete_vm(
        MACHINE_NAME,
        true,
        vm_common::DeleteVmOptions {
            stop_if_running: true,
            cascade: false,
        },
    )?;
    eprintln!(
        "Recreating the Docker machine ({}, {} CPUs, {} MiB, {} GiB disk){}...",
        settings.image,
        settings.cpus,
        settings.mem,
        settings.disk_gib,
        if args.volumes {
            ", with no Docker data"
        } else {
            ", keeping images, containers and volumes"
        }
    );
    create_machine(&settings, env)?;
    restore_held_storage(MACHINE_NAME)?;
    start_machine(env)?;
    wire_host(env)?;
    wait_until_ready(env)
}

fn discard_held_storage() -> smolvm::Result<()> {
    let held = held_storage_dir();
    match std::fs::remove_dir_all(&held) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::config("remove held Docker data", e.to_string())),
    }
}

fn delete(env: &HostEnv, force: bool) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;
    let record = find_managed(&db)?;
    drop(db);
    if record.is_some() && !force && !confirm_delete()? {
        println!("Kept the Docker machine.");
        return Ok(());
    }
    if record.is_some() {
        vm_common::delete_vm(
            MACHINE_NAME,
            true,
            vm_common::DeleteVmOptions {
                stop_if_running: true,
                cascade: false,
            },
        )?;
    }
    discard_held_storage()?;
    let machine_socket = env.machine_socket();
    let cleanup = [
        integration::unlink_socket(&env.socket, &machine_socket),
        integration::remove_context(&env.docker_config, &env.socket),
        integration::remove_testcontainers_host(&env.testcontainers, &env.socket),
    ];
    for result in cleanup {
        if let Err(e) = result {
            eprintln!("warning: {e}");
        }
    }
    println!(
        "Deleted the Docker machine, its data and the '{}' context.",
        integration::CONTEXT_NAME
    );
    if default_socket_is_ours(env) {
        println!(
            "/var/run/docker.sock still links to it: `sudo rm /var/run/docker.sock` removes it."
        );
    }
    Ok(())
}

fn confirm_delete() -> smolvm::Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(Error::config(
            "delete the Docker machine",
            "this deletes every image, container and volume; pass --force to confirm",
        ));
    }
    eprint!("Delete the Docker machine with every image, container and volume? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| Error::config("read confirmation", e.to_string()))?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// `/var/run/docker.sock`, the path tools fall back to.
const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

fn default_socket_is_ours(env: &HostEnv) -> bool {
    std::fs::read_link(DEFAULT_SOCKET).is_ok_and(|target| target == env.socket)
}

fn link_default_socket(env: &HostEnv, print: bool, force: bool) -> smolvm::Result<()> {
    if default_socket_is_ours(env) {
        println!(
            "{DEFAULT_SOCKET} already links to {}.",
            env.socket.display()
        );
        return Ok(());
    }
    let occupied = std::fs::symlink_metadata(DEFAULT_SOCKET).is_ok();
    if occupied && !force {
        return Err(Error::config(
            "link /var/run/docker.sock",
            format!(
                "{DEFAULT_SOCKET} already exists and belongs to another engine; pass --force \
                 to replace it"
            ),
        ));
    }
    let command = format!("sudo ln -sfn {} {DEFAULT_SOCKET}", env.socket.display());
    if print {
        println!("{command}");
        return Ok(());
    }
    eprintln!("Running: {command}");
    let status = std::process::Command::new("sudo")
        .args(["ln", "-sfn"])
        .arg(&env.socket)
        .arg(DEFAULT_SOCKET)
        .status()
        .map_err(|e| Error::config("run sudo", e.to_string()))?;
    if !status.success() {
        return Err(Error::config(
            "link /var/run/docker.sock",
            format!("sudo ln exited with {status}"),
        ));
    }
    println!(
        "Linked {DEFAULT_SOCKET} to {}. macOS clears /var/run at boot; run this again after a \
         restart.",
        env.socket.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(cpus: usize, mem_gib: u64) -> HostResources {
        HostResources {
            cpus,
            mem_bytes: Some(mem_gib * 1024 * 1024 * 1024),
        }
    }

    #[test]
    fn memory_default_is_half_of_ram_capped_at_8_gib() {
        assert_eq!(host(8, 8).default_mem_mib(), 4096);
        assert_eq!(host(8, 16).default_mem_mib(), 8192);
        assert_eq!(host(8, 64).default_mem_mib(), 8192);
        assert_eq!(host(8, 1).default_mem_mib(), 1024, "never below 1 GiB");
        let unknown = HostResources {
            cpus: 4,
            mem_bytes: None,
        };
        assert_eq!(unknown.default_mem_mib(), 4096);
    }

    #[test]
    fn cpu_default_is_every_host_cpu() {
        assert_eq!(host(8, 8).default_cpus(), 8);
        assert_eq!(host(1000, 8).default_cpus(), 255);
    }

    #[test]
    fn create_args_describe_the_managed_machine() {
        let settings = MachineSettings::new(&StartArgs::default(), &host(8, 8));
        let home = Path::new("/Users/me");
        let socket = stable_socket_path(home);
        let args = settings.create_args(home, &socket);
        let dash = args.iter().position(|a| a == "--").unwrap();
        let joined = args[..dash].join(" ");
        for expected in [
            "--name docker",
            "--label smolvm.docker=managed",
            "--image docker:29-dind",
            "--cpus 8",
            "--mem 4096",
            "--storage 64",
            "--net --net-backend virtio-net",
            "--docker-socket",
            "-v /var/lib/docker -v /var/lib/containerd",
            "-v /Users/me:/Users/me",
            "-e SMOLVM_DOCKER_HOST_SOCKET=/Users/me/.smolvm/run/docker.sock",
        ] {
            assert!(
                joined.contains(expected),
                "missing `{expected}` in {joined}"
            );
        }
        assert!(!joined.contains(PINNED_IMAGE_LABEL));
        assert!(!joined.contains(ENV_MIRRORS));
        assert_eq!(&args[dash + 1..dash + 3], ["/bin/sh", "-c"]);
        assert_eq!(args[dash + 3], BOOT_SCRIPT);
        assert_eq!(args.len(), dash + 4);
    }

    #[test]
    fn create_args_carry_explicit_choices() {
        let args = StartArgs {
            cpus: Some(2),
            mem: Some(3000),
            disk: Some(100),
            image: Some("docker:28-dind".into()),
            registry_mirrors: vec!["https://mirror.gcr.io".into(), "https://m2".into()],
            no_home: true,
        };
        let settings = MachineSettings::new(&args, &host(8, 8));
        let args = settings.create_args(Path::new("/home/me"), Path::new("/s"));
        let dash = args.iter().position(|a| a == "--").unwrap();
        let joined = args[..dash].join(" ");
        assert!(joined.contains("--cpus 2 --mem 3000 --storage 100"));
        assert!(joined.contains("--image docker:28-dind"));
        assert!(joined.contains("--label smolvm.docker.image=pinned"));
        assert!(
            joined.contains("-e SMOLVM_DOCKER_REGISTRY_MIRRORS=https://mirror.gcr.io https://m2")
        );
        assert!(!joined.contains("/home/me:/home/me"));
        assert!(
            joined.contains("-e SMOLVM_DOCKER_HOST_SOCKET=/s"),
            "the socket path resolves in the machine even without the home share"
        );
    }

    #[test]
    fn create_args_parse_as_machine_create() {
        #[derive(Parser)]
        #[command(no_binary_name = true)]
        struct CreateArgv {
            #[command(flatten)]
            create: crate::cli::machine::CreateCmd,
        }
        let settings = MachineSettings::new(
            &StartArgs {
                registry_mirrors: vec!["https://mirror.gcr.io".into()],
                ..StartArgs::default()
            },
            &host(4, 16),
        );
        let home = Path::new("/Users/me");
        let parsed =
            CreateArgv::try_parse_from(settings.create_args(home, &stable_socket_path(home)))
                .unwrap();
        let create = parsed.create;
        assert_eq!(create.name.as_deref(), Some("docker"));
        assert_eq!(create.cpus, Some(4));
        assert_eq!(create.mem, Some(8192));
        assert!(create.docker_socket && create.net);
        assert_eq!(
            create.net_backend,
            Some(smolvm::network::NetworkBackend::VirtioNet)
        );
        assert_eq!(
            create.volume,
            [
                "/var/lib/docker",
                "/var/lib/containerd",
                "/Users/me:/Users/me"
            ]
        );
        assert_eq!(create.command, ["/bin/sh", "-c", BOOT_SCRIPT]);
    }

    fn record_from(settings: &MachineSettings, home: &Path) -> VmRecord {
        let args = settings.create_args(home, &stable_socket_path(home));
        let mut record = VmRecord::new(
            MACHINE_NAME.into(),
            settings.cpus,
            settings.mem,
            vec![],
            vec![],
            true,
        );
        record.storage_gb = Some(settings.disk_gib);
        record.image = Some(settings.image.clone());
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--label" => {
                    let (k, v) = iter.next().unwrap().split_once('=').unwrap();
                    record.labels.insert(k.into(), v.into());
                }
                "-e" => {
                    let (k, v) = iter.next().unwrap().split_once('=').unwrap();
                    record.env.push((k.into(), v.into()));
                }
                "-v" => {
                    if let Some((h, g)) = iter.next().unwrap().split_once(':') {
                        record.mounts.push((h.into(), g.into(), false));
                    }
                }
                _ => {}
            }
        }
        record
    }

    #[test]
    fn reset_keeps_the_machines_settings_unless_overridden() {
        let home = Path::new("/Users/me");
        let original = MachineSettings::new(
            &StartArgs {
                cpus: Some(3),
                mem: Some(5000),
                disk: Some(80),
                registry_mirrors: vec!["https://mirror.gcr.io".into()],
                ..StartArgs::default()
            },
            &host(8, 8),
        );
        let record = record_from(&original, home);
        let kept = MachineSettings::from_record(&record, home, &StartArgs::default());
        assert_eq!(kept, original);

        let changed = MachineSettings::from_record(
            &record,
            home,
            &StartArgs {
                mem: Some(2048),
                no_home: true,
                ..StartArgs::default()
            },
        );
        assert_eq!(changed.mem, 2048);
        assert!(!changed.share_home);
        assert_eq!(changed.cpus, 3);
    }

    #[test]
    fn reset_moves_an_unpinned_image_to_the_default_and_keeps_a_pinned_one() {
        let home = Path::new("/Users/me");
        let mut record = record_from(
            &MachineSettings::new(&StartArgs::default(), &host(4, 8)),
            home,
        );
        record.image = Some("docker:28-dind".into());
        let settings = MachineSettings::from_record(&record, home, &StartArgs::default());
        assert_eq!(settings.image, DEFAULT_IMAGE);
        assert!(!settings.image_pinned);

        let pinned = MachineSettings::new(
            &StartArgs {
                image: Some("registry.example/docker:dind".into()),
                ..StartArgs::default()
            },
            &host(4, 8),
        );
        let record = record_from(&pinned, home);
        let settings = MachineSettings::from_record(&record, home, &StartArgs::default());
        assert_eq!(settings.image, "registry.example/docker:dind");
        assert!(settings.image_pinned);
    }

    #[test]
    fn storage_moves_with_its_markers_and_never_overwrites() {
        let root = tempfile::tempdir().unwrap();
        let machine = root.path().join("vm");
        let held = root.path().join("held");
        std::fs::create_dir_all(&machine).unwrap();
        for name in [
            "storage.raw",
            "storage.formatted",
            "storage.seed",
            "overlay.raw",
            "agent.sock",
        ] {
            std::fs::write(machine.join(name), name).unwrap();
        }
        assert_eq!(move_storage(&machine, &held).unwrap(), 3);
        let mut moved: Vec<String> = std::fs::read_dir(&held)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        moved.sort();
        assert_eq!(moved, ["storage.formatted", "storage.raw", "storage.seed"]);
        assert!(
            machine.join("overlay.raw").exists(),
            "the overlay is not kept"
        );

        std::fs::write(machine.join("storage.raw"), "new").unwrap();
        let err = move_storage(&machine, &held).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(held.join("storage.raw")).unwrap(),
            "storage.raw"
        );
    }

    #[test]
    fn boot_script_is_valid_sh_and_execs_the_image_entrypoint() {
        assert!(BOOT_SCRIPT.contains("exec dockerd-entrypoint.sh \"$@\""));
        assert!(BOOT_SCRIPT.contains("--host-gateway-ip="));
        assert!(BOOT_SCRIPT.contains(ENV_HOST_SOCKET));
        assert!(BOOT_SCRIPT.contains(ENV_MIRRORS));
        if let Ok(status) = std::process::Command::new("sh")
            .args(["-n", "-c", BOOT_SCRIPT])
            .status()
        {
            assert!(status.success(), "sh -n rejected the boot script");
        }
    }

    #[test]
    fn hints_name_the_front_end_that_was_run() {
        assert_eq!(front_end_name(Some("smol")), "smol");
        assert_eq!(front_end_name(Some("smolvm")), "smolvm");
        assert_eq!(front_end_name(Some("smolvm-bin")), "smolvm");
        assert_eq!(front_end_name(None), "smolvm");
    }

    #[test]
    fn bare_docker_is_start_and_subcommands_parse() {
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            docker: DockerCmd,
        }
        let bare = Cli::try_parse_from(["smolvm", "--mem", "2048"]).unwrap();
        assert!(bare.docker.action.is_none());
        assert_eq!(bare.docker.start.mem, Some(2048));
        let reset = Cli::try_parse_from(["smolvm", "reset", "--volumes", "--cpus", "2"]).unwrap();
        match reset.docker.action {
            Some(DockerAction::Reset(args)) => {
                assert!(args.volumes);
                assert_eq!(args.settings.cpus, Some(2));
            }
            other => panic!("expected reset, got {other:?}"),
        }
        assert!(matches!(
            Cli::try_parse_from(["smolvm", "link-socket", "--print"])
                .unwrap()
                .docker
                .action,
            Some(DockerAction::LinkSocket {
                print: true,
                force: false
            })
        ));
    }
}
