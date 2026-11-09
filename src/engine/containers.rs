//! Containers: each one a machine, booted on start and stopped when its
//! command exits.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::filters::Filters;
use super::images::ImageRecord;
use super::model::{ContainerConfig, CreateRequest, HealthConfig, HostConfig};
use super::runtime::{Exit, Input, InputQueue, Output};
use super::util::{ApiError, ApiResult};
use super::Engine;

/// Label naming the engine container a machine belongs to.
pub(crate) const MACHINE_LABEL: &str = "smolvm.engine/container";

/// What a container is doing, persisted with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StateRecord {
    /// `created`, `running`, `paused`, `restarting`, `removing`, `exited` or `dead`.
    pub status: String,
    pub pid: i64,
    pub exit_code: i64,
    pub error: String,
    pub started_at: String,
    pub finished_at: String,
    pub oom_killed: bool,
    #[serde(default)]
    pub health: Option<HealthRecord>,
}

impl Default for StateRecord {
    fn default() -> Self {
        Self {
            status: "created".into(),
            pid: 0,
            exit_code: 0,
            error: String::new(),
            started_at: super::util::ZERO_TIME.into(),
            finished_at: super::util::ZERO_TIME.into(),
            oom_killed: false,
            health: None,
        }
    }
}

/// A container's health, as `State.Health` reports it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct HealthRecord {
    pub status: String,
    pub failing_streak: i64,
    pub log: Vec<HealthProbe>,
}

/// One health check run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HealthProbe {
    pub start: String,
    pub end: String,
    pub exit_code: i64,
    pub output: String,
}

/// A container port published on the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PublishedPort {
    pub container_port: u16,
    /// `tcp` or `udp`.
    pub proto: String,
    pub host_ip: String,
    pub host_port: u16,
}

impl PublishedPort {
    /// The addresses the port listens on, as Docker lists them: the IPv4
    /// wildcard also stands for the IPv6 one.
    pub(crate) fn listen_ips(&self) -> Vec<&str> {
        if self.host_ip == "0.0.0.0" {
            vec!["0.0.0.0", "::"]
        } else {
            vec![self.host_ip.as_str()]
        }
    }

    /// The address the machine's port listens on.
    pub(crate) fn listen(&self) -> Option<std::net::IpAddr> {
        self.host_ip.parse().ok()
    }
}

/// A mount, resolved to what the machine shares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct MountRecord {
    /// `bind`, `volume` or `tmpfs`.
    pub kind: String,
    /// Host path (bind), volume name (volume), empty (tmpfs).
    pub source: String,
    pub destination: String,
    pub read_only: bool,
    /// Index of the machine share serving it (bind and volume).
    #[serde(default)]
    pub share: Option<usize>,
    /// For a bind of one file: its name below the shared directory.
    #[serde(default)]
    pub subpath: Option<String>,
    /// Bind or volume mode string, as given (`ro`, `z`, ...).
    #[serde(default)]
    pub mode: String,
    /// tmpfs mount options.
    #[serde(default)]
    pub options: Vec<String>,
    /// Fill a new volume from the image (volume mounts).
    #[serde(default)]
    pub copy_up: bool,
    /// A host socket made reachable at `destination` instead of a share.
    #[serde(default)]
    pub socket: bool,
}

/// One network a container is attached to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EndpointRecord {
    pub network_id: String,
    pub endpoint_id: String,
    pub aliases: Vec<String>,
    #[serde(default)]
    pub requested_ip: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub prefix_len: u8,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub links: Vec<String>,
}

/// Everything persisted about one container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ContainerRecord {
    pub id: String,
    pub name: String,
    pub created: String,
    /// The image as the client named it.
    pub image: String,
    pub image_id: String,
    /// The digest-pinned reference the machine runs.
    pub pull_ref: String,
    pub machine: String,
    /// The effective config: the client's merged over the image's.
    pub config: ContainerConfig,
    pub host_config: HostConfig,
    /// `HostConfig` exactly as sent, for inspect.
    pub host_config_raw: serde_json::Value,
    pub networks: BTreeMap<String, EndpointRecord>,
    pub path: String,
    pub args: Vec<String>,
    pub state: StateRecord,
    pub restart_count: u32,
    pub ports: Vec<PublishedPort>,
    pub mounts: Vec<MountRecord>,
    /// Stopped by a user, so `unless-stopped` and `always` keep it down.
    #[serde(default)]
    pub user_stopped: bool,
    /// Running when the engine stopped, so its restart policy applies at the
    /// next engine start.
    #[serde(default)]
    pub running_at_shutdown: bool,
    /// Tar archives uploaded before the first start, as `(host path,
    /// destination)`, unpacked into the container at start.
    #[serde(default)]
    pub pending_archives: Vec<(String, String)>,
}

impl ContainerRecord {
    pub(crate) fn short_id(&self) -> &str {
        &self.id[..12]
    }

    /// Labels and the attributes events carry.
    pub(crate) fn event_attributes(&self) -> BTreeMap<String, String> {
        let mut attrs = self.config.labels.clone();
        attrs.insert("image".into(), self.image.clone());
        attrs.insert("name".into(), self.name.clone());
        attrs
    }
}

/// A live container: its record plus what a run needs.
pub(crate) struct Container {
    record: parking_lot::Mutex<ContainerRecord>,
    /// Serializes start, stop, restart and remove.
    pub(crate) op: Arc<tokio::sync::Mutex<()>>,
    /// Held while the machine is being stopped after an exit; a start or a
    /// remove waits for it.
    pub(crate) vm: Arc<tokio::sync::Mutex<()>>,
    pub(crate) output: tokio::sync::broadcast::Sender<Output>,
    pub(crate) input: InputQueue,
    pub(crate) log_written: tokio::sync::Notify,
    running: parking_lot::Mutex<Option<Running>>,
    exits: tokio::sync::watch::Sender<ExitState>,
}

/// What exists only while the container runs.
struct Running {
    /// The agent socket of the container's machine.
    socket: PathBuf,
    /// The machine's process handle; dropping it stops the machine.
    vm: Option<crate::embedded::handle::VmHandle>,
    /// Ends the health checker.
    _health: Option<tokio::task::AbortHandle>,
}

/// Counter of exits plus the last code, for `wait`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExitState {
    pub exits: u64,
    pub code: i64,
    pub removed: bool,
}

impl Container {
    pub(crate) fn from_record(record: ContainerRecord) -> Arc<Self> {
        let (output, _) = tokio::sync::broadcast::channel(4096);
        let code = record.state.exit_code;
        Arc::new(Self {
            record: parking_lot::Mutex::new(record),
            op: Arc::new(tokio::sync::Mutex::new(())),
            vm: Arc::new(tokio::sync::Mutex::new(())),
            output,
            input: InputQueue::default(),
            log_written: tokio::sync::Notify::new(),
            running: parking_lot::Mutex::new(None),
            exits: tokio::sync::watch::channel(ExitState {
                code,
                ..Default::default()
            })
            .0,
        })
    }

    pub(crate) fn id(&self) -> String {
        self.record.lock().id.clone()
    }

    /// The lifecycle lock, owned (held across a temporary boot).
    pub(crate) async fn op_lock(self: &Arc<Self>) -> tokio::sync::OwnedMutexGuard<()> {
        self.op.clone().lock_owned().await
    }

    pub(crate) fn name(&self) -> String {
        self.record.lock().name.clone()
    }

    pub(crate) fn record(&self) -> ContainerRecord {
        self.record.lock().clone()
    }

    pub(crate) fn is_running(&self) -> bool {
        self.running.lock().is_some()
    }

    /// The agent socket while the container runs.
    pub(crate) fn socket(&self) -> Option<PathBuf> {
        self.running.lock().as_ref().map(|r| r.socket.clone())
    }

    /// Change the record and persist it.
    pub(crate) fn update(&self, engine: &Engine, f: impl FnOnce(&mut ContainerRecord)) {
        let snapshot = {
            let mut record = self.record.lock();
            f(&mut record);
            record.clone()
        };
        if let Err(e) = engine.store.save_container(&snapshot) {
            tracing::warn!(container = %snapshot.id, error = %e, "could not save container record");
        }
    }

    pub(crate) fn subscribe_exits(&self) -> tokio::sync::watch::Receiver<ExitState> {
        self.exits.subscribe()
    }

    fn emit(&self, engine: &Engine, action: &str, extra: &[(&str, String)]) {
        let record = self.record.lock();
        let mut attrs = record.event_attributes();
        for (k, v) in extra {
            attrs.insert((*k).to_string(), v.clone());
        }
        engine.events.emit("container", action, &record.id, attrs);
    }
}

// ============================================================================
// Create
// ============================================================================

/// `POST /containers/create`.
pub(crate) async fn create(
    engine: &Arc<Engine>,
    name: Option<String>,
    req: CreateRequest,
    raw_host_config: serde_json::Value,
    platform: Option<String>,
) -> ApiResult<(String, Vec<String>)> {
    let image = engine
        .images
        .resolve(&req.config.image)
        .ok_or_else(|| ApiError::not_found(format!("No such image: {}", req.config.image)))?;
    if let Some(platform) = platform.as_deref().filter(|p| !p.is_empty()) {
        let want_arch = platform.split('/').nth(1).unwrap_or("");
        if !want_arch.is_empty() && image.architecture() != want_arch {
            return Err(ApiError::not_found(format!(
                "image with reference {} was found but its platform (linux/{}) does not match the specified platform ({platform})",
                req.config.image,
                image.architecture()
            )));
        }
    }
    let id = super::util::new_id();
    let name = match name.filter(|n| !n.is_empty()) {
        Some(n) => {
            let n = n.trim_start_matches('/').to_string();
            if !super::util::valid_container_name(&n) {
                return Err(ApiError::bad_request(format!(
                    "Invalid container name ({n}), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed"
                )));
            }
            n
        }
        None => loop {
            let candidate = super::util::random_name();
            if engine.find_container(&candidate).is_none() {
                break candidate;
            }
        },
    };
    if let Some(existing) = engine.containers.read().values().find(|c| c.name() == name) {
        return Err(ApiError::conflict(format!(
            "Conflict. The container name \"/{name}\" is already in use by container \"{}\". You have to remove (or rename) that container to be able to reuse that name.",
            existing.id()
        )));
    }

    let mut warnings = Vec::new();
    let mut config = effective_config(&req.config, &image, &id);
    let (path, args) = command_of(&req.config, &image)
        .ok_or_else(|| ApiError::bad_request("no command specified"))?;
    let host_config = req.host_config.clone();
    if host_config.network_mode.starts_with("container:") {
        return Err(ApiError::bad_request(
            "network mode container:<name> is not supported: every container has its own machine and network stack",
        ));
    }
    if host_config.network_mode == "host" {
        warnings.push(
            "host networking is not available: each container is its own machine; it uses the default network instead".into(),
        );
    }

    let (mounts, shares, sockets) = resolve_mounts(engine, &req, &image, &id)?;
    let ports = resolve_ports(engine, &mut config, &host_config)?;
    let networks = super::network::attach_at_create(engine, &id, &name, &req)?;

    let machine = format!("docker-{}", &id[..12]);
    let mut labels = BTreeMap::new();
    labels.insert(MACHINE_LABEL.to_string(), id.clone());
    let spec = crate::machine_spec::CreateSpec {
        net: host_config.network_mode != "none",
        network_backend: (host_config.network_mode != "none")
            .then_some(crate::network::NetworkBackend::VirtioNet),
        mounts: shares,
        published_sockets: sockets,
        ports: ports
            .iter()
            .map(|p| {
                crate::data::network::PortMapping::with_protocol(
                    p.host_port,
                    p.container_port,
                    if p.proto == "udp" {
                        crate::data::network::PortProtocol::Udp
                    } else {
                        crate::data::network::PortProtocol::Tcp
                    },
                )
                .listening_on(p.listen())
            })
            .collect(),
        cpus: cpus_of(&host_config),
        mem: memory_of(&host_config),
        rosetta: needs_rosetta(&image),
        dns: host_config.dns.iter().find_map(|d| d.parse().ok()),
        dns_options: host_config.dns_options.clone(),
        // On an internal network only, a container has no way out.
        allowed_cidrs: super::network::internal_only(engine, &networks).then(Vec::new),
        switch: (!networks.is_empty()).then(|| super::network::attachment(engine, &id)),
        labels,
        ..Default::default()
    };
    let record = ContainerRecord {
        id: id.clone(),
        name: name.clone(),
        created: super::util::now_rfc3339(),
        image: req.config.image.clone(),
        image_id: image.id.clone(),
        pull_ref: image.pull_ref.clone(),
        machine: machine.clone(),
        config,
        host_config,
        host_config_raw: raw_host_config,
        networks,
        path,
        args,
        state: StateRecord::default(),
        restart_count: 0,
        ports,
        mounts,
        user_stopped: false,
        running_at_shutdown: false,
        pending_archives: Vec::new(),
    };

    let e = engine.clone();
    let pull_ref = image.pull_ref.clone();
    let machine_for_task = machine.clone();
    tokio::task::spawn_blocking(move || -> crate::Result<()> {
        crate::embedded::control::create_vm_from_spec(
            &e.db,
            &machine_for_task,
            Some(&pull_ref),
            spec,
        )?;
        // Start the machine's storage from the image's seed now, so the first
        // start finds the image in place. Best effort: without it, the first
        // start pulls in the guest. A machine that will branch from a warm
        // base takes the base's storage instead.
        let branches = e
            .db
            .get_vm(&machine_for_task)
            .ok()
            .flatten()
            .is_some_and(|vm| e.bases.ready_for(&vm));
        let builder = if branches { None } else { crate::image_seed::builder_exe().ok() };
        if let Some(exe) = builder {
            if let Err(error) = crate::image_seed::seed_storage(
                &exe,
                &machine_for_task,
                &pull_ref,
                &crate::registry::PullAuth::FromConfig,
                None,
                Some(super::images::PINNED_DIGEST_TTL_SECS),
                None,
                None,
            ) {
                tracing::debug!(%error, machine = %machine_for_task, "no image seed for the container");
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(format!("create machine for container: {e}")))?;

    engine.store.save_container(&record)?;
    let container = Container::from_record(record);
    engine
        .containers
        .write()
        .insert(id.clone(), container.clone());
    container.emit(engine, "create", &[]);
    Ok((id, warnings))
}

/// The client's config merged over the image's, as inspect shows it.
fn effective_config(req: &ContainerConfig, image: &ImageRecord, id: &str) -> ContainerConfig {
    let img: ContainerConfig =
        serde_json::from_value(image.container_config().clone()).unwrap_or_default();
    let mut c = req.clone();
    c.env = merge_env(&img.env, &req.env);
    let (entrypoint, cmd) = resolve_entrypoint_cmd(req, &img);
    c.entrypoint = entrypoint;
    c.cmd = cmd;
    if c.working_dir.is_empty() {
        c.working_dir = img.working_dir.clone();
    }
    if c.user.is_empty() {
        c.user = img.user.clone();
    }
    if c.hostname.is_empty() {
        c.hostname = id[..12].to_string();
    }
    let mut labels = img.labels.clone();
    labels.extend(req.labels.clone());
    c.labels = labels;
    for (port, v) in img.exposed_ports {
        c.exposed_ports.entry(port).or_insert(v);
    }
    for (vol, v) in img.volumes {
        c.volumes.entry(vol).or_insert(v);
    }
    if c.stop_signal.is_none() {
        c.stop_signal = img.stop_signal.clone();
    }
    c.healthcheck = merge_health(req.healthcheck.as_ref(), img.healthcheck.as_ref());
    c
}

/// Docker's rule: the client's entrypoint replaces the image's (and drops
/// its cmd unless the client gave one); no client entrypoint keeps the
/// image's, with the client's cmd or else the image's.
fn resolve_entrypoint_cmd(
    req: &ContainerConfig,
    img: &ContainerConfig,
) -> (Option<Vec<String>>, Option<Vec<String>>) {
    let user_cmd = req.cmd.clone().filter(|c| !c.is_empty());
    match &req.entrypoint {
        Some(ep) if !ep.is_empty() && !(ep.len() == 1 && ep[0].is_empty()) => {
            (Some(ep.clone()), user_cmd)
        }
        Some(_) => (None, user_cmd.or_else(|| img.cmd.clone())),
        None => (img.entrypoint.clone(), user_cmd.or_else(|| img.cmd.clone())),
    }
}

/// The container's argv as `(Path, Args)`.
fn command_of(req: &ContainerConfig, image: &ImageRecord) -> Option<(String, Vec<String>)> {
    let img: ContainerConfig =
        serde_json::from_value(image.container_config().clone()).unwrap_or_default();
    let (ep, cmd) = resolve_entrypoint_cmd(req, &img);
    let mut argv = ep.unwrap_or_default();
    argv.extend(cmd.unwrap_or_default());
    let mut it = argv.into_iter();
    let path = it.next()?;
    Some((path, it.collect()))
}

fn merge_env(image: &[String], container: &[String]) -> Vec<String> {
    let key = |e: &str| e.split('=').next().unwrap_or("").to_string();
    let overridden: BTreeSet<String> = container.iter().map(|e| key(e)).collect();
    let mut out: Vec<String> = image
        .iter()
        .filter(|e| !overridden.contains(&key(e)))
        .cloned()
        .collect();
    out.extend(container.iter().cloned());
    out
}

/// A client health check over the image's: unset fields keep the image's.
fn merge_health(req: Option<&HealthConfig>, img: Option<&HealthConfig>) -> Option<HealthConfig> {
    match (req, img) {
        (None, img) => img.cloned(),
        (Some(r), None) => Some(r.clone()),
        (Some(r), Some(i)) => {
            let mut h = r.clone();
            if h.test.is_empty() {
                h.test = i.test.clone();
            }
            if h.interval == 0 {
                h.interval = i.interval;
            }
            if h.timeout == 0 {
                h.timeout = i.timeout;
            }
            if h.start_period == 0 {
                h.start_period = i.start_period;
            }
            if h.start_interval == 0 {
                h.start_interval = i.start_interval;
            }
            if h.retries == 0 {
                h.retries = i.retries;
            }
            Some(h)
        }
    }
}

fn cpus_of(host: &HostConfig) -> Option<u8> {
    let cpus = if host.nano_cpus > 0 {
        (host.nano_cpus as f64 / 1e9).ceil()
    } else if host.cpu_quota > 0 {
        let period = if host.cpu_period > 0 {
            host.cpu_period
        } else {
            100_000
        };
        (host.cpu_quota as f64 / period as f64).ceil()
    } else {
        return None;
    };
    Some(cpus.clamp(1.0, 64.0) as u8)
}

/// Machine memory for a container memory limit: the limit plus the guest
/// kernel's own share.
fn memory_of(host: &HostConfig) -> Option<u32> {
    (host.memory > 0).then(|| ((host.memory >> 20) as u32 + 64).max(192))
}

fn needs_rosetta(image: &ImageRecord) -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64")) && image.architecture() == "amd64"
}

/// The machine shares, socket bridges and mount records for a container.
#[allow(clippy::type_complexity)]
fn resolve_mounts(
    engine: &Engine,
    req: &CreateRequest,
    image: &ImageRecord,
    id: &str,
) -> ApiResult<(
    Vec<MountRecord>,
    Vec<crate::data::storage::HostMount>,
    Vec<crate::config::PublishedSocketConfig>,
)> {
    let mut mounts: Vec<MountRecord> = Vec::new();
    let mut add = |m: MountRecord| -> ApiResult<()> {
        if mounts.iter().any(|o| o.destination == m.destination) {
            return Err(ApiError::bad_request(format!(
                "Duplicate mount point: {}",
                m.destination
            )));
        }
        mounts.push(m);
        Ok(())
    };
    for bind in &req.host_config.binds {
        let parts: Vec<&str> = bind.split(':').collect();
        let (source, dest, mode) = match parts.as_slice() {
            [s, d] => (*s, *d, ""),
            [s, d, m] => (*s, *d, *m),
            _ => {
                return Err(ApiError::bad_request(format!(
                    "invalid volume specification: '{bind}'"
                )))
            }
        };
        if !dest.starts_with('/') {
            return Err(ApiError::bad_request(format!(
                "invalid volume specification: '{bind}': invalid mount config: mount path must be absolute"
            )));
        }
        let read_only = mode.split(',').any(|o| o == "ro");
        if source.starts_with('/') {
            // `-v` creates a missing host directory, as Docker does, unless
            // the path stands for a socket (the Docker socket's own path).
            let path = std::path::Path::new(source);
            if !path.exists() && socket_source(path, &engine.config.socket).is_none() {
                std::fs::create_dir_all(path)
                    .map_err(|e| ApiError::internal(format!("create bind source {source}: {e}")))?;
            }
            add(MountRecord {
                kind: "bind".into(),
                source: source.into(),
                destination: dest.into(),
                read_only,
                mode: mode.into(),
                ..default_mount()
            })?;
        } else {
            let (vol, _) = engine.volumes.create(
                &engine.store,
                Some(source),
                BTreeMap::new(),
                BTreeMap::new(),
                false,
            )?;
            add(MountRecord {
                kind: "volume".into(),
                source: vol.name,
                destination: dest.into(),
                read_only,
                mode: mode.into(),
                copy_up: !mode.split(',').any(|o| o == "nocopy"),
                ..default_mount()
            })?;
        }
    }
    for m in &req.host_config.mounts {
        if !m.target.starts_with('/') {
            return Err(ApiError::bad_request(format!(
                "invalid mount config: mount path must be absolute: {}",
                m.target
            )));
        }
        match m.kind.as_str() {
            "bind" => {
                if !std::path::Path::new(&m.source).exists() {
                    return Err(ApiError::bad_request(format!(
                        "invalid mount config for type \"bind\": bind source path does not exist: {}",
                        m.source
                    )));
                }
                add(MountRecord {
                    kind: "bind".into(),
                    source: m.source.clone(),
                    destination: m.target.clone(),
                    read_only: m.read_only,
                    ..default_mount()
                })?;
            }
            "volume" => {
                let labels = m
                    .volume_options
                    .as_ref()
                    .map(|o| o.labels.clone())
                    .unwrap_or_default();
                let anonymous = m.source.is_empty();
                let (vol, _) = engine.volumes.create(
                    &engine.store,
                    (!m.source.is_empty()).then_some(m.source.as_str()),
                    labels,
                    BTreeMap::new(),
                    anonymous,
                )?;
                let subpath = m
                    .volume_options
                    .as_ref()
                    .map(|o| o.subpath.clone())
                    .filter(|s| !s.is_empty());
                add(MountRecord {
                    kind: "volume".into(),
                    source: vol.name,
                    destination: m.target.clone(),
                    read_only: m.read_only,
                    copy_up: !m.volume_options.as_ref().is_some_and(|o| o.no_copy)
                        && subpath.is_none(),
                    subpath,
                    ..default_mount()
                })?;
            }
            "tmpfs" => {
                let mut options = Vec::new();
                if let Some(t) = &m.tmpfs_options {
                    if t.size_bytes > 0 {
                        options.push(format!("size={}", t.size_bytes));
                    }
                    if t.mode > 0 {
                        options.push(format!("mode={:o}", t.mode));
                    }
                }
                add(MountRecord {
                    kind: "tmpfs".into(),
                    destination: m.target.clone(),
                    read_only: m.read_only,
                    options,
                    ..default_mount()
                })?;
            }
            other => {
                return Err(ApiError::bad_request(format!(
                    "mount type \"{other}\" is not supported"
                )))
            }
        }
    }
    for (dest, opts) in &req.host_config.tmpfs {
        add(MountRecord {
            kind: "tmpfs".into(),
            destination: dest.clone(),
            options: opts
                .split(',')
                .filter(|o| !o.is_empty())
                .map(str::to_string)
                .collect(),
            ..default_mount()
        })?;
    }
    // Anonymous volumes the client asked for (`docker run -v /data`).
    for dest in req.config.volumes.keys() {
        if mounts.iter().any(|m| &m.destination == dest) {
            continue;
        }
        let (vol, _) =
            engine
                .volumes
                .create(&engine.store, None, BTreeMap::new(), BTreeMap::new(), true)?;
        mounts.push(MountRecord {
            kind: "volume".into(),
            source: vol.name,
            destination: dest.clone(),
            copy_up: true,
            ..default_mount()
        });
    }
    let _ = (image, id);

    // Turn binds and volumes into machine shares. A bind of a host socket
    // becomes a socket bridge (the Docker socket included); a bind of one
    // file shares its directory and binds the file from it.
    let engine_socket = engine.config.socket.clone();
    let mut shares: Vec<crate::data::storage::HostMount> = Vec::new();
    let mut sockets = Vec::new();
    for m in mounts.iter_mut() {
        let host_path: PathBuf = match m.kind.as_str() {
            "bind" => PathBuf::from(&m.source),
            "volume" => engine.volumes.mountpoint(&m.source),
            _ => continue,
        };
        if m.kind == "bind" {
            if let Some(socket) = socket_source(&host_path, &engine_socket) {
                m.socket = true;
                sockets.push(crate::config::PublishedSocketConfig {
                    direction: smolvm_protocol::publish_socket::SocketDirection::Mount,
                    guest_path: m.destination.clone(),
                    host_path: Some(socket.to_string_lossy().into_owned()),
                });
                continue;
            }
        }
        let (dir, subpath) = if m.kind == "volume" {
            (host_path, m.subpath.clone())
        } else if host_path.is_dir() {
            (host_path, None)
        } else {
            let parent = host_path
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/"));
            let file = host_path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned());
            (parent, file)
        };
        let dir = dir.canonicalize().unwrap_or(dir);
        let target = if subpath.is_none() {
            PathBuf::from(&m.destination)
        } else {
            PathBuf::from(format!("/run/smolvm-shares/{}", shares.len()))
        };
        let index = match shares.iter().position(|s| {
            s.source == dir
                && s.read_only == m.read_only
                && subpath.is_some()
                && s.target.starts_with("/run/smolvm-shares")
        }) {
            Some(i) => i,
            None => {
                shares.push(crate::data::storage::HostMount {
                    source: dir,
                    target,
                    read_only: m.read_only,
                    staged: false,
                    recorded_ownership: true,
                });
                shares.len() - 1
            }
        };
        m.share = Some(index);
        m.subpath = subpath;
    }
    Ok((mounts, shares, sockets))
}

fn default_mount() -> MountRecord {
    MountRecord {
        kind: String::new(),
        source: String::new(),
        destination: String::new(),
        read_only: false,
        share: None,
        subpath: None,
        mode: String::new(),
        options: Vec::new(),
        copy_up: false,
        socket: false,
    }
}

/// The host socket a bind of `path` stands for: the path itself when it is a
/// Unix socket, and the engine's own socket for `/var/run/docker.sock` (the
/// path containers conventionally mount) when nothing else listens there.
fn socket_source(path: &std::path::Path, engine_socket: &std::path::Path) -> Option<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let is_socket = |p: &std::path::Path| {
        std::fs::metadata(p)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
    };
    if path == engine_socket
        || std::fs::canonicalize(path).ok().as_deref()
            == std::fs::canonicalize(engine_socket).ok().as_deref()
    {
        return Some(engine_socket.to_path_buf());
    }
    if path == std::path::Path::new("/var/run/docker.sock")
        || path == std::path::Path::new("/run/docker.sock")
    {
        if is_socket(path) && std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Some(path.to_path_buf());
        }
        return Some(engine_socket.to_path_buf());
    }
    is_socket(path).then(|| path.to_path_buf())
}

/// Host ports for the container's published ports, allocating free ones for
/// `-P` and for bindings without a host port.
fn resolve_ports(
    engine: &Engine,
    config: &mut ContainerConfig,
    host: &HostConfig,
) -> ApiResult<Vec<PublishedPort>> {
    let taken: BTreeSet<(u16, String)> = engine
        .containers
        .read()
        .values()
        .flat_map(|c| c.record().ports.into_iter().map(|p| (p.host_port, p.proto)))
        .collect();
    let mut out: Vec<PublishedPort> = Vec::new();
    let parse_key = |key: &str| -> ApiResult<(u16, String)> {
        let (port, proto) = key.split_once('/').unwrap_or((key, "tcp"));
        let port: u16 = port
            .parse()
            .map_err(|_| ApiError::bad_request(format!("invalid port specification: {key}")))?;
        let proto = proto.to_ascii_lowercase();
        if proto != "tcp" && proto != "udp" {
            return Err(ApiError::bad_request(format!(
                "protocol {proto} is not supported (tcp and udp are)"
            )));
        }
        Ok((port, proto))
    };
    let mut keys: Vec<(String, Vec<super::model::PortBinding>)> = host
        .port_bindings
        .iter()
        .map(|(k, v)| (k.clone(), v.clone().unwrap_or_default()))
        .collect();
    if host.publish_all_ports {
        for key in config.exposed_ports.keys() {
            if !keys.iter().any(|(k, _)| k == key) {
                keys.push((key.clone(), vec![super::model::PortBinding::default()]));
            }
        }
    }
    for (key, bindings) in keys {
        let (container_port, proto) = parse_key(&key)?;
        config
            .exposed_ports
            .entry(format!("{container_port}/{proto}"))
            .or_insert_with(|| serde_json::json!({}));
        let bindings = if bindings.is_empty() {
            vec![super::model::PortBinding::default()]
        } else {
            bindings
        };
        for b in bindings {
            // No address means every interface, as with Docker.
            let host_ip: std::net::IpAddr = match b
                .host_ip
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
            {
                "" => std::net::Ipv4Addr::UNSPECIFIED.into(),
                ip => ip.parse().map_err(|_| {
                    ApiError::bad_request(format!(
                        "invalid host IP address {:?} for port {key}",
                        b.host_ip
                    ))
                })?,
            };
            let used = |port: u16| {
                taken.contains(&(port, proto.clone()))
                    || out.iter().any(|p| p.host_port == port && p.proto == proto)
            };
            let host_port = match b.host_port.trim() {
                "" | "0" => free_port(&proto, host_ip, &used)?,
                range if range.contains('-') => {
                    let (lo, hi) = range.split_once('-').unwrap();
                    let lo: u16 = lo.parse().map_err(|_| {
                        ApiError::bad_request(format!("invalid port range {range}"))
                    })?;
                    let hi: u16 = hi.parse().map_err(|_| {
                        ApiError::bad_request(format!("invalid port range {range}"))
                    })?;
                    (lo..=hi)
                        .find(|p| !used(*p) && port_free(&proto, host_ip, *p))
                        .ok_or_else(|| {
                            ApiError::internal(format!("no free host port in {range}"))
                        })?
                }
                p => p
                    .parse()
                    .map_err(|_| ApiError::bad_request(format!("invalid host port {p}")))?,
            };
            if used(host_port) {
                return Err(ApiError::internal(format!(
                    "Bind for {}:{host_port} failed: port is already allocated",
                    show_ip(host_ip)
                )));
            }
            out.push(PublishedPort {
                container_port,
                proto: proto.clone(),
                host_ip: host_ip.to_string(),
                host_port,
            });
        }
    }
    Ok(out)
}

/// An address as Docker prints it beside a port: IPv6 in brackets.
fn show_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    }
}

fn port_free(proto: &str, ip: std::net::IpAddr, port: u16) -> bool {
    if proto == "udp" {
        std::net::UdpSocket::bind((ip, port)).is_ok()
    } else {
        std::net::TcpListener::bind((ip, port)).is_ok()
    }
}

fn free_port(proto: &str, ip: std::net::IpAddr, used: &dyn Fn(u16) -> bool) -> ApiResult<u16> {
    for _ in 0..64 {
        let port = if proto == "udp" {
            std::net::UdpSocket::bind((ip, 0))
                .and_then(|s| s.local_addr())
                .map(|a| a.port())
        } else {
            std::net::TcpListener::bind((ip, 0))
                .and_then(|s| s.local_addr())
                .map(|a| a.port())
        }
        .map_err(|e| ApiError::internal(format!("allocate a host port: {e}")))?;
        if !used(port) {
            return Ok(port);
        }
    }
    Err(ApiError::internal("no free host port"))
}

// ============================================================================
// Start, exit, stop
// ============================================================================

/// `POST /containers/{id}/start`. `Ok(false)` when it already runs.
pub(crate) async fn start(engine: &Arc<Engine>, c: &Arc<Container>) -> ApiResult<bool> {
    let _op = c.op.lock().await;
    start_locked(engine, c).await
}

async fn start_locked(engine: &Arc<Engine>, c: &Arc<Container>) -> ApiResult<bool> {
    if c.is_running() {
        return Ok(false);
    }
    // A machine still shutting down after the last exit must finish first.
    let _vm = c.vm.clone().lock_owned().await;
    let record = c.record();
    if record.state.status == "removing" {
        return Err(ApiError::conflict("container is being removed"));
    }
    super::network::before_start(engine, c).await?;
    let record = c.record();

    // Boot the machine and make sure the image is in its storage.
    let e = engine.clone();
    let machine = record.machine.clone();
    let pull_ref = record.pull_ref.clone();
    let first_start = record.state.started_at == super::util::ZERO_TIME;
    let booted = tokio::task::spawn_blocking(
        move || -> crate::Result<(crate::embedded::handle::VmHandle, bool)> {
            // A first start branches from the image's warm base when it can.
            let branched = if first_start {
                super::warm::branch(&e, &machine)
            } else {
                None
            };
            let is_branch = branched.is_some();
            let handle = match branched {
                Some(handle) => handle,
                None => crate::embedded::control::start_vm(&e.db, &machine)?.handle,
            };
            let mut client = crate::agent::AgentClient::connect_with_retry(handle.agent_socket())?;
            if client.query(&pull_ref)?.is_none() {
                client.pull_with_registry_config(&pull_ref)?;
            }
            Ok((handle, is_branch))
        },
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (handle, branched) = match booted {
        Ok(h) => h,
        Err(err) => {
            let msg = format!("failed to start container {}: {err}", record.short_id());
            c.update(engine, |r| r.state.error = msg.clone());
            stop_machine(engine, &record.machine, None).await;
            remove_after_failed_start(engine, c);
            return Err(ApiError::internal(msg));
        }
    };
    let socket = handle.agent_socket();

    // The container's other networks go on its interface before anything
    // in it runs.
    let addressed = if branched {
        super::network::after_branch(&socket, &record).await
    } else {
        super::network::after_boot(&socket, &record).await
    };
    if let Err(e) = addressed {
        let mut handle = handle;
        let _ = tokio::task::spawn_blocking(move || handle.stop()).await;
        stop_machine(engine, &record.machine, None).await;
        remove_after_failed_start(engine, c);
        return Err(e);
    }

    // Files uploaded before the first start go in now, before the command.
    for (file, destination) in &record.pending_archives {
        let unpacked = match tokio::fs::read(file).await {
            Ok(bytes) => super::archive::unpack(&socket, &record, &bytes, destination).await,
            Err(e) => Err(ApiError::internal(format!("read staged archive: {e}"))),
        };
        let _ = tokio::fs::remove_file(file).await;
        if let Err(e) = unpacked {
            tracing::warn!(container = %record.id, error = %e.message, "could not unpack an uploaded archive");
        }
    }

    let spec = start_spec(engine, &record);
    let started = async {
        let (mut reader, mut writer) = super::runtime::connect(&socket).await?;
        writer
            .send(&smolvm_protocol::AgentRequest::ContainerStart(Box::new(
                spec,
            )))
            .await?;
        match reader.recv().await? {
            smolvm_protocol::AgentResponse::Started => Ok((reader, writer)),
            other => Err(std::io::Error::other(
                super::runtime::error_text(&other).unwrap_or_else(|| format!("{other:?}")),
            )),
        }
    }
    .await;
    let (reader, writer) = match started {
        Ok(rw) => rw,
        Err(err) => {
            let msg = format!(
                "failed to create task for container: failed to create shim task: OCI runtime create failed: {err}"
            );
            let code = if msg.contains("executable file not found")
                || msg.contains("no such file or directory")
            {
                127
            } else if msg.contains("permission denied") {
                126
            } else {
                128
            };
            c.update(engine, |r| {
                r.state.error = msg.clone();
                r.state.exit_code = code;
            });
            let mut handle = handle;
            let _ = tokio::task::spawn_blocking(move || handle.stop()).await;
            let e = engine.clone();
            let machine = record.machine.clone();
            let _ = tokio::task::spawn_blocking(move || {
                crate::embedded::control::mark_stopped(&e.db, &machine)
            })
            .await;
            remove_after_failed_start(engine, c);
            return Err(ApiError::bad_request(msg));
        }
    };

    let pid = handle.child_pid().unwrap_or(0) as i64;
    c.update(engine, |r| {
        r.state.status = "running".into();
        r.state.pid = pid;
        r.state.exit_code = 0;
        r.state.error.clear();
        r.state.oom_killed = false;
        r.state.started_at = super::util::now_rfc3339();
        r.state.finished_at = super::util::ZERO_TIME.into();
        r.pending_archives.clear();
        if r.config.healthcheck.as_ref().is_some_and(health_enabled) {
            r.state.health = Some(HealthRecord {
                status: "starting".into(),
                failing_streak: 0,
                log: Vec::new(),
            });
        }
    });
    let health = record
        .config
        .healthcheck
        .clone()
        .filter(health_enabled)
        .map(|h| tokio::spawn(health_loop(engine.clone(), c.clone(), h)).abort_handle());
    *c.running.lock() = Some(Running {
        socket,
        vm: Some(handle),
        _health: health,
    });
    c.emit(engine, "start", &[]);

    // Carry the container's I/O until its command exits.
    let e = engine.clone();
    let container = c.clone();
    let tty = record.config.tty;
    let log_path = super::logs::path(&engine.store, &record.id);
    tokio::spawn(async move {
        let mut log = super::logs::LogWriter::open(&log_path, tty).ok();
        let exit = super::runtime::pump(reader, writer, &container.input, |stream, data| {
            if let Some(log) = log.as_mut() {
                log.write(stream, &data);
            }
            container.log_written.notify_waiters();
            let _ = container
                .output
                .send(Output::Data(stream, axum::body::Bytes::from(data)));
        })
        .await;
        if let Some(log) = log.as_mut() {
            log.flush();
        }
        container.log_written.notify_waiters();
        on_exit(e, container, exit).await;
    });
    Ok(true)
}

/// A start that failed leaves an auto-remove container to be removed, as the
/// client that asked for `--rm` waits for exactly that.
fn remove_after_failed_start(engine: &Arc<Engine>, c: &Arc<Container>) {
    if c.record().host_config.auto_remove {
        let (e, c) = (engine.clone(), c.clone());
        tokio::spawn(async move {
            let _ = remove(&e, &c, true, true).await;
        });
    }
}

/// The agent request that runs the container's command.
fn start_spec(engine: &Engine, record: &ContainerRecord) -> smolvm_protocol::ContainerStartSpec {
    use smolvm_protocol::ContainerMount;
    let mut mounts: Vec<&MountRecord> = record.mounts.iter().filter(|m| !m.socket).collect();
    mounts.sort_by_key(|m| std::path::Path::new(&m.destination).components().count());
    let mounts = mounts
        .into_iter()
        .map(|m| match m.kind.as_str() {
            "tmpfs" => ContainerMount::Tmpfs {
                target: m.destination.clone(),
                options: m.options.clone(),
            },
            _ => ContainerMount::Share {
                tag: crate::data::storage::HostMount::mount_tag(m.share.unwrap_or(0)),
                subpath: m.subpath.clone(),
                target: m.destination.clone(),
                read_only: m.read_only,
                copy_up: m.copy_up,
            },
        })
        .collect();
    let mut argv = vec![record.path.clone()];
    argv.extend(record.args.iter().cloned());
    let env = record
        .config
        .env
        .iter()
        .filter_map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    let mut hosts: Vec<(String, String)> = super::network::hosts_entries(engine, record);
    for entry in &record.host_config.extra_hosts {
        let (name, ip) = entry
            .split_once(':')
            .or_else(|| entry.split_once('='))
            .unwrap_or((entry.as_str(), ""));
        let ip = if ip == "host-gateway" {
            super::network::host_gateway(record)
        } else {
            ip.to_string()
        };
        if !ip.is_empty() {
            hosts.push((ip, name.to_string()));
        }
    }
    smolvm_protocol::ContainerStartSpec {
        id: record.id.clone(),
        image: record.pull_ref.clone(),
        overlay_id: overlay_id(record),
        command: argv,
        env,
        workdir: (!record.config.working_dir.is_empty()).then(|| record.config.working_dir.clone()),
        user: (!record.config.user.is_empty()).then(|| record.config.user.clone()),
        tty: record.config.tty,
        open_stdin: record.config.open_stdin,
        hostname: Some(record.config.hostname.clone()),
        hosts,
        mounts,
        read_only_rootfs: record.host_config.readonly_rootfs,
        shm_size: (record.host_config.shm_size > 0).then_some(record.host_config.shm_size as u64),
    }
}

/// The persistent overlay a container's root filesystem lives on.
pub(crate) fn overlay_id(record: &ContainerRecord) -> String {
    record.machine.clone()
}

/// The container's command ended: record it, stop the machine, and apply the
/// restart policy.
async fn on_exit(engine: Arc<Engine>, c: Arc<Container>, exit: Exit) {
    tracing::info!(container = %c.id(), name = %c.name(), code = exit.code, oom = exit.oom, "container exited");
    let vm_guard = c.vm.clone().lock_owned().await;
    let running = c.running.lock().take();
    let started_at = c.record().state.started_at;
    c.update(&engine, |r| {
        r.state.status = "exited".into();
        r.state.pid = 0;
        r.state.exit_code = exit.code;
        r.state.oom_killed = exit.oom;
        r.state.finished_at = super::util::now_rfc3339();
        if let Some(h) = r.state.health.as_mut() {
            h.status = "unhealthy".into();
        }
    });
    let _ = c.output.send(Output::End);
    c.emit(&engine, "die", &[("exitCode", exit.code.to_string())]);
    c.exits.send_modify(|s| {
        s.exits += 1;
        s.code = exit.code;
    });

    // The command is gone; stop its machine. Nothing is left to flush but
    // the disks, so no grace period.
    let record = c.record();
    if let Some(mut handle) = running.and_then(|mut r| r.vm.take()) {
        let _ = tokio::task::spawn_blocking(move || handle.stop_with_timeout(Some(Duration::ZERO)))
            .await;
    }
    stop_machine(&engine, &record.machine, Some(Duration::ZERO)).await;
    super::network::after_stop(&engine, &c).await;
    drop(vm_guard);

    if record.host_config.auto_remove {
        let _ = remove(&engine, &c, true, true).await;
        return;
    }
    if !should_restart(&record, exit.code) {
        return;
    }
    let ran = super::util::unix_seconds(&super::util::now_rfc3339())
        - super::util::unix_seconds(&started_at);
    let attempt = if ran >= 10 { 0 } else { record.restart_count };
    let delay = Duration::from_millis(100u64.saturating_mul(1 << attempt.min(10)))
        .min(Duration::from_secs(60));
    c.update(&engine, |r| {
        r.state.status = "restarting".into();
        r.restart_count += 1;
    });
    tokio::time::sleep(delay).await;
    let _op = c.op.lock().await;
    let current = c.record();
    if current.state.status != "restarting" || current.user_stopped {
        return;
    }
    if let Err(e) = start_boxed(engine.clone(), c.clone()).await {
        tracing::warn!(container = %current.id, error = %e.message, "restart failed");
        c.update(&engine, |r| {
            r.state.status = "exited".into();
            r.state.error = e.message.clone();
        });
    }
}

/// [`start_locked`] behind a box: a start spawns the task that, at the
/// exit, may start again, and the type of that cycle has to be cut somewhere.
fn start_boxed(
    engine: Arc<Engine>,
    c: Arc<Container>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ApiResult<bool>> + Send>> {
    Box::pin(async move { start_locked(&engine, &c).await })
}

fn should_restart(record: &ContainerRecord, code: i64) -> bool {
    if record.user_stopped {
        return false;
    }
    let policy = &record.host_config.restart_policy;
    match policy.name.as_str() {
        "always" | "unless-stopped" => true,
        "on-failure" => {
            code != 0
                && (policy.maximum_retry_count <= 0
                    || (record.restart_count as i64) < policy.maximum_retry_count)
        }
        _ => false,
    }
}

/// Stop the machine behind a container, whatever state it is in.
pub(crate) async fn stop_machine(engine: &Arc<Engine>, machine: &str, timeout: Option<Duration>) {
    let e = engine.clone();
    let machine = machine.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        let alive =
            e.db.get_vm(&machine)
                .ok()
                .flatten()
                .is_some_and(|r| r.state == crate::config::RecordState::Running);
        if alive {
            let _ = crate::embedded::control::stop_vm_with_timeout(&e.db, &machine, timeout);
        } else {
            let _ = crate::embedded::control::mark_stopped(&e.db, &machine);
        }
    })
    .await;
}

/// Send `signal` to the container's command.
pub(crate) async fn signal(c: &Container, signal: &str) -> ApiResult<()> {
    signal_processes(c, signal, false).await
}

/// Send `signal` to the container's command, or with `all` to every process
/// in the container.
async fn signal_processes(c: &Container, signal: &str, all: bool) -> ApiResult<()> {
    let socket = c
        .socket()
        .ok_or_else(|| ApiError::conflict(format!("Container {} is not running", c.id())))?;
    let reply = super::runtime::request(
        &socket,
        &smolvm_protocol::AgentRequest::ContainerSignal {
            overlay_id: overlay_id(&c.record()),
            signal: signal.to_string(),
            all,
        },
    )
    .await
    .map_err(|e| ApiError::internal(format!("signal container: {e}")))?;
    match super::runtime::error_text(&reply) {
        Some(e) => Err(ApiError::internal(format!("signal container: {e}"))),
        None => Ok(()),
    }
}

/// `POST /containers/{id}/kill`.
pub(crate) async fn kill(engine: &Arc<Engine>, c: &Arc<Container>, sig: &str) -> ApiResult<()> {
    let number = super::util::signal_number(sig)
        .ok_or_else(|| ApiError::bad_request(format!("Invalid signal: {sig}")))?;
    if !c.is_running() {
        return Err(ApiError::conflict(format!(
            "Cannot kill container: {}: Container {} is not running",
            c.name(),
            c.id()
        )));
    }
    let stop_signal = c
        .record()
        .config
        .stop_signal
        .as_deref()
        .and_then(super::util::signal_number)
        .unwrap_or(15);
    if number == 9 || number == stop_signal {
        // A container a user kills stays down, as one they stop does.
        c.update(engine, |r| r.user_stopped = true);
    }
    c.emit(engine, "kill", &[("signal", number.to_string())]);
    let mut exits = c.subscribe_exits();
    let before = exits.borrow().exits;
    signal(c, &number.to_string()).await?;
    if number == 9 {
        // As Docker does, SIGKILL returns once the container is gone, so the
        // client's next request (usually a remove) finds it stopped.
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            exits.wait_for(|s| s.exits > before),
        )
        .await;
        let _vm = c.vm.lock().await;
    }
    Ok(())
}

/// `POST /containers/{id}/stop`. `Ok(false)` when it was not running.
pub(crate) async fn stop(
    engine: &Arc<Engine>,
    c: &Arc<Container>,
    timeout: Option<i64>,
    sig: Option<String>,
) -> ApiResult<bool> {
    let _op = c.op.lock().await;
    stop_locked(engine, c, timeout, sig).await
}

async fn stop_locked(
    engine: &Arc<Engine>,
    c: &Arc<Container>,
    timeout: Option<i64>,
    sig: Option<String>,
) -> ApiResult<bool> {
    let record = c.record();
    if record.state.status == "restarting" {
        c.update(engine, |r| {
            r.user_stopped = true;
            r.state.status = "exited".into();
        });
        return Ok(true);
    }
    if !c.is_running() {
        return Ok(false);
    }
    c.update(engine, |r| r.user_stopped = true);
    if record.state.status == "paused" {
        let _ = signal_processes(c, "SIGCONT", true).await;
        c.update(engine, |r| r.state.status = "running".into());
    }
    let timeout = timeout
        .or(record.config.stop_timeout)
        .unwrap_or(10)
        .clamp(-1, 3600);
    let sig = sig
        .or_else(|| record.config.stop_signal.clone())
        .unwrap_or_else(|| "SIGTERM".into());
    let mut exits = c.subscribe_exits();
    let before = exits.borrow().exits;
    let exited = |exits: &mut tokio::sync::watch::Receiver<ExitState>, d: Duration| {
        let mut rx = exits.clone();
        async move {
            tokio::time::timeout(d, rx.wait_for(|s| s.exits > before))
                .await
                .is_ok()
        }
    };
    let number = super::util::signal_number(&sig).unwrap_or(15);
    if number != 9 && timeout != 0 {
        c.emit(engine, "kill", &[("signal", number.to_string())]);
        let _ = signal(c, &number.to_string()).await;
        let wait = if timeout < 0 {
            Duration::from_secs(3600 * 24)
        } else {
            Duration::from_secs(timeout as u64)
        };
        if !exited(&mut exits, wait).await {
            c.emit(engine, "kill", &[("signal", "9".into())]);
            let _ = signal(c, "9").await;
        }
    } else {
        c.emit(engine, "kill", &[("signal", "9".into())]);
        let _ = signal(c, "9").await;
    }
    if !exited(&mut exits, Duration::from_secs(10)).await {
        // The agent did not end it; stop the machine, which ends everything.
        let socket_gone = c.running.lock().as_mut().and_then(|r| r.vm.take());
        if let Some(mut handle) = socket_gone {
            let _ =
                tokio::task::spawn_blocking(move || handle.stop_with_timeout(Some(Duration::ZERO)))
                    .await;
        }
        let _ = exited(&mut exits, Duration::from_secs(30)).await;
    }
    // Wait for the machine to be down too, so an immediate start works.
    let _vm = c.vm.lock().await;
    c.emit(engine, "stop", &[]);
    Ok(true)
}

/// `POST /containers/{id}/restart`.
pub(crate) async fn restart(
    engine: &Arc<Engine>,
    c: &Arc<Container>,
    timeout: Option<i64>,
    sig: Option<String>,
) -> ApiResult<()> {
    let _op = c.op.lock().await;
    stop_locked(engine, c, timeout, sig).await?;
    c.update(engine, |r| r.user_stopped = false);
    start_locked(engine, c).await?;
    c.emit(engine, "restart", &[]);
    Ok(())
}

/// `DELETE /containers/{id}`.
pub(crate) async fn remove(
    engine: &Arc<Engine>,
    c: &Arc<Container>,
    force: bool,
    volumes: bool,
) -> ApiResult<()> {
    let _op = c.op.lock().await;
    let record = c.record();
    if c.is_running() || record.state.status == "restarting" {
        if !force {
            return Err(ApiError::conflict(format!(
                "cannot remove container \"/{}\": container is running: stop the container before removing or force remove",
                record.name
            )));
        }
        stop_locked(engine, c, Some(0), Some("SIGKILL".into())).await?;
    }
    c.update(engine, |r| r.state.status = "removing".into());
    let _vm = c.vm.lock().await;
    let e = engine.clone();
    let machine = record.machine.clone();
    tokio::task::spawn_blocking(move || {
        if let Some(vm) = e.db.get_vm(&machine).ok().flatten() {
            if let Err(error) = crate::embedded::control::delete_vm(&e.db, &machine) {
                tracing::warn!(%machine, %error, "could not delete the container's machine");
            }
            // The last container branched from a retired base takes it along.
            if vm.golden.is_some() {
                super::warm::collect(&e);
            }
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    super::network::detach_all(engine, c).await;
    engine.containers.write().remove(&record.id);
    engine.store.remove_container(&record.id);
    if volumes {
        for m in &record.mounts {
            if m.kind == "volume" {
                if let Some(v) = engine.volumes.get(&m.source) {
                    if v.anonymous && !volume_in_use(engine, &v.name) {
                        let _ = engine.volumes.remove(&engine.store, &v.name);
                        engine
                            .events
                            .emit("volume", "destroy", &v.name, BTreeMap::new());
                    }
                }
            }
        }
    }
    c.emit(engine, "destroy", &[]);
    c.exits.send_modify(|s| s.removed = true);
    Ok(())
}

/// Whether any container mounts the volume.
pub(crate) fn volume_in_use(engine: &Engine, name: &str) -> bool {
    engine.containers.read().values().any(|c| {
        c.record()
            .mounts
            .iter()
            .any(|m| m.kind == "volume" && m.source == name)
    })
}

/// `POST /containers/{id}/wait`: block until the condition holds and return
/// the exit code.
pub(crate) async fn wait(c: &Arc<Container>, condition: &str) -> ApiResult<i64> {
    let mut rx = c.subscribe_exits();
    let now = *rx.borrow();
    match condition {
        "next-exit" => {
            let s = rx
                .wait_for(|s| s.exits > now.exits || s.removed)
                .await
                .map_err(|_| ApiError::internal("container went away"))?;
            Ok(s.code)
        }
        "removed" => {
            let s = rx
                .wait_for(|s| s.removed)
                .await
                .map_err(|_| ApiError::internal("container went away"))?;
            Ok(s.code)
        }
        _ => {
            if !c.is_running() && c.record().state.status != "restarting" {
                return Ok(c.record().state.exit_code);
            }
            let s = rx
                .wait_for(|s| s.exits > now.exits || s.removed)
                .await
                .map_err(|_| ApiError::internal("container went away"))?;
            Ok(s.code)
        }
    }
}

/// `POST /containers/{id}/pause` and `/unpause`: stop or continue every
/// process of the container.
pub(crate) async fn pause(engine: &Arc<Engine>, c: &Arc<Container>, pause: bool) -> ApiResult<()> {
    let _op = c.op.lock().await;
    let status = c.record().state.status;
    match (pause, status.as_str()) {
        (true, "running") => {}
        (true, "paused") => {
            return Err(ApiError::conflict(format!(
                "Container {} is already paused",
                c.id()
            )))
        }
        (true, _) => {
            return Err(ApiError::conflict(format!(
                "Container {} is not running",
                c.id()
            )))
        }
        (false, "paused") => {}
        (false, _) => {
            return Err(ApiError::conflict(format!(
                "Container {} is not paused",
                c.id()
            )))
        }
    }
    signal_processes(c, if pause { "SIGSTOP" } else { "SIGCONT" }, true).await?;
    c.update(engine, |r| {
        r.state.status = if pause { "paused" } else { "running" }.into()
    });
    c.emit(engine, if pause { "pause" } else { "unpause" }, &[]);
    Ok(())
}

/// `POST /containers/{id}/rename`.
pub(crate) fn rename(engine: &Engine, c: &Container, new_name: &str) -> ApiResult<()> {
    let new_name = new_name.trim_start_matches('/');
    if !super::util::valid_container_name(new_name) {
        return Err(ApiError::bad_request(format!(
            "Invalid container name ({new_name}), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed"
        )));
    }
    if let Some(other) = engine.find_container(new_name) {
        if other.name() == new_name && other.id() != c.id() {
            return Err(ApiError::conflict(format!(
                "Conflict. The container name \"/{new_name}\" is already in use by container \"{}\". You have to remove (or rename) that container to be able to reuse that name.",
                other.id()
            )));
        }
    }
    let old = c.name();
    c.update(engine, |r| r.name = new_name.to_string());
    c.emit(engine, "rename", &[("oldName", format!("/{old}"))]);
    Ok(())
}

// ============================================================================
// Health checks
// ============================================================================

fn health_enabled(h: &HealthConfig) -> bool {
    !h.test.is_empty() && h.test[0] != "NONE"
}

/// Run the container's health check while it runs.
async fn health_loop(engine: Arc<Engine>, c: Arc<Container>, h: HealthConfig) {
    let ns = |v: i64, default: u64| {
        if v > 0 {
            Duration::from_nanos(v as u64)
        } else {
            Duration::from_secs(default)
        }
    };
    let interval = ns(h.interval, 30);
    let timeout = ns(h.timeout, 30);
    let start_period = Duration::from_nanos(h.start_period.max(0) as u64);
    let start_interval = ns(h.start_interval, 5);
    let retries = if h.retries > 0 { h.retries } else { 3 };
    let argv: Vec<String> = match h.test.first().map(String::as_str) {
        Some("CMD-SHELL") => vec!["/bin/sh".into(), "-c".into(), h.test[1..].join(" ")],
        Some("CMD") => h.test[1..].to_vec(),
        _ => h.test.clone(),
    };
    let began = tokio::time::Instant::now();
    let mut first = true;
    loop {
        let in_start = began.elapsed() < start_period;
        let wait = if first {
            if in_start {
                start_interval.min(interval)
            } else {
                interval
            }
        } else if in_start {
            start_interval
        } else {
            interval
        };
        first = false;
        tokio::time::sleep(wait).await;
        if !c.is_running() {
            return;
        }
        let start = super::util::now_rfc3339();
        let result = super::exec::run_capture(&engine, &c, &argv, timeout).await;
        let (code, output) = match result {
            Ok(r) => r,
            Err(e) => (-1, e.message),
        };
        let in_start = began.elapsed() < start_period;
        let mut changed = None;
        c.update(&engine, |r| {
            let health = r.state.health.get_or_insert_with(Default::default);
            let before = health.status.clone();
            if code == 0 {
                health.status = "healthy".into();
                health.failing_streak = 0;
            } else if !in_start || health.status == "healthy" {
                health.failing_streak += 1;
                if health.failing_streak >= retries {
                    health.status = "unhealthy".into();
                }
            }
            health.log.push(HealthProbe {
                start: start.clone(),
                end: super::util::now_rfc3339(),
                exit_code: code,
                output: output.chars().take(4096).collect(),
            });
            let len = health.log.len();
            if len > 5 {
                health.log.drain(..len - 5);
            }
            if health.status != before {
                changed = Some(health.status.clone());
            }
        });
        if let Some(status) = changed {
            c.emit(&engine, &format!("health_status: {status}"), &[]);
        }
    }
}

// ============================================================================
// Engine start and stop
// ============================================================================

/// Bring containers in line after an engine start: whatever ran when the
/// engine went away is stopped, and restart policies apply.
pub(crate) async fn recover(engine: &Arc<Engine>) {
    let containers: Vec<Arc<Container>> = engine.containers.read().values().cloned().collect();
    for c in containers {
        let record = c.record();
        let was_running = matches!(
            record.state.status.as_str(),
            "running" | "restarting" | "paused"
        ) || record.running_at_shutdown;
        if matches!(
            record.state.status.as_str(),
            "running" | "restarting" | "paused"
        ) {
            stop_machine(engine, &record.machine, Some(Duration::ZERO)).await;
            c.update(engine, |r| {
                r.state.status = "exited".into();
                r.state.pid = 0;
                r.state.exit_code = 255;
                r.state.finished_at = super::util::now_rfc3339();
            });
        }
        if record.state.status == "removing" {
            let _ = remove(engine, &c, true, false).await;
            continue;
        }
        let policy = record.host_config.restart_policy.name.as_str();
        let restart = match policy {
            "always" => true,
            "unless-stopped" => !record.user_stopped,
            "on-failure" => was_running,
            _ => false,
        } && (was_running || policy == "always");
        c.update(engine, |r| {
            r.running_at_shutdown = false;
            if restart {
                r.user_stopped = false;
            }
        });
        if restart {
            let (e, c) = (engine.clone(), c.clone());
            tokio::spawn(async move {
                if let Err(err) = start(&e, &c).await {
                    tracing::warn!(container = %c.id(), error = %err.message, "restart at engine start failed");
                }
            });
        }
    }
}

/// Stop every running container, as the engine exits.
pub(crate) async fn shutdown_all(engine: &Arc<Engine>) {
    let running: Vec<Arc<Container>> = engine
        .containers
        .read()
        .values()
        .filter(|c| c.is_running())
        .cloned()
        .collect();
    let mut tasks = Vec::new();
    for c in running {
        let e = engine.clone();
        tasks.push(tokio::spawn(async move {
            let user_stopped = c.record().user_stopped;
            c.update(&e, |r| r.running_at_shutdown = true);
            let _ = stop(&e, &c, None, None).await;
            c.update(&e, |r| r.user_stopped = user_stopped);
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
}

// ============================================================================
// Views
// ============================================================================

/// `GET /containers/{id}/json`.
pub(crate) fn inspect(engine: &Engine, c: &Container, size: bool) -> serde_json::Value {
    let r = c.record();
    let running = c.is_running();
    let state = &r.state;
    let health = state.health.as_ref().map(|h| {
        serde_json::json!({
            "Status": h.status,
            "FailingStreak": h.failing_streak,
            "Log": h.log.iter().map(|p| serde_json::json!({
                "Start": p.start, "End": p.end, "ExitCode": p.exit_code, "Output": p.output,
            })).collect::<Vec<_>>(),
        })
    });
    let mut host_config = r.host_config_raw.clone();
    if !host_config.is_object() {
        host_config = serde_json::json!({});
    }
    if let Some(obj) = host_config.as_object_mut() {
        let defaults = [
            ("NetworkMode", serde_json::json!(network_mode(&r))),
            (
                "RestartPolicy",
                serde_json::json!({"Name": if r.host_config.restart_policy.name.is_empty() { "no" } else { r.host_config.restart_policy.name.as_str() }, "MaximumRetryCount": r.host_config.restart_policy.maximum_retry_count}),
            ),
            (
                "LogConfig",
                serde_json::json!({"Type": "json-file", "Config": {}}),
            ),
            ("Binds", serde_json::json!(r.host_config.binds)),
            (
                "PortBindings",
                serde_json::json!(r.host_config.port_bindings),
            ),
            ("AutoRemove", serde_json::json!(r.host_config.auto_remove)),
            ("Privileged", serde_json::json!(r.host_config.privileged)),
            (
                "PublishAllPorts",
                serde_json::json!(r.host_config.publish_all_ports),
            ),
            (
                "ReadonlyRootfs",
                serde_json::json!(r.host_config.readonly_rootfs),
            ),
            ("Memory", serde_json::json!(r.host_config.memory)),
            ("NanoCpus", serde_json::json!(r.host_config.nano_cpus)),
            (
                "ShmSize",
                serde_json::json!(if r.host_config.shm_size > 0 {
                    r.host_config.shm_size
                } else {
                    67108864
                }),
            ),
            ("Runtime", serde_json::json!("smolvm")),
            ("Isolation", serde_json::json!("")),
            ("ExtraHosts", serde_json::json!(r.host_config.extra_hosts)),
        ];
        for (k, v) in defaults {
            let missing = obj.get(k).is_none_or(|x| x.is_null());
            if missing || k == "NetworkMode" || k == "RestartPolicy" {
                obj.insert(k.to_string(), v);
            }
        }
    }
    let mut config = serde_json::to_value(&r.config).unwrap_or_default();
    if let Some(obj) = config.as_object_mut() {
        obj.insert("Image".into(), serde_json::json!(r.image));
        obj.insert("OnBuild".into(), serde_json::Value::Null);
        if r.config.healthcheck.is_none() {
            obj.remove("Healthcheck");
        }
        if r.config.stop_timeout.is_none() {
            obj.remove("StopTimeout");
        }
        if r.config.stop_signal.is_none() {
            obj.remove("StopSignal");
        }
    }
    let exec_ids: Vec<String> = engine
        .execs
        .lock()
        .values()
        .filter(|e| e.container_id == r.id)
        .map(|e| e.id.clone())
        .collect();
    let mut out = serde_json::json!({
        "Id": r.id,
        "Created": r.created,
        "Path": r.path,
        "Args": r.args,
        "State": {
            "Status": state.status,
            "Running": running,
            "Paused": state.status == "paused",
            "Restarting": state.status == "restarting",
            "OOMKilled": state.oom_killed,
            "Dead": state.status == "dead",
            "Pid": if running { state.pid } else { 0 },
            "ExitCode": state.exit_code,
            "Error": state.error,
            "StartedAt": state.started_at,
            "FinishedAt": state.finished_at,
        },
        "Image": r.image_id,
        "ResolvConfPath": "",
        "HostnamePath": "",
        "HostsPath": "",
        "LogPath": super::logs::path(&engine.store, &r.id),
        "Name": format!("/{}", r.name),
        "RestartCount": r.restart_count,
        "Driver": "smolvm",
        "Platform": "linux",
        "MountLabel": "",
        "ProcessLabel": "",
        "AppArmorProfile": "",
        "ExecIDs": if exec_ids.is_empty() { serde_json::Value::Null } else { serde_json::json!(exec_ids) },
        "HostConfig": host_config,
        "GraphDriver": {"Name": "smolvm", "Data": {"Machine": r.machine}},
        "Mounts": mounts_view(engine, &r),
        "Config": config,
        "NetworkSettings": super::network::settings_view(engine, &r, running),
    });
    if let Some(h) = health {
        out["State"]["Health"] = h;
    }
    if size {
        out["SizeRw"] = serde_json::json!(0);
        out["SizeRootFs"] = serde_json::json!(0);
    }
    out
}

fn network_mode(r: &ContainerRecord) -> String {
    match r.host_config.network_mode.as_str() {
        "" | "default" => "bridge".into(),
        other => other.into(),
    }
}

/// `Mounts` of inspect and list.
pub(crate) fn mounts_view(engine: &Engine, r: &ContainerRecord) -> Vec<serde_json::Value> {
    r.mounts
        .iter()
        .filter(|m| m.kind != "tmpfs")
        .map(|m| match m.kind.as_str() {
            "volume" => serde_json::json!({
                "Type": "volume",
                "Name": m.source,
                "Source": engine.volumes.mountpoint(&m.source),
                "Destination": m.destination,
                "Driver": "local",
                "Mode": if m.mode.is_empty() { "z" } else { m.mode.as_str() },
                "RW": !m.read_only,
                "Propagation": "",
            }),
            _ => serde_json::json!({
                "Type": "bind",
                "Source": m.source,
                "Destination": m.destination,
                "Mode": m.mode,
                "RW": !m.read_only,
                "Propagation": "rprivate",
            }),
        })
        .collect()
}

/// The `Ports` list of `GET /containers/json`.
fn ports_list(r: &ContainerRecord, running: bool) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for key in r.config.exposed_ports.keys() {
        let (port, proto) = key.split_once('/').unwrap_or((key, "tcp"));
        let port: u16 = port.parse().unwrap_or(0);
        let published: Vec<&PublishedPort> = r
            .ports
            .iter()
            .filter(|p| p.container_port == port && p.proto == proto)
            .collect();
        if published.is_empty() || !running {
            out.push(serde_json::json!({"PrivatePort": port, "Type": proto}));
        } else {
            for p in published {
                for ip in p.listen_ips() {
                    out.push(serde_json::json!({
                        "IP": ip, "PrivatePort": port, "PublicPort": p.host_port, "Type": proto,
                    }));
                }
            }
        }
    }
    out
}

/// `GET /containers/json` entry.
pub(crate) fn summary(engine: &Engine, c: &Container) -> serde_json::Value {
    let r = c.record();
    let running = c.is_running();
    let mut command = r.path.clone();
    for a in &r.args {
        command.push(' ');
        command.push_str(a);
    }
    serde_json::json!({
        "Id": r.id,
        "Names": [format!("/{}", r.name)],
        "Image": r.image,
        "ImageID": r.image_id,
        "Command": command,
        "Created": super::util::unix_seconds(&r.created),
        "Ports": ports_list(&r, running),
        "Labels": r.config.labels,
        "State": r.state.status,
        "Status": status_text(&r, running),
        "HostConfig": {"NetworkMode": network_mode(&r)},
        "NetworkSettings": {"Networks": super::network::settings_view(engine, &r, running)["Networks"]},
        "Mounts": mounts_view(engine, &r),
    })
}

/// `Up 5 minutes (healthy)`, `Exited (0) 3 seconds ago`, ...
fn status_text(r: &ContainerRecord, running: bool) -> String {
    let now = std::time::SystemTime::now();
    let since = |ts: &str| {
        humantime::parse_rfc3339_weak(ts)
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .unwrap_or_default()
    };
    match r.state.status.as_str() {
        "created" => "Created".into(),
        "restarting" => format!(
            "Restarting ({}) {} ago",
            r.state.exit_code,
            human_duration(since(&r.state.finished_at))
        ),
        "removing" => "Removal In Progress".into(),
        "paused" => format!("Up {} (Paused)", human_duration(since(&r.state.started_at))),
        _ if running => {
            let mut s = format!("Up {}", human_duration(since(&r.state.started_at)));
            if let Some(h) = &r.state.health {
                match h.status.as_str() {
                    "starting" => s.push_str(" (health: starting)"),
                    "" => {}
                    other => s.push_str(&format!(" ({other})")),
                }
            }
            s
        }
        _ => {
            if r.state.finished_at == super::util::ZERO_TIME {
                "Created".into()
            } else {
                format!(
                    "Exited ({}) {} ago",
                    r.state.exit_code,
                    human_duration(since(&r.state.finished_at))
                )
            }
        }
    }
}

/// Docker's `units.HumanDuration`.
fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0 => "Less than a second".into(),
        1 => "1 second".into(),
        2..=59 => format!("{s} seconds"),
        60..=119 => "About a minute".into(),
        120..=3599 => format!("{} minutes", s / 60),
        3600..=7199 => "About an hour".into(),
        7200..=172_799 => format!("{} hours", s / 3600),
        172_800..=1_209_599 => format!("{} days", s / 86400),
        1_209_600..=5_183_999 => format!("{} weeks", s / 604_800),
        5_184_000..=63_071_999 => format!("{} months", s / 2_592_000),
        _ => format!("{} years", s / 31_536_000),
    }
}

/// Whether `c` passes the `docker ps` filters.
pub(crate) fn matches(engine: &Engine, c: &Container, filters: &Filters) -> bool {
    let r = c.record();
    let running = c.is_running();
    filters.any("id", |id| r.id.starts_with(id))
        && filters.any("name", |n| {
            let n = n.trim_start_matches('/');
            let anchored = n.starts_with('^');
            let n = n.trim_start_matches('^');
            let (n, end) = match n.strip_suffix('$') {
                Some(n) => (n, true),
                None => (n, false),
            };
            match (anchored, end) {
                (true, true) => r.name == n,
                (true, false) => r.name.starts_with(n),
                (false, true) => r.name.ends_with(n),
                (false, false) => r.name.contains(n),
            }
        })
        && filters.labels_match("label", &r.config.labels)
        && filters.any("status", |s| s == r.state.status)
        && filters.any("exited", |code| {
            r.state.status == "exited" && code.parse::<i64>().ok() == Some(r.state.exit_code)
        })
        && filters.any("ancestor", |a| {
            r.image == a
                || r.image_id == a
                || engine
                    .images
                    .resolve(a)
                    .is_some_and(|img| img.id == r.image_id)
        })
        && filters.any("health", |h| {
            let status = r
                .state
                .health
                .as_ref()
                .map(|h| h.status.as_str())
                .unwrap_or("none");
            h == status
        })
        && filters.any("volume", |v| {
            r.mounts.iter().any(|m| m.source == v || m.destination == v)
        })
        && filters.any("network", |n| {
            r.networks.contains_key(n) || r.networks.values().any(|e| e.network_id.starts_with(n))
        })
        && filters.any("publish", |p| {
            let port = p.split('/').next().unwrap_or(p);
            r.ports.iter().any(|x| x.host_port.to_string() == port)
        })
        && filters.any("expose", |p| {
            let port = p.split('/').next().unwrap_or(p);
            r.config
                .exposed_ports
                .keys()
                .any(|k| k.split('/').next() == Some(port))
        })
        && filters.any("is-task", |t| t == "false")
        && (running
            || !filters.has("status")
            || filters.get("status").iter().any(|s| s != "running"))
}

/// Push `input` to a running container's process.
pub(crate) fn send_input(c: &Container, input: Input) {
    c.input.push(input);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(config: serde_json::Value) -> ImageRecord {
        ImageRecord {
            id: "sha256:abc".into(),
            repo_tags: vec![],
            repo_digests: vec![],
            pull_ref: String::new(),
            config: serde_json::json!({"architecture": "arm64", "config": config}),
            size: 0,
            pulled: String::new(),
            last_tag_time: String::new(),
        }
    }

    fn cfg(entrypoint: Option<Vec<&str>>, cmd: Option<Vec<&str>>) -> ContainerConfig {
        ContainerConfig {
            entrypoint: entrypoint.map(|v| v.into_iter().map(String::from).collect()),
            cmd: cmd.map(|v| v.into_iter().map(String::from).collect()),
            ..Default::default()
        }
    }

    #[test]
    fn entrypoint_and_cmd_follow_docker() {
        let img =
            image(serde_json::json!({"Entrypoint": ["docker-entrypoint.sh"], "Cmd": ["postgres"]}));
        let argv = |c: &ContainerConfig| {
            let (p, a) = command_of(c, &img).unwrap();
            let mut v = vec![p];
            v.extend(a);
            v
        };
        assert_eq!(argv(&cfg(None, None)), ["docker-entrypoint.sh", "postgres"]);
        assert_eq!(
            argv(&cfg(None, Some(vec!["psql"]))),
            ["docker-entrypoint.sh", "psql"]
        );
        assert_eq!(argv(&cfg(Some(vec!["sh"]), None)), ["sh"]);
        assert_eq!(
            argv(&cfg(Some(vec!["sh"]), Some(vec!["-c", "x"]))),
            ["sh", "-c", "x"]
        );
        // `--entrypoint ""` drops the image's entrypoint and keeps its cmd.
        assert_eq!(argv(&cfg(Some(vec![]), None)), ["postgres"]);
        assert_eq!(argv(&cfg(Some(vec![""]), Some(vec!["id"]))), ["id"]);
    }

    #[test]
    fn env_merges_by_key() {
        let merged = merge_env(
            &["PATH=/usr/bin".into(), "A=1".into()],
            &["A=2".into(), "B=3".into()],
        );
        assert_eq!(merged, ["PATH=/usr/bin", "A=2", "B=3"]);
    }

    #[test]
    fn health_fields_fall_back_to_the_image() {
        let img = HealthConfig {
            test: vec!["CMD".into(), "true".into()],
            interval: 5,
            retries: 3,
            ..Default::default()
        };
        let req = HealthConfig {
            interval: 1,
            ..Default::default()
        };
        let h = merge_health(Some(&req), Some(&img)).unwrap();
        assert_eq!(h.test, img.test);
        assert_eq!(h.interval, 1);
        assert_eq!(h.retries, 3);
    }

    #[test]
    fn durations_read_like_docker() {
        assert_eq!(human_duration(Duration::from_secs(0)), "Less than a second");
        assert_eq!(human_duration(Duration::from_secs(5)), "5 seconds");
        assert_eq!(human_duration(Duration::from_secs(90)), "About a minute");
        assert_eq!(human_duration(Duration::from_secs(7200)), "2 hours");
    }

    #[test]
    fn restart_policies() {
        let mut r: ContainerRecord = serde_json::from_value(serde_json::json!({
            "id": "a".repeat(64), "name": "x", "created": "", "image": "", "image_id": "",
            "pull_ref": "", "machine": "", "config": {}, "host_config": {}, "host_config_raw": {},
            "networks": {}, "path": "sh", "args": [], "state": StateRecord::default(),
            "restart_count": 0, "ports": [], "mounts": []
        }))
        .unwrap();
        assert!(!should_restart(&r, 1));
        r.host_config.restart_policy.name = "on-failure".into();
        r.host_config.restart_policy.maximum_retry_count = 2;
        assert!(should_restart(&r, 1));
        assert!(!should_restart(&r, 0));
        r.restart_count = 2;
        assert!(!should_restart(&r, 1));
        r.host_config.restart_policy.name = "always".into();
        assert!(should_restart(&r, 0));
        r.user_stopped = true;
        assert!(!should_restart(&r, 0));
    }
}
