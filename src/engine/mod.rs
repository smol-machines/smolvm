//! The Docker Engine API, answered by smolvm itself.
//!
//! `smolvm engine` listens on a Unix socket and speaks the subset of the
//! Docker Engine API that the `docker` CLI, Docker Compose, Testcontainers
//! and Dev Containers use. There is no Docker daemon anywhere: every
//! container is a smol machine started from its image, with its own kernel.
//!
//! How the Docker objects map onto machines:
//!
//! - **Image**: pulled in a guest, as every smolvm image is, into a shared
//!   image seed (see [`crate::image_seed`]) that each container's storage
//!   disk starts from. The engine keeps the image's config (fetched with the
//!   same registry authorization) so it can answer `docker image inspect` and
//!   resolve a container's command without booting anything.
//! - **Container**: one machine (`docker-<id>`), created from the image when
//!   the container is created. Starting the container boots the machine and
//!   runs the container's command as the init of the image container inside
//!   it ([`smolvm_protocol::AgentRequest::ContainerStart`]); the command's
//!   exit is the container's exit, after which the machine stops.
//! - **Logs**: the engine reads the command's stdout and stderr from the agent
//!   and writes them, timestamped and per stream, to a log file per container.
//! - **Volume**: a host directory shared into each machine that mounts it.
//! - **Network**: see [`network`].
//!
//! State lives under `<data dir>/smolvm/engine`: one JSON record per
//! container, image, volume and network, so the engine can restart and pick
//! up where it was.

mod api;
mod archive;
mod build;
mod containers;
mod events;
mod exec;
mod filters;
mod images;
mod logs;
mod model;
mod network;
mod runtime;
mod store;
mod stream;
mod util;
mod volumes;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use model::API_VERSION;

/// Where the engine listens and keeps its state.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Unix socket the Docker API is served on.
    pub socket: PathBuf,
    /// Directory holding the engine's records, logs and volumes.
    pub root: PathBuf,
}

impl EngineConfig {
    /// The default socket, `~/.smolvm/run/docker.sock`, and state directory.
    pub fn default_paths() -> crate::Result<Self> {
        let home =
            dirs::home_dir().ok_or_else(|| crate::Error::config("engine", "no home directory"))?;
        let data = dirs::data_local_dir()
            .ok_or_else(|| crate::Error::config("engine", "no data directory"))?;
        Ok(Self {
            socket: default_socket_path(&home),
            root: data.join("smolvm").join("engine"),
        })
    }
}

/// `~/.smolvm/run/docker.sock` for `home`.
pub fn default_socket_path(home: &Path) -> PathBuf {
    home.join(".smolvm").join("run").join("docker.sock")
}

/// Shared engine state. Handlers hold it behind an `Arc`.
pub(crate) struct Engine {
    pub(crate) config: EngineConfig,
    pub(crate) db: crate::db::SmolvmDb,
    pub(crate) store: store::Store,
    pub(crate) containers: parking_lot::RwLock<HashMap<String, Arc<containers::Container>>>,
    pub(crate) images: images::Images,
    pub(crate) volumes: volumes::Volumes,
    pub(crate) networks: network::Networks,
    pub(crate) execs: parking_lot::Mutex<HashMap<String, Arc<exec::Exec>>>,
    pub(crate) events: events::Events,
}

impl Engine {
    fn open(config: EngineConfig) -> crate::Result<Arc<Self>> {
        let store = store::Store::open(&config.root)?;
        let db = crate::db::SmolvmDb::open()?;
        let images = images::Images::load(&store)?;
        let volumes = volumes::Volumes::load(&store)?;
        let networks = network::Networks::load(&store, &config.socket)?;
        let engine = Arc::new(Self {
            config,
            db,
            store,
            containers: parking_lot::RwLock::new(HashMap::new()),
            images,
            volumes,
            networks,
            execs: parking_lot::Mutex::new(HashMap::new()),
            events: events::Events::new(),
        });
        for record in engine.store.load_containers()? {
            let container = containers::Container::from_record(record);
            engine
                .containers
                .write()
                .insert(container.id().to_string(), container);
        }
        Ok(engine)
    }

    /// The container named by a full id, a unique id prefix, or a name.
    pub(crate) fn find_container(&self, name_or_id: &str) -> Option<Arc<containers::Container>> {
        let key = name_or_id.trim_start_matches('/');
        let containers = self.containers.read();
        if let Some(c) = containers.get(key) {
            return Some(c.clone());
        }
        if let Some(c) = containers.values().find(|c| c.name() == key) {
            return Some(c.clone());
        }
        let mut matches = containers.values().filter(|c| c.id().starts_with(key));
        match (matches.next(), matches.next()) {
            (Some(c), None) if !key.is_empty() => Some(c.clone()),
            _ => None,
        }
    }
}

/// Serve the Docker Engine API on `config.socket` until SIGINT or SIGTERM.
/// Running containers are stopped on the way out, as a Docker daemon without
/// live restore stops them.
pub async fn serve(config: EngineConfig) -> crate::Result<()> {
    let engine = tokio::task::spawn_blocking(move || Engine::open(config))
        .await
        .map_err(|e| crate::Error::config("engine", e.to_string()))??;
    containers::recover(&engine).await;

    let listener = bind_socket(&engine.config.socket)?;
    tracing::info!(socket = %engine.config.socket.display(), "engine listening");
    let app = api::router(engine.clone());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(crate::Error::Io)?;
    let mut graceful = stop_rx.clone();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = graceful.wait_for(|stop| *stop).await;
    });
    let mut server = std::pin::pin!(std::future::IntoFuture::into_future(server));
    let served = tokio::select! {
        result = &mut server => result,
        _ = async {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        } => {
            let _ = stop_tx.send(true);
            // Long-lived streams (events, logs, attach) never finish on their
            // own; give requests a moment, then go.
            match tokio::time::timeout(std::time::Duration::from_secs(5), &mut server).await {
                Ok(result) => result,
                Err(_) => Ok(()),
            }
        }
    };
    drop(stop_rx);
    containers::shutdown_all(&engine).await;
    let _ = std::fs::remove_file(&engine.config.socket);
    served.map_err(crate::Error::Io)
}

/// Bind the API socket, replacing a stale one. The socket is private to the
/// user, like the Docker socket is to its group.
fn bind_socket(path: &Path) -> crate::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(crate::Error::config(
                "engine",
                format!("another engine is already listening on {}", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
